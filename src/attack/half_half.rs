use super::*;
use crate::math::{mod_inverse, verify_private_key};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{Zero, Signed, Euclid, ToPrimitive};
use k256::elliptic_curve::PrimeField;

pub struct HalfHalfAttack;

impl Attack for HalfHalfAttack {
    fn name(&self) -> &'static str {
        "half-half"
    }

    fn min_signatures(&self) -> usize {
        1
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        for sig in signatures {
            if let Some(_key) = try_recover_half_half(sig) {
                let group = SignatureGroup {
                    r: sig.r,
                    pubkey: sig.pubkey.clone(),
                    signatures: vec![sig.clone()],
                    confidence: 1.0,
                };
                vulns.push(Vulnerability {
                    attack_type: self.name().to_string(),
                    group,
                });
            }
        }
        vulns
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        let sig = &vuln.group.signatures[0];
        try_recover_half_half(sig)
    }
}

fn try_recover_half_half(sig: &Signature) -> Option<RecoveredKey> {
    let n_bi = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();

    let s = scalar_to_biguint(&sig.s);
    let r = scalar_to_biguint(&sig.r);
    let z = scalar_to_biguint(&sig.z);

    let two_128 = BigUint::from(1u64) << 128;
    let z_msb = &z >> 128;
    let h = (z_msb << 128) % &n_bi;

    let a = (s.clone() + &n_bi - (r.clone() * &two_128 % &n_bi)) % &n_bi;
    let b = (&n_bi - &r) % &n_bi;
    let c = (z.clone() + &n_bi - (s.clone() * h % &n_bi)) % &n_bi;

    let b_inv = mod_inverse_biguint(&b, &n_bi)?;
    let d = (&n_bi - (a * &b_inv % &n_bi)) % &n_bi;
    let e = c * &b_inv % &n_bi;

    if let Some((x_msb_bi, x_lsb_bi)) = solve_2d_closest_vector(d, e, &n_bi) {
        let priv_key_bi = (&x_msb_bi << 128) + &x_lsb_bi;
        if priv_key_bi < n_bi {
            let priv_key = biguint_to_scalar(&priv_key_bi);
            if verify_private_key(&priv_key, &sig.r, &sig.s, &sig.z, &sig.pubkey) {
                return Some(RecoveredKey {
                    private_key: priv_key,
                    private_key_decimal: priv_key_bi.to_string(),
                    pubkey: sig.pubkey.clone(),
                });
            }
        }
    }

    None
}

fn solve_2d_closest_vector(d: BigUint, e: BigUint, n: &BigUint) -> Option<(BigUint, BigUint)> {
    let b1 = (BigInt::from(1), d.to_bigint().unwrap());
    let b2 = (BigInt::from(0), n.to_bigint().unwrap());
    let t = (BigInt::from(0), -(e.to_bigint().unwrap()));

    let (v1, v2) = gauss_reduce(b1, b2);

    let det = &v1.0 * &v2.1 - &v1.1 * &v2.0;
    if det.is_zero() { return None; }

    let a1_num = &t.0 * &v2.1 - &t.1 * &v2.0;
    let a2_num = &v1.0 * &t.1 - &v1.1 * &t.0;

    let c1_base = &a1_num / &det;
    let c2_base = &a2_num / &det;

    for i in -1..=1 {
        for j in -1..=1 {
            let c1_bi = &c1_base + BigInt::from(i);
            let c2_bi = &c2_base + BigInt::from(j);

            let closest = (
                &c1_bi * &v1.0 + &c2_bi * &v2.0,
                &c1_bi * &v1.1 + &c2_bi * &v2.1,
            );

            let x_msb = &closest.0;
            let y = &closest.1;

            let x_msb_abs = x_msb.abs().to_biguint().unwrap();
            let x_lsb_abs = (y + e.to_bigint().unwrap()).rem_euclid(&n.to_bigint().unwrap()).to_biguint().unwrap();

            if x_msb_abs < (BigUint::from(1u64) << 128) && x_lsb_abs < (BigUint::from(1u64) << 128) {
                return Some((x_msb_abs, x_lsb_abs));
            }
        }
    }

    None
}

fn gauss_reduce(mut u: (BigInt, BigInt), mut v: (BigInt, BigInt)) -> ((BigInt, BigInt), (BigInt, BigInt)) {
    loop {
        if norm_sq(&u) > norm_sq(&v) {
            std::mem::swap(&mut u, &mut v);
        }

        let sc = dot(&u, &v);
        let norm_u = norm_sq(&u);
        let m = round_div(sc, norm_u);

        if m.is_zero() {
            return (u, v);
        }

        v.0 -= &m * &u.0;
        v.1 -= &m * &u.1;
    }
}

fn norm_sq(v: &(BigInt, BigInt)) -> BigInt {
    &v.0 * &v.0 + &v.1 * &v.1
}

fn dot(u: &(BigInt, BigInt), v: &(BigInt, BigInt)) -> BigInt {
    &u.0 * &v.0 + &u.1 * &v.1
}

fn round_div(num: BigInt, den: BigInt) -> BigInt {
    let half_den = den.abs() / 2;
    if num >= BigInt::zero() {
        (num + half_den) / den
    } else {
        (num - half_den) / den
    }
}

fn scalar_to_biguint(s: &Scalar) -> BigUint {
    BigUint::from_bytes_be(&s.to_bytes())
}

fn biguint_to_scalar(bi: &BigUint) -> Scalar {
    let mut bytes = [0u8; 32];
    let bi_bytes = bi.to_bytes_be();
    let offset = 32 - bi_bytes.len();
    bytes[offset..].copy_from_slice(&bi_bytes);
    Scalar::from_repr(bytes.into()).unwrap()
}

fn mod_inverse_biguint(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_scalar = biguint_to_scalar(&(a % m));
    mod_inverse(&a_scalar).map(|inv| scalar_to_biguint(&inv))
}
