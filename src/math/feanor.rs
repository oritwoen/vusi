//! Feanor-math integration for polynomial operations over secp256k1's scalar field.
//!
//! This module provides conversion utilities between k256::Scalar and feanor-math's
//! BigInt representation, enabling polynomial factorization over the scalar field.

use feanor_math::homomorphism::Homomorphism;
use feanor_math::integer::IntegerRingStore;
use feanor_math::pid::EuclideanRingStore;
use feanor_math::ring::RingStore;
use feanor_math::rings::rust_bigint::RustBigintRing;
use k256::elliptic_curve::ff::PrimeField;
use k256::Scalar;

/// secp256k1 curve order n in hexadecimal.
const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Type alias for feanor-math BigInt elements.
pub type BigIntElement =
    <<RustBigintRing as RingStore>::Type as feanor_math::ring::RingBase>::Element;

/// Returns the secp256k1 curve order n as a feanor-math BigInt.
pub fn secp256k1_order_bigint() -> BigIntElement {
    let zz = RustBigintRing::RING;
    zz.parse(SECP256K1_ORDER_HEX, 16)
        .expect("SECP256K1_ORDER_HEX should parse as base-16 BigInt")
}

/// Converts big-endian bytes to a feanor-math BigInt.
pub fn bigint_from_be_bytes(bytes: &[u8]) -> BigIntElement {
    let zz = RustBigintRing::RING;

    let base = zz.int_hom().map(256);
    let mut acc = zz.zero();
    for &b in bytes {
        acc = zz.add(zz.mul(acc, zz.clone_el(&base)), zz.int_hom().map(b as i32));
    }
    acc
}

/// Converts a feanor-math BigInt to a fixed 32-byte big-endian array.
///
/// Returns `None` if the BigInt requires more than 32 bytes to represent
/// (i.e., if the value hasn't been reduced mod n).
pub fn bigint_to_be_bytes_fixed_32(mut x: BigIntElement) -> Option<[u8; 32]> {
    let zz = RustBigintRing::RING;

    let base = zz.int_hom().map(256);
    let mut tmp = Vec::<u8>::new();

    while !zz.is_zero(&x) {
        let (q, r) = zz.euclidean_div_rem(x, &base);
        x = q;

        // r is in [0, 255]
        let r_f64 = zz.to_float_approx(&r).round();
        let r_u8: u8 = if r_f64 >= 0.0 && r_f64 <= 255.0 {
            r_f64 as u8
        } else {
            panic!("remainder should fit in u8, got {}", r_f64)
        };
        tmp.push(r_u8);
    }

    tmp.reverse();

    if tmp.len() > 32 {
        return None;
    }

    let mut out = [0u8; 32];
    let start = 32 - tmp.len();
    out[start..].copy_from_slice(&tmp);
    Some(out)
}

/// Converts a k256::Scalar to a feanor-math BigInt.
pub fn scalar_to_bigint(scalar: &Scalar) -> BigIntElement {
    bigint_from_be_bytes(&scalar.to_bytes())
}

/// Converts a feanor-math BigInt to a k256::Scalar.
///
/// Returns `None` if the BigInt does not represent a valid scalar
/// (e.g., if it's >= the curve order or requires more than 32 bytes).
pub fn bigint_to_scalar(big: &BigIntElement) -> Option<Scalar> {
    let zz = RustBigintRing::RING;
    let bytes = bigint_to_be_bytes_fixed_32(zz.clone_el(big))?;
    Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_to_feanor_roundtrip() {
        let original = Scalar::from(123456789u64);
        let big = scalar_to_bigint(&original);
        let recovered = bigint_to_scalar(&big).unwrap();
        assert_eq!(original, recovered);
    }
}
