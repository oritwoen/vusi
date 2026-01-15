#![cfg(feature = "polynonce")]

// Spike validation for feanor-math on secp256k1 order `n`.
//
// Copied from `src/math.rs` (secp256k1 order constant, hex, lines 28-31).
// Toolchain: rustc 1.92.0 (ded5c06cf 2025-12-08) (Arch Linux rust 1:1.92.0-1).

use feanor_math::algorithms::poly_factor::FactorPolyField;
use feanor_math::field::FieldStore;
use feanor_math::homomorphism::Homomorphism;
use feanor_math::integer::IntegerRingStore;
use feanor_math::pid::EuclideanRingStore;
use feanor_math::ring::{RingExtensionStore, RingStore};
use feanor_math::rings::poly::dense_poly::DensePolyRing;
use feanor_math::rings::poly::PolyRingStore;
use feanor_math::rings::rust_bigint::RustBigintRing;
use feanor_math::rings::zn::zn_big::Zn;
use feanor_math::rings::zn::ZnRingStore;
use k256::elliptic_curve::ff::PrimeField;
use k256::Scalar;

const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

type BigIntElement = <<RustBigintRing as RingStore>::Type as feanor_math::ring::RingBase>::Element;

fn secp256k1_order_bigint() -> BigIntElement {
    let zz = RustBigintRing::RING;
    zz.parse(SECP256K1_ORDER_HEX, 16)
        .expect("SECP256K1_ORDER_HEX should parse as base-16 BigInt")
}

fn bigint_from_be_bytes(bytes: &[u8]) -> BigIntElement {
    let zz = RustBigintRing::RING;

    let base = zz.int_hom().map(256);
    let mut acc = zz.zero();
    for &b in bytes {
        acc = zz.add(zz.mul(acc, zz.clone_el(&base)), zz.int_hom().map(b as i32));
    }
    acc
}

fn bigint_to_be_bytes_fixed_32(mut x: BigIntElement) -> [u8; 32] {
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

    let mut out = [0u8; 32];
    let start = 32 - tmp.len();
    out[start..].copy_from_slice(&tmp);
    out
}

#[test]
fn spike_secp256k1_order_as_field_is_ok() {
    let zz = RustBigintRing::RING;
    let n = secp256k1_order_bigint();
    let zn = Zn::new(zz, n);

    assert!(
        zn.as_field().is_ok(),
        "secp256k1 order n should be prime (field conversion must succeed)"
    );
}

#[test]
fn spike_construct_modulus_from_hex_bigint() {
    let zz = RustBigintRing::RING;

    let n_from_hex = zz.parse(SECP256K1_ORDER_HEX, 16).unwrap();

    // n is 256-bit (definitely larger than u64)
    assert!(
        zz.abs_highest_set_bit(&n_from_hex).unwrap() >= 255,
        "expected n to be at least 256-bit"
    );
}

#[test]
fn spike_create_polynomial_x_minus_known_root_over_field() {
    let zz = RustBigintRing::RING;
    let n = secp256k1_order_bigint();
    let zn = Zn::new(zz, n);
    let fp = zn.as_field().unwrap();

    let poly_ring = DensePolyRing::new(&fp, "X");

    let root = fp.int_hom().map(12345);
    let minus_root = fp.negate(fp.clone_el(&root));

    // f(X) = X - root
    let f = poly_ring.from_terms([(minus_root, 0), (poly_ring.base_ring().one(), 1)]);

    assert_eq!(Some(1), poly_ring.degree(&f));
}

#[test]
fn spike_factor_linear_polynomial_and_recover_root() {
    let zz = RustBigintRing::RING;
    let n = secp256k1_order_bigint();
    let zn = Zn::new(zz, n);
    let fp = zn.as_field().unwrap();

    let poly_ring = DensePolyRing::new(&fp, "X");

    let root = fp.int_hom().map(4242);
    let minus_root = fp.negate(fp.clone_el(&root));

    // f(X) = X - root
    let f = poly_ring.from_terms([(minus_root, 0), (poly_ring.base_ring().one(), 1)]);

    let (factors, unit) = <_ as FactorPolyField>::factor_poly(&poly_ring, &f);

    assert!(
        fp.is_one(&unit),
        "expected monic linear polynomial to factor with unit 1"
    );
    assert_eq!(1, factors.len());
    assert_eq!(Some(1), poly_ring.degree(&factors[0].0));

    // For aX + b, root = -b/a
    let factor = &factors[0].0;
    let b = poly_ring.coefficient_at(factor, 0);
    let a = poly_ring.coefficient_at(factor, 1);
    let recovered = fp.negate(fp.div(&b, &a));

    assert!(fp.eq_el(&root, &recovered));
}

#[test]
fn spike_roundtrip_k256_scalar_through_feanor_bigint_bytes() {
    // Scalar -> bytes -> feanor BigInt -> bytes -> Scalar
    let original = Scalar::from(123456789u64);
    let original_bytes = original.to_bytes();

    let big = bigint_from_be_bytes(&original_bytes);
    let roundtrip_bytes = bigint_to_be_bytes_fixed_32(big);

    let recovered = Option::<Scalar>::from(Scalar::from_repr(roundtrip_bytes.into()))
        .expect("roundtrip bytes should represent a valid k256::Scalar");

    assert_eq!(original, recovered);
}
