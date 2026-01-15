//! Mathematical utilities for ECDSA operations

use anyhow::{anyhow, bail, Result};
use k256::elliptic_curve::ff::PrimeField;
use k256::Scalar;
use num_bigint::BigUint;
use num_traits::Num;

pub enum ScalarKind {
    RorS,
    Z,
}

pub fn parse_scalar_decimal_strict(s: &str, kind: ScalarKind) -> Result<Scalar> {
    if s.is_empty() {
        bail!("Empty decimal string");
    }
    if !s.chars().all(|c| c.is_ascii_digit()) {
        bail!("Invalid decimal string: only digits 0-9 allowed");
    }
    if s.len() > 1 && s.starts_with('0') {
        bail!("Invalid decimal string: no leading zeros allowed");
    }

    let biguint =
        BigUint::from_str_radix(s, 10).map_err(|e| anyhow!("Failed to parse decimal: {}", e))?;

    let n = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    if biguint >= n {
        bail!("Value >= secp256k1 order n, ensure your data is already reduced");
    }

    let bytes = biguint.to_bytes_be();
    if bytes.len() > 32 {
        bail!("Value too large for Scalar");
    }

    let mut padded = [0u8; 32];
    let offset = 32 - bytes.len();
    padded[offset..].copy_from_slice(&bytes);

    let scalar = Option::<Scalar>::from(Scalar::from_repr(padded.into()))
        .ok_or_else(|| anyhow!("Invalid scalar representation"))?;

    match kind {
        ScalarKind::RorS => {
            if bool::from(scalar.is_zero()) {
                bail!("r and s values cannot be zero");
            }
        }
        ScalarKind::Z => {}
    }

    Ok(scalar)
}

pub fn scalar_to_decimal_string(scalar: &Scalar) -> String {
    let bytes = scalar.to_bytes();
    let biguint = BigUint::from_bytes_be(&bytes);
    biguint.to_string()
}

pub fn mod_inverse(a: &Scalar) -> Option<Scalar> {
    a.invert().into()
}

pub fn recover_nonce(z1: &Scalar, z2: &Scalar, s1: &Scalar, s2: &Scalar) -> Option<Scalar> {
    let ds = *s1 - *s2;
    if bool::from(ds.is_zero()) {
        return None;
    }
    let dz = *z1 - *z2;
    let ds_inv = mod_inverse(&ds)?;
    Some(dz * ds_inv)
}

pub fn recover_private_key(r: &Scalar, s: &Scalar, z: &Scalar, k: &Scalar) -> Option<Scalar> {
    let r_inv = mod_inverse(r)?;
    Some((*s * *k - *z) * r_inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scalar_decimal_strict_valid() {
        let s = parse_scalar_decimal_strict(
            "6819641642398093696120236467967538361543858578256722584730163952555838220871",
            ScalarKind::RorS,
        )
        .unwrap();
        assert!(!bool::from(s.is_zero()));
    }

    #[test]
    fn test_parse_scalar_decimal_strict_rejects_zero_for_r_s() {
        let result = parse_scalar_decimal_strict("0", ScalarKind::RorS);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scalar_decimal_strict_allows_zero_for_z() {
        let result = parse_scalar_decimal_strict("0", ScalarKind::Z);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scalar_to_decimal_roundtrip() {
        let original =
            "35027840177330064405683178523079910253772859809146826320797401203281604260438";
        let scalar = parse_scalar_decimal_strict(original, ScalarKind::RorS).unwrap();
        let back = scalar_to_decimal_string(&scalar);
        assert_eq!(back, original);
    }

    #[test]
    fn test_mod_inverse() {
        let a = parse_scalar_decimal_strict("12345", ScalarKind::RorS).unwrap();
        let inv = mod_inverse(&a).unwrap();
        let product = a * inv;
        assert_eq!(product, Scalar::ONE);
    }

    #[test]
    fn test_recover_private_key_real_tx() {
        let r = parse_scalar_decimal_strict(
            "6819641642398093696120236467967538361543858578256722584730163952555838220871",
            ScalarKind::RorS,
        )
        .unwrap();
        let s1 = parse_scalar_decimal_strict(
            "5111069398017465712735164463809304352000044522184731945150717785434666956473",
            ScalarKind::RorS,
        )
        .unwrap();
        let z1 = parse_scalar_decimal_strict(
            "4834837306435966184874350434501389872155834069808640791394730023708942795899",
            ScalarKind::Z,
        )
        .unwrap();
        let s2 = parse_scalar_decimal_strict(
            "31133511789966193434473156682648022965280901634950536313584626906865295404159",
            ScalarKind::RorS,
        )
        .unwrap();
        let z2 = parse_scalar_decimal_strict(
            "108808786585075507407446857551522706228868950080801424952567576192808212665067",
            ScalarKind::Z,
        )
        .unwrap();

        let k = recover_nonce(&z1, &z2, &s1, &s2).unwrap();

        let priv_key1 = recover_private_key(&r, &s1, &z1, &k).unwrap();
        let priv_key2 = recover_private_key(&r, &s2, &z2, &k).unwrap();

        let expected =
            "62958994860637178871299877498639209302063112480839791435318431648713002718353";

        let result1 = scalar_to_decimal_string(&priv_key1);
        let result2 = scalar_to_decimal_string(&priv_key2);

        assert_eq!(
            result1, expected,
            "Signature 1 should recover the private key"
        );
        assert_eq!(
            result2, expected,
            "Signature 2 should recover the same private key"
        );
    }

    #[test]
    fn test_parse_scalar_rejects_z_ge_n() {
        let n_decimal =
            "115792089237316195423570985008687907852837564279074904382605163141518161494337";
        let result = parse_scalar_decimal_strict(n_decimal, ScalarKind::Z);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("secp256k1 order"));
    }
}
