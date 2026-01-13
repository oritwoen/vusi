//! Signature data types and grouping logic

use crate::math::{parse_scalar_decimal_strict, ScalarKind};
use anyhow::Result;
use k256::elliptic_curve::ff::PrimeField;
use k256::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.filter(|s| !s.trim().is_empty()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInput {
    pub r: String,
    pub s: String,
    pub z: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub pubkey: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
    pub z: Scalar,
    pub pubkey: Option<String>,
}

impl TryFrom<SignatureInput> for Signature {
    type Error = anyhow::Error;

    fn try_from(input: SignatureInput) -> Result<Self> {
        let r = parse_scalar_decimal_strict(&input.r, ScalarKind::RorS)?;
        let s = parse_scalar_decimal_strict(&input.s, ScalarKind::RorS)?;
        let z = parse_scalar_decimal_strict(&input.z, ScalarKind::Z)?;

        let pubkey = if let Some(pk) = input.pubkey {
            let normalized = normalize_pubkey(Some(&pk));
            if let Some(norm) = &normalized {
                validate_pubkey_hex(norm)?;
            }
            normalized
        } else {
            None
        };

        Ok(Signature { r, s, z, pubkey })
    }
}

pub fn normalize_pubkey(pubkey: Option<&str>) -> Option<String> {
    let p = pubkey?;
    let trimmed = p.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    Some(without_prefix.to_lowercase())
}

fn validate_pubkey_hex(pubkey: &str) -> Result<()> {
    if !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Invalid pubkey: must be hexadecimal");
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SignatureGroup {
    pub r: Scalar,
    pub pubkey: Option<String>,
    pub signatures: Vec<Signature>,
    pub confidence: f64,
}

pub fn group_by_r_and_pubkey(sigs: &[Signature]) -> Vec<SignatureGroup> {
    let mut groups: HashMap<([u8; 32], Option<String>), Vec<Signature>> = HashMap::new();

    for sig in sigs {
        let r_bytes: [u8; 32] = sig.r.to_bytes().into();
        let norm_pubkey = sig.pubkey.clone();

        groups
            .entry((r_bytes, norm_pubkey))
            .or_default()
            .push(sig.clone());
    }

    groups
        .into_iter()
        .map(|((r_bytes, pubkey), signatures)| {
            let r = Option::<Scalar>::from(Scalar::from_repr(r_bytes.into())).unwrap();
            let confidence = if pubkey.is_some() { 1.0 } else { 0.8 };
            SignatureGroup {
                r,
                pubkey,
                signatures,
                confidence,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_input_parse_decimal() {
        let input = SignatureInput {
            r: "6819641642398093696120236467967538361543858578256722584730163952555838220871"
                .to_string(),
            s: "5111069398017465712735164463809304352000044522184731945150717785434666956473"
                .to_string(),
            z: "4834837306435966184874350434501389872155834069808640791394730023708942795899"
                .to_string(),
            pubkey: None,
        };
        let sig = Signature::try_from(input).unwrap();
        assert!(!bool::from(sig.r.is_zero()));
    }

    #[test]
    fn test_group_by_r_and_pubkey_same_pubkey() {
        let input1 = SignatureInput {
            r: "123".to_string(),
            s: "456".to_string(),
            z: "789".to_string(),
            pubkey: Some("02abcdef".to_string()),
        };
        let input2 = SignatureInput {
            r: "123".to_string(),
            s: "111".to_string(),
            z: "222".to_string(),
            pubkey: Some("02abcdef".to_string()),
        };

        let sig1 = Signature::try_from(input1).unwrap();
        let sig2 = Signature::try_from(input2).unwrap();

        let groups = group_by_r_and_pubkey(&[sig1, sig2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].signatures.len(), 2);
        assert_eq!(groups[0].confidence, 1.0);
    }

    #[test]
    fn test_group_by_r_and_pubkey_none_pubkey() {
        let input1 = SignatureInput {
            r: "123".to_string(),
            s: "456".to_string(),
            z: "789".to_string(),
            pubkey: None,
        };
        let input2 = SignatureInput {
            r: "123".to_string(),
            s: "111".to_string(),
            z: "222".to_string(),
            pubkey: None,
        };

        let sig1 = Signature::try_from(input1).unwrap();
        let sig2 = Signature::try_from(input2).unwrap();

        let groups = group_by_r_and_pubkey(&[sig1, sig2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].signatures.len(), 2);
        assert_eq!(groups[0].confidence, 0.8);
    }

    #[test]
    fn test_group_by_r_and_pubkey_different_pubkey() {
        let input1 = SignatureInput {
            r: "123".to_string(),
            s: "456".to_string(),
            z: "789".to_string(),
            pubkey: Some("02abcdef".to_string()),
        };
        let input2 = SignatureInput {
            r: "123".to_string(),
            s: "111".to_string(),
            z: "222".to_string(),
            pubkey: Some("03fedcba".to_string()),
        };

        let sig1 = Signature::try_from(input1).unwrap();
        let sig2 = Signature::try_from(input2).unwrap();

        let groups = group_by_r_and_pubkey(&[sig1, sig2]);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_pubkey_normalization_case_insensitive() {
        let input1 = SignatureInput {
            r: "123".to_string(),
            s: "456".to_string(),
            z: "789".to_string(),
            pubkey: Some("02ABCDEF".to_string()),
        };
        let input2 = SignatureInput {
            r: "123".to_string(),
            s: "111".to_string(),
            z: "222".to_string(),
            pubkey: Some("02abcdef".to_string()),
        };

        let sig1 = Signature::try_from(input1).unwrap();
        let sig2 = Signature::try_from(input2).unwrap();

        let groups = group_by_r_and_pubkey(&[sig1, sig2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].signatures.len(), 2);
    }

    #[test]
    fn test_pubkey_normalization_0x_prefix() {
        let input1 = SignatureInput {
            r: "123".to_string(),
            s: "456".to_string(),
            z: "789".to_string(),
            pubkey: Some("0x02abcdef".to_string()),
        };
        let input2 = SignatureInput {
            r: "123".to_string(),
            s: "111".to_string(),
            z: "222".to_string(),
            pubkey: Some("02abcdef".to_string()),
        };

        let sig1 = Signature::try_from(input1).unwrap();
        let sig2 = Signature::try_from(input2).unwrap();

        let groups = group_by_r_and_pubkey(&[sig1, sig2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].signatures.len(), 2);
    }
}
