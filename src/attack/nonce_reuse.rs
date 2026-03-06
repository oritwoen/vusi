//! Nonce reuse attack implementation

use super::*;
use crate::math::{
    recover_nonce, recover_private_key, scalar_to_decimal_string, scalar_to_hex_string,
};
use crate::signature::group_by_r_and_pubkey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint};

pub struct NonceReuseAttack;

impl Attack for NonceReuseAttack {
    fn name(&self) -> &'static str {
        "nonce-reuse"
    }

    fn min_signatures(&self) -> usize {
        2
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        group_by_r_and_pubkey(signatures)
            .into_iter()
            .filter(|g| g.signatures.len() >= 2)
            .map(|group| Vulnerability {
                attack_type: self.name().to_string(),
                group,
            })
            .collect()
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        let sigs = &vuln.group.signatures;
        if sigs.len() < 2 {
            return None;
        }

        for i in 0..sigs.len() {
            for j in (i + 1)..sigs.len() {
                if let Some(key) = try_recover_pair(&sigs[i], &sigs[j], &vuln.group.pubkey) {
                    return Some(key);
                }
            }
        }
        None
    }
}

fn try_recover_pair(
    sig1: &Signature,
    sig2: &Signature,
    pubkey: &Option<String>,
) -> Option<RecoveredKey> {
    if pubkey.is_some() {
        // With pubkey: try both s2 polarities and verify d*G == pubkey.
        // Handles mixed low-s/high-s normalization (BIP62).
        for &s2 in &[sig2.s, -sig2.s] {
            let k = match recover_nonce(&sig1.z, &sig2.z, &sig1.s, &s2) {
                Some(k) => k,
                None => continue,
            };
            let priv_key = match recover_private_key(&sig1.r, &sig1.s, &sig1.z, &k) {
                Some(d) => d,
                None => continue,
            };
            if verify_key_matches_pubkey(&priv_key, pubkey.as_ref().unwrap()) {
                return Some(RecoveredKey {
                    private_key: priv_key,
                    private_key_decimal: scalar_to_decimal_string(&priv_key),
                    private_key_hex: scalar_to_hex_string(&priv_key),
                    pubkey: pubkey.clone(),
                });
            }
        }
        None
    } else {
        let k = recover_nonce(&sig1.z, &sig2.z, &sig1.s, &sig2.s)?;
        let priv_key = recover_private_key(&sig1.r, &sig1.s, &sig1.z, &k)?;
        Some(RecoveredKey {
            private_key: priv_key,
            private_key_decimal: scalar_to_decimal_string(&priv_key),
            private_key_hex: scalar_to_hex_string(&priv_key),
            pubkey: pubkey.clone(),
        })
    }
}

fn verify_key_matches_pubkey(d: &Scalar, pubkey: &str) -> bool {
    let computed = ProjectivePoint::GENERATOR * *d;
    let affine: AffinePoint = computed.into();
    let compressed = hex::encode(affine.to_encoded_point(true).as_bytes());
    let uncompressed = hex::encode(affine.to_encoded_point(false).as_bytes());
    let pk = pubkey.to_lowercase();
    pk == compressed || pk == uncompressed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SignatureInput;

    fn make_test_signatures() -> Vec<Signature> {
        vec![
            Signature::try_from(SignatureInput {
                r: "6819641642398093696120236467967538361543858578256722584730163952555838220871"
                    .into(),
                s: "5111069398017465712735164463809304352000044522184731945150717785434666956473"
                    .into(),
                z: "4834837306435966184874350434501389872155834069808640791394730023708942795899"
                    .into(),
                pubkey: None,
                timestamp: None,
                kp: None,
            })
            .unwrap(),
            Signature::try_from(SignatureInput {
                r: "6819641642398093696120236467967538361543858578256722584730163952555838220871"
                    .into(),
                s: "31133511789966193434473156682648022965280901634950536313584626906865295404159"
                    .into(),
                z: "108808786585075507407446857551522706228868950080801424952567576192808212665067"
                    .into(),
                pubkey: None,
                timestamp: None,
                kp: None,
            })
            .unwrap(),
        ]
    }

    #[test]
    fn test_nonce_reuse_detection() {
        let sigs = make_test_signatures();
        let attack = NonceReuseAttack;
        let vulns = attack.detect(&sigs);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].attack_type, "nonce-reuse");
    }

    #[test]
    fn test_nonce_reuse_recovery_real_tx() {
        let sigs = make_test_signatures();
        let attack = NonceReuseAttack;
        let vulns = attack.detect(&sigs);
        let recovered = attack.recover(&vulns[0]).unwrap();

        let expected =
            "62958994860637178871299877498639209302063112480839791435318431648713002718353";
        assert_eq!(recovered.private_key_decimal, expected);
    }

    #[test]
    fn test_nonce_reuse_recovery_with_pubkey_verification() {
        use k256::elliptic_curve::ff::PrimeField;

        let d = Scalar::from(42u64);
        let pubkey_point = (ProjectivePoint::GENERATOR * d).to_affine();
        let pubkey_hex = hex::encode(pubkey_point.to_encoded_point(true).as_bytes());

        let k = Scalar::from(1000u64);
        let z1 = Scalar::from(111u64);
        let z2 = Scalar::from(222u64);

        let kg = ProjectivePoint::GENERATOR * k;
        let r = Scalar::from_repr_vartime(*kg.to_affine().to_encoded_point(false).x().unwrap())
            .unwrap();

        let k_inv = Option::<Scalar>::from(k.invert()).unwrap();
        let s1 = k_inv * (z1 + r * d);
        let s2 = k_inv * (z2 + r * d);

        let sigs = vec![
            Signature {
                r,
                s: s1,
                z: z1,
                pubkey: Some(pubkey_hex.clone()),
                timestamp: None,
                kp: None,
            },
            Signature {
                r,
                s: s2,
                z: z2,
                pubkey: Some(pubkey_hex.clone()),
                timestamp: None,
                kp: None,
            },
        ];

        let attack = NonceReuseAttack;
        let vulns = attack.detect(&sigs);
        assert_eq!(vulns.len(), 1);

        let recovered = attack.recover(&vulns[0]).unwrap();
        assert_eq!(recovered.private_key, d);
    }

    #[test]
    fn test_nonce_reuse_recovery_negated_s_with_pubkey() {
        use k256::elliptic_curve::ff::PrimeField;

        let d = Scalar::from(42u64);
        let pubkey_point = (ProjectivePoint::GENERATOR * d).to_affine();
        let pubkey_hex = hex::encode(pubkey_point.to_encoded_point(true).as_bytes());

        let k = Scalar::from(1000u64);
        let z1 = Scalar::from(111u64);
        let z2 = Scalar::from(222u64);

        let kg = ProjectivePoint::GENERATOR * k;
        let r = Scalar::from_repr_vartime(*kg.to_affine().to_encoded_point(false).x().unwrap())
            .unwrap();

        let k_inv = Option::<Scalar>::from(k.invert()).unwrap();
        let s1 = k_inv * (z1 + r * d);
        let s2_raw = k_inv * (z2 + r * d);
        // Negate s2 to simulate mixed low-s/high-s normalization (BIP62)
        let s2_negated = -s2_raw;

        let sigs = vec![
            Signature {
                r,
                s: s1,
                z: z1,
                pubkey: Some(pubkey_hex.clone()),
                timestamp: None,
                kp: None,
            },
            Signature {
                r,
                s: s2_negated,
                z: z2,
                pubkey: Some(pubkey_hex.clone()),
                timestamp: None,
                kp: None,
            },
        ];

        let attack = NonceReuseAttack;
        let vulns = attack.detect(&sigs);
        assert_eq!(vulns.len(), 1);

        let recovered = attack.recover(&vulns[0]);
        assert!(
            recovered.is_some(),
            "Should recover key even with negated s when pubkey is available"
        );
        assert_eq!(recovered.unwrap().private_key, d);
    }

    #[test]
    fn test_no_false_positives_different_r() {
        let sigs = vec![
            Signature::try_from(SignatureInput {
                r: "123".into(),
                s: "456".into(),
                z: "789".into(),
                pubkey: None,
                timestamp: None,
                kp: None,
            })
            .unwrap(),
            Signature::try_from(SignatureInput {
                r: "999".into(),
                s: "111".into(),
                z: "222".into(),
                pubkey: None,
                timestamp: None,
                kp: None,
            })
            .unwrap(),
        ];
        let attack = NonceReuseAttack;
        let vulns = attack.detect(&sigs);
        assert!(vulns.is_empty());
    }
}
