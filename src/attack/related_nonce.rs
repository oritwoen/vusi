use super::*;
use crate::math::{scalar_to_decimal_string, mod_inverse, verify_private_key};

pub struct RelatedNonceAttack;

impl Attack for RelatedNonceAttack {
    fn name(&self) -> &'static str {
        "related-nonce"
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
                if let Some(_key) = try_recover_related(&sigs[i], &sigs[i+1], &pubkey) {
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
        try_recover_related(&sigs[0], &sigs[1], &vuln.group.pubkey)
    }
}

fn try_recover_related(sig1: &Signature, sig2: &Signature, pubkey: &Option<String>) -> Option<RecoveredKey> {
    for d in 1..=100 {
        let delta = Scalar::from(d as u64);
        if let Some(priv_key) = solve_linear_relationship(sig1, sig2, delta, Scalar::ONE) {
            return Some(make_recovered_key(priv_key, pubkey.clone()));
        }
    }

    let alphas = [Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
    for alpha in alphas {
        if let Some(priv_key) = solve_linear_relationship(sig1, sig2, Scalar::ZERO, alpha) {
             return Some(make_recovered_key(priv_key, pubkey.clone()));
        }
    }

    None
}

fn solve_linear_relationship(sig1: &Signature, sig2: &Signature, delta: Scalar, alpha: Scalar) -> Option<Scalar> {
    let s1_inv = mod_inverse(&sig1.s)?;

    if alpha == Scalar::ONE {
        let s1_inv_s2 = s1_inv * sig2.s;
        let lhs = (s1_inv_s2 * sig1.r) - sig2.r;
        let rhs = sig2.z - (delta * sig2.s) - (s1_inv_s2 * sig1.z);

        if bool::from(lhs.is_zero()) { return None; }
        let x = rhs * mod_inverse(&lhs)?;
        if verify_private_key(&x, &sig1.r, &sig1.s, &sig1.z, &sig1.pubkey) { return Some(x); }
    } else if bool::from(delta.is_zero()) {
        let as2_inv = mod_inverse(&(alpha * sig2.s))?;
        let lhs = (s1_inv * sig1.r) - (as2_inv * sig2.r);
        let rhs = (as2_inv * sig2.z) - (s1_inv * sig1.z);

        if bool::from(lhs.is_zero()) { return None; }
        let x = rhs * mod_inverse(&lhs)?;
        if verify_private_key(&x, &sig1.r, &sig1.s, &sig1.z, &sig1.pubkey) { return Some(x); }
    }

    None
}

fn make_recovered_key(priv_key: Scalar, pubkey: Option<String>) -> RecoveredKey {
    RecoveredKey {
        private_key: priv_key,
        private_key_decimal: scalar_to_decimal_string(&priv_key),
        pubkey,
    }
}
