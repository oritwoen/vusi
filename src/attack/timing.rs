use super::*;

pub struct TimingAttack;

impl Attack for TimingAttack {
    fn name(&self) -> &'static str {
        "timing"
    }

    fn min_signatures(&self) -> usize {
        10
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        let sigs_with_timing: Vec<&Signature> = signatures.iter().filter(|s| s.timing.is_some()).collect();
        if sigs_with_timing.len() < self.min_signatures() {
            return vec![];
        }

        let timings: Vec<f64> = sigs_with_timing.iter().map(|s| s.timing.unwrap() as f64).collect();
        let mean = timings.iter().sum::<f64>() / timings.len() as f64;
        let variance = timings.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / timings.len() as f64;
        let std_dev = variance.sqrt();

        if mean > 0.0 && std_dev / mean > 0.05 {
            return vec![Vulnerability {
                attack_type: self.name().to_string(),
                group: SignatureGroup {
                    r: signatures[0].r,
                    pubkey: None,
                    signatures: signatures.to_vec(),
                    confidence: 0.5,
                },
            }];
        }

        vec![]
    }

    fn recover(&self, _vuln: &Vulnerability) -> Option<RecoveredKey> {
        None
    }
}
