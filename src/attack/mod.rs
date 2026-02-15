//! Attack detection and exploitation traits

use crate::signature::{Signature, SignatureGroup};
use k256::Scalar;

pub mod nonce_reuse;
pub mod related_nonce;
pub mod half_half;
pub mod lcg;
pub mod timing;

pub use nonce_reuse::NonceReuseAttack;
pub use related_nonce::RelatedNonceAttack;
pub use half_half::HalfHalfAttack;
pub use lcg::LcgAttack;
pub use timing::TimingAttack;

pub trait Attack: Send + Sync {
    fn name(&self) -> &'static str;
    fn min_signatures(&self) -> usize;
    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability>;
    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey>;
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub attack_type: String,
    pub group: SignatureGroup,
}

#[derive(Debug, Clone)]
pub struct RecoveredKey {
    pub private_key: Scalar,
    pub private_key_decimal: String,
    pub pubkey: Option<String>,
}
