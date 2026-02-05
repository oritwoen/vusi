//! Attack detection and exploitation traits

use crate::signature::{Signature, SignatureGroup};
use k256::Scalar;

pub mod nonce_reuse;
pub use nonce_reuse::NonceReuseAttack;

#[cfg(feature = "biased-nonce")]
pub mod biased_nonce;
#[cfg(feature = "biased-nonce")]
pub use biased_nonce::BiasedNonceAttack;

#[cfg(feature = "polynonce")]
pub mod polynonce;
#[cfg(feature = "polynonce")]
pub use polynonce::PolynonceAttack;

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
