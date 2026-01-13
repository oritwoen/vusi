//! ECDSA signature vulnerability analysis library
//!
//! This library provides tools for detecting and exploiting vulnerabilities
//! in ECDSA signatures, focusing on nonce reuse attacks.

pub mod signature;
pub mod math;
pub mod attack;
pub mod provider;

pub use signature::{Signature, SignatureInput};
pub use attack::Attack;
