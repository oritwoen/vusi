//! ECDSA signature vulnerability analysis library
//!
//! This library provides tools for detecting and exploiting vulnerabilities
//! in ECDSA signatures, focusing on nonce reuse attacks.

pub mod attack;
pub mod math;
pub mod provider;
pub mod signature;

pub use attack::Attack;
pub use signature::{Signature, SignatureInput};
