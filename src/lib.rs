//! Function-Hiding Inner Product Encryption (FH-IPE) - Practical construction
//!
//! This crate provides a readable, pragmatic implementation of a function-hiding inner
//! product encryption scheme inspired by Kim et al., "Function-Hiding Inner Product
//! Encryption is Practical" (ePrint 2016/440). It uses the Arkworks ecosystem with
//! the BLS12-381 pairing-friendly curve for high performance.
//!
//! Design choices:
//! - Pairing group: BLS12-381 (fast, widely used)
//! - Simplicity/readability first; API exposes vectors as slices of field elements
//! - Focuses on integer vectors represented modulo the scalar field Fr
//! - Not constant-time across all code paths; do not use for production without a security review
//!
//! Minimal API:
//! - setup: generates public parameters
//! - keygen: produces a function key for vector x
//! - encrypt: encrypts vector y into a ciphertext
//! - decrypt: recovers <x, y> in the scalar field when both are in correct domain

pub mod types;
pub mod util;
pub mod ipe;

pub use ipe::{decrypt, encrypt, keygen, setup};
pub use types::{Ciphertext, FunctionKey, PublicParams, MasterSecretKey};