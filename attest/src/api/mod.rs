//! Public contracts for the `attest` crate — the things downstream
//! consumers see.
//!
//! Types here are stable across SPI swaps: swapping `NoopAttester`
//! for `CosignAttester` never changes these signatures.

pub mod attestation;
pub mod error;
pub mod predicate_type;
pub mod signature;
