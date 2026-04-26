//! Public API layer (L2).
//!
//! New spec-driven surface lives in `build_error`, `build_output`,
//! and `oci_manifest`. Legacy types under `error`, `spec`, and
//! `manifest` are kept as plain serde data so sibling crates
//! (`oci-publish`, the `cli`) compile while their refactors land.

pub mod build_error;
pub mod build_output;
pub mod oci_manifest;

pub mod error;
pub mod manifest;
pub mod spec;
