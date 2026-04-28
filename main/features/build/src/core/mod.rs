//! Core (L3) — pure pipeline logic. No I/O outside the `Cas` and
//! the spec-anchored source paths.

pub mod layer;
pub mod oci_assembly;
pub mod tar_builder;
