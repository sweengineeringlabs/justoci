//! Pure-Rust builders for SLSA provenance + CycloneDX SBOM predicates.
//!
//! No I/O, no subprocess, no network. Each builder transforms a
//! well-typed input (`BuildContext`, `ComponentInfo` list) into a
//! predicate value ready for embedding in a Statement. The SPI
//! layer handles signing + attachment.

pub mod emit;
pub mod sbom_builder;
pub mod slsa_builder;
