//! Supply-chain attestation vehicle for vmisolate.
//!
//! Scaffolds ADR-016 pillars B (SLSA provenance) + C (CycloneDX SBOM).
//! Implementation of the full pipelines is follow-up work under #24;
//! this crate provides the api/core/spi/saf shape those PRs land into.
//!
//! # Layout
//!
//! - `api/` — public contracts: [`Attestation`], [`Statement`],
//!   [`Predicate`], [`Signature`], [`AttestError`].
//! - `core/` — pure-Rust builders: [`core::SlsaBuilder`],
//!   [`core::SbomBuilder`]; serialization via [`core::emit_statement`].
//! - `spi/` — signing backends: [`spi::NoopAttester`] (tests),
//!   [`spi::CosignAttester`] (shells out to the cosign CLI).
//! - `saf/` — operator-facing entry: [`saf::attest_build`] drives
//!   the full builder → emitter → signer pipeline.
//!
//! # Quick use
//!
//! ```
//! use attest::{AttestConfig, BuildContext, Subject, attest_build};
//! use attest::spi::NoopAttester;
//! use std::sync::Arc;
//!
//! let ctx = BuildContext {
//!     spec_sha256: "a1b2c3".into(),
//!     builder_id: "https://example.com/ci/run/1".into(),
//!     artifacts: vec![],
//!     packages: vec![],
//!     started_at_unix: 0,
//!     finished_at_unix: 0,
//! };
//!
//! let config = AttestConfig {
//!     subject: Subject {
//!         name: "example:1.0".into(),
//!         digest_sha256: "deadbeef".into(),
//!     },
//!     attester: Arc::new(NoopAttester::new()),
//! };
//!
//! let attestation = attest_build(&ctx, &config).unwrap();
//! assert_eq!(attestation.statement().subject.name, "example:1.0");
//! ```
//!
//! # What's in scope for the scaffold
//!
//! - Real trait surface (no `todo!()` in public fn sigs)
//! - Functional `NoopAttester` for tests
//! - `CosignAttester` that shells out to `cosign attest` when
//!   present; fails with a clear error otherwise
//! - In-toto Statement serialization that produces valid JSON
//!   matching the `https://in-toto.io/Statement/v1` schema
//!
//! # What's NOT in scope (follow-ups under #24)
//!
//! - Reproducibility CI workflow (pillar A — separate PR)
//! - Real SLSA predicate wiring inside `ocimage publish`
//! - CycloneDX schema compliance beyond the top-level shape
//! - Fleet-side verification gate (pull-time cosign verify)
//! - Rekor client (transparency log upload)
//! - Key rotation / KMS integration

pub mod api;
pub mod core;
pub mod spi;
pub mod saf;

// Public re-exports for ergonomic consumer imports.
pub use api::attestation::{Attestation, Statement, Subject};
pub use api::error::AttestError;
pub use api::predicate_type::{Predicate, PredicateType};
pub use api::signature::Signature;
pub use core::slsa_builder::{ArtifactDigest, BuildContext, PackageRecord, SlsaBuilder};
pub use core::sbom_builder::{ComponentInfo, SbomBuilder};
pub use saf::config::AttestConfig;
pub use saf::facade::attest_build;
