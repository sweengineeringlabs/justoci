//! SAF facade layer (L4) for `oci-publish`.
//!
//! Two entry points, one per publish level. Each is a thin adapter
//! around the matching SPI impl — load `BuildArtifacts` from disk,
//! delegate, return a summary DTO.

mod attestation;
mod http_publish;
mod oci_push;

pub use attestation::{
    attest_build_dir, sbom_from_build_dir, write_attestation_statement, AttestMode,
    AttestationError,
};
pub use http_publish::{publish_http, HttpPublishSummary};
pub use oci_push::{push_oci, OciPushSummary};
