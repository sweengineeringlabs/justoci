//! `oci-publish` — ship a built vmisolate VM image to a sink.
//!
//! Two entry points, matching ADR-015's level split:
//!
//! * [`publish_http`] — Level 2: write an `index.json` + content-addressed
//!   blobs under a local directory. Pair with any static HTTP host.
//! * [`push_oci`] — Level 4: push as an OCI artifact to any
//!   distribution-spec registry (GHCR, Harbor, ECR, …).
//!
//! Split out of the former `ocimage` crate in the 2f-δ refactor;
//! depends on `oci-build` for the shared `BuildArtifacts` + `Error`
//! types so build and publish can be composed without a circular dep.

mod spi;
mod saf;

/// Pragmatic one-error model: both crates surface the same `Error`
/// enum so CLI callers match on one shape. The canonical definition
/// lives in `oci-build`; `oci-publish` re-exports it.
pub use oci_build::api::error::Error;

pub use saf::*;
