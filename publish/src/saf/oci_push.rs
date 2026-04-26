//! SAF facade for `ocimage push` — the ADR-015 **Level 4** (OCI
//! distribution spec) push path.
//!
//! Thin wrapper: load artifacts from disk, spin up a scoped tokio
//! runtime, and drive the async [`OciPusher`] SPI to completion.
//! The runtime is single-shot — the CLI is sync, the push is async
//! one-shot, and we don't want a long-lived executor loitering in
//! the process.

use std::path::Path;

use serde::Serialize;

use oci_build::api::error::Error;
use oci_build::api::spec::BuildArtifacts;
use crate::spi::image_publisher::oci_pusher::OciPusher;

/// What a successful `push_oci` call produced.
#[derive(Debug, Clone, Serialize)]
pub struct OciPushSummary {
    /// The OCI reference that was pushed (e.g.
    /// `ghcr.io/acme/vmisolate-alpine:3.20`). Echoed so callers /
    /// CI can log it without re-parsing the CLI argv.
    pub reference: String,
    /// sha256 digest of the uploaded OCI artifact manifest. This
    /// is the immutable pointer tenants should pin in production —
    /// the tag is a mutable alias.
    pub manifest_digest: String,
    /// Bytes actually transferred to the registry (blob sizes that
    /// the registry didn't already have via cross-repo mount).
    /// In Phase 2f-β we cannot cheaply distinguish cross-mounted
    /// blobs from fresh uploads, so this is reported as the honest
    /// upper bound: `kernel + initrd + rootfs + config` summed.
    pub bytes_pushed: u64,
}

/// Push the artifacts under `build_dir` to an OCI-distribution
/// registry at `reference`. Auth: anonymous by default; basic auth
/// via `OCIMAGE_REGISTRY_USER` + `OCIMAGE_REGISTRY_PASSWORD`.
pub fn push_oci(build_dir: &Path, reference: &str) -> Result<OciPushSummary, Error> {
    let artifacts = BuildArtifacts::load_from_dir(build_dir)?;
    let pusher = OciPusher::new();

    // New per-call runtime: the CLI is synchronous and this is a
    // one-shot RPC. Multi-threaded `new()` so the `oci-distribution`
    // + `reqwest` tasks don't contend on a single-thread scheduler
    // under chunked uploads.
    let runtime = tokio::runtime::Runtime::new().map_err(Error::Io)?;
    runtime.block_on(pusher.push(&artifacts, reference))
}
