//! SAF facade for `ocimage publish-http` — the ADR-015 **Level 2**
//! (HTTP index + content-addressed blobs) publish path.
//!
//! This is the thin L4 adapter: parse the on-disk `BuildArtifacts`
//! directory, delegate to the `HttpPublisher` SPI impl, return a
//! `HttpPublishSummary` that both the CLI and library callers can
//! consume.

use std::path::{Path, PathBuf};

use serde::Serialize;

use oci_build::api::error::Error;
use oci_build::api::spec::BuildArtifacts;
use crate::spi::image_publisher::http_publisher::HttpPublisher;

/// What a successful `publish_http` call produced. Printed to the
/// CLI (as JSON on `--json`, or a summary line otherwise) and
/// returned to library callers so they can feed it into a CD
/// pipeline — e.g. emit a Slack message with `index_path`.
#[derive(Debug, Clone, Serialize)]
pub struct HttpPublishSummary {
    /// The image id that was published — mirrors the `id` field of
    /// the `ImageSpec` (e.g. `alpine:3.20`). Carried through so
    /// `ocimage build && ocimage publish-http` can be composed
    /// without the caller re-reading the config.
    pub image_id: String,
    /// Absolute path to the `index.json` that was written / updated.
    pub index_path: PathBuf,
    /// Count of blobs under `<output>/blobs/sha256/` that belong
    /// to this publish call (3 if rootfs-less, 4 with rootfs).
    pub blob_count: usize,
    /// Sum of `kernel + initrd + rootfs + config` bytes on disk.
    /// Operators watch this to size `[fleet.images].max_cache_bytes`.
    pub total_bytes: u64,
}

/// Publish the artifacts under `build_dir` into a Level-2-compatible
/// layout under `output_dir`. Idempotent per ADR-015: if
/// `output_dir/index.json` already has an entry for the same image
/// id, it's replaced in place; blobs are content-addressed so an
/// unchanged build is a no-op on disk.
pub fn publish_http(
    build_dir: &Path,
    output_dir: &Path,
) -> Result<HttpPublishSummary, Error> {
    let artifacts = BuildArtifacts::load_from_dir(build_dir)?;
    let publisher = HttpPublisher::new(output_dir.to_path_buf());
    publisher.publish(&artifacts)
}
