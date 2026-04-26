//! Output of a successful spec-driven build.

use std::path::PathBuf;

use cas::Digest;

/// Result of [`crate::saf::build::build`].
///
/// The on-disk layout under `output_dir` is a complete OCI Image
/// Layout v1.1 tree:
///
/// ```text
/// <output_dir>/
/// ├── oci-layout
/// ├── index.json
/// └── blobs/sha256/
///     ├── <layer1-digest>
///     ├── …
///     ├── <config-digest>
///     └── <manifest-digest>
/// ```
///
/// The `manifest_digest` is what downstream consumers (registries,
/// `oras pull`, `crane pull`) will refer to as the artifact's
/// content-addressable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildOutput {
    /// Digest of the OCI image manifest blob. Stable across re-runs
    /// for the same `Spec` (Production-Guarantees-§2).
    pub manifest_digest: Digest,
    /// Digest of the OCI image config blob.
    pub config_digest: Digest,
    /// Digests of the layer blobs in the manifest's `layers[]` order.
    pub layer_digests: Vec<Digest>,
    /// The directory that holds the final layout. Always equal to
    /// the `output_dir` argument the caller passed to `build`.
    pub output_dir: PathBuf,
}
