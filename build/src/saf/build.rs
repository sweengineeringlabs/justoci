//! Public `build` entry point.
//!
//! ## Atomicity contract (Production-Guarantees-§6)
//!
//! - All output goes to `<output_dir>.partial` first.
//! - On success, `.partial` is renamed to `<output_dir>`.
//! - On failure, `.partial` stays where it is and the function
//!   returns the typed error. No half-written `<output_dir>` ever
//!   appears — consumer tools can rely on its presence implying
//!   "complete, self-consistent output."
//!
//! Within `.partial` we stage:
//!
//! ```text
//! <output_dir>.partial/
//!   blobs/sha256/...     ← FsCas
//!   oci-layout
//!   index.json
//! ```
//!
//! `FsCas` itself uses tmp + rename for each blob, so partial blobs
//! never become visible inside `blobs/sha256/` even within a build
//! that ultimately fails.
//!
//! ## Idempotence
//!
//! Re-building into a directory whose `.partial` sibling already
//! exists overwrites the partial state. Re-building into a
//! directory that already exists at the final path is the caller's
//! choice — we DO NOT silently delete it. The contract is "successful
//! build means no partial state exists"; an existing complete output
//! is a deliberate decision (overwrite vs. fail) that belongs at the
//! CLI layer.

use std::fs;
use std::path::{Path, PathBuf};

use cas::FsCas;
use spec::LoadedSpec;

use crate::api::build_error::BuildError;
use crate::api::build_output::BuildOutput;
use crate::api::oci_manifest::{
    OciDescriptor, OciIndex, OciLayout, MEDIA_TYPE_OCI_INDEX,
};
use crate::core::layer::assemble_layer;
use crate::core::oci_assembly::{
    assemble_config_and_manifest, check_layer_count_post_assembly,
};

/// Build an OCI Image Layout v1.1 from a `LoadedSpec`.
///
/// `LoadedSpec` carries the spec together with the directory its
/// relative layer source paths anchor against — this is the explicit
/// contract that replaces the earlier heuristic. Callers that
/// construct an in-memory `Spec` with absolute layer paths still
/// work: `LoadedSpec::resolve` is a no-op for absolute paths.
///
/// `output_dir` MUST NOT already exist as the final destination —
/// the function refuses to overwrite a complete directory. If the
/// caller wants to rebuild, they must remove the old directory
/// first. (`<output_dir>.partial` from an earlier failed run IS
/// overwritten — that's expected recovery behaviour.)
///
/// On success returns the digests of the manifest, config, and each
/// layer in spec order.
///
/// On failure returns a typed `BuildError` and leaves
/// `<output_dir>.partial` on disk for diagnosis. The final
/// `<output_dir>` is never created on a failed build.
pub fn build(
    loaded: &LoadedSpec,
    output_dir: &Path,
) -> Result<BuildOutput, BuildError> {
    if output_dir.exists() {
        return Err(BuildError::Io {
            path: output_dir.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "output_dir already exists; remove it before rebuilding",
            ),
        });
    }

    let spec = &loaded.spec;
    let spec_dir = &loaded.spec_dir;

    let partial = partial_path(output_dir);
    // Drop any stale partial from an earlier failed run; per the
    // doc-comment this is the expected recovery behaviour.
    if partial.exists() {
        fs::remove_dir_all(&partial).map_err(|source| BuildError::Io {
            path: partial.clone(),
            source,
        })?;
    }
    fs::create_dir_all(&partial).map_err(|source| BuildError::Io {
        path: partial.clone(),
        source,
    })?;

    // The `FsCas` lays down `<partial>/blobs/sha256/...` exactly the
    // way OCI Image Layout requires.
    let cas = FsCas::new(&partial).map_err(|source| BuildError::ManifestWrite { source })?;

    // ── Layers ────────────────────────────────────────────────
    let mut layer_descriptors: Vec<OciDescriptor> = Vec::with_capacity(spec.layers.len());
    let mut layer_digests = Vec::with_capacity(spec.layers.len());
    for (position, layer) in spec.layers.iter().enumerate() {
        let result = assemble_layer(layer, position, spec_dir, &cas)?;
        layer_descriptors.push(result.descriptor);
        layer_digests.push(result.digest);
    }
    check_layer_count_post_assembly(spec.kind, layer_descriptors.len())?;

    // ── Config + manifest ────────────────────────────────────
    let assembled = assemble_config_and_manifest(spec, layer_descriptors, &cas)?;

    // ── oci-layout marker ────────────────────────────────────
    let layout_path = partial.join("oci-layout");
    let layout_bytes =
        serde_json::to_vec(&OciLayout::pinned()).map_err(|source| BuildError::Json { source })?;
    fs::write(&layout_path, &layout_bytes).map_err(|source| BuildError::Io {
        path: layout_path.clone(),
        source,
    })?;

    // ── index.json ───────────────────────────────────────────
    let index = OciIndex {
        schema_version: 2,
        media_type: MEDIA_TYPE_OCI_INDEX.to_string(),
        manifests: vec![assembled.manifest_descriptor.clone()],
        annotations: Default::default(),
    };
    let index_bytes =
        serde_json::to_vec(&index).map_err(|source| BuildError::Json { source })?;
    let index_path = partial.join("index.json");
    fs::write(&index_path, &index_bytes).map_err(|source| BuildError::Io {
        path: index_path.clone(),
        source,
    })?;

    // ── Promote partial to final ──────────────────────────────
    // This is the atomic flip: until this rename succeeds, no
    // consumer that polls for `output_dir` sees anything.
    fs::rename(&partial, output_dir).map_err(|source| BuildError::Io {
        path: output_dir.to_path_buf(),
        source,
    })?;

    Ok(BuildOutput {
        manifest_digest: assembled.manifest_digest,
        config_digest: assembled.config_digest,
        layer_digests,
        output_dir: output_dir.to_path_buf(),
    })
}

fn partial_path(output_dir: &Path) -> PathBuf {
    let mut s = output_dir.as_os_str().to_owned();
    s.push(".partial");
    PathBuf::from(s)
}
