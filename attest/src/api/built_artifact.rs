//! Input type passed from `build` to `attest`.
//!
//! `BuiltArtifact` describes the OCI artifact the attestation
//! pipeline is to attest about: the manifest digest (the subject of
//! the SLSA statement, the cosign signature, and the SBOM), the
//! config blob digest, and the per-layer digests in declaration
//! order. Plus the validated `Spec` that produced them and the
//! canonical spec hash.
//!
//! This type is the contract between the build crate (Worker A) and
//! the attest crate (this one). Build constructs one of these on
//! successful build; attest consumes it without touching the
//! filesystem (every byte it needs is already in the digests + the
//! Spec).

use cas::Digest;
use spec::Spec;

/// A successfully-built OCI artifact, ready to be attested.
///
/// Field invariants enforced by the constructor:
/// - `layer_digests.len() == spec.layers.len()`
/// - `layer_digests` is in declaration order (index 0 = first layer).
/// - All digests are sha256 (v0 only).
#[derive(Debug, Clone)]
pub struct BuiltArtifact {
    /// Digest of the OCI manifest blob.
    pub manifest_digest: Digest,
    /// Digest of the OCI config blob.
    pub config_digest: Digest,
    /// One entry per layer, in declaration order. The `usize` is the
    /// layer's position in `spec.layers` — kept explicit so callers
    /// constructing from partial info can't mis-zip the order.
    pub layer_digests: Vec<(usize, Digest)>,
    /// The validated spec that drove the build.
    pub spec: Spec,
    /// Canonical spec hash (`sha256(jcs(spec_to_json(spec)))`).
    /// Computed by the build crate via `spec::spec_hash` and passed
    /// through so the SLSA statement can pin the build to a specific
    /// spec without re-canonicalising.
    pub spec_hash: Digest,
}

impl BuiltArtifact {
    /// Construct a `BuiltArtifact`, validating the layer-digest count.
    ///
    /// Returns `Err` with a descriptive message if `layer_digests`
    /// doesn't match `spec.layers` in length or ordering.
    pub fn new(
        manifest_digest: Digest,
        config_digest: Digest,
        layer_digests: Vec<(usize, Digest)>,
        spec: Spec,
        spec_hash: Digest,
    ) -> Result<Self, BuiltArtifactError> {
        if layer_digests.len() != spec.layers.len() {
            return Err(BuiltArtifactError::LayerCountMismatch {
                spec_layers: spec.layers.len(),
                provided: layer_digests.len(),
            });
        }
        for (expected_idx, (got_idx, _)) in layer_digests.iter().enumerate() {
            if expected_idx != *got_idx {
                return Err(BuiltArtifactError::LayerOrderMismatch {
                    expected_position: expected_idx,
                    got_position: *got_idx,
                });
            }
        }
        Ok(BuiltArtifact {
            manifest_digest,
            config_digest,
            layer_digests,
            spec,
            spec_hash,
        })
    }
}

/// Errors raised by `BuiltArtifact::new` when the build crate hands
/// us inconsistent layer info. These are programming errors at the
/// build/attest boundary, not user-facing — but they're typed rather
/// than panic-ing because the boundary is between two crates and a
/// typed error makes the contract explicit.
#[derive(Debug, thiserror::Error)]
pub enum BuiltArtifactError {
    #[error("layer count mismatch: spec declares {spec_layers} layers, build provided {provided} digests")]
    LayerCountMismatch {
        spec_layers: usize,
        provided: usize,
    },

    #[error("layer order mismatch: expected position {expected_position}, got {got_position}")]
    LayerOrderMismatch {
        expected_position: usize,
        got_position: usize,
    },
}
