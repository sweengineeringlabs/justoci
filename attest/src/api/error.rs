use spec::SpecError;
use thiserror::Error;

use cas::CasError;

/// Errors raised by the attestation pipeline.
///
/// Variants are split by which pillar failed so the CLI can map onto
/// the spec doc's exit-code table (`AttestError` → exit 3) while
/// still surfacing actionable detail to operators. `SignNotRecorded`
/// is distinct from `SignFailed` because the spec's Production
/// Guarantee §6 says "Sign + Rekor are coupled" — a sign that
/// succeeded but did not record in Rekor is the artifact-is-unsigned
/// state, and operators investigating must see the Rekor-side error
/// rather than a generic "sign failed".
#[derive(Debug, Error)]
pub enum AttestError {
    /// Spec-level error surfaced through attestation. Usually means
    /// the caller passed a `BuiltArtifact` whose embedded `Spec` was
    /// constructed bypassing `parse_and_validate`. Should be rare.
    #[error("spec error during attestation: {0}")]
    Spec(#[from] SpecError),

    /// SLSA statement could not be serialised or written to the CAS.
    /// `source` carries the underlying JSON / CAS / IO error.
    #[error("failed to emit SLSA statement: {source}")]
    SlsaEmit {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// SBOM emission failed for the named format. Distinct variant
    /// per format isn't necessary — `format` carries the discriminator.
    #[error("failed to emit {format} SBOM: {source}")]
    SbomEmit {
        format: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The signer is unavailable.
    ///
    /// On the **sigstore-rs** production path (default feature),
    /// this variant means the OIDC identity token is not configured
    /// — no `SIGSTORE_ID_TOKEN` or `OIDC_TOKEN` env var. The fix is
    /// to provide an OIDC token (e.g. from GitHub Actions ambient
    /// identity, or a Sigstore browser-OIDC flow piped through the
    /// env var) or set `attestation.sign.kind = "off"`.
    ///
    /// On the **cosign-subprocess** fallback path (opt-in via
    /// `--features cosign-subprocess`), this variant means the
    /// `cosign` binary is not on `PATH`. The fix is to install
    /// cosign from <https://github.com/sigstore/cosign> or set
    /// `attestation.sign.kind = "off"`.
    ///
    /// The variant is named `CosignNotInstalled` for source-compat
    /// with v0 (renaming would churn every test using the variant
    /// for no semantic gain). Its Display message covers both
    /// production paths so operators get an actionable hint
    /// regardless of the active feature.
    ///
    /// Distinct from `SignFailed` because there is nothing to
    /// retry — the host configuration is missing.
    #[error(
        "signer unavailable: provide an OIDC token via SIGSTORE_ID_TOKEN or OIDC_TOKEN \
        (sigstore-rs path), OR install cosign on PATH (cosign-subprocess path), \
        OR set attestation.sign.kind = \"off\""
    )]
    CosignNotInstalled,

    /// Cosign returned a non-zero exit code at the signing step
    /// itself (before Rekor coupling). `stderr` is the captured
    /// cosign stderr, trimmed.
    #[error("cosign signing failed: {stderr}")]
    SignFailed { stderr: String },

    /// Cosign signed successfully but the Rekor transparency-log
    /// entry could not be confirmed. Per spec doc §6, this means the
    /// artifact is **not signed** — the caller MUST NOT treat the
    /// signature blob as committed.
    #[error("signature was not recorded in Rekor (artifact is unsigned): {rekor_error}")]
    SignNotRecorded { rekor_error: String },

    /// CAS write failed when storing an attestation blob.
    #[error("cas error: {0}")]
    Cas(#[from] CasError),

    /// Generic IO failure (writing predicate to a temp file for
    /// cosign, etc.).
    #[error("io error during attestation: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },
}

impl From<std::io::Error> for AttestError {
    fn from(source: std::io::Error) -> Self {
        AttestError::Io { source }
    }
}
