//! Output types produced by the attestation pipeline.
//!
//! Each pillar emits a single immutable record describing **the
//! referrer blob** as it now exists in the CAS: the digest, the
//! media type to use when registering the OCI 1.1 referrer, and
//! enough metadata for the publish crate to build the referrer
//! descriptor without re-reading the blob.
//!
//! The bytes themselves live in the `Cas`. Consumers fetch them by
//! digest when they need to push to a registry or hand them to
//! cosign-verify.

use cas::Digest;

/// SLSA in-toto Statement referrer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlsaStatement {
    /// Digest of the JSON-serialised in-toto Statement, addressable
    /// in the CAS.
    pub blob_digest: Digest,
    /// Length of the JSON payload in bytes — needed by the publish
    /// crate to fill the OCI descriptor's `size` field.
    pub size: u64,
    /// `application/vnd.in-toto+json` per the in-toto attestation
    /// spec. Stored as a plain string so consumers don't need a
    /// dedicated enum.
    pub media_type: &'static str,
    /// The predicateType URI emitted in the statement (today always
    /// `https://slsa.dev/provenance/v1`). Kept here so publish can
    /// surface it as an OCI referrer annotation without re-parsing
    /// the blob.
    pub predicate_type: &'static str,
}

/// SBOM referrer — CycloneDX or SPDX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sbom {
    pub blob_digest: Digest,
    pub size: u64,
    /// `application/vnd.cyclonedx+json` or
    /// `application/spdx+json`. The format dictates the media type;
    /// callers do not pick.
    pub media_type: SbomMediaType,
}

/// SBOM media type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomMediaType {
    /// `application/vnd.cyclonedx+json` (CycloneDX 1.5).
    CycloneDxJson,
    /// `application/spdx+json` (SPDX 2.3).
    SpdxJson,
}

impl SbomMediaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SbomMediaType::CycloneDxJson => "application/vnd.cyclonedx+json",
            SbomMediaType::SpdxJson => "application/spdx+json",
        }
    }
}

/// Cosign signature referrer.
///
/// The `bundle_digest` addresses the cosign DSSE/bundle blob in the
/// CAS. `rekor_log_index` is the transparency-log entry that
/// confirms the artifact is signed — its presence is mandatory: per
/// spec doc §6, a `Signature` is only constructed when Rekor has
/// confirmed the entry, so receiving a `Signature` value means the
/// artifact is signed. There is no half-state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub bundle_digest: Digest,
    pub size: u64,
    /// Always `application/vnd.dev.cosign.simplesigning.v1+json`
    /// for v0. Stored as a constant for the publish crate.
    pub media_type: &'static str,
    /// Rekor's log index for this entry. Operators use this to look
    /// up the transparency-log record post-hoc.
    pub rekor_log_index: u64,
    /// Identity that signed (OIDC subject for keyless, key
    /// fingerprint or path for keyed).
    pub identity: String,
}

/// Aggregate result of `attest()`. Each field is `Some` if the
/// corresponding pillar ran, `None` if it was opted out via the
/// spec's `Off` variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationOutputs {
    pub slsa: Option<SlsaStatement>,
    pub sbom: Option<Sbom>,
    pub signature: Option<Signature>,
}
