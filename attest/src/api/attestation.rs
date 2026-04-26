//! Core attestation types.
//!
//! An `Attestation` is a [`Statement`] + a [`Signature`]. The
//! `Statement` follows the in-toto `https://in-toto.io/Statement/v1`
//! schema — `{ _type, subject, predicateType, predicate }`. The
//! `Signature` is whatever the SPI backend produced (cosign blob,
//! offline key signature, etc.).

use serde::{Deserialize, Serialize};

use super::predicate_type::Predicate;
use super::signature::Signature;

/// Subject of an attestation — what's being certified.
///
/// Keyed by content digest, not by name or tag. A tag can be
/// reassigned; a digest is immutable. `name` is carried for
/// human-readable context only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    /// Human-readable name. For OCI artifacts: the reference
    /// (e.g. `ghcr.io/acme/llmboot:0.1.14`). For local builds:
    /// the `image_id` from the spec.
    pub name: String,

    /// SHA-256 digest, hex-encoded lowercase, no `sha256:` prefix.
    /// Matches the on-disk `blobs/sha256/<hex>` naming convention
    /// used by the publish crate.
    pub digest_sha256: String,
}

/// In-toto Statement — the signed payload.
///
/// The `_type` field is hardcoded to the in-toto v1 schema URI.
/// `predicate_type` names which concrete schema the predicate
/// follows (SLSA v1, CycloneDX v1.5, custom). `predicate` is the
/// opaque payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    /// Statement schema URI. Always
    /// `https://in-toto.io/Statement/v1` for this crate.
    #[serde(rename = "_type")]
    pub type_uri: String,

    /// Subject — typically a single artifact. In-toto permits
    /// arrays; we keep it to one for simplicity.
    pub subject: Subject,

    /// URI naming the schema of `predicate`. See
    /// [`super::predicate_type::PredicateType`] for the values
    /// this crate knows about.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,

    /// The actual claim — SLSA provenance body, CycloneDX SBOM
    /// body, etc. Opaque at this layer.
    pub predicate: Predicate,
}

impl Statement {
    /// Canonical `_type` value for every Statement this crate
    /// produces. Exposed as a pub const so tests can assert
    /// against it without hard-coding the literal.
    pub const TYPE_URI: &'static str = "https://in-toto.io/Statement/v1";

    /// Build a fresh Statement. Validates that the subject digest
    /// is non-empty + hex-ish (64 chars). Returns
    /// [`AttestError::InvalidContext`] on malformed input.
    pub fn new(
        subject: Subject,
        predicate: Predicate,
    ) -> Result<Self, super::error::AttestError> {
        if subject.digest_sha256.is_empty() {
            return Err(super::error::AttestError::InvalidContext {
                reason: "subject.digest_sha256 is empty".into(),
            });
        }
        if subject.digest_sha256.len() != 64
            || !subject
                .digest_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(super::error::AttestError::InvalidContext {
                reason: format!(
                    "subject.digest_sha256 must be 64 lowercase hex chars; got {:?}",
                    subject.digest_sha256
                ),
            });
        }

        Ok(Self {
            type_uri: Self::TYPE_URI.to_string(),
            predicate_type: predicate.predicate_type_uri().to_string(),
            subject,
            predicate,
        })
    }
}

/// A signed attestation — Statement plus its Signature.
///
/// Consumers treat this as opaque: they hand it to a verifier that
/// checks the signature against a trust policy. Only the verifier
/// looks inside.
#[derive(Debug, Clone)]
pub struct Attestation {
    statement: Statement,
    signature: Signature,
}

impl Attestation {
    /// Build an Attestation from a verified-by-the-attester pair.
    /// The SPI backend is the only caller; no public constructor
    /// without going through [`super::super::spi::Attester`].
    pub fn new(statement: Statement, signature: Signature) -> Self {
        Self { statement, signature }
    }

    /// The signed Statement. Callers typically use this for
    /// verification or logging; the raw JSON bytes live in the
    /// Signature's covered payload.
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// The signature over the Statement. Verifiers use this plus
    /// a trust policy to accept or reject the attestation.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::predicate_type::{Predicate, PredicateType};
    use crate::core::slsa_builder::SlsaProvenance;

    fn sample_subject(digest: &str) -> Subject {
        Subject {
            name: "example:1.0".into(),
            digest_sha256: digest.into(),
        }
    }

    fn sample_predicate() -> Predicate {
        Predicate::SlsaProvenance(SlsaProvenance::default())
    }

    #[test]
    fn test_statement_new_accepts_valid_hex_digest() {
        let digest = "a".repeat(64);
        let s = Statement::new(sample_subject(&digest), sample_predicate()).unwrap();
        assert_eq!(s.type_uri, Statement::TYPE_URI);
        assert_eq!(
            s.predicate_type,
            PredicateType::SlsaProvenance.uri()
        );
    }

    #[test]
    fn test_statement_new_rejects_empty_digest() {
        let err = Statement::new(sample_subject(""), sample_predicate()).unwrap_err();
        match err {
            crate::api::error::AttestError::InvalidContext { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn test_statement_new_rejects_short_digest() {
        let err = Statement::new(sample_subject("abcdef"), sample_predicate()).unwrap_err();
        match err {
            crate::api::error::AttestError::InvalidContext { reason } => {
                assert!(reason.contains("64"));
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn test_statement_new_rejects_non_hex_digest() {
        // 64 chars but contains non-hex
        let bad = "z".repeat(64);
        let err = Statement::new(sample_subject(&bad), sample_predicate()).unwrap_err();
        match err {
            crate::api::error::AttestError::InvalidContext { reason } => {
                assert!(reason.contains("hex"));
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn test_statement_serializes_with_in_toto_keys() {
        let digest = "f".repeat(64);
        let s = Statement::new(sample_subject(&digest), sample_predicate()).unwrap();
        let json = serde_json::to_string(&s).unwrap();
        // In-toto schema uses `_type` and `predicateType` — preserved
        // through serde rename attrs.
        assert!(json.contains(r#""_type":"https://in-toto.io/Statement/v1""#));
        assert!(json.contains(r#""predicateType""#));
        assert!(json.contains(r#""subject""#));
    }
}
