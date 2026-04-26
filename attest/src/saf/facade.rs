//! One-call pipeline: `BuildContext` + `AttestConfig` -> `Attestation`.
//!
//! Stages:
//! 1. Build an SLSA predicate from the BuildContext.
//! 2. Construct a Statement binding Subject + predicate.
//! 3. Hand the Statement to the configured Attester (noop or cosign).
//! 4. Wrap both into an Attestation.
//!
//! Pure composition — no new logic, just sequences the layers.

use crate::api::attestation::{Attestation, Statement};
use crate::api::error::AttestError;
use crate::api::predicate_type::Predicate;
use crate::core::slsa_builder::{BuildContext, SlsaBuilder};
use crate::saf::config::AttestConfig;

/// Run the full SLSA-provenance attestation pipeline.
///
/// The pipeline is:
///
/// ```text
///   BuildContext  ──►  SlsaBuilder  ──►  SlsaProvenance
///                                              │
///                          Subject  ───────────┤
///                                              ▼
///                                          Statement
///                                              │
///                                    Attester::sign
///                                              │
///                                              ▼
///                                         Signature
///                                              │
///                          combine with Statement
///                                              │
///                                              ▼
///                                         Attestation
/// ```
///
/// Returns [`AttestError::InvalidContext`] if the `BuildContext`
/// or Subject is malformed, [`AttestError::AttesterFailed`] if
/// the signing backend refused.
pub fn attest_build(
    ctx: &BuildContext,
    config: &AttestConfig,
) -> Result<Attestation, AttestError> {
    tracing::debug!(
        target: "attest::saf",
        attester = config.attester.name(),
        subject = %config.subject.name,
        "building SLSA attestation"
    );

    let slsa = SlsaBuilder::new().build(ctx)?;
    let statement = Statement::new(
        config.subject.clone(),
        Predicate::SlsaProvenance(slsa),
    )?;
    let signature = config.attester.sign(&statement)?;

    Ok(Attestation::new(statement, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::attestation::Subject;
    use crate::api::predicate_type::PredicateType;
    use crate::core::slsa_builder::{ArtifactDigest, PackageRecord};
    use crate::spi::NoopAttester;
    use std::sync::Arc;

    fn sample_ctx() -> BuildContext {
        BuildContext {
            spec_sha256: "abcd".repeat(16),
            builder_id: "https://example.com/ci/run/1".into(),
            artifacts: vec![ArtifactDigest {
                name: "kernel".into(),
                sha256: "dead".repeat(16),
            }],
            packages: vec![PackageRecord {
                name: "ca-certificates".into(),
                version: "20230506-r0".into(),
                family: "apk".into(),
            }],
            started_at_unix: 1_700_000_000,
            finished_at_unix: 1_700_000_010,
        }
    }

    fn sample_config() -> AttestConfig {
        AttestConfig {
            subject: Subject {
                name: "example:1.0".into(),
                digest_sha256: "f".repeat(64),
            },
            attester: Arc::new(NoopAttester::new()),
        }
    }

    #[test]
    fn test_facade_produces_attestation_with_slsa_predicate() {
        let att = attest_build(&sample_ctx(), &sample_config()).unwrap();
        assert_eq!(
            att.statement().predicate_type,
            PredicateType::SlsaProvenance.uri()
        );
        assert_eq!(att.statement().subject.name, "example:1.0");
        // NoopAttester emits the unsigned sentinel.
        assert!(att.signature().is_unsigned());
    }

    #[test]
    fn test_facade_propagates_invalid_context() {
        let mut ctx = sample_ctx();
        ctx.builder_id = "".into();
        let err = attest_build(&ctx, &sample_config()).unwrap_err();
        match err {
            AttestError::InvalidContext { reason } => {
                assert!(reason.contains("builder_id"));
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn test_facade_propagates_malformed_subject_digest() {
        let mut cfg = sample_config();
        cfg.subject.digest_sha256 = "not-hex".into();
        let err = attest_build(&sample_ctx(), &cfg).unwrap_err();
        match err {
            AttestError::InvalidContext { reason } => {
                assert!(reason.contains("64") || reason.contains("hex"));
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn test_facade_invokes_attester_exactly_once() {
        // We can't peek inside Arc<dyn Attester>, so construct
        // a concrete NoopAttester Arc and keep a typed clone for
        // inspection. Arc::clone is cheap.
        let noop = Arc::new(NoopAttester::new());
        let config = AttestConfig {
            subject: Subject {
                name: "example:1.0".into(),
                digest_sha256: "a".repeat(64),
            },
            attester: noop.clone(),
        };
        let _ = attest_build(&sample_ctx(), &config).unwrap();
        assert_eq!(noop.sign_count(), 1);
    }

    #[test]
    fn test_facade_records_builder_id_in_statement() {
        let att = attest_build(&sample_ctx(), &sample_config()).unwrap();
        // The SLSA builder_id should round-trip through into the
        // predicate.
        let json = serde_json::to_string(&att.statement().predicate).unwrap();
        assert!(json.contains("https://example.com/ci/run/1"));
    }
}
