//! Statement serialization.
//!
//! Writes an in-toto `Statement` to canonical JSON bytes that
//! consumers hand to a signer. Deterministic — the same Statement
//! input always produces the same output bytes, so a re-attest
//! doesn't churn the registry.

use crate::api::attestation::Statement;
use crate::api::error::AttestError;

/// Serialize a Statement to JSON bytes ready for signing.
///
/// Uses `serde_json::to_vec` (not `to_vec_pretty`) so the output is
/// compact — cosign's DSSE payload hashes the raw bytes, and any
/// whitespace churn would invalidate signatures across otherwise-
/// identical rebuilds.
///
/// Returns [`AttestError::Serialization`] on malformed input —
/// shouldn't fire from well-formed callers.
pub fn emit_statement(statement: &Statement) -> Result<Vec<u8>, AttestError> {
    serde_json::to_vec(statement).map_err(|e| AttestError::Serialization {
        detail: format!("{e}"),
    })
}

/// Write a Statement to a target path. Convenience for test
/// fixtures + offline signing workflows where the signer consumes
/// a file. Always writes the canonical (compact) form.
pub fn write_statement_to_path(
    statement: &Statement,
    path: &std::path::Path,
) -> Result<(), AttestError> {
    let bytes = emit_statement(statement)?;
    std::fs::write(path, bytes).map_err(|e| AttestError::io(e, format!("writing {}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::attestation::Subject;
    use crate::api::predicate_type::Predicate;
    use crate::core::slsa_builder::{BuildContext, SlsaBuilder};

    fn sample_statement() -> Statement {
        let ctx = BuildContext {
            spec_sha256: "abcd".repeat(16),
            builder_id: "https://example.com".into(),
            artifacts: vec![],
            packages: vec![],
            started_at_unix: 0,
            finished_at_unix: 0,
        };
        let slsa = SlsaBuilder::new().build(&ctx).unwrap();
        let subject = Subject {
            name: "example:1.0".into(),
            digest_sha256: "f".repeat(64),
        };
        Statement::new(subject, Predicate::SlsaProvenance(slsa)).unwrap()
    }

    #[test]
    fn test_emit_produces_valid_json() {
        let s = sample_statement();
        let bytes = emit_statement(&s).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            parsed["_type"].as_str().unwrap(),
            "https://in-toto.io/Statement/v1"
        );
        assert_eq!(
            parsed["predicateType"].as_str().unwrap(),
            "https://slsa.dev/provenance/v1"
        );
    }

    #[test]
    fn test_emit_is_deterministic() {
        let s = sample_statement();
        let a = emit_statement(&s).unwrap();
        let b = emit_statement(&s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_write_to_path_produces_same_bytes_as_emit() {
        let s = sample_statement();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("statement.json");
        write_statement_to_path(&s, &path).unwrap();

        let disk_bytes = std::fs::read(&path).unwrap();
        let emit_bytes = emit_statement(&s).unwrap();
        assert_eq!(disk_bytes, emit_bytes);
    }
}
