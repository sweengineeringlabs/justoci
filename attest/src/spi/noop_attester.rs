//! Test-double attester. Returns an unsigned sentinel signature.
//!
//! Never valid for real consumers — production verifiers reject
//! `Signature::unsigned()` by design. Used by:
//!
//! - Unit tests that exercise the api/core/saf layers without
//!   requiring cosign or network access.
//! - Integration tests that want to construct an Attestation
//!   without a real signing backend.
//! - Dev-mode builds where signing is intentionally skipped
//!   (operator opts in via an explicit config flag).

use super::Attester;
use crate::api::attestation::Statement;
use crate::api::error::AttestError;
use crate::api::signature::Signature;

/// The test-double attester.
///
/// Records the number of `sign` calls for test assertions.
pub struct NoopAttester {
    signs: std::sync::atomic::AtomicUsize,
}

impl NoopAttester {
    pub fn new() -> Self {
        Self {
            signs: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many times `sign` has been invoked. Useful for tests
    /// that want to assert the facade called through the SPI.
    pub fn sign_count(&self) -> usize {
        self.signs.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for NoopAttester {
    fn default() -> Self {
        Self::new()
    }
}

impl Attester for NoopAttester {
    fn sign(&self, _statement: &Statement) -> Result<Signature, AttestError> {
        self.signs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Signature::unsigned())
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::attestation::{Statement, Subject};
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
        Statement::new(
            Subject {
                name: "example:1.0".into(),
                digest_sha256: "f".repeat(64),
            },
            Predicate::SlsaProvenance(slsa),
        )
        .unwrap()
    }

    #[test]
    fn test_noop_returns_unsigned_sentinel() {
        let a = NoopAttester::new();
        let s = a.sign(&sample_statement()).unwrap();
        assert!(s.is_unsigned());
    }

    #[test]
    fn test_noop_counts_sign_calls() {
        let a = NoopAttester::new();
        assert_eq!(a.sign_count(), 0);
        let _ = a.sign(&sample_statement()).unwrap();
        assert_eq!(a.sign_count(), 1);
        let _ = a.sign(&sample_statement()).unwrap();
        assert_eq!(a.sign_count(), 2);
    }

    #[test]
    fn test_noop_name_is_stable() {
        assert_eq!(NoopAttester::new().name(), "noop");
    }
}
