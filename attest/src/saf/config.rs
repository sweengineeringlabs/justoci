//! Caller configuration for `attest_build`.

use std::sync::Arc;

use crate::api::attestation::Subject;
use crate::spi::Attester;

/// Caller-supplied config for one attestation run.
///
/// Keeps the subject (what's being certified) + the attester
/// (how it gets signed) together so `attest_build` has one
/// argument to thread through.
#[derive(Clone)]
pub struct AttestConfig {
    /// The subject being attested — its name (typically the image
    /// reference) + content digest.
    pub subject: Subject,

    /// Signing backend. Injected by the caller so tests can use
    /// `NoopAttester` without compile-time feature flags. Held
    /// behind `Arc` so the facade can clone-and-ship without
    /// requiring `Attester: Clone` on impls.
    pub attester: Arc<dyn Attester>,
}

impl std::fmt::Debug for AttestConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestConfig")
            .field("subject", &self.subject)
            .field("attester_name", &self.attester.name())
            .finish()
    }
}
