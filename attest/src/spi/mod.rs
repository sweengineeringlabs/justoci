//! Signing backends. One `Attester` trait, two impls (one for
//! production via cosign, one for tests). Future: a raw Ed25519
//! offline signer + a Rekor-uploading variant.

pub mod cosign_attester;
pub mod noop_attester;

pub use cosign_attester::CosignAttester;
pub use noop_attester::NoopAttester;

use crate::api::attestation::Statement;
use crate::api::error::AttestError;
use crate::api::signature::Signature;

/// One signing backend. Takes a Statement, produces a Signature
/// plus (implicitly) whatever side effect the backend does —
/// cosign attaches to an OCI artifact; offline signers write to
/// disk; `NoopAttester` does nothing but return an unsigned
/// sentinel.
///
/// Impls are `Send + Sync` so the facade can hold them behind
/// `Arc<dyn Attester>` without lifetime gymnastics.
pub trait Attester: Send + Sync {
    /// Sign the statement. Implementations may produce side
    /// effects (upload to OCI registry, hit Rekor, write a
    /// sidecar file). Callers pass in the Statement and get back
    /// a Signature opaque enough for downstream verification.
    ///
    /// Passing the statement as `&Statement` (not bytes) is
    /// deliberate: the serializer (`core::emit::emit_statement`)
    /// is authoritative and every impl reads from it, guaranteeing
    /// signed bytes match verified bytes.
    fn sign(&self, statement: &Statement) -> Result<Signature, AttestError>;

    /// Human-readable backend name for error messages + logs.
    /// e.g. `"cosign-keyless"`, `"noop"`. Stable across versions.
    fn name(&self) -> &'static str;
}
