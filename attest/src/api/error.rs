//! Error surface for the `attest` crate.
//!
//! Errors are flat (no nested enums) so callers can match without
//! chasing trees. Each variant carries enough context for an
//! operator to diagnose without reading the source.

use thiserror::Error;

/// Every failure path surfaced by this crate.
#[derive(Debug, Error)]
pub enum AttestError {
    /// A predicate couldn't be serialized — malformed input (e.g.
    /// non-utf-8 strings in subject name). Should never fire from
    /// well-formed callers; indicates a caller-side bug.
    #[error("predicate serialization failed: {detail}")]
    Serialization { detail: String },

    /// The attester backend failed to sign or attach. Covers:
    /// cosign not on PATH, OIDC handshake failed, registry
    /// auth refused, network error. `detail` carries the
    /// backend's stderr verbatim when available.
    #[error("attester backend failed: {detail}")]
    AttesterFailed { detail: String },

    /// The build context passed to a builder was malformed —
    /// missing required fields, invalid digest format, etc.
    /// Distinct from `Serialization` because the fault is in the
    /// `BuildContext` value, not the serialization step.
    #[error("invalid build context: {reason}")]
    InvalidContext { reason: String },

    /// I/O failure during attestation write (serialization to
    /// disk for offline signing, etc.). Wraps `std::io::Error`
    /// with path context for clearer operator messages.
    #[error("i/o: {detail}")]
    Io {
        #[source]
        source: std::io::Error,
        detail: String,
    },
}

impl AttestError {
    /// Convenience for callers that want to wrap an `io::Error`
    /// with a human-readable path/context string.
    pub fn io(source: std::io::Error, detail: impl Into<String>) -> Self {
        AttestError::Io {
            source,
            detail: detail.into(),
        }
    }
}
