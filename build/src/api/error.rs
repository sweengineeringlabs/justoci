//! Legacy error type kept so sibling crates (`oci-publish`, the
//! `cli`) continue to compile while their own refactors land. New
//! pipeline code uses [`crate::api::build_error::BuildError`].
//!
//! Variants here are pruned: `Chroot`, `Initrd`, `Package`,
//! `BaseRootfsNotFound`, and `KernelNotFound` were tied to the
//! vmisolate-coupled image builder that moved out of this crate.
//! The remaining variants are still used by external consumers and
//! the surviving shape preserves their field layouts so callers
//! match exactly as before.

/// Errors raised by legacy publish / artifact-loading paths.
///
/// The new spec-driven build pipeline returns
/// [`crate::api::build_error::BuildError`] instead. The two enums
/// are intentionally distinct: an operator looking at a typed
/// error should see "this came from the build pipeline" or "this
/// came from the publish pipeline" without ambiguity.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Filesystem / process-spawn / read-write failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration or CLI-argument error that's the user's fault,
    /// not a bug. Maps to a non-zero CLI exit code with `message`
    /// printed verbatim to stderr.
    #[error("configuration error: {message}")]
    Config { message: String },

    /// A spec TOML file failed to parse, OR passed parsing but
    /// failed semantic validation. `reason` names the specific field.
    #[error("invalid image spec: {reason}")]
    SpecInvalid { reason: String },

    /// Serde-layer failure — TOML parse or JSON write. Forwarded
    /// from the underlying library so callers can match on it
    /// to distinguish a malformed spec from a semantic-validation
    /// rejection (`SpecInvalid`).
    #[error("serde error: {0}")]
    Serde(String),

    /// A `BuildArtifacts::load_from_dir` call couldn't find one of
    /// the expected files (`kernel`, `initrd.cpio`, `config.json`).
    /// `which` names the missing artifact; `dir` is the directory
    /// the caller pointed at.
    #[error("build artifact missing: {which} not found under {dir}")]
    ArtifactMissing { which: &'static str, dir: String },

    /// Generic publish/push failure. `reason` is the specific
    /// cause (digest mismatch, manifest rejected, auth failed, …).
    /// Both `HttpPublisher` (Level 2) and `OciPusher` (Level 4)
    /// funnel here so CLI callers get one error shape to match on.
    #[error("publish failed: {reason}")]
    Publish { reason: String },

    /// The OCI registry couldn't be reached — DNS, TLS, HTTP 5xx,
    /// or auth-token exchange failed. Distinct from `Publish` so
    /// operators can tell "my image is wrong" from "the registry
    /// is down."
    #[error("registry {registry} unreachable: {reason}")]
    RegistryUnreachable { registry: String, reason: String },
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Serde(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_display_mentions_io() {
        // Bug this would catch: a refactor that swaps the `Display`
        // string and breaks CLI output that grep-matches on "I/O".
        let err = Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing",
        ));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_spec_invalid_display_carries_reason() {
        // Bug this would catch: a `Display` impl that forgets to
        // include the `reason` field, leaving operators with a
        // useless "invalid image spec:" message.
        let err = Error::SpecInvalid {
            reason: "packages field unsupported".into(),
        };
        assert!(err.to_string().contains("packages field unsupported"));
    }

    #[test]
    fn test_serde_from_toml_round_trips_error_text() {
        // Bug this would catch: the `From<toml::de::Error>` impl
        // dropping the underlying parser message, leaving callers
        // unable to point at the offending TOML line.
        let bad_toml = "spec_version = \n";
        let toml_err = toml::from_str::<toml::Value>(bad_toml).unwrap_err();
        let toml_err_text = toml_err.to_string();
        let our_err: Error = toml_err.into();
        match our_err {
            Error::Serde(msg) => assert_eq!(msg, toml_err_text),
            other => panic!("expected Error::Serde, got {other:?}"),
        }
    }

    #[test]
    fn test_artifact_missing_carries_which_and_dir() {
        // Bug this would catch: a regression that prints the dir
        // but not the missing artifact name (or vice-versa) — the
        // operator wouldn't know whether to fix the path or rerun
        // the previous build step.
        let err = Error::ArtifactMissing {
            which: "kernel",
            dir: "/tmp/out".into(),
        };
        let s = err.to_string();
        assert!(s.contains("kernel"));
        assert!(s.contains("/tmp/out"));
    }
}
