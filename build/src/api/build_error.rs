//! Typed errors for the spec-driven build pipeline.
//!
//! Distinct from the legacy [`crate::api::error::Error`] so that
//! callers matching on a build-side failure see only build-side
//! variants — no `Publish` / `RegistryUnreachable` arms surfacing
//! from a function that never publishes anything.
//!
//! Every variant carries enough context for an operator to act
//! without re-running the build:
//!
//! - Layer-position errors name the offending layer's index so the
//!   operator can find it in the spec.
//! - I/O variants always include the absolute path that failed.
//! - The `Spec` and `Cas` wrappers preserve their underlying
//!   thiserror sources so chained `Display` walks render the full
//!   reason.

use std::path::PathBuf;

use thiserror::Error;

/// Errors raised by the spec-driven build pipeline.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The input spec failed to parse / validate. Wraps the spec
    /// crate's typed error so the offending TOML field surfaces
    /// unchanged. Should never occur in practice when callers obtain
    /// the `Spec` via `spec::parse_and_validate`, but the variant
    /// exists so a future spec-loading layer (e.g. canonicalisation
    /// for the SLSA statement) can surface its own validation errors
    /// through the same enum.
    #[error("spec error: {0}")]
    Spec(#[from] spec::SpecError),

    /// Compressing layer #`position` failed. The wrapped IO error
    /// carries the underlying cause (disk full, encoder rejected
    /// input, etc.).
    #[error("layer #{position} compression failed: {source}")]
    LayerCompression {
        position: usize,
        #[source]
        source: std::io::Error,
    },

    /// Writing the layer blob to the CAS failed. `position` ties the
    /// failure to a spec layer; the wrapped `cas::CasError` carries
    /// the underlying cause (digest mismatch, disk full, etc.).
    #[error("layer #{position} write to cas failed: {source}")]
    LayerWrite {
        position: usize,
        #[source]
        source: cas::CasError,
    },

    /// Building a deterministic tar from `[[layers.files]]` failed.
    /// `position` is the spec layer; the wrapped error carries the
    /// underlying cause (source file unreadable, tar header
    /// construction error, etc.).
    #[error("layer #{position} tar build failed: {source}")]
    TarBuild {
        position: usize,
        #[source]
        source: std::io::Error,
    },

    /// Writing the manifest, config blob, or `index.json` failed.
    /// Distinct from `LayerWrite` so a config / manifest issue
    /// surfaces in the error message rather than a generic write
    /// failure.
    #[error("oci manifest / config / index write failed: {source}")]
    ManifestWrite {
        #[source]
        source: cas::CasError,
    },

    /// I/O error reading or writing a file outside the CAS — the
    /// `oci-layout` marker, `index.json`, or rename of the partial
    /// directory. `path` names the file that failed.
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Serialising the OCI manifest / config / index to JSON failed.
    /// Distinct from `Io` so callers can tell "couldn't serialise"
    /// from "couldn't write the bytes."
    #[error("json serialisation failed: {source}")]
    Json {
        #[source]
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_layer_compression_display_includes_position() {
        // Bug this would catch: a `Display` impl that drops the
        // `position` field, leaving operators with "layer compression
        // failed" but no way to know which layer (vm_image has 3).
        let err = BuildError::LayerCompression {
            position: 2,
            source: io::Error::other("broken pipe"),
        };
        let s = err.to_string();
        assert!(s.contains("#2"), "missing layer position in: {s}");
        assert!(s.contains("compression"), "missing variant tag in: {s}");
    }

    #[test]
    fn test_io_variant_carries_path() {
        // Bug this would catch: using `Error::Io(io::Error)` without
        // the path — operator gets "no such file or directory" with
        // no way to know which file.
        let err = BuildError::Io {
            path: PathBuf::from("/nonexistent/index.json"),
            source: io::Error::new(io::ErrorKind::NotFound, "missing"),
        };
        let s = err.to_string();
        assert!(s.contains("/nonexistent/index.json"));
    }

    #[test]
    fn test_spec_error_chains_through() {
        // Bug this would catch: a refactor that wraps `SpecError` in
        // `Display`-only text loses the underlying span info that
        // points at the offending TOML line. The `#[from]` source
        // chain must stay intact.
        let spec_err = spec::SpecError::UnknownKind {
            got: "bogus".into(),
        };
        let build_err: BuildError = spec_err.into();
        // `source()` should walk to the underlying SpecError so
        // formatters that follow chains print the full reason.
        let s = build_err.to_string();
        assert!(s.contains("bogus"), "spec error text not threaded: {s}");
    }

    #[test]
    fn test_tar_build_display_includes_position_and_source() {
        // Bug this would catch: the tar variant printing only the
        // position OR only the source — operators need both ("which
        // layer" + "what went wrong").
        let err = BuildError::TarBuild {
            position: 0,
            source: io::Error::new(io::ErrorKind::PermissionDenied, "EACCES on /etc"),
        };
        let s = err.to_string();
        assert!(s.contains("#0"));
        assert!(s.contains("EACCES"));
    }
}
