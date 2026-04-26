//! Error types for ocimage.

/// Errors raised by the image-build pipeline.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Filesystem / process-spawn / read-write failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration or CLI-argument error that's the user's
    /// fault, not a bug. Maps to a non-zero CLI exit code with
    /// `message` printed verbatim to stderr.
    #[error("configuration error: {message}")]
    Config { message: String },

    /// A spec TOML file failed to parse, OR passed parsing but
    /// failed semantic validation (e.g., non-empty `packages`
    /// list in Phase 2f-α). `reason` names the specific field.
    #[error("invalid image spec: {reason}")]
    SpecInvalid { reason: String },

    /// The base rootfs file referenced by the spec isn't on the
    /// filesystem. Usually a typo in `base.path` or a missing
    /// `bootstrap.sh` run.
    #[error("base rootfs not found: {path}")]
    BaseRootfsNotFound { path: String },

    /// The kernel bzImage the build pipeline needs to stage
    /// isn't where we expected. Same cause as `BaseRootfsNotFound`
    /// — the `bootstrap.sh` step didn't run or produced files
    /// in a different layout.
    #[error("kernel not found: {path} — run bootstrap.sh to produce it")]
    KernelNotFound { path: String },

    /// Initrd construction failed inside the `userspace` crate
    /// (cpio writer, xkvm-fs binary read, config.json generation).
    #[error("initrd construction failed: {reason}")]
    Initrd { reason: String },

    /// A package manager rejected a package list. Not emitted in
    /// Phase 2f-α (package install is stubbed). `family` is the
    /// installer family (`apk` / `apt` / …); `packages` is the
    /// argv it tried; `reason` is the tool's stderr tail.
    #[error("{family} failed to install {packages:?}: {reason}")]
    Package {
        family: &'static str,
        packages: Vec<String>,
        reason: String,
    },

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
    /// is down." Only emitted by the Level 4 push path.
    #[error("registry {registry} unreachable: {reason}")]
    RegistryUnreachable { registry: String, reason: String },

    /// Host-side chroot substrate failure — surfaces mount, exec,
    /// copy_in, or write_file errors from the `chroot` crate. Only
    /// emitted by the Phase 2f-α+ package-install / file-overlay
    /// paths.
    #[error("chroot: {0}")]
    Chroot(#[from] chroot::ChrootError),
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
    fn test_io_error_wraps_source() {
        let err = Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing",
        ));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_spec_invalid_display_carries_reason() {
        let err = Error::SpecInvalid {
            reason: "packages field unsupported in 2f-α".into(),
        };
        assert!(err.to_string().contains("packages field unsupported"));
    }

    #[test]
    fn test_base_rootfs_not_found_display_carries_path() {
        let err = Error::BaseRootfsNotFound {
            path: "/nonexistent.ext4".into(),
        };
        assert!(err.to_string().contains("/nonexistent.ext4"));
    }

    #[test]
    fn test_package_error_includes_family_and_packages() {
        let err = Error::Package {
            family: super::super::manifest::INSTALLER_FAMILY_ALPINE_APK,
            packages: vec!["foo".into(), "bar".into()],
            reason: "mirror down".into(),
        };
        let s = err.to_string();
        assert!(s.contains("alpine_apk"));
        assert!(s.contains("foo"));
        assert!(s.contains("mirror down"));
    }
}
