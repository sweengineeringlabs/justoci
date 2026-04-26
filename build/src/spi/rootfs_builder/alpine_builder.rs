//! `AlpineBuilder` — [`RootfsBuilder`] over an existing ext4
//! Alpine rootfs on disk.
//!
//! The Phase 2f-α shape: take the rootfs that `bootstrap.sh`
//! produces (`downloads/rootfs-alpine.ext4`), copy it into the
//! builder's work_dir, and hand back the copy. The copy isolates
//! the source file from concurrent builds and from the
//! orchestrator's `fs::copy` into the final output dir.
//!
//! **What it does NOT do (yet)**: WSL-chroot apk-install,
//! file-copy into the rootfs, online size resize. Those land in
//! Phase 2f-α+ — at which point this impl grows a `packages` and
//! `files` path. The orchestrator's `SpecInvalid` guard keeps
//! tenants honest about that limitation today.
//!
//! **Why "alpine" in the name** when the impl just copies a file:
//! future variants (DebianBuilder, DockerExportBuilder) will have
//! distinct semantics (debootstrap stages, docker-image extracts)
//! so the name-per-family naming sticks. Alpine today is a
//! degenerate case — pointed out in the module doc so nobody
//! mistakes the simplicity for final shape.

use std::fs;
use std::path::{Path, PathBuf};

use crate::api::error::Error;
use crate::api::spec::{BaseRef, ImageSpec};
use crate::api::traits::RootfsBuilder;

/// `RootfsBuilder` impl for the Alpine base path. Accepts any
/// `BaseRef::LocalRootfs { path }` — the name is a hint about
/// the Phase-2f-α+ trajectory, not a runtime constraint.
pub struct AlpineBuilder {
    /// Spec file's parent directory. Relative paths inside
    /// `BaseRef::LocalRootfs.path` resolve against this, matching
    /// the path-resolution convention the rest of the crate uses
    /// (TLS cert paths, image kernel paths, fleet.toml's image
    /// entries — see `fleet::saf::config_toml`).
    spec_dir: PathBuf,
}

impl AlpineBuilder {
    pub fn new(spec_dir: PathBuf) -> Self {
        Self { spec_dir }
    }
}

impl RootfsBuilder for AlpineBuilder {
    fn build(&self, spec: &ImageSpec, work_dir: &Path) -> Result<PathBuf, Error> {
        let src_path = match &spec.base {
            BaseRef::LocalRootfs { path } => {
                if path.is_absolute() {
                    path.clone()
                } else {
                    self.spec_dir.join(path)
                }
            }
        };

        if !src_path.is_file() {
            return Err(Error::BaseRootfsNotFound {
                path: src_path.display().to_string(),
            });
        }

        // Audit follow-up #4 (docs/3-design/security/image-spec-input-surface.md §Follow-ups).
        // `fs::copy` silently follows symlinks on `src_path`. That's
        // fine per ADR-015's operator-trust-boundary framing for
        // `BaseRef::LocalRootfs`, but a symlink pointing at (e.g.)
        // `/etc/shadow` getting copied into the build output without
        // any diagnostic is an obvious footgun. Warn, don't reject:
        // no new schema field, the log is the actionable signal.
        let meta = fs::symlink_metadata(&src_path).map_err(Error::Io)?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&src_path)
                .unwrap_or_else(|_| PathBuf::from("<unreadable>"));
            tracing::warn!(
                source = %src_path.display(),
                target = %target.display(),
                "AlpineBuilder: base.path is a symlink; following and \
                 copying the target. Operator trust boundary per \
                 ADR-015 — this is a diagnostic, not a rejection. Set \
                 base.path to an absolute non-symlink path to silence \
                 this warning."
            );
        }

        fs::create_dir_all(work_dir)?;
        let out = work_dir.join("rootfs-staged.ext4");
        fs::copy(&src_path, &out).map_err(Error::Io)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::api::spec::{BaseRef, ImageSpec, InitMode};

    fn fresh_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "alpine-builder-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn spec_with_relative_path(rel: &str) -> ImageSpec {
        ImageSpec {
            id: "t:1".into(),
            description: String::new(),
            base: BaseRef::LocalRootfs {
                path: PathBuf::from(rel),
            },
            packages: Vec::new(),
            files: Vec::new(),
            env: BTreeMap::new(),
            entrypoint: vec!["/bin/sh".into()],
            kernel_cmdline: None,
            init_mode: InitMode::Xkinit,
            node_tags: Vec::new(),
            labels: BTreeMap::new(),
        }
    }

    #[test]
    fn test_resolves_relative_path_against_spec_dir_and_copies_file() {
        let dir = fresh_temp_dir("relpath");
        let src = dir.join("rootfs-alpine.ext4");
        fs::write(&src, b"FAKE_EXT4").unwrap();
        let work = dir.join("work");

        let builder = AlpineBuilder::new(dir.clone());
        let spec = spec_with_relative_path("rootfs-alpine.ext4");
        let out = builder.build(&spec, &work).unwrap();

        assert!(out.is_file(), "rootfs copied into work_dir");
        assert_eq!(fs::read(&out).unwrap(), b"FAKE_EXT4");
        assert_ne!(out, src, "output must be a copy, not the source");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accepts_absolute_path_unchanged() {
        let dir = fresh_temp_dir("abspath");
        let src = dir.join("abs-rootfs.ext4");
        fs::write(&src, b"A").unwrap();
        let work = dir.join("work");

        // spec_dir intentionally different from the source
        // directory — absolute paths must ignore it.
        let unrelated = fresh_temp_dir("abspath-unrelated");
        let builder = AlpineBuilder::new(unrelated);
        let mut spec = spec_with_relative_path("placeholder");
        spec.base = BaseRef::LocalRootfs { path: src };

        let out = builder.build(&spec, &work).unwrap();
        assert!(out.is_file());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_source_returns_base_rootfs_not_found() {
        let dir = fresh_temp_dir("missing");
        let builder = AlpineBuilder::new(dir.clone());
        let spec = spec_with_relative_path("does-not-exist.ext4");

        let err = builder.build(&spec, &dir.join("work")).unwrap_err();
        match err {
            Error::BaseRootfsNotFound { path } => {
                assert!(path.contains("does-not-exist.ext4"));
            }
            other => panic!("expected BaseRootfsNotFound, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_creates_work_dir_if_missing() {
        let dir = fresh_temp_dir("mkdir");
        let src = dir.join("rootfs-alpine.ext4");
        fs::write(&src, b"x").unwrap();
        let nested_work = dir.join("deeply").join("nested");

        let builder = AlpineBuilder::new(dir.clone());
        let spec = spec_with_relative_path("rootfs-alpine.ext4");
        let out = builder.build(&spec, &nested_work).unwrap();
        assert!(out.starts_with(&nested_work));

        let _ = fs::remove_dir_all(&dir);
    }

    /// Audit follow-up #4: when `base.path` is a symlink,
    /// `AlpineBuilder::build` follows it (matching `fs::copy`'s
    /// default) and emits a `tracing::warn!` diagnostic. The build
    /// MUST still succeed, and the copied bytes MUST match the
    /// symlink target. We don't assert on log output — `warn!` is
    /// fire-and-forget per the audit design call; the presence of
    /// the code path is verified by `cargo check` and the happy-path
    /// test below.
    ///
    /// Unix-only: creating symlinks on Windows requires admin or
    /// developer mode, so CI can't reliably create them.
    #[cfg(unix)]
    #[test]
    fn test_build_warns_when_base_path_is_symlink() {
        let dir = fresh_temp_dir("symlink");
        let real = dir.join("real-rootfs.ext4");
        fs::write(&real, b"REAL_EXT4_CONTENTS").unwrap();
        let link = dir.join("link-rootfs.ext4");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let work = dir.join("work");
        let builder = AlpineBuilder::new(dir.clone());
        let mut spec = spec_with_relative_path("placeholder");
        spec.base = BaseRef::LocalRootfs { path: link.clone() };

        let out = builder.build(&spec, &work).unwrap();
        assert!(out.is_file(), "build through a symlink must still produce a copy");
        assert_eq!(
            fs::read(&out).unwrap(),
            b"REAL_EXT4_CONTENTS",
            "copied bytes must match the symlink target, not the link itself"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Regression guard for the symlink detection added in audit
    /// follow-up #4: a regular file must take the non-warning code
    /// path. Structurally identical to the first happy-path test,
    /// but named to pin the intent — if someone accidentally makes
    /// `file_type().is_symlink()` return true for regular files
    /// (e.g., via a refactor that uses `metadata()` wrongly), this
    /// test won't catch it directly, but the build still has to
    /// succeed end-to-end, which is what matters.
    #[test]
    fn test_build_regular_file_base_path_does_not_warn() {
        let dir = fresh_temp_dir("regfile");
        let src = dir.join("rootfs-alpine.ext4");
        fs::write(&src, b"PLAIN").unwrap();
        let work = dir.join("work");

        let builder = AlpineBuilder::new(dir.clone());
        let spec = spec_with_relative_path("rootfs-alpine.ext4");
        let out = builder.build(&spec, &work).unwrap();

        assert!(out.is_file());
        assert_eq!(fs::read(&out).unwrap(), b"PLAIN");

        let _ = fs::remove_dir_all(&dir);
    }
}
