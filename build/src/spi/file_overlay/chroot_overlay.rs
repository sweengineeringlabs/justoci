//! [`FileOverlay`] impl that copies host files into the rootfs via an
//! already-entered chroot.
//!
//! Works alongside [`crate::spi::package_installer::alpine_apk::AlpineApkInstaller`]
//! on the same `ChrootHandle` — the orchestrator enters once, runs
//! package install, then runs file overlay, then drops the handle.
//!
//! # Contract
//!
//! - `source` resolves against the spec file's parent directory if
//!   relative. Absolute sources pass through unchanged.
//! - `dest` MUST be absolute (guest-side rootfs path). No `..`.
//!   No `/proc`, `/sys`, `/dev` prefix. These rules are enforced at
//!   the central validator AND defense-in-depth here.
//! - Symlinks in `source` are rejected by default. A future
//!   `follow_symlinks = true` per-entry flag can relax this; for
//!   now we fail loud so a crafted spec can't copy
//!   `/etc/shadow` via a symlink from an innocent-looking source.
//! - Directory `source` is rejected — the v1 surface is single-file
//!   only. Recursive dir copy lands in a follow-up with an explicit
//!   opt-in flag on `FileEntry`.
//!
//! # Hardening deferred (tracked in #18 + #24)
//!
//! - Content-hash manifest (sha256 of each copied file into
//!   `build-manifest.json`).
//! - Deterministic stat preservation with `SOURCE_DATE_EPOCH`.
//! - Overwrite tracking (warn when copy overwrites a file placed by
//!   the package installer).

use std::path::{Path, PathBuf};

use crate::api::error::Error;
use crate::api::spec::FileEntry;
use crate::api::traits::FileOverlay;

/// Default impl — copies per-entry via the injected chroot handle.
///
/// Construct with the spec file's parent dir so relative `source`
/// paths resolve consistently with how `AlpineBuilder` resolves
/// `base.path`.
pub struct ChrootFileOverlay {
    spec_dir: PathBuf,
}

impl ChrootFileOverlay {
    pub fn new(spec_dir: PathBuf) -> Self {
        Self { spec_dir }
    }
}

impl FileOverlay for ChrootFileOverlay {
    fn apply(
        &self,
        handle: &mut dyn chroot::ChrootHandle,
        files: &[FileEntry],
    ) -> Result<(), Error> {
        for entry in files {
            // Resolve source: relative → spec_dir-anchored, absolute
            // → verbatim. Matches AlpineBuilder's base-path rule.
            let source = if entry.source.is_absolute() {
                entry.source.clone()
            } else {
                self.spec_dir.join(&entry.source)
            };

            // Defense-in-depth dest check. Central validator should
            // have caught these; if someone bypasses it, we still
            // refuse rather than writing to a bad path.
            if let Some(reason) = reject_dest(&entry.dest) {
                return Err(Error::SpecInvalid {
                    reason: format!(
                        "files[].dest `{}` rejected by overlay: {reason}",
                        entry.dest.display()
                    ),
                });
            }

            // Source existence + shape.
            let meta = std::fs::symlink_metadata(&source).map_err(|e| Error::Config {
                message: format!(
                    "files[].source `{}` (resolved to `{}`): {e}",
                    entry.source.display(),
                    source.display()
                ),
            })?;
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(Error::SpecInvalid {
                    reason: format!(
                        "files[].source `{}` is a symlink — reject by default (opt-in \
                         `follow_symlinks = true` is a future field, not in this cut)",
                        source.display()
                    ),
                });
            }
            if ft.is_dir() {
                return Err(Error::SpecInvalid {
                    reason: format!(
                        "files[].source `{}` is a directory — recursive copy is \
                         intentionally out of scope in v1; split into per-file entries",
                        source.display()
                    ),
                });
            }
            if !ft.is_file() {
                return Err(Error::SpecInvalid {
                    reason: format!(
                        "files[].source `{}` is neither a regular file nor a directory \
                         (devices, sockets, FIFOs all rejected)",
                        source.display()
                    ),
                });
            }

            // Normalise the source path before handing to the chroot:
            // `spec_dir.join(relative)` on Windows can yield mixed
            // separators plus unresolved `..` (e.g. `main/examples\..\..\
            // downloads/llmd`), which the host→WSL path translator
            // rejects. `canonicalize` produces an absolute, resolved
            // path on both platforms. Safe to run AFTER the symlink +
            // file-type checks above because those have already
            // rejected anything we don't want canonicalize to follow.
            let source = source.canonicalize().map_err(|e| Error::Config {
                message: format!(
                    "files[].source `{}` — canonicalize failed: {e}",
                    source.display()
                ),
            })?;

            handle
                .copy_in(&source, &entry.dest, entry.mode)
                .map_err(|e| Error::Config {
                    message: format!(
                        "copy_in failed for `{}` -> `{}`: {e}",
                        source.display(),
                        entry.dest.display()
                    ),
                })?;

            tracing::info!(
                target: "ocimage::file_overlay",
                source = %source.display(),
                dest = %entry.dest.display(),
                mode = ?entry.mode,
                "file overlay applied",
            );
        }
        Ok(())
    }
}

/// Same rules as the central validator's `file_dest_rejection` —
/// duplicated here to keep the FileOverlay impl self-defending without
/// depending on validator internals.
///
/// **Note**: dest paths are GUEST paths (Linux rootfs). We check
/// `starts_with('/')` manually rather than `std::Path::is_absolute`,
/// because on Windows hosts the std check interprets `/opt/foo` as
/// relative (no drive letter) — but in the guest rootfs it's absolute.
fn reject_dest(dest: &Path) -> Option<&'static str> {
    let s = match dest.to_str() {
        Some(s) => s,
        None => return Some("not valid UTF-8"),
    };
    if !s.starts_with('/') {
        return Some("not absolute — guest paths must start with `/`");
    }
    // Split-string check for ".." so Windows backslash handling and
    // std's drive-letter heuristics can't sneak through.
    if s.split('/').any(|seg| seg == "..") {
        return Some("contains `..` segment — path traversal rejected");
    }
    for deny in ["/proc", "/sys", "/dev"] {
        if s == deny || s.starts_with(&format!("{deny}/")) {
            return Some("targets a pseudofs directory (/proc, /sys, /dev)");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroot::spi::noop::NoopChroot;
    use chroot::Chroot;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "overlay-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn entry(source: impl Into<PathBuf>, dest: impl Into<PathBuf>, mode: Option<u32>) -> FileEntry {
        FileEntry {
            source: source.into(),
            dest: dest.into(),
            mode,
        }
    }

    #[test]
    fn test_relative_source_resolves_against_spec_dir() {
        let work = tmp_dir("rel-source");
        let spec_dir = work.join("specs");
        fs::create_dir_all(&spec_dir).unwrap();
        fs::write(spec_dir.join("llmboot-serve"), b"ELF").unwrap();

        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(spec_dir.clone());

        overlay
            .apply(
                &mut *h,
                &[entry("llmboot-serve", "/usr/bin/llmboot-serve", Some(0o755))],
            )
            .expect("apply succeeds");

        let materialised = rootfs
            .parent()
            .unwrap()
            .join("rootfs.ext4.noop-root/usr/bin/llmboot-serve");
        assert!(materialised.exists());
        assert_eq!(fs::read(&materialised).unwrap(), b"ELF");

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_absolute_source_passes_through() {
        let work = tmp_dir("abs-source");
        let src = work.join("absolute.bin");
        fs::write(&src, b"ABS").unwrap();

        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        // spec_dir is unrelated to the absolute source.
        let overlay = ChrootFileOverlay::new(work.join("irrelevant"));

        overlay
            .apply(&mut *h, &[entry(&src, "/opt/absolute.bin", None)])
            .expect("absolute source accepted");

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_rejects_relative_dest() {
        let work = tmp_dir("rel-dest");
        fs::write(work.join("src.bin"), b"x").unwrap();
        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(work.clone());

        let err = overlay
            .apply(&mut *h, &[entry("src.bin", "relative/dest", None)])
            .unwrap_err();
        match err {
            Error::SpecInvalid { reason } => {
                assert!(reason.contains("not absolute"), "got: {reason}");
            }
            other => panic!("expected SpecInvalid, got {other:?}"),
        }

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_rejects_parent_segment_dest() {
        let work = tmp_dir("parent-dest");
        fs::write(work.join("src.bin"), b"x").unwrap();
        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(work.clone());

        let err = overlay
            .apply(&mut *h, &[entry("src.bin", "/etc/../etc/passwd", None)])
            .unwrap_err();
        match err {
            Error::SpecInvalid { reason } => {
                assert!(reason.contains("`..`"), "got: {reason}");
            }
            other => panic!("expected SpecInvalid, got {other:?}"),
        }

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_rejects_pseudofs_prefix_dest() {
        let work = tmp_dir("pseudofs-dest");
        fs::write(work.join("src.bin"), b"x").unwrap();
        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(work.clone());

        for bad in ["/proc/self/status", "/sys/kernel", "/dev/null", "/proc", "/dev"] {
            match overlay.apply(&mut *h, &[entry("src.bin", bad, None)]) {
                Err(Error::SpecInvalid { reason }) => {
                    assert!(reason.contains("pseudofs"), "for {bad}: {reason}");
                }
                other => panic!("expected SpecInvalid for {bad}, got {other:?}"),
            }
        }

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_rejects_directory_source() {
        let work = tmp_dir("dir-source");
        let src_dir = work.join("my-dir");
        fs::create_dir_all(&src_dir).unwrap();
        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(work.clone());

        let err = overlay
            .apply(&mut *h, &[entry(&src_dir, "/opt/dir", None)])
            .unwrap_err();
        match err {
            Error::SpecInvalid { reason } => {
                assert!(reason.contains("directory"), "got: {reason}");
            }
            other => panic!("expected SpecInvalid, got {other:?}"),
        }

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_rejects_missing_source_with_config_error() {
        let work = tmp_dir("missing-source");
        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(work.clone());

        let err = overlay
            .apply(&mut *h, &[entry("nonexistent", "/opt/missing", None)])
            .unwrap_err();
        match err {
            Error::Config { message } => {
                assert!(message.contains("nonexistent"), "got: {message}");
            }
            other => panic!("expected Config, got {other:?}"),
        }

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_empty_files_list_is_noop() {
        let work = tmp_dir("empty");
        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(work.clone());
        overlay.apply(&mut *h, &[]).unwrap();

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }

    #[cfg(unix)]
    #[test]
    fn test_rejects_symlink_source() {
        use std::os::unix::fs::symlink;
        let work = tmp_dir("symlink-source");
        let real = work.join("real.bin");
        fs::write(&real, b"REAL").unwrap();
        let link = work.join("link");
        symlink(&real, &link).unwrap();
        let rootfs = work.join("rootfs.ext4");
        fs::write(&rootfs, b"IMG").unwrap();

        let c = NoopChroot::new();
        let mut h = c.enter(&rootfs).unwrap();
        let overlay = ChrootFileOverlay::new(work.clone());

        let err = overlay
            .apply(&mut *h, &[entry(&link, "/opt/link.bin", None)])
            .unwrap_err();
        match err {
            Error::SpecInvalid { reason } => {
                assert!(reason.contains("symlink"), "got: {reason}");
            }
            other => panic!("expected SpecInvalid, got {other:?}"),
        }

        drop(h);
        let _ = fs::remove_dir_all(&work);
    }
}
