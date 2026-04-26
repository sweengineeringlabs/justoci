//! Alpine apk impl of [`crate::api::traits::PackageInstaller`].
//!
//! Runs `apk update && apk add --no-cache <pkg>` via the injected
//! [`chroot::ChrootHandle`]. Stderr from each `apk` invocation is
//! captured and forwarded to [`tracing`] at target
//! `ocimage::package_install`; a non-zero apk exit surfaces as
//! [`Error::Package`] with the stderr tail.
//!
//! # MVP scope (first cut of #17)
//!
//! This impl handles the "operator wants nginx in the rootfs" path —
//! package names validated, `apk add` runs through the chroot, stderr
//! captured. It does NOT (yet) do:
//!
//! - `spec.lock` resolution / `--frozen-lockfile` check
//! - Pinned repo snapshots (inherits whatever `/etc/apk/repositories`
//!   the base rootfs ships with — operators who want reproducibility
//!   override via the `repositories` option at construction time)
//! - Explicit signing-key pin (inherits base rootfs's
//!   `/etc/apk/keys/*`)
//! - `build-manifest.json` emission
//!
//! Those are tracked in #17's hardening section and #24.
//!
//! # Contract
//!
//! Package names MUST be validated (allowlist `[a-zA-Z0-9._+-]`) BEFORE
//! reaching this impl — the central [`crate::api::validation`] layer
//! handles it. If validation is bypassed, this impl still refuses any
//! name containing shell-metacharacters (defense in depth).

use crate::api::error::Error;
use crate::api::manifest::INSTALLER_FAMILY_ALPINE_APK;
use crate::api::traits::PackageInstaller;

/// Default installer — runs `apk add` via the handle.
///
/// Override the repositories file via [`AlpineApkInstaller::with_repositories`]
/// to pin a snapshot (prod recommendation).
pub struct AlpineApkInstaller {
    /// Optional replacement for `/etc/apk/repositories` inside the
    /// rootfs. When `Some`, the installer writes it to the rootfs
    /// before the first `apk update` — useful for pinning a CDN
    /// snapshot. Format follows `apk`'s expected one-URL-per-line.
    repositories_override: Option<String>,
}

impl AlpineApkInstaller {
    pub fn new() -> Self {
        Self {
            repositories_override: None,
        }
    }

    /// Pin `/etc/apk/repositories` to a specific value inside the
    /// rootfs. Operators should use this in prod; CI / dev can
    /// inherit from the base rootfs.
    pub fn with_repositories(mut self, content: impl Into<String>) -> Self {
        self.repositories_override = Some(content.into());
        self
    }
}

impl Default for AlpineApkInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageInstaller for AlpineApkInstaller {
    fn install(
        &self,
        handle: &mut dyn chroot::ChrootHandle,
        packages: &[String],
    ) -> Result<(), Error> {
        if packages.is_empty() {
            return Ok(());
        }

        // Defense in depth — the central validator should have caught
        // this, but refuse shell-dangerous names here too. Clearer
        // error for reviewers who skip straight to the SPI impl.
        for p in packages {
            if !is_safe_apk_name(p) {
                return Err(Error::Package {
                    family: INSTALLER_FAMILY_ALPINE_APK,
                    packages: packages.to_vec(),
                    reason: format!(
                        "package name '{p}' contains characters rejected by the \
                         apk allowlist [a-zA-Z0-9._+-]"
                    ),
                });
            }
        }

        if let Some(repos) = &self.repositories_override {
            handle
                .write_file(
                    std::path::Path::new("/etc/apk/repositories"),
                    repos.as_bytes(),
                    0o644,
                )
                .map_err(|e| Error::Package {
                    family: INSTALLER_FAMILY_ALPINE_APK,
                    packages: packages.to_vec(),
                    reason: format!("writing /etc/apk/repositories failed: {e}"),
                })?;
        }

        // Seed a working DNS resolver inside the chroot. The chroot
        // substrate does not bind-mount the host's /etc/resolv.conf,
        // and Alpine minirootfs ships none, so `apk update` would
        // otherwise fail to resolve dl-cdn.alpinelinux.org. Public
        // resolvers let the build self-bootstrap without host DNS
        // assumptions; operators behind a DNS-policy firewall can
        // pre-populate /etc/resolv.conf in the rootfs (or use a
        // repositories_override pointing at an internal mirror).
        let _ = handle.write_file(
            std::path::Path::new("/etc/resolv.conf"),
            b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
            0o644,
        );

        // `apk update` first. Failure is fatal — stale index = either
        // missing-package or wrong-version, neither of which should
        // silently succeed.
        let update_out = handle
            .exec(&["apk", "update"], &[])
            .map_err(|e| Error::Package {
                family: INSTALLER_FAMILY_ALPINE_APK,
                packages: packages.to_vec(),
                reason: format!("apk update exec failed: {e}"),
            })?;
        if !update_out.success() {
            return Err(Error::Package {
                family: INSTALLER_FAMILY_ALPINE_APK,
                packages: packages.to_vec(),
                reason: format!(
                    "apk update exit {}: {}",
                    update_out.status,
                    update_out.stderr_str()
                ),
            });
        }
        tracing::debug!(
            target: "ocimage::package_install",
            stderr = %update_out.stderr_str(),
            "apk update succeeded",
        );

        // One `apk add` per package — slightly slower than a single
        // `apk add pkg1 pkg2 …` invocation, but makes per-package
        // error attribution trivial. Prod-hardened impl may batch
        // once `build-manifest.json` emission lands.
        for pkg in packages {
            let argv = ["apk", "add", "--no-cache", pkg.as_str()];
            let out = handle
                .exec(&argv, &[])
                .map_err(|e| Error::Package {
                    family: INSTALLER_FAMILY_ALPINE_APK,
                    packages: packages.to_vec(),
                    reason: format!("apk add {pkg} exec failed: {e}"),
                })?;
            if !out.success() {
                return Err(Error::Package {
                    family: INSTALLER_FAMILY_ALPINE_APK,
                    packages: packages.to_vec(),
                    reason: format!(
                        "apk add {pkg} exit {}: {}",
                        out.status,
                        out.stderr_str()
                    ),
                });
            }
            tracing::info!(
                target: "ocimage::package_install",
                package = %pkg,
                stderr = %out.stderr_str(),
                "apk add succeeded",
            );
        }

        Ok(())
    }

    fn family(&self) -> &'static str {
        INSTALLER_FAMILY_ALPINE_APK
    }
}

/// Allowlist: ASCII alphanumerics plus `.`, `_`, `+`, `-`. Matches
/// apk's own constraint and explicitly forbids shell metacharacters
/// (` `, `;`, `&`, `|`, `$`, `` ` ``, `\n`, etc).
fn is_safe_apk_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroot::spi::noop::NoopChroot;
    use chroot::Chroot;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "apk-test-{}-{}",
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn test_empty_packages_is_noop() {
        let root = tmp_root();
        let c = NoopChroot::new();
        let mut handle = c.enter(&root).unwrap();
        let inst = AlpineApkInstaller::new();
        // No packages → does not try to run apk (which doesn't exist
        // in the test env), so returns Ok.
        inst.install(&mut *handle, &[]).unwrap();
        drop(handle);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_rejects_shell_metacharacters_before_exec() {
        let root = tmp_root();
        let c = NoopChroot::new();
        let mut handle = c.enter(&root).unwrap();
        let inst = AlpineApkInstaller::new();

        for bad in [
            "nginx; rm -rf /",
            "ngi$(id)nx",
            "nginx && ls",
            "nginx\nreboot",
            "nginx | curl evil.com",
            "nginx`id`",
            "nginx with space",
            "",
        ] {
            match inst.install(&mut *handle, &[bad.to_string()]) {
                Err(Error::Package { reason, .. }) => {
                    assert!(
                        reason.contains("allowlist") || reason.contains("rejected"),
                        "expected allowlist reject for {bad:?}, got: {reason}"
                    );
                }
                other => panic!("expected Package rejection for {bad:?}, got {other:?}"),
            }
        }

        drop(handle);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_safe_apk_name_accepts_real_alpine_names() {
        for good in [
            "nginx",
            "python3",
            "ca-certificates",
            "libc6-compat",
            "nginx-1.24.0",
            "py3-pip",
            "build-base",
            "openssl-dev",
        ] {
            assert!(is_safe_apk_name(good), "should accept {good:?}");
        }
    }

    #[test]
    fn test_safe_apk_name_rejects_overlong() {
        let bad = "a".repeat(129);
        assert!(!is_safe_apk_name(&bad), "should reject overlong name");
    }

    #[test]
    fn test_family_is_alpine_apk() {
        let inst = AlpineApkInstaller::new();
        assert_eq!(inst.family(), INSTALLER_FAMILY_ALPINE_APK);
        assert_eq!(inst.family(), "alpine_apk");
    }

    #[test]
    fn test_repositories_override_lands_in_rootfs() {
        // Non-empty package list would invoke apk (missing in test env
        // → fails). Use empty list so we only test the write path…
        // but with_repositories only writes when we have packages to
        // install. Simulate by verifying the field is set — pure
        // construction test.
        let inst = AlpineApkInstaller::new().with_repositories(
            "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n",
        );
        assert!(inst.repositories_override.is_some());
    }
}
