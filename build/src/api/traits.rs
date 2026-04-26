//! SPI trait contracts for ocimage.
//!
//! Three pluggable layers:
//! * [`RootfsBuilder`] — produces rootfs bytes from a base
//!   (existing ext4 file, debootstrap, docker image, …). One
//!   impl per source family.
//! * [`PackageInstaller`] — runs a package manager inside a
//!   mounted rootfs. One impl per manager family (apk / apt /
//!   dnf / pacman).
//! * [`ImageBuilder`] — the top-level orchestrator. Consumes an
//!   [`ImageSpec`], delegates rootfs construction to
//!   `RootfsBuilder`, package install to `PackageInstaller`,
//!   cpio + config.json construction to the `userspace` crate,
//!   and writes the four artifacts to disk.

use std::path::Path;

use super::error::Error;
use super::spec::{BuildArtifacts, FileEntry, ImageSpec};

/// Builds a complete image per spec. Default impl lives in
/// `core::service::default_image_service` and composes the
/// lower-level SPIs below.
pub trait ImageBuilder: Send + Sync {
    /// Produce all four image artifacts under `output_dir`.
    /// The builder may create subdirectories.
    fn build(
        &self,
        spec: &ImageSpec,
        output_dir: &Path,
    ) -> Result<BuildArtifacts, Error>;
}

/// Produces the rootfs layer as a file on disk.
///
/// Impls vary by source — existing ext4 files, debootstrap runs,
/// docker-image extractions — but they all return a path to a
/// rootfs image that the orchestrator then treats as opaque
/// bytes when constructing the final output.
pub trait RootfsBuilder: Send + Sync {
    /// Materialise the rootfs for `spec` somewhere under
    /// `work_dir` and return the path. The orchestrator owns
    /// `work_dir`; the impl may scribble freely inside it.
    fn build(
        &self,
        spec: &ImageSpec,
        work_dir: &Path,
    ) -> Result<std::path::PathBuf, Error>;
}

/// Installs packages into an already-entered chroot.
///
/// Impls focus on "run `apk add` / `apt install` through the handle";
/// they don't deal with mount mechanics. The orchestrator owns the
/// [`chroot::ChrootHandle`] lifecycle so #18 file-overlay can reuse
/// the same handle without re-mounting.
///
/// **Phase 2f-α+**: `AlpineApkInstaller` is the first impl (#17).
/// Apt / dnf follow as separate variants. Trait signature changed
/// from `(mount_path, packages)` to `(handle, packages)` on
/// 2026-04-20 — no prior consumers.
pub trait PackageInstaller: Send + Sync {
    /// Install `packages` via `handle`. Must leave the filesystem in
    /// a consistent state even on partial failure (no half-written
    /// package databases).
    fn install(
        &self,
        handle: &mut dyn chroot::ChrootHandle,
        packages: &[String],
    ) -> Result<(), Error>;

    /// Name of the package-manager family this impl handles
    /// ([`crate::api::manifest::INSTALLER_FAMILY_ALPINE_APK`], future
    /// `"apt"`, `"dnf"`). Used by the orchestrator to pick an impl
    /// based on the rootfs's detected distro, and recorded in the
    /// build manifest for SBOM/purl generation. Implementations MUST
    /// return a constant string declared under `api::manifest` so
    /// both sides of the build/publish wire reference the same value.
    fn family(&self) -> &'static str;
}

/// Copies host files into the rootfs via an already-entered chroot.
///
/// Sibling to [`PackageInstaller`] — both take an open
/// [`chroot::ChrootHandle`] so the orchestrator can run package
/// install + file overlay under a single mount. First impl is
/// [`crate::spi::file_overlay::chroot_overlay::ChrootFileOverlay`].
pub trait FileOverlay: Send + Sync {
    /// Apply `files` to the rootfs via `handle`. Source paths
    /// resolve against the overlay impl's internal `spec_dir` (set
    /// at construction time) — the orchestrator has no say in that.
    /// Dest paths must already be validated (absolute, no `..`, no
    /// pseudofs prefix) by the central validator; this impl does a
    /// defense-in-depth re-check.
    fn apply(
        &self,
        handle: &mut dyn chroot::ChrootHandle,
        files: &[FileEntry],
    ) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_builder_is_object_safe() {
        fn _accept(_b: &dyn ImageBuilder) {}
    }

    #[test]
    fn test_rootfs_builder_is_object_safe() {
        fn _accept(_b: &dyn RootfsBuilder) {}
    }

    #[test]
    fn test_package_installer_is_object_safe() {
        fn _accept(_i: &dyn PackageInstaller) {}
    }

    #[test]
    fn test_file_overlay_is_object_safe() {
        fn _accept(_o: &dyn FileOverlay) {}
    }
}
