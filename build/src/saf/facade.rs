//! SAF facade — the top-level `build_image` entry point.
//!
//! Responsible for path resolution (spec_dir for relative paths
//! inside the spec) and wiring the default `RootfsBuilder` +
//! kernel / xkvm-fs binary paths into `DefaultImageService`.
//! Callers who want to inject a different `RootfsBuilder`
//! (integration tests, or a future Docker-export variant)
//! construct `DefaultImageService` directly instead.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::api::error::Error;
use crate::api::spec::{BuildArtifacts, ImageSpec};
use crate::api::traits::ImageBuilder;
use crate::core::service::DefaultImageService;
use crate::spi::file_overlay::chroot_overlay::ChrootFileOverlay;
use crate::spi::package_installer::alpine_apk::AlpineApkInstaller;
use crate::spi::rootfs_builder::alpine_builder::AlpineBuilder;

/// Build a single image per `spec`. Parses the spec TOML from
/// `spec_path`, runs the default pipeline, writes the four
/// artifacts to `output_dir`.
///
/// * `spec_path` — TOML file. Anchors relative paths inside the
///   spec (`base.path`, etc.) to its own parent directory.
/// * `output_dir` — where kernel / initrd / rootfs / config.json
///   land. Created if missing.
/// * `kernel_path` — bzImage to embed. Caller picks; typically
///   `<repo>/downloads/bzImage_6.19.7`.
/// * `xkvm_fs_path` — the Rust PID-1 init binary. Typically
///   `<repo>/downloads/xkvm-fs`.
pub fn build_image(
    spec_path: &Path,
    output_dir: &Path,
    kernel_path: PathBuf,
    xkvm_fs_path: PathBuf,
) -> Result<BuildArtifacts, Error> {
    let raw = std::fs::read_to_string(spec_path).map_err(|e| Error::Config {
        message: format!("reading spec {}: {e}", spec_path.display()),
    })?;
    let spec: ImageSpec = toml::from_str(&raw)?;

    // Hash the raw TOML bytes — NOT the reparsed spec — so the
    // manifest's `spec_sha256` ties to exactly what the operator
    // committed, including whitespace + comment layout. That's the
    // attestable input per #24.
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let spec_sha256 = hex_lower(&hasher.finalize());

    let spec_dir = spec_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let rootfs_builder = Arc::new(AlpineBuilder::new(spec_dir.clone()));
    let work_dir = output_dir.join(".work");
    let mut svc = DefaultImageService::new(rootfs_builder, kernel_path, xkvm_fs_path, work_dir)
        .with_spec_dir(spec_dir.clone())
        .with_spec_sha256(spec_sha256);

    // Wire the Phase 2f-α+ overlay pipeline (#16/#17/#18) on demand —
    // only when the spec actually requests packages or files. Skipping
    // this branch for overlay-free specs keeps `ocimage build` runnable
    // on hosts without WSL / Linux chroot privileges.
    if !spec.packages.is_empty() || !spec.files.is_empty() {
        let chroot_impl = chroot::detect_host().map_err(|e| Error::Config {
            message: format!(
                "spec has packages or files but no chroot substrate available on this host: {e}"
            ),
        })?;
        // `detect_host` returns `Box<dyn Chroot>`; `with_overlay` wants
        // `Arc<dyn Chroot>`. One allocation via `Arc::from`.
        let chroot_arc: Arc<dyn chroot::Chroot> = Arc::from(chroot_impl);
        svc = svc
            .with_overlay(chroot_arc.clone(), Arc::new(AlpineApkInstaller::new()))
            .with_file_overlay(Arc::new(ChrootFileOverlay::new(spec_dir)));
    }

    svc.build(&spec, output_dir)
}

fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0xF) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fresh_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ocimage-facade-{}-{}-{}",
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

    #[test]
    fn test_build_image_end_to_end_with_staged_fixtures() {
        // Stages a spec, a fake rootfs, a fake kernel, a fake
        // xkvm-fs — then walks the facade end-to-end. Proves the
        // three layers (saf → core → spi) compose without a
        // live WSL or a real kernel. No network, no WSL.
        let dir = fresh_temp_dir("e2e");
        let rootfs = dir.join("rootfs.ext4");
        fs::write(&rootfs, b"FAKE_ROOTFS").unwrap();
        let kernel = dir.join("bzImage");
        fs::write(&kernel, b"FAKE_KERNEL").unwrap();
        let xkvm_fs = dir.join("xkvm-fs");
        fs::write(&xkvm_fs, b"FAKE_XKVM_FS").unwrap();

        let spec = dir.join("spec.toml");
        fs::write(
            &spec,
            r#"
                id = "e2e:1"
                description = "end-to-end smoke"
                init_mode = "xkinit"
                entrypoint = ["/bin/true"]

                [base]
                kind = "local_rootfs"
                path = "rootfs.ext4"

                [env]
                [labels]
            "#,
        )
        .unwrap();

        let out = dir.join("out");
        let artifacts = build_image(&spec, &out, kernel, xkvm_fs).unwrap();

        assert!(artifacts.kernel_path.is_file());
        assert!(artifacts.initrd_path.is_file());
        assert!(artifacts.rootfs_path.as_ref().unwrap().is_file());
        assert!(artifacts.config_path.is_file());

        // Sanity: config.json mentions the spec id.
        let config = fs::read_to_string(&artifacts.config_path).unwrap();
        assert!(config.contains("e2e:1"));

        let _ = fs::remove_dir_all(&dir);
    }
}
