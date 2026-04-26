//! Default [`ImageBuilder`] implementation.
//!
//! Orchestrates the three-step build:
//!
//! 1. Delegate rootfs production to the configured [`RootfsBuilder`].
//!    Phase 2f-α ships one impl — `AlpineBuilder` — that reuses an
//!    existing `downloads/rootfs-alpine.ext4` verbatim.
//! 2. Build the initrd layer via `userspace::XkInitBuilder`. Zero
//!    cpio-writer code in this crate — we reuse the library.
//! 3. Copy the kernel (`downloads/bzImage_6.19.7`) and write the
//!    ADR-015 config manifest as `config.json`. Emit a
//!    [`BuildArtifacts`] pointing at the four paths.
//!
//! Validation: rejects `packages` and `files` with `SpecInvalid`
//! until the WSL-chroot-install path lands (flagged in the
//! `ImageSpec` docs). Keeps the failure loud so tenants aren't
//! surprised by silent no-ops.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use userspace::{InitBuilder, InitOptions, XkInitBuilder};

use crate::api::error::Error;
use crate::api::manifest::{
    build_manifest, sha256_file, ArtifactDigests, FileManifestEntry, PackageManifest,
};
use crate::api::spec::{BaseRef, BuildArtifacts, ImageSpec, InitMode};
use crate::api::traits::{FileOverlay, ImageBuilder, PackageInstaller, RootfsBuilder};
use crate::api::validation::validate_image_spec;

/// Default `ImageBuilder` impl. Takes an injected `RootfsBuilder`
/// so callers (and tests) can swap the alpine-specific producer
/// for a mock without touching orchestration.
///
/// Phase 2f-α+ adds two optional SPI slots — `chroot` and
/// `package_installer`. Both must be set for a spec with non-empty
/// `packages` to build; absent either, the builder rejects the spec
/// with a clear error. Keeping them optional preserves back-compat
/// for the Phase 2f-α construction sites that don't yet wire them.
pub struct DefaultImageService {
    rootfs_builder: Arc<dyn RootfsBuilder>,
    /// Host-side chroot substrate. Required for specs with non-empty
    /// `packages` or (future #18) `files`. `None` means "legacy
    /// Phase 2f-α behaviour" — the builder rejects overlay requests.
    chroot: Option<Arc<dyn chroot::Chroot>>,
    /// Package-manager impl matched to the base rootfs's distro.
    /// Required alongside `chroot` for `packages` to work.
    package_installer: Option<Arc<dyn PackageInstaller>>,
    /// Host-to-guest file-overlay impl. Required alongside `chroot`
    /// for `files` to work.
    file_overlay: Option<Arc<dyn FileOverlay>>,
    /// Host path to the shared kernel bzImage. The kernel doesn't
    /// vary per-image in Phase 2f-α; one copy per output dir.
    kernel_path: PathBuf,
    /// Host path to the xkvm-fs PID-1 binary (linked into every
    /// xkinit initrd).
    xkvm_fs_path: PathBuf,
    /// Where rootfs-builder scratch work lives.
    work_dir: PathBuf,
    /// Spec file's parent directory — used to resolve relative
    /// `files[].source` paths for digest computation (must match
    /// the `ChrootFileOverlay`'s resolution rule). Set via
    /// [`DefaultImageService::with_spec_dir`] when building from a
    /// TOML file; `None` means relative sources resolve against the
    /// process CWD (what `Path::join` does).
    spec_dir: Option<PathBuf>,
    /// SHA256 of the spec TOML source. Fed into build-manifest.json
    /// so the manifest is tied to its producer. Set by the SAF
    /// facade (`build_image`) which has read the raw spec. Direct
    /// `DefaultImageService` callers (e.g. tests) may leave it
    /// `None` — the manifest then records `"spec_sha256": null`.
    spec_sha256: Option<String>,
}

impl DefaultImageService {
    pub fn new(
        rootfs_builder: Arc<dyn RootfsBuilder>,
        kernel_path: PathBuf,
        xkvm_fs_path: PathBuf,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            rootfs_builder,
            chroot: None,
            package_installer: None,
            file_overlay: None,
            kernel_path,
            xkvm_fs_path,
            work_dir,
            spec_dir: None,
            spec_sha256: None,
        }
    }

    /// Record the spec file's parent directory so relative
    /// `files[].source` paths resolve consistently between the
    /// manifest digest and the FileOverlay's copy_in.
    pub fn with_spec_dir(mut self, spec_dir: PathBuf) -> Self {
        self.spec_dir = Some(spec_dir);
        self
    }

    /// Record the SHA256 of the spec TOML source. Ties the produced
    /// manifest to its producer.
    pub fn with_spec_sha256(mut self, sha256: String) -> Self {
        self.spec_sha256 = Some(sha256);
        self
    }

    /// Enable package-install overlay support (the `packages`
    /// field in ImageSpec). Both args required — installing
    /// packages without a chroot substrate is impossible, and a
    /// chroot without an installer would mount without reason.
    pub fn with_overlay(
        mut self,
        chroot: Arc<dyn chroot::Chroot>,
        installer: Arc<dyn PackageInstaller>,
    ) -> Self {
        self.chroot = Some(chroot);
        self.package_installer = Some(installer);
        self
    }

    /// Enable file-overlay support (the `files` field in ImageSpec).
    /// Requires `.with_overlay(...)` to have been called first — the
    /// chroot substrate is shared between the installer and the
    /// file-overlay (single mount, both consumers).
    pub fn with_file_overlay(mut self, overlay: Arc<dyn FileOverlay>) -> Self {
        self.file_overlay = Some(overlay);
        self
    }
}

impl ImageBuilder for DefaultImageService {
    fn build(
        &self,
        spec: &ImageSpec,
        output_dir: &Path,
    ) -> Result<BuildArtifacts, Error> {
        validate(spec)?;
        // Touch base variant so rustc-wise unused-field warnings
        // on `BaseRef::LocalRootfs.path` don't fire — the variant
        // is consumed by the RootfsBuilder impl.
        match &spec.base {
            BaseRef::LocalRootfs { .. } => {}
        }

        fs::create_dir_all(output_dir)?;
        fs::create_dir_all(&self.work_dir)?;

        // Step 1 — rootfs.
        let rootfs_src = self.rootfs_builder.build(spec, &self.work_dir)?;
        let rootfs_dst = output_dir.join("rootfs.ext4");
        fs::copy(&rootfs_src, &rootfs_dst).map_err(Error::Io)?;

        // Step 1b (Phase 2f-α+) — overlay packages and/or files if
        // the spec asks for them AND the orchestrator was wired with
        // the chroot + installer + overlay SPIs. The chroot handle
        // lifetime spans both operations so package install and file
        // overlay share one mount.
        let need_packages = !spec.packages.is_empty();
        let need_files = !spec.files.is_empty();
        if need_packages || need_files {
            let chroot_impl = self.chroot.as_ref().ok_or_else(|| Error::Config {
                message: "spec has non-empty packages or files but \
                          DefaultImageService was constructed without a chroot \
                          substrate — call .with_overlay(chroot, installer) \
                          and .with_file_overlay(overlay) on the builder"
                    .into(),
            })?;

            if need_packages && self.package_installer.is_none() {
                return Err(Error::Config {
                    message: "spec has non-empty packages but no PackageInstaller \
                              was wired — call .with_overlay(chroot, installer)"
                        .into(),
                });
            }
            if need_files && self.file_overlay.is_none() {
                return Err(Error::Config {
                    message: "spec has non-empty files but no FileOverlay was \
                              wired — call .with_file_overlay(overlay)"
                        .into(),
                });
            }

            let mut handle = chroot_impl.enter(&rootfs_dst)?;
            if need_packages {
                self.package_installer
                    .as_ref()
                    .unwrap()
                    .install(&mut *handle, &spec.packages)?;
            }
            if need_files {
                self.file_overlay
                    .as_ref()
                    .unwrap()
                    .apply(&mut *handle, &spec.files)?;
            }
            drop(handle);
        }

        // Step 2 — initrd. Cpio writing lives in `userspace`, not
        // here — the no-duplication audit before Phase 2f called
        // this out explicitly.
        let xkvm_fs = fs::read(&self.xkvm_fs_path).map_err(|_| Error::Config {
            message: format!(
                "xkvm-fs binary not found at {} — run bootstrap.sh",
                self.xkvm_fs_path.display()
            ),
        })?;

        let options = InitOptions {
            interactive: spec.entrypoint.is_empty(),
            ..Default::default()
        };
        let env_pairs: Vec<(String, String)> = spec
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let initrd_bytes = match spec.init_mode {
            InitMode::Xkinit => {
                if spec.entrypoint.is_empty() {
                    XkInitBuilder
                        .build_interactive_initrd(&xkvm_fs, &env_pairs, &[], &options)
                        .map_err(|e| Error::Initrd {
                            reason: format!("xkinit interactive: {e}"),
                        })?
                } else {
                    XkInitBuilder
                        .build_container_initrd(
                            &xkvm_fs,
                            &spec.entrypoint,
                            &env_pairs,
                            &[],
                            &options,
                        )
                        .map_err(|e| Error::Initrd {
                            reason: format!("xkinit container: {e}"),
                        })?
                }
            }
            InitMode::Busybox => {
                return Err(Error::Config {
                    message:
                        "init_mode = \"busybox\" not wired in Phase 2f-α; use \"xkinit\""
                            .into(),
                });
            }
        };
        let initrd_dst = output_dir.join("initrd.cpio");
        fs::write(&initrd_dst, &initrd_bytes)?;

        // Step 3 — kernel + config.json.
        if !self.kernel_path.is_file() {
            return Err(Error::KernelNotFound {
                path: self.kernel_path.display().to_string(),
            });
        }
        let kernel_dst = output_dir.join("kernel");
        fs::copy(&self.kernel_path, &kernel_dst)?;

        let config_dst = output_dir.join("config.json");
        let manifest = ConfigManifest::from_spec(spec);
        let manifest_json = serde_json::to_vec_pretty(&manifest)?;
        fs::write(&config_dst, &manifest_json)?;

        // Step 4 (#24.A) — build-manifest.json. Digests are computed
        // AFTER the overlay steps so rootfs.ext4's digest captures
        // the final bytes (post package-install + file-overlay), not
        // the base rootfs's pre-overlay bytes.
        let artifacts = ArtifactDigests {
            kernel_sha256: sha256_file(&kernel_dst)?,
            initrd_cpio_sha256: sha256_file(&initrd_dst)?,
            rootfs_ext4_sha256: sha256_file(&rootfs_dst)?,
            config_json_sha256: sha256_file(&config_dst)?,
        };
        let installer_family = self
            .package_installer
            .as_ref()
            .filter(|_| !spec.packages.is_empty())
            .map(|i| i.family().to_string());
        let packages_manifest = PackageManifest {
            installer_family,
            requested: spec.packages.clone(),
        };
        let file_manifest = self.file_manifest_entries(spec)?;

        let build_m = build_manifest(
            spec,
            artifacts,
            packages_manifest,
            file_manifest,
            self.spec_sha256.clone(),
        );
        let manifest_dst = output_dir.join("build-manifest.json");
        fs::write(&manifest_dst, build_m.to_deterministic_json()?)?;

        Ok(BuildArtifacts {
            kernel_path: kernel_dst,
            initrd_path: initrd_dst,
            rootfs_path: Some(rootfs_dst),
            config_path: config_dst,
            manifest_path: Some(manifest_dst),
        })
    }
}

impl DefaultImageService {
    /// Compute per-entry `FileManifestEntry` with the resolved source
    /// path — uses `spec_dir` for relative sources to match
    /// [`crate::spi::file_overlay::chroot_overlay::ChrootFileOverlay`]'s
    /// resolution rule.
    fn file_manifest_entries(
        &self,
        spec: &ImageSpec,
    ) -> Result<Vec<FileManifestEntry>, Error> {
        let cwd = PathBuf::from(".");
        let anchor = self.spec_dir.as_ref().unwrap_or(&cwd);
        spec.files
            .iter()
            .map(|e| {
                let resolved = if e.source.is_absolute() {
                    e.source.clone()
                } else {
                    anchor.join(&e.source)
                };
                FileManifestEntry::from_entry(e, &resolved)
            })
            .collect()
    }
}


// --- validation -------------------------------------------------------------

fn validate(spec: &ImageSpec) -> Result<(), Error> {
    // Central input-safety gate — closes issues #8, #9, #10. Runs
    // before the phase-2f-α feature gates so a malformed `id`
    // surfaces with its specific threat message rather than being
    // masked by the generic `packages`/`files` rejection. Must
    // happen before any filesystem work in `build`.
    let result = validate_image_spec(spec);
    if !result.allowed {
        return Err(Error::SpecInvalid {
            reason: result
                .reason
                .unwrap_or_else(|| "ImageSpec failed validation".into()),
        });
    }
    // Both `packages` (#17) and `files` (#18) are now wired in
    // Phase 2f-α+. Validator-level grammar checks (package-name
    // allowlist, file-dest absolutes / no-`..` / no-pseudofs) live
    // in `validate_image_spec` above. The orchestrator enforces
    // "installer + overlay + chroot present" at build time, not
    // here.
    Ok(())
}

// --- ADR-015 config manifest -----------------------------------------------

#[derive(serde::Serialize)]
struct ConfigManifest {
    schema_version: u32,
    id: String,
    description: String,
    kernel_cmdline: String,
    node_tags: Vec<String>,
    init_mode: String,
    entrypoint: Vec<String>,
    env: std::collections::BTreeMap<String, String>,
    labels: std::collections::BTreeMap<String, String>,
}

impl ConfigManifest {
    fn from_spec(spec: &ImageSpec) -> Self {
        Self {
            schema_version: 1,
            id: spec.id.clone(),
            description: spec.description.clone(),
            kernel_cmdline: spec
                .kernel_cmdline
                .clone()
                .unwrap_or_else(|| "console=ttyS0 rdinit=/init".into()),
            node_tags: spec.node_tags.clone(),
            init_mode: match spec.init_mode {
                InitMode::Xkinit => "xkinit".into(),
                InitMode::Busybox => "busybox".into(),
            },
            entrypoint: spec.entrypoint.clone(),
            env: spec.env.clone(),
            labels: spec.labels.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockRootfsBuilder {
        calls: Mutex<Vec<(String, PathBuf)>>,
    }

    impl RootfsBuilder for MockRootfsBuilder {
        fn build(
            &self,
            spec: &ImageSpec,
            work_dir: &Path,
        ) -> Result<PathBuf, Error> {
            self.calls
                .lock()
                .unwrap()
                .push((spec.id.clone(), work_dir.to_path_buf()));
            let out = work_dir.join("mock-rootfs.ext4");
            fs::write(&out, b"MOCK_ROOTFS_BYTES")?;
            Ok(out)
        }
    }

    fn fresh_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ocimage-test-{}-{}-{}",
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

    fn basic_spec() -> ImageSpec {
        use std::collections::BTreeMap;
        ImageSpec {
            id: "test:1".into(),
            description: "test image".into(),
            base: BaseRef::LocalRootfs {
                path: PathBuf::from("unused-by-mock"),
            },
            packages: Vec::new(),
            files: Vec::new(),
            env: BTreeMap::new(),
            entrypoint: vec!["/bin/true".into()],
            kernel_cmdline: None,
            init_mode: InitMode::Xkinit,
            node_tags: vec!["linux".into()],
            labels: BTreeMap::new(),
        }
    }

    fn stage_kernel_and_xkvm_fs(dir: &Path) -> (PathBuf, PathBuf) {
        let kernel = dir.join("kernel-fixture");
        fs::write(&kernel, b"FAKE_BZIMAGE_BYTES").unwrap();
        let xkvm_fs = dir.join("xkvm-fs-fixture");
        fs::write(&xkvm_fs, b"FAKE_XKVM_FS_ELF_BYTES").unwrap();
        (kernel, xkvm_fs)
    }

    #[test]
    fn test_build_produces_four_artifacts_with_expected_paths() {
        let dir = fresh_temp_dir("happy");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let mock = Arc::new(MockRootfsBuilder {
            calls: Mutex::new(Vec::new()),
        });
        let svc = DefaultImageService::new(
            mock.clone(),
            kernel,
            xkvm_fs,
            dir.join("work"),
        );

        let out = dir.join("out");
        let artifacts = svc.build(&basic_spec(), &out).unwrap();

        assert!(artifacts.kernel_path.is_file());
        assert!(artifacts.initrd_path.is_file());
        assert!(artifacts.rootfs_path.as_ref().unwrap().is_file());
        assert!(artifacts.config_path.is_file());

        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "test:1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_without_overlay_wiring_rejects_non_empty_packages_with_config_error() {
        // Phase 2f-α+ behaviour: when spec.packages is non-empty but
        // the orchestrator was constructed without .with_overlay(...),
        // the build fails with Error::Config pointing at the missing
        // wiring, NOT Error::SpecInvalid (which is reserved for the
        // central validator). Tests that callers constructing the
        // service in legacy Phase-2f-α style still get a loud error
        // instead of a silent no-op.
        let dir = fresh_temp_dir("packages");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        );

        let mut spec = basic_spec();
        spec.packages = vec!["postgresql16".into()];
        let err = svc.build(&spec, &dir.join("out")).unwrap_err();
        match err {
            Error::Config { message } => {
                assert!(
                    message.contains("packages") && message.contains("chroot"),
                    "Config message should name both packages and chroot: {message}"
                );
            }
            other => panic!("expected Config, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_with_overlay_wiring_invokes_installer_for_packages() {
        // Green path: orchestrator wired with NoopChroot + a mock
        // installer that records what it was called with. Proves the
        // chroot→installer flow runs end to end without touching a
        // real apk binary.
        use chroot::spi::noop::NoopChroot;
        let dir = fresh_temp_dir("pkg-green");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);

        struct RecordingInstaller {
            packages_seen: Mutex<Vec<Vec<String>>>,
        }
        impl PackageInstaller for RecordingInstaller {
            fn install(
                &self,
                _handle: &mut dyn chroot::ChrootHandle,
                packages: &[String],
            ) -> Result<(), Error> {
                self.packages_seen
                    .lock()
                    .unwrap()
                    .push(packages.to_vec());
                Ok(())
            }
            fn family(&self) -> &'static str {
                "mock"
            }
        }

        let installer = Arc::new(RecordingInstaller {
            packages_seen: Mutex::new(Vec::new()),
        });
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        )
        .with_overlay(Arc::new(NoopChroot::new()), installer.clone());

        let mut spec = basic_spec();
        spec.packages = vec!["nginx".into(), "curl".into()];
        svc.build(&spec, &dir.join("out")).expect("build succeeds");

        let seen = installer.packages_seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "installer called exactly once");
        assert_eq!(seen[0], vec!["nginx".to_string(), "curl".to_string()]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_with_files_wiring_invokes_overlay() {
        // Green path for #18: orchestrator wired with NoopChroot +
        // ChrootFileOverlay. Proves the file-overlay branch runs.
        use crate::spi::file_overlay::chroot_overlay::ChrootFileOverlay;
        use chroot::spi::noop::NoopChroot;
        use crate::api::spec::FileEntry;

        let dir = fresh_temp_dir("file-green");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let src = dir.join("llmboot-serve");
        fs::write(&src, b"FAKE_BINARY").unwrap();

        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        )
        .with_spec_dir(dir.clone())
        .with_overlay(
            Arc::new(NoopChroot::new()),
            Arc::new(crate::spi::package_installer::alpine_apk::AlpineApkInstaller::new()),
        )
        .with_file_overlay(Arc::new(ChrootFileOverlay::new(dir.clone())));

        let mut spec = basic_spec();
        spec.files = vec![FileEntry {
            source: "llmboot-serve".into(),
            dest: "/usr/bin/llmboot-serve".into(),
            mode: Some(0o755),
        }];
        svc.build(&spec, &dir.join("out")).expect("build succeeds");

        // Materialised under the noop sibling dir.
        let expected = dir
            .join("out/rootfs.ext4.noop-root/usr/bin/llmboot-serve");
        assert!(expected.exists(), "expected overlay-written file at {}", expected.display());
        assert_eq!(fs::read(&expected).unwrap(), b"FAKE_BINARY");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_manifest_json_emitted_with_stable_structure() {
        // #24.A acceptance: build-manifest.json present in output
        // dir, parseable, with the expected invariants — schema v1,
        // 4 artifact digests populated, spec-order preserved.
        let dir = fresh_temp_dir("manifest");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);

        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        )
        .with_spec_sha256("deadbeef".repeat(8));

        let spec = basic_spec();
        let artifacts = svc.build(&spec, &dir.join("out")).expect("build ok");
        let manifest_path = artifacts.manifest_path.expect("manifest path returned");
        assert!(manifest_path.is_file(), "build-manifest.json exists");

        let bytes = fs::read(&manifest_path).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.ends_with('\n'), "trailing newline preserved");

        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["id"], "test:1");
        assert_eq!(parsed["spec_sha256"].as_str().unwrap().len(), 64);
        for key in ["kernel_sha256", "initrd_cpio_sha256", "rootfs_ext4_sha256", "config_json_sha256"] {
            let s = parsed["artifacts"][key].as_str().expect(key);
            assert_eq!(s.len(), 64, "{key} should be 64 hex chars");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_without_overlay_wiring_rejects_non_empty_files_with_config_error() {
        use crate::api::spec::FileEntry;

        let dir = fresh_temp_dir("file-no-wiring");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        fs::write(dir.join("src.bin"), b"x").unwrap();
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        );

        let mut spec = basic_spec();
        spec.files = vec![FileEntry {
            source: dir.join("src.bin"),
            dest: "/opt/x".into(),
            mode: None,
        }];
        let err = svc.build(&spec, &dir.join("out")).unwrap_err();
        match err {
            Error::Config { message } => {
                assert!(
                    message.contains("files") || message.contains("chroot"),
                    "Config should name files or chroot: {message}"
                );
            }
            other => panic!("expected Config, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_rejects_file_dest_at_validator() {
        use crate::api::spec::FileEntry;

        let dir = fresh_temp_dir("dest-validator");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        );

        let mut spec = basic_spec();
        spec.files = vec![FileEntry {
            source: "unused".into(),
            dest: "/proc/self/status".into(),
            mode: None,
        }];
        let err = svc.build(&spec, &dir.join("out")).unwrap_err();
        match err {
            Error::SpecInvalid { reason } => {
                assert!(reason.contains("pseudofs"), "got: {reason}");
            }
            other => panic!("expected SpecInvalid, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_rejects_invalid_package_name_at_validator() {
        // Shell-metacharacter in a package name must fail at the
        // central validator with SpecInvalid, well before reaching
        // the installer. Defense in depth for #17.
        let dir = fresh_temp_dir("pkg-validator");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        );

        let mut spec = basic_spec();
        spec.packages = vec!["nginx; rm -rf /".into()];
        let err = svc.build(&spec, &dir.join("out")).unwrap_err();
        match err {
            Error::SpecInvalid { reason } => {
                assert!(
                    reason.contains("package name") || reason.contains("allowlist"),
                    "SpecInvalid reason should name the package or allowlist: {reason}"
                );
            }
            other => panic!("expected SpecInvalid, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_rejects_missing_kernel_with_kernel_not_found() {
        let dir = fresh_temp_dir("nokernel");
        let (_real_kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            dir.join("does-not-exist-kernel"),
            xkvm_fs,
            dir.join("work"),
        );

        let err = svc.build(&basic_spec(), &dir.join("out")).unwrap_err();
        assert!(matches!(err, Error::KernelNotFound { .. }));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_rejects_busybox_init_mode_in_this_phase() {
        let dir = fresh_temp_dir("busybox");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        );

        let mut spec = basic_spec();
        spec.init_mode = InitMode::Busybox;
        let err = svc.build(&spec, &dir.join("out")).unwrap_err();
        assert!(matches!(err, Error::Config { .. }));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_manifest_uses_default_kernel_cmdline_when_omitted() {
        let m = ConfigManifest::from_spec(&basic_spec());
        assert_eq!(m.kernel_cmdline, "console=ttyS0 rdinit=/init");
        assert_eq!(m.init_mode, "xkinit");
    }

    #[test]
    fn test_config_manifest_preserves_tenant_supplied_kernel_cmdline() {
        let mut spec = basic_spec();
        spec.kernel_cmdline = Some("console=ttyS0 nosmp".into());
        let m = ConfigManifest::from_spec(&spec);
        assert_eq!(m.kernel_cmdline, "console=ttyS0 nosmp");
    }

    // Catches: issue #8 / #10 regressing — a newline in `id` must
    // be rejected at the top of `build`, with a `SpecInvalid` error
    // whose reason names the field, and no output files must be
    // written. If this test passes after deleting the validator
    // call, the gate is fake.
    #[test]
    fn test_build_rejects_newline_in_id_before_writing_artifacts() {
        let dir = fresh_temp_dir("newline-id");
        let (kernel, xkvm_fs) = stage_kernel_and_xkvm_fs(&dir);
        let svc = DefaultImageService::new(
            Arc::new(MockRootfsBuilder {
                calls: Mutex::new(Vec::new()),
            }),
            kernel,
            xkvm_fs,
            dir.join("work"),
        );

        let mut spec = basic_spec();
        spec.id = "foo\nExecStart=/bin/evil".into();
        let out = dir.join("out");
        let err = svc.build(&spec, &out).unwrap_err();
        match err {
            Error::SpecInvalid { reason } => {
                assert!(
                    reason.contains("id"),
                    "reason must name the field: {reason}"
                );
                assert!(
                    reason.contains("newline"),
                    "reason must describe the threat: {reason}"
                );
            }
            other => panic!("expected SpecInvalid, got {other:?}"),
        }

        // No artifact files must exist — validator runs before any
        // fs::create_dir_all / copy / write. Even the output dir
        // should not have been created by build.
        assert!(
            !out.exists() || fs::read_dir(&out).unwrap().next().is_none(),
            "build must write no files when spec fails validation; found entries in {}",
            out.display()
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
