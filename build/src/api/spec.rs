//! `ImageSpec` — the DTO that describes a vmisolate VM image.
//!
//! Parsed from TOML (by `saf::facade::execute`) or constructed
//! programmatically. `core::service::DefaultImageService` consumes
//! it and produces the four on-disk artifacts per ADR-015
//! (kernel / initrd / rootfs / config.json).
//!
//! Kept deliberately generic — no hardcoded application names,
//! no enum of "supported images." Any TOML that deserializes to
//! this struct is a valid image spec; adding Postgres / Redis /
//! anything-else is a matter of writing a new TOML file, not
//! touching this code.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

/// A buildable VM image.
///
/// Serde-derived so a TOML file parses straight into this.
/// Unknown fields are rejected at parse time — typos fail fast
/// rather than silently dropping content.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSpec {
    /// Image identifier, used as the OCI reference when pushed
    /// (e.g. `alpine:3.20`, `my-org/xkvm-postgres:16`). Free-form
    /// at this layer; OCI push (`ocimage::spi::oci_push`)
    /// validates against the distribution spec.
    pub id: String,

    /// Human-readable description. Free text.
    #[serde(default)]
    pub description: String,

    /// How to obtain the base rootfs layer. See [`BaseRef`].
    pub base: BaseRef,

    /// Packages to install on top of the base rootfs. The active
    /// [`crate::api::traits::PackageInstaller`] impl decides how
    /// (apk / apt / dnf / …).
    ///
    /// **Phase 2f-α status**: carried on the spec but ignored by
    /// the current `AlpineBuilder` impl — which uses the base
    /// rootfs unmodified. Package-install arrives in 2f-α+ once
    /// the WSL-chroot shell-out is stabilised. Validation rejects
    /// non-empty `packages` today with a clear error so nobody
    /// thinks their request landed.
    #[serde(default)]
    pub packages: Vec<String>,

    /// Extra files to copy into the rootfs at build time. Each
    /// entry is a host-filesystem source + a rootfs-relative
    /// destination.
    ///
    /// **Phase 2f-α status**: same as `packages` — carried,
    /// rejected with a clear error if non-empty. Lands with the
    /// chroot-install work.
    #[serde(default)]
    pub files: Vec<FileEntry>,

    /// Environment variables injected at VM boot via
    /// `/etc/xkvm.conf` (xkinit) or BusyBox init exports. Same map
    /// as Fleet's `CreateInstanceRequest.env`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,

    /// Guest-side command line. Written into `/etc/xkvm.conf`
    /// for xkinit-mode images. Empty = drop to an interactive
    /// shell (requires `init_mode = "xkinit"` + `interactive = true`
    /// in the generated config).
    #[serde(default)]
    pub entrypoint: Vec<String>,

    /// Linux kernel command line. `None` = use the default from
    /// ADR-015's config manifest (`console=ttyS0 rdinit=/init`).
    #[serde(default)]
    pub kernel_cmdline: Option<String>,

    /// Init system packaged into the initrd layer. See [`InitMode`].
    #[serde(default)]
    pub init_mode: InitMode,

    /// Scheduler hints — which nodes can boot this image. Empty =
    /// any node. Flows to Fleet's `Image.node_tags`.
    #[serde(default)]
    pub node_tags: Vec<String>,

    /// Free-form labels, propagated to OCI manifest annotations
    /// under the `org.opencontainers.image.*` namespace (authors,
    /// source, version, licence, etc.).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Where the base rootfs comes from.
///
/// Only one variant ships in Phase 2f-α. The enum shape exists so
/// adding `Debootstrap`, `DockerImage`, or `OciArtifact` lands as
/// a new variant + a new `RootfsBuilder` SPI impl, not a redesign.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BaseRef {
    /// Path to an existing ext4 / squashfs rootfs file. Relative
    /// paths resolve against the spec file's parent directory;
    /// absolute paths pass through unchanged.
    LocalRootfs { path: PathBuf },
    // Future:
    //   Debootstrap { suite: String, mirror: String, arch: String },
    //   DockerImage { reference: String },
    //   OciArtifact { reference: String },
}

/// File to copy into the rootfs at build time. See
/// [`ImageSpec::files`] for the current-phase limitations.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Source path on the build host. Relative paths resolve
    /// against the spec file's parent directory.
    pub source: PathBuf,
    /// Destination path inside the guest rootfs. Must be absolute.
    pub dest: PathBuf,
    /// Unix mode bits (e.g. `0o755`). `None` = copy the source's
    /// mode verbatim.
    #[serde(default)]
    pub mode: Option<u32>,
}

/// Which init system is baked into the initrd layer.
///
/// `Xkinit` uses the Rust `xkvm-fs` PID-1 binary — emits
/// `XIKA_READY` on `ttyS0` (which xkvmd's boot-timeout watcher
/// looks for), supports `/etc/xkvm.conf`-driven DHCP / volume
/// mounts / chroot-to-rootfs / package install. The default.
///
/// `Busybox` uses the shell-script init (`userspace::BusyboxInitBuilder`).
/// Lighter; no chroot-to-rootfs, no XIKA_READY handshake. Suitable
/// for dev iteration (`xkvm boot --entrypoint`), not tenant images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitMode {
    #[default]
    Xkinit,
    Busybox,
}

/// Output of a successful `ImageBuilder::build` call. All four
/// paths point into the caller-supplied `output_dir` — the
/// builder owns layout, the caller owns the parent dir.
#[derive(Debug, Clone)]
pub struct BuildArtifacts {
    /// bzImage or raw vmlinux. Same media type as ADR-015 layer 0.
    pub kernel_path: PathBuf,
    /// cpio newc archive. ADR-015 layer 1.
    pub initrd_path: PathBuf,
    /// ext4 / squashfs block image. ADR-015 layer 2. `None` when
    /// the spec produces an initrd-only image.
    pub rootfs_path: Option<PathBuf>,
    /// JSON config manifest per ADR-015.
    pub config_path: PathBuf,
    /// `build-manifest.json` (#24.A) — deterministic record of what
    /// went into the image. Consumed by the reproducibility gate,
    /// SLSA attestation, and SBOM generation. `None` when an older
    /// `BuildArtifacts::load_from_dir` call didn't find the file
    /// (pre-#24 images lack it).
    pub manifest_path: Option<PathBuf>,
}

impl BuildArtifacts {
    /// Reconstruct a `BuildArtifacts` from a directory that was
    /// previously written by `DefaultImageService::build` (or any
    /// caller that respects the canonical filenames).
    ///
    /// Expects: `kernel`, `initrd.cpio`, `config.json` — all
    /// required. `rootfs.ext4` — optional; present ⇒ included in
    /// the returned struct, absent ⇒ `rootfs_path = None`.
    ///
    /// This is the bridge between `build` (which produces files on
    /// disk) and the publish / push subcommands (which consume a
    /// directory of build output). Decoupling lets operators run
    /// them as separate steps or from separate machines.
    pub fn load_from_dir(dir: &std::path::Path) -> Result<Self, crate::api::error::Error> {
        use crate::api::error::Error;

        let kernel_path = dir.join("kernel");
        if !kernel_path.is_file() {
            return Err(Error::ArtifactMissing {
                which: "kernel",
                dir: dir.display().to_string(),
            });
        }
        let initrd_path = dir.join("initrd.cpio");
        if !initrd_path.is_file() {
            return Err(Error::ArtifactMissing {
                which: "initrd.cpio",
                dir: dir.display().to_string(),
            });
        }
        let config_path = dir.join("config.json");
        if !config_path.is_file() {
            return Err(Error::ArtifactMissing {
                which: "config.json",
                dir: dir.display().to_string(),
            });
        }
        let rootfs_candidate = dir.join("rootfs.ext4");
        let rootfs_path = if rootfs_candidate.is_file() {
            Some(rootfs_candidate)
        } else {
            None
        };
        // build-manifest.json is optional — images produced before
        // #24.A landed won't have it, and load_from_dir is used on
        // those legacy outputs (e.g. during publish).
        let manifest_candidate = dir.join("build-manifest.json");
        let manifest_path = if manifest_candidate.is_file() {
            Some(manifest_candidate)
        } else {
            None
        };
        Ok(Self {
            kernel_path,
            initrd_path,
            rootfs_path,
            config_path,
            manifest_path,
        })
    }
}
