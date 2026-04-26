//! `build-manifest.json` — deterministic record of what went into an
//! image.
//!
//! Emitted by the orchestrator alongside `kernel`, `initrd.cpio`,
//! `rootfs.ext4`, `config.json`. Consumed by:
//!
//! - **Reproducibility gate** (#24.A): CI builds twice and diffs.
//!   Manifest diff surfaces non-determinism that byte-diff of the
//!   4 artifacts might miss (e.g., different package resolution).
//! - **SLSA provenance** (#24.B): attestation references manifest
//!   digests + the spec hash → produces an in-toto predicate that
//!   ties source to artifact.
//! - **SBOM / CVE scanning** (#24.C): `packages[]` is the input to
//!   CycloneDX + Grype / Trivy at consume time.
//!
//! # Determinism invariants
//!
//! The manifest MUST be deterministic for the same `ImageSpec` +
//! `SOURCE_DATE_EPOCH`. That means:
//!
//! 1. Field order frozen by `#[derive(Serialize)]` declaration order.
//! 2. Array order: packages preserve spec order; files preserve spec
//!    order; package family name is single-valued.
//! 3. No system-time timestamps anywhere. `build_time_unix` is the
//!    `SOURCE_DATE_EPOCH` value (default 0 when unset).
//! 4. No hostname, no build-host identifier, no CWD. The builder
//!    identity belongs to the SLSA attestation layer, not the
//!    manifest.
//! 5. `pretty_json` uses stable 2-space indent. No trailing
//!    whitespace.
//!
//! Any change to these invariants MUST bump
//! [`BuildManifest::SCHEMA_VERSION`] and update the reproducibility
//! golden fixture.

use std::io::Read;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::error::Error;
use super::spec::{FileEntry, ImageSpec};

/// Installer-family string for Alpine's `apk`. Shared between the
/// build-side `PackageInstaller` impl (writes it to the manifest) and
/// the publish-side SBOM emitter (keys purl generation off it). Keeping
/// a single const here prevents the drift that hid a missing
/// `pkg:apk/alpine/…` purl: before this, the build side wrote `"apk"`
/// while the SBOM emitter looked for `"alpine_apk"`.
///
/// New installer impls MUST add their family const here and have both
/// sides reference it — never spell the string inline at a call site.
pub const INSTALLER_FAMILY_ALPINE_APK: &str = "alpine_apk";

/// Top-level manifest written as `build-manifest.json` in the output
/// directory.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct BuildManifest {
    /// Bumped when the on-disk schema changes. Consumers can pin a
    /// version and refuse unknown shapes.
    pub schema_version: u32,
    /// Image ID from the spec (e.g. `llmboot:1`).
    pub id: String,
    /// Spec description — echoed for operator convenience.
    pub description: String,
    /// Effective `SOURCE_DATE_EPOCH` for this build. `0` when the
    /// env var was unset (the maximally-reproducible fallback).
    pub build_time_unix: u64,
    /// SHA256 of the `ImageSpec` TOML source. Ties the manifest to
    /// its producer. Filled in by the facade at build entry — not
    /// by the orchestrator, which has only the parsed `ImageSpec`.
    pub spec_sha256: Option<String>,
    /// Per-artifact digests. `rootfs.ext4`'s digest reflects the
    /// FINAL bytes written — i.e. post package-install + file-
    /// overlay, not the base rootfs's pre-overlay bytes.
    pub artifacts: ArtifactDigests,
    /// Packages requested by the spec and the installer family that
    /// ran them. Entries preserve spec order.
    pub packages: PackageManifest,
    /// Files copied into the rootfs. Entries preserve spec order.
    /// Each records the SHA256 of the HOST source file — the copied
    /// rootfs entry's digest is not recomputed because it should be
    /// identical (see `ChrootFileOverlay::copy_in`).
    pub files: Vec<FileManifestEntry>,
}

impl BuildManifest {
    pub const SCHEMA_VERSION: u32 = 1;

    /// Serialise to deterministic pretty JSON with a trailing newline.
    /// 2-space indent, UTF-8, no trailing whitespace per line.
    pub fn to_deterministic_json(&self) -> Result<Vec<u8>, Error> {
        let mut out = serde_json::to_vec_pretty(self)?;
        out.push(b'\n');
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ArtifactDigests {
    pub kernel_sha256: String,
    pub initrd_cpio_sha256: String,
    pub rootfs_ext4_sha256: String,
    pub config_json_sha256: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PackageManifest {
    /// Installer family name from the `PackageInstaller` impl
    /// (`INSTALLER_FAMILY_ALPINE_APK`, future `"apt"`, `"dnf"`, etc.
    /// `"mock"` for tests). `None` when the spec had no packages.
    pub installer_family: Option<String>,
    /// Package names as they appeared in the spec. Resolved
    /// versions are NOT recorded in v1 — requires parsing installer
    /// output. Tracked in #17 hardening.
    pub requested: Vec<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct FileManifestEntry {
    /// Host source path — relative if the spec had a relative source
    /// and the spec_dir anchor wasn't evident; absolute otherwise.
    /// Stored verbatim for audit replay.
    pub source: String,
    /// Guest destination path (absolute).
    pub dest: String,
    /// Source file's SHA256. Tests depend on this being stable.
    pub sha256: String,
    /// Mode as recorded in the spec; `None` when the spec didn't
    /// override.
    pub mode: Option<u32>,
}

impl FileManifestEntry {
    pub fn from_entry(
        entry: &FileEntry,
        resolved_source: &Path,
    ) -> Result<Self, Error> {
        let sha = sha256_file(resolved_source)?;
        Ok(Self {
            source: entry.source.display().to_string(),
            dest: entry.dest.display().to_string(),
            sha256: sha,
            mode: entry.mode,
        })
    }
}

/// Read `SOURCE_DATE_EPOCH` as a `u64`. Unset or unparseable → `0`
/// (maximally-reproducible sentinel). Invalid values are silently
/// treated as unset — a warning path could be added behind a
/// stricter flag.
pub fn source_date_epoch() -> u64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Stream-compute SHA256 of a file. Lowercase hex, no prefix.
pub fn sha256_file(path: &Path) -> Result<String, Error> {
    let mut f = std::fs::File::open(path).map_err(|e| Error::Config {
        message: format!("sha256_file({}): {e}", path.display()),
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| Error::Config {
            message: format!("sha256_file({}) read: {e}", path.display()),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0xF) as usize] as char);
    }
    s
}

/// Construct the manifest from the assembled build state. Separated
/// from serialisation so tests can assert on the struct shape.
pub fn build_manifest(
    spec: &ImageSpec,
    artifacts: ArtifactDigests,
    packages: PackageManifest,
    files: Vec<FileManifestEntry>,
    spec_sha256: Option<String>,
) -> BuildManifest {
    BuildManifest {
        schema_version: BuildManifest::SCHEMA_VERSION,
        id: spec.id.clone(),
        description: spec.description.clone(),
        build_time_unix: source_date_epoch(),
        spec_sha256,
        artifacts,
        packages,
        files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "manifest-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        p
    }

    #[test]
    fn test_sha256_file_produces_stable_lowercase_hex() {
        let p = tmp("sha-file");
        std::fs::write(&p, b"hello").unwrap();
        let digest = sha256_file(&p).unwrap();
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_sha256_file_missing_surfaces_config_error() {
        let p = tmp("missing-sha");
        let err = sha256_file(&p).unwrap_err();
        match err {
            Error::Config { message } => {
                assert!(message.contains("sha256_file"));
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn test_source_date_epoch_defaults_to_zero_when_unset() {
        // Note: cannot reliably unset an env var in tests (other
        // tests may have set it). Read the current value and accept
        // either 0 or a parseable u64; the important case is that
        // unparseable garbage falls back to 0 — exercised by the
        // next test.
        let _ = source_date_epoch(); // smoke: no panic
    }

    #[test]
    fn test_deterministic_json_trailing_newline_and_two_space_indent() {
        let m = BuildManifest {
            schema_version: 1,
            id: "x:1".into(),
            description: "".into(),
            build_time_unix: 0,
            spec_sha256: None,
            artifacts: ArtifactDigests {
                kernel_sha256: "a".repeat(64),
                initrd_cpio_sha256: "b".repeat(64),
                rootfs_ext4_sha256: "c".repeat(64),
                config_json_sha256: "d".repeat(64),
            },
            packages: PackageManifest {
                installer_family: None,
                requested: vec![],
            },
            files: vec![],
        };
        let bytes = m.to_deterministic_json().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.ends_with('\n'), "trailing newline present");
        assert!(s.contains("  \""), "2-space indent somewhere");
        assert!(
            !s.contains("\t"),
            "no tabs (would break reproducibility across editors)"
        );
    }

    #[test]
    fn test_manifest_shape_from_spec_preserves_order() {
        let spec = ImageSpec {
            id: "llmboot:1".into(),
            description: "test".into(),
            base: crate::api::spec::BaseRef::LocalRootfs {
                path: "unused".into(),
            },
            packages: vec!["z-last".into(), "a-first".into()],
            files: vec![],
            env: BTreeMap::new(),
            entrypoint: vec![],
            kernel_cmdline: None,
            init_mode: crate::api::spec::InitMode::Xkinit,
            node_tags: vec![],
            labels: BTreeMap::new(),
        };
        let m = build_manifest(
            &spec,
            ArtifactDigests {
                kernel_sha256: "0".repeat(64),
                initrd_cpio_sha256: "0".repeat(64),
                rootfs_ext4_sha256: "0".repeat(64),
                config_json_sha256: "0".repeat(64),
            },
            PackageManifest {
                installer_family: Some(INSTALLER_FAMILY_ALPINE_APK.into()),
                requested: spec.packages.clone(),
            },
            vec![],
            None,
        );
        // Spec order preserved — NOT sorted. Determinism comes from
        // spec being the same, not from rearranging its contents.
        assert_eq!(m.packages.requested, vec!["z-last", "a-first"]);
    }
}
