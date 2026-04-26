//! `ocimage` — the operator-facing CLI.
//!
//! Subcommands: `build` (2f-α), `publish-http` (2f-β Level 2),
//! `push` (2f-β Level 4), `systemd generate` (2f-δ).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use oci_build::build_image;
use oci_publish::{
    attest_build_dir, publish_http, push_oci, sbom_from_build_dir, write_attestation_statement,
    AttestMode,
};
use oci_systemd::{generate_unit, UnitOptions};

#[derive(Debug, Parser)]
#[command(version, about = "Build and publish vmisolate VM images (ADR-015).")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Build a VM image from a TOML spec. Outputs kernel +
    /// initrd.cpio + rootfs.ext4 + config.json to `--output`.
    Build {
        /// Path to the `ImageSpec` TOML file. Relative paths
        /// inside the spec resolve against this file's parent
        /// directory.
        spec: PathBuf,

        /// Output directory. Created if missing.
        #[arg(long, short = 'o', default_value = "build/out")]
        output: PathBuf,

        /// Host path to the Linux kernel bzImage to embed.
        /// Defaults to the canonical repo location.
        #[arg(
            long,
            env = "OCIMAGE_KERNEL",
            default_value = "downloads/bzImage_6.19.7"
        )]
        kernel: PathBuf,

        /// Host path to the xkvm-fs PID-1 init binary. `bootstrap.sh`
        /// produces it under `downloads/xkvm-fs`.
        #[arg(
            long,
            env = "OCIMAGE_XKVM_FS",
            default_value = "downloads/xkvm-fs"
        )]
        xkvm_fs: PathBuf,
    },

    /// Publish a built image to a local directory as an
    /// ADR-015 Level-2 index.json + content-addressed blobs.
    /// Pair with any static HTTP host.
    PublishHttp {
        /// Directory produced by a previous `build` — must
        /// contain kernel, initrd.cpio, config.json (+ optionally
        /// rootfs.ext4).
        build_dir: PathBuf,

        /// Where to write `index.json` + `blobs/sha256/<hash>`.
        /// Created if missing. Existing `index.json` is merged
        /// (entry for this image id replaced, others preserved).
        #[arg(long, short = 'o')]
        output: PathBuf,

        /// Emit a SLSA provenance attestation alongside the
        /// published artefacts (ADR-016 pillar B). Writes
        /// `attestation.json` (in-toto Statement, compact JSON)
        /// into the output directory. Unsigned by default;
        /// set `--sign-with` to cosign-sign the statement.
        #[arg(long)]
        attest: bool,

        /// Signing mode when `--attest` is set. Accepted values:
        /// `unsigned` (default — NoopAttester; never valid for
        /// production verifiers), `cosign-keyless:<identity>`,
        /// or `cosign-keyed:<path>:<identity>`. Cosign must be on
        /// PATH for the cosign modes.
        #[arg(long, default_value = "unsigned")]
        sign_with: String,

        /// Builder identity to embed in the SLSA predicate. In CI:
        /// the workflow run URL. Locally: any operator-chosen
        /// identifier. Defaults to `local-operator` when empty.
        #[arg(long, default_value = "")]
        builder_id: String,
    },

    /// Push a built image to an OCI distribution registry
    /// (GHCR, Harbor, ECR, …). Auth via env vars
    /// `OCIMAGE_REGISTRY_USER` + `OCIMAGE_REGISTRY_PASSWORD`;
    /// anonymous if unset.
    Push {
        /// Directory produced by a previous `build`.
        build_dir: PathBuf,

        /// OCI reference — `host[:port]/namespace/name:tag`.
        /// Example: `ghcr.io/acme/vmisolate-alpine:3.20`.
        reference: String,

        /// Emit a SLSA provenance attestation alongside the
        /// pushed artefact (ADR-016 pillar B). Writes
        /// `attestation.json` next to the build directory so the
        /// operator can hand it to `cosign attest` directly, or
        /// so a CI pipeline can upload it to the registry as an
        /// OCI artifact. Unsigned by default.
        #[arg(long)]
        attest: bool,

        /// Signing mode when `--attest` is set. See `publish-http`
        /// docs for the format.
        #[arg(long, default_value = "unsigned")]
        sign_with: String,

        /// Builder identity to embed in the SLSA predicate.
        #[arg(long, default_value = "")]
        builder_id: String,
    },

    /// Emit a CycloneDX SBOM from a built image's `build-manifest.json`
    /// (ADR-016 pillar C). The output is a valid CycloneDX v1.5
    /// document that Grype / Trivy / dependency-track can consume
    /// without surface-scanning the rootfs filesystem.
    Sbom {
        /// Directory produced by a previous `ocimage build` — must
        /// contain `build-manifest.json` (emitted by default since
        /// Phase 2f-α).
        build_dir: PathBuf,

        /// Path where the CycloneDX document is written. Defaults
        /// to `<build-dir>/packages.cdx.json` so the SBOM lives
        /// alongside the artefacts.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Systemd integration. Generate `.service` units that boot a
    /// previously-built image via xkvm on a target host.
    Systemd {
        #[command(subcommand)]
        action: SystemdAction,
    },
}

#[derive(Debug, Subcommand)]
enum SystemdAction {
    /// Emit a systemd `.service` unit whose `ExecStart` is
    /// `xkvm boot --kernel … --initrd … --kali …` against the
    /// artifacts under `<build-dir>`.
    Generate {
        /// Directory produced by a previous `ocimage build`.
        /// Must contain `kernel`, `initrd.cpio`, `rootfs.ext4`,
        /// `config.json`.
        build_dir: PathBuf,

        /// Destination for the unit. If this points at an existing
        /// directory, the filename is synthesised from the image id
        /// (slashes → `-`, colons → `_`, plus a `.service` suffix).
        #[arg(long, short = 'o')]
        output: PathBuf,

        /// Absolute path to xkvm on the host that will run the unit.
        #[arg(long, default_value = "/usr/bin/xkvm")]
        xkvm_path: PathBuf,

        /// Optional `User=` line. Omit to run the unit as root.
        #[arg(long)]
        user: Option<String>,

        /// `[Install] WantedBy=` target.
        #[arg(long, default_value = "multi-user.target")]
        wanted_by: String,
    },
}

fn main() -> ExitCode {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ocimage: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Build {
            spec,
            output,
            kernel,
            xkvm_fs,
        } => {
            tracing::info!(
                spec = %spec.display(),
                output = %output.display(),
                "building image",
            );
            let artifacts = build_image(&spec, &output, kernel, xkvm_fs)?;
            println!("kernel:  {}", artifacts.kernel_path.display());
            println!("initrd:  {}", artifacts.initrd_path.display());
            if let Some(r) = &artifacts.rootfs_path {
                println!("rootfs:  {}", r.display());
            }
            println!("config:  {}", artifacts.config_path.display());
            Ok(())
        }
        Commands::PublishHttp {
            build_dir,
            output,
            attest,
            sign_with,
            builder_id,
        } => {
            tracing::info!(
                build_dir = %build_dir.display(),
                output = %output.display(),
                "publishing http (level 2)",
            );
            let summary = publish_http(&build_dir, &output)?;
            println!("image:    {}", summary.image_id);
            println!("index:    {}", summary.index_path.display());
            println!("blobs:    {}", summary.blob_count);
            println!("bytes:    {}", summary.total_bytes);

            if attest {
                let mode = parse_attest_mode(&sign_with)?;
                let attestation = attest_build_dir(
                    &build_dir,
                    &summary.image_id,
                    &builder_id,
                    mode,
                )
                .map_err(|e| oci_build::api::error::Error::Config {
                    message: format!("{e}"),
                })?;
                let sidecar = output.join("attestation.json");
                write_attestation_statement(&attestation, &sidecar).map_err(|e| {
                    oci_build::api::error::Error::Config {
                        message: format!("{e}"),
                    }
                })?;
                println!("attest:   {}", sidecar.display());
                if attestation.signature().is_unsigned() {
                    println!("          (unsigned — dev mode; use --sign-with=cosign-keyless:<id> for real signing)");
                }
            }
            Ok(())
        }
        Commands::Push {
            build_dir,
            reference,
            attest,
            sign_with,
            builder_id,
        } => {
            tracing::info!(
                build_dir = %build_dir.display(),
                reference = %reference,
                "pushing oci (level 4)",
            );
            let summary = push_oci(&build_dir, &reference)?;
            println!("reference: {}", summary.reference);
            println!("digest:    {}", summary.manifest_digest);
            println!("pushed:    {} bytes", summary.bytes_pushed);

            if attest {
                let mode = parse_attest_mode(&sign_with)?;
                let attestation = attest_build_dir(
                    &build_dir,
                    &summary.reference,
                    &builder_id,
                    mode,
                )
                .map_err(|e| oci_build::api::error::Error::Config {
                    message: format!("{e}"),
                })?;
                let sidecar = build_dir.join("attestation.json");
                write_attestation_statement(&attestation, &sidecar).map_err(|e| {
                    oci_build::api::error::Error::Config {
                        message: format!("{e}"),
                    }
                })?;
                println!("attest:    {}", sidecar.display());
                if attestation.signature().is_unsigned() {
                    println!("           (unsigned — dev mode; use --sign-with=cosign-keyless:<id> for real signing)");
                }
            }
            Ok(())
        }
        Commands::Sbom { build_dir, output } => {
            let out_path = output.unwrap_or_else(|| build_dir.join("packages.cdx.json"));
            tracing::info!(
                build_dir = %build_dir.display(),
                output = %out_path.display(),
                "generating CycloneDX SBOM",
            );
            let bytes = sbom_from_build_dir(&build_dir).map_err(|e| {
                oci_build::api::error::Error::Config {
                    message: format!("{e}"),
                }
            })?;
            std::fs::write(&out_path, &bytes).map_err(|e| {
                oci_build::api::error::Error::Config {
                    message: format!("writing SBOM to {}: {e}", out_path.display()),
                }
            })?;
            println!("sbom:  {}", out_path.display());
            println!("bytes: {}", bytes.len());
            Ok(())
        }
        Commands::Systemd { action } => match action {
            SystemdAction::Generate {
                build_dir,
                output,
                xkvm_path,
                user,
                wanted_by,
            } => {
                tracing::info!(
                    build_dir = %build_dir.display(),
                    output = %output.display(),
                    "generating systemd unit",
                );
                let opts = UnitOptions {
                    xkvm_path,
                    user,
                    wanted_by,
                };
                let path = generate_unit(&build_dir, &output, opts)?;
                println!("unit: {}", path.display());
                Ok(())
            }
        },
    }
}

/// Parse the `--sign-with` flag into an `AttestMode`.
///
/// Accepts:
///   * `"unsigned"` — NoopAttester (dev default)
///   * `"cosign-keyless:<identity>"` — cosign keyless + OIDC
///   * `"cosign-keyed:<path>:<identity>"` — cosign keyed file
///
/// Unknown values → `Error::Config` with an explanation.
fn parse_attest_mode(raw: &str) -> Result<AttestMode, oci_build::api::error::Error> {
    if raw == "unsigned" {
        return Ok(AttestMode::Unsigned);
    }
    if let Some(identity) = raw.strip_prefix("cosign-keyless:") {
        if identity.is_empty() {
            return Err(oci_build::api::error::Error::Config {
                message: "--sign-with=cosign-keyless:<identity> — identity is empty".into(),
            });
        }
        return Ok(AttestMode::CosignKeyless {
            identity: identity.to_string(),
        });
    }
    if let Some(rest) = raw.strip_prefix("cosign-keyed:") {
        let (key_path, identity) = rest.split_once(':').ok_or_else(|| {
            oci_build::api::error::Error::Config {
                message: "--sign-with=cosign-keyed:<path>:<identity> — missing :identity part".into(),
            }
        })?;
        if key_path.is_empty() || identity.is_empty() {
            return Err(oci_build::api::error::Error::Config {
                message: "--sign-with=cosign-keyed:<path>:<identity> — path and identity must be non-empty".into(),
            });
        }
        return Ok(AttestMode::CosignKeyed {
            key_path: PathBuf::from(key_path),
            identity: identity.to_string(),
        });
    }
    Err(oci_build::api::error::Error::Config {
        message: format!(
            "--sign-with: unknown mode {raw:?}. Accepted: unsigned, cosign-keyless:<id>, cosign-keyed:<path>:<id>"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_attest_mode_unsigned() {
        let m = parse_attest_mode("unsigned").unwrap();
        assert!(matches!(m, AttestMode::Unsigned));
    }

    #[test]
    fn test_parse_attest_mode_cosign_keyless() {
        let m = parse_attest_mode("cosign-keyless:https://ci.example.com/run/1").unwrap();
        match m {
            AttestMode::CosignKeyless { identity } => {
                assert_eq!(identity, "https://ci.example.com/run/1");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attest_mode_cosign_keyed() {
        let m = parse_attest_mode("cosign-keyed:/keys/cosign.key:fingerprint:abc").unwrap();
        match m {
            AttestMode::CosignKeyed { key_path, identity } => {
                assert_eq!(key_path, PathBuf::from("/keys/cosign.key"));
                assert_eq!(identity, "fingerprint:abc");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_parse_attest_mode_rejects_unknown() {
        let err = parse_attest_mode("bogus").unwrap_err();
        assert!(format!("{err}").contains("unknown mode"));
    }

    #[test]
    fn test_parse_attest_mode_rejects_empty_keyless_identity() {
        let err = parse_attest_mode("cosign-keyless:").unwrap_err();
        assert!(format!("{err}").contains("identity is empty"));
    }

    #[test]
    fn test_parse_attest_mode_rejects_malformed_keyed() {
        let err = parse_attest_mode("cosign-keyed:/keys/cosign.key").unwrap_err();
        assert!(format!("{err}").contains("missing :identity"));
    }
}

