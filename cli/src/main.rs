//! `ocimage` — clap dispatcher + spec-doc §7 exit-code mapping.
//!
//! All business logic lives in the `swe_justoci_oci_cli` library
//! (`cmd::*`, `verify_engine`, `policy`, `referrers`). This binary
//! is a thin shim: parse args, call one of the typed entry points,
//! print the result on stdout (machine-readable), exit with the
//! right code.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use swe_justoci_oci_cli::cmd::publish::{AuthMode, PublishAuthMode};
use swe_justoci_oci_cli::cmd::sbom::SbomFormat;
use swe_justoci_oci_cli::cmd::verify::{VerifyAuthMode, VerifyOptions};
use swe_justoci_oci_cli::cmd::{build, inspect, publish, sbom, verify};
use swe_justoci_oci_cli::error::CliError;
use swe_justoci_oci_cli::verify_engine::PillarVerdict;

#[derive(Debug, Parser)]
#[command(version, about = "Build, publish, and verify justoci OCI artifacts.")]
struct Cli {
    /// Suppress secondary stderr human-eyes log lines. Stdout
    /// stays machine-parseable; the flag governs the `tracing`
    /// preamble only.
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Produce an OCI image dir from a justoci spec, optionally
    /// emitting SLSA + SBOM + cosign signature referrers.
    Build {
        /// Path to the justoci spec TOML.
        spec: PathBuf,

        /// Output directory. Created if missing.
        #[arg(short = 'o', long, default_value = "build/out")]
        output: PathBuf,

        /// Skip the attestation pipeline. Surfaces as exit 0 with
        /// "skipped: --no-attest" on stdout. Useful for offline
        /// dev iteration; production builds should NOT set this.
        #[arg(long)]
        no_attest: bool,
    },

    /// Push a built OCI image dir to a sink (HTTP static dir or
    /// OCI Distribution v2 registry).
    Publish {
        /// OCI image dir produced by `ocimage build`.
        dir: PathBuf,

        /// Sink URI. Either `http:<path>` for a static-served
        /// directory, or `registry:<host>/<repo>:<tag>` for an
        /// OCI Distribution v2 registry.
        #[arg(long)]
        to: String,

        /// Auth mode for `registry:` sinks. `env` (default) reads
        /// REGISTRY_TOKEN, then REGISTRY_USERNAME+REGISTRY_PASSWORD.
        /// `basic` requires --registry-username + --registry-password.
        /// `bearer` requires --registry-token. `vault` (only when the
        /// CLI is built with `--features vault`) reads VAULT_ADDR +
        /// VAULT_TOKEN and looks up `<--vault-base-path>/<registry>`.
        /// `docker-config` (only when the CLI is built with
        /// `--features docker-config`) reads `~/.docker/config.json`
        /// (or `--docker-config-path PATH`) and looks up
        /// `auths.<registry>`.
        #[arg(long, default_value = "env")]
        auth: String,

        /// Explicit anonymous push. Skips env-var credential
        /// resolution entirely — the shorthand for "I know this
        /// registry is public-writable" (e.g. a local `registry:2`
        /// smoke test). Mutually exclusive with `--auth` /
        /// `--registry-*` flags. Ignored on HTTP sinks.
        #[arg(long)]
        no_auth: bool,

        /// Username for `--auth basic`.
        #[arg(long, env = "REGISTRY_USERNAME")]
        registry_username: Option<String>,

        /// Password for `--auth basic`.
        #[arg(long, env = "REGISTRY_PASSWORD")]
        registry_password: Option<String>,

        /// Bearer token for `--auth bearer`.
        #[arg(long, env = "REGISTRY_TOKEN")]
        registry_token: Option<String>,

        /// Vault KV v2 base path consulted by `--auth vault`.
        /// Resolved as `<base-path>/<registry>` on the wire. Only
        /// honoured when the CLI is built with `--features vault`;
        /// otherwise the flag is accepted but ignored (any
        /// `--auth vault` selection errors out at parse time).
        #[arg(long, default_value = "secret/data/registry")]
        vault_base_path: String,

        /// Override path for `--auth docker-config`. Defaults to
        /// `~/.docker/config.json`. Only honoured when the CLI is
        /// built with `--features docker-config`; otherwise the
        /// flag is accepted but ignored (any `--auth docker-config`
        /// selection errors out at parse time).
        #[arg(long)]
        docker_config_path: Option<PathBuf>,
    },

    /// Verify an OCI artifact's attestation pillars + (optional)
    /// policy gates.
    ///
    /// `<reference>` is detected path-first: an existing path on
    /// disk is verified locally; otherwise it's parsed as a
    /// registry reference (`host[:port]/repo:tag` or
    /// `host/repo@sha256:<hex>`) and pulled into a tempdir before
    /// the same local-verify path runs.
    Verify {
        /// Path to a local OCI image-layout dir, OR a registry
        /// reference (`ghcr.io/acme/img:v1`,
        /// `localhost:5000/foo:latest`, `registry.io/foo@sha256:…`).
        reference: String,

        /// Optional policy.toml declaring slsa.level / sign /
        /// sbom gates. Without it, verify reports the pillar
        /// states informationally and exits 0.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Auth mode for registry references. Same shape as
        /// `ocimage publish`. `env` (default) reads
        /// REGISTRY_TOKEN, then REGISTRY_USERNAME+REGISTRY_PASSWORD.
        /// `basic` requires --registry-username +
        /// --registry-password. `bearer` requires
        /// --registry-token. `vault` (only when the CLI is built
        /// with `--features vault`) reads VAULT_ADDR + VAULT_TOKEN
        /// and looks up `<--vault-base-path>/<registry>`.
        /// `docker-config` (only when the CLI is built with
        /// `--features docker-config`) reads `~/.docker/config.json`
        /// (or `--docker-config-path PATH`) and looks up
        /// `auths.<registry>`.
        ///
        /// Ignored when `<reference>` is a local path.
        #[arg(long, default_value = "env")]
        auth: String,

        /// Explicit anonymous pull. Skips env-var credential
        /// resolution entirely — the shorthand for "I know this
        /// registry is public-readable." Ignored on local paths.
        #[arg(long)]
        no_auth: bool,

        /// Username for `--auth basic`.
        #[arg(long, env = "REGISTRY_USERNAME")]
        registry_username: Option<String>,

        /// Password for `--auth basic`.
        #[arg(long, env = "REGISTRY_PASSWORD")]
        registry_password: Option<String>,

        /// Bearer token for `--auth bearer`.
        #[arg(long, env = "REGISTRY_TOKEN")]
        registry_token: Option<String>,

        /// Vault KV v2 base path consulted by `--auth vault`.
        /// Resolved as `<base-path>/<registry>` on the wire. Only
        /// honoured when the CLI is built with `--features vault`;
        /// otherwise the flag is accepted but ignored (any
        /// `--auth vault` selection errors out at parse time).
        #[arg(long, default_value = "secret/data/registry")]
        vault_base_path: String,

        /// Override path for `--auth docker-config`. Defaults to
        /// `~/.docker/config.json`. Only honoured when the CLI is
        /// built with `--features docker-config`; otherwise the
        /// flag is accepted but ignored (any `--auth docker-config`
        /// selection errors out at parse time).
        #[arg(long)]
        docker_config_path: Option<PathBuf>,

        /// Strict mode for the OCI 1.1 referrers API. On registry refs,
        /// a 404 from `/v2/<repo>/referrers/<digest>` becomes a hard
        /// error (exit 5) instead of a soft "no referrers" warning.
        /// No-op on local image-layout paths (referrers come from
        /// index.json there).
        #[arg(long)]
        require_referrers: bool,
    },

    /// Emit (from spec) or extract (from image dir) an SBOM.
    Sbom {
        /// Either a spec.toml (preview SBOM) or an image dir
        /// (extract emitted SBOM).
        input: PathBuf,

        /// Where to write the SBOM. Without this, writes to stdout.
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        /// SBOM format. Only honoured in spec mode (image mode
        /// returns whatever format the build emitted).
        #[arg(long, default_value = "cyclonedx")]
        format: String,
    },

    /// Inspect a spec (canonical bytes + spec hash) or an image
    /// dir (manifest digest + config + layers + referrers).
    Inspect { input: PathBuf },
}

fn main() -> ExitCode {
    // We initialise tracing AFTER parsing args so `--quiet` can
    // suppress it. EnvFilter still reads RUST_LOG / OCIMAGE_LOG.
    let cli = Cli::parse();

    if !cli.quiet {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .try_init();
    }

    match dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Diagnostics on stderr — operators see the chained
            // error context. Stdout already carries any partial
            // machine-readable output the subcommand wrote
            // before failing.
            let _ = writeln!(std::io::stderr(), "ocimage: {e}");
            // Walk error sources for the full chain.
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                let _ = writeln!(std::io::stderr(), "  caused by: {s}");
                src = s.source();
            }
            ExitCode::from(e.exit_code())
        }
    }
}

fn dispatch(command: Commands) -> Result<(), CliError> {
    match command {
        Commands::Build {
            spec,
            output,
            no_attest,
        } => {
            let summary = build::run(&spec, &output, no_attest)?;
            // Machine-readable stdout. Operators / CI parse line-
            // prefix to extract digests.
            println!("manifest_digest: {}", summary.manifest_digest);
            println!("spec_hash:       {}", summary.spec_hash);
            println!("output_dir:      {}", summary.output_dir.display());
            match &summary.attestation_summary {
                None => println!("attestation:     skipped: --no-attest"),
                Some(a) => {
                    println!(
                        "slsa:            {}",
                        a.slsa_digest.as_deref().unwrap_or("(off)")
                    );
                    println!(
                        "sbom:            {}",
                        a.sbom_digest.as_deref().unwrap_or("(off)")
                    );
                    println!(
                        "signature:       {}",
                        a.signature_digest.as_deref().unwrap_or("(off)")
                    );
                }
            }
            Ok(())
        }
        Commands::Publish {
            dir,
            to,
            auth,
            no_auth,
            registry_username,
            registry_password,
            registry_token,
            vault_base_path,
            docker_config_path,
        } => {
            let publish_auth = parse_publish_auth_mode(
                no_auth,
                &auth,
                registry_username,
                registry_password,
                registry_token,
                &vault_base_path,
                docker_config_path,
            )?;
            let outcome = publish::run(&dir, &to, publish_auth)?;
            for d in &outcome.digests_pushed {
                println!("pushed:  {d}");
            }
            for d in &outcome.digests_skipped {
                println!("skipped: {d}");
            }
            println!("bytes:   {}", outcome.bytes_uploaded);
            Ok(())
        }
        Commands::Verify {
            reference,
            policy,
            auth,
            no_auth,
            registry_username,
            registry_password,
            registry_token,
            vault_base_path,
            docker_config_path,
            require_referrers,
        } => {
            let verify_auth = parse_verify_auth_mode(
                no_auth,
                &auth,
                registry_username,
                registry_password,
                registry_token,
                &vault_base_path,
                docker_config_path,
            )?;
            let opts = VerifyOptions { require_referrers };
            let report =
                verify::run_with_options(&reference, policy.as_deref(), verify_auth, &opts)?;
            println!("manifest: {}", report.manifest_digest);
            println!(
                "slsa:      {}  {}",
                report.slsa.label(),
                pillar_detail(&report.slsa)
            );
            println!(
                "sbom:      {}  {}",
                report.sbom.label(),
                pillar_detail(&report.sbom)
            );
            println!(
                "signature: {}  {}",
                report.signature.label(),
                pillar_detail(&report.signature)
            );
            Ok(())
        }
        Commands::Sbom {
            input,
            output,
            format,
        } => {
            let fmt = SbomFormat::parse(&format)?;
            let bytes = sbom::run(&input, fmt)?;
            match output {
                Some(p) => {
                    std::fs::write(&p, &bytes).map_err(|source| CliError::CliIo {
                        path: p.display().to_string(),
                        source,
                    })?;
                    println!("sbom: {}", p.display());
                    println!("bytes: {}", bytes.len());
                }
                None => {
                    std::io::stdout()
                        .write_all(&bytes)
                        .map_err(|source| CliError::CliIo {
                            path: "<stdout>".into(),
                            source,
                        })?;
                }
            }
            Ok(())
        }
        Commands::Inspect { input } => {
            match inspect::run(&input)? {
                inspect::InspectOutput::Spec {
                    canonical_json,
                    spec_hash,
                } => {
                    std::io::stdout()
                        .write_all(&canonical_json)
                        .map_err(|source| CliError::CliIo {
                            path: "<stdout>".into(),
                            source,
                        })?;
                    println!();
                    println!("spec_hash: {spec_hash}");
                }
                inspect::InspectOutput::Image {
                    manifest_digest,
                    config_digest,
                    config_media_type,
                    layers,
                    referrers,
                } => {
                    println!("manifest_digest: {manifest_digest}");
                    println!("config:          {config_digest} ({config_media_type})");
                    for (i, l) in layers.iter().enumerate() {
                        println!(
                            "layer[{i}]:  {} ({}, {} bytes)",
                            l.digest, l.media_type, l.size
                        );
                    }
                    for r in &referrers {
                        println!(
                            "referrer: {}  {} ({} bytes)",
                            r.digest, r.artifact_type, r.size
                        );
                    }
                }
            }
            Ok(())
        }
    }
}

fn pillar_detail(v: &PillarVerdict) -> &str {
    match v {
        PillarVerdict::Missing => "(no referrer found)",
        PillarVerdict::Found { detail } => detail,
        PillarVerdict::Failed { detail } => detail,
    }
}

/// Parse the publish-side auth surface. `--no-auth` is the
/// explicit-anonymous override (yielding `auth: None` on the
/// registry sink); otherwise the same `--auth env|basic|bearer`
/// matrix maps to a `PublishAuthMode::Authenticated`. Mutual
/// exclusion: an operator who passes both `--no-auth` and any
/// `--auth ...` / `--registry-*` flag gets a typed error rather
/// than a silently-ignored credential — same shape as verify.
fn parse_publish_auth_mode(
    no_auth: bool,
    raw: &str,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    vault_base_path: &str,
    docker_config_path: Option<PathBuf>,
) -> Result<PublishAuthMode, CliError> {
    if no_auth {
        let auth_was_set = raw != "env"
            || username.is_some()
            || password.is_some()
            || token.is_some()
            || docker_config_path.is_some();
        if auth_was_set {
            return Err(CliError::Cli {
                detail: "--no-auth is mutually exclusive with --auth / --registry-* / \
                         --docker-config-path flags"
                    .into(),
            });
        }
        return Ok(PublishAuthMode::Anonymous);
    }
    let mode = parse_auth_mode(
        raw,
        username,
        password,
        token,
        vault_base_path,
        docker_config_path,
    )?;
    Ok(PublishAuthMode::Authenticated(mode))
}

/// Parse the verify-side auth surface. `--no-auth` is the
/// explicit-anonymous override; otherwise the same `--auth env|basic|bearer`
/// matrix as publish maps to a `VerifyAuthMode::Authenticated`.
fn parse_verify_auth_mode(
    no_auth: bool,
    raw: &str,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    vault_base_path: &str,
    docker_config_path: Option<PathBuf>,
) -> Result<VerifyAuthMode, CliError> {
    if no_auth {
        // Explicit anonymous wins over `--auth ...`. We don't
        // silently accept the conflict — that would surprise an
        // operator who set both — so we surface a typed error
        // when both are present and meaningful.
        let auth_was_set = raw != "env"
            || username.is_some()
            || password.is_some()
            || token.is_some()
            || docker_config_path.is_some();
        if auth_was_set {
            return Err(CliError::Cli {
                detail: "--no-auth is mutually exclusive with --auth / --registry-* / \
                         --docker-config-path flags"
                    .into(),
            });
        }
        return Ok(VerifyAuthMode::Anonymous);
    }
    let mode = parse_auth_mode(
        raw,
        username,
        password,
        token,
        vault_base_path,
        docker_config_path,
    )?;
    Ok(VerifyAuthMode::Authenticated(mode))
}

fn parse_auth_mode(
    raw: &str,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    vault_base_path: &str,
    docker_config_path: Option<PathBuf>,
) -> Result<AuthMode, CliError> {
    match raw {
        "env" => Ok(AuthMode::Env),
        "basic" => {
            let username = username.ok_or_else(|| CliError::Cli {
                detail: "--auth basic requires --registry-username (or REGISTRY_USERNAME)".into(),
            })?;
            let password = password.ok_or_else(|| CliError::Cli {
                detail: "--auth basic requires --registry-password (or REGISTRY_PASSWORD)".into(),
            })?;
            if username.is_empty() || password.is_empty() {
                return Err(CliError::Cli {
                    detail: "--auth basic: username and password must be non-empty".into(),
                });
            }
            Ok(AuthMode::Basic { username, password })
        }
        "bearer" => {
            let token = token.ok_or_else(|| CliError::Cli {
                detail: "--auth bearer requires --registry-token (or REGISTRY_TOKEN)".into(),
            })?;
            if token.is_empty() {
                return Err(CliError::Cli {
                    detail: "--auth bearer: token must be non-empty".into(),
                });
            }
            Ok(AuthMode::Bearer { token })
        }
        #[cfg(feature = "vault")]
        "vault" => {
            if vault_base_path.is_empty() {
                return Err(CliError::Cli {
                    detail: "--auth vault: --vault-base-path must be non-empty".into(),
                });
            }
            Ok(AuthMode::Vault {
                base_path: vault_base_path.to_string(),
            })
        }
        #[cfg(not(feature = "vault"))]
        "vault" => Err(CliError::Cli {
            detail: format!(
                "--auth vault: this binary was built without the `vault` feature \
                 (--vault-base-path={vault_base_path:?} was supplied but ignored). \
                 Rebuild with `cargo build --features vault` (see \
                 docs/6-deployment/auth_providers.md)."
            ),
        }),
        #[cfg(feature = "docker-config")]
        "docker-config" => Ok(AuthMode::DockerConfig {
            config_path: docker_config_path,
        }),
        #[cfg(not(feature = "docker-config"))]
        "docker-config" => {
            // Touch the docker-config-only flag so the param is
            // consumed on every build path; the diagnostic mentions
            // it explicitly so the operator can correlate the error
            // with the flag they passed.
            let path_hint = docker_config_path
                .as_ref()
                .map(|p| format!(" (--docker-config-path={p:?} was supplied but ignored)"))
                .unwrap_or_default();
            Err(CliError::Cli {
                detail: format!(
                    "--auth docker-config: this binary was built without the \
                     `docker-config` feature{path_hint}. Rebuild with \
                     `cargo build --features docker-config` (see \
                     docs/6-deployment/auth_providers.md)."
                ),
            })
        }
        other => {
            // Build the "expected" list at the same time the cfg
            // gates decide which variants are visible. Keeps the
            // diagnostic in sync with the actual binary's surface
            // — on a default-feature build, the operator who typed
            // `--auth vault` should NOT see "vault" in the
            // expected list (that would be misleading).
            let modes = match (cfg!(feature = "vault"), cfg!(feature = "docker-config")) {
                (true, true) => "env, basic, bearer, vault, or docker-config",
                (true, false) => "env, basic, bearer, or vault",
                (false, true) => "env, basic, bearer, or docker-config",
                (false, false) => "env, basic, or bearer",
            };
            // `docker_config_path` may be Some on this branch even
            // when the operator typed an unknown `--auth ...`
            // value; touching it suppresses the unused-binding
            // warning on every cfg path.
            let _ = (vault_base_path, docker_config_path);
            Err(CliError::Cli {
                detail: format!("--auth: unknown mode {other:?} (expected {modes})"),
            })
        }
    }
}
