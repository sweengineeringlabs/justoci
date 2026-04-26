//! `ocimage publish <dir> --to <sink> [--auth ...]`.
//!
//! `<sink>` is a URI-shaped string:
//!
//! - `http:/path/to/dest`    → [`oci_publish::PublishSink::Http`]
//! - `registry:<host>/<repo>:<tag>` → [`oci_publish::PublishSink::Registry`]
//!
//! Auth resolution for `registry:` sinks:
//!
//! - `--auth env`           → [`RegistryAuth::FromEnv`] (default)
//! - `--auth basic`         → requires `--registry-username` + `--registry-password`
//! - `--auth bearer`        → requires `--registry-token`
//!
//! Errors map to `PublishError` → exit 4. URI-parse errors land as
//! `CliError::Cli` → exit 64 because they're an operator-flag typo
//! rather than a publish-backend failure.

use std::path::{Path, PathBuf};

use oci_publish::{publish, ImageDir, PublishOutcome, PublishSink, RegistryAuth};

use crate::error::CliError;

/// CLI auth mode, before resolution into `RegistryAuth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// Pull from env vars (`REGISTRY_TOKEN`, then
    /// `REGISTRY_USERNAME`+`REGISTRY_PASSWORD`).
    Env,
    /// HTTP Basic.
    Basic { username: String, password: String },
    /// Pre-acquired bearer token.
    Bearer { token: String },
}

impl AuthMode {
    /// Convert to the publish crate's `RegistryAuth`.
    pub fn into_registry_auth(self) -> RegistryAuth {
        match self {
            AuthMode::Env => RegistryAuth::FromEnv,
            AuthMode::Basic { username, password } => RegistryAuth::Basic { username, password },
            AuthMode::Bearer { token } => RegistryAuth::Bearer { token },
        }
    }
}

/// Parse a sink URI. Returns either an HTTP sink or the registry
/// triple needed to construct the registry sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedSink {
    Http {
        dest_dir: PathBuf,
    },
    Registry {
        registry: String,
        repository: String,
        tag: String,
    },
}

/// Parse a `--to` URI. The grammar is deliberately tiny so a typo
/// fails locally with a clear message instead of hitting the network.
pub fn parse_sink_uri(raw: &str) -> Result<ParsedSink, CliError> {
    if let Some(rest) = raw.strip_prefix("http:") {
        if rest.is_empty() {
            return Err(CliError::Cli {
                detail: "--to http: <path> is empty".into(),
            });
        }
        return Ok(ParsedSink::Http {
            dest_dir: PathBuf::from(rest),
        });
    }
    if let Some(rest) = raw.strip_prefix("registry:") {
        // <host>/<repo>:<tag>. Repo may itself contain `/` so we
        // split on the LAST `:` for the tag, then on the FIRST `/`
        // for the host/repo split.
        let (host_repo, tag) = rest.rsplit_once(':').ok_or_else(|| CliError::Cli {
            detail: format!("--to registry:<host>/<repo>:<tag> — missing :tag in {raw:?}"),
        })?;
        if tag.is_empty() {
            return Err(CliError::Cli {
                detail: format!("--to registry:<host>/<repo>:<tag> — tag empty in {raw:?}"),
            });
        }
        let (registry, repository) = host_repo.split_once('/').ok_or_else(|| CliError::Cli {
            detail: format!("--to registry:<host>/<repo>:<tag> — missing /repository in {raw:?}"),
        })?;
        if registry.is_empty() || repository.is_empty() {
            return Err(CliError::Cli {
                detail: format!(
                    "--to registry:<host>/<repo>:<tag> — host or repo empty in {raw:?}"
                ),
            });
        }
        return Ok(ParsedSink::Registry {
            registry: registry.to_string(),
            repository: repository.to_string(),
            tag: tag.to_string(),
        });
    }
    Err(CliError::Cli {
        detail: format!(
            "--to: unknown sink scheme in {raw:?} (expected http:<path> or registry:<host>/<repo>:<tag>)"
        ),
    })
}

/// Run the publish subcommand.
pub fn run(image_dir: &Path, sink_uri: &str, auth: AuthMode) -> Result<PublishOutcome, CliError> {
    let parsed = parse_sink_uri(sink_uri)?;
    let image = ImageDir::open(image_dir).map_err(oci_publish::PublishError::from)?;
    let sink = match parsed {
        ParsedSink::Http { dest_dir } => PublishSink::Http { dest_dir },
        ParsedSink::Registry {
            registry,
            repository,
            tag,
        } => PublishSink::Registry {
            registry,
            repository,
            tag,
            auth: Some(auth.into_registry_auth()),
        },
    };
    let outcome = publish(&image, &sink)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: parse_sink_uri stripping the `http:` prefix incorrectly
    // and routing it into the registry parser — would surface as a
    // confusing "missing :tag" error instead of the operator's actual
    // bug (a typo in the path).
    #[test]
    fn test_parse_sink_uri_http_extracts_path() {
        let p = parse_sink_uri("http:/tmp/out").unwrap();
        match p {
            ParsedSink::Http { dest_dir } => assert_eq!(dest_dir, PathBuf::from("/tmp/out")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // Catches: parse_sink_uri silently accepting an empty registry
    // host (e.g. `registry:/foo/bar:tag`) — would forward an empty
    // string to the publish layer, hitting an HTTPS://:443/foo/bar
    // URL that returns a confusing connection error instead of a
    // local "host empty" message.
    #[test]
    fn test_parse_sink_uri_registry_rejects_empty_host() {
        let err = parse_sink_uri("registry:/repo:tag").unwrap_err();
        match err {
            CliError::Cli { detail } => assert!(detail.contains("host or repo empty")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // Catches: parse_sink_uri using `splitn(3, ':')` instead of
    // `rsplit_once(':')` — a registry host with a `:port` would
    // get split wrong (`host` becomes `registry`, `port/repo` becomes
    // the repo, and `tag` becomes the port).
    #[test]
    fn test_parse_sink_uri_registry_with_port() {
        let p = parse_sink_uri("registry:localhost:5000/acme/img:0.1.0").unwrap();
        match p {
            ParsedSink::Registry {
                registry,
                repository,
                tag,
            } => {
                assert_eq!(registry, "localhost:5000");
                assert_eq!(repository, "acme/img");
                assert_eq!(tag, "0.1.0");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // Catches: parse_sink_uri quietly accepting an unknown scheme as
    // a "default to http" — silent acceptance of e.g. `s3://...`
    // would let the operator think they pushed to S3 when in fact
    // nothing happened.
    #[test]
    fn test_parse_sink_uri_unknown_scheme_rejected() {
        let err = parse_sink_uri("s3://bucket").unwrap_err();
        match err {
            CliError::Cli { detail } => assert!(detail.contains("unknown sink scheme")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // Catches: AuthMode::into_registry_auth dropping the password
    // field on the Basic conversion — would silently authenticate
    // anonymously even though the operator gave a password.
    #[test]
    fn test_auth_mode_basic_round_trip() {
        let m = AuthMode::Basic {
            username: "u".into(),
            password: "p".into(),
        };
        match m.into_registry_auth() {
            RegistryAuth::Basic { username, password } => {
                assert_eq!(username, "u");
                assert_eq!(password, "p");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
