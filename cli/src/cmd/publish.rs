//! `ocimage publish <dir> --to <sink> [--auth ...] [--no-auth]`.
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
//! - `--no-auth`            → `auth: None` on the sink (explicit anonymous,
//!   skips env lookup; the shorthand for "I know this registry is
//!   public-writable", e.g. a local `registry:2` smoke test).
//!
//! Errors map to `PublishError` → exit 4. URI-parse errors land as
//! `CliError::Cli` → exit 64 because they're an operator-flag typo
//! rather than a publish-backend failure.

use std::path::{Path, PathBuf};

use oci_publish::{publish, ImageDir, PublishOutcome, PublishSink, RegistryAuth};

use crate::error::CliError;

/// CLI auth mode, before resolution into `RegistryAuth`.
///
/// `Vault` is gated behind the `vault` Cargo feature: without the
/// feature, neither the variant nor the underlying `vaultrs` dep
/// exists, and the default binary keeps its current shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// Pull from env vars (`REGISTRY_TOKEN`, then
    /// `REGISTRY_USERNAME`+`REGISTRY_PASSWORD`).
    Env,
    /// HTTP Basic.
    Basic { username: String, password: String },
    /// Pre-acquired bearer token.
    Bearer { token: String },
    /// HashiCorp Vault KV v2 — resolves `<base_path>/<registry>` at
    /// publish/verify time. Construction reads `VAULT_ADDR` +
    /// `VAULT_TOKEN` from the environment; the resolution itself
    /// happens via [`AuthMode::resolve_for_registry`] right before
    /// the wire call so the host is known.
    #[cfg(feature = "vault")]
    Vault { base_path: String },
}

impl AuthMode {
    /// Convert to the publish crate's `RegistryAuth`.
    ///
    /// `Vault` is fallible-by-host and goes through
    /// [`Self::resolve_for_registry`] instead — it cannot collapse
    /// to a `RegistryAuth` without first reading the secret. Calling
    /// this method on the Vault variant is a programming error and
    /// panics; the CLI dispatchers always run `resolve_for_registry`
    /// first.
    pub fn into_registry_auth(self) -> RegistryAuth {
        match self {
            AuthMode::Env => RegistryAuth::FromEnv,
            AuthMode::Basic { username, password } => RegistryAuth::Basic { username, password },
            AuthMode::Bearer { token } => RegistryAuth::Bearer { token },
            #[cfg(feature = "vault")]
            AuthMode::Vault { .. } => {
                panic!(
                    "AuthMode::Vault must be resolved via resolve_for_registry before calling \
                     into_registry_auth — this is a CLI dispatcher bug",
                );
            }
        }
    }

    /// Resolve a host-dependent auth mode (today: only `Vault`) into
    /// a host-independent one suitable for [`Self::into_registry_auth`].
    ///
    /// For non-Vault variants this is a no-op identity. For `Vault`
    /// it constructs a [`crate::registry::VaultProvider`] from
    /// env, calls `resolve(host)`, and translates the resulting
    /// `Authorization` header back into either
    /// [`AuthMode::Basic`] (when the secret carried `username` +
    /// `password`) or [`AuthMode::Bearer`] (when it carried
    /// `token`).
    ///
    /// Returns the same variants as the input — never escalates
    /// shape — except that Vault is replaced with whichever of
    /// Basic/Bearer the secret payload selected.
    pub fn resolve_for_registry(self, registry: &str) -> Result<Self, crate::error::CliError> {
        // `registry` is only consulted when `self` is the Vault
        // variant — for every other mode the host is irrelevant
        // (Env reads process env; Basic / Bearer carry pre-resolved
        // creds). The two cfg branches below are distinct so neither
        // build path has an unused parameter or trailing dance.
        #[cfg(feature = "vault")]
        {
            match self {
                AuthMode::Vault { base_path } => resolve_vault_for_registry(&base_path, registry),
                other => Ok(other),
            }
        }
        #[cfg(not(feature = "vault"))]
        {
            // Touch `registry` in the diagnostic so the param is
            // referenced on every build path. Today this branch is
            // unreachable in practice (no host-dependent variant
            // exists without the feature), but keeping the param
            // shape stable across cfgs avoids a v-shaped function
            // signature that would force every caller to re-cfg.
            let _ = registry;
            Ok(self)
        }
    }
}

/// Resolve the Vault provider for a specific registry host.
///
/// `from_env` returns `Ok(None)` when `VAULT_ADDR` / `VAULT_TOKEN`
/// are unset; we treat that as a typed CLI error rather than a
/// silent fall-through to anonymous, mirroring the EnvProvider's
/// "set-but-empty is an error" rule. An operator who passed
/// `--auth vault` wanted Vault used; surfacing the misconfiguration
/// is the contract.
///
/// We call the typed `resolve_auth_mode` accessor (parallel to the
/// trait's `resolve`) so we get back the raw `username`+`password`
/// / `token` fields directly, without round-tripping through
/// `Authorization:` header composition + decode.
#[cfg(feature = "vault")]
fn resolve_vault_for_registry(
    base_path: &str,
    registry: &str,
) -> Result<AuthMode, crate::error::CliError> {
    use crate::registry::credential_provider::vault::{
        ResolvedVaultAuth, VaultProvider, ENV_VAULT_ADDR, ENV_VAULT_TOKEN,
    };

    let provider = VaultProvider::from_env(base_path)
        .map_err(|cred_err| crate::error::CliError::Cli {
            detail: format!("--auth vault: {cred_err}"),
        })?
        .ok_or_else(|| crate::error::CliError::Cli {
            detail: format!(
                "--auth vault: {ENV_VAULT_ADDR} and {ENV_VAULT_TOKEN} must both be set + non-empty"
            ),
        })?;
    let resolved = provider
        .resolve_auth_mode(registry)
        .map_err(|cred_err| crate::error::CliError::Cli {
            detail: format!("--auth vault: {cred_err}"),
        })?
        .ok_or_else(|| crate::error::CliError::Cli {
            detail: format!(
                "--auth vault: no Vault entry for registry {registry:?} (path \
                 {base_path:?}/{registry} returned 404)"
            ),
        })?;
    Ok(match resolved {
        ResolvedVaultAuth::Bearer { token } => AuthMode::Bearer { token },
        ResolvedVaultAuth::Basic { username, password } => AuthMode::Basic { username, password },
    })
}

/// Auth selector for `ocimage publish`. Mirrors verify's
/// `VerifyAuthMode`: either an explicit anonymous push (no
/// `Authorization:` header sent, no env lookup attempted) or one of
/// the [`AuthMode`] variants resolved from `--auth`.
///
/// We don't widen [`AuthMode`] itself with an `Anonymous` variant
/// because publish's [`AuthMode`] is also surfaced through verify
/// (`VerifyAuthMode::Authenticated(AuthMode)`), and conflating
/// "unset env" with "explicit anon" there would erase the difference
/// between "I forgot to export REGISTRY_TOKEN" and "this registry
/// is public" — operators rely on the typed-error noise of the
/// former.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishAuthMode {
    /// Explicit anonymous — `auth: None` on the registry sink.
    /// Used for unauthenticated `registry:2` smoke tests and
    /// public-writable mirrors.
    Anonymous,
    /// Pre-resolved auth from `--auth env|basic|bearer`.
    Authenticated(AuthMode),
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
///
/// `auth` selects either an explicit-anonymous push (`--no-auth`,
/// yielding `auth: None` on the registry sink — no `Authorization`
/// header on the wire, no env lookup attempted) or the pre-resolved
/// `AuthMode` from `--auth env|basic|bearer`. HTTP sinks ignore
/// `auth` entirely (no auth surface there).
pub fn run(
    image_dir: &Path,
    sink_uri: &str,
    auth: PublishAuthMode,
) -> Result<PublishOutcome, CliError> {
    let parsed = parse_sink_uri(sink_uri)?;
    let image = ImageDir::open(image_dir).map_err(oci_publish::PublishError::from)?;
    let sink = match parsed {
        ParsedSink::Http { dest_dir } => PublishSink::Http { dest_dir },
        ParsedSink::Registry {
            registry,
            repository,
            tag,
        } => {
            // Resolve host-dependent auth (today: only Vault) BEFORE
            // building the sink so the publish-crate layer receives a
            // host-independent `RegistryAuth`. Vault has to read the
            // KV path keyed by the registry host; for every other
            // variant `resolve_for_registry` is a no-op identity.
            let registry_auth = match auth {
                PublishAuthMode::Anonymous => None,
                PublishAuthMode::Authenticated(mode) => {
                    let resolved = mode.resolve_for_registry(&registry)?;
                    Some(resolved.into_registry_auth())
                }
            };
            PublishSink::Registry {
                registry,
                repository,
                tag,
                auth: registry_auth,
            }
        }
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

    /// Constructs the same `PublishSink` `run()` would build, given a
    /// parsed `--to` registry URI and a `PublishAuthMode`. Used by
    /// the auth-projection tests below to assert the wire-side
    /// `auth: Option<RegistryAuth>` field matches the operator's
    /// flag intent without spinning up a real ImageDir.
    fn build_sink_for_test(uri: &str, auth: PublishAuthMode) -> PublishSink {
        match parse_sink_uri(uri).unwrap() {
            ParsedSink::Http { dest_dir } => PublishSink::Http { dest_dir },
            ParsedSink::Registry {
                registry,
                repository,
                tag,
            } => {
                let registry_auth = match auth {
                    PublishAuthMode::Anonymous => None,
                    PublishAuthMode::Authenticated(mode) => Some(mode.into_registry_auth()),
                };
                PublishSink::Registry {
                    registry,
                    repository,
                    tag,
                    auth: registry_auth,
                }
            }
        }
    }

    // Catches: a future refactor that quietly maps
    // `PublishAuthMode::Anonymous` onto `RegistryAuth::FromEnv`
    // (e.g. by reusing `AuthMode::Env`) — the registry sink would
    // then attempt env lookup and surface a confusing
    // `PublishError::Auth` to the operator who explicitly asked
    // for `--no-auth`. The contract is `auth: None` on the wire.
    #[test]
    fn test_publish_auth_mode_anonymous_yields_sink_auth_none() {
        let sink = build_sink_for_test(
            "registry:localhost:5000/acme/img:0.1.0",
            PublishAuthMode::Anonymous,
        );
        match sink {
            PublishSink::Registry { auth, .. } => assert!(
                auth.is_none(),
                "PublishAuthMode::Anonymous must yield auth: None on the sink"
            ),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // Catches: a future refactor that flattens
    // `PublishAuthMode::Authenticated(AuthMode::Env)` to
    // `PublishAuthMode::Anonymous` "because the env path can fail
    // anyway" — operators rely on the typed PublishError::Auth
    // diagnostic when they forget to export REGISTRY_TOKEN, and
    // silent anonymous publish would mask that bug.
    #[test]
    fn test_publish_auth_mode_authenticated_env_yields_some_from_env() {
        let sink = build_sink_for_test(
            "registry:localhost:5000/acme/img:0.1.0",
            PublishAuthMode::Authenticated(AuthMode::Env),
        );
        match sink {
            PublishSink::Registry {
                auth: Some(RegistryAuth::FromEnv),
                ..
            } => {}
            other => panic!("expected Some(FromEnv); got {other:?}"),
        }
    }
}
