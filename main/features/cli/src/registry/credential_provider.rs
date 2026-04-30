//! Credential provider trait surface.
//!
//! Replaces the previous `AuthMode` enum on the registry-pull path.
//! New providers (Vault, Docker-config, custom) implement this
//! trait and register with [`AuthManager`]. The public CLI flag UX
//! is preserved at the [`crate::main`] / [`crate::cmd::verify`]
//! boundary — `--auth env|basic|bearer` and `--no-auth` translate
//! into a `Vec<Box<dyn CredentialProvider>>` that AuthManager
//! iterates.
//!
//! ### Trait shape
//!
//! [`CredentialProvider::resolve`] returns:
//!
//! - `Ok(Some(Credentials))` — this provider produced credentials
//!   for `registry`. AuthManager stops walking and uses them.
//! - `Ok(None)` — this provider has nothing to offer for this
//!   registry. AuthManager moves to the next provider. Returning
//!   `Some(empty)` instead of `None` would silently shadow every
//!   downstream provider; that's a class of bug we explicitly
//!   guard against in the per-provider tests.
//! - `Err(CredError)` — this provider is broken (e.g. Vault is
//!   down). AuthManager surfaces the error rather than silently
//!   falling through to anonymous: an operator who configured
//!   Vault wants to know it failed, not to find their CI silently
//!   pushed unauthenticated.
//!
//! ### Built-in implementations
//!
//! - [`AnonymousProvider`] — always returns `Ok(None)`. Placeholder
//!   for explicit "no auth" so `--no-auth` translates into a
//!   provider chain rather than an empty-vec edge case.
//! - [`BasicProvider`] — pre-supplied username + password →
//!   `Authorization: Basic <b64>`.
//! - [`BearerProvider`] — pre-supplied token →
//!   `Authorization: Bearer <token>`.
//! - [`EnvProvider`] — reads `REGISTRY_TOKEN`, then
//!   `REGISTRY_USERNAME` + `REGISTRY_PASSWORD`. Returns `Ok(None)`
//!   when no env match (lets a downstream provider try) but
//!   surfaces a typed error when env vars are present-but-empty
//!   (an operator who exported `REGISTRY_TOKEN=""` wants the
//!   misconfiguration named, not silently ignored).

use thiserror::Error;

// Vault-backed provider. Compiled only when the parent crate is
// built with `--features vault` so the default binary doesn't pay
// the `vaultrs` + tokio dep-graph cost. The module's surface is
// re-exported by the parent module via the gated re-export below.
#[cfg(feature = "vault")]
pub mod vault;

// Docker-config-backed provider. Compiled only when the parent
// crate is built with `--features docker-config` so the default
// binary doesn't pay the `base64` + `dirs` dep-graph cost. The
// module reads `~/.docker/config.json` and resolves the registry
// credentials an operator already provisioned via `docker login`.
// It does NOT depend on Docker the daemon being installed — only
// on the static config file at the well-known path.
#[cfg(feature = "docker-config")]
pub mod docker_config;

/// One environment-variable name reused across the env provider.
/// Mirrors the publish side's variable so an operator who configured
/// `justoci publish` keeps the same surface for `justoci verify`.
const ENV_REGISTRY_TOKEN: &str = "REGISTRY_TOKEN";
const ENV_REGISTRY_USERNAME: &str = "REGISTRY_USERNAME";
const ENV_REGISTRY_PASSWORD: &str = "REGISTRY_PASSWORD";

/// Credentials a provider produced for a registry call.
///
/// The provider owns header construction so [`AuthManager`] never
/// has to know about scheme details (`Basic`, `Bearer`, future
/// schemes a Vault provider might mint). The string is the exact
/// byte sequence to send as the `Authorization` HTTP header.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Pre-built `Authorization:` header value (e.g. `"Basic ..."`,
    /// `"Bearer ..."`).
    pub auth_header: String,
    /// Stable identifier of the producing provider, for logging /
    /// diagnostics. Same semantics as [`CredentialProvider::name`].
    pub source: &'static str,
}

/// Typed error surface for [`CredentialProvider`] implementations.
///
/// Carries `provider: &'static str` on every variant so log output
/// names which provider failed. No `anyhow` — the trait surface
/// is a load-bearing contract the CLI exit-code mapping depends on.
#[derive(Debug, Error)]
pub enum CredError {
    /// The provider was asked for credentials and tried, but failed
    /// in a way that's not an I/O fault (e.g. Vault returned a 403,
    /// docker-config has no entry for this registry but the file
    /// exists, env vars were exported but empty).
    #[error("provider {provider} failed to resolve credentials: {detail}")]
    ProviderFailed {
        provider: &'static str,
        detail: String,
    },
    /// The provider hit an underlying I/O fault (e.g. couldn't read
    /// `~/.docker/config.json`, couldn't connect to Vault).
    #[error("io error in provider {provider}: {source}")]
    Io {
        provider: &'static str,
        #[source]
        source: std::io::Error,
    },
}

/// A pluggable source of registry credentials.
///
/// Implementations MUST be `Send + Sync` so [`AuthManager`] can hold
/// them in a `Vec<Box<dyn CredentialProvider>>` shared across
/// threads — even though today the registry-pull path is
/// blocking-single-threaded, future async / parallel-blob-pull work
/// shouldn't have to refactor the trait.
pub trait CredentialProvider: Send + Sync {
    /// Try to resolve credentials for `registry`.
    ///
    /// - `Ok(Some(creds))` → use these credentials. AuthManager
    ///   stops walking after the first `Some`.
    /// - `Ok(None)` → "I have nothing to offer for this registry."
    ///   AuthManager continues to the next provider.
    /// - `Err(CredError)` → the provider is broken. AuthManager
    ///   surfaces this rather than silently falling through.
    fn resolve(&self, registry: &str) -> Result<Option<Credentials>, CredError>;

    /// Stable identifier of this provider, used in log output and
    /// in the [`Credentials::source`] field. Examples: `"env"`,
    /// `"basic"`, `"bearer"`, `"docker-config"`, `"vault"`.
    fn name(&self) -> &'static str;
}

// ── Built-in providers ──────────────────────────────────────────────

/// Always returns `Ok(None)`. The explicit "no auth" placeholder so
/// `--no-auth` translates to a one-element provider chain instead of
/// an empty-vec edge case. Returning `Ok(None)` (not `Err`) is the
/// contract: if a chain ever places `AnonymousProvider` BEFORE other
/// providers, those other providers must still get a chance to
/// resolve.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnonymousProvider;

impl CredentialProvider for AnonymousProvider {
    fn resolve(&self, _registry: &str) -> Result<Option<Credentials>, CredError> {
        Ok(None)
    }
    fn name(&self) -> &'static str {
        "anonymous"
    }
}

/// HTTP Basic auth from a pre-supplied username + password.
#[derive(Debug, Clone)]
pub struct BasicProvider {
    username: String,
    password: String,
}

impl BasicProvider {
    /// Construct from explicit creds. Empty username or password is
    /// rejected at construction time so the failure surfaces at the
    /// CLI boundary (not on the first wire call, where it would
    /// look like a 401 to an operator).
    pub fn new(username: String, password: String) -> Result<Self, CredError> {
        if username.is_empty() || password.is_empty() {
            return Err(CredError::ProviderFailed {
                provider: "basic",
                detail: "username and password must be non-empty".to_string(),
            });
        }
        Ok(BasicProvider { username, password })
    }
}

impl CredentialProvider for BasicProvider {
    fn resolve(&self, _registry: &str) -> Result<Option<Credentials>, CredError> {
        let pair = format!("{}:{}", self.username, self.password);
        Ok(Some(Credentials {
            auth_header: format!("Basic {}", base64_encode(pair.as_bytes())),
            source: "basic",
        }))
    }
    fn name(&self) -> &'static str {
        "basic"
    }
}

/// Pre-acquired bearer token (e.g. a CI-injected GHCR PAT).
#[derive(Debug, Clone)]
pub struct BearerProvider {
    token: String,
}

impl BearerProvider {
    /// Construct from a token string. Empty tokens are rejected at
    /// construction time — sending `Authorization: Bearer ` (empty)
    /// triggers a 400 from the registry that's harder to debug than
    /// a local "token must be non-empty" error.
    pub fn new(token: String) -> Result<Self, CredError> {
        if token.is_empty() {
            return Err(CredError::ProviderFailed {
                provider: "bearer",
                detail: "token must be non-empty".to_string(),
            });
        }
        Ok(BearerProvider { token })
    }
}

impl CredentialProvider for BearerProvider {
    fn resolve(&self, _registry: &str) -> Result<Option<Credentials>, CredError> {
        Ok(Some(Credentials {
            auth_header: format!("Bearer {}", self.token),
            source: "bearer",
        }))
    }
    fn name(&self) -> &'static str {
        "bearer"
    }
}

/// Resolve credentials from environment variables.
///
/// Precedence:
/// 1. `REGISTRY_TOKEN` → `Bearer <token>`.
/// 2. `REGISTRY_USERNAME` + `REGISTRY_PASSWORD` → `Basic <b64>`.
/// 3. None of the above → `Ok(None)` so the next provider in the
///    chain gets a chance.
///
/// `REGISTRY_TOKEN=""` (set but empty) is treated as a typed error,
/// not as `None`: an operator who explicitly exported the variable
/// wanted to use it; surfacing the misconfiguration is better than
/// silently chaining onto the next provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvProvider;

impl EnvProvider {
    pub fn new() -> Self {
        EnvProvider
    }
}

impl CredentialProvider for EnvProvider {
    fn resolve(&self, _registry: &str) -> Result<Option<Credentials>, CredError> {
        match std::env::var(ENV_REGISTRY_TOKEN) {
            Ok(t) if !t.is_empty() => {
                return Ok(Some(Credentials {
                    auth_header: format!("Bearer {t}"),
                    source: "env",
                }));
            }
            Ok(_) => {
                // Set but empty: this is a misconfiguration, not a
                // "fall through to next provider" signal.
                return Err(CredError::ProviderFailed {
                    provider: "env",
                    detail: format!(
                        "{ENV_REGISTRY_TOKEN} is set but empty; unset it or provide a token"
                    ),
                });
            }
            Err(_) => {} // not set — try userpass below.
        }
        let user = std::env::var(ENV_REGISTRY_USERNAME).ok();
        let pass = std::env::var(ENV_REGISTRY_PASSWORD).ok();
        match (user, pass) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
                let pair = format!("{u}:{p}");
                Ok(Some(Credentials {
                    auth_header: format!("Basic {}", base64_encode(pair.as_bytes())),
                    source: "env",
                }))
            }
            (Some(u), Some(p)) if u.is_empty() || p.is_empty() => {
                // Both set, at least one empty — like the token case,
                // an operator who exported these wanted them used.
                Err(CredError::ProviderFailed {
                    provider: "env",
                    detail: format!(
                        "{ENV_REGISTRY_USERNAME} / {ENV_REGISTRY_PASSWORD} are set but at \
                         least one is empty; unset both or provide non-empty values"
                    ),
                })
            }
            _ => {
                // Neither token nor userpass available — let the
                // next provider try. NOT an error: an operator who
                // intentionally chained EnvProvider before
                // AnonymousProvider expects the chain to fall
                // through cleanly when env is unset.
                Ok(None)
            }
        }
    }
    fn name(&self) -> &'static str {
        "env"
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Minimal base64 encoder for HTTP Basic auth header construction.
/// Mirrors the helper the publish side uses — same alphabet, same
/// padding rules, no extra dep dragged in for a few call sites.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Serialises tests in this module that mutate the
    /// `REGISTRY_*` env vars. Without it, parallel cargo test
    /// threads would race the process-global env and flake.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Snapshot + restore the three env vars so tests don't leak
    /// state into each other or into a sibling test crate that
    /// later asserts an unset variable.
    struct EnvGuard {
        prev_token: Option<String>,
        prev_user: Option<String>,
        prev_pass: Option<String>,
    }
    impl EnvGuard {
        fn capture() -> Self {
            EnvGuard {
                prev_token: std::env::var(ENV_REGISTRY_TOKEN).ok(),
                prev_user: std::env::var(ENV_REGISTRY_USERNAME).ok(),
                prev_pass: std::env::var(ENV_REGISTRY_PASSWORD).ok(),
            }
        }
        fn clear(&self) {
            std::env::remove_var(ENV_REGISTRY_TOKEN);
            std::env::remove_var(ENV_REGISTRY_USERNAME);
            std::env::remove_var(ENV_REGISTRY_PASSWORD);
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(ENV_REGISTRY_TOKEN);
            std::env::remove_var(ENV_REGISTRY_USERNAME);
            std::env::remove_var(ENV_REGISTRY_PASSWORD);
            if let Some(v) = &self.prev_token {
                std::env::set_var(ENV_REGISTRY_TOKEN, v);
            }
            if let Some(v) = &self.prev_user {
                std::env::set_var(ENV_REGISTRY_USERNAME, v);
            }
            if let Some(v) = &self.prev_pass {
                std::env::set_var(ENV_REGISTRY_PASSWORD, v);
            }
        }
    }

    /// Catches: a provider that returns `Some(Credentials { auth_header: "" })`
    /// (or anything other than `Ok(None)`) when it has no creds to
    /// offer. Such a provider would silently shadow every downstream
    /// provider — an operator who chained `[AnonymousProvider,
    /// BasicProvider]` would never see the BasicProvider fire,
    /// because AnonymousProvider would have already "returned" creds.
    #[test]
    fn test_anonymous_provider_returns_none() {
        let p = AnonymousProvider;
        let got = p.resolve("ghcr.io").expect("must not error");
        assert!(
            got.is_none(),
            "AnonymousProvider must return Ok(None), not Some(empty); \
             returning Some would silently shadow downstream providers"
        );
        assert_eq!(p.name(), "anonymous");
    }

    /// Catches: a misimplemented base64 alphabet, missing padding,
    /// or wrong scheme name (`Authorization: basic` vs `Basic`) on
    /// the BasicProvider. Such a bug would manifest as 401s against
    /// any private registry without any actionable local error —
    /// the operator would chase a network problem that's actually
    /// in our header construction.
    ///
    /// Reference: `printf 'admin:hunter2' | base64` → `YWRtaW46aHVudGVyMg==`.
    #[test]
    fn test_basic_provider_constructs_correct_header() {
        let p = BasicProvider::new("admin".into(), "hunter2".into()).unwrap();
        let creds = p.resolve("ghcr.io").unwrap().unwrap();
        assert_eq!(creds.auth_header, "Basic YWRtaW46aHVudGVyMg==");
        assert_eq!(creds.source, "basic");
    }

    /// Catches: a regression that lets BasicProvider construct with
    /// empty username or password. Without this guard, the provider
    /// would emit `Authorization: Basic Og==` (base64 of `:`) and
    /// every wire call would 401 with no actionable diagnostic.
    #[test]
    fn test_basic_provider_rejects_empty_credentials_at_construction() {
        let err = BasicProvider::new("".into(), "p".into()).unwrap_err();
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, "basic");
                assert!(detail.contains("non-empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: BearerProvider emitting the wrong scheme (e.g.
    /// `Authorization: bearer` lowercase, or `Token <tok>` instead
    /// of `Bearer <tok>`). Same failure mode as the basic test —
    /// 401s with no local fix point.
    #[test]
    fn test_bearer_provider_constructs_correct_header() {
        let p = BearerProvider::new("ghp_xxxxxxxxxxxxxxxx".into()).unwrap();
        let creds = p.resolve("ghcr.io").unwrap().unwrap();
        assert_eq!(creds.auth_header, "Bearer ghp_xxxxxxxxxxxxxxxx");
        assert_eq!(creds.source, "bearer");
    }

    /// Catches: BearerProvider accepting an empty token at
    /// construction time. Sending `Authorization: Bearer ` produces
    /// a confusing 400 from most registries.
    #[test]
    fn test_bearer_provider_rejects_empty_token_at_construction() {
        let err = BearerProvider::new("".into()).unwrap_err();
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, "bearer");
                assert!(detail.contains("non-empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: EnvProvider preferring `REGISTRY_USERNAME` +
    /// `REGISTRY_PASSWORD` over `REGISTRY_TOKEN` when both are
    /// present. GitHub Actions PAT-based workflows export
    /// `REGISTRY_TOKEN` and rely on it winning over any stale
    /// userpass left in the runner env; reversing the precedence
    /// would silently use the wrong credentials and confuse the
    /// operator on a 401.
    #[test]
    fn test_env_provider_prefers_token_over_userpass() {
        let _g = env_lock();
        let _restore = EnvGuard::capture();
        _restore.clear();
        std::env::set_var(ENV_REGISTRY_TOKEN, "tok-wins");
        std::env::set_var(ENV_REGISTRY_USERNAME, "u");
        std::env::set_var(ENV_REGISTRY_PASSWORD, "p");
        let creds = EnvProvider::new()
            .resolve("any-registry")
            .expect("must not error")
            .expect("must return Some when env vars are set");
        assert_eq!(
            creds.auth_header, "Bearer tok-wins",
            "REGISTRY_TOKEN must win over REGISTRY_USERNAME+REGISTRY_PASSWORD when both are set",
        );
    }

    /// Catches: EnvProvider returning `Some(empty)` (or any other
    /// non-None) when no env vars are set. That shape would skip
    /// every downstream provider and break a chain like
    /// `[EnvProvider, BasicProvider]` — the BasicProvider would
    /// never fire, and the operator would see anonymous-pull
    /// behaviour despite passing `--auth basic` after `--auth env`.
    #[test]
    fn test_env_provider_returns_none_when_unset() {
        let _g = env_lock();
        let _restore = EnvGuard::capture();
        _restore.clear();
        let got = EnvProvider::new()
            .resolve("any-registry")
            .expect("unset env must not error");
        assert!(
            got.is_none(),
            "EnvProvider must return Ok(None) when unset; got {got:?}",
        );
    }

    /// Catches: EnvProvider silently treating
    /// `REGISTRY_TOKEN=""` (set but empty) as "unset" and falling
    /// through to the next provider. An operator who exported the
    /// variable wanted to use it; surfacing the misconfiguration
    /// is the contract.
    #[test]
    fn test_env_provider_empty_token_is_typed_error() {
        let _g = env_lock();
        let _restore = EnvGuard::capture();
        _restore.clear();
        std::env::set_var(ENV_REGISTRY_TOKEN, "");
        let err = EnvProvider::new()
            .resolve("any-registry")
            .expect_err("empty token must surface as error, not None");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, "env");
                assert!(detail.contains("REGISTRY_TOKEN"));
                assert!(detail.contains("empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }
}
