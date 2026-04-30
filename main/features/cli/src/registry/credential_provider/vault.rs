//! [`VaultCredentialProvider`] — pulls registry credentials from a
//! HashiCorp Vault KV v2 path.
//!
//! Compiled only when the parent crate is built with `--features vault`.
//! Without that feature, `vaultrs` is not in the dep graph and this
//! module does not exist; the default `oci` binary keeps the same
//! shape it had before this provider was added.
//!
//! ## Why a trait-bound backend
//!
//! `vaultrs` is async and talks to a real Vault server over HTTP.
//! Mapping its response shape to [`Credentials`] is logic we want to
//! unit-test without spinning up a Vault dev server. The provider is
//! therefore generic over a [`VaultBackend`] trait that owns the
//! single "read this KV v2 path" operation; production code wires
//! the [`VaultrsBackend`] impl which spins a tokio runtime and calls
//! `vaultrs::kv2::read`, while tests inject a hand-rolled stub
//! returning canned JSON so every mapping branch has a test that
//! names the bug it catches.
//!
//! ## Path layout
//!
//! Vault KV v2 reads use the `<mount>/data/<key>` URL form on the
//! wire, but the `vaultrs::kv2::read` helper takes `(mount, key)`
//! and inserts `/data/` itself. We accept a single `base_path`
//! string (default `"secret/data/registry"`) at construction, split
//! it on the first `/data/` to recover `(mount, prefix)`, and
//! append the registry host as the final path segment. So
//! `base_path = "secret/data/registry"` + `registry = "ghcr.io"`
//! reads `secret/data/registry/ghcr.io` on the wire.
//!
//! ## Auth
//!
//! By default we read `VAULT_ADDR` + `VAULT_TOKEN` from the
//! environment, mirroring the standard Vault SDK convention so a CI
//! runner that already has Vault Agent populating those vars works
//! without per-tool config. For AppRole / Kubernetes / JWT auth,
//! callers can construct the provider with [`VaultCredentialProvider::new`]
//! and a pre-acquired token; the v1 surface stops there. AppRole
//! login is a follow-up.
//!
//! ## Response schema
//!
//! The KV v2 secret under `<base_path>/<registry>` is expected to
//! be a JSON object carrying either:
//!
//! - `{ "username": "...", "password": "..." }` — Basic auth, OR
//! - `{ "token": "..." }` — Bearer token.
//!
//! Both fields may coexist; in that case **token wins**. Reasoning:
//! tokens are usually narrower-scoped (a registry-specific PAT) and
//! more recently rotated than a long-lived admin username/password
//! pair, so an operator who provisioned both intends the token to
//! be the active credential. The precedence is asserted by
//! [`tests::test_vault_response_with_both_token_and_userpass_prefers_token`].
//!
//! ## Failure mapping
//!
//! - **404 from Vault** → `Ok(None)`. The path doesn't exist for
//!   this registry, so the provider has nothing to offer; the
//!   AuthManager moves to the next provider in the chain. Note this
//!   is the only "soft" outcome — every other failure is hard.
//! - **401 / 403 from Vault** → [`CredError::ProviderFailed`]. The
//!   operator gave us a token, the token doesn't permit the read;
//!   silently falling through to anonymous would mask the
//!   misconfiguration.
//! - **Malformed response** (neither `username`+`password` nor
//!   `token` is present and a string) → [`CredError::ProviderFailed`].
//!   An operator who wrote a secret to this path expected it used;
//!   silently falling through hides their schema bug.
//! - **Network / connection failure** → [`CredError::Io`]. Vault is
//!   unreachable; surface so CI fails loudly rather than pushing
//!   unauthenticated.

use std::env;

use serde::Deserialize;

use super::{CredError, CredentialProvider, Credentials};

/// Stable identifier of this provider — appears in
/// [`Credentials::source`] and in [`CredError`] variants so log lines
/// and exit-code diagnostics name "vault" specifically when they're
/// caused by this provider rather than a sibling one.
pub const PROVIDER_NAME: &str = "vault";

/// Default Vault KV v2 base path. The wire form is `<mount>/data/<prefix>/<key>`.
/// `secret/data/registry` resolves to mount `secret`, prefix `registry`,
/// and a per-registry key suffix (e.g. `ghcr.io`).
pub const DEFAULT_BASE_PATH: &str = "secret/data/registry";

/// Env vars consulted by [`VaultCredentialProvider::from_env`]. We
/// match the standard Vault SDK convention so an operator who
/// already has Vault Agent populating these doesn't have to learn a
/// second name.
pub const ENV_VAULT_ADDR: &str = "VAULT_ADDR";
pub const ENV_VAULT_TOKEN: &str = "VAULT_TOKEN";

/// Errors a [`VaultBackend`] can surface. Modeled to preserve the
/// HTTP status code distinctly because the provider's mapping logic
/// (404 → `Ok(None)`, 401/403 → `Err(ProviderFailed)`) depends on it.
#[derive(Debug)]
pub enum VaultBackendError {
    /// The Vault server returned an HTTP status the backend could
    /// recognise. `code == 404` means "path not found" (mapped to
    /// `Ok(None)` by the provider); other codes propagate as
    /// `CredError::ProviderFailed` with the status surfaced in the
    /// detail string.
    Api { code: u16, detail: String },
    /// I/O / transport failure (no Vault server reachable, TLS
    /// handshake aborted, etc.).
    Io { detail: String },
}

impl std::fmt::Display for VaultBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultBackendError::Api { code, detail } => {
                write!(f, "vault API error {code}: {detail}")
            }
            VaultBackendError::Io { detail } => write!(f, "vault I/O error: {detail}"),
        }
    }
}

impl std::error::Error for VaultBackendError {}

/// Single operation the provider needs from a Vault server. Owning
/// this in a trait — rather than calling `vaultrs` directly — is
/// what lets the unit tests stub the response shape without spinning
/// up a real Vault.
pub trait VaultBackend: Send + Sync {
    /// Read a KV v2 secret at `<mount>/data/<key>` and return the
    /// deserialised JSON object. `mount` is the engine mount point
    /// (`secret`); `key` is the path within it (`registry/ghcr.io`).
    /// 404 from Vault MUST surface as `VaultBackendError::Api { code: 404, ... }`
    /// — the provider relies on the distinction to map "no creds for
    /// this registry" (`Ok(None)`) versus "Vault auth is broken"
    /// (`Err`).
    fn read_kv2(&self, mount: &str, key: &str) -> Result<serde_json::Value, VaultBackendError>;
}

/// Schema of the JSON object stored under the KV v2 path. Both
/// fields are optional so the deserialiser accepts either userpass
/// or token shape; the validation that *some* recognisable shape
/// must be present runs in [`map_response_to_credentials`].
#[derive(Debug, Deserialize)]
struct VaultRegistrySecret {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

/// A [`CredentialProvider`] that fetches registry credentials from a
/// Vault KV v2 path.
///
/// Generic over [`VaultBackend`] so production code uses the
/// real-Vault [`VaultrsBackend`] while unit tests inject a stub.
pub struct VaultCredentialProvider<B: VaultBackend> {
    backend: B,
    /// Mount point (e.g. `secret`).
    mount: String,
    /// Prefix inside the mount, joined to the registry host on each
    /// resolve call. May be empty (e.g. `secret/data` with no
    /// prefix → `secret/data/<registry>` on the wire).
    prefix: String,
}

impl<B: VaultBackend> VaultCredentialProvider<B> {
    /// Construct directly from a backend + base path. The base path
    /// must contain `/data/` (KV v2 convention). For test code or
    /// custom auth (AppRole, etc.).
    pub fn with_backend(backend: B, base_path: &str) -> Result<Self, CredError> {
        let (mount, prefix) = parse_base_path(base_path)?;
        Ok(Self {
            backend,
            mount,
            prefix,
        })
    }
}

/// Typed result of [`VaultCredentialProvider::resolve_auth_mode`] —
/// the raw fields the secret carried, before they're folded into a
/// pre-built `Authorization` header.
///
/// Exists alongside the trait's [`Credentials`] return shape so the
/// CLI dispatcher can map Vault output back into
/// [`crate::cmd::publish::AuthMode::Basic`] /
/// [`crate::cmd::publish::AuthMode::Bearer`] without round-tripping
/// through header-encode + base64-decode (which would also accept a
/// tampered Vault response that decoded to an unintended pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedVaultAuth {
    /// Secret carried `username` + `password`. Maps to HTTP Basic.
    Basic { username: String, password: String },
    /// Secret carried `token`. Maps to a pre-acquired bearer.
    Bearer { token: String },
}

impl<B: VaultBackend> VaultCredentialProvider<B> {
    /// Resolve into a typed [`ResolvedVaultAuth`] for the CLI
    /// dispatcher path. Same backend call + same precedence /
    /// validation rules as the [`CredentialProvider::resolve`]
    /// trait method (404 → `Ok(None)`, 401/403 → ProviderFailed,
    /// malformed response → ProviderFailed, token-wins-over-userpass).
    /// Returns the raw `(username, password)` / `token` fields
    /// directly so the caller can construct an
    /// [`crate::cmd::publish::AuthMode`] without inverting the
    /// encoded header.
    pub fn resolve_auth_mode(
        &self,
        registry: &str,
    ) -> Result<Option<ResolvedVaultAuth>, CredError> {
        if registry.is_empty() {
            return Err(CredError::ProviderFailed {
                provider: PROVIDER_NAME,
                detail: "registry name must be non-empty".into(),
            });
        }
        let key = if self.prefix.is_empty() {
            registry.to_string()
        } else {
            format!("{}/{}", self.prefix, registry)
        };
        let raw = match self.backend.read_kv2(&self.mount, &key) {
            Ok(v) => v,
            Err(VaultBackendError::Api { code: 404, .. }) => return Ok(None),
            Err(e) => {
                return Err(CredError::ProviderFailed {
                    provider: PROVIDER_NAME,
                    detail: format!("read {}/data/{}: {e}", self.mount, key),
                });
            }
        };
        map_response_to_auth_mode(raw).map(Some)
    }
}

impl<B: VaultBackend> CredentialProvider for VaultCredentialProvider<B> {
    fn resolve(&self, registry: &str) -> Result<Option<Credentials>, CredError> {
        // Dispatch through the typed shape so the trait + dispatcher
        // paths agree byte-for-byte on what counts as a valid Vault
        // response. Header composition is the only difference.
        let Some(resolved) = self.resolve_auth_mode(registry)? else {
            return Ok(None);
        };
        let auth_header = match resolved {
            ResolvedVaultAuth::Bearer { token } => format!("Bearer {token}"),
            ResolvedVaultAuth::Basic { username, password } => {
                let pair = format!("{username}:{password}");
                format!("Basic {}", base64_encode(pair.as_bytes()))
            }
        };
        Ok(Some(Credentials {
            auth_header,
            source: PROVIDER_NAME,
        }))
    }

    fn name(&self) -> &'static str {
        PROVIDER_NAME
    }
}

/// Map a deserialised Vault KV v2 secret to [`ResolvedVaultAuth`].
///
/// Precedence rule: when both `token` AND (`username`+`password`)
/// are present and non-empty, **token wins**. See module-level
/// docs for the reasoning; the test
/// `test_vault_response_with_both_token_and_userpass_prefers_token`
/// pins this contract.
///
/// Returns:
/// - `Ok(ResolvedVaultAuth)` for a recognisable shape.
/// - `Err(CredError::ProviderFailed)` for a malformed shape (no
///   recognisable fields, or a field present but empty / wrong
///   type). We deliberately do not return `Ok(None)` analogue here:
///   a 404 from Vault is "no path"; reaching this function means
///   the path WAS read, and silently treating a malformed payload
///   as "no creds" would mask the operator's schema bug.
fn map_response_to_auth_mode(raw: serde_json::Value) -> Result<ResolvedVaultAuth, CredError> {
    let parsed: VaultRegistrySecret =
        serde_json::from_value(raw.clone()).map_err(|e| CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: format!(
                "vault response did not match expected schema (expected username+password \
                 or token as strings): {e}"
            ),
        })?;

    // Token branch wins when present + non-empty (precedence rule).
    if let Some(tok) = parsed.token.as_deref() {
        if !tok.is_empty() {
            return Ok(ResolvedVaultAuth::Bearer {
                token: tok.to_string(),
            });
        }
        // Token field present but empty: this is a misconfiguration,
        // not "fall through to userpass". An operator who wrote
        // `token = ""` to Vault is a bug, not a feature.
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "vault secret 'token' field is set but empty".into(),
        });
    }

    match (parsed.username.as_deref(), parsed.password.as_deref()) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Ok(ResolvedVaultAuth::Basic {
            username: u.to_string(),
            password: p.to_string(),
        }),
        (Some(_), Some(_)) => Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "vault secret has username and password fields but at least one is empty"
                .into(),
        }),
        _ => Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: format!(
                "vault response missing both 'token' and 'username'+'password' \
                 (got keys: {:?})",
                response_top_level_keys(&raw),
            ),
        }),
    }
}

/// Split a `secret/data/registry`-style base path into `(mount, prefix)`.
/// Errors if the `/data/` infix is absent — the KV v2 convention is
/// load-bearing, and a path without it is almost certainly an
/// operator typo (e.g. `secret/registry` for KV v1 written into a v2
/// mount).
fn parse_base_path(base: &str) -> Result<(String, String), CredError> {
    // Strip a trailing slash but NOT a leading one — a leading
    // slash means the operator wrote `/data/foo` (empty mount),
    // which we want to surface as the specific "empty mount"
    // diagnostic, not as the generic "missing /data/ infix" one.
    let working = base.strip_suffix('/').unwrap_or(base);
    if working.is_empty() {
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "vault base path must not be empty".into(),
        });
    }
    let (mount, prefix) = match working.split_once("/data/") {
        Some((m, p)) => (m.to_string(), p.trim_matches('/').to_string()),
        None => {
            // Allow a bare `<mount>/data` (no prefix) — that's a
            // valid KV v2 root, just no per-prefix grouping.
            if let Some(m) = working.strip_suffix("/data") {
                (m.to_string(), String::new())
            } else {
                return Err(CredError::ProviderFailed {
                    provider: PROVIDER_NAME,
                    detail: format!(
                        "vault base path {base:?} must contain '/data/' (KV v2 convention) — \
                         e.g. 'secret/data/registry'"
                    ),
                });
            }
        }
    };
    if mount.is_empty() {
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: format!("vault base path {base:?} has empty mount before '/data/'"),
        });
    }
    Ok((mount, prefix))
}

/// List the top-level JSON keys in a value for diagnostics. Bounded
/// to 16 keys so a hostile / huge response can't dictate operator
/// log noise.
fn response_top_level_keys(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Object(map) => map.keys().take(16).cloned().collect(),
        _ => vec![format!("<non-object: {}>", json_type_name(v))],
    }
}

fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Minimal base64 encoder — same shape as the sibling `BasicProvider`
/// helper. Duplicated rather than shared because the sibling is
/// `pub(super)`-private to `credential_provider.rs` and exposing it
/// would widen the API surface for one call site.
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

// ── Real-Vault backend ───────────────────────────────────────────────────

/// Production [`VaultBackend`] backed by `vaultrs` over a tokio
/// runtime. The runtime is owned per-provider so a CLI invocation
/// that doesn't use Vault never spins one up; the provider's
/// resolve calls are blocking from the rest of the CLI's perspective.
pub struct VaultrsBackend {
    client: vaultrs::client::VaultClient,
    /// A current-thread tokio runtime owned by the provider.
    /// Spinning it once at construction time means each `resolve()`
    /// call is a `block_on` rather than a runtime build — important
    /// when we later move to multi-blob pulls and `resolve` is hit
    /// on a hot path. Current-thread (vs multi-thread) keeps the
    /// extra-thread cost off the default-vault binary; we only need
    /// one thread at a time for the single in-flight Vault read.
    runtime: tokio::runtime::Runtime,
}

// Manual Debug — `VaultClient` and `tokio::runtime::Runtime` don't
// impl Debug, so a derive doesn't compile. We don't want to leak
// any secret-bearing field into log output anyway, so the manual
// impl prints a stable type-name marker only.
impl std::fmt::Debug for VaultrsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultrsBackend").finish_non_exhaustive()
    }
}

impl VaultrsBackend {
    fn new(address: &str, token: &str) -> Result<Self, CredError> {
        if address.is_empty() {
            return Err(CredError::ProviderFailed {
                provider: PROVIDER_NAME,
                detail: format!("{ENV_VAULT_ADDR} must be non-empty"),
            });
        }
        if token.is_empty() {
            return Err(CredError::ProviderFailed {
                provider: PROVIDER_NAME,
                detail: format!("{ENV_VAULT_TOKEN} must be non-empty"),
            });
        }
        let settings = vaultrs::client::VaultClientSettingsBuilder::default()
            .address(address)
            .token(token)
            .build()
            .map_err(|e| CredError::ProviderFailed {
                provider: PROVIDER_NAME,
                detail: format!("vault settings: {e}"),
            })?;
        let client =
            vaultrs::client::VaultClient::new(settings).map_err(|e| CredError::ProviderFailed {
                provider: PROVIDER_NAME,
                detail: format!("vault client: {e}"),
            })?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|source| CredError::Io {
                provider: PROVIDER_NAME,
                source,
            })?;
        Ok(Self { client, runtime })
    }
}

impl VaultBackend for VaultrsBackend {
    fn read_kv2(&self, mount: &str, key: &str) -> Result<serde_json::Value, VaultBackendError> {
        let fut = vaultrs::kv2::read::<serde_json::Value>(&self.client, mount, key);
        let result = self.runtime.block_on(fut);
        match result {
            Ok(v) => Ok(v),
            Err(vaultrs::error::ClientError::APIError { code, errors }) => {
                Err(VaultBackendError::Api {
                    code,
                    detail: if errors.is_empty() {
                        format!("HTTP {code}")
                    } else {
                        errors.join("; ")
                    },
                })
            }
            Err(e) => Err(VaultBackendError::Io {
                detail: format!("{e}"),
            }),
        }
    }
}

/// Type alias for the production-shaped provider — `--auth vault`
/// resolves through this. Unit tests use the generic
/// `VaultCredentialProvider<StubBackend>` so they don't depend on a
/// running Vault.
pub type VaultProvider = VaultCredentialProvider<VaultrsBackend>;

impl VaultProvider {
    /// Construct from `VAULT_ADDR` + `VAULT_TOKEN` env vars. Returns
    /// `Ok(None)` if either is unset (lets the CLI map that to a
    /// clean "vault not configured" exit) and an error if they're
    /// set but the underlying client construction fails.
    pub fn from_env(base_path: &str) -> Result<Option<Self>, CredError> {
        let addr = match env::var(ENV_VAULT_ADDR) {
            Ok(a) if !a.is_empty() => a,
            _ => return Ok(None),
        };
        let token = match env::var(ENV_VAULT_TOKEN) {
            Ok(t) if !t.is_empty() => t,
            _ => return Ok(None),
        };
        let backend = VaultrsBackend::new(&addr, &token)?;
        Self::with_backend(backend, base_path).map(Some)
    }

    /// Construct with explicit address + token. For AppRole / JWT
    /// callers that have already minted a token by some external
    /// path; also used by the integration test which wires a
    /// dev-server token directly.
    pub fn new(address: &str, token: &str, base_path: &str) -> Result<Self, CredError> {
        let backend = VaultrsBackend::new(address, token)?;
        Self::with_backend(backend, base_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Minimal in-test [`VaultBackend`] — every call returns the
    /// same canned response (or error). Tracks the last-requested
    /// `(mount, key)` tuple so tests can assert the path
    /// composition is correct.
    struct StubBackend {
        response: Mutex<Result<serde_json::Value, VaultBackendError>>,
        last_key: Mutex<Option<(String, String)>>,
    }
    impl StubBackend {
        fn ok(v: serde_json::Value) -> Self {
            Self {
                response: Mutex::new(Ok(v)),
                last_key: Mutex::new(None),
            }
        }
        fn err(e: VaultBackendError) -> Self {
            Self {
                response: Mutex::new(Err(e)),
                last_key: Mutex::new(None),
            }
        }
    }
    impl VaultBackend for StubBackend {
        fn read_kv2(&self, mount: &str, key: &str) -> Result<serde_json::Value, VaultBackendError> {
            *self.last_key.lock().unwrap() = Some((mount.to_string(), key.to_string()));
            // Clone-or-move-equivalent: serde_json::Value is Clone,
            // VaultBackendError is not, so the latter is "consumed"
            // by replacing it with a sentinel for the next call.
            // Tests only call resolve() once, so this is fine.
            let mut slot = self.response.lock().unwrap();
            match &*slot {
                Ok(v) => Ok(v.clone()),
                Err(_) => std::mem::replace(
                    &mut *slot,
                    Err(VaultBackendError::Io {
                        detail: "stub already consumed".into(),
                    }),
                ),
            }
        }
    }

    fn make_provider(stub: StubBackend) -> VaultCredentialProvider<StubBackend> {
        VaultCredentialProvider::with_backend(stub, DEFAULT_BASE_PATH)
            .expect("default base path must parse")
    }

    /// Catches: a regression where a Vault response with both
    /// `username` and `password` fields produces a malformed Basic
    /// header (missing field silently coerces to empty, header
    /// becomes `Basic <b64-of-only-userpart>` and the registry
    /// 401s with no actionable diagnostic).
    #[test]
    fn test_vault_response_with_username_password_maps_to_basic() {
        let stub = StubBackend::ok(serde_json::json!({
            "username": "admin",
            "password": "hunter2",
        }));
        let p = make_provider(stub);
        let creds = p
            .resolve("ghcr.io")
            .expect("must succeed")
            .expect("must yield Some");
        // base64 of `admin:hunter2` → `YWRtaW46aHVudGVyMg==`.
        assert_eq!(creds.auth_header, "Basic YWRtaW46aHVudGVyMg==");
        assert_eq!(creds.source, PROVIDER_NAME);
    }

    /// Catches: a Vault response carrying `token` as a non-string
    /// type (e.g. an integer, because the operator wrote a numeric
    /// secret) silently coercing to "" / "0" / junk and the wire
    /// call hitting a 400. The schema validation must reject the
    /// payload up front.
    #[test]
    fn test_vault_response_with_token_maps_to_bearer() {
        let stub = StubBackend::ok(serde_json::json!({ "token": "ghp_xxxxxx" }));
        let p = make_provider(stub);
        let creds = p
            .resolve("ghcr.io")
            .expect("must succeed")
            .expect("must yield Some");
        assert_eq!(creds.auth_header, "Bearer ghp_xxxxxx");
        assert_eq!(creds.source, PROVIDER_NAME);
    }

    /// Catches: an integer `token` field silently mapped to junk
    /// instead of the schema validator rejecting up front. Without
    /// this, `token = 42` would get serialised to a Bearer header
    /// of garbage and the 400 from the registry would send the
    /// operator chasing a network bug.
    #[test]
    fn test_vault_response_with_non_string_token_is_provider_failed() {
        let stub = StubBackend::ok(serde_json::json!({ "token": 42 }));
        let p = make_provider(stub);
        let err = p
            .resolve("ghcr.io")
            .expect_err("non-string token must surface as ProviderFailed");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(
                    detail.contains("schema") || detail.contains("string"),
                    "detail must name the schema mismatch; got {detail:?}",
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: a 404 from Vault treated as "broken provider" rather
    /// than "this provider doesn't have creds for this registry."
    /// Operator scenario: Vault has secrets for `ghcr.io` but not
    /// `docker.io`; the chain `[Vault, Anonymous]` must let
    /// `docker.io` fall through to anonymous, not error out.
    #[test]
    fn test_vault_path_not_found_returns_none() {
        let stub = StubBackend::err(VaultBackendError::Api {
            code: 404,
            detail: "not found".into(),
        });
        let p = make_provider(stub);
        let got = p
            .resolve("docker.io")
            .expect("404 must NOT surface as Err — chain must walk");
        assert!(
            got.is_none(),
            "404 from Vault must map to Ok(None) so the chain reaches the next provider; \
             got Some({got:?})",
        );
    }

    /// Catches: a 401/403 from Vault silently treated like 404,
    /// causing the chain to fall through to anonymous and an
    /// operator who configured Vault to see their CI silently push
    /// unauthenticated. Auth failures from Vault MUST be loud.
    #[test]
    fn test_vault_auth_failure_returns_provider_failed() {
        let stub = StubBackend::err(VaultBackendError::Api {
            code: 403,
            detail: "permission denied".into(),
        });
        let p = make_provider(stub);
        let err = p
            .resolve("ghcr.io")
            .expect_err("403 must NOT silently fall through");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(
                    detail.contains("403"),
                    "detail must surface the HTTP status; got {detail:?}",
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: a Vault response that doesn't contain ANY
    /// recognisable credential field (no token, no username/password)
    /// silently treated as "no creds, fall through" — which would
    /// hide an operator's schema bug (e.g. they wrote
    /// `{ "user": "x", "pass": "y" }` instead of the expected key
    /// names).
    #[test]
    fn test_vault_malformed_response_returns_provider_failed() {
        let stub = StubBackend::ok(serde_json::json!({
            "user": "wrong-key",
            "pass": "wrong-key",
        }));
        let p = make_provider(stub);
        let err = p
            .resolve("ghcr.io")
            .expect_err("schema mismatch must surface, not silently fall through");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(
                    detail.contains("missing") || detail.contains("token"),
                    "detail must explain what was missing; got {detail:?}",
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: an ambiguous response (both token AND username/password
    /// present) producing non-deterministic credential choice. The
    /// contract is "token wins"; reversing it would silently change
    /// what an operator's chained config does and surface as
    /// 401-against-userpass or vice versa.
    #[test]
    fn test_vault_response_with_both_token_and_userpass_prefers_token() {
        let stub = StubBackend::ok(serde_json::json!({
            "username": "admin",
            "password": "hunter2",
            "token": "ghp_winner",
        }));
        let p = make_provider(stub);
        let creds = p.resolve("ghcr.io").unwrap().unwrap();
        assert_eq!(
            creds.auth_header, "Bearer ghp_winner",
            "ambiguous shape must deterministically prefer token; got {:?}",
            creds.auth_header,
        );
    }

    /// Catches: a `token` field present but empty silently falling
    /// through to userpass. An operator who wrote `token = ""`
    /// expected the token path used; surfacing the empty-string
    /// misconfiguration is the contract.
    #[test]
    fn test_vault_response_with_empty_token_is_provider_failed() {
        let stub = StubBackend::ok(serde_json::json!({
            "token": "",
            "username": "fallback",
            "password": "fallback",
        }));
        let p = make_provider(stub);
        let err = p
            .resolve("ghcr.io")
            .expect_err("empty token must surface, not fall through to userpass");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(
                    detail.contains("empty"),
                    "detail must say 'empty': {detail:?}"
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: the provider composing the wrong wire path (e.g.
    /// dropping the prefix, doubling slashes, or escaping the
    /// registry host). Without this test, a refactor that switched
    /// `format!("{}/{}", prefix, registry)` to a join helper that
    /// stripped trailing-slashes incorrectly would silently 404
    /// every read.
    #[test]
    fn test_vault_wire_path_composition() {
        let stub = StubBackend::ok(serde_json::json!({ "token": "t" }));
        let p = make_provider(stub);
        p.resolve("ghcr.io").unwrap().unwrap();
        let key = p.backend.last_key.lock().unwrap().clone().unwrap();
        assert_eq!(key.0, "secret", "mount must be 'secret'");
        assert_eq!(
            key.1, "registry/ghcr.io",
            "wire key must be '<prefix>/<registry>'",
        );
    }

    /// Catches: an empty registry argument silently composing a
    /// list-shaped path that returns an unexpected response. Empty
    /// is a misuse, surfaces as a clear error.
    #[test]
    fn test_vault_resolve_with_empty_registry_is_provider_failed() {
        let stub = StubBackend::ok(serde_json::json!({ "token": "t" }));
        let p = make_provider(stub);
        let err = p
            .resolve("")
            .expect_err("empty registry must error, not silently list");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(detail.contains("non-empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: `parse_base_path` accepting a KV-v1-shaped path
    /// (`secret/registry`, no `/data/` infix) and silently producing
    /// wrong wire URLs. The KV v2 convention is load-bearing.
    #[test]
    fn test_parse_base_path_rejects_kv_v1_shape() {
        let err = parse_base_path("secret/registry").expect_err("must reject KV v1 path");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(detail.contains("/data/"), "detail must explain: {detail:?}");
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: `parse_base_path` mishandling a trailing `/data` (no
    /// prefix) — splitting by `"/data/"` would miss the trailing
    /// case and reject a valid empty-prefix path. The fallback to
    /// `strip_suffix("/data")` is the patch for this.
    #[test]
    fn test_parse_base_path_accepts_bare_data_root() {
        let (mount, prefix) = parse_base_path("kv/data").unwrap();
        assert_eq!(mount, "kv");
        assert_eq!(prefix, "");
    }

    /// Catches: `parse_base_path` letting `"/data/foo"` (empty
    /// mount) through. Without the explicit empty-mount check, the
    /// downstream wire call would hit `/v1//data/foo` which is a
    /// malformed Vault URL and the operator would chase a confusing
    /// 404.
    #[test]
    fn test_parse_base_path_rejects_empty_mount() {
        let err = parse_base_path("/data/registry").expect_err("must reject empty mount");
        match err {
            CredError::ProviderFailed { detail, .. } => {
                assert!(detail.contains("empty mount"), "got {detail:?}");
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: VaultrsBackend constructed with empty address /
    /// token producing a confusing client-internal error rather
    /// than the local "must be non-empty" diagnostic. Same
    /// fail-fast shape as Basic/Bearer providers.
    #[test]
    fn test_vaultrs_backend_rejects_empty_token() {
        let err = VaultrsBackend::new("http://127.0.0.1:8200", "")
            .expect_err("empty token must be rejected at construction");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(detail.contains("VAULT_TOKEN") && detail.contains("non-empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_vaultrs_backend_rejects_empty_address() {
        let err = VaultrsBackend::new("", "tok").expect_err("empty addr must be rejected");
        match err {
            CredError::ProviderFailed { detail, .. } => {
                assert!(detail.contains("VAULT_ADDR") && detail.contains("non-empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: `provider.name()` returning a stale string when the
    /// provider is renamed in source. The Credentials.source field
    /// must match the provider name (used in log diagnostics to
    /// trace which provider sourced a given credential).
    #[test]
    fn test_provider_name_matches_credentials_source() {
        let stub = StubBackend::ok(serde_json::json!({ "token": "t" }));
        let p = make_provider(stub);
        let creds = p.resolve("ghcr.io").unwrap().unwrap();
        assert_eq!(p.name(), PROVIDER_NAME);
        assert_eq!(creds.source, PROVIDER_NAME);
    }
}
