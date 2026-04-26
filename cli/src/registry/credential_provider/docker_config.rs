//! [`DockerConfigCredentialProvider`] — pulls registry credentials
//! from the static `~/.docker/config.json` an operator already wrote
//! when they ran `docker login`.
//!
//! Compiled only when the parent crate is built with
//! `--features docker-config`. Without that feature, neither
//! `base64` nor `dirs` is in the dep graph and this module does not
//! exist; the default `ocimage` binary keeps the same shape it had
//! before this provider was added.
//!
//! ## What this provider IS NOT
//!
//! This provider does not depend on Docker the daemon being
//! installed, running, or even ever invoked locally. It only reads
//! the static JSON file at the well-known path. That keeps the
//! "no Docker as a runtime dep" rule from
//! [`docs/3-design/scope-and-boundaries.md`] intact: an operator
//! with a `config.json` (e.g. one written by `podman login`, or
//! synthesised by a CI workflow's `mkdir ~/.docker && cat > config.json`
//! step) gets credential resolution without `docker` itself being
//! on PATH.
//!
//! ## Why a trait-bound backend
//!
//! The mapping logic — `auth` field base64 decode, precedence
//! between `auth` and explicit `username` + `password`, Bearer
//! flavour for `identitytoken`, fallthrough rules for unknown
//! registries — is the part we want to unit-test exhaustively. The
//! filesystem read is a single byte-array load. Keeping the load
//! behind a [`DockerConfigBackend`] trait lets every unit test
//! inject canned `auths` maps (or simulated read failures) without
//! ever touching the real `~/.docker/config.json` (which would race
//! across parallel `cargo test` threads and leak operator state
//! into the test).
//!
//! ## Schema (Docker config.json v2 form)
//!
//! ```json
//! {
//!   "auths": {
//!     "ghcr.io": { "auth": "<base64-encoded username:password>" },
//!     "registry.acme.io": {
//!       "username": "...",
//!       "password": "..."
//!     },
//!     "tokenized.example": {
//!       "identitytoken": "<oauth-style-bearer>"
//!     }
//!   },
//!   "credHelpers": {
//!     "ecr.amazonaws.com": "ecr-login"
//!   }
//! }
//! ```
//!
//! v0 of this provider supports the `auths` block only. The
//! `credHelpers` delegation requires a subprocess call to a
//! `docker-credential-<name>` binary (stdin: registry URL; stdout:
//! `{"Username":"...","Secret":"..."}` JSON) and is tracked as a
//! v0.2 follow-up — see the issue linked from the commit.
//!
//! ## Lookup rules
//!
//! 1. Look up `auths.<registry>` exactly. If found and parseable,
//!    return it.
//! 2. If not found, try `auths.https://<registry>` — Docker stores
//!    some entries with the scheme prefix (older client versions,
//!    explicit `docker login https://ghcr.io`).
//! 3. If still not found, return `Ok(None)`. The chain walker moves
//!    to the next provider; this is NOT a hard error because a
//!    missing entry is the normal "I'm not logged into this
//!    registry" case.
//!
//! ## Precedence between `auth` and explicit `username` / `password`
//!
//! When both are present, **`auth` wins**. Docker's documented
//! behaviour is that the `auth` field is the authoritative
//! base64-encoded form; explicit `username` / `password` fields are
//! a convenience shape some tools (and older `docker login`
//! versions) emit but `docker login` itself writes only `auth`.
//! Reversing the precedence would mean two tools editing the same
//! `config.json` end up disagreeing on which credentials are active
//! depending on which one wrote last. Pinned by
//! [`tests::test_auth_field_wins_over_explicit_userpass`].
//!
//! ## Failure mapping
//!
//! - **Config file missing** → `Ok(None)`. An operator who never
//!   ran `docker login` should not have their `--auth docker-config`
//!   invocation hard-fail; the chain walker moves to the next
//!   provider (likely Anonymous) and the wire layer continues. This
//!   mirrors the Vault provider's "404 → Ok(None)" rule.
//! - **Config file malformed JSON** → [`CredError::ProviderFailed`].
//!   The operator has a `config.json` but it's corrupt; silent
//!   fallthrough would mask the schema bug.
//! - **`auth` field present but not valid base64** → [`CredError::ProviderFailed`].
//!   A garbled `auth` field is operator data corruption; same
//!   reasoning as the malformed-JSON case.
//! - **`auth` field decodes but lacks the `:` separator** → [`CredError::ProviderFailed`].
//!   The decoded bytes are not a valid `username:password` pair.
//! - **`auth` is empty after decoding both halves** (decoded form is
//!   `:` only) → [`CredError::ProviderFailed`]. Mirrors the
//!   BasicProvider's "empty userpass at construction" guard.
//! - **Half-populated entry** (e.g. `username` set, `password`
//!   missing) → [`CredError::ProviderFailed`]. Same fail-loud
//!   contract as the EnvProvider's "set but empty" guard.
//! - **I/O fault reading the file** (permission denied, unreadable
//!   media) → [`CredError::Io`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::Deserialize;

use super::{CredError, CredentialProvider, Credentials};

/// Stable identifier of this provider — appears in
/// [`Credentials::source`] and in [`CredError`] variants so log lines
/// and exit-code diagnostics name "docker-config" specifically when
/// they're caused by this provider rather than a sibling one.
pub const PROVIDER_NAME: &str = "docker-config";

/// Single operation the provider needs from the filesystem. Owning
/// this in a trait lets every unit test inject canned `auths` maps
/// without touching the real `~/.docker/config.json`.
///
/// `None` means "the file does not exist." `Some(map)` means the
/// file exists and parsed cleanly; the map MUST be the exact
/// `auths` block from the JSON. An I/O fault or a JSON-parse error
/// surfaces as `Err`, not `Ok(None)` — the distinction is
/// load-bearing for the provider's "missing file → Ok(None) so the
/// chain walker continues" mapping.
pub trait DockerConfigBackend: Send + Sync {
    /// Read and parse the Docker config file. Returns:
    ///
    /// - `Ok(None)` when the file does not exist (operator never ran
    ///   `docker login`).
    /// - `Ok(Some(auths))` when the file exists and parsed; `auths`
    ///   is the per-registry map.
    /// - `Err(CredError::Io)` on I/O failure (permission denied, etc.).
    /// - `Err(CredError::ProviderFailed)` on JSON parse failure.
    fn load_auths(&self) -> Result<Option<HashMap<String, AuthEntry>>, CredError>;
}

/// One entry in the `auths.<registry>` map. Every field is optional
/// at the deserialiser level so the parser accepts every documented
/// shape (`auth` only, explicit `username`+`password`, `identitytoken`);
/// per-entry validation runs in [`map_entry_to_resolved`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthEntry {
    /// Base64-encoded `username:password` pair. The authoritative
    /// form `docker login` writes; precedence is `auth` > explicit.
    #[serde(default)]
    pub auth: Option<String>,
    /// Explicit username. Some tools (e.g. older `docker login`
    /// versions, `podman login` with `--authfile`) emit this
    /// alongside or instead of `auth`.
    #[serde(default)]
    pub username: Option<String>,
    /// Explicit password. Pairs with `username`.
    #[serde(default)]
    pub password: Option<String>,
    /// OAuth-style identity token. Maps to a Bearer flavour of
    /// resolved auth. Set by `docker login` for registries that
    /// negotiate an OIDC flow (some Docker Hub / GHCR variants).
    #[serde(default, rename = "identitytoken")]
    pub identity_token: Option<String>,
}

/// Schema of the top-level `~/.docker/config.json`. Only the
/// `auths` field is consumed by v0; every other key is ignored.
#[derive(Debug, Deserialize)]
struct DockerConfigFile {
    #[serde(default)]
    auths: HashMap<String, AuthEntry>,
}

/// Typed result of [`DockerConfigCredentialProvider::resolve_auth_mode`] —
/// the raw fields the entry carried, before they're folded into a
/// pre-built `Authorization` header.
///
/// Exists alongside the trait's [`Credentials`] return shape so the
/// CLI dispatcher can map docker-config output back into
/// [`crate::cmd::publish::AuthMode::Basic`] /
/// [`crate::cmd::publish::AuthMode::Bearer`] without round-tripping
/// through header-encode + base64-decode. Mirrors the Vault
/// provider's `ResolvedVaultAuth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedDockerAuth {
    /// Entry carried `auth` (decoded) or explicit `username` +
    /// `password`. Maps to HTTP Basic.
    Basic { username: String, password: String },
    /// Entry carried `identitytoken`. Maps to a pre-acquired bearer.
    Bearer { token: String },
}

/// A [`CredentialProvider`] that fetches registry credentials from
/// `~/.docker/config.json`.
///
/// Generic over [`DockerConfigBackend`] so production code uses the
/// real-filesystem [`DockerConfigFsBackend`] while unit tests inject
/// a stub.
pub struct DockerConfigCredentialProvider<B: DockerConfigBackend> {
    backend: B,
}

impl<B: DockerConfigBackend> DockerConfigCredentialProvider<B> {
    /// Construct directly from a backend. For test code or for
    /// callers that want to point the provider at a non-default
    /// config path (e.g. CI runners that stage a fixture).
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Resolve into a typed [`ResolvedDockerAuth`] for the CLI
    /// dispatcher path. Same backend call + same precedence /
    /// validation rules as the [`CredentialProvider::resolve`]
    /// trait method.
    ///
    /// Returns `Ok(None)` when:
    /// - The config file does not exist (operator never ran `docker login`).
    /// - The file exists but contains no `auths.<registry>` entry
    ///   for either the bare host or `https://<host>` form.
    pub fn resolve_auth_mode(
        &self,
        registry: &str,
    ) -> Result<Option<ResolvedDockerAuth>, CredError> {
        if registry.is_empty() {
            return Err(CredError::ProviderFailed {
                provider: PROVIDER_NAME,
                detail: "registry name must be non-empty".into(),
            });
        }
        let Some(auths) = self.backend.load_auths()? else {
            // File does not exist — operator never ran docker login.
            // Soft fall-through so the chain walker continues.
            return Ok(None);
        };
        let entry = lookup_entry(&auths, registry);
        let Some(entry) = entry else {
            // File exists but has no entry for this registry. Soft
            // fall-through — same shape as Vault's 404 → Ok(None).
            return Ok(None);
        };
        map_entry_to_resolved(entry).map(Some)
    }
}

impl<B: DockerConfigBackend> CredentialProvider for DockerConfigCredentialProvider<B> {
    fn resolve(&self, registry: &str) -> Result<Option<Credentials>, CredError> {
        // Dispatch through the typed shape so the trait + dispatcher
        // paths agree byte-for-byte on what counts as a valid entry.
        // Header composition is the only difference.
        let Some(resolved) = self.resolve_auth_mode(registry)? else {
            return Ok(None);
        };
        let auth_header = match resolved {
            ResolvedDockerAuth::Bearer { token } => format!("Bearer {token}"),
            ResolvedDockerAuth::Basic { username, password } => {
                let pair = format!("{username}:{password}");
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()),
                )
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

/// Look up `auths.<registry>`. First the bare host, then the
/// `https://<host>` form Docker writes for some entries (older
/// clients, explicit `docker login https://ghcr.io`). Returns the
/// first match, or `None` if neither key is present.
fn lookup_entry<'a>(
    auths: &'a HashMap<String, AuthEntry>,
    registry: &str,
) -> Option<&'a AuthEntry> {
    if let Some(e) = auths.get(registry) {
        return Some(e);
    }
    let with_scheme = format!("https://{registry}");
    auths.get(&with_scheme)
}

/// Map an [`AuthEntry`] to [`ResolvedDockerAuth`].
///
/// Precedence:
/// 1. `auth` field decodes to `username:password` → Basic. Wins
///    over every other field — Docker's documented behaviour.
/// 2. `identitytoken` set + non-empty → Bearer.
/// 3. Explicit `username` + `password`, both non-empty → Basic.
///
/// Every validation failure produces [`CredError::ProviderFailed`]
/// with a detail string that names the specific schema bug. We
/// deliberately do NOT return `Ok(None)` analogue here: reaching
/// this function means an entry WAS found for the registry; silently
/// treating a malformed entry as "no creds" would mask the
/// operator's `config.json` corruption.
fn map_entry_to_resolved(entry: &AuthEntry) -> Result<ResolvedDockerAuth, CredError> {
    // `auth` field wins when present + non-empty.
    if let Some(raw_auth) = entry.auth.as_deref() {
        if !raw_auth.is_empty() {
            return decode_auth_field(raw_auth);
        }
        // `auth` field present but empty: this is a misconfiguration,
        // not "fall through to explicit fields". An operator (or a
        // tool) that wrote `auth = ""` meant for that to be the
        // active credential; silently using the username/password
        // would hide the bug.
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config 'auth' field is set but empty".into(),
        });
    }

    // identitytoken → Bearer.
    if let Some(tok) = entry.identity_token.as_deref() {
        if !tok.is_empty() {
            return Ok(ResolvedDockerAuth::Bearer {
                token: tok.to_string(),
            });
        }
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config 'identitytoken' field is set but empty".into(),
        });
    }

    // Explicit username + password.
    match (entry.username.as_deref(), entry.password.as_deref()) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Ok(ResolvedDockerAuth::Basic {
            username: u.to_string(),
            password: p.to_string(),
        }),
        (Some(_), Some(_)) => Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail:
                "docker config entry has username and password fields but at least one is empty"
                    .into(),
        }),
        (Some(_), None) => Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config entry has 'username' but no 'password'".into(),
        }),
        (None, Some(_)) => Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config entry has 'password' but no 'username'".into(),
        }),
        (None, None) => Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config entry carries no recognisable credential fields \
                     (expected one of: 'auth', 'identitytoken', or 'username'+'password')"
                .into(),
        }),
    }
}

/// Decode a base64-encoded `auth` field (the `username:password`
/// form `docker login` writes). Validation failures map to
/// `CredError::ProviderFailed` with a specific detail string.
fn decode_auth_field(raw: &str) -> Result<ResolvedDockerAuth, CredError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: format!(
                "docker config 'auth' field is not valid base64 ({e}); \
                 expected base64-encoded 'username:password'"
            ),
        })?;
    let pair = std::str::from_utf8(&decoded).map_err(|e| CredError::ProviderFailed {
        provider: PROVIDER_NAME,
        detail: format!(
            "docker config 'auth' field decoded to non-UTF-8 bytes ({e}); \
             expected 'username:password'"
        ),
    })?;
    // `username:password` — split on the FIRST `:` because passwords
    // may legitimately contain `:` (RFC 7617 §2.1 says only the
    // first colon is the delimiter).
    let (username, password) = pair
        .split_once(':')
        .ok_or_else(|| CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config 'auth' field decoded but lacks ':' separator; \
                 expected 'username:password'"
                .into(),
        })?;
    if username.is_empty() && password.is_empty() {
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config 'auth' field decoded to ':' only (empty user + pass)".into(),
        });
    }
    if username.is_empty() {
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config 'auth' field decoded with empty username".into(),
        });
    }
    if password.is_empty() {
        return Err(CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "docker config 'auth' field decoded with empty password".into(),
        });
    }
    Ok(ResolvedDockerAuth::Basic {
        username: username.to_string(),
        password: password.to_string(),
    })
}

// ── Real-filesystem backend ──────────────────────────────────────────────

/// Production [`DockerConfigBackend`] backed by a real on-disk
/// `~/.docker/config.json` (or any explicit override path).
///
/// Constructed via [`DockerConfigFsBackend::from_default_path`] —
/// which uses `dirs::home_dir()` to resolve `~` portably — or
/// [`DockerConfigFsBackend::from_path`] for an explicit override
/// (the `--docker-config-path` CLI flag).
#[derive(Debug, Clone)]
pub struct DockerConfigFsBackend {
    path: PathBuf,
}

impl DockerConfigFsBackend {
    /// Construct pointing at `<HOME>/.docker/config.json`. Returns
    /// `Err(CredError::ProviderFailed)` if the home directory can
    /// not be resolved on this platform — surfacing the
    /// misconfiguration loudly rather than silently falling through
    /// to "config missing" (which would mask a non-standard CI
    /// runner setup where `$HOME` is unset).
    pub fn from_default_path() -> Result<Self, CredError> {
        let home = dirs::home_dir().ok_or_else(|| CredError::ProviderFailed {
            provider: PROVIDER_NAME,
            detail: "unable to resolve home directory (no $HOME / %USERPROFILE% set?); \
                     pass --docker-config-path explicitly"
                .into(),
        })?;
        Ok(Self {
            path: home.join(".docker").join("config.json"),
        })
    }

    /// Construct pointing at an explicit path. Used by the CLI when
    /// `--docker-config-path PATH` is supplied, and by integration
    /// tests staging a fixture.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Path the backend will read on `load_auths`. Used in
    /// diagnostics so an operator who passed `--docker-config-path`
    /// and got an error knows which path the provider actually hit.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DockerConfigBackend for DockerConfigFsBackend {
    fn load_auths(&self) -> Result<Option<HashMap<String, AuthEntry>>, CredError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CredError::Io {
                    provider: PROVIDER_NAME,
                    source,
                });
            }
        };
        let parsed: DockerConfigFile =
            serde_json::from_slice(&bytes).map_err(|e| CredError::ProviderFailed {
                provider: PROVIDER_NAME,
                detail: format!(
                    "docker config at {} is not valid JSON ({e})",
                    self.path.display()
                ),
            })?;
        Ok(Some(parsed.auths))
    }
}

/// Type alias for the production-shaped provider — `--auth docker-config`
/// resolves through this. Unit tests use the generic
/// `DockerConfigCredentialProvider<StubBackend>` so they don't depend
/// on the operator's real `~/.docker/config.json`.
pub type DockerConfigProvider = DockerConfigCredentialProvider<DockerConfigFsBackend>;

impl DockerConfigProvider {
    /// Construct from the default `~/.docker/config.json` path.
    pub fn from_default_path() -> Result<Self, CredError> {
        Ok(Self::new(DockerConfigFsBackend::from_default_path()?))
    }

    /// Construct pointing at an explicit path (the
    /// `--docker-config-path PATH` CLI flag).
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        Self::new(DockerConfigFsBackend::from_path(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Minimal in-test [`DockerConfigBackend`]. Returns the same
    /// canned response for every call. Tracks whether `load_auths`
    /// was hit so tests can assert short-circuiting (e.g. an empty
    /// registry argument errors before the file is read).
    struct StubBackend {
        response: Result<Option<HashMap<String, AuthEntry>>, String>,
        hits: Mutex<u32>,
    }
    impl StubBackend {
        fn ok(map: HashMap<String, AuthEntry>) -> Self {
            Self {
                response: Ok(Some(map)),
                hits: Mutex::new(0),
            }
        }
        fn missing() -> Self {
            Self {
                response: Ok(None),
                hits: Mutex::new(0),
            }
        }
        fn provider_failed(detail: &str) -> Self {
            Self {
                response: Err(detail.to_string()),
                hits: Mutex::new(0),
            }
        }
    }
    impl DockerConfigBackend for StubBackend {
        fn load_auths(&self) -> Result<Option<HashMap<String, AuthEntry>>, CredError> {
            *self.hits.lock().unwrap() += 1;
            match &self.response {
                Ok(v) => Ok(v.clone()),
                Err(detail) => Err(CredError::ProviderFailed {
                    provider: PROVIDER_NAME,
                    detail: detail.clone(),
                }),
            }
        }
    }

    fn entry_with_auth(b64: &str) -> AuthEntry {
        AuthEntry {
            auth: Some(b64.to_string()),
            ..AuthEntry::default()
        }
    }
    fn entry_with_userpass(u: &str, p: &str) -> AuthEntry {
        AuthEntry {
            username: Some(u.to_string()),
            password: Some(p.to_string()),
            ..AuthEntry::default()
        }
    }
    fn entry_with_token(tok: &str) -> AuthEntry {
        AuthEntry {
            identity_token: Some(tok.to_string()),
            ..AuthEntry::default()
        }
    }

    /// Catches: a misimplemented base64 decode silently producing
    /// malformed auth — e.g. swapping URL-safe and standard
    /// alphabets, or treating padding chars as data. Without the
    /// roundtrip assertion, the wire call would 401 and an operator
    /// would chase a network bug that's actually in our decoder.
    ///
    /// Reference: `printf 'admin:hunter2' | base64` → `YWRtaW46aHVudGVyMg==`.
    #[test]
    fn test_auth_field_with_base64_userpass_decodes_to_basic() {
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry_with_auth("YWRtaW46aHVudGVyMg=="));
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let resolved = p
            .resolve_auth_mode("ghcr.io")
            .expect("must succeed")
            .expect("must yield Some");
        assert_eq!(
            resolved,
            ResolvedDockerAuth::Basic {
                username: "admin".into(),
                password: "hunter2".into(),
            }
        );
    }

    /// Catches: a schema variant that bypasses the base64 path. Some
    /// tools (older `docker login`, `podman login --authfile`) write
    /// explicit `username` + `password` fields instead of `auth`.
    /// Without this test, a refactor that hard-coded "always look at
    /// `auth`" would silently fail every podman-written config.
    #[test]
    fn test_explicit_username_password_returns_basic() {
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry_with_userpass("u", "p"));
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let resolved = p
            .resolve_auth_mode("ghcr.io")
            .unwrap()
            .expect("must yield Some");
        assert_eq!(
            resolved,
            ResolvedDockerAuth::Basic {
                username: "u".into(),
                password: "p".into(),
            }
        );
    }

    /// Catches: an ambiguous-precedence regression where an entry
    /// carrying both `auth` AND explicit `username`+`password`
    /// produces non-deterministic credential choice. The contract is
    /// "auth wins" (mirrors Docker's documented behaviour); reversing
    /// it would silently change which credentials are sent when two
    /// tools edit the same `config.json`.
    #[test]
    fn test_auth_field_wins_over_explicit_userpass() {
        // base64('admin-from-auth:secret-from-auth') →
        // `YWRtaW4tZnJvbS1hdXRoOnNlY3JldC1mcm9tLWF1dGg=`
        let entry = AuthEntry {
            auth: Some("YWRtaW4tZnJvbS1hdXRoOnNlY3JldC1mcm9tLWF1dGg=".into()),
            username: Some("ignored-u".into()),
            password: Some("ignored-p".into()),
            ..AuthEntry::default()
        };
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry);
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let resolved = p.resolve_auth_mode("ghcr.io").unwrap().unwrap();
        assert_eq!(
            resolved,
            ResolvedDockerAuth::Basic {
                username: "admin-from-auth".into(),
                password: "secret-from-auth".into(),
            },
            "ambiguous shape must deterministically prefer 'auth' field; \
             explicit username/password must be ignored when 'auth' is non-empty"
        );
    }

    /// Catches: `identitytoken` misclassified as a username when it's
    /// actually an OAuth-style bearer. Without this branch, the
    /// header would be `Authorization: Basic <b64-of-token-no-colon>`,
    /// which the registry would reject with a 400; an operator
    /// relying on the OIDC flow would chase a confusing wire bug.
    #[test]
    fn test_identitytoken_returns_bearer() {
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry_with_token("ghp_xxxxxx"));
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let resolved = p.resolve_auth_mode("ghcr.io").unwrap().unwrap();
        assert_eq!(
            resolved,
            ResolvedDockerAuth::Bearer {
                token: "ghp_xxxxxx".into(),
            },
        );
    }

    /// Catches: a registry stored under the `https://` form (older
    /// `docker login` clients write this) not being found when
    /// looked up as the bare host. The contract: try bare, then
    /// `https://<host>`. Without the fallback, an operator who ran
    /// `docker login https://ghcr.io` from an old Docker would have
    /// `--auth docker-config` silently miss their entry.
    #[test]
    fn test_https_prefix_lookup_falls_through() {
        let mut auths = HashMap::new();
        auths.insert(
            "https://ghcr.io".into(),
            entry_with_userpass("u-https", "p-https"),
        );
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let resolved = p.resolve_auth_mode("ghcr.io").unwrap().unwrap();
        assert_eq!(
            resolved,
            ResolvedDockerAuth::Basic {
                username: "u-https".into(),
                password: "p-https".into(),
            },
            "lookup must try bare host AND 'https://<host>' so older docker login \
             entries still resolve"
        );
    }

    /// Catches: a missing `~/.docker/config.json` bubbling up as
    /// `Err(...)` instead of `Ok(None)`. The contract: an operator
    /// who never ran `docker login` should see the chain walker
    /// continue to the next provider, not a hard failure. Mirrors
    /// the Vault provider's "404 → Ok(None)" rule.
    #[test]
    fn test_missing_config_file_returns_ok_none() {
        let p = DockerConfigCredentialProvider::new(StubBackend::missing());
        let got = p
            .resolve_auth_mode("ghcr.io")
            .expect("missing file must NOT surface as Err — chain must walk");
        assert!(
            got.is_none(),
            "missing config.json must map to Ok(None); got Some({got:?})",
        );
    }

    /// Catches: malformed `config.json` silently treated as "no
    /// creds, fall through" — which would mask the operator's
    /// schema corruption (e.g. an editor wrote BOM bytes, or a
    /// truncated write). Like the Vault provider's "schema
    /// mismatch is loud" rule.
    #[test]
    fn test_malformed_json_returns_provider_failed() {
        let p = DockerConfigCredentialProvider::new(StubBackend::provider_failed("not valid JSON"));
        let err = p
            .resolve_auth_mode("ghcr.io")
            .expect_err("malformed JSON must surface, not silently fall through");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(detail.contains("JSON") || detail.contains("valid"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: a garbled `auth` field (non-base64 chars, odd
    /// length, etc.) silently treated as "no creds for this
    /// registry" so the chain falls through. Without this guard, an
    /// operator who corrupted their `config.json` (e.g. a manual
    /// edit) would see anonymous-pull behaviour instead of a
    /// loud "fix your auth field" error.
    #[test]
    fn test_base64_decode_failure_returns_provider_failed() {
        let mut auths = HashMap::new();
        // `!!!` is not valid base64.
        auths.insert("ghcr.io".into(), entry_with_auth("!!!"));
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let err = p
            .resolve_auth_mode("ghcr.io")
            .expect_err("invalid base64 must NOT silently fall through");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(
                    detail.contains("base64"),
                    "detail must explain the base64 problem; got {detail:?}",
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: a half-populated entry (e.g. only `username` set,
    /// no `password`) silently treated as valid — which would emit
    /// an `Authorization: Basic <b64-of-user:>` header and the
    /// registry would 401 with no actionable diagnostic.
    #[test]
    fn test_username_only_no_password_returns_provider_failed() {
        let mut auths = HashMap::new();
        auths.insert(
            "ghcr.io".into(),
            AuthEntry {
                username: Some("u".into()),
                ..AuthEntry::default()
            },
        );
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let err = p
            .resolve_auth_mode("ghcr.io")
            .expect_err("half-populated entry must surface as error");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(
                    detail.contains("password"),
                    "detail must name the missing field; got {detail:?}",
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: an "any-registry-found" fallthrough where the
    /// provider returns the FIRST entry in the `auths` map
    /// regardless of which registry was asked for. The contract:
    /// only a key match for the exact host (or `https://<host>`)
    /// counts; anything else is `Ok(None)` and the chain continues.
    #[test]
    fn test_unknown_registry_returns_ok_none() {
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry_with_userpass("u", "p"));
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let got = p
            .resolve_auth_mode("docker.io")
            .expect("unknown registry must NOT surface as Err — chain must walk");
        assert!(
            got.is_none(),
            "unknown registry must map to Ok(None); got Some({got:?})",
        );
    }

    /// Catches: an empty registry argument silently composing a
    /// list-shaped lookup or hitting the file system anyway. Empty
    /// is operator misuse; surfacing it as a typed error matches
    /// the Vault provider's "empty registry is non-empty" rule.
    /// Also asserts the empty-registry check short-circuits BEFORE
    /// `backend.load_auths` is invoked — otherwise an empty registry
    /// against a slow file read (e.g. NFS-mounted home dir) would
    /// still pay the I/O.
    #[test]
    fn test_resolve_with_empty_registry_is_provider_failed() {
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(HashMap::new()));
        let err = p
            .resolve_auth_mode("")
            .expect_err("empty registry must error, not silently list");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(detail.contains("non-empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
        let hits = *p.backend.hits.lock().unwrap();
        assert_eq!(
            hits, 0,
            "empty registry must short-circuit before backend.load_auths is called"
        );
    }

    /// Catches: `auth` field present but empty silently falling
    /// through to explicit username/password. An operator who
    /// wrote `auth = ""` expected the auth path used; surfacing the
    /// empty-string misconfiguration is the contract — same shape
    /// as the Vault provider's empty-token guard.
    #[test]
    fn test_empty_auth_field_is_provider_failed() {
        let entry = AuthEntry {
            auth: Some("".into()),
            username: Some("fallback-u".into()),
            password: Some("fallback-p".into()),
            ..AuthEntry::default()
        };
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry);
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let err = p
            .resolve_auth_mode("ghcr.io")
            .expect_err("empty auth field must surface, not fall through");
        match err {
            CredError::ProviderFailed { provider, detail } => {
                assert_eq!(provider, PROVIDER_NAME);
                assert!(detail.contains("empty"));
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: an `auth` field that decodes successfully but
    /// produces bytes WITHOUT a `:` separator (e.g. someone wrote
    /// a base64-encoded plain token instead of `username:password`).
    /// Without this guard, the resolved credential would carry the
    /// whole token as the username and an empty password — wire
    /// call 401s with no clue.
    #[test]
    fn test_auth_field_decodes_but_lacks_separator_is_provider_failed() {
        // base64('no-separator-here') → `bm8tc2VwYXJhdG9yLWhlcmU=`
        let mut auths = HashMap::new();
        auths.insert(
            "ghcr.io".into(),
            entry_with_auth("bm8tc2VwYXJhdG9yLWhlcmU="),
        );
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let err = p
            .resolve_auth_mode("ghcr.io")
            .expect_err("auth field without ':' must surface");
        match err {
            CredError::ProviderFailed { detail, .. } => {
                assert!(
                    detail.contains("separator") || detail.contains(":"),
                    "detail must explain the missing separator; got {detail:?}",
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: a regression where the `name()` method drifts from
    /// the `Credentials::source` field — log diagnostics rely on
    /// these matching to trace which provider sourced a given
    /// credential.
    #[test]
    fn test_provider_name_matches_credentials_source() {
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry_with_userpass("u", "p"));
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let creds = p.resolve("ghcr.io").unwrap().unwrap();
        assert_eq!(p.name(), PROVIDER_NAME);
        assert_eq!(creds.source, PROVIDER_NAME);
    }

    /// Catches: `resolve()` (the trait surface used by AuthManager)
    /// disagreeing with `resolve_auth_mode()` (the typed accessor
    /// used by the CLI dispatcher) on what counts as a valid entry.
    /// Both paths must agree byte-for-byte; the only difference is
    /// header composition.
    #[test]
    fn test_resolve_trait_path_emits_correct_basic_header() {
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry_with_userpass("admin", "hunter2"));
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let creds = p.resolve("ghcr.io").unwrap().unwrap();
        // base64 of `admin:hunter2` → `YWRtaW46aHVudGVyMg==`.
        assert_eq!(creds.auth_header, "Basic YWRtaW46aHVudGVyMg==");
    }

    /// Catches: an `identitytoken` field present but empty silently
    /// falling through (or being treated as a valid empty token,
    /// producing `Authorization: Bearer ` which is a 400 from most
    /// registries). Same fail-loud rule as the empty-`auth` guard.
    #[test]
    fn test_empty_identitytoken_is_provider_failed() {
        let entry = AuthEntry {
            identity_token: Some("".into()),
            ..AuthEntry::default()
        };
        let mut auths = HashMap::new();
        auths.insert("ghcr.io".into(), entry);
        let p = DockerConfigCredentialProvider::new(StubBackend::ok(auths));
        let err = p
            .resolve_auth_mode("ghcr.io")
            .expect_err("empty identitytoken must surface");
        match err {
            CredError::ProviderFailed { detail, .. } => {
                assert!(detail.contains("empty"), "got {detail:?}");
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }
}
