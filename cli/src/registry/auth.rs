//! Authentication for the registry-pull path.
//!
//! Two pieces of machinery live here:
//!
//! 1. **[`AuthManager`].** Owns a chain of
//!    [`crate::registry::credential_provider::CredentialProvider`]
//!    impls + a per-registry bearer-token cache. Replaces what was
//!    previously a flat `AuthMode` enum on the wire context. New
//!    providers (Vault, Docker-config) plug in by implementing the
//!    trait — the wire layer doesn't grow vendor knowledge.
//!
//! 2. **The 401-then-WWW-Authenticate dance.** OCI Distribution
//!    Spec §3.4 lets an anonymous (or basic-auth-credentialed) GET
//!    return 401 with a `WWW-Authenticate: Bearer realm=…,service=…,scope=…`
//!    header. The client fetches a short-lived bearer token from
//!    the realm and retries the original request. This is how
//!    Docker Hub and GHCR's anonymous-readable repos work today.
//!
//!    [`fetch_bearer_token`], [`extract_bearer_challenge`], and
//!    [`parse_bearer_challenge`] are pull-private helpers
//!    [`crate::registry::pull`] threads through its retry loop.
//!    The cached bearer is then stored via
//!    [`AuthManager::cache_bearer`] so subsequent blob fetches
//!    don't re-401 — without that cache, every blob in a pull
//!    would re-run the dance.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::StatusCode;

use super::credential_provider::{CredError, CredentialProvider, Credentials};
use super::error::{preview_body_capped, RegistryPullError};

/// Per-HTTP-request timeout for the token-realm exchange. Same
/// 60-second cap the publish side uses; long enough for a slow
/// realm, short enough that a wedged token endpoint can't hang
/// the verify forever.
pub(super) const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Coordinator that walks a chain of [`CredentialProvider`]s and
/// caches bearer tokens harvested via the OCI 401-then-realm dance.
///
/// ### Walking semantics
///
/// [`AuthManager::resolve`] iterates providers in registration order:
///
/// - First `Ok(Some(creds))` wins; iteration stops there.
/// - First `Err(CredError)` short-circuits — a broken provider
///   (e.g. Vault is down) is surfaced rather than silently falling
///   through to anonymous.
/// - All `Ok(None)` → returns `Ok(None)` (the chain is exhausted;
///   the wire layer treats this as "send no Authorization header").
///
/// ### Bearer cache
///
/// A successful 401-realm dance produces a short-lived bearer
/// token. [`AuthManager::cache_bearer`] stores it keyed by registry
/// host so subsequent blob fetches in the same pull session reuse
/// the token instead of re-401-ing on every blob. The cache is
/// [`Mutex`]-protected because the trait surface promises
/// `Send + Sync`; today the registry-pull path is blocking-single-
/// threaded so contention is zero, but locking now means a future
/// parallel-blob-pull refactor doesn't have to revisit the auth
/// surface.
pub struct AuthManager {
    providers: Vec<Box<dyn CredentialProvider>>,
    /// Bearer tokens harvested via the 401-realm dance, keyed by
    /// registry host (`ghcr.io`, `localhost:5000`, …). Survives
    /// across blob fetches in a single pull. The HashMap's value
    /// is the raw bearer token string the dance returned; the
    /// caller (`pull::send_with_retry`) wraps it as
    /// `Authorization: Bearer <tok>` per request.
    cached_bearer: Mutex<HashMap<String, String>>,
}

impl AuthManager {
    /// Build an AuthManager from a chain of providers.
    pub fn new(providers: Vec<Box<dyn CredentialProvider>>) -> Self {
        AuthManager {
            providers,
            cached_bearer: Mutex::new(HashMap::new()),
        }
    }

    /// Walk providers in order, returning the first `Some` or the
    /// first `Err`. `Ok(None)` after exhausting the chain means
    /// "no credentials" — the wire layer sends no Authorization
    /// header, and the registry decides whether anonymous access
    /// is allowed (and may still up-grade to bearer via the 401
    /// dance on this same call).
    pub fn resolve(&self, registry: &str) -> Result<Option<Credentials>, CredError> {
        for provider in &self.providers {
            match provider.resolve(registry)? {
                Some(creds) => return Ok(Some(creds)),
                None => continue,
            }
        }
        Ok(None)
    }

    /// Cache a bearer token harvested from a 401-realm dance.
    /// Subsequent calls to [`AuthManager::cached_bearer`] for the
    /// same `registry` return `Some(token)` so the wire layer can
    /// attach `Authorization: Bearer <token>` without re-running
    /// the dance. Without this cache, every blob fetch in a multi-
    /// blob pull would re-401, re-token-dance, and re-retry.
    pub fn cache_bearer(&self, registry: &str, token: String) {
        // .lock() can poison; we recover by taking the inner. The
        // dance never panics while holding the lock, so the
        // poisoned state would only happen via a downstream bug;
        // recovering keeps the rest of the pull resilient.
        let mut map = self.cached_bearer.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(registry.to_string(), token);
    }

    /// Look up a previously-cached bearer token for `registry`.
    /// `None` means no dance has run yet for this registry in this
    /// session.
    pub fn cached_bearer(&self, registry: &str) -> Option<String> {
        let map = self.cached_bearer.lock().unwrap_or_else(|p| p.into_inner());
        map.get(registry).cloned()
    }
}

/// Build an `Authorization` HeaderValue from a credentials string.
/// Marks the header as sensitive so it's redacted in any reqwest
/// debug output.
pub(super) fn header_value_from_credentials(
    cred: &Credentials,
) -> Result<HeaderValue, RegistryPullError> {
    let mut hv =
        HeaderValue::from_str(&cred.auth_header).map_err(|source| RegistryPullError::Auth {
            source: Box::new(source),
        })?;
    hv.set_sensitive(true);
    Ok(hv)
}

/// Build an `Authorization: Bearer <token>` HeaderValue from a raw
/// bearer-token string (as cached by [`AuthManager::cache_bearer`]).
pub(super) fn header_value_from_bearer(token: &str) -> Result<HeaderValue, RegistryPullError> {
    let mut hv = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|source| {
        RegistryPullError::Auth {
            source: Box::new(source),
        }
    })?;
    hv.set_sensitive(true);
    Ok(hv)
}

/// Parse a `WWW-Authenticate: Bearer realm=…,service=…,scope=…`
/// header into its key/value pairs. Returns `None` if the header
/// isn't a Bearer challenge (e.g. `Basic realm=…`); the caller
/// surfaces RegistryRefused without the token-dance.
pub(super) fn parse_bearer_challenge(header: &str) -> Option<HashMap<String, String>> {
    let trimmed = header.trim();
    let scheme_end = trimmed.find(' ')?;
    let scheme = &trimmed[..scheme_end];
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let params_str = &trimmed[scheme_end + 1..];
    let mut out = HashMap::new();
    // The grammar is `key="value", key2="value2"` (RFC 7235). Walk
    // characters tracking quote state so commas inside quoted
    // values don't break the split.
    let mut chars = params_str.chars().peekable();
    while chars.peek().is_some() {
        // Skip whitespace.
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == ',' {
                chars.next();
            } else {
                break;
            }
        }
        // Read key.
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                chars.next();
                break;
            } else if c == ',' || c.is_whitespace() {
                break;
            } else {
                key.push(c);
                chars.next();
            }
        }
        if key.is_empty() {
            break;
        }
        // Read value (optionally quoted).
        let mut val = String::new();
        if let Some(&c) = chars.peek() {
            if c == '"' {
                chars.next();
                for c2 in chars.by_ref() {
                    if c2 == '"' {
                        break;
                    }
                    val.push(c2);
                }
            } else {
                while let Some(&c2) = chars.peek() {
                    if c2 == ',' {
                        break;
                    }
                    val.push(c2);
                    chars.next();
                }
            }
        }
        out.insert(key, val);
    }
    Some(out)
}

/// Fetch a short-lived bearer token from the realm advertised by a
/// `WWW-Authenticate` header. The static auth header (if any) is
/// reused as the realm-side credentials — Docker Hub / GHCR
/// expect basic-auth on the token endpoint then return a bearer
/// token to use against the registry endpoint.
///
/// Returns the raw bearer token string (without the `Bearer ` prefix)
/// so the caller can stash it in [`AuthManager::cache_bearer`]
/// keyed by registry, then re-derive the header on each request.
pub(super) fn fetch_bearer_token(
    client: &Client,
    challenge: &HashMap<String, String>,
    static_auth: Option<&HeaderValue>,
) -> Result<String, RegistryPullError> {
    let realm = challenge
        .get("realm")
        .ok_or_else(|| RegistryPullError::Auth {
            source: "WWW-Authenticate Bearer challenge missing realm parameter".into(),
        })?;
    // Build the token URL: `<realm>?service=<service>&scope=<scope>`.
    let mut url = realm.clone();
    let mut sep = if url.contains('?') { '&' } else { '?' };
    if let Some(svc) = challenge.get("service") {
        url.push(sep);
        url.push_str("service=");
        url.push_str(&urlencode(svc));
        sep = '&';
    }
    if let Some(scope) = challenge.get("scope") {
        url.push(sep);
        url.push_str("scope=");
        url.push_str(&urlencode(scope));
    }

    let mut req = client.get(&url);
    if let Some(auth_hv) = static_auth {
        req = req.header(AUTHORIZATION, auth_hv.clone());
    }
    let resp = req.send().map_err(|e| RegistryPullError::Auth {
        source: Box::new(e),
    })?;
    let status = resp.status();
    if !status.is_success() {
        let url_for_err = url.clone();
        let body_bytes = read_response_body_capped(resp);
        let body = preview_body_capped(&body_bytes);
        return Err(RegistryPullError::Auth {
            source: format!(
                "token endpoint {url_for_err} returned HTTP {}: {body}",
                status.as_u16()
            )
            .into(),
        });
    }
    let body_bytes = resp.bytes().map_err(|e| RegistryPullError::Auth {
        source: Box::new(e),
    })?;
    let parsed: serde_json::Value =
        serde_json::from_slice(&body_bytes).map_err(|e| RegistryPullError::Auth {
            source: format!("token endpoint returned non-JSON: {e}").into(),
        })?;
    // OCI / Docker accept either `token` or `access_token`. Try both.
    let token_str = parsed
        .get("token")
        .or_else(|| parsed.get("access_token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RegistryPullError::Auth {
            source: "token endpoint JSON missing 'token' / 'access_token'".into(),
        })?;
    if token_str.is_empty() {
        return Err(RegistryPullError::Auth {
            source: "token endpoint returned empty token string".into(),
        });
    }
    Ok(token_str.to_string())
}

/// If `resp` is a 401 with a parseable `WWW-Authenticate: Bearer`
/// challenge, return the parsed challenge. Otherwise `None` —
/// callers fall through to the 401-as-RegistryRefused error.
pub(super) fn extract_bearer_challenge(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Option<HashMap<String, String>> {
    if status != StatusCode::UNAUTHORIZED {
        return None;
    }
    let hv = headers.get(WWW_AUTHENTICATE)?;
    let s = hv.to_str().ok()?;
    parse_bearer_challenge(s)
}

/// Bounded read of an error-response body. Same shape publish uses
/// — a hostile registry must not dictate operator memory.
fn read_response_body_capped(resp: reqwest::blocking::Response) -> Vec<u8> {
    use std::io::Read;
    let cap = super::error::MAX_REGISTRY_BODY_PREVIEW;
    let mut buf = vec![0u8; cap];
    let mut total = 0;
    let mut reader = resp;
    loop {
        if total >= cap {
            break;
        }
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    buf.truncate(total);
    buf
}

/// Minimal URL-encoder for query-string values. Same minimal scope
/// as publish's base64: avoid dragging `urlencoding` into the dep
/// tree for a few call sites. Encodes everything except
/// unreserved + a small allow-list (`,/`) the OCI scope strings
/// commonly contain.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == '.'
            || c == '~'
            || c == ','
            || c == '/'
            || c == ':'
        {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::credential_provider::{
        AnonymousProvider, BasicProvider, BearerProvider, CredentialProvider,
    };

    // Catches: parse_bearer_challenge accepting a Basic challenge
    // and routing it into the bearer-token dance — would silently
    // hit the wrong endpoint and the operator would chase a
    // confusing error.
    #[test]
    fn test_parse_bearer_challenge_basic_returns_none() {
        assert!(parse_bearer_challenge("Basic realm=\"r\"").is_none());
    }

    // Catches: parse_bearer_challenge dropping a parameter when
    // the value is unquoted. Docker Hub uses the quoted form;
    // GHCR uses unquoted. Both must work.
    #[test]
    fn test_parse_bearer_challenge_quoted_values() {
        let h = parse_bearer_challenge(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\"",
        )
        .unwrap();
        assert_eq!(
            h.get("realm").map(String::as_str),
            Some("https://auth.docker.io/token")
        );
        assert_eq!(
            h.get("service").map(String::as_str),
            Some("registry.docker.io")
        );
        assert_eq!(
            h.get("scope").map(String::as_str),
            Some("repository:library/alpine:pull")
        );
    }

    #[test]
    fn test_parse_bearer_challenge_unquoted_values() {
        let h = parse_bearer_challenge("Bearer realm=https://x/token,service=svc").unwrap();
        assert_eq!(h.get("realm").map(String::as_str), Some("https://x/token"));
        assert_eq!(h.get("service").map(String::as_str), Some("svc"));
    }

    // Catches: parse_bearer_challenge confusing case — registries
    // can capitalise `Bearer` differently. Case-insensitive scheme
    // match per RFC 7235.
    #[test]
    fn test_parse_bearer_challenge_lowercase_scheme() {
        let h = parse_bearer_challenge("bearer realm=\"x\"").unwrap();
        assert_eq!(h.get("realm").map(String::as_str), Some("x"));
    }

    // Catches: a regression where url-encoding a value drops `:`
    // — OCI scope strings (`repository:foo/bar:pull`) contain
    // colons and the token endpoint must see them verbatim.
    #[test]
    fn test_urlencode_preserves_colon_and_slash() {
        let e = urlencode("repository:library/alpine:pull");
        assert_eq!(e, "repository:library/alpine:pull");
    }

    // Catches: a urlencode that lets a space through verbatim —
    // would produce a malformed query string.
    #[test]
    fn test_urlencode_escapes_space() {
        let e = urlencode("a b");
        assert_eq!(e, "a%20b");
    }

    // ── AuthManager tests ─────────────────────────────────────────

    /// Catches: AuthManager not stopping at the first `Some` —
    /// would let a downstream provider override the chosen creds.
    /// E.g. if [Bearer, Basic] both return Some, the chain must
    /// pick Bearer (registered first), not Basic. The contract
    /// "first Some wins" is what makes the chain order meaningful.
    #[test]
    fn test_auth_manager_walks_providers_in_order() {
        let providers: Vec<Box<dyn CredentialProvider>> = vec![
            Box::new(BearerProvider::new("first-token".into()).unwrap()),
            Box::new(BasicProvider::new("u".into(), "p".into()).unwrap()),
        ];
        let mgr = AuthManager::new(providers);
        let creds = mgr
            .resolve("ghcr.io")
            .expect("must not error")
            .expect("first provider returns Some");
        assert_eq!(
            creds.auth_header, "Bearer first-token",
            "first provider's creds must win — got {:?}",
            creds.auth_header,
        );
        assert_eq!(creds.source, "bearer");
    }

    /// Catches: AuthManager treating an `Ok(None)` as a stopping
    /// condition. The chain `[Anonymous, Bearer]` must keep walking
    /// past Anonymous (which returns Ok(None)) and reach Bearer.
    /// Without this, AnonymousProvider would silently shadow every
    /// downstream provider in chains that include it.
    #[test]
    fn test_auth_manager_skips_none_to_reach_next_provider() {
        let providers: Vec<Box<dyn CredentialProvider>> = vec![
            Box::new(AnonymousProvider),
            Box::new(BearerProvider::new("downstream-tok".into()).unwrap()),
        ];
        let mgr = AuthManager::new(providers);
        let creds = mgr.resolve("ghcr.io").unwrap().expect("must reach Bearer");
        assert_eq!(creds.auth_header, "Bearer downstream-tok");
    }

    /// A provider that always errors. Models a broken Vault or
    /// Docker-config provider — the kind of failure that must NOT
    /// silently fall through to anonymous.
    struct AlwaysErrorProvider;
    impl CredentialProvider for AlwaysErrorProvider {
        fn resolve(&self, _registry: &str) -> Result<Option<Credentials>, CredError> {
            Err(CredError::ProviderFailed {
                provider: "test-broken",
                detail: "simulated upstream failure".into(),
            })
        }
        fn name(&self) -> &'static str {
            "test-broken"
        }
    }

    /// Catches: AuthManager silently skipping an `Err` provider and
    /// falling through to a downstream Anonymous (or any other)
    /// provider. Operator scenario: Vault is wedged. The operator's
    /// CI must FAIL loudly, not silently push unauthenticated.
    #[test]
    fn test_auth_manager_first_err_short_circuits() {
        let providers: Vec<Box<dyn CredentialProvider>> = vec![
            Box::new(AlwaysErrorProvider),
            // Downstream provider that WOULD succeed if reached —
            // the test asserts it isn't reached.
            Box::new(BearerProvider::new("would-succeed".into()).unwrap()),
        ];
        let mgr = AuthManager::new(providers);
        let err = mgr.resolve("ghcr.io").expect_err("Err must short-circuit");
        match err {
            CredError::ProviderFailed { provider, .. } => {
                assert_eq!(
                    provider, "test-broken",
                    "the failing provider must be named — operators rely on the diagnostic",
                );
            }
            other => panic!("expected ProviderFailed, got {other:?}"),
        }
    }

    /// Catches: forgetting to populate the bearer cache after the
    /// 401 dance. Without this, every subsequent blob fetch in a
    /// multi-blob pull re-401s and re-runs the dance. The test
    /// asserts: cache_bearer + cached_bearer round-trip across
    /// "calls" simulating sequential blob fetches.
    #[test]
    fn test_cached_bearer_survives_across_resolve_calls() {
        let mgr = AuthManager::new(vec![]);
        let registry = "ghcr.io";
        // Initially, no cached bearer for this registry.
        assert!(
            mgr.cached_bearer(registry).is_none(),
            "no dance has run yet — cached_bearer must be None",
        );
        // Simulate the 401 dance completing.
        mgr.cache_bearer(registry, "harvested-token".into());
        // Subsequent blob fetches see the cached token without
        // re-running the dance.
        assert_eq!(
            mgr.cached_bearer(registry).as_deref(),
            Some("harvested-token"),
            "subsequent blob fetches must see the cached token; \
             without this, every blob in a pull would re-401",
        );
        // A second call returns the same cached token (didn't get
        // popped or invalidated by the read).
        assert_eq!(
            mgr.cached_bearer(registry).as_deref(),
            Some("harvested-token"),
            "cached_bearer must be a peek, not a take — multiple blob fetches read it",
        );
    }

    /// Catches: AuthManager keying the bearer cache by something
    /// other than registry host. If the cache used a global key
    /// (e.g. an empty string), a multi-registry session would mix
    /// tokens. We don't have multi-registry pulls today but the
    /// trait surface promises per-registry semantics; pinning the
    /// contract now keeps a future breakage out.
    #[test]
    fn test_cached_bearer_is_keyed_by_registry() {
        let mgr = AuthManager::new(vec![]);
        mgr.cache_bearer("ghcr.io", "ghcr-token".into());
        mgr.cache_bearer("docker.io", "docker-token".into());
        assert_eq!(mgr.cached_bearer("ghcr.io").as_deref(), Some("ghcr-token"));
        assert_eq!(
            mgr.cached_bearer("docker.io").as_deref(),
            Some("docker-token")
        );
        assert!(
            mgr.cached_bearer("other.example").is_none(),
            "an unrelated registry must NOT see another registry's cached token",
        );
    }
}
