//! Authentication for the registry-pull path.
//!
//! Reuses [`oci_publish::RegistryAuth`] — the same enum publish
//! already exposes — so an operator who configured auth for
//! `ocimage publish` doesn't have to learn a second model for
//! `ocimage verify <registry-ref>`.
//!
//! Two auth shapes are handled here:
//!
//! 1. **Pre-supplied credentials.** Basic / Bearer / FromEnv resolve
//!    to a static `Authorization` header value before the first
//!    request fires. The header rides every wire call.
//!
//! 2. **The 401-then-WWW-Authenticate dance.** OCI Distribution
//!    Spec §3.4 lets an anonymous (or basic-auth-credentialed) GET
//!    return 401 with a `WWW-Authenticate: Bearer realm=…,service=…,scope=…`
//!    header. The client fetches a short-lived bearer token from
//!    the realm and retries the original request. This is how
//!    Docker Hub and GHCR's anonymous-readable repos work today.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::StatusCode;

use oci_publish::RegistryAuth;

use super::error::{preview_body_capped, RegistryPullError};

/// Per-HTTP-request timeout for the token-realm exchange. Same
/// 60-second cap the publish side uses; long enough for a slow
/// realm, short enough that a wedged token endpoint can't hang
/// the verify forever.
pub(super) const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// One env var name the publish side uses; we re-import them so
/// the test surface for "no credentials in env" is consistent.
const ENV_REGISTRY_TOKEN: &str = "REGISTRY_TOKEN";
const ENV_REGISTRY_USERNAME: &str = "REGISTRY_USERNAME";
const ENV_REGISTRY_PASSWORD: &str = "REGISTRY_PASSWORD";

/// Resolve a `RegistryAuth` mode into a static `Authorization`
/// header value (or `None` for anonymous). Mirrors the publish
/// side's `resolve_auth` so the two paths agree on env-var
/// precedence (`REGISTRY_TOKEN` > `REGISTRY_USERNAME`+`REGISTRY_PASSWORD`).
pub(super) fn resolve_static_auth_header(
    auth: &RegistryAuth,
) -> Result<HeaderValue, RegistryPullError> {
    let header_value = match auth {
        RegistryAuth::Bearer { token } => {
            if token.is_empty() {
                return Err(RegistryPullError::Auth {
                    source: "RegistryAuth::Bearer with empty token".into(),
                });
            }
            format!("Bearer {token}")
        }
        RegistryAuth::Basic { username, password } => {
            if username.is_empty() || password.is_empty() {
                return Err(RegistryPullError::Auth {
                    source: "RegistryAuth::Basic requires non-empty username + password".into(),
                });
            }
            let creds = format!("{username}:{password}");
            format!("Basic {}", base64_encode(creds.as_bytes()))
        }
        RegistryAuth::FromEnv => {
            if let Ok(t) = std::env::var(ENV_REGISTRY_TOKEN) {
                if !t.is_empty() {
                    format!("Bearer {t}")
                } else {
                    return Err(RegistryPullError::Auth {
                        source: format!(
                            "{ENV_REGISTRY_TOKEN} is set but empty; unset it or provide a token"
                        )
                        .into(),
                    });
                }
            } else {
                let user = std::env::var(ENV_REGISTRY_USERNAME).unwrap_or_default();
                let pass = std::env::var(ENV_REGISTRY_PASSWORD).unwrap_or_default();
                if user.is_empty() || pass.is_empty() {
                    return Err(RegistryPullError::Auth {
                        source: format!(
                            "no registry credentials in env: set {ENV_REGISTRY_TOKEN}, \
                             or both {ENV_REGISTRY_USERNAME} and {ENV_REGISTRY_PASSWORD}"
                        )
                        .into(),
                    });
                }
                let creds = format!("{user}:{pass}");
                format!("Basic {}", base64_encode(creds.as_bytes()))
            }
        }
    };
    let mut hv = HeaderValue::from_str(&header_value).map_err(|source| RegistryPullError::Auth {
        source: Box::new(source),
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
                while let Some(c2) = chars.next() {
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
pub(super) fn fetch_bearer_token(
    client: &Client,
    challenge: &HashMap<String, String>,
    static_auth: Option<&HeaderValue>,
) -> Result<HeaderValue, RegistryPullError> {
    let realm = challenge.get("realm").ok_or_else(|| RegistryPullError::Auth {
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
    let mut hv = HeaderValue::from_str(&format!("Bearer {token_str}")).map_err(|e| {
        RegistryPullError::Auth {
            source: Box::new(e),
        }
    })?;
    hv.set_sensitive(true);
    Ok(hv)
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
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' || c == ',' || c == '/' || c == ':' {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Minimal base64 encoder for HTTP Basic auth. Mirrors the
/// publish-side helper — same alphabet + padding rules.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
        assert_eq!(h.get("realm").map(String::as_str), Some("https://auth.docker.io/token"));
        assert_eq!(h.get("service").map(String::as_str), Some("registry.docker.io"));
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

    // Catches: resolve_static_auth_header silently letting an empty
    // bearer token through. The wire layer would attach
    // `Authorization: Bearer ` (empty) and the registry returns a
    // confusing 400; failing locally is the operator's fix point.
    #[test]
    fn test_resolve_static_auth_header_rejects_empty_bearer() {
        let err =
            resolve_static_auth_header(&RegistryAuth::Bearer { token: "".into() }).unwrap_err();
        match err {
            RegistryPullError::Auth { .. } => {}
            other => panic!("expected Auth error, got {other:?}"),
        }
    }

    // Catches: resolve_static_auth_header generating a malformed
    // Basic header (missing colon between user and password, or
    // wrong base64 alphabet). Pre-computed reference value:
    // `printf 'admin:hunter2' | base64`.
    #[test]
    fn test_resolve_static_auth_header_basic_matches_reference() {
        let h = resolve_static_auth_header(&RegistryAuth::Basic {
            username: "admin".into(),
            password: "hunter2".into(),
        })
        .unwrap();
        assert_eq!(h.to_str().unwrap(), "Basic YWRtaW46aHVudGVyMg==");
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
}
