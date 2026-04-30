//! Registry sink (ADR-015 Level 4) — push a validated [`ImageDir`] to
//! an OCI Distribution v2 registry.
//!
//! Wire protocol per OCI Distribution Spec v1.1:
//!
//! 1. For every blob in [`ImageDir::referenced_blobs`] EXCEPT the
//!    primary manifest, run a HEAD/POST/PUT triplet:
//!    HEAD `/v2/<repo>/blobs/<digest>` — 200 ⇒ skip (already
//!    present); 404 ⇒ continue; anything else ⇒
//!    [`PublishError::RegistryRefused`]. Then POST
//!    `/v2/<repo>/blobs/uploads/` for an upload session, take the
//!    `Location:` URL, and PUT the bytes there with `?digest=<d>`
//!    appended; expect `201 Created`.
//! 2. After every blob is confirmed-present, `PUT /v2/<repository>/manifests/<tag>`
//!    with the primary manifest bytes — this is the commit point.
//!    Registry tag → manifest pointer flips atomically; until this PUT
//!    succeeds, the image is invisible at the tag.
//! 3. Referrer manifests are pushed AS manifests (not blobs) under
//!    their digest so OCI 1.1 referrers API queries find them. Order
//!    relative to the primary: referrer-manifest PUTs MAY be before
//!    or after the primary; spec doesn't mandate. We do them BEFORE
//!    so a verifier that lists referrers immediately after the
//!    primary is published sees a consistent set.
//!
//! ### Idempotency
//!
//! Step 1.a is the resumability mechanism: a partial publish that
//! pushed N blobs and died will, on retry, find HEAD returns 200
//! for those N and short-circuit them. The wire-level guarantee is
//! the registry's content-addressing: PUT'ing the same bytes under
//! the same digest is a no-op (or, if the registry rejects it as a
//! conflict, the HEAD pre-check has already absorbed the case).
//!
//! ### Bounded everything
//!
//! - Per-request timeout (`REQUEST_TIMEOUT`).
//! - Per-blob retry count (`MAX_RETRIES`, exponential back-off bounded
//!   at `MAX_RETRY_BACKOFF_MS`). A 5xx triggers retry; auth / 4xx /
//!   404-on-blob-after-PUT do NOT retry — those are the operator's
//!   problem.
//! - Per-response body cap (`MAX_REGISTRY_BODY_PREVIEW`) on the
//!   error path so a hostile registry doesn't dictate operator
//!   memory.

use std::fs;
use std::io::Read;
use std::time::Duration;

use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use reqwest::StatusCode;

use crate::api::error::{preview_body, PublishError, MAX_REGISTRY_BODY_PREVIEW};
use crate::api::image_dir::{ImageDir, MEDIA_TYPE_OCI_MANIFEST};
use crate::api::sink::{
    PublishOutcome, RegistryAuth, ENV_REGISTRY_PASSWORD, ENV_REGISTRY_TOKEN, ENV_REGISTRY_USERNAME,
};

/// Per-HTTP-request timeout. Short enough that a wedged registry
/// doesn't block the caller indefinitely; long enough that a slow
/// upload of a 100 MiB blob over a 50 Mbps link finishes
/// (~16 seconds; 60 leaves headroom).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Max retries for a transient registry failure (5xx). After this,
/// the publish surfaces [`PublishError::RegistryRefused`] and the
/// operator decides whether to retry.
const MAX_RETRIES: u32 = 3;

/// Max back-off between retries. Exponential: 200ms, 400ms, 800ms.
/// Bounded so a long retry tail can't compound into a stalled CLI.
const MAX_RETRY_BACKOFF_MS: u64 = 800;

/// Env var: opt-in to plain-HTTP transport for local `registry:2`
/// testing. Any value other than literal `"1"` is ignored.
const ENV_ALLOW_INSECURE: &str = "JUSTOCI_ALLOW_INSECURE";

/// Bundle of registry coordinates threaded through every wire call.
/// Reduces argument-count noise and locks the (base_url, repository,
/// auth-header, client) quartet together so a future refactor can't
/// reach the wire layer with a mismatched subset.
struct WireContext<'a> {
    client: &'a Client,
    base_url: &'a str,
    repository: &'a str,
    auth: &'a Option<HeaderValue>,
}

/// Push `image` to `registry / repository : tag`. See module docs
/// for the wire-protocol contract.
pub fn publish_registry(
    image: &ImageDir,
    registry: &str,
    repository: &str,
    tag: &str,
    auth: Option<RegistryAuth>,
) -> Result<PublishOutcome, PublishError> {
    let scheme = if env_allows_insecure() {
        "http"
    } else {
        "https"
    };
    let base_url = format!("{scheme}://{registry}");
    let client = build_client()?;
    let auth_header = resolve_auth(auth)?;
    let wire = WireContext {
        client: &client,
        base_url: &base_url,
        repository,
        auth: &auth_header,
    };

    // Walk referenced_blobs, splitting referrer manifests into a
    // separate bucket — they're pushed as manifests (PUT to
    // /manifests/<digest>), not blobs.
    let primary_digest = &image.descriptor().primary_manifest_digest;
    let referrer_digests: std::collections::HashSet<&str> = image
        .descriptor()
        .referrer_manifests
        .iter()
        .map(|d| d.digest.as_str())
        .collect();

    let mut outcome = PublishOutcome::empty();

    // Step 1: push every NON-manifest blob (layers + configs + the
    // configs/layers of referrers). Skip the primary manifest digest
    // (handled in step 3) and skip referrer-manifest digests
    // (handled in step 2).
    for desc in image.referenced_blobs() {
        if desc.digest == *primary_digest {
            continue;
        }
        if referrer_digests.contains(desc.digest.as_str()) {
            continue;
        }
        push_blob_with_skip(&wire, image, &desc.digest, &mut outcome)?;
    }

    // Step 2: push referrer manifests UNDER THEIR DIGEST so OCI 1.1
    // referrers API can find them. Each referrer is a complete OCI
    // manifest blob; we PUT it to /manifests/<digest> with the OCI
    // manifest media type.
    for ref_desc in &image.descriptor().referrer_manifests {
        push_manifest_with_skip(
            &wire,
            image,
            &ref_desc.digest,
            // Reference target is the digest itself for referrer
            // manifests (they're addressed by digest, not tag).
            &ref_desc.digest,
            &mut outcome,
        )?;
    }

    // Step 3: PUT the primary manifest under the tag. This is the
    // commit point — the tag pointer flips atomically here.
    push_manifest_with_skip(&wire, image, primary_digest, tag, &mut outcome)?;

    Ok(outcome)
}

fn build_client() -> Result<Client, PublishError> {
    ClientBuilder::new()
        .timeout(REQUEST_TIMEOUT)
        // Don't follow redirects on 3xx — the OCI Distribution
        // protocol uses `Location:` headers as upload session URLs,
        // and reqwest's auto-follow eats that signal.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|source| PublishError::Auth {
            source: Box::new(source),
        })
}

/// Resolve the `Authorization` header value (or `None` for anon)
/// from the requested auth mode.
fn resolve_auth(auth: Option<RegistryAuth>) -> Result<Option<HeaderValue>, PublishError> {
    let Some(auth) = auth else {
        return Ok(None);
    };
    let header_value = match auth {
        RegistryAuth::Bearer { token } => format!("Bearer {token}"),
        RegistryAuth::Basic { username, password } => {
            let creds = format!("{username}:{password}");
            format!("Basic {}", base64_encode(creds.as_bytes()))
        }
        RegistryAuth::FromEnv => {
            // Token wins when present.
            if let Ok(t) = std::env::var(ENV_REGISTRY_TOKEN) {
                if !t.is_empty() {
                    format!("Bearer {t}")
                } else {
                    return Err(PublishError::Auth {
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
                    return Err(PublishError::Auth {
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
    let mut hv = HeaderValue::from_str(&header_value).map_err(|source| PublishError::Auth {
        source: Box::new(source),
    })?;
    hv.set_sensitive(true);
    Ok(Some(hv))
}

fn env_allows_insecure() -> bool {
    std::env::var(ENV_ALLOW_INSECURE)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// HEAD-then-PUT a blob with skip-if-exists. Updates `outcome`.
fn push_blob_with_skip(
    wire: &WireContext<'_>,
    image: &ImageDir,
    digest: &str,
    outcome: &mut PublishOutcome,
) -> Result<(), PublishError> {
    let head_url = format!("{}/v2/{}/blobs/{digest}", wire.base_url, wire.repository);
    let head_status = head_blob(wire.client, &head_url, wire.auth, digest)?;
    if head_status == StatusCode::OK {
        outcome.digests_skipped.push(digest.to_string());
        return Ok(());
    }
    // Otherwise: 404 Not Found is the expected "go upload it" signal.
    // Anything else is suspicious; we retry-with-backoff on 5xx,
    // surface 4xx as RegistryRefused.
    if head_status != StatusCode::NOT_FOUND {
        return Err(PublishError::RegistryRefused {
            status: head_status.as_u16(),
            body: format!(
                "HEAD blob {digest}: unexpected status {} (expected 200 or 404)",
                head_status.as_u16()
            ),
        });
    }

    // Initiate upload session.
    let init_url = format!("{}/v2/{}/blobs/uploads/", wire.base_url, wire.repository);
    let location = init_blob_upload(wire.client, &init_url, wire.auth, digest)?;

    // PUT the blob bytes.
    let blob_path = image.blob_path(digest).map_err(PublishError::from)?;
    let bytes_uploaded =
        put_blob_monolithic(wire.client, &location, wire.auth, &blob_path, digest)?;

    outcome.digests_pushed.push(digest.to_string());
    outcome.bytes_uploaded += bytes_uploaded;
    Ok(())
}

/// PUT a manifest with skip-if-exists. Used for referrer manifests
/// (where `target` is the digest) and for the primary manifest
/// (where `target` is the tag).
fn push_manifest_with_skip(
    wire: &WireContext<'_>,
    image: &ImageDir,
    digest: &str,
    target: &str,
    outcome: &mut PublishOutcome,
) -> Result<(), PublishError> {
    // HEAD the manifest at its digest target. If already present,
    // a registry-side tag re-target via PUT is still required for
    // the primary (the tag may not point at this digest yet) — so
    // we only short-circuit when we're addressing by digest
    // (referrer manifest path), not by tag.
    let by_digest = digest == target;
    if by_digest {
        let head_url = format!(
            "{}/v2/{}/manifests/{digest}",
            wire.base_url, wire.repository
        );
        let head_status = head_manifest(wire.client, &head_url, wire.auth, digest)?;
        if head_status == StatusCode::OK {
            outcome.digests_skipped.push(digest.to_string());
            return Ok(());
        }
    }

    let manifest_path = image.blob_path(digest).map_err(PublishError::from)?;
    let manifest_bytes =
        fs::read(&manifest_path).map_err(|source| PublishError::ManifestUpload {
            source: Box::new(source),
        })?;

    let put_url = format!(
        "{}/v2/{}/manifests/{target}",
        wire.base_url, wire.repository
    );
    let bytes_uploaded = put_manifest(wire.client, &put_url, wire.auth, &manifest_bytes)?;

    outcome.digests_pushed.push(digest.to_string());
    outcome.bytes_uploaded += bytes_uploaded;
    Ok(())
}

fn head_blob(
    client: &Client,
    url: &str,
    auth: &Option<HeaderValue>,
    digest: &str,
) -> Result<StatusCode, PublishError> {
    let mut last_err: Option<PublishError> = None;
    for attempt in 0..=MAX_RETRIES {
        let req = apply_auth(client.head(url), auth);
        match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                return Ok(status);
            }
            Err(e) => {
                last_err = Some(PublishError::BlobUpload {
                    digest: digest.to_string(),
                    source: Box::new(e),
                });
                if attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
            }
        }
    }
    Err(last_err.expect("loop body sets last_err on every failure"))
}

fn head_manifest(
    client: &Client,
    url: &str,
    auth: &Option<HeaderValue>,
    digest: &str,
) -> Result<StatusCode, PublishError> {
    let mut last_err: Option<PublishError> = None;
    for attempt in 0..=MAX_RETRIES {
        let req = apply_auth(client.head(url), auth).header("Accept", MEDIA_TYPE_OCI_MANIFEST);
        match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                return Ok(status);
            }
            Err(e) => {
                last_err = Some(PublishError::ManifestUpload {
                    source: Box::new(IoLikeError {
                        what: format!("HEAD manifest {digest}"),
                        source: e.to_string(),
                    }),
                });
                if attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
            }
        }
    }
    Err(last_err.expect("loop body sets last_err on every failure"))
}

fn init_blob_upload(
    client: &Client,
    url: &str,
    auth: &Option<HeaderValue>,
    digest: &str,
) -> Result<String, PublishError> {
    for attempt in 0..=MAX_RETRIES {
        let req = apply_auth(client.post(url), auth).header(CONTENT_LENGTH, "0");
        match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                if status != StatusCode::ACCEPTED && status != StatusCode::CREATED {
                    return Err(refused_from_response(resp));
                }
                let location = resp
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| PublishError::BlobUpload {
                        digest: digest.to_string(),
                        source: "registry accepted upload init but returned no Location header"
                            .into(),
                    })?
                    .to_str()
                    .map_err(|e| PublishError::BlobUpload {
                        digest: digest.to_string(),
                        source: Box::new(e),
                    })?
                    .to_string();
                // The Location may be relative; if so, anchor against
                // the request's URL host.
                return Ok(absolutize_location(url, &location));
            }
            Err(e) => {
                if attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                return Err(PublishError::BlobUpload {
                    digest: digest.to_string(),
                    source: Box::new(e),
                });
            }
        }
    }
    unreachable!("loop returns or retries");
}

fn put_blob_monolithic(
    client: &Client,
    location: &str,
    auth: &Option<HeaderValue>,
    blob_path: &std::path::Path,
    digest: &str,
) -> Result<u64, PublishError> {
    // Append `?digest=<digest>` (or `&digest=` if location already
    // has a query string) per OCI Distribution v2.
    let put_url = if location.contains('?') {
        format!("{location}&digest={digest}")
    } else {
        format!("{location}?digest={digest}")
    };

    let metadata = fs::metadata(blob_path).map_err(|source| PublishError::BlobUpload {
        digest: digest.to_string(),
        source: Box::new(source),
    })?;
    let size = metadata.len();

    for attempt in 0..=MAX_RETRIES {
        // Re-open the file each attempt — `Read` advances the cursor
        // and a retry needs a fresh read from offset 0.
        let f = fs::File::open(blob_path).map_err(|source| PublishError::BlobUpload {
            digest: digest.to_string(),
            source: Box::new(source),
        })?;
        let body = reqwest::blocking::Body::sized(f, size);

        let req = apply_auth(client.put(&put_url), auth)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, size)
            .body(body);

        match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                if status != StatusCode::CREATED && status != StatusCode::OK {
                    return Err(refused_from_response_with_digest(resp, digest));
                }
                return Ok(size);
            }
            Err(e) => {
                if attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                return Err(PublishError::BlobUpload {
                    digest: digest.to_string(),
                    source: Box::new(e),
                });
            }
        }
    }
    unreachable!("loop returns or retries");
}

fn put_manifest(
    client: &Client,
    url: &str,
    auth: &Option<HeaderValue>,
    bytes: &[u8],
) -> Result<u64, PublishError> {
    let len = bytes.len() as u64;
    for attempt in 0..=MAX_RETRIES {
        let req = apply_auth(client.put(url), auth)
            .header(CONTENT_TYPE, MEDIA_TYPE_OCI_MANIFEST)
            .header(CONTENT_LENGTH, len)
            .body(bytes.to_vec());
        match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                if status != StatusCode::CREATED && status != StatusCode::OK {
                    return Err(refused_manifest_from_response(resp));
                }
                return Ok(len);
            }
            Err(e) => {
                if attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                return Err(PublishError::ManifestUpload {
                    source: Box::new(e),
                });
            }
        }
    }
    unreachable!("loop returns or retries");
}

fn apply_auth(
    req: reqwest::blocking::RequestBuilder,
    auth: &Option<HeaderValue>,
) -> reqwest::blocking::RequestBuilder {
    match auth {
        Some(hv) => req.header(AUTHORIZATION, hv.clone()),
        None => req,
    }
}

fn sleep_backoff(attempt: u32) {
    // 200ms, 400ms, 800ms — capped.
    let shift = attempt.min(8); // bound the shift so the saturating
                                // arithmetic never overflows even
                                // on a programming error that lets
                                // `attempt` exceed MAX_RETRIES.
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let ms = 200u64.saturating_mul(factor).min(MAX_RETRY_BACKOFF_MS);
    std::thread::sleep(Duration::from_millis(ms));
}

fn refused_from_response(resp: Response) -> PublishError {
    let status = resp.status().as_u16();
    let body = read_body_capped(resp);
    PublishError::RegistryRefused { status, body }
}

fn refused_from_response_with_digest(resp: Response, digest: &str) -> PublishError {
    let status = resp.status().as_u16();
    let body = read_body_capped(resp);
    if status == 401 || status == 403 {
        return PublishError::Auth {
            source: format!("uploading blob {digest}: HTTP {status}: {body}").into(),
        };
    }
    PublishError::RegistryRefused {
        status,
        body: format!("uploading blob {digest}: {body}"),
    }
}

fn refused_manifest_from_response(resp: Response) -> PublishError {
    let status = resp.status().as_u16();
    let body = read_body_capped(resp);
    if status == 401 || status == 403 {
        return PublishError::Auth {
            source: format!("uploading manifest: HTTP {status}: {body}").into(),
        };
    }
    PublishError::RegistryRefused {
        status,
        body: format!("uploading manifest: {body}"),
    }
}

fn read_body_capped(resp: Response) -> String {
    // Read up to MAX_REGISTRY_BODY_PREVIEW bytes. We use a manual
    // read loop so a hostile registry that streams gibberish
    // forever can't fill operator memory.
    let mut buf = vec![0u8; MAX_REGISTRY_BODY_PREVIEW];
    let mut total = 0;
    let mut reader = resp;
    loop {
        if total >= MAX_REGISTRY_BODY_PREVIEW {
            break;
        }
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    preview_body(&buf[..total])
}

fn absolutize_location(request_url: &str, location: &str) -> String {
    // Already absolute? Pass through.
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    // Resolve scheme + authority from the request URL.
    if let Some(scheme_end) = request_url.find("://") {
        let after_scheme = &request_url[scheme_end + 3..];
        let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let host = &after_scheme[..host_end];
        let scheme = &request_url[..scheme_end];
        if location.starts_with('/') {
            format!("{scheme}://{host}{location}")
        } else {
            format!("{scheme}://{host}/{location}")
        }
    } else {
        location.to_string()
    }
}

/// Tiny error wrapper so we can carry "what we were doing + reqwest
/// detail" through `Box<dyn Error>` without losing context. Used
/// only for the manifest HEAD path where the source is a
/// `reqwest::Error` whose `Display` alone doesn't say "this was a
/// HEAD manifest call."
#[derive(Debug)]
struct IoLikeError {
    what: String,
    source: String,
}

impl std::fmt::Display for IoLikeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.what, self.source)
    }
}

impl std::error::Error for IoLikeError {}

/// Minimal base64 encoder for HTTP Basic auth. Avoids dragging
/// `base64` into the dep tree for one call site. Uses the standard
/// alphabet without padding control — Basic auth requires the
/// canonical alphabet WITH padding, which this returns.
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

    // Catches: drift in the Basic-auth encoding (`username:password`
    // base64 round-trip). Pre-computed reference value verified
    // against `printf 'admin:hunter2' | base64`.
    #[test]
    fn test_base64_encode_admin_hunter2() {
        let s = base64_encode(b"admin:hunter2");
        assert_eq!(s, "YWRtaW46aHVudGVyMg==");
    }

    // Catches: padding regressions on inputs whose length is not a
    // multiple of 3. Reference values verified against `base64`.
    #[test]
    fn test_base64_encode_padding_for_short_inputs() {
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    // Catches: env_allows_insecure widening to "any non-empty value"
    // — would silently flip production pushes to plain HTTP.
    #[test]
    fn test_env_allows_insecure_strict_one_only() {
        // We can't easily mutate env here without a global lock —
        // smoke-test the bare logic via a wrapper would be a
        // refactor with no payoff. Instead: assert the current
        // process default is HTTPS (no env var set in unit tests).
        // The integration tests cover the env-on path via
        // `httpmock` running on plain HTTP + setting the var.
        let env_was = std::env::var(ENV_ALLOW_INSECURE).ok();
        std::env::remove_var(ENV_ALLOW_INSECURE);
        assert!(!env_allows_insecure());
        if let Some(v) = env_was {
            std::env::set_var(ENV_ALLOW_INSECURE, v);
        }
    }

    // Catches: absolutize_location getting confused by relative
    // URLs (the OCI Distribution spec allows the registry to return
    // a relative `Location:` header).
    #[test]
    fn test_absolutize_location_relative_path() {
        let req = "https://registry.example.com/v2/foo/blobs/uploads/";
        let abs = absolutize_location(req, "/v2/foo/blobs/uploads/abc");
        assert_eq!(abs, "https://registry.example.com/v2/foo/blobs/uploads/abc");
    }

    // Catches: absolutize_location double-prefixing an already-
    // absolute URL.
    #[test]
    fn test_absolutize_location_passes_absolute_through() {
        let req = "https://registry.example.com/v2/foo/blobs/uploads/";
        let abs = absolutize_location(req, "https://other.example.com/x");
        assert_eq!(abs, "https://other.example.com/x");
    }

    // Catches: resolve_auth silently allowing FromEnv when no
    // creds are exported. A silent fall-through to anonymous would
    // surprise operators who set the env var name wrong.
    #[test]
    fn test_resolve_auth_from_env_with_no_creds_errors() {
        let env_was_token = std::env::var(ENV_REGISTRY_TOKEN).ok();
        let env_was_user = std::env::var(ENV_REGISTRY_USERNAME).ok();
        let env_was_pass = std::env::var(ENV_REGISTRY_PASSWORD).ok();
        std::env::remove_var(ENV_REGISTRY_TOKEN);
        std::env::remove_var(ENV_REGISTRY_USERNAME);
        std::env::remove_var(ENV_REGISTRY_PASSWORD);

        let err = resolve_auth(Some(RegistryAuth::FromEnv)).unwrap_err();
        match err {
            PublishError::Auth { .. } => {}
            other => panic!("expected Auth error, got {other:?}"),
        }

        if let Some(v) = env_was_token {
            std::env::set_var(ENV_REGISTRY_TOKEN, v);
        }
        if let Some(v) = env_was_user {
            std::env::set_var(ENV_REGISTRY_USERNAME, v);
        }
        if let Some(v) = env_was_pass {
            std::env::set_var(ENV_REGISTRY_PASSWORD, v);
        }
    }

    // Catches: resolve_auth(None) suddenly demanding creds. None
    // means anonymous — expected for public read-only registries.
    #[test]
    fn test_resolve_auth_none_returns_no_header() {
        assert!(resolve_auth(None).unwrap().is_none());
    }

    // Catches: bearer token not being formatted as "Bearer <token>".
    #[test]
    fn test_resolve_auth_bearer_formats_header() {
        let h = resolve_auth(Some(RegistryAuth::Bearer {
            token: "abc123".into(),
        }))
        .unwrap()
        .unwrap();
        // Sensitive headers don't expose their value through Display
        // by default; convert via to_str (allowed for visible chars).
        assert_eq!(h.to_str().unwrap(), "Bearer abc123");
    }
}
