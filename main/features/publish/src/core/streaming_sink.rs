//! Streaming sink — push a single-layer OCI artifact directly from a
//! source file to an OCI Distribution registry, skipping the intermediate
//! OCI image layout on disk.
//!
//! The single public entry point is [`push_artifact_streaming`]. It takes
//! a pre-computed digest so callers that already hashed the source (e.g.
//! for signing) do not pay for a second SHA-256 pass.
//!
//! ### Wire sequence
//! 1. HEAD-then-skip the 2-byte empty config blob (`{}`).
//! 2. HEAD-then-skip the layer blob; if absent, stream from `source`.
//! 3. Build a minimal OCI Image Manifest in memory and compute its SHA-256.
//! 4. PUT the manifest at `tag`.
//!
//! ### Why a separate file
//! `registry_sink` walks a pre-built [`crate::api::image_dir::ImageDir`] — it
//! requires that the OCI layout was already materialised on disk. This module
//! goes the other direction: it builds the wire payloads on the fly so no
//! layout directory is ever written.

use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::time::Duration;

use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use reqwest::StatusCode;
use sha2::{Digest as _, Sha256};

use crate::api::error::{preview_body, PublishError, MAX_REGISTRY_BODY_PREVIEW};
use crate::api::image_dir::MEDIA_TYPE_OCI_MANIFEST;
use crate::api::sink::{
    PublishOutcome, RegistryAuth, ENV_REGISTRY_PASSWORD, ENV_REGISTRY_TOKEN, ENV_REGISTRY_USERNAME,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RETRIES: u32 = 3;
const MAX_RETRY_BACKOFF_MS: u64 = 800;
const ENV_ALLOW_INSECURE: &str = "JUSTOCI_ALLOW_INSECURE";

/// The canonical OCI empty config blob.
///
/// OCI 1.1 §5.2 recommends `{}` (2 bytes) for descriptor-only / artifact
/// manifests. Its SHA-256 is the well-known `44136fa3…` digest that every
/// OCI-aware tool recognises. The registry's HEAD check short-circuits
/// the upload on subsequent pushes because the digest is globally stable.
const EMPTY_CONFIG: &[u8] = b"{}";
const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const MEDIA_TYPE_EMPTY_CONFIG: &str = "application/vnd.oci.empty.v1+json";

/// Registry coordinates bundled for internal helpers, mirroring the
/// `WireContext` pattern in `registry_sink`.
struct Wire<'a> {
    client: &'a Client,
    base_url: &'a str,
    repository: &'a str,
    auth: &'a Option<HeaderValue>,
}

/// Push a single-layer OCI artifact directly from `source` to an OCI
/// Distribution registry, bypassing the intermediate OCI layout on disk.
///
/// `layer_digest_hex` must be the lowercase SHA-256 hex of `source`'s
/// content; `layer_size` must equal its byte count. Both are caller-supplied
/// so callers that already computed the digest (e.g. for signing) avoid a
/// second hash pass. The registry validates the digest on receipt and rejects
/// mismatches.
#[allow(clippy::too_many_arguments)]
pub fn push_artifact_streaming(
    source: &Path,
    layer_digest_hex: &str,
    layer_size: u64,
    layer_media_type: &str,
    registry: &str,
    repository: &str,
    tag: &str,
    auth: Option<RegistryAuth>,
) -> Result<PublishOutcome, PublishError> {
    let layer_digest = format!("sha256:{layer_digest_hex}");

    let scheme = if env_allows_insecure() { "http" } else { "https" };
    let base_url = format!("{scheme}://{registry}");
    let client = build_client()?;
    let auth_header = resolve_auth(auth)?;
    let wire = Wire {
        client: &client,
        base_url: &base_url,
        repository,
        auth: &auth_header,
    };

    let mut outcome = PublishOutcome::empty();

    push_bytes_blob_with_skip(&wire, EMPTY_CONFIG, EMPTY_CONFIG_DIGEST, &mut outcome)?;
    push_file_blob_with_skip(&wire, source, &layer_digest, layer_size, &mut outcome)?;

    let manifest = build_manifest_json(layer_media_type, &layer_digest, layer_size);
    let manifest_hex = hex_sha256(&manifest);
    let manifest_digest = format!("sha256:{manifest_hex}");
    let put_url = format!("{base_url}/v2/{repository}/manifests/{tag}");
    let manifest_len = put_manifest(wire.client, &put_url, wire.auth, &manifest)?;
    outcome.digests_pushed.push(manifest_digest);
    outcome.bytes_uploaded += manifest_len;

    Ok(outcome)
}

fn push_bytes_blob_with_skip(
    wire: &Wire<'_>,
    data: &[u8],
    digest: &str,
    outcome: &mut PublishOutcome,
) -> Result<(), PublishError> {
    let head_url = format!("{}/v2/{}/blobs/{digest}", wire.base_url, wire.repository);
    if head_blob(wire.client, &head_url, wire.auth, digest)? == StatusCode::OK {
        outcome.digests_skipped.push(digest.to_string());
        return Ok(());
    }

    let init_url = format!("{}/v2/{}/blobs/uploads/", wire.base_url, wire.repository);
    let location = init_blob_upload(wire.client, &init_url, wire.auth, digest)?;
    let put_url = append_digest_param(&location, digest);
    let size = data.len() as u64;

    let req = apply_auth(wire.client.put(&put_url), wire.auth)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, size)
        .body(data.to_vec());
    let resp = req.send().map_err(|e| PublishError::BlobUpload {
        digest: digest.to_string(),
        source: Box::new(e),
    })?;
    let status = resp.status();
    if status != StatusCode::CREATED && status != StatusCode::OK {
        return Err(PublishError::BlobUpload {
            digest: digest.to_string(),
            source: format!("registry returned HTTP {}", status.as_u16()).into(),
        });
    }
    outcome.digests_pushed.push(digest.to_string());
    outcome.bytes_uploaded += size;
    Ok(())
}

fn push_file_blob_with_skip(
    wire: &Wire<'_>,
    path: &Path,
    digest: &str,
    size: u64,
    outcome: &mut PublishOutcome,
) -> Result<(), PublishError> {
    let head_url = format!("{}/v2/{}/blobs/{digest}", wire.base_url, wire.repository);
    if head_blob(wire.client, &head_url, wire.auth, digest)? == StatusCode::OK {
        outcome.digests_skipped.push(digest.to_string());
        return Ok(());
    }

    let init_url = format!("{}/v2/{}/blobs/uploads/", wire.base_url, wire.repository);
    let location = init_blob_upload(wire.client, &init_url, wire.auth, digest)?;
    let put_url = append_digest_param(&location, digest);

    for attempt in 0..=MAX_RETRIES {
        let f = fs::File::open(path).map_err(|source| PublishError::Io { source })?;
        let body = reqwest::blocking::Body::sized(f, size);
        let req = apply_auth(wire.client.put(&put_url), wire.auth)
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
                    return Err(PublishError::BlobUpload {
                        digest: digest.to_string(),
                        source: format!("registry returned HTTP {}", status.as_u16()).into(),
                    });
                }
                outcome.digests_pushed.push(digest.to_string());
                outcome.bytes_uploaded += size;
                return Ok(());
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
    Err(last_err.expect("loop sets last_err on every failure"))
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
                    return Err(PublishError::RegistryRefused {
                        status: status.as_u16(),
                        body: read_body_capped(resp),
                    });
                }
                let location = resp
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| PublishError::BlobUpload {
                        digest: digest.to_string(),
                        source: "registry accepted upload but returned no Location header".into(),
                    })?
                    .to_str()
                    .map_err(|e| PublishError::BlobUpload {
                        digest: digest.to_string(),
                        source: Box::new(e),
                    })?
                    .to_string();
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
                    return Err(PublishError::ManifestUpload {
                        source: format!("registry returned HTTP {}", status.as_u16()).into(),
                    });
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

fn build_client() -> Result<Client, PublishError> {
    ClientBuilder::new()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| PublishError::Auth { source: Box::new(e) })
}

fn resolve_auth(auth: Option<RegistryAuth>) -> Result<Option<HeaderValue>, PublishError> {
    let Some(auth) = auth else {
        return Ok(None);
    };
    let header_value = match auth {
        RegistryAuth::Bearer { token } => format!("Bearer {token}"),
        RegistryAuth::Basic { username, password } => {
            format!(
                "Basic {}",
                base64_encode(format!("{username}:{password}").as_bytes())
            )
        }
        RegistryAuth::FromEnv => {
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
                format!(
                    "Basic {}",
                    base64_encode(format!("{user}:{pass}").as_bytes())
                )
            }
        }
    };
    let mut hv = HeaderValue::from_str(&header_value)
        .map_err(|e| PublishError::Auth { source: Box::new(e) })?;
    hv.set_sensitive(true);
    Ok(Some(hv))
}

fn env_allows_insecure() -> bool {
    std::env::var(ENV_ALLOW_INSECURE)
        .map(|v| v == "1")
        .unwrap_or(false)
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
    let shift = attempt.min(8);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let ms = 200u64.saturating_mul(factor).min(MAX_RETRY_BACKOFF_MS);
    std::thread::sleep(Duration::from_millis(ms));
}

fn absolutize_location(request_url: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
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

fn append_digest_param(location: &str, digest: &str) -> String {
    if location.contains('?') {
        format!("{location}&digest={digest}")
    } else {
        format!("{location}?digest={digest}")
    }
}

fn read_body_capped(resp: reqwest::blocking::Response) -> String {
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

fn build_manifest_json(layer_media_type: &str, layer_digest: &str, layer_size: u64) -> Vec<u8> {
    let v = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_OCI_MANIFEST,
        "config": {
            "mediaType": MEDIA_TYPE_EMPTY_CONFIG,
            "digest": EMPTY_CONFIG_DIGEST,
            "size": 2u64
        },
        "layers": [{
            "mediaType": layer_media_type,
            "digest": layer_digest,
            "size": layer_size
        }]
    });
    serde_json::to_vec(&v)
        .expect("manifest JSON serialisation is infallible for known-valid inputs")
}

fn hex_sha256(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let hash = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in hash {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// Minimal base64 encoder for HTTP Basic auth. Standard alphabet with
/// padding; mirrors the implementation in `registry_sink` so both sinks
/// use consistent encoding.
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

    // Catches: EMPTY_CONFIG_DIGEST drifting from the actual SHA-256 of `{}`.
    // The registry rejects uploads whose digest doesn't match the bytes.
    #[test]
    fn test_empty_config_digest_matches_content() {
        let actual = format!("sha256:{}", hex_sha256(EMPTY_CONFIG));
        assert_eq!(
            actual, EMPTY_CONFIG_DIGEST,
            "EMPTY_CONFIG_DIGEST constant is wrong"
        );
    }

    // Catches: build_manifest_json producing invalid JSON or missing
    // required OCI manifest fields (schemaVersion, config, layers).
    #[test]
    fn test_build_manifest_json_is_valid_oci_manifest() {
        let bytes = build_manifest_json("application/octet-stream", "sha256:abcd1234", 1024);
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["mediaType"], MEDIA_TYPE_OCI_MANIFEST);
        assert_eq!(v["config"]["digest"], EMPTY_CONFIG_DIGEST);
        assert_eq!(v["config"]["size"], 2u64);
        assert_eq!(v["layers"][0]["mediaType"], "application/octet-stream");
        assert_eq!(v["layers"][0]["digest"], "sha256:abcd1234");
        assert_eq!(v["layers"][0]["size"], 1024u64);
    }

    // Catches: hex_sha256 producing the wrong length or wrong casing.
    // A 63-char or uppercase hex would produce an invalid OCI digest.
    #[test]
    fn test_hex_sha256_length_and_casing() {
        let h = hex_sha256(b"hello");
        assert_eq!(h.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(
            h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "hex must be lowercase"
        );
    }

    // Catches: absolutize_location failing to prepend scheme+host to a
    // registry-relative Location header. A wrong URL makes all streaming
    // pushes fail with a network error.
    #[test]
    fn test_absolutize_location_handles_relative_path() {
        let req = "http://127.0.0.1:5000/v2/repo/blobs/uploads/";
        let abs = absolutize_location(req, "/v2/repo/blobs/uploads/abc");
        assert_eq!(abs, "http://127.0.0.1:5000/v2/repo/blobs/uploads/abc");
    }

    // Catches: absolutize_location double-prefixing an already-absolute URL.
    #[test]
    fn test_absolutize_location_passes_through_absolute() {
        let req = "http://a.example/v2/r/blobs/uploads/";
        let loc = "http://b.example/v2/r/blobs/uploads/xyz";
        assert_eq!(absolutize_location(req, loc), loc);
    }

    // Catches: append_digest_param using `?` when the location already has a
    // query string — that produces a malformed URL the registry rejects.
    #[test]
    fn test_append_digest_param_uses_ampersand_when_query_exists() {
        let loc = "http://r/v2/r/blobs/uploads/abc?state=xyz";
        let result = append_digest_param(loc, "sha256:deadbeef");
        assert!(result.contains("state=xyz"), "existing query preserved");
        assert!(
            result.contains("&digest=sha256:deadbeef"),
            "digest appended with &"
        );
    }

    // Catches: append_digest_param using `&` when no query string exists.
    #[test]
    fn test_append_digest_param_uses_question_mark_for_first_param() {
        let loc = "http://r/v2/r/blobs/uploads/abc";
        let result = append_digest_param(loc, "sha256:cafebabe");
        assert_eq!(result, "http://r/v2/r/blobs/uploads/abc?digest=sha256:cafebabe");
    }

    // Catches: base64_encode producing wrong output for HTTP Basic auth.
    // A wrong encoding silently produces an invalid Authorization header.
    #[test]
    fn test_base64_encode_known_value() {
        assert_eq!(base64_encode(b"admin:hunter2"), "YWRtaW46aHVudGVyMg==");
    }
}
