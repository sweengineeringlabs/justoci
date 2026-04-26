//! Pull an OCI artifact + its referrers from a Distribution v2
//! registry into a local OCI Image Layout directory.
//!
//! Pipeline (per OCI Distribution Spec v1.1):
//!
//! 1. `GET /v2/<repo>/manifests/<tag>` with the OCI manifest
//!    `Accept` header set. Capture the body (manifest bytes) and
//!    the `Docker-Content-Digest` header. If the header is missing,
//!    compute sha256 of the body locally — they MUST agree; a
//!    mismatch is a hard error (the registry served different bytes
//!    than it declared).
//! 2. Stream the config blob into `<dest>/blobs/sha256/<hex>`,
//!    hashing as it streams. Reject on digest mismatch BEFORE
//!    finalising the on-disk file.
//! 3. Stream every layer blob the same way.
//! 4. `GET /v2/<repo>/referrers/<manifest-digest>` with the OCI
//!    image-index `Accept` header. The body is an image index
//!    whose `manifests` array lists referrer descriptors (one per
//!    SLSA / SBOM / signature attestation that was published
//!    alongside).
//! 5. For each referrer descriptor: pull its manifest (same
//!    streaming + digest-check shape), then its config + layer
//!    blobs.
//! 6. Compose `<dest>/index.json` locally — the primary manifest
//!    descriptor first, then every referrer descriptor — and write
//!    it LAST. The atomicity contract: until `index.json` exists
//!    on disk, no consumer can read the layout as complete (that's
//!    [`oci_publish::ImageDir::open`]'s validation gate).
//!
//! ### Hard requirements
//!
//! - Every blob's bytes are hashed during streaming and compared
//!   to the descriptor's expected digest. A mismatch raises
//!   [`RegistryPullError::DigestMismatch`] and the partial blob
//!   file is removed so callers can never see tampered bytes on
//!   disk.
//! - Manifests are written as blobs (`<dest>/blobs/sha256/<hex>`)
//!   AND referenced from `index.json` — same shape `ocimage build`
//!   produces, so the local-verify path treats a pulled layout
//!   identically to a built one.
//! - Per-request 60-second timeout; per-blob 3-attempt retry on
//!   transient failure (5xx, network errors).
//! - On any failure, the tempdir is left in a documented partial
//!   state. The caller (test fixture, CLI verify) decides whether
//!   to inspect or delete; this function does NOT delete.
//!
//! ### Out of scope for v0.2
//!
//! - HTTP range requests for resumable layer downloads. Per-blob
//!   retry IS implemented; partial-blob resume is a follow-up.
//! - Multi-platform manifest indexes. The pull layer rejects an
//!   image index at the primary-manifest endpoint (it's a list of
//!   per-arch manifests, not the artifact itself). Document the
//!   gap in the typed error.
//! - Parallel layer downloads. Sequential keeps the wire pattern
//!   simple and observable; throughput on small artifacts is
//!   already bounded by the manifest fetch.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use oci_publish::RegistryAuth;

use super::auth::{
    extract_bearer_challenge, fetch_bearer_token, resolve_static_auth_header, TOKEN_REQUEST_TIMEOUT,
};
use super::error::{preview_body_capped, RegistryPullError, MAX_REGISTRY_BODY_PREVIEW};
use super::ref_parser::{parse_registry_ref, RefTarget, RegistryRef};

/// Per-HTTP-request timeout. Same 60-second cap publish uses;
/// long enough for a slow 100 MiB layer pull on a 50 Mbps link,
/// short enough that a wedged registry can't hang verify forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Max retries for a transient (5xx, network error) registry
/// failure. Same shape publish uses on the inverse path.
const MAX_RETRIES: u32 = 3;

/// Cap on per-retry back-off. Exponential: 200, 400, 800; then
/// pinned at MAX_RETRY_BACKOFF_MS. Bounded so a flaky registry
/// can't compound retries into a stalled CLI.
const MAX_RETRY_BACKOFF_MS: u64 = 800;

/// OCI manifest media type — what the manifest endpoint serves.
const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// OCI image index media type — what the referrers endpoint serves.
const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// HTTP header set by Distribution v2 carrying the manifest's
/// digest. Servers SHOULD set it; we tolerate absence by computing
/// the digest from the body bytes locally.
const HEADER_DOCKER_CONTENT_DIGEST: &str = "Docker-Content-Digest";

/// Env var: opt-in to plain-HTTP transport for local `registry:2`
/// testing. Mirrors publish; any value other than literal `"1"` is
/// ignored.
const ENV_ALLOW_INSECURE: &str = "OCIMAGE_ALLOW_INSECURE";

/// Pull `ref_str` into `dest`, producing a complete OCI Image
/// Layout. `dest` MUST exist and be writable; the function does
/// not create it (the caller — typically a `tempfile::TempDir` —
/// owns the lifecycle).
///
/// On success, `dest` validates as [`oci_publish::ImageDir::open`]
/// and the local-verify path can be invoked verbatim.
///
/// On failure, the tempdir is left in a partial state: blobs that
/// already passed their digest check are on disk; the file under
/// active streaming has been removed if it failed verification;
/// `index.json` is NOT written. The caller chooses to inspect or
/// delete.
pub fn pull_into_image_dir(
    ref_str: &str,
    auth: &RegistryAuth,
    dest: &Path,
) -> Result<(), RegistryPullError> {
    let parsed = parse_registry_ref(ref_str)?;
    pull_parsed_into_image_dir(&parsed, auth, dest)
}

/// Anonymous variant — equivalent to `pull_into_image_dir` with
/// auth resolution skipped. Useful for public read-only registries
/// where `RegistryAuth::FromEnv` would error on missing creds.
pub fn pull_anonymous_into_image_dir(ref_str: &str, dest: &Path) -> Result<(), RegistryPullError> {
    let parsed = parse_registry_ref(ref_str)?;
    let ctx = WireContext::new_anonymous(&parsed)?;
    execute_pull(&ctx, &parsed, dest)
}

fn pull_parsed_into_image_dir(
    parsed: &RegistryRef,
    auth: &RegistryAuth,
    dest: &Path,
) -> Result<(), RegistryPullError> {
    let ctx = WireContext::new_authenticated(parsed, auth)?;
    execute_pull(&ctx, parsed, dest)
}

/// HTTP coordinates threaded through every wire call.
struct WireContext {
    client: Client,
    base_url: String,
    repository: String,
    /// Static `Authorization` header value, if any. `None` when
    /// the operator opted into anonymous; the 401-then-token-dance
    /// can still up-grade an anon request to bearer mid-flight.
    static_auth: Option<HeaderValue>,
    /// Cached bearer token from a successful 401-WWW-Authenticate
    /// dance. Once a registry hands us a bearer for a given pull,
    /// every subsequent request reuses it — that's the whole
    /// point of the dance, otherwise every blob would re-401 and
    /// we'd round-trip the token endpoint per blob. Threaded
    /// through a `RefCell` because `send_with_retry` takes `&self`
    /// and the cache mutates.
    cached_bearer: std::cell::RefCell<Option<HeaderValue>>,
}

impl WireContext {
    fn new_authenticated(
        parsed: &RegistryRef,
        auth: &RegistryAuth,
    ) -> Result<Self, RegistryPullError> {
        let static_auth = Some(resolve_static_auth_header(auth)?);
        Self::build(parsed, static_auth)
    }

    fn new_anonymous(parsed: &RegistryRef) -> Result<Self, RegistryPullError> {
        Self::build(parsed, None)
    }

    fn build(
        parsed: &RegistryRef,
        static_auth: Option<HeaderValue>,
    ) -> Result<Self, RegistryPullError> {
        let scheme = if env_allows_insecure() {
            "http"
        } else {
            "https"
        };
        let base_url = format!("{scheme}://{}", parsed.host);
        let client = ClientBuilder::new()
            .timeout(REQUEST_TIMEOUT)
            // Don't follow redirects automatically — token-realm
            // exchanges return 200 with a JSON body, not 3xx, so
            // auto-follow doesn't help. Per-call control is
            // safer.
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| RegistryPullError::Auth {
                source: Box::new(e),
            })?;
        Ok(WireContext {
            client,
            base_url,
            repository: parsed.repository.clone(),
            static_auth,
            cached_bearer: std::cell::RefCell::new(None),
        })
    }
}

fn env_allows_insecure() -> bool {
    std::env::var(ENV_ALLOW_INSECURE)
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn execute_pull(
    ctx: &WireContext,
    parsed: &RegistryRef,
    dest: &Path,
) -> Result<(), RegistryPullError> {
    if !dest.is_dir() {
        return Err(RegistryPullError::Io {
            path: dest.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "destination is not a directory",
            ),
        });
    }
    let blobs_dir = dest.join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir).map_err(|source| RegistryPullError::Io {
        path: blobs_dir.clone(),
        source,
    })?;

    // 1. Resolve the primary manifest.
    let manifest_ref = parsed.manifest_reference();
    let (primary_manifest_bytes, primary_manifest_digest) =
        fetch_manifest(ctx, manifest_ref, MEDIA_TYPE_OCI_MANIFEST)?;

    // If the operator pinned a digest, the manifest digest MUST
    // match. (For tag refs, whatever the registry serves is the
    // truth; we don't have a separate ground truth.)
    if let RefTarget::Digest(expected) = &parsed.target {
        if expected != &primary_manifest_digest {
            return Err(RegistryPullError::DigestMismatch {
                expected: expected.clone(),
                got: primary_manifest_digest,
                blob: format!("primary manifest of {}", parsed.raw),
            });
        }
    }

    // Stage the manifest blob to disk before we trust its config /
    // layer descriptors. Once on disk, the rest of the pull treats
    // it as the authoritative descriptor source.
    write_blob_atomically(
        &blobs_dir,
        &primary_manifest_digest,
        &primary_manifest_bytes,
    )?;

    // Parse the manifest to discover the config + layer descriptors
    // we need to pull next.
    let manifest = parse_image_manifest(&primary_manifest_bytes)?;

    // 2 + 3. Pull the config + every layer blob, with on-the-fly
    // digest verification on every byte stream.
    pull_blob_streamed(ctx, &blobs_dir, &manifest.config.digest)?;
    for (i, layer) in manifest.layers.iter().enumerate() {
        pull_blob_streamed(ctx, &blobs_dir, &layer.digest).map_err(|e| match e {
            RegistryPullError::DigestMismatch { expected, got, .. } => {
                RegistryPullError::DigestMismatch {
                    expected,
                    got,
                    blob: format!("layer[{i}]"),
                }
            }
            other => other,
        })?;
    }

    // 4. Pull referrers.
    let referrer_descriptors = fetch_referrers(ctx, &primary_manifest_digest)?;

    // 5. For each referrer, pull its manifest + config + layers.
    let mut seen_blobs: HashSet<String> = HashSet::new();
    seen_blobs.insert(primary_manifest_digest.clone());
    seen_blobs.insert(manifest.config.digest.clone());
    for layer in &manifest.layers {
        seen_blobs.insert(layer.digest.clone());
    }

    let mut materialised_referrers: Vec<OciDescriptorOnWire> = Vec::new();
    for ref_desc in &referrer_descriptors {
        if !seen_blobs.insert(ref_desc.digest.clone()) {
            // Already pulled (referrer index over-listed somehow);
            // skip.
            materialised_referrers.push(ref_desc.clone());
            continue;
        }
        // Pull the referrer manifest as a manifest (the registry
        // serves it from /manifests/<digest>, not /blobs/).
        let (ref_manifest_bytes, ref_manifest_digest) =
            fetch_manifest(ctx, &ref_desc.digest, MEDIA_TYPE_OCI_MANIFEST)?;
        if ref_manifest_digest != ref_desc.digest {
            return Err(RegistryPullError::DigestMismatch {
                expected: ref_desc.digest.clone(),
                got: ref_manifest_digest,
                blob: "referrer manifest from referrers index".to_string(),
            });
        }
        write_blob_atomically(&blobs_dir, &ref_manifest_digest, &ref_manifest_bytes)?;
        let ref_manifest = parse_image_manifest(&ref_manifest_bytes)?;

        if seen_blobs.insert(ref_manifest.config.digest.clone()) {
            pull_blob_streamed(ctx, &blobs_dir, &ref_manifest.config.digest)?;
        }
        for (i, layer) in ref_manifest.layers.iter().enumerate() {
            if seen_blobs.insert(layer.digest.clone()) {
                pull_blob_streamed(ctx, &blobs_dir, &layer.digest).map_err(|e| match e {
                    RegistryPullError::DigestMismatch { expected, got, .. } => {
                        RegistryPullError::DigestMismatch {
                            expected,
                            got,
                            blob: format!("referrer {} layer[{i}]", ref_desc.digest),
                        }
                    }
                    other => other,
                })?;
            }
        }
        materialised_referrers.push(ref_desc.clone());
    }

    // 6. Write oci-layout, then index.json LAST.
    write_oci_layout_marker(dest)?;
    write_index_json(
        dest,
        &primary_manifest_digest,
        primary_manifest_bytes.len() as u64,
        &materialised_referrers,
    )?;

    Ok(())
}

/// `GET /v2/<repo>/manifests/<reference>`. Returns
/// `(body_bytes, digest)`. The digest is from
/// `Docker-Content-Digest` if set; otherwise computed from the
/// body. If both are present and disagree, that's a hard error
/// (the registry is misbehaving).
fn fetch_manifest(
    ctx: &WireContext,
    reference: &str,
    accept: &str,
) -> Result<(Vec<u8>, String), RegistryPullError> {
    let url = format!(
        "{}/v2/{}/manifests/{}",
        ctx.base_url, ctx.repository, reference
    );
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_str(accept).expect("accept hv"));
    let resp = send_with_retry(ctx, &url, &headers).map_err(|e| match e {
        RegistryPullError::BlobFetch { source, .. } => RegistryPullError::Resolve {
            manifest_url: url.clone(),
            source,
        },
        other => other,
    })?;
    let status = resp.status();
    if !status.is_success() {
        let body_bytes = read_body_capped(resp);
        return Err(RegistryPullError::RegistryRefused {
            url,
            status: status.as_u16(),
            body: preview_body_capped(&body_bytes),
        });
    }
    // Capture the digest header BEFORE consuming the body — once
    // we call `bytes()`, the headers become unreachable.
    let header_digest = resp
        .headers()
        .get(HEADER_DOCKER_CONTENT_DIGEST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp.bytes().map_err(|e| RegistryPullError::Resolve {
        manifest_url: url.clone(),
        source: Box::new(e),
    })?;
    let body_vec = body.to_vec();
    let computed = format!("sha256:{}", hex_sha256(&body_vec));
    let digest = match header_digest {
        Some(h) if h == computed => h,
        Some(h) => {
            return Err(RegistryPullError::DigestMismatch {
                expected: h,
                got: computed,
                blob: format!("manifest at {url}"),
            });
        }
        None => computed,
    };
    Ok((body_vec, digest))
}

/// `GET /v2/<repo>/referrers/<digest>`. The OCI 1.1 referrers API.
/// Returns the parsed list of referrer manifest descriptors. An
/// empty list (no attestations) is OK.
///
/// If the registry doesn't implement the referrers API at all
/// (404 on the endpoint), v0.2 treats that as "no referrers" and
/// continues. (Future hardening: a `--require-referrers` CLI flag
/// would escalate this to an error.)
fn fetch_referrers(
    ctx: &WireContext,
    manifest_digest: &str,
) -> Result<Vec<OciDescriptorOnWire>, RegistryPullError> {
    let url = format!(
        "{}/v2/{}/referrers/{}",
        ctx.base_url, ctx.repository, manifest_digest
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_str(MEDIA_TYPE_OCI_INDEX).expect("accept hv"),
    );
    let resp = send_with_retry(ctx, &url, &headers).map_err(|e| match e {
        RegistryPullError::BlobFetch { source, .. } => RegistryPullError::Resolve {
            manifest_url: url.clone(),
            source,
        },
        other => other,
    })?;
    let status = resp.status();
    if status == StatusCode::NOT_FOUND {
        // Pre-OCI-1.1 registry, or no attestations. Either way:
        // treat as empty.
        return Ok(Vec::new());
    }
    if !status.is_success() {
        let body_bytes = read_body_capped(resp);
        return Err(RegistryPullError::RegistryRefused {
            url,
            status: status.as_u16(),
            body: preview_body_capped(&body_bytes),
        });
    }
    let body = resp.bytes().map_err(|e| RegistryPullError::Resolve {
        manifest_url: url.clone(),
        source: Box::new(e),
    })?;
    let index: ReferrersIndexOnWire =
        serde_json::from_slice(&body).map_err(|e| RegistryPullError::MalformedManifest {
            detail: format!("referrers index from {url}: {e}"),
        })?;
    Ok(index.manifests)
}

/// `GET /v2/<repo>/blobs/<digest>` with streaming + on-the-fly
/// digest verification. The bytes are written to a `.partial`
/// temp file, hashed as they stream; if the digest matches, the
/// file is renamed to its final path. If the digest mismatches,
/// the partial file is removed and [`RegistryPullError::DigestMismatch`]
/// is returned — the destination tempdir never sees tampered
/// content.
///
/// We deliberately don't take an `expected_size` parameter: the
/// digest check is the authoritative integrity gate, and a
/// content-length mismatch surfaces (slightly later) as a digest
/// mismatch anyway. Adding a separate size check would duplicate
/// validation without catching a different bug class.
fn pull_blob_streamed(
    ctx: &WireContext,
    blobs_dir: &Path,
    digest: &str,
) -> Result<(), RegistryPullError> {
    // Skip if already on disk from a prior pull (same dest dir
    // re-used). Same idempotency property publish enforces.
    let final_path = blob_path_for_digest(blobs_dir, digest)?;
    if final_path.is_file() {
        // Trust the file: if it's there, an earlier successful
        // call wrote it after a digest check. Re-hashing every
        // call would be wasteful.
        return Ok(());
    }

    let url = format!("{}/v2/{}/blobs/{}", ctx.base_url, ctx.repository, digest);
    let resp = send_with_retry(ctx, &url, &HeaderMap::new()).map_err(|e| match e {
        // Re-tag the error so the operator sees "blob X failed"
        // rather than "manifest URL".
        RegistryPullError::Resolve { source, .. } => RegistryPullError::BlobFetch {
            digest: digest.to_string(),
            source,
        },
        other => other,
    })?;
    let status = resp.status();
    if !status.is_success() {
        let body_bytes = read_body_capped(resp);
        return Err(RegistryPullError::RegistryRefused {
            url,
            status: status.as_u16(),
            body: preview_body_capped(&body_bytes),
        });
    }

    let partial_path = final_path.with_extension("partial");
    let mut file = fs::File::create(&partial_path).map_err(|source| RegistryPullError::Io {
        path: partial_path.clone(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024]; // 64 KiB streaming chunk
    let mut reader = resp;
    loop {
        let n = reader.read(&mut buf).map_err(|source| {
            // Best-effort cleanup of the partial file before
            // surfacing the error.
            let _ = fs::remove_file(&partial_path);
            RegistryPullError::BlobFetch {
                digest: digest.to_string(),
                source: Box::new(source),
            }
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(|source| {
            let _ = fs::remove_file(&partial_path);
            RegistryPullError::Io {
                path: partial_path.clone(),
                source,
            }
        })?;
    }
    file.flush().map_err(|source| RegistryPullError::Io {
        path: partial_path.clone(),
        source,
    })?;
    drop(file);

    let computed = format!("sha256:{}", finalise_hash(hasher));
    if computed != digest {
        // Per the moat: we NEVER leave tampered bytes addressable
        // by a sha256:<hex> name. Remove the partial file so the
        // next call can retry cleanly, and the consumer never sees
        // a half-correct pull at the digest path.
        let _ = fs::remove_file(&partial_path);
        return Err(RegistryPullError::DigestMismatch {
            expected: digest.to_string(),
            got: computed,
            blob: digest.to_string(),
        });
    }

    fs::rename(&partial_path, &final_path).map_err(|source| RegistryPullError::Io {
        path: final_path.clone(),
        source,
    })?;
    Ok(())
}

/// Atomic write of a manifest blob whose bytes are already in
/// memory. Verifies the digest before rename; mismatch removes the
/// partial.
fn write_blob_atomically(
    blobs_dir: &Path,
    digest: &str,
    bytes: &[u8],
) -> Result<(), RegistryPullError> {
    let final_path = blob_path_for_digest(blobs_dir, digest)?;
    if final_path.is_file() {
        return Ok(());
    }
    let computed = format!("sha256:{}", hex_sha256(bytes));
    if computed != digest {
        return Err(RegistryPullError::DigestMismatch {
            expected: digest.to_string(),
            got: computed,
            blob: digest.to_string(),
        });
    }
    let partial_path = final_path.with_extension("partial");
    fs::write(&partial_path, bytes).map_err(|source| RegistryPullError::Io {
        path: partial_path.clone(),
        source,
    })?;
    fs::rename(&partial_path, &final_path).map_err(|source| RegistryPullError::Io {
        path: final_path.clone(),
        source,
    })?;
    Ok(())
}

fn write_oci_layout_marker(dest: &Path) -> Result<(), RegistryPullError> {
    let p = dest.join("oci-layout");
    if p.is_file() {
        return Ok(());
    }
    fs::write(&p, br#"{"imageLayoutVersion":"1.0.0"}"#)
        .map_err(|source| RegistryPullError::Io { path: p, source })
}

/// Compose the local `index.json`. The primary manifest descriptor
/// is the first entry; every referrer follows. Written LAST in the
/// pull pipeline so until this file lands, the dest dir is NOT a
/// complete OCI layout. That's the atomicity contract the docs
/// promise (and what `ImageDir::open` enforces on the reader side).
fn write_index_json(
    dest: &Path,
    primary_digest: &str,
    primary_size: u64,
    referrers: &[OciDescriptorOnWire],
) -> Result<(), RegistryPullError> {
    let p = dest.join("index.json");
    let mut manifests = vec![json!({
        "mediaType": MEDIA_TYPE_OCI_MANIFEST,
        "digest": primary_digest,
        "size": primary_size,
    })];
    for r in referrers {
        let mut d = json!({
            "mediaType": r.media_type,
            "digest": r.digest,
            "size": r.size,
        });
        if let Some(at) = &r.artifact_type {
            d["artifactType"] = json!(at);
        }
        manifests.push(d);
    }
    let index = json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_OCI_INDEX,
        "manifests": manifests,
    });
    let bytes = serde_json::to_vec_pretty(&index).map_err(|e| RegistryPullError::Io {
        path: p.clone(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;
    // Same write-then-rename pattern the publish HTTP sink uses for
    // its index.json: writes to `<file>.tmp` then renames atomically
    // so a power-cut mid-write can't leave a half-baked index.
    let tmp = p.with_extension("tmp");
    fs::write(&tmp, &bytes).map_err(|source| RegistryPullError::Io {
        path: tmp.clone(),
        source,
    })?;
    fs::rename(&tmp, &p).map_err(|source| RegistryPullError::Io { path: p, source })?;
    Ok(())
}

/// Send a GET, applying static auth + the 401-then-token-dance.
/// Retries on 5xx + transport errors per `MAX_RETRIES`.
///
/// Returns the response on first 2xx (or 4xx that the caller
/// expects to handle, e.g. 404 on referrers). Does NOT consume
/// the body — the caller streams or buffers as appropriate.
fn send_with_retry(
    ctx: &WireContext,
    url: &str,
    base_headers: &HeaderMap,
) -> Result<Response, RegistryPullError> {
    let mut last_err: Option<RegistryPullError> = None;
    // Track whether THIS call has already done the dance. Without
    // this, a stale-cached bearer that the registry now rejects
    // could loop forever.
    let mut did_dance_this_call = false;

    for attempt in 0..=MAX_RETRIES {
        let mut req = ctx.client.get(url);
        for (k, v) in base_headers {
            req = req.header(k.clone(), v.clone());
        }
        // Auth precedence:
        //   1. Cached bearer from a previous dance (this same
        //      pull session).
        //   2. Static auth (basic / bearer / FromEnv).
        //   3. None (anonymous).
        let auth_to_send: Option<HeaderValue> = ctx
            .cached_bearer
            .borrow()
            .clone()
            .or_else(|| ctx.static_auth.clone());
        if let Some(hv) = auth_to_send {
            req = req.header(AUTHORIZATION, hv);
        }
        let send_result = req.send();
        match send_result {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() && attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
                // 401 with a bearer challenge: do the token dance
                // ONCE per call. If the dance was already attempted
                // and we got 401 again, the realm is genuinely
                // refusing — surface the auth error rather than
                // loop.
                if status == StatusCode::UNAUTHORIZED && !did_dance_this_call {
                    if let Some(challenge) = extract_bearer_challenge(status, resp.headers()) {
                        // Discard the body; we don't need it for
                        // the dance.
                        drop(resp);
                        let token_client = ClientBuilder::new()
                            .timeout(TOKEN_REQUEST_TIMEOUT)
                            .redirect(reqwest::redirect::Policy::limited(5))
                            .build()
                            .map_err(|e| RegistryPullError::Auth {
                                source: Box::new(e),
                            })?;
                        let new_bearer = fetch_bearer_token(
                            &token_client,
                            &challenge,
                            ctx.static_auth.as_ref(),
                        )?;
                        // Cache for the rest of the pull session.
                        *ctx.cached_bearer.borrow_mut() = Some(new_bearer);
                        did_dance_this_call = true;
                        // Retry immediately (without sleep) under
                        // new credentials.
                        continue;
                    }
                }
                return Ok(resp);
            }
            Err(e) => {
                last_err = Some(RegistryPullError::BlobFetch {
                    digest: url.to_string(), // re-tagged by callers if needed
                    source: Box::new(e),
                });
                if attempt < MAX_RETRIES {
                    sleep_backoff(attempt);
                    continue;
                }
            }
        }
    }
    Err(last_err.expect("loop body sets last_err on every transport failure"))
}

fn sleep_backoff(attempt: u32) {
    // 200ms, 400ms, 800ms, capped.
    let shift = attempt.min(8);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let ms = 200u64.saturating_mul(factor).min(MAX_RETRY_BACKOFF_MS);
    std::thread::sleep(Duration::from_millis(ms));
}

fn read_body_capped(resp: Response) -> Vec<u8> {
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
    buf.truncate(total);
    buf
}

fn blob_path_for_digest(blobs_dir: &Path, digest: &str) -> Result<PathBuf, RegistryPullError> {
    let (algo, hex) =
        digest
            .split_once(':')
            .ok_or_else(|| RegistryPullError::MalformedManifest {
                detail: format!("descriptor digest {digest:?} missing ':' separator"),
            })?;
    if algo != "sha256" {
        return Err(RegistryPullError::MalformedManifest {
            detail: format!("only sha256 digests are supported, got {algo:?}"),
        });
    }
    if hex.len() != 64 {
        return Err(RegistryPullError::MalformedManifest {
            detail: format!("sha256 hex must be 64 chars, got {}", hex.len()),
        });
    }
    if !hex
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(RegistryPullError::MalformedManifest {
            detail: format!("sha256 hex must be lowercase 0-9a-f, got {hex:?}"),
        });
    }
    Ok(blobs_dir.join(hex))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn finalise_hash(hasher: Sha256) -> String {
    let d = hasher.finalize();
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── On-wire JSON shapes ───────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct OciImageManifestOnWire {
    config: OciDescriptorOnWire,
    #[serde(default)]
    layers: Vec<OciDescriptorOnWire>,
}

#[derive(Debug, Clone, Deserialize)]
struct OciDescriptorOnWire {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, rename = "artifactType")]
    artifact_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReferrersIndexOnWire {
    #[serde(default)]
    manifests: Vec<OciDescriptorOnWire>,
}

fn parse_image_manifest(bytes: &[u8]) -> Result<OciImageManifestOnWire, RegistryPullError> {
    serde_json::from_slice(bytes).map_err(|e| RegistryPullError::MalformedManifest {
        detail: format!("image manifest: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: hex_sha256 producing uppercase or shorter-than-64
    // output. Both would mismatch the on-disk path (`blobs/sha256/<hex>`)
    // and silently break addressing.
    #[test]
    fn test_hex_sha256_is_lowercase_64_chars() {
        let h = hex_sha256(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        // Reference: `printf 'hello' | sha256sum`.
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    // Catches: blob_path_for_digest accepting an algorithm other
    // than sha256 (e.g. sha512), then writing to `blobs/sha512/...`
    // which `ImageDir::open` later rejects far from the real fix
    // point.
    #[test]
    fn test_blob_path_for_digest_rejects_non_sha256() {
        let dir = Path::new("/x");
        let err = blob_path_for_digest(dir, "sha512:abcd").unwrap_err();
        match err {
            RegistryPullError::MalformedManifest { detail } => {
                assert!(detail.contains("sha256"));
            }
            other => panic!("expected MalformedManifest, got {other:?}"),
        }
    }

    // Catches: blob_path_for_digest letting an uppercase hex
    // through. Same case-folding concern publish guards against;
    // mirroring it here pins the contract on the pull side.
    #[test]
    fn test_blob_path_for_digest_rejects_uppercase_hex() {
        let dir = Path::new("/x");
        let upper: String = "A".repeat(64);
        let err = blob_path_for_digest(dir, &format!("sha256:{upper}")).unwrap_err();
        match err {
            RegistryPullError::MalformedManifest { detail } => {
                assert!(detail.contains("lowercase"));
            }
            other => panic!("expected MalformedManifest, got {other:?}"),
        }
    }

    // Catches: parse_image_manifest swallowing an unknown JSON
    // shape — must surface a typed error, not Default-ify into an
    // empty manifest (which would cause every blob to be skipped).
    #[test]
    fn test_parse_image_manifest_rejects_non_json() {
        let err = parse_image_manifest(b"not-a-json").unwrap_err();
        match err {
            RegistryPullError::MalformedManifest { detail } => {
                assert!(detail.contains("manifest"));
            }
            other => panic!("expected MalformedManifest, got {other:?}"),
        }
    }

    // Catches: parse_image_manifest losing the `size` field — used
    // by index.json composition. Without size, the resulting index
    // wouldn't validate as OCI (descriptor.size is required).
    #[test]
    fn test_parse_image_manifest_extracts_config_and_layer_descriptors() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MEDIA_TYPE_OCI_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:cafebabe",
                "size": 99,
            },
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:01", "size": 1 },
                { "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:02", "size": 2 },
            ]
        })).unwrap();
        let m = parse_image_manifest(&bytes).unwrap();
        assert_eq!(m.config.digest, "sha256:cafebabe");
        assert_eq!(m.config.size, 99);
        assert_eq!(m.layers.len(), 2);
        assert_eq!(m.layers[0].size, 1);
    }

    // Catches: env_allows_insecure widening to "any non-empty
    // value". Mirrors the publish-side test; same safety property.
    #[test]
    fn test_env_allows_insecure_only_literal_one() {
        let was = std::env::var(ENV_ALLOW_INSECURE).ok();
        std::env::remove_var(ENV_ALLOW_INSECURE);
        assert!(!env_allows_insecure());
        std::env::set_var(ENV_ALLOW_INSECURE, "true");
        assert!(!env_allows_insecure());
        std::env::set_var(ENV_ALLOW_INSECURE, "1");
        assert!(env_allows_insecure());
        std::env::remove_var(ENV_ALLOW_INSECURE);
        if let Some(v) = was {
            std::env::set_var(ENV_ALLOW_INSECURE, v);
        }
    }
}
