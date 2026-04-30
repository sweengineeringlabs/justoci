//! Registry sink — happy-path wire test against httpmock-faked
//! OCI Distribution v2 endpoint.
//!
//! Asserts the publish makes the right HEAD/PUT calls in the right
//! order. The registry-fixture mocks:
//!   * HEAD /v2/<repo>/blobs/<digest> → 404 ("not present, please upload")
//!   * POST /v2/<repo>/blobs/uploads/ → 202 with `Location:` header
//!   * PUT  <Location>?digest=<digest> → 201 ("blob created")
//!   * HEAD /v2/<repo>/manifests/<digest> → 404 (referrers)
//!   * PUT  /v2/<repo>/manifests/<tag-or-digest> → 201

#[path = "common/mod.rs"]
mod common;

use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};

use httpmock::prelude::*;
use httpmock::Method::HEAD;
use oci_publish::{publish, ImageDir, PublishSink, RegistryAuth};

use common::{Fixture, Referrer};

/// Serializes tests in this file (and any sibling registry test
/// files in this package) that mutate `JUSTOCI_ALLOW_INSECURE`.
/// `cargo test` runs tests in a single binary in parallel; without
/// this lock, two tests racing to set/unset the env var would flake.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Catches: a publish that sends EVERY blob unconditionally,
/// without consulting HEAD first. That would burn enormous
/// bandwidth on rebuilds where most layers are unchanged. The
/// HEAD-then-PUT skip-if-exists is THE production guarantee §6
/// behaviour; without it, `publish` is not "resumable on transient
/// failures".
///
/// Setup: a fixture with 2 layers + 1 config + 1 manifest. Mock:
///   * HEAD all-blobs → 404 (registry has nothing)
///   * POST upload init → 202 with Location
///   * PUT blob → 201
///   * PUT manifest → 201
///
/// Assert the HEAD count is exactly the non-manifest blob count
/// AND every blob got HEAD'd before any PUT.
#[test]
fn test_publish_registry_emits_head_before_put_for_every_non_manifest_blob() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let src = tempfile::tempdir().unwrap();
    let layout = Fixture::default().build(src.path());
    let img = ImageDir::open(src.path()).unwrap();

    let server = MockServer::start();
    let repo = "acme/example";
    let tag = "v1";

    // HEAD on every non-manifest blob returns 404 — registry has
    // nothing yet. That's the trigger to upload.
    let head_blob_mock = server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/blobs/sha256:"));
        then.status(404);
    });

    // POST /v2/<repo>/blobs/uploads/ → 202 + Location header.
    // The Location is per-upload-session unique; we use the same
    // mock url for every session for simplicity. Real registries
    // mint a UUID; the publish layer must re-use whatever they
    // hand back.
    let upload_url = format!("/v2/{repo}/blobs/uploads/abc-session");
    let post_init_mock = server.mock(|when, then| {
        when.method(POST).path(format!("/v2/{repo}/blobs/uploads/"));
        then.status(202)
            .header("location", upload_url.clone())
            .body("");
    });

    // PUT <Location>?digest=...&... → 201.
    let put_blob_mock = server.mock(|when, then| {
        when.method(PUT).path(upload_url.clone());
        then.status(201).body("");
    });

    // HEAD on referrer manifests — none in this fixture, so the
    // mock simply isn't invoked. Returning 404 is correct
    // either way.
    let _head_manifest_mock = server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/manifests/sha256:"));
        then.status(404);
    });

    // PUT /v2/<repo>/manifests/<tag> → 201.
    let put_manifest_mock = server.mock(|when, then| {
        when.method(PUT).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(201).body("");
    });

    let outcome = publish(
        &img,
        &PublishSink::Registry {
            registry: format!("127.0.0.1:{}", server.port()),
            repository: repo.to_string(),
            tag: tag.to_string(),
            auth: None,
        },
    )
    .expect("registry publish must succeed");

    // Non-manifest blobs = 2 layers + 1 config = 3.
    let non_manifest_count = layout.layers.len() + 1;
    assert_eq!(
        head_blob_mock.hits(),
        non_manifest_count,
        "every non-manifest blob must be HEAD'd before PUT — that's the skip-if-exists optimisation",
    );
    assert_eq!(
        post_init_mock.hits(),
        non_manifest_count,
        "every blob that 404'd on HEAD must trigger a POST upload init",
    );
    assert_eq!(
        put_blob_mock.hits(),
        non_manifest_count,
        "every initiated upload must be PUT to completion",
    );
    assert_eq!(
        put_manifest_mock.hits(),
        1,
        "primary manifest PUT must run exactly once",
    );

    // Outcome reports the right counters.
    assert_eq!(
        outcome.digests_skipped.len(),
        0,
        "first publish, registry has nothing, nothing should be skipped",
    );
    // pushed = 3 blobs + 1 manifest.
    assert_eq!(outcome.digests_pushed.len(), 4);
    // bytes_uploaded includes the manifest's bytes; just assert > 0.
    assert!(outcome.bytes_uploaded > 0);

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

/// Catches: a publish that fails to short-circuit when HEAD
/// reports the blob already exists. If the registry has all
/// layers, we should ONLY send the manifest PUT — every PUT-blob
/// sent in that scenario is wasted bandwidth.
#[test]
fn test_publish_registry_skips_blobs_already_present_at_head() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let src = tempfile::tempdir().unwrap();
    let layout = Fixture::default().build(src.path());
    let img = ImageDir::open(src.path()).unwrap();

    let server = MockServer::start();
    let repo = "acme/already-have-blobs";
    let tag = "v1";

    // HEAD all blobs returns 200 — registry already has them.
    let head_mock = server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/blobs/sha256:"));
        then.status(200).header("content-length", "0");
    });

    // POST init must NOT be called. We register it as a
    // catch-all "if you call me, the test fails" mock.
    let post_init_must_not_fire = server.mock(|when, then| {
        when.method(POST).path(format!("/v2/{repo}/blobs/uploads/"));
        then.status(202)
            .header("location", "/should-not-fire")
            .body("");
    });

    // Manifest PUT still fires.
    let put_manifest = server.mock(|when, then| {
        when.method(PUT).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(201).body("");
    });

    let outcome = publish(
        &img,
        &PublishSink::Registry {
            registry: format!("127.0.0.1:{}", server.port()),
            repository: repo.to_string(),
            tag: tag.to_string(),
            auth: None,
        },
    )
    .expect("registry publish must succeed when blobs already exist");

    let non_manifest_count = layout.layers.len() + 1;
    assert_eq!(
        head_mock.hits(),
        non_manifest_count,
        "HEAD must run for every non-manifest blob",
    );
    assert_eq!(
        post_init_must_not_fire.hits(),
        0,
        "blobs already present at HEAD must NOT trigger a POST upload — bandwidth waste",
    );
    assert_eq!(put_manifest.hits(), 1, "primary manifest still PUT");

    // Outcome reports skips.
    assert_eq!(
        outcome.digests_skipped.len(),
        non_manifest_count,
        "every non-manifest blob must land in digests_skipped, got: {:?}",
        outcome.digests_skipped,
    );
    // Manifest still pushed.
    assert_eq!(outcome.digests_pushed.len(), 1);

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

/// Catches: a publish that doesn't include `Authorization: Bearer
/// <token>` on its requests when `RegistryAuth::Bearer` is set.
/// Without this, every request to a private registry 401s and
/// the user gets a confusing "registry refused" error instead of
/// "auth misconfigured."
#[test]
fn test_publish_registry_sends_bearer_token_when_provided() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let src = tempfile::tempdir().unwrap();
    Fixture::default().build(src.path());
    let img = ImageDir::open(src.path()).unwrap();

    let server = MockServer::start();
    let repo = "acme/needs-auth";
    let tag = "v1";

    let upload_url = format!("/v2/{repo}/blobs/uploads/abc-session");
    let auth_token = "secret-bearer-token";
    let auth_header = format!("Bearer {auth_token}");

    // HEAD requires the auth header to match. If publish forgets
    // to send it, this mock won't match and the test fails on
    // "expected status 404, got 0 hits" (httpmock's catch-all is
    // a 404 not-matched, which on the publish layer surfaces as
    // RegistryRefused).
    let head_mock = server.mock(|when, then| {
        when.method(HEAD)
            .header("authorization", auth_header.clone())
            .path_contains(format!("/v2/{repo}/blobs/sha256:"));
        then.status(404);
    });

    server.mock(|when, then| {
        when.method(POST)
            .header("authorization", auth_header.clone())
            .path(format!("/v2/{repo}/blobs/uploads/"));
        then.status(202)
            .header("location", upload_url.clone())
            .body("");
    });
    server.mock(|when, then| {
        when.method(PUT)
            .header("authorization", auth_header.clone())
            .path(upload_url.clone());
        then.status(201).body("");
    });
    server.mock(|when, then| {
        when.method(PUT)
            .header("authorization", auth_header.clone())
            .path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(201).body("");
    });

    let result = publish(
        &img,
        &PublishSink::Registry {
            registry: format!("127.0.0.1:{}", server.port()),
            repository: repo.to_string(),
            tag: tag.to_string(),
            auth: Some(RegistryAuth::Bearer {
                token: auth_token.to_string(),
            }),
        },
    );

    assert!(
        result.is_ok(),
        "publish with bearer token must succeed when mock requires it; got: {:?}",
        result,
    );
    assert!(
        head_mock.hits() > 0,
        "the HEAD mock that requires Authorization: Bearer <token> must have matched at least once",
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

/// Catches: referrer-manifest blobs being silently dropped. SLSA /
/// SBOM / signature blobs MUST be pushed alongside the primary
/// artifact so OCI 1.1 verifiers can find them via the referrers
/// API. This is the contract from spec-v0.md:
/// "All three artefacts live as OCI 1.1 referrers of the main artifact".
#[test]
fn test_publish_registry_pushes_referrer_manifests_under_their_digest() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let src = tempfile::tempdir().unwrap();
    let layout = Fixture::default()
        .with_referrer(Referrer {
            config_bytes: br#"{"_type":"in-toto"}"#.to_vec(),
            layer_bytes: b"slsa-statement".to_vec(),
            artifact_type: "application/vnd.in-toto+json".to_string(),
        })
        .build(src.path());
    let img = ImageDir::open(src.path()).unwrap();

    let server = MockServer::start();
    let repo = "acme/with-referrer";
    let tag = "v1";

    let referrer_digest = layout.referrers[0].manifest_blob.digest.clone();

    server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/blobs/sha256:"));
        then.status(404);
    });
    server.mock(|when, then| {
        when.method(POST).path(format!("/v2/{repo}/blobs/uploads/"));
        then.status(202)
            .header("location", format!("/v2/{repo}/blobs/uploads/sess"))
            .body("");
    });
    server.mock(|when, then| {
        when.method(PUT)
            .path(format!("/v2/{repo}/blobs/uploads/sess"));
        then.status(201).body("");
    });
    server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/manifests/sha256:"));
        then.status(404);
    });

    // The KEY assertion: a PUT to /manifests/<referrer-digest>
    // must be observed. Without this, referrers are unreachable
    // for verifiers.
    let put_referrer = server.mock(|when, then| {
        when.method(PUT)
            .path(format!("/v2/{repo}/manifests/{referrer_digest}"));
        then.status(201).body("");
    });

    let put_primary = server.mock(|when, then| {
        when.method(PUT).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(201).body("");
    });

    let outcome = publish(
        &img,
        &PublishSink::Registry {
            registry: format!("127.0.0.1:{}", server.port()),
            repository: repo.to_string(),
            tag: tag.to_string(),
            auth: None,
        },
    )
    .expect("registry publish with referrer must succeed");

    assert_eq!(
        put_referrer.hits(),
        1,
        "referrer manifest must be PUT under its digest so OCI 1.1 referrers API finds it",
    );
    assert_eq!(put_primary.hits(), 1);

    // Outcome includes the referrer digest in pushed.
    assert!(
        outcome.digests_pushed.contains(&referrer_digest),
        "outcome.digests_pushed must include referrer manifest digest, got: {:?}",
        outcome.digests_pushed,
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}
