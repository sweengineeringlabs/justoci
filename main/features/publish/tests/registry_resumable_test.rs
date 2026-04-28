//! Resumability test for the registry sink.
//!
//! Bug it catches: a publish that fails on the Nth blob upload
//! and is retried by the operator must NOT re-upload the (N-1)
//! blobs that already landed. This is the production-guarantee
//! §6 contract: re-publish is a HEAD-driven no-op for already-
//! present blobs.
//!
//! Strategy: drive two `publish` calls back to back. On the
//! FIRST call, the mock for ONE specific blob's PUT returns 500,
//! so that blob's upload fails and the publish errors out. On
//! the SECOND call, the mock is reconfigured: every blob HEAD
//! that was successfully PUT in the first call now returns 200
//! (skip), and only the failed blob's HEAD returns 404.
//!
//! Assert: the second call's POST upload init count matches the
//! ONE remaining blob, not all of them.

#[path = "common/mod.rs"]
mod common;

use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};

use httpmock::prelude::*;
use httpmock::Method::HEAD;
use oci_publish::{publish, ImageDir, PublishSink};

use common::Fixture;

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Catches: a registry sink that uploads every blob unconditionally
/// on a retry, instead of consulting HEAD first. Without this, a
/// publish flake on a 2 GiB image forces the operator to re-upload
/// all 2 GiB on retry — which violates production guarantee §6.
#[test]
fn test_publish_registry_retry_only_uploads_blobs_not_yet_present() {
    let _g = env_lock();
    env::set_var("OCIMAGE_ALLOW_INSECURE", "1");

    let src = tempfile::tempdir().unwrap();
    let layout = Fixture::default().build(src.path());
    let img = ImageDir::open(src.path()).unwrap();

    // Pick a "stuck" blob whose upload fails the first time.
    // Use the SECOND layer (not the first) so the publish has
    // a chance to upload at least one blob successfully before
    // hitting the failure.
    let stuck_digest = layout.layers[1].digest.clone();
    let succeed_digests: Vec<String> = vec![
        layout.layers[0].digest.clone(),
        layout.config.digest.clone(),
    ];

    // ---- FIRST PUBLISH (will fail) ---------------------------------
    let server = MockServer::start();
    let repo = "acme/resumable";
    let tag = "v1";

    // HEAD for every blob → 404 the first time.
    server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/blobs/sha256:"));
        then.status(404);
    });

    // POST upload init: succeed for the "succeed" digests; 500
    // for the stuck one. We can't easily distinguish the digest
    // at POST init time (it's only on the PUT), so we let init
    // succeed for everything and 500 the PUT.
    let upload_url = format!("/v2/{repo}/blobs/uploads/sess");
    server.mock(|when, then| {
        when.method(POST).path(format!("/v2/{repo}/blobs/uploads/"));
        then.status(202)
            .header("location", upload_url.clone())
            .body("");
    });

    // PUT to the upload URL: 500 when the digest matches the stuck
    // one, 201 otherwise. The query string contains
    // `digest=<digest>`; httpmock's query_param matcher checks it.
    server.mock(|when, then| {
        when.method(PUT)
            .path(upload_url.clone())
            .query_param("digest", stuck_digest.clone());
        // After 1 retry, return 500 every time so the publish
        // gives up and surfaces an error.
        then.status(500).body("simulated transient failure");
    });
    server.mock(|when, then| {
        // Default branch for the other digests. Returns 201.
        // httpmock's matchers compose by inclusion — we list each
        // succeeding digest explicitly so the catch-all 500 above
        // doesn't shadow these.
        when.method(PUT)
            .path(upload_url.clone())
            .query_param("digest", succeed_digests[0].clone());
        then.status(201).body("");
    });
    server.mock(|when, then| {
        when.method(PUT)
            .path(upload_url.clone())
            .query_param("digest", succeed_digests[1].clone());
        then.status(201).body("");
    });

    // Manifest PUT: shouldn't fire on the failing run.
    server.mock(|when, then| {
        when.method(PUT).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(201).body("");
    });

    let registry = format!("127.0.0.1:{}", server.port());
    let sink = PublishSink::Registry {
        registry: registry.clone(),
        repository: repo.to_string(),
        tag: tag.to_string(),
        auth: None,
    };

    let first_result = publish(&img, &sink);
    assert!(
        first_result.is_err(),
        "first publish must fail (the stuck blob is mocked to 500)",
    );

    // ---- SECOND PUBLISH (retry, simulating the registry caching
    //      the blobs that succeeded the first time) -----------------
    //
    // We can't ask httpmock to return different 200/404 per blob
    // for the SECOND publish on the SAME server. The cleanest way
    // is to run the second publish against a FRESH server that's
    // been pre-configured to:
    //   * HEAD on `succeed_digests` → 200 (already there)
    //   * HEAD on `stuck_digest`    → 404 (still missing)
    //   * POST + PUT for the stuck digest → 201 (recovered)
    //   * PUT manifest              → 201
    //
    // This is structurally identical to the real-world retry,
    // because in the real world the registry's state IS what
    // distinguishes "first publish" from "retry" — a fresh
    // mock server with the right pre-configured 200/404s is the
    // honest model.

    let server2 = MockServer::start();
    let head_succeed_mocks: Vec<_> = succeed_digests
        .iter()
        .map(|d| {
            server2.mock(|when, then| {
                when.method(HEAD).path(format!("/v2/{repo}/blobs/{d}"));
                then.status(200).header("content-length", "0");
            })
        })
        .collect();
    let head_stuck_mock = server2.mock(|when, then| {
        when.method(HEAD)
            .path(format!("/v2/{repo}/blobs/{stuck_digest}"));
        then.status(404);
    });
    let post_init = server2.mock(|when, then| {
        when.method(POST).path(format!("/v2/{repo}/blobs/uploads/"));
        then.status(202)
            .header("location", upload_url.clone())
            .body("");
    });
    let put_stuck = server2.mock(|when, then| {
        when.method(PUT).path(upload_url.clone());
        then.status(201).body("");
    });
    let put_manifest = server2.mock(|when, then| {
        when.method(PUT).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(201).body("");
    });

    let registry2 = format!("127.0.0.1:{}", server2.port());
    let sink2 = PublishSink::Registry {
        registry: registry2,
        repository: repo.to_string(),
        tag: tag.to_string(),
        auth: None,
    };
    let outcome = publish(&img, &sink2)
        .expect("second publish must succeed — the stuck blob is now uploadable");

    // Every "already present" blob got HEAD'd and short-circuited.
    for m in &head_succeed_mocks {
        assert_eq!(
            m.hits(),
            1,
            "every previously-uploaded blob must be HEAD'd (and skipped)",
        );
    }
    assert_eq!(
        head_stuck_mock.hits(),
        1,
        "the previously-stuck blob must be HEAD'd",
    );

    // POST upload init must fire EXACTLY ONCE — only for the
    // recovered blob. If a regression makes the publish re-upload
    // all blobs, this jumps to 3.
    assert_eq!(
        post_init.hits(),
        1,
        "retry must only initiate uploads for blobs not yet present, got hits={} (expected 1)",
        post_init.hits(),
    );
    assert_eq!(put_stuck.hits(), 1);
    assert_eq!(put_manifest.hits(), 1);

    // Outcome reports the right counters.
    assert_eq!(
        outcome.digests_skipped.len(),
        succeed_digests.len(),
        "the previously-uploaded blobs must land in digests_skipped",
    );
    // pushed = stuck blob + manifest.
    assert_eq!(outcome.digests_pushed.len(), 2);

    env::remove_var("OCIMAGE_ALLOW_INSECURE");
}
