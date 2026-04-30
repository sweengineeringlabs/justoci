//! Referrer-content propagation test.
//!
//! Bug it catches: a publish that pushes referrer MANIFESTS but
//! drops their config + layer blobs (a manifest is just a
//! descriptor pointing at a config + layers; the blobs themselves
//! must also land at the destination, or a verifier resolving the
//! referrer manifest 404s on its layers).
//!
//! Verified for the HTTP sink (filesystem assertions) and the
//! Registry sink (httpmock observability).

#[path = "common/mod.rs"]
mod common;

use std::env;
use std::fs;
use std::sync::{Mutex, MutexGuard, OnceLock};

use httpmock::prelude::*;
use httpmock::Method::HEAD;
use oci_publish::{publish, ImageDir, PublishSink};

use common::{Fixture, Referrer};

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Catches: HTTP-sink publish dropping referrer config / layer
/// blobs. The manifest could land but the blobs it references
/// would 404, breaking SLSA / SBOM lookup.
#[test]
fn test_publish_http_includes_referrer_config_and_layer_blobs() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let layout = Fixture::default()
        .with_referrer(Referrer {
            config_bytes: br#"{"_type":"in-toto"}"#.to_vec(),
            layer_bytes: b"slsa-statement-bytes".to_vec(),
            artifact_type: "application/vnd.in-toto+json".to_string(),
        })
        .build(src.path());

    let img = ImageDir::open(src.path()).unwrap();
    publish(
        &img,
        &PublishSink::Http {
            dest_dir: dst.path().to_path_buf(),
        },
    )
    .expect("publish must succeed");

    // The three blobs that comprise the referrer (manifest, config,
    // layer) must all be present at the destination.
    let r = &layout.referrers[0];
    for (label, digest) in [
        ("referrer manifest", &r.manifest_blob.digest),
        ("referrer config", &r.config_blob.digest),
        ("referrer layer", &r.layer_blob.digest),
    ] {
        let (_, hex) = digest.split_once(':').unwrap();
        let path = dst.path().join("blobs").join("sha256").join(hex);
        assert!(
            path.is_file(),
            "{label} blob {digest} must be present in dest at {path:?}",
        );
        let dst_bytes = fs::read(&path).unwrap();
        let src_bytes = fs::read(src.path().join("blobs").join("sha256").join(hex)).unwrap();
        assert_eq!(
            dst_bytes, src_bytes,
            "{label} blob {digest} bytes diverged between src and dst",
        );
    }
}

/// Catches: Registry-sink publish that pushes the referrer manifest
/// but skips its config + layer blob uploads. The manifest would
/// land at /manifests/<digest> with a 200 HEAD on the manifest
/// itself, but the layers it references would 404 — the OCI
/// referrers API consumer would see "found a referrer" but couldn't
/// actually pull its content.
#[test]
fn test_publish_registry_uploads_every_referrer_blob() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let src = tempfile::tempdir().unwrap();
    let layout = Fixture::default()
        .with_referrer(Referrer {
            config_bytes: br#"{"_type":"in-toto"}"#.to_vec(),
            layer_bytes: b"slsa-statement-bytes".to_vec(),
            artifact_type: "application/vnd.in-toto+json".to_string(),
        })
        .with_referrer(Referrer {
            config_bytes: br#"{"sbom":"cyclonedx"}"#.to_vec(),
            layer_bytes: b"sbom-bytes".to_vec(),
            artifact_type: "application/vnd.cyclonedx+json".to_string(),
        })
        .build(src.path());
    let img = ImageDir::open(src.path()).unwrap();

    let server = MockServer::start();
    let repo = "acme/with-2-referrers";
    let tag = "v1";

    // HEAD all blobs → 404; POST + PUT succeed.
    server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/blobs/sha256:"));
        then.status(404);
    });
    server.mock(|when, then| {
        when.method(HEAD)
            .path_contains(format!("/v2/{repo}/manifests/sha256:"));
        then.status(404);
    });
    server.mock(|when, then| {
        when.method(POST).path(format!("/v2/{repo}/blobs/uploads/"));
        then.status(202)
            .header("location", format!("/v2/{repo}/blobs/uploads/sess"))
            .body("");
    });
    let put_blob_mock = server.mock(|when, then| {
        when.method(PUT)
            .path(format!("/v2/{repo}/blobs/uploads/sess"));
        then.status(201).body("");
    });
    server.mock(|when, then| {
        when.method(PUT)
            .path_contains(format!("/v2/{repo}/manifests/"));
        then.status(201).body("");
    });

    publish(
        &img,
        &PublishSink::Registry {
            registry: format!("127.0.0.1:{}", server.port()),
            repository: repo.to_string(),
            tag: tag.to_string(),
            auth: None,
        },
    )
    .expect("publish must succeed");

    // Expected non-manifest blob count:
    //   * 2 primary layers + 1 primary config = 3
    //   * each referrer: 1 layer + 1 config = 2 each
    //   * 2 referrers = 4
    //   * total = 7
    let primary_non_manifest = layout.layers.len() + 1;
    let per_referrer_non_manifest = 2; // layer + config, the manifest goes via /manifests
    let expected_blob_uploads =
        primary_non_manifest + layout.referrers.len() * per_referrer_non_manifest;

    assert_eq!(
        put_blob_mock.hits(),
        expected_blob_uploads,
        "every referrer's config and layer must be PUT as a blob upload — got {} hits, expected {}",
        put_blob_mock.hits(),
        expected_blob_uploads,
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}
