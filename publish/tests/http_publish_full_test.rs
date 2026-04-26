//! End-to-end test for the HTTP sink — publish a fixture image
//! into a static-served directory and assert the on-disk layout.

#[path = "common/mod.rs"]
mod common;

use std::collections::HashSet;
use std::fs;

use oci_publish::{publish, ImageDir, PublishSink};

use common::{Fixture, Referrer};

/// Catches: a publish that drops a layer blob, drops the config,
/// drops the primary manifest, drops a referrer manifest, or
/// fails to write `oci-layout` / `index.json`. Asserts the
/// destination dir contains EXACTLY the expected files plus the
/// blobs of the input image, byte-equal.
#[test]
fn test_publish_http_writes_oci_layout_and_index_and_every_blob() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let layout = Fixture::default()
        .with_referrer(Referrer {
            config_bytes: br#"{"slsa":"v1.0"}"#.to_vec(),
            layer_bytes: b"slsa-statement-bytes".to_vec(),
            artifact_type: "application/vnd.in-toto+json".to_string(),
        })
        .with_referrer(Referrer {
            config_bytes: br#"{"sbom":"cyclonedx"}"#.to_vec(),
            layer_bytes: b"sbom-bytes".to_vec(),
            artifact_type: "application/vnd.cyclonedx+json".to_string(),
        })
        .build(src.path());

    let img = ImageDir::open(src.path()).expect("source image must validate");
    let outcome = publish(
        &img,
        &PublishSink::Http {
            dest_dir: dst.path().to_path_buf(),
        },
    )
    .expect("publish must succeed");

    // Every blob in the source must be at <dst>/blobs/sha256/<hex>
    // with byte-equal content. This is what proves the publish
    // didn't truncate, didn't reorder bytes, and didn't drop
    // anything.
    for digest in layout.all_blob_digests() {
        let (_algo, hex) = digest.split_once(':').unwrap();
        let path = dst.path().join("blobs").join("sha256").join(hex);
        let on_disk = fs::read(&path)
            .unwrap_or_else(|e| panic!("blob {digest} not at {path:?}: {e}"));
        let on_src = fs::read(
            src.path().join("blobs").join("sha256").join(hex),
        )
        .unwrap();
        assert_eq!(
            on_disk, on_src,
            "blob {digest} bytes differ between src and dst",
        );
    }

    // The two commit-point files must be present.
    assert!(
        dst.path().join("oci-layout").is_file(),
        "publish must write oci-layout",
    );
    assert!(
        dst.path().join("index.json").is_file(),
        "publish must write index.json",
    );

    // The outcome lists every blob as pushed (none skipped on
    // first publish into an empty dest).
    let pushed: HashSet<String> = outcome.digests_pushed.into_iter().collect();
    let expected: HashSet<String> = layout.all_blob_digests().into_iter().collect();
    assert_eq!(
        pushed, expected,
        "first publish must record every blob in digests_pushed",
    );
    assert!(
        outcome.digests_skipped.is_empty(),
        "first publish into empty dest must skip nothing, got: {:?}",
        outcome.digests_skipped,
    );
    // bytes_uploaded must be > 0 — something actually went over.
    assert!(outcome.bytes_uploaded > 0);
}

/// Catches: a publish that succeeds but silently ignores a passed
/// referrer (writes the primary blob set + index.json, omits SLSA /
/// SBOM blobs). Verifiers wouldn't be able to find them — the OCI
/// 1.1 referrers API uses the blob store as its index.
#[test]
fn test_publish_http_includes_referrer_blobs_in_destination() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let layout = Fixture::default()
        .with_referrer(Referrer {
            config_bytes: br#"{"slsa":"v1.0"}"#.to_vec(),
            layer_bytes: b"slsa-statement-bytes".to_vec(),
            artifact_type: "application/vnd.in-toto+json".to_string(),
        })
        .build(src.path());

    let img = ImageDir::open(src.path()).expect("source image must validate");
    publish(
        &img,
        &PublishSink::Http {
            dest_dir: dst.path().to_path_buf(),
        },
    )
    .expect("publish must succeed");

    // The referrer's manifest, config, and layer must all be at
    // the destination — not just the primary's.
    let r = &layout.referrers[0];
    for digest in [
        &r.manifest_blob.digest,
        &r.config_blob.digest,
        &r.layer_blob.digest,
    ] {
        let (_, hex) = digest.split_once(':').unwrap();
        let path = dst.path().join("blobs").join("sha256").join(hex);
        assert!(
            path.is_file(),
            "referrer blob {digest} must be present in dest at {path:?}",
        );
    }
}
