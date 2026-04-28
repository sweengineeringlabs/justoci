//! Atomicity test for the HTTP sink — assert that a publish which
//! fails mid-copy does NOT leave a half-published image visible to
//! consumers. Specifically: `index.json` must be the LAST thing
//! written, AFTER all blobs are present.
//!
//! Bug it catches: an impl that wrote `index.json` first (or wrote
//! it speculatively before all blobs were copied) would expose a
//! half-state where a consumer sees `index.json` claiming N blobs
//! but only M < N of them are on disk. The OCI image consumer would
//! then fail with a confusing mid-stream "missing blob" error.

#[path = "common/mod.rs"]
mod common;

use std::fs;

use oci_publish::{publish, ImageDir, PublishSink};

use common::Fixture;

/// Force a mid-copy failure by deleting one of the source layer
/// blobs after `ImageDir::open` validated everything was present
/// but before `publish` runs the copy. The publish errors; we
/// assert the partial state at the destination is "no index.json"
/// rather than "index.json + missing blobs."
#[test]
fn test_publish_http_index_absent_when_blob_copy_fails_midway() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let layout = Fixture::default().build(src.path());

    // Open + validate while everything is present.
    let img = ImageDir::open(src.path()).expect("source image must validate");

    // Now sabotage: remove one of the layer blobs from the source
    // dir. The publish will:
    //   * write oci-layout (small file, succeeds)
    //   * walk referenced_blobs, copy the first few, then hit a
    //     File::open error on the missing one
    //   * NEVER reach the final atomic index.json write.
    let (_algo, hex) = layout.layers[0].digest.split_once(':').unwrap();
    let to_delete = src.path().join("blobs").join("sha256").join(hex);
    fs::remove_file(&to_delete).expect("test setup: delete sabotaged layer");

    let result = publish(
        &img,
        &PublishSink::Http {
            dest_dir: dst.path().to_path_buf(),
        },
    );
    assert!(
        result.is_err(),
        "publish with a missing source blob must error, got: {:?}",
        result,
    );

    // The safety property: index.json is NOT visible. Without this
    // property, a consumer reading the dst dir would see
    // index.json claiming a layer that's not on disk, and fail
    // mid-stream rather than at "no image here."
    assert!(
        !dst.path().join("index.json").exists(),
        "publish failure must NOT leave a partial index.json — that exposes a half-published image to consumers",
    );

    // It's fine for some blobs to be already copied (they're
    // content-addressed, a retry will skip them).
    let blobs_dir = dst.path().join("blobs").join("sha256");
    if blobs_dir.exists() {
        // We don't assert anything about the count; it's
        // implementation-defined how many blobs land before the
        // failure. The contract is just "no index.json yet."
        let _ = fs::read_dir(&blobs_dir);
    }
}

/// Catches: an impl that writes index.json speculatively at the
/// START of publish (or as a side-effect of the first blob copy).
/// Stronger version of the previous test: by failing on the FIRST
/// blob copy (not midway), we prove index.json isn't pre-emitted
/// before any blob lands.
#[test]
fn test_publish_http_index_absent_when_first_blob_unreadable() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let layout = Fixture::default().build(src.path());

    let img = ImageDir::open(src.path()).unwrap();

    // Delete every layer + config blob so the first copy fails.
    // The `referenced_blobs` order puts layers first; deleting
    // the first one guarantees the first iteration of the copy
    // loop errors.
    for digest in [
        &layout.layers[0].digest,
        &layout.layers[1].digest,
        &layout.config.digest,
    ] {
        let (_, hex) = digest.split_once(':').unwrap();
        fs::remove_file(src.path().join("blobs").join("sha256").join(hex))
            .expect("test setup: delete blob");
    }

    let result = publish(
        &img,
        &PublishSink::Http {
            dest_dir: dst.path().to_path_buf(),
        },
    );
    assert!(result.is_err());
    assert!(
        !dst.path().join("index.json").exists(),
        "first-blob failure must NOT leave a speculative index.json",
    );
}
