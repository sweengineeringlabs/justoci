//! Idempotency test for the HTTP sink — publishing twice must
//! produce a destination directory that's bit-identical to the
//! first publish, with the second pass reporting EVERY blob as
//! "skipped" rather than "pushed."

#[path = "common/mod.rs"]
mod common;

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use oci_publish::{publish, ImageDir, PublishSink};

use common::Fixture;

/// Catches: a publish that re-writes blobs unconditionally — this
/// would inflate disk I/O on every CI run, defeat the resumability
/// guarantee from spec-v0 §6 ("Publish is per-blob with retries.
/// Resumable on transient failures via the registry's content-
/// addressed semantics: re-pushing an existing blob is a no-op.")
#[test]
fn test_publish_http_twice_skips_every_blob_on_second_pass() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let layout = Fixture::default().build(src.path());

    let img = ImageDir::open(src.path()).unwrap();
    let sink = PublishSink::Http {
        dest_dir: dst.path().to_path_buf(),
    };

    let _ = publish(&img, &sink).expect("first publish must succeed");
    let outcome2 = publish(&img, &sink).expect("second publish must succeed");

    // Every blob the fixture has must be reported as skipped.
    let expected: HashSet<String> = layout.all_blob_digests().into_iter().collect();
    let skipped: HashSet<String> = outcome2.digests_skipped.iter().cloned().collect();
    assert_eq!(
        skipped, expected,
        "every blob must be skipped on republish, got pushed={:?}, skipped={:?}",
        outcome2.digests_pushed, outcome2.digests_skipped,
    );
    assert!(
        outcome2.digests_pushed.is_empty(),
        "republish must push nothing, got: {:?}",
        outcome2.digests_pushed,
    );
    assert_eq!(
        outcome2.bytes_uploaded, 0,
        "republish must not transfer any bytes",
    );
}

/// Catches: publishing twice and ending up with a bit-different
/// destination directory (e.g. timestamp drift in index.json,
/// different blob ordering on disk). The OCI image dir is
/// content-addressed; bit-identical re-publish is the contract.
#[test]
fn test_publish_http_twice_produces_byte_identical_dest_dir() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    Fixture::default().build(src.path());

    let img = ImageDir::open(src.path()).unwrap();
    let sink = PublishSink::Http {
        dest_dir: dst.path().to_path_buf(),
    };

    let _ = publish(&img, &sink).unwrap();
    let snapshot1 = snapshot_dir(dst.path());
    let _ = publish(&img, &sink).unwrap();
    let snapshot2 = snapshot_dir(dst.path());

    assert_eq!(
        snapshot1, snapshot2,
        "republish must leave the destination bit-identical",
    );
}

/// Recursively read every file under `root` into a `(relative-path,
/// bytes)` pair. Sorted for deterministic comparison. Excludes
/// any temp files left over from a still-in-flight rename — those
/// are the publish layer's transient state, not a stable artifact.
fn snapshot_dir(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    walk(root, root, &mut out);
    // Filter out any leftover temp files; their names embed
    // process id + nanos and so wouldn't match across runs even
    // for an idempotent publisher.
    out.retain(|(name, _)| !name.contains(".tmp-oci-publish"));
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk(root: &Path, here: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let entries = match fs::read_dir(here) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let kind = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if kind.is_dir() {
            walk(root, &path, out);
        } else if kind.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&path).unwrap();
            out.push((rel, bytes));
        }
    }
}
