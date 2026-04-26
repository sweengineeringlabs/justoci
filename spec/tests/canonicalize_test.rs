//! JCS canonicalisation + spec hash tests.

use std::fs;
use std::path::PathBuf;

use spec::{canonical_bytes, parse_and_validate_str, spec_hash};
use tempfile::TempDir;

fn staged(spec_text: &str, files: &[&str]) -> (String, PathBuf) {
    let dir = TempDir::new().unwrap();
    for f in files {
        let target = dir.path().join(f);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&target, b"").unwrap();
    }
    let path = dir.path().to_path_buf();
    std::mem::forget(dir);
    (spec_text.to_string(), path)
}

const SPEC_A: &str = r#"
spec_version = "0"
id           = "stable:1"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"
"#;

/// Same spec parsed twice → identical hash.
///
/// Bug it catches: a hasher that pulled in a timestamp, a process
/// id, or any other non-deterministic input would produce different
/// hashes for the same file across runs — invalidating the entire
/// SLSA reproducibility claim.
#[test]
fn test_spec_hash_is_deterministic_across_parses() {
    let (text, dir) = staged(SPEC_A, &["blob.bin"]);
    let spec1 = parse_and_validate_str(&text, dir.clone()).unwrap();
    let spec2 = parse_and_validate_str(&text, dir).unwrap();
    let h1 = spec_hash(&spec1).unwrap();
    let h2 = spec_hash(&spec2).unwrap();
    assert_eq!(h1, h2, "same spec must hash identically across parses");
}

/// Reformatting whitespace doesn't change the hash.
///
/// Bug it catches: a "hash the raw TOML bytes" implementation
/// would give different hashes for semantically-identical specs
/// that differ only in indentation. JCS canonicalisation normalises
/// these away.
#[test]
fn test_spec_hash_ignores_whitespace_reformatting() {
    let original = SPEC_A;
    let reformatted = r#"
spec_version="0"
id="stable:1"
kind="raw_image"
[[layers]]
source="blob.bin"
media_type="application/octet-stream"
"#;
    let (text_a, dir_a) = staged(original, &["blob.bin"]);
    let (text_b, dir_b) = staged(reformatted, &["blob.bin"]);

    let spec_a = parse_and_validate_str(&text_a, dir_a).unwrap();
    let spec_b = parse_and_validate_str(&text_b, dir_b).unwrap();

    assert_eq!(spec_hash(&spec_a).unwrap(), spec_hash(&spec_b).unwrap());
}

/// Reordering keys doesn't change the hash (JCS sorts keys).
#[test]
fn test_spec_hash_ignores_key_order() {
    let order_a = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"
"#;
    let order_b = r#"
kind         = "raw_image"
id           = "x:1"
spec_version = "0"

[[layers]]
media_type = "application/octet-stream"
source     = "blob.bin"
"#;
    let (text_a, dir_a) = staged(order_a, &["blob.bin"]);
    let (text_b, dir_b) = staged(order_b, &["blob.bin"]);

    let spec_a = parse_and_validate_str(&text_a, dir_a).unwrap();
    let spec_b = parse_and_validate_str(&text_b, dir_b).unwrap();

    assert_eq!(spec_hash(&spec_a).unwrap(), spec_hash(&spec_b).unwrap());
}

/// Different content → different hash.
///
/// Bug it catches: a hasher that swallowed differences (e.g. only
/// hashed the spec_version) would let an attacker swap layer media
/// types without detection.
#[test]
fn test_spec_hash_differs_when_id_changes() {
    let a = SPEC_A;
    let b = SPEC_A.replace(r#"id           = "stable:1""#, r#"id           = "stable:2""#);
    let (text_a, dir_a) = staged(a, &["blob.bin"]);
    let (text_b, dir_b) = staged(&b, &["blob.bin"]);

    let spec_a = parse_and_validate_str(&text_a, dir_a).unwrap();
    let spec_b = parse_and_validate_str(&text_b, dir_b).unwrap();

    assert_ne!(spec_hash(&spec_a).unwrap(), spec_hash(&spec_b).unwrap());
}

/// Spec hash uses the OCI digest format (`sha256:<hex>`).
///
/// Bug it catches: a custom hash format would force every downstream
/// consumer to learn it. Anchoring on `cas::Digest`'s `Display`
/// ensures the hash drops straight into manifests, SLSA statements,
/// and registry calls without re-encoding.
#[test]
fn test_spec_hash_format_is_oci_digest() {
    let (text, dir) = staged(SPEC_A, &["blob.bin"]);
    let spec = parse_and_validate_str(&text, dir).unwrap();
    let hash = spec_hash(&spec).unwrap();
    let s = hash.to_string();
    assert!(s.starts_with("sha256:"), "expected sha256:... form, got {s}");
    assert_eq!(s.len(), "sha256:".len() + 64);
}

/// Canonical bytes are valid JSON.
///
/// Bug it catches: JCS output that produced invalid JSON (e.g. by
/// fumbling escape sequences) would break any downstream consumer
/// that tries to parse the SLSA-statement subject.
#[test]
fn test_canonical_bytes_are_valid_json() {
    let (text, dir) = staged(SPEC_A, &["blob.bin"]);
    let spec = parse_and_validate_str(&text, dir).unwrap();
    let bytes = canonical_bytes(&spec).unwrap();
    let _v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("JCS output must be valid JSON");
}

