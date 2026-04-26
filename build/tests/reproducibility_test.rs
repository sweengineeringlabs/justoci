//! Production-Guarantees-§2: same Spec + same source files → same
//! manifest digest. Bit-identical layer / config / manifest bytes.
//!
//! This is THE critical test. If it fails, the SLSA provenance
//! statement consumers attach to the artifact is meaningless because
//! re-running the build produces a different artifact identity.

mod common;

use std::collections::BTreeSet;
use std::fs;

use oci_build::build;

#[test]
fn test_two_builds_of_same_spec_produce_identical_manifest_digest() {
    let work = tempfile::TempDir::new().unwrap();
    // Both builds read the SAME source files in the SAME staging
    // dir. Re-staging would touch mtimes; this test isolates the
    // build pipeline's determinism, not the staging script's.
    let fx = common::stage_vm_image_fixture(work.path());
    let toml_text = common::vm_image_toml(&fx);

    let spec_a = common::parse_spec(&toml_text, work.path());
    let spec_b = common::parse_spec(&toml_text, work.path());

    let out_a = work.path().join("a");
    let out_b = work.path().join("b");

    let res_a = build(&spec_a, &out_a).expect("build a");
    let res_b = build(&spec_b, &out_b).expect("build b");

    assert_eq!(
        res_a.manifest_digest, res_b.manifest_digest,
        "Production-Guarantees-§2: manifest digests must match across re-runs"
    );
    assert_eq!(
        res_a.config_digest, res_b.config_digest,
        "config digest must match too — config bytes must be deterministic"
    );
    assert_eq!(
        res_a.layer_digests, res_b.layer_digests,
        "layer digests must match in order and content"
    );

    // Belt-and-braces: the on-disk blob filenames in each output
    // must form the same set. If the digests above match, this is
    // implied — but a regression in atomic write could leave different
    // blobs even with matching descriptors.
    let blob_set = |dir: &std::path::Path| -> BTreeSet<String> {
        fs::read_dir(dir.join("blobs").join("sha256"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|d| d.file_name().to_string_lossy().to_string())
            .collect()
    };
    assert_eq!(
        blob_set(&out_a),
        blob_set(&out_b),
        "blob filenames (= digests) must match across re-runs"
    );
}

#[test]
fn test_two_builds_produce_byte_identical_manifest_blobs() {
    // Bug this would catch: a non-determinism in the manifest JSON
    // bytes that the digest equality test (above) would already
    // catch — but this test localises the failure to "the manifest
    // bytes differ" so the investigation starts at the right place.
    let work = tempfile::TempDir::new().unwrap();
    let fx = common::stage_vm_image_fixture(work.path());
    let toml_text = common::vm_image_toml(&fx);

    let spec = common::parse_spec(&toml_text, work.path());
    let out_a = work.path().join("a");
    let out_b = work.path().join("b");

    let res_a = build(&spec, &out_a).unwrap();
    let res_b = build(&spec, &out_b).unwrap();

    let bytes_a = fs::read(out_a.join("blobs").join("sha256").join(res_a.manifest_digest.hex()))
        .unwrap();
    let bytes_b = fs::read(out_b.join("blobs").join("sha256").join(res_b.manifest_digest.hex()))
        .unwrap();
    assert_eq!(bytes_a, bytes_b, "manifest JSON bytes must be identical");
}
