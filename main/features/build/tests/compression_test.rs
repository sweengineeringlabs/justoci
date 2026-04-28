//! Compression backends — gzip / zstd / none.
//!
//! Bugs these tests catch:
//!
//! - The `Compression` enum match silently picks `None` (so gzip /
//!   zstd never runs) — output bytes match the no-compression case
//!   and the digest never differs. Caught by the cross-mode digest
//!   inequality assertions.
//!
//! - The descriptor reports the digest of the UNCOMPRESSED bytes
//!   while the CAS holds the COMPRESSED bytes — a registry would
//!   accept the upload (the CAS wrote the right bytes for some
//!   digest) but every consumer would refuse to verify. Caught by
//!   the descriptor-digest-equals-CAS-blob assertion.

mod common;

use std::fs;
use std::path::Path;

use cas::{Algorithm, Digest};
use oci_build::build;

fn build_single_layer_spec_toml(blob_path: &Path, compression: &str) -> String {
    let media_type = match compression {
        "gzip" => "application/vnd.example.payload+gzip",
        "zstd" => "application/vnd.example.payload+zstd",
        "none" => "application/vnd.example.payload",
        _ => panic!("unsupported compression: {compression}"),
    };
    format!(
        r#"
spec_version = "0"
id = "x:1"
kind = "oci_artifact"

[[layers]]
source = "{blob}"
media_type = "{media_type}"
compression = "{compression}"
"#,
        blob = common::posix(blob_path),
    )
}

fn payload(n: usize) -> Vec<u8> {
    // Repetitive enough that gzip and zstd compress visibly; 16 KiB
    // produces compressed sizes well below the original.
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        v.push(((i * 13) % 251) as u8);
    }
    v
}

#[test]
fn test_compression_modes_produce_distinct_digests() {
    // Bug this catches: `Compression::Gzip` / `Compression::Zstd`
    // arms broken (no-op fallthrough) — the digests would all match
    // the no-compression digest.
    let work = tempfile::TempDir::new().unwrap();
    let bytes = payload(16 * 1024);
    let blob = work.path().join("payload.bin");
    fs::write(&blob, &bytes).unwrap();

    let dig = |compression: &str, sub: &str| -> Digest {
        let toml_text = build_single_layer_spec_toml(&blob, compression);
        let spec = common::parse_spec(&toml_text, work.path());
        let out = work.path().join(sub);
        let res = build(&spec, &out).unwrap();
        res.layer_digests[0].clone()
    };
    let none = dig("none", "out-none");
    let gzip = dig("gzip", "out-gzip");
    let zstd = dig("zstd", "out-zstd");

    assert_ne!(none, gzip, "gzip output bytes must differ from no-comp");
    assert_ne!(none, zstd, "zstd output bytes must differ from no-comp");
    assert_ne!(gzip, zstd, "gzip and zstd must produce distinct digests");
}

#[test]
fn test_descriptor_digest_addresses_compressed_blob() {
    // Bug this catches: the manifest says `sha256:X` but the blob
    // at `blobs/sha256/X` doesn't actually hash to X — every
    // OCI-compliant consumer rejects the artifact. This is THE
    // cardinal OCI invariant.
    let work = tempfile::TempDir::new().unwrap();
    let bytes = payload(16 * 1024);
    let blob = work.path().join("payload.bin");
    fs::write(&blob, &bytes).unwrap();

    for (compression, name) in [("gzip", "g"), ("zstd", "z"), ("none", "n")] {
        let toml_text = build_single_layer_spec_toml(&blob, compression);
        let spec = common::parse_spec(&toml_text, work.path());
        let out = work.path().join(name);
        let res = build(&spec, &out).unwrap();

        let blob_bytes = fs::read(
            out.join("blobs")
                .join("sha256")
                .join(res.layer_digests[0].hex()),
        )
        .unwrap();
        let actual = Digest::from_bytes(Algorithm::Sha256, &blob_bytes);
        assert_eq!(
            actual, res.layer_digests[0],
            "{compression}: descriptor digest must equal SHA256 of blob bytes on disk"
        );

        // For `none`, blob bytes should equal source bytes.
        if compression == "none" {
            assert_eq!(blob_bytes, bytes, "no-comp blob bytes must equal source");
        } else {
            assert_ne!(
                blob_bytes, bytes,
                "{compression}: blob bytes must NOT equal source (compression must run)"
            );
        }
    }
}

#[test]
fn test_compressed_layer_digest_is_stable_across_two_builds() {
    // Bug this catches: a non-deterministic encoder setting
    // (e.g. timestamp in gzip header). Without reproducible
    // compression, the layer digest churns and SLSA provenance
    // becomes unverifiable.
    let work = tempfile::TempDir::new().unwrap();
    let bytes = payload(16 * 1024);
    let blob = work.path().join("payload.bin");
    fs::write(&blob, &bytes).unwrap();

    for compression in ["gzip", "zstd"] {
        let toml_text = build_single_layer_spec_toml(&blob, compression);
        let spec_a = common::parse_spec(&toml_text, work.path());
        let spec_b = common::parse_spec(&toml_text, work.path());
        let out_a = work.path().join(format!("a-{compression}"));
        let out_b = work.path().join(format!("b-{compression}"));
        let res_a = build(&spec_a, &out_a).unwrap();
        let res_b = build(&spec_b, &out_b).unwrap();
        assert_eq!(
            res_a.layer_digests[0], res_b.layer_digests[0],
            "{compression}: digest must be stable across two builds"
        );
    }
}
