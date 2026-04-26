//! End-to-end integration test for the `publish_http` SAF facade.
//!
//! Proves that the saf → spi layers compose against a realistic
//! `BuildArtifacts` directory-on-disk, matching what the CLI
//! (`ocimage publish-http`) would hand the facade.
//!
//! Everything runs off a `std::env::temp_dir()`-rooted scratch dir
//! using the same unique-suffix pattern as `saf::facade::tests`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use oci_publish::{publish_http, Error};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn fresh_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ocimage-publish-http-int-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_file(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(path).unwrap();
    f.write_all(content).unwrap();
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn stage_build_dir(
    build_dir: &Path,
    id: &str,
    description: &str,
    kernel: &[u8],
    initrd: &[u8],
    rootfs: Option<&[u8]>,
    node_tags: &[&str],
) {
    write_file(&build_dir.join("kernel"), kernel);
    write_file(&build_dir.join("initrd.cpio"), initrd);
    if let Some(r) = rootfs {
        write_file(&build_dir.join("rootfs.ext4"), r);
    }
    let tags_json: Vec<Value> =
        node_tags.iter().map(|t| Value::String((*t).to_string())).collect();
    let config = json!({
        "schema_version": 1,
        "id": id,
        "description": description,
        "kernel_cmdline": "console=ttyS0 rdinit=/init",
        "node_tags": tags_json,
        "init_mode": "xkinit",
    });
    write_file(
        &build_dir.join("config.json"),
        &serde_json::to_vec_pretty(&config).unwrap(),
    );
}

/// Happy-path end-to-end. Catches: any wiring regression between
/// `publish_http` → `BuildArtifacts::load_from_dir` → `HttpPublisher`,
/// and any digest/layout drift that would break the Fleet-side
/// `HttpImageProvider` reader.
#[test]
fn test_publish_http_writes_level2_layout_for_rootfs_image() {
    let dir = fresh_temp_dir("rootfs");
    let build = dir.join("build");
    let out = dir.join("out");

    let kernel = b"FAKE_KERNEL_BZIMAGE_CONTENT";
    let initrd = b"FAKE_INITRD_CPIO_CONTENT";
    let rootfs = b"FAKE_ROOTFS_EXT4_CONTENT";
    stage_build_dir(
        &build,
        "alpine:3.20",
        "Alpine Linux 3.20 integration-test fixture",
        kernel,
        initrd,
        Some(rootfs),
        &["linux", "x86_64"],
    );

    let summary = publish_http(&build, &out).expect("publish_http should succeed");

    // --- summary fields -------------------------------------------------
    assert_eq!(summary.image_id, "alpine:3.20");
    assert_eq!(summary.blob_count, 4, "kernel + initrd + rootfs + config");
    assert_eq!(summary.index_path, out.join("index.json"));

    let config_bytes = fs::read(build.join("config.json")).unwrap();
    let expected_total =
        (kernel.len() + initrd.len() + rootfs.len() + config_bytes.len()) as u64;
    assert_eq!(summary.total_bytes, expected_total);

    // --- directory layout ----------------------------------------------
    assert!(out.join("index.json").is_file());
    let blobs_dir = out.join("blobs").join("sha256");
    assert!(blobs_dir.is_dir(), "blobs/sha256 must exist");

    let k_hex = hex_sha256(kernel);
    let i_hex = hex_sha256(initrd);
    let r_hex = hex_sha256(rootfs);
    let c_hex = hex_sha256(&config_bytes);

    assert_eq!(fs::read(blobs_dir.join(&k_hex)).unwrap(), kernel);
    assert_eq!(fs::read(blobs_dir.join(&i_hex)).unwrap(), initrd);
    assert_eq!(fs::read(blobs_dir.join(&r_hex)).unwrap(), rootfs);
    assert_eq!(fs::read(blobs_dir.join(&c_hex)).unwrap(), config_bytes);

    // --- index.json shape ----------------------------------------------
    let index: Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    assert_eq!(index["schema_version"], json!(1));
    let images = index["images"].as_array().unwrap();
    assert_eq!(images.len(), 1);
    let entry = &images[0];
    assert_eq!(entry["id"], json!("alpine:3.20"));
    assert_eq!(
        entry["description"],
        json!("Alpine Linux 3.20 integration-test fixture")
    );
    assert_eq!(entry["kernel_sha256"], json!(k_hex));
    assert_eq!(entry["initrd_sha256"], json!(i_hex));
    assert_eq!(entry["rootfs_sha256"], json!(r_hex));
    assert_eq!(entry["config_sha256"], json!(c_hex));
    assert_eq!(entry["kernel_url"], json!(format!("blobs/sha256/{k_hex}")));
    assert_eq!(entry["initrd_url"], json!(format!("blobs/sha256/{i_hex}")));
    assert_eq!(entry["rootfs_url"], json!(format!("blobs/sha256/{r_hex}")));
    assert_eq!(entry["config_url"], json!(format!("blobs/sha256/{c_hex}")));
    assert_eq!(entry["node_tags"], json!(["linux", "x86_64"]));
    assert_eq!(entry["size_bytes"], json!(expected_total));

    let _ = fs::remove_dir_all(&dir);
}

/// Catches: the facade accepting a build_dir that's missing the
/// mandatory `kernel` file (the error flows from
/// `BuildArtifacts::load_from_dir`; this test proves the facade
/// doesn't swallow it).
#[test]
fn test_publish_http_missing_kernel_returns_artifact_missing() {
    let dir = fresh_temp_dir("missing-kernel");
    let build = dir.join("build");
    let out = dir.join("out");
    fs::create_dir_all(&build).unwrap();

    // initrd + config but NO kernel.
    write_file(&build.join("initrd.cpio"), b"I");
    write_file(
        &build.join("config.json"),
        br#"{"schema_version":1,"id":"x:1"}"#,
    );

    let err = publish_http(&build, &out).expect_err("kernel missing must fail");
    match err {
        Error::ArtifactMissing { which, .. } => {
            assert_eq!(which, "kernel");
        }
        other => panic!("expected Error::ArtifactMissing, got {other:?}"),
    }

    // No partial side-effects: out/ must not have a half-written
    // index.json. (Actually, `load_from_dir` fails before any
    // publisher work, so there should be no out/ at all.)
    assert!(
        !out.join("index.json").exists(),
        "publish must not write a partial index when it errors"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Catches: the facade creating a new index that silently erases
/// prior entries when a second image is published. This is the
/// multi-tenant "one output dir, many images" scenario operators
/// will hit in CI.
#[test]
fn test_publish_http_merges_two_images_into_one_index() {
    let dir = fresh_temp_dir("merge");
    let out = dir.join("out");
    let b1 = dir.join("b1");
    let b2 = dir.join("b2");

    stage_build_dir(&b1, "foo:1", "first", b"KA", b"IA", Some(b"RA"), &["linux"]);
    stage_build_dir(&b2, "bar:2", "second", b"KB", b"IB", None, &["linux"]);

    let s1 = publish_http(&b1, &out).unwrap();
    let s2 = publish_http(&b2, &out).unwrap();
    assert_eq!(s1.image_id, "foo:1");
    assert_eq!(s2.image_id, "bar:2");
    assert_eq!(s1.blob_count, 4);
    assert_eq!(s2.blob_count, 3);

    let index: Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    let images = index["images"].as_array().unwrap();
    assert_eq!(images.len(), 2, "both images must survive the merge");
    let ids: Vec<&str> =
        images.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"foo:1"));
    assert!(ids.contains(&"bar:2"));

    let _ = fs::remove_dir_all(&dir);
}
