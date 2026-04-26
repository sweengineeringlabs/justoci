//! `HttpPublisher` — ADR-015 **Level 2** publish impl.
//!
//! Takes a `BuildArtifacts` directory (produced by
//! `DefaultImageService::build`) and writes it out as the Level-2
//! layout: an `index.json` catalog at the root plus each blob under
//! `blobs/sha256/<digest>`. Designed to be served verbatim by any
//! static HTTP host — nginx, S3 website mode, GitHub releases —
//! and consumed by Fleet's (planned) `HttpImageProvider`.
//!
//! **Content addressing**: every blob's on-disk name is the lowercase
//! hex of its SHA-256. Republishing identical content is a no-op on
//! disk (same path, skip-if-exists). Republishing the same `image_id`
//! with changed content rewrites the index entry in place — the
//! previous blob may linger but is no longer referenced.
//!
//! **Atomic writes**: blobs and the index are written to a `.tmp`
//! suffix and then renamed. A crash mid-publish leaves the catalog in
//! a consistent prior state, never a half-written file.
//!
//! **Streaming hash**: blobs are hashed and copied in 64 KiB chunks —
//! a multi-GiB rootfs never forces a full read into RAM.
//!
//! **Scope**: this impl is the push-side companion to the future
//! `fleet::spi::image_provider::HttpImageProvider` pull-side (ADR-015
//! §Decision). The two never share a process; they share only the
//! on-disk layout + the index schema.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use oci_build::api::error::Error;
use oci_build::api::spec::BuildArtifacts;
use crate::saf::HttpPublishSummary;

/// Buffer size for the streaming hash-and-copy loop. 64 KiB matches
/// the ext4 readahead window and keeps peak memory bounded
/// regardless of blob size.
const HASH_COPY_CHUNK_BYTES: usize = 64 * 1024;

/// JSON schema version emitted into `index.json`. Must match the
/// `schema_version` value ADR-015 §Level 2 defines. Bumping requires
/// a coordinated change to `HttpImageProvider`'s parser.
const INDEX_SCHEMA_VERSION: u64 = 1;

/// `ImagePublisher` impl that writes a Level-2 directory layout.
///
/// Owns the target `output_dir`. Multiple publishes into the same
/// dir are supported and encouraged — the index merges per
/// `image_id` and preserves sibling entries verbatim.
pub struct HttpPublisher {
    output_dir: PathBuf,
}

impl HttpPublisher {
    /// Construct a publisher rooted at `output_dir`. The directory
    /// is created on first `publish` call if missing; constructing
    /// the struct does no I/O.
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }

    /// Publish `artifacts` into the output directory per ADR-015.
    ///
    /// Algorithm:
    /// 1. `mkdir -p <output>/blobs/sha256`.
    /// 2. For each artifact file (kernel, initrd, rootfs?, config),
    ///    stream-hash the content and copy it to `blobs/sha256/<hex>`
    ///    atomically (skip if the target already exists — same hash
    ///    = same content).
    /// 3. Parse the config.json to extract the image id and (optional)
    ///    `node_tags`.
    /// 4. Merge the new index entry into `index.json` (replacing any
    ///    entry with the same id; preserving others).
    /// 5. Write `index.json` atomically.
    pub fn publish(&self, artifacts: &BuildArtifacts) -> Result<HttpPublishSummary, Error> {
        let blobs_dir = self.output_dir.join("blobs").join("sha256");
        fs::create_dir_all(&blobs_dir)?;

        // --- 1. hash + stage blobs ---------------------------------------
        let kernel = stage_blob(&artifacts.kernel_path, &blobs_dir)?;
        let initrd = stage_blob(&artifacts.initrd_path, &blobs_dir)?;
        let config = stage_blob(&artifacts.config_path, &blobs_dir)?;
        let rootfs = match artifacts.rootfs_path.as_ref() {
            Some(p) => Some(stage_blob(p, &blobs_dir)?),
            None => None,
        };

        // --- 2. parse config.json for id + node_tags ---------------------
        let config_value: Value = {
            let raw = fs::read(&artifacts.config_path)?;
            serde_json::from_slice(&raw)?
        };
        let image_id = config_value
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Publish {
                reason: format!(
                    "config.json at {} missing required string field `id`",
                    artifacts.config_path.display()
                ),
            })?
            .to_string();
        let description = config_value
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let node_tags: Vec<String> = config_value
            .get("node_tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        // --- 3. build the new entry --------------------------------------
        let total_bytes = kernel.size
            + initrd.size
            + config.size
            + rootfs.as_ref().map(|r| r.size).unwrap_or(0);
        let blob_count = 3 + if rootfs.is_some() { 1 } else { 0 };

        let mut entry = Map::new();
        entry.insert("id".into(), Value::String(image_id.clone()));
        entry.insert("description".into(), Value::String(description));
        entry.insert(
            "kernel_url".into(),
            Value::String(format!("blobs/sha256/{}", kernel.digest)),
        );
        entry.insert(
            "kernel_sha256".into(),
            Value::String(kernel.digest.clone()),
        );
        entry.insert(
            "initrd_url".into(),
            Value::String(format!("blobs/sha256/{}", initrd.digest)),
        );
        entry.insert(
            "initrd_sha256".into(),
            Value::String(initrd.digest.clone()),
        );
        if let Some(r) = rootfs.as_ref() {
            entry.insert(
                "rootfs_url".into(),
                Value::String(format!("blobs/sha256/{}", r.digest)),
            );
            entry.insert(
                "rootfs_sha256".into(),
                Value::String(r.digest.clone()),
            );
        }
        entry.insert(
            "config_url".into(),
            Value::String(format!("blobs/sha256/{}", config.digest)),
        );
        entry.insert(
            "config_sha256".into(),
            Value::String(config.digest.clone()),
        );
        entry.insert("size_bytes".into(), json!(total_bytes));
        entry.insert(
            "node_tags".into(),
            Value::Array(node_tags.into_iter().map(Value::String).collect()),
        );
        let new_entry = Value::Object(entry);

        // --- 4. merge into index.json ------------------------------------
        let index_path = self.output_dir.join("index.json");
        let mut images: Vec<Value> = if index_path.exists() {
            let raw = fs::read(&index_path)?;
            let parsed: Value = serde_json::from_slice(&raw)?;
            parsed
                .get("images")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Replace in place if the id already exists; else append.
        let existing_pos = images.iter().position(|img| {
            img.get("id").and_then(|v| v.as_str()) == Some(image_id.as_str())
        });
        match existing_pos {
            Some(i) => images[i] = new_entry,
            None => images.push(new_entry),
        }

        let index_doc = json!({
            "schema_version": INDEX_SCHEMA_VERSION,
            "images": images,
        });
        let index_bytes = serde_json::to_vec_pretty(&index_doc)?;

        // --- 5. atomic index write ---------------------------------------
        let tmp = index_path.with_extension("json.tmp");
        fs::write(&tmp, &index_bytes)?;
        // Rename over an existing file is atomic on POSIX; on Windows
        // `fs::rename` requires the target not to exist, so remove it
        // first. The window is small but non-zero — documented as a
        // known Windows caveat; production use expects POSIX hosts.
        if cfg!(windows) && index_path.exists() {
            fs::remove_file(&index_path)?;
        }
        fs::rename(&tmp, &index_path)?;

        Ok(HttpPublishSummary {
            image_id,
            index_path,
            blob_count,
            total_bytes,
        })
    }
}

/// Outcome of staging one file into the content-addressed store.
struct StagedBlob {
    digest: String,
    size: u64,
}

/// Hash `src` with SHA-256 (streaming, 64 KiB chunks), then copy it
/// into `blobs_dir/<hex>` via a `.tmp`-and-rename. If the destination
/// already exists the copy is skipped — content-addressed means the
/// existing file is byte-equal by construction.
fn stage_blob(src: &Path, blobs_dir: &Path) -> Result<StagedBlob, Error> {
    // Pass 1 — hash + size. Streaming avoids loading multi-GiB rootfs
    // images into RAM.
    let (digest_hex, size) = hash_file_streaming(src)?;

    let dst = blobs_dir.join(&digest_hex);
    if dst.exists() {
        // Content-addressed: same hash = same bytes. Skip re-write
        // and return the digest.
        return Ok(StagedBlob {
            digest: digest_hex,
            size,
        });
    }

    // Pass 2 — copy to `<dst>.tmp` then rename atomically.
    let tmp = blobs_dir.join(format!("{}.tmp", digest_hex));
    fs::copy(src, &tmp)?;
    if cfg!(windows) && dst.exists() {
        fs::remove_file(&dst)?;
    }
    fs::rename(&tmp, &dst)?;

    Ok(StagedBlob {
        digest: digest_hex,
        size,
    })
}

/// Stream `path` through a SHA-256 hasher. Returns (lowercase-hex
/// digest, byte count).
fn hash_file_streaming(path: &Path) -> Result<(String, u64), Error> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_COPY_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        };
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    Ok((hex, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;

    fn fresh_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "http-publisher-test-{}-{}-{}",
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

    fn stage_build_dir(
        dir: &Path,
        image_id: &str,
        kernel: &[u8],
        initrd: &[u8],
        rootfs: Option<&[u8]>,
        node_tags: &[&str],
    ) -> BuildArtifacts {
        let kernel_path = dir.join("kernel");
        write_file(&kernel_path, kernel);
        let initrd_path = dir.join("initrd.cpio");
        write_file(&initrd_path, initrd);
        let rootfs_path = rootfs.map(|bytes| {
            let p = dir.join("rootfs.ext4");
            write_file(&p, bytes);
            p
        });
        let config_path = dir.join("config.json");
        let tags_json: Vec<Value> =
            node_tags.iter().map(|t| Value::String((*t).to_string())).collect();
        let config = json!({
            "schema_version": 1,
            "id": image_id,
            "description": format!("{image_id} description"),
            "node_tags": tags_json,
        });
        write_file(&config_path, serde_json::to_vec_pretty(&config).unwrap().as_slice());
        BuildArtifacts {
            kernel_path,
            initrd_path,
            rootfs_path,
            config_path,
            manifest_path: None,
        }
    }

    /// Expected sha256 (lowercase hex) computed independently from
    /// the same `sha2` crate the impl uses. If the impl uses a
    /// different hash or messes up hex encoding, this fails.
    fn hex_sha256(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // Catches: the publisher writing the wrong digest (e.g. uppercase
    // hex, base64, or a stale hash from a previous blob), wrong file
    // contents under blobs/, or a missing index entry.
    #[test]
    fn test_publish_writes_index_and_blobs_with_correct_sha256() {
        let dir = fresh_temp_dir("happy");
        let build = dir.join("build");
        let out = dir.join("out");

        let k = b"KERNEL-BYTES-1";
        let i = b"INITRD-BYTES-1";
        let r = b"ROOTFS-BYTES-1";
        let artifacts = stage_build_dir(&build, "alpine:3.20", k, i, Some(r), &["linux"]);

        let publisher = HttpPublisher::new(out.clone());
        let summary = publisher.publish(&artifacts).unwrap();

        assert_eq!(summary.image_id, "alpine:3.20");
        assert_eq!(summary.blob_count, 4, "3 blobs + rootfs");
        assert_eq!(summary.index_path, out.join("index.json"));

        // Verify index.json structure.
        let index: Value =
            serde_json::from_slice(&fs::read(&summary.index_path).unwrap()).unwrap();
        assert_eq!(index["schema_version"], json!(1));
        let images = index["images"].as_array().unwrap();
        assert_eq!(images.len(), 1);
        let entry = &images[0];
        assert_eq!(entry["id"], json!("alpine:3.20"));
        assert_eq!(entry["node_tags"], json!(["linux"]));

        // Verify every digest against an independent computation.
        let k_hex = hex_sha256(k);
        let i_hex = hex_sha256(i);
        let r_hex = hex_sha256(r);
        let config_bytes = fs::read(&artifacts.config_path).unwrap();
        let c_hex = hex_sha256(&config_bytes);

        assert_eq!(entry["kernel_sha256"], json!(k_hex));
        assert_eq!(entry["initrd_sha256"], json!(i_hex));
        assert_eq!(entry["rootfs_sha256"], json!(r_hex));
        assert_eq!(entry["config_sha256"], json!(c_hex));
        assert_eq!(entry["kernel_url"], json!(format!("blobs/sha256/{k_hex}")));
        assert_eq!(entry["rootfs_url"], json!(format!("blobs/sha256/{r_hex}")));

        // Verify blob files exist with byte-exact content.
        let blob_k = out.join("blobs").join("sha256").join(&k_hex);
        assert!(blob_k.is_file(), "kernel blob missing at {blob_k:?}");
        assert_eq!(fs::read(&blob_k).unwrap(), k);
        let blob_i = out.join("blobs").join("sha256").join(&i_hex);
        assert_eq!(fs::read(&blob_i).unwrap(), i);
        let blob_r = out.join("blobs").join("sha256").join(&r_hex);
        assert_eq!(fs::read(&blob_r).unwrap(), r);
        let blob_c = out.join("blobs").join("sha256").join(&c_hex);
        assert_eq!(fs::read(&blob_c).unwrap(), config_bytes);

        assert_eq!(
            summary.total_bytes,
            (k.len() + i.len() + r.len() + config_bytes.len()) as u64
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // Catches: republish duplicating the entry instead of replacing
    // (two entries with same id) or failing to update the digest when
    // content changes.
    #[test]
    fn test_publish_twice_replaces_in_place() {
        let dir = fresh_temp_dir("replace");
        let build1 = dir.join("build1");
        let build2 = dir.join("build2");
        let out = dir.join("out");

        let a1 = stage_build_dir(&build1, "foo:1", b"K1", b"I1", Some(b"R1"), &[]);
        let publisher = HttpPublisher::new(out.clone());
        publisher.publish(&a1).unwrap();

        let a2 = stage_build_dir(&build2, "foo:1", b"K2", b"I2", Some(b"R2"), &[]);
        let s2 = publisher.publish(&a2).unwrap();

        let index: Value =
            serde_json::from_slice(&fs::read(&s2.index_path).unwrap()).unwrap();
        let images = index["images"].as_array().unwrap();
        assert_eq!(images.len(), 1, "same id should not duplicate");

        let entry = &images[0];
        let k2_hex = hex_sha256(b"K2");
        assert_eq!(
            entry["kernel_sha256"], json!(k2_hex),
            "entry should point at the NEW kernel digest"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // Catches: index.json being overwritten instead of merged,
    // erasing sibling tenants' images.
    #[test]
    fn test_publish_two_images_both_present() {
        let dir = fresh_temp_dir("two");
        let out = dir.join("out");
        let b1 = dir.join("b1");
        let b2 = dir.join("b2");

        let a1 = stage_build_dir(&b1, "foo:1", b"AK", b"AI", Some(b"AR"), &["linux"]);
        let a2 = stage_build_dir(&b2, "bar:2", b"BK", b"BI", None, &["linux", "x86_64"]);

        let publisher = HttpPublisher::new(out.clone());
        publisher.publish(&a1).unwrap();
        publisher.publish(&a2).unwrap();

        let index: Value =
            serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
        let images = index["images"].as_array().unwrap();
        assert_eq!(images.len(), 2);
        let ids: HashSet<&str> =
            images.iter().map(|e| e["id"].as_str().unwrap()).collect();
        assert!(ids.contains("foo:1"));
        assert!(ids.contains("bar:2"));

        let _ = fs::remove_dir_all(&dir);
    }

    // Catches: the publisher emitting `rootfs_url: null` or
    // `rootfs_sha256: ""` when there is no rootfs — both of which
    // would break the Fleet-side `HttpImageProvider` parser that
    // uses optional fields.
    #[test]
    fn test_publish_omits_rootfs_keys_when_no_rootfs() {
        let dir = fresh_temp_dir("norootfs");
        let build = dir.join("build");
        let out = dir.join("out");

        let artifacts = stage_build_dir(&build, "initramfs:1", b"K", b"I", None, &[]);
        let publisher = HttpPublisher::new(out.clone());
        let summary = publisher.publish(&artifacts).unwrap();
        assert_eq!(summary.blob_count, 3);

        let index: Value =
            serde_json::from_slice(&fs::read(&summary.index_path).unwrap()).unwrap();
        let entry = &index["images"].as_array().unwrap()[0];
        let obj = entry.as_object().unwrap();
        assert!(!obj.contains_key("rootfs_url"), "rootfs_url must be omitted");
        assert!(
            !obj.contains_key("rootfs_sha256"),
            "rootfs_sha256 must be omitted"
        );
        // Required keys still present.
        assert!(obj.contains_key("kernel_url"));
        assert!(obj.contains_key("initrd_url"));
        assert!(obj.contains_key("config_url"));

        let _ = fs::remove_dir_all(&dir);
    }

    // Catches: publisher accepting a config.json with no `id` field
    // (would produce a meaningless index entry id="").
    #[test]
    fn test_publish_rejects_config_without_id() {
        let dir = fresh_temp_dir("noid");
        let build = dir.join("build");
        let out = dir.join("out");
        fs::create_dir_all(&build).unwrap();

        write_file(&build.join("kernel"), b"K");
        write_file(&build.join("initrd.cpio"), b"I");
        // config.json deliberately missing `id`.
        write_file(
            &build.join("config.json"),
            br#"{ "schema_version": 1, "description": "no id" }"#,
        );

        let artifacts = BuildArtifacts {
            kernel_path: build.join("kernel"),
            initrd_path: build.join("initrd.cpio"),
            rootfs_path: None,
            config_path: build.join("config.json"),
            manifest_path: None,
        };
        let publisher = HttpPublisher::new(out);
        match publisher.publish(&artifacts).unwrap_err() {
            Error::Publish { reason } => {
                assert!(
                    reason.contains("id"),
                    "error should name the missing field, got: {reason}"
                );
            }
            other => panic!("expected Error::Publish, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // Catches: the streaming hasher producing a different digest than
    // a one-shot `Sha256::digest` call for content larger than one
    // chunk (64 KiB).
    #[test]
    fn test_streaming_hash_matches_oneshot_for_multi_chunk_file() {
        let dir = fresh_temp_dir("streaming");
        let path = dir.join("big.bin");

        // 200 KiB of a repeating pattern — spans multiple 64 KiB
        // buffer reads to exercise the loop.
        let mut content = Vec::with_capacity(200 * 1024);
        for i in 0..(200 * 1024) {
            content.push((i % 251) as u8);
        }
        fs::write(&path, &content).unwrap();

        let (hex, size) = hash_file_streaming(&path).unwrap();
        assert_eq!(size, content.len() as u64);
        assert_eq!(hex, hex_sha256(&content));

        let _ = fs::remove_dir_all(&dir);
    }

    // Catches: a regression where republishing the same content
    // triggers a write error because the destination already exists
    // and the impl forgot the skip-if-exists guard.
    #[test]
    fn test_publish_is_idempotent_for_unchanged_content() {
        let dir = fresh_temp_dir("idem");
        let build = dir.join("build");
        let out = dir.join("out");

        let artifacts = stage_build_dir(&build, "foo:1", b"K", b"I", Some(b"R"), &[]);
        let publisher = HttpPublisher::new(out.clone());
        publisher.publish(&artifacts).unwrap();
        // Second call with the SAME artifact files must not error.
        let s = publisher.publish(&artifacts).unwrap();
        assert_eq!(s.image_id, "foo:1");

        let _ = fs::remove_dir_all(&dir);
    }
}
