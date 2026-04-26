//! Shared test fixtures for the publish integration test suite.
//!
//! Centralises the "build a tiny but valid OCI image dir in a
//! tempdir" recipe so individual test files don't repeat the
//! manifest-assembly boilerplate. Each test file declares
//! `#[path = "common/mod.rs"] mod common;` to pull this in.
//!
//! What we produce:
//!
//! ```text
//! <root>/
//!   oci-layout                      JSON: imageLayoutVersion = 1.0.0
//!   index.json                      JSON: 1 manifest descriptor (the primary),
//!                                   plus N referrer manifest descriptors.
//!   blobs/sha256/<hex of every>     2 layer blobs, 1 config blob, 1 primary
//!                                   manifest blob, 0 or more referrer manifest
//!                                   blobs (each with config + 1 layer of its own).
//! ```
//!
//! Bytes-for-bytes deterministic: same `Fixture` builder + same
//! caller args ⇒ identical digests. That property is load-bearing
//! for the idempotency tests.

#![allow(dead_code)] // Each individual test file uses a subset of
                      // these helpers; cargo treats integration
                      // tests as separate crates so unused-from-
                      // here-but-used-from-there is a normal cross-
                      // file dead-code warning. This allow is scoped
                      // to the common test helper, NOT to a
                      // production crate root. Per CLAUDE.md
                      // memory note this is the permitted boundary.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// One blob's worth of bytes + the digest you compute over them.
/// Returned by `write_blob_into` so a test can assert digests match
/// what the publish path produced.
#[derive(Debug, Clone)]
pub struct Blob {
    pub digest: String,
    pub size: u64,
    pub bytes: Vec<u8>,
}

impl Blob {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = format!("sha256:{}", hex_sha256(bytes));
        Blob {
            digest,
            size: bytes.len() as u64,
            bytes: bytes.to_vec(),
        }
    }
}

/// Lower-case hex of the sha256 of `bytes`. Independent of the
/// `cas` crate so a cas regression can't make a test pass
/// tautologically.
pub fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Builder for an OCI image dir fixture. Build pattern lets each
/// test pick the deviations it cares about (extra layers, referrer
/// types) without copy-pasting the happy-path setup.
pub struct Fixture {
    pub layer_bodies: Vec<Vec<u8>>,
    pub config_body: Vec<u8>,
    /// Each entry: (config_bytes, layer_bytes, optional_artifact_type).
    /// The fixture builds a complete manifest blob + index entry
    /// for each one, with `subject` pointing at the primary.
    pub referrers: Vec<Referrer>,
}

#[derive(Clone)]
pub struct Referrer {
    pub config_bytes: Vec<u8>,
    pub layer_bytes: Vec<u8>,
    pub artifact_type: String,
}

impl Default for Fixture {
    fn default() -> Self {
        Fixture {
            // 2 distinct layer bodies — the OCI spec's minimum
            // useful image. Using DIFFERENT bytes per layer keeps
            // their digests distinct so a "wrong digest" bug in
            // the publish path produces visible test failures
            // rather than masquerading as a "same digest" pass.
            layer_bodies: vec![b"layer-zero-body".to_vec(), b"layer-one-body".to_vec()],
            config_body: br#"{"architecture":"amd64","os":"linux","config":{}}"#.to_vec(),
            referrers: Vec::new(),
        }
    }
}

impl Fixture {
    pub fn with_referrer(mut self, r: Referrer) -> Self {
        self.referrers.push(r);
        self
    }

    pub fn with_layer(mut self, body: Vec<u8>) -> Self {
        self.layer_bodies.push(body);
        self
    }

    /// Write the OCI image dir into `root` and return a populated
    /// [`FixtureLayout`] view. `root` must exist; we don't create
    /// it because the tempdir crate does that for us.
    pub fn build(&self, root: &Path) -> FixtureLayout {
        let blobs = root.join("blobs").join("sha256");
        fs::create_dir_all(&blobs).unwrap();

        // 1. write each layer blob, capturing digests + sizes.
        let mut layer_blobs = Vec::with_capacity(self.layer_bodies.len());
        for body in &self.layer_bodies {
            let b = Blob::from_bytes(body);
            write_blob(&blobs, &b);
            layer_blobs.push(b);
        }

        // 2. write the config blob.
        let config_blob = Blob::from_bytes(&self.config_body);
        write_blob(&blobs, &config_blob);

        // 3. construct the primary OCI manifest, hash + write it.
        let primary_manifest_value = build_manifest_json(
            &config_blob,
            &layer_blobs,
            None, // no subject — primary
            None, // no artifactType
        );
        let primary_manifest_bytes = serde_json::to_vec(&primary_manifest_value).unwrap();
        let primary_manifest_blob = Blob::from_bytes(&primary_manifest_bytes);
        write_blob(&blobs, &primary_manifest_blob);

        // 4. for each referrer: write its config, layer, and manifest
        //    blobs, with `subject` pointing at the primary.
        let mut referrer_records = Vec::with_capacity(self.referrers.len());
        for r in &self.referrers {
            let cfg = Blob::from_bytes(&r.config_bytes);
            write_blob(&blobs, &cfg);
            let layer = Blob::from_bytes(&r.layer_bytes);
            write_blob(&blobs, &layer);

            let subject_desc = manifest_descriptor_value(&primary_manifest_blob, None);
            let manifest_value = build_manifest_json(
                &cfg,
                std::slice::from_ref(&layer),
                Some(subject_desc),
                Some(r.artifact_type.clone()),
            );
            let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
            let manifest_blob = Blob::from_bytes(&manifest_bytes);
            write_blob(&blobs, &manifest_blob);
            referrer_records.push(ReferrerRecord {
                manifest_blob,
                config_blob: cfg,
                layer_blob: layer,
                artifact_type: r.artifact_type.clone(),
            });
        }

        // 5. write index.json referencing the primary + all referrers.
        let mut manifest_descriptors = vec![manifest_descriptor_value(
            &primary_manifest_blob,
            None,
        )];
        for r in &referrer_records {
            manifest_descriptors.push(manifest_descriptor_value(
                &r.manifest_blob,
                Some(r.artifact_type.clone()),
            ));
        }
        let index = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": manifest_descriptors,
        });
        let index_bytes = serde_json::to_vec_pretty(&index).unwrap();
        fs::write(root.join("index.json"), &index_bytes).unwrap();

        // 6. write oci-layout.
        fs::write(
            root.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();

        FixtureLayout {
            root: root.to_path_buf(),
            layers: layer_blobs,
            config: config_blob,
            primary_manifest: primary_manifest_blob,
            referrers: referrer_records,
            index_bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixtureLayout {
    pub root: PathBuf,
    pub layers: Vec<Blob>,
    pub config: Blob,
    pub primary_manifest: Blob,
    pub referrers: Vec<ReferrerRecord>,
    pub index_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ReferrerRecord {
    pub manifest_blob: Blob,
    pub config_blob: Blob,
    pub layer_blob: Blob,
    pub artifact_type: String,
}

impl FixtureLayout {
    /// Return every blob digest the fixture wrote — useful for
    /// asserting the publish path didn't miss any.
    pub fn all_blob_digests(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .layers
            .iter()
            .chain(std::iter::once(&self.config))
            .chain(std::iter::once(&self.primary_manifest))
            .map(|b| b.digest.clone())
            .collect();
        for r in &self.referrers {
            out.push(r.manifest_blob.digest.clone());
            out.push(r.config_blob.digest.clone());
            out.push(r.layer_blob.digest.clone());
        }
        out
    }
}

fn write_blob(blobs_dir: &Path, blob: &Blob) {
    let (_algo, hex) = blob.digest.split_once(':').unwrap();
    let path = blobs_dir.join(hex);
    fs::write(&path, &blob.bytes).unwrap();
}

fn build_manifest_json(
    config: &Blob,
    layers: &[Blob],
    subject: Option<Value>,
    artifact_type: Option<String>,
) -> Value {
    let mut m = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config.digest,
            "size": config.size,
        },
        "layers": layers.iter().map(|l| json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": l.digest,
            "size": l.size,
        })).collect::<Vec<_>>(),
    });
    if let Some(s) = subject {
        m["subject"] = s;
    }
    if let Some(at) = artifact_type {
        m["artifactType"] = json!(at);
    }
    m
}

fn manifest_descriptor_value(manifest: &Blob, artifact_type: Option<String>) -> Value {
    let mut d = json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest.digest,
        "size": manifest.size,
    });
    if let Some(at) = artifact_type {
        d["artifactType"] = json!(at);
    }
    d
}
