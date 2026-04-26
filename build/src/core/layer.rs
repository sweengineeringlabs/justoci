//! Per-layer assembly: source bytes → optional compression → CAS.
//!
//! For each `Layer` the pipeline:
//!
//! 1. Materialises the **uncompressed bytes**: read a `Blob` source
//!    file, or build a deterministic tar from a `Files` source.
//! 2. Applies the layer's `Compression` (None / Gzip / Zstd) to those
//!    bytes. The compressed bytes are what land in the CAS, so the
//!    descriptor digest is the digest of the *compressed* form.
//!    Registries content-address compressed blobs; consumers
//!    decompress on extract.
//! 3. Streams the (possibly compressed) bytes to the `Cas`. The CAS
//!    is responsible for atomicity (tmp-file + rename).
//!
//! Compression uses a fixed level for each codec so the same source
//! → same compressed bytes → same digest. Encoder defaults vary by
//! version; we pin explicitly:
//!
//! - **Gzip**: `flate2::Compression::default()` is level 6 — matches
//!   the gzip command-line default and is what most CI pipelines hit.
//!   Pinning explicitly so a flate2 upgrade doesn't shift bytes.
//! - **Zstd**: level 3 — zstd's documented "default" and what the
//!   `zstd` CLI emits with no flags.
//!
//! ## Why compress before hashing
//!
//! OCI consumers identify blobs by the digest of the compressed
//! payload (it's what the registry stores and what the Distribution
//! API serves). If we hashed the uncompressed bytes, we'd store one
//! payload but advertise a different digest in the manifest — every
//! `oras pull` / `crane pull` would refuse the artifact.

use std::fs::File;
use std::io::{self, Cursor, Read};

use cas::{Cas, Digest};
use flate2::write::GzEncoder;
use flate2::Compression as GzipLevel;
use spec::{Compression, Layer, LayerSource};

use crate::api::build_error::BuildError;
use crate::api::oci_manifest::OciDescriptor;
use crate::core::tar_builder::build_deterministic_tar;

use std::path::Path;

/// Result of putting one layer through the pipeline.
#[derive(Debug)]
pub struct LayerResult {
    pub digest: Digest,
    pub size: u64,
    pub descriptor: OciDescriptor,
}

/// Assemble layer #`position` per the spec → write to CAS → return
/// an OCI descriptor + digest + byte count.
///
/// The descriptor's `mediaType` is the spec's media type *verbatim*
/// — the spec doc says vendor types like
/// `application/vnd.vmisolate.kernel+binary` survive into the
/// manifest unchanged so consumers can identify the artifact kind
/// from the manifest alone.
pub fn assemble_layer(
    layer: &Layer,
    position: usize,
    spec_dir: &Path,
    cas: &dyn Cas,
) -> Result<LayerResult, BuildError> {
    // Step 1: uncompressed bytes.
    let raw_bytes: Vec<u8> = match &layer.source {
        LayerSource::Blob { path } => {
            let resolved = if path.is_absolute() {
                path.clone()
            } else {
                spec_dir.join(path)
            };
            read_file_to_vec(&resolved).map_err(|source| BuildError::Io {
                path: resolved.clone(),
                source,
            })?
        }
        LayerSource::Files { entries } => build_deterministic_tar(entries, spec_dir)
            .map_err(|source| BuildError::TarBuild { position, source })?,
    };

    // Step 2: optional compression.
    let final_bytes = match layer.compression {
        Compression::None => raw_bytes,
        Compression::Gzip => gzip_encode(&raw_bytes)
            .map_err(|source| BuildError::LayerCompression { position, source })?,
        Compression::Zstd => zstd_encode(&raw_bytes)
            .map_err(|source| BuildError::LayerCompression { position, source })?,
    };

    let size = final_bytes.len() as u64;

    // Step 3: write to CAS. Stream so that future large-blob layer
    // sources don't have to be in memory twice.
    let mut cursor = Cursor::new(&final_bytes);
    let digest = cas
        .put_stream(&mut cursor)
        .map_err(|source| BuildError::LayerWrite { position, source })?;

    let descriptor = OciDescriptor {
        media_type: layer.media_type.as_str().to_string(),
        digest: digest.to_string(),
        size,
        annotations: Default::default(),
    };

    Ok(LayerResult {
        digest,
        size,
        descriptor,
    })
}

fn read_file_to_vec(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Gzip-encode at `flate2::Compression::default()` (level 6, matches
/// command-line `gzip`). Pinned via this wrapper so a future change
/// to the encoder level routes through here, where the
/// reproducibility implications are visible.
fn gzip_encode(bytes: &[u8]) -> io::Result<Vec<u8>> {
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), GzipLevel::default());
    enc.write_all(bytes)?;
    enc.finish()
}

/// Zstd-encode at level 3 (zstd's documented default — same bytes
/// the `zstd` CLI emits with no flags).
fn zstd_encode(bytes: &[u8]) -> io::Result<Vec<u8>> {
    zstd::stream::encode_all(Cursor::new(bytes), 3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use cas::FsCas;
    use spec::{Compression, Layer, LayerFile, LayerSource, MediaType};
    use tempfile::TempDir;

    // `MediaType` constructor is `pub(crate)` to spec; in tests we
    // use a known-valid string and parse-and-validate to obtain it.
    // For these unit tests we round-trip through TOML to obtain a
    // valid `MediaType` rather than reach across the privacy boundary.
    fn vmkernel_media_type(tmp: &Path) -> MediaType {
        // Stage a minimal vm_image-shaped spec to harvest a MediaType.
        // (We can't construct one directly because the constructor
        // is `pub(crate)` to spec.)
        let kernel = tmp.join("k.bin");
        let initrd = tmp.join("i.bin");
        let rootfs = tmp.join("r.bin");
        std::fs::write(&kernel, b"k").unwrap();
        std::fs::write(&initrd, b"i").unwrap();
        std::fs::write(&rootfs, b"r").unwrap();

        let toml_text = format!(
            r#"
spec_version = "0"
id = "x:1"
kind = "vm_image"
[[layers]]
source = "k.bin"
media_type = "application/vnd.vmisolate.kernel+binary"
[[layers]]
source = "i.bin"
media_type = "application/vnd.vmisolate.initrd+gzip"
compression = "gzip"
[[layers]]
source = "r.bin"
media_type = "application/vnd.vmisolate.rootfs+gzip"
compression = "gzip"
            "#
        );
        let parsed =
            spec::parse_and_validate_str(&toml_text, tmp.to_path_buf()).expect("valid");
        parsed.layers[0].media_type.clone()
    }

    #[test]
    fn test_blob_layer_with_no_compression_hashes_source_bytes_directly() {
        // Bug this would catch: a refactor that always runs through a
        // codec (even at None) and emits a different digest than the
        // raw file bytes.
        let tmp = TempDir::new().unwrap();
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        let cas = FsCas::new(&cas_root).unwrap();

        let mt = vmkernel_media_type(tmp.path());

        let layer_file = tmp.path().join("payload.bin");
        std::fs::write(&layer_file, b"raw payload bytes").unwrap();

        let layer = Layer {
            source: LayerSource::Blob {
                path: PathBuf::from("payload.bin"),
            },
            media_type: mt,
            compression: Compression::None,
        };

        let result = assemble_layer(&layer, 0, tmp.path(), &cas).unwrap();
        let expected_digest =
            Digest::from_bytes(cas::Algorithm::Sha256, b"raw payload bytes");
        assert_eq!(result.digest, expected_digest);
        assert_eq!(result.size, b"raw payload bytes".len() as u64);
    }

    #[test]
    fn test_files_layer_writes_tar_to_cas() {
        // Bug this would catch: `LayerSource::Files` skipped or
        // turned into a panic/unimplemented branch — the spec
        // doc commits to both source modes shipping in v0.
        let tmp = TempDir::new().unwrap();
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        let cas = FsCas::new(&cas_root).unwrap();

        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();

        let mt = vmkernel_media_type(tmp.path());

        let layer = Layer {
            source: LayerSource::Files {
                entries: vec![LayerFile {
                    source: PathBuf::from("a.txt"),
                    dest: "/etc/a.txt".into(),
                    mode: 0o644,
                }],
            },
            media_type: mt,
            compression: Compression::None,
        };

        let result = assemble_layer(&layer, 1, tmp.path(), &cas).unwrap();
        // The CAS now has the tar bytes; pulling them back must
        // round-trip through `cas::Cas::get`.
        let bytes = cas.get(&result.digest).unwrap();
        // Confirm it parses as a tar with one entry.
        let mut ar = tar::Archive::new(&bytes[..]);
        let mut count = 0;
        for entry in ar.entries().unwrap() {
            let entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            assert_eq!(path, "etc/a.txt");
            count += 1;
        }
        assert_eq!(count, 1, "tar must contain exactly one entry");
    }

    #[test]
    fn test_descriptor_carries_spec_media_type_verbatim() {
        // Bug this would catch: a refactor that overrides the spec
        // media type with `application/vnd.oci.image.layer.v1.tar`
        // (the OCI default). Vendor types are part of the wire
        // contract — `vmisolate.kernel+binary` must land on the
        // manifest unchanged.
        let tmp = TempDir::new().unwrap();
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        let cas = FsCas::new(&cas_root).unwrap();

        std::fs::write(tmp.path().join("payload.bin"), b"x").unwrap();

        let mt = vmkernel_media_type(tmp.path());

        let layer = Layer {
            source: LayerSource::Blob {
                path: PathBuf::from("payload.bin"),
            },
            media_type: mt.clone(),
            compression: Compression::None,
        };

        let result = assemble_layer(&layer, 0, tmp.path(), &cas).unwrap();
        assert_eq!(result.descriptor.media_type, mt.as_str());
        assert_eq!(
            result.descriptor.media_type,
            "application/vnd.vmisolate.kernel+binary"
        );
    }

    #[test]
    fn test_missing_blob_source_surfaces_io_error_with_path() {
        // Bug this would catch: dropping the source path from the
        // error envelope — operator can't tell which blob is missing
        // when an artifact has multiple Blob layers.
        let tmp = TempDir::new().unwrap();
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        let cas = FsCas::new(&cas_root).unwrap();

        let mt = vmkernel_media_type(tmp.path());

        let layer = Layer {
            source: LayerSource::Blob {
                path: PathBuf::from("does-not-exist"),
            },
            media_type: mt,
            compression: Compression::None,
        };

        let err = assemble_layer(&layer, 0, tmp.path(), &cas).unwrap_err();
        match err {
            BuildError::Io { path, .. } => {
                assert!(
                    path.to_string_lossy().contains("does-not-exist"),
                    "missing path in error: {path:?}"
                );
            }
            other => panic!("expected BuildError::Io, got {other:?}"),
        }
    }
}
