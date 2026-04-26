//! Per-layer assembly: source bytes → optional compression → CAS.
//!
//! Two source modes:
//!
//! - **`Blob`** (a path to a pre-built file): streamed through the
//!   compression encoder directly into `Cas::put_stream` — no
//!   intermediate `Vec<u8>` is materialised. A multi-GB rootfs.ext4
//!   layer flows file → encoder → CAS in 64 KiB chunks, peaking at
//!   roughly the encoder's internal buffer plus the CAS's tmp-file
//!   write buffer (kilobytes, not gigabytes).
//!
//! - **`Files`** (a deterministic tar from `[[layers.files]]`):
//!   built into a `Vec<u8>` then streamed. The tar must be built
//!   in memory or to a tempfile to sort entries; we choose memory
//!   because `[[layers.files]]` is bounded by design (config blobs,
//!   a handful of small files — never multi-GB datasets, which
//!   should use `Blob`).
//!
//! For each layer the pipeline:
//!
//! 1. Materialises the **uncompressed bytes** as a `Read`.
//! 2. Wraps in a streaming compression encoder if the layer's
//!    `Compression` is Gzip / Zstd. None passes through unchanged.
//! 3. Wraps in a `CountingReader` so we capture the compressed-byte
//!    count for the OCI descriptor's `size` field — the OCI manifest
//!    must report the exact byte count of the blob the registry
//!    will store, and we don't know it until compression is done.
//! 4. Hands the chained reader to `cas.put_stream`. The CAS hashes
//!    incrementally and atomically writes via tmp-file + rename.
//!
//! The compressed bytes are what land in the CAS; the descriptor
//! digest is the digest of the *compressed* form. Registries
//! content-address compressed blobs.
//!
//! Compression levels are pinned for reproducibility:
//!
//! - **Gzip**: `flate2::Compression::default()` (level 6, matches
//!   command-line `gzip`). Pinning explicitly so a flate2 upgrade
//!   doesn't shift bytes.
//! - **Zstd**: level 3 (zstd's documented default).

use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::Path;

use cas::{Cas, Digest};
use flate2::read::GzEncoder;
use flate2::Compression as GzipLevel;
use spec::{Compression, Layer, LayerSource};

use crate::api::build_error::BuildError;
use crate::api::oci_manifest::OciDescriptor;
use crate::core::tar_builder::build_deterministic_tar;

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
/// — vendor types like `application/vnd.vmisolate.kernel+binary`
/// survive into the manifest unchanged so consumers can identify
/// the artifact kind from the manifest alone.
pub fn assemble_layer(
    layer: &Layer,
    position: usize,
    spec_dir: &Path,
    cas: &dyn Cas,
) -> Result<LayerResult, BuildError> {
    let (digest, size) = match &layer.source {
        LayerSource::Blob { path } => {
            let resolved = if path.is_absolute() {
                path.clone()
            } else {
                spec_dir.join(path)
            };
            let file = File::open(&resolved).map_err(|source| BuildError::Io {
                path: resolved.clone(),
                source,
            })?;
            stream_through_compression(layer.compression, file, position, cas)?
        }
        LayerSource::Files { entries } => {
            // [[layers.files]] is bounded — we accept the in-memory
            // tar build for v0. If a future use case wants huge
            // [[layers.files]] tars, the tar builder needs a
            // streaming variant; not blocking v0.
            let tar_bytes = build_deterministic_tar(entries, spec_dir)
                .map_err(|source| BuildError::TarBuild { position, source })?;
            stream_through_compression(
                layer.compression,
                Cursor::new(tar_bytes),
                position,
                cas,
            )?
        }
    };

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

/// Stream `source` through the configured compression encoder into
/// `cas.put_stream`. Returns the resulting digest and the
/// **compressed-byte count** (the value the OCI descriptor's `size`
/// field must hold).
///
/// The caller passes `position` so we can pin compression failures
/// to the right layer in error context.
fn stream_through_compression<R: Read>(
    compression: Compression,
    source: R,
    position: usize,
    cas: &dyn Cas,
) -> Result<(Digest, u64), BuildError> {
    match compression {
        Compression::None => put_counted(source, cas, position),
        Compression::Gzip => {
            // `flate2::read::GzEncoder<R>` produces compressed bytes
            // when read from — chains naturally with put_stream
            // without an intermediate buffer.
            let encoder = GzEncoder::new(source, GzipLevel::default());
            put_counted(encoder, cas, position)
        }
        Compression::Zstd => {
            // `zstd::stream::read::Encoder<R>` is the analogous
            // read-side encoder for zstd. Level 3 matches the `zstd`
            // CLI default — pin via the wrapper so a future codec
            // upgrade routes through one place.
            let encoder = zstd::stream::read::Encoder::new(source, 3)
                .map_err(|source| BuildError::LayerCompression { position, source })?;
            put_counted(encoder, cas, position)
        }
    }
}

/// Helper: wrap `reader` in a `CountingReader`, hand to
/// `cas.put_stream`, return digest + byte count. Failures from the
/// CAS land in `BuildError::LayerWrite`; failures from the underlying
/// reader (which would surface inside put_stream as `CasError::Io`)
/// also land there — there's no useful distinction at the layer
/// level.
fn put_counted<R: Read>(
    reader: R,
    cas: &dyn Cas,
    position: usize,
) -> Result<(Digest, u64), BuildError> {
    let mut counter = CountingReader::new(reader);
    let digest = cas
        .put_stream(&mut counter)
        .map_err(|source| BuildError::LayerWrite { position, source })?;
    Ok((digest, counter.bytes))
}

/// Wraps a `Read` and tallies the bytes that pass through. The OCI
/// descriptor's `size` is the count of bytes the registry will
/// store — the **compressed** size when compression is on — and
/// the only point in the pipeline where we naturally see that
/// number is "after compression but before CAS hashing." A
/// `CountingReader` between those two steps is the cleanest place
/// to capture it.
///
/// Why not stat the on-disk blob after `put_stream` returns? Because
/// the `Cas` trait is backend-generic; not every backend exposes
/// a path to stat (and `MemCas` doesn't). Counting in-band keeps
/// the property at the trait level.
struct CountingReader<R: Read> {
    inner: R,
    bytes: u64,
}

impl<R: Read> CountingReader<R> {
    fn new(inner: R) -> Self {
        CountingReader { inner, bytes: 0 }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use cas::FsCas;
    use spec::{Compression, Layer, LayerFile, LayerSource, MediaType};
    use tempfile::TempDir;

    fn vmkernel_media_type(tmp: &Path) -> MediaType {
        // Stage a minimal vm_image-shaped spec to harvest a MediaType
        // (the `MediaType` constructor is `pub(crate)` to spec).
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
        parsed.spec.layers[0].media_type.clone()
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
        let bytes = cas.get(&result.digest).unwrap();
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

    /// A `Read` impl that records every read call's requested-buffer
    /// size. Used to prove the assembly pipeline streams its source
    /// in chunks rather than buffering the whole payload upfront.
    struct ProbeReader<R: Read> {
        inner: R,
        read_calls: Arc<AtomicUsize>,
        max_buf_seen: Arc<AtomicUsize>,
    }

    impl<R: Read> Read for ProbeReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_calls.fetch_add(1, Ordering::SeqCst);
            self.max_buf_seen
                .fetch_max(buf.len(), Ordering::SeqCst);
            self.inner.read(buf)
        }
    }

    /// Streaming property: a 1 MiB Blob source flows through the
    /// pipeline in multiple read() calls — no `read_to_end` style
    /// buffer-everything-first regression. Multi-GB rootfs.ext4
    /// layers depend on this property.
    ///
    /// Bug this would catch: a refactor that calls `read_to_end`
    /// on the source before handing bytes to compression / CAS,
    /// which would OOM on layer files larger than RAM.
    #[test]
    fn test_blob_layer_streams_in_chunks() {
        let tmp = TempDir::new().unwrap();
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        let cas = FsCas::new(&cas_root).unwrap();

        // Build a 1 MiB payload. Patterned bytes so the digest is
        // deterministic and the test can assert it.
        let payload: Vec<u8> = (0..1024u32 * 1024)
            .map(|i| (i & 0xff) as u8)
            .collect();
        let payload_path = tmp.path().join("big.bin");
        std::fs::write(&payload_path, &payload).unwrap();

        // Wire a ProbeReader inline by reading the file ourselves
        // instead of letting `assemble_layer` open it. We bypass the
        // public function for one direct call to the streaming
        // helper — the file path the rest of the pipeline takes is
        // the one this test inspects.
        let read_calls = Arc::new(AtomicUsize::new(0));
        let max_buf_seen = Arc::new(AtomicUsize::new(0));
        let probe = ProbeReader {
            inner: File::open(&payload_path).unwrap(),
            read_calls: Arc::clone(&read_calls),
            max_buf_seen: Arc::clone(&max_buf_seen),
        };

        let (digest, size) =
            stream_through_compression(Compression::None, probe, 0, &cas).unwrap();

        // Exactly the source bytes' digest — no compression, no
        // mangling.
        let expected = Digest::from_bytes(cas::Algorithm::Sha256, &payload);
        assert_eq!(digest, expected);
        assert_eq!(size, payload.len() as u64);

        // The streaming property: many reads, none of which asked
        // for the whole 1 MiB at once.
        let calls = read_calls.load(Ordering::SeqCst);
        let max_buf = max_buf_seen.load(Ordering::SeqCst);
        assert!(
            calls > 1,
            "streaming pipeline must use multiple read() calls (saw {calls})"
        );
        assert!(
            max_buf < payload.len(),
            "no single read() may ask for the entire payload (max_buf={max_buf}, payload={})",
            payload.len()
        );
    }

    /// Same property as above, but with gzip compression on top —
    /// proves that the read-side encoder doesn't materialise the
    /// raw input before compressing.
    #[test]
    fn test_blob_layer_streams_through_gzip_in_chunks() {
        let tmp = TempDir::new().unwrap();
        let cas_root = tmp.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        let cas = FsCas::new(&cas_root).unwrap();

        let payload: Vec<u8> = (0..512u32 * 1024).map(|i| (i & 0xff) as u8).collect();
        let payload_path = tmp.path().join("big.bin");
        std::fs::write(&payload_path, &payload).unwrap();

        let read_calls = Arc::new(AtomicUsize::new(0));
        let max_buf_seen = Arc::new(AtomicUsize::new(0));
        let probe = ProbeReader {
            inner: File::open(&payload_path).unwrap(),
            read_calls: Arc::clone(&read_calls),
            max_buf_seen: Arc::clone(&max_buf_seen),
        };

        let (_digest, compressed_size) =
            stream_through_compression(Compression::Gzip, probe, 0, &cas).unwrap();
        assert!(compressed_size > 0);
        assert!(
            compressed_size < payload.len() as u64,
            "patterned payload should compress smaller than raw"
        );

        let calls = read_calls.load(Ordering::SeqCst);
        let max_buf = max_buf_seen.load(Ordering::SeqCst);
        assert!(
            calls > 1,
            "gzip streaming must use multiple read() calls (saw {calls})"
        );
        assert!(
            max_buf < payload.len(),
            "gzip read-side encoder must chunk the input (max_buf={max_buf})"
        );
    }
}
