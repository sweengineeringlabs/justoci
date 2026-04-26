//! HTTP sink (ADR-015 Level 2) — copy a validated [`ImageDir`] into a
//! static-served directory.
//!
//! Algorithm:
//!
//! 1. `mkdir -p <dest>/blobs/sha256/`.
//! 2. Write `<dest>/oci-layout` (idempotent: byte-equal targets are
//!    a no-op).
//! 3. For every blob in [`ImageDir::referenced_blobs`] (which orders
//!    layers + configs + referrer manifests + primary manifest LAST),
//!    skip-if-exists at `<dest>/blobs/sha256/<hex>`; otherwise copy
//!    via temp-file + atomic rename.
//! 4. **As the LAST step**, write `<dest>/index.json` atomically. This
//!    is the commit point — until the rename succeeds, consumers see
//!    "no image at this dir" rather than "half-published image."
//!
//! ### Resumable + idempotent
//!
//! Skip-if-exists at step 3 means re-publishing the same image is
//! a no-op (every blob lands in `digests_skipped`). A failed publish
//! that copied N blobs and then died can be retried — the next
//! attempt skips the N blobs already on disk.
//!
//! ### Atomic commit
//!
//! Step 4 is the safety property: a publish that succeeds means
//! `index.json` is present and points at blobs that all exist; a
//! publish that fails before step 4 leaves `index.json` either
//! absent (first publish) or pointing at the previous version
//! (re-publish), but never at a partial new version. The atomic
//! `rename(2)` over `index.json` is what enforces this.

use std::fs;
use std::io;
use std::path::Path;

use crate::api::error::PublishError;
use crate::api::image_dir::{ImageDir, INDEX_JSON_FILE, OCI_LAYOUT_FILE};
use crate::api::sink::PublishOutcome;

/// Buffer size for blob-copy I/O. 64 KiB matches the ext4 readahead
/// window and bounds peak memory at one buffer per thread.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// Suffix appended to the temp file used during atomic blob writes.
/// Includes process id + nanosecond timestamp at the call site to
/// avoid collisions across concurrent publishers; this constant is
/// the static prefix shared with `gc` so a future janitor can sweep
/// orphaned temp files.
const BLOB_TMP_PREFIX: &str = ".tmp-oci-publish";

/// Publish `image` into the static directory at `dest_dir`.
///
/// See module docs for the contract; see `tests/http_*` for the
/// behaviour bugs the test suite catches.
pub fn publish_http(image: &ImageDir, dest_dir: &Path) -> Result<PublishOutcome, PublishError> {
    let blobs_dir = dest_dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir).map_err(|source| PublishError::Destination {
        path: blobs_dir.clone(),
        source,
    })?;

    // Step 2 — propagate `oci-layout` verbatim. Idempotent: byte-
    // equal target is a no-op. The OCI Image Layout file is small
    // (single JSON object, < 32 bytes) so we don't bother with a
    // streaming hash; the test suite pins the byte-equality.
    let layout_bytes = image.read_oci_layout_bytes().map_err(PublishError::from)?;
    let layout_path = dest_dir.join(OCI_LAYOUT_FILE);
    write_if_changed(&layout_path, &layout_bytes)?;

    // Step 3 — copy every referenced blob, skip-if-exists. The
    // referenced_blobs ordering (layers → config → referrers →
    // primary manifest LAST) matches the registry-sink ordering;
    // for the HTTP sink the order is irrelevant on disk, but we
    // keep it consistent for sanity.
    let mut outcome = PublishOutcome::empty();
    for desc in image.referenced_blobs() {
        let src = image.blob_path(&desc.digest).map_err(PublishError::from)?;
        let dst = blobs_dir.join(blob_hex_of(&desc.digest)?);
        if dst.exists() {
            outcome.digests_skipped.push(desc.digest.clone());
            continue;
        }
        let bytes = copy_blob_atomic(&src, &dst, &blobs_dir, &desc.digest)?;
        outcome.bytes_uploaded += bytes;
        outcome.digests_pushed.push(desc.digest.clone());
    }

    // Step 4 — write `index.json` atomically as the commit point.
    // We do this AFTER every blob is on disk so a partial run never
    // exposes a half-published image. The file is propagated
    // verbatim — the input is already a valid OCI image index.
    let index_bytes = image.read_index_bytes().map_err(PublishError::from)?;
    let index_path = dest_dir.join(INDEX_JSON_FILE);
    write_atomic_index(&index_path, &index_bytes)?;

    Ok(outcome)
}

/// Extract the lowercase hex from `algorithm:hex`. The image-dir
/// validation already rejected non-sha256 / wrong-length / mixed-case
/// digests, so this is a structural split, not a re-validation.
fn blob_hex_of(digest: &str) -> Result<String, PublishError> {
    digest
        .split_once(':')
        .map(|(_, hex)| hex.to_string())
        .ok_or_else(|| PublishError::MalformedImageDir {
            detail: format!("digest {digest:?} has no algorithm:hex separator"),
        })
}

/// Copy `src` to `dst` via a same-directory temp file + atomic rename.
///
/// Why same-directory: `rename(2)` is only atomic when source and
/// destination are on the same filesystem. The temp file lives in
/// the same `blobs/sha256/` subdir as the final blob, which is the
/// same filesystem by construction.
///
/// Why atomic: if the publish dies mid-copy, the temp file may
/// linger but the canonical `<hex>` path is either absent or
/// pointing at a complete prior copy — never at a partial new one.
///
/// Returns the byte count copied.
fn copy_blob_atomic(
    src: &Path,
    dst: &Path,
    tmp_dir: &Path,
    digest: &str,
) -> Result<u64, PublishError> {
    // Unique temp name. `process::id()` + nanos is enough collision
    // resistance for concurrent publishers; the digest is folded in
    // so a janitor sweeping `.tmp-oci-publish-*` files can correlate
    // with a half-finished blob.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!(
        "{BLOB_TMP_PREFIX}-{}-{}-{}",
        std::process::id(),
        nanos,
        blob_hex_of(digest)?
    );
    let tmp = tmp_dir.join(&tmp_name);

    let bytes = match copy_chunked(src, &tmp) {
        Ok(b) => b,
        Err(e) => {
            // Best-effort cleanup of the partial temp file. The
            // primary error is what bubbles up.
            let _ = fs::remove_file(&tmp);
            return Err(PublishError::BlobUpload {
                digest: digest.to_string(),
                source: Box::new(e),
            });
        }
    };

    // Cross-platform: Windows refuses `rename` over an existing
    // target. After `dst.exists()` returned false above, a racing
    // writer could land here; the `remove_file` is best-effort and
    // any subsequent rename still atomically replaces.
    #[cfg(windows)]
    if dst.exists() {
        let _ = fs::remove_file(dst);
    }

    fs::rename(&tmp, dst).map_err(|source| PublishError::BlobUpload {
        digest: digest.to_string(),
        source: Box::new(source),
    })?;

    Ok(bytes)
}

/// Stream `src` to `dst` in 64 KiB chunks. Returns the byte count.
fn copy_chunked(src: &Path, dst: &Path) -> io::Result<u64> {
    use io::Read;
    use io::Write;
    let mut input = fs::File::open(src)?;
    let mut output = fs::File::create(dst)?;
    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        output.write_all(&buf[..n])?;
        total += n as u64;
    }
    output.sync_all()?;
    Ok(total)
}

/// Write `bytes` to `path` only if `path` either doesn't exist or
/// has different content. Used for `oci-layout` — small, idempotent,
/// often byte-equal across re-publishes.
fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<(), PublishError> {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        "{}-oci-layout-{}",
        BLOB_TMP_PREFIX,
        std::process::id(),
    ));
    fs::write(&tmp, bytes).map_err(|source| PublishError::Destination {
        path: tmp.clone(),
        source,
    })?;
    finalize_atomic(&tmp, path)?;
    Ok(())
}

/// Atomic write of `index.json`. The path is the commit point —
/// `rename(2)` makes the new version visible in one step.
fn write_atomic_index(path: &Path, bytes: &[u8]) -> Result<(), PublishError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        "{}-index-{}-{}",
        BLOB_TMP_PREFIX,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::write(&tmp, bytes).map_err(|source| PublishError::Destination {
        path: tmp.clone(),
        source,
    })?;
    finalize_atomic(&tmp, path)?;
    Ok(())
}

/// Cross-platform atomic rename. Windows refuses `rename` over an
/// existing target; `remove + rename` is the documented escape
/// (the rename window is tiny but non-zero on Windows — POSIX hosts
/// observe the truly-atomic `rename(2)` semantics).
fn finalize_atomic(tmp: &Path, dst: &Path) -> Result<(), PublishError> {
    #[cfg(windows)]
    if dst.exists() {
        if let Err(source) = fs::remove_file(dst) {
            // On Windows, removing a file held open elsewhere fails
            // with PermissionDenied. We surface this verbatim — a
            // higher layer can decide to retry.
            return Err(PublishError::Destination {
                path: dst.to_path_buf(),
                source,
            });
        }
    }
    fs::rename(tmp, dst).map_err(|source| PublishError::Destination {
        path: dst.to_path_buf(),
        source,
    })
}

/// Public file-name prefix for the temp files this sink uses.
/// Exported so a CI test or a future janitor can sweep them
/// without depending on private constants.
pub const TEMP_FILE_PREFIX: &str = BLOB_TMP_PREFIX;
