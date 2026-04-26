//! `PublishError` — the typed failure surface for `publish`.
//!
//! Every variant carries actionable context for an operator:
//!
//!   * which blob digest failed an upload?
//!   * which path on disk was unreadable?
//!   * what HTTP status + body did the registry return?
//!
//! Variants are deliberately granular — the CLI can route on
//! `RegistryRefused` (re-try after fixing the image) versus
//! `BlobUpload` with a transient `source` (re-try the same image)
//! without parsing strings.

use std::path::PathBuf;

use cas::CasError;

/// Errors raised by [`crate::publish`] (and its per-sink helpers).
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// Filesystem or network I/O error not otherwise classified.
    /// Carries the source for chained `Display`. The publish-side
    /// HTTP sink raises this for `read`/`write`/`rename` failures
    /// on the destination directory.
    #[error("i/o error: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },

    /// A specific blob upload (registry sink: PUT to a blob URL;
    /// http sink: copy + rename) failed mid-flight. The `digest`
    /// names the blob so an operator can correlate against the
    /// image's manifest. The registry-sink variant carries the
    /// HTTP error chain through `source` (so `display`/`source()`
    /// surface it).
    #[error("uploading blob {digest} failed: {source}")]
    BlobUpload {
        digest: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The manifest upload itself failed. Distinct from
    /// [`Self::BlobUpload`] because manifest upload is the commit
    /// point — after every other blob is present, the manifest
    /// PUT (or `index.json` rename) is what makes the image
    /// visible. A failure here means the image stays invisible,
    /// which is the desired safety property.
    #[error("uploading manifest failed: {source}")]
    ManifestUpload {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The registry returned a non-2xx response other than the
    /// 404 that triggers an upload. `status` is the HTTP status
    /// code; `body` is a bounded slice of the response body
    /// (truncated to [`MAX_REGISTRY_BODY_PREVIEW`] bytes — a
    /// hostile registry must not fill operator memory).
    #[error("registry refused (HTTP {status}): {body}")]
    RegistryRefused { status: u16, body: String },

    /// Authentication failed. Carries the underlying source so an
    /// operator can tell "wrong password" from "no token endpoint
    /// configured" without parsing strings. Variants:
    ///
    ///   * env vars missing when [`crate::api::sink::RegistryAuth::FromEnv`]
    ///     is requested,
    ///   * registry rejected the credentials (HTTP 401 + WWW-Authenticate),
    ///   * token-exchange round trip failed (network or 401).
    #[error("authentication failed: {source}")]
    Auth {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Bubble-up from the underlying `cas` crate when the
    /// HTTP sink mounts the input image dir as a read-only
    /// `FsCas` and a blob is missing or corrupt.
    #[error("cas: {0}")]
    Cas(#[from] CasError),

    /// The input directory is not a valid OCI image layout.
    /// Examples: `oci-layout` missing, `index.json` malformed,
    /// `imageLayoutVersion != "1.0.0"`, manifest digest doesn't
    /// resolve to a blob under `blobs/sha256/`. `detail` names
    /// the specific defect so the operator can fix the producer.
    #[error("malformed image dir: {detail}")]
    MalformedImageDir { detail: String },

    /// A target path on disk could not be created (HTTP sink:
    /// `dest_dir` lives on a read-only volume, parent dir
    /// missing, etc.). `path` names the offending location.
    #[error("destination path {path:?} unusable: {source}")]
    Destination {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Cap on the body slice surfaced through [`PublishError::RegistryRefused`].
/// The registry side is untrusted; a 4 KiB preview is enough for the
/// operator to identify the failure without letting the response
/// dictate process memory.
pub const MAX_REGISTRY_BODY_PREVIEW: usize = 4 * 1024;

/// Truncate a registry response body to a bounded preview. Public
/// only inside the crate; tests assert the boundary behaviour.
pub(crate) fn preview_body(raw: &[u8]) -> String {
    let cap = raw.len().min(MAX_REGISTRY_BODY_PREVIEW);
    String::from_utf8_lossy(&raw[..cap]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: a regression where preview_body forgets the bounded
    // cap and returns the full body — letting a hostile registry
    // dictate operator memory.
    #[test]
    fn test_preview_body_caps_at_max_registry_body_preview() {
        let big = vec![b'x'; MAX_REGISTRY_BODY_PREVIEW * 2];
        let p = preview_body(&big);
        assert_eq!(p.len(), MAX_REGISTRY_BODY_PREVIEW);
    }

    // Catches: a UTF-8 sequence split mid-codepoint by a naive
    // truncate — `from_utf8_lossy` makes this safe; the test
    // documents the contract so a future "use String::truncate"
    // refactor doesn't silently regress to a panic.
    #[test]
    fn test_preview_body_handles_invalid_utf8_without_panic() {
        let mut bad = vec![0xc3, 0x28]; // invalid 2-byte sequence
        bad.extend_from_slice(b" tail");
        let p = preview_body(&bad);
        assert!(p.contains("tail"));
    }

    // Catches: someone changing PublishError::RegistryRefused's
    // Display string format and breaking CLI log parsers that
    // grep for "HTTP 4xx".
    #[test]
    fn test_registry_refused_display_includes_status_and_body() {
        let e = PublishError::RegistryRefused {
            status: 403,
            body: "denied".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("403"));
        assert!(s.contains("denied"));
    }

    // Catches: malformed image dir error losing the `detail`
    // field, which would force the operator to read the source
    // to know what was wrong.
    #[test]
    fn test_malformed_image_dir_display_carries_detail() {
        let e = PublishError::MalformedImageDir {
            detail: "oci-layout missing".into(),
        };
        assert!(format!("{e}").contains("oci-layout missing"));
    }
}
