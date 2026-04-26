//! Typed failure surface for the registry-pull path.
//!
//! Every variant carries enough context for an operator to act:
//! which URL was being requested, which digest mismatched, which
//! registry returned a non-2xx + a bounded preview of the body.
//!
//! `RegistryPullError` folds into [`crate::error::CliError::RegistryPull`]
//! at the CLI boundary; pull-as-library callers can match the
//! structured form directly.

use std::path::PathBuf;

/// Cap on the body slice surfaced through [`RegistryPullError::RegistryRefused`].
/// The registry side is untrusted; a 4 KiB preview is enough for the
/// operator to identify the failure without letting the response
/// dictate process memory. Mirrors `oci_publish::error::MAX_REGISTRY_BODY_PREVIEW`.
pub const MAX_REGISTRY_BODY_PREVIEW: usize = 4 * 1024;

/// Errors raised by the registry-pull path.
#[derive(Debug, thiserror::Error)]
pub enum RegistryPullError {
    /// The reference string didn't parse as `host[:port]/repo:tag`
    /// or `@sha256:<hex>`. `got` is the operator's exact input;
    /// `reason` names the specific defect.
    #[error("malformed registry ref {got:?}: {reason}")]
    MalformedRef { got: String, reason: String },

    /// `GET /v2/<repo>/manifests/<ref>` failed at the network /
    /// transport level. The chained `source` carries the reqwest
    /// error so error chains render the underlying cause.
    #[error("resolving manifest at {manifest_url}: {source}")]
    Resolve {
        manifest_url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// `GET /v2/<repo>/blobs/<digest>` failed at the network /
    /// transport level. `digest` is the exact blob the pull was
    /// fetching.
    #[error("fetching blob {digest}: {source}")]
    BlobFetch {
        digest: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// **The integrity-check failure.** The registry served bytes
    /// for `blob` whose sha256 did not match the descriptor's
    /// `expected` digest. We never write a tampered blob to disk —
    /// the hasher rejects on the fly. This is the moat that makes
    /// registry-pull verify meaningful: without it, a malicious
    /// registry could swap any blob's content.
    #[error("digest mismatch on blob {blob}: expected {expected}, got {got}")]
    DigestMismatch {
        expected: String,
        got: String,
        blob: String,
    },

    /// The registry returned a non-2xx response. `status` is the
    /// HTTP status; `body` is a bounded slice of the response body
    /// (truncated to [`MAX_REGISTRY_BODY_PREVIEW`]).
    #[error("registry refused {url} (HTTP {status}): {body}")]
    RegistryRefused {
        url: String,
        status: u16,
        body: String,
    },

    /// Authentication failed: env vars unset when env-mode auth was
    /// requested, registry rejected the credentials with 401 and the
    /// re-authenticated retry also failed, token-realm exchange
    /// network error.
    #[error("authentication failed: {source}")]
    Auth {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Filesystem I/O failure writing to the destination tempdir.
    /// `path` names the offending location (a blob path or
    /// `index.json` / `oci-layout`).
    #[error("i/o at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The manifest or referrer-index JSON the registry returned
    /// didn't parse as the OCI shape we expected. `detail` names
    /// the specific defect (missing field, wrong type).
    #[error("malformed manifest from registry: {detail}")]
    MalformedManifest { detail: String },
}

/// Truncate a registry response body to a bounded preview. Returns a
/// lossy-decoded string (a registry that streams non-UTF-8 still
/// produces a readable error). Internal — tests assert the boundary.
pub(crate) fn preview_body_capped(raw: &[u8]) -> String {
    let cap = raw.len().min(MAX_REGISTRY_BODY_PREVIEW);
    String::from_utf8_lossy(&raw[..cap]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: preview_body_capped forgetting the bounded cap and
    // letting a hostile registry dictate operator memory. Same
    // safety property publish enforces; mirroring it here pins the
    // contract on the pull side too.
    #[test]
    fn test_preview_body_capped_truncates_at_max() {
        let big = vec![b'x'; MAX_REGISTRY_BODY_PREVIEW * 2];
        let p = preview_body_capped(&big);
        assert_eq!(p.len(), MAX_REGISTRY_BODY_PREVIEW);
    }

    // Catches: a Display impl that drops the operator-actionable
    // bits (the URL and HTTP status) — a CI log scraper would lose
    // the signal it routes on.
    #[test]
    fn test_registry_refused_display_carries_url_and_status() {
        let e = RegistryPullError::RegistryRefused {
            url: "https://r.example/v2/foo/manifests/v1".into(),
            status: 404,
            body: "manifest unknown".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("404"));
        assert!(s.contains("manifest unknown"));
        assert!(s.contains("v2/foo/manifests/v1"));
    }

    // Catches: a Display impl that drops the digests on a mismatch
    // — without both digests the operator can't tell whether the
    // tampering was at the layer or the manifest level.
    #[test]
    fn test_digest_mismatch_display_carries_both_digests() {
        let e = RegistryPullError::DigestMismatch {
            expected: "sha256:aaa".into(),
            got: "sha256:bbb".into(),
            blob: "layer[2]".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("sha256:aaa"));
        assert!(s.contains("sha256:bbb"));
        assert!(s.contains("layer[2]"));
    }
}
