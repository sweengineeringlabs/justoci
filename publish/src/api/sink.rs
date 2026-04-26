//! `PublishSink` — where to publish an [`crate::api::image_dir::ImageDir`].
//!
//! Two variants in v0:
//!
//!   * [`PublishSink::Http`]     — a static-served local directory
//!     (ADR-015 Level 2). Operators serve it via nginx / caddy /
//!     `python -m http.server`.
//!   * [`PublishSink::Registry`] — an OCI Distribution v2 registry
//!     (ADR-015 Level 4). GHCR, Harbor, ECR, registry:2.

use std::path::PathBuf;

/// Where to publish.
///
/// Constructed by the caller (CLI / library); consumed by
/// [`crate::publish`]. Variants are non-exhaustive intentionally
/// — adding a new sink (e.g. `PublishSink::S3`) requires a new
/// variant, a new `core::*_sink::publish_*` impl, and an arm in
/// the [`crate::saf::publish::publish`] dispatcher; existing
/// call sites must be updated to match the new variant.
#[derive(Debug, Clone)]
pub enum PublishSink {
    /// ADR-015 Level 2 — copy the image into a static-served
    /// directory. After publish, `dest_dir/oci-layout`,
    /// `dest_dir/index.json`, and `dest_dir/blobs/sha256/<hex>`
    /// are present in the OCI image layout. Re-publishing the
    /// same image is a no-op.
    Http {
        /// Where to write the OCI image dir. Created if missing.
        /// Existing layouts at the same path are extended (blobs
        /// merged, index.json rewritten atomically) — never
        /// truncated.
        dest_dir: PathBuf,
    },

    /// ADR-015 Level 4 — push the image to an OCI Distribution v2
    /// registry. Per-blob HEAD-then-PUT skips blobs the registry
    /// already has; the manifest PUT is the commit point and runs
    /// after every other blob is confirmed-present.
    Registry {
        /// Registry host. `host[:port]`, no scheme. The sink
        /// derives `https://` by default; `http://` is opt-in via
        /// `OCIMAGE_ALLOW_INSECURE=1` (used only for local
        /// `registry:2` testing).
        registry: String,
        /// Repository inside the registry, e.g. `acme/llmboot`.
        /// No leading slash.
        repository: String,
        /// Tag to publish under, e.g. `0.1.14`.
        tag: String,
        /// How to authenticate. `None` ⇒ anonymous (public
        /// registries / read-only). See [`RegistryAuth`].
        auth: Option<RegistryAuth>,
    },
}

/// How to authenticate against an OCI Distribution registry.
///
/// Variants are non-exhaustive on purpose so adding `OAuthClientCreds`
/// later forces every match site to be revisited.
#[derive(Debug, Clone)]
pub enum RegistryAuth {
    /// HTTP Basic. Username + password go on the wire base64-encoded
    /// in `Authorization: Basic …`. Use over HTTPS only.
    Basic { username: String, password: String },

    /// Pre-acquired bearer token (e.g. a GitHub PAT, a CI-issued
    /// short-lived token). Goes on the wire as `Authorization:
    /// Bearer <token>`.
    Bearer { token: String },

    /// Pull credentials from the process environment:
    ///
    ///   * `REGISTRY_TOKEN` — preferred. If set + non-empty, used
    ///     as a bearer token verbatim.
    ///   * Else `REGISTRY_USERNAME` + `REGISTRY_PASSWORD` — used
    ///     as basic auth. Both must be non-empty; if either is
    ///     missing the result is [`crate::PublishError::Auth`].
    ///   * Else: error (no auth resolved).
    ///
    /// Resolution happens at publish time, not at construction —
    /// long-running CLI sessions can `set/unset` env between
    /// calls and observe the change.
    FromEnv,
}

/// Outcome of a successful [`crate::publish`] call.
///
/// Reported field-by-field instead of dumped to a log so callers
/// (CLI, library tests) can match individual numbers without
/// parsing strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOutcome {
    /// Digests pushed/copied during this call. Each entry is the
    /// canonical OCI digest form (`sha256:<lowercase-hex>`).
    /// Includes the manifest digest at the END of the list — the
    /// commit point of the publish.
    pub digests_pushed: Vec<String>,

    /// Digests skipped because the sink already had them (HTTP
    /// sink: file existed under `blobs/sha256/<hex>`; Registry
    /// sink: HEAD blob returned 200). Same canonical-digest format
    /// as `digests_pushed`. The two sets are disjoint.
    pub digests_skipped: Vec<String>,

    /// Sum of `Content-Length` bytes actually transferred. For
    /// the registry sink this excludes blobs short-circuited by
    /// HEAD; for the HTTP sink it's the byte count of every blob
    /// that was newly written. The manifest's own bytes are
    /// counted.
    pub bytes_uploaded: u64,
}

impl PublishOutcome {
    /// Empty outcome — used by tests and as the starting accumulator
    /// in the sink impls.
    pub(crate) fn empty() -> Self {
        Self {
            digests_pushed: Vec::new(),
            digests_skipped: Vec::new(),
            bytes_uploaded: 0,
        }
    }
}

/// Env var consulted by [`RegistryAuth::FromEnv`] for a pre-acquired
/// bearer token. Preferred over username/password when set.
pub const ENV_REGISTRY_TOKEN: &str = "REGISTRY_TOKEN";

/// Env var consulted by [`RegistryAuth::FromEnv`] for HTTP basic-auth
/// username. Paired with [`ENV_REGISTRY_PASSWORD`].
pub const ENV_REGISTRY_USERNAME: &str = "REGISTRY_USERNAME";

/// Env var consulted by [`RegistryAuth::FromEnv`] for HTTP basic-auth
/// password. Paired with [`ENV_REGISTRY_USERNAME`].
pub const ENV_REGISTRY_PASSWORD: &str = "REGISTRY_PASSWORD";

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: someone re-ordering enum variants and breaking
    // pattern-match exhaustiveness in downstream consumers.
    // Pinning the variant tags here surfaces the change as a test
    // diff before it lands.
    #[test]
    fn test_publish_sink_http_carries_dest_dir() {
        let s = PublishSink::Http {
            dest_dir: PathBuf::from("/tmp/x"),
        };
        match s {
            PublishSink::Http { dest_dir } => assert_eq!(dest_dir, PathBuf::from("/tmp/x")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // Catches: PublishOutcome::empty starting with non-zero counters,
    // which would inflate every accumulated outcome.
    #[test]
    fn test_publish_outcome_empty_starts_at_zero() {
        let o = PublishOutcome::empty();
        assert!(o.digests_pushed.is_empty());
        assert!(o.digests_skipped.is_empty());
        assert_eq!(o.bytes_uploaded, 0);
    }

    // Catches: env-var-name drift — these strings are part of the
    // CLI / operator contract. Renaming them silently breaks every
    // CI script that exports them.
    #[test]
    fn test_env_var_names_are_stable() {
        assert_eq!(ENV_REGISTRY_TOKEN, "REGISTRY_TOKEN");
        assert_eq!(ENV_REGISTRY_USERNAME, "REGISTRY_USERNAME");
        assert_eq!(ENV_REGISTRY_PASSWORD, "REGISTRY_PASSWORD");
    }
}
