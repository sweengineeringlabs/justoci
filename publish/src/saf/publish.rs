//! `publish` — public dispatch over [`PublishSink`].
//!
//! This is intentionally thin: validate input is reachable + non-trivial,
//! delegate to the matching core impl, propagate the typed outcome.

use crate::api::error::PublishError;
use crate::api::image_dir::ImageDir;
use crate::api::sink::{PublishOutcome, PublishSink};
use crate::core::{http_sink, registry_sink};

/// Publish `image` to `sink`. The single public entry point of
/// the crate.
///
/// Behaviour by sink:
///   * [`PublishSink::Http`]     — see [`crate::core::http_sink::publish_http`].
///   * [`PublishSink::Registry`] — see [`crate::core::registry_sink::publish_registry`].
///
/// Both paths are resumable per ADR-015 production guarantee §6:
/// re-publishing the same image yields a [`PublishOutcome`] in
/// which every digest lands in `digests_skipped`.
pub fn publish(image: &ImageDir, sink: &PublishSink) -> Result<PublishOutcome, PublishError> {
    match sink {
        PublishSink::Http { dest_dir } => http_sink::publish_http(image, dest_dir),
        PublishSink::Registry {
            registry,
            repository,
            tag,
            auth,
        } => {
            // Defensive validation of the wire-level identifiers.
            // The OCI Distribution spec restricts repository names
            // and tags; an empty string here would let the publish
            // hit a malformed URL and surface a confusing 404 from
            // the registry.
            check_registry_field("registry", registry)?;
            check_registry_field("repository", repository)?;
            check_registry_field("tag", tag)?;
            registry_sink::publish_registry(image, registry, repository, tag, auth.clone())
        }
    }
}

fn check_registry_field(name: &str, value: &str) -> Result<(), PublishError> {
    if value.is_empty() {
        return Err(PublishError::MalformedImageDir {
            detail: format!(
                "PublishSink::Registry.{name} is empty — expected a non-empty value"
            ),
        });
    }
    if value.contains(char::is_whitespace) {
        return Err(PublishError::MalformedImageDir {
            detail: format!(
                "PublishSink::Registry.{name} contains whitespace, which OCI Distribution v2 forbids: {value:?}"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Catches: publish() forwarding an empty registry/repository/tag
    // to the wire layer, where it surfaces as a confusing 404 from
    // the registry instead of a clean local error.
    #[test]
    fn test_publish_rejects_empty_registry_field() {
        // We can't construct a fully validated ImageDir without the
        // tempdir-fixture infra (lives in tests/). Test the field
        // checker directly — the failure path doesn't depend on
        // ImageDir at all.
        let err = check_registry_field("registry", "").unwrap_err();
        match err {
            PublishError::MalformedImageDir { detail } => {
                assert!(detail.contains("empty"));
            }
            other => panic!("expected MalformedImageDir, got {other:?}"),
        }
    }

    // Catches: a registry name with embedded whitespace landing in
    // a URL — silent quoting would turn `bad name` into `bad%20name`
    // which won't resolve.
    #[test]
    fn test_publish_rejects_whitespace_in_registry_field() {
        let err = check_registry_field("repository", "acme/has space").unwrap_err();
        match err {
            PublishError::MalformedImageDir { detail } => {
                assert!(detail.contains("whitespace"));
            }
            other => panic!("expected MalformedImageDir, got {other:?}"),
        }
    }

    // Documentation-only smoke: PublishSink::Http variant builds.
    // (The real test is the http_publish_full_test integration test;
    // this only catches a regression where the variant signature
    // changes.)
    #[test]
    fn test_publish_sink_http_variant_constructable() {
        let _s = PublishSink::Http {
            dest_dir: PathBuf::from("/tmp/x"),
        };
    }
}
