//! Integration tests for `ocimage::push_oci`.
//!
//! # Test strategy: (b) env-gated real registry
//!
//! The ADR-015 §Level-4 push path needs a real OCI registry to
//! exercise the wire. This test stays silent (skipped with a
//! `println!` note) unless all three of
//!
//!   * `OCIMAGE_INT_TEST_REGISTRY` — e.g. `localhost:5000`
//!   * `OCIMAGE_INT_TEST_USER`     — basic-auth username (or anything)
//!   * `OCIMAGE_INT_TEST_PASSWORD` — basic-auth password
//!
//! are set. When they are set, the test builds a tiny synthetic
//! `BuildArtifacts` directory (kernel / initrd.cpio / config.json —
//! rootfs-less to keep bytes small), pushes, and asserts the
//! returned `OciPushSummary` is internally consistent.
//!
//! Rationale for (b) over (a)/wiremock:
//!   * oci-distribution's push path issues a sequence of HEAD /
//!     POST / PATCH / PUT / PUT requests, each with digest
//!     matching against the live blob data. Mocking that faithfully
//!     reproduces the protocol in-test, which would pin us to the
//!     v0.11 wire shape — brittle across oci-distribution updates.
//!   * A real registry (e.g. `docker run -p 5000:5000 registry:2`)
//!     validates against the actual distribution spec, which is
//!     what we actually care about.
//!   * CI can stand up a `registry:2` sidecar and flip the env
//!     vars to cover the wire; local dev gets the happy-path tests
//!     in the unit-test module of `oci_pusher.rs`.
//!
//! # Talking to a plain-HTTP local registry
//!
//! `oci-distribution`'s default client is HTTPS-only (webpki-roots
//! bundle via `rustls-tls`), so `registry:2` on `localhost:5000`
//! speaks HTTP and the default client refuses to dial it. Set
//!
//!   * `OCIMAGE_ALLOW_INSECURE=1`
//!
//! alongside the three env vars above to flip the client to
//! `ClientProtocol::Http`. This is a CI/dev escape hatch only;
//! never set it against a production registry.
//!
//! The non-gated tests below cover the operator-error surface
//! (missing artifacts, invalid reference) which don't need a
//! registry at all — they fail before any network I/O.

use std::fs;
use std::path::PathBuf;

use oci_publish::{push_oci, Error};

/// Write a minimally valid `BuildArtifacts`-shaped directory under
/// `dir` so `load_from_dir` succeeds. Used by tests that need a
/// real input path — they don't care about blob contents.
fn scaffold_build_dir(dir: &std::path::Path) {
    fs::create_dir_all(dir).expect("create build dir");
    fs::write(dir.join("kernel"), b"fake-kernel-bytes").unwrap();
    fs::write(dir.join("initrd.cpio"), b"fake-initrd-bytes").unwrap();
    fs::write(
        dir.join("config.json"),
        br#"{"schema_version":1,"id":"int-test:1"}"#,
    )
    .unwrap();
}

/// Temporary directory unique per test — no `tempfile` dep, so we
/// use `std::env::temp_dir()` + the test's name. `std::env::temp_dir`
/// returns a process-wide tempdir; adding a unique suffix keeps
/// parallel `cargo test` invocations apart.
fn unique_temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let d = std::env::temp_dir()
        .join(format!("ocimage-int-{}-{}", tag, nanos));
    fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------------
// Test 1: invalid reference — registry-free, always runs.
//
// Catches: someone wrapping `Reference::try_from` failure in
// `Error::RegistryUnreachable`, which would misroute a bad-ref CLI
// invocation to a network-retry loop instead of a fast exit.
// ---------------------------------------------------------------------
#[test]
fn test_push_oci_rejects_invalid_reference_with_publish_error() {
    let build_dir = unique_temp_dir("bad-ref");
    scaffold_build_dir(&build_dir);

    // Empty string — trivially unparseable as an OCI reference.
    let result = push_oci(&build_dir, "");
    match result {
        Err(Error::Publish { reason }) => {
            assert!(
                reason.contains("invalid reference"),
                "reason must name the class of failure, got: {}",
                reason,
            );
        }
        other => panic!(
            "expected Error::Publish for bad reference, got: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&build_dir);
}

// ---------------------------------------------------------------------
// Test 2: missing artifact in build_dir — registry-free, always runs.
//
// Catches: a regression where `push_oci` skips the BuildArtifacts
// load-and-check and goes straight to the network, which would
// produce a confusing "no such file" inside the push flow instead
// of a clean ArtifactMissing up front.
// ---------------------------------------------------------------------
#[test]
fn test_push_oci_reports_artifact_missing_when_build_dir_incomplete() {
    let build_dir = unique_temp_dir("missing-artifact");
    // Deliberately only write the kernel — initrd.cpio is absent.
    fs::write(build_dir.join("kernel"), b"x").unwrap();

    let result = push_oci(&build_dir, "ghcr.io/acme/x:1");
    match result {
        Err(Error::ArtifactMissing { which, .. }) => {
            assert_eq!(
                which, "initrd.cpio",
                "must report the first missing artifact, not a generic error",
            );
        }
        other => panic!(
            "expected Error::ArtifactMissing, got: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&build_dir);
}

// ---------------------------------------------------------------------
// Test 3: end-to-end push against a live registry — ENV-GATED.
//
// Catches: any bug in the wire format (media types, manifest schema,
// auth handshake, chunked upload) that the unit tests can't see.
// Skipped unless the operator opts in via the three env vars — see
// the module-level doc for the rationale.
// ---------------------------------------------------------------------
#[test]
fn test_push_oci_wire_push_against_live_registry() {
    let registry = match std::env::var("OCIMAGE_INT_TEST_REGISTRY") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            println!(
                "[skip] test_push_oci_wire_push_against_live_registry: \
                 set OCIMAGE_INT_TEST_REGISTRY + _USER + _PASSWORD to run.",
            );
            return;
        }
    };
    let user = match std::env::var("OCIMAGE_INT_TEST_USER") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            println!(
                "[skip] test_push_oci_wire_push_against_live_registry: \
                 OCIMAGE_INT_TEST_USER unset.",
            );
            return;
        }
    };
    let password = match std::env::var("OCIMAGE_INT_TEST_PASSWORD") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            println!(
                "[skip] test_push_oci_wire_push_against_live_registry: \
                 OCIMAGE_INT_TEST_PASSWORD unset.",
            );
            return;
        }
    };

    let build_dir = unique_temp_dir("live-push");
    scaffold_build_dir(&build_dir);

    // Export creds via the `ocimage` standard env vars (what
    // `OciPusher::new` reads). Snapshot + restore afterwards so
    // we don't pollute sibling tests.
    let prev_user = std::env::var("OCIMAGE_REGISTRY_USER").ok();
    let prev_pass = std::env::var("OCIMAGE_REGISTRY_PASSWORD").ok();
    std::env::set_var("OCIMAGE_REGISTRY_USER", &user);
    std::env::set_var("OCIMAGE_REGISTRY_PASSWORD", &password);

    // Unique tag per run so repeated CI runs don't false-positive
    // on a pre-existing manifest.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let reference = format!("{}/ocimage/int-test:{}", registry, nanos);

    let summary = push_oci(&build_dir, &reference)
        .expect("live push against configured registry should succeed");

    assert_eq!(summary.reference, reference);
    assert!(
        summary.manifest_digest.starts_with("sha256:"),
        "manifest_digest must be sha256-prefixed, got: {}",
        summary.manifest_digest,
    );
    assert_eq!(
        summary.manifest_digest.len(),
        "sha256:".len() + 64,
        "sha256 hex must be 64 chars, got: {}",
        summary.manifest_digest,
    );
    assert!(
        summary.bytes_pushed > 0,
        "something must have been pushed — got 0 bytes",
    );

    // Restore env.
    std::env::remove_var("OCIMAGE_REGISTRY_USER");
    std::env::remove_var("OCIMAGE_REGISTRY_PASSWORD");
    if let Some(v) = prev_user {
        std::env::set_var("OCIMAGE_REGISTRY_USER", v);
    }
    if let Some(v) = prev_pass {
        std::env::set_var("OCIMAGE_REGISTRY_PASSWORD", v);
    }

    let _ = fs::remove_dir_all(&build_dir);
}
