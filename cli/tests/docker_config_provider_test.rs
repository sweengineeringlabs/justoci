//! Integration test for the [`DockerConfigProvider`] against a real
//! on-disk `config.json`.
//!
//! Compiled only when the parent crate is built with
//! `--features docker-config` (declared via
//! `required-features = ["docker-config"]` in `cli/Cargo.toml`).
//! Unlike the Vault integration test, this one needs no external
//! service: every test stages a tempdir, writes a fixture
//! `config.json`, and points the provider at it.
//!
//! ## What's exercised
//!
//! The unit tests under
//! `cli/src/registry/credential_provider/docker_config.rs::tests`
//! stub the [`DockerConfigBackend`] trait and exercise the entry
//! mapping logic exhaustively. THIS test exists because the unit
//! tests never touch the filesystem — they could pass even if
//! [`DockerConfigFsBackend`] had a bug in its byte-level path
//! resolution, JSON parse boundary, or `NotFound` IO mapping.
//!
//! Catches: any wire-shape drift between writing a `config.json`
//! and reading it back via the provider's real-filesystem backend.

#![cfg(feature = "docker-config")]

use std::fs;

use swe_justoci_oci_cli::registry::credential_provider::docker_config::{
    DockerConfigProvider, ResolvedDockerAuth,
};
use swe_justoci_oci_cli::registry::CredentialProvider;

/// Catches: a regression where the FS backend's `serde_json` parse
/// or path resolution silently corrupts the round-trip from a
/// real on-disk `config.json` to a `ResolvedDockerAuth::Basic`
/// emitted by the provider. Without this test, every unit test
/// could pass even if the FS backend were broken.
#[test]
fn test_real_config_round_trips_basic_auth() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    // base64('admin:hunter2') = `YWRtaW46aHVudGVyMg==`
    let body = serde_json::json!({
        "auths": {
            "ghcr.io": { "auth": "YWRtaW46aHVudGVyMg==" }
        }
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();

    let provider = DockerConfigProvider::from_path(&path);
    let resolved = provider
        .resolve_auth_mode("ghcr.io")
        .expect("read must succeed against the staged config")
        .expect("ghcr.io was just written so read must yield Some");
    match resolved {
        ResolvedDockerAuth::Basic { username, password } => {
            assert_eq!(username, "admin");
            assert_eq!(password, "hunter2");
        }
        other => panic!("expected Basic, got {other:?}"),
    }

    // Also exercise the trait surface (used by AuthManager when the
    // provider is chained). This catches a regression where the
    // trait method and the typed accessor disagree on what counts
    // as a valid entry.
    let creds = provider
        .resolve("ghcr.io")
        .expect("trait resolve must succeed")
        .expect("trait resolve must yield Some");
    assert_eq!(creds.auth_header, "Basic YWRtaW46aHVudGVyMg==");
    assert_eq!(creds.source, "docker-config");
}

/// Catches: a regression in the explicit `username`+`password`
/// schema branch. Some tools (older `docker login`,
/// `podman login --authfile`) write that shape instead of `auth`;
/// proving the FS backend round-trips it pins the wire-side
/// contract for those tools.
#[test]
fn test_real_config_round_trips_explicit_userpass() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    let body = serde_json::json!({
        "auths": {
            "registry.acme.io": {
                "username": "ci-user",
                "password": "ci-secret"
            }
        }
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();

    let provider = DockerConfigProvider::from_path(&path);
    let resolved = provider
        .resolve_auth_mode("registry.acme.io")
        .expect("must succeed")
        .expect("must yield Some");
    match resolved {
        ResolvedDockerAuth::Basic { username, password } => {
            assert_eq!(username, "ci-user");
            assert_eq!(password, "ci-secret");
        }
        other => panic!("expected Basic, got {other:?}"),
    }
}

/// Catches: a non-existent `config.json` bubbling up as `Err` on
/// the FS backend rather than the documented `Ok(None)`. The
/// provider's contract is that a missing file is a soft signal
/// (operator never ran `docker login`) — the chain walker must
/// continue.
#[test]
fn test_missing_config_returns_ok_none() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("does-not-exist.json");
    assert!(!path.exists(), "fixture path must be missing for this test");

    let provider = DockerConfigProvider::from_path(&path);
    let got = provider
        .resolve_auth_mode("ghcr.io")
        .expect("missing config file must NOT surface as Err");
    assert!(
        got.is_none(),
        "missing config.json must map to Ok(None); got Some({got:?})",
    );
}

/// Catches: the FS backend silently treating a malformed
/// `config.json` as "no creds, fall through" — which would mask
/// the operator's data corruption (e.g. a truncated write, a
/// stray BOM). The contract is `ProviderFailed`, not `Ok(None)`.
#[test]
fn test_malformed_config_returns_provider_failed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    // Not valid JSON.
    fs::write(&path, b"this is not json {").unwrap();

    let provider = DockerConfigProvider::from_path(&path);
    let err = provider
        .resolve_auth_mode("ghcr.io")
        .expect_err("malformed JSON must surface, not silently fall through");
    let s = format!("{err}");
    assert!(
        s.contains("docker-config") && (s.contains("JSON") || s.contains("valid")),
        "error must name the provider AND the JSON problem; got {s:?}",
    );
}
