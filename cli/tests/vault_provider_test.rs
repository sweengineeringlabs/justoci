//! Integration test for the [`VaultCredentialProvider`] against a
//! real HashiCorp Vault dev server.
//!
//! Compiled only when the parent crate is built with `--features vault`
//! (declared via `required-features = ["vault"]` in `cli/Cargo.toml`),
//! and every test inside is `#[ignore]`-gated so the default
//! `cargo test --features vault` run skips it. Operators wire it
//! into their local box with:
//!
//! ```bash
//! vault server -dev -dev-root-token-id=dev-only &
//! export VAULT_ADDR=http://127.0.0.1:8200
//! export VAULT_TOKEN=dev-only
//! cargo test -p swe_justoci_oci_cli --features vault \
//!     --test vault_provider_test -- --ignored --test-threads=1
//! ```
//!
//! The single-threaded execution is load-bearing: every test in this
//! module mutates the same `secret/data/registry/<host>` paths in
//! Vault, and parallel writes would race.
//!
//! ## What's exercised
//!
//! `test_vault_dev_server_round_trips_basic_creds` writes a
//! `username` + `password` secret to Vault, constructs the provider
//! with the same token + base path, and asserts that resolve()
//! returns the expected Basic auth header. Catches: any regression
//! that breaks the wire-side contract between `vaultrs::kv2::write`
//! and `vaultrs::kv2::read` for the secret shape we depend on
//! (e.g. a vaultrs version bump that changes the JSON envelope).

#![cfg(feature = "vault")]

use std::env;

use swe_justoci_oci_cli::registry::credential_provider::vault::{ResolvedVaultAuth, VaultProvider};
use swe_justoci_oci_cli::registry::CredentialProvider;

/// Test base path. Distinct from the production default so a
/// developer running this test against a Vault that ALSO holds
/// production secrets doesn't risk overwriting them.
const TEST_BASE_PATH: &str = "secret/data/justoci-test/registry";

/// Mount + KV-v2 prefix the test writes to. Mirrors the parsing
/// `VaultCredentialProvider` does internally so writes land on the
/// same wire path the read will hit.
const TEST_MOUNT: &str = "secret";
const TEST_PREFIX: &str = "justoci-test/registry";

/// Skip wrapper: returns `(addr, token)` if both env vars are set,
/// or prints a SKIP line and returns None otherwise. Same shape as
/// the registry_smoke_test's docker-presence check; lets CI without
/// Vault produce a green test rather than a red one.
fn vault_env_or_skip() -> Option<(String, String)> {
    let addr = env::var("VAULT_ADDR").ok().filter(|s| !s.is_empty())?;
    let token = env::var("VAULT_TOKEN").ok().filter(|s| !s.is_empty())?;
    Some((addr, token))
}

/// Write a KV v2 secret via vaultrs. The provider only ever READS,
/// so the test owns the write path itself; we drive it through the
/// same vaultrs client to ensure read+write agree on schema.
fn write_secret(addr: &str, token: &str, key: &str, payload: serde_json::Value) {
    let settings = vaultrs::client::VaultClientSettingsBuilder::default()
        .address(addr)
        .token(token)
        .build()
        .expect("vault settings build");
    let client = vaultrs::client::VaultClient::new(settings).expect("vault client new");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime
        .block_on(vaultrs::kv2::set(&client, TEST_MOUNT, key, &payload))
        .expect("vault kv2 set");
}

/// Catches: any wire-shape drift between `vaultrs::kv2::set` and
/// `vaultrs::kv2::read` that would cause the provider to round-trip
/// real Vault credentials incorrectly. The unit tests stub the
/// backend, so this is the only test that proves the production
/// `VaultrsBackend` actually talks to Vault end-to-end.
#[test]
#[ignore = "requires VAULT_ADDR + VAULT_TOKEN pointing at a dev-server"]
fn test_vault_dev_server_round_trips_basic_creds() {
    let Some((addr, token)) = vault_env_or_skip() else {
        eprintln!(
            "SKIP: VAULT_ADDR / VAULT_TOKEN not set. Run `vault server -dev` and export both."
        );
        return;
    };
    let key = format!("{TEST_PREFIX}/example.com");
    write_secret(
        &addr,
        &token,
        &key,
        serde_json::json!({
            "username": "ci-user",
            "password": "ci-secret",
        }),
    );

    // Build the provider and assert the round-trip via the typed
    // accessor (used by the CLI dispatcher).
    let provider =
        VaultProvider::new(&addr, &token, TEST_BASE_PATH).expect("vault provider construct");
    let resolved = provider
        .resolve_auth_mode("example.com")
        .expect("read must succeed against dev server")
        .expect("write happened just above so read must yield Some");
    match resolved {
        ResolvedVaultAuth::Basic { username, password } => {
            assert_eq!(username, "ci-user");
            assert_eq!(password, "ci-secret");
        }
        other => panic!("expected Basic, got {other:?}"),
    }

    // Also exercise the trait surface (used by AuthManager when the
    // provider is chained with others). This catches a regression
    // where the trait method and the typed accessor disagree on
    // what counts as a valid response.
    let creds = provider
        .resolve("example.com")
        .expect("trait resolve must succeed")
        .expect("trait resolve must yield Some");
    // base64 of `ci-user:ci-secret` → `Y2ktdXNlcjpjaS1zZWNyZXQ=`.
    assert_eq!(creds.auth_header, "Basic Y2ktdXNlcjpjaS1zZWNyZXQ=");
    assert_eq!(creds.source, "vault");
}

/// Catches: a Vault entry written with `token` (Bearer shape)
/// silently mapped to Basic, or vice versa. The provider's
/// precedence and shape detection are exercised by unit tests; this
/// test pins the wire-side contract that a real Vault accepts and
/// returns the same JSON shape we depend on.
#[test]
#[ignore = "requires VAULT_ADDR + VAULT_TOKEN pointing at a dev-server"]
fn test_vault_dev_server_round_trips_bearer_token() {
    let Some((addr, token)) = vault_env_or_skip() else {
        eprintln!(
            "SKIP: VAULT_ADDR / VAULT_TOKEN not set. Run `vault server -dev` and export both."
        );
        return;
    };
    let key = format!("{TEST_PREFIX}/bearer-host.example");
    write_secret(
        &addr,
        &token,
        &key,
        serde_json::json!({ "token": "ghp_int_test_xxxxx" }),
    );

    let provider =
        VaultProvider::new(&addr, &token, TEST_BASE_PATH).expect("vault provider construct");
    let resolved = provider
        .resolve_auth_mode("bearer-host.example")
        .expect("read must succeed")
        .expect("write happened so read must yield Some");
    match resolved {
        ResolvedVaultAuth::Bearer { token } => assert_eq!(token, "ghp_int_test_xxxxx"),
        other => panic!("expected Bearer, got {other:?}"),
    }
}

/// Catches: a real Vault returning a non-404 status when a path
/// doesn't exist (some Vault versions / proxies return 403 for
/// unreadable AND non-existent paths). The provider must observe
/// the genuine 404 path via the dev server before we trust the
/// 404 → Ok(None) mapping holds end-to-end.
#[test]
#[ignore = "requires VAULT_ADDR + VAULT_TOKEN pointing at a dev-server"]
fn test_vault_dev_server_missing_path_returns_none() {
    let Some((addr, token)) = vault_env_or_skip() else {
        eprintln!(
            "SKIP: VAULT_ADDR / VAULT_TOKEN not set. Run `vault server -dev` and export both."
        );
        return;
    };
    let provider =
        VaultProvider::new(&addr, &token, TEST_BASE_PATH).expect("vault provider construct");
    // Use a nonsense host we never wrote to — the dev server should
    // 404 on read, which the provider maps to Ok(None).
    let got = provider
        .resolve_auth_mode("does-not-exist.example.invalid")
        .expect("404 must NOT surface as Err");
    assert!(
        got.is_none(),
        "missing path must map to Ok(None), got Some({got:?})",
    );
}
