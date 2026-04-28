//! Integration tests for `ocimage verify --require-referrers`.
//!
//! The `--require-referrers` strict-mode flag (Issue #2) escalates a
//! 404 from `/v2/<repo>/referrers/<digest>` from a soft warning to a
//! hard typed error. This file owns the end-to-end coverage for both
//! the default (silent-tolerate) and strict (escalate) policies on
//! the registry-pull path.
//!
//! The pull layer is exercised via the public library API so each
//! test stands up an httpmock-faked OCI Distribution v2 endpoint
//! and asserts the typed error returned (or absence of error). We
//! don't shell out to the `ocimage` binary because the binary's
//! clap layer is already covered by `cli_exit_codes_test.rs` — the
//! contract under test here is the strict-mode wire path.
//!
//! Each test names the bug it would catch in its leading comment.

use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};

use httpmock::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use swe_justoci_oci_cli::error::CliError;
use swe_justoci_oci_cli::registry::{
    pull_anonymous_into_image_dir_with_options, PullOptions, RegistryPullError,
};

/// Serialises tests that mutate `OCIMAGE_ALLOW_INSECURE`. Same
/// pattern `registry_pull_test.rs` uses; without it, parallel tests
/// racing the env var would flake.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_sha256(bytes))
}

/// Compose the minimal three-blob OCI image manifest a pull will
/// fetch (manifest + config + one layer). Returned as
/// `(manifest_bytes, manifest_digest, config_bytes, config_digest,
///   layer_bytes, layer_digest)` so each test wires its own mocks.
struct MinimalImage {
    manifest_bytes: Vec<u8>,
    manifest_digest: String,
    config_bytes: Vec<u8>,
    config_digest: String,
    layer_bytes: Vec<u8>,
    layer_digest: String,
}

fn compose_minimal_image() -> MinimalImage {
    let config_bytes = b"{\"architecture\":\"amd64\"}".to_vec();
    let config_digest = digest_of(&config_bytes);
    let layer_bytes = b"layer-payload".to_vec();
    let layer_digest = digest_of(&layer_bytes);
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": layer_digest,
            "size": layer_bytes.len(),
        }],
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_digest = digest_of(&manifest_bytes);
    MinimalImage {
        manifest_bytes,
        manifest_digest,
        config_bytes,
        config_digest,
        layer_bytes,
        layer_digest,
    }
}

/// Mount the manifest + config + layer endpoints. The referrers
/// endpoint is intentionally NOT mounted here — each test mounts
/// its own 404 (or 200) on `/referrers/` to isolate the strict-mode
/// behaviour under test.
fn mount_image_minus_referrers(server: &MockServer, repo: &str, tag: &str, image: &MinimalImage) {
    server.mock(|when, then| {
        when.method(GET).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(200)
            .header("Docker-Content-Digest", image.manifest_digest.clone())
            .body(image.manifest_bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config_digest));
        then.status(200).body(image.config_bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layer_digest));
        then.status(200).body(image.layer_bytes.clone());
    });
}

// ── Default behaviour: 404 on referrers is silently tolerated ─────

// Catches: a regression that escalates a 404 on `/referrers/` to
// an error in the DEFAULT (no-flag) path. Pre-OCI-1.1 registries
// must keep working; an `ocimage verify ghcr.io/legacy/img:v1`
// against a registry that doesn't host attestations should still
// pull the artifact, write a complete image layout, and let the
// local-verify layer report "no referrers found" softly. Without
// this test, an over-eager fix to Issue #2 would break verify
// against every legacy registry.
#[test]
fn test_pull_404_on_referrers_default_mode_silently_tolerated() {
    let _g = env_lock();
    env::set_var("OCIMAGE_ALLOW_INSECURE", "1");

    let image = compose_minimal_image();
    let server = MockServer::start();
    let repo = "legacy/img";
    let tag = "v1";

    mount_image_minus_referrers(&server, repo, tag, &image);
    // Referrers endpoint: 404 (pre-OCI-1.1 registry shape).
    let referrers_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest_digest));
        then.status(404).body("not found");
    });

    let dest = tempfile::tempdir().unwrap();
    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());

    // Default options: require_referrers=false. The pull MUST
    // succeed — the 404 is silently treated as "no referrers".
    let opts = PullOptions::default();
    pull_anonymous_into_image_dir_with_options(&ref_str, dest.path(), &opts)
        .expect("default-mode pull must succeed despite 404 on /referrers/");

    // The referrers endpoint must have been hit (otherwise the
    // tolerated-404 path was never exercised — the test would be
    // a no-op).
    assert!(
        referrers_mock.hits() >= 1,
        "the 404 referrers mock must have been hit at least once"
    );
    // The destination must be a complete OCI Image Layout — the
    // local-verify path will read an empty referrer list from
    // index.json and report soft "missing" verdicts.
    assert!(
        dest.path().join("index.json").is_file(),
        "default-mode pull must still write index.json (the layout is complete with zero referrers)"
    );

    env::remove_var("OCIMAGE_ALLOW_INSECURE");
}

// ── Strict mode: 404 on referrers escalates to typed error ────────

// Catches: the strict-mode escalation silently regressing back to
// the soft-tolerate path. This is the entire point of Issue #2 —
// an operator who set `--require-referrers` because they refuse
// to deploy from a non-OCI-1.1 registry MUST get a hard exit-5
// failure, not a "verify reports no attestations and exits 0"
// false-success. The test asserts both the typed error variant
// AND that the variant carries the registry host + repository so
// a CI log scraper can route on the failure across a fleet of
// mirrors.
#[test]
fn test_pull_404_on_referrers_strict_mode_returns_referrers_not_supported() {
    let _g = env_lock();
    env::set_var("OCIMAGE_ALLOW_INSECURE", "1");

    let image = compose_minimal_image();
    let server = MockServer::start();
    let repo = "legacy/strict";
    let tag = "v1";

    mount_image_minus_referrers(&server, repo, tag, &image);
    // Referrers endpoint: 404 (pre-OCI-1.1 registry shape).
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest_digest));
        then.status(404).body("not found");
    });

    let dest = tempfile::tempdir().unwrap();
    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());
    let host = format!("127.0.0.1:{}", server.port());

    // Strict mode: require_referrers=true. The pull MUST fail
    // with `ReferrersNotSupported`.
    let opts = PullOptions {
        require_referrers: true,
    };
    let err = pull_anonymous_into_image_dir_with_options(&ref_str, dest.path(), &opts)
        .expect_err("strict-mode pull must fail on 404 referrers");

    match err {
        RegistryPullError::ReferrersNotSupported {
            registry,
            repository,
        } => {
            assert_eq!(
                registry, host,
                "ReferrersNotSupported must carry the registry host so a CI log scraper can route per-mirror, got {registry:?}",
            );
            assert_eq!(
                repository, repo,
                "ReferrersNotSupported must carry the repository path so an operator can audit per-repo support, got {repository:?}",
            );
        }
        other => panic!("expected ReferrersNotSupported, got {other:?}"),
    }

    // CRITICAL: index.json MUST NOT be written on the strict-mode
    // failure. The atomicity contract says until index.json lands,
    // no consumer can read the layout as complete; a strict-mode
    // failure that writes index.json anyway would let a downstream
    // consumer pick up a referrer-less layout as if it were valid.
    assert!(
        !dest.path().join("index.json").is_file(),
        "strict-mode failure must NOT write index.json (else consumers see a referrer-less artifact as complete)",
    );

    env::remove_var("OCIMAGE_ALLOW_INSECURE");
}

// Catches: a strict-mode regression that triggers
// `ReferrersNotSupported` on registries that DO support the
// referrers API but happen to return zero attestations. The OCI
// 1.1 spec requires a 200 with an empty `manifests` array in this
// case — escalating it to "registry doesn't support referrers"
// would be a false alarm for any well-behaved registry hosting
// an unsigned artifact. Without this test, a reviewer might
// "simplify" the strict-mode check to "any non-2xx" and silently
// break verify against well-behaved-but-unattested artifacts.
#[test]
fn test_pull_strict_mode_accepts_200_with_empty_referrers_list() {
    let _g = env_lock();
    env::set_var("OCIMAGE_ALLOW_INSECURE", "1");

    let image = compose_minimal_image();
    let server = MockServer::start();
    let repo = "modern/empty";
    let tag = "v1";

    mount_image_minus_referrers(&server, repo, tag, &image);
    // Referrers endpoint: 200 with empty manifests array.
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest_digest));
        then.status(200).body(
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [],
            }))
            .unwrap(),
        );
    });

    let dest = tempfile::tempdir().unwrap();
    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());

    let opts = PullOptions {
        require_referrers: true,
    };
    pull_anonymous_into_image_dir_with_options(&ref_str, dest.path(), &opts)
        .expect("strict mode must accept a 200 with empty referrers (registry supports the API; artifact has no attestations)");

    // The pull succeeded → index.json is written. Strict mode is
    // about API support, not attestation presence.
    assert!(
        dest.path().join("index.json").is_file(),
        "strict mode + 200-with-empty-referrers must produce a complete layout",
    );

    env::remove_var("OCIMAGE_ALLOW_INSECURE");
}

// ── Verify-dispatch level: --require-referrers maps to exit 5 ─────

// Catches: a wiring regression where the CLI's
// `--require-referrers` clap flag is parsed but never threaded
// into the pull layer — the flag would silently be a no-op and
// every strict-mode invocation would falsely report success.
// This test exercises the full verify dispatch (auth resolution
// + tempdir + pull) and asserts that the typed
// `RegistryPullError::ReferrersNotSupported` propagates through
// `CliError::RegistryPull` (exit code 5) when the flag is set.
#[test]
fn test_verify_dispatch_strict_mode_returns_cli_error_registry_pull() {
    use swe_justoci_oci_cli::cmd::verify;

    let _g = env_lock();
    env::set_var("OCIMAGE_ALLOW_INSECURE", "1");

    let image = compose_minimal_image();
    let server = MockServer::start();
    let repo = "legacy/dispatch";
    let tag = "v1";

    mount_image_minus_referrers(&server, repo, tag, &image);
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest_digest));
        then.status(404).body("not found");
    });

    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());

    let opts = verify::VerifyOptions {
        require_referrers: true,
    };
    let err = verify::run_with_options(&ref_str, None, verify::VerifyAuthMode::Anonymous, &opts)
        .expect_err("strict-mode verify must fail on 404 referrers");

    match err {
        CliError::RegistryPull(RegistryPullError::ReferrersNotSupported { .. }) => {
            // Expected: typed pull-layer error propagated through
            // the CLI surface. CliError::RegistryPull maps to exit
            // 5 per spec doc §7.
            assert_eq!(
                err.exit_code(),
                5,
                "ReferrersNotSupported MUST exit 5 (verify-class failure), not 4 (publish-class) or 64 (catastrophic)",
            );
        }
        other => panic!("expected CliError::RegistryPull(ReferrersNotSupported), got {other:?}",),
    }

    env::remove_var("OCIMAGE_ALLOW_INSECURE");
}

// Catches: the default-mode dispatch regressing — verify with no
// `--require-referrers` against a 404-referrers registry MUST
// continue past the pull layer. The pull succeeds, then the
// local-verify path runs against the empty-referrer layout. The
// final outcome may still be a `CliError::Verify` (because no
// attestation pillars exist), but that's a verify-engine call,
// NOT a `RegistryPull(ReferrersNotSupported)` — confirming the
// flag is genuinely opt-in.
#[test]
fn test_verify_dispatch_default_mode_does_not_return_referrers_not_supported() {
    use swe_justoci_oci_cli::cmd::verify;

    let _g = env_lock();
    env::set_var("OCIMAGE_ALLOW_INSECURE", "1");

    let image = compose_minimal_image();
    let server = MockServer::start();
    let repo = "legacy/default-dispatch";
    let tag = "v1";

    mount_image_minus_referrers(&server, repo, tag, &image);
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest_digest));
        then.status(404).body("not found");
    });

    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());

    // Default options (require_referrers=false). The pull layer
    // tolerates the 404; the local-verify layer reports zero
    // pillars Found. Whatever the FINAL outcome is, it MUST NOT
    // be a `RegistryPull(ReferrersNotSupported)` — that would
    // mean the strict-mode escalation fired without the flag.
    let result = verify::run_with_options(
        &ref_str,
        None,
        verify::VerifyAuthMode::Anonymous,
        &verify::VerifyOptions::default(),
    );
    match result {
        Ok(_report) => {
            // Verify completed without error → exit 0, missing
            // pillars reported informationally. That's the
            // documented v0.2 default behaviour for unattested
            // artifacts pulled from a 404-referrers registry.
        }
        Err(CliError::Verify(_)) => {
            // Acceptable too: a verify-engine failure (e.g. the
            // local layout's pillars couldn't be classified). It
            // is NOT a registry-pull failure.
        }
        Err(CliError::RegistryPull(RegistryPullError::ReferrersNotSupported { .. })) => {
            panic!(
                "default-mode verify must NOT escalate 404-referrers to ReferrersNotSupported; \
                 the flag is opt-in",
            );
        }
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }

    env::remove_var("OCIMAGE_ALLOW_INSECURE");
}
