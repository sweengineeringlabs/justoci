//! Registry-pull integration tests for `justoci verify <registry-ref>`.
//!
//! Each test stands up an httpmock-faked OCI Distribution v2
//! endpoint, pre-stages the manifests + blobs the pull will fetch,
//! and asserts the on-disk OCI Image Layout that emerges in the
//! tempdir. The pull layer is exercised via the public library API
//! ([`swe_justoci_oci_cli::registry::pull_into_image_dir`] and
//! `pull_anonymous_into_image_dir`) — we don't shell out to the
//! `justoci` binary because the binary's clap layer is tested
//! separately and the pull contract is at the library boundary.
//!
//! Every test names the bug it would catch in its leading comment;
//! a test that just asserts "didn't crash" is not in this file.

use std::env;
use std::fs;
use std::sync::{Mutex, MutexGuard, OnceLock};

use httpmock::prelude::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use oci_publish::{ImageDir, RegistryAuth};

use swe_justoci_oci_cli::cmd::publish::AuthMode;
use swe_justoci_oci_cli::cmd::verify::VerifyAuthMode;
use swe_justoci_oci_cli::error::CliError;
use swe_justoci_oci_cli::registry::{
    parse_registry_ref, pull_anonymous_into_image_dir, pull_into_image_dir, RefTarget,
    RegistryPullError,
};

/// Serialises tests in this file that mutate `JUSTOCI_ALLOW_INSECURE`.
/// Same pattern publish's registry tests use; without it, parallel
/// tests racing the env var would flake.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Hex-of-sha256(bytes). Lower-case 64 chars.
fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_sha256(bytes))
}

/// One blob: bytes + digest + size. Returned by `Fixture::compose`
/// so individual tests can assert per-blob digests round-trip
/// through the pull pipeline.
#[derive(Clone)]
struct Blob {
    bytes: Vec<u8>,
    digest: String,
    size: u64,
}

impl Blob {
    fn new(bytes: Vec<u8>) -> Self {
        let digest = digest_of(&bytes);
        let size = bytes.len() as u64;
        Blob {
            bytes,
            digest,
            size,
        }
    }
}

/// The on-the-wire shape the registry would serve. We compose this
/// per-test to control exactly what the pull pipeline sees.
struct ServedImage {
    manifest: Blob,
    config: Blob,
    layers: Vec<Blob>,
    referrers: Vec<ServedReferrer>,
}

struct ServedReferrer {
    manifest: Blob,
    config: Blob,
    layer: Blob,
    artifact_type: String,
}

/// Build a complete OCI image manifest JSON value.
fn make_image_manifest(
    config: &Blob,
    layers: &[Blob],
    subject: Option<Value>,
    artifact_type: Option<&str>,
) -> Value {
    let mut m = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config.digest,
            "size": config.size,
        },
        "layers": layers.iter().map(|l| json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": l.digest,
            "size": l.size,
        })).collect::<Vec<_>>(),
    });
    if let Some(s) = subject {
        m["subject"] = s;
    }
    if let Some(at) = artifact_type {
        m["artifactType"] = json!(at);
    }
    m
}

/// Compose a complete served-image fixture: primary manifest +
/// optional referrers, all consistent (referrer manifests'
/// `subject` points at the primary digest).
fn compose_served_image(
    config_body: &[u8],
    layer_bodies: &[Vec<u8>],
    referrers_spec: &[(Vec<u8>, Vec<u8>, &str)],
) -> ServedImage {
    let layers: Vec<Blob> = layer_bodies.iter().cloned().map(Blob::new).collect();
    let config = Blob::new(config_body.to_vec());
    let primary_manifest_value = make_image_manifest(&config, &layers, None, None);
    let primary_manifest_bytes = serde_json::to_vec(&primary_manifest_value).unwrap();
    let manifest = Blob::new(primary_manifest_bytes);

    let primary_subject = json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest.digest,
        "size": manifest.size,
    });

    let mut referrers = Vec::with_capacity(referrers_spec.len());
    for (cfg, lyr, at) in referrers_spec {
        let cfg_blob = Blob::new(cfg.clone());
        let lyr_blob = Blob::new(lyr.clone());
        let ref_manifest_value = make_image_manifest(
            &cfg_blob,
            std::slice::from_ref(&lyr_blob),
            Some(primary_subject.clone()),
            Some(at),
        );
        let ref_manifest_bytes = serde_json::to_vec(&ref_manifest_value).unwrap();
        let ref_manifest = Blob::new(ref_manifest_bytes);
        referrers.push(ServedReferrer {
            manifest: ref_manifest,
            config: cfg_blob,
            layer: lyr_blob,
            artifact_type: at.to_string(),
        });
    }
    ServedImage {
        manifest,
        config,
        layers,
        referrers,
    }
}

/// Stand up the standard set of mocks for a complete pull. Each
/// test calls this to wire all the endpoints. The returned
/// `ImageMocks` is a keep-alive handle: dropping it unmounts the
/// httpmock entries, so the test must hold the value until the
/// pull has finished. Field-level access isn't needed by current
/// tests — the assertions go through `ImageDir::open` post-pull.
fn mount_image_mocks<'a>(
    server: &'a MockServer,
    repo: &str,
    tag: &str,
    image: &ServedImage,
) -> ImageMocks<'a> {
    let mut all = Vec::new();

    // Manifest GET.
    all.push(server.mock(|when, then| {
        when.method(GET).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(200)
            .header("content-type", "application/vnd.oci.image.manifest.v1+json")
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    }));

    // Config blob GET.
    all.push(server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest));
        then.status(200).body(image.config.bytes.clone());
    }));

    // Layer blob GETs.
    for layer in &image.layers {
        all.push(server.mock(|when, then| {
            when.method(GET)
                .path(format!("/v2/{repo}/blobs/{}", layer.digest));
            then.status(200).body(layer.bytes.clone());
        }));
    }

    // Referrers index — lists referrer manifest descriptors.
    let referrer_descriptors: Vec<Value> = image
        .referrers
        .iter()
        .map(|r| {
            json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": r.manifest.digest,
                "size": r.manifest.size,
                "artifactType": r.artifact_type,
            })
        })
        .collect();
    let referrers_index = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": referrer_descriptors,
    });
    all.push(server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest));
        then.status(200)
            .header("content-type", "application/vnd.oci.image.index.v1+json")
            .body(serde_json::to_vec(&referrers_index).unwrap());
    }));

    // Referrer manifest GETs (by digest) + their config + layer blobs.
    for r in &image.referrers {
        all.push(server.mock(|when, then| {
            when.method(GET)
                .path(format!("/v2/{repo}/manifests/{}", r.manifest.digest));
            then.status(200)
                .header("content-type", "application/vnd.oci.image.manifest.v1+json")
                .header("Docker-Content-Digest", r.manifest.digest.clone())
                .body(r.manifest.bytes.clone());
        }));
        all.push(server.mock(|when, then| {
            when.method(GET)
                .path(format!("/v2/{repo}/blobs/{}", r.config.digest));
            then.status(200).body(r.config.bytes.clone());
        }));
        all.push(server.mock(|when, then| {
            when.method(GET)
                .path(format!("/v2/{repo}/blobs/{}", r.layer.digest));
            then.status(200).body(r.layer.bytes.clone());
        }));
    }

    ImageMocks { _mocks: all }
}

/// Keep-alive handle for every Mock the fixture mounts. Tests
/// don't introspect individual mocks (they assert against the
/// final on-disk layout via `ImageDir::open`); the handle just
/// has to live until the test ends, so dropping it after the
/// pull doesn't unmount endpoints mid-flight.
struct ImageMocks<'a> {
    /// All mocks in mount order: manifest, config, every layer,
    /// the referrers index, then every referrer's manifest +
    /// config + layer. The `_` prefix tells the compiler this is
    /// intentionally never read (per Rust idiom for keep-alive
    /// guards) — it's NOT a CLAUDE-md `#[allow(dead_code)]`
    /// dance, it's the documented "keeps RAII guards alive" pattern.
    _mocks: Vec<httpmock::Mock<'a>>,
}

// ── Reference-parser tests (strictly local; no network) ──────────

// Catches: a parser regression that accepts garbage. The first
// line of defence — without it, a typo'd ref is an HTTPS round
// trip with a confusing failure mode.
#[test]
fn test_ref_parser_rejects_malformed_inputs() {
    // Each of these should fail fast with MalformedRef. The
    // selection covers each defect class the parser is meant to
    // catch.
    let malformed = [
        "",                         // empty
        "ghcr.io",                  // no repo
        "ghcr.io/foo",              // no tag, no digest
        "https://ghcr.io/foo:v1",   // scheme prefix
        "myreg/foo:v1",             // bare hostname
        "ghcr.io/foo:v1/test",      // illegal tag char
        "ghcr.io/foo@sha256:short", // wrong digest length
        "ghcr.io/foo@sha512:0000000000000000000000000000000000000000000000000000000000000000",
    ];
    for raw in &malformed {
        let err = parse_registry_ref(raw).unwrap_err();
        match err {
            RegistryPullError::MalformedRef { .. } => {}
            other => panic!("expected MalformedRef for {raw:?}, got {other:?}"),
        }
    }
}

// Catches: a parser regression that misclassifies one of the
// canonical OCI reference forms. Round-trip the host / repo /
// target through the parser to assert the split is right.
#[test]
fn test_ref_parser_accepts_registry_canonical_forms() {
    let cases: &[(&str, &str, &str, RefTarget)] = &[
        (
            "ghcr.io/foo/bar:v1",
            "ghcr.io",
            "foo/bar",
            RefTarget::Tag("v1".into()),
        ),
        (
            "localhost:5000/foo:latest",
            "localhost:5000",
            "foo",
            RefTarget::Tag("latest".into()),
        ),
        (
            "registry.io/foo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry.io",
            "foo",
            RefTarget::Digest(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
        ),
    ];
    for (raw, host, repo, target) in cases {
        let parsed = parse_registry_ref(raw).unwrap();
        assert_eq!(parsed.host, *host, "for {raw:?}");
        assert_eq!(parsed.repository, *repo, "for {raw:?}");
        assert_eq!(parsed.target, *target, "for {raw:?}");
    }
}

// ── Pull integration tests (httpmock-driven) ─────────────────────

// Catches: the pull layer skipping the digest check on streamed
// layer bytes — would silently accept a tampered blob and write
// it to disk under a name claiming it's the right content.
#[test]
fn test_pull_streams_layer_bytes_with_digest_check() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    // 1 MiB layer — large enough to ensure streaming (> the 64 KiB
    // chunk size) and small enough not to slow tests.
    let big_layer: Vec<u8> = (0..(1024 * 1024)).map(|i| (i & 0xff) as u8).collect();
    let image = compose_served_image(
        b"{\"architecture\":\"amd64\"}",
        std::slice::from_ref(&big_layer),
        &[],
    );

    let server = MockServer::start();
    let repo = "acme/streamed";
    let tag = "v1";
    let _mocks = mount_image_mocks(&server, repo, tag, &image);

    let dest = tempfile::tempdir().unwrap();
    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());
    pull_anonymous_into_image_dir(&ref_str, dest.path()).expect("pull must succeed");

    // The streamed layer must be on disk at its sha256 path AND
    // its bytes must hash back to the same digest. (This is what
    // proves the pull layer wrote the verified bytes, not just
    // any bytes.)
    let layer_digest = &image.layers[0].digest;
    let layer_hex = layer_digest.split_once(':').unwrap().1;
    let layer_path = dest.path().join("blobs").join("sha256").join(layer_hex);
    assert!(
        layer_path.is_file(),
        "layer blob must be at blobs/sha256/<hex>, got {layer_path:?}"
    );
    let on_disk = fs::read(&layer_path).unwrap();
    assert_eq!(
        digest_of(&on_disk),
        *layer_digest,
        "layer bytes on disk must hash back to the descriptor digest",
    );
    assert_eq!(on_disk.len(), big_layer.len(), "size must match");

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the moat. If the pull layer trusts the registry's
// declared digest without verifying the bytes, a malicious or
// corrupted registry can swap content and the local-verify path
// would still report the artifact as "valid" — the whole
// registry-pull verify becomes meaningless. The DigestMismatch
// must be raised AND no blob file may exist at the expected
// digest path.
#[test]
fn test_pull_rejects_digest_mismatch() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    // Compose a legit image, but then stand up the layer endpoint
    // serving DIFFERENT bytes than the manifest's layer digest
    // claims. The digest in the manifest stays as the hash of the
    // `original_layer_bytes`; the endpoint serves
    // `tampered_bytes`.
    let original_layer_bytes = b"original-layer".to_vec();
    let tampered_bytes = b"TAMPERED-bytes-different-length-and-content".to_vec();
    let image = compose_served_image(b"{}", std::slice::from_ref(&original_layer_bytes), &[]);

    let server = MockServer::start();
    let repo = "acme/tampered";
    let tag = "v1";

    // Manifest: legit.
    server.mock(|when, then| {
        when.method(GET).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(200)
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest));
        then.status(200).body(image.config.bytes.clone());
    });
    // Layer endpoint: tampered.
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layers[0].digest));
        then.status(200).body(tampered_bytes.clone());
    });
    // Empty referrers index.
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest));
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
    let err = pull_anonymous_into_image_dir(&ref_str, dest.path()).unwrap_err();
    match err {
        RegistryPullError::DigestMismatch { expected, got, .. } => {
            assert_eq!(expected, image.layers[0].digest);
            assert_ne!(got, expected, "got must differ from expected");
        }
        other => panic!("expected DigestMismatch, got {other:?}"),
    }

    // Critical: the tampered blob must NOT be on disk under the
    // expected digest path. Otherwise a retry would skip it
    // (because the pull layer's idempotency optimisation trusts
    // existing files).
    let hex = image.layers[0].digest.split_once(':').unwrap().1;
    let blob_path = dest.path().join("blobs").join("sha256").join(hex);
    assert!(
        !blob_path.exists(),
        "the tampered blob must NEVER be addressable at the expected digest path; \
         leaving it there would bypass the digest check on a retry. found at: {blob_path:?}",
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the pull layer not assembling a valid OCI Image
// Layout. After a successful pull, the dest dir must validate
// as `ImageDir::open` — the same gate the local-verify path
// uses. Without this end-to-end assertion, a refactor to e.g.
// drop a referrer entry from index.json wouldn't surface as a
// failed pull, only as a confusing downstream verify result.
#[test]
fn test_pull_assembles_local_oci_layout_with_referrers() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let image = compose_served_image(
        b"{\"architecture\":\"amd64\",\"os\":\"linux\"}",
        &[b"layer-zero".to_vec(), b"layer-one".to_vec()],
        &[
            (
                br#"{"_type":"in-toto","subject":[]}"#.to_vec(),
                b"slsa-statement-bytes".to_vec(),
                "application/vnd.in-toto+json",
            ),
            (
                br#"{"sigstore":"v1"}"#.to_vec(),
                b"cosign-bundle-bytes".to_vec(),
                "application/vnd.dev.cosign.simplesigning.v1+json",
            ),
        ],
    );

    let server = MockServer::start();
    let repo = "acme/full";
    let tag = "v1";
    let _mocks = mount_image_mocks(&server, repo, tag, &image);

    let dest = tempfile::tempdir().unwrap();
    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());
    pull_anonymous_into_image_dir(&ref_str, dest.path()).expect("pull must succeed");

    // The dest dir must validate as a complete OCI image layout.
    let img = ImageDir::open(dest.path()).expect("pulled dir must validate as ImageDir");
    assert_eq!(
        img.descriptor().primary_manifest_digest,
        image.manifest.digest
    );
    assert_eq!(img.descriptor().layers.len(), 2);
    assert_eq!(
        img.descriptor().referrer_manifests.len(),
        2,
        "both referrer manifests must be present in the assembled index",
    );
    // Both blobs (config + each referrer's manifest, config, layer)
    // are addressable at their digest paths.
    for r in &image.referrers {
        for blob in [&r.manifest, &r.config, &r.layer] {
            let hex = blob.digest.split_once(':').unwrap().1;
            let p = dest.path().join("blobs").join("sha256").join(hex);
            assert!(
                p.is_file(),
                "referrer blob {} must exist at {p:?}",
                blob.digest
            );
        }
    }

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the pull writing index.json before all blobs have
// landed. The atomicity contract: until index.json exists, the
// dest dir is NOT a valid layout — `ImageDir::open` fails. A
// regression that creates index.json early would let a consumer
// see a half-pulled image as complete and start using it.
#[test]
fn test_pull_index_json_written_last_on_failure() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    // Compose an image where the referrer pull will fail mid-flight
    // (the referrer blob endpoint returns 404 unconditionally, so
    // pulling the referrer's layer fails). The test asserts:
    //   1. the pull errors,
    //   2. index.json does NOT exist,
    //   3. the primary manifest + its blobs ARE on disk (the pull
    //      did make progress).
    let image = compose_served_image(
        b"{}",
        &[b"primary-layer".to_vec()],
        &[(
            b"slsa-config".to_vec(),
            b"slsa-layer".to_vec(),
            "application/vnd.in-toto+json",
        )],
    );

    let server = MockServer::start();
    let repo = "acme/half-pull";
    let tag = "v1";

    // Manifest, config, primary layer: serve.
    server.mock(|when, then| {
        when.method(GET).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(200)
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest));
        then.status(200).body(image.config.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layers[0].digest));
        then.status(200).body(image.layers[0].bytes.clone());
    });

    // Referrers index: lists the referrer.
    let referrer_descriptors = vec![json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": image.referrers[0].manifest.digest,
        "size": image.referrers[0].manifest.size,
        "artifactType": image.referrers[0].artifact_type,
    })];
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest));
        then.status(200).body(
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": referrer_descriptors,
            }))
            .unwrap(),
        );
    });

    // Referrer manifest fetch: serve.
    server.mock(|when, then| {
        when.method(GET).path(format!(
            "/v2/{repo}/manifests/{}",
            image.referrers[0].manifest.digest
        ));
        then.status(200)
            .header(
                "Docker-Content-Digest",
                image.referrers[0].manifest.digest.clone(),
            )
            .body(image.referrers[0].manifest.bytes.clone());
    });
    // Referrer config + layer: SABOTAGE — return 500 on every attempt
    // so retries exhaust and the pull fails.
    server.mock(|when, then| {
        when.method(GET).path(format!(
            "/v2/{repo}/blobs/{}",
            image.referrers[0].config.digest
        ));
        then.status(500).body("internal error");
    });
    server.mock(|when, then| {
        when.method(GET).path(format!(
            "/v2/{repo}/blobs/{}",
            image.referrers[0].layer.digest
        ));
        then.status(500).body("internal error");
    });

    let dest = tempfile::tempdir().unwrap();
    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());
    let err = pull_anonymous_into_image_dir(&ref_str, dest.path()).unwrap_err();
    match err {
        RegistryPullError::RegistryRefused { .. } => {}
        other => panic!("expected RegistryRefused, got {other:?}"),
    }

    // index.json MUST NOT exist on a failed pull.
    let index_path = dest.path().join("index.json");
    assert!(
        !index_path.is_file(),
        "index.json must be the LAST file written; on failure it must NOT exist (otherwise consumers see a half-pulled image as complete)"
    );

    // The primary manifest + its blobs SHOULD be on disk
    // (we made progress before failing). Asserting this proves
    // the index-last contract isn't a no-op.
    let primary_hex = image.manifest.digest.split_once(':').unwrap().1;
    assert!(
        dest.path().join("blobs").join("sha256").join(primary_hex).is_file(),
        "primary manifest blob should be on disk (the pull did make progress before the referrer fetch failed)",
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the pull layer attaching an Authorization header on
// a `pull_anonymous_into_image_dir` call. Public registries
// 401 unconditionally if any unexpected auth header is present;
// the anonymous shorthand must NOT send credentials.
#[test]
fn test_pull_anonymous_does_not_send_authorization_header() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let image = compose_served_image(b"{}", &[b"layer".to_vec()], &[]);
    let server = MockServer::start();
    let repo = "public/img";
    let tag = "v1";

    // Mocks that REQUIRE no Authorization header (httpmock's
    // matches_when matches absence by checking the header is
    // missing or empty). We use a custom matcher.
    let manifest_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/manifests/{tag}"))
            .matches(|req| {
                req.headers
                    .as_ref()
                    .map(|hs| {
                        hs.iter()
                            .all(|(k, _)| !k.eq_ignore_ascii_case("authorization"))
                    })
                    .unwrap_or(true)
            });
        then.status(200)
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest));
        then.status(200).body(image.config.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layers[0].digest));
        then.status(200).body(image.layers[0].bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest));
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
    pull_anonymous_into_image_dir(&ref_str, dest.path())
        .expect("anonymous pull must succeed without auth");
    assert_eq!(
        manifest_mock.hits(),
        1,
        "manifest must be fetched exactly once"
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the pull layer dropping the Authorization header on
// `--auth basic`. Without this, every request to a private
// registry 401s and the operator gets a confusing "registry
// refused" error instead of "auth misconfigured."
#[test]
fn test_pull_basic_auth_attaches_authorization_header_on_every_request() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let image = compose_served_image(b"{}", &[b"layer".to_vec()], &[]);
    let server = MockServer::start();
    let repo = "private/img";
    let tag = "v1";

    // `printf 'admin:hunter2' | base64` => YWRtaW46aHVudGVyMg==
    let expected_auth = "Basic YWRtaW46aHVudGVyMg==";

    let manifest_auth_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/manifests/{tag}"))
            .header("authorization", expected_auth);
        then.status(200)
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest))
            .header("authorization", expected_auth);
        then.status(200).body(image.config.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layers[0].digest))
            .header("authorization", expected_auth);
        then.status(200).body(image.layers[0].bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest))
            .header("authorization", expected_auth);
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
    let auth = RegistryAuth::Basic {
        username: "admin".into(),
        password: "hunter2".into(),
    };
    pull_into_image_dir(&ref_str, &auth, dest.path()).expect("basic-auth pull must succeed");
    assert!(
        manifest_auth_mock.hits() >= 1,
        "the manifest mock that requires the Basic auth header must have matched",
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the pull layer dropping the bearer token on
// `--auth bearer`. Same shape as the basic-auth test; bearer
// is the second of the two pre-supplied auth modes.
#[test]
fn test_pull_bearer_token_attaches_authorization_header() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let image = compose_served_image(b"{}", &[b"layer".to_vec()], &[]);
    let server = MockServer::start();
    let repo = "private/img";
    let tag = "v1";
    let token = "secret-bearer";
    let expected_auth = format!("Bearer {token}");

    let manifest_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/manifests/{tag}"))
            .header("authorization", expected_auth.clone());
        then.status(200)
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest))
            .header("authorization", expected_auth.clone());
        then.status(200).body(image.config.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layers[0].digest))
            .header("authorization", expected_auth.clone());
        then.status(200).body(image.layers[0].bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest))
            .header("authorization", expected_auth.clone());
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
    let auth = RegistryAuth::Bearer {
        token: token.into(),
    };
    pull_into_image_dir(&ref_str, &auth, dest.path()).expect("bearer-auth pull must succeed");
    assert!(manifest_mock.hits() >= 1, "manifest mock must have matched");

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the pull layer not implementing the OCI Distribution
// §3.4 401-then-bearer dance. Public read-only repos on Docker
// Hub and GHCR work this way: anonymous GET → 401 with
// `WWW-Authenticate: Bearer realm=…` → fetch token from realm
// → retry original request with bearer token. Without this,
// `justoci verify ghcr.io/anonymous/public:v1` would fail on
// every public repo.
#[test]
fn test_pull_401_triggers_token_dance_and_succeeds_on_retry() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let image = compose_served_image(b"{}", &[b"x".to_vec()], &[]);
    let server = MockServer::start();
    let repo = "needs-token/img";
    let tag = "v1";

    // The token endpoint lives under /token (httpmock serves it
    // from the same MockServer, which keeps the test single-process).
    let token_realm = format!("http://{}/token", server.address());
    let issued_token = "freshly-minted-bearer";
    let challenge =
        format!(r#"Bearer realm="{token_realm}",service="acme",scope="repository:{repo}:pull""#);

    // First manifest GET (no Authorization): 401 with challenge.
    let unauth_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/manifests/{tag}"))
            .matches(|req| {
                req.headers
                    .as_ref()
                    .map(|hs| {
                        hs.iter()
                            .all(|(k, _)| !k.eq_ignore_ascii_case("authorization"))
                    })
                    .unwrap_or(true)
            });
        then.status(401)
            .header("WWW-Authenticate", challenge.clone())
            .body("auth required");
    });

    // Token endpoint serves a JSON body with `token`.
    let token_mock = server.mock(|when, then| {
        when.method(GET).path("/token");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(r#"{{"token":"{issued_token}"}}"#));
    });

    // Retry under bearer auth: serve the manifest.
    let bearer_auth = format!("Bearer {issued_token}");
    let auth_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/manifests/{tag}"))
            .header("authorization", bearer_auth.clone());
        then.status(200)
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    });
    // Subsequent blobs under bearer.
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest))
            .header("authorization", bearer_auth.clone());
        then.status(200).body(image.config.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layers[0].digest))
            .header("authorization", bearer_auth.clone());
        then.status(200).body(image.layers[0].bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest))
            .header("authorization", bearer_auth.clone());
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
    pull_anonymous_into_image_dir(&ref_str, dest.path())
        .expect("anonymous pull must succeed via the token dance");

    assert!(
        unauth_mock.hits() >= 1,
        "the no-auth manifest GET must have happened (the dance trigger)"
    );
    assert!(
        token_mock.hits() >= 1,
        "the token-realm GET must have happened (the dance step)"
    );
    assert!(
        auth_mock.hits() >= 1,
        "the bearer-authenticated manifest GET must have happened (the dance retry)"
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the pull layer not retrying 5xx — a flaky registry
// would fail every pull on the first transient blip, even though
// retrying succeeds. Same retry contract publish has on the push
// side; mirroring it here means a verify on the same flaky
// registry behaves consistently.
#[test]
fn test_pull_5xx_retried_then_succeeds() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let image = compose_served_image(b"{}", &[b"layer".to_vec()], &[]);
    let server = MockServer::start();
    let repo = "flaky/img";
    let tag = "v1";

    // First two manifest GETs: 503. Third: 200. httpmock supports
    // a "max" hit count (`expect_match`), but the simpler approach
    // is two distinct mocks with the second taking over after the
    // first is exhausted via `times(N)`. We use sequential mocks
    // with `then.return_with(...)` style — but httpmock doesn't
    // expose stateful body switching. Workaround: build TWO mocks
    // with disjoint paths via `path_contains` won't help since
    // the URL is identical. Use `expect_match_times(2)` then a
    // catch-all 200.

    // httpmock 0.7's `matches` predicate is a bare `fn` pointer
    // (no captures permitted). We use a process-static atomic
    // counter, scoped to this test by the env_lock above so two
    // tests can't race the same counter. The matcher fires 503
    // for the first 2 hits; on the third the matcher fails to
    // match and the next mock (200) takes over.
    use std::sync::atomic::{AtomicU32, Ordering};
    static RETRY_COUNTER: AtomicU32 = AtomicU32::new(0);
    RETRY_COUNTER.store(0, Ordering::SeqCst);
    fn first_two_hits(_req: &httpmock::prelude::HttpMockRequest) -> bool {
        let n = RETRY_COUNTER.fetch_add(1, Ordering::SeqCst);
        n < 2
    }

    let dynamic_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/manifests/{tag}"))
            .matches(first_two_hits);
        then.status(503).body("temporarily unavailable");
    });
    let success_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(200)
            .header("Docker-Content-Digest", image.manifest.digest.clone())
            .body(image.manifest.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.config.digest));
        then.status(200).body(image.config.bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/blobs/{}", image.layers[0].digest));
        then.status(200).body(image.layers[0].bytes.clone());
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/v2/{repo}/referrers/{}", image.manifest.digest));
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
    pull_anonymous_into_image_dir(&ref_str, dest.path())
        .expect("pull must succeed after 5xx retries");

    assert_eq!(
        dynamic_mock.hits(),
        2,
        "the 503 mock must have been hit exactly twice (the first two attempts)"
    );
    assert!(
        success_mock.hits() >= 1,
        "the 200 mock must have been hit on the third attempt",
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// Catches: the retry counter being unbounded. A flaky registry
// that returns 5xx forever must surface a typed RegistryRefused
// (not an infinite loop, not a panic). The error must carry
// the URL + status so an operator can identify the failure.
#[test]
fn test_pull_5xx_after_max_retries_fails_with_typed_error() {
    let _g = env_lock();
    env::set_var("JUSTOCI_ALLOW_INSECURE", "1");

    let server = MockServer::start();
    let repo = "always-broken/img";
    let tag = "v1";

    // Permanent 503 on the manifest endpoint.
    let broken_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/v2/{repo}/manifests/{tag}"));
        then.status(503).body("server is on fire");
    });

    let dest = tempfile::tempdir().unwrap();
    let ref_str = format!("127.0.0.1:{}/{repo}:{tag}", server.port());
    let err = pull_anonymous_into_image_dir(&ref_str, dest.path()).unwrap_err();
    match err {
        RegistryPullError::RegistryRefused {
            status, url, body, ..
        } => {
            assert_eq!(
                status, 503,
                "final status must be the 503 the registry returned"
            );
            assert!(
                url.contains(&format!("/v2/{repo}/manifests/{tag}")),
                "error URL must point at the failing endpoint, got {url:?}",
            );
            assert!(
                body.contains("on fire"),
                "error body preview must include the server's response, got {body:?}",
            );
        }
        other => panic!("expected RegistryRefused, got {other:?}"),
    }
    // The retry count is bounded — assert hits <= MAX_RETRIES + 1.
    // (The pull retries up to MAX_RETRIES = 3 transient failures,
    // so up to 4 attempts total before surfacing.)
    let hits = broken_mock.hits();
    assert!(
        (2..=4).contains(&hits),
        "retry count must be bounded between 2 (initial + 1 retry) and 4 (initial + 3 retries), got {hits}",
    );

    env::remove_var("JUSTOCI_ALLOW_INSECURE");
}

// ── CLI dispatcher integration ────────────────────────────────────

// Catches: a malformed registry ref being routed to the network
// (no path on disk, can't be parsed as a ref). The whole point
// of strict ref parsing is to fail locally with a clear typed
// error before any network round-trip — saving the operator a
// confusing-timeout debug session.
#[test]
fn test_verify_dispatch_malformed_ref_with_no_path_fails_locally() {
    use swe_justoci_oci_cli::cmd::verify;
    // `bogus-ref-without-slash` is neither a path nor a parseable
    // registry reference. The dispatcher must surface
    // RegistryPullError::MalformedRef without trying any network
    // call.
    let err = verify::run("bogus-ref-without-slash", None, VerifyAuthMode::Anonymous)
        .expect_err("malformed ref must fail");
    match err {
        CliError::RegistryPull(RegistryPullError::MalformedRef { reason, .. }) => {
            assert!(
                reason.contains("'/'") || reason.contains("tag"),
                "MalformedRef must explain the defect, got {reason:?}",
            );
        }
        other => panic!("expected RegistryPull(MalformedRef), got {other:?}"),
    }
}

// Catches: `--auth basic` with empty creds being silently
// accepted (and the wire layer producing a malformed Authorization
// header). The auth-resolution layer must reject empty creds at
// the boundary, not mid-pull.
#[test]
fn test_verify_dispatch_basic_auth_with_empty_creds_rejected() {
    use swe_justoci_oci_cli::cmd::verify;
    // Use a bogus ref so we don't actually round-trip; the auth
    // resolution happens before the first wire call, so the
    // failure surfaces early with the right error class.
    // Provide an existing dest path (anything that doesn't parse
    // as a ref) — and rely on the parser failing FIRST, but with
    // empty Basic creds, the auth resolver must fail. We pick a
    // valid ref shape so the parser succeeds and we exercise the
    // auth resolver.
    let auth = VerifyAuthMode::Authenticated(AuthMode::Basic {
        username: "".into(),
        password: "".into(),
    });
    let err = verify::run("registry.example/foo:v1", None, auth).expect_err("must fail");
    match err {
        CliError::RegistryPull(RegistryPullError::Auth { source }) => {
            let s = source.to_string();
            assert!(
                s.contains("non-empty") || s.contains("empty"),
                "Auth error must mention the empty-creds defect, got {s:?}",
            );
        }
        other => panic!("expected RegistryPull(Auth), got {other:?}"),
    }
}
