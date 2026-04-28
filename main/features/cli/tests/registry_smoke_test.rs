//! Real-registry smoke test against `docker run -d registry:2`.
//!
//! Gated `#[ignore]` because it requires Docker available on the
//! host. CI runs it via `cargo test … -- --ignored --test-threads=1`
//! in the dedicated `smoke` job. Local invocation:
//!
//! ```bash
//! docker pull registry:2   # one-time
//! cargo test -p swe_justoci_oci_cli \
//!     --test registry_smoke_test \
//!     -- --ignored --test-threads=1
//! ```
//!
//! ## Why this test exists
//!
//! The httpmock-based registry tests in `registry_pull_test.rs` and
//! the publish crate's `registry_*_test.rs` set cover the OCI
//! Distribution v2 wire shape — they assert the right HEAD/POST/PUT
//! sequence, the right headers, the right error mapping. What they
//! cannot catch is **behavioural drift** between our mock and a real
//! registry implementation:
//!
//! - **Upload-session URL shape.** httpmock returns a fixed
//!   `Location:` value we control; the real `registry:2` mints a
//!   per-session UUID under `/v2/<repo>/blobs/uploads/<uuid>?…`.
//!   A regression that hard-codes any path component would pass
//!   the mock and 404 against the real registry.
//! - **HEAD-then-PUT contract on a re-publish.** Our mocks decide
//!   in advance which HEADs return 200 vs 404; the real registry
//!   actually persists state between calls. If `push_blob_with_skip`
//!   misreads the HEAD status (say, treats a 200 as "go upload"),
//!   the second publish to the same tag would re-upload every blob
//!   instead of skipping. Mocks can't catch that — they just
//!   replay the script.
//! - **Manifest media-type negotiation.** registry:2 inspects the
//!   `Content-Type` on the manifest PUT and rejects mismatches with
//!   400/415; httpmock accepts whatever we send. A regression that
//!   sends `application/json` instead of
//!   `application/vnd.oci.image.manifest.v1+json` would pass mocks
//!   and break publishes.
//! - **Round-trip byte equality.** We assert the digest the build
//!   computed equals the `Docker-Content-Digest` the real registry
//!   reports on `GET /v2/<repo>/manifests/<tag>`. If anything in
//!   the pipeline (compression, JSON re-serialization,
//!   trailing-newline handling) silently mutates manifest bytes,
//!   the digests diverge.
//!
//! ## Approach
//!
//! Container management uses `std::process::Command::new("docker")`
//! rather than the `testcontainers` crate. Reasons:
//!   - Zero new dev-deps to vet (testcontainers pulls a
//!     non-trivial transitive tree, including a Docker API client).
//!   - The Drop-guard idiom for cleanup is exactly what we need,
//!     and is six lines.
//!   - Explicit `-p <host>:5000` lets us pick a free port at test
//!     time and pass the same `host:port` to `ocimage publish`.
//!
//! ## Flake mitigations
//!
//! - **Port pickup.** Bind `TcpListener` to `127.0.0.1:0` to grab an
//!   OS-assigned free port, drop the listener, then `docker run -p
//!   <port>:5000`. There is a brief race where another process could
//!   grab that port between our drop and docker's bind — vanishingly
//!   rare on a CI runner, and a retry would re-roll the port.
//! - **Container readiness.** registry:2 starts in 1-3s. We poll
//!   `GET /v2/` (the catalog endpoint) with a 30s budget and a 250ms
//!   step. The smoke job sets `--test-threads=1`, so two smoke tests
//!   never race the same daemon.
//! - **Cleanup.** `RegistryGuard`'s Drop runs `docker stop` + `docker
//!   rm`. Even on panic / assertion failure the container goes away.
//! - **Pre-pull.** CI pre-pulls `registry:2` before invoking cargo
//!   so a docker-hub rate-limit blip surfaces as a CI-step failure
//!   (loud) rather than a confusing test failure (quiet).
//!
//! ## Skip behaviour when Docker is absent
//!
//! If `docker info` fails the test prints a SKIP line on stderr and
//! returns Ok. CI's smoke job runs on `ubuntu-latest`, which has
//! Docker pre-installed; the skip path exists for developer
//! laptops that ran `cargo test --ignored` without Docker.

mod common;

use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

/// Tear-down guard for the spawned `registry:2` container. Runs
/// `docker stop` + `docker rm` on Drop, including on panic — the
/// whole point of the guard is that the container goes away even
/// when an assertion above fails partway through the test body.
struct RegistryGuard {
    name: String,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        // `docker stop` sends SIGTERM and waits up to 10s by
        // default. We discard stdout/stderr; a stop failure on
        // teardown should not mask the test's own failure
        // diagnostic. `--rm` on `docker run` would auto-clean,
        // but stop+rm is more deterministic — it works even if
        // the daemon's `--rm` reaper is slow.
        let _ = Command::new("docker")
            .args(["stop", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Probe whether `docker` is on PATH and the daemon is reachable.
/// Returns `Some(stderr)` with a short reason when Docker is
/// unavailable so the test can print one SKIP line and return Ok.
fn docker_unavailable_reason() -> Option<String> {
    match Command::new("docker")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(out) if out.status.success() => None,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Truncate the daemon's full diagnostic — one line is
            // plenty for a SKIP message.
            let first = stderr.lines().next().unwrap_or("docker info failed");
            Some(first.to_string())
        }
        Err(e) => Some(format!("docker not on PATH: {e}")),
    }
}

/// Bind a TCP listener to `127.0.0.1:0` to get an OS-assigned
/// free port, then drop the listener so docker can claim it.
/// There is a brief TOCTOU window where another process could
/// race in; on a CI runner with `--test-threads=1`, this is a
/// non-issue. We surface a clear panic if bind fails — the
/// alternative (silently picking a hard-coded port like 5000) is
/// worse: it'd fail flakily depending on what else is running.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("addr").port()
}

/// Spawn `docker run -d -p <host>:5000 --name <name> registry:2`
/// and wait until `GET http://127.0.0.1:<host>/v2/` returns 200.
/// Returns the guard on success; panics with a descriptive message
/// on failure (which is the right outcome — the smoke test cannot
/// continue without a registry, and the panic carries the docker
/// error to the operator).
fn start_registry(name: &str, host_port: u16) -> RegistryGuard {
    // Start detached. `-p 127.0.0.1:<host_port>:5000` binds only
    // loopback so a CI runner doesn't accidentally expose the
    // registry on its public interface during the test window.
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-p",
            &format!("127.0.0.1:{host_port}:5000"),
            "registry:2",
        ])
        .output()
        .expect("docker run failed to spawn");
    if !run.status.success() {
        panic!(
            "docker run failed (status {:?}): stdout={:?} stderr={:?}",
            run.status,
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr),
        );
    }
    // The guard is constructed BEFORE readiness polling so a slow
    // registry that never wakes up is still cleaned up on the
    // panic-on-timeout path.
    let guard = RegistryGuard {
        name: name.to_string(),
    };
    wait_for_v2_ready(host_port);
    guard
}

/// Poll `GET /v2/` until 200 OK or timeout. The OCI Distribution
/// spec defines `/v2/` as the API root probe — registry:2 returns
/// 200 with an empty body when ready.
fn wait_for_v2_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let url = format!("http://127.0.0.1:{port}/v2/");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest client");
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send() {
            if resp.status().as_u16() == 200 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "registry:2 at {url} did not become ready within 30s; \
         this is a flake-vs-regression boundary — investigate \
         the docker logs for the spawned container before raising \
         the timeout"
    );
}

/// Read a manifest from the live registry and return
/// `(docker_content_digest_header, body_bytes)`.
fn fetch_manifest(port: u16, repo: &str, tag: &str) -> (String, Vec<u8>) {
    let url = format!("http://127.0.0.1:{port}/v2/{repo}/manifests/{tag}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client");
    // Send the OCI manifest accept header so the registry returns
    // the OCI media type body, not Docker-schema-2.
    let resp = client
        .get(&url)
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json",
        )
        .send()
        .expect("GET manifest");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "registry must serve the manifest we just published; got {} from {url}",
        resp.status(),
    );
    let digest = resp
        .headers()
        .get("Docker-Content-Digest")
        .expect("registry must return Docker-Content-Digest header on manifest GET")
        .to_str()
        .expect("digest header is ASCII")
        .to_string();
    let mut body = Vec::new();
    resp.bytes()
        .expect("read manifest body")
        .as_ref()
        .read_to_end(&mut body)
        .expect("buffer body");
    (digest, body)
}

/// Pull the build's manifest digest out of `<build_dir>/index.json`.
fn read_manifest_digest_from_index(build_dir: &Path) -> String {
    let bytes = std::fs::read(build_dir.join("index.json")).expect("read index.json");
    let v: Value = serde_json::from_slice(&bytes).expect("parse index.json");
    v.get("manifests")
        .and_then(|m| m.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("digest"))
        .and_then(|d| d.as_str())
        .expect("index.json has a primary manifest digest")
        .to_string()
}

/// Run `ocimage publish <build_dir> --to registry:127.0.0.1:<port>/<repo>:<tag>`
/// against the live registry and return the captured stdout (used
/// by callers to assert pushed/skipped/bytes lines).
fn run_publish(build_dir: &Path, port: u16, repo: &str, tag: &str) -> String {
    // registry:2's default config accepts both anonymous and
    // basic-auth requests; we pass dummy basic creds because the
    // CLI's `parse_auth_mode("basic", …)` requires non-empty
    // username + password and there is no `--no-auth` flag on
    // publish today. The registry ignores the header.
    let out = common::ocimage_bin()
        .arg("publish")
        .arg(build_dir)
        .arg("--to")
        .arg(format!("registry:127.0.0.1:{port}/{repo}:{tag}"))
        .arg("--auth")
        .arg("basic")
        .arg("--registry-username")
        .arg("anon")
        .arg("--registry-password")
        .arg("anon")
        // The registry sink consults OCIMAGE_ALLOW_INSECURE for
        // http:// (vs the default https://). Without this, the
        // sink would attempt a TLS handshake against the plain-
        // HTTP registry container and fail with a confusing
        // "tls handshake error" instead of completing.
        .env("OCIMAGE_ALLOW_INSECURE", "1")
        .output()
        .expect("ocimage publish spawn");
    if !out.status.success() {
        panic!(
            "ocimage publish failed (status {:?}): stdout={:?} stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    String::from_utf8(out.stdout).expect("ocimage publish stdout is utf-8")
}

/// Parse the `bytes:   <n>` line `ocimage publish` writes to stdout.
/// The CLI emits exactly this prefix per `cli/src/main.rs` Publish
/// arm; if the prefix changes, this helper's panic message tells
/// the operator which contract just shifted.
fn parse_bytes_uploaded(stdout: &str) -> u64 {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("bytes:") {
            return rest
                .trim()
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("publish stdout 'bytes:' line is not a u64: {line:?}"));
        }
    }
    panic!("publish stdout missing 'bytes:' line; full stdout was:\n{stdout}")
}

/// Count `pushed:` / `skipped:` line occurrences. The CLI emits one
/// per digest, so counts are direct evidence of the
/// HEAD-then-PUT skip-if-exists state machine's behaviour.
fn count_prefix(stdout: &str, prefix: &str) -> usize {
    stdout.lines().filter(|l| l.starts_with(prefix)).count()
}

/// Bug it catches: an OCI Distribution wire-shape regression that
/// httpmock-based tests don't see. Specifically:
///   1. `publish_registry` hard-coding any path component of the
///      upload-session URL that the real registry mints as a UUID
///      (httpmock returns a fixed `Location:` value).
///   2. The HEAD-then-PUT skip-if-exists state machine misreading
///      a stateful registry's responses on the SECOND publish —
///      mocks can't drift state between calls; a real registry can.
///   3. The pipeline silently mutating manifest bytes
///      (compression, re-serialization, trailing-newline handling)
///      so the digest the build computed differs from the
///      `Docker-Content-Digest` the registry returns.
///
/// The non-`--ignored` cargo test suite continues to pass without
/// Docker because of the gate; CI's `smoke` job runs the ignored
/// test in a job that gates on Docker availability.
#[test]
#[ignore]
fn test_full_pipeline_against_real_registry_2_container() {
    if let Some(reason) = docker_unavailable_reason() {
        eprintln!(
            "SKIP test_full_pipeline_against_real_registry_2_container: \
             Docker is required for this smoke test ({reason})"
        );
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());
    let build_dir = tmp.path().join("oci-build-out");

    // ── 1. build ──────────────────────────────────────────────
    // `--no-attest` to skip the Sigstore subprocess; the smoke
    // test's contract is "the OCI Distribution wire works against
    // a real registry", not "cosign keyless works". Attestation has
    // its own dedicated test (`e2e_build_verify_test`'s attested
    // variant) that exercises slsa + sbom referrers.
    let build_out = common::ocimage_bin()
        .arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&build_dir)
        .arg("--no-attest")
        .output()
        .expect("ocimage build spawn");
    if !build_out.status.success() {
        panic!(
            "ocimage build failed (status {:?}): stdout={:?} stderr={:?}",
            build_out.status,
            String::from_utf8_lossy(&build_out.stdout),
            String::from_utf8_lossy(&build_out.stderr),
        );
    }
    let build_manifest_digest = read_manifest_digest_from_index(&build_dir);
    assert!(
        build_manifest_digest.starts_with("sha256:"),
        "build did not emit a sha256 manifest digest, got {build_manifest_digest:?}",
    );

    // ── 2. spawn registry:2 on a free port ────────────────────
    let host_port = pick_free_port();
    // Container name embeds the port so two concurrent CI shards
    // (despite --test-threads=1 inside one process) don't collide.
    // We pin to the test-name + port; the Drop guard cleans up on
    // every exit path including panic.
    let container_name = format!("justoci-smoke-{host_port}");
    let _guard = start_registry(&container_name, host_port);

    let repo = "smoke/firmware";
    let tag = "v1";

    // ── 3. first publish ──────────────────────────────────────
    let stdout1 = run_publish(&build_dir, host_port, repo, tag);
    let pushed1 = count_prefix(&stdout1, "pushed:");
    let skipped1 = count_prefix(&stdout1, "skipped:");
    let bytes1 = parse_bytes_uploaded(&stdout1);
    assert!(
        pushed1 >= 2,
        "first publish must report >=2 pushed digests (config + 1 layer + manifest), \
         got {pushed1}; full stdout:\n{stdout1}"
    );
    assert_eq!(
        skipped1, 0,
        "first publish to a fresh registry must skip nothing; got {skipped1} skipped lines, \
         full stdout:\n{stdout1}"
    );
    assert!(
        bytes1 > 0,
        "first publish must report bytes_uploaded > 0; got {bytes1}, full stdout:\n{stdout1}"
    );

    // ── 4. verify against the live registry ───────────────────
    // `ocimage verify <ref>` pulls into a tempdir then runs the
    // local-verify path. Anonymous (`--no-auth`) because registry:2
    // accepts both. Exit 0 with `slsa: missing` etc. is the
    // documented contract for `--no-attest` builds.
    let verify_out = common::ocimage_bin()
        .arg("verify")
        .arg(format!("127.0.0.1:{host_port}/{repo}:{tag}"))
        .arg("--no-auth")
        .env("OCIMAGE_ALLOW_INSECURE", "1")
        .output()
        .expect("ocimage verify spawn");
    if !verify_out.status.success() {
        panic!(
            "ocimage verify failed (status {:?}): stdout={:?} stderr={:?}",
            verify_out.status,
            String::from_utf8_lossy(&verify_out.stdout),
            String::from_utf8_lossy(&verify_out.stderr),
        );
    }
    let verify_stdout = String::from_utf8(verify_out.stdout).expect("verify stdout utf8");
    assert!(
        verify_stdout.contains(&format!("manifest: {build_manifest_digest}")),
        "verify must report the same manifest digest the build emitted; \
         build_digest={build_manifest_digest:?}, verify_stdout=\n{verify_stdout}"
    );

    // ── 5. byte-equality round-trip via direct registry GET ───
    // The strongest assertion in the test: the digest the build
    // computed locally must exactly match the digest the registry
    // computes on its stored manifest bytes. If anything in
    // publish (e.g. re-serializing JSON, adding a trailing
    // newline) mutated the manifest, the digests diverge here
    // even though everything else passed.
    let (registry_digest_header, registry_manifest_body) = fetch_manifest(host_port, repo, tag);
    assert_eq!(
        registry_digest_header, build_manifest_digest,
        "registry's Docker-Content-Digest header must equal the build's manifest digest; \
         any mismatch means publish mutated bytes in transit",
    );
    // Re-hash the body the registry served and confirm the digest
    // header isn't lying. (registry:2 won't lie, but a regression
    // in our publish that PUT bytes mismatching the digest would
    // surface here as "registry computed X, but our build said Y".)
    use sha2::{Digest, Sha256};
    let body_hex = Sha256::digest(&registry_manifest_body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        format!("sha256:{body_hex}"),
        build_manifest_digest,
        "the manifest bytes the registry serves must hash back to the build's digest; \
         a mismatch means manifest bytes were mutated end-to-end",
    );

    // ── 6. re-publish and assert idempotency contract ─────────
    // Important: the contract is NOT "0 bytes uploaded on second
    // publish" — re-publishing to the same TAG always re-PUTs the
    // primary manifest (the registry must accept the tag-flip even
    // when the manifest bytes are unchanged), per the comment in
    // `publish/src/core/registry_sink.rs::push_manifest_with_skip`:
    //
    //   > a registry-side tag re-target via PUT is still required
    //   > for the primary (the tag may not point at this digest yet)
    //
    // What MUST hold:
    //   (a) every NON-manifest blob is reported as `skipped:`
    //       (HEAD returned 200 — already there).
    //   (b) `bytes_uploaded` shrinks dramatically — only the
    //       manifest body is re-uploaded, which is a few hundred
    //       bytes against the firmware fixture's 4 KiB+ payload.
    //
    // The bug this catches: a publish that ignores the HEAD
    // response and re-uploads every blob unconditionally on
    // every invocation. That would make `ocimage publish` worse
    // than `docker push` and burn enormous bandwidth on rebuilds.
    let stdout2 = run_publish(&build_dir, host_port, repo, tag);
    let pushed2 = count_prefix(&stdout2, "pushed:");
    let skipped2 = count_prefix(&stdout2, "skipped:");
    let bytes2 = parse_bytes_uploaded(&stdout2);
    assert!(
        skipped2 >= 2,
        "second publish must skip every NON-manifest blob (config + each layer); \
         got skipped={skipped2}, pushed={pushed2}, full stdout:\n{stdout2}"
    );
    // The primary manifest re-PUT is the only thing pushed by
    // digest (or a referrer-manifest re-PUT when attest ran;
    // here --no-attest, so there's exactly one manifest in flight).
    assert!(
        pushed2 <= 1,
        "second publish must push at most the primary manifest re-tag; \
         got pushed={pushed2}, full stdout:\n{stdout2}"
    );
    // bytes2 should be a small fraction of bytes1 (just the manifest
    // body, ~hundreds of bytes; not the firmware payload, ~kibibytes).
    // We assert strictly less, with the manifest-only ceiling proven
    // by the GET above.
    let manifest_body_len = registry_manifest_body.len() as u64;
    assert!(
        bytes2 <= manifest_body_len,
        "second publish bytes_uploaded must be at most the manifest body size \
         (only the tag-flip PUT happens); got bytes={bytes2}, manifest_size={manifest_body_len}, \
         full stdout:\n{stdout2}"
    );
    assert!(
        bytes2 < bytes1,
        "second publish must upload strictly fewer bytes than the first \
         (skip-if-exists must do real work); got bytes2={bytes2}, bytes1={bytes1}",
    );

    // _guard drops here → docker stop + docker rm, even if any of
    // the assertions above panicked.
}
