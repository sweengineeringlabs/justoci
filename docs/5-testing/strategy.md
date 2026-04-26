# Testing strategy

## The cardinal rule

**Every test names the bug it would catch.**

Already stated in [`4-development/contributing.md`](../4-development/contributing.md).
Repeated here because it's the single most important rule of the
test suite.

A test that doesn't name a bug is a smoke test. Smoke tests give
false confidence — they pass when nothing is wrong AND when
something subtle is wrong. Replace them with assertion-bound
tests, or delete them.

## Test pattern

```rust
/// `<short summary of what's tested>`.
///
/// Bug it catches: <specific regression that would surface>.
/// <How the test would surface it.>
#[test]
fn test_<action>_<condition>_<expectation>() {
    // Setup that puts the system into the precondition.
    let ...;

    // Trigger the action under test.
    let result = ...;

    // Assert the specific behaviour.
    assert_eq!(result, expected, "...");
}
```

Test name follows `test_<action>_<condition>_<expectation>` per
the user's CLAUDE.md naming rules.

## Test categories the suite covers

For each feature, the suite includes a representative subset of:

| Category | What it proves | Example from this codebase |
|----------|---------------|---------------------------|
| Smoke (anchor) | Feature exists and runs | `test_valid_spec_round_trips` (validation) |
| Boundary | Limits handled | `test_blob_layer_streams_in_chunks` (1 MiB streaming) |
| Negative | Bad input rejected | `test_pull_rejects_digest_mismatch` |
| Integration | Works with neighbours | `test_e2e_build_then_publish_then_verify_succeeds` |
| Regression | Known-bug protection | `test_get_detects_on_disk_corruption` (CAS integrity) |
| Reproducibility | Same input → same bytes | `test_manifest_digest_is_byte_identical_across_rebuilds` |

The "anchor" smoke test is the one exception to the
no-tautological-tests rule: it confirms the test setup itself
isn't broken before any individual rule test fires. It does
*one* assertion, and the negative tests do the work.

## Per-crate test counts

| Crate | Tests | Bug classes covered |
|-------|------:|---------------------|
| `justcas/cas` | 20 | digest format, atomic put, integrity-on-read, gc, streaming, concurrent put |
| `spec` | 32 | parse, validate every rule, JCS canonicalisation determinism + content-sensitivity, cross-language fixture self-consistency |
| `build` | 50 | reproducibility, atomic build, streaming compression, deterministic tar, kind-aware layer count, descriptor verbatim media types |
| `attest` | 29 | SLSA structure + reproducibility, CycloneDX/SPDX shape, opt-out per pillar, sign+Rekor coupling, CosignNotInstalled mapping |
| `publish` | 47 | image-dir validation, http skip-if-exists, http atomic index, registry HEAD-then-PUT, registry resumable, registry manifest-last, referrers pushed |
| `cli` | 102 | exit-code mapping per error class, build / publish / verify / sbom / inspect happy paths, registry-pull (incl. token dance, 5xx retry, digest mismatch rejection) |
| **total** | **~280** | |

Each row is a real bug-class count, not a line-of-code count.

## Test environment expectations

- **No flakiness.** Tests pass on every run, every host, every
  retry. If a test is flaky, fix it or delete it.
- **No external network.** Tests use `httpmock` to stand up
  in-process HTTP servers. Real registry tests are gated behind
  `--ignored` so CI's main run stays hermetic.
- **No real cosign in the main test set.** Tests use the
  `StubCosignInvoker` / `StubCosignVerifyInvoker` to script
  outcomes. The cosign-on-PATH probe runs as `--ignored` and is
  exercised in CI with `cosign` actually installed via
  `sigstore/cosign-installer@v3`.
- **Tempdir per test.** No shared global state across tests;
  each test creates its own `tempfile::TempDir` and tears down
  on drop.
- **`OCIMAGE_*` env tests serialised.** Tests that mutate
  process-wide env (`OCIMAGE_COSIGN_BIN`, `REGISTRY_TOKEN`) use
  a `Mutex` to serialise. CI runs them with `--test-threads=1`
  in the dedicated `--ignored` pass.

## Smoke tests

One `#[ignore]`-gated test per real-world dependency the unit
suite can't fake convincingly. Each one names the wire-shape /
behavioural-drift bug class it catches that mocks miss:

| Test | Crate | Real dep | Bug class caught |
|------|-------|----------|------------------|
| `test_full_pipeline_against_real_registry_2_container` | `cli` | Docker + `registry:2` | OCI Distribution v2 wire-shape drift between httpmock and a real registry: upload-session UUIDs, stateful HEAD-then-PUT skip-if-exists across re-publishes, manifest media-type negotiation, manifest byte-equality round-trip |
| `verify_go.sh` (CI: `jcs-cross-lang`) | repo-root `tests/fixtures/jcs/` | Go ≥1.22 + `gowebpki/jcs` | Cross-language JCS / spec-hash drift: a Go re-implementation of `spec_to_json` + `gowebpki/jcs` must byte-match the Rust impl on every fixture, otherwise Production Guarantee §3 (same spec → same hash across language re-impls) is broken |

## Cross-language JCS fixtures

The set under [`tests/fixtures/jcs/`](../../tests/fixtures/jcs/)
ships representative spec fixtures (anchor, unicode strings, numeric
edge cases, recursive lex key ordering, full vm_image) along with
the JCS canonical bytes and `sha256:<hex>` digest the Rust impl
produces. Each fixture's `README.md` names the cross-language
regression class it surfaces — e.g. a Python re-impl using
`json.dumps(..., ensure_ascii=True)` would fail `unicode-strings/`,
a Go re-impl using natural-sort key ordering would fail
`nested-key-ordering/`.

The `jcs-cross-lang` CI job runs three checks:

1. `cargo run --bin regenerate-jcs-fixtures -- --check` — fails
   loudly if a contributor edited a fixture's `spec.toml` without
   re-running the regeneration binary, so the Rust impl and the
   committed expected files would no longer agree.
2. `bash tests/fixtures/jcs/verify_go.sh` — compiles the Go-side
   re-implementation under `tests/fixtures/jcs/verify_go/` and
   asserts byte-for-byte agreement with every fixture.
3. The same drift catches surface in `cargo test --workspace` via
   the `jcs_fixtures_test` integration test in the `spec` crate
   (asserts `canonical_bytes` and `spec_hash` match the committed
   expected files for every fixture).

Python parity (via `verify_python.py` + the PyPI `jcs` package) is
available for local runs but is not part of the CI gate — Go is
the mandatory cross-language check.

Smoke tests are NOT run by `cargo test --workspace`. They run
under:

```bash
cargo test -p swe_justoci_oci_cli --test registry_smoke_test \
    -- --ignored --test-threads=1
```

CI's dedicated `smoke` job exercises them on `ubuntu-latest`
(Docker pre-installed). Each smoke test prints a `SKIP` line
on stderr and returns `Ok` when its real dep is unavailable
on the host — local `cargo test --workspace -- --ignored` on
a Docker-less laptop won't fail spuriously.

## What's NOT tested

- **Real Sigstore Fulcio + Rekor.** The keyless flow opens a
  browser for OIDC; CI isn't equipped for that. The cosign
  subprocess + the `CosignInvoker` trait are tested with stubs.
  Real Sigstore integration is a v0.2 task using `sigstore-rs`.
- **Multi-platform manifests.** v1.0 work; v0 specs target one
  platform per artifact.
- **Range-request resumability.** v1.0 work; v0 retries the
  whole blob.

## CI gates

The workflow's `test` job runs:

```bash
cargo check --workspace --all-targets
cargo test  --workspace
cargo test  --workspace -- --ignored --test-threads=1   # cosign-on-PATH probe
```

The workflow's `clippy` job runs:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

The workflow's `fmt` job runs:

```bash
cargo fmt --all -- --check
```

The workflow's `smoke` job runs:

```bash
cargo test -p swe_justoci_oci_cli --test registry_smoke_test \
    -- --ignored --test-threads=1
```

All under `RUSTFLAGS=-D warnings`. Any warning fails the build.
This is how the "no `#[allow(...)]` dances" rule survives across
PRs.

## Coverage philosophy

Coverage % is not tracked. The bug-it-catches rule is stricter:
"100% statement coverage" is meaningless if the assertions are
tautological, and the rule forces every test to do real work.

If a code path has no test, ask why. Either:
1. Write the test that names the bug it catches; or
2. Delete the code path.

Untested-but-shipped code is technical debt. Untested-and-
deleted code is freedom.
