# Roadmap

## v0 — shipped

The full pipeline, end-to-end, with ~258 tests across the
workspace.

| Phase | Scope | Status | Commit |
|-------|-------|--------|--------|
| P0 | `spec` crate — TOML parser + validator + JCS canonicaliser | ✓ | `bc12925` |
| P1A | `build` crate — Spec → OCI Image Layout v1.1 | ✓ | `ebb0822` |
| P1B | `attest` crate — SLSA + CycloneDX/SPDX SBOM + cosign+Rekor | ✓ | `7ad82b7` |
| P1C | `publish` crate — HTTP + OCI Distribution sinks | ✓ | `55d016a` |
| Fragility fix | `LoadedSpec` wrapper + streaming compression | ✓ | `0bbd4ca` |
| P2 | `cli` — 5 subcommands, typed exit codes | ✓ | `11f73d1` |
| Cleanup | Drop legacy ImageSpec / BuildManifest from build | ✓ | `a59d2e5` |
| P3 | vmisolate-side `oci-image-builder` adapter | ✓ | `ab8631b` |
| v0.2 | `ocimage verify <registry-ref>` (pull-then-verify) | ✓ | `31a7c89` |
| CI | GitHub Actions for both repos | ✓ | `b47085e` / `44f4ad9` |
| Docs | SDLC-phase documentation tree | ✓ | (this commit) |
| Refactor | Move `oci-systemd` to vmisolate (xkvm-specific) | ✓ | (issue #5) |
| Dogfood | Full pipeline against `registry:2`, no-attest path (`examples/dogfood/`) | ✓ | (issue #6) |

## v0.2 — in flight / next

- **`[[files]]` overlay support for `vm_image`** — the vmisolate
  adapter currently rejects non-empty `[[files]]` with a typed
  error. Implementation needs cross-platform ext4 manipulation
  (mount → copy → unmount → re-hash) or a portable Rust ext4
  writer. Tracked as v0.1 work for the adapter.

- ~~**`sigstore-rs` migration in `attest`**~~ — **DONE (issue
  #13)**. The cosign subprocess shell-out has been replaced with
  the linked-in [`sigstore`](https://crates.io/crates/sigstore)
  SDK as the production path. Same security guarantees (Fulcio +
  Rekor + transparency log), no PATH dependency. The
  `CosignInvoker` trait was the migration seam: the new
  `SigstoreInvoker` and the legacy `RealCosignInvoker` (now
  gated behind the opt-in `cosign-subprocess` feature) both
  implement it, and every existing test runs against both via
  `StubCosignInvoker` injection. The §6 Rekor-coupling rule is
  preserved end-to-end — sigstore-rs's `SigningSession::sign`
  errors when Rekor write fails, so a Rekor-less bundle is
  unreachable on the new path. See `docs/3-design/cosign-rekor.md`
  for the updated flow.

- **Real Sigstore staging end-to-end test (issue #14)** — still
  pending. Issue #13 ships the SDK migration with stubbed unit +
  integration tests; #14 adds a `#[ignore]`-gated test that
  drives a real OIDC flow against `fulcio.sigstage.dev` /
  `rekor.sigstage.dev` from a CI job with `id-token: write`. Not
  shipped inline with #13 because the GitHub Actions OIDC bootstrap
  is non-trivial and the failure modes (token exchange, audience
  mismatch, staging-trust-root drift) are best handled in their
  own commit.

- **`--require-referrers` strict mode for verify** — today, a
  registry that returns 404 on `/v2/.../referrers/<digest>` is
  silently treated as "no attestations" so pre-OCI-1.1 registries
  don't error out. Strict mode would escalate this to a hard error
  for consumers who want to refuse artifacts without referrer
  support.

## v1.0 — on the runway

- **Multi-platform manifests.** `spec_version = "1"` work — a
  single artifact ID points at an image index whose manifests are
  per-platform (`linux/amd64`, `linux/arm64`, `linux/none-armv7`).
  Selector flag on the CLI: `--platform <os/arch>`.

- **HTTP range-request resumability.** Per-blob retry is
  implemented; partial-blob resume on long downloads is the
  follow-up.

- **Parallel layer downloads on pull.** Sequential is simpler and
  observable; throughput on small artifacts is bound by manifest
  fetch anyway. Enable parallel for large artifacts via a
  `--parallel <N>` flag.

- **`MediaType::parse` exposed publicly.** Today programmatic
  callers (the vmisolate adapter) round-trip through TOML to
  construct a `Spec`. Exposing `MediaType::parse(&str)` as public
  with full validation lets adapters skip the round-trip.
  Defensible to defer because the round-trip enforces
  single-validator integrity; the wart is real but rare. See
  P3 worker E's "surprises" report.

## Open questions

- **crates.io publication.** Today both repos use git path-deps.
  Publishing to crates.io makes adoption easier for outside
  consumers but commits us to API stability earlier than v0
  warranted. Defer until v0.2 stabilises.

- **MSRV pin.** `Cargo.toml` files currently say `rust-version =
  "1.75"` or `"1.86"`. Should pin a single MSRV across the
  workspace and assert it in CI. Bookkeeping, not a v0 blocker.
