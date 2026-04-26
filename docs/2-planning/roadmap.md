# Roadmap

## v0 — shipped

The full pipeline, end-to-end. ~286 default-feature tests across
the workspace plus 14 `#[ignore]`-gated tests for real-dep
integration (Docker registry, cosign-on-PATH, Vault dev-server,
Sigstore staging).

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
| Docs | SDLC-phase documentation tree | ✓ | `b0f55e1` |

## Recent batch — closed since the docs tree commit

| Issue | Title | Commit |
|------:|-------|--------|
| #2 | `--require-referrers` strict mode | `e318101` |
| #3 | Public `MediaType::parse` API | `c023560` |
| #4 | MSRV pin (1.86) + CI gate | `7db6a1a` |
| #5 | Move `oci-systemd` to vmisolate | `3772222` / vmisolate `09f6d56` |
| #6 | Dogfood example (`examples/dogfood/`) | `6daeec2` |
| #7 | Real registry smoke test (gated) | `1aec209` |
| #10 | Cross-language JCS fixture | `6fb2a1d` |
| #13 | sigstore-rs migration | `958b85d` |
| #14 | Sigstore staging e2e harness (skip-pass mode) | `78b31f4` |
| #15 | Vault credential provider | `e68a481` |
| #16 | Docker config credential provider | `23cb3ec` |
| #17 | `CredentialProvider` trait refactor | `b2edd2c` |
| #18 | Canonicalisation projection-rule docs | `6a8b14f` |
| #19 | Stale JCS fixture comment | `c4cf8f4` |
| (license) | Relicense MIT → Apache-2.0 | `b88866e` (justoci) / `82e81fc` (justcas) |
| (research) | Research notes (Apache-vs-MIT, OCI providers) | `f639751` / `21522ac` |
| (design) | Scope-and-boundaries doc — "justoci stands alone" | `b3ecf74` |

## v0.2 — outstanding

- **`[[files]]` overlay support for `vm_image`** — vmisolate#70.
  The vmisolate adapter rejects non-empty `[[files]]` with a typed
  error today. Cross-platform ext4 manipulation (mount → copy →
  unmount → re-hash, or a portable Rust ext4 writer). 2-4 days.
- **HTTP Range-resumable blob pulls** — issue #8. Per-blob retry
  works today; mid-blob resume on long downloads is next. 1-2 days.
- **Parallel layer downloads on pull** — issue #9. `--parallel <N>`
  flag. Cancel-on-error semantics need care. 1-2 days.
- **crates.io publication** — issue #12. ~1-2 hours setup. Defer
  until v0.2 stabilises (commits us to API stability).
- **`docker-config` credHelpers subprocess delegation** — issue
  #20. Today's provider supports the inline `auth` field; full
  credHelpers (e.g. `docker-credential-ecr-login`) is a follow-up.
- **CI vault-e2e job** — issue #22. The Vault provider's three
  `#[ignore]`-gated tests need a Vault dev-server in CI to
  actually run.
- **Tracking: sigstore-rs upstream gap** — issue #21 / upstream
  `sigstore/sigstore-rs#562`. No public `SigningContext::staging()`;
  blocks our staging e2e from running real signing. CI job is wired
  and SKIP-passes today; activates automatically when upstream
  lands.

## v1.0 — on the runway

- **Multi-platform manifests** — issue #11. `spec_version = "1"`.
  Single artifact ID → image index with per-platform manifests.
  CLI `--platform <os/arch>` selector. JCS canonicalisation
  rules updated. Cross-language fixture extended. 1-2 weeks.
- **vmisolate workspace MSRV pin** — vmisolate#71. Same treatment
  as justoci had in #4 (pin via `[workspace.package]` + CI gate).
  Independent of the rest of v1.0. ~1-2 hours.

## Open questions

- **`pentest`-shaped work** (CVE / secrets scanning over published
  artifacts). Out of scope for v0; if user demand materialises, the
  right answer is a separate sibling repo (`justpentest` or
  similar) that consumes justoci's SBOM output, not folded into
  justoci itself. See `docs/3-design/scope-and-boundaries.md`.

## Decision log

- **2026-04-26** — Audited xikaftin parallel project. Concluded
  justoci stays self-contained; port ideas not deps. License
  migrated to Apache-2.0 (`b88866e` / `82e81fc`) — correct
  destination independent of the integration question. See
  `docs/3-design/scope-and-boundaries.md`.
- **2026-04-26** — sigstore-rs migration (issue #13). Subprocess
  fallback retained behind `cosign-subprocess` feature for
  air-gapped builds; new `SigstoreInvoker` (linked-in SDK) is the
  default. §6 Rekor-coupling preserved at the SDK level.
- **2026-04-26** — `CredentialProvider` trait refactor (issue
  #17) replaced the `AuthMode` enum at the auth layer. New
  providers (Vault #15, Docker config #16) compose without
  touching the core. Vault and Docker-config gated behind
  Cargo features so the default binary stays lean (default
  binary is unchanged; `--features vault` adds +862 KiB,
  `--features docker-config` adds +22 KiB).
