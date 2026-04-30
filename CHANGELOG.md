# Changelog

All notable changes to justoci are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). justoci uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) starting at 1.0.0; releases prior to 1.0.0 are versioned `0.x.y` and may contain breaking changes between minor versions.

---

## [Unreleased]

### Planned (v0.2)

- `[[files]]` overlay support for vmisolate initramfs composition (issue #7 / vmisolate#70)
- HTTP Range-resumable layer downloads (issue #8)
- Parallel layer downloads (issue #9)
- crates.io publication of all five crates (issue #12)
- CI Vault dev-server end-to-end job (issue #22)
- `credHelpers` subprocess credential delegation (issue #20)

---

## [0.1.0] — 2026-04-28

Initial release of the justoci attested OCI artifact pipeline.

### Added

**Five-crate workspace:**
- `swe_justoci_spec` — TOML spec parser, JCS canonicalisation (RFC 8785), validator. Three artifact kinds: `oci_artifact`, `vm_image`, `raw_image`.
- `swe_justoci_oci_build` — `LoadedSpec` → OCI Image Layout v1.1. Streaming compression (gzip/zstd), deterministic tar (sorted entries, `mtime=0`, `uid:gid=0:0`), atomic output rename.
- `swe_justoci_attest` — Three attestation pillars: SLSA Provenance v1, CycloneDX 1.5 / SPDX 2.3 SBOM, cosign+Rekor coupled signing. All emitted as OCI 1.1 referrer manifests. Migrated default signer from cosign subprocess to `sigstore-rs` SDK (issue #13).
- `swe_justoci_oci_publish` — OCI Image Layout → HTTP sink or OCI Distribution v2 registry. Per-blob HEAD-then-PUT idempotency; manifest written last (atomicity). Resumable on transient failures.
- `swe_justoci_oci_cli` — `justoci` operator CLI: `build`, `publish`, `verify`, `sbom`, `inspect`. Typed exit codes per spec §7. Auth: anonymous, bearer/env-var, Vault (feature-gated), Docker-config (feature-gated).

**Registry operations:**
- `justoci verify` supports both local OCI Image Layout paths and live registry references. On-the-fly digest verification during streaming pull; rejection before write on mismatch.
- `--require-referrers` strict mode: exits 5 on a registry that does not implement the OCI 1.1 referrers endpoint.
- `--policy` file gating: SLSA level, cosign `builder_id` glob, required SBOM format.
- Bearer token dance (OCI Distribution §3.4) handled transparently.

**Credential providers:**
- `--auth vault` (behind `--features vault`): HashiCorp Vault KV v2 path keyed by registry host.
- `--auth docker-config` (behind `--features docker-config`): reads `~/.docker/config.json`; does not require Docker daemon.

**Cross-language JCS fixture set:**
- Five fixtures covering anchor, unicode strings, numeric edge cases, nested key ordering, full `vm_image`. Each fixture ships canonical bytes + `sha256:<hex>` for Go/Python cross-language verification.
- CI `jcs-cross-lang` job: Rust regeneration check + Go re-implementation (`gowebpki/jcs`) mandatory; Python optional.

**Test suite:**
- ~306 default-feature tests across the workspace; every test named with the bug it would catch.
- 14 `#[ignore]`-gated integration tests for real-dep surfaces (cosign-on-PATH, `registry:2`, Sigstore staging, Vault).

**Documentation:**
- Phase-organised docs: ideation, design, development, testing, deployment.
- Architecture with four Mermaid diagrams (inclusion, block, data flow, sequence).
- Production guarantees encoded and enforced across nine non-functional requirements.

### Changed

- License migrated from MIT to Apache-2.0 (commit `b88866e`) to match OCI specs, Sigstore, and the CNCF ecosystem. Matches `justcas`, `justsign`, `justext4`, `vmisolate`.

### Fixed

- `CredentialProvider` chain: `docker-config` provider now correctly falls through to the next provider on missing credentials rather than returning a hard error.
- `Digest::parse` rejects uppercase hex (was silently accepting, creating potential HashMap collision surface).

---

[Unreleased]: https://github.com/sweengineeringlabs/justoci/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sweengineeringlabs/justoci/releases/tag/v0.1.0
