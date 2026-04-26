# justoci — executive summary

## What

An opinionated build / publish / attest pipeline for content-addressed
OCI artifacts. One TOML file in, one fully-attested OCI Image Layout
v1.1 directory out, ready to push to any OCI distribution registry.

## Who it's for

Teams shipping **non-container OCI artifacts** to production:

- **VM image producers** — appliance / firmware / boot-image vendors
  who need SLSA + cosign for compliance but don't want to roll their
  own pipeline.
- **ML-model distributors** — shipping quantised weights as oras-style
  OCI artifacts with provenance attached.
- **Embedded firmware teams** — flashing signed firmware to fleets,
  needing per-build SLSA provenance + SBOMs for scan tooling.
- **Anyone using `oras` + `cosign` + bash today** for a non-container
  artifact and wanting one tool that does it all.

Not for container builds — Docker / Buildah / `ko` / BuildKit own
that space and do it well.

## The product opinion

**Attestation is on by default.** Every artifact built by justoci
gets SLSA provenance, a CycloneDX SBOM, and a cosign signature
unless the spec explicitly opts out. The opt-out is for testing and
developer iteration; production builds get all three pillars.

This is the differentiation. Today's `oras` + `cosign` + bash
pipelines work but require teams to wire SLSA, SBOMs, and signing
themselves and remember to keep them in sync as artifacts evolve.
justoci packages the opinion: ship to prod, ship attested.

## Status

v0 frozen. Five CLI subcommands working end-to-end (build, publish,
verify, sbom, inspect). **~286 default-feature tests across the
workspace, every test named with the bug it would catch** (no smoke
tests, no tautological assertions). CI runs on every push under
`RUSTFLAGS=-D warnings` with cosign installed in the runner so the
cosign-on-PATH probe is exercised against real cosign in CI.

Plus 14 `#[ignore]`-gated tests for real-dep integration:
- Cosign-on-PATH probe (covered by CI's `cosign-installer` step).
- Real `registry:2` Docker container (covered by CI's `smoke` job).
- `examples/dogfood/run.sh` end-to-end pipeline (manual + Docker).
- Vault dev-server provider tests (issue #22 wires the CI job).
- Sigstore staging e2e harness (CI job wired; SKIP-passes pending
  upstream `sigstore/sigstore-rs#562`).
- Cross-language JCS verification — Go (`gowebpki/jcs`) mandatory in
  CI; Python (`pyjcs`) optional, ships verifier alongside.

## The spec, distilled

```toml
spec_version = "0"
id           = "device-firmware:1.4.2"
kind         = "raw_image"

[[layers]]
source     = "build/firmware.bin"
media_type = "application/vnd.devboard-x7.firmware+binary"

[annotations]
"org.opencontainers.image.version" = "1.4.2"

# [attestation] omitted -> defaults apply:
#   SLSA L2 + CycloneDX SBOM + cosign-keyless
```

Three artifact `kind`s in v0: `oci_artifact` (oras-style generic),
`vm_image` (kernel + initrd + rootfs), `raw_image` (single flashable
blob). Adding new kinds is additive — see
[`4-development/adding-a-kind.md`](./4-development/adding-a-kind.md)
for the recipe.

## Production guarantees, distilled

- **Reproducible.** Same spec + same source files → bit-identical
  artifact digest.
- **Spec hash via JCS.** RFC 8785, language-agnostic, so re-impls in
  Go / Python compute the same hash for the same input.
- **Atomic build, atomic publish.** Failed runs leave `.partial`
  state for diagnosis; the final artifact only exists when
  self-consistent.
- **Coupled signing.** `cosign sign` succeeds → Rekor record
  confirmed → artifact considered signed. No half-states.
- **Integrity on every read.** Pulling a blob from the CAS
  re-hashes; corruption surfaces as a typed error.

Full list at [`3-design/spec-v0.md`](./3-design/spec-v0.md)
§"Production guarantees".

## Repo layout

- `spec` — TOML parser + validator + JCS canonicaliser.
- `build` — `Spec` → OCI Image Layout v1.1.
- `attest` — SLSA + SBOM + cosign+Rekor.
- `publish` — HTTP + OCI Distribution sinks.
- `cli` — `ocimage` operator CLI (5 subcommands).

External: [`justcas`](https://github.com/sweengineeringlabs/justcas)
sibling repo, content-addressed-storage primitive.

## Roadmap

- v0 (shipped): everything above + sigstore-rs SDK migration (#13)
  + Vault and Docker-config credential providers (#15 / #16) +
  CredentialProvider trait surface (#17) + cross-language JCS
  fixture set (#10) + license migration to Apache-2.0.
- v0.2 (next): `[[files]]` overlay support (vmisolate#70),
  HTTP Range-resumable pulls (#8), parallel layer downloads (#9),
  crates.io publication (#12), CI vault-e2e job (#22),
  credHelpers subprocess delegation (#20).
- v1.0: multi-platform manifests (#11). Tracked
  upstream-blocked: real Sigstore staging end-to-end signing
  (issue #21 / `sigstore/sigstore-rs#562`).

See `docs/2-planning/roadmap.md` for the full table with commit
hashes.
