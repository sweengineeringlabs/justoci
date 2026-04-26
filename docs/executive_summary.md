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
verify, sbom, inspect). 258 tests across the workspace, every test
named with the bug it would catch (no smoke tests, no tautological
assertions). CI runs on every push under `RUSTFLAGS=-D warnings`
with cosign installed in the runner so the cosign-on-PATH probe is
exercised against real cosign in CI.

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
- `systemd` — xkvm-specific `.service` generator (will move out;
  not part of the generic product).

External: [`justcas`](https://github.com/sweengineeringlabs/justcas)
sibling repo, content-addressed-storage primitive.

## Roadmap

- v0 (shipped): everything above.
- v0.2 (in flight): `[[files]]` overlay support for `vm_image`,
  `sigstore-rs` migration to drop the cosign subprocess.
- v1.0: multi-platform manifests, registry-pull resumability via
  HTTP range requests, parallel layer downloads.
