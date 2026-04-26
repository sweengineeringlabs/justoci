# justoci

**One TOML file → attested OCI artifact, for any artifact type.**

`justoci` is an opinionated build / publish / attest pipeline for
content-addressed OCI artifacts. The opinion that distinguishes it
from `oras` + `cosign` + a bash script: **attestation is on by
default**. Every artifact you build gets SLSA provenance, a CycloneDX
SBOM, and a cosign signature unless your spec explicitly opts out.

It is not a container builder. It targets the **non-container
artifact niche** OCI's spec was extended to cover but no opinionated
tool serves end-to-end:

- **VM images** (kernel + initrd + rootfs.ext4)
- **Firmware** (raw flashable blobs for embedded devices)
- **Generic OCI artifacts** (oras-style — ML weights, Helm charts,
  WASM modules, bespoke binary blobs)

For each kind, you write one TOML spec file and run `ocimage build`.
The output is a real OCI Image Layout v1.1 directory consumable by
`oras pull`, `crane pull`, or any OCI distribution registry, with
SLSA + SBOM + cosign attestations attached as OCI 1.1 referrers.

## What you write

```toml
spec_version = "0"
id           = "device-firmware:1.4.2"
kind         = "raw_image"

[[layers]]
source     = "build/firmware.bin"
media_type = "application/vnd.devboard-x7.firmware+binary"

[annotations]
"org.opencontainers.image.version" = "1.4.2"
"vendor.device.model"              = "DevBoard-X7"

# [attestation] omitted -> defaults apply:
#   SLSA L2 + CycloneDX SBOM + cosign-keyless
```

## What you run

```bash
ocimage build   spec.toml -o dist/
ocimage publish dist/ --to registry:ghcr.io/acme/firmware:1.4.2
ocimage verify  ghcr.io/acme/firmware:1.4.2 --policy policy.toml
```

Five subcommands total: `build`, `publish`, `verify`, `sbom`,
`inspect`. Each uses typed exit codes per the spec doc so CI
pipelines route on exit code, not stderr parsing.

## Crates

| Crate     | Package                       | Role                                                                                  |
|-----------|-------------------------------|---------------------------------------------------------------------------------------|
| `spec`    | `swe_justoci_spec`            | TOML parser + validator + JCS canonicaliser. The single source of truth for v0 specs. |
| `build`   | `swe_justoci_oci_build`       | `Spec` → OCI Image Layout v1.1. Streaming compression, deterministic tar, atomic.     |
| `attest`  | `swe_justoci_attest`          | SLSA v1 provenance + CycloneDX/SPDX SBOM + cosign-with-Rekor. All as OCI referrers.  |
| `publish` | `swe_justoci_oci_publish`     | HTTP sink + OCI Distribution v2 sink. HEAD-then-PUT idempotence, manifest-last commit. |
| `cli`     | `swe_justoci_oci_cli`         | `ocimage` operator CLI. Five subcommands, typed exit codes.                          |
| `systemd` | `swe_justoci_oci_systemd`     | Generate systemd `.service` units that boot a built image. (Will move out — xkvm-specific.) |

External: `cas` lives at the [`justcas`](../justcas) sibling repo
(content-addressed-storage primitive — sha256 digests, atomic put,
streaming integrity verification).

## Why TOML, why opinionated

**TOML.** One file, no YAML indentation traps, round-trips cleanly
into the OCI manifest's JSON config blob. The Rust + Python ecosystem
has standardised on TOML for `cargo`, `pyproject`, `uv`, and others —
operators don't need a new format to learn.

**Opinionated.** Today's appliance / firmware / VM-image teams stitch
attested-publish from `oras` + `cosign` + bash. The pieces work but
nobody packages them with sane defaults. justoci's opinion: if you
ship to production, you sign + provenance + SBOM. The opt-out is for
testing, not for the production path.

## Production guarantees

These are encoded in the code, not just the docs. See
[`docs/spec-v0.md`](docs/spec-v0.md) §"Production guarantees" for
the full list. Highlights:

- **Reproducible.** Same spec + same source files → bit-identical
  artifact digest. Pinned compression levels, sorted-entry tars,
  no embedded timestamps in the manifest.
- **Spec hash via JCS.** RFC 8785 JSON Canonicalization Scheme over
  the TOML→JSON projection. Language-agnostic — re-implementations
  of justoci in Go / Python compute the same hash for the same input.
- **Atomic build.** Failed builds leave `*.partial` for diagnosis;
  the final output dir never exists in a half-written state.
- **Atomic publish.** Manifest writes last (HTTP sink writes
  `index.json` last; registry sink PUTs the manifest last). Failed
  publishes never expose a half-pushed image.
- **Coupled signing.** `cosign sign` succeeds → Rekor record
  confirmed → only then is the artifact "signed". If Rekor fails,
  the artifact is unsigned (no half-states).
- **Integrity on every read.** Pull a blob from the CAS, the bytes
  are re-hashed before return; corruption surfaces as a typed error,
  never as silent bad bytes.

## Documentation

- [`docs/spec-v0.md`](docs/spec-v0.md) — the spec format, frozen for v0.
- [`examples/vm-image.toml`](examples/vm-image.toml) — vmisolate VM image.
- [`examples/oci-artifact.toml`](examples/oci-artifact.toml) — generic oras-style artifact (ML weights).
- [`examples/firmware.toml`](examples/firmware.toml) — raw flashable firmware.

## Build

```
cargo build --workspace
cargo test  --workspace
```

## Status

v0 — frozen spec format, all five CLI subcommands working, ~250 tests
across the workspace. Each test names a real bug it would catch
(no smoke / tautological tests).

What's next on the roadmap:

- **`[[files]]` overlay** for vm_image kind — derived rootfs assembly
  with file overlay applied at build time.
- **`sigstore-rs`** in `attest` — replace the cosign subprocess shell-out
  with linked-in signing (no PATH dependency in production).
- **Multi-platform manifests** (`spec_version = "1"` work).

## Sibling repos

- [`vmisolate`](../vmisolate) — microVM platform. Uses justoci for
  image build via the `oci-image-builder` adapter.
- [`justcas`](../justcas) — content-addressed-storage primitive
  underlying every blob in justoci.
