# justoci spec v0

*One TOML file → attested OCI artifact, for any artifact type.*

## What this is

The justoci spec is a single TOML file that describes everything needed
to produce a content-addressed, attested OCI artifact: identity, layers,
config, annotations, and attestation policy. One spec → one artifact.

The product opinion: **attestation is on by default.** Every artifact
built by justoci gets SLSA provenance, a CycloneDX SBOM, and a cosign
signature unless the spec explicitly opts out. No separate sign step,
no separate SBOM step, no separate provenance pipeline.

## Why TOML

- One file, human-readable, no YAML indentation traps.
- Round-trips cleanly to the OCI manifest's JSON config blob.
- `cargo`, `pyproject`, and the broader Rust/Python tooling ecosystem
  already standardise on it.

## Top-level structure

```toml
id          = "<name>:<tag>"   # required
kind        = "<artifact-kind>" # required — see "Kinds" below
description = "..."             # optional

[platform]                      # optional
os   = "linux"
arch = "x86_64"

[[layers]]                      # ordered, at least one required
source      = "path/to/blob"
media_type  = "application/vnd.example+binary"
compression = "gzip"            # optional: gzip | zstd | none

[config]                        # optional, kind-specific
# arbitrary keys → serialised as the OCI image config blob

[annotations]                   # optional — keys land on the OCI manifest
"org.opencontainers.image.title" = "..."

[attestation]                   # optional — defaults below
slsa.level        = 2           # 0 (off) | 1 | 2 | 3 | 4
slsa.builder_id   = "..."       # default: <git remote>@<rev>
sbom.format       = "cyclonedx" # cyclonedx | spdx | off
sbom.scope        = "layers"    # layers | sources | both
sign.kind         = "cosign-keyless"   # cosign-keyless | cosign-key | off
sign.identity     = "..."       # for keyless: OIDC identity; for key: path
```

## Kinds

`kind` is the artifact-type discriminator. v0 ships three:

| `kind`         | What it is                                             | Sample media types                              |
|----------------|--------------------------------------------------------|-------------------------------------------------|
| `oci_artifact` | Generic OCI artifact (oras-style). Fully type-agnostic. | Caller-defined (`application/vnd.<vendor>+...`) |
| `vm_image`     | Bootable VM image — kernel + initrd + rootfs.          | `application/vnd.vmisolate.kernel+binary` etc.  |
| `raw_image`    | Single flashable blob (firmware, disk image).          | `application/vnd.firmware.raw+binary` etc.      |

Each kind has a recommended `[config]` schema (see worked examples).
Unknown keys in `[config]` are passed through to the OCI config blob
verbatim — the kind's role is *validation*, not *transformation*.

## Layers

Layers are content-addressed blobs that become OCI layer descriptors:

- `source` — file path relative to the spec file's directory.
- `media_type` — full OCI media type. Custom vendor types are encouraged
  for non-container artifacts (`application/vnd.<vendor>.<thing>+<format>`).
- `compression` — `gzip` (default for `+gzip` media types), `zstd`, or
  `none` (default otherwise). Compression happens at build time; the
  resulting layer's media type reflects the compressed form.
- The layer's digest (sha256) is computed at build time and recorded
  both in the OCI manifest and the SLSA statement.

Layer order is preserved exactly — for VM images, it determines boot
order (kernel → initrd → rootfs by convention).

## Config blob

`[config]` becomes the OCI image config (referenced by digest from the
manifest). The schema is *kind-specific* but justoci doesn't enforce
field types — it serialises the TOML to JSON and embeds. Type-specific
validation lives in *consumer* tools (e.g. vmisolate validates `vm_image`
configs against its own `ConfigManifest`).

This is deliberate: justoci is the *transport* and *attestation* pipeline.
The "what does this artifact mean" knowledge lives in the consumer.

## Attestation: the opinion

If `[attestation]` is omitted entirely, these defaults apply:

```toml
[attestation]
slsa.level      = 2
slsa.builder_id = "<git remote>@<rev>"   # auto-derived
sbom.format     = "cyclonedx"
sbom.scope      = "layers"
sign.kind       = "cosign-keyless"
# sign.identity left unset → cosign uses the ambient OIDC identity
```

To opt out of any pillar, set its top-level field to `"off"` / `0`:

```toml
[attestation]
slsa.level  = 0
sbom.format = "off"
sign.kind   = "off"
```

But the product position is: **don't.** If your artifact ships to
production, all three pillars matter. The opt-out exists for testing
and developer iteration, not for production builds.

### What you get

- **SLSA statement** — in-toto `Statement` with `predicateType =
  https://slsa.dev/provenance/v1`. Names the builder, the spec hash,
  the resolved layer digests, the build-time invocation. Stored
  alongside the artifact as a referrer (OCI 1.1 referrers API).
- **SBOM** — CycloneDX 1.5 (default) or SPDX 2.3. Scope `layers`
  enumerates layer contents; `sources` enumerates the build-time deps;
  `both` does both.
- **Signature** — cosign over the artifact digest. Keyless mode uses
  Sigstore's Fulcio + Rekor by default.

All three live as **OCI 1.1 referrers** of the main artifact — pull
the artifact, you can list and verify its attestations from the same
registry without a separate signing service.

## Worked examples

Three reference specs ship in `examples/`:

1. [`examples/vm-image.toml`](../examples/vm-image.toml) — vmisolate
   VM image (kernel + initrd + rootfs.ext4 + xkvm boot config). Shows
   the `vm_image` kind end-to-end.
2. [`examples/oci-artifact.toml`](../examples/oci-artifact.toml) —
   ML model weights (GGML quantized Llama-7B). Shows generic
   `oci_artifact` with vendor media types and an opaque config blob.
3. [`examples/firmware.toml`](../examples/firmware.toml) — embedded
   device firmware as a raw flashable image. Shows the minimal
   `raw_image` case with no entrypoint, no rootfs.

Each example demonstrates a different default-attestation outcome.

## CLI surface

```
ocimage build   <spec.toml> [-o <dir>]      # produce artifact + attestations
ocimage publish <dir> --to <sink>           # push to HTTP / OCI registry
ocimage verify  <ref>                       # verify SLSA + SBOM + signature
ocimage sbom    <spec-or-ref> [-o <file>]   # emit/extract SBOM only
```

Build and publish are decoupled so CI can sign artifacts in a
hardened environment separate from the build host.

## Out of scope for v0

- **Multi-platform / fat manifests.** A spec describes one artifact for
  one platform. Multi-platform images come in v1.
- **Build-time scripts.** Layers are pre-existing files; justoci does
  not run a builder. (vmisolate runs its own image build *before*
  invoking justoci.)
- **Mutable tags / image promotion.** Build outputs are content-
  addressed; tag management is the registry's job.
- **In-toto attestation chains.** v0 emits a single SLSA statement;
  multi-step attestation chains land later.

## Open questions (to resolve before v0 freeze)

1. **Compression default for unknown media types** — `none` or `zstd`?
   `none` is safest (matches `oras` behaviour); `zstd` saves bandwidth
   for free. Lean: `none`, callers opt in.
2. **`[[files]]` convenience block** — generate a layer from individual
   files (with `source`, `dest`, `mode`) instead of a pre-built tarball.
   Useful, but adds a "build a layer" responsibility justoci was trying
   to avoid. Lean: ship in v0.1, not v0.
3. **Spec hashing algorithm** — sha256 over the canonical TOML serialisation
   for the SLSA statement's spec ref. Need to pin which TOML library's
   canonical form, or define our own.
