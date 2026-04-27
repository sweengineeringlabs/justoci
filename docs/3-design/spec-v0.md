# justoci spec v0

*One TOML file → attested OCI artifact, for any artifact type.
Production-grade from day one — no opt-in robustness, no later "we'll
harden it" milestones.*

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
spec_version = "0"              # required — pins parser semantics
id          = "<name>:<tag>"    # required
kind        = "<artifact-kind>" # required — see "Kinds" below
description = "..."             # optional

[platform]                      # optional
os   = "linux"
arch = "x86_64"

[[layers]]                      # at least one required, ordered
source      = "path/to/blob"    # mutually exclusive with [[layers.files]]
media_type  = "application/vnd.example+binary"
compression = "none"            # none (default) | gzip | zstd

# Or — build a layer from individual files:
[[layers]]
media_type = "application/vnd.example.tar+gzip"
compression = "gzip"
[[layers.files]]
source = "config/app.toml"
dest   = "/etc/app.toml"
mode   = 0o644

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

| `kind`         | What it is                                              | Layer count   | Sample media types                              |
|----------------|---------------------------------------------------------|---------------|-------------------------------------------------|
| `oci_artifact` | Generic OCI artifact (oras-style). Fully type-agnostic. | 1+ (any)      | Caller-defined (`application/vnd.<vendor>+...`) |
| `vm_image`     | Bootable VM image — kernel + initrd + rootfs.           | exactly 3     | `application/vnd.vmisolate.kernel+binary` etc.  |
| `raw_image`    | Single flashable blob (firmware, disk image).           | exactly 1     | `application/vnd.firmware.raw+binary` etc.      |

### Layer ordering rules

Validated at spec-load time:

- `vm_image` — layers MUST appear in boot order: `kernel`, `initrd`,
  `rootfs`. The first layer's media type must match `*kernel*`, the
  second `*initrd*`, the third `*rootfs*`. Reordering = build error.
- `oci_artifact` — caller-defined order, preserved as written.
- `raw_image` — exactly one layer. Two or more = build error.

Each kind has a recommended `[config]` schema (see worked examples).
Unknown keys in `[config]` are passed through to the OCI config blob
verbatim — the kind's role is *validation*, not *transformation*.

## Layers

Two source modes, mutually exclusive per layer:

### `source = "..."` — pre-built blob

```toml
[[layers]]
source     = "build/rootfs.ext4"
media_type = "application/vnd.vmisolate.rootfs.ext4+gzip"
compression = "gzip"
```

The file at `source` is read, optionally compressed, then content-hashed.

### `[[layers.files]]` — assemble from files

```toml
[[layers]]
media_type  = "application/vnd.config.tar+gzip"
compression = "gzip"
[[layers.files]]
source = "config/app.toml"
dest   = "/etc/app.toml"
mode   = 0o644
[[layers.files]]
source = "config/keys/"     # directories descend recursively
dest   = "/etc/keys/"
mode   = 0o600
```

justoci builds a deterministic tar (sorted entries, `mtime = 0`,
fixed uid/gid `0:0`), compresses if requested, then hashes. **Same
input files → same digest, every time.**

### Compression defaults

- If `media_type` ends in `+gzip` and `compression` is unset → `gzip`.
- If `media_type` ends in `+zstd` and `compression` is unset → `zstd`.
- Otherwise (default for unknown media types) → `none`.

The product position: never compress something the caller didn't ask
for. Predictability beats bandwidth.

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
  Sigstore's Fulcio + Rekor. Strict ordering: sign succeeds → Rekor
  log entry confirmed → artifact considered signed. If Rekor fails,
  the artifact is unsigned (no half-states).

### SLSA level claims

L2 is the realistic default. To claim L3+, justoci must be invoked from
a hosted build platform that meets SLSA's isolation requirements
(GitHub Actions reusable workflow, Tekton chains, etc.). The spec
declares the *intended* level; the build environment determines
whether the claim is *valid*. Mismatched claims surface as a hard
validation error from `ocimage verify`.

All three artefacts live as **OCI 1.1 referrers** of the main artifact —
pull the artifact, you can list and verify its attestations from the
same registry without a separate signing service.

## Production guarantees

Locked in for v0:

### 1. Spec versioning

`spec_version = "0"` is required at the top of every spec. Future
versions (v1+) may change shape; old specs still build under v0
semantics. Parsers reject unknown versions rather than silently
misinterpreting them.

### 2. Reproducible builds

Same spec + same source files → same artifact digest. Bit-for-bit.

- Layer digests are sha256 of (compressed) blob content. No metadata.
- Tar layers (`[[layers.files]]`) use sorted entries, `mtime = 0`,
  `uid:gid = 0:0`, `mode` from spec.
- The OCI manifest's `created` annotation is intentionally absent
  from the manifest (placed in the SLSA statement instead, where it
  belongs).
- The SLSA statement records a `build_started` timestamp, but the
  spec hash that pins the build is computed *before* timestamps are
  introduced — the spec hash is reproducible across re-runs.

### 3. Spec canonicalisation

Spec identity is `sha256(jcs(toml_to_json(spec)))`:

1. Parse TOML to a JSON-compatible value tree.
2. Apply RFC 8785 JSON Canonicalization Scheme (JCS).
3. SHA-256 the canonical bytes.

JCS is IETF-standard, language-agnostic, and has implementations in
Rust, Go, Python, JS — so re-implementations of justoci in other
languages compute the same spec hash for the same input.

### 4. Validation at spec load

Spec parsing is the first error boundary. By the time a `Spec` value
exists in memory, every one of the following has been checked:

- All required fields present (`spec_version`, `id`, `kind`, `[[layers]]`
  with the kind-correct count).
- `id` matches `^[a-z0-9][a-z0-9._-]*:[a-zA-Z0-9._-]+$`.
- Each layer's `source` file exists and is readable, OR its
  `[[layers.files]]` block is non-empty and every source path resolves.
- Each `media_type` matches the OCI media-type grammar
  (`type "/" subtype ["+" suffix]`).
- Annotation keys reserved by OCI (`org.opencontainers.image.*`) carry
  values that match the OCI spec's expectations for that key (e.g.
  `created` is RFC3339, `version` is non-empty).
- Cosign identity format is parseable (regex for keyless, file-path
  exists for key mode).
- SLSA level is in `{0, 1, 2, 3, 4}`.

Spec errors fail at *load* time with a single typed error containing
the offending field's TOML span — not at build time, halfway through
processing.

### 5. Typed error model

```text
JustociError
├── SpecError       — load + validation failures
├── BuildError      — compression, hashing, manifest assembly
├── AttestError     — SLSA emit, SBOM generation, signing
└── PublishError    — network, auth, registry rejection
```

Each variant carries enough context for an operator to act:
file path + line/col span for spec errors; HTTP status + response body
for publish errors; underlying tool stderr for build/attest errors.

### 6. Partial-failure semantics

- **Build is atomic per artifact.** A successful build produces a
  complete, self-consistent output directory. A failed build leaves
  the output directory in a `*.partial` state and exits non-zero —
  consumer tools must not pick up partial outputs.
- **Publish is per-blob with retries.** Resumable on transient
  failures via the registry's content-addressed semantics: re-pushing
  an existing blob is a no-op.
- **Sign + Rekor are coupled.** Sign succeeds → Rekor record
  confirmed → artifact considered signed. If Rekor fails after sign,
  the artifact is unsigned and the CLI exits non-zero.

### 7. CLI exit codes

```
0    success
1    SpecError       — fix the spec, retry
2    BuildError      — fix the inputs, retry
3    AttestError     — re-run with --no-attest if signing infra is
                       unavailable; otherwise fix and retry
4    PublishError    — transient or auth; safe to retry
5    VerifyError     — verify pillar failed or policy violation;
                       not transient — fix the artifact / policy
64+  catastrophic / unexpected (CLI-local: argument parsing,
                       sink URI typos, IO errors writing -o files)
```

CI pipelines route on the exit code without parsing stderr.

### 8. OCI compliance pin

- OCI Image Spec v1.1.
- OCI Distribution Spec v1.1 (referrers API required).
- Manifest `schemaVersion = 2`, `mediaType = application/vnd.oci.image.manifest.v1+json`.

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
ocimage verify  <ref> [--auth ...]          # verify SLSA + SBOM + signature
ocimage sbom    <spec-or-ref> [-o <file>]   # emit/extract SBOM only
ocimage inspect <spec-or-ref>               # canonical form + spec hash
```

Build and publish are decoupled so CI can sign artifacts in a
hardened environment separate from the build host.

### `ocimage verify <ref>` — local path or registry reference

`<ref>` is detected path-first:

- **Local OCI Image Layout dir.** If the ref names an existing path
  on disk, verify runs against that layout directly (the v0
  baseline behaviour).
- **Registry reference.** If the ref does NOT exist on disk, it's
  parsed as `host[:port]/repository:tag` (or
  `host/repository@sha256:<hex>`). The artifact + every attestation
  referrer is pulled from the registry into a tempdir; the
  verifier then runs against that tempdir verbatim. Every blob is
  hashed during streaming and rejected on digest mismatch — a
  tampered registry can never feed verify a swapped layer.

Auth flags mirror `ocimage publish`:

```
ocimage verify ghcr.io/acme/app:v1
ocimage verify ghcr.io/acme/app:v1 --auth bearer --registry-token $GH_PAT
ocimage verify ghcr.io/acme/app:v1 --auth vault [--vault-base-path PATH]
ocimage verify ghcr.io/acme/app:v1 --auth docker-config [--docker-config-path PATH]
ocimage verify localhost:5000/acme/app:0.1.0 --no-auth
ocimage verify registry.io/acme/app@sha256:<hex> --policy policy.toml
ocimage verify ghcr.io/acme/app:v1 --require-referrers
```

`--auth env` (default) reads `REGISTRY_TOKEN`, then
`REGISTRY_USERNAME` + `REGISTRY_PASSWORD`. `--no-auth` is the
explicit-anonymous shorthand. `--auth vault` is gated behind the
`vault` Cargo feature and pulls credentials from a HashiCorp Vault
KV v2 path keyed on the registry host (default base path
`secret/data/registry`). `--auth docker-config` is gated behind
the `docker-config` Cargo feature and reads the static
`~/.docker/config.json` an operator already wrote when they ran
`docker login` (override path with `--docker-config-path PATH`); it
does **not** depend on Docker the daemon being installed. See
[`docs/6-deployment/auth_providers.md`](../6-deployment/auth_providers.md)
for the per-provider config + secret schema.

The 401-then-`WWW-Authenticate` bearer-token dance (OCI Distribution
§3.4) is handled transparently — public repos on Docker Hub / GHCR
work without operator-supplied credentials.

The same flag set applies to `ocimage publish --to registry:<host>/<repo>:<tag>`.

#### `--require-referrers` (strict OCI 1.1 mode)

The OCI Distribution v1.1 referrers endpoint
(`/v2/<repo>/referrers/<digest>`) is the wire-level mechanism that
makes attestations discoverable. A registry that implements it
returns 200 with an empty `manifests` array when the artifact has
no attestations; a registry that does not implement it returns 404
on the endpoint URL.

Default behaviour: a 404 on `/referrers/` is silently treated as
"no referrers". This keeps `ocimage verify` working against
pre-OCI-1.1 registries (legacy mirrors, older Harbor versions,
third-party proxies that haven't been upgraded). The verdict
table reports the SLSA / SBOM / signature pillars as `missing`,
and exit code is governed by the `--policy` gate (or 0 if no
policy was supplied).

Strict mode (`--require-referrers`): a 404 on `/referrers/`
escalates to a typed `RegistryPullError::ReferrersNotSupported`
and the CLI exits 5. This is for consumers who refuse to deploy
artifacts pulled from a registry that fundamentally cannot host
attestations — operating an SBOM/SLSA-mandatory deploy pipeline
from a non-OCI-1.1 registry would be a silent compliance gap
otherwise.

The flag is a no-op on local OCI Image Layout paths: there's no
`/referrers/` endpoint to 404 on, because referrers are read from
`index.json` directly. The flag is documented as a no-op for
local paths in the CLI help so an operator who mixes local and
remote refs in one CI script isn't surprised.

Out of scope for v0.2 of registry-pull verify (tracked for later):

- HTTP range requests for resumable layer downloads (per-blob retry
  is implemented; partial-blob resume is a follow-up).
- Multi-platform manifest indexes.
- Parallel layer downloads.

## Out of scope for v0

- **Multi-platform / fat manifests.** A spec describes one artifact for
  one platform. Multi-platform images come in v1.
- **Build-time scripts.** Layers are pre-existing files or
  spec-described file sets; justoci does not run a builder. (vmisolate
  runs its own image build *before* invoking justoci.)
- **Mutable tags / image promotion.** Build outputs are content-
  addressed; tag management is the registry's job.
- **In-toto attestation chains.** v0 emits a single SLSA statement;
  multi-step attestation chains land later.
