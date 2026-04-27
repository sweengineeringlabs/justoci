# The non-container OCI artifact niche

## Background

The OCI Image Spec was originally designed for container images.
In 2021, OCI published the **OCI Artifact** extension that allows
the same registry distribution machinery (manifest + content-
addressed blobs + tags) to ship arbitrary content with vendor-
defined media types.

`oras` was the first mainstream tool to popularise this — it lets
you push *any* file as an OCI artifact and pull it back via
content-addressed reference. Helm charts, WASM modules, ML model
weights, and increasingly VM images and firmware are now
distributed this way.

## The Docker tool vs the OCI Distribution protocol

A common confusion when entering this niche: **Docker the tool**
(the container daemon you `docker run`) is *not* the same as
**OCI Distribution v2** (the registry protocol that started in
the Docker ecosystem and was standardised by OCI in 2017).

| | Docker the tool | OCI Distribution v2 (the protocol) |
|---|---|---|
| What it is | A container runtime daemon | An HTTP-based content-addressed blob protocol |
| Required by users? | No, only for container workflows | Yes — every OCI registry speaks it |
| Speaks to registries | Yes, via the Distribution protocol | This is the protocol itself |
| Plays a role in the non-container niche? | **No.** Embedded teams, ML model shippers, firmware vendors don't run Docker on dev boxes | **Yes.** It's the universal content-addressed channel for any artifact, container or not |

ghcr.io, ECR, GCR, ACR, Harbor, Quay, the open-source
`distribution` server, and dozens of others all speak OCI
Distribution v2 — none of them require Docker the tool on the
consumer side. They're HTTPS endpoints, not Docker hosts.

**This is what makes the niche addressable.** The shipping
infrastructure is already universal. Non-container artifact
teams have a place to *put* their artifacts. The gap is that
nobody packages an opinionated **build / sign / SBOM / push /
verify** pipeline around that infrastructure for non-container
shapes.

Practical implication: justoci is a static binary that talks
HTTPS to OCI registries. It does not depend on Docker at
runtime, on dev boxes, or in production. Docker only appears in
the test harness (`registry:2` is the easiest reference
implementation to spin up in CI), never in the user's path.

## Where the gap is

OCI artifact distribution has matured. **Attested artifact
distribution has not.**

Concretely:

| Tool                | Push artifact | Sign | SLSA provenance | SBOM | All from one spec |
|---------------------|:-:|:-:|:-:|:-:|:-:|
| `oras`              | ✓ | — | — | — | — |
| `cosign sign-blob`  | — | ✓ | — | — | — |
| `slsa-github-generator` | — | — | ✓ | — | — |
| `syft` / `cdxgen`   | — | — | — | ✓ | — |
| `docker buildx`     | ✓ container | ✓ | ✓ (BuildKit attestations) | ✓ | container only |
| **`justoci`**       | ✓ | ✓ | ✓ | ✓ | ✓ |

Container builders (`docker buildx`, BuildKit, `ko`) have integrated
attestation well. **Non-container artifact builders have not.**
Today's teams shipping firmware, VM images, ML weights stitch
multiple tools together.

## Concrete categories of producer

### Appliance / VM image vendors

Projects like Bottlerocket, Flatcar Container Linux, Talos, Fedora
CoreOS each ship VM/appliance images and roll their own publish
pipeline. Smaller appliance vendors (security gateways, edge
compute, NAS images) have nothing — many distribute via S3
without provenance.

### Embedded firmware

Projects shipping fleet-update systems (Mender, RAUC, OSTree)
distribute firmware builds. Each rolls its own attestation. Smaller
embedded teams often ship signed-but-unprovenance'd firmware over
HTTPS.

### Unikernels and bootable artifacts

Unikraft, MirageOS, Nanos produce minimal bootable artifacts.
Currently distributed via per-project mechanisms; OCI artifact +
attestation is a natural fit nobody serves.

### ML model distribution

Quantised model weights (`.gguf`, `.safetensors`, etc.) shipped as
oras-style OCI artifacts is a fast-growing pattern, with weights
themselves being an emerging supply-chain concern (model
provenance + tamper detection).

### Sysext / portable services

systemd-sysext distributes "extension" raw images. No standard
attestation pipeline.

### Anyone past one bash script

Teams that started with "publish via S3" and grew to "publish via
OCI artifact" still need attestation, and rolling cosign + SLSA + SBOM
into their bash script for each release is the pain point.

## What "production-deployable" attestation looks like

In all of the above cases, "production-deployable" means:

1. **Reproducible builds.** Same source → same artifact digest, so
   the same SLSA statement covers re-builds.
2. **Pinned provenance.** The build environment (builder ID, commit
   hash, build parameters) is captured in the SLSA statement.
3. **Signed transparently.** Sigstore's Fulcio + Rekor provide
   keyless signing with a public transparency log; Rekor entry
   confirmation must couple with sign success (no half-states).
4. **SBOM with the right scope.** For weights: layer-scope only
   (the bytes are opaque). For firmware: source-scope (capture the
   build inputs). For VM images: both (layer contents +
   build-time deps).
5. **Verifiable in production.** Pull the artifact, fetch its
   referrers, validate against a policy file in your deploy
   pipeline.

`justoci`'s value is shipping all of this from one spec file with
sane defaults.

## Risk and counter-arguments

- **"Just use oras + cosign + bash"** — fine for one team, breaks
  down across many. The discipline of "always attest" requires the
  pipeline to default to it, not require remembering.
- **"Container builders already do this"** — true for containers,
  not for the niche above. We're not competing with `docker
  buildx`; we're filling the non-container slot.
- **"Doesn't this need Docker to run?"** — no. Docker the tool
  plays no role at runtime; the registries the tool talks to
  speak HTTP. See the table above for the full disentanglement.
- **"Tooling sprawl is a problem"** — yes, which is why there's
  one tool here, not three.
