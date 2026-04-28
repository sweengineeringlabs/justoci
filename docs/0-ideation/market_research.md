# Market research

**Audience**: Product leads, architects, contributors

Ecosystem facts and producer niche analysis behind justoci's positioning. Two questions answered here: (1) what does the OCI distribution landscape look like, and (2) who actually needs attested non-container artifact pipelines?

---

## The non-container OCI artifact niche

### Background

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

### The Docker tool vs the OCI Distribution protocol

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

### Where the gap is

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

### Concrete categories of producer

#### Appliance / VM image vendors

Projects like Bottlerocket, Flatcar Container Linux, Talos, Fedora
CoreOS each ship VM/appliance images and roll their own publish
pipeline. Smaller appliance vendors (security gateways, edge
compute, NAS images) have nothing — many distribute via S3
without provenance.

#### Embedded firmware

Projects shipping fleet-update systems (Mender, RAUC, OSTree)
distribute firmware builds. Each rolls its own attestation. Smaller
embedded teams often ship signed-but-unprovenance'd firmware over
HTTPS.

#### Unikernels and bootable artifacts

Unikraft, MirageOS, Nanos produce minimal bootable artifacts.
Currently distributed via per-project mechanisms; OCI artifact +
attestation is a natural fit nobody serves.

#### ML model distribution

Quantised model weights (`.gguf`, `.safetensors`, etc.) shipped as
oras-style OCI artifacts is a fast-growing pattern, with weights
themselves being an emerging supply-chain concern (model
provenance + tamper detection).

#### Sysext / portable services

systemd-sysext distributes "extension" raw images. No standard
attestation pipeline.

#### Anyone past one bash script

Teams that started with "publish via S3" and grew to "publish via
OCI artifact" still need attestation, and rolling cosign + SLSA + SBOM
into their bash script for each release is the pain point.

### What "production-deployable" attestation looks like

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

### Risk and counter-arguments

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

---

## OCI Distribution v2 providers

Survey of providers `ocimage` can target, grouped by deployment
model. The OCI Distribution Spec v2 is a standard HTTP protocol;
any compliant provider works as a destination for `ocimage
publish` and a source for `ocimage verify`.

This is the universe of "places to put your artifacts." Pick one.

### Public hosted

| Provider | URL prefix | Auth | Pricing | OCI 1.1 referrers | Notes |
|---|---|---|---|---|---|
| **GitHub Container Registry (ghcr.io)** | `ghcr.io/<owner>/<repo>` | Bearer (PAT or `GITHUB_TOKEN`) | Free for public repos; private has GitHub Packages quota | ✓ | Most accessible if you already have a GitHub account. PAT needs `write:packages` (push) or `read:packages` (pull). |
| **Docker Hub** | `docker.io/<owner>/<image>` (or `<owner>/<image>`) | Basic (Docker Hub creds) or Bearer | Free public; rate-limited unauth pulls (100/6h per IP) | ✓ since 2024 | Anonymous pulls rate-limited per IP — auth even for read in CI. |
| **AWS ECR** | `<account>.dkr.ecr.<region>.amazonaws.com/<repo>` | Bearer (token from `aws ecr get-login-password`) | Per GB-month + per-request | ✓ | IAM-controlled. Token expires every 12 h — refresh in long-running pipelines. |
| **Google Artifact Registry** | `<region>-docker.pkg.dev/<project>/<repo>/<image>` | Bearer (gcloud-issued or service account JSON) | Per GB-month + egress | ✓ | Successor to GCR (which is being sunset). Service account auth via `gcloud auth print-access-token`. |
| **Azure Container Registry** | `<name>.azurecr.io/<repo>` | Bearer (Azure AD or admin user) | Per GB-month + per-request | ✓ | Premium tier needed for some features (geo-replication, content trust). |
| **Quay.io (Red Hat)** | `quay.io/<owner>/<repo>` | Bearer (Quay token) | Free public; paid private | ✓ | Strong vulnerability scanning baked into the UI. |
| **JFrog Artifactory** | `<host>.jfrog.io/<repo>/<image>` | Basic or Bearer | Commercial only | ✓ | Enterprise; multi-format (npm, Maven, OCI, etc.). |
| **GitLab Container Registry** | `<gitlab-host>/<group>/<project>` | Bearer (PAT or `CI_JOB_TOKEN`) | Free per project | ✓ | Co-located with the GitLab project — handy for self-hosted GitLab. |
| **Cloudsmith** | `docker.cloudsmith.io/<owner>/<repo>` | Basic | Per repo + bandwidth | ✓ | OCI artifacts as first-class, not just containers. |

### Self-hosted (open source)

| Project | Stability | Footprint | Notes |
|---|---|---|---|
| **`distribution/distribution`** (formerly Docker Registry) | Stable; OCI standard reference impl | Single Go binary or `registry:2` container | The canonical implementation. What the OCI spec is tested against. v3.0.0+ has native referrers API. |
| **Harbor** (CNCF graduated) | Stable; production-ready | Multiple containers (registry + portal + scanner + DB) | Adds policy, replication, vulnerability scanning, RBAC, project isolation on top of distribution. |
| **Zot** (CNCF sandbox) | Stable; gaining adoption | Single binary | OCI-native (no Docker legacy code). Built-in CVE scanning, web UI. Lightweight self-host. |
| **Trow** | Less active; solo maintainer | Single binary | Lightweight, Kubernetes-focused. Limited adoption. |
| **Sonatype Nexus** | Production-ready | JVM + heavy dep tree | Multi-format. Commercial-friendly licensing options. |

### Local-test options

| Tool | What you run | Pros | Cons |
|---|---|---|---|
| `docker run registry:2` | Container | One-line spin-up; the de facto local test target | Requires Docker daemon (license restrictions for orgs > 250 employees on Docker Desktop) |
| `podman run registry:2` | Container | Same image, no daemon, no licensing | Requires Podman install |
| `./registry serve config.yml` | Standalone binary from `distribution/distribution` releases | No container runtime; same code as `registry:2`, just unwrapped | Manual config file (small — 10 lines) |
| `zot serve config.json` | Standalone binary | OCI-native; no Docker legacy; built-in scanning | Less battle-tested than `distribution/distribution` |
| In-process (`httpmock`) | Cargo dev-dep | Test-fixture grade; no install | Cannot exercise stateful behaviour (HEAD-then-PUT idempotency, upload-session UUIDs) |

`httpmock` covers the wire shape and is what justoci's unit
tests use. Real-registry tests (`#[ignore]`-gated smoke test in
`cli/tests/registry_smoke_test.rs`) need one of the other four.

### OCI 1.1 referrers API support

The referrers API (`GET /v2/<repo>/referrers/<digest>`) is the
attestation-discovery endpoint. v0 of the OCI Distribution spec
that introduced it is from 2023; mature registries support it
now, with quirks.

| Provider | Native `/referrers/` endpoint | Fallback referrers-tag scheme |
|---|:-:|:-:|
| ghcr.io | ✓ | yes |
| Docker Hub | ✓ since 2024 | yes |
| ECR | ✓ | yes |
| Artifact Registry | ✓ | yes |
| ACR | ✓ | yes |
| Quay | ✓ | yes |
| Harbor (≥ 2.10) | ✓ | yes |
| distribution v3+ | ✓ | yes |
| `registry:2` (image) | ✓ since `distribution` v3.0.0 | yes for older v2.x tags |
| Zot | ✓ | yes |

**Fallback "referrers tag scheme":** OCI's compatibility method
when the native endpoint is absent. Attestations get pushed under
predictable tags like `<digest>.att`, and consumers list tags
matching that pattern. Slower and racier than the native API.

`ocimage verify` today uses the native API only. Issue #2
(`--require-referrers` strict mode) escalates a 404 on the native
endpoint to a hard error; the fallback path is on the v0.2
roadmap.

### Recommended provider for dogfooding

**ghcr.io.** Free, zero install, you already have a GitHub
account. Auth via PAT with `write:packages` scope — set
`REGISTRY_TOKEN` and run `ocimage publish ... --auth env`.

If air-gapped or offline-only is a hard requirement, use the
standalone `distribution/distribution` `registry` binary — same
code as `registry:2`, no Docker dependency, single Go binary.

### References

- [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) — the protocol.
- [OCI Image Spec](https://github.com/opencontainers/image-spec) — what the manifests look like.
- [`distribution/distribution`](https://github.com/distribution/distribution) — the reference server.
- [Harbor](https://goharbor.io/) — self-hosted, batteries-included.
- [Zot](https://zotregistry.dev/) — OCI-native self-hosted.
- [ORAS](https://oras.land/) — the tool that popularised non-container artifacts on OCI registries.
- [OCI 1.1 Referrers explainer](https://opencontainers.org/posts/blog/2024-03-13-image-and-distribution-1-1/) — design + rollout.
