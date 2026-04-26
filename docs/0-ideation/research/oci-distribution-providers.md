# OCI Distribution v2 protocol providers

Survey of providers `ocimage` can target, grouped by deployment
model. The OCI Distribution Spec v2 is a standard HTTP protocol;
any compliant provider works as a destination for `ocimage
publish` and a source for `ocimage verify`.

This is the universe of "places to put your artifacts." Pick one.

## Public hosted

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

## Self-hosted (open source)

| Project | Stability | Footprint | Notes |
|---|---|---|---|
| **`distribution/distribution`** (formerly Docker Registry) | Stable; OCI standard reference impl | Single Go binary or `registry:2` container | The canonical implementation. What the OCI spec is tested against. v3.0.0+ has native referrers API. |
| **Harbor** (CNCF graduated) | Stable; production-ready | Multiple containers (registry + portal + scanner + DB) | Adds policy, replication, vulnerability scanning, RBAC, project isolation on top of distribution. |
| **Zot** (CNCF sandbox) | Stable; gaining adoption | Single binary | OCI-native (no Docker legacy code). Built-in CVE scanning, web UI. Lightweight self-host. |
| **Trow** | Less active; solo maintainer | Single binary | Lightweight, Kubernetes-focused. Limited adoption. |
| **Sonatype Nexus** | Production-ready | JVM + heavy dep tree | Multi-format. Commercial-friendly licensing options. |

## Local-test options

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

## OCI 1.1 referrers API support

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

## Recommended provider for dogfooding

**ghcr.io.** Free, zero install, you already have a GitHub
account. Auth via PAT with `write:packages` scope — set
`REGISTRY_TOKEN` and run `ocimage publish ... --auth env`.

If air-gapped or offline-only is a hard requirement, use the
standalone `distribution/distribution` `registry` binary — same
code as `registry:2`, no Docker dependency, single Go binary.

## References

- [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) — the protocol.
- [OCI Image Spec](https://github.com/opencontainers/image-spec) — what the manifests look like.
- [`distribution/distribution`](https://github.com/distribution/distribution) — the reference server.
- [Harbor](https://goharbor.io/) — self-hosted, batteries-included.
- [Zot](https://zotregistry.dev/) — OCI-native self-hosted.
- [ORAS](https://oras.land/) — the tool that popularised non-container artifacts on OCI registries.
- [OCI 1.1 Referrers explainer](https://opencontainers.org/posts/blog/2024-03-13-image-and-distribution-1-1/) — design + rollout.
