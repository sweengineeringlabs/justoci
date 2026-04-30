# Scope and boundaries

**Audience**: Contributors, project leads

What `justoci` is, what it's not, and why. Records the strategic
position so future contributors don't re-open the question every
time a parallel project comes up.

## The position

**`justoci` stands alone.** The name is by design — "just OCI"
declares that everything an operator needs for the OCI artifact
pipeline lives in this one tool. Users `cargo install justoci`
and ship; nothing else is required at runtime.

This means:

- No transitive dependency on parallel projects (xikaftin,
  oras-rs, etc.) for any code that runs in production.
- No "you also need to install X" prerequisite, beyond `cosign`
  for the attestation pillar (and that's slated for replacement
  via `sigstore-rs` linking — issue #13).
- The dep tree contains only what justoci's own audience needs.

## What's in scope

The **opinionated client-side pipeline** for non-container OCI
artifacts:

| Stage | Scope |
|-------|-------|
| **Spec** | TOML parser + JCS canonicalisation + validator. The opinion lives here: `kind` discriminator, `[[layers]]` schema, `[attestation]` defaults. |
| **Build** | `Spec` → OCI Image Layout v1.1. Streaming compression, deterministic tar, atomic write. |
| **Attest** | SLSA v1 provenance + CycloneDX/SPDX SBOM + cosign+Rekor coupled signing. All as OCI 1.1 referrers. |
| **Publish** | Push to HTTP sink (static dir) or OCI Distribution v2 registry. Per-blob HEAD-then-PUT idempotency, manifest-last atomicity. |
| **Verify** | Pull from local layout or registry-ref. Validate SLSA + SBOM + cosign signature; gate against optional `--policy` file. |
| **Pull** | Fetch artifact + referrers from a registry into a local OCI Image Layout, with on-the-fly digest verification. |
| **Auth** | Anonymous / Basic / Bearer / env-var resolution at the CLI boundary. Optional Vault / Docker-config providers behind feature flags. |
| **CLI** | `justoci` operator binary: `build`, `publish`, `verify`, `sbom`, `inspect`. Typed exit codes per spec doc §7. |

## What's out of scope

| | Why |
|---|---|
| **Being a registry server** | justoci's audience runs *clients* against existing registries (ghcr.io, ECR, Harbor, etc.). Standing up a registry is what `distribution/distribution` and Harbor are for. The HTTP sink in `publish` writes a static-served directory — that's a *transport target*, not a registry implementation. |
| **Container runtime** | runc, containerd, podman, and parallel projects (e.g. xikaftin/oci-runtime) own this space. justoci produces and verifies artifacts; it does not execute them. |
| **Container build (Dockerfile, BuildKit)** | docker buildx, ko, kaniko own this. justoci is for *non-container* artifacts. |
| **Image scanning (CVE / secrets)** | Trivy, Grype, Snyk, Sysdig own this. SBOM emission is in scope (so scanners can consume justoci's output); running the scan is not. |
| **Mutable tags, registry mirroring, GC of remote registries** | These are registry-side concerns, not artifact-pipeline concerns. |
| **Multi-tenancy, RBAC, audit logging** | Belongs to the registry the operator chose. justoci pushes to the registry; the registry enforces who can push. |

## Why not depend on a parallel umbrella project

We audited a parallel project (xikaftin) that has overlapping
machinery — its own cas crate, its own OCI Distribution wire,
its own auth abstraction with Vault + Docker-config support.
The audit is captured in
[`market_research.md`](../0-ideation/market_research.md)
and on private analysis of the xikaftin tree.

Depending on it would have given us:

- ✓ Vault and Docker-config credential providers.
- ✓ A more thorough `CredentialProvider` trait abstraction.
- ✓ Async client with progress callbacks.

But it would have cost us:

- ✗ A streaming-regressed `put_stream` (xikaftin's buffers the
  whole payload before hashing — defeats Production Guarantee
  §2 for multi-GB layers).
- ✗ A digest-parser that accepts uppercase hex (HashMap
  collisions).
- ✗ No native OCI 1.1 referrers handling — we'd have to keep
  ours as a thin layer on top.
- ✗ A runtime coupling to a parallel project's release cadence,
  build system, and contributor base.
- ✗ A ~10k LOC dep added to justoci's binary for features most
  users don't need.

The cost-benefit was wrong. The audit also surfaced gaps in
justoci (Vault provider, Docker-config provider, `CredentialProvider`
trait) that we now address on our own terms — port the
*ideas*, not the dep, behind feature flags so the binary stays
lean for the audience that doesn't need them.

## Why keep `justcas` as a sibling repo

`justcas` is the content-addressed-storage primitive. It's its
own repo because:

1. CAS is reusable beyond OCI (Git-style content storage,
   build caches, document deduplication).
2. Justoci's binary doesn't need to bundle the CAS source; a
   path-dep keeps the build graph honest.
3. The justcas crate is small (~500 LOC), frozen, and stable.
   No maintenance overhead.

It is *not* a dependency on a parallel umbrella project — it's
our own primitive, owned by us, that we factor out for clarity
rather than vendor inline.

## Pulling in ideas vs pulling in deps

When a parallel project has good code, the right move is **port
it**, not depend on it.

- License compatibility: justoci is Apache-2.0 (since `b88866e`).
  Compatible with most ecosystem projects.
- Attribution: portions ported from third-party projects get
  `NOTICE` entries identifying source + commit, per Apache-2.0.
- Modification freedom: once ported, we own the code.
  Improvements (e.g. justcas's streaming `put_stream`,
  uppercase-rejecting `Digest::parse`) get applied without
  upstream coordination.
- Audience fit: we tune ported code to the non-container niche
  (no Docker assumed, env-var creds first-class, OCI 1.1
  referrers always native).

The trade-off is a maintenance burden — porting means we own
fixes the upstream lands. Mitigation: keep ports small, scoped
to what justoci's audience actually needs, behind feature flags
where the dep cost would otherwise grow.

## Open boundaries (where the position may evolve)

- **`sigstore-rs`** (issue #13): justoci will link sigstore-rs
  directly, replacing the cosign subprocess. This is "depend on
  a real crate" not "depend on a parallel umbrella" — sigstore-rs
  is the sanctioned Rust SDK for the Sigstore project. Distinct
  from "depending on a parallel OCI tool."

- **crates.io publication** (issue #12): the moment we publish,
  the boundary becomes part of justoci's API contract. Worth
  re-reading this doc before the first publish to confirm it
  still describes the project we ship.

- **Future `pentest`-shaped work** (CVE / secrets scanning):
  out of scope today. If user demand materialises, the right
  answer is a *separate* sibling repo (e.g. `justpentest`) that
  consumes justoci's SBOM output, not folded into justoci itself.

## Decision log

- **2026-04-26** — Audit of xikaftin/oci-image, xikaftin/image-registry,
  xikaftin/oci-runtime. Concluded: justoci stays self-contained;
  port ideas not deps. License migrated to Apache-2.0 (commit
  `b88866e` justoci, `82e81fc` justcas) regardless — Apache-2.0
  is the ecosystem standard and the right destination
  independent of the integration question.
