# Research notes

Background research informing justoci's design decisions and
positioning. Distinct from the ideation pages above (which carry
the *opinion* / *pitch*) — these are *information* documents that
gather facts about the surrounding ecosystem.

## Contents

- [`oci-distribution-providers.md`](./oci-distribution-providers.md)
  — Survey of OCI Distribution v2 protocol providers (public
  hosted, self-hosted, local-test options) with auth shape,
  pricing, OCI 1.1 referrers API support, and notable quirks per
  provider.
- [`apache-2-vs-mit.md`](./apache-2-vs-mit.md) — License-choice
  analysis. Why justoci migrated from MIT to Apache-2.0 in
  `b88866e`, what the patent terms actually buy, why the
  ecosystem (OCI specs, Sigstore, CNCF projects) is overwhelmingly
  Apache-2.0.

## When to add a new research doc

When background information *informs* a design decision but isn't
itself opinionated, it lives here. Examples for future:

- `slsa-frameworks-comparison.md` — SLSA L1 / L2 / L3 / L4 in
  practice, what builders meet what level.
- `sbom-formats-comparison.md` — CycloneDX vs SPDX vs SWID,
  scope semantics, tool support.
- `sigstore-vs-x509.md` — keyless OIDC + transparency log vs
  traditional cert-based signing trade-offs.
- `tar-determinism-techniques.md` — sorted entries, mtime
  zeroing, USTAR vs PAX, GNU LongLink avoidance.

When the doc starts asserting an opinion ("we should pick X
because..."), promote it out of `research/` into the appropriate
SDLC phase (most often `0-ideation/` or `3-design/`).
