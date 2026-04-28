# Architecture Decision Records

**Audience**: Contributors, architects

This directory tracks Architecture Decision Records (ADRs) for justoci. Each ADR documents a significant design choice, the context that drove it, and the trade-offs accepted.

## Format

ADRs follow the `NNN-title.md` naming convention (zero-padded number, snake_case title words). Status values: `Accepted`, `Superseded by ADR-NNN`, `Deprecated`.

## Index

No ADRs recorded yet. Key decisions made during v0 are captured inline in the design documents:

| Decision | Location |
|----------|----------|
| Hand-rolled OCI types (no `oci-spec` crate) | [`architecture.md` §"Why hand-rolled OCI structs"](../architecture.md) |
| Hand-rolled OCI Distribution wire | [`architecture.md` §"Why hand-rolled OCI Distribution wire"](../architecture.md) |
| cosign + Rekor coupling (no half-states) | [`cosign_rekor.md`](../cosign_rekor.md) |
| JCS canonicalisation for spec hash | [`canonicalisation.md`](../canonicalisation.md) |
| Attestation on by default | [`../../../docs/0-ideation/value_proposition.md`](../../0-ideation/value_proposition.md) |
| Scope: non-container only, no pentest/CVE work | [`scope_and_boundaries.md`](../scope_and_boundaries.md) |
| License: Apache-2.0 over MIT | [`../../0-ideation/research/apache-2-vs-mit.md`](../../0-ideation/research/apache-2-vs-mit.md) |

When a decision warrants its own ADR (new crate, breaking change, cross-repo integration), add `NNN-decision_title.md` here and link it in this index.
