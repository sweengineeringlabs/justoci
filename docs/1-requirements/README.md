# Requirements

**Audience**: Contributors, architects, product leads

Formal requirements artifacts for justoci. This phase captures what the system must do, independent of how it does it.

## Status

v0 requirements are expressed through the design documents (spec, CLI surface, production guarantees) rather than a separate SRS. Formal requirements artifacts will be created here when the project scope expands beyond a single maintainer team.

## Contents

| Artifact | Status | Description |
|----------|--------|-------------|
| `srs.md` | Not yet written | Software Requirements Specification |
| `traceability_matrix.md` | Not yet written | Requirements ↔ test traceability |

## Interim References

Until formal requirements documents exist, requirements are traceable through:

- **Functional requirements**: [`docs/3-design/cli_surface.md`](../3-design/cli_surface.md) — the five-subcommand surface
- **Non-functional requirements**: [`docs/3-design/production_guarantees.md`](../3-design/production_guarantees.md) — reproducibility, atomicity, typed errors
- **Scope**: [`docs/3-design/scope_and_boundaries.md`](../3-design/scope_and_boundaries.md) — what justoci does and does not do
