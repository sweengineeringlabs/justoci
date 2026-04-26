# justoci documentation

Documentation for the justoci attested OCI artifact pipeline,
organised by SDLC phase.

## Quick start

```bash
# Build a spec
ocimage build spec.toml -o dist/

# Publish to a registry
ocimage publish dist/ --to registry:ghcr.io/acme/firmware:1.4.2

# Verify a registry artifact
ocimage verify ghcr.io/acme/firmware:1.4.2 --policy policy.toml
```

See [`0-ideation/value-proposition.md`](./0-ideation/value-proposition.md)
for the product framing, [`3-design/spec-v0.md`](./3-design/spec-v0.md)
for the spec format, and [`6-deployment/ci-integration.md`](./6-deployment/ci-integration.md)
for using `ocimage` in CI.

## Structure

| Phase | Contains |
|-------|----------|
| [`0-ideation/`](./0-ideation) | Product opinion, market niche, why this vs `oras + cosign + bash`. |
| [`1-requirements/`](./1-requirements) | CLI subcommands as functional reqs, production guarantees as non-functional reqs. |
| [`2-planning/`](./2-planning) | Roadmap — done, in flight, on the runway. |
| [`3-design/`](./3-design) | Spec format (frozen v0), architecture, JCS canonicalisation, cosign+Rekor coupled signing, OCI 1.1 referrer model. |
| [`4-development/`](./4-development) | Cross-repo dev setup, contributing, the bug-it-catches test rule. |
| [`5-testing/`](./5-testing) | Test strategy, coverage map. |
| [`6-deployment/`](./6-deployment) | CI integration patterns. |
| [`7-operations/`](./7-operations) | Verify-policy format, troubleshooting (exit codes), runbook. |

[`SUMMARY.md`](./SUMMARY.md) is the mdbook-style index if you want
the linear reading order.

[`executive_summary.md`](./executive_summary.md) is the one-page
"what is this and why does it exist" for stakeholders.
