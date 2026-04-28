# justoci documentation

**Audience**: All

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

See [`0-ideation/value_proposition.md`](./0-ideation/value_proposition.md)
for the product framing, [`3-design/spec_v0.md`](./3-design/spec_v0.md)
for the spec format, [`3-design/integration_guide.md`](./3-design/integration_guide.md)
for embedding the pipeline in your own systems, and
[`6-deployment/deployment_guide.md`](./6-deployment/deployment_guide.md)
for using `ocimage` in CI.

## Structure

| Phase | Contains |
|-------|----------|
| [`0-ideation/`](./0-ideation) | Product opinion ([`value_proposition.md`](./0-ideation/value_proposition.md)), use cases ([`use_case.md`](./0-ideation/use_case.md)), market research ([`market_research.md`](./0-ideation/market_research.md)), roadmap. Includes [`research/`](./0-ideation/research) for one-off analyses (license choice). |
| [`3-design/`](./3-design) | Spec format (frozen v0), architecture (with mermaid diagrams), JCS canonicalisation, cosign+Rekor coupled signing, OCI 1.1 referrer model, CLI surface, production guarantees, integration guide. |
| [`4-development/`](./4-development) | Developer guide (cross-repo dev setup + contributing + bug-it-catches test rule), adding a kind. |
| [`5-testing/`](./5-testing) | Testing strategy, coverage map. |
| [`6-deployment/`](./6-deployment) | Deployment guide (CI integration recipes), auth providers, verify-policy format, troubleshooting. |

[`SUMMARY.md`](./SUMMARY.md) is the mdbook-style index if you want
the linear reading order.

[`executive_summary.md`](./executive_summary.md) is the one-page
"what is this and why does it exist" for stakeholders.
