# Operation

**Audience**: Operators, platform engineers

Runbooks, monitoring, and operational guidance for justoci in production.

## Status

`justoci` is a CLI tool, not a long-running daemon, so operational concerns are lighter than for a service. The primary operational docs live in `6-deployment/`. This directory will hold runbooks and operational guidance as deployment patterns mature.

## Contents

| Artifact | Status | Description |
|----------|--------|-------------|
| `runbook.md` | Not yet written | Incident response and common operational tasks |

## Interim References

- **Troubleshooting**: [`docs/6-deployment/troubleshooting.md`](../6-deployment/troubleshooting.md) — typed exit codes and resolution steps
- **Auth configuration**: [`docs/6-deployment/auth_providers.md`](../6-deployment/auth_providers.md) — registry credential chain
- **Verify policy**: [`docs/6-deployment/verify_policy.md`](../6-deployment/verify_policy.md) — policy.toml format and enforcement
