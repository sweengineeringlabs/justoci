# Security Policy

**Audience**: Security researchers, downstream library consumers, CI operators, anyone reporting a vulnerability or auditing justoci.

## WHAT: Coverage and supported versions

justoci is an OCI artifact build and verification pipeline. Its `justoci verify` command is a security gate — a vulnerability that lets justoci return exit 0 for an artifact that should be rejected compromises every deploy pipeline that relies on that gate.

### Supported versions

justoci is pre-1.0. The supported version is the most recent published `0.x.y` release plus the current `main` branch. Older `0.x.*` releases are not patched separately — upgrade to the latest.

| Version | Supported |
|---|---|
| Latest `0.x.y` published release | yes |
| `main` branch | yes (rolling) |
| Older `0.x.*` releases | no — upgrade |

### What's in scope

- `justoci verify` returning exit 0 for an artifact whose SLSA provenance, SBOM, or cosign signature should be rejected under any non-trivially-wrong policy.
- `--require-referrers` being bypassable — a 404 on `/referrers/` escalating to a silent pass rather than exit 5.
- Path traversal in `[[layers.files]]` source or dest paths allowing reads from or writes to locations outside the spec's intended scope.
- Command injection via spec TOML fields that are passed verbatim to the cosign subprocess or sigstore-rs call path.
- Digest acceptance bypass — `justoci publish`, `justoci verify`, or the CAS layer accepting a blob without re-hashing it against its expected digest.
- Auth credential leakage — registry tokens, Vault secrets, or docker-config credentials appearing in logs, error messages, or artifact metadata.
- SLSA `builder_id` or SAN policy bypass in the verifier that allows a policy match to succeed when the actual claim doesn't satisfy the configured pattern.

### What's out of scope

- The Sigstore public-good infrastructure (Fulcio, Rekor) — report those upstream at <https://github.com/sigstore>.
- The `sigstore-rs` and `cosign` dependencies — report those to their respective maintainers.
- The `justcas` sibling repo — report those at <https://github.com/sweengineeringlabs/justcas>.
- Registry-level attacks (registry ACLs, registry-side tag mutation) — report those to your registry vendor.
- Attacks requiring the operator to ship a malicious `Cargo.toml` or `build.rs`.
- Local-machine attacks where the attacker already has code execution as the build operator.

## WHY: Why private disclosure matters

A bypass in `justoci verify` is silent — the pipeline reports success, the artifact deploys, and the supply-chain gap isn't visible until an incident occurs. Premature public disclosure of an unpatched bypass gives attackers a window to exploit pipelines before operators can upgrade.

We triage reports privately, issue CVEs under coordinated disclosure, and document confirmed issues in a public advisory once operators have had time to upgrade.

## HOW: Reporting and response

### Reporting a vulnerability

**Do NOT open a public issue for a security report.**

Use one of:

1. **GitHub Security Advisory** — preferred. Open a private advisory at <https://github.com/sweengineeringlabs/justoci/security/advisories/new>.
2. **Email** — `engineers@swelabs.io`. Include `[justoci security]` in the subject. PGP encryption optional; if you want a key, email first and we will respond with one.

Please include:

- A description of the issue and its impact (what the verifier accepts that it should reject, what the operator believed about the artifact's provenance).
- A minimum reproduction — a spec TOML, a policy file, a command sequence, or attacker-controlled input.
- Affected versions / commits, if known.
- Any suggested mitigation or fix.
- Whether you want public credit in the eventual advisory.

### Response SLA

| Action | Target |
|---|---|
| Acknowledge receipt | 3 business days |
| Initial triage + severity decision | 7 business days |
| Patch released for confirmed high-severity issues | 30 days from confirmation |
| Public advisory + CVE | Coordinated with reporter; default 90-day disclosure window |

Severity is assessed on the verification surface: a policy bypass that allows an unsigned artifact to pass `justoci verify --policy` is `Critical` regardless of the code change size.

### Known pre-1.0 limitations

The following are acknowledged gaps, not hidden bugs. Reports confirming these specific gaps will be triaged as expected until the tracking issue closes.

| Gap | Detail | Tracked |
|---|---|---|
| Cosign subprocess injection surface | The `CosignInvoker` subprocess path passes identity arguments derived from the spec; spec fields are validated at parse time, but novel injection vectors via Unicode or argument splitting may exist. | Review at crates.io publish |
| sigstore-rs replaces cosign subprocess | The default production signer is transitioning from subprocess to linked SDK; subprocess path remains until #13 closes. | [#13](https://github.com/sweengineeringlabs/justoci/issues/13) |

### Hall of fame

Reporters who choose public credit are acknowledged in the release notes of the advisory patch once the corresponding advisory is public.

## Summary

justoci's `justoci verify` is a security gate in production deploy pipelines; a silent bypass is more dangerous than a visible crash. Reports that allow an artifact to pass verification when it should not are treated as high or critical regardless of code change size. Disclose privately via GitHub Security Advisory or `engineers@swelabs.io`; expect acknowledgement within 3 business days.

**Key takeaways**:
1. Use the GitHub Security Advisory for private, structured disclosure — do not open a public issue.
2. Include a minimum reproduction showing what the verifier accepts that it should reject.
3. Pre-1.0 known gaps (listed above) are tracked and acknowledged — reports confirming those are expected.

---

**Related documentation**:
- [`docs/3-design/production_guarantees.md`](docs/3-design/production_guarantees.md) — the nine production guarantees, including integrity-on-read and coupled signing
- [`docs/3-design/scope_and_boundaries.md`](docs/3-design/scope_and_boundaries.md) — what justoci is and is not responsible for
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution process, including security-aware review criteria

**Last Updated**: 2026-04-28
**Version**: 0.1
**Next Review**: 2026-07-28
