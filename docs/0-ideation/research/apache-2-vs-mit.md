# Apache-2.0 vs MIT

Background research on the licensing choice. justoci was originally
MIT; integrating with the xikaftin umbrella (Apache-2.0) forced the
question. This page captures the analysis that drove the migration
in commit `b88866e` (justoci) / `82e81fc` (justcas).

## At a glance

| | MIT | Apache-2.0 |
|---|---|---|
| Length | ~170 words | ~10,000 words |
| Permission to use / modify / redistribute | yes | yes |
| Attribution required | yes | yes |
| **Explicit patent grant from contributors** | **no** (implicit via copyright) | **yes** (§3) |
| **Patent retaliation clause** | none | yes — sue a contributor over patents in the work, lose your patent grant |
| Modification disclosure | not required | required (mark changed files) |
| Trademark use | silent | explicitly excluded |
| NOTICE file mechanism | no | yes |
| GPL compatibility | GPL-2 + GPL-3 | GPL-3 only (patent terms incompatible with GPL-2) |

## Why the patent terms matter

MIT's silence on patents leaves users with only the *implicit* patent
license that follows from a copyright grant. That's enough for
small libraries where contributors are unlikely to hold patents
reading on the work, but inadequate for projects that:

- Are commercial / enterprise targets (their legal teams want
  explicit patent terms).
- Sit in patent-dense areas (cryptography, networking,
  containers, attestation — all areas where industry actors
  hold patent portfolios).
- Have many contributors (each could hold patents the user
  would want explicit licenses to).

Apache-2.0's §3 fixes both ends:

- **Patent grant**: every contributor grants a perpetual, royalty-free
  license to any of their patents that read on the contribution. No
  ambiguity.
- **Patent retaliation**: if anyone sues an Apache-2.0 contributor
  alleging patent infringement on the licensed work, that party's
  patent grant terminates. This is a defensive moat against patent
  trolls — sue us, lose your right to use us.

For attestation tooling specifically, this matters. Any project
that touches signing, transparency logs, or supply-chain claims is
in territory where patent risk is non-zero. Explicit terms reduce
the surface area for "is this safe to adopt?" conversations with
legal teams at adopting companies.

## Why MIT → Apache-2.0 is one-way

MIT permits sublicensing. That means MIT code can be relicensed to
Apache-2.0 by anyone who copies it (because Apache-2.0's terms are
strictly more demanding than MIT's, so meeting Apache-2.0 also
means meeting MIT).

The reverse is impossible. Apache-2.0 has terms (the patent grant,
the patent retaliation, the NOTICE file requirement) that MIT
doesn't preserve. A redistributor can't strip them out.

Practical consequence: **once a dependency in your tree is
Apache-2.0, your project must accept Apache-2.0 (or a compatible
upgrade like AGPL-3.0+) for any code that links it.** You can't
keep your project MIT and pull in Apache-2.0 deps without
de-facto re-licensing the combined work.

This forced justoci's hand: xikaftin/oci-image/cas and
xikaftin/image-registry/* are Apache-2.0. To depend on them,
justoci had to switch.

## What MIT does buy

Honest accounting:

- **Brevity.** 170 words is human-readable in 60 seconds. The
  10k-word Apache-2.0 isn't, even though most of those words are
  legal definitions.
- **GPL-2 compatibility.** If your project has to link or be
  linked into GPL-2-only code (notably the Linux kernel, BusyBox,
  GRUB), MIT works and Apache-2.0 doesn't. Apache-2.0 is fine
  with GPL-3.
- **No NOTICE bookkeeping.** Apache-2.0 requires a NOTICE file
  that lists attributions; MIT doesn't have a parallel mechanism.
  In practice this is a 5-minute task per release for small
  projects.

For justoci's use case — non-container artifact pipeline, no
GPL-2 dep tree, target audience is enterprise / CI / appliance
teams — none of these MIT advantages move the needle.

## Why projects in this space pick Apache-2.0

The OCI / supply-chain ecosystem is overwhelmingly Apache-2.0:

- **OCI specs themselves** — image-spec, distribution-spec,
  runtime-spec.
- **Reference implementations** — `distribution/distribution`
  (the registry), `runc`, `containerd`, `cri-tools`.
- **Sigstore** — `cosign`, `rekor`, `fulcio`, `sigstore-rs`.
- **OpenSSF tools** — `slsa-github-generator`, `scorecard`,
  `allstar`.
- **CNCF projects more broadly** — Kubernetes, Helm, etcd, gRPC,
  Envoy, Harbor, Notary, OPA. The CNCF default is Apache-2.0.
- **Rust itself** — Apache-2.0 OR MIT (dual-licensed); most Rust
  projects pick Apache-2.0 by convention.

When a new project in this space ships under MIT, integrators
notice. When it ships under Apache-2.0, nobody asks why.

## What the migration touched

For the historical record:

- justoci `b88866e` — top-level `LICENSE` file added; 5 crate
  `[package]` license fields flipped MIT → Apache-2.0
  (`spec`, `build`, `attest`, `publish`, `cli`).
- justcas `82e81fc` — top-level `LICENSE` file added; one crate
  `[package]` field flipped.
- xikaftin's existing Apache-2.0 LICENSE file was used as the
  template (copied verbatim — the standard 200-line text is
  unchanged across projects).

Both repos `cargo check --workspace` clean post-migration; no
behavioural change.

## When to revisit

A v1.0 release would be the natural moment to confirm:

- Re-survey the dep tree for any GPL-2-only deps that snuck in
  (would force a re-evaluation).
- Confirm contributors are aware of the patent grant they're
  making by submitting PRs (a CONTRIBUTING.md mention covers it).
- Decide whether to add explicit DCO sign-off requirements for
  contributions (not Apache-2.0-mandated but common pairing).

Until then, Apache-2.0 is correct for the project's posture.

## References

- [Apache License 2.0 full text](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](https://opensource.org/license/mit) — the original
  Expat License; the OSI-canonical form.
- [Apache 2.0 vs MIT vs others — choosealicense.com](https://choosealicense.com/licenses/) — the
  GitHub-blessed plain-language summary.
- [Apache Software Foundation FAQ on §3 patent retaliation](https://www.apache.org/legal/apache-license-faqs.html) —
  the canonical explanation of the patent grant and retaliation
  clause from the licensor.
- [Rust API Guidelines on dual-licensing](https://rust-lang.github.io/api-guidelines/necessities.html#crate-and-its-dependencies-have-a-permissive-license-c-permissive) —
  why most Rust crates dual-license under Apache-2.0 OR MIT.
