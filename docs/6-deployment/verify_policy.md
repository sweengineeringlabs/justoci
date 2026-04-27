# Verify-policy format

The `--policy <policy.toml>` flag on `ocimage verify` gates the
artifact against operator-defined rules. Without `--policy`,
verify reports each pillar's status without enforcing.

## Schema

```toml
[slsa]
# Minimum acceptable SLSA level. Verify fails if the artifact's
# SLSA statement claims a level lower than this. Set to 0 to
# accept any (including absent SLSA).
level = 2

# Optional: exact builder_id match. Use to lock to a specific
# build platform (e.g. a specific GitHub Actions reusable
# workflow) so an attacker can't forge SLSA from a different
# workflow.
builder_id = "https://github.com/acme/firmware/.github/workflows/release.yml@refs/heads/main"

[sign]
# Whether a valid cosign signature with confirmed Rekor entry
# is required. Set to false to allow VerifiedNotRecorded as a
# soft pass (NOT recommended for production).
required = true

# Optional: signing identity gate.
#
# For cosign-keyless: a regex matching the OIDC identity that
# signed the artifact. Use to require signing by a specific
# user or service account.
identity = "^release-bot@acme\\.com$"

[sbom]
# Acceptable SBOM formats. The artifact must have at least one
# SBOM referrer in one of the listed formats. Empty list means
# no SBOM gate.
formats = ["cyclonedx"]
```

Every field is optional. An empty `policy.toml` (just `[slsa]`,
`[sign]`, `[sbom]` headers with no fields) is equivalent to no
policy at all — verify reports status without enforcing.

## How gates compose

Each gate is independent. If multiple gates fail, verify reports
the *first* failure as the exit-causing error:

```
[✓] SLSA statement found and well-formed (level 2)
[✓] Cosign signature found and Rekor recorded
[✗] Cosign identity 'random-user@example.com' does not match
    policy regex '^release-bot@acme\\.com$'

Exit 5: VerifyError::PolicyViolation { rule: "sign.identity", ... }
```

The full report is on stdout; the typed error class is the exit
code.

## Identity regex syntax

The `[sign].identity` field is a Rust `regex::Regex`. Standard
syntax:

- `^` / `$` for anchoring
- `\\.` to escape a literal dot in TOML (because TOML strings
  unescape `\\.` to `\.`)
- `[a-z]`, `+`, `*`, `?` for character classes and quantifiers
- `(foo|bar)` for alternation

Examples:

```toml
# Exact match (a single email)
identity = "^release-bot@acme\\.com$"

# Any user from one domain
identity = "^[a-z0-9._-]+@acme\\.com$"

# A specific GitHub Actions reusable workflow ref
identity = "^https://github\\.com/acme/firmware/\\.github/workflows/release\\.yml@refs/(heads|tags)/.*$"

# Allow either of two release identities
identity = "^(release-bot|release-bot-eu)@acme\\.com$"
```

## SLSA level enforcement

The level the artifact's SLSA statement claims is *not
authoritative on its own* — anyone can write `slsa.level = 4` in
their spec. The level claim is meaningful only when paired with
the `builder_id` gate, because the builder is what determines
whether the level claim is valid.

Practical rule: **always pair `[slsa].level` with
`[sign].builder_id`** in production policies.

```toml
[slsa]
level = 3                                  # claim
[sign]
required = true
builder_id = "https://github.com/.../release.yml@refs/heads/main"  # truth
```

If the builder_id matches a hosted-runner workflow that meets
SLSA L3 isolation requirements, the level=3 claim is genuine.

## Common policy patterns

### Strict production

```toml
[slsa]
level = 2
builder_id = "https://github.com/acme/.../release.yml@refs/heads/main"

[sign]
required = true
identity = "^[a-z0-9._-]+@acme\\.com$"

[sbom]
formats = ["cyclonedx"]
```

### Permissive staging

```toml
[slsa]
level = 0      # accept anything (including SLSA-absent artifacts)

[sign]
required = false   # allow VerifiedNotRecorded

[sbom]
formats = []   # don't require an SBOM
```

### "Just check it has a signature"

```toml
[sign]
required = true
```

Empty `[slsa]` and `[sbom]` sections — no gate on those pillars.

## Where policy files live

By convention, in `.ocimage/<name>.toml` at the repo root. CI
workflows reference them by relative path:

```yaml
ocimage verify ${REGISTRY}/${REPO}:${TAG} \
  --policy .ocimage/release-policy.toml
```

Different policies for different environments:

```
.ocimage/
├── release-policy.toml      # used for promoting to prod
├── staging-policy.toml      # used in CI
└── dev-policy.toml          # permissive, for dev iteration
```

## Out of scope for v0

- **Time-bound policies.** "Signature must be ≤ 30 days old."
  Belongs in v0.2 with Rekor inclusion-time validation.
- **Multi-signer policies.** "Either of these two signers."
  Today's `identity` regex is single-pattern; multi-pattern
  alternation works via regex `(a|b)` but is a wart. v0.2
  reshape to an array form.
- **Subject digest pinning.** "This specific artifact must
  match this specific digest." Today's verify validates
  signatures cover the artifact's manifest digest; pinning a
  specific digest is the registry's job (immutable tag /
  pin-by-digest pulls).
