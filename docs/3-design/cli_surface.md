# CLI surface — functional requirements

**Audience**: Contributors, architects

The `justoci` operator CLI exposes five subcommands. Each is a
functional requirement validated by integration tests in
`cli/tests/`.

## `justoci build <spec.toml> [-o <dir>] [--no-attest]`

**Functional requirement.** Given a valid spec file, produce an
OCI Image Layout v1.1 directory containing the artifact + its
attestation referrers (unless `--no-attest` is set).

**Pipeline.** `parse_and_validate(spec)` → `build(loaded, output)` →
unless `--no-attest`: open `FsCas` rooted at output → construct
`BuiltArtifact` → `attest(built, attestation, cas)` → wire results
into `index.json` as OCI 1.1 referrers.

**Atomicity.** Output goes to `<output>.partial` first; on success,
atomic rename to `<output>`. Failed builds leave `.partial` for
diagnosis; the final `<output>` only exists when self-consistent.

**Stdout shape.** Manifest digest, spec hash, attestation summary
(or "skipped: --no-attest").

**Exit codes.** `0` success; `1` SpecError; `2` BuildError;
`3` AttestError.

## `justoci publish <dir> --to <sink> [--auth ...]`

**Functional requirement.** Given a built OCI Image Layout
directory and a sink, push the artifact + all referrers to that
sink.

**Sink syntax:**
- `http:/path/to/dest` — copy to a static-served directory
  (Level-2 OCI Distribution).
- `registry:<host>/<repo>:<tag>` — push to an OCI Distribution
  v2 registry (Level-4).

**Auth (registry sinks):**
- `--auth env` (default) — read `REGISTRY_TOKEN`, then
  `REGISTRY_USERNAME` + `REGISTRY_PASSWORD`.
- `--auth basic --registry-username U --registry-password P`
- `--auth bearer --registry-token T`
- `--no-auth` — explicit anonymous.

**Idempotency.** HTTP sink: skip-if-exists per blob. Registry sink:
HEAD blob → 200 short-circuits; only 404 triggers POST + PUT.
Re-publish reports every blob in `digests_skipped`, transfers 0
bytes.

**Atomicity.** HTTP sink writes `index.json` last. Registry sink
PUTs the manifest last (after layers + config + referrers
confirmed-present).

**Exit code.** `4` PublishError.

## `justoci verify <ref> [--policy <file>] [--auth ...] [--require-referrers]`

**Functional requirement.** Given an artifact reference (local
OCI layout path or `<host>/<repo>:<tag>`), validate its SLSA +
SBOM + cosign attestations exist and are well-formed; if `--policy`
supplied, gate against the policy file.

**Ref detection.**
- Existing path on disk → local layout, runs verify against it.
- Otherwise → parse as registry ref, pull into a tempdir
  (streaming downloads with on-the-fly digest verification),
  run verify against the tempdir.

**Policy file (`policy.toml`).**
```toml
[slsa]
level = 2                   # require ≥ this level

[sign]
required = true             # signature must be present + valid
builder_id = "..."          # exact match required (optional)

[sbom]
formats = ["cyclonedx", "spdx"]   # at least one must be present
```

**Validation steps:**
1. Open the (local or pulled) ImageDir.
2. Enumerate referrers from `index.json`.
3. For each cosign signature referrer: invoke cosign verify-blob;
   require Rekor entry present (no `--no-rekor` accepted).
4. For each SLSA referrer: validate JSON shape, predicateType,
   subject digest matches manifest digest.
5. For each SBOM referrer: validate JSON shape.
6. If `--policy`: gate each pillar against the policy.

**`--require-referrers` (strict OCI 1.1 mode).**

Default behaviour: a 404 from
`/v2/<repo>/referrers/<digest>` on the registry-pull path is
silently treated as "no referrers" so pre-OCI-1.1 registries don't
error out. The verdict table reports the missing pillars; final
exit is governed by `--policy` (or 0 if absent).

With `--require-referrers`: a 404 on `/referrers/` escalates to
`RegistryPullError::ReferrersNotSupported` and the CLI exits 5.
Set this when the operator refuses to deploy artifacts from a
registry that cannot host attestations.

The flag is a no-op for local OCI Image Layout paths: referrers
on a local layout come from `index.json` directly, so there is
no `/referrers/` endpoint that could 404. The CLI help text
documents the no-op explicitly.

**Exit code.** `5` VerifyError (verify pillar failed or policy
violation, or strict-mode `ReferrersNotSupported`).

## `justoci sbom <spec-or-ref> [-o <file>] [--format <cyclonedx|spdx>]`

**Functional requirement.** Emit or extract an SBOM.

**Two modes:**
- **Spec mode** — `<spec-or-ref>` is a `.toml` path. Generates a
  pre-build SBOM preview from the spec's resolved layer sources.
- **Image mode** — `<spec-or-ref>` is a built OCI Image Layout
  directory. Walks referrers, finds the SBOM, emits its bytes.

**Format flag.** Default `cyclonedx`; `spdx` for SPDX 2.3.

## `justoci inspect <spec-or-ref>`

**Functional requirement.** For debugging.

- **Spec mode** — print canonical (JCS) form of the spec + its
  hash.
- **Image mode** — print manifest digest + config digest + layer
  media types + referrer descriptors.

Useful as the canary that confirms a spec parses cleanly before
running a full build.
