# Production guarantees — non-functional requirements

These are encoded in code, not just documentation. Each guarantee
has at least one test that names the bug it would catch if the
guarantee regressed. See [`5-testing/strategy.md`](../5-testing/strategy.md)
for the test pattern.

The full statement of each guarantee lives in
[`3-design/spec-v0.md`](../3-design/spec-v0.md) §"Production
guarantees". This page summarises and links to enforcement.

## 1. Spec versioning

`spec_version = "0"` is required at the top of every spec. Future
versions ship parsers that accept their own value plus, optionally,
older values via a compatibility shim. Parsers reject unknown
versions rather than silently misinterpreting them.

**Enforced by.** `spec/src/core/validate.rs`: the validator rejects
any value other than `"0"`. Tested in
`spec/tests/validation_test.rs::test_unsupported_spec_version_rejected`.

## 2. Reproducible builds

Same spec + same source files → bit-identical artifact digest.

**Enforced by.**
- Pinned compression levels (gzip = 6, zstd = 3) in
  `build/src/core/layer.rs`.
- Sorted-entry deterministic tar (mtime=0, uid:gid=0:0, USTAR
  format) in `build/src/core/tar_builder.rs`.
- No timestamps in the OCI manifest (per OCI 1.1 spec; the
  `created` annotation is intentionally absent — timestamps live
  in the SLSA statement only).
- Manifest serialisation via `serde_json::to_vec` with
  `BTreeMap`-backed annotations + `skip_serializing_if = "Option::is_none"`
  for absent fields.

**Tested by.** `build/tests/reproducibility_test.rs` — builds the
same spec twice into different dirs, asserts manifest digest +
manifest bytes are byte-identical. `build/tests/compression_test.rs`
asserts compression bytes are stable across re-runs.

## 3. Spec canonicalisation via JCS

Spec hash is `sha256(jcs(toml_to_json(spec)))`.

**Enforced by.** `spec/src/saf/canonicalize.rs` — projects `Spec`
to `serde_json::Value` with stable field naming, then runs
`serde_jcs::to_vec` (RFC 8785 JSON Canonicalization Scheme), then
hashes via `cas::Digest`.

**Why this matters.** JCS is IETF-standard and language-agnostic.
A future Go or Python re-implementation of justoci computes the
same hash for the same TOML input. The hash is the SLSA
statement's pin on the build inputs.

**Tested by.** `spec/tests/canonicalize_test.rs` —
deterministic-across-parses, ignores-whitespace,
ignores-key-order, differs-when-content-differs, format-is-OCI-digest,
output-is-valid-JSON.

## 4. Validation at spec load

Spec parsing is the first error boundary. By the time `parse_and_validate`
returns `Ok(LoadedSpec)`, every guarantee has been checked.

**Rules:**
- All required fields present.
- `id` matches `^[a-z0-9][a-z0-9._-]*:[a-zA-Z0-9._-]+$`.
- Each `[[layers]]` source path exists and is readable, OR its
  `[[layers.files]]` block is non-empty and every source resolves.
- Each `media_type` matches the OCI media-type grammar.
- Reserved annotation keys (`org.opencontainers.image.*`) carry
  spec-conformant values (`created` is RFC3339, `version` is
  non-empty).
- Cosign identity format is parseable.
- SLSA level is in `{0, 1, 2, 3, 4}`.

**Tested by.** `spec/tests/validation_test.rs` — 19 tests, one per
rule, each naming the bug it catches.

## 5. Typed error model

```text
SpecError | BuildError | AttestError | PublishError | RegistryPullError | VerifyError
```

Every variant carries actionable context: file paths for IO errors,
HTTP status + URL for registry errors, expected vs actual digests
for content errors. No `anyhow::Result` in the public API surface
of any crate.

**Enforced by.** `*Error` enums in each crate's `src/api/error.rs`
or equivalent. CLI maps to spec-doc-§7 exit codes in
`cli/src/error.rs`.

## 6. Partial-failure semantics

- **Build is atomic per artifact.** Output goes to `*.partial`;
  rename on success only. Failed builds never produce a
  half-complete `<output_dir>`.
- **Publish is per-blob with retries.** Resumable on transient
  failures via the registry's content-addressed semantics
  (re-pushing an existing blob is a no-op via HEAD probe).
- **Sign + Rekor are coupled.** `cosign sign` succeeds → Rekor log
  entry confirmed → only then is the artifact "signed". If Rekor
  fails, return `AttestError::SignNotRecorded`; the artifact is
  unsigned (no half-states).

**Tested by.**
- `build/tests/atomicity_test.rs` — failed build leaves no final
  dir but does leave `.partial`.
- `publish/tests/http_atomic_index_test.rs` — sabotage mid-copy →
  no `index.json` at dest.
- `attest/tests/sign_not_recorded_returns_specific_error_test.rs`
  — Rekor-failure → `SignNotRecorded` (not collapsed into
  `SignFailed`).

## 7. CLI exit codes per error class

| Code | Class | When |
|------|-------|------|
| 0 | success | |
| 1 | SpecError | Fix the spec, retry |
| 2 | BuildError | Fix the inputs, retry |
| 3 | AttestError | Re-run with `--no-attest` if signing infra unavailable |
| 4 | PublishError | Transient or auth — safe to retry |
| 5 | VerifyError | Verify pillar failed or policy violation |
| 64+ | catastrophic / unexpected | |

**Tested by.** `cli/tests/cli_exit_codes_test.rs` — every class
proven by a spawned-binary test.

## 8. OCI 1.1 compliance pin

- OCI Image Spec v1.1.
- OCI Distribution Spec v1.1 (referrers API required).
- Manifest `schemaVersion = 2`,
  `mediaType = application/vnd.oci.image.manifest.v1+json`.

**Enforced by.** `build/src/api/oci_manifest.rs` — hand-rolled
typed structs with media-type constants. Manifest type +
schemaVersion are not configurable.

## 9. Integrity on every read

Every CAS read (local or remote) re-hashes the bytes against the
expected digest before returning. A blob that disagrees with its
digest path is *corrupt*; raises a typed `Corrupt` /
`DigestMismatch` error, never silent bad bytes.

**Enforced by.**
- `justcas/cas/src/spi/fs_cas.rs` — `get` and `get_stream` re-hash.
- `cli/src/registry/pull.rs` — streaming downloads hash on the fly,
  reject digest mismatches before writing to disk.

**Tested by.**
- `justcas/cas/tests/fs_cas_int_test.rs::test_get_detects_on_disk_corruption`
- `cli/tests/registry_pull_test.rs::test_pull_rejects_digest_mismatch`
