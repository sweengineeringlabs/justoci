# Troubleshooting

**Audience**: Operators, developers

> **TLDR**: Typed exit codes (0 = success, 1–5 = error class, 64+ = catastrophic) are the first diagnostic; this guide maps each code class to root cause and resolution steps.

CLI exit codes are typed per error class. The first place to look
for "what went wrong" is the exit code.

| Code | Class | Meaning | Recovery |
|-----:|-------|---------|----------|
| 0 | success | | |
| 1 | SpecError | Spec parse / validation failed | Fix the spec, retry |
| 2 | BuildError | Layer assembly / compression / IO | Fix inputs, retry |
| 3 | AttestError | SLSA / SBOM / cosign / Rekor | See "Attest errors" below |
| 4 | PublishError | Network / auth / registry | Retry; check auth |
| 5 | VerifyError | Verify pillar failed or policy violation | See "Verify errors" |
| 64+ | catastrophic / unexpected | | Investigate; file an issue |

Stderr carries the human-readable detail. Exit code is the
machine-readable class.

## Spec errors (exit 1)

### `MalformedId`

```
Error: artifact id 'MyApp:1.0.0' is malformed: name must start with [a-z0-9]
```

OCI registries reject uppercase in the name component. Lowercase
the name part (the tag can stay mixed-case).

### `WrongLayerCount`

```
Error: kind 'vm_image' requires exactly 3 layers, got 2
```

Each kind has a strict layer count rule (see
[`3-design/spec_v0.md`](../3-design/spec_v0.md) §"Kinds"). Either
add the missing layer or change the kind.

### `WrongLayerOrder`

```
Error: vm_image layer #0 expected media_type containing 'kernel',
       got 'application/vnd.vmisolate.rootfs.ext4+gzip'
```

vm_image layers MUST be ordered kernel → initrd → rootfs. Reorder
the `[[layers]]` blocks to match.

### `UnreadableSource`

```
Error: layer #2 source path 'downloads/rootfs.ext4' is not
       readable: No such file or directory
```

Surfaces at spec-load time, not build time, by design — Production
Guarantee §6 (atomic build). Either the file is missing or the
working directory is wrong.

### `LayerSourceConflict`

```
Error: layer #1 must declare exactly one of `source = "..."` or
       `[[layers.files]]`, got: both `source = "..."` and
       `[[layers.files]]` set
```

A layer is exactly one source mode. Pick one.

## Build errors (exit 2)

### `Io { path }`

```
Error: io error during cas operation:
       failed to write to /var/cache/justoci/blobs/sha256/...
       Permission denied (os error 13)
```

The output directory or its CAS subdir lacks write permission.
Check ownership / mode.

### Output directory already exists

```
Error: output_dir already exists; remove it before rebuilding
```

Build refuses to overwrite a complete output dir (the previous
build's atomicity is preserved). Either delete the old dir or
output to a fresh path.

### `LayerWrite` from CAS

If a layer's source file vanishes mid-build, you get a typed
`LayerWrite` error with the layer position. Build atomicity §6:
the partial output dir survives at `<output>.partial` for
diagnosis.

## Attest errors (exit 3)

### `CosignNotInstalled`

```
Error: cosign was not found on PATH; install via
       sigstore/cosign-installer or set JUSTOCI_COSIGN_BIN
```

cosign must be on PATH for signing. Install via your platform's
package manager, or set `JUSTOCI_COSIGN_BIN=/path/to/cosign`.

CI workflows use:
```yaml
- uses: sigstore/cosign-installer@v3
```

### `SignNotRecorded`

```
Error: cosign signed manifest digest sha256:abc... but no Rekor
       log index was returned. The artifact is treated as unsigned
       per the cosign+Rekor coupled rule.
       cosign output:
         <stderr lines>
```

This is the §6 coupled-signing guarantee firing. Sign succeeded
but Rekor write failed. Two recoveries:

1. **Re-run** when Rekor is back. The build output dir survives
   (build atomicity), so you don't have to rebuild — re-run
   `justoci build` to retry attest only? Not in v0; today
   `justoci build` runs build+attest as one. Re-run the whole
   command.
2. **Build with `--no-attest`** if you must ship now and
   re-attest later.

### `SignFailed`

```
Error: cosign sign exited non-zero:
       <stderr>
```

cosign itself rejected the signing operation. Common causes:
key file missing (cosign-key mode), OIDC token expired
(keyless mode), or network failure to Fulcio. See cosign stderr
for specifics.

## Publish errors (exit 4)

### `Auth`

```
Error: registry authentication failed: 401 Unauthorized
       www-authenticate: Bearer realm="..."
```

Check `REGISTRY_TOKEN` / `REGISTRY_USERNAME` / `REGISTRY_PASSWORD`
env vars or the corresponding `--auth` flags. For ghcr.io, the
token needs `write:packages` scope.

### `RegistryRefused { status, body }`

```
Error: registry refused 403 Forbidden:
       { "errors": [{ "code": "DENIED", "message": "..." }] }
```

The registry accepted auth but rejected the operation. Common
causes: insufficient permissions on the repository, repository
doesn't exist, registry quota.

### `BlobUpload` retried then failed

```
Error: blob sha256:... upload failed after 3 attempts:
       <last attempt error>
```

Transient network issues. Re-run; the per-blob HEAD short-circuit
means already-uploaded blobs aren't re-uploaded.

## Verify errors (exit 5)

### `PolicyViolation { rule }`

```
Error: policy violation:
  rule: sign.identity
  expected: regex '^release-bot@acme\\.com$'
  got: 'random-user@example.com'
```

The artifact's signing identity doesn't match the policy regex.
Either:

1. The artifact was signed by the wrong identity (legitimate
   policy enforcement firing).
2. The policy is too strict (broaden the regex).

Decision belongs to the operator — verify is doing its job.

### `RekorNotRecorded`

```
Error: cosign signature for sha256:... has no Rekor log entry;
       the artifact is unsigned per the cosign+Rekor coupled rule
```

Same coupled-signing rule as on attest. Either:

1. The artifact was published with `--no-attest` (not signed at
   all — verify pillar reports "no signature found" first; this
   error is the half-signed state).
2. The signing pipeline used `cosign sign --no-rekor` (not
   permitted by justoci, but may have been used by a prior
   non-justoci tool).

### `SignatureInvalid`

```
Error: cosign verify-blob failed: signature does not match
       manifest digest sha256:...
       cosign output:
         <stderr>
```

The signature is for a *different* digest than the artifact
itself. Strong sign of tampering — refuse to deploy and
investigate.

## Registry-pull errors (verify with registry ref)

### `MalformedRef`

```
Error: registry ref 'ghcr.io/foo' is malformed: missing tag
       (expected <host>/<repo>:<tag>)
```

Add the tag.

### `DigestMismatch`

```
Error: blob sha256:expected... bytes hash to sha256:got... —
       refusing to write to disk
```

The registry returned bytes that don't match the digest claimed
by the manifest. Either tampering or registry corruption. Refuse
to deploy and report to your registry's operator.

### `ReferrersNotSupported` (strict mode only)

```
Error: registry ghcr.io does not implement the OCI 1.1 referrers
       API for repository acme/app (404 on /v2/<repo>/referrers/<digest>);
       --require-referrers refuses to deploy from such registries
```

Surfaced ONLY when the operator passed `--require-referrers` to
`justoci verify`. The flag escalates a 404 on the OCI 1.1
referrers endpoint from a soft "no referrers found" to a hard
exit-5 failure.

Two recoveries:

1. **Drop `--require-referrers`.** The default behaviour is to
   silently tolerate the 404 — verify will continue, report the
   pillars as `missing`, and exit 0 (or whatever `--policy` says).
   Use this if the registry genuinely doesn't host attestations
   and that's acceptable for the consumer.
2. **Migrate the artifact to an OCI-1.1 registry.** Re-publish
   the artifact (and its referrers) to a registry that implements
   the referrers API: ghcr.io, GitLab Registry 16+, Docker Hub
   (modern), Harbor 2.8+, zot, distribution/distribution v3+.

The flag is a no-op for local OCI Image Layout paths — if you
hit this error, the ref must be a registry reference.

## Where to file an issue

If you hit exit code 64 (catastrophic) or any unexpected
behaviour, file at
<https://github.com/sweengineeringlabs/justoci/issues> with:

1. The full command line (redact secrets).
2. The exit code.
3. Stderr from the run.
4. Spec file (redacted) if reproducible.
5. `justoci --version`.
