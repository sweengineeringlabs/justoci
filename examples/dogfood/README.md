# Dogfood: full pipeline against `registry:2`

End-to-end smoke test that drives `ocimage` against a real OCI
Distribution v2 registry — Docker's `registry:2` image, run locally.
This closes justoci issue #6.

## What this proves

The build → publish → verify loop works end-to-end against a real
registry, on the real wire, over the real OCI Distribution v2
protocol. Specifically:

- `ocimage build --no-attest` produces a valid OCI Image Layout dir.
- `ocimage publish --no-auth` HEAD-then-PUTs every blob, sends the
  manifest last, and reports `pushed:` / `skipped:` counts honestly.
- `ocimage verify --no-auth` pulls the artifact back into a tempdir
  and walks the (empty, no-attest) pillar table without crashing.

## Why it exists

The unit tests in `cli/tests/registry_pull_test.rs` and
`publish/tests/registry_*` use `httpmock` to fake the registry's
HTTP layer. That's fast, reproducible, and good for catching wire
errors — but `httpmock` only sees what we tell it to. It can't catch
behavioural drift the real `registry:2` would: spec-compliant
quirks like `Docker-Content-Digest` header casing, `Location`
header relative-vs-absolute, blob-upload-session redirect chains,
or a 4xx that fakes 200 in a mock.

This dogfood script catches all of that — once per push, against
a registry that ships in production at every Docker Hub /
Harbor / GHCR / ECR install.

## Prereqs

- Docker available (`docker run --rm hello-world` should work).
- `cargo` on `PATH` (workspace MSRV: 1.86; see
  `docs/4-development/setup.md`).
- `python` on `PATH` for the free-port probe.
- `curl` on `PATH` for the registry liveness check.

## How to run

```bash
bash run.sh
```

The script `cd`s itself, so it's safe to invoke from anywhere.
Expected output ends with:

```
✓ dogfood passed — built, pushed, pulled-and-verified through registry:2 at port <N>
```

Exit code is 0 on success.

## What to do if it fails

1. Read `docker logs <container-name>` (the script prints the
   container name on failure). The registry logs every request
   it serves; an unexpected 4xx points straight at the failing
   layer.
2. Re-run with `RUST_LOG=debug` (or `OCIMAGE_LOG=debug`) to see
   the wire calls from the cli side.
3. Confirm `OCIMAGE_ALLOW_INSECURE=1` is honoured — the script
   exports it, but if you copied a subset of commands by hand
   you'll see "https connection refused" without it.

## Scope

This script does **not** exercise attestation. SLSA + cosign
+ Sigstore against a live registry is tracked separately as
issue #14, which adds the cosign signer + Rekor witness on top
of this same scaffold.
