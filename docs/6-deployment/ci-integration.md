# CI integration

The `ocimage` CLI is designed for CI pipelines: typed exit codes
per error class, no interactive prompts, no stderr-vs-stdout
ambiguity.

## Reference recipe — GitHub Actions

A full build → publish → verify pipeline:

```yaml
name: Release

on:
  push:
    tags: ["v*"]

env:
  REGISTRY: ghcr.io
  REPO:     acme/firmware

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents:    read
      packages:    write       # for ghcr.io push
      id-token:    write       # for cosign-keyless OIDC

    steps:
      - uses: actions/checkout@v4

      - name: Install ocimage CLI
        run: |
          # Once justoci is published to crates.io / a release feed,
          # this step becomes `cargo install ocimage` or downloading
          # a prebuilt. Until then, build from source:
          git clone https://github.com/sweengineeringlabs/justoci.git
          git clone https://github.com/sweengineeringlabs/justcas.git
          (cd justoci && cargo install --path cli)

      - uses: sigstore/cosign-installer@v3
        with:
          cosign-release: v2.4.0

      - name: Build artifact
        run: |
          ocimage build firmware.spec.toml -o dist/

      - name: Push to registry
        run: |
          ocimage publish dist/ \
            --to registry:${REGISTRY}/${REPO}:${{ github.ref_name }} \
            --auth bearer \
            --registry-token ${{ secrets.GITHUB_TOKEN }}

      - name: Verify the just-published artifact
        run: |
          ocimage verify ${REGISTRY}/${REPO}:${{ github.ref_name }} \
            --auth bearer \
            --registry-token ${{ secrets.GITHUB_TOKEN }} \
            --policy .ocimage/release-policy.toml
```

## Routing on exit code

CI pipelines route on `ocimage`'s exit code, never on stderr
parsing.

```yaml
      - name: Build with retry on transient errors
        run: |
          set +e
          ocimage build spec.toml -o dist/
          rc=$?
          set -e
          case $rc in
            0)  echo "::notice::build succeeded" ;;
            1)  echo "::error::spec error — fix spec.toml"; exit 1 ;;
            2)  echo "::error::build error — fix inputs"; exit 1 ;;
            3)  echo "::warning::attest error — re-running with --no-attest"
                ocimage build spec.toml -o dist/ --no-attest ;;
            4)  echo "::warning::publish transient — retry"
                ocimage build spec.toml -o dist/ ;;
            *)  echo "::error::unexpected ($rc)"; exit 1 ;;
          esac
```

| Exit | Class | Pipeline action |
|-----:|-------|-----------------|
| 0 | success | continue |
| 1 | SpecError | hard fail; spec needs human fix |
| 2 | BuildError | hard fail; inputs need human fix |
| 3 | AttestError | retry, or fall back to `--no-attest` if signing infra unavailable |
| 4 | PublishError | safe to retry (transient or auth) |
| 5 | VerifyError | hard fail; artifact does not meet policy |
| 64+ | catastrophic | hard fail; investigate |

## Verify-policy patterns

Production verify usually runs from a deploy pipeline against an
artifact promoted to a registry:

```toml
# .ocimage/prod-verify.toml
[slsa]
level = 2

[sign]
required = true
builder_id = "https://github.com/acme/firmware/.github/workflows/release.yml@refs/tags/v*"

[sbom]
formats = ["cyclonedx"]
```

Then in the deploy job:

```yaml
      - name: Verify before deploy
        run: |
          ocimage verify ${REGISTRY}/${REPO}:${{ inputs.tag }} \
            --auth bearer \
            --registry-token ${{ secrets.DEPLOY_TOKEN }} \
            --policy .ocimage/prod-verify.toml
```

If the artifact at the tag wasn't built by the expected workflow
(SLSA `builder_id` mismatch), or wasn't signed (`sign.required`),
or doesn't have a CycloneDX SBOM, verify exits 5 and the deploy
fails closed.

## Artifact promotion (build-once, deploy-many)

The OCI manifest digest is stable across publishes. Build in one
job, publish to staging, run integration tests, then re-tag in
prod *without rebuilding*:

```yaml
  build-and-stage:
    steps:
      - run: ocimage build spec.toml -o dist/
      - run: |
          ocimage publish dist/ \
            --to registry:staging.acme.io/firmware:${{ github.sha }}
      - id: digest
        run: |
          # Capture the manifest digest for promotion below
          DIGEST=$(ocimage inspect dist/ | grep manifest_digest | awk '{print $2}')
          echo "digest=$DIGEST" >> $GITHUB_OUTPUT

  promote:
    needs: build-and-stage
    if: ${{ needs.integration-tests.result == 'success' }}
    steps:
      - run: |
          # Pull from staging, push to prod by digest — no rebuild,
          # signatures + SLSA + SBOM all carry across.
          ocimage verify staging.acme.io/firmware:${{ github.sha }} \
            --policy .ocimage/staging-policy.toml
          # ... promote via your registry's tag/digest mechanism ...
```

## Other CI systems

The CLI is portable — same patterns work on GitLab CI, CircleCI,
Buildkite, Tekton, Argo Workflows. The exit codes, the env-var
auth (`REGISTRY_TOKEN`), and the policy file format are
CI-system-agnostic.

## Things to NOT do in CI

- **Don't commit policy.toml secrets.** Cosign identity
  regexes are fine to commit (they're public matchers). Tokens
  go in CI secret stores.
- **Don't disable `--policy` to pass a deploy.** If verify is
  failing in prod, that's a signal the artifact lineage is
  broken. Fix the source, don't bypass the gate.
- **Don't reuse `--no-attest` outside CI failure recovery.** A
  shipped-without-attestation artifact is a debt — track it,
  re-attest when infra recovers, never ship it as steady state.
