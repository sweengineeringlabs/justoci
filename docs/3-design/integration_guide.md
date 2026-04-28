# Integration guide

**Audience**: Integrators, platform engineers

> **TLDR**: Three integration shapes — CLI in CI (binary + typed exit codes), Rust library (link `build`/`attest`/`publish` crates directly), and verifier gate (pull-then-verify from a registry ref) — with concrete recipes for each.

justoci is designed to be embedded three ways: as a CLI driven
from a CI workflow, as a set of Rust libraries linked into a host
application, and as a verifier gating downstream pulls. This
document walks through each shape with a concrete recipe.

The guiding rule is **wire compatibility**: justoci builds
OCI 1.1 referrer manifests that are byte-equivalent to what
cosign and sigstore-rs produce. A consumer that already
trusts cosign signatures + Rekor entries does not need a new
verifier — they need to know which media types to look for
(see [`oci_referrers.md`](./oci_referrers.md)).

## Shape 1 — as a CLI in CI

The most common integration. `ocimage` ships as a single static
binary; you call `build`, `publish`, and `verify` from your CI
workflow with the same exit-code discipline you use for any other
build tool.

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
          # Until justoci ships a release binary feed (issue #12),
          # build from source. Both repos must be checked out as
          # siblings — see docs/4-development/developer_guide.md.
          git clone https://github.com/sweengineeringlabs/justoci.git
          git clone https://github.com/sweengineeringlabs/justcas.git
          (cd justoci && cargo install --path cli)

      - uses: sigstore/cosign-installer@v3
        with:
          cosign-release: v2.4.0

      - name: ocimage build
        run: ocimage build firmware.spec.toml -o dist/

      - name: ocimage publish
        run: |
          ocimage publish dist/ \
            --to registry:${REGISTRY}/${REPO}:${{ github.ref_name }} \
            --auth bearer \
            --registry-token ${{ secrets.GITHUB_TOKEN }}

      - name: ocimage verify
        run: |
          ocimage verify ${REGISTRY}/${REPO}:${{ github.ref_name }} \
            --auth bearer \
            --registry-token ${{ secrets.GITHUB_TOKEN }} \
            --policy .ocimage/release-policy.toml
```

The CLI never prompts. Every failure is a typed exit code per
[`spec_v0.md`](./spec_v0.md) §7 (1=spec, 2=build, 3=attest,
4=publish, 5=verify, 64+=catastrophic). CI pipelines route on
exit code, not stderr parsing — see
[`6-deployment/deployment_guide.md`](../6-deployment/deployment_guide.md)
for the full routing recipe and a build-once-deploy-many
artifact-promotion pattern.

The portability story: same exit codes, same `REGISTRY_TOKEN`
env var convention, same policy file format work on GitLab CI,
CircleCI, Buildkite, Tekton, Argo Workflows. The CLI is
CI-system-agnostic.

## Shape 2 — as a library

Each justoci crate is a normal Rust library with a public SAF
(Service Application Facade) layer. Hosts that want to embed the
build pipeline — for example vmisolate's `oci-image-builder`
adapter, which projects vmisolate's TOML image-spec into a
justoci spec before invoking `oci_build::build` — depend on the
crates directly.

`Cargo.toml`:

```toml
[dependencies]
spec        = { package = "swe_justoci_spec",        path = "../justoci/spec" }
attest      = { package = "swe_justoci_attest",      path = "../justoci/attest" }
oci-build   = { package = "swe_justoci_oci_build",   path = "../justoci/build" }
oci-publish = { package = "swe_justoci_oci_publish", path = "../justoci/publish" }
cas         = { package = "swe_justcas_cas",         path = "../justcas/cas" }
```

(crates.io publication is tracked as roadmap issue #12; until
then path-deps are the supported integration.)

A worked end-to-end embed:

```rust
use spec::{parse_and_validate, spec_hash};
use oci_build::build as oci_build;
use attest::{attest, BuiltArtifact};
use oci_publish::{publish, ImageDir, PublishSink, RegistryAuth};
use cas::FsCas;

fn release(spec_path: &std::path::Path, dest: &str) -> anyhow::Result<()> {
    // 1. Parse + validate the TOML spec, producing a typed
    //    LoadedSpec. Errors are SpecError variants — fix them
    //    before retrying.
    let loaded = parse_and_validate(spec_path)?;

    // 2. Compute the canonical spec hash. JCS-stable, so a Go
    //    or Python re-implementation of justoci would compute
    //    the same hash for the same TOML input.
    let hash = spec_hash(&loaded.spec);

    // 3. Assemble the OCI Image Layout v1.1 directory. Streaming
    //    compression, sorted-entry tar, atomic rename on success.
    let out = std::path::Path::new("./dist");
    let built = oci_build(&loaded, out)?;

    // 4. Run the three attestation pillars. SLSA + CycloneDX +
    //    cosign-with-Rekor. Each lands in the FsCas alongside
    //    the manifest blobs and is later registered as an OCI 1.1
    //    referrer of the manifest.
    let cas = FsCas::open(out)?;
    let artifact = BuiltArtifact::from_build(&built, &loaded.spec, hash);
    let _outputs = attest(&artifact, &loaded.spec.attestation, &cas)?;

    // 5. Push to the registry. HEAD-then-PUT skip-if-exists per
    //    blob; manifest is the LAST PUT so consumers never see a
    //    half-published image.
    let dir  = ImageDir::open(out)?;
    let auth = RegistryAuth::Bearer(std::env::var("REGISTRY_TOKEN")?);
    let sink = PublishSink::Registry { reference: dest.to_string(), auth };
    let _outcome = publish(&dir, &sink)?;

    Ok(())
}
```

The seam-by-seam invariants:

- `spec` ↔ `oci-build`: `LoadedSpec`. Build doesn't know about
  TOML.
- `oci-build` ↔ `attest`: `BuiltArtifact`. Attest doesn't know
  about `Cargo.toml` of build.
- `oci-build` ↔ `oci-publish`: nothing. Publish only knows
  `ImageDir`s on disk.
- `attest` ↔ `oci-publish`: nothing direct. Attestation outputs
  land in the same CAS that publish reads from.

These are the same seams documented in
[`architecture.md`](./architecture.md), and they're what lets a
host application substitute its own SLSA emitter, its own SBOM
generator, or its own `CosignInvoker` without touching the
public surface of the other crates.

### Justsign integration via `--features justsign`

The default production signer is the `sigstore-rs` SDK linked in
directly. For environments where the SDK dep tree is unwelcome,
two opt-in alternatives exist:

- `--features cosign-subprocess` — invoke the `cosign` binary as
  a subprocess. Legacy fallback.
- `--features justsign` — use the
  [`justsign`](https://github.com/sweengineeringlabs/justsign)
  sibling crate's `JustsignInvoker`. Delegates to the four
  `swe_justsign_*` crates pulled in via the workspace path-deps
  declared in [`Cargo.toml`](../../Cargo.toml). The four crates
  compose into the justsign-backed signing surface that
  justsign issue #16 wires up:
  `swe_justsign_sign` (`sign_blob_keyless()` +
  `EcdsaP256Signer`), `swe_justsign_fulcio`
  (`HttpFulcioClient` + `build_csr()`), `swe_justsign_rekor`
  (`HttpRekorClient`, transparency-log submit), and
  `swe_justsign_spec` (`Bundle::encode_json()` for the
  canonicalised JSON the invoker hands back as `bundle_bytes`).
  The Rekor coupling rule from
  [`cosign_rekor.md`](./cosign_rekor.md) is enforced at the
  `sign_blob_keyless` boundary — sign-success without a Rekor
  record surfaces as `AttestError::SignNotRecorded`, never as
  silent success.

All three invokers implement the same `CosignInvoker` trait, so
swapping one for another is a feature-flag flip — no code
changes in the host application.

## Shape 3 — as a verifier gating downstream pulls

Production deploys typically run verify from a deploy pipeline
against an artifact promoted to a registry. The verifier reads a
policy file describing the gates each pillar must pass, and
exits 5 if any gate fails.

`policy.toml`:

```toml
# .ocimage/prod-verify.toml — gates a production deploy.

[slsa]
# Minimum SLSA level the artifact's referrer must declare.
# "level = 0" means SLSA presence is informational only; ≥1 makes
# it a hard gate.
level = 2

[sign]
# Cosign signature gate. `required = true` makes the absence of a
# signature referrer fail closed. `builder_id` is a glob the
# artifact's cert-claimed identity must match — pin it to your
# release workflow ref so a signed-but-from-the-wrong-CI artifact
# also fails closed.
required   = true
builder_id = "https://github.com/acme/firmware/.github/workflows/release.yml@refs/tags/v*"

[sbom]
# Required SBOM formats. CycloneDX is the project default; SPDX
# is also accepted via the spec's `[attestation.sbom]` block.
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
(SLSA `builder_id` mismatch), or wasn't signed
(`sign.required = true`), or doesn't have a CycloneDX SBOM,
verify exits 5 and the deploy fails closed. The verify pass
re-checks every blob's digest on pull (Production Guarantee §9
— integrity on every read), so a tampered registry can't
sneak past either.

For the full policy schema see
[`6-deployment/verify_policy.md`](../6-deployment/verify_policy.md);
for the operator runbook around policy authoring see
[`6-deployment/deployment_guide.md`](../6-deployment/deployment_guide.md).

## Wire compatibility

justoci's output is OCI Image Spec v1.1 + OCI Distribution Spec
v1.1. The referrer manifests it writes are the same shape cosign
and sigstore-rs write — `application/vnd.in-toto+json` for SLSA,
`application/vnd.cyclonedx+json` (or `application/spdx+json`)
for SBOM, `application/vnd.dev.cosign.simplesigning.v1+json` for
the cosign signature. A consumer that already pulls OCI 1.1
referrers and feeds them to cosign or sigstore-rs verifies
justoci's artifacts without a code change.

This is by design: justoci's opinion is on **what to attest**,
not on a new wire format. The wire format is OCI 1.1, the
signature is cosign-shape, the transparency log is Rekor, the
SBOM is CycloneDX/SPDX.

## What's intentionally out of scope

- **Container builds.** justoci is not a container builder.
  Docker / Buildah / `ko` / BuildKit own that space. See
  [`scope_and_boundaries.md`](./scope_and_boundaries.md) for
  the full out-of-scope list.
- **Runtime execution.** justoci produces and verifies
  artifacts; it doesn't execute them. vmisolate consumes the
  output via the `oci-image-builder` adapter; that's the
  reference embed shape for a runtime-side host.
- **Key management.** Cosign-keyless mode delegates to
  Sigstore's Fulcio; cosign-key mode reads a key file you
  provide. Bring-your-own KMS is a host concern.
- **Policy distribution.** The `.ocimage/policy.toml` file
  lives in *your* repository. Distributing it to deploy
  pipelines is your CI's job, not justoci's.
