# Value proposition

**Audience**: Stakeholders, product leads

## The opinion

**Attestation is on by default.**

Every artifact justoci builds gets SLSA provenance, a CycloneDX SBOM,
and a cosign signature with Rekor confirmation, unless the spec
explicitly opts out. The opt-out exists for testing; production
builds ship attested by default.

## The problem this solves

Today's appliance, firmware, VM-image, and ML-model teams stitch
attested-publish pipelines from `oras` + `cosign` + `syft` + bash.
The pieces work — but they require each team to:

1. Decide what each pillar means for their artifact (does an SBOM
   over an opaque ML weights blob even add signal?)
2. Wire SLSA provenance into their CI so the build environment
   parameters are captured.
3. Run cosign separately and reconcile its output back into a
   referrer relationship with the published artifact.
4. Keep all three pillars in sync as the artifact evolves.

In practice this means most teams ship one or two of the three
pillars, not all three, and not consistently across builds.

## Why this matters

Supply-chain compromise is a board-level concern. US Executive Order
14028 mandates SBOMs for federal software. EU CRA requires
demonstrable provenance for products sold into the EU.
[OpenSSF SLSA](https://slsa.dev) is the de facto framework but its
adoption is uneven for non-container artifacts because no
opinionated tool ships the full pipeline.

`justoci` is that tool for the non-container artifact niche.

## The pitch in one paragraph

You write one TOML file describing your artifact (kernel + initrd +
rootfs for a VM, or a `.gguf` weights file for an ML model, or a
flashable firmware blob). You run `ocimage build spec.toml -o dist/`.
The output is an OCI Image Layout directory with the artifact, an
SLSA provenance statement pinning the build, a CycloneDX SBOM,
and a cosign signature with a Rekor transparency log entry, all
attached as OCI 1.1 referrers. You run `ocimage publish dist/ --to
registry:ghcr.io/acme/...` to push to any OCI distribution registry.
Consumers run `ocimage verify ghcr.io/acme/... --policy policy.toml`
to validate everything against their own gates. One tool, one spec,
production-grade attestation.

## What justoci is not

- **Not a container builder.** Docker / Buildah / `ko` / BuildKit
  own that space and do it well. justoci targets the non-container
  artifact niche specifically.
- **Not a runtime.** It produces and verifies artifacts; it doesn't
  execute them. (Vmisolate and similar tools handle execution.)
- **Not a registry.** It pushes to any OCI Distribution v2 registry
  (ghcr.io, Docker Hub, Harbor, ACR, ECR, GCR, Quay, distribution).
- **Not a key management system.** Cosign-keyless mode delegates to
  Sigstore's Fulcio; cosign-key mode reads a key file you provide.

## Where justoci ends, your CI begins

The product surface is build, publish, attest, and verify. The
choice of *when* to build (PR vs main vs tag), *where* to publish
(staging vs prod registry), and *what policy* to enforce on verify
(allow-list of identities, required SLSA level) lives in your CI
pipelines. justoci provides the primitives; your CI composes them.

See [`6-deployment/deployment_guide.md`](../6-deployment/deployment_guide.md)
for a worked GitHub Actions recipe, and
[`3-design/integration_guide.md`](../3-design/integration_guide.md)
for embedding the pipeline as a library or CLI.
