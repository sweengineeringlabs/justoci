# Use cases

**Audience**: Product leads, architects, integrators

Concrete actor + action + outcome descriptions for justoci. Each use case names who is doing what, under what constraints, and what a successful outcome looks like.

---

## UC-01: Firmware vendor ships a signed, attested release artifact

**Actor**: Embedded firmware team (2–10 engineers, no dedicated DevSecOps)

**Context**: The team produces a flashable `.bin` for an IoT gateway. They currently distribute via S3 with an SHA-256 checksum file. A customer's procurement team has started asking for SLSA provenance before approval.

**Flow**:
1. CI builds `firmware.bin` and places it in `build/`.
2. A `spec.toml` describes the artifact: `kind = "raw_image"`, one layer pointing at `build/firmware.bin`, vendor annotations.
3. CI runs `ocimage build spec.toml -o dist/`.
4. CI runs `ocimage publish dist/ --to registry:ghcr.io/acme/gateway-fw:2.1.0`.
5. The procurement team runs `ocimage verify ghcr.io/acme/gateway-fw:2.1.0 --policy policy.toml` against a policy that requires SLSA L2 and a known signer identity.

**Outcome**: The artifact is in the customer's registry with SLSA provenance, a CycloneDX SBOM, and a cosign signature — all attached as OCI 1.1 referrers. The customer's verify step passes without the firmware team writing any signing code.

**Constraints satisfied**: No Docker daemon required. Works on Windows CI runners. No cosign binary on PATH required.

---

## UC-02: ML model weights distributed with tamper-detection

**Actor**: ML platform team distributing quantised model weights (`.gguf` files) to downstream inference teams.

**Context**: Model weights are large (2–70 GB) and increasingly a supply-chain concern — a tampered model can produce subtly wrong outputs. The team wants consumers to be able to verify "this is the exact weights file that came out of our training run."

**Flow**:
1. Training pipeline produces `model-7b-q4.gguf`.
2. `spec.toml` with `kind = "oci_artifact"`, media type `application/vnd.org.gguf.weights`, layer pointing at the weights file.
3. `ocimage build` + `ocimage publish` runs in CI on artifact finalization.
4. Inference team pulls via `oras pull` or `crane pull` — no justoci required on the consumer side.
5. Security team periodically runs `ocimage verify` to confirm the referrers chain is intact.

**Outcome**: Any inference team can verify the weights digest against the Rekor transparency log entry without trusting the distribution channel.

**Constraints satisfied**: Consumer does not need to adopt justoci. OCI Image Layout output is compatible with any OCI-compliant registry and pull client.

---

## UC-03: VM image pipeline replaces a shell-script attestation chain

**Actor**: Platform engineering team that builds Linux microVM images for a cloud product.

**Context**: The team currently runs `oras push` + a bash wrapper calling `cosign sign-blob` + a separate `syft` SBOM generation step. The three tools drift: SBOM format changes, cosign CLI flags change between versions, and the bash glue breaks once per quarter.

**Flow**:
1. Existing image build produces `kernel`, `initrd`, `rootfs.ext4`.
2. One `spec.toml` with `kind = "vm_image"`, three layers, SLSA + SBOM defaults.
3. Replace the bash chain with two commands: `ocimage build` + `ocimage publish`.
4. Existing consumers (`ocimage verify` or cosign) need no changes — wire format is identical.

**Outcome**: Three-tool bash chain replaced by one spec file. SLSA provenance, SBOM, and cosign signature are always present — not conditional on a bash script running all three steps.

**Constraints satisfied**: Wire-compatible with existing cosign verifiers. No changes required on the consumer side.

---

## UC-04: Unikernel project adds OCI distribution to its release pipeline

**Actor**: Unikernel project maintainer (solo or small team) currently distributing via GitHub Releases as a `.tar.gz`.

**Context**: A downstream integrator wants to pull the unikernel via an OCI registry rather than a URL to get content-addressed distribution and referrer-based attestation discovery.

**Flow**:
1. Maintainer writes a `spec.toml`: `kind = "oci_artifact"`, custom media type for the unikernel format, one layer.
2. GitHub Actions workflow runs `ocimage build` + `ocimage publish` on every tag push.
3. Integrator pulls via registry reference, fetches referrers, validates signature.

**Outcome**: The project distributes via OCI with provenance from day one, using the same GitHub Actions OIDC token it already has — no key management, no new infrastructure.

**Constraints satisfied**: Keyless signing via existing GitHub Actions OIDC. Free public infrastructure (ghcr.io + sigstore.dev). Zero additional operational cost.
