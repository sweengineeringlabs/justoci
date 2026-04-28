# Glossary

**Audience**: All

Alphabetized list of terms used in justoci.

---

**artifact kind** - The type discriminator in a justoci spec (`oci_artifact`, `vm_image`, `raw_image`). Determines which builder runs and what layer shapes are valid.

**attestation** - The bundle of SLSA provenance, CycloneDX SBOM, and cosign signature attached to a built artifact as OCI 1.1 referrer manifests.

**CAS (Content-Addressed Storage)** - Storage where each blob is identified by its SHA-256 digest rather than a name. The `justcas` sibling repo provides the `Cas` trait + `FsCas` + `MemCas` implementations.

**cosign** - The Sigstore tool for signing OCI artifacts. justoci uses sigstore-rs (linked SDK) by default; a subprocess fallback is available via the `cosign-subprocess` Cargo feature for air-gapped builds.

**CycloneDX** - An SBOM standard used by justoci's `attest` crate. justoci emits CycloneDX 1.5 by default; SPDX 2.3 is available via the spec's `attestation.sbom_format` field.

**DSSE (Dead Simple Signing Envelope)** - The envelope format used for Sigstore bundles. A Sigstore bundle contains a DSSE-signed SLSA or cosign payload plus the Rekor log entry proof.

**image layout** - See OCI Image Layout.

**JCS (JSON Canonicalization Scheme)** - RFC 8785. A deterministic JSON serialisation: sorted keys, no insignificant whitespace. justoci applies JCS to the TOML→JSON projection of the spec to produce the `spec_hash` — the build pin in the SLSA provenance statement. Reproducible across Rust, Go, and Python implementations.

**keyless signing** - Sigstore's OIDC-based signing mode. The signer proves workload identity via an OIDC token (GitHub Actions, GCP, etc.); Fulcio issues a short-lived certificate; the certificate and signature are logged in Rekor. No long-lived key material to manage.

**`LoadedSpec`** - The seam between the `spec` and `build` crates. `parse_and_validate` returns a `LoadedSpec` containing the validated `Spec` and the `spec_hash`. Build and attest receive a `LoadedSpec` — they never touch the TOML directly.

**media type** - The MIME-like string in an OCI descriptor that identifies the content type of a blob (e.g. `application/vnd.devboard-x7.firmware+binary`). Operator-supplied for each layer in the spec.

**OCI (Open Container Initiative)** - The standards body that governs the OCI Image Spec, OCI Distribution Spec v2, and the OCI Artifact extension used by justoci.

**OCI Distribution v2** - The HTTP-based content-addressed blob protocol standardised by OCI (originated in the Docker Registry v2 protocol). All major registries (ghcr.io, ECR, GCR, ACR, Harbor, Quay) speak it. justoci speaks it natively; Docker the tool is not required.

**OCI Image Layout** - An on-disk directory format defined by the OCI Image Spec. `ocimage build` produces an OCI Image Layout v1.1 directory directly consumable by `oras pull`, `crane pull`, or any registry push tool.

**production guarantee** - An invariant encoded in justoci's code and covered by at least one test that names the bug it would catch. See `docs/3-design/production_guarantees.md` for the full list.

**referrer** - An OCI 1.1 construct: a manifest that references another manifest (the "subject") via the OCI referrers API. justoci attaches SLSA, SBOM, and cosign signature manifests as referrers to the primary artifact manifest.

**Rekor** - Sigstore's append-only transparency log for signatures. justoci couples cosign signing to Rekor log confirmation — a signature only counts when the Rekor entry is confirmed. See `docs/3-design/cosign_rekor.md`.

**SBOM (Software Bill of Materials)** - A machine-readable inventory of a software artifact's components. justoci emits a CycloneDX or SPDX SBOM as an OCI referrer for every build.

**SLSA (Supply-chain Levels for Software Artifacts)** - The OpenSSF framework for build provenance. justoci generates SLSA Provenance v1 statements (targeting SLSA Level 2) for every build.

**spec hash** - The SHA-256 of the JCS-canonicalised TOML→JSON projection of the spec. Used as the build pin in the SLSA provenance statement and in the OCI image config. Same spec → same hash, across Rust/Go/Python re-implementations.

**spec_version** - A required field in every justoci TOML spec. `"0"` pins the parser to v0 semantics; future breaking changes will bump to `"1"`.

**Vault** - HashiCorp Vault. Supported as an optional credential provider via the `--features vault` Cargo feature (adds +862 KiB to the binary). See `docs/6-deployment/auth_providers.md`.

---

## See Also

- [Architecture](3-design/architecture.md)
- [Spec v0](3-design/spec_v0.md)
- [Production guarantees](3-design/production_guarantees.md)
