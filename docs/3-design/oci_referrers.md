# OCI 1.1 referrer model

**Audience**: Contributors, architects

## What

Attestations (SLSA statements, SBOMs, cosign signatures) are
attached to the primary artifact via the **OCI 1.1 Referrers API**.
Pull the artifact, and you can list and verify its attestations
from the same registry — no separate signing service, no
side-channel.

## How a referrer manifest looks

A referrer is a normal OCI manifest with a `subject` field
pointing at the manifest of the artifact it references.

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.in-toto+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:<slsa-statement-blob-digest>",
      "size": 1234
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:<primary-manifest-digest>",
    "size": 567
  }
}
```

Three things to notice:

1. `subject` is the link to the primary artifact. The registry
   indexes referrers by this field.
2. `artifactType` declares what *kind* of attestation this is
   (in-toto SLSA, CycloneDX SBOM, cosign signature, etc.).
3. `config` is the canonical OCI 1.1 "empty config" — a 2-byte
   JSON `{}` blob with a fixed sha256. Required because OCI
   manifests must have a config descriptor.

## Discovery

The registry's `GET /v2/<repo>/referrers/<manifest-digest>`
endpoint returns an OCI image index whose `manifests` array lists
referrer descriptors:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    { "digest": "sha256:<slsa-referrer>", "artifactType": "application/vnd.in-toto+json", ... },
    { "digest": "sha256:<sbom-referrer>", "artifactType": "application/vnd.cyclonedx+json", ... },
    { "digest": "sha256:<sig-referrer>", "artifactType": "application/vnd.dev.cosign.simplesigning.v1+json", ... }
  ]
}
```

`ocimage verify` walks this list, classifies each entry by
`artifactType`, and validates the corresponding pillar.

## How `ocimage build` writes them

`build` produces the primary artifact in the OCI Image Layout.
`attest` writes the SLSA statement / SBOM / signature bytes to
the same `FsCas`, returns descriptors. CLI then:

1. Constructs a referrer manifest for each (with the right
   `artifactType` + `subject` pointing at the primary manifest
   digest).
2. Writes the referrer manifest to the CAS.
3. Rewrites `index.json` (atomically via tempfile-then-rename) to
   include all referrer manifests in its `manifests` array.

The output dir's `index.json` ends up with the primary manifest
as the first entry plus every referrer:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    { "digest": "sha256:<primary>", ... },
    { "digest": "sha256:<slsa-referrer>", "artifactType": "...", ... },
    { "digest": "sha256:<sbom-referrer>", "artifactType": "...", ... },
    { "digest": "sha256:<sig-referrer>",  "artifactType": "...", ... }
  ]
}
```

## How `ocimage publish` ships them

The publish path treats every entry in `index.json` as a
manifest to push:

- HTTP sink: copy each manifest blob + its layer blobs to
  `<dest>/blobs/sha256/<hex>`. Write `index.json` LAST.
- Registry sink: PUT each referrer manifest by digest (not by
  tag). The registry indexes them automatically because of the
  `subject` field. PUT the primary manifest LAST (commit point).

## How `ocimage verify` finds them

For local refs: walk `index.json` directly.

For registry refs: pull the primary manifest by tag, then call
`GET /v2/<repo>/referrers/<primary-digest>` to enumerate
referrers, then pull each referrer manifest + its layer blobs.

## Why this model

The alternative is a side-channel attestation service
(Rekor-only, separate database, etc.). Putting attestations as
referrers means:

1. **Single distribution channel.** If you can pull the
   artifact, you can pull its attestations. No separate auth or
   network hop.
2. **Tamper-evident at the registry.** Removing an attestation
   means removing a referrer manifest, which the registry's audit
   log captures.
3. **Canonical OCI semantics.** Any registry that supports OCI
   1.1 (which is most of them now: ghcr.io, Docker Hub,
   distribution, Harbor, ACR, ECR, GCR, Quay) supports referrers
   without registry-specific code paths.

## Consumer compatibility

Pre-OCI-1.1 registries don't support `/v2/.../referrers/<digest>`.
For those, justoci's pull layer falls back to "no attestations
available" — the artifact pulls fine, verify reports the missing
referrers as a soft warning unless `--policy [sign].required =
true` is set.

The `--require-referrers` strict mode (v0.2 roadmap) would
escalate the missing-referrers case to a hard error for
consumers who refuse to deploy artifacts from registries that
don't support attestation discovery.
