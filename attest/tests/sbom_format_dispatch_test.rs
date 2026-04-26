//! Asserts the SBOM-format dispatch in `saf::attest`.
//!
//! Bug this catches: a swap of CycloneDx/Spdx branches in the match
//! statement (or a wrong format-string in the dispatch) would emit
//! a CycloneDX SBOM when the spec asked for SPDX (or vice versa).
//! Verifiers parsing the SBOM by media type would refuse the file.

mod common;

use cas::{Cas, FsCas};
use spec::{AttestationConfig, SbomConfig, SbomFormat, SbomScope, SignKind, SlsaConfig, SlsaLevel};
use tempfile::TempDir;

use attest::core::cosign::{CosignOutcome, StubCosignInvoker};
use attest::saf::attest::attest_with_invoker;
use attest::SbomMediaType;

fn run(format: SbomFormat) -> Option<SbomMediaType> {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    // Disable other pillars to isolate the SBOM dispatch.
    let cfg = AttestationConfig {
        slsa: SlsaConfig {
            level: SlsaLevel::Off,
            builder_id: None,
        },
        sbom: SbomConfig {
            format,
            scope: SbomScope::Layers,
        },
        sign: spec::SignConfig {
            kind: SignKind::Off,
            identity: None,
        },
    };

    let invoker = StubCosignInvoker::new(CosignOutcome::CosignNotInstalled);
    let outputs = attest_with_invoker(&built, &cfg, &cas, &invoker).expect("attest");
    outputs.sbom.map(|s| s.media_type)
}

#[test]
fn test_dispatch_cyclonedx_format_emits_cyclonedx_media_type() {
    assert_eq!(
        run(SbomFormat::CycloneDx),
        Some(SbomMediaType::CycloneDxJson)
    );
}

#[test]
fn test_dispatch_spdx_format_emits_spdx_media_type() {
    assert_eq!(run(SbomFormat::Spdx), Some(SbomMediaType::SpdxJson));
}

#[test]
fn test_dispatch_off_format_emits_none() {
    assert_eq!(run(SbomFormat::Off), None);
}

#[test]
fn test_spdx_document_is_well_formed_spdx_2_3() {
    // Bug this catches: an SPDX dispatch that produced a CycloneDX
    // body would have the right media type but the wrong content.
    // We assert SPDX-specific top-level fields.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let cfg = AttestationConfig {
        slsa: SlsaConfig {
            level: SlsaLevel::Off,
            builder_id: None,
        },
        sbom: SbomConfig {
            format: SbomFormat::Spdx,
            scope: SbomScope::Layers,
        },
        sign: spec::SignConfig {
            kind: SignKind::Off,
            identity: None,
        },
    };
    let invoker = StubCosignInvoker::new(CosignOutcome::CosignNotInstalled);
    let outputs = attest_with_invoker(&built, &cfg, &cas, &invoker).expect("attest");
    let sbom = outputs.sbom.expect("Spdx requested");
    let bytes = cas.get(&sbom.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(v["spdxVersion"], "SPDX-2.3");
    assert_eq!(v["dataLicense"], "CC0-1.0");
    assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
}
