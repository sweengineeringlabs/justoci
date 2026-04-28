//! Production-Guarantees-§6: failed builds leave no half-written
//! `output_dir`.
//!
//! Two cases under test:
//!
//! 1. Build fails because a layer source disappeared between spec
//!    validation and layer assembly. The pipeline must surface a
//!    typed error AND the final `output_dir` must NOT exist.
//!    `<output_dir>.partial` MAY exist (and is expected to, for
//!    diagnosis) — but consumer tools polling for `output_dir`
//!    must never see a half-built state.
//!
//! 2. Re-running into an existing `output_dir` is rejected. The
//!    contract is "successful build implies clean output_dir";
//!    silently overwriting would invalidate that contract.
//!
//! Bug these tests catch: a refactor that writes `index.json` /
//! `oci-layout` directly into `output_dir` instead of `.partial` —
//! consumer pulling the artifact mid-build would see an `index.json`
//! whose manifest descriptor isn't yet on disk.

mod common;

use std::fs;

use oci_build::{build, BuildError};

#[test]
fn test_failed_build_does_not_create_final_output_dir() {
    let work = tempfile::TempDir::new().unwrap();
    let fx = common::stage_vm_image_fixture(work.path());
    let toml_text = common::vm_image_toml(&fx);
    let spec = common::parse_spec(&toml_text, work.path());

    // Pull the rug out from under the second layer's source. The
    // spec validator already checked the file exists, but the build
    // layer reads the bytes again at assembly time.
    fs::remove_file(&fx.initrd).unwrap();

    let output = work.path().join("out-fail");
    let err = build(&spec, &output).expect_err("build must fail when layer source vanishes");

    // Typed error must point at the failing layer.
    match &err {
        BuildError::Io { path, .. } => {
            assert!(
                path.to_string_lossy().contains("initrd"),
                "error path must name the missing layer source: {path:?}"
            );
        }
        other => panic!("expected BuildError::Io, got {other:?}"),
    }

    // §6 atomicity: the final dir must NOT exist.
    assert!(
        !output.exists(),
        "failed build must NOT create output_dir; got {output:?}"
    );

    // The partial dir, on the other hand, IS expected — operators
    // diagnose the failure by inspecting it.
    let partial = work.path().join("out-fail.partial");
    assert!(
        partial.exists(),
        "failed build must leave .partial dir for diagnosis"
    );
}

#[test]
fn test_existing_output_dir_is_rejected_with_typed_error() {
    // Bug this catches: a `build()` impl that silently wipes or
    // merges into an existing output_dir — operator can't tell a
    // fresh build from a clobbered one.
    let work = tempfile::TempDir::new().unwrap();
    let fx = common::stage_vm_image_fixture(work.path());
    let toml_text = common::vm_image_toml(&fx);
    let spec = common::parse_spec(&toml_text, work.path());

    let output = work.path().join("preexisting");
    fs::create_dir_all(&output).unwrap();
    fs::write(output.join("decoy"), b"i was here first").unwrap();

    let err = build(&spec, &output).expect_err("build must refuse existing output_dir");
    match err {
        BuildError::Io { path, .. } => {
            assert_eq!(path, output, "error must name the offending output_dir");
        }
        other => panic!("expected BuildError::Io for existing dir, got {other:?}"),
    }

    // The decoy file is untouched.
    let decoy = fs::read(output.join("decoy")).unwrap();
    assert_eq!(decoy, b"i was here first", "decoy must not be clobbered");
}

#[test]
fn test_stale_partial_dir_is_replaced_on_rebuild() {
    // Bug this catches: a refactor that fails to clean up a stale
    // `.partial` from an earlier failed run, then writes new blobs
    // alongside old ones — the next build's CAS holds blobs that
    // aren't referenced by the new manifest. (CAS gc would catch
    // this, but the build itself shouldn't depend on gc to clean up
    // its own mess.)
    let work = tempfile::TempDir::new().unwrap();
    let fx = common::stage_vm_image_fixture(work.path());
    let toml_text = common::vm_image_toml(&fx);
    let spec = common::parse_spec(&toml_text, work.path());

    let output = work.path().join("out");
    let partial = work.path().join("out.partial");
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("garbage.bin"), b"left over from prior run").unwrap();

    build(&spec, &output).expect("rebuild must succeed despite stale .partial");
    assert!(output.exists());
    // The stale garbage is gone — the build wiped .partial before
    // writing fresh blobs.
    assert!(!output.join("garbage.bin").exists());
}
