//! Deterministic tar — black-box equivalent of the unit tests in
//! `core::tar_builder`, but exercised via the public `build` entry
//! point so a regression in plumbing (e.g. `assemble_layer` not
//! threading the spec_dir into the tar builder) surfaces here.
//!
//! Bug this catches: the tar bytes for a `[[layers.files]]` layer
//! drift across re-runs OR depend on the order entries appear in
//! the spec. Either kills reproducibility for any artifact whose
//! layers are file collections (config bundles, key sets).

mod common;

use std::fs;
use std::path::Path;

use oci_build::build;

fn write_payload_files(dir: &Path) {
    fs::write(dir.join("a.toml"), b"[a]\nname = \"a\"\n").unwrap();
    fs::write(dir.join("b.toml"), b"[b]\nname = \"b\"\n").unwrap();
    fs::write(dir.join("c.toml"), b"[c]\nname = \"c\"\n").unwrap();
}

fn files_layer_toml_in_order(dir: &Path) -> String {
    format!(
        r#"
spec_version = "0"
id = "config-bundle:1"
kind = "oci_artifact"

[[layers]]
media_type = "application/vnd.example.config.tar"
[[layers.files]]
source = "{a}"
dest = "/etc/a.toml"
mode = 0o644
[[layers.files]]
source = "{b}"
dest = "/etc/b.toml"
mode = 0o644
[[layers.files]]
source = "{c}"
dest = "/etc/c.toml"
mode = 0o644
"#,
        a = common::posix(&dir.join("a.toml")),
        b = common::posix(&dir.join("b.toml")),
        c = common::posix(&dir.join("c.toml")),
    )
}

fn files_layer_toml_permuted(dir: &Path) -> String {
    // c, a, b — a different declaration order for the SAME files.
    format!(
        r#"
spec_version = "0"
id = "config-bundle:1"
kind = "oci_artifact"

[[layers]]
media_type = "application/vnd.example.config.tar"
[[layers.files]]
source = "{c}"
dest = "/etc/c.toml"
mode = 0o644
[[layers.files]]
source = "{a}"
dest = "/etc/a.toml"
mode = 0o644
[[layers.files]]
source = "{b}"
dest = "/etc/b.toml"
mode = 0o644
"#,
        a = common::posix(&dir.join("a.toml")),
        b = common::posix(&dir.join("b.toml")),
        c = common::posix(&dir.join("c.toml")),
    )
}

#[test]
fn test_tar_layer_digest_is_stable_across_two_builds() {
    let work = tempfile::TempDir::new().unwrap();
    write_payload_files(work.path());
    let toml_text = files_layer_toml_in_order(work.path());

    let spec_a = common::parse_spec(&toml_text, work.path());
    let spec_b = common::parse_spec(&toml_text, work.path());

    let res_a = build(&spec_a, &work.path().join("a")).unwrap();
    let res_b = build(&spec_b, &work.path().join("b")).unwrap();

    assert_eq!(
        res_a.layer_digests[0], res_b.layer_digests[0],
        "tar layer digest must be stable across two builds"
    );
}

#[test]
fn test_tar_layer_digest_invariant_under_input_permutation() {
    // Production-Guarantees-§2 corollary: rearranging
    // `[[layers.files]]` blocks must NOT change the layer digest.
    // The tar builder sorts by destination internally — this test
    // proves that contract end-to-end.
    let work = tempfile::TempDir::new().unwrap();
    write_payload_files(work.path());

    let in_order = files_layer_toml_in_order(work.path());
    let permuted = files_layer_toml_permuted(work.path());

    let spec_a = common::parse_spec(&in_order, work.path());
    let spec_b = common::parse_spec(&permuted, work.path());

    let res_a = build(&spec_a, &work.path().join("a")).unwrap();
    let res_b = build(&spec_b, &work.path().join("b")).unwrap();

    assert_eq!(
        res_a.layer_digests[0], res_b.layer_digests[0],
        "permuting [[layers.files]] order must NOT change the tar layer digest"
    );
}
