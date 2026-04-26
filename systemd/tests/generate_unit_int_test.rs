//! End-to-end integration test for `oci_systemd::generate_unit`.
//!
//! Each test stages a fake `ocimage build` output directory in
//! `std::env::temp_dir()` (same unique-suffix pattern used elsewhere
//! in the oci/ crates) and exercises the saf-level entry. Each test
//! names the bug it is there to catch — per the "no fake work" rule:
//! if the guarded behaviour is broken, the test MUST be able to fail.

use std::fs;
use std::path::{Path, PathBuf};

use oci_systemd::{generate_unit, Error, UnitOptions};

fn fresh_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "oci-systemd-int-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn stage_build_dir(root: &Path, id: &str, description: &str) {
    fs::write(root.join("kernel"), b"KERN").unwrap();
    fs::write(root.join("initrd.cpio"), b"INITRD").unwrap();
    fs::write(root.join("rootfs.ext4"), b"ROOTFS").unwrap();
    let config = serde_json::json!({
        "schema_version": 1,
        "id": id,
        "description": description,
        "kernel_cmdline": "console=ttyS0 rdinit=/init",
        "node_tags": ["linux"],
        "init_mode": "xkinit",
        "entrypoint": [],
        "env": {},
        "labels": {},
    });
    fs::write(
        root.join("config.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
}

/// Catches: regressions that drop or rename the `[Unit]` / `[Service]`
/// sections, forget the absolute kernel/initrd/rootfs paths in
/// `ExecStart`, or lose the `[Install] WantedBy=` line — any of which
/// would produce a unit systemd refuses to load.
#[test]
fn test_generate_unit_writes_service_with_expected_keys() {
    let work = fresh_temp_dir("happy");
    let build = work.join("build");
    fs::create_dir_all(&build).unwrap();
    stage_build_dir(&build, "alpine:3.20", "Alpine smoke image");

    let out = work.join("alpine.service");
    let written = generate_unit(&build, &out, UnitOptions::default()).expect("generate_unit");
    assert!(
        written.exists(),
        "unit file must exist on disk: {:?}",
        written
    );

    let body = fs::read_to_string(&written).unwrap();
    let abs_build = fs::canonicalize(&build).unwrap();
    let abs = |name: &str| {
        // Mirror oci_systemd::display_path exactly so the assert
        // matches regardless of host: strip the Windows `\\?\`
        // verbatim prefix then normalise `\` separators to `/` for
        // the Linux-targeted unit file.
        let s = abs_build.join(name).display().to_string();
        let s = s.strip_prefix(r"\\?\").map(str::to_owned).unwrap_or(s);
        s.replace('\\', "/")
    };

    assert!(body.contains("[Unit]"), "missing [Unit]:\n{body}");
    assert!(body.contains("[Service]"), "missing [Service]:\n{body}");
    assert!(body.contains("[Install]"), "missing [Install]:\n{body}");
    assert!(
        body.contains("Description=Alpine smoke image (xkvm: alpine:3.20)"),
        "description line missing/wrong:\n{body}"
    );
    let expected_exec = format!(
        "ExecStart=/usr/bin/xkvm boot --kernel {k} --initrd {i} --kali {r} --init-mode xkinit --timeout 60",
        k = abs("kernel"),
        i = abs("initrd.cpio"),
        r = abs("rootfs.ext4"),
    );
    assert!(
        body.contains(&expected_exec),
        "ExecStart mismatch.\nexpected: {expected_exec}\ngot:\n{body}"
    );
    assert!(
        body.contains("WantedBy=multi-user.target"),
        "WantedBy missing:\n{body}"
    );
    // Default options leave `User=` out.
    assert!(!body.contains("User="), "unexpected User= line:\n{body}");
}

/// Catches: a future refactor that passes `build_dir` through
/// verbatim instead of canonicalising it — which would emit a unit
/// whose `ExecStart` breaks the moment systemd runs it from a CWD
/// other than the one the operator used at `ocimage systemd generate`
/// time.
#[test]
fn test_generate_unit_absolutises_relative_build_dir() {
    let work = fresh_temp_dir("relative");
    let build = work.join("rel-build");
    fs::create_dir_all(&build).unwrap();
    stage_build_dir(&build, "rel:1", "rel test");

    // Run from inside `work` and pass a plain relative path.
    let prev_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&work).unwrap();
    let out = work.join("rel.service");
    let res = generate_unit(Path::new("rel-build"), &out, UnitOptions::default());
    std::env::set_current_dir(&prev_cwd).unwrap();

    let written = res.expect("generate_unit should accept relative build_dir");
    let body = fs::read_to_string(&written).unwrap();

    assert!(
        !body.contains("ExecStart=/usr/bin/xkvm boot --kernel rel-build/"),
        "ExecStart still references the relative path:\n{body}"
    );
    // Must reference an absolute path to kernel (posix `/` or
    // Windows `X:\`). Check both forms so the assert is meaningful
    // on either host.
    let exec_line = body
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("ExecStart= line present");
    let is_abs = exec_line.contains(" --kernel /")
        || exec_line.contains(" --kernel \\")
        || exec_line
            .split(" --kernel ")
            .nth(1)
            .map(|rest| {
                // Windows drive letter e.g. `C:\…`
                let head: String = rest.chars().take(3).collect();
                head.len() == 3
                    && head.chars().nth(1) == Some(':')
                    && (head.chars().nth(2) == Some('\\') || head.chars().nth(2) == Some('/'))
            })
            .unwrap_or(false);
    assert!(is_abs, "--kernel path is not absolute in: {exec_line}");
}

/// Catches: a regression where the artifact-existence precheck is
/// skipped and `generate_unit` silently writes a unit pointing at a
/// non-existent `config.json` — which the operator would only
/// discover at `systemctl start`.
#[test]
fn test_generate_unit_rejects_missing_config_json() {
    let work = fresh_temp_dir("nocfg");
    let build = work.join("build");
    fs::create_dir_all(&build).unwrap();
    // kernel + initrd + rootfs but NO config.json.
    fs::write(build.join("kernel"), b"KERN").unwrap();
    fs::write(build.join("initrd.cpio"), b"INITRD").unwrap();
    fs::write(build.join("rootfs.ext4"), b"ROOTFS").unwrap();

    let out = work.join("x.service");
    let err = generate_unit(&build, &out, UnitOptions::default())
        .expect_err("must fail when config.json is absent");
    match err {
        Error::ArtifactMissing(msg) => {
            assert!(
                msg.contains("config.json"),
                "error should name config.json, got: {msg}"
            );
        }
        other => panic!("expected ArtifactMissing, got {other:?}"),
    }
    assert!(
        !out.exists(),
        "unit file must not be written on artifact error"
    );
}

/// Catches: a regression where a malformed config (missing required
/// `id`) is swallowed and the unit is rendered with an empty id —
/// which would yield `Description=… (xkvm: )` and a nonsensical
/// Documentation line.
#[test]
fn test_generate_unit_rejects_malformed_config_json() {
    let work = fresh_temp_dir("badcfg");
    let build = work.join("build");
    fs::create_dir_all(&build).unwrap();
    fs::write(build.join("kernel"), b"KERN").unwrap();
    fs::write(build.join("initrd.cpio"), b"INITRD").unwrap();
    fs::write(build.join("rootfs.ext4"), b"ROOTFS").unwrap();
    // Valid JSON, but missing the required `id` field.
    fs::write(
        build.join("config.json"),
        br#"{"schema_version": 1, "description": "no id here"}"#,
    )
    .unwrap();

    let out = work.join("bad.service");
    let err = generate_unit(&build, &out, UnitOptions::default())
        .expect_err("must fail on malformed config.json");
    match err {
        Error::ConfigParse(msg) => {
            assert!(
                msg.contains("config.json"),
                "error should name config.json, got: {msg}"
            );
        }
        other => panic!("expected ConfigParse, got {other:?}"),
    }
}

/// Catches: a regression where the `user` / `wanted_by` options are
/// accepted by the API but never threaded into the render — a silent
/// "declare and abandon" anti-pattern that would leave operators
/// unable to run units under a dedicated service user or hook them
/// into a non-default target.
#[test]
fn test_generate_unit_honours_custom_user_and_wanted_by() {
    let work = fresh_temp_dir("useropts");
    let build = work.join("build");
    fs::create_dir_all(&build).unwrap();
    stage_build_dir(&build, "custom:1", "custom opts");

    let out = work.join("custom.service");
    let opts = UnitOptions {
        user: Some("vm".into()),
        wanted_by: "graphical.target".into(),
        ..UnitOptions::default()
    };
    let written = generate_unit(&build, &out, opts).unwrap();
    let body = fs::read_to_string(&written).unwrap();

    assert!(body.contains("\nUser=vm\n"), "User= line missing:\n{body}");
    assert!(
        body.contains("WantedBy=graphical.target"),
        "WantedBy= override missing:\n{body}"
    );
    assert!(
        !body.contains("WantedBy=multi-user.target"),
        "default WantedBy leaked through:\n{body}"
    );
}

/// Catches: a regression where `output` being a directory silently
/// falls through as if it were a file path — producing either an I/O
/// error ("is a directory") or, worse, clobbering the directory.
/// Also pins the documented escape scheme (`/`→`-`, `:`→`_`) so
/// consumers of the filename (package scripts, systemd drop-ins)
/// don't break.
#[test]
fn test_generate_unit_slashes_in_id_sanitised_when_output_is_dir() {
    let work = fresh_temp_dir("iddir");
    let build = work.join("build");
    fs::create_dir_all(&build).unwrap();
    stage_build_dir(&build, "acme/alpine:3.20", "sanitised id");

    let out_dir = work.join("units");
    fs::create_dir_all(&out_dir).unwrap();

    let written = generate_unit(&build, &out_dir, UnitOptions::default()).unwrap();

    let fname = written.file_name().unwrap().to_string_lossy().to_string();
    assert_eq!(
        fname, "acme-alpine_3.20.service",
        "filename escape scheme drifted: got {fname}"
    );
    // Confirm the file really landed under the directory the caller
    // passed in — canonicalisation means we compare canonical roots.
    let canon_out_dir = fs::canonicalize(&out_dir).unwrap();
    assert!(
        written.starts_with(&canon_out_dir),
        "written path {written:?} not under {canon_out_dir:?}"
    );
}
