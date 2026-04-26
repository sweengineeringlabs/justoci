//! `oci-systemd` — generate systemd unit files that boot an
//! `ocimage build` output directory via xkvm.
//!
//! Contract (Phase 2f-δ):
//!
//! * Input  — a directory laid out by [`oci_build::build_image`]:
//!   `kernel`, `initrd.cpio`, `rootfs.ext4`, `config.json`.
//! * Output — a systemd `.service` unit whose `ExecStart` is
//!   `xkvm boot --kernel … --initrd … --kali … --init-mode xkinit
//!   --timeout 60`, with all artifact paths absolutised so the unit
//!   is reproducible regardless of the operator's CWD at generate
//!   time.
//!
//! The unit deliberately does not bake in `entrypoint`/`env` from
//! `config.json` — those belong inside the image. The host-side
//! unit only says "boot this image with xkvm". Keeping the contract
//! narrow means the unit stays valid after in-place image rebuilds.
//!
//! See `docs/3-design/adr/015-image-registry.md` for the full
//! publish/boot pipeline.
//!
//! ## Intended caller
//!
//! ```no_run
//! use std::path::Path;
//! use oci_systemd::{generate_unit, UnitOptions};
//!
//! let path = generate_unit(
//!     Path::new("build/smoke/out"),
//!     Path::new("/tmp/alpine.service"),
//!     UnitOptions::default(),
//! ).unwrap();
//! println!("wrote {}", path.display());
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Errors raised by `oci-systemd`.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("build artifact missing: {0}")]
    ArtifactMissing(String),

    #[error("config.json malformed: {0}")]
    ConfigParse(String),
}

/// Per-deploy tunables for the generated unit. Options that operators
/// routinely change across hosts live here; everything else is baked
/// in so two generations of the same image yield the same unit.
#[derive(Debug, Clone)]
pub struct UnitOptions {
    /// Absolute path to the xkvm binary on the target host.
    pub xkvm_path: PathBuf,
    /// Optional `User=` line. `None` → omit, unit runs as root.
    pub user: Option<String>,
    /// `[Install] WantedBy=` target.
    pub wanted_by: String,
}

impl Default for UnitOptions {
    fn default() -> Self {
        Self {
            xkvm_path: PathBuf::from("/usr/bin/xkvm"),
            user: None,
            wanted_by: "multi-user.target".into(),
        }
    }
}

/// Subset of `config.json` we need to render a unit. Extra fields in
/// the file are ignored — callers that need them read the file
/// themselves.
#[derive(Debug, Deserialize)]
struct ConfigHeader {
    id: String,
    #[serde(default)]
    description: String,
}

/// Names of the four artifacts produced by `ocimage build` that the
/// unit references. Kept together so the missing-artifact check and
/// the `ExecStart` composer can't drift.
const KERNEL_FILE: &str = "kernel";
const INITRD_FILE: &str = "initrd.cpio";
const ROOTFS_FILE: &str = "rootfs.ext4";
const CONFIG_FILE: &str = "config.json";

/// Default boot timeout (seconds) passed to `xkvm boot --timeout`.
/// 60s matches the smoke script and gives a guest room to reach
/// `XIKA_READY` on a cold host. Operators who need a different bound
/// hand-edit the rendered unit — not exposed in `UnitOptions` because
/// it's rarely worth tuning per-deploy.
const DEFAULT_BOOT_TIMEOUT_SECS: u32 = 60;

/// Generate a systemd `.service` unit for booting the `ocimage build`
/// output at `build_dir` via xkvm, and write it to `output`.
///
/// If `output` is an existing directory, the file is written under
/// `<output>/<sanitised-image-id>.service` where `/` in the id
/// becomes `-` and `:` becomes `_` (the only two ADR-015 id
/// separators that aren't valid in a filename on Linux or Windows).
///
/// Returns the absolute path actually written.
pub fn generate_unit(
    build_dir: &Path,
    output: &Path,
    options: UnitOptions,
) -> Result<PathBuf, Error> {
    // 1. Absolutise the build dir so the rendered unit doesn't depend
    //    on the caller's CWD. Canonicalize also verifies it exists
    //    and is readable — cheap front-loaded sanity check.
    let build_dir = fs::canonicalize(build_dir).map_err(|e| {
        Error::ArtifactMissing(format!("{}: {e}", build_dir.display()))
    })?;

    // 2. Require every artifact the unit names — fail fast instead of
    //    writing a unit that will blow up at `systemctl start`.
    for required in [KERNEL_FILE, INITRD_FILE, ROOTFS_FILE, CONFIG_FILE] {
        let p = build_dir.join(required);
        if !p.exists() {
            return Err(Error::ArtifactMissing(p.display().to_string()));
        }
    }

    // 3. Pull id + description from config.json. Anything else in the
    //    file is out of scope for the unit (see module-level doc).
    let cfg_path = build_dir.join(CONFIG_FILE);
    let cfg_bytes = fs::read(&cfg_path)?;
    let cfg: ConfigHeader = serde_json::from_slice(&cfg_bytes)
        .map_err(|e| Error::ConfigParse(format!("{}: {e}", cfg_path.display())))?;
    if cfg.id.trim().is_empty() {
        return Err(Error::ConfigParse(format!(
            "{}: empty `id` field",
            cfg_path.display()
        )));
    }

    // 4. Render the unit.
    let unit = render_unit(&build_dir, &cfg, &options);

    // 5. Resolve the final output path. If `output` points at a
    //    directory, synthesise a filename from the image id.
    let out_path = if output.is_dir() {
        output.join(format!("{}.service", sanitise_id(&cfg.id)))
    } else {
        output.to_path_buf()
    };

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    fs::write(&out_path, unit)?;

    // Return an absolute path where possible so callers can log it
    // without having to re-resolve against their own CWD.
    let abs = fs::canonicalize(&out_path).unwrap_or(out_path);
    Ok(abs)
}

/// Render the unit body. Pure — no I/O — so tests can exercise it in
/// isolation if needed.
fn render_unit(abs_build_dir: &Path, cfg: &ConfigHeader, opts: &UnitOptions) -> String {
    let kernel = abs_build_dir.join(KERNEL_FILE);
    let initrd = abs_build_dir.join(INITRD_FILE);
    let rootfs = abs_build_dir.join(ROOTFS_FILE);

    let description = if cfg.description.trim().is_empty() {
        format!("xkvm boot of {}", cfg.id)
    } else {
        cfg.description.clone()
    };

    let user_line = match &opts.user {
        Some(u) => format!("User={u}\n"),
        None => String::new(),
    };

    format!(
        "[Unit]\n\
         Description={description} (xkvm: {id})\n\
         Documentation=https://github.com/sweengineeringlabs/vmisolate/blob/main/docs/3-design/adr/015-image-registry.md\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         {user_line}\
         ExecStart={xkvm} boot --kernel {kernel} --initrd {initrd} --kali {rootfs} --init-mode xkinit --timeout {timeout}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy={wanted_by}\n",
        description = description,
        id = cfg.id,
        user_line = user_line,
        xkvm = display_path(&opts.xkvm_path),
        kernel = display_path(&kernel),
        initrd = display_path(&initrd),
        rootfs = display_path(&rootfs),
        timeout = DEFAULT_BOOT_TIMEOUT_SECS,
        wanted_by = opts.wanted_by,
    )
}

/// Render a path for use in the emitted systemd unit.
///
/// Systemd unit files always target Linux hosts, so two Windows-
/// specific cleanups happen here:
///
/// * Strip the `\\?\` verbatim prefix that `fs::canonicalize`
///   returns on Windows for long paths.
/// * Replace `\` separators with `/` so the rendered `ExecStart`
///   is consumable on Linux (where `\` is a literal character,
///   not a path separator).
///
/// On Linux both transforms are no-ops — `Path::display` already
/// uses `/` and never emits the verbatim prefix.
fn display_path(p: &Path) -> String {
    let s = p.display().to_string();
    let s = s.strip_prefix(r"\\?\").map(str::to_owned).unwrap_or(s);
    s.replace('\\', "/")
}

/// Turn an image id like `acme/alpine:3.20` into a filename-safe
/// stem. `/` → `-`, `:` → `_`; everything else is passed through.
/// Documented behaviour — tests assert it, operators rely on it.
fn sanitise_id(id: &str) -> String {
    id.chars()
        .map(|c| match c {
            '/' => '-',
            ':' => '_',
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit-level coverage of the pure helper. Catches: a future edit
    // broadening the escape set (e.g. stripping dots) without
    // updating callers/docs.
    #[test]
    fn test_sanitise_id_replaces_slash_and_colon_only() {
        assert_eq!(sanitise_id("acme/alpine:3.20"), "acme-alpine_3.20");
        assert_eq!(sanitise_id("plain"), "plain");
        assert_eq!(sanitise_id("a/b/c:1:2"), "a-b-c_1_2");
    }

    // Catches: someone deleting the Windows verbatim-prefix strip and
    // shipping `\\?\C:\…` into a Linux unit file. Also pins the
    // post-strip backslash→slash substitution so the rendered path is
    // consumable on the target Linux host.
    #[test]
    fn test_display_path_strips_verbatim_prefix_and_normalises_separators() {
        // Pure Linux path — must round-trip unchanged.
        let p = PathBuf::from("/tmp/kernel");
        assert_eq!(display_path(&p), "/tmp/kernel");

        #[cfg(windows)]
        {
            // Verbatim-prefixed Windows path → strip prefix, then
            // normalise separators.
            let p = PathBuf::from(r"\\?\C:\tmp\kernel");
            assert_eq!(display_path(&p), "C:/tmp/kernel");
        }
    }

    // Catches: Issue #13 regressing. On Linux-host unit files a
    // backslash is a literal character; if a Windows build host emits
    // paths with `\` separators, the rendered `ExecStart` can't be
    // executed.
    #[test]
    fn test_display_path_converts_windows_backslashes_to_slashes() {
        // Exercise the substitution explicitly via a literal
        // backslash-separated path. This check runs on every host —
        // the input is a `PathBuf` from a raw string, so behaviour
        // depends on the substitution, not the host's path-parsing.
        let p = PathBuf::from(r"C:\Users\op\build\kernel");
        let rendered = display_path(&p);
        assert!(
            !rendered.contains('\\'),
            "rendered path must not contain any \\ separators, got {rendered:?}"
        );
        // Be specific about the expected output on Windows, where
        // PathBuf renders the input as-is.
        #[cfg(windows)]
        assert_eq!(rendered, "C:/Users/op/build/kernel");
    }
}
