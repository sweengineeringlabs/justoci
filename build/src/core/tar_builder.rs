//! Deterministic tar builder for `LayerSource::Files` layers.
//!
//! ## Determinism contract (Production-Guarantees-§2)
//!
//! Same `[[layers.files]]` block + same source files on disk → same
//! tar bytes. The `tar` archive format encodes a lot of metadata that
//! varies on real systems; we explicitly pin every field that does:
//!
//! - **Order** — entries sorted lexicographically by `dest`. The
//!   spec author's authored order is *intentionally* discarded:
//!   reordering the spec's `[[layers.files]]` entries must NOT
//!   change the tar bytes (otherwise reproducibility breaks for any
//!   spec that gets reformatted).
//! - **mtime** = 0. Source-file mtime varies wildly even across
//!   `git clone`s of the same repo.
//! - **uid:gid** = 0:0, **uname:gname** = "" (empty). Build hosts
//!   run under different uids; "root:root" varies in name on
//!   non-Linux build hosts.
//! - **mode** taken from the spec, NOT from the source file's
//!   on-disk mode. The spec is the authority; `chmod` on the host
//!   must not perturb the layer.
//! - **format** = USTAR (PAX records would embed `mtime` in
//!   nanoseconds, defeating the mtime=0 pinning).
//! - **link names**, **device numbers**, **PAX extensions** — never
//!   emitted; we refuse symlinks / devices at validation time.
//!
//! ## Directory descent
//!
//! A `LayerFile { source: <dir>, dest: "/etc/keys/", mode: 0o600 }`
//! descends `<dir>` recursively. Each child's tar `path` is
//! `dest + relative_to_source(child)`. Children inherit the
//! `LayerFile`'s `mode` — the spec mode is the authority.
//!
//! ## Path normalisation
//!
//! Tar paths inside the archive are forward-slash, no leading slash,
//! no `..`. Spec dest paths come absolute (`/etc/app.toml`); we strip
//! the leading `/` because tar paths are relative-to-root by convention.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use spec::LayerFile;
use tar::{Builder, EntryType, Header};

/// Build a deterministic tar from a list of `LayerFile`s. Source
/// paths in each entry resolve against `spec_dir` if relative.
///
/// Returns the in-memory tar bytes. Layers fit in memory for the
/// scenarios v0 supports (config files, key bundles, model weights
/// up to a few GB on a build host with adequate RAM); streaming
/// straight to the CAS lands in a follow-up if a real workload
/// exceeds that.
pub fn build_deterministic_tar(
    entries: &[LayerFile],
    spec_dir: &Path,
) -> io::Result<Vec<u8>> {
    // Walk every entry into a flat list of `(tar_path, mode, source)`
    // triples first, then sort by tar_path. This is what makes the
    // build order-independent: spec authors can rearrange
    // `[[layers.files]]` blocks freely.
    let mut flat: BTreeMap<String, FlatEntry> = BTreeMap::new();
    for entry in entries {
        let resolved_source = resolve(spec_dir, &entry.source);
        let dest = normalise_dest(&entry.dest);
        flatten_entry(&resolved_source, &dest, entry.mode, &mut flat)?;
    }

    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = Builder::new(&mut buf);
        // mode=Deterministic skips PAX longname records up to the
        // ustar 100-byte path limit. Paths longer than that fall
        // through to PAX, which is fine — PAX records use only
        // path/linkname (no timestamps, since we set mtime=0).
        builder.mode(tar::HeaderMode::Deterministic);

        for (tar_path, fe) in &flat {
            match fe {
                FlatEntry::Dir { mode } => {
                    let mut header = Header::new_ustar();
                    header.set_size(0);
                    header.set_mode(*mode);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Directory);
                    // Tar dir entries customarily end with "/".
                    let path = if tar_path.ends_with('/') {
                        tar_path.clone()
                    } else {
                        format!("{tar_path}/")
                    };
                    header.set_cksum();
                    let empty: &[u8] = &[];
                    builder.append_data(&mut header, &path, io::Cursor::new(empty))?;
                }
                FlatEntry::File { mode, source } => {
                    let metadata = fs::metadata(source)?;
                    if !metadata.is_file() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "tar source {} is not a regular file",
                                source.display()
                            ),
                        ));
                    }
                    let mut header = Header::new_ustar();
                    header.set_size(metadata.len());
                    header.set_mode(*mode);
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Regular);
                    header.set_cksum();
                    let mut f = fs::File::open(source)?;
                    builder.append_data(&mut header, tar_path, &mut f as &mut dyn Read)?;
                }
            }
        }

        builder.finish()?;
    }
    Ok(buf)
}

enum FlatEntry {
    Dir { mode: u32 },
    File { mode: u32, source: PathBuf },
}

fn flatten_entry(
    source: &Path,
    dest: &str,
    mode: u32,
    out: &mut BTreeMap<String, FlatEntry>,
) -> io::Result<()> {
    let metadata = fs::metadata(source)?;
    if metadata.is_file() {
        out.insert(
            dest.trim_end_matches('/').to_string(),
            FlatEntry::File {
                mode,
                source: source.to_path_buf(),
            },
        );
        return Ok(());
    }
    if metadata.is_dir() {
        // Emit the directory entry itself so consumers extracting the
        // tar recreate the directory before its children.
        let dir_dest = if dest.ends_with('/') {
            dest.trim_end_matches('/').to_string()
        } else {
            dest.to_string()
        };
        out.insert(dir_dest.clone(), FlatEntry::Dir { mode });

        // Read children, sort lexicographically by name (NOT by
        // OS-dependent readdir order), then recurse.
        let mut children: Vec<PathBuf> =
            fs::read_dir(source)?.filter_map(Result::ok).map(|d| d.path()).collect();
        children.sort();
        for child in children {
            let name = child
                .file_name()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("child of {} has no filename", source.display()),
                    )
                })?
                .to_str()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "non-UTF8 filename under {} cannot land in a tar layer",
                            source.display()
                        ),
                    )
                })?
                .to_string();
            let child_dest = format!("{dir_dest}/{name}");
            flatten_entry(&child, &child_dest, mode, out)?;
        }
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "tar source {} is neither a regular file nor a directory \
             (symlinks / devices not supported in v0 layers)",
            source.display()
        ),
    ))
}

fn resolve(spec_dir: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        spec_dir.join(p)
    }
}

/// Tar paths are relative-to-root and use `/` separators. The spec
/// gives us absolute Unix-style paths (`/etc/app.toml`); strip the
/// leading slash and replace any backslashes — though backslashes
/// shouldn't appear since `dest` is a `String` chosen by the spec
/// author.
fn normalise_dest(dest: &str) -> String {
    let trimmed = dest.trim_start_matches('/');
    trimmed.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn write(dir: &Path, rel: &str, contents: &[u8]) -> PathBuf {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn test_normalise_dest_strips_leading_slash() {
        // Bug this would catch: tar paths starting with "/" — most
        // tar consumers reject absolute paths or extract them
        // outside the working tree.
        assert_eq!(normalise_dest("/etc/app.toml"), "etc/app.toml");
        assert_eq!(normalise_dest("etc/app.toml"), "etc/app.toml");
    }

    #[test]
    fn test_single_file_round_trips_through_tar() {
        // Bug this would catch: a header field set wrong (size, mode)
        // makes `tar -tvf` reject the archive or extract garbage.
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "src/app.toml", b"hello");

        let entries = vec![LayerFile {
            source: PathBuf::from("src/app.toml"),
            dest: "/etc/app.toml".into(),
            mode: 0o644,
        }];

        let bytes = build_deterministic_tar(&entries, tmp.path()).unwrap();
        let mut ar = tar::Archive::new(&bytes[..]);
        let mut found_file = false;
        for entry in ar.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "etc/app.toml" {
                let header = entry.header();
                assert_eq!(header.mode().unwrap(), 0o644);
                assert_eq!(header.uid().unwrap(), 0);
                assert_eq!(header.gid().unwrap(), 0);
                assert_eq!(header.mtime().unwrap(), 0);
                let mut payload = Vec::new();
                entry.read_to_end(&mut payload).unwrap();
                assert_eq!(payload, b"hello");
                found_file = true;
            }
        }
        assert!(found_file, "tar must contain etc/app.toml");
    }

    #[test]
    fn test_directory_descent_emits_sorted_children() {
        // Bug this would catch: relying on OS readdir order, which
        // varies between Linux (insertion-ordered tmpfs) and macOS
        // (HFS+ name-sorted) and Windows (NTFS). Without an explicit
        // sort, the same source dir produces different tars on
        // different hosts.
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "keys/zebra.pem", b"Z");
        write(tmp.path(), "keys/alpha.pem", b"A");
        write(tmp.path(), "keys/middle.pem", b"M");

        let entries = vec![LayerFile {
            source: PathBuf::from("keys"),
            dest: "/etc/keys/".into(),
            mode: 0o600,
        }];

        let bytes = build_deterministic_tar(&entries, tmp.path()).unwrap();
        let mut ar = tar::Archive::new(&bytes[..]);
        let paths: Vec<String> = ar
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.path().ok().map(|p| p.to_string_lossy().to_string()))
            .filter(|p| p.starts_with("etc/keys/") && !p.ends_with('/'))
            .collect();

        assert_eq!(
            paths,
            vec![
                "etc/keys/alpha.pem".to_string(),
                "etc/keys/middle.pem".to_string(),
                "etc/keys/zebra.pem".to_string(),
            ],
            "children must appear in lexicographic order, got {paths:?}"
        );
    }

    #[test]
    fn test_two_runs_same_input_produce_byte_identical_tar() {
        // Bug this would catch: any non-determinism in the tar bytes.
        // This is the §2 reproducibility contract — fail loudly.
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "config/a.toml", b"a");
        write(tmp.path(), "config/b.toml", b"b");

        let entries = vec![
            LayerFile {
                source: PathBuf::from("config/a.toml"),
                dest: "/etc/a.toml".into(),
                mode: 0o644,
            },
            LayerFile {
                source: PathBuf::from("config/b.toml"),
                dest: "/etc/b.toml".into(),
                mode: 0o644,
            },
        ];

        let first = build_deterministic_tar(&entries, tmp.path()).unwrap();
        let second = build_deterministic_tar(&entries, tmp.path()).unwrap();
        assert_eq!(
            first, second,
            "tar bytes must be identical across two runs of the same input"
        );
    }

    #[test]
    fn test_input_order_does_not_change_tar_bytes() {
        // Bug this would catch: a refactor that emits entries in
        // input order — reformatting the spec's `[[layers.files]]`
        // table would silently change the layer digest.
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "a.txt", b"a");
        write(tmp.path(), "b.txt", b"b");
        write(tmp.path(), "c.txt", b"c");

        let mk = |source: &str, dest: &str| LayerFile {
            source: PathBuf::from(source),
            dest: dest.into(),
            mode: 0o644,
        };

        let in_order = vec![mk("a.txt", "/a"), mk("b.txt", "/b"), mk("c.txt", "/c")];
        let permuted = vec![mk("c.txt", "/c"), mk("a.txt", "/a"), mk("b.txt", "/b")];

        let bytes_in = build_deterministic_tar(&in_order, tmp.path()).unwrap();
        let bytes_perm = build_deterministic_tar(&permuted, tmp.path()).unwrap();
        assert_eq!(
            bytes_in, bytes_perm,
            "permuting the [[layers.files]] order must not change tar bytes"
        );
    }

    #[test]
    fn test_missing_source_surfaces_io_error() {
        // Bug this would catch: a panic on missing source instead of
        // a typed `io::Error` — hides the operator-actionable cause.
        let tmp = TempDir::new().unwrap();
        let entries = vec![LayerFile {
            source: PathBuf::from("does-not-exist"),
            dest: "/etc/x".into(),
            mode: 0o644,
        }];
        let err = build_deterministic_tar(&entries, tmp.path()).unwrap_err();
        assert!(
            matches!(err.kind(), io::ErrorKind::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    #[test]
    fn test_spec_mode_overrides_host_mode() {
        // Bug this would catch: copying the source file's on-disk
        // mode into the tar header. Source mode varies with umask /
        // chmod on the build host; the spec is the authority.
        let tmp = TempDir::new().unwrap();
        let source = write(tmp.path(), "x.bin", b"x");
        // Set an unusual mode on the source so we can see it leak.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o777)).unwrap();
        }
        let _ = source; // silence on non-unix

        let entries = vec![LayerFile {
            source: PathBuf::from("x.bin"),
            dest: "/usr/local/bin/x".into(),
            mode: 0o755,
        }];

        let bytes = build_deterministic_tar(&entries, tmp.path()).unwrap();
        let mut ar = tar::Archive::new(&bytes[..]);
        let entry = ar.entries().unwrap().next().unwrap().unwrap();
        let mode = entry.header().mode().unwrap();
        assert_eq!(
            mode, 0o755,
            "spec mode 0o755 must win over source on-disk mode"
        );
    }
}
