//! Central `ImageSpec` input validator.
//!
//! # Why here
//!
//! `oci-build` is the earliest producer that sees operator-supplied
//! `ImageSpec` values (parsed from TOML or constructed programmatically
//! via the SAF facade). Every downstream emitter — `oci-systemd` unit
//! rendering, `oci-publish` HTTP layout, `oci-push` OCI manifest
//! writers, future Fleet consumers — inherits the resulting
//! `config.json` and the `ImageSpec` shape. Validating once, here,
//! prevents every downstream from re-implementing the same defensive
//! checks and lets each of them assume clean input.
//!
//! # Fail closed
//!
//! The validator returns a [`ValidationResult`] with `allowed: false`
//! whenever any check fails. [`crate::core::service::default_service`]
//! maps that into an [`crate::api::error::Error::SpecInvalid`] at the
//! top of `DefaultImageService::build`, **before** any filesystem work
//! happens — no partial artifacts, no half-written `config.json`.
//!
//! # Belt and braces
//!
//! `oci-systemd` keeps its own narrow defensive checks (e.g. the
//! `sanitise_id` allowlist, the empty-id reject in `generate_unit`).
//! Those stay in place: this central validator catches at build time;
//! the oci-systemd checks catch the case where an operator constructs
//! a `ConfigHeader`-equivalent programmatically and skips the build
//! step. Two layers, same policy.
//!
//! # Closes
//!
//! * Issue #8 — oci-systemd unit injection via newlines in
//!   `id`/`description` (HIGH).
//! * Issue #9 — `sanitise_id` allowlist on image ids (MEDIUM).
//! * Issue #10 — the central validator itself (this file).

use std::path::Path;

use super::spec::{BaseRef, ImageSpec};

/// Outcome of [`validate_image_spec`].
///
/// `allowed = true` is the happy path — `threats` is empty and
/// `severity` is [`Severity::None`]. Any check failure flips `allowed`
/// to `false`, sets `severity` to the highest severity across all
/// recorded threats, and populates `threats` with one entry per
/// failure. `reason` is a pre-formatted human-readable summary that
/// callers (specifically `DefaultImageService::build`) can forward
/// into an `Error::SpecInvalid { reason }` without additional
/// formatting.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// `true` ⇒ the spec is safe to build. `false` ⇒ reject.
    pub allowed: bool,
    /// Highest severity across `threats`. `None` when `threats`
    /// is empty. `High` for any unit-injection / argv-null /
    /// kernel-cmdline newline — threats that let a tenant escape
    /// the structured boundary. `Low` for formatting / allowlist
    /// violations that won't hurt correctness but risk surprising
    /// downstream consumers.
    pub severity: Severity,
    /// One entry per individual check failure. Callers that want
    /// programmatic access (e.g. CLI colouring by severity, audit
    /// log emission) walk this list rather than re-parsing `reason`.
    pub threats: Vec<Threat>,
    /// Pre-formatted human-readable summary. `None` when `allowed`.
    pub reason: Option<String>,
}

/// Severity ladder, ordered `None < Low < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// No threats recorded.
    None,
    /// Formatting / allowlist violation. Build should reject but
    /// there's no active exploit path.
    Low,
    /// Structured-boundary escape — newline / null-byte / control
    /// char in a field that downstream emitters splice into
    /// line-oriented or null-terminated formats.
    High,
}

/// Individual check failure. Each variant names the class of bug
/// the check catches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Threat {
    /// Newline (`\n` or `\r`) in a field that downstream emitters
    /// splice into line-oriented formats (systemd unit keys,
    /// `/etc/xkvm.conf`). Closes issue #8.
    NewlineInIdentifier { field: &'static str },
    /// C0 control byte (other than tab) or DEL in a field that
    /// downstream emitters splice into human-readable output.
    /// Renders garbled / invisible content and can confuse line
    /// parsers.
    ControlCharInField { field: &'static str, byte: u8 },
    /// A required field (currently `id`) is empty.
    EmptyRequiredField { field: &'static str },
    /// An environment-variable key failed the POSIX identifier
    /// grammar (`[A-Za-z_][A-Za-z0-9_]*`). Catches
    /// `KEY=value\nOTHERKEY=override` style injections into
    /// `/etc/xkvm.conf`.
    NonPosixEnvKey { key: String },
    /// An OCI annotation key failed the
    /// `[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.…)*` grammar from the
    /// OCI image spec. Catches uppercase / leading- or
    /// trailing-hyphen keys that registries reject.
    InvalidAnnotationKey { key: String },
    /// A null byte appeared in any argv element. Kernel argv is
    /// null-byte-terminated, so embedded nulls truncate the
    /// command silently.
    NullByteInEntrypoint,
    /// A field exceeded its byte-length cap. See the `MAX_*_BYTES`
    /// constants below for the enforced caps. Caps are operator-
    /// facing defaults — no tenant DoS today because single-spec
    /// parsing is bounded, but downstream consumers (OCI
    /// registries, systemd unit parsers, gRPC frames) have their
    /// own ceilings that unbounded input eventually hits. Failing
    /// early at build time beats a silent registry truncation.
    TooLong { field: &'static str, actual: usize, max: usize },
    /// A `packages[]` entry contained a character outside the apk /
    /// apt allowlist `[A-Za-z0-9._+-]`. Closes the PackageInstaller
    /// side of #17 — defense in depth against shell-injection
    /// (`nginx; rm -rf /`) and newline-splice attacks.
    InvalidPackageName { name: String },
    /// A `files[*].dest` failed the dest-path grammar. Three
    /// sub-causes collapsed under one variant to keep the enum
    /// flat — `reason` names which rule failed:
    ///   * "not absolute" — dest must start with `/`
    ///   * "parent segment" — contains a `..` component
    ///   * "pseudofs prefix" — starts with `/proc`, `/sys`, or `/dev`
    ///     (runtime-only directories that build-time writes either
    ///     ignore or confuse)
    /// Closes the central-validator side of #18.
    InvalidFileDest { dest: String, reason: &'static str },
}

/// Byte-length caps applied by the central validator. Pinned by
/// tests so a future edit can't quietly raise them.
///
/// All caps are in bytes (not characters) because downstream
/// consumers — registries, systemd, `/etc/xkvm.conf`, gRPC frames
/// — all measure wire size, not code-point count.
pub const MAX_ID_BYTES: usize = 256;
pub const MAX_DESCRIPTION_BYTES: usize = 4096;
pub const MAX_KERNEL_CMDLINE_BYTES: usize = 2048;
pub const MAX_ENV_VALUE_BYTES: usize = 4096;
pub const MAX_LABEL_VALUE_BYTES: usize = 4096;

impl Threat {
    fn severity(&self) -> Severity {
        match self {
            // Structured-boundary escapes — actively dangerous.
            Threat::NewlineInIdentifier { .. }
            | Threat::ControlCharInField { .. }
            | Threat::NullByteInEntrypoint => Severity::High,
            // Formatting / allowlist — reject but not an exploit.
            // TooLong sits here alongside other Low-severity limits:
            // the build should reject but there's no active exploit.
            Threat::EmptyRequiredField { .. }
            | Threat::NonPosixEnvKey { .. }
            | Threat::InvalidAnnotationKey { .. }
            | Threat::TooLong { .. }
            | Threat::InvalidPackageName { .. }
            | Threat::InvalidFileDest { .. } => Severity::Low,
        }
    }

    fn describe(&self) -> String {
        match self {
            Threat::NewlineInIdentifier { field } => {
                format!("newline in `{field}` — would split downstream unit/config lines")
            }
            Threat::ControlCharInField { field, byte } => format!(
                "control byte 0x{byte:02x} in `{field}` — not printable, breaks line parsers"
            ),
            Threat::EmptyRequiredField { field } => {
                format!("required field `{field}` is empty")
            }
            Threat::NonPosixEnvKey { key } => format!(
                "env key `{key}` is not a POSIX identifier ([A-Za-z_][A-Za-z0-9_]*)"
            ),
            Threat::InvalidAnnotationKey { key } => format!(
                "label key `{key}` is not a valid OCI annotation key"
            ),
            Threat::NullByteInEntrypoint => {
                "null byte in entrypoint argv element — kernel argv is null-terminated".into()
            }
            Threat::TooLong { field, actual, max } => {
                format!("field `{field}` is {actual} bytes (cap {max})")
            }
            Threat::InvalidPackageName { name } => format!(
                "package name `{name}` contains characters outside the \
                 allowlist [A-Za-z0-9._+-] — rejected before reaching the installer"
            ),
            Threat::InvalidFileDest { dest, reason } => format!(
                "files[].dest `{dest}` rejected: {reason}"
            ),
        }
    }
}

/// Validate an [`ImageSpec`]. See the module doc for where this sits
/// in the pipeline and why downstream crates trust its output.
pub fn validate_image_spec(spec: &ImageSpec) -> ValidationResult {
    let mut threats: Vec<Threat> = Vec::new();

    // 1. `id` — required, no newlines, no control chars, capped byte
    //    length. Catches #8 unit-injection at the build-time boundary;
    //    the byte cap fails early on oversized ids that downstream
    //    OCI registries would reject anyway.
    if spec.id.is_empty() {
        threats.push(Threat::EmptyRequiredField { field: "id" });
    } else {
        push_line_and_control_threats(&spec.id, "id", &mut threats);
        push_length_threat(&spec.id, "id", MAX_ID_BYTES, &mut threats);
    }

    // 2. `description` — optional, same formatting rules as `id`
    //    once set (systemd `Description=` is line-oriented), plus a
    //    4 KiB cap. A multi-kilobyte description has no user-facing
    //    use and blows past some registry annotation limits.
    push_line_and_control_threats(&spec.description, "description", &mut threats);
    push_length_threat(
        &spec.description,
        "description",
        MAX_DESCRIPTION_BYTES,
        &mut threats,
    );

    // 3. `env` keys — POSIX identifier grammar. Rejects keys that
    //    would let a value splice new `KEY=value` lines into
    //    `/etc/xkvm.conf`.
    //    `env` values — no C0 control chars. The key-side POSIX
    //    check alone is insufficient: a value like
    //    `"legit\nKEY2=override"` still writes two `KEY=value`
    //    lines into `/etc/xkvm.conf` if the xkvm-fs config writer
    //    doesn't escape newlines on emit. Closing the surface at
    //    the producer boundary is cheaper than escaping at every
    //    downstream writer. See audit doc follow-up #1.
    for (key, value) in &spec.env {
        if !is_posix_env_key(key) {
            threats.push(Threat::NonPosixEnvKey { key: key.clone() });
        }
        if let Some(bad) = first_forbidden_control_byte(value) {
            threats.push(Threat::ControlCharInField {
                field: "env.value",
                byte: bad,
            });
        }
        push_length_threat(value, "env.value", MAX_ENV_VALUE_BYTES, &mut threats);
    }

    // 4. `labels` keys — OCI annotation grammar. Values: no control
    //    chars (they flow into JSON which tolerates them but
    //    downstream viewers don't).
    for (key, value) in &spec.labels {
        if !is_oci_annotation_key(key) {
            threats.push(Threat::InvalidAnnotationKey { key: key.clone() });
        }
        if let Some(bad) = first_forbidden_control_byte(value) {
            threats.push(Threat::ControlCharInField {
                field: "labels.value",
                byte: bad,
            });
        }
        push_length_threat(value, "labels.value", MAX_LABEL_VALUE_BYTES, &mut threats);
    }

    // 5. `node_tags` — non-empty, no whitespace, no control chars.
    //    Whitespace in a tag would split Fleet's scheduler matcher.
    for tag in &spec.node_tags {
        if tag.is_empty() {
            threats.push(Threat::EmptyRequiredField { field: "node_tags[]" });
            continue;
        }
        if let Some(bad) = first_forbidden_control_byte(tag) {
            threats.push(Threat::ControlCharInField {
                field: "node_tags[]",
                byte: bad,
            });
        }
        if tag.chars().any(char::is_whitespace) {
            // A bare space in a tag isn't a control char but it
            // still breaks scheduler matching — report it as a
            // control-char threat on the space byte for a single
            // consistent surface.
            threats.push(Threat::ControlCharInField {
                field: "node_tags[]",
                byte: b' ',
            });
        }
    }

    // 6. `entrypoint` — no null bytes anywhere. Linux argv is
    //    null-terminated; an embedded `\0` truncates the command.
    for arg in &spec.entrypoint {
        if arg.as_bytes().contains(&0u8) {
            threats.push(Threat::NullByteInEntrypoint);
            break;
        }
    }

    // 7. `kernel_cmdline` — no newlines, no null bytes, byte cap.
    //    The kernel whitespace-splits this; embedded newlines would
    //    pass through unnoticed into /proc/cmdline. The 2 KiB cap
    //    matches x86_64 `COMMAND_LINE_SIZE` default — anything
    //    longer is silently truncated by the kernel, which is its
    //    own bug class; fail loudly at build time instead.
    if let Some(cmdline) = &spec.kernel_cmdline {
        for (i, b) in cmdline.as_bytes().iter().enumerate() {
            match *b {
                b'\n' | b'\r' => {
                    threats.push(Threat::NewlineInIdentifier {
                        field: "kernel_cmdline",
                    });
                    break;
                }
                0u8 => {
                    threats.push(Threat::ControlCharInField {
                        field: "kernel_cmdline",
                        byte: 0,
                    });
                    break;
                }
                _ => {}
            }
            // Only scan until we hit one bad byte — one threat per
            // field is enough signal; no value in flooding.
            let _ = i;
        }
        push_length_threat(
            cmdline,
            "kernel_cmdline",
            MAX_KERNEL_CMDLINE_BYTES,
            &mut threats,
        );
    }

    // 8. `BaseRef::LocalRootfs.path` — intentionally unrestricted.
    //    The operator authors the spec and has full host-FS access
    //    at build time; `..` segments are a legitimate way to reach
    //    a shared `downloads/` directory from a checked-in reference
    //    spec (e.g. `main/examples/llmboot.spec.toml`). Issue #42
    //    removed the old traversal check — tenant-crossing inputs
    //    (FileEntry.dest) retain theirs below.

    // 9. `packages[]` — each entry must match the allowlist
    //    `[A-Za-z0-9._+-]`. Defense against shell-injection via a
    //    crafted TOML (`nginx; rm -rf /`) AND against newline-splice
    //    attacks on the installer's stderr capture. Closes the
    //    PackageInstaller side of #17.
    for pkg in &spec.packages {
        if !is_valid_apk_package_name(pkg) {
            threats.push(Threat::InvalidPackageName { name: pkg.clone() });
        }
    }

    // 10. `files[*].dest` — absolute, no `..` segments, not under
    //     pseudofs directories. The FileOverlay impl re-checks at
    //     runtime (defense in depth); this pass is the canonical
    //     build-time gate. Closes the central-validator side of #18.
    for entry in &spec.files {
        if let Some(reason) = file_dest_rejection(&entry.dest) {
            threats.push(Threat::InvalidFileDest {
                dest: entry.dest.display().to_string(),
                reason,
            });
        }
    }

    // Assemble the result.
    if threats.is_empty() {
        ValidationResult {
            allowed: true,
            severity: Severity::None,
            threats,
            reason: None,
        }
    } else {
        let severity = threats
            .iter()
            .map(Threat::severity)
            .max()
            .unwrap_or(Severity::None);
        let reason = format_reason(&threats);
        ValidationResult {
            allowed: false,
            severity,
            threats,
            reason: Some(reason),
        }
    }
}

// --- helpers ----------------------------------------------------------------

/// Push [`Threat::NewlineInIdentifier`] and/or
/// Push a [`Threat::TooLong`] if `s` exceeds `max` bytes. Size is
/// measured in bytes, not characters — downstream wire/disk
/// consumers care about byte count regardless of encoding.
fn push_length_threat(
    s: &str,
    field: &'static str,
    max: usize,
    threats: &mut Vec<Threat>,
) {
    let actual = s.len();
    if actual > max {
        threats.push(Threat::TooLong { field, actual, max });
    }
}

/// [`Threat::ControlCharInField`] entries for any forbidden byte in
/// `s`. "Forbidden" = `\n`, `\r`, and every C0 control byte except
/// tab (`\x09`), plus DEL (`\x7f`).
fn push_line_and_control_threats(
    s: &str,
    field: &'static str,
    threats: &mut Vec<Threat>,
) {
    let mut saw_newline = false;
    let mut bad_control: Option<u8> = None;
    for b in s.as_bytes() {
        match *b {
            b'\n' | b'\r' if !saw_newline => {
                threats.push(Threat::NewlineInIdentifier { field });
                saw_newline = true;
            }
            0x00..=0x08 | 0x0B..=0x1F | 0x7F if bad_control.is_none() => {
                bad_control = Some(*b);
            }
            _ => {}
        }
    }
    if let Some(byte) = bad_control {
        threats.push(Threat::ControlCharInField { field, byte });
    }
}

/// First forbidden control byte in `s`, or `None` if the string is
/// clean. Forbidden = C0 control bytes except tab, plus DEL.
fn first_forbidden_control_byte(s: &str) -> Option<u8> {
    s.as_bytes().iter().copied().find(|b| {
        matches!(*b, 0x00..=0x08 | 0x0A..=0x1F | 0x7F)
    })
}

/// POSIX identifier grammar: `[A-Za-z_][A-Za-z0-9_]*`, non-empty.
fn is_posix_env_key(key: &str) -> bool {
    let mut bytes = key.as_bytes().iter();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || *first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// OCI annotation key grammar from the image-spec:
///   `[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*`
///
/// Each dot-separated component must start and end with
/// `[a-z0-9]` and may contain hyphens in the middle.
fn is_oci_annotation_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    key.split('.').all(is_oci_annotation_component)
}

fn is_oci_annotation_component(comp: &str) -> bool {
    let bytes = comp.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_lower_alnum(first) || !is_lower_alnum(last) {
        return false;
    }
    bytes
        .iter()
        .all(|b| is_lower_alnum(*b) || *b == b'-')
}

/// Apk / apt allowlist: ASCII alphanumerics plus `.`, `_`, `+`, `-`.
/// Max 128 bytes — longer names are unheard of in practice and the
/// cap keeps the `spec.lock` file rows reasonably-sized.
fn is_valid_apk_package_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// Returns `Some(reason)` if the given `files[].dest` violates a
/// dest-path rule, else `None`. Split from the iteration so tests
/// can table-drive the rules.
///
/// **Note**: dest is a GUEST path (Linux rootfs). We check
/// `starts_with('/')` manually rather than `std::Path::is_absolute`,
/// because on Windows hosts the std check interprets `/opt/foo` as
/// relative (no drive letter) — but in the guest rootfs it's absolute.
fn file_dest_rejection(dest: &Path) -> Option<&'static str> {
    let s = match dest.to_str() {
        Some(s) => s,
        None => return Some("not valid UTF-8"),
    };
    if !s.starts_with('/') {
        return Some("not absolute — guest paths must start with `/`");
    }
    if s.split('/').any(|seg| seg == "..") {
        return Some("contains `..` segment — path traversal rejected");
    }
    for deny in ["/proc", "/sys", "/dev"] {
        if s == deny || s.starts_with(&format!("{deny}/")) {
            return Some("targets a pseudofs directory (/proc, /sys, /dev)");
        }
    }
    None
}

fn format_reason(threats: &[Threat]) -> String {
    let mut out = String::from("ImageSpec failed validation: ");
    for (i, t) in threats.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        out.push_str(&t.describe());
    }
    out
}

// --- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::spec::{BaseRef, ImageSpec, InitMode};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn clean_spec() -> ImageSpec {
        ImageSpec {
            id: "acme/alpine:3.20".into(),
            description: "Alpine smoke image".into(),
            base: BaseRef::LocalRootfs {
                path: PathBuf::from("/abs/path/rootfs.ext4"),
            },
            packages: Vec::new(),
            files: Vec::new(),
            env: BTreeMap::new(),
            entrypoint: vec!["/bin/true".into()],
            kernel_cmdline: None,
            init_mode: InitMode::Xkinit,
            node_tags: vec!["linux".into()],
            labels: BTreeMap::new(),
        }
    }

    // Catches: issue #10 — a spec with an empty `id` silently
    // building and producing a config.json that downstream
    // consumers can't key on.
    #[test]
    fn test_empty_id_is_rejected() {
        let mut spec = clean_spec();
        spec.id = String::new();
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r
            .threats
            .contains(&Threat::EmptyRequiredField { field: "id" }));
        assert_eq!(r.severity, Severity::Low);
    }

    // Catches: issue #8 — a tenant with write access to the spec
    // TOML slipping a newline into `id` to inject a new key into
    // the generated systemd unit.
    #[test]
    fn test_newline_in_id_is_rejected_with_threat() {
        let mut spec = clean_spec();
        spec.id = "foo\nbar".into();
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r
            .threats
            .contains(&Threat::NewlineInIdentifier { field: "id" }));
        assert_eq!(r.severity, Severity::High);
        assert!(r.reason.as_ref().unwrap().contains("newline"));
    }

    // Catches: issue #8 — same injection class but via the
    // description field, which systemd renders verbatim into
    // `Description=…`.
    #[test]
    fn test_newline_in_description_is_rejected() {
        let mut spec = clean_spec();
        spec.description = "line1\nExecStart=/bin/evil".into();
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.contains(&Threat::NewlineInIdentifier {
            field: "description",
        }));
    }

    // Catches: a control byte (bell, backspace) in the id that
    // wouldn't splice lines but would render a garbled unit /
    // confuse log scrapers.
    #[test]
    fn test_control_char_in_id_is_rejected() {
        let mut spec = clean_spec();
        spec.id = "foo\x07bar".into();
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.contains(&Threat::ControlCharInField {
            field: "id",
            byte: 0x07,
        }));
    }

    // Catches: an over-broad control-char reject list blocking
    // tab. Tab is legitimate whitespace in description text.
    #[test]
    fn test_tab_in_description_is_allowed() {
        let mut spec = clean_spec();
        spec.description = "col1\tcol2".into();
        let r = validate_image_spec(&spec);
        assert!(r.allowed, "tab must pass validation, got {r:?}");
    }

    // Catches: env-key injection. `"KEY WITH SPACE"` and
    // `"123BAD"` both break the POSIX grammar that `/etc/xkvm.conf`
    // parsers assume.
    #[test]
    fn test_non_posix_env_key_is_rejected() {
        for bad in ["123BAD", "KEY WITH SPACE", "", "KEY=VALUE"] {
            let mut spec = clean_spec();
            spec.env.insert(bad.into(), "v".into());
            let r = validate_image_spec(&spec);
            assert!(!r.allowed, "expected rejection for key {bad:?}");
            assert!(r.threats.iter().any(|t| matches!(
                t,
                Threat::NonPosixEnvKey { key } if key == bad
            )));
        }
    }

    // Catches: an over-strict POSIX check rejecting legal keys.
    #[test]
    fn test_posix_env_key_is_allowed() {
        let mut spec = clean_spec();
        spec.env.insert("MY_VAR_1".into(), "value".into());
        spec.env.insert("_under".into(), "value".into());
        let r = validate_image_spec(&spec);
        assert!(r.allowed, "clean env keys must pass, got {r:?}");
    }

    // Catches: audit follow-up #1. Key-side POSIX grammar alone is
    // insufficient because the downstream writer may emit values
    // verbatim into `/etc/xkvm.conf` — `value="legit\nKEY2=override"`
    // then splices a second KEY line into the guest's env. Closing
    // the surface at the producer boundary.
    #[test]
    fn test_newline_in_env_value_is_rejected() {
        let mut spec = clean_spec();
        spec.env.insert("KEY".into(), "legit\nKEY2=override".into());
        let r = validate_image_spec(&spec);
        assert!(!r.allowed, "newline in env value must be rejected");
        assert!(
            r.threats.iter().any(|t| matches!(
                t,
                Threat::ControlCharInField { field: "env.value", byte: b'\n' }
            )),
            "expected ControlCharInField on env.value with byte 0x0a, got {:?}",
            r.threats
        );
    }

    // Catches: the same gap for other C0 bytes (null, form feed,
    // vertical tab, …) — not just newline. The forbidden-byte set
    // is the same one the description / id checks use; this test
    // pins that env.value shares the set rather than a narrower one.
    #[test]
    fn test_null_byte_in_env_value_is_rejected() {
        let mut spec = clean_spec();
        spec.env.insert("KEY".into(), "bytes-before\0bytes-after".into());
        let r = validate_image_spec(&spec);
        assert!(!r.allowed, "null byte in env value must be rejected");
        assert!(r.threats.iter().any(|t| matches!(
            t,
            Threat::ControlCharInField { field: "env.value", byte: 0 }
        )));
    }

    // Catches: uppercase or hyphen-terminated annotation keys
    // that OCI registries reject at manifest submit time — we'd
    // rather fail at build.
    #[test]
    fn test_invalid_oci_annotation_key_is_rejected() {
        for bad in [
            "UPPERCASE",
            "hyphen-terminated-",
            "-hyphen-start",
            "double..dot",
            "",
        ] {
            let mut spec = clean_spec();
            spec.labels.insert(bad.into(), "v".into());
            let r = validate_image_spec(&spec);
            assert!(
                !r.allowed,
                "expected rejection for annotation key {bad:?}"
            );
            assert!(r.threats.iter().any(|t| matches!(
                t,
                Threat::InvalidAnnotationKey { key } if key == bad
            )));
        }
    }

    // Catches: the OCI grammar being narrowed too far and rejecting
    // the canonical reverse-DNS keys the image-spec blesses.
    #[test]
    fn test_valid_oci_annotation_key_is_allowed() {
        let mut spec = clean_spec();
        spec.labels
            .insert("org.opencontainers.image.authors".into(), "me".into());
        spec.labels
            .insert("org.opencontainers.image.version".into(), "1.0".into());
        spec.labels.insert("a".into(), "single-char".into());
        let r = validate_image_spec(&spec);
        assert!(r.allowed, "reverse-DNS keys must pass, got {r:?}");
    }

    // Catches: a null byte in argv silently truncating the
    // entrypoint when the kernel exec's it.
    #[test]
    fn test_null_byte_in_entrypoint_is_rejected() {
        let mut spec = clean_spec();
        spec.entrypoint = vec!["cmd\0".into()];
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.contains(&Threat::NullByteInEntrypoint));
        assert_eq!(r.severity, Severity::High);
    }

    // Catches: a newline in `kernel_cmdline` surviving through
    // `/proc/cmdline` and fooling whoever reads it.
    #[test]
    fn test_newline_in_kernel_cmdline_is_rejected() {
        let mut spec = clean_spec();
        spec.kernel_cmdline = Some("console=ttyS0\nextra=evil".into());
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.contains(&Threat::NewlineInIdentifier {
            field: "kernel_cmdline",
        }));
    }

    // Issue #42: relative `..` in a base path is allowed by design.
    // ImageSpec is an operator-authored build-time artifact — relative
    // paths to a shared `downloads/` dir are a legitimate pattern for
    // shippable reference specs (e.g. `main/examples/llmboot.spec.toml`
    // reaching `<repo>/downloads/rootfs-alpine.ext4`). This test pins
    // that behaviour so a future over-cautious tightening can't silently
    // break the reference-spec pattern.
    #[test]
    fn test_parent_dir_in_relative_base_path_is_allowed() {
        let mut spec = clean_spec();
        spec.base = BaseRef::LocalRootfs {
            path: PathBuf::from("../../downloads/rootfs-alpine.ext4"),
        };
        let r = validate_image_spec(&spec);
        assert!(
            r.allowed,
            "relative base path with `..` must pass (issue #42); got {r:?}"
        );
    }

    // Catches: an over-zealous path check flagging absolute paths
    // that are the operator's filesystem responsibility.
    #[test]
    fn test_absolute_base_path_is_allowed() {
        let mut spec = clean_spec();
        spec.base = BaseRef::LocalRootfs {
            path: PathBuf::from("/abs/path/rootfs.ext4"),
        };
        let r = validate_image_spec(&spec);
        assert!(r.allowed, "absolute path must pass, got {r:?}");
    }

    // Catches: the happy path regressing — a clean spec being
    // rejected by an overzealous new check.
    #[test]
    fn test_clean_spec_returns_allowed_none_severity() {
        let r = validate_image_spec(&clean_spec());
        assert!(r.allowed);
        assert_eq!(r.severity, Severity::None);
        assert!(r.threats.is_empty());
        assert!(r.reason.is_none());
    }

    // ── Length bounds (audit follow-up #2) ──────────────────────

    // Catches: the cap constants being silently widened (or a
    // caller bypassing the helper). Pinning the exact numbers
    // forces anyone raising a cap to read a test and explain why.
    #[test]
    fn test_length_caps_pin_exact_byte_values() {
        assert_eq!(MAX_ID_BYTES, 256);
        assert_eq!(MAX_DESCRIPTION_BYTES, 4096);
        assert_eq!(MAX_KERNEL_CMDLINE_BYTES, 2048);
        assert_eq!(MAX_ENV_VALUE_BYTES, 4096);
        assert_eq!(MAX_LABEL_VALUE_BYTES, 4096);
    }

    // Catches: id length bound not firing. Oversized ids would
    // otherwise land in config.json + systemd Description + OCI
    // manifest tag-equivalent fields and get rejected by
    // downstream emitters with opaque errors.
    #[test]
    fn test_id_over_max_bytes_is_rejected() {
        let mut spec = clean_spec();
        spec.id = "a".repeat(MAX_ID_BYTES + 1);
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(
            r.threats.iter().any(|t| matches!(
                t,
                Threat::TooLong { field: "id", actual, max }
                    if *actual == MAX_ID_BYTES + 1 && *max == MAX_ID_BYTES
            )),
            "expected TooLong on id, got {:?}",
            r.threats
        );
    }

    // Catches: off-by-one — a value exactly at the cap must pass.
    #[test]
    fn test_id_at_exact_max_bytes_is_allowed() {
        let mut spec = clean_spec();
        spec.id = "a".repeat(MAX_ID_BYTES);
        let r = validate_image_spec(&spec);
        assert!(r.allowed, "id at cap must pass, got {r:?}");
    }

    #[test]
    fn test_description_over_max_bytes_is_rejected() {
        let mut spec = clean_spec();
        spec.description = "d".repeat(MAX_DESCRIPTION_BYTES + 1);
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.iter().any(|t| matches!(
            t,
            Threat::TooLong { field: "description", .. }
        )));
    }

    // Catches: kernel_cmdline cap not firing. Kernel silently
    // truncates over-long command lines (`COMMAND_LINE_SIZE` on
    // x86_64 is 2048); we'd rather fail at build than boot a VM
    // with truncated boot args.
    #[test]
    fn test_kernel_cmdline_over_max_bytes_is_rejected() {
        let mut spec = clean_spec();
        spec.kernel_cmdline = Some("x".repeat(MAX_KERNEL_CMDLINE_BYTES + 1));
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.iter().any(|t| matches!(
            t,
            Threat::TooLong { field: "kernel_cmdline", .. }
        )));
    }

    #[test]
    fn test_env_value_over_max_bytes_is_rejected() {
        let mut spec = clean_spec();
        spec.env.insert("KEY".into(), "v".repeat(MAX_ENV_VALUE_BYTES + 1));
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.iter().any(|t| matches!(
            t,
            Threat::TooLong { field: "env.value", .. }
        )));
    }

    #[test]
    fn test_label_value_over_max_bytes_is_rejected() {
        let mut spec = clean_spec();
        spec.labels.insert(
            "org.test.key".into(),
            "v".repeat(MAX_LABEL_VALUE_BYTES + 1),
        );
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.iter().any(|t| matches!(
            t,
            Threat::TooLong { field: "labels.value", .. }
        )));
    }

    // Catches: TooLong being miscategorised as High severity. It's
    // a formatting / DoS-adjacent issue, not a structured-boundary
    // escape — Low is the correct class.
    #[test]
    fn test_too_long_is_low_severity() {
        let mut spec = clean_spec();
        spec.id = "a".repeat(MAX_ID_BYTES + 1);
        let r = validate_image_spec(&spec);
        assert_eq!(r.severity, Severity::Low);
    }

    // Catches: whitespace in a node tag silently surviving and
    // breaking Fleet's scheduler string match.
    #[test]
    fn test_whitespace_in_node_tag_is_rejected() {
        let mut spec = clean_spec();
        spec.node_tags = vec!["has space".into()];
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.iter().any(|t| matches!(
            t,
            Threat::ControlCharInField { field, .. } if *field == "node_tags[]"
        )));
    }

    // Catches: control chars in a label value slipping through
    // into the rendered JSON config manifest.
    #[test]
    fn test_control_char_in_label_value_is_rejected() {
        let mut spec = clean_spec();
        spec.labels
            .insert("org.example.note".into(), "line1\x01line2".into());
        let r = validate_image_spec(&spec);
        assert!(!r.allowed);
        assert!(r.threats.iter().any(|t| matches!(
            t,
            Threat::ControlCharInField { field, byte: 0x01 } if *field == "labels.value"
        )));
    }
}
