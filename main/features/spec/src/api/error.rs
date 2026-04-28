use thiserror::Error;

/// Errors raised while loading and validating a justoci spec.
///
/// Every variant carries enough context for an operator to fix the
/// spec without re-running the build: which field, which value,
/// what was expected. `TomlSyntax` and `TomlSchema` thread through
/// the underlying `toml` crate's positional info so a typo gets
/// reported at the right line.
#[derive(Debug, Error)]
pub enum SpecError {
    /// `spec_version` is missing or holds a value this parser doesn't
    /// know about. v0 only accepts `"0"`. Future versions ship parsers
    /// that accept their own value plus, optionally, older values via
    /// a compatibility shim.
    #[error("unsupported spec_version '{got}' (this build supports {supported:?})")]
    UnsupportedSpecVersion {
        got: String,
        supported: &'static [&'static str],
    },

    /// `id` doesn't match `<name>:<tag>` where name is lowercase
    /// `[a-z0-9._-]` starting with `[a-z0-9]`, and tag is
    /// `[a-zA-Z0-9._-]`.
    #[error("artifact id '{got}' is malformed: {reason}")]
    MalformedId { got: String, reason: &'static str },

    /// `kind` holds a string that isn't one of the known kinds.
    #[error("unknown kind '{got}' (expected one of: oci_artifact, vm_image, raw_image)")]
    UnknownKind { got: String },

    /// The number of layers doesn't match what the kind requires.
    /// `vm_image` requires exactly 3 (kernel/initrd/rootfs);
    /// `raw_image` requires exactly 1; `oci_artifact` requires ≥1.
    #[error("kind '{kind}' requires {expected} layers, got {actual}")]
    WrongLayerCount {
        kind: &'static str,
        expected: &'static str,
        actual: usize,
    },

    /// `vm_image` layer ordering violation. Layers must appear in
    /// boot order: layer 0 is the kernel, layer 1 the initrd,
    /// layer 2 the rootfs. The check is performed against the
    /// `media_type` substring (`"kernel"`, `"initrd"`, `"rootfs"`).
    #[error(
        "vm_image layer #{position} expected media_type containing '{expected_marker}', got '{got_media_type}'"
    )]
    WrongLayerOrder {
        position: usize,
        expected_marker: &'static str,
        got_media_type: String,
    },

    /// A layer declared both `source` and a `[[layers.files]]` block,
    /// or neither. Exactly one source mode per layer.
    #[error("layer #{position} must declare exactly one of `source = \"...\"` or `[[layers.files]]`, got: {detail}")]
    LayerSourceConflict {
        position: usize,
        detail: &'static str,
    },

    /// A layer's `source` path doesn't exist or isn't readable.
    /// Surfaced at spec-load time rather than build time so the
    /// operator gets one clean error instead of a half-built artifact.
    #[error("layer #{position} source path '{path}' is not readable: {detail}")]
    UnreadableSource {
        position: usize,
        path: String,
        detail: String,
    },

    /// A `[[layers.files]]` block has zero entries. An empty layer
    /// is never useful and almost always a copy-paste mistake.
    #[error("layer #{position} has empty [[layers.files]] block — drop the layer or add entries")]
    EmptyFilesBlock { position: usize },

    /// A media-type string doesn't satisfy the `type "/" subtype
    /// ["+" suffix]` grammar.
    #[error("layer #{position} media_type '{got}' violates OCI grammar (expected `type/subtype[+suffix]`)")]
    MalformedMediaType { position: usize, got: String },

    /// Unknown `compression` value.
    #[error("layer #{position} compression '{got}' is not one of: none, gzip, zstd")]
    UnknownCompression { position: usize, got: String },

    /// SLSA level outside `{0, 1, 2, 3, 4}`.
    #[error("attestation.slsa.level {got} is out of range (allowed: 0..=4)")]
    SlsaLevelOutOfRange { got: i64 },

    /// SBOM format string isn't recognised.
    #[error("attestation.sbom.format '{got}' is not one of: cyclonedx, spdx, off")]
    UnknownSbomFormat { got: String },

    /// SBOM scope string isn't recognised.
    #[error("attestation.sbom.scope '{got}' is not one of: layers, sources, both")]
    UnknownSbomScope { got: String },

    /// Sign kind string isn't recognised.
    #[error("attestation.sign.kind '{got}' is not one of: cosign-keyless, cosign-key, off")]
    UnknownSignKind { got: String },

    /// Cosign-key mode without an `identity` (path).
    #[error("sign.kind = 'cosign-key' requires sign.identity to point at a key file")]
    MissingSigningKeyPath,

    /// Reserved OCI annotation key carries a value that violates the
    /// OCI image-spec's expectations (e.g. `created` must be RFC3339).
    #[error("annotation key '{key}' carries an invalid value: {detail}")]
    InvalidReservedAnnotation { key: String, detail: String },

    /// TOML deserialisation failed (syntax or type mismatch). Wraps
    /// the underlying `toml::de::Error` which already carries the
    /// span/line info.
    #[error("toml parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// IO failure while reading the spec file from disk.
    #[error("failed to read spec at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
