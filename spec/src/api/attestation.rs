/// `[attestation]` block. Defaults match the spec doc: SLSA L2,
/// CycloneDX SBOM scoped to `layers`, cosign-keyless signing.
///
/// `Default::default()` produces the on-by-default posture the
/// product opinion requires — callers that want overrides supply a
/// non-default value via spec parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationConfig {
    pub slsa: SlsaConfig,
    pub sbom: SbomConfig,
    pub sign: SignConfig,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        AttestationConfig {
            slsa: SlsaConfig::default(),
            sbom: SbomConfig::default(),
            sign: SignConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlsaConfig {
    pub level: SlsaLevel,
    /// `None` means "auto-derive at build time from `<git remote>@<rev>`".
    pub builder_id: Option<String>,
}

impl Default for SlsaConfig {
    fn default() -> Self {
        SlsaConfig {
            level: SlsaLevel::L2,
            builder_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlsaLevel {
    /// Off — explicit opt-out. The product position is "don't"; this
    /// variant exists for testing / dev iteration.
    Off,
    L1,
    L2,
    L3,
    L4,
}

impl SlsaLevel {
    pub fn from_int(n: i64) -> Option<Self> {
        match n {
            0 => Some(SlsaLevel::Off),
            1 => Some(SlsaLevel::L1),
            2 => Some(SlsaLevel::L2),
            3 => Some(SlsaLevel::L3),
            4 => Some(SlsaLevel::L4),
            _ => None,
        }
    }

    pub fn as_int(&self) -> i64 {
        match self {
            SlsaLevel::Off => 0,
            SlsaLevel::L1 => 1,
            SlsaLevel::L2 => 2,
            SlsaLevel::L3 => 3,
            SlsaLevel::L4 => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomConfig {
    pub format: SbomFormat,
    pub scope: SbomScope,
}

impl Default for SbomConfig {
    fn default() -> Self {
        SbomConfig {
            format: SbomFormat::CycloneDx,
            scope: SbomScope::Layers,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
    Off,
}

impl SbomFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cyclonedx" => Some(SbomFormat::CycloneDx),
            "spdx" => Some(SbomFormat::Spdx),
            "off" => Some(SbomFormat::Off),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SbomFormat::CycloneDx => "cyclonedx",
            SbomFormat::Spdx => "spdx",
            SbomFormat::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomScope {
    Layers,
    Sources,
    Both,
}

impl SbomScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "layers" => Some(SbomScope::Layers),
            "sources" => Some(SbomScope::Sources),
            "both" => Some(SbomScope::Both),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SbomScope::Layers => "layers",
            SbomScope::Sources => "sources",
            SbomScope::Both => "both",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignConfig {
    pub kind: SignKind,
    /// For `CosignKeyless`: optional OIDC identity regex.
    /// For `CosignKey`: required path to a key file.
    /// For `Off`: must be `None`.
    pub identity: Option<String>,
}

impl Default for SignConfig {
    fn default() -> Self {
        SignConfig {
            kind: SignKind::CosignKeyless,
            identity: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKind {
    CosignKeyless,
    CosignKey,
    Off,
}

impl SignKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cosign-keyless" => Some(SignKind::CosignKeyless),
            "cosign-key" => Some(SignKind::CosignKey),
            "off" => Some(SignKind::Off),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SignKind::CosignKeyless => "cosign-keyless",
            SignKind::CosignKey => "cosign-key",
            SignKind::Off => "off",
        }
    }
}
