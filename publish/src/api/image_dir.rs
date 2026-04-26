//! `ImageDir` — opaque newtype around a validated OCI image directory.
//!
//! `ImageDir::open(path)` is the input boundary for `publish`. By the
//! time it returns `Ok`, every one of the following has been checked:
//!
//!   * `<path>/oci-layout` exists, is valid JSON, and reports
//!     `imageLayoutVersion = "1.0.0"`.
//!   * `<path>/index.json` exists and parses as an OCI image index.
//!   * The index contains exactly one primary-artifact manifest
//!     descriptor (a `subject`-less manifest), and zero or more
//!     referrer manifests (manifests with a `subject` field pointing
//!     at the primary).
//!   * The primary manifest blob exists at
//!     `<path>/blobs/sha256/<hex>` and parses.
//!   * The config descriptor named by the primary manifest has its
//!     blob present.
//!   * Every layer descriptor has its blob present.
//!   * Every referrer manifest blob is present and references the
//!     primary as its `subject`.
//!
//! Anything else is a [`PublishError::MalformedImageDir`] with a
//! `detail` string naming the specific defect — the producer (build,
//! attest) is at fault. The publish layer trusts what survived this
//! check and never re-validates downstream.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::api::error::PublishError;

/// Sentinel: this is the OCI image-layout version we accept. The
/// OCI Image Layout spec v1.0 is the only ratified version; future
/// `1.x` bumps would require coordinated reader updates so we
/// reject them rather than silently misinterpret.
pub const SUPPORTED_LAYOUT_VERSION: &str = "1.0.0";

/// File name of the OCI image-layout marker. Constant so a typo in
/// one place doesn't mismatch a typo in another.
pub const OCI_LAYOUT_FILE: &str = "oci-layout";

/// File name of the OCI image index. ditto.
pub const INDEX_JSON_FILE: &str = "index.json";

/// OCI manifest media type, v1. We only accept this — the `+json`
/// suffix differentiates it from a layer media type.
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// Errors raised by [`ImageDir::open`]. Exposed (not just
/// internal) so library callers can match on the cause without
/// stringly-typed comparisons. Folded into
/// [`PublishError::MalformedImageDir`] for the publish entry point;
/// a user of this module standalone can keep the structured form.
#[derive(Debug, thiserror::Error)]
pub enum ImageDirError {
    #[error("{file} not found at {path:?}")]
    MissingFile { file: &'static str, path: PathBuf },

    #[error("{file} at {path:?}: malformed JSON: {detail}")]
    MalformedJson {
        file: &'static str,
        path: PathBuf,
        detail: String,
    },

    #[error(
        "oci-layout at {path:?} reports imageLayoutVersion {found:?}, only {expected:?} is supported"
    )]
    UnsupportedLayoutVersion {
        path: PathBuf,
        found: String,
        expected: &'static str,
    },

    #[error(
        "index.json at {path:?} contains no primary artifact manifest \
         (every manifest has a `subject` — there's no top-level artifact to publish)"
    )]
    NoPrimaryManifest { path: PathBuf },

    #[error(
        "index.json at {path:?} contains {count} primary-artifact manifests; \
         publish only supports a single primary"
    )]
    MultiplePrimaryManifests { path: PathBuf, count: usize },

    #[error("blob {digest} referenced by {context} is missing under blobs/sha256/")]
    MissingBlob { digest: String, context: String },

    #[error("manifest {digest} has unsupported mediaType {found:?}")]
    UnsupportedManifestMediaType { digest: String, found: String },

    #[error("descriptor {digest} has invalid digest format: {detail}")]
    InvalidDigestFormat { digest: String, detail: String },

    #[error("i/o reading {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl From<ImageDirError> for PublishError {
    fn from(e: ImageDirError) -> Self {
        PublishError::MalformedImageDir {
            detail: format!("{e}"),
        }
    }
}

/// One descriptor inside an OCI manifest or index. Mirrors the OCI
/// Image Spec descriptor exactly so we can serialise it back out
/// when the registry sink writes a manifest's config or layer
/// references — but our reading path is the only thing that needs
/// the full struct, hence `Deserialize`.
#[derive(Debug, Clone, Deserialize)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, rename = "artifactType")]
    pub artifact_type: Option<String>,
}

/// Internal: an OCI image manifest, parsed from a blob under
/// `blobs/sha256/<hex>`. Carries `config`, `layers`, and the
/// optional `subject` that turns it into a referrer.
#[derive(Debug, Clone, Deserialize)]
struct OciImageManifest {
    #[serde(default, rename = "mediaType")]
    media_type: Option<String>,
    config: OciDescriptor,
    #[serde(default)]
    layers: Vec<OciDescriptor>,
    #[serde(default)]
    subject: Option<OciDescriptor>,
}

/// Internal: the on-disk shape of `index.json`.
#[derive(Debug, Clone, Deserialize)]
struct OciImageIndex {
    #[serde(default)]
    manifests: Vec<OciDescriptor>,
}

/// Internal: the on-disk shape of `oci-layout`.
#[derive(Debug, Clone, Deserialize)]
struct OciLayoutMarker {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

/// Public, structured view of a validated OCI image dir. Returned
/// inside the [`ImageDir`] newtype but exposed as a separate struct
/// so callers can introspect the manifest digest / referrer count
/// for logging without re-parsing JSON.
#[derive(Debug, Clone)]
pub struct ImageDescriptor {
    /// Digest of the primary manifest blob (the artifact this
    /// image dir publishes). `sha256:<hex>` form.
    pub primary_manifest_digest: String,

    /// Size of the primary manifest blob in bytes.
    pub primary_manifest_size: u64,

    /// Descriptor of the primary manifest's config blob.
    pub config: OciDescriptor,

    /// Layer descriptors in primary-manifest order.
    pub layers: Vec<OciDescriptor>,

    /// Referrer-manifest descriptors. Every entry's blob is a
    /// manifest under `blobs/sha256/` whose `subject` is the
    /// primary manifest. SLSA + SBOM + signature artifacts live
    /// here per OCI 1.1.
    pub referrer_manifests: Vec<OciDescriptor>,
}

/// Validated handle on an OCI image directory.
///
/// Construct via [`Self::open`]. The newtype is opaque so the only
/// way to reach the inside is through accessors that report
/// post-validation invariants.
#[derive(Debug, Clone)]
pub struct ImageDir {
    root: PathBuf,
    descriptor: ImageDescriptor,
    /// All blobs (referenced by the primary manifest, its config,
    /// all layers, all referrer manifests, and all referrer
    /// manifests' configs+layers). Used by the sink layer to
    /// decide what to copy / push without re-walking the image.
    /// Always includes the primary manifest digest itself.
    referenced_blobs: Vec<OciDescriptor>,
}

impl ImageDir {
    /// Validate `path` and return an `ImageDir` handle. See module
    /// docs for the validation contract.
    pub fn open(path: &Path) -> Result<Self, ImageDirError> {
        let layout_path = path.join(OCI_LAYOUT_FILE);
        if !layout_path.is_file() {
            return Err(ImageDirError::MissingFile {
                file: OCI_LAYOUT_FILE,
                path: layout_path,
            });
        }
        let layout_bytes = fs::read(&layout_path).map_err(|source| ImageDirError::Io {
            path: layout_path.clone(),
            source,
        })?;
        let layout: OciLayoutMarker =
            serde_json::from_slice(&layout_bytes).map_err(|e| ImageDirError::MalformedJson {
                file: OCI_LAYOUT_FILE,
                path: layout_path.clone(),
                detail: e.to_string(),
            })?;
        if layout.image_layout_version != SUPPORTED_LAYOUT_VERSION {
            return Err(ImageDirError::UnsupportedLayoutVersion {
                path: layout_path,
                found: layout.image_layout_version,
                expected: SUPPORTED_LAYOUT_VERSION,
            });
        }

        let index_path = path.join(INDEX_JSON_FILE);
        if !index_path.is_file() {
            return Err(ImageDirError::MissingFile {
                file: INDEX_JSON_FILE,
                path: index_path,
            });
        }
        let index_bytes = fs::read(&index_path).map_err(|source| ImageDirError::Io {
            path: index_path.clone(),
            source,
        })?;
        let index: OciImageIndex =
            serde_json::from_slice(&index_bytes).map_err(|e| ImageDirError::MalformedJson {
                file: INDEX_JSON_FILE,
                path: index_path.clone(),
                detail: e.to_string(),
            })?;

        // Walk every manifest descriptor in index.json, parse its
        // blob, and bucket into primary vs referrer based on the
        // presence of a `subject` field.
        let mut primary_candidates: Vec<(OciDescriptor, OciImageManifest)> = Vec::new();
        let mut referrers: Vec<(OciDescriptor, OciImageManifest)> = Vec::new();

        for desc in &index.manifests {
            validate_digest_format(&desc.digest)?;
            if desc.media_type != MEDIA_TYPE_OCI_MANIFEST {
                return Err(ImageDirError::UnsupportedManifestMediaType {
                    digest: desc.digest.clone(),
                    found: desc.media_type.clone(),
                });
            }
            let manifest_blob_path = blob_path_of(path, &desc.digest)?;
            if !manifest_blob_path.is_file() {
                return Err(ImageDirError::MissingBlob {
                    digest: desc.digest.clone(),
                    context: format!("manifest descriptor in {INDEX_JSON_FILE}"),
                });
            }
            let manifest_bytes =
                fs::read(&manifest_blob_path).map_err(|source| ImageDirError::Io {
                    path: manifest_blob_path.clone(),
                    source,
                })?;
            let manifest: OciImageManifest =
                serde_json::from_slice(&manifest_bytes).map_err(|e| {
                    ImageDirError::MalformedJson {
                        file: "blobs/sha256/<manifest>",
                        path: manifest_blob_path,
                        detail: e.to_string(),
                    }
                })?;
            // mediaType inside manifest, when present, must agree
            // with the descriptor's mediaType.
            if let Some(mt) = manifest.media_type.as_deref() {
                if mt != MEDIA_TYPE_OCI_MANIFEST {
                    return Err(ImageDirError::UnsupportedManifestMediaType {
                        digest: desc.digest.clone(),
                        found: mt.to_string(),
                    });
                }
            }
            if manifest.subject.is_some() {
                referrers.push((desc.clone(), manifest));
            } else {
                primary_candidates.push((desc.clone(), manifest));
            }
        }

        let (primary_desc, primary_manifest) = match primary_candidates.len() {
            0 => return Err(ImageDirError::NoPrimaryManifest { path: index_path }),
            1 => primary_candidates
                .pop()
                .expect("len() == 1 confirmed above"),
            n => {
                return Err(ImageDirError::MultiplePrimaryManifests {
                    path: index_path,
                    count: n,
                });
            }
        };

        // Validate primary's config + layer blobs are present.
        validate_descriptor_blob_present(
            path,
            &primary_manifest.config,
            "primary manifest config",
        )?;
        for (i, layer) in primary_manifest.layers.iter().enumerate() {
            validate_descriptor_blob_present(path, layer, &format!("primary manifest layer[{i}]"))?;
        }

        // Validate every referrer's `subject` digest matches the
        // primary, and that each referrer's config + layer blobs
        // are present.
        for (ref_desc, ref_manifest) in &referrers {
            let subject = ref_manifest
                .subject
                .as_ref()
                .expect("subject was the bucket discriminator");
            if subject.digest != primary_desc.digest {
                return Err(ImageDirError::MissingBlob {
                    digest: subject.digest.clone(),
                    context: format!(
                        "referrer manifest {}'s subject digest does not match the primary manifest digest {}",
                        ref_desc.digest, primary_desc.digest
                    ),
                });
            }
            validate_descriptor_blob_present(
                path,
                &ref_manifest.config,
                &format!("referrer {} config", ref_desc.digest),
            )?;
            for (i, layer) in ref_manifest.layers.iter().enumerate() {
                validate_descriptor_blob_present(
                    path,
                    layer,
                    &format!("referrer {} layer[{i}]", ref_desc.digest),
                )?;
            }
        }

        // Compute the union of all blobs the publish path must
        // copy/push. Order: layers, then config, then referrer
        // manifests + their content, then primary manifest LAST
        // (so a registry-sink walking this list naturally puts
        // the manifest at the end).
        //
        // Deduplicate by digest — a layer and a referrer can
        // legitimately share content (an empty config, e.g.).
        let mut seen: HashSet<String> = HashSet::new();
        let mut referenced: Vec<OciDescriptor> = Vec::new();
        let push =
            |desc: OciDescriptor, seen: &mut HashSet<String>, out: &mut Vec<OciDescriptor>| {
                if seen.insert(desc.digest.clone()) {
                    out.push(desc);
                }
            };
        for layer in &primary_manifest.layers {
            push(layer.clone(), &mut seen, &mut referenced);
        }
        push(primary_manifest.config.clone(), &mut seen, &mut referenced);
        for (ref_desc, ref_manifest) in &referrers {
            for layer in &ref_manifest.layers {
                push(layer.clone(), &mut seen, &mut referenced);
            }
            push(ref_manifest.config.clone(), &mut seen, &mut referenced);
            push(ref_desc.clone(), &mut seen, &mut referenced);
        }
        // Primary manifest LAST.
        push(primary_desc.clone(), &mut seen, &mut referenced);

        let referrer_manifests = referrers.into_iter().map(|(d, _)| d).collect();
        let descriptor = ImageDescriptor {
            primary_manifest_digest: primary_desc.digest.clone(),
            primary_manifest_size: primary_desc.size,
            config: primary_manifest.config,
            layers: primary_manifest.layers,
            referrer_manifests,
        };

        Ok(ImageDir {
            root: path.to_path_buf(),
            descriptor,
            referenced_blobs: referenced,
        })
    }

    /// Root directory of the image.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Validated descriptor view.
    pub fn descriptor(&self) -> &ImageDescriptor {
        &self.descriptor
    }

    /// All blobs the publish path needs to materialise at the sink,
    /// in copy order: layers + configs + referrer manifests +
    /// primary manifest LAST. The primary-manifest-last invariant
    /// is what makes the manifest the commit point.
    pub fn referenced_blobs(&self) -> &[OciDescriptor] {
        &self.referenced_blobs
    }

    /// Descriptor of the primary manifest. Convenience for the
    /// registry sink, which has to PUT it after every other blob
    /// is confirmed-present.
    pub fn primary_manifest(&self) -> OciDescriptor {
        OciDescriptor {
            media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
            digest: self.descriptor.primary_manifest_digest.clone(),
            size: self.descriptor.primary_manifest_size,
            artifact_type: None,
        }
    }

    /// Resolve a digest to a filesystem path under
    /// `<root>/blobs/sha256/<hex>`. Returns an error if the digest
    /// uses an algorithm other than `sha256` or has a malformed
    /// `algorithm:hex` shape.
    pub fn blob_path(&self, digest: &str) -> Result<PathBuf, ImageDirError> {
        blob_path_of(&self.root, digest)
    }

    /// Read the bytes of `index.json` verbatim. Used by the HTTP
    /// sink, which writes the same bytes to the destination dir
    /// as its commit point.
    pub fn read_index_bytes(&self) -> Result<Vec<u8>, ImageDirError> {
        let p = self.root.join(INDEX_JSON_FILE);
        fs::read(&p).map_err(|source| ImageDirError::Io { path: p, source })
    }

    /// Read the bytes of `oci-layout` verbatim. Same use as
    /// [`Self::read_index_bytes`] — the HTTP sink propagates this
    /// file unchanged.
    pub fn read_oci_layout_bytes(&self) -> Result<Vec<u8>, ImageDirError> {
        let p = self.root.join(OCI_LAYOUT_FILE);
        fs::read(&p).map_err(|source| ImageDirError::Io { path: p, source })
    }
}

/// Convert an OCI digest (`sha256:<hex>`) to its on-disk blob path
/// (`<root>/blobs/sha256/<hex>`). Rejects non-sha256 algorithms
/// because the OCI Image Layout spec mandates the `<algorithm>`
/// directory match the digest's algorithm.
fn blob_path_of(root: &Path, digest: &str) -> Result<PathBuf, ImageDirError> {
    let (algo, hex) = digest
        .split_once(':')
        .ok_or_else(|| ImageDirError::InvalidDigestFormat {
            digest: digest.to_string(),
            detail: "missing 'algorithm:hex' separator".into(),
        })?;
    if algo != "sha256" {
        return Err(ImageDirError::InvalidDigestFormat {
            digest: digest.to_string(),
            detail: format!("only sha256 is supported, got {algo:?}"),
        });
    }
    if hex.len() != 64 {
        return Err(ImageDirError::InvalidDigestFormat {
            digest: digest.to_string(),
            detail: format!("sha256 hex must be 64 chars, got {}", hex.len()),
        });
    }
    if !hex
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(ImageDirError::InvalidDigestFormat {
            digest: digest.to_string(),
            detail: "hex must be lowercase".into(),
        });
    }
    Ok(root.join("blobs").join(algo).join(hex))
}

fn validate_digest_format(digest: &str) -> Result<(), ImageDirError> {
    let (algo, hex) = digest
        .split_once(':')
        .ok_or_else(|| ImageDirError::InvalidDigestFormat {
            digest: digest.to_string(),
            detail: "missing 'algorithm:hex' separator".into(),
        })?;
    if algo != "sha256" {
        return Err(ImageDirError::InvalidDigestFormat {
            digest: digest.to_string(),
            detail: format!("only sha256 is supported, got {algo:?}"),
        });
    }
    if hex.len() != 64 {
        return Err(ImageDirError::InvalidDigestFormat {
            digest: digest.to_string(),
            detail: format!("sha256 hex must be 64 chars, got {}", hex.len()),
        });
    }
    Ok(())
}

fn validate_descriptor_blob_present(
    root: &Path,
    desc: &OciDescriptor,
    context: &str,
) -> Result<(), ImageDirError> {
    validate_digest_format(&desc.digest)?;
    let p = blob_path_of(root, &desc.digest)?;
    if !p.is_file() {
        return Err(ImageDirError::MissingBlob {
            digest: desc.digest.clone(),
            context: context.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: blob_path_of accepting a non-sha256 algorithm and
    // pointing the publish loop at a non-existent directory.
    #[test]
    fn test_blob_path_of_rejects_non_sha256_algorithm() {
        let r = Path::new("/x");
        let err = blob_path_of(r, "sha512:abcd").unwrap_err();
        match err {
            ImageDirError::InvalidDigestFormat { detail, .. } => {
                assert!(detail.contains("sha256"));
            }
            other => panic!("expected InvalidDigestFormat, got {other:?}"),
        }
    }

    // Catches: a digest that's missing the colon being silently
    // joined to a path verbatim — would silently address a wrong
    // file.
    #[test]
    fn test_blob_path_of_rejects_missing_separator() {
        let r = Path::new("/x");
        let err = blob_path_of(r, "abcd").unwrap_err();
        match err {
            ImageDirError::InvalidDigestFormat { detail, .. } => {
                assert!(detail.contains("separator"));
            }
            other => panic!("expected InvalidDigestFormat, got {other:?}"),
        }
    }

    // Catches: uppercase hex slipping through and addressing the
    // wrong file on case-insensitive filesystems (Windows / macOS),
    // or simply mismatching what `cas` produces.
    #[test]
    fn test_blob_path_of_rejects_uppercase_hex() {
        let r = Path::new("/x");
        let upper: String = std::iter::repeat_n('A', 64).collect();
        let err = blob_path_of(r, &format!("sha256:{upper}")).unwrap_err();
        match err {
            ImageDirError::InvalidDigestFormat { detail, .. } => {
                assert!(detail.contains("lowercase"));
            }
            other => panic!("expected InvalidDigestFormat, got {other:?}"),
        }
    }

    // Catches: a sha256 digest with the wrong hex length being
    // accepted. Producing the wrong path silently is dangerous.
    #[test]
    fn test_blob_path_of_rejects_short_hex() {
        let r = Path::new("/x");
        let err = blob_path_of(r, "sha256:deadbeef").unwrap_err();
        match err {
            ImageDirError::InvalidDigestFormat { detail, .. } => {
                assert!(detail.contains("64"));
            }
            other => panic!("expected InvalidDigestFormat, got {other:?}"),
        }
    }

    // Catches: blob_path_of computing the wrong nested path layout
    // (e.g. dropping the algorithm dir). The OCI Image Layout spec
    // mandates `blobs/<algorithm>/<hex>` — drift breaks every
    // consumer.
    #[test]
    fn test_blob_path_of_canonical_layout() {
        let r = Path::new("/x");
        let hex: String = std::iter::repeat_n('a', 64).collect();
        let p = blob_path_of(r, &format!("sha256:{hex}")).unwrap();
        assert!(
            p.ends_with(format!("blobs/sha256/{hex}"))
                || p.ends_with(format!("blobs\\sha256\\{hex}"))
        );
    }
}
