//! Registry reference parser.
//!
//! Accepts the canonical OCI Distribution reference forms used by
//! `ocimage verify <ref>` once the local-path branch has already
//! ruled out a directory:
//!
//! - `host/repo:tag`            (`ghcr.io/acme/img:v1`)
//! - `host:port/repo:tag`       (`localhost:5000/acme/img:0.1.0`)
//! - `host/repo@sha256:<hex>`   (`registry.io/acme/img@sha256:abc…`)
//! - `host:port/repo@sha256:<hex>`
//!
//! Repository segments may contain `/` (e.g. `acme/team/img`); the
//! parser walks from the right to extract the tag/digest then takes
//! the first `/` after the host[:port] as the host/repo split.
//!
//! The grammar is deliberately strict: ambiguous inputs (no `/`,
//! empty repo, etc.) fail with a typed [`RegistryPullError::MalformedRef`]
//! before any network I/O so an operator typo never reaches the wire.

use super::error::RegistryPullError;

/// What the user pinned in the ref. Either a mutable tag pointer
/// (registry-side mapping → manifest digest) or a content-addressed
/// digest (no indirection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefTarget {
    /// `:<tag>` form. The pull layer issues
    /// `GET /v2/<repo>/manifests/<tag>` and reads the manifest digest
    /// from the `Docker-Content-Digest` header (or computes it from
    /// the body bytes if missing — they MUST agree).
    Tag(String),
    /// `@sha256:<hex>` form. The pull layer issues
    /// `GET /v2/<repo>/manifests/<digest>` and verifies the body
    /// hashes to the same digest.
    Digest(String),
}

/// One parsed registry reference, broken into the three coordinates
/// every wire call needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRef {
    /// Host and optional port, no scheme. `ghcr.io` or
    /// `localhost:5000`.
    pub host: String,
    /// Repository, including any nested namespace. `acme/team/img`.
    pub repository: String,
    /// Tag or digest target.
    pub target: RefTarget,
    /// Original input string. Carried for error context so a typed
    /// error can include exactly what the operator typed without
    /// the parser stitching pieces back together.
    pub raw: String,
}

impl RegistryRef {
    /// The reference fragment used to address the manifest endpoint.
    /// Tag form returns the tag; digest form returns the digest.
    pub fn manifest_reference(&self) -> &str {
        match &self.target {
            RefTarget::Tag(t) => t,
            RefTarget::Digest(d) => d,
        }
    }
}

/// Parse a registry reference. The parser is strict — every defect
/// surfaces as [`RegistryPullError::MalformedRef`] with a `reason`
/// string the operator can act on without re-reading source.
///
/// Detection rule (callers): if the input is an existing path on
/// disk, treat as a local OCI layout — do NOT call this parser.
/// Otherwise try this; if it errors, the caller surfaces the error
/// as a typed CLI failure instead of silently routing to the
/// network.
pub fn parse_registry_ref(raw: &str) -> Result<RegistryRef, RegistryPullError> {
    if raw.is_empty() {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: "empty reference".to_string(),
        });
    }
    if raw.contains(' ') {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: "whitespace in reference".to_string(),
        });
    }
    // Reject schemes — this parser owns the bare `host/repo:tag`
    // grammar; consumers like the CLI strip the path-vs-ref decision
    // upstream.
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: "scheme prefix is not part of an OCI reference".to_string(),
        });
    }

    // Split off the digest first if present — it has the highest
    // priority because `@` cannot legally appear elsewhere.
    let (head, target) = match raw.rsplit_once('@') {
        Some((head, digest)) => {
            validate_digest_format(digest, raw)?;
            (head, RefTarget::Digest(digest.to_string()))
        }
        None => {
            // Pure tag form. The tag is what comes after the LAST `:`
            // — but the LAST `:` could also be the host port separator
            // in `host:port/repo`. Rule: a `:` is a tag separator only
            // if it appears AFTER the FIRST `/`. If the only `:` in
            // the string is in the host part (no `/` after it), there
            // is no tag and the ref is malformed.
            let first_slash = raw.find('/').ok_or_else(|| RegistryPullError::MalformedRef {
                got: raw.to_string(),
                reason: "no '/' separator — a ref must be host[:port]/repo[:tag|@digest]"
                    .to_string(),
            })?;
            let after_slash = &raw[first_slash..];
            let last_colon_after_slash = after_slash.rfind(':');
            match last_colon_after_slash {
                Some(rel_idx) => {
                    let abs_idx = first_slash + rel_idx;
                    let tag = &raw[abs_idx + 1..];
                    if tag.is_empty() {
                        return Err(RegistryPullError::MalformedRef {
                            got: raw.to_string(),
                            reason: "empty tag after ':'".to_string(),
                        });
                    }
                    // Tags: alphanumerics + `_.-`, max 128 chars per
                    // OCI Distribution Spec §2.
                    validate_tag_format(tag, raw)?;
                    (&raw[..abs_idx], RefTarget::Tag(tag.to_string()))
                }
                None => {
                    return Err(RegistryPullError::MalformedRef {
                        got: raw.to_string(),
                        reason: "missing tag — expected host[:port]/repo:tag or @sha256:<hex>"
                            .to_string(),
                    });
                }
            }
        }
    };

    // `head` is now `host[:port]/repo[/sub-repo...]`.
    // Split into host vs repo on the FIRST `/`.
    let first_slash = head.find('/').ok_or_else(|| RegistryPullError::MalformedRef {
        got: raw.to_string(),
        reason: "missing '/' between host and repository".to_string(),
    })?;
    let host = &head[..first_slash];
    let repository = &head[first_slash + 1..];

    if host.is_empty() {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: "empty host".to_string(),
        });
    }
    if repository.is_empty() {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: "empty repository".to_string(),
        });
    }
    validate_host_format(host, raw)?;
    validate_repository_format(repository, raw)?;

    Ok(RegistryRef {
        host: host.to_string(),
        repository: repository.to_string(),
        target,
        raw: raw.to_string(),
    })
}

/// Tag character grammar: `[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}` per
/// OCI Distribution Spec v1.1 §2 ("Pulling manifests"). We don't
/// enforce the leading-char restriction strictly (some real-world
/// registries accept `.`) but we do enforce length and allowed-set.
fn validate_tag_format(tag: &str, raw: &str) -> Result<(), RegistryPullError> {
    const MAX_TAG_LEN: usize = 128;
    if tag.len() > MAX_TAG_LEN {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: format!("tag exceeds {MAX_TAG_LEN} chars"),
        });
    }
    for c in tag.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-') {
            return Err(RegistryPullError::MalformedRef {
                got: raw.to_string(),
                reason: format!("tag contains illegal character {c:?}"),
            });
        }
    }
    Ok(())
}

/// `sha256:<64-lowercase-hex>` — the only digest algorithm v0
/// supports across the build / publish / verify surface.
fn validate_digest_format(digest: &str, raw: &str) -> Result<(), RegistryPullError> {
    let (algo, hex) = digest.split_once(':').ok_or_else(|| RegistryPullError::MalformedRef {
        got: raw.to_string(),
        reason: "digest missing ':' separator (expected sha256:<hex>)".to_string(),
    })?;
    if algo != "sha256" {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: format!("unsupported digest algorithm {algo:?}; only sha256 is supported"),
        });
    }
    if hex.len() != 64 {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: format!("sha256 hex must be 64 chars, got {}", hex.len()),
        });
    }
    if !hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: "sha256 hex must be lowercase 0-9a-f".to_string(),
        });
    }
    Ok(())
}

/// Host: ASCII letters / digits / `-` / `.` / `:` (port). We accept
/// IPv4 dotted-quads + DNS names; bracketed IPv6 isn't in v0 scope
/// (the OCI ref grammar permits it but justoci ships against
/// `host:port`-style references for v0).
fn validate_host_format(host: &str, raw: &str) -> Result<(), RegistryPullError> {
    if host.starts_with(':') || host.ends_with(':') {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: format!("malformed host {host:?} (stray ':')"),
        });
    }
    for c in host.chars() {
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':') {
            return Err(RegistryPullError::MalformedRef {
                got: raw.to_string(),
                reason: format!("host contains illegal character {c:?}"),
            });
        }
    }
    // A registry host MUST contain a `.` (DNS name) or a `:` (port)
    // — bare names like `myregistry` are the docker-hub legacy form
    // we don't support in v0.
    if !host.contains('.') && !host.contains(':') {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: format!(
                "host {host:?} is not a registry — expected `<dns>` or `<host>:<port>` \
                 (Docker Hub default-host shorthand isn't supported in v0)"
            ),
        });
    }
    Ok(())
}

/// Repository per OCI Distribution Spec v1.1 §2: lowercase alnum,
/// `_.-/` separators, max 256 chars.
fn validate_repository_format(repo: &str, raw: &str) -> Result<(), RegistryPullError> {
    const MAX_REPO_LEN: usize = 256;
    if repo.len() > MAX_REPO_LEN {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: format!("repository exceeds {MAX_REPO_LEN} chars"),
        });
    }
    if repo.starts_with('/') || repo.ends_with('/') {
        return Err(RegistryPullError::MalformedRef {
            got: raw.to_string(),
            reason: "repository cannot start or end with '/'".to_string(),
        });
    }
    for c in repo.chars() {
        if !(c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '_'
            || c == '.'
            || c == '-'
            || c == '/')
        {
            return Err(RegistryPullError::MalformedRef {
                got: raw.to_string(),
                reason: format!("repository contains illegal character {c:?}"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: parser silently accepting an empty input — would
    // forward an empty host to reqwest, hitting `https:///v2/...`
    // and surfacing a confusing connection error instead of the
    // operator's actual bug.
    #[test]
    fn test_parse_registry_ref_empty_input_rejected() {
        let err = parse_registry_ref("").unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: parser accepting `host:port` without a repo. The
    // pull layer would build `GET /v2//manifests/...` and the
    // registry would 400, leaving the operator chasing a
    // confusing 4xx instead of "you forgot the repo".
    #[test]
    fn test_parse_registry_ref_host_only_rejected() {
        let err = parse_registry_ref("ghcr.io").unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("'/'"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: a parser that uses `splitn(2, ':')` for the tag
    // split — would slice `localhost:5000/foo:tag` into
    // (`localhost`, `5000/foo:tag`) and leave the repo half
    // containing a `:`. Last-colon-after-first-slash is the
    // correct rule.
    #[test]
    fn test_parse_registry_ref_localhost_with_port_and_tag() {
        let r = parse_registry_ref("localhost:5000/acme/img:0.1.0").unwrap();
        assert_eq!(r.host, "localhost:5000");
        assert_eq!(r.repository, "acme/img");
        assert_eq!(r.target, RefTarget::Tag("0.1.0".into()));
    }

    // Catches: parser that drops nested-namespace `/` in repos —
    // `ghcr.io/team/sub/img:v1` is a legit reference shape that
    // must round-trip its repository verbatim.
    #[test]
    fn test_parse_registry_ref_nested_repo_with_tag() {
        let r = parse_registry_ref("ghcr.io/team/sub/img:v1").unwrap();
        assert_eq!(r.host, "ghcr.io");
        assert_eq!(r.repository, "team/sub/img");
        assert_eq!(r.target, RefTarget::Tag("v1".into()));
    }

    // Catches: parser that doesn't switch on `@` for digest form.
    // Tag forms with `@` in them aren't real; the digest form must
    // produce a Digest target so the pull layer addresses
    // `/manifests/sha256:...` instead of `/manifests/<tag>`.
    #[test]
    fn test_parse_registry_ref_digest_form() {
        let hex = "a".repeat(64);
        let raw = format!("registry.io/foo@sha256:{hex}");
        let r = parse_registry_ref(&raw).unwrap();
        assert_eq!(r.host, "registry.io");
        assert_eq!(r.repository, "foo");
        assert_eq!(r.target, RefTarget::Digest(format!("sha256:{hex}")));
    }

    // Catches: parser accepting non-hex characters in the digest
    // — would silently address a wrong blob path on disk and the
    // tempdir layout assembly would later fail with a confusing
    // "blob not found" error far from the actual cause.
    #[test]
    fn test_parse_registry_ref_digest_with_non_hex_rejected() {
        let raw = format!("registry.io/foo@sha256:{}", "z".repeat(64));
        let err = parse_registry_ref(&raw).unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("0-9a-f") || reason.contains("hex"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: parser accepting an unsupported digest algorithm.
    // The on-disk blob layout is `blobs/sha256/<hex>`; sha512 etc.
    // would later fail at layout-assembly time, far from the
    // operator's real fix point.
    #[test]
    fn test_parse_registry_ref_non_sha256_digest_rejected() {
        let raw = format!("registry.io/foo@sha512:{}", "a".repeat(128));
        let err = parse_registry_ref(&raw).unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("sha256"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: parser accepting a missing tag (`registry.io/foo`
    // with no `:tag` and no `@digest`). Without this, the pull
    // would address `/manifests/foo` — wrong endpoint shape — and
    // the registry would 404 confusingly.
    #[test]
    fn test_parse_registry_ref_missing_tag_rejected() {
        let err = parse_registry_ref("registry.io/foo").unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("tag"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: parser accepting bare hostnames without a dot or
    // port (`docker.io` shorthand). v0 doesn't support the Docker
    // Hub default-host fallback; explicit hosts only.
    #[test]
    fn test_parse_registry_ref_bare_hostname_rejected() {
        let err = parse_registry_ref("myreg/foo:v1").unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("registry") || reason.contains("DNS") || reason.contains("dns"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: parser accepting an unsupported tag character. Tags
    // like `v1/test` would let nested-path injection sneak through
    // into the URL, hitting unintended endpoints.
    #[test]
    fn test_parse_registry_ref_tag_with_illegal_char_rejected() {
        let err = parse_registry_ref("ghcr.io/foo:v1/test").unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("illegal") || reason.contains("tag"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: parser accepting a URL scheme. The CLI surface uses
    // bare references; an `https://` prefix is the operator
    // confusing the ref grammar with a URL — fail locally with a
    // clear message.
    #[test]
    fn test_parse_registry_ref_scheme_prefix_rejected() {
        let err = parse_registry_ref("https://ghcr.io/foo:v1").unwrap_err();
        match err {
            RegistryPullError::MalformedRef { reason, .. } => {
                assert!(reason.contains("scheme"));
            }
            other => panic!("expected MalformedRef, got {other:?}"),
        }
    }

    // Catches: manifest_reference returning the wrong half for
    // digest refs — would build the GET URL with the tag-style
    // path (`/manifests/<digest-string-but-meant-as-tag>`) and
    // 404.
    #[test]
    fn test_manifest_reference_digest_returns_full_digest() {
        let hex = "b".repeat(64);
        let raw = format!("registry.io/foo@sha256:{hex}");
        let r = parse_registry_ref(&raw).unwrap();
        assert_eq!(r.manifest_reference(), format!("sha256:{hex}"));
    }
}
