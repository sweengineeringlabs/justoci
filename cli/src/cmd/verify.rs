//! `ocimage verify <ref> [--policy <policy.toml>]`.
//!
//! v0 contract: `<ref>` is a path to a local OCI image-layout dir.
//! Registry-pull is v0.2 — until then the operator pulls into a
//! local layout (`oras pull` or `crane export`) and verifies that.
//!
//! Returns a [`VerifyReport`] on success. The CLI layer prints the
//! pillar verdicts (table) and exits 0 if no policy was supplied
//! and no pillar was Found-but-Failed; otherwise the typed
//! `VerifyError` propagates to exit 5.

use std::path::Path;

use crate::error::CliError;
use crate::policy::Policy;
use crate::verify_engine::{verify, RealCosignVerifyInvoker, VerifyReport};

/// Run the verify subcommand. Production path uses
/// [`RealCosignVerifyInvoker`]; tests can swap in a stub via the
/// `verify_engine::verify` entry point directly.
pub fn run(
    image_dir: &Path,
    policy_path: Option<&Path>,
) -> Result<VerifyReport, CliError> {
    let policy: Option<Policy> = match policy_path {
        Some(p) => Some(Policy::load(p)?),
        None => None,
    };
    let invoker = RealCosignVerifyInvoker::new();
    let report = verify(image_dir, policy.as_ref(), &invoker)?;
    Ok(report)
}
