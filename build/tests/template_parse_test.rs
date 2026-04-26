//! Guard the shipped templates against schema drift.
//!
//! Every TOML under `templates/` must parse cleanly into
//! `ImageSpec`. Templates are embedded via `include_str!` so tests
//! stay green regardless of the cwd the harness runs from.
//!
//! Phase 2f-α nuance: `packages` and `files` parse fine at the
//! TOML layer (the schema allows them). They're rejected at
//! `core::service` validation time. The dedicated test
//! `test_packages_parse_even_though_validation_rejects` below
//! keeps that distinction honest so future refactors don't
//! accidentally teach the parser to reject them and break the
//! "carry forward as typed fields, reject later" contract.

use oci_build::api::spec::{BaseRef, ImageSpec, InitMode};

const ALPINE_MINIMAL: &str = include_str!("../templates/alpine-minimal.toml");
const POSTGRES_16: &str = include_str!("../templates/postgres-16.toml");
const REDIS_7: &str = include_str!("../templates/redis-7.toml");

#[test]
fn test_alpine_minimal_parses_and_matches_shape() {
    let spec: ImageSpec = toml::from_str(ALPINE_MINIMAL)
        .expect("alpine-minimal.toml must parse into ImageSpec");

    assert_eq!(spec.id, "alpine-minimal:1.0");
    assert!(
        spec.description.contains("Alpine"),
        "description field is used by fleetctl list — must survive parse"
    );
    assert_eq!(spec.init_mode, InitMode::Xkinit);
    assert!(
        spec.entrypoint.is_empty(),
        "alpine-minimal is meant to drop to a shell; non-empty entrypoint defeats that"
    );
    assert!(matches!(spec.base, BaseRef::LocalRootfs { .. }));
    assert!(spec.node_tags.iter().any(|t| t == "linux"));
    assert!(spec.packages.is_empty(), "Phase 2f-α: packages must stay empty");
    assert!(spec.files.is_empty(), "Phase 2f-α: files must stay empty");
    assert!(spec.labels.contains_key("org.opencontainers.image.authors"));
}

#[test]
fn test_postgres_16_parses_with_entrypoint_and_env() {
    let spec: ImageSpec = toml::from_str(POSTGRES_16)
        .expect("postgres-16.toml must parse into ImageSpec");

    assert_eq!(spec.id, "postgres:16");
    assert!(
        spec.entrypoint.first().map(|s| s.as_str()) == Some("/usr/bin/pg_ctl"),
        "postgres template's first entrypoint arg must be pg_ctl; got {:?}",
        spec.entrypoint
    );
    assert!(
        spec.env.contains_key("POSTGRES_DB"),
        "postgres template must expose POSTGRES_DB — tenants override via Fleet env"
    );
    assert!(spec.env.contains_key("PGDATA"));
    assert_eq!(spec.init_mode, InitMode::Xkinit);
    assert!(matches!(spec.base, BaseRef::LocalRootfs { .. }));
}

#[test]
fn test_redis_7_parses_with_server_entrypoint() {
    let spec: ImageSpec = toml::from_str(REDIS_7)
        .expect("redis-7.toml must parse into ImageSpec");

    assert_eq!(spec.id, "redis:7");
    assert!(
        spec.entrypoint
            .first()
            .map(|s| s.as_str()) == Some("/usr/bin/redis-server"),
        "redis template's first entrypoint arg must be redis-server; got {:?}",
        spec.entrypoint
    );
    assert!(spec.env.contains_key("REDIS_MAXMEMORY"));
    assert_eq!(spec.init_mode, InitMode::Xkinit);
}

#[test]
fn test_packages_parse_even_though_validation_rejects() {
    // `packages` is a valid schema field — the TOML parser must
    // accept it. Semantic validation (2f-α: reject non-empty
    // packages until chroot-install lands) runs at core::service,
    // not here. This test guards the "carry forward as typed
    // fields, reject later" contract so a future refactor can't
    // silently start dropping the field at parse time.
    let toml_with_packages = r#"
        id = "wip:0"
        description = "WIP"
        init_mode = "xkinit"
        entrypoint = ["/bin/true"]
        packages = ["postgresql16", "redis"]

        [base]
        kind = "local_rootfs"
        path = "downloads/rootfs-alpine.ext4"

        [env]
        [labels]
    "#;
    let spec: ImageSpec = toml::from_str(toml_with_packages)
        .expect("packages field must parse — rejection is a validation concern, not a parse concern");
    assert_eq!(spec.packages, vec!["postgresql16".to_string(), "redis".to_string()]);
}

#[test]
fn test_unknown_fields_are_rejected_at_parse_time() {
    // deny_unknown_fields on ImageSpec catches typos. A tenant
    // who types `entrypoin` instead of `entrypoint` gets a clear
    // error, not silent data loss.
    let typo = r#"
        id = "typo:0"
        entrypoin = ["oops"]

        [base]
        kind = "local_rootfs"
        path = "x"

        [env]
        [labels]
    "#;
    let err = toml::from_str::<ImageSpec>(typo)
        .err()
        .expect("unknown-field must fail parse");
    assert!(
        err.to_string().contains("entrypoin") || err.to_string().contains("unknown"),
        "error must identify the typo; got {err}"
    );
}
