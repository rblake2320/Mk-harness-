//! PostgreSQL persistence for the MK action kernel.
//!
//! Every tenant-scoped operation runs inside a [`TenantTx`], which issues
//! `SET LOCAL kernel.tenant_id` so row-level security is enforced by the
//! database *in addition to* the `tenant_id` predicates in every query.
//! Cross-tenant maintenance (lease sweeps, the audit verifier) uses the
//! explicitly named role policies in the migration, never a bypass flag in
//! application code.
//!
//! Queries use runtime-checked `sqlx::query` rather than the compile-time
//! macros so the crate builds without a database; the integration suite
//! (`tests/postgres.rs`) exercises every statement against a real PostgreSQL.

pub mod actions;
pub mod adapters;
pub mod approvals;
pub mod assertions;
pub mod audit;
pub mod consent;
pub mod drafts;
pub mod error;
pub mod fingerprint;
pub mod human_approval;
pub mod idempotency;
pub mod keys;
pub mod messaging;
pub mod outbox;
pub mod policy;
pub mod privacy;
pub mod probes;
pub mod resolutions;
pub mod tx;

pub use error::StoreError;
pub use tx::{Store, TenantTx};

/// Database URL for a process: `MK_DATABASE_URL` verbatim, or — the shape the
/// orchestrator injects (`infra/terraform`): `MK_DB_HOST`, `MK_DB_USER`,
/// `MK_DB_PASSWORD` (secret), optional `MK_DB_NAME` (default `mkharness`) and
/// `MK_DB_PORT` (5432) — composed here with the password percent-encoded and
/// `sslmode=require`, so no URL containing a secret is ever written into a
/// task definition or environment file.
pub fn database_url_from_env() -> Result<String, StoreError> {
    database_url_from(|k| std::env::var(k).ok())
}

/// Pure form of [`database_url_from_env`] over any variable lookup.
pub fn database_url_from(lookup: impl Fn(&str) -> Option<String>) -> Result<String, StoreError> {
    let get = |k: &str| lookup(k).filter(|v| !v.trim().is_empty());
    if let Some(u) = get("MK_DATABASE_URL") {
        return Ok(u);
    }
    let (Some(host), Some(user), Some(pw)) =
        (get("MK_DB_HOST"), get("MK_DB_USER"), get("MK_DB_PASSWORD"))
    else {
        return Err(StoreError::Corrupt(
            "MK_DATABASE_URL or MK_DB_HOST/MK_DB_USER/MK_DB_PASSWORD required",
        ));
    };
    let name = get("MK_DB_NAME").unwrap_or_else(|| "mkharness".into());
    let port = get("MK_DB_PORT").unwrap_or_else(|| "5432".into());
    // With an explicit root certificate the client verifies the server name against that
    // CA alone (sqlx-core does not add bundled webpki roots when a root path is given).
    let ssl = get("MK_DB_SSLROOTCERT").map_or_else(
        || "sslmode=require".to_owned(),
        |path| format!("sslmode=verify-full&sslrootcert={}", enc_path(&path)),
    );
    let enc = |s: &str| {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(char::from(b));
                }
                _ => {
                    use std::fmt::Write as _;
                    let _ = write!(out, "%{b:02X}");
                }
            }
        }
        out
    };
    Ok(format!(
        "postgres://{}:{}@{host}:{port}/{name}?{ssl}",
        enc(&user),
        enc(&pw)
    ))
}

fn enc_path(s: &str) -> String {
    s.replace('%', "%25")
        .replace('&', "%26")
        .replace('?', "%3F")
        .replace('#', "%23")
        .replace(' ', "%20")
}

/// Embedded migrations for the `kernel` schema. Built by hand (no
/// `sqlx::migrate!` proc-macro) so the `sqlx-macros` dependency, and the
/// MySQL driver it drags into the lockfile, stay out of the supply chain.
/// Add new files here in version order; CI's `migrations_are_registered`
/// test fails if a file in `migrations/kernel` is missing from this list.
pub fn migrator() -> sqlx::migrate::Migrator {
    use sqlx::migrate::{Migration, MigrationType, Migrator};
    use std::borrow::Cow;
    const FILES: &[(i64, &str, &str)] = &[
        (
            1,
            "kernel schema",
            include_str!("../../../../migrations/kernel/0001_kernel_schema.sql"),
        ),
        (
            2,
            "assertion jtis",
            include_str!("../../../../migrations/kernel/0002_assertion_jtis.sql"),
        ),
        (
            3,
            "human approval authority",
            include_str!("../../../../migrations/kernel/0003_human_approval_authority.sql"),
        ),
        (
            4,
            "provider messaging",
            include_str!("../../../../migrations/kernel/0004_provider_messaging.sql"),
        ),
        (
            5,
            "key versions",
            include_str!("../../../../migrations/kernel/0005_key_versions.sql"),
        ),
        (
            6,
            "tenant scoped dedupe",
            include_str!("../../../../migrations/kernel/0006_tenant_scoped_dedupe.sql"),
        ),
        (
            7,
            "permission destination binding",
            include_str!("../../../../migrations/kernel/0007_permission_destination.sql"),
        ),
        (
            8,
            "versioned destination fingerprints",
            include_str!("../../../../migrations/kernel/0008_fingerprint_versions.sql"),
        ),
        (
            9,
            "tenant directory",
            include_str!("../../../../migrations/kernel/0009_tenant_directory.sql"),
        ),
        (
            10,
            "reconciliation check watermark",
            include_str!("../../../../migrations/kernel/0010_reconciliation_checks.sql"),
        ),
        (
            11,
            "worker reconciliation evidence grant",
            include_str!("../../../../migrations/kernel/0011_reconciliation_event_grant.sql"),
        ),
        (
            12,
            "passkey submission resolutions",
            include_str!("../../../../migrations/kernel/0012_submission_resolutions.sql"),
        ),
        (
            13,
            "durable public inbound probes",
            include_str!("../../../../migrations/kernel/0013_inbound_probes.sql"),
        ),
        (
            14,
            "draft version invalidation fences",
            include_str!("../../../../migrations/kernel/0014_draft_invalidation.sql"),
        ),
        (
            15,
            "draft fence insert guard",
            include_str!("../../../../migrations/kernel/0015_draft_fence_insert_guard.sql"),
        ),
        (
            16,
            "draft rollout backfill",
            include_str!("../../../../migrations/kernel/0016_draft_rollout_backfill.sql"),
        ),
        (
            17,
            "privacy erasure and subject fences",
            include_str!("../../../../migrations/kernel/0017_privacy_erasure.sql"),
        ),
        (
            18,
            "provider erasure receipts",
            include_str!("../../../../migrations/kernel/0018_provider_erasure_receipts.sql"),
        ),
        (
            19,
            "privacy intake privileges",
            include_str!("../../../../migrations/kernel/0019_privacy_intake_privileges.sql"),
        ),
    ];
    let migrations: Vec<Migration> = FILES
        .iter()
        .map(|(version, description, sql)| {
            Migration::new(
                *version,
                Cow::Borrowed(description),
                MigrationType::Simple,
                sqlx::SqlStr::from_static(sql),
                false,
            )
        })
        .collect();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    #[test]
    fn migrations_are_registered() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../migrations/kernel");
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .expect("migrations dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                std::path::Path::new(n)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("sql"))
            })
            .collect();
        files.sort();
        let registered = super::migrator().migrations.len();
        assert_eq!(
            files.len(),
            registered,
            "every migration file must be embedded: {files:?}"
        );
    }
}

#[cfg(test)]
mod database_url_tests {
    use super::database_url_from;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn verbatim_url_wins() {
        let u = database_url_from(env(&[
            ("MK_DATABASE_URL", "postgres://a:b@h/db"),
            ("MK_DB_HOST", "x"),
        ]));
        assert_eq!(u.unwrap_or_default(), "postgres://a:b@h/db");
    }

    #[test]
    fn composed_url_percent_encodes_the_password_and_requires_tls() {
        let u = database_url_from(env(&[
            ("MK_DB_HOST", "pg.internal"),
            ("MK_DB_USER", "mk_api_login"),
            ("MK_DB_PASSWORD", "p@ss/w:rd#1 é"),
        ]));
        assert_eq!(
            u.unwrap_or_default(),
            "postgres://mk_api_login:p%40ss%2Fw%3Ard%231%20%C3%A9@pg.internal:5432/mkharness?sslmode=require"
        );
    }

    #[test]
    fn explicit_root_cert_switches_to_verify_full() {
        let u = database_url_from(env(&[
            ("MK_DB_HOST", "pg"),
            ("MK_DB_USER", "u"),
            ("MK_DB_PASSWORD", "p"),
            ("MK_DB_SSLROOTCERT", "/etc/mk/rds global.pem"),
        ]));
        assert_eq!(
            u.unwrap_or_default(),
            "postgres://u:p@pg:5432/mkharness?sslmode=verify-full&sslrootcert=/etc/mk/rds%20global.pem"
        );
    }

    #[test]
    fn empty_url_falls_through_and_missing_parts_is_an_error() {
        assert!(database_url_from(env(&[("MK_DATABASE_URL", "  "), ("MK_DB_HOST", "h")])).is_err());
        assert!(
            database_url_from(env(&[
                ("MK_DB_HOST", "h"),
                ("MK_DB_USER", "u"),
                ("MK_DB_PASSWORD", "")
            ]))
            .is_err()
        );
    }
}
