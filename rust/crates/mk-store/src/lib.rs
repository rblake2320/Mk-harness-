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
pub mod error;
pub mod human_approval;
pub mod idempotency;
pub mod outbox;
pub mod policy;
pub mod tx;

pub use error::StoreError;
pub use tx::{Store, TenantTx};

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
    ];
    let migrations: Vec<Migration> = FILES
        .iter()
        .map(|(version, description, sql)| {
            Migration::new(
                *version,
                Cow::Borrowed(description),
                MigrationType::Simple,
                Cow::Borrowed(sql),
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
