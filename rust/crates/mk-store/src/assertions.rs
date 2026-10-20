//! Durable, cluster-wide single-use registry for actor-assertion `jti`s.
//!
//! `INSERT … ON CONFLICT DO NOTHING` is the whole algorithm: exactly one
//! request can insert a given `jti`; every other sees zero rows affected and
//! is a replay. The insert runs in its own implicit transaction *before* the
//! handler's transaction, so a request that fails later still consumed its
//! `jti` — a token is single-use regardless of outcome.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiOutcome {
    Fresh,
    Replayed,
}

pub async fn consume_jti(
    pool: &PgPool,
    jti: Uuid,
    tenant_id: Uuid,
    subject: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<JtiOutcome, StoreError> {
    let res = sqlx::query(
        "INSERT INTO kernel.assertion_jtis (jti, tenant_id, subject, expires_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING",
    )
    .bind(jti)
    .bind(tenant_id)
    .bind(subject)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(if res.rows_affected() == 1 {
        JtiOutcome::Fresh
    } else {
        JtiOutcome::Replayed
    })
}

/// Housekeeping: drop rows whose assertion could no longer verify anyway.
pub async fn purge_jtis(pool: &PgPool, now: DateTime<Utc>) -> Result<u64, StoreError> {
    let res = sqlx::query("DELETE FROM kernel.assertion_jtis WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
