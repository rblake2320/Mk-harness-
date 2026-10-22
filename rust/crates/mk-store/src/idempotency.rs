//! `(tenant, action_kind, idempotency_key)` → first action. Same digest
//! returns the original; different digest is a conflict.

use mk_crypto::Digest;
use mk_domain::{ActionId, ActionKind};
use sqlx::Row;

use crate::error::StoreError;
use crate::tx::TenantTx;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyOutcome {
    /// First time this key was seen; proceed and create the action.
    Fresh,
    /// Same key, same request: return the original action.
    Replay(ActionId),
}

pub async fn check_or_insert(
    tx: &mut TenantTx<'_>,
    kind: ActionKind,
    key: &str,
    request_digest: &Digest,
    action_id: ActionId,
) -> Result<IdempotencyOutcome, StoreError> {
    let kind_s = serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let existing = sqlx::query(
        "SELECT request_digest, first_action_id FROM kernel.idempotency_records
         WHERE tenant_id = $1 AND action_kind = $2
         AND ((NOT key_erased AND idempotency_key = $3) OR (key_erased AND idempotency_key = $4)) FOR UPDATE",
    )
    .bind(tx.tenant().0)
    .bind(&kind_s)
    .bind(key)
    .bind(Digest::of(key.as_bytes()).to_string())
    .fetch_optional(tx.conn())
    .await?;
    if let Some(r) = existing {
        let stored: String = r.try_get("request_digest")?;
        if mk_crypto::constant_time_eq(stored.as_bytes(), request_digest.to_string().as_bytes()) {
            return Ok(IdempotencyOutcome::Replay(ActionId::from_uuid(
                r.try_get("first_action_id")?,
            )));
        }
        return Err(StoreError::Conflict(
            "idempotency key reused with different content",
        ));
    }
    sqlx::query(
        "INSERT INTO kernel.idempotency_records (tenant_id, action_kind, idempotency_key, request_digest, first_action_id)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(tx.tenant().0)
    .bind(&kind_s)
    .bind(key)
    .bind(request_digest.to_string())
    .bind(action_id.0)
    .execute(tx.conn())
    .await?;
    Ok(IdempotencyOutcome::Fresh)
}
