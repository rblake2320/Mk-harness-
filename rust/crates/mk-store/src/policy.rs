//! Tenant policy configuration and kill switches.

use chrono::{DateTime, Utc};
use mk_audit::{EventType, NewEvent};
use mk_domain::TenantId;
use mk_policy::TenantPolicy;
use serde_json::json;
use sqlx::{PgPool, Row};

use crate::actions::Actor;
use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

/// Load the newest policy version for the tenant, or conservative defaults
/// when none has been written. Also returns the tenant's UTC offset minutes
/// for contact-hour evaluation.
pub async fn load(tx: &mut TenantTx<'_>) -> Result<(TenantPolicy, i32), StoreError> {
    let tenant = tx.tenant();
    let r = sqlx::query(
        "SELECT dispatch_enabled, agent_operations_entitled, allow_self_approval, contact_hours_start, contact_hours_end,
                contact_tz, contact_tz_offset_minutes, max_per_contact_per_day, approval_ttl_secs, required_opt_out_phrase,
                roles_allowed_to_propose
         FROM kernel.policy_versions WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant.0)
    .fetch_optional(tx.conn())
    .await?;
    let Some(r) = r else {
        return Ok((TenantPolicy::defaults(tenant), -300));
    };
    let tenant_switch: Option<bool> = sqlx::query("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope = 'tenant' AND tenant_id = $1")
        .bind(tenant.0)
        .fetch_optional(tx.conn())
        .await?
        .map(|k| k.try_get("dispatch_enabled"))
        .transpose()?;
    let p = TenantPolicy {
        tenant_id: tenant,
        dispatch_enabled: r.try_get::<bool, _>("dispatch_enabled")?
            && tenant_switch.unwrap_or(true),
        agent_operations_entitled: r.try_get("agent_operations_entitled")?,
        allow_self_approval: r.try_get("allow_self_approval")?,
        contact_hours: (
            u8::try_from(r.try_get::<i16, _>("contact_hours_start")?).unwrap_or(0),
            u8::try_from(r.try_get::<i16, _>("contact_hours_end")?).unwrap_or(0),
        ),
        contact_tz: r.try_get("contact_tz")?,
        max_per_contact_per_day: u32::try_from(r.try_get::<i32, _>("max_per_contact_per_day")?)
            .unwrap_or(0),
        approval_ttl_secs: u32::try_from(r.try_get::<i32, _>("approval_ttl_secs")?).unwrap_or(900),
        required_opt_out_phrase: r.try_get("required_opt_out_phrase")?,
        roles_allowed_to_propose: r.try_get("roles_allowed_to_propose")?,
    };
    Ok((p, r.try_get("contact_tz_offset_minutes")?))
}

pub async fn write(
    tx: &mut TenantTx<'_>,
    version: &str,
    p: &TenantPolicy,
    tz_offset_minutes: i32,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.policy_versions (tenant_id, version, dispatch_enabled, agent_operations_entitled, allow_self_approval,
           contact_hours_start, contact_hours_end, contact_tz, contact_tz_offset_minutes, max_per_contact_per_day, approval_ttl_secs,
           required_opt_out_phrase, roles_allowed_to_propose)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(tx.tenant().0)
    .bind(version)
    .bind(p.dispatch_enabled)
    .bind(p.agent_operations_entitled)
    .bind(p.allow_self_approval)
    .bind(i16::from(p.contact_hours.0))
    .bind(i16::from(p.contact_hours.1))
    .bind(&p.contact_tz)
    .bind(tz_offset_minutes)
    .bind(i32::try_from(p.max_per_contact_per_day).unwrap_or(i32::MAX))
    .bind(i32::try_from(p.approval_ttl_secs).unwrap_or(900))
    .bind(&p.required_opt_out_phrase)
    .bind(&p.roles_allowed_to_propose)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Global kill switch (no tenant context; readable by every runtime role).
pub async fn global_dispatch_enabled(pool: &PgPool) -> Result<bool, StoreError> {
    let r = sqlx::query("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope = 'global'")
        .fetch_optional(pool)
        .await?;
    // Missing row fails closed.
    Ok(r.map(|r| r.try_get("dispatch_enabled"))
        .transpose()?
        .unwrap_or(false))
}

pub async fn set_global_dispatch(
    pool: &PgPool,
    enabled: bool,
    changed_by: &str,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE kernel.kill_switches SET dispatch_enabled = $1, changed_by = $2, changed_at = now() WHERE scope = 'global'")
        .bind(enabled)
        .bind(changed_by)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_tenant_dispatch(
    tx: &mut TenantTx<'_>,
    enabled: bool,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let tenant: TenantId = tx.tenant();
    sqlx::query(
        "INSERT INTO kernel.kill_switches (scope, tenant_id, dispatch_enabled, changed_by, changed_at) VALUES ('tenant',$1,$2,$3,$4)
         ON CONFLICT (tenant_id) WHERE scope = 'tenant' DO UPDATE SET dispatch_enabled = EXCLUDED.dispatch_enabled, changed_by = EXCLUDED.changed_by, changed_at = EXCLUDED.changed_at",
    )
    .bind(tenant.0)
    .bind(enabled)
    .bind(actor.actor_id)
    .bind(now)
    .execute(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tenant,
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: None,
            event_type: EventType::KillSwitchChanged,
            payload_redacted: json!({"scope": "tenant", "dispatch_enabled": enabled}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok(())
}
