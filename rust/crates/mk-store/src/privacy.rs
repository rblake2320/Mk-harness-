//! Transactional, fail-closed content erasure. Provider deletion is separately
//! receipted; ambiguous submissions retain reconciliation data and report blocked.
use crate::{
    actions::{self, Actor},
    audit::append_event,
    error::StoreError,
    tx::TenantTx,
};
use chrono::{DateTime, Utc};
use mk_audit::{EventType, NewEvent};
use mk_contracts::ActionRequest;
use mk_crypto::Digest;
use mk_domain::{ActionId, ActionState, ResourceType, Transition, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Contact,
    Account,
}
impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Account => "account",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErasureReceipt {
    pub tenant_id: Uuid,
    pub request_id: Uuid,
    pub subject_kind: SubjectKind,
    pub subject_id: Uuid,
    pub active_content_erased: bool,
    pub pending_provider_deletions: i64,
    pub pending_provider_retention: i64,
    pub blocked_actions: i64,
    pub pending_sender_cleanup: i64,
}

pub async fn check_subject(
    tx: &mut TenantTx<'_>,
    kind: SubjectKind,
    id: Uuid,
) -> Result<(), StoreError> {
    let erased: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel.privacy_erasure_requests
        WHERE tenant_id=$1 AND subject_kind=$2 AND subject_id=$3)",
    )
    .bind(tx.tenant().0)
    .bind(kind.as_str())
    .bind(id)
    .fetch_one(tx.conn())
    .await?;
    if erased {
        Err(StoreError::Erased)
    } else {
        Ok(())
    }
}

pub async fn check_intake(tx: &mut TenantTx<'_>, req: &ActionRequest) -> Result<(), StoreError> {
    tx.assert_tenant(req.tenant_id)?;
    check_subject(tx, SubjectKind::Account, req.requested_by.0).await?;
    if req.resource.resource_type == ResourceType::Contact
        && let Ok(id) = req.resource.id.parse::<Uuid>()
    {
        check_subject(tx, SubjectKind::Contact, id).await?;
    }
    Ok(())
}

pub async fn destination_erased(
    tx: &mut TenantTx<'_>,
    channel: &str,
    destination: &crate::fingerprint::Fingerprints,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel.privacy_destination_fences
        WHERE tenant_id=$1 AND channel=$2 AND (destination_hash=$3 OR destination_fingerprints && $4))")
        .bind(tx.tenant().0).bind(channel).bind(&destination.primary).bind(&destination.tagged)
        .fetch_one(tx.conn()).await?)
}

#[allow(clippy::too_many_arguments)]
pub async fn erase(
    tx: &mut TenantTx<'_>,
    request_id: Uuid,
    kind: SubjectKind,
    subject: Uuid,
    by: UserId,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<ErasureReceipt, StoreError> {
    if !tx.erasure {
        return Err(StoreError::Conflict(
            "erasure requires an exclusive tenant transaction",
        ));
    }
    if request_id.is_nil() || subject.is_nil() {
        return Err(StoreError::Conflict("nil erasure identity"));
    }
    let tenant = tx.tenant();
    let previous = sqlx::query(
        "SELECT request_id,subject_kind,subject_id FROM kernel.privacy_erasure_requests
        WHERE tenant_id=$1 AND (request_id=$2 OR (subject_kind=$3 AND subject_id=$4))",
    )
    .bind(tenant.0)
    .bind(request_id)
    .bind(kind.as_str())
    .bind(subject)
    .fetch_optional(tx.conn())
    .await?;
    if let Some(row) = previous {
        if row.try_get::<Uuid, _>("request_id")? != request_id
            || row.try_get::<String, _>("subject_kind")? != kind.as_str()
            || row.try_get::<Uuid, _>("subject_id")? != subject
        {
            return Err(StoreError::Conflict("erasure identity already bound"));
        }
    } else {
        sqlx::query("INSERT INTO kernel.privacy_erasure_requests(tenant_id,request_id,subject_kind,subject_id,requested_at)
            VALUES($1,$2,$3,$4,$5)")
            .bind(tenant.0).bind(request_id).bind(kind.as_str()).bind(subject).bind(now).execute(tx.conn()).await?;
        append_event(tx, NewEvent { tenant_id: tenant, occurred_at: now, actor_type: actor.actor_type,
            actor_id: actor.actor_id, action_id: None, event_type: EventType::PrivacyRequested,
            payload_redacted: json!({"request_id":request_id,"subject_kind":kind,"subject_id":subject}),
            trace_id: actor.trace_id, policy_version: actor.policy_version }).await?;
    }

    // Fences preserve only destination fingerprints, not the address or body.
    if kind == SubjectKind::Contact {
        sqlx::query("INSERT INTO kernel.privacy_destination_fences(tenant_id,request_id,channel,destination_hash,destination_fingerprints)
            SELECT tenant_id,$2,channel,destination_hash,destination_fingerprints FROM kernel.contact_permissions
            WHERE tenant_id=$1 AND contact_id=$3 AND destination_hash IS NOT NULL
            UNION SELECT tenant_id,$2,channel,destination_hash,destination_fingerprints FROM kernel.actions
            WHERE tenant_id=$1 AND resource_type='contact' AND kernel.privacy_resource_uuid(resource_id)=$3 AND channel IS NOT NULL AND destination_hash IS NOT NULL
            ON CONFLICT DO NOTHING")
            .bind(tenant.0).bind(request_id).bind(subject).execute(tx.conn()).await?;
    }

    let action_ids: Vec<Uuid> = sqlx::query_scalar("SELECT action_id FROM kernel.actions WHERE tenant_id=$1
        AND (($2='account' AND requested_by=$3) OR ($2='contact' AND resource_type='contact' AND kernel.privacy_resource_uuid(resource_id)=$3))
        AND content_erased_at IS NULL ORDER BY action_id FOR UPDATE")
        .bind(tenant.0).bind(kind.as_str()).bind(subject).fetch_all(tx.conn()).await?;
    let mut blocked_actions = 0;
    for id in action_ids {
        let action_id = ActionId::from_uuid(id);
        let action = actions::get_for_update(tx, action_id).await?;
        // Once dispatch has crossed its commit boundary it may be in the
        // provider's hands. Keep the bytes required to resolve it; never resend.
        let provider_pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel.message_deliveries
            WHERE tenant_id=$1 AND action_id=$2 AND state NOT IN ('delivered','failed'))",
        )
        .bind(tenant.0)
        .bind(id)
        .fetch_one(tx.conn())
        .await?;
        let unresolved = action.state == ActionState::ReconciliationRequired
            && crate::resolutions::decision(tx, action_id).await?.is_none();
        if action.state == ActionState::Dispatching || unresolved || provider_pending {
            blocked_actions += 1;
            continue;
        }
        sqlx::query("INSERT INTO kernel.privacy_provider_deletions(tenant_id,request_id,sender_identity_id,provider,provider_message_id)
            SELECT tenant_id,$2,sender_identity_id,provider,provider_message_id FROM kernel.message_deliveries
            WHERE tenant_id=$1 AND action_id=$3 AND provider_message_id IS NOT NULL ON CONFLICT DO NOTHING")
            .bind(tenant.0).bind(request_id).bind(id).execute(tx.conn()).await?;
        sqlx::query("UPDATE kernel.approvals SET revoked_at=COALESCE(revoked_at,$3),revoked_by=COALESCE(revoked_by,$4),reason=NULL
            WHERE tenant_id=$1 AND action_id=$2")
            .bind(tenant.0).bind(id).bind(now).bind(by.0).execute(tx.conn()).await?;
        if action.state.is_cancellable() {
            actions::transition(
                tx,
                action_id,
                Transition::Cancel,
                Some("privacy_erasure"),
                actor,
                now,
            )
            .await?;
        }
        let keys = sqlx::query(
            "SELECT action_kind,idempotency_key FROM kernel.idempotency_records
            WHERE tenant_id=$1 AND first_action_id=$2 AND NOT key_erased FOR UPDATE",
        )
        .bind(tenant.0)
        .bind(id)
        .fetch_all(tx.conn())
        .await?;
        for row in keys {
            let key: String = row.try_get("idempotency_key")?;
            let action_kind: String = row.try_get("action_kind")?;
            sqlx::query(
                "UPDATE kernel.idempotency_records SET idempotency_key=$4,key_erased=true
                WHERE tenant_id=$1 AND action_kind=$2 AND idempotency_key=$3 AND NOT key_erased",
            )
            .bind(tenant.0)
            .bind(action_kind)
            .bind(&key)
            .bind(Digest::of(key.as_bytes()).to_string())
            .execute(tx.conn())
            .await?;
        }
        sqlx::query("UPDATE kernel.message_deliveries SET reconciliation_note=NULL WHERE tenant_id=$1 AND action_id=$2")
            .bind(tenant.0).bind(id).execute(tx.conn()).await?;
        sqlx::query("UPDATE kernel.actions SET canonical_request=''::bytea,purpose='',idempotency_key=$3,content_erased_at=$4
            WHERE tenant_id=$1 AND action_id=$2")
            .bind(tenant.0).bind(id).bind(Digest::of(action.request.idempotency_key.as_bytes()).to_string())
            .bind(now).execute(tx.conn()).await?;
        append_event(
            tx,
            NewEvent {
                tenant_id: tenant,
                occurred_at: now,
                actor_type: actor.actor_type,
                actor_id: actor.actor_id,
                action_id: Some(action_id),
                event_type: EventType::ContentErased,
                payload_redacted: json!({"request_id":request_id,"action_digest":action.digest}),
                trace_id: actor.trace_id,
                policy_version: actor.policy_version,
            },
        )
        .await?;
    }
    if kind == SubjectKind::Contact {
        sqlx::query("UPDATE kernel.contact_permissions SET status='revoked',revoked_at=COALESCE(revoked_at,$3),
            source='privacy-erased',scope='{}',destination_sealed=NULL WHERE tenant_id=$1 AND contact_id=$2")
            .bind(tenant.0).bind(subject).bind(now).execute(tx.conn()).await?;
        sqlx::query("UPDATE kernel.suppressions s SET destination_sealed=NULL,source='privacy-erased',reason='privacy-erased'
            WHERE s.tenant_id=$1 AND EXISTS(SELECT 1 FROM kernel.privacy_destination_fences f
            WHERE f.tenant_id=s.tenant_id AND f.request_id=$2 AND (s.channel IS NULL OR s.channel=f.channel)
            AND (s.normalized_destination_hash=f.destination_hash OR s.destination_fingerprints && f.destination_fingerprints))")
            .bind(tenant.0).bind(request_id).execute(tx.conn()).await?;
    }
    let inbound = sqlx::query("SELECT i.event_id,i.sender_identity_id,i.provider,i.provider_event_id
        FROM kernel.inbound_events i WHERE i.tenant_id=$1 AND i.content_erased_at IS NULL
        AND (($2='account' AND EXISTS(SELECT 1 FROM kernel.sender_identities s WHERE s.tenant_id=i.tenant_id
          AND s.sender_identity_id=i.sender_identity_id AND s.owner_user_id=$3))
        OR EXISTS(SELECT 1 FROM kernel.privacy_destination_fences f WHERE f.tenant_id=i.tenant_id AND f.request_id=$4
          AND f.channel='sms' AND (f.destination_hash=i.source_destination_hash OR f.destination_fingerprints && i.destination_fingerprints)))
        FOR UPDATE OF i")
        .bind(tenant.0).bind(kind.as_str()).bind(subject).bind(request_id).fetch_all(tx.conn()).await?;
    for row in inbound {
        let id: Uuid = row.try_get("event_id")?;
        sqlx::query("INSERT INTO kernel.privacy_provider_deletions(tenant_id,request_id,sender_identity_id,provider,provider_message_id)
            VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(tenant.0).bind(request_id).bind(row.try_get::<Uuid,_>("sender_identity_id")?)
            .bind(row.try_get::<String,_>("provider")?).bind(row.try_get::<String,_>("provider_event_id")?).execute(tx.conn()).await?;
        sqlx::query("UPDATE kernel.inbound_events SET content_sealed=''::bytea,destination_sealed=NULL,
            content_reference='privacy-erased',processed_at=COALESCE(processed_at,$3),content_erased_at=$3
            WHERE tenant_id=$1 AND event_id=$2")
            .bind(tenant.0).bind(id).bind(now).execute(tx.conn()).await?;
    }
    if kind == SubjectKind::Account {
        let user = UserId::from_uuid(subject);
        sqlx::query("UPDATE kernel.sender_identities SET status='disabled',display_name='',registration_ref='' WHERE tenant_id=$1 AND owner_user_id=$2")
            .bind(tenant.0).bind(subject).execute(tx.conn()).await?;
        // The exclusive tenant lock precedes the approval/action/audit locks.
        crate::approvals::revoke_live_by_approver(tx, user, None, by, now).await?;
        if !sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM kernel.revocations WHERE tenant_id=$1 AND kind='user' AND user_id=$2)")
            .bind(tenant.0).bind(subject).fetch_one(tx.conn()).await? {
            crate::human_approval::revoke(tx,crate::human_approval::RevocationTarget::User(user),by,"privacy-erasure",now).await?;
        }
        sqlx::query("UPDATE kernel.approval_credentials SET label='',revoked_at=COALESCE(revoked_at,$3),revoked_by=COALESCE(revoked_by,$4)
            WHERE tenant_id=$1 AND user_id=$2")
            .bind(tenant.0).bind(subject).bind(now).bind(by.0).execute(tx.conn()).await?;
    }
    // Sender credentials cannot be discarded until message and owned-resource
    // cleanup has receipts. Report that pending work explicitly on account erase.
    let pending_sender_cleanup: i64 = if kind == SubjectKind::Account {
        sqlx::query_scalar(
            "SELECT count(*) FROM kernel.sender_identities WHERE tenant_id=$1 AND owner_user_id=$2",
        )
        .bind(tenant.0)
        .bind(subject)
        .fetch_one(tx.conn())
        .await?
    } else {
        0
    };
    let active_content_erased = blocked_actions == 0 && pending_sender_cleanup == 0;
    if active_content_erased {
        sqlx::query("UPDATE kernel.privacy_erasure_requests SET content_erased_at=COALESCE(content_erased_at,$3)
            WHERE tenant_id=$1 AND request_id=$2")
            .bind(tenant.0).bind(request_id).bind(now).execute(tx.conn()).await?;
    }
    let pending_provider_deletions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.privacy_provider_deletions
        WHERE tenant_id=$1 AND request_id=$2 AND confirmed_at IS NULL",
    )
    .bind(tenant.0)
    .bind(request_id)
    .fetch_one(tx.conn())
    .await?;
    let pending_provider_retention: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.privacy_provider_deletions
        WHERE tenant_id=$1 AND request_id=$2 AND confirmed_at IS NOT NULL AND backup_confirmed_at IS NULL",
    ).bind(tenant.0).bind(request_id).fetch_one(tx.conn()).await?;
    Ok(ErasureReceipt {
        tenant_id: tenant.0,
        request_id,
        subject_kind: kind,
        subject_id: subject,
        active_content_erased,
        pending_provider_deletions,
        pending_provider_retention,
        blocked_actions,
        pending_sender_cleanup,
    })
}

#[derive(Debug)]
pub struct ProviderDeletion {
    pub deletion_id: Uuid,
    pub request_id: Uuid,
    pub sender_identity_id: Uuid,
    pub provider: String,
    pub provider_message_id: String,
    pub lease_id: Uuid,
    pub attempts: i32,
}

/// Claim one item immediately before I/O. A batch lease can expire while its
/// earlier members are waiting on the network. SKIP LOCKED supports replicas.
pub async fn claim_provider_deletion(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
) -> Result<Option<ProviderDeletion>, StoreError> {
    let lease = Uuid::now_v7();
    let row = sqlx::query("WITH due AS (SELECT deletion_id FROM kernel.privacy_provider_deletions
        WHERE tenant_id=$1 AND confirmed_at IS NULL AND next_attempt_at<=$2
        ORDER BY next_attempt_at,deletion_id LIMIT 1 FOR UPDATE SKIP LOCKED)
        UPDATE kernel.privacy_provider_deletions d SET attempts=d.attempts+1,lease_id=$3,next_attempt_at=$2+interval '90 seconds'
        FROM due WHERE d.tenant_id=$1 AND d.deletion_id=due.deletion_id
        RETURNING d.deletion_id,d.request_id,d.sender_identity_id,d.provider,d.provider_message_id,d.attempts")
        .bind(tx.tenant().0).bind(now).bind(lease).fetch_optional(tx.conn()).await?;
    row.map(|r| {
        Ok(ProviderDeletion {
            deletion_id: r.try_get("deletion_id")?,
            request_id: r.try_get("request_id")?,
            sender_identity_id: r.try_get("sender_identity_id")?,
            provider: r.try_get("provider")?,
            provider_message_id: r.try_get("provider_message_id")?,
            lease_id: lease,
            attempts: r.try_get("attempts")?,
        })
    })
    .transpose()
}

/// CAS receipt + caller audit must commit together. An expired lease cannot
/// overwrite the receipt of a replacement worker, even after a late response.
pub async fn finish_provider_deletion(
    tx: &mut TenantTx<'_>,
    job: &ProviderDeletion,
    receipt: Option<&Digest>,
    error: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let delay = 30_i64 * (1_i64 << job.attempts.clamp(0, 7));
    let updated = sqlx::query("UPDATE kernel.privacy_provider_deletions SET lease_id=NULL,last_error=$4,
        confirmed_at=CASE WHEN $5::text IS NOT NULL THEN $6 ELSE NULL END,receipt_digest=$5,
        backup_not_before=CASE WHEN $5::text IS NOT NULL THEN $6+interval '30 days' ELSE NULL END,
        next_attempt_at=$7 WHERE tenant_id=$1 AND deletion_id=$2 AND lease_id=$3 AND confirmed_at IS NULL")
        .bind(tx.tenant().0).bind(job.deletion_id).bind(job.lease_id).bind(error)
        .bind(receipt.map(ToString::to_string)).bind(now).bind(now+chrono::Duration::seconds(delay.min(3600)))
        .execute(tx.conn()).await?;
    Ok(updated.rows_affected() == 1)
}
