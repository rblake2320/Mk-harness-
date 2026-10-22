//! Content-free recovery ledger. Its digest and minimum freshness time must
//! come from an independently retained source, never the restored database.
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use mk_crypto::Digest;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{Store, StoreError, TenantTx, privacy::SubjectKind};

const FORMAT: &str = "mk-kernel-erasure-ledger-v1";
pub const MAX_LEDGER_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    format: String,
    exported_at: DateTime<Utc>,
    requests: Vec<Request>,
    fences: Vec<Fence>,
    #[serde(skip)]
    authenticated_digest: Option<Digest>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tenant_id: Uuid,
    request_id: Uuid,
    subject_kind: SubjectKind,
    subject_id: Uuid,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    tenant_id: Uuid,
    request_id: Uuid,
    channel: String,
    destination_hash: String,
    destination_fingerprints: Vec<String>,
}

fn hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Entire input is authenticated and validated before any database mutation.
pub fn load(
    raw: &[u8],
    expected: &str,
    not_before: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Ledger, StoreError> {
    let expected: Digest = format!(
        "sha256:{}",
        expected.strip_prefix("sha256:").unwrap_or(expected)
    )
    .parse()
    .map_err(|_| StoreError::Conflict("invalid external ledger digest"))?;
    if raw.len() > MAX_LEDGER_BYTES || Digest::of(raw) != expected {
        return Err(StoreError::Conflict(
            "privacy ledger digest mismatch or size limit",
        ));
    }
    let mut ledger: Ledger =
        serde_json::from_slice(raw).map_err(|_| StoreError::Conflict("privacy ledger format"))?;
    if ledger.format != FORMAT || ledger.exported_at < not_before || ledger.exported_at > now {
        return Err(StoreError::Conflict("privacy ledger version or freshness"));
    }
    let mut requests = BTreeMap::new();
    let mut subjects = BTreeSet::new();
    for request in &ledger.requests {
        if request.tenant_id.is_nil()
            || request.request_id.is_nil()
            || request.subject_id.is_nil()
            || request.requested_at > ledger.exported_at
            || requests
                .insert(
                    (request.tenant_id, request.request_id),
                    request.subject_kind,
                )
                .is_some()
            || !subjects.insert((
                request.tenant_id,
                request.subject_kind.as_str(),
                request.subject_id,
            ))
        {
            return Err(StoreError::Conflict(
                "privacy ledger duplicate or invalid request",
            ));
        }
    }
    let mut fences = BTreeSet::new();
    for fence in &ledger.fences {
        if requests.get(&(fence.tenant_id, fence.request_id)) != Some(&SubjectKind::Contact)
            || serde_json::from_value::<mk_domain::Channel>(serde_json::Value::String(
                fence.channel.clone(),
            ))
            .is_err()
            || !hex_hash(&fence.destination_hash)
            || fence.destination_fingerprints.len() > 16
            || !fences.insert((
                fence.tenant_id,
                fence.request_id,
                &fence.channel,
                &fence.destination_hash,
            ))
        {
            return Err(StoreError::Conflict(
                "privacy ledger invalid destination fence",
            ));
        }
        let mut tags = BTreeSet::new();
        for tag in &fence.destination_fingerprints {
            let Some((kid, hash)) = tag.split_once(':') else {
                return Err(StoreError::Conflict("privacy ledger invalid fingerprint"));
            };
            if kid.is_empty()
                || kid.len() > 16
                || !kid.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
                || !hex_hash(hash)
                || !tags.insert(tag)
            {
                return Err(StoreError::Conflict("privacy ledger invalid fingerprint"));
            }
        }
    }
    ledger.authenticated_digest = Some(expected);
    Ok(ledger)
}

/// One read-only, repeatable snapshot, including fences for contacts created
/// after the backup point. Quiesce source intake before the final export.
pub async fn export(store: &Store) -> Result<Vec<u8>, StoreError> {
    let mut tx = store.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let tenants: Vec<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM kernel.tenant_directory ORDER BY tenant_id")
            .fetch_all(&mut *tx)
            .await?;
    let mut requests = Vec::new();
    let mut fences = Vec::new();
    for tenant in tenants {
        sqlx::query("SELECT set_config('kernel.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        for row in sqlx::query("SELECT request_id,subject_kind,subject_id,requested_at FROM kernel.privacy_erasure_requests WHERE tenant_id=$1 ORDER BY request_id")
            .bind(tenant).fetch_all(&mut *tx).await? {
            let kind:String=row.try_get("subject_kind")?;
            requests.push(Request { tenant_id:tenant,request_id:row.try_get("request_id")?,
                subject_kind:serde_json::from_value(serde_json::Value::String(kind)).map_err(|_| StoreError::Corrupt("privacy subject kind"))?,
                subject_id:row.try_get("subject_id")?,requested_at:row.try_get("requested_at")? });
        }
        for row in sqlx::query("SELECT request_id,channel,destination_hash,destination_fingerprints FROM kernel.privacy_destination_fences WHERE tenant_id=$1 ORDER BY request_id,channel,destination_hash")
            .bind(tenant).fetch_all(&mut *tx).await? {
            fences.push(Fence { tenant_id:tenant,request_id:row.try_get("request_id")?,channel:row.try_get("channel")?,
                destination_hash:row.try_get("destination_hash")?,destination_fingerprints:row.try_get("destination_fingerprints")? });
        }
    }
    tx.commit().await?;
    let ledger = Ledger {
        format: FORMAT.into(),
        exported_at: Utc::now(),
        requests,
        fences,
        authenticated_digest: None,
    };
    let raw = serde_json::to_vec(&ledger)
        .map_err(|_| StoreError::Corrupt("privacy ledger serialization"))?;
    // Refuse to export a ledger our recovery path would reject.
    load(
        &raw,
        &Digest::of(&raw).to_string(),
        ledger.exported_at,
        Utc::now(),
    )?;
    Ok(raw)
}

#[derive(Debug, Serialize)]
pub struct ReplayReport {
    pub applied: bool,
    pub requests: usize,
    pub fences: usize,
    pub pending_content: usize,
    pub enforced: bool,
}

async fn scope(tx: &mut TenantTx<'_>, tenant: Uuid) -> Result<(), StoreError> {
    sqlx::query("SELECT set_config('kernel.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(tx.conn())
        .await?;
    tx.tenant = mk_domain::TenantId::from_uuid(tenant);
    Ok(())
}

/// Atomic replay across all subjects. The entire restored identity set is
/// validated before any destructive statement; a failure rolls back everything.
/// Dispatch stays disabled. Uncertain sends remain quarantined for resolution.
pub async fn replay(
    store: &Store,
    ledger: &Ledger,
    apply: bool,
) -> Result<ReplayReport, StoreError> {
    let digest = ledger
        .authenticated_digest
        .as_ref()
        .ok_or(StoreError::Conflict(
            "ledger has no external authentication pin",
        ))?;
    let mut tx = store
        .begin_erasure(mk_domain::TenantId::from_uuid(Uuid::nil()))
        .await?;
    let enabled: Option<bool> = sqlx::query_scalar(
        "SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global' FOR SHARE",
    )
    .fetch_optional(tx.conn())
    .await?;
    if enabled != Some(false) {
        return Err(StoreError::Conflict(
            "disable dispatch before privacy recovery",
        ));
    }
    let known: Vec<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM kernel.tenant_directory ORDER BY tenant_id")
            .fetch_all(tx.conn())
            .await?;
    let tenants: BTreeSet<_> = known
        .into_iter()
        .chain(ledger.requests.iter().map(|r| r.tenant_id))
        .collect();
    // Acquire every exclusive gate in deterministic order before row/audit locks.
    for tenant in &tenants {
        sqlx::query("SELECT kernel.privacy_tenant_lock($1,true)")
            .bind(tenant)
            .execute(tx.conn())
            .await?;
    }
    let expected: BTreeMap<_, _> = ledger
        .requests
        .iter()
        .map(|r| ((r.tenant_id, r.request_id), r))
        .collect();
    for tenant in &tenants {
        scope(&mut tx, *tenant).await?;
        for row in sqlx::query("SELECT request_id,subject_kind,subject_id,requested_at FROM kernel.privacy_erasure_requests WHERE tenant_id=$1")
            .bind(tenant).fetch_all(tx.conn()).await? {
            let id:Uuid=row.try_get("request_id")?;
            let request=expected.get(&(*tenant,id)).ok_or(StoreError::Conflict("ledger omits a retained erasure request"))?;
            if row.try_get::<String,_>("subject_kind")? != request.subject_kind.as_str()
                || row.try_get::<Uuid,_>("subject_id")? != request.subject_id
                || row.try_get::<DateTime<Utc>,_>("requested_at")? != request.requested_at {
                return Err(StoreError::Conflict("ledger conflicts with retained erasure identity"));
            }
        }
    }
    let now = Utc::now();
    if apply {
        for request in &ledger.requests {
            scope(&mut tx, request.tenant_id).await?;
            sqlx::query("INSERT INTO kernel.privacy_erasure_requests(tenant_id,request_id,subject_kind,subject_id,requested_at)
                VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,request_id) DO NOTHING")
                .bind(request.tenant_id).bind(request.request_id).bind(request.subject_kind.as_str())
                .bind(request.subject_id).bind(request.requested_at).execute(tx.conn()).await?;
        }
        for fence in &ledger.fences {
            scope(&mut tx, fence.tenant_id).await?;
            sqlx::query("INSERT INTO kernel.privacy_destination_fences(tenant_id,request_id,channel,destination_hash,destination_fingerprints)
                VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind(fence.tenant_id).bind(fence.request_id).bind(&fence.channel).bind(&fence.destination_hash)
                .bind(&fence.destination_fingerprints).execute(tx.conn()).await?;
            // Preserve later key-version tags already in the restored database;
            // a missing tag is not permission to discard an existing fence.
            sqlx::query(
                "UPDATE kernel.privacy_destination_fences SET destination_fingerprints=
                ARRAY(SELECT DISTINCT unnest(destination_fingerprints || $5::text[]))
                WHERE tenant_id=$1 AND request_id=$2 AND channel=$3 AND destination_hash=$4",
            )
            .bind(fence.tenant_id)
            .bind(fence.request_id)
            .bind(&fence.channel)
            .bind(&fence.destination_hash)
            .bind(&fence.destination_fingerprints)
            .execute(tx.conn())
            .await?;
        }
        // Contacts first, then accounts, preserving the externally bound IDs.
        for kind in [SubjectKind::Contact, SubjectKind::Account] {
            for request in ledger.requests.iter().filter(|r| r.subject_kind == kind) {
                scope(&mut tx, request.tenant_id).await?;
                crate::privacy::erase(
                    &mut tx,
                    request.request_id,
                    kind,
                    request.subject_id,
                    mk_domain::UserId::from_uuid(Uuid::nil()),
                    crate::actions::Actor {
                        actor_type: mk_audit::ActorType::System,
                        actor_id: "privacy-ledger-replay",
                        trace_id: None,
                        policy_version: mk_policy::POLICY_VERSION.0,
                    },
                    now,
                )
                .await?;
                crate::audit::append_event(&mut tx,mk_audit::NewEvent {
                    tenant_id:mk_domain::TenantId::from_uuid(request.tenant_id),occurred_at:now,
                    actor_type:mk_audit::ActorType::System,actor_id:"privacy-ledger-replay",action_id:None,
                    event_type:mk_audit::EventType::PrivacyRestored,
                    payload_redacted:serde_json::json!({"request_id":request.request_id,"ledger_digest":digest}),
                    trace_id:None,policy_version:mk_policy::POLICY_VERSION.0,
                }).await?;
            }
        }
    }
    let mut pending_content = 0;
    for request in &ledger.requests {
        scope(&mut tx, request.tenant_id).await?;
        let erased: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel.privacy_erasure_requests
            WHERE tenant_id=$1 AND request_id=$2 AND content_erased_at IS NOT NULL)",
        )
        .bind(request.tenant_id)
        .bind(request.request_id)
        .fetch_one(tx.conn())
        .await?;
        let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel.actions WHERE tenant_id=$1
            AND (($2='account' AND requested_by=$3) OR ($2='contact' AND resource_type='contact' AND kernel.privacy_resource_uuid(resource_id)=$3))
            AND (content_erased_at IS NULL OR octet_length(canonical_request)<>0))")
            .bind(request.tenant_id).bind(request.subject_kind.as_str()).bind(request.subject_id).fetch_one(tx.conn()).await?;
        if !erased || live {
            pending_content += 1;
        }
    }
    for fence in &ledger.fences {
        scope(&mut tx, fence.tenant_id).await?;
        let present:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel.privacy_destination_fences
            WHERE tenant_id=$1 AND request_id=$2 AND channel=$3 AND destination_hash=$4 AND destination_fingerprints @> $5::text[])")
            .bind(fence.tenant_id).bind(fence.request_id).bind(&fence.channel).bind(&fence.destination_hash)
            .bind(&fence.destination_fingerprints).fetch_one(tx.conn()).await?;
        if !present {
            pending_content += 1;
        }
    }
    let report = ReplayReport {
        applied: apply,
        requests: ledger.requests.len(),
        fences: ledger.fences.len(),
        pending_content,
        enforced: pending_content == 0,
    };
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(report)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Static unit-test fixtures; no production input.
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> Value {
        json!({"format":FORMAT,"exported_at":"2026-10-22T00:00:00Z",
            "requests":[{"tenant_id":Uuid::new_v4(),"request_id":Uuid::new_v4(),
            "subject_kind":"contact","subject_id":Uuid::new_v4(),"requested_at":"2026-10-21T00:00:00Z"}],"fences":[]})
    }

    fn checked(value: &Value) -> Result<Ledger, StoreError> {
        let raw = serde_json::to_vec(value).unwrap();
        load(
            &raw,
            &Digest::of(&raw).to_string(),
            "2026-10-22T00:00:00Z".parse().unwrap(),
            "2026-10-22T00:01:00Z".parse().unwrap(),
        )
    }

    #[test]
    fn fence_vocabulary_matches_every_domain_channel() {
        for channel in [
            "sms",
            "email",
            "dm",
            "social",
            "instagram",
            "facebook",
            "tiktok",
            "x",
        ] {
            let mut value = fixture();
            value["fences"] = json!([{"tenant_id":value["requests"][0]["tenant_id"],
                "request_id":value["requests"][0]["request_id"],"channel":channel,
                "destination_hash":"a".repeat(64),"destination_fingerprints":[format!("m0:{}","a".repeat(64))]}]);
            assert!(checked(&value).is_ok());
            value["fences"][0]["channel"] = json!("unknown");
            assert!(checked(&value).is_err());
        }
    }

    #[test]
    fn rejects_malformed_duplicate_unbound_or_account_fences() {
        let mut good = fixture();
        good["fences"] = json!([{"tenant_id":good["requests"][0]["tenant_id"],
            "request_id":good["requests"][0]["request_id"],"channel":"sms",
            "destination_hash":"a".repeat(64),"destination_fingerprints":[format!("m0:{}","a".repeat(64))]}]);
        for invalid in [
            "",
            "secret",
            "A0:",
            "m0:bad",
            &format!("{}:{}", "k".repeat(17), "a".repeat(64)),
        ] {
            let mut value = good.clone();
            value["fences"][0]["destination_fingerprints"] = json!([invalid]);
            assert!(checked(&value).is_err());
        }
        let mut value = good.clone();
        value["fences"][0]["request_id"] = json!(Uuid::new_v4());
        assert!(checked(&value).is_err());
        value = good.clone();
        value["requests"][0]["subject_kind"] = json!("account");
        assert!(checked(&value).is_err());
        value = good.clone();
        value["fences"] = json!([good["fences"][0], good["fences"][0]]);
        assert!(checked(&value).is_err());
        value = good.clone();
        let tag = good["fences"][0]["destination_fingerprints"][0].clone();
        value["fences"][0]["destination_fingerprints"] = json!([tag, tag]);
        assert!(checked(&value).is_err());
    }

    #[test]
    fn deserialized_ledger_has_no_external_authentication() {
        let value = fixture();
        let raw = serde_json::to_vec(&value).unwrap();
        let unchecked: Ledger = serde_json::from_slice(&raw).unwrap();
        assert!(unchecked.authenticated_digest.is_none());
        assert!(checked(&value).unwrap().authenticated_digest.is_some());
        assert!(load(&raw, "sha256:wrong", Utc::now(), Utc::now()).is_err());
    }
}
