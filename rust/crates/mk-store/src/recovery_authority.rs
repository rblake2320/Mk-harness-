//! Recovery of withdrawn authority without exporting credentials or contact data.
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use mk_crypto::Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{StoreError, TenantTx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Permission,
    ApprovalCredential,
    Adapter,
    AdapterCredential,
    Draft,
}

const KINDS: [Kind; 5] = [
    Kind::Permission,
    Kind::ApprovalCredential,
    Kind::Adapter,
    Kind::AdapterCredential,
    Kind::Draft,
];

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::ApprovalCredential => "approval_credential",
            Self::Adapter => "adapter",
            Self::AdapterCredential => "adapter_credential",
            Self::Draft => "draft",
        }
    }
    fn table(self) -> &'static str {
        match self {
            Self::Permission => "contact_permissions",
            Self::ApprovalCredential => "approval_credentials",
            Self::Adapter => "adapter_registrations",
            Self::AdapterCredential => "adapter_credentials",
            Self::Draft => "invalidated_drafts",
        }
    }
    fn id(self) -> &'static str {
        match self {
            Self::Permission => "permission_id",
            Self::ApprovalCredential => "credential_row_id",
            Self::Adapter => "adapter_id",
            Self::AdapterCredential => "credential_id",
            Self::Draft => "draft_id",
        }
    }
    fn identity_fields(self) -> &'static [&'static str] {
        match self {
            Self::Permission => &[
                "contact_id",
                "channel",
                "scope",
                "proof_digest",
                "granted_at",
                "expires_at",
                "recorded_by",
                "created_at",
            ],
            Self::ApprovalCredential => &[
                "user_id",
                "credential_id",
                "alg",
                "public_key",
                "aaguid",
                "created_at",
            ],
            Self::Adapter => &["agent_id", "adapter_kind", "created_at"],
            Self::AdapterCredential => &["adapter_id", "secret_fingerprint", "created_at"],
            Self::Draft => &[],
        }
    }
    fn event(self) -> mk_audit::EventType {
        match self {
            Self::Permission => mk_audit::EventType::PermissionRevoked,
            Self::ApprovalCredential => mk_audit::EventType::ApprovalCredentialRevoked,
            Self::Adapter => mk_audit::EventType::AdapterRevoked,
            Self::AdapterCredential => mk_audit::EventType::AdapterRotated,
            Self::Draft => mk_audit::EventType::DraftInvalidated,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Withdrawal {
    tenant_id: Uuid,
    kind: Kind,
    entity_id: Uuid,
    identity_digest: String,
    not_after: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct AuthorityLedger(Vec<Withdrawal>);

struct Observed {
    kind: Kind,
    entity: Uuid,
    identity: String,
    cutoff: Option<DateTime<Utc>>,
}

fn time(row: &Value, field: &str) -> Result<Option<DateTime<Utc>>, StoreError> {
    match row.get(field) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(v)) => v
            .parse()
            .map(Some)
            .map_err(|_| StoreError::Corrupt("authority time")),
        _ => Err(StoreError::Corrupt("authority time")),
    }
}

async fn observed(conn: &mut PgConnection, tenant: Uuid) -> Result<Vec<Observed>, StoreError> {
    let mut out = Vec::new();
    for kind in KINDS {
        let query = format!(
            "SELECT to_jsonb(r) AS record FROM kernel.{} r WHERE tenant_id=$1 ORDER BY {}",
            kind.table(),
            kind.id()
        );
        for row in sqlx::query(sqlx::AssertSqlSafe(query))
            .bind(tenant)
            .fetch_all(&mut *conn)
            .await?
        {
            let value: sqlx::types::Json<Value> = row.try_get("record")?;
            let entity = serde_json::from_value::<Uuid>(value[kind.id()].clone())
                .map_err(|_| StoreError::Corrupt("authority identity"))?;
            let mut identity = vec![
                json!("mk-recovery-authority-v1"),
                json!(kind),
                json!(tenant),
                json!(entity),
            ];
            for field in kind.identity_fields() {
                identity.push(
                    value
                        .get(*field)
                        .ok_or(StoreError::Corrupt("authority identity field"))?
                        .clone(),
                );
            }
            let encoded = serde_json::to_vec(&identity)
                .map_err(|_| StoreError::Corrupt("authority identity encoding"))?;
            let cutoff = match kind {
                Kind::Draft => time(&value, "invalidated_at")?,
                Kind::AdapterCredential => {
                    [time(&value, "revoked_at")?, time(&value, "not_after")?]
                        .into_iter()
                        .flatten()
                        .min()
                }
                _ => time(&value, "revoked_at")?,
            };
            out.push(Observed {
                kind,
                entity,
                identity: Digest::of(&encoded).to_string(),
                cutoff,
            });
        }
    }
    Ok(out)
}

impl AuthorityLedger {
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn tenants(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.0.iter().map(|r| r.tenant_id)
    }
    pub(crate) fn validate(&self, exported: DateTime<Utc>) -> Result<(), StoreError> {
        let mut ids = BTreeSet::new();
        for row in &self.0 {
            let latest = exported
                + if row.kind == Kind::AdapterCredential {
                    Duration::hours(1)
                } else {
                    Duration::zero()
                };
            if row.tenant_id.is_nil()
                || row.entity_id.is_nil()
                || !ids.insert((row.kind, row.entity_id))
                || row.not_after > latest
                || row.identity_digest.parse::<Digest>().is_err()
            {
                return Err(StoreError::Conflict("invalid recovered authority"));
            }
        }
        Ok(())
    }
    pub(crate) async fn export_tenant(
        &mut self,
        conn: &mut PgConnection,
        tenant: Uuid,
    ) -> Result<(), StoreError> {
        let mut merged: BTreeMap<(Kind, Uuid), Withdrawal> = BTreeMap::new();
        for row in observed(conn, tenant).await? {
            if let Some(cutoff) = row.cutoff {
                merged.insert(
                    (row.kind, row.entity),
                    Withdrawal {
                        tenant_id: tenant,
                        kind: row.kind,
                        entity_id: row.entity,
                        identity_digest: row.identity,
                        not_after: cutoff,
                    },
                );
            }
        }
        for row in sqlx::query("SELECT to_jsonb(f) AS record FROM kernel.recovery_authority_fences f WHERE tenant_id=$1 ORDER BY kind,entity_id")
            .bind(tenant).fetch_all(&mut *conn).await? {
            let value:sqlx::types::Json<Value>=row.try_get("record")?;
            let fence:Withdrawal=serde_json::from_value(value.0).map_err(|_|StoreError::Corrupt("authority fence"))?;
            if let Some(existing)=merged.get_mut(&(fence.kind,fence.entity_id)) {
                if existing.identity_digest!=fence.identity_digest { return Err(StoreError::Conflict("recovered authority identity changed")); }
                existing.not_after=existing.not_after.min(fence.not_after);
            } else { merged.insert((fence.kind,fence.entity_id),fence); }
        }
        self.0.extend(merged.into_values());
        Ok(())
    }
    pub(crate) async fn validate_retained(&self, tx: &mut TenantTx<'_>) -> Result<(), StoreError> {
        let tenant = tx.tenant().0;
        let expected: BTreeMap<_, _> = self
            .0
            .iter()
            .filter(|r| r.tenant_id == tenant)
            .map(|r| ((r.kind, r.entity_id), r))
            .collect();
        let mut retained = Self::default();
        retained.export_tenant(tx.conn(), tenant).await?;
        for row in retained.0 {
            let candidate =
                expected
                    .get(&(row.kind, row.entity_id))
                    .ok_or(StoreError::Conflict(
                        "ledger omits retained authority withdrawal",
                    ))?;
            if candidate.identity_digest != row.identity_digest
                || candidate.not_after > row.not_after
            {
                return Err(StoreError::Conflict(
                    "ledger relaxes retained authority withdrawal",
                ));
            }
        }
        for row in observed(tx.conn(), tenant).await? {
            if let Some(candidate) = expected.get(&(row.kind, row.entity))
                && candidate.identity_digest != row.identity
            {
                return Err(StoreError::Conflict("restored authority identity conflict"));
            }
        }
        Ok(())
    }
    pub(crate) async fn apply(
        &self,
        tx: &mut TenantTx<'_>,
        digest: &Digest,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let tenant = tx.tenant().0;
        for row in self.0.iter().filter(|r| r.tenant_id == tenant) {
            sqlx::query("INSERT INTO kernel.recovery_authority_fences(tenant_id,kind,entity_id,identity_digest,not_after) VALUES($1,$2,$3,$4,$5)
                ON CONFLICT(tenant_id,kind,entity_id) DO UPDATE SET not_after=LEAST(kernel.recovery_authority_fences.not_after,EXCLUDED.not_after)")
                .bind(tenant).bind(row.kind.name()).bind(row.entity_id).bind(&row.identity_digest).bind(row.not_after).execute(tx.conn()).await?;
            if row.kind == Kind::Draft {
                sqlx::query("INSERT INTO kernel.invalidated_drafts(tenant_id,draft_id,invalidated_by,invalidated_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                    .bind(tenant).bind(row.entity_id).bind(Uuid::nil()).bind(row.not_after).execute(tx.conn()).await?;
                crate::drafts::invalidate(
                    tx,
                    row.entity_id,
                    mk_domain::UserId::from_uuid(Uuid::nil()),
                    true,
                    crate::actions::Actor {
                        actor_type: mk_audit::ActorType::System,
                        actor_id: "recovery-ledger-replay",
                        trace_id: None,
                        policy_version: mk_policy::POLICY_VERSION.0,
                    },
                    now,
                )
                .await?;
            } else {
                let assignment = match row.kind {
                    Kind::Permission => "status='revoked',revoked_at=LEAST(revoked_at,$3)",
                    Kind::AdapterCredential => "not_after=LEAST(not_after,$3)",
                    _ => "revoked_at=LEAST(revoked_at,$3)",
                };
                let query = format!(
                    "UPDATE kernel.{} SET {assignment} WHERE tenant_id=$1 AND {}=$2",
                    row.kind.table(),
                    row.kind.id()
                );
                sqlx::query(sqlx::AssertSqlSafe(query))
                    .bind(tenant)
                    .bind(row.entity_id)
                    .bind(row.not_after)
                    .execute(tx.conn())
                    .await?;
            }
            crate::audit::append_event(tx,mk_audit::NewEvent { tenant_id:tx.tenant(),occurred_at:now,
                actor_type:mk_audit::ActorType::System,actor_id:"recovery-ledger-replay",action_id:None,event_type:row.kind.event(),
                payload_redacted:json!({"recovery_entity_id":row.entity_id,"ledger_digest":digest}),trace_id:None,
                policy_version:mk_policy::POLICY_VERSION.0 }).await?;
        }
        Ok(())
    }
    pub(crate) async fn pending(&self, tx: &mut TenantTx<'_>) -> Result<usize, StoreError> {
        let tenant = tx.tenant().0;
        let actual: BTreeMap<_, _> = observed(tx.conn(), tenant)
            .await?
            .into_iter()
            .map(|r| ((r.kind, r.entity), r))
            .collect();
        let mut pending = 0;
        for row in self.0.iter().filter(|r| r.tenant_id == tenant) {
            let fenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel.recovery_authority_fences WHERE tenant_id=$1 AND kind=$2 AND entity_id=$3 AND identity_digest=$4 AND not_after<=$5)")
                .bind(tenant).bind(row.kind.name()).bind(row.entity_id).bind(&row.identity_digest).bind(row.not_after).fetch_one(tx.conn()).await?;
            let enforced = actual.get(&(row.kind, row.entity_id)).is_none_or(|a| {
                a.identity == row.identity_digest && a.cutoff.is_some_and(|c| c <= row.not_after)
            });
            let mut cancellable = false;
            if row.kind == Kind::Draft {
                let states:Vec<String> = sqlx::query_scalar("SELECT a.state FROM kernel.actions a JOIN kernel.draft_action_refs r USING(tenant_id,action_id) WHERE r.tenant_id=$1 AND r.draft_id=$2")
                    .bind(tenant).bind(row.entity_id).fetch_all(tx.conn()).await?;
                for state in states {
                    let state: mk_domain::ActionState = serde_json::from_value(json!(state))
                        .map_err(|_| StoreError::Corrupt("recovered draft action state"))?;
                    cancellable |= state.is_cancellable();
                }
            }
            pending += usize::from(!fenced || !enforced || cancellable);
        }
        Ok(pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<(AuthorityLedger, DateTime<Utc>), chrono::ParseError> {
        let now: DateTime<Utc> = "2026-10-22T00:00:00Z".parse()?;
        Ok((
            AuthorityLedger(vec![Withdrawal {
                tenant_id: Uuid::new_v4(),
                kind: Kind::Permission,
                entity_id: Uuid::new_v4(),
                identity_digest: Digest::of(b"synthetic identity").to_string(),
                not_after: now,
            }]),
            now,
        ))
    }

    #[test]
    fn withdrawals_require_closed_non_nil_unique_identities_and_bounded_times()
    -> Result<(), Box<dyn std::error::Error>> {
        let (good, now) = fixture()?;
        assert!(good.validate(now).is_ok());
        let value = serde_json::to_value(&good)?;
        for (field, invalid) in [
            ("tenant_id", json!(Uuid::nil())),
            ("entity_id", json!(Uuid::nil())),
            ("identity_digest", json!("private-key")),
            ("not_after", json!(now + Duration::seconds(1))),
        ] {
            let mut changed = value.clone();
            changed[0][field] = invalid;
            assert!(
                serde_json::from_value::<AuthorityLedger>(changed)?
                    .validate(now)
                    .is_err()
            );
        }
        for (field, invalid) in [
            ("kind", json!("arbitrary_table")),
            ("secret", json!("private")),
        ] {
            let mut changed = value.clone();
            changed[0][field] = invalid;
            assert!(serde_json::from_value::<AuthorityLedger>(changed).is_err());
        }
        let mut duplicate = good.0[0].clone();
        duplicate.tenant_id = Uuid::new_v4();
        assert!(
            AuthorityLedger(vec![good.0[0].clone(), duplicate])
                .validate(now)
                .is_err()
        );
        let (mut scheduled, _) = fixture()?;
        scheduled.0[0].kind = Kind::AdapterCredential;
        scheduled.0[0].not_after = now + Duration::minutes(30);
        assert!(scheduled.validate(now).is_ok());
        scheduled.0[0].not_after = now + Duration::hours(2);
        assert!(scheduled.validate(now).is_err());
        Ok(())
    }
}
