//! Content-free restriction recovery. Never exports destinations, reasons or session IDs.
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use mk_crypto::Digest;
use mk_domain::{TenantId, UserId};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row, postgres::PgRow};
use uuid::Uuid;

use crate::{StoreError, TenantTx, human_approval::session_revocation_digest};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Restrictions {
    suppressions: Vec<Suppression>,
    revocations: Vec<Revocation>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suppression {
    tenant_id: Uuid,
    suppression_id: Uuid,
    channel: Option<String>,
    destination_hash: Option<String>,
    destination_fingerprints: Vec<String>,
    scope: String,
    permanent: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    tenant_id: Uuid,
    revocation_id: Uuid,
    user_id: Uuid,
    kind: String,
    session_digest: Option<String>,
    revoked_at: DateTime<Utc>,
}

fn suppression(row: &PgRow) -> Result<Suppression, StoreError> {
    Ok(Suppression {
        tenant_id: row.try_get("tenant_id")?,
        suppression_id: row.try_get("suppression_id")?,
        channel: row.try_get("channel")?,
        destination_hash: row.try_get("normalized_destination_hash")?,
        destination_fingerprints: row.try_get("destination_fingerprints")?,
        scope: row.try_get("scope")?,
        permanent: row.try_get("permanent")?,
        created_at: row.try_get("created_at")?,
    })
}

fn revocation(row: &PgRow) -> Result<Revocation, StoreError> {
    let tenant = row.try_get("tenant_id")?;
    let user = row.try_get("user_id")?;
    let session: Option<String> = row.try_get("session_id")?;
    let digest = match session {
        Some(id) => Some(session_revocation_digest(
            TenantId::from_uuid(tenant),
            UserId::from_uuid(user),
            &id,
        )),
        None => row.try_get("session_digest")?,
    };
    Ok(Revocation {
        tenant_id: tenant,
        revocation_id: row.try_get("revocation_id")?,
        user_id: user,
        kind: row.try_get("kind")?,
        session_digest: digest,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn fingerprints(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.len() <= 16
        && values.iter().all(|tag| {
            let Some((kid, value)) = tag.split_once(':') else {
                return false;
            };
            !kid.is_empty()
                && kid.len() <= 16
                && kid.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
                && hash(value)
                && seen.insert(tag)
        })
}

fn compatible(left: &Suppression, right: &Suppression) -> bool {
    left.tenant_id == right.tenant_id
        && left.suppression_id == right.suppression_id
        && left.channel == right.channel
        && left.scope == right.scope
        && left.permanent == right.permanent
        && left.created_at == right.created_at
        && (left.destination_hash == right.destination_hash
            || left
                .destination_fingerprints
                .iter()
                .any(|tag| right.destination_fingerprints.contains(tag)))
}

impl Restrictions {
    pub(crate) fn validate(&self, exported_at: DateTime<Utc>) -> Result<(), StoreError> {
        let mut ids = BTreeSet::new();
        for row in &self.suppressions {
            let channel = row.channel.as_ref().is_none_or(|c| {
                serde_json::from_value::<mk_domain::Channel>(serde_json::Value::String(c.clone()))
                    .is_ok()
            });
            let shape = match row.scope.as_str() {
                "tenant" => {
                    row.channel.is_none()
                        && row.destination_hash.is_none()
                        && row.destination_fingerprints.is_empty()
                }
                "channel" => {
                    row.channel.is_some()
                        && row.destination_hash.is_none()
                        && row.destination_fingerprints.is_empty()
                }
                "destination" => {
                    row.channel.is_some()
                        && row.destination_hash.as_deref().is_some_and(hash)
                        && !row.destination_fingerprints.is_empty()
                }
                _ => false,
            };
            if row.tenant_id.is_nil()
                || row.suppression_id.is_nil()
                || !ids.insert(row.suppression_id)
                || row.created_at > exported_at
                || !channel
                || !shape
                || !fingerprints(&row.destination_fingerprints)
            {
                return Err(StoreError::Conflict("invalid recovery suppression"));
            }
        }
        ids.clear();
        for row in &self.revocations {
            let shape = match row.kind.as_str() {
                "user" => row.session_digest.is_none(),
                "session" => row
                    .session_digest
                    .as_deref()
                    .is_some_and(|d| d.strip_prefix("sha256:").is_some_and(hash)),
                _ => false,
            };
            if row.tenant_id.is_nil()
                || row.user_id.is_nil()
                || row.revocation_id.is_nil()
                || !ids.insert(row.revocation_id)
                || row.revoked_at > exported_at
                || !shape
            {
                return Err(StoreError::Conflict("invalid recovery revocation"));
            }
        }
        Ok(())
    }

    pub(crate) fn tenants(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.suppressions
            .iter()
            .map(|r| r.tenant_id)
            .chain(self.revocations.iter().map(|r| r.tenant_id))
    }

    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.suppressions.len(), self.revocations.len())
    }

    pub(crate) async fn export_tenant(
        &mut self,
        conn: &mut PgConnection,
        tenant: Uuid,
    ) -> Result<(), StoreError> {
        for row in sqlx::query("SELECT * FROM kernel.suppressions WHERE tenant_id=$1 AND lifted_at IS NULL ORDER BY suppression_id")
            .bind(tenant).fetch_all(&mut *conn).await? {
            self.suppressions.push(suppression(&row)?);
        }
        for row in sqlx::query(
            "SELECT * FROM kernel.revocations WHERE tenant_id=$1 ORDER BY revocation_id",
        )
        .bind(tenant)
        .fetch_all(&mut *conn)
        .await?
        {
            self.revocations.push(revocation(&row)?);
        }
        Ok(())
    }

    pub(crate) async fn validate_retained(&self, tx: &mut TenantTx<'_>) -> Result<(), StoreError> {
        for row in sqlx::query("SELECT * FROM kernel.suppressions WHERE tenant_id=$1")
            .bind(tx.tenant().0)
            .fetch_all(tx.conn())
            .await?
        {
            let existing = suppression(&row)?;
            let expected = self
                .suppressions
                .iter()
                .find(|r| r.suppression_id == existing.suppression_id);
            if let Some(expected) = expected {
                if !compatible(&existing, expected) {
                    return Err(StoreError::Conflict(
                        "recovery suppression identity conflict",
                    ));
                }
            } else if row
                .try_get::<Option<DateTime<Utc>>, _>("lifted_at")?
                .is_none()
            {
                // Do not silently drop a retained opt-out. A legitimate later
                // lift needs explicit reconciliation, not automatic permission.
                return Err(StoreError::Conflict(
                    "ledger omits retained active suppression",
                ));
            }
        }
        for row in sqlx::query("SELECT * FROM kernel.revocations WHERE tenant_id=$1")
            .bind(tx.tenant().0)
            .fetch_all(tx.conn())
            .await?
        {
            let existing = revocation(&row)?;
            if !self.revocations.contains(&existing) {
                return Err(StoreError::Conflict(
                    "ledger omits or conflicts with retained revocation",
                ));
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
        for row in self.suppressions.iter().filter(|r| r.tenant_id == tenant) {
            sqlx::query("INSERT INTO kernel.suppressions(tenant_id,suppression_id,channel,normalized_destination_hash,destination_fingerprints,scope,permanent,created_at,reason,source)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,'recovery','recovery') ON CONFLICT(tenant_id,suppression_id) DO UPDATE
                SET lifted_at=NULL,lifted_by=NULL,destination_fingerprints=ARRAY(SELECT DISTINCT unnest(kernel.suppressions.destination_fingerprints || EXCLUDED.destination_fingerprints))")
                .bind(tenant).bind(row.suppression_id).bind(&row.channel).bind(&row.destination_hash)
                .bind(&row.destination_fingerprints).bind(&row.scope).bind(row.permanent).bind(row.created_at).execute(tx.conn()).await?;
            crate::audit::append_event(tx, mk_audit::NewEvent { tenant_id: tx.tenant(), occurred_at: now,
                actor_type: mk_audit::ActorType::System, actor_id: "recovery-ledger-replay", action_id: None,
                event_type: mk_audit::EventType::SuppressionAdded,
                payload_redacted: serde_json::json!({"suppression_id":row.suppression_id,"channel":row.channel,"permanent":row.permanent,"ledger_digest":digest}),
                trace_id: None, policy_version: mk_policy::POLICY_VERSION.0 }).await?;
        }
        for row in self.revocations.iter().filter(|r| r.tenant_id == tenant) {
            sqlx::query("INSERT INTO kernel.revocations(tenant_id,revocation_id,user_id,kind,session_digest,revoked_at,revoked_by,reason)
                VALUES($1,$2,$3,$4,$5,$6,$7,'recovery') ON CONFLICT(tenant_id,revocation_id) DO NOTHING")
                .bind(tenant).bind(row.revocation_id).bind(row.user_id).bind(&row.kind).bind(&row.session_digest)
                .bind(row.revoked_at).bind(Uuid::nil()).execute(tx.conn()).await?;
            crate::audit::append_event(tx, mk_audit::NewEvent { tenant_id: tx.tenant(), occurred_at: now,
                actor_type: mk_audit::ActorType::System, actor_id: "recovery-ledger-replay", action_id: None,
                event_type: mk_audit::EventType::PrincipalRevoked,
                payload_redacted: serde_json::json!({"revocation_id":row.revocation_id,"kind":row.kind,"ledger_digest":digest}),
                trace_id: None, policy_version: mk_policy::POLICY_VERSION.0 }).await?;
        }
        Ok(())
    }

    pub(crate) async fn pending(&self, tx: &mut TenantTx<'_>) -> Result<usize, StoreError> {
        let mut pending = 0;
        let tenant = tx.tenant().0;
        for expected in self.suppressions.iter().filter(|r| r.tenant_id == tenant) {
            let actual = sqlx::query("SELECT * FROM kernel.suppressions WHERE tenant_id=$1 AND suppression_id=$2 AND lifted_at IS NULL")
                .bind(tenant).bind(expected.suppression_id).fetch_optional(tx.conn()).await?;
            let enforced = if let Some(actual) = actual {
                let actual = suppression(&actual)?;
                compatible(&actual, expected)
                    && expected
                        .destination_fingerprints
                        .iter()
                        .all(|tag| actual.destination_fingerprints.contains(tag))
            } else {
                false
            };
            pending += usize::from(!enforced);
        }
        for expected in self.revocations.iter().filter(|r| r.tenant_id == tenant) {
            let actual = sqlx::query(
                "SELECT * FROM kernel.revocations WHERE tenant_id=$1 AND revocation_id=$2",
            )
            .bind(tenant)
            .bind(expected.revocation_id)
            .fetch_optional(tx.conn())
            .await?;
            let enforced = match actual {
                Some(row) => revocation(&row)? == *expected,
                None => false,
            };
            pending += usize::from(!enforced);
        }
        Ok(pending)
    }
}
