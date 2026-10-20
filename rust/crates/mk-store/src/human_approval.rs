//! Separated human-approval authority (WP06): registered WebAuthn credentials,
//! kernel-issued single-use challenges bound to an action digest, and
//! session/user revocations.

use chrono::{DateTime, Duration, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_crypto::webauthn::{CoseAlg, CredentialPublicKey, RegisteredCredential, approval_challenge};
use mk_crypto::Digest;
use mk_domain::{ActionId, TenantId, UserId};
use serde::Serialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

pub const REGISTER_CHALLENGE_TTL_SECS: i64 = 300;
pub const APPROVE_CHALLENGE_TTL_SECS: i64 = 120;

#[derive(Debug, Clone, Serialize)]
pub struct CredentialView {
    pub credential_row_id: Uuid,
    pub user_id: UserId,
    pub credential_id_b64: String,
    pub alg: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub credential_row_id: Uuid,
    pub user_id: UserId,
    pub credential_id: Vec<u8>,
    pub public_key: CredentialPublicKey,
    pub sign_count: u32,
}

#[derive(Debug, Clone)]
pub struct IssuedChallenge {
    pub challenge_id: Uuid,
    pub challenge: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Register,
    Approve,
    /// Platform-operator step-up bound to an operation digest (no action).
    Operator,
}

fn random32() -> [u8; 32] {
    use rand::RngCore as _;
    let mut n = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// Issue a registration challenge for `user`.
pub async fn issue_register_challenge(
    tx: &mut TenantTx<'_>,
    user: UserId,
    now: DateTime<Utc>,
) -> Result<IssuedChallenge, StoreError> {
    let nonce = random32();
    let challenge = nonce.to_vec(); // registration binds to user via the row
    let expires_at = now + Duration::seconds(REGISTER_CHALLENGE_TTL_SECS);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO kernel.approval_challenges (tenant_id, user_id, kind, nonce, challenge, created_at, expires_at)
         VALUES ($1,$2,'register',$3,$4,$5,$6) RETURNING challenge_id",
    )
    .bind(tx.tenant().0)
    .bind(user.0)
    .bind(nonce.as_slice())
    .bind(challenge.as_slice())
    .bind(now)
    .bind(expires_at)
    .fetch_one(tx.conn())
    .await?;
    Ok(IssuedChallenge { challenge_id: id, challenge, expires_at })
}

/// Issue an approval challenge bound to `(tenant, user, action, digest)`.
pub async fn issue_approve_challenge(
    tx: &mut TenantTx<'_>,
    user: UserId,
    action_id: ActionId,
    digest: &Digest,
    now: DateTime<Utc>,
) -> Result<IssuedChallenge, StoreError> {
    let nonce = random32();
    let tenant = tx.tenant();
    let challenge = approval_challenge(
        tenant.0.as_bytes(),
        user.0.as_bytes(),
        action_id.0.as_bytes(),
        digest,
        &nonce,
    )
    .to_vec();
    let expires_at = now + Duration::seconds(APPROVE_CHALLENGE_TTL_SECS);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO kernel.approval_challenges (tenant_id, user_id, kind, action_id, action_digest, nonce, challenge, created_at, expires_at)
         VALUES ($1,$2,'approve',$3,$4,$5,$6,$7,$8) RETURNING challenge_id",
    )
    .bind(tenant.0)
    .bind(user.0)
    .bind(action_id.0)
    .bind(digest.to_string())
    .bind(nonce.as_slice())
    .bind(challenge.as_slice())
    .bind(now)
    .bind(expires_at)
    .fetch_one(tx.conn())
    .await?;
    Ok(IssuedChallenge { challenge_id: id, challenge, expires_at })
}

/// Atomically consume a live challenge of `kind` for `user`. For `Approve`, the
/// stored action id and digest must equal the ones being approved — a challenge
/// issued for one version of an action is useless for any other.
pub async fn consume_challenge(
    tx: &mut TenantTx<'_>,
    user: UserId,
    kind: ChallengeKind,
    challenge: &[u8],
    bound: Option<(ActionId, &Digest)>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let kind_s = match kind {
        ChallengeKind::Register => "register",
        ChallengeKind::Approve => "approve",
        ChallengeKind::Operator => "operator",
    };
    // Burn first (any live row with these bytes for this user), then check the
    // binding. A challenge presented against the wrong action is spent, not
    // left live for a second try.
    let row = sqlx::query(
        "UPDATE kernel.approval_challenges SET consumed_at = $1
         WHERE tenant_id = $2 AND user_id = $3 AND kind = $4 AND challenge = $5
           AND consumed_at IS NULL AND expires_at > $1
         RETURNING action_id, action_digest",
    )
    .bind(now)
    .bind(tx.tenant().0)
    .bind(user.0)
    .bind(kind_s)
    .bind(challenge)
    .fetch_optional(tx.conn())
    .await?
    .ok_or(StoreError::Conflict("challenge unknown, expired, or already consumed"))?;
    let stored_action: Option<Uuid> = row.try_get("action_id")?;
    let stored_digest: Option<String> = row.try_get("action_digest")?;
    match (kind, bound) {
        (ChallengeKind::Register, None) if stored_action.is_none() && stored_digest.is_none() => Ok(()),
        (ChallengeKind::Approve, Some((a, d)))
            if stored_action == Some(a.0) && stored_digest.as_deref() == Some(d.to_string().as_str()) =>
        {
            Ok(())
        }
        (ChallengeKind::Operator, Some((a, d)))
            if a.0.is_nil() && stored_action.is_none() && stored_digest.as_deref() == Some(d.to_string().as_str()) =>
        {
            Ok(())
        }
        _ => Err(StoreError::Conflict("challenge is bound to a different action or operation")),
    }
}

/// Issue a platform-operator step-up challenge bound to `op_digest`
/// (e.g. `Digest::of(b"global-kill-switch:enable")`).
pub async fn issue_operator_challenge(
    tx: &mut TenantTx<'_>,
    user: UserId,
    op_digest: &Digest,
    now: DateTime<Utc>,
) -> Result<IssuedChallenge, StoreError> {
    let nonce = random32();
    let tenant = tx.tenant();
    let challenge = approval_challenge(tenant.0.as_bytes(), user.0.as_bytes(), Uuid::nil().as_bytes(), op_digest, &nonce).to_vec();
    let expires_at = now + Duration::seconds(APPROVE_CHALLENGE_TTL_SECS);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO kernel.approval_challenges (tenant_id, user_id, kind, action_digest, nonce, challenge, created_at, expires_at)
         VALUES ($1,$2,'operator',$3,$4,$5,$6,$7) RETURNING challenge_id",
    )
    .bind(tenant.0)
    .bind(user.0)
    .bind(op_digest.to_string())
    .bind(nonce.as_slice())
    .bind(challenge.as_slice())
    .bind(now)
    .bind(expires_at)
    .fetch_one(tx.conn())
    .await?;
    Ok(IssuedChallenge { challenge_id: id, challenge, expires_at })
}


pub async fn insert_credential(
    tx: &mut TenantTx<'_>,
    user: UserId,
    cred: &RegisteredCredential,
    label: &str,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    let row_id: Uuid = sqlx::query_scalar(
        "INSERT INTO kernel.approval_credentials (tenant_id, user_id, credential_id, alg, public_key, sign_count, aaguid, attestation_fmt, label, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING credential_row_id",
    )
    .bind(tx.tenant().0)
    .bind(user.0)
    .bind(cred.credential_id.as_slice())
    .bind(cred.public_key.alg.as_str())
    .bind(cred.public_key.key.as_slice())
    .bind(i64::from(cred.sign_count))
    .bind(cred.aaguid.as_slice())
    .bind(&cred.attestation_format)
    .bind(label)
    .bind(now)
    .fetch_one(tx.conn())
    .await
    .map_err(|e| match StoreError::from(e) {
        StoreError::Conflict(_) => StoreError::Conflict("credential already registered"),
        other => other,
    })?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &user.to_string(),
            action_id: None,
            event_type: EventType::ApprovalCredentialRegistered,
            payload_redacted: json!({"credential_row_id": row_id, "alg": cred.public_key.alg.as_str(),
                                     "attestation_fmt": cred.attestation_format, "user_verified": cred.user_verified}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(row_id)
}

/// A live credential for `user` with this raw credential id, locked for update
/// so two concurrent assertions cannot both pass the counter check.
pub async fn credential_for_update(
    tx: &mut TenantTx<'_>,
    user: UserId,
    credential_id: &[u8],
) -> Result<StoredCredential, StoreError> {
    let r = sqlx::query(
        "SELECT credential_row_id, user_id, credential_id, alg, public_key, sign_count FROM kernel.approval_credentials
         WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3 AND revoked_at IS NULL FOR UPDATE",
    )
    .bind(tx.tenant().0)
    .bind(user.0)
    .bind(credential_id)
    .fetch_optional(tx.conn())
    .await?
    .ok_or(StoreError::NotFound)?;
    let alg = CoseAlg::parse(&r.try_get::<String, _>("alg")?).map_err(|_| StoreError::Corrupt("alg"))?;
    Ok(StoredCredential {
        credential_row_id: r.try_get("credential_row_id")?,
        user_id: UserId::from_uuid(r.try_get("user_id")?),
        credential_id: r.try_get("credential_id")?,
        public_key: CredentialPublicKey { alg, key: r.try_get("public_key")? },
        sign_count: u32::try_from(r.try_get::<i64, _>("sign_count")?).map_err(|_| StoreError::Corrupt("sign_count"))?,
    })
}

pub async fn record_use(
    tx: &mut TenantTx<'_>,
    row_id: Uuid,
    new_sign_count: u32,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE kernel.approval_credentials SET sign_count = $1, last_used_at = $2 WHERE tenant_id = $3 AND credential_row_id = $4",
    )
    .bind(i64::from(new_sign_count))
    .bind(now)
    .bind(tx.tenant().0)
    .bind(row_id)
    .execute(tx.conn())
    .await?;
    Ok(())
}

pub async fn list_credentials(tx: &mut TenantTx<'_>, user: UserId) -> Result<Vec<CredentialView>, StoreError> {
    use base64::Engine as _;
    let rows = sqlx::query(
        "SELECT credential_row_id, user_id, credential_id, alg, label, created_at, last_used_at, revoked_at
         FROM kernel.approval_credentials WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at",
    )
    .bind(tx.tenant().0)
    .bind(user.0)
    .fetch_all(tx.conn())
    .await?;
    rows.iter()
        .map(|r| {
            Ok(CredentialView {
                credential_row_id: r.try_get("credential_row_id")?,
                user_id: UserId::from_uuid(r.try_get("user_id")?),
                credential_id_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(r.try_get::<Vec<u8>, _>("credential_id")?),
                alg: r.try_get("alg")?,
                label: r.try_get("label")?,
                created_at: r.try_get("created_at")?,
                last_used_at: r.try_get("last_used_at")?,
                revoked_at: r.try_get("revoked_at")?,
            })
        })
        .collect()
}

pub async fn has_live_credential(tx: &mut TenantTx<'_>, user: UserId) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.approval_credentials WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(tx.tenant().0)
    .bind(user.0)
    .fetch_one(tx.conn())
    .await?;
    Ok(n > 0)
}

pub async fn revoke_credential(
    tx: &mut TenantTx<'_>,
    row_id: Uuid,
    by: UserId,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let res = sqlx::query(
        "UPDATE kernel.approval_credentials SET revoked_at = $1, revoked_by = $2
         WHERE tenant_id = $3 AND credential_row_id = $4 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(by.0)
    .bind(tx.tenant().0)
    .bind(row_id)
    .execute(tx.conn())
    .await?;
    if res.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &by.to_string(),
            action_id: None,
            event_type: EventType::ApprovalCredentialRevoked,
            payload_redacted: json!({"credential_row_id": row_id}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}

// ------------------------------------------------------------------ revocations

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationTarget<'a> {
    /// One session of one user.
    Session(UserId, &'a str),
    /// Every session of a user.
    User(UserId),
}

pub async fn revoke(
    tx: &mut TenantTx<'_>,
    target: RevocationTarget<'_>,
    by: UserId,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    let (kind, sid, uid) = match target {
        RevocationTarget::Session(u, s) => ("session", Some(s), u.0),
        RevocationTarget::User(u) => ("user", None, u.0),
    };
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO kernel.revocations (tenant_id, kind, session_id, user_id, reason, revoked_by, revoked_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING revocation_id",
    )
    .bind(tx.tenant().0)
    .bind(kind)
    .bind(sid)
    .bind(uid)
    .bind(reason)
    .bind(by.0)
    .bind(now)
    .fetch_one(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &by.to_string(),
            action_id: None,
            event_type: EventType::PrincipalRevoked,
            payload_redacted: json!({"revocation_id": id, "kind": kind, "has_reason": !reason.is_empty()}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(id)
}

/// Pool-level (pre-tenant-context) check used while authenticating a request:
/// is this `(tenant, user, session)` revoked? A user revocation covers every
/// session; a session revocation covers that session only.
pub async fn is_revoked(
    pool: &PgPool,
    tenant: TenantId,
    user: UserId,
    session_id: &str,
) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.revocations
         WHERE tenant_id = $1 AND user_id = $2 AND (kind = 'user' OR (kind = 'session' AND session_id = $3))",
    )
    .bind(tenant.0)
    .bind(user.0)
    .bind(session_id)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

/// Transaction-level check at dispatch: was the approver (user or the session
/// that approved) revoked at or after the approval was recorded?
pub async fn approver_revoked_since(
    tx: &mut TenantTx<'_>,
    approver: UserId,
    session_id: Option<&str>,
    approved_at: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.revocations
         WHERE tenant_id = $1 AND user_id = $2 AND revoked_at >= $4
           AND (kind = 'user' OR (kind = 'session' AND session_id = $3))",
    )
    .bind(tx.tenant().0)
    .bind(approver.0)
    .bind(session_id)
    .bind(approved_at)
    .fetch_one(tx.conn())
    .await?;
    Ok(n > 0)
}

/// Housekeeping: purge expired challenges (worker).
pub async fn purge_challenges(pool: &PgPool, now: DateTime<Utc>) -> Result<u64, StoreError> {
    let res = sqlx::query("DELETE FROM kernel.approval_challenges WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
