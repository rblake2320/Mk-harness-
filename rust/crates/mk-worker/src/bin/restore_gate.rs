//! `mk-restore-gate`: restoration without re-sending (contract row O9).
//!
//! Run against a freshly restored database BEFORE any dispatch is enabled. It
//! never enables anything — enabling the global switch is a human operator
//! action with a passkey step-up. Every check prints a JSON line; the exit code
//! is non-zero unless every check passed.
//!
//!   mk-restore-gate --restored-at <RFC3339> [--apply]
//!
//! Without `--apply` it reports what it would change. With `--apply` it:
//!   * marks in-flight actions (dispatching) as reconciliation_required and
//!     their delivery records as submission_unknown ("uncertain → unknown");
//!   * revokes every live approval created before `--restored-at` and cancels
//!     the queued actions they authorised (pre-restore approvals are invalid);
//!
//! Checks (all must pass): global dispatch disabled; audit chain verifies for
//! every tenant; suppression ledger readable with row count; every active
//! sender credential and adapter credential unseals with the configured
//! keyring; no action left in dispatching; no delivery left in
//! submission_started; no live approval older than the restore point.
//!
//! Env: MK_DATABASE_URL (owner identity for --apply; readonly suffices for
//! report mode), MK_MASTER_KEY, MK_KEK / MK_KEK_ID.

use chrono::{DateTime, Utc};
use mk_crypto::MasterKey;
use mk_domain::Transition;
use mk_store::actions::{self, Actor};
use mk_store::{Store, keys};
use serde_json::json;
use sqlx::Row;

fn report(check: &str, ok: bool, detail: serde_json::Value) {
    println!("{}", json!({"check": check, "ok": ok, "detail": detail}));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let restored_at: DateTime<Utc> = args
        .iter()
        .position(|a| a == "--restored-at")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
        .ok_or_else(|| {
            anyhow::anyhow!("usage: mk-restore-gate --restored-at <RFC3339> [--apply]")
        })?;
    let apply = args.iter().any(|a| a == "--apply");
    let master = MasterKey::from_base64(&std::env::var("MK_MASTER_KEY")?)
        .map_err(|e| anyhow::anyhow!("MK_MASTER_KEY: {e}"))?;
    let store = Store::connect(&mk_store::database_url_from_env()?, 4).await?;
    let pool = store.pool();
    let now = Utc::now();
    let mut all_ok = true;
    let mut ok = |c: &str, pass: bool, d: serde_json::Value| {
        all_ok &= pass;
        report(c, pass, d);
    };
    let actor = Actor {
        actor_type: mk_audit::ActorType::System,
        actor_id: "restore-gate",
        trace_id: None,
        policy_version: mk_policy::POLICY_VERSION.0,
    };

    // 1. Dispatch must be globally disabled on a restored environment.
    let enabled = mk_store::policy::global_dispatch_enabled(pool).await?;
    ok(
        "global_dispatch_disabled",
        !enabled,
        json!({"dispatch_enabled": enabled}),
    );

    // 2. Keyring loads (credentials are recoverable) — prerequisite for 5.
    let keyring = match keys::keyring_from_env(pool, &master).await {
        Ok(k) => {
            ok(
                "keyring_loads",
                true,
                json!({"current": k.current_version(), "versions": k.versions()}),
            );
            Some(k)
        }
        Err(e) => {
            ok("keyring_loads", false, json!({"error": e.to_string()}));
            None
        }
    };

    // 3. Audit chain per tenant.
    let tenants = mk_store::audit::all_tenants(pool).await?;
    let mut chain_failures = Vec::new();
    for t in &tenants {
        let mut tx = store.begin(*t).await?;
        if let Err(e) = mk_store::audit::verify_tenant(&mut tx).await {
            chain_failures.push(json!({"tenant": t, "error": e.to_string()}));
        }
    }
    ok(
        "audit_chain_verified",
        chain_failures.is_empty(),
        json!({"tenants": tenants.len(), "failures": chain_failures}),
    );

    // 4. Suppression / deletion ledger present and readable.
    let sup: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel.suppressions WHERE lifted_at IS NULL")
            .fetch_one(pool)
            .await?;
    let rev: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel.revocations")
        .fetch_one(pool)
        .await?;
    ok(
        "suppression_ledger_loaded",
        true,
        json!({"live_suppressions": sup, "revocations": rev}),
    );

    // 5. Sender bindings and adapter credentials unseal with the loaded keyring.
    if let Some(k) = &keyring {
        let mut bad = 0u64;
        let mut total = 0u64;
        for t in &tenants {
            let mut tx = store.begin(*t).await?;
            let ids: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT sender_identity_id FROM kernel.sender_identities WHERE tenant_id = $1 AND status = 'active'")
                .bind(t.0)
                .fetch_all(tx.raw_conn())
                .await?;
            for id in ids {
                total += 1;
                if mk_store::messaging::sender_secret(&mut tx, k, id)
                    .await
                    .is_err()
                {
                    bad += 1;
                }
            }
            let regs: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT adapter_id FROM kernel.adapter_registrations WHERE tenant_id = $1 AND revoked_at IS NULL")
                .bind(t.0)
                .fetch_all(tx.raw_conn())
                .await?;
            for a in regs {
                total += 1;
                if mk_store::adapters::live_secrets(
                    &mut tx,
                    k,
                    mk_domain::AdapterId::from_uuid(a),
                    now,
                )
                .await
                .is_err()
                {
                    bad += 1;
                }
            }
        }
        ok(
            "credentials_unseal",
            bad == 0,
            json!({"checked": total, "unreadable": bad}),
        );
    } else {
        ok(
            "credentials_unseal",
            false,
            json!({"skipped": "keyring did not load"}),
        );
    }

    // 6. In-flight actions → reconciliation_required; deliveries → submission_unknown.
    let inflight =
        sqlx::query("SELECT tenant_id, action_id FROM kernel.actions WHERE state = 'dispatching'")
            .fetch_all(pool)
            .await?;
    let mut fixed = 0u64;
    if apply {
        for r in &inflight {
            let t = mk_domain::TenantId::from_uuid(r.try_get("tenant_id")?);
            let a = mk_domain::ActionId::from_uuid(r.try_get("action_id")?);
            let mut tx = store.begin(t).await?;
            actions::transition(
                &mut tx,
                a,
                Transition::RequireReconciliation,
                Some("restored_in_flight"),
                actor,
                now,
            )
            .await?;
            sqlx::query("UPDATE kernel.message_deliveries SET state = 'submission_unknown', reconciliation_note = 'restored while in flight', updated_at = $3 WHERE tenant_id = $1 AND action_id = $2 AND state = 'submission_started'")
                .bind(t.0).bind(a.0).bind(now).execute(tx.raw_conn()).await?;
            mk_store::outbox::release_lease_any(&mut tx, a).await?;
            tx.commit().await?;
            fixed += 1;
        }
    }
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel.actions WHERE state = 'dispatching'")
            .fetch_one(pool)
            .await?;
    let started: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.message_deliveries WHERE state = 'submission_started'",
    )
    .fetch_one(pool)
    .await?;
    ok(
        "in_flight_marked_unknown",
        remaining == 0 && started == 0,
        json!({"found_in_flight": inflight.len(), "marked": fixed, "remaining_dispatching": remaining, "remaining_submission_started": started, "apply": apply}),
    );

    // 7. Pre-restore pending approvals are invalid.
    let pre = sqlx::query("SELECT tenant_id, approval_id, action_id FROM kernel.approvals WHERE decision = 'approved' AND consumed_at IS NULL AND revoked_at IS NULL AND created_at < $1")
        .bind(restored_at)
        .fetch_all(pool)
        .await?;
    let mut revoked = 0u64;
    if apply {
        for r in &pre {
            let t = mk_domain::TenantId::from_uuid(r.try_get("tenant_id")?);
            let ap = mk_domain::ApprovalId::from_uuid(r.try_get("approval_id")?);
            let a = mk_domain::ActionId::from_uuid(r.try_get("action_id")?);
            let mut tx = store.begin(t).await?;
            let by = mk_domain::UserId::from_uuid(uuid::Uuid::nil());
            if mk_store::approvals::revoke(&mut tx, ap, by, actor, now)
                .await
                .is_ok()
            {
                let act = actions::get_for_update(&mut tx, a).await?;
                if act.state.is_cancellable() {
                    actions::transition(
                        &mut tx,
                        a,
                        Transition::Cancel,
                        Some("pre_restore_approval_invalidated"),
                        actor,
                        now,
                    )
                    .await?;
                }
                revoked += 1;
            }
            tx.commit().await?;
        }
    }
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel.approvals WHERE decision = 'approved' AND consumed_at IS NULL AND revoked_at IS NULL AND created_at < $1")
        .bind(restored_at)
        .fetch_one(pool)
        .await?;
    ok(
        "pre_restore_approvals_invalidated",
        left == 0,
        json!({"found": pre.len(), "revoked": revoked, "remaining": left, "restored_at": restored_at, "apply": apply}),
    );

    // 8. Reconciliation backlog is visible (not a failure, but must be listed for the operator).
    let unknown: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.actions WHERE state = 'reconciliation_required'",
    )
    .fetch_one(pool)
    .await?;
    report(
        "reconciliation_backlog",
        true,
        json!({"actions_requiring_human_reconciliation": unknown,
        "note": "resolve each against provider records before any replacement message; dispatch stays disabled until the release owner authorises"}),
    );

    println!(
        "{}",
        json!({"gate": if all_ok { "PASS" } else { "FAIL" }, "apply": apply,
        "next": if all_ok { "operator may enable dispatch via /kill-switch/global with passkey step-up after reviewing the reconciliation backlog" } else { "do not enable dispatch" }})
    );
    if !all_ok {
        std::process::exit(1);
    }
    Ok(())
}
