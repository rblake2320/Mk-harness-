//! Authenticated mobile-adapter callbacks:
//! `POST /adapter/v1/work-orders/{task_id}/callbacks`.
//!
//! Order of checks (every failure is audited, none reveals which secret
//! or adapter exists): tenant+agent headers → registration active → HMAC
//! over the exact bytes with every live credential → nonce single-use
//! (durable, same transaction) → body contract → monotonic state change.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use mk_audit::ActorType;
use mk_contracts::mobile::{CallbackKind, MobileCallback};
use mk_crypto::hmac_sig::{HDR_AGENT, HDR_NONCE, HDR_SIGNATURE, HDR_TENANT, HDR_TIMESTAMP};
use mk_crypto::{NonceWindow, VerifyParams, verify_hmac};
use mk_domain::{ActionId, ActionState, TenantId, Transition};
use mk_store::actions::{self, Actor};
use mk_store::{StoreError, adapters, outbox};
use serde::Serialize;
use serde_json::json;

use crate::error::ApiError;
use crate::metrics::AuthFailLabels;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct CallbackResponse {
    pub applied: bool,
    pub state: ActionState,
}

fn unauthorized(headers: &HeaderMap) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "CALLBACK_REJECTED",
        "Callback rejected",
    )
    .with_request_id(headers)
}

pub async fn callback(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    body: Bytes,
) -> Result<Json<CallbackResponse>, ApiError> {
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let tenant: TenantId = h(HDR_TENANT).parse().map_err(|_| unauthorized(&headers))?;
    let agent_id = h(HDR_AGENT);
    let action_id = uuid::Uuid::try_parse(&task_id)
        .map(ActionId::from_uuid)
        .map_err(|_| unauthorized(&headers))?;
    let now = Utc::now();
    let path = format!("/adapter/v1/work-orders/{task_id}/callbacks");
    let fail = |code: &str| {
        st.metrics
            .hmac_failures
            .get_or_create(&AuthFailLabels {
                code: code.to_owned(),
            })
            .inc();
    };

    let mut tx = st
        .store
        .begin(tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let reg = match adapters::get_by_agent(&mut tx, &agent_id).await {
        Ok(r) if r.is_active(now) => r,
        Ok(r) => {
            let _ = adapters::record_signature_failure(
                &mut tx,
                Some(r.adapter_id),
                "adapter_revoked",
                now,
            )
            .await;
            let _ = tx.commit().await;
            fail("adapter_revoked");
            return Err(unauthorized(&headers));
        }
        Err(_) => {
            let _ = adapters::record_signature_failure(&mut tx, None, "adapter_unknown", now).await;
            let _ = tx.commit().await;
            fail("adapter_unknown");
            return Err(unauthorized(&headers));
        }
    };
    let secrets = adapters::live_secrets(&mut tx, &st.master, reg.adapter_id, now)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let (ts, nonce, sig) = (h(HDR_TIMESTAMP), h(HDR_NONCE), h(HDR_SIGNATURE));
    let mut last_err = mk_crypto::HmacError::SignatureMismatch;
    let verified = secrets.iter().any(|s| {
        match verify_hmac(
            s,
            VerifyParams {
                method: "POST",
                path: &path,
                timestamp: &ts,
                nonce: &nonce,
                signature_hex: &sig,
                body: &body,
                now_unix: now.timestamp(),
                tolerance_secs: st.callback_tolerance_secs,
            },
        ) {
            Ok(()) => true,
            Err(e) => {
                last_err = e;
                false
            }
        }
    });
    if !verified {
        let _ =
            adapters::record_signature_failure(&mut tx, Some(reg.adapter_id), last_err.code(), now)
                .await;
        let _ = tx.commit().await;
        fail(last_err.code());
        return Err(unauthorized(&headers));
    }
    let retain = NonceWindow::from_tolerance(st.callback_tolerance_secs).retain_secs;
    if let Err(e) = adapters::record_nonce(
        &mut tx,
        reg.adapter_id,
        &nonce,
        chrono::Duration::seconds(retain),
        now,
    )
    .await
    {
        if matches!(e, StoreError::Conflict(_)) {
            // The nonce insert failed inside this tx; audit in a fresh one.
            drop(tx);
            let mut t2 = st
                .store
                .begin(tenant)
                .await
                .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            let _ = adapters::record_signature_failure(
                &mut t2,
                Some(reg.adapter_id),
                "nonce_replayed",
                now,
            )
            .await;
            let _ = t2.commit().await;
            fail("nonce_replayed");
            return Err(unauthorized(&headers));
        }
        return Err(ApiError::from(e).with_request_id(&headers));
    }
    adapters::touch_last_used(&mut tx, reg.adapter_id, now)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;

    // Authenticated. Now the body must match a published callback contract.
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CONTRACT_VIOLATION",
            "not json",
        )
        .with_request_id(&headers)
    })?;
    let (cb, kind) =
        MobileCallback::parse(&value).map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let body_digest = mk_crypto::Digest::of(&body).to_string();
    let actor = Actor {
        actor_type: ActorType::Adapter,
        actor_id: &agent_id,
        trace_id: None,
        policy_version: mk_policy::POLICY_VERSION.0,
    };
    let action = actions::get_for_update(&mut tx, action_id)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    // The callback must belong to the adapter that was dispatched to.
    if action
        .request
        .arguments
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        != Some(agent_id.as_str())
    {
        adapters::record_callback(
            &mut tx,
            reg.adapter_id,
            action_id,
            kind_str(kind),
            &body_digest,
            &nonce,
            false,
            now,
        )
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
        tx.commit()
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "CALLBACK_WRONG_AGENT",
            "Action was not dispatched to this agent",
        )
        .with_request_id(&headers));
    }
    let (applied, state) = match (kind, action.state) {
        (CallbackKind::Executing, ActionState::Dispatching) => (false, ActionState::Dispatching),
        (CallbackKind::Complete, ActionState::Dispatching) => {
            actions::transition(&mut tx, action_id, Transition::Complete, None, actor, now)
                .await
                .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            outbox::record_attempt_end(
                &mut tx,
                action_id,
                action.attempt,
                "completed",
                None,
                Some(reg.adapter_id.0),
                Some(&task_id),
                Some(&body_digest),
                now,
            )
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            outbox::release_lease_any(&mut tx, action_id)
                .await
                .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            (true, ActionState::Completed)
        }
        (CallbackKind::Failed, ActionState::Dispatching) => {
            actions::transition(
                &mut tx,
                action_id,
                Transition::FailFinal,
                Some(&cb.error_code),
                actor,
                now,
            )
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            outbox::record_attempt_end(
                &mut tx,
                action_id,
                action.attempt,
                "failed_final",
                Some(&cb.error_code),
                Some(reg.adapter_id.0),
                Some(&task_id),
                Some(&body_digest),
                now,
            )
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            outbox::dead_letter(
                &mut tx,
                action_id,
                "failed_final",
                action.attempt,
                Some(&cb.error_code),
                json!({"source": "device_callback", "error_code": cb.error_code}),
                now,
            )
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            outbox::release_lease_any(&mut tx, action_id)
                .await
                .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            (true, ActionState::FailedFinal)
        }
        // Monotonic: anything after a terminal state is an idempotent no-op.
        (_, s) if s.is_terminal() => (false, s),
        (_, s) => {
            // Executing/complete for an action that never reached Dispatching
            // is a protocol error from the device; record and refuse.
            adapters::record_callback(
                &mut tx,
                reg.adapter_id,
                action_id,
                kind_str(kind),
                &body_digest,
                &nonce,
                false,
                now,
            )
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            tx.commit()
                .await
                .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "CALLBACK_OUT_OF_ORDER",
                "Action is not dispatching",
            )
            .detail(s.to_string())
            .with_request_id(&headers));
        }
    };
    adapters::record_callback(
        &mut tx,
        reg.adapter_id,
        action_id,
        kind_str(kind),
        &body_digest,
        &nonce,
        applied,
        now,
    )
    .await
    .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    if applied {
        st.metrics.callbacks_applied.inc();
    } else {
        st.metrics.callbacks_duplicate.inc();
    }
    Ok(Json(CallbackResponse { applied, state }))
}

const fn kind_str(k: CallbackKind) -> &'static str {
    match k {
        CallbackKind::Executing => "executing",
        CallbackKind::Complete => "complete",
        CallbackKind::Failed => "failed",
    }
}
