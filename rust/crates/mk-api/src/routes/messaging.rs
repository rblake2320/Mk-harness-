//! Provider messaging (WP07): sender identities, Twilio status callbacks and
//! inbound webhooks, inbound work queue for async meaning processing, and
//! inbound-health controls.
//!
//! Webhook authentication (row C2): `X-Twilio-Signature` is verified against
//! the **configured** public URL (`MK_PUBLIC_WEBHOOK_BASE` + request path +
//! query) with the sender identity's own auth token. `Host`, `X-Forwarded-*`
//! and any other client-supplied header are never consulted.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use mk_adapters::twilio::{DeliveryState, OptOutSignal, detect_opt_out, verify_twilio_signature};
use mk_crypto::{AdapterSecret, Digest};
use mk_domain::{ActionState, Channel, Transition, UserId};
use mk_store::messaging::{self as ms, EventOutcome, InboundOutcome};
use mk_store::{actions, consent, outbox};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::state::AppState;

const TWIML_EMPTY: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Response></Response>"#;
const MAX_FORM_BYTES: usize = 64 * 1024;

fn public_url(st: &AppState, uri: &Uri) -> Result<String, ApiError> {
    let base = st.public_webhook_base.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "WEBHOOKS_NOT_CONFIGURED",
            "MK_PUBLIC_WEBHOOK_BASE is not set",
        )
    })?;
    let mut url = format!("{}{}", base.trim_end_matches('/'), uri.path());
    if let Some(q) = uri.query() {
        url.push('?');
        url.push_str(q);
    }
    Ok(url)
}

fn parse_form(body: &[u8]) -> Result<Vec<(String, String)>, ApiError> {
    if body.len() > MAX_FORM_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "WEBHOOK_TOO_LARGE",
            "form body too large",
        ));
    }
    Ok(url::form_urlencoded::parse(body).into_owned().collect())
}

fn field<'a>(form: &'a [(String, String)], k: &str) -> Option<&'a str> {
    form.iter()
        .find(|(key, _)| key == k)
        .map(|(_, v)| v.as_str())
}

fn forbidden(code: &str, title: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, code, title)
}

/// Authenticate a Twilio webhook: resolve the sender from the path, verify the
/// signature over the configured public URL, and check the `AccountSid` the
/// provider echoed. Returns the sender (with its secret) and the parsed form.
async fn authenticate(
    st: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    sender_identity_id: Uuid,
    body: &Bytes,
) -> Result<(ms::SenderIdentitySecret, Vec<(String, String)>), ApiError> {
    let url = public_url(st, uri)?;
    let form = parse_form(body)?;
    let sig = headers
        .get("x-twilio-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if sig.is_empty() {
        return Err(forbidden("WEBHOOK_UNSIGNED", "missing X-Twilio-Signature"));
    }
    let sender =
        match ms::sender_secret_by_id(st.store.pool(), &st.keyring, sender_identity_id).await {
            Ok(s) => s,
            // Unknown sender: same answer as a bad signature, so the path cannot be probed.
            Err(mk_store::StoreError::NotFound) => {
                return Err(forbidden("WEBHOOK_SIGNATURE_INVALID", "signature invalid"));
            }
            Err(e) => return Err(e.into()),
        };
    let token = AdapterSecret::new(sender.auth_token.expose_secret());
    if !verify_twilio_signature(&token, &url, &form, sig) {
        st.metrics
            .assertion_failures
            .get_or_create(&crate::metrics::AuthFailLabels {
                code: "webhook_signature_invalid".into(),
            })
            .inc();
        return Err(forbidden("WEBHOOK_SIGNATURE_INVALID", "signature invalid"));
    }
    if field(&form, "AccountSid") != Some(sender.account_sid.as_str()) {
        return Err(forbidden(
            "WEBHOOK_ACCOUNT_MISMATCH",
            "AccountSid does not belong to this sender",
        ));
    }
    if sender.status != "active" {
        return Err(forbidden("SENDER_DISABLED", "sender identity disabled"));
    }
    Ok((sender, form))
}

fn twiml_ok() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "text/xml")],
        TWIML_EMPTY,
    )
        .into_response()
}

fn callback_binding(uri: &Uri) -> Result<Option<(mk_domain::ActionId, i32)>, ApiError> {
    let form: Vec<_> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect();
    let count = |key: &str| form.iter().filter(|(k, _)| k == key).count();
    if count("mk_action") == 0 && count("mk_attempt") == 0 {
        return Ok(None);
    }
    let invalid = || {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CALLBACK_BINDING_INVALID",
            "Invalid attempt binding",
        )
    };
    if count("mk_action") != 1 || count("mk_attempt") != 1 {
        return Err(invalid());
    }
    let action = field(&form, "mk_action")
        .unwrap_or_default()
        .parse()
        .map_err(|_| invalid())?;
    let attempt: i32 = field(&form, "mk_attempt")
        .unwrap_or_default()
        .parse()
        .map_err(|_| invalid())?;
    if attempt < 1 {
        return Err(invalid());
    }
    Ok(Some((action, attempt)))
}

// ------------------------------------------------------------ status callback

/// `POST /webhooks/twilio/status/{sender_identity_id}`
pub async fn twilio_status(
    State(st): State<AppState>,
    Path(sender_identity_id): Path<Uuid>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    let (sender, form) = authenticate(&st, &uri, &headers, sender_identity_id, &body)
        .await
        .map_err(rid)?;
    let message_sid = field(&form, "MessageSid")
        .or_else(|| field(&form, "SmsSid"))
        .unwrap_or_default()
        .to_owned();
    let status = field(&form, "MessageStatus")
        .or_else(|| field(&form, "SmsStatus"))
        .unwrap_or_default()
        .to_owned();
    let error_code = field(&form, "ErrorCode").map(ToOwned::to_owned);
    if !mk_adapters::twilio::valid_message_sid(&message_sid) || status.is_empty() {
        return Err(rid(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "WEBHOOK_FIELDS",
            "MessageSid and MessageStatus required",
        )));
    }
    let now = Utc::now();
    let raw_digest = Digest::of(&body);
    let mut tx = st
        .store
        .begin(sender.tenant_id)
        .await
        .map_err(|e| rid(e.into()))?;
    // Outbound callbacks do not test the inbound-reply path (C8).
    let binding = callback_binding(&uri).map_err(rid)?;
    let Some(delivery) =
        ms::delivery_for_callback(&mut tx, &message_sid, sender_identity_id, binding)
            .await
            .map_err(|e| rid(e.into()))?
    else {
        // A callback for a message we never recorded as submitted: preserve
        // the fact (audit), do nothing else. Could be a reconciliation clue.
        mk_store::audit::append_event(
            &mut tx,
            mk_audit::NewEvent {
                tenant_id: sender.tenant_id,
                occurred_at: now,
                actor_type: mk_audit::ActorType::System,
                actor_id: "twilio-webhook",
                action_id: None,
                event_type: mk_audit::EventType::DeliveryEvent,
                payload_redacted: json!({"unmatched": true, "provider_status": status, "raw_event_digest": raw_digest.to_string()}),
                trace_id: None,
                policy_version: mk_policy::POLICY_VERSION.0,
            },
        )
        .await
        .map_err(|e| rid(e.into()))?;
        tx.commit().await.map_err(|e| rid(e.into()))?;
        return Ok(twiml_ok());
    };
    let current = delivery_state_of(&delivery.state);
    let evidence = DeliveryState::from_twilio_status(&status);
    let folded = evidence.map_or(current, |e| DeliveryState::fold(current, e));
    let read = status == "read";
    let outcome = ms::record_delivery_event(
        &mut tx,
        &delivery,
        &format!("{message_sid}:{status}"),
        &status,
        error_code.as_deref(),
        &raw_digest,
        folded.as_str(),
        read,
        now,
    )
    .await
    .map_err(|e| rid(e.into()))?;
    if let EventOutcome::Recorded { .. } = outcome {
        // Drive the kernel action lifecycle from provider evidence.
        let action = match actions::get_for_update(&mut tx, delivery.action_id).await {
            Ok(action) => action,
            Err(mk_store::StoreError::Erased) => {
                // A late authenticated receipt is still evidence. Keep its
                // monotonic metadata without loading or resurrecting content.
                mk_store::audit::append_event(
                    &mut tx,
                    mk_audit::NewEvent {
                        tenant_id: sender.tenant_id,
                        occurred_at: now,
                        actor_type: mk_audit::ActorType::System,
                        actor_id: "twilio-webhook",
                        action_id: Some(delivery.action_id),
                        event_type: mk_audit::EventType::DeliveryEvent,
                        payload_redacted: json!({"content_erased":true,"provider_status":status,
                        "folded_state":folded.as_str(),"raw_event_digest":raw_digest.to_string()}),
                        trace_id: None,
                        policy_version: mk_policy::POLICY_VERSION.0,
                    },
                )
                .await
                .map_err(|e| rid(e.into()))?;
                tx.commit().await.map_err(|e| rid(e.into()))?;
                return Ok(twiml_ok());
            }
            Err(error) => return Err(rid(error.into())),
        };
        let actor = actions::Actor {
            actor_type: mk_audit::ActorType::System,
            actor_id: "twilio-webhook",
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        };
        if action.state == ActionState::Dispatching {
            match folded {
                DeliveryState::Sent | DeliveryState::Delivered => {
                    actions::transition(
                        &mut tx,
                        delivery.action_id,
                        Transition::Complete,
                        None,
                        actor,
                        now,
                    )
                    .await
                    .map_err(|e| rid(e.into()))?;
                    outbox::record_attempt_end(
                        &mut tx,
                        delivery.action_id,
                        action.attempt,
                        "completed",
                        None,
                        Some(sender_identity_id),
                        Some(&message_sid),
                        Some(&raw_digest.to_string()),
                        now,
                    )
                    .await
                    .map_err(|e| rid(e.into()))?;
                    outbox::release_lease_any(&mut tx, delivery.action_id)
                        .await
                        .map_err(|e| rid(e.into()))?;
                }
                DeliveryState::Failed => {
                    let code = error_code
                        .clone()
                        .map_or_else(|| "provider_failed".to_owned(), |c| format!("provider_{c}"));
                    actions::transition(
                        &mut tx,
                        delivery.action_id,
                        Transition::FailFinal,
                        Some(&code),
                        actor,
                        now,
                    )
                    .await
                    .map_err(|e| rid(e.into()))?;
                    outbox::record_attempt_end(
                        &mut tx,
                        delivery.action_id,
                        action.attempt,
                        "failed_final",
                        Some(&code),
                        Some(sender_identity_id),
                        Some(&message_sid),
                        Some(&raw_digest.to_string()),
                        now,
                    )
                    .await
                    .map_err(|e| rid(e.into()))?;
                    outbox::dead_letter(
                        &mut tx,
                        delivery.action_id,
                        "failed_final",
                        action.attempt,
                        Some(&code),
                        json!({"source": "twilio_status", "status": status}),
                        now,
                    )
                    .await
                    .map_err(|e| rid(e.into()))?;
                    outbox::release_lease_any(&mut tx, delivery.action_id)
                        .await
                        .map_err(|e| rid(e.into()))?;
                }
                _ => {}
            }
        } else if action.state == ActionState::Completed
            && action.error_code.as_deref() == Some(mk_store::messaging::ACCEPTED_CALLBACK_PENDING)
            && folded == DeliveryState::Failed
        {
            // Completed at lease expiry on the provider's acceptance; the provider
            // now reports the message failed. The action stays completed (it was
            // executed exactly once) but the failure is NOT hidden: the attempt is
            // closed as failed and a dead letter raises the alert (C3/C4).
            let code = error_code
                .clone()
                .map_or_else(|| "provider_failed".to_owned(), |c| format!("provider_{c}"));
            outbox::record_attempt_end(
                &mut tx,
                delivery.action_id,
                action.attempt,
                "failed_final",
                Some(&code),
                Some(sender_identity_id),
                Some(&message_sid),
                Some(&raw_digest.to_string()),
                now,
            )
            .await
            .map_err(|e| rid(e.into()))?;
            outbox::dead_letter(
                &mut tx,
                delivery.action_id,
                "completed_delivery_failed",
                action.attempt,
                Some(&code),
                json!({"source": "twilio_status", "status": status, "after": "lease_expiry_completion"}),
                now,
            )
            .await
            .map_err(|e| rid(e.into()))?;
        }
        mk_store::audit::append_event(
            &mut tx,
            mk_audit::NewEvent {
                tenant_id: sender.tenant_id,
                occurred_at: now,
                actor_type: mk_audit::ActorType::System,
                actor_id: "twilio-webhook",
                action_id: Some(delivery.action_id),
                event_type: mk_audit::EventType::DeliveryEvent,
                payload_redacted: json!({"provider_status": status, "folded_state": folded.as_str(), "error_code": error_code,
                                         "raw_event_digest": raw_digest.to_string()}),
                trace_id: None,
                policy_version: mk_policy::POLICY_VERSION.0,
            },
        )
        .await
        .map_err(|e| rid(e.into()))?;
    }
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(twiml_ok())
}

fn delivery_state_of(s: &str) -> DeliveryState {
    match s {
        "provider_accepted" => DeliveryState::ProviderAccepted,
        "sent" => DeliveryState::Sent,
        "delivered" => DeliveryState::Delivered,
        "failed" => DeliveryState::Failed,
        "delivery_unknown" => DeliveryState::DeliveryUnknown,
        _ => DeliveryState::SubmissionStarted,
    }
}

// ------------------------------------------------------------ inbound webhook

/// `POST /webhooks/twilio/inbound/{sender_identity_id}` — contract C5 order:
/// authenticate → bind tenant/sender → durable dedupe → detect opt-out →
/// suppress / hold → acknowledge; meaning is processed asynchronously by the
/// application through `/internal/v1/inbound/pending`.
pub async fn twilio_inbound(
    State(st): State<AppState>,
    Path(sender_identity_id): Path<Uuid>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    let (sender, form) = authenticate(&st, &uri, &headers, sender_identity_id, &body)
        .await
        .map_err(rid)?;
    if let Some(probe) = field(&form, "MkHealthProbe") {
        // No customer row, permission, suppression or task is created. A
        // successful status alone cannot mark health: the worker reads back
        // this exact, pre-issued, signed body's committed generation.
        let id: Uuid = probe
            .parse()
            .map_err(|_| rid(forbidden("PROBE_INVALID", "Invalid probe")))?;
        if form.len() != 3 || sender.from_number.as_deref() != field(&form, "To") {
            return Err(rid(forbidden("PROBE_BINDING", "Probe sender mismatch")));
        }
        let mut tx = st
            .store
            .begin(sender.tenant_id)
            .await
            .map_err(|e| rid(e.into()))?;
        if !mk_store::probes::receive(
            &mut tx,
            sender_identity_id,
            id,
            &Digest::of(&body),
            Utc::now(),
        )
        .await
        .map_err(|e| rid(e.into()))?
        {
            return Err(rid(forbidden(
                "PROBE_EXPIRED_OR_REPLAYED",
                "Probe is not current",
            )));
        }
        tx.commit().await.map_err(|e| rid(e.into()))?;
        return Ok(twiml_ok());
    }
    let message_sid = field(&form, "MessageSid")
        .or_else(|| field(&form, "SmsSid"))
        .unwrap_or_default()
        .to_owned();
    let from = field(&form, "From").unwrap_or_default().to_owned();
    let to = field(&form, "To").unwrap_or_default().to_owned();
    let text = field(&form, "Body").unwrap_or_default().to_owned();
    if message_sid.is_empty() || from.is_empty() {
        return Err(rid(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "WEBHOOK_FIELDS",
            "MessageSid and From required",
        )));
    }
    // Bind: the message must be addressed to this sender's own number.
    if let Some(num) = &sender.from_number
        && &to != num
    {
        return Err(rid(forbidden(
            "WEBHOOK_SENDER_MISMATCH",
            "To does not match the sender identity",
        )));
    }
    let now = Utc::now();
    let raw_digest = Digest::of(&body);
    let dest = st
        .fingerprints
        .compute(sender.tenant_id, Channel::Sms, &from);
    let signal = detect_opt_out(&text);
    let (signal_s, disposition) = match signal {
        OptOutSignal::Explicit => ("explicit", "suppressed"),
        OptOutSignal::Possible => ("possible", "held"),
        OptOutSignal::None => ("none", "queued_for_meaning"),
    };
    // Record, suppress and cancel in one transaction; a transient rollback
    // (deadlock / serialization / lock timeout) is retried, because the provider
    // does not redeliver inbound messages — a lost STOP is unacceptable.
    let mut attempt: u64 = 0;
    loop {
        attempt += 1;
        match inbound_tx(
            &st,
            &sender,
            sender_identity_id,
            &dest,
            &from,
            &text,
            &message_sid,
            &raw_digest,
            signal,
            signal_s,
            disposition,
            now,
        )
        .await
        {
            Err(e) if e.code == "STORE_TRANSIENT" && attempt < 4 => {
                tracing::warn!(
                    attempt,
                    "inbound transaction rolled back (transient); retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(25 * attempt)).await;
            }
            other => return other.map_err(rid),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn inbound_tx(
    st: &AppState,
    sender: &ms::SenderIdentitySecret,
    sender_identity_id: Uuid,
    dest: &mk_store::fingerprint::Fingerprints,
    from: &str,
    text: &str,
    message_sid: &str,
    raw_digest: &Digest,
    signal: OptOutSignal,
    signal_s: &str,
    disposition: &str,
    now: chrono::DateTime<Utc>,
) -> Result<Response, ApiError> {
    let ident = |e: ApiError| e;
    let mut tx = st
        .store
        .begin(sender.tenant_id)
        .await
        .map_err(|e| ident(e.into()))?;
    // C6: the same control path dispatch authorization takes.
    ms::lock_control_path(&mut tx, Channel::Sms.as_str(), dest)
        .await
        .map_err(|e| ident(e.into()))?;
    let rec = ms::record_inbound(
        &mut tx,
        &st.keyring,
        message_sid,
        sender_identity_id,
        dest,
        from,
        None,
        &SecretString::from(text.to_owned()),
        raw_digest,
        signal_s,
        disposition,
        now,
    )
    .await
    .map_err(|e| ident(e.into()))?;
    let event_id = match rec {
        InboundOutcome::Duplicate(id) | InboundOutcome::Erased(id) => {
            // Redelivery: no new suppression, no new hold, no new task.
            tx.commit().await.map_err(|e| ident(e.into()))?;
            let _ = id;
            st.metrics
                .inbound_events
                .get_or_create(&crate::metrics::DispositionLabels {
                    disposition: "duplicate".into(),
                })
                .inc();
            return Ok(twiml_ok());
        }
        InboundOutcome::Recorded(id) => id,
    };
    st.metrics
        .inbound_events
        .get_or_create(&crate::metrics::DispositionLabels {
            disposition: disposition.into(),
        })
        .inc();
    let actor = actions::Actor {
        actor_type: mk_audit::ActorType::System,
        actor_id: "twilio-inbound",
        trace_id: None,
        policy_version: mk_policy::POLICY_VERSION.0,
    };
    match signal {
        OptOutSignal::Explicit => {
            consent::add_suppression(
                &mut tx,
                Some(Channel::Sms),
                Some(dest),
                Some((&st.keyring, from)),
                "destination",
                "sms_opt_out",
                true,
                "sms_reply",
                actor,
                now,
            )
            .await
            .map_err(|e| ident(e.into()))?;
            cancel_pending(&mut tx, dest, "opt_out", actor, now)
                .await
                .map_err(ident)?;
            audit_inbound(
                &mut tx,
                sender.tenant_id,
                mk_audit::EventType::InboundOptOut,
                event_id,
                "explicit",
                now,
            )
            .await
            .map_err(ident)?;
        }
        OptOutSignal::Possible => {
            // A hold is a non-permanent suppression a human must lift; it blocks
            // dispatch exactly like an opt-out until then.
            consent::add_suppression(
                &mut tx,
                Some(Channel::Sms),
                Some(dest),
                Some((&st.keyring, from)),
                "destination",
                "possible_opt_out_hold",
                false,
                "sms_reply",
                actor,
                now,
            )
            .await
            .map_err(|e| ident(e.into()))?;
            cancel_pending(&mut tx, dest, "possible_opt_out_hold", actor, now)
                .await
                .map_err(ident)?;
            audit_inbound(
                &mut tx,
                sender.tenant_id,
                mk_audit::EventType::InboundHeld,
                event_id,
                "possible",
                now,
            )
            .await
            .map_err(ident)?;
        }
        OptOutSignal::None => {}
    }
    ms::mark_inbound_acknowledged(&mut tx, event_id, now)
        .await
        .map_err(|e| ident(e.into()))?;
    tx.commit().await.map_err(|e| ident(e.into()))?;
    Ok(twiml_ok())
}

async fn cancel_pending(
    tx: &mut mk_store::TenantTx<'_>,
    dest: &mk_store::fingerprint::Fingerprints,
    reason: &str,
    actor: actions::Actor<'_>,
    now: DateTime<Utc>,
) -> Result<u32, ApiError> {
    let mut n = 0;
    for id in actions::pending_for_destination(tx, Some(Channel::Sms), Some(dest)).await? {
        let a = actions::get_for_update(tx, id).await?;
        if a.state.is_suppressible() {
            actions::transition(tx, id, Transition::Suppress, Some(reason), actor, now).await?;
            n += 1;
        }
    }
    Ok(n)
}

async fn audit_inbound(
    tx: &mut mk_store::TenantTx<'_>,
    tenant: mk_domain::TenantId,
    et: mk_audit::EventType,
    event_id: Uuid,
    signal: &str,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    mk_store::audit::append_event(
        tx,
        mk_audit::NewEvent {
            tenant_id: tenant,
            occurred_at: now,
            actor_type: mk_audit::ActorType::System,
            actor_id: "twilio-inbound",
            action_id: None,
            event_type: et,
            payload_redacted: json!({"inbound_event_id": event_id, "signal": signal}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}

// ------------------------------------------------------------ sender identities (internal)

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterSenderBody {
    pub owner_user_id: UserId,
    pub display_name: String,
    pub account_sid: String,
    pub auth_token: SecretString,
    #[serde(default)]
    pub from_number: Option<String>,
    #[serde(default)]
    pub messaging_service_sid: Option<String>,
}

/// `POST /internal/v1/senders` (tenant_admin)
pub async fn register_sender(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(b): Json<RegisterSenderBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    p.require_role("tenant_admin").map_err(rid)?;
    if b.display_name.is_empty()
        || b.display_name.chars().count() > 120
        || b.auth_token.expose_secret().len() < 16
    {
        return Err(rid(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SENDER_FIELDS",
            "display_name 1..120 chars; auth_token ≥16 chars",
        )));
    }
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let id = ms::register_sender(
        &mut tx,
        &st.keyring,
        b.owner_user_id,
        &b.display_name,
        &b.account_sid,
        &b.auth_token,
        b.from_number.as_deref(),
        b.messaging_service_sid.as_deref(),
        p.user,
        now,
    )
    .await
    .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    let base = st.public_webhook_base.clone().unwrap_or_default();
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "sender_identity_id": id,
            "registration_status": "unverified",
            "configure_in_provider": {
                "status_callback_url": format!("{base}/webhooks/twilio/status/{id}"),
                "inbound_webhook_url": format!("{base}/webhooks/twilio/inbound/{id}"),
            }
        })),
    ))
}

/// `GET /internal/v1/senders`
pub async fn list_senders(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Vec<ms::SenderIdentityView>>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    Ok(Json(
        ms::list_senders(&mut tx).await.map_err(|e| rid(e.into()))?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationBody {
    pub registration_status: String,
    #[serde(default)]
    pub reference: String,
}

/// `POST /internal/v1/senders/{id}/registration` (tenant_admin) — records
/// 10DLC / toll-free registration evidence. A sender that is not `registered`
/// is still usable in staging against the simulator; production enablement is
/// gated on this in pre-flight, not here.
pub async fn set_registration(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<RegistrationBody>,
) -> Result<StatusCode, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    p.require_role("tenant_admin").map_err(rid)?;
    if !matches!(
        b.registration_status.as_str(),
        "unverified" | "pending" | "registered" | "rejected"
    ) || b.reference.len() > 200
    {
        return Err(rid(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "REGISTRATION_FIELDS",
            "bad status or reference",
        )));
    }
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    ms::set_registration_status(
        &mut tx,
        id,
        &b.registration_status,
        &b.reference,
        p.user,
        now,
    )
    .await
    .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ inbound queue + health (internal)

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryExceptionQuery {
    pub after: Option<Uuid>,
    pub limit: Option<i64>,
}

/// Read-only queue. A generic "dismiss" never changes provider evidence or
/// clears the human-resolution requirement for an uncertain submission.
pub async fn delivery_exceptions(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Query(q): Query<DeliveryExceptionQuery>,
) -> Result<Json<Value>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    if !p.has_role("consultant") && !p.has_role("manager") && !p.has_role("tenant_admin") {
        return Err(rid(forbidden(
            "ROLE_REQUIRED",
            "A human manager is required",
        )));
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let mut items = ms::delivery_exceptions(
        &mut tx,
        p.user,
        p.has_role("tenant_admin"),
        q.after,
        limit + 1,
    )
    .await
    .map_err(|e| rid(e.into()))?;
    let next = if items.len() > usize::try_from(limit).unwrap_or(100) {
        items.pop();
        items.last().map(|i| i["delivery_id"].clone())
    } else {
        None
    };
    Ok(Json(json!({"items":items, "next_cursor":next})))
}

#[derive(Debug, Deserialize)]
pub struct PendingQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /internal/v1/inbound/pending` — unprocessed inbound events with the
/// body unsealed for the tenant's authenticated principal (never an agent).
pub async fn inbound_pending(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Query(q): Query<PendingQuery>,
) -> Result<Json<Vec<ms::InboundView>>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    if !p.has_role("consultant") && !p.has_role("manager") && !p.has_role("tenant_admin") {
        return Err(rid(forbidden(
            "AGENT_CANNOT_READ_INBOUND",
            "customer messages are not available to agent principals",
        )));
    }
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let v = ms::pending_inbound(&mut tx, &st.keyring, q.limit.unwrap_or(50).clamp(1, 200))
        .await
        .map_err(|e| rid(e.into()))?;
    Ok(Json(v))
}

/// `POST /internal/v1/inbound/{event_id}/processed`
pub async fn inbound_processed(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(event_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    if !p.has_role("consultant") && !p.has_role("manager") && !p.has_role("tenant_admin") {
        return Err(rid(forbidden(
            "HUMAN_ROLE_REQUIRED",
            "only a consultant, manager or tenant administrator may process inbound events",
        )));
    }
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let ok = ms::mark_inbound_processed(&mut tx, event_id, now)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(rid(ApiError::new(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no unprocessed event",
        )))
    }
}

/// `GET /internal/v1/inbound/health`
pub async fn inbound_health(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let h = ms::inbound_health(&mut tx)
        .await
        .map_err(|e| rid(e.into()))?;
    let block = ms::inbound_dispatch_block(&mut tx, now)
        .await
        .map_err(|e| rid(e.into()))?;
    let pending = ms::pending_inbound_count(&mut tx)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(
        json!({"health": h, "dispatch_blocked": block, "pending_events": pending, "stale_after_secs": ms::INBOUND_STALE_SECS}),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthBody {
    pub ok: bool,
    #[serde(default)]
    pub reason: String,
}

/// Administrators may report failure (fail-safe), never assert success in lieu
/// of the worker's committed public-webhook probe receipt.
pub async fn inbound_health_report(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(b): Json<HealthBody>,
) -> Result<StatusCode, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    p.require_role("tenant_admin").map_err(rid)?;
    if b.ok {
        return Err(rid(forbidden(
            "HEALTH_RECEIPT_REQUIRED",
            "A caller assertion cannot mark inbound healthy",
        )));
    }
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    ms::inbound_failure(&mut tx, &b.reason, now)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /internal/v1/inbound/pause` / `POST /internal/v1/inbound/resume` (tenant_admin).
pub async fn inbound_pause(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    p.require_role("tenant_admin").map_err(rid)?;
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    ms::pause_inbound(&mut tx, now)
        .await
        .map_err(|e| rid(e.into()))?;
    audit_inbound(
        &mut tx,
        p.tenant,
        mk_audit::EventType::InboundPaused,
        Uuid::nil(),
        "manual",
        now,
    )
    .await
    .map_err(rid)?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn inbound_resume(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    p.require_role("tenant_admin").map_err(rid)?;
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let resumed = ms::resume_inbound(&mut tx, now)
        .await
        .map_err(|e| rid(e.into()))?;
    if resumed {
        audit_inbound(
            &mut tx,
            p.tenant,
            mk_audit::EventType::InboundResumed,
            Uuid::nil(),
            "manual",
            now,
        )
        .await
        .map_err(rid)?;
    }
    let pending = ms::pending_inbound_count(&mut tx)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(json!({"resumed": resumed, "pending_events": pending,
                   "note": if resumed { "" } else { "resume requires a successful inbound check within the stale window and zero pending events" }})))
}

/// Attach provider delivery details to an action result (GET /actions/{id}).
pub async fn enrich_result(
    tx: &mut mk_store::TenantTx<'_>,
    result: &mut mk_contracts::ActionResult,
) -> Result<(), ApiError> {
    if let Some(d) = ms::delivery_for_action(tx, result.action_id).await? {
        // Terminal action history stays unchanged. Only after the human's
        // bound decision may the public message state use the provider facts.
        let observed = if result.state == mk_domain::ActionState::ReconciliationRequired
            && mk_store::resolutions::decision(tx, result.action_id)
                .await?
                .is_some()
        {
            mk_domain::ActionState::Completed
        } else {
            result.state
        };
        result.message_state = Some(mk_contracts::MessageState::derive(observed, Some(&d.state)));
        result.read_status = Some(d.read_status);
        result.provider_message_id = d.provider_message_id;
    }
    Ok(())
}
