//! Mobile adapter contract simulator (in-process).
//!
//! Binds to `127.0.0.1:0`, verifies the kernel's HMAC on incoming work
//! orders, validates them against the published schema, and replies with
//! deterministic modes. It is **not** a device implementation and never
//! changes `verified_on_device` evidence. Used by the Rust test suite and by
//! `mk-simulator` for local conformance runs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use mk_contracts::mobile::MobileWorkOrder;
use mk_crypto::{AdapterSecret, NonceWindow, ReplayGuard, VerifyParams, verify_hmac};
use serde_json::Value;
use tokio::sync::{Mutex, mpsc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimMode {
    Accept,
    FailOnce,
    Reject,
    UnsupportedActions,
}

#[derive(Debug)]
struct SimState {
    secret: AdapterSecret,
    tenant: String,
    agent: String,
    mode: SimMode,
    calls: AtomicUsize,
    replay: Mutex<ReplayGuard>,
    received: mpsc::UnboundedSender<MobileWorkOrder>,
    tolerance_secs: i64,
}

#[derive(Debug)]
pub struct Simulator {
    pub addr: SocketAddr,
    pub received: mpsc::UnboundedReceiver<MobileWorkOrder>,
    handle: tokio::task::JoinHandle<()>,
}

/// Post the two callbacks a real device would send (`executing`, then
/// `complete` or `failed`) to the kernel, signed with the device secret.
/// `callback_base` replaces the scheme+authority of the order's
/// `callback_url` so a local kernel can be targeted over plain HTTP.
pub async fn post_callbacks(
    order: &MobileWorkOrder,
    secret: &AdapterSecret,
    tenant: &str,
    callback_base: &str,
    fail_code: Option<&str>,
) -> Result<Vec<u16>, String> {
    let path = format!("/adapter/v1/work-orders/{}/callbacks", order.task_id);
    let url = format!("{}{path}", callback_base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let bodies: Vec<String> = match fail_code {
        None => vec![
            r#"{"error_code":"","result":{},"schema":"consultant-studio.mobile-execution-state.v1","status":"executing"}"#.into(),
            r#"{"error_code":"","result":{"sent":true},"schema":"consultant-studio.mobile-execution-completion.v1","status":"complete"}"#.into(),
        ],
        Some(code) => vec![
            format!(r#"{{"error_code":"{code}","result":{{}},"schema":"consultant-studio.mobile-execution-failure.v1","status":"failed"}}"#),
        ],
    };
    let mut statuses = Vec::new();
    for body in bodies {
        let ts = chrono::Utc::now().timestamp().to_string();
        let nonce = uuid::Uuid::now_v7().simple().to_string();
        let h = mk_crypto::sign_hmac(secret, "POST", &path, &ts, &nonce, body.as_bytes())
            .map_err(|e| e.to_string())?;
        let resp = client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-mobile-agent", &order.agent_id)
            .header("x-mobile-tenant", tenant)
            .header("x-mobile-timestamp", h.timestamp)
            .header("x-mobile-nonce", h.nonce)
            .header("x-mobile-signature", h.signature_hex)
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        statuses.push(resp.status().as_u16());
    }
    Ok(statuses)
}

impl Simulator {
    pub async fn start(
        secret: AdapterSecret,
        tenant: &str,
        agent: &str,
        mode: SimMode,
    ) -> std::io::Result<Self> {
        Self::start_on("127.0.0.1:0", secret, tenant, agent, mode).await
    }

    pub async fn start_on(
        bind: &str,
        secret: AdapterSecret,
        tenant: &str,
        agent: &str,
        mode: SimMode,
    ) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(SimState {
            secret,
            tenant: tenant.to_owned(),
            agent: agent.to_owned(),
            mode,
            calls: AtomicUsize::new(0),
            replay: Mutex::new(ReplayGuard::new()),
            received: tx,
            tolerance_secs: 120,
        });
        let app = Router::new()
            .route("/sim/v1/work-orders", post(intake))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            addr,
            received: rx,
            handle,
        })
    }

    #[must_use]
    pub fn intake_url(&self) -> String {
        format!("http://{}/sim/v1/work-orders", self.addr)
    }

    #[must_use]
    pub fn authority(&self) -> String {
        self.addr.to_string()
    }
}

impl Drop for Simulator {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn intake(
    State(s): State<Arc<SimState>>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    if h("x-mobile-agent") != s.agent || h("x-mobile-tenant") != s.tenant {
        return (StatusCode::FORBIDDEN, "wrong_agent_or_tenant");
    }
    let (ts, nonce, sig) = (
        h("x-mobile-timestamp"),
        h("x-mobile-nonce"),
        h("x-mobile-signature"),
    );
    let now = chrono::Utc::now().timestamp();
    if verify_hmac(
        &s.secret,
        VerifyParams {
            method: "POST",
            path: "/sim/v1/work-orders",
            timestamp: &ts,
            nonce: &nonce,
            signature_hex: &sig,
            body: &body,
            now_unix: now,
            tolerance_secs: s.tolerance_secs,
        },
    )
    .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "bad_signature");
    }
    if s.replay
        .lock()
        .await
        .check_and_record(
            &format!("{}:{}", s.tenant, s.agent),
            &nonce,
            now,
            NonceWindow::from_tolerance(s.tolerance_secs),
        )
        .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "nonce_replayed");
    }
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "not_json"),
    };
    if mk_contracts::validate(mk_contracts::SchemaId::MobileWorkOrder, &v).is_err() {
        return (StatusCode::UNPROCESSABLE_ENTITY, "contract_violation");
    }
    let order: MobileWorkOrder = match serde_json::from_value(v) {
        Ok(o) => o,
        Err(_) => return (StatusCode::UNPROCESSABLE_ENTITY, "contract_violation"),
    };
    let n = s.calls.fetch_add(1, Ordering::SeqCst);
    let _ = s.received.send(order);
    match s.mode {
        SimMode::Accept => (StatusCode::ACCEPTED, "accepted"),
        SimMode::FailOnce if n == 0 => (StatusCode::SERVICE_UNAVAILABLE, "fail_once"),
        SimMode::FailOnce => (StatusCode::ACCEPTED, "accepted"),
        SimMode::Reject => (StatusCode::UNPROCESSABLE_ENTITY, "rejected"),
        SimMode::UnsupportedActions => (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_actions"),
    }
}
