//! Twilio Messages API simulator (in-process, loopback only). Test equipment
//! for the adapter, the worker and the live smoke: implements the subset the
//! kernel uses (`POST /Messages.json`, `GET /Messages.json?To=&DateSent=`),
//! checks HTTP basic auth, and injects faults. It also knows how to **post the
//! status callbacks and inbound webhooks** Twilio would send, signed with the
//! auth token over the configured public URL, so webhook verification is
//! exercised on real request shapes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use base64::Engine as _;
use mk_crypto::AdapterSecret;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::twilio::twilio_signature;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwilioSimMode {
    /// 201 with a message sid.
    Accept,
    /// 400 code 21610 — recipient unsubscribed at the provider.
    RecipientOptedOut,
    /// 400 code 21211 — invalid destination.
    InvalidDestination,
    /// 500 for the first N calls, then accept.
    ServerErrorThenAccept(usize),
    /// Create the message, then drop the connection without a response
    /// (the ambiguous case). Reconciliation finds the message.
    AcceptButDropResponse,
    /// 429 rate limited.
    RateLimited,
}

#[derive(Debug)]
struct SimState {
    account_sid: String,
    auth_token: AdapterSecret,
    mode: TwilioSimMode,
    calls: AtomicUsize,
    /// Messages "created" at the provider, by sid.
    messages: Mutex<Vec<Value>>,
}

#[derive(Debug)]
pub struct TwilioSimulator {
    pub addr: SocketAddr,
    state: Arc<SimState>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for TwilioSimulator {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn basic_ok(headers: &HeaderMap, sid: &str, token: &AdapterSecret) -> bool {
    let Some(h) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(b64) = h.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64) else {
        return false;
    };
    let want = format!(
        "{sid}:{}",
        std::str::from_utf8(token.expose_bytes()).unwrap_or_default()
    );
    mk_crypto::constant_time_eq(&raw, want.as_bytes())
}

fn parse_form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

async fn create_message(
    State(st): State<Arc<SimState>>,
    Path(account): Path<String>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if account != st.account_sid || !basic_ok(&headers, &st.account_sid, &st.auth_token) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"code": 20003, "message": "Authenticate", "status": 401})),
        )
            .into_response();
    }
    let n = st.calls.fetch_add(1, Ordering::SeqCst);
    let form = parse_form(&body);
    let to = form.get("To").cloned().unwrap_or_default();
    let from = form
        .get("From")
        .cloned()
        .or_else(|| form.get("MessagingServiceSid").cloned())
        .unwrap_or_default();
    let text = form.get("Body").cloned().unwrap_or_default();
    if !form.contains_key("StatusCallback") {
        return (StatusCode::BAD_REQUEST, axum::Json(json!({"code": 21609, "message": "StatusCallback required by simulator", "status": 400}))).into_response();
    }
    let reject = |code: i64, msg: &str| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"code": code, "message": msg, "status": 400})),
        )
            .into_response()
    };
    match st.mode {
        TwilioSimMode::RecipientOptedOut => {
            return reject(21610, "Attempt to send to unsubscribed recipient");
        }
        TwilioSimMode::InvalidDestination => return reject(21211, "Invalid 'To' Phone Number"),
        TwilioSimMode::RateLimited => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({"code": 20429, "status": 429})),
            )
                .into_response();
        }
        TwilioSimMode::ServerErrorThenAccept(k) if n < k => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
        _ => {}
    }
    let sid = format!("SM{}", uuid::Uuid::now_v7().simple());
    let msg = json!({
        "sid": sid, "status": "queued", "to": to, "from": from, "body": text,
        "status_callback": form.get("StatusCallback").cloned().unwrap_or_default(),
        "date_created": chrono::Utc::now().to_rfc2822(), "error_code": null, "num_segments": "1",
        "account_sid": st.account_sid,
        "messaging_service_sid": form.get("MessagingServiceSid"),
    });
    st.messages.lock().await.push(msg.clone());
    if st.mode == TwilioSimMode::AcceptButDropResponse {
        // Simulate a connection cut after the provider committed the message:
        // return an invalid, truncated body so the client sees a body error.
        let mut r =
            axum::response::Response::new(axum::body::Body::from_stream(futures_stream_err()));
        *r.status_mut() = StatusCode::CREATED;
        return r;
    }
    (StatusCode::CREATED, axum::Json(msg)).into_response()
}

fn futures_stream_err()
-> impl futures_core::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
    // One chunk then an error: the client sees a body read failure.
    tokio_stream::iter(vec![
        Ok(axum::body::Bytes::from_static(b"{\"sid\":\"SM")),
        Err(std::io::Error::other("connection reset by simulator")),
    ])
}

async fn list_messages(
    State(st): State<Arc<SimState>>,
    Path(account): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if account != st.account_sid || !basic_ok(&headers, &st.account_sid, &st.auth_token) {
        return (StatusCode::UNAUTHORIZED, "").into_response();
    }
    let msgs = st.messages.lock().await;
    let out: Vec<Value> = msgs
        .iter()
        .filter(|m| q.get("To").is_none_or(|t| m["to"] == json!(t)))
        .filter(|m| q.get("From").is_none_or(|f| m["from"] == json!(f)))
        .cloned()
        .collect();
    axum::Json(json!({"messages": out, "page_size": 50})).into_response()
}

async fn fetch_message(
    State(st): State<Arc<SimState>>,
    Path((account, resource)): Path<(String, String)>,
    headers: HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if account != st.account_sid || !basic_ok(&headers, &st.account_sid, &st.auth_token) {
        return (StatusCode::UNAUTHORIZED, "").into_response();
    }
    let sid = resource.strip_suffix(".json").unwrap_or_default();
    let messages = st.messages.lock().await;
    match messages.iter().find(|m| m["sid"] == sid) {
        Some(m) => axum::Json(m.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "").into_response(),
    }
}

impl TwilioSimulator {
    pub async fn start(
        account_sid: &str,
        auth_token: AdapterSecret,
        mode: TwilioSimMode,
    ) -> std::io::Result<Self> {
        Self::start_on("127.0.0.1:0", account_sid, auth_token, mode).await
    }

    pub async fn start_on(
        bind: &str,
        account_sid: &str,
        auth_token: AdapterSecret,
        mode: TwilioSimMode,
    ) -> std::io::Result<Self> {
        let state = Arc::new(SimState {
            account_sid: account_sid.to_owned(),
            auth_token,
            mode,
            calls: AtomicUsize::new(0),
            messages: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route(
                "/2010-04-01/Accounts/{account}/Messages.json",
                post(create_message).get(list_messages),
            )
            .route(
                "/2010-04-01/Accounts/{account}/Messages/{resource}",
                get(fetch_message),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            addr,
            state,
            handle,
        })
    }

    #[must_use]
    pub fn api_base(&self) -> String {
        format!("http://{}", self.addr)
    }

    #[must_use]
    pub fn authority(&self) -> String {
        self.addr.to_string()
    }

    pub async fn created_messages(&self) -> Vec<Value> {
        self.state.messages.lock().await.clone()
    }

    /// Inject authoritative provider state independently of callback delivery.
    pub async fn set_message_status(&self, sid: &str, status: &str) {
        for message in self.state.messages.lock().await.iter_mut() {
            if message["sid"] == sid {
                message["status"] = json!(status);
            }
        }
    }

    /// Mark a created message as having had its callbacks posted (standalone binary bookkeeping).
    pub async fn take_uncalled(&self) -> Vec<Value> {
        let mut msgs = self.state.messages.lock().await;
        let mut out = Vec::new();
        for m in msgs.iter_mut() {
            if m.get("callbacks_posted").is_none() {
                m["callbacks_posted"] = json!(true);
                out.push(m.clone());
            }
        }
        out
    }

    /// Status-callback post for a message created through this simulator,
    /// using the `StatusCallback` URL the kernel supplied on submission as the
    /// public URL (what Twilio signs over) and `deliver_base` to reach it.
    pub async fn post_status_for(
        &self,
        msg: &Value,
        deliver_base: &str,
        status: &str,
    ) -> Result<(u16, String), String> {
        let public = msg["status_callback"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let path = url::Url::parse(&public)
            .map(|u| {
                format!(
                    "{}{}",
                    u.path(),
                    u.query().map_or(String::new(), |q| format!("?{q}"))
                )
            })
            .unwrap_or_default();
        let deliver = format!("{}{}", deliver_base.trim_end_matches('/'), path);
        let form: Vec<(String, String)> = vec![
            (
                "MessageSid".into(),
                msg["sid"].as_str().unwrap_or_default().into(),
            ),
            ("MessageStatus".into(), status.into()),
            ("AccountSid".into(), self.state.account_sid.clone()),
            (
                "From".into(),
                msg["from"].as_str().unwrap_or_default().into(),
            ),
            ("To".into(), msg["to"].as_str().unwrap_or_default().into()),
            ("ApiVersion".into(), "2010-04-01".into()),
        ];
        self.post_signed(&public, &deliver, form, false).await
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }

    /// Post a status callback exactly as Twilio would: form-encoded, signed
    /// with the auth token over `public_url` (the URL Twilio believes it is
    /// calling), delivered to `deliver_to` (where the kernel actually listens).
    pub async fn post_status_callback(
        &self,
        public_url: &str,
        deliver_to: &str,
        message_sid: &str,
        status: &str,
        error_code: Option<&str>,
        tamper_signature: bool,
    ) -> Result<(u16, String), String> {
        let mut form: Vec<(String, String)> = vec![
            ("MessageSid".into(), message_sid.into()),
            ("MessageStatus".into(), status.into()),
            ("AccountSid".into(), self.state.account_sid.clone()),
            ("From".into(), "+15005550006".into()),
            ("To".into(), "+15555550100".into()),
            ("ApiVersion".into(), "2010-04-01".into()),
        ];
        if let Some(e) = error_code {
            form.push(("ErrorCode".into(), e.into()));
        }
        self.post_signed(public_url, deliver_to, form, tamper_signature)
            .await
    }

    /// Post an inbound message webhook as Twilio would.
    pub async fn post_inbound(
        &self,
        public_url: &str,
        deliver_to: &str,
        message_sid: &str,
        from: &str,
        to: &str,
        body: &str,
        tamper_signature: bool,
    ) -> Result<(u16, String), String> {
        let form: Vec<(String, String)> = vec![
            ("MessageSid".into(), message_sid.into()),
            ("SmsSid".into(), message_sid.into()),
            ("AccountSid".into(), self.state.account_sid.clone()),
            ("From".into(), from.into()),
            ("To".into(), to.into()),
            ("Body".into(), body.into()),
            ("NumMedia".into(), "0".into()),
            ("NumSegments".into(), "1".into()),
            ("ApiVersion".into(), "2010-04-01".into()),
        ];
        self.post_signed(public_url, deliver_to, form, tamper_signature)
            .await
    }

    async fn post_signed(
        &self,
        public_url: &str,
        deliver_to: &str,
        form: Vec<(String, String)>,
        tamper_signature: bool,
    ) -> Result<(u16, String), String> {
        let mut sig = twilio_signature(&self.state.auth_token, public_url, &form);
        if tamper_signature {
            sig = format!(
                "{}{}",
                &sig[..sig.len() - 2],
                if sig.ends_with("A=") { "B=" } else { "A=" }
            );
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client
            .post(deliver_to)
            .header("x-twilio-signature", sig)
            // What a hostile proxy might add; the kernel must ignore these.
            .header("x-forwarded-host", "attacker.example")
            .header("x-forwarded-proto", "http")
            .form(&form)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body))
    }
}
