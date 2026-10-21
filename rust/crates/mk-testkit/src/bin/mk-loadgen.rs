#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::struct_field_names
)]
//! `mk-loadgen`: load generator and SLO measurement against a live kernel
//! (contract O2–O4). Test equipment — never shipped in the kernel image.
//!
//! Drives the governed path exactly as the application does: mints actor
//! assertions with the dev key, registers an approver passkey (software
//! authenticator), proposes `sms.provider.send.v1` actions as an agent,
//! approves them with a transaction-bound WebAuthn assertion, then observes
//! each action until the provider simulator's signed callbacks move it to
//! `delivered`. In parallel it issues reads and signed inbound webhooks and
//! verifies that an opt-out blocks the next proposal at the authorization
//! boundary.
//!
//! Output: one JSON report (`--out`) with raw percentiles and a verdict per
//! SLO row from `docs/slo.md`. The report states the run's duration and rates;
//! a run shorter than the contract envelope is reported as such and never
//! called a qualification.
//!
//! Env (as in scripts/kernel-live-smoke.sh): MK_KERNEL_URL, DEV_PRIVATE_KEY,
//! MK_WEBHOOK_BASE (what the provider is configured with), MK_TWSIM_ACCOUNT_SID,
//! MK_TWSIM_AUTH_TOKEN, MK_LOAD_RP_ID / MK_LOAD_ORIGIN (passkey rp/origin).
//!
//! Args: --duration-secs N --proposals-per-sec R --reads-per-sec R
//!       --inbound-per-sec R --tenants N --out report.json

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use mk_crypto::webauthn::softauthn::SoftAuthenticator;
use mk_crypto::{ActorAssertion, AssertionSigner};
use serde::Serialize;
use serde_json::{Value, json};
use sha1::Sha1;
use tokio::sync::Mutex;
use uuid::Uuid;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Clone)]
#[allow(dead_code)]
struct Args {
    duration: Duration,
    proposals_per_sec: f64,
    reads_per_sec: f64,
    inbound_per_sec: f64,
    tenants: usize,
    out: String,
}

fn arg<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Default)]
struct Series(Mutex<Vec<f64>>);

impl Series {
    async fn push(&self, secs: f64) {
        self.0.lock().await.push(secs);
    }
    async fn summary(&self) -> Summary {
        let mut v = self.0.lock().await.clone();
        v.sort_by(f64::total_cmp);
        let q = |p: f64| -> f64 {
            if v.is_empty() {
                return 0.0;
            }
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
            v[idx.min(v.len() - 1)]
        };
        Summary {
            count: v.len(),
            p50: q(0.50),
            p95: q(0.95),
            p99: q(0.99),
            max: v.last().copied().unwrap_or(0.0),
        }
    }
}

#[derive(Serialize, Clone, Copy, Default)]
struct Summary {
    count: usize,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

struct Counters {
    proposals_ok: AtomicU64,
    proposals_rejected: AtomicU64,
    proposals_error: AtomicU64,
    approvals_ok: AtomicU64,
    approvals_error: AtomicU64,
    delivered: AtomicU64,
    not_delivered_in_time: AtomicU64,
    consent_cancelled: AtomicU64,
    approvals_refused: AtomicU64,
    reads_ok: AtomicU64,
    reads_error: AtomicU64,
    inbound_ok: AtomicU64,
    inbound_error: AtomicU64,
    optout_blocked: AtomicU64,
    optout_not_blocked: AtomicU64,
    duplicate_provider_messages: AtomicU64,
}

impl Counters {
    fn new() -> Self {
        Self {
            proposals_ok: AtomicU64::new(0),
            proposals_rejected: AtomicU64::new(0),
            proposals_error: AtomicU64::new(0),
            approvals_ok: AtomicU64::new(0),
            approvals_error: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            not_delivered_in_time: AtomicU64::new(0),
            consent_cancelled: AtomicU64::new(0),
            approvals_refused: AtomicU64::new(0),
            reads_ok: AtomicU64::new(0),
            reads_error: AtomicU64::new(0),
            inbound_ok: AtomicU64::new(0),
            inbound_error: AtomicU64::new(0),
            optout_blocked: AtomicU64::new(0),
            optout_not_blocked: AtomicU64::new(0),
            duplicate_provider_messages: AtomicU64::new(0),
        }
    }
}

struct Tenant {
    id: Uuid,
    agent: Uuid,
    approver: Uuid,
    sender_id: Uuid,
    from_number: String,
    authenticator: Mutex<SoftAuthenticator>,
    contacts: Mutex<Vec<(Uuid, String, u32)>>, // (contact, to number, uses today)
    next_phone: AtomicU64,
}

struct Rig {
    http: reqwest::Client,
    kernel: String,
    webhook_base: String,
    signer: AssertionSigner,
    account_sid: String,
    auth_token: String,
    rp_id: String,
    origin: String,
    counters: Counters,
    lat_propose: Series,
    lat_approve: Series,
    lat_approved_to_dispatch_start: Series,
    lat_approved_to_delivered: Series,
    lat_read: Series,
    lat_inbound: Series,
    lat_optout_to_block: Series,
    seen_provider_ids: Mutex<HashMap<String, Uuid>>,
}

impl Rig {
    fn token(&self, tenant: Uuid, user: Uuid, roles: &[&str]) -> String {
        let now = chrono::Utc::now().timestamp();
        self.signer
            .sign(&ActorAssertion {
                iss: "mk-fastapi".into(),
                aud: "mk-action-kernel".into(),
                sub: user,
                tenant_id: tenant,
                roles: roles.iter().map(|r| (*r).to_owned()).collect(),
                session_id: "loadgen".into(),
                request_id: Uuid::now_v7().to_string(),
                iat: now,
                exp: now + 60,
                jti: Uuid::now_v7(),
            })
            .unwrap_or_default()
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> Result<(u16, Value), reqwest::Error> {
        let mut r = self
            .http
            .request(method, format!("{}{path}", self.kernel))
            .bearer_auth(token);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await?;
        let status = resp.status().as_u16();
        let v = resp.json::<Value>().await.unwrap_or(Value::Null);
        Ok((status, v))
    }

    /// Local-noon zone for the contact so contact-hours policy passes at any UTC hour.
    fn noon_zone() -> String {
        let utc_hour = i64::from(
            chrono::Utc::now()
                .format("%H")
                .to_string()
                .parse::<u8>()
                .unwrap_or(12),
        );
        // local = utc + offset; want local ≈ 12 → offset = 12 - utc_hour, within [-12, 14].
        let offset = (12 - utc_hour).clamp(-12, 14);
        // IANA "Etc/GMT±N" is inverted: Etc/GMT-3 is UTC+3.
        match offset {
            0 => "Etc/UTC".into(),
            o if o > 0 => format!("Etc/GMT-{o}"),
            o => format!("Etc/GMT+{}", -o),
        }
    }

    async fn setup_tenant(&self, i: usize) -> anyhow::Result<Tenant> {
        let id = Uuid::now_v7();
        let (admin, agent, approver) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let from_number = format!(
            "+1500555{:04}",
            (u64::from(rand::random::<u16>()) + i as u64) % 10000
        );
        let (s, v) = self
            .call(
                reqwest::Method::POST,
                "/internal/v1/senders",
                &self.token(id, admin, &["tenant_admin"]),
                Some(json!({"owner_user_id": approver, "display_name": format!("Load Business {i}"), "account_sid": self.account_sid,
                            "auth_token": self.auth_token, "from_number": from_number})),
            )
            .await?;
        anyhow::ensure!(s == 201, "sender registration {s}: {v}");
        let sender_id: Uuid = v["sender_identity_id"]
            .as_str()
            .unwrap_or_default()
            .parse()?;
        let (s, _) = self
            .call(
                reqwest::Method::POST,
                "/internal/v1/inbound/health",
                &self.token(id, admin, &["tenant_admin"]),
                Some(json!({"ok": true})),
            )
            .await?;
        anyhow::ensure!(s == 204, "inbound health {s}");
        // Passkey for the approver.
        let mut auth = SoftAuthenticator::new_es256();
        let (s, begin) = self
            .call(
                reqwest::Method::POST,
                "/internal/v1/approval-credentials/register/begin",
                &self.token(id, approver, &["manager"]),
                Some(json!({})),
            )
            .await?;
        anyhow::ensure!(s == 200, "register/begin {s}: {begin}");
        let challenge =
            mk_crypto::webauthn::b64url_decode(begin["challenge"].as_str().unwrap_or(""))
                .unwrap_or_default();
        let (cdj, att) = auth.register(&challenge, &self.rp_id, &self.origin);
        let (s, fin) = self
            .call(
                reqwest::Method::POST,
                "/internal/v1/approval-credentials/register/finish",
                &self.token(id, approver, &["manager"]),
                Some(json!({"client_data_json": B64URL.encode(&cdj), "attestation_object": B64URL.encode(&att), "label": "loadgen"})),
            )
            .await?;
        anyhow::ensure!(s == 201, "register/finish {s}: {fin}");
        Ok(Tenant {
            id,
            agent,
            approver,
            sender_id,
            from_number,
            authenticator: Mutex::new(auth),
            contacts: Mutex::new(Vec::new()),
            next_phone: AtomicU64::new(1000),
        })
    }

    /// A contact with consent and fewer than two sends today (policy v1 cap).
    async fn contact(&self, t: &Tenant) -> anyhow::Result<(Uuid, String)> {
        {
            let mut cs = t.contacts.lock().await;
            if let Some(c) = cs.iter_mut().find(|c| c.2 < 2) {
                c.2 += 1;
                return Ok((c.0, c.1.clone()));
            }
        }
        let n = t.next_phone.fetch_add(1, Ordering::Relaxed);
        let contact = Uuid::now_v7();
        let to = format!("+1555{n:07}");
        let (s, v) = self
            .call(
                reqwest::Method::POST,
                &format!("/internal/v1/contacts/{contact}/permissions"),
                &self.token(t.id, t.approver, &["manager"]),
                Some(json!({"channel": "sms", "destination": to, "scope": ["customer_requested_follow_up"], "source": "web_form",
                            "proof_digest": format!("sha256:{}", "1".repeat(64)),
                            "granted_at": "2026-10-01T00:00:00Z", "expires_at": "2027-10-01T00:00:00Z"})),
            )
            .await?;
        anyhow::ensure!(s == 201, "permission {s}: {v}");
        t.contacts.lock().await.push((contact, to.clone(), 1));
        Ok((contact, to))
    }

    fn proposal(t: &Tenant, contact: Uuid, to: &str, text: &str) -> Value {
        json!({
            "schema_version": "mk.action.v1",
            "tenant_id": Uuid::nil(), "requested_by": Uuid::nil(),
            "origin": {"type": "agent", "session_id": "load", "model_call_id": Uuid::now_v7().simple().to_string()},
            "workflow": "customer_follow_up", "action_kind": "send_sms", "tool_id": "sms.provider.send.v1",
            "resource": {"type": "contact", "id": contact.to_string()},
            "arguments": {"contact_id": contact.to_string(), "template_id": "t.v1", "rendered_text": text, "to": to,
                          "sender_identity_id": t.sender_id.to_string(), "contact_tz": Self::noon_zone()},
            "purpose": "customer_requested_follow_up", "risk": "high",
            "requested_at": chrono::Utc::now().to_rfc3339(),
            "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339(),
            "idempotency_key": format!("load:{contact}:{}", Uuid::now_v7().simple()),
            "evidence": [{"type": "conversation", "id": "c1", "digest": format!("sha256:{}", "0".repeat(64))}]
        })
    }

    /// Propose → approve → observe to delivered. Records every latency.
    async fn one_message(self: Arc<Self>, t: Arc<Tenant>) {
        let Ok((contact, to)) = self.contact(&t).await else {
            self.counters
                .proposals_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let body = Self::proposal(
            &t,
            contact,
            &to,
            "Hi! Your refill is ready. Reply STOP to opt out.",
        );
        let t0 = Instant::now();
        let Ok((s, v)) = self
            .call(
                reqwest::Method::POST,
                "/internal/v1/actions",
                &self.token(t.id, t.agent, &["agent"]),
                Some(body),
            )
            .await
        else {
            self.counters
                .proposals_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.lat_propose.push(t0.elapsed().as_secs_f64()).await;
        if s != 202 {
            self.counters
                .proposals_rejected
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.counters.proposals_ok.fetch_add(1, Ordering::Relaxed);
        let aid = v["result"]["action_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let digest = v["result"]["action_digest"].clone();
        // Approve with a transaction-bound passkey assertion.
        let t1 = Instant::now();
        let Ok((s, ch)) = self
            .call(
                reqwest::Method::POST,
                &format!("/internal/v1/actions/{aid}/approval-challenge"),
                &self.token(t.id, t.approver, &["manager"]),
                Some(json!({})),
            )
            .await
        else {
            self.counters
                .approvals_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if (400..500).contains(&s) {
            self.counters
                .approvals_refused
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if s != 200 {
            self.counters
                .approvals_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let challenge = mk_crypto::webauthn::b64url_decode(ch["challenge"].as_str().unwrap_or(""))
            .unwrap_or_default();
        let wa = {
            let mut a = t.authenticator.lock().await;
            let (cdj, ad, sig) = a.assert(&challenge, &self.rp_id, &self.origin);
            json!({"credential_id": B64URL.encode(&a.credential_id), "client_data_json": B64URL.encode(&cdj),
                   "authenticator_data": B64URL.encode(&ad), "signature": B64URL.encode(&sig)})
        };
        let Ok((s, _)) = self
            .call(
                reqwest::Method::POST,
                &format!("/internal/v1/actions/{aid}/approve"),
                &self.token(t.id, t.approver, &["manager"]),
                Some(json!({"action_digest": digest, "webauthn": wa})),
            )
            .await
        else {
            self.counters
                .approvals_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let approved_at = Instant::now();
        self.lat_approve.push(t1.elapsed().as_secs_f64()).await;
        if (400..500).contains(&s) {
            // Refused by the kernel (e.g. the action was suppressed by a STOP that
            // landed between proposal and approval): a correct decision, not an error.
            self.counters
                .approvals_refused
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if s != 200 {
            self.counters
                .approvals_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.counters.approvals_ok.fetch_add(1, Ordering::Relaxed);
        // Observe: dispatch start = first state past queued; delivered = provider callbacks applied.
        let mut started: Option<f64> = None;
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let Ok((s, v)) = self
                .call(
                    reqwest::Method::GET,
                    &format!("/internal/v1/actions/{aid}"),
                    &self.token(t.id, t.approver, &["manager"]),
                    None,
                )
                .await
            else {
                continue;
            };
            if s != 200 {
                continue;
            }
            let ms = v["message_state"].as_str().unwrap_or("");
            if started.is_none() && ms != "queued" && ms != "awaiting_approval" {
                started = Some(approved_at.elapsed().as_secs_f64());
            }
            if ms == "delivered" {
                if let Some(pid) = v["provider_message_id"].as_str() {
                    let mut seen = self.seen_provider_ids.lock().await;
                    if seen.insert(pid.to_owned(), t.id).is_some() {
                        self.counters
                            .duplicate_provider_messages
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                self.lat_approved_to_dispatch_start
                    .push(started.unwrap_or(0.0))
                    .await;
                self.lat_approved_to_delivered
                    .push(approved_at.elapsed().as_secs_f64())
                    .await;
                self.counters.delivered.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if matches!(ms, "cancelled" | "suppressed") {
                // A STOP arrived between approval and dispatch: the kernel cancelled the
                // queued send. Correct behaviour, recorded separately from failures.
                self.counters
                    .consent_cancelled
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            if matches!(ms, "failed" | "expired" | "submission_unknown") {
                break;
            }
        }
        self.counters
            .not_delivered_in_time
            .fetch_add(1, Ordering::Relaxed);
    }

    async fn one_read(self: Arc<Self>, t: Arc<Tenant>) {
        let t0 = Instant::now();
        match self
            .call(
                reqwest::Method::GET,
                "/internal/v1/approvals/pending",
                &self.token(t.id, t.approver, &["manager"]),
                None,
            )
            .await
        {
            Ok((200, _)) => {
                self.lat_read.push(t0.elapsed().as_secs_f64()).await;
                self.counters.reads_ok.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.counters.reads_error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn twilio_signature(&self, public_url: &str, form: &[(String, String)]) -> String {
        let mut sorted: Vec<&(String, String)> = form.iter().collect();
        sorted.sort();
        let mut data = public_url.to_owned();
        for (k, v) in sorted {
            data.push_str(k);
            data.push_str(v);
        }
        // HMAC accepts any key length; the Err arm is unreachable but handled without panicking.
        let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(self.auth_token.as_bytes()) else {
            return String::new();
        };
        mac.update(data.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    async fn post_inbound(
        &self,
        t: &Tenant,
        from: &str,
        body: &str,
    ) -> Result<u16, reqwest::Error> {
        let path = format!("/webhooks/twilio/inbound/{}", t.sender_id);
        let form: Vec<(String, String)> = vec![
            (
                "MessageSid".into(),
                format!("SMload{}", Uuid::now_v7().simple()),
            ),
            ("AccountSid".into(), self.account_sid.clone()),
            ("From".into(), from.into()),
            ("To".into(), t.from_number.clone()),
            ("Body".into(), body.into()),
            ("NumMedia".into(), "0".into()),
        ];
        let sig = self.twilio_signature(&format!("{}{path}", self.webhook_base), &form);
        let resp = self
            .http
            .post(format!("{}{path}", self.kernel))
            .header("x-twilio-signature", sig)
            .form(&form)
            .send()
            .await?;
        Ok(resp.status().as_u16())
    }

    /// Benign inbound: measures persistence latency (the 200 means recorded + deduped durably).
    async fn one_inbound(self: Arc<Self>, t: Arc<Tenant>) {
        let from = format!("+1555{:07}", 9_000_000 + (rand::random::<u32>() % 900_000));
        let t0 = Instant::now();
        match self
            .post_inbound(&t, &from, "Thanks, see you Thursday!")
            .await
        {
            Ok(200) => {
                self.lat_inbound.push(t0.elapsed().as_secs_f64()).await;
                self.counters.inbound_ok.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.counters.inbound_error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Opt-out → next proposal to that destination must be refused immediately.
    async fn one_optout(self: Arc<Self>, t: Arc<Tenant>) {
        let Ok((contact, to)) = self.contact(&t).await else {
            return;
        };
        // The destination is about to opt out: never hand this contact to a normal send again.
        if let Some(c) = t.contacts.lock().await.iter_mut().find(|c| c.0 == contact) {
            c.2 = u32::MAX;
        }
        let t0 = Instant::now();
        if !matches!(self.post_inbound(&t, &to, "STOP").await, Ok(200)) {
            self.counters.inbound_error.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let body = Self::proposal(&t, contact, &to, "One more thing. Reply STOP to opt out.");
        match self
            .call(
                reqwest::Method::POST,
                "/internal/v1/actions",
                &self.token(t.id, t.agent, &["agent"]),
                Some(body),
            )
            .await
        {
            Ok((403, v)) if v["decision"]["code"] == json!("suppressed") => {
                self.lat_optout_to_block
                    .push(t0.elapsed().as_secs_f64())
                    .await;
                self.counters.optout_blocked.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.counters
                    .optout_not_blocked
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Serialize)]
struct SloRow {
    id: &'static str,
    requirement: &'static str,
    target: &'static str,
    measured: Value,
    pass: Option<bool>,
    note: &'static str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    let args = Args {
        duration: Duration::from_secs(arg(&argv, "--duration-secs", 60)),
        proposals_per_sec: arg(&argv, "--proposals-per-sec", 2.0),
        reads_per_sec: arg(&argv, "--reads-per-sec", 10.0),
        inbound_per_sec: arg(&argv, "--inbound-per-sec", 1.0),
        tenants: arg(&argv, "--tenants", 2),
        out: arg(&argv, "--out", "load-report.json".to_owned()),
    };
    let env = |k: &str| std::env::var(k).map_err(|_| anyhow::anyhow!("missing env {k}"));
    let sk_raw = B64URL.decode(env("DEV_PRIVATE_KEY")?)?;
    let sk: [u8; 32] = sk_raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("DEV_PRIVATE_KEY must be 32 bytes"))?;
    let rig = Arc::new(Rig {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(64)
            .build()?,
        kernel: env("MK_KERNEL_URL")?.trim_end_matches('/').to_owned(),
        webhook_base: env("MK_WEBHOOK_BASE")?.trim_end_matches('/').to_owned(),
        signer: AssertionSigner::new(
            std::env::var("KERNEL_ASSERTION_KID").unwrap_or_else(|_| "k1".into()),
            ed25519_dalek::SigningKey::from_bytes(&sk),
        ),
        account_sid: env("MK_TWSIM_ACCOUNT_SID")?,
        auth_token: env("MK_TWSIM_AUTH_TOKEN")?,
        rp_id: std::env::var("MK_LOAD_RP_ID").unwrap_or_else(|_| "localhost".into()),
        origin: std::env::var("MK_LOAD_ORIGIN").unwrap_or_else(|_| "http://localhost:8000".into()),
        counters: Counters::new(),
        lat_propose: Series::default(),
        lat_approve: Series::default(),
        lat_approved_to_dispatch_start: Series::default(),
        lat_approved_to_delivered: Series::default(),
        lat_read: Series::default(),
        lat_inbound: Series::default(),
        lat_optout_to_block: Series::default(),
        seen_provider_ids: Mutex::new(HashMap::new()),
    });

    eprintln!("[loadgen] setting up {} tenant(s)", args.tenants);
    let mut tenants = Vec::new();
    for i in 0..args.tenants {
        tenants.push(Arc::new(rig.setup_tenant(i).await?));
    }
    let started = Instant::now();
    let end = started + args.duration;
    let mut handles = Vec::new();
    let mut tick = 0u64;
    let period = Duration::from_millis(100);
    let mut next = Instant::now();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let per_tick = |rate: f64, tick: u64| -> u64 {
        // Deterministic fractional scheduling: rate/10 per 100 ms tick.
        let want = (rate * (tick + 1) as f64 / 10.0).floor() as u64;
        let had = (rate * tick as f64 / 10.0).floor() as u64;
        want - had
    };
    while Instant::now() < end {
        for _ in 0..per_tick(args.proposals_per_sec, tick) {
            let t = tenants[(tick as usize) % tenants.len()].clone();
            handles.push(tokio::spawn(rig.clone().one_message(t)));
        }
        for _ in 0..per_tick(args.reads_per_sec, tick) {
            let t = tenants[(tick as usize + 1) % tenants.len()].clone();
            handles.push(tokio::spawn(rig.clone().one_read(t)));
        }
        for _ in 0..per_tick(args.inbound_per_sec, tick) {
            let t = tenants[(tick as usize) % tenants.len()].clone();
            handles.push(tokio::spawn(rig.clone().one_inbound(t)));
        }
        if tick % 100 == 50 {
            // One opt-out probe every 10 s.
            let t = tenants[(tick as usize) % tenants.len()].clone();
            handles.push(tokio::spawn(rig.clone().one_optout(t)));
        }
        tick += 1;
        next += period;
        tokio::time::sleep_until(tokio::time::Instant::from_std(next)).await;
        if tick.is_multiple_of(100) {
            eprintln!(
                "[loadgen] t={}s proposals_ok={} delivered={} reads_ok={} inbound_ok={}",
                started.elapsed().as_secs(),
                rig.counters.proposals_ok.load(Ordering::Relaxed),
                rig.counters.delivered.load(Ordering::Relaxed),
                rig.counters.reads_ok.load(Ordering::Relaxed),
                rig.counters.inbound_ok.load(Ordering::Relaxed)
            );
        }
    }
    eprintln!("[loadgen] draining in-flight observations");
    for h in handles {
        let _ = h.await;
    }
    let wall = started.elapsed();

    let c = &rig.counters;
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let (propose, approve, start, delivered, read, inbound, optout) = (
        rig.lat_propose.summary().await,
        rig.lat_approve.summary().await,
        rig.lat_approved_to_dispatch_start.summary().await,
        rig.lat_approved_to_delivered.summary().await,
        rig.lat_read.summary().await,
        rig.lat_inbound.summary().await,
        rig.lat_optout_to_block.summary().await,
    );
    let total_api =
        g(&c.proposals_ok) + g(&c.proposals_rejected) + g(&c.approvals_ok) + g(&c.reads_ok);
    let errors = g(&c.proposals_error) + g(&c.approvals_error) + g(&c.reads_error);
    #[allow(clippy::cast_precision_loss)]
    let error_ratio = if total_api + errors == 0 {
        0.0
    } else {
        errors as f64 / (total_api + errors) as f64
    };
    let envelope = args.duration >= Duration::from_hours(8)
        && args.proposals_per_sec >= 20.0
        && args.reads_per_sec >= 100.0;

    let rows = vec![
        SloRow {
            id: "O3-api-p95",
            requirement: "non-AI API p95 ≤ 500 ms",
            target: "0.5",
            measured: json!({"propose_p95": propose.p95, "approve_p95": approve.p95, "read_p95": read.p95}),
            pass: Some(propose.p95 <= 0.5 && approve.p95 <= 0.5 && read.p95 <= 0.5),
            note: "propose, approve (incl. passkey challenge round-trip) and pending-approvals read",
        },
        SloRow {
            id: "O3-api-p99",
            requirement: "non-AI API p99 ≤ 1.5 s",
            target: "1.5",
            measured: json!({"propose_p99": propose.p99, "approve_p99": approve.p99, "read_p99": read.p99}),
            pass: Some(propose.p99 <= 1.5 && approve.p99 <= 1.5 && read.p99 <= 1.5),
            note: "",
        },
        SloRow {
            id: "O3-dispatch-start",
            requirement: "approved eligible action → dispatch start p95 ≤ 10 s / p99 ≤ 60 s",
            target: "10 / 60",
            measured: json!({"p95": start.p95, "p99": start.p99, "count": start.count}),
            pass: Some(start.count > 0 && start.p95 <= 10.0 && start.p99 <= 60.0),
            note: "observed by polling at 100 ms; includes outbox relay + stream + worker lease",
        },
        SloRow {
            id: "O3-delivered",
            requirement: "approved → delivered via signed callbacks (informational)",
            target: "—",
            measured: json!({"p95": delivered.p95, "p99": delivered.p99, "count": delivered.count}),
            pass: None,
            note: "simulator callbacks; real provider latency is not represented",
        },
        SloRow {
            id: "O3-inbound-persist",
            requirement: "inbound persistence p99 ≤ 2 s",
            target: "2",
            measured: json!({"p99": inbound.p99, "count": inbound.count}),
            pass: Some(inbound.count > 0 && inbound.p99 <= 2.0),
            note: "signed webhook → 200 (recorded, deduped, sealed)",
        },
        SloRow {
            id: "O3-optout",
            requirement: "opt-out recorded → new dispatch blocked immediately at the authorization boundary",
            target: "every probe",
            measured: json!({"blocked": g(&c.optout_blocked), "not_blocked": g(&c.optout_not_blocked), "p99_secs": optout.p99}),
            pass: Some(g(&c.optout_not_blocked) == 0 && g(&c.optout_blocked) > 0),
            note: "STOP then an immediate proposal to the same destination must be 403 suppressed",
        },
        SloRow {
            id: "O4-no-dup",
            requirement: "no unauthorized or duplicate execution",
            target: "0",
            measured: json!({"duplicate_provider_message_ids": g(&c.duplicate_provider_messages), "not_delivered_in_time": g(&c.not_delivered_in_time)}),
            pass: Some(g(&c.duplicate_provider_messages) == 0),
            note: "duplicate detection is by provider message id across the whole run",
        },
        SloRow {
            id: "O4-errors",
            requirement: "error rate under load",
            target: "< 5% transport/5xx",
            measured: json!({"ratio": error_ratio, "errors": errors}),
            pass: Some(error_ratio < 0.05),
            note: "",
        },
        SloRow {
            id: "O4-envelope",
            requirement: "8 h at envelope (20 proposal/s, 100 read/s, 10 dispatch/s), 30 min at 2×, 24 h at ½",
            target: "run length and rates",
            measured: json!({"duration_secs": wall.as_secs(), "proposals_per_sec": args.proposals_per_sec, "reads_per_sec": args.reads_per_sec}),
            pass: Some(envelope),
            note: if envelope {
                "envelope run"
            } else {
                "NOT an envelope run — this report is a functional load check, not qualification evidence"
            },
        },
    ];
    let report = json!({
        "tool": "mk-loadgen",
        "at": chrono::Utc::now().to_rfc3339(),
        "run": {"duration_secs": wall.as_secs(), "tenants": args.tenants, "proposals_per_sec": args.proposals_per_sec, "reads_per_sec": args.reads_per_sec, "inbound_per_sec": args.inbound_per_sec, "envelope_run": envelope},
        "counts": {
            "proposals_ok": g(&c.proposals_ok), "proposals_rejected": g(&c.proposals_rejected), "proposals_error": g(&c.proposals_error),
            "approvals_ok": g(&c.approvals_ok), "approvals_error": g(&c.approvals_error),
            "delivered": g(&c.delivered), "not_delivered_in_time": g(&c.not_delivered_in_time),
            "consent_cancelled_before_dispatch": g(&c.consent_cancelled), "approvals_refused_4xx": g(&c.approvals_refused),
            "reads_ok": g(&c.reads_ok), "reads_error": g(&c.reads_error),
            "inbound_ok": g(&c.inbound_ok), "inbound_error": g(&c.inbound_error),
            "optout_blocked": g(&c.optout_blocked), "optout_not_blocked": g(&c.optout_not_blocked),
            "duplicate_provider_message_ids": g(&c.duplicate_provider_messages)
        },
        "latency_secs": {"propose": propose, "approve": approve, "approved_to_dispatch_start": start, "approved_to_delivered": delivered, "read_pending_approvals": read, "inbound_webhook": inbound, "optout_to_block": optout},
        "slo": rows,
        "verdict": {
            "all_measured_slos_pass": rows.iter().filter(|r| r.id != "O4-envelope").all(|r| r.pass.unwrap_or(true)),
            "qualification_evidence": envelope,
            "status_vocabulary": "author-run → Implemented at most; Independently verified requires a second person to run and record this"
        }
    });
    std::fs::write(&args.out, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report["verdict"])?);
    let all_ok = report["verdict"]["all_measured_slos_pass"]
        .as_bool()
        .unwrap_or(false);
    if !all_ok {
        std::process::exit(1);
    }
    Ok(())
}
