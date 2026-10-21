//! Twilio Programmable Messaging adapter (`twilio-sms-v1`) — contract row C1.
//!
//! Production SMS transport per `docs/transport-decision.md`. Each consultant
//! business has its own registered sender (a dedicated number or Messaging
//! Service) and its own provider credentials, resolved per tenant through a
//! [`SenderResolver`]; nothing here is shared across businesses.
//!
//! Boundaries that this module enforces:
//! * **Egress** only to the allowlisted Twilio API authority.
//! * **Error classification** is conservative: anything that *may* have
//!   created a message on the provider side is `Ambiguous` (the kernel then
//!   records `submission_unknown` and never blindly retries). Only failures
//!   that provably happened before the request left are `Transient`.
//! * **Webhook authentication** is Twilio's documented procedure —
//!   `base64(HMAC-SHA1(auth_token, public_url + sorted(k+v)...))` compared in
//!   constant time against `X-Twilio-Signature` — computed over the *configured
//!   public URL*, never a client-supplied `Host`/`X-Forwarded-*` header.
//! * **Provider opt-out** (`21610 unsubscribed recipient`) is surfaced as a
//!   distinct permanent error so the caller suppresses the destination.
//! * **Reconciliation** lists provider messages for `(from, to, date)` and
//!   matches by body digest; it reports `Unknown` rather than guess.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use mk_crypto::{AdapterSecret, Digest};
use mk_domain::{ActionKind, TenantId};
use mk_queue::RetryClass;
use serde::Deserialize;
use serde_json::Value;
use sha1::Sha1;

use crate::egress::EgressAllowlist;
use crate::{
    ActionAdapter, AdapterDescriptor, AdapterError, AdapterReceipt, AuthorizedAction,
    ReconcileResult, sealed,
};

pub const ADAPTER_KIND: &str = "twilio-sms-v1";
pub const TOOL_ID: &str = "sms.provider.send.v1";
pub const DEFAULT_API_AUTHORITY: &str = "api.twilio.com";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_BODY_CHARS: usize = 1600;

/// A resolved sender for one consultant business.
#[derive(Clone)]
pub struct TwilioSender {
    pub sender_identity_id: uuid::Uuid,
    pub account_sid: String,
    pub auth_token: AdapterSecret,
    /// Exactly one of `from_number` / `messaging_service_sid`.
    pub from_number: Option<String>,
    pub messaging_service_sid: Option<String>,
    /// Kernel-owned public URL for status callbacks (includes the sender id).
    pub status_callback_url: String,
}

impl std::fmt::Debug for TwilioSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TwilioSender(id={}, account={}…)", self.sender_identity_id, &self.account_sid[..self.account_sid.len().min(6)])
    }
}

#[async_trait]
pub trait SenderResolver: Send + Sync + std::fmt::Debug {
    async fn resolve(&self, tenant: TenantId, sender_identity_id: uuid::Uuid) -> Option<TwilioSender>;
}

#[derive(Debug)]
pub struct TwilioAdapter {
    client: reqwest::Client,
    egress: EgressAllowlist,
    api_base: url::Url,
    resolver: Box<dyn SenderResolver>,
}

impl sealed::Sealed for TwilioAdapter {}

/// Provider error codes we classify specially. Everything else in 4xx is
/// permanent (bad request) and 5xx is ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderOutcome {
    Accepted,
    /// 21610 — recipient has opted out at the provider. Caller must suppress.
    RecipientOptedOut,
    InvalidDestination,
    SenderNotCapable,
    RateLimited,
    AuthFailed,
    Other4xx,
    Server5xx,
}

#[derive(Debug, Deserialize)]
struct TwilioMessage {
    sid: String,
    status: String,
    #[serde(default)]
    error_code: Option<i64>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    date_created: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TwilioError {
    #[serde(default)]
    code: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TwilioList {
    #[serde(default)]
    messages: Vec<TwilioMessage>,
}

impl TwilioAdapter {
    pub fn new(
        egress: EgressAllowlist,
        api_base: &str,
        resolver: Box<dyn SenderResolver>,
    ) -> Result<Self, AdapterError> {
        let api_base = url::Url::parse(api_base).map_err(|_| AdapterError::permanent("api_base_invalid"))?;
        egress
            .check(api_base.as_str())
            .map_err(|_| AdapterError::permanent("api_base_not_allowlisted"))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent("mk-action-kernel/twilio-sms-v1")
            .build()
            .map_err(|_| AdapterError::permanent("client_build"))?;
        Ok(Self { client, egress, api_base, resolver })
    }

    fn messages_url(&self, account_sid: &str) -> Result<url::Url, AdapterError> {
        if !account_sid.starts_with("AC") || account_sid.len() != 34 || !account_sid[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AdapterError::permanent("account_sid_invalid"));
        }
        self.api_base
            .join(&format!("/2010-04-01/Accounts/{account_sid}/Messages.json"))
            .map_err(|_| AdapterError::permanent("url"))
    }

    /// Form body for a send. Pure: unit-tested without the network.
    pub fn build_form(sender: &TwilioSender, to: &str, body: &str) -> Result<Vec<(&'static str, String)>, AdapterError> {
        validate_e164(to)?;
        if body.is_empty() || body.chars().count() > MAX_BODY_CHARS {
            return Err(AdapterError::permanent("body_length"));
        }
        let mut form = vec![("To", to.to_owned()), ("Body", body.to_owned()), ("StatusCallback", sender.status_callback_url.clone())];
        match (&sender.from_number, &sender.messaging_service_sid) {
            (Some(f), None) => {
                validate_e164(f)?;
                form.push(("From", f.clone()));
            }
            (None, Some(m)) if m.starts_with("MG") && m.len() == 34 => form.push(("MessagingServiceSid", m.clone())),
            _ => return Err(AdapterError::permanent("sender_misconfigured")),
        }
        Ok(form)
    }

    /// Classify a provider HTTP response.
    pub fn classify(status: u16, body: &[u8]) -> ProviderOutcome {
        match status {
            200..=299 => ProviderOutcome::Accepted,
            401 | 403 => ProviderOutcome::AuthFailed,
            429 => ProviderOutcome::RateLimited,
            400..=499 => {
                let code = serde_json::from_slice::<TwilioError>(body).ok().and_then(|e| e.code);
                match code {
                    Some(21610) => ProviderOutcome::RecipientOptedOut,
                    Some(21211 | 21614 | 21217 | 21408) => ProviderOutcome::InvalidDestination,
                    Some(21606 | 21612 | 21660 | 21661) => ProviderOutcome::SenderNotCapable,
                    _ => ProviderOutcome::Other4xx,
                }
            }
            _ => ProviderOutcome::Server5xx,
        }
    }
}

fn validate_e164(s: &str) -> Result<(), AdapterError> {
    let ok = s.len() >= 9 && s.len() <= 16 && s.starts_with('+') && s[1..].bytes().all(|b| b.is_ascii_digit()) && !s.starts_with("+0");
    if ok { Ok(()) } else { Err(AdapterError::permanent("destination_not_e164")) }
}

/// Twilio request validation: `X-Twilio-Signature` =
/// `base64(HMAC-SHA1(auth_token, url ‖ Σ_{k sorted} k‖v))`, where `url` is the
/// exact public URL Twilio was configured to call (scheme, host, port if
/// non-default, path, and query string). Compared in constant time.
#[must_use]
pub fn twilio_signature(auth_token: &AdapterSecret, public_url: &str, form: &[(String, String)]) -> String {
    let mut sorted: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (k, v) in form {
        sorted.entry(k.as_str()).or_default().push(v.as_str());
    }
    let mut data = public_url.to_owned();
    for (k, vs) in sorted {
        let mut vs = vs;
        vs.sort_unstable();
        for v in vs {
            data.push_str(k);
            data.push_str(v);
        }
    }
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(auth_token.expose_bytes()).unwrap_or_else(|_| {
        // HMAC accepts any key length; unreachable, but never panic in an adapter.
        <Hmac<Sha1> as Mac>::new_from_slice(b"").unwrap_or_else(|_| unreachable_mac())
    });
    mac.update(data.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn unreachable_mac() -> Hmac<Sha1> {
    // `Hmac::new_from_slice` cannot fail for any key length; this exists only
    // to keep the no-panic lint honest.
    #[allow(clippy::expect_used)]
    <Hmac<Sha1> as Mac>::new_from_slice(&[0u8; 1]).expect("hmac accepts any key")
}

/// Verify a webhook. `public_url` must come from kernel configuration.
pub fn verify_twilio_signature(
    auth_token: &AdapterSecret,
    public_url: &str,
    form: &[(String, String)],
    header_value: &str,
) -> bool {
    let expected = twilio_signature(auth_token, public_url, form);
    mk_crypto::constant_time_eq(expected.as_bytes(), header_value.trim().as_bytes())
}

/// Monotonic delivery states derived from provider callbacks (contract C3).
/// Order matters: a callback can only move a message *forward*; a late
/// `sent` after `delivered` is recorded as an event but changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeliveryState {
    SubmissionStarted = 0,
    ProviderAccepted = 1,
    Sent = 2,
    Delivered = 3,
    /// Provider reported a terminal failure (`failed`, `undelivered`).
    Failed = 4,
    /// Provider says sent but no delivery evidence will ever arrive, or the
    /// provider reported `unknown`. Never set because time passed.
    DeliveryUnknown = 5,
}

impl DeliveryState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubmissionStarted => "submission_started",
            Self::ProviderAccepted => "provider_accepted",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }

    /// Map a Twilio `MessageStatus` to evidence. `None` = no state change
    /// (e.g. `receiving`, `scheduled`, `canceled` on an unsent message).
    #[must_use]
    pub fn from_twilio_status(s: &str) -> Option<Self> {
        match s {
            "queued" | "accepted" | "sending" => Some(Self::ProviderAccepted),
            "sent" => Some(Self::Sent),
            "delivered" | "read" => Some(Self::Delivered),
            "failed" | "undelivered" | "canceled" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Monotonic fold: terminal evidence (`Delivered`, `Failed`) is never
    /// overwritten by weaker evidence; `DeliveryUnknown` only applies to a
    /// message that was `Sent` and is explicitly declared unknown.
    #[must_use]
    pub fn fold(current: Self, event: Self) -> Self {
        match (current, event) {
            (Self::Delivered | Self::Failed, _) => current,
            (Self::DeliveryUnknown, Self::Delivered | Self::Failed) => event,
            (Self::DeliveryUnknown, _) => current,
            (c, e) if e > c => e,
            (c, _) => c,
        }
    }
}

#[async_trait]
impl ActionAdapter for TwilioAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            adapter_kind: ADAPTER_KIND,
            tool_ids: &[TOOL_ID],
            kinds: &[ActionKind::SendSms],
            callback_based: true,
            pii_fields: &["to", "rendered_text", "contact_id"],
        }
    }

    async fn validate(&self, action: &AuthorizedAction) -> Result<(), AdapterError> {
        if action.request.action_kind != ActionKind::SendSms {
            return Err(AdapterError::permanent("kind_not_supported"));
        }
        let args = &action.request.arguments;
        let to = args.get("to").and_then(Value::as_str).ok_or(AdapterError::permanent("missing_destination"))?;
        validate_e164(to)?;
        args.get("rendered_text").and_then(Value::as_str).ok_or(AdapterError::permanent("missing_rendered_text"))?;
        args.get("sender_identity_id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<uuid::Uuid>().ok())
            .ok_or(AdapterError::permanent("missing_sender_identity"))?;
        Ok(())
    }

    async fn execute(&self, action: &AuthorizedAction) -> Result<AdapterReceipt, AdapterError> {
        self.validate(action).await?;
        let args = &action.request.arguments;
        let to = args.get("to").and_then(Value::as_str).unwrap_or_default();
        let text = args.get("rendered_text").and_then(Value::as_str).unwrap_or_default();
        let sid: uuid::Uuid = args.get("sender_identity_id").and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or_default();
        let sender = self
            .resolver
            .resolve(action.tenant_id, sid)
            .await
            .ok_or(AdapterError::permanent("sender_not_registered"))?;
        let url = self.messages_url(&sender.account_sid)?;
        self.egress.check(url.as_str()).map_err(|_| AdapterError::permanent("egress_not_allowlisted"))?;
        let form = Self::build_form(&sender, to, text)?;
        let resp = self
            .client
            .post(url)
            .basic_auth(&sender.account_sid, Some(std::str::from_utf8(sender.auth_token.expose_bytes()).unwrap_or_default()))
            .form(&form)
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            // Could not connect: the request never left. Safe to retry.
            Err(e) if e.is_connect() => return Err(AdapterError::transient("provider_unreachable")),
            // Request may have been received: the message may exist. Never retry blindly.
            Err(_) => return Err(AdapterError::ambiguous("response_lost")),
        };
        let status = resp.status().as_u16();
        let bytes = match resp.bytes().await {
            Ok(b) if b.len() <= MAX_RESPONSE_BYTES => b,
            Ok(_) => return Err(AdapterError::ambiguous("response_too_large")),
            Err(_) => return Err(AdapterError::ambiguous("response_body_lost")),
        };
        match Self::classify(status, &bytes) {
            ProviderOutcome::Accepted => {
                let m: TwilioMessage = serde_json::from_slice(&bytes).map_err(|_| AdapterError::ambiguous("response_unparseable"))?;
                if !m.sid.starts_with("SM") && !m.sid.starts_with("MM") {
                    return Err(AdapterError::ambiguous("message_sid_invalid"));
                }
                let _ = m.status; // provider_accepted; callbacks carry the rest
                Ok(AdapterReceipt {
                    adapter_id: Some(sender.sender_identity_id),
                    external_ref: Some(m.sid),
                    result_digest: Some(Digest::of(&bytes)),
                    pending_callback: true,
                })
            }
            ProviderOutcome::RecipientOptedOut => Err(AdapterError::permanent("provider_opt_out")),
            ProviderOutcome::InvalidDestination => Err(AdapterError::permanent("destination_invalid")),
            ProviderOutcome::SenderNotCapable => Err(AdapterError::permanent("sender_not_capable")),
            ProviderOutcome::AuthFailed => Err(AdapterError::permanent("provider_auth_failed")),
            ProviderOutcome::RateLimited => Err(AdapterError { class: RetryClass::RateLimited { retry_after_secs: 30 }, code: "provider_rate_limited" }),
            ProviderOutcome::Other4xx => Err(AdapterError::permanent("provider_rejected")),
            // A 5xx after the request was received may or may not have created the message.
            ProviderOutcome::Server5xx => Err(AdapterError::ambiguous("provider_5xx")),
        }
    }

    /// Reconcile an ambiguous submission by listing the sender's messages to
    /// the destination for the attempt day and matching on the body digest.
    /// `external_ref` on the receipt is the kernel action id when no provider
    /// sid was obtained; the caller supplies `(tenant, sender, to, body, date)`
    /// through `reconcile_submission` instead of this trait method.
    async fn reconcile(&self, _receipt: &AdapterReceipt) -> Result<ReconcileResult, AdapterError> {
        Ok(ReconcileResult::Unknown)
    }
}

impl TwilioAdapter {
    /// Search the provider for a message matching an ambiguous submission.
    /// Returns the provider sid when exactly one matching message exists.
    pub async fn reconcile_submission(
        &self,
        tenant: TenantId,
        sender_identity_id: uuid::Uuid,
        to: &str,
        body: &str,
        date_sent_utc: chrono::NaiveDate,
    ) -> Result<Reconciled, AdapterError> {
        let sender = self.resolver.resolve(tenant, sender_identity_id).await.ok_or(AdapterError::permanent("sender_not_registered"))?;
        let mut url = self.messages_url(&sender.account_sid)?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("To", to).append_pair("DateSent", &date_sent_utc.format("%Y-%m-%d").to_string()).append_pair("PageSize", "50");
            if let Some(f) = &sender.from_number {
                q.append_pair("From", f);
            }
        }
        let resp = self
            .client
            .get(url)
            .basic_auth(&sender.account_sid, Some(std::str::from_utf8(sender.auth_token.expose_bytes()).unwrap_or_default()))
            .send()
            .await
            .map_err(|_| AdapterError::transient("provider_unreachable"))?;
        if !resp.status().is_success() {
            return Err(AdapterError::transient("provider_list_failed"));
        }
        let bytes = resp.bytes().await.map_err(|_| AdapterError::transient("provider_list_failed"))?;
        let list: TwilioList = serde_json::from_slice(&bytes).map_err(|_| AdapterError::transient("provider_list_unparseable"))?;
        let want = Digest::of(body.as_bytes());
        let matches: Vec<&TwilioMessage> = list
            .messages
            .iter()
            .filter(|m| m.to.as_deref() == Some(to) && m.body.as_deref().is_some_and(|b| Digest::of(b.as_bytes()).ct_eq(&want)))
            .collect();
        Ok(match matches.as_slice() {
            [] => Reconciled::NotFound,
            [m] => Reconciled::Found { provider_message_id: m.sid.clone(), status: m.status.clone(), error_code: m.error_code, date_created: m.date_created.clone() },
            _ => Reconciled::Multiple(matches.len()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    /// No matching message exists at the provider: the submission did not happen.
    NotFound,
    /// Exactly one matching message exists.
    Found { provider_message_id: String, status: String, error_code: Option<i64>, date_created: Option<String> },
    /// More than one match: a human must resolve; never pick one.
    Multiple(usize),
}

// ---------------------------------------------------------------------------
// Opt-out detection on inbound text (contract: explicit vs. possible).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptOutSignal {
    /// Carrier-standard keywords: suppress immediately.
    Explicit,
    /// Natural-language refusal that is not a standard keyword: hold.
    Possible,
    None,
}

/// Standard English opt-out keywords honoured by US carriers / Twilio
/// Advanced Opt-Out. Matched on the trimmed, case-folded whole message, or
/// as the first word followed only by punctuation.
const EXPLICIT: &[&str] = &["stop", "stopall", "unsubscribe", "cancel", "end", "quit", "revoke", "optout", "opt-out", "opt out"];
/// Clear natural-language stop requests: not carrier keywords, but unambiguous.
/// Mirrored in `backend/app/inbound.py::_EXPLICIT_PHRASES`; keep both in sync.
const EXPLICIT_PHRASES: &[&str] = &[
    "stop texting", "stop messaging", "don't text", "dont text", "do not text", "don't message", "do not message",
    "remove me", "take me off", "no more texts", "no more messages", "unsubscribe me", "stop sending", "stop contacting",
    "lose my number", "please stop",
];
const POSSIBLE: &[&str] = &["leave me alone", "not interested", "wrong number", "unsub", "stop it", "go away", "no thanks", "no thank you"];

#[must_use]
pub fn detect_opt_out(body: &str) -> OptOutSignal {
    let norm: String = body.trim().to_lowercase().chars().filter(|c| !matches!(c, '.' | '!' | '?' | ',' | '"' | '\'' | '\u{201c}' | '\u{201d}')).collect();
    let norm = norm.split_whitespace().collect::<Vec<_>>().join(" ");
    if EXPLICIT.contains(&norm.as_str()) {
        return OptOutSignal::Explicit;
    }
    let first = norm.split(' ').next().unwrap_or("");
    if EXPLICIT.contains(&first) && norm.split(' ').count() <= 2 && !norm.starts_with("stop by") {
        return OptOutSignal::Explicit;
    }
    if EXPLICIT_PHRASES.iter().any(|p| norm.contains(p)) {
        return OptOutSignal::Explicit;
    }
    if POSSIBLE.iter().any(|p| norm.contains(p)) || (norm.contains("stop") && !norm.contains("stop by") && !norm.contains("nonstop") && !norm.contains("non-stop")) {
        return OptOutSignal::Possible;
    }
    OptOutSignal::None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sender() -> TwilioSender {
        TwilioSender {
            sender_identity_id: uuid::Uuid::nil(),
            account_sid: format!("AC{}", "a".repeat(32)),
            auth_token: AdapterSecret::new("12345"),
            from_number: Some("+15005550006".into()),
            messaging_service_sid: None,
            status_callback_url: "https://kernel.example.com/webhooks/twilio/status/00000000-0000-0000-0000-000000000000".into(),
        }
    }

    #[test]
    fn signature_matches_twilio_documented_example() {
        // From Twilio's "Validating requests" docs: token 12345, URL
        // https://mycompany.com/myapp.php?foo=1&bar=2 with the documented params
        // yields RSOYDt4T1cUTdK1PDd93/VVr8B8=.
        let token = AdapterSecret::new("12345");
        let url = "https://mycompany.com/myapp.php?foo=1&bar=2";
        let form: Vec<(String, String)> = [
            ("CallSid", "CA1234567890ABCDE"), ("Caller", "+14158675309"), ("Digits", "1234"),
            ("From", "+14158675309"), ("To", "+18005551212"),
        ].iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        assert_eq!(twilio_signature(&token, url, &form), "RSOYDt4T1cUTdK1PDd93/VVr8B8=");
        assert!(verify_twilio_signature(&token, url, &form, "RSOYDt4T1cUTdK1PDd93/VVr8B8="));
        // Forged Host / different configured URL → invalid.
        assert!(!verify_twilio_signature(&token, "https://attacker.example/myapp.php?foo=1&bar=2", &form, "RSOYDt4T1cUTdK1PDd93/VVr8B8="));
        // One changed param → invalid.
        let mut tampered = form.clone();
        tampered[2].1 = "1235".into();
        assert!(!verify_twilio_signature(&token, url, &tampered, "RSOYDt4T1cUTdK1PDd93/VVr8B8="));
        assert!(!verify_twilio_signature(&token, url, &form, ""));
    }

    #[test]
    fn form_requires_exactly_one_sender_and_e164() {
        let s = sender();
        let f = TwilioAdapter::build_form(&s, "+15555550100", "Hi. Reply STOP to opt out.").unwrap();
        assert!(f.iter().any(|(k, v)| *k == "From" && v == "+15005550006"));
        assert!(f.iter().any(|(k, _)| *k == "StatusCallback"));
        assert!(TwilioAdapter::build_form(&s, "5555550100", "x").is_err());
        let mut both = sender();
        both.messaging_service_sid = Some(format!("MG{}", "b".repeat(32)));
        assert_eq!(TwilioAdapter::build_form(&both, "+15555550100", "x").unwrap_err().code, "sender_misconfigured");
        let mut none = sender();
        none.from_number = None;
        assert_eq!(TwilioAdapter::build_form(&none, "+15555550100", "x").unwrap_err().code, "sender_misconfigured");
        assert_eq!(TwilioAdapter::build_form(&s, "+15555550100", &"x".repeat(1601)).unwrap_err().code, "body_length");
    }

    #[test]
    fn classification_is_conservative() {
        assert_eq!(TwilioAdapter::classify(201, b"{}"), ProviderOutcome::Accepted);
        assert_eq!(TwilioAdapter::classify(400, br#"{"code":21610,"message":"unsubscribed"}"#), ProviderOutcome::RecipientOptedOut);
        assert_eq!(TwilioAdapter::classify(400, br#"{"code":21211}"#), ProviderOutcome::InvalidDestination);
        assert_eq!(TwilioAdapter::classify(400, br#"{"code":99999}"#), ProviderOutcome::Other4xx);
        assert_eq!(TwilioAdapter::classify(401, b""), ProviderOutcome::AuthFailed);
        assert_eq!(TwilioAdapter::classify(429, b""), ProviderOutcome::RateLimited);
        assert_eq!(TwilioAdapter::classify(500, b""), ProviderOutcome::Server5xx);
        assert_eq!(TwilioAdapter::classify(503, b"not json"), ProviderOutcome::Server5xx);
    }

    #[test]
    fn delivery_state_is_monotonic_and_never_time_upgraded() {
        use DeliveryState as D;
        let mut s = D::SubmissionStarted;
        for ev in ["queued", "sent", "delivered"] {
            s = D::fold(s, D::from_twilio_status(ev).unwrap());
        }
        assert_eq!(s, D::Delivered);
        // Late, out-of-order weaker evidence does not regress.
        assert_eq!(D::fold(D::Delivered, D::Sent), D::Delivered);
        assert_eq!(D::fold(D::Delivered, D::ProviderAccepted), D::Delivered);
        assert_eq!(D::fold(D::Failed, D::Delivered), D::Failed);
        assert_eq!(D::fold(D::Sent, D::ProviderAccepted), D::Sent);
        // Unknown can later be resolved by terminal evidence only.
        assert_eq!(D::fold(D::DeliveryUnknown, D::Sent), D::DeliveryUnknown);
        assert_eq!(D::fold(D::DeliveryUnknown, D::Delivered), D::Delivered);
        assert_eq!(D::from_twilio_status("receiving"), None);
        assert_eq!(D::from_twilio_status("read"), Some(D::Delivered));
    }

    #[test]
    fn opt_out_detection_separates_explicit_from_possible() {
        use OptOutSignal as O;
        for s in ["STOP", "stop", " Stop. ", "UNSUBSCRIBE", "Stop!", "quit", "END", "opt out", "STOP please",
                  "please stop texting me", "I'm not interested, remove me", "Can you stop sending these"] {
            assert_eq!(detect_opt_out(s), O::Explicit, "{s}");
        }
        for s in ["wrong number", "stop it already", "leave me alone", "not interested", "no thanks"] {
            assert_eq!(detect_opt_out(s), O::Possible, "{s}");
        }
        for s in ["Stop by anytime, I'd love a sample!", "yes Thursday works", "I can't stop by today but Friday is good", "nonstop fun", "Thanks!"] {
            assert_ne!(detect_opt_out(s), O::Explicit, "{s}");
        }
        assert_eq!(detect_opt_out("Stop by anytime, I'd love a sample!"), O::None);
        assert_eq!(detect_opt_out("yes Thursday works"), O::None);
    }
}
