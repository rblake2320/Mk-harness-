use std::sync::Arc;

use mk_crypto::{AssertionVerifier, Keyring, MasterKey};
use mk_policy::ToolAllowlist;
use mk_store::Store;

use crate::metrics::Metrics;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub verifier: AssertionVerifier,
    /// Fingerprint HMAC key (stable). Sealing uses `keyring`.
    pub master: MasterKey,
    /// Versioned envelope keys for data at rest (S6).
    pub keyring: Keyring,
    /// Destination fingerprint keys (first = current); see `mk_store::fingerprint`.
    pub fingerprints: Arc<mk_store::fingerprint::FingerprintKeys>,
    pub tools: Arc<ToolAllowlist>,
    pub metrics: Arc<Metrics>,
    /// Per-tenant rate limits and replica in-flight cap (O2).
    pub limiter: crate::limits::Limiter,
    /// HMAC timestamp tolerance for adapter callbacks (seconds).
    pub callback_tolerance_secs: i64,
    /// Feature flag: when false, proposals are evaluated and recorded but
    /// never enqueued (shadow mode).
    pub rust_kernel_enabled: bool,
    /// Human-approval authority (WP06). `Some` → every approve requires a
    /// kernel-verified WebAuthn assertion; `None` is legal only when
    /// `MK_ALLOW_UNBOUND_APPROVAL=1` and every approval row is marked `unbound`.
    pub approval_rp: Option<ApprovalRp>,
    /// Public base URL the messaging provider calls (e.g. `https://hooks.example.com`).
    /// Webhook signatures are verified over this, never over request headers.
    pub public_webhook_base: Option<String>,
}

/// WebAuthn relying-party configuration for approvals.
#[derive(Debug, Clone)]
pub struct ApprovalRp {
    /// e.g. `app.example.com` — the effective domain of the approval UI.
    pub rp_id: String,
    /// Exact origins allowed in clientDataJSON, e.g. `https://app.example.com`.
    pub origins: Vec<String>,
    /// Require the user-verified flag (biometric/PIN). Always true in production.
    pub require_uv: bool,
}

impl ApprovalRp {
    /// Parse `MK_APPROVAL_RP_ID` / `MK_APPROVAL_ORIGINS` (comma-separated).
    pub fn from_env() -> Result<Option<Self>, String> {
        let rp_id = std::env::var("MK_APPROVAL_RP_ID")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let allow_unbound = std::env::var("MK_ALLOW_UNBOUND_APPROVAL").is_ok_and(|v| v == "1");
        match rp_id {
            None if allow_unbound => Ok(None),
            None => Err("MK_APPROVAL_RP_ID is required (set MK_ALLOW_UNBOUND_APPROVAL=1 only for development)".into()),
            Some(rp_id) => {
                let origins: Vec<String> = std::env::var("MK_APPROVAL_ORIGINS")
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().trim_end_matches('/').to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                if origins.is_empty() {
                    return Err("MK_APPROVAL_ORIGINS must list at least one https origin".into());
                }
                for o in &origins {
                    let ok_scheme = o.starts_with("https://")
                        || (o.starts_with("http://localhost") || o.starts_with("http://127.0.0.1"));
                    if !ok_scheme {
                        return Err(format!("MK_APPROVAL_ORIGINS: '{o}' must be https (http only for localhost)"));
                    }
                    let host = o.trim_start_matches("https://").trim_start_matches("http://");
                    let host = host.split(':').next().unwrap_or("");
                    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
                        return Err(format!("MK_APPROVAL_ORIGINS: '{o}' is not within rp id '{rp_id}'"));
                    }
                }
                let require_uv = !std::env::var("MK_APPROVAL_ALLOW_NO_UV").is_ok_and(|v| v == "1");
                Ok(Some(Self { rp_id, origins, require_uv }))
            }
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppState(enabled={})", self.rust_kernel_enabled)
    }
}
