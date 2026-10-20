use std::sync::Arc;

use mk_crypto::{AssertionVerifier, MasterKey};
use mk_policy::ToolAllowlist;
use mk_store::Store;
use tokio::sync::Mutex;

use crate::auth::JtiGuard;
use crate::metrics::Metrics;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub verifier: AssertionVerifier,
    pub master: MasterKey,
    pub tools: Arc<ToolAllowlist>,
    pub metrics: Arc<Metrics>,
    pub jti: Arc<Mutex<JtiGuard>>,
    /// HMAC timestamp tolerance for adapter callbacks (seconds).
    pub callback_tolerance_secs: i64,
    /// Feature flag: when false, proposals are evaluated and recorded but
    /// never enqueued (shadow mode).
    pub rust_kernel_enabled: bool,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppState(enabled={})", self.rust_kernel_enabled)
    }
}
