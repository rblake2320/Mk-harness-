//! Process configuration from environment. Secrets are read once and never
//! logged.

use mk_crypto::MasterKey;
use secrecy::SecretString;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: SecretString,
    pub redis_url: SecretString,
    pub master_key: MasterKey,
    pub worker_id: String,
    pub adapter_intake_template: String,
    /// Twilio API base (empty = adapter disabled). Production: https://api.twilio.com
    pub twilio_api_base: String,
    /// Public base URL the provider calls back (kernel webhook ingress).
    pub public_webhook_base: String,
    pub egress_authorities: Vec<String>,
    pub allow_loopback_http: bool,
    pub batch: usize,
    pub lease_secs: u64,
    /// `/metrics` listener (`MK_METRICS_BIND`, default loopback :9100; empty disables).
    pub metrics_bind: String,
    /// Gauge sampler period in seconds (`MK_METRICS_SAMPLE_SECS`, default 15).
    pub metrics_sample_secs: u64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let get = |k: &str| std::env::var(k).map_err(|_| anyhow::anyhow!("missing env {k}"));
        Ok(Self {
            database_url: SecretString::from(get("MK_DATABASE_URL")?),
            redis_url: SecretString::from(get("MK_REDIS_URL")?),
            master_key: MasterKey::from_base64(&get("MK_MASTER_KEY")?)
                .map_err(|e| anyhow::anyhow!("MK_MASTER_KEY: {e}"))?,
            worker_id: std::env::var("MK_WORKER_ID")
                .unwrap_or_else(|_| format!("worker-{}", uuid::Uuid::now_v7().simple())),
            adapter_intake_template: std::env::var("MK_MOBILE_INTAKE_URL").unwrap_or_default(),
            twilio_api_base: std::env::var("MK_TWILIO_API_BASE").unwrap_or_default(),
            public_webhook_base: std::env::var("MK_PUBLIC_WEBHOOK_BASE").unwrap_or_default(),
            egress_authorities: std::env::var("MK_EGRESS_AUTHORITIES")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_owned())
                .collect(),
            allow_loopback_http: std::env::var("MK_ALLOW_LOOPBACK_HTTP").is_ok_and(|v| v == "1"),
            batch: std::env::var("MK_WORKER_BATCH")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16),
            lease_secs: std::env::var("MK_LEASE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
            metrics_bind: std::env::var("MK_METRICS_BIND")
                .unwrap_or_else(|_| "127.0.0.1:9100".into()),
            metrics_sample_secs: std::env::var("MK_METRICS_SAMPLE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
        })
    }
}

pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .try_init();
}
