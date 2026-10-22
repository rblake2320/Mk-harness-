//! Public inbound route probes: signed HTTP + committed, exact-generation receipt.
//! No customer message or provider API call is produced by a probe.
use chrono::Utc;
use mk_adapters::{egress::EgressAllowlist, twilio::twilio_signature};
use mk_crypto::{AdapterSecret, Digest, Keyring};
use mk_domain::TenantId;
use mk_store::{Store, messaging as ms, probes};
use secrecy::ExposeSecret as _;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct InboundProbe {
    store: Store,
    keyring: Keyring,
    client: reqwest::Client,
    egress: EgressAllowlist,
    base: String,
    slots: Arc<tokio::sync::Semaphore>,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub checked: usize,
    pub confirmed: usize,
    pub failed: usize,
    pub tenant_failures: usize,
}

impl Stats {
    fn merge(&mut self, other: Self) {
        self.checked += other.checked;
        self.confirmed += other.confirmed;
        self.failed += other.failed;
        self.tenant_failures += other.tenant_failures;
    }
}

struct Job {
    sender: Uuid,
    id: Uuid,
    body: String,
    signature: String,
    url: String,
}

impl InboundProbe {
    pub fn new(
        store: Store,
        keyring: Keyring,
        egress: EgressAllowlist,
        base: &str,
    ) -> anyhow::Result<Self> {
        let base = egress.check(base)?;
        if base.path() != "/" {
            anyhow::bail!("public webhook base must be an origin without path");
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            store,
            keyring,
            client,
            egress,
            base: base.as_str().trim_end_matches('/').to_owned(),
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }

    pub async fn run_once(&self, tenants: &[TenantId]) -> anyhow::Result<Stats> {
        let mut stats = Stats::default();
        let mut tasks = tokio::task::JoinSet::new();
        for &tenant in tenants {
            if tasks.len() >= 16
                && let Some(result) = tasks.join_next().await
            {
                match result? {
                    Ok(part) => stats.merge(part),
                    Err(_) => stats.tenant_failures += 1,
                }
            }
            let this = self.clone();
            tasks.spawn(async move { this.run_tenant(tenant).await });
        }
        while let Some(result) = tasks.join_next().await {
            match result? {
                Ok(part) => stats.merge(part),
                Err(_) => stats.tenant_failures += 1,
            }
        }
        Ok(stats)
    }

    async fn run_tenant(&self, tenant: TenantId) -> anyhow::Result<Stats> {
        let mut stats = Stats::default();
        let now = Utc::now();
        let mut tx = self.store.begin(tenant).await?;
        probes::latch_outage(&mut tx, now).await?;
        let due = probes::due(&mut tx, now).await?;
        let mut jobs = Vec::new();
        for sender_id in due {
            let s = ms::sender_secret(&mut tx, &self.keyring, sender_id).await?;
            let id = Uuid::new_v4();
            let form = vec![
                ("AccountSid".to_owned(), s.account_sid),
                ("MkHealthProbe".to_owned(), id.to_string()),
                ("To".to_owned(), s.from_number.unwrap_or_default()),
            ];
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&form)
                .finish();
            let url = format!("{}/webhooks/twilio/inbound/{sender_id}", self.base);
            self.egress.check(&url)?;
            let signature = twilio_signature(
                &AdapterSecret::new(s.auth_token.expose_secret()),
                &url,
                &form,
            );
            probes::issue(&mut tx, sender_id, id, &Digest::of(body.as_bytes()), now).await?;
            jobs.push(Job {
                sender: sender_id,
                id,
                body,
                signature,
                url,
            });
        }
        tx.commit().await?;
        // Bound concurrency; each tenant claims at most 32, network timeout
        // 5s, generation lifetime 10s. No DB connection is held during HTTP.
        let mut tasks = tokio::task::JoinSet::new();
        for job in jobs {
            let this = self.clone();
            tasks.spawn(async move { this.check(tenant, job).await });
        }
        while let Some(result) = tasks.join_next().await {
            stats.checked += 1;
            if result?? {
                stats.confirmed += 1;
            } else {
                stats.failed += 1;
            }
        }
        let mut tx = self.store.begin(tenant).await?;
        let now = Utc::now();
        if probes::all_fresh(&mut tx, now).await? {
            ms::inbound_ok(&mut tx, now).await?;
            probes::recover_if_drained(&mut tx, now).await?;
        }
        tx.commit().await?;
        Ok(stats)
    }

    async fn check(&self, tenant: TenantId, job: Job) -> anyhow::Result<bool> {
        let _slot = self.slots.acquire().await?;
        let mut tx = self.store.begin(tenant).await?;
        let current = probes::start(&mut tx, job.sender, job.id, Utc::now()).await?;
        tx.commit().await?;
        if !current {
            return Ok(false);
        }
        let response = self
            .client
            .post(&job.url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-twilio-signature", &job.signature)
            .body(job.body)
            .send()
            .await;
        let status_ok = response
            .as_ref()
            .is_ok_and(|r| r.status() == reqwest::StatusCode::OK);
        let now = Utc::now();
        let mut tx = self.store.begin(tenant).await?;
        let confirmed = status_ok && probes::confirm(&mut tx, job.sender, job.id, now).await?;
        if !confirmed {
            let code = if status_ok {
                "probe_receipt_missing"
            } else {
                "probe_transport_failed"
            };
            probes::fail(&mut tx, job.sender, job.id, code).await?;
            ms::inbound_failure(&mut tx, code, now).await?;
            probes::latch_outage(&mut tx, now).await?;
        }
        tx.commit().await?;
        Ok(confirmed)
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        let this = Arc::new(self);
        tokio::spawn(async move {
            loop {
                if let Ok(tenants) = mk_store::audit::all_tenants(this.store.pool()).await {
                    if let Ok(stats) = this.run_once(&tenants).await {
                        tracing::info!(?stats, "public inbound checks");
                    } else {
                        tracing::warn!("public inbound checks failed");
                    }
                } else {
                    tracing::warn!("inbound-check tenant listing failed");
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        })
    }
}
