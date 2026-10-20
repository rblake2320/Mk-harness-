//! Store-backed [`AgentResolver`]: looks up the registration and unseals the
//! newest live credential for signing.

use async_trait::async_trait;
use mk_adapters::mobile::{AgentResolver, AgentTarget};
use mk_crypto::MasterKey;
use mk_domain::TenantId;
use mk_store::{Store, adapters};

#[derive(Debug)]
pub struct StoreResolver {
    pub store: Store,
    pub master: MasterKey,
    /// Intake path appended to `https://{callback_authority_of_agent}`; in v1
    /// the device agent's intake authority is configured per adapter kind.
    pub intake_url_template: String,
}

#[async_trait]
impl AgentResolver for StoreResolver {
    async fn resolve(&self, tenant: TenantId, agent_id: &str) -> Option<AgentTarget> {
        let now = chrono::Utc::now();
        let mut tx = self.store.begin(tenant).await.ok()?;
        let reg = adapters::get_by_agent(&mut tx, agent_id).await.ok()?;
        if !reg.is_active(now) {
            return None;
        }
        let secrets = adapters::live_secrets(&mut tx, &self.master, reg.adapter_id, now)
            .await
            .ok()?;
        let secret = secrets.into_iter().next()?;
        let _ = adapters::touch_last_used(&mut tx, reg.adapter_id, now).await;
        tx.commit().await.ok()?;
        Some(AgentTarget {
            adapter_id: reg.adapter_id.0,
            agent_id: reg.agent_id.clone(),
            intake_url: self
                .intake_url_template
                .replace("{agent_id}", &reg.agent_id),
            secret,
            callback_authority: reg.callback_authority,
            capabilities: reg.capabilities,
        })
    }
}
