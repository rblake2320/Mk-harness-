//! Store-backed [`AgentResolver`]: looks up the registration and unseals the
//! newest live credential for signing.

use async_trait::async_trait;
use mk_adapters::mobile::{AgentResolver, AgentTarget};
use mk_adapters::twilio::{SenderResolver, TwilioSender};
use mk_crypto::AdapterSecret;
use mk_crypto::Keyring;
use mk_domain::TenantId;
use mk_store::{Store, adapters};
use secrecy::ExposeSecret as _;

#[derive(Debug)]
pub struct StoreResolver {
    pub store: Store,
    pub keyring: Keyring,
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
        let secrets = adapters::live_secrets(&mut tx, &self.keyring, reg.adapter_id, now)
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

/// Store-backed [`SenderResolver`] for the Twilio adapter: unseals the
/// tenant's sender credentials for one submission. The status-callback URL is
/// kernel-owned: `{public_base}/webhooks/twilio/status/{sender_identity_id}`.
#[derive(Debug)]
pub struct StoreSenderResolver {
    pub store: Store,
    pub keyring: Keyring,
    pub public_webhook_base: String,
}

#[async_trait]
impl SenderResolver for StoreSenderResolver {
    async fn resolve(
        &self,
        tenant: TenantId,
        sender_identity_id: uuid::Uuid,
    ) -> Option<TwilioSender> {
        self.resolve_scoped(tenant, sender_identity_id, false).await
    }

    async fn resolve_for_erasure(
        &self,
        tenant: TenantId,
        sender_identity_id: uuid::Uuid,
    ) -> Option<TwilioSender> {
        self.resolve_scoped(tenant, sender_identity_id, true).await
    }
}

impl StoreSenderResolver {
    async fn resolve_scoped(
        &self,
        tenant: TenantId,
        sender_identity_id: uuid::Uuid,
        erasure: bool,
    ) -> Option<TwilioSender> {
        let mut tx = self.store.begin(tenant).await.ok()?;
        let s = if erasure {
            mk_store::messaging::sender_secret_for_erasure(
                &mut tx,
                &self.keyring,
                sender_identity_id,
            )
            .await
        } else {
            mk_store::messaging::sender_secret(&mut tx, &self.keyring, sender_identity_id).await
        }
        .ok()?;
        tx.commit().await.ok()?;
        Some(TwilioSender {
            sender_identity_id,
            account_sid: s.account_sid,
            auth_token: AdapterSecret::new(s.auth_token.expose_secret()),
            from_number: s.from_number,
            messaging_service_sid: s.messaging_service_sid,
            status_callback_url: format!(
                "{}/webhooks/twilio/status/{sender_identity_id}",
                self.public_webhook_base.trim_end_matches('/')
            ),
        })
    }
}
