//! `mobile-adapter-v1`: delivers a signed `consultant-studio.mobile-work-order.v1`
//! to a registered device agent. Completion arrives by authenticated callback
//! (`POST /adapter/v1/work-orders/{action_id}/callbacks`), handled by the API.

use std::time::Duration;

use async_trait::async_trait;
use mk_contracts::mobile::{
    CALLBACK_AUTH, MOBILE_ADAPTER, MOBILE_WORK_ORDER_SCHEMA, MobileWorkOrder, WorkOrderStep,
};
use mk_crypto::{AdapterSecret, Digest, sign_hmac};
use mk_domain::{ActionKind, TenantId};
use secrecy::ExposeSecret;
use serde_json::Value;

use crate::egress::EgressAllowlist;
use crate::{
    ActionAdapter, AdapterDescriptor, AdapterError, AdapterReceipt, AuthorizedAction,
    ReconcileResult, sealed,
};

/// What the adapter needs to reach one device agent. Resolved per action by
/// the worker from `kernel.adapter_registrations` + unsealed credentials.
#[derive(Clone)]
pub struct AgentTarget {
    pub adapter_id: uuid::Uuid,
    pub agent_id: String,
    /// Full URL of the agent's work-order intake endpoint (allowlisted).
    pub intake_url: String,
    pub secret: AdapterSecret,
    pub callback_authority: String,
    pub capabilities: Vec<String>,
}

impl std::fmt::Debug for AgentTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AgentTarget(agent_id={}, intake_url={})",
            self.agent_id, self.intake_url
        )
    }
}

/// Resolves the device agent for a tenant+agent id. Implemented over the
/// store by the worker; by a map in tests.
#[async_trait]
pub trait AgentResolver: Send + Sync + std::fmt::Debug {
    async fn resolve(&self, tenant: TenantId, agent_id: &str) -> Option<AgentTarget>;
}

#[derive(Debug)]
pub struct MobileAdapter {
    client: reqwest::Client,
    egress: EgressAllowlist,
    resolver: Box<dyn AgentResolver>,
    upstream_contract: String,
}

impl sealed::Sealed for MobileAdapter {}

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

impl MobileAdapter {
    pub fn new(
        egress: EgressAllowlist,
        resolver: Box<dyn AgentResolver>,
        upstream_contract: &str,
    ) -> Result<Self, AdapterError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent("mk-action-kernel/mobile-adapter-v1")
            .build()
            .map_err(|_| AdapterError::permanent("client_build"))?;
        Ok(Self {
            client,
            egress,
            resolver,
            upstream_contract: upstream_contract.to_owned(),
        })
    }

    /// Build the work order for an authorized action. The callback URL is
    /// kernel-owned: it is derived from the registration's allowlisted
    /// authority, never from the request.
    pub fn build_work_order(
        &self,
        action: &AuthorizedAction,
        target: &AgentTarget,
    ) -> Result<MobileWorkOrder, AdapterError> {
        let args = &action.request.arguments;
        let text = args
            .get("rendered_text")
            .and_then(Value::as_str)
            .ok_or(AdapterError::permanent("missing_rendered_text"))?;
        let to = args
            .get("to")
            .and_then(Value::as_str)
            .ok_or(AdapterError::permanent("missing_destination"))?;
        let (workflow, steps, actions_required) = match action.request.action_kind {
            ActionKind::SendSms => {
                validate_e164(to)?;
                (
                    action
                        .request
                        .workflow
                        .mobile_contract_name()
                        .unwrap_or("follow_up"),
                    vec![
                        WorkOrderStep::Open {
                            target: "sms".into(),
                        },
                        WorkOrderStep::Input {
                            field: "recipient".into(),
                            value: to.to_owned(),
                        },
                        WorkOrderStep::Input {
                            field: "message".into(),
                            value: text.to_owned(),
                        },
                        WorkOrderStep::Click {
                            description: "Tap send".into(),
                        },
                        WorkOrderStep::Scrape {
                            description: "Delivery status".into(),
                            return_as: "sent".into(),
                        },
                    ],
                    vec!["open".to_owned(), "input".to_owned()],
                )
            }
            ActionKind::SendDm => {
                let platform = args
                    .get("platform")
                    .and_then(Value::as_str)
                    .unwrap_or("instagram");
                if !["instagram", "facebook", "tiktok", "x"].contains(&platform) {
                    return Err(AdapterError::permanent("unsupported_platform"));
                }
                (
                    action
                        .request
                        .workflow
                        .mobile_contract_name()
                        .unwrap_or("follow_up"),
                    vec![
                        WorkOrderStep::Open {
                            target: platform.to_owned(),
                        },
                        WorkOrderStep::Input {
                            field: "search".into(),
                            value: to.to_owned(),
                        },
                        WorkOrderStep::Click {
                            description: "Open conversation".into(),
                        },
                        WorkOrderStep::Input {
                            field: "message".into(),
                            value: text.to_owned(),
                        },
                        WorkOrderStep::Click {
                            description: "Tap send".into(),
                        },
                    ],
                    vec!["open".to_owned(), "input".to_owned()],
                )
            }
            ActionKind::PostSocial => (
                "social_post",
                vec![
                    WorkOrderStep::Open {
                        target: args
                            .get("platform")
                            .and_then(Value::as_str)
                            .unwrap_or("instagram")
                            .to_owned(),
                    },
                    WorkOrderStep::Click {
                        description: "New post".into(),
                    },
                    WorkOrderStep::Input {
                        field: "caption".into(),
                        value: text.to_owned(),
                    },
                    WorkOrderStep::Click {
                        description: "Share".into(),
                    },
                ],
                vec!["open".to_owned(), "input".to_owned()],
            ),
            _ => return Err(AdapterError::permanent("unsupported_action_kind")),
        };
        for needed in &actions_required {
            if !target.capabilities.iter().any(|c| c == needed) {
                return Err(AdapterError::permanent("adapter_capability_missing"));
            }
        }
        let task_id = action.action_id.0.simple().to_string();
        let callback_url = format!(
            "https://{}/adapter/v1/work-orders/{task_id}/callbacks",
            target.callback_authority
        );
        let order = MobileWorkOrder {
            schema: MOBILE_WORK_ORDER_SCHEMA.into(),
            adapter: MOBILE_ADAPTER.into(),
            upstream_contract: self.upstream_contract.clone(),
            verified_on_device: false,
            workflow: workflow.to_owned(),
            steps,
            clawscript_source: format!("# generated by mk-action-kernel for {task_id}\n"),
            adapter_actions_required: actions_required,
            result_fields: vec!["sent".into()],
            task_id,
            agent_id: target.agent_id.clone(),
            callback_url,
            callback_auth: CALLBACK_AUTH.into(),
        };
        order
            .validate()
            .map_err(|_| AdapterError::permanent("work_order_contract_violation"))?;
        Ok(order)
    }
}

fn validate_e164(s: &str) -> Result<(), AdapterError> {
    let ok = s.len() >= 9
        && s.len() <= 16
        && s.starts_with('+')
        && s[1..].bytes().all(|b| b.is_ascii_digit())
        && !s.starts_with("+0");
    if ok {
        Ok(())
    } else {
        Err(AdapterError::permanent("destination_not_e164"))
    }
}

#[async_trait]
impl ActionAdapter for MobileAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            adapter_kind: "mobile-adapter-v1",
            tool_ids: &[
                "mobile.sms.send.v1",
                "mobile.dm.send.v1",
                "mobile.social.post.v1",
            ],
            kinds: &[
                ActionKind::SendSms,
                ActionKind::SendDm,
                ActionKind::PostSocial,
            ],
            callback_based: true,
            pii_fields: &["to", "rendered_text"],
        }
    }

    async fn validate(&self, action: &AuthorizedAction) -> Result<(), AdapterError> {
        let agent_id = action
            .request
            .arguments
            .get("agent_id")
            .and_then(Value::as_str)
            .ok_or(AdapterError::permanent("missing_agent_id"))?;
        let target = self
            .resolver
            .resolve(action.tenant_id, agent_id)
            .await
            .ok_or(AdapterError::permanent("agent_not_registered"))?;
        self.egress
            .check(&target.intake_url)
            .map_err(|_| AdapterError::permanent("intake_url_not_allowlisted"))?;
        self.build_work_order(action, &target).map(|_| ())
    }

    async fn execute(&self, action: &AuthorizedAction) -> Result<AdapterReceipt, AdapterError> {
        let agent_id = action
            .request
            .arguments
            .get("agent_id")
            .and_then(Value::as_str)
            .ok_or(AdapterError::permanent("missing_agent_id"))?;
        let target = self
            .resolver
            .resolve(action.tenant_id, agent_id)
            .await
            .ok_or(AdapterError::permanent("agent_not_registered"))?;
        let url = self
            .egress
            .check(&target.intake_url)
            .map_err(|_| AdapterError::permanent("intake_url_not_allowlisted"))?;
        let order = self.build_work_order(action, &target)?;
        let body = order
            .wire_bytes()
            .map_err(|_| AdapterError::permanent("work_order_serialize"))?;
        let ts = chrono::Utc::now().timestamp().to_string();
        let nonce = uuid::Uuid::now_v7().simple().to_string();
        let headers = sign_hmac(&target.secret, "POST", url.path(), &ts, &nonce, &body)
            .map_err(|_| AdapterError::permanent("sign"))?;
        let resp = self
            .client
            .post(url.clone())
            .header("content-type", "application/json")
            .header("x-mobile-agent", &target.agent_id)
            .header("x-mobile-tenant", action.tenant_id.to_string())
            .header("x-mobile-timestamp", &headers.timestamp)
            .header("x-mobile-nonce", &headers.nonce)
            .header("x-mobile-signature", &headers.signature_hex)
            .header("idempotency-key", &order.task_id)
            .body(body.clone())
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) if e.is_connect() || e.is_timeout() => {
                return Err(AdapterError::transient("agent_unreachable"));
            }
            // Request sent, response lost: the device may have accepted it.
            Err(_) => return Err(AdapterError::ambiguous("response_lost")),
        };
        let status = resp.status();
        let bytes = match resp.bytes().await {
            Ok(b) if b.len() <= MAX_RESPONSE_BYTES => b,
            Ok(_) => return Err(AdapterError::permanent("response_too_large")),
            Err(_) => return Err(AdapterError::ambiguous("response_body_lost")),
        };
        match status.as_u16() {
            200..=299 => Ok(AdapterReceipt {
                adapter_id: Some(target.adapter_id),
                external_ref: Some(order.task_id.clone()),
                result_digest: Some(Digest::of(&bytes)),
                pending_callback: true,
            }),
            409 => Err(AdapterError::permanent("task_id_content_conflict")),
            429 => Err(AdapterError {
                class: mk_queue::RetryClass::RateLimited {
                    retry_after_secs: 60,
                },
                code: "agent_busy",
            }),
            400 | 401 | 403 | 404 | 422 => Err(AdapterError::permanent("agent_rejected")),
            500..=599 => Err(AdapterError::transient("agent_error")),
            _ => Err(AdapterError::ambiguous("unexpected_status")),
        }
    }

    async fn reconcile(&self, _receipt: &AdapterReceipt) -> Result<ReconcileResult, AdapterError> {
        // v1 agents have no status query endpoint; reconciliation is driven
        // by callbacks. Report Unknown so the action stays in
        // ReconciliationRequired for an operator.
        Ok(ReconcileResult::Unknown)
    }
}

/// Expose the secret bytes length for diagnostics without the value.
#[must_use]
pub fn secret_len(s: &secrecy::SecretString) -> usize {
    s.expose_secret().len()
}
