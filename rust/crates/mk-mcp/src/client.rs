//! Kernel client used by the MCP server. The HTTP implementation talks to
//! `mk-action-api` with a per-call actor assertion supplied by the host
//! (FastAPI mints assertions for the agent session; the MCP sidecar never
//! holds a signing key).

use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("kernel unavailable")]
    Unavailable,
    #[error("kernel rejected: {code}")]
    Rejected {
        status: u16,
        code: String,
        detail: Option<String>,
    },
    #[error("assertion unavailable")]
    NoAssertion,
}

#[async_trait]
pub trait KernelClient: Send + Sync + std::fmt::Debug {
    async fn propose(&self, body: Value) -> Result<Value, KernelError>;
    async fn get_action(&self, action_id: &str) -> Result<Value, KernelError>;
    async fn list_pending(&self, limit: usize) -> Result<Value, KernelError>;
    async fn cancel(&self, action_id: &str) -> Result<Value, KernelError>;
    async fn search_knowledge(
        &self,
        query: &str,
        collection: Option<&str>,
        limit: usize,
    ) -> Result<Value, KernelError>;
}

/// Supplies a fresh, short-lived actor assertion for each kernel call.
#[async_trait]
pub trait AssertionSource: Send + Sync + std::fmt::Debug {
    async fn assertion(&self) -> Option<String>;
}

#[derive(Debug)]
pub struct HttpKernelClient {
    client: reqwest::Client,
    base: String,
    knowledge_base: Option<String>,
    assertions: Box<dyn AssertionSource>,
}

const MAX_RESPONSE: usize = 256 * 1024;

impl HttpKernelClient {
    pub fn new(
        base: &str,
        knowledge_base: Option<&str>,
        assertions: Box<dyn AssertionSource>,
    ) -> Result<Self, KernelError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| KernelError::Unavailable)?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
            knowledge_base: knowledge_base.map(|s| s.trim_end_matches('/').to_owned()),
            assertions,
        })
    }

    async fn send(
        &self,
        method: reqwest::Method,
        url: String,
        body: Option<Value>,
    ) -> Result<Value, KernelError> {
        let token = self
            .assertions
            .assertion()
            .await
            .ok_or(KernelError::NoAssertion)?;
        let mut req = self.client.request(method, url).bearer_auth(token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|_| KernelError::Unavailable)?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|_| KernelError::Unavailable)?;
        if bytes.len() > MAX_RESPONSE {
            return Err(KernelError::Unavailable);
        }
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if (200..300).contains(&status) || status == 403 && v.get("decision").is_some() {
            Ok(v)
        } else {
            Err(KernelError::Rejected {
                status,
                code: v
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_owned(),
                detail: v.get("detail").and_then(Value::as_str).map(str::to_owned),
            })
        }
    }
}

#[async_trait]
impl KernelClient for HttpKernelClient {
    async fn propose(&self, body: Value) -> Result<Value, KernelError> {
        self.send(
            reqwest::Method::POST,
            format!("{}/internal/v1/actions", self.base),
            Some(body),
        )
        .await
    }
    async fn get_action(&self, action_id: &str) -> Result<Value, KernelError> {
        let id = uuid::Uuid::parse_str(action_id).map_err(|_| KernelError::Rejected {
            status: 422,
            code: "INVALID_ID".into(),
            detail: None,
        })?;
        self.send(
            reqwest::Method::GET,
            format!("{}/internal/v1/actions/{id}", self.base),
            None,
        )
        .await
    }
    async fn list_pending(&self, _limit: usize) -> Result<Value, KernelError> {
        self.send(
            reqwest::Method::GET,
            format!("{}/internal/v1/approvals/pending", self.base),
            None,
        )
        .await
    }
    async fn cancel(&self, action_id: &str) -> Result<Value, KernelError> {
        let id = uuid::Uuid::parse_str(action_id).map_err(|_| KernelError::Rejected {
            status: 422,
            code: "INVALID_ID".into(),
            detail: None,
        })?;
        self.send(
            reqwest::Method::POST,
            format!("{}/internal/v1/actions/{id}/cancel", self.base),
            None,
        )
        .await
    }
    async fn search_knowledge(
        &self,
        query: &str,
        collection: Option<&str>,
        limit: usize,
    ) -> Result<Value, KernelError> {
        let Some(kb) = &self.knowledge_base else {
            return Err(KernelError::Rejected {
                status: 503,
                code: "KNOWLEDGE_UNAVAILABLE".into(),
                detail: None,
            });
        };
        self.send(
            reqwest::Method::POST,
            format!("{kb}/search"),
            Some(serde_json::json!({"query": query, "collection": collection, "limit": limit})),
        )
        .await
    }
}
