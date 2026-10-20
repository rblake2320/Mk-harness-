//! `ServerHandler` implementation. Every call: size-bounded → schema-validated
//! → forwarded to the kernel → redacted. Tool output is data, never an
//! instruction, and the server adds no "system" text.

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer};
use serde_json::{Map, Value, json};

use crate::client::{KernelClient, KernelError};
use crate::tools::{MAX_ARGS_BYTES, tool_manifest};

#[derive(Debug, Clone)]
pub struct McpServer {
    client: Arc<dyn KernelClient>,
    tools: Arc<Vec<Tool>>,
}

impl McpServer {
    #[must_use]
    pub fn new(client: Arc<dyn KernelClient>) -> Self {
        Self {
            client,
            tools: Arc::new(tool_manifest()),
        }
    }

    fn validate_args(tool: &Tool, args: &Map<String, Value>) -> Result<(), String> {
        let v = Value::Object(args.clone());
        let bytes = serde_json::to_vec(&v).map_err(|_| "unserializable".to_owned())?;
        if bytes.len() > MAX_ARGS_BYTES {
            return Err("arguments too large".into());
        }
        let schema = Value::Object((*tool.input_schema).clone());
        let validator =
            jsonschema::validator_for(&schema).map_err(|_| "schema unavailable".to_owned())?;
        if let Some(e) = validator.iter_errors(&v).next() {
            let mut msg = e.to_string();
            msg.truncate(200);
            return Err(format!("{}: {msg}", e.instance_path));
        }
        Ok(())
    }

    /// Redact fields that must never flow back into model context.
    fn redact(v: Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.into_iter()
                    .filter(|(k, _)| {
                        !matches!(
                            k.as_str(),
                            "rendered_text"
                                | "to"
                                | "destination"
                                | "enrollment_secret"
                                | "canonical_request"
                        )
                    })
                    .map(|(k, v)| (k, Self::redact(v)))
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.into_iter().map(Self::redact).collect()),
            other => other,
        }
    }

    async fn dispatch(&self, name: &str, args: Map<String, Value>) -> Result<Value, KernelError> {
        match name {
            "mk.propose_action" => self.client.propose(Value::Object(args)).await,
            "mk.get_action" => {
                self.client
                    .get_action(
                        args.get("action_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
                    .await
            }
            "mk.list_pending_approvals" => {
                self.client
                    .list_pending(
                        args.get("limit")
                            .and_then(Value::as_u64)
                            .map_or(50, |n| usize::try_from(n).unwrap_or(50)),
                    )
                    .await
            }
            "mk.cancel_action" => {
                self.client
                    .cancel(
                        args.get("action_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
                    .await
            }
            "mk.search_knowledge" => {
                self.client
                    .search_knowledge(
                        args.get("query")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                        args.get("collection").and_then(Value::as_str),
                        args.get("limit")
                            .and_then(Value::as_u64)
                            .map_or(5, |n| usize::try_from(n).unwrap_or(5)),
                    )
                    .await
            }
            _ => Err(KernelError::Rejected {
                status: 404,
                code: "UNKNOWN_TOOL".into(),
                detail: None,
            }),
        }
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "MK action kernel. Tools only create proposals or read state; nothing here sends a message or approves one. A human approves in the MK application.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items((*self.tools).clone()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools.iter().find(|t| t.name == name).cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(tool) = self.get_tool(&request.name) else {
            return Err(McpError::invalid_params(
                format!("unknown tool {}", request.name),
                None,
            ));
        };
        let args = request.arguments.unwrap_or_default();
        if let Err(msg) = Self::validate_args(&tool, &args) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                json!({"error": "invalid_arguments", "detail": msg}).to_string(),
            )])
            .into());
        }
        tracing::info!(tool = %request.name, args_digest = %mk_crypto::sha256_hex(&serde_json::to_vec(&args).unwrap_or_default()), "mcp tool call");
        match self.dispatch(&request.name, args).await {
            Ok(v) => Ok(CallToolResult::success(vec![ContentBlock::text(
                Self::redact(v).to_string(),
            )])
            .into()),
            Err(KernelError::Rejected {
                status,
                code,
                detail,
            }) => Ok(CallToolResult::error(vec![ContentBlock::text(
                json!({"error": code, "status": status, "detail": detail}).to_string(),
            )])
            .into()),
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(
                json!({"error": "kernel_unavailable", "detail": e.to_string()}).to_string(),
            )])
            .into()),
        }
    }
}
