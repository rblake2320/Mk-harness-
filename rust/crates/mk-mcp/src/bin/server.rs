//! `mk-mcp-server`: stdio MCP server over the kernel API.
//! Env: MK_KERNEL_URL, MK_KNOWLEDGE_URL (optional), MK_ASSERTION_FILE (a file
//! the host refreshes with a current assertion; read on every call).

use std::sync::Arc;

use async_trait::async_trait;
use mk_mcp::McpServer;
use mk_mcp::client::{AssertionSource, HttpKernelClient};
use rmcp::ServiceExt;
use rmcp::transport::stdio;

#[derive(Debug)]
struct FileAssertion(String);

#[async_trait]
impl AssertionSource for FileAssertion {
    async fn assertion(&self) -> Option<String> {
        tokio::fs::read_to_string(&self.0)
            .await
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
    let base = std::env::var("MK_KERNEL_URL")?;
    let kb = std::env::var("MK_KNOWLEDGE_URL").ok();
    let file = std::env::var("MK_ASSERTION_FILE")?;
    let client = HttpKernelClient::new(&base, kb.as_deref(), Box::new(FileAssertion(file)))?;
    tracing::info!(manifest_digest = %mk_mcp::tool_manifest_digest(), "mk-mcp-server starting");
    let service = McpServer::new(Arc::new(client)).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
