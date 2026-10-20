//! Constrained MCP surface for the MK action kernel.
//!
//! Exactly five tools exist, and none of them performs a side effect:
//! `mk.propose_action` creates a *proposal* that still goes through policy
//! and human approval inside the kernel. There is deliberately no
//! `approve_action` and no adapter tool. The tool manifest is pinned by
//! digest ([`TOOL_MANIFEST_DIGEST`]); a change to any tool name, schema, or
//! description fails the test suite until the pin is reviewed.

pub mod client;
pub mod server;
pub mod tools;

pub use client::{HttpKernelClient, KernelClient, KernelError};
pub use server::McpServer;
pub use tools::{TOOL_MANIFEST_DIGEST, tool_manifest, tool_manifest_digest};
