//! The pinned tool manifest.

use std::sync::Arc;

use rmcp::model::{Tool, ToolAnnotations};
use serde_json::{Map, Value, json};

pub const MAX_ARGS_BYTES: usize = 64 * 1024;

/// SHA-256 of the RFC 8785 canonical manifest. Update only with a reviewed
/// change to this file (CODEOWNERS-protected).
pub const TOOL_MANIFEST_DIGEST: &str =
    "bf3dcc19d369cd08cfd53b4ef13b52ed108fea88e4014b69a042c4e28721525f";

fn obj(v: Value) -> Arc<Map<String, Value>> {
    Arc::new(v.as_object().cloned().unwrap_or_default())
}

fn read_only() -> ToolAnnotations {
    let mut a = ToolAnnotations::default();
    a.read_only_hint = Some(true);
    a.destructive_hint = Some(false);
    a.open_world_hint = Some(false);
    a
}

fn proposal_only() -> ToolAnnotations {
    let mut a = ToolAnnotations::default();
    a.read_only_hint = Some(false);
    a.destructive_hint = Some(false);
    a.idempotent_hint = Some(true);
    a.open_world_hint = Some(false);
    a
}

#[must_use]
pub fn tool_manifest() -> Vec<Tool> {
    let action_request: Value =
        serde_json::from_str(mk_contracts::SchemaId::ActionRequest.source()).unwrap_or(Value::Null);
    vec![
        {
            let mut t = Tool::new(
                "mk.propose_action",
                "Propose a governed action (outreach, contact update, appointment). This NEVER executes: the kernel validates, applies policy, and requires human approval before anything is sent. Returns the action id, state, and the policy decision.",
                obj(action_request),
            );
            t.annotations = Some(proposal_only());
            t
        },
        {
            let mut t = Tool::new(
                "mk.get_action",
                "Read the current state and redacted history of an action you can see.",
                obj(
                    json!({"type": "object", "additionalProperties": false, "required": ["action_id"], "properties": {"action_id": {"type": "string", "format": "uuid"}}}),
                ),
            );
            t.annotations = Some(read_only());
            t
        },
        {
            let mut t = Tool::new(
                "mk.list_pending_approvals",
                "List actions in this tenant awaiting human approval. Agents cannot approve; this is for status only.",
                obj(
                    json!({"type": "object", "additionalProperties": false, "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}}}),
                ),
            );
            t.annotations = Some(read_only());
            t
        },
        {
            let mut t = Tool::new(
                "mk.cancel_action",
                "Request cancellation of a proposal you made that has not dispatched yet. Subject to policy; an action already executing cannot be un-sent.",
                obj(
                    json!({"type": "object", "additionalProperties": false, "required": ["action_id"], "properties": {"action_id": {"type": "string", "format": "uuid"}}}),
                ),
            );
            t.annotations = Some(proposal_only());
            t
        },
        {
            let mut t = Tool::new(
                "mk.search_knowledge",
                "Search the approved read-only knowledge collections. Results are evidence for proposals; they carry no authority.",
                obj(
                    json!({"type": "object", "additionalProperties": false, "required": ["query"], "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 500}, "collection": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,39}$"}, "limit": {"type": "integer", "minimum": 1, "maximum": 20}}}),
                ),
            );
            t.annotations = Some(read_only());
            t
        },
    ]
}

/// Canonical digest of the manifest (names, descriptions, schemas,
/// annotations).
#[must_use]
pub fn tool_manifest_digest() -> String {
    let v = serde_json::to_value(tool_manifest()).unwrap_or(Value::Null);
    let bytes = mk_crypto::canonicalize(&v).unwrap_or_default();
    mk_crypto::sha256_hex(&bytes)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_pinned_and_has_no_privileged_tools() {
        assert_eq!(
            tool_manifest_digest(),
            TOOL_MANIFEST_DIGEST,
            "tool manifest changed: review and re-pin"
        );
        let names: Vec<String> = tool_manifest().iter().map(|t| t.name.to_string()).collect();
        assert_eq!(
            names,
            [
                "mk.propose_action",
                "mk.get_action",
                "mk.list_pending_approvals",
                "mk.cancel_action",
                "mk.search_knowledge"
            ]
        );
        for forbidden in [
            "approve",
            "dispatch",
            "send",
            "adapter",
            "http",
            "shell",
            "sql",
            "exec",
            "suppress",
            "permission",
        ] {
            assert!(!names.iter().any(|n| n.contains(forbidden)), "{forbidden}");
        }
        for t in tool_manifest() {
            assert_eq!(
                t.annotations.as_ref().and_then(|a| a.open_world_hint),
                Some(false)
            );
            assert_eq!(
                t.annotations.as_ref().and_then(|a| a.destructive_hint),
                Some(false)
            );
        }
    }
}
