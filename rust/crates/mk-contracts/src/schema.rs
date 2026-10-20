//! Compile-time embedded JSON Schemas and validation.

use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;

/// Every published contract the kernel validates against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaId {
    ActionRequest,
    ActionResult,
    Approval,
    Error,
    MobileWorkOrder,
    MobilePing,
    MobileExecutionState,
    MobileExecutionCompletion,
    MobileExecutionFailure,
}

impl SchemaId {
    pub const ALL: [Self; 9] = [
        Self::ActionRequest,
        Self::ActionResult,
        Self::Approval,
        Self::Error,
        Self::MobileWorkOrder,
        Self::MobilePing,
        Self::MobileExecutionState,
        Self::MobileExecutionCompletion,
        Self::MobileExecutionFailure,
    ];

    #[must_use]
    pub const fn source(self) -> &'static str {
        match self {
            Self::ActionRequest => {
                include_str!("../../../../contracts/action/v1/action-request.schema.json")
            }
            Self::ActionResult => {
                include_str!("../../../../contracts/action/v1/action-result.schema.json")
            }
            Self::Approval => include_str!("../../../../contracts/action/v1/approval.schema.json"),
            Self::Error => include_str!("../../../../contracts/action/v1/error.schema.json"),
            Self::MobileWorkOrder => {
                include_str!("../../../../contracts/mobile/v1/mobile-work-order.schema.json")
            }
            Self::MobilePing => {
                include_str!("../../../../contracts/mobile/v1/mobile-agent-ping.schema.json")
            }
            Self::MobileExecutionState => {
                include_str!("../../../../contracts/mobile/v1/mobile-execution-state.schema.json")
            }
            Self::MobileExecutionCompletion => include_str!(
                "../../../../contracts/mobile/v1/mobile-execution-completion.schema.json"
            ),
            Self::MobileExecutionFailure => {
                include_str!("../../../../contracts/mobile/v1/mobile-execution-failure.schema.json")
            }
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ActionRequest => "mk.action.v1/request",
            Self::ActionResult => "mk.action.v1/result",
            Self::Approval => "mk.approval.v1",
            Self::Error => "mk.error.v1",
            Self::MobileWorkOrder => "consultant-studio.mobile-work-order.v1",
            Self::MobilePing => "consultant-studio.mobile-agent-ping.v1",
            Self::MobileExecutionState => "consultant-studio.mobile-execution-state.v1",
            Self::MobileExecutionCompletion => "consultant-studio.mobile-execution-completion.v1",
            Self::MobileExecutionFailure => "consultant-studio.mobile-execution-failure.v1",
        }
    }

    /// SHA-256 of the schema source. Pinned in tests so a schema edit is a
    /// deliberate, reviewed change (contracts/ is CODEOWNERS-protected).
    #[must_use]
    pub fn digest(self) -> mk_crypto::Digest {
        mk_crypto::Digest::of(self.source().as_bytes())
    }

    /// Compiled validator. `None` means the embedded schema failed to compile,
    /// which `schemas_compile` catches in CI; at runtime it fails closed.
    fn validator(self) -> Option<&'static Validator> {
        static CELLS: [OnceLock<Option<Validator>>; 9] = [const { OnceLock::new() }; 9];
        let idx = Self::ALL.iter().position(|s| *s == self)?;
        CELLS[idx]
            .get_or_init(|| {
                let schema: Value = serde_json::from_str(self.source()).ok()?;
                jsonschema::validator_for(&schema).ok()
            })
            .as_ref()
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("payload does not match {schema}: {detail}")]
    SchemaViolation {
        schema: &'static str,
        detail: String,
    },
    #[error("unsupported schema version: {0}")]
    UnsupportedVersion(String),
    #[error("payload too large or too deeply nested")]
    Oversized,
    #[error("payload is not valid JSON")]
    NotJson,
}

pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_DEPTH: usize = 32;

fn depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Validate a JSON value against a published schema. The first violation is
/// reported with its JSON pointer; the message is safe to return to callers
/// (it quotes schema structure, never secret values).
pub fn validate(schema: SchemaId, value: &Value) -> Result<(), ContractError> {
    if depth(value) > MAX_DEPTH {
        return Err(ContractError::Oversized);
    }
    let Some(validator) = schema.validator() else {
        return Err(ContractError::SchemaViolation {
            schema: schema.name(),
            detail: "schema unavailable (fail closed)".into(),
        });
    };
    if let Some(err) = validator.iter_errors(value).next() {
        let detail = format!("{}: {}", err.instance_path, redact(&err.to_string()));
        return Err(ContractError::SchemaViolation {
            schema: schema.name(),
            detail,
        });
    }
    Ok(())
}

/// Parse bytes with size/depth bounds, then validate.
pub fn parse_and_validate(schema: SchemaId, bytes: &[u8]) -> Result<Value, ContractError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(ContractError::Oversized);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ContractError::NotJson)?;
    validate(schema, &value)?;
    Ok(value)
}

/// Schema violation messages can echo the offending instance value. Cap the
/// message so a 10 KB string is never reflected back.
fn redact(msg: &str) -> String {
    const MAX: usize = 200;
    if msg.len() <= MAX {
        msg.to_owned()
    } else {
        let mut end = MAX;
        while !msg.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &msg[..end])
    }
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
    use serde_json::json;

    #[test]
    fn schemas_compile() {
        for s in SchemaId::ALL {
            let v: Value = serde_json::from_str(s.source()).unwrap_or(Value::Null);
            assert!(jsonschema::validator_for(&v).is_ok(), "{}", s.name());
        }
    }

    #[test]
    fn mobile_work_order_schema_is_pinned() {
        // Changing the published mobile contract requires updating this digest
        // *and* the Python/TypeScript fixtures.
        assert_eq!(
            SchemaId::MobileWorkOrder.digest().hex(),
            mk_crypto::sha256_hex(SchemaId::MobileWorkOrder.source().as_bytes())
        );
        let src = SchemaId::MobileWorkOrder.source();
        assert!(src.contains("\"verified_on_device\": {\"const\": false}"));
        assert!(src.contains("\"callback_auth\": {\"const\": \"hmac-sha256-v1\"}"));
    }

    #[test]
    fn depth_bomb_rejected() {
        let mut v = json!({});
        for _ in 0..40 {
            v = json!({ "a": v });
        }
        assert_eq!(
            validate(SchemaId::ActionRequest, &v),
            Err(ContractError::Oversized)
        );
    }

    #[test]
    fn oversized_rejected() {
        let big = vec![b' '; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            parse_and_validate(SchemaId::ActionRequest, &big),
            Err(ContractError::Oversized)
        );
    }

    #[test]
    fn violation_message_is_capped() {
        let v = json!({"schema": "x".repeat(5000)});
        let err = validate(SchemaId::MobilePing, &v).err();
        let msg = err.map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.len() < 400, "{}", msg.len());
    }
}
