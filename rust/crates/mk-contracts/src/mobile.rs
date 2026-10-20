//! `consultant-studio.mobile-*.v1` contracts, preserved byte-for-byte from the
//! published Python agent_ops contract.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::schema::{ContractError, SchemaId, validate};

pub const MOBILE_WORK_ORDER_SCHEMA: &str = "consultant-studio.mobile-work-order.v1";
pub const MOBILE_ADAPTER: &str = "mobile-adapter-v1";
pub const CALLBACK_AUTH: &str = "hmac-sha256-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkOrderStep {
    Open {
        target: String,
    },
    OpenUrl {
        url: String,
    },
    Click {
        description: String,
    },
    Input {
        field: String,
        value: String,
    },
    Scrape {
        description: String,
        return_as: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MobileWorkOrder {
    pub schema: String,
    pub adapter: String,
    pub upstream_contract: String,
    /// Always `false` until real-device evidence exists. The schema pins it.
    pub verified_on_device: bool,
    pub workflow: String,
    pub steps: Vec<WorkOrderStep>,
    pub clawscript_source: String,
    pub adapter_actions_required: Vec<String>,
    pub result_fields: Vec<String>,
    /// 32 lowercase hex characters (legacy format, preserved).
    pub task_id: String,
    pub agent_id: String,
    /// Kernel-owned; never user-supplied. Must be on an allowlisted authority.
    pub callback_url: String,
    pub callback_auth: String,
}

impl MobileWorkOrder {
    pub fn validate(&self) -> Result<(), ContractError> {
        let v = serde_json::to_value(self).map_err(|_| ContractError::NotJson)?;
        validate(SchemaId::MobileWorkOrder, &v)
    }

    /// Compact UTF-8 bytes as transmitted and signed. The signature covers
    /// exactly these bytes.
    pub fn wire_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let v = serde_json::to_value(self).map_err(|_| ContractError::NotJson)?;
        mk_crypto::canonicalize(&v).map_err(|_| ContractError::Oversized)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MobilePing {
    pub schema: String,
    pub status: String,
}

/// Callback body. All three published callback schemas share this shape and
/// differ only in `schema`/`status` constants, so one struct covers them and
/// [`MobileCallback::kind`] identifies which contract validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MobileCallback {
    pub schema: String,
    pub status: String,
    pub result: Map<String, Value>,
    pub error_code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackKind {
    Executing,
    Complete,
    Failed,
}

impl MobileCallback {
    /// Validate against whichever callback schema matches `schema`, failing
    /// closed on anything else.
    pub fn parse(value: &Value) -> Result<(Self, CallbackKind), ContractError> {
        let schema = value
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (id, kind) = match schema {
            "consultant-studio.mobile-execution-state.v1" => {
                (SchemaId::MobileExecutionState, CallbackKind::Executing)
            }
            "consultant-studio.mobile-execution-completion.v1" => {
                (SchemaId::MobileExecutionCompletion, CallbackKind::Complete)
            }
            "consultant-studio.mobile-execution-failure.v1" => {
                (SchemaId::MobileExecutionFailure, CallbackKind::Failed)
            }
            other => return Err(ContractError::UnsupportedVersion(other.to_owned())),
        };
        validate(id, value)?;
        let cb: Self =
            serde_json::from_value(value.clone()).map_err(|e| ContractError::SchemaViolation {
                schema: id.name(),
                detail: e.to_string(),
            })?;
        Ok((cb, kind))
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

    fn order() -> MobileWorkOrder {
        MobileWorkOrder {
            schema: MOBILE_WORK_ORDER_SCHEMA.into(),
            adapter: MOBILE_ADAPTER.into(),
            upstream_contract: "phoneclaw@c59995b".into(),
            verified_on_device: false,
            workflow: "follow_up".into(),
            steps: vec![
                WorkOrderStep::Open { target: "sms".into() },
                WorkOrderStep::Input { field: "to".into(), value: "+15555550100".into() },
                WorkOrderStep::Input { field: "body".into(), value: "Hi".into() },
                WorkOrderStep::Click { description: "send".into() },
                WorkOrderStep::Scrape { description: "status".into(), return_as: "sent".into() },
            ],
            clawscript_source: "open sms".into(),
            adapter_actions_required: vec!["open".into(), "input".into()],
            result_fields: vec!["sent".into()],
            task_id: "0191f6f0e2b47a2b9c5c3d1e2f3a4b5c".into(),
            agent_id: "simulator-1".into(),
            callback_url: "https://kernel.internal/adapter/v1/work-orders/0191f6f0e2b47a2b9c5c3d1e2f3a4b5c/callbacks".into(),
            callback_auth: CALLBACK_AUTH.into(),
        }
    }

    #[test]
    fn valid_order_passes_published_schema() {
        assert_eq!(order().validate(), Ok(()));
    }

    #[test]
    fn verified_on_device_true_is_rejected_by_contract() {
        let mut o = order();
        o.verified_on_device = true;
        assert!(o.validate().is_err());
    }

    #[test]
    fn open_url_must_be_https_and_targets_closed() {
        let mut o = order();
        o.steps = vec![WorkOrderStep::OpenUrl {
            url: "http://evil.example".into(),
        }];
        assert!(o.validate().is_err());
        let mut o = order();
        o.steps = vec![WorkOrderStep::Open {
            target: "bank_app".into(),
        }];
        assert!(o.validate().is_err());
    }

    #[test]
    fn step_limits_and_task_id_shape() {
        let mut o = order();
        o.steps = vec![
            WorkOrderStep::Click {
                description: "x".into()
            };
            21
        ];
        assert!(o.validate().is_err());
        let mut o = order();
        o.task_id = "0191f6f0-e2b4-7a2b-9c5c-3d1e2f3a4b5c".into();
        assert!(
            o.validate().is_err(),
            "legacy task_id is 32 bare hex, not a hyphenated uuid"
        );
    }

    #[test]
    fn callbacks_parse_by_schema_and_reject_mismatch() {
        let ok = json!({"schema":"consultant-studio.mobile-execution-completion.v1","status":"complete","result":{"sent":true},"error_code":""});
        assert_eq!(
            MobileCallback::parse(&ok).map(|(_, k)| k),
            Ok(CallbackKind::Complete)
        );
        let bad = json!({"schema":"consultant-studio.mobile-execution-completion.v1","status":"failed","result":{},"error_code":""});
        assert!(MobileCallback::parse(&bad).is_err());
        let bad = json!({"schema":"consultant-studio.mobile-execution-failure.v1","status":"failed","result":{},"error_code":"Device Unavailable"});
        assert!(
            MobileCallback::parse(&bad).is_err(),
            "error_code pattern is lowercase"
        );
        let unknown = json!({"schema":"consultant-studio.mobile-execution-approval.v1","status":"approved","result":{},"error_code":""});
        assert!(matches!(
            MobileCallback::parse(&unknown),
            Err(ContractError::UnsupportedVersion(_))
        ));
    }
}
