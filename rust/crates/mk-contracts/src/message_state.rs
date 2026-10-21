//! Contract row C3: the customer-message lifecycle vocabulary exposed in every
//! API response, derived from the kernel action state plus provider evidence.
//! The same definitions must appear in UI, support material and marketing;
//! this module is their single source.

use mk_domain::ActionState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageState {
    Proposed,
    AwaitingApproval,
    Approved,
    Queued,
    DispatchAuthorized,
    SubmissionStarted,
    ProviderAccepted,
    Sent,
    Delivered,
    Failed,
    DeliveryUnknown,
    SubmissionUnknown,
    Cancelled,
    Denied,
    Expired,
}

impl MessageState {
    pub const ALL: [Self; 15] = [
        Self::Proposed,
        Self::AwaitingApproval,
        Self::Approved,
        Self::Queued,
        Self::DispatchAuthorized,
        Self::SubmissionStarted,
        Self::ProviderAccepted,
        Self::Sent,
        Self::Delivered,
        Self::Failed,
        Self::DeliveryUnknown,
        Self::SubmissionUnknown,
        Self::Cancelled,
        Self::Denied,
        Self::Expired,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Approved => "approved",
            Self::Queued => "queued",
            Self::DispatchAuthorized => "dispatch_authorized",
            Self::SubmissionStarted => "submission_started",
            Self::ProviderAccepted => "provider_accepted",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::DeliveryUnknown => "delivery_unknown",
            Self::SubmissionUnknown => "submission_unknown",
            Self::Cancelled => "cancelled",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Human definition, verbatim from the contract. UI/support/marketing
    /// copy must quote these, not paraphrase them.
    #[must_use]
    pub const fn definition(self) -> &'static str {
        match self {
            Self::Proposed => "Proposed by the AI or the consultant; nothing has been authorized.",
            Self::AwaitingApproval => "Waiting for an explicit human approval gesture.",
            Self::Approved => "Approved by a human; not yet queued for execution.",
            Self::Queued => "Queued for execution; policy will be re-evaluated before any send.",
            Self::DispatchAuthorized => {
                "Dispatch authorization obtained; no provider request has been made."
            }
            Self::SubmissionStarted => {
                "The provider request is in flight or its outcome is not yet recorded."
            }
            Self::ProviderAccepted => "Provider acknowledged submission.",
            Self::Sent => "Provider reports outbound network submission.",
            Self::Delivered => "Supported provider/carrier receipt reports delivery.",
            Self::Failed => "Provider reported a terminal failure.",
            Self::DeliveryUnknown => {
                "Evidence is insufficient to say whether the message was delivered."
            }
            Self::SubmissionUnknown => {
                "Evidence is insufficient to say whether the message was submitted; a human must resolve before any replacement."
            }
            Self::Cancelled => "Cancelled before any provider submission.",
            Self::Denied => "Refused by policy; nothing was sent.",
            Self::Expired => "The authorization window elapsed before execution.",
        }
    }

    /// Derive from the kernel action state plus the delivery record's state
    /// (one of the `mk-adapters::twilio::DeliveryState` strings or
    /// `submission_unknown`) when a message delivery exists.
    #[must_use]
    pub fn derive(action: ActionState, delivery: Option<&str>) -> Self {
        let from_delivery = |fallback: Self| match delivery {
            Some("submission_started") => Self::SubmissionStarted,
            Some("provider_accepted") => Self::ProviderAccepted,
            Some("sent") => Self::Sent,
            Some("delivered") => Self::Delivered,
            Some("failed") => Self::Failed,
            Some("delivery_unknown") => Self::DeliveryUnknown,
            Some("submission_unknown") => Self::SubmissionUnknown,
            _ => fallback,
        };
        match action {
            ActionState::Draft | ActionState::PolicyPending => Self::Proposed,
            ActionState::Denied => Self::Denied,
            ActionState::ApprovalRequired => Self::AwaitingApproval,
            ActionState::Approved => Self::Approved,
            ActionState::Queued => Self::Queued,
            ActionState::Dispatching => from_delivery(Self::DispatchAuthorized),
            // Completed with no provider record (e.g. device-agent test path):
            // there is no provider evidence, so delivery is unknown.
            ActionState::Completed => from_delivery(Self::DeliveryUnknown),
            ActionState::FailedRetryable | ActionState::FailedFinal => from_delivery(Self::Failed),
            ActionState::Cancelled | ActionState::Suppressed => Self::Cancelled,
            ActionState::Expired => Self::Expired,
            ActionState::ReconciliationRequired => Self::SubmissionUnknown,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary_matches_contract_exactly() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/action/v1/action-result.schema.json"
        ))
        .unwrap();
        let listed: Vec<&str> = schema["properties"]["message_state"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ours: Vec<&str> = MessageState::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(listed, ours);
        for s in MessageState::ALL {
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::json!(s.as_str())
            );
            assert!(!s.definition().is_empty());
        }
    }

    #[test]
    fn derivation_never_overclaims() {
        use ActionState as A;
        use MessageState as M;
        assert_eq!(
            M::derive(A::Completed, None),
            M::DeliveryUnknown,
            "no provider evidence → unknown, not sent"
        );
        assert_eq!(M::derive(A::Completed, Some("sent")), M::Sent);
        assert_eq!(M::derive(A::Completed, Some("delivered")), M::Delivered);
        assert_eq!(M::derive(A::Dispatching, None), M::DispatchAuthorized);
        assert_eq!(
            M::derive(A::Dispatching, Some("submission_started")),
            M::SubmissionStarted
        );
        assert_eq!(
            M::derive(A::ReconciliationRequired, Some("sent")),
            M::SubmissionUnknown,
            "kernel uncertainty wins"
        );
        assert_eq!(M::derive(A::Suppressed, Some("delivered")), M::Cancelled);
        assert_eq!(M::derive(A::FailedFinal, None), M::Failed);
    }
}
