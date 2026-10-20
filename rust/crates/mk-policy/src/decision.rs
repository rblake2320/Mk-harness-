//! Decision and obligation vocabulary.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct PolicyVersion(pub &'static str);

/// Stable reason codes. These appear in audit payloads, problem details,
/// and metrics labels (bounded cardinality by construction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DenyCode {
    TenantMismatch,
    ActorNotAuthorized,
    ToolNotAllowlisted,
    ToolKindMismatch,
    ActionExpired,
    EntitlementMissing,
    ContactPermissionMissing,
    ContactPermissionExpired,
    ContactPermissionRevoked,
    ContactPermissionScopeMismatch,
    Suppressed,
    OutsideContactHours,
    FrequencyLimitExceeded,
    OptOutTextMissing,
    DestinationNotAllowlisted,
    DispatchDisabled,
    ApprovalMissing,
    ApprovalExpired,
    ApprovalRevoked,
    ApprovalConsumed,
    ApprovalDigestMismatch,
    ApprovalWrongAction,
    ApprovalWrongTenant,
    ApprovalRejected,
    SelfApprovalForbidden,
    ApproverNotAuthorized,
    PermanentSuppressionLiftForbidden,
}

impl DenyCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TenantMismatch => "tenant_mismatch",
            Self::ActorNotAuthorized => "actor_not_authorized",
            Self::ToolNotAllowlisted => "tool_not_allowlisted",
            Self::ToolKindMismatch => "tool_kind_mismatch",
            Self::ActionExpired => "action_expired",
            Self::EntitlementMissing => "entitlement_missing",
            Self::ContactPermissionMissing => "contact_permission_missing",
            Self::ContactPermissionExpired => "contact_permission_expired",
            Self::ContactPermissionRevoked => "contact_permission_revoked",
            Self::ContactPermissionScopeMismatch => "contact_permission_scope_mismatch",
            Self::Suppressed => "suppressed",
            Self::OutsideContactHours => "outside_contact_hours",
            Self::FrequencyLimitExceeded => "frequency_limit_exceeded",
            Self::OptOutTextMissing => "opt_out_text_missing",
            Self::DestinationNotAllowlisted => "destination_not_allowlisted",
            Self::DispatchDisabled => "dispatch_disabled",
            Self::ApprovalMissing => "approval_missing",
            Self::ApprovalExpired => "approval_expired",
            Self::ApprovalRevoked => "approval_revoked",
            Self::ApprovalConsumed => "approval_consumed",
            Self::ApprovalDigestMismatch => "approval_digest_mismatch",
            Self::ApprovalWrongAction => "approval_wrong_action",
            Self::ApprovalWrongTenant => "approval_wrong_tenant",
            Self::ApprovalRejected => "approval_rejected",
            Self::SelfApprovalForbidden => "self_approval_forbidden",
            Self::ApproverNotAuthorized => "approver_not_authorized",
            Self::PermanentSuppressionLiftForbidden => "permanent_suppression_lift_forbidden",
        }
    }

    /// Denials that should move an already-queued action to `Suppressed`
    /// (consent changed) rather than `Denied`.
    #[must_use]
    pub const fn is_consent_change(self) -> bool {
        matches!(
            self,
            Self::ContactPermissionExpired
                | Self::ContactPermissionRevoked
                | Self::ContactPermissionMissing
                | Self::Suppressed
        )
    }
}

/// Enforcement requirements the executor must honour. A decision is never a
/// bare boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "obligation", rename_all = "snake_case")]
pub enum Obligation {
    /// Redact these argument keys from logs and audit payloads.
    RedactFields { keys: Vec<String> },
    /// Hard cap on recipients in one action.
    MaxRecipients { max: u32 },
    /// Only dispatch within this local-time window (inclusive hours, 0-23).
    SendWindow {
        start_hour: u8,
        end_hour: u8,
        tz: String,
    },
    /// The rendered text must contain this opt-out phrase (case-insensitive).
    RequireOptOutText { phrase: String },
    /// Route to this adapter kind only.
    AdapterKind { kind: String },
    /// Approval must come from a different user than the requester.
    SeparateApprover,
    /// Approval expires this many seconds after it is granted.
    ApprovalTtlSecs { secs: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow {
        obligations: Vec<Obligation>,
    },
    Deny {
        code: DenyCode,
        reason: String,
    },
    RequireApproval {
        /// Named approval policy (e.g. `"outreach_high"`), for the approval UI.
        approval_policy: String,
        obligations: Vec<Obligation>,
    },
    RequireMoreInformation {
        fields: Vec<String>,
    },
}

impl Decision {
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    #[must_use]
    pub fn deny_code(&self) -> Option<DenyCode> {
        match self {
            Self::Deny { code, .. } => Some(*code),
            _ => None,
        }
    }

    #[must_use]
    pub fn obligations(&self) -> &[Obligation] {
        match self {
            Self::Allow { obligations } | Self::RequireApproval { obligations, .. } => obligations,
            _ => &[],
        }
    }
}
