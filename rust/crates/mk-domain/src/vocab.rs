//! Closed vocabularies. Every enum here is `#[serde(rename_all = "snake_case")]`
//! and `deny_unknown` by construction: an unrecognised string fails to parse,
//! which is the fail-closed behaviour the kernel requires.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Workflow {
    CustomerFollowUp,
    FollowUp,
    Appointment,
    OrderStatus,
    RecruitOutreach,
    SocialPost,
}

impl Workflow {
    /// Workflows that contact a third party. These always require human
    /// approval and a current contact permission.
    #[must_use]
    pub const fn is_outreach(self) -> bool {
        matches!(
            self,
            Self::CustomerFollowUp | Self::FollowUp | Self::RecruitOutreach | Self::OrderStatus
        )
    }

    /// Workflows on which self-approval is disabled regardless of tenant config.
    #[must_use]
    pub const fn forbids_self_approval(self) -> bool {
        matches!(self, Self::RecruitOutreach)
    }

    /// Wire name as published in `mobile-work-order.schema.json`.
    #[must_use]
    pub const fn mobile_contract_name(self) -> Option<&'static str> {
        match self {
            Self::FollowUp | Self::CustomerFollowUp => Some("follow_up"),
            Self::Appointment => Some("appointment"),
            Self::OrderStatus => Some("order_status"),
            Self::RecruitOutreach => Some("recruit_outreach"),
            Self::SocialPost => Some("social_post"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    SendSms,
    SendEmail,
    SendDm,
    CreateAppointment,
    UpdateContact,
    PostSocial,
    MobileWorkOrder,
}

impl ActionKind {
    /// Does executing this kind produce an externally visible message to a
    /// person? Outreach is always approval-gated and permission-gated.
    #[must_use]
    pub const fn is_outreach(self) -> bool {
        matches!(
            self,
            Self::SendSms | Self::SendEmail | Self::SendDm | Self::MobileWorkOrder
        )
    }

    /// The channel this kind communicates over, if any.
    #[must_use]
    pub const fn channel(self) -> Option<Channel> {
        match self {
            Self::SendSms => Some(Channel::Sms),
            Self::SendEmail => Some(Channel::Email),
            Self::SendDm => Some(Channel::Dm),
            Self::PostSocial => Some(Channel::Social),
            Self::MobileWorkOrder => None, // channel comes from the work order target
            Self::CreateAppointment | Self::UpdateContact => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Sms,
    Email,
    Dm,
    Social,
    Instagram,
    Facebook,
    Tiktok,
    X,
}

impl Channel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sms => "sms",
            Self::Email => "email",
            Self::Dm => "dm",
            Self::Social => "social",
            Self::Instagram => "instagram",
            Self::Facebook => "facebook",
            Self::Tiktok => "tiktok",
            Self::X => "x",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Contact,
    Appointment,
    Post,
    Tenant,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginType {
    Agent,
    Human,
    System,
    Mcp,
}

impl OriginType {
    /// Origins that are *untrusted proposers*. Their proposals are evaluated
    /// identically to any other, but they can never carry approval authority.
    #[must_use]
    pub const fn is_autonomous(self) -> bool {
        matches!(self, Self::Agent | Self::Mcp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PermissionStatus {
    Granted,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
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
    fn unknown_variants_fail_closed() {
        assert!(serde_json::from_str::<Workflow>("\"delete_everything\"").is_err());
        assert!(serde_json::from_str::<ActionKind>("\"http_request\"").is_err());
        assert!(serde_json::from_str::<Risk>("\"none\"").is_err());
    }

    #[test]
    fn outreach_classification() {
        assert!(ActionKind::SendSms.is_outreach());
        assert!(ActionKind::MobileWorkOrder.is_outreach());
        assert!(!ActionKind::UpdateContact.is_outreach());
        assert!(Workflow::RecruitOutreach.forbids_self_approval());
        assert!(!Workflow::SocialPost.is_outreach());
    }

    #[test]
    fn risk_is_ordered() {
        assert!(Risk::Low < Risk::Medium && Risk::Medium < Risk::High);
    }
}
