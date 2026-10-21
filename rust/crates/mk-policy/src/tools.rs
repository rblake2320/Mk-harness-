//! Exact-authority tool allowlist. Deny by default: a `tool_id` not listed
//! here cannot be proposed, approved, or executed, and a listed tool may only
//! be used for the action kinds and channels it declares.

use mk_domain::{ActionKind, Channel, Risk};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEntry {
    pub tool_id: &'static str,
    pub kinds: &'static [ActionKind],
    pub channels: &'static [Channel],
    /// Minimum risk classification the kernel assigns regardless of what the
    /// proposer claimed. Proposers can raise risk, never lower it.
    pub floor_risk: Risk,
    /// Adapter kind that executes it.
    pub adapter_kind: &'static str,
    /// Hosts this tool may reach. Empty = no network egress.
    pub egress_hosts: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAllowlist {
    entries: Vec<ToolEntry>,
}

impl ToolAllowlist {
    /// The version-one allowlist. Note what is *absent*: no generic HTTP, SQL,
    /// shell, filesystem, or browser tool exists and none may be added without
    /// a reviewed change to this file (CODEOWNERS-protected).
    #[must_use]
    pub fn v1() -> Self {
        Self {
            entries: vec![
                ToolEntry {
                    tool_id: "mobile.sms.send.v1",
                    kinds: &[ActionKind::SendSms],
                    channels: &[Channel::Sms],
                    floor_risk: Risk::High,
                    adapter_kind: "mobile-adapter-v1",
                    egress_hosts: &[],
                },
                // Production SMS transport (docs/transport-decision.md): a
                // registered sender per consultant business via the Twilio
                // adapter. The only tool with egress, pinned to the provider.
                ToolEntry {
                    tool_id: "sms.provider.send.v1",
                    kinds: &[ActionKind::SendSms],
                    channels: &[Channel::Sms],
                    floor_risk: Risk::High,
                    adapter_kind: "twilio-sms-v1",
                    egress_hosts: &["api.twilio.com"],
                },
                ToolEntry {
                    tool_id: "mobile.dm.send.v1",
                    kinds: &[ActionKind::SendDm],
                    channels: &[
                        Channel::Instagram,
                        Channel::Facebook,
                        Channel::Tiktok,
                        Channel::X,
                    ],
                    floor_risk: Risk::High,
                    adapter_kind: "mobile-adapter-v1",
                    egress_hosts: &[],
                },
                ToolEntry {
                    tool_id: "mobile.social.post.v1",
                    kinds: &[ActionKind::PostSocial],
                    channels: &[
                        Channel::Social,
                        Channel::Instagram,
                        Channel::Facebook,
                        Channel::Tiktok,
                        Channel::X,
                    ],
                    floor_risk: Risk::Medium,
                    adapter_kind: "mobile-adapter-v1",
                    egress_hosts: &[],
                },
                ToolEntry {
                    tool_id: "crm.contact.update.v1",
                    kinds: &[ActionKind::UpdateContact],
                    channels: &[],
                    floor_risk: Risk::Low,
                    adapter_kind: "crm-internal-v1",
                    egress_hosts: &[],
                },
                ToolEntry {
                    tool_id: "calendar.appointment.create.v1",
                    kinds: &[ActionKind::CreateAppointment],
                    channels: &[],
                    floor_risk: Risk::Medium,
                    adapter_kind: "calendar-internal-v1",
                    egress_hosts: &[],
                },
            ],
        }
    }

    #[must_use]
    pub fn get(&self, tool_id: &str) -> Option<&ToolEntry> {
        self.entries.iter().find(|e| e.tool_id == tool_id)
    }

    #[must_use]
    pub fn permits(&self, tool_id: &str, kind: ActionKind, channel: Option<Channel>) -> bool {
        self.get(tool_id).is_some_and(|e| {
            e.kinds.contains(&kind) && channel.is_none_or(|c| e.channels.contains(&c))
        })
    }

    #[must_use]
    pub fn ids(&self) -> Vec<&'static str> {
        self.entries.iter().map(|e| e.tool_id).collect()
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

    #[test]
    fn no_dangerous_tools_exist() {
        let l = ToolAllowlist::v1();
        for forbidden in [
            "http", "sql", "shell", "exec", "fs", "file", "browser", "curl",
        ] {
            assert!(
                !l.ids().iter().any(|id| id.contains(forbidden)),
                "{forbidden} must not appear in the tool allowlist"
            );
        }
    }

    #[test]
    fn kind_and_channel_binding() {
        let l = ToolAllowlist::v1();
        assert!(l.permits(
            "mobile.sms.send.v1",
            ActionKind::SendSms,
            Some(Channel::Sms)
        ));
        assert!(!l.permits(
            "mobile.sms.send.v1",
            ActionKind::SendSms,
            Some(Channel::Email)
        ));
        assert!(!l.permits("mobile.sms.send.v1", ActionKind::UpdateContact, None));
        assert!(!l.permits(
            "mobile.sms.send.v2",
            ActionKind::SendSms,
            Some(Channel::Sms)
        ));
        assert!(!l.permits("", ActionKind::SendSms, None));
    }

    #[test]
    fn every_allowlisted_kind_has_an_adapter_implementation() {
        // `mobile_work_order` is a transport kind with no adapter builder; it
        // must never be proposable, or it would consume a human approval and
        // then dead-letter.
        let l = ToolAllowlist::v1();
        for e in &l.entries {
            assert!(
                !e.kinds.contains(&ActionKind::MobileWorkOrder),
                "{}",
                e.tool_id
            );
        }
        assert!(!l.permits(
            "mobile.sms.send.v1",
            ActionKind::MobileWorkOrder,
            Some(Channel::Sms)
        ));
    }

    #[test]
    fn dm_tool_binds_to_platform_channels() {
        let l = ToolAllowlist::v1();
        assert!(l.permits(
            "mobile.dm.send.v1",
            ActionKind::SendDm,
            Some(Channel::Instagram)
        ));
        assert!(!l.permits("mobile.dm.send.v1", ActionKind::SendDm, Some(Channel::Dm)));
        assert!(!l.permits("mobile.dm.send.v1", ActionKind::SendDm, Some(Channel::Sms)));
    }

    #[test]
    fn only_the_provider_sms_tool_has_egress_and_it_is_pinned() {
        for e in &ToolAllowlist::v1().entries {
            if e.tool_id == "sms.provider.send.v1" {
                assert_eq!(e.egress_hosts, &["api.twilio.com"]);
                assert_eq!(e.adapter_kind, "twilio-sms-v1");
            } else {
                assert!(e.egress_hosts.is_empty(), "{}", e.tool_id);
            }
        }
    }
}
