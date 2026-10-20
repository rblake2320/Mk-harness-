//! Outbound adapters.
//!
//! The [`ActionAdapter`] trait is sealed: only adapters in this crate can
//! implement it, which is how the "no generic HTTP/SQL/shell tool" rule is
//! enforced at the type level. Each adapter declares a [`AdapterDescriptor`]
//! that the worker checks against the policy obligations before calling
//! `execute`.

pub mod egress;
pub mod mobile;
pub mod simulator;

use async_trait::async_trait;
use mk_contracts::ActionRequest;
use mk_crypto::Digest;
use mk_domain::{ActionId, ActionKind, TenantId};
use mk_queue::RetryClass;

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDescriptor {
    pub adapter_kind: &'static str,
    pub tool_ids: &'static [&'static str],
    pub kinds: &'static [ActionKind],
    /// Completion arrives via callback (`true`) or synchronously (`false`).
    pub callback_based: bool,
    /// Argument keys that are PII and must never be logged.
    pub pii_fields: &'static [&'static str],
}

/// An action the worker has already authorized: policy rechecked, approval
/// consumed, lease held. Adapters receive nothing else.
#[derive(Debug, Clone)]
pub struct AuthorizedAction {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub attempt: u32,
    pub request: ActionRequest,
    pub action_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterReceipt {
    pub adapter_id: Option<uuid::Uuid>,
    pub external_ref: Option<String>,
    pub result_digest: Option<Digest>,
    /// `true` when the adapter accepted the work and completion will arrive
    /// by authenticated callback.
    pub pending_callback: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("adapter error [{class:?}] {code}")]
pub struct AdapterError {
    pub class: RetryClass,
    pub code: &'static str,
}

impl AdapterError {
    #[must_use]
    pub const fn permanent(code: &'static str) -> Self {
        Self {
            class: RetryClass::Permanent,
            code,
        }
    }
    #[must_use]
    pub const fn transient(code: &'static str) -> Self {
        Self {
            class: RetryClass::Transient,
            code,
        }
    }
    #[must_use]
    pub const fn ambiguous(code: &'static str) -> Self {
        Self {
            class: RetryClass::Ambiguous,
            code,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileResult {
    Completed,
    Failed,
    StillPending,
    Unknown,
}

#[async_trait]
pub trait ActionAdapter: sealed::Sealed + Send + Sync {
    fn descriptor(&self) -> AdapterDescriptor;
    async fn validate(&self, action: &AuthorizedAction) -> Result<(), AdapterError>;
    async fn execute(&self, action: &AuthorizedAction) -> Result<AdapterReceipt, AdapterError>;
    async fn reconcile(&self, receipt: &AdapterReceipt) -> Result<ReconcileResult, AdapterError>;
}

/// Internal no-network adapters for CRM/calendar kinds. They record intent
/// only; the FastAPI application remains the system of record for those
/// objects in v1.
#[derive(Debug, Default)]
pub struct InternalRecordAdapter;

impl sealed::Sealed for InternalRecordAdapter {}

#[async_trait]
impl ActionAdapter for InternalRecordAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            adapter_kind: "crm-internal-v1",
            tool_ids: &["crm.contact.update.v1", "calendar.appointment.create.v1"],
            kinds: &[ActionKind::UpdateContact, ActionKind::CreateAppointment],
            callback_based: false,
            pii_fields: &["email", "phone", "notes"],
        }
    }

    async fn validate(&self, action: &AuthorizedAction) -> Result<(), AdapterError> {
        if self
            .descriptor()
            .kinds
            .contains(&action.request.action_kind)
        {
            Ok(())
        } else {
            Err(AdapterError::permanent("unsupported_action_kind"))
        }
    }

    async fn execute(&self, action: &AuthorizedAction) -> Result<AdapterReceipt, AdapterError> {
        Ok(AdapterReceipt {
            adapter_id: None,
            external_ref: Some(format!("internal:{}", action.action_id)),
            result_digest: Some(Digest::of(action.action_digest.as_bytes())),
            pending_callback: false,
        })
    }

    async fn reconcile(&self, _receipt: &AdapterReceipt) -> Result<ReconcileResult, AdapterError> {
        Ok(ReconcileResult::Completed)
    }
}

/// Registry keyed by adapter kind. Deliberately a closed enum of
/// constructors, not a plugin loader.
#[derive(Debug)]
pub struct AdapterRegistry {
    pub internal: InternalRecordAdapter,
    pub mobile: Option<mobile::MobileAdapter>,
}

impl AdapterRegistry {
    #[must_use]
    pub fn get(&self, adapter_kind: &str) -> Option<&dyn ActionAdapter> {
        match adapter_kind {
            "crm-internal-v1" | "calendar-internal-v1" => Some(&self.internal),
            "mobile-adapter-v1" => self.mobile.as_ref().map(|m| m as &dyn ActionAdapter),
            _ => None,
        }
    }
}
