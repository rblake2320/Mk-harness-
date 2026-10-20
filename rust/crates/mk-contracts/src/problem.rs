//! RFC 9457 problem details with stable internal codes. Never carries stack
//! traces, secrets, or upstream bodies.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub code: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

impl ProblemDetails {
    #[must_use]
    pub fn new(status: u16, code: &str, title: &str, request_id: &str) -> Self {
        Self {
            problem_type: format!("urn:mk:error:{}", code.to_ascii_lowercase()),
            title: title.to_owned(),
            status,
            detail: None,
            code: code.to_owned(),
            request_id: request_id.to_owned(),
            trace_id: None,
            fields: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        let d: String = detail.into();
        self.detail = Some(if d.len() > 2000 {
            let mut end = 2000;
            while !d.is_char_boundary(end) {
                end -= 1;
            }
            d[..end].to_owned()
        } else {
            d
        });
        self
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
    use crate::schema::{SchemaId, validate};

    #[test]
    fn matches_error_schema() {
        let p = ProblemDetails::new(403, "POLICY_DENIED", "Policy denied the action", "req-1")
            .with_detail("contact permission revoked");
        let v = serde_json::to_value(&p).unwrap_or_default();
        assert_eq!(validate(SchemaId::Error, &v), Ok(()));
        assert_eq!(p.problem_type, "urn:mk:error:policy_denied");
    }

    #[test]
    fn detail_is_capped() {
        let p = ProblemDetails::new(500, "INTERNAL", "x", "r").with_detail("a".repeat(10_000));
        assert_eq!(p.detail.map(|d| d.len()), Some(2000));
    }
}
