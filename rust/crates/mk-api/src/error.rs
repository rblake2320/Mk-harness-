//! HTTP error mapping. Everything becomes RFC 9457 problem details with a
//! stable `code`; nothing leaks a stack trace, SQL, or upstream body.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use mk_contracts::ProblemDetails;
use mk_policy::DenyCode;
use mk_store::StoreError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub title: String,
    pub detail: Option<String>,
    pub request_id: String,
    /// Seconds for a `Retry-After` header (429/503 capacity refusals).
    pub retry_after: Option<u64>,
}

impl ApiError {
    #[must_use]
    pub fn new(status: StatusCode, code: &str, title: &str) -> Self {
        Self {
            status,
            code: code.to_owned(),
            title: title.to_owned(),
            detail: None,
            request_id: String::new(),
            retry_after: None,
        }
    }

    #[must_use]
    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }

    #[must_use]
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }

    #[must_use]
    pub fn with_request_id(mut self, headers: &HeaderMap) -> Self {
        self.request_id.clear();
        self.request_id.push_str(
            headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown"),
        );
        self
    }

    #[must_use]
    pub fn deny(code: DenyCode) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            &code.as_str().to_ascii_uppercase(),
            "Policy denied the action",
        )
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        let (status, title) = match &e {
            StoreError::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            StoreError::Conflict(_) => (StatusCode::CONFLICT, "Conflict"),
            StoreError::Transition(_) => (StatusCode::CONFLICT, "Illegal state transition"),
            StoreError::Contract(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Contract violation"),
            StoreError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "Store unavailable"),
            StoreError::Transient(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "Transient conflict; retry")
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };
        tracing::error!(code = e.code(), error = %e, "store error");
        let mut err = Self::new(status, e.code(), title);
        if let StoreError::Conflict(reason) = &e {
            err.detail = Some((*reason).to_owned());
        }
        err
    }
}

impl From<mk_contracts::ContractError> for ApiError {
    fn from(e: mk_contracts::ContractError) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CONTRACT_VIOLATION",
            "Payload does not match contract",
        )
        .detail(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut p = ProblemDetails::new(
            self.status.as_u16(),
            &self.code,
            &self.title,
            &self.request_id,
        );
        if let Some(d) = self.detail {
            p = p.with_detail(d);
        }
        let mut resp = (self.status, Json(p)).into_response();
        if let Some(secs) = self.retry_after {
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from(secs),
            );
        }
        if let Ok(v) = "application/problem+json".parse() {
            resp.headers_mut()
                .insert(axum::http::header::CONTENT_TYPE, v);
        }
        resp
    }
}
