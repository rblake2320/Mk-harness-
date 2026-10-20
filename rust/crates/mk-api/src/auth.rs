//! Actor-assertion extraction and `jti` single-use enforcement for writes.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use mk_crypto::{ActorAssertion, NonceWindow, ReplayGuard};
use mk_domain::{TenantId, UserId};

use crate::error::ApiError;
use crate::state::AppState;

/// Process-local jti guard. Assertions live ≤ 60 s + skew, so a 130 s window
/// is sufficient. In a multi-replica deployment pair this with sticky
/// routing or a shared store; the assertion's short life bounds the exposure.
pub type JtiGuard = ReplayGuard;
pub const JTI_WINDOW: NonceWindow = NonceWindow { retain_secs: 130 };

/// The verified principal for a request.
#[derive(Debug, Clone)]
pub struct Principal {
    pub tenant: TenantId,
    pub user: UserId,
    pub roles: Vec<String>,
    pub session_id: String,
    pub request_id: String,
    pub assertion: ActorAssertion,
}

impl Principal {
    #[must_use]
    pub fn has_role(&self, r: &str) -> bool {
        self.roles.iter().any(|x| x == r)
    }

    pub fn require_role(&self, r: &str) -> Result<(), ApiError> {
        if self.has_role(r) {
            Ok(())
        } else {
            Err(
                ApiError::new(StatusCode::FORBIDDEN, "ROLE_REQUIRED", "Role required")
                    .detail(format!("requires role {r}")),
            )
        }
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "ASSERTION_MISSING",
                    "Actor assertion required",
                )
                .with_request_id(&parts.headers)
            })?;
        // Duplicate Authorization headers are a smuggling vector: refuse.
        if parts
            .headers
            .get_all(axum::http::header::AUTHORIZATION)
            .iter()
            .count()
            > 1
        {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "ASSERTION_AMBIGUOUS",
                "Multiple Authorization headers",
            )
            .with_request_id(&parts.headers));
        }
        let now = chrono::Utc::now().timestamp();
        let assertion = state.verifier.verify(token, now).map_err(|e| {
            state
                .metrics
                .assertion_failures
                .get_or_create(&crate::metrics::AuthFailLabels {
                    code: e.code().to_owned(),
                })
                .inc();
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                &e.code().to_ascii_uppercase(),
                "Actor assertion rejected",
            )
            .with_request_id(&parts.headers)
        })?;
        // Single-use jti for every non-GET request.
        if parts.method != axum::http::Method::GET {
            let mut g = state.jti.lock().await;
            if g.check_and_record("jti", &assertion.jti.to_string(), now, JTI_WINDOW)
                .is_err()
            {
                state
                    .metrics
                    .assertion_failures
                    .get_or_create(&crate::metrics::AuthFailLabels {
                        code: "assertion_replayed".into(),
                    })
                    .inc();
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "ASSERTION_REPLAYED",
                    "Assertion already used",
                )
                .with_request_id(&parts.headers));
            }
        }
        Ok(Self {
            tenant: TenantId::from_uuid(assertion.tenant_id),
            user: UserId::from_uuid(assertion.sub),
            roles: assertion.roles.clone(),
            session_id: assertion.session_id.clone(),
            request_id: assertion.request_id.clone(),
            assertion,
        })
    }
}
