//! `POST /internal/v1/erasures` — subject erasure, kernel side (contract S13).
//! Tenant administrators only (FastAPI sends it on behalf of the consultant who
//! erased the customer); never an agent. Body: `request_ref` (the application's
//! erasure request id, idempotency key), `destination_hashes` (fingerprint tags),
//! `action_ids`. See `mk_store::erasure` for exactly what is erased and kept.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use mk_store::erasure::{self, ErasureError, MAX_ACTIONS, MAX_HASHES};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EraseBody {
    pub request_ref: String,
    #[serde(default)]
    pub destination_hashes: Vec<String>,
    #[serde(default)]
    pub action_ids: Vec<Uuid>,
}

fn bad(code: &'static str, detail: &str) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        code,
        "Invalid erasure request",
    )
    .detail(detail.to_owned())
}

/// A fingerprint tag is `<kid>:<64 hex>` (versioned) or bare 64 hex (legacy).
fn valid_hash(h: &str) -> bool {
    let hex = h.rsplit_once(':').map_or(h, |(kid, hex)| {
        if kid.is_empty()
            || kid.len() > 16
            || !kid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return "";
        }
        hex
    });
    hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub async fn erase(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(body): Json<EraseBody>,
) -> Result<Json<erasure::ErasureResult>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    if p.has_role("agent") && p.roles.len() == 1 {
        return Err(rid(ApiError::new(
            StatusCode::FORBIDDEN,
            "AGENT_CANNOT_ERASE",
            "Requires a human principal",
        )));
    }
    p.require_role("tenant_admin").map_err(rid)?;
    let r = body.request_ref.trim();
    if r.is_empty()
        || r.len() > 64
        || !r
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_:".contains(c))
    {
        return Err(rid(bad(
            "BAD_REQUEST_REF",
            "request_ref: 1–64 of [A-Za-z0-9-_:]",
        )));
    }
    if body.destination_hashes.len() > MAX_HASHES || body.action_ids.len() > MAX_ACTIONS {
        return Err(rid(bad(
            "TOO_MANY",
            "too many destination hashes or action ids",
        )));
    }
    if body.destination_hashes.is_empty() && body.action_ids.is_empty() {
        return Err(rid(bad("EMPTY_SCOPE", "nothing to erase")));
    }
    if let Some(h) = body.destination_hashes.iter().find(|h| !valid_hash(h)) {
        let _ = h;
        return Err(rid(bad(
            "BAD_DESTINATION_HASH",
            "destination hashes must be fingerprint tags",
        )));
    }
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let out = erasure::erase_subject(
        &mut tx,
        r,
        p.user,
        &body.destination_hashes,
        &body.action_ids,
        Utc::now(),
    )
    .await
    .map_err(|e| match e {
        ErasureError::InFlight(n) => {
            rid(
                ApiError::new(StatusCode::CONFLICT, "DISPATCH_IN_FLIGHT", "Retry later").detail(
                    format!("{n} matching action(s) are being dispatched; retry after they finish"),
                ),
            )
        }
        ErasureError::Store(s) => rid(s.into()),
    })?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::valid_hash;

    #[test]
    fn destination_hash_shapes() {
        let hex = "a".repeat(64);
        assert!(valid_hash(&hex));
        assert!(valid_hash(&format!("m0:{hex}")));
        assert!(valid_hash(&format!("k-2026_1:{hex}")));
        for bad in [
            String::new(),
            "a".repeat(63),
            "A".repeat(64),
            format!(":{hex}"),
            format!("x y:{hex}"),
            format!("{}:{hex}", "k".repeat(17)),
            format!("m0:{}", "g".repeat(64)),
            "+15555550100".into(),
        ] {
            assert!(!valid_hash(&bad), "{bad}");
        }
    }
}
