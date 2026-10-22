//! Internal HTTP API. Listens on the private service network only.
//!
//! Every `/internal/v1/*` request carries a short-lived Ed25519 actor
//! assertion minted by FastAPI; `/adapter/v1/*` callbacks carry the
//! mobile-adapter HMAC headers instead. Handlers translate HTTP into store
//! and policy calls and back; they contain no authorization logic of their
//! own.

pub mod auth;
pub mod error;
pub mod limits;
pub mod metrics;
pub mod routes;
pub mod state;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use std::time::Duration;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;

pub use state::{AppState, ApprovalRp};

pub const MAX_BODY_BYTES: usize = 256 * 1024;

pub fn router(state: AppState) -> Router {
    let internal = Router::new()
        .route("/actions", post(routes::actions::propose))
        .route("/actions/{action_id}", get(routes::actions::get))
        .route("/actions/{action_id}/cancel", post(routes::actions::cancel))
        .route("/actions/{action_id}/replay", post(routes::actions::replay))
        .route(
            "/actions/{action_id}/approve",
            post(routes::approvals::approve),
        )
        .route(
            "/actions/{action_id}/reject",
            post(routes::approvals::reject),
        )
        .route("/approvals/pending", get(routes::approvals::pending))
        .route(
            "/actions/{action_id}/approval-challenge",
            post(routes::human_approval::approval_challenge),
        )
        .route(
            "/approval-credentials/register/begin",
            post(routes::human_approval::register_begin),
        )
        .route(
            "/approval-credentials/register/finish",
            post(routes::human_approval::register_finish),
        )
        .route("/approval-credentials", get(routes::human_approval::list))
        .route(
            "/approval-credentials/{credential_row_id}/revoke",
            post(routes::human_approval::revoke_credential),
        )
        .route(
            "/revocations",
            post(routes::human_approval::revoke_principal),
        )
        .route(
            "/approvals/{approval_id}/revoke",
            post(routes::approvals::revoke),
        )
        .route(
            "/contacts/{contact_id}/permissions",
            post(routes::consent::grant_permission),
        )
        .route(
            "/contacts/{contact_id}/permissions/{permission_id}/revoke",
            post(routes::consent::revoke_permission),
        )
        .route("/suppressions", post(routes::consent::add_suppression))
        .route(
            "/suppressions/{suppression_id}",
            delete(routes::consent::lift_suppression),
        )
        .route("/adapters", post(routes::adapters::register))
        .route("/adapters/{adapter_id}", get(routes::adapters::get))
        .route(
            "/adapters/{adapter_id}/rotate",
            post(routes::adapters::rotate),
        )
        .route(
            "/adapters/{adapter_id}/revoke",
            post(routes::adapters::revoke),
        )
        .route("/kill-switch/tenant", post(routes::ops::tenant_kill_switch))
        .route("/kill-switch/global", post(routes::ops::global_kill_switch))
        .route(
            "/kill-switch/global/challenge",
            post(routes::human_approval::global_enable_challenge),
        )
        .route(
            "/senders",
            post(routes::messaging::register_sender).get(routes::messaging::list_senders),
        )
        .route(
            "/senders/{id}/registration",
            post(routes::messaging::set_registration),
        )
        .route("/inbound/pending", get(routes::messaging::inbound_pending))
        .route(
            "/inbound/{event_id}/processed",
            post(routes::messaging::inbound_processed),
        )
        .route(
            "/inbound/health",
            get(routes::messaging::inbound_health).post(routes::messaging::inbound_health_report),
        )
        .route("/inbound/pause", post(routes::messaging::inbound_pause))
        .route("/inbound/resume", post(routes::messaging::inbound_resume))
        // O2: refuse immediately (503 + Retry-After) when the replica is full,
        // rather than queueing into the request timeout. Webhooks, adapter
        // callbacks and health are outside this router and never shed.
        .layer(axum::middleware::from_fn_with_state(state.clone(), shed));

    Router::new()
        .nest("/internal/v1", internal)
        .route(
            "/adapter/v1/work-orders/{action_id}/callbacks",
            post(routes::callbacks::callback),
        )
        // Provider webhooks: public ingress, authenticated by provider signature.
        .route(
            "/webhooks/twilio/status/{sender_identity_id}",
            post(routes::messaging::twilio_status),
        )
        .route(
            "/webhooks/twilio/inbound/{sender_identity_id}",
            post(routes::messaging::twilio_inbound),
        )
        .route("/health/live", get(routes::ops::live))
        .route("/health/ready", get(routes::ops::ready))
        .route("/metrics", get(routes::ops::metrics))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            record_request,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(state)
}

async fn shed(
    axum::extract::State(st): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if limits::is_safety_control(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    let Some(permit) = st.limiter.try_enter() else {
        st.metrics
            .rejected
            .get_or_create(&metrics::AuthFailLabels {
                code: "over_capacity".into(),
            })
            .inc();
        return limits::over_capacity(req.headers());
    };
    let res = next.run(req).await;
    drop(permit);
    res
}

/// Request counter + latency histogram keyed by the *matched route template*
/// (`/internal/v1/actions/{action_id}`), never the concrete path, so no
/// identifier reaches the metrics endpoint and cardinality stays bounded.
async fn record_request(
    axum::extract::State(st): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let started = std::time::Instant::now();
    let res = next.run(req).await;
    st.metrics
        .requests
        .get_or_create(&metrics::RouteLabels {
            route: route.clone(),
            status: res.status().as_u16(),
        })
        .inc();
    st.metrics
        .request_duration
        .get_or_create(&metrics::PathLabels { route })
        .observe(started.elapsed().as_secs_f64());
    res
}
