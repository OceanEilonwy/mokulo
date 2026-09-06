//! The HTTP API surface. See `docs/DESIGN.md` §10.
//!
//! Three simplifications worth naming up front, all reasonable for this pass and
//! all noted rather than hidden:
//!
//! 1. `Store` access from handlers goes through `state.store.lock().unwrap()`
//!    directly rather than a dedicated writer-actor thread reached over a channel.
//!    SQLite disallows concurrent writers regardless, so this is a correct - if
//!    simpler - realization of "single writer" (same reasoning as the concurrency
//!    stress test in `store.rs`). It does mean a handler briefly blocks the async
//!    worker thread it's running on for the duration of a query; fine for
//!    single-digit-millisecond local SQLite access, worth revisiting with
//!    `spawn_blocking` if a slower storage backend ever sits behind this trait.
//! 2. `wallet_handles` is populated eagerly at boot by `main` (via
//!    `Store::list_active_tenants` + `KeyCustody::unseal_and_register`), with the
//!    lazy path in `resolve_wallet_handle` kept as a fallback for a tenant created
//!    after boot.
//! 3. Rate limiting (`rate_limit`) is a fixed-window per-IP counter, not a proper
//!    token bucket - simpler, and sufficient for the actual goal (§DESIGN.md §12).
//!    The PoW-challenge fallback for sustained load is not implemented.
//! 4. CORS (`build_cors_layer`) re-derives the same `allowed_origins` check
//!    `public::resolve_public_tenant` already does server-side (§DESIGN.md §12: the
//!    app-layer check is the actual guarantee, this layer only makes the browser's
//!    *own* enforcement work at all) via one extra `Store` lookup per preflight -
//!    negligible against local SQLite, and it's what lets a genuinely cross-origin
//!    merchant site's `fetch()` calls succeed instead of being silently blocked by
//!    the browser for lacking `Access-Control-Allow-Origin`.
//!
//! Not implemented in this pass: TLS termination (expected to sit behind a reverse
//! proxy or terminate via `rustls` in `main`, not implemented here).

mod admin;
mod public;
pub mod rate_limit;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::extract::FromRequestParts;
use axum::http::{Method, StatusCode, header, request::Parts};
use axum::middleware;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde_json::json;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use crate::exchange_rate::ExchangeRateProvider;
use crate::key_custody::{KeyCustody, KeyCustodyError, WalletHandle};
use crate::status::OrderStatus;
use crate::store::{SharedStore, StoreError, Tenant};

use rate_limit::{rate_limit_middleware, RateLimiter};

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub key_custody: Arc<dyn KeyCustody>,
    pub exchange_rate: Arc<dyn ExchangeRateProvider>,
    pub wallet_handles: Arc<RwLock<HashMap<String, WalletHandle>>>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Which networks this instance can actually scan - i.e. which
    /// `[monero_node.<network>]` sections are configured. A tenant can only be
    /// created for a network in this set; otherwise its address would be derived
    /// but never scanned by anything; see `docs/DESIGN.md` §7 (multi-network) and
    /// `admin::create_tenant`.
    pub configured_networks: Arc<std::collections::HashSet<monero::Network>>,
}

pub fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/api/v1/admin/tenants", post(admin::create_tenant))
        .route(
            "/api/v1/admin/tenant",
            get(admin::get_own_tenant).patch(admin::patch_own_tenant).delete(admin::delete_own_tenant),
        )
        .route("/api/v1/admin/tenant/rotate-secret", post(admin::rotate_secret))
        .route("/api/v1/admin/tenant/orders", get(admin::list_orders))
        .route("/api/v1/admin/tenant/orders/{payment_id}", get(admin::get_order_detail))
        .route(
            "/api/v1/admin/tenant/webhooks",
            get(admin::list_webhooks).post(admin::create_webhook),
        )
        .route("/api/v1/admin/tenant/webhooks/{webhook_id}", delete(admin::delete_webhook))
        .route("/api/v1/t/{pk}/orders", post(public::create_order))
        .route("/api/v1/t/{pk}/orders/{payment_id}", get(public::get_order_status))
        .route(
            "/api/v1/t/{pk}/orders/{payment_id}/refund-address",
            post(public::set_refund_address),
        )
        .route("/pay/v1/{pk}/{payment_id}", get(public::payment_page))
        .route("/static/moneropay-client.js", get(public::client_library))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(build_cors_layer(state.store.clone()))
        .with_state(state)
}

/// Only the `/api/v1/t/{pk}/orders...` family needs real cross-origin browser
/// support: it's the surface a merchant's own (necessarily different-origin) static
/// site calls directly via `fetch()`. `/pay/v1/...` is loaded as an iframe `src` and
/// polls its own origin from inside that frame - same-origin, no CORS involved -
/// and `/static/moneropay-client.js` is a plain `<script src>` load, which was never
/// subject to CORS in the first place. The admin API is deliberately left with no
/// CORS grant at all: it's a backend-to-backend surface authenticated by a secret
/// token, never meant to be called from an arbitrary browser tab.
fn build_cors_layer(store: SharedStore) -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE])
        .allow_origin(AllowOrigin::predicate(move |origin, parts| {
            let Some(pk) = public_orders_route_pk(parts.uri.path()) else {
                return false;
            };
            let Ok(origin_str) = origin.to_str() else {
                return false;
            };
            let store = store.lock().unwrap();
            matches!(
                store.find_tenant_by_public_key(pk),
                Ok(Some(tenant)) if tenant.allowed_origins.iter().any(|o| o == origin_str)
            )
        }))
}

/// Extracts `{pk}` from a path if it matches `/api/v1/t/{pk}/orders...` - shared by
/// `build_cors_layer`'s preflight check (which runs before axum's own path-param
/// extraction, on the raw `Parts`) so the same route family stays defined in one
/// place rather than drifting out of sync with the `.route(...)` calls above.
fn public_orders_route_pk(path: &str) -> Option<&str> {
    let mut segments = path.trim_start_matches('/').split('/');
    match (segments.next(), segments.next(), segments.next(), segments.next(), segments.next()) {
        (Some("api"), Some("v1"), Some("t"), Some(pk), Some("orders")) => Some(pk),
        _ => None,
    }
}

pub use crate::now_unix;

pub use crate::network::{network_str, parse_network};

pub fn parse_status_query(s: &str) -> Result<OrderStatus, ApiError> {
    match s {
        "pending" => Ok(OrderStatus::Pending),
        "unconfirmed" => Ok(OrderStatus::Unconfirmed),
        "confirming" => Ok(OrderStatus::Confirming),
        "paid" => Ok(OrderStatus::Paid),
        "partial" => Ok(OrderStatus::Partial),
        "overpaid" => Ok(OrderStatus::Overpaid),
        "expired" => Ok(OrderStatus::Expired),
        other => Err(ApiError::BadRequest(format!("unknown status filter: {other}"))),
    }
}

/// Resolves a tenant *entirely* from the presented `sk_` bearer token - never from
/// any path parameter. This is the structural fix from `docs/DESIGN.md` §10.1: there
/// is nothing in a `/api/v1/admin/tenant/*` route for a leaked or guessed identifier
/// to authorize, because none of them accept one.
pub struct AuthedTenant(pub Tenant);

impl FromRequestParts<AppState> for AuthedTenant {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = header_value.strip_prefix("Bearer ").ok_or(ApiError::Unauthorized)?;
        let tenant = state
            .store
            .lock()
            .unwrap()
            .find_tenant_by_secret_token(token)?
            .ok_or(ApiError::Unauthorized)?;
        Ok(AuthedTenant(tenant))
    }
}

/// Ensures a tenant has a live `WalletHandle` in this process, registering it with
/// `KeyCustody` from its sealed material on first use if it doesn't yet.
pub async fn resolve_wallet_handle(state: &AppState, tenant: &Tenant) -> Result<WalletHandle, ApiError> {
    if let Some(handle) = state.wallet_handles.read().unwrap().get(&tenant.id).copied() {
        return Ok(handle);
    }
    // The registration can't happen under the lock (it's `async`, and holding a
    // std `RwLock` across an `.await` would be a deadlock waiting to happen), so two
    // concurrent first-uses of the same tenant can both reach here. Re-check under
    // the write lock and keep whichever landed first: without this, the loser's
    // handle is silently overwritten in the map while the key material it registered
    // stays live in `KeyCustody` forever, unreachable and unremovable - a leaked
    // extra copy of a tenant's private view key, and one that `delete_own_tenant`
    // would then fail to clean up on offboarding.
    let handle = state.key_custody.unseal_and_register(&tenant.sealed_key_material).await?;
    let winner = {
        let mut handles = state.wallet_handles.write().unwrap();
        *handles.entry(tenant.id.clone()).or_insert(handle)
    };
    if winner != handle {
        let _ = state.key_custody.remove_wallet(handle).await;
    }
    Ok(winner)
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    NotFound,
    Forbidden(String),
    BadRequest(String),
    Internal(String),
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => ApiError::NotFound,
            StoreError::Sqlite(e) => ApiError::Internal(e.to_string()),
        }
    }
}

impl From<KeyCustodyError> for ApiError {
    fn from(e: KeyCustodyError) -> Self {
        match e {
            KeyCustodyError::UnknownWallet => ApiError::NotFound,
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
