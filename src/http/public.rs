use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, Json};
use qrcode::render::svg;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};

use crate::exchange_rate::{compute_xmr_amount, format_piconero_as_xmr};
use crate::key_custody::SubaddressIndex;
use crate::store::{NewOrder, Tenant};
use crate::templates::{status_label, CheckoutViewModel, PaymentViewModel, TemplateEngine};

use super::{parse_network, AppState, ApiError, now_unix, resolve_wallet_handle};

/// Resolves a tenant by its public key (not a secret - safe to look up directly
/// from a path parameter) and enforces the origin allowlist independently of
/// whatever CORS header this response also carries, per `docs/DESIGN.md` §12: CORS
/// is a browser-enforced courtesy, not a server-side guarantee, so a script that
/// simply doesn't run in a browser is not stopped by it. When no `Origin` header is
/// present at all (non-browser clients, curl, server-to-server), the request is
/// allowed through - this endpoint has no secret to protect, only a "which sites can
/// call this on a customer's behalf" concern that only applies to browser contexts.
async fn resolve_public_tenant(state: &AppState, pk: &str, origin: Option<&str>) -> Result<Tenant, ApiError> {
    let tenant = state.store.lock().unwrap().find_tenant_by_public_key(pk)?.ok_or(ApiError::NotFound)?;
    if let Some(origin) = origin {
        if !tenant.allowed_origins.iter().any(|o| o == origin) {
            return Err(ApiError::Forbidden("origin not allowed for this tenant".into()));
        }
    }
    Ok(tenant)
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    merchant_order_id: Option<String>,
    fiat_amount: String,
    fiat_currency: String,
    description: Option<String>,
}

#[derive(Serialize)]
pub struct CreateOrderResponse {
    payment_id: String,
    address: String,
    xmr_amount_piconero: u64,
    fiat_amount: String,
    fiat_currency: String,
    expires_at: i64,
}

pub async fn create_order(
    Path(pk): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateOrderRequest>,
) -> Result<Json<CreateOrderResponse>, ApiError> {
    let origin = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok());
    let tenant = resolve_public_tenant(&state, &pk, origin).await?;

    let piconero_per_unit = state
        .exchange_rate
        .piconero_per_unit(&req.fiat_currency)
        .ok_or_else(|| ApiError::BadRequest(format!("unsupported currency: {}", req.fiat_currency)))?;
    let xmr_amount_piconero = compute_xmr_amount(&req.fiat_amount, piconero_per_unit)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let handle = resolve_wallet_handle(&state, &tenant).await?;
    // tenant.network was validated against a configured node at tenant-creation
    // time - a parse failure here means the stored value is corrupt, not that the
    // customer did anything wrong.
    let network = parse_network(&tenant.network)
        .map_err(|e| ApiError::Internal(format!("tenant has an invalid stored network: {e}")))?;

    // Peek at the index, derive its address, then claim the index and insert the
    // order together in one lock hold - never allocate first and insert later.
    // `next_minor_index` is what the scanner reads to decide which subaddresses it
    // scans, so between an eager allocation and the order row's insertion there is a
    // window in which a scanner tick will match a real output against an index no
    // order exists for and silently drop it. Inside a mined block that loss is
    // permanent: blocks are scanned exactly once, and the scanner marks the height
    // scanned whether or not the match was recorded. Deriving the address before
    // claiming keeps the `.await` (which cannot happen under the store lock) outside
    // the atomic part.
    //
    // A losing racer re-derives against the next index; it never burns one, so the
    // loop cannot walk the counter forward on contention. The bound only exists so a
    // pathological hot tenant can't spin here forever.
    let now = now_unix();
    let mut created = None;
    for _ in 0..8 {
        let minor_index = state.store.lock().unwrap().peek_next_minor_index(&tenant.id)?;
        let address = state
            .key_custody
            .derive_subaddress(handle, SubaddressIndex { major: 0, minor: minor_index }, network)
            .await?;
        let order = state.store.lock().unwrap().create_order_claiming_minor_index(
            minor_index,
            NewOrder {
                tenant_id: tenant.id.clone(),
                merchant_order_id: req.merchant_order_id.clone(),
                minor_index,
                address: address.to_string(),
                fiat_currency: req.fiat_currency.clone(),
                fiat_amount: req.fiat_amount.clone(),
                exchange_rate: piconero_per_unit.to_string(),
                xmr_amount_piconero,
                description: req.description.clone(),
                created_at: now,
                expires_at: now + tenant.order_expiry_seconds,
            },
        )?;
        if let Some(order) = order {
            created = Some(order);
            break;
        }
    }
    let order = created.ok_or_else(|| {
        ApiError::Internal("could not claim a subaddress index for this order - too much concurrent contention".into())
    })?;

    Ok(Json(CreateOrderResponse {
        payment_id: order.id,
        address: order.address,
        xmr_amount_piconero: order.xmr_amount_piconero,
        fiat_amount: order.fiat_amount,
        fiat_currency: order.fiat_currency,
        expires_at: order.expires_at,
    }))
}

#[derive(Serialize)]
pub struct OrderStatusResponse {
    payment_id: String,
    status: String,
    address: String,
    confirmations: u64,
    amount_received_piconero: u64,
    xmr_amount_piconero: u64,
    double_spend_detected_at: Option<i64>,
    expires_at: i64,
}

/// Note: only `pk_` and `payment_id` scope this lookup - there is no `sk_` to check
/// here by design, since a payment_id is an unguessable random identifier the
/// customer already holds (from the order-creation response), not a secret this
/// server needs to authenticate. The equivalent IDOR concern for the *admin* surface
/// (see `docs/DESIGN.md` §10.1) doesn't apply the same way here: this route's whole
/// job is to let anyone holding a payment_id check its status.
pub async fn get_order_status(
    Path((pk, payment_id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<OrderStatusResponse>, ApiError> {
    let store = state.store.lock().unwrap();
    let tenant = store.find_tenant_by_public_key(&pk)?.ok_or(ApiError::NotFound)?;
    let order = store.get_order(&tenant.id, &payment_id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(OrderStatusResponse {
        payment_id: order.id,
        status: order.status.as_str().to_string(),
        address: order.address,
        confirmations: order.confirmations,
        amount_received_piconero: order.amount_received_piconero,
        xmr_amount_piconero: order.xmr_amount_piconero,
        double_spend_detected_at: order.double_spend_detected_at,
        expires_at: order.expires_at,
    }))
}

#[derive(Deserialize)]
pub struct SetRefundAddressRequest {
    refund_address: String,
}

pub async fn set_refund_address(
    Path((pk, payment_id)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(req): Json<SetRefundAddressRequest>,
) -> Result<(), ApiError> {
    let store = state.store.lock().unwrap();
    let tenant = store.find_tenant_by_public_key(&pk)?.ok_or(ApiError::NotFound)?;
    let updated = store.set_refund_address(&tenant.id, &payment_id, &req.refund_address)?;
    if updated {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

const CLIENT_LIBRARY_JS: &str = include_str!("../../static/moneropay-client.js");

/// The thin embed library merchant sites `<script src>` (`docs/DESIGN.md` §14).
/// Served from this binary rather than a CDN so a self-hoster's static site has no
/// third-party dependency in its payment path.
pub async fn client_library() -> impl axum::response::IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8")], CLIENT_LIBRARY_JS)
}

fn short_txid(txid: &str) -> String {
    if txid.len() <= 16 {
        return txid.to_string();
    }
    format!("{}…{}", &txid[..8], &txid[txid.len() - 6..])
}

/// Renders the SVG produced by the `qrcode` crate for direct inline embedding: its
/// `<?xml ...?>` prolog is valid standalone SVG but not valid HTML, so an HTML
/// parser turns it into visible/garbled markup rather than a processing
/// instruction. Stripping down to the `<svg ...>` tag itself is what actually
/// embeds cleanly.
fn qr_svg_for_html(data: &str) -> Result<String, ApiError> {
    let full = QrCode::new(data.as_bytes())
        .map_err(|e| ApiError::Internal(format!("failed to encode QR code: {e}")))?
        .render::<svg::Color>()
        .build();
    match full.find("<svg") {
        Some(idx) => Ok(full[idx..].to_string()),
        None => Ok(full),
    }
}

/// The public, unauthenticated checkout page (`docs/DESIGN.md` §14). Like
/// `get_order_status`, `payment_id` alone (not a secret) scopes this lookup - it's
/// the unguessable identifier a customer already holds, not something this route
/// needs to further authenticate.
///
/// A fresh `TemplateEngine` is built per request from the tenant's
/// `template_dir` rather than cached in `AppState`: this keeps a merchant's
/// template edit live immediately (no server restart, matching
/// `templates.rs`'s "no rebuild required" goal) at the cost of re-parsing one
/// small Handlebars template per page view - a fine trade at this project's
/// scale, worth revisiting only if a real hosted instance shows it as a hot path.
pub async fn payment_page(
    Path((pk, payment_id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Html<String>, ApiError> {
    let (order, tenant, valid_payments, current_height) = {
        let store = state.store.lock().unwrap();
        let tenant = store.find_tenant_by_public_key(&pk)?.ok_or(ApiError::NotFound)?;
        let order = store.get_order(&tenant.id, &payment_id)?.ok_or(ApiError::NotFound)?;
        let valid_payments = store.get_valid_payments(&order.id)?;
        let current_height = store.max_scanned_height(&tenant.network)?.unwrap_or(0);
        (order, tenant, valid_payments, current_height)
    };

    let (status_label_text, status_class, is_terminal) = status_label(order.status.as_str());

    let payments = valid_payments
        .into_iter()
        .map(|p| {
            let confirmations = match p.block_height {
                Some(h) if current_height >= h as u64 => current_height - h as u64 + 1,
                _ => 0,
            };
            PaymentViewModel {
                txid_short: short_txid(&p.txid),
                amount_xmr: format_piconero_as_xmr(p.amount_piconero),
                confirmations,
                is_zero_conf: p.block_height.is_none(),
            }
        })
        .collect();

    let qr_code_svg = qr_svg_for_html(&order.address)?;

    let view = CheckoutViewModel {
        payment_id: order.id,
        status: order.status.as_str().to_string(),
        status_label: status_label_text,
        status_class: status_class.to_string(),
        address: order.address,
        qr_code_svg,
        xmr_amount: format_piconero_as_xmr(order.xmr_amount_piconero),
        amount_received_xmr: format_piconero_as_xmr(order.amount_received_piconero),
        fiat_amount: order.fiat_amount,
        fiat_currency: order.fiat_currency,
        confirmations: order.confirmations,
        confirmations_required: tenant.confirmations_required,
        is_terminal,
        double_spend_detected_at: order.double_spend_detected_at,
        expires_at: order.expires_at,
        merchant_order_id: order.merchant_order_id,
        description: order.description,
        payments,
    };

    let engine = TemplateEngine::new(tenant.template_dir.as_deref())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let html = engine.render_checkout(&view).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Html(html))
}
