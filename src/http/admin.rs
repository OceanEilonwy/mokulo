use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use crate::auth::generate_webhook_secret;
use crate::key_custody::{SubaddressIndex, WalletMaterial};
use crate::status::OrderStatus;
use crate::store::{NewTenant, Order, OrderPaymentRow, TenantConfigPatch, Webhook};

use super::{AppState, ApiError, AuthedTenant, network_str, now_unix, parse_network, parse_status_query};

#[derive(Deserialize)]
pub struct CreateTenantRequest {
    view_key_hex: String,
    spend_pubkey_hex: String,
    network: Option<String>,
    allowed_origins: Vec<String>,
    confirmations_required: Option<u64>,
    zero_conf_max_piconero: Option<u64>,
    order_expiry_seconds: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateTenantResponse {
    tenant_id: String,
    public_key: String,
    secret_token: String,
}

pub async fn create_tenant(
    State(state): State<AppState>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<CreateTenantResponse>, ApiError> {
    let material = WalletMaterial::from_hex(&req.view_key_hex, &req.spend_pubkey_hex)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let network = parse_network(req.network.as_deref().unwrap_or("mainnet")).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if !state.configured_networks.contains(&network) {
        return Err(ApiError::BadRequest(format!(
            "no monero_node is configured for network {:?} on this instance",
            network_str(network)
        )));
    }

    validate_tenant_settings(req.confirmations_required, req.order_expiry_seconds)?;

    let handle = state.key_custody.register_wallet(material.clone()).await?;
    let primary_address = state
        .key_custody
        .derive_subaddress(handle, SubaddressIndex::default(), network)
        .await?;
    let sealed = state.key_custody.seal(&material).await?;

    let created = state.store.lock().unwrap().create_tenant(
        NewTenant {
            key_custody_backend: "plain".into(),
            sealed_key_material: sealed,
            primary_address: primary_address.to_string(),
            network: network_str(network).to_string(),
            allowed_origins: req.allowed_origins,
            confirmations_required: req.confirmations_required,
            zero_conf_max_piconero: req.zero_conf_max_piconero,
            order_expiry_seconds: req.order_expiry_seconds,
        },
        now_unix(),
    );
    // A failed insert leaves a registered wallet nothing holds a handle to - key
    // material live in `KeyCustody` for the rest of the process's life, with no
    // tenant row to ever offboard it. Hand it back before returning the error.
    let created = match created {
        Ok(created) => created,
        Err(e) => {
            let _ = state.key_custody.remove_wallet(handle).await;
            return Err(e.into());
        }
    };

    state.wallet_handles.write().unwrap().insert(created.tenant.id.clone(), handle);

    Ok(Json(CreateTenantResponse {
        tenant_id: created.tenant.id,
        public_key: created.tenant.public_key,
        secret_token: created.secret_token,
    }))
}

/// Upper bound on a tenant-chosen order lifetime. Well past anything useful (30
/// days), and far enough below `i64::MAX` that `created_at + order_expiry_seconds`
/// cannot overflow for any wall-clock `created_at` this system will ever see -
/// that overflow panics in a debug build and wraps to a deadline *in the past* in a
/// release one, which would mark every one of that tenant's orders expired on
/// creation.
const MAX_ORDER_EXPIRY_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Upper bound on tenant-chosen confirmations. ~24 hours of blocks; anything beyond
/// this is indistinguishable from "never settles".
const MAX_CONFIRMATIONS_REQUIRED: u64 = 720;

/// Shared by tenant creation and tenant patching, because both write the same two
/// columns and a bound enforced on only one of them is not a bound.
///
/// Neither value is dangerous to *us* - a tenant can only misconfigure their own
/// orders - but both have silent failure modes rather than loud ones, which is what
/// makes them worth rejecting at the edge. `confirmations_required = 0` marks an
/// order `Paid` off a transaction still sitting in the mempool, bypassing the
/// `zero_conf_max_piconero` ceiling that exists precisely to bound that risk;
/// `order_expiry_seconds <= 0` produces orders that are already expired when the
/// customer first loads the payment page.
fn validate_tenant_settings(
    confirmations_required: Option<u64>,
    order_expiry_seconds: Option<i64>,
) -> Result<(), ApiError> {
    if let Some(confirmations) = confirmations_required {
        if confirmations == 0 || confirmations > MAX_CONFIRMATIONS_REQUIRED {
            return Err(ApiError::BadRequest(format!(
                "confirmations_required must be between 1 and {MAX_CONFIRMATIONS_REQUIRED}; 0 would treat an unconfirmed transaction as final"
            )));
        }
    }
    if let Some(seconds) = order_expiry_seconds {
        if seconds <= 0 || seconds > MAX_ORDER_EXPIRY_SECONDS {
            return Err(ApiError::BadRequest(format!(
                "order_expiry_seconds must be between 1 and {MAX_ORDER_EXPIRY_SECONDS}; a non-positive value expires every order on creation"
            )));
        }
    }
    Ok(())
}

#[derive(Serialize)]
pub struct TenantView {
    tenant_id: String,
    public_key: String,
    primary_address: String,
    network: String,
    confirmations_required: u64,
    zero_conf_max_piconero: Option<u64>,
    order_expiry_seconds: i64,
    allowed_origins: Vec<String>,
}

impl From<crate::store::Tenant> for TenantView {
    fn from(t: crate::store::Tenant) -> Self {
        TenantView {
            tenant_id: t.id,
            public_key: t.public_key,
            primary_address: t.primary_address,
            network: t.network,
            confirmations_required: t.confirmations_required,
            zero_conf_max_piconero: t.zero_conf_max_piconero,
            order_expiry_seconds: t.order_expiry_seconds,
            allowed_origins: t.allowed_origins,
        }
    }
}

pub async fn get_own_tenant(AuthedTenant(tenant): AuthedTenant) -> Json<TenantView> {
    Json(TenantView::from(tenant))
}

#[derive(Deserialize, Default)]
pub struct PatchTenantRequest {
    allowed_origins: Option<Vec<String>>,
    confirmations_required: Option<u64>,
    zero_conf_max_piconero: Option<u64>,
    order_expiry_seconds: Option<i64>,
}

pub async fn patch_own_tenant(
    AuthedTenant(tenant): AuthedTenant,
    State(state): State<AppState>,
    Json(req): Json<PatchTenantRequest>,
) -> Result<Json<TenantView>, ApiError> {
    validate_tenant_settings(req.confirmations_required, req.order_expiry_seconds)?;
    let patch = TenantConfigPatch {
        allowed_origins: req.allowed_origins,
        confirmations_required: req.confirmations_required,
        zero_conf_max_piconero_set: req.zero_conf_max_piconero.is_some(),
        zero_conf_max_piconero: req.zero_conf_max_piconero,
        order_expiry_seconds: req.order_expiry_seconds,
        template_dir_set: false,
        template_dir: None,
    };
    let store = state.store.lock().unwrap();
    store.update_tenant_config(&tenant.id, patch)?;
    let refetched = store.get_tenant_by_id(&tenant.id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(TenantView::from(refetched)))
}

#[derive(Serialize)]
pub struct RotateSecretResponse {
    secret_token: String,
}

pub async fn rotate_secret(
    AuthedTenant(tenant): AuthedTenant,
    State(state): State<AppState>,
) -> Result<Json<RotateSecretResponse>, ApiError> {
    let new_secret = state.store.lock().unwrap().rotate_tenant_secret(&tenant.id)?;
    Ok(Json(RotateSecretResponse { secret_token: new_secret }))
}

pub async fn delete_own_tenant(
    AuthedTenant(tenant): AuthedTenant,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let removed_handle = state.wallet_handles.write().unwrap().remove(&tenant.id);
    if let Some(handle) = removed_handle {
        // Best-effort: an already-unknown handle is not an error worth surfacing here.
        let _ = state.key_custody.remove_wallet(handle).await;
    }
    state.store.lock().unwrap().disable_tenant(&tenant.id, now_unix())?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct OrderView {
    payment_id: String,
    merchant_order_id: Option<String>,
    address: String,
    fiat_currency: String,
    fiat_amount: String,
    xmr_amount_piconero: u64,
    amount_received_piconero: u64,
    status: String,
    confirmations: u64,
    double_spend_detected_at: Option<i64>,
    refund_address: Option<String>,
    created_at: i64,
    expires_at: i64,
    updated_at: i64,
}

impl From<Order> for OrderView {
    fn from(o: Order) -> Self {
        OrderView {
            payment_id: o.id,
            merchant_order_id: o.merchant_order_id,
            address: o.address,
            fiat_currency: o.fiat_currency,
            fiat_amount: o.fiat_amount,
            xmr_amount_piconero: o.xmr_amount_piconero,
            amount_received_piconero: o.amount_received_piconero,
            status: o.status.as_str().to_string(),
            confirmations: o.confirmations,
            double_spend_detected_at: o.double_spend_detected_at,
            refund_address: o.refund_address,
            created_at: o.created_at,
            expires_at: o.expires_at,
            updated_at: o.updated_at,
        }
    }
}

#[derive(Deserialize)]
pub struct ListOrdersQuery {
    status: Option<String>,
    cursor: Option<i64>,
    limit: Option<u32>,
}

pub async fn list_orders(
    AuthedTenant(tenant): AuthedTenant,
    State(state): State<AppState>,
    Query(q): Query<ListOrdersQuery>,
) -> Result<Json<Vec<OrderView>>, ApiError> {
    let status_filter: Option<OrderStatus> = q.status.as_deref().map(parse_status_query).transpose()?;
    let limit = q.limit.unwrap_or(50).min(200);
    let orders = state.store.lock().unwrap().list_orders(&tenant.id, status_filter, limit, q.cursor)?;
    Ok(Json(orders.into_iter().map(OrderView::from).collect()))
}

#[derive(Serialize)]
pub struct PaymentView {
    txid: String,
    output_index: i64,
    amount_piconero: u64,
    first_seen_at: i64,
    block_height: Option<i64>,
    voided_at: Option<i64>,
}

impl From<OrderPaymentRow> for PaymentView {
    fn from(p: OrderPaymentRow) -> Self {
        PaymentView {
            txid: p.txid,
            output_index: p.output_index,
            amount_piconero: p.amount_piconero,
            first_seen_at: p.first_seen_at,
            block_height: p.block_height,
            voided_at: p.voided_at,
        }
    }
}

#[derive(Serialize)]
pub struct OrderDetailResponse {
    #[serde(flatten)]
    order: OrderView,
    payments: Vec<PaymentView>,
}

pub async fn get_order_detail(
    AuthedTenant(tenant): AuthedTenant,
    Path(payment_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<OrderDetailResponse>, ApiError> {
    let store = state.store.lock().unwrap();
    let order = store.get_order(&tenant.id, &payment_id)?.ok_or(ApiError::NotFound)?;
    let payments = store.get_all_payments(&order.id)?;
    Ok(Json(OrderDetailResponse {
        order: OrderView::from(order),
        payments: payments.into_iter().map(PaymentView::from).collect(),
    }))
}

#[derive(Deserialize)]
pub struct CreateWebhookRequest {
    url: String,
    extra_headers: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct CreateWebhookResponse {
    webhook_id: String,
    signing_secret: String,
}

pub async fn create_webhook(
    AuthedTenant(tenant): AuthedTenant,
    State(state): State<AppState>,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<Json<CreateWebhookResponse>, ApiError> {
    let parsed = url::Url::parse(&req.url).map_err(|e| ApiError::BadRequest(format!("invalid url: {e}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ApiError::BadRequest("only http/https URLs are allowed".into()));
    }
    // Resolved-IP SSRF validation (see webhook_sign::validate_webhook_url) happens
    // at delivery time in the not-yet-built delivery worker, not here - DNS can
    // change between registration and delivery, so a registration-time-only check
    // would be insufficient on its own regardless.
    let secret = generate_webhook_secret();
    let extra_headers_json = req.extra_headers.map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string());
    let webhook = state
        .store
        .lock()
        .unwrap()
        .create_webhook(&tenant.id, &req.url, &extra_headers_json, &secret, now_unix())?;
    Ok(Json(CreateWebhookResponse { webhook_id: webhook.id, signing_secret: secret }))
}

#[derive(Serialize)]
pub struct WebhookView {
    webhook_id: String,
    url: String,
    enabled: bool,
    created_at: i64,
}

impl From<Webhook> for WebhookView {
    fn from(w: Webhook) -> Self {
        WebhookView { webhook_id: w.id, url: w.url, enabled: w.enabled, created_at: w.created_at }
    }
}

pub async fn list_webhooks(
    AuthedTenant(tenant): AuthedTenant,
    State(state): State<AppState>,
) -> Result<Json<Vec<WebhookView>>, ApiError> {
    let webhooks = state.store.lock().unwrap().list_webhooks(&tenant.id)?;
    Ok(Json(webhooks.into_iter().map(WebhookView::from).collect()))
}

pub async fn delete_webhook(
    AuthedTenant(tenant): AuthedTenant,
    Path(webhook_id): Path<String>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let deleted = state.store.lock().unwrap().delete_webhook(&tenant.id, &webhook_id)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

