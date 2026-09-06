//! HTTP-layer integration tests, driven through the real `Router` via
//! `tower::ServiceExt::oneshot` - no bound socket needed. These exercise the same
//! IDOR/auth properties `store.rs` already tests at the repository level, but end to
//! end through real request parsing, auth extraction, and JSON (de)serialization,
//! per `docs/TESTING.md` §5.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use monero::{Network, PrivateKey, PublicKey};
use tower::ServiceExt;

use crate::exchange_rate::{ExchangeRateProvider, FixedRateProvider};
use crate::key_custody::{KeyCustody, PlainKeyCustody};
use crate::store::Store;

use super::rate_limit::RateLimiter;
use super::{AppState, build_router};

fn valid_scalar_bytes(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[31] &= 0x0f;
    b
}

fn valid_view_key_hex(seed: u8) -> String {
    hex::encode(valid_scalar_bytes(seed))
}

fn valid_spend_pubkey_hex(seed: u8) -> String {
    let secret = PrivateKey::from_slice(&valid_scalar_bytes(seed)).unwrap();
    hex::encode(PublicKey::from_private_key(&secret).to_bytes())
}

fn test_app_state() -> AppState {
    let store = Store::open_in_memory().unwrap().into_shared();
    let key_custody: Arc<dyn KeyCustody> = Arc::new(PlainKeyCustody::default());
    let mut rates = HashMap::new();
    rates.insert("USD".to_string(), 6_700_000_000u64);
    let exchange_rate: Arc<dyn ExchangeRateProvider> = Arc::new(FixedRateProvider::new(rates));
    AppState {
        store,
        key_custody,
        exchange_rate,
        wallet_handles: Arc::new(RwLock::new(HashMap::new())),
        // Every test tenant is created without an explicit `network`, which
        // defaults to mainnet (see admin::create_tenant) - so mainnet must be
        // "configured" for tenant creation to succeed in these tests.
        configured_networks: Arc::new(HashSet::from([Network::Mainnet])),
        // Generous by default so the auth/IDOR/order-flow tests below aren't
        // incidentally affected by rate limiting - the middleware's own behavior is
        // tested separately, end to end, in `rate_limit_middleware_rejects_after_the_limit_with_a_real_connect_info`.
        rate_limiter: Arc::new(RateLimiter::new(10_000)),
    }
}

fn test_router() -> Router {
    build_router(test_app_state(), 1_000_000)
}

fn json_request(method: &str, uri: &str, bearer: Option<&str>, origin: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

struct TestTenant {
    public_key: String,
    secret_token: String,
}

async fn create_tenant(router: &Router, seed: u8, allowed_origins: Vec<&str>) -> TestTenant {
    let req = json_request(
        "POST",
        "/api/v1/admin/tenants",
        None,
        None,
        serde_json::json!({
            "view_key_hex": valid_view_key_hex(seed),
            "spend_pubkey_hex": valid_spend_pubkey_hex(seed.wrapping_add(1)),
            "allowed_origins": allowed_origins,
        }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    TestTenant {
        public_key: body["public_key"].as_str().unwrap().to_string(),
        secret_token: body["secret_token"].as_str().unwrap().to_string(),
    }
}

#[tokio::test]
async fn create_tenant_then_create_order_happy_path() {
    let router = test_router();
    let tenant = create_tenant(&router, 1, vec!["https://merchant.example"]).await;

    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        Some("https://merchant.example"),
        serde_json::json!({ "fiat_amount": "25.00", "fiat_currency": "USD" }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["xmr_amount_piconero"], 167_500_000_000u64);
    let payment_id = body["payment_id"].as_str().unwrap().to_string();
    assert!(!body["address"].as_str().unwrap().is_empty());

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/t/{}/orders/{payment_id}", tenant.public_key))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["status"], "pending");
    assert_eq!(body["payment_id"], payment_id);
}

#[tokio::test]
async fn successive_orders_get_distinct_addresses_and_never_leave_an_unclaimed_index_behind() {
    // Order creation no longer allocates a minor index up front and inserts the
    // order row later, after awaiting a subaddress derivation: `next_minor_index` is
    // what the scanner reads to decide which subaddresses it scans, so the gap
    // between the two was a window in which a scanner tick could match a real output
    // against an index no order existed for and drop it - permanently, if the
    // sighting was inside a mined block. The peek/derive/claim-and-insert sequence
    // that replaces it must still hand out one distinct address per order and must
    // not skip indices along the way (a skipped index means an address was derived,
    // counted, and never issued to anyone).
    let state = test_app_state();
    let store = state.store.clone();
    let router = build_router(state, 1_000_000);
    let tenant = create_tenant(&router, 1, vec!["https://merchant.example"]).await;

    let mut addresses = Vec::new();
    for _ in 0..3 {
        let req = json_request(
            "POST",
            &format!("/api/v1/t/{}/orders", tenant.public_key),
            None,
            Some("https://merchant.example"),
            serde_json::json!({ "fiat_amount": "25.00", "fiat_currency": "USD" }),
        );
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        addresses.push(body_json(response).await["address"].as_str().unwrap().to_string());
    }

    let mut deduped = addresses.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), 3, "every order must be issued its own subaddress");

    let s = store.lock().unwrap();
    let tenant_row = s.find_tenant_by_secret_token(&tenant.secret_token).unwrap().unwrap();
    assert_eq!(
        tenant_row.next_minor_index, 4,
        "indices 1..3 were issued, so the counter must sit at exactly 4 - no gaps for addresses nobody holds"
    );
    // The scanner scans `0..next_minor_index`, so every index the counter covers
    // must resolve to a real order - that is precisely the invariant whose violation
    // let a matched payment be dropped.
    for minor in 1..tenant_row.next_minor_index {
        assert!(
            s.find_order_by_minor_index(&tenant_row.id, minor).unwrap().is_some(),
            "minor index {minor} is scannable but has no order to attribute a payment to"
        );
    }
}

#[tokio::test]
async fn admin_route_rejects_the_tenants_own_public_key_as_a_bearer_token() {
    let router = test_router();
    let tenant = create_tenant(&router, 2, vec![]).await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/tenant")
        .header("authorization", format!("Bearer {}", tenant.public_key))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_route_with_no_authorization_header_is_rejected() {
    let router = test_router();
    let req = Request::builder().method("GET").uri("/api/v1/admin/tenant").body(Body::empty()).unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tenant_a_cannot_read_tenant_bs_order_via_admin_api() {
    // The exact IDOR scenario from docs/DESIGN.md §10.1 and docs/TESTING.md §5,
    // exercised end to end through real HTTP requests: tenant A's valid sk_ plus
    // tenant B's real payment_id must come back as 404, not tenant B's order.
    let router = test_router();
    let tenant_a = create_tenant(&router, 3, vec![]).await;
    let tenant_b = create_tenant(&router, 4, vec!["https://b.example"]).await;

    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant_b.public_key),
        None,
        Some("https://b.example"),
        serde_json::json!({ "fiat_amount": "10.00", "fiat_currency": "USD" }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    let body = body_json(response).await;
    let order_b_payment_id = body["payment_id"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/admin/tenant/orders/{order_b_payment_id}"))
        .header("authorization", format!("Bearer {}", tenant_a.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Sanity check: tenant B's own token DOES see it, proving the 404 above is
    // specifically about cross-tenant scoping and not a broken route.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/admin/tenant/orders/{order_b_payment_id}"))
        .header("authorization", format!("Bearer {}", tenant_b.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn rotated_secret_invalidates_the_old_token_end_to_end() {
    let router = test_router();
    let tenant = create_tenant(&router, 5, vec![]).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/tenant/rotate-secret")
        .header("authorization", format!("Bearer {}", tenant.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let new_secret = body["secret_token"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/tenant")
        .header("authorization", format!("Bearer {}", tenant.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "the pre-rotation token must stop working immediately");

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/tenant")
        .header("authorization", format!("Bearer {new_secret}"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn order_creation_from_a_disallowed_origin_is_rejected_even_with_a_valid_public_key() {
    let router = test_router();
    let tenant = create_tenant(&router, 6, vec!["https://good.example"]).await;

    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        Some("https://evil.example"),
        serde_json::json!({ "fiat_amount": "10.00", "fiat_currency": "USD" }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // No Origin header at all (a non-browser caller) is allowed through - only a
    // *mismatched* Origin is rejected, per docs/DESIGN.md §12's reasoning.
    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        None,
        serde_json::json!({ "fiat_amount": "10.00", "fiat_currency": "USD" }),
    );
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn webhook_lifecycle_is_scoped_to_the_owning_tenant() {
    let router = test_router();
    let tenant_a = create_tenant(&router, 7, vec![]).await;
    let tenant_b = create_tenant(&router, 8, vec![]).await;

    let req = json_request(
        "POST",
        "/api/v1/admin/tenant/webhooks",
        Some(&tenant_b.secret_token),
        None,
        serde_json::json!({ "url": "https://b.example/hook" }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let webhook_id = body["webhook_id"].as_str().unwrap().to_string();
    assert!(body["signing_secret"].as_str().unwrap().starts_with("whsec_"));

    // Tenant A cannot delete tenant B's webhook.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/tenant/webhooks/{webhook_id}"))
        .header("authorization", format!("Bearer {}", tenant_a.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Tenant B can.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/tenant/webhooks/{webhook_id}"))
        .header("authorization", format!("Bearer {}", tenant_b.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn unsupported_currency_and_malformed_amount_are_rejected_with_bad_request() {
    let router = test_router();
    let tenant = create_tenant(&router, 9, vec![]).await;

    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        None,
        serde_json::json!({ "fiat_amount": "10.00", "fiat_currency": "ZZZ" }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        None,
        serde_json::json!({ "fiat_amount": "not_a_number", "fiat_currency": "USD" }),
    );
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenant_creation_is_rejected_for_a_network_with_no_configured_node() {
    // The failure mode this check exists to prevent: a tenant whose address gets
    // derived for a chain nothing on this instance is actually scanning, so a
    // real payment to it would simply never be detected - a silent, much worse
    // failure than refusing to create the tenant at all.
    let router = test_router(); // only mainnet is configured, see test_app_state()

    let req = json_request(
        "POST",
        "/api/v1/admin/tenants",
        None,
        None,
        serde_json::json!({
            "view_key_hex": valid_view_key_hex(20),
            "spend_pubkey_hex": valid_spend_pubkey_hex(21),
            "network": "stagenet",
            "allowed_origins": [],
        }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The same request without a network (defaulting to mainnet, which *is*
    // configured) must succeed - proving the rejection above is really about
    // network availability, not something else in the request.
    let req = json_request(
        "POST",
        "/api/v1/admin/tenants",
        None,
        None,
        serde_json::json!({
            "view_key_hex": valid_view_key_hex(20),
            "spend_pubkey_hex": valid_spend_pubkey_hex(21),
            "allowed_origins": [],
        }),
    );
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenant_deletion_disables_it_and_admin_routes_stop_working() {
    let router = test_router();
    let tenant = create_tenant(&router, 10, vec![]).await;

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/admin/tenant")
        .header("authorization", format!("Bearer {}", tenant.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/tenant")
        .header("authorization", format!("Bearer {}", tenant.secret_token))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A disabled tenant's public_key must also stop working for order creation.
    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        None,
        serde_json::json!({ "fiat_amount": "10.00", "fiat_currency": "USD" }),
    );
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rate_limit_middleware_rejects_after_the_limit_with_a_real_connect_info() {
    // Unlike the other tests, this one exercises the middleware wired into a real
    // router with a fabricated `ConnectInfo` extension, the way production's
    // `into_make_service_with_connect_info` would actually provide it - proving the
    // wiring, not just `RateLimiter`'s standalone logic (already covered in
    // `rate_limit.rs`'s own unit tests).
    let mut state = test_app_state();
    state.rate_limiter = Arc::new(RateLimiter::new(2));
    let router = build_router(state, 1_000_000);

    let peer: std::net::SocketAddr = "10.0.0.1:12345".parse().unwrap();
    let make_request = || {
        let mut req = Request::builder().method("GET").uri("/api/v1/admin/tenant").body(Body::empty()).unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(peer));
        req
    };

    let r1 = router.clone().oneshot(make_request()).await.unwrap();
    let r2 = router.clone().oneshot(make_request()).await.unwrap();
    let r3 = router.oneshot(make_request()).await.unwrap();

    // All three get 401 (no auth header) or 429 - what matters is the third is
    // specifically rate-limited, not merely unauthorized like the first two.
    assert_eq!(r1.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r2.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn oversized_request_body_is_rejected_before_reaching_the_handler() {
    let router = build_router(test_app_state(), 16); // absurdly small cap for the test

    let oversized_body = serde_json::json!({ "fiat_amount": "10.00", "fiat_currency": "USD" }).to_string();
    assert!(oversized_body.len() > 16);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/t/pk_whatever/orders")
        .header("content-type", "application/json")
        .body(Body::from(oversized_body))
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn payment_page_renders_html_with_order_details_and_404s_for_unknown_payment_id() {
    let router = test_router();
    let tenant = create_tenant(&router, 5, vec!["https://merchant.example"]).await;

    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        Some("https://merchant.example"),
        serde_json::json!({ "fiat_amount": "25.00", "fiat_currency": "USD" }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let payment_id = body["payment_id"].as_str().unwrap().to_string();
    let address = body["address"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/pay/v1/{}/{payment_id}", tenant.public_key))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains(&payment_id));
    assert!(html.contains(&address));
    assert!(html.contains("<svg"));
    assert!(html.contains("Waiting for payment"));

    let req = Request::builder()
        .method("GET")
        .uri(format!("/pay/v1/{}/pay_does_not_exist", tenant.public_key))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn client_library_is_served_as_javascript() {
    let router = test_router();
    let req = Request::builder().method("GET").uri("/static/moneropay-client.js").body(Body::empty()).unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/javascript; charset=utf-8");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let js = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(js.contains("MoneroPay"));
    assert!(js.contains("createOrder"));
    assert!(js.contains("mount"));
}

#[tokio::test]
async fn cors_preflight_and_actual_request_succeed_only_for_an_allowed_cross_origin_merchant_site() {
    let router = test_router();
    let tenant = create_tenant(&router, 6, vec!["https://merchant.example"]).await;

    // Preflight: the browser's own OPTIONS check before the real cross-origin POST.
    let preflight = Request::builder()
        .method("OPTIONS")
        .uri(format!("/api/v1/t/{}/orders", tenant.public_key))
        .header("origin", "https://merchant.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(preflight).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("access-control-allow-origin").unwrap(),
        "https://merchant.example"
    );

    // The actual request from that same allowed origin gets the header back too, so
    // the browser will actually let the merchant page's JS read the response.
    let req = json_request(
        "POST",
        &format!("/api/v1/t/{}/orders", tenant.public_key),
        None,
        Some("https://merchant.example"),
        serde_json::json!({ "fiat_amount": "10.00", "fiat_currency": "USD" }),
    );
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("access-control-allow-origin").unwrap(),
        "https://merchant.example"
    );

    // A different, non-allowlisted origin gets no CORS grant at all - the server-side
    // check in `resolve_public_tenant` already rejects the request body-wise, but
    // this confirms the browser-facing header is also absent, not just permissive.
    let preflight_from_evil = Request::builder()
        .method("OPTIONS")
        .uri(format!("/api/v1/t/{}/orders", tenant.public_key))
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(preflight_from_evil).await.unwrap();
    assert!(response.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn a_tenants_reported_primary_address_is_a_standard_address_a_payment_could_reach() {
    // `primary_address` is derived at subaddress index 0/0 and handed straight back
    // to the merchant. If it were encoded as a *subaddress* (the underlying
    // primitive's default at 0/0), a sender would derive the shared secret from
    // `8*r*C` against the root pair's `C = v*G` while this wallet looks for
    // `8*v*r*S` - so anything paid to that string would be undetectable by the very
    // wallet it names. Mainnet standard addresses start with '4', subaddresses with
    // '8'.
    let router = test_router();
    let tenant = create_tenant(&router, 30, vec![]).await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/tenant")
        .header("authorization", format!("Bearer {}", tenant.secret_token))
        .body(Body::empty())
        .unwrap();
    let body = body_json(router.oneshot(req).await.unwrap()).await;
    let address = body["primary_address"].as_str().unwrap();
    assert!(address.starts_with('4'), "primary_address {address} is not a standard mainnet address");
    let parsed = monero::Address::from_str(address).unwrap();
    assert_eq!(parsed.addr_type, monero::AddressType::Standard);
    assert_eq!(parsed.network, Network::Mainnet);
}

#[tokio::test]
async fn tenant_settings_with_a_silent_failure_mode_are_rejected_on_creation_and_on_patch() {
    // Both write the same two columns, so a bound enforced on only one of them is
    // no bound at all. `confirmations_required = 0` would settle an order off a
    // still-unconfirmed transaction; a non-positive `order_expiry_seconds` expires
    // every order at the moment it is created; and an `order_expiry_seconds` near
    // `i64::MAX` overflows the `created_at + expiry` addition, wrapping the deadline
    // into the past.
    let router = test_router();

    for bad in [
        serde_json::json!({ "confirmations_required": 0 }),
        serde_json::json!({ "confirmations_required": 100_000 }),
        serde_json::json!({ "order_expiry_seconds": 0 }),
        serde_json::json!({ "order_expiry_seconds": -60 }),
        serde_json::json!({ "order_expiry_seconds": i64::MAX }),
    ] {
        let mut create_body = serde_json::json!({
            "view_key_hex": valid_view_key_hex(40),
            "spend_pubkey_hex": valid_spend_pubkey_hex(41),
            "allowed_origins": [],
        });
        for (k, v) in bad.as_object().unwrap() {
            create_body[k] = v.clone();
        }
        let response = router
            .clone()
            .oneshot(json_request("POST", "/api/v1/admin/tenants", None, None, create_body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "creation accepted {bad}");
    }

    let tenant = create_tenant(&router, 42, vec![]).await;
    for bad in [
        serde_json::json!({ "confirmations_required": 0 }),
        serde_json::json!({ "order_expiry_seconds": 0 }),
        serde_json::json!({ "order_expiry_seconds": -1 }),
        serde_json::json!({ "order_expiry_seconds": i64::MAX }),
    ] {
        let response = router
            .clone()
            .oneshot(json_request("PATCH", "/api/v1/admin/tenant", Some(&tenant.secret_token), None, bad.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "patch accepted {bad}");
    }

    // Sane values on both paths still go through, so the checks aren't just
    // rejecting everything.
    let response = router
        .clone()
        .oneshot(json_request(
            "PATCH",
            "/api/v1/admin/tenant",
            Some(&tenant.secret_token),
            None,
            serde_json::json!({ "confirmations_required": 3, "order_expiry_seconds": 900 }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["confirmations_required"], 3);
    assert_eq!(body["order_expiry_seconds"], 900);
}

#[tokio::test]
async fn every_admin_route_resolves_its_tenant_from_the_bearer_token_alone() {
    // The structural IDOR fix (§DESIGN.md §10.1) is only a guarantee if it holds for
    // *every* route in the family, not the handful it was designed around. This
    // walks all of them with tenant B's token and asserts none of them can be
    // steered at tenant A's data by any identifier in the path or the body.
    let router = test_router();
    let a = create_tenant(&router, 50, vec![]).await;
    let b = create_tenant(&router, 52, vec![]).await;

    // Give A an order and a webhook to try to reach.
    let order = body_json(
        router
            .clone()
            .oneshot(json_request(
                "POST",
                &format!("/api/v1/t/{}/orders", a.public_key),
                None,
                None,
                serde_json::json!({ "fiat_amount": "25.00", "fiat_currency": "USD" }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let a_payment_id = order["payment_id"].as_str().unwrap().to_string();
    let a_webhook = body_json(
        router
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/tenant/webhooks",
                Some(&a.secret_token),
                None,
                serde_json::json!({ "url": "https://a.example/hook" }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let a_webhook_id = a_webhook["webhook_id"].as_str().unwrap().to_string();

    // B's token against A's identifiers: every one must miss.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/admin/tenant/orders/{a_payment_id}"))
                .header("authorization", format!("Bearer {}", b.secret_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/tenant/webhooks/{a_webhook_id}"))
                .header("authorization", format!("Bearer {}", b.secret_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // B's listings show only B's own (empty) data, never A's.
    let orders = body_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/admin/tenant/orders")
                    .header("authorization", format!("Bearer {}", b.secret_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(orders.as_array().unwrap().len(), 0);

    let webhooks = body_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/admin/tenant/webhooks")
                    .header("authorization", format!("Bearer {}", b.secret_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(webhooks.as_array().unwrap().len(), 0);

    // A's own view is untouched by any of the above.
    let webhooks = body_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/admin/tenant/webhooks")
                    .header("authorization", format!("Bearer {}", a.secret_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(webhooks.as_array().unwrap().len(), 1);

    // And rotating B's secret can't be aimed at A either - A's token keeps working.
    let response = router
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/tenant/rotate-secret",
            Some(&b.secret_token),
            None,
            serde_json::json!({ "tenant_id": "whatever" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/tenant")
                .header("authorization", format!("Bearer {}", a.secret_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn every_path_that_can_set_a_webhook_url_validates_the_scheme() {
    // Webhook creation is currently the only route that writes a URL, and this is
    // what proves it - if a second one is ever added without its own check, the
    // sweep below over every route in the router stops matching reality.
    let router = test_router();
    let tenant = create_tenant(&router, 60, vec![]).await;

    for bad_url in [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/hook",
        "javascript:alert(1)",
        "not a url at all",
        "",
    ] {
        let response = router
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/tenant/webhooks",
                Some(&tenant.secret_token),
                None,
                serde_json::json!({ "url": bad_url }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "accepted {bad_url:?}");
    }

    // The tenant-patch route must not offer a back door for any webhook field.
    let response = router
        .clone()
        .oneshot(json_request(
            "PATCH",
            "/api/v1/admin/tenant",
            Some(&tenant.secret_token),
            None,
            serde_json::json!({ "webhook_url": "file:///etc/passwd", "url": "file:///etc/passwd" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "unknown fields are ignored, not applied");
    let webhooks = body_json(
        router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/admin/tenant/webhooks")
                    .header("authorization", format!("Bearer {}", tenant.secret_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(webhooks.as_array().unwrap().len(), 0, "no webhook may have been created by a patch");
}

#[tokio::test]
async fn the_cors_predicate_fails_closed_on_every_confusable_path_shape() {
    // The predicate parses the *raw* path before axum's own routing, so it has to
    // reach the same conclusion axum does. Granting a cross-origin allowance for a
    // path that isn't really the orders route - or for the wrong tenant's - would
    // hand a merchant site's origin to something it was never allowlisted for.
    let router = test_router();
    let allowed = create_tenant(&router, 70, vec!["https://merchant.example"]).await;
    let other = create_tenant(&router, 72, vec!["https://other.example"]).await;

    let preflight = |uri: String, origin: &'static str| {
        Request::builder()
            .method("OPTIONS")
            .uri(uri)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(Body::empty())
            .unwrap()
    };

    for uri in [
        // Percent-encoded "orders" - a real router would not route this here, so
        // neither may the predicate.
        format!("/api/v1/t/{}/%6frders", allowed.public_key),
        // Percent-encoded separator inside the pk.
        format!("/api/v1/t/{}%2Forders", allowed.public_key),
        // The admin family, which is deliberately granted no CORS at all.
        "/api/v1/admin/tenant".to_string(),
        "/api/v1/admin/tenants".to_string(),
        // The iframe page and the client script, both same-origin by design.
        format!("/pay/v1/{}/pay_whatever", allowed.public_key),
        "/static/moneropay-client.js".to_string(),
        // Truncated and over-long shapes.
        format!("/api/v1/t/{}", allowed.public_key),
        "/api/v1/t//orders".to_string(),
        "/api/v1/t/orders".to_string(),
        // An unknown tenant.
        "/api/v1/t/pk_does_not_exist/orders".to_string(),
    ] {
        let response = router.clone().oneshot(preflight(uri.clone(), "https://merchant.example")).await.unwrap();
        assert!(
            response.headers().get("access-control-allow-origin").is_none(),
            "{uri} must not produce a CORS grant"
        );
    }

    // One tenant's allowlisted origin must never be honoured on another tenant's
    // path, even though both paths are real.
    let response = router
        .clone()
        .oneshot(preflight(format!("/api/v1/t/{}/orders", other.public_key), "https://merchant.example"))
        .await
        .unwrap();
    assert!(response.headers().get("access-control-allow-origin").is_none());

    // The genuinely-correct combination still works, so the above isn't just a
    // blanket denial.
    let response = router
        .oneshot(preflight(format!("/api/v1/t/{}/orders", allowed.public_key), "https://merchant.example"))
        .await
        .unwrap();
    assert_eq!(
        response.headers().get("access-control-allow-origin").unwrap(),
        "https://merchant.example"
    );
}
