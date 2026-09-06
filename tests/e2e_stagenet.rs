//! Real end-to-end test: creates an order through the actual `moneropay_core`
//! library (config -> store -> key custody -> scanner -> router - the same pieces
//! `main.rs` wires together, just driven directly instead of over a bound TCP
//! socket), pays it with a genuine tiny transaction constructed, signed, and
//! broadcast entirely in Rust (see `tests/support/mod.rs`) from a real,
//! faucet-funded Monero **stagenet** wallet, and asserts the real chain scanner
//! detects it.
//!
//! The only external dependency this test has is the public stagenet node itself
//! (`e2e/moneropay-stagenet.toml`'s `[monero_node.stagenet]`) - no wallet-rpc or
//! any other external process. Sending the payment is done by
//! `support::StagenetSpendWallet`, built on the `monero-wallet` crate.
//!
//! Follows the same pattern as `daemon_rpc::live_node_tests`: excluded from the
//! default `cargo test` run via `#[ignore]` (it needs live network access, so it
//! can't be hermetic), run explicitly with:
//!
//! ```sh
//! cargo test --test e2e_stagenet -- --ignored --nocapture
//! ```
//!
//! Run from the repository root - `Config::from_file` and `stagenet-wallets.json`
//! below are both read relative to `cargo test`'s working directory (the package
//! root). See `e2e/README.md` for the full picture.

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use monero::Network;
use serde_json::{json, Value};
use tower::ServiceExt;

use moneropay_core::config::Config;
use moneropay_core::daemon::MoneroDaemonClient;
use moneropay_core::daemon_rpc::RpcDaemonClient;
use moneropay_core::exchange_rate::{parse_xmr_to_piconero, ExchangeRateProvider};
use moneropay_core::http::rate_limit::RateLimiter;
use moneropay_core::http::{build_router, now_unix, AppState};
use moneropay_core::key_custody::{KeyCustody, PlainKeyCustody, WalletMaterial};
use moneropay_core::network::network_str;
use moneropay_core::scanner::run_scan_tick;
use moneropay_core::store::{NewTenant, Store};

use support::StagenetSpendWallet;

const CONFIG_PATH: &str = "e2e/moneropay-stagenet.toml";
const WALLETS_PATH: &str = "e2e/stagenet-wallets.json";

/// Confirms the configured stagenet node is actually reachable before doing
/// anything else with it - a misconfigured host/port, or a node that's temporarily
/// down, would otherwise only surface deep inside the scan-and-poll loop as an
/// opaque `DaemonError` after the payment has already been sent.
async fn require_daemon_reachable(daemon: &dyn MoneroDaemonClient, host: &str, port: u16) {
    if let Err(e) = daemon.get_height().await {
        panic!(
            "\n\ncannot reach the stagenet node at {host}:{port} (configured in {CONFIG_PATH}'s \
             [monero_node.stagenet]): {e}\n\
             Check that host/port, your network connection, or try a different public stagenet \
             node (search \"monero stagenet public node\" for alternatives).\n"
        );
    }
}

async fn oneshot_json(router: &axum::Router, method: &str, uri: String, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let response = router.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("response body was not JSON: {e}"));
    (status, json)
}

/// Appends `tx_hash` to `customer.known_txids` in `e2e/stagenet-wallets.json` and
/// writes the file back, so a future run automatically finds this run's change
/// output once it's confirmed and unlocked - see the comment on `known_txids` in
/// that file, and `support::StagenetSpendWallet::spendable_now`.
///
/// Re-reads the file fresh (rather than reusing the copy read minutes earlier at
/// the top of the test) and writes via a temp-file-plus-rename rather than a
/// direct truncating write, so two overlapping runs can't clobber each other's
/// appended txid, and a crash or Ctrl-C mid-write can't leave this
/// credentials-bearing file half-written.
fn record_known_txid(tx_hash: &str) {
    let mut wallets_json: Value = serde_json::from_str(
        &std::fs::read_to_string(WALLETS_PATH).unwrap_or_else(|e| panic!("failed to read {WALLETS_PATH}: {e}")),
    )
    .unwrap_or_else(|e| panic!("failed to parse {WALLETS_PATH}: {e}"));
    let known =
        wallets_json["customer"]["known_txids"].as_array_mut().expect("customer.known_txids must be an array");
    if !known.iter().any(|v| v.as_str() == Some(tx_hash)) {
        known.push(json!(tx_hash));
    }
    let tmp_path = format!("{WALLETS_PATH}.tmp");
    std::fs::write(&tmp_path, serde_json::to_string_pretty(&wallets_json).unwrap() + "\n")
        .unwrap_or_else(|e| panic!("failed to write {tmp_path}: {e}"));
    std::fs::rename(&tmp_path, WALLETS_PATH)
        .unwrap_or_else(|e| panic!("failed to move {tmp_path} into place over {WALLETS_PATH}: {e}"));
}

#[tokio::test]
#[ignore]
async fn real_stagenet_payment_is_detected_end_to_end() {
    let config = Config::from_file(CONFIG_PATH).unwrap_or_else(|e| {
        panic!("failed to load {CONFIG_PATH} (run from the repo root): {e}")
    });
    config.validate().expect("e2e config should be valid");
    let wallet_cfg = config.wallet.as_ref().expect("e2e config must have a [wallet] bootstrap section");
    let node_cfg = config.monero_node.get(Network::Stagenet).expect("e2e config must have [monero_node.stagenet]");
    let node_url = format!("http{}://{}:{}", if node_cfg.ssl { "s" } else { "" }, node_cfg.host, node_cfg.port);

    let wallets_json: Value = serde_json::from_str(
        &std::fs::read_to_string(WALLETS_PATH).unwrap_or_else(|e| panic!("failed to read {WALLETS_PATH}: {e}")),
    )
    .unwrap_or_else(|e| panic!("failed to parse {WALLETS_PATH}: {e}"));
    let customer_address = wallets_json["customer"]["address"].as_str().expect("customer.address missing").to_string();
    let customer_spend_key_hex =
        wallets_json["customer"]["private_spend_key"].as_str().expect("customer.private_spend_key missing").to_string();
    let customer_view_key_hex =
        wallets_json["customer"]["private_view_key"].as_str().expect("customer.private_view_key missing").to_string();
    let known_txids: Vec<String> = wallets_json["customer"]["known_txids"]
        .as_array()
        .expect("customer.known_txids missing")
        .iter()
        .map(|v| v.as_str().expect("known_txids entries must be strings").to_string())
        .collect();

    // Same boot sequence as main.rs's happy path, minus the webhook loop (not
    // exercised by this test) and the bound TCP listener (the router is driven
    // in-process via `oneshot` instead).
    let store = Store::open_in_memory().unwrap().into_shared();
    let key_custody: Arc<dyn KeyCustody> = Arc::new(PlainKeyCustody::default());
    let exchange_rate: Arc<dyn ExchangeRateProvider> =
        Arc::new(config.exchange_rate.build_fixed_rate_provider().expect("invalid exchange_rate.rates in e2e config"));
    let daemon: Arc<dyn MoneroDaemonClient> = Arc::new(
        RpcDaemonClient::new(&node_cfg.host, node_cfg.port, node_cfg.ssl, node_cfg.accept_self_signed_certs)
            .expect("failed to build daemon RPC client"),
    );
    require_daemon_reachable(daemon.as_ref(), &node_cfg.host, node_cfg.port).await;

    let material = WalletMaterial::from_hex(&wallet_cfg.private_view_key, &wallet_cfg.public_spend_key)
        .expect("invalid [wallet] key material in e2e config");
    let sealed = key_custody.seal(&material).await.unwrap();
    let created = store
        .lock()
        .unwrap()
        .create_tenant(
            NewTenant {
                key_custody_backend: "plain".to_string(),
                sealed_key_material: sealed,
                primary_address: wallet_cfg.primary_address.clone(),
                network: wallet_cfg.network.clone(),
                allowed_origins: wallet_cfg.allowed_origins.clone(),
                confirmations_required: Some(config.payment.confirmations_required),
                zero_conf_max_piconero: config
                    .payment
                    .zero_conf_max_xmr
                    .as_deref()
                    .and_then(|s| parse_xmr_to_piconero(s).ok()),
                order_expiry_seconds: Some(config.payment.order_expiry_minutes * 60),
            },
            now_unix(),
        )
        .expect("failed to create tenant");
    let pk = created.tenant.public_key.clone();
    let handle = key_custody.unseal_and_register(&created.tenant.sealed_key_material).await.unwrap();
    let wallet_handles = Arc::new(RwLock::new(HashMap::from([(created.tenant.id.clone(), handle)])));

    let app_state = AppState {
        store: store.clone(),
        key_custody: key_custody.clone(),
        exchange_rate,
        wallet_handles,
        rate_limiter: Arc::new(RateLimiter::new(10_000)),
        configured_networks: Arc::new(HashSet::from([Network::Stagenet])),
    };
    let router = build_router(app_state, 1_000_000);

    // -- create a real order for a genuinely tiny amount (see e2e/README.md for
    // why the fixed exchange rate is tuned to make $0.05 map to a few hundred
    // thousand piconero) --
    let (status, order) = oneshot_json(
        &router,
        "POST",
        format!("/api/v1/t/{pk}/orders"),
        Some(json!({
            "merchant_order_id": format!("rust-e2e-{}", now_unix()),
            "fiat_amount": "0.05",
            "fiat_currency": "USD",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "order creation failed: {order:?}");
    let payment_id = order["payment_id"].as_str().unwrap().to_string();
    let address = order["address"].as_str().unwrap().to_string();
    let amount_piconero = order["xmr_amount_piconero"].as_u64().unwrap();
    println!("created order {payment_id}: {amount_piconero} piconero to {address}");

    // -- pay it for real: construct, sign, and broadcast the transaction ourselves
    // (no wallet-rpc or any other external wallet process - see tests/support/mod.rs) --
    let spend_wallet = StagenetSpendWallet::connect(
        &node_url,
        node_cfg.accept_self_signed_certs,
        &customer_spend_key_hex,
        &customer_view_key_hex,
        &customer_address,
    )
    .await
    .unwrap_or_else(|e| panic!("\n\n{e}\n"));
    let tx_hash = spend_wallet
        .send(daemon.as_ref(), &known_txids, &address, amount_piconero)
        .await
        .unwrap_or_else(|e| panic!("\n\n{e}\n"));
    let tx_hash_hex = hex::encode(tx_hash);
    println!("sent real stagenet payment, tx {tx_hash_hex}");
    record_known_txid(&tx_hash_hex);

    // -- drive the real scanner ourselves (no background task/sleep loop needed -
    // this *is* the same `run_scan_tick` the production loop in main.rs calls on a
    // timer) and poll until the payment is detected --
    let tenants = vec![(created.tenant.id.clone(), handle)];
    let mut last_status = String::new();
    for attempt in 1..=30 {
        run_scan_tick(&store, key_custody.as_ref(), daemon.as_ref(), network_str(Network::Stagenet), &tenants, config.payment.reorg_check_depth)
            .await
            .expect("scan tick failed");

        let (status, order_status) =
            oneshot_json(&router, "GET", format!("/api/v1/t/{pk}/orders/{payment_id}"), None).await;
        assert_eq!(status, StatusCode::OK);
        last_status = order_status["status"].as_str().unwrap().to_string();
        println!("[{attempt}/30] status={last_status}");

        if matches!(last_status.as_str(), "paid" | "confirming" | "overpaid") {
            println!("PASS: order {payment_id} reached status '{last_status}' (tx {tx_hash_hex})");
            return;
        }
        assert_ne!(last_status, "expired", "order expired before the real payment was detected");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("order {payment_id} still '{last_status}' after 30 scan attempts - real stagenet payment (tx {tx_hash_hex}) was not detected");
}
