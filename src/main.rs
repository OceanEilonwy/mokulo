//! Boot sequence: load config, open storage, bootstrap the self-hosted tenant if
//! configured, register every tenant's wallet with `KeyCustody`, then run the
//! chain scanner (once per configured network), the webhook delivery loop, and the
//! HTTP server concurrently.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use monero::Network;
use moneropay_core::cli::{self, Action};
use moneropay_core::config::Config;
use moneropay_core::daemon::MoneroDaemonClient;
use moneropay_core::daemon_rpc::RpcDaemonClient;
use moneropay_core::exchange_rate::ExchangeRateProvider;
use moneropay_core::http::rate_limit::RateLimiter;
use moneropay_core::http::{build_router, now_unix, AppState};
use moneropay_core::init_wizard;
use moneropay_core::key_custody::{KeyCustody, PlainKeyCustody, WalletHandle, WalletMaterial};
use moneropay_core::local_admin;
use moneropay_core::network::network_str;
use moneropay_core::scanner::run_scan_tick;
use moneropay_core::store::{NewTenant, SharedStore, Store};
use moneropay_core::webhook_delivery::run_delivery_tick;

/// All argv parsing lives in `moneropay_core::cli` (a lib module, unit-testable
/// the normal way) - this function is just the untestable-by-nature glue that
/// turns its result into process exit codes and side effects (stdin/stdout,
/// running the wizard, `std::process::exit`). `async` only because
/// `init_wizard::run_interactive` now makes a real network call when its "test
/// this node" prompt is accepted; already fine to await here since `main` is
/// itself async.
async fn dispatch_args() -> (std::path::PathBuf, bool) {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse_args(&raw) {
        Ok(Action::Help) => {
            print!("{}", cli::HELP_TEXT);
            std::process::exit(0);
        }
        Ok(Action::Init(init_args)) => {
            let path = init_args.config_path_override.map(std::path::PathBuf::from).unwrap_or_else(init_wizard::default_config_path);
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let mut output = std::io::stdout();
            match init_wizard::run_interactive(&mut input, &mut output, init_args.network, &path).await {
                Ok(init_wizard::WizardOutcome::Written(_)) => std::process::exit(0),
                Ok(init_wizard::WizardOutcome::Cancelled) => std::process::exit(1),
                Err(e) => {
                    eprintln!("setup wizard failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Ok(Action::RotateSecret { config_path, pk }) => {
            let store = open_local_store(&config_path);
            match local_admin::rotate_secret(&store, pk.as_deref()) {
                Ok((pk, secret)) => {
                    println!("Tenant: {pk}");
                    println!("New secret: {secret}");
                    println!("(shown once - store it now; the old secret no longer works)");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Ok(Action::ShowTenant { config_path, pk }) => {
            let store = open_local_store(&config_path);
            match local_admin::show_tenant(&store, pk.as_deref()) {
                Ok(s) => {
                    println!("Public key:            {}", s.public_key);
                    println!("Network:               {}", s.network);
                    println!("Primary address:       {}", s.primary_address);
                    println!(
                        "Allowed origins:       {}",
                        if s.allowed_origins.is_empty() { "(none configured)".to_string() } else { s.allowed_origins.join(", ") }
                    );
                    println!("Confirmations required: {}", s.confirmations_required);
                    println!(
                        "Zero-conf ceiling:     {}",
                        s.zero_conf_max_piconero.map(|p| format!("{p} piconero")).unwrap_or_else(|| "(disabled)".to_string())
                    );
                    println!("Order expiry:          {} minutes", s.order_expiry_seconds / 60);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Ok(Action::Snippet { config_path, pk, endpoint }) => {
            let store = open_local_store(&config_path);
            let endpoint = match endpoint {
                Some(e) => e,
                None => {
                    let stdin = std::io::stdin();
                    let mut input = stdin.lock();
                    let mut output = std::io::stdout();
                    init_wizard::prompt(
                        &mut output,
                        &mut input,
                        "What URL will customers reach this server at? (through any reverse proxy/domain in front of it)",
                        None,
                    )
                    .unwrap_or_default()
                }
            };
            match local_admin::snippet(&store, pk.as_deref(), &endpoint) {
                Ok(html) => {
                    print!("{html}");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Ok(Action::RunServer { config_path, strict_tls }) => (config_path, strict_tls),
        Err(e) => {
            eprintln!("{e}\n\nRun with --help for usage.");
            std::process::exit(1);
        }
    }
}

/// Opens the database co-located with `config_path` (see
/// `init_wizard::database_path_for`) for the local-admin commands, which need
/// direct DB access and nothing else from the config file itself.
fn open_local_store(config_path: &std::path::Path) -> Store {
    let db_path = init_wizard::database_path_for(config_path);
    Store::open_file(&db_path.to_string_lossy()).unwrap_or_else(|e| {
        eprintln!("failed to open database at {}: {e}", db_path.display());
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    let (config_path, strict_tls) = dispatch_args().await;
    let config_path_display = config_path.display().to_string();
    let config = Config::from_file(&config_path.to_string_lossy()).unwrap_or_else(|e| {
        eprintln!("failed to load config from {config_path_display}: {e}");
        std::process::exit(1);
    });
    if let Err(e) = config.validate() {
        eprintln!("invalid config: {e}");
        std::process::exit(1);
    }

    let db_path = init_wizard::database_path_for(&config_path);
    let store = Store::open_file(&db_path.to_string_lossy()).expect("failed to open database").into_shared();
    let key_custody: Arc<dyn KeyCustody> = Arc::new(PlainKeyCustody::default());
    let exchange_rate: Arc<dyn ExchangeRateProvider> = Arc::new(
        config
            .exchange_rate
            .build_fixed_rate_provider()
            .expect("invalid exchange_rate.rates entry in config"),
    );

    // One daemon client per configured network (§DESIGN.md §7) - a single instance
    // can hold mainnet tenants for real customers alongside stagenet/testnet
    // tenants for testing, each scanned against its own node.
    let daemons: HashMap<Network, Arc<dyn MoneroDaemonClient>> = config
        .monero_node
        .iter()
        .map(|(network, node_config)| {
            let accept_self_signed = node_config.accept_self_signed_certs && !strict_tls;
            let client: Arc<dyn MoneroDaemonClient> = Arc::new(
                RpcDaemonClient::new(&node_config.host, node_config.port, node_config.ssl, accept_self_signed)
                    .unwrap_or_else(|e| panic!("failed to build Monero daemon RPC client for {network:?}: {e}")),
            );
            (network, client)
        })
        .collect();
    let configured_networks: Arc<HashSet<Network>> = Arc::new(daemons.keys().copied().collect());

    bootstrap_self_hosted_tenant(&store, &key_custody, &config).await;
    let wallet_handles = Arc::new(RwLock::new(register_all_tenants(&store, &key_custody).await));

    let app_state = AppState {
        store: store.clone(),
        key_custody: key_custody.clone(),
        exchange_rate,
        wallet_handles: wallet_handles.clone(),
        rate_limiter: Arc::new(RateLimiter::new(config.server.rate_limit_per_ip_per_min)),
        configured_networks,
    };

    let allow_private_urls = config.webhooks.allow_private_urls;
    let delivery_timeout_ms = config.webhooks.delivery_timeout_ms;
    let delivery_max_attempts = config.webhooks.max_attempts;
    let delivery_store = store.clone();
    supervise("webhook delivery", move || {
        run_webhook_delivery_loop(
            delivery_store.clone(),
            allow_private_urls,
            delivery_timeout_ms,
            delivery_max_attempts,
        )
    });

    let reorg_check_depth = config.payment.reorg_check_depth;
    let poll_interval = Duration::from_millis(config.payment.mempool_poll_interval_ms);
    let daemons = Arc::new(daemons);
    supervise("chain scanner", move || {
        run_scanner_loop(
            store.clone(),
            key_custody.clone(),
            daemons.clone(),
            wallet_handles.clone(),
            reorg_check_depth,
            poll_interval,
        )
    });

    let router = build_router(app_state, config.server.max_body_bytes);
    let listener = tokio::net::TcpListener::bind(&config.server.bind).await.expect("failed to bind server address");
    println!("moneropay listening on {}", config.server.bind);
    axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .expect("server error");
}

/// Runs a background loop under a supervisor that survives its death.
///
/// A bare `tokio::spawn` of an infinite loop has a failure mode that is uniquely bad
/// here: a panic anywhere inside the task kills *only* that task. The `JoinHandle` is
/// dropped, nothing observes the error, and the HTTP server keeps serving happily -
/// so the service goes on accepting orders and quoting addresses while no chain
/// scanning and no webhook delivery is happening at all. Every one of those orders
/// gets paid and never noticed. There is no signal short of a merchant eventually
/// complaining.
///
/// So: log loudly, then restart. The delay is there because the most likely cause of
/// a panic is a condition that will still hold a moment later (a poisoned lock, a
/// node returning something unparseable), and a hot restart loop would bury the very
/// message that explains it.
fn supervise<F, Fut>(name: &'static str, make_loop: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // The inner spawn is what makes the panic catchable: a panic propagating
            // through `.await` in *this* task would kill the supervisor too.
            match tokio::spawn(make_loop()).await {
                Ok(()) => eprintln!("BUG: {name} loop returned; it is not supposed to terminate. Restarting in 5s."),
                Err(e) if e.is_panic() => {
                    eprintln!("FATAL: {name} loop PANICKED: {e}. No {name} work is happening until it restarts. Restarting in 5s.");
                }
                Err(e) => {
                    eprintln!("{name} loop was cancelled: {e}. Not restarting.");
                    return;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Creates the one tenant a self-hosted deployment needs, from `[wallet]` in the
/// config - but only once, on first boot. Idempotent across restarts by checking
/// whether any tenant already exists first, rather than tracking a separate
/// "already bootstrapped" flag.
async fn bootstrap_self_hosted_tenant(store: &SharedStore, key_custody: &Arc<dyn KeyCustody>, config: &Config) {
    let Some(wallet) = &config.wallet else { return };
    let already_bootstrapped = store.lock().unwrap().count_tenants().unwrap_or(0) > 0;
    if already_bootstrapped {
        return;
    }

    let material = WalletMaterial::from_hex(&wallet.private_view_key, &wallet.public_spend_key)
        .expect("invalid [wallet] key material in config");
    let sealed = key_custody.seal(&material).await.expect("failed to seal bootstrap wallet material");

    let created = store
        .lock()
        .unwrap()
        .create_tenant(
            NewTenant {
                key_custody_backend: "plain".to_string(),
                sealed_key_material: sealed,
                primary_address: wallet.primary_address.clone(),
                network: wallet.network.clone(),
                allowed_origins: wallet.allowed_origins.clone(),
                confirmations_required: Some(config.payment.confirmations_required),
                zero_conf_max_piconero: config
                    .payment
                    .zero_conf_max_xmr
                    .as_deref()
                    .and_then(|s| moneropay_core::exchange_rate::parse_xmr_to_piconero(s).ok()),
                order_expiry_seconds: Some(config.payment.order_expiry_minutes * 60),
            },
            now_unix(),
        )
        .expect("failed to create bootstrap tenant");

    println!(
        "bootstrapped self-hosted tenant: public_key={} (save this - it goes in your site's JS)",
        created.tenant.public_key
    );
    println!(
        "bootstrap admin secret: {} (shown once - store it now, e.g. in a password manager)",
        created.secret_token
    );
}

/// Eagerly registers every non-disabled tenant's sealed key material with
/// `KeyCustody`, so `AppState::wallet_handles` starts populated rather than relying
/// solely on the lazy on-first-use path in `http::resolve_wallet_handle`.
async fn register_all_tenants(store: &SharedStore, key_custody: &Arc<dyn KeyCustody>) -> HashMap<String, WalletHandle> {
    let tenants = store.lock().unwrap().list_active_tenants().expect("failed to list tenants at boot");
    let mut handles = HashMap::new();
    for tenant in tenants {
        match key_custody.unseal_and_register(&tenant.sealed_key_material).await {
            Ok(handle) => {
                handles.insert(tenant.id, handle);
            }
            Err(e) => eprintln!("failed to register tenant {} with key custody: {e}", tenant.id),
        }
    }
    handles
}

async fn run_webhook_delivery_loop(
    store: SharedStore,
    allow_private_urls: bool,
    timeout_ms: u64,
    max_attempts: u32,
) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build webhook HTTP client");
    let timeout = Duration::from_millis(timeout_ms);

    loop {
        // `run_delivery_tick` locks the store only around its own brief synchronous
        // sections, never across the outbound HTTP `.await`s it performs per
        // delivery - see its doc comment for why that matters.
        if let Err(e) =
            run_delivery_tick(&store, &client, allow_private_urls, timeout, max_attempts, now_unix()).await
        {
            eprintln!("webhook delivery tick failed: {e}");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Runs one `run_scan_tick` per configured network, per round. Re-reads
/// `wallet_handles` fresh every round (rather than a boot-time snapshot) so a
/// tenant created at runtime via the admin API - on any network - is picked up
/// without a restart; `run_scan_tick` itself filters that full list down to the
/// network it was called for (see its doc comment).
///
/// Sequential across networks, not concurrent: with typically one or two networks
/// configured, the simplicity is worth more than the parallelism, but a slow or
/// unresponsive node on one network delaying the next network's tick within the
/// same round is a real, accepted tradeoff worth revisiting if a deployment ever
/// configures enough networks (or gets an unreliable enough node) for it to matter.
async fn run_scanner_loop(
    store: SharedStore,
    key_custody: Arc<dyn KeyCustody>,
    daemons: Arc<HashMap<Network, Arc<dyn MoneroDaemonClient>>>,
    wallet_handles: Arc<RwLock<HashMap<String, WalletHandle>>>,
    reorg_check_depth: u64,
    poll_interval: Duration,
) {
    loop {
        let tenants: Vec<(String, WalletHandle)> =
            wallet_handles.read().unwrap().iter().map(|(id, h)| (id.clone(), *h)).collect();
        for (network, daemon) in daemons.iter() {
            if let Err(e) =
                run_scan_tick(&store, key_custody.as_ref(), daemon.as_ref(), network_str(*network), &tenants, reorg_check_depth)
                    .await
            {
                eprintln!("scan tick failed for {network:?}: {e}");
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}
