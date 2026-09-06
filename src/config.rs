//! TOML configuration, per `docs/DESIGN.md` §13. One file, sensible defaults - "one
//! config file, one binary" is a stated v1 goal (§DESIGN.md §2).

use std::collections::HashMap;

use monero::Network;
use serde::Deserialize;

use crate::exchange_rate::{parse_xmr_to_piconero, FixedRateProvider};
use crate::network::parse_network;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid exchange rate for {currency}: {source}")]
    InvalidRate {
        currency: String,
        #[source]
        source: crate::exchange_rate::AmountError,
    },
    #[error("no [monero_node.<network>] section is configured - need at least one of mainnet, stagenet, testnet")]
    NoNodesConfigured,
    #[error("[wallet] specifies network {0:?}, but no [monero_node.{0}] is configured")]
    BootstrapNetworkNotConfigured(String),
    #[error("{field} is {value}, but must be {expected}")]
    OutOfRange {
        field: &'static str,
        value: String,
        expected: &'static str,
    },
    #[error("exchange_rate.provider {0:?} is not implemented - only \"fixed\" exists in this version")]
    UnknownRateProvider(String),
    #[error(
        "payment.zero_conf_max_fiat has been renamed to payment.zero_conf_max_xmr, because the value was \
         never denominated in fiat: it is compared directly against the piconero total an order has \
         received. Reading it as fiat (as the old name and the DESIGN.md example both invited) makes a \
         ceiling written as \"50.00\" mean 50 XMR rather than $50 - hundreds of times more zero-conf \
         double-spend exposure than intended, which is the exact risk this setting exists to bound. Rename \
         the key and re-check the value: it is an amount of XMR, e.g. \"0.25\"."
    )]
    ZeroConfCeilingRenamed,
}

fn require<T: std::fmt::Display + PartialOrd>(
    field: &'static str,
    value: T,
    min: T,
    max: T,
    expected: &'static str,
) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::OutOfRange { field, value: value.to_string(), expected });
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// One instance can watch multiple networks at once (§DESIGN.md §7) - a
    /// developer's single server can hold mainnet tenants for real customers
    /// alongside stagenet/testnet tenants for testing, each scanned against its own
    /// daemon. At least one of `mainnet`/`stagenet`/`testnet` must be present; see
    /// `Config::validate`. `#[serde(default)]` so a config omitting `[monero_node]`
    /// entirely still parses (as empty) rather than failing before `validate` gets
    /// a chance to produce a clearer, dedicated error for that case.
    #[serde(default)]
    pub monero_node: MoneroNodesConfig,
    /// Self-hosted bootstrap only: creates the one tenant this deployment needs at
    /// first boot. Absent entirely on a hosted instance where tenants are created at
    /// runtime via the admin API instead (§DESIGN.md §4).
    pub wallet: Option<WalletBootstrapConfig>,
    #[serde(default)]
    pub exchange_rate: ExchangeRateConfig,
    #[serde(default)]
    pub payment: PaymentConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub webhooks: WebhooksConfig,
}

impl Config {
    /// Cross-field checks serde can't express: at least one network must be
    /// configured at all, and `[wallet]` (if present) must name a network that
    /// actually has a node configured - otherwise its address would be derived but
    /// never scanned by anything, a silent "payments never detected" failure mode
    /// far worse than refusing to boot.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.monero_node.is_empty() {
            return Err(ConfigError::NoNodesConfigured);
        }
        if let Some(wallet) = &self.wallet {
            let network = parse_network(&wallet.network)
                .map_err(|_| ConfigError::BootstrapNetworkNotConfigured(wallet.network.clone()))?;
            if self.monero_node.get(network).is_none() {
                return Err(ConfigError::BootstrapNetworkNotConfigured(wallet.network.clone()));
            }
        }
        self.validate_bounds()
    }

    /// Range checks on every numeric knob. These exist because serde will happily
    /// accept `0` for any of them, and each zero has a *silent* failure mode rather
    /// than a loud one - which is the worst possible shape for a payments service:
    ///
    /// - `order_expiry_minutes = 0` (or negative) makes every order expire at or
    ///   before the moment it is created, so no payment is ever creditable.
    /// - `confirmations_required = 0` marks an order `Paid` off an unconfirmed
    ///   transaction, bypassing the zero-conf ceiling entirely and releasing goods
    ///   against a transaction that can still be replaced.
    /// - `mempool_poll_interval_ms = 0` turns the scanner into a hot loop that
    ///   hammers the node until it rate-limits or bans this client, at which point
    ///   payments stop being detected for a reason nothing here reports.
    /// - `rate_limit_per_ip_per_min = 0` rejects *every* request, including the
    ///   merchant's own - the limiter checks the count before incrementing it.
    /// - `max_body_bytes = 0` rejects every request body, i.e. all order creation.
    /// - `delivery_timeout_ms`/`max_attempts` at 0 mean no webhook is ever
    ///   successfully delivered.
    ///
    /// The upper bounds are deliberately generous - they exist to catch a
    /// transposed digit or a wrong unit (milliseconds typed as seconds, minutes as
    /// seconds), not to express an opinion about tuning. `order_expiry_minutes` in
    /// particular is capped well below the point where `* 60` could overflow the
    /// `i64` seconds it is converted to in `main`.
    fn validate_bounds(&self) -> Result<(), ConfigError> {
        if self.exchange_rate.provider != "fixed" {
            return Err(ConfigError::UnknownRateProvider(self.exchange_rate.provider.clone()));
        }
        for (network, node) in self.monero_node.iter() {
            if node.host.trim().is_empty() {
                return Err(ConfigError::OutOfRange {
                    field: "monero_node.<network>.host",
                    value: format!("{:?} (for {network:?})", node.host),
                    expected: "a non-empty hostname or IP address",
                });
            }
            require("monero_node.<network>.port", node.port, 1, u16::MAX, "between 1 and 65535")?;
        }

        require("payment.confirmations_required", self.payment.confirmations_required, 1, 720, "at least 1 (0 would treat an unconfirmed transaction as final) and at most 720 (~24h)")?;
        require("payment.order_expiry_minutes", self.payment.order_expiry_minutes, 1, 60 * 24 * 365, "at least 1 minute and at most a year")?;
        require("payment.reorg_check_depth", self.payment.reorg_check_depth, 1, 10_000, "at least 1 block and at most 10000")?;
        require("payment.mempool_poll_interval_ms", self.payment.mempool_poll_interval_ms, 100, 3_600_000, "at least 100ms and at most an hour")?;
        if self.payment.zero_conf_max_fiat.is_some() {
            return Err(ConfigError::ZeroConfCeilingRenamed);
        }
        if let Some(ceiling) = &self.payment.zero_conf_max_xmr {
            parse_xmr_to_piconero(ceiling).map_err(|source| ConfigError::InvalidRate {
                currency: "payment.zero_conf_max_xmr".to_string(),
                source,
            })?;
        }

        self.server.bind.parse::<std::net::SocketAddr>().map_err(|_| ConfigError::OutOfRange {
            field: "server.bind",
            value: self.server.bind.clone(),
            expected: "an address:port this process can bind, e.g. \"0.0.0.0:8443\"",
        })?;
        require("server.worker_threads", self.server.worker_threads, 1, 1024, "at least 1")?;
        require("server.rate_limit_per_ip_per_min", self.server.rate_limit_per_ip_per_min, 1, 1_000_000, "at least 1 (0 rejects every request, including the merchant's own)")?;
        require("server.max_body_bytes", self.server.max_body_bytes, 256, 16 * 1024 * 1024, "at least 256 bytes and at most 16MiB")?;

        require("webhooks.delivery_timeout_ms", self.webhooks.delivery_timeout_ms, 100, 300_000, "at least 100ms and at most 5 minutes")?;
        require("webhooks.max_attempts", self.webhooks.max_attempts, 1, 64, "at least 1 and at most 64")?;

        for (currency, xmr_decimal) in &self.exchange_rate.rates {
            let rate = parse_xmr_to_piconero(xmr_decimal)
                .map_err(|source| ConfigError::InvalidRate { currency: currency.clone(), source })?;
            if rate == 0 {
                // A zero rate prices every order in this currency at zero piconero,
                // and an order for nothing is satisfied by paying nothing.
                return Err(ConfigError::OutOfRange {
                    field: "exchange_rate.rates.<currency>",
                    value: format!("{xmr_decimal:?} (for {currency})"),
                    expected: "greater than zero",
                });
            }
        }
        Ok(())
    }
}

/// Per-network node configuration - a TOML table keyed by network name, e.g.
/// `[monero_node.mainnet]`, `[monero_node.stagenet]`. A self-hoster running only
/// mainnet in production configures just that one section.
#[derive(Debug, Deserialize, Default)]
pub struct MoneroNodesConfig {
    pub mainnet: Option<MoneroNodeConfig>,
    pub stagenet: Option<MoneroNodeConfig>,
    pub testnet: Option<MoneroNodeConfig>,
}

impl MoneroNodesConfig {
    pub fn get(&self, network: Network) -> Option<&MoneroNodeConfig> {
        match network {
            Network::Mainnet => self.mainnet.as_ref(),
            Network::Stagenet => self.stagenet.as_ref(),
            Network::Testnet => self.testnet.as_ref(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.mainnet.is_none() && self.stagenet.is_none() && self.testnet.is_none()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Network, &MoneroNodeConfig)> {
        [(Network::Mainnet, &self.mainnet), (Network::Stagenet, &self.stagenet), (Network::Testnet, &self.testnet)]
            .into_iter()
            .filter_map(|(network, cfg)| cfg.as_ref().map(|c| (network, c)))
    }
}

#[derive(Debug, Deserialize)]
pub struct MoneroNodeConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub ssl: bool,
    /// Defaults **on**: community-run public Monero nodes overwhelmingly serve
    /// self-signed TLS certificates, so rejecting them by default would make the
    /// common case fail out of the box for exactly the audience this project
    /// targets. Set to `false` (in the config file, or `--strict-tls` on the
    /// command line) to require a real CA-signed certificate instead. Note this is
    /// `reqwest`'s blunt `danger_accept_invalid_certs` underneath, so it also
    /// tolerates other certificate problems (expired, wrong hostname) - it isn't
    /// scoped to "self-signed but otherwise fine" specifically.
    #[serde(default = "default_true")]
    pub accept_self_signed_certs: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct WalletBootstrapConfig {
    pub primary_address: String,
    pub private_view_key: String,
    pub public_spend_key: String,
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_network() -> String {
    "mainnet".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRateConfig {
    /// Only "fixed" is implemented in this pass - a Haveno-backed provider is
    /// deferred (§DESIGN.md §16). `rates` maps a fiat currency code to an
    /// XMR-denominated decimal string (e.g. `"0.0067"` XMR per 1 USD).
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub rates: HashMap<String, String>,
}

fn default_provider() -> String {
    "fixed".to_string()
}

impl Default for ExchangeRateConfig {
    fn default() -> Self {
        ExchangeRateConfig { provider: default_provider(), rates: HashMap::new() }
    }
}

impl ExchangeRateConfig {
    pub fn build_fixed_rate_provider(&self) -> Result<FixedRateProvider, ConfigError> {
        let mut piconero_rates = HashMap::new();
        for (currency, xmr_decimal) in &self.rates {
            let piconero_per_unit = parse_xmr_to_piconero(xmr_decimal)
                .map_err(|source| ConfigError::InvalidRate { currency: currency.clone(), source })?;
            piconero_rates.insert(currency.clone(), piconero_per_unit);
        }
        Ok(FixedRateProvider::new(piconero_rates))
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct PaymentConfig {
    pub confirmations_required: u64,
    /// The largest total an order may be treated as `paid` on while still entirely
    /// unconfirmed, as a decimal **XMR** amount (e.g. `"0.25"`).
    ///
    /// Denominated in XMR, not fiat, because that is the only thing it can be:
    /// `derive_status` compares it against `tenants.zero_conf_max_piconero`, which is
    /// the piconero sum of an order's payments, and nothing in that comparison knows
    /// which currency the order was priced in. The key used to be spelled
    /// `zero_conf_max_fiat` (and `DESIGN.md` §13 illustrated it as `50.00`), which
    /// read as dollars and silently bought roughly three hundred times the intended
    /// zero-conf exposure. `zero_conf_max_fiat` is now refused outright - see
    /// `ConfigError::ZeroConfCeilingRenamed` - rather than ignored, so nobody carries
    /// the old reading across the rename.
    pub zero_conf_max_xmr: Option<String>,
    /// Retained solely so the removed spelling produces a loud, explanatory error
    /// instead of being silently dropped as an unknown key (serde ignores unknown
    /// fields, which here would quietly turn a configured ceiling into no ceiling).
    /// Never read for its value.
    pub zero_conf_max_fiat: Option<String>,
    pub order_expiry_minutes: i64,
    pub reorg_check_depth: u64,
    pub mempool_poll_interval_ms: u64,
}

impl Default for PaymentConfig {
    fn default() -> Self {
        PaymentConfig {
            confirmations_required: 10,
            zero_conf_max_xmr: None,
            zero_conf_max_fiat: None,
            order_expiry_minutes: 30,
            reorg_check_depth: 20,
            mempool_poll_interval_ms: 1000,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    /// Currently accepted and range-checked but *not* applied: `main` uses
    /// `#[tokio::main]`'s default multi-threaded runtime (one worker per core).
    /// Kept in the schema rather than removed so an existing config file naming it
    /// doesn't start failing to parse, and validated so it can't hold a value that
    /// would be nonsense once it is wired up.
    pub worker_threads: usize,
    pub rate_limit_per_ip_per_min: u32,
    pub max_body_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind: "0.0.0.0:8443".to_string(),
            worker_threads: 2,
            rate_limit_per_ip_per_min: 20,
            max_body_bytes: 8192,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct WebhooksConfig {
    /// SSRF escape hatch for a self-hoster testing against their own LAN - see
    /// `docs/DESIGN.md` §11. Must default to `false`; the default must stay closed.
    pub allow_private_urls: bool,
    pub delivery_timeout_ms: u64,
    pub max_attempts: u32,
}

impl Default for WebhooksConfig {
    fn default() -> Self {
        WebhooksConfig { allow_private_urls: false, delivery_timeout_ms: 5000, max_attempts: 8 }
    }
}

impl std::str::FromStr for Config {
    type Err = ConfigError;

    fn from_str(contents: &str) -> Result<Config, ConfigError> {
        Ok(toml::from_str(contents)?)
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Config, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        contents.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange_rate::ExchangeRateProvider;
    use std::str::FromStr;

    #[test]
    fn minimal_config_parses_with_defaults_applied() {
        let toml = r#"
            [monero_node.mainnet]
            host = "127.0.0.1"
            port = 18081
        "#;
        let config = Config::from_str(toml).unwrap();
        let mainnet = config.monero_node.get(Network::Mainnet).unwrap();
        assert_eq!(mainnet.host, "127.0.0.1");
        assert!(!mainnet.ssl);
        assert!(
            mainnet.accept_self_signed_certs,
            "must default on - most public Monero nodes self-sign, unlike the webhook SSRF escape hatch below"
        );
        assert!(config.monero_node.get(Network::Stagenet).is_none());
        assert!(config.wallet.is_none());
        assert_eq!(config.payment.confirmations_required, 10);
        assert_eq!(config.server.bind, "0.0.0.0:8443");
        assert!(!config.webhooks.allow_private_urls, "SSRF escape hatch must default closed");
        config.validate().unwrap();
    }

    #[test]
    fn accept_self_signed_certs_can_be_explicitly_disabled() {
        let toml = r#"
            [monero_node.mainnet]
            host = "127.0.0.1"
            port = 18081
            accept_self_signed_certs = false
        "#;
        let config = Config::from_str(toml).unwrap();
        assert!(!config.monero_node.get(Network::Mainnet).unwrap().accept_self_signed_certs);
    }

    #[test]
    fn multiple_networks_can_be_configured_at_once() {
        // The point of this whole structure: one instance holding mainnet tenants
        // for real customers alongside stagenet tenants for testing, each scanned
        // against its own node.
        let toml = r#"
            [monero_node.mainnet]
            host = "mainnet.example"
            port = 18081

            [monero_node.stagenet]
            host = "stagenet.example"
            port = 38081
            ssl = true
        "#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.monero_node.get(Network::Mainnet).unwrap().host, "mainnet.example");
        assert_eq!(config.monero_node.get(Network::Stagenet).unwrap().host, "stagenet.example");
        assert!(config.monero_node.get(Network::Testnet).is_none());
        assert_eq!(config.monero_node.iter().count(), 2);
        config.validate().unwrap();
    }

    #[test]
    fn validate_rejects_a_config_with_no_networks_configured_at_all() {
        let toml = r#"
            [server]
            bind = "127.0.0.1:9000"
        "#;
        let config = Config::from_str(toml).unwrap();
        assert!(matches!(config.validate(), Err(ConfigError::NoNodesConfigured)));
    }

    #[test]
    fn validate_rejects_a_wallet_bootstrap_naming_an_unconfigured_network() {
        // Catches exactly the silent failure mode this validation exists to
        // prevent: a tenant whose address would be derived for a chain nothing is
        // ever scanning.
        let toml = r#"
            [monero_node.mainnet]
            host = "127.0.0.1"
            port = 18081

            [wallet]
            primary_address = "4abc"
            private_view_key = "aa"
            public_spend_key = "bb"
            network = "stagenet"
        "#;
        let config = Config::from_str(toml).unwrap();
        assert!(matches!(config.validate(), Err(ConfigError::BootstrapNetworkNotConfigured(n)) if n == "stagenet"));
    }

    #[test]
    fn full_config_with_wallet_bootstrap_and_rates_parses() {
        let toml = r#"
            [monero_node.mainnet]
            host = "127.0.0.1"
            port = 18081
            ssl = true

            [monero_node.stagenet]
            host = "127.0.0.1"
            port = 38081

            [wallet]
            primary_address = "4abc"
            private_view_key = "aa"
            public_spend_key = "bb"
            network = "stagenet"
            allowed_origins = ["https://merchant.example"]

            [exchange_rate]
            provider = "fixed"
            [exchange_rate.rates]
            USD = "0.0067"

            [payment]
            confirmations_required = 3
            order_expiry_minutes = 15

            [server]
            bind = "127.0.0.1:9000"

            [webhooks]
            allow_private_urls = true
        "#;
        let config = Config::from_str(toml).unwrap();
        assert!(config.monero_node.get(Network::Mainnet).unwrap().ssl);
        let wallet = config.wallet.as_ref().unwrap();
        assert_eq!(wallet.network, "stagenet");
        assert_eq!(wallet.allowed_origins, vec!["https://merchant.example"]);
        assert_eq!(config.payment.confirmations_required, 3);
        assert_eq!(config.server.bind, "127.0.0.1:9000");
        assert!(config.webhooks.allow_private_urls);
        config.validate().unwrap();

        let provider = config.exchange_rate.build_fixed_rate_provider().unwrap();
        assert_eq!(provider.piconero_per_unit("USD"), Some(6_700_000_000));
    }

    #[test]
    fn invalid_rate_decimal_in_config_is_a_clear_error_not_a_panic() {
        let toml = r#"
            [monero_node.mainnet]
            host = "127.0.0.1"
            port = 18081
            [exchange_rate.rates]
            USD = "not_a_number"
        "#;
        let config = Config::from_str(toml).unwrap();
        let err = config.exchange_rate.build_fixed_rate_provider().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRate { .. }));
    }

    /// A config that passes `validate()` today, for tests that vary one field.
    fn config_with(extra: &str) -> Config {
        let toml = format!(
            r#"
            [monero_node.mainnet]
            host = "127.0.0.1"
            port = 18081
            {extra}
        "#
        );
        Config::from_str(&toml).unwrap()
    }

    #[test]
    fn every_numeric_knob_with_a_silent_failure_mode_at_zero_is_rejected() {
        // Each of these parses fine and then breaks the service quietly rather than
        // loudly - no order ever creditable, an unconfirmed transaction treated as
        // final, a node hammered until it bans us, every request rejected. Refusing
        // to boot is the only visible failure available.
        let cases: &[(&str, &str)] = &[
            ("[payment]\nconfirmations_required = 0", "payment.confirmations_required"),
            ("[payment]\norder_expiry_minutes = 0", "payment.order_expiry_minutes"),
            ("[payment]\norder_expiry_minutes = -30", "payment.order_expiry_minutes"),
            ("[payment]\nreorg_check_depth = 0", "payment.reorg_check_depth"),
            ("[payment]\nmempool_poll_interval_ms = 0", "payment.mempool_poll_interval_ms"),
            ("[server]\nrate_limit_per_ip_per_min = 0", "server.rate_limit_per_ip_per_min"),
            ("[server]\nmax_body_bytes = 0", "server.max_body_bytes"),
            ("[server]\nworker_threads = 0", "server.worker_threads"),
            ("[webhooks]\ndelivery_timeout_ms = 0", "webhooks.delivery_timeout_ms"),
            ("[webhooks]\nmax_attempts = 0", "webhooks.max_attempts"),
        ];
        for (extra, field) in cases {
            let err = config_with(extra).validate().unwrap_err();
            assert!(
                matches!(&err, ConfigError::OutOfRange { field: f, .. } if f == field),
                "{extra:?} should be rejected as {field}, got {err}"
            );
        }
    }

    #[test]
    fn an_order_expiry_large_enough_to_overflow_its_seconds_conversion_is_rejected() {
        // `main` converts this to seconds with `* 60`; at i64::MAX that overflows,
        // which panics in a debug build and silently wraps to a *past* deadline in a
        // release one - every order instantly expired.
        let err = config_with(&format!("[payment]\norder_expiry_minutes = {}", i64::MAX)).validate().unwrap_err();
        assert!(matches!(err, ConfigError::OutOfRange { field: "payment.order_expiry_minutes", .. }));
        // The largest accepted value still converts without overflowing.
        let config = config_with("[payment]\norder_expiry_minutes = 525600");
        config.validate().unwrap();
        assert!(config.payment.order_expiry_minutes.checked_mul(60).is_some());
    }

    #[test]
    fn a_zero_exchange_rate_is_rejected_because_it_would_price_orders_at_nothing() {
        let err = config_with("[exchange_rate.rates]\nUSD = \"0\"").validate().unwrap_err();
        assert!(matches!(err, ConfigError::OutOfRange { field: "exchange_rate.rates.<currency>", .. }), "got {err}");
        assert!(matches!(
            config_with("[exchange_rate.rates]\nUSD = \"0.0000000000001\"").validate().unwrap_err(),
            ConfigError::InvalidRate { .. }
        ));
        config_with("[exchange_rate.rates]\nUSD = \"0.000000000001\"").validate().unwrap();
    }

    #[test]
    fn an_unimplemented_rate_provider_is_refused_rather_than_silently_ignored() {
        // `build_fixed_rate_provider` is called unconditionally in `main`, so a
        // config naming a provider that doesn't exist would boot and quietly serve
        // fixed rates under a name promising live ones.
        let err = config_with("[exchange_rate]\nprovider = \"haveno\"").validate().unwrap_err();
        assert!(matches!(err, ConfigError::UnknownRateProvider(p) if p == "haveno"));
    }

    #[test]
    fn an_unusable_node_address_or_bind_address_is_rejected_at_startup() {
        let toml = r#"
            [monero_node.mainnet]
            host = ""
            port = 18081
        "#;
        assert!(matches!(
            Config::from_str(toml).unwrap().validate().unwrap_err(),
            ConfigError::OutOfRange { field: "monero_node.<network>.host", .. }
        ));

        let toml = r#"
            [monero_node.mainnet]
            host = "127.0.0.1"
            port = 0
        "#;
        assert!(matches!(
            Config::from_str(toml).unwrap().validate().unwrap_err(),
            ConfigError::OutOfRange { field: "monero_node.<network>.port", .. }
        ));

        assert!(matches!(
            config_with("[server]\nbind = \"not-an-address\"").validate().unwrap_err(),
            ConfigError::OutOfRange { field: "server.bind", .. }
        ));
    }

    #[test]
    fn a_malformed_zero_conf_ceiling_is_caught_at_startup_not_silently_dropped() {
        // `main` parses this with `.ok()` and treats a parse failure as "no zero-conf
        // ceiling configured" - a tenant would silently get stricter behaviour than
        // the operator asked for, with nothing logged.
        let err = config_with("[payment]\nzero_conf_max_xmr = \"1.2.3\"").validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRate { currency, .. } if currency == "payment.zero_conf_max_xmr"));
        config_with("[payment]\nzero_conf_max_xmr = \"0.5\"").validate().unwrap();
    }

    #[test]
    fn the_zero_conf_ceiling_is_denominated_in_xmr_and_the_old_fiat_name_is_refused_not_ignored() {
        // The value lands in `tenants.zero_conf_max_piconero` and is compared by
        // `derive_status` against the piconero total an order has received - so it is
        // an XMR amount and can be nothing else. Under the old key name
        // (`zero_conf_max_fiat`), and following DESIGN.md §13's own example of
        // `50.00`, an operator writing what they read as "$50" configured a 50 XMR
        // zero-conf ceiling instead: on the order of three hundred times the
        // double-spend exposure this setting exists to bound, applied silently to
        // every order.
        //
        // Serde ignores unknown keys, so simply renaming the field would have turned
        // an existing `zero_conf_max_fiat` line into *no ceiling at all* without a
        // word - safer in direction, but still a config file quietly not meaning what
        // it says. Refusing to boot is the only visible option.
        let err = config_with("[payment]\nzero_conf_max_fiat = \"50.00\"").validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroConfCeilingRenamed), "got {err}");
        assert!(
            err.to_string().contains("50 XMR") && err.to_string().contains("zero_conf_max_xmr"),
            "the error has to name both the new key and the unit that was actually being applied: {err}"
        );

        // Even a value that would parse fine is refused - the point is the unit the
        // operator believed they were writing, not whether the number is well-formed.
        assert!(matches!(
            config_with("[payment]\nzero_conf_max_fiat = \"0.25\"").validate().unwrap_err(),
            ConfigError::ZeroConfCeilingRenamed
        ));

        // And the new key carries the same value through to piconero unchanged.
        let config = config_with("[payment]\nzero_conf_max_xmr = \"0.25\"");
        config.validate().unwrap();
        assert_eq!(
            parse_xmr_to_piconero(config.payment.zero_conf_max_xmr.as_deref().unwrap()).unwrap(),
            250_000_000_000,
            "0.25 XMR, not 25 of anything else"
        );
    }

    #[test]
    fn malformed_toml_is_a_parse_error() {
        let err = Config::from_str("not valid toml [[[").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let err = Config::from_file("/nonexistent/path/moneropay.toml").unwrap_err();
        assert!(matches!(err, ConfigError::Io(_)));
    }
}
