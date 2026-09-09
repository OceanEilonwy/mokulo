//! `moneropay-core --init`: an interactive wizard that produces (or updates) a
//! `moneropay.toml` a self-hoster never has to hand-write from scratch, and can
//! read back later without consulting the docs - see `WizardAnswers::render_toml`.
//!
//! Design points worth stating up front:
//!
//! - **One network per run.** `--init` alone configures `[monero_node.mainnet]`;
//!   `--init --stagenet` or `--init --testnet` configures that network instead.
//!   Deliberately not "pick any combination of networks in one pass": a self-hoster
//!   adding stagenet later, after mainnet is already live, is the common case this
//!   is built around, not a one-time exhaustive setup.
//! - **Merging, not overwriting.** If the target file already exists, it's parsed
//!   first (`WizardAnswers::from_existing`) and only the target network's
//!   `[monero_node.<network>]` section is added or replaced - every other section
//!   (the other networks, `[wallet]`, `[payment]`, `[server]`, `[webhooks]`,
//!   `[exchange_rate]`) carries its *value* forward unchanged. Re-running
//!   `--init --stagenet` after `--init` (mainnet) must never make the mainnet
//!   section disappear or reset.
//! - **Regenerated, not textually patched.** The merge above works by re-rendering
//!   the *entire* file from a `WizardAnswers` populated from the old one plus the
//!   new network - not a partial text edit of the old file in place. This keeps
//!   the output's "every option present, active or commented with its default"
//!   property exactly as strong on a merge run as on a first run, at the honest
//!   cost that a comment a person hand-added to a previous version of the file
//!   won't survive a re-run (the tool's own generated comments regenerate fine;
//!   nothing here tries to be a comment-preserving TOML editor). Nothing is
//!   written to disk until the very end, so a cancelled run - or one aborted by a
//!   `?` partway through - never touches the existing file.
//! - **Active vs. commented is decided by value, not provenance.** After loading
//!   (or defaulting) every setting, a field renders as an active `key = value`
//!   line if it differs from `Config`'s own hardcoded default, or as
//!   `# key = default  # note` if it matches. This is simpler than tracking
//!   "did a human type this or was it left alone" through a merge, and arguably
//!   more honest: it reflects what the file actually *does*, not how it got there.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use monero::Network;

use crate::config::{Config, ExchangeRateConfig, PaymentConfig, ServerConfig, WebhooksConfig};
use crate::network::network_str;

// ---------------------------------------------------------------------------
// CLI-facing argument parsing (pure, so `main`'s argv handling stays a thin
// wrapper and this is unit-testable without spawning a process).
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct InitArgs {
    pub network: Network,
    /// Overrides the XDG-resolved default path when given (`--init --config <path>`).
    pub config_path_override: Option<String>,
}

/// Parses the flags meaningful to `--init` out of the full argv (`--init` itself
/// included, since callers pass the whole slice) - `--stagenet`/`--testnet` select
/// the target network (mainnet if neither is given), and `--config <path>`
/// overrides where the file is read from/written to. Rejects `--stagenet` and
/// `--testnet` together: one network per run is the whole point (see the module
/// doc), so asking for both is almost certainly a misunderstanding worth failing
/// loudly on rather than silently picking one.
pub fn parse_init_args(args: &[String]) -> Result<InitArgs, String> {
    let mut network = None;
    let mut config_path_override = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--stagenet" if network.is_none() || network == Some(Network::Stagenet) => {
                network = Some(Network::Stagenet)
            }
            "--testnet" if network.is_none() || network == Some(Network::Testnet) => {
                network = Some(Network::Testnet)
            }
            "--stagenet" | "--testnet" => {
                return Err("--stagenet and --testnet cannot both be given - --init configures one network \
                             per run; run it again for the other one."
                    .to_string())
            }
            "--config" => {
                let path = iter
                    .next()
                    .ok_or_else(|| "--config needs a path argument".to_string())?;
                config_path_override = Some(path.clone());
            }
            _ => {}
        }
    }
    Ok(InitArgs { network: network.unwrap_or(Network::Mainnet), config_path_override })
}

/// `$XDG_CONFIG_HOME/moneropay/moneropay.toml` if set and non-empty (the XDG Base
/// Directory spec treats an empty value as "unset", not "the current directory"),
/// else `$HOME/.config/moneropay/moneropay.toml`. Pure function of the two
/// relevant env vars rather than reading `std::env` directly, so tests never need
/// to mutate real process environment - a real hazard under `cargo test`'s default
/// parallelism, since env vars are process-global.
pub fn resolve_config_path(xdg_config_home: Option<&str>, home: Option<&str>) -> PathBuf {
    if let Some(xdg) = xdg_config_home {
        if !xdg.is_empty() {
            return Path::new(xdg).join("moneropay").join("moneropay.toml");
        }
    }
    let home = home.unwrap_or(".");
    Path::new(home).join(".config").join("moneropay").join("moneropay.toml")
}

/// `resolve_config_path` wired to the real process environment - the only caller
/// that should ever be, outside a test.
pub fn default_config_path() -> PathBuf {
    resolve_config_path(std::env::var("XDG_CONFIG_HOME").ok().as_deref(), std::env::var("HOME").ok().as_deref())
}

/// Where the SQLite database for a given config file lives: `moneropay.db` next to
/// it, in the same directory - not, as an earlier version of `main.rs` hardcoded,
/// `./moneropay.db` relative to whatever directory the process happens to be
/// launched from. That mattered only cosmetically while the config path itself was
/// also just a bare relative filename most people ran from one fixed directory; it
/// stopped being cosmetic the moment the config started defaulting to a stable,
/// launched-from-anywhere XDG path (`default_config_path` above) - a database that
/// stayed CWD-relative would silently open a *different* file (or a fresh, empty
/// one) depending on where `moneropay-core` happened to be run from, and so would
/// every `local_admin` command below, which needs to reliably find the same
/// database the running server uses. Co-locating them means both are pinned by the
/// one thing every one of these commands already takes: the config path.
///
/// A relative config path with no directory component (`Path::parent()` returns
/// `Some("")`) still resolves the database to a bare `moneropay.db` in the current
/// directory, unchanged - the existing `e2e/` workflow (run from inside `e2e/`,
/// passing just `moneropay-stagenet.toml`) keeps working exactly as before.
pub fn database_path_for(config_path: &Path) -> PathBuf {
    config_path.parent().unwrap_or_else(|| Path::new("")).join("moneropay.db")
}

// ---------------------------------------------------------------------------
// Curated public nodes
// ---------------------------------------------------------------------------

/// `(menu label, host, port)`. Verified live/real at the time this was written -
/// see the comment on each. A self-hoster is always offered "custom" too; nothing
/// here is a recommendation to trust a third party's node for anything beyond
/// getting started; see the note this prints alongside the menu.
fn curated_nodes(network: Network) -> &'static [(&'static str, &'static str, u16)] {
    match network {
        Network::Mainnet => &[
            ("node.moneroworld.com:18089 - long-standing community-run node list", "node.moneroworld.com", 18089),
            ("node.hollingworth.xyz:18089", "node.hollingworth.xyz", 18089),
        ],
        // Verified extensively against the real chain across this project's own
        // e2e test suite (see e2e/README.md).
        Network::Stagenet => &[("node.monerodevs.org:38089", "node.monerodevs.org", 38089)],
        // From RINO's own published community node list.
        Network::Testnet => &[("testnet.community.rino.io:28081 (RINO)", "testnet.community.rino.io", 28081)],
    }
}

// ---------------------------------------------------------------------------
// Collected answers -> rendered config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct NodeAnswer {
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub accept_self_signed_certs: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WalletAnswer {
    pub primary_address: String,
    pub private_view_key: String,
    pub public_spend_key: String,
    pub network: String,
    pub allowed_origins: Vec<String>,
}

/// Every setting `Config` understands, always holding a concrete value (the
/// default if nothing else set it) - `render_toml` decides active-vs-commented by
/// comparing each one against `Config`'s own `Default` impls, not by tracking
/// separately whether a human touched it. `nodes` is the one field with no
/// "default": at least one network must end up configured for the file to be
/// bootable at all (`Config::validate`), so the wizard flow guarantees the target
/// network is always inserted before this is ever rendered.
pub struct WizardAnswers {
    pub nodes: Vec<(String, NodeAnswer)>,
    pub wallet: Option<WalletAnswer>,
    pub exchange_rate_provider: String,
    pub exchange_rates: Vec<(String, String)>,
    pub confirmations_required: u64,
    pub zero_conf_max_xmr: Option<String>,
    pub order_expiry_minutes: i64,
    pub reorg_check_depth: u64,
    pub mempool_poll_interval_ms: u64,
    pub server_bind: String,
    pub worker_threads: usize,
    pub rate_limit_per_ip_per_min: u32,
    pub max_body_bytes: usize,
    pub webhooks_allow_private_urls: bool,
    pub webhooks_delivery_timeout_ms: u64,
    pub webhooks_max_attempts: u32,
}

impl Default for WizardAnswers {
    /// A brand-new config's starting point: no networks yet (the wizard flow
    /// always adds the target one before rendering), every other section at
    /// `Config`'s own defaults.
    fn default() -> Self {
        let payment = PaymentConfig::default();
        let server = ServerConfig::default();
        let webhooks = WebhooksConfig::default();
        WizardAnswers {
            nodes: Vec::new(),
            wallet: None,
            exchange_rate_provider: ExchangeRateConfig::default().provider,
            exchange_rates: Vec::new(),
            confirmations_required: payment.confirmations_required,
            zero_conf_max_xmr: None,
            order_expiry_minutes: payment.order_expiry_minutes,
            reorg_check_depth: payment.reorg_check_depth,
            mempool_poll_interval_ms: payment.mempool_poll_interval_ms,
            server_bind: server.bind,
            worker_threads: server.worker_threads,
            rate_limit_per_ip_per_min: server.rate_limit_per_ip_per_min,
            max_body_bytes: server.max_body_bytes,
            webhooks_allow_private_urls: webhooks.allow_private_urls,
            webhooks_delivery_timeout_ms: webhooks.delivery_timeout_ms,
            webhooks_max_attempts: webhooks.max_attempts,
        }
    }
}

impl WizardAnswers {
    /// Populates every field from an already-parsed config - the merge starting
    /// point for a run against a file that already exists. `Config`'s own
    /// `#[serde(default)]` handling means `cfg`'s fields already carry real values
    /// (defaults included) regardless of which sections the file actually spelled
    /// out, so this is a straight field-by-field copy.
    pub fn from_existing(cfg: &Config) -> Self {
        let mut nodes = Vec::new();
        for (network, node) in cfg.monero_node.iter() {
            nodes.push((
                network_str(network).to_string(),
                NodeAnswer {
                    host: node.host.clone(),
                    port: node.port,
                    ssl: node.ssl,
                    accept_self_signed_certs: node.accept_self_signed_certs,
                },
            ));
        }
        let wallet = cfg.wallet.as_ref().map(|w| WalletAnswer {
            primary_address: w.primary_address.clone(),
            private_view_key: w.private_view_key.clone(),
            public_spend_key: w.public_spend_key.clone(),
            network: w.network.clone(),
            allowed_origins: w.allowed_origins.clone(),
        });
        WizardAnswers {
            nodes,
            wallet,
            exchange_rate_provider: cfg.exchange_rate.provider.clone(),
            exchange_rates: cfg.exchange_rate.rates.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            confirmations_required: cfg.payment.confirmations_required,
            zero_conf_max_xmr: cfg.payment.zero_conf_max_xmr.clone(),
            order_expiry_minutes: cfg.payment.order_expiry_minutes,
            reorg_check_depth: cfg.payment.reorg_check_depth,
            mempool_poll_interval_ms: cfg.payment.mempool_poll_interval_ms,
            server_bind: cfg.server.bind.clone(),
            worker_threads: cfg.server.worker_threads,
            rate_limit_per_ip_per_min: cfg.server.rate_limit_per_ip_per_min,
            max_body_bytes: cfg.server.max_body_bytes,
            webhooks_allow_private_urls: cfg.webhooks.allow_private_urls,
            webhooks_delivery_timeout_ms: cfg.webhooks.delivery_timeout_ms,
            webhooks_max_attempts: cfg.webhooks.max_attempts,
        }
    }

    /// Inserts or replaces `network`'s node entry, preserving every other
    /// network's position - re-running `--init` for a network already present
    /// (updating its node choice) must not reorder or duplicate the others.
    fn set_node(&mut self, network: Network, node: NodeAnswer) {
        let key = network_str(network).to_string();
        if let Some(existing) = self.nodes.iter_mut().find(|(n, _)| *n == key) {
            existing.1 = node;
        } else {
            self.nodes.push((key, node));
        }
    }

    /// Renders the complete, self-documenting config file: every field `Config`
    /// understands appears, either as a live `key = value` (when it differs from
    /// the hardcoded default) or as `# key = default  # note` (when it doesn't) -
    /// so reading the file top to bottom is a complete guide to what can be
    /// changed and what it currently is, with no need to cross-reference the docs.
    pub fn render_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# moneropay-core configuration - generated by `moneropay-core --init`.\n\
             #\n\
             # Every setting below is either active (`key = value`) or shown commented out\n\
             # with the value it defaults to if you leave it alone - uncomment and edit any\n\
             # line to change it. Re-run `moneropay-core --init` (optionally with --stagenet\n\
             # or --testnet) to add another network without disturbing what's already here.\n\n",
        );

        for (network, node) in &self.nodes {
            out.push_str(&format!("[monero_node.{network}]\n"));
            out.push_str(&format!("host = {:?}\n", node.host));
            out.push_str(&format!("port = {}\n", node.port));
            bool_line(&mut out, "ssl", node.ssl, false, "set true if this node serves RPC over HTTPS");
            bool_line(
                &mut out,
                "accept_self_signed_certs",
                node.accept_self_signed_certs,
                true,
                "most public Monero nodes self-sign; set false to require a real CA-signed cert",
            );
            out.push('\n');
        }

        match &self.wallet {
            Some(w) => {
                out.push_str(
                    "# Self-hosted bootstrap: creates the one tenant this deployment needs at first\n\
                     # boot. Omit this whole [wallet] section for a hosted instance that creates\n\
                     # tenants at runtime via the admin API instead.\n[wallet]\n",
                );
                out.push_str(&format!("primary_address = {:?}\n", w.primary_address));
                out.push_str(&format!("private_view_key = {:?}\n", w.private_view_key));
                out.push_str(&format!("public_spend_key = {:?}\n", w.public_spend_key));
                out.push_str(&format!("network = {:?}\n", w.network));
                out.push_str(&format!(
                    "allowed_origins = [{}]  # merchant site origin(s) allowed to embed the checkout widget\n",
                    w.allowed_origins.iter().map(|o| format!("{o:?}")).collect::<Vec<_>>().join(", ")
                ));
                out.push('\n');
            }
            None => {
                out.push_str(
                    "# No [wallet] section: this instance is in \"hosted\" mode - create tenants at\n\
                     # runtime via POST /api/v1/admin/tenants instead. To bootstrap a single\n\
                     # self-hosted tenant here instead, add:\n\
                     # [wallet]\n\
                     # primary_address = \"...\"\n\
                     # private_view_key = \"...\"\n\
                     # public_spend_key = \"...\"\n\
                     # network = \"mainnet\"\n\
                     # allowed_origins = [\"https://your-merchant-site.example\"]\n\n",
                );
            }
        }

        out.push_str("[exchange_rate]\n");
        str_line(&mut out, "provider", &self.exchange_rate_provider, "fixed", "\"fixed\" is the only implemented provider today");
        out.push_str("[exchange_rate.rates]\n");
        if self.exchange_rates.is_empty() {
            out.push_str(
                "# Maps a currency code to an XMR-per-unit decimal amount, e.g.:\n\
                 # USD = \"0.0067\"   # 1 USD = 0.0067 XMR\n\
                 # Every order-creation call names a fiat_currency that must have an entry here -\n\
                 # with none configured, no order can ever be created.\n",
            );
        } else {
            for (currency, rate) in &self.exchange_rates {
                out.push_str(&format!("{currency} = {rate:?}\n"));
            }
        }
        out.push('\n');

        let default_payment = PaymentConfig::default();
        out.push_str("[payment]\n");
        num_line(
            &mut out,
            "confirmations_required",
            self.confirmations_required,
            default_payment.confirmations_required,
            "blocks before a payment counts as final; 1-720",
        );
        match &self.zero_conf_max_xmr {
            Some(v) => out.push_str(&format!(
                "zero_conf_max_xmr = {v:?}  # orders at or under this many XMR are trusted before confirmation\n"
            )),
            None => out.push_str(
                "# zero_conf_max_xmr = \"0.25\"  # unset by default: nothing is trusted before confirmation.\n\
                 # An XMR amount (not fiat - see docs/DESIGN.md §13), e.g. \"0.25\". Orders at or\n\
                 # under this total are treated as paid immediately on an unconfirmed transaction.\n\
                 # Real double-spend exposure - keep it small.\n",
            ),
        }
        num_line(
            &mut out,
            "order_expiry_minutes",
            self.order_expiry_minutes,
            default_payment.order_expiry_minutes,
            "how long an unpaid order stays open; 1 minute to 1 year",
        );
        num_line(
            &mut out,
            "reorg_check_depth",
            self.reorg_check_depth,
            default_payment.reorg_check_depth,
            "how many recent blocks are re-checked for reorgs each tick; 1-10000",
        );
        num_line(
            &mut out,
            "mempool_poll_interval_ms",
            self.mempool_poll_interval_ms,
            default_payment.mempool_poll_interval_ms,
            "how often the mempool is polled for zero-conf payments; 100ms-1h",
        );
        out.push('\n');

        let default_server = ServerConfig::default();
        out.push_str("[server]\n");
        str_line(&mut out, "bind", &self.server_bind, &default_server.bind, "address:port the HTTP API listens on");
        num_line(
            &mut out,
            "worker_threads",
            self.worker_threads,
            default_server.worker_threads,
            "accepted but not yet applied - the async runtime picks its own worker count",
        );
        num_line(
            &mut out,
            "rate_limit_per_ip_per_min",
            self.rate_limit_per_ip_per_min,
            default_server.rate_limit_per_ip_per_min,
            "requests allowed per source IP per minute",
        );
        num_line(
            &mut out,
            "max_body_bytes",
            self.max_body_bytes,
            default_server.max_body_bytes,
            "largest accepted request body, in bytes",
        );
        out.push('\n');

        let default_webhooks = WebhooksConfig::default();
        out.push_str("[webhooks]\n");
        bool_line(
            &mut out,
            "allow_private_urls",
            self.webhooks_allow_private_urls,
            default_webhooks.allow_private_urls,
            "SSRF escape hatch for testing against your own LAN - leave false in production",
        );
        num_line(
            &mut out,
            "delivery_timeout_ms",
            self.webhooks_delivery_timeout_ms,
            default_webhooks.delivery_timeout_ms,
            "how long to wait for a merchant endpoint to respond; 100ms-5min",
        );
        num_line(
            &mut out,
            "max_attempts",
            self.webhooks_max_attempts,
            default_webhooks.max_attempts,
            "delivery attempts before giving up on a webhook event; 1-64",
        );

        out
    }
}

fn bool_line(out: &mut String, key: &str, value: bool, default: bool, note: &str) {
    if value == default {
        out.push_str(&format!("# {key} = {default}  # default; {note}\n"));
    } else {
        out.push_str(&format!("{key} = {value}  # {note}\n"));
    }
}

fn num_line<T: std::fmt::Display + PartialEq>(out: &mut String, key: &str, value: T, default: T, note: &str) {
    if value == default {
        out.push_str(&format!("# {key} = {default}  # default; {note}\n"));
    } else {
        out.push_str(&format!("{key} = {value}  # {note}\n"));
    }
}

fn str_line(out: &mut String, key: &str, value: &str, default: &str, note: &str) {
    if value == default {
        out.push_str(&format!("# {key} = {default:?}  # default; {note}\n"));
    } else {
        out.push_str(&format!("{key} = {value:?}  # {note}\n"));
    }
}

// ---------------------------------------------------------------------------
// The interactive driver
// ---------------------------------------------------------------------------

pub enum WizardOutcome {
    Written(PathBuf),
    Cancelled,
}

/// `pub` (not `pub(crate)`): `main.rs` is a separate binary crate depending on
/// this one, and reuses this directly for the one other place the CLI needs a
/// plain "ask a question, get a line back" prompt outside the wizard proper -
/// `--snippet`'s "what URL will customers reach this at" question.
pub fn prompt(output: &mut impl Write, input: &mut impl BufRead, question: &str, default: Option<&str>) -> io::Result<String> {
    match default {
        Some(d) if !d.is_empty() => write!(output, "{question} [{d}]: ")?,
        _ => write!(output, "{question}: ")?,
    }
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    let trimmed = line.trim();
    Ok(if trimmed.is_empty() { default.unwrap_or("").to_string() } else { trimmed.to_string() })
}

fn prompt_yes_no(output: &mut impl Write, input: &mut impl BufRead, question: &str, default_yes: bool) -> io::Result<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    let answer = prompt(output, input, &format!("{question} [{hint}]"), None)?;
    Ok(if answer.is_empty() { default_yes } else { matches!(answer.to_lowercase().as_str(), "y" | "yes") })
}

/// Presents `options` numbered from 1, `default_idx` pre-selected on Enter. Loops
/// (re-prompting) on anything that doesn't parse as a valid choice - there's no
/// reasonable way to "fail" an interactive prompt into a default, since an
/// unattended/scripted run isn't this feature's target use case.
fn prompt_choice(output: &mut impl Write, input: &mut impl BufRead, question: &str, options: &[String], default_idx: usize) -> io::Result<usize> {
    writeln!(output, "{question}")?;
    for (i, opt) in options.iter().enumerate() {
        writeln!(output, "  {}) {opt}{}", i + 1, if i == default_idx { "  (default)" } else { "" })?;
    }
    loop {
        let answer = prompt(output, input, "Choice", Some(&(default_idx + 1).to_string()))?;
        if let Ok(n) = answer.parse::<usize>() {
            if n >= 1 && n <= options.len() {
                return Ok(n - 1);
            }
        }
        writeln!(output, "Please enter a number between 1 and {}.", options.len())?;
    }
}

fn prompt_node(output: &mut impl Write, input: &mut impl BufRead, network: Network, default_node: Option<&NodeAnswer>) -> io::Result<NodeAnswer> {
    let curated = curated_nodes(network);
    let mut labels: Vec<String> = curated.iter().map(|(label, _, _)| label.to_string()).collect();
    labels.push("Custom (enter your own host/port)".to_string());
    writeln!(
        output,
        "\nChoose a {} node. Community nodes are convenient to start with, but they can see \
         (not spend) which addresses you're watching - run your own node for production if that matters to you.",
        network_str(network)
    )?;
    let default_idx = labels.len() - 1; // "custom" unless we can match an existing entry below
    let default_idx = default_node
        .and_then(|d| curated.iter().position(|(_, h, p)| h == &d.host && *p == d.port))
        .unwrap_or(default_idx);
    let choice = prompt_choice(output, input, "Node", &labels, default_idx)?;
    if let Some((_, host, port)) = curated.get(choice) {
        Ok(NodeAnswer { host: host.to_string(), port: *port, ssl: false, accept_self_signed_certs: true })
    } else {
        let host = prompt(output, input, "Host", default_node.map(|d| d.host.as_str()))?;
        let port_str = prompt(
            output,
            input,
            "Port",
            default_node.map(|d| d.port.to_string()).as_deref().or(Some("18081")),
        )?;
        let port: u16 = port_str.parse().unwrap_or(18081);
        let ssl = prompt_yes_no(output, input, "Does this node serve RPC over HTTPS?", default_node.is_some_and(|d| d.ssl))?;
        let accept_self_signed =
            prompt_yes_no(output, input, "Accept a self-signed certificate?", default_node.map(|d| d.accept_self_signed_certs).unwrap_or(true))?;
        Ok(NodeAnswer { host, port, ssl, accept_self_signed_certs: accept_self_signed })
    }
}

/// Runs the interactive wizard against `input`/`output`, targeting `network`,
/// reading and merging into (or creating fresh) whatever config already exists at
/// `config_path`. Writes only on explicit final confirmation - see the module doc
/// for why nothing touches disk before that point.
pub async fn run_interactive<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    network: Network,
    config_path: &Path,
) -> io::Result<WizardOutcome> {
    writeln!(output, "moneropay-core setup")?;
    writeln!(output, "Configuring: {}", network_str(network))?;
    writeln!(output, "Target file: {}\n", config_path.display())?;

    let mut answers = if config_path.exists() {
        match std::fs::read_to_string(config_path).ok().and_then(|s| s.parse::<Config>().ok()) {
            Some(existing) => {
                let networks: Vec<&str> = existing.monero_node.iter().map(|(n, _)| network_str(n)).collect();
                writeln!(
                    output,
                    "Found an existing config here (networks already set up: {}). It will be updated in \
                     place - everything except {} is left as it is.\n",
                    if networks.is_empty() { "none".to_string() } else { networks.join(", ") },
                    network_str(network)
                )?;
                WizardAnswers::from_existing(&existing)
            }
            None => {
                writeln!(output, "A file already exists at {} but couldn't be read as a valid config.", config_path.display())?;
                if prompt_yes_no(output, input, "Replace it with a fresh one? Nothing is written until you confirm at the end", false)? {
                    WizardAnswers::default()
                } else {
                    writeln!(output, "Leaving the existing file untouched. Nothing was changed.")?;
                    return Ok(WizardOutcome::Cancelled);
                }
            }
        }
    } else {
        WizardAnswers::default()
    };

    let mode_options = vec![
        "Simple - a sensible default setup, minimal questions".to_string(),
        "Advanced - review every setting".to_string(),
    ];
    let advanced = prompt_choice(output, input, "\nSetup mode:", &mode_options, 0)? == 1;

    let existing_node = answers.nodes.iter().find(|(n, _)| *n == network_str(network)).map(|(_, node)| node.clone());
    let node = prompt_node(output, input, network, existing_node.as_ref())?;
    answers.set_node(network, node.clone());

    writeln!(output)?;
    if prompt_yes_no(output, input, "Test this node connection now?", false)? {
        write!(output, "Connecting to {}:{}... ", node.host, node.port)?;
        output.flush()?;
        match test_node_connection(&node.host, node.port, node.ssl, node.accept_self_signed_certs).await {
            Ok(height) => writeln!(output, "reachable (current height: {height}).")?,
            Err(e) => writeln!(
                output,
                "could not connect: {e}\n  You can still save this config and fix the node setting later - \
                 a temporarily unreachable node doesn't block anything else here."
            )?,
        }
    }

    writeln!(output)?;
    let existing_wallet = answers.wallet.clone();
    match existing_wallet {
        Some(existing) => {
            writeln!(output, "An existing wallet bootstrap is configured (network: {}).", existing.network)?;
            let choices = vec![
                "Keep it as it is".to_string(),
                "Add an allowed origin to it (e.g. a new site embedding the widget)".to_string(),
                "Replace it entirely".to_string(),
            ];
            match prompt_choice(output, input, "What would you like to do?", &choices, 0)? {
                1 => {
                    let origins_raw = prompt(output, input, "New origin(s) to add (comma-separated)", None)?;
                    let mut updated = existing;
                    for origin in origins_raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        if !updated.allowed_origins.iter().any(|o| o == origin) {
                            updated.allowed_origins.push(origin.to_string());
                        }
                    }
                    answers.wallet = Some(updated);
                }
                2 => answers.wallet = prompt_wallet(output, input, &answers)?,
                _ => {} // keep as-is
            }
        }
        None => {
            if prompt_yes_no(
                output,
                input,
                "Configure a self-hosted wallet now? (You can skip this and create tenants later via the admin API)",
                false,
            )? {
                answers.wallet = prompt_wallet(output, input, &answers)?;
            }
        }
    }

    writeln!(output)?;
    if answers.exchange_rates.is_empty() {
        writeln!(output, "No fiat exchange rate is configured yet - every order-creation call needs one, or it will be rejected.")?;
        if prompt_yes_no(output, input, "Add one now?", true)? {
            prompt_exchange_rate(output, input, &mut answers)?;
        }
    } else if advanced {
        writeln!(output, "Configured exchange rates: {}", answers.exchange_rates.iter().map(|(c, _)| c.as_str()).collect::<Vec<_>>().join(", "))?;
        while prompt_yes_no(output, input, "Add another currency?", false)? {
            prompt_exchange_rate(output, input, &mut answers)?;
        }
    }

    if advanced {
        writeln!(output, "\n-- Payment settings --")?;
        answers.confirmations_required = prompt_num(output, input, "Confirmations required before an order is final (1-720)", answers.confirmations_required)?;
        let zero_conf_default = answers.zero_conf_max_xmr.clone().unwrap_or_default();
        let zero_conf =
            prompt(output, input, "Zero-conf trust ceiling in XMR (blank = disabled, nothing trusted before confirmation)", Some(&zero_conf_default))?;
        answers.zero_conf_max_xmr = if zero_conf.trim().is_empty() { None } else { Some(zero_conf) };
        answers.order_expiry_minutes = prompt_num(output, input, "Minutes before an unpaid order expires", answers.order_expiry_minutes)?;
        answers.reorg_check_depth = prompt_num(output, input, "Blocks re-checked for reorgs each tick", answers.reorg_check_depth)?;
        answers.mempool_poll_interval_ms = prompt_num(output, input, "Mempool poll interval, milliseconds", answers.mempool_poll_interval_ms)?;

        writeln!(output, "\n-- Server settings --")?;
        answers.server_bind = prompt(output, input, "Bind address", Some(&answers.server_bind))?;
        answers.rate_limit_per_ip_per_min = prompt_num(output, input, "Requests per source IP per minute", answers.rate_limit_per_ip_per_min)?;
        answers.max_body_bytes = prompt_num(output, input, "Max request body size, bytes", answers.max_body_bytes)?;

        writeln!(output, "\n-- Webhook settings --")?;
        answers.webhooks_allow_private_urls =
            prompt_yes_no(output, input, "Allow webhook URLs pointing at private/LAN addresses? (leave off in production)", answers.webhooks_allow_private_urls)?;
        answers.webhooks_delivery_timeout_ms = prompt_num(output, input, "Webhook delivery timeout, milliseconds", answers.webhooks_delivery_timeout_ms)?;
        answers.webhooks_max_attempts = prompt_num(output, input, "Webhook delivery attempts before giving up", answers.webhooks_max_attempts)?;
    }

    let rendered = answers.render_toml();
    writeln!(output, "\n----------------------------------------")?;
    write!(output, "{rendered}")?;
    writeln!(output, "----------------------------------------")?;
    if !prompt_yes_no(output, input, &format!("\nWrite this to {}?", config_path.display()), true)? {
        writeln!(output, "Nothing was written.")?;
        return Ok(WizardOutcome::Cancelled);
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, rendered)?;
    writeln!(output, "Wrote {}\n", config_path.display())?;

    let config_flag =
        if config_path == default_config_path() { String::new() } else { format!(" --config {}", config_path.display()) };
    writeln!(output, "Next steps:")?;
    if answers.wallet.is_some() {
        writeln!(output, "  1. Start the server:   moneropay-core{config_flag}")?;
        writeln!(
            output,
            "     On first boot it prints your tenant's public key (pk_...) and admin secret \
             (sk_...) - the secret is shown once, save it now."
        )?;
        writeln!(output, "  2. Get a ready-to-paste integration snippet for your site:")?;
        writeln!(output, "     moneropay-core --snippet{config_flag}")?;
    } else {
        writeln!(output, "  1. Start the server:   moneropay-core{config_flag}")?;
        writeln!(
            output,
            "     No [wallet] is configured, so this is a hosted instance - create your first \
             tenant with POST /api/v1/admin/tenants (see docs/DESIGN.md §10)."
        )?;
        writeln!(output, "  2. Get a ready-to-paste integration snippet for that tenant:")?;
        writeln!(output, "     moneropay-core --snippet{config_flag} --pk <pk_the tenant you just created>")?;
    }
    writeln!(
        output,
        "  3. If order creation fails in the browser with a CORS error, double-check `allowed_origins` \
         in the config matches your site's exact origin (scheme + host + port, no trailing slash)."
    )?;
    writeln!(output, "  4. See e2e/demo-shop/ in the source repo for a complete worked example.")?;

    Ok(WizardOutcome::Written(config_path.to_path_buf()))
}

/// The live check behind "Test this node connection now?". Talks to a real node
/// via the real `RpcDaemonClient` - `daemon_rpc.rs`'s own tests already cover that
/// client's correctness in depth, so this function isn't independently re-tested
/// here; every wizard test below declines this prompt (the default), keeping the
/// hermetic suite free of real network calls. Verified live instead, the same way
/// this whole feature was.
async fn test_node_connection(host: &str, port: u16, ssl: bool, accept_self_signed_certs: bool) -> Result<u64, String> {
    let client = crate::daemon_rpc::RpcDaemonClient::new(host, port, ssl, accept_self_signed_certs).map_err(|e| e.to_string())?;
    crate::daemon::MoneroDaemonClient::get_height(&client).await.map_err(|e| e.to_string())
}

fn prompt_num<T: std::str::FromStr + std::fmt::Display>(output: &mut impl Write, input: &mut impl BufRead, question: &str, current: T) -> io::Result<T> {
    loop {
        let answer = prompt(output, input, question, Some(&current.to_string()))?;
        match answer.parse() {
            Ok(v) => return Ok(v),
            Err(_) => writeln!(output, "Please enter a number.")?,
        }
    }
}

fn prompt_wallet<W: Write, R: BufRead>(output: &mut W, input: &mut R, answers: &WizardAnswers) -> io::Result<Option<WalletAnswer>> {
    let configured_networks: Vec<&str> = answers.nodes.iter().map(|(n, _)| n.as_str()).collect();
    let default_network = configured_networks.first().copied().unwrap_or("mainnet");
    writeln!(
        output,
        "This needs your wallet's private view key and public spend key - never the private spend \
         key. With the Monero CLI: `monero-wallet-cli --wallet-file <file> viewkey` and `spendkey` \
         (spendkey prints the private key; the public one is derived from it, or use \
         `address` and your wallet software's \"view key\" export)."
    )?;
    let primary_address = prompt(output, input, "Primary wallet address", None)?;
    let private_view_key = prompt(output, input, "Private view key (hex)", None)?;
    let public_spend_key = prompt(output, input, "Public spend key (hex)", None)?;
    let network = loop {
        let candidate = prompt(output, input, &format!("Network this wallet is on ({})", configured_networks.join(", ")), Some(default_network))?;
        if configured_networks.contains(&candidate.as_str()) {
            break candidate;
        }
        writeln!(output, "That network isn't configured yet - choose one of: {}", configured_networks.join(", "))?;
    };
    let origins_raw = prompt(output, input, "Merchant site origin(s) allowed to embed the checkout widget (comma-separated, blank for none yet)", None)?;
    let allowed_origins = origins_raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
    Ok(Some(WalletAnswer { primary_address, private_view_key, public_spend_key, network, allowed_origins }))
}

fn prompt_exchange_rate<W: Write, R: BufRead>(output: &mut W, input: &mut R, answers: &mut WizardAnswers) -> io::Result<()> {
    let currency = prompt(output, input, "Currency code", Some("USD"))?.to_uppercase();
    loop {
        let price_str = prompt(output, input, &format!("Current price of 1 XMR in {currency}"), None)?;
        match price_str.trim().parse::<f64>() {
            Ok(price) if price > 0.0 => {
                let per_unit = 1.0 / price;
                // 12 decimal places matches piconero granularity (parse_xmr_to_piconero
                // rejects more), and is generous enough that the reciprocal of any
                // sane price doesn't need more.
                let rate = format!("{per_unit:.12}");
                answers.exchange_rates.retain(|(c, _)| c != &currency);
                answers.exchange_rates.push((currency, rate));
                return Ok(());
            }
            _ => writeln!(output, "Enter a positive number, e.g. 150 or 150.25.")?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    async fn run(script: &str, network: Network, path: &Path) -> (WizardOutcome, String) {
        let mut input = Cursor::new(script.as_bytes());
        let mut output = Vec::new();
        let outcome = run_interactive(&mut input, &mut output, network, path).await.unwrap();
        (outcome, String::from_utf8(output).unwrap())
    }

    fn temp_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("moneropay_init_test_{name}_{}", uuid::Uuid::new_v4()))
    }

    // -- resolve_config_path -------------------------------------------------

    #[test]
    fn prefers_xdg_config_home_when_set_and_non_empty() {
        assert_eq!(
            resolve_config_path(Some("/xdg"), Some("/home/rachel")),
            PathBuf::from("/xdg/moneropay/moneropay.toml")
        );
    }

    #[test]
    fn falls_back_to_home_dot_config_when_xdg_is_unset() {
        assert_eq!(
            resolve_config_path(None, Some("/home/rachel")),
            PathBuf::from("/home/rachel/.config/moneropay/moneropay.toml")
        );
    }

    #[test]
    fn an_empty_xdg_config_home_is_treated_as_unset_per_the_xdg_spec() {
        assert_eq!(
            resolve_config_path(Some(""), Some("/home/rachel")),
            PathBuf::from("/home/rachel/.config/moneropay/moneropay.toml")
        );
    }

    // -- parse_init_args -------------------------------------------------

    #[test]
    fn no_network_flag_defaults_to_mainnet() {
        let args = parse_init_args(&["--init".to_string()]).unwrap();
        assert_eq!(args.network, Network::Mainnet);
        assert!(args.config_path_override.is_none());
    }

    #[test]
    fn stagenet_and_testnet_flags_select_their_network() {
        assert_eq!(parse_init_args(&["--init".to_string(), "--stagenet".to_string()]).unwrap().network, Network::Stagenet);
        assert_eq!(parse_init_args(&["--init".to_string(), "--testnet".to_string()]).unwrap().network, Network::Testnet);
    }

    #[test]
    fn stagenet_and_testnet_together_is_a_clear_error() {
        let err = parse_init_args(&["--init".to_string(), "--stagenet".to_string(), "--testnet".to_string()]).unwrap_err();
        assert!(err.contains("one network per run"), "got {err}");
    }

    #[test]
    fn config_flag_overrides_the_target_path() {
        let args = parse_init_args(&["--init".to_string(), "--config".to_string(), "/tmp/custom.toml".to_string()]).unwrap();
        assert_eq!(args.config_path_override.as_deref(), Some("/tmp/custom.toml"));
    }

    #[test]
    fn missing_config_path_value_is_a_clear_error() {
        assert!(parse_init_args(&["--init".to_string(), "--config".to_string()]).is_err());
    }

    // -- end-to-end wizard runs -----------------------------------------------

    /// Answers in order: mode(simple)=Enter, node choice=1 (curated #1), test node
    /// connection=no, wallet=no, exchange rate=yes/USD/150, final confirm=yes.
    fn simple_mainnet_script() -> String {
        "\n1\nn\nn\ny\nUSD\n150\ny\n".to_string()
    }

    #[tokio::test]
    async fn simple_mode_produces_a_valid_bootable_config() {
        let path = temp_config_path("simple");
        let (outcome, transcript) = run(&simple_mainnet_script(), Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Written(_)));
        assert!(transcript.contains("Simple"), "should have offered the mode choice");

        let config = Config::from_file(path.to_str().unwrap()).unwrap();
        config.validate().unwrap();
        assert!(config.monero_node.get(Network::Mainnet).is_some());
        assert_eq!(config.monero_node.get(Network::Mainnet).unwrap().host, "node.moneroworld.com");
        assert!(config.wallet.is_none(), "wallet setup was declined");
        assert_eq!(
            crate::exchange_rate::parse_xmr_to_piconero(config.exchange_rate.rates.get("USD").unwrap()).unwrap(),
            crate::exchange_rate::parse_xmr_to_piconero(&format!("{:.12}", 1.0f64 / 150.0)).unwrap()
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn every_config_field_name_appears_in_the_generated_file() {
        // The user-facing guarantee this whole feature exists for: whether active
        // or commented out, every setting `Config` understands is visible without
        // reading the docs.
        let path = temp_config_path("exhaustive");
        // Advanced mode this time, so every section actually gets walked and every
        // field name is exercised by the wizard itself, not just present via a
        // default render. mode=2(advanced), node=1, test node connection=n, wallet=n,
        // rate=y/USD/150, then 11 blank (default) answers through every advanced-mode
        // field (confirmations, zero_conf, expiry, reorg, poll, bind, rate_limit,
        // max_body, allow_private, timeout, max_attempts), final=y.
        let script = format!("2\n1\nn\nn\ny\nUSD\n150\n{}y\n", "\n".repeat(11));
        let (outcome, _) = run(&script, Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Written(_)));

        let rendered = std::fs::read_to_string(&path).unwrap();
        let expected_fields = [
            "host", "port", "ssl", "accept_self_signed_certs",
            "provider",
            "confirmations_required", "zero_conf_max_xmr", "order_expiry_minutes", "reorg_check_depth", "mempool_poll_interval_ms",
            "bind", "worker_threads", "rate_limit_per_ip_per_min", "max_body_bytes",
            "allow_private_urls", "delivery_timeout_ms", "max_attempts",
        ];
        for field in expected_fields {
            assert!(rendered.contains(field), "missing {field} in:\n{rendered}");
        }
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn advanced_mode_custom_values_round_trip_into_the_parsed_config() {
        let path = temp_config_path("advanced");
        // mode=2(advanced), node=3(mainnet's curated list has 2 entries, so
        // "custom" is choice 3: host/port/ssl=n/self-signed=n),
        // test node connection=n, wallet=n, rate (exchange_rates starts empty so this
        // is a one-shot "add one now?" prompt, not the advanced-mode add-another
        // loop): y/EUR/200,
        // payment: confirmations=5, zero_conf=0.1, expiry=45, reorg=30, poll=2000,
        // server: bind=127.0.0.1:9999, rate_limit=99, max_body=4096,
        // webhooks: allow_private=y, timeout=1234, attempts=3,
        // final confirm=y
        let script = "2\n3\nnode.example.org\n18081\nn\nn\nn\nn\ny\nEUR\n200\n5\n0.1\n45\n30\n2000\n127.0.0.1:9999\n99\n4096\ny\n1234\n3\ny\n";
        let (outcome, _) = run(script, Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Written(_)));

        let config = Config::from_file(path.to_str().unwrap()).unwrap();
        config.validate().unwrap();
        let node = config.monero_node.get(Network::Mainnet).unwrap();
        assert_eq!(node.host, "node.example.org");
        assert!(!node.accept_self_signed_certs);
        assert_eq!(config.payment.confirmations_required, 5);
        assert_eq!(config.payment.zero_conf_max_xmr.as_deref(), Some("0.1"));
        assert_eq!(config.payment.order_expiry_minutes, 45);
        assert_eq!(config.payment.reorg_check_depth, 30);
        assert_eq!(config.payment.mempool_poll_interval_ms, 2000);
        assert_eq!(config.server.bind, "127.0.0.1:9999");
        assert_eq!(config.server.rate_limit_per_ip_per_min, 99);
        assert_eq!(config.server.max_body_bytes, 4096);
        assert!(config.webhooks.allow_private_urls);
        assert_eq!(config.webhooks.delivery_timeout_ms, 1234);
        assert_eq!(config.webhooks.max_attempts, 3);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_second_run_for_a_different_network_preserves_the_first_networks_settings_unchanged() {
        let path = temp_config_path("merge");
        run(&simple_mainnet_script(), Network::Mainnet, &path).await;
        let after_first = std::fs::read_to_string(&path).unwrap();
        assert!(after_first.contains("node.moneroworld.com"));

        // Second run targets stagenet: mode(simple), node choice=1, test node
        // connection=no, wallet=no (none exists yet), exchange rate already
        // configured + not advanced so no re-prompt, final confirm=yes.
        let script = "\n1\nn\nn\ny\n";
        let (outcome, transcript) = run(script, Network::Stagenet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Written(_)));
        assert!(transcript.contains("mainnet"), "should have announced the existing network: {transcript}");

        let config = Config::from_file(path.to_str().unwrap()).unwrap();
        config.validate().unwrap();
        // Mainnet untouched...
        assert_eq!(config.monero_node.get(Network::Mainnet).unwrap().host, "node.moneroworld.com");
        // ...and stagenet added alongside it.
        assert_eq!(config.monero_node.get(Network::Stagenet).unwrap().host, "node.monerodevs.org");
        // The exchange rate from the first run survived the second run untouched.
        assert!(config.exchange_rate.rates.contains_key("USD"));
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn re_running_for_the_same_network_updates_just_that_networks_node_and_nothing_else() {
        let path = temp_config_path("re-run-same-network");
        run(&simple_mainnet_script(), Network::Mainnet, &path).await;

        // mode(simple), node choice=2 (the second curated mainnet entry this time),
        // test node connection=no, wallet stays declined, no new rate needed,
        // confirm=yes.
        let script = "\n2\nn\nn\ny\n";
        run(script, Network::Mainnet, &path).await;

        let config = Config::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(config.monero_node.get(Network::Mainnet).unwrap().host, "node.hollingworth.xyz");
        assert_eq!(config.monero_node.iter().count(), 1, "still exactly one network");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn declining_the_final_confirmation_writes_nothing() {
        let path = temp_config_path("declined");
        let script = "\n1\nn\nn\ny\nUSD\n150\nn\n"; // final answer: n
        let (outcome, _) = run(script, Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Cancelled));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn declining_the_final_confirmation_on_a_merge_run_leaves_the_existing_file_byte_for_byte_unchanged() {
        let path = temp_config_path("declined-merge");
        run(&simple_mainnet_script(), Network::Mainnet, &path).await;
        let before = std::fs::read_to_string(&path).unwrap();

        let script = "\n1\nn\nn\nn\n"; // node=1, test node connection=n, wallet=n, (rates already configured + simple mode = no rate prompt), final=n
        let (outcome, _) = run(script, Network::Stagenet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Cancelled));

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "declining must not modify the file at all");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_malformed_existing_file_is_not_silently_clobbered() {
        let path = temp_config_path("malformed");
        std::fs::write(&path, "this is not valid toml [[[").unwrap();

        let script = "n\n"; // decline replacing it
        let (outcome, transcript) = run(script, Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Cancelled));
        assert!(transcript.contains("couldn't be read"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "this is not valid toml [[[");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_malformed_existing_file_can_be_explicitly_replaced() {
        let path = temp_config_path("malformed-replace");
        std::fs::write(&path, "this is not valid toml [[[").unwrap();

        let script = format!("y\n{}", simple_mainnet_script());
        let (outcome, _) = run(&script, Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Written(_)));
        Config::from_file(path.to_str().unwrap()).unwrap().validate().unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn an_existing_wallet_section_is_offered_to_keep_and_is_preserved_when_kept() {
        let path = temp_config_path("wallet-kept");
        // First run: configure mainnet with a wallet. mode(simple), node=1, test
        // node connection=n, wallet configure(none existing)=y, then wallet fields,
        // rate=y/USD/150, final=y.
        let script = "\n1\nn\ny\n4abc\nviewkeyhex\nspendkeyhex\nmainnet\nhttps://merchant.example\ny\nUSD\n150\ny\n";
        run(script, Network::Mainnet, &path).await;
        let config = Config::from_file(path.to_str().unwrap()).unwrap();
        assert!(config.wallet.is_some());

        // Second run for stagenet: keep the existing wallet as-is. node=1, test node
        // connection=n, then the wallet choice is now a 3-way `prompt_choice` -
        // "1" (or blank) selects "Keep it as it is" - final=y.
        let script2 = "\n1\nn\n1\ny\n";
        run(script2, Network::Stagenet, &path).await;
        let config2 = Config::from_file(path.to_str().unwrap()).unwrap();
        let wallet = config2.wallet.unwrap();
        assert_eq!(wallet.primary_address, "4abc");
        assert_eq!(wallet.network, "mainnet");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn wallet_network_must_be_one_of_the_configured_networks() {
        let path = temp_config_path("wallet-bad-network");
        // mode(simple), node=1, test node connection=n, wallet configure=y, then
        // wallet fields: try "testnet" (not configured) first, get rejected, then
        // "mainnet", origins=blank, rate=y/USD/150, final=y.
        let script = "\n1\nn\ny\n4abc\nviewkeyhex\nspendkeyhex\ntestnet\nmainnet\n\ny\nUSD\n150\ny\n";
        let (outcome, transcript) = run(script, Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Written(_)));
        assert!(transcript.contains("isn't configured yet"));
        let config = Config::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(config.wallet.unwrap().network, "mainnet");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn custom_node_entry_is_used_verbatim() {
        let path = temp_config_path("custom-node");
        // Mainnet's curated list has 2 entries, so "custom" is choice 3.
        // host/port/ssl=y/self-signed=n, test node connection=n, wallet=n,
        // rate=y/USD/150, final=y.
        let script = "\n3\nnode.mine.example\n18089\ny\nn\nn\nn\ny\nUSD\n150\ny\n";
        run(script, Network::Mainnet, &path).await;
        let config = Config::from_file(path.to_str().unwrap()).unwrap();
        let node = config.monero_node.get(Network::Mainnet).unwrap();
        assert_eq!(node.host, "node.mine.example");
        assert_eq!(node.port, 18089);
        assert!(node.ssl);
        assert!(!node.accept_self_signed_certs);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn declining_the_exchange_rate_prompt_still_leaves_documented_syntax_in_the_file() {
        let path = temp_config_path("no-rate");
        let script = "\n1\nn\nn\nn\ny\n"; // node=1, test node connection=n, wallet=n, add rate=n, confirm=y
        let (outcome, _) = run(script, Network::Mainnet, &path).await;
        assert!(matches!(outcome, WizardOutcome::Written(_)));
        let rendered = std::fs::read_to_string(&path).unwrap();
        assert!(rendered.contains("[exchange_rate.rates]"));
        assert!(rendered.contains("USD = \"0.0067\""), "documented example syntax should still be shown: {rendered}");
        // Still parses, just can't create an order until a rate is added.
        Config::from_file(path.to_str().unwrap()).unwrap().validate().unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn default_valued_fields_render_commented_and_non_default_ones_render_active() {
        let answers = WizardAnswers {
            nodes: vec![("mainnet".to_string(), NodeAnswer { host: "n.example".to_string(), port: 18081, ssl: false, accept_self_signed_certs: true })],
            confirmations_required: 10, // matches PaymentConfig::default()
            order_expiry_minutes: 999,  // does not match the default of 30
            ..WizardAnswers::default()
        };
        let rendered = answers.render_toml();
        assert!(rendered.contains("# confirmations_required = 10"), "default value should be commented: {rendered}");
        assert!(rendered.contains("order_expiry_minutes = 999") && !rendered.contains("# order_expiry_minutes"), "non-default value should be active: {rendered}");
    }
}
