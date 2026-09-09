//! Top-level argv parsing for the `moneropay-core` binary - kept in the lib crate
//! (not `main.rs`) so it's unit-testable the normal way, and so `main.rs` stays a
//! thin wrapper around whatever this decides the process should do.

use std::path::PathBuf;

use crate::init_wizard::{self, InitArgs};

#[derive(Debug)]
pub enum Action {
    RunServer { config_path: PathBuf, strict_tls: bool },
    Init(InitArgs),
    /// Mints a fresh admin secret for a tenant, invalidating the old one - see
    /// `local_admin::rotate_secret`.
    RotateSecret { config_path: PathBuf, pk: Option<String> },
    /// Prints a tenant's non-secret settings - see `local_admin::show_tenant`.
    ShowTenant { config_path: PathBuf, pk: Option<String> },
    /// Prints a ready-to-paste widget integration snippet - see `local_admin::snippet`.
    Snippet { config_path: PathBuf, pk: Option<String>, endpoint: Option<String> },
    Help,
}

pub const HELP_TEXT: &str = "\
moneropay-core - a self-hosted Monero payment gateway

USAGE:
    moneropay-core [OPTIONS] [CONFIG_PATH]
    moneropay-core --init [--stagenet | --testnet] [--config <PATH>]
    moneropay-core --rotate-secret [--config <PATH>] [--pk <PK>]
    moneropay-core --show-tenant [--config <PATH>] [--pk <PK>]
    moneropay-core --snippet [--config <PATH>] [--pk <PK>] [--endpoint <URL>]

With no other mode, starts the HTTP server, reading its configuration from
CONFIG_PATH (or --config PATH) if given, otherwise from the default location:

    $XDG_CONFIG_HOME/moneropay/moneropay.toml
    (falling back to $HOME/.config/moneropay/moneropay.toml if
    XDG_CONFIG_HOME is unset or empty)

which is also where `--init` writes to by default, and where the database
(`moneropay.db`, alongside the config) is read from by every mode below -
running `moneropay-core` with no arguments after `moneropay-core --init` finds
the file it just wrote, and every other command below finds the same database
the running server uses, without needing to be told where it is.

OPTIONS:
    --config <PATH>   Path to the config file, for every mode. Equivalent to
                      passing PATH positionally when starting the server;
                      takes precedence if both are given.
    --strict-tls      Require a real CA-signed certificate from every configured
                      node, overriding accept_self_signed_certs in the config
                      file. Only meaningful when starting the server.
    --init            Run the interactive setup wizard instead of starting the
                      server. Configures mainnet by default; combine with
                      --stagenet or --testnet to add or update that network
                      instead. Safe to re-run against an existing config file -
                      it's merged into, not overwritten.
    --rotate-secret   Mint a fresh admin secret (sk_...) for a tenant,
                      invalidating the old one - the only way back in if you've
                      lost it. Needs the server to have been started at least
                      once (a tenant has to exist first).
    --show-tenant     Print a tenant's current settings (public key, network,
                      address, allowed origins, thresholds) - never its keys or
                      secret.
    --snippet         Print a ready-to-paste HTML/JS snippet that embeds the
                      checkout widget on your site, pre-filled with a real
                      tenant's public key. --endpoint <URL> is the address
                      customers will actually reach this server at (through
                      any reverse proxy/domain in front of it) - you'll be
                      asked for it if you don't pass it.
    --pk <PK>         Which tenant --rotate-secret/--show-tenant/--snippet act
                      on. Only needed if more than one tenant is configured -
                      the common, self-hosted, single-tenant case is found
                      automatically.
    --help, -h        Print this help and exit.

EXAMPLES:
    moneropay-core                       Start the server using the default config location.
    moneropay-core --config my.toml      Start the server using a specific config file.
    moneropay-core my.toml               Same as above (positional form).
    moneropay-core --init                Walk through setting up mainnet.
    moneropay-core --init --stagenet     Add or update stagenet in the existing config.
    moneropay-core --snippet --endpoint https://pay.example.com
                                          Print the paste-ready widget snippet for your site.
";

/// Parses the full process argv (excluding argv[0]). `--help`/`-h` short-circuits
/// everything else - present anywhere, it wins. `--init` (checked next) hands the
/// rest of the args to `init_wizard::parse_init_args`, which owns the
/// `--stagenet`/`--testnet`/`--config` grammar for that mode. Otherwise this is a
/// normal server run: `--config <path>` or a bare positional argument names the
/// config file (the former winning if both are somehow given), falling back to
/// the same XDG-resolved default `--init` itself writes to when neither is given,
/// which is the fix for a server started with no arguments not finding a file
/// `--init` just wrote - the whole point of resolving it the same way in both
/// places rather than defaulting to a bare relative "moneropay.toml".
pub fn parse_args(args: &[String]) -> Result<Action, String> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Action::Help);
    }
    if args.iter().any(|a| a == "--init") {
        return init_wizard::parse_init_args(args).map(Action::Init);
    }
    if args.iter().any(|a| a == "--rotate-secret") {
        let parsed = parse_local_admin_args(args)?;
        return Ok(Action::RotateSecret { config_path: parsed.config_path, pk: parsed.pk });
    }
    if args.iter().any(|a| a == "--show-tenant") {
        let parsed = parse_local_admin_args(args)?;
        return Ok(Action::ShowTenant { config_path: parsed.config_path, pk: parsed.pk });
    }
    if args.iter().any(|a| a == "--snippet") {
        let parsed = parse_local_admin_args(args)?;
        return Ok(Action::Snippet { config_path: parsed.config_path, pk: parsed.pk, endpoint: parsed.endpoint });
    }

    let mut config_path_override: Option<String> = None;
    let mut positional: Option<String> = None;
    let mut strict_tls = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--strict-tls" => strict_tls = true,
            "--config" => {
                let path = iter.next().ok_or_else(|| "--config needs a path argument".to_string())?;
                config_path_override = Some(path.clone());
            }
            other => positional = Some(other.to_string()),
        }
    }
    let config_path =
        config_path_override.or(positional).map(PathBuf::from).unwrap_or_else(init_wizard::default_config_path);
    Ok(Action::RunServer { config_path, strict_tls })
}

struct LocalAdminArgs {
    config_path: PathBuf,
    pk: Option<String>,
    endpoint: Option<String>,
}

/// Shared `--config`/`--pk`/`--endpoint` parsing for `--rotate-secret`,
/// `--show-tenant`, and `--snippet` - the three modes that act on the local
/// database rather than starting the server or the wizard. `--endpoint` is
/// harmless to parse even for the two modes that ignore it (`--rotate-secret`,
/// `--show-tenant`); not erroring on an unused-but-recognized flag is friendlier
/// than making the three modes subtly different in what they'll accept.
fn parse_local_admin_args(args: &[String]) -> Result<LocalAdminArgs, String> {
    let mut config_path_override = None;
    let mut pk = None;
    let mut endpoint = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                let path = iter.next().ok_or_else(|| "--config needs a path argument".to_string())?;
                config_path_override = Some(path.clone());
            }
            "--pk" => {
                let value = iter.next().ok_or_else(|| "--pk needs a value".to_string())?;
                pk = Some(value.clone());
            }
            "--endpoint" => {
                let value = iter.next().ok_or_else(|| "--endpoint needs a value".to_string())?;
                endpoint = Some(value.clone());
            }
            _ => {}
        }
    }
    let config_path = config_path_override.map(PathBuf::from).unwrap_or_else(init_wizard::default_config_path);
    Ok(LocalAdminArgs { config_path, pk, endpoint })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_arguments_falls_back_to_the_xdg_resolved_default_path() {
        // The bug this module exists to fix: a server started bare must look in
        // the same place `--init` writes to by default, not a hardcoded relative
        // "moneropay.toml" in whatever directory it happens to be launched from.
        match parse_args(&args(&[])).unwrap() {
            Action::RunServer { config_path, strict_tls } => {
                assert_eq!(config_path, init_wizard::default_config_path());
                assert!(!strict_tls);
            }
            _ => panic!("expected RunServer"),
        }
    }

    #[test]
    fn a_bare_positional_argument_is_the_config_path() {
        match parse_args(&args(&["my.toml"])).unwrap() {
            Action::RunServer { config_path, .. } => assert_eq!(config_path, PathBuf::from("my.toml")),
            _ => panic!("expected RunServer"),
        }
    }

    #[test]
    fn the_config_flag_names_the_config_path() {
        match parse_args(&args(&["--config", "my.toml"])).unwrap() {
            Action::RunServer { config_path, .. } => assert_eq!(config_path, PathBuf::from("my.toml")),
            _ => panic!("expected RunServer"),
        }
    }

    #[test]
    fn the_config_flag_wins_over_a_positional_argument_when_both_are_given() {
        match parse_args(&args(&["positional.toml", "--config", "flagged.toml"])).unwrap() {
            Action::RunServer { config_path, .. } => assert_eq!(config_path, PathBuf::from("flagged.toml")),
            _ => panic!("expected RunServer"),
        }
    }

    #[test]
    fn missing_config_path_value_is_a_clear_error_not_a_panic() {
        assert!(parse_args(&args(&["--config"])).is_err());
    }

    #[test]
    fn strict_tls_combines_with_a_config_path() {
        match parse_args(&args(&["--strict-tls", "my.toml"])).unwrap() {
            Action::RunServer { config_path, strict_tls } => {
                assert!(strict_tls);
                assert_eq!(config_path, PathBuf::from("my.toml"));
            }
            _ => panic!("expected RunServer"),
        }
    }

    #[test]
    fn help_flag_wins_over_everything_else_wherever_it_appears() {
        assert!(matches!(parse_args(&args(&["--help"])).unwrap(), Action::Help));
        assert!(matches!(parse_args(&args(&["-h"])).unwrap(), Action::Help));
        assert!(matches!(parse_args(&args(&["--init", "--stagenet", "--help"])).unwrap(), Action::Help));
        assert!(matches!(parse_args(&args(&["my.toml", "--help"])).unwrap(), Action::Help));
    }

    #[test]
    fn init_flag_delegates_to_the_wizards_own_argument_parsing() {
        match parse_args(&args(&["--init"])).unwrap() {
            Action::Init(init_args) => assert_eq!(init_args.network, monero::Network::Mainnet),
            _ => panic!("expected Init"),
        }
        match parse_args(&args(&["--init", "--stagenet"])).unwrap() {
            Action::Init(init_args) => assert_eq!(init_args.network, monero::Network::Stagenet),
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn init_flag_surfaces_the_wizards_own_argument_errors() {
        // --stagenet + --testnet together is init_wizard::parse_init_args's own
        // error - this just confirms it actually propagates through this layer
        // rather than being swallowed or panicking.
        let err = parse_args(&args(&["--init", "--stagenet", "--testnet"])).unwrap_err();
        assert!(err.contains("one network per run"), "got {err}");
    }

    #[test]
    fn help_text_documents_every_real_flag() {
        for flag in [
            "--config", "--strict-tls", "--init", "--stagenet", "--testnet", "--rotate-secret", "--show-tenant",
            "--snippet", "--pk", "--endpoint", "--help",
        ] {
            assert!(HELP_TEXT.contains(flag), "help text should mention {flag}");
        }
    }

    #[test]
    fn rotate_secret_flag_defaults_to_the_default_config_path_and_no_pk() {
        match parse_args(&args(&["--rotate-secret"])).unwrap() {
            Action::RotateSecret { config_path, pk } => {
                assert_eq!(config_path, init_wizard::default_config_path());
                assert!(pk.is_none());
            }
            _ => panic!("expected RotateSecret"),
        }
    }

    #[test]
    fn show_tenant_flag_accepts_config_and_pk_overrides() {
        match parse_args(&args(&["--show-tenant", "--config", "my.toml", "--pk", "pk_abc"])).unwrap() {
            Action::ShowTenant { config_path, pk } => {
                assert_eq!(config_path, PathBuf::from("my.toml"));
                assert_eq!(pk.as_deref(), Some("pk_abc"));
            }
            _ => panic!("expected ShowTenant"),
        }
    }

    #[test]
    fn snippet_flag_accepts_an_endpoint_override() {
        match parse_args(&args(&["--snippet", "--endpoint", "https://pay.example.com"])).unwrap() {
            Action::Snippet { endpoint, pk, .. } => {
                assert_eq!(endpoint.as_deref(), Some("https://pay.example.com"));
                assert!(pk.is_none());
            }
            _ => panic!("expected Snippet"),
        }
    }

    #[test]
    fn help_still_wins_over_the_new_local_admin_flags() {
        assert!(matches!(parse_args(&args(&["--rotate-secret", "--help"])).unwrap(), Action::Help));
        assert!(matches!(parse_args(&args(&["--snippet", "--help"])).unwrap(), Action::Help));
    }
}
