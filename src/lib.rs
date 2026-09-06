pub mod auth;
pub mod config;
pub mod daemon;
pub mod daemon_rpc;
pub mod exchange_rate;
pub mod http;
pub mod key_custody;
pub mod network;
pub mod scanner;
pub mod status;
pub mod store;
pub mod templates;
pub mod webhook_delivery;
pub mod webhook_sign;

pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}
