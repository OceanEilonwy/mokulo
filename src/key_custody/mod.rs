//! The `KeyCustody` boundary.
//!
//! Everything on the caller's side of this trait — the HTTP API, the chain scanner,
//! the tenant registry — deals only in [`WalletHandle`]s. Nobody outside a
//! `KeyCustody` implementation ever holds a private view key in their own stack
//! frame or struct. That's the whole point of drawing the line here: it's the one
//! seam a future implementation can slot behind to change *where* key material
//! physically lives (this process's heap, a sealed enclave, a remote HSM) without
//! touching the scanner, the tenant model, or the API layer at all.
//!
//! [`PlainKeyCustody`] is the only implementation today. It keeps view pairs in
//! ordinary process memory with no encryption and no isolation from the host
//! process — appropriate for a self-hosted, single-tenant deployment, where a
//! host-level attacker already owns the one wallet on the box regardless of what
//! this backend does. A multi-tenant, hosted deployment should implement this trait
//! against a TEE (AWS Nitro Enclaves, AMD SEV-SNP) instead, so that compromising the
//! host process yields scan requests and results but never the keys that answered
//! them. See the design notes in the project README for why SGX specifically is a
//! poor fit for this workload (secret-scalar EC multiplication is exactly what its
//! published side-channel attacks target) and why VM-based isolation is preferred.

mod plain;
pub use plain::PlainKeyCustody;

use std::ops::Range;

pub use monero::cryptonote::subaddress::Index as SubaddressIndex;
pub use monero::Network;
use monero::{Address, PrivateKey, PublicKey, Transaction, ViewPair};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque reference to a registered wallet's key material.
///
/// Carries no key data itself — it's safe to log, store in SQLite next to a
/// `tenant_id`, and pass across the async/sync boundary freely. Going from a
/// `WalletHandle` back to actual scalars is only possible from inside a
/// `KeyCustody` implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalletHandle(Uuid);

impl WalletHandle {
    fn new() -> Self {
        WalletHandle(Uuid::new_v4())
    }
}

/// The watch-only key material for one tenant's wallet: a private view key and a
/// public spend key. Deliberately not a private spend key — nothing in this system
/// is ever able to construct or sign a transaction, only observe them. Losing a
/// `WalletMaterial` compromises a tenant's payment privacy; it never compromises
/// their funds.
///
/// The `Debug` impl redacts the view key on purpose — this type is likely to end up
/// in a request struct at some point, and derived `Debug` would happily print the
/// private key into a log line.
#[derive(Clone, ZeroizeOnDrop)]
pub struct WalletMaterial {
    view_key: [u8; 32],
    #[zeroize(skip)] // public by definition, nothing to protect
    spend_pubkey: [u8; 32],
}

impl WalletMaterial {
    pub fn new(view_key: [u8; 32], spend_pubkey: [u8; 32]) -> Self {
        WalletMaterial {
            view_key,
            spend_pubkey,
        }
    }

    /// Convenience constructor for the admin API, where a tenant pastes both keys as
    /// hex strings copied out of their wallet software.
    pub fn from_hex(view_key_hex: &str, spend_pubkey_hex: &str) -> Result<Self, KeyCustodyError> {
        let view_key = decode_32(view_key_hex, "view key")?;
        let spend_pubkey = decode_32(spend_pubkey_hex, "spend public key")?;
        Ok(WalletMaterial::new(view_key, spend_pubkey))
    }

    /// Only for use inside a `KeyCustody` implementation, to turn sealed/at-rest
    /// material into the crypto types needed to actually scan or derive addresses.
    /// Not `pub(crate)` because real backends (a Nitro or SEV-SNP implementation)
    /// will live in their own crates — but callers outside a `KeyCustody`
    /// implementation should never need this.
    pub fn to_view_pair(&self) -> Result<ViewPair, KeyCustodyError> {
        let view = PrivateKey::from_slice(&self.view_key)
            .map_err(|e| KeyCustodyError::InvalidKeyMaterial(format!("view key: {e}")))?;
        let spend = PublicKey::from_slice(&self.spend_pubkey)
            .map_err(|e| KeyCustodyError::InvalidKeyMaterial(format!("spend public key: {e}")))?;
        Ok(ViewPair { view, spend })
    }

    /// Raw `view_key || spend_pubkey` bytes, for a `KeyCustody` implementation's
    /// `seal` to work with. Same access-scope convention as `to_view_pair`: not
    /// `pub(crate)` since real backends live in their own crates, but nothing
    /// outside a `KeyCustody` implementation should call this.
    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.view_key);
        out[32..].copy_from_slice(&self.spend_pubkey);
        out
    }

    /// Inverse of `to_raw_bytes`, for a `KeyCustody` implementation's
    /// `unseal_and_register` to work with.
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self, KeyCustodyError> {
        if bytes.len() != 64 {
            return Err(KeyCustodyError::InvalidKeyMaterial(format!(
                "expected 64 bytes (view key || spend pubkey), got {}",
                bytes.len()
            )));
        }
        let mut view_key = [0u8; 32];
        let mut spend_pubkey = [0u8; 32];
        view_key.copy_from_slice(&bytes[..32]);
        spend_pubkey.copy_from_slice(&bytes[32..]);
        Ok(WalletMaterial::new(view_key, spend_pubkey))
    }
}

impl std::fmt::Debug for WalletMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletMaterial")
            .field("view_key", &"<redacted>")
            .field("spend_pubkey", &hex::encode(self.spend_pubkey))
            .finish()
    }
}

fn decode_32(hex_str: &str, what: &'static str) -> Result<[u8; 32], KeyCustodyError> {
    let mut bytes = hex::decode(hex_str)
        .map_err(|e| KeyCustodyError::InvalidKeyMaterial(format!("{what}: {e}")))?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(KeyCustodyError::InvalidKeyMaterial(format!(
            "{what}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum KeyCustodyError {
    #[error("no wallet registered for this handle")]
    UnknownWallet,
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
    #[error("key custody backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("scan failed: {0}")]
    ScanFailed(String),
}

/// One transaction output found to belong to a wallet during a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedOutput {
    /// Position of this output within the transaction (`vout` index).
    pub output_index: usize,
    /// Which subaddress (account/index pair) the output was paid to.
    pub subaddress_index: SubaddressIndex,
    /// Amount in piconero. `None` only if the output's amount couldn't be decrypted,
    /// which should not happen for an output this wallet actually owns.
    pub amount_piconero: Option<u64>,
}

/// The boundary between "the rest of the payment service" and "wherever tenant view
/// keys actually live." See the module docs for the threat model this exists to
/// narrow.
///
/// A note on the `major_range`/`minor_range` parameters shared by
/// `derive_subaddress` and `scan_tx_outputs`: building a lookup table for a range
/// costs one scalar multiplication per candidate index, because that's how the
/// underlying primitive works — it derives every spend key in the range up front,
/// then checks outputs against the resulting table. [`PlainKeyCustody`] amortizes
/// this by caching the table per wallet and rebuilding only when the requested range
/// actually changes, so a tenant with a stable set of pending orders pays that cost
/// once, not once per transaction scanned. That said, callers should still keep
/// ranges as tight as possible around currently-*active* (non-terminal) orders — a
/// cache only helps once it's warm, and the *first* scan after a range widens still
/// pays the full construction cost, so an ever-growing `0..next_free_index` (rather
/// than recycling minor indices from completed orders) would mean that cost keeps
/// growing indefinitely instead of staying flat. Any other `KeyCustody`
/// implementation — a future TEE-backed one included — should assume the same
/// applies and cache accordingly; this trait doesn't hide the cost model, on
/// purpose, since it's a real constraint of Monero's stealth-address design.
#[async_trait::async_trait]
pub trait KeyCustody: Send + Sync {
    /// Take ownership of freshly-submitted watch-only key material (e.g. a tenant
    /// pasting keys into the onboarding form) and return an opaque handle to it.
    /// `material` is consumed; implementations must not retain it in any form the
    /// caller can reach afterwards.
    async fn register_wallet(&self, material: WalletMaterial) -> Result<WalletHandle, KeyCustodyError>;

    /// Forget a wallet's key material entirely (tenant offboarding).
    async fn remove_wallet(&self, handle: WalletHandle) -> Result<(), KeyCustodyError>;

    /// Produce the bytes a caller should persist for this wallet — e.g. in a
    /// `tenants` table row — so it can be re-registered after a process restart,
    /// when `PlainKeyCustody`'s in-memory registry (and any handle it issued) is
    /// gone. This is deliberately a *separate* concern from the rest of this trait:
    /// everything else here is about protecting keys while they're in use; this
    /// pair (`seal`/`unseal_and_register`) is about protecting them at rest.
    /// `PlainKeyCustody` seals to plain bytes, matching its "no encryption" stance
    /// everywhere else. A TEE-backed implementation should seal to something only
    /// it (or an enclave with the same measurement) can unseal, so a stolen
    /// database file is not sufficient to recover a tenant's view key even though
    /// this same backend's job during scanning is to keep it in the clear.
    async fn seal(&self, material: &WalletMaterial) -> Result<Vec<u8>, KeyCustodyError>;

    /// Inverse of `seal`, run once at startup per stored wallet. Combines unsealing
    /// with registration in one call — sealed bytes should never come back out as a
    /// `WalletMaterial` a caller could hold onto; the only thing that leaves this
    /// call is a fresh `WalletHandle`.
    async fn unseal_and_register(&self, sealed: &[u8]) -> Result<WalletHandle, KeyCustodyError>;

    /// Derive the receiving address for one subaddress index. Requires the private
    /// view key internally, which is exactly why it lives behind this boundary
    /// rather than in the order-creation code path.
    async fn derive_subaddress(
        &self,
        handle: WalletHandle,
        index: SubaddressIndex,
        network: Network,
    ) -> Result<Address, KeyCustodyError>;

    /// Check every output of `tx` against the given index ranges, returning the
    /// ones that belong to this wallet. `tx` is public blockchain data (from the
    /// mempool or a confirmed block) — nothing about the transaction itself is
    /// sensitive, only the key used to check it.
    async fn scan_tx_outputs(
        &self,
        handle: WalletHandle,
        tx: &Transaction,
        major_range: Range<u32>,
        minor_range: Range<u32>,
    ) -> Result<Vec<MatchedOutput>, KeyCustodyError>;
}
