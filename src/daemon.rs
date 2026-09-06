//! `MoneroDaemonClient`: the trait wrapping calls the chain scanner needs against
//! `monerod`, so reorg/double-spend logic (`src/scanner.rs`) can be tested against a
//! deterministic scripted fake instead of a live node. See `docs/DESIGN.md` §7.1.
//!
//! The real implementation (talking to `monerod` over `reqwest` + `rustls`) is not
//! part of this pass - only the trait, its types, and the test double are
//! implemented here, since the reorg/double-spend *logic* behind this boundary is
//! the part worth getting right and testing thoroughly before wiring up the RPC
//! plumbing on the other side of it.

use monero::Transaction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyImageStatus {
    Unspent,
    SpentInBlockchain,
    SpentInPool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxLocation {
    InBlock(u64),
    InPool,
    NotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("daemon request failed: {0}")]
    Request(String),
}

#[async_trait::async_trait]
pub trait MoneroDaemonClient: Send + Sync {
    async fn get_height(&self) -> Result<u64, DaemonError>;
    async fn get_block_hash(&self, height: u64) -> Result<String, DaemonError>;
    async fn get_block_transactions(&self, height: u64) -> Result<Vec<Transaction>, DaemonError>;
    async fn get_mempool_transactions(&self) -> Result<Vec<Transaction>, DaemonError>;
    async fn locate_transaction(&self, txid: &str) -> Result<TxLocation, DaemonError>;
    async fn is_key_image_spent(&self, key_images: &[String]) -> Result<Vec<KeyImageStatus>, DaemonError>;
}

/// Test double for `MoneroDaemonClient`, scripted via a small timeline API. Lets
/// reorg/double-spend scenarios be constructed deterministically, without a live or
/// regtest `monerod` - see `docs/TESTING.md` §3 for why this matters (reorgs are
/// rare in production, so bugs here are exactly the kind that go unnoticed for a
/// long time otherwise).
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct FakeBlock {
        hash: String,
        txs: Vec<Transaction>,
    }

    #[derive(Default)]
    struct State {
        blocks: HashMap<u64, FakeBlock>,
        height: u64,
        /// When set, `get_height` reports this instead of `height` - models a
        /// public endpoint's height-reporting backend being temporarily ahead of
        /// whatever backend actually serves block data, an inconsistency observed
        /// live against a real public node (see `run_scan_tick`'s bootstrap
        /// branch). Deliberately independent of `height`, which `push_block` still
        /// uses for its own auto-increment - the two heights need to be able to
        /// disagree for the scenario this exists to model.
        height_override: Option<u64>,
        mempool: Vec<Transaction>,
        /// txid -> location, explicitly tracked rather than derived from `blocks`
        /// so a test can put a tx "in the pool" without it ever having been mined,
        /// or mark it fully gone (NotFound) after a reorg.
        tx_locations: HashMap<String, TxLocation>,
        key_image_status: HashMap<String, KeyImageStatus>,
    }

    #[derive(Default)]
    pub struct FakeDaemonClient {
        state: Mutex<State>,
    }

    fn txid_of(tx: &Transaction) -> String {
        // Must match production's txid computation exactly (see
        // `scanner::tx_id_hex`) - a test double using a different identity scheme
        // than the real scanner would silently make every `locate_transaction`
        // lookup miss, since the scanner records payments keyed by the real hash.
        use monero::cryptonote::hash::Hashable;
        hex::encode(tx.hash().to_bytes())
    }

    impl FakeDaemonClient {
        pub fn new() -> Self {
            Self::default()
        }

        /// Mines a new block at the next height, containing `txs`. Each tx is
        /// recorded as `InBlock(height)`, matching what a real node would report.
        pub fn push_block(&self, hash: &str, txs: Vec<Transaction>) -> u64 {
            let mut state = self.state.lock().unwrap();
            let height = state.height + 1;
            for tx in &txs {
                state.tx_locations.insert(txid_of(tx), TxLocation::InBlock(height));
            }
            state.blocks.insert(height, FakeBlock { hash: hash.to_string(), txs });
            state.height = height;
            state.height_override = None; // a real block now backs this height - any prior lag is resolved
            height
        }

        /// Places a block at an explicit height, rather than at "one past the last
        /// one pushed". The only way to script a chain that includes height 0:
        /// `push_block` starts counting at 1, so the genesis-divergence branch of
        /// reorg handling (no common ancestor to re-anchor to) is otherwise
        /// unreachable from a test. Also useful for building a chain around a gap.
        pub fn seed_block_at(&self, height: u64, hash: &str, txs: Vec<Transaction>) {
            let mut state = self.state.lock().unwrap();
            for tx in &txs {
                state.tx_locations.insert(txid_of(tx), TxLocation::InBlock(height));
            }
            state.blocks.insert(height, FakeBlock { hash: hash.to_string(), txs });
            state.height = state.height.max(height);
        }

        /// Makes `get_height` report one past the last real block, without that
        /// block actually existing - models a public endpoint's height-reporting
        /// backend being briefly ahead of its block-serving backend. See
        /// `height_override`'s doc comment.
        pub fn advance_height_without_a_block(&self) {
            let mut state = self.state.lock().unwrap();
            state.height_override = Some(state.height + 1);
        }

        /// Makes `get_height` report an arbitrary height, however far from the
        /// blocks this fake can actually serve. The generalisation of
        /// `advance_height_without_a_block`, for the case where the discrepancy is
        /// not a one-block lag but a daemon simply asserting something untrue - see
        /// `docs/DESIGN.md` §7.7 on what the scanner does and does not take on
        /// trust from its configured node.
        pub fn report_height(&self, height: u64) {
            self.state.lock().unwrap().height_override = Some(height);
        }

        pub fn set_mempool(&self, txs: Vec<Transaction>) {
            let mut state = self.state.lock().unwrap();
            for tx in &txs {
                state.tx_locations.entry(txid_of(tx)).or_insert(TxLocation::InPool);
            }
            state.mempool = txs;
        }

        /// Simulates a reorg: replaces every block from `from_height` to the
        /// current tip with `new_blocks` (each `(hash, txs)`), re-tagging every
        /// previously-known tx that isn't in one of the new blocks as `NotFound`
        /// (the caller then decides, via `set_key_image_status`, whether that's a
        /// "still propagating" or "proven double-spend" situation).
        pub fn reorg_from(&self, from_height: u64, new_blocks: Vec<(&str, Vec<Transaction>)>) {
            let mut state = self.state.lock().unwrap();
            let old_txids: Vec<String> = state
                .blocks
                .iter()
                .filter(|(h, _)| **h >= from_height)
                .flat_map(|(_, b)| b.txs.iter().map(txid_of))
                .collect();
            state.blocks.retain(|h, _| *h < from_height);

            let mut height = from_height - 1;
            let mut new_txids = Vec::new();
            for (hash, txs) in new_blocks {
                height += 1;
                for tx in &txs {
                    let id = txid_of(tx);
                    state.tx_locations.insert(id.clone(), TxLocation::InBlock(height));
                    new_txids.push(id);
                }
                state.blocks.insert(height, FakeBlock { hash: hash.to_string(), txs });
            }
            state.height = height;

            for txid in old_txids {
                if !new_txids.contains(&txid) {
                    state.tx_locations.insert(txid, TxLocation::NotFound);
                }
            }
        }

        pub fn set_key_image_status(&self, key_image_hex: &str, status: KeyImageStatus) {
            self.state.lock().unwrap().key_image_status.insert(key_image_hex.to_string(), status);
        }

        pub fn drop_from_mempool(&self, tx: &Transaction) {
            let mut state = self.state.lock().unwrap();
            state.mempool.retain(|t| txid_of(t) != txid_of(tx));
            state.tx_locations.insert(txid_of(tx), TxLocation::NotFound);
        }
    }

    #[async_trait::async_trait]
    impl MoneroDaemonClient for FakeDaemonClient {
        async fn get_height(&self) -> Result<u64, DaemonError> {
            let state = self.state.lock().unwrap();
            Ok(state.height_override.unwrap_or(state.height))
        }

        async fn get_block_hash(&self, height: u64) -> Result<String, DaemonError> {
            self.state
                .lock()
                .unwrap()
                .blocks
                .get(&height)
                .map(|b| b.hash.clone())
                .ok_or_else(|| DaemonError::Request(format!("no block at height {height}")))
        }

        async fn get_block_transactions(&self, height: u64) -> Result<Vec<Transaction>, DaemonError> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .blocks
                .get(&height)
                .map(|b| b.txs.clone())
                .unwrap_or_default())
        }

        async fn get_mempool_transactions(&self) -> Result<Vec<Transaction>, DaemonError> {
            Ok(self.state.lock().unwrap().mempool.clone())
        }

        async fn locate_transaction(&self, txid: &str) -> Result<TxLocation, DaemonError> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .tx_locations
                .get(txid)
                .copied()
                .unwrap_or(TxLocation::NotFound))
        }

        async fn is_key_image_spent(&self, key_images: &[String]) -> Result<Vec<KeyImageStatus>, DaemonError> {
            let state = self.state.lock().unwrap();
            Ok(key_images
                .iter()
                .map(|ki| state.key_image_status.get(ki).copied().unwrap_or(KeyImageStatus::Unspent))
                .collect())
        }
    }

    pub fn txid_hex(tx: &Transaction) -> String {
        txid_of(tx)
    }
}
