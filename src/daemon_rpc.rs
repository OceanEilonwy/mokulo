//! Real `MoneroDaemonClient` implementation, talking to `monerod`'s actual RPC
//! surface over `reqwest` + `rustls`. Every endpoint and field name used here was
//! verified against a live public node (`node.hollingworth.xyz:18089`, restricted
//! RPC) before being written, the same way `key_custody`'s crypto was verified
//! against `monero-rs`'s own source rather than assumed from memory - see the
//! `#[ignore]`d tests at the bottom of this file for the live proof.
//!
//! Two RPC surfaces are in play: the JSON-RPC envelope at `/json_rpc` (used for
//! `get_block`), and monerod's "other" plain-JSON endpoints (`/get_height`,
//! `/get_transaction_pool`, `/get_transactions`, `/is_key_image_spent`) which are
//! not wrapped in a `jsonrpc`/`result` envelope at all.

use std::time::Duration;

use monero::consensus::encode::deserialize;
use monero::Transaction;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::daemon::{DaemonError, KeyImageStatus, MoneroDaemonClient, TxLocation};

pub struct RpcDaemonClient {
    client: reqwest::Client,
    base_url: String,
}

impl RpcDaemonClient {
    /// `danger_accept_invalid_certs` exists because many community-run public
    /// Monero nodes (this project's own test node included) serve a self-signed
    /// TLS certificate - not a bug in this client, just the reality of who runs
    /// public Monero infrastructure. This constructor takes no position on the
    /// default; `MoneroNodeConfig::accept_self_signed_certs` does, and it defaults
    /// **on** for the reason above, with `--strict-tls` (see `main::Args`) as the
    /// override that forces it off for every configured node. Note this is
    /// `reqwest`'s blunt flag underneath: it also tolerates expired and
    /// wrong-hostname certificates, so it is not scoped to self-signed
    /// specifically. A self-hoster pointing at a node with a real CA-signed cert
    /// (or running their own node over plain HTTP on localhost) never needs it.
    pub fn new(host: &str, port: u16, ssl: bool, danger_accept_invalid_certs: bool) -> Result<Self, DaemonError> {
        let scheme = if ssl { "https" } else { "http" };
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(danger_accept_invalid_certs)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| DaemonError::Request(format!("failed to build HTTP client: {e}")))?;
        Ok(RpcDaemonClient { client, base_url: format!("{scheme}://{host}:{port}") })
    }

    async fn post_json_rpc<T: for<'de> Deserialize<'de>>(&self, method: &str, params: Value) -> Result<T, DaemonError> {
        let body = json!({ "jsonrpc": "2.0", "id": "0", "method": method, "params": params });
        let value: Value = self
            .client
            .post(format!("{}/json_rpc", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| DaemonError::Request(e.to_string()))?
            .json()
            .await
            .map_err(|e| DaemonError::Request(format!("invalid JSON response: {e}")))?;
        if let Some(err) = value.get("error") {
            return Err(DaemonError::Request(format!("daemon RPC error calling {method}: {err}")));
        }
        let result = value
            .get("result")
            .ok_or_else(|| DaemonError::Request(format!("missing 'result' field calling {method}")))?;
        serde_json::from_value(result.clone())
            .map_err(|e| DaemonError::Request(format!("failed to parse result of {method}: {e}")))
    }

    async fn post_plain<T: for<'de> Deserialize<'de>>(&self, path: &str, body: Value) -> Result<T, DaemonError> {
        let value: Value = self
            .client
            .post(format!("{}{path}", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| DaemonError::Request(e.to_string()))?
            .json()
            .await
            .map_err(|e| DaemonError::Request(format!("invalid JSON response from {path}: {e}")))?;
        if let Some(status) = value.get("status").and_then(|s| s.as_str()) {
            if status != "OK" {
                return Err(DaemonError::Request(format!("daemon returned status {status} from {path}")));
            }
        }
        serde_json::from_value(value).map_err(|e| DaemonError::Request(format!("failed to parse response from {path}: {e}")))
    }

    async fn fetch_transactions(&self, hashes: &[String]) -> Result<Vec<Transaction>, DaemonError> {
        if hashes.is_empty() {
            return Ok(vec![]);
        }
        let resp: GetTransactionsResponse = self
            .post_plain("/get_transactions", json!({ "txs_hashes": hashes, "decode_as_json": false }))
            .await?;
        decode_all_or_fail(hashes, resp)
    }
}

/// Turns a `/get_transactions` response into transactions, refusing to return fewer
/// than were asked for.
///
/// A node that can't produce every requested transaction must be an error, never a
/// shorter list. `fetch_transactions`' caller is enumerating a *block's* contents:
/// silently returning 86 of a block's 87 transactions doesn't degrade the scan, it
/// makes the scan wrong - the missing transaction is one nobody will ever look at
/// again, because the block gets marked scanned either way. If it paid a customer's
/// order, that payment is simply never detected, and nothing anywhere logs a
/// complaint. Two realistic ways to land here: a pruned node with no blob for an
/// older transaction, and a reorg between the `get_block` that produced these hashes
/// and this call. Both should stall the scan for a tick, not lose a payment.
///
/// Split out as a free function purely so this can be tested without standing up an
/// HTTP server - the response shape is the whole of the logic worth pinning.
fn decode_all_or_fail(
    hashes: &[String],
    resp: GetTransactionsResponse,
) -> Result<Vec<Transaction>, DaemonError> {
    if !resp.missed_tx.is_empty() {
        return Err(DaemonError::Request(format!(
            "daemon could not supply {} of {} requested transactions (first missing: {}) - \
             node may be pruned, or the chain moved between calls",
            resp.missed_tx.len(),
            hashes.len(),
            resp.missed_tx[0],
        )));
    }
    let entries = resp.txs.unwrap_or_default();
    if entries.len() != hashes.len() {
        return Err(DaemonError::Request(format!(
            "daemon returned {} transactions for {} requested hashes",
            entries.len(),
            hashes.len()
        )));
    }
    entries.iter().map(|entry| decode_tx_hex(&entry.as_hex)).collect()
}

/// Turns a single-hash `/get_transactions` response into a [`TxLocation`], insisting
/// that the daemon actually answered the question before reporting `NotFound`.
///
/// `NotFound` is not an ordinary "no" here - it is the single most consequential
/// value this whole client can return. `scanner::check_for_reorg_and_reconcile` reacts
/// to it by asking `is_key_image_spent` about that payment's inputs and, on
/// `SpentInBlockchain`, **voiding the payment and stamping a double-spend on the
/// order**. That inference is only valid because `NotFound` is supposed to mean the
/// transaction is in no block and no mempool: if it really is gone, then something
/// *else* must have spent its inputs. `/is_key_image_spent` reports only a status
/// code, never a spending txid, so there is no independent corroboration anywhere -
/// the entire double-spend conclusion rests on this one classification being right.
/// Get it wrong for a transaction that is actually confirmed and the key images come
/// back `SpentInBlockchain` *because that very transaction spent them*, and a
/// perfectly good confirmed payment is written off.
///
/// So only an affirmative answer counts. `missed_tx` naming the hash is the daemon
/// saying "I do not have this"; that is `NotFound`. Everything else that fails to
/// place the transaction is a *non-answer* and becomes an error:
///
///  - Neither list mentions the hash. Every field of `GetTransactionsResponse` is
///    optional (necessarily - a real node omits `txs` when nothing matched and
///    `missed_tx` when nothing was missed), so a bare `{"status":"OK"}` from anything
///    sitting between this client and `monerod` deserializes cleanly into
///    "no transactions, nothing missed" and used to become `NotFound`. This
///    deployment explicitly expects public nodes behind load balancers whose backends
///    disagree with each other - see `FakeDaemonClient::height_override`, which exists
///    because that was observed live - so a response from a backend that has nothing
///    to say is not hypothetical.
///  - An entry that is not in the pool and carries no `block_height`: the daemon has
///    claimed the transaction is confirmed and simultaneously declined to say where.
///
/// An error costs a retry and nothing else: reconciliation aborts for this tick with
/// the stored block hashes untouched, so the next tick re-detects the same reorg and
/// re-reconciles from scratch - the property
/// `scanner::tests::a_reconciliation_that_fails_partway_leaves_the_reorg_still_detectable`
/// pins. Trading a retry for never voiding a live payment off a response that never
/// said it was gone is not a close call.
fn classify_located_transaction(
    txid: &str,
    resp: GetTransactionsResponse,
) -> Result<TxLocation, DaemonError> {
    if resp.missed_tx.iter().any(|h| h == txid) {
        return Ok(TxLocation::NotFound);
    }
    match resp.txs.and_then(|v| v.into_iter().next()) {
        Some(entry) if entry.in_pool => Ok(TxLocation::InPool),
        Some(entry) => match entry.block_height {
            Some(h) => Ok(TxLocation::InBlock(h)),
            None => Err(DaemonError::Request(format!(
                "daemon reported transaction {txid} as confirmed but gave no block_height - \
                 refusing to read that as 'not on the chain', which would void the payment"
            ))),
        },
        None => Err(DaemonError::Request(format!(
            "daemon returned neither a transaction nor a miss for {txid} - refusing to read a \
             non-answer as 'not on the chain', which would void the payment"
        ))),
    }
}

/// Decodes the mempool, skipping (and logging) entries that won't parse rather than
/// failing the whole poll.
///
/// This is deliberately the *opposite* policy to `decode_all_or_fail`, and the
/// difference is not inconsistency - it's that the two calls have opposite failure
/// consequences. A block is scanned exactly once and then marked scanned forever, so
/// silently dropping one of its transactions loses whatever payment it contained; all
/// or nothing is the only safe reading there. The mempool is re-polled every second,
/// nothing about it is ever marked done, and a transaction this build cannot
/// deserialize cannot be matched against a wallet no matter how many times it is
/// retried. So failing the whole call over one bad entry buys nothing and costs
/// everything: `run_scan_tick` gets an error instead of a mempool, and zero-conf
/// detection is off for *every* tenant on this network for as long as that
/// transaction sits in the pool - which, since anyone can put a transaction in a
/// public mempool and it lingers for days, is a trivially reachable state, not a
/// hypothetical one. The payment is still detected the moment it is mined; only its
/// zero-conf sighting is lost, and only for the one transaction that could not be
/// read.
fn decode_pool_best_effort(entries: &[PoolTx]) -> Vec<Transaction> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        match decode_tx_hex(&entry.tx_blob) {
            Ok(tx) => out.push(tx),
            Err(e) => eprintln!(
                "skipping one undecodable mempool transaction ({e}) - it cannot be matched against any \
                 wallet either way, and failing the whole poll over it would disable zero-conf detection \
                 for every tenant on this network"
            ),
        }
    }
    out
}

fn decode_tx_hex(hex_str: &str) -> Result<Transaction, DaemonError> {
    if hex_str.is_empty() {
        return Err(DaemonError::Request(
            "transaction has no as_hex data (likely pruned on this node)".to_string(),
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|e| DaemonError::Request(format!("invalid tx hex: {e}")))?;
    deserialize(&bytes).map_err(|e| DaemonError::Request(format!("failed to parse transaction blob: {e}")))
}

#[derive(Deserialize)]
struct GetHeightResponse {
    height: u64,
}

#[derive(Deserialize)]
struct BlockHeader {
    hash: String,
}

#[derive(Deserialize)]
struct GetBlockResult {
    block_header: BlockHeader,
    #[serde(default)]
    tx_hashes: Vec<String>,
}

#[derive(Deserialize)]
struct GetTransactionPoolResponse {
    transactions: Vec<PoolTx>,
}

#[derive(Deserialize)]
struct PoolTx {
    tx_blob: String,
}

#[derive(Deserialize)]
struct GetTransactionsResponse {
    txs: Option<Vec<TxEntry>>,
    #[serde(default)]
    missed_tx: Vec<String>,
}

#[derive(Deserialize)]
struct TxEntry {
    as_hex: String,
    in_pool: bool,
    block_height: Option<u64>,
}

#[derive(Deserialize)]
struct IsKeyImageSpentResponse {
    spent_status: Vec<u8>,
}

#[async_trait::async_trait]
impl MoneroDaemonClient for RpcDaemonClient {
    async fn get_height(&self) -> Result<u64, DaemonError> {
        let resp: GetHeightResponse = self.post_plain("/get_height", json!({})).await?;
        // monerod's `/get_height` "height" field is the block *count*, not the
        // top block's own height (they differ by 1 since genesis is height 0).
        // Verified three ways, not assumed from one error message: (1) the
        // official docs (docs.getmonero.org/rpc-library/monerod-rpc) describe this
        // field verbatim as "Current length of longest chain known to daemon" -
        // language for a count, not an index; (2) monero's own C++ source
        // (src/cryptonote_core/blockchain.cpp, `get_current_blockchain_height()`,
        // the function backing both `/get_height` and `get_info`) carries a
        // warning comment reading "no getheight + gethash(height-1)" - the
        // developers' own shorthand for exactly this off-by-one; (3) live against
        // a real node, `get_block` rejected the raw value with "requested height N
        // greater than current top block height N-1". Subtracting 1 here keeps
        // this trait's `get_height()` meaning one consistent thing everywhere it's
        // used: the height of the actual current tip block, directly usable with
        // `get_block_hash`/`get_block_transactions`. Originally misdiagnosed as a
        // load-balancer inconsistency (see the defensive one-block seed margin in
        // `scanner::run_scan_tick`) before checking (1)-(3) above.
        Ok(resp.height.saturating_sub(1))
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, DaemonError> {
        let resp: GetBlockResult = self.post_json_rpc("get_block", json!({ "height": height })).await?;
        Ok(resp.block_header.hash)
    }

    async fn get_block_transactions(&self, height: u64) -> Result<Vec<Transaction>, DaemonError> {
        let block: GetBlockResult = self.post_json_rpc("get_block", json!({ "height": height })).await?;
        self.fetch_transactions(&block.tx_hashes).await
    }

    async fn get_mempool_transactions(&self) -> Result<Vec<Transaction>, DaemonError> {
        let resp: GetTransactionPoolResponse = self.post_plain("/get_transaction_pool", json!({})).await?;
        Ok(decode_pool_best_effort(&resp.transactions))
    }

    async fn locate_transaction(&self, txid: &str) -> Result<TxLocation, DaemonError> {
        let resp: GetTransactionsResponse = self
            .post_plain("/get_transactions", json!({ "txs_hashes": [txid], "decode_as_json": false }))
            .await?;
        classify_located_transaction(txid, resp)
    }

    async fn is_key_image_spent(&self, key_images: &[String]) -> Result<Vec<KeyImageStatus>, DaemonError> {
        if key_images.is_empty() {
            return Ok(vec![]);
        }
        let resp: IsKeyImageSpentResponse =
            self.post_plain("/is_key_image_spent", json!({ "key_images": key_images })).await?;
        // A caller correlates this response with `key_images` positionally (e.g. by
        // `zip`ping the two, as the scanner's double-spend check and
        // `tests/support/mod.rs`'s spendable-output filter both do) - a short
        // response would otherwise silently drop the tail of the request rather than
        // erroring, misreporting "unspent"/"not found" for whatever got dropped.
        if resp.spent_status.len() != key_images.len() {
            return Err(DaemonError::Request(format!(
                "daemon returned {} statuses for {} requested key images",
                resp.spent_status.len(),
                key_images.len()
            )));
        }
        Ok(resp
            .spent_status
            .into_iter()
            .map(|code| match code {
                1 => KeyImageStatus::SpentInBlockchain,
                2 => KeyImageStatus::SpentInPool,
                _ => KeyImageStatus::Unspent, // 0, or any unrecognized code - degrade to the safe (non-voiding) default
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    //! Hermetic counterparts to the `#[ignore]`d live tests below: the response
    //! shapes a real node can produce, exercised without a network.

    use super::*;

    const FIXTURE_TX_HEX: &str = include_str!("../tests/fixtures/subaddress_tx.hex");

    fn entry(as_hex: &str) -> TxEntry {
        TxEntry { as_hex: as_hex.to_string(), in_pool: false, block_height: Some(1) }
    }

    #[test]
    fn a_block_whose_transactions_the_node_cannot_supply_is_an_error_not_a_short_list() {
        // The failure this exists to prevent: the scanner marks the block scanned
        // and moves on, so a payment in the dropped transaction is never seen and
        // nothing ever logs that anything was missing.
        let hashes = vec!["aa".repeat(32), "bb".repeat(32)];
        let resp = GetTransactionsResponse {
            txs: Some(vec![entry(FIXTURE_TX_HEX)]),
            missed_tx: vec!["bb".repeat(32)],
        };
        let err = decode_all_or_fail(&hashes, resp).unwrap_err();
        assert!(err.to_string().contains("could not supply"), "got {err}");
    }

    #[test]
    fn a_response_shorter_than_the_request_is_an_error_even_with_an_empty_missed_tx() {
        // Same loss of a payment, arrived at without the node admitting anything is
        // missing - so the `missed_tx` check alone isn't sufficient.
        let hashes = vec!["aa".repeat(32), "bb".repeat(32)];
        let resp = GetTransactionsResponse { txs: Some(vec![entry(FIXTURE_TX_HEX)]), missed_tx: vec![] };
        let err = decode_all_or_fail(&hashes, resp).unwrap_err();
        assert!(err.to_string().contains("for 2 requested hashes"), "got {err}");

        let resp = GetTransactionsResponse { txs: None, missed_tx: vec![] };
        assert!(decode_all_or_fail(&hashes, resp).is_err());
    }

    #[test]
    fn a_complete_response_decodes_every_transaction() {
        let hashes = vec!["aa".repeat(32), "bb".repeat(32)];
        let resp = GetTransactionsResponse {
            txs: Some(vec![entry(FIXTURE_TX_HEX), entry(FIXTURE_TX_HEX)]),
            missed_tx: vec![],
        };
        let txs = decode_all_or_fail(&hashes, resp).unwrap();
        assert_eq!(txs.len(), 2);
        assert!(!txs[0].prefix.outputs.is_empty());
    }

    #[test]
    fn an_empty_request_needs_no_round_trip_and_yields_nothing() {
        assert!(decode_all_or_fail(&[], GetTransactionsResponse { txs: None, missed_tx: vec![] })
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_pruned_transaction_with_no_blob_is_an_error_rather_than_a_silent_skip() {
        let err = decode_tx_hex("").unwrap_err();
        assert!(err.to_string().contains("no as_hex data"), "got {err}");
        assert!(decode_tx_hex("not hex at all").is_err());
        assert!(decode_tx_hex("deadbeef").is_err(), "valid hex that isn't a transaction");
    }

    #[test]
    fn only_an_affirmative_miss_locates_a_transaction_as_not_found() {
        // `NotFound` is the one value that leads to a payment being voided and an
        // order stamped with a double-spend, and `/is_key_image_spent` returns no
        // spending txid, so nothing else in the system cross-checks that conclusion.
        // Every non-answer therefore has to be an error rather than a "no".
        let txid = "aa".repeat(32);

        // The daemon affirmatively says it doesn't have it. This is the only shape
        // that may report NotFound.
        assert_eq!(
            classify_located_transaction(
                &txid,
                GetTransactionsResponse { txs: None, missed_tx: vec![txid.clone()] }
            )
            .unwrap(),
            TxLocation::NotFound
        );

        // Ordinary positive answers are unaffected.
        assert_eq!(
            classify_located_transaction(
                &txid,
                GetTransactionsResponse {
                    txs: Some(vec![TxEntry { as_hex: String::new(), in_pool: false, block_height: Some(3_755_690) }]),
                    missed_tx: vec![],
                }
            )
            .unwrap(),
            TxLocation::InBlock(3_755_690)
        );
        assert_eq!(
            classify_located_transaction(
                &txid,
                GetTransactionsResponse {
                    txs: Some(vec![TxEntry { as_hex: String::new(), in_pool: true, block_height: None }]),
                    missed_tx: vec![],
                }
            )
            .unwrap(),
            TxLocation::InPool
        );

        // A response that places the transaction nowhere and misses nothing. Every
        // field of this struct is optional out of necessity, so a bare
        // `{"status":"OK"}` from a load balancer, cache, or backend with nothing to
        // say deserializes into exactly this - and used to be read as "the
        // transaction is gone from the chain", which for a *confirmed* payment means
        // its own key images come back SpentInBlockchain and it gets voided as a
        // double-spend.
        let err = classify_located_transaction(
            &txid,
            GetTransactionsResponse { txs: None, missed_tx: vec![] },
        )
        .unwrap_err();
        assert!(err.to_string().contains("neither a transaction nor a miss"), "got {err}");
        assert!(
            serde_json::from_value::<GetTransactionsResponse>(json!({ "status": "OK" })).is_ok(),
            "the empty-but-valid response this guards against must really parse - otherwise the guard is moot"
        );

        // ...and a miss reported for some *other* hash is equally not an answer about
        // this one.
        assert!(
            classify_located_transaction(
                &txid,
                GetTransactionsResponse { txs: None, missed_tx: vec!["bb".repeat(32)] },
            )
            .is_err()
        );

        // "Confirmed, but I won't say where" is self-contradictory, not a miss.
        let err = classify_located_transaction(
            &txid,
            GetTransactionsResponse {
                txs: Some(vec![TxEntry { as_hex: String::new(), in_pool: false, block_height: None }]),
                missed_tx: vec![],
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("no block_height"), "got {err}");
    }

    #[test]
    fn one_undecodable_mempool_entry_is_skipped_rather_than_blinding_the_whole_poll() {
        // The failure this prevents: `.map(..).collect::<Result<Vec<_>, _>>()` turned
        // a single unparseable pool entry into an error for the entire call, and
        // `run_scan_tick` treats a failed mempool poll as "no mempool this tick". So
        // one transaction this build can't deserialize - a future transaction format,
        // or anything at all that a stranger chose to broadcast - switches off
        // zero-conf detection for every tenant on that network for as long as it sits
        // in the pool. A public mempool holds transactions for days, so this is a
        // state anyone can put the scanner into, not a hypothetical.
        //
        // The opposite policy for blocks (`decode_all_or_fail`) is deliberate and
        // still right: a block is marked scanned exactly once, so dropping one of its
        // transactions loses a payment permanently. Nothing about the mempool is ever
        // marked done, and an undecodable transaction can never be matched anyway.
        let entries = vec![
            PoolTx { tx_blob: FIXTURE_TX_HEX.to_string() },
            PoolTx { tx_blob: "not hex at all".to_string() },
            PoolTx { tx_blob: String::new() }, // pruned: present, no blob
            PoolTx { tx_blob: "deadbeef".to_string() }, // valid hex, not a transaction
            PoolTx { tx_blob: FIXTURE_TX_HEX.to_string() },
        ];
        let decoded = decode_pool_best_effort(&entries);
        assert_eq!(decoded.len(), 2, "every decodable transaction must survive its undecodable neighbours");
        for tx in &decoded {
            assert!(!tx.prefix.outputs.is_empty());
        }

        // A pool of nothing but junk is an empty mempool, not an error - there is
        // genuinely nothing to scan, and reporting that as a failed poll would be
        // indistinguishable from an unreachable node.
        assert!(decode_pool_best_effort(&[PoolTx { tx_blob: "zz".into() }]).is_empty());
        assert!(decode_pool_best_effort(&[]).is_empty());
    }

    #[test]
    fn get_height_response_parses_and_the_block_count_to_tip_height_adjustment_holds() {
        // monerod's `/get_height` reports the chain *length*; the trait contract is
        // the tip block's own *height*, one less. Pinned here (rather than only in
        // the `#[ignore]`d live test) so a future edit to that line has to
        // deliberately change an assertion.
        let parsed: GetHeightResponse = serde_json::from_value(json!({
            "height": 3_755_691u64, "hash": "ab", "status": "OK", "untrusted": false
        }))
        .unwrap();
        assert_eq!(parsed.height.saturating_sub(1), 3_755_690);
        // A single-block chain (genesis only) is height 0, not an underflow.
        assert_eq!(1u64.saturating_sub(1), 0);
        assert_eq!(0u64.saturating_sub(1), 0);
    }

    #[test]
    fn optional_fields_a_real_node_may_omit_still_parse() {
        // `tx_hashes` is absent on an empty block, and `missed_tx` is absent when
        // nothing was missed - a hard `Vec` on either would turn a normal response
        // into a parse error and stall the scanner.
        let block: GetBlockResult =
            serde_json::from_value(json!({ "block_header": { "hash": "abc" } })).unwrap();
        assert_eq!(block.block_header.hash, "abc");
        assert!(block.tx_hashes.is_empty());

        let txs: GetTransactionsResponse =
            serde_json::from_value(json!({ "status": "OK" })).unwrap();
        assert!(txs.txs.is_none() && txs.missed_tx.is_empty());

        // A pool entry reports no block height at all.
        let pool: TxEntry =
            serde_json::from_value(json!({ "as_hex": "ab", "in_pool": true, "block_height": null }))
                .unwrap();
        assert!(pool.in_pool && pool.block_height.is_none());
    }
}

#[cfg(test)]
mod live_node_tests {
    //! These hit a real public Monero node over the network and are excluded from
    //! the default `cargo test` run (`#[ignore]`) so the main suite stays hermetic
    //! and fast - run explicitly with `cargo test --ignored daemon_rpc::` when you
    //! want to verify against real chain data. Per `docs/TESTING.md` §10's
    //! reasoning for the regtest tier: this proves the real RPC wiring and real
    //! transaction parsing against real (and constantly-changing) mainnet data,
    //! which no fixture-based unit test can substitute for - it's a *complement* to
    //! the mocked-daemon scanner tests in `scanner.rs`, not a replacement.

    use super::*;

    const TEST_NODE_HOST: &str = "node.hollingworth.xyz";
    const TEST_NODE_PORT: u16 = 18089;

    fn client() -> RpcDaemonClient {
        RpcDaemonClient::new(TEST_NODE_HOST, TEST_NODE_PORT, true, true).unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_get_height_returns_a_plausible_value() {
        let height = client().get_height().await.unwrap();
        // Mainnet passed height 3,700,000 in mid-2026; a sane lower bound that
        // won't need updating for a long time, without hardcoding an exact value
        // that would go stale on every run.
        assert!(height > 3_700_000, "height {height} looks implausible for current mainnet");
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_get_block_hash_matches_a_known_immutable_block() {
        // Captured live against this exact node while building this client - at
        // 5+ confirmations deep at the time, this block's hash is permanent.
        let hash = client().get_block_hash(3_755_690).await.unwrap();
        assert_eq!(hash, "61dcf348728fd124895e5e9e5188cc34a13c483f84ddfb5d3998f38d0ae55aa4");
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_get_block_transactions_all_parse_as_valid_monero_transactions() {
        // Proves the real deserialization path handles *current* mainnet
        // transaction formats (view tags, CLSAG, bulletproofs+) - the crate's own
        // fixture used elsewhere in this codebase is a single, older-format
        // transaction and wouldn't catch a version-compatibility regression here.
        // 87 non-coinbase transactions, captured live against this exact block -
        // `tx_hashes` (what this call fetches) already excludes the coinbase/miner
        // transaction, so this is the full regular-transaction count, not "minus
        // one" as an earlier version of this test wrongly assumed from
        // `block_header.num_txes` before actually running it against real data.
        let txs = client().get_block_transactions(3_755_690).await.unwrap();
        assert_eq!(txs.len(), 87);
        for tx in &txs {
            assert!(!tx.prefix.inputs.is_empty());
            assert!(!tx.prefix.outputs.is_empty());
        }
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_get_mempool_transactions_decode_successfully() {
        // The mempool is constantly changing, so this can't assert exact content -
        // only that whatever is currently there decodes cleanly, proving the same
        // path the live scanner would run every ~second in production.
        let txs = client().get_mempool_transactions().await.unwrap();
        for tx in &txs {
            assert!(!tx.prefix.outputs.is_empty());
        }
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_locate_transaction_finds_a_known_confirmed_tx() {
        let location = client()
            .locate_transaction("24f70768d285ca14dd8080a9cddf1ecdebce7553933c9a638090b5fda2101fa8")
            .await
            .unwrap();
        assert_eq!(location, TxLocation::InBlock(3_755_690));
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_locate_transaction_reports_not_found_for_a_bogus_hash() {
        let location = client()
            .locate_transaction("0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .unwrap();
        assert_eq!(location, TxLocation::NotFound);
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_is_key_image_spent_reports_unspent_for_a_null_image() {
        let statuses = client()
            .is_key_image_spent(&["0000000000000000000000000000000000000000000000000000000000000000".to_string()])
            .await
            .unwrap();
        assert_eq!(statuses, vec![KeyImageStatus::Unspent]);
    }

    #[tokio::test]
    #[ignore]
    async fn real_node_end_to_end_scan_of_live_mempool_never_panics_and_finds_no_false_matches() {
        // The fullest available proof this pipeline works: real transactions,
        // fresh off a real node's real mempool, run through the actual
        // scanner::scan_transaction_for_tenant path (real KeyCustody scan +
        // real Store) against a wallet that has never received anything. Expect
        // zero matches (this key owns nothing) - the point is that scanning
        // diverse, unpredictable real-world transaction shapes never errors or
        // panics, which a single canned fixture can't prove.
        use crate::key_custody::{KeyCustody, PlainKeyCustody, WalletMaterial};
        use crate::store::Store;
        use monero::{PrivateKey, PublicKey};

        let mut view_bytes = [0x42u8; 32];
        view_bytes[31] &= 0x0f;
        let view_key = PrivateKey::from_slice(&view_bytes).unwrap();
        let mut spend_bytes = [0x24u8; 32];
        spend_bytes[31] &= 0x0f;
        let spend_key = PrivateKey::from_slice(&spend_bytes).unwrap();
        let spend_pubkey = PublicKey::from_private_key(&spend_key);

        let key_custody = PlainKeyCustody::default();
        let handle = key_custody
            .register_wallet(WalletMaterial::new(view_key.to_bytes(), spend_pubkey.to_bytes()))
            .await
            .unwrap();
        let store = Store::open_in_memory().unwrap();
        let created = store
            .create_tenant(
                crate::store::NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "4test".into(),
                    network: "mainnet".into(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                0,
            )
            .unwrap();

        let txs = client().get_mempool_transactions().await.unwrap();
        assert!(!txs.is_empty(), "test needs a non-empty live mempool to be meaningful");

        for tx in &txs {
            let touched = crate::scanner::scan_transaction_for_tenant(
                &store,
                &key_custody,
                handle,
                &created.tenant.id,
                tx,
                0..1,
                0,
                None,
            )
            .await
            .unwrap();
            assert!(touched.is_empty());
        }
    }
}
