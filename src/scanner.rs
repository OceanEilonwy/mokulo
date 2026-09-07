//! Chain scanning: matching transactions against active tenants, and reorg /
//! double-spend detection. See `docs/DESIGN.md` §7.
//!
//! Deliberately built against the `MoneroDaemonClient` trait rather than a live
//! node, and against `Store` directly rather than the (not-yet-built) writer-actor
//! wrapper - the correctness of the reconciliation logic doesn't depend on which
//! thread runs it, only on doing the right thing with what the daemon reports.

use std::collections::HashSet;
use std::ops::Range;

use monero::cryptonote::hash::Hashable;
use monero::Transaction;

use crate::daemon::{DaemonError, KeyImageStatus, MoneroDaemonClient, TxLocation};
use crate::key_custody::{KeyCustody, KeyCustodyError, WalletHandle};
use crate::store::{Store, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error(transparent)]
    Daemon(#[from] DaemonError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    KeyCustody(#[from] KeyCustodyError),
}

type Result<T> = std::result::Result<T, ScannerError>;

pub fn tx_id_hex(tx: &Transaction) -> String {
    hex::encode(tx.hash().to_bytes())
}

fn key_images_of(tx: &Transaction) -> Vec<String> {
    tx.prefix
        .inputs
        .iter()
        .filter_map(|input| match input {
            monero::blockdata::transaction::TxIn::ToKey { k_image, .. } => {
                Some(hex::encode(k_image.image.to_bytes()))
            }
            monero::blockdata::transaction::TxIn::Gen { .. } => None,
        })
        .collect()
}

/// The result of scanning one transaction against one wallet - pure `KeyCustody`
/// output, no `Store` involved. Deliberately separate from persisting it (see
/// `record_scan_match`): `rusqlite::Connection` is `Send` but not `Sync`, so a
/// `&Store` reference held across an `.await` (as combining these two steps into
/// one async function would require, since `KeyCustody::scan_tx_outputs` awaits)
/// makes the containing future `!Send` - fine for a future only ever `.await`ed
/// directly inside another task (every test in this file does that), but fatal the
/// moment anything containing it is handed to `tokio::spawn`, which requires the
/// whole future to be `Send + 'static`. `scanner::run_scan_tick` is spawned in
/// production (`main.rs`), so this split isn't a style preference - the combined
/// version simply cannot be spawned. Caught by the compiler, not a test, the first
/// time this code was actually wired into a spawned task rather than awaited
/// directly in a test.
pub struct ScanResult {
    pub matches: Vec<crate::key_custody::MatchedOutput>,
    pub txid: String,
    pub key_images_json: String,
}

pub async fn scan_transaction(
    key_custody: &dyn KeyCustody,
    handle: WalletHandle,
    tx: &Transaction,
    minor_range: Range<u32>,
) -> Result<ScanResult> {
    let matches = key_custody.scan_tx_outputs(handle, tx, 0..1, minor_range).await?;
    Ok(ScanResult {
        matches,
        txid: tx_id_hex(tx),
        key_images_json: serde_json::to_string(&key_images_of(tx)).unwrap(),
    })
}

/// Persists a `ScanResult` against one tenant. Purely synchronous - no `.await`
/// anywhere in this function, so a `&Store` parameter here is never an issue.
/// Returns the set of order ids touched, so the caller knows which orders need
/// `Store::recompute_order_status`.
pub fn record_scan_match(
    store: &Store,
    tenant_id: &str,
    scan: &ScanResult,
    seen_at: i64,
    block_height: Option<u64>,
) -> Result<HashSet<String>> {
    let mut touched = HashSet::new();
    for m in &scan.matches {
        let Some(order) = store.find_order_by_minor_index(tenant_id, m.subaddress_index.minor)? else {
            continue; // a match against an index with no order row is not this scanner's problem to solve
        };
        // An output whose amount couldn't be decrypted is skipped, not recorded as
        // zero. A present-but-zero row is strictly worse than no row: it contributes
        // nothing to the received total while still dragging `min_confirmations` and
        // `all_zero_conf` around in the status derivation (see status.rs's
        // `a_zeroed_but_present_row_is_not_a_safe_substitute_for_exclusion`), and it
        // can never be cleaned up afterwards - voiding requires affirmative
        // double-spend proof, which will never arrive for a perfectly valid output.
        // Skipping leaves the tick free to record it properly once the amount is
        // recoverable.
        let Some(amount) = m.amount_piconero else {
            eprintln!(
                "scanner: output {} of tx {} matched order {} but its amount could not be decrypted - not recording it",
                m.output_index, scan.txid, order.id
            );
            continue;
        };
        store.record_payment_match(
            &order.id,
            &scan.txid,
            m.output_index as i64,
            amount,
            &scan.key_images_json,
            seen_at,
            block_height.map(|h| h as i64),
        )?;
        touched.insert(order.id);
    }
    Ok(touched)
}

/// Convenience wrapper combining `scan_transaction` + `record_scan_match`, for
/// callers that `.await` it directly within their own task rather than spawning it
/// (every test in this file does exactly that, so the `!Send` issue never bites
/// them). `run_scan_tick` (spawned in production) deliberately does not use this;
/// it calls the two halves separately instead.
#[allow(clippy::too_many_arguments)] // one scan call's genuinely-independent inputs; a params struct would just move the ceremony, not remove it
pub async fn scan_transaction_for_tenant(
    store: &Store,
    key_custody: &dyn KeyCustody,
    handle: WalletHandle,
    tenant_id: &str,
    tx: &Transaction,
    minor_range: Range<u32>,
    seen_at: i64,
    block_height: Option<u64>,
) -> Result<HashSet<String>> {
    let scan = scan_transaction(key_custody, handle, tx, minor_range).await?;
    record_scan_match(store, tenant_id, &scan, seen_at, block_height)
}

pub struct ReconcileReport {
    /// Lowest height at which the canonical chain diverged from what was
    /// previously scanned, if any reorg was detected this call.
    pub reorg_detected_at: Option<u64>,
    /// Orders whose payments changed in a way that warrants a status recompute.
    pub dirty_orders: Vec<String>,
    /// The subset of `dirty_orders` where the change was specifically a proven
    /// double-spend (a payment voided because its key image was confirmed spent by
    /// a different transaction) - callers use this to enqueue the independent
    /// `order.double_spend_detected` webhook event (see `docs/DESIGN.md` §11),
    /// separate from whatever `order.<status>` event the recompute may also imply.
    pub double_spent_orders: Vec<String>,
}

/// Checks for a reorg within the last `reorg_check_depth` blocks and, if one is
/// found, re-evaluates every payment whose recorded `block_height` falls in the
/// affected range. Never voids a payment on ambiguous evidence (§DESIGN.md 7.5) -
/// only when `is_key_image_spent` affirmatively proves a different transaction
/// consumed the same inputs. Safe to call unconditionally on every scan tick: with
/// no reorg, this is just a handful of hash comparisons against the stored window.
///
/// Takes `&SharedStore`, locking only around each brief synchronous call and never
/// across a daemon RPC `.await` - this function can make many sequential network
/// calls (a hash check per block in the window, then a `locate_transaction` and
/// possibly an `is_key_image_spent` per affected payment), so holding the store
/// lock for its whole duration would block every other request touching the store
/// for as long as all of that network I/O takes. Same reasoning as
/// `webhook_delivery::run_delivery_tick`.
pub async fn check_for_reorg_and_reconcile(
    store: &crate::store::SharedStore,
    daemon: &dyn MoneroDaemonClient,
    network: &str,
    reorg_check_depth: u64,
    now: i64,
) -> Result<ReconcileReport> {
    let height = daemon.get_height().await?;
    let window_start = height.saturating_sub(reorg_check_depth);

    // Detection is read-only against the store: the corrected hashes are *not*
    // written back here. Writing them mid-detection (as this loop used to) makes the
    // reorg undetectable to any later attempt - stored and actual hashes now agree -
    // while the payments it affects have not been reconciled yet. A crash, or any
    // `?` further down (a `locate_transaction` against a briefly-unreachable node is
    // enough), then left those payments permanently stranded on the old chain with
    // nothing to tell the next tick anything had happened.
    let mut reorg_point: Option<u64> = None;
    for h in window_start..=height {
        let stored_hash = store.lock().unwrap().get_scanned_block_hash(network, h)?;
        if let Some(stored_hash) = stored_hash {
            let actual_hash = daemon.get_block_hash(h).await?;
            if actual_hash != stored_hash {
                reorg_point = Some(h);
                break; // the first divergence is the reorg point; everything above it is re-scanned wholesale
            }
        }
    }

    let mut dirty_orders = HashSet::new();
    let mut double_spent_orders = HashSet::new();

    if let Some(reorg_point) = reorg_point {
        let affected = store.lock().unwrap().find_payments_at_or_after_height(network, reorg_point)?;
        for payment in affected {
            match daemon.locate_transaction(&payment.txid).await? {
                TxLocation::InBlock(new_height) => {
                    store.lock().unwrap().update_payment_block_height(
                        &payment.order_id,
                        &payment.txid,
                        payment.output_index,
                        Some(new_height as i64),
                    )?;
                    dirty_orders.insert(payment.order_id.clone());
                }
                TxLocation::InPool => {
                    store.lock().unwrap().update_payment_block_height(
                        &payment.order_id,
                        &payment.txid,
                        payment.output_index,
                        None,
                    )?;
                    dirty_orders.insert(payment.order_id.clone());
                }
                TxLocation::NotFound => {
                    if void_if_double_spend_proven(store, daemon, &payment, height, now).await? {
                        dirty_orders.insert(payment.order_id.clone());
                        double_spent_orders.insert(payment.order_id.clone());
                    }
                }
            }
        }

        // The reverse direction: a payment an earlier pass voided as a proven
        // double-spend, whose transaction has since come back to the canonical chain
        // because the *replacement* was itself reorged out. Voiding is a conclusion
        // drawn from a chain state that can change, so it can't be treated as final;
        // without this, a merchant's genuinely-paid order stays permanently short by
        // the voided amount. `double_spend_detected_at` stays set regardless - it
        // records that an incident occurred, not that it is currently in effect.
        let previously_voided = store.lock().unwrap().find_voided_payments_at_or_after_height(network, reorg_point)?;
        for payment in previously_voided {
            if let TxLocation::InBlock(new_height) = daemon.locate_transaction(&payment.txid).await? {
                let s = store.lock().unwrap();
                if s.unvoid_payment(&payment.order_id, &payment.txid, payment.output_index)? {
                    s.update_payment_block_height(
                        &payment.order_id,
                        &payment.txid,
                        payment.output_index,
                        Some(new_height as i64),
                    )?;
                    dirty_orders.insert(payment.order_id.clone());
                }
            }
        }
    }

    {
        let s = store.lock().unwrap();
        // The notifying recompute, not the bare one: a reorg-driven transition
        // (`paid` -> `confirming` when a tx falls back to the mempool, say) is
        // exactly as webhook-worthy as a forward-scan-driven one, and a merchant
        // discovering by polling that an order silently stopped being paid is the
        // worst possible way to learn about it.
        for order_id in &dirty_orders {
            recompute_and_notify(&s, order_id, height, now)?;
        }
    }

    // Only now that every affected payment has been re-evaluated is it safe to let
    // the stored view of the chain catch up. Dropping the rows at and above the
    // reorg point (rather than overwriting them with the new hashes) does double
    // duty: the next detection pass sees nothing to re-reconcile, *and*
    // `max_scanned_height` falls back to `reorg_point - 1` so the next tick's
    // forward scan re-covers `reorg_point..tip` against the replacement chain,
    // picking up any payment that exists only there. Should this tick die before
    // reaching this line, nothing has been written, and the next tick simply detects
    // the same reorg again and redoes the work - reconciliation is idempotent.
    if let Some(reorg_point) = reorg_point {
        // ...with one thing to be careful about: "walks back to `reorg_point - 1`"
        // is only true while a row still exists at or below that height. When the
        // reorg point is the *lowest* block this network has a row for - routine on a
        // recently-started scanner, whose window begins at the tip it bootstrapped
        // from - the delete empties the table outright, and an empty table is exactly
        // what `run_scan_tick` reads as "this network has never been scanned", which
        // makes it re-seed at the current tip. Every replacement block between the
        // reorg point and the tip would then be skipped forever, taking any payment
        // that exists only in the winning chain with it - the precise failure
        // dropping these rows was introduced to prevent.
        //
        // Re-anchoring the common ancestor fixes the high-water mark in place. Its
        // hash is fetched before the lock is taken, since nothing may `.await` while
        // holding the store mutex; one extra RPC per detected reorg is not worth
        // conditionalising.
        //
        // The anchor is fetched *before* anything is deleted, and a failure to fetch
        // it abandons the delete entirely rather than proceeding without it. Treating
        // a failed lookup as "no anchor" (which an `.ok()` here quietly did) reaches
        // precisely the outcome the paragraph above exists to prevent, just via a
        // transient RPC error instead of a missing row: the rows are gone, the table
        // can now be empty, and the next tick reads that as "never scanned" and
        // re-seeds at the tip - skipping every replacement block between the reorg
        // point and the tip, permanently and silently. Leaving the stored hashes
        // untouched instead costs nothing: they still describe the losing chain, so
        // the next tick detects the same reorg and redoes this whole step, exactly
        // as it does when reconciliation itself fails partway.
        let anchor = reorg_point.checked_sub(1);
        let anchor_hash = match anchor {
            Some(h) => match daemon.get_block_hash(h).await {
                Ok(hash) => Some(hash),
                Err(e) => {
                    eprintln!(
                        "reorg at {reorg_point} on {network}: could not read the hash of the common ancestor \
                         at {h} ({e}) - leaving the scanned-block window untouched so the next tick re-detects \
                         this reorg, rather than dropping rows this tick can no longer re-anchor"
                    );
                    return Ok(ReconcileReport {
                        reorg_detected_at: Some(reorg_point),
                        dirty_orders: dirty_orders.into_iter().collect(),
                        double_spent_orders: double_spent_orders.into_iter().collect(),
                    });
                }
            },
            // A divergence at height 0 means the genesis block changed, which cannot
            // happen on any real chain. There is no ancestor to anchor to and nothing
            // to preserve, so the delete goes ahead and the next tick re-seeds.
            None => None,
        };
        let s = store.lock().unwrap();
        s.forget_scanned_blocks_at_or_above(network, reorg_point)?;
        if s.max_scanned_height(network)?.is_none() {
            if let (Some(h), Some(hash)) = (anchor, anchor_hash) {
                s.set_scanned_block(network, h, &hash)?;
            }
        }
    }

    Ok(ReconcileReport {
        reorg_detected_at: reorg_point,
        dirty_orders: dirty_orders.into_iter().collect(),
        double_spent_orders: double_spent_orders.into_iter().collect(),
    })
}

/// What one `check_vanished_mempool_payments` sweep concluded. Same two lists as
/// `ReconcileReport`, minus the reorg point (this sweep is not about the chain
/// changing shape).
pub struct VanishedPoolReport {
    /// Orders whose payments changed and therefore need a status recompute.
    pub dirty_orders: Vec<String>,
    /// The subset of `dirty_orders` where a payment was voided on affirmative
    /// double-spend proof - the `order.double_spend_detected` webhook's trigger.
    pub double_spent_orders: Vec<String>,
}

/// Re-examines every payment that is still mempool-only (`block_height IS NULL`)
/// and whose transaction is no longer in the mempool snapshot this tick polled.
///
/// This exists because reorg reconciliation cannot cover the most ordinary
/// double-spend there is. `check_for_reorg_and_reconcile` only re-examines existing
/// payments when a *stored block hash stops matching*, which is a reorg and nothing
/// else. But the textbook attack on a merchant watching the mempool involves no
/// reorg at all: broadcast transaction A to the merchant's node (the order is
/// matched at zero confirmations, and under a `zero_conf_max_piconero` ceiling
/// immediately reads as `paid`), then get transaction B, spending the same inputs,
/// mined instead. A is never mined, so no block the scanner recorded ever changes,
/// so nothing ever looked at that payment again: it sat at `block_height IS NULL`
/// forever, counting in full towards an order the customer never actually paid, with
/// no `order.double_spend_detected` webhook ever fired. The same blind spot swallows
/// the honest version of the story - a transaction that is dropped or evicted from
/// the pool (Monero has no replace-by-fee, but a transaction can still expire out of
/// the pool after `CRYPTONOTE_MEMPOOL_TX_LIVETIME`, or simply never propagate) -
/// which is why the "gone but not proven double-spent" case is deliberately left
/// re-checkable rather than resolved.
///
/// Cheap by construction: a payment whose transaction is still in the pool costs
/// nothing (the snapshot the tick already fetched answers it), and one that has just
/// been mined normally has its height set by this same tick's block scan before this
/// runs, so it isn't in the query's result set either. Only a genuinely vanished
/// transaction costs an RPC, and the evidence rule is identical to
/// `check_for_reorg_and_reconcile`'s: never void on absence, only on an affirmative
/// `SpentInBlockchain` for one of the payment's own key images.
///
/// `mempool_txids` must be a snapshot of an *actually successful* poll. A failed
/// poll must skip this sweep entirely rather than pass an empty set, which would
/// read as "every unconfirmed payment has vanished" and burn one RPC per payment
/// re-establishing that they hadn't.
pub async fn check_vanished_mempool_payments(
    store: &crate::store::SharedStore,
    daemon: &dyn MoneroDaemonClient,
    network: &str,
    mempool_txids: &HashSet<String>,
    current_height: u64,
    now: i64,
) -> Result<VanishedPoolReport> {
    let unconfirmed = store.lock().unwrap().find_unconfirmed_payments(network)?;
    let mut dirty_orders = HashSet::new();
    let mut double_spent_orders = HashSet::new();

    for payment in unconfirmed {
        if mempool_txids.contains(&payment.txid) {
            continue; // still pending in the pool - nothing has been decided about it yet
        }
        match daemon.locate_transaction(&payment.txid).await? {
            // Mined after all: the pool snapshot was taken before the block arrived,
            // or the block scan stopped short of that height this tick. Recording the
            // height here is the same write the block scan would have made, and
            // costs the payment nothing if the block scan gets there first.
            TxLocation::InBlock(new_height) => {
                store.lock().unwrap().update_payment_block_height(
                    &payment.order_id,
                    &payment.txid,
                    payment.output_index,
                    Some(new_height as i64),
                )?;
                dirty_orders.insert(payment.order_id.clone());
            }
            // The daemon's live pool disagrees with the snapshot taken at the top of
            // this tick (it was re-broadcast, or the snapshot was simply a moment
            // stale). Nothing to conclude either way.
            TxLocation::InPool => {}
            TxLocation::NotFound => {
                // Dropped, evicted, still-propagating, and genuinely double-spent
                // transactions are all indistinguishable from here except by their key
                // images - `void_if_double_spend_proven` is where that's resolved, the
                // same way `check_for_reorg_and_reconcile` resolves the identical
                // question. Voiding on anything less would write off a payment the
                // customer really made.
                if void_if_double_spend_proven(store, daemon, &payment, current_height, now).await? {
                    dirty_orders.insert(payment.order_id.clone());
                    double_spent_orders.insert(payment.order_id.clone());
                }
            }
        }
    }

    Ok(VanishedPoolReport {
        dirty_orders: dirty_orders.into_iter().collect(),
        double_spent_orders: double_spent_orders.into_iter().collect(),
    })
}

/// Enqueues a webhook delivery for every enabled webhook on `order_id`'s tenant.
/// Internal orchestration helper - routes through `Store::get_order_tenant_id`
/// (unscoped by design, see its doc comment) since the scanner only has a bare
/// `order_id` at this point, not a tenant-authenticated request.
///
/// Wraps whatever event-specific fields the caller supplies in a common envelope
/// carrying an `event_id`, the `event` type, and a `created_at` timestamp. The
/// `event_id` is minted once per *event* here and baked into the stored payload, so
/// every retry of that delivery re-sends the identical id under the identical
/// signature: that is what lets a receiver tell "the same notification again, my ack
/// must have been lost" apart from "a genuine second transition to the same status",
/// which the previous `{payment_id, status}` payload made indistinguishable. The
/// timestamp being inside the signed body (rather than only an unsigned header) is
/// what stops a captured delivery from being replayable against the merchant
/// indefinitely.
fn enqueue_webhook_event(store: &Store, order_id: &str, event_type: &str, payload: &serde_json::Value, now: i64) -> Result<()> {
    let Some(tenant_id) = store.get_order_tenant_id(order_id)? else { return Ok(()) };
    let webhooks: Vec<_> = store.list_webhooks(&tenant_id)?.into_iter().filter(|w| w.enabled).collect();
    if webhooks.is_empty() {
        return Ok(());
    }

    let mut envelope = payload.clone();
    let fields = envelope
        .as_object_mut()
        .expect("every webhook event payload in this module is constructed as a JSON object");
    fields.insert("event_id".into(), serde_json::json!(new_event_id()));
    fields.insert("event".into(), serde_json::json!(event_type));
    fields.insert("created_at".into(), serde_json::json!(now));
    let body = envelope.to_string();

    for webhook in webhooks {
        store.enqueue_webhook_delivery(&webhook.id, order_id, event_type, &body, now)?;
    }
    Ok(())
}

fn new_event_id() -> String {
    format!("evt_{}", uuid::Uuid::new_v4().simple())
}

/// Recomputes an order's status and, on an actual transition, enqueues an
/// `order.<status>` webhook event for every one of its tenant's webhooks. This is
/// the *only* place status-transition webhooks are enqueued - see
/// `docs/DESIGN.md` §11 for why that's a transition-triggered event, never a
/// per-confirmation-count tick.
///
/// The status write and the enqueue it implies happen in one transaction. They are
/// not independently retryable: `recompute_order_status` decides "did anything
/// change" by comparing against the *stored* status, so the instant the new status
/// commits the transition stops being detectable. Enqueueing separately meant a
/// transient store error (or a crash) in the window between them didn't postpone the
/// merchant's `order.paid`, it destroyed it - permanently, for an order that really
/// is paid. Rolling the status back with the failed enqueue leaves the next tick to
/// redo both.
fn recompute_and_notify(store: &Store, order_id: &str, current_height: u64, now: i64) -> Result<()> {
    store.in_transaction(|store| recompute_and_notify_in_tx(store, order_id, current_height, now))
}

/// The body of `recompute_and_notify`, minus the transaction, for callers that are
/// already inside one - `Store::in_transaction` uses `unchecked_transaction`, so
/// nesting it would fail at SQLite's "cannot start a transaction within a
/// transaction" rather than composing.
fn recompute_and_notify_in_tx(store: &Store, order_id: &str, current_height: u64, now: i64) -> Result<()> {
    let (old_status, new_status) = store.recompute_order_status(order_id, current_height, now)?;
    if old_status != new_status {
        let payload = serde_json::json!({ "payment_id": order_id, "status": new_status.as_str() });
        enqueue_webhook_event(store, order_id, &format!("order.{new_status}"), &payload, now)?;
    }
    Ok(())
}

/// Checks whether `payment`'s own key images prove a double-spend and, if so, voids
/// it (see `void_and_notify`) and reports that it did.
///
/// Shared by `check_for_reorg_and_reconcile` and `check_vanished_mempool_payments`,
/// whose "this payment's transaction is nowhere to be found" case both resolve
/// identically: never void on absence alone, only on an affirmative
/// `SpentInBlockchain` for one of the payment's own key images (§DESIGN.md 7.5). One
/// copy of that evidence rule, not two that could quietly drift apart under a future
/// edit to just one of them.
///
/// Takes `&SharedStore` rather than an already-held `&Store`, and does the daemon
/// call *before* acquiring the lock, for the same reason every other lock hold in
/// this file is kept brief: `is_key_image_spent` is network I/O, and nothing may
/// `.await` while holding the store mutex.
async fn void_if_double_spend_proven(
    store: &crate::store::SharedStore,
    daemon: &dyn MoneroDaemonClient,
    payment: &crate::store::OrderPaymentRow,
    current_height: u64,
    now: i64,
) -> Result<bool> {
    let key_images: Vec<String> = serde_json::from_str(&payment.key_images_json).unwrap_or_default();
    let statuses = daemon.is_key_image_spent(&key_images).await?;
    if !statuses.contains(&KeyImageStatus::SpentInBlockchain) {
        // Still ambiguous (still propagating, or a re-check will catch it next tick)
        // - never void on this evidence alone.
        return Ok(false);
    }
    let s = store.lock().unwrap();
    void_and_notify(&s, &payment.order_id, &payment.txid, payment.output_index, current_height, now)?;
    Ok(true)
}

/// Voids a payment proven double-spent and, in the *same transaction*, records every
/// consequence: the sticky `double_spend_detected_at` stamp, the owning order's
/// recomputed status, the `order.<status>` event if that status moved, and the
/// `order.double_spend_detected` event.
///
/// The atomicity is the point. A void is a committed write, but everything that makes
/// it visible to a merchant used to happen only after the whole reconciliation pass
/// finished - so one unreachable node partway through that pass discarded all of it,
/// and not recoverably. The voided row drops out of the input set of both sweeps by
/// construction (it is no longer an unvoided payment, nor an unconfirmed one), and an
/// order in a terminal status is skipped by the per-tick recompute as well - which is
/// exactly the state an order sits in when this matters, since the merchant was told
/// it was paid. The order was left permanently reading `paid` for money that had been
/// double-spent, with no event ever sent.
fn void_and_notify(
    store: &Store,
    order_id: &str,
    txid: &str,
    output_index: i64,
    current_height: u64,
    now: i64,
) -> Result<()> {
    store.in_transaction(|store| {
        store.void_payment(order_id, txid, output_index, now)?;
        store.mark_double_spend_detected(order_id, now)?;
        recompute_and_notify_in_tx(store, order_id, current_height, now)?;
        // One event per voided payment row (docs/DESIGN.md §11), independent of
        // whatever status transition the recompute above may also have announced.
        enqueue_webhook_event(
            store,
            order_id,
            "order.double_spend_detected",
            &serde_json::json!({ "payment_id": order_id }),
            now,
        )
    })
}

/// One full scan tick for one network: mempool, any new confirmed blocks, then a
/// reorg check - composing the primitives above into what a production scanner
/// loop actually runs on an interval. `network` scopes everything to one chain: the
/// `daemon` passed in must be the client for that same network, `tenants` should be
/// pre-filtered (or filters itself further, see below) to that network's tenants,
/// and every `scanned_blocks`/reorg call is keyed by it. A multi-network instance
/// (§DESIGN.md §7) calls this once per configured network per round, each with its
/// own daemon and its own independent block-height bookkeeping - mixing them under
/// one call would compare block hashes across unrelated chains.
///
/// Takes `&SharedStore` and re-locks it around each `scan_transaction_for_tenant`
/// call rather than for the whole tick - but unlike `webhook_delivery::run_delivery_tick`,
/// it does *not* avoid holding the lock across `scan_transaction_for_tenant`'s
/// internal `.await` on `KeyCustody::scan_tx_outputs`. That await is CPU-bound
/// in-process work (elliptic-curve scalar multiplication), not network I/O, so the
/// hold time is microseconds rather than however long a merchant's webhook
/// endpoint takes to respond - a materially different, and currently accepted,
/// tradeoff. Worth revisiting with `spawn_blocking` if profiling ever shows
/// contention with HTTP handlers.
///
/// On first run (no `scanned_blocks` history at all), seeds at the current chain
/// tip rather than replaying the entire chain from genesis - this is a payment
/// gateway watching for new incoming payments, not a block explorer backfilling
/// history.
pub async fn run_scan_tick(
    store: &crate::store::SharedStore,
    key_custody: &dyn KeyCustody,
    daemon: &dyn MoneroDaemonClient,
    network: &str,
    tenants: &[(String, WalletHandle)],
    reorg_check_depth: u64,
) -> Result<()> {
    let now = crate::now_unix();

    // The active watchlist (docs/DESIGN.md §7.3): only tenants with at least one
    // order still capable of receiving a *new* detected payment are worth the
    // scalar-multiplication cost of scanning. `active_tenant_ids` is a fresh query
    // against the one mutex-serialized Store, not a separately-maintained cache -
    // see its doc comment in `store.rs` for why that's a deliberate choice, not a
    // missed optimization: an incrementally add/removed cache has a real TOCTOU
    // race (a tenant's last order can settle and a brand-new order can arrive for
    // the same tenant in the wrong order relative to an out-of-band "remove"
    // decision, wrongly dropping a tenant with a genuinely pending order), and
    // paying for a fresh indexed query every tick is negligible next to the EC
    // math it avoids. Taking both queries (`active_tenant_ids` and each
    // `get_tenant_by_id`) under one lock hold keeps them mutually consistent -
    // no writer can slip in between deciding a tenant is active and reading its
    // current `next_minor_index`.
    //
    // Also filters by `t.network == network` even though `active_tenant_ids`
    // already scopes by network at the query level - a defensive second check
    // against whatever `tenants` the caller happened to pass in (e.g. a boot-time
    // snapshot spanning every configured network), so a mismatched daemon can never
    // be handed a tenant that belongs to a different chain.
    let ranges: Vec<(String, WalletHandle, Range<u32>)> = {
        let s = store.lock().unwrap();
        let active_ids: HashSet<String> = s.active_tenant_ids(network)?.into_iter().collect();
        tenants
            .iter()
            .filter(|(tenant_id, _)| active_ids.contains(tenant_id))
            .filter_map(|(tenant_id, handle)| {
                let t = s.get_tenant_by_id(tenant_id).ok().flatten()?;
                (t.network == network).then_some((tenant_id.clone(), *handle, 0..t.next_minor_index))
            })
            .collect()
    };

    let mut touched: HashSet<String> = HashSet::new();

    // A failed mempool poll is survivable (the next tick re-polls a second later) but
    // must not be *silent*: if it keeps failing, zero-conf detection is simply off for
    // this network, and an operator whose orders never leave `pending` before a block
    // arrives has nothing anywhere to tell them why.
    let mempool = match daemon.get_mempool_transactions().await {
        Ok(txs) => Some(txs),
        Err(e) => {
            eprintln!("polling the mempool on {network} failed - no zero-conf detection this tick: {e}");
            None
        }
    };
    // The txids of an *actually successful* poll, kept for the vanished-payment
    // sweep below - `None` (a failed poll) makes that sweep skip entirely rather
    // than mistake "we didn't look" for "the pool is empty".
    let mut mempool_txids: Option<HashSet<String>> = None;
    if let Some(mempool_txs) = mempool {
        mempool_txids = Some(mempool_txs.iter().map(tx_id_hex).collect());
        for tx in &mempool_txs {
            for (tenant_id, handle, minor_range) in &ranges {
                // Compute (async, no Store - see ScanResult's doc comment) then
                // persist (sync, no .await) as two separate steps, never a single
                // await-spanning call holding a &Store.
                //
                // A failure here is genuinely recoverable by doing nothing: the
                // mempool is re-polled roughly every second, so the same transaction
                // comes back around next tick. It still gets logged rather than
                // silently swallowed - a persistently failing scan or store call
                // that never surfaces anywhere is indistinguishable from "no
                // payments are arriving".
                match scan_transaction(key_custody, *handle, tx, minor_range.clone()).await {
                    Ok(scan) => {
                        let s = store.lock().unwrap();
                        match record_scan_match(&s, tenant_id, &scan, now, None) {
                            Ok(order_ids) => touched.extend(order_ids),
                            Err(e) => eprintln!(
                                "recording a mempool match for tenant {tenant_id} on {network} failed (will retry next tick): {e}"
                            ),
                        }
                    }
                    Err(e) => eprintln!("scanning a mempool tx for tenant {tenant_id} on {network} failed: {e}"),
                }
            }
        }
    }

    // A failure anywhere in here means "skip block scanning this tick, try again
    // next time" - it must never discard the mempool-scan results already
    // gathered above by short-circuiting the whole function. An earlier version of
    // this function did exactly that (`return Ok(())` from inside this block),
    // which silently dropped a real mempool match's status recompute + webhook
    // whenever the tip-seeding bootstrap below hit the lagging-backend condition
    // it exists to handle - caught only by a test asserting the mempool match's
    // *end-to-end* effect (status + webhook), not just that scanning didn't error.
    let current_height = daemon.get_height().await?;
    let last_scanned = store.lock().unwrap().max_scanned_height(network)?;
    let scan_range = match last_scanned {
        Some(h) => Some((h + 1, current_height)),
        None => {
            // Seeds one block behind the reported tip as a small safety margin
            // against a daemon momentarily reporting a height it can't yet serve a
            // block for (e.g. genuine replication lag across a pool of backend
            // nodes behind a public endpoint). This margin was originally added to
            // work around what turned out to be a different, deterministic bug -
            // `RpcDaemonClient::get_height` misreading monerod's block-count
            // convention as the tip height itself, now fixed at its source in
            // `daemon_rpc.rs`. Kept anyway as cheap, genuine defense for the
            // scenario it actually describes, now that a real bug isn't hiding
            // behind it.
            let seed_height = current_height.saturating_sub(1);
            match daemon.get_block_hash(seed_height).await {
                Ok(hash) => {
                    store.lock().unwrap().set_scanned_block(network, seed_height, &hash)?;
                    Some((seed_height + 1, current_height))
                }
                Err(_) => None,
            }
        }
    };

    // Unlike the mempool loop above, a failure here is *not* self-healing: a block is
    // scanned exactly once, and `set_scanned_block` moves the high-water mark past it
    // whether or not anything in it was successfully recorded. So a single transient
    // store error while recording a match used to lose that payment permanently and
    // without a trace - the block was marked scanned regardless, and nothing ever
    // looked at it again. Any failure at a height therefore abandons the rest of the
    // block range *without* marking that height scanned, leaving the next tick to
    // retry it from the same place; re-recording an already-recorded match is a no-op
    // thanks to `UNIQUE(order_id, txid, output_index)`.
    //
    // Deliberately a `break` rather than an early `return Err(..)`: the mempool
    // matches already gathered above still need their status recompute and webhooks,
    // which returning here would discard (a bug this function has had once before -
    // see the comment above `current_height`).
    if let Some((scan_from, scan_to)) = scan_range {
        'heights: for height in scan_from..=scan_to {
            // Silence here is uniquely dangerous, because unlike every other failure
            // in this loop it is not necessarily transient. A node that cannot supply
            // one of block `height`'s transactions - a pruned node with no blob for
            // it, or any transaction this build of `monero-rs` cannot deserialize -
            // fails this call identically on every subsequent tick, at the same
            // height, forever. The high-water mark never moves again and *no payment
            // on this network is ever detected again*, which without a log line is
            // indistinguishable from "no customers are paying". Stopping the range is
            // still the right call (marking the block scanned would lose whatever it
            // contains); saying so out loud is what makes it diagnosable.
            let block_txs = match daemon.get_block_transactions(height).await {
                Ok(txs) => txs,
                Err(e) => {
                    eprintln!(
                        "fetching the transactions of block {height} on {network} failed - leaving block \
                         {height} unscanned so the next tick retries it. If this repeats at the same height, \
                         the scanner is stuck there and no payment on {network} is being detected: {e}"
                    );
                    break 'heights;
                }
            };
            for tx in &block_txs {
                for (tenant_id, handle, minor_range) in &ranges {
                    let scan = match scan_transaction(key_custody, *handle, tx, minor_range.clone()).await {
                        Ok(scan) => scan,
                        Err(e) => {
                            eprintln!(
                                "scanning a tx in block {height} on {network} for tenant {tenant_id} failed - \
                                 leaving block {height} unscanned so the next tick retries it: {e}"
                            );
                            break 'heights;
                        }
                    };
                    let recorded = {
                        let s = store.lock().unwrap();
                        record_scan_match(&s, tenant_id, &scan, now, Some(height))
                    };
                    match recorded {
                        Ok(order_ids) => touched.extend(order_ids),
                        Err(e) => {
                            eprintln!(
                                "recording a match in block {height} on {network} for tenant {tenant_id} failed - \
                                 leaving block {height} unscanned so the next tick retries it: {e}"
                            );
                            break 'heights;
                        }
                    }
                }
            }
            // Failing to read the hash of a block that was otherwise scanned fine is
            // the same "abandon the range here" situation as any other failure at
            // this height, and for a sharper reason than it looks: continuing would
            // leave a *hole* - height H unrecorded while H+1 onwards are - and
            // `check_for_reorg_and_reconcile` skips heights it has no stored hash
            // for. A later reorg starting at H is then first noticed at H+1, so the
            // reorg point is reported one block too high: the payments actually
            // orphaned at H are never re-evaluated (they keep counting towards their
            // order at a height that no longer exists) and block H of the replacement
            // chain is never rescanned. Stopping here instead simply re-scans H next
            // tick, which is a no-op for anything already recorded.
            match daemon.get_block_hash(height).await {
                // `break 'heights` rather than `?` on the store write, for the same
                // reason every other failure in this loop breaks: returning here
                // would discard the mempool matches gathered above before their
                // status recompute and webhooks ever run - the exact bug called out
                // twice in the comments above. Not marking the height scanned leaves
                // the next tick to redo it, which is a no-op for anything already
                // recorded.
                Ok(hash) => {
                    let written = store.lock().unwrap().set_scanned_block(network, height, &hash);
                    if let Err(e) = written {
                        eprintln!(
                            "recording block {height} on {network} as scanned failed - leaving it unscanned \
                             so the next tick retries it: {e}"
                        );
                        break 'heights;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "reading the hash of block {height} on {network} failed - leaving block {height} \
                         unscanned so the next tick retries it rather than leaving a gap in the reorg window: {e}"
                    );
                    break 'heights;
                }
            }
        }
    }

    // Reconciliation runs *before* the recompute sweep below, not after it. Both
    // orderings recompute the same orders; only this one recomputes them from payment
    // rows the chain still agrees with. Sweeping first means that on the one tick
    // where a reorg is detected, every non-terminal order is evaluated against
    // heights reconciliation is about to invalidate - so an order whose payment was
    // just orphaned can cross its confirmation threshold and fire `order.paid`
    // moments before the same tick voids that payment and fires the retraction. A
    // merchant acting on `order.paid` ships goods; "we sent it, then took it back a
    // second later" is not a recoverable webhook. Reconciling first costs nothing:
    // with no reorg this is a handful of hash comparisons, and the orders it marks
    // dirty simply recompute to the same value again in the sweep, which enqueues
    // nothing when nothing changed.
    let report = check_for_reorg_and_reconcile(store, daemon, network, reorg_check_depth, now).await;

    // The blind spot reorg detection structurally cannot cover: a zero-conf payment
    // whose transaction quietly leaves the pool without ever being mined, because a
    // conflicting transaction won instead. No stored block hash changes in that
    // story, so nothing above would ever look at that payment again. Runs after the
    // block scan deliberately - a transaction mined this tick already has its height
    // recorded by then and is not a candidate at all - and, like reconciliation,
    // before the recompute sweep, so a voided payment can never be announced as a
    // settlement moments before it is retracted.
    let vanished = match &mempool_txids {
        Some(txids) => check_vanished_mempool_payments(store, daemon, network, txids, current_height, now).await,
        None => Ok(VanishedPoolReport { dirty_orders: vec![], double_spent_orders: vec![] }),
    };
    if let Ok(report) = &vanished {
        // Unioned into `touched` rather than recomputed here: an order whose only
        // payment was just voided may well be terminal (`paid` off the zero-conf
        // ceiling is exactly the case this sweep exists for), so it is absent from
        // the non-terminal set the sweep below iterates and would otherwise never be
        // recomputed at all.
        touched.extend(report.dirty_orders.iter().cloned());
    }

    // Every non-terminal order on this network is recomputed, not only the orders
    // whose transactions were matched this tick. An order's status depends on the
    // current chain height (confirmations are derived, never stored per payment) and
    // on wall-clock time (expiry), so an order with entirely unchanged payments still
    // changes status as the chain grows. Recomputing only the `touched` set meant an
    // order was recomputed exactly once - at one confirmation - and then stayed
    // `confirming` forever no matter how deeply buried its payment became, and an
    // unpaid order never became `expired` at all. `touched` is unioned in rather than
    // replaced because a just-matched order may already be terminal (and so absent
    // from the non-terminal set) yet still need its amounts refreshed. The set union
    // is also what keeps this from double-firing webhooks: each order is recomputed
    // at most once per tick, and `recompute_and_notify` only enqueues on an actual
    // status change.
    //
    // Deliberately still runs when reconciliation above failed (its result is only
    // unwrapped afterwards): a node that went unreachable partway through
    // reconciliation leaves a pure retry for the next tick, and holding every order's
    // expiry and confirmation growth hostage to it would turn a transient node blip
    // into orders that silently stop advancing.
    let to_recompute: HashSet<String> = store
        .lock()
        .unwrap()
        .non_terminal_order_ids(network)?
        .into_iter()
        .chain(touched.iter().cloned())
        .collect();
    for order_id in &to_recompute {
        let s = store.lock().unwrap();
        recompute_and_notify(&s, order_id, current_height, now)?;
    }

    // Both reports' `double_spent_orders` are informational here: the
    // `order.double_spend_detected` event for each voided payment was already
    // enqueued by `void_and_notify`, in the same transaction as the void itself, so
    // that a failure later in the same pass can neither lose the event nor leave the
    // order's status describing money that has been written off. Unwrapped only now,
    // after the recompute sweep above, so a node that died mid-reconciliation still
    // leaves every other order's confirmations and expiry advancing.
    let _ = report?;
    let _ = vanished?;

    // Nothing reads a scanned-block row from further back than the reorg window, so
    // keeping every row this service has ever written is pure growth - a block every
    // two minutes, forever, on hardware whose storage is often an SD card. The
    // retention is measured from *this scanner's own* high-water mark rather than the
    // daemon's reported height, so a node briefly claiming an absurd tip cannot talk
    // the scanner into deleting the window it needs, and it is deliberately several
    // times `reorg_check_depth`: the only thing that has to survive is enough history
    // for the deepest reorg the window claims to handle, plus room for a rewind to
    // find its common ancestor below that.
    //
    // Last in the tick, and non-fatal: this is housekeeping, and a tick that detected
    // a payment must not be reported as failed because a delete didn't land.
    {
        let s = store.lock().unwrap();
        if let Ok(Some(high_water)) = s.max_scanned_height(network) {
            let keep_from = high_water.saturating_sub(reorg_check_depth.saturating_mul(4));
            if let Err(e) = s.prune_scanned_blocks_below(network, keep_from) {
                eprintln!("pruning scanned blocks below {keep_from} on {network} failed (harmless, retried next tick): {e}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Scenario coverage checklist for the scanner.
    //!
    //! Reorgs, double-spends and hostile or broken nodes are rare in production and
    //! catastrophic when mishandled, so this module is organised around *classes of
    //! real-world chain and network condition* rather than around functions. The map
    //! below exists so a future maintainer can see at a glance which conditions are
    //! claimed to be covered - and, just as importantly, which limitations are
    //! deliberate. `docs/TESTING.md` §3 is the prose companion to this list.
    //!
    //! 1. **Reorgs, every depth.**
    //!    `a_reorg_is_detected_at_its_true_fork_point_at_every_depth_the_window_covers`
    //!    (1 block through the full `reorg_check_depth` window, one case per depth);
    //!    `a_reorg_deeper_than_the_window_is_reported_at_the_window_edge_and_leaves_older_payments_alone`
    //!    (the documented limitation, §DESIGN.md 3);
    //!    `a_settled_order_is_walked_back_when_a_reorg_deeper_than_confirmations_required_orphans_its_payment`
    //!    (the September 2025 mainnet shape: 18 blocks against 10 confirmations);
    //!    `a_reorg_whose_fork_is_below_every_recorded_block_rewinds_to_that_oldest_block` and
    //!    `a_reorg_back_to_the_oldest_recorded_block_does_not_look_like_a_scanner_that_never_ran`
    //!    (common ancestor at, and below, the edge of the recorded window);
    //!    `reorg_moving_a_tx_to_a_different_block_updates_height_without_voiding`,
    //!    `a_payment_a_reorg_dropped_to_the_mempool_can_still_be_voided_when_later_proven_double_spent`
    //!    (the three outcomes a reorg can have for a payment: remined, pooled, gone).
    //! 2. **Selfish-mining-shaped rapid chain splits.**
    //!    `rapidly_alternating_chain_tips_never_lose_or_double_count_a_payment` - the tip
    //!    trading places repeatedly, the same transaction moving in and out of the
    //!    chain, which is what a withholding pool looks like from here.
    //! 3. **Double-spends, every variant.**
    //!    `reorg_where_tx_vanishes_and_key_image_proven_spent_elsewhere_voids_and_flags_double_spend`
    //!    (the base case); `reorg_where_tx_vanishes_but_key_image_still_unspent_does_not_void`
    //!    (never void on ambiguity); `a_double_spend_mined_in_a_different_block_than_the_original_voids_it_once`;
    //!    `voiding_one_of_an_orders_two_payments_leaves_the_other_counting`;
    //!    `a_voided_payment_is_restored_when_its_transaction_returns_to_the_chain` and
    //!    `a_third_transaction_claiming_the_same_inputs_keeps_the_original_voided`
    //!    (un-voiding, and the chained case where a *third* transaction takes the inputs);
    //!    `a_zero_conf_payment_double_spent_out_of_the_mempool_is_voided_with_no_reorg_involved`
    //!    (the reorg-free mempool double-spend - see `check_vanished_mempool_payments`);
    //!    `a_mempool_payment_that_merely_disappears_is_never_voided_on_that_evidence_alone`
    //!    (dropped/evicted transactions, which Monero produces without any attacker).
    //! 4. **Daemon disconnects and network failures.**
    //!    `a_node_failing_partway_through_the_block_range_resumes_from_that_exact_block`;
    //!    `a_failed_mempool_poll_skips_the_vanished_payment_sweep_rather_than_assuming_an_empty_pool`;
    //!    `a_reconciliation_that_fails_partway_leaves_the_reorg_still_detectable` and
    //!    `a_key_image_lookup_failing_mid_reconciliation_leaves_the_reorg_detectable`
    //!    (failures at each step of reconciliation);
    //!    `a_request_that_times_out_rather_than_failing_fast_is_still_just_a_failed_tick`;
    //!    `a_void_that_lands_before_the_node_fails_still_updates_the_order_it_belongs_to`
    //!    (a committed void and everything that makes it visible are one transaction -
    //!    see `void_and_notify`);
    //!    `a_block_whose_hash_cannot_be_read_stops_the_range_instead_of_leaving_a_gap`;
    //!    `first_run_bootstrap_tolerates_a_daemon_reporting_a_tip_it_cannot_yet_serve`.
    //!    Store-side failures at the same boundaries:
    //!    `a_store_failure_recording_a_block_match_leaves_that_block_unscanned_for_the_next_tick`,
    //!    `a_store_failure_marking_a_block_scanned_does_not_discard_the_ticks_mempool_matches`,
    //!    `a_status_change_whose_webhook_cannot_be_enqueued_is_rolled_back_rather_than_lost`.
    //! 5. **Dishonest or swapped daemons** (see `docs/DESIGN.md` §7.7 for which of
    //!    these are closed and which are accepted trust boundaries).
    //!    `swapping_to_a_daemon_serving_a_different_chain_reconciles_exactly_like_a_reorg`
    //!    (a node presenting a different history is handled by, and is indistinguishable
    //!    from, ordinary reorg detection - which is why no per-daemon sync state exists);
    //!    `a_daemon_that_omits_a_transaction_from_its_mempool_only_delays_detection`;
    //!    `a_transaction_a_daemon_invents_cannot_become_a_payment_unless_it_matches_a_wallet`;
    //!    `an_inflated_reported_height_inflates_confirmations_which_is_an_accepted_trust_boundary`;
    //!    `a_daemon_far_behind_the_recorded_high_water_mark_neither_rescans_nor_discards_its_window`.
    //! 6. **Many transactions per block.**
    //!    `several_transactions_in_one_block_paying_one_order_are_all_recorded_and_summed`;
    //!    `one_transactions_outputs_are_routed_to_whichever_order_owns_each_index`;
    //!    `one_tick_can_void_a_double_spent_payment_for_one_order_and_record_a_new_one_for_another`
    //!    (a payment and an unrelated void in one tick, across two orders sharing one
    //!    transaction - the cross-tenant case migration 0004 exists for).
    //! 7. **Everything else worth naming.**
    //!    `an_output_whose_amount_cannot_be_decrypted_is_skipped_not_recorded_as_zero` and
    //!    `an_amount_that_only_decrypts_on_a_later_tick_is_recorded_then_never_unrecorded`
    //!    (inconsistent amount recovery across ticks, both orderings);
    //!    `a_payment_completing_an_order_in_the_tick_its_deadline_passes_settles_rather_than_expiring`
    //!    (expiry versus payment within one tick, both sides of the boundary);
    //!    `a_chain_with_no_blocks_at_all_is_a_harmless_no_op_tick` and
    //!    `a_divergence_at_the_genesis_block_has_no_ancestor_to_re_anchor_to`
    //!    (degenerate chains: height 0, height 1, genesis divergence);
    //!    `the_scanned_block_window_stays_bounded_as_the_chain_grows`;
    //!    `a_tick_that_detects_a_reorg_never_announces_paid_from_the_chain_it_is_about_to_discard`
    //!    (intra-tick ordering); `the_transaction_variants_these_tests_are_built_from_are_genuinely_distinct`
    //!    (the fixtures the scenarios above are constructed from are what they claim).
    //!
    //! Deliberately *not* covered here, with reasons: clock skew between `now_unix()`
    //! and block timestamps (the scanner never reads a block timestamp - expiry is
    //! purely local wall-clock, so there is no interaction to test); two orders sharing
    //! one subaddress within a tenant (`UNIQUE(tenant_id, minor_index)` makes it
    //! unreachable, and store.rs's `concurrent_minor_index_allocation_never_duplicates`
    //! covers the allocation path that could otherwise reach it); proof-of-work,
    //! difficulty and timestamp validation of blocks (never performed - see
    //! §DESIGN.md 7.7).

    use super::*;
    use crate::daemon::fake::FakeDaemonClient;
    use crate::key_custody::{KeyCustodyError, MatchedOutput, Network, PlainKeyCustody, SubaddressIndex, WalletMaterial};
    use crate::store::{NewOrder, NewTenant};
    use monero::consensus::encode::deserialize;
    use monero::{Address, PrivateKey, PublicKey};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Wraps a real `KeyCustody` and counts calls to `scan_tx_outputs` - the direct
    /// way to prove the active-watchlist optimization actually engages (§DESIGN.md
    /// §7.3), rather than trusting it by inspection. Delegates every other method
    /// unchanged.
    #[derive(Default)]
    struct CountingKeyCustody {
        inner: PlainKeyCustody,
        scan_calls: AtomicU64,
    }

    #[async_trait::async_trait]
    impl KeyCustody for CountingKeyCustody {
        async fn register_wallet(&self, material: WalletMaterial) -> std::result::Result<WalletHandle, KeyCustodyError> {
            self.inner.register_wallet(material).await
        }
        async fn remove_wallet(&self, handle: WalletHandle) -> std::result::Result<(), KeyCustodyError> {
            self.inner.remove_wallet(handle).await
        }
        async fn seal(&self, material: &WalletMaterial) -> std::result::Result<Vec<u8>, KeyCustodyError> {
            self.inner.seal(material).await
        }
        async fn unseal_and_register(&self, sealed: &[u8]) -> std::result::Result<WalletHandle, KeyCustodyError> {
            self.inner.unseal_and_register(sealed).await
        }
        async fn derive_subaddress(
            &self,
            handle: WalletHandle,
            index: SubaddressIndex,
            network: Network,
        ) -> std::result::Result<Address, KeyCustodyError> {
            self.inner.derive_subaddress(handle, index, network).await
        }
        async fn scan_tx_outputs(
            &self,
            handle: WalletHandle,
            tx: &Transaction,
            major_range: Range<u32>,
            minor_range: Range<u32>,
        ) -> std::result::Result<Vec<MatchedOutput>, KeyCustodyError> {
            self.scan_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.scan_tx_outputs(handle, tx, major_range, minor_range).await
        }
    }

    /// Wraps a `FakeDaemonClient` and fails exactly one call - `locate_transaction` -
    /// modelling the most ordinary thing that can go wrong halfway through reorg
    /// reconciliation: the node becomes briefly unreachable after the divergence has
    /// been detected but before the affected payments have been re-evaluated.
    struct DaemonFailingLocate {
        inner: FakeDaemonClient,
    }

    #[async_trait::async_trait]
    impl MoneroDaemonClient for DaemonFailingLocate {
        async fn get_height(&self) -> std::result::Result<u64, DaemonError> {
            self.inner.get_height().await
        }
        async fn get_block_hash(&self, height: u64) -> std::result::Result<String, DaemonError> {
            self.inner.get_block_hash(height).await
        }
        async fn get_block_transactions(&self, height: u64) -> std::result::Result<Vec<Transaction>, DaemonError> {
            self.inner.get_block_transactions(height).await
        }
        async fn get_mempool_transactions(&self) -> std::result::Result<Vec<Transaction>, DaemonError> {
            self.inner.get_mempool_transactions().await
        }
        async fn locate_transaction(&self, _txid: &str) -> std::result::Result<TxLocation, DaemonError> {
            Err(DaemonError::Request("simulated node failure mid-reconciliation".into()))
        }
        async fn is_key_image_spent(&self, key_images: &[String]) -> std::result::Result<Vec<KeyImageStatus>, DaemonError> {
            self.inner.is_key_image_spent(key_images).await
        }
    }

    /// Wraps a `FakeDaemonClient` and fails `get_block_hash` for exactly one height,
    /// leaving everything else - including `get_block_transactions` for that same
    /// height - working. Models one RPC in a tick's sequence failing where its
    /// immediate neighbours succeed, which is the only way a *gap* (rather than a
    /// clean stopping point) can appear in the scanned-block window.
    struct DaemonFailingBlockHashAt {
        inner: FakeDaemonClient,
        failing_height: AtomicU64,
    }

    /// Sentinel for `failing_height` meaning "no height fails" - the wrapper is
    /// deliberately toggleable so one test can drive both the failing tick and the
    /// healthy tick that must recover from it.
    const NO_FAILING_HEIGHT: u64 = u64::MAX;

    #[async_trait::async_trait]
    impl MoneroDaemonClient for DaemonFailingBlockHashAt {
        async fn get_height(&self) -> std::result::Result<u64, DaemonError> {
            self.inner.get_height().await
        }
        async fn get_block_hash(&self, height: u64) -> std::result::Result<String, DaemonError> {
            if height == self.failing_height.load(Ordering::SeqCst) {
                return Err(DaemonError::Request(format!("simulated failure reading the hash of block {height}")));
            }
            self.inner.get_block_hash(height).await
        }
        async fn get_block_transactions(&self, height: u64) -> std::result::Result<Vec<Transaction>, DaemonError> {
            self.inner.get_block_transactions(height).await
        }
        async fn get_mempool_transactions(&self) -> std::result::Result<Vec<Transaction>, DaemonError> {
            self.inner.get_mempool_transactions().await
        }
        async fn locate_transaction(&self, txid: &str) -> std::result::Result<TxLocation, DaemonError> {
            self.inner.locate_transaction(txid).await
        }
        async fn is_key_image_spent(&self, key_images: &[String]) -> std::result::Result<Vec<KeyImageStatus>, DaemonError> {
            self.inner.is_key_image_spent(key_images).await
        }
    }

    /// Which RPC a `DaemonFailingFrom` wrapper is watching. One method at a time,
    /// deliberately: every scenario below is about a *specific* call failing while
    /// its neighbours keep working, which is what distinguishes "the node blipped
    /// mid-tick" from "the node is down" (the latter needs no wrapper - a fake with
    /// no blocks in it already behaves that way).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum DaemonCall {
        Height,
        BlockTransactions,
        Mempool,
        Locate,
        KeyImageSpent,
    }

    /// Wraps a `FakeDaemonClient`, counting calls to one chosen RPC and failing them
    /// from the Nth (0-based) onwards. The generalisation of `DaemonFailingLocate`
    /// and `DaemonFailingBlockHashAt` above, which each hard-code one method: those
    /// stay as they are (their tests read better naming the specific failure), this
    /// one covers the mid-tick failures that need to land on a *particular call* of
    /// a repeated RPC - the second block of a range, say, rather than the first.
    ///
    /// Doubles as a call counter (`fail_from = NO_FAILING_CALL` never fails), which
    /// is how the tests below assert that the vanished-payment sweep costs no RPCs
    /// in the ordinary case rather than trusting that by inspection.
    ///
    /// Generic over the client it wraps so two of these can be stacked - one method
    /// failing while another is counted - which is what "prove the sweep was skipped
    /// *because* the poll failed" needs.
    struct DaemonFailingFrom<D: MoneroDaemonClient> {
        inner: D,
        method: DaemonCall,
        fail_from: AtomicU64,
        calls: AtomicU64,
        /// Milliseconds to wait before the failure surfaces - the difference between
        /// a connection refused instantly and a request that hangs until its client
        /// timeout expires (`RpcDaemonClient` sets 15s). Zero for everything that
        /// doesn't care.
        delay_ms: u64,
    }

    /// Sentinel for `fail_from`: count, never fail.
    const NO_FAILING_CALL: u64 = u64::MAX;

    impl<D: MoneroDaemonClient> DaemonFailingFrom<D> {
        fn counting(inner: D, method: DaemonCall) -> Self {
            Self { inner, method, fail_from: AtomicU64::new(NO_FAILING_CALL), calls: AtomicU64::new(0), delay_ms: 0 }
        }
        fn failing_from(inner: D, method: DaemonCall, nth: u64) -> Self {
            Self { inner, method, fail_from: AtomicU64::new(nth), calls: AtomicU64::new(0), delay_ms: 0 }
        }
        fn timing_out_from(inner: D, method: DaemonCall, nth: u64, delay_ms: u64) -> Self {
            Self { inner, method, fail_from: AtomicU64::new(nth), calls: AtomicU64::new(0), delay_ms }
        }
        fn call_count(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
        fn stop_failing(&self) {
            self.fail_from.store(NO_FAILING_CALL, Ordering::SeqCst);
        }
        async fn gate(&self, method: DaemonCall) -> std::result::Result<(), DaemonError> {
            if method != self.method {
                return Ok(());
            }
            let nth = self.calls.fetch_add(1, Ordering::SeqCst);
            if nth >= self.fail_from.load(Ordering::SeqCst) {
                if self.delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
                }
                return Err(DaemonError::Request(format!("simulated {method:?} failure on call {nth}")));
            }
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl<D: MoneroDaemonClient> MoneroDaemonClient for DaemonFailingFrom<D> {
        async fn get_height(&self) -> std::result::Result<u64, DaemonError> {
            self.gate(DaemonCall::Height).await?;
            self.inner.get_height().await
        }
        async fn get_block_hash(&self, height: u64) -> std::result::Result<String, DaemonError> {
            self.inner.get_block_hash(height).await
        }
        async fn get_block_transactions(&self, height: u64) -> std::result::Result<Vec<Transaction>, DaemonError> {
            self.gate(DaemonCall::BlockTransactions).await?;
            self.inner.get_block_transactions(height).await
        }
        async fn get_mempool_transactions(&self) -> std::result::Result<Vec<Transaction>, DaemonError> {
            self.gate(DaemonCall::Mempool).await?;
            self.inner.get_mempool_transactions().await
        }
        async fn locate_transaction(&self, txid: &str) -> std::result::Result<TxLocation, DaemonError> {
            self.gate(DaemonCall::Locate).await?;
            self.inner.locate_transaction(txid).await
        }
        async fn is_key_image_spent(&self, key_images: &[String]) -> std::result::Result<Vec<KeyImageStatus>, DaemonError> {
            self.gate(DaemonCall::KeyImageSpent).await?;
            self.inner.is_key_image_spent(key_images).await
        }
    }

    /// The same real fixture transaction and view pair used in
    /// `src/key_custody/plain.rs`'s tests - it pays subaddress 0/1. Reused here so
    /// scanner-level tests exercise real crypto end to end, not a stub that assumes
    /// matching works.
    fn fixture_tx() -> Transaction {
        let raw_tx = hex::decode(include_str!("../tests/fixtures/subaddress_tx.hex")).unwrap();
        deserialize(&raw_tx).unwrap()
    }

    fn fixture_view_key() -> [u8; 32] {
        PrivateKey::from_slice(
            &hex::decode("bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07").unwrap(),
        )
        .unwrap()
        .to_bytes()
    }

    fn fixture_spend_pubkey() -> [u8; 32] {
        let secret_spend = PrivateKey::from_slice(
            &hex::decode("e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907").unwrap(),
        )
        .unwrap();
        PublicKey::from_private_key(&secret_spend).to_bytes()
    }

    async fn setup() -> (Store, PlainKeyCustody, WalletHandle, String, String) {
        setup_with_zero_conf_ceiling(None).await
    }

    /// `setup()` with a merchant-configured zero-conf trust ceiling, for the
    /// scenarios where an order settles off a mempool sighting alone - the case a
    /// plain double-spend actually costs a merchant something, since they may have
    /// shipped against it.
    async fn setup_with_zero_conf_ceiling(
        zero_conf_max_piconero: Option<u64>,
    ) -> (Store, PlainKeyCustody, WalletHandle, String, String) {
        let store = Store::open_in_memory().unwrap();
        let key_custody = PlainKeyCustody::default();
        let handle = key_custody
            .register_wallet(WalletMaterial::new(fixture_view_key(), fixture_spend_pubkey()))
            .await
            .unwrap();

        let created = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "4fixture".into(),
                    network: "mainnet".into(),
                    allowed_origins: vec![],
                    confirmations_required: Some(10),
                    zero_conf_max_piconero,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();
        let tenant_id = created.tenant.id.clone();

        // The fixture tx pays subaddress 0/1 - derive that address for real via
        // KeyCustody and issue the order against it, exactly as production code
        // would (order creation happens to land on minor index 1 here since the
        // tenant starts at next_minor_index = 1).
        let index = store.allocate_minor_index(&tenant_id).unwrap();
        assert_eq!(index, 1, "fixture tx pays minor index 1 - keep this in sync with the order below");
        let address = key_custody
            .derive_subaddress(handle, SubaddressIndex { major: 0, minor: index }, Network::Mainnet)
            .await
            .unwrap();

        let order = store
            .create_order(NewOrder {
                tenant_id: tenant_id.clone(),
                merchant_order_id: None,
                minor_index: index,
                address: address.to_string(),
                fiat_currency: "USD".into(),
                fiat_amount: "1.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 1, // fixture tx amount is unknown ahead of time; use a trivially-satisfied amount
                description: None,
                created_at: 1000,
                // Genuinely in the future: every tick now recomputes every
                // non-terminal order, so a fixture expiry in the past (999_999_999 is
                // in 2001) would flip these orders to `expired` on the first tick.
                expires_at: crate::now_unix() + 3600,
            })
            .unwrap();

        (store, key_custody, handle, tenant_id, order.id)
    }

    #[tokio::test]
    async fn scanning_a_mempool_tx_records_a_payment_against_the_right_order() {
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();

        let touched = scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, None)
            .await
            .unwrap();

        assert_eq!(touched, HashSet::from([order_id.clone()]));
        let payments = store.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1);
        assert!(payments[0].amount_piconero > 0);
        assert_eq!(payments[0].block_height, None); // mempool-only
    }

    #[tokio::test]
    async fn rescanning_the_same_mempool_tx_does_not_duplicate_the_payment() {
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();

        for _ in 0..3 {
            scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, None)
                .await
                .unwrap();
        }
        assert_eq!(store.get_all_payments(&order_id).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn reorg_moving_a_tx_to_a_different_block_updates_height_without_voiding() {
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();

        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();

        let daemon = FakeDaemonClient::new();
        // Fast-forward the fake daemon's internal height counter to 49 by pushing
        // filler blocks, then reorg from 50 with the tx moved to the new height 51.
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        daemon.reorg_from(50, vec![("hash_50_v2", vec![]), ("hash_51_v2", vec![tx.clone()])]);

        let store = store.into_shared();
        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(50));
        assert!(report.dirty_orders.contains(&order_id));
        assert!(report.double_spent_orders.is_empty());

        let payments = store.lock().unwrap().get_all_payments(&order_id).unwrap();
        assert_eq!(payments[0].block_height, Some(51));
        assert!(payments[0].voided_at.is_none());
    }

    #[tokio::test]
    async fn reorg_where_tx_vanishes_and_key_image_proven_spent_elsewhere_voids_and_flags_double_spend() {
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let txid = tx_id_hex(&tx);
        let key_images = key_images_of(&tx);
        assert!(!key_images.is_empty(), "fixture tx must have at least one input to test key-image proof");

        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();

        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        // The replacement chain does NOT include our tx at all - it vanished.
        daemon.reorg_from(50, vec![("hash_50_v2", vec![])]);
        // And its inputs are now proven spent by a different, unrelated transaction.
        for ki in &key_images {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }

        let store = store.into_shared();
        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(50));
        assert_eq!(report.dirty_orders, vec![order_id.clone()]);
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);

        let store = store.lock().unwrap();
        let payments = store.get_all_payments(&order_id).unwrap();
        assert!(payments[0].voided_at.is_some());
        let order = store.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert!(order.double_spend_detected_at.is_some());
        let _ = txid; // kept for readability of the scenario, not asserted on directly
    }

    #[tokio::test]
    async fn reorg_where_tx_vanishes_but_key_image_still_unspent_does_not_void() {
        // Safety property: never void on ambiguous evidence. A tx that vanished
        // from the chain but whose inputs are still unspent is most likely just
        // still propagating and will be re-caught on a later tick.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();

        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();

        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        daemon.reorg_from(50, vec![("hash_50_v2", vec![])]);
        // Deliberately do NOT mark the key images as spent - default is Unspent.

        let store = store.into_shared();
        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert!(report.double_spent_orders.is_empty());

        let payments = store.lock().unwrap().get_all_payments(&order_id).unwrap();
        assert!(payments[0].voided_at.is_none(), "must not void on ambiguous (unspent) evidence");
    }

    #[tokio::test]
    async fn no_reorg_when_hashes_still_match_is_a_cheap_no_op() {
        let store = Store::open_in_memory().unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50").unwrap();
        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 50 {
            let h = if last_height == 49 { "hash_50" } else { "filler" };
            last_height = daemon.push_block(h, vec![]);
        }

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, None);
        assert!(report.dirty_orders.is_empty());
    }

    #[tokio::test]
    async fn run_scan_tick_matches_mempool_tx_recomputes_status_and_enqueues_a_webhook() {
        // End-to-end proof of the composed orchestration, not just its pieces: a
        // real transaction sitting in a fake daemon's mempool gets matched, the
        // owning order's status transitions (pending -> unconfirmed, since this is
        // a 0-conf-only match with no zero-conf trust ceiling configured), and
        // exactly one webhook delivery is enqueued for that transition.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let webhook = store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]); // the fake starts at height 0 with no block there at all; give the first-run tip bootstrap something real to seed from
        daemon.set_mempool(vec![fixture_tx()]);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.status, crate::status::OrderStatus::Unconfirmed);
        assert!(order.amount_received_piconero > 0);

        let due = s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].webhook_id, webhook.id);
        assert_eq!(due[0].event_type, "order.unconfirmed");
    }

    /// Creates a tenant with one pending order against `key_custody`, returning
    /// `(tenant_id, handle, order_id)`. Shared by the watchlist tests below, which
    /// need to construct tenants against a `CountingKeyCustody` rather than
    /// `setup()`'s hardcoded `PlainKeyCustody`.
    async fn tenant_with_pending_order(
        store: &Store,
        key_custody: &dyn KeyCustody,
        view_key: [u8; 32],
        spend_pubkey: [u8; 32],
    ) -> (String, WalletHandle, String) {
        let handle = key_custody.register_wallet(WalletMaterial::new(view_key, spend_pubkey)).await.unwrap();
        let tenant = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "4x".into(),
                    network: "mainnet".into(),
                    allowed_origins: vec![],
                    confirmations_required: Some(10),
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();
        let index = store.allocate_minor_index(&tenant.tenant.id).unwrap();
        let address = key_custody
            .derive_subaddress(handle, SubaddressIndex { major: 0, minor: index }, Network::Mainnet)
            .await
            .unwrap();
        let order = store
            .create_order(NewOrder {
                tenant_id: tenant.tenant.id.clone(),
                merchant_order_id: None,
                minor_index: index,
                address: address.to_string(),
                fiat_currency: "USD".into(),
                fiat_amount: "1.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 1,
                description: None,
                created_at: 1000,
                // Genuinely in the future: every tick now recomputes every
                // non-terminal order, so a fixture expiry in the past (999_999_999 is
                // in 2001) would flip these orders to `expired` on the first tick.
                expires_at: crate::now_unix() + 3600,
            })
            .unwrap();
        (tenant.tenant.id, handle, order.id)
    }

    fn arbitrary_wallet_material(seed: u8) -> ([u8; 32], [u8; 32]) {
        let mut view_bytes = [seed; 32];
        view_bytes[31] &= 0x0f;
        let mut spend_seed = [seed.wrapping_add(1); 32];
        spend_seed[31] &= 0x0f;
        let secret_spend = PrivateKey::from_slice(&spend_seed).unwrap();
        (view_bytes, PublicKey::from_private_key(&secret_spend).to_bytes())
    }

    #[tokio::test]
    async fn run_scan_tick_never_calls_key_custody_for_a_tenant_with_no_pending_orders() {
        // Direct proof of docs/DESIGN.md §7.3's active-watchlist optimization,
        // using a call-counting spy rather than trusting it by inspection - see
        // docs/TESTING.md §4. Tenant A has a pending order and a real fixture view
        // pair (so a genuine match happens); tenant B is registered with
        // KeyCustody but has never had any order at all.
        let key_custody = CountingKeyCustody::default();
        let store = Store::open_in_memory().unwrap();

        let (tenant_a, handle_a, _order_a) =
            tenant_with_pending_order(&store, &key_custody, fixture_view_key(), fixture_spend_pubkey()).await;

        let (view_b, spend_b) = arbitrary_wallet_material(0x70);
        let handle_b = key_custody.register_wallet(WalletMaterial::new(view_b, spend_b)).await.unwrap();
        let tenant_b = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "4b".into(),
                    network: "mainnet".into(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();

        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.set_mempool(vec![fixture_tx()]);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_a, handle_a), (tenant_b.tenant.id, handle_b)], 20)
            .await
            .unwrap();

        assert_eq!(
            key_custody.scan_calls.load(Ordering::SeqCst),
            1,
            "exactly one scan call expected: tenant A (has a pending order) scanned once, tenant B (no orders ever) never scanned"
        );
    }

    #[tokio::test]
    async fn run_scan_tick_never_scans_a_tenant_on_a_different_network_even_if_included_in_the_input_list() {
        // Defense-in-depth for the multi-network design (§DESIGN.md §7): a
        // mainnet-network tick must not touch a pending stagenet tenant's data at
        // all, even though `active_tenant_ids` already scopes by network - this
        // proves the *second*, independent filter (`t.network == network` in
        // `run_scan_tick` itself) actually engages, guarding against a caller (e.g.
        // a future refactor of `main.rs`'s scanner loop) accidentally passing an
        // unfiltered, all-networks tenant list into a single network's tick.
        let key_custody = CountingKeyCustody::default();
        let store = Store::open_in_memory().unwrap();

        let (mainnet_tenant, mainnet_handle, _order) =
            tenant_with_pending_order(&store, &key_custody, fixture_view_key(), fixture_spend_pubkey()).await;

        let (view_b, spend_b) = arbitrary_wallet_material(0x50);
        let stagenet_handle = key_custody.register_wallet(WalletMaterial::new(view_b, spend_b)).await.unwrap();
        let stagenet_tenant = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "5stagenet".into(),
                    network: "stagenet".into(),
                    allowed_origins: vec![],
                    confirmations_required: Some(10),
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();
        // A genuinely pending order on stagenet - if the network filter didn't
        // work, this tenant would be scanned too.
        store
            .create_order(NewOrder {
                tenant_id: stagenet_tenant.tenant.id.clone(),
                merchant_order_id: None,
                minor_index: store.allocate_minor_index(&stagenet_tenant.tenant.id).unwrap(),
                address: "5someaddress".into(),
                fiat_currency: "USD".into(),
                fiat_amount: "1.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 1,
                description: None,
                created_at: 1000,
                // Genuinely in the future: every tick now recomputes every
                // non-terminal order, so a fixture expiry in the past (999_999_999 is
                // in 2001) would flip these orders to `expired` on the first tick.
                expires_at: crate::now_unix() + 3600,
            })
            .unwrap();

        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.set_mempool(vec![fixture_tx()]);

        // Deliberately pass BOTH tenants into a "mainnet" tick, simulating
        // main.rs's scanner loop handing the *full* wallet_handles registry
        // (spanning every configured network) to a single network's call.
        run_scan_tick(
            &store,
            &key_custody,
            &daemon,
            "mainnet",
            &[(mainnet_tenant, mainnet_handle), (stagenet_tenant.tenant.id, stagenet_handle)],
            20,
        )
        .await
        .unwrap();

        assert_eq!(
            key_custody.scan_calls.load(Ordering::SeqCst),
            1,
            "only the mainnet tenant should be scanned during a \"mainnet\" tick, regardless of what else is in the input list"
        );
    }

    #[tokio::test]
    async fn run_scan_tick_stops_scanning_a_tenant_the_tick_after_it_fully_settles() {
        // Complements the store-level test of the same scenario
        // (`tenant_becomes_inactive_once_its_only_order_settles...` in store.rs) by
        // proving it at the scanner's actual call boundary: once an order reaches a
        // terminal status, the *next* tick must not invoke KeyCustody for that
        // tenant at all, even though the exact same mempool transaction is still
        // sitting there.
        let key_custody = CountingKeyCustody::default();
        let store = Store::open_in_memory().unwrap();
        let (tenant_id, _handle, order_id) =
            tenant_with_pending_order(&store, &key_custody, fixture_view_key(), fixture_spend_pubkey()).await;
        let handle = key_custody
            .register_wallet(WalletMaterial::new(fixture_view_key(), fixture_spend_pubkey()))
            .await
            .unwrap();
        // (Re-registering under the same key material is fine for this test - only
        // the handle identity matters for routing scan calls, not which handle
        // number KeyCustody happened to assign.)

        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.set_mempool(vec![fixture_tx()]);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(key_custody.scan_calls.load(Ordering::SeqCst), 1);

        // Force the order to a terminal state the way "10 confirmations later"
        // naturally would: give the payment tick 1 already recorded a real block
        // height (rather than layering on a second payment, which would leave the
        // first one's 0-conf status dragging min-confirmations back to 0) and
        // recompute - the same public API the real block-scanning path uses.
        {
            let s = store.lock().unwrap();
            let txid = tx_id_hex(&fixture_tx());
            s.update_payment_block_height(&order_id, &txid, 1, Some(1)).unwrap(); // output_index 1, per the fixture's known match (see key_custody::plain's tests)
            let (_, new_status) = s.recompute_order_status(&order_id, 100, 1600).unwrap(); // 100 confirmations
            assert!(matches!(new_status, crate::status::OrderStatus::Paid | crate::status::OrderStatus::Overpaid));
        }

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();
        assert_eq!(
            key_custody.scan_calls.load(Ordering::SeqCst),
            1,
            "tenant settled after tick 1 - tick 2 must not invoke KeyCustody for it again, even with the same mempool tx still present"
        );
    }

    #[tokio::test]
    async fn run_scan_tick_on_first_run_seeds_near_the_current_tip_instead_of_scanning_all_history() {
        // A fresh scanner (no scanned_blocks yet) must not try to replay the
        // entire chain. It seeds one block behind the reported tip (see the next
        // test for why) but then immediately scans forward through the real tip
        // too within the same tick, provided that block is actually fetchable -
        // the lagging-backend condition the seed-behind logic guards against is
        // the exception, not the common case.
        let (store, key_custody, handle, tenant_id, _order_id) = setup().await;
        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        for i in 0..10 {
            daemon.push_block(&format!("h{i}"), vec![]);
        }

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();

        assert_eq!(store.lock().unwrap().max_scanned_height("mainnet").unwrap(), Some(10));
    }

    #[tokio::test]
    async fn first_run_bootstrap_tolerates_a_daemon_reporting_a_tip_it_cannot_yet_serve() {
        // Observed live against a real public node (see the comment on
        // `run_scan_tick`'s bootstrap branch): a public endpoint can be a small
        // pool of backend nodes a block apart, so `get_height` can briefly report
        // a tip that `get_block_hash` then rejects for that same height. This must
        // degrade to "try again next tick", never a hard error that kills the tick.
        let (store, key_custody, handle, tenant_id, _order_id) = setup().await;
        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        for i in 0..10 {
            daemon.push_block(&format!("h{i}"), vec![]);
        }
        // Simulate the height-reporting backend being one block ahead of the
        // block-serving backend: report height 11, but no block 11 exists yet.
        daemon.advance_height_without_a_block();

        let result = run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await;
        assert!(result.is_ok(), "must not hard-fail the tick just because the tip block isn't fetchable yet");
        // Falls back to seeding one behind the (unfetchable) reported tip, i.e.
        // height 10, which *does* exist.
        assert_eq!(store.lock().unwrap().max_scanned_height("mainnet").unwrap(), Some(10));

        // Once the block-serving backend catches up, a later tick proceeds
        // normally from where the fallback seeded it.
        daemon.push_block("h10_actual", vec![]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();
        assert_eq!(store.lock().unwrap().max_scanned_height("mainnet").unwrap(), Some(11));
    }

    #[tokio::test]
    async fn an_output_whose_amount_cannot_be_decrypted_is_skipped_not_recorded_as_zero() {
        // Monero output-amount recovery can fail, which is why `MatchedOutput::
        // amount_piconero` is an `Option` at all. Recording the failure as a
        // 0-piconero payment is strictly worse than recording nothing: the row
        // contributes no money while still participating in `min_confirmations` and
        // `all_zero_conf` (see status.rs's
        // `a_zeroed_but_present_row_is_not_a_safe_substitute_for_exclusion`, which
        // documents exactly how that corrupts the derived status), and it can never
        // be removed afterwards, because voiding requires affirmative double-spend
        // proof that will never arrive for a perfectly valid output.
        let (store, _key_custody, _handle, tenant_id, order_id) = setup().await;

        let scan = ScanResult {
            matches: vec![MatchedOutput {
                output_index: 0,
                subaddress_index: SubaddressIndex { major: 0, minor: 1 }, // the order created by setup()
                amount_piconero: None,
            }],
            txid: "tx_with_an_undecryptable_output".into(),
            key_images_json: "[]".into(),
        };

        let touched = record_scan_match(&store, &tenant_id, &scan, 1500, Some(50)).unwrap();
        assert!(touched.is_empty(), "an unmeasurable output must not even mark the order as needing a recompute");
        assert!(
            store.get_all_payments(&order_id).unwrap().is_empty(),
            "nothing may be persisted for an output whose amount could not be recovered"
        );

        // The order is untouched, so a later tick that *can* decrypt the amount is
        // still free to record it properly.
        let order = store.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.status, crate::status::OrderStatus::Pending);
        assert_eq!(order.amount_received_piconero, 0);
    }

    #[tokio::test]
    async fn a_store_failure_recording_a_block_match_leaves_that_block_unscanned_for_the_next_tick() {
        // The highest-consequence silent failure in this file: block scanning used
        // to discard the error from `record_scan_match` (`if let Ok(..)`) and then
        // call `set_scanned_block` for that height regardless. Blocks are scanned
        // exactly once, so one transient store error meant the payment inside that
        // block was never seen by anything, ever, with nothing logged. The block must
        // instead stay unscanned so the next tick retries it - re-recording is a
        // no-op thanks to `UNIQUE(order_id, txid, output_index)`.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]); // height 1 - something for the tip bootstrap to seed from
        daemon.push_block("h2", vec![fixture_tx()]); // height 2 - carries the payment

        // Fail only *inserts* into order_payments, leaving every read working, so
        // this reproduces a write failure specifically rather than a broken database.
        store
            .lock()
            .unwrap()
            .execute_raw_for_test(
                "CREATE TRIGGER simulated_write_failure BEFORE INSERT ON order_payments
                 BEGIN SELECT RAISE(ABORT, 'simulated store failure'); END;",
            )
            .unwrap();

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(
            store.lock().unwrap().max_scanned_height("mainnet").unwrap(),
            Some(1),
            "block 2's match failed to record - marking it scanned would lose that payment permanently"
        );
        assert!(store.lock().unwrap().get_all_payments(&order_id).unwrap().is_empty());

        // Once the store is healthy again, the very next tick re-covers the block it
        // deliberately left behind.
        store.lock().unwrap().execute_raw_for_test("DROP TRIGGER simulated_write_failure;").unwrap();
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();

        assert_eq!(store.lock().unwrap().max_scanned_height("mainnet").unwrap(), Some(2));
        let payments = store.lock().unwrap().get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].block_height, Some(2));
    }

    #[tokio::test]
    async fn an_order_reaches_paid_as_the_chain_advances_without_any_new_payment_arriving() {
        // The bug this protects against made the service unusable for its actual
        // purpose: `run_scan_tick` recomputed only the orders whose transactions it
        // matched *that tick*, but an order's confirmation count is derived from the
        // current chain height at recompute time and stored nowhere. So an order was
        // recomputed exactly once - at one confirmation - and then sat at
        // `confirming` forever no matter how deeply its payment was buried, with the
        // `order.paid` webhook the merchant is waiting on never firing.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await; // confirmations_required = 10
        let webhook = store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.push_block("h2", vec![fixture_tx()]); // the payment lands at height 2

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
            assert_eq!(order.status, crate::status::OrderStatus::Confirming, "one confirmation, ten required");
        }

        // Nine more blocks, none of which contain anything for this order at all.
        for i in 3..=11 {
            daemon.push_block(&format!("h{i}"), vec![]);
        }
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(
            order.status,
            crate::status::OrderStatus::Overpaid, // the fixture tx pays more than this order's trivially-small expected amount
            "10 confirmations deep - nothing new matched, but the chain moved"
        );
        assert_eq!(order.confirmations, 10);

        // And the transition the merchant is actually waiting on was announced.
        let events: Vec<String> = s
            .due_webhook_deliveries(crate::now_unix() + 1, 10)
            .unwrap()
            .into_iter()
            .inspect(|d| assert_eq!(d.webhook_id, webhook.id))
            .map(|d| d.event_type)
            .collect();
        assert_eq!(
            events,
            vec!["order.confirming".to_string(), "order.overpaid".to_string()],
            "exactly one event per real transition, in order, with no repeats from the per-tick recompute"
        );
    }

    #[tokio::test]
    async fn an_unpaid_order_past_its_deadline_becomes_expired_on_a_tick_that_matches_nothing() {
        // The same root cause as the confirmations bug, on the other axis: expiry is
        // a function of wall-clock time, and an order that never receives a payment
        // is never in the `touched` set, so it was never recomputed and stayed
        // `pending` indefinitely.
        let (store, key_custody, handle, tenant_id, _order_id) = setup().await;
        let webhook = store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();

        // A second order on the same tenant, already past its deadline and never paid.
        let stale = store
            .create_order(NewOrder {
                tenant_id: tenant_id.clone(),
                merchant_order_id: None,
                minor_index: store.allocate_minor_index(&tenant_id).unwrap(),
                address: "sub_expired".into(),
                fiat_currency: "USD".into(),
                fiat_amount: "1.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 1_000_000,
                description: None,
                created_at: 1000,
                expires_at: crate::now_unix() - 1,
            })
            .unwrap();
        assert_eq!(stale.status, crate::status::OrderStatus::Pending);
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]); // an entirely uneventful tick: no mempool, no matches

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert_eq!(
            s.get_order(&tenant_id, &stale.id).unwrap().unwrap().status,
            crate::status::OrderStatus::Expired
        );
        let expired_events = s
            .due_webhook_deliveries(crate::now_unix() + 1, 10)
            .unwrap()
            .into_iter()
            .filter(|d| d.order_id == stale.id)
            .map(|d| d.event_type)
            .collect::<Vec<_>>();
        assert_eq!(expired_events, vec!["order.expired".to_string()]);
        let _ = webhook;
    }

    #[tokio::test]
    async fn a_reorg_driven_status_change_enqueues_a_webhook_just_like_a_forward_scan_one() {
        // Reorg reconciliation called the bare `Store::recompute_order_status`
        // instead of the notifying wrapper the normal payment path uses, and
        // `run_scan_tick` then threw `dirty_orders` away entirely - so an order
        // walking backwards from `paid` to `confirming` because its transaction was
        // remined shallower updated silently, and the merchant's only way to find
        // out was to poll.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let webhook = store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let tx = fixture_tx();

        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();
        let (_, status) = store.recompute_order_status(&order_id, 100, 1600).unwrap();
        assert_eq!(status, crate::status::OrderStatus::Overpaid, "51 confirmations deep before the reorg");

        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        // The transaction survives the reorg but is remined at the new tip, so it is
        // suddenly one confirmation deep again instead of fifty-one.
        daemon.reorg_from(50, vec![("hash_50_v2", vec![]), ("hash_51_v2", vec![tx.clone()])]);

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(50));
        assert!(report.double_spent_orders.is_empty(), "a remined transaction is not a double-spend");

        let s = store.lock().unwrap();
        assert_eq!(
            s.get_order(&tenant_id, &order_id).unwrap().unwrap().status,
            crate::status::OrderStatus::Confirming
        );
        let due = s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap();
        assert_eq!(due.len(), 1, "the paid -> confirming transition must be announced exactly once");
        assert_eq!(due[0].event_type, "order.confirming");
        assert_eq!(due[0].webhook_id, webhook.id);
    }

    #[tokio::test]
    async fn a_reconciliation_that_fails_partway_leaves_the_reorg_still_detectable() {
        // The stored block hashes used to be corrected *inside* the detection loop,
        // before any payment had been looked at. Once that write landed, the stored
        // and actual chains agreed, so a later failure - or a crash - meant no future
        // tick could ever tell a reorg had happened, and the payments it affected
        // were stranded on a chain that no longer exists. Correcting the stored view
        // only after reconciliation succeeds makes a failed pass a pure retry.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();
        let store = store.into_shared();

        let inner = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = inner.push_block(&format!("filler_{last_height}"), vec![]);
        }
        inner.reorg_from(50, vec![("hash_50_v2", vec![]), ("hash_51_v2", vec![tx.clone()])]);

        let failing = DaemonFailingLocate { inner };
        assert!(
            check_for_reorg_and_reconcile(&store, &failing, "mainnet", 20, 2000).await.is_err(),
            "the node failure must surface, not be swallowed"
        );
        assert_eq!(
            store.lock().unwrap().get_scanned_block_hash("mainnet", 50).unwrap(),
            Some("hash_50_v1".to_string()),
            "the stored hash must still describe the old chain, or nothing will ever notice the reorg again"
        );
        assert_eq!(
            store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].block_height,
            Some(50),
            "and the payment is still unreconciled, as the failed pass left it"
        );

        // The retry a healthy next tick performs now works, because the evidence the
        // detection depends on is still there.
        let report = check_for_reorg_and_reconcile(&store, &failing.inner, "mainnet", 20, 2100).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(50));
        assert_eq!(store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].block_height, Some(51));
    }

    #[tokio::test]
    async fn after_a_reorg_the_replacement_blocks_are_forward_scanned_again() {
        // Reconciliation only ever re-examines payments it already knew about, so a
        // payment that exists *only* in the replacement chain - the transaction was
        // rebroadcast and mined into the fork that won - was never seen at all: the
        // scanner's high-water mark was still above those heights and blocks below it
        // are never revisited. Dropping the scanned-block rows at and above the reorg
        // point is what puts them back in range of the ordinary forward scan.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        // A scanner that has already worked its way up to height 51 on the old chain.
        for h in 40..=51 {
            store.set_scanned_block("mainnet", h, &format!("old_{h}")).unwrap();
        }
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("old_{}", last_height + 1), vec![]);
        }
        // The fork replaces 50 and 51, and the payment lives at height 50 - *below*
        // the high-water mark, so nothing would ever look there again on its own.
        daemon.reorg_from(50, vec![("new_50", vec![fixture_tx()]), ("new_51", vec![])]);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            assert_eq!(
                s.max_scanned_height("mainnet").unwrap(),
                Some(49),
                "the high-water mark must fall back below the reorg point"
            );
            assert!(s.get_all_payments(&order_id).unwrap().is_empty(), "nothing found yet - this tick only rewound");
        }

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(51), "and forward scanning caught back up");
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1, "the payment that exists only in the replacement chain was found");
        assert_eq!(payments[0].block_height, Some(50));
    }

    #[tokio::test]
    async fn a_voided_payment_is_restored_when_its_transaction_returns_to_the_chain() {
        // Voiding is a conclusion drawn from a chain state that can itself change:
        // the replacement transaction that proved the double-spend can be reorged
        // out in turn, putting the original back on the canonical chain. Because
        // `find_payments_at_or_after_height` filters voided rows out, a voided
        // payment was invisible to every future reconciliation pass and the
        // merchant's genuinely-paid order stayed permanently short.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let key_images = key_images_of(&tx);

        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        daemon.reorg_from(50, vec![("hash_50_v2", vec![])]); // the tx vanishes
        for ki in &key_images {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain); // ...and is proven double-spent
        }

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);
        assert!(store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].voided_at.is_some());

        // Now the attacker's replacement chain loses, and the original transaction is
        // back in a block. (The forward scan would have recorded the new hash for
        // height 50 between the two reconciliations; do that by hand here.)
        store.lock().unwrap().set_scanned_block("mainnet", 50, "hash_50_v2").unwrap();
        daemon.reorg_from(50, vec![("hash_50_v3", vec![tx.clone()])]);

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2100).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(50));
        assert!(report.dirty_orders.contains(&order_id));

        let s = store.lock().unwrap();
        let payment = s.get_all_payments(&order_id).unwrap().remove(0);
        assert!(payment.voided_at.is_none(), "the payment is canonical again and must count towards the order");
        assert_eq!(payment.block_height, Some(50));
        // Sticky by design: a double-spend attempt was genuinely observed on this
        // order, and that remains true regardless of how the chain settled.
        assert!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().double_spend_detected_at.is_some());
    }

    #[tokio::test]
    async fn every_webhook_payload_carries_a_stable_event_id_and_a_timestamp() {
        // The payload used to be just `{payment_id, status}`, which gives a receiver
        // nothing to dedupe on (a retry of a lost-ack delivery is byte-identical to a
        // genuine second transition to the same status) and nothing to bound a replay
        // with (a captured delivery stays valid forever). Both the id and the
        // timestamp live *inside* the signed body, not only in headers.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.push_block("h2", vec![fixture_tx()]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let first_payload: serde_json::Value = {
            let s = store.lock().unwrap();
            let due = s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap();
            assert_eq!(due.len(), 1);
            serde_json::from_str(&due[0].payload_json).unwrap()
        };
        assert_eq!(first_payload["payment_id"], serde_json::json!(order_id));
        assert_eq!(first_payload["status"], serde_json::json!("confirming"));
        assert_eq!(first_payload["event"], serde_json::json!("order.confirming"));
        assert!(
            first_payload["event_id"].as_str().is_some_and(|id| id.starts_with("evt_")),
            "every event needs an id a receiver can dedupe on: {first_payload}"
        );
        assert!(first_payload["created_at"].as_i64().is_some(), "and a timestamp to bound replays with");

        // A retry of the same delivery re-sends the identical, identically-signed
        // body - the id must identify the *event*, not the attempt.
        {
            let s = store.lock().unwrap();
            let due = s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap();
            s.schedule_webhook_retry(due[0].delivery_id, 0, Some(500), Some("boom"), crate::now_unix()).unwrap();
            let retried = s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap();
            let retried_payload: serde_json::Value = serde_json::from_str(&retried[0].payload_json).unwrap();
            assert_eq!(retried_payload["event_id"], first_payload["event_id"]);
        }

        // A genuinely different transition gets a genuinely different id.
        for i in 3..=11 {
            daemon.push_block(&format!("h{i}"), vec![]);
        }
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();
        let s = store.lock().unwrap();
        let paid = s
            .due_webhook_deliveries(crate::now_unix() + 1, 10)
            .unwrap()
            .into_iter()
            .find(|d| d.event_type == "order.overpaid")
            .expect("the settled transition must have been enqueued");
        let settled_payload: serde_json::Value = serde_json::from_str(&paid.payload_json).unwrap();
        assert_ne!(settled_payload["event_id"], first_payload["event_id"]);
    }

    #[tokio::test]
    async fn a_block_whose_hash_cannot_be_read_stops_the_range_instead_of_leaving_a_gap() {
        // Every other failure inside the height loop abandons the range without
        // marking the height scanned; reading the block's *hash* was the one step
        // whose failure was silently ignored, and it is the step that decides whether
        // the height is recorded at all. Skipping it while carrying on to the next
        // height leaves a hole: height H unrecorded, H+1 onwards recorded.
        //
        // A hole is worse than a stopping point, because reorg detection skips
        // heights it has no stored hash for. A later reorg genuinely starting at H is
        // then first noticed at H+1, so the reported reorg point is one block too
        // high - the payments actually orphaned at H are never re-evaluated (they go
        // on counting towards their order at a height that no longer exists) and
        // block H of the replacement chain is never rescanned.
        let (store, key_custody, handle, tenant_id, _order_id) = setup().await;
        store.set_scanned_block("mainnet", 1, "h1").unwrap();
        let store = store.into_shared();

        let inner = FakeDaemonClient::new();
        for i in 1..=5 {
            inner.push_block(&format!("h{i}"), vec![]);
        }
        let daemon = DaemonFailingBlockHashAt { inner, failing_height: AtomicU64::new(3) };

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        {
            let s = store.lock().unwrap();
            assert_eq!(
                s.max_scanned_height("mainnet").unwrap(),
                Some(2),
                "the range must stop at the height whose hash could not be read, not step over it"
            );
            for h in 3..=5 {
                assert!(
                    s.get_scanned_block_hash("mainnet", h).unwrap().is_none(),
                    "block {h} must not be recorded once the range was abandoned at 3"
                );
            }
        }

        // And the next healthy tick re-covers the whole abandoned range, leaving a
        // contiguous window with nothing missing from the middle of it.
        daemon.failing_height.store(NO_FAILING_HEIGHT, Ordering::SeqCst);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(5));
        for h in 1..=5 {
            assert!(s.get_scanned_block_hash("mainnet", h).unwrap().is_some(), "block {h} must be recorded");
        }
    }

    #[tokio::test]
    async fn a_reorg_whose_common_ancestor_hash_cannot_be_read_leaves_the_scanned_window_intact() {
        // The same permanent loss as
        // `a_reorg_back_to_the_oldest_recorded_block_does_not_look_like_a_scanner_that_never_ran`,
        // reached the other way: the rewind's re-anchor step *does* run, but the one
        // RPC it depends on - reading the common ancestor's hash - fails transiently.
        // Treating that as "there is no ancestor" (which an `.ok()` did) still deletes
        // every row, still empties the table, and still makes the next tick read the
        // network as never-scanned and re-seed at the tip. Every replacement block
        // between the reorg point and the tip is skipped forever, taking any payment
        // that exists only in the winning chain with it.
        //
        // Nothing has to be deleted this tick. The stored hashes still describe the
        // losing chain, so leaving them alone means the next tick detects the same
        // reorg and redoes the whole step - the same idempotent retry
        // `a_reconciliation_that_fails_partway_leaves_the_reorg_still_detectable`
        // relies on.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();
        let store = store.into_shared();

        let inner = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = inner.push_block(&format!("filler_{last_height}"), vec![]);
        }
        // The fork replaces 50 and 51; the payment exists only in the new 50.
        inner.reorg_from(50, vec![("new_50", vec![fixture_tx()]), ("new_51", vec![])]);
        // 49 is the common ancestor the rewind must re-anchor to - and the one hash
        // this node will not serve.
        let daemon = DaemonFailingBlockHashAt { inner, failing_height: AtomicU64::new(49) };

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            assert_eq!(
                s.get_scanned_block_hash("mainnet", 50).unwrap().as_deref(),
                Some("hash_50_v1"),
                "with no anchor available, the losing chain's hash must stay put so the reorg stays detectable"
            );
            assert!(
                s.max_scanned_height("mainnet").unwrap().is_some(),
                "the window must never be emptied by a rewind that cannot re-anchor - an empty window reads \
                 as 'never scanned' and re-seeds at the tip"
            );
        }

        // The node recovers; the very next tick completes the rewind it deferred.
        daemon.failing_height.store(NO_FAILING_HEIGHT, Ordering::SeqCst);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(
            store.lock().unwrap().max_scanned_height("mainnet").unwrap(),
            Some(49),
            "the rewind must now land on the common ancestor"
        );

        // ...and the tick after that forward-scans the replacement chain and finds the
        // payment that only ever existed there.
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();
        let s = store.lock().unwrap();
        assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(51));
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1, "the payment that exists only in the replacement chain must still be found");
        assert_eq!(payments[0].block_height, Some(50));
    }

    #[tokio::test]
    async fn a_store_failure_marking_a_block_scanned_does_not_discard_the_ticks_mempool_matches() {
        // Every failure inside the height loop is documented as a `break`, never a
        // `return`, for one specific reason: the mempool matches gathered earlier in
        // the same tick still need their status recompute and their webhooks, and
        // returning here throws both away. Writing the scanned-block row was the one
        // remaining step that still used `?`, so a transient store error there didn't
        // just skip the block - it silently swallowed a real, already-recorded
        // zero-conf payment's `order.unconfirmed` notification too.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.push_block("h2", vec![]);
        daemon.set_mempool(vec![fixture_tx()]); // the payment arrives zero-conf
        store.lock().unwrap().set_scanned_block("mainnet", 1, "h1").unwrap();

        let webhook = store
            .lock()
            .unwrap()
            .create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000)
            .unwrap();

        // Fail only writes to `scanned_blocks`, leaving every other table (and every
        // read) working - a write failure at exactly that one step, not a broken
        // database.
        store
            .lock()
            .unwrap()
            .execute_raw_for_test(
                "CREATE TRIGGER simulated_scanned_block_write_failure BEFORE INSERT ON scanned_blocks
                 BEGIN SELECT RAISE(ABORT, 'simulated store failure'); END;",
            )
            .unwrap();

        let result = run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await;
        assert!(result.is_ok(), "a failure marking a block scanned must abandon the range, not the whole tick");

        {
            let s = store.lock().unwrap();
            assert_eq!(
                s.max_scanned_height("mainnet").unwrap(),
                Some(1),
                "block 2 must stay unscanned so the next tick retries it"
            );
            // The mempool half of the tick must have survived intact: the payment is
            // recorded, the status was recomputed off it, and the transition was
            // announced.
            let payments = s.get_all_payments(&order_id).unwrap();
            assert_eq!(payments.len(), 1);
            assert_eq!(payments[0].block_height, None, "still mempool-only");
            let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
            assert_ne!(
                order.status,
                crate::status::OrderStatus::Pending,
                "the mempool match's status recompute must not have been discarded"
            );
            let due = s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap();
            assert!(
                due.iter().any(|d| d.webhook_id == webhook.id && d.event_type.starts_with("order.")),
                "the mempool match's status-transition webhook must not have been discarded"
            );
        }

        // And the block the tick deliberately left behind is covered once the store
        // is healthy again.
        store
            .lock()
            .unwrap()
            .execute_raw_for_test("DROP TRIGGER simulated_scanned_block_write_failure;")
            .unwrap();
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();
        assert_eq!(store.lock().unwrap().max_scanned_height("mainnet").unwrap(), Some(2));
    }

    #[tokio::test]
    async fn a_reorg_back_to_the_oldest_recorded_block_does_not_look_like_a_scanner_that_never_ran() {
        // `forget_scanned_blocks_at_or_above` walks the high-water mark back to
        // `reorg_point - 1` - but only while a row still exists at or below that
        // height. When the reorg point *is* the oldest block this network has a row
        // for (routine on a recently-started scanner, whose window begins at the tip
        // it bootstrapped from) the delete empties the table outright, and an empty
        // table is precisely what `run_scan_tick` reads as "never scanned this
        // network", which makes it re-seed at the current tip. Every replacement
        // block between the reorg point and the tip is then skipped forever - taking
        // with it any payment that exists only in the chain that won, which is the
        // exact loss dropping those rows was introduced to prevent.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        // A scanner whose entire history is one block: height 50, on the old chain.
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        // The fork replaces 50 and 51, and the payment lives only in the new 50.
        daemon.reorg_from(50, vec![("new_50", vec![fixture_tx()]), ("new_51", vec![])]);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(
            store.lock().unwrap().max_scanned_height("mainnet").unwrap(),
            Some(49),
            "the rewind must leave the high-water mark at the common ancestor, not at nothing at all"
        );

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(51));
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1, "the payment that exists only in the replacement chain was found");
        assert_eq!(payments[0].block_height, Some(50));
    }

    #[tokio::test]
    async fn a_tick_that_detects_a_reorg_never_announces_paid_from_the_chain_it_is_about_to_discard() {
        // Ordering, not logic: reconciliation and the per-tick recompute sweep both
        // ran, but the sweep ran first, so on the one tick where a reorg is detected
        // every non-terminal order was evaluated against heights reconciliation was
        // about to invalidate. An order whose payment had just been orphaned could
        // therefore cross its confirmation threshold and fire `order.paid` seconds
        // before the same tick voided that payment and fired the retraction - and a
        // merchant who acted on `order.paid` has already shipped.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await; // confirmations_required = 10
        store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let tx = fixture_tx();
        let key_images = key_images_of(&tx);

        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();
        let (_, status) = store.recompute_order_status(&order_id, 50, 1600).unwrap();
        assert_eq!(status, crate::status::OrderStatus::Confirming, "one confirmation, ten required");
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        // The replacement chain runs to height 60 and does not contain the
        // transaction at all - so counted against the *stale* height 50 the payment
        // now looks eleven confirmations deep, comfortably past the threshold, while
        // in reality it has been double-spent.
        let replacement: Vec<(&str, Vec<Transaction>)> =
            ["v2_50", "v2_51", "v2_52", "v2_53", "v2_54", "v2_55", "v2_56", "v2_57", "v2_58", "v2_59", "v2_60"]
                .into_iter()
                .map(|h| (h, vec![]))
                .collect();
        daemon.reorg_from(50, replacement);
        for ki in &key_images {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.amount_received_piconero, 0, "the voided payment must not count towards the order");
        assert!(order.double_spend_detected_at.is_some());

        let events: Vec<String> =
            s.due_webhook_deliveries(crate::now_unix() + 1, 20).unwrap().into_iter().map(|d| d.event_type).collect();
        assert!(
            !events.iter().any(|e| e == "order.paid" || e == "order.overpaid"),
            "no settlement may ever be announced from payment data the same tick is in the middle of retracting, got: {events:?}"
        );
    }

    #[tokio::test]
    async fn a_payment_a_reorg_dropped_to_the_mempool_can_still_be_voided_when_later_proven_double_spent() {
        // Reconciliation itself writes `block_height = NULL` when the daemon reports
        // a payment's transaction back in the pool - and the query that finds
        // payments to re-examine filtered on `block_height >= ?`, which SQL's
        // three-valued logic makes false for NULL. So the very act of handling one
        // reorg made the payment invisible to every reconciliation that followed: it
        // could be proven double-spent a hundred times over and would never be
        // voided, propping up the order's received total permanently.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let key_images = key_images_of(&tx);

        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        store.set_scanned_block("mainnet", 50, "hash_50_v1").unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        let mut last_height = 0;
        while last_height < 49 {
            last_height = daemon.push_block(&format!("filler_{last_height}"), vec![]);
        }
        // First reorg: the transaction falls out of its block and back into the pool.
        daemon.set_mempool(vec![tx.clone()]);
        daemon.reorg_from(50, vec![("hash_50_v2", vec![])]);

        check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(
            store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].block_height,
            None,
            "reconciliation itself is what puts the row into the state that used to hide it"
        );

        // Later, the attacker's replacement confirms: the pooled transaction is
        // dropped for good and its inputs are provably consumed elsewhere.
        daemon.drop_from_mempool(&tx);
        for ki in &key_images {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        store.lock().unwrap().set_scanned_block("mainnet", 50, "hash_50_v2").unwrap();
        daemon.reorg_from(50, vec![("hash_50_v3", vec![])]);

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2100).await.unwrap();
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);

        let s = store.lock().unwrap();
        assert!(s.get_all_payments(&order_id).unwrap()[0].voided_at.is_some());
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.amount_received_piconero, 0);
        assert!(order.double_spend_detected_at.is_some());
    }

    #[tokio::test]
    async fn a_status_change_whose_webhook_cannot_be_enqueued_is_rolled_back_rather_than_lost() {
        // The status write and the enqueue announcing it were two separate
        // autocommits, and `recompute_order_status` decides "did anything change" by
        // comparing against the *stored* status - so the moment the new status lands,
        // the transition stops being detectable. A failure in the window between them
        // therefore didn't delay the merchant's `order.confirming`, it destroyed it:
        // no later tick could ever re-derive that a transition had happened.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        // Fail only enqueues, leaving every other write working, so this reproduces
        // the specific window rather than a broken database.
        store
            .execute_raw_for_test(
                "CREATE TRIGGER simulated_enqueue_failure BEFORE INSERT ON webhook_deliveries
                 BEGIN SELECT RAISE(ABORT, 'simulated store failure'); END;",
            )
            .unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.push_block("h2", vec![fixture_tx()]);

        let result = run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await;
        assert!(result.is_err(), "the enqueue failure must surface, not be swallowed");
        assert_eq!(
            store.lock().unwrap().get_order(&tenant_id, &order_id).unwrap().unwrap().status,
            crate::status::OrderStatus::Pending,
            "the status must not have advanced past a transition nothing will ever announce"
        );

        // Once the store is healthy again, the next tick performs both halves.
        store.lock().unwrap().execute_raw_for_test("DROP TRIGGER simulated_enqueue_failure;").unwrap();
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert_eq!(
            s.get_order(&tenant_id, &order_id).unwrap().unwrap().status,
            crate::status::OrderStatus::Confirming
        );
        let due = s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event_type, "order.confirming");
    }

    // ---------------------------------------------------------------------
    // Scenario-coverage block: chain, network and adversarial conditions.
    // See the checklist at the top of this module for what maps to what.
    // ---------------------------------------------------------------------

    /// A second, distinct transaction paying the *same* subaddress with the *same*
    /// outputs and the *same* key images as `fixture_tx()`. Only `unlock_time`
    /// differs, which changes the transaction hash (it is part of the prefix, and
    /// the prefix is hashed) without touching the transaction public key, the
    /// output keys, or the amount commitments that scanning and amount recovery
    /// depend on.
    ///
    /// This is what makes multi-transaction and double-spend scenarios testable
    /// against real crypto with a single fixture: two variants are two genuinely
    /// different txids that both match the fixture view pair, and - because they
    /// share their inputs - they are also a realistic *conflicting pair*, which is
    /// exactly the shape of a Monero double-spend (same key images, different
    /// transaction).
    fn fixture_tx_variant(unlock_time: u64) -> Transaction {
        let mut tx = fixture_tx();
        tx.prefix.unlock_time = monero::VarInt(unlock_time);
        tx
    }

    /// Pushes `1..=height` onto a fresh fake chain, each block empty and hashed
    /// `{prefix}_{h}`, and records the same hashes into `store` for `from..=height`
    /// - i.e. a scanner that has already worked its way up this chain.
    fn chain_scanned_to(store: &Store, height: u64, recorded_from: u64, prefix: &str) -> FakeDaemonClient {
        let daemon = FakeDaemonClient::new();
        for h in 1..=height {
            daemon.push_block(&format!("{prefix}_{h}"), vec![]);
        }
        for h in recorded_from..=height {
            store.set_scanned_block("mainnet", h, &format!("{prefix}_{h}")).unwrap();
        }
        daemon
    }

    /// Replaces `fork..=tip` with a chain whose hashes are prefixed `new_`, keeping
    /// the (hash, txs) plumbing of `reorg_from`'s `&str` API out of every caller.
    fn reorg_to_new_chain(daemon: &FakeDaemonClient, fork: u64, tip: u64, tx_at: Option<(u64, Transaction)>) {
        reorg_to_chain(daemon, fork, tip, "new", tx_at)
    }

    /// `reorg_to_new_chain` with a caller-chosen hash prefix, for tests that switch
    /// between more than two chains and need each one's hashes to be distinct from
    /// every other's.
    fn reorg_to_chain(
        daemon: &FakeDaemonClient,
        fork: u64,
        tip: u64,
        prefix: &str,
        tx_at: Option<(u64, Transaction)>,
    ) {
        let hashes: Vec<String> = (fork..=tip).map(|h| format!("{prefix}_{h}")).collect();
        let blocks: Vec<(&str, Vec<Transaction>)> = hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                let height = fork + i as u64;
                let txs = match &tx_at {
                    Some((h, tx)) if *h == height => vec![tx.clone()],
                    _ => vec![],
                };
                (hash.as_str(), txs)
            })
            .collect();
        daemon.reorg_from(fork, blocks);
    }

    /// One reorg of `tip - fork + 1` blocks against a scanner that has recorded the
    /// previous 30 blocks, returning the height reconciliation reports it at.
    async fn reorg_point_for(fork: u64, tip: u64, reorg_check_depth: u64) -> Option<u64> {
        let store = Store::open_in_memory().unwrap();
        let daemon = chain_scanned_to(&store, tip, tip - 30, "old");
        reorg_to_new_chain(&daemon, fork, tip, None);
        let store = store.into_shared();
        check_for_reorg_and_reconcile(&store, &daemon, "mainnet", reorg_check_depth, 2000)
            .await
            .unwrap()
            .reorg_detected_at
    }

    #[tokio::test]
    async fn a_reorg_is_detected_at_its_true_fork_point_at_every_depth_the_window_covers() {
        // Reorg depth is not a parameter anything in the detection loop branches on,
        // but "not branching on it" is precisely the kind of claim that quietly stops
        // being true, and the real network has now produced reorgs (18 blocks, on
        // mainnet, in September 2025) deeper than this system's default
        // `confirmations_required`. Walking every depth the window covers - one block
        // through the window edge itself - is cheap and forecloses an off-by-one at
        // either end.
        //
        // With `reorg_check_depth = 20` the window is `tip-20..=tip`, i.e. 21
        // heights, so a 21-block reorg is the deepest one whose true fork point is
        // still inside it.
        let tip = 100;
        for depth in 1..=21u64 {
            let fork = tip - depth + 1;
            assert_eq!(
                reorg_point_for(fork, tip, 20).await,
                Some(fork),
                "a {depth}-block reorg (fork at {fork}) must be reported at its own fork point"
            );
        }
    }

    #[tokio::test]
    async fn a_reorg_deeper_than_the_window_is_reported_at_the_window_edge_and_leaves_older_payments_alone() {
        // The documented limitation (§DESIGN.md 3: "defending against reorgs deeper
        // than a configured window" is a non-goal), pinned down as executable
        // behavior rather than left as prose. What actually happens is worth being
        // precise about, because it is *not* "the reorg is missed": every stored hash
        // in the window mismatches, so the first one checked - the window edge - is
        // reported as the reorg point. That is a real detection, but at a height
        // above the true fork, so payments below the window keep counting towards
        // their orders at heights that no longer exist, and the replacement chain's
        // blocks below the window are never rescanned.
        //
        // The operational consequence, spelled out for whoever tunes this: the only
        // defense against a reorg deeper than `reorg_check_depth` is configuring
        // `reorg_check_depth` deeper than any reorg you intend to survive. The
        // September 2025 mainnet reorg was 18 blocks; the default is 20.
        let tip = 100;
        assert_eq!(
            reorg_point_for(79, tip, 20).await,
            Some(80),
            "a fork one block below the window is reported at the window edge, not at 79"
        );

        // And the payment orphaned below the window is left untouched by that pass.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let daemon = chain_scanned_to(&store, tip, tip - 30, "old");
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &fixture_tx(), 0..3, 1500, Some(79))
            .await
            .unwrap();
        reorg_to_new_chain(&daemon, 79, tip, None);
        let store = store.into_shared();

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(80));
        let payments = store.lock().unwrap().get_all_payments(&order_id).unwrap();
        assert_eq!(
            payments[0].block_height,
            Some(79),
            "a payment below the window is not re-evaluated - this is the documented cost of the window, \
             and the reason `reorg_check_depth` must exceed the deepest reorg a deployment wants to survive"
        );
    }

    #[tokio::test]
    async fn a_settled_order_is_walked_back_when_a_reorg_deeper_than_confirmations_required_orphans_its_payment() {
        // The September 2025 shape, at this system's defaults: an 18-block reorg
        // against `confirmations_required = 10` reverts blocks the merchant was
        // already told were final. Nothing in the reorg path branches on
        // `confirmations_required` (10 and 11 blocks deep take exactly the same code
        // path), so what needs proving is the end-to-end consequence: an order that
        // reached a terminal, shipped-against status is walked back, and the merchant
        // is told, rather than the retraction being visible only to a poller.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await; // confirmations_required = 10
        store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let tx = fixture_tx();
        let daemon = chain_scanned_to(&store, 100, 70, "old");
        // Payment 18 blocks deep - comfortably "final" at ten confirmations.
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(83))
            .await
            .unwrap();
        let (_, status) = store.recompute_order_status(&order_id, 100, 1600).unwrap();
        assert_eq!(status, crate::status::OrderStatus::Overpaid, "18 confirmations deep before the reorg");

        // An 18-block reorg that does not carry the transaction, and whose inputs are
        // proven consumed by something else.
        for ki in &key_images_of(&tx) {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        reorg_to_new_chain(&daemon, 83, 100, None);
        let store = store.into_shared();

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(83));
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);

        let s = store.lock().unwrap();
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.amount_received_piconero, 0, "the orphaned payment must stop counting");
        assert_eq!(order.status, crate::status::OrderStatus::Pending);
        assert!(order.double_spend_detected_at.is_some());
        let events: Vec<String> =
            s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap().into_iter().map(|d| d.event_type).collect();
        assert!(
            events.contains(&"order.pending".to_string()),
            "a merchant told `overpaid` must be told when that stops being true: {events:?}"
        );
    }

    #[tokio::test]
    async fn a_reorg_whose_fork_is_below_every_recorded_block_rewinds_to_that_oldest_block() {
        // The boundary the round-2 fix
        // (`a_reorg_back_to_the_oldest_recorded_block_does_not_look_like_a_scanner_that_never_ran`)
        // sits next to, probed explicitly: there, the fork *is* the oldest recorded
        // block; here it is strictly below it, so the common ancestor falls outside
        // the recorded window entirely. Detection still fires at the oldest recorded
        // height (nothing lower has a hash to compare), the rewind re-anchors one
        // block below it, and the window is never emptied - the state that would
        // otherwise read as "this network has never been scanned" and re-seed at the
        // tip, skipping every replacement block in between.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        // A scanner whose entire history is heights 50..=52.
        let daemon = FakeDaemonClient::new();
        for h in 1..=52 {
            daemon.push_block(&format!("old_{h}"), vec![]);
        }
        for h in 50..=52 {
            store.set_scanned_block("mainnet", h, &format!("old_{h}")).unwrap();
        }
        // The fork is at 45 - five blocks below anything this scanner recorded - and
        // the payment exists only in the replacement chain.
        reorg_to_new_chain(&daemon, 45, 52, Some((51, fixture_tx())));
        let store = store.into_shared();

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(
            store.lock().unwrap().max_scanned_height("mainnet").unwrap(),
            Some(49),
            "the rewind must land just below the oldest recorded block, never on an empty window"
        );

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();
        let s = store.lock().unwrap();
        assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(52));
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1, "the payment that exists only in the replacement chain must be found");
        assert_eq!(payments[0].block_height, Some(51));
    }

    /// A transaction that *conflicts* with `fixture_tx()` - it spends the same
    /// inputs, so it carries the same key images - but pays somebody else: its
    /// outputs are stripped, so it matches no wallet in this test suite. This is the
    /// attacker's side of a Monero double-spend, which is always "same key images,
    /// different transaction" (there is no replace-by-fee to express it any other
    /// way).
    fn conflicting_tx(seed: u64) -> Transaction {
        let mut tx = fixture_tx_variant(seed);
        tx.prefix.outputs.clear();
        tx
    }

    /// A second payment to the same order that is *not* in conflict with the
    /// fixture: same outputs (so it still matches, and still pays the order), but
    /// different inputs, hence different key images. Two transactions paying one
    /// order have to look like this - two transactions sharing key images could
    /// never both be valid.
    fn independent_payment_tx(seed: u8) -> Transaction {
        let mut tx = fixture_tx_variant(0x1000 + seed as u64);
        for input in tx.prefix.inputs.iter_mut() {
            if let monero::blockdata::transaction::TxIn::ToKey { k_image, .. } = input {
                let mut bytes = k_image.image.to_bytes();
                bytes[0] ^= seed;
                k_image.image = monero::cryptonote::hash::Hash(bytes);
            }
        }
        tx
    }

    #[tokio::test]
    async fn the_transaction_variants_these_tests_are_built_from_are_genuinely_distinct() {
        // Every multi-transaction and double-spend scenario below rests on these
        // three shapes actually being what they claim. If a future `monero-rs`
        // changed what the transaction hash covers, or which fields scanning reads,
        // the scenarios would still "pass" while quietly testing one transaction
        // against itself.
        let (_store, key_custody, handle, _tenant_id, _order_id) = setup().await;
        let base = fixture_tx();
        let variant = fixture_tx_variant(42);
        let conflicting = conflicting_tx(42);
        let independent = independent_payment_tx(3);

        assert_ne!(tx_id_hex(&base), tx_id_hex(&variant), "a different unlock_time must be a different txid");
        assert_ne!(tx_id_hex(&base), tx_id_hex(&conflicting));
        assert_ne!(tx_id_hex(&base), tx_id_hex(&independent));

        assert_eq!(key_images_of(&base), key_images_of(&variant), "a variant spends the same inputs");
        assert_eq!(key_images_of(&base), key_images_of(&conflicting), "a conflicting tx is one sharing key images");
        assert_ne!(key_images_of(&base), key_images_of(&independent), "an independent payment spends other inputs");

        for (label, tx, expected) in [
            ("the fixture itself", &base, 1),
            ("changing unlock_time must not break output matching", &variant, 1),
            ("changing key images must not break output matching", &independent, 1),
            ("the attacker's transaction pays somebody else", &conflicting, 0),
        ] {
            let matches = scan_transaction(&key_custody, handle, tx, 0..3).await.unwrap().matches.len();
            assert_eq!(matches, expected, "{label}");
        }
    }

    #[tokio::test]
    async fn rapidly_alternating_chain_tips_never_lose_or_double_count_a_payment() {
        // The selfish-mining shape, from this scanner's point of view. A pool that
        // withholds blocks and publishes them in bursts (which is what Qubic was
        // doing against Monero through August-September 2025) does not present as one
        // clean reorg: it presents as the tip repeatedly changing its mind, with the
        // same transaction moving between blocks - or out of the chain and back -
        // several times in a row.
        //
        // The property that has to survive that is bookkeeping, not detection: one
        // payment row, counted once, at whatever height the chain most recently
        // agreed on, with no double-spend ever flagged (nothing was ever double-spent
        // here - the transaction stayed valid throughout, only its block kept
        // changing).
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let daemon = chain_scanned_to(&store, 51, 40, "c0");
        // The payment starts life mined at height 50 on the chain the scanner has
        // already recorded.
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        let store = store.into_shared();

        // Three rounds of the tip trading places: the withheld chain wins and the
        // transaction is nowhere, then the honest chain wins it back at a different
        // height, and so on. Two ticks per round because a rewind and the forward
        // rescan it enables are deliberately separate ticks (see
        // `after_a_reorg_the_replacement_blocks_are_forward_scanned_again`).
        for round in 0..3u64 {
            let withheld = format!("w{round}");
            let public = format!("p{round}");
            reorg_to_chain(&daemon, 50, 52 + round, &withheld, None); // the tx vanishes entirely
            for _ in 0..2 {
                run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20)
                    .await
                    .unwrap();
            }
            reorg_to_chain(&daemon, 50, 53 + round, &public, Some((51 + round, tx.clone()))); // ...and comes back, deeper each time
            for _ in 0..2 {
                run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20)
                    .await
                    .unwrap();
            }

            let s = store.lock().unwrap();
            let payments = s.get_all_payments(&order_id).unwrap();
            assert_eq!(payments.len(), 1, "round {round}: one transaction is one payment row, however often it moves");
            assert!(payments[0].voided_at.is_none(), "round {round}: a remined transaction is not a double-spend");
            assert_eq!(
                payments[0].block_height,
                Some((51 + round) as i64),
                "round {round}: at the height the chain last agreed on"
            );
            let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
            assert!(order.double_spend_detected_at.is_none(), "round {round}: nothing here was ever double-spent");
            assert_eq!(order.amount_received_piconero, payments[0].amount_piconero, "round {round}: counted exactly once");
        }
    }

    #[tokio::test]
    async fn a_double_spend_mined_in_a_different_block_than_the_original_voids_it_once() {
        // The variant the existing double-spend tests don't cover: the conflicting
        // transaction isn't just "somewhere in the chain", it is mined at a
        // *different height* than the original occupied, and the replacement chain is
        // longer than the one it replaced. Nothing about the reasoning changes -
        // `locate_transaction` says the original is nowhere, its key images say
        // something else spent them - but "the heights line up" is an assumption
        // worth not having.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let attacker = conflicting_tx(9);
        let daemon = chain_scanned_to(&store, 51, 40, "old");
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        for ki in &key_images_of(&tx) {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        // The replacement chain runs two blocks longer and carries the attacker's
        // transaction at 53, nowhere near where the original sat.
        reorg_to_new_chain(&daemon, 50, 53, Some((53, attacker)));
        let store = store.into_shared();

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);

        let s = store.lock().unwrap();
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1, "the attacker's transaction pays nobody here - it must not become a payment row");
        assert!(payments[0].voided_at.is_some());
        assert_eq!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().amount_received_piconero, 0);
    }

    #[tokio::test]
    async fn voiding_one_of_an_orders_two_payments_leaves_the_other_counting() {
        // §TESTING.md 3's "exact two-transaction scenario from design review", at the
        // scanner level rather than the status-function level: an order paid by two
        // independent transactions, one of which is double-spent. The surviving
        // payment must keep counting, the order's total must fall by exactly the
        // voided amount, and `double_spend_detected_at` must be stamped even though
        // the two facts are on different axes.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let first = fixture_tx();
        let second = independent_payment_tx(5);
        let daemon = chain_scanned_to(&store, 51, 40, "old");
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &first, 0..3, 1500, Some(50))
            .await
            .unwrap();
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &second, 0..3, 1500, Some(50))
            .await
            .unwrap();
        let total_before = store.get_order(&tenant_id, &order_id).unwrap().unwrap();
        let _ = total_before;

        // Only the first transaction is double-spent; the second is remined at 51.
        for ki in &key_images_of(&first) {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        reorg_to_new_chain(&daemon, 50, 51, Some((51, second.clone())));
        let store = store.into_shared();

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);

        let s = store.lock().unwrap();
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 2);
        let (voided, kept): (Vec<_>, Vec<_>) = payments.iter().partition(|p| p.voided_at.is_some());
        assert_eq!(voided.len(), 1, "exactly the double-spent transaction is written off");
        assert_eq!(voided[0].txid, tx_id_hex(&first));
        assert_eq!(kept[0].txid, tx_id_hex(&second));
        assert_eq!(kept[0].block_height, Some(51), "the survivor follows the chain to its new height");
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.amount_received_piconero, kept[0].amount_piconero, "only the survivor's amount counts");
        assert!(order.double_spend_detected_at.is_some(), "the incident is recorded regardless of the resulting status");
    }

    #[tokio::test]
    async fn a_third_transaction_claiming_the_same_inputs_keeps_the_original_voided() {
        // The un-voiding path, pushed one step further than
        // `a_voided_payment_is_restored_when_its_transaction_returns_to_the_chain`
        // takes it. There, the transaction that beat the original was itself reorged
        // out and the original came back. Here it is reorged out and a *third*
        // transaction - a different txid, still spending the same inputs - takes its
        // place. The original is still nowhere, its inputs are still provably
        // consumed by something else, and it must therefore stay voided: un-voiding
        // is conditioned on the original actually returning to the chain, not on the
        // particular replacement that displaced it going away.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let key_images = key_images_of(&tx);
        let daemon = chain_scanned_to(&store, 50, 40, "old");
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        for ki in &key_images {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        reorg_to_chain(&daemon, 50, 50, "b", Some((50, conflicting_tx(1)))); // the second transaction wins
        let store = store.into_shared();

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);
        assert!(store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].voided_at.is_some());

        // The second transaction's block loses in turn, but a third one - not the
        // original - takes the inputs.
        store.lock().unwrap().set_scanned_block("mainnet", 50, "b_50").unwrap();
        reorg_to_chain(&daemon, 50, 50, "c", Some((50, conflicting_tx(2))));

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2100).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(50));

        let s = store.lock().unwrap();
        let payment = s.get_all_payments(&order_id).unwrap().remove(0);
        assert!(
            payment.voided_at.is_some(),
            "the original never returned to the chain - its replacement being replaced changes nothing"
        );
        assert_eq!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().amount_received_piconero, 0);
    }

    #[tokio::test]
    async fn a_zero_conf_payment_double_spent_out_of_the_mempool_is_voided_with_no_reorg_involved() {
        // The gap this sweep was added to close, and the most consequential one in
        // this file: the textbook attack on a merchant watching the mempool involves
        // no reorg at all. Broadcast transaction A so the merchant's node sees it
        // (with a zero-conf ceiling configured, the order reads `paid` immediately -
        // that is what the setting is for), then get transaction B, spending the same
        // inputs, mined instead. A is never mined, so no block hash the scanner
        // recorded ever changes, so reorg reconciliation - the only thing that ever
        // re-examined an existing payment - never runs. The payment sat at
        // `block_height IS NULL` forever, counting in full towards an order that was
        // never paid, and no `order.double_spend_detected` webhook ever fired.
        let (store, key_custody, handle, tenant_id, order_id) = setup_with_zero_conf_ceiling(Some(u64::MAX)).await;
        store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let tx = fixture_tx();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.set_mempool(vec![tx.clone()]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
            assert_eq!(order.status, crate::status::OrderStatus::Overpaid, "settled off the mempool sighting alone");
        }

        // The attack lands: A leaves the pool without ever being mined, and a
        // different transaction spending its inputs is confirmed.
        daemon.drop_from_mempool(&tx);
        daemon.push_block("h2", vec![conflicting_tx(11)]);
        for ki in &key_images_of(&tx) {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1);
        assert!(payments[0].voided_at.is_some(), "a proven double-spend must be written off with or without a reorg");
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.amount_received_piconero, 0);
        assert_eq!(order.status, crate::status::OrderStatus::Pending);
        assert!(order.double_spend_detected_at.is_some());
        let events: Vec<String> =
            s.due_webhook_deliveries(crate::now_unix() + 1, 10).unwrap().into_iter().map(|d| d.event_type).collect();
        assert!(
            events.contains(&"order.double_spend_detected".to_string()),
            "the merchant who shipped against this needs telling: {events:?}"
        );
        assert!(events.contains(&"order.pending".to_string()), "and the status retraction is its own event: {events:?}");
    }

    #[tokio::test]
    async fn a_mempool_payment_that_merely_disappears_is_never_voided_on_that_evidence_alone() {
        // The honest half of the same story, and the reason the sweep cannot simply
        // treat "gone from the pool" as "gone". Monero has no replace-by-fee, but a
        // transaction can still leave a pool without being mined - it can expire out
        // after `CRYPTONOTE_MEMPOOL_TX_LIVETIME` (three days), be dropped by a node
        // under pressure, or never have propagated past the node that first saw it.
        // The customer's money may be perfectly fine and the transaction may be
        // remined or rebroadcast at any point, so absence proves nothing and must
        // never void: the same evidence rule reorg reconciliation follows.
        let (store, key_custody, handle, tenant_id, order_id) = setup_with_zero_conf_ceiling(Some(u64::MAX)).await;
        let tx = fixture_tx();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.set_mempool(vec![tx.clone()]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        daemon.drop_from_mempool(&tx); // vanished, with nothing proven about its inputs
        daemon.push_block("h2", vec![]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        {
            let s = store.lock().unwrap();
            let payments = s.get_all_payments(&order_id).unwrap();
            assert!(payments[0].voided_at.is_none(), "an evicted or still-propagating transaction is not a double-spend");
            assert_eq!(payments[0].block_height, None, "and it is left exactly as it was, re-checkable next tick");
            assert!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().double_spend_detected_at.is_none());
        }

        // And when it does come back and get mined, it is picked up as normal.
        daemon.push_block("h3", vec![tx.clone()]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        let s = store.lock().unwrap();
        assert_eq!(s.get_all_payments(&order_id).unwrap()[0].block_height, Some(3));
    }

    #[tokio::test]
    async fn the_vanished_payment_sweep_costs_nothing_while_a_transaction_is_where_it_should_be() {
        // The sweep runs on every tick of every network, so "cheap by construction"
        // has to be a property, not an aspiration: a payment still sitting in the
        // pool is answered by the snapshot the tick already fetched, and one mined
        // this tick has had its height written by the block scan before the sweep
        // looks. Neither costs an RPC. Only a genuinely vanished transaction does.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let store = store.into_shared();

        let inner = FakeDaemonClient::new();
        inner.push_block("h1", vec![]);
        inner.set_mempool(vec![tx.clone()]);
        let daemon = DaemonFailingFrom::counting(inner, DaemonCall::Locate);

        for _ in 0..3 {
            run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        }
        assert_eq!(daemon.call_count(), 0, "a transaction still in the pool must never be looked up");

        // Mined, and out of the pool in the same tick - the ordinary lifecycle.
        daemon.inner.drop_from_mempool(&tx);
        daemon.inner.push_block("h2", vec![tx.clone()]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].block_height, Some(2));
        assert_eq!(
            daemon.call_count(),
            0,
            "the block scan anchors the payment before the sweep runs, so the ordinary path stays free"
        );

        // And it stays free once the payment is confirmed, tick after tick.
        for _ in 0..3 {
            run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        }
        assert_eq!(daemon.call_count(), 0);
    }

    #[tokio::test]
    async fn a_failed_mempool_poll_skips_the_vanished_payment_sweep_rather_than_assuming_an_empty_pool() {
        // The sweep's one dangerous input is the mempool snapshot: an empty set means
        // "every unconfirmed payment has vanished". A *failed* poll must therefore
        // skip it entirely rather than pass the empty set it has - not for
        // correctness of the void decision (the `locate_transaction` that follows
        // would still answer `InPool` and conclude nothing), but because it would
        // otherwise burn one RPC per pending payment, on every tick, for exactly as
        // long as the node is having trouble.
        let (store, key_custody, handle, tenant_id, _order_id) = setup().await;
        let store = store.into_shared();

        let tx = fixture_tx();
        let fake = FakeDaemonClient::new();
        fake.push_block("h1", vec![]);
        fake.set_mempool(vec![tx.clone()]);
        // First tick polls the pool successfully and records the payment; from the
        // second call onwards the poll fails. The outer wrapper counts the lookups
        // the sweep would make.
        let daemon =
            DaemonFailingFrom::counting(DaemonFailingFrom::failing_from(fake, DaemonCall::Mempool, 1), DaemonCall::Locate);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(store.lock().unwrap().get_all_payments(&_order_id).unwrap().len(), 1);

        let result = run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await;
        assert!(result.is_ok(), "a failed mempool poll must not fail the tick - the rest of it still has work to do");
        assert_eq!(daemon.call_count(), 0, "with no usable snapshot, the sweep must not run at all");

        // The node recovers, and the transaction really is gone from the pool this
        // time - now the sweep does run, which is what makes the assertion above a
        // statement about the failed poll rather than about there being no work.
        daemon.inner.stop_failing();
        daemon.inner.inner.drop_from_mempool(&tx);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(daemon.call_count(), 1, "one lookup for the one payment that has genuinely vanished");
    }

    #[tokio::test]
    async fn a_node_failing_partway_through_the_block_range_resumes_from_that_exact_block() {
        // A tick is not atomic - it is a sequence of independent RPCs - so "the node
        // went away mid-tick" has as many shapes as there are calls in it. This is
        // the shape with the sharpest consequence: the range loop has already scanned
        // and recorded one block when the *next* block's transactions fail to arrive.
        // The high-water mark must stop exactly there, not step over the block it
        // never read, and the next healthy tick must pick it up with no payment lost
        // and none recorded twice.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        store.set_scanned_block("mainnet", 1, "h1").unwrap();
        let store = store.into_shared();

        let fake = FakeDaemonClient::new();
        fake.push_block("h1", vec![]);
        fake.push_block("h2", vec![]);
        fake.push_block("h3", vec![fixture_tx()]); // the payment is in the block that fails
        fake.push_block("h4", vec![]);
        let daemon = DaemonFailingFrom::failing_from(fake, DaemonCall::BlockTransactions, 1);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(2), "the range stops at the block it could not read");
            assert!(s.get_all_payments(&order_id).unwrap().is_empty());
        }

        daemon.stop_failing();
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id, handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(4));
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1, "exactly one payment - not lost by the failure, not duplicated by the retry");
        assert_eq!(payments[0].block_height, Some(3));
    }

    #[tokio::test]
    async fn a_request_that_times_out_rather_than_failing_fast_is_still_just_a_failed_tick() {
        // At this boundary a timeout and a refused connection are the same event -
        // `RpcDaemonClient` gives every request a 15-second client timeout and
        // surfaces whatever comes back as a `DaemonError` either way - but "the tick
        // that eventually errors leaves the same state as the tick that errors
        // immediately" is exactly the sort of thing that is true by construction
        // right up until some future retry or partial-progress logic makes it not.
        // The failure here resolves late (after an actual `.await` that yields)
        // rather than synchronously.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let store = store.into_shared();

        let fake = FakeDaemonClient::new();
        fake.push_block("h1", vec![]);
        fake.push_block("h2", vec![fixture_tx()]);
        let daemon = DaemonFailingFrom::timing_out_from(fake, DaemonCall::Height, 0, 20);

        let result = run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await;
        assert!(result.is_err(), "a tick that cannot learn the chain height has nothing to say about any order");
        {
            let s = store.lock().unwrap();
            assert_eq!(s.max_scanned_height("mainnet").unwrap(), None, "nothing may be recorded as scanned");
            assert_eq!(
                s.get_order(&tenant_id, &order_id).unwrap().unwrap().status,
                crate::status::OrderStatus::Pending,
                "and no order may have advanced on evidence the tick never got"
            );
        }

        daemon.stop_failing();
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        let s = store.lock().unwrap();
        assert_eq!(s.get_all_payments(&order_id).unwrap().len(), 1, "the next tick recovers the payment exactly once");
        assert_eq!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().status, crate::status::OrderStatus::Confirming);
    }

    #[tokio::test]
    async fn a_key_image_lookup_failing_mid_reconciliation_leaves_the_reorg_detectable() {
        // The sibling of `a_reconciliation_that_fails_partway_leaves_the_reorg_still_detectable`,
        // one RPC further in: the divergence is found, the vanished transaction is
        // located (nowhere), and the node dies on the one call that would decide
        // whether that means "double-spent" or "still propagating". The stored hashes
        // must still describe the losing chain afterwards, or nothing will ever
        // re-derive that a reorg happened and the payment stays stranded.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let fake = chain_scanned_to(&store, 50, 40, "old");
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(50))
            .await
            .unwrap();
        for ki in &key_images_of(&tx) {
            fake.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        reorg_to_new_chain(&fake, 50, 51, None);
        let store = store.into_shared();
        let daemon = DaemonFailingFrom::failing_from(fake, DaemonCall::KeyImageSpent, 0);

        assert!(
            check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.is_err(),
            "the node failure must surface rather than be read as 'no proof of a double-spend'"
        );
        {
            let s = store.lock().unwrap();
            assert_eq!(s.get_scanned_block_hash("mainnet", 50).unwrap().as_deref(), Some("old_50"));
            assert!(s.get_all_payments(&order_id).unwrap()[0].voided_at.is_none(), "nothing may be voided on no evidence");
        }

        daemon.stop_failing();
        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2100).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(50));
        assert_eq!(report.double_spent_orders, vec![order_id.clone()]);
        assert!(store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].voided_at.is_some());
    }

    #[tokio::test]
    async fn swapping_to_a_daemon_serving_a_different_chain_reconciles_exactly_like_a_reorg() {
        // The concrete answer to "do we need to record where we synced up to *per
        // daemon*, so it can be redone if a daemon turns out to be dishonest?".
        //
        // This system configures exactly one daemon per network (`main.rs` builds a
        // `HashMap<Network, Arc<dyn MoneroDaemonClient>>`), so there is no pool of
        // daemon identities to key sync state by. What there *is* is a record of
        // which `(height, hash)` pairs this scanner has accepted - and that record is
        // checked against whatever daemon is answering *now*, with no notion of which
        // daemon supplied it originally. So pointing the scanner at a different node
        // serving a different history is not a case the reorg machinery fails to
        // cover: it is bit-for-bit the same case, and the same code re-derives,
        // re-locates and rescans exactly as it would for an honest reorg. That is the
        // property this test pins down - the same store, two entirely separate
        // daemon instances, no notification that anything changed.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();

        let honest = FakeDaemonClient::new();
        for h in 1..=49 {
            honest.push_block(&format!("a_{h}"), vec![]);
        }
        honest.push_block("a_50", vec![tx.clone()]);
        honest.push_block("a_51", vec![]);
        let store = store.into_shared();
        store.lock().unwrap().set_scanned_block("mainnet", 49, "a_49").unwrap();
        run_scan_tick(&store, &key_custody, &honest, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(store.lock().unwrap().get_all_payments(&order_id).unwrap()[0].block_height, Some(50));

        // A different node entirely: same network, chain diverging at 48, and the
        // payment nowhere in it. Nothing tells the scanner the daemon changed.
        let other = FakeDaemonClient::new();
        for h in 1..=47 {
            other.push_block(&format!("a_{h}"), vec![]);
        }
        for h in 48..=55 {
            other.push_block(&format!("b_{h}"), vec![]);
        }

        run_scan_tick(&store, &key_custody, &other, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            assert_eq!(
                s.max_scanned_height("mainnet").unwrap(),
                Some(48),
                "the divergence is found and rewound, exactly as for a reorg - at 49 rather than the true fork at \
                 48 because 48 is a height this scanner never recorded a hash for, and detection can only ever be \
                 as fine-grained as the window it kept"
            );
            let payment = &s.get_all_payments(&order_id).unwrap()[0];
            assert!(
                payment.voided_at.is_none(),
                "the new node not having the transaction proves nothing about it - never void on that"
            );
        }

        // ...and the scanner then works forward over the new node's chain.
        run_scan_tick(&store, &key_custody, &other, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(store.lock().unwrap().max_scanned_height("mainnet").unwrap(), Some(55));

        // Swapping back is symmetric: the *first* node is now the one presenting a
        // divergent history, and gets reconciled the same way.
        run_scan_tick(&store, &key_custody, &honest, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert_eq!(
            store.lock().unwrap().max_scanned_height("mainnet").unwrap(),
            Some(47),
            "no daemon is privileged - the stored chain is re-validated against whoever is answering"
        );
    }

    #[tokio::test]
    async fn a_daemon_that_omits_a_transaction_from_its_mempool_only_delays_detection() {
        // The benign half of "a daemon lies about the pool". An omission cannot
        // falsify anything: the scanner records payments from what it is shown, so
        // being shown less means seeing a payment later (when it is mined), never
        // seeing a wrong one. Worth an executable statement because the *cost* of the
        // omission is a real, bounded thing a merchant may care about - zero-conf
        // detection is what is lost, nothing else.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        // The transaction is genuinely in flight, but this node's pool never shows it.
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            assert!(s.get_all_payments(&order_id).unwrap().is_empty(), "nothing to see - only zero-conf is lost");
            assert_eq!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().status, crate::status::OrderStatus::Pending);
        }

        daemon.push_block("h2", vec![tx]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1, "the payment is detected in full the moment it is mined");
        assert_eq!(payments[0].block_height, Some(2));
        assert_eq!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().status, crate::status::OrderStatus::Confirming);
    }

    #[tokio::test]
    async fn a_transaction_a_daemon_invents_cannot_become_a_payment_unless_it_matches_a_wallet() {
        // The other half: a daemon inserting transactions that are not really in the
        // pool (or blocks). This cannot manufacture a payment, and the reason is
        // structural rather than a check anywhere in this file - a payment row exists
        // only where `KeyCustody` matched an output against a tenant's own view key,
        // which a daemon does not have. A phantom transaction that does not match is
        // simply scanned and discarded; one that *does* match would have to be a real
        // transaction really paying that subaddress, which is not a lie.
        let key_custody = PlainKeyCustody::default();
        let store = Store::open_in_memory().unwrap();
        let (view, spend) = arbitrary_wallet_material(0x33); // a tenant this fixture does *not* pay
        let (tenant_id, handle, order_id) = tenant_with_pending_order(&store, &key_custody, view, spend).await;
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.push_block("h2", vec![fixture_tx()]);
        daemon.set_mempool(vec![fixture_tx_variant(77)]);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert!(s.get_all_payments(&order_id).unwrap().is_empty(), "no wallet matched, so no payment exists");
        assert_eq!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().status, crate::status::OrderStatus::Pending);
        assert_eq!(s.get_order(&tenant_id, &order_id).unwrap().unwrap().amount_received_piconero, 0);
    }

    #[tokio::test]
    async fn an_inflated_reported_height_inflates_confirmations_which_is_an_accepted_trust_boundary() {
        // Recorded here as executable documentation of a boundary, not as a bug: the
        // confirmation count is `current_height - block_height + 1` off whatever
        // `get_height` returns, and nothing cross-checks that against the blocks the
        // scanner has actually seen. A daemon claiming a higher tip than exists
        // therefore ages payments faster than the chain does.
        //
        // This is not separately fixable, and the reason is worth stating: the
        // scanner validates no proof of work anywhere (by design - that is monerod's
        // job, §DESIGN.md 7.5), so a node willing to lie about its height can just as
        // cheaply serve a fabricated chain of block hashes to back the lie up.
        // Clamping confirmations to the scanner's own high-water mark would raise the
        // cost of the lie by nothing while making every honest post-reorg rewind
        // briefly under-count confirmations. The boundary is "the configured node is
        // trusted about the chain" - see docs/DESIGN.md §7.7.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await; // confirmations_required = 10
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.push_block("h2", vec![fixture_tx()]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
            assert_eq!(order.status, crate::status::OrderStatus::Confirming);
            assert_eq!(order.confirmations, 1, "one real block, one confirmation");
        }

        daemon.report_height(1_000); // the node asserts a tip it has no blocks for
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.confirmations, 999, "taken at face value - the documented trust boundary");
        assert_eq!(order.status, crate::status::OrderStatus::Overpaid);
    }

    #[tokio::test]
    async fn a_daemon_far_behind_the_recorded_high_water_mark_neither_rescans_nor_discards_its_window() {
        // The opposite lie, which is usually not a lie at all: a node reporting a
        // height *below* what this scanner has already recorded. The overwhelmingly
        // common cause is honest - a node resyncing from scratch, or a freshly
        // provisioned one still catching up - and the correct response is to do
        // nothing at all and wait. Specifically it must not "rewind to the tip the
        // daemon has", which for a resyncing mainnet node would discard the entire
        // scanned window and re-seed hundreds of thousands of blocks in the past.
        //
        // Recovery needs no special case: once the node climbs back into the window,
        // any genuine divergence is caught by the ordinary hash comparison (see
        // `swapping_to_a_daemon_serving_a_different_chain_reconciles_exactly_like_a_reorg`).
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let tx = fixture_tx();
        scan_transaction_for_tenant(&store, &key_custody, handle, &tenant_id, &tx, 0..3, 1500, Some(95))
            .await
            .unwrap();
        for h in 70..=100 {
            store.set_scanned_block("mainnet", h, &format!("old_{h}")).unwrap();
        }
        let (_, status) = store.recompute_order_status(&order_id, 100, 1600).unwrap();
        assert_eq!(status, crate::status::OrderStatus::Confirming, "six confirmations, ten required");
        let store = store.into_shared();

        // The node is at height 30, three quarters of the way through a resync.
        let daemon = FakeDaemonClient::new();
        for h in 1..=30 {
            daemon.push_block(&format!("old_{h}"), vec![]);
        }

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        assert_eq!(
            s.max_scanned_height("mainnet").unwrap(),
            Some(100),
            "the window belongs to the chain, not to whichever node is currently answering"
        );
        assert_eq!(s.get_scanned_block_hash("mainnet", 95).unwrap().as_deref(), Some("old_95"));
        let payment = &s.get_all_payments(&order_id).unwrap()[0];
        assert!(payment.voided_at.is_none(), "a node that hasn't got there yet proves nothing about a payment");
        assert_eq!(payment.block_height, Some(95));
    }

    #[tokio::test]
    async fn several_transactions_in_one_block_paying_one_order_are_all_recorded_and_summed() {
        // A block is not "one transaction for us at most". A customer paying in two
        // instalments that happen to land together, a wallet splitting a payment, and
        // an accidental second payment to the same address all produce this, and the
        // arithmetic has to hold: three rows, three amounts, one total, one status
        // recompute.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let txs = vec![fixture_tx(), independent_payment_tx(1), independent_payment_tx(2)];
        let per_tx_amount = {
            let scan = scan_transaction(&key_custody, handle, &txs[0], 0..3).await.unwrap();
            scan.matches[0].amount_piconero.unwrap()
        };
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.push_block("h2", txs);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let payments = s.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 3, "three distinct transactions are three payments, not one deduplicated row");
        assert!(payments.iter().all(|p| p.block_height == Some(2)));
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(order.amount_received_piconero, per_tx_amount * 3);
        assert_eq!(order.status, crate::status::OrderStatus::Confirming, "one confirmation, ten required");
    }

    #[tokio::test]
    async fn one_transactions_outputs_are_routed_to_whichever_order_owns_each_index() {
        // One transaction can pay several of a tenant's subaddresses at once (a
        // customer settling two invoices in one send is the obvious case). Routing is
        // per matched output, by minor index, and this is the step where a subtle
        // mistake would attribute a payment to the wrong customer's order - a
        // failure that shows up as one merchant's order marked paid by another's
        // money.
        //
        // Driven through `record_scan_match` with a constructed match set rather than
        // a real transaction: the fixture pays exactly one index, and manufacturing a
        // second real payment to a *different* index needs transaction construction
        // (which is what the stagenet end-to-end test exists for). The routing logic
        // being tested is entirely on this side of the crypto.
        let (store, _key_custody, _handle, tenant_id, first_order) = setup().await;
        let second_index = store.allocate_minor_index(&tenant_id).unwrap();
        assert_eq!(second_index, 2);
        let second_order = store
            .create_order(NewOrder {
                tenant_id: tenant_id.clone(),
                merchant_order_id: None,
                minor_index: second_index,
                address: "sub_2".into(),
                fiat_currency: "USD".into(),
                fiat_amount: "1.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 1,
                description: None,
                created_at: 1000,
                expires_at: crate::now_unix() + 3600,
            })
            .unwrap();

        let scan = ScanResult {
            matches: vec![
                MatchedOutput { output_index: 0, subaddress_index: SubaddressIndex { major: 0, minor: 1 }, amount_piconero: Some(700) },
                MatchedOutput { output_index: 1, subaddress_index: SubaddressIndex { major: 0, minor: 2 }, amount_piconero: Some(900) },
                // An index no order was ever issued for - a tenant's own older
                // subaddress, say. Must be dropped, not attributed to anything.
                MatchedOutput { output_index: 2, subaddress_index: SubaddressIndex { major: 0, minor: 9 }, amount_piconero: Some(100) },
            ],
            txid: "tx_paying_two_orders".into(),
            key_images_json: "[]".into(),
        };

        let touched = record_scan_match(&store, &tenant_id, &scan, 1500, Some(50)).unwrap();
        assert_eq!(touched, HashSet::from([first_order.clone(), second_order.id.clone()]));

        let first = store.get_all_payments(&first_order).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].amount_piconero, 700, "each order gets its own output's amount, never the transaction total");
        let second = store.get_all_payments(&second_order.id).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].amount_piconero, 900);
    }

    #[tokio::test]
    async fn one_tick_can_void_a_double_spent_payment_for_one_order_and_record_a_new_one_for_another() {
        // Two facts arriving in the same block, on the same tick, for different
        // orders: an older payment is orphaned and proven double-spent, while the
        // replacement chain carries a brand-new payment. Neither may contaminate the
        // other - and the shape also exercises the cross-tenant case migration 0004
        // exists for, since both tenants here are configured with the same view key
        // (a merchant running a second instance against one wallet), so one
        // transaction legitimately pays two different orders.
        let key_custody = PlainKeyCustody::default();
        let store = Store::open_in_memory().unwrap();
        let (tenant_a, handle_a, order_a) =
            tenant_with_pending_order(&store, &key_custody, fixture_view_key(), fixture_spend_pubkey()).await;
        let (tenant_b, handle_b, order_b) =
            tenant_with_pending_order(&store, &key_custody, fixture_view_key(), fixture_spend_pubkey()).await;

        let doomed = fixture_tx();
        let fresh = independent_payment_tx(6);
        let daemon = chain_scanned_to(&store, 51, 40, "old");
        // Only tenant A had a payment before the reorg.
        scan_transaction_for_tenant(&store, &key_custody, handle_a, &tenant_a, &doomed, 0..3, 1500, Some(50))
            .await
            .unwrap();
        for ki in &key_images_of(&doomed) {
            daemon.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        reorg_to_new_chain(&daemon, 50, 51, Some((50, fresh.clone())));
        let store = store.into_shared();

        let tenants = [(tenant_a.clone(), handle_a), (tenant_b.clone(), handle_b)];
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &tenants, 20).await.unwrap(); // detects, voids, rewinds
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &tenants, 20).await.unwrap(); // rescans the replacement chain

        let s = store.lock().unwrap();
        let a_payments = s.get_all_payments(&order_a).unwrap();
        assert_eq!(a_payments.len(), 2, "the voided one and the new one both belong to A's audit trail");
        let voided: Vec<_> = a_payments.iter().filter(|p| p.voided_at.is_some()).collect();
        assert_eq!(voided.len(), 1);
        assert_eq!(voided[0].txid, tx_id_hex(&doomed));
        let order_a_row = s.get_order(&tenant_a, &order_a).unwrap().unwrap();
        assert!(
            order_a_row.double_spend_detected_at.is_some(),
            "the incident stays recorded even though a later payment covered the order"
        );
        assert_eq!(order_a_row.amount_received_piconero, a_payments.iter().find(|p| p.voided_at.is_none()).unwrap().amount_piconero);

        let b_payments = s.get_all_payments(&order_b).unwrap();
        assert_eq!(b_payments.len(), 1, "B gets its own row for the same output - the constraint is per order");
        assert_eq!(b_payments[0].txid, tx_id_hex(&fresh));
        assert!(b_payments[0].voided_at.is_none());
        assert!(
            s.get_order(&tenant_b, &order_b).unwrap().unwrap().double_spend_detected_at.is_none(),
            "another order's double-spend is not B's problem"
        );
    }

    #[tokio::test]
    async fn an_amount_that_only_decrypts_on_a_later_tick_is_recorded_then_never_unrecorded() {
        // Amount recovery returning `None` is not necessarily a permanent property of
        // an output - `MatchedOutput::amount_piconero` is an `Option` precisely
        // because the decryption can fail - so the two orderings both need defining.
        // Failing first and succeeding later must record the payment (the "skip, do
        // not write a zero" rule exists to keep that possible); succeeding first and
        // failing later must leave the recorded payment exactly as it is, since a
        // payment is only ever removed on affirmative double-spend proof.
        let (store, _key_custody, _handle, tenant_id, order_id) = setup().await;
        let undecryptable = ScanResult {
            matches: vec![MatchedOutput {
                output_index: 0,
                subaddress_index: SubaddressIndex { major: 0, minor: 1 },
                amount_piconero: None,
            }],
            txid: "tx_flaky_amount".into(),
            key_images_json: "[]".into(),
        };
        let decrypted = ScanResult {
            matches: vec![MatchedOutput {
                output_index: 0,
                subaddress_index: SubaddressIndex { major: 0, minor: 1 },
                amount_piconero: Some(4_242),
            }],
            txid: "tx_flaky_amount".into(),
            key_images_json: "[]".into(),
        };

        record_scan_match(&store, &tenant_id, &undecryptable, 1500, Some(50)).unwrap();
        assert!(store.get_all_payments(&order_id).unwrap().is_empty());

        let touched = record_scan_match(&store, &tenant_id, &decrypted, 1600, Some(50)).unwrap();
        assert_eq!(touched, HashSet::from([order_id.clone()]), "the later success records it in full");
        assert_eq!(store.get_all_payments(&order_id).unwrap()[0].amount_piconero, 4_242);

        record_scan_match(&store, &tenant_id, &undecryptable, 1700, Some(50)).unwrap();
        let payments = store.get_all_payments(&order_id).unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].amount_piconero, 4_242, "a later failure to decrypt must not disturb a recorded payment");
        assert!(payments[0].voided_at.is_none());
    }

    #[tokio::test]
    async fn a_payment_completing_an_order_in_the_tick_its_deadline_passes_settles_rather_than_expiring() {
        // Expiry and payment are evaluated in one place, from one snapshot, so their
        // relative ordering within a tick is not a race - but it is worth an
        // executable statement, because "the customer paid at the last second" is
        // both common and the case where getting it wrong means keeping the money and
        // telling the customer their order expired. The status ladder only reaches
        // `expired` when the total falls *short*; a covered order is never expired,
        // however late it was covered.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        store
            .execute_raw_for_test(&format!("UPDATE orders SET expires_at = {} WHERE id = '{order_id}'", crate::now_unix() - 1))
            .unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);
        daemon.set_mempool(vec![fixture_tx()]);

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();

        let s = store.lock().unwrap();
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(
            order.status,
            crate::status::OrderStatus::Unconfirmed,
            "paid in full, if only just - the deadline governs orders that fall short, not covered ones"
        );
        assert!(order.amount_received_piconero > 0);

        // The other side of the same boundary: a *partial* payment past the deadline
        // does expire, and keeping both cases in one test is what stops a future
        // "fix" for either from quietly inverting the other.
        let partial = s
            .create_order(NewOrder {
                tenant_id: tenant_id.clone(),
                merchant_order_id: None,
                minor_index: s.allocate_minor_index(&tenant_id).unwrap(),
                address: "sub_partial".into(),
                fiat_currency: "USD".into(),
                fiat_amount: "1.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 10_000_000,
                description: None,
                created_at: 1000,
                expires_at: crate::now_unix() - 1,
            })
            .unwrap();
        s.record_payment_match(&partial.id, "tx_partial", 0, 1, "[]", 1500, None).unwrap();
        let (_, status) = s.recompute_order_status(&partial.id, 1, crate::now_unix()).unwrap();
        assert_eq!(status, crate::status::OrderStatus::Expired);
    }

    #[tokio::test]
    async fn a_chain_with_no_blocks_at_all_is_a_harmless_no_op_tick() {
        // The degenerate small-chain cases a fresh regtest or a just-initialised
        // private network actually produces: a node reporting height 0 with nothing
        // to serve. Everything here is unsigned arithmetic around a tip
        // (`height - reorg_check_depth`, `current_height - 1`), which is exactly the
        // shape that panics on underflow in debug builds if a `saturating_sub` is
        // ever dropped, and a payment gateway that panics on an empty chain fails
        // its first ever tick against a fresh node.
        let (store, key_custody, handle, tenant_id, order_id) = setup().await;
        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();

        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            assert_eq!(s.max_scanned_height("mainnet").unwrap(), None, "nothing to seed from, so nothing recorded");
            assert!(s.get_all_payments(&order_id).unwrap().is_empty());
        }

        // One block exists: the whole chain is height 1, and the tick must still
        // behave (seeding one behind the tip lands on height 0, which does not exist
        // here, so it degrades to "try again next tick" rather than erroring).
        daemon.push_block("only_block", vec![fixture_tx()]);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        assert!(check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.is_ok());
    }

    #[tokio::test]
    async fn a_divergence_at_the_genesis_block_has_no_ancestor_to_re_anchor_to() {
        // The one branch of the rewind that is otherwise unreachable: `reorg_point`
        // of 0 means the *genesis block* changed, so `reorg_point - 1` is not a
        // height at all. It cannot happen on any real chain - but the code has an
        // explicit branch for it, and an explicit branch with no test is a branch
        // nobody has ever run. The delete goes ahead with nothing to re-anchor to,
        // leaving an empty window that the next tick re-seeds from the tip.
        let store = Store::open_in_memory().unwrap();
        store.set_scanned_block("mainnet", 0, "genesis_v0").unwrap();
        store.set_scanned_block("mainnet", 1, "block_1_v0").unwrap();
        let store = store.into_shared();

        let daemon = FakeDaemonClient::new();
        daemon.seed_block_at(0, "genesis_v1", vec![]);
        daemon.push_block("block_1_v1", vec![]);

        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", 20, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(0));
        assert_eq!(
            store.lock().unwrap().max_scanned_height("mainnet").unwrap(),
            None,
            "there is no ancestor to preserve below genesis, so the window is emptied and re-seeded next tick"
        );
    }

    #[tokio::test]
    async fn the_scanned_block_window_stays_bounded_as_the_chain_grows() {
        // §TESTING.md 3's resource item, and the reason `prune_scanned_blocks_below`
        // exists. Two minutes per block means ~260k rows a year of pure growth for a
        // table nothing ever reads more than `reorg_check_depth` blocks back into,
        // on hardware that is often a router with an SD card.
        //
        // What the retention must *not* do matters more than the size it saves: the
        // window can never be pruned to nothing (an empty window reads as "this
        // network was never scanned" and re-seeds at the tip, skipping everything in
        // between), and a reorg at the far edge of the configured depth must still
        // find both a stored hash to notice it and an ancestor to re-anchor to
        // afterwards.
        let (store, key_custody, handle, tenant_id, _order_id) = setup().await;
        let store = store.into_shared();
        let daemon = FakeDaemonClient::new();
        daemon.push_block("h1", vec![]);

        let depth = 5;
        for i in 2..=60 {
            daemon.push_block(&format!("h{i}"), vec![]);
            run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], depth).await.unwrap();
        }

        {
            let s = store.lock().unwrap();
            assert_eq!(s.max_scanned_height("mainnet").unwrap(), Some(60));
            let retained: u64 = (0..=60).filter(|h| s.get_scanned_block_hash("mainnet", *h).unwrap().is_some()).count() as u64;
            assert!(retained > depth, "the window must always comfortably cover the configured reorg depth: {retained}");
            assert!(retained <= depth * 4 + 2, "and must not grow with the chain: {retained} rows after 60 blocks");
        }

        // A reorg at the deepest point the configured window claims to cover is still
        // both detectable and rewindable after all that pruning.
        // (Same tip, so the window is exactly `60-depth..=60` and the fork sits on
        // its lower edge - a reorg that also *grew* the chain would move the window
        // up with it, which is the separate limitation
        // `a_reorg_deeper_than_the_window_is_reported_at_the_window_edge_and_leaves_older_payments_alone`
        // covers.)
        reorg_to_new_chain(&daemon, 60 - depth, 60, None);
        let report = check_for_reorg_and_reconcile(&store, &daemon, "mainnet", depth, 2000).await.unwrap();
        assert_eq!(report.reorg_detected_at, Some(60 - depth));
        assert_eq!(
            store.lock().unwrap().max_scanned_height("mainnet").unwrap(),
            Some(60 - depth - 1),
            "the rewind still finds an ancestor to anchor on below the pruned window"
        );
    }

    #[tokio::test]
    async fn a_void_that_lands_before_the_node_fails_still_updates_the_order_it_belongs_to() {
        // The nastiest shape of "the node went away mid-tick", and the reason voiding
        // and the status recompute it implies are one transaction rather than two
        // steps a failure can land between.
        //
        // A void is a *committed* write. Everything that makes it visible - the
        // order's status and received total, the retraction webhook, the
        // double-spend event - used to happen only after the whole sweep finished,
        // so a node failure on a later payment discarded all of it. That is
        // unrecoverable rather than merely delayed: the voided row is excluded from
        // the next tick's sweep by construction (it is no longer an unconfirmed
        // payment), and an order sitting in a terminal status is excluded from the
        // per-tick recompute too. The merchant is left looking at `paid` for an
        // order whose money was double-spent, permanently, with no event ever sent.
        let (store, key_custody, handle, tenant_id, order_id) = setup_with_zero_conf_ceiling(Some(u64::MAX)).await;
        store.create_webhook(&tenant_id, "https://merchant.example/hook", "{}", "whsec_x", 1000).unwrap();
        let first = fixture_tx();
        let second = independent_payment_tx(8);
        let per_tx = {
            let scan = scan_transaction(&key_custody, handle, &first, 0..3).await.unwrap();
            scan.matches[0].amount_piconero.unwrap()
        };
        // An order that needs *both* payments, so voiding either one has to be
        // visible in the order's status rather than being absorbed by the other.
        store
            .execute_raw_for_test(&format!(
                "UPDATE orders SET xmr_amount_piconero = {} WHERE id = '{order_id}'",
                per_tx * 2
            ))
            .unwrap();
        let store = store.into_shared();

        let fake = FakeDaemonClient::new();
        fake.push_block("h1", vec![]);
        fake.set_mempool(vec![first.clone(), second.clone()]);
        let daemon = DaemonFailingFrom::counting(fake, DaemonCall::Locate);
        run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await.unwrap();
        {
            let s = store.lock().unwrap();
            let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
            assert_eq!(order.status, crate::status::OrderStatus::Paid, "covered by both payments, trusted at zero-conf");
        }

        // Both transactions are double-spent out of the pool at once, and the node
        // dies on the second lookup - after the first payment has already been voided.
        daemon.inner.drop_from_mempool(&first);
        daemon.inner.drop_from_mempool(&second);
        for ki in key_images_of(&first).iter().chain(key_images_of(&second).iter()) {
            daemon.inner.set_key_image_status(ki, KeyImageStatus::SpentInBlockchain);
        }
        daemon.fail_from.store(1, Ordering::SeqCst);

        let result = run_scan_tick(&store, &key_custody, &daemon, "mainnet", &[(tenant_id.clone(), handle)], 20).await;
        assert!(result.is_err(), "the node failure must surface");

        let s = store.lock().unwrap();
        let payments = s.get_all_payments(&order_id).unwrap();
        let voided: Vec<_> = payments.iter().filter(|p| p.voided_at.is_some()).collect();
        assert_eq!(voided.len(), 1, "exactly one payment was resolved before the node failed");
        let order = s.get_order(&tenant_id, &order_id).unwrap().unwrap();
        assert_eq!(
            order.amount_received_piconero, per_tx,
            "the order's total must reflect the void that actually committed"
        );
        assert_eq!(
            order.status,
            crate::status::OrderStatus::Partial,
            "an order whose money was voided must never be left reading `paid` because a later RPC failed"
        );
        assert!(order.double_spend_detected_at.is_some());
        let events: Vec<String> =
            s.due_webhook_deliveries(crate::now_unix() + 1, 20).unwrap().into_iter().map(|d| d.event_type).collect();
        assert!(events.contains(&"order.double_spend_detected".to_string()), "and the merchant is told: {events:?}");
        assert!(events.contains(&"order.partial".to_string()), "including the retraction of `paid`: {events:?}");
    }

    #[test]
    fn run_scan_ticks_future_is_send() {
        // Direct regression test for a real bug caught only when this code was
        // actually wired into `tokio::spawn` in `main.rs`, not by any of the
        // `#[tokio::test]`s above: `rusqlite::Connection` is `Send` but not `Sync`,
        // so a `&Store` held across an `.await` (as combining
        // `scan_transaction`+`record_scan_match` into one async function would
        // require) makes the containing future `!Send`. Every test above awaits
        // `run_scan_tick` directly inside its own task, which never requires
        // `Send` - only `tokio::spawn`'s `F: Send + 'static` bound does, and
        // nothing here exercises that. This compiles only if the future actually
        // is `Send`; it doesn't need to run to prove the property.
        fn assert_send<T: Send>(_: T) {}

        let store = Store::open_in_memory().unwrap().into_shared();
        let key_custody = PlainKeyCustody::default();
        let daemon = FakeDaemonClient::new();
        let tenants: Vec<(String, WalletHandle)> = vec![];
        assert_send(run_scan_tick(&store, &key_custody, &daemon, "mainnet", &tenants, 20));
    }
}
