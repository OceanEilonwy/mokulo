//! The single source of truth for `orders.status`. See `docs/DESIGN.md` §7.6.
//!
//! This is a pure function, deliberately: it is called after *every* mutation to an
//! order's payments (a new match, a reorg moving a block height, a reorg voiding a
//! row), rather than being patched incrementally per event type. An earlier design
//! that treated "double-spent" as a status value alongside `Paid`/`Partial`/etc. broke
//! the moment a second contributing payment could cover an order after the first was
//! voided - see `double_spend_detected_at` in the schema, which is why that fact lives
//! outside this function entirely.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrderStatus {
    Pending,
    Unconfirmed,
    Confirming,
    Paid,
    Partial,
    Overpaid,
    Expired,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OrderStatus::Pending => "pending",
            OrderStatus::Unconfirmed => "unconfirmed",
            OrderStatus::Confirming => "confirming",
            OrderStatus::Paid => "paid",
            OrderStatus::Partial => "partial",
            OrderStatus::Overpaid => "overpaid",
            OrderStatus::Expired => "expired",
        }
    }
}

impl fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One contributing payment, as seen by the status function - deliberately not the
/// full `order_payments` row shape, just what the derivation needs. `confirmations`
/// is 0 for anything still unconfirmed (mempool-only); the caller (the store layer)
/// is responsible for turning `block_height` into a confirmation count against the
/// current chain height before calling this.
#[derive(Debug, Clone, Copy)]
pub struct PaymentView {
    pub amount_piconero: u64,
    pub confirmations: u64,
    pub is_zero_conf: bool, // true iff block_height IS NULL for this payment
}

#[derive(Debug, Clone, Copy)]
pub struct StatusInputs {
    pub xmr_amount_piconero: u64,
    pub confirmations_required: u64,
    /// `None` = the tenant never trusts 0-conf as sufficient, regardless of amount.
    pub zero_conf_max_piconero: Option<u64>,
    pub now: i64,
    pub expires_at: i64,
}

/// Derive an order's status from its currently-valid (non-voided) payments. Callers
/// must exclude voided rows from `payments` before calling this - this function has
/// no notion of "voided" at all, on purpose, since double-spend handling is entirely
/// the caller's concern (see module docs).
pub fn derive_status(payments: &[PaymentView], inputs: StatusInputs) -> OrderStatus {
    let total: u64 = payments.iter().map(|p| p.amount_piconero).sum();
    let min_confirmations = payments.iter().map(|p| p.confirmations).min().unwrap_or(0);
    let all_zero_conf = !payments.is_empty() && payments.iter().all(|p| p.is_zero_conf);

    if total >= inputs.xmr_amount_piconero {
        let sufficiently_confirmed = min_confirmations >= inputs.confirmations_required;
        // Deliberately *not* also gated on `all_zero_conf`, though the obvious reading
        // of "zero-conf trust" (and this function's original form, and DESIGN.md
        // §7.6's pseudocode before it was corrected to match) says it should be.
        //
        // The ceiling means "a total this small doesn't need to wait for
        // confirmations." Requiring `all_zero_conf` on top of that withdraws the trust
        // the moment the transaction is *mined* - the one event that can only ever
        // make a payment safer. With a ceiling set and `confirmations_required = 10`,
        // an order under the ceiling went `paid` off the mempool sighting, then back to
        // `confirming` about two minutes later when the block arrived, then to `paid`
        // again nine blocks after that. That is not an edge case: it is what happens to
        // every single order this setting applies to, which is the entire reason the
        // setting exists.
        //
        // Two consequences, both bad in the way this codebase is otherwise careful to
        // avoid. `order.paid` is retracted by an `order.confirming` that follows it -
        // exactly the "we sent it, then took it back a second later" sequence
        // `scanner::run_scan_tick` reorders a whole tick to prevent, arrived at here
        // with no reorg involved at all. And the later re-entry to `paid` is a genuine
        // status transition, so it is announced with a *fresh* `event_id`, which under
        // the event-id contract explicitly tells the merchant "this is a second
        // transition, not a redelivery" - so a merchant deduplicating correctly still
        // ships twice.
        //
        // Dropping the condition makes the ladder monotone in evidence: nothing an
        // order learns about the chain can ever lower its status. It cannot loosen the
        // ceiling either - `total <= ceiling` still bounds the exposure to exactly what
        // the merchant opted into, and a confirmed payment strictly dominates the
        // mempool sighting that was already being trusted.
        let zero_conf_trusted = inputs.zero_conf_max_piconero.is_some_and(|ceiling| total <= ceiling);

        if sufficiently_confirmed || zero_conf_trusted {
            if total > inputs.xmr_amount_piconero {
                OrderStatus::Overpaid
            } else {
                OrderStatus::Paid
            }
        } else if all_zero_conf {
            OrderStatus::Unconfirmed
        } else {
            OrderStatus::Confirming
        }
    } else if inputs.now > inputs.expires_at {
        // Even a partial payment past the deadline surfaces as expired - the funds
        // still exist at the address and require manual merchant handling, since no
        // automated refund path exists anywhere in this system (see DESIGN.md §3).
        OrderStatus::Expired
    } else if total == 0 {
        OrderStatus::Pending
    } else {
        OrderStatus::Partial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(expected: u64, conf_required: u64, zero_conf_ceiling: Option<u64>, now: i64, expires_at: i64) -> StatusInputs {
        StatusInputs {
            xmr_amount_piconero: expected,
            confirmations_required: conf_required,
            zero_conf_max_piconero: zero_conf_ceiling,
            now,
            expires_at,
        }
    }

    fn confirmed(amount: u64, confirmations: u64) -> PaymentView {
        PaymentView { amount_piconero: amount, confirmations, is_zero_conf: false }
    }

    fn zero_conf(amount: u64) -> PaymentView {
        PaymentView { amount_piconero: amount, confirmations: 0, is_zero_conf: true }
    }

    #[test]
    fn no_payments_before_expiry_is_pending() {
        let status = derive_status(&[], inputs(100, 10, None, 500, 1000));
        assert_eq!(status, OrderStatus::Pending);
    }

    #[test]
    fn no_payments_after_expiry_is_expired() {
        let status = derive_status(&[], inputs(100, 10, None, 1500, 1000));
        assert_eq!(status, OrderStatus::Expired);
    }

    #[test]
    fn partial_payment_before_expiry_is_partial_regardless_of_confirmation_depth() {
        // A fully-confirmed half-payment is still "partial", not "confirming" -
        // partial is about amount, confirming is about a fully-funded order that
        // just hasn't accumulated enough confirmations yet.
        let status = derive_status(&[confirmed(50, 100)], inputs(100, 10, None, 500, 1000));
        assert_eq!(status, OrderStatus::Partial);
    }

    #[test]
    fn partial_payment_after_expiry_is_expired_not_partial() {
        // Deliberate: funds sit at the address unresolved past the deadline, which
        // requires manual merchant handling since there is no auto-refund path.
        let status = derive_status(&[confirmed(50, 100)], inputs(100, 10, None, 1500, 1000));
        assert_eq!(status, OrderStatus::Expired);
    }

    #[test]
    fn full_amount_all_zero_conf_no_ceiling_is_unconfirmed() {
        let status = derive_status(&[zero_conf(100)], inputs(100, 10, None, 500, 1000));
        assert_eq!(status, OrderStatus::Unconfirmed);
    }

    #[test]
    fn full_amount_all_zero_conf_covered_by_ceiling_is_paid() {
        let status = derive_status(&[zero_conf(100)], inputs(100, 10, Some(200), 500, 1000));
        assert_eq!(status, OrderStatus::Paid);
    }

    #[test]
    fn full_amount_all_zero_conf_exceeding_ceiling_is_unconfirmed() {
        let status = derive_status(&[zero_conf(100)], inputs(100, 10, Some(50), 500, 1000));
        assert_eq!(status, OrderStatus::Unconfirmed);
    }

    #[test]
    fn full_amount_mixed_zero_conf_and_onchain_below_threshold_is_confirming_not_unconfirmed() {
        // The instant any contributing payment has a block height, all_zero_conf
        // must be false - this is the branch that would be wrong if implemented as
        // independent conditionals instead of one ladder.
        let status = derive_status(
            &[confirmed(60, 2), zero_conf(40)],
            inputs(100, 10, None, 500, 1000),
        );
        assert_eq!(status, OrderStatus::Confirming);
    }

    #[test]
    fn min_confirmations_exactly_at_threshold_is_paid() {
        let status = derive_status(&[confirmed(100, 10)], inputs(100, 10, None, 500, 1000));
        assert_eq!(status, OrderStatus::Paid);
    }

    #[test]
    fn min_confirmations_one_below_threshold_is_confirming() {
        let status = derive_status(&[confirmed(100, 9)], inputs(100, 10, None, 500, 1000));
        assert_eq!(status, OrderStatus::Confirming);
    }

    #[test]
    fn overpaid_confirmed() {
        let status = derive_status(&[confirmed(150, 10)], inputs(100, 10, None, 500, 1000));
        assert_eq!(status, OrderStatus::Overpaid);
    }

    #[test]
    fn overpaid_zero_conf_covered_by_ceiling() {
        let status = derive_status(&[zero_conf(150)], inputs(100, 10, Some(200), 500, 1000));
        assert_eq!(status, OrderStatus::Overpaid);
    }

    #[test]
    fn multi_payment_one_voided_leaves_partial() {
        // Direct regression test for the multi-transaction/double-spend scenario
        // that corrected this design: two payments summing to exactly the expected
        // amount, one later voided (excluded by the caller before calling this
        // function) - the survivor alone is insufficient.
        let all = [confirmed(60, 10), confirmed(40, 10)];
        let after_void = &all[..1]; // caller excludes the voided row entirely
        assert_eq!(
            derive_status(&all, inputs(100, 10, None, 500, 1000)),
            OrderStatus::Paid
        );
        assert_eq!(
            derive_status(after_void, inputs(100, 10, None, 500, 1000)),
            OrderStatus::Partial
        );
    }

    #[test]
    fn multi_payment_voiding_one_still_leaves_enough_stays_paid() {
        // A double-spend that turns out to be financially irrelevant (redundant
        // payments covered the order anyway) must not downgrade the order.
        let survivors = [confirmed(60, 10), confirmed(60, 10)]; // one voided elsewhere, these two remain
        assert_eq!(
            derive_status(&survivors, inputs(100, 10, None, 500, 1000)),
            OrderStatus::Overpaid
        );
    }

    #[test]
    fn a_ceiling_trusted_order_stays_paid_once_its_transaction_is_mined() {
        // The regression: `zero_conf_trusted` also required `all_zero_conf`, so the
        // trust evaporated the instant the transaction got a block height - the one
        // event that can only make a payment safer. An order under the ceiling went
        // `paid` -> `confirming` -> `paid` as an ordinary mined block arrived, with no
        // reorg anywhere in sight, on every order the setting applies to.
        //
        // Walking the whole lifecycle rather than asserting one row, because the
        // property that matters is the *sequence*: status must never move backwards as
        // the chain adds evidence.
        let ceiling = Some(200u64);
        let inputs = |now| inputs(100, 10, ceiling, now, 100_000);

        // Mempool sighting: trusted, because the total is under the ceiling.
        assert_eq!(derive_status(&[zero_conf(100)], inputs(500)), OrderStatus::Paid);
        // Mined, one confirmation - far below `confirmations_required = 10`. This is
        // the step that used to retract the `order.paid` the merchant already acted on.
        assert_eq!(
            derive_status(&[confirmed(100, 1)], inputs(600)),
            OrderStatus::Paid,
            "a mined payment must not be trusted *less* than the same payment in the mempool"
        );
        // Every depth in between, up to and past the threshold.
        for confirmations in 1..=12 {
            assert_eq!(
                derive_status(&[confirmed(100, confirmations)], inputs(700)),
                OrderStatus::Paid,
                "status must never move backwards at {confirmations} confirmations"
            );
        }

        // The ceiling still bounds exactly what it did before: a total above it gets
        // no waiver at any depth below the threshold, mined or not.
        assert_eq!(derive_status(&[zero_conf(300)], inputs(500)), OrderStatus::Unconfirmed);
        assert_eq!(derive_status(&[confirmed(300, 1)], inputs(500)), OrderStatus::Confirming);
        assert_eq!(derive_status(&[confirmed(300, 10)], inputs(500)), OrderStatus::Overpaid);

        // ...and with no ceiling configured at all, nothing is waived - the ladder is
        // untouched for every tenant that never opted in.
        assert_eq!(derive_status(&[confirmed(100, 1)], super::tests::inputs(100, 10, None, 500, 100_000)), OrderStatus::Confirming);
        assert_eq!(derive_status(&[zero_conf(100)], super::tests::inputs(100, 10, None, 500, 100_000)), OrderStatus::Unconfirmed);

        // A mixed set - one payment mined, one still in the mempool - is likewise
        // judged on the total against the ceiling, not on which rows happen to have a
        // height yet. Newly routine now that `block_height` is upserted after the fact.
        assert_eq!(derive_status(&[confirmed(60, 2), zero_conf(40)], inputs(800)), OrderStatus::Paid);
    }

    #[test]
    fn a_settled_order_is_never_walked_back_to_expired_by_the_clock_alone() {
        // Every non-terminal order is now recomputed on every tick, so a settled order
        // gets re-derived long after its `expires_at` has passed. `expired` must stay
        // unreachable for anything fully funded - the deadline is about orders that
        // were never paid, and a `paid` order flipping to `expired` because time moved
        // would retract a settlement for no reason at all.
        for payments in [
            vec![confirmed(100, 10)],       // settled on confirmations
            vec![zero_conf(100)],           // settled on the zero-conf ceiling
            vec![confirmed(150, 10)],       // overpaid
        ] {
            let long_past_expiry = inputs(100, 10, Some(200), 9_999_999, 1000);
            assert!(
                matches!(
                    derive_status(&payments, long_past_expiry),
                    OrderStatus::Paid | OrderStatus::Overpaid
                ),
                "a funded order must not expire: {payments:?}"
            );
        }
        // An order still short of the amount does expire, ceiling or not - the ceiling
        // waives confirmations, never the amount.
        assert_eq!(
            derive_status(&[zero_conf(99)], inputs(100, 10, Some(200), 9_999_999, 1000)),
            OrderStatus::Expired
        );
    }

    #[test]
    fn a_zeroed_but_present_row_is_not_a_safe_substitute_for_exclusion() {
        // This function has no concept of "voided" - it trusts the caller to fully
        // remove voided rows from the slice, not merely zero out their amount.
        // Demonstrating the divergence here documents *why* that contract matters:
        // a lingering zero-amount row still participates in `min_confirmations` and
        // `all_zero_conf`, silently downgrading a `Paid` order to `Confirming` even
        // though it contributes nothing financially.
        let zeroed_but_present = [
            confirmed(100, 10),
            PaymentView { amount_piconero: 0, confirmations: 0, is_zero_conf: true },
        ];
        let properly_excluded = [confirmed(100, 10)];
        assert_eq!(derive_status(&properly_excluded, inputs(100, 10, None, 500, 1000)), OrderStatus::Paid);
        assert_eq!(derive_status(&zeroed_but_present, inputs(100, 10, None, 500, 1000)), OrderStatus::Confirming);
    }
}
