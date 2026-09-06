//! Fiat-to-XMR conversion for order creation. See `docs/DESIGN.md` §13
//! (`[exchange_rate]` config) - a real Haveno-backed provider is not implemented in
//! this pass; only the trait and a fixed-rate implementation useful for a
//! self-hoster who wants to peg a rate manually, or for testing.
//!
//! Money is never a float anywhere in this system (see `docs/DESIGN.md` §8.1) -
//! `compute_xmr_amount` does the fiat-decimal-string -> piconero conversion as exact
//! integer arithmetic, never `f64`.

pub trait ExchangeRateProvider: Send + Sync {
    /// Piconero per one whole unit of `fiat_currency` (e.g. per $1.00), or `None`
    /// if this provider doesn't have a rate for that currency.
    fn piconero_per_unit(&self, fiat_currency: &str) -> Option<u64>;
}

#[derive(Debug)]
pub struct FixedRateProvider {
    rates: std::collections::HashMap<String, u64>,
}

impl FixedRateProvider {
    pub fn new(rates: std::collections::HashMap<String, u64>) -> Self {
        FixedRateProvider { rates }
    }
}

impl ExchangeRateProvider for FixedRateProvider {
    fn piconero_per_unit(&self, fiat_currency: &str) -> Option<u64> {
        self.rates.get(fiat_currency).copied()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AmountError {
    #[error("amount is not a valid decimal number")]
    InvalidDecimal,
    #[error("amount must be positive")]
    NotPositive,
    #[error("amount has more than 2 decimal places")]
    TooManyDecimalPlaces,
    #[error("amount is too large to represent in piconero")]
    TooLarge,
}

/// Splits a decimal string into its (whole, fraction) digit runs, rejecting anything
/// that isn't purely ASCII digits on either side.
///
/// The explicit digit check is not redundant with the `u128::from_str` that follows:
/// Rust's integer parser accepts a leading `+`, so without this `"1.+5"` parses
/// happily - and *wrongly*, because the `+` then eats one of the zero-padding slots
/// and shifts the fraction by a decimal place. That input would silently become 1.05
/// rather than being rejected. For a value that decides what a customer is charged,
/// "silently a different number" is the failure mode to design against.
fn split_decimal(s: &str) -> Result<(&str, &str), AmountError> {
    let (whole, fraction) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(AmountError::InvalidDecimal);
    }
    let all_digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(whole) || !all_digits(fraction) {
        return Err(AmountError::InvalidDecimal);
    }
    Ok((whole, fraction))
}

/// Converts a decimal fiat amount string (e.g. "24.99", "5", "5.5") into piconero,
/// given a rate expressed as piconero-per-whole-unit. Fiat amounts are assumed to
/// have at most 2 decimal places (true of every currency this is likely to see in
/// v1) - rejected outright otherwise, rather than silently truncating a customer's
/// entered amount.
///
/// Rounds *up* to the next whole piconero when the division isn't exact. The
/// remainder is at most one piconero (1e-12 XMR, economically nothing either way),
/// but the direction still has to be chosen deliberately rather than fall out of
/// whatever `/` happens to do: rounding down would make the order's target amount
/// strictly less than the fiat price, so a customer paying it exactly would leave
/// the merchant short and the order would still settle as `Paid`. Rounding up can
/// only ever ask for a hair more than the price, which the status ladder already
/// handles as an overpayment. Erring against the party who chose the amount is the
/// safe direction.
pub fn compute_xmr_amount(fiat_amount: &str, piconero_per_unit: u64) -> Result<u64, AmountError> {
    let (whole, fraction) = split_decimal(fiat_amount)?;
    if fraction.len() > 2 {
        return Err(AmountError::TooManyDecimalPlaces);
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| AmountError::TooLarge)? };
    let fraction_padded = format!("{fraction:0<2}"); // "5" -> "50", "" -> "00"
    let frac: u128 = fraction_padded.parse().map_err(|_| AmountError::InvalidDecimal)?;
    let cents = whole
        .checked_mul(100)
        .and_then(|c| c.checked_add(frac))
        .ok_or(AmountError::TooLarge)?;
    if cents == 0 {
        return Err(AmountError::NotPositive);
    }
    let scaled = cents.checked_mul(piconero_per_unit as u128).ok_or(AmountError::TooLarge)?;
    let piconero = scaled.div_ceil(100);
    // `as u64` here would wrap silently, turning a huge order into a trivially cheap
    // one - the exact shape of bug that costs a merchant real money without ever
    // producing an error to notice.
    let piconero = u64::try_from(piconero).map_err(|_| AmountError::TooLarge)?;
    if piconero == 0 {
        // Only reachable with a zero (or absurdly small) configured rate, but an
        // order for zero piconero would be satisfied by paying nothing at all -
        // `derive_status` would call it `Paid` on an empty payment set.
        return Err(AmountError::NotPositive);
    }
    Ok(piconero)
}

/// Converts an XMR-denominated decimal string (up to 12 decimal places - XMR's own
/// precision) into piconero. Used for turning a config file's human-entered rate
/// (e.g. `"0.0067"` XMR per USD) into the integer `piconero_per_unit` an
/// `ExchangeRateProvider` deals in - kept separate from `compute_xmr_amount` since
/// that one assumes 2 fiat decimal places, not 12.
pub fn parse_xmr_to_piconero(xmr_amount: &str) -> Result<u64, AmountError> {
    let (whole, fraction) = split_decimal(xmr_amount)?;
    if fraction.len() > 12 {
        return Err(AmountError::TooManyDecimalPlaces);
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| AmountError::TooLarge)? };
    let fraction_padded = format!("{fraction:0<12}");
    let frac: u128 = fraction_padded.parse().map_err(|_| AmountError::InvalidDecimal)?;
    let piconero = whole
        .checked_mul(1_000_000_000_000)
        .and_then(|p| p.checked_add(frac))
        .ok_or(AmountError::TooLarge)?;
    // u64 tops out just short of 18.45M XMR - close enough to the total supply that
    // a plausible-looking config value can cross it. `as u64` would wrap it to
    // something small and wrong, and since this feeds `piconero_per_unit` for a whole
    // currency, every order priced in that currency would inherit the error.
    u64::try_from(piconero).map_err(|_| AmountError::TooLarge)
}

/// Inverse of `parse_xmr_to_piconero`, for display purposes (the payment page,
/// order API responses that show an XMR amount rather than raw piconero): formats
/// piconero as a fixed-12-decimal XMR string, e.g. `500_000_000_000` ->
/// `"0.500000000000"`. Deliberately fixed-width rather than trimming trailing
/// zeros - a customer comparing this against what their wallet shows benefits from
/// the full precision being visible, not a shortened form that could be misread.
pub fn format_piconero_as_xmr(piconero: u64) -> String {
    let whole = piconero / 1_000_000_000_000;
    let frac = piconero % 1_000_000_000_000;
    format!("{whole}.{frac:012}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twenty_five_dollars_at_a_known_rate_matches_hand_computed_value() {
        // 0.0067 XMR/USD expressed as piconero-per-USD: 0.0067 * 1e12 = 6_700_000_000
        let piconero_per_usd = 6_700_000_000u64;
        let amount = compute_xmr_amount("25.00", piconero_per_usd).unwrap();
        assert_eq!(amount, 167_500_000_000);
    }

    #[test]
    fn whole_number_amount_without_a_decimal_point_works() {
        assert_eq!(compute_xmr_amount("5", 1_000_000).unwrap(), 5_000_000);
    }

    #[test]
    fn single_decimal_digit_is_treated_as_tenths() {
        assert_eq!(compute_xmr_amount("5.5", 1_000_000).unwrap(), 5_500_000);
    }

    #[test]
    fn more_than_two_decimal_places_is_rejected_not_truncated() {
        assert_eq!(compute_xmr_amount("5.123", 1_000_000), Err(AmountError::TooManyDecimalPlaces));
    }

    #[test]
    fn zero_or_empty_amount_is_rejected() {
        assert_eq!(compute_xmr_amount("0.00", 1_000_000), Err(AmountError::NotPositive));
        assert_eq!(compute_xmr_amount("", 1_000_000), Err(AmountError::InvalidDecimal));
    }

    #[test]
    fn non_numeric_amount_is_rejected() {
        assert_eq!(compute_xmr_amount("abc", 1_000_000), Err(AmountError::InvalidDecimal));
    }

    #[test]
    fn parse_xmr_to_piconero_matches_hand_computed_values() {
        assert_eq!(parse_xmr_to_piconero("0.0067").unwrap(), 6_700_000_000);
        assert_eq!(parse_xmr_to_piconero("1").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_xmr_to_piconero("0.000000000001").unwrap(), 1); // one piconero
        assert_eq!(parse_xmr_to_piconero("0.0000000000001"), Err(AmountError::TooManyDecimalPlaces)); // 13 places
    }

    #[test]
    fn format_piconero_as_xmr_matches_hand_computed_values() {
        assert_eq!(format_piconero_as_xmr(6_700_000_000), "0.006700000000");
        assert_eq!(format_piconero_as_xmr(1_000_000_000_000), "1.000000000000");
        assert_eq!(format_piconero_as_xmr(1), "0.000000000001");
        assert_eq!(format_piconero_as_xmr(0), "0.000000000000");
    }

    #[test]
    fn format_and_parse_xmr_round_trip() {
        for piconero in [0u64, 1, 6_700_000_000, 1_000_000_000_000, 167_500_000_000] {
            let formatted = format_piconero_as_xmr(piconero);
            assert_eq!(parse_xmr_to_piconero(&formatted).unwrap(), piconero, "round trip failed for {piconero}");
        }
    }

    #[test]
    fn a_value_too_large_for_u64_piconero_is_an_error_not_a_silent_wraparound() {
        // 2^64 piconero exactly: the old `as u64` cast turned this into 0, so a
        // config rate of this size would have priced every order in that currency
        // at nothing.
        assert_eq!(parse_xmr_to_piconero("18446744.073709551616"), Err(AmountError::TooLarge));
        assert_eq!(parse_xmr_to_piconero("20000000"), Err(AmountError::TooLarge));
        // One piconero below the wrap point must still be accepted exactly.
        assert_eq!(parse_xmr_to_piconero("18446744.073709551615").unwrap(), u64::MAX);

        // Same wraparound reachable through the order-pricing path: a large fiat
        // amount at a normal rate.
        assert_eq!(compute_xmr_amount("99999999999", 6_700_000_000), Err(AmountError::TooLarge));
        // ...and through a whole part too big for the u128 intermediate itself.
        assert!(matches!(
            parse_xmr_to_piconero(&"9".repeat(40)),
            Err(AmountError::TooLarge)
        ));
    }

    #[test]
    fn a_leading_plus_sign_is_rejected_rather_than_shifting_the_decimal_place() {
        // Rust's integer parser accepts `+`, and the `+` then consumed one of the
        // zero-padding slots: "1.+5" silently became 1.05 instead of being refused.
        assert_eq!(compute_xmr_amount("1.+5", 1_000_000_000_000), Err(AmountError::InvalidDecimal));
        assert_eq!(parse_xmr_to_piconero("1.+5"), Err(AmountError::InvalidDecimal));
        assert_eq!(parse_xmr_to_piconero("+1"), Err(AmountError::InvalidDecimal));
        assert_eq!(compute_xmr_amount("+25.00", 1_000_000), Err(AmountError::InvalidDecimal));
    }

    #[test]
    fn every_other_malformed_decimal_shape_is_rejected() {
        for bad in [
            "", ".", "..", "1.2.3", "-1", "-0.5", "1e5", "1E5", " 5", "5 ", "\t5", "5\n", "1_000",
            "0x10", "NaN", "inf", "٥", "1,5", "5.", // trailing dot: fraction is empty, whole is "5"
        ] {
            let result = parse_xmr_to_piconero(bad);
            if bad == "5." {
                // A trailing dot is a degenerate but unambiguous "5" - accepted on
                // purpose, documented here so it isn't mistaken for an oversight.
                assert_eq!(result.unwrap(), 5_000_000_000_000);
                continue;
            }
            assert!(result.is_err(), "{bad:?} should be rejected, got {result:?}");
        }
    }

    #[test]
    fn a_fractional_piconero_remainder_rounds_up_so_the_merchant_is_never_short() {
        // 1 cent at a rate of 15 piconero/unit is 0.15 piconero. Rounding down gives
        // 0 - an order satisfiable by paying nothing. Rounding up gives 1, at a cost
        // of one piconero (1e-12 XMR) to the customer.
        assert_eq!(compute_xmr_amount("0.01", 15).unwrap(), 1);
        // 3 cents at 5 piconero/unit = 0.15 -> 1, not 0.
        assert_eq!(compute_xmr_amount("0.03", 5).unwrap(), 1);
        // 101 cents at 1 piconero/unit = 1.01 -> 2, never 1.
        assert_eq!(compute_xmr_amount("1.01", 1).unwrap(), 2);
        // Exact divisions must not be nudged upwards by the ceiling.
        assert_eq!(compute_xmr_amount("25.00", 6_700_000_000).unwrap(), 167_500_000_000);
        assert_eq!(compute_xmr_amount("1.00", 100).unwrap(), 100);
    }

    #[test]
    fn an_order_can_never_be_priced_at_zero_piconero() {
        // A zero-priced order is satisfied by an empty payment set - `derive_status`
        // would report it `Paid` the moment it was created.
        assert_eq!(compute_xmr_amount("25.00", 0), Err(AmountError::NotPositive));
        assert_eq!(compute_xmr_amount("0.00", 6_700_000_000), Err(AmountError::NotPositive));
    }

    #[test]
    fn fixed_rate_provider_returns_none_for_unknown_currency() {
        let provider = FixedRateProvider::new(std::collections::HashMap::from([("USD".to_string(), 6_700_000_000)]));
        assert_eq!(provider.piconero_per_unit("USD"), Some(6_700_000_000));
        assert_eq!(provider.piconero_per_unit("EUR"), None);
    }
}
