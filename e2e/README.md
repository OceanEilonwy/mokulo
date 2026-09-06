# Real stagenet end-to-end test

The actual test lives in Rust: [`../tests/e2e_stagenet.rs`](../tests/e2e_stagenet.rs),
run via `cargo test` like any other test in this crate. It drives the real
`moneropay_core` library - config, store, key custody, scanner, router; the same
pieces `main.rs` wires together - against a real public Monero **stagenet** node,
and pays the order it creates with a real (tiny) transaction constructed, signed,
and broadcast entirely in Rust (see [`../tests/support/mod.rs`](../tests/support/mod.rs),
built on the `monero-wallet` crate) from a wallet that was funded by a public
stagenet faucet. Nothing here is mocked, and nothing here needs an external wallet
process - the point is to prove the actual scanning, detection, and status-update
logic works against a real chain, not just a simulated one. This directory holds
the fixtures that test needs, plus a demo shop for manually eyeballing the same
flow through the actual embedded widget in a browser.

**The only external dependency is the public stagenet node itself** - no
wallet-rpc, no `monero-wallet-cli`, no other process. Sending the test payment
happens by directly scanning known transactions with the customer wallet's own
private keys, selecting real decoys, signing a real CLSAG + Bulletproofs+
transaction, and broadcasting it over the node's plain RPC - see the module doc
comment on `tests/support/mod.rs` for the full explanation and why it's safe to
trust that path's randomness/cryptography.

Following the same pattern as `daemon_rpc::live_node_tests` (`src/daemon_rpc.rs`),
the test is `#[ignore]`d so the default `cargo test` run stays hermetic and fast -
run it explicitly, from the repository root:

```bash
cargo test --test e2e_stagenet -- --ignored --nocapture
```

**This can take a few minutes.** Real decoy selection against this specific node
involves a large `get_output_distribution` fetch plus, on stagenet's comparatively
sparse RingCT output set, extra resample rounds to find enough *unlocked* decoys -
an observed full run took ~250s. See the timeout comment in
`tests/support/mod.rs::connect` for detail.

## Infrastructure used

- **Node**: `node.monerodevs.org:38089` (public stagenet node) - configured in
  `moneropay-stagenet.toml`'s `[monero_node.stagenet]`.
- **Faucet**: https://stagenet-faucet.xmr-tw.org/ - funded the customer wallet
  below. Funding txids are recorded in `stagenet-wallets.json`.
- **Wallets**: `stagenet-wallets.json` persists the keys for two wallets so the
  whole setup is reproducible without re-funding from the faucet every time:
  - `merchant` - the tenant's watch-only wallet, bootstrapped into
    `moneropay-stagenet.toml`. moneropay only ever needs its view key + spend
    public key (never the spend key), so that's all that's configured there.
  - `customer` - an ordinary wallet that received faucet funds and is used to
    *send* test payments to orders, via `private_spend_key`/`private_view_key`
    read directly by `tests/e2e_stagenet.rs`. Never given to moneropay - it plays
    the role of "the person paying an invoice." `known_txids` lists every
    transaction that has ever paid this wallet (the original faucet payouts, plus
    every test run's own tx, since its change output pays the wallet again) - the
    test scans all of these each run (skipping any not yet confirmed) and appends
    its own new tx here on success, so later runs automatically pick up earlier
    change without needing a fresh faucet payout every time.

  This file contains real (if worthless - stagenet has no exchange value)
  private keys. Treat it like any other credentials file. The test **writes back**
  to it (appending to `known_txids`) after a successful run - that's expected.

## One-time setup

Just `moneropay-core` built:

```bash
cargo build --manifest-path ../Cargo.toml
```

## Running the test

```bash
cargo test --test e2e_stagenet -- --ignored --nocapture
```

This builds the moneropay router in-process straight from `moneropay-stagenet.toml`
(via `tower::ServiceExt::oneshot` - no bound port, no separate `moneropay-core`
process needed), creates a real order against it, pays that order with a real
transaction sent from the customer wallet, then drives the real scanner
(`run_scan_tick`, the same function `main.rs`'s production loop calls on a timer)
and polls the order's status until it reports `paid` (or a terminal
confirming/overpaid state) - failing the test otherwise.

**(Optional) Watch it happen in a browser too.** The test above only proves the
library logic; to see the same flow through the actual server process and
embedded widget, start the server and demo shop separately:

```bash
# from e2e/, in one terminal:
../target/debug/moneropay-core moneropay-stagenet.toml
# prints a pk_... on first boot - note it

# in another terminal:
cd demo-shop && python3 -m http.server 8190
# then open http://127.0.0.1:8190/?endpoint=http://127.0.0.1:8180&pk=pk_...
# and click "Buy with Monero" - paying that order needs a separate real transfer,
# e.g. by adapting tests/support/mod.rs's StagenetSpendWallet
```

`moneropay.db*` (created alongside the config) is that server's tenant/order
database; delete it to start over with a fresh bootstrap.

## Why the config is tuned the way it is

- `confirmations_required = 1` and `zero_conf_max_xmr = "0.01"`: stagenet
  blocks land roughly every ~2 minutes, so requiring several confirmations
  would make the test spend most of its wall-clock time waiting on the chain
  instead of exercising moneropay's own detection logic. Every test payment
  here is well under 0.01 XMR, so it's covered entirely by 0-conf detection and
  resolves in seconds once broadcast. (This field is XMR-denominated, not
  fiat, despite the name it used to have - a real bug caught in the production
  config, see `docs/DESIGN.md` §13.)
- `USD = "0.0067"` in `[exchange_rate.rates]`: an arbitrary fixed rate (not a
  live market price) chosen so a human-readable fiat amount like `$0.05` maps
  to a genuinely tiny real payment (a few hundred thousand piconero), per the
  project's own constraint of only moving trivial amounts on this shared
  faucet-funded wallet.

## A note on running the test repeatedly

Monero requires 10 confirmations (~20 minutes on stagenet) before a received or
change output becomes spendable. `tests/support/mod.rs`'s `send` already accounts
for this (`spendable_now` filters by age, not just spent-status) and greedily
picks only as many outputs as needed - so as long as *some* output across
`known_txids` is old enough and unspent, a run succeeds without help. If every
known output is either too young or already spent, the test fails fast with a
clear message naming the customer address and the faucet URL, rather than hanging
or false-passing.

## Reproducing from scratch (new faucet funds)

If `stagenet-wallets.json`'s customer wallet ever runs dry (every `known_txids`
entry spent, and change too small/young to help):

1. Open https://stagenet-faucet.xmr-tw.org/ and send funds to
   `stagenet-wallets.json`'s existing `customer.address` (no need to generate a
   new wallet - the same address can receive any number of faucet payouts).
2. Add the faucet's txid to `customer.known_txids` in `stagenet-wallets.json`.
