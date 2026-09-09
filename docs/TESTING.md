# MoneroPay — Test Suite Document

Companion to [`DESIGN.md`](DESIGN.md). For each area: what to test, why it matters
enough to test deliberately (rather than relying on incidental coverage), and how to
implement it. Organized by component, in roughly the order a component would be built.

## 0. Testing Philosophy

- **Prefer real cryptographic primitives over mocks wherever feasible.** The
  `key_custody` tests already do this — they scan a real transaction, lifted
  byte-for-byte from `monero-rs`'s own test suite, against a real view pair, rather
  than asserting against a hand-rolled stub of what scanning "should" do. A mocked
  crypto layer can pass while the real math is wrong; a real fixture can't.
- **Mock only the one boundary that can't run in CI: `monerod` itself.** Everything
  behind `MoneroDaemonClient` (§DESIGN.md 7.1) gets a scripted fake for unit-level
  scanner/reorg tests. A separate, smaller integration tier runs against a real
  `monerod --regtest` for wiring-level confidence (§10).
- **Pure functions get exhaustive, table-driven tests.** The status-derivation
  function (§DESIGN.md 7.6) is the highest-value target for this: it's a pure function
  of a handful of inputs, every branch is enumerable, and it is the single source of
  truth for what a merchant and customer see.
- **Concurrency-sensitive components get stress tests, not just unit tests.** The
  writer actor's single-writer property and minor-index uniqueness are *assumptions*
  the rest of the system depends on — the risk category here is races, so the test
  has to actually create concurrency, not just call methods sequentially.
- **Security-relevant negative tests are not optional.** IDOR prevention, SSRF
  mitigation, and webhook signature verification each get dedicated adversarial tests,
  not incidental coverage from happy-path tests.

## 1. `KeyCustody` Boundary

Already implemented in `src/key_custody/plain.rs` (4 tests passing as of this
writing); listed here for completeness and to flag gaps.

| Test | Why | How | Status |
|---|---|---|---|
| Register → derive subaddress 0/0 → matches root view pair keys | Baseline correctness of the register/derive path | Compare `public_spend`/`public_view` against independently-derived values | **Done** |
| Register → remove → derive fails `UnknownWallet` | Handles must not outlive their wallet | Call `derive_subaddress` after `remove_wallet`, assert error variant | **Done** |
| Scan a real fixture transaction, known view pair → finds the one owned output with the right subaddress index and a nonzero decrypted amount | Proves the real RingCT amount-decryption + key-matching path works, not just that the trait compiles | `monero-rs`'s own `code_coverage_owned_tx_out` test vector, copied via script (never hand-retyped, to avoid transcription bugs) | **Done** |
| Repeated scans over an unchanged range rebuild the lookup table exactly once; a range change triggers exactly one more rebuild | Proves the caching optimization (§DESIGN.md 6.2.4) actually engages, not just that results stay correct | `#[cfg(test)]` atomic rebuild counter on `WalletEntry`, asserted after 3 same-range calls and 1 range-widening call | **Done** |
| Seal → unseal_and_register on a fresh backend instance ("simulated restart") derives the same address as before sealing | Proves the at-rest round trip actually survives a process restart, which is the entire reason `seal`/`unseal_and_register` exist | Two separate `PlainKeyCustody` instances; assert derived addresses match despite different `WalletHandle`s | **Done** |
| `WalletMaterial::from_hex`/`from_raw_bytes` reject malformed input (wrong length, non-hex) | Admin API will feed this directly from user-typed hex; must fail with `InvalidKeyMaterial`, not panic | Table of bad inputs (empty string, odd-length hex, 31/33 bytes, non-hex chars) | **Gap — add** |
| `scan_tx_outputs`/`derive_subaddress` on an unknown handle → `UnknownWallet`, not a panic | Defensive boundary — a caller bug (stale handle after restart) must degrade to an error, not a crash | Call each method with a handle from a *different* `PlainKeyCustody` instance | **Gap — add** |
| Concurrent scans across many wallets/handles complete without deadlock | The `RwLock`-per-registry + `Mutex`-per-wallet-cache combination is new; worth a direct concurrency smoke test | Spawn N tokio tasks calling `scan_tx_outputs` against a mix of shared and distinct handles; assert all complete within a timeout | **Gap — add** |
| `seal()` output is versioned by `key_custody_backend`, and `unseal_and_register` on mismatched bytes fails loudly | Prevents a future TEE backend from silently misinterpreting `PlainKeyCustody`-sealed bytes (or vice versa) after a backend migration | Feed `PlainKeyCustody::unseal_and_register` a byte string of the wrong length; assert `InvalidKeyMaterial`, not a garbage successful registration | **Gap — add** |

Testing note: `ZeroizeOnDrop` correctness (does the view key actually get scrubbed from
memory) is not practically assertable from safe Rust — trust the `zeroize` crate's own
test suite for that guarantee rather than trying to inspect freed memory. It's enough
to assert, once, that `WalletMaterial` implements `ZeroizeOnDrop` at compile time (a
trait-bound smoke test), not to try to prove it at runtime.

## 2. Order Status Derivation (§DESIGN.md 7.6)

**Why this gets disproportionate attention**: it is the one function every other
component (webhooks, the widget, the admin API) trusts without re-deriving, and it has
the most edge cases per line of any component in the system — multi-payment
interactions, the zero-conf ceiling, and expiry all intersect here.

Implement as table-driven (or `rstest`/`proptest`-parametrized) tests over
`(valid_payments, xmr_amount_piconero, confirmations_required, zero_conf_max_piconero,
now, expires_at) -> expected_status`:

| Scenario | Expected | Why it's worth a named case |
|---|---|---|
| No payments, before expiry | `pending` | Baseline |
| No payments, after expiry | `expired` | Time-boundary branch |
| One payment, amount < expected, before expiry, regardless of its confirmation depth | `partial` | Confirms "partial" is about *amount*, not confirmation depth — a fully-confirmed half-payment is still `partial`, not `confirming` |
| One payment, amount < expected, **after** expiry | `expired` | Deliberate: funds can sit at the address unresolved past the deadline; this is intentional given no auto-refund path exists, and needs to be locked in as a named case, not an accident |
| Total == expected, all contributing payments 0-conf, `zero_conf_max_piconero` is `NULL` | `unconfirmed` | The "seen but not trusted" branch — must not be conflated with `confirming` |
| Total == expected, all 0-conf, `zero_conf_max_piconero >= total` | `paid` | Merchant-configured 0-conf trust path |
| Total == expected, all 0-conf, `zero_conf_max_piconero < total` | `unconfirmed` | Ceiling correctly *not* applied when amount exceeds it |
| Total == expected, mixed 0-conf + on-chain payments, `min_conf < confirmations_required` | `confirming`, not `unconfirmed` | `all_zero_conf` must be false the instant *any* contributing row has a `block_height` |
| Total == expected, `min_conf == confirmations_required` exactly | `paid` | Off-by-one boundary — `>=`, not `>` |
| Total == expected, `min_conf == confirmations_required - 1` | `confirming` | The other side of the same boundary |
| Total > expected, confirmed | `overpaid` | |
| Total > expected, 0-conf, covered by the ceiling | `overpaid` | Combines the overpaid and 0-conf-trust branches — easy to get wrong if they're implemented as separate conditionals instead of one ladder |
| Two payments summing to exactly `expected`, one later voided, remainder < expected | `partial` (recomputed from the survivor alone) | **Direct regression test for the multi-transaction/double-spend scenario this design was corrected for** — see below |
| Two/three payments where voiding one still leaves the total ≥ expected | `paid` (unchanged) | Proves a double-spend that turns out to be financially irrelevant does not incorrectly downgrade the order |
| A voided payment's row is fully excluded from `total`/`min_conf`, not just zeroed | Guards against an implementation that filters late or double-counts | Assert directly against the SQL-level aggregate, not just the Rust-level derivation, if the recompute is partially expressed as a query |

**Independence test (critical, given this was the exact bug caught in design review)**:
construct a case where voiding a payment changes `status` and one where it does not,
and assert `double_spend_detected_at` is set **in both**, while `status` differs
appropriately. This is the direct executable version of "these are two axes, not one,"
and should be the canonical regression test protecting that decision going forward.

## 3. Chain Scanner & Reorg Detection

**Why this deserves more test investment than its size suggests**: reorgs are rare in
production, which means a bug here can go unnoticed for a long time and then surface
exactly when a merchant's money is on the line. This is the inverse of "test what
breaks often" — test this because it's high-consequence and low-frequency, which means
production usage will not shake the bugs out for you.

Requires a `FakeDaemonClient` (implements `MoneroDaemonClient`, §DESIGN.md 7.1) driven
by a small scripted timeline: `push_block(height, hash, txs)`,
`reorg_from(height, new_blocks)`, `set_mempool(txs)`, `set_key_image_status(image,
status)`. This makes every scenario below deterministic and fast, with no live node.

| Scenario | Why | How |
|---|---|---|
| Happy path: tx seen in mempool → included in a block → confirmations increase as height advances → reaches `paid` | Baseline wiring test for the scanner's own orchestration (as distinct from `KeyCustody`'s crypto correctness, already covered in §1) | `FakeDaemonClient` timeline; scanner-level test can stub the `KeyCustody` call itself if convenient, since this test is about orchestration, not crypto |
| Mempool poll idempotency: the same unconfirmed tx observed across many poll ticks produces exactly one `order_payments` row | The scanner polls every ~1s and *will* see the same tx repeatedly; this must be a no-op, not a growing pile of duplicate rows or a surfaced error | Feed the same tx to the scan-and-record path N times; assert row count stays 1 (relies on, and should explicitly exercise, `UNIQUE(txid, output_index)`) |
| Reorg where the tx reappears at a different height | Most common real-world reorg outcome; must not misreport as a problem | Script a `reorg_from` that includes the same tx in a different block; assert `block_height` updates, no incorrect status regression, no spurious double-spend event |
| Reorg where the tx falls back into the mempool | Second most common outcome | Script a reorg whose replacement blocks omit the tx but the mempool still has it; assert `block_height → NULL`, confirmations → 0, status recomputes (e.g. `paid → confirming`/`unconfirmed`) |
| Reorg where the tx vanishes and `is_key_image_spent` proves a different, confirmed transaction consumed the same inputs | The actual double-spend case | Script the vanish + a `set_key_image_status(image, SpentInBlockchain)` with a different txid; assert `voided_at` set, status recomputed, `double_spend_detected_at` stamped, `order.double_spend_detected` webhook enqueued |
| Reorg where the tx vanishes but `is_key_image_spent` reports unspent (still propagating) | **Safety property**: must never void on ambiguous evidence | Same vanish, but `set_key_image_status` reports unspent; assert the payment row is left alone (not voided), pending a later re-check |
| The exact two-transaction scenario from design review: one payment voided, the other intact | Direct regression test tying the scanner-level behavior to the status-function test in §2 | Two matched payments on one order; void one via the daemon-proof path above; assert the *order's* recomputed status and `double_spend_detected_at` match §2's expectations, exercised through the full scanner path this time, not just the pure function in isolation |
| A reorg is reported at its true fork point at every depth the window covers; one deeper is reported at the window's edge instead | This limitation is a deliberate design choice (§DESIGN.md 3, 7.5) — the test exists to keep it an intentional, documented boundary rather than something that silently regresses. Note the original phrasing here ("one deeper than the window is *not caught*") turned out to be wrong when actually exercised: a deeper reorg **is** detected, just at the wrong (too high) height, which is a materially different failure mode — payments below the window keep counting at heights that no longer exist | Loop one case per depth from 1 to the full window; then one case one block deeper, asserting the reported point is the window edge and that a payment below it is left untouched. **Done** (`a_reorg_is_detected_at_its_true_fork_point_at_every_depth_the_window_covers`, `a_reorg_deeper_than_the_window_is_reported_at_the_window_edge_and_leaves_older_payments_alone`) |
| `scanned_blocks` stays bounded in size over many simulated blocks | Resource/leak concern, not correctness — but the pruning that bounds it must never empty the window (an empty window reads as "never scanned" and re-seeds at the tip) | Advance the fake chain far past the configured window; assert the row count stays capped, then assert a reorg at the far edge of the configured depth is still both detectable and rewindable. **Done** (`the_scanned_block_window_stays_bounded_as_the_chain_grows`) |
| A zero-conf payment whose transaction leaves the mempool without being mined, because a conflicting transaction won | The one double-spend shape reorg detection structurally cannot see (no recorded block hash ever changes), and the one a merchant trusting `zero_conf_max_xmr` is actually exposed to | Record a mempool match, drop the transaction from the fake's pool, mine a conflicting transaction, mark the shared key images `SpentInBlockchain`; assert the void, the status retraction and the `order.double_spend_detected` event. Then the same script with the key images left unspent, asserting *no* void — a dropped or evicted transaction is not a double-spend. **Done** (`a_zero_conf_payment_double_spent_out_of_the_mempool_is_voided_with_no_reorg_involved`, `a_mempool_payment_that_merely_disappears_is_never_voided_on_that_evidence_alone`) |
| The tip trades places repeatedly (a block-withholding pool publishing in bursts), with one transaction moving in and out of the chain | The realistic on-the-wire shape of selfish mining, as opposed to one clean reorg — the property at risk is bookkeeping (one row, counted once), not detection | Several rounds of `reorg_from` alternating between two chains, two ticks each; assert one payment row, the latest agreed height, no double-spend flag, and the amount counted exactly once. **Done** (`rapidly_alternating_chain_tips_never_lose_or_double_count_a_payment`) |
| A different daemon, serving a divergent history, is swapped in mid-run | Answers "do we need per-daemon sync state?" — no: the stored `(height, hash)` window is re-validated against whoever answers now, so a swapped, rolled-back, eclipsed or lying node is the same case as a reorg and takes the same code path (§DESIGN.md 7.7) | Drive ticks against one `FakeDaemonClient`, then against a second with a different chain, then back; assert reconciliation and rewind each time. **Done** (`swapping_to_a_daemon_serving_a_different_chain_reconciles_exactly_like_a_reorg`) |
| A node that fails partway through a reconciliation pass, *after* a void has already committed | The one mid-tick failure whose damage is not self-healing: a voided row leaves both sweeps' input sets by construction and a terminal order is skipped by the per-tick recompute, so a deferred status update is lost permanently rather than retried | Two mempool payments, both proven double-spent, with the daemon failing on the second lookup; assert the first void's status change, total, and both webhook events all landed anyway. **Done** (`a_void_that_lands_before_the_node_fails_still_updates_the_order_it_belongs_to`) |
| A node lying about height, omitting or inventing mempool/block transactions, or reporting a height far below the recorded high-water mark | These are the trust-boundary cases (§DESIGN.md 7.7); the tests exist to state which are closed by construction and which are accepted, so a future change can't quietly move one across the line | One test per case, asserting the *actual* consequence rather than an aspiration: inflated height inflates confirmations (accepted), an invented transaction cannot become a payment (closed), an omitted one only delays detection (bounded), a lagging node changes nothing at all (closed). **Done** |

## 4. Chain Scanner Throughput / Active Watchlist

| Test | Why | How |
|---|---|---|
| `KeyCustody.scan_tx_outputs` is never invoked for a tenant with zero pending orders | This is the entire justification for the active-watchlist design (§DESIGN.md 7.3) — worth proving directly rather than trusting it by inspection | Wrap `KeyCustody` in a call-counting spy; register many tenants, give only one a pending order; assert the spy's call count attributes only to that tenant across several scan ticks |
| Randomized sequence of range changes causes a table rebuild exactly on each distinct range and never on a repeat | Generalizes the fixed rebuild-count test already in `plain.rs` (§1) beyond the two hand-picked cases | `proptest`-generated sequence of `(major_range, minor_range)` pairs with repeats interspersed; assert rebuild count equals the number of *distinct adjacent* range changes |

## 5. Multi-Tenancy & Auth (IDOR focus)

**Why dedicated adversarial tests, not just happy-path auth tests**: this exact bug
class (a path parameter usable for authorization alongside a separate token) was
caught during design review, not incidentally. The fix is structural (no `{id}` in
tenant-scoped routes), but the *row-level* version of the same rule
(`WHERE id = ? AND tenant_id = ?`) is a per-handler discipline that regressions can
reintroduce one handler at a time — this needs standing test coverage, not a one-time
audit.

| Test | Why | How |
|---|---|---|
| Tenant A's valid `sk_` + tenant B's real `payment_id` → 404, not tenant B's order | The one place a client-supplied identifier still exists within a tenant-scoped route; must never be sufficient on its own | Create orders under two tenants; request B's `payment_id` using A's token; assert 404 (not 403 — don't confirm the id even exists) |
| `pk_` alone, on any `/api/v1/admin/*` route | `pk_` must never be usable as authorization anywhere | Every admin route, called with a bearer value that's actually a `pk_`; assert rejected |
| A rotated `sk_` stops working immediately | Rotation must invalidate the old token, not just issue a new one alongside it | Rotate; retry a request with the pre-rotation token; assert rejected |
| A single-bit-flipped valid token is rejected | Confirms the real SHA-256 hash-compare path is being used rather than e.g. a prefix or length check | Flip one character of a known-valid `sk_`; assert rejected |
| `POST /api/v1/t/{pk}/orders` from an `Origin` not in that tenant's `allowed_origins` → rejected, even with a valid `pk_` | The origin check is application-layer and independent of the browser-enforced CORS header — must be tested directly, since a browser test can't prove a server-side guarantee | Send the request with a curl-equivalent (no real browser CORS involved) with a disallowed `Origin` header |
| Two tenants issued back-to-back never receive the same `pk_`/`sk_`, and a tenant's `sk_` is never recoverable via any `GET` | Basic credential hygiene | Direct assertions on creation responses and subsequent `GET`s |
| The local-admin CLI (`--rotate-secret`/`--show-tenant`/`--snippet`, `src/local_admin.rs`) never needs or accepts an `sk_`, resolves the target tenant from `--pk` or (if omitted) the single active tenant, and errors listing every `pk_` when more than one exists with none named | This is a deliberately different, weaker-gated auth boundary than §10's bearer-token API — justified only because it requires filesystem access to the box, which already implies more trust than any `sk_` could grant (DESIGN.md §4.1); the tests exist to keep that boundary from silently drifting (e.g. an accidental cross-tenant resolution) rather than to re-prove the HTTP-level rotation test above | Unit tests against a real `Store` with 0/1/2+ tenants; assert the right tenant (or the right error) every time, and that `show_tenant`'s output never includes key material |

## 6. Writer Actor & Concurrency Correctness

**Why stress tests specifically**: the single-writer design is a correctness
*assumption* everything else (minor-index uniqueness, idempotent payment recording)
relies on. The risk category is races, which sequential unit tests cannot exercise by
construction — these tests must actually generate concurrency.

| Test | Why | How |
|---|---|---|
| N concurrent order-creation requests for one tenant never allocate the same `minor_index` | Directly protects the "two customers never watch the same address" property (§DESIGN.md 8.2) | Spawn N (e.g. 100+) concurrent create-order calls against a real writer actor backed by a temp-file or in-memory-with-shared-cache SQLite; collect all issued `minor_index` values; assert no duplicates. This should hold even if it's also backstopped by `UNIQUE(tenant_id, minor_index)` — the test should assert zero constraint-violation retries under normal load, not just eventual correctness through a retry loop |
| N concurrent duplicate match-events (simulating the scanner double-reporting one output across ticks) resolve to exactly one `order_payments` row | Mirrors §3's idempotency test but specifically stresses the writer's handling of the `UNIQUE(txid, output_index)` conflict under real concurrency, not sequential calls | Fire the same match event from multiple concurrent tasks; assert one row, and that the "losing" writes fail closed (no error surfaced to a client) rather than corrupting `amount_received_piconero` via a lost update |
| A long-running write transaction never blocks a concurrent read | The entire justification for splitting the read pool from the writer (§DESIGN.md 9) | Hold a writer-actor transaction open deliberately (e.g. via a test hook); issue a concurrent read-pool query; assert it returns promptly rather than waiting on the writer |
| An interrupted process (simulated by killing mid-write and restarting against the same DB file) leaves a consistent schema | WAL crash-recovery is a SQLite guarantee, but this system depends on it heavily enough to deserve a direct regression test rather than trusting it by reputation | Kill the process (or the connection) mid-transaction in a controlled way; reopen the same database file; assert the schema and existing rows are intact and queryable |

## 7. Webhook Delivery

| Test | Why | How |
|---|---|---|
| HMAC signature matches an independently-computed value for a fixed `(secret, payload)` test vector | Merchants implement verification against the documented scheme; a fixed vector lets them (and this test suite) cross-check the exact same computation | Hardcode a `(secret, payload, expected_signature)` triple in the test; recompute and compare bit-for-bit — this triple should also appear in end-user documentation |
| A failing endpoint (mock server returning 500) increments `attempt_count` and pushes `next_attempt_at` out on a backoff schedule; a later 2xx sets `delivered_at` and stops retries | Core reliability contract | Local mock HTTP server (e.g. `wiremock`) scripted to fail N times then succeed; drive the delivery worker's claim-and-attempt loop directly rather than through a real clock/sleep |
| A webhook URL resolving to a loopback/private/link-local address is rejected at **both** registration and delivery time | SSRF is a real vector here (§DESIGN.md 11) — the "at both times" phrasing matters because DNS can change between registration and delivery, so a registration-time-only check is insufficient | Register a webhook with a public-looking hostname whose DNS is then changed (or stub the resolver) to a private IP before delivery; assert the delivery is refused, not just the registration |
| A webhook target that issues an HTTP redirect to a private address is not followed | Same SSRF concern, redirect-based bypass specifically | Mock server responding with a 3xx to a private IP; assert the delivery worker does not follow it |
| A status transition fires exactly one `order.<status>` event; an independent double-spend void fires exactly one `order.double_spend_detected` event; a void that also changes status fires both | Direct test of the two-event-family design (§DESIGN.md 11) — this is the same distinction §2's "independence test" checks at the status-function level, checked here at the delivery-enqueueing level | Drive each scenario through the writer actor; assert the exact multiset of `webhook_deliveries.event_type` rows created |
| A duplicate delivery (simulated lost-ack) is accepted as an expected, documented characteristic, not silently deduped by hidden logic | The at-least-once contract must actually hold, not just be claimed in docs | Simulate an ack loss (client receives 2xx, worker doesn't observe it before a retry fires); assert two deliveries occur, i.e. that this isn't secretly exactly-once |

## 8. DDoS Protections

| Test | Why | How |
|---|---|---|
| Per-IP rate limit trips after the configured request count within the window, and resets after the window elapses | Core mechanism correctness | Drive requests past the configured limit from one simulated source IP; assert rejection, then advance time (or wait out a short test-configured window) and assert requests succeed again |
| An oversized request body is rejected before JSON parsing | Defends against a cheap way to waste CPU on parsing before validation | Send a body larger than `max_body_bytes`; assert rejection and that no parse work occurred (e.g. via a spy/log assertion, if feasible) |
| A correct proof-of-work solution is accepted; an insufficient-difficulty one is rejected; a replayed (already-used) nonce is rejected | The PoW fallback needs its own correctness tests, not just "it's there" | Construct solutions at, below, and re-using a prior challenge's difficulty/nonce; assert accept/reject/reject respectively |
| Global concurrency cap: requests beyond the configured limit queue or reject rather than spawning unbounded tasks | Directly tests the semaphore's presence, not just that requests eventually succeed | Drive many concurrent slow-handler requests; assert the number of simultaneously in-flight requests never exceeds the configured cap |

## 9. Schema / Migration

Automates what was manually verified live against `sqlite3` during design (§DESIGN.md
8) — that verification should not be the only time these constraints get exercised.

| Test | Why | How |
|---|---|---|
| `CHECK (status IN (...))` rejects any value outside the seven valid ones | Regression protection — this constraint was specifically tightened once already (removing `'double_spent'`) during design | Attempt an insert/update with an invalid status string; assert the DB rejects it |
| `UNIQUE(tenant_id, minor_index)` rejects double-issuance | Backstop for the writer-actor allocation logic in §6 | Attempt to insert two orders with the same `(tenant_id, minor_index)` |
| `UNIQUE(txid, output_index)` makes duplicate payment recording a constraint violation the application layer turns into a no-op | Backstop for §3/§6's idempotency tests | Attempt duplicate insert directly against the table, independent of any application code, to isolate the schema-level guarantee from the app-level handling of it |
| Foreign keys reject an order/payment/webhook referencing a nonexistent tenant/order | Prevents orphaned rows | Attempt inserts with a bogus parent id with `PRAGMA foreign_keys = ON` |
| The migration applies cleanly to a fresh database | Baseline — this exact check was run manually multiple times during design and should not regress to a manual step | Apply `migrations/0001_init.sql` to a fresh temp file in a test, assert success |

## 10. Integration / End-to-End

**Why a separate tier from §3's mocked-daemon tests**: unit-level correctness against
a scripted fake doesn't prove the pieces compose correctly against a *real* Monero
node's actual RPC responses (real serialization quirks, real field-naming, real error
shapes). Conversely, a real node can't practically simulate a reorg on demand, so this
tier is for wiring confidence, not for the reorg scenarios in §3.

- Run against Monero's own `--regtest` mode in CI: fast, free, deterministic block
  timing (blocks are mined on demand rather than waited for).
- At least one full-lifecycle smoke test: create an order, fund it from a regtest
  wallet, mine blocks, observe `status` transitions through both the polling API and
  the SSE stream, confirm the real `MoneroDaemonClient` implementation's RPC calls
  parse correctly against a real node's real responses.
- Explicitly out of scope for this tier: reorg/double-spend scenarios (regtest doesn't
  produce realistic reorg conditions since the test controls the chain directly) —
  those stay in §3 against the scripted fake.
- Implemented today against a real public **stagenet** node rather than a local
  `--regtest` instance (simpler to stand up, no local `monerod` build required):
  [`tests/e2e_stagenet.rs`](../tests/e2e_stagenet.rs) drives the real
  config → store → key custody → scanner → router pipeline in-process and pays the
  order it creates with a genuine transaction constructed, signed, and broadcast
  entirely in Rust (`tests/support/mod.rs`, no external wallet process). `#[ignore]`d
  like `daemon_rpc::live_node_tests`, run explicitly with
  `cargo test --test e2e_stagenet -- --ignored --nocapture`; see
  [`e2e/README.md`](../e2e/README.md) for detail - the public stagenet node is the
  only external dependency.

## 11. Client Library / Widget (browser-level)

**Why this tier exists separately**: it's the one surface with no compiler/type
system backing it (plain JS on an arbitrary third-party static site) and the one place
cross-origin behavior needs to be proven end-to-end rather than assumed from the
server-side tests in §5.

| Test | Why | How |
|---|---|---|
| Order creation from a disallowed origin is rejected | Confirms the *server-side* enforcement (§5) is what's actually protecting this, not just browser CORS, which is a client-side courtesy an attacker's own script simply doesn't have to honor | Drive a real browser context (or headless equivalent) from a page served on a non-allowed origin; assert the request fails, then separately confirm via §5 that this isn't only a client-side illusion |
| `postMessage` payload shape is stable across a status change | The merchant's own page depends on this contract | Drive a checkout through a status transition in a test harness; assert the received message matches the documented shape |
| SSE reconnects after a dropped connection without duplicating already-seen status updates | Real-world flakiness (router Wi-Fi, mobile customers) makes this a realistic scenario, not a hypothetical one | Simulate a connection drop mid-stream; assert reconnection occurs and no duplicate/out-of-order UI state results |
| The double-spend explanation banner renders independently of the current status label | Direct UI-level regression test for the two-axis design (§2, §DESIGN.md 7.6) — this is the customer-facing consequence of that decision and deserves its own check, not just the data-layer test | Render the widget against a fixture order with `double_spend_detected_at` set and `status = 'paid'`; assert both the "paid" state and the warning banner are visible simultaneously |

## 12. Non-Functional / Resource

These are advisory, not hard gates — resource measurements are inherently noisier on
shared CI hardware than correctness assertions, so treat a failure as a signal to
investigate rather than an automatic build break.

| Test | Why | How |
|---|---|---|
| Binary size stays within a tracked budget | Directly protects the "as small as possible" goal (§DESIGN.md 2) from silent dependency creep | CI step comparing the built binary's size against a checked-in baseline, failing (or warning) past a configured delta |
| Idle CPU/memory footprint stays within a rough budget | Directly protects "minimal resource use, doesn't compete with the router's other duties" | Run the server idle for a fixed period under a resource-measuring wrapper; assert RSS and CPU time stay under a generous threshold — treat as advisory given shared-CI noise |
