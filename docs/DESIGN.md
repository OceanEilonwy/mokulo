# MoneroPay — Design Document

Status: pre-implementation design. Everything here except the `key_custody` module
(`src/key_custody/`) and the schema (`migrations/0001_init.sql`) is specification, not
code. Where those two exist already, this document describes them at the level of
"what an engineer needs to know to use or extend them," not a restatement of their
source — read the code itself for exact signatures when in doubt.

## 1. Purpose

A self-hostable Monero payment gateway for static sites with no backend of their own
(the motivating case: a site on GitHub Pages). The site embeds a small client library
that talks, via `fetch`, to a separately-hosted payment service — typically running on
the merchant's own home router — which renders a checkout UI (iframed or linked
directly), tracks orders, watches the chain for payment, and notifies the merchant via
webhook.

It is designed from day one to also work as a multi-tenant, community-hosted instance
serving many unrelated merchants, without that being a different code path — a
self-hosted deployment is simply a deployment with one tenant.

## 2. Goals

- **Trivial to set up.** One config file, one binary, sensible defaults. No database
  server, no sidecar processes (notably: no `monero-wallet-rpc`).
- **Single static executable, no dynamic libraries.** Must build for
  `*-unknown-linux-musl` and run on modest ARM or x86 router-class hardware.
- **Minimal resource use.** The host is usually also doing routing, DHCP, Wi-Fi, and
  possibly other services; this should not compete meaningfully for CPU or memory.
- **Fast 0-conf detection.** Mempool visibility within about a second of broadcast,
  without pulling in a C dependency (ZMQ) to get it.
- **Multi-tenant capable, single-tenant simple.** The tenant abstraction must not add
  ceremony to the one-merchant case.
- **Never able to move funds.** Every wallet this system knows about is watch-only.
  There is no code path, in any configuration, that holds or uses a private spend key.
- **DDoS-resistant by default**, since several endpoints are necessarily unauthenticated
  (a static site has nowhere to keep a secret).
- **Reusable and open-sourceable.** Design boundaries (`KeyCustody` chief among them)
  so a hosted, security-hardened deployment is a plugged-in backend, not a fork.

## 3. Non-Goals (v1)

Explicitly out of scope, and not accidentally so — call these out if a change request
would reintroduce them:

- **Automated refunds or any outbound Monero transaction.** No spend key exists
  anywhere in this system to make one possible. A refund address is recorded for the
  merchant to action manually, forever, not just in v1.
- **ZMQ-based mempool push notifications.** Requires `libzmq`, a C library, in tension
  with "no dynamic libraries" and "as small as possible." Mempool polling (~1s) is the
  v1 mechanism; ZMQ is a possible opt-in feature-flagged enhancement later, never a
  default dependency.
- **Subaddress index recycling.** Indices are allocated monotonically per tenant and
  never reused. This is a deliberate simplicity/privacy tradeoff (see §8.2); recycling
  is a scaling optimization for a high-volume tenant, not a v1 concern.
- **A platform/operator admin tier** for the hosted multi-tenant case (an operator
  looking at *any* tenant's data for support purposes). Only tenant self-service auth
  exists in v1. This is a materially different, higher-privilege concept and should get
  its own explicit, clearly-named route namespace when it's actually built — never a
  quiet override on tenant-scoped routes.
- **Gated/invite-only tenant creation** on a hosted instance. v1 tenant creation is
  open, protected only by the standard DDoS layer (§12).
- **In-place webhook secret rotation.** Rotate via delete-and-recreate.
- **Defending against reorgs deeper than a configured window.** The window only needs
  to comfortably exceed `confirmations_required`; deeper reorgs are a statement about
  Monero consensus economics, not something application code should try to override.
- **TEE-backed `KeyCustody` implementation.** The boundary is built to make this a
  drop-in backend later (§6), but v1 ships only the plaintext `PlainKeyCustody`.
- **Generating Monero wallets on the operator's behalf.** `--init` (§4.1) walks a
  self-hoster through *entering* their existing wallet's view/spend keys, never
  through creating a new wallet — this project has no reason to touch spend-key
  material, and a self-hoster is assumed to already have (or know how to make,
  with `monero-wallet-cli` or any other wallet software) the wallet they want to
  receive into.

## 4. Deployment Model

Both of the following are the same binary, same schema, same code path — the only
difference is how many rows exist in `tenants`:

- **Self-hosted, single-tenant.** One `tenants` row, created once at first boot from
  the TOML config's `[wallet]` section (an internal call into the same logic
  `POST /api/v1/admin/tenants` uses — not necessarily an HTTP round-trip against
  itself).
- **Hosted, multi-tenant.** Tenants are created at runtime via the admin API, each
  bringing their own watch-only wallet. New tenants must be scannable without a
  restart (§7.3).

### 4.1 Onboarding tooling

`moneropay-core --init` (optionally `--stagenet`/`--testnet`, `--config <path>`) is
an interactive wizard that produces or merges `moneropay.toml` — curated node
choice with a live "test this connection now" check, the `[wallet]` bootstrap
walked through field by field (or, on a re-run against an existing bootstrap,
offered as keep-as-is / add an allowed origin / replace entirely), and a rendered
file with every setting present, active or commented with its default. It
deliberately does not generate wallet key material — a self-hoster brings their
own existing wallet (§3, non-goals).

Three further flags (`--rotate-secret`, `--show-tenant`, `--snippet`, each taking
`--config` and, for a hosted instance with more than one tenant, `--pk`) operate
directly on the local SQLite file rather than through the HTTP admin API in §10 —
justified by the same reasoning as §6.3's local-file `PlainKeyCustody`: filesystem
access to the box already implies more trust than any `sk_` could grant, and this
is a single-operator, self-hosted tool, not a service with a separate admin role
to keep out. `--snippet` in particular exists to close the onboarding gap of
turning a freshly bootstrapped tenant into a pasteable "Pay with Monero" button —
it prints a ready-to-embed HTML/JS block pre-filled with the tenant's real `pk_`
and an operator-supplied endpoint URL (never derived from `[server].bind`, which
says nothing about the externally-reachable URL once a reverse proxy sits in
front of it).

The database always lives next to whichever config file was actually used
(`moneropay.db` in the config's own directory, not the process's CWD) so these
commands, and the server itself, reliably agree on which file they mean
regardless of the directory `moneropay-core` happens to be launched from.

## 5. High-Level Architecture

```
 ┌────────────────────┐   fetch/SSE    ┌──────────────────────────────────────────┐
 │ Static site (GH     │───────────────▶│ Payment service (single Rust binary)      │
 │ Pages) + client lib  │                │                                          │
 └────────────────────┘                │  ┌────────────┐   ┌──────────────────┐    │
                                        │  │ HTTP API   │   │ Chain Scanner     │    │
                                        │  │ (axum/tower│   │ - mempool poll    │    │
                                        │  │ on tokio)  │   │ - block poll      │    │
                                        │  └─────┬──────┘   │ - reorg detector  │    │
                                        │        │           └────────┬─────────┘    │
                                        │        │  mpsc               │ mpsc        │
                                        │        ▼                     ▼             │
                                        │  ┌──────────────────────────────────┐      │
                                        │  │        Writer Actor (single)      │      │
                                        │  │  owns the one SQLite write conn   │      │
                                        │  └────────────────┬──────────────────┘      │
                                        │                   │                         │
                                        │        ┌──────────┴───────────┐             │
                                        │        ▼                      ▼             │
                                        │  ┌───────────┐         ┌─────────────┐      │
                                        │  │ SQLite     │◀───────│ Read pool    │      │
                                        │  │ (WAL)      │  reads │ (HTTP GETs)  │      │
                                        │  └───────────┘         └─────────────┘      │
                                        │                                              │
                                        │  ┌────────────────┐   ┌──────────────────┐  │
                                        │  │ KeyCustody      │   │ Webhook Delivery  │  │
                                        │  │ (PlainKeyCustody)│   │ Worker            │  │
                                        │  └────────────────┘   └──────────────────┘  │
                                        └──────────────┬───────────────────────────────┘
                                                        │ RPC (rustls)
                                                        ▼
                                                  monerod (user's node)
```

Components, each with one clear owner of state:

| Component | Owns | Never does |
|---|---|---|
| HTTP API layer | Request/response, auth resolution, CORS/Origin checks | Direct SQLite writes; talks to the writer actor and read pool only |
| `KeyCustody` | Private view keys, scan/derive crypto | Anything involving a spend key; never returns key material to a caller |
| Chain Scanner | Polling monerod, matching outputs, reorg detection | SQLite access — sends match/void events to the writer actor |
| Writer Actor | The single SQLite write connection; all mutations | Outbound HTTP (webhooks go through the delivery worker) |
| Read pool | Pooled read-only SQLite connections (WAL) | Any write |
| Webhook Delivery Worker | Outbound HTTP to merchant endpoints | Order/tenant state mutation beyond its own delivery-log rows |

## 6. The `KeyCustody` Boundary

**Status: implemented** (`src/key_custody/`). This section describes its role and
contract; see the module doc comments for full rationale.

### 6.1 Why it exists

Every wallet in this system is watch-only (private view key + public spend key only),
so the worst outcome of a compromise is loss of *payment-visibility privacy* for
however many tenants share that key material — never loss of funds, since no code path
anywhere holds a spend key. `KeyCustody` exists to make *where* that view key material
physically lives, and who can read it while it's in use, a swappable implementation
detail rather than something baked into the scanner or the HTTP layer.

- **Self-hosted single-tenant**: a host-level compromise already means "the attacker
  owns the one wallet on the box" regardless of what `KeyCustody` does — so the
  reference `PlainKeyCustody` backend (plaintext, in-process memory, no isolation) is a
  fully appropriate default, not a placeholder to feel bad about.
- **Hosted multi-tenant**: a host-level compromise (rogue admin, compromised
  hypervisor, remote exploit) would otherwise expose *every* tenant's view key at once.
  This is the scenario a hardware-backed implementation (AWS Nitro Enclaves or AMD
  SEV-SNP preferred; SGX specifically is a poor fit because secret-scalar EC
  multiplication — exactly what scanning does — is precisely what SGX's published
  side-channel attacks target) is meant to close, by keeping the key encrypted in
  memory even from a host process with root.

### 6.2 Contract

```rust
pub struct WalletHandle(/* opaque */);           // Copy, Eq, Hash — safe to store/log
pub struct WalletMaterial { /* view key + public spend key, ZeroizeOnDrop */ }
pub struct MatchedOutput { output_index, subaddress_index, amount_piconero: Option<u64> }
pub enum KeyCustodyError { UnknownWallet, InvalidKeyMaterial(String),
                           BackendUnavailable(String), ScanFailed(String) }

#[async_trait]
pub trait KeyCustody: Send + Sync {
    async fn register_wallet(&self, material: WalletMaterial) -> Result<WalletHandle, KeyCustodyError>;
    async fn remove_wallet(&self, handle: WalletHandle) -> Result<(), KeyCustodyError>;
    async fn seal(&self, material: &WalletMaterial) -> Result<Vec<u8>, KeyCustodyError>;
    async fn unseal_and_register(&self, sealed: &[u8]) -> Result<WalletHandle, KeyCustodyError>;
    async fn derive_subaddress(&self, handle: WalletHandle, index: SubaddressIndex, network: Network)
        -> Result<Address, KeyCustodyError>;
    async fn scan_tx_outputs(&self, handle: WalletHandle, tx: &monero::Transaction,
        major_range: Range<u32>, minor_range: Range<u32>) -> Result<Vec<MatchedOutput>, KeyCustodyError>;
}
```

Invariants every implementation (including future ones) must uphold:

1. `WalletMaterial` passed into `register_wallet` must not be retained anywhere the
   caller can reach it again — the only thing that comes back is an opaque handle.
2. `seal`/`unseal_and_register` are the *only* sanctioned way key material crosses the
   at-rest boundary (the `tenants.sealed_key_material` column). `PlainKeyCustody` seals
   to plain bytes (no encryption — consistent with its everywhere-else stance); a
   TEE-backed implementation should seal to something only it can unseal, so a stolen
   database file alone is insufficient even though the same backend keeps keys in the
   clear *while scanning*. At-rest protection and in-use protection are separate
   concerns this pair exists specifically to decouple.
3. `derive_subaddress` requires the private view key internally (subaddress spend-key
   derivation is `S' = S + Hs(v || index)·G`), which is why address issuance goes
   through this boundary and not through the order-creation code path directly.
4. **Cost model**: `scan_tx_outputs`/`derive_subaddress` cost is `O(range size)` scalar
   multiplications *unless the implementation caches the per-range lookup table*, since
   the underlying primitive derives every candidate spend key across the range up
   front. `PlainKeyCustody` caches this per wallet, rebuilding only when the requested
   `(major_range, minor_range)` changes — a tenant with a stable set of pending orders
   pays that cost once, not once per transaction scanned. Any other implementation
   should assume the same and cache accordingly; this cost is a property of Monero's
   stealth-address design, not something the trait tries to hide from callers.
5. Key images (used for double-spend detection, §7.5) are **not** part of this
   boundary — they're public data readable directly from a transaction's inputs,
   unrelated to any wallet's keys, and the chain scanner reads them directly.

### 6.3 `PlainKeyCustody`

The only implementation in v1. In-process `RwLock<HashMap<WalletHandle, WalletEntry>>`,
where `WalletEntry` holds the `ViewPair` plus a `Mutex<Option<CachedTable>>` for the
per-range table cache described above. No encryption at rest, no process isolation.

## 7. Chain Scanning & Payment Detection

### 7.1 `MoneroDaemonClient` (new component, not yet implemented)

A trait wrapping the raw calls the scanner needs against `monerod`, so the scanner's
own logic — especially reorg handling — can be tested against a scripted fake instead
of a live node:

```rust
#[async_trait]
pub trait MoneroDaemonClient: Send + Sync {
    async fn get_height(&self) -> Result<u64, DaemonError>;
    async fn get_block_hash(&self, height: u64) -> Result<String, DaemonError>;
    async fn get_block_transactions(&self, height: u64) -> Result<Vec<monero::Transaction>, DaemonError>;
    async fn get_mempool_transactions(&self) -> Result<Vec<monero::Transaction>, DaemonError>;
    async fn is_key_image_spent(&self, key_images: &[String]) -> Result<Vec<KeyImageStatus>, DaemonError>;
}
```

The real implementation talks to `monerod`'s JSON-RPC and plain-HTTP RPC endpoints over
`reqwest` + `rustls` (never OpenSSL, to keep the static-binary goal intact). `ssl`,
`host`, `port` from `[monero_node]` config select the connection.

### 7.2 0-conf and confirmed detection

- **Mempool**: poll `get_mempool_transactions` on a fixed interval (config
  `mempool_poll_interval_ms`, default ~1000ms). Every returned transaction is run
  through `scan_tx_outputs` for every tenant currently on the active watchlist (§7.3).
- **Blocks**: poll `get_height`; on increase, fetch and scan each new block's
  transactions the same way, and record `(height, block_hash)` into `scanned_blocks`.
- A matched output becomes (or updates) one `order_payments` row, sent to the writer
  actor as a message, never written directly by a scan worker.

### 7.3 Active watchlist

Scanning cost is inherently per-`(tx, tenant)` — Monero's stealth addresses require a
scalar multiplication per candidate view key, unlike Bitcoin's hash-lookupable
addresses. The overwhelming majority of registered tenants have no pending order at any
given moment, so the scanner must not pay that cost for them:

- An in-memory map, `Arc<RwLock<HashMap<TenantId, (WalletHandle, Range<u32>)>>>` (the
  "watchlist"), holds only tenants with at least one non-terminal order.
- The writer actor adds/removes a tenant from this map the instant an order becomes
  non-terminal / reaches a terminal state — no polling, no DB query per tx.
- On boot, every non-disabled tenant's `sealed_key_material` is passed through
  `unseal_and_register` to obtain a fresh `WalletHandle` for this process's lifetime
  (`PlainKeyCustody`'s registry is in-memory-only and does not survive a restart); the
  watchlist itself is then populated from `orders WHERE status NOT IN (...)` per
  tenant.
- The range per tenant is `0..next_minor_index` (§8.2) — this only grows over a
  tenant's lifetime in v1, which is acceptable given the `KeyCustody` table cache makes
  it a one-time cost per *new order*, not per transaction scanned.

### 7.4 Scan worker pool

Matching is CPU-bound (elliptic-curve scalar multiplication) and must never run inline
on the tokio runtime's async worker threads, or it stalls every other in-flight
request for its duration. A small, explicitly-bounded pool (sized to leave cores free
for the router's other duties, e.g. `num_cpus - 1`, minimum 1, configurable) fans
`(tx, active_tenant)` pairs out and sends results to the writer actor over a channel —
pool workers never touch SQLite directly (§9).

### 7.5 Reorg and double-spend detection

Motivation: real Monero mining-pool reorgs (of the kind seen from large hashrate
concentrations) can revert blocks a merchant may already have treated as confirmed.
This must be detected and reported, never silently ignored, and never something this
service attempts to prevent (that's a Monero-consensus question, not an application
one) — only to *notice and report*.

**Detecting a reorg**: for every scanned block, compare the hash `monerod` now reports
for that height against what's stored in `scanned_blocks`. A mismatch means everything
from that height up must be re-evaluated. The window pruned into `scanned_blocks` only
needs to be modestly deeper than `confirmations_required` (config
`reorg_check_depth`), not unbounded.

**Re-evaluating an affected `order_payments` row** (whose `block_height` falls in the
reorged range):

1. Tx reappears in a later/different block → update `block_height`; no status
   implication beyond a confirmation-count recompute.
2. Tx reappears in the mempool → `block_height = NULL`; falls back to unconfirmed.
3. Tx is nowhere (mempool or any block) → **ambiguous** until proven otherwise: call
   `is_key_image_spent` on the key images captured for that row at match time
   (`order_payments.key_images_json` — plain public data read directly from
   `tx.prefix.inputs`, entirely outside `KeyCustody`). Never void a payment on this
   ambiguous evidence alone — only on an affirmative "spent in blockchain by a
   different txid" result. Otherwise: still propagating, re-check later.

**On confirmed double-spend**: set `order_payments.voided_at`, recompute the owning
order's `status` (§7.6) and `amount_received_piconero` from the remaining non-voided
rows, stamp `orders.double_spend_detected_at` if not already set, enqueue an
`order.double_spend_detected` webhook (independent of whatever `order.<status>`
webhook, if any, results from the recompute — see §11).

All of that is **one transaction** (`scanner::void_and_notify`), not a void followed
by bookkeeping. A void is a committed write whose consequences cannot be re-derived
later: the voided row is excluded from every subsequent reconciliation input set by
construction, and an order in a terminal status is skipped by the per-tick recompute —
which is precisely the state that matters here, since the merchant has already been
told it was paid. Deferring the recompute to the end of the pass meant one unreachable
node partway through left an order permanently reading `paid` for money that had been
double-spent, with no event ever sent.

**Double-spends that involve no reorg at all**: reorg detection is triggered by a
stored block hash ceasing to match, which by construction only ever fires for a
payment that was *mined*. The textbook attack on a merchant watching the mempool
never gets that far: broadcast transaction A so the merchant's node sees it (with a
`zero_conf_max_xmr` ceiling configured, the order reads `paid` immediately — that is
what the setting is for), then get transaction B, spending the same inputs, mined
instead. A is never mined, no recorded block hash ever changes, and the payment would
otherwise sit at `block_height IS NULL` forever, counting in full towards an order
nobody paid.

So every tick also sweeps the payments that are still mempool-only
(`scanner::check_vanished_mempool_payments`). A payment whose transaction is still in
the pool snapshot the tick already fetched costs nothing; one mined this tick has had
its height written by the block scan before the sweep runs. Only a transaction that
has genuinely left the pool without being mined is looked up, and it is resolved by
exactly the evidence rules above: re-located if it turns out to be in a block, voided
only on an affirmative `SpentInBlockchain`, and otherwise left alone. That last case
is not rare or hostile — Monero has no replace-by-fee, but a transaction can still
expire out of a pool (`CRYPTONOTE_MEMPOOL_TX_LIVETIME`, three days), be dropped under
memory pressure, or simply never propagate — and "the customer's transaction is gone
from this node's pool" never proves it will not be mined later.

**Reorg depth is a configuration decision, not a code one.** `reorg_check_depth`
bounds what can be reconciled at all: a reorg whose fork point falls below the window
is still *detected* (every stored hash in the window mismatches, so the window's lower
edge is reported as the reorg point), but the payments orphaned below it are never
re-evaluated and the replacement chain's blocks below it are never rescanned. The
default (20) was chosen when Monero reorgs were single-block events. Monero mainnet
has since produced an 18-block reorg (September 2025, during the Qubic mining
campaign), and at least one major exchange responded by requiring 720 confirmations on
XMR deposits. A deployment accepting meaningful value should set both
`confirmations_required` and `reorg_check_depth` against that reality rather than
against the defaults.

### 7.6 Order status: a pure, always-recomputed function

This is the single source of truth for `orders.status`, called after **every**
mutation to `order_payments` (new match, reorg moves a height, reorg voids a row) —
never patched incrementally per event type. Treating a double-spend as "the order's
new status" (rather than an orthogonal fact) was an earlier design mistake, caught by
walking through a two-transaction example where only one of two contributing payments
gets voided — see §7.5 and the schema comment on `orders.double_spend_detected_at` for
why the two are kept separate.

```
valid    = order_payments rows for this order WHERE voided_at IS NULL
total    = SUM(valid.amount_piconero)
min_conf = MIN(confirmations of each row in valid)   -- an unconfirmed row contributes 0
all_zero_conf = every row in valid has block_height IS NULL

if total >= xmr_amount_piconero:
    if min_conf >= confirmations_required:
        return total > xmr_amount_piconero ? overpaid : paid
    elif zero_conf_max_piconero is not null
         and total <= zero_conf_max_piconero:
        return total > xmr_amount_piconero ? overpaid : paid   # merchant-configured 0-conf trust
        # Deliberately NOT also gated on all_zero_conf. The ceiling waives the
        # confirmation requirement for small totals; adding `and all_zero_conf`
        # withdrew that waiver the moment the tx was mined, so an order under the
        # ceiling went paid -> confirming -> paid as an ordinary block arrived, with
        # no reorg involved. That both retracts an order.paid the merchant may have
        # shipped against and re-announces the later `paid` under a fresh event_id
        # (i.e. as a genuine second transition, not a redelivery). A mined payment
        # strictly dominates the mempool sighting already being trusted, so the
        # ceiling alone is the correct condition and keeps the ladder monotone in
        # evidence.
    elif all_zero_conf:
        return unconfirmed   # full amount seen, mempool only, not (yet) trusted
    else:
        return confirming    # at least one payment on-chain, not enough confirmations yet
else:
    if now() > expires_at:
        return expired       # even a partial payment past the deadline surfaces as expired;
                              # the funds still exist at the address and require manual
                              # merchant handling — no automated refund path exists (§3)
    elif total == 0:
        return pending
    else:
        return partial
```

`double_spend_detected_at` is never read by this function and never written by it — it
is set exactly once (first occurrence) by the reorg-handling path in §7.5 and otherwise
left alone, including when `status` later recovers to `paid` via other contributing
transactions.

### 7.7 What the scanner takes on trust from its node

The scanner is a *client* of one configured `monerod` per network (`main.rs` builds a
`HashMap<Network, Arc<dyn MoneroDaemonClient>>`; there is no pool, no quorum, and no
second opinion). It validates no proof of work, no difficulty, no block timestamps and
no transaction signatures — that is the node's job, and duplicating it would mean
building a second Monero implementation inside a payment gateway. What follows is
therefore the deliberate trust boundary, written down so it is a decision rather than
an assumption.

**Trusted, with no cross-check possible:**

- **`get_height`.** Confirmation counts are `current_height - block_height + 1` off
  whatever the node reports. A node claiming a higher tip than exists ages payments
  faster than the chain does. This is not separately fixable: a node willing to lie
  about its height can as cheaply serve a fabricated chain of block hashes to back the
  lie up, so clamping confirmations to the scanner's own high-water mark would raise
  the attacker's cost by nothing while making every honest post-reorg rewind
  briefly under-count. (Covered as executable documentation by
  `an_inflated_reported_height_inflates_confirmations_which_is_an_accepted_trust_boundary`.)
- **`is_key_image_spent`.** A false "spent in blockchain" causes a valid payment to be
  voided; a false "unspent" delays (never prevents) detection of a real double-spend,
  since the check is re-run on every subsequent reorg and mempool sweep. Nothing else
  the scanner holds can corroborate a key-image status — key images are exactly the
  data a light client cannot derive for itself.
- **Block contents.** A node that omits a transaction from a block hides a payment;
  one that invents transactions cannot manufacture a payment, because a payment row
  exists only where `KeyCustody` matched an output against the tenant's own view key,
  which the node does not have.
- **Mempool contents.** Omission costs zero-conf detection and nothing else — the
  payment is still found when it is mined. Invention is inert, for the same reason as
  block contents.

**Not trusted — checked against what was recorded:**

- **Chain history.** Every scanned block's `(height, hash)` is stored and re-compared
  against whatever the node now reports (§7.5). This check has no notion of *why* the
  chain changed, which is what makes it cover more than reorgs: a node that has been
  replaced, rolled back, eclipsed onto an attacker's fork, or is simply lying about
  history presents as a hash mismatch and is reconciled identically. This is also why
  there is no per-daemon sync state to keep — the record is of what *this scanner*
  accepted, and it is re-validated against whoever answers next, so swapping daemons
  needs no special handling (`swapping_to_a_daemon_serving_a_different_chain_reconciles_exactly_like_a_reorg`).
- **Payments already recorded.** Never removed on absence, only on affirmative proof
  (§7.5), so a node that "forgets" a transaction cannot make a merchant's money
  disappear from the record.

**The deployment consequence**: the node is a trusted component. Point this service at
your own `monerod`, not at a public endpoint you do not control, whenever the payments
matter — and note that a *single* node is also the unit an eclipse attack targets
(there is published work on practical eclipse attacks against Monero's P2P layer), so
"my own node" means one whose peers you are willing to trust too.

## 8. Data Model

Canonical DDL: [`migrations/0001_init.sql`](../migrations/0001_init.sql) — validated
against a real `sqlite3` (constraints exercised live: `CHECK` on `status`,
`UNIQUE(tenant_id, minor_index)`, `UNIQUE(txid, output_index)`, and the foreign keys).
Reproduced here for reference; the migration file is the source of truth if these ever
diverge.

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE tenants (
    id                      TEXT PRIMARY KEY,
    public_key              TEXT NOT NULL UNIQUE,
    secret_token_hash       TEXT NOT NULL,
    key_custody_backend     TEXT NOT NULL,
    sealed_key_material     BLOB NOT NULL,
    primary_address         TEXT NOT NULL,
    network                 TEXT NOT NULL DEFAULT 'mainnet',
    next_minor_index        INTEGER NOT NULL DEFAULT 1,
    confirmations_required  INTEGER NOT NULL DEFAULT 10,
    zero_conf_max_piconero  INTEGER,
    order_expiry_seconds    INTEGER NOT NULL DEFAULT 1800,
    allowed_origins         TEXT NOT NULL,
    template_dir            TEXT,
    created_at              INTEGER NOT NULL,
    disabled_at             INTEGER
);

CREATE TABLE orders (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL REFERENCES tenants(id),
    merchant_order_id        TEXT,
    minor_index              INTEGER NOT NULL,
    address                  TEXT NOT NULL,
    fiat_currency            TEXT NOT NULL,
    fiat_amount              TEXT NOT NULL,
    exchange_rate            TEXT NOT NULL,
    xmr_amount_piconero      INTEGER NOT NULL,
    amount_received_piconero INTEGER NOT NULL DEFAULT 0,
    status                   TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'unconfirmed', 'confirming', 'paid', 'partial', 'overpaid', 'expired')),
    confirmations            INTEGER NOT NULL DEFAULT 0,
    double_spend_detected_at INTEGER,
    refund_address           TEXT,
    description              TEXT,
    created_at               INTEGER NOT NULL,
    expires_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL,
    UNIQUE (tenant_id, minor_index)
);
CREATE INDEX orders_tenant_status_idx ON orders (tenant_id, status);
CREATE INDEX orders_tenant_merchant_order_idx ON orders (tenant_id, merchant_order_id);

CREATE TABLE order_payments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id        TEXT NOT NULL REFERENCES orders(id),
    txid            TEXT NOT NULL,
    output_index    INTEGER NOT NULL,
    amount_piconero INTEGER NOT NULL,
    key_images_json TEXT NOT NULL,
    first_seen_at   INTEGER NOT NULL,
    block_height    INTEGER,
    voided_at       INTEGER,
    UNIQUE (txid, output_index)
);
CREATE INDEX order_payments_order_idx ON order_payments (order_id);

CREATE TABLE scanned_blocks (
    height     INTEGER PRIMARY KEY,
    block_hash TEXT NOT NULL
);

CREATE TABLE webhooks (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    url            TEXT NOT NULL,
    extra_headers  TEXT NOT NULL DEFAULT '{}',
    signing_secret TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     INTEGER NOT NULL
);
CREATE INDEX webhooks_tenant_idx ON webhooks (tenant_id);

CREATE TABLE webhook_deliveries (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id           TEXT NOT NULL REFERENCES webhooks(id),
    order_id             TEXT NOT NULL REFERENCES orders(id),
    event_type           TEXT NOT NULL,
    payload_json         TEXT NOT NULL,
    attempt_count        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at      INTEGER NOT NULL,
    delivered_at         INTEGER,
    last_attempted_at    INTEGER,
    last_response_status INTEGER,
    last_error           TEXT
);
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_attempt_at) WHERE delivered_at IS NULL;
```

### 8.1 Design notes

- **Money is never a float.** `fiat_amount` and `exchange_rate` are decimal strings.
- **`key_custody_backend`** lets a future migration to a different `KeyCustody`
  implementation fail loudly on a format mismatch rather than silently
  misinterpreting `sealed_key_material` bytes.
- **`order_payments` is append-mostly, never deleted.** Voided rows are kept
  (`voided_at` set) as the audit trail for "why does this order show partial" or "when
  was this order double-spent" — both answerable without reading logs.
- **`webhook_deliveries` is a queue-as-table**, not a separate broker — matters for
  staying a single small binary. The partial index on `next_attempt_at` is what the
  delivery worker's claim query uses; this has been verified live to be selected by
  SQLite's query planner for that exact query shape.

### 8.2 Why minor indices are never recycled (v1)

Each order gets a subaddress index no other order for that tenant has ever used, so two
customers are never watching the same address (a subaddress *reused* across two orders
would let one customer observe when the other's payment lands). The cost is the active
scan range only grows over a tenant's lifetime — acceptable at realistic v1 volumes
given the `KeyCustody` cache (§6.2 point 4), and explicitly deferred rather than solved
speculatively (§3).

## 9. Concurrency Model

- **Runtime**: `tokio`, with an explicitly configurable `worker_threads` (default
  conservative, e.g. 2), so the service has a hard, predictable CPU ceiling independent
  of how many client connections (including long-lived SSE streams) are open — chosen
  over a thread-per-connection sync model specifically because idle SSE connections are
  effectively free as parked tasks, whereas each would pin a full OS thread otherwise.
- **Writer actor**: a single task owning the one SQLite write connection. All mutations
  — minor-index allocation, order creation, payment matches, reorg-driven updates and
  voids, webhook-delivery enqueueing — funnel through one `mpsc` channel to it, so
  SQLite's single-writer constraint is satisfied by construction rather than by
  discipline. It is also the natural point to push SSE updates to subscribers, since it
  already knows exactly what changed.
- **Scan workers**: a bounded pool doing pure CPU-bound matching (§7.4), no DB access,
  sending results to the writer over a channel.
- **Read pool**: separate pooled read-only connections (SQLite WAL mode) for
  `GET`/status-poll handlers, independent of the writer so a slow write never blocks a
  status poll.
- **Webhook delivery worker**: separate async task(s) polling due `webhook_deliveries`
  rows and performing outbound HTTP — isolated so a slow or hostile merchant endpoint
  can never stall order-state commits.

## 10. HTTP API Surface

All JSON endpoints share one version prefix, `/api/v1`, including admin routes — there
is no principled reason to exempt admin from the same breaking-change discipline the
public surface gets, and a reverse-proxy rule restricting admin traffic (e.g. to a LAN)
matches on `/api/v1/admin/*` exactly as easily as on a bare `/admin/*`. The
checkout/payment-link page is a *different kind of surface* (rendered HTML, not a
JSON data contract) and gets its own independent version namespace, `/pay/v1/...`.

### 10.1 Auth model

Two credential types per tenant:

- **`pk_...` (public key)** — embedded in the merchant's static site JS. Identifies
  which tenant's orders/widget a request concerns. Not a secret; never accepted as
  authorization for anything.
- **`sk_...` (admin secret)** — stored only as a SHA-256 hex digest
  (`secret_token_hash`, unique-indexed for O(1) lookup). Deliberately not a slow,
  memory-hard hash like Argon2id: the token is high-entropy and machine-generated, not
  a human password, so there is no brute-force-resistance benefit to buy — only the
  cost of turning every auth check into a linear Argon2-verify scan over all tenants.
  Comparing the hash of the presented token against the stored hash with plain `==` is
  fine here too (no separate constant-time compare needed): the attacker controls the
  hash's *input*, not its output, and SHA-256's avalanche effect means a near-miss
  input has no predictable relationship to a near-miss digest, unlike comparing a raw
  secret byte-by-byte. Shown to the tenant exactly once (creation or rotation
  response).

**Structural rule, not a per-handler discipline**: every `/api/v1/admin/tenant/...`
route resolves *which* tenant is being operated on **entirely from the `sk_` bearer
token**, never from a path parameter. This was a deliberate correction during design —
an earlier draft had `/admin/tenants/{id}/...` alongside a separate bearer token,
which is exactly the shape that invites an IDOR (tenant A's valid token + tenant B's
`id` in the URL) unless every handler remembers to cross-check the two. Removing `{id}`
from these routes removes the bug class structurally: there is nothing in the URL for a
token to be checked against. Any route that still needs a client-supplied identifier
within a tenant's own scope (e.g. `{payment_id}`) must filter its query by *both* that
identifier *and* the token-resolved `tenant_id` (`WHERE id = ? AND tenant_id = ?`,
never `WHERE id = ?` alone) — ideally enforced once, centrally, by middleware that hands
every handler an already-scoped tenant context, not re-implemented per handler.

### 10.2 Admin API (`/api/v1/admin/...`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/v1/admin/tenants` | none (DDoS layer only, §12) | `{view_key_hex, spend_pubkey_hex, network, allowed_origins[], confirmations_required?, zero_conf_max_xmr?, order_expiry_seconds?}` → `{tenant_id, public_key, secret_token}` (secret shown once) |
| `GET` | `/api/v1/admin/tenant` | `sk_` | Own config; never returns `sealed_key_material` or the token hash |
| `PATCH` | `/api/v1/admin/tenant` | `sk_` | Mutable fields only: `allowed_origins`, `confirmations_required`, `zero_conf_max_xmr`, `order_expiry_seconds`, `template_dir`. Key material and `public_key` are immutable — rotate by creating a new tenant |
| `POST` | `/api/v1/admin/tenant/rotate-secret` | `sk_` | Invalidates the old secret, returns a new one once |
| `DELETE` | `/api/v1/admin/tenant` | `sk_` | Soft-delete: `key_custody.remove_wallet()`, set `disabled_at`; orders keep a valid FK |
| `GET` | `/api/v1/admin/tenant/orders?status=&cursor=` | `sk_` | Paginated |
| `GET` | `/api/v1/admin/tenant/orders/{payment_id}` | `sk_` | Includes `order_payments` audit trail |
| `POST` | `/api/v1/admin/tenant/webhooks` | `sk_` | `{url, extra_headers?}` → `{webhook_id, signing_secret}` (shown once — an API convention here, not a hashing guarantee, since HMAC signing needs the real bytes on every delivery) |
| `GET` | `/api/v1/admin/tenant/webhooks` | `sk_` | List (never re-shows `signing_secret`) |
| `DELETE` | `/api/v1/admin/tenant/webhooks/{id}` | `sk_` | Rotation is delete+recreate in v1 |

### 10.3 Public API (`/api/v1/t/{pk}/...`)

No bearer auth — scoped by `pk_` in the path plus an `allowed_origins` check on
`Origin`, independent of the CORS header itself.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/v1/t/{pk}/orders` | `{merchant_order_id?, fiat_amount, fiat_currency, description?}` → `{payment_id, address, xmr_amount, exchange_rate, expires_at}` |
| `GET` | `/api/v1/t/{pk}/orders/{payment_id}` | Status poll |
| `GET` | `/api/v1/t/{pk}/orders/{payment_id}/events` | SSE, pushed by the writer actor |
| `POST` | `/api/v1/t/{pk}/orders/{payment_id}/refund-address` | Records only; nothing ever sends it |

### 10.4 Payment link / widget (`/pay/v1/{pk}/{payment_id}`)

One route serves both the iframe embed target *and* a standalone link a merchant hands
a customer directly (email, chat) that "continues to work" independent of the
merchant's own site. Both uses share the same rendering logic — `postMessage` calls to
a parent window are harmless no-ops when there is no parent listening — so this
deliberately avoids maintaining two near-identical template sets. Rendered from the
tenant's `template_dir` (or the server default), showing the recomputed `status` plus,
independently, a double-spend explanation banner whenever `double_spend_detected_at`
is set (§7.6) — the banner's presence is not tied to which `status` is currently shown.

## 11. Webhook Delivery

- One row is inserted into `webhook_deliveries` per enabled webhook, per **event**, for
  two independent event families:
  - `order.<status>` — fired on a `status` *transition* (recompute produced a different
    value than before), never on a same-status recompute (e.g. a confirmation count
    ticking up without crossing the threshold).
  - `order.double_spend_detected` — fired once per voided `order_payments` row,
    independent of whether that same recompute also produced a status transition. A
    single reorg can legitimately enqueue both, or the double-spend event alone if the
    order's aggregate status didn't move (e.g. a redundant payment still covers it).
- The writer actor enqueues; a separate delivery worker claims due rows
  (`delivered_at IS NULL AND next_attempt_at <= now()`) and performs the HTTP call —
  never the writer itself, so a slow or unresponsive merchant endpoint cannot stall
  order-state commits.
- Each delivery is signed: HMAC-SHA256 of the body using the webhook's
  `signing_secret`, sent as a header (`X-MoneroPay-Signature`).
- Every payload carries a common envelope alongside its event-specific fields:
  `event_id` (`evt_…`, minted once per *event* — every retry of that delivery re-sends
  the same id under the same signature), `event` (the event type, mirroring
  `X-MoneroPay-Event`), and `created_at` (unix seconds). `event_id` is also sent as
  `X-MoneroPay-Event-Id`, read back out of the signed body so header and body can
  never disagree. Both fields are *inside* the signed body deliberately: without an
  id, a retry of a lost-ack delivery is byte-identical to a genuine second transition
  to the same status, and without a timestamp a captured delivery can be replayed
  against the merchant indefinitely.
- Failure handling: short timeout (a few seconds), exponential backoff via
  `attempt_count`/`next_attempt_at`, giving up after a bounded number of attempts (row
  stays for inspection via the admin API, retries just stop).
- Delivery is **at-least-once, not exactly-once** — a merchant's endpoint may see a
  duplicate if a 2xx response is lost after being sent. This is a documented contract,
  not an oversight: webhook handlers are expected to be idempotent, and the payload's
  `event_id` is the value to dedupe on (it is stable across retries of one event and
  distinct between genuinely separate ones).
- **SSRF mitigation is mandatory, on by default.** A merchant-supplied webhook URL is
  an outbound-request vector this server would otherwise make on the operator's
  network — relevant to a home-router self-hoster but critical for a hosted
  multi-tenant operator. The delivery worker must resolve the hostname and reject
  private/loopback/link-local ranges **at connect time**, not just at registration
  (DNS can change between the two), and must not follow redirects blindly. A config
  escape hatch for a self-hoster testing against their own LAN is acceptable; the
  default must be closed.

## 12. DDoS Protections

The realistic threat model: unauthenticated endpoints (`POST /api/v1/t/{pk}/orders`,
`POST /api/v1/admin/tenants`) exist by necessity, since a static site has nowhere to
keep a secret. Layers, cheapest first:

1. **Per-IP token-bucket rate limiting** on state-changing endpoints.
2. **Small request body caps**, enforced before JSON parsing.
3. **`allowed_origins` enforcement independent of the CORS header** — reject
   non-matching `Origin`/`Referer` at the application layer too, not just via the
   browser-enforced CORS mechanism (which is a client-side courtesy, not a server-side
   guarantee).
4. **Optional JS proof-of-work challenge**, gated behind a load threshold (normal
   traffic never sees it) — no third-party CAPTCHA dependency, no accounts.
5. **Bounded global concurrency** (a semaphore in front of the router) in addition to
   per-IP limits — relevant specifically because the async model makes idle
   connections cheap, so an attacker can open far more of them before hitting OS fd
   limits than a thread-per-connection model would allow.
6. **Short connection timeouts**, bounded worker/task counts.
7. **Documented, not implemented**: running behind Tor (hides the home IP entirely) or
   a reverse proxy/CDN for a clearnet domain — a deployment recommendation, not app
   code.

## 13. Configuration Surface (sketch)

```toml
[monero_node]
host = "127.0.0.1"
port = 18081
ssl = false

[wallet]                      # self-hosted bootstrap only; ignored once tenants exist
primary_address = "4..."
private_view_key = "..."

[exchange_rate]
provider = "haveno"           # pluggable trait: haveno | kraken | coingecko | fixed
cache_seconds = 60

[payment]
confirmations_required = 10
zero_conf_max_xmr = "0.25"    # XMR, not fiat: compared against the piconero total received
order_expiry_minutes = 30
reorg_check_depth = 20        # blocks; should exceed confirmations_required with margin
mempool_poll_interval_ms = 1000

[server]
bind = "0.0.0.0:8443"
worker_threads = 2
tls = "rustls"                # rustls | none (behind an external reverse proxy)
tls_cert = "/etc/moneropay/cert.pem"
tls_key = "/etc/moneropay/key.pem"

[templates]
dir = "/etc/moneropay/templates"   # overridable with --templates-dir

[ddos]
rate_limit_per_ip_per_min = 20
max_body_bytes = 8192
pow_challenge = "auto"        # off | auto | always

[webhooks]
allow_private_urls = false    # SSRF escape hatch, self-hosted LAN testing only
delivery_timeout_ms = 5000
max_attempts = 8
```

## 14. Client Library

```html
<script src="https://pay.example.com/static/moneropay-client.js"></script>
<div id="checkout"></div>
<script>
  const order = await MoneroPay.createOrder({
    endpoint: "https://pay.example.com",
    publicKey: "pk_...",
    merchantOrderId: "shop-order-1234",
    fiatAmount: 25.00,
    fiatCurrency: "USD",
  });
  MoneroPay.mount("#checkout", order.paymentId, {
    onPaid: (o) => window.location = "/thank-you.html",
    onExpired: () => alert("Payment window expired"),
  });
</script>
```

`mount()` injects an `<iframe src="https://pay.example.com/pay/v1/{pk}/{paymentId}">`
and listens for `postMessage` events the page posts on status changes. All payment
logic and UI lives server-side in the templates; the client library stays thin
deliberately, since it is the one surface running as plain JS on an arbitrary
third-party site with no build step assumed.

## 15. Build & Packaging

| Concern | Choice | Why |
|---|---|---|
| HTTP | `axum` on `hyper`/`tokio` | `tower`/`tower-http` give body-size limits, timeouts, and concurrency limiting as drop-in layers instead of hand-rolled code in a security-sensitive path |
| TLS | `rustls` | pure Rust; avoids an OpenSSL dynamic dependency |
| DB | `rusqlite` (`bundled` feature) | SQLite compiled statically into the binary — still a single static executable, no separate DB process |
| Monero crypto | `monero` crate (monero-rs) | pure Rust, no `monero-wallet-rpc` sidecar; verified in this project against real fixture data (see `src/key_custody/plain.rs` tests) |
| Password/token hashing | `argon2` | for `secret_token_hash` |
| Rate limiting | `governor` | in-memory, no Redis |
| Templates | `handlebars` (loaded from disk at runtime) | user-editable files, no recompile needed |
| Build target | `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl` | fully static; covers typical router SoCs |

Explicitly avoided: `monero-wallet-rpc` (separate C++ process), OpenSSL, ZMQ/`libzmq`
— all for the same reason: they conflict with "single static binary, no dynamic
libraries."

## 16. Deferred / Future Work

Listed so a future change doesn't have to rediscover why these were left out:

- TEE-backed `KeyCustody` implementation (Nitro/SEV-SNP preferred over SGX; see §6.1).
- Minor-index recycling/bucketing for high-volume tenants (§8.2).
- ZMQ-based mempool push as an opt-in, feature-flagged alternative to polling.
- A platform/operator admin tier for the hosted deployment, with its own route
  namespace and credential type, entirely separate from tenant `sk_` auth.
- Gated tenant creation (an `operator_token` requirement) for a hosted instance that
  wants invite-only onboarding.
- In-place webhook secret rotation.
- `SubKeyChecker` table-cache improvements beyond the current per-wallet clone (e.g.
  avoiding the `HashMap` clone on every cache hit) if profiling ever shows it matters.
