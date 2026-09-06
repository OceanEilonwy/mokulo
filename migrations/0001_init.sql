-- Connection pragmas (journal_mode = WAL, synchronous = NORMAL, foreign_keys = ON)
-- deliberately do NOT live here. `synchronous` and `foreign_keys` are per-connection
-- settings, not properties stored in the database file, so setting them in a
-- migration applies them only to the one connection that happened to run that
-- migration - on every subsequent boot against an already-migrated file the
-- migration is skipped and foreign key enforcement is silently off. They are set in
-- `Store::open_file`/`open_in_memory` instead (see `store::configure_connection`,
-- which also documents the WAL/NORMAL durability tradeoff), which additionally lets
-- each migration below run inside a transaction - `PRAGMA journal_mode = WAL` cannot.

-- One row per merchant. A self-hosted, single-tenant deployment has exactly one
-- row here, inserted once at first boot from the TOML config - multi-tenancy is
-- not a special mode, it's just what happens when more than one row exists.
CREATE TABLE tenants (
    id                      TEXT PRIMARY KEY,       -- opaque id, e.g. "tn_" + uuid4
    public_key              TEXT NOT NULL UNIQUE,   -- "pk_..." - embedded in the merchant's static site JS, not a secret
    secret_token_hash       TEXT NOT NULL UNIQUE,    -- SHA-256 hex digest of the "sk_..." admin token, indexed for O(1) lookup. Deliberately NOT a slow/memory-hard hash (Argon2 etc.): the token is a high-entropy random value, not a human password, so brute-force resistance from a slow hash buys nothing but would turn lookup into a linear Argon2-verify scan over every tenant. The raw token is shown exactly once, at creation/rotation, and never stored. All /api/v1/admin/tenant/* routes resolve "which tenant" from this token alone - never from a path parameter, so there is nothing for a leaked or guessed identifier to authorize.
    key_custody_backend     TEXT NOT NULL,           -- which KeyCustody impl sealed `sealed_key_material` - "plain" today; lets a later migration to a TEE backend fail loudly on a mismatch instead of silently misinterpreting bytes
    sealed_key_material     BLOB NOT NULL,           -- output of KeyCustody::seal - opaque to this table; PlainKeyCustody seals to plain view_key||spend_pubkey bytes, a TEE backend would seal to something only it can unseal
    primary_address         TEXT NOT NULL,           -- display-only (e.g. tenant dashboard); never used for scanning, which only ever goes through KeyCustody
    network                 TEXT NOT NULL DEFAULT 'mainnet',
    next_minor_index        INTEGER NOT NULL DEFAULT 1,  -- monotonically increasing, never reused - see note below on why
    confirmations_required  INTEGER NOT NULL DEFAULT 10,
    zero_conf_max_piconero  INTEGER,                 -- NULL = never treat 0-conf as paid; otherwise the ceiling above which only a confirmed tx counts
    order_expiry_seconds    INTEGER NOT NULL DEFAULT 1800,
    allowed_origins         TEXT NOT NULL,           -- JSON array of origins, e.g. ["https://merchant.github.io"] - enforced both as the CORS header and as an independent Origin check on state-changing requests
    template_dir            TEXT,                    -- NULL = server's default template directory
    created_at              INTEGER NOT NULL,        -- unix seconds
    disabled_at             INTEGER                  -- NULL = active; set on offboarding instead of deleting the row, so historical orders keep a valid foreign key
);

-- Minor indices are never recycled in v1: each order gets a subaddress index no
-- other order for this tenant has ever used, so two customers can never be
-- watching the same address. The cost is that the scanner's active range for a
-- tenant is `0..next_minor_index`, which only grows - fine at the order volumes a
-- single self-hosted merchant or a modestly busy hosted tenant will see, given the
-- KeyCustody table cache means this is a one-time rebuild per new order, not per
-- transaction scanned. A high-volume tenant outgrowing this is a real scaling
-- question (recycle indices from long-completed orders, or bucket by time) that
-- shouldn't be solved speculatively before it's an actual problem.

CREATE TABLE orders (
    id                       TEXT PRIMARY KEY,       -- "pay_" + uuid4, the payment_id handed to the client library, used in both the widget/payment-link URL and webhook payloads
    tenant_id                TEXT NOT NULL REFERENCES tenants(id),
    merchant_order_id        TEXT,                   -- opaque string from the merchant's own site; not unique across or even within a tenant, purely informational
    minor_index              INTEGER NOT NULL,
    address                  TEXT NOT NULL,           -- derived subaddress, cached at creation so replaying it doesn't need a KeyCustody call
    fiat_currency            TEXT NOT NULL,
    fiat_amount              TEXT NOT NULL,           -- decimal string, e.g. "24.99" - never a REAL/float, to avoid rounding drift on money
    exchange_rate            TEXT NOT NULL,           -- XMR per unit of fiat_currency, locked at order creation; decimal string
    xmr_amount_piconero      INTEGER NOT NULL,        -- expected amount, locked at creation from fiat_amount * exchange_rate
    amount_received_piconero INTEGER NOT NULL DEFAULT 0,  -- running total across non-voided order_payments rows, maintained by the writer actor
    status                   TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'unconfirmed', 'confirming', 'paid', 'partial', 'overpaid', 'expired')),
        -- Deliberately not a status value: whether a double-spend occurred is an
        -- orthogonal fact (see double_spend_detected_at below), not a payment-amount
        -- state. A voided payment can leave an order at 'pending', 'partial', or
        -- even still 'paid' if other contributing transactions cover it - status is
        -- always recomputed fresh from non-voided order_payments rows, never
        -- patched in place for a specific event.
    confirmations            INTEGER NOT NULL DEFAULT 0,  -- min confirmations across contributing (non-voided) payments - see order_payments
    double_spend_detected_at INTEGER,                 -- sticky flag: set the FIRST time any payment contributing to this order is voided (see order_payments.voided_at), and never cleared afterwards even if `status` recovers to 'paid' via other transactions. A convenience for "should the widget show a warning at all" - full detail per incident (which txid, when) always lives on the order_payments rows themselves, not here.
    refund_address           TEXT,                    -- customer-supplied, recorded only; nothing in this system ever sends a refund automatically (no spend key exists to do it with)
    description              TEXT,
    created_at               INTEGER NOT NULL,
    expires_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL,
    UNIQUE (tenant_id, minor_index)
);

CREATE INDEX orders_tenant_status_idx ON orders (tenant_id, status);
CREATE INDEX orders_tenant_merchant_order_idx ON orders (tenant_id, merchant_order_id);

-- Every matched output the scanner reports lands here first, before the order's
-- aggregate columns are updated from it. This is what makes partial/split
-- payments and overpayment detection possible (sum the non-voided rows, compare
-- to xmr_amount_piconero) and gives an audit trail a merchant can actually inspect
-- - "the order shows partial, here's why" shouldn't require reading logs.
CREATE TABLE order_payments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id        TEXT NOT NULL REFERENCES orders(id),
    txid            TEXT NOT NULL,
    output_index    INTEGER NOT NULL,
    amount_piconero INTEGER NOT NULL,
    key_images_json TEXT NOT NULL,      -- JSON array of this tx's input key images (hex) - public data, unrelated to any wallet's keys, captured purely so a later re-check can call monerod's is_key_image_spent if this tx ever disappears from the chain. Not derived through KeyCustody.
    first_seen_at   INTEGER NOT NULL,   -- when the scanner first observed this output, whether in the mempool or a block
    block_height    INTEGER,            -- NULL while unconfirmed. No longer treated as immutable once set - a reorg can move a tx to a different height, or drop it back to NULL if it falls back into the mempool; see scanned_blocks.
    voided_at       INTEGER,            -- set if a reorg is later found to have dropped this specific payment for good (its key image ended up spent by a different, unrelated transaction). The row is kept, never deleted, as the audit record of what happened; amount_received_piconero and status are recomputed excluding voided rows.
    UNIQUE (txid, output_index)         -- the scanner polls the mempool every ~1s and will see the same tx repeatedly; this makes recording a match an idempotent upsert instead of needing separate dedup logic
);

CREATE INDEX order_payments_order_idx ON order_payments (order_id);

-- A rolling window of recently-scanned block hashes, kept so the scanner can
-- notice a reorg by comparing "the hash I recorded for height H" against "the
-- hash monerod reports for height H now", rather than assuming a block it has
-- already scanned stays canonical forever. Pruned to the last
-- `reorg_check_depth` blocks (a server config value, default modestly deeper
-- than confirmations_required) as new blocks arrive - this only needs to cover
-- the depth a merchant hasn't yet treated as final, not defend against
-- arbitrarily deep reorgs, which is a question about Monero's own consensus
-- security, not something this service can second-guess.
CREATE TABLE scanned_blocks (
    height     INTEGER PRIMARY KEY,
    block_hash TEXT NOT NULL
);

-- One row per merchant-registered webhook endpoint. A tenant can register more
-- than one (e.g. one for their own logging, one for order-fulfillment
-- automation), so this is a child table rather than columns on tenants.
CREATE TABLE webhooks (
    id            TEXT PRIMARY KEY,       -- "wh_" + uuid4
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    url           TEXT NOT NULL,
    extra_headers TEXT NOT NULL DEFAULT '{}',  -- JSON object of additional headers to send, e.g. a bearer token the merchant's own endpoint expects
    signing_secret TEXT NOT NULL,          -- used to compute an HMAC-SHA256 signature per delivery (sent as a header) so the merchant's endpoint can verify authenticity. Unlike secret_token_hash, this must be stored reversibly - it's needed on every delivery, not just checked once - so "shown once" for this value is an API convention, not a hashing guarantee. Rotate via delete+recreate in v1; no in-place rotation endpoint yet.
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
);

CREATE INDEX webhooks_tenant_idx ON webhooks (tenant_id);

-- Delivery log and retry queue in one table - no separate broker needed, which
-- matters for staying a single small binary. A row is inserted the moment a
-- webhook-worthy status transition commits, and the delivery worker claims due
-- rows (`next_attempt_at <= now AND delivered_at IS NULL`) instead of the writer
-- actor ever making an outbound HTTP call itself.
CREATE TABLE webhook_deliveries (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id          TEXT NOT NULL REFERENCES webhooks(id),
    order_id            TEXT NOT NULL REFERENCES orders(id),
    event_type          TEXT NOT NULL,    -- either "order.<status>" fired once per *status transition* (not per confirmation-count tick), or the independent "order.double_spend_detected", fired once per voided order_payments row regardless of whether that also changed status
    payload_json        TEXT NOT NULL,    -- the exact body sent (or to be sent) - kept verbatim so a merchant dispute over "what did you send me" has an answer
    attempt_count        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at      INTEGER NOT NULL,  -- now() for a fresh delivery; pushed out with backoff after each failure
    delivered_at         INTEGER,           -- NULL until a 2xx response is received; a delivered row is done, regardless of attempt_count
    last_attempted_at    INTEGER,
    last_response_status INTEGER,
    last_error           TEXT
);

CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_attempt_at) WHERE delivered_at IS NULL;
