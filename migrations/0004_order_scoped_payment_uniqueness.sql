-- Scopes the payment-dedup constraint to the owning order.
--
-- `UNIQUE (txid, output_index)` was global, which is only correct as long as no
-- two orders can ever legitimately be paid by the same transaction output. That
-- holds within one tenant (each order gets its own subaddress), but not across
-- tenants: two tenants configured with the *same* view key - a merchant running a
-- second instance against one wallet, or a staging tenant pointed at production
-- key material - both match the same output, and whichever one the scanner
-- recorded second silently lost its payment to `ON CONFLICT DO NOTHING`. Keying
-- the constraint by `order_id` as well keeps mempool-poll idempotency exactly as
-- strong (the scanner re-reporting one output for one order still collapses to a
-- single row) while letting two genuinely distinct orders each record their own.
--
-- SQLite cannot alter a table's constraints in place, so this rebuilds the table
-- and copies every row across. Column list is written out explicitly rather than
-- `SELECT *` so a future column addition can't silently shift positions here.
CREATE TABLE order_payments_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id        TEXT NOT NULL REFERENCES orders(id),
    txid            TEXT NOT NULL,
    output_index    INTEGER NOT NULL,
    amount_piconero INTEGER NOT NULL,
    key_images_json TEXT NOT NULL,
    first_seen_at   INTEGER NOT NULL,
    block_height    INTEGER,
    voided_at       INTEGER,
    UNIQUE (order_id, txid, output_index)
);

INSERT INTO order_payments_new
    (id, order_id, txid, output_index, amount_piconero, key_images_json, first_seen_at, block_height, voided_at)
SELECT id, order_id, txid, output_index, amount_piconero, key_images_json, first_seen_at, block_height, voided_at
FROM order_payments;

DROP TABLE order_payments;

ALTER TABLE order_payments_new RENAME TO order_payments;

-- Dropping the old table dropped its index with it.
CREATE INDEX order_payments_order_idx ON order_payments (order_id);
