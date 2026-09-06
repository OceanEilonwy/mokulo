//! The persistence layer. A `Store` wraps one `rusqlite::Connection` and is not
//! `Sync` on its own — SQLite allows exactly one writer at a time regardless, so the
//! production async layer is expected to guard a `Store` behind a single owner (a
//! dedicated thread receiving commands over a channel, or, as used for the
//! concurrency test in this module, an `Arc<Mutex<Store>>`) rather than opening many
//! writable connections. Read-only access can use as many separate connections as
//! needed (SQLite's WAL mode allows concurrent readers alongside the one writer) —
//! that pool is not implemented here, since every method below is exercised directly
//! against a single connection for correctness testing.
//!
//! This module intentionally has no `KeyCustody` dependency: deriving a subaddress
//! for a new order happens *before* `create_order` is called, by whatever orchestrates
//! order creation (the future HTTP handler / writer actor) — `Store` only persists the
//! result.

use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::auth::{generate_public_key, generate_secret_token, hash_secret_token};
use crate::status::{OrderStatus, PaymentView, StatusInputs, derive_status};

/// Every migration file, applied in order, exactly once each - tracked in
/// `schema_migrations` rather than assumed from `CREATE TABLE`'s own failure mode.
/// Re-running the raw DDL against an already-migrated database (e.g. every time the
/// server restarts against its existing `moneropay.db`) would otherwise crash with
/// "table already exists" - a real bug caught by actually restarting the compiled
/// binary against a file it had already created, not by any unit test, since every
/// unit test in this codebase opens a fresh `:memory:` database exactly once.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_active_orders_index.sql")),
    (3, include_str!("../migrations/0003_network_scoped_scanning.sql")),
    (4, include_str!("../migrations/0004_order_scoped_payment_uniqueness.sql")),
];

/// Connection-level settings that are *not* persisted in the database file, so they
/// have to be re-applied every single time a connection is opened - not just on the
/// boot that happened to run the initial migration. `foreign_keys` in particular
/// defaults to OFF in SQLite: setting it once inside `0001_init.sql` meant foreign
/// key enforcement was silently inactive on every restart after the very first one.
/// (`journal_mode = WAL` *is* persisted in the file, but is set here too so a fresh
/// file gets it from the first connection onward rather than only mid-migration.)
///
/// WAL + NORMAL is the standard pairing for this workload: WAL lets the writer commit
/// while read connections keep serving status polls, and NORMAL is durable against
/// application/process crashes under WAL (only an OS crash or power loss can lose the
/// last few commits). This isn't a ledger moving funds - it's a record of payments
/// observed on-chain - so that tradeoff beats paying fsync-per-commit latency.
///
/// Must run before `apply_migrations`: `PRAGMA foreign_keys` is a no-op if issued
/// inside a transaction, and each migration now runs inside one.
fn configure_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )
}

/// Each migration's DDL and its `schema_migrations` bookkeeping row commit together
/// or not at all. Without that, a crash in the window between the two re-runs the
/// migration on the next boot, which for anything containing `CREATE TABLE` or
/// `DROP TABLE` (0003 and 0004 both do) fails outright and leaves the server unable
/// to start against its own database.
fn apply_migrations(conn: &Connection) -> rusqlite::Result<()> {
    apply_migration_list(conn, MIGRATIONS)
}

/// Split out from `apply_migrations` purely so a test can drive it with a
/// deliberately-failing migration - the all-or-nothing property is invisible from
/// the outside otherwise, since every real migration succeeds.
fn apply_migration_list(conn: &Connection, migrations: &[(i64, &str)]) -> rusqlite::Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)")?;
    for (version, sql) in migrations {
        let already_applied: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
            params![version],
            |row| row.get(0),
        )?;
        if !already_applied {
            // `unchecked_transaction` rather than `Connection::transaction` only
            // because every `Store` method takes `&self`, not `&mut self` - the
            // single-writer discipline this module documents makes the borrow-level
            // check it forgoes redundant.
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            tx.execute("INSERT INTO schema_migrations (version) VALUES (?1)", params![version])?;
            tx.commit()?;
        }
    }
    Ok(())
}

pub type SharedStore = Arc<Mutex<Store>>;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("not found")]
    NotFound,
}

type Result<T> = std::result::Result<T, StoreError>;

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: String,
    pub public_key: String,
    pub key_custody_backend: String,
    pub sealed_key_material: Vec<u8>,
    pub primary_address: String,
    pub network: String,
    pub next_minor_index: u32,
    pub confirmations_required: u64,
    pub zero_conf_max_piconero: Option<u64>,
    pub order_expiry_seconds: i64,
    pub allowed_origins: Vec<String>,
    pub template_dir: Option<String>,
    pub created_at: i64,
    pub disabled_at: Option<i64>,
}

pub struct NewTenant {
    pub key_custody_backend: String,
    pub sealed_key_material: Vec<u8>,
    pub primary_address: String,
    pub network: String,
    pub allowed_origins: Vec<String>,
    pub confirmations_required: Option<u64>,
    pub zero_conf_max_piconero: Option<u64>,
    pub order_expiry_seconds: Option<i64>,
}

/// A partial update to a tenant's config. Fields are plain `Option<T>` for
/// "unchanged vs. set to a value" (there's no way to clear `allowed_origins` etc.
/// back to empty via this API, which is fine - it's never meant to be empty).
/// `zero_conf_max_piconero` and `template_dir` are the two fields that legitimately
/// need to be *cleared* to `NULL`, so they get an explicit `_set` flag alongside the
/// `Option<T>` value to distinguish "leave alone" from "set to None".
#[derive(Default)]
pub struct TenantConfigPatch {
    pub allowed_origins: Option<Vec<String>>,
    pub confirmations_required: Option<u64>,
    pub zero_conf_max_piconero_set: bool,
    pub zero_conf_max_piconero: Option<u64>,
    pub order_expiry_seconds: Option<i64>,
    pub template_dir_set: bool,
    pub template_dir: Option<String>,
}

pub struct CreatedTenant {
    pub tenant: Tenant,
    /// Shown here exactly once - callers must hand this to the operator and never
    /// persist it themselves; only `secret_token_hash` is stored.
    pub secret_token: String,
}

#[derive(Debug, Clone)]
pub struct Order {
    pub id: String,
    pub tenant_id: String,
    pub merchant_order_id: Option<String>,
    pub minor_index: u32,
    pub address: String,
    pub fiat_currency: String,
    pub fiat_amount: String,
    pub exchange_rate: String,
    pub xmr_amount_piconero: u64,
    pub amount_received_piconero: u64,
    pub status: OrderStatus,
    pub confirmations: u64,
    pub double_spend_detected_at: Option<i64>,
    pub refund_address: Option<String>,
    pub description: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
}

pub struct NewOrder {
    pub tenant_id: String,
    pub merchant_order_id: Option<String>,
    pub minor_index: u32,
    pub address: String,
    pub fiat_currency: String,
    pub fiat_amount: String,
    pub exchange_rate: String,
    pub xmr_amount_piconero: u64,
    pub description: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct OrderPaymentRow {
    pub id: i64,
    pub order_id: String,
    pub txid: String,
    pub output_index: i64,
    pub amount_piconero: u64,
    pub key_images_json: String,
    pub first_seen_at: i64,
    pub block_height: Option<i64>,
    pub voided_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Webhook {
    pub id: String,
    pub tenant_id: String,
    pub url: String,
    pub extra_headers: String,
    pub signing_secret: String,
    pub enabled: bool,
    pub created_at: i64,
}

fn status_to_str(s: OrderStatus) -> &'static str {
    s.as_str()
}

fn status_from_str(s: &str) -> OrderStatus {
    match s {
        "pending" => OrderStatus::Pending,
        "unconfirmed" => OrderStatus::Unconfirmed,
        "confirming" => OrderStatus::Confirming,
        "paid" => OrderStatus::Paid,
        "partial" => OrderStatus::Partial,
        "overpaid" => OrderStatus::Overpaid,
        "expired" => OrderStatus::Expired,
        other => panic!("unknown status in database: {other}"), // schema CHECK constraint makes this unreachable
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

impl Store {
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        configure_connection(&conn)?;
        apply_migrations(&conn)?;
        Ok(Store { conn })
    }

    pub fn open_file(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        configure_connection(&conn)?;
        apply_migrations(&conn)?;
        Ok(Store { conn })
    }

    pub fn into_shared(self) -> SharedStore {
        Arc::new(Mutex::new(self))
    }

    /// Runs `f` inside one SQLite transaction against this same connection, so a
    /// group of writes that only makes sense together either all land or none do.
    ///
    /// Exists because "persist a status change" and "enqueue the webhook announcing
    /// it" are two separate statements that must not be able to come apart: the new
    /// status commits first, and `recompute_order_status` derives "did anything
    /// change" by comparing against the *stored* status, so once the status write is
    /// visible the transition can never be re-detected. A failure (or a crash)
    /// between the two therefore didn't delay the webhook, it deleted it - the
    /// merchant's `order.paid` never fires, for an order that is `paid`.
    ///
    /// Nested calls are not supported (SQLite has no nested `BEGIN`); every caller
    /// is a top-level orchestration step. Rolls back on any error, including one
    /// raised by `f` itself, because the `Transaction` guard's default drop behaviour
    /// is rollback.
    pub fn in_transaction<T, E, F>(&self, f: F) -> std::result::Result<T, E>
    where
        F: FnOnce(&Store) -> std::result::Result<T, E>,
        E: From<StoreError>,
    {
        let tx = self.conn.unchecked_transaction().map_err(StoreError::from)?;
        let out = f(self)?;
        tx.commit().map_err(StoreError::from)?;
        Ok(out)
    }

    /// Test-only escape hatch for breaking the schema on purpose, so failure paths
    /// that only a genuine `StoreError` can reach (a scanner tick that must not mark
    /// a block scanned when recording a match failed) can be exercised without a
    /// mock persistence layer. Not compiled into the binary.
    #[cfg(test)]
    pub fn execute_raw_for_test(&self, sql: &str) -> Result<()> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    // -- Tenants --------------------------------------------------------

    pub fn create_tenant(&self, new: NewTenant, now: i64) -> Result<CreatedTenant> {
        let id = new_id("tn");
        let public_key = generate_public_key();
        let secret_token = generate_secret_token();
        let secret_hash = hash_secret_token(&secret_token);
        let allowed_origins_json = serde_json::to_string(&new.allowed_origins).unwrap();

        self.conn.execute(
            "INSERT INTO tenants (id, public_key, secret_token_hash, key_custody_backend,
                sealed_key_material, primary_address, network, next_minor_index,
                confirmations_required, zero_conf_max_piconero, order_expiry_seconds,
                allowed_origins, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12)",
            params![
                id,
                public_key,
                secret_hash,
                new.key_custody_backend,
                new.sealed_key_material,
                new.primary_address,
                new.network,
                new.confirmations_required.unwrap_or(10) as i64,
                new.zero_conf_max_piconero.map(|v| v as i64),
                new.order_expiry_seconds.unwrap_or(1800),
                allowed_origins_json,
                now,
            ],
        )?;

        let tenant = self.get_tenant_by_id(&id)?.ok_or(StoreError::NotFound)?;
        Ok(CreatedTenant { tenant, secret_token })
    }

    fn row_to_tenant(row: &rusqlite::Row) -> rusqlite::Result<Tenant> {
        let allowed_origins_json: String = row.get("allowed_origins")?;
        let allowed_origins: Vec<String> =
            serde_json::from_str(&allowed_origins_json).unwrap_or_default();
        Ok(Tenant {
            id: row.get("id")?,
            public_key: row.get("public_key")?,
            key_custody_backend: row.get("key_custody_backend")?,
            sealed_key_material: row.get("sealed_key_material")?,
            primary_address: row.get("primary_address")?,
            network: row.get("network")?,
            next_minor_index: row.get::<_, i64>("next_minor_index")? as u32,
            confirmations_required: row.get::<_, i64>("confirmations_required")? as u64,
            zero_conf_max_piconero: row
                .get::<_, Option<i64>>("zero_conf_max_piconero")?
                .map(|v| v as u64),
            order_expiry_seconds: row.get("order_expiry_seconds")?,
            allowed_origins,
            template_dir: row.get("template_dir")?,
            created_at: row.get("created_at")?,
            disabled_at: row.get("disabled_at")?,
        })
    }

    /// Every non-disabled tenant - used at boot to eagerly register every wallet
    /// with `KeyCustody` before serving any requests, so the lazy-on-first-use path
    /// in the HTTP layer (`http::resolve_wallet_handle`) is a fallback, not the
    /// only path.
    pub fn list_active_tenants(&self) -> Result<Vec<Tenant>> {
        let mut stmt = self.conn.prepare("SELECT * FROM tenants WHERE disabled_at IS NULL")?;
        let rows = stmt.query_map([], Self::row_to_tenant)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn count_tenants(&self) -> Result<u64> {
        let count: i64 = self.conn.query_row("SELECT COUNT(*) FROM tenants", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn get_tenant_by_id(&self, id: &str) -> Result<Option<Tenant>> {
        self.conn
            .query_row("SELECT * FROM tenants WHERE id = ?1", params![id], Self::row_to_tenant)
            .optional()
            .map_err(Into::into)
    }

    pub fn find_tenant_by_public_key(&self, public_key: &str) -> Result<Option<Tenant>> {
        self.conn
            .query_row(
                "SELECT * FROM tenants WHERE public_key = ?1 AND disabled_at IS NULL",
                params![public_key],
                Self::row_to_tenant,
            )
            .optional()
            .map_err(Into::into)
    }

    /// The *only* sanctioned way to resolve a tenant for an admin request: entirely
    /// from the presented secret token, never from any path parameter. See
    /// `docs/DESIGN.md` §10.1 for why this is structural, not a per-handler check.
    pub fn find_tenant_by_secret_token(&self, raw_token: &str) -> Result<Option<Tenant>> {
        let hash = hash_secret_token(raw_token);
        self.conn
            .query_row(
                "SELECT * FROM tenants WHERE secret_token_hash = ?1 AND disabled_at IS NULL",
                params![hash],
                Self::row_to_tenant,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn rotate_tenant_secret(&self, tenant_id: &str) -> Result<String> {
        let new_token = generate_secret_token();
        let new_hash = hash_secret_token(&new_token);
        let changed = self.conn.execute(
            "UPDATE tenants SET secret_token_hash = ?2 WHERE id = ?1",
            params![tenant_id, new_hash],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(new_token)
    }

    /// Updates only the fields the admin API allows a tenant to change about
    /// itself. `public_key`, key material, and `network` are deliberately absent -
    /// see `docs/DESIGN.md` §10.2 (rotate by creating a new tenant, not by mutating
    /// key material in place). Each field is `Option<Option<T>>`-free by design:
    /// `None` means "leave unchanged", so a partial PATCH body only touches the
    /// fields it actually included.
    pub fn update_tenant_config(&self, tenant_id: &str, patch: TenantConfigPatch) -> Result<()> {
        if let Some(origins) = &patch.allowed_origins {
            let json = serde_json::to_string(origins).unwrap();
            self.conn.execute(
                "UPDATE tenants SET allowed_origins = ?2 WHERE id = ?1",
                params![tenant_id, json],
            )?;
        }
        if let Some(v) = patch.confirmations_required {
            self.conn.execute(
                "UPDATE tenants SET confirmations_required = ?2 WHERE id = ?1",
                params![tenant_id, v as i64],
            )?;
        }
        if patch.zero_conf_max_piconero_set {
            self.conn.execute(
                "UPDATE tenants SET zero_conf_max_piconero = ?2 WHERE id = ?1",
                params![tenant_id, patch.zero_conf_max_piconero.map(|v| v as i64)],
            )?;
        }
        if let Some(v) = patch.order_expiry_seconds {
            self.conn.execute(
                "UPDATE tenants SET order_expiry_seconds = ?2 WHERE id = ?1",
                params![tenant_id, v],
            )?;
        }
        if patch.template_dir_set {
            self.conn.execute(
                "UPDATE tenants SET template_dir = ?2 WHERE id = ?1",
                params![tenant_id, patch.template_dir],
            )?;
        }
        Ok(())
    }

    /// Paginated, newest first, optionally filtered by status. `cursor` is the
    /// `created_at` of the last row from a previous page (exclusive) - simple and
    /// sufficient at v1 scale; see docs/DESIGN.md for why a cleverer keyset scheme
    /// isn't warranted yet.
    pub fn list_orders(
        &self,
        tenant_id: &str,
        status_filter: Option<OrderStatus>,
        limit: u32,
        cursor: Option<i64>,
    ) -> Result<Vec<Order>> {
        let status_str = status_filter.map(status_to_str);
        let mut stmt = self.conn.prepare(
            "SELECT * FROM orders
             WHERE tenant_id = ?1
               AND (?2 IS NULL OR status = ?2)
               AND (?3 IS NULL OR created_at < ?3)
             ORDER BY created_at DESC
             LIMIT ?4",
        )?;
        let rows = stmt
            .query_map(params![tenant_id, status_str, cursor, limit], Self::row_to_order)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The tenant ids the chain scanner should actually spend scalar-multiplication
    /// effort on this tick: those with at least one order still capable of
    /// receiving a *new* detected payment. See `docs/DESIGN.md` §7.3 for the
    /// motivation (Monero's stealth addresses make scanning cost per-tenant, so a
    /// tenant with nothing pending should cost the scanner nothing) and this
    /// method's own module-level discussion in `scanner.rs` for why this is a
    /// fresh query every tick rather than an incrementally-maintained cache: with
    /// every order mutation already serialized through the single
    /// `Arc<Mutex<Store>>`, a fresh read is both simpler and race-free by
    /// construction, and cheap enough (see `orders_status_tenant_idx`) that there's
    /// no real performance case for a cache that could instead drift out of sync.
    ///
    /// `Paid`/`Overpaid`/`Expired` are excluded on purpose: once every order for a
    /// tenant reaches one of those, there is nothing further for *new-match*
    /// scanning to find. This does not weaken double-spend protection for an
    /// already-`Paid` order - reorg reconciliation (`scanner::check_for_reorg_and_reconcile`)
    /// re-examines already-recorded payments directly via
    /// `find_payments_at_or_after_height`, entirely independent of tenant
    /// watchlist membership, so a `Paid` order can still be correctly walked back
    /// to `Partial` by a later-discovered double-spend even though its tenant left
    /// this list.
    /// Scoped by network as well as status: a multi-network instance (§DESIGN.md
    /// §7) scans each network with its own daemon client on its own tick, so the
    /// watchlist for "this tick, this network" must not include a tenant that
    /// happens to be active but belongs to a different chain - it has nothing to
    /// do with the daemon this call is about to use.
    pub fn active_tenant_ids(&self, network: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT o.tenant_id FROM orders o
             JOIN tenants t ON t.id = o.tenant_id
             WHERE o.status IN (?1, ?2, ?3, ?4) AND t.network = ?5",
        )?;
        let rows = stmt
            .query_map(
                params![
                    status_to_str(OrderStatus::Pending),
                    status_to_str(OrderStatus::Unconfirmed),
                    status_to_str(OrderStatus::Confirming),
                    status_to_str(OrderStatus::Partial),
                    network,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every order on `network` still in a non-terminal status - the same four
    /// statuses `active_tenant_ids` treats as active, one level down (orders rather
    /// than their tenants), served by the same `orders_status_tenant_idx (status,
    /// tenant_id)` index as a handful of index-range probes.
    ///
    /// The scanner needs this because an order's status is a function of the *current
    /// chain height*, not only of its payments: confirmations are derived as
    /// `current_height - block_height + 1` at recompute time and stored nowhere, and
    /// expiry is a function of wall-clock time. So an order whose payments haven't
    /// changed at all still needs recomputing every tick - otherwise a fully-paid
    /// order is recomputed exactly once, at one confirmation, and stays `confirming`
    /// forever, and an unpaid order sails past `expires_at` without ever becoming
    /// `expired`. Both were live bugs when the scanner recomputed only the orders
    /// whose transactions it matched during that same tick.
    pub fn non_terminal_order_ids(&self, network: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT o.id FROM orders o
             JOIN tenants t ON t.id = o.tenant_id
             WHERE o.status IN (?1, ?2, ?3, ?4) AND t.network = ?5",
        )?;
        let rows = stmt
            .query_map(
                params![
                    status_to_str(OrderStatus::Pending),
                    status_to_str(OrderStatus::Unconfirmed),
                    status_to_str(OrderStatus::Confirming),
                    status_to_str(OrderStatus::Partial),
                    network,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn disable_tenant(&self, tenant_id: &str, now: i64) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE tenants SET disabled_at = ?2 WHERE id = ?1",
            params![tenant_id, now],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Atomically claims the next unused minor index for a tenant and advances the
    /// counter, in one statement - this is what makes the "two orders never share a
    /// subaddress" property hold under concurrent order creation (backstopped by the
    /// `UNIQUE(tenant_id, minor_index)` constraint regardless).
    ///
    /// Order creation deliberately does *not* use this: an index claimed here and
    /// turned into an order row later leaves a window where the scanner considers an
    /// address scannable that no order can be attributed to. See
    /// `create_order_claiming_minor_index`, which advances the counter and inserts
    /// the order together.
    pub fn allocate_minor_index(&self, tenant_id: &str) -> Result<u32> {
        let allocated: i64 = self.conn.query_row(
            "UPDATE tenants SET next_minor_index = next_minor_index + 1
             WHERE id = ?1
             RETURNING next_minor_index - 1",
            params![tenant_id],
            |row| row.get(0),
        )?;
        Ok(allocated as u32)
    }

    /// The index `allocate_minor_index` would hand out next, without claiming it.
    /// Only useful in combination with `create_order_claiming_minor_index` - see
    /// that method for why order creation can't simply allocate first.
    pub fn peek_next_minor_index(&self, tenant_id: &str) -> Result<u32> {
        let next: i64 = self.conn.query_row(
            "SELECT next_minor_index FROM tenants WHERE id = ?1",
            params![tenant_id],
            |row| row.get(0),
        )?;
        Ok(next as u32)
    }

    /// Claims `expected_index` for `tenant_id` and inserts `new` as one atomic unit,
    /// returning `Ok(None)` (having changed nothing) if the tenant's counter has
    /// moved on since `peek_next_minor_index` reported that index.
    ///
    /// The atomicity is the point. `next_minor_index` is what the scanner reads to
    /// decide *which subaddresses it scans* (`0..next_minor_index`), so the moment it
    /// is advanced, the corresponding subaddress becomes scannable. If the order row
    /// doesn't exist yet at that moment - as it didn't while order creation allocated
    /// an index, released the store lock to `await` a subaddress derivation, and only
    /// then inserted the order - a scanner tick landing in that window matches an
    /// output against an index that `find_order_by_minor_index` can't resolve, and
    /// drops the match. For a mempool sighting the next tick re-finds it; for a
    /// sighting inside a mined block it is lost for good, because blocks are scanned
    /// exactly once. Advancing the counter and creating the order together closes
    /// that window entirely.
    ///
    /// Callers derive the subaddress for the *peeked* index before calling this and
    /// retry on `Ok(None)`; a losing racer costs one extra derivation and burns no
    /// index (the conditional UPDATE leaves the counter untouched when it doesn't
    /// match), so two concurrent creations can never end up sharing an address.
    pub fn create_order_claiming_minor_index(&self, expected_index: u32, new: NewOrder) -> Result<Option<Order>> {
        let tx = self.conn.unchecked_transaction()?;
        let claimed = tx.execute(
            "UPDATE tenants SET next_minor_index = next_minor_index + 1
             WHERE id = ?1 AND next_minor_index = ?2",
            params![new.tenant_id, expected_index],
        )?;
        if claimed == 0 {
            return Ok(None);
        }
        let id = new_id("pay");
        Self::insert_order(&tx, &id, &new)?;
        tx.commit()?;
        Ok(Some(self.get_order_by_id(&id)?.ok_or(StoreError::NotFound)?))
    }

    // -- Orders -----------------------------------------------------------

    /// Free function over a bare `&Connection` so both `create_order` and
    /// `create_order_claiming_minor_index` (which runs inside a `Transaction`) can
    /// share one copy of the INSERT.
    fn insert_order(conn: &Connection, id: &str, new: &NewOrder) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO orders (id, tenant_id, merchant_order_id, minor_index, address,
                fiat_currency, fiat_amount, exchange_rate, xmr_amount_piconero,
                description, created_at, expires_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?11)",
            params![
                id,
                new.tenant_id,
                new.merchant_order_id,
                new.minor_index,
                new.address,
                new.fiat_currency,
                new.fiat_amount,
                new.exchange_rate,
                new.xmr_amount_piconero as i64,
                new.description,
                new.created_at,
                new.expires_at,
            ],
        )?;
        Ok(())
    }

    pub fn create_order(&self, new: NewOrder) -> Result<Order> {
        let id = new_id("pay");
        Self::insert_order(&self.conn, &id, &new)?;
        self.get_order_by_id(&id)?.ok_or(StoreError::NotFound)
    }

    fn row_to_order(row: &rusqlite::Row) -> rusqlite::Result<Order> {
        let status_str: String = row.get("status")?;
        Ok(Order {
            id: row.get("id")?,
            tenant_id: row.get("tenant_id")?,
            merchant_order_id: row.get("merchant_order_id")?,
            minor_index: row.get::<_, i64>("minor_index")? as u32,
            address: row.get("address")?,
            fiat_currency: row.get("fiat_currency")?,
            fiat_amount: row.get("fiat_amount")?,
            exchange_rate: row.get("exchange_rate")?,
            xmr_amount_piconero: row.get::<_, i64>("xmr_amount_piconero")? as u64,
            amount_received_piconero: row.get::<_, i64>("amount_received_piconero")? as u64,
            status: status_from_str(&status_str),
            confirmations: row.get::<_, i64>("confirmations")? as u64,
            double_spend_detected_at: row.get("double_spend_detected_at")?,
            refund_address: row.get("refund_address")?,
            description: row.get("description")?,
            created_at: row.get("created_at")?,
            expires_at: row.get("expires_at")?,
            updated_at: row.get("updated_at")?,
        })
    }

    fn get_order_by_id(&self, id: &str) -> Result<Option<Order>> {
        self.conn
            .query_row("SELECT * FROM orders WHERE id = ?1", params![id], Self::row_to_order)
            .optional()
            .map_err(Into::into)
    }

    /// Routes a scanner match (which only knows a subaddress minor index) back to
    /// the order that index was issued for.
    pub fn find_order_by_minor_index(&self, tenant_id: &str, minor_index: u32) -> Result<Option<Order>> {
        self.conn
            .query_row(
                "SELECT * FROM orders WHERE tenant_id = ?1 AND minor_index = ?2",
                params![tenant_id, minor_index],
                Self::row_to_order,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Scoped by `tenant_id` in the query itself - the IDOR-prevention rule from
    /// `docs/DESIGN.md` §10.1 applied at the row level. A payment_id belonging to a
    /// different tenant must come back as `Ok(None)`, indistinguishable from a
    /// nonexistent one.
    pub fn get_order(&self, tenant_id: &str, payment_id: &str) -> Result<Option<Order>> {
        self.conn
            .query_row(
                "SELECT * FROM orders WHERE id = ?1 AND tenant_id = ?2",
                params![payment_id, tenant_id],
                Self::row_to_order,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Scoped by `tenant_id`, same IDOR-prevention rule as `get_order`. Records
    /// only - nothing in this system ever sends to a refund address (§DESIGN.md 3).
    pub fn set_refund_address(&self, tenant_id: &str, payment_id: &str, refund_address: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE orders SET refund_address = ?3 WHERE id = ?1 AND tenant_id = ?2",
            params![payment_id, tenant_id, refund_address],
        )?;
        Ok(changed > 0)
    }

    // -- Payments / reorg bookkeeping --------------------------------------

    /// Idempotent: relies on `UNIQUE(order_id, txid, output_index)`. Returns `true`
    /// if this call actually inserted a new row (as opposed to the mempool-polling
    /// scanner re-reporting a transaction it already recorded).
    ///
    /// The conflict clause is `DO UPDATE`, not `DO NOTHING`, specifically so a
    /// mempool-first payment can still learn its block height. The scanner polls the
    /// mempool roughly every second, so in practice *every* real payment is recorded
    /// with `block_height = NULL` before it is ever seen in a block; `DO NOTHING`
    /// then silently discarded the `Some(height)` the block scan supplied moments
    /// later, permanently stranding the payment at zero confirmations and invisible
    /// to `find_payments_at_or_after_height` (which filters on `block_height >= ?`).
    /// `COALESCE` makes the update one-way - a later mempool re-sighting of an
    /// already-mined transaction can never null out a height that is already known -
    /// and the `WHERE` guard stops a duplicate insert from resurrecting a payment
    /// that reorg reconciliation has already voided.
    #[allow(clippy::too_many_arguments)]
    pub fn record_payment_match(
        &self,
        order_id: &str,
        txid: &str,
        output_index: i64,
        amount_piconero: u64,
        key_images_json: &str,
        first_seen_at: i64,
        block_height: Option<i64>,
    ) -> Result<bool> {
        // Whether this is a genuinely new row has to be established before the
        // upsert: with `DO UPDATE`, `execute`'s changed-row count is 1 for both
        // paths and can't distinguish them. A separate read is safe here because
        // every write to this database is already serialized through one writer
        // (see this module's header comment).
        let already_present: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM order_payments WHERE order_id = ?1 AND txid = ?2 AND output_index = ?3)",
            params![order_id, txid, output_index],
            |row| row.get(0),
        )?;
        self.conn.execute(
            "INSERT INTO order_payments (order_id, txid, output_index, amount_piconero,
                key_images_json, first_seen_at, block_height)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(order_id, txid, output_index) DO UPDATE SET
                 block_height = COALESCE(excluded.block_height, order_payments.block_height)
             WHERE order_payments.voided_at IS NULL",
            params![
                order_id,
                txid,
                output_index,
                amount_piconero as i64,
                key_images_json,
                first_seen_at,
                block_height
            ],
        )?;
        Ok(!already_present)
    }

    /// Used when a reorg moves a previously-confirmed payment to a different height,
    /// or drops it back into the mempool (`new_height = None`). Addressed by
    /// `(order_id, txid, output_index)` - the same key the uniqueness constraint
    /// uses - so that when two orders legitimately share one output (see migration
    /// 0004) reconciling one of them never rewrites the other's row.
    pub fn update_payment_block_height(
        &self,
        order_id: &str,
        txid: &str,
        output_index: i64,
        new_height: Option<i64>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE order_payments SET block_height = ?4
             WHERE order_id = ?1 AND txid = ?2 AND output_index = ?3 AND voided_at IS NULL",
            params![order_id, txid, output_index, new_height],
        )?;
        Ok(())
    }

    /// Marks a payment permanently reversed. Never called on ambiguous evidence -
    /// only once `is_key_image_spent` affirmatively proves a different, unrelated
    /// transaction consumed the same inputs (see `docs/DESIGN.md` §7.5). Returns
    /// `false` if the row didn't exist or was already voided (idempotent).
    pub fn void_payment(&self, order_id: &str, txid: &str, output_index: i64, voided_at: i64) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE order_payments SET voided_at = ?4
             WHERE order_id = ?1 AND txid = ?2 AND output_index = ?3 AND voided_at IS NULL",
            params![order_id, txid, output_index, voided_at],
        )?;
        Ok(changed > 0)
    }

    /// Clears `voided_at` on a payment that reorg reconciliation had previously
    /// written off, because the transaction it records has since returned to the
    /// canonical chain (its replacement was itself reorged out). Deliberately does
    /// *not* touch `orders.double_spend_detected_at`, which the schema defines as
    /// sticky: "a double-spend was once observed on this order" stays true forever,
    /// independently of whether the payment ultimately stood. Returns `false` if the
    /// row didn't exist or wasn't voided (idempotent).
    pub fn unvoid_payment(&self, order_id: &str, txid: &str, output_index: i64) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE order_payments SET voided_at = NULL
             WHERE order_id = ?1 AND txid = ?2 AND output_index = ?3 AND voided_at IS NOT NULL",
            params![order_id, txid, output_index],
        )?;
        Ok(changed > 0)
    }

    pub fn get_valid_payments(&self, order_id: &str) -> Result<Vec<OrderPaymentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM order_payments WHERE order_id = ?1 AND voided_at IS NULL",
        )?;
        let rows = stmt
            .query_map(params![order_id], Self::row_to_payment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every payment (voided or not) for an order - the audit trail a merchant can
    /// inspect for "why does this show partial" or "when was this double-spent".
    pub fn get_all_payments(&self, order_id: &str) -> Result<Vec<OrderPaymentRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM order_payments WHERE order_id = ?1 ORDER BY first_seen_at")?;
        let rows = stmt
            .query_map(params![order_id], Self::row_to_payment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn row_to_payment(row: &rusqlite::Row) -> rusqlite::Result<OrderPaymentRow> {
        Ok(OrderPaymentRow {
            id: row.get("id")?,
            order_id: row.get("order_id")?,
            txid: row.get("txid")?,
            output_index: row.get("output_index")?,
            amount_piconero: row.get::<_, i64>("amount_piconero")? as u64,
            key_images_json: row.get("key_images_json")?,
            first_seen_at: row.get("first_seen_at")?,
            block_height: row.get("block_height")?,
            voided_at: row.get("voided_at")?,
        })
    }

    /// Every non-voided payment on the given network that a reorg detected at
    /// `min_height` needs to re-evaluate: those recorded at or above that height,
    /// *plus* those with no height at all. Scoped by network (via a join through
    /// `orders`/`tenants`), not just height: heights are only comparable within one
    /// chain, so without this a reorg on one network would incorrectly re-examine
    /// payments belonging to a completely unrelated chain that happens to share the
    /// same numbers.
    ///
    /// The `block_height IS NULL` half is not an optimisation-avoidance nicety, it
    /// closes a one-way trapdoor. A `NULL` height means "seen, not in any block" -
    /// which is exactly what reconciliation itself writes when `locate_transaction`
    /// reports `InPool`. Filtering on `block_height >= ?` alone (SQL three-valued
    /// logic makes `NULL >= n` false, never true) meant that the moment a reorg
    /// pushed a payment back into the mempool, no later reconciliation pass could
    /// ever see that row again: its transaction could subsequently be proven
    /// double-spent and it would still never be voided, silently propping up an
    /// order's received total forever. Unconfirmed payments are inherently "above"
    /// any block height, so re-examining them is also just the correct reading of
    /// the question this query asks.
    pub fn find_payments_at_or_after_height(&self, network: &str, min_height: u64) -> Result<Vec<OrderPaymentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT op.* FROM order_payments op
             JOIN orders o ON o.id = op.order_id
             JOIN tenants t ON t.id = o.tenant_id
             WHERE op.voided_at IS NULL
               AND (op.block_height >= ?1 OR op.block_height IS NULL)
               AND t.network = ?2",
        )?;
        let rows = stmt
            .query_map(params![min_height as i64, network], Self::row_to_payment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The voided counterpart of `find_payments_at_or_after_height`: payments a
    /// previous reconciliation pass wrote off, whose recorded height falls in the
    /// range a newly-detected reorg has just invalidated. Voiding is not evidence
    /// that stays true forever - the replacement transaction that proved the
    /// double-spend can itself be reorged out, putting the original back on the
    /// canonical chain - so these rows have to be re-examined rather than treated as
    /// permanently settled. Kept as a separate query from the non-voided one because
    /// the two get genuinely different treatment (re-locate and possibly un-void, vs.
    /// re-locate and possibly void). Includes `block_height IS NULL` rows for the
    /// same reason its non-voided counterpart does - see that method's doc comment.
    pub fn find_voided_payments_at_or_after_height(
        &self,
        network: &str,
        min_height: u64,
    ) -> Result<Vec<OrderPaymentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT op.* FROM order_payments op
             JOIN orders o ON o.id = op.order_id
             JOIN tenants t ON t.id = o.tenant_id
             WHERE op.voided_at IS NOT NULL
               AND (op.block_height >= ?1 OR op.block_height IS NULL)
               AND t.network = ?2",
        )?;
        let rows = stmt
            .query_map(params![min_height as i64, network], Self::row_to_payment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every non-voided payment on `network` that is still mempool-only - matched
    /// from a transaction the scanner has never seen in a block. These are the rows
    /// a plain (reorg-free) double-spend attacks: the customer's transaction is
    /// broadcast, matched at zero confirmations, and then simply never mined because
    /// a *different* transaction spending the same inputs won instead. No block hash
    /// ever changes in that story, so reorg detection never fires and
    /// `find_payments_at_or_after_height` is never called - which is why these rows
    /// need their own sweep (`scanner::check_vanished_mempool_payments`) rather than
    /// riding along with reorg reconciliation.
    ///
    /// Scoped by network for the same reason its height-based counterparts are: one
    /// network's daemon must never be asked about another chain's transactions.
    pub fn find_unconfirmed_payments(&self, network: &str) -> Result<Vec<OrderPaymentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT op.* FROM order_payments op
             JOIN orders o ON o.id = op.order_id
             JOIN tenants t ON t.id = o.tenant_id
             WHERE op.voided_at IS NULL
               AND op.block_height IS NULL
               AND t.network = ?1",
        )?;
        let rows = stmt
            .query_map(params![network], Self::row_to_payment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn find_payment_by_key_image(&self, key_image_hex: &str) -> Result<Vec<OrderPaymentRow>> {
        // key_images_json is a small JSON array (typically 1-2 entries); a LIKE scan
        // is adequate at v1 scale and avoids a separate normalized table for what is
        // purely reorg-bookkeeping metadata (see docs/DESIGN.md §8.1).
        let pattern = format!("%\"{key_image_hex}\"%");
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM order_payments WHERE key_images_json LIKE ?1 AND voided_at IS NULL")?;
        let rows = stmt
            .query_map(params![pattern], Self::row_to_payment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Recomputes `status`, `confirmations`, and `amount_received_piconero` from the
    /// order's currently-valid payments and persists the result. This is the *only*
    /// place `orders.status` is written - see `docs/DESIGN.md` §7.6. Returns
    /// `(old_status, new_status)` so the caller can decide whether a status-transition
    /// webhook event is warranted.
    pub fn recompute_order_status(
        &self,
        order_id: &str,
        current_height: u64,
        now: i64,
    ) -> Result<(OrderStatus, OrderStatus)> {
        let order = self.get_order_by_id(order_id)?.ok_or(StoreError::NotFound)?;
        let tenant = self.get_tenant_by_id(&order.tenant_id)?.ok_or(StoreError::NotFound)?;
        let valid = self.get_valid_payments(order_id)?;

        let views: Vec<PaymentView> = valid
            .iter()
            .map(|p| {
                let confirmations = match p.block_height {
                    Some(h) if current_height >= h as u64 => current_height - h as u64 + 1,
                    _ => 0,
                };
                PaymentView {
                    amount_piconero: p.amount_piconero,
                    confirmations,
                    is_zero_conf: p.block_height.is_none(),
                }
            })
            .collect();

        let total: u64 = views.iter().map(|v| v.amount_piconero).sum();
        let min_confirmations = views.iter().map(|v| v.confirmations).min().unwrap_or(0);

        let new_status = derive_status(
            &views,
            StatusInputs {
                xmr_amount_piconero: order.xmr_amount_piconero,
                confirmations_required: tenant.confirmations_required,
                zero_conf_max_piconero: tenant.zero_conf_max_piconero,
                now,
                expires_at: order.expires_at,
            },
        );

        self.conn.execute(
            "UPDATE orders SET status = ?2, confirmations = ?3, amount_received_piconero = ?4, updated_at = ?5
             WHERE id = ?1",
            params![order_id, status_to_str(new_status), min_confirmations as i64, total as i64, now],
        )?;

        Ok((order.status, new_status))
    }

    /// Sticky, first-occurrence-only - see schema comment on `double_spend_detected_at`.
    pub fn mark_double_spend_detected(&self, order_id: &str, at: i64) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE orders SET double_spend_detected_at = ?2 WHERE id = ?1 AND double_spend_detected_at IS NULL",
            params![order_id, at],
        )?;
        Ok(changed > 0)
    }

    // -- Reorg bookkeeping --------------------------------------------------

    /// The highest height the scanner has recorded a hash for *on this network*, or
    /// `None` if it has never scanned a block on it yet. Used at boot (per network)
    /// to decide where to resume: rather than replaying the entire chain history on
    /// first run, the scanner seeds this at the current tip and only scans forward
    /// from there (see `scanner::run_scan_tick`). Scoped by network because heights
    /// are meaningless across chains - mainnet height 100 and stagenet height 100
    /// are unrelated blocks.
    pub fn max_scanned_height(&self, network: &str) -> Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT MAX(height) FROM scanned_blocks WHERE network = ?1",
                params![network],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map(|opt| opt.map(|h| h as u64))
            .map_err(Into::into)
    }

    /// Not scoped by tenant - internal orchestration use only (the scanner needs to
    /// route a bare `order_id` back to its tenant to look up webhooks). Never
    /// expose this through the HTTP layer; every externally-reachable order lookup
    /// must go through `get_order`'s tenant-scoped query instead.
    pub fn get_order_tenant_id(&self, order_id: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT tenant_id FROM orders WHERE id = ?1", params![order_id], |row| row.get(0))
            .optional()
            .map_err(Into::into)
    }

    pub fn get_scanned_block_hash(&self, network: &str, height: u64) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT block_hash FROM scanned_blocks WHERE network = ?1 AND height = ?2",
                params![network, height as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn set_scanned_block(&self, network: &str, height: u64, hash: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO scanned_blocks (network, height, block_hash) VALUES (?1, ?2, ?3)
             ON CONFLICT(network, height) DO UPDATE SET block_hash = excluded.block_hash",
            params![network, height as i64, hash],
        )?;
        Ok(())
    }

    /// Forgets every block at or above `height` on this network, walking
    /// `max_scanned_height` back to `height - 1` so the next tick's forward scan
    /// naturally re-covers `height..tip`.
    ///
    /// Called once a reorg starting at `height` has been fully reconciled. Without
    /// it, reconciliation fixes up the payments it already knew about but nothing
    /// ever *scans* the replacement blocks, so a payment that exists only in the new
    /// chain - the transaction was rebroadcast and mined into the fork that won - is
    /// never seen at all: the scanner's high-water mark is still above those heights,
    /// and blocks below it are never revisited.
    pub fn forget_scanned_blocks_at_or_above(&self, network: &str, height: u64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM scanned_blocks WHERE network = ?1 AND height >= ?2",
            params![network, height as i64],
        )?;
        Ok(())
    }

    pub fn prune_scanned_blocks_below(&self, network: &str, min_height: u64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM scanned_blocks WHERE network = ?1 AND height < ?2",
            params![network, min_height as i64],
        )?;
        Ok(())
    }

    // -- Webhooks -------------------------------------------------------

    pub fn create_webhook(
        &self,
        tenant_id: &str,
        url: &str,
        extra_headers_json: &str,
        signing_secret: &str,
        now: i64,
    ) -> Result<Webhook> {
        let id = new_id("wh");
        self.conn.execute(
            "INSERT INTO webhooks (id, tenant_id, url, extra_headers, signing_secret, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, tenant_id, url, extra_headers_json, signing_secret, now],
        )?;
        Ok(Webhook {
            id,
            tenant_id: tenant_id.to_string(),
            url: url.to_string(),
            extra_headers: extra_headers_json.to_string(),
            signing_secret: signing_secret.to_string(),
            enabled: true,
            created_at: now,
        })
    }

    pub fn list_webhooks(&self, tenant_id: &str) -> Result<Vec<Webhook>> {
        let mut stmt = self.conn.prepare("SELECT * FROM webhooks WHERE tenant_id = ?1")?;
        let rows = stmt
            .query_map(params![tenant_id], |row| {
                Ok(Webhook {
                    id: row.get("id")?,
                    tenant_id: row.get("tenant_id")?,
                    url: row.get("url")?,
                    extra_headers: row.get("extra_headers")?,
                    signing_secret: row.get("signing_secret")?,
                    enabled: row.get::<_, i64>("enabled")? != 0,
                    created_at: row.get("created_at")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Scoped by `tenant_id`, same IDOR-prevention rule as `get_order`. Returns
    /// `false` (not an error) if the webhook doesn't exist or belongs to a different
    /// tenant - the two are indistinguishable from the caller's perspective.
    pub fn delete_webhook(&self, tenant_id: &str, webhook_id: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM webhooks WHERE id = ?1 AND tenant_id = ?2",
            params![webhook_id, tenant_id],
        )?;
        Ok(changed > 0)
    }

    pub fn enqueue_webhook_delivery(
        &self,
        webhook_id: &str,
        order_id: &str,
        event_type: &str,
        payload_json: &str,
        next_attempt_at: i64,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO webhook_deliveries (webhook_id, order_id, event_type, payload_json, next_attempt_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![webhook_id, order_id, event_type, payload_json, next_attempt_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// One delivery attempt's worth of everything the delivery worker needs,
    /// joined from `webhook_deliveries` and `webhooks` in one query so the worker
    /// never has to look up the owning webhook separately per row.
    pub fn due_webhook_deliveries(&self, now: i64, limit: u32) -> Result<Vec<DueDelivery>> {
        let mut stmt = self.conn.prepare(
            "SELECT d.id, d.webhook_id, d.order_id, d.event_type, d.payload_json, d.attempt_count,
                    w.url, w.extra_headers, w.signing_secret
             FROM webhook_deliveries d
             JOIN webhooks w ON w.id = d.webhook_id
             WHERE d.delivered_at IS NULL AND d.next_attempt_at <= ?1 AND w.enabled = 1
             ORDER BY d.next_attempt_at
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![now, limit], |row| {
                Ok(DueDelivery {
                    delivery_id: row.get(0)?,
                    webhook_id: row.get(1)?,
                    order_id: row.get(2)?,
                    event_type: row.get(3)?,
                    payload_json: row.get(4)?,
                    attempt_count: row.get::<_, i64>(5)? as u32,
                    url: row.get(6)?,
                    extra_headers_json: row.get(7)?,
                    signing_secret: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn mark_webhook_delivered(&self, delivery_id: i64, response_status: u16, at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE webhook_deliveries SET delivered_at = ?2, last_attempted_at = ?2, last_response_status = ?3
             WHERE id = ?1",
            params![delivery_id, at, response_status as i64],
        )?;
        Ok(())
    }

    pub fn schedule_webhook_retry(
        &self,
        delivery_id: i64,
        next_attempt_at: i64,
        response_status: Option<u16>,
        error: Option<&str>,
        at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE webhook_deliveries
             SET attempt_count = attempt_count + 1,
                 next_attempt_at = ?2,
                 last_attempted_at = ?3,
                 last_response_status = ?4,
                 last_error = ?5
             WHERE id = ?1",
            params![delivery_id, next_attempt_at, at, response_status.map(|s| s as i64), error],
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DueDelivery {
    pub delivery_id: i64,
    pub webhook_id: String,
    pub order_id: String,
    pub event_type: String,
    pub payload_json: String,
    pub attempt_count: u32,
    pub url: String,
    pub extra_headers_json: String,
    pub signing_secret: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_tenant(store: &Store) -> CreatedTenant {
        store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![0u8; 64],
                    primary_address: "4addr".into(),
                    network: "mainnet".into(),
                    allowed_origins: vec!["https://merchant.example".into()],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap()
    }

    fn new_order(store: &Store, tenant_id: &str, minor_index: u32) -> Order {
        store
            .create_order(NewOrder {
                tenant_id: tenant_id.to_string(),
                merchant_order_id: None,
                minor_index,
                address: format!("sub_{minor_index}"),
                fiat_currency: "USD".into(),
                fiat_amount: "25.00".into(),
                exchange_rate: "0.0067".into(),
                xmr_amount_piconero: 100,
                description: None,
                created_at: 1000,
                expires_at: 2000,
            })
            .unwrap()
    }

    #[test]
    fn list_active_tenants_excludes_disabled_ones() {
        let store = Store::open_in_memory().unwrap();
        let a = new_tenant(&store);
        let b = new_tenant(&store);
        assert_eq!(store.count_tenants().unwrap(), 2);

        store.disable_tenant(&b.tenant.id, 2000).unwrap();
        let active = store.list_active_tenants().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, a.tenant.id);
        // Disabling doesn't delete the row - count_tenants includes it still.
        assert_eq!(store.count_tenants().unwrap(), 2);
    }

    #[test]
    fn reopening_an_existing_database_file_does_not_reapply_migrations() {
        // Direct regression test for a real bug: `open_file` used to re-run the raw
        // `CREATE TABLE` migration SQL unconditionally, which crashed with "table
        // already exists" the moment the server was restarted against a database it
        // had already created - caught only by actually restarting the compiled
        // binary, since every other test in this file opens a fresh `:memory:` db
        // exactly once and would never exercise a second `open_file` call against
        // the same path.
        let path = std::env::temp_dir().join(format!("moneropay_test_{}.db", Uuid::new_v4()));
        let path_str = path.to_str().unwrap();

        let store = Store::open_file(path_str).unwrap();
        let created = new_tenant(&store);
        drop(store);

        // Reopening must not panic or error, and must see the data the first
        // connection wrote.
        let reopened = Store::open_file(path_str).unwrap();
        let refetched = reopened.get_tenant_by_id(&created.tenant.id).unwrap();
        assert_eq!(refetched.unwrap().id, created.tenant.id);
        drop(reopened);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn create_and_lookup_tenant_by_public_key_and_secret_token() {
        let store = Store::open_in_memory().unwrap();
        let created = new_tenant(&store);

        let by_pk = store.find_tenant_by_public_key(&created.tenant.public_key).unwrap();
        assert_eq!(by_pk.unwrap().id, created.tenant.id);

        let by_secret = store.find_tenant_by_secret_token(&created.secret_token).unwrap();
        assert_eq!(by_secret.unwrap().id, created.tenant.id);

        assert!(store.find_tenant_by_secret_token("sk_wrong").unwrap().is_none());
    }

    #[test]
    fn rotated_secret_invalidates_the_old_token() {
        let store = Store::open_in_memory().unwrap();
        let created = new_tenant(&store);
        let new_secret = store.rotate_tenant_secret(&created.tenant.id).unwrap();

        assert!(store.find_tenant_by_secret_token(&created.secret_token).unwrap().is_none());
        assert!(store.find_tenant_by_secret_token(&new_secret).unwrap().is_some());
    }

    #[test]
    fn disabled_tenant_is_not_found_by_public_key_or_secret() {
        let store = Store::open_in_memory().unwrap();
        let created = new_tenant(&store);
        store.disable_tenant(&created.tenant.id, 2000).unwrap();

        assert!(store.find_tenant_by_public_key(&created.tenant.public_key).unwrap().is_none());
        assert!(store.find_tenant_by_secret_token(&created.secret_token).unwrap().is_none());
    }

    #[test]
    fn minor_index_allocation_starts_at_one_and_increments() {
        let store = Store::open_in_memory().unwrap();
        let created = new_tenant(&store);
        assert_eq!(store.allocate_minor_index(&created.tenant.id).unwrap(), 1);
        assert_eq!(store.allocate_minor_index(&created.tenant.id).unwrap(), 2);
        assert_eq!(store.allocate_minor_index(&created.tenant.id).unwrap(), 3);
    }

    #[test]
    fn concurrent_minor_index_allocation_never_duplicates() {
        // Direct test of docs/TESTING.md §6's top concurrency requirement: N
        // concurrent order-creation requests for one tenant must never allocate the
        // same minor_index. A Mutex-guarded Store is a legitimate, simple
        // realization of "single writer" for SQLite (which disallows concurrent
        // writers regardless) - this proves the allocation logic itself is correct
        // under real concurrent access, not just sequential calls.
        let store = Store::open_in_memory().unwrap();
        let created = new_tenant(&store);
        let tenant_id = created.tenant.id.clone();
        let shared = store.into_shared();

        let threads: Vec<_> = (0..50)
            .map(|_| {
                let shared = Arc::clone(&shared);
                let tenant_id = tenant_id.clone();
                std::thread::spawn(move || shared.lock().unwrap().allocate_minor_index(&tenant_id).unwrap())
            })
            .collect();

        let mut indices: Vec<u32> = threads.into_iter().map(|h| h.join().unwrap()).collect();
        indices.sort_unstable();
        let mut deduped = indices.clone();
        deduped.dedup();
        assert_eq!(indices.len(), deduped.len(), "duplicate minor_index allocated under concurrency");
        assert_eq!(indices, (1..=50).collect::<Vec<_>>());
    }

    #[test]
    fn get_order_is_scoped_by_tenant_and_returns_none_across_tenants() {
        // Row-level IDOR test: tenant A's id plus tenant B's real payment_id must
        // come back as None, not tenant B's order. See docs/DESIGN.md §10.1.
        let store = Store::open_in_memory().unwrap();
        let tenant_a = new_tenant(&store);
        let tenant_b = new_tenant(&store);
        let order_b = new_order(&store, &tenant_b.tenant.id, 1);

        assert!(store.get_order(&tenant_a.tenant.id, &order_b.id).unwrap().is_none());
        assert!(store.get_order(&tenant_b.tenant.id, &order_b.id).unwrap().is_some());
    }

    #[test]
    fn delete_webhook_is_scoped_by_tenant() {
        let store = Store::open_in_memory().unwrap();
        let tenant_a = new_tenant(&store);
        let tenant_b = new_tenant(&store);
        let webhook_b = store
            .create_webhook(&tenant_b.tenant.id, "https://b.example/hook", "{}", "secret", 1000)
            .unwrap();

        assert!(!store.delete_webhook(&tenant_a.tenant.id, &webhook_b.id).unwrap());
        assert_eq!(store.list_webhooks(&tenant_b.tenant.id).unwrap().len(), 1);
        assert!(store.delete_webhook(&tenant_b.tenant.id, &webhook_b.id).unwrap());
        assert_eq!(store.list_webhooks(&tenant_b.tenant.id).unwrap().len(), 0);
    }

    #[test]
    fn duplicate_payment_match_is_idempotent() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        let first = store
            .record_payment_match(&order.id, "txabc", 0, 100, "[]", 1500, None)
            .unwrap();
        let second = store
            .record_payment_match(&order.id, "txabc", 0, 100, "[]", 1600, None)
            .unwrap();

        assert!(first);
        assert!(!second, "re-reporting the same output must be a no-op, not a new row");
        assert_eq!(store.get_all_payments(&order.id).unwrap().len(), 1);
    }

    #[test]
    fn recompute_status_reflects_new_payment_and_persists() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        assert_eq!(order.status, OrderStatus::Pending);

        store
            .record_payment_match(&order.id, "txabc", 0, 100, "[]", 1500, Some(50))
            .unwrap();
        let (old, new) = store.recompute_order_status(&order.id, 59, 1600).unwrap(); // 10 confirmations
        assert_eq!(old, OrderStatus::Pending);
        assert_eq!(new, OrderStatus::Paid);

        let refetched = store.get_order(&tenant.tenant.id, &order.id).unwrap().unwrap();
        assert_eq!(refetched.status, OrderStatus::Paid);
        assert_eq!(refetched.amount_received_piconero, 100);
        assert_eq!(refetched.confirmations, 10);
    }

    #[test]
    fn voiding_one_of_two_payments_drops_status_to_partial_and_recomputes_total() {
        // The exact two-transaction scenario from design review, exercised through
        // the store: two payments summing to the expected amount reach `paid`;
        // voiding one drops the order to `partial` with the total recomputed from
        // the survivor alone.
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        store.record_payment_match(&order.id, "tx_a", 0, 60, "[\"ki_a\"]", 1500, Some(50)).unwrap();
        store.record_payment_match(&order.id, "tx_b", 0, 40, "[\"ki_b\"]", 1500, Some(50)).unwrap();
        let (_, paid) = store.recompute_order_status(&order.id, 59, 1600).unwrap();
        assert_eq!(paid, OrderStatus::Paid);

        assert!(store.void_payment(&order.id, "tx_a", 0, 1700).unwrap());
        assert!(store.mark_double_spend_detected(&order.id, 1700).unwrap());
        let (before, after) = store.recompute_order_status(&order.id, 59, 1700).unwrap();
        assert_eq!(before, OrderStatus::Paid);
        assert_eq!(after, OrderStatus::Partial);

        let refetched = store.get_order(&tenant.tenant.id, &order.id).unwrap().unwrap();
        assert_eq!(refetched.amount_received_piconero, 40);
        assert!(refetched.double_spend_detected_at.is_some());
    }

    #[test]
    fn double_spend_flag_is_independent_of_status_when_redundant_payment_covers_order() {
        // The other half of the same scenario: voiding one payment when a third,
        // redundant one still covers the order must leave status at `paid` while
        // still recording that a double-spend occurred.
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        store.record_payment_match(&order.id, "tx_a", 0, 60, "[\"ki_a\"]", 1500, Some(50)).unwrap();
        store.record_payment_match(&order.id, "tx_c", 0, 100, "[\"ki_c\"]", 1500, Some(50)).unwrap();
        let (_, before_void) = store.recompute_order_status(&order.id, 59, 1600).unwrap();
        assert_eq!(before_void, OrderStatus::Overpaid); // 160 total against an expected 100

        store.void_payment(&order.id, "tx_a", 0, 1700).unwrap();
        store.mark_double_spend_detected(&order.id, 1700).unwrap();
        let (_, after) = store.recompute_order_status(&order.id, 59, 1700).unwrap();

        // tx_c alone (100) exactly covers the expected amount - still `paid`, not
        // downgraded, even though a double-spend genuinely occurred on this order.
        assert_eq!(after, OrderStatus::Paid);
        let refetched = store.get_order(&tenant.tenant.id, &order.id).unwrap().unwrap();
        assert!(refetched.double_spend_detected_at.is_some());
    }

    #[test]
    fn mark_double_spend_detected_is_sticky_first_occurrence_only() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        assert!(store.mark_double_spend_detected(&order.id, 1000).unwrap());
        assert!(!store.mark_double_spend_detected(&order.id, 2000).unwrap(), "must not overwrite the first timestamp");

        let refetched = store.get_order(&tenant.tenant.id, &order.id).unwrap().unwrap();
        assert_eq!(refetched.double_spend_detected_at, Some(1000));
    }

    #[test]
    fn update_tenant_config_only_touches_included_fields() {
        let store = Store::open_in_memory().unwrap();
        let created = new_tenant(&store);

        store
            .update_tenant_config(
                &created.tenant.id,
                TenantConfigPatch {
                    confirmations_required: Some(3),
                    ..Default::default()
                },
            )
            .unwrap();
        let refetched = store.get_tenant_by_id(&created.tenant.id).unwrap().unwrap();
        assert_eq!(refetched.confirmations_required, 3);
        assert_eq!(refetched.allowed_origins, created.tenant.allowed_origins); // untouched

        store
            .update_tenant_config(
                &created.tenant.id,
                TenantConfigPatch {
                    zero_conf_max_piconero_set: true,
                    zero_conf_max_piconero: Some(500),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            store.get_tenant_by_id(&created.tenant.id).unwrap().unwrap().zero_conf_max_piconero,
            Some(500)
        );

        // Explicitly clearing back to NULL requires the _set flag.
        store
            .update_tenant_config(
                &created.tenant.id,
                TenantConfigPatch { zero_conf_max_piconero_set: true, zero_conf_max_piconero: None, ..Default::default() },
            )
            .unwrap();
        assert_eq!(
            store.get_tenant_by_id(&created.tenant.id).unwrap().unwrap().zero_conf_max_piconero,
            None
        );
    }

    #[test]
    fn list_orders_filters_by_status_and_paginates_newest_first() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        for i in 1..=3u32 {
            new_order(&store, &tenant.tenant.id, i);
        }
        let all = store.list_orders(&tenant.tenant.id, None, 10, None).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all[0].created_at >= all[1].created_at); // newest first (all equal here, but ordering must not error)

        let pending_only = store.list_orders(&tenant.tenant.id, Some(OrderStatus::Pending), 10, None).unwrap();
        assert_eq!(pending_only.len(), 3);
        let paid_only = store.list_orders(&tenant.tenant.id, Some(OrderStatus::Paid), 10, None).unwrap();
        assert_eq!(paid_only.len(), 0);

        let page = store.list_orders(&tenant.tenant.id, None, 2, None).unwrap();
        assert_eq!(page.len(), 2);
    }

    #[test]
    fn active_tenant_ids_includes_every_non_terminal_status_and_excludes_terminal_ones() {
        let store = Store::open_in_memory().unwrap();

        // One tenant per status, so each row's own status is the only variable.
        let mut tenants_by_status = std::collections::HashMap::new();
        for (i, status) in [
            OrderStatus::Pending,
            OrderStatus::Unconfirmed,
            OrderStatus::Confirming,
            OrderStatus::Partial,
            OrderStatus::Paid,
            OrderStatus::Overpaid,
            OrderStatus::Expired,
        ]
        .into_iter()
        .enumerate()
        {
            let tenant = new_tenant(&store);
            let order = new_order(&store, &tenant.tenant.id, i as u32 + 1);
            store
                .conn
                .execute("UPDATE orders SET status = ?2 WHERE id = ?1", params![order.id, status_to_str(status)])
                .unwrap();
            tenants_by_status.insert(status, tenant.tenant.id);
        }

        let active: std::collections::HashSet<String> = store.active_tenant_ids("mainnet").unwrap().into_iter().collect();

        for status in [OrderStatus::Pending, OrderStatus::Unconfirmed, OrderStatus::Confirming, OrderStatus::Partial] {
            assert!(active.contains(&tenants_by_status[&status]), "{status} must be active");
        }
        for status in [OrderStatus::Paid, OrderStatus::Overpaid, OrderStatus::Expired] {
            assert!(!active.contains(&tenants_by_status[&status]), "{status} must not be active");
        }
    }

    #[test]
    fn tenant_with_no_orders_at_all_is_not_active() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        assert!(!store.active_tenant_ids("mainnet").unwrap().contains(&tenant.tenant.id));
    }

    #[test]
    fn tenant_becomes_inactive_once_its_only_order_settles_then_active_again_on_a_fresh_order() {
        // The exact scenario the scanner's watchlist must get right without a
        // stale-cache race: a tenant drops off, then a brand-new order brings it
        // straight back - proving there's no "sticky exclusion" once a tenant has
        // ever gone fully terminal. Query-fresh-every-tick (rather than an
        // incrementally add/removed cache) makes this automatic - there's no
        // cached "inactive" state that a new order needs to invalidate.
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order_a = new_order(&store, &tenant.tenant.id, 1);

        assert!(store.active_tenant_ids("mainnet").unwrap().contains(&tenant.tenant.id));

        store.record_payment_match(&order_a.id, "tx_a", 0, 100, "[]", 1500, Some(50)).unwrap();
        let (_, status) = store.recompute_order_status(&order_a.id, 59, 1600).unwrap();
        assert_eq!(status, OrderStatus::Paid);
        assert!(
            !store.active_tenant_ids("mainnet").unwrap().contains(&tenant.tenant.id),
            "tenant must drop off once its only order is fully settled"
        );

        let order_b = new_order(&store, &tenant.tenant.id, 2);
        assert!(
            store.active_tenant_ids("mainnet").unwrap().contains(&tenant.tenant.id),
            "a fresh order must bring the tenant straight back onto the watchlist"
        );
        let _ = order_b;
    }

    #[test]
    fn tenant_stays_active_while_any_one_of_several_orders_remains_pending() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order_a = new_order(&store, &tenant.tenant.id, 1);
        let _order_b = new_order(&store, &tenant.tenant.id, 2);

        store.record_payment_match(&order_a.id, "tx_a", 0, 100, "[]", 1500, Some(50)).unwrap();
        store.recompute_order_status(&order_a.id, 59, 1600).unwrap();

        assert!(
            store.active_tenant_ids("mainnet").unwrap().contains(&tenant.tenant.id),
            "order_b is still pending, so the tenant must stay active even though order_a settled"
        );
    }

    #[test]
    fn webhook_delivery_queue_lifecycle() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        let webhook = store
            .create_webhook(&tenant.tenant.id, "https://merchant.example/hook", "{}", "whsec_x", 1000)
            .unwrap();

        let id = store
            .enqueue_webhook_delivery(&webhook.id, &order.id, "order.paid", "{\"a\":1}", 1000)
            .unwrap();

        // Not due yet if next_attempt_at is in the future.
        assert!(store.due_webhook_deliveries(999, 10).unwrap().is_empty());
        let due = store.due_webhook_deliveries(1000, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].delivery_id, id);
        assert_eq!(due[0].url, "https://merchant.example/hook");
        assert_eq!(due[0].signing_secret, "whsec_x");
        assert_eq!(due[0].attempt_count, 0);

        // A failed attempt reschedules and increments attempt_count; it stays due
        // once the new next_attempt_at has passed.
        store.schedule_webhook_retry(id, 2000, Some(500), Some("server error"), 1000).unwrap();
        assert!(store.due_webhook_deliveries(1500, 10).unwrap().is_empty());
        let due = store.due_webhook_deliveries(2000, 10).unwrap();
        assert_eq!(due[0].attempt_count, 1);

        // A successful delivery removes it from the due set permanently, even if
        // asked about at a much later time.
        store.mark_webhook_delivered(id, 200, 2000).unwrap();
        assert!(store.due_webhook_deliveries(999_999, 10).unwrap().is_empty());
    }

    #[test]
    fn disabling_a_webhook_removes_its_deliveries_from_the_due_set() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        let webhook = store
            .create_webhook(&tenant.tenant.id, "https://merchant.example/hook", "{}", "whsec_x", 1000)
            .unwrap();
        store.enqueue_webhook_delivery(&webhook.id, &order.id, "order.paid", "{}", 1000).unwrap();

        store.conn.execute("UPDATE webhooks SET enabled = 0 WHERE id = ?1", params![webhook.id]).unwrap();
        assert!(store.due_webhook_deliveries(1000, 10).unwrap().is_empty());
    }

    #[test]
    fn max_scanned_height_reflects_the_highest_recorded_block() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.max_scanned_height("mainnet").unwrap(), None);
        store.set_scanned_block("mainnet", 100, "h100").unwrap();
        store.set_scanned_block("mainnet", 105, "h105").unwrap();
        store.set_scanned_block("mainnet", 102, "h102").unwrap();
        assert_eq!(store.max_scanned_height("mainnet").unwrap(), Some(105));
    }

    #[test]
    fn get_order_tenant_id_is_unscoped_by_design() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        assert_eq!(store.get_order_tenant_id(&order.id).unwrap(), Some(tenant.tenant.id));
        assert_eq!(store.get_order_tenant_id("pay_nonexistent").unwrap(), None);
    }

    #[test]
    fn scanned_blocks_round_trip_and_prune() {
        let store = Store::open_in_memory().unwrap();
        store.set_scanned_block("mainnet", 100, "hash100").unwrap();
        store.set_scanned_block("mainnet", 101, "hash101").unwrap();
        assert_eq!(store.get_scanned_block_hash("mainnet", 100).unwrap(), Some("hash100".to_string()));

        // Reorg overwrite at the same height.
        store.set_scanned_block("mainnet", 100, "hash100_v2").unwrap();
        assert_eq!(store.get_scanned_block_hash("mainnet", 100).unwrap(), Some("hash100_v2".to_string()));

        store.prune_scanned_blocks_below("mainnet", 101).unwrap();
        assert_eq!(store.get_scanned_block_hash("mainnet", 100).unwrap(), None);
        assert!(store.get_scanned_block_hash("mainnet", 101).unwrap().is_some());
    }

    #[test]
    fn scanned_blocks_are_fully_isolated_per_network() {
        // The entire point of the network-scoped rewrite: block heights are only
        // comparable within one chain, so two networks must be able to record
        // *different* hashes at the *same* height without colliding, and querying
        // one network must never see the other's data.
        let store = Store::open_in_memory().unwrap();
        store.set_scanned_block("mainnet", 100, "mainnet_hash_100").unwrap();
        store.set_scanned_block("stagenet", 100, "stagenet_hash_100").unwrap();

        assert_eq!(store.get_scanned_block_hash("mainnet", 100).unwrap(), Some("mainnet_hash_100".to_string()));
        assert_eq!(store.get_scanned_block_hash("stagenet", 100).unwrap(), Some("stagenet_hash_100".to_string()));
        assert_eq!(store.get_scanned_block_hash("testnet", 100).unwrap(), None, "a third, never-written network must see nothing");

        // Advancing one network's tip must not affect the other's.
        store.set_scanned_block("mainnet", 105, "mainnet_hash_105").unwrap();
        assert_eq!(store.max_scanned_height("mainnet").unwrap(), Some(105));
        assert_eq!(store.max_scanned_height("stagenet").unwrap(), Some(100));

        // Pruning one network's old blocks must not touch the other's.
        store.prune_scanned_blocks_below("mainnet", 105).unwrap();
        assert_eq!(store.get_scanned_block_hash("mainnet", 100).unwrap(), None);
        assert_eq!(
            store.get_scanned_block_hash("stagenet", 100).unwrap(),
            Some("stagenet_hash_100".to_string()),
            "pruning mainnet must not prune stagenet's row at the same height"
        );
    }

    #[test]
    fn active_tenant_ids_is_scoped_by_network() {
        let store = Store::open_in_memory().unwrap();
        let mainnet_tenant = new_tenant(&store); // new_tenant() always uses "mainnet"
        new_order(&store, &mainnet_tenant.tenant.id, 1);

        let stagenet_tenant = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "5stagenet".into(),
                    network: "stagenet".into(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();
        new_order(&store, &stagenet_tenant.tenant.id, 1);

        let mainnet_active = store.active_tenant_ids("mainnet").unwrap();
        assert!(mainnet_active.contains(&mainnet_tenant.tenant.id));
        assert!(!mainnet_active.contains(&stagenet_tenant.tenant.id), "a stagenet tenant must never appear in a mainnet query");

        let stagenet_active = store.active_tenant_ids("stagenet").unwrap();
        assert!(stagenet_active.contains(&stagenet_tenant.tenant.id));
        assert!(!stagenet_active.contains(&mainnet_tenant.tenant.id));
    }

    #[test]
    fn find_payments_at_or_after_height_is_scoped_by_network() {
        // Two tenants on different networks, each with a payment recorded at the
        // *same* height - a reorg reconciliation pass on one network must never
        // pick up the other's payment just because the numeric heights coincide.
        let store = Store::open_in_memory().unwrap();
        let mainnet_tenant = new_tenant(&store);
        let mainnet_order = new_order(&store, &mainnet_tenant.tenant.id, 1);
        store.record_payment_match(&mainnet_order.id, "tx_mainnet", 0, 100, "[]", 1500, Some(50)).unwrap();

        let stagenet_tenant = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "5stagenet".into(),
                    network: "stagenet".into(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();
        let stagenet_order = new_order(&store, &stagenet_tenant.tenant.id, 1);
        store.record_payment_match(&stagenet_order.id, "tx_stagenet", 0, 100, "[]", 1500, Some(50)).unwrap();

        let mainnet_affected = store.find_payments_at_or_after_height("mainnet", 50).unwrap();
        assert_eq!(mainnet_affected.len(), 1);
        assert_eq!(mainnet_affected[0].txid, "tx_mainnet");

        let stagenet_affected = store.find_payments_at_or_after_height("stagenet", 50).unwrap();
        assert_eq!(stagenet_affected.len(), 1);
        assert_eq!(stagenet_affected[0].txid, "tx_stagenet");
    }

    #[test]
    fn find_unconfirmed_payments_returns_only_live_mempool_only_rows_of_one_network() {
        // The sweep that catches a plain (reorg-free) zero-conf double-spend runs off
        // this query, so what it must *not* return matters as much as what it does: a
        // mined payment (already anchored to a block), an already-voided one (nothing
        // left to decide), and another network's payment (a daemon must never be
        // asked about a chain it doesn't serve).
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let mempool_order = new_order(&store, &tenant.tenant.id, 1);
        let mined_order = new_order(&store, &tenant.tenant.id, 2);
        let voided_order = new_order(&store, &tenant.tenant.id, 3);
        store.record_payment_match(&mempool_order.id, "tx_pool", 0, 100, "[]", 1500, None).unwrap();
        store.record_payment_match(&mined_order.id, "tx_mined", 0, 100, "[]", 1500, Some(50)).unwrap();
        store.record_payment_match(&voided_order.id, "tx_voided", 0, 100, "[]", 1500, None).unwrap();
        store.void_payment(&voided_order.id, "tx_voided", 0, 1600).unwrap();

        let stagenet_tenant = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "5stagenet".into(),
                    network: "stagenet".into(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();
        let stagenet_order = new_order(&store, &stagenet_tenant.tenant.id, 1);
        store.record_payment_match(&stagenet_order.id, "tx_stagenet_pool", 0, 100, "[]", 1500, None).unwrap();

        let found = store.find_unconfirmed_payments("mainnet").unwrap();
        assert_eq!(found.len(), 1, "only the live mempool-only mainnet row: {found:?}");
        assert_eq!(found[0].txid, "tx_pool");

        let stagenet_found = store.find_unconfirmed_payments("stagenet").unwrap();
        assert_eq!(stagenet_found.len(), 1);
        assert_eq!(stagenet_found[0].txid, "tx_stagenet_pool");
    }

    #[test]
    fn a_mempool_first_payment_gains_its_block_height_once_the_tx_is_mined() {
        // Direct regression test for the single most consequential bug in this file:
        // `ON CONFLICT DO NOTHING` meant the block scan's `Some(height)` was thrown
        // away because the mempool poll had already inserted the same output with
        // `block_height = NULL` seconds earlier. Since the scanner polls the mempool
        // roughly every second, essentially *every* real payment arrives in that
        // order, so essentially every real payment was permanently stuck at zero
        // confirmations - never advancing past `unconfirmed`, and invisible to
        // `find_payments_at_or_after_height` (and therefore to reorg reconciliation).
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        assert!(store.record_payment_match(&order.id, "txabc", 0, 100, "[]", 1500, None).unwrap());
        assert_eq!(store.get_all_payments(&order.id).unwrap()[0].block_height, None);

        // Same output, now seen inside a block - the row must learn its height.
        assert!(!store.record_payment_match(&order.id, "txabc", 0, 100, "[]", 1600, Some(50)).unwrap());
        let payments = store.get_all_payments(&order.id).unwrap();
        assert_eq!(payments.len(), 1, "still exactly one row - this is an update, not a second payment");
        assert_eq!(payments[0].block_height, Some(50));

        // And with a height known, the payment is now reachable by reorg
        // reconciliation, which filters on `block_height >= ?`.
        assert_eq!(store.find_payments_at_or_after_height("mainnet", 50).unwrap().len(), 1);
    }

    #[test]
    fn a_late_mempool_resighting_never_nulls_out_an_already_known_block_height() {
        // The other direction of the same upsert. A node can still list a
        // just-mined transaction in its pool for a short while, so the mempool scan
        // legitimately re-reports it with `block_height = None` *after* the block
        // scan recorded a real height. COALESCE is what stops that from walking the
        // payment's confirmations back to zero on every subsequent tick.
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        store.record_payment_match(&order.id, "txabc", 0, 100, "[]", 1500, Some(50)).unwrap();
        store.record_payment_match(&order.id, "txabc", 0, 100, "[]", 1600, None).unwrap();

        assert_eq!(store.get_all_payments(&order.id).unwrap()[0].block_height, Some(50));
    }

    #[test]
    fn a_duplicate_insert_cannot_resurrect_a_voided_payment() {
        // The `WHERE voided_at IS NULL` guard on the upsert. A voided payment is a
        // proven double-spend; the scanner will keep seeing that transaction in the
        // mempool for as long as it propagates, and each re-sighting reaches the
        // same upsert. That must not quietly revise the row it decided against.
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        store.record_payment_match(&order.id, "txabc", 0, 100, "[]", 1500, None).unwrap();
        assert!(store.void_payment(&order.id, "txabc", 0, 1600).unwrap());

        store.record_payment_match(&order.id, "txabc", 0, 100, "[]", 1700, Some(50)).unwrap();
        let payments = store.get_all_payments(&order.id).unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].voided_at, Some(1600), "still voided");
        assert_eq!(payments[0].block_height, None, "and the guarded update must not have run either");
    }

    #[test]
    fn two_orders_can_each_record_the_same_transaction_output() {
        // Migration 0004. `UNIQUE(txid, output_index)` was global, so when two
        // tenants share a view key - a second instance pointed at one wallet, a
        // staging tenant on production key material - both scanners match the same
        // output and the second one's payment vanished into `DO NOTHING`. Scoping
        // the constraint by `order_id` lets each order keep its own row while
        // mempool-poll idempotency within one order is unchanged.
        let store = Store::open_in_memory().unwrap();
        let tenant_a = new_tenant(&store);
        let tenant_b = new_tenant(&store);
        let order_a = new_order(&store, &tenant_a.tenant.id, 1);
        let order_b = new_order(&store, &tenant_b.tenant.id, 1);

        assert!(store.record_payment_match(&order_a.id, "shared_tx", 0, 100, "[]", 1500, Some(50)).unwrap());
        assert!(store.record_payment_match(&order_b.id, "shared_tx", 0, 100, "[]", 1500, Some(50)).unwrap());

        assert_eq!(store.get_all_payments(&order_a.id).unwrap().len(), 1);
        assert_eq!(store.get_all_payments(&order_b.id).unwrap().len(), 1);

        // Within one order it is still an idempotent no-op, exactly as before.
        assert!(!store.record_payment_match(&order_a.id, "shared_tx", 0, 100, "[]", 1600, Some(50)).unwrap());
        assert_eq!(store.get_all_payments(&order_a.id).unwrap().len(), 1);
    }

    #[test]
    fn unvoid_payment_restores_a_row_without_clearing_the_double_spend_flag() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        store.record_payment_match(&order.id, "tx_a", 0, 100, "[]", 1500, Some(50)).unwrap();
        store.void_payment(&order.id, "tx_a", 0, 1600).unwrap();
        store.mark_double_spend_detected(&order.id, 1600).unwrap();

        assert!(store.unvoid_payment(&order.id, "tx_a", 0).unwrap());
        assert!(store.get_all_payments(&order.id).unwrap()[0].voided_at.is_none());
        assert!(!store.unvoid_payment(&order.id, "tx_a", 0).unwrap(), "idempotent - already un-voided");

        // Sticky by design (see the schema comment): the incident happened, whether
        // or not the payment ultimately stood.
        let refetched = store.get_order(&tenant.tenant.id, &order.id).unwrap().unwrap();
        assert_eq!(refetched.double_spend_detected_at, Some(1600));
    }

    #[test]
    fn non_terminal_order_ids_covers_exactly_the_recomputable_statuses_and_one_network() {
        // The query behind the scanner's per-tick "recompute everything still in
        // flight" pass. It must include every status whose correct value can change
        // without any new payment (confirmations grow with the chain, `pending`
        // expires with the clock) and exclude the settled ones, and must not reach
        // across networks - heights on another chain are unrelated numbers.
        let store = Store::open_in_memory().unwrap();
        let mut ids_by_status = std::collections::HashMap::new();
        for (i, status) in [
            OrderStatus::Pending,
            OrderStatus::Unconfirmed,
            OrderStatus::Confirming,
            OrderStatus::Partial,
            OrderStatus::Paid,
            OrderStatus::Overpaid,
            OrderStatus::Expired,
        ]
        .into_iter()
        .enumerate()
        {
            let tenant = new_tenant(&store);
            let order = new_order(&store, &tenant.tenant.id, i as u32 + 1);
            store
                .conn
                .execute("UPDATE orders SET status = ?2 WHERE id = ?1", params![order.id, status_to_str(status)])
                .unwrap();
            ids_by_status.insert(status, order.id);
        }

        let ids: std::collections::HashSet<String> =
            store.non_terminal_order_ids("mainnet").unwrap().into_iter().collect();
        for status in [OrderStatus::Pending, OrderStatus::Unconfirmed, OrderStatus::Confirming, OrderStatus::Partial] {
            assert!(ids.contains(&ids_by_status[&status]), "{status} orders must be recomputed every tick");
        }
        for status in [OrderStatus::Paid, OrderStatus::Overpaid, OrderStatus::Expired] {
            assert!(!ids.contains(&ids_by_status[&status]), "{status} is terminal - nothing left to recompute");
        }

        let stagenet = store
            .create_tenant(
                NewTenant {
                    key_custody_backend: "plain".into(),
                    sealed_key_material: vec![],
                    primary_address: "5stagenet".into(),
                    network: "stagenet".into(),
                    allowed_origins: vec![],
                    confirmations_required: None,
                    zero_conf_max_piconero: None,
                    order_expiry_seconds: None,
                },
                1000,
            )
            .unwrap();
        let stagenet_order = new_order(&store, &stagenet.tenant.id, 1);
        assert!(!store.non_terminal_order_ids("mainnet").unwrap().contains(&stagenet_order.id));
        assert!(store.non_terminal_order_ids("stagenet").unwrap().contains(&stagenet_order.id));
    }

    #[test]
    fn claiming_a_minor_index_and_creating_its_order_is_all_or_nothing() {
        // The atomicity that closes the order-creation race: `next_minor_index` is
        // what the scanner reads to decide which subaddresses it scans, so it must
        // never be advanced except together with the order row that explains the
        // advance. Proven here by forcing the order insert to fail (a duplicate
        // `(tenant_id, minor_index)`) and asserting the counter did not move -
        // under the old "allocate, await a derivation, then insert" sequence the
        // counter advanced first and stayed advanced regardless.
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let tenant_id = tenant.tenant.id.clone();

        let first = store.peek_next_minor_index(&tenant_id).unwrap();
        let order = store
            .create_order_claiming_minor_index(first, NewOrder {
                tenant_id: tenant_id.clone(),
                merchant_order_id: None,
                minor_index: first,
                address: "sub_1".into(),
                fiat_currency: "USD".into(),
                fiat_amount: "25.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 100,
                description: None,
                created_at: 1000,
                expires_at: 2000,
            })
            .unwrap()
            .expect("the first claim of a fresh index must succeed");
        assert_eq!(order.minor_index, first);
        assert_eq!(store.peek_next_minor_index(&tenant_id).unwrap(), first + 1);

        // A claim of an index the counter has already moved past changes nothing at
        // all - the caller re-derives against the new index rather than burning one.
        let stale = store
            .create_order_claiming_minor_index(first, NewOrder {
                tenant_id: tenant_id.clone(),
                merchant_order_id: None,
                minor_index: first,
                address: "sub_1_again".into(),
                fiat_currency: "USD".into(),
                fiat_amount: "25.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 100,
                description: None,
                created_at: 1000,
                expires_at: 2000,
            })
            .unwrap();
        assert!(stale.is_none());
        assert_eq!(store.peek_next_minor_index(&tenant_id).unwrap(), first + 1, "a losing racer must not burn an index");

        // A *failing* insert (this minor_index is already taken, violating
        // UNIQUE(tenant_id, minor_index)) must roll the counter bump back with it.
        let next = store.peek_next_minor_index(&tenant_id).unwrap();
        let failed = store.create_order_claiming_minor_index(next, NewOrder {
            tenant_id: tenant_id.clone(),
            merchant_order_id: None,
            minor_index: first, // deliberately the already-used index, not `next`
            address: "sub_collision".into(),
            fiat_currency: "USD".into(),
            fiat_amount: "25.00".into(),
            exchange_rate: "1".into(),
            xmr_amount_piconero: 100,
            description: None,
            created_at: 1000,
            expires_at: 2000,
        });
        assert!(failed.is_err());
        assert_eq!(
            store.peek_next_minor_index(&tenant_id).unwrap(),
            next,
            "a failed order insert must not leave the counter advanced past an order that does not exist"
        );
    }

    #[test]
    fn foreign_keys_are_enforced_on_a_reopened_database_file() {
        // `PRAGMA foreign_keys` is a per-*connection* setting that SQLite defaults
        // to OFF, and it lived in `0001_init.sql`. Migrations run once, so every
        // boot after the very first one against an existing file skipped that
        // statement entirely and ran with foreign key enforcement silently
        // disabled - the exact opposite of what the schema documents. Asserting it
        // on a *reopened* file is the whole point: a fresh database passes either
        // way, which is why this went unnoticed.
        let path = std::env::temp_dir().join(format!("moneropay_fk_test_{}.db", Uuid::new_v4()));
        let path_str = path.to_str().unwrap();

        let store = Store::open_file(path_str).unwrap();
        drop(store); // the connection that ran the migrations is gone

        let reopened = Store::open_file(path_str).unwrap();
        let err = reopened
            .create_order(NewOrder {
                tenant_id: "tn_does_not_exist".into(),
                merchant_order_id: None,
                minor_index: 1,
                address: "sub_1".into(),
                fiat_currency: "USD".into(),
                fiat_amount: "1.00".into(),
                exchange_rate: "1".into(),
                xmr_amount_piconero: 1,
                description: None,
                created_at: 1000,
                expires_at: 2000,
            })
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error { code: rusqlite::ErrorCode::ConstraintViolation, .. },
                    _
                ))
            ),
            "an order referencing a nonexistent tenant must be rejected on a reopened connection, got: {err:?}"
        );

        drop(reopened);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn a_failing_migration_leaves_neither_its_schema_changes_nor_its_version_row() {
        // Each migration body and its `schema_migrations` insert were two separate
        // statements, so a crash between them re-ran the migration on the next boot
        // - which, for any migration containing CREATE TABLE or DROP TABLE (0003
        // and 0004 both do), fails outright and leaves the server unable to start
        // against its own database. Wrapping the pair in a transaction makes a
        // half-applied migration impossible; this drives that with a migration that
        // succeeds partway and then fails.
        let conn = Connection::open_in_memory().unwrap();
        let migrations: &[(i64, &str)] = &[
            (1, "CREATE TABLE ok_table (id INTEGER PRIMARY KEY);"),
            (2, "CREATE TABLE half_applied (id INTEGER PRIMARY KEY); THIS IS NOT VALID SQL;"),
        ];
        let err = apply_migration_list(&conn, migrations).unwrap_err();
        let _ = err;

        let applied: Vec<i64> = {
            let mut stmt = conn.prepare("SELECT version FROM schema_migrations ORDER BY version").unwrap();
            let rows = stmt.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            rows
        };
        assert_eq!(applied, vec![1], "the migration that succeeded is recorded; the one that failed is not");

        let half_applied_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='half_applied')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !half_applied_exists,
            "the failed migration's CREATE TABLE must have rolled back - otherwise re-running it next boot fails with 'table already exists'"
        );

        // And the retry a restart would perform now succeeds against a fixed
        // migration, rather than tripping over its own leftovers.
        let fixed: &[(i64, &str)] = &[migrations[0], (2, "CREATE TABLE half_applied (id INTEGER PRIMARY KEY);")];
        apply_migration_list(&conn, fixed).unwrap();
    }

    #[test]
    fn migration_0004_rebuilds_order_payments_without_losing_existing_rows() {
        // 0004 changes a constraint, which SQLite can only do by rebuilding the
        // table and copying every row across - the one kind of migration that can
        // silently destroy live payment history if the column list drifts. Driven
        // here the way a real upgrade runs it: bring a database up to the *previous*
        // schema version, put real data in it, then apply the rest.
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn).unwrap();
        apply_migration_list(&conn, &MIGRATIONS[..3]).unwrap();
        let store = Store { conn };

        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        // Inserted directly rather than through `record_payment_match`, whose
        // conflict target names a constraint this schema version doesn't have yet.
        store
            .execute_raw_for_test(&format!(
                "INSERT INTO order_payments (order_id, txid, output_index, amount_piconero,
                    key_images_json, first_seen_at, block_height, voided_at)
                 VALUES ('{}', 'tx_from_before_the_upgrade', 2, 4242, '[\"ki_a\"]', 1500, 77, 1600)",
                order.id
            ))
            .unwrap();

        apply_migration_list(&store.conn, MIGRATIONS).unwrap();

        let payments = store.get_all_payments(&order.id).unwrap();
        assert_eq!(payments.len(), 1, "the pre-upgrade payment must survive the table rebuild");
        assert_eq!(payments[0].txid, "tx_from_before_the_upgrade");
        assert_eq!(payments[0].output_index, 2);
        assert_eq!(payments[0].amount_piconero, 4242);
        assert_eq!(payments[0].key_images_json, "[\"ki_a\"]");
        assert_eq!(payments[0].first_seen_at, 1500);
        assert_eq!(payments[0].block_height, Some(77), "every column, not just the ones the new constraint names");
        assert_eq!(payments[0].voided_at, Some(1600));

        // And the new constraint is genuinely in force afterwards.
        let other_tenant = new_tenant(&store);
        let other_order = new_order(&store, &other_tenant.tenant.id, 1);
        assert!(store
            .record_payment_match(&other_order.id, "tx_from_before_the_upgrade", 2, 100, "[]", 1700, Some(77))
            .unwrap());

        // SQLite drops a table's indexes with the table, and does *not* re-derive
        // them for the replacement - so a rebuild migration silently un-indexes
        // whatever it forgets to recreate, with nothing failing and only a
        // progressively slower query to show for it. Assert the full expected set
        // rather than just the one 0004 remembered to recreate.
        let indexes: Vec<String> = {
            let mut stmt = store
                .conn
                .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='order_payments' AND sql IS NOT NULL ORDER BY name")
                .unwrap();
            let rows = stmt.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            rows
        };
        assert_eq!(
            indexes,
            vec!["order_payments_order_idx".to_string()],
            "every explicitly-declared index that existed on order_payments before the rebuild must exist after it"
        );
        // ...plus the implicit index backing the new constraint, which is what makes
        // the upsert's `ON CONFLICT(order_id, txid, output_index)` target resolvable
        // at all.
        let has_unique_index: bool = store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_index_list('order_payments') WHERE origin='u' AND \"unique\"=1)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_unique_index, "the UNIQUE(order_id, txid, output_index) constraint must survive as a real index");
    }

    #[test]
    fn a_payment_a_reorg_pushed_back_into_the_mempool_stays_visible_to_reconciliation() {
        // `block_height IS NULL` is exactly what reorg reconciliation writes when the
        // daemon reports a payment's transaction back in the pool - and SQL's
        // three-valued logic makes `NULL >= n` false, so filtering on `block_height >=
        // ?` alone made that row invisible to every subsequent reconciliation pass.
        // The payment could then be proven double-spent and would still never be
        // voided, propping up the order's received total forever.
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        store.record_payment_match(&order.id, "tx_a", 0, 100, "[]", 1500, Some(50)).unwrap();
        assert_eq!(store.find_payments_at_or_after_height("mainnet", 50).unwrap().len(), 1);

        // A reorg drops it back to the mempool.
        store.update_payment_block_height(&order.id, "tx_a", 0, None).unwrap();
        let still_visible = store.find_payments_at_or_after_height("mainnet", 50).unwrap();
        assert_eq!(still_visible.len(), 1, "an unconfirmed payment is above every block height, not below all of them");
        assert_eq!(still_visible[0].block_height, None);

        // The same applies to the voided half of the pair, which un-voiding depends on.
        store.void_payment(&order.id, "tx_a", 0, 1600).unwrap();
        assert!(store.find_payments_at_or_after_height("mainnet", 50).unwrap().is_empty());
        assert_eq!(store.find_voided_payments_at_or_after_height("mainnet", 50).unwrap().len(), 1);

        // And a network scope violation is still impossible either way.
        assert!(store.find_payments_at_or_after_height("stagenet", 50).unwrap().is_empty());
        assert!(store.find_voided_payments_at_or_after_height("stagenet", 50).unwrap().is_empty());
    }

    #[test]
    fn in_transaction_rolls_every_write_back_when_the_closure_fails() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);

        let result: Result<()> = store.in_transaction(|s| {
            s.record_payment_match(&order.id, "tx_a", 0, 100, "[]", 1500, Some(50))?;
            s.mark_double_spend_detected(&order.id, 1600)?;
            Err(StoreError::NotFound)
        });
        assert!(result.is_err());
        assert!(store.get_all_payments(&order.id).unwrap().is_empty(), "the whole group must be gone, not just the last write");
        assert!(store.get_order(&tenant.tenant.id, &order.id).unwrap().unwrap().double_spend_detected_at.is_none());

        // And the successful case commits normally.
        store
            .in_transaction(|s| s.record_payment_match(&order.id, "tx_a", 0, 100, "[]", 1500, Some(50)))
            .unwrap();
        assert_eq!(store.get_all_payments(&order.id).unwrap().len(), 1);
    }

    #[test]
    fn forget_scanned_blocks_at_or_above_walks_the_high_water_mark_back() {
        let store = Store::open_in_memory().unwrap();
        for h in 100..=105 {
            store.set_scanned_block("mainnet", h, &format!("hash{h}")).unwrap();
        }
        store.set_scanned_block("stagenet", 103, "stagenet_hash").unwrap();

        store.forget_scanned_blocks_at_or_above("mainnet", 103).unwrap();
        assert_eq!(store.max_scanned_height("mainnet").unwrap(), Some(102));
        assert!(store.get_scanned_block_hash("mainnet", 103).unwrap().is_none());
        assert_eq!(
            store.get_scanned_block_hash("stagenet", 103).unwrap(),
            Some("stagenet_hash".to_string()),
            "another network's window at the same height must be untouched"
        );
    }

    #[test]
    fn find_payment_by_key_image_locates_the_owning_row() {
        let store = Store::open_in_memory().unwrap();
        let tenant = new_tenant(&store);
        let order = new_order(&store, &tenant.tenant.id, 1);
        store
            .record_payment_match(&order.id, "tx_a", 0, 60, "[\"deadbeef\",\"cafef00d\"]", 1500, None)
            .unwrap();

        let found = store.find_payment_by_key_image("cafef00d").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].txid, "tx_a");

        assert!(store.find_payment_by_key_image("not_present").unwrap().is_empty());
    }
}
