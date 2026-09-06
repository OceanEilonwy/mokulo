-- Supports Store::active_tenant_ids(), the query behind the scanner's active
-- watchlist (docs/DESIGN.md §7.3): "which tenants currently have at least one
-- non-terminal order". That query filters by `status` first with no `tenant_id`
-- predicate, which the existing `orders_tenant_status_idx (tenant_id, status)` -
-- built for "given a tenant, what's their order status distribution" - can't serve
-- efficiently, since tenant_id is its leading column. This index leads with
-- `status` instead, so SQLite can satisfy the watchlist query as a handful of
-- index-range probes (one per non-terminal status) rather than a full table scan,
-- regardless of how much all-time order history has accumulated.
CREATE INDEX orders_status_tenant_idx ON orders (status, tenant_id);
