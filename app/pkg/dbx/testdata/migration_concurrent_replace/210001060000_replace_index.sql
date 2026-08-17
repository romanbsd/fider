DROP INDEX CONCURRENTLY IF EXISTS conc_replace_dummy_idx;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS conc_replace_dummy_idx ON conc_replace_dummy (tenant_id, device_hash);
