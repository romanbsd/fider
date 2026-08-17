CREATE TABLE IF NOT EXISTS conc_repair_dummy (id BIGSERIAL PRIMARY KEY, tenant_id INT NOT NULL, device_hash TEXT);

-- A concurrent index build that was interrupted can leave an invalid index
-- behind; IF NOT EXISTS alone would then skip building it forever. Mirrors
-- the leading comment in the real users_tenant_device_hash_idx migration, so
-- this test actually exercises the comment-stripping path.
DROP INDEX CONCURRENTLY IF EXISTS conc_repair_dummy_idx;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS conc_repair_dummy_idx ON conc_repair_dummy (tenant_id, device_hash);
