CREATE TABLE IF NOT EXISTS conc_repair_dummy (id BIGSERIAL PRIMARY KEY, tenant_id INT NOT NULL, device_hash TEXT);

DROP INDEX CONCURRENTLY IF EXISTS conc_repair_dummy_idx;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS conc_repair_dummy_idx ON conc_repair_dummy (tenant_id, device_hash);
