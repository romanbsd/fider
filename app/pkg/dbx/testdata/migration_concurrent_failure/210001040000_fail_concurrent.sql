CREATE TABLE IF NOT EXISTS conc_atomic_dummy (id BIGSERIAL PRIMARY KEY, tenant_id INT NOT NULL, device_hash TEXT);

ALTER TABLE definitely_not_a_table ADD COLUMN foo TEXT;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS conc_atomic_dummy_idx ON conc_atomic_dummy (tenant_id, device_hash);
