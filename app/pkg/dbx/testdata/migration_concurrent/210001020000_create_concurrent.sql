CREATE TABLE conc_dummy (id BIGSERIAL PRIMARY KEY, tenant_id INT NOT NULL, device_hash TEXT);

CREATE UNIQUE INDEX CONCURRENTLY conc_dummy_tenant_device_idx ON conc_dummy (tenant_id, device_hash);
