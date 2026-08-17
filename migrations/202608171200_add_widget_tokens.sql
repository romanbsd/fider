CREATE TABLE widget_tokens (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    INTEGER NOT NULL REFERENCES tenants (id),
    token_hash   TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    UNIQUE (tenant_id, token_hash)
);

CREATE INDEX widget_tokens_tenant_id_idx ON widget_tokens (tenant_id);

ALTER TABLE users ADD COLUMN device_hash TEXT;

CREATE UNIQUE INDEX users_tenant_device_hash_idx ON users (tenant_id, device_hash);
