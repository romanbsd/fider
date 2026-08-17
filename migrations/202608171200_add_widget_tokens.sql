CREATE TABLE IF NOT EXISTS widget_tokens (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    INTEGER NOT NULL REFERENCES tenants (id),
    token_hash   TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    UNIQUE (tenant_id, token_hash)
);

CREATE INDEX IF NOT EXISTS widget_tokens_tenant_id_idx ON widget_tokens (tenant_id);

ALTER TABLE users ADD COLUMN IF NOT EXISTS device_hash TEXT;

-- A concurrent index build that was interrupted can leave an invalid index
-- behind; IF NOT EXISTS alone would then skip building it forever. Drop any
-- leftover index first so a re-run repairs the build rather than skipping it.
DROP INDEX IF EXISTS users_tenant_device_hash_idx;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_tenant_device_hash_idx ON users (tenant_id, device_hash);