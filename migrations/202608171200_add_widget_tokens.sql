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

-- Hash of the per-device secret issued at a device's first widget sign-in,
-- required to re-authenticate that device afterwards. Proves possession of
-- something beyond the shared tenant widget token, which every device of a
-- tenant uses, so a token holder can't authenticate as an arbitrary known
-- device_hash. Empty for every non-device user.
ALTER TABLE users ADD COLUMN IF NOT EXISTS device_secret_hash TEXT;

-- A concurrent index build that was interrupted can leave an invalid index
-- behind; IF NOT EXISTS alone would then skip building it forever. The
-- migration runner only executes this DROP when the index is actually
-- invalid (see indexIsValid in app/pkg/dbx/migrate.go) — an already-valid
-- index is left alone rather than dropped and racing a rebuild. CONCURRENTLY
-- avoids the ACCESS EXCLUSIVE lock a plain DROP INDEX would take.
DROP INDEX CONCURRENTLY IF EXISTS users_tenant_device_hash_idx;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_tenant_device_hash_idx ON users (tenant_id, device_hash);