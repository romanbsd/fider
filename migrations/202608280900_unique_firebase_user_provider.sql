DROP INDEX CONCURRENTLY IF EXISTS user_provider_firebase_identity_uq;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS user_provider_firebase_identity_uq
ON user_providers (tenant_id, provider, provider_uid)
WHERE provider = 'firebase';

ALTER TABLE users ADD COLUMN IF NOT EXISTS name_is_placeholder BOOLEAN NOT NULL DEFAULT FALSE;
