-- OAuth identity table: stable (provider, provider_user_id) -> user_id mapping.
--
-- Email is not a reliable join key for OAuth: a user can change their email at
-- the provider, two different provider accounts can briefly share an email,
-- and providers don't guarantee that email is the canonical identifier.
-- The provider-issued user id (Google "sub", Kakao "id") is the only stable key.
--
-- Note: backend has spring.jpa.hibernate.ddl-auto=validate, so this table MUST
-- exist before the backend image with the new OAuthIdentity entity boots.
-- Run this migration on the prod DB BEFORE deploying the corresponding code.

CREATE TABLE IF NOT EXISTS oauth_identities (
    id                BIGSERIAL PRIMARY KEY,
    user_id           BIGINT      NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    provider          VARCHAR(20) NOT NULL,   -- 'google' | 'kakao'
    provider_user_id  VARCHAR(64) NOT NULL,   -- Google: sub. Kakao: id (numeric string).
    created_at        TIMESTAMP   NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_oauth_identities_provider_uid UNIQUE (provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS ix_oauth_identities_user_id ON oauth_identities(user_id);
