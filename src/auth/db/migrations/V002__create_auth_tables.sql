-- 1. users
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    credential_identifier VARCHAR(255) NOT NULL UNIQUE,
    password_verifier VARCHAR(255) NOT NULL,
    password_algorithm VARCHAR(64) NOT NULL,
    password_updated_at TIMESTAMPTZ NOT NULL,
    account_status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1
);

-- 2. devices
CREATE TABLE IF NOT EXISTS devices (
    device_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    device_status VARCHAR(32) NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(255),
    last_authenticated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- 3. device_public_keys
CREATE TABLE IF NOT EXISTS device_public_keys (
    key_id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    key_type VARCHAR(64) NOT NULL,
    public_key BYTEA NOT NULL,
    key_status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_key_id UUID REFERENCES device_public_keys(key_id)
);

-- 4. sessions
CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    session_status VARCHAR(32) NOT NULL,
    authentication_level VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ NOT NULL
);

-- 5. refresh_tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    refresh_token_id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    token_verifier VARCHAR(128) NOT NULL UNIQUE,
    token_status VARCHAR(32) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    replaced_by_token_id UUID REFERENCES refresh_tokens(refresh_token_id)
);

-- 6. mfa_configurations
CREATE TABLE IF NOT EXISTS mfa_configurations (
    mfa_configuration_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    factor_type VARCHAR(32) NOT NULL,
    encrypted_secret BYTEA NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    enabled_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1
);

-- 7. mfa_challenges
CREATE TABLE IF NOT EXISTS mfa_challenges (
    mfa_challenge_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    session_id UUID NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    challenge_purpose VARCHAR(32) NOT NULL,
    challenge_status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);
