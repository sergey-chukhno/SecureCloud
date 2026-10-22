-- Secondary indexes for fast relational lookup and composite status filtering
CREATE INDEX IF NOT EXISTS idx_devices_user_status ON devices(user_id, device_status);
CREATE INDEX IF NOT EXISTS idx_device_keys_device_status ON device_public_keys(device_id, key_status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_status ON sessions(user_id, session_status);
CREATE INDEX IF NOT EXISTS idx_sessions_device_status ON sessions(device_id, session_status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_status ON refresh_tokens(session_id, token_status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_device_status ON refresh_tokens(device_id, token_status);
CREATE INDEX IF NOT EXISTS idx_mfa_config_user_status ON mfa_configurations(user_id, status);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_status ON mfa_challenges(user_id, challenge_status);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_session_status ON mfa_challenges(session_id, challenge_status);
