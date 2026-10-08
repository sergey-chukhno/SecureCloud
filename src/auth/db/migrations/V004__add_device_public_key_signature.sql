-- 1. Add signature column for signed prekeys
ALTER TABLE device_public_keys ADD COLUMN IF NOT EXISTS signature BYTEA;

-- 2. Index for atomic single-use One-Time Prekey claiming (SKIP LOCKED)
CREATE INDEX IF NOT EXISTS idx_device_keys_otk_claim 
ON device_public_keys(device_id, created_at) 
WHERE key_type = 'ONE_TIME_PREKEY' AND key_status = 'Active';
