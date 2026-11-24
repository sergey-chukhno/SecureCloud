-- =============================================================================
-- SecureCloud Files Service — Schema Migration V002 (AUDIT-015)
-- Hardens `files_outbox` for M6 durability, severity routing, multi-worker
-- row leasing (`FOR UPDATE SKIP LOCKED`), quarantine isolation, and bounded
-- retention cleanup.
-- =============================================================================

-- 1. Allow NULL aggregate_id for service-level rejections prior to file_id assignment (e.g., E14)
ALTER TABLE files_outbox
    ALTER COLUMN aggregate_id DROP NOT NULL;

-- 2. Add canonical audit severity column and constraint
ALTER TABLE files_outbox
    ADD COLUMN IF NOT EXISTS severity VARCHAR(16) NOT NULL DEFAULT 'INFO';

ALTER TABLE files_outbox
DROP CONSTRAINT IF EXISTS files_outbox_severity_check;

ALTER TABLE files_outbox
    ADD CONSTRAINT files_outbox_severity_check
        CHECK (severity IN ('INFO', 'WARNING', 'SECURITY', 'CRITICAL'));

-- 3. Extend lifecycle status constraint to include QUARANTINED for poison-pill isolation
ALTER TABLE files_outbox
DROP CONSTRAINT IF EXISTS files_outbox_status_check;

ALTER TABLE files_outbox
    ADD CONSTRAINT files_outbox_status_check
        CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED', 'QUARANTINED'));

-- 4. Ensure retry_count remains non-negative
ALTER TABLE files_outbox
DROP CONSTRAINT IF EXISTS files_outbox_retry_count_check;

ALTER TABLE files_outbox
    ADD CONSTRAINT files_outbox_retry_count_check
        CHECK (retry_count >= 0);

-- 5. Add diagnostic error summary and time-bounded worker lease columns
ALTER TABLE files_outbox
    ADD COLUMN IF NOT EXISTS last_error TEXT NULL;

ALTER TABLE files_outbox
    ADD COLUMN IF NOT EXISTS leased_until TIMESTAMPTZ NULL;

-- 6. Replace M5 pending index with lease-aware partial index for SKIP LOCKED batch claiming
DROP INDEX IF EXISTS idx_files_outbox_pending;

CREATE INDEX IF NOT EXISTS idx_files_outbox_pending
    ON files_outbox (created_at ASC, leased_until)
    WHERE status = 'PENDING';

-- 7. Add partial index for bounded batch purging of acknowledged PUBLISHED records
CREATE INDEX IF NOT EXISTS idx_files_outbox_cleanup
    ON files_outbox (processed_at ASC)
    WHERE status = 'PUBLISHED' AND processed_at IS NOT NULL;
