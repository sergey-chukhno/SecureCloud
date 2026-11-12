-- Migration: V005__create_auth_outbox_table.sql
-- Purpose: Transactional Outbox for SecureCloud Auth Service (AUDIT-013)

CREATE TABLE IF NOT EXISTS auth_outbox (
    event_id UUID PRIMARY KEY,
    aggregate_type VARCHAR(32) NOT NULL,
    aggregate_id UUID,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'SECURITY', 'CRITICAL')),
    payload_json JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED', 'QUARANTINED')),
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    leased_until TIMESTAMPTZ
    );

-- Index for high-velocity outbox polling and worker leasing
CREATE INDEX IF NOT EXISTS idx_auth_outbox_pending_polling
    ON auth_outbox (created_at ASC)
    WHERE status = 'PENDING';

-- Index for lease expiration recovery
CREATE INDEX IF NOT EXISTS idx_auth_outbox_leased
    ON auth_outbox (leased_until)
    WHERE status = 'PENDING' AND leased_until IS NOT NULL;

-- Index for safe background retention cleanup
CREATE INDEX IF NOT EXISTS idx_auth_outbox_cleanup
    ON auth_outbox (processed_at)
    WHERE status = 'PUBLISHED';
