-- V003: Create Schema Version Tracking Table
-- Tracks applied migrations with cryptographic SHA-256 checksums to guarantee idempotency and prevent drift.

CREATE TABLE IF NOT EXISTS securecloud_messaging.schema_migrations (
    version int,
    script_name text,
    checksum text,
    applied_at timestamp,
    PRIMARY KEY (version)
);
