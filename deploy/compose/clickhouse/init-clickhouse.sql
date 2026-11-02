-- Bootstrap initialization script for ClickHouse 24.8 (AUDIT-008-T02)
-- Provisions securecloud_audit database, least-privilege audit_user, and admin audit_migrator.

CREATE DATABASE IF NOT EXISTS securecloud_audit;

-- 1. Dedicated schema migration / administrative user for DDL & TTL lifecycle verification
CREATE USER IF NOT EXISTS audit_migrator IDENTIFIED WITH sha256_password BY 'audit_migrator_dev_secret';
GRANT CREATE DATABASE, CREATE TABLE, ALTER TTL, OPTIMIZE, SHOW, SELECT, INSERT ON securecloud_audit.* TO audit_migrator;

-- 2. Routine Audit Service application user (least-privilege append + read on audit_events)
CREATE USER IF NOT EXISTS audit_user IDENTIFIED WITH sha256_password BY 'audit_dev_db_secret';
GRANT SELECT, INSERT, SHOW TABLES, DICTGET ON securecloud_audit.* TO audit_user;

-- Preserve compatibility with scripts/verify-persistence-infra.sh Check 10 marker table
GRANT CREATE TABLE, DROP TABLE ON securecloud_audit.persistent_marker TO audit_user;

-- 3. Pre-create audit_events table with 36-month TTL
CREATE TABLE IF NOT EXISTS securecloud_audit.audit_events
(
    event_id UUID,

    occurred_at DateTime64(3, 'UTC'),
    received_at DateTime64(3, 'UTC'),

    event_type LowCardinality(String),
    severity LowCardinality(String),

    producer_service LowCardinality(String),
    producer_instance String,

    actor_type LowCardinality(String),
    actor_id String,

    target_type LowCardinality(String),
    target_id String,

    correlation_id UUID,
    causation_id UUID,

    event_data String
    )
    ENGINE = MergeTree
    PARTITION BY toYYYYMM(occurred_at)
    ORDER BY
(
    occurred_at,
    producer_service,
    event_type,
    event_id
)
    TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE;

-- Explicitly revoke mutation, deletion, truncation, and drop permissions on audit_events from audit_user
REVOKE ALTER, DELETE, TRUNCATE, DROP TABLE ON securecloud_audit.audit_events FROM audit_user;
