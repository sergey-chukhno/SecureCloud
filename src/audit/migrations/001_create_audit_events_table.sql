-- SecureCloud Audit Service - ClickHouse Migration 001
-- Table: securecloud_audit.audit_events
-- Authoritative Schema Definition (ADR-006, Audit Data Model 5.28)

CREATE DATABASE IF NOT EXISTS securecloud_audit;

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
    TTL toDateTime(occurred_at) + INTERVAL 36 MONTH;