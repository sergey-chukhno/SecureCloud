-- V006: Create Durable Sharded Audit Outbox Table for Messaging Service (ADR-012, AUDIT-014)
-- Partition key: ((outbox_bucket, shard_id)) where outbox_bucket = YYYYMMDDHH (UTC) and shard_id in [0..15]
-- Clustering key: created_at ASC, event_id ASC
-- Compaction: TimeWindowCompactionStrategy (4-hour windows) with 7-day safety TTL (604800s)

CREATE TABLE IF NOT EXISTS securecloud_messaging.messaging_audit_outbox (
    outbox_bucket text,
    shard_id int,
    created_at timestamp,
    event_id text,
    event_type text,
    severity text,
    actor_user_id text,
    actor_device_id text,
    target_resource text,
    payload_proto_bin blob,
    publish_status text,
    attempt_count int,
    last_attempt_at timestamp,
    last_error text,
    leased_until timestamp,
    PRIMARY KEY ((outbox_bucket, shard_id), created_at, event_id)
) WITH CLUSTERING ORDER BY (created_at ASC, event_id ASC)
  AND compaction = {
      'class': 'TimeWindowCompactionStrategy',
      'compaction_window_unit': 'HOURS',
      'compaction_window_size': '4'
  }
  AND default_time_to_live = 604800;
  