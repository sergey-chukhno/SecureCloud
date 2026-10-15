-- V002: Create Core Messaging Tables
-- Strict alignment with 03-messaging-data-model.md and ADR-006, ADR-007, ADR-010.

-- 1. conversations_by_id: Retrieve canonical conversation metadata by ConversationId
CREATE TABLE IF NOT EXISTS securecloud_messaging.conversations_by_id (
    conversation_id text,
    conversation_type text,
    created_at timestamp,
    created_by_user_id text,
    metadata_version int,
    PRIMARY KEY (conversation_id)
);

-- 2. direct_conversation_by_users: O(1) idempotent resolution of 1:1 conversation for canonical user pair
-- Partition key: ((user_a_id, user_b_id)) with user_a_id < user_b_id lexicographically
CREATE TABLE IF NOT EXISTS securecloud_messaging.direct_conversation_by_users (
    user_a_id text,
    user_b_id text,
    conversation_id text,
    created_at timestamp,
    PRIMARY KEY ((user_a_id, user_b_id))
);

-- 3. group_metadata_by_conversation: Retrieve/update group title and lifecycle state (ACTIVE / CLOSED)
CREATE TABLE IF NOT EXISTS securecloud_messaging.group_metadata_by_conversation (
    conversation_id text,
    group_name text,
    group_status text,
    created_by_user_id text,
    created_at timestamp,
    updated_at timestamp,
    metadata_version int,
    PRIMARY KEY (conversation_id)
);

-- 4. conversation_members_by_conversation: List participants for a conversation; query role and status
CREATE TABLE IF NOT EXISTS securecloud_messaging.conversation_members_by_conversation (
    conversation_id text,
    user_id text,
    membership_status text,
    role text,
    joined_at timestamp,
    left_at timestamp,
    membership_version int,
    PRIMARY KEY ((conversation_id), user_id)
);

-- 5. conversations_by_user: Paginated query of recent conversations for a user inbox list
CREATE TABLE IF NOT EXISTS securecloud_messaging.conversations_by_user (
    user_id text,
    last_activity_at timestamp,
    conversation_id text,
    conversation_type text,
    membership_status text,
    unread_state_version int,
    PRIMARY KEY ((user_id), last_activity_at, conversation_id)
) WITH CLUSTERING ORDER BY (last_activity_at DESC, conversation_id ASC);

-- 6. messages_by_conversation: Chronological retrieval of conversation history; monthly time-bucketed
-- Partition key: ((conversation_id, message_bucket)) where message_bucket = YYYYMM (UTC)
-- Clustering key: message_sequence ASC, message_id ASC
CREATE TABLE IF NOT EXISTS securecloud_messaging.messages_by_conversation (
    conversation_id text,
    message_bucket text,
    message_sequence bigint,
    message_id text,
    sender_user_id text,
    sender_device_id text,
    message_priority text,
    accepted_at timestamp,
    ciphertext_envelope text,
    envelope_version int,
    file_reference_ids list<text>,
    PRIMARY KEY ((conversation_id, message_bucket), message_sequence, message_id)
) WITH CLUSTERING ORDER BY (message_sequence ASC, message_id ASC);

-- 7. pending_deliveries_by_device: Device-oriented active delivery queue; undelivered envelopes for DeviceId
-- Partition key: ((device_id, delivery_bucket)) where delivery_bucket = YYYYMM (UTC)
-- Clustering key: accepted_at ASC, message_id ASC
CREATE TABLE IF NOT EXISTS securecloud_messaging.pending_deliveries_by_device (
    device_id text,
    delivery_bucket text,
    accepted_at timestamp,
    message_id text,
    conversation_id text,
    message_sequence bigint,
    message_priority text,
    delivery_state text,
    attempt_count int,
    next_retry_at timestamp,
    PRIMARY KEY ((device_id, delivery_bucket), accepted_at, message_id)
) WITH CLUSTERING ORDER BY (accepted_at ASC, message_id ASC);

-- 8. delivery_state_by_message: Fan-out status tracking across all recipient devices for a message
CREATE TABLE IF NOT EXISTS securecloud_messaging.delivery_state_by_message (
    message_id text,
    recipient_device_id text,
    recipient_user_id text,
    delivery_state text,
    delivered_at timestamp,
    read_at timestamp,
    PRIMARY KEY ((message_id), recipient_device_id)
);

-- 9. sync_state_by_device: Incremental synchronization cursor for a device in a conversation
CREATE TABLE IF NOT EXISTS securecloud_messaging.sync_state_by_device (
    device_id text,
    conversation_id text,
    last_synced_sequence bigint,
    last_sync_at timestamp,
    sync_version int,
    PRIMARY KEY ((device_id), conversation_id)
);

-- 10. message_submission_by_idempotency_key: Enforce atomic deduplication for client message retries
CREATE TABLE IF NOT EXISTS securecloud_messaging.message_submission_by_idempotency_key (
    sender_device_id text,
    idempotency_key text,
    message_id text,
    conversation_id text,
    message_sequence bigint,
    submission_status text,
    created_at timestamp,
    PRIMARY KEY ((sender_device_id), idempotency_key)
);

-- 11. messaging_outbox_events: Transactional outbox for asynchronous domain event publication
CREATE TABLE IF NOT EXISTS securecloud_messaging.messaging_outbox_events (
    outbox_bucket text,
    created_at timestamp,
    event_id text,
    conversation_id text,
    event_type text,
    payload_json text,
    published_at timestamp,
    publish_status text,
    PRIMARY KEY ((outbox_bucket), created_at, event_id)
) WITH CLUSTERING ORDER BY (created_at ASC, event_id ASC);
