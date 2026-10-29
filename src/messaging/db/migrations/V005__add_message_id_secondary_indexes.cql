-- V005: Add secondary indexes for bounded message_id lookups (MSG-012-T03)
CREATE INDEX IF NOT EXISTS idx_messages_by_id ON securecloud_messaging.messages_by_conversation (message_id);
CREATE INDEX IF NOT EXISTS idx_pending_deliveries_by_msg_id ON securecloud_messaging.pending_deliveries_by_device (message_id);

