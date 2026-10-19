-- V004: Add E2E encrypted envelope columns to pending_deliveries_by_device (ADR-008, MSG-006)
ALTER TABLE securecloud_messaging.pending_deliveries_by_device ADD ciphertext_blob blob;
ALTER TABLE securecloud_messaging.pending_deliveries_by_device ADD ephemeral_public_key blob;
ALTER TABLE securecloud_messaging.pending_deliveries_by_device ADD iv blob;
ALTER TABLE securecloud_messaging.pending_deliveries_by_device ADD auth_tag blob;
ALTER TABLE securecloud_messaging.pending_deliveries_by_device ADD algorithm text;
ALTER TABLE securecloud_messaging.pending_deliveries_by_device ADD protocol_version int;
ALTER TABLE securecloud_messaging.pending_deliveries_by_device ADD one_time_prekey_id text;
