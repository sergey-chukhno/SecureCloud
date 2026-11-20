#pragma once

#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/device_id.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

enum class ConnectivityState { Online, Offline, Syncing };

[[nodiscard]] std::string_view to_string(ConnectivityState state) noexcept;
[[nodiscard]] std::optional<ConnectivityState> connectivity_state_from_string(std::string_view str) noexcept;
[[nodiscard]] bool can_transition_connectivity_state(ConnectivityState current, ConnectivityState next) noexcept;

enum class OfflineOutboxOperationType {
    EncryptedMessageSubmission,
    DeliveryAck,
    ReadReceipt,
    FileKeyEnvelopeSubmission
};

[[nodiscard]] std::string_view to_string(OfflineOutboxOperationType type) noexcept;
[[nodiscard]] std::optional<OfflineOutboxOperationType>
offline_outbox_operation_type_from_string(std::string_view str) noexcept;

/// Losslessly serializable mirror of FanOutSubmissionRequest storing pre-encrypted ciphertexts
/// so offline outbox replay never re-steps Double Ratchet or Sender Key chains (ADR-008).
struct OfflineOutboxFanOutPayload {
    ConversationId conversation_id;
    std::string idempotency_key;
    std::vector<crypto::PerDeviceDeliveryPayload> device_payloads;
    std::optional<std::vector<uint8_t>> group_envelope_bytes;
    int32_t priority{0};

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<OfflineOutboxFanOutPayload> from_json(std::string_view json_str);

    bool operator==(const OfflineOutboxFanOutPayload& other) const noexcept = default;
};

struct OfflineOutboxDeliveryAckPayload {
    MessageId message_id;
    DeviceId recipient_device_id;
    int64_t delivered_at_ms{0};

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<OfflineOutboxDeliveryAckPayload> from_json(std::string_view json_str);

    bool operator==(const OfflineOutboxDeliveryAckPayload& other) const noexcept = default;
};

struct OfflineOutboxReadReceiptPayload {
    ConversationId conversation_id;
    MessageId message_id;
    DeviceId reader_device_id;
    int64_t read_at_ms{0};

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<OfflineOutboxReadReceiptPayload> from_json(std::string_view json_str);

    bool operator==(const OfflineOutboxReadReceiptPayload& other) const noexcept = default;
};

struct OfflineOutboxRecord {
    std::string outbox_id;
    OfflineOutboxOperationType operation_type{OfflineOutboxOperationType::EncryptedMessageSubmission};
    ConversationId conversation_id;
    MessageId message_id;
    std::string transfer_id;
    std::string idempotency_key;
    int32_t priority{0};
    std::string payload_json;
    uint32_t attempt_count{0};
    int64_t created_at_ms{0};
    int64_t next_retry_at_ms{0};
    int64_t expires_at_ms{0};
    std::string last_error;

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<OfflineOutboxRecord> from_json(std::string_view json_str);

    bool operator==(const OfflineOutboxRecord& other) const noexcept = default;
};

struct SyncCursorRecord {
    DeviceId device_id;
    ConversationId conversation_id;
    uint64_t last_delivered_sequence{0};
    int64_t last_sync_timestamp_ms{0};
    int32_t sync_version{1};

    bool advance_monotonically(uint64_t new_sequence, int64_t timestamp_ms) noexcept;

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<SyncCursorRecord> from_json(std::string_view json_str);

    bool operator==(const SyncCursorRecord& other) const noexcept = default;
};

struct RemoteConversationSummary {
    ConversationId conversation_id;
    ConversationType type{ConversationType::Direct};
    std::string title;
    UserId creator_user_id;
    int64_t created_at_ms{0};
    std::vector<UserId> participant_user_ids;

    bool operator==(const RemoteConversationSummary& other) const noexcept = default;
};

struct CatchUpSyncReport {
    std::size_t outbox_flushed_count{0};
    std::size_t outbox_remaining_count{0};
    std::size_t messages_merged_count{0};
    std::size_t duplicates_skipped_count{0};
    std::size_t conversations_reconciled_count{0};
    std::size_t contacts_reconciled_count{0};
    std::size_t transfers_resumed_count{0};

    bool operator==(const CatchUpSyncReport& other) const noexcept = default;
};

} // namespace securecloud::client::domain
