#pragma once

#include "domain/contact.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/sender_key_models.hpp"
#include "domain/delivery_state.hpp"
#include "domain/device_id.hpp"
#include "domain/message_id.hpp"
#include "domain/offline_sync_models.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

enum class RealtimeEventType {
    InboundDirectMessage,
    InboundGroupMessage,
    InboundSenderKeyDistribution,
    DeliveryAck,
    ReadReceipt,
    PresenceUpdate
};

struct DeliveryAckRecord {
    MessageId message_id;
    DeviceId recipient_device_id;
    int64_t delivered_at_ms{0};
};

struct ReadReceiptRecord {
    ConversationId conversation_id;
    MessageId message_id;
    DeviceId reader_device_id;
    int64_t read_at_ms{0};
};

struct MessageDeliveryStatusInfo {
    MessageId message_id;
    DeliveryState delivery_state{DeliveryState::Accepted};
    uint64_t server_sequence_number{0};
    int64_t updated_at_ms{0};
};

struct RealtimeEvent {
    RealtimeEventType type{RealtimeEventType::InboundDirectMessage};
    uint64_t server_sequence_number{0};
    int64_t timestamp_ms{0};
    ConversationId conversation_id;
    MessageId message_id;
    UserId actor_user_id;
    DeviceId actor_device_id;
    int32_t priority{0};
    std::optional<crypto::PerDeviceDeliveryPayload> direct_payload;
    std::optional<std::vector<uint8_t>> group_envelope_bytes;
    std::optional<crypto::SenderKeyDistributionMessage> sender_key_distribution;
    PresenceStatus presence_status{PresenceStatus::Offline};
};

struct ConversationMessagesPage {
    std::vector<RealtimeEvent> events;
    bool has_more{false};
    uint64_t next_sequence{0};
    uint64_t latest_sequence{0};
    std::optional<SyncCursorRecord> cursor{std::nullopt};
};

struct RetryPolicyConfig {
    uint32_t max_attempts{5};
    std::chrono::milliseconds initial_backoff{500};
    std::chrono::milliseconds max_backoff{30000};
    double jitter_ratio{0.25};
    std::chrono::seconds expiration_ttl{std::chrono::hours(24)};
};

struct ReadReceiptPolicy {
    static constexpr std::string_view kStorageKey = "messaging.privacy.send_read_receipts";
    bool send_read_receipts_enabled{true};
};

} // namespace securecloud::client::domain
