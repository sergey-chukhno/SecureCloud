#pragma once

#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace securecloud::messaging::service {

/// Command submitted by a recipient device indicating the user has opened/presented a message (ADR-007, ADR-008).
struct ReadReceiptCommand {
    domain::MessageId message_id;
    domain::ConversationId conversation_id;
    domain::UserId caller_user_id;
    domain::DeviceId reader_device_id;
    std::chrono::system_clock::time_point read_at;
};

/// Response confirming authoritative recording of a read receipt.
struct ReadReceiptResponse {
    domain::MessageId message_id;
    domain::ConversationId conversation_id;
    domain::UserId reader_user_id;
    domain::DeviceId reader_device_id;
    v1::DeliveryState state{v1::DELIVERY_STATE_READ};
    std::chrono::system_clock::time_point recorded_at;
    bool is_idempotent_replay{false};
};

/// Aggregated read receipt breakdown for a message in a 1:1 or group conversation.
struct MessageReadStatusResponse {
    domain::MessageId message_id;
    domain::ConversationId conversation_id;
    uint32_t total_recipients{0};
    uint32_t read_recipients{0};
    std::vector<domain::LogicalRecipientReadStatus> recipient_read_statuses;
};

} // namespace securecloud::messaging::service
