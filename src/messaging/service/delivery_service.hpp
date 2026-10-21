#pragma once

#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_service.hpp" // for ServiceResult

#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace securecloud::messaging::service {

/// Command representing an affirmative delivery acknowledgement from a recipient device (ADR-007, ADR-008).
struct DeliveryAckCommand {
    domain::MessageId message_id;
    domain::DeviceId recipient_device_id;
    domain::UserId caller_user_id;
    std::chrono::system_clock::time_point delivered_at;
    std::optional<domain::ConversationId> conversation_id{std::nullopt};
};

/// Response containing the updated delivery state and recording timestamp.
struct DeliveryAckResponse {
    domain::MessageId message_id;
    v1::DeliveryState state{v1::DELIVERY_STATE_DELIVERED};
    std::chrono::system_clock::time_point recorded_at;
    bool is_idempotent_replay{false};
};

/**
 * @brief Authoritative Delivery Service responsible for recipient delivery acknowledgements,
 * ScyllaDB state commits, and transactional outbox event publication (MSG-007-T05).
 *
 * Invariants:
 * 1. Zero Plaintext (ADR-008): Only handles delivery metadata, timestamps, and recipient routing.
 * 2. Device Ownership & Authorization: Confirms caller owns the acknowledging device.
 * 3. Idempotent Delivery Receipts: Duplicate receipts for DELIVERED or READ messages succeed deterministically.
 * 4. Dual-Write Safety (ADR-005): Emits `ConversationOutboxEventType::MessageDelivered` via Transactional Outbox.
 */
class DeliveryService {
  public:
    DeliveryService(std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                    std::shared_ptr<repository::IOutboxRepository> outbox_repo);
    ~DeliveryService() = default;

    DeliveryService(const DeliveryService&) = delete;
    DeliveryService& operator=(const DeliveryService&) = delete;
    DeliveryService(DeliveryService&&) = default;
    DeliveryService& operator=(DeliveryService&&) = default;

    /**
     * @brief Authoritatively records a recipient device's affirmative delivery receipt.
     *
     * @param cmd Strongly-typed delivery ack command.
     * @return ServiceResult containing DeliveryAckResponse on success or domain error.
     */
    [[nodiscard]] ServiceResult<DeliveryAckResponse> acknowledge_delivery(const DeliveryAckCommand& cmd);

  private:
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<repository::IOutboxRepository> outbox_repo_;
};

} // namespace securecloud::messaging::service
