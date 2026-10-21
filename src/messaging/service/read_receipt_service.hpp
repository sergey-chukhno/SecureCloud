#pragma once

#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/membership_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "service/conversation_service.hpp" // for ServiceResult
#include "service/read_receipt_commands.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::messaging::service {

/**
 * @brief Authoritative Read Receipt Domain Service (MSG-008-T02).
 *
 * Implements authoritative read receipt recording and logical recipient read state
 * aggregation for 1:1 and group conversations, adhering to ADR-007, ADR-008, and ADR-009.
 *
 * Core Guarantees:
 * 1. Semantic Decoupling: Presence != Delivery != Read != Synchronization.
 * 2. Authorization & Ownership: Caller cannot submit read receipts on behalf of another user.
 * 3. Conversation Membership: Caller must be an active participant in the conversation.
 * 4. Device Revocation Check: Revoked devices cannot generate valid read receipts.
 * 5. Monotonic & Idempotent: Duplicate receipts for the same message/device succeed deterministically.
 * 6. Logical Recipient Aggregation: User is marked as Read when >=1 active device reports read;
 *    group conversations report separate read states per logical recipient user.
 * 7. Transactional Outbox: Emits ConversationOutboxEventType::MessageRead for asynchronous Audit.
 */
class ReadReceiptService {
  public:
    /// Callback predicate returning true if the device is currently in DEVICE_STATUS_ACTIVE.
    using DeviceStatusChecker = std::function<bool(const domain::DeviceId&)>;

    ReadReceiptService(std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                       std::shared_ptr<repository::IMembershipRepository> membership_repo,
                       std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                       DeviceStatusChecker device_status_checker = nullptr);
    ~ReadReceiptService() = default;

    ReadReceiptService(const ReadReceiptService&) = delete;
    ReadReceiptService& operator=(const ReadReceiptService&) = delete;
    ReadReceiptService(ReadReceiptService&&) = default;
    ReadReceiptService& operator=(ReadReceiptService&&) = default;

    /**
     * @brief Authoritatively records a recipient device's read receipt.
     *
     * @param cmd Strongly-typed read receipt command.
     * @return ServiceResult containing ReadReceiptResponse on success or domain error code.
     */
    [[nodiscard]] ServiceResult<ReadReceiptResponse> record_read_receipt(const ReadReceiptCommand& cmd);

    /**
     * @brief Aggregates per-logical-recipient read statuses for a message.
     *
     * @param conversation_id Target conversation identifier.
     * @param message_id Target message identifier.
     * @param caller_user_id Authenticated caller querying read status.
     * @return ServiceResult containing MessageReadStatusResponse breakdown.
     */
    [[nodiscard]] ServiceResult<MessageReadStatusResponse>
    get_message_read_status(const domain::ConversationId& conversation_id, const domain::MessageId& message_id,
                            const domain::UserId& caller_user_id);

  private:
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<repository::IMembershipRepository> membership_repo_;
    std::shared_ptr<repository::IOutboxRepository> outbox_repo_;
    DeviceStatusChecker device_status_checker_;
};

} // namespace securecloud::messaging::service
