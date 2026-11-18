#pragma once

#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/membership_repository_interface.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "service/conversation_service.hpp"
#include "service/read_receipt_commands.hpp"

#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::messaging::service {

class ReadReceiptService {
  public:
    using DeviceStatusChecker = std::function<bool(const domain::DeviceId&)>;

    ReadReceiptService(std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                       std::shared_ptr<repository::IMembershipRepository> membership_repo,
                       std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                       std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo,
                       DeviceStatusChecker device_status_checker = nullptr);
    ~ReadReceiptService() = default;

    ReadReceiptService(const ReadReceiptService&) = delete;
    ReadReceiptService& operator=(const ReadReceiptService&) = delete;
    ReadReceiptService(ReadReceiptService&&) = delete;
    ReadReceiptService& operator=(ReadReceiptService&&) = delete;

    [[nodiscard]] ServiceResult<ReadReceiptResponse> record_read_receipt(const ReadReceiptCommand& cmd);

    [[nodiscard]] ServiceResult<MessageReadStatusResponse>
    get_message_read_status(const domain::ConversationId& conversation_id, const domain::MessageId& message_id,
                            const domain::UserId& caller_user_id);

    [[nodiscard]] ServiceResult<domain::MessageDeliverySummary>
    get_message_delivery_summary(const domain::ConversationId& conversation_id, const domain::MessageId& message_id,
                                 const domain::UserId& caller_user_id);

  private:
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<repository::IMembershipRepository> membership_repo_;
    std::shared_ptr<repository::IOutboxRepository> outbox_repo_;
    std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo_;
    DeviceStatusChecker device_status_checker_;

    static constexpr size_t kNumStripes = 64;
    mutable std::array<std::mutex, kNumStripes> receipt_stripes_;
};

} // namespace securecloud::messaging::service
