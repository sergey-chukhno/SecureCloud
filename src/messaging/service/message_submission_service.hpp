#pragma once

#include "domain/message_entity.hpp"
#include "domain/submission_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/e2e_envelope_validator.hpp"
#include "service/idempotency_guard.hpp"
#include "service/recipient_device_resolution_service.hpp"
#include "service/sequence_allocator_interface.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>

namespace securecloud::messaging::service {

struct MessageSubmissionResponse {
    domain::MessageId message_id;
    domain::ConversationId conversation_id;
    domain::MessageSequence message_sequence{0};
    std::chrono::system_clock::time_point accepted_at;
    v1::DeliveryState initial_state{v1::DELIVERY_STATE_QUEUED};
    bool is_replay{false};
};

class MessageSubmissionService {
  public:
    MessageSubmissionService(std::shared_ptr<ConversationAuthorizationService> auth_service,
                             std::shared_ptr<ISequenceAllocator> sequence_allocator,
                             std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard,
                             std::shared_ptr<repository::IMessageRepository> message_repo,
                             std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                             std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                             std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo,
                             std::shared_ptr<E2EEnvelopeValidator> envelope_validator = nullptr,
                             std::shared_ptr<RecipientDeviceResolutionService> resolution_service = nullptr);

    [[nodiscard]] ServiceResult<MessageSubmissionResponse> submit_message(const domain::MessageSubmissionCommand& cmd);

  private:
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<ISequenceAllocator> sequence_allocator_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<repository::IMessageRepository> message_repo_;
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<repository::IOutboxRepository> outbox_repo_;
    std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo_;
    std::shared_ptr<E2EEnvelopeValidator> envelope_validator_{nullptr};
    std::shared_ptr<RecipientDeviceResolutionService> resolution_service_{nullptr};

    static constexpr size_t kNumStripes = 64;
    std::array<std::mutex, kNumStripes> submission_stripes_;
};

} // namespace securecloud::messaging::service
