#pragma once

#include "domain/message_entity.hpp"
#include "domain/submission_types.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/idempotency_guard.hpp"
#include "service/sequence_allocator_interface.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>

namespace securecloud::messaging::service {

/**
 * @brief Successful message submission result returned by MessageSubmissionService.
 */
struct MessageSubmissionResponse {
    domain::MessageId message_id;
    domain::ConversationId conversation_id;
    domain::MessageSequence message_sequence{0};
    std::chrono::system_clock::time_point accepted_at;
    v1::DeliveryState initial_state{v1::DELIVERY_STATE_QUEUED};
    bool is_replay{false};
};

/**
 * @brief Authoritative message submission application service.
 *
 * Implements the critical durability boundary (ADR-007, ADR-008):
 * 1. Syntactic & Cryptographic Envelope Validation (SubmissionValidator)
 * 2. Participant Authorization & Active Standing (ConversationAuthorizationService)
 * 3. Cryptographic Fingerprinting & Idempotency Evaluation (IdempotencyGuard)
 * 4. Monotonic Sequence Allocation within UTC monthly partition (ISequenceAllocator)
 * 5. Immutable Message Envelope Persistence (IMessageRepository)
 * 6. Initial Per-Device Delivery State Persistence (IDeliveryStateRepository)
 * 7. Transactional Outbox Event Publication (IOutboxRepository)
 * 8. Durable Idempotency Commit (IdempotencyGuard)
 */
class MessageSubmissionService {
  public:
    MessageSubmissionService(std::shared_ptr<ConversationAuthorizationService> auth_service,
                             std::shared_ptr<ISequenceAllocator> sequence_allocator,
                             std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard,
                             std::shared_ptr<repository::IMessageRepository> message_repo,
                             std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                             std::shared_ptr<repository::IOutboxRepository> outbox_repo);

    /**
     * @brief Authoritatively processes a client message submission request.
     *
     * @param cmd Strongly-typed submission command.
     * @return ServiceResult containing MessageSubmissionResponse on success or domain error.
     */
    [[nodiscard]] ServiceResult<MessageSubmissionResponse> submit_message(const domain::MessageSubmissionCommand& cmd);

  private:
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<ISequenceAllocator> sequence_allocator_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<repository::IMessageRepository> message_repo_;
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<repository::IOutboxRepository> outbox_repo_;

    static constexpr size_t kNumStripes = 64;
    std::array<std::mutex, kNumStripes> submission_stripes_;
};

} // namespace securecloud::messaging::service
