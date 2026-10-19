#include "service/message_submission_service.hpp"

#include "domain/submission_fingerprint.hpp"
#include "service/submission_validator.hpp"

#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace securecloud::messaging::service {

MessageSubmissionService::MessageSubmissionService(std::shared_ptr<ConversationAuthorizationService> auth_service,
                                                   std::shared_ptr<ISequenceAllocator> sequence_allocator,
                                                   std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard,
                                                   std::shared_ptr<repository::IMessageRepository> message_repo,
                                                   std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                                                   std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                                                   std::shared_ptr<E2EEnvelopeValidator> envelope_validator,
                                                   std::shared_ptr<RecipientDeviceResolutionService> resolution_service)
    : auth_service_(std::move(auth_service)), sequence_allocator_(std::move(sequence_allocator)),
      idempotency_guard_(std::move(idempotency_guard)), message_repo_(std::move(message_repo)),
      delivery_repo_(std::move(delivery_repo)), outbox_repo_(std::move(outbox_repo)),
      envelope_validator_(std::move(envelope_validator)), resolution_service_(std::move(resolution_service)) {
    if (!auth_service_ || !sequence_allocator_ || !idempotency_guard_ || !message_repo_ || !delivery_repo_ ||
        !outbox_repo_) {
        throw std::invalid_argument("MessageSubmissionService requires non-null dependencies");
    }
}

ServiceResult<MessageSubmissionResponse>
MessageSubmissionService::submit_message(const domain::MessageSubmissionCommand& cmd) {
    // 1. Syntactic & Cryptographic Envelope Validation (SubmissionValidator)
    auto val_result = SubmissionValidator::validate(cmd);
    if (!val_result) {
        return ServiceResult<MessageSubmissionResponse>::fail(
            val_result.error_code, util::ZeroPlaintextGuard::sanitize_error_message(val_result.error_message));
    }

    // 2. Participant Authorization & Active Standing Check (ConversationAuthorizationService)
    auto auth_result = auth_service_->can_send_message(cmd.caller_user_id, cmd.conversation_id);
    if (!auth_result) {
        return ServiceResult<MessageSubmissionResponse>::fail(
            auth_result.error_code, util::ZeroPlaintextGuard::sanitize_error_message(auth_result.reason));
    }

    // 2b. Comprehensive E2E Envelope Security & Anti-Plaintext Validation (ADR-008, MSG-006)
    if (envelope_validator_) {
        domain::E2EMessageEnvelope env;
        env.conversation_id = cmd.conversation_id;
        env.sender_user_id = cmd.caller_user_id;
        env.sender_device_id = cmd.sender_device_id;
        env.protocol_version = cmd.protocol_version;

        for (const auto& target : cmd.delivery_targets) {
            domain::PerDeviceEnvelope pde;
            pde.recipient_user_id = target.recipient_user_id;
            pde.recipient_device_id = target.recipient_device_id;
            pde.ciphertext_blob = target.ciphertext_blob;
            pde.ephemeral_public_key = target.ephemeral_public_key;
            pde.iv = target.iv;
            pde.auth_tag = target.auth_tag;
            auto algo_opt = domain::e2e_algorithm_from_string(target.algorithm);
            pde.algorithm = algo_opt.value_or(domain::E2EAlgorithm::XChaCha20_Poly1305);
            pde.protocol_version = target.protocol_version;
            pde.one_time_prekey_id = target.one_time_prekey_id;
            env.per_device_envelopes.push_back(std::move(pde));
        }

        MessagingCallerContext caller_ctx;
        caller_ctx.base.user_id = cmd.caller_user_id.str();
        caller_ctx.base.device_id = cmd.sender_device_id.str();

        std::vector<domain::UserId> participants;
        auto active_members = auth_service_->membership_repository().list_active_participants(cmd.conversation_id);
        for (const auto& m : active_members) {
            participants.push_back(m.user_id);
        }
        if (participants.empty()) {
            participants.push_back(cmd.caller_user_id);
            for (const auto& target : cmd.delivery_targets) {
                if (std::find(participants.begin(), participants.end(), target.recipient_user_id) ==
                    participants.end()) {
                    participants.push_back(target.recipient_user_id);
                }
            }
        }

        auto env_val_result =
            envelope_validator_->validate(env, caller_ctx, participants, /*enforce_completeness=*/true);
        if (!env_val_result.is_valid) {
            return ServiceResult<MessageSubmissionResponse>::fail(
                env_val_result.error_code,
                util::ZeroPlaintextGuard::sanitize_error_message(env_val_result.error_message));
        }
    }

    // Synchronize concurrent submissions with identical idempotency keys (ADR-009, MSG-005-T04)
    size_t stripe_idx = 0;
    if (!cmd.client_idempotency_token.empty()) {
        stripe_idx =
            std::hash<std::string>{}(cmd.sender_device_id.str() + ":" + cmd.client_idempotency_token) % kNumStripes;
    }
    std::lock_guard<std::mutex> lock(submission_stripes_[stripe_idx]);

    // 3. Cryptographic Payload Fingerprint Calculation (ADR-008 SHA-256)
    std::string fingerprint = domain::calculate_submission_fingerprint(cmd);

    // 4. Client Idempotency Evaluation
    auto idem_result = idempotency_guard_->evaluate_submission(cmd, fingerprint);
    if (idem_result.action == IdempotencyAction::RetryWait) {
        // Bounded wait to allow in-flight duplicate submission to commit (MSG-005-T03)
        for (int retry = 0; retry < 20; ++retry) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            idem_result = idempotency_guard_->evaluate_submission(cmd, fingerprint);
            if (idem_result.action != IdempotencyAction::RetryWait) {
                break;
            }
        }
    }

    switch (idem_result.action) {
    case IdempotencyAction::ReturnCached: {
        const auto& record = *idem_result.cached_record;
        MessageSubmissionResponse resp;
        resp.message_id = record.message_id;
        resp.conversation_id = record.conversation_id;
        resp.message_sequence = record.message_sequence;
        resp.accepted_at = record.created_at;
        resp.initial_state = v1::DELIVERY_STATE_QUEUED;
        resp.is_replay = true;
        return ServiceResult<MessageSubmissionResponse>::ok(resp);
    }
    case IdempotencyAction::RejectConflict:
        return ServiceResult<MessageSubmissionResponse>::fail(
            idem_result.error_code, util::ZeroPlaintextGuard::sanitize_error_message(idem_result.error_message));

    case IdempotencyAction::RetryWait:
        return ServiceResult<MessageSubmissionResponse>::fail(
            v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
            "A submission with this idempotency key is currently being processed. Please retry.");

    case IdempotencyAction::ProceedNew:
        break;
    }

    // 5. Global Message Identifier and Acceptance Timestamp Generation (UUIDv7)
    auto message_id = domain::MessageId::generate_v7();
    auto accepted_at = std::chrono::system_clock::now();

    // 6. Claim token in database: mark idempotency as PROCESSING
    idempotency_guard_->mark_processing(cmd, fingerprint, message_id);

    try {
        // 7. Time-bucketing and monotonic sequence allocation within monthly UTC partition
        auto message_bucket = domain::MessageBucket::from_time_point(accepted_at);
        uint64_t sequence = sequence_allocator_->allocate_sequence(cmd.conversation_id, message_bucket);

        // 8. Durably persist immutable MessageEntity in messages_by_conversation
        domain::MessageEntity msg_entity;
        msg_entity.conversation_id = cmd.conversation_id;
        msg_entity.message_bucket = message_bucket;
        msg_entity.message_sequence = sequence;
        msg_entity.message_id = message_id;
        msg_entity.sender_user_id = cmd.caller_user_id;
        msg_entity.sender_device_id = cmd.sender_device_id;
        msg_entity.priority = cmd.priority;
        msg_entity.accepted_at = accepted_at;
        msg_entity.envelope.ciphertext = cmd.delivery_targets.front().ciphertext_blob;
        msg_entity.envelope.envelope_version = static_cast<int32_t>(cmd.protocol_version);

        message_repo_->save_message(msg_entity);

        // 9. Durably persist initial active delivery queues and fan-out tracking state
        std::vector<domain::DeviceDeliveryRecord> pending_records;
        pending_records.reserve(cmd.delivery_targets.size());
        std::vector<domain::RecipientDeliveryState> recipient_states;
        recipient_states.reserve(cmd.delivery_targets.size());

        for (const auto& target : cmd.delivery_targets) {
            domain::DeviceDeliveryRecord d_rec;
            d_rec.device_id = target.recipient_device_id;
            d_rec.delivery_bucket = message_bucket.value();
            d_rec.accepted_at = accepted_at;
            d_rec.message_id = message_id;
            d_rec.conversation_id = cmd.conversation_id;
            d_rec.message_sequence = sequence;
            d_rec.message_priority = cmd.priority;
            d_rec.delivery_state = domain::DeliveryState::Pending;
            d_rec.attempt_count = 0;

            // Envelope fields (MSG-006-T04 / T05)
            d_rec.ciphertext_blob = target.ciphertext_blob;
            d_rec.ephemeral_public_key = target.ephemeral_public_key;
            d_rec.iv = target.iv;
            d_rec.auth_tag = target.auth_tag;
            auto algo_opt = domain::e2e_algorithm_from_string(target.algorithm);
            d_rec.algorithm = algo_opt.value_or(domain::E2EAlgorithm::XChaCha20_Poly1305);
            d_rec.protocol_version = target.protocol_version;
            d_rec.one_time_prekey_id = target.one_time_prekey_id;
            pending_records.push_back(d_rec);

            domain::RecipientDeliveryState r_state;
            r_state.message_id = message_id;
            r_state.recipient_device_id = target.recipient_device_id;
            r_state.recipient_user_id = target.recipient_user_id;
            r_state.delivery_state = domain::DeliveryState::Pending;
            recipient_states.push_back(r_state);
        }

        delivery_repo_->save_pending_deliveries(pending_records);
        delivery_repo_->save_recipient_delivery_states(recipient_states);

        // 10. Durably persist Transactional Outbox Event for decoupled worker fan-out
        domain::ConversationOutboxEvent outbox_evt;
        outbox_evt.event_id = domain::MessageId::generate_v7().to_string();
        outbox_evt.conversation_id = cmd.conversation_id;
        outbox_evt.event_type = domain::ConversationOutboxEventType::MessageSent;
        outbox_evt.created_at = accepted_at;

        std::ostringstream json_ss;
        json_ss << "{\"message_id\":\"" << message_id.to_string() << "\","
                << "\"sequence\":" << sequence << ","
                << "\"sender_user_id\":\"" << cmd.caller_user_id.str() << "\","
                << "\"sender_device_id\":\"" << cmd.sender_device_id.str() << "\","
                << "\"recipient_device_count\":" << cmd.delivery_targets.size() << "}";
        outbox_evt.payload_json = json_ss.str();

        outbox_repo_->enqueue_event(outbox_evt);

        // 11. Durably mark Idempotency Record as COMMITTED
        idempotency_guard_->mark_committed(cmd, fingerprint, message_id, sequence);

        // 12. Return success response (Initial acceptance boundary committed)
        MessageSubmissionResponse response;
        response.message_id = message_id;
        response.conversation_id = cmd.conversation_id;
        response.message_sequence = sequence;
        response.accepted_at = accepted_at;
        response.initial_state = v1::DELIVERY_STATE_QUEUED;
        response.is_replay = false;

        return ServiceResult<MessageSubmissionResponse>::ok(response);
    } catch (const std::exception& ex) {
        // Upon persistence failure, mark idempotency as failed so client can safely retry
        idempotency_guard_->mark_failed(cmd.sender_device_id, cmd.client_idempotency_token);
        return ServiceResult<MessageSubmissionResponse>::fail(
            v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
            util::ZeroPlaintextGuard::sanitize_error_message(std::string("Message persistence failed: ") + ex.what()));
    }
}

} // namespace securecloud::messaging::service
