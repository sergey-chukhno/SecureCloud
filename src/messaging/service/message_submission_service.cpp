#include "service/message_submission_service.hpp"

#include "audit/canonical_audit_mapper.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"
#include "domain/submission_fingerprint.hpp"
#include "service/submission_validator.hpp"

#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace securecloud::messaging::service {

namespace {

void stage_submission_audit_events(repository::IMessagingAuditOutboxRepository* audit_repo,
                                   const domain::MessageSubmissionCommand& cmd, const domain::MessageId& message_id,
                                   uint64_t sequence, std::chrono::system_clock::time_point occurred_at,
                                   bool check_existing) {
    if (audit_repo == nullptr) {
        return;
    }

    const std::string routing_key = cmd.conversation_id.to_string();
    const std::string bucket = domain::compute_outbox_bucket_utc(occurred_at);
    const int32_t shard_id = domain::compute_outbox_shard_id(routing_key);

    size_t total_envelope_bytes = 0;
    for (const auto& target : cmd.delivery_targets) {
        total_envelope_bytes += target.ciphertext_blob.size();
    }

    const std::string submitted_event_id =
        domain::generate_message_audit_event_id(message_id, domain::MessagingAuditEventType::MessageSubmitted);
    if (!check_existing || !audit_repo->has_event(bucket, shard_id, occurred_at, submitted_event_id)) {
        nlohmann::json meta = {
            {"conversation_id", routing_key},
            {"sequence", sequence},
            {"priority", domain::to_string(cmd.priority)},
            {"recipient_device_count", cmd.delivery_targets.size()},
            {"envelope_bytes", total_envelope_bytes},
            {"protocol_version", static_cast<int32_t>(cmd.protocol_version)},
        };
        if (check_existing) {
            meta["forward_recovered"] = true;
        }

        domain::MessagingAuditEvent submitted_event{
            .event_id = submitted_event_id,
            .event_type = domain::MessagingAuditEventType::MessageSubmitted,
            .severity = domain::MessagingAuditSeverity::Info,
            .occurred_at = occurred_at,
            .actor_user_id = cmd.caller_user_id,
            .actor_device_id = cmd.sender_device_id,
            .target_resource = message_id.to_string(),
            .payload_json = meta.dump(),
            .correlation_id = cmd.correlation_id,
        };
        audit::stage_canonical_audit_event(audit_repo, submitted_event, routing_key);
    }

    if (cmd.priority == domain::MessagePriority::Emergency) {
        const std::string emergency_event_id =
            domain::generate_message_audit_event_id(message_id, domain::MessagingAuditEventType::EmergencyActivated);
        if (!check_existing || !audit_repo->has_event(bucket, shard_id, occurred_at, emergency_event_id)) {
            const nlohmann::json emergency_meta = {
                {"conversation_id", routing_key},
                {"message_id", message_id.to_string()},
                {"priority", "EMERGENCY"},
                {"recipient_device_count", cmd.delivery_targets.size()},
            };

            domain::MessagingAuditEvent emergency_event{
                .event_id = emergency_event_id,
                .event_type = domain::MessagingAuditEventType::EmergencyActivated,
                .severity = domain::MessagingAuditSeverity::Critical,
                .occurred_at = occurred_at,
                .actor_user_id = cmd.caller_user_id,
                .actor_device_id = cmd.sender_device_id,
                .target_resource = routing_key,
                .payload_json = emergency_meta.dump(),
                .correlation_id = cmd.correlation_id,
            };
            audit::stage_canonical_audit_event(audit_repo, emergency_event, routing_key);
        }
    }
}

} // namespace

MessageSubmissionService::MessageSubmissionService(
    std::shared_ptr<ConversationAuthorizationService> auth_service,
    std::shared_ptr<ISequenceAllocator> sequence_allocator,
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard,
    std::shared_ptr<repository::IMessageRepository> message_repo,
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
    std::shared_ptr<repository::IOutboxRepository> outbox_repo,
    std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo,
    std::shared_ptr<E2EEnvelopeValidator> envelope_validator,
    std::shared_ptr<RecipientDeviceResolutionService> resolution_service)
    : auth_service_(std::move(auth_service)), sequence_allocator_(std::move(sequence_allocator)),
      idempotency_guard_(std::move(idempotency_guard)), message_repo_(std::move(message_repo)),
      delivery_repo_(std::move(delivery_repo)), outbox_repo_(std::move(outbox_repo)),
      audit_repo_(std::move(audit_repo)), envelope_validator_(std::move(envelope_validator)),
      resolution_service_(std::move(resolution_service)) {
    if (!auth_service_ || !sequence_allocator_ || !idempotency_guard_ || !message_repo_ || !delivery_repo_ ||
        !outbox_repo_ || !audit_repo_) {
        throw std::invalid_argument("MessageSubmissionService requires non-null dependencies");
    }
}

ServiceResult<MessageSubmissionResponse>
MessageSubmissionService::submit_message(const domain::MessageSubmissionCommand& cmd) {
    auto val_result = SubmissionValidator::validate(cmd);
    if (!val_result) {
        return ServiceResult<MessageSubmissionResponse>::fail(
            val_result.error_code, util::ZeroPlaintextGuard::sanitize_error_message(val_result.error_message));
    }

    auto auth_result = auth_service_->can_send_message(cmd.caller_user_id, cmd.conversation_id);
    if (!auth_result) {
        const auto denied_at = std::chrono::system_clock::now();
        domain::MessagingAuditEvent denied_event{
            .event_id = domain::generate_audit_event_id(),
            .event_type = domain::MessagingAuditEventType::SecurityAuthorizationDenied,
            .severity = domain::MessagingAuditSeverity::Security,
            .occurred_at = denied_at,
            .actor_user_id = cmd.caller_user_id,
            .actor_device_id = cmd.sender_device_id,
            .target_resource = cmd.conversation_id.to_string(),
            .payload_json = R"({"action":"SUBMIT_MESSAGE","reason":"NOT_AN_ACTIVE_MEMBER"})",
            .correlation_id = cmd.correlation_id,
        };
        audit::stage_canonical_audit_event(audit_repo_.get(), denied_event, cmd.conversation_id.to_string());

        return ServiceResult<MessageSubmissionResponse>::fail(
            auth_result.error_code, util::ZeroPlaintextGuard::sanitize_error_message(auth_result.reason));
    }

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

    size_t stripe_idx = 0;
    if (!cmd.client_idempotency_token.empty()) {
        stripe_idx =
            std::hash<std::string>{}(cmd.sender_device_id.str() + ":" + cmd.client_idempotency_token) % kNumStripes;
    }
    std::lock_guard<std::mutex> lock(submission_stripes_[stripe_idx]);

    std::string fingerprint = domain::calculate_submission_fingerprint(cmd);

    auto idem_result = idempotency_guard_->evaluate_submission(cmd, fingerprint);
    if (idem_result.action == IdempotencyAction::RetryWait) {
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

        // Idempotent forward recovery: only stage if missing from audit outbox so PUBLISHED rows stay intact
        stage_submission_audit_events(audit_repo_.get(), cmd, record.message_id, record.message_sequence,
                                      record.created_at, /*check_existing=*/true);

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

    auto message_id = domain::MessageId::generate_v7();
    auto accepted_at = std::chrono::system_clock::now();

    idempotency_guard_->mark_processing(cmd, fingerprint, message_id);

    try {
        auto message_bucket = domain::MessageBucket::from_time_point(accepted_at);
        uint64_t sequence = sequence_allocator_->allocate_sequence(cmd.conversation_id, message_bucket);

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

        stage_submission_audit_events(audit_repo_.get(), cmd, message_id, sequence, accepted_at,
                                      /*check_existing=*/false);

        idempotency_guard_->mark_committed(cmd, fingerprint, message_id, sequence, accepted_at);

        MessageSubmissionResponse response;
        response.message_id = message_id;
        response.conversation_id = cmd.conversation_id;
        response.message_sequence = sequence;
        response.accepted_at = accepted_at;
        response.initial_state = v1::DELIVERY_STATE_QUEUED;
        response.is_replay = false;

        return ServiceResult<MessageSubmissionResponse>::ok(response);
    } catch (const std::exception& ex) {
        idempotency_guard_->mark_failed(cmd.sender_device_id, cmd.client_idempotency_token);
        return ServiceResult<MessageSubmissionResponse>::fail(
            v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
            util::ZeroPlaintextGuard::sanitize_error_message(std::string("Message persistence failed: ") + ex.what()));
    }
}

} // namespace securecloud::messaging::service
