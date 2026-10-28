#include "service/messaging_service_impl.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "domain/delivery_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/presence_types.hpp"
#include "securecloud/grpc/caller_context.hpp"
#include "securecloud/security/mtls_config.hpp"
#include "service/conversation_service.hpp"
#include "service/delivery_lifecycle.hpp"
#include "service/message_submission_service.hpp"
#include "service/messaging_caller_context.hpp"
#include "service/messaging_error_mapper.hpp"
#include "service/read_receipt_commands.hpp"
#include "service/read_receipt_service.hpp"

#include <chrono>
#include <future>
#include <iostream>
#include <string_view>
#include <utility>

namespace securecloud::messaging::service {

namespace {

void log_rpc_invocation(std::string_view rpc_name, const ::grpc::ServerContext* context) {
    const std::string correlation_id = MessagingServiceImpl::extract_correlation_id(context);
    const std::string peer = MessagingServiceImpl::extract_peer_identity(context);
    std::cout << "[DEBUG] [messaging] " << rpc_name << " invoked (correlation_id='" << correlation_id << "', peer='"
              << peer << "')\n";
}

void populate_conversation_metadata(const ConversationDetails& details,
                                    securecloud::messaging::v1::ConversationMetadata* out) {
    out->set_conversation_id(details.conversation.conversation_id.to_string());
    if (details.conversation.type == domain::ConversationType::Direct) {
        out->set_type(securecloud::messaging::v1::CONVERSATION_TYPE_DIRECT);
    } else {
        out->set_type(securecloud::messaging::v1::CONVERSATION_TYPE_GROUP);
        if (details.group_metadata) {
            out->set_title(details.group_metadata->title);
        }
    }
    out->set_creator_user_id(details.conversation.created_by_user_id.str());
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(details.conversation.created_at.time_since_epoch())
                  .count();
    out->set_created_at_unix_ms(ms);
    for (const auto& p : details.active_participants) {
        out->add_participant_user_ids(p.user_id.str());
    }
}

void populate_message_envelope(const domain::MessageEntity& entity,
                               securecloud::messaging::v1::MessageEnvelope* envelope,
                               const domain::DeviceId* recipient_device_id = nullptr,
                               const domain::DeviceDeliveryRecord* device_record = nullptr,
                               bool is_untargeted_for_device = false) {
    envelope->set_message_id(entity.message_id.to_string());
    envelope->set_conversation_id(entity.conversation_id.to_string());
    envelope->set_sender_user_id(entity.sender_user_id.str());
    envelope->set_sender_device_id(entity.sender_device_id.str());
    switch (entity.priority) {
    case domain::MessagePriority::Urgent:
        envelope->set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_URGENT);
        break;
    case domain::MessagePriority::Emergency:
        envelope->set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_EMERGENCY);
        break;
    case domain::MessagePriority::Normal:
    default:
        envelope->set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_NORMAL);
        break;
    }
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(entity.accepted_at.time_since_epoch()).count();
    envelope->set_created_at_unix_ms(ms);

    if (device_record != nullptr) {
        auto* target = envelope->add_delivery_targets();
        target->set_recipient_device_id(recipient_device_id ? recipient_device_id->str()
                                                            : entity.sender_device_id.str());
        switch (device_record->delivery_state) {
        case domain::DeliveryState::Queued:
            target->set_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);
            break;
        case domain::DeliveryState::Delivering:
            target->set_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERING);
            break;
        case domain::DeliveryState::Delivered:
            target->set_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
            break;
        case domain::DeliveryState::RetryWait:
            target->set_state(securecloud::messaging::v1::DELIVERY_STATE_RETRY_WAIT);
            break;
        case domain::DeliveryState::Expired:
            target->set_state(securecloud::messaging::v1::DELIVERY_STATE_EXPIRED);
            break;
        default:
            target->set_state(securecloud::messaging::v1::DELIVERY_STATE_UNSPECIFIED);
            break;
        }

        auto* ep = target->mutable_encrypted_payload();
        ep->set_ciphertext_blob(device_record->ciphertext_blob);
        ep->set_ephemeral_public_key(reinterpret_cast<const char*>(device_record->ephemeral_public_key.data()),
                                     device_record->ephemeral_public_key.size());
        ep->set_initialization_vector(reinterpret_cast<const char*>(device_record->iv.data()),
                                      device_record->iv.size());
        ep->set_auth_tag(reinterpret_cast<const char*>(device_record->auth_tag.data()), device_record->auth_tag.size());
        ep->set_algorithm(domain::to_string(device_record->algorithm));
    } else if (!is_untargeted_for_device && !entity.envelope.ciphertext.empty()) {
        auto* target = envelope->add_delivery_targets();
        target->set_recipient_device_id(recipient_device_id ? recipient_device_id->str()
                                                            : entity.sender_device_id.str());
        target->set_state(securecloud::messaging::v1::DELIVERY_STATE_DELIVERED);
        auto* ep = target->mutable_encrypted_payload();
        ep->set_ciphertext_blob(entity.envelope.ciphertext);
        ep->set_algorithm("XChaCha20-Poly1305");
    }
}

void populate_sync_cursor(const domain::DeviceSyncCursor& cursor, securecloud::messaging::v1::SyncCursor* out) {
    out->set_device_id(cursor.device_id.str());
    out->set_conversation_id(cursor.conversation_id.to_string());
    out->set_last_delivered_sequence(static_cast<int64_t>(cursor.last_synced_sequence));
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(cursor.last_sync_at.time_since_epoch()).count();
    out->set_last_sync_timestamp_unix_ms(ms);
}

::grpc::Status sync_status_to_grpc_status(SyncMessagesStatus status, const std::string& error_message,
                                          const std::string& correlation_id, ::grpc::ServerContext* context) {
    switch (status) {
    case SyncMessagesStatus::Success:
        return ::grpc::Status::OK;
    case SyncMessagesStatus::NotAuthorized:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                              error_message.empty() ? "Caller is not an active participant" : error_message,
                              correlation_id, context);
    case SyncMessagesStatus::ConversationNotFound:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
                              error_message.empty() ? "Conversation not found" : error_message, correlation_id,
                              context);
    case SyncMessagesStatus::CursorOutOfBounds:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS,
                              error_message.empty() ? "Cursor out of bounds" : error_message, correlation_id, context);
    case SyncMessagesStatus::InvalidArguments:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                              error_message.empty() ? "Invalid arguments" : error_message, correlation_id, context);
    case SyncMessagesStatus::StorageError:
    default:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                              error_message.empty() ? "Internal storage error" : error_message, correlation_id,
                              context);
    }
}

::grpc::Status cursor_update_status_to_grpc_status(SyncCursorUpdateStatus status, const std::string& error_message,
                                                   const std::string& correlation_id, ::grpc::ServerContext* context) {
    switch (status) {
    case SyncCursorUpdateStatus::Success:
        return ::grpc::Status::OK;
    case SyncCursorUpdateStatus::RegressionRejected:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS,
                              error_message.empty() ? "Cursor sequence regression rejected" : error_message,
                              correlation_id, context);
    case SyncCursorUpdateStatus::OutOfBoundsRejected:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS,
                              error_message.empty() ? "Cursor sequence exceeds conversation ceiling" : error_message,
                              correlation_id, context);
    case SyncCursorUpdateStatus::VersionConflict:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT,
                              error_message.empty() ? "Sync version conflict" : error_message, correlation_id, context);
    case SyncCursorUpdateStatus::InvalidCursor:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                              error_message.empty() ? "Invalid cursor arguments" : error_message, correlation_id,
                              context);
    case SyncCursorUpdateStatus::StorageError:
    default:
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                              error_message.empty() ? "Internal storage error" : error_message, correlation_id,
                              context);
    }
}

} // namespace

MessagingServiceImpl::MessagingServiceImpl(std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool,
                                           std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool,
                                           std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool,
                                           std::shared_ptr<ConversationService> conversation_service,
                                           std::shared_ptr<MessageSubmissionService> submission_service,
                                           std::shared_ptr<DeliveryService> delivery_service,
                                           std::shared_ptr<ReadReceiptService> read_receipt_service,
                                           std::shared_ptr<MessageSyncService> sync_service,
                                           std::shared_ptr<SyncCursorManager> cursor_manager,
                                           std::shared_ptr<IPresenceCoordinator> presence_coordinator,
                                           std::shared_ptr<RecipientDeviceResolutionService> resolution_service)
    : submission_pool_(std::move(submission_pool)), delivery_pool_(std::move(delivery_pool)),
      sync_pool_(std::move(sync_pool)), conversation_service_(std::move(conversation_service)),
      submission_service_(std::move(submission_service)), delivery_service_(std::move(delivery_service)),
      read_receipt_service_(std::move(read_receipt_service)), sync_service_(std::move(sync_service)),
      cursor_manager_(std::move(cursor_manager)), presence_coordinator_(std::move(presence_coordinator)),
      resolution_service_(std::move(resolution_service)) {}

bool MessagingServiceImpl::check_and_record_presence_rate_limit(const domain::UserId& user_id) {
    const auto now = std::chrono::steady_clock::now();
    const auto window = std::chrono::minutes(1);
    constexpr size_t k_max_updates_per_minute = 12;

    std::lock_guard<std::mutex> lock(presence_rate_limit_mutex_);
    auto& timestamps = presence_rate_limits_[user_id];

    while (!timestamps.empty() && (now - timestamps.front()) > window) {
        timestamps.pop_front();
    }

    if (timestamps.size() >= k_max_updates_per_minute) {
        return false;
    }

    timestamps.push_back(now);
    return true;
}

// --- Message lifecycle RPCs ---

::grpc::Status MessagingServiceImpl::SendMessage(::grpc::ServerContext* context,
                                                 const ::securecloud::messaging::v1::SendMessageRequest* request,
                                                 ::securecloud::messaging::v1::SendMessageResponse* response) {
    log_rpc_invocation("SendMessage", context);
    if (!submission_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return val_status;
    }

    std::string effective_device_id = caller_ctx.device_id();
    if (effective_device_id.empty() && !request->sender_device_id().empty()) {
        effective_device_id = request->sender_device_id();
    }
    if (effective_device_id.empty() || !common::rpc::is_valid_uuid(effective_device_id)) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Missing or invalid device ID header (expected RFC 4122 UUID)"};
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return {::grpc::StatusCode::UNAUTHENTICATED, "Missing or invalid user ID header (expected RFC 4122 UUID)"};
    }
    domain::DeviceId sender_dev_id(effective_device_id);
    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    domain::MessageSubmissionCommand cmd;
    cmd.caller_user_id = *caller_id;
    cmd.sender_device_id = sender_dev_id;
    cmd.conversation_id = *conv_id;
    cmd.client_idempotency_token = !request->client_idempotency_token().empty() ? request->client_idempotency_token()
                                                                                : caller_ctx.idempotency_token;

    switch (request->priority()) {
    case v1::MESSAGE_PRIORITY_NORMAL:
        cmd.priority = domain::MessagePriority::Normal;
        break;
    case v1::MESSAGE_PRIORITY_URGENT:
        cmd.priority = domain::MessagePriority::Urgent;
        break;
    case v1::MESSAGE_PRIORITY_EMERGENCY:
        cmd.priority = domain::MessagePriority::Emergency;
        break;
    default:
        cmd.priority = domain::MessagePriority::Normal;
        break;
    }

    if (request->expires_at_unix_ms() > 0) {
        cmd.expires_at =
            std::chrono::system_clock::time_point(std::chrono::milliseconds(request->expires_at_unix_ms()));
    }

    for (const auto& target : request->delivery_targets()) {
        domain::DeviceDeliveryTarget dt;
        auto rec_uid = domain::UserId::from_string(target.recipient_user_id());
        if (!rec_uid || target.recipient_device_id().empty()) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                  "Invalid recipient user or device ID format", caller_ctx.correlation_id(), context);
        }
        dt.recipient_user_id = *rec_uid;
        dt.recipient_device_id = domain::DeviceId(target.recipient_device_id());

        const auto& ep = target.encrypted_payload();
        dt.ciphertext_blob = ep.ciphertext_blob();
        dt.ephemeral_public_key.assign(ep.ephemeral_public_key().begin(), ep.ephemeral_public_key().end());
        dt.iv.assign(ep.initialization_vector().begin(), ep.initialization_vector().end());
        dt.auth_tag.assign(ep.auth_tag().begin(), ep.auth_tag().end());
        dt.algorithm = ep.algorithm().empty() ? "XChaCha20-Poly1305" : ep.algorithm();
        cmd.delivery_targets.push_back(std::move(dt));
    }

    struct SubmissionTaskResult {
        ServiceResult<MessageSubmissionResponse> result;
        size_t target_count{0};
    };

    auto run_task = [sub_svc = submission_service_, command = std::move(cmd)]() -> SubmissionTaskResult {
        size_t t_count = command.delivery_targets.size();
        return {sub_svc->submit_message(command), t_count};
    };

    SubmissionTaskResult task_result;
    if (submission_pool_) {
        auto promise = std::make_shared<std::promise<SubmissionTaskResult>>();
        auto future = promise->get_future();
        bool enqueued = submission_pool_->try_submit([promise, run_task]() {
            try {
                promise->set_value(run_task());
            } catch (const std::exception& ex) {
                promise->set_value(
                    {ServiceResult<MessageSubmissionResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, ex.what()),
                     0});
            } catch (...) {
                promise->set_value({ServiceResult<MessageSubmissionResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                                                   "Unknown worker failure"),
                                    0});
            }
        });

        if (!enqueued) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                                  "Submission queue capacity exceeded", caller_ctx.correlation_id(), context);
        }

        if (context->raw_deadline().tv_sec != 0 || context->raw_deadline().tv_nsec != 0) {
            auto deadline = context->deadline();
            if (deadline < std::chrono::system_clock::time_point::max()) {
                auto wait_res = future.wait_until(deadline);
                if (wait_res == std::future_status::timeout) {
                    return {::grpc::StatusCode::DEADLINE_EXCEEDED, "SendMessage deadline exceeded"};
                }
            }
        }
        task_result = future.get();
    } else {
        task_result = run_task();
    }

    if (!task_result.result) {
        return to_grpc_status(task_result.result.error_code, task_result.result.error_message,
                              caller_ctx.correlation_id(), context);
    }

    response->set_message_id(task_result.result.value.message_id.to_string());
    response->set_conversation_id(task_result.result.value.conversation_id.to_string());
    auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(task_result.result.value.accepted_at.time_since_epoch())
            .count();
    response->set_accepted_at_unix_ms(ms);
    response->set_initial_state(task_result.result.value.initial_state);
    response->set_target_count(static_cast<uint32_t>(task_result.target_count));
    return ::grpc::Status::OK;
}

::grpc::Status MessagingServiceImpl::GetMessages(::grpc::ServerContext* context,
                                                 const ::securecloud::messaging::v1::GetMessagesRequest* request,
                                                 ::securecloud::messaging::v1::GetMessagesResponse* response) {
    log_rpc_invocation("GetMessages", context);
    if (!sync_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return val_status;
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return {::grpc::StatusCode::UNAUTHENTICATED, "Missing or invalid user ID header (expected RFC 4122 UUID)"};
    }

    if (!caller_ctx.device_id().empty() && !request->recipient_device_id().empty() &&
        caller_ctx.device_id() != request->recipient_device_id()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                              "Caller device cannot query messages on behalf of a different device",
                              caller_ctx.correlation_id(), context);
    }

    std::string effective_device_id =
        !request->recipient_device_id().empty() ? request->recipient_device_id() : caller_ctx.device_id();
    if (effective_device_id.empty()) {
        effective_device_id = "device-default";
    }

    if (resolution_service_) {
        auto dev_status = resolution_service_->get_device_status(*caller_id, domain::DeviceId(effective_device_id));
        if (dev_status.has_value() && *dev_status != securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
                                  "Calling device has been revoked or is not active", caller_ctx.correlation_id(),
                                  context);
        }
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    SyncDeviceMessagesCommand cmd;
    cmd.device_id = domain::DeviceId(effective_device_id);
    cmd.conversation_id = *conv_id;
    cmd.since_sequence =
        request->since_sequence() > 0 ? static_cast<domain::MessageSequence>(request->since_sequence()) : 0;
    cmd.max_messages = request->max_results() > 0 ? request->max_results() : k_default_sync_batch_size;

    auto run_task = [sync_svc = sync_service_, caller = *caller_id, command = std::move(cmd)]() {
        return sync_svc->sync_messages(caller, command);
    };

    SyncMessagesResult task_result;
    if (sync_pool_) {
        auto promise = std::make_shared<std::promise<SyncMessagesResult>>();
        auto future = promise->get_future();
        bool enqueued = sync_pool_->try_submit([promise, run_task]() {
            try {
                promise->set_value(run_task());
            } catch (const std::exception& ex) {
                promise->set_value(SyncMessagesResult::failure(SyncMessagesStatus::StorageError, domain::DeviceId(""),
                                                               std::nullopt, ex.what()));
            } catch (...) {
                promise->set_value(SyncMessagesResult::failure(SyncMessagesStatus::StorageError, domain::DeviceId(""),
                                                               std::nullopt, "Unknown worker failure"));
            }
        });

        if (!enqueued) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                                  "Sync worker pool capacity exceeded", caller_ctx.correlation_id(), context);
        }

        if (context->raw_deadline().tv_sec != 0 || context->raw_deadline().tv_nsec != 0) {
            auto deadline = context->deadline();
            if (deadline < std::chrono::system_clock::time_point::max()) {
                auto wait_res = future.wait_until(deadline);
                if (wait_res == std::future_status::timeout) {
                    return {::grpc::StatusCode::DEADLINE_EXCEEDED, "GetMessages deadline exceeded"};
                }
            }
        }
        task_result = future.get();
    } else {
        task_result = run_task();
    }

    if (!task_result.is_success()) {
        return sync_status_to_grpc_status(task_result.status, task_result.error_message, caller_ctx.correlation_id(),
                                          context);
    }

    for (const auto& msg : task_result.messages) {
        const domain::DeviceDeliveryRecord* dev_rec = nullptr;
        auto it = task_result.device_envelopes.find(msg.message_id);
        if (it != task_result.device_envelopes.end()) {
            dev_rec = &it->second;
        }
        bool is_untargeted =
            task_result.untargeted_messages.find(msg.message_id) != task_result.untargeted_messages.end();
        populate_message_envelope(msg, response->add_messages(), &task_result.device_id, dev_rec, is_untargeted);
    }
    response->set_has_more(task_result.has_more);
    response->set_latest_sequence(static_cast<int64_t>(task_result.latest_sequence));
    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::AcknowledgeDelivery(::grpc::ServerContext* context,
                                          const ::securecloud::messaging::v1::AcknowledgeDeliveryRequest* request,
                                          ::securecloud::messaging::v1::AcknowledgeDeliveryResponse* response) {
    log_rpc_invocation("AcknowledgeDelivery", context);
    if (!delivery_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return val_status;
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return {::grpc::StatusCode::UNAUTHENTICATED, "Missing or invalid user ID header (expected RFC 4122 UUID)"};
    }

    auto msg_id = domain::MessageId::from_string(request->message_id());
    if (!msg_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE, "Invalid message ID format",
                              caller_ctx.correlation_id(), context);
    }

    if (!caller_ctx.device_id().empty() && !request->recipient_device_id().empty() &&
        caller_ctx.device_id() != request->recipient_device_id()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                              "Caller device cannot acknowledge delivery on behalf of a different device",
                              caller_ctx.correlation_id(), context);
    }

    std::string effective_device_id = request->recipient_device_id();
    if (effective_device_id.empty()) {
        effective_device_id = caller_ctx.device_id();
    }
    if (effective_device_id.empty() || !common::rpc::is_valid_uuid(effective_device_id)) {
        return {::grpc::StatusCode::INVALID_ARGUMENT,
                "Missing or invalid recipient device ID (expected RFC 4122 UUID)"};
    }

    if (resolution_service_) {
        auto dev_status = resolution_service_->get_device_status(*caller_id, domain::DeviceId(effective_device_id));
        if (dev_status.has_value() && *dev_status != securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
                                  "Calling device has been revoked or is not active", caller_ctx.correlation_id(),
                                  context);
        }
    }

    DeliveryAckCommand cmd;
    cmd.message_id = *msg_id;
    cmd.recipient_device_id = domain::DeviceId(effective_device_id);
    cmd.caller_user_id = *caller_id;
    cmd.caller_device_id = domain::DeviceId(caller_ctx.device_id());
    if (request->delivered_at_unix_ms() > 0) {
        cmd.delivered_at =
            std::chrono::system_clock::time_point(std::chrono::milliseconds(request->delivered_at_unix_ms()));
    } else {
        cmd.delivered_at = std::chrono::system_clock::now();
    }

    auto run_task = [deliv_svc = delivery_service_, command = std::move(cmd)]() {
        return deliv_svc->acknowledge_delivery(command);
    };

    ServiceResult<DeliveryAckResponse> task_result;
    if (delivery_pool_) {
        auto promise = std::make_shared<std::promise<ServiceResult<DeliveryAckResponse>>>();
        auto future = promise->get_future();
        bool enqueued = delivery_pool_->try_submit([promise, run_task]() {
            try {
                promise->set_value(run_task());
            } catch (const std::exception& ex) {
                promise->set_value(
                    ServiceResult<DeliveryAckResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, ex.what()));
            } catch (...) {
                promise->set_value(ServiceResult<DeliveryAckResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                                            "Unknown worker failure"));
            }
        });

        if (!enqueued) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                                  "Delivery worker pool capacity exceeded", caller_ctx.correlation_id(), context);
        }

        if (context->raw_deadline().tv_sec != 0 || context->raw_deadline().tv_nsec != 0) {
            auto deadline = context->deadline();
            if (deadline < std::chrono::system_clock::time_point::max()) {
                auto wait_res = future.wait_until(deadline);
                if (wait_res == std::future_status::timeout) {
                    return {::grpc::StatusCode::DEADLINE_EXCEEDED, "AcknowledgeDelivery deadline exceeded"};
                }
            }
        }
        task_result = future.get();
    } else {
        task_result = run_task();
    }

    if (!task_result) {
        return to_grpc_status(task_result.error_code, task_result.error_message, caller_ctx.correlation_id(), context);
    }

    response->set_message_id(task_result.value.message_id.to_string());
    response->set_state(task_result.value.state);
    auto recorded_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(task_result.value.recorded_at.time_since_epoch()).count();
    response->set_recorded_at_unix_ms(recorded_ms);
    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::SendReadReceipt(::grpc::ServerContext* context,
                                      const ::securecloud::messaging::v1::SendReadReceiptRequest* request,
                                      ::securecloud::messaging::v1::SendReadReceiptResponse* response) {
    log_rpc_invocation("SendReadReceipt", context);
    if (!read_receipt_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return val_status;
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return {::grpc::StatusCode::UNAUTHENTICATED, "Missing or invalid user ID header (expected RFC 4122 UUID)"};
    }

    auto msg_id = domain::MessageId::from_string(request->message_id());
    if (!msg_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE, "Invalid message ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    if (!caller_ctx.device_id().empty() && !request->reader_device_id().empty() &&
        caller_ctx.device_id() != request->reader_device_id()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                              "Caller device cannot submit read receipts on behalf of a different device",
                              caller_ctx.correlation_id(), context);
    }

    std::string effective_device_id = request->reader_device_id();
    if (effective_device_id.empty()) {
        effective_device_id = caller_ctx.device_id();
    }
    if (effective_device_id.empty() || !common::rpc::is_valid_uuid(effective_device_id)) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Missing or invalid reader device ID (expected RFC 4122 UUID)"};
    }

    if (resolution_service_) {
        auto dev_status = resolution_service_->get_device_status(*caller_id, domain::DeviceId(effective_device_id));
        if (dev_status.has_value() && *dev_status != securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
                                  "Calling device has been revoked or is not active", caller_ctx.correlation_id(),
                                  context);
        }
    }

    ReadReceiptCommand cmd;
    cmd.message_id = *msg_id;
    cmd.conversation_id = *conv_id;
    cmd.reader_device_id = domain::DeviceId(effective_device_id);
    cmd.caller_user_id = *caller_id;
    cmd.caller_device_id = domain::DeviceId(caller_ctx.device_id());
    if (request->read_at_unix_ms() > 0) {
        cmd.read_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(request->read_at_unix_ms()));
    } else {
        cmd.read_at = std::chrono::system_clock::now();
    }

    auto run_task = [receipt_svc = read_receipt_service_, command = std::move(cmd)]() {
        return receipt_svc->record_read_receipt(command);
    };

    ServiceResult<ReadReceiptResponse> task_result;
    if (delivery_pool_) {
        auto promise = std::make_shared<std::promise<ServiceResult<ReadReceiptResponse>>>();
        auto future = promise->get_future();
        bool enqueued = delivery_pool_->try_submit([promise, run_task]() {
            try {
                promise->set_value(run_task());
            } catch (const std::exception& ex) {
                promise->set_value(
                    ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, ex.what()));
            } catch (...) {
                promise->set_value(ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                                            "Unknown worker failure"));
            }
        });

        if (!enqueued) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                                  "Delivery worker pool capacity exceeded", caller_ctx.correlation_id(), context);
        }

        if (context->raw_deadline().tv_sec != 0 || context->raw_deadline().tv_nsec != 0) {
            auto deadline = context->deadline();
            if (deadline < std::chrono::system_clock::time_point::max()) {
                auto wait_res = future.wait_until(deadline);
                if (wait_res == std::future_status::timeout) {
                    return {::grpc::StatusCode::DEADLINE_EXCEEDED, "SendReadReceipt deadline exceeded"};
                }
            }
        }
        task_result = future.get();
    } else {
        task_result = run_task();
    }

    if (!task_result) {
        return to_grpc_status(task_result.error_code, task_result.error_message, caller_ctx.correlation_id(), context);
    }

    response->set_message_id(task_result.value.message_id.to_string());
    response->set_state(task_result.value.state);
    auto recorded_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(task_result.value.recorded_at.time_since_epoch()).count();
    response->set_recorded_at_unix_ms(recorded_ms);
    return ::grpc::Status::OK;
}

::grpc::Status MessagingServiceImpl::GetMessageDeliveryStatus(
    ::grpc::ServerContext* context, const ::securecloud::messaging::v1::GetMessageDeliveryStatusRequest* request,
    ::securecloud::messaging::v1::GetMessageDeliveryStatusResponse* response) {
    log_rpc_invocation("GetMessageDeliveryStatus", context);
    if (!read_receipt_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return val_status;
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return {::grpc::StatusCode::UNAUTHENTICATED, "Missing or invalid user ID header (expected RFC 4122 UUID)"};
    }

    auto msg_id = domain::MessageId::from_string(request->message_id());
    if (!msg_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE, "Invalid message ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto res = read_receipt_service_->get_message_delivery_summary(*conv_id, *msg_id, *caller_id);
    if (!res) {
        return to_grpc_status(res.error_code, res.error_message, caller_ctx.correlation_id(), context);
    }

    const auto& summary = res.value;
    response->set_message_id(summary.message_id.to_string());
    response->set_conversation_id(summary.conversation_id.to_string());

    auto* summary_pb = response->mutable_summary();
    summary_pb->set_total_targets(summary.total_targets);
    summary_pb->set_delivered_targets(summary.delivered_targets);
    summary_pb->set_pending_targets(summary.pending_targets);
    summary_pb->set_expired_targets(summary.expired_targets);

    for (const auto& dev : summary.device_statuses) {
        auto* dev_pb = response->add_device_statuses();
        dev_pb->set_device_id(dev.device_id.str());
        dev_pb->set_recipient_user_id(dev.recipient_user_id.str());
        dev_pb->set_delivery_state(to_proto_delivery_state(dev.delivery_state));
        if (dev.delivered_at) {
            auto ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(dev.delivered_at->time_since_epoch()).count();
            dev_pb->set_delivered_at_unix_ms(ms);
        }
        dev_pb->set_attempt_count(dev.attempt_count);
    }

    for (const auto& r : summary.recipient_read_statuses) {
        auto* read_pb = response->add_recipient_read_statuses();
        read_pb->set_user_id(r.user_id.str());
        read_pb->set_is_read(r.read_state == domain::ReadState::Read);
        if (r.read_at) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(r.read_at->time_since_epoch()).count();
            read_pb->set_read_at_unix_ms(ms);
        }
        if (r.reader_device_id) {
            read_pb->set_reader_device_id(r.reader_device_id->str());
        }
    }

    return ::grpc::Status::OK;
}

// --- Conversation & membership RPCs ---

::grpc::Status
MessagingServiceImpl::CreateConversation(::grpc::ServerContext* context,
                                         const ::securecloud::messaging::v1::CreateConversationRequest* request,
                                         ::securecloud::messaging::v1::CreateConversationResponse* response) {
    log_rpc_invocation("CreateConversation", context);
    if (!conversation_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    ServiceResult<domain::ConversationEntity> result;
    if (request->type() == v1::CONVERSATION_TYPE_DIRECT) {
        if (request->participant_user_ids().empty()) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                  "Direct conversation requires recipient user ID", caller_ctx.correlation_id(),
                                  context);
        }
        auto recipient_id = domain::UserId::from_string(request->participant_user_ids(0));
        if (!recipient_id) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid recipient user ID",
                                  caller_ctx.correlation_id(), context);
        }
        result = conversation_service_->create_direct_conversation(*caller_id, *recipient_id);
    } else if (request->type() == v1::CONVERSATION_TYPE_GROUP) {
        std::vector<domain::UserId> initial_participants;
        for (const auto& uid_str : request->participant_user_ids()) {
            auto uid = domain::UserId::from_string(uid_str);
            if (uid) {
                initial_participants.push_back(*uid);
            }
        }
        result = conversation_service_->create_group_conversation(*caller_id, request->title(), initial_participants);
    } else {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid or unsupported conversation type",
                              caller_ctx.correlation_id(), context);
    }

    if (!result) {
        return to_grpc_status(result.error_code, result.error_message, caller_ctx.correlation_id(), context);
    }

    auto details = conversation_service_->get_conversation(*caller_id, result.value.conversation_id);
    if (details) {
        populate_conversation_metadata(details.value, response->mutable_conversation());
    } else {
        response->mutable_conversation()->set_conversation_id(result.value.conversation_id.to_string());
    }

    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::GetConversation(::grpc::ServerContext* context,
                                      const ::securecloud::messaging::v1::GetConversationRequest* request,
                                      ::securecloud::messaging::v1::GetConversationResponse* response) {
    log_rpc_invocation("GetConversation", context);
    if (!conversation_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto details = conversation_service_->get_conversation(*caller_id, *conv_id);
    if (!details) {
        return to_grpc_status(details.error_code, details.error_message, caller_ctx.correlation_id(), context);
    }

    populate_conversation_metadata(details.value, response->mutable_conversation());
    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::ListConversations(::grpc::ServerContext* context,
                                        const ::securecloud::messaging::v1::ListConversationsRequest* request,
                                        ::securecloud::messaging::v1::ListConversationsResponse* response) {
    log_rpc_invocation("ListConversations", context);
    if (!conversation_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    int limit = request->max_results() > 0 ? static_cast<int>(request->max_results()) : 50;
    std::optional<std::string> page_token =
        request->page_token().empty() ? std::nullopt : std::make_optional(request->page_token());

    auto result = conversation_service_->list_user_conversations(*caller_id, limit, page_token);
    if (!result) {
        return to_grpc_status(result.error_code, result.error_message, caller_ctx.correlation_id(), context);
    }

    for (const auto& item : result.value.items) {
        if (item.membership_status != domain::MembershipStatus::Active) {
            continue;
        }
        auto* conv_meta = response->add_conversations();
        conv_meta->set_conversation_id(item.conversation_id.to_string());
        conv_meta->set_type(item.type == domain::ConversationType::Direct ? v1::CONVERSATION_TYPE_DIRECT
                                                                          : v1::CONVERSATION_TYPE_GROUP);
        auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(item.last_activity_at.time_since_epoch()).count();
        conv_meta->set_created_at_unix_ms(ms);
    }

    if (result.value.next_page_token) {
        response->set_next_page_token(*result.value.next_page_token);
    }

    return ::grpc::Status::OK;
}

::grpc::Status MessagingServiceImpl::AddParticipant(::grpc::ServerContext* context,
                                                    const ::securecloud::messaging::v1::AddParticipantRequest* request,
                                                    ::securecloud::messaging::v1::AddParticipantResponse* response) {
    log_rpc_invocation("AddParticipant", context);
    if (!conversation_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto target_id = domain::UserId::from_string(request->participant_user_id());
    if (!target_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid target participant user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto result = conversation_service_->add_participant(*caller_id, *conv_id, *target_id);
    if (!result) {
        return to_grpc_status(result.error_code, result.error_message, caller_ctx.correlation_id(), context);
    }

    response->set_conversation_id(request->conversation_id());
    response->set_participant_user_id(request->participant_user_id());

    auto details = conversation_service_->get_conversation(*caller_id, *conv_id);
    if (details) {
        response->set_total_participants(static_cast<uint32_t>(details.value.active_participants.size()));
    }

    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::RemoveParticipant(::grpc::ServerContext* context,
                                        const ::securecloud::messaging::v1::RemoveParticipantRequest* request,
                                        ::securecloud::messaging::v1::RemoveParticipantResponse* response) {
    log_rpc_invocation("RemoveParticipant", context);
    if (!conversation_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto target_id = domain::UserId::from_string(request->participant_user_id());
    if (!target_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid target participant user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto result = conversation_service_->remove_participant(*caller_id, *conv_id, *target_id);
    if (!result) {
        return to_grpc_status(result.error_code, result.error_message, caller_ctx.correlation_id(), context);
    }

    response->set_conversation_id(request->conversation_id());
    response->set_participant_user_id(request->participant_user_id());

    auto details = conversation_service_->get_conversation(*caller_id, *conv_id);
    if (details) {
        response->set_total_participants(static_cast<uint32_t>(details.value.active_participants.size()));
    }

    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::LeaveConversation(::grpc::ServerContext* context,
                                        const ::securecloud::messaging::v1::LeaveConversationRequest* request,
                                        ::securecloud::messaging::v1::LeaveConversationResponse* response) {
    log_rpc_invocation("LeaveConversation", context);
    if (!conversation_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto result = conversation_service_->leave_conversation(*caller_id, *conv_id);
    if (!result) {
        return to_grpc_status(result.error_code, result.error_message, caller_ctx.correlation_id(), context);
    }

    response->set_conversation_id(request->conversation_id());
    response->set_success(true);
    return ::grpc::Status::OK;
}

::grpc::Status MessagingServiceImpl::UpdateConversationMetadata(
    ::grpc::ServerContext* context, const ::securecloud::messaging::v1::UpdateConversationMetadataRequest* request,
    ::securecloud::messaging::v1::UpdateConversationMetadataResponse* response) {
    log_rpc_invocation("UpdateConversationMetadata", context);
    if (!conversation_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    auto result = conversation_service_->update_group_metadata(*caller_id, *conv_id, request->title());
    if (!result) {
        return to_grpc_status(result.error_code, result.error_message, caller_ctx.correlation_id(), context);
    }

    auto details = conversation_service_->get_conversation(*caller_id, *conv_id);
    if (details) {
        populate_conversation_metadata(details.value, response->mutable_conversation());
    } else {
        response->mutable_conversation()->set_conversation_id(request->conversation_id());
        response->mutable_conversation()->set_title(result.value.title);
    }

    return ::grpc::Status::OK;
}

// --- Device synchronization RPCs ---

::grpc::Status
MessagingServiceImpl::SyncDeviceMessages(::grpc::ServerContext* context,
                                         const ::securecloud::messaging::v1::SyncDeviceMessagesRequest* request,
                                         ::securecloud::messaging::v1::SyncDeviceMessagesResponse* response) {
    log_rpc_invocation("SyncDeviceMessages", context);
    if (!sync_service_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return val_status;
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return {::grpc::StatusCode::UNAUTHENTICATED, "Missing or invalid user ID header (expected RFC 4122 UUID)"};
    }

    if (!caller_ctx.device_id().empty() && !request->device_id().empty() &&
        caller_ctx.device_id() != request->device_id()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                              "Caller device cannot sync messages on behalf of a different device",
                              caller_ctx.correlation_id(), context);
    }

    std::string effective_device_id = !request->device_id().empty() ? request->device_id() : caller_ctx.device_id();
    if (effective_device_id.empty()) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Missing device ID"};
    }

    if (resolution_service_) {
        auto dev_status = resolution_service_->get_device_status(*caller_id, domain::DeviceId(effective_device_id));
        if (dev_status.has_value() && *dev_status != securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
                                  "Calling device has been revoked or is not active", caller_ctx.correlation_id(),
                                  context);
        }
    }

    if (request->conversation_id().empty()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Missing conversation ID",
                              caller_ctx.correlation_id(), context);
    }
    auto conv_id = domain::ConversationId::from_string(request->conversation_id());
    if (!conv_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    if (request->since_sequence() < 0) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS, "since_sequence must be non-negative",
                              caller_ctx.correlation_id(), context);
    }

    SyncDeviceMessagesCommand cmd;
    cmd.device_id = domain::DeviceId(effective_device_id);
    cmd.conversation_id = *conv_id;
    cmd.since_sequence = static_cast<domain::MessageSequence>(request->since_sequence());
    cmd.max_messages = request->max_messages() > 0 ? request->max_messages() : k_default_sync_batch_size;

    auto run_task = [sync_svc = sync_service_, caller = *caller_id, command = std::move(cmd)]() {
        return sync_svc->sync_messages(caller, command);
    };

    SyncMessagesResult task_result;
    if (sync_pool_) {
        auto promise = std::make_shared<std::promise<SyncMessagesResult>>();
        auto future = promise->get_future();
        bool enqueued = sync_pool_->try_submit([promise, run_task]() {
            try {
                promise->set_value(run_task());
            } catch (const std::exception& ex) {
                promise->set_value(SyncMessagesResult::failure(SyncMessagesStatus::StorageError, domain::DeviceId(""),
                                                               std::nullopt, ex.what()));
            } catch (...) {
                promise->set_value(SyncMessagesResult::failure(SyncMessagesStatus::StorageError, domain::DeviceId(""),
                                                               std::nullopt, "Unknown worker failure"));
            }
        });

        if (!enqueued) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                                  "Sync worker pool capacity exceeded", caller_ctx.correlation_id(), context);
        }

        if (context->raw_deadline().tv_sec != 0 || context->raw_deadline().tv_nsec != 0) {
            auto deadline = context->deadline();
            if (deadline < std::chrono::system_clock::time_point::max()) {
                auto wait_res = future.wait_until(deadline);
                if (wait_res == std::future_status::timeout) {
                    return {::grpc::StatusCode::DEADLINE_EXCEEDED, "SyncDeviceMessages deadline exceeded"};
                }
            }
        }
        task_result = future.get();
    } else {
        task_result = run_task();
    }

    if (!task_result.is_success()) {
        return sync_status_to_grpc_status(task_result.status, task_result.error_message, caller_ctx.correlation_id(),
                                          context);
    }

    response->set_device_id(task_result.device_id.str());
    response->set_has_more(task_result.has_more);
    response->set_next_sequence(static_cast<int64_t>(task_result.next_sequence));
    response->set_latest_sequence(static_cast<int64_t>(task_result.latest_sequence));
    if (task_result.cursor.is_valid()) {
        populate_sync_cursor(task_result.cursor, response->mutable_cursor());
    }
    for (const auto& msg : task_result.messages) {
        const domain::DeviceDeliveryRecord* dev_rec = nullptr;
        auto it = task_result.device_envelopes.find(msg.message_id);
        if (it != task_result.device_envelopes.end()) {
            dev_rec = &it->second;
        }
        bool is_untargeted =
            task_result.untargeted_messages.find(msg.message_id) != task_result.untargeted_messages.end();
        populate_message_envelope(msg, response->add_messages(), &task_result.device_id, dev_rec, is_untargeted);
    }
    return ::grpc::Status::OK;
}

::grpc::Status MessagingServiceImpl::GetSyncCursor(::grpc::ServerContext* context,
                                                   const ::securecloud::messaging::v1::GetSyncCursorRequest* request,
                                                   ::securecloud::messaging::v1::GetSyncCursorResponse* response) {
    log_rpc_invocation("GetSyncCursor", context);
    if (!cursor_manager_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string dev_id_str = !request->device_id().empty() ? request->device_id() : caller_ctx.device_id();
    if (dev_id_str.empty()) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Missing device ID"};
    }

    domain::ConversationId conv_id;
    if (!request->conversation_id().empty()) {
        auto parsed_conv = domain::ConversationId::from_string(request->conversation_id());
        if (!parsed_conv) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                                  caller_ctx.correlation_id(), context);
        }
        conv_id = *parsed_conv;
    }

    auto run_task = [mgr = cursor_manager_, dev_id = domain::DeviceId(dev_id_str), conv_id]() {
        return mgr->get_cursor(dev_id, conv_id);
    };

    domain::DeviceSyncCursor task_result;
    if (sync_pool_) {
        auto promise = std::make_shared<std::promise<domain::DeviceSyncCursor>>();
        auto future = promise->get_future();
        bool enqueued = sync_pool_->try_submit([promise, run_task]() {
            try {
                promise->set_value(run_task());
            } catch (...) {
                promise->set_value(domain::DeviceSyncCursor{});
            }
        });

        if (!enqueued) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                                  "Sync worker pool capacity exceeded", caller_ctx.correlation_id(), context);
        }

        if (context->raw_deadline().tv_sec != 0 || context->raw_deadline().tv_nsec != 0) {
            auto deadline = context->deadline();
            if (deadline < std::chrono::system_clock::time_point::max()) {
                auto wait_res = future.wait_until(deadline);
                if (wait_res == std::future_status::timeout) {
                    return {::grpc::StatusCode::DEADLINE_EXCEEDED, "GetSyncCursor deadline exceeded"};
                }
            }
        }
        task_result = future.get();
    } else {
        task_result = run_task();
    }

    populate_sync_cursor(task_result, response->mutable_cursor());
    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::UpdateSyncCursor(::grpc::ServerContext* context,
                                       const ::securecloud::messaging::v1::UpdateSyncCursorRequest* request,
                                       ::securecloud::messaging::v1::UpdateSyncCursorResponse* response) {
    log_rpc_invocation("UpdateSyncCursor", context);
    if (!cursor_manager_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }
    if (!request->has_cursor()) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request must contain cursor"};
    }

    auto cancel_status = check_deadline_and_cancellation(context);
    if (!cancel_status.ok()) {
        return cancel_status;
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    const auto& cursor_proto = request->cursor();
    std::string dev_id_str = !cursor_proto.device_id().empty() ? cursor_proto.device_id() : caller_ctx.device_id();
    if (dev_id_str.empty()) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Missing device ID"};
    }

    auto parsed_conv = domain::ConversationId::from_string(cursor_proto.conversation_id());
    if (!parsed_conv) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "Invalid conversation ID format",
                              caller_ctx.correlation_id(), context);
    }

    if (cursor_proto.last_delivered_sequence() < 0) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS, "Sequence must be non-negative",
                              caller_ctx.correlation_id(), context);
    }

    UpdateSyncCursorCommand cmd{
        .device_id = domain::DeviceId(dev_id_str),
        .conversation_id = *parsed_conv,
        .new_sequence = static_cast<domain::MessageSequence>(cursor_proto.last_delivered_sequence()),
        .sync_version = 0,
    };

    auto run_task = [mgr = cursor_manager_, command = std::move(cmd)]() { return mgr->update_cursor(command); };

    SyncCursorUpdateOutcome task_result;
    if (sync_pool_) {
        auto promise = std::make_shared<std::promise<SyncCursorUpdateOutcome>>();
        auto future = promise->get_future();
        bool enqueued = sync_pool_->try_submit([promise, run_task]() {
            try {
                promise->set_value(run_task());
            } catch (const std::exception& ex) {
                promise->set_value(SyncCursorUpdateOutcome{
                    .status = SyncCursorUpdateStatus::StorageError, .cursor = {}, .error_message = ex.what()});
            } catch (...) {
                promise->set_value(SyncCursorUpdateOutcome{.status = SyncCursorUpdateStatus::StorageError,
                                                           .cursor = {},
                                                           .error_message = "Unknown worker failure"});
            }
        });

        if (!enqueued) {
            return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                                  "Sync worker pool capacity exceeded", caller_ctx.correlation_id(), context);
        }

        if (context->raw_deadline().tv_sec != 0 || context->raw_deadline().tv_nsec != 0) {
            auto deadline = context->deadline();
            if (deadline < std::chrono::system_clock::time_point::max()) {
                auto wait_res = future.wait_until(deadline);
                if (wait_res == std::future_status::timeout) {
                    return {::grpc::StatusCode::DEADLINE_EXCEEDED, "UpdateSyncCursor deadline exceeded"};
                }
            }
        }
        task_result = future.get();
    } else {
        task_result = run_task();
    }

    if (!task_result.is_success()) {
        return cursor_update_status_to_grpc_status(task_result.status, task_result.error_message,
                                                   caller_ctx.correlation_id(), context);
    }

    response->set_success(true);
    populate_sync_cursor(task_result.cursor, response->mutable_cursor());
    return ::grpc::Status::OK;
}

// --- Presence signaling & query RPCs ---

::grpc::Status MessagingServiceImpl::UpdatePresence(::grpc::ServerContext* context,
                                                    const ::securecloud::messaging::v1::UpdatePresenceRequest* request,
                                                    ::securecloud::messaging::v1::UpdatePresenceResponse* response) {
    log_rpc_invocation("UpdatePresence", context);
    if (!presence_coordinator_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    // Rate bounding: max 12 updates per minute per user
    if (!check_and_record_presence_rate_limit(*caller_id)) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
                              "Presence update rate limit exceeded (max 12 per minute)", caller_ctx.correlation_id(),
                              context);
    }

    const std::string sanitized_message = domain::sanitize_status_message(request->custom_status_message());
    const auto target_status = domain::from_proto(request->status());

    if (target_status == domain::PresenceStatus::Unspecified ||
        (target_status == domain::PresenceStatus::Online && sanitized_message.empty())) {
        presence_coordinator_->clear_user_override(*caller_id);
    } else {
        presence_coordinator_->set_user_override(*caller_id, target_status, sanitized_message);
    }

    const auto current_presence = presence_coordinator_->get_user_presence(*caller_id);
    *response->mutable_presence() = domain::to_proto(current_presence);
    return ::grpc::Status::OK;
}

::grpc::Status MessagingServiceImpl::GetPresence(::grpc::ServerContext* context,
                                                 const ::securecloud::messaging::v1::GetPresenceRequest* request,
                                                 ::securecloud::messaging::v1::GetPresenceResponse* response) {
    log_rpc_invocation("GetPresence", context);
    if (!presence_coordinator_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    auto target_id = domain::UserId::from_string(request->user_id());
    if (!target_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid target user ID format",
                              caller_ctx.correlation_id(), context);
    }

    // Mutual-Conversation Privacy Guard (MSG-010):
    // Allow immediately if caller is querying their own presence.
    // Otherwise, verify caller and target share at least one mutual active conversation.
    // If not, privacy-shield the response to OFFLINE (preventing existence / presence oracle).
    bool is_authorized = (*caller_id == *target_id);
    if (!is_authorized && conversation_service_) {
        is_authorized = conversation_service_->shares_mutual_conversation(*caller_id, *target_id);
    }

    if (!is_authorized) {
        domain::UserPresence shielded_presence{
            .user_id = *target_id,
            .status = domain::PresenceStatus::Offline,
            .last_active_at = {},
            .custom_status_message = "",
            .active_device_count = 0,
        };
        *response->mutable_presence() = domain::to_proto(shielded_presence);
        return ::grpc::Status::OK;
    }

    const auto presence = presence_coordinator_->get_user_presence(*target_id);
    *response->mutable_presence() = domain::to_proto(presence);
    return ::grpc::Status::OK;
}

::grpc::Status
MessagingServiceImpl::BatchGetPresence(::grpc::ServerContext* context,
                                       const ::securecloud::messaging::v1::BatchGetPresenceRequest* request,
                                       ::securecloud::messaging::v1::BatchGetPresenceResponse* response) {
    log_rpc_invocation("BatchGetPresence", context);
    if (!presence_coordinator_) {
        return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
    }
    if (!request || !response) {
        return {::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null"};
    }

    auto caller_ctx = extract_messaging_caller_context(context);
    std::string error_reason;
    auto val_status = validate_messaging_caller_context(caller_ctx, kRequireUserId, error_reason);
    if (!val_status.ok()) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, error_reason, caller_ctx.correlation_id(), context);
    }

    auto caller_id = domain::UserId::from_string(caller_ctx.user_id());
    if (!caller_id) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Invalid caller user ID",
                              caller_ctx.correlation_id(), context);
    }

    if (request->user_ids_size() > 100) {
        return to_grpc_status(v1::MESSAGING_ERROR_CODE_UNSPECIFIED, "Batch size exceeds maximum limit of 100 user IDs",
                              caller_ctx.correlation_id(), context);
    }

    for (const auto& uid_str : request->user_ids()) {
        auto target_id = domain::UserId::from_string(uid_str);
        if (!target_id) {
            auto* p = response->add_presences();
            p->set_user_id(uid_str);
            p->set_status(securecloud::messaging::v1::PRESENCE_STATUS_OFFLINE);
            p->set_last_active_unix_ms(0);
            continue;
        }

        bool is_authorized = (*caller_id == *target_id);
        if (!is_authorized && conversation_service_) {
            is_authorized = conversation_service_->shares_mutual_conversation(*caller_id, *target_id);
        }

        if (!is_authorized) {
            domain::UserPresence shielded_presence{
                .user_id = *target_id,
                .status = domain::PresenceStatus::Offline,
                .last_active_at = {},
                .custom_status_message = "",
                .active_device_count = 0,
            };
            *response->add_presences() = domain::to_proto(shielded_presence);
        } else {
            const auto presence = presence_coordinator_->get_user_presence(*target_id);
            *response->add_presences() = domain::to_proto(presence);
        }
    }

    return ::grpc::Status::OK;
}

// --- Metadata & security helpers ---

std::string MessagingServiceImpl::extract_correlation_id(const ::grpc::ServerContext* context) {
    if (!context) {
        return "";
    }
    return securecloud::common::rpc::extract_caller_context(context).correlation_id;
}

std::string MessagingServiceImpl::extract_peer_identity(const ::grpc::ServerContext* context) {
    if (!context) {
        return "anonymous";
    }
    return extract_peer_identity(context->auth_context().get());
}

std::string MessagingServiceImpl::extract_peer_identity(const ::grpc::AuthContext* auth_context) {
    return securecloud::common::rpc::extract_peer_identity(auth_context);
}

bool MessagingServiceImpl::is_authorized_peer(const ::grpc::ServerContext* context) {
    return securecloud::common::rpc::is_authorized_service_peer(context);
}

bool MessagingServiceImpl::is_authorized_peer(const ::grpc::AuthContext* auth_context) {
    return securecloud::common::rpc::is_authorized_service_peer(auth_context);
}

} // namespace securecloud::messaging::service
