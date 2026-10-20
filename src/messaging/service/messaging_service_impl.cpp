#include "service/messaging_service_impl.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/grpc/caller_context.hpp"
#include "securecloud/security/mtls_config.hpp"
#include "service/conversation_service.hpp"
#include "service/message_submission_service.hpp"
#include "service/messaging_caller_context.hpp"
#include "service/messaging_error_mapper.hpp"

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

} // namespace

MessagingServiceImpl::MessagingServiceImpl(std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool,
                                           std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool,
                                           std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool,
                                           std::shared_ptr<ConversationService> conversation_service,
                                           std::shared_ptr<MessageSubmissionService> submission_service,
                                           std::shared_ptr<DeliveryService> delivery_service)
    : submission_pool_(std::move(submission_pool)), delivery_pool_(std::move(delivery_pool)),
      sync_pool_(std::move(sync_pool)), conversation_service_(std::move(conversation_service)),
      submission_service_(std::move(submission_service)), delivery_service_(std::move(delivery_service)) {}

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
                                                 const ::securecloud::messaging::v1::GetMessagesRequest* /*request*/,
                                                 ::securecloud::messaging::v1::GetMessagesResponse* /*response*/) {
    log_rpc_invocation("GetMessages", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
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

    std::string effective_device_id = request->recipient_device_id();
    if (effective_device_id.empty()) {
        effective_device_id = caller_ctx.device_id();
    }
    if (effective_device_id.empty() || !common::rpc::is_valid_uuid(effective_device_id)) {
        return {::grpc::StatusCode::INVALID_ARGUMENT,
                "Missing or invalid recipient device ID (expected RFC 4122 UUID)"};
    }

    DeliveryAckCommand cmd;
    cmd.message_id = *msg_id;
    cmd.recipient_device_id = domain::DeviceId(effective_device_id);
    cmd.caller_user_id = *caller_id;
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
                                      const ::securecloud::messaging::v1::SendReadReceiptRequest* /*request*/,
                                      ::securecloud::messaging::v1::SendReadReceiptResponse* /*response*/) {
    log_rpc_invocation("SendReadReceipt", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
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
                                         const ::securecloud::messaging::v1::SyncDeviceMessagesRequest* /*request*/,
                                         ::securecloud::messaging::v1::SyncDeviceMessagesResponse* /*response*/) {
    log_rpc_invocation("SyncDeviceMessages", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::GetSyncCursor(::grpc::ServerContext* context,
                                    const ::securecloud::messaging::v1::GetSyncCursorRequest* /*request*/,
                                    ::securecloud::messaging::v1::GetSyncCursorResponse* /*response*/) {
    log_rpc_invocation("GetSyncCursor", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::UpdateSyncCursor(::grpc::ServerContext* context,
                                       const ::securecloud::messaging::v1::UpdateSyncCursorRequest* /*request*/,
                                       ::securecloud::messaging::v1::UpdateSyncCursorResponse* /*response*/) {
    log_rpc_invocation("UpdateSyncCursor", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

// --- Presence signaling & query RPCs ---

::grpc::Status
MessagingServiceImpl::UpdatePresence(::grpc::ServerContext* context,
                                     const ::securecloud::messaging::v1::UpdatePresenceRequest* /*request*/,
                                     ::securecloud::messaging::v1::UpdatePresenceResponse* /*response*/) {
    log_rpc_invocation("UpdatePresence", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status MessagingServiceImpl::GetPresence(::grpc::ServerContext* context,
                                                 const ::securecloud::messaging::v1::GetPresenceRequest* /*request*/,
                                                 ::securecloud::messaging::v1::GetPresenceResponse* /*response*/) {
    log_rpc_invocation("GetPresence", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::BatchGetPresence(::grpc::ServerContext* context,
                                       const ::securecloud::messaging::v1::BatchGetPresenceRequest* /*request*/,
                                       ::securecloud::messaging::v1::BatchGetPresenceResponse* /*response*/) {
    log_rpc_invocation("BatchGetPresence", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
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
