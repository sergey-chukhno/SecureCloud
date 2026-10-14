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
#include "service/messaging_caller_context.hpp"
#include "service/messaging_error_mapper.hpp"

#include <chrono>
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
                                           std::shared_ptr<ConversationService> conversation_service)
    : submission_pool_(std::move(submission_pool)), delivery_pool_(std::move(delivery_pool)),
      sync_pool_(std::move(sync_pool)), conversation_service_(std::move(conversation_service)) {}

// --- Message lifecycle RPCs ---

::grpc::Status MessagingServiceImpl::SendMessage(::grpc::ServerContext* context,
                                                 const ::securecloud::messaging::v1::SendMessageRequest* /*request*/,
                                                 ::securecloud::messaging::v1::SendMessageResponse* /*response*/) {
    log_rpc_invocation("SendMessage", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status MessagingServiceImpl::GetMessages(::grpc::ServerContext* context,
                                                 const ::securecloud::messaging::v1::GetMessagesRequest* /*request*/,
                                                 ::securecloud::messaging::v1::GetMessagesResponse* /*response*/) {
    log_rpc_invocation("GetMessages", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::AcknowledgeDelivery(::grpc::ServerContext* context,
                                          const ::securecloud::messaging::v1::AcknowledgeDeliveryRequest* /*request*/,
                                          ::securecloud::messaging::v1::AcknowledgeDeliveryResponse* /*response*/) {
    log_rpc_invocation("AcknowledgeDelivery", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
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
