#include "service/messaging_service_impl.hpp"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/security/mtls_config.hpp"

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

} // namespace

MessagingServiceImpl::MessagingServiceImpl(std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool,
                                           std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool,
                                           std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool)
    : submission_pool_(std::move(submission_pool)), delivery_pool_(std::move(delivery_pool)),
      sync_pool_(std::move(sync_pool)) {}

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
                                         const ::securecloud::messaging::v1::CreateConversationRequest* /*request*/,
                                         ::securecloud::messaging::v1::CreateConversationResponse* /*response*/) {
    log_rpc_invocation("CreateConversation", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::GetConversation(::grpc::ServerContext* context,
                                      const ::securecloud::messaging::v1::GetConversationRequest* /*request*/,
                                      ::securecloud::messaging::v1::GetConversationResponse* /*response*/) {
    log_rpc_invocation("GetConversation", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::ListConversations(::grpc::ServerContext* context,
                                        const ::securecloud::messaging::v1::ListConversationsRequest* /*request*/,
                                        ::securecloud::messaging::v1::ListConversationsResponse* /*response*/) {
    log_rpc_invocation("ListConversations", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::AddParticipant(::grpc::ServerContext* context,
                                     const ::securecloud::messaging::v1::AddParticipantRequest* /*request*/,
                                     ::securecloud::messaging::v1::AddParticipantResponse* /*response*/) {
    log_rpc_invocation("AddParticipant", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
}

::grpc::Status
MessagingServiceImpl::RemoveParticipant(::grpc::ServerContext* context,
                                        const ::securecloud::messaging::v1::RemoveParticipantRequest* /*request*/,
                                        ::securecloud::messaging::v1::RemoveParticipantResponse* /*response*/) {
    log_rpc_invocation("RemoveParticipant", context);
    return {::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message};
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

// --- Metadata & security helpers ---

std::string MessagingServiceImpl::extract_correlation_id(const ::grpc::ServerContext* context) {
    if (!context) {
        return "";
    }
    const auto& metadata = context->client_metadata();
    auto it = metadata.find("x-correlation-id");
    if (it != metadata.end()) {
        return {it->second.data(), it->second.size()};
    }
    it = metadata.find("x-request-id");
    if (it != metadata.end()) {
        return {it->second.data(), it->second.size()};
    }
    return "";
}

std::string MessagingServiceImpl::extract_peer_identity(const ::grpc::ServerContext* context) {
    if (!context) {
        return "anonymous";
    }
    return extract_peer_identity(context->auth_context().get());
}

std::string MessagingServiceImpl::extract_peer_identity(const ::grpc::AuthContext* auth_context) {
    if (!auth_context || !auth_context->IsPeerAuthenticated()) {
        return "anonymous";
    }
    auto identity = securecloud::common::security::extract_peer_service_identity(*auth_context);
    return identity.value_or("unknown_peer");
}

bool MessagingServiceImpl::is_authorized_peer(const ::grpc::ServerContext* context) {
    if (!context) {
        return false;
    }
    return is_authorized_peer(context->auth_context().get());
}

bool MessagingServiceImpl::is_authorized_peer(const ::grpc::AuthContext* auth_context) {
    if (!auth_context || !auth_context->IsPeerAuthenticated()) {
        return false;
    }
    return securecloud::common::security::verify_peer_service_identity(*auth_context, "gateway") ||
           securecloud::common::security::verify_peer_service_identity(*auth_context, "auth") ||
           securecloud::common::security::verify_peer_service_identity(*auth_context, "messaging") ||
           securecloud::common::security::verify_peer_service_identity(*auth_context, "files");
}

} // namespace securecloud::messaging::service
