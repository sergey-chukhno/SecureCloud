#include "grpc/messaging_service_client.hpp"

#include <grpcpp/grpcpp.h>
#include <utility>

namespace securecloud::gateway::grpc {
namespace {

DependencyError null_stub_error() {
    return DependencyError{
        .kind = DependencyErrorKind::ServiceUnavailable,
        .message = "MessagingService stub is unavailable or null",
        .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
    };
}

} // namespace

MessagingServiceClient::MessagingServiceClient(
    std::shared_ptr<securecloud::messaging::v1::MessagingService::StubInterface> stub)
    : stub_(std::move(stub)) {}

MessagingServiceClient::MessagingServiceClient(const std::shared_ptr<::grpc::Channel>& channel)
    : stub_(channel ? securecloud::messaging::v1::MessagingService::NewStub(channel) : nullptr) {}

Result<securecloud::messaging::v1::SendMessageResponse>
MessagingServiceClient::send_message(const securecloud::messaging::v1::SendMessageRequest& req,
                                     ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::SendMessageResponse resp;
    auto status = stub_->SendMessage(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::GetMessagesResponse>
MessagingServiceClient::get_messages(const securecloud::messaging::v1::GetMessagesRequest& req,
                                     ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::GetMessagesResponse resp;
    auto status = stub_->GetMessages(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>
MessagingServiceClient::acknowledge_delivery(const securecloud::messaging::v1::AcknowledgeDeliveryRequest& req,
                                             ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::AcknowledgeDeliveryResponse resp;
    auto status = stub_->AcknowledgeDelivery(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::SendReadReceiptResponse>
MessagingServiceClient::send_read_receipt(const securecloud::messaging::v1::SendReadReceiptRequest& req,
                                          ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::SendReadReceiptResponse resp;
    auto status = stub_->SendReadReceipt(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::GetMessageDeliveryStatusResponse>
MessagingServiceClient::get_message_delivery_status(
    const securecloud::messaging::v1::GetMessageDeliveryStatusRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::GetMessageDeliveryStatusResponse resp;
    auto status = stub_->GetMessageDeliveryStatus(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::CreateConversationResponse>
MessagingServiceClient::create_conversation(const securecloud::messaging::v1::CreateConversationRequest& req,
                                            ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::CreateConversationResponse resp;
    auto status = stub_->CreateConversation(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::GetConversationResponse>
MessagingServiceClient::get_conversation(const securecloud::messaging::v1::GetConversationRequest& req,
                                         ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::GetConversationResponse resp;
    auto status = stub_->GetConversation(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::ListConversationsResponse>
MessagingServiceClient::list_conversations(const securecloud::messaging::v1::ListConversationsRequest& req,
                                           ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::ListConversationsResponse resp;
    auto status = stub_->ListConversations(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::AddParticipantResponse>
MessagingServiceClient::add_participant(const securecloud::messaging::v1::AddParticipantRequest& req,
                                        ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::AddParticipantResponse resp;
    auto status = stub_->AddParticipant(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::RemoveParticipantResponse>
MessagingServiceClient::remove_participant(const securecloud::messaging::v1::RemoveParticipantRequest& req,
                                           ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::RemoveParticipantResponse resp;
    auto status = stub_->RemoveParticipant(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::LeaveConversationResponse>
MessagingServiceClient::leave_conversation(const securecloud::messaging::v1::LeaveConversationRequest& req,
                                           ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::LeaveConversationResponse resp;
    auto status = stub_->LeaveConversation(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::UpdateConversationMetadataResponse>
MessagingServiceClient::update_conversation_metadata(
    const securecloud::messaging::v1::UpdateConversationMetadataRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::UpdateConversationMetadataResponse resp;
    auto status = stub_->UpdateConversationMetadata(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>
MessagingServiceClient::sync_device_messages(const securecloud::messaging::v1::SyncDeviceMessagesRequest& req,
                                             ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::SyncDeviceMessagesResponse resp;
    auto status = stub_->SyncDeviceMessages(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::GetSyncCursorResponse>
MessagingServiceClient::get_sync_cursor(const securecloud::messaging::v1::GetSyncCursorRequest& req,
                                        ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::GetSyncCursorResponse resp;
    auto status = stub_->GetSyncCursor(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::UpdateSyncCursorResponse>
MessagingServiceClient::update_sync_cursor(const securecloud::messaging::v1::UpdateSyncCursorRequest& req,
                                           ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::UpdateSyncCursorResponse resp;
    auto status = stub_->UpdateSyncCursor(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::UpdatePresenceResponse>
MessagingServiceClient::update_presence(const securecloud::messaging::v1::UpdatePresenceRequest& req,
                                        ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::UpdatePresenceResponse resp;
    auto status = stub_->UpdatePresence(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::GetPresenceResponse>
MessagingServiceClient::get_presence(const securecloud::messaging::v1::GetPresenceRequest& req,
                                     ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::GetPresenceResponse resp;
    auto status = stub_->GetPresence(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::messaging::v1::BatchGetPresenceResponse>
MessagingServiceClient::batch_get_presence(const securecloud::messaging::v1::BatchGetPresenceRequest& req,
                                           ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::messaging::v1::BatchGetPresenceResponse resp;
    auto status = stub_->BatchGetPresence(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

} // namespace securecloud::gateway::grpc
