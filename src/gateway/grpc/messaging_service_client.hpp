#pragma once

#include "grpc/messaging_client_interface.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::gateway::grpc {

class MessagingServiceClient : public IMessagingClient {
  public:
    explicit MessagingServiceClient(std::shared_ptr<securecloud::messaging::v1::MessagingService::StubInterface> stub);
    explicit MessagingServiceClient(const std::shared_ptr<::grpc::Channel>& channel);

    ~MessagingServiceClient() override = default;

    // --- Message Submission & Delivery ---
    Result<securecloud::messaging::v1::SendMessageResponse>
    send_message(const securecloud::messaging::v1::SendMessageRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::GetMessagesResponse>
    get_messages(const securecloud::messaging::v1::GetMessagesRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>
    acknowledge_delivery(const securecloud::messaging::v1::AcknowledgeDeliveryRequest& req,
                         ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::SendReadReceiptResponse>
    send_read_receipt(const securecloud::messaging::v1::SendReadReceiptRequest& req, ClientCallContext& ctx) override;

    // --- Conversation Topology & Membership ---
    Result<securecloud::messaging::v1::CreateConversationResponse>
    create_conversation(const securecloud::messaging::v1::CreateConversationRequest& req,
                        ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::GetConversationResponse>
    get_conversation(const securecloud::messaging::v1::GetConversationRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::ListConversationsResponse>
    list_conversations(const securecloud::messaging::v1::ListConversationsRequest& req,
                       ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::AddParticipantResponse>
    add_participant(const securecloud::messaging::v1::AddParticipantRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::RemoveParticipantResponse>
    remove_participant(const securecloud::messaging::v1::RemoveParticipantRequest& req,
                       ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::LeaveConversationResponse>
    leave_conversation(const securecloud::messaging::v1::LeaveConversationRequest& req,
                       ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::UpdateConversationMetadataResponse>
    update_conversation_metadata(const securecloud::messaging::v1::UpdateConversationMetadataRequest& req,
                                 ClientCallContext& ctx) override;

    // --- Device Stream Synchronization ---
    Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>
    sync_device_messages(const securecloud::messaging::v1::SyncDeviceMessagesRequest& req,
                         ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::GetSyncCursorResponse>
    get_sync_cursor(const securecloud::messaging::v1::GetSyncCursorRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::UpdateSyncCursorResponse>
    update_sync_cursor(const securecloud::messaging::v1::UpdateSyncCursorRequest& req, ClientCallContext& ctx) override;

    // --- Presence Protocol ---
    Result<securecloud::messaging::v1::UpdatePresenceResponse>
    update_presence(const securecloud::messaging::v1::UpdatePresenceRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::GetPresenceResponse>
    get_presence(const securecloud::messaging::v1::GetPresenceRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::messaging::v1::BatchGetPresenceResponse>
    batch_get_presence(const securecloud::messaging::v1::BatchGetPresenceRequest& req, ClientCallContext& ctx) override;

  private:
    std::shared_ptr<securecloud::messaging::v1::MessagingService::StubInterface> stub_;
};

} // namespace securecloud::gateway::grpc
