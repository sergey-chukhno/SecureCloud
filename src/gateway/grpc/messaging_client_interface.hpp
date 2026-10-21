#pragma once

#include "grpc/client_call_context.hpp"
#include "grpc/dependency_error.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"

namespace securecloud::gateway::grpc {

/// Abstract downstream client interface for the Messaging microservice (ADR-004, GW-003, GW-010).
/// Defines typed RPC contracts directly consuming securecloud_proto without intermediate DTO re-declarations.
class IMessagingClient {
  public:
    virtual ~IMessagingClient() = default;

    // --- Message Submission & Delivery ---
    virtual Result<securecloud::messaging::v1::SendMessageResponse>
    send_message(const securecloud::messaging::v1::SendMessageRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::GetMessagesResponse>
    get_messages(const securecloud::messaging::v1::GetMessagesRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::AcknowledgeDeliveryResponse>
    acknowledge_delivery(const securecloud::messaging::v1::AcknowledgeDeliveryRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::SendReadReceiptResponse>
    send_read_receipt(const securecloud::messaging::v1::SendReadReceiptRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::GetMessageDeliveryStatusResponse>
    get_message_delivery_status(const securecloud::messaging::v1::GetMessageDeliveryStatusRequest& req,
                                ClientCallContext& ctx) = 0;

    // --- Conversation Topology & Membership ---
    virtual Result<securecloud::messaging::v1::CreateConversationResponse>
    create_conversation(const securecloud::messaging::v1::CreateConversationRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::GetConversationResponse>
    get_conversation(const securecloud::messaging::v1::GetConversationRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::ListConversationsResponse>
    list_conversations(const securecloud::messaging::v1::ListConversationsRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::AddParticipantResponse>
    add_participant(const securecloud::messaging::v1::AddParticipantRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::RemoveParticipantResponse>
    remove_participant(const securecloud::messaging::v1::RemoveParticipantRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::LeaveConversationResponse>
    leave_conversation(const securecloud::messaging::v1::LeaveConversationRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::UpdateConversationMetadataResponse>
    update_conversation_metadata(const securecloud::messaging::v1::UpdateConversationMetadataRequest& req,
                                 ClientCallContext& ctx) = 0;

    // --- Device Stream Synchronization ---
    virtual Result<securecloud::messaging::v1::SyncDeviceMessagesResponse>
    sync_device_messages(const securecloud::messaging::v1::SyncDeviceMessagesRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::GetSyncCursorResponse>
    get_sync_cursor(const securecloud::messaging::v1::GetSyncCursorRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::UpdateSyncCursorResponse>
    update_sync_cursor(const securecloud::messaging::v1::UpdateSyncCursorRequest& req, ClientCallContext& ctx) = 0;

    // --- Presence Protocol ---
    virtual Result<securecloud::messaging::v1::UpdatePresenceResponse>
    update_presence(const securecloud::messaging::v1::UpdatePresenceRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::GetPresenceResponse>
    get_presence(const securecloud::messaging::v1::GetPresenceRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::messaging::v1::BatchGetPresenceResponse>
    batch_get_presence(const securecloud::messaging::v1::BatchGetPresenceRequest& req, ClientCallContext& ctx) = 0;
};

/// Alias matching ticket nomenclature
using MessagingClientInterface = IMessagingClient;

} // namespace securecloud::gateway::grpc
