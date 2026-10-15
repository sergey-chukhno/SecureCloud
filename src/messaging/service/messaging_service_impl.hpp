#pragma once

#include "concurrency/bounded_worker_pool.hpp"

// Undefine conflicting Win32 macros before and after gRPC header includes
#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "securecloud/messaging/v1/messaging.grpc.pb.h"

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "service/conversation_service.hpp"
#include "service/message_submission_service.hpp"

#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>

namespace securecloud::messaging::service {

/// gRPC service implementation for securecloud.messaging.v1.MessagingService (ADR-004).
class MessagingServiceImpl final : public securecloud::messaging::v1::MessagingService::Service {
  public:
    static constexpr const char* k_unimplemented_message = "RPC not implemented in MSG-001 foundation";

    explicit MessagingServiceImpl(std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool = nullptr,
                                  std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool = nullptr,
                                  std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool = nullptr,
                                  std::shared_ptr<ConversationService> conversation_service = nullptr,
                                  std::shared_ptr<MessageSubmissionService> submission_service = nullptr);
    ~MessagingServiceImpl() override = default;

    MessagingServiceImpl(const MessagingServiceImpl&) = delete;
    MessagingServiceImpl& operator=(const MessagingServiceImpl&) = delete;
    MessagingServiceImpl(MessagingServiceImpl&&) = delete;
    MessagingServiceImpl& operator=(MessagingServiceImpl&&) = delete;

    // --- Message lifecycle RPCs ---
    ::grpc::Status SendMessage(::grpc::ServerContext* context,
                               const ::securecloud::messaging::v1::SendMessageRequest* request,
                               ::securecloud::messaging::v1::SendMessageResponse* response) override;

    ::grpc::Status GetMessages(::grpc::ServerContext* context,
                               const ::securecloud::messaging::v1::GetMessagesRequest* request,
                               ::securecloud::messaging::v1::GetMessagesResponse* response) override;

    ::grpc::Status AcknowledgeDelivery(::grpc::ServerContext* context,
                                       const ::securecloud::messaging::v1::AcknowledgeDeliveryRequest* request,
                                       ::securecloud::messaging::v1::AcknowledgeDeliveryResponse* response) override;

    ::grpc::Status SendReadReceipt(::grpc::ServerContext* context,
                                   const ::securecloud::messaging::v1::SendReadReceiptRequest* request,
                                   ::securecloud::messaging::v1::SendReadReceiptResponse* response) override;

    // --- Conversation & membership RPCs ---
    ::grpc::Status CreateConversation(::grpc::ServerContext* context,
                                      const ::securecloud::messaging::v1::CreateConversationRequest* request,
                                      ::securecloud::messaging::v1::CreateConversationResponse* response) override;

    ::grpc::Status GetConversation(::grpc::ServerContext* context,
                                   const ::securecloud::messaging::v1::GetConversationRequest* request,
                                   ::securecloud::messaging::v1::GetConversationResponse* response) override;

    ::grpc::Status ListConversations(::grpc::ServerContext* context,
                                     const ::securecloud::messaging::v1::ListConversationsRequest* request,
                                     ::securecloud::messaging::v1::ListConversationsResponse* response) override;

    ::grpc::Status AddParticipant(::grpc::ServerContext* context,
                                  const ::securecloud::messaging::v1::AddParticipantRequest* request,
                                  ::securecloud::messaging::v1::AddParticipantResponse* response) override;

    ::grpc::Status RemoveParticipant(::grpc::ServerContext* context,
                                     const ::securecloud::messaging::v1::RemoveParticipantRequest* request,
                                     ::securecloud::messaging::v1::RemoveParticipantResponse* response) override;

    ::grpc::Status LeaveConversation(::grpc::ServerContext* context,
                                     const ::securecloud::messaging::v1::LeaveConversationRequest* request,
                                     ::securecloud::messaging::v1::LeaveConversationResponse* response) override;

    ::grpc::Status
    UpdateConversationMetadata(::grpc::ServerContext* context,
                               const ::securecloud::messaging::v1::UpdateConversationMetadataRequest* request,
                               ::securecloud::messaging::v1::UpdateConversationMetadataResponse* response) override;

    // --- Device synchronization RPCs ---
    ::grpc::Status SyncDeviceMessages(::grpc::ServerContext* context,
                                      const ::securecloud::messaging::v1::SyncDeviceMessagesRequest* request,
                                      ::securecloud::messaging::v1::SyncDeviceMessagesResponse* response) override;

    ::grpc::Status GetSyncCursor(::grpc::ServerContext* context,
                                 const ::securecloud::messaging::v1::GetSyncCursorRequest* request,
                                 ::securecloud::messaging::v1::GetSyncCursorResponse* response) override;

    ::grpc::Status UpdateSyncCursor(::grpc::ServerContext* context,
                                    const ::securecloud::messaging::v1::UpdateSyncCursorRequest* request,
                                    ::securecloud::messaging::v1::UpdateSyncCursorResponse* response) override;

    // --- Presence signaling & query RPCs ---
    ::grpc::Status UpdatePresence(::grpc::ServerContext* context,
                                  const ::securecloud::messaging::v1::UpdatePresenceRequest* request,
                                  ::securecloud::messaging::v1::UpdatePresenceResponse* response) override;

    ::grpc::Status GetPresence(::grpc::ServerContext* context,
                               const ::securecloud::messaging::v1::GetPresenceRequest* request,
                               ::securecloud::messaging::v1::GetPresenceResponse* response) override;

    ::grpc::Status BatchGetPresence(::grpc::ServerContext* context,
                                    const ::securecloud::messaging::v1::BatchGetPresenceRequest* request,
                                    ::securecloud::messaging::v1::BatchGetPresenceResponse* response) override;

    /// Helper to extract correlation ID from gRPC context metadata (x-correlation-id or x-request-id).
    [[nodiscard]] static std::string extract_correlation_id(const ::grpc::ServerContext* context);

    /// Helper to extract peer SAN identity from mTLS auth context.
    [[nodiscard]] static std::string extract_peer_identity(const ::grpc::ServerContext* context);
    [[nodiscard]] static std::string extract_peer_identity(const ::grpc::AuthContext* auth_context);

    /// Verifies peer SAN identity matches an authorized service (gateway, auth, messaging, files).
    [[nodiscard]] static bool is_authorized_peer(const ::grpc::ServerContext* context);
    [[nodiscard]] static bool is_authorized_peer(const ::grpc::AuthContext* auth_context);

    [[nodiscard]] std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool() const noexcept {
        return submission_pool_;
    }
    [[nodiscard]] std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool() const noexcept {
        return delivery_pool_;
    }
    [[nodiscard]] std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool() const noexcept { return sync_pool_; }
    [[nodiscard]] std::shared_ptr<ConversationService> conversation_service() const noexcept {
        return conversation_service_;
    }
    [[nodiscard]] std::shared_ptr<MessageSubmissionService> submission_service() const noexcept {
        return submission_service_;
    }

  private:
    std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool_;
    std::shared_ptr<ConversationService> conversation_service_;
    std::shared_ptr<MessageSubmissionService> submission_service_;
};

} // namespace securecloud::messaging::service
