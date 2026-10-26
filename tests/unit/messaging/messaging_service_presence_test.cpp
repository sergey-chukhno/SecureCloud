#include "domain/presence_types.hpp"
#include "repository/in_memory_conversation_repository.hpp"
#include "repository/in_memory_membership_repository.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/presence_coordinator.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::service {
namespace {

using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceId;
using domain::MembershipStatus;
using domain::ParticipantRole;
using domain::UserId;

class MessagingServicePresenceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        alice_user_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        alice_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36091");

        bob_user_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        bob_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36092");

        charlie_user_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
        charlie_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36093");

        conv_id_ = ConversationId::generate_v7();

        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        conv_service_ = std::make_shared<ConversationService>(*conv_repo_, *member_repo_, *auth_service_);

        presence_coordinator_ = std::make_shared<PresenceCoordinator>();

        // Set up active direct conversation between Alice and Bob
        const auto now = std::chrono::system_clock::now();
        ConversationEntity conv{
            .conversation_id = conv_id_,
            .type = ConversationType::Direct,
            .created_by_user_id = alice_user_,
            .created_at = now,
        };
        conv_repo_->save_conversation(conv);

        ConversationParticipantEntity p_alice{
            .conversation_id = conv_id_,
            .user_id = alice_user_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        };
        member_repo_->add_participant(p_alice);
        member_repo_->touch_user_conversation(alice_user_, conv_id_, ConversationType::Direct, MembershipStatus::Active,
                                              now);

        ConversationParticipantEntity p_bob{
            .conversation_id = conv_id_,
            .user_id = bob_user_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        };
        member_repo_->add_participant(p_bob);
        member_repo_->touch_user_conversation(bob_user_, conv_id_, ConversationType::Direct, MembershipStatus::Active,
                                              now);

        // Connect devices: Alice, Bob, and Charlie are all physically ONLINE
        presence_coordinator_->on_device_connected(alice_user_, alice_device_);
        presence_coordinator_->on_device_connected(bob_user_, bob_device_);
        presence_coordinator_->on_device_connected(charlie_user_, charlie_device_);

        service_impl_ =
            std::make_unique<MessagingServiceImpl>(nullptr, nullptr, nullptr, conv_service_, nullptr, nullptr, nullptr,
                                                   nullptr, nullptr, presence_coordinator_);

        grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);

        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        ASSERT_NE(channel_, nullptr);
        stub_ = v1::MessagingService::NewStub(channel_);
        ASSERT_NE(stub_, nullptr);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    UserId alice_user_;
    DeviceId alice_device_;
    UserId bob_user_;
    DeviceId bob_device_;
    UserId charlie_user_;
    DeviceId charlie_device_;
    ConversationId conv_id_;

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<ConversationService> conv_service_;
    std::shared_ptr<PresenceCoordinator> presence_coordinator_;

    std::unique_ptr<MessagingServiceImpl> service_impl_;
    std::unique_ptr<grpc::Server> server_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

// ============================================================================
// UpdatePresence Tests
// ============================================================================

TEST_F(MessagingServicePresenceTest, UpdatePresenceSuccessAndSanitization) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-device-id", alice_device_.str());
    context.AddMetadata("x-correlation-id", "corr-update-pres-01");

    v1::UpdatePresenceRequest request;
    request.set_status(v1::PRESENCE_STATUS_AWAY);
    request.set_custom_status_message("   Focusing on sprint deliverables   ");

    v1::UpdatePresenceResponse response;
    auto status = stub_->UpdatePresence(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.presence().user_id(), alice_user_.str());
    EXPECT_EQ(response.presence().status(), v1::PRESENCE_STATUS_AWAY);
    EXPECT_EQ(response.presence().custom_status_message(), "Focusing on sprint deliverables");

    // Coordinator in-memory state reflects update
    auto current = presence_coordinator_->get_user_presence(alice_user_);
    EXPECT_EQ(current.status, domain::PresenceStatus::Away);
    EXPECT_EQ(current.custom_status_message, "Focusing on sprint deliverables");
}

TEST_F(MessagingServicePresenceTest, UpdatePresenceClearOverride) {
    // 1. Set explicit busy override
    presence_coordinator_->set_user_override(alice_user_, domain::PresenceStatus::Busy, "Do Not Disturb");

    // 2. Clear override by setting ONLINE with empty message
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-correlation-id", "corr-clear-01");

    v1::UpdatePresenceRequest request;
    request.set_status(v1::PRESENCE_STATUS_ONLINE);
    request.set_custom_status_message("");

    v1::UpdatePresenceResponse response;
    auto status = stub_->UpdatePresence(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.presence().status(), v1::PRESENCE_STATUS_ONLINE);
    EXPECT_TRUE(response.presence().custom_status_message().empty());

    auto current = presence_coordinator_->get_user_presence(alice_user_);
    EXPECT_EQ(current.status, domain::PresenceStatus::Online);
    EXPECT_TRUE(current.custom_status_message.empty());
}

TEST_F(MessagingServicePresenceTest, UpdatePresenceUnauthenticatedReturnsError) {
    grpc::ClientContext context; // No x-user-id

    v1::UpdatePresenceRequest request;
    request.set_status(v1::PRESENCE_STATUS_AWAY);
    v1::UpdatePresenceResponse response;

    auto status = stub_->UpdatePresence(&context, request, &response);
    EXPECT_FALSE(status.ok());
}

TEST_F(MessagingServicePresenceTest, UpdatePresenceRateLimitExceeded) {
    // Perform 12 rapid updates (within 1-minute window)
    for (int i = 0; i < 12; ++i) {
        grpc::ClientContext context;
        context.AddMetadata("x-user-id", alice_user_.str());
        context.AddMetadata("x-correlation-id", "corr-rate-" + std::to_string(i));

        v1::UpdatePresenceRequest request;
        request.set_status(v1::PRESENCE_STATUS_BUSY);
        request.set_custom_status_message("Status " + std::to_string(i));

        v1::UpdatePresenceResponse response;
        auto status = stub_->UpdatePresence(&context, request, &response);
        ASSERT_TRUE(status.ok()) << "Update " << i << " failed: " << status.error_message();
    }

    // 13th update must be rejected with RESOURCE_EXHAUSTED
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());
    context.AddMetadata("x-correlation-id", "corr-rate-13");

    v1::UpdatePresenceRequest request;
    request.set_status(v1::PRESENCE_STATUS_AWAY);
    v1::UpdatePresenceResponse response;

    auto status = stub_->UpdatePresence(&context, request, &response);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_NE(status.error_message().find("rate limit exceeded"), std::string::npos);
}

// ============================================================================
// GetPresence & Mutual-Conversation Privacy Guard Tests
// ============================================================================

TEST_F(MessagingServicePresenceTest, GetPresenceSelfAlwaysReturnsTrueStatus) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());

    v1::GetPresenceRequest request;
    request.set_user_id(alice_user_.str());

    v1::GetPresenceResponse response;
    auto status = stub_->GetPresence(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.presence().user_id(), alice_user_.str());
    EXPECT_EQ(response.presence().status(), v1::PRESENCE_STATUS_ONLINE);
}

TEST_F(MessagingServicePresenceTest, GetPresenceMutualConversationReturnsRealStatus) {
    // Alice and Bob share an active direct conversation -> Alice can view Bob's status
    presence_coordinator_->set_user_override(bob_user_, domain::PresenceStatus::Busy, "Coding");

    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());

    v1::GetPresenceRequest request;
    request.set_user_id(bob_user_.str());

    v1::GetPresenceResponse response;
    auto status = stub_->GetPresence(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.presence().user_id(), bob_user_.str());
    EXPECT_EQ(response.presence().status(), v1::PRESENCE_STATUS_BUSY);
    EXPECT_EQ(response.presence().custom_status_message(), "Coding");
}

TEST_F(MessagingServicePresenceTest, GetPresenceNonMutualStrangerShieldedToOffline) {
    // Charlie is physically connected and ONLINE, but shares NO conversation with Alice
    // Mutual-Conversation Privacy Guard must shield Charlie to OFFLINE
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());

    v1::GetPresenceRequest request;
    request.set_user_id(charlie_user_.str());

    v1::GetPresenceResponse response;
    auto status = stub_->GetPresence(&context, request, &response);

    // Invariant: Status is OK (preventing user enumeration / relationship oracle), but payload is OFFLINE
    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    EXPECT_EQ(response.presence().user_id(), charlie_user_.str());
    EXPECT_EQ(response.presence().status(), v1::PRESENCE_STATUS_OFFLINE);
    EXPECT_TRUE(response.presence().custom_status_message().empty());
}

// ============================================================================
// BatchGetPresence Tests
// ============================================================================

TEST_F(MessagingServicePresenceTest, BatchGetPresenceUpTo100WithPrivacyShielding) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());

    v1::BatchGetPresenceRequest request;
    request.add_user_ids(alice_user_.str());   // Self -> Online
    request.add_user_ids(bob_user_.str());     // Mutual contact -> Online
    request.add_user_ids(charlie_user_.str()); // Stranger -> Shielded to Offline

    v1::BatchGetPresenceResponse response;
    auto status = stub_->BatchGetPresence(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();
    ASSERT_EQ(response.presences_size(), 3);

    // 1. Alice (Self)
    EXPECT_EQ(response.presences(0).user_id(), alice_user_.str());
    EXPECT_EQ(response.presences(0).status(), v1::PRESENCE_STATUS_ONLINE);

    // 2. Bob (Mutual)
    EXPECT_EQ(response.presences(1).user_id(), bob_user_.str());
    EXPECT_EQ(response.presences(1).status(), v1::PRESENCE_STATUS_ONLINE);

    // 3. Charlie (Shielded)
    EXPECT_EQ(response.presences(2).user_id(), charlie_user_.str());
    EXPECT_EQ(response.presences(2).status(), v1::PRESENCE_STATUS_OFFLINE);
}

TEST_F(MessagingServicePresenceTest, BatchGetPresenceExceeding100ReturnsInvalidArgument) {
    grpc::ClientContext context;
    context.AddMetadata("x-user-id", alice_user_.str());

    v1::BatchGetPresenceRequest request;
    for (int i = 0; i < 101; ++i) {
        request.add_user_ids("0191ec4d-91b4-7b4d-b6a9-8e41e3d36" + std::to_string(i + 100));
    }

    v1::BatchGetPresenceResponse response;
    auto status = stub_->BatchGetPresence(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_message().find("limit of 100"), std::string::npos);
}

// ============================================================================
// Unimplemented Guard Test
// ============================================================================

TEST_F(MessagingServicePresenceTest, UnimplementedWhenCoordinatorNull) {
    // Create service without PresenceCoordinator
    auto null_service = std::make_unique<MessagingServiceImpl>(nullptr, nullptr, nullptr, conv_service_, nullptr,
                                                               nullptr, nullptr, nullptr, nullptr, nullptr);

    grpc::ServerBuilder builder;
    builder.RegisterService(null_service.get());
    auto server = builder.BuildAndStart();
    auto channel = server->InProcessChannel(grpc::ChannelArguments{});
    auto stub = v1::MessagingService::NewStub(channel);

    grpc::ClientContext context;
    v1::GetPresenceRequest req;
    req.set_user_id(alice_user_.str());
    v1::GetPresenceResponse resp;

    auto status = stub->GetPresence(&context, req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    EXPECT_EQ(status.error_message(), MessagingServiceImpl::k_unimplemented_message);

    server->Shutdown();
    server->Wait();
}

} // namespace
} // namespace securecloud::messaging::service
