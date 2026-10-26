#include "domain/presence_types.hpp"
#include "repository/in_memory_conversation_repository.hpp"
#include "repository/in_memory_membership_repository.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/presence_coordinator.hpp"
#include "telemetry/presence_metrics.hpp"

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

class PresencePrivacyGuardTest : public ::testing::Test {
  protected:
    void SetUp() override {
        alice_user_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        alice_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36091");

        bob_user_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        bob_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36092");

        charlie_user_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
        charlie_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36093");

        stranger_user_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
        stranger_device_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36098");

        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        conv_service_ = std::make_shared<ConversationService>(*conv_repo_, *member_repo_, *auth_service_);

        presence_coordinator_ = std::make_shared<PresenceCoordinator>();

        // Set up active direct conversation between Alice and Bob
        direct_conv_id_ = ConversationId::generate_v7();
        const auto now = std::chrono::system_clock::now();
        ConversationEntity direct_conv{
            .conversation_id = direct_conv_id_,
            .type = ConversationType::Direct,
            .created_by_user_id = alice_user_,
            .created_at = now,
        };
        conv_repo_->save_conversation(direct_conv);

        ConversationParticipantEntity p_alice{
            .conversation_id = direct_conv_id_,
            .user_id = alice_user_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        };
        member_repo_->add_participant(p_alice);
        member_repo_->touch_user_conversation(alice_user_, direct_conv_id_, ConversationType::Direct,
                                              MembershipStatus::Active, now);

        ConversationParticipantEntity p_bob{
            .conversation_id = direct_conv_id_,
            .user_id = bob_user_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        };
        member_repo_->add_participant(p_bob);
        member_repo_->touch_user_conversation(bob_user_, direct_conv_id_, ConversationType::Direct,
                                              MembershipStatus::Active, now);

        // All users connect their devices and are physically ONLINE
        presence_coordinator_->on_device_connected(alice_user_, alice_device_);
        presence_coordinator_->on_device_connected(bob_user_, bob_device_);
        presence_coordinator_->on_device_connected(charlie_user_, charlie_device_);
        presence_coordinator_->on_device_connected(stranger_user_, stranger_device_);

        // Set custom status on Bob
        presence_coordinator_->set_user_override(bob_user_, domain::PresenceStatus::Busy, "Emergency response triage");

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

        telemetry::PresenceMetrics::instance().reset();
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::unique_ptr<::grpc::ClientContext> make_caller_context(const UserId& user_id,
                                                               const DeviceId& device_id = DeviceId("dev-1")) {
        auto ctx = std::make_unique<::grpc::ClientContext>();
        ctx->AddMetadata("x-user-id", user_id.str());
        ctx->AddMetadata("x-device-id", device_id.str());
        ctx->AddMetadata("x-correlation-id", "corr-privacy-test");
        return ctx;
    }

    UserId alice_user_;
    DeviceId alice_device_;
    UserId bob_user_;
    DeviceId bob_device_;
    UserId charlie_user_;
    DeviceId charlie_device_;
    UserId stranger_user_;
    DeviceId stranger_device_;

    ConversationId direct_conv_id_;

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<ConversationService> conv_service_;
    std::shared_ptr<PresenceCoordinator> presence_coordinator_;

    std::unique_ptr<MessagingServiceImpl> service_impl_;
    std::unique_ptr<::grpc::Server> server_;
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> stub_;
};

// ============================================================================
// Privacy Guard Unit Tests
// ============================================================================

TEST_F(PresencePrivacyGuardTest, SelfPresenceBypassesMutualCheck) {
    auto ctx = make_caller_context(alice_user_, alice_device_);
    v1::GetPresenceRequest req;
    req.set_user_id(alice_user_.str());

    v1::GetPresenceResponse resp;
    auto status = stub_->GetPresence(ctx.get(), req, &resp);

    ASSERT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.presence().user_id(), alice_user_.str());
    EXPECT_EQ(resp.presence().status(), v1::PRESENCE_STATUS_ONLINE);
    EXPECT_GT(resp.presence().last_active_unix_ms(), 0);
}

TEST_F(PresencePrivacyGuardTest, MutualDirectConversationAllowsRealPresence) {
    // Alice and Bob share direct_conv_id_ -> Alice querying Bob must see Bob's actual status (Busy + custom message)
    auto ctx = make_caller_context(alice_user_, alice_device_);
    v1::GetPresenceRequest req;
    req.set_user_id(bob_user_.str());

    v1::GetPresenceResponse resp;
    auto status = stub_->GetPresence(ctx.get(), req, &resp);

    ASSERT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.presence().user_id(), bob_user_.str());
    EXPECT_EQ(resp.presence().status(), v1::PRESENCE_STATUS_BUSY);
    EXPECT_EQ(resp.presence().custom_status_message(), "Emergency response triage");
    EXPECT_GT(resp.presence().last_active_unix_ms(), 0);
}

TEST_F(PresencePrivacyGuardTest, MutualGroupConversationAllowsRealPresence) {
    // Charlie initially has no mutual conversation with Alice -> shielded
    {
        auto ctx = make_caller_context(alice_user_, alice_device_);
        v1::GetPresenceRequest req;
        req.set_user_id(charlie_user_.str());

        v1::GetPresenceResponse resp;
        auto status = stub_->GetPresence(ctx.get(), req, &resp);

        ASSERT_TRUE(status.ok());
        EXPECT_EQ(resp.presence().status(), v1::PRESENCE_STATUS_OFFLINE);
        EXPECT_EQ(resp.presence().last_active_unix_ms(), 0);
    }

    // Now establish a Group conversation with Alice, Bob, and Charlie
    const auto group_id = ConversationId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    ConversationEntity group_conv{
        .conversation_id = group_id,
        .type = ConversationType::Group,
        .created_by_user_id = alice_user_,
        .created_at = now,
    };
    conv_repo_->save_conversation(group_conv);

    ConversationParticipantEntity p_alice{
        .conversation_id = group_id,
        .user_id = alice_user_,
        .role = ParticipantRole::Admin,
        .status = MembershipStatus::Active,
        .joined_at = now,
    };
    member_repo_->add_participant(p_alice);
    member_repo_->touch_user_conversation(alice_user_, group_id, ConversationType::Group, MembershipStatus::Active,
                                          now);

    ConversationParticipantEntity p_charlie{
        .conversation_id = group_id,
        .user_id = charlie_user_,
        .role = ParticipantRole::Member,
        .status = MembershipStatus::Active,
        .joined_at = now,
    };
    member_repo_->add_participant(p_charlie);
    member_repo_->touch_user_conversation(charlie_user_, group_id, ConversationType::Group, MembershipStatus::Active,
                                          now);

    // Alice querying Charlie should now reveal Charlie's real presence
    {
        auto ctx = make_caller_context(alice_user_, alice_device_);
        v1::GetPresenceRequest req;
        req.set_user_id(charlie_user_.str());

        v1::GetPresenceResponse resp;
        auto status = stub_->GetPresence(ctx.get(), req, &resp);

        ASSERT_TRUE(status.ok());
        EXPECT_EQ(resp.presence().user_id(), charlie_user_.str());
        EXPECT_EQ(resp.presence().status(), v1::PRESENCE_STATUS_ONLINE);
        EXPECT_GT(resp.presence().last_active_unix_ms(), 0);
    }
}

TEST_F(PresencePrivacyGuardTest, NonMutualStrangerShieldedToOffline) {
    // Stranger attempts to query Bob
    auto ctx = make_caller_context(stranger_user_, stranger_device_);
    v1::GetPresenceRequest req;
    req.set_user_id(bob_user_.str());

    v1::GetPresenceResponse resp;
    auto status = stub_->GetPresence(ctx.get(), req, &resp);

    // Must return 200 OK without revealing user presence (preventing existence / presence oracle)
    ASSERT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.presence().user_id(), bob_user_.str());
    EXPECT_EQ(resp.presence().status(), v1::PRESENCE_STATUS_OFFLINE);
    EXPECT_EQ(resp.presence().custom_status_message(), "");
    EXPECT_EQ(resp.presence().last_active_unix_ms(), 0);
}

TEST_F(PresencePrivacyGuardTest, ParticipantRemovalDecaysToShieldedOffline) {
    // Bob leaves the direct conversation
    auto bob_part = member_repo_->find_participant(direct_conv_id_, bob_user_);
    ASSERT_TRUE(bob_part.has_value());
    bob_part->status = MembershipStatus::Left;
    member_repo_->update_participant(*bob_part);
    member_repo_->touch_user_conversation(bob_user_, direct_conv_id_, ConversationType::Direct, MembershipStatus::Left,
                                          std::chrono::system_clock::now());

    // Alice queries Bob -> Bob is no longer an active participant, so presence is shielded
    auto ctx = make_caller_context(alice_user_, alice_device_);
    v1::GetPresenceRequest req;
    req.set_user_id(bob_user_.str());

    v1::GetPresenceResponse resp;
    auto status = stub_->GetPresence(ctx.get(), req, &resp);

    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.presence().status(), v1::PRESENCE_STATUS_OFFLINE);
    EXPECT_EQ(resp.presence().last_active_unix_ms(), 0);
}

TEST_F(PresencePrivacyGuardTest, BatchGetPresencePrivacyPartitioning) {
    auto ctx = make_caller_context(alice_user_, alice_device_);
    v1::BatchGetPresenceRequest req;
    req.add_user_ids(alice_user_.str());    // Self (allowed)
    req.add_user_ids(bob_user_.str());      // Mutual (allowed)
    req.add_user_ids(stranger_user_.str()); // Stranger (shielded)
    req.add_user_ids(charlie_user_.str());  // Non-mutual (shielded)

    v1::BatchGetPresenceResponse resp;
    auto status = stub_->BatchGetPresence(ctx.get(), req, &resp);

    ASSERT_TRUE(status.ok());
    ASSERT_EQ(resp.presences_size(), 4);

    // 0: Alice (self) -> Online
    EXPECT_EQ(resp.presences(0).user_id(), alice_user_.str());
    EXPECT_EQ(resp.presences(0).status(), v1::PRESENCE_STATUS_ONLINE);

    // 1: Bob (mutual) -> Busy
    EXPECT_EQ(resp.presences(1).user_id(), bob_user_.str());
    EXPECT_EQ(resp.presences(1).status(), v1::PRESENCE_STATUS_BUSY);
    EXPECT_EQ(resp.presences(1).custom_status_message(), "Emergency response triage");

    // 2: Stranger -> Shielded Offline
    EXPECT_EQ(resp.presences(2).user_id(), stranger_user_.str());
    EXPECT_EQ(resp.presences(2).status(), v1::PRESENCE_STATUS_OFFLINE);
    EXPECT_EQ(resp.presences(2).last_active_unix_ms(), 0);

    // 3: Charlie -> Shielded Offline
    EXPECT_EQ(resp.presences(3).user_id(), charlie_user_.str());
    EXPECT_EQ(resp.presences(3).status(), v1::PRESENCE_STATUS_OFFLINE);
    EXPECT_EQ(resp.presences(3).last_active_unix_ms(), 0);
}

TEST_F(PresencePrivacyGuardTest, TelemetryMetricsTrackingAndPrometheusExport) {
    auto& metrics = telemetry::PresenceMetrics::instance();
    metrics.reset();

    // Verify initial state
    EXPECT_EQ(metrics.active_connections(), 0);
    EXPECT_EQ(metrics.presence_status_count("online"), 0);

    // Simulate metrics operations
    metrics.set_active_connections(42);
    metrics.increment_active_connections();
    EXPECT_EQ(metrics.active_connections(), 43);

    metrics.set_presence_status_count("online", 15);
    metrics.set_presence_status_count("busy", 3);
    metrics.set_presence_status_count("away", 2);
    metrics.set_presence_status_count("offline", 5);

    EXPECT_EQ(metrics.presence_status_count("online"), 15);
    EXPECT_EQ(metrics.presence_status_count("busy"), 3);

    metrics.record_connection_churn(telemetry::ConnectionChurnEvent::Connected);
    metrics.record_connection_churn(telemetry::ConnectionChurnEvent::Connected);
    metrics.record_connection_churn(telemetry::ConnectionChurnEvent::Disconnected);
    metrics.record_connection_churn(telemetry::ConnectionChurnEvent::Evicted);

    EXPECT_EQ(metrics.connection_churn(telemetry::ConnectionChurnEvent::Connected), 2);
    EXPECT_EQ(metrics.connection_churn(telemetry::ConnectionChurnEvent::Disconnected), 1);
    EXPECT_EQ(metrics.connection_churn(telemetry::ConnectionChurnEvent::Evicted), 1);

    metrics.increment_fast_track_dispatches(7);
    EXPECT_EQ(metrics.fast_track_dispatches_total(), 7);

    metrics.record_presence_update_latency(0.002); // 2ms
    metrics.record_presence_update_latency(0.008); // 8ms
    EXPECT_EQ(metrics.latency_sample_count(), 2);
    EXPECT_GT(metrics.latency_sum(), 0.009);

    // Verify Prometheus exposition format
    const auto prom_text = metrics.to_prometheus_text();
    EXPECT_NE(prom_text.find("messaging_active_connections 43"), std::string::npos);
    EXPECT_NE(prom_text.find("messaging_presence_status{status=\"online\"} 15"), std::string::npos);
    EXPECT_NE(prom_text.find("messaging_presence_status{status=\"busy\"} 3"), std::string::npos);
    EXPECT_NE(prom_text.find("messaging_connection_churn_total{event=\"connected\"} 2"), std::string::npos);
    EXPECT_NE(prom_text.find("messaging_connection_churn_total{event=\"evicted\"} 1"), std::string::npos);
    EXPECT_NE(prom_text.find("messaging_fast_track_dispatches_total 7"), std::string::npos);
    EXPECT_NE(prom_text.find("messaging_presence_update_latency_seconds_count 2"), std::string::npos);
}

} // namespace
} // namespace securecloud::messaging::service
