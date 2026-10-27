#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "concurrency/bounded_worker_pool.hpp"
#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/connection_lifecycle_manager.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "delivery/realtime_delivery_accelerator.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/message_types.hpp"
#include "domain/presence_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "domain/sync_types.hpp"
#include "gateway_config.hpp"
#include "grpc/messaging_client_interface.hpp"
#include "grpc/messaging_service_client.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/proxy/messaging_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/router.hpp"
#include "messaging/repository/conversation_repository_interface.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_service.hpp"
#include "service/delivery_service.hpp"
#include "service/delivery_state_transition_guard.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/presence_coordinator.hpp"
#include "telemetry/presence_metrics.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

inline void ensure_integration_winsock() noexcept {
    static const bool initialized = []() noexcept {
        WSADATA wsa{};
        return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}
#else
inline void ensure_integration_winsock() noexcept {}
#endif

#include <chrono>
#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

namespace securecloud::messaging {
namespace {

using delivery::MockDeviceDeliveryChannel;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageId;
using domain::MessagePriority;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::UserId;
using domain::UserPresence;

class InMemoryDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mu_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    [[nodiscard]] std::vector<DeviceDeliveryRecord>
    fetch_pending_for_device(const DeviceId& device_id, const std::string& delivery_bucket, size_t limit) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<DeviceDeliveryRecord> result;
        for (const auto& rec : pending_) {
            if (rec.device_id == device_id && (delivery_bucket.empty() || rec.delivery_bucket == delivery_bucket)) {
                if (rec.delivery_state == DeliveryState::Queued || rec.delivery_state == DeliveryState::Delivering) {
                    result.push_back(rec);
                    if (result.size() >= limit) {
                        break;
                    }
                }
            }
        }
        return result;
    }

    void update_device_delivery_status(const DeviceId& device_id, const std::string& delivery_bucket,
                                       const std::chrono::system_clock::time_point& accepted_at,
                                       const MessageId& message_id, DeliveryState state, int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket &&
                rec.accepted_at == accepted_at && rec.message_id == message_id) {
                rec.delivery_state = state;
                rec.attempt_count = attempt_count;
                rec.next_retry_at = next_retry;
                break;
            }
        }
    }

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mu_);
        recipient_states_.insert(recipient_states_.end(), states.begin(), states.end());
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point&) override {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& rec : pending_) {
            if (rec.message_id == message_id && rec.device_id == recipient_device_id) {
                rec.delivery_state = DeliveryState::Delivered;
            }
        }
        for (auto& s : recipient_states_) {
            if (s.message_id == message_id && s.recipient_device_id == recipient_device_id) {
                s.delivery_state = DeliveryState::Delivered;
            }
        }
    }

    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}

    [[nodiscard]] std::vector<RecipientDeliveryState>
    get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<RecipientDeliveryState> result;
        for (const auto& s : recipient_states_) {
            if (s.message_id == message_id) {
                result.push_back(s);
            }
        }
        return result;
    }

    std::optional<DeviceDeliveryRecord> get_record(const DeviceId& device_id, const MessageId& message_id) const {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& r : pending_) {
            if (r.device_id == device_id && r.message_id == message_id) {
                return r;
            }
        }
        return std::nullopt;
    }

  private:
    mutable std::mutex mu_;
    std::vector<DeviceDeliveryRecord> pending_;
    std::vector<RecipientDeliveryState> recipient_states_;
};

class MessagingPresenceIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ensure_integration_winsock();
        telemetry::PresenceMetrics::instance().reset();

        u1_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
        d1_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36091");

        u2_ = *UserId::from_string("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
        d2_ = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36092");

        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<service::ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        conv_service_ = std::make_shared<service::ConversationService>(*conv_repo_, *member_repo_, *auth_service_);

        presence_coordinator_ = std::make_shared<service::PresenceCoordinator>();
        delivery_repo_ = std::make_shared<InMemoryDeliveryStateRepository>();

        connection_registry_ = std::make_shared<delivery::DeviceConnectionRegistry>();

        lifecycle_manager_ = std::make_shared<delivery::ConnectionLifecycleManager>(
            connection_registry_, presence_coordinator_, std::chrono::milliseconds(50), std::chrono::seconds(60));

        delivery::DeliverySchedulerConfig sched_config{
            .max_global_queued_tasks = 1000,
            .max_tasks_per_device = 50,
            .emergency_queue_reserved_slots = 100,
        };
        scheduler_ = std::make_shared<delivery::BoundedDeliveryScheduler>(sched_config);

        accelerator_ =
            std::make_shared<delivery::RealtimeDeliveryAccelerator>(delivery_repo_, scheduler_, connection_registry_,
                                                                    delivery::RealtimeDeliveryAcceleratorConfig{
                                                                        .max_fast_track_batch = 50,
                                                                        .max_delivery_ttl = std::chrono::hours(24),
                                                                    });
        accelerator_->attach_to_lifecycle_manager(*lifecycle_manager_);

        // Direct conversation between U1 and U2
        conv_id_ = ConversationId::generate_v7();
        const auto now = std::chrono::system_clock::now();
        ConversationEntity conv{
            .conversation_id = conv_id_,
            .type = ConversationType::Direct,
            .created_by_user_id = u1_,
            .created_at = now,
        };
        conv_repo_->save_conversation(conv);

        ConversationParticipantEntity p1{
            .conversation_id = conv_id_,
            .user_id = u1_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        };
        member_repo_->add_participant(p1);
        member_repo_->touch_user_conversation(u1_, conv_id_, ConversationType::Direct, MembershipStatus::Active, now);

        ConversationParticipantEntity p2{
            .conversation_id = conv_id_,
            .user_id = u2_,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = now,
        };
        member_repo_->add_participant(p2);
        member_repo_->touch_user_conversation(u2_, conv_id_, ConversationType::Direct, MembershipStatus::Active, now);

        // Start in-process gRPC service
        service_impl_ =
            std::make_unique<service::MessagingServiceImpl>(nullptr, nullptr, nullptr, conv_service_, nullptr, nullptr,
                                                            nullptr, nullptr, nullptr, presence_coordinator_);

        grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);

        channel_ = server_->InProcessChannel(grpc::ChannelArguments{});
        ASSERT_NE(channel_, nullptr);
        messaging_client_ = std::make_shared<gateway::grpc::MessagingServiceClient>(channel_);

        // Gateway HTTP proxy handler
        deadline_mgr_ = std::make_shared<gateway::http::DeadlineManager>();
        retry_policy_ = std::make_shared<gateway::http::RetryPolicy>();
        bulkhead_mgr_ = std::make_shared<gateway::http::BulkheadManager>();
        circuit_breaker_ =
            std::make_shared<gateway::http::CircuitBreaker>("messaging", gateway::GatewayCircuitBreakerConfig{
                                                                             .enabled = true,
                                                                             .failure_threshold = 5,
                                                                             .recovery_timeout_ms = 1000,
                                                                             .half_open_probe_count = 1,
                                                                         });

        gateway_handler_ = std::make_unique<gateway::http::MessagingProxyHandler>(
            messaging_client_, deadline_mgr_, retry_policy_, bulkhead_mgr_, circuit_breaker_);
        gateway_handler_->register_routes(router_);
    }

    void TearDown() override {
        lifecycle_manager_->stop();
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    gateway::http::AuthenticatedContext make_auth_ctx(const UserId& uid, const DeviceId& did) {
        return gateway::http::AuthenticatedContext(uid.str(), did.str(), "sess-integ",
                                                   auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                                   {"messaging:read", "messaging:write"}, 1800000000000LL);
    }

    UserId u1_;
    DeviceId d1_;
    UserId u2_;
    DeviceId d2_;
    ConversationId conv_id_;

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<service::ConversationAuthorizationService> auth_service_;
    std::shared_ptr<service::ConversationService> conv_service_;
    std::shared_ptr<service::PresenceCoordinator> presence_coordinator_;
    std::shared_ptr<InMemoryDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<delivery::DeviceConnectionRegistry> connection_registry_;
    std::shared_ptr<delivery::ConnectionLifecycleManager> lifecycle_manager_;
    std::shared_ptr<delivery::BoundedDeliveryScheduler> scheduler_;
    std::shared_ptr<delivery::RealtimeDeliveryAccelerator> accelerator_;

    std::unique_ptr<service::MessagingServiceImpl> service_impl_;
    std::unique_ptr<::grpc::Server> server_;
    std::shared_ptr<::grpc::Channel> channel_;
    std::shared_ptr<gateway::grpc::IMessagingClient> messaging_client_;

    std::shared_ptr<gateway::http::DeadlineManager> deadline_mgr_;
    std::shared_ptr<gateway::http::RetryPolicy> retry_policy_;
    std::shared_ptr<gateway::http::BulkheadManager> bulkhead_mgr_;
    std::shared_ptr<gateway::http::CircuitBreaker> circuit_breaker_;
    std::unique_ptr<gateway::http::MessagingProxyHandler> gateway_handler_;
    gateway::http::Router router_;
};

// ============================================================================
// 1. Non-Conflation Axiom & Reconnect Fast-Track Lifecycle Integration Test
// ============================================================================

TEST_F(MessagingPresenceIntegrationTest, StrictNonConflationInvariantUnderConnectionChurn) {
    // -------------------------------------------------------------------------
    // Step 1: Connect Device D1 for User U1. Assert presence reports ONLINE.
    // -------------------------------------------------------------------------
    auto ch1 = std::make_shared<MockDeviceDeliveryChannel>(d1_, u1_);
    lifecycle_manager_->establish_connection(ch1, "127.0.0.1", "SecureCloud/1.0", 1);

    auto presence1 = presence_coordinator_->get_user_presence(u1_);
    EXPECT_TRUE(presence1.is_online());
    EXPECT_EQ(presence1.status, domain::PresenceStatus::Online);

    // -------------------------------------------------------------------------
    // Step 2: Send Message M1 destined for Device D1.
    // -------------------------------------------------------------------------
    const auto m1 = MessageId::generate_v7();
    const auto now = std::chrono::system_clock::now();
    const auto bucket = MessageBucket::from_time_point(now).value();

    DeviceDeliveryRecord rec1{
        .device_id = d1_,
        .delivery_bucket = bucket,
        .accepted_at = now,
        .message_id = m1,
        .conversation_id = conv_id_,
        .message_priority = MessagePriority::Normal,
        .delivery_state = DeliveryState::Queued,
        .attempt_count = 0,
        .ciphertext_blob = "encrypted-payload-bytes",
        .protocol_version = domain::E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
    };
    delivery_repo_->save_pending_deliveries({rec1});

    // -------------------------------------------------------------------------
    // Step 3: Assert Non-Conflation Property 1:
    // Even though D1 is ONLINE and connected, M1 state in ScyllaDB is QUEUED, NOT DELIVERED.
    // -------------------------------------------------------------------------
    auto state_step3 = delivery_repo_->get_record(d1_, m1);
    ASSERT_TRUE(state_step3.has_value());
    EXPECT_EQ(state_step3->delivery_state, DeliveryState::Queued);

    // -------------------------------------------------------------------------
    // Step 4: Disconnect Device D1 abruptly (simulate elevator / dead-zone drop).
    // -------------------------------------------------------------------------
    lifecycle_manager_->terminate_connection(d1_);
    auto presence_step4 = presence_coordinator_->get_user_presence(u1_);
    EXPECT_EQ(presence_step4.status, domain::PresenceStatus::Offline);

    // -------------------------------------------------------------------------
    // Step 5: Assert Non-Conflation Property 2:
    // M1 state remains durably QUEUED in ScyllaDB. No message loss occurs.
    // -------------------------------------------------------------------------
    auto state_step5 = delivery_repo_->get_record(d1_, m1);
    ASSERT_TRUE(state_step5.has_value());
    EXPECT_EQ(state_step5->delivery_state, DeliveryState::Queued);

    // -------------------------------------------------------------------------
    // Step 6: Reconnect Device D1 with a fresh transport session.
    // -------------------------------------------------------------------------
    auto ch1_new = std::make_shared<MockDeviceDeliveryChannel>(d1_, u1_);
    lifecycle_manager_->establish_connection(ch1_new, "127.0.0.1", "SecureCloud/1.0", 1);

    auto presence_step6 = presence_coordinator_->get_user_presence(u1_);
    EXPECT_EQ(presence_step6.status, domain::PresenceStatus::Online);

    // -------------------------------------------------------------------------
    // Step 7: RealtimeDeliveryAccelerator fast-tracks M1 into the scheduler.
    // -------------------------------------------------------------------------
    EXPECT_GT(accelerator_->total_accelerated_count(), 0);
    EXPECT_GT(telemetry::PresenceMetrics::instance().fast_track_dispatches_total(), 0);

    // -------------------------------------------------------------------------
    // Step 8: Device D1 submits affirmative AcknowledgeDelivery.
    // -------------------------------------------------------------------------
    delivery_repo_->record_delivery_ack(m1, d1_, std::chrono::system_clock::now());

    // -------------------------------------------------------------------------
    // Step 9: Verify M1 transitions to durable DELIVERED in ScyllaDB.
    // -------------------------------------------------------------------------
    auto state_step9 = delivery_repo_->get_record(d1_, m1);
    ASSERT_TRUE(state_step9.has_value());
    EXPECT_EQ(state_step9->delivery_state, DeliveryState::Delivered);

    // -------------------------------------------------------------------------
    // Step 10: Disconnect Device D1 again. Assert M1 remains durably DELIVERED (no rollback).
    // -------------------------------------------------------------------------
    lifecycle_manager_->terminate_connection(d1_);
    auto state_step10 = delivery_repo_->get_record(d1_, m1);
    ASSERT_TRUE(state_step10.has_value());
    EXPECT_EQ(state_step10->delivery_state, DeliveryState::Delivered);
}

// ============================================================================
// 2. Gateway REST Proxy -> gRPC Presence Integration Test
// ============================================================================

TEST_F(MessagingPresenceIntegrationTest, GatewayRestToGrpcPresenceIntegration) {
    // Connect devices for U1 and U2 so they are physically online and have active presence
    presence_coordinator_->on_device_connected(u1_, d1_);
    presence_coordinator_->on_device_connected(u2_, d2_);

    // 1. PUT /v1/presence/me via Gateway HTTP Proxy
    httplib::Request put_req;
    put_req.method = "PUT";
    put_req.path = "/v1/presence/me";
    put_req.body = R"({"status": "busy", "custom_status_message": "Conducting surgical triage"})";

    httplib::Response put_res;
    gateway_handler_->handle_update_presence(put_req, put_res, make_auth_ctx(u1_, d1_));

    ASSERT_EQ(put_res.status, 200);
    auto put_body = nlohmann::json::parse(put_res.body);
    EXPECT_EQ(put_body["user_id"], u1_.str());
    EXPECT_EQ(put_body["status"], "busy");
    EXPECT_EQ(put_body["custom_status_message"], "Conducting surgical triage");

    // 2. POST /v1/users/presence/batch via Gateway HTTP Proxy
    httplib::Request batch_req;
    batch_req.method = "POST";
    batch_req.path = "/v1/users/presence/batch";
    nlohmann::json batch_json;
    batch_json["user_ids"] = {u1_.str(), u2_.str()};
    batch_req.body = batch_json.dump();

    httplib::Response batch_res;
    gateway_handler_->handle_batch_get_presence(batch_req, batch_res, make_auth_ctx(u1_, d1_));

    ASSERT_EQ(batch_res.status, 200);
    auto batch_resp = nlohmann::json::parse(batch_res.body);
    ASSERT_TRUE(batch_resp.is_array());
    ASSERT_EQ(batch_resp.size(), 2);
    EXPECT_EQ(batch_resp[0]["user_id"], u1_.str());
    EXPECT_EQ(batch_resp[0]["status"], "busy");
    EXPECT_EQ(batch_resp[1]["user_id"], u2_.str());
    EXPECT_EQ(batch_resp[1]["status"], "online");
}

// ============================================================================
// 3. Multi-Device Fleet Aggregation Integration Test
// ============================================================================

TEST_F(MessagingPresenceIntegrationTest, MultiDeviceFleetAggregationLifecycle) {
    const auto d1_mobile = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36093");
    const auto d1_laptop = DeviceId("0191ec4d-91b4-7b4d-b6a9-8e41e3d36094");

    auto ch_mobile = std::make_shared<MockDeviceDeliveryChannel>(d1_mobile, u1_);
    auto ch_laptop = std::make_shared<MockDeviceDeliveryChannel>(d1_laptop, u1_);

    // 1. Mobile connects -> User Online
    lifecycle_manager_->establish_connection(ch_mobile, "10.0.0.1", "Android-Client/1.0", 1);
    EXPECT_TRUE(presence_coordinator_->get_user_presence(u1_).is_online());
    EXPECT_EQ(presence_coordinator_->get_user_presence(u1_).active_device_count, 1);

    // 2. Laptop connects -> User still Online, active device count = 2
    lifecycle_manager_->establish_connection(ch_laptop, "10.0.0.2", "Linux-Client/1.0", 1);
    EXPECT_TRUE(presence_coordinator_->get_user_presence(u1_).is_online());
    EXPECT_EQ(presence_coordinator_->get_user_presence(u1_).active_device_count, 2);

    // 3. Mobile disconnects -> User remains Online because laptop is active
    lifecycle_manager_->terminate_connection(d1_mobile);
    EXPECT_TRUE(presence_coordinator_->get_user_presence(u1_).is_online());
    EXPECT_EQ(presence_coordinator_->get_user_presence(u1_).active_device_count, 1);

    // 4. Laptop disconnects -> User transitions to Offline
    lifecycle_manager_->terminate_connection(d1_laptop);
    auto presence_final = presence_coordinator_->get_user_presence(u1_);
    EXPECT_FALSE(presence_final.is_online());
    EXPECT_EQ(presence_final.status, domain::PresenceStatus::Offline);
    EXPECT_EQ(presence_final.active_device_count, 0);
    EXPECT_GT(presence_final.last_active_at.time_since_epoch().count(), 0);
}

} // namespace
} // namespace securecloud::messaging
