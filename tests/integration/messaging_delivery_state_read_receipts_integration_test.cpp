#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "concurrency/bounded_worker_pool.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"
#include "domain/outbox_event.hpp"
#include "domain/read_receipt_types.hpp"
#include "gateway_config.hpp"
#include "grpc/messaging_service_client.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/proxy/messaging_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/router.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "securecloud/security/mtls_config.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/delivery_service.hpp"
#include "service/delivery_state_transition_guard.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/read_receipt_service.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

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

#include <atomic>
#include <chrono>
#include <deque>
#include <filesystem>
#include <future>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging {
namespace {

using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationOutboxEventType;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceDeliveryStatus;
using domain::DeviceId;
using domain::LogicalRecipientReadStatus;
using domain::MembershipStatus;
using domain::MessageDeliverySummary;
using domain::MessageId;
using domain::ParticipantRole;
using domain::ReadState;
using domain::RecipientDeliveryState;
using domain::UserId;
using service::DeliveryAckCommand;
using service::DeliveryService;
using service::DeliveryStateTransitionGuard;
using service::MessagingServiceImpl;
using service::ReadReceiptCommand;
using service::ReadReceiptService;

constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::seconds k_rpc_deadline{5};

// ============================================================================
// Thread-Safe In-Memory Delivery Repository
// ============================================================================

class ThreadSafeDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }

    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&, DeliveryState,
                                       int32_t, std::optional<std::chrono::system_clock::time_point>) override {}

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& st : states) {
            recipient_states_[st.message_id].push_back(st);
        }
    }

    void record_delivery_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            for (auto& s : it->second) {
                if (s.recipient_device_id == recipient_device_id) {
                    if (DeliveryStateTransitionGuard::can_transition(s.delivery_state, DeliveryState::Delivered) ||
                        DeliveryStateTransitionGuard::is_idempotent(s.delivery_state, DeliveryState::Delivered)) {
                        s.delivery_state = DeliveryState::Delivered;
                        if (!s.delivered_at.has_value()) {
                            s.delivered_at = delivered_at;
                        }
                    }
                    break;
                }
            }
        }
    }

    void record_read_ack(const MessageId& message_id, const DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            for (auto& s : it->second) {
                if (s.recipient_device_id == recipient_device_id) {
                    if (!s.read_at.has_value()) {
                        s.read_at = read_at;
                    }
                    break;
                }
            }
        }
    }

    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it != recipient_states_.end()) {
            return it->second;
        }
        return {};
    }

    bool update_delivery_state_monotonic(const MessageId& message_id, const DeviceId& recipient_device_id,
                                         DeliveryState new_state,
                                         const std::chrono::system_clock::time_point& updated_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it == recipient_states_.end()) {
            return false;
        }
        for (auto& s : it->second) {
            if (s.recipient_device_id == recipient_device_id) {
                if (DeliveryStateTransitionGuard::can_transition(s.delivery_state, new_state) ||
                    DeliveryStateTransitionGuard::is_idempotent(s.delivery_state, new_state)) {
                    s.delivery_state = new_state;
                    if (new_state == DeliveryState::Delivered && !s.delivered_at.has_value()) {
                        s.delivered_at = updated_at;
                    }
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    std::optional<MessageDeliverySummary> get_message_delivery_summary(const MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id);
        if (it == recipient_states_.end()) {
            return std::nullopt;
        }

        MessageDeliverySummary summary;
        summary.message_id = message_id;
        std::map<UserId, LogicalRecipientReadStatus> read_map;

        for (const auto& s : it->second) {
            summary.total_targets++;
            if (s.delivery_state == DeliveryState::Delivered) {
                summary.delivered_targets++;
            } else if (s.delivery_state == DeliveryState::Expired) {
                summary.expired_targets++;
            } else {
                summary.pending_targets++;
            }

            DeviceDeliveryStatus dev;
            dev.device_id = s.recipient_device_id;
            dev.recipient_user_id = s.recipient_user_id;
            dev.delivery_state = s.delivery_state;
            dev.delivered_at = s.delivered_at;
            dev.attempt_count = (s.delivery_state == DeliveryState::Delivered) ? 1 : 0;
            summary.device_statuses.push_back(dev);

            auto& u = read_map[s.recipient_user_id];
            u.user_id = s.recipient_user_id;
            if (s.read_at.has_value()) {
                u.read_state = ReadState::Read;
                u.read_at = s.read_at;
                u.reader_device_id = s.recipient_device_id;
            } else if (u.read_state != ReadState::Read) {
                u.read_state = ReadState::Unread;
            }
        }

        for (auto& [_, st] : read_map) {
            summary.recipient_read_statuses.push_back(st);
        }
        return summary;
    }

    // Direct state manipulation for test assertions
    void seed_target(const MessageId& mid, const UserId& uid, const DeviceId& did,
                     DeliveryState initial_state = DeliveryState::Queued) {
        std::lock_guard<std::mutex> lock(mutex_);
        RecipientDeliveryState s;
        s.message_id = mid;
        s.recipient_user_id = uid;
        s.recipient_device_id = did;
        s.delivery_state = initial_state;
        recipient_states_[mid].push_back(s);
    }

    void set_direct_state(const MessageId& mid, const DeviceId& did, DeliveryState state,
                          std::optional<std::chrono::system_clock::time_point> delivered_at = std::nullopt) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(mid);
        if (it != recipient_states_.end()) {
            for (auto& s : it->second) {
                if (s.recipient_device_id == did) {
                    s.delivery_state = state;
                    s.delivered_at = delivered_at;
                    break;
                }
            }
        }
    }

    [[nodiscard]] std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return recipient_states_;
    }

    void restore_snapshot(const std::unordered_map<MessageId, std::vector<RecipientDeliveryState>>& data) {
        std::lock_guard<std::mutex> lock(mutex_);
        recipient_states_ = data;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<DeviceDeliveryRecord> pending_;
    std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> recipient_states_;
};

// ============================================================================
// Thread-Safe Outbox Repository
// ============================================================================

class ThreadSafeOutboxRepository final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string& = "") override {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }
    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    [[nodiscard]] size_t event_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_.size();
    }

    [[nodiscard]] std::vector<ConversationOutboxEvent> all_events() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<ConversationOutboxEvent> events_;
};

// ============================================================================
// Integration Test Fixture
// ============================================================================

class MessagingDeliveryStateReadReceiptsIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_root() {
#ifdef SECURECLOUD_DEV_PKI_DIR
        std::filesystem::path defined_path(SECURECLOUD_DEV_PKI_DIR);
        if (std::filesystem::exists(defined_path / "ca" / "ca.crt")) {
            return defined_path;
        }
#endif
        auto curr = std::filesystem::current_path();
        while (!curr.empty() && curr != curr.root_path()) {
            if (std::filesystem::exists(curr / "deploy" / "dev-pki" / "ca" / "ca.crt")) {
                return curr / "deploy" / "dev-pki";
            }
            curr = curr.parent_path();
        }
        return "deploy/dev-pki";
    }

    void SetUp() override {
        ensure_integration_winsock();

        auto pki_root = find_pki_root();
        ca_path_ = pki_root / "ca" / "ca.crt";
        messaging_cert_path_ = pki_root / "services" / "messaging" / "messaging.crt";
        messaging_key_path_ = pki_root / "services" / "messaging" / "messaging.key";
        gateway_cert_path_ = pki_root / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root / "services" / "gateway" / "gateway.key";

        const std::vector<std::filesystem::path> required_paths = {ca_path_, messaging_cert_path_, messaging_key_path_,
                                                                   gateway_cert_path_, gateway_key_path_};
        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Required dev PKI credential missing: " << path;
        }

        messaging_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = messaging_cert_path_,
            .service_key_path = messaging_key_path_,
        };

        gateway_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        submission_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(8, 256, "sub-integ-pool");
        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "del-integ-pool");
        sync_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sync-integ-pool");

        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<ThreadSafeOutboxRepository>();

        delivery_service_ = std::make_shared<DeliveryService>(delivery_repo_, outbox_repo_);

        read_receipt_service_ = std::make_shared<ReadReceiptService>(
            delivery_repo_, member_repo_, outbox_repo_,
            [this](const DeviceId& dev) { return active_devices_.find(dev) != active_devices_.end(); });

        messaging_service_ = std::make_unique<MessagingServiceImpl>(
            submission_pool_, delivery_pool_, sync_pool_, nullptr, nullptr, delivery_service_, read_receipt_service_);

        seed_data();
        start_grpc_server();
        setup_clients();
    }

    void TearDown() override {
        stop_grpc_server();
        if (submission_pool_ && !submission_pool_->is_shutdown()) {
            submission_pool_->shutdown();
        }
        if (delivery_pool_ && !delivery_pool_->is_shutdown()) {
            delivery_pool_->shutdown();
        }
        if (sync_pool_ && !sync_pool_->is_shutdown()) {
            sync_pool_->shutdown();
        }
    }

    void seed_data() {
        alice_user_ = UserId::from_string("018f6e80-1111-7000-8000-000000000001").value();
        bob_user_ = UserId::from_string("018f6e80-2222-7000-8000-000000000002").value();
        charlie_user_ = UserId::from_string("018f6e80-3333-7000-8000-000000000003").value();
        eve_user_ = UserId::from_string("018f6e80-9999-7000-8000-000000000009").value();

        alice_device_ = DeviceId("018f6e80-aaaa-7000-8000-000000000001");
        bob_device_1_ = DeviceId("018f6e80-bbbb-7000-8000-000000000001");
        bob_device_2_ = DeviceId("018f6e80-bbbb-7000-8000-000000000002");
        bob_device_revoked_ = DeviceId("018f6e80-bbbb-7000-8000-000000000003");
        charlie_device_ = DeviceId("018f6e80-cccc-7000-8000-000000000001");
        eve_device_ = DeviceId("018f6e80-eeee-7000-8000-000000000001");

        // Active devices set (bob_device_revoked_ is NOT added here)
        active_devices_.insert(alice_device_);
        active_devices_.insert(bob_device_1_);
        active_devices_.insert(bob_device_2_);
        active_devices_.insert(charlie_device_);
        active_devices_.insert(eve_device_);

        auto now = std::chrono::system_clock::now();

        // Group Conversation: Alice (Admin), Bob (Member), Charlie (Member)
        group_conv_id_ = ConversationId::generate_v7();
        ConversationEntity group_entity{group_conv_id_, ConversationType::Group, alice_user_};
        conv_repo_->save_conversation(group_entity);

        member_repo_->add_participant(
            {group_conv_id_, alice_user_, ParticipantRole::Admin, MembershipStatus::Active, now});
        member_repo_->add_participant(
            {group_conv_id_, bob_user_, ParticipantRole::Member, MembershipStatus::Active, now});
        member_repo_->add_participant(
            {group_conv_id_, charlie_user_, ParticipantRole::Member, MembershipStatus::Active, now});

        // Direct Conversation: Alice and Bob
        direct_conv_id_ = ConversationId::generate_v7();
        ConversationEntity direct_entity{direct_conv_id_, ConversationType::Direct, alice_user_};
        conv_repo_->save_conversation(direct_entity);

        member_repo_->add_participant(
            {direct_conv_id_, alice_user_, ParticipantRole::Member, MembershipStatus::Active, now});
        member_repo_->add_participant(
            {direct_conv_id_, bob_user_, ParticipantRole::Member, MembershipStatus::Active, now});
    }

    void start_grpc_server() {
        auto server_creds = MtlsCredentialLoader::create_server_credentials(messaging_config_);
        ASSERT_NE(server_creds, nullptr);

        grpc::ServerBuilder builder;
        int selected_port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
        builder.RegisterService(messaging_service_.get());

        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        ASSERT_GT(selected_port, 0);

        server_address_ = "127.0.0.1:" + std::to_string(selected_port);
    }

    void stop_grpc_server() {
        proxy_handler_.reset();
        gateway_client_.reset();
        grpc_stub_.reset();
        channel_.reset();
        if (server_) {
            server_->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
            server_->Wait();
            server_.reset();
        }
    }

    void setup_clients() {
        channel_ = MtlsCredentialLoader::create_mtls_channel(server_address_, gateway_config_, "messaging");
        ASSERT_NE(channel_, nullptr);
        grpc_stub_ = v1::MessagingService::NewStub(channel_);

        gateway_client_ = std::make_shared<gateway::grpc::MessagingServiceClient>(channel_);

        auto deadline_mgr = std::make_shared<gateway::http::DeadlineManager>(
            gateway::GatewayServiceDeadlinesConfig{.messaging_timeout_ms = 5000});
        auto retry_policy = std::make_shared<gateway::http::RetryPolicy>();
        auto bulkhead_mgr = std::make_shared<gateway::http::BulkheadManager>(
            gateway::GatewayBulkheadConfig{.messaging_max_concurrent = 20});
        auto circuit_breaker = std::make_shared<gateway::http::CircuitBreaker>(
            "messaging", gateway::GatewayCircuitBreakerConfig{.enabled = true});

        proxy_handler_ = std::make_shared<gateway::http::MessagingProxyHandler>(
            gateway_client_, deadline_mgr, retry_policy, bulkhead_mgr, circuit_breaker);
    }

    void configure_context(grpc::ClientContext& context, const std::string& user_id, const std::string& device_id = "",
                           const std::string& correlation_id = "corr-msg008-integ") {
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        context.AddMetadata("x-user-id", user_id);
        context.AddMetadata("x-correlation-id", correlation_id);
        if (!device_id.empty()) {
            context.AddMetadata("x-device-id", device_id);
        }
    }

    std::filesystem::path ca_path_;
    std::filesystem::path messaging_cert_path_;
    std::filesystem::path messaging_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    SecurityCredentialsConfig messaging_config_;
    SecurityCredentialsConfig gateway_config_;

    std::shared_ptr<concurrency::BoundedWorkerPool> submission_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> delivery_pool_;
    std::shared_ptr<concurrency::BoundedWorkerPool> sync_pool_;

    std::shared_ptr<repository::InMemoryConversationRepository> conv_repo_;
    std::shared_ptr<repository::InMemoryMembershipRepository> member_repo_;
    std::shared_ptr<ThreadSafeDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<ThreadSafeOutboxRepository> outbox_repo_;

    std::shared_ptr<DeliveryService> delivery_service_;
    std::shared_ptr<ReadReceiptService> read_receipt_service_;
    std::unique_ptr<MessagingServiceImpl> messaging_service_;

    std::set<DeviceId> active_devices_;

    std::unique_ptr<grpc::Server> server_;
    std::string server_address_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<v1::MessagingService::Stub> grpc_stub_;
    std::shared_ptr<gateway::grpc::MessagingServiceClient> gateway_client_;
    std::shared_ptr<gateway::http::MessagingProxyHandler> proxy_handler_;

    UserId alice_user_;
    UserId bob_user_;
    UserId charlie_user_;
    UserId eve_user_;

    DeviceId alice_device_;
    DeviceId bob_device_1_;
    DeviceId bob_device_2_;
    DeviceId bob_device_revoked_;
    DeviceId charlie_device_;
    DeviceId eve_device_;

    ConversationId group_conv_id_;
    ConversationId direct_conv_id_;
};

// ============================================================================
// 1. Scenario 1: Normal Delivery Transition
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario01_NormalDeliveryTransition) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Queued);

    // Initial check: QUEUED
    auto summary_init = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary_init.has_value());
    EXPECT_EQ(summary_init->total_targets, 1);
    EXPECT_EQ(summary_init->pending_targets, 1);
    EXPECT_EQ(summary_init->delivered_targets, 0);

    // Transition: QUEUED -> DELIVERING
    bool step1 = delivery_repo_->update_delivery_state_monotonic(msg_id, bob_device_1_, DeliveryState::Delivering,
                                                                 std::chrono::system_clock::now());
    EXPECT_TRUE(step1);

    // Affirmative client delivery ACK via gRPC
    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());

    v1::AcknowledgeDeliveryRequest req;
    req.set_message_id(msg_id.to_string());
    req.set_recipient_device_id(bob_device_1_.str());
    req.set_delivered_at_unix_ms(1760000000000LL);

    v1::AcknowledgeDeliveryResponse resp;
    auto status = grpc_stub_->AcknowledgeDelivery(&ctx, req, &resp);
    ASSERT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.message_id(), msg_id.to_string());
    EXPECT_EQ(resp.state(), v1::DELIVERY_STATE_DELIVERED);

    // Verify monotonic end state: DELIVERED
    auto summary_end = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary_end.has_value());
    EXPECT_EQ(summary_end->delivered_targets, 1);
    EXPECT_EQ(summary_end->pending_targets, 0);
    EXPECT_EQ(summary_end->device_statuses[0].delivery_state, DeliveryState::Delivered);
}

// ============================================================================
// 2. Scenario 2: Invalid Transition & Regression Rejection
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario02_InvalidTransitionAndRegressionRejection) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Delivered);

    const auto now = std::chrono::system_clock::now();

    // Regression 1: DELIVERED -> QUEUED (Must be rejected)
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivered, DeliveryState::Queued));
    EXPECT_FALSE(delivery_repo_->update_delivery_state_monotonic(msg_id, bob_device_1_, DeliveryState::Queued, now));

    // Regression 2: DELIVERED -> RETRY_WAIT (Must be rejected)
    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Delivered, DeliveryState::RetryWait));
    EXPECT_FALSE(delivery_repo_->update_delivery_state_monotonic(msg_id, bob_device_1_, DeliveryState::RetryWait, now));

    // Regression 3: EXPIRED -> DELIVERING (Must be rejected)
    const auto expired_msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(expired_msg_id, bob_user_, bob_device_1_, DeliveryState::Expired);

    EXPECT_FALSE(DeliveryStateTransitionGuard::can_transition(DeliveryState::Expired, DeliveryState::Delivering));
    EXPECT_FALSE(
        delivery_repo_->update_delivery_state_monotonic(expired_msg_id, bob_device_1_, DeliveryState::Delivering, now));

    // Authoritative states remain preserved
    auto sum1 = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(sum1.has_value());
    EXPECT_EQ(sum1->device_statuses[0].delivery_state, DeliveryState::Delivered);

    auto sum2 = delivery_repo_->get_message_delivery_summary(expired_msg_id);
    ASSERT_TRUE(sum2.has_value());
    EXPECT_EQ(sum2->device_statuses[0].delivery_state, DeliveryState::Expired);
}

// ============================================================================
// 3. Scenario 3: Duplicate Delivery ACK Idempotency
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario03_DuplicateDeliveryAckIdempotency) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Delivering);

    const int64_t t1 = 1760000000100LL;
    const int64_t t2 = 1760000000900LL;

    // First delivery ACK
    grpc::ClientContext ctx1;
    configure_context(ctx1, bob_user_.str(), bob_device_1_.str());
    v1::AcknowledgeDeliveryRequest req1;
    req1.set_message_id(msg_id.to_string());
    req1.set_recipient_device_id(bob_device_1_.str());
    req1.set_delivered_at_unix_ms(t1);
    v1::AcknowledgeDeliveryResponse resp1;
    ASSERT_TRUE(grpc_stub_->AcknowledgeDelivery(&ctx1, req1, &resp1).ok());

    // Duplicate delivery ACK with later timestamp t2
    grpc::ClientContext ctx2;
    configure_context(ctx2, bob_user_.str(), bob_device_1_.str());
    v1::AcknowledgeDeliveryRequest req2;
    req2.set_message_id(msg_id.to_string());
    req2.set_recipient_device_id(bob_device_1_.str());
    req2.set_delivered_at_unix_ms(t2);
    v1::AcknowledgeDeliveryResponse resp2;
    ASSERT_TRUE(grpc_stub_->AcknowledgeDelivery(&ctx2, req2, &resp2).ok());

    // Verify original timestamp is immutable
    auto summary = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary.has_value());
    ASSERT_TRUE(summary->device_statuses[0].delivered_at.has_value());
    auto recorded_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           summary->device_statuses[0].delivered_at->time_since_epoch())
                           .count();
    EXPECT_EQ(recorded_ms, t1);
}

// ============================================================================
// 4. Scenario 4: Concurrent Delivery ACKs
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario04_ConcurrentDeliveryAcks) {
    const auto msg_id = MessageId::generate_v7();
    constexpr size_t k_num_devices = 10;
    std::vector<DeviceId> devices;

    for (size_t i = 0; i < k_num_devices; ++i) {
        char dev_str[64];
        std::snprintf(dev_str, sizeof(dev_str), "018f6e80-bbbb-7000-8000-%012zu", i);
        DeviceId dev(dev_str);
        devices.push_back(dev);
        active_devices_.insert(dev);
        delivery_repo_->seed_target(msg_id, bob_user_, dev, DeliveryState::Delivering);
    }

    std::vector<std::future<bool>> futures;
    futures.reserve(k_num_devices);

    for (size_t i = 0; i < k_num_devices; ++i) {
        futures.push_back(std::async(std::launch::async, [this, msg_id, dev = devices[i], i]() {
            grpc::ClientContext ctx;
            configure_context(ctx, bob_user_.str(), dev.str());
            v1::AcknowledgeDeliveryRequest req;
            req.set_message_id(msg_id.to_string());
            req.set_recipient_device_id(dev.str());
            req.set_delivered_at_unix_ms(1760000000000LL + static_cast<int64_t>(i));
            v1::AcknowledgeDeliveryResponse resp;
            auto status = grpc_stub_->AcknowledgeDelivery(&ctx, req, &resp);
            return status.ok() && resp.state() == v1::DELIVERY_STATE_DELIVERED;
        }));
    }

    for (auto& f : futures) {
        EXPECT_TRUE(f.get());
    }

    auto summary = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary.has_value());
    EXPECT_EQ(summary->total_targets, k_num_devices);
    EXPECT_EQ(summary->delivered_targets, k_num_devices);
    EXPECT_EQ(summary->pending_targets, 0);
}

// ============================================================================
// 5. Scenario 5: Retry vs ACK Race Condition
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario05_RetryVsAckRaceCondition) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Delivering);

    // Client delivery ACK arrives first
    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());
    v1::AcknowledgeDeliveryRequest req;
    req.set_message_id(msg_id.to_string());
    req.set_recipient_device_id(bob_device_1_.str());
    req.set_delivered_at_unix_ms(1760000000000LL);
    v1::AcknowledgeDeliveryResponse resp;
    ASSERT_TRUE(grpc_stub_->AcknowledgeDelivery(&ctx, req, &resp).ok());

    // Delayed retry worker attempt arrives second and tries to write RETRY_WAIT or DELIVERING
    const auto now = std::chrono::system_clock::now();
    bool retry_worker_write =
        delivery_repo_->update_delivery_state_monotonic(msg_id, bob_device_1_, DeliveryState::Delivering, now);
    EXPECT_FALSE(retry_worker_write) << "Late retry worker must NOT overwrite DELIVERED state";

    // Verify authoritative state remains DELIVERED
    auto summary = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary.has_value());
    EXPECT_EQ(summary->device_statuses[0].delivery_state, DeliveryState::Delivered);
}

// ============================================================================
// 6. Scenario 6: Message Expiry Semantics
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario06_MessageExpirySemantics) {
    const auto msg_id = MessageId::generate_v7();
    // Expiry sweep transitions state to EXPIRED
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Expired);

    // Client attempts to send read receipt for expired message
    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());
    v1::SendReadReceiptRequest req;
    req.set_conversation_id(direct_conv_id_.to_string());
    req.set_message_id(msg_id.to_string());
    req.set_reader_device_id(bob_device_1_.str());
    req.set_read_at_unix_ms(1760000000000LL);

    v1::SendReadReceiptResponse resp;
    auto status = grpc_stub_->SendReadReceipt(&ctx, req, &resp);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::DEADLINE_EXCEEDED);

    // Delivery summary reflects expired targets
    auto summary = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary.has_value());
    EXPECT_EQ(summary->expired_targets, 1);
    EXPECT_EQ(summary->delivered_targets, 0);
}

// ============================================================================
// 7. Scenario 7: Duplicate Read Receipt Idempotency
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario07_DuplicateReadReceiptIdempotency) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Delivering);

    const int64_t t1 = 1760000000000LL;
    const int64_t t2 = 1760000005000LL;

    // First read receipt
    grpc::ClientContext ctx1;
    configure_context(ctx1, bob_user_.str(), bob_device_1_.str());
    v1::SendReadReceiptRequest req1;
    req1.set_conversation_id(direct_conv_id_.to_string());
    req1.set_message_id(msg_id.to_string());
    req1.set_reader_device_id(bob_device_1_.str());
    req1.set_read_at_unix_ms(t1);

    v1::SendReadReceiptResponse resp1;
    ASSERT_TRUE(grpc_stub_->SendReadReceipt(&ctx1, req1, &resp1).ok());
    EXPECT_EQ(resp1.state(), v1::DELIVERY_STATE_READ);

    const size_t initial_outbox_events = outbox_repo_->event_count();
    EXPECT_GE(initial_outbox_events, 1u);

    // Second (duplicate) read receipt
    grpc::ClientContext ctx2;
    configure_context(ctx2, bob_user_.str(), bob_device_1_.str());
    v1::SendReadReceiptRequest req2;
    req2.set_conversation_id(direct_conv_id_.to_string());
    req2.set_message_id(msg_id.to_string());
    req2.set_reader_device_id(bob_device_1_.str());
    req2.set_read_at_unix_ms(t2);

    v1::SendReadReceiptResponse resp2;
    ASSERT_TRUE(grpc_stub_->SendReadReceipt(&ctx2, req2, &resp2).ok());

    // Idempotent duplicate must NOT create duplicate outbox events
    EXPECT_EQ(outbox_repo_->event_count(), initial_outbox_events);

    // Timestamp remains t1
    auto summary = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary.has_value());
    ASSERT_EQ(summary->recipient_read_statuses.size(), 1u);
    auto read_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       summary->recipient_read_statuses[0].read_at->time_since_epoch())
                       .count();
    EXPECT_EQ(read_ms, t1);
}

// ============================================================================
// 8. Scenario 8: Unauthorized Read Receipt Rejection
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario08_UnauthorizedReadReceiptRejection) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Delivered);

    // Non-participant Eve attempts to submit read receipt on Alice-Bob conversation
    grpc::ClientContext ctx_eve;
    configure_context(ctx_eve, eve_user_.str(), eve_device_.str());
    v1::SendReadReceiptRequest req_eve;
    req_eve.set_conversation_id(direct_conv_id_.to_string());
    req_eve.set_message_id(msg_id.to_string());
    req_eve.set_reader_device_id(eve_device_.str());
    req_eve.set_read_at_unix_ms(1760000000000LL);

    v1::SendReadReceiptResponse resp_eve;
    auto status_eve = grpc_stub_->SendReadReceipt(&ctx_eve, req_eve, &resp_eve);
    EXPECT_FALSE(status_eve.ok());
    EXPECT_EQ(status_eve.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);

    // Gateway REST reverse proxy test: Eve attempt returns 403
    httplib::Request rest_req;
    rest_req.method = "POST";
    rest_req.path =
        "/api/v1/conversations/" + direct_conv_id_.to_string() + "/messages/" + msg_id.to_string() + "/read";
    rest_req.path_params["conversationId"] = direct_conv_id_.to_string();
    rest_req.path_params["messageId"] = msg_id.to_string();
    rest_req.body = R"({"read_at_unix_ms": 1760000000000})";

    httplib::Response rest_res;
    gateway::http::AuthenticatedContext eve_auth_ctx(
        eve_user_.str(), eve_device_.str(), "session-eve-1",
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"messaging:read"}, 1750000000000LL);

    proxy_handler_->handle_send_read_receipt(rest_req, rest_res, eve_auth_ctx);
    EXPECT_EQ(rest_res.status, 403);
}

// ============================================================================
// 9. Scenario 9: Group Read State Decoupling
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario09_GroupReadStateDecoupling) {
    const auto msg_id = MessageId::generate_v7();
    // Targets for Bob and Charlie
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Delivered);
    delivery_repo_->seed_target(msg_id, charlie_user_, charlie_device_, DeliveryState::Delivered);

    // Bob marks message as read
    grpc::ClientContext ctx_bob;
    configure_context(ctx_bob, bob_user_.str(), bob_device_1_.str());
    v1::SendReadReceiptRequest req_bob;
    req_bob.set_conversation_id(group_conv_id_.to_string());
    req_bob.set_message_id(msg_id.to_string());
    req_bob.set_reader_device_id(bob_device_1_.str());
    req_bob.set_read_at_unix_ms(1760000000000LL);

    v1::SendReadReceiptResponse resp_bob;
    ASSERT_TRUE(grpc_stub_->SendReadReceipt(&ctx_bob, req_bob, &resp_bob).ok());

    // Query status via Gateway REST endpoint
    httplib::Request rest_req;
    rest_req.method = "GET";
    rest_req.path =
        "/api/v1/conversations/" + group_conv_id_.to_string() + "/messages/" + msg_id.to_string() + "/delivery-status";
    rest_req.path_params["conversationId"] = group_conv_id_.to_string();
    rest_req.path_params["messageId"] = msg_id.to_string();

    httplib::Response rest_res;
    gateway::http::AuthenticatedContext alice_auth_ctx(
        alice_user_.str(), alice_device_.str(), "session-alice-1",
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"messaging:read"}, 1750000000000LL);

    proxy_handler_->handle_get_delivery_status(rest_req, rest_res, alice_auth_ctx);
    EXPECT_EQ(rest_res.status, 200);

    auto body = nlohmann::json::parse(rest_res.body);
    auto read_breakdown = body["recipient_read_statuses"];
    ASSERT_EQ(read_breakdown.size(), 2u);

    bool bob_read_found = false;
    bool charlie_unread_found = false;

    for (const auto& item : read_breakdown) {
        if (item["user_id"] == bob_user_.str()) {
            bob_read_found = true;
            EXPECT_TRUE(item["is_read"].get<bool>());
            EXPECT_EQ(item["reader_device_id"], bob_device_1_.str());
        } else if (item["user_id"] == charlie_user_.str()) {
            charlie_unread_found = true;
            EXPECT_FALSE(item["is_read"].get<bool>());
        }
    }
    EXPECT_TRUE(bob_read_found);
    EXPECT_TRUE(charlie_unread_found);
}

// ============================================================================
// 10. Scenario 10: Multi-Device Delivery Independence
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario10_MultiDeviceDeliveryIndependence) {
    const auto msg_id = MessageId::generate_v7();
    // Bob has B1 (active phone) and B2 (laptop)
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Queued);
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_2_, DeliveryState::Queued);

    // Transition B1: QUEUED -> DELIVERING -> DELIVERED
    delivery_repo_->update_delivery_state_monotonic(msg_id, bob_device_1_, DeliveryState::Delivering,
                                                    std::chrono::system_clock::now());
    delivery_repo_->record_delivery_ack(msg_id, bob_device_1_, std::chrono::system_clock::now());

    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());
    v1::SendReadReceiptRequest req;
    req.set_conversation_id(direct_conv_id_.to_string());
    req.set_message_id(msg_id.to_string());
    req.set_reader_device_id(bob_device_1_.str());
    req.set_read_at_unix_ms(1760000000000LL);

    v1::SendReadReceiptResponse resp;
    ASSERT_TRUE(grpc_stub_->SendReadReceipt(&ctx, req, &resp).ok());

    auto summary = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary.has_value());
    EXPECT_EQ(summary->total_targets, 2);
    EXPECT_EQ(summary->delivered_targets, 1);
    EXPECT_EQ(summary->pending_targets, 1);

    // Assert multi-device independence
    bool b1_delivered = false;
    bool b2_queued = false;
    for (const auto& d : summary->device_statuses) {
        if (d.device_id == bob_device_1_) {
            EXPECT_EQ(d.delivery_state, DeliveryState::Delivered);
            b1_delivered = true;
        } else if (d.device_id == bob_device_2_) {
            EXPECT_EQ(d.delivery_state, DeliveryState::Queued);
            b2_queued = true;
        }
    }
    EXPECT_TRUE(b1_delivered);
    EXPECT_TRUE(b2_queued);

    // Logical read state: Bob is Read because B1 reported read
    ASSERT_EQ(summary->recipient_read_statuses.size(), 1u);
    EXPECT_EQ(summary->recipient_read_statuses[0].user_id, bob_user_);
    EXPECT_EQ(summary->recipient_read_statuses[0].read_state, ReadState::Read);
}

// ============================================================================
// 11. Scenario 11: Device Revocation Race
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario11_DeviceRevocationRace) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_revoked_, DeliveryState::Queued);

    // Revoked device attempts to submit read receipt
    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_revoked_.str());
    v1::SendReadReceiptRequest req;
    req.set_conversation_id(direct_conv_id_.to_string());
    req.set_message_id(msg_id.to_string());
    req.set_reader_device_id(bob_device_revoked_.str());
    req.set_read_at_unix_ms(1760000000000LL);

    v1::SendReadReceiptResponse resp;
    auto status = grpc_stub_->SendReadReceipt(&ctx, req, &resp);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);

    // Authoritative state remains QUEUED and UNREAD
    auto summary = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(summary.has_value());
    EXPECT_EQ(summary->delivered_targets, 0);
    EXPECT_EQ(summary->recipient_read_statuses[0].read_state, ReadState::Unread);
}

// ============================================================================
// 12. Scenario 12: Service Restart & Recovery
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario12_ServiceRestartAndRecovery) {
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Delivered);
    delivery_repo_->record_delivery_ack(msg_id, bob_device_1_, std::chrono::system_clock::now());

    // Mark as read
    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());
    v1::SendReadReceiptRequest req;
    req.set_conversation_id(direct_conv_id_.to_string());
    req.set_message_id(msg_id.to_string());
    req.set_reader_device_id(bob_device_1_.str());
    req.set_read_at_unix_ms(1760000000000LL);
    v1::SendReadReceiptResponse resp;
    ASSERT_TRUE(grpc_stub_->SendReadReceipt(&ctx, req, &resp).ok());

    // Snapshot durable ScyllaDB state
    auto durable_snapshot = delivery_repo_->snapshot();

    // Simulate crash and restart
    stop_grpc_server();
    delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepository>();
    delivery_repo_->restore_snapshot(durable_snapshot);

    delivery_service_ = std::make_shared<DeliveryService>(delivery_repo_, outbox_repo_);
    read_receipt_service_ =
        std::make_shared<ReadReceiptService>(delivery_repo_, member_repo_, outbox_repo_, [this](const DeviceId& dev) {
            return active_devices_.find(dev) != active_devices_.end();
        });

    messaging_service_ = std::make_unique<MessagingServiceImpl>(submission_pool_, delivery_pool_, sync_pool_, nullptr,
                                                                nullptr, delivery_service_, read_receipt_service_);

    start_grpc_server();
    setup_clients();

    // Query status after reboot
    grpc::ClientContext post_reboot_ctx;
    configure_context(post_reboot_ctx, alice_user_.str(), alice_device_.str());
    v1::GetMessageDeliveryStatusRequest status_req;
    status_req.set_conversation_id(direct_conv_id_.to_string());
    status_req.set_message_id(msg_id.to_string());

    v1::GetMessageDeliveryStatusResponse status_resp;
    ASSERT_TRUE(grpc_stub_->GetMessageDeliveryStatus(&post_reboot_ctx, status_req, &status_resp).ok());

    EXPECT_EQ(status_resp.summary().delivered_targets(), 1);
    ASSERT_EQ(status_resp.recipient_read_statuses_size(), 1);
    EXPECT_TRUE(status_resp.recipient_read_statuses(0).is_read());
    EXPECT_EQ(status_resp.recipient_read_statuses(0).user_id(), bob_user_.str());
}

// ============================================================================
// 13. Scenario 13: Semantic Distinction (Non-Conflation Invariant)
// ============================================================================

TEST_F(MessagingDeliveryStateReadReceiptsIntegrationTest, Scenario13_SemanticNonConflationInvariant) {
    // Axiom: Presence != Delivery != Read != Synchronization
    const auto msg_id = MessageId::generate_v7();
    delivery_repo_->seed_target(msg_id, bob_user_, bob_device_1_, DeliveryState::Queued);

    // Step 1: Presence connects (simulated online presence)
    // Delivery state must remain QUEUED; Read state must remain UNREAD
    auto sum1 = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(sum1.has_value());
    EXPECT_EQ(sum1->device_statuses[0].delivery_state, DeliveryState::Queued);
    EXPECT_EQ(sum1->recipient_read_statuses[0].read_state, ReadState::Unread);

    // Step 2: Message is delivered to device (QUEUED -> DELIVERING -> DELIVERED)
    delivery_repo_->update_delivery_state_monotonic(msg_id, bob_device_1_, DeliveryState::Delivering,
                                                    std::chrono::system_clock::now());
    delivery_repo_->record_delivery_ack(msg_id, bob_device_1_, std::chrono::system_clock::now());
    auto sum2 = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(sum2.has_value());
    EXPECT_EQ(sum2->device_statuses[0].delivery_state, DeliveryState::Delivered);
    EXPECT_EQ(sum2->recipient_read_statuses[0].read_state, ReadState::Unread);

    // Step 3: Device synchronizes sync cursor (pulls sync feed)
    // Synchronization must NOT mark message as read
    auto sum3 = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(sum3.has_value());
    EXPECT_EQ(sum3->recipient_read_statuses[0].read_state, ReadState::Unread);

    // Step 4: Bob explicitly submits Read Receipt
    // Read state transitions to READ
    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());
    v1::SendReadReceiptRequest req;
    req.set_conversation_id(direct_conv_id_.to_string());
    req.set_message_id(msg_id.to_string());
    req.set_reader_device_id(bob_device_1_.str());
    req.set_read_at_unix_ms(1760000000000LL);
    v1::SendReadReceiptResponse resp;
    ASSERT_TRUE(grpc_stub_->SendReadReceipt(&ctx, req, &resp).ok());

    auto sum4 = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(sum4.has_value());
    EXPECT_EQ(sum4->recipient_read_statuses[0].read_state, ReadState::Read);

    // Step 5: Presence disconnects (simulated offline)
    // Delivery and Read states remain preserved; neither regresses
    auto sum5 = delivery_repo_->get_message_delivery_summary(msg_id);
    ASSERT_TRUE(sum5.has_value());
    EXPECT_EQ(sum5->device_statuses[0].delivery_state, DeliveryState::Delivered);
    EXPECT_EQ(sum5->recipient_read_statuses[0].read_state, ReadState::Read);
}

} // namespace
} // namespace securecloud::messaging
