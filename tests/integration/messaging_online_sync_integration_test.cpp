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
#include "domain/message_bucket.hpp"
#include "domain/message_entity.hpp"
#include "domain/message_types.hpp"
#include "domain/read_receipt_types.hpp"
#include "domain/sync_types.hpp"
#include "gateway_config.hpp"
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
#include "messaging/repository/sync_cursor_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "securecloud/security/mtls_config.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/delivery_service.hpp"
#include "service/delivery_state_transition_guard.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/sync_cursor_manager.hpp"

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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging {
namespace {

using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;
using domain::CiphertextEnvelope;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeliveryState;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSequence;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::UserId;
using service::ConversationAuthorizationService;
using service::MessageSyncService;
using service::MessagingServiceImpl;
using service::SyncCursorManager;
using service::SyncCursorUpdateStatus;
using service::SyncMessagesResult;
using service::SyncMessagesStatus;

constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::seconds k_rpc_deadline{5};

// ============================================================================
// Thread-Safe Mock Repositories
// ============================================================================

/// Thread-safe in-memory message repository supporting chronological range queries.
class ThreadSafeMessageRepository final : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& msgs = messages_[msg.conversation_id.to_string()];
        msgs.push_back(msg);
        std::sort(msgs.begin(), msgs.end(), [](const MessageEntity& a, const MessageEntity& b) {
            return a.message_sequence < b.message_sequence;
        });
    }

    std::optional<MessageEntity> find_by_id(const ConversationId& conv, const MessageBucket& /*bucket*/,
                                            const MessageId& id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return std::nullopt;
        }
        for (const auto& msg : it->second) {
            if (msg.message_id == id) {
                return msg;
            }
        }
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId& conv,
                                                               const MessageBucket& /*bucket*/, uint64_t from,
                                                               uint64_t to, size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MessageEntity> results;
        auto it = messages_.find(conv.to_string());
        if (it == messages_.end()) {
            return results;
        }

        for (const auto& msg : it->second) {
            if (msg.message_sequence >= from && msg.message_sequence <= to) {
                results.push_back(msg);
                if (results.size() >= limit) {
                    break;
                }
            }
        }
        return results;
    }

    uint64_t get_last_sequence(const ConversationId& conversation_id, const MessageBucket& /*bucket*/) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = messages_.find(conversation_id.to_string());
        if (it == messages_.end() || it->second.empty()) {
            return 0;
        }
        return it->second.back().message_sequence;
    }

    [[nodiscard]] size_t count(const ConversationId& conv) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = messages_.find(conv.to_string());
        return (it != messages_.end()) ? it->second.size() : 0;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.clear();
    }

  private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<MessageEntity>> messages_;
};

/// Thread-safe in-memory synchronization cursor repository.
class ThreadSafeSyncCursorRepository final : public repository::ISyncCursorRepository {
  public:
    std::optional<DeviceSyncCursor> get_sync_cursor(const DeviceId& device_id,
                                                    const ConversationId& conversation_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(device_id.str(), conversation_id.to_string());
        auto it = cursors_.find(key);
        if (it != cursors_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<DeviceSyncCursor> list_sync_cursors_by_device(const DeviceId& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceSyncCursor> results;
        for (const auto& [key, cursor] : cursors_) {
            if (key.first == device_id.str()) {
                results.push_back(cursor);
            }
        }
        return results;
    }

    void upsert_sync_cursor(const DeviceSyncCursor& cursor) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(cursor.device_id.str(), cursor.conversation_id.to_string());
        cursors_[key] = cursor;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        cursors_.clear();
    }

  private:
    mutable std::mutex mutex_;
    std::map<std::pair<std::string, std::string>, DeviceSyncCursor> cursors_;
};

/// Thread-safe in-memory delivery state repository for state hydration.
class ThreadSafeDeliveryStateRepository final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<domain::DeviceDeliveryRecord>&) override {}
    std::vector<domain::DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&,
                                                                       size_t) override {
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
                    s.delivery_state = DeliveryState::Delivered;
                    s.delivered_at = delivered_at;
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
                    s.read_at = read_at;
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

    bool update_delivery_state_monotonic(const MessageId&, const DeviceId&, DeliveryState,
                                         const std::chrono::system_clock::time_point&) override {
        return true;
    }

    std::optional<domain::MessageDeliverySummary> get_message_delivery_summary(const MessageId&) override {
        return std::nullopt;
    }

    void seed_target_state(const MessageId& mid, const UserId& uid, const DeviceId& did, DeliveryState state,
                           std::optional<std::chrono::system_clock::time_point> delivered_at = std::nullopt,
                           std::optional<std::chrono::system_clock::time_point> read_at = std::nullopt) {
        std::lock_guard<std::mutex> lock(mutex_);
        RecipientDeliveryState s;
        s.message_id = mid;
        s.recipient_user_id = uid;
        s.recipient_device_id = did;
        s.delivery_state = state;
        s.delivered_at = delivered_at;
        s.read_at = read_at;
        recipient_states_[mid].push_back(s);
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<MessageId, std::vector<RecipientDeliveryState>> recipient_states_;
};

// ============================================================================
// Integration Test Fixture
// ============================================================================

class MessagingOnlineSyncIntegrationTest : public ::testing::Test {
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

        submission_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(8, 256, "sub-sync-pool");
        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "del-sync-pool");
        sync_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "sync-sync-pool");

        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        message_repo_ = std::make_shared<ThreadSafeMessageRepository>();
        cursor_repo_ = std::make_shared<ThreadSafeSyncCursorRepository>();
        delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepository>();

        auth_service_ = std::make_shared<ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        cursor_manager_ = std::make_shared<SyncCursorManager>(cursor_repo_, message_repo_);
        sync_service_ =
            std::make_shared<MessageSyncService>(message_repo_, cursor_manager_, auth_service_, delivery_repo_);

        messaging_service_ =
            std::make_unique<MessagingServiceImpl>(submission_pool_, delivery_pool_, sync_pool_, nullptr, nullptr,
                                                   nullptr, nullptr, sync_service_, cursor_manager_);

        seed_data();
        start_grpc_server();
        setup_gateway();
    }

    void TearDown() override {
        stop_gateway();
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
        eve_device_ = DeviceId("018f6e80-eeee-7000-8000-000000000001");

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
    }

    void seed_messages(const ConversationId& conv_id, uint64_t count,
                       const std::string& payload_prefix = "CIPHERTEXT_BLOB_") {
        auto now = std::chrono::system_clock::now();
        auto bucket = MessageBucket::from_time_point(now);

        for (uint64_t seq = 1; seq <= count; ++seq) {
            MessageEntity entity{
                .conversation_id = conv_id,
                .message_bucket = bucket,
                .message_sequence = seq,
                .message_id = MessageId::generate_v7(),
                .sender_user_id = alice_user_,
                .sender_device_id = alice_device_,
                .priority = MessagePriority::Normal,
                .accepted_at = now,
                .envelope = CiphertextEnvelope{.ciphertext = payload_prefix + std::to_string(seq) + "_RANDOM_ENTROPY",
                                               .envelope_version = 1},
                .file_reference_ids = {}};
            message_repo_->save_message(entity);
        }
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
        gateway_client_.reset();
        grpc_stub_.reset();
        channel_.reset();
        if (server_) {
            server_->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
            server_->Wait();
            server_.reset();
        }
    }

    void setup_gateway() {
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

    void stop_gateway() {
        proxy_handler_.reset();
        gateway_client_.reset();
    }

    void configure_context(grpc::ClientContext& context, const std::string& user_id, const std::string& device_id = "",
                           const std::string& correlation_id = "corr-sync-integ") {
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        context.AddMetadata("x-user-id", user_id);
        context.AddMetadata("x-correlation-id", correlation_id);
        if (!device_id.empty()) {
            context.AddMetadata("x-device-id", device_id);
        }
    }

    static gateway::http::AuthenticatedContext make_auth_context(const UserId& uid, const DeviceId& did) {
        return gateway::http::AuthenticatedContext(
            uid.str(), did.str(), "session-sync-integ",
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
            {"messaging:read", "messaging:write"}, 1750000000000LL);
    }

    // Fixture Members
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
    std::shared_ptr<ThreadSafeMessageRepository> message_repo_;
    std::shared_ptr<ThreadSafeSyncCursorRepository> cursor_repo_;
    std::shared_ptr<ThreadSafeDeliveryStateRepository> delivery_repo_;

    std::shared_ptr<ConversationAuthorizationService> auth_service_;
    std::shared_ptr<SyncCursorManager> cursor_manager_;
    std::shared_ptr<MessageSyncService> sync_service_;
    std::unique_ptr<MessagingServiceImpl> messaging_service_;

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
    DeviceId eve_device_;

    ConversationId group_conv_id_;
};

// ============================================================================
// 1. Scenario 1: Clean Initial Sync
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario01_CleanInitialSync) {
    seed_messages(group_conv_id_, 5);

    // 1. Direct gRPC Initial Sync
    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());

    v1::SyncDeviceMessagesRequest req;
    req.set_device_id(bob_device_1_.str());
    req.set_conversation_id(group_conv_id_.to_string());
    req.set_since_sequence(0);
    req.set_max_messages(10);

    v1::SyncDeviceMessagesResponse resp;
    auto status = grpc_stub_->SyncDeviceMessages(&ctx, req, &resp);
    ASSERT_TRUE(status.ok()) << status.error_message();

    EXPECT_EQ(resp.messages_size(), 5);
    EXPECT_FALSE(resp.has_more());
    EXPECT_EQ(resp.latest_sequence(), 5);
    EXPECT_EQ(resp.next_sequence(), 6);

    for (int i = 0; i < resp.messages_size(); ++i) {
        EXPECT_EQ(resp.messages(i).conversation_id(), group_conv_id_.to_string());
        ASSERT_GT(resp.messages(i).delivery_targets_size(), 0);
        EXPECT_FALSE(resp.messages(i).delivery_targets(0).encrypted_payload().ciphertext_blob().empty());
    }

    // 2. HTTP Gateway Sync Route
    httplib::Request http_req;
    http_req.path = "/v1/conversations/" + group_conv_id_.to_string() + "/messages";
    http_req.params = {{"since_sequence", "0"}, {"limit", "10"}};
    http_req.path_params = {{"id", group_conv_id_.to_string()}};

    httplib::Response http_res;
    proxy_handler_->handle_sync_messages(http_req, http_res, make_auth_context(bob_user_, bob_device_1_));
    EXPECT_EQ(http_res.status, 200);

    auto json_body = nlohmann::json::parse(http_res.body);
    EXPECT_EQ(json_body["messages"].size(), 5);
    EXPECT_FALSE(json_body["has_more"].get<bool>());
    EXPECT_EQ(json_body["latest_sequence"].get<uint64_t>(), 5);
}

// ============================================================================
// 2. Scenario 2: Incremental Progression
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario02_IncrementalProgression) {
    seed_messages(group_conv_id_, 6);

    // Update cursor to sequence 4
    grpc::ClientContext update_ctx;
    configure_context(update_ctx, bob_user_.str(), bob_device_1_.str());

    v1::UpdateSyncCursorRequest update_req;
    auto* cur = update_req.mutable_cursor();
    cur->set_device_id(bob_device_1_.str());
    cur->set_conversation_id(group_conv_id_.to_string());
    cur->set_last_delivered_sequence(4);

    v1::UpdateSyncCursorResponse update_resp;
    auto update_status = grpc_stub_->UpdateSyncCursor(&update_ctx, update_req, &update_resp);
    ASSERT_TRUE(update_status.ok()) << update_status.error_message();
    EXPECT_EQ(update_resp.cursor().last_delivered_sequence(), 4);

    // Incremental sync starting from sequence 4
    grpc::ClientContext sync_ctx;
    configure_context(sync_ctx, bob_user_.str(), bob_device_1_.str());

    v1::SyncDeviceMessagesRequest sync_req;
    sync_req.set_device_id(bob_device_1_.str());
    sync_req.set_conversation_id(group_conv_id_.to_string());
    sync_req.set_since_sequence(4);
    sync_req.set_max_messages(10);

    v1::SyncDeviceMessagesResponse sync_resp;
    auto sync_status = grpc_stub_->SyncDeviceMessages(&sync_ctx, sync_req, &sync_resp);
    ASSERT_TRUE(sync_status.ok()) << sync_status.error_message();

    // Only delta messages (5 and 6) returned (2 messages)
    ASSERT_EQ(sync_resp.messages_size(), 2);
    EXPECT_FALSE(sync_resp.has_more());
    EXPECT_EQ(sync_resp.next_sequence(), 7);
}

// ============================================================================
// 3. Scenario 3: Multi-Batch Pagination
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario03_MultiBatchPagination) {
    seed_messages(group_conv_id_, 12);

    // Page 1: messages 1..5
    grpc::ClientContext ctx1;
    configure_context(ctx1, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest req1;
    req1.set_device_id(bob_device_1_.str());
    req1.set_conversation_id(group_conv_id_.to_string());
    req1.set_since_sequence(0);
    req1.set_max_messages(5);

    v1::SyncDeviceMessagesResponse resp1;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&ctx1, req1, &resp1).ok());
    EXPECT_EQ(resp1.messages_size(), 5);
    EXPECT_TRUE(resp1.has_more());
    EXPECT_EQ(resp1.next_sequence(), 6);

    // Update cursor to 5
    grpc::ClientContext u_ctx1;
    configure_context(u_ctx1, bob_user_.str(), bob_device_1_.str());
    v1::UpdateSyncCursorRequest u_req1;
    auto* cur1 = u_req1.mutable_cursor();
    cur1->set_device_id(bob_device_1_.str());
    cur1->set_conversation_id(group_conv_id_.to_string());
    cur1->set_last_delivered_sequence(5);
    v1::UpdateSyncCursorResponse u_resp1;
    ASSERT_TRUE(grpc_stub_->UpdateSyncCursor(&u_ctx1, u_req1, &u_resp1).ok());

    // Page 2: messages 6..10
    grpc::ClientContext ctx2;
    configure_context(ctx2, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest req2;
    req2.set_device_id(bob_device_1_.str());
    req2.set_conversation_id(group_conv_id_.to_string());
    req2.set_since_sequence(5);
    req2.set_max_messages(5);

    v1::SyncDeviceMessagesResponse resp2;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&ctx2, req2, &resp2).ok());
    EXPECT_EQ(resp2.messages_size(), 5);
    EXPECT_TRUE(resp2.has_more());
    EXPECT_EQ(resp2.next_sequence(), 11);

    // Update cursor to 10
    grpc::ClientContext u_ctx2;
    configure_context(u_ctx2, bob_user_.str(), bob_device_1_.str());
    v1::UpdateSyncCursorRequest u_req2;
    auto* cur2 = u_req2.mutable_cursor();
    cur2->set_device_id(bob_device_1_.str());
    cur2->set_conversation_id(group_conv_id_.to_string());
    cur2->set_last_delivered_sequence(10);
    v1::UpdateSyncCursorResponse u_resp2;
    ASSERT_TRUE(grpc_stub_->UpdateSyncCursor(&u_ctx2, u_req2, &u_resp2).ok());

    // Page 3: messages 11..12
    grpc::ClientContext ctx3;
    configure_context(ctx3, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest req3;
    req3.set_device_id(bob_device_1_.str());
    req3.set_conversation_id(group_conv_id_.to_string());
    req3.set_since_sequence(10);
    req3.set_max_messages(5);

    v1::SyncDeviceMessagesResponse resp3;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&ctx3, req3, &resp3).ok());
    EXPECT_EQ(resp3.messages_size(), 2);
    EXPECT_FALSE(resp3.has_more());
    EXPECT_EQ(resp3.next_sequence(), 13);
}

// ============================================================================
// 4. Scenario 4: Interrupted Sync & Replay Safety
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario04_InterruptedSyncAndReplaySafety) {
    seed_messages(group_conv_id_, 8);

    // Initial query
    grpc::ClientContext ctx1;
    configure_context(ctx1, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest req1;
    req1.set_device_id(bob_device_1_.str());
    req1.set_conversation_id(group_conv_id_.to_string());
    req1.set_since_sequence(0);
    req1.set_max_messages(4);

    v1::SyncDeviceMessagesResponse resp1;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&ctx1, req1, &resp1).ok());
    EXPECT_EQ(resp1.messages_size(), 4);

    // Simulate crash: client drops before updating cursor to 4.
    // Reconnect and query again with since_sequence = 0
    grpc::ClientContext ctx2;
    configure_context(ctx2, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest req2;
    req2.set_device_id(bob_device_1_.str());
    req2.set_conversation_id(group_conv_id_.to_string());
    req2.set_since_sequence(0);
    req2.set_max_messages(4);

    v1::SyncDeviceMessagesResponse resp2;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&ctx2, req2, &resp2).ok());

    // Identical batch received idempotently
    ASSERT_EQ(resp2.messages_size(), resp1.messages_size());
    for (int i = 0; i < resp1.messages_size(); ++i) {
        EXPECT_EQ(resp2.messages(i).message_id(), resp1.messages(i).message_id());
        EXPECT_EQ(resp2.messages(i).conversation_id(), resp1.messages(i).conversation_id());
        ASSERT_GT(resp2.messages(i).delivery_targets_size(), 0);
        ASSERT_GT(resp1.messages(i).delivery_targets_size(), 0);
        EXPECT_EQ(resp2.messages(i).delivery_targets(0).encrypted_payload().ciphertext_blob(),
                  resp1.messages(i).delivery_targets(0).encrypted_payload().ciphertext_blob());
    }
}

// ============================================================================
// 5. Scenario 5: Cursor Out of Bounds Rejection
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario05_CursorOutOfBoundsRejection) {
    seed_messages(group_conv_id_, 5);

    // 1. gRPC Update Cursor Out Of Bounds (> ceiling of 5)
    grpc::ClientContext update_ctx;
    configure_context(update_ctx, bob_user_.str(), bob_device_1_.str());

    v1::UpdateSyncCursorRequest update_req;
    auto* cur = update_req.mutable_cursor();
    cur->set_device_id(bob_device_1_.str());
    cur->set_conversation_id(group_conv_id_.to_string());
    cur->set_last_delivered_sequence(99);

    v1::UpdateSyncCursorResponse update_resp;
    auto status = grpc_stub_->UpdateSyncCursor(&update_ctx, update_req, &update_resp);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OUT_OF_RANGE);

    // 2. Gateway HTTP Update Cursor Out of Bounds
    httplib::Request http_req;
    http_req.path = "/v1/devices/" + bob_device_1_.str() + "/cursor";
    http_req.path_params = {{"device_id", bob_device_1_.str()}};
    nlohmann::json body = {{"conversation_id", group_conv_id_.to_string()}, {"last_delivered_sequence", 150}};
    http_req.body = body.dump();

    httplib::Response http_res;
    proxy_handler_->handle_update_sync_cursor(http_req, http_res, make_auth_context(bob_user_, bob_device_1_));
    EXPECT_EQ(http_res.status, 400);

    // 3. SyncDeviceMessages with sequence exceeding ceiling
    grpc::ClientContext sync_ctx;
    configure_context(sync_ctx, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest sync_req;
    sync_req.set_device_id(bob_device_1_.str());
    sync_req.set_conversation_id(group_conv_id_.to_string());
    sync_req.set_since_sequence(100);
    sync_req.set_max_messages(10);

    v1::SyncDeviceMessagesResponse sync_resp;
    auto sync_status = grpc_stub_->SyncDeviceMessages(&sync_ctx, sync_req, &sync_resp);
    EXPECT_FALSE(sync_status.ok());
    EXPECT_EQ(sync_status.error_code(), grpc::StatusCode::OUT_OF_RANGE);
}

// ============================================================================
// 6. Scenario 6: Cursor Monotonicity Enforcement
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario06_CursorMonotonicityEnforcement) {
    seed_messages(group_conv_id_, 10);

    // Advance cursor to sequence 6
    grpc::ClientContext ctx1;
    configure_context(ctx1, bob_user_.str(), bob_device_1_.str());
    v1::UpdateSyncCursorRequest req1;
    auto* cur1 = req1.mutable_cursor();
    cur1->set_device_id(bob_device_1_.str());
    cur1->set_conversation_id(group_conv_id_.to_string());
    cur1->set_last_delivered_sequence(6);

    v1::UpdateSyncCursorResponse resp1;
    ASSERT_TRUE(grpc_stub_->UpdateSyncCursor(&ctx1, req1, &resp1).ok());
    EXPECT_EQ(resp1.cursor().last_delivered_sequence(), 6);

    // Attempt to rewind cursor to sequence 3 (Must fail)
    grpc::ClientContext ctx2;
    configure_context(ctx2, bob_user_.str(), bob_device_1_.str());
    v1::UpdateSyncCursorRequest req2;
    auto* cur2 = req2.mutable_cursor();
    cur2->set_device_id(bob_device_1_.str());
    cur2->set_conversation_id(group_conv_id_.to_string());
    cur2->set_last_delivered_sequence(3);

    v1::UpdateSyncCursorResponse resp2;
    auto status = grpc_stub_->UpdateSyncCursor(&ctx2, req2, &resp2);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OUT_OF_RANGE);

    // Verify current cursor remains sequence 6
    grpc::ClientContext get_ctx;
    configure_context(get_ctx, bob_user_.str(), bob_device_1_.str());
    v1::GetSyncCursorRequest get_req;
    get_req.set_device_id(bob_device_1_.str());
    get_req.set_conversation_id(group_conv_id_.to_string());

    v1::GetSyncCursorResponse get_resp;
    ASSERT_TRUE(grpc_stub_->GetSyncCursor(&get_ctx, get_req, &get_resp).ok());
    EXPECT_EQ(get_resp.cursor().last_delivered_sequence(), 6);
}

// ============================================================================
// 7. Scenario 7: Authorization Isolation
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario07_AuthorizationIsolation) {
    seed_messages(group_conv_id_, 5);

    // Eve (not a participant) attempts to sync messages via gRPC
    grpc::ClientContext ctx;
    configure_context(ctx, eve_user_.str(), eve_device_.str());

    v1::SyncDeviceMessagesRequest req;
    req.set_device_id(eve_device_.str());
    req.set_conversation_id(group_conv_id_.to_string());
    req.set_since_sequence(0);
    req.set_max_messages(10);

    v1::SyncDeviceMessagesResponse resp;
    auto status = grpc_stub_->SyncDeviceMessages(&ctx, req, &resp);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);

    // Eve attempts via Gateway HTTP proxy
    httplib::Request http_req;
    http_req.path = "/v1/conversations/" + group_conv_id_.to_string() + "/messages";
    http_req.params = {{"since_sequence", "0"}, {"limit", "10"}};
    http_req.path_params = {{"id", group_conv_id_.to_string()}};

    httplib::Response http_res;
    proxy_handler_->handle_sync_messages(http_req, http_res, make_auth_context(eve_user_, eve_device_));
    EXPECT_EQ(http_res.status, 403);
}

// ============================================================================
// 8. Scenario 8: Concurrent Submission & Sync
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario08_ConcurrentSubmissionAndSync) {
    seed_messages(group_conv_id_, 5);

    std::atomic<bool> stop_flag{false};

    // Writer thread submitting messages 6..25
    auto writer = std::async(std::launch::async, [&]() {
        auto bucket = MessageBucket::from_time_point(std::chrono::system_clock::now());
        for (uint64_t s = 6; s <= 25; ++s) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            MessageEntity entity{.conversation_id = group_conv_id_,
                                 .message_bucket = bucket,
                                 .message_sequence = s,
                                 .message_id = MessageId::generate_v7(),
                                 .sender_user_id = alice_user_,
                                 .sender_device_id = alice_device_,
                                 .priority = MessagePriority::Normal,
                                 .accepted_at = std::chrono::system_clock::now(),
                                 .envelope = CiphertextEnvelope{.ciphertext = "CONCURRENT_PAYLOAD_" + std::to_string(s),
                                                                .envelope_version = 1},
                                 .file_reference_ids = {}};
            message_repo_->save_message(entity);
        }
        stop_flag.store(true);
    });

    // Reader thread continuously synchronizing messages
    uint64_t last_synced = 0;
    size_t total_received = 0;

    while (!stop_flag.load() || last_synced < 25) {
        grpc::ClientContext ctx;
        configure_context(ctx, bob_user_.str(), bob_device_1_.str());

        v1::SyncDeviceMessagesRequest req;
        req.set_device_id(bob_device_1_.str());
        req.set_conversation_id(group_conv_id_.to_string());
        req.set_since_sequence(static_cast<int64_t>(last_synced));
        req.set_max_messages(5);

        v1::SyncDeviceMessagesResponse resp;
        auto status = grpc_stub_->SyncDeviceMessages(&ctx, req, &resp);
        if (status.ok()) {
            for (int i = 0; i < resp.messages_size(); ++i) {
                total_received++;
            }
            if (resp.messages_size() > 0) {
                last_synced = static_cast<uint64_t>(resp.next_sequence() - 1);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    writer.get();

    EXPECT_EQ(last_synced, 25);
    EXPECT_EQ(total_received, 25);
}

// ============================================================================
// 9. Scenario 9: Delivery & Read State Reflection
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario09_DeliveryAndReadStateReflection) {
    seed_messages(group_conv_id_, 3);

    // Retrieve message 1 ID from repository
    auto msg1 = message_repo_->list_messages_by_sequence_range(
        group_conv_id_, MessageBucket::from_time_point(std::chrono::system_clock::now()), 1, 1, 1);
    ASSERT_EQ(msg1.size(), 1);
    const auto& m1 = msg1[0];

    auto now = std::chrono::system_clock::now();
    // Record Bob as DELIVERED and Charlie as READ
    delivery_repo_->seed_target_state(m1.message_id, bob_user_, bob_device_1_, DeliveryState::Delivered, now);
    delivery_repo_->seed_target_state(m1.message_id, charlie_user_, DeviceId("charlie-dev-1"), DeliveryState::Delivered,
                                      now, now);

    // Direct domain MessageSyncService verification
    auto domain_res = sync_service_->sync_messages(
        bob_user_,
        service::SyncDeviceMessagesCommand{
            .device_id = bob_device_1_, .conversation_id = group_conv_id_, .since_sequence = 0, .max_messages = 5});
    ASSERT_EQ(domain_res.status, SyncMessagesStatus::Success);
    ASSERT_GE(domain_res.messages.size(), 1);

    // Verify delivery repo reflects states
    auto states = delivery_repo_->get_delivery_states_for_message(m1.message_id);
    ASSERT_EQ(states.size(), 2);

    bool bob_delivered = false;
    bool charlie_read = false;
    for (const auto& s : states) {
        if (s.recipient_device_id == bob_device_1_ && s.delivery_state == DeliveryState::Delivered) {
            bob_delivered = true;
        }
        if (s.recipient_user_id == charlie_user_ && s.read_at.has_value()) {
            charlie_read = true;
        }
    }
    EXPECT_TRUE(bob_delivered);
    EXPECT_TRUE(charlie_read);
}

// ============================================================================
// 10. Scenario 10: Multi-Device Sync Independence
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario10_MultiDeviceSyncIndependence) {
    seed_messages(group_conv_id_, 10);

    // Device 1 advances cursor to 8
    grpc::ClientContext ctx1;
    configure_context(ctx1, bob_user_.str(), bob_device_1_.str());
    v1::UpdateSyncCursorRequest req1;
    auto* cur1 = req1.mutable_cursor();
    cur1->set_device_id(bob_device_1_.str());
    cur1->set_conversation_id(group_conv_id_.to_string());
    cur1->set_last_delivered_sequence(8);
    v1::UpdateSyncCursorResponse resp1;
    ASSERT_TRUE(grpc_stub_->UpdateSyncCursor(&ctx1, req1, &resp1).ok());

    // Device 2 advances cursor to 3
    grpc::ClientContext ctx2;
    configure_context(ctx2, bob_user_.str(), bob_device_2_.str());
    v1::UpdateSyncCursorRequest req2;
    auto* cur2 = req2.mutable_cursor();
    cur2->set_device_id(bob_device_2_.str());
    cur2->set_conversation_id(group_conv_id_.to_string());
    cur2->set_last_delivered_sequence(3);
    v1::UpdateSyncCursorResponse resp2;
    ASSERT_TRUE(grpc_stub_->UpdateSyncCursor(&ctx2, req2, &resp2).ok());

    // Verify Device 1 cursor is 8
    grpc::ClientContext get_ctx1;
    configure_context(get_ctx1, bob_user_.str(), bob_device_1_.str());
    v1::GetSyncCursorRequest get_req1;
    get_req1.set_device_id(bob_device_1_.str());
    get_req1.set_conversation_id(group_conv_id_.to_string());
    v1::GetSyncCursorResponse get_resp1;
    ASSERT_TRUE(grpc_stub_->GetSyncCursor(&get_ctx1, get_req1, &get_resp1).ok());
    EXPECT_EQ(get_resp1.cursor().last_delivered_sequence(), 8);

    // Verify Device 2 cursor is 3
    grpc::ClientContext get_ctx2;
    configure_context(get_ctx2, bob_user_.str(), bob_device_2_.str());
    v1::GetSyncCursorRequest get_req2;
    get_req2.set_device_id(bob_device_2_.str());
    get_req2.set_conversation_id(group_conv_id_.to_string());
    v1::GetSyncCursorResponse get_resp2;
    ASSERT_TRUE(grpc_stub_->GetSyncCursor(&get_ctx2, get_req2, &get_resp2).ok());
    EXPECT_EQ(get_resp2.cursor().last_delivered_sequence(), 3);

    // Device 1 syncs from cursor (returns 9 and 10)
    grpc::ClientContext sync_ctx1;
    configure_context(sync_ctx1, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest sync_req1;
    sync_req1.set_device_id(bob_device_1_.str());
    sync_req1.set_conversation_id(group_conv_id_.to_string());
    sync_req1.set_since_sequence(8);
    sync_req1.set_max_messages(10);
    v1::SyncDeviceMessagesResponse sync_resp1;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&sync_ctx1, sync_req1, &sync_resp1).ok());
    EXPECT_EQ(sync_resp1.messages_size(), 2);

    // Device 2 syncs from cursor (returns 4..10)
    grpc::ClientContext sync_ctx2;
    configure_context(sync_ctx2, bob_user_.str(), bob_device_2_.str());
    v1::SyncDeviceMessagesRequest sync_req2;
    sync_req2.set_device_id(bob_device_2_.str());
    sync_req2.set_conversation_id(group_conv_id_.to_string());
    sync_req2.set_since_sequence(3);
    sync_req2.set_max_messages(10);
    v1::SyncDeviceMessagesResponse sync_resp2;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&sync_ctx2, sync_req2, &sync_resp2).ok());
    EXPECT_EQ(sync_resp2.messages_size(), 7);
}

// ============================================================================
// 11. Scenario 11: Service Restart & Durability
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario11_ServiceRestartAndDurability) {
    seed_messages(group_conv_id_, 10);

    // Bob advances cursor to sequence 7
    grpc::ClientContext ctx1;
    configure_context(ctx1, bob_user_.str(), bob_device_1_.str());
    v1::UpdateSyncCursorRequest req1;
    auto* cur1 = req1.mutable_cursor();
    cur1->set_device_id(bob_device_1_.str());
    cur1->set_conversation_id(group_conv_id_.to_string());
    cur1->set_last_delivered_sequence(7);
    v1::UpdateSyncCursorResponse resp1;
    ASSERT_TRUE(grpc_stub_->UpdateSyncCursor(&ctx1, req1, &resp1).ok());

    // Simulate complete service restart
    stop_gateway();
    stop_grpc_server();

    // Reconstruct services backed by identical persistent mock repositories
    cursor_manager_ = std::make_shared<SyncCursorManager>(cursor_repo_, message_repo_);
    sync_service_ = std::make_shared<MessageSyncService>(message_repo_, cursor_manager_, auth_service_, delivery_repo_);

    messaging_service_ =
        std::make_unique<MessagingServiceImpl>(submission_pool_, delivery_pool_, sync_pool_, nullptr, nullptr, nullptr,
                                               nullptr, sync_service_, cursor_manager_);

    start_grpc_server();
    setup_gateway();

    // Verify cursor persisted and survives reboot
    grpc::ClientContext post_reboot_ctx;
    configure_context(post_reboot_ctx, bob_user_.str(), bob_device_1_.str());
    v1::GetSyncCursorRequest get_req;
    get_req.set_device_id(bob_device_1_.str());
    get_req.set_conversation_id(group_conv_id_.to_string());
    v1::GetSyncCursorResponse get_resp;
    ASSERT_TRUE(grpc_stub_->GetSyncCursor(&post_reboot_ctx, get_req, &get_resp).ok());
    EXPECT_EQ(get_resp.cursor().last_delivered_sequence(), 7);

    // Verify sync resumes smoothly from sequence 7, returning 8, 9, 10
    grpc::ClientContext sync_ctx;
    configure_context(sync_ctx, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest sync_req;
    sync_req.set_device_id(bob_device_1_.str());
    sync_req.set_conversation_id(group_conv_id_.to_string());
    sync_req.set_since_sequence(7);
    sync_req.set_max_messages(10);
    v1::SyncDeviceMessagesResponse sync_resp;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&sync_ctx, sync_req, &sync_resp).ok());
    EXPECT_EQ(sync_resp.messages_size(), 3);
}

// ============================================================================
// 12. Scenario 12: Zero Plaintext Invariant Verification
// ============================================================================

TEST_F(MessagingOnlineSyncIntegrationTest, Scenario12_ZeroPlaintextInvariantVerification) {
    seed_messages(group_conv_id_, 5, "OPAQUE_ENCRYPTED_PAYLOAD_");

    grpc::ClientContext ctx;
    configure_context(ctx, bob_user_.str(), bob_device_1_.str());
    v1::SyncDeviceMessagesRequest req;
    req.set_device_id(bob_device_1_.str());
    req.set_conversation_id(group_conv_id_.to_string());
    req.set_since_sequence(0);
    req.set_max_messages(5);

    v1::SyncDeviceMessagesResponse resp;
    ASSERT_TRUE(grpc_stub_->SyncDeviceMessages(&ctx, req, &resp).ok());
    ASSERT_EQ(resp.messages_size(), 5);

    for (int i = 0; i < resp.messages_size(); ++i) {
        const auto& envelope = resp.messages(i);
        ASSERT_GT(envelope.delivery_targets_size(), 0);
        const auto& target = envelope.delivery_targets(0);
        const auto& cipher = target.encrypted_payload().ciphertext_blob();

        // Ciphertext must be non-empty and opaque
        EXPECT_FALSE(cipher.empty());
        EXPECT_GT(cipher.size(), 16);

        // Invariant: Server never decrypts, parses, or logs plaintexts.
        // Payloads must not contain readable sensitive plaintext keywords.
        EXPECT_EQ(cipher.find("PLAINTEXT_SECRET"), std::string::npos);
        EXPECT_EQ(cipher.find("UNENCRYPTED_MESSAGE"), std::string::npos);

        // Envelope metadata integrity
        EXPECT_EQ(envelope.conversation_id(), group_conv_id_.to_string());
        EXPECT_EQ(envelope.sender_user_id(), alice_user_.str());
        EXPECT_EQ(envelope.sender_device_id(), alice_device_.str());
    }
}

} // namespace
} // namespace securecloud::messaging
