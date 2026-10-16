#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "concurrency/bounded_worker_pool.hpp"
#include "domain/conversation_types.hpp"
#include "domain/message_entity.hpp"
#include "domain/submission_types.hpp"
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
#include "messaging/repository/idempotency_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "messaging_config.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "securecloud/security/mtls_config.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/idempotency_guard.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/messaging_error_mapper.hpp"
#include "service/messaging_service_impl.hpp"

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
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace grpc::testing {

class ServerContextTestSpouse {
  public:
    explicit ServerContextTestSpouse(::grpc::ServerContext* ctx) : ctx_(ctx) {}

    void add_client_metadata(const std::string& key, const std::string& val) {
        stored_strings_.push_back(key);
        stored_strings_.push_back(val);
        const auto& k = stored_strings_[stored_strings_.size() - 2];
        const auto& v = stored_strings_.back();
        ctx_->client_metadata_.map()->insert(
            std::make_pair(::grpc::string_ref(k.data(), k.size()), ::grpc::string_ref(v.data(), v.size())));
    }

  private:
    ::grpc::ServerContext* ctx_;
    std::deque<std::string> stored_strings_;
};

} // namespace grpc::testing

namespace securecloud::messaging {
namespace {

using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::GroupMetadataEntity;
using domain::GroupStatus;
using domain::IdempotencyRecord;

using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::SubmissionStatus;
using domain::UserId;
using service::MessageSubmissionIdempotencyGuard;
using service::MessageSubmissionService;
using service::MessagingServiceImpl;

constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::seconds k_rpc_deadline{5};

// ============================================================================
// Thread-Safe Mock Repositories
// ============================================================================

class ThreadSafeMessageRepository : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_messages_.push_back(msg);
    }

    std::optional<MessageEntity> find_by_id(const ConversationId&, const MessageBucket&, const MessageId&) override {
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId&, const MessageBucket&, uint64_t,
                                                               uint64_t, size_t) override {
        return {};
    }

    uint64_t get_last_sequence(const ConversationId&, const MessageBucket&) override { return 0; }

    size_t count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_messages_.size();
    }

    std::vector<MessageEntity> all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_messages_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<MessageEntity> saved_messages_;
};

class ThreadSafeDeliveryStateRepository : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_pending_.insert(saved_pending_.end(), records.begin(), records.end());
    }

    std::vector<DeviceDeliveryRecord> fetch_pending_for_device(const DeviceId&, const std::string&, size_t) override {
        return {};
    }

    void update_device_delivery_status(const DeviceId&, const std::string&,
                                       const std::chrono::system_clock::time_point&, const MessageId&,
                                       domain::DeliveryState, int32_t,
                                       std::optional<std::chrono::system_clock::time_point>) override {}

    void save_recipient_delivery_states(const std::vector<RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_recipient_states_.insert(saved_recipient_states_.end(), states.begin(), states.end());
    }

    void record_delivery_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {
    }
    void record_read_ack(const MessageId&, const DeviceId&, const std::chrono::system_clock::time_point&) override {}
    std::vector<RecipientDeliveryState> get_delivery_states_for_message(const MessageId&) override { return {}; }

    size_t pending_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_pending_.size();
    }

  private:
    mutable std::mutex mutex_;
    std::vector<DeviceDeliveryRecord> saved_pending_;
    std::vector<RecipientDeliveryState> saved_recipient_states_;
};

class ThreadSafeOutboxRepository : public repository::IOutboxRepository {
  public:
    void enqueue_event(const ConversationOutboxEvent& event, const std::string&) override {
        std::lock_guard<std::mutex> lock(mutex_);
        enqueued_events_.push_back(event);
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string&, size_t) override { return {}; }
    void mark_event_published(const std::string&, std::chrono::system_clock::time_point, const std::string&,
                              std::chrono::system_clock::time_point) override {}

    size_t count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enqueued_events_.size();
    }

    std::vector<ConversationOutboxEvent> all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enqueued_events_;
    }

  private:
    mutable std::mutex mutex_;
    std::vector<ConversationOutboxEvent> enqueued_events_;
};

class ThreadSafeIdempotencyRepository : public repository::IIdempotencyRepository {
  public:
    std::optional<IdempotencyRecord> find_submission(const DeviceId& sender_device_id,
                                                     const std::string& idempotency_key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = sender_device_id.str() + ":" + idempotency_key;
        auto it = records_.find(key);
        if (it != records_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void save_submission(const IdempotencyRecord& record) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = record.sender_device_id.str() + ":" + record.idempotency_key;
        records_[key] = record;
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, IdempotencyRecord> records_;
};

// ============================================================================
// Integration Test Fixture
// ============================================================================

class MessagingSubmissionIntegrationTest : public ::testing::Test {
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
        auth_service_ = std::make_shared<service::ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        sequence_allocator_ = std::make_shared<service::InMemorySequenceAllocator>();
        idempotency_repo_ = std::make_shared<ThreadSafeIdempotencyRepository>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        message_repo_ = std::make_shared<ThreadSafeMessageRepository>();
        delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<ThreadSafeOutboxRepository>();

        submission_service_ = std::make_shared<MessageSubmissionService>(
            auth_service_, sequence_allocator_, idempotency_guard_, message_repo_, delivery_repo_, outbox_repo_);

        messaging_service_ = std::make_unique<MessagingServiceImpl>(submission_pool_, delivery_pool_, sync_pool_,
                                                                    nullptr, submission_service_);

        seed_data();
        start_server();
        setup_clients();
    }

    void TearDown() override {
        stop_server();
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
        alice_user_ = UserId("018d0000-0000-7000-8000-000000000001");
        bob_user_ = UserId("018d0000-0000-7000-8000-000000000002");
        charlie_user_ = UserId("018d0000-0000-7000-8000-000000000003");
        eve_user_ = UserId("018d0000-0000-7000-8000-000000000004");

        alice_device_ = DeviceId("018d0000-0000-7000-8000-000000000011");
        bob_device_1_ = DeviceId("018d0000-0000-7000-8000-000000000021");
        bob_device_2_ = DeviceId("018d0000-0000-7000-8000-000000000022");
        charlie_device_ = DeviceId("018d0000-0000-7000-8000-000000000031");
        eve_device_ = DeviceId("018d0000-0000-7000-8000-000000000041");

        // 1. Direct conversation between Alice and Bob
        direct_conv_id_ = ConversationId::generate_v7();
        ConversationEntity direct_conv{direct_conv_id_, ConversationType::Direct, alice_user_};
        conv_repo_->save_conversation(direct_conv);

        auto now = std::chrono::system_clock::now();
        ConversationParticipantEntity p_alice{direct_conv_id_, alice_user_, ParticipantRole::Member,
                                              MembershipStatus::Active, now};
        ConversationParticipantEntity p_bob{direct_conv_id_, bob_user_, ParticipantRole::Member,
                                            MembershipStatus::Active, now};
        member_repo_->add_participant(p_alice);
        member_repo_->add_participant(p_bob);

        // 2. Active group conversation with Alice, Bob, Charlie
        active_group_id_ = ConversationId::generate_v7();
        ConversationEntity active_group{active_group_id_, ConversationType::Group, alice_user_};
        conv_repo_->save_conversation(active_group);

        member_repo_->add_participant(
            {active_group_id_, alice_user_, ParticipantRole::Admin, MembershipStatus::Active, now});
        member_repo_->add_participant(
            {active_group_id_, bob_user_, ParticipantRole::Member, MembershipStatus::Active, now});
        member_repo_->add_participant(
            {active_group_id_, charlie_user_, ParticipantRole::Member, MembershipStatus::Active, now});

        // 3. Closed group conversation
        closed_group_id_ = ConversationId::generate_v7();
        ConversationEntity closed_group{closed_group_id_, ConversationType::Group, alice_user_};
        conv_repo_->save_conversation(closed_group);
        conv_repo_->save_group_metadata(GroupMetadataEntity{
            .conversation_id = closed_group_id_,
            .title = "Closed Group",
            .status = GroupStatus::Closed,
            .created_at = now,
            .updated_at = now,
            .metadata_version = 1,
        });

        member_repo_->add_participant(
            {closed_group_id_, alice_user_, ParticipantRole::Admin, MembershipStatus::Active, now});
    }

    void start_server() {
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

    void stop_server() {
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
                           const std::string& correlation_id = "corr-sub-integ", const std::string& token = "") {
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        context.AddMetadata("x-user-id", user_id);
        context.AddMetadata("x-correlation-id", correlation_id);
        if (!device_id.empty()) {
            context.AddMetadata("x-device-id", device_id);
        }
        if (!token.empty()) {
            context.AddMetadata("x-idempotency-token", token);
        }
    }

    v1::SendMessageRequest build_direct_request(const std::string& token = "tok-integ-default-1") {
        v1::SendMessageRequest req;
        req.set_conversation_id(direct_conv_id_.to_string());
        req.set_sender_device_id(alice_device_.str());
        req.set_priority(v1::MESSAGE_PRIORITY_NORMAL);
        req.set_client_idempotency_token(token);

        // Target 1: Bob phone
        auto* target1 = req.add_delivery_targets();
        target1->set_recipient_user_id(bob_user_.str());
        target1->set_recipient_device_id(bob_device_1_.str());
        auto* payload1 = target1->mutable_encrypted_payload();
        payload1->set_ciphertext_blob("encrypted-cipher-target-1");
        payload1->set_ephemeral_public_key(std::string(32, '\x11'));
        payload1->set_initialization_vector(std::string(24, '\x22'));
        payload1->set_auth_tag(std::string(16, '\x33'));
        payload1->set_algorithm("XChaCha20-Poly1305");

        // Target 2: Bob laptop
        auto* target2 = req.add_delivery_targets();
        target2->set_recipient_user_id(bob_user_.str());
        target2->set_recipient_device_id(bob_device_2_.str());
        auto* payload2 = target2->mutable_encrypted_payload();
        payload2->set_ciphertext_blob("encrypted-cipher-target-2");
        payload2->set_ephemeral_public_key(std::string(32, '\x44'));
        payload2->set_initialization_vector(std::string(24, '\x55'));
        payload2->set_auth_tag(std::string(16, '\x66'));
        payload2->set_algorithm("XChaCha20-Poly1305");

        return req;
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
    std::shared_ptr<service::ConversationAuthorizationService> auth_service_;
    std::shared_ptr<service::InMemorySequenceAllocator> sequence_allocator_;
    std::shared_ptr<ThreadSafeIdempotencyRepository> idempotency_repo_;
    std::shared_ptr<MessageSubmissionIdempotencyGuard> idempotency_guard_;
    std::shared_ptr<ThreadSafeMessageRepository> message_repo_;
    std::shared_ptr<ThreadSafeDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<ThreadSafeOutboxRepository> outbox_repo_;

    std::shared_ptr<MessageSubmissionService> submission_service_;
    std::unique_ptr<MessagingServiceImpl> messaging_service_;

    std::string server_address_;
    std::unique_ptr<grpc::Server> server_;
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
    DeviceId charlie_device_;
    DeviceId eve_device_;

    ConversationId direct_conv_id_;
    ConversationId active_group_id_;
    ConversationId closed_group_id_;
};

// ============================================================================
// Test 1: Happy Path Submission
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, HappyPathSubmissionSuccess) {
    grpc::ClientContext context;
    configure_context(context, alice_user_.str(), alice_device_.str(), "corr-happy-path", "tok-happy-path-12345");

    v1::SendMessageRequest req = build_direct_request("tok-happy-path-12345");
    v1::SendMessageResponse resp;

    auto status = grpc_stub_->SendMessage(&context, req, &resp);
    ASSERT_TRUE(status.ok()) << "gRPC SendMessage failed: " << status.error_message();

    EXPECT_FALSE(resp.message_id().empty());
    EXPECT_EQ(resp.conversation_id(), direct_conv_id_.to_string());
    EXPECT_GT(resp.accepted_at_unix_ms(), 0);
    EXPECT_EQ(resp.initial_state(), v1::DELIVERY_STATE_QUEUED);
    EXPECT_EQ(resp.target_count(), 2u);

    // Verify database mutations
    EXPECT_EQ(message_repo_->count(), 1u);
    EXPECT_EQ(delivery_repo_->pending_count(), 2u);
    EXPECT_EQ(outbox_repo_->count(), 1u);

    // Verify outbox payload contains the persisted message ID
    auto events = outbox_repo_->all();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_NE(events[0].payload_json.find(resp.message_id()), std::string::npos);
}

// ============================================================================
// Test 2: Idempotent Replay (Zero Duplicate Secondary Writes)
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, IdempotentReplayReturnsCachedWithoutDuplicateWrites) {
    v1::SendMessageRequest req = build_direct_request("tok-replay-test-unique");

    // 1. Initial submission
    grpc::ClientContext context1;
    configure_context(context1, alice_user_.str(), alice_device_.str(), "corr-replay-1", "tok-replay-test-unique");
    v1::SendMessageResponse resp1;
    auto status1 = grpc_stub_->SendMessage(&context1, req, &resp1);
    ASSERT_TRUE(status1.ok());

    // 2. Resend exact same submission (mobile client retry)
    grpc::ClientContext context2;
    configure_context(context2, alice_user_.str(), alice_device_.str(), "corr-replay-2", "tok-replay-test-unique");
    v1::SendMessageResponse resp2;
    auto status2 = grpc_stub_->SendMessage(&context2, req, &resp2);
    ASSERT_TRUE(status2.ok());

    EXPECT_EQ(resp1.message_id(), resp2.message_id());
    EXPECT_EQ(resp1.conversation_id(), resp2.conversation_id());
    EXPECT_NEAR(resp1.accepted_at_unix_ms(), resp2.accepted_at_unix_ms(), 100);

    // 0 duplicate secondary writes
    EXPECT_EQ(message_repo_->count(), 1u);
    EXPECT_EQ(delivery_repo_->pending_count(), 2u);
    EXPECT_EQ(outbox_repo_->count(), 1u);
}

// ============================================================================
// Test 3: Conflicting Idempotency Token Reuse
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, ConflictingIdempotencyTokenReuseRejected) {
    // 1. Legitimate submission
    grpc::ClientContext context1;
    configure_context(context1, alice_user_.str(), alice_device_.str(), "corr-conf-1", "tok-conflict-token-99");
    v1::SendMessageRequest req1 = build_direct_request("tok-conflict-token-99");
    v1::SendMessageResponse resp1;
    auto status1 = grpc_stub_->SendMessage(&context1, req1, &resp1);
    ASSERT_TRUE(status1.ok());

    // 2. Reusing token with modified payload
    grpc::ClientContext context2;
    configure_context(context2, alice_user_.str(), alice_device_.str(), "corr-conf-2", "tok-conflict-token-99");
    v1::SendMessageRequest req2 = build_direct_request("tok-conflict-token-99");
    req2.mutable_delivery_targets(0)->mutable_encrypted_payload()->set_ciphertext_blob("tampered-or-conflicting-body");
    v1::SendMessageResponse resp2;

    auto status2 = grpc_stub_->SendMessage(&context2, req2, &resp2);
    EXPECT_EQ(status2.error_code(), grpc::StatusCode::ALREADY_EXISTS);

    // Verify trailing metadata contains domain error detail
    auto error_detail = service::extract_error_detail(context2);
    ASSERT_TRUE(error_detail.has_value());
    EXPECT_EQ(error_detail->error_code(), v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);

    // Zero additional secondary writes
    EXPECT_EQ(message_repo_->count(), 1u);
    EXPECT_EQ(outbox_repo_->count(), 1u);
}

// ============================================================================
// Test 4: Concurrent Duplicate Submissions (Race Condition Resilience)
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, ConcurrentDuplicateSubmissionsDeduplicatedAtomically) {
    constexpr int k_num_threads = 10;
    const std::string shared_token = "tok-concurrent-race-12345";

    std::vector<std::future<std::pair<grpc::Status, v1::SendMessageResponse>>> futures;
    futures.reserve(k_num_threads);

    std::atomic<bool> start_gate{false};

    for (int i = 0; i < k_num_threads; ++i) {
        futures.push_back(std::async(std::launch::async, [&, i]() {
            while (!start_gate.load()) {
                std::this_thread::yield();
            }

            grpc::ClientContext ctx;
            configure_context(ctx, alice_user_.str(), alice_device_.str(), "corr-race-" + std::to_string(i),
                              shared_token);
            v1::SendMessageRequest r = build_direct_request(shared_token);
            v1::SendMessageResponse resp;
            auto status = grpc_stub_->SendMessage(&ctx, r, &resp);
            return std::make_pair(status, resp);
        }));
    }

    // Trigger all threads simultaneously
    start_gate.store(true);

    std::string canonical_message_id;
    for (auto& f : futures) {
        auto [status, resp] = f.get();
        ASSERT_TRUE(status.ok()) << "Thread submission failed: " << status.error_message();
        ASSERT_FALSE(resp.message_id().empty());

        if (canonical_message_id.empty()) {
            canonical_message_id = resp.message_id();
        } else {
            EXPECT_EQ(resp.message_id(), canonical_message_id);
        }
    }

    // Crucial Invariant: Exactly 1 message written despite 10 concurrent submissions
    EXPECT_EQ(message_repo_->count(), 1u);
    EXPECT_EQ(delivery_repo_->pending_count(), 2u);
    EXPECT_EQ(outbox_repo_->count(), 1u);
}

// ============================================================================
// Test 5: Unauthorized Sender Rejection
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, UnauthorizedSenderRejected) {
    grpc::ClientContext context;
    configure_context(context, eve_user_.str(), eve_device_.str(), "corr-eve-intrusion", "tok-eve-token-123");

    v1::SendMessageRequest req = build_direct_request("tok-eve-token-123");
    req.set_sender_device_id(eve_device_.str());
    v1::SendMessageResponse resp;

    auto status = grpc_stub_->SendMessage(&context, req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);

    auto error_detail = service::extract_error_detail(context);
    ASSERT_TRUE(error_detail.has_value());
    EXPECT_EQ(error_detail->error_code(), v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    // Zero writes
    EXPECT_EQ(message_repo_->count(), 0u);
    EXPECT_EQ(outbox_repo_->count(), 0u);
}

// ============================================================================
// Test 6: Closed Conversation Rejection
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, ClosedConversationRejected) {
    grpc::ClientContext context;
    configure_context(context, alice_user_.str(), alice_device_.str(), "corr-closed-conv", "tok-closed-12345");

    v1::SendMessageRequest req;
    req.set_conversation_id(closed_group_id_.to_string());
    req.set_sender_device_id(alice_device_.str());
    req.set_client_idempotency_token("tok-closed-12345");

    auto* target = req.add_delivery_targets();
    target->set_recipient_user_id(bob_user_.str());
    target->set_recipient_device_id(bob_device_1_.str());
    auto* payload = target->mutable_encrypted_payload();
    payload->set_ciphertext_blob("encrypted-cipher");
    payload->set_ephemeral_public_key(std::string(32, '\x11'));
    payload->set_initialization_vector(std::string(24, '\x22'));
    payload->set_auth_tag(std::string(16, '\x33'));
    payload->set_algorithm("XChaCha20-Poly1305");

    v1::SendMessageResponse resp;
    auto status = grpc_stub_->SendMessage(&context, req, &resp);
    EXPECT_FALSE(status.ok());

    // Zero writes
    EXPECT_EQ(message_repo_->count(), 0u);
    EXPECT_EQ(outbox_repo_->count(), 0u);
}

// ============================================================================
// Test 7: Bounded Queue Backpressure & Saturation
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, BoundedQueueSaturationReturnsResourceExhausted) {
    auto constrained_pool = std::make_shared<concurrency::BoundedWorkerPool>(1, 1, "test-small-pool");
    auto busy_service =
        std::make_unique<MessagingServiceImpl>(constrained_pool, nullptr, nullptr, nullptr, submission_service_);

    std::atomic<bool> block_worker{true};
    std::promise<void> worker_started_prom;
    auto worker_started = worker_started_prom.get_future();

    // 1. Block the 1 worker thread
    ASSERT_TRUE(constrained_pool->try_submit([&]() {
        worker_started_prom.set_value();
        while (block_worker.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }));
    worker_started.wait();

    // 2. Fill the 1 available queue slot
    ASSERT_TRUE(constrained_pool->try_submit([]() {}));

    // 3. Next call must be rejected immediately with RESOURCE_EXHAUSTED
    grpc::ServerContext server_ctx;
    v1::SendMessageRequest req = build_direct_request("tok-queue-full-test");
    v1::SendMessageResponse resp;

    // Use test spouse to inject caller context
    grpc::testing::ServerContextTestSpouse spouse(&server_ctx);
    spouse.add_client_metadata("x-user-id", alice_user_.str());
    spouse.add_client_metadata("x-device-id", alice_device_.str());

    auto status = busy_service->SendMessage(&server_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);

    // Unblock and clean up
    block_worker.store(false);
    constrained_pool->drain_and_stop();
}

// ============================================================================
// Test 8: Gateway HTTP End-to-End Integration
// ============================================================================

TEST_F(MessagingSubmissionIntegrationTest, GatewayHttpEndToEndIntegration) {
    gateway::http::AuthenticatedContext alice_auth_ctx(alice_user_.str(), alice_device_.str(), "session-alice-live",
                                                       auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                                       {"messaging:read", "messaging:write"}, 1750000000000LL);

    // 1. Success path (HTTP 201 Created)
    httplib::Request req1;
    req1.method = "POST";
    req1.path = "/api/v1/messages";
    req1.set_header("Content-Type", "application/json");
    req1.set_header("X-Request-ID", "req-gw-e2e-001");
    req1.set_header("X-Idempotency-Token", "tok-gw-e2e-12345");

    nlohmann::json body1;
    body1["conversation_id"] = direct_conv_id_.to_string();
    body1["priority"] = "normal";
    body1["delivery_targets"] = nlohmann::json::array({{{"recipient_user_id", bob_user_.str()},
                                                        {"recipient_device_id", bob_device_1_.str()},
                                                        {"encrypted_payload",
                                                         {{"ciphertext_blob", "gateway-encrypted-bytes"},
                                                          {"ephemeral_public_key", "ephemeral-key-bytes-test-000001"},
                                                          {"initialization_vector", "iv-bytes-12345678-24bytes!"},
                                                          {"auth_tag", "tag-bytes-12345678-16b"},
                                                          {"algorithm", "XChaCha20-Poly1305"}}}}});
    req1.body = body1.dump();

    httplib::Response res1;
    proxy_handler_->handle_send_message(req1, res1, alice_auth_ctx);

    EXPECT_EQ(res1.status, 201);
    auto resp_json1 = nlohmann::json::parse(res1.body);
    EXPECT_FALSE(resp_json1["message_id"].get<std::string>().empty());
    EXPECT_EQ(resp_json1["conversation_id"], direct_conv_id_.to_string());
    EXPECT_EQ(resp_json1["initial_state"], "QUEUED");
    EXPECT_EQ(resp_json1["target_count"], 1);

    // 2. Conflicting idempotency reuse via Gateway (HTTP 409 Conflict)
    httplib::Request req2;
    req2.method = "POST";
    req2.path = "/api/v1/messages";
    req2.set_header("Content-Type", "application/json");
    req2.set_header("X-Request-ID", "req-gw-e2e-002");
    req2.set_header("X-Idempotency-Token", "tok-gw-e2e-12345"); // Same token

    nlohmann::json body2 = body1;
    body2["delivery_targets"][0]["encrypted_payload"]["ciphertext_blob"] = "different-bytes";
    req2.body = body2.dump();

    httplib::Response res2;
    proxy_handler_->handle_send_message(req2, res2, alice_auth_ctx);

    EXPECT_EQ(res2.status, 409);
    auto resp_json2 = nlohmann::json::parse(res2.body);
    EXPECT_EQ(resp_json2["error"]["code"], "CONFLICT");

    // 3. Unauthorized sender via Gateway (HTTP 403 Forbidden)
    gateway::http::AuthenticatedContext eve_auth_ctx(eve_user_.str(), eve_device_.str(), "session-eve-intruder",
                                                     auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                                     {"messaging:read", "messaging:write"}, 1750000000000LL);

    httplib::Request req3;
    req3.method = "POST";
    req3.path = "/api/v1/messages";
    req3.set_header("Content-Type", "application/json");
    req3.set_header("X-Request-ID", "req-gw-e2e-003");
    req3.set_header("X-Idempotency-Token", "tok-gw-eve-123");

    nlohmann::json body3 = body1;
    body3["sender_device_id"] = eve_device_.str();
    req3.body = body3.dump();

    httplib::Response res3;
    proxy_handler_->handle_send_message(req3, res3, eve_auth_ctx);

    EXPECT_EQ(res3.status, 403);
    auto resp_json3 = nlohmann::json::parse(res3.body);
    EXPECT_EQ(resp_json3["error"]["code"], "PERMISSION_DENIED");
}

} // namespace
} // namespace securecloud::messaging
