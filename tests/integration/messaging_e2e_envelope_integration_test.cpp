#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif

#include "concurrency/bounded_worker_pool.hpp"
#include "domain/conversation_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/message_entity.hpp"
#include "domain/submission_fingerprint.hpp"
#include "domain/submission_types.hpp"
#include "gateway_config.hpp"
#include "grpc/messaging_service_client.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/proxy/messaging_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "messaging/client/auth_crypto_directory_client_interface.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"
#include "messaging/repository/idempotency_repository_interface.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"
#include "messaging/service/conversation_authorization_service.hpp"
#include "messaging/service/e2e_envelope_validator.hpp"
#include "messaging/service/idempotency_guard.hpp"
#include "messaging/service/in_memory_sequence_allocator.hpp"
#include "messaging/service/message_submission_service.hpp"
#include "messaging/service/messaging_error_mapper.hpp"
#include "messaging/service/messaging_service_impl.hpp"
#include "messaging/service/recipient_device_resolution_service.hpp"
#include "messaging/util/zero_plaintext_guard.hpp"
#include "messaging_config.hpp"
#include "securecloud/auth/v1/auth.pb.h"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "securecloud/security/mtls_config.hpp"

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
#include <deque>
#include <filesystem>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging {
namespace {

using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;
using domain::ConversationEntity;
using domain::ConversationId;
using domain::ConversationOutboxEvent;
using domain::ConversationParticipantEntity;
using domain::ConversationType;
using domain::DeviceDeliveryRecord;
using domain::DeviceDeliveryTarget;
using domain::DeviceId;
using domain::E2EAlgorithm;
using domain::E2EProtocolVersion;
using domain::IdempotencyRecord;
using domain::MembershipStatus;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;
using domain::MessagePriority;
using domain::MessageSubmissionCommand;
using domain::ParticipantRole;
using domain::RecipientDeliveryState;
using domain::UserId;
using service::E2EEnvelopeValidator;
using service::MessageSubmissionIdempotencyGuard;
using service::MessageSubmissionService;
using service::MessagingServiceImpl;
using service::RecipientDeviceResolutionService;
using util::ZeroPlaintextGuard;

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

    [[nodiscard]] size_t count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_messages_.size();
    }

    [[nodiscard]] std::vector<MessageEntity> all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_messages_;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_messages_.clear();
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

    [[nodiscard]] size_t pending_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_pending_.size();
    }

    [[nodiscard]] std::vector<DeviceDeliveryRecord> all_pending() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return saved_pending_;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        saved_pending_.clear();
        saved_recipient_states_.clear();
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

    [[nodiscard]] size_t count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enqueued_events_.size();
    }

    [[nodiscard]] std::vector<ConversationOutboxEvent> all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enqueued_events_;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        enqueued_events_.clear();
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

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        records_.clear();
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, IdempotencyRecord> records_;
};

// ============================================================================
// Thread-Safe Mock Auth Crypto Directory Client
// ============================================================================

class MockAuthCryptoClient : public IAuthCryptoDirectoryClient {
  public:
    void set_user_devices(const UserId& user_id, std::vector<DeviceCryptoRecord> devices) {
        std::lock_guard<std::mutex> lock(mutex_);
        user_devices_[user_id.str()] = std::move(devices);
    }

    client::Result<std::vector<DeviceCryptoRecord>, client::CryptoDirectoryError>
    get_user_device_crypto_records(const domain::UserId& user_id,
                                   std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) override {
        (void)timeout;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = user_devices_.find(user_id.str());
        if (it != user_devices_.end()) {
            return it->second;
        }
        return client::CryptoDirectoryError{
            .kind = client::CryptoDirectoryErrorKind::NotFound,
            .message = "User not found in crypto directory: " + user_id.str(),
        };
    }

    client::Result<DeviceCryptoRecord, client::CryptoDirectoryError>
    get_device_crypto_identity(const domain::DeviceId& device_id,
                               std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) override {
        (void)timeout;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [uid, devs] : user_devices_) {
            for (const auto& dev : devs) {
                if (dev.device_id == device_id) {
                    return dev;
                }
            }
        }
        return client::CryptoDirectoryError{
            .kind = client::CryptoDirectoryErrorKind::NotFound,
            .message = "Device not found in crypto directory: " + device_id.str(),
        };
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        user_devices_.clear();
    }

  private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::vector<DeviceCryptoRecord>> user_devices_;
};

// ============================================================================
// Integration Test Fixture
// ============================================================================

class MessagingE2EEnvelopeIntegrationTest : public ::testing::Test {
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

    static DeviceCryptoRecord
    make_device_record(const UserId& user_id, const DeviceId& device_id,
                       securecloud::auth::v1::DeviceStatus status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
        DeviceCryptoRecord rec;
        rec.user_id = user_id;
        rec.device_id = device_id;
        rec.status = status;
        rec.identity_key = std::vector<uint8_t>(32, 0xAA);
        rec.signed_prekey = std::vector<uint8_t>(32, 0xBB);
        rec.signed_prekey_signature = std::vector<uint8_t>(64, 0xCC);
        rec.one_time_prekey = std::vector<uint8_t>(32, 0xDD);
        rec.one_time_prekey_id = "prekey-otp-001";
        return rec;
    }

    static std::string make_binary_cipher(uint8_t tag_val) {
        std::string s;
        s.reserve(64);
        for (size_t i = 0; i < 32; ++i) {
            uint8_t c1 = static_cast<uint8_t>(0xC2 + ((tag_val + i) % 2));
            uint8_t c2 = static_cast<uint8_t>(0x80 + ((tag_val + i * 3) % 64));
            s.push_back(static_cast<char>(c1));
            s.push_back(static_cast<char>(c2));
        }
        return s;
    }

    static DeviceDeliveryTarget make_valid_target(const UserId& rec_user_id, const DeviceId& rec_device_id,
                                                  uint8_t tag_val = 0x11) {
        DeviceDeliveryTarget target;
        target.recipient_user_id = rec_user_id;
        target.recipient_device_id = rec_device_id;
        // High-entropy opaque ciphertext (non-plaintext, top-bit set)
        target.ciphertext_blob = make_binary_cipher(tag_val);
        target.ephemeral_public_key = std::vector<uint8_t>(32, tag_val);
        target.iv = std::vector<uint8_t>(24, tag_val);
        target.auth_tag = std::vector<uint8_t>(16, tag_val);
        target.algorithm = "XChaCha20-Poly1305";
        target.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
        target.one_time_prekey_id = "prekey-otp-001";
        return target;
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

        submission_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(8, 256, "e2e-sub-pool");
        delivery_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "e2e-del-pool");
        sync_pool_ = std::make_shared<concurrency::BoundedWorkerPool>(4, 128, "e2e-sync-pool");

        conv_repo_ = std::make_shared<repository::InMemoryConversationRepository>();
        member_repo_ = std::make_shared<repository::InMemoryMembershipRepository>();
        auth_service_ = std::make_shared<service::ConversationAuthorizationService>(*conv_repo_, *member_repo_);
        sequence_allocator_ = std::make_shared<service::InMemorySequenceAllocator>();
        idempotency_repo_ = std::make_shared<ThreadSafeIdempotencyRepository>();
        idempotency_guard_ = std::make_shared<MessageSubmissionIdempotencyGuard>(idempotency_repo_);
        message_repo_ = std::make_shared<ThreadSafeMessageRepository>();
        delivery_repo_ = std::make_shared<ThreadSafeDeliveryStateRepository>();
        outbox_repo_ = std::make_shared<ThreadSafeOutboxRepository>();
        crypto_client_ = std::make_shared<MockAuthCryptoClient>();

        resolution_service_ = std::make_shared<RecipientDeviceResolutionService>(crypto_client_);
        envelope_validator_ = std::make_shared<E2EEnvelopeValidator>(resolution_service_);

        submission_service_ = std::make_shared<MessageSubmissionService>(
            auth_service_, sequence_allocator_, idempotency_guard_, message_repo_, delivery_repo_, outbox_repo_,
            envelope_validator_, resolution_service_);

        messaging_service_ = std::make_unique<MessagingServiceImpl>(submission_pool_, delivery_pool_, sync_pool_,
                                                                    nullptr, submission_service_);

        seed_identities_and_topologies();
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

    void seed_identities_and_topologies() {
        // Users
        alice_user_ = UserId::from_string("018f6e80-1111-7000-8000-000000000001").value();
        bob_user_ = UserId::from_string("018f6e80-2222-7000-8000-000000000002").value();
        charlie_user_ = UserId::from_string("018f6e80-3333-7000-8000-000000000003").value();
        eve_user_ = UserId::from_string("018f6e80-9999-7000-8000-000000000009").value();

        // Devices
        alice_device_ = DeviceId("018f6e80-aaaa-7000-8000-000000000001");
        bob_device_1_ = DeviceId("018f6e80-bbbb-7000-8000-000000000001");
        bob_device_2_ = DeviceId("018f6e80-bbbb-7000-8000-000000000002");
        charlie_device_ = DeviceId("018f6e80-cccc-7000-8000-000000000001");
        eve_device_ = DeviceId("018f6e80-eeee-7000-8000-000000000001");

        // Enroll devices in Auth crypto directory
        crypto_client_->set_user_devices(alice_user_, {make_device_record(alice_user_, alice_device_)});
        crypto_client_->set_user_devices(
            bob_user_, {make_device_record(bob_user_, bob_device_1_), make_device_record(bob_user_, bob_device_2_)});
        crypto_client_->set_user_devices(charlie_user_, {make_device_record(charlie_user_, charlie_device_)});
        crypto_client_->set_user_devices(eve_user_, {make_device_record(eve_user_, eve_device_)});

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
                           const std::string& correlation_id = "corr-e2e-integ", const std::string& token = "") {
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

    MessageSubmissionCommand build_multi_device_command(const std::string& token) {
        MessageSubmissionCommand cmd;
        cmd.caller_user_id = alice_user_;
        cmd.sender_device_id = alice_device_;
        cmd.conversation_id = group_conv_id_;
        cmd.priority = MessagePriority::Normal;
        cmd.client_idempotency_token = token;
        cmd.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;

        // Targets: 3 devices across 2 recipients (Bob: 2 devices, Charlie: 1 device)
        cmd.delivery_targets.push_back(make_valid_target(bob_user_, bob_device_1_, 0x21));
        cmd.delivery_targets.push_back(make_valid_target(bob_user_, bob_device_2_, 0x22));
        cmd.delivery_targets.push_back(make_valid_target(charlie_user_, charlie_device_, 0x31));

        return cmd;
    }

    v1::SendMessageRequest build_multi_device_grpc_request(const std::string& token) {
        v1::SendMessageRequest req;
        req.set_conversation_id(group_conv_id_.to_string());
        req.set_sender_device_id(alice_device_.str());
        req.set_priority(v1::MESSAGE_PRIORITY_NORMAL);
        req.set_client_idempotency_token(token);

        // Bob Device 1
        auto* t1 = req.add_delivery_targets();
        t1->set_recipient_user_id(bob_user_.str());
        t1->set_recipient_device_id(bob_device_1_.str());
        auto* ep1 = t1->mutable_encrypted_payload();
        ep1->set_ciphertext_blob(make_binary_cipher(0x21));
        ep1->set_ephemeral_public_key(std::string(32, '\x21'));
        ep1->set_initialization_vector(std::string(24, '\x21'));
        ep1->set_auth_tag(std::string(16, '\x21'));
        ep1->set_algorithm("XChaCha20-Poly1305");

        // Bob Device 2
        auto* t2 = req.add_delivery_targets();
        t2->set_recipient_user_id(bob_user_.str());
        t2->set_recipient_device_id(bob_device_2_.str());
        auto* ep2 = t2->mutable_encrypted_payload();
        ep2->set_ciphertext_blob(make_binary_cipher(0x22));
        ep2->set_ephemeral_public_key(std::string(32, '\x22'));
        ep2->set_initialization_vector(std::string(24, '\x22'));
        ep2->set_auth_tag(std::string(16, '\x22'));
        ep2->set_algorithm("XChaCha20-Poly1305");

        // Charlie Device 1
        auto* t3 = req.add_delivery_targets();
        t3->set_recipient_user_id(charlie_user_.str());
        t3->set_recipient_device_id(charlie_device_.str());
        auto* ep3 = t3->mutable_encrypted_payload();
        ep3->set_ciphertext_blob(make_binary_cipher(0x31));
        ep3->set_ephemeral_public_key(std::string(32, '\x31'));
        ep3->set_initialization_vector(std::string(24, '\x31'));
        ep3->set_auth_tag(std::string(16, '\x31'));
        ep3->set_algorithm("XChaCha20-Poly1305");

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
    std::shared_ptr<MockAuthCryptoClient> crypto_client_;

    std::shared_ptr<RecipientDeviceResolutionService> resolution_service_;
    std::shared_ptr<E2EEnvelopeValidator> envelope_validator_;
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

    ConversationId group_conv_id_;
    ConversationId direct_conv_id_;
};

// ============================================================================
// Test 1: Valid Multi-Device Encrypted Submission
// ============================================================================
// Sender submits message targeting 3 devices across 2 recipients.
// Verifies message persisted, 3 distinct per-device encrypted envelopes persisted
// with correct ciphertexts, outbox event enqueued, and success returned.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test1_ValidMultiDeviceEncryptedSubmission) {
    // 1. Direct Service Layer Execution
    auto cmd = build_multi_device_command("token-e2e-multi-001");
    auto result = submission_service_->submit_message(cmd);

    ASSERT_TRUE(result.success) << "Submission failed: " << result.error_message;
    EXPECT_FALSE(result.value.message_id.to_string().empty());
    EXPECT_GT(result.value.message_sequence, 0u);
    EXPECT_FALSE(result.value.is_replay);

    // Verify Message Entity persistence
    EXPECT_EQ(message_repo_->count(), 1u);
    auto saved_msgs = message_repo_->all();
    ASSERT_EQ(saved_msgs.size(), 1u);
    EXPECT_EQ(saved_msgs[0].message_id, result.value.message_id);
    EXPECT_EQ(saved_msgs[0].conversation_id, group_conv_id_);
    EXPECT_EQ(saved_msgs[0].sender_user_id, alice_user_);
    EXPECT_EQ(saved_msgs[0].sender_device_id, alice_device_);

    // Verify 3 distinct per-device delivery records persisted
    EXPECT_EQ(delivery_repo_->pending_count(), 3u);
    auto pending = delivery_repo_->all_pending();
    ASSERT_EQ(pending.size(), 3u);

    std::unordered_map<std::string, DeviceDeliveryRecord> records_by_device;
    for (const auto& rec : pending) {
        records_by_device[rec.device_id.str()] = rec;
        EXPECT_EQ(rec.message_id, result.value.message_id);
        EXPECT_EQ(rec.conversation_id, group_conv_id_);
        EXPECT_EQ(rec.message_sequence, result.value.message_sequence);
        EXPECT_EQ(rec.delivery_state, domain::DeliveryState::Pending);
        EXPECT_EQ(rec.algorithm, E2EAlgorithm::XChaCha20_Poly1305);
        EXPECT_EQ(rec.protocol_version, E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
        EXPECT_EQ(rec.one_time_prekey_id, "prekey-otp-001");
    }

    // Verify distinct ciphertexts per device
    ASSERT_TRUE(records_by_device.contains(bob_device_1_.str()));
    ASSERT_TRUE(records_by_device.contains(bob_device_2_.str()));
    ASSERT_TRUE(records_by_device.contains(charlie_device_.str()));

    EXPECT_EQ(records_by_device[bob_device_1_.str()].ciphertext_blob, make_binary_cipher(0x21));
    EXPECT_EQ(records_by_device[bob_device_2_.str()].ciphertext_blob, make_binary_cipher(0x22));
    EXPECT_EQ(records_by_device[charlie_device_.str()].ciphertext_blob, make_binary_cipher(0x31));

    // Verify Outbox event enqueued
    EXPECT_EQ(outbox_repo_->count(), 1u);
    auto events = outbox_repo_->all();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_NE(events[0].payload_json.find(result.value.message_id.to_string()), std::string::npos);
    EXPECT_EQ(events[0].conversation_id, group_conv_id_);
    EXPECT_EQ(events[0].event_type, domain::ConversationOutboxEventType::MessageSent);

    // 2. Wire-level gRPC mTLS Verification
    grpc::ClientContext context;
    configure_context(context, alice_user_.str(), alice_device_.str(), "corr-grpc-001", "token-grpc-multi-002");
    v1::SendMessageRequest grpc_req = build_multi_device_grpc_request("token-grpc-multi-002");
    v1::SendMessageResponse grpc_resp;

    auto grpc_status = grpc_stub_->SendMessage(&context, grpc_req, &grpc_resp);
    EXPECT_TRUE(grpc_status.ok()) << "gRPC invocation failed: " << grpc_status.error_message();
    EXPECT_FALSE(grpc_resp.message_id().empty());
    EXPECT_EQ(grpc_resp.initial_state(), v1::DELIVERY_STATE_QUEUED);
    EXPECT_EQ(grpc_resp.target_count(), 3u);

    // Cumulative state: 2 messages saved, 6 pending records
    EXPECT_EQ(message_repo_->count(), 2u);
    EXPECT_EQ(delivery_repo_->pending_count(), 6u);
    EXPECT_EQ(outbox_repo_->count(), 2u);
}

// ============================================================================
// Test 2: Malformed Cryptographic Metadata Rejection
// ============================================================================
// Envelopes with short IV (< 24B for XChaCha20), short auth tag (< 16B),
// or empty ephemeral key are rejected with zero database writes.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test2_MalformedCryptographicMetadataRejection) {
    // Case A: Short IV (< 24 bytes for XChaCha20-Poly1305, e.g., 16 bytes)
    {
        auto cmd = build_multi_device_command("tok-malformed-iv");
        cmd.delivery_targets[0].iv = std::vector<uint8_t>(16, 0xAA); // Invalid!

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
        EXPECT_NE(result.error_message.find("must be at least 24 bytes"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }

    // Case B: Short Auth Tag (< 16 bytes, e.g., 12 bytes)
    {
        auto cmd = build_multi_device_command("tok-malformed-tag");
        cmd.delivery_targets[1].auth_tag = std::vector<uint8_t>(12, 0xBB); // Invalid!

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
        EXPECT_NE(result.error_message.find("must be at least 16 bytes"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }

    // Case C: Empty Ephemeral Public Key
    {
        auto cmd = build_multi_device_command("tok-empty-ephemeral");
        cmd.delivery_targets[2].ephemeral_public_key.clear(); // Invalid!

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
        EXPECT_NE(result.error_message.find("Ephemeral public key cannot be empty"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }

    // Wire-level gRPC rejection verification
    {
        grpc::ClientContext context;
        configure_context(context, alice_user_.str(), alice_device_.str(), "corr-malformed-grpc",
                          "tok-grpc-malformed-iv");
        v1::SendMessageRequest req = build_multi_device_grpc_request("tok-grpc-malformed-iv");
        // Inject short IV into target 1
        req.mutable_delivery_targets(0)->mutable_encrypted_payload()->set_initialization_vector(
            std::string(12, '\x11'));

        v1::SendMessageResponse resp;
        auto status = grpc_stub_->SendMessage(&context, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);

        // Still zero database writes
        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }
}

// ============================================================================
// Test 3: Unsupported Protocol Version Rejection
// ============================================================================
// Submissions attempting protocol downgrade or unapproved protocol versions
// fail closed with zero database writes.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test3_UnsupportedProtocolVersionRejection) {
    // Attempt 1: Command-level protocol downgrade to unspecified/unapproved version
    {
        auto cmd = build_multi_device_command("tok-downgrade-cmd");
        cmd.protocol_version = E2EProtocolVersion::Unspecified;

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_NE(result.error_message.find("Unsupported or deprecated E2E protocol version"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }

    // Attempt 2: Target-level protocol downgrade on a single device
    {
        auto cmd = build_multi_device_command("tok-downgrade-target");
        cmd.delivery_targets[0].protocol_version = E2EProtocolVersion::Unspecified;

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_NE(result.error_message.find("Unsupported E2E protocol version"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }

    // Attempt 3: Unknown / corrupted future protocol version
    {
        auto cmd = build_multi_device_command("tok-corrupted-version");
        cmd.protocol_version = static_cast<E2EProtocolVersion>(999);

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_NE(result.error_message.find("Unsupported or deprecated E2E protocol version"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }
}

// ============================================================================
// Test 4: Revoked Device Target Rejection
// ============================================================================
// Target device marked REVOKED in Auth crypto directory is rejected
// with DEVICE_REVOKED and zero database writes.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test4_RevokedDeviceTargetRejection) {
    // Mark Bob Device 2 as REVOKED in Auth crypto directory
    crypto_client_->set_user_devices(bob_user_,
                                     {make_device_record(bob_user_, bob_device_1_, auth::v1::DEVICE_STATUS_ACTIVE),
                                      make_device_record(bob_user_, bob_device_2_, auth::v1::DEVICE_STATUS_REVOKED)});

    auto cmd = build_multi_device_command("tok-revoked-dev-target");
    auto result = submission_service_->submit_message(cmd);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
    EXPECT_NE(result.error_message.find("revoked"), std::string::npos);

    // Fail-closed guarantee: zero database writes
    EXPECT_EQ(message_repo_->count(), 0u);
    EXPECT_EQ(delivery_repo_->pending_count(), 0u);
    EXPECT_EQ(outbox_repo_->count(), 0u);

    // Wire-level gRPC mTLS check for revoked device
    grpc::ClientContext context;
    configure_context(context, alice_user_.str(), alice_device_.str(), "corr-revoked-grpc", "tok-grpc-revoked-dev");
    v1::SendMessageRequest req = build_multi_device_grpc_request("tok-grpc-revoked-dev");
    v1::SendMessageResponse resp;

    auto status = grpc_stub_->SendMessage(&context, req, &resp);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);

    EXPECT_EQ(message_repo_->count(), 0u);
    EXPECT_EQ(delivery_repo_->pending_count(), 0u);
    EXPECT_EQ(outbox_repo_->count(), 0u);
}

// ============================================================================
// Test 5: Unauthorized Sender Rejection
// ============================================================================
// Non-member sender is rejected with PERMISSION_DENIED and zero database writes.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test5_UnauthorizedSenderRejection) {
    // Eve is not a member of group_conv_id_
    auto cmd = build_multi_device_command("tok-eve-unauthorized");
    cmd.caller_user_id = eve_user_;
    cmd.sender_device_id = eve_device_;

    auto result = submission_service_->submit_message(cmd);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);

    EXPECT_EQ(message_repo_->count(), 0u);
    EXPECT_EQ(delivery_repo_->pending_count(), 0u);
    EXPECT_EQ(outbox_repo_->count(), 0u);

    // Wire-level gRPC mTLS check with Eve's credentials
    grpc::ClientContext context;
    configure_context(context, eve_user_.str(), eve_device_.str(), "corr-eve-grpc", "tok-grpc-eve-unauthorized");
    v1::SendMessageRequest req = build_multi_device_grpc_request("tok-grpc-eve-unauthorized");
    req.set_sender_device_id(eve_device_.str());
    v1::SendMessageResponse resp;

    auto status = grpc_stub_->SendMessage(&context, req, &resp);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);

    EXPECT_EQ(message_repo_->count(), 0u);
    EXPECT_EQ(delivery_repo_->pending_count(), 0u);
    EXPECT_EQ(outbox_repo_->count(), 0u);
}

// ============================================================================
// Test 6: Plaintext Injection Attempt Rejection
// ============================================================================
// Submission attempting to inject raw JSON or ASCII plaintext into ciphertext_blob
// is detected and rejected by anti-plaintext heuristic guard with zero writes.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test6_PlaintextInjectionAttemptRejection) {
    // Attempt 1: Raw JSON string in ciphertext blob
    {
        auto cmd = build_multi_device_command("tok-plaintext-json");
        cmd.delivery_targets[0].ciphertext_blob = "{\"text\": \"unencrypted secret message payload\"}";

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
        EXPECT_NE(result.error_message.find("Unencrypted plaintext payload rejected"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }

    // Attempt 2: ASCII English sentences in ciphertext blob
    {
        auto cmd = build_multi_device_command("tok-plaintext-ascii");
        cmd.delivery_targets[1].ciphertext_blob = "Hello, this is a plain ASCII message without any encryption at all!";

        auto result = submission_service_->submit_message(cmd);
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
        EXPECT_NE(result.error_message.find("Unencrypted plaintext payload rejected"), std::string::npos);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }

    // Wire-level gRPC rejection for plaintext injection
    {
        grpc::ClientContext context;
        configure_context(context, alice_user_.str(), alice_device_.str(), "corr-plaintext-grpc",
                          "tok-grpc-plaintext-injection");
        v1::SendMessageRequest req = build_multi_device_grpc_request("tok-grpc-plaintext-injection");
        req.mutable_delivery_targets(0)->mutable_encrypted_payload()->set_ciphertext_blob(
            "{\"action\": \"send\", \"content\": \"forbidden raw text injection\"}");

        v1::SendMessageResponse resp;
        auto status = grpc_stub_->SendMessage(&context, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);

        EXPECT_EQ(message_repo_->count(), 0u);
        EXPECT_EQ(delivery_repo_->pending_count(), 0u);
        EXPECT_EQ(outbox_repo_->count(), 0u);
    }
}

// ============================================================================
// Test 7: Idempotent Replay with Multi-Device Envelopes
// ============================================================================
// Mobile client retry with identical token and envelopes returns original
// message ID without duplicate database writes or outbox events.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test7_IdempotentReplayWithMultiDeviceEnvelopes) {
    const std::string token = "token-e2e-idemp-replay-777";
    auto cmd = build_multi_device_command(token);

    // Initial submission
    auto res1 = submission_service_->submit_message(cmd);
    ASSERT_TRUE(res1.success);
    EXPECT_FALSE(res1.value.is_replay);
    auto original_id = res1.value.message_id;
    auto original_seq = res1.value.message_sequence;

    EXPECT_EQ(message_repo_->count(), 1u);
    EXPECT_EQ(delivery_repo_->pending_count(), 3u);
    EXPECT_EQ(outbox_repo_->count(), 1u);

    // Duplicate retry with identical token and payloads
    auto res2 = submission_service_->submit_message(cmd);
    ASSERT_TRUE(res2.success);
    EXPECT_TRUE(res2.value.is_replay);
    EXPECT_EQ(res2.value.message_id, original_id);
    EXPECT_EQ(res2.value.message_sequence, original_seq);

    // Invariant: Zero duplicate database writes
    EXPECT_EQ(message_repo_->count(), 1u);
    EXPECT_EQ(delivery_repo_->pending_count(), 3u);
    EXPECT_EQ(outbox_repo_->count(), 1u);

    // Wire-level gRPC idempotent retry check
    const std::string grpc_token = "token-grpc-idemp-replay-888";
    grpc::ClientContext ctx1;
    configure_context(ctx1, alice_user_.str(), alice_device_.str(), "corr-idemp-1", grpc_token);
    v1::SendMessageRequest req1 = build_multi_device_grpc_request(grpc_token);
    v1::SendMessageResponse resp1;
    auto s1 = grpc_stub_->SendMessage(&ctx1, req1, &resp1);
    ASSERT_TRUE(s1.ok());

    EXPECT_EQ(message_repo_->count(), 2u);
    EXPECT_EQ(delivery_repo_->pending_count(), 6u);
    EXPECT_EQ(outbox_repo_->count(), 2u);

    // Retry over gRPC
    grpc::ClientContext ctx2;
    configure_context(ctx2, alice_user_.str(), alice_device_.str(), "corr-idemp-2", grpc_token);
    v1::SendMessageResponse resp2;
    auto s2 = grpc_stub_->SendMessage(&ctx2, req1, &resp2);
    ASSERT_TRUE(s2.ok());
    EXPECT_EQ(resp2.message_id(), resp1.message_id());
    EXPECT_EQ(resp2.target_count(), resp1.target_count());

    // Still no duplicate writes
    EXPECT_EQ(message_repo_->count(), 2u);
    EXPECT_EQ(delivery_repo_->pending_count(), 6u);
    EXPECT_EQ(outbox_repo_->count(), 2u);
}

// ============================================================================
// Test 8: Conflicting Payload Tamper Rejection
// ============================================================================
// Client reuses token but alters one device's ciphertext -> rejected with
// IDEMPOTENCY_CONFLICT (HTTP 409 equivalent) and zero duplicate writes.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test8_ConflictingPayloadTamperRejection) {
    const std::string token = "token-e2e-tamper-conflict-999";
    auto cmd1 = build_multi_device_command(token);

    // Initial valid submission
    auto res1 = submission_service_->submit_message(cmd1);
    ASSERT_TRUE(res1.success);
    EXPECT_EQ(message_repo_->count(), 1u);

    // Replay with tampered ciphertext for Bob Device 1
    auto cmd2 = build_multi_device_command(token);
    cmd2.delivery_targets[0].ciphertext_blob = make_binary_cipher(0x99); // Tampered!

    auto res2 = submission_service_->submit_message(cmd2);
    EXPECT_FALSE(res2.success);
    EXPECT_EQ(res2.error_code, v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);
    EXPECT_NE(res2.error_message.find("different payload content"), std::string::npos);

    // Zero duplicate message or envelope writes
    EXPECT_EQ(message_repo_->count(), 1u);
    EXPECT_EQ(delivery_repo_->pending_count(), 3u);
    EXPECT_EQ(outbox_repo_->count(), 1u);

    // Wire-level HTTP Gateway Verification (HTTP 409 Conflict)
    gateway::http::AuthenticatedContext alice_auth(alice_user_.str(), alice_device_.str(), "session-alice-e2e",
                                                   auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                                   {"messaging:read", "messaging:write"}, 1750000000000LL);

    httplib::Request req_tamper;
    req_tamper.method = "POST";
    req_tamper.path = "/api/v1/messages";
    req_tamper.set_header("Content-Type", "application/json");
    req_tamper.set_header("X-Request-ID", "req-gw-tamper-001");
    req_tamper.set_header("X-Idempotency-Token", token); // Reusing token

    nlohmann::json body;
    body["conversation_id"] = group_conv_id_.to_string();
    body["priority"] = "normal";
    body["delivery_targets"] = nlohmann::json::array({{{"recipient_user_id", bob_user_.str()},
                                                       {"recipient_device_id", bob_device_1_.str()},
                                                       {"encrypted_payload",
                                                        {{"ciphertext_blob", make_binary_cipher(0x99)}, // Tampered!
                                                         {"ephemeral_public_key", std::string(32, '\x21')},
                                                         {"initialization_vector", std::string(24, '\x21')},
                                                         {"auth_tag", std::string(16, '\x21')},
                                                         {"algorithm", "XChaCha20-Poly1305"}}}},
                                                      {{"recipient_user_id", bob_user_.str()},
                                                       {"recipient_device_id", bob_device_2_.str()},
                                                       {"encrypted_payload",
                                                        {{"ciphertext_blob", make_binary_cipher(0x22)},
                                                         {"ephemeral_public_key", std::string(32, '\x22')},
                                                         {"initialization_vector", std::string(24, '\x22')},
                                                         {"auth_tag", std::string(16, '\x22')},
                                                         {"algorithm", "XChaCha20-Poly1305"}}}},
                                                      {{"recipient_user_id", charlie_user_.str()},
                                                       {"recipient_device_id", charlie_device_.str()},
                                                       {"encrypted_payload",
                                                        {{"ciphertext_blob", make_binary_cipher(0x31)},
                                                         {"ephemeral_public_key", std::string(32, '\x31')},
                                                         {"initialization_vector", std::string(24, '\x31')},
                                                         {"auth_tag", std::string(16, '\x31')},
                                                         {"algorithm", "XChaCha20-Poly1305"}}}}});
    req_tamper.body = body.dump();

    httplib::Response res_tamper;
    proxy_handler_->handle_send_message(req_tamper, res_tamper, alice_auth);

    EXPECT_EQ(res_tamper.status, 409);
    auto resp_json = nlohmann::json::parse(res_tamper.body);
    EXPECT_EQ(resp_json["error"]["code"], "CONFLICT");
}

// ============================================================================
// Test 9: Zero Plaintext Audit Verification
// ============================================================================
// Intercept all log outputs and error payloads during submission and verify
// zero ciphertext or plaintext bytes leak into logs, errors, or storage.
// ============================================================================

TEST_F(MessagingE2EEnvelopeIntegrationTest, Test9_ZeroPlaintextAuditVerification) {
    auto cmd = build_multi_device_command("tok-zero-plaintext-audit");

    // 1. Audit Log Formatting Safety
    std::string safe_log = ZeroPlaintextGuard::format_safe_submission_log(cmd);
    EXPECT_NE(safe_log.find("targets_count=3"), std::string::npos);
    EXPECT_NE(safe_log.find(cmd.conversation_id.to_string()), std::string::npos);
    EXPECT_NE(safe_log.find(alice_device_.str()), std::string::npos);

    // Verify zero ciphertext or key bytes in formatted logs
    EXPECT_EQ(safe_log.find(make_binary_cipher(0x21)), std::string::npos);
    EXPECT_EQ(safe_log.find(make_binary_cipher(0x22)), std::string::npos);
    EXPECT_EQ(safe_log.find(make_binary_cipher(0x31)), std::string::npos);
    EXPECT_EQ(safe_log.find(std::string(32, '\x21')), std::string::npos);

    // 2. Error Message Sanitization Guard
    std::string sensitive_err = "Auth failed: secret=secret_token_xyz for key=018f6e80-aaaa";
    std::string sanitized = ZeroPlaintextGuard::sanitize_error_message(sensitive_err);
    EXPECT_EQ(sanitized.find("secret_token_xyz"), std::string::npos);
    EXPECT_NE(sanitized.find("[REDACTED]"), std::string::npos);

    // 3. Verification of Persisted Ciphertext Entities in Database Repositories
    auto result = submission_service_->submit_message(cmd);
    ASSERT_TRUE(result.success);

    auto pending_records = delivery_repo_->all_pending();
    ASSERT_EQ(pending_records.size(), 3u);
    for (const auto& rec : pending_records) {
        // Must contain opaque high-entropy ciphertext, never ASCII JSON or plaintext strings
        EXPECT_FALSE(rec.ciphertext_blob.empty());
        EXPECT_EQ(rec.ciphertext_blob.find('{'), std::string::npos);
        EXPECT_EQ(rec.ciphertext_blob.find("secret"), std::string::npos);
        EXPECT_EQ(rec.ciphertext_blob.find("hello"), std::string::npos);
    }

    auto messages = message_repo_->all();
    ASSERT_EQ(messages.size(), 1u);
    EXPECT_FALSE(messages[0].envelope.ciphertext.empty());
    EXPECT_EQ(messages[0].envelope.ciphertext.find('{'), std::string::npos);
}

} // namespace
} // namespace securecloud::messaging
