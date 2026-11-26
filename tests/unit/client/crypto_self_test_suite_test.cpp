#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "domain/crypto/crypto_self_test.hpp"
#include "domain/local_audit_event.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain::crypto::test {
namespace {

using namespace std::chrono_literals;
using application::ApplicationLifecycleState;
using application::ClientApplication;
using application::ClientBootstrap;
using application::ClientConfig;
using application::ClientError;
using application::ClientErrorCode;
using application::ClientResult;
using application::interfaces::DeviceCryptoDirectoryEntry;
using application::interfaces::DeviceRegistrationResult;
using application::interfaces::FileChunkDownloadResult;
using application::interfaces::FileChunkUploadRequest;
using application::interfaces::FileChunkUploadResult;
using application::interfaces::FileUploadFinalizeRequest;
using application::interfaces::FileUploadFinalizeResult;
using application::interfaces::FileUploadInitRequest;
using application::interfaces::FileUploadInitResult;
using application::interfaces::IGatewayClient;
using application::interfaces::ISecureStorage;
using application::interfaces::PairingInitiationResult;
using application::interfaces::PrekeyUpdateResult;
using application::interfaces::RemoteFileMetadata;
using application::interfaces::TlsCertificateInfo;
using application::interfaces::UserProfileSyncResult;
using common::configuration::SecretString;
using infrastructure::adapters::DefaultGatewayClient;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;
using infrastructure::adapters::SqlCipherLocalStore;

class CountingGateway final : public IGatewayClient {
  public:
    explicit CountingGateway(std::shared_ptr<DefaultGatewayClient> inner) : inner_(std::move(inner)) {}

    [[nodiscard]] std::size_t probe_count() const noexcept { return probe_count_.load(std::memory_order_acquire); }
    [[nodiscard]] std::size_t total_calls() const noexcept { return total_calls_.load(std::memory_order_acquire); }

    ClientResult<bool> probe_gateway(std::string_view path) override {
        probe_count_.fetch_add(1U, std::memory_order_acq_rel);
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->probe_gateway(path);
    }
    ClientResult<std::string> send_message(const ConversationId& conversation_id,
                                           std::string_view encrypted_envelope) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->send_message(conversation_id, encrypted_envelope);
    }
    ClientResult<std::string>
    submit_encrypted_message(const application::interfaces::FanOutSubmissionRequest& request) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->submit_encrypted_message(request);
    }
    ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->sync_messages(cursor);
    }
    ClientResult<DeliveryState> acknowledge_delivery(const MessageId& message_id, const DeviceId& recipient_device_id,
                                                     int64_t delivered_at_ms) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->acknowledge_delivery(message_id, recipient_device_id, delivered_at_ms);
    }
    ClientResult<DeliveryState> send_read_receipt(const ConversationId& conversation_id, const MessageId& message_id,
                                                  const DeviceId& reader_device_id, int64_t read_at_ms) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->send_read_receipt(conversation_id, message_id, reader_device_id, read_at_ms);
    }
    ClientResult<domain::MessageDeliveryStatusInfo> get_message_delivery_status(const ConversationId& conversation_id,
                                                                                const MessageId& message_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->get_message_delivery_status(conversation_id, message_id);
    }
    ClientResult<domain::ConversationMessagesPage> fetch_conversation_messages(const ConversationId& conversation_id,
                                                                               const DeviceId& recipient_device_id,
                                                                               uint64_t since_sequence,
                                                                               std::size_t max_results) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->fetch_conversation_messages(conversation_id, recipient_device_id, since_sequence, max_results);
    }
    ClientResult<SyncCursorRecord> get_sync_cursor(const DeviceId& device_id,
                                                   const ConversationId& conversation_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->get_sync_cursor(device_id, conversation_id);
    }
    ClientResult<SyncCursorRecord> update_sync_cursor(const SyncCursorRecord& cursor) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->update_sync_cursor(cursor);
    }
    ClientResult<std::vector<domain::RemoteConversationSummary>>
    list_remote_conversations(const UserId& user_id, std::size_t max_results) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->list_remote_conversations(user_id, max_results);
    }
    uint64_t subscribe_realtime_events(IGatewayClient::RealtimeEventHandler handler) override {
        return inner_->subscribe_realtime_events(std::move(handler));
    }
    void unsubscribe_realtime_events(uint64_t subscription_id) override {
        inner_->unsubscribe_realtime_events(subscription_id);
    }
    ClientResult<bool> validate_token(std::string_view token) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->validate_token(token);
    }
    ClientResult<void> disconnect() override { return inner_->disconnect(); }
    ClientResult<DeviceRegistrationResult> register_device(const UserId& user_id, const PrekeyBundle& bundle) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->register_device(user_id, bundle);
    }
    ClientResult<PrekeyUpdateResult> update_crypto_prekeys(const DeviceId& device_id,
                                                           std::optional<std::vector<uint8_t>> signed_prekey,
                                                           std::optional<std::vector<uint8_t>> signed_prekey_signature,
                                                           std::vector<OneTimePrekeyRecord> one_time_prekeys) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->update_crypto_prekeys(device_id, std::move(signed_prekey), std::move(signed_prekey_signature),
                                             std::move(one_time_prekeys));
    }
    ClientResult<domain::PrekeyInventoryStatus> get_prekey_inventory_status(const DeviceId& device_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->get_prekey_inventory_status(device_id);
    }
    ClientResult<std::vector<DeviceCryptoDirectoryEntry>>
    get_device_crypto_directory(const UserId& user_id, const std::vector<DeviceId>& device_ids) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->get_device_crypto_directory(user_id, device_ids);
    }
    ClientResult<PairingInitiationResult> initiate_device_pairing(const DeviceId& device_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->initiate_device_pairing(device_id);
    }
    ClientResult<void> authorize_device_pairing(const DeviceId& device_id, std::string_view pairing_code,
                                                std::string_view mfa_token) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->authorize_device_pairing(device_id, pairing_code, mfa_token);
    }
    ClientResult<std::vector<Device>> list_user_devices(const UserId& user_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->list_user_devices(user_id);
    }
    ClientResult<void> revoke_device(const DeviceId& device_id, std::string_view mfa_token) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->revoke_device(device_id, mfa_token);
    }
    ClientResult<std::vector<DirectoryUserEntry>> search_directory_users(std::string_view query,
                                                                         std::size_t limit) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->search_directory_users(query, limit);
    }
    ClientResult<DirectoryUserEntry> lookup_user_identity(const UserId& user_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->lookup_user_identity(user_id);
    }
    ClientResult<FileUploadInitResult> init_file_upload(const FileUploadInitRequest& request) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->init_file_upload(request);
    }
    ClientResult<FileChunkUploadResult> upload_file_chunk(const FileChunkUploadRequest& request) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->upload_file_chunk(request);
    }
    ClientResult<FileUploadFinalizeResult> finalize_file_upload(const FileUploadFinalizeRequest& request) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->finalize_file_upload(request);
    }
    ClientResult<void> cancel_file_upload(std::string_view upload_id, std::string_view reason) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->cancel_file_upload(upload_id, reason);
    }
    ClientResult<RemoteFileMetadata> get_file_metadata(std::string_view file_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->get_file_metadata(file_id);
    }
    ClientResult<FileChunkDownloadResult> download_file_chunk(std::string_view file_id, uint32_t chunk_index) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->download_file_chunk(file_id, chunk_index);
    }
    ClientResult<void> delete_file(std::string_view file_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->delete_file(file_id);
    }
    ClientResult<UserProfile> get_user_profile(const UserId& user_id) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->get_user_profile(user_id);
    }
    ClientResult<UserProfileSyncResult> update_user_profile(const UserProfile& public_profile) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->update_user_profile(public_profile);
    }
    ClientResult<TlsCertificateInfo> inspect_tls_certificate(std::string_view host, uint16_t port) override {
        total_calls_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->inspect_tls_certificate(host, port);
    }

  private:
    std::shared_ptr<DefaultGatewayClient> inner_;
    std::atomic<std::size_t> probe_count_{0U};
    std::atomic<std::size_t> total_calls_{0U};
};

class FaultySecureStorage final : public ISecureStorage {
  public:
    enum class FaultMode { FailStoreCanary, CorruptReadbackCanary };

    explicit FaultySecureStorage(FaultMode mode) : mode_(mode) {}

    ClientResult<void> store_secret(std::string_view key_id, const SecretString& secret) override {
        if (mode_ == FaultMode::FailStoreCanary && key_id == CryptoSelfTest::kCanaryStorageKey) {
            return ClientResult<void>::error(ClientError::storage("Simulated secure enclave write failure"));
        }
        return inner_.store_secret(key_id, secret);
    }
    ClientResult<SecretString> get_secret(std::string_view key_id) override {
        if (mode_ == FaultMode::CorruptReadbackCanary && key_id == CryptoSelfTest::kCanaryStorageKey) {
            return ClientResult<SecretString>::ok(SecretString("corrupted-canary-readback-0000"));
        }
        return inner_.get_secret(key_id);
    }
    ClientResult<void> delete_secret(std::string_view key_id) override { return inner_.delete_secret(key_id); }
    ClientResult<bool> has_secret(std::string_view key_id) override { return inner_.has_secret(key_id); }
    ClientResult<std::vector<std::string>> list_secret_keys() override { return inner_.list_secret_keys(); }
    ClientResult<std::size_t> purge_all_secrets() override { return inner_.purge_all_secrets(); }

  private:
    FaultMode mode_;
    MemorySecureStorage inner_;
};

class CryptoSelfTestSuiteTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_crypto_selftest_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "selftest_vault.db").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(CryptoSelfTestSuiteTest, AllSixRealOpenSslChecksPassUnderColdStartBudgetAndLeaveStorageClean) {
    MemorySecureStorage secure_storage;

    const auto report = CryptoSelfTest::run_all(&secure_storage);
    const double total_ms = static_cast<double>(report.total_duration_us) / 1000.0;

    std::cout << "[CryptoSelfTest] overall_passed=" << (report.overall_passed ? "true" : "false") << " backend=\""
              << report.crypto_backend << "\""
              << " total_ms=" << total_ms << " total_us=" << report.total_duration_us << "\n";
    for (const auto& c : report.checks) {
        std::cout << "[CryptoSelfTest]   check=" << c.check_name << " passed=" << (c.passed ? "true" : "false")
                  << " us=" << c.duration_us << " detail=\"" << c.detail << "\"\n";
    }

    EXPECT_TRUE(report.overall_passed);
    EXPECT_TRUE(report.failed_checks_summary().empty());
    EXPECT_NE(report.crypto_backend.find("OpenSSL"), std::string::npos);
    EXPECT_LT(report.total_duration_us, 20000);
    ASSERT_EQ(report.checks.size(), 6U);
    for (const auto& check : report.checks) {
        EXPECT_TRUE(check.passed) << check.check_name << ": " << check.detail;
    }

    const auto has_canary = secure_storage.has_secret(CryptoSelfTest::kCanaryStorageKey);
    ASSERT_TRUE(has_canary.is_ok());
    EXPECT_FALSE(has_canary.value());
    EXPECT_TRUE(secure_storage.list_secret_keys().value().empty());

    const nlohmann::json parsed = nlohmann::json::parse(report.to_json(), nullptr, false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed["overall_passed"].get<bool>());
    EXPECT_EQ(parsed["checks"].size(), 6U);
}

TEST_F(CryptoSelfTestSuiteTest, HealthyColdBootRunsSelfTestLogsAuditAndAllowsGatewayProbe) {
    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_;

    auto inner_gw = std::make_shared<DefaultGatewayClient>(cfg);
    auto counting_gw_ptr = std::make_unique<CountingGateway>(inner_gw);
    CountingGateway* gw_observer = counting_gw_ptr.get();

    auto secure_storage = std::make_unique<MemorySecureStorage>();
    auto crypto_provider = std::make_unique<OpenSslCryptoProvider>();
    auto local_store = std::make_unique<SqlCipherLocalStore>(*secure_storage, *crypto_provider);

    auto bootstrap = ClientBootstrap::create_with_adapters(cfg, std::move(counting_gw_ptr), std::move(local_store),
                                                           std::move(secure_storage), std::move(crypto_provider));
    ClientApplication app(std::move(bootstrap));

    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());
    EXPECT_TRUE(app.is_running());

    ASSERT_TRUE(app.last_self_test_report().has_value());
    EXPECT_TRUE(app.last_self_test_report()->overall_passed);
    EXPECT_NE(app.last_self_test_report()->crypto_backend.find("OpenSSL"), std::string::npos);
    EXPECT_EQ(gw_observer->probe_count(), 1U);

    ASSERT_NE(app.bootstrap().local_audit_logger(), nullptr);
    const auto verify_res = app.bootstrap().local_audit_logger()->verify_chain_integrity();
    ASSERT_TRUE(verify_res.is_ok());
    EXPECT_TRUE(verify_res.value().valid);

    const auto recent = app.bootstrap().local_audit_logger()->recent_events(10U);
    ASSERT_TRUE(recent.is_ok());
    ASSERT_FALSE(recent.value().empty());
    EXPECT_EQ(recent.value().front().event_type, "crypto.selftest.passed");
    EXPECT_EQ(recent.value().front().category, domain::LocalAuditCategory::CryptoSelfTest);
    EXPECT_EQ(recent.value().front().outcome, domain::LocalAuditOutcome::Success);

    EXPECT_TRUE(app.shutdown().is_ok());

    // Even offline default-config boots (StubCryptoProvider) run real OpenSSL 3.x KATs on initialize().
    ClientApplication offline_app(ClientConfig::create_default());
    ASSERT_TRUE(offline_app.initialize().is_ok());
    ASSERT_TRUE(offline_app.last_self_test_report().has_value());
    EXPECT_TRUE(offline_app.last_self_test_report()->overall_passed);
    EXPECT_NE(offline_app.last_self_test_report()->crypto_backend.find("OpenSSL"), std::string::npos);
    EXPECT_TRUE(offline_app.shutdown().is_ok());
}

TEST_F(CryptoSelfTestSuiteTest, FaultInjectedCryptoOrCsprngFailureFailsClosedBeforeGatewayContact) {
    const std::vector<std::string> check_names = {
        "ed25519_kat", "x25519_kat", "aes_256_gcm_kat", "hkdf_sha256_kat", "csprng_health",
    };

    for (const auto& check_name : check_names) {
        const std::string case_db = (temp_dir_ / (check_name + ".db")).string();
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = case_db;

        auto inner_gw = std::make_shared<DefaultGatewayClient>(cfg);
        auto counting_gw_ptr = std::make_unique<CountingGateway>(inner_gw);
        CountingGateway* gw_observer = counting_gw_ptr.get();

        auto secure_storage = std::make_unique<MemorySecureStorage>();
        auto open_crypto = std::make_unique<OpenSslCryptoProvider>();
        auto local_store = std::make_unique<SqlCipherLocalStore>(*secure_storage, *open_crypto);

        auto bootstrap = ClientBootstrap::create_with_adapters(cfg, std::move(counting_gw_ptr), std::move(local_store),
                                                               std::move(secure_storage), std::move(open_crypto));
        bootstrap->set_self_test_fault_injector([check_name](std::string_view name) -> std::optional<std::string> {
            if (name == check_name) {
                return std::string("Simulated KAT failure for ") + check_name;
            }
            return std::nullopt;
        });

        ClientApplication app(std::move(bootstrap));
        const auto init_res = app.initialize();
        ASSERT_TRUE(init_res.is_error()) << check_name;
        EXPECT_EQ(init_res.error().code(), ClientErrorCode::CryptoOperationFailed) << check_name;
        EXPECT_EQ(app.state(), ApplicationLifecycleState::Terminated) << check_name;

        // Zero network calls may be made after any cryptographic self-test failure.
        EXPECT_EQ(gw_observer->probe_count(), 0U) << check_name;
        EXPECT_EQ(gw_observer->total_calls(), 0U) << check_name;
        EXPECT_TRUE(app.start().is_error()) << check_name;
        EXPECT_EQ(gw_observer->total_calls(), 0U) << check_name;

        ASSERT_TRUE(app.last_self_test_report().has_value()) << check_name;
        EXPECT_FALSE(app.last_self_test_report()->overall_passed) << check_name;
        EXPECT_NE(app.last_self_test_report()->failed_checks_summary().find(check_name), std::string::npos);

        ASSERT_NE(app.bootstrap().local_audit_logger(), nullptr);
        const auto recent = app.bootstrap().local_audit_logger()->recent_events(5U);
        ASSERT_TRUE(recent.is_ok()) << check_name;
        ASSERT_FALSE(recent.value().empty()) << check_name;
        EXPECT_EQ(recent.value().front().event_type, "crypto.selftest.failed") << check_name;
        EXPECT_EQ(recent.value().front().outcome, domain::LocalAuditOutcome::Failure) << check_name;
    }
}

TEST_F(CryptoSelfTestSuiteTest, FailingSecureStorageCanaryAbortsBootBeforeGatewayContact) {
    const std::vector<FaultySecureStorage::FaultMode> modes = {
        FaultySecureStorage::FaultMode::FailStoreCanary,
        FaultySecureStorage::FaultMode::CorruptReadbackCanary,
    };

    for (std::size_t idx = 0U; idx < modes.size(); ++idx) {
        const std::string case_db = (temp_dir_ / ("storage_fault_" + std::to_string(idx) + ".db")).string();
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = case_db;

        auto inner_gw = std::make_shared<DefaultGatewayClient>(cfg);
        auto counting_gw_ptr = std::make_unique<CountingGateway>(inner_gw);
        CountingGateway* gw_observer = counting_gw_ptr.get();

        auto faulty_storage = std::make_unique<FaultySecureStorage>(modes[idx]);
        auto crypto_provider = std::make_unique<OpenSslCryptoProvider>();
        auto local_store = std::make_unique<SqlCipherLocalStore>(*faulty_storage, *crypto_provider);

        auto bootstrap = ClientBootstrap::create_with_adapters(cfg, std::move(counting_gw_ptr), std::move(local_store),
                                                               std::move(faulty_storage), std::move(crypto_provider));
        ClientApplication app(std::move(bootstrap));

        const auto init_res = app.initialize();
        ASSERT_TRUE(init_res.is_error());
        EXPECT_EQ(init_res.error().code(), ClientErrorCode::CryptoOperationFailed);
        EXPECT_EQ(app.state(), ApplicationLifecycleState::Terminated);
        EXPECT_EQ(gw_observer->probe_count(), 0U);
        EXPECT_EQ(gw_observer->total_calls(), 0U);

        ASSERT_TRUE(app.last_self_test_report().has_value());
        EXPECT_FALSE(app.last_self_test_report()->overall_passed);
        EXPECT_NE(app.last_self_test_report()->failed_checks_summary().find("secure_storage_canary"),
                  std::string::npos);

        const auto has_canary = app.bootstrap().secure_storage().has_secret(CryptoSelfTest::kCanaryStorageKey);
        ASSERT_TRUE(has_canary.is_ok());
        EXPECT_FALSE(has_canary.value());

        ASSERT_NE(app.bootstrap().local_audit_logger(), nullptr);
        const auto recent = app.bootstrap().local_audit_logger()->recent_events(5U);
        ASSERT_TRUE(recent.is_ok());
        ASSERT_FALSE(recent.value().empty());
        EXPECT_EQ(recent.value().front().event_type, "crypto.selftest.failed");
    }
}

} // namespace
} // namespace securecloud::client::domain::crypto::test
