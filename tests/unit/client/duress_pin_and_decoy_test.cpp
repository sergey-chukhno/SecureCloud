#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/auth_manager.hpp"
#include "application/managers/emergency_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/emergency_models.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "infrastructure/client_logger.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::application::managers::test {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure;
using namespace securecloud::client::infrastructure::adapters;
using securecloud::common::configuration::SecretString;

DeviceCryptoDirectoryEntry seed_device_bundle(ISecureStorage& storage, OpenSslCryptoProvider& crypto,
                                              const DeviceId& did) {
    auto ik = crypto.generate_identity_keypair().value();
    auto spk = crypto.generate_signed_prekey(ik.private_key).value();
    auto otk = crypto.generate_dh_keypair().value();

    DevicePrivateBundle bundle(did, ik.public_key, std::move(ik.private_key), spk.public_key,
                               std::move(spk.private_key), spk.signature);
    bundle.add_one_time_prekey(did.value() + "-otk-1", std::move(otk.private_key));
    EXPECT_TRUE(KeyStorageHelper::save_bundle(storage, bundle).is_ok());

    return DeviceCryptoDirectoryEntry{
        .device_id = did,
        .identity_key = ik.public_key,
        .signed_prekey = spk.public_key,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = otk.public_key,
        .one_time_prekey_id = did.value() + "-otk-1",
        .identity_key_fingerprint = "",
    };
}

class CountingProbeGateway final : public IGatewayClient {
  public:
    explicit CountingProbeGateway(std::shared_ptr<DefaultGatewayClient> inner) : inner_(std::move(inner)) {}

    [[nodiscard]] std::size_t probe_count() const noexcept { return probe_count_.load(std::memory_order_acquire); }
    void reset_probe_count() noexcept { probe_count_.store(0U, std::memory_order_release); }

    ClientResult<bool> probe_gateway(std::string_view path) override {
        probe_count_.fetch_add(1U, std::memory_order_acq_rel);
        return inner_->probe_gateway(path);
    }
    ClientResult<std::string> send_message(const ConversationId& conversation_id,
                                           std::string_view encrypted_envelope) override {
        return inner_->send_message(conversation_id, encrypted_envelope);
    }
    ClientResult<std::string> submit_encrypted_message(const FanOutSubmissionRequest& request) override {
        return inner_->submit_encrypted_message(request);
    }
    ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) override {
        return inner_->sync_messages(cursor);
    }
    ClientResult<DeliveryState> acknowledge_delivery(const MessageId& message_id, const DeviceId& recipient_device_id,
                                                     int64_t delivered_at_ms) override {
        return inner_->acknowledge_delivery(message_id, recipient_device_id, delivered_at_ms);
    }
    ClientResult<DeliveryState> send_read_receipt(const ConversationId& conversation_id, const MessageId& message_id,
                                                  const DeviceId& reader_device_id, int64_t read_at_ms) override {
        return inner_->send_read_receipt(conversation_id, message_id, reader_device_id, read_at_ms);
    }
    ClientResult<MessageDeliveryStatusInfo> get_message_delivery_status(const ConversationId& conversation_id,
                                                                        const MessageId& message_id) override {
        return inner_->get_message_delivery_status(conversation_id, message_id);
    }
    ClientResult<ConversationMessagesPage> fetch_conversation_messages(const ConversationId& conversation_id,
                                                                       const DeviceId& recipient_device_id,
                                                                       uint64_t since_sequence,
                                                                       std::size_t max_results) override {
        return inner_->fetch_conversation_messages(conversation_id, recipient_device_id, since_sequence, max_results);
    }
    ClientResult<SyncCursorRecord> get_sync_cursor(const DeviceId& device_id,
                                                   const ConversationId& conversation_id) override {
        return inner_->get_sync_cursor(device_id, conversation_id);
    }
    ClientResult<SyncCursorRecord> update_sync_cursor(const SyncCursorRecord& cursor) override {
        return inner_->update_sync_cursor(cursor);
    }
    ClientResult<std::vector<RemoteConversationSummary>> list_remote_conversations(const UserId& user_id,
                                                                                   std::size_t max_results) override {
        return inner_->list_remote_conversations(user_id, max_results);
    }
    uint64_t subscribe_realtime_events(RealtimeEventHandler handler) override {
        return inner_->subscribe_realtime_events(std::move(handler));
    }
    void unsubscribe_realtime_events(uint64_t subscription_id) override {
        inner_->unsubscribe_realtime_events(subscription_id);
    }
    ClientResult<bool> validate_token(std::string_view token) override { return inner_->validate_token(token); }
    ClientResult<void> disconnect() override { return inner_->disconnect(); }
    ClientResult<DeviceRegistrationResult> register_device(const UserId& user_id, const PrekeyBundle& bundle) override {
        return inner_->register_device(user_id, bundle);
    }
    ClientResult<PrekeyUpdateResult> update_crypto_prekeys(const DeviceId& device_id,
                                                           std::optional<std::vector<uint8_t>> signed_prekey,
                                                           std::optional<std::vector<uint8_t>> signed_prekey_signature,
                                                           std::vector<OneTimePrekeyRecord> one_time_prekeys) override {
        return inner_->update_crypto_prekeys(device_id, std::move(signed_prekey), std::move(signed_prekey_signature),
                                             std::move(one_time_prekeys));
    }
    ClientResult<PrekeyInventoryStatus> get_prekey_inventory_status(const DeviceId& device_id) override {
        return inner_->get_prekey_inventory_status(device_id);
    }
    ClientResult<std::vector<DeviceCryptoDirectoryEntry>>
    get_device_crypto_directory(const UserId& user_id, const std::vector<DeviceId>& device_ids) override {
        return inner_->get_device_crypto_directory(user_id, device_ids);
    }
    ClientResult<PairingInitiationResult> initiate_device_pairing(const DeviceId& device_id) override {
        return inner_->initiate_device_pairing(device_id);
    }
    ClientResult<void> authorize_device_pairing(const DeviceId& device_id, std::string_view pairing_code,
                                                std::string_view mfa_token) override {
        return inner_->authorize_device_pairing(device_id, pairing_code, mfa_token);
    }
    ClientResult<std::vector<Device>> list_user_devices(const UserId& user_id) override {
        return inner_->list_user_devices(user_id);
    }
    ClientResult<void> revoke_device(const DeviceId& device_id, std::string_view mfa_token) override {
        return inner_->revoke_device(device_id, mfa_token);
    }
    ClientResult<std::vector<DirectoryUserEntry>> search_directory_users(std::string_view query,
                                                                         std::size_t limit) override {
        return inner_->search_directory_users(query, limit);
    }
    ClientResult<DirectoryUserEntry> lookup_user_identity(const UserId& user_id) override {
        return inner_->lookup_user_identity(user_id);
    }
    ClientResult<FileUploadInitResult> init_file_upload(const FileUploadInitRequest& request) override {
        return inner_->init_file_upload(request);
    }
    ClientResult<FileChunkUploadResult> upload_file_chunk(const FileChunkUploadRequest& request) override {
        return inner_->upload_file_chunk(request);
    }
    ClientResult<FileUploadFinalizeResult> finalize_file_upload(const FileUploadFinalizeRequest& request) override {
        return inner_->finalize_file_upload(request);
    }
    ClientResult<void> cancel_file_upload(std::string_view upload_id, std::string_view reason) override {
        return inner_->cancel_file_upload(upload_id, reason);
    }
    ClientResult<RemoteFileMetadata> get_file_metadata(std::string_view file_id) override {
        return inner_->get_file_metadata(file_id);
    }
    ClientResult<FileChunkDownloadResult> download_file_chunk(std::string_view file_id, uint32_t chunk_index) override {
        return inner_->download_file_chunk(file_id, chunk_index);
    }
    ClientResult<void> delete_file(std::string_view file_id) override { return inner_->delete_file(file_id); }
    ClientResult<UserProfile> get_user_profile(const UserId& user_id) override {
        return inner_->get_user_profile(user_id);
    }
    ClientResult<UserProfileSyncResult> update_user_profile(const UserProfile& public_profile) override {
        return inner_->update_user_profile(public_profile);
    }
    ClientResult<TlsCertificateInfo> inspect_tls_certificate(std::string_view host, uint16_t port) override {
        return inner_->inspect_tls_certificate(host, port);
    }

  private:
    std::shared_ptr<DefaultGatewayClient> inner_;
    std::atomic<std::size_t> probe_count_{0U};
};

class DuressPinAndDecoyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_duress_pin_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "vault.db";
    }

    void TearDown() override {
        (void)ClientLogger::flush_and_close_log_file();
        ClientLogger::reset_sink();
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    struct TestContext {
        std::shared_ptr<DefaultGatewayClient> inner_gateway;
        CountingProbeGateway* counting_gateway{nullptr};
        std::unique_ptr<ClientBootstrap> bootstrap;
    };

    static TestContext create_context(const std::filesystem::path& db_file) {
        auto inner = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
        auto gw = std::make_unique<CountingProbeGateway>(inner);
        auto* gw_ptr = gw.get();

        auto storage = std::make_unique<MemorySecureStorage>();
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto store = std::make_unique<SqlCipherLocalStore>(*storage, *crypto);
        EXPECT_TRUE(store->open(db_file.string()).is_ok());

        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = db_file.string();

        auto bootstrap = ClientBootstrap::create_with_adapters(cfg, std::move(gw), std::move(store), std::move(storage),
                                                               std::move(crypto));
        return TestContext{
            .inner_gateway = std::move(inner),
            .counting_gateway = gw_ptr,
            .bootstrap = std::move(bootstrap),
        };
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(DuressPinAndDecoyTest, ConfigureValidateSaltAndConstantTimeVerify) {
    auto ctx = create_context(db_path_);
    auto& em = ctx.bootstrap->emergency_manager();
    auto& storage = ctx.bootstrap->secure_storage();

    EXPECT_FALSE(em.has_duress_pin());
    EXPECT_FALSE(em.duress_post_wipe_mode().has_value());

    // Enforce 6..1024 byte Option A bounds.
    const auto empty_res = em.configure_duress_pin(SecretString(""));
    ASSERT_TRUE(empty_res.is_error());
    EXPECT_EQ(empty_res.error().category(), ClientErrorCategory::Validation);

    const auto short_res = em.configure_duress_pin(SecretString("12345"));
    ASSERT_TRUE(short_res.is_error());
    EXPECT_EQ(short_res.error().category(), ClientErrorCategory::Validation);

    const auto too_long_res = em.configure_duress_pin(SecretString(std::string(1025U, 'a')));
    ASSERT_TRUE(too_long_res.is_error());
    EXPECT_EQ(too_long_res.error().category(), ClientErrorCategory::Validation);

    // 6-char numeric PIN accepted and hashed with salted PBKDF2-HMAC-SHA256.
    ASSERT_TRUE(em.configure_duress_pin(SecretString("911420"), PostWipeMode::DecoyWorkspace).is_ok());
    EXPECT_TRUE(em.has_duress_pin());
    EXPECT_EQ(em.duress_post_wipe_mode(), std::optional<PostWipeMode>(PostWipeMode::DecoyWorkspace));

    const auto stored1 = storage.get_secret(std::string(DuressPinConfig::kStorageKey));
    ASSERT_TRUE(stored1.is_ok());
    EXPECT_EQ(stored1.value().expose_unredacted_secret().find("911420"), std::string::npos);

    const auto cfg1 = DuressPinConfig::from_json(stored1.value().expose_unredacted_secret());
    ASSERT_TRUE(cfg1.has_value());
    EXPECT_TRUE(cfg1->enabled);
    EXPECT_EQ(cfg1->pbkdf2_iterations, 100000U);
    EXPECT_EQ(cfg1->salt_hex.size(), 32U);
    EXPECT_EQ(cfg1->derived_hash_hex.size(), 64U);

    // Constant-time verification accepts exact match and rejects 1-char / prefix / suffix mismatches.
    EXPECT_TRUE(em.verify_duress_credential(SecretString("911420")).value());
    EXPECT_FALSE(em.verify_duress_credential(SecretString("911421")).value());
    EXPECT_FALSE(em.verify_duress_credential(SecretString("91142")).value());
    EXPECT_FALSE(em.verify_duress_credential(SecretString("9114200")).value());
    EXPECT_FALSE(em.verify_duress_credential(SecretString("")).value());

    // Re-configuring the exact same PIN generates a fresh salt and distinct hash.
    ASSERT_TRUE(em.configure_duress_pin(SecretString("911420"), PostWipeMode::DecoyWorkspace).is_ok());
    const auto stored2 = storage.get_secret(std::string(DuressPinConfig::kStorageKey));
    ASSERT_TRUE(stored2.is_ok());
    const auto cfg2 = DuressPinConfig::from_json(stored2.value().expose_unredacted_secret());
    ASSERT_TRUE(cfg2.has_value());
    EXPECT_NE(cfg2->salt_hex, cfg1->salt_hex);
    EXPECT_NE(cfg2->derived_hash_hex, cfg1->derived_hash_hex);

    // Full password-style passphrase with leading/trailing spaces & symbols: NO trimming (Option A parity).
    const std::string spaced_passphrase = " Autumn-Backup-42! ";
    ASSERT_TRUE(em.configure_duress_pin(SecretString(spaced_passphrase), PostWipeMode::DecoyWorkspace).is_ok());
    EXPECT_TRUE(em.verify_duress_credential(SecretString(spaced_passphrase)).value());
    EXPECT_FALSE(em.verify_duress_credential(SecretString("Autumn-Backup-42!")).value());

    // Exact 1024-byte PasswordCredential maximum length is accepted and verified cleanly.
    const std::string max_passphrase(1024U, 'Z');
    ASSERT_TRUE(em.configure_duress_pin(SecretString(max_passphrase), PostWipeMode::UnconfiguredReset).is_ok());
    EXPECT_TRUE(em.verify_duress_credential(SecretString(max_passphrase)).value());

    // Clear removes config and is idempotent.
    ASSERT_TRUE(em.clear_duress_pin().is_ok());
    EXPECT_FALSE(em.has_duress_pin());
    EXPECT_FALSE(em.duress_post_wipe_mode().has_value());
    EXPECT_FALSE(em.verify_duress_credential(SecretString(max_passphrase)).value());
    EXPECT_TRUE(em.clear_duress_pin().is_ok());
}

TEST_F(DuressPinAndDecoyTest, SilentDuressLoginTriggersFullWipeUnder500MsWithZeroNetworkCallsAndOpensDecoyWorkspace) {
    auto ctx = create_context(db_path_);
    auto& bootstrap = *ctx.bootstrap;

    ASSERT_TRUE(bootstrap.auth_manager().authenticate("alice", "real-master-pw").is_ok());
    EXPECT_EQ(ctx.counting_gateway->probe_count(), 1U);

    OpenSslCryptoProvider crypto;
    const auto alice_dir = seed_device_bundle(bootstrap.secure_storage(), crypto, DeviceId("alice-dev-1"));
    MemorySecureStorage bob_storage;
    const auto bob_dir = seed_device_bundle(bob_storage, crypto, DeviceId("bob-dev-1"));
    ctx.inner_gateway->set_simulated_user_directory(UserId("alice"), {alice_dir});
    ctx.inner_gateway->set_simulated_user_directory(UserId("bob"), {bob_dir});

    bootstrap.initialize_ratchet_session_manager(UserId("alice"), DeviceId("alice-dev-1"));
    const std::string msg = "Sensitive operational plan";
    ASSERT_TRUE(
        bootstrap.ratchet_session_manager()
            ->encrypt_for_device(UserId("bob"), DeviceId("bob-dev-1"),
                                 std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()))
            .is_ok());
    EXPECT_EQ(bootstrap.ratchet_session_manager()->active_session_count(), 1U);

    const ConversationId cid("conv-real-1");
    ASSERT_TRUE(
        bootstrap.local_store()
            .save_conversation(Conversation(cid, ConversationType::Direct, "Ops", {UserId("alice"), UserId("bob")}))
            .is_ok());

    const std::filesystem::path cache_dir = temp_dir_ / "downloads";
    std::filesystem::create_directories(cache_dir);
    const std::filesystem::path part_file = cache_dir / "intel.pdf.part";
    {
        std::ofstream ofs(part_file, std::ios::binary | std::ios::trunc);
        ofs << "partial-encrypted-payload";
    }
    bootstrap.emergency_manager().register_shred_directory(cache_dir, {".part"});

    const std::filesystem::path log_file = temp_dir_ / "logs" / "client.log";
    ASSERT_TRUE(ClientLogger::set_log_file_path(log_file));
    ClientLogger::info("Session", "Operator workstation ready");

    // Configure Duress PIN and log out so the login screen is active.
    const std::string duress_pin = "Coerced-Pass!2026";
    ASSERT_TRUE(bootstrap.emergency_manager()
                    .configure_duress_pin(SecretString(duress_pin), PostWipeMode::DecoyWorkspace)
                    .is_ok());
    ASSERT_TRUE(bootstrap.auth_manager().logout().is_ok());
    ctx.counting_gateway->reset_probe_count();

    // Attacker forces operator to sign in; operator enters the Duress PIN.
    const auto auth_res = bootstrap.auth_manager().authenticate_with_duress_check("alice", duress_pin);
    ASSERT_TRUE(auth_res.is_ok());
    const auto& login = auth_res.value();

    EXPECT_EQ(login.outcome, AuthOutcome::DuressWipeTriggered);
    EXPECT_EQ(login.post_wipe_mode, PostWipeMode::DecoyWorkspace);
    EXPECT_TRUE(login.is_decoy_session);
    ASSERT_TRUE(login.wipe_report.has_value());
    EXPECT_EQ(login.wipe_report->trigger_source, PanicTriggerSource::DuressPin);
    EXPECT_EQ(login.wipe_report->post_wipe_mode, PostWipeMode::DecoyWorkspace);
    EXPECT_TRUE(login.wipe_report->all_critical_steps_succeeded);
    EXPECT_LT(login.wipe_report->duration_ms, 500);

    // Zero network requests leaked the duress credential.
    EXPECT_EQ(ctx.counting_gateway->probe_count(), 0U);

    // Full forensic wipe executed: volatile caches, ISecureStorage (including duress config), DB & disk files gone.
    EXPECT_EQ(bootstrap.ratchet_session_manager()->active_session_count(), 0U);
    EXPECT_TRUE(bootstrap.secure_storage().list_secret_keys().value().empty());
    EXPECT_FALSE(bootstrap.emergency_manager().has_duress_pin());
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_FALSE(std::filesystem::exists(part_file));
    EXPECT_FALSE(std::filesystem::exists(log_file));

    // Plausible empty Decoy Workspace is active with zero live credentials in storage.
    EXPECT_TRUE(bootstrap.auth_manager().is_authenticated());
    EXPECT_TRUE(bootstrap.auth_manager().is_decoy_session());
    EXPECT_EQ(bootstrap.auth_manager().current_user(), UserId("alice"));
    EXPECT_EQ(bootstrap.auth_manager().last_auth_outcome(), AuthOutcome::DuressWipeTriggered);
    EXPECT_TRUE(bootstrap.auth_manager().session_token().is_error());

    // One-shot fuse: re-entering the same duress PIN can no longer match.
    EXPECT_FALSE(bootstrap.emergency_manager().verify_duress_credential(SecretString(duress_pin)).value());
}

TEST_F(DuressPinAndDecoyTest, DuressLoginWithUnconfiguredResetAndEmergencyLockedLeavesUserUnauthenticated) {
    // Subcase A: PostWipeMode::UnconfiguredReset via legacy authenticate() wrapper.
    {
        const std::filesystem::path reset_db = temp_dir_ / "reset_vault.db";
        auto ctx = create_context(reset_db);
        auto& bootstrap = *ctx.bootstrap;

        const std::string duress_pin = "wipe-reset-99";
        ASSERT_TRUE(bootstrap.emergency_manager()
                        .configure_duress_pin(SecretString(duress_pin), PostWipeMode::UnconfiguredReset)
                        .is_ok());

        ctx.counting_gateway->reset_probe_count();
        const auto res = bootstrap.auth_manager().authenticate("alice", duress_pin);
        ASSERT_TRUE(res.is_ok());
        EXPECT_FALSE(res.value());
        EXPECT_EQ(ctx.counting_gateway->probe_count(), 0U);
        EXPECT_FALSE(bootstrap.auth_manager().is_authenticated());
        EXPECT_FALSE(bootstrap.auth_manager().is_decoy_session());
        EXPECT_EQ(bootstrap.auth_manager().last_auth_outcome(), AuthOutcome::DuressWipeTriggered);
        EXPECT_EQ(bootstrap.auth_manager().last_post_wipe_mode(), PostWipeMode::UnconfiguredReset);
        EXPECT_TRUE(bootstrap.secure_storage().list_secret_keys().value().empty());
        EXPECT_FALSE(std::filesystem::exists(reset_db));
    }

    // Subcase B: PostWipeMode::EmergencyLocked.
    {
        const std::filesystem::path lock_db = temp_dir_ / "lock_vault.db";
        auto ctx = create_context(lock_db);
        auto& bootstrap = *ctx.bootstrap;

        const std::string duress_pin = "wipe-lock-88";
        ASSERT_TRUE(bootstrap.emergency_manager()
                        .configure_duress_pin(SecretString(duress_pin), PostWipeMode::EmergencyLocked)
                        .is_ok());

        ctx.counting_gateway->reset_probe_count();
        const auto res = bootstrap.auth_manager().authenticate_with_duress_check("alice", duress_pin);
        ASSERT_TRUE(res.is_ok());
        EXPECT_EQ(res.value().outcome, AuthOutcome::DuressWipeTriggered);
        EXPECT_EQ(res.value().post_wipe_mode, PostWipeMode::EmergencyLocked);
        EXPECT_FALSE(res.value().is_decoy_session);
        EXPECT_EQ(ctx.counting_gateway->probe_count(), 0U);
        EXPECT_FALSE(bootstrap.auth_manager().is_authenticated());
        EXPECT_FALSE(bootstrap.auth_manager().is_decoy_session());
        EXPECT_EQ(bootstrap.auth_manager().last_post_wipe_mode(), PostWipeMode::EmergencyLocked);
        EXPECT_TRUE(bootstrap.secure_storage().list_secret_keys().value().empty());
        EXPECT_FALSE(std::filesystem::exists(lock_db));
    }
}

TEST_F(DuressPinAndDecoyTest, NormalPasswordLoginWithDuressConfiguredPreservesVaultAndLogoutClearsDecoyState) {
    auto ctx = create_context(db_path_);
    auto& bootstrap = *ctx.bootstrap;

    const std::string duress_pin = "duress-999999";
    ASSERT_TRUE(bootstrap.emergency_manager()
                    .configure_duress_pin(SecretString(duress_pin), PostWipeMode::DecoyWorkspace)
                    .is_ok());

    ctx.counting_gateway->reset_probe_count();
    const auto normal_res = bootstrap.auth_manager().authenticate("alice", "real-password-123456");
    ASSERT_TRUE(normal_res.is_ok());
    EXPECT_TRUE(normal_res.value());
    EXPECT_EQ(ctx.counting_gateway->probe_count(), 1U);
    EXPECT_TRUE(bootstrap.auth_manager().is_authenticated());
    EXPECT_FALSE(bootstrap.auth_manager().is_decoy_session());
    EXPECT_EQ(bootstrap.auth_manager().last_auth_outcome(), AuthOutcome::Authenticated);
    EXPECT_TRUE(bootstrap.emergency_manager().has_duress_pin());
    EXPECT_TRUE(std::filesystem::exists(db_path_));
    EXPECT_TRUE(bootstrap.auth_manager().session_token().is_ok());

    // Transition via duress into decoy workspace, then confirm logout() resets decoy state cleanly.
    ASSERT_TRUE(bootstrap.auth_manager().logout().is_ok());
    const auto decoy_res = bootstrap.auth_manager().authenticate_with_duress_check("alice", duress_pin);
    ASSERT_TRUE(decoy_res.is_ok());
    EXPECT_TRUE(bootstrap.auth_manager().is_decoy_session());

    ASSERT_TRUE(bootstrap.auth_manager().logout().is_ok());
    EXPECT_FALSE(bootstrap.auth_manager().is_authenticated());
    EXPECT_FALSE(bootstrap.auth_manager().is_decoy_session());
    EXPECT_FALSE(bootstrap.auth_manager().last_auth_outcome().has_value());
    EXPECT_TRUE(bootstrap.auth_manager().current_user().empty());
}

TEST_F(DuressPinAndDecoyTest, ProgrammaticTriggerDuressWipeAndZeroLogLeakage) {
    std::vector<std::string> captured_logs;
    ClientLogger::set_custom_sink(
        [&captured_logs](LogLevel /*level*/, std::string_view /*tag*/, std::string_view message,
                         std::string_view /*correlation_id*/) { captured_logs.emplace_back(message); });

    auto ctx = create_context(db_path_);
    auto& bootstrap = *ctx.bootstrap;

    const std::filesystem::path log_file = temp_dir_ / "logs" / "duress_audit.log";
    ASSERT_TRUE(ClientLogger::set_log_file_path(log_file));
    ClientLogger::info("AuthTest", "Setting up workstation credentials");

    const std::string duress_pin = "SecretDuress#777";
    ASSERT_TRUE(bootstrap.emergency_manager()
                    .configure_duress_pin(SecretString(duress_pin), PostWipeMode::DecoyWorkspace)
                    .is_ok());

    const auto cfg_secret = bootstrap.secure_storage().get_secret(std::string(DuressPinConfig::kStorageKey));
    ASSERT_TRUE(cfg_secret.is_ok());
    const auto parsed_cfg = DuressPinConfig::from_json(cfg_secret.value().expose_unredacted_secret());
    ASSERT_TRUE(parsed_cfg.has_value());

    ctx.counting_gateway->reset_probe_count();
    const auto wipe_res = bootstrap.auth_manager().trigger_duress_wipe("decoy-alice");
    ASSERT_TRUE(wipe_res.is_ok());
    EXPECT_EQ(wipe_res.value().trigger_source, PanicTriggerSource::DuressPin);
    EXPECT_EQ(wipe_res.value().post_wipe_mode, PostWipeMode::DecoyWorkspace);
    EXPECT_LT(wipe_res.value().duration_ms, 500);
    EXPECT_EQ(ctx.counting_gateway->probe_count(), 0U);

    EXPECT_TRUE(bootstrap.auth_manager().is_authenticated());
    EXPECT_TRUE(bootstrap.auth_manager().is_decoy_session());
    EXPECT_EQ(bootstrap.auth_manager().current_user(), UserId("decoy-alice"));
    EXPECT_TRUE(bootstrap.secure_storage().list_secret_keys().value().empty());
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_FALSE(std::filesystem::exists(log_file));

    for (const auto& entry : captured_logs) {
        EXPECT_EQ(entry.find(duress_pin), std::string::npos);
        EXPECT_EQ(entry.find(parsed_cfg->salt_hex), std::string::npos);
        EXPECT_EQ(entry.find(parsed_cfg->derived_hash_hex), std::string::npos);
    }

    const std::string redacted =
        ClientLogger::sanitize("duress_pin=" + duress_pin + " salt_hex=" + parsed_cfg->salt_hex +
                               " derived_hash_hex=" + parsed_cfg->derived_hash_hex);
    EXPECT_EQ(redacted.find(duress_pin), std::string::npos);
    EXPECT_EQ(redacted.find(parsed_cfg->salt_hex), std::string::npos);
    EXPECT_EQ(redacted.find(parsed_cfg->derived_hash_hex), std::string::npos);
}

} // namespace
} // namespace securecloud::client::application::managers::test
