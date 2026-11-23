#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/auth_manager.hpp"
#include "application/managers/emergency_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/emergency_models.hpp"
#include "domain/file_transfer.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "infrastructure/client_logger.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::client::application::managers::test {
namespace {

using namespace std::chrono_literals;
using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure;
using namespace securecloud::client::infrastructure::adapters;

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
    };
}

class AckingGatewayAdapter final : public IGatewayClient {
  public:
    explicit AckingGatewayAdapter(std::shared_ptr<DefaultGatewayClient> inner, bool ack_on_second_poll = false)
        : inner_(std::move(inner)), ack_on_second_poll_(ack_on_second_poll) {}

    void set_ack_on_second_poll(bool enabled) noexcept {
        ack_on_second_poll_ = enabled;
        status_polls_ = 0U;
    }

    ClientResult<bool> probe_gateway(std::string_view path) override { return inner_->probe_gateway(path); }
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
        auto base = inner_->get_message_delivery_status(conversation_id, message_id);
        if (base.is_error()) {
            return base;
        }
        ++status_polls_;
        if (ack_on_second_poll_ && status_polls_ >= 2U) {
            auto info = base.value();
            info.delivery_state = DeliveryState::Delivered;
            return ClientResult<MessageDeliveryStatusInfo>::ok(info);
        }
        return base;
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

  private:
    std::shared_ptr<DefaultGatewayClient> inner_;
    bool ack_on_second_poll_{false};
    std::size_t status_polls_{0U};
};

class EmergencyWipePipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_emergency_pipeline_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "vault.db";
    }

    void TearDown() override {
        (void)ClientLogger::flush_and_close_log_file();
        ClientLogger::reset_sink();
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::unique_ptr<ClientBootstrap> create_sqlcipher_bootstrap(const std::filesystem::path& db_file,
                                                                       std::shared_ptr<DefaultGatewayClient> shared_gw,
                                                                       bool ack_on_second_poll) {
        auto storage = std::make_unique<MemorySecureStorage>();
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto store = std::make_unique<SqlCipherLocalStore>(*storage, *crypto);
        EXPECT_TRUE(store->open(db_file.string()).is_ok());

        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = db_file.string();
        auto gw = std::make_unique<AckingGatewayAdapter>(std::move(shared_gw), ack_on_second_poll);
        return ClientBootstrap::create_with_adapters(cfg, std::move(gw), std::move(store), std::move(storage),
                                                     std::move(crypto));
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(EmergencyWipePipelineTest, FullThreePhaseDestructionCompletesUnder500MsAndZeroizesAllLayers) {
    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_.string();

    ClientBootstrap bootstrap(cfg);

    // 1. Authenticate session, seed local device keys, and initialize RatchetSessionManager via ClientBootstrap.
    ASSERT_TRUE(bootstrap.auth_manager().authenticate("alice", "strong-passphrase").is_ok());
    ASSERT_TRUE(bootstrap.auth_manager().is_authenticated());
    OpenSslCryptoProvider crypto;
    const auto alice_dir = seed_device_bundle(bootstrap.secure_storage(), crypto, DeviceId("alice-dev-1"));
    bootstrap.initialize_ratchet_session_manager(UserId("alice"), DeviceId("alice-dev-1"));
    ASSERT_NE(bootstrap.ratchet_session_manager(), nullptr);

    // 2. Establish real Double Ratchet session with Bob via OpenSslCryptoProvider.
    MemorySecureStorage bob_storage;
    const auto bob_dir = seed_device_bundle(bob_storage, crypto, DeviceId("bob-dev-1"));
    auto* sim_gw = dynamic_cast<DefaultGatewayClient*>(&bootstrap.gateway());
    ASSERT_NE(sim_gw, nullptr);
    sim_gw->set_simulated_user_directory(UserId("alice"), {alice_dir});
    sim_gw->set_simulated_user_directory(UserId("bob"), {bob_dir});

    const std::string msg_text = "Confidential field update";
    const auto enc_res = bootstrap.ratchet_session_manager()->encrypt_for_device(
        UserId("bob"), DeviceId("bob-dev-1"),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg_text.data()), msg_text.size()));
    ASSERT_TRUE(enc_res.is_ok());
    EXPECT_EQ(bootstrap.ratchet_session_manager()->active_session_count(), 1U);

    // 3. Stage offline outbox/retry entry, sync cursor, partial .part download, cache artifact & disk log.
    const ConversationId cid("conv-panic-1");
    Conversation conv(cid, ConversationType::Direct, "Ops Direct", {UserId("alice"), UserId("bob")});
    ASSERT_TRUE(bootstrap.local_store().save_conversation(conv).is_ok());

    sim_gw->set_simulated_submission_failure(true, "Simulated offline");
    const auto stage_res = bootstrap.messaging_manager().stage_outbound_message(
        cid, UserId("alice"), DeviceId("alice-dev-1"), "Queued draft");
    ASSERT_TRUE(stage_res.is_ok());
    EXPECT_EQ(bootstrap.messaging_manager().pending_retry_count(), 1U);
    sim_gw->set_simulated_submission_failure(false);

    ASSERT_TRUE(bootstrap.local_store()
                    .save_sync_cursor(SyncCursorRecord{
                        .device_id = DeviceId("alice-dev-1"),
                        .conversation_id = cid,
                        .last_delivered_sequence = 42ULL,
                        .last_sync_timestamp_ms = 1763890000000LL,
                    })
                    .is_ok());
    (void)bootstrap.sync_manager().poll_realtime_updates(DeviceId("alice-dev-1"));
    EXPECT_EQ(bootstrap.sync_manager().conversation_cursor(cid), 42ULL);

    const std::filesystem::path download_dest = temp_dir_ / "downloads" / "briefing.pdf";
    const std::filesystem::path download_part = std::filesystem::path(download_dest.string() + ".part");
    std::filesystem::create_directories(download_dest.parent_path());
    {
        std::ofstream ofs(download_part, std::ios::binary | std::ios::trunc);
        ofs << "partial-encrypted-chunk-bytes-0123456789";
    }
    FileTransferRecord tx_rec;
    tx_rec.transfer_id = "tx-partial-1";
    tx_rec.file_id = "file-partial-1";
    tx_rec.conversation_id = cid;
    tx_rec.direction = FileTransferDirection::Inbound;
    tx_rec.status = FileTransferStatus::InProgress;
    tx_rec.file_name = "briefing.pdf";
    tx_rec.local_path = download_dest.string();
    ASSERT_TRUE(bootstrap.local_store().save_file_transfer(tx_rec).is_ok());

    const std::filesystem::path extra_cache_dir = temp_dir_ / "cache";
    std::filesystem::create_directories(extra_cache_dir);
    const std::filesystem::path cache_part = extra_cache_dir / "thumbnail.part";
    {
        std::ofstream ofs(cache_part, std::ios::binary | std::ios::trunc);
        ofs << "cached-thumb-bytes";
    }
    bootstrap.emergency_manager().register_shred_directory(extra_cache_dir, {".part"});

    const std::filesystem::path log_file = temp_dir_ / "logs" / "client.log";
    ASSERT_TRUE(ClientLogger::set_log_file_path(log_file));
    ClientLogger::info("PanicTest", "Runtime activity before panic wipe");
    ASSERT_TRUE(std::filesystem::exists(db_path_));
    ASSERT_TRUE(std::filesystem::exists(download_part));
    ASSERT_TRUE(std::filesystem::exists(cache_part));
    ASSERT_TRUE(std::filesystem::exists(log_file));

    ASSERT_TRUE(bootstrap.secure_storage()
                    .store_secret("file_transfer.key.file-partial-1", common::configuration::SecretString("00112233"))
                    .is_ok());
    ASSERT_TRUE(bootstrap.secure_storage()
                    .store_secret(std::string(DuressPinConfig::kStorageKey),
                                  common::configuration::SecretString(R"({"enabled":true})"))
                    .is_ok());

    // Execute full 3-phase forensic wipe.
    const auto report_res =
        bootstrap.emergency_manager().execute_panic_wipe(PanicTriggerSource::Hotkey, PostWipeMode::EmergencyLocked);
    ASSERT_TRUE(report_res.is_ok());
    const auto& report = report_res.value();

    EXPECT_TRUE(report.all_critical_steps_succeeded);
    EXPECT_LT(report.duration_ms, 500);
    EXPECT_EQ(report.trigger_source, PanicTriggerSource::Hotkey);
    EXPECT_EQ(report.post_wipe_mode, PostWipeMode::EmergencyLocked);
    EXPECT_FALSE(report.broadcast_attempted);
    EXPECT_GT(report.secrets_purged_count, 0U);
    EXPECT_GE(report.files_shredded_count, 4U);
    EXPECT_EQ(report.volatile_caches_cleared, 5U);

    // Phase 1 volatile verification.
    EXPECT_FALSE(bootstrap.auth_manager().is_authenticated());
    EXPECT_EQ(bootstrap.ratchet_session_manager()->active_session_count(), 0U);
    EXPECT_EQ(bootstrap.messaging_manager().pending_retry_count(), 0U);
    EXPECT_EQ(bootstrap.sync_manager().conversation_cursor(cid), 0ULL);

    // Phase 2 secret storage verification.
    const auto remaining_keys = bootstrap.secure_storage().list_secret_keys();
    ASSERT_TRUE(remaining_keys.is_ok());
    EXPECT_TRUE(remaining_keys.value().empty());

    // Phase 3 on-disk verification.
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_FALSE(std::filesystem::exists(download_part));
    EXPECT_FALSE(std::filesystem::exists(cache_part));
    EXPECT_FALSE(std::filesystem::exists(log_file));
    EXPECT_TRUE(bootstrap.local_store().database_path().empty());
    EXPECT_TRUE(bootstrap.emergency_manager().is_wiped());
    ASSERT_TRUE(bootstrap.emergency_manager().last_wipe_report().has_value());
    EXPECT_EQ(*bootstrap.emergency_manager().last_wipe_report(), report);
}

TEST_F(EmergencyWipePipelineTest, PreWipeE2eeEmergencyBroadcastWithLocationAckThenImmediateWipe) {
    auto shared_gw = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
    auto bootstrap = create_sqlcipher_bootstrap(db_path_, shared_gw, /*ack_on_second_poll=*/true);

    const UserId alice_uid("alice");
    const DeviceId alice_did("alice-dev-1");
    const UserId bob_uid("bob");
    const DeviceId bob_did("bob-dev-1");

    OpenSslCryptoProvider crypto;
    const auto alice_dir = seed_device_bundle(bootstrap->secure_storage(), crypto, alice_did);

    MemorySecureStorage bob_storage;
    const auto bob_dir = seed_device_bundle(bob_storage, crypto, bob_did);

    shared_gw->set_simulated_user_directory(alice_uid, {alice_dir});
    shared_gw->set_simulated_user_directory(bob_uid, {bob_dir});

    ASSERT_TRUE(bootstrap->auth_manager().authenticate("alice", "pw").is_ok());
    bootstrap->initialize_ratchet_session_manager(alice_uid, alice_did);

    const ConversationId cid("conv-secops-lead");
    Conversation conv(cid, ConversationType::Direct, "SecOps Team Lead", {alice_uid, bob_uid});
    ASSERT_TRUE(bootstrap->local_store().save_conversation(conv).is_ok());

    EmergencyBroadcastRequest broadcast_req;
    broadcast_req.conversation_id = cid;
    broadcast_req.sender_user_id = alice_uid;
    broadcast_req.sender_device_id = alice_did;
    broadcast_req.alert_plaintext = "PANIC WIPE INITIATED: Device compromised";
    broadcast_req.encrypted_location_json = R"({"lat":46.948,"lon":7.447,"accuracy_m":10})";
    broadcast_req.wait_for_acknowledgement = true;
    broadcast_req.ack_timeout = 500ms;

    const auto wipe_res = bootstrap->emergency_manager().execute_broadcast_and_wipe(
        broadcast_req, PanicTriggerSource::UiPanicButton, PostWipeMode::EmergencyLocked);
    ASSERT_TRUE(wipe_res.is_ok());
    const auto& report = wipe_res.value();

    EXPECT_TRUE(report.broadcast_attempted);
    EXPECT_TRUE(report.broadcast_acknowledged);
    EXPECT_TRUE(report.all_critical_steps_succeeded);
    EXPECT_LT(report.duration_ms, 500);

    // Gateway received priority=3 E2EE payload without plaintext leak; Bob decrypts with standard Double Ratchet.
    ASSERT_EQ(shared_gw->submitted_fanouts().size(), 1U);
    const auto& fanout = shared_gw->submitted_fanouts().front();
    EXPECT_EQ(fanout.priority, 3);
    ASSERT_FALSE(fanout.device_payloads.empty());

    const auto& bob_payload = fanout.device_payloads.front();
    EXPECT_EQ(bob_payload.ciphertext_blob.find("Device compromised"), std::string::npos);

    RatchetSessionManager bob_ratchet(*shared_gw, bob_storage, crypto, bob_uid, bob_did);
    const auto dec_res = bob_ratchet.decrypt_payload_from_device(alice_uid, alice_did, bob_payload);
    ASSERT_TRUE(dec_res.is_ok());

    const auto parsed_alert = nlohmann::json::parse(dec_res.value().expose_unredacted_secret());
    EXPECT_EQ(parsed_alert.at("type"), "securecloud.emergency_broadcast.v1");
    EXPECT_EQ(parsed_alert.at("alert"), broadcast_req.alert_plaintext);
    EXPECT_EQ(parsed_alert.at("location").at("lat").get<double>(), 46.948);

    // Alice's vault & keys were immediately shredded right after the broadcast.
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_TRUE(bootstrap->secure_storage().list_secret_keys().value().empty());
    EXPECT_TRUE(bootstrap->emergency_manager().is_wiped());
}

TEST_F(EmergencyWipePipelineTest, FailSafeOfflineAndTimeoutBroadcastNeverBlocksLocalWipe) {
    // Subcase A: Network completely offline -> broadcast fails, local wipe completes unconditionally.
    {
        const std::filesystem::path offline_db = temp_dir_ / "offline_vault.db";
        auto shared_gw = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
        auto bootstrap = create_sqlcipher_bootstrap(offline_db, shared_gw, /*ack_on_second_poll=*/false);

        const UserId alice_uid("alice");
        const DeviceId alice_did("alice-dev-1");
        const UserId bob_uid("bob");
        const DeviceId bob_did("bob-dev-1");

        OpenSslCryptoProvider crypto;
        const auto alice_dir = seed_device_bundle(bootstrap->secure_storage(), crypto, alice_did);
        MemorySecureStorage bob_storage;
        const auto bob_dir = seed_device_bundle(bob_storage, crypto, bob_did);
        shared_gw->set_simulated_user_directory(alice_uid, {alice_dir});
        shared_gw->set_simulated_user_directory(bob_uid, {bob_dir});

        bootstrap->initialize_ratchet_session_manager(alice_uid, alice_did);

        const ConversationId cid("conv-offline-panic");
        Conversation conv(cid, ConversationType::Direct, "Team Lead", {alice_uid, bob_uid});
        ASSERT_TRUE(bootstrap->local_store().save_conversation(conv).is_ok());

        // Pre-warm X3DH directory lookup while online, then cut network submission.
        shared_gw->set_simulated_submission_failure(true, "Gateway unreachable");

        EmergencyBroadcastRequest req;
        req.conversation_id = cid;
        req.sender_user_id = alice_uid;
        req.sender_device_id = alice_did;
        req.alert_plaintext = "Distress offline attempt";
        req.wait_for_acknowledgement = true;
        req.ack_timeout = 50ms;

        const auto wipe_res = bootstrap->emergency_manager().execute_broadcast_and_wipe(
            req, PanicTriggerSource::UiPanicButton, PostWipeMode::EmergencyLocked);
        ASSERT_TRUE(wipe_res.is_ok());
        EXPECT_TRUE(wipe_res.value().broadcast_attempted);
        EXPECT_FALSE(wipe_res.value().broadcast_acknowledged);
        EXPECT_TRUE(wipe_res.value().all_critical_steps_succeeded);
        EXPECT_LT(wipe_res.value().duration_ms, 500);
        EXPECT_FALSE(std::filesystem::exists(offline_db));
        EXPECT_TRUE(bootstrap->secure_storage().list_secret_keys().value().empty());
    }

    // Subcase B: Submission accepted by Gateway, recipient never acknowledges within ack_timeout -> bounded wait then
    // wipe.
    {
        const std::filesystem::path timeout_db = temp_dir_ / "timeout_vault.db";
        auto shared_gw = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
        auto bootstrap = create_sqlcipher_bootstrap(timeout_db, shared_gw, /*ack_on_second_poll=*/false);

        const UserId alice_uid("alice");
        const DeviceId alice_did("alice-dev-2");
        const UserId bob_uid("bob");
        const DeviceId bob_did("bob-dev-2");

        OpenSslCryptoProvider crypto;
        const auto alice_dir = seed_device_bundle(bootstrap->secure_storage(), crypto, alice_did);
        MemorySecureStorage bob_storage;
        const auto bob_dir = seed_device_bundle(bob_storage, crypto, bob_did);
        shared_gw->set_simulated_user_directory(alice_uid, {alice_dir});
        shared_gw->set_simulated_user_directory(bob_uid, {bob_dir});

        bootstrap->initialize_ratchet_session_manager(alice_uid, alice_did);

        const ConversationId cid("conv-timeout-panic");
        Conversation conv(cid, ConversationType::Direct, "Team Lead", {alice_uid, bob_uid});
        ASSERT_TRUE(bootstrap->local_store().save_conversation(conv).is_ok());

        EmergencyBroadcastRequest req;
        req.conversation_id = cid;
        req.sender_user_id = alice_uid;
        req.sender_device_id = alice_did;
        req.alert_plaintext = "Distress timeout test";
        req.wait_for_acknowledgement = true;
        req.ack_timeout = 30ms;

        const auto wipe_res = bootstrap->emergency_manager().execute_broadcast_and_wipe(req, PanicTriggerSource::Hotkey,
                                                                                        PostWipeMode::EmergencyLocked);
        ASSERT_TRUE(wipe_res.is_ok());
        EXPECT_TRUE(wipe_res.value().broadcast_attempted);
        EXPECT_FALSE(wipe_res.value().broadcast_acknowledged);
        EXPECT_TRUE(wipe_res.value().all_critical_steps_succeeded);
        EXPECT_LT(wipe_res.value().duration_ms, 500);
        EXPECT_FALSE(std::filesystem::exists(timeout_db));
        EXPECT_TRUE(bootstrap->secure_storage().list_secret_keys().value().empty());
        ASSERT_TRUE(bootstrap->emergency_manager().last_broadcast_result().has_value());
        EXPECT_TRUE(bootstrap->emergency_manager().last_broadcast_result()->submitted);
        EXPECT_FALSE(bootstrap->emergency_manager().last_broadcast_result()->acknowledged);
    }
}

TEST_F(EmergencyWipePipelineTest, LegacyTriggerEmergencyWipeAndResetForFreshReOnboarding) {
    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_.string();

    ClientBootstrap bootstrap(cfg);
    ASSERT_TRUE(bootstrap.auth_manager().authenticate("alice", "pw").is_ok());

    const auto legacy_res = bootstrap.emergency_manager().trigger_emergency_wipe();
    ASSERT_TRUE(legacy_res.is_ok());
    EXPECT_TRUE(bootstrap.emergency_manager().is_wiped());
    ASSERT_TRUE(bootstrap.emergency_manager().last_wipe_report().has_value());
    EXPECT_EQ(bootstrap.emergency_manager().last_wipe_report()->trigger_source, PanicTriggerSource::Programmatic);
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_TRUE(bootstrap.secure_storage().list_secret_keys().value().empty());

    // Reset state cleanly for fresh onboarding onto a new vault.
    bootstrap.emergency_manager().reset_wiped_state();
    EXPECT_FALSE(bootstrap.emergency_manager().is_wiped());
    EXPECT_FALSE(bootstrap.emergency_manager().last_wipe_report().has_value());
    EXPECT_TRUE(bootstrap.local_store().open(db_path_.string()).is_ok());
    EXPECT_TRUE(bootstrap.auth_manager().authenticate("alice", "new-pw").is_ok());
}

} // namespace
} // namespace securecloud::client::application::managers::test
