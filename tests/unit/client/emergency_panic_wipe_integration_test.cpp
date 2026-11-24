#include "application/client_application.hpp"
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
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/window_state_manager.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <span>
#include <string>
#include <vector>

namespace securecloud::client::integration::test {
namespace {

using namespace std::chrono_literals;
using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;
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
    };
}

class AckingAndCountingGateway final : public IGatewayClient {
  public:
    AckingAndCountingGateway(std::shared_ptr<DefaultGatewayClient> inner, bool ack_on_second_poll)
        : inner_(std::move(inner)), ack_on_second_poll_(ack_on_second_poll) {}

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
    bool ack_on_second_poll_{false};
    std::size_t status_polls_{0U};
    std::atomic<std::size_t> probe_count_{0U};
};

struct IntegrationQmlWarningCapture {
    inline static std::vector<std::string> warnings;
    inline static QtMessageHandler previous{nullptr};

    static void handler(QtMsgType type, const QMessageLogContext& context, const QString& msg) {
        const std::string category = context.category != nullptr ? context.category : "";
        if ((type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg) && category != "qt.qpa.fonts") {
            const std::string text = msg.toStdString();
            if (text.find("Populating font family aliases") == std::string::npos) {
                warnings.push_back(text);
            }
        }
        if (previous != nullptr) {
            previous(type, context, msg);
        }
    }
};

class EmergencyPanicWipeIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_e2e_panic_" + suffix);
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
        auto gw = std::make_unique<AckingAndCountingGateway>(std::move(shared_gw), ack_on_second_poll);
        return ClientBootstrap::create_with_adapters(cfg, std::move(gw), std::move(store), std::move(storage),
                                                     std::move(crypto));
    }

    [[nodiscard]] ClientConfig make_config() const {
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = db_path_.string();
        return cfg;
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(EmergencyPanicWipeIntegrationTest, Scenario1_Sub500MsForensicWipeAcrossActiveVaultRatchetsFilesAndLogs) {
    ClientConfig cfg = make_config();
    ClientBootstrap bootstrap(cfg);

    ASSERT_TRUE(bootstrap.auth_manager().authenticate("alice", "MasterPassphrase!2026").is_ok());

    OpenSslCryptoProvider crypto;
    const auto alice_dir = seed_device_bundle(bootstrap.secure_storage(), crypto, DeviceId("alice-dev-1"));
    MemorySecureStorage bob_storage;
    const auto bob_dir = seed_device_bundle(bob_storage, crypto, DeviceId("bob-dev-1"));

    auto* sim_gw = dynamic_cast<DefaultGatewayClient*>(&bootstrap.gateway());
    ASSERT_NE(sim_gw, nullptr);
    sim_gw->set_simulated_user_directory(UserId("alice"), {alice_dir});
    sim_gw->set_simulated_user_directory(UserId("bob"), {bob_dir});

    bootstrap.initialize_ratchet_session_manager(UserId("alice"), DeviceId("alice-dev-1"));

    // 1. Active 1:1 Double Ratchet session.
    const std::string direct_msg = "E2E pairwise secret";
    ASSERT_TRUE(bootstrap.ratchet_session_manager()
                    ->encrypt_for_device(UserId("bob"), DeviceId("bob-dev-1"),
                                         std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(direct_msg.data()),
                                                                  direct_msg.size()))
                    .is_ok());
    EXPECT_EQ(bootstrap.ratchet_session_manager()->active_session_count(), 1U);

    // 2. Group conversation generating Sender Key state in ISecureStorage + staged offline retry item.
    const auto group_res = bootstrap.messaging_manager().create_group_conversation(UserId("alice"), "E2E Ops Group",
                                                                                   {UserId("alice"), UserId("bob")});
    ASSERT_TRUE(group_res.is_ok());
    const ConversationId group_cid = group_res.value().conversation_id();
    ASSERT_TRUE(bootstrap.messaging_manager()
                    .stage_outbound_message(group_cid, UserId("alice"), DeviceId("alice-dev-1"), "Group key init")
                    .is_ok());

    sim_gw->set_simulated_submission_failure(true, "Simulated offline");
    ASSERT_TRUE(bootstrap.messaging_manager()
                    .stage_outbound_message(group_cid, UserId("alice"), DeviceId("alice-dev-1"), "Queued offline draft")
                    .is_ok());
    EXPECT_EQ(bootstrap.messaging_manager().pending_retry_count(), 1U);
    sim_gw->set_simulated_submission_failure(false);

    // 3. In-progress FileTransferRecord, partial .part cache, file key secret, Duress PIN, and disk log.
    const std::filesystem::path dl_dest = temp_dir_ / "downloads" / "mission.bin";
    const std::filesystem::path dl_part = std::filesystem::path(dl_dest.string() + ".part");
    std::filesystem::create_directories(dl_dest.parent_path());
    {
        std::ofstream ofs(dl_part, std::ios::binary | std::ios::trunc);
        ofs << "partial-encrypted-download-sector-bytes";
    }
    FileTransferRecord tx_rec;
    tx_rec.transfer_id = "tx-e2e-1";
    tx_rec.file_id = "file-e2e-1";
    tx_rec.conversation_id = group_cid;
    tx_rec.direction = FileTransferDirection::Inbound;
    tx_rec.status = FileTransferStatus::InProgress;
    tx_rec.file_name = "mission.bin";
    tx_rec.local_path = dl_dest.string();
    ASSERT_TRUE(bootstrap.local_store().save_file_transfer(tx_rec).is_ok());

    const std::filesystem::path cache_dir = temp_dir_ / "cache";
    std::filesystem::create_directories(cache_dir);
    const std::filesystem::path cache_part = cache_dir / "chunk_0.part";
    {
        std::ofstream ofs(cache_part, std::ios::binary | std::ios::trunc);
        ofs << "cached-chunk-bytes";
    }
    bootstrap.emergency_manager().register_shred_directory(cache_dir, {".part"});

    ASSERT_TRUE(bootstrap.secure_storage()
                    .store_secret("file_transfer.key.file-e2e-1", SecretString("00112233445566778899aabbccddeeff"))
                    .is_ok());
    ASSERT_TRUE(bootstrap.emergency_manager()
                    .configure_duress_pin(SecretString("E2e-Duress!2026"), PostWipeMode::EmergencyLocked)
                    .is_ok());

    const std::filesystem::path log_file = temp_dir_ / "logs" / "client_e2e.log";
    ASSERT_TRUE(ClientLogger::set_log_file_path(log_file));
    ClientLogger::info("E2ETest", "Workstation active prior to panic wipe");

    ASSERT_GE(bootstrap.secure_storage().list_secret_keys().value().size(), 5U);
    ASSERT_TRUE(std::filesystem::exists(db_path_));
    ASSERT_TRUE(std::filesystem::exists(dl_part));
    ASSERT_TRUE(std::filesystem::exists(cache_part));
    ASSERT_TRUE(std::filesystem::exists(log_file));

    // Execute full 3-phase forensic wipe.
    const auto report_res =
        bootstrap.emergency_manager().execute_panic_wipe(PanicTriggerSource::Hotkey, PostWipeMode::EmergencyLocked);
    ASSERT_TRUE(report_res.is_ok());
    const auto& report = report_res.value();

    EXPECT_TRUE(report.all_critical_steps_succeeded);
    EXPECT_LT(report.duration_ms, 500);
    EXPECT_GE(report.secrets_purged_count, 5U);
    EXPECT_GE(report.files_shredded_count, 4U);
    EXPECT_EQ(report.volatile_caches_cleared, 5U);

    EXPECT_FALSE(bootstrap.auth_manager().is_authenticated());
    EXPECT_EQ(bootstrap.ratchet_session_manager()->active_session_count(), 0U);
    EXPECT_EQ(bootstrap.messaging_manager().pending_retry_count(), 0U);
    EXPECT_FALSE(bootstrap.emergency_manager().has_duress_pin());
    EXPECT_TRUE(bootstrap.secure_storage().list_secret_keys().value().empty());
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_FALSE(std::filesystem::exists(dl_part));
    EXPECT_FALSE(std::filesystem::exists(cache_part));
    EXPECT_FALSE(std::filesystem::exists(log_file));
}

TEST_F(EmergencyPanicWipeIntegrationTest, Scenario2_PreWipeE2eeEmergencyBroadcastWithLocationAckAndOfflineFailSafe) {
    // Subcase A: Priority=3 E2EE distress alert + encrypted location JSON acknowledged before wipe.
    {
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

        const ConversationId cid("conv-secops-e2e");
        ASSERT_TRUE(
            bootstrap->local_store()
                .save_conversation(Conversation(cid, ConversationType::Direct, "SecOps Lead", {alice_uid, bob_uid}))
                .is_ok());

        EmergencyBroadcastRequest req;
        req.conversation_id = cid;
        req.sender_user_id = alice_uid;
        req.sender_device_id = alice_did;
        req.alert_plaintext = "E2E PANIC: Field device seized";
        req.encrypted_location_json = R"({"lat":46.948,"lon":7.447,"zone":"HQ-North"})";
        req.wait_for_acknowledgement = true;
        req.ack_timeout = 500ms;

        const auto wipe_res = bootstrap->emergency_manager().execute_broadcast_and_wipe(
            req, PanicTriggerSource::UiPanicButton, PostWipeMode::EmergencyLocked);
        ASSERT_TRUE(wipe_res.is_ok());
        EXPECT_TRUE(wipe_res.value().broadcast_attempted);
        EXPECT_TRUE(wipe_res.value().broadcast_acknowledged);
        EXPECT_TRUE(wipe_res.value().all_critical_steps_succeeded);
        EXPECT_LT(wipe_res.value().duration_ms, 500);
        EXPECT_FALSE(std::filesystem::exists(db_path_));
        EXPECT_TRUE(bootstrap->secure_storage().list_secret_keys().value().empty());

        ASSERT_EQ(shared_gw->submitted_fanouts().size(), 1U);
        const auto& fanout = shared_gw->submitted_fanouts().front();
        EXPECT_EQ(fanout.priority, 3);
        ASSERT_FALSE(fanout.device_payloads.empty());
        const auto& payload = fanout.device_payloads.front();
        EXPECT_EQ(payload.ciphertext_blob.find("Field device seized"), std::string::npos);
        EXPECT_EQ(payload.ciphertext_blob.find("HQ-North"), std::string::npos);

        RatchetSessionManager bob_ratchet(*shared_gw, bob_storage, crypto, bob_uid, bob_did);
        const auto dec_res = bob_ratchet.decrypt_payload_from_device(alice_uid, alice_did, payload);
        ASSERT_TRUE(dec_res.is_ok());
        const auto parsed = nlohmann::json::parse(dec_res.value().expose_unredacted_secret());
        EXPECT_EQ(parsed.at("type"), "securecloud.emergency_broadcast.v1");
        EXPECT_EQ(parsed.at("alert"), req.alert_plaintext);
        EXPECT_EQ(parsed.at("location").at("zone"), "HQ-North");
    }

    // Subcase B: Offline Gateway never blocks or stalls Phase 1-3 local destruction.
    {
        const std::filesystem::path offline_db = temp_dir_ / "offline_e2e_vault.db";
        auto shared_gw = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
        auto bootstrap = create_sqlcipher_bootstrap(offline_db, shared_gw, /*ack_on_second_poll=*/false);

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
        const ConversationId cid("conv-offline-e2e");
        ASSERT_TRUE(
            bootstrap->local_store()
                .save_conversation(Conversation(cid, ConversationType::Direct, "SecOps Lead", {alice_uid, bob_uid}))
                .is_ok());

        shared_gw->set_simulated_failure(true, "Air-gapped outage");

        EmergencyBroadcastRequest req;
        req.conversation_id = cid;
        req.sender_user_id = alice_uid;
        req.sender_device_id = alice_did;
        req.alert_plaintext = "Offline distress signal";
        req.wait_for_acknowledgement = true;
        req.ack_timeout = 30ms;

        const auto wipe_res = bootstrap->emergency_manager().execute_broadcast_and_wipe(req, PanicTriggerSource::Hotkey,
                                                                                        PostWipeMode::EmergencyLocked);
        ASSERT_TRUE(wipe_res.is_ok());
        EXPECT_TRUE(wipe_res.value().broadcast_attempted);
        EXPECT_FALSE(wipe_res.value().broadcast_acknowledged);
        EXPECT_TRUE(wipe_res.value().all_critical_steps_succeeded);
        EXPECT_LT(wipe_res.value().duration_ms, 500);
        EXPECT_FALSE(std::filesystem::exists(offline_db));
        EXPECT_TRUE(bootstrap->secure_storage().list_secret_keys().value().empty());
    }
}

TEST_F(EmergencyPanicWipeIntegrationTest, Scenario3_LoginDuressPinSilentWipeToPlausibleDecoyWorkspace) {
    ClientApplication app(make_config());
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    WorkspaceViewModel workspace_vm(app, nav);
    app_vm.setWorkspaceViewModel(&workspace_vm);

    app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("Real-Master-Pw!2026"));
    ASSERT_TRUE(workspace_vm.addContact(QStringLiteral("bob@securecloud.org"), QStringLiteral("Bob Operator"),
                                        QStringLiteral("SecOps Lead")));
    const QString conv_id =
        workspace_vm.conversations().first().toMap().value(QStringLiteral("conversationId")).toString();
    workspace_vm.selectConversation(conv_id);
    ASSERT_TRUE(workspace_vm.sendMessage(QStringLiteral("Classified mission debrief")));
    EXPECT_FALSE(workspace_vm.conversations().isEmpty());
    EXPECT_FALSE(workspace_vm.activeMessages().isEmpty());

    const QString duress_pass = QStringLiteral(" Autumn-Backup-42! ");
    ASSERT_TRUE(app_vm.configureDuressPin(duress_pass, 2)); // PostWipeMode::DecoyWorkspace
    EXPECT_TRUE(app_vm.hasDuressPinConfigured());
    app_vm.requestLogout();

    // Attacker forces operator login; operator supplies Duress PIN into standard password field.
    app_vm.requestLogin(QStringLiteral("alice"), duress_pass);

    const auto report_opt = app.bootstrap().emergency_manager().last_wipe_report();
    ASSERT_TRUE(report_opt.has_value());
    EXPECT_EQ(report_opt->trigger_source, PanicTriggerSource::DuressPin);
    EXPECT_TRUE(report_opt->all_critical_steps_succeeded);
    EXPECT_LT(report_opt->duration_ms, 500);

    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_TRUE(app.bootstrap().secure_storage().list_secret_keys().value().empty());
    EXPECT_FALSE(app_vm.hasDuressPinConfigured());

    EXPECT_TRUE(app_vm.isAuthenticated());
    EXPECT_TRUE(app_vm.isDecoySession());
    EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::MainWorkspace);
    EXPECT_TRUE(workspace_vm.conversations().isEmpty());
    EXPECT_TRUE(workspace_vm.activeMessages().isEmpty());
    EXPECT_TRUE(app_vm.lastWipeReportSummary().isEmpty());
    EXPECT_EQ(app_vm.connectionStatus(), QStringLiteral("Connected"));
    EXPECT_EQ(app_vm.securityBadgeType(), QStringLiteral("Info"));
    EXPECT_FALSE(app_vm.sessionStatusText().contains(QStringLiteral("Wipe")));

    (void)app.shutdown();
}

TEST_F(EmergencyPanicWipeIntegrationTest, Scenario4_CleanUnconfiguredResetAndFreshReOnboardingAfterPanicWipe) {
    ClientApplication app(make_config());
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    WorkspaceViewModel workspace_vm(app, nav);
    app_vm.setWorkspaceViewModel(&workspace_vm);

    app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("Initial-Pw!2026"));
    ASSERT_TRUE(workspace_vm.addContact(QStringLiteral("charlie@securecloud.org"), QStringLiteral("Charlie"),
                                        QStringLiteral("Analyst")));
    EXPECT_TRUE(std::filesystem::exists(db_path_));

    // Panic wipe with UnconfiguredReset followed by UI resetClientAfterWipe.
    app_vm.triggerInstantPanicWipe(1);
    EXPECT_FALSE(std::filesystem::exists(db_path_));
    EXPECT_TRUE(app.bootstrap().secure_storage().list_secret_keys().value().empty());
    EXPECT_EQ(nav.currentState(), NavigationController::NavigationState::Unauthenticated);

    app_vm.resetClientAfterWipe();
    EXPECT_FALSE(app_vm.isEmergencyWiped());
    EXPECT_FALSE(app_vm.isDecoySession());

    // Re-onboard onto fresh SQLCipher database without stale state or lock errors.
    ASSERT_TRUE(app.bootstrap().local_store().open(db_path_.string()).is_ok());
    app_vm.requestLogin(QStringLiteral("alice-reborn"), QStringLiteral("Fresh-Pw!2026"));
    EXPECT_TRUE(app_vm.isAuthenticated());
    EXPECT_FALSE(app_vm.isDecoySession());
    EXPECT_TRUE(std::filesystem::exists(db_path_));

    ASSERT_TRUE(workspace_vm.addContact(QStringLiteral("dana@securecloud.org"), QStringLiteral("Dana"),
                                        QStringLiteral("Fresh Peer")));
    const QString fresh_cid =
        workspace_vm.conversations().first().toMap().value(QStringLiteral("conversationId")).toString();
    workspace_vm.selectConversation(fresh_cid);
    ASSERT_TRUE(workspace_vm.sendMessage(QStringLiteral("Clean re-onboarded session verified")));
    EXPECT_EQ(workspace_vm.conversations().size(), 1);
    EXPECT_EQ(workspace_vm.activeMessages().size(), 1);

    (void)app.shutdown();
}

TEST_F(EmergencyPanicWipeIntegrationTest, Scenario5_HeadlessQmlPanicModalTelemetryCardAndDecoyLifecycle) {
    IntegrationQmlWarningCapture::warnings.clear();
    IntegrationQmlWarningCapture::previous = qInstallMessageHandler(&IntegrationQmlWarningCapture::handler);

    ClientApplication app(make_config());
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    NavigationController nav;
    AppViewModel app_vm(app, nav);
    WorkspaceViewModel workspace_vm(app, nav);
    app_vm.setWorkspaceViewModel(&workspace_vm);
    UiTheme theme;
    WindowStateManager win_state;

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &app_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspace_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &win_state);

    QQmlComponent main_comp(&engine, QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    ASSERT_TRUE(main_comp.isReady()) << main_comp.errorString().toStdString();
    QObject* main_obj = main_comp.create();
    ASSERT_NE(main_obj, nullptr);

    QQmlComponent emergency_comp(&engine, QUrl(QStringLiteral("qrc:/qml/EmergencyPlaceholder.qml")));
    ASSERT_TRUE(emergency_comp.isReady()) << emergency_comp.errorString().toStdString();
    QObject* emergency_obj = emergency_comp.create();
    ASSERT_NE(emergency_obj, nullptr);

    QQmlComponent settings_comp(&engine, QUrl(QStringLiteral("qrc:/qml/SettingsPlaceholder.qml")));
    ASSERT_TRUE(settings_comp.isReady()) << settings_comp.errorString().toStdString();
    QObject* settings_obj = settings_comp.create();
    ASSERT_NE(settings_obj, nullptr);

    // 1. Live panic wipe populates EmergencyPlaceholder telemetry bindings.
    app_vm.triggerInstantPanicWipe(0);
    QCoreApplication::processEvents();
    EXPECT_TRUE(emergency_obj->property("hasReport").toBool());
    EXPECT_NE(emergency_obj->findChild<QObject*>(QStringLiteral("resetAfterWipeButton")), nullptr);
    theme.setThemeMode(ThemeMode::Dark);
    QCoreApplication::processEvents();
    theme.setThemeMode(ThemeMode::Light);
    QCoreApplication::processEvents();

    // 2. Reset, re-open DB, configure Duress PIN, and verify Decoy UI suppression in Main.qml.
    app_vm.resetClientAfterWipe();
    ASSERT_TRUE(app.bootstrap().local_store().open(db_path_.string()).is_ok());
    ASSERT_TRUE(app_vm.configureDuressPin(QStringLiteral("e2e-qml-duress"), 2));
    app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("e2e-qml-duress"));
    QCoreApplication::processEvents();

    EXPECT_TRUE(app_vm.isDecoySession());
    EXPECT_TRUE(main_obj->property("showAuthenticatedChrome").toBool());
    theme.setThemeMode(ThemeMode::Dark);
    QCoreApplication::processEvents();
    theme.setThemeMode(ThemeMode::Light);
    QCoreApplication::processEvents();

    delete settings_obj;
    delete emergency_obj;
    delete main_obj;
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();

    qInstallMessageHandler(IntegrationQmlWarningCapture::previous);
    EXPECT_TRUE(IntegrationQmlWarningCapture::warnings.empty())
        << (IntegrationQmlWarningCapture::warnings.empty() ? "" : IntegrationQmlWarningCapture::warnings.front());

    (void)app.shutdown();
}

} // namespace
} // namespace securecloud::client::integration::test
