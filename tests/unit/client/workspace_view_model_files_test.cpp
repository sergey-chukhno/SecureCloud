#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/auth_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/file_transfer.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QSignalSpy>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;

class ForwardingSecureStorage final : public ISecureStorage {
  public:
    explicit ForwardingSecureStorage(std::shared_ptr<MemorySecureStorage> inner) : inner_(std::move(inner)) {}

    ClientResult<void> store_secret(std::string_view key_id,
                                    const common::configuration::SecretString& secret) override {
        return inner_->store_secret(key_id, secret);
    }
    ClientResult<common::configuration::SecretString> get_secret(std::string_view key_id) override {
        return inner_->get_secret(key_id);
    }
    ClientResult<void> delete_secret(std::string_view key_id) override { return inner_->delete_secret(key_id); }
    ClientResult<bool> has_secret(std::string_view key_id) override { return inner_->has_secret(key_id); }
    ClientResult<std::vector<std::string>> list_secret_keys() override { return inner_->list_secret_keys(); }
    ClientResult<std::size_t> purge_all_secrets() override { return inner_->purge_all_secrets(); }

  private:
    std::shared_ptr<MemorySecureStorage> inner_;
};

class SharedGatewayAdapter final : public IGatewayClient {
  public:
    explicit SharedGatewayAdapter(std::shared_ptr<DefaultGatewayClient> inner) : inner_(std::move(inner)) {}

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
};

struct UiFileWorkstation {
    UserId uid;
    DeviceId did;
    std::filesystem::path db_path;
    std::shared_ptr<DefaultGatewayClient> shared_gateway;
    std::shared_ptr<MemorySecureStorage> secure_storage;
    std::unique_ptr<ClientApplication> app;
    std::vector<uint8_t> ik_pub;
    std::vector<uint8_t> spk_pub;
    std::vector<uint8_t> spk_sig;
    std::vector<uint8_t> otk_pub;
    std::string otk_id;

    UiFileWorkstation(std::string user, std::string dev, std::filesystem::path db_file,
                      std::shared_ptr<DefaultGatewayClient> gw, uint32_t wire_chunk_size = 1024U)
        : uid(std::move(user)), did(std::move(dev)), db_path(std::move(db_file)), shared_gateway(std::move(gw)),
          secure_storage(std::make_shared<MemorySecureStorage>()) {
        OpenSslCryptoProvider crypto;
        auto ik = crypto.generate_identity_keypair().value();
        auto spk = crypto.generate_signed_prekey(ik.private_key).value();
        auto otk = crypto.generate_dh_keypair().value();

        ik_pub = ik.public_key;
        spk_pub = spk.public_key;
        spk_sig = spk.signature;
        otk_pub = otk.public_key;
        otk_id = did.value() + "-otpk-01";

        std::unordered_map<std::string, common::configuration::SecretString> otk_privs;
        otk_privs.emplace(otk_id, std::move(otk.private_key));
        DevicePrivateBundle bundle(did, ik.public_key, std::move(ik.private_key), spk.public_key,
                                   std::move(spk.private_key), spk.signature, std::move(otk_privs));
        (void)KeyStorageHelper::save_bundle(*secure_storage, bundle);

        boot(wire_chunk_size);
    }

    ~UiFileWorkstation() { shutdown(); }

    void boot(uint32_t wire_chunk_size = 1024U) {
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = db_path.string();
        auto gw = std::make_unique<SharedGatewayAdapter>(shared_gateway);
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto sec = std::make_unique<ForwardingSecureStorage>(secure_storage);
        auto sql = std::make_unique<SqlCipherLocalStore>(*secure_storage, *crypto);

        auto bootstrap = ClientBootstrap::create_with_adapters(std::move(cfg), std::move(gw), std::move(sql),
                                                               std::move(sec), std::move(crypto));
        app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(app->initialize().is_ok());
        EXPECT_TRUE(app->start().is_ok());
        EXPECT_TRUE(app->bootstrap().auth_manager().authenticate(uid.value(), "Passphrase!23").is_ok());
        app->bootstrap().initialize_ratchet_session_manager(uid, did);
        EXPECT_TRUE(app->bootstrap().file_manager().set_wire_chunk_size(wire_chunk_size).is_ok());
    }

    void shutdown() {
        if (app) {
            EXPECT_TRUE(app->shutdown().is_ok());
            app.reset();
        }
    }

    DeviceCryptoDirectoryEntry directory_entry() const {
        return DeviceCryptoDirectoryEntry{
            .device_id = did,
            .identity_key = ik_pub,
            .signed_prekey = spk_pub,
            .signed_prekey_signature = spk_sig,
            .one_time_prekey = otk_pub,
            .one_time_prekey_id = otk_id,
            .status = DeviceAuthorizationStatus::Authorized,
        };
    }

    FileManager& files() noexcept { return app->bootstrap().file_manager(); }
    ILocalStore& local_store() noexcept { return app->bootstrap().local_store(); }
};

std::vector<uint8_t> make_sample_bytes(std::size_t size, uint8_t seed) {
    std::vector<uint8_t> out(size);
    for (std::size_t i = 0U; i < size; ++i) {
        out[i] = static_cast<uint8_t>((i * 67U + seed) & 0xFFU);
    }
    return out;
}

std::vector<uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

void write_file_bytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ofs.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    ofs.flush();
}

QVariantMap find_transfer_in_list(const QVariantList& list, const QString& transfer_id) {
    for (const auto& entry : list) {
        const QVariantMap map = entry.toMap();
        if (map.value(QStringLiteral("transferId")).toString() == transfer_id) {
            return map;
        }
    }
    return {};
}

class WorkspaceViewModelFilesTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_wvm_files_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        gateway_ = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    void wire_direct_conversation(UiFileWorkstation& alice, UiFileWorkstation& bob, const ConversationId& cid) {
        gateway_->set_simulated_user_directory(bob.uid, {bob.directory_entry()});
        gateway_->set_simulated_user_directory(alice.uid, {alice.directory_entry()});

        Conversation conv(cid, ConversationType::Direct, "Alice & Bob");
        conv.add_participant(alice.uid, ParticipantRole::Member);
        conv.add_participant(bob.uid, ParticipantRole::Member);
        ASSERT_TRUE(alice.local_store().save_conversation(conv).is_ok());
        ASSERT_TRUE(bob.local_store().save_conversation(conv).is_ok());

        Contact bob_contact(bob.uid, "Bob", KeyVerificationStatus::Verified, "fp-bob");
        Contact alice_contact(alice.uid, "Alice", KeyVerificationStatus::Verified, "fp-alice");
        ASSERT_TRUE(alice.local_store().save_contact(bob_contact).is_ok());
        ASSERT_TRUE(bob.local_store().save_contact(alice_contact).is_ok());
    }

    std::filesystem::path temp_dir_;
    std::shared_ptr<DefaultGatewayClient> gateway_;
};

TEST_F(WorkspaceViewModelFilesTest, UploadLocalFileNormalizesFileUrlUpdatesVaultAndPersistsAcrossRestart) {
    UiFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    UiFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-ui-upload-restart");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source" / "vault-report.bin";
    const std::vector<uint8_t> payload = make_sample_bytes(3500U, 0x29U); // 4 chunks at 1024 B wire chunk size
    write_file_bytes(src_file, payload);

    NavigationController nav;
    nav.setAuthenticated(true);
    {
        WorkspaceViewModel vm(*alice.app, nav);
        EXPECT_TRUE(vm.fileTransfers().isEmpty());
        vm.selectConversation(QString::fromStdString(cid.value()));

        const QString fileUrl = QUrl::fromLocalFile(QString::fromStdString(src_file.string())).toString();
        const QString txId = vm.uploadLocalFile(fileUrl);
        ASSERT_FALSE(txId.isEmpty());

        const QVariantMap details = vm.selectedTransferDetails();
        EXPECT_EQ(details.value(QStringLiteral("transferId")).toString(), txId);
        EXPECT_EQ(details.value(QStringLiteral("fileName")).toString(), QStringLiteral("vault-report.bin"));
        EXPECT_EQ(details.value(QStringLiteral("status")).toString(), QStringLiteral("Completed"));
        EXPECT_EQ(details.value(QStringLiteral("statusText")).toString(), QStringLiteral("Encrypted & Verified"));
        EXPECT_EQ(details.value(QStringLiteral("progressPercent")).toInt(), 100);
        EXPECT_EQ(details.value(QStringLiteral("completedChunks")).toInt(), 4);
        EXPECT_EQ(details.value(QStringLiteral("totalChunks")).toInt(), 4);
        EXPECT_FALSE(details.value(QStringLiteral("canPause")).toBool());
        EXPECT_FALSE(details.value(QStringLiteral("canResume")).toBool());
        EXPECT_TRUE(details.value(QStringLiteral("canCancel")).toBool());

        const QVariantList msgs = vm.activeMessages();
        ASSERT_FALSE(msgs.isEmpty());
        const QVariantMap lastMsg = msgs.back().toMap();
        EXPECT_TRUE(lastMsg.value(QStringLiteral("isFileTransfer")).toBool());
        EXPECT_EQ(lastMsg.value(QStringLiteral("transferId")).toString(), txId);
        EXPECT_EQ(lastMsg.value(QStringLiteral("fileName")).toString(), QStringLiteral("vault-report.bin"));
        EXPECT_FALSE(lastMsg.value(QStringLiteral("text")).toString().contains(QStringLiteral("file_key_hex")));
    }

    // Restart Alice against persisted SQLCipher DB + ISecureStorage and confirm Vault hydrates cleanly
    alice.shutdown();
    alice.boot(1024U);
    {
        WorkspaceViewModel restartedVm(*alice.app, nav);
        ASSERT_EQ(restartedVm.fileTransfers().size(), 1);
        const QVariantMap hydrated = restartedVm.selectedTransferDetails();
        EXPECT_EQ(hydrated.value(QStringLiteral("fileName")).toString(), QStringLiteral("vault-report.bin"));
        EXPECT_EQ(hydrated.value(QStringLiteral("status")).toString(), QStringLiteral("Completed"));
        EXPECT_EQ(hydrated.value(QStringLiteral("progressPercent")).toInt(), 100);
        EXPECT_EQ(hydrated.value(QStringLiteral("totalChunks")).toInt(), 4);

        const QVariantList msgs = restartedVm.activeMessages();
        ASSERT_EQ(msgs.size(), 1);
        EXPECT_TRUE(msgs.front().toMap().value(QStringLiteral("isFileTransfer")).toBool());
        EXPECT_FALSE(
            msgs.front().toMap().value(QStringLiteral("text")).toString().contains(QStringLiteral("file_key_hex")));
    }
}

TEST_F(WorkspaceViewModelFilesTest, PauseResumeAndCancelControlsUpdateViewModelPropertiesAndFlags) {
    UiFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    UiFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-ui-pause-resume");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source" / "pausable.bin";
    write_file_bytes(src_file, make_sample_bytes(4500U, 0x5AU)); // 5 chunks

    NavigationController nav;
    nav.setAuthenticated(true);
    WorkspaceViewModel vm(*alice.app, nav);
    vm.selectConversation(QString::fromStdString(cid.value()));

    QString capturedTxId;
    bool pause_triggered = false;
    QObject::connect(&vm, &WorkspaceViewModel::fileTransfersChanged, &vm, [&]() {
        if (pause_triggered) {
            return;
        }
        const QVariantList current = vm.fileTransfers();
        if (!current.isEmpty()) {
            const QVariantMap m = current.front().toMap();
            if (m.value(QStringLiteral("status")).toString() == QStringLiteral("InProgress") &&
                m.value(QStringLiteral("completedChunks")).toInt() == 2) {
                pause_triggered = true;
                capturedTxId = m.value(QStringLiteral("transferId")).toString();
                EXPECT_TRUE(vm.pauseFileTransfer(capturedTxId));
            }
        }
    });

    const QString txId = vm.uploadLocalFile(QString::fromStdString(src_file.string()));
    ASSERT_FALSE(txId.isEmpty());
    EXPECT_TRUE(pause_triggered);
    EXPECT_EQ(txId, capturedTxId);

    const QVariantMap pausedDetails = find_transfer_in_list(vm.fileTransfers(), txId);
    EXPECT_EQ(pausedDetails.value(QStringLiteral("status")).toString(), QStringLiteral("Paused"));
    EXPECT_EQ(pausedDetails.value(QStringLiteral("statusText")).toString(), QStringLiteral("Paused"));
    EXPECT_EQ(pausedDetails.value(QStringLiteral("completedChunks")).toInt(), 2);
    EXPECT_EQ(pausedDetails.value(QStringLiteral("totalChunks")).toInt(), 5);
    EXPECT_EQ(pausedDetails.value(QStringLiteral("progressPercent")).toInt(), 40);
    EXPECT_FALSE(pausedDetails.value(QStringLiteral("canPause")).toBool());
    EXPECT_TRUE(pausedDetails.value(QStringLiteral("canResume")).toBool());
    EXPECT_TRUE(pausedDetails.value(QStringLiteral("canCancel")).toBool());

    ASSERT_TRUE(vm.resumeFileTransfer(txId));
    const QVariantMap completedDetails = vm.selectedTransferDetails();
    EXPECT_EQ(completedDetails.value(QStringLiteral("status")).toString(), QStringLiteral("Completed"));
    EXPECT_EQ(completedDetails.value(QStringLiteral("statusText")).toString(), QStringLiteral("Encrypted & Verified"));
    EXPECT_EQ(completedDetails.value(QStringLiteral("progressPercent")).toInt(), 100);
    EXPECT_EQ(completedDetails.value(QStringLiteral("completedChunks")).toInt(), 5);
    EXPECT_FALSE(completedDetails.value(QStringLiteral("canResume")).toBool());

    ASSERT_TRUE(vm.cancelFileTransfer(txId));
    const QVariantMap cancelledDetails = vm.selectedTransferDetails();
    EXPECT_EQ(cancelledDetails.value(QStringLiteral("status")).toString(), QStringLiteral("Cancelled"));
    EXPECT_EQ(cancelledDetails.value(QStringLiteral("statusText")).toString(), QStringLiteral("Cancelled"));
    EXPECT_FALSE(cancelledDetails.value(QStringLiteral("canCancel")).toBool());
    EXPECT_FALSE(cancelledDetails.value(QStringLiteral("canResume")).toBool());
}

TEST_F(WorkspaceViewModelFilesTest, RealtimeInboundKeyEnvelopeIngestsAndDownloadsVerifiedFile) {
    UiFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    UiFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-ui-inbound-dl");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source" / "secret-blueprint.dat";
    const std::vector<uint8_t> original_bytes = make_sample_bytes(3800U, 0x71U);
    write_file_bytes(src_file, original_bytes);

    NavigationController navAlice;
    NavigationController navBob;
    navAlice.setAuthenticated(true);
    navBob.setAuthenticated(true);
    WorkspaceViewModel aliceVm(*alice.app, navAlice);
    WorkspaceViewModel bobVm(*bob.app, navBob);

    gateway_->clear_submitted_fanouts();
    aliceVm.selectConversation(QString::fromStdString(cid.value()));
    ASSERT_FALSE(aliceVm.uploadLocalFile(QString::fromStdString(src_file.string())).isEmpty());

    ASSERT_EQ(gateway_->submitted_fanouts().size(), 1U);
    ASSERT_EQ(gateway_->submitted_fanouts()[0].device_payloads.size(), 1U);

    // Emit inbound realtime event onto Bob's gateway subscription and process Qt queued events
    RealtimeEvent ev;
    ev.type = RealtimeEventType::InboundDirectMessage;
    ev.conversation_id = cid;
    ev.message_id = MessageId("msg-rt-file-1");
    ev.actor_user_id = alice.uid;
    ev.actor_device_id = alice.did;
    ev.server_sequence_number = 77;
    ev.direct_payload = gateway_->submitted_fanouts()[0].device_payloads[0];
    gateway_->emit_realtime_event(ev);
    QCoreApplication::processEvents();

    ASSERT_EQ(bobVm.fileTransfers().size(), 1);
    const QVariantMap inboundTx = bobVm.selectedTransferDetails();
    const QString bobTransferId = inboundTx.value(QStringLiteral("transferId")).toString();
    EXPECT_EQ(inboundTx.value(QStringLiteral("direction")).toString(), QStringLiteral("Inbound"));
    EXPECT_EQ(inboundTx.value(QStringLiteral("status")).toString(), QStringLiteral("Pending"));
    EXPECT_EQ(inboundTx.value(QStringLiteral("statusText")).toString(), QStringLiteral("Ready to Download"));
    EXPECT_EQ(inboundTx.value(QStringLiteral("progressPercent")).toInt(), 0);
    EXPECT_TRUE(inboundTx.value(QStringLiteral("canDownload")).toBool());
    EXPECT_FALSE(inboundTx.value(QStringLiteral("canPause")).toBool());

    bobVm.selectConversation(QString::fromStdString(cid.value()));
    const QVariantList bobMsgs = bobVm.activeMessages();
    ASSERT_EQ(bobMsgs.size(), 1);
    EXPECT_TRUE(bobMsgs.front().toMap().value(QStringLiteral("isFileTransfer")).toBool());
    EXPECT_EQ(bobMsgs.front().toMap().value(QStringLiteral("transferId")).toString(), bobTransferId);
    EXPECT_FALSE(
        bobMsgs.front().toMap().value(QStringLiteral("text")).toString().contains(QStringLiteral("file_key_hex")));

    const std::filesystem::path dest_file = temp_dir_ / "downloads" / "secret-blueprint.dat";
    const QString destUrl = QUrl::fromLocalFile(QString::fromStdString(dest_file.string())).toString();
    ASSERT_TRUE(bobVm.downloadEncryptedFile(bobTransferId, destUrl));

    const QVariantMap completedDl = bobVm.selectedTransferDetails();
    EXPECT_EQ(completedDl.value(QStringLiteral("status")).toString(), QStringLiteral("Completed"));
    EXPECT_EQ(completedDl.value(QStringLiteral("statusText")).toString(), QStringLiteral("Encrypted & Verified"));
    EXPECT_EQ(completedDl.value(QStringLiteral("progressPercent")).toInt(), 100);
    EXPECT_FALSE(completedDl.value(QStringLiteral("canDownload")).toBool());
    EXPECT_EQ(read_file_bytes(dest_file), original_bytes);
}

TEST_F(WorkspaceViewModelFilesTest, QmlWorkspacePlaceholderBindsVaultProgressBarAndTransferControls) {
    UiFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    UiFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-ui-qml-vault");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source" / "qml-bound.bin";
    write_file_bytes(src_file, make_sample_bytes(4500U, 0x9CU)); // 5 chunks

    UiTheme theme;
    NavigationController nav;
    nav.setAuthenticated(true);
    AppViewModel appVm(*alice.app, nav);
    WorkspaceViewModel workspaceVm(*alice.app, nav);
    workspaceVm.selectConversation(QString::fromStdString(cid.value()));

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("Theme", &theme);
    engine.rootContext()->setContextProperty("navigationController", &nav);
    engine.rootContext()->setContextProperty("appViewModel", &appVm);
    engine.rootContext()->setContextProperty("workspaceViewModel", &workspaceVm);

    QQmlComponent comp(&engine, QUrl("qrc:/qml/WorkspacePlaceholder.qml"));
    ASSERT_TRUE(comp.isReady()) << comp.errorString().toStdString();
    std::unique_ptr<QObject> workspaceObj(comp.create());
    ASSERT_NE(workspaceObj, nullptr);

    workspaceVm.setActiveSection(QStringLiteral("Files"));

    auto* progressBar = workspaceObj->findChild<QObject*>("vaultManifestProgressBar");
    auto* chunkLabel = workspaceObj->findChild<QObject*>("vaultChunkReadoutLabel");
    auto* pauseBtn = workspaceObj->findChild<QObject*>("vaultPauseTransferButton");
    auto* resumeBtn = workspaceObj->findChild<QObject*>("vaultResumeTransferButton");
    auto* downloadBtn = workspaceObj->findChild<QObject*>("vaultDownloadTransferButton");
    auto* cancelBtn = workspaceObj->findChild<QObject*>("vaultCancelTransferButton");
    ASSERT_NE(progressBar, nullptr);
    ASSERT_NE(chunkLabel, nullptr);
    ASSERT_NE(pauseBtn, nullptr);
    ASSERT_NE(resumeBtn, nullptr);
    ASSERT_NE(downloadBtn, nullptr);
    ASSERT_NE(cancelBtn, nullptr);

    // Pause upload mid-stream so Resume button becomes visible and ProgressBar == 40%
    bool pause_triggered = false;
    QObject::connect(&workspaceVm, &WorkspaceViewModel::fileTransfersChanged, &workspaceVm, [&]() {
        if (pause_triggered) {
            return;
        }
        const QVariantList list = workspaceVm.fileTransfers();
        if (!list.isEmpty()) {
            const QVariantMap m = list.front().toMap();
            if (m.value(QStringLiteral("status")).toString() == QStringLiteral("InProgress") &&
                m.value(QStringLiteral("completedChunks")).toInt() == 2) {
                pause_triggered = true;
                EXPECT_TRUE(workspaceVm.pauseFileTransfer(m.value(QStringLiteral("transferId")).toString()));
            }
        }
    });

    const QString txId = workspaceVm.uploadLocalFile(QString::fromStdString(src_file.string()));
    ASSERT_FALSE(txId.isEmpty());
    EXPECT_TRUE(pause_triggered);
    QCoreApplication::processEvents();

    EXPECT_DOUBLE_EQ(progressBar->property("value").toDouble(), 40.0);
    EXPECT_TRUE(chunkLabel->property("text").toString().contains(QStringLiteral("2 / 5 chunks")));
    EXPECT_FALSE(pauseBtn->property("visible").toBool());
    EXPECT_TRUE(resumeBtn->property("visible").toBool());
    EXPECT_FALSE(downloadBtn->property("visible").toBool());
    EXPECT_TRUE(cancelBtn->property("enabled").toBool());

    ASSERT_TRUE(workspaceVm.resumeFileTransfer(txId));
    QCoreApplication::processEvents();
    EXPECT_DOUBLE_EQ(progressBar->property("value").toDouble(), 100.0);
    EXPECT_TRUE(chunkLabel->property("text").toString().contains(QStringLiteral("5 / 5 chunks")));
    EXPECT_FALSE(resumeBtn->property("visible").toBool());

    workspaceObj.reset();
    engine.clearComponentCache();
    engine.rootContext()->setContextProperty("workspaceViewModel", QVariant());
    engine.rootContext()->setContextProperty("appViewModel", QVariant());
    engine.rootContext()->setContextProperty("navigationController", QVariant());
    engine.rootContext()->setContextProperty("Theme", QVariant());
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
}

TEST_F(WorkspaceViewModelFilesTest, LegacyStageAndCancelRemainsCompatibleInHeadlessSeedMode) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    NavigationController nav;
    nav.setAuthenticated(true);
    WorkspaceViewModel workspace(app, nav);

    ASSERT_EQ(workspace.fileTransfers().size(), 3);
    const QString txId = workspace.stageEncryptedFileTransfer(QStringLiteral("legacy-audit.enc"), 2097152);
    ASSERT_FALSE(txId.isEmpty());
    EXPECT_EQ(workspace.fileTransfers().size(), 4);

    const QVariantMap staged = workspace.selectedTransferDetails();
    EXPECT_EQ(staged.value(QStringLiteral("status")).toString(), QStringLiteral("Completed"));
    EXPECT_EQ(staged.value(QStringLiteral("progressPercent")).toInt(), 100);
    EXPECT_TRUE(staged.value(QStringLiteral("canCancel")).toBool());

    EXPECT_TRUE(workspace.cancelFileTransfer(txId));
    const QVariantMap cancelled = workspace.selectedTransferDetails();
    EXPECT_EQ(cancelled.value(QStringLiteral("status")).toString(), QStringLiteral("Cancelled"));
    EXPECT_EQ(cancelled.value(QStringLiteral("statusText")).toString(), QStringLiteral("Cancelled"));
    EXPECT_FALSE(cancelled.value(QStringLiteral("canCancel")).toBool());
}

} // namespace
} // namespace securecloud::client::tests
