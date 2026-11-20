#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/auth_manager.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
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
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
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
using namespace securecloud::client::domain::crypto;
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

  private:
    std::shared_ptr<DefaultGatewayClient> inner_;
};

struct E2eFileWorkstation {
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

    E2eFileWorkstation(std::string user, std::string dev, std::filesystem::path db_file,
                       std::shared_ptr<DefaultGatewayClient> gw, uint32_t wire_chunk_size = kDefaultFileWireChunkSize)
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

    ~E2eFileWorkstation() { shutdown(); }

    void boot(uint32_t wire_chunk_size = kDefaultFileWireChunkSize) {
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
    MessagingManager& messaging() noexcept { return app->bootstrap().messaging_manager(); }
    ContactManager& contacts() noexcept { return app->bootstrap().contact_manager(); }
    ILocalStore& local_store() noexcept { return app->bootstrap().local_store(); }
};

std::vector<uint8_t> make_sample_bytes(std::size_t size, uint8_t seed) {
    std::vector<uint8_t> out(size);
    for (std::size_t i = 0U; i < size; ++i) {
        out[i] = static_cast<uint8_t>((i * 73U + seed) & 0xFFU);
    }
    return out;
}

std::vector<uint8_t> read_binary_file(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

void write_binary_file(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ofs.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    ofs.flush();
}

bool contains_ascii_bytes(const std::vector<uint8_t>& haystack, std::string_view needle) {
    if (needle.empty() || haystack.size() < needle.size()) {
        return false;
    }
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

class EncryptedFileTransferIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_client_011_e2e_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        gateway_ = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
    }

    void TearDown() override {
        gateway_->set_simulated_chunk_failure(std::nullopt);
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    void wire_direct_conversation(E2eFileWorkstation& alice, E2eFileWorkstation& bob, const ConversationId& cid) {
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

TEST_F(EncryptedFileTransferIntegrationTest,
       Scenario1MultiChunkEncryptedUploadE2eeKeyDeliveryVerifiedDownloadAndForensicAudit) {
    E2eFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    E2eFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-e2e-s1");
    wire_direct_conversation(alice, bob, cid);

    const std::string plaintextMarker = "CONFIDENTIAL-CLIENT-011-PAYLOAD-MARKER-9981";
    const std::string secretFilename = "classified-audit-dossier-2026.bin";
    std::vector<uint8_t> original_bytes = make_sample_bytes(4800U, 0x41U);
    std::memcpy(original_bytes.data() + 128U, plaintextMarker.data(), plaintextMarker.size());
    const std::filesystem::path src_file = temp_dir_ / "alice_docs" / secretFilename;
    write_binary_file(src_file, original_bytes);

    gateway_->clear_submitted_fanouts();
    const auto up_res = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
        .mime_type = "application/octet-stream",
        .sender_display_name = "Alice",
    });
    ASSERT_TRUE(up_res.is_ok()) << up_res.error().user_message();
    const FileTransferRecord& up_rec = up_res.value().record;
    EXPECT_EQ(up_rec.status, FileTransferStatus::Completed);
    EXPECT_EQ(up_rec.total_chunks, 5U);
    EXPECT_EQ(up_rec.completed_chunks, 5U);
    EXPECT_EQ(up_rec.progress_percent(), 100U);

    // Deliver Double Ratchet encrypted key envelope over realtime event stream to Bob
    ASSERT_EQ(gateway_->submitted_fanouts().size(), 1U);
    ASSERT_EQ(gateway_->submitted_fanouts()[0].device_payloads.size(), 1U);
    RealtimeEvent ev;
    ev.type = RealtimeEventType::InboundDirectMessage;
    ev.conversation_id = cid;
    ev.message_id = MessageId("msg-e2e-s1-key");
    ev.actor_user_id = alice.uid;
    ev.actor_device_id = alice.did;
    ev.server_sequence_number = 10U;
    ev.direct_payload = gateway_->submitted_fanouts()[0].device_payloads[0];

    const auto proc_res = bob.messaging().process_inbound_realtime_event(ev);
    ASSERT_TRUE(proc_res.is_ok());
    ASSERT_TRUE(proc_res.value().has_value());
    const std::string& envelope_json = proc_res.value()->encrypted_envelope_ref();
    ASSERT_TRUE(FileAttachmentKeyEnvelope::is_file_attachment_envelope(envelope_json));

    const auto ingest_res = bob.files().ingest_inbound_key_envelope_json(cid, alice.uid, envelope_json);
    ASSERT_TRUE(ingest_res.is_ok());
    const std::filesystem::path dst_file = temp_dir_ / "bob_downloads" / secretFilename;
    const auto dl_res = bob.files().start_download(ingest_res.value().transfer_id, dst_file.string());
    ASSERT_TRUE(dl_res.is_ok()) << dl_res.error().user_message();
    EXPECT_EQ(dl_res.value().status, FileTransferStatus::Completed);
    EXPECT_EQ(dl_res.value().progress_percent(), 100U);
    EXPECT_EQ(read_binary_file(dst_file), original_bytes);

    // Forensic scan: Gateway raw chunk bytes & both SQLCipher .db files contain zero plaintext data/metadata
    alice.shutdown();
    bob.shutdown();

    const std::vector<uint8_t> gateway_raw = gateway_->stored_file_raw_bytes(up_rec.file_id);
    EXPECT_FALSE(gateway_raw.empty());
    EXPECT_FALSE(contains_ascii_bytes(gateway_raw, plaintextMarker));
    EXPECT_FALSE(contains_ascii_bytes(gateway_raw, secretFilename));

    const std::vector<uint8_t> alice_db_bytes = read_binary_file(temp_dir_ / "alice.db");
    const std::vector<uint8_t> bob_db_bytes = read_binary_file(temp_dir_ / "bob.db");
    EXPECT_FALSE(alice_db_bytes.empty());
    EXPECT_FALSE(bob_db_bytes.empty());
    EXPECT_FALSE(contains_ascii_bytes(alice_db_bytes, plaintextMarker));
    EXPECT_FALSE(contains_ascii_bytes(alice_db_bytes, secretFilename));
    EXPECT_FALSE(contains_ascii_bytes(bob_db_bytes, plaintextMarker));
    EXPECT_FALSE(contains_ascii_bytes(bob_db_bytes, secretFilename));
}

TEST_F(EncryptedFileTransferIntegrationTest,
       Scenario2MidTransferPauseAndFullApplicationRestartResumeUploadAndDownload) {
    E2eFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    E2eFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-e2e-s2");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source" / "resumable-5chunks.bin";
    const std::vector<uint8_t> original_bytes = make_sample_bytes(4500U, 0x62U); // 5 chunks at 1024 B wire size
    write_binary_file(src_file, original_bytes);

    alice.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 2U) {
            EXPECT_TRUE(alice.files().pause_transfer(rec.transfer_id).is_ok());
        }
    });

    const auto up_paused = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(up_paused.is_ok());
    EXPECT_EQ(up_paused.value().record.status, FileTransferStatus::Paused);
    EXPECT_EQ(up_paused.value().record.completed_chunks, 2U);
    const std::string up_tx_id = up_paused.value().record.transfer_id;
    const std::string file_id = up_paused.value().record.file_id;
    EXPECT_EQ(gateway_->uploaded_chunk_call_count(file_id), 2U);

    // Shutdown and restart Alice against persisted SQLCipher + ISecureStorage
    alice.shutdown();
    alice.boot(1024U);

    const auto up_resumed = alice.files().resume_upload(up_tx_id, alice.uid, alice.did, "Alice");
    ASSERT_TRUE(up_resumed.is_ok()) << up_resumed.error().user_message();
    EXPECT_EQ(up_resumed.value().record.status, FileTransferStatus::Completed);
    EXPECT_EQ(up_resumed.value().record.completed_chunks, 5U);
    // Strictly chunks 2, 3, 4 uploaded on resume -> total upload calls across both sessions == 5
    EXPECT_EQ(gateway_->uploaded_chunk_call_count(file_id), 5U);
    ASSERT_TRUE(up_resumed.value().key_envelope.has_value());

    // Ingest key envelope on Bob, pause download after 2/5 chunks, restart Bob, resume strictly chunks 2..4
    const auto ingest_res = bob.files().ingest_inbound_key_envelope(cid, alice.uid, *up_resumed.value().key_envelope);
    ASSERT_TRUE(ingest_res.is_ok());
    const std::string dl_tx_id = ingest_res.value().transfer_id;

    bob.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 2U) {
            EXPECT_TRUE(bob.files().pause_transfer(rec.transfer_id).is_ok());
        }
    });

    const std::filesystem::path dst_file = temp_dir_ / "downloads" / "resumable-5chunks.bin";
    const auto dl_paused = bob.files().start_download(dl_tx_id, dst_file.string());
    ASSERT_TRUE(dl_paused.is_ok());
    EXPECT_EQ(dl_paused.value().status, FileTransferStatus::Paused);
    EXPECT_EQ(dl_paused.value().completed_chunks, 2U);
    EXPECT_TRUE(std::filesystem::exists(dst_file.string() + ".part"));
    EXPECT_FALSE(std::filesystem::exists(dst_file));

    bob.shutdown();
    bob.boot(1024U);
    gateway_->set_simulated_chunk_failure(0U, "Chunk 0 must not be re-downloaded on resume");
    const auto dl_resumed = bob.files().resume_transfer(dl_tx_id);
    ASSERT_TRUE(dl_resumed.is_ok()) << dl_resumed.error().user_message();
    gateway_->set_simulated_chunk_failure(std::nullopt);

    EXPECT_EQ(dl_resumed.value().status, FileTransferStatus::Completed);
    EXPECT_EQ(dl_resumed.value().completed_chunks, 5U);
    EXPECT_FALSE(std::filesystem::exists(dst_file.string() + ".part"));
    EXPECT_EQ(read_binary_file(dst_file), original_bytes);
}

TEST_F(EncryptedFileTransferIntegrationTest, Scenario3AdversarialFailClosedTamperedSwappedTruncatedAndWrongKey) {
    E2eFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    E2eFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-e2e-s3");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source" / "tamper-target.bin";
    write_binary_file(src_file, make_sample_bytes(3500U, 0x33U)); // 4 chunks (0..3)

    const auto up_res = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(up_res.is_ok());
    ASSERT_TRUE(up_res.value().key_envelope.has_value());
    const FileAttachmentKeyEnvelope env = *up_res.value().key_envelope;
    const std::string file_id = env.file_id;

    const std::vector<uint8_t> orig_chunk0 = gateway_->download_file_chunk(file_id, 0U).value().encrypted_data;
    const std::vector<uint8_t> orig_chunk1 = gateway_->download_file_chunk(file_id, 1U).value().encrypted_data;
    const std::vector<uint8_t> orig_chunk3 = gateway_->download_file_chunk(file_id, 3U).value().encrypted_data;

    // Attack A: 1-byte ciphertext mutation (even with server SHA-256 recomputed -> GCM auth tag fails)
    {
        std::vector<uint8_t> tampered = orig_chunk1;
        tampered[20U] ^= 0xFFU;
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 1U, tampered, true));

        const auto in_res = bob.files().ingest_inbound_key_envelope(cid, alice.uid, env);
        ASSERT_TRUE(in_res.is_ok());
        const std::filesystem::path dst = temp_dir_ / "bad_tamper.bin";
        const auto dl_res = bob.files().start_download(in_res.value().transfer_id, dst.string());
        EXPECT_TRUE(dl_res.is_error());
        EXPECT_FALSE(std::filesystem::exists(dst));
        EXPECT_FALSE(std::filesystem::exists(dst.string() + ".part"));
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 1U, orig_chunk1, true));
    }

    // Attack B: Swapped chunk index 0 and 1 (fails per-chunk AAD chunk_index binding)
    {
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 0U, orig_chunk1, true));
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 1U, orig_chunk0, true));

        const auto in_res = bob.files().ingest_inbound_key_envelope(cid, alice.uid, env);
        ASSERT_TRUE(in_res.is_ok());
        const std::filesystem::path dst = temp_dir_ / "bad_swap.bin";
        const auto dl_res = bob.files().start_download(in_res.value().transfer_id, dst.string());
        EXPECT_TRUE(dl_res.is_error());
        EXPECT_FALSE(std::filesystem::exists(dst));
        EXPECT_FALSE(std::filesystem::exists(dst.string() + ".part"));
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 0U, orig_chunk0, true));
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 1U, orig_chunk1, true));
    }

    // Attack C: Truncated terminal stream + is_final AAD enforcement
    {
        OpenSslCryptoProvider direct_crypto;
        const auto engine = FileCryptoEngine::create(1024U).value();
        const auto raw_key = FileCryptoEngine::decode_key_hex(env.file_key_hex).value();
        EXPECT_TRUE(engine.decrypt_chunk(direct_crypto, raw_key, file_id, 3U, false, orig_chunk3).is_error());

        std::vector<uint8_t> truncated = orig_chunk3;
        ASSERT_GT(truncated.size(), 8U);
        truncated.resize(truncated.size() - 8U);
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 3U, truncated, true));

        const auto in_res = bob.files().ingest_inbound_key_envelope(cid, alice.uid, env);
        ASSERT_TRUE(in_res.is_ok());
        const std::filesystem::path dst = temp_dir_ / "bad_truncated.bin";
        const auto dl_res = bob.files().start_download(in_res.value().transfer_id, dst.string());
        EXPECT_TRUE(dl_res.is_error());
        EXPECT_FALSE(std::filesystem::exists(dst));
        EXPECT_FALSE(std::filesystem::exists(dst.string() + ".part"));
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(file_id, 3U, orig_chunk3, true));
    }

    // Attack D: Wrong file_key stored for decryption -> GCM authentication fails closed
    {
        FileAttachmentKeyEnvelope wrong_key_env = env;
        const auto other_key = FileCryptoEngine::generate_file_key().value();
        wrong_key_env.file_key_hex = FileCryptoEngine::encode_key_hex(other_key).value();

        const auto in_res = bob.files().ingest_inbound_key_envelope(cid, alice.uid, wrong_key_env);
        ASSERT_TRUE(in_res.is_ok());
        const std::filesystem::path dst = temp_dir_ / "bad_wrong_key.bin";
        const auto dl_res = bob.files().start_download(in_res.value().transfer_id, dst.string());
        EXPECT_TRUE(dl_res.is_error());
        EXPECT_FALSE(std::filesystem::exists(dst));
        EXPECT_FALSE(std::filesystem::exists(dst.string() + ".part"));
    }
}

TEST_F(EncryptedFileTransferIntegrationTest,
       Scenario4Production4MiBWireChunkStreamingCancellationAndAdr008KeyChangedGuard) {
    // Use production 4 MiB wire chunk default (kDefaultFileWireChunkSize = 4,194,304 bytes)
    E2eFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_,
                             kDefaultFileWireChunkSize);
    E2eFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, kDefaultFileWireChunkSize);
    const ConversationId cid("conv-e2e-s4");
    wire_direct_conversation(alice, bob, cid);

    // 8.5 MiB yields 3 chunks: chunks 0 and 1 MUST be exact 4,194,304 B on wire (4,194,276 B plaintext + 28 B overhead)
    constexpr std::size_t kEightPointFiveMiB = (8U * 1024U * 1024U) + (512U * 1024U);
    const std::filesystem::path large_src = temp_dir_ / "source" / "large-8.5mib.bin";
    const std::vector<uint8_t> large_bytes = make_sample_bytes(kEightPointFiveMiB, 0x19U);
    write_binary_file(large_src, large_bytes);

    const auto up_res = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = large_src.string(),
    });
    ASSERT_TRUE(up_res.is_ok()) << up_res.error().user_message();
    EXPECT_EQ(up_res.value().record.chunk_size_bytes, kDefaultFileWireChunkSize);
    EXPECT_EQ(up_res.value().record.total_chunks, 3U);

    const std::string large_file_id = up_res.value().record.file_id;
    EXPECT_EQ(gateway_->download_file_chunk(large_file_id, 0U).value().encrypted_data.size(),
              kDefaultFileWireChunkSize);
    EXPECT_EQ(gateway_->download_file_chunk(large_file_id, 1U).value().encrypted_data.size(),
              kDefaultFileWireChunkSize);
    EXPECT_EQ(gateway_->download_file_chunk(large_file_id, 2U).value().encrypted_data.size(),
              (kEightPointFiveMiB - (2ULL * (kDefaultFileWireChunkSize - kFileChunkAeadOverheadBytes))) +
                  kFileChunkAeadOverheadBytes);

    ASSERT_TRUE(up_res.value().key_envelope.has_value());
    const auto ingest_large = bob.files().ingest_inbound_key_envelope(cid, alice.uid, *up_res.value().key_envelope);
    ASSERT_TRUE(ingest_large.is_ok());
    const std::filesystem::path large_dst = temp_dir_ / "downloads" / "large-8.5mib.bin";
    const auto dl_large = bob.files().start_download(ingest_large.value().transfer_id, large_dst.string());
    ASSERT_TRUE(dl_large.is_ok()) << dl_large.error().user_message();
    EXPECT_EQ(read_binary_file(large_dst), large_bytes);

    // Cancellation cleanup: aborts remote upload, deletes key in ISecureStorage & deletes .part file
    ASSERT_TRUE(bob.files().set_wire_chunk_size(1024U).is_ok());
    ASSERT_TRUE(alice.files().set_wire_chunk_size(1024U).is_ok());
    const std::filesystem::path small_src = temp_dir_ / "source" / "cancel-me.bin";
    write_binary_file(small_src, make_sample_bytes(3500U, 0x22U));

    alice.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 1U) {
            EXPECT_TRUE(alice.files().pause_transfer(rec.transfer_id).is_ok());
        }
    });
    const auto paused_cancel = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = small_src.string(),
    });
    ASSERT_TRUE(paused_cancel.is_ok());
    alice.files().set_progress_callback({});
    const std::string cancel_tx = paused_cancel.value().record.transfer_id;
    const std::string cancel_fid = paused_cancel.value().record.file_id;
    EXPECT_TRUE(alice.secure_storage->has_secret(FileManager::file_key_storage_id(cancel_fid)).value());
    ASSERT_TRUE(alice.files().cancel_transfer(cancel_tx).is_ok());
    EXPECT_EQ(alice.files().get_transfer(cancel_tx).value().status, FileTransferStatus::Cancelled);
    EXPECT_FALSE(alice.secure_storage->has_secret(FileManager::file_key_storage_id(cancel_fid)).value());
    EXPECT_FALSE(gateway_->has_stored_file(cancel_fid));

    // ADR-008 KeyChanged guard halts encrypted upload until safety number re-verification
    Contact changed_bob(bob.uid, "Bob", KeyVerificationStatus::KeyChanged, "fp-bob-rotated");
    ASSERT_TRUE(alice.contacts().add_or_update_contact(changed_bob).is_ok());
    const auto blocked_up = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = small_src.string(),
    });
    EXPECT_TRUE(blocked_up.is_error());

    ASSERT_TRUE(alice.contacts().verify_contact_key(bob.uid, true).is_ok());
    const auto allowed_up = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = small_src.string(),
    });
    EXPECT_TRUE(allowed_up.is_ok()) << allowed_up.error().user_message();
}

TEST_F(EncryptedFileTransferIntegrationTest,
       Scenario5WorkspaceViewModelAndQmlVaultProgressControlsAndRestartHydration) {
    E2eFileWorkstation alice("alice@securecloud.org", "dev-alice", temp_dir_ / "alice.db", gateway_, 1024U);
    E2eFileWorkstation bob("bob@securecloud.org", "dev-bob", temp_dir_ / "bob.db", gateway_, 1024U);
    const ConversationId cid("conv-e2e-s5");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source" / "vault-e2e.dat";
    const std::vector<uint8_t> original_bytes = make_sample_bytes(4500U, 0x88U); // 5 chunks -> 40% after 2
    write_binary_file(src_file, original_bytes);

    NavigationController navAlice;
    navAlice.setAuthenticated(true);
    {
        UiTheme theme;
        NavigationController navBob;
        navBob.setAuthenticated(true);
        AppViewModel appAlice(*alice.app, navAlice);
        WorkspaceViewModel vmAlice(*alice.app, navAlice);
        WorkspaceViewModel vmBob(*bob.app, navBob);

        QQmlApplicationEngine engine;
        engine.rootContext()->setContextProperty("Theme", &theme);
        engine.rootContext()->setContextProperty("navigationController", &navAlice);
        engine.rootContext()->setContextProperty("appViewModel", &appAlice);
        engine.rootContext()->setContextProperty("workspaceViewModel", &vmAlice);

        QQmlComponent comp(&engine, QUrl("qrc:/qml/WorkspacePlaceholder.qml"));
        ASSERT_TRUE(comp.isReady()) << comp.errorString().toStdString();
        std::unique_ptr<QObject> qmlWorkspace(comp.create());
        ASSERT_NE(qmlWorkspace, nullptr);

        vmAlice.selectConversation(QString::fromStdString(cid.value()));
        vmAlice.setActiveSection(QStringLiteral("Files"));

        auto* progressBar = qmlWorkspace->findChild<QObject*>("vaultManifestProgressBar");
        auto* chunkLabel = qmlWorkspace->findChild<QObject*>("vaultChunkReadoutLabel");
        auto* resumeBtn = qmlWorkspace->findChild<QObject*>("vaultResumeTransferButton");
        ASSERT_NE(progressBar, nullptr);
        ASSERT_NE(chunkLabel, nullptr);
        ASSERT_NE(resumeBtn, nullptr);

        bool paused_once = false;
        QObject::connect(&vmAlice, &WorkspaceViewModel::fileTransfersChanged, &vmAlice, [&]() {
            if (paused_once) {
                return;
            }
            const QVariantList txs = vmAlice.fileTransfers();
            if (!txs.isEmpty()) {
                const QVariantMap m = txs.front().toMap();
                if (m.value(QStringLiteral("status")).toString() == QStringLiteral("InProgress") &&
                    m.value(QStringLiteral("completedChunks")).toInt() == 2) {
                    paused_once = true;
                    EXPECT_TRUE(vmAlice.pauseFileTransfer(m.value(QStringLiteral("transferId")).toString()));
                }
            }
        });

        gateway_->clear_submitted_fanouts();
        const QString upTxId =
            vmAlice.uploadLocalFile(QUrl::fromLocalFile(QString::fromStdString(src_file.string())).toString());
        ASSERT_FALSE(upTxId.isEmpty());
        EXPECT_TRUE(paused_once);
        QCoreApplication::processEvents();

        EXPECT_DOUBLE_EQ(progressBar->property("value").toDouble(), 40.0);
        EXPECT_TRUE(chunkLabel->property("text").toString().contains(QStringLiteral("2 / 5 chunks")));
        EXPECT_TRUE(resumeBtn->property("visible").toBool());

        ASSERT_TRUE(vmAlice.resumeFileTransfer(upTxId));
        QCoreApplication::processEvents();
        EXPECT_DOUBLE_EQ(progressBar->property("value").toDouble(), 100.0);
        EXPECT_TRUE(chunkLabel->property("text").toString().contains(QStringLiteral("5 / 5 chunks")));
        EXPECT_FALSE(resumeBtn->property("visible").toBool());
        ASSERT_FALSE(vmAlice.activeMessages().isEmpty());
        EXPECT_FALSE(
            vmAlice.activeMessages().back().toMap().value(QStringLiteral("text")).toString().contains("file_key_hex"));

        // Push realtime envelope event to Bob's WorkspaceViewModel and download via file:// URL
        ASSERT_EQ(gateway_->submitted_fanouts().size(), 1U);
        ASSERT_EQ(gateway_->submitted_fanouts()[0].device_payloads.size(), 1U);
        RealtimeEvent ev;
        ev.type = RealtimeEventType::InboundDirectMessage;
        ev.conversation_id = cid;
        ev.message_id = MessageId("msg-e2e-s5");
        ev.actor_user_id = alice.uid;
        ev.actor_device_id = alice.did;
        ev.server_sequence_number = 50U;
        ev.direct_payload = gateway_->submitted_fanouts()[0].device_payloads[0];
        gateway_->emit_realtime_event(ev);
        QCoreApplication::processEvents();

        ASSERT_EQ(vmBob.fileTransfers().size(), 1);
        const QString bobTxId = vmBob.selectedTransferDetails().value(QStringLiteral("transferId")).toString();
        EXPECT_TRUE(vmBob.selectedTransferDetails().value(QStringLiteral("canDownload")).toBool());

        const std::filesystem::path bob_dst = temp_dir_ / "bob_ui_dl" / "vault-e2e.dat";
        ASSERT_TRUE(vmBob.downloadEncryptedFile(
            bobTxId, QUrl::fromLocalFile(QString::fromStdString(bob_dst.string())).toString()));
        EXPECT_EQ(vmBob.selectedTransferDetails().value(QStringLiteral("status")).toString(),
                  QStringLiteral("Completed"));
        EXPECT_EQ(read_binary_file(bob_dst), original_bytes);

        qmlWorkspace.reset();
        engine.clearComponentCache();
        engine.rootContext()->setContextProperty("workspaceViewModel", QVariant());
        engine.rootContext()->setContextProperty("appViewModel", QVariant());
        engine.rootContext()->setContextProperty("navigationController", QVariant());
        engine.rootContext()->setContextProperty("Theme", QVariant());
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    // Restart Alice and confirm Vault ledger hydrates from SQLCipher cleanly
    alice.shutdown();
    alice.boot(1024U);
    WorkspaceViewModel restartedAliceVm(*alice.app, navAlice);
    ASSERT_EQ(restartedAliceVm.fileTransfers().size(), 1);
    EXPECT_EQ(restartedAliceVm.selectedTransferDetails().value(QStringLiteral("progressPercent")).toInt(), 100);
    EXPECT_EQ(restartedAliceVm.selectedTransferDetails().value(QStringLiteral("completedChunks")).toInt(), 5);
    EXPECT_EQ(restartedAliceVm.selectedTransferDetails().value(QStringLiteral("totalChunks")).toInt(), 5);
}

} // namespace
} // namespace securecloud::client::tests
