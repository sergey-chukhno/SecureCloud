#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/file_transfer.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

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

struct FileWorkstation {
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

    FileWorkstation(std::string user, std::string dev, std::filesystem::path db_file,
                    std::shared_ptr<DefaultGatewayClient> gw)
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

        boot();
    }

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
    ILocalStore& local_store() noexcept { return app->bootstrap().local_store(); }
};

std::vector<uint8_t> make_file_bytes(std::size_t size, uint8_t seed) {
    std::vector<uint8_t> out(size);
    for (std::size_t i = 0U; i < size; ++i) {
        out[i] = static_cast<uint8_t>((i * 97U + seed) & 0xFFU);
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

class FileManagerPipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_file_manager_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        gateway_ = std::make_shared<DefaultGatewayClient>(ClientConfig::create_default());
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    void wire_direct_conversation(FileWorkstation& alice, FileWorkstation& bob, const ConversationId& cid) {
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

TEST_F(FileManagerPipelineTest, FullUploadKeyDistributionAndVerifiedDownloadProducesBitIdenticalFile) {
    FileWorkstation alice("alice", "dev-alice", temp_dir_ / "alice.db", gateway_);
    FileWorkstation bob("bob", "dev-bob", temp_dir_ / "bob.db", gateway_);
    const ConversationId cid("conv-files-e2e");
    wire_direct_conversation(alice, bob, cid);

    // 1024 B wire chunk -> 996 B plaintext/chunk -> 4500 B yields 5 chunks
    const std::filesystem::path src_file = temp_dir_ / "alice_docs" / "architecture-spec.bin";
    const std::vector<uint8_t> original_bytes = make_file_bytes(4500U, 0x3DU);
    write_binary_file(src_file, original_bytes);

    std::vector<uint32_t> progress_steps;
    alice.files().set_progress_callback(
        [&](const FileTransferRecord& rec) { progress_steps.push_back(rec.progress_percent()); });

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
    ASSERT_FALSE(progress_steps.empty());
    EXPECT_EQ(progress_steps.back(), 100U);

    // Per-file key stored in ISecureStorage, never in Gateway raw bytes or SQLCipher .db
    ASSERT_TRUE(alice.secure_storage->has_secret(FileManager::file_key_storage_id(up_rec.file_id)).value());
    EXPECT_TRUE(gateway_->has_stored_file(up_rec.file_id));
    const std::vector<uint8_t> gateway_bytes = gateway_->stored_file_raw_bytes(up_rec.file_id);
    EXPECT_EQ(std::search(gateway_bytes.begin(), gateway_bytes.end(), original_bytes.begin(), original_bytes.end()),
              gateway_bytes.end());

    // Verify E2EE envelope message was submitted via MessagingManager and deliver it to Bob
    ASSERT_EQ(gateway_->submitted_fanouts().size(), 1U);
    ASSERT_EQ(gateway_->submitted_fanouts()[0].device_payloads.size(), 1U);
    const auto bob_msg_res = bob.messaging().process_inbound_message(
        cid, alice.uid, alice.did, gateway_->submitted_fanouts()[0].device_payloads[0], 0, "Alice");
    ASSERT_TRUE(bob_msg_res.is_ok()) << bob_msg_res.error().user_message();
    EXPECT_TRUE(FileAttachmentKeyEnvelope::is_file_attachment_envelope(bob_msg_res.value().encrypted_envelope_ref()));

    const auto ingest_res =
        bob.files().ingest_inbound_key_envelope_json(cid, alice.uid, bob_msg_res.value().encrypted_envelope_ref());
    ASSERT_TRUE(ingest_res.is_ok()) << ingest_res.error().user_message();
    EXPECT_EQ(ingest_res.value().status, FileTransferStatus::Pending);

    const std::filesystem::path dst_file = temp_dir_ / "bob_downloads" / "architecture-spec.bin";
    const auto dl_res = bob.files().start_download(ingest_res.value().transfer_id, dst_file.string());
    ASSERT_TRUE(dl_res.is_ok()) << dl_res.error().user_message();
    EXPECT_EQ(dl_res.value().status, FileTransferStatus::Completed);
    EXPECT_EQ(dl_res.value().completed_chunks, 5U);
    EXPECT_TRUE(std::filesystem::exists(dst_file));
    EXPECT_FALSE(std::filesystem::exists(dst_file.string() + ".part"));
    EXPECT_EQ(read_binary_file(dst_file), original_bytes);
}

TEST_F(FileManagerPipelineTest, PauseAndFullRestartResumeUploadUploadsRemainingChunksOnly) {
    FileWorkstation alice("alice", "dev-alice", temp_dir_ / "alice.db", gateway_);
    FileWorkstation bob("bob", "dev-bob", temp_dir_ / "bob.db", gateway_);
    const ConversationId cid("conv-pause-upload");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "resume_upload.bin";
    const std::vector<uint8_t> original_bytes = make_file_bytes(4500U, 0x71U);
    write_binary_file(src_file, original_bytes);

    alice.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 2U) {
            EXPECT_TRUE(alice.files().pause_transfer(rec.transfer_id).is_ok());
        }
    });

    const auto paused_res = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(paused_res.is_ok()) << paused_res.error().user_message();
    EXPECT_EQ(paused_res.value().record.status, FileTransferStatus::Paused);
    EXPECT_EQ(paused_res.value().record.completed_chunks, 2U);
    const std::string transfer_id = paused_res.value().record.transfer_id;
    const std::string file_id = paused_res.value().record.file_id;
    EXPECT_EQ(gateway_->uploaded_chunk_call_count(file_id), 2U);
    EXPECT_FALSE(gateway_->has_stored_file(file_id));

    // Full workstation shutdown & restart from SQLCipher + ISecureStorage
    alice.shutdown();
    alice.boot(1024U);

    const auto reloaded = alice.files().get_transfer(transfer_id);
    ASSERT_TRUE(reloaded.is_ok());
    EXPECT_EQ(reloaded.value().status, FileTransferStatus::Paused);
    EXPECT_EQ(reloaded.value().completed_chunks, 2U);

    const auto resumed_res = alice.files().resume_transfer(transfer_id);
    ASSERT_TRUE(resumed_res.is_ok()) << resumed_res.error().user_message();
    EXPECT_EQ(resumed_res.value().status, FileTransferStatus::Completed);
    EXPECT_EQ(resumed_res.value().completed_chunks, 5U);
    // Strictly chunks 2, 3, 4 uploaded on resume -> 2 + 3 == 5 total calls (zero re-uploads)
    EXPECT_EQ(gateway_->uploaded_chunk_call_count(file_id), 5U);
    ASSERT_TRUE(gateway_->has_stored_file(file_id));

    // Verify Bob can download and decrypt the resumed upload bit-identically
    ASSERT_EQ(gateway_->submitted_fanouts().size(), 1U);
    const auto bob_msg = bob.messaging().process_inbound_message(cid, alice.uid, alice.did,
                                                                 gateway_->submitted_fanouts()[0].device_payloads[0]);
    ASSERT_TRUE(bob_msg.is_ok());
    const auto bob_ingest =
        bob.files().ingest_inbound_key_envelope_json(cid, alice.uid, bob_msg.value().encrypted_envelope_ref());
    ASSERT_TRUE(bob_ingest.is_ok());
    const std::filesystem::path dst_file = temp_dir_ / "resumed_output.bin";
    const auto dl_res = bob.files().start_download(bob_ingest.value().transfer_id, dst_file.string());
    ASSERT_TRUE(dl_res.is_ok());
    EXPECT_EQ(read_binary_file(dst_file), original_bytes);
}

TEST_F(FileManagerPipelineTest, PauseAndFullRestartResumeDownloadResumesFromPartFileWithoutRedownload) {
    FileWorkstation alice("alice", "dev-alice", temp_dir_ / "alice.db", gateway_);
    FileWorkstation bob("bob", "dev-bob", temp_dir_ / "bob.db", gateway_);
    const ConversationId cid("conv-pause-download");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "source_for_dl_resume.bin";
    const std::vector<uint8_t> original_bytes = make_file_bytes(4500U, 0x99U);
    write_binary_file(src_file, original_bytes);

    const auto up_res = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(up_res.is_ok());
    ASSERT_TRUE(up_res.value().key_envelope.has_value());

    const auto ingest_res = bob.files().ingest_inbound_key_envelope(cid, alice.uid, *up_res.value().key_envelope);
    ASSERT_TRUE(ingest_res.is_ok());
    const std::string dl_transfer_id = ingest_res.value().transfer_id;

    bob.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 2U) {
            EXPECT_TRUE(bob.files().pause_transfer(rec.transfer_id).is_ok());
        }
    });

    const std::filesystem::path dst_file = temp_dir_ / "bob_resume_target.bin";
    const auto paused_dl = bob.files().start_download(dl_transfer_id, dst_file.string());
    ASSERT_TRUE(paused_dl.is_ok()) << paused_dl.error().user_message();
    EXPECT_EQ(paused_dl.value().status, FileTransferStatus::Paused);
    EXPECT_EQ(paused_dl.value().completed_chunks, 2U);
    EXPECT_TRUE(std::filesystem::exists(dst_file.string() + ".part"));
    EXPECT_FALSE(std::filesystem::exists(dst_file));

    // Fail downloads for chunks 0 and 1 so resuming fails if it tried to re-download them
    bob.shutdown();
    bob.boot(1024U);
    gateway_->set_simulated_chunk_failure(0U, "Chunk 0 must not be re-downloaded");

    const auto resumed_dl = bob.files().resume_transfer(dl_transfer_id);
    ASSERT_TRUE(resumed_dl.is_ok()) << resumed_dl.error().user_message();
    EXPECT_EQ(resumed_dl.value().status, FileTransferStatus::Completed);
    EXPECT_EQ(resumed_dl.value().completed_chunks, 5U);
    EXPECT_TRUE(std::filesystem::exists(dst_file));
    EXPECT_FALSE(std::filesystem::exists(dst_file.string() + ".part"));
    EXPECT_EQ(read_binary_file(dst_file), original_bytes);
}

TEST_F(FileManagerPipelineTest, TamperedRemoteChunkFailsClosedAndDeletesPartFile) {
    FileWorkstation alice("alice", "dev-alice", temp_dir_ / "alice.db", gateway_);
    FileWorkstation bob("bob", "dev-bob", temp_dir_ / "bob.db", gateway_);
    const ConversationId cid("conv-tamper");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "integrity_source.bin";
    write_binary_file(src_file, make_file_bytes(3500U, 0x24U));

    const auto up_res = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(up_res.is_ok());
    ASSERT_TRUE(up_res.value().key_envelope.has_value());

    // Case 1: Mutate chunk 1 ciphertext in storage without recomputing chunk SHA-256 (after chunk 0 wrote to .part)
    {
        const auto ingest_res = bob.files().ingest_inbound_key_envelope(cid, alice.uid, *up_res.value().key_envelope);
        ASSERT_TRUE(ingest_res.is_ok());

        const auto good_chunk1 = gateway_->download_file_chunk(up_res.value().record.file_id, 1U);
        ASSERT_TRUE(good_chunk1.is_ok());
        std::vector<uint8_t> tampered_chunk1 = good_chunk1.value().encrypted_data;
        tampered_chunk1[20] ^= 0xFFU;
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(up_res.value().record.file_id, 1U, tampered_chunk1,
                                                                /*recompute_server_sha256=*/false));

        const std::filesystem::path dst1 = temp_dir_ / "tamper_case1.bin";
        const auto dl_res = bob.files().start_download(ingest_res.value().transfer_id, dst1.string());
        ASSERT_TRUE(dl_res.is_error());
        EXPECT_EQ(dl_res.error().category(), ClientErrorCategory::Crypto);
        EXPECT_FALSE(std::filesystem::exists(dst1));
        EXPECT_FALSE(std::filesystem::exists(dst1.string() + ".part"));
        const auto stored_rec = bob.files().get_transfer(ingest_res.value().transfer_id);
        ASSERT_TRUE(stored_rec.is_ok());
        EXPECT_EQ(stored_rec.value().status, FileTransferStatus::Failed);
    }

    // Case 2: Recompute server SHA-256 on tampered chunk 1 (simulates compromised storage server)
    {
        const auto ingest_res2 = bob.files().ingest_inbound_key_envelope(cid, alice.uid, *up_res.value().key_envelope);
        ASSERT_TRUE(ingest_res2.is_ok());

        const auto dl_chunk1 = gateway_->download_file_chunk(up_res.value().record.file_id, 1U);
        ASSERT_TRUE(dl_chunk1.is_ok());
        std::vector<uint8_t> re_tampered = dl_chunk1.value().encrypted_data;
        re_tampered[24] ^= 0x55U;
        ASSERT_TRUE(gateway_->mutate_stored_file_chunk_for_test(up_res.value().record.file_id, 1U, re_tampered,
                                                                /*recompute_server_sha256=*/true));

        const std::filesystem::path dst2 = temp_dir_ / "tamper_case2.bin";
        const auto dl_res2 = bob.files().start_download(ingest_res2.value().transfer_id, dst2.string());
        ASSERT_TRUE(dl_res2.is_error());
        EXPECT_FALSE(std::filesystem::exists(dst2));
        EXPECT_FALSE(std::filesystem::exists(dst2.string() + ".part"));
    }
}

TEST_F(FileManagerPipelineTest, CancelTransferAbortsRemoteUploadPurgesKeyAndDeletesPartFile) {
    FileWorkstation alice("alice", "dev-alice", temp_dir_ / "alice.db", gateway_);
    FileWorkstation bob("bob", "dev-bob", temp_dir_ / "bob.db", gateway_);
    const ConversationId cid("conv-cancel");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "cancel_src.bin";
    write_binary_file(src_file, make_file_bytes(4500U, 0x12U));

    // Pause upload at chunk 1, then cancel it while paused
    alice.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 1U) {
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
    const std::string up_tx = up_paused.value().record.transfer_id;
    const std::string up_fid = up_paused.value().record.file_id;
    const std::string upload_id = up_paused.value().record.upload_id;
    EXPECT_TRUE(alice.secure_storage->has_secret(FileManager::file_key_storage_id(up_fid)).value());

    ASSERT_TRUE(alice.files().cancel_transfer(up_tx).is_ok());
    EXPECT_FALSE(alice.secure_storage->has_secret(FileManager::file_key_storage_id(up_fid)).value());
    EXPECT_EQ(alice.files().get_transfer(up_tx).value().status, FileTransferStatus::Cancelled);
    EXPECT_TRUE(gateway_->finalize_file_upload(FileUploadFinalizeRequest{.upload_id = upload_id, .file_id = up_fid})
                    .is_error());

    // Now test active download cancel during progress callback cleans up .part + key
    alice.files().set_progress_callback({});
    const auto complete_up = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(complete_up.is_ok());
    ASSERT_TRUE(complete_up.value().key_envelope.has_value());

    const auto dl_ingest = bob.files().ingest_inbound_key_envelope(cid, alice.uid, *complete_up.value().key_envelope);
    ASSERT_TRUE(dl_ingest.is_ok());
    const std::string dl_tx = dl_ingest.value().transfer_id;
    const std::string dl_fid = dl_ingest.value().file_id;

    bob.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 2U) {
            EXPECT_TRUE(bob.files().cancel_transfer(rec.transfer_id).is_ok());
        }
    });

    const std::filesystem::path dst_file = temp_dir_ / "cancelled_dl.bin";
    const auto dl_cancel_res = bob.files().start_download(dl_tx, dst_file.string());
    ASSERT_TRUE(dl_cancel_res.is_error());
    EXPECT_EQ(bob.files().get_transfer(dl_tx).value().status, FileTransferStatus::Cancelled);
    EXPECT_FALSE(bob.secure_storage->has_secret(FileManager::file_key_storage_id(dl_fid)).value());
    EXPECT_FALSE(std::filesystem::exists(dst_file));
    EXPECT_FALSE(std::filesystem::exists(dst_file.string() + ".part"));
}

TEST_F(FileManagerPipelineTest, Adr008KeyChangedAndBlockedPeerHaltsUploadBeforeAndAfterChunks) {
    FileWorkstation alice("alice", "dev-alice", temp_dir_ / "alice.db", gateway_);
    FileWorkstation bob("bob", "dev-bob", temp_dir_ / "bob.db", gateway_);
    const ConversationId cid("conv-adr008-guard");
    wire_direct_conversation(alice, bob, cid);

    const std::filesystem::path src_file = temp_dir_ / "guarded.bin";
    write_binary_file(src_file, make_file_bytes(2500U, 0x42U));

    // 1. KeyChanged blocks upload before any chunks are uploaded
    Contact changed_bob(bob.uid, "Bob", KeyVerificationStatus::KeyChanged, "fp-bob-old");
    ASSERT_TRUE(alice.local_store().save_contact(changed_bob).is_ok());
    const auto guard1 = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(guard1.is_error());
    EXPECT_TRUE(alice.files().list_transfers(cid).value().empty());

    // 2. Blocked peer also blocks upload
    Contact blocked_bob(bob.uid, "Bob", KeyVerificationStatus::Verified, "fp-bob", /*is_blocked=*/true);
    ASSERT_TRUE(alice.local_store().save_contact(blocked_bob).is_ok());
    const auto guard2 = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(guard2.is_error());

    // 3. Re-verify Bob, start upload, then trigger KeyChanged mid-transfer -> E2EE dispatch halts
    Contact verified_bob(bob.uid, "Bob", KeyVerificationStatus::Verified, "fp-bob");
    ASSERT_TRUE(alice.local_store().save_contact(verified_bob).is_ok());
    gateway_->clear_submitted_fanouts();

    alice.files().set_progress_callback([&](const FileTransferRecord& rec) {
        if (rec.status == FileTransferStatus::InProgress && rec.completed_chunks == 2U) {
            Contact mid_changed(bob.uid, "Bob", KeyVerificationStatus::KeyChanged, "fp-bob");
            EXPECT_TRUE(alice.local_store().save_contact(mid_changed).is_ok());
        }
    });

    const auto mid_guard = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(mid_guard.is_error());
    EXPECT_TRUE(gateway_->submitted_fanouts().empty());
}

TEST_F(FileManagerPipelineTest, ValidationRejectsInvalidFilesAndTransientNetworkDropIsResumable) {
    FileWorkstation alice("alice", "dev-alice", temp_dir_ / "alice.db", gateway_);
    FileWorkstation bob("bob", "dev-bob", temp_dir_ / "bob.db", gateway_);
    const ConversationId cid("conv-drop");
    wire_direct_conversation(alice, bob, cid);

    EXPECT_TRUE(alice.files()
                    .start_upload(FileUploadRequest{
                        .conversation_id = cid,
                        .owner_user_id = alice.uid,
                        .owner_device_id = alice.did,
                        .local_file_path = (temp_dir_ / "missing.bin").string(),
                    })
                    .is_error());

    const std::filesystem::path empty_file = temp_dir_ / "empty.bin";
    write_binary_file(empty_file, {});
    EXPECT_TRUE(alice.files()
                    .start_upload(FileUploadRequest{
                        .conversation_id = cid,
                        .owner_user_id = alice.uid,
                        .owner_device_id = alice.did,
                        .local_file_path = empty_file.string(),
                    })
                    .is_error());

    const std::filesystem::path src_file = temp_dir_ / "drop_retry.bin";
    write_binary_file(src_file, make_file_bytes(3200U, 0x63U));

    gateway_->set_simulated_chunk_failure(2U, "Simulated transient link loss at chunk 2");
    const auto dropped_res = alice.files().start_upload(FileUploadRequest{
        .conversation_id = cid,
        .owner_user_id = alice.uid,
        .owner_device_id = alice.did,
        .peer_user_id = bob.uid,
        .local_file_path = src_file.string(),
    });
    ASSERT_TRUE(dropped_res.is_error());
    EXPECT_EQ(dropped_res.error().category(), ClientErrorCategory::Network);

    const auto transfers = alice.files().list_transfers(cid);
    ASSERT_TRUE(transfers.is_ok());
    ASSERT_EQ(transfers.value().size(), 1U);
    EXPECT_EQ(transfers.value()[0].status, FileTransferStatus::Paused);
    EXPECT_EQ(transfers.value()[0].completed_chunks, 2U);

    gateway_->set_simulated_chunk_failure(std::nullopt);
    const auto resumed = alice.files().resume_transfer(transfers.value()[0].transfer_id);
    ASSERT_TRUE(resumed.is_ok()) << resumed.error().user_message();
    EXPECT_EQ(resumed.value().status, FileTransferStatus::Completed);
    EXPECT_EQ(resumed.value().completed_chunks, 4U);
}

} // namespace
} // namespace securecloud::client::tests
