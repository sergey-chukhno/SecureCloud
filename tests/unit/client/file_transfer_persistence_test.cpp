#include "domain/file_transfer.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <vector>

namespace securecloud::client::infrastructure::adapters::test {
namespace {

using namespace std::chrono_literals;
using domain::Conversation;
using domain::ConversationId;
using domain::ConversationType;
using domain::FileTransferDirection;
using domain::FileTransferRecord;
using domain::FileTransferStatus;
using domain::UserId;
using securecloud::common::configuration::SecretString;

FileTransferRecord make_transfer_record(std::string transfer_id, std::string file_id, const std::string& conv_id,
                                        FileTransferDirection direction, FileTransferStatus status,
                                        uint32_t total_chunks, uint32_t completed_chunks, int64_t updated_at_ms,
                                        std::string file_name = "spec.pdf",
                                        std::string local_path = "/tmp/vault/spec.pdf") {
    FileTransferRecord rec;
    rec.transfer_id = std::move(transfer_id);
    rec.file_id = std::move(file_id);
    rec.upload_id = "upload-" + rec.file_id;
    rec.conversation_id = ConversationId(conv_id);
    rec.peer_user_id = UserId("bob-uid");
    rec.local_path = std::move(local_path);
    rec.file_name = std::move(file_name);
    rec.mime_type = "application/pdf";
    rec.cipher_suite = "AES-256-GCM-v1";
    rec.direction = direction;
    rec.status = status;
    rec.plaintext_size_bytes = 20480ULL;
    rec.encrypted_size_bytes = 20592ULL;
    rec.chunk_size_bytes = 4096U;
    rec.total_chunks = total_chunks;
    rec.completed_chunks = completed_chunks;
    rec.plaintext_sha256 = std::string(64U, 'a');
    rec.ciphertext_sha256 = std::string(64U, 'b');
    rec.created_at_ms = 1760000000000LL;
    rec.updated_at_ms = updated_at_ms;
    return rec;
}

class FileTransferPersistenceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_file_transfers_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "client_vault.db").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::string read_raw_bytes(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return {};
        }
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(FileTransferPersistenceTest, MemoryLocalStoreCrudFilteringOrderingAndCascade) {
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("mem").is_ok());

    const ConversationId conv_a("conv-a");
    const ConversationId conv_b("conv-b");
    ASSERT_TRUE(store.save_conversation(Conversation(conv_a, ConversationType::Direct, "Conv A")).is_ok());
    ASSERT_TRUE(store.save_conversation(Conversation(conv_b, ConversationType::Direct, "Conv B")).is_ok());

    FileTransferRecord r1 = make_transfer_record("tr-1", "file-1", "conv-a", FileTransferDirection::Outbound,
                                                 FileTransferStatus::InProgress, 5U, 2U, 1000LL);
    FileTransferRecord r2 = make_transfer_record("tr-2", "file-2", "conv-b", FileTransferDirection::Inbound,
                                                 FileTransferStatus::Paused, 8U, 3U, 2000LL);
    FileTransferRecord r3 = make_transfer_record("tr-3", "file-3", "conv-a", FileTransferDirection::Outbound,
                                                 FileTransferStatus::Completed, 4U, 4U, 3000LL);

    ASSERT_TRUE(store.save_file_transfer(r1).is_ok());
    ASSERT_TRUE(store.save_file_transfer(r2).is_ok());
    ASSERT_TRUE(store.save_file_transfer(r3).is_ok());

    // Upsert checkpoint progression
    r1.completed_chunks = 4U;
    r1.updated_at_ms = 4000LL;
    ASSERT_TRUE(store.save_file_transfer(r1).is_ok());

    const auto fetched = store.get_file_transfer("tr-1");
    ASSERT_TRUE(fetched.is_ok());
    EXPECT_EQ(fetched.value().completed_chunks, 4U);
    EXPECT_EQ(fetched.value().progress_percent(), 80U);

    // Unfiltered newest-first ordering
    const auto all_res = store.list_file_transfers();
    ASSERT_TRUE(all_res.is_ok());
    ASSERT_EQ(all_res.value().size(), 3U);
    EXPECT_EQ(all_res.value()[0].transfer_id, "tr-1");
    EXPECT_EQ(all_res.value()[1].transfer_id, "tr-3");
    EXPECT_EQ(all_res.value()[2].transfer_id, "tr-2");

    // Conversation-filtered listing
    const auto conv_a_list = store.list_file_transfers(conv_a);
    ASSERT_TRUE(conv_a_list.is_ok());
    ASSERT_EQ(conv_a_list.value().size(), 2U);
    EXPECT_EQ(conv_a_list.value()[0].transfer_id, "tr-1");
    EXPECT_EQ(conv_a_list.value()[1].transfer_id, "tr-3");

    ASSERT_TRUE(store.delete_file_transfer("tr-3").is_ok());
    EXPECT_TRUE(store.get_file_transfer("tr-3").is_error());
    EXPECT_TRUE(store.delete_file_transfer("tr-3").is_error());

    // Cascade delete conversation removes tr-1 but leaves conv-b tr-2
    ASSERT_TRUE(store.delete_conversation(conv_a).is_ok());
    const auto remaining = store.list_file_transfers();
    ASSERT_TRUE(remaining.is_ok());
    ASSERT_EQ(remaining.value().size(), 1U);
    EXPECT_EQ(remaining.value()[0].transfer_id, "tr-2");

    // Validation & closed-store checks
    FileTransferRecord invalid = r2;
    invalid.transfer_id.clear();
    EXPECT_TRUE(store.save_file_transfer(invalid).is_error());
    EXPECT_TRUE(store.get_file_transfer("").is_error());
    EXPECT_TRUE(store.delete_file_transfer("").is_error());

    ASSERT_TRUE(store.close().is_ok());
    EXPECT_TRUE(store.save_file_transfer(r2).is_error());
    EXPECT_TRUE(store.get_file_transfer("tr-2").is_error());
    EXPECT_TRUE(store.list_file_transfers().is_error());
    EXPECT_TRUE(store.delete_file_transfer("tr-2").is_error());
}

TEST_F(FileTransferPersistenceTest, SqlCipherLocalStoreRestartDurabilityAndCheckpointUpdates) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    const ConversationId conv_1("conv-sql-1");
    const ConversationId conv_2("conv-sql-2");

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        ASSERT_TRUE(store.save_conversation(Conversation(conv_1, ConversationType::Direct, "Chat 1")).is_ok());
        ASSERT_TRUE(store.save_conversation(Conversation(conv_2, ConversationType::Group, "Group 2")).is_ok());

        FileTransferRecord outbound =
            make_transfer_record("tr-up-1", "file-up-1", "conv-sql-1", FileTransferDirection::Outbound,
                                 FileTransferStatus::InProgress, 5U, 2U, 1000LL);
        ASSERT_TRUE(store.save_file_transfer(outbound).is_ok());

        // Transition InProgress -> Paused preserving chunk 2 checkpoint
        outbound.status = FileTransferStatus::Paused;
        outbound.updated_at_ms = 2000LL;
        ASSERT_TRUE(store.save_file_transfer(outbound).is_ok());

        FileTransferRecord inbound =
            make_transfer_record("tr-dn-1", "file-dn-1", "conv-sql-2", FileTransferDirection::Inbound,
                                 FileTransferStatus::InProgress, 4U, 1U, 3000LL);
        ASSERT_TRUE(store.save_file_transfer(inbound).is_ok());
        ASSERT_TRUE(store.close().is_ok());
    }

    // Reopen fresh instance simulating full process restart
    SqlCipherLocalStore reopened(secure_storage, crypto);
    ASSERT_TRUE(reopened.open(db_path_).is_ok());

    const auto up_res = reopened.get_file_transfer("tr-up-1");
    ASSERT_TRUE(up_res.is_ok());
    EXPECT_EQ(up_res.value().status, FileTransferStatus::Paused);
    EXPECT_EQ(up_res.value().completed_chunks, 2U);
    EXPECT_EQ(up_res.value().total_chunks, 5U);
    EXPECT_EQ(up_res.value().progress_percent(), 40U);

    // Resume and complete
    FileTransferRecord resumed = up_res.value();
    resumed.status = FileTransferStatus::Completed;
    resumed.completed_chunks = 5U;
    resumed.updated_at_ms = 5000LL;
    ASSERT_TRUE(reopened.save_file_transfer(resumed).is_ok());

    const auto all_list = reopened.list_file_transfers();
    ASSERT_TRUE(all_list.is_ok());
    ASSERT_EQ(all_list.value().size(), 2U);
    EXPECT_EQ(all_list.value()[0].transfer_id, "tr-up-1");
    EXPECT_EQ(all_list.value()[0].status, FileTransferStatus::Completed);
    EXPECT_EQ(all_list.value()[1].transfer_id, "tr-dn-1");

    const auto conv2_list = reopened.list_file_transfers(conv_2);
    ASSERT_TRUE(conv2_list.is_ok());
    ASSERT_EQ(conv2_list.value().size(), 1U);
    EXPECT_EQ(conv2_list.value()[0].transfer_id, "tr-dn-1");

    ASSERT_TRUE(reopened.delete_conversation(conv_2).is_ok());
    EXPECT_TRUE(reopened.get_file_transfer("tr-dn-1").is_error());
    ASSERT_TRUE(reopened.delete_file_transfer("tr-up-1").is_ok());
    EXPECT_TRUE(reopened.list_file_transfers().value().empty());
}

TEST_F(FileTransferPersistenceTest, SqlCipherDatabaseContainsZeroPlaintextTransferMetadataOnDisk) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    const std::string secret_filename = "classified-merger-plan.pdf";
    const std::string secret_local_path = "/Users/alice/Vault/classified-merger-plan.pdf";
    const std::string secret_pt_sha(64U, 'e');
    const std::string secret_ct_sha(64U, 'f');

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());

        FileTransferRecord rec = make_transfer_record("tr-secret-01", "file-secret-01", "conv-secret-01",
                                                      FileTransferDirection::Outbound, FileTransferStatus::Paused, 6U,
                                                      3U, 1760000010000LL, secret_filename, secret_local_path);
        rec.plaintext_sha256 = secret_pt_sha;
        rec.ciphertext_sha256 = secret_ct_sha;
        ASSERT_TRUE(store.save_file_transfer(rec).is_ok());
        ASSERT_TRUE(store.close().is_ok());
    }

    const std::string db_bytes = read_raw_bytes(db_path_);
    const std::string wal_bytes = read_raw_bytes(db_path_ + "-wal");
    const std::string combined = db_bytes + wal_bytes;

    ASSERT_FALSE(db_bytes.empty());
    EXPECT_EQ(combined.find("SQLite format 3"), std::string::npos);
    EXPECT_EQ(combined.find(secret_filename), std::string::npos);
    EXPECT_EQ(combined.find(secret_local_path), std::string::npos);
    EXPECT_EQ(combined.find("tr-secret-01"), std::string::npos);
    EXPECT_EQ(combined.find(secret_pt_sha), std::string::npos);
    EXPECT_EQ(combined.find(secret_ct_sha), std::string::npos);
}

TEST_F(FileTransferPersistenceTest, SqlCipherRejectsWrongMasterKeyAndInvalidInputs) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        const FileTransferRecord rec =
            make_transfer_record("tr-key-check", "file-key-check", "conv-key-check", FileTransferDirection::Inbound,
                                 FileTransferStatus::Pending, 2U, 0U, 1000LL);
        ASSERT_TRUE(store.save_file_transfer(rec).is_ok());

        FileTransferRecord invalid = rec;
        invalid.file_id.clear();
        EXPECT_TRUE(store.save_file_transfer(invalid).is_error());
        EXPECT_TRUE(store.get_file_transfer("").is_error());
        EXPECT_TRUE(store.get_file_transfer("non-existent").is_error());
        EXPECT_TRUE(store.delete_file_transfer("").is_error());
        EXPECT_TRUE(store.delete_file_transfer("non-existent").is_error());
        ASSERT_TRUE(store.close().is_ok());
    }

    // Overwrite master key in ISecureStorage with a different valid 256-bit key
    ASSERT_TRUE(
        secure_storage.store_secret(SqlCipherLocalStore::kMasterKeyId, SecretString(std::string(64U, '9'))).is_ok());

    SqlCipherLocalStore tampered(secure_storage, crypto);
    const auto open_res = tampered.open(db_path_);
    ASSERT_TRUE(open_res.is_error());
    EXPECT_EQ(open_res.error().category(), application::ClientErrorCategory::Crypto);
    EXPECT_FALSE(tampered.is_open());
}

} // namespace
} // namespace securecloud::client::infrastructure::adapters::test
