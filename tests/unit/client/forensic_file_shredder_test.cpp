#include "infrastructure/adapters/file_shredder.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "infrastructure/client_logger.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace std::chrono_literals;
using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure;
using namespace securecloud::client::infrastructure::adapters;

class ForensicFileShredderTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_file_shredder_test_" + suffix);
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override {
        (void)ClientLogger::flush_and_close_log_file();
        ClientLogger::reset_sink();
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::vector<uint8_t> read_binary(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    static std::string read_text(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    std::filesystem::path temp_dir_;
};

TEST_F(ForensicFileShredderTest, ThreePassOverwriteObservedOnDiskBeforeTruncateAndUnlink) {
    const std::filesystem::path target = temp_dir_ / "sensitive_secret_cache.bin";
    const std::string plaintext = "TOP_SECRET_E2EE_RATCHET_PLAINTEXT_SAMPLE_1234567890";
    {
        std::ofstream ofs(target, std::ios::binary | std::ios::trunc);
        ofs.write(plaintext.data(), static_cast<std::streamsize>(plaintext.size()));
    }
    const std::vector<uint8_t> original_bytes(plaintext.begin(), plaintext.end());

    std::vector<std::vector<uint8_t>> observed_passes;
    ShredOptions options;
    options.overwrite_passes = 3U;
    options.pass_observer = [&observed_passes](uint32_t pass_index, const std::filesystem::path& file_path) {
        (void)pass_index;
        observed_passes.push_back(read_binary(file_path));
    };

    const auto res = FileShredder::shred_file(target, options);
    ASSERT_TRUE(res.is_ok());
    EXPECT_EQ(res.value(), plaintext.size() * 3U);
    EXPECT_FALSE(std::filesystem::exists(target));

    ASSERT_EQ(observed_passes.size(), 3U);
    // Pass 0 must be all 0x00 bytes of exact original length.
    EXPECT_EQ(observed_passes[0], std::vector<uint8_t>(original_bytes.size(), 0x00));
    // Pass 1 must be all 0xFF bytes of exact original length.
    EXPECT_EQ(observed_passes[1], std::vector<uint8_t>(original_bytes.size(), 0xFF));
    // Pass 2 must be random entropy distinct from original plaintext, all-zero, and all-0xFF.
    EXPECT_EQ(observed_passes[2].size(), original_bytes.size());
    EXPECT_NE(observed_passes[2], original_bytes);
    EXPECT_NE(observed_passes[2], observed_passes[0]);
    EXPECT_NE(observed_passes[2], observed_passes[1]);
}

TEST_F(ForensicFileShredderTest, MultiChunkStreamingShred256KiBFile) {
    const std::filesystem::path target = temp_dir_ / "large_attachment.part";
    constexpr std::size_t kSize = 256U * 1024U; // 4 x 64 KiB streaming chunks
    {
        std::vector<uint8_t> payload(kSize, 0x5A);
        std::ofstream ofs(target, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    }

    ShredOptions options;
    options.overwrite_passes = 3U;
    options.chunk_size_bytes = 65536U;

    const auto res = FileShredder::shred_file(target, options);
    ASSERT_TRUE(res.is_ok());
    EXPECT_EQ(res.value(), kSize * 3U);
    EXPECT_FALSE(std::filesystem::exists(target));
}

TEST_F(ForensicFileShredderTest, IdempotentMissingFileZeroByteFileAndDirectoryRejection) {
    const std::filesystem::path missing = temp_dir_ / "does_not_exist.db";
    const auto missing_res = FileShredder::shred_file(missing);
    ASSERT_TRUE(missing_res.is_ok());
    EXPECT_EQ(missing_res.value(), 0U);

    const std::filesystem::path empty_file = temp_dir_ / "empty.part";
    {
        std::ofstream ofs(empty_file, std::ios::binary | std::ios::trunc);
    }
    ASSERT_TRUE(std::filesystem::exists(empty_file));
    const auto empty_res = FileShredder::shred_file(empty_file);
    ASSERT_TRUE(empty_res.is_ok());
    EXPECT_EQ(empty_res.value(), 0U);
    EXPECT_FALSE(std::filesystem::exists(empty_file));

    const auto dir_res = FileShredder::shred_file(temp_dir_);
    ASSERT_TRUE(dir_res.is_error());
    EXPECT_EQ(dir_res.error().category(), ClientErrorCategory::Validation);

    const auto empty_path_res = FileShredder::shred_file(std::filesystem::path{});
    ASSERT_TRUE(empty_path_res.is_error());
    EXPECT_EQ(empty_path_res.error().category(), ClientErrorCategory::Validation);
}

TEST_F(ForensicFileShredderTest, SelectiveDirectoryArtifactShreddingPreservesUnrelatedFiles) {
    const std::filesystem::path p1 = temp_dir_ / "download_01.part";
    const std::filesystem::path p2 = temp_dir_ / "client_runtime.log";
    const std::filesystem::path p3 = temp_dir_ / "vault.db-wal";
    const std::filesystem::path p4 = temp_dir_ / "vault.db-shm";
    const std::filesystem::path keep = temp_dir_ / "readme_unrelated.txt";

    for (const auto& f : {p1, p2, p3, p4, keep}) {
        std::ofstream ofs(f, std::ios::binary | std::ios::trunc);
        ofs << "artifact-content-" << f.filename().string();
    }

    const auto res = FileShredder::shred_directory_artifacts(temp_dir_, {".part", ".log", "-wal", "-shm"});
    ASSERT_TRUE(res.is_ok());
    EXPECT_TRUE(res.value().failed_paths.empty());
    EXPECT_EQ(res.value().files_shredded, 4U);
    EXPECT_GT(res.value().bytes_overwritten, 0U);

    EXPECT_FALSE(std::filesystem::exists(p1));
    EXPECT_FALSE(std::filesystem::exists(p2));
    EXPECT_FALSE(std::filesystem::exists(p3));
    EXPECT_FALSE(std::filesystem::exists(p4));
    EXPECT_TRUE(std::filesystem::exists(keep));
}

TEST_F(ForensicFileShredderTest, SqlCipherLocalStoreDestroyAndShredRemovesVaultSidecarsAndMasterKey) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;
    SqlCipherLocalStore sql_store(secure_storage, crypto);

    const std::filesystem::path db_file = temp_dir_ / "encrypted_client.db";
    const std::filesystem::path wal_file = temp_dir_ / "encrypted_client.db-wal";
    const std::filesystem::path shm_file = temp_dir_ / "encrypted_client.db-shm";

    ASSERT_TRUE(sql_store.open(db_file.string()).is_ok());

    const ConversationId cid("conv-shred-01");
    const auto now = std::chrono::system_clock::time_point(1763890100000ms);
    Conversation conv(cid, ConversationType::Direct, "Secret Channel", {UserId("alice"), UserId("bob")}, now, now, 1,
                      false);
    ASSERT_TRUE(sql_store.save_conversation(conv).is_ok());

    Message msg(MessageId("msg-shred-01"), cid, UserId("alice"), DeviceId("dev-a1"), DeliveryState::Delivered, now,
                "cipher-blob-ref-1234", 2);
    ASSERT_TRUE(sql_store.save_message(msg).is_ok());

    // Ensure WAL/SHM sidecar presence is covered (create synthetic sidecars if OS checkpointed cleanly).
    if (!std::filesystem::exists(wal_file)) {
        std::ofstream ofs(wal_file, std::ios::binary | std::ios::trunc);
        ofs << "wal-frame-bytes";
    }
    if (!std::filesystem::exists(shm_file)) {
        std::ofstream ofs(shm_file, std::ios::binary | std::ios::trunc);
        ofs << "shm-index-bytes";
    }

    ASSERT_TRUE(secure_storage.has_secret(SqlCipherLocalStore::kMasterKeyId).value());

    // Invoke polymorphically through ILocalStore& as EmergencyManager will in T03.
    ILocalStore& store_iface = sql_store;
    const auto destroy_res = store_iface.destroy_and_shred();
    ASSERT_TRUE(destroy_res.is_ok());
    // Note: clean SQLite close checkpoints/removes active -wal and -shm before returning, leaving >=1 .db file to
    // shred.
    EXPECT_GE(destroy_res.value(), 1U);

    EXPECT_FALSE(sql_store.is_open());
    EXPECT_TRUE(sql_store.database_path().empty());
    EXPECT_FALSE(std::filesystem::exists(db_file));
    EXPECT_FALSE(std::filesystem::exists(wal_file));
    EXPECT_FALSE(std::filesystem::exists(shm_file));
    EXPECT_FALSE(secure_storage.has_secret(SqlCipherLocalStore::kMasterKeyId).value());

    // Also verify post-close/crash scenario where leftover -wal/-shm sidecars remain alongside a closed vault.
    const std::filesystem::path crash_db = temp_dir_ / "crash_recovery.db";
    const std::filesystem::path crash_wal = temp_dir_ / "crash_recovery.db-wal";
    const std::filesystem::path crash_shm = temp_dir_ / "crash_recovery.db-shm";
    ASSERT_TRUE(sql_store.open(crash_db.string()).is_ok());
    ASSERT_TRUE(sql_store.save_conversation(conv).is_ok());
    ASSERT_TRUE(sql_store.close().is_ok());
    {
        std::ofstream ofs_wal(crash_wal, std::ios::binary | std::ios::trunc);
        ofs_wal << "orphan-wal-frame-bytes";
        std::ofstream ofs_shm(crash_shm, std::ios::binary | std::ios::trunc);
        ofs_shm << "orphan-shm-index-bytes";
    }
    const auto crash_destroy = store_iface.destroy_and_shred();
    ASSERT_TRUE(crash_destroy.is_ok());
    EXPECT_EQ(crash_destroy.value(), 3U);
    EXPECT_FALSE(std::filesystem::exists(crash_db));
    EXPECT_FALSE(std::filesystem::exists(crash_wal));
    EXPECT_FALSE(std::filesystem::exists(crash_shm));
    EXPECT_FALSE(secure_storage.has_secret(SqlCipherLocalStore::kMasterKeyId).value());

    // Verify MemoryLocalStore::destroy_and_shred clears all collections and closes cleanly.
    MemoryLocalStore mem_store;
    ASSERT_TRUE(mem_store.open("mem").is_ok());
    ASSERT_TRUE(mem_store.save_conversation(conv).is_ok());
    const auto mem_destroy = mem_store.destroy_and_shred();
    ASSERT_TRUE(mem_destroy.is_ok());
    EXPECT_EQ(mem_destroy.value(), 0U);
    EXPECT_TRUE(mem_store.list_conversations().is_error());
}

TEST_F(ForensicFileShredderTest, ClientLoggerDiskFileCloseShredAndDuressSanitization) {
    const std::filesystem::path log_file = temp_dir_ / "logs" / "securecloud_client.log";
    ASSERT_TRUE(ClientLogger::set_log_file_path(log_file));
    EXPECT_EQ(ClientLogger::log_file_path(), log_file);

    ClientLogger::info("EmergencyAuth",
                       R"({"duress_pin":"998877","derived_hash_hex":"deadbeef","salt_hex":"00112233","event":"test"})");
    ClientLogger::warn("EmergencyAuth", "duress_pin=998877&token=abc123");

    const std::string log_contents = read_text(log_file);
    EXPECT_FALSE(log_contents.empty());
    EXPECT_EQ(log_contents.find("998877"), std::string::npos);
    EXPECT_EQ(log_contents.find("deadbeef"), std::string::npos);
    EXPECT_EQ(log_contents.find("00112233"), std::string::npos);
    EXPECT_EQ(log_contents.find("abc123"), std::string::npos);
    EXPECT_NE(log_contents.find("[REDACTED]"), std::string::npos);

    const std::filesystem::path closed_log = ClientLogger::flush_and_close_log_file();
    EXPECT_EQ(closed_log, log_file);
    EXPECT_TRUE(ClientLogger::log_file_path().empty());

    const auto shred_res = FileShredder::shred_file(closed_log);
    ASSERT_TRUE(shred_res.is_ok());
    EXPECT_GT(shred_res.value(), 0U);
    EXPECT_FALSE(std::filesystem::exists(log_file));
}

} // namespace
} // namespace securecloud::client::tests
