#include "files/files_config.hpp"
#include "files/service/storage_engine.hpp"
#include "files/storage/s3_client.hpp"
#include "files/storage/s3_exceptions.hpp"
#include "securecloud/health/transport_probe.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace securecloud::files {
namespace {

using service::IStorageEngine;
using service::StorageEngine;
using storage::ByteRange;
using storage::CompletedPart;
using storage::S3Client;
using storage::S3ClientConfig;
using storage::SigV4Signer;

#ifdef _WIN32
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

inline std::string generate_test_uuid() {
    static std::atomic<uint64_t> counter{1};
    const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
    uint64_t id = counter.fetch_add(1);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << (now & 0xFFFFFFFF) << "-" << std::setw(4)
        << ((now >> 32) & 0xFFFF) << "-4" << std::setw(3) << (id & 0x0FFF) << "-a" << std::setw(3) << (id & 0x0FFF)
        << "-" << std::setw(12) << (now ^ id);
    return oss.str();
}

class FilesMinioStorageIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ensure_integration_winsock();

        const char* env_host = std::getenv("MINIO_HOST");
        minio_host_ = env_host ? env_host : "127.0.0.1";

        const char* env_port = std::getenv("MINIO_PORT");
        minio_port_ = env_port ? static_cast<uint16_t>(std::strtol(env_port, nullptr, 10)) : 9000;

        // Preflight probe to MinIO S3 endpoint
        if (!common::health::probe_tcp_connectivity(minio_host_, minio_port_, std::chrono::milliseconds(500))) {
            GTEST_SKIP() << "MinIO S3 instance on " << minio_host_ << ":" << minio_port_
                         << " is not reachable; skipping live integration tests.";
        }

        const char* env_endpoint = std::getenv("MINIO_ENDPOINT");
        s3_cfg_.endpoint = env_endpoint ? env_endpoint : ("http://" + minio_host_ + ":" + std::to_string(minio_port_));

        const char* env_bucket = std::getenv("MINIO_BUCKET");
        s3_cfg_.bucket = env_bucket ? env_bucket : "securecloud-files-encrypted";

        const char* env_user = std::getenv("MINIO_ACCESS_KEY");
        s3_cfg_.access_key = env_user ? env_user : "files_minio_user";

        const char* env_secret = std::getenv("MINIO_SECRET_KEY");
        s3_cfg_.secret_key = common::configuration::SecretString(env_secret ? env_secret : "files_minio_secret");

        s3_cfg_.default_timeout = std::chrono::milliseconds(3000);

        s3_client_ = std::make_shared<S3Client>(s3_cfg_);
        engine_ = std::make_unique<StorageEngine>(s3_client_);
    }

    std::string minio_host_{"127.0.0.1"};
    uint16_t minio_port_{9000};
    S3ClientConfig s3_cfg_;
    std::shared_ptr<S3Client> s3_client_;
    std::unique_ptr<StorageEngine> engine_;
};

// ============================================================================
// TC1: Live Bucket Reachability & Credential Validation
// ============================================================================
TEST_F(FilesMinioStorageIntegrationTest, TC1_LiveBucketReachabilityAndPing) {
    ASSERT_TRUE(s3_client_ != nullptr);
    EXPECT_TRUE(s3_client_->ping_bucket(std::chrono::milliseconds(2000)));
}

// ============================================================================
// TC2: Live Chunk PUT and GET Roundtrip with SHA-256 Verification (1 MiB)
// ============================================================================
TEST_F(FilesMinioStorageIntegrationTest, TC2_LiveChunkPutAndGetRoundtrip) {
    const std::string transfer_id = generate_test_uuid();
    constexpr size_t kPayloadSize = 1024 * 1024; // 1 MiB

    std::string payload;
    payload.reserve(kPayloadSize);
    for (size_t i = 0; i < kPayloadSize; ++i) {
        payload.push_back(static_cast<char>((i * 31 + 17) & 0xFF));
    }

    const std::string expected_sha256 = SigV4Signer::sha256_hex(payload);

    // 1. Put chunk
    EXPECT_TRUE(engine_->put_chunk(transfer_id, 0, payload, expected_sha256));

    // 2. Get chunk
    auto fetched = engine_->get_chunk(transfer_id, 0);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(fetched->size(), payload.size());
    EXPECT_EQ(*fetched, payload);

    // 3. Verify SHA-256 of retrieved payload
    EXPECT_EQ(SigV4Signer::sha256_hex(*fetched), expected_sha256);

    // 4. Clean up
    EXPECT_TRUE(engine_->delete_chunk(transfer_id, 0));
}

// ============================================================================
// TC3: Range GET Verification Matching Exact Byte Slices from Live MinIO
// ============================================================================
TEST_F(FilesMinioStorageIntegrationTest, TC3_LiveRangeGetVerification) {
    const std::string file_id = generate_test_uuid();
    constexpr size_t kFileSize = 16 * 1024; // 16 KiB

    std::string file_payload;
    file_payload.reserve(kFileSize);
    for (size_t i = 0; i < kFileSize; ++i) {
        file_payload.push_back(static_cast<char>((i * 7 + 13) & 0xFF));
    }

    const std::string file_sha = SigV4Signer::sha256_hex(file_payload);

    // Put finalized file object
    EXPECT_TRUE(engine_->put_file_object(file_id, 1, file_payload, file_sha));

    // Range read: First 1024 bytes (0-1023)
    ByteRange range1{.start_byte = 0, .end_byte = 1023};
    auto slice1 = engine_->get_file_object(file_id, 1, range1);
    ASSERT_TRUE(slice1.has_value());
    EXPECT_EQ(slice1->size(), 1024);
    EXPECT_EQ(*slice1, file_payload.substr(0, 1024));

    // Range read: Next 1024 bytes (1024-2047)
    ByteRange range2{.start_byte = 1024, .end_byte = 2047};
    auto slice2 = engine_->get_file_object(file_id, 1, range2);
    ASSERT_TRUE(slice2.has_value());
    EXPECT_EQ(slice2->size(), 1024);
    EXPECT_EQ(*slice2, file_payload.substr(1024, 1024));

    // Clean up
    EXPECT_TRUE(engine_->delete_file_objects(file_id));
}

// ============================================================================
// TC4: Multipart Chunk Assembly & Upload of Large Encrypted Payload (5+ MiB)
// ============================================================================
TEST_F(FilesMinioStorageIntegrationTest, TC4_LiveMultipartUploadLifecycle) {
    const std::string object_key = "objects/" + generate_test_uuid() + "/1";

    // MinIO / S3 requires parts to be at least 5 MiB (except for the last part)
    constexpr size_t kPart1Size = 5 * 1024 * 1024; // 5 MiB
    constexpr size_t kPart2Size = 1024;            // 1 KiB

    std::string part1(kPart1Size, 'A');
    std::string part2(kPart2Size, 'B');

    // 1. Create multipart upload
    const std::string upload_id = s3_client_->create_multipart_upload(object_key);
    ASSERT_FALSE(upload_id.empty());

    // 2. Upload part 1
    const std::string etag1 = s3_client_->upload_part(object_key, upload_id, 1, part1);
    ASSERT_FALSE(etag1.empty());

    // 3. Upload part 2
    const std::string etag2 = s3_client_->upload_part(object_key, upload_id, 2, part2);
    ASSERT_FALSE(etag2.empty());

    // 4. Complete multipart upload
    std::vector<CompletedPart> parts = {
        CompletedPart{.part_number = 1, .etag = etag1},
        CompletedPart{.part_number = 2, .etag = etag2}
    };
    EXPECT_TRUE(s3_client_->complete_multipart_upload(object_key, upload_id, parts));

    // 5. Verify assembled object exists and check content length
    EXPECT_TRUE(s3_client_->object_exists(object_key));
    auto meta = s3_client_->head_object(object_key);
    EXPECT_EQ(meta.content_length, kPart1Size + kPart2Size);

    // 6. Clean up
    EXPECT_TRUE(s3_client_->delete_object(object_key));
    EXPECT_FALSE(s3_client_->object_exists(object_key));
}

// ============================================================================
// TC5: Live Cleanup and Deletion of Transfer Chunks
// ============================================================================
TEST_F(FilesMinioStorageIntegrationTest, TC5_LiveBatchTransferCleanup) {
    const std::string transfer_id = generate_test_uuid();

    std::string chunk0 = "chunk-data-0";
    std::string chunk1 = "chunk-data-1";
    std::string chunk2 = "chunk-data-2";

    EXPECT_TRUE(engine_->put_chunk(transfer_id, 0, chunk0, SigV4Signer::sha256_hex(chunk0)));
    EXPECT_TRUE(engine_->put_chunk(transfer_id, 1, chunk1, SigV4Signer::sha256_hex(chunk1)));
    EXPECT_TRUE(engine_->put_chunk(transfer_id, 2, chunk2, SigV4Signer::sha256_hex(chunk2)));

    // Verify all 3 chunks exist
    EXPECT_TRUE(engine_->get_chunk(transfer_id, 0).has_value());
    EXPECT_TRUE(engine_->get_chunk(transfer_id, 1).has_value());
    EXPECT_TRUE(engine_->get_chunk(transfer_id, 2).has_value());

    // Delete all chunks for transfer
    EXPECT_TRUE(engine_->delete_transfer_chunks(transfer_id));

    // Verify all chunks are deleted
    EXPECT_FALSE(engine_->get_chunk(transfer_id, 0).has_value());
    EXPECT_FALSE(engine_->get_chunk(transfer_id, 1).has_value());
    EXPECT_FALSE(engine_->get_chunk(transfer_id, 2).has_value());
}

// ============================================================================
// TC6: Cold Restart Durability
// ============================================================================
TEST_F(FilesMinioStorageIntegrationTest, TC6_ColdRestartDurability) {
    const std::string transfer_id = generate_test_uuid();
    const std::string payload = "cold-restart-durability-test-payload";
    const std::string sha = SigV4Signer::sha256_hex(payload);

    // 1. Store chunk using current engine
    EXPECT_TRUE(engine_->put_chunk(transfer_id, 0, payload, sha));

    // 2. Destroy current engine and client instances
    engine_.reset();
    s3_client_.reset();

    // 3. Re-instantiate fresh client and engine instances simulating cold process restart
    auto fresh_client = std::make_shared<S3Client>(s3_cfg_);
    StorageEngine fresh_engine(fresh_client);

    // 4. Verify chunk persists and data is intact
    auto fetched = fresh_engine.get_chunk(transfer_id, 0);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(*fetched, payload);

    // 5. Clean up
    EXPECT_TRUE(fresh_engine.delete_chunk(transfer_id, 0));
}

} // namespace
} // namespace securecloud::files
