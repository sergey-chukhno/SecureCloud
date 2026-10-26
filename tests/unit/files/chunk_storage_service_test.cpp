#include "files/service/chunk_storage_service.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/storage/s3_client.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>

namespace securecloud::files::service {
namespace {

class MockHttpTransport : public storage::IHttpTransport {
  public:
    storage::HttpResponse execute(const storage::HttpRequest& req) override {
        last_request = req;
        call_count++;
        return storage::HttpResponse{
            .status_code = 200,
            .status_message = "OK",
            .headers = {{"ETag", "\"d41d8cd98f00b204e9800998ecf8427e\""}},
            .body = "",
        };
    }

    storage::HttpRequest last_request;
    int call_count{0};
};

TEST(ChunkStorageServiceTest, CanonicalStagingKeyConstruction) {
    EXPECT_EQ(ChunkStorageService::build_staging_key("upload-123", 0), "staging/upload-123/0");
    EXPECT_EQ(ChunkStorageService::build_staging_key("018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e", 42),
              "staging/018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e/42");
}

TEST(ChunkStorageServiceTest, StoreChunkStagesPayloadToS3) {
    auto transport = std::make_shared<MockHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);

    ChunkStorageService service(nullptr, s3_client, nullptr, nullptr, nullptr);

    std::string payload = "encrypted ciphertext data block";
    std::string sha = compute_sha256_hex(payload);
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = sha,
    };

    auto res = service.store_chunk(dto, "user-alice");
    EXPECT_TRUE(res.accepted);
    EXPECT_FALSE(res.is_duplicate);
    EXPECT_EQ(res.received_sha256, sha);
    EXPECT_EQ(res.chunk_index, 0);
    EXPECT_EQ(res.bytes_written, static_cast<int64_t>(payload.size()));

    EXPECT_EQ(transport->call_count, 1);
    EXPECT_EQ(transport->last_request.method, "PUT");
    EXPECT_NE(transport->last_request.path.find("staging/018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e/0"), std::string::npos);
    EXPECT_EQ(transport->last_request.body, payload);
}

} // namespace
} // namespace securecloud::files::service
