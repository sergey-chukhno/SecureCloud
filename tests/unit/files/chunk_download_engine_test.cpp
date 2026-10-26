#include "files/service/chunk_download_engine.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/storage/s3_client.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>

namespace securecloud::files::service {
namespace {

class RangeSupportingHttpTransport : public storage::IHttpTransport {
  public:
    storage::HttpResponse execute(const storage::HttpRequest& req) override {
        std::string path = req.path;
        if (!path.empty() && path[0] == '/') {
            path = path.substr(1);
        }
        std::string bucket_prefix = "securecloud-files-encrypted/";
        if (path.rfind(bucket_prefix, 0) == 0) {
            path = path.substr(bucket_prefix.size());
        }

        auto it = objects.find(path);
        if (it == objects.end()) {
            return storage::HttpResponse{
                .status_code = 404,
                .status_message = "Not Found",
                .headers = {},
                .body = "Object not found",
            };
        }

        const std::string& full_body = it->second;

        // Check for Range header
        auto range_it = req.headers.find("Range");
        if (range_it != req.headers.end()) {
            std::string range_val = range_it->second; // format: "bytes=start-end" or "bytes=start-"
            if (range_val.rfind("bytes=", 0) == 0) {
                std::string spec = range_val.substr(6);
                auto dash = spec.find('-');
                if (dash != std::string::npos) {
                    uint64_t start = std::stoull(spec.substr(0, dash));
                    uint64_t end = full_body.size() > 0 ? (full_body.size() - 1) : 0;
                    if (dash + 1 < spec.size()) {
                        end = std::stoull(spec.substr(dash + 1));
                    }
                    if (start <= end && start < full_body.size()) {
                        uint64_t actual_end = std::min(end, static_cast<uint64_t>(full_body.size() - 1));
                        std::string slice = full_body.substr(start, actual_end - start + 1);
                        return storage::HttpResponse{
                            .status_code = 206,
                            .status_message = "Partial Content",
                            .headers = {
                                {"Content-Range", "bytes " + std::to_string(start) + "-" + std::to_string(actual_end) + "/" + std::to_string(full_body.size())},
                                {"Content-Length", std::to_string(slice.size())}
                            },
                            .body = slice,
                        };
                    }
                }
            }
        }

        return storage::HttpResponse{
            .status_code = 200,
            .status_message = "OK",
            .headers = {{"Content-Length", std::to_string(full_body.size())}},
            .body = full_body,
        };
    }

    std::map<std::string, std::string> objects;
};

TEST(ChunkDownloadEngineTest, CanonicalVersionKey) {
    EXPECT_EQ(ChunkDownloadEngine::build_version_key("file-123", 1), "objects/file-123/1");
    EXPECT_EQ(ChunkDownloadEngine::build_version_key("file-abc", 5), "objects/file-abc/5");
}

TEST(ChunkDownloadEngineTest, FetchChunkSuccess) {
    auto transport = std::make_shared<RangeSupportingHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ChunkDownloadEngine engine(s3_client);

    std::string file_id = "018f6e80-7b23-74d1-81f8-000000000001";
    int32_t version = 1;
    std::string key = "objects/" + file_id + "/1";

    // Create a 5 MiB file (chunk 0 = 4 MiB 'A', chunk 1 = 1 MiB 'B')
    std::string chunk0_data(4 * 1024 * 1024, 'A');
    std::string chunk1_data(1 * 1024 * 1024, 'B');
    std::string full_payload = chunk0_data + chunk1_data;
    transport->objects[key] = full_payload;

    // Fetch chunk 0
    auto res0 = engine.fetch_chunk(file_id, version, 0, full_payload.size());
    EXPECT_EQ(res0.file_id, file_id);
    EXPECT_EQ(res0.version_number, version);
    EXPECT_EQ(res0.chunk_index, 0);
    EXPECT_EQ(res0.chunk_size_bytes, 4 * 1024 * 1024);
    EXPECT_EQ(res0.encrypted_data, chunk0_data);
    EXPECT_EQ(res0.ciphertext_sha256, compute_sha256_hex(chunk0_data));

    // Fetch chunk 1
    auto res1 = engine.fetch_chunk(file_id, version, 1, full_payload.size());
    EXPECT_EQ(res1.chunk_index, 1);
    EXPECT_EQ(res1.chunk_size_bytes, 1 * 1024 * 1024);
    EXPECT_EQ(res1.encrypted_data, chunk1_data);
    EXPECT_EQ(res1.ciphertext_sha256, compute_sha256_hex(chunk1_data));
}

TEST(ChunkDownloadEngineTest, FetchChunkOutOfBoundsThrows) {
    auto transport = std::make_shared<RangeSupportingHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ChunkDownloadEngine engine(s3_client);

    // 1000 byte file has 1 chunk (index 0). Index 1 is out of range.
    EXPECT_THROW(engine.fetch_chunk("file-1", 1, 1, 1000), std::out_of_range);
}

TEST(ChunkDownloadEngineTest, FetchChunkEmptyFile) {
    auto transport = std::make_shared<RangeSupportingHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ChunkDownloadEngine engine(s3_client);

    auto res = engine.fetch_chunk("file-empty", 1, 0, 0);
    EXPECT_EQ(res.chunk_size_bytes, 0);
    EXPECT_EQ(res.encrypted_data, "");
    EXPECT_EQ(res.ciphertext_sha256, compute_sha256_hex(""));
}

TEST(ChunkDownloadEngineTest, FetchChunkNotFoundThrows) {
    auto transport = std::make_shared<RangeSupportingHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ChunkDownloadEngine engine(s3_client);

    // Key not in transport->objects
    EXPECT_THROW(engine.fetch_chunk("file-not-found", 1, 0, 1000), storage::S3ObjectNotFoundException);
}

} // namespace
} // namespace securecloud::files::service
