#include "files/service/object_assembly_engine.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>

namespace securecloud::files::service {
namespace {

class InMemoryHttpTransport : public storage::IHttpTransport {
  public:
    storage::HttpResponse execute(const storage::HttpRequest& req) override {
        // Strip leading slash and bucket prefix if present
        std::string path = req.path;
        if (!path.empty() && path[0] == '/') {
            path = path.substr(1);
        }
        std::string bucket_prefix = "securecloud-files-encrypted/";
        if (path.rfind(bucket_prefix, 0) == 0) {
            path = path.substr(bucket_prefix.size());
        }

        if (req.method == "GET") {
            auto it = objects.find(path);
            if (it == objects.end()) {
                return storage::HttpResponse{
                    .status_code = 404,
                    .status_message = "Not Found",
                    .headers = {},
                    .body = "Object not found",
                };
            }
            return storage::HttpResponse{
                .status_code = 200,
                .status_message = "OK",
                .headers = {{"Content-Length", std::to_string(it->second.size())}},
                .body = it->second,
            };
        } else if (req.method == "PUT") {
            objects[path] = req.body;
            put_calls[path] = req.body;
            return storage::HttpResponse{
                .status_code = 200,
                .status_message = "OK",
                .headers = {{"ETag", "\"etag-123\""}},
                .body = "",
            };
        } else if (req.method == "DELETE") {
            objects.erase(path);
            deleted_keys.push_back(path);
            return storage::HttpResponse{
                .status_code = 204,
                .status_message = "No Content",
                .headers = {},
                .body = "",
            };
        }

        return storage::HttpResponse{
            .status_code = 500,
            .status_message = "Internal Server Error",
            .headers = {},
            .body = "Unsupported method",
        };
    }

    std::map<std::string, std::string> objects;
    std::map<std::string, std::string> put_calls;
    std::vector<std::string> deleted_keys;
};

TEST(ObjectAssemblyEngineTest, CanonicalVersionKeyConstruction) {
    EXPECT_EQ(ObjectAssemblyEngine::build_version_key("018f6e80-7b23-74d1-81f8-000000000001", 1),
              "objects/018f6e80-7b23-74d1-81f8-000000000001/1");
    EXPECT_EQ(ObjectAssemblyEngine::build_version_key("file-42", 5),
              "objects/file-42/5");
}

TEST(ObjectAssemblyEngineTest, AssembleMultiChunkObject) {
    auto transport = std::make_shared<InMemoryHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ObjectAssemblyEngine engine(s3_client);

    std::string transfer_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e";
    std::string chunk0_data = "First encrypted payload block";
    std::string chunk1_data = "Second encrypted payload block";

    std::string key0 = "staging/" + transfer_id + "/0";
    std::string key1 = "staging/" + transfer_id + "/1";

    transport->objects[key0] = chunk0_data;
    transport->objects[key1] = chunk1_data;

    FileChunkEntity c0;
    c0.transfer_id = transfer_id;
    c0.chunk_index = 0;
    c0.chunk_size = chunk0_data.size();
    c0.chunk_hash_sha256 = compute_sha256_hex(chunk0_data);
    c0.minio_chunk_key = key0;

    FileChunkEntity c1;
    c1.transfer_id = transfer_id;
    c1.chunk_index = 1;
    c1.chunk_size = chunk1_data.size();
    c1.chunk_hash_sha256 = compute_sha256_hex(chunk1_data);
    c1.minio_chunk_key = key1;

    std::string file_id = "018f6e80-7b23-74d1-81f8-000000000001";
    auto result = engine.assemble_version_object(file_id, 1, transfer_id, {c1, c0}); // out of order input

    std::string expected_whole_payload = chunk0_data + chunk1_data;
    std::string expected_hash = compute_sha256_hex(expected_whole_payload);

    EXPECT_EQ(result.target_object_key, "objects/" + file_id + "/1");
    EXPECT_EQ(result.total_bytes, expected_whole_payload.size());
    EXPECT_EQ(result.computed_sha256, expected_hash);

    // Verify written to storage
    EXPECT_EQ(transport->objects["objects/" + file_id + "/1"], expected_whole_payload);
}

TEST(ObjectAssemblyEngineTest, RejectCorruptedStagedChunk) {
    auto transport = std::make_shared<InMemoryHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ObjectAssemblyEngine engine(s3_client);

    std::string transfer_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e";
    std::string key0 = "staging/" + transfer_id + "/0";
    transport->objects[key0] = "Tampered or corrupted payload";

    FileChunkEntity c0;
    c0.transfer_id = transfer_id;
    c0.chunk_index = 0;
    c0.chunk_size = 30;
    c0.chunk_hash_sha256 = compute_sha256_hex("Original valid payload");
    c0.minio_chunk_key = key0;

    EXPECT_THROW(
        engine.assemble_version_object("file-1", 1, transfer_id, {c0}),
        storage::S3IntegrityException);
}

TEST(ObjectAssemblyEngineTest, AssembleEmptyFileObject) {
    auto transport = std::make_shared<InMemoryHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ObjectAssemblyEngine engine(s3_client);

    auto result = engine.assemble_version_object("file-empty", 1, "transfer-empty", {});
    EXPECT_EQ(result.total_bytes, 0);
    EXPECT_EQ(result.computed_sha256, compute_sha256_hex(""));
    EXPECT_EQ(transport->objects["objects/file-empty/1"], "");
}

TEST(ObjectAssemblyEngineTest, CleanupStagingChunksDeletesIdempotently) {
    auto transport = std::make_shared<InMemoryHttpTransport>();
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, transport);
    ObjectAssemblyEngine engine(s3_client);

    std::string transfer_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e";
    std::string key0 = "staging/" + transfer_id + "/0";
    std::string key1 = "staging/" + transfer_id + "/1";

    transport->objects[key0] = "data0";
    transport->objects[key1] = "data1";

    FileChunkEntity c0;
    c0.minio_chunk_key = key0;
    FileChunkEntity c1;
    c1.minio_chunk_key = key1;

    engine.cleanup_staging_chunks(transfer_id, {c0, c1});

    EXPECT_EQ(transport->objects.find(key0), transport->objects.end());
    EXPECT_EQ(transport->objects.find(key1), transport->objects.end());
    EXPECT_EQ(transport->deleted_keys.size(), 2);
}

} // namespace
} // namespace securecloud::files::service
