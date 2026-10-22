#include "files/service/storage_engine.hpp"
#include "files/storage/s3_client.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::service {
namespace {

using storage::HttpRequest;
using storage::HttpResponse;
using storage::IHttpTransport;
using storage::S3Client;
using storage::S3ClientConfig;
using storage::S3ClientException;
using storage::S3IntegrityException;
using storage::SigV4Signer;

/// Mock transport for inspecting requests issued by StorageEngine through S3Client
class StorageMockHttpTransport : public IHttpTransport {
  public:
    HttpResponse execute(const HttpRequest& req) override {
        executed_requests_.push_back(req);

        auto it = scripted_responses_.find(req.method + " " + req.path);
        if (it != scripted_responses_.end()) {
            return it->second;
        }

        // Default behaviors
        if (req.method == "PUT") {
            return HttpResponse{200, "OK", {{"etag", "\"mock-etag\""}}, ""};
        }
        if (req.method == "GET") {
            return HttpResponse{200, "OK", {{"content-length", "12"}, {"etag", "\"mock-etag\""}}, "chunk-payload"};
        }
        if (req.method == "DELETE") {
            return HttpResponse{204, "No Content", {}, ""};
        }
        return HttpResponse{200, "OK", {}, ""};
    }

    void set_response(const std::string& method, const std::string& path, HttpResponse res) {
        scripted_responses_[method + " " + path] = std::move(res);
    }

    [[nodiscard]] const std::vector<HttpRequest>& executed_requests() const noexcept { return executed_requests_; }

  private:
    std::map<std::string, HttpResponse> scripted_responses_;
    std::vector<HttpRequest> executed_requests_;
};

class StorageEngineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_transport_ = std::make_shared<StorageMockHttpTransport>();
        S3ClientConfig cfg;
        cfg.endpoint = "http://minio:9000";
        cfg.bucket = "securecloud-files-encrypted";
        cfg.access_key = "files_admin";
        cfg.secret_key = common::configuration::SecretString("files_secret");

        s3_client_ = std::make_shared<S3Client>(cfg, mock_transport_);
        engine_ = std::make_unique<StorageEngine>(s3_client_);
    }

    std::shared_ptr<StorageMockHttpTransport> mock_transport_;
    std::shared_ptr<S3Client> s3_client_;
    std::unique_ptr<StorageEngine> engine_;
};

TEST_F(StorageEngineTest, OpaqueKeyDerivation) {
    const std::string transfer_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const uint32_t chunk_idx = 42;
    const std::string file_id = "f9e8d7c6-b5a4-3210-fedc-ba9876543210";
    const uint32_t version_num = 3;

    const std::string chunk_key = StorageEngine::derive_chunk_key(transfer_id, chunk_idx);
    EXPECT_EQ(chunk_key, "chunks/a1b2c3d4-e5f6-7890-abcd-ef1234567890/42");

    const std::string file_key = StorageEngine::derive_file_object_key(file_id, version_num);
    EXPECT_EQ(file_key, "objects/f9e8d7c6-b5a4-3210-fedc-ba9876543210/3");

    // Invariant: Keys must NEVER expose plaintext filenames, emails, or usernames
    EXPECT_EQ(chunk_key.find("password"), std::string::npos);
    EXPECT_EQ(chunk_key.find(".pdf"), std::string::npos);
    EXPECT_EQ(chunk_key.find("@"), std::string::npos);
}

TEST_F(StorageEngineTest, PutAndGetChunkSuccess) {
    const std::string transfer_id = "test-transfer-100";
    const uint32_t chunk_idx = 0;
    const std::string encrypted_data = "encrypted-ciphertext-bytes-0123456789";
    const std::string expected_hash = SigV4Signer::sha256_hex(encrypted_data);

    // 1. Put chunk
    EXPECT_TRUE(engine_->put_chunk(transfer_id, chunk_idx, encrypted_data, expected_hash));
    ASSERT_EQ(mock_transport_->executed_requests().size(), 1);

    const auto& put_req = mock_transport_->executed_requests().back();
    EXPECT_EQ(put_req.method, "PUT");
    EXPECT_EQ(put_req.path, "/securecloud-files-encrypted/chunks/test-transfer-100/0");
    EXPECT_EQ(put_req.body, encrypted_data);
    EXPECT_EQ(put_req.headers.at("x-amz-content-sha256"), expected_hash);

    // 2. Get chunk
    mock_transport_->set_response(
        "GET", "/securecloud-files-encrypted/chunks/test-transfer-100/0",
        HttpResponse{200, "OK", {{"content-length", std::to_string(encrypted_data.size())}}, encrypted_data});

    auto fetched = engine_->get_chunk(transfer_id, chunk_idx);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(*fetched, encrypted_data);
}

TEST_F(StorageEngineTest, IntegrityMismatchRejection) {
    const std::string transfer_id = "test-transfer-mismatch";
    const uint32_t chunk_idx = 1;
    const std::string encrypted_data = "corrupted-ciphertext-bytes";
    const std::string tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000";

    // Mismatched checksum MUST throw S3IntegrityException before S3 upload
    EXPECT_THROW((void)engine_->put_chunk(transfer_id, chunk_idx, encrypted_data, tampered_hash), S3IntegrityException);

    // Ensure no S3 request was sent
    EXPECT_TRUE(mock_transport_->executed_requests().empty());

    // Same check for file object
    EXPECT_THROW((void)engine_->put_file_object("file-1", 1, encrypted_data, tampered_hash), S3IntegrityException);
    EXPECT_TRUE(mock_transport_->executed_requests().empty());
}

TEST_F(StorageEngineTest, GetChunkNotFoundReturnsNullOpt) {
    const std::string transfer_id = "transfer-not-found";
    const uint32_t chunk_idx = 5;

    mock_transport_->set_response("GET", "/securecloud-files-encrypted/chunks/transfer-not-found/5",
                                  HttpResponse{404, "Not Found", {}, ""});

    auto fetched = engine_->get_chunk(transfer_id, chunk_idx);
    EXPECT_FALSE(fetched.has_value());
}

TEST_F(StorageEngineTest, DeleteChunkSuccess) {
    const std::string transfer_id = "transfer-del";
    const uint32_t chunk_idx = 2;

    EXPECT_TRUE(engine_->delete_chunk(transfer_id, chunk_idx));
    ASSERT_EQ(mock_transport_->executed_requests().size(), 1);

    const auto& del_req = mock_transport_->executed_requests().back();
    EXPECT_EQ(del_req.method, "DELETE");
    EXPECT_EQ(del_req.path, "/securecloud-files-encrypted/chunks/transfer-del/2");
}

TEST_F(StorageEngineTest, FileObjectOperations) {
    const std::string file_id = "file-uuid-999";
    const uint32_t version_num = 1;
    const std::string file_data = "encrypted-file-content";
    const std::string expected_hash = SigV4Signer::sha256_hex(file_data);

    // Put file object
    EXPECT_TRUE(engine_->put_file_object(file_id, version_num, file_data, expected_hash));
    const auto& put_req = mock_transport_->executed_requests().back();
    EXPECT_EQ(put_req.method, "PUT");
    EXPECT_EQ(put_req.path, "/securecloud-files-encrypted/objects/file-uuid-999/1");

    // Get file object with Range header
    mock_transport_->set_response("GET", "/securecloud-files-encrypted/objects/file-uuid-999/1",
                                  HttpResponse{206, "Partial Content", {{"content-length", "4"}}, "encr"});

    storage::ByteRange range{.start_byte = 0, .end_byte = 3};
    auto partial = engine_->get_file_object(file_id, version_num, range);
    ASSERT_TRUE(partial.has_value());
    EXPECT_EQ(*partial, "encr");

    const auto& get_req = mock_transport_->executed_requests().back();
    EXPECT_EQ(get_req.method, "GET");
    EXPECT_EQ(get_req.headers.at("range"), "bytes=0-3");
}

TEST_F(StorageEngineTest, BatchChunkCleanup) {
    const std::string transfer_id = "transfer-cleanup-id";
    const std::string list_xml = "<ListBucketResult>"
                                 "<Contents><Key>chunks/transfer-cleanup-id/0</Key></Contents>"
                                 "<Contents><Key>chunks/transfer-cleanup-id/1</Key></Contents>"
                                 "<Contents><Key>chunks/transfer-cleanup-id/2</Key></Contents>"
                                 "</ListBucketResult>";

    mock_transport_->set_response(
        "GET", "/securecloud-files-encrypted?list-type=2&max-keys=1000&prefix=chunks/transfer-cleanup-id/",
        HttpResponse{200, "OK", {}, list_xml});

    EXPECT_TRUE(engine_->delete_transfer_chunks(transfer_id));

    // Verify list request was issued, followed by 3 DELETE requests
    const auto& reqs = mock_transport_->executed_requests();
    ASSERT_EQ(reqs.size(), 4);

    EXPECT_EQ(reqs[0].method, "GET");
    EXPECT_EQ(reqs[1].method, "DELETE");
    EXPECT_EQ(reqs[1].path, "/securecloud-files-encrypted/chunks/transfer-cleanup-id/0");
    EXPECT_EQ(reqs[2].method, "DELETE");
    EXPECT_EQ(reqs[2].path, "/securecloud-files-encrypted/chunks/transfer-cleanup-id/1");
    EXPECT_EQ(reqs[3].method, "DELETE");
    EXPECT_EQ(reqs[3].path, "/securecloud-files-encrypted/chunks/transfer-cleanup-id/2");
}

TEST_F(StorageEngineTest, NullS3ClientThrows) {
    StorageEngine null_engine(nullptr);

    EXPECT_THROW((void)null_engine.put_chunk("t", 0, "data", ""), S3ClientException);
    EXPECT_THROW((void)null_engine.get_chunk("t", 0), S3ClientException);
    EXPECT_THROW((void)null_engine.delete_chunk("t", 0), S3ClientException);
    EXPECT_THROW((void)null_engine.put_file_object("f", 1, "data", ""), S3ClientException);
    EXPECT_THROW((void)null_engine.get_file_object("f", 1), S3ClientException);
    EXPECT_THROW((void)null_engine.delete_file_objects("f"), S3ClientException);
    EXPECT_THROW((void)null_engine.delete_transfer_chunks("t"), S3ClientException);
}

} // namespace
} // namespace securecloud::files::service
