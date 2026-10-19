#include "files/storage/s3_client.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::storage {
namespace {

/// Mock HTTP transport for unit testing S3Client requests and SigV4 verification
class MockHttpTransport : public IHttpTransport {
  public:
    explicit MockHttpTransport(int status_code = 200, std::string body = "",
                               std::map<std::string, std::string> headers = {})
        : status_code_(status_code), body_(std::move(body)), headers_(std::move(headers)) {}

    HttpResponse execute(const HttpRequest& req) override {
        last_request_ = req;
        execution_count_++;
        return HttpResponse{status_code_, "Mock Status", headers_, body_};
    }

    void set_response(int status_code, std::string body = "", std::map<std::string, std::string> headers = {}) {
        status_code_ = status_code;
        body_ = std::move(body);
        headers_ = std::move(headers);
    }

    [[nodiscard]] const HttpRequest& last_request() const noexcept { return last_request_; }

    [[nodiscard]] size_t execution_count() const noexcept { return execution_count_; }

  private:
    int status_code_{200};
    std::string body_;
    std::map<std::string, std::string> headers_;
    HttpRequest last_request_;
    size_t execution_count_{0};
};

TEST(S3ClientTest, SigV4Sha256AndHmacDerivation) {
    // 1. SHA-256 standard empty string digest
    const std::string empty_hash = SigV4Signer::sha256_hex("");
    EXPECT_EQ(empty_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // 2. SHA-256 known test vector: "abc"
    const std::string abc_hash = SigV4Signer::sha256_hex("abc");
    EXPECT_EQ(abc_hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // 3. HMAC-SHA256 known test vector
    const std::string key = "key";
    const std::string message = "The quick brown fox jumps over the lazy dog";
    const auto hmac_res = SigV4Signer::hmac_sha256(key.data(), key.size(), message);
    const std::string hmac_hex = SigV4Signer::hex_encode(hmac_res.data(), hmac_res.size());
    EXPECT_EQ(hmac_hex, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");

    // 4. AWS SigV4 5-stage key derivation returns 32-byte binary key
    const auto signing_key =
        SigV4Signer::derive_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3");
    EXPECT_EQ(signing_key.size(), 32);
    const std::string signing_key_hex = SigV4Signer::hex_encode(signing_key.data(), signing_key.size());
    EXPECT_FALSE(signing_key_hex.empty());
    EXPECT_EQ(signing_key_hex.size(), 64);
}

TEST(S3ClientTest, SigV4HeaderFormatting) {
    HttpRequest req;
    req.method = "HEAD";
    req.path = "/test-bucket";
    req.host = "minio";
    req.port = 9000;

    const std::string access_key = "AKIAIOSFODNN7EXAMPLE";
    const std::string secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // Fixed timestamp: 2026-09-23 12:00:00 UTC
    const auto fixed_time = std::chrono::system_clock::from_time_t(1790164800);

    SigV4Signer::sign_request(req, access_key, secret_key, "us-east-1", "s3", fixed_time);

    // Verify required headers
    ASSERT_TRUE(req.headers.find("host") != req.headers.end());
    EXPECT_EQ(req.headers["host"], "minio:9000");

    ASSERT_TRUE(req.headers.find("x-amz-date") != req.headers.end());
    EXPECT_EQ(req.headers["x-amz-date"], "20260923T120000Z");

    ASSERT_TRUE(req.headers.find("x-amz-content-sha256") != req.headers.end());
    EXPECT_EQ(req.headers["x-amz-content-sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    ASSERT_TRUE(req.headers.find("authorization") != req.headers.end());
    const std::string& auth = req.headers["authorization"];

    EXPECT_NE(auth.find("AWS4-HMAC-SHA256 Credential=" + access_key + "/20260923/us-east-1/s3/aws4_request"),
              std::string::npos);
    EXPECT_NE(auth.find("SignedHeaders=host;x-amz-content-sha256;x-amz-date"), std::string::npos);
    EXPECT_NE(auth.find("Signature="), std::string::npos);

    // Signature must be a 64-character lowercase hex string
    const size_t sig_pos = auth.find("Signature=");
    ASSERT_NE(sig_pos, std::string::npos);
    const std::string sig_val = auth.substr(sig_pos + 10);
    EXPECT_EQ(sig_val.size(), 64);
}

TEST(S3ClientTest, ConfigValidationAndExtraction) {
    // Valid configuration
    S3ClientConfig valid;
    valid.endpoint = "http://minio:9000";
    valid.bucket = "securecloud-files-encrypted";
    valid.access_key = "files_user";
    valid.secret_key = common::configuration::SecretString("files_secret");
    EXPECT_NO_THROW(valid.validate());

    // Empty endpoint
    S3ClientConfig invalid_endpoint = valid;
    invalid_endpoint.endpoint = "";
    EXPECT_THROW(invalid_endpoint.validate(), S3ClientException);

    // Empty bucket
    S3ClientConfig invalid_bucket = valid;
    invalid_bucket.bucket = "";
    EXPECT_THROW(invalid_bucket.validate(), S3ClientException);

    // Empty access key
    S3ClientConfig invalid_access = valid;
    invalid_access.access_key = "";
    EXPECT_THROW(invalid_access.validate(), S3ClientException);

    // Empty secret key
    S3ClientConfig invalid_secret = valid;
    invalid_secret.secret_key = common::configuration::SecretString("");
    EXPECT_THROW(invalid_secret.validate(), S3AuthenticationException);

    // Extraction from FilesConfig
    FilesConfig files_cfg;
    files_cfg.s3_endpoint = "http://127.0.0.1:9000";
    files_cfg.s3_bucket = "custom-bucket";
    files_cfg.s3_access_key = "custom_user";
    files_cfg.s3_secret_key = common::configuration::SecretString("custom_secret");

    S3ClientConfig from_files = S3ClientConfig::from_files_config(files_cfg);
    EXPECT_EQ(from_files.endpoint, "http://127.0.0.1:9000");
    EXPECT_EQ(from_files.bucket, "custom-bucket");
    EXPECT_EQ(from_files.access_key, "custom_user");
    EXPECT_EQ(from_files.secret_key.expose_unredacted_secret(), "custom_secret");
    EXPECT_NO_THROW(from_files.validate());
}

TEST(S3ClientTest, PingBucketSuccessOn200OK) {
    auto mock_transport = std::make_shared<MockHttpTransport>(200);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    EXPECT_EQ(client.endpoint_host(), "minio");
    EXPECT_EQ(client.endpoint_port(), 9000);

    EXPECT_TRUE(client.ping_bucket(std::chrono::milliseconds(500)));
    EXPECT_EQ(mock_transport->execution_count(), 1);

    const auto& last_req = mock_transport->last_request();
    EXPECT_EQ(last_req.method, "HEAD");
    EXPECT_EQ(last_req.path, "/securecloud-files-encrypted");
    EXPECT_EQ(last_req.host, "minio");
    EXPECT_EQ(last_req.port, 9000);
}

TEST(S3ClientTest, PingBucketFailureReturnsFalseWithoutThrowing) {
    auto mock_transport = std::make_shared<MockHttpTransport>(404);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "nonexistent-bucket";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    // 404 returns false
    EXPECT_FALSE(client.ping_bucket());

    // 500 returns false
    mock_transport->set_response(500);
    EXPECT_FALSE(client.ping_bucket());

    // Socket connect failure (status 0) returns false
    mock_transport->set_response(0);
    EXPECT_FALSE(client.ping_bucket());
}

TEST(S3ClientTest, ObjectExistsSuccessOn200OK) {
    auto mock_transport = std::make_shared<MockHttpTransport>(200);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    EXPECT_TRUE(client.object_exists("0191ec4d-chunk-0"));
    EXPECT_EQ(mock_transport->last_request().method, "HEAD");
    EXPECT_EQ(mock_transport->last_request().path, "/securecloud-files-encrypted/0191ec4d-chunk-0");
}

TEST(S3ClientTest, ObjectExistsNotFoundReturnsFalse) {
    auto mock_transport = std::make_shared<MockHttpTransport>(404);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    EXPECT_FALSE(client.object_exists("nonexistent-chunk"));
}

TEST(S3ClientTest, ObjectExistsForbiddenThrowsAuthenticationException) {
    auto mock_transport = std::make_shared<MockHttpTransport>(403);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("wrong_secret");

    S3Client client(cfg, mock_transport);

    EXPECT_THROW((void)client.object_exists("chunk-0"), S3AuthenticationException);
}

TEST(S3ClientTest, ObjectExistsConnectionFailureThrowsConnectionException) {
    auto mock_transport = std::make_shared<MockHttpTransport>(0);

    S3ClientConfig cfg;
    cfg.endpoint = "http://unreachable-host:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    EXPECT_THROW((void)client.object_exists("chunk-0"), S3ConnectionException);
}

TEST(S3ClientTest, PutObjectSuccessAndHeaders) {
    auto mock_transport = std::make_shared<MockHttpTransport>(200);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    const std::string ciphertext = "\x01\x02\x03\x04\x05\x06\x07\x08";
    const std::string expected_hash = SigV4Signer::sha256_hex(ciphertext);

    EXPECT_TRUE(client.put_object("chunks/transfer-1/0", ciphertext, "application/octet-stream", expected_hash));
    EXPECT_EQ(mock_transport->execution_count(), 1);

    const auto& req = mock_transport->last_request();
    EXPECT_EQ(req.method, "PUT");
    EXPECT_EQ(req.path, "/securecloud-files-encrypted/chunks/transfer-1/0");
    EXPECT_EQ(req.body, ciphertext);

    ASSERT_TRUE(req.headers.find("content-type") != req.headers.end());
    EXPECT_EQ(req.headers.at("content-type"), "application/octet-stream");

    ASSERT_TRUE(req.headers.find("content-length") != req.headers.end());
    EXPECT_EQ(req.headers.at("content-length"), std::to_string(ciphertext.size()));

    ASSERT_TRUE(req.headers.find("x-amz-content-sha256") != req.headers.end());
    EXPECT_EQ(req.headers.at("x-amz-content-sha256"), expected_hash);

    ASSERT_TRUE(req.headers.find("authorization") != req.headers.end());
    EXPECT_TRUE(req.headers.at("authorization").starts_with("AWS4-HMAC-SHA256"));
}

TEST(S3ClientTest, GetObjectFullAndRange) {
    std::map<std::string, std::string> headers = {
        {"etag", "\"abcdef123456\""},
        {"content-type", "application/octet-stream"},
        {"content-length", "10"}
    };
    auto mock_transport = std::make_shared<MockHttpTransport>(200, "0123456789", headers);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    // Full GET
    auto res = client.get_object("objects/file-1/1");
    EXPECT_EQ(res.status_code, 200);
    EXPECT_EQ(res.body, "0123456789");
    EXPECT_EQ(res.content_length, 10);
    EXPECT_EQ(res.etag, "abcdef123456");
    EXPECT_EQ(res.content_type, "application/octet-stream");
    EXPECT_EQ(mock_transport->last_request().method, "GET");
    EXPECT_EQ(mock_transport->last_request().path, "/securecloud-files-encrypted/objects/file-1/1");
    EXPECT_TRUE(mock_transport->last_request().headers.find("range") == mock_transport->last_request().headers.end());

    // Range GET
    ByteRange range{.start_byte = 0, .end_byte = 4};
    mock_transport->set_response(206, "01234", {{"etag", "\"range-etag\""}, {"content-length", "5"}});
    auto range_res = client.get_object("objects/file-1/1", range);
    EXPECT_EQ(range_res.status_code, 206);
    EXPECT_EQ(range_res.body, "01234");
    EXPECT_EQ(range_res.content_length, 5);
    EXPECT_EQ(range_res.etag, "range-etag");

    ASSERT_TRUE(mock_transport->last_request().headers.find("range") != mock_transport->last_request().headers.end());
    EXPECT_EQ(mock_transport->last_request().headers.at("range"), "bytes=0-4");
}

TEST(S3ClientTest, HeadObjectSuccessAndNotFound) {
    std::map<std::string, std::string> headers = {
        {"etag", "\"head-etag-999\""},
        {"content-type", "application/octet-stream"},
        {"content-length", "4096"}
    };
    auto mock_transport = std::make_shared<MockHttpTransport>(200, "", headers);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    auto meta = client.head_object("objects/file-1/1");
    EXPECT_EQ(meta.content_length, 4096);
    EXPECT_EQ(meta.etag, "head-etag-999");
    EXPECT_EQ(meta.content_type, "application/octet-stream");
    EXPECT_EQ(mock_transport->last_request().method, "HEAD");
    EXPECT_EQ(mock_transport->last_request().path, "/securecloud-files-encrypted/objects/file-1/1");

    // 404 throws S3ObjectNotFoundException
    mock_transport->set_response(404);
    EXPECT_THROW((void)client.head_object("nonexistent"), S3ObjectNotFoundException);
}

TEST(S3ClientTest, DeleteObjectIdempotence) {
    auto mock_transport = std::make_shared<MockHttpTransport>(204);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    // 204 No Content -> true
    EXPECT_TRUE(client.delete_object("chunks/t1/0"));
    EXPECT_EQ(mock_transport->last_request().method, "DELETE");
    EXPECT_EQ(mock_transport->last_request().path, "/securecloud-files-encrypted/chunks/t1/0");

    // 200 OK -> true
    mock_transport->set_response(200);
    EXPECT_TRUE(client.delete_object("chunks/t1/0"));

    // 404 Not Found -> true (idempotent delete)
    mock_transport->set_response(404);
    EXPECT_TRUE(client.delete_object("chunks/t1/0"));

    // 403 Forbidden -> throws S3AuthenticationException
    mock_transport->set_response(403);
    EXPECT_THROW((void)client.delete_object("chunks/t1/0"), S3AuthenticationException);
}

TEST(S3ClientTest, ServerAndConnectionExceptions) {
    auto mock_transport = std::make_shared<MockHttpTransport>(500);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    EXPECT_THROW((void)client.put_object("key", "data"), S3ServerException);
    EXPECT_THROW((void)client.get_object("key"), S3ServerException);
    EXPECT_THROW((void)client.head_object("key"), S3ServerException);
    EXPECT_THROW((void)client.delete_object("key"), S3ServerException);

    // Socket failure (status code 0) throws S3ConnectionException
    mock_transport->set_response(0);
    EXPECT_THROW((void)client.put_object("key", "data"), S3ConnectionException);
    EXPECT_THROW((void)client.get_object("key"), S3ConnectionException);
    EXPECT_THROW((void)client.head_object("key"), S3ConnectionException);
    EXPECT_THROW((void)client.delete_object("key"), S3ConnectionException);
}

TEST(S3ClientTest, MultipartUploadLifecycleMock) {
    const std::string init_response =
        "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Bucket>securecloud-files-encrypted</Bucket>"
        "<Key>objects/file-10/1</Key>"
        "<UploadId>mp-upload-id-9988</UploadId>"
        "</InitiateMultipartUploadResult>";

    auto mock_transport = std::make_shared<MockHttpTransport>(200, init_response);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    // 1. Initiate multipart upload
    std::string upload_id = client.create_multipart_upload("objects/file-10/1");
    EXPECT_EQ(upload_id, "mp-upload-id-9988");
    EXPECT_EQ(mock_transport->last_request().method, "POST");
    EXPECT_EQ(mock_transport->last_request().path, "/securecloud-files-encrypted/objects/file-10/1?uploads");

    // 2. Upload part 1
    mock_transport->set_response(200, "", {{"etag", "\"part1-etag-hex\""}});
    std::string etag1 = client.upload_part("objects/file-10/1", upload_id, 1, "part1_data");
    EXPECT_EQ(etag1, "part1-etag-hex");
    EXPECT_EQ(mock_transport->last_request().method, "PUT");
    EXPECT_EQ(mock_transport->last_request().path,
              "/securecloud-files-encrypted/objects/file-10/1?partNumber=1&uploadId=mp-upload-id-9988");
    EXPECT_EQ(mock_transport->last_request().body, "part1_data");

    // 3. Upload part 2
    mock_transport->set_response(200, "", {{"etag", "\"part2-etag-hex\""}});
    std::string etag2 = client.upload_part("objects/file-10/1", upload_id, 2, "part2_data");
    EXPECT_EQ(etag2, "part2-etag-hex");

    // 4. Complete multipart upload
    mock_transport->set_response(200, "<CompleteMultipartUploadResult/>");
    std::vector<CompletedPart> parts = {{1, etag1}, {2, etag2}};
    EXPECT_TRUE(client.complete_multipart_upload("objects/file-10/1", upload_id, parts));
    EXPECT_EQ(mock_transport->last_request().method, "POST");
    EXPECT_EQ(mock_transport->last_request().path,
              "/securecloud-files-encrypted/objects/file-10/1?uploadId=mp-upload-id-9988");
    EXPECT_NE(mock_transport->last_request().body.find("<PartNumber>1</PartNumber><ETag>\"part1-etag-hex\"</ETag>"),
              std::string::npos);
    EXPECT_NE(mock_transport->last_request().body.find("<PartNumber>2</PartNumber><ETag>\"part2-etag-hex\"</ETag>"),
              std::string::npos);
}

TEST(S3ClientTest, AbortMultipartUploadMock) {
    auto mock_transport = std::make_shared<MockHttpTransport>(204);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    // 204 No Content -> true
    EXPECT_TRUE(client.abort_multipart_upload("objects/file-10/1", "mp-upload-id-9988"));
    EXPECT_EQ(mock_transport->last_request().method, "DELETE");
    EXPECT_EQ(mock_transport->last_request().path,
              "/securecloud-files-encrypted/objects/file-10/1?uploadId=mp-upload-id-9988");

    // 404 Not Found -> true (idempotent abort)
    mock_transport->set_response(404);
    EXPECT_TRUE(client.abort_multipart_upload("objects/file-10/1", "mp-upload-id-9988"));

    // 403 Forbidden -> throws
    mock_transport->set_response(403);
    EXPECT_THROW((void)client.abort_multipart_upload("objects/file-10/1", "mp-upload-id-9988"),
                 S3AuthenticationException);
}

TEST(S3ClientTest, ListObjectsV2ParsingMock) {
    const std::string xml_list_response =
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Name>securecloud-files-encrypted</Name>"
        "<Prefix>chunks/t-123/</Prefix>"
        "<KeyCount>2</KeyCount>"
        "<MaxKeys>1000</MaxKeys>"
        "<IsTruncated>true</IsTruncated>"
        "<NextContinuationToken>token-next-456</NextContinuationToken>"
        "<Contents>"
        "<Key>chunks/t-123/0</Key>"
        "<LastModified>2026-10-19T10:00:00.000Z</LastModified>"
        "<ETag>\"etag-chunk-0\"</ETag>"
        "<Size>4096</Size>"
        "<StorageClass>STANDARD</StorageClass>"
        "</Contents>"
        "<Contents>"
        "<Key>chunks/t-123/1</Key>"
        "<LastModified>2026-10-19T10:00:05.000Z</LastModified>"
        "<ETag>\"etag-chunk-1\"</ETag>"
        "<Size>2048</Size>"
        "<StorageClass>STANDARD</StorageClass>"
        "</Contents>"
        "</ListBucketResult>";

    auto mock_transport = std::make_shared<MockHttpTransport>(200, xml_list_response);

    S3ClientConfig cfg;
    cfg.endpoint = "http://minio:9000";
    cfg.bucket = "securecloud-files-encrypted";
    cfg.access_key = "minio_admin";
    cfg.secret_key = common::configuration::SecretString("minio_secret");

    S3Client client(cfg, mock_transport);

    auto result = client.list_objects("chunks/t-123/", 1000);
    EXPECT_EQ(mock_transport->last_request().method, "GET");
    EXPECT_EQ(mock_transport->last_request().path,
              "/securecloud-files-encrypted?list-type=2&max-keys=1000&prefix=chunks/t-123/");

    EXPECT_TRUE(result.is_truncated);
    EXPECT_EQ(result.next_continuation_token, "token-next-456");
    EXPECT_EQ(result.key_count, 2);
    ASSERT_EQ(result.objects.size(), 2);

    EXPECT_EQ(result.objects[0].key, "chunks/t-123/0");
    EXPECT_EQ(result.objects[0].etag, "etag-chunk-0");
    EXPECT_EQ(result.objects[0].size, 4096);
    EXPECT_EQ(result.objects[0].last_modified, "2026-10-19T10:00:00.000Z");

    EXPECT_EQ(result.objects[1].key, "chunks/t-123/1");
    EXPECT_EQ(result.objects[1].etag, "etag-chunk-1");
    EXPECT_EQ(result.objects[1].size, 2048);
    EXPECT_EQ(result.objects[1].last_modified, "2026-10-19T10:00:05.000Z");

    // Error handling on 403
    mock_transport->set_response(403);
    EXPECT_THROW((void)client.list_objects("chunks/t-123/"), S3AuthenticationException);
}

} // namespace
} // namespace securecloud::files::storage
