#include "files/storage/s3_client.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::storage {
namespace {

/// Mock HTTP transport for unit testing S3Client requests and SigV4 verification
class MockHttpTransport : public IHttpTransport {
public:
    explicit MockHttpTransport(int status_code = 200, std::string body = "")
        : status_code_(status_code), body_(std::move(body)) {}

    HttpResponse execute(const HttpRequest& req) override {
        last_request_ = req;
        execution_count_++;
        return HttpResponse{status_code_, "Mock Status", {}, body_};
    }

    void set_response(int status_code, std::string body = "") {
        status_code_ = status_code;
        body_ = std::move(body);
    }

    [[nodiscard]] const HttpRequest& last_request() const noexcept {
        return last_request_;
    }

    [[nodiscard]] size_t execution_count() const noexcept {
        return execution_count_;
    }

private:
    int status_code_{200};
    std::string body_;
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
    const auto signing_key = SigV4Signer::derive_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                                                             "20130524", "us-east-1", "s3");
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

} // namespace
} // namespace securecloud::files::storage
