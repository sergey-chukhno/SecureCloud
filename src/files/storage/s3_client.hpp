#pragma once

#include "files/files_config.hpp"
#include "files/storage/s3_exceptions.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::files::storage {

/// Low-level HTTP request model for S3 communication
struct HttpRequest {
    std::string method{"GET"};
    std::string path{"/"};
    std::string host{"127.0.0.1"};
    uint16_t port{9000};
    std::map<std::string, std::string> headers;
    std::string body;
    std::chrono::milliseconds timeout{1000};
};

/// Low-level HTTP response model for S3 communication
struct HttpResponse {
    int status_code{0};
    std::string status_message;
    std::map<std::string, std::string> headers;
    std::string body;

    [[nodiscard]] bool is_2xx() const noexcept { return status_code >= 200 && status_code < 300; }
};

/// Abstract HTTP transport interface enabling zero-network deterministic unit test mocks
class IHttpTransport {
  public:
    virtual ~IHttpTransport() = default;
    virtual HttpResponse execute(const HttpRequest& req) = 0;
};

/// Strongly typed configuration model for MinIO S3 object storage
struct S3ClientConfig {
    std::string endpoint{"http://minio:9000"};
    std::string bucket{"securecloud-files-encrypted"};
    std::string access_key{"files_minio_user"};
    common::configuration::SecretString secret_key;
    std::string region{"us-east-1"};
    std::chrono::milliseconds default_timeout{1000};

    /// Constructs S3ClientConfig from FilesConfig
    static S3ClientConfig from_files_config(const FilesConfig& config);

    /// Validates endpoint and bucket configurations
    void validate() const;
};

/// AWS Signature Version 4 (SigV4) cryptographic request signer using OpenSSL
class SigV4Signer {
  public:
    /// Computes lowercase hex-encoded SHA-256 digest of input
    [[nodiscard]] static std::string sha256_hex(std::string_view data);

    /// Computes binary HMAC-SHA256 digest
    [[nodiscard]] static std::vector<uint8_t> hmac_sha256(const void* key, size_t key_len, std::string_view data);

    /// Hex-encodes binary bytes to lowercase string
    [[nodiscard]] static std::string hex_encode(const uint8_t* data, size_t len);

    /// Derives 5-stage AWS SigV4 signing key
    [[nodiscard]] static std::vector<uint8_t> derive_signing_key(const std::string& secret_key,
                                                                 const std::string& date_stamp,
                                                                 const std::string& region, const std::string& service);

    /// Signs an HttpRequest in-place with AWS4-HMAC-SHA256 Authorization header
    static void sign_request(HttpRequest& req, const std::string& access_key, const std::string& secret_key,
                             const std::string& region, const std::string& service,
                             const std::chrono::system_clock::time_point& now = std::chrono::system_clock::now());
};

/// Default socket-based HTTP/1.1 transport implementation
class DefaultHttpTransport : public IHttpTransport {
  public:
    DefaultHttpTransport() = default;
    ~DefaultHttpTransport() override = default;

    HttpResponse execute(const HttpRequest& req) override;
};

/// Lightweight, non-blocking S3 client wrapper for MinIO storage
class S3Client {
  public:
    explicit S3Client(S3ClientConfig config, std::shared_ptr<IHttpTransport> transport = nullptr);
    ~S3Client() = default;

    // S3 client is non-copyable, movable
    S3Client(const S3Client&) = delete;
    S3Client& operator=(const S3Client&) = delete;
    S3Client(S3Client&&) noexcept = default;
    S3Client& operator=(S3Client&&) noexcept = default;

    /// Verifies target S3 bucket existence and reachability within bounded timeout.
    /// Issues HEAD /<bucket>. Returns true on 200 OK, false on error or not found without throwing.
    [[nodiscard]] bool ping_bucket(std::chrono::milliseconds timeout = std::chrono::milliseconds(1000)) noexcept;

    /// Checks whether an object exists in the target bucket.
    /// Issues HEAD /<bucket>/<object_key>.
    /// Returns true on 200 OK, false on 404 Not Found.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ClientException on unexpected HTTP error status.
    [[nodiscard]] bool object_exists(const std::string& object_key,
                                     std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));

    [[nodiscard]] const S3ClientConfig& config() const noexcept;
    [[nodiscard]] const std::string& endpoint_host() const noexcept;
    [[nodiscard]] uint16_t endpoint_port() const noexcept;

  private:
    void parse_endpoint();

    S3ClientConfig config_;
    std::shared_ptr<IHttpTransport> transport_;
    std::string host_{"127.0.0.1"};
    uint16_t port_{9000};
    bool is_https_{false};
};

} // namespace securecloud::files::storage
