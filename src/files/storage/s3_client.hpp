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

/// Specification of a byte range for partial content requests (HTTP Range header)
struct ByteRange {
    uint64_t start_byte{0};
    std::optional<uint64_t> end_byte{std::nullopt};

    [[nodiscard]] std::string to_header_value() const {
        if (end_byte.has_value()) {
            return "bytes=" + std::to_string(start_byte) + "-" + std::to_string(*end_byte);
        }
        return "bytes=" + std::to_string(start_byte) + "-";
    }
};

/// High-level response model for object retrieval
struct S3ObjectResponse {
    int status_code{0};
    std::string body;
    size_t content_length{0};
    std::string etag;
    std::string content_type;
    std::map<std::string, std::string> headers;

    [[nodiscard]] bool is_2xx() const noexcept { return status_code >= 200 && status_code < 300; }
};

/// High-level metadata model for object inspection (HEAD object)
struct S3ObjectMetadata {
    size_t content_length{0};
    std::string etag;
    std::string content_type;
    std::map<std::string, std::string> headers;
};

/// Completed part representation for CompleteMultipartUpload
struct CompletedPart {
    uint32_t part_number{0};
    std::string etag;
};

/// High-level representation of an individual object in ListObjectsResult
struct S3ObjectInfo {
    std::string key;
    size_t size{0};
    std::string etag;
    std::string last_modified;
};

/// High-level response model for ListObjectsV2
struct ListObjectsResult {
    std::vector<S3ObjectInfo> objects;
    bool is_truncated{false};
    std::string next_continuation_token;
    size_t key_count{0};
};

/// Abstract HTTP transport interface enabling zero-network deterministic unit test mocks
class IHttpTransport {
  public:
    virtual ~IHttpTransport() = default;
    virtual HttpResponse execute(const HttpRequest& req) = 0;
};

/// Exponential backoff retry policy with jitter for transient S3/MinIO failures
struct S3RetryPolicy {
    uint32_t max_retries{3};
    std::chrono::milliseconds initial_backoff{50};
    std::chrono::milliseconds max_backoff{500};
    double jitter_factor{0.2};

    /// Classifies HTTP status code: 0 (network/reset), 500, 502, 503, 504 are retryable.
    /// 400, 401, 403, 404 are non-retryable.
    [[nodiscard]] bool is_retryable(int status_code) const noexcept {
        if (status_code == 0) {
            return true;
        }
        return status_code == 500 || status_code == 502 || status_code == 503 || status_code == 504;
    }

    [[nodiscard]] std::chrono::milliseconds calculate_backoff(uint32_t attempt) const noexcept;
};

/// Strongly typed configuration model for MinIO S3 object storage
struct S3ClientConfig {
    std::string endpoint{"http://minio:9000"};
    std::string bucket{"securecloud-files-encrypted"};
    std::string access_key{"files_minio_user"};
    common::configuration::SecretString secret_key;
    std::string region{"us-east-1"};
    std::chrono::milliseconds default_timeout{1000};
    S3RetryPolicy retry_policy{};

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

/// Default socket-based HTTP/1.1 transport implementation with Keep-Alive connection pooling
class DefaultHttpTransport : public IHttpTransport {
  public:
    DefaultHttpTransport();
    ~DefaultHttpTransport() override;

    HttpResponse execute(const HttpRequest& req) override;

  private:
    void close_current_socket() noexcept;

#ifdef _WIN32
    uintptr_t cached_sock_{~static_cast<uintptr_t>(0)};
#else
    int cached_sock_{-1};
#endif
    std::string cached_host_;
    uint16_t cached_port_{0};
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

    /// Puts an object into the target bucket.
    /// Issues PUT /<bucket>/<object_key>.
    /// Automatically sets Content-Type, Content-Length, and x-amz-content-sha256.
    /// If sha256_hex is empty, it is calculated automatically from payload.
    /// Returns true on 200 OK or 201 Created.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on unexpected HTTP error status.
    bool put_object(const std::string& object_key, std::string_view payload,
                    const std::string& content_type = "application/octet-stream",
                    const std::string& sha256_hex = "",
                    std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    /// Retrieves an object (or byte range) from the target bucket.
    /// Issues GET /<bucket>/<object_key>.
    /// Returns S3ObjectResponse on 200 OK or 206 Partial Content.
    /// Throws S3ObjectNotFoundException on 404 Not Found.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on unexpected HTTP error status.
    [[nodiscard]] S3ObjectResponse get_object(const std::string& object_key,
                                             std::optional<ByteRange> range = std::nullopt,
                                             std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    /// Retrieves metadata for an object without downloading its body.
    /// Issues HEAD /<bucket>/<object_key>.
    /// Returns S3ObjectMetadata on 200 OK.
    /// Throws S3ObjectNotFoundException on 404 Not Found.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on unexpected HTTP error status.
    [[nodiscard]] S3ObjectMetadata head_object(const std::string& object_key,
                                              std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));

    /// Deletes an object from the target bucket.
    /// Issues DELETE /<bucket>/<object_key>.
    /// In S3, deleting a non-existent key is idempotent and returns 204 or 200.
    /// Returns true on 204 No Content, 200 OK, or 404 Not Found.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on unexpected HTTP error status.
    bool delete_object(const std::string& object_key,
                       std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));

    /// Initiates a multipart upload for an object.
    /// Issues POST /<bucket>/<object_key>?uploads.
    /// Returns upload_id string extracted from XML response.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on error.
    [[nodiscard]] std::string create_multipart_upload(const std::string& object_key,
                                                      const std::string& content_type = "application/octet-stream",
                                                      std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    /// Uploads an individual part in a multipart upload.
    /// Issues PUT /<bucket>/<object_key>?partNumber=<part_number>&uploadId=<upload_id>.
    /// Returns unquoted ETag header from response.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on error.
    [[nodiscard]] std::string upload_part(const std::string& object_key, const std::string& upload_id,
                                          uint32_t part_number, std::string_view payload,
                                          const std::string& sha256_hex = "",
                                          std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    /// Completes a multipart upload by assembling uploaded parts.
    /// Issues POST /<bucket>/<object_key>?uploadId=<upload_id> with XML part list.
    /// Returns true on 200 OK.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on error.
    bool complete_multipart_upload(const std::string& object_key, const std::string& upload_id,
                                   const std::vector<CompletedPart>& parts,
                                   std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

    /// Aborts an active multipart upload and frees uploaded part storage.
    /// Issues DELETE /<bucket>/<object_key>?uploadId=<upload_id>.
    /// Returns true on 204 No Content, 200 OK, or 404 Not Found (idempotent).
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on error.
    bool abort_multipart_upload(const std::string& object_key, const std::string& upload_id,
                                std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    /// Lists objects in the target bucket matching an optional prefix (ListObjectsV2).
    /// Issues GET /<bucket>?list-type=2&prefix=...
    /// Returns ListObjectsResult parsed from S3 XML response.
    /// Throws S3AuthenticationException on 403 Forbidden.
    /// Throws S3ServerException on 5xx.
    /// Throws S3ConnectionException on connection failure.
    /// Throws S3ClientException on error.
    [[nodiscard]] ListObjectsResult list_objects(const std::string& prefix = "", size_t max_keys = 1000,
                                                const std::string& continuation_token = "",
                                                std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    [[nodiscard]] const S3ClientConfig& config() const noexcept;
    [[nodiscard]] const std::string& endpoint_host() const noexcept;
    [[nodiscard]] uint16_t endpoint_port() const noexcept;
    [[nodiscard]] const S3RetryPolicy& retry_policy() const noexcept { return retry_policy_; }
    void set_retry_policy(S3RetryPolicy policy) noexcept { retry_policy_ = policy; }

  private:
    void parse_endpoint();
    [[nodiscard]] HttpResponse execute_with_retry(HttpRequest req);

    S3ClientConfig config_;
    std::shared_ptr<IHttpTransport> transport_;
    std::string host_{"127.0.0.1"};
    uint16_t port_{9000};
    bool is_https_{false};
    S3RetryPolicy retry_policy_{};
};

} // namespace securecloud::files::storage
