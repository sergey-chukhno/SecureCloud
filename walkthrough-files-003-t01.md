# Walkthrough: FILES-003-T01 — S3Client Core Object Operations (PUT, GET, HEAD, DELETE)

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-003-T01`  
**Card**: `FILES-003` (Establish MinIO Object Storage Integration)  
**Branch**: `feature/files-003-Establish-MinIO-object-storage-integration`

The primary objective of `FILES-003-T01` is to expand the low-level MinIO S3 storage transport (`src/files/storage/s3_client.{hpp,cpp}`) from a reachability-only probe (`ping_bucket`, `object_exists`) into a full, robust REST client capable of:
1. `put_object`: Uploading encrypted chunk/file payloads with explicit or calculated SHA-256 payload digest signing via AWS SigV4.
2. `get_object`: Downloading encrypted objects with support for byte-range requests (`bytes=start-end`), populating full response metadata (`ETag`, `Content-Type`, `Content-Length`).
3. `head_object`: Inspecting object presence, size, and `ETag` without transferring object payload bytes over the wire.
4. `delete_object`: Idempotently deleting object keys (treating HTTP 204, 200, and 404 as success).
5. Granular HTTP error status mapping to strongly typed exceptions (`S3AuthenticationException`, `S3ObjectNotFoundException`, `S3ServerException`, `S3ConnectionException`).

---

## 2. Key Components Delivered

### 2.1 Typed S3 Exceptions (`src/files/storage/s3_exceptions.hpp`)
Introduced specific exception types to distinguish server-side 5xx errors and payload integrity mismatches from client or authentication errors:
- `S3ServerException`: Thrown when MinIO returns HTTP 500..599 server errors.
- `S3IntegrityException`: Reserved for SHA-256 digest mismatches during upload/download.
- Existing exceptions preserved: `S3ClientException`, `S3BucketNotFoundException`, `S3AuthenticationException`, `S3ObjectNotFoundException`, `S3ConnectionException`.

### 2.2 Data Models & Signatures (`src/files/storage/s3_client.hpp`)
Added high-level data models isolating domain services from raw HTTP protocol details:
```cpp
struct ByteRange {
    uint64_t start_byte{0};
    std::optional<uint64_t> end_byte{std::nullopt};
    [[nodiscard]] std::string to_header_value() const;
};

struct S3ObjectResponse {
    int status_code{0};
    std::string body;
    size_t content_length{0};
    std::string etag;
    std::string content_type;
    std::map<std::string, std::string> headers;
    [[nodiscard]] bool is_2xx() const noexcept;
};

struct S3ObjectMetadata {
    size_t content_length{0};
    std::string etag;
    std::string content_type;
    std::map<std::string, std::string> headers;
};
```

Added core object manipulation operations to `S3Client`:
- `bool put_object(const std::string& object_key, std::string_view payload, const std::string& content_type, const std::string& sha256_hex, std::chrono::milliseconds timeout)`
- `S3ObjectResponse get_object(const std::string& object_key, std::optional<ByteRange> range, std::chrono::milliseconds timeout)`
- `S3ObjectMetadata head_object(const std::string& object_key, std::chrono::milliseconds timeout)`
- `bool delete_object(const std::string& object_key, std::chrono::milliseconds timeout)`

### 2.3 HTTP Wire Implementation & SigV4 Signer (`src/files/storage/s3_client.cpp`)
1. **SigV4 Payload Hash Optimization**:
   - `SigV4Signer::sign_request` now checks if `x-amz-content-sha256` is already populated in request headers. If provided (e.g. from pre-computed chunk checksums), it reuses it directly, eliminating redundant SHA-256 computations.
2. **HTTP Response Parsing in `DefaultHttpTransport`**:
   - Added robust header splitting and parsing after `\r\n\r\n`.
   - Populates `HttpResponse::headers` with case-insensitive lowercased keys.
   - Extracts and isolates `HttpResponse::body` for non-HEAD requests.
3. **ETag Unquoting**:
   - Helper `unquote()` automatically strips enclosing HTTP double quotes from S3 `ETag` headers (`"hash"` -> `hash`).

---

## 3. Verification & Unit Test Suite

The test suite in `tests/unit/files/s3_client_test.cpp` was expanded with 5 comprehensive test suites using the zero-network `MockHttpTransport`:

| Test Name | Validations | Status |
| :--- | :--- | :---: |
| `S3ClientTest.SigV4Sha256AndHmacDerivation` | AWS test vectors for SHA-256 and HMAC-SHA256 | **PASSED** |
| `S3ClientTest.SigV4HeaderFormatting` | AWS SigV4 authorization header, date format, signed headers | **PASSED** |
| `S3ClientTest.ConfigValidationAndExtraction` | Valid and invalid configurations, FilesConfig conversion | **PASSED** |
| `S3ClientTest.PingBucketSuccessOn200OK` | HEAD bucket reachability on 200 OK | **PASSED** |
| `S3ClientTest.PingBucketFailureReturnsFalseWithoutThrowing` | Non-throwing behavior on 404, 500, socket failure | **PASSED** |
| `S3ClientTest.ObjectExistsSuccessOn200OK` | HEAD object verification | **PASSED** |
| `S3ClientTest.ObjectExistsNotFoundReturnsFalse` | 404 returns false cleanly | **PASSED** |
| `S3ClientTest.ObjectExistsForbiddenThrowsAuthenticationException` | 403 throws `S3AuthenticationException` | **PASSED** |
| `S3ClientTest.ObjectExistsConnectionFailureThrowsConnectionException` | Connection failure throws `S3ConnectionException` | **PASSED** |
| `S3ClientTest.PutObjectSuccessAndHeaders` | **NEW**: Validates PUT body, `Content-Type`, `Content-Length`, `x-amz-content-sha256`, and SigV4 auth | **PASSED** |
| `S3ClientTest.GetObjectFullAndRange` | **NEW**: Validates full GET and partial range GET (`Range: bytes=0-4`), unquoting of `ETag` | **PASSED** |
| `S3ClientTest.HeadObjectSuccessAndNotFound` | **NEW**: Validates metadata retrieval (content-length, etag) and 404 exception | **PASSED** |
| `S3ClientTest.DeleteObjectIdempotence` | **NEW**: Validates idempotent deletion on 204, 200, and 404 | **PASSED** |
| `S3ClientTest.ServerAndConnectionExceptions` | **NEW**: Validates 500/503 mapping to `S3ServerException` and socket failure to `S3ConnectionException` | **PASSED** |
| **Total** | **14 / 14 Tests Passing** | **100% PASS** |

### Test Execution Output:
```text
[==========] Running 14 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 14 tests from S3ClientTest
[ RUN      ] S3ClientTest.SigV4Sha256AndHmacDerivation
[       OK ] S3ClientTest.SigV4Sha256AndHmacDerivation (21 ms)
[ RUN      ] S3ClientTest.SigV4HeaderFormatting
[       OK ] S3ClientTest.SigV4HeaderFormatting (0 ms)
[ RUN      ] S3ClientTest.ConfigValidationAndExtraction
[       OK ] S3ClientTest.ConfigValidationAndExtraction (0 ms)
[ RUN      ] S3ClientTest.PingBucketSuccessOn200OK
[       OK ] S3ClientTest.PingBucketSuccessOn200OK (0 ms)
[ RUN      ] S3ClientTest.PingBucketFailureReturnsFalseWithoutThrowing
[       OK ] S3ClientTest.PingBucketFailureReturnsFalseWithoutThrowing (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsSuccessOn200OK
[       OK ] S3ClientTest.ObjectExistsSuccessOn200OK (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsNotFoundReturnsFalse
[       OK ] S3ClientTest.ObjectExistsNotFoundReturnsFalse (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsForbiddenThrowsAuthenticationException
[       OK ] S3ClientTest.ObjectExistsForbiddenThrowsAuthenticationException (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsConnectionFailureThrowsConnectionException
[       OK ] S3ClientTest.ObjectExistsConnectionFailureThrowsConnectionException (0 ms)
[ RUN      ] S3ClientTest.PutObjectSuccessAndHeaders
[       OK ] S3ClientTest.PutObjectSuccessAndHeaders (0 ms)
[ RUN      ] S3ClientTest.GetObjectFullAndRange
[       OK ] S3ClientTest.GetObjectFullAndRange (0 ms)
[ RUN      ] S3ClientTest.HeadObjectSuccessAndNotFound
[       OK ] S3ClientTest.HeadObjectSuccessAndNotFound (0 ms)
[ RUN      ] S3ClientTest.DeleteObjectIdempotence
[       OK ] S3ClientTest.DeleteObjectIdempotence (0 ms)
[ RUN      ] S3ClientTest.ServerAndConnectionExceptions
[       OK ] S3ClientTest.ServerAndConnectionExceptions (0 ms)
[----------] 14 tests from S3ClientTest (24 ms total)

[----------] Global test environment tear-down
[==========] 14 tests from 1 test suite ran. (24 ms total)
[  PASSED  ] 14 tests.
```

---

## 4. Invariants Enforced
- **Zero-Plaintext Invariant (ADR-005, ADR-008)**: Payload bytes passed to `put_object` or received by `get_object` are treated as opaque binary streams; no decryption or plaintext inspection is performed.
- **Idempotent Deletion**: `delete_object` safely treats missing keys as already deleted (204/200/404), ensuring retry safety.
- **Port 5432 Protection**: Strict observance maintained; no port 5432 operations performed.
- **Compiler Warnings**: Zero warnings across MSVC and MinGW toolchains.

---

## 5. Next Steps
Proceeding to **`FILES-003-T02`**: *S3Client Multipart Upload API & Object Listing* (`create_multipart_upload`, `upload_part`, `complete_multipart_upload`, `abort_multipart_upload`, `list_objects`).
