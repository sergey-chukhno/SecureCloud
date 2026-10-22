# Walkthrough: FILES-003-T02 — S3Client Multipart Upload API & Object Listing

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-003-T02`  
**Card**: `FILES-003` (Establish MinIO Object Storage Integration)  
**Branch**: `feature/files-003-Establish-MinIO-object-storage-integration`

The primary objective of `FILES-003-T02` is to extend `src/files/storage/s3_client.{hpp,cpp}` to support S3-compatible **Multipart Uploads** and **Object Listing (ListObjectsV2)**. This capability is required for:
1. Assembling large encrypted files and chunks without loading the entire payload into RAM at once.
2. Gracefully aborting abandoned or interrupted multipart uploads to release storage resources.
3. Listing chunks matching a transfer prefix (`chunks/<transfer_id>/`) for verification, assembly, and automated retention cleanup.

---

## 2. Key Components Delivered

### 2.1 Multipart & Listing Data Models (`src/files/storage/s3_client.hpp`)
Added data models for multipart part tracking and object enumeration:
```cpp
struct CompletedPart {
    uint32_t part_number{0};
    std::string etag;
};

struct S3ObjectInfo {
    std::string key;
    size_t size{0};
    std::string etag;
    std::string last_modified;
};

struct ListObjectsResult {
    std::vector<S3ObjectInfo> objects;
    bool is_truncated{false};
    std::string next_continuation_token;
    size_t key_count{0};
};
```

### 2.2 S3 REST Method Implementations (`src/files/storage/s3_client.cpp`)
1. **`create_multipart_upload`**:
   - Issues `POST /<bucket>/<object_key>?uploads` with AWS SigV4 authorization.
   - Parses `<UploadId>...</UploadId>` from the MinIO XML response.
2. **`upload_part`**:
   - Issues `PUT /<bucket>/<object_key>?partNumber=<part_number>&uploadId=<upload_id>`.
   - Passes payload with `x-amz-content-sha256` header.
   - Extracts and unquotes the returned `ETag` header.
3. **`complete_multipart_upload`**:
   - Issues `POST /<bucket>/<object_key>?uploadId=<upload_id>`.
   - Generates the standard `<CompleteMultipartUpload>` XML payload with sorted `<Part>` elements.
4. **`abort_multipart_upload`**:
   - Issues `DELETE /<bucket>/<object_key>?uploadId=<upload_id>`.
   - Handles 204, 200, and 404 idempotently to clean up intermediate parts.
5. **`list_objects` (ListObjectsV2)**:
   - Issues `GET /<bucket>?list-type=2&prefix=<prefix>&max-keys=<max_keys>`.
   - Parses `<Contents>` elements (`Key`, `Size`, `ETag`, `LastModified`), `<IsTruncated>`, and `<NextContinuationToken>`.

### 2.3 AWS SigV4 Canonical Query String Sorting
Expanded `SigV4Signer::sign_request` to parse raw HTTP query strings, split parameters by `&`, sort them alphabetically by parameter name in compliance with AWS SigV4 specifications, and construct canonical requests with exact query parameter signatures.

---

## 3. Verification & Unit Test Suite

The test suite in `tests/unit/files/s3_client_test.cpp` was expanded with 3 new comprehensive mock tests:

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
| `S3ClientTest.PutObjectSuccessAndHeaders` | Validates PUT body, `Content-Type`, `Content-Length`, `x-amz-content-sha256` | **PASSED** |
| `S3ClientTest.GetObjectFullAndRange` | Validates full GET and partial range GET (`Range: bytes=0-4`) | **PASSED** |
| `S3ClientTest.HeadObjectSuccessAndNotFound` | Validates metadata retrieval and 404 exception | **PASSED** |
| `S3ClientTest.DeleteObjectIdempotence` | Validates idempotent deletion on 204, 200, and 404 | **PASSED** |
| `S3ClientTest.ServerAndConnectionExceptions` | Validates 500/503 mapping to `S3ServerException` and socket failure | **PASSED** |
| `S3ClientTest.MultipartUploadLifecycleMock` | **NEW**: Full initiate -> upload parts 1 & 2 -> complete multipart flow | **PASSED** |
| `S3ClientTest.AbortMultipartUploadMock` | **NEW**: Validates abort deletion on 204, 404, and 403 error mapping | **PASSED** |
| `S3ClientTest.ListObjectsV2ParsingMock` | **NEW**: XML parsing of ListObjectsV2 response, keys, sizes, and pagination tokens | **PASSED** |
| **Total** | **17 / 17 Tests Passing** | **100% PASS** |

### Test Execution Output:
```text
[==========] Running 17 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 17 tests from S3ClientTest
[ RUN      ] S3ClientTest.SigV4Sha256AndHmacDerivation
[       OK ] S3ClientTest.SigV4Sha256AndHmacDerivation (2 ms)
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
[ RUN      ] S3ClientTest.MultipartUploadLifecycleMock
[       OK ] S3ClientTest.MultipartUploadLifecycleMock (0 ms)
[ RUN      ] S3ClientTest.AbortMultipartUploadMock
[       OK ] S3ClientTest.AbortMultipartUploadMock (0 ms)
[ RUN      ] S3ClientTest.ListObjectsV2ParsingMock
[       OK ] S3ClientTest.ListObjectsV2ParsingMock (0 ms)
[----------] 17 tests from S3ClientTest (6 ms total)

[----------] Global test environment tear-down
[==========] 17 tests from 1 test suite ran. (6 ms total)
[  PASSED  ] 17 tests.
```

---

## 4. Invariants Enforced
- **Zero-Plaintext Invariant (ADR-005, ADR-008)**: Multipart parts and listed objects operate strictly on ciphertext; zero plaintexts are processed or leaked.
- **Query Parameter Canonical Sorting**: SigV4 signatures correctly handle query strings across all multipart and listing routes.
- **Port 5432 Invariant**: Observational protection strictly preserved.

---

## 5. Next Steps
Proceeding to **`FILES-003-T03`**: *StorageEngine Domain Abstraction Layer* (`src/files/service/storage_engine.{hpp,cpp}`).
