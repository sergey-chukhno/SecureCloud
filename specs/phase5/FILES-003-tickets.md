# FILES-003 — Establish MinIO Object Storage Integration
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: FILES-003 (or FILE-003)  
**Milestone**: M5 — Secure Files  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-003** establishes the authoritative **MinIO S3-compatible Object Storage Integration** for the **SecureCloud Files Service** (`securecloud-files`). Building directly upon the initial reachability client created in **FILES-001** and the PostgreSQL persistence foundation established in **FILES-002**, this card provides robust, bounded, and resilient object storage operations for encrypted file objects and chunks, lifecycle metadata inspection, streaming range reads, integrity verification, and storage cleanup.

### Key Invariants & Architectural Boundaries
1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design 6.1, 6.2, 6.17)**:
   - Neither the Files Service nor MinIO ever possesses plaintext file contents, plaintext filenames, user private cryptographic keys, or file-encryption keys.
   - All object storage operations (`PutObject`, `GetObject`, `UploadPart`) execute strictly on pre-encrypted ciphertext bytes.
2. **Authority Separation of Concerns (Initial Backlog Review Item 1, Files Design 6.17)**:
   - **PostgreSQL 17** (`securecloud_files`): Authoritative for file metadata, transfer lifecycle, chunk receipts, user access grants, and transactional outbox.
   - **MinIO S3** (`securecloud-files-encrypted`): Authoritative exclusively for encrypted binary object storage and chunk payload persistence.
3. **Opaque Object Key Invariant (Files Design 6.17)**:
   - Object keys in S3 must be strictly opaque identifiers derived from UUIDs (e.g. `chunks/<transfer_id>/<chunk_index>` or `files/<file_id>/<version_number>`).
   - Object keys MUST NEVER expose usernames, emails, conversation titles, or plaintext filenames.
4. **End-to-End Cryptographic Integrity Invariant (Files Design 6.8, 6.9, 6.18)**:
   - Every chunk or object uploaded must be accompanied by its SHA-256 checksum (`x-amz-content-sha256` in AWS SigV4).
   - Chunk submissions with mismatched hashes must be rejected prior to durable acceptance.
   - Retrieved data must be verified against expected checksums.
5. **Bounded Resource & Backpressure Invariant (Files Design 6.13, 6.14)**:
   - Memory buffers for uploads and downloads must remain strictly bounded (maximum 4 MiB logical chunk size).
   - Object storage operations must execute under configurable timeouts and bounded concurrency with retry policies (exponential backoff with jitter for transient errors).
6. **M1 Non-Regression Invariant**:
   - Zero compilation warnings or errors across macOS (AppleClang), Windows (MSVC x64), and Windows (MinGW-w64).
   - Port 5432 host PostgreSQL guard remains strictly observed. MinIO uses port 9000 (S3 API).

---

## 2. Component Architecture & Object Key Model

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                         SecureCloud Files Service                      │
 │                                                                        │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │                         StorageEngine                            │  │
 │  │  - Translates domain operations (put_chunk, get_chunk, cleanup)  │  │
 │  │  - Enforces opaque key derivation:                               │  │
 │  │      chunks/{transfer_id}/{chunk_index}                          │  │
 │  │      objects/{file_id}/{version_number}                          │  │
 │  │  - Computes and asserts SHA-256 integrity checksums              │  │
 │  └──────────────────────────────┬───────────────────────────────────┘  │
 │                                 │                                      │
 │  ┌──────────────────────────────▼───────────────────────────────────┐  │
 │  │                            S3Client                              │  │
 │  │  - AWS SigV4 Signer (HMAC-SHA256, payload hash)                 │  │
 │  │  - Bounded HTTP/1.1 Transport (Keep-Alive, socket pooling)       │  │
 │  │  - Core Operations: PUT, GET, HEAD, DELETE, LIST                 │  │
 │  │  - Multipart Operations: Initiate, UploadPart, Complete, Abort   │  │
 │  │  - Transient Error Classifier & Exponential Backoff Retry        │  │
 │  └──────────────────────────────┬───────────────────────────────────┘  │
 └─────────────────────────────────┼──────────────────────────────────────┘
                                   │ HTTP/1.1 REST (AWS SigV4)
                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      MinIO S3 Object Storage                           │
 │                Bucket: securecloud-files-encrypted                     │
 │                                                                        │
 │   /chunks/{transfer_id}/{chunk_index}  <-- In-progress transfer chunks │
 │   /objects/{file_id}/{version_number}  <-- Finalized encrypted files   │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Dependency Graph & Implementation Sequence

```text
                                FILES-003-T01
                    (S3Client Core Object Operations)
                                   │
                                   ▼
                                FILES-003-T02
                    (S3Client Multipart & Listing API)
                                   │
                                   ▼
                                FILES-003-T03
                    (StorageEngine Domain Abstraction)
                                   │
                                   ▼
                                FILES-003-T04
                    (Resilience, Retries & HTTP Connection Pool)
                                   │
                                   ▼
                                FILES-003-T05
                    (Unit Test Suite & Mock Verification)
                                   │
                                   ▼
                                FILES-003-T06
                    (MinIO Live Integration Test & Card Sign-Off)
```

---

## 4. Implementation Tickets

### FILES-003-T01 — S3Client Core Object Operations (PUT, GET, HEAD, DELETE)

1. **Ticket ID**: `FILES-003-T01`
2. **Title**: S3Client Core Object Operations (PUT, GET, HEAD, DELETE)
3. **Objective**: Expand `src/files/storage/s3_client.{hpp,cpp}` to implement full REST operations for single objects: `put_object`, `get_object` (with optional byte-range), `head_object`, and `delete_object`, signed with AWS SigV4 including exact payload SHA-256 hashes.
4. **Architectural Purpose**: Provides the core HTTP REST abstraction for writing, reading, inspecting, and deleting encrypted objects in MinIO without exposing storage details to upper layers (Files Design 6.17).
5. **Scope**:
   - Add `S3ObjectResponse`:
     ```cpp
     struct S3ObjectResponse {
         int status_code{0};
         std::string body;
         size_t content_length{0};
         std::string etag;
         std::string content_type;
         std::map<std::string, std::string> metadata;
     };
     ```
   - Add `ByteRange` struct for range requests (`bytes=start-end`):
     ```cpp
     struct ByteRange {
         uint64_t start_byte{0};
         std::optional<uint64_t> end_byte{std::nullopt};
         [[nodiscard]] std::string to_header_value() const;
     };
     ```
   - Implement in `S3Client`:
     - `put_object(object_key, payload, content_type, sha256_hex, timeout)`: Issues `PUT /<bucket>/<object_key>` with `x-amz-content-sha256`. Validates 200 OK / 201 Created.
     - `get_object(object_key, range, timeout)`: Issues `GET /<bucket>/<object_key>` with optional `Range` header. Returns `S3ObjectResponse`.
     - `head_object(object_key, timeout)`: Issues `HEAD /<bucket>/<object_key>`. Returns object metadata, content length, and ETag.
     - `delete_object(object_key, timeout)`: Issues `DELETE /<bucket>/<object_key>`. Handles 204 No Content / 200 OK / 404 Not Found idempotently.
   - Map HTTP error status codes to typed exceptions in `s3_exceptions.hpp`:
     - 404 -> `S3ObjectNotFoundException`
     - 403/401 -> `S3AuthenticationException`
     - 5xx -> `S3ServerException`
     - Network/Timeout -> `S3ConnectionException`
6. **Explicit Out-of-Scope**: Multipart uploads (T02) and domain key mapping (T03).
7. **Dependencies**: Upstream FILES-001-T03. Downstream FILES-003-T02.
8. **Exact Repository Starting Point**: `src/files/storage/s3_client.hpp`, `src/files/storage/s3_client.cpp`, `src/files/storage/s3_exceptions.hpp`.
9. **Files to Modify**:
   - `src/files/storage/s3_client.hpp`
   - `src/files/storage/s3_client.cpp`
   - `src/files/storage/s3_exceptions.hpp`
10. **Acceptance Criteria**:
    - All 4 methods correctly format HTTP paths, headers, and SigV4 signatures.
    - Zero plaintexts leaked in log messages or headers.
    - Unit tests pass with mock HTTP transport.

---

### FILES-003-T02 — S3Client Multipart Upload API & Object Listing

1. **Ticket ID**: `FILES-003-T02`
2. **Title**: S3Client Multipart Upload API & Object Listing
3. **Objective**: Extend `S3Client` to support S3 Multipart Uploads (`create_multipart_upload`, `upload_part`, `complete_multipart_upload`, `abort_multipart_upload`) and S3 ListObjectsV2 for prefix queries and cleanup.
4. **Architectural Purpose**: Enables streaming and chunked assembly for large files exceeding single-PUT boundaries, and provides object enumeration for abandoned transfer cleanup (Files Design 6.8, 6.20).
5. **Scope**:
   - Define data models:
     ```cpp
     struct CompletedPart {
         uint32_t part_number{0};
         std::string etag;
     };

     struct S3ObjectInfo {
         std::string key;
         size_t size{0};
         std::string etag;
         std::chrono::system_clock::time_point last_modified;
     };

     struct ListObjectsResult {
         std::vector<S3ObjectInfo> objects;
         bool is_truncated{false};
         std::string next_continuation_token;
     };
     ```
   - Implement in `S3Client`:
     - `create_multipart_upload(object_key)`: Issues `POST /<bucket>/<object_key>?uploads`. Parses XML response to extract `UploadId`.
     - `upload_part(object_key, upload_id, part_number, payload, sha256_hex)`: Issues `PUT /<bucket>/<object_key>?partNumber=X&uploadId=Y`. Returns part ETag.
     - `complete_multipart_upload(object_key, upload_id, parts)`: Issues `POST /<bucket>/<object_key>?uploadId=Y` with `<CompleteMultipartUpload>` XML body.
     - `abort_multipart_upload(object_key, upload_id)`: Issues `DELETE /<bucket>/<object_key>?uploadId=Y`.
     - `list_objects(prefix, max_keys, continuation_token)`: Issues `GET /<bucket>?list-type=2&prefix=...`. Parses XML response.
6. **Explicit Out-of-Scope**: PostgreSQL transaction integration (owned by service layer).
7. **Dependencies**: Upstream FILES-003-T01. Downstream FILES-003-T03.
8. **Files to Modify**:
   - `src/files/storage/s3_client.hpp`
   - `src/files/storage/s3_client.cpp`
9. **Acceptance Criteria**:
   - XML payloads for initiate, complete, and listing parse cleanly across platforms.
   - Multipart abort cleanly releases uncommitted part storage.

---

### FILES-003-T03 — StorageEngine Domain Abstraction Layer

1. **Ticket ID**: `FILES-003-T03`
2. **Title**: StorageEngine Domain Abstraction Layer
3. **Objective**: Replace the stub implementation in `src/files/service/storage_engine.{hpp,cpp}` with a production `StorageEngine` class providing opaque object key derivation, chunk storage, retrieval, and file object deletion.
4. **Architectural Purpose**: Isolates the domain service layer from low-level S3 REST semantics, enforcing the Zero-Plaintext invariant, opaque key hierarchy, and cryptographic integrity verification (Files Design 6.3, 6.17).
5. **Scope**:
   - Define interface in `src/files/service/storage_engine.hpp`:
     ```cpp
     class IStorageEngine {
       public:
         virtual ~IStorageEngine() = default;

         virtual bool put_chunk(const std::string& transfer_id, uint32_t chunk_index,
                                std::string_view encrypted_data, const std::string& expected_sha256) = 0;

         virtual std::optional<std::string> get_chunk(const std::string& transfer_id,
                                                      uint32_t chunk_index) = 0;

         virtual bool delete_chunk(const std::string& transfer_id, uint32_t chunk_index) = 0;

         virtual bool put_file_object(const std::string& file_id, uint32_t version_number,
                                      std::string_view encrypted_data, const std::string& expected_sha256) = 0;

         virtual std::optional<std::string> get_file_object(const std::string& file_id,
                                                            uint32_t version_number,
                                                            std::optional<storage::ByteRange> range = std::nullopt) = 0;

         virtual bool delete_file_objects(const std::string& file_id) = 0;

         virtual bool delete_transfer_chunks(const std::string& transfer_id) = 0;
     };
     ```
   - Implement `StorageEngine` in `src/files/service/storage_engine.cpp`:
     - Opaque key schemas:
       - Chunks: `chunks/{transfer_id}/{chunk_index}`
       - Finalized objects: `objects/{file_id}/{version_number}`
     - Validates SHA-256 of incoming data against `expected_sha256`. Throws `S3IntegrityException` if mismatched.
     - Validates SHA-256 of outgoing data on `get_chunk`.
     - `delete_transfer_chunks`: Lists objects with prefix `chunks/{transfer_id}/` and issues bounded deletion.
6. **Explicit Out-of-Scope**: Direct database mutations (handled by `FileRepository` / `FileChunkRepository`).
7. **Dependencies**: Upstream FILES-003-T01, FILES-003-T02. Downstream FILES-003-T04.
8. **Files to Create/Modify**:
   - `src/files/service/storage_engine.hpp`
   - `src/files/service/storage_engine.cpp`
   - `src/files/CMakeLists.txt`
9. **Acceptance Criteria**:
   - Chunk and file operations strictly reject mismatched hashes.
   - All object keys are opaque UUID paths.
   - Deletion routines cleanly handle missing objects idempotently.

---

### FILES-003-T04 — Storage Resilience, Retries & HTTP Connection Pooling

1. **Ticket ID**: `FILES-003-T04`
2. **Title**: Storage Resilience, Retries & HTTP Connection Pooling
3. **Objective**: Implement socket connection reuse / pooling in `DefaultHttpTransport` and an exponential backoff retry policy with jitter for transient S3/MinIO failures (HTTP 500, 503, connection reset).
4. **Architectural Purpose**: Ensures Files Service withstands network blips, TCP handshake overhead, and temporary MinIO restarts without dropping in-flight transfers or leaking sockets (ADR-010, Files Design 6.13, 6.14).
5. **Scope**:
   - Implement `S3RetryPolicy`:
     - Max retries: 3.
     - Initial backoff: 50ms, max backoff: 500ms, randomized jitter factor: 0.2.
     - Classifies errors: 500, 502, 503, 504 and connection resets are retryable; 400, 403, 404 are non-retryable.
   - Optimize `DefaultHttpTransport`:
     - Support HTTP/1.1 `Connection: keep-alive`.
     - Socket reuse for consecutive requests to the same host/port.
     - Graceful socket reconnect on closed connection.
     - Configurable connect and read/write timeouts.
6. **Explicit Out-of-Scope**: PostgreSQL retry logic (already handled by connection pool).
7. **Dependencies**: Upstream FILES-003-T01. Downstream FILES-003-T05.
8. **Files to Modify**:
   - `src/files/storage/s3_client.hpp`
   - `src/files/storage/s3_client.cpp`
9. **Acceptance Criteria**:
   - Transient 503 errors recover automatically within retry budget.
   - Non-retryable errors fail immediately without wasteful retries.
   - Sockets close cleanly on process termination without leaks.

---

### FILES-003-T05 — Storage Engine & S3Client Unit Test Suites

1. **Ticket ID**: `FILES-003-T05`
2. **Title**: Storage Engine & S3Client Unit Test Suites
3. **Objective**: Author comprehensive unit test suites for `S3Client` and `StorageEngine` in `tests/unit/files/` validating all operations, error paths, SigV4 headers, hash integrity, and retry behavior using zero-network mock transports.
4. **Architectural Purpose**: Guarantees deterministic, offline verification of all object storage logic and edge cases across all target platforms (macOS, Linux, Windows MSVC, Windows MinGW).
5. **Scope**:
   - Expand `tests/unit/files/s3_client_test.cpp`:
     - `PutObjectSuccessAndHeaders`: Verifies AWS SigV4 authorization header, content SHA-256 header, body formatting.
     - `GetObjectFullAndRange`: Verifies range header generation (`bytes=0-1023`) and response parsing.
     - `HeadObjectSuccessAndNotFound`: Verifies metadata parsing and 404 exception.
     - `DeleteObjectIdempotence`: Verifies 204, 200, and 404 return cleanly.
     - `MultipartUploadLifecycle`: Mocks Initiate -> UploadPart 1..N -> Complete flow.
     - `ListObjectsV2Parsing`: Tests XML parsing of object keys, sizes, and truncation flags.
     - `RetryPolicyTransientRecovery`: Verifies 503 followed by 200 succeeds after retry.
     - `RetryPolicyExhaustion`: Verifies permanent failure throws after 3 attempts.
   - Author `tests/unit/files/storage_engine_test.cpp`:
     - `PutAndGetChunkSuccess`: Tests chunk storage and retrieval with matching SHA-256.
     - `IntegrityMismatchRejection`: Tests that corrupted data throws `S3IntegrityException`.
     - `OpaqueKeyDerivation`: Asserts that keys contain strictly UUIDs and no user/filename data.
     - `BatchChunkCleanup`: Verifies prefix-based deletion of transfer chunks.
   - Register tests in `tests/unit/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Live Docker container tests (owned by T06).
7. **Dependencies**: Upstream FILES-003-T01, FILES-003-T02, FILES-003-T03, FILES-003-T04. Downstream FILES-003-T06.
8. **Files to Create/Modify**:
   - `tests/unit/files/s3_client_test.cpp`
   - `tests/unit/files/storage_engine_test.cpp`
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - All unit tests pass with zero network dependency.
   - 100% test pass rate across GCC, Clang, and MSVC.

---

### FILES-003-T06 — MinIO Live Integration Test Suite & Card Sign-Off

1. **Ticket ID**: `FILES-003-T06`
2. **Title**: MinIO Live Integration Test Suite & Card Sign-Off
3. **Objective**: Implement a live end-to-end integration test suite in `tests/integration/files_minio_storage_integration_test.cpp` against a running MinIO S3 instance, validating real-world chunk uploads, range downloads, multipart transfers, integrity verification, and cold restarts.
4. **Architectural Purpose**: Final quality gate proving that `StorageEngine` and `S3Client` correctly interface with MinIO S3 over real HTTP sockets, preserving ciphertext and metadata across process lifecycles.
5. **Scope**:
   - Implement `tests/integration/files_minio_storage_integration_test.cpp`:
     - Test fixture with TCP preflight probe (`127.0.0.1:9000`). If MinIO is unreachable, skips cleanly via `GTEST_SKIP()` without failing CI.
     - TC1: Live bucket reachability and credential validation (`ping_bucket`).
     - TC2: Live chunk PUT and GET roundtrip with SHA-256 verification (1 MiB ciphertext).
     - TC3: Range GET verification matching exact byte slices from live MinIO.
     - TC4: Multipart chunk assembly and upload of large encrypted payload (5 MiB).
     - TC5: Live cleanup and deletion of transfer chunks.
     - TC6: Cold restart durability: store chunk, destroy `StorageEngine` instance, instantiate new instance, verify chunk persistence.
   - Register target in `tests/integration/CMakeLists.txt`.
   - Update walkthrough documentation (`walkthrough-files-003-*.md`).
6. **Explicit Out-of-Scope**: Gateway proxy routing (Milestone 5 later cards).
7. **Dependencies**: Upstream FILES-003-T01 through FILES-003-T05.
8. **Files to Create/Modify**:
   - `tests/integration/files_minio_storage_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`
   - `walkthrough-files-003-*.md`
9. **Acceptance Criteria**:
   - All live integration tests pass when MinIO container is active.
   - Non-regression across all previous 89 FILES-002 tests and Milestone 1 test suites.
   - Full sign-off checklist completed.

---

## 5. Quality Gate & Sign-Off Checklist for Card FILES-003

- [x] Zero-Plaintext Invariant: Only encrypted ciphertext is sent to or retrieved from MinIO.
- [x] Opaque Key Invariant: Object keys derive exclusively from UUIDs and indices; no user or file plaintexts are leaked.
- [x] End-to-End Cryptographic Integrity: Payload SHA-256 digests are asserted on write and read.
- [x] Bounded Buffering: No whole-file buffering in memory; maximum 4 MiB logical chunk size enforced.
- [x] S3 REST Capabilities: Full implementation of PUT, GET (with Range), HEAD, DELETE, ListObjectsV2, and Multipart Uploads.
- [x] Transient Failure Resilience: Configurable exponential backoff retries with jitter for 500/503 errors.
- [x] Unit Test Coverage: Deterministic mock transport unit tests covering all operations and error states.
- [x] Live Integration Verification: Integration test suite passing cleanly against live MinIO container on port 9000.
- [x] Cross-Platform Cleanliness: Zero warnings or errors on Windows (MSVC / MinGW) and macOS.
- [x] Non-Regression: All existing 89 FILES-002 tests and Phase 1 / 2 tests pass without regressions.

