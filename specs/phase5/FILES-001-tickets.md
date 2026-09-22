# FILES-001 — Establish Files Service Foundation
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: FILES-001 (or FILE-001)  
**Milestone**: M5 — Secure Files  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-001** establishes the foundational runtime architecture, gRPC IPC contracts, dual-storage client infrastructure (PostgreSQL 17 for metadata + MinIO S3 for encrypted binary objects), dual-dependency health/readiness engine, lifecycle management, and integration testing harness for the **SecureCloud Files Service** (`securecloud-files`).

### Key Invariants & Architectural Boundaries
1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design 6.1, 6.26)**:
   The Files Service operates **exclusively on pre-encrypted file ciphertext**. It must NEVER receive, decrypt, compress, inspect, or possess:
   - Plaintext file content.
   - User or device private cryptographic keys.
   - Plaintext file-encryption keys.
   - Administrative decryption backdoors.
   File encryption and decryption are strictly client-side endpoint responsibilities.
2. **Strict Observational Host PostgreSQL 14 Guard**:
   The developer workstation host runs an active PostgreSQL 14 instance on `localhost:5432`. SecureCloud workflows MUST NEVER attempt to connect to, stop, restart, reconfigure, or bind to host port `5432`. SecureCloud PostgreSQL 17 binds strictly to `127.0.0.1:5433` (container port `5432`).
3. **Dual-Persistence Ownership Architecture (Files Design 6.17)**:
   - **PostgreSQL 17** (`securecloud_files`): Authoritative transactional database for file metadata, transfer states, access policies, chunk tracking, and transactional outbox.
   - **MinIO S3 Object Storage** (`securecloud-files-encrypted`): Authoritative durable storage for encrypted binary objects and chunks.
   - Large binary payloads must **never** be stored in PostgreSQL.
4. **Dual-Dependency Health & Readiness Model**:
   Readiness evaluation verifies reachability to **both** critical storage dependencies:
   - PostgreSQL database ping (`SELECT 1`).
   - MinIO S3 bucket existence and reachability (`HEAD /securecloud-files-encrypted`).
   If **either** dependency is unavailable, readiness immediately degrades to `NOT_SERVING` while process liveness remains `SERVING`.
5. **Zero Backend Business Logic in FILES-001**:
   FILES-001 establishes the service skeleton, configuration, database/S3 connectivity foundations, and transport security. It does **not** implement chunk streaming, resumable upload assembly (FILE-005), or finalization (FILE-006). All 7 authoritative proto RPCs must return deterministic `grpc::StatusCode::UNIMPLEMENTED`.
6. **M1 Non-Regression Invariant**:
   All Milestone 1 capabilities, CMake build presets, protobuf generation targets, mTLS credential loaders, and `verify-local.py` orchestration must continue passing cleanly across macOS (AppleClang), Windows (MSVC x64), and Windows (MinGW-w64).

---

## 2. Dependency Graph

```text
               SC-005 (Protobuf Pipeline)
               SC-010 (mTLS Transport & Credentials)
               SC-011 (Persistence Infrastructure: Postgres & MinIO)
               SC-012 (Common Configuration Model)
               SC-013 (Health & Readiness Contracts)
                          │
                          ▼
                     FILES-001-T01
            (Protobuf & gRPC Contract Baseline)
                          │
          ┌───────────────┴───────────────┐
          │                               │
          ▼                               ▼
     FILES-001-T02                   FILES-001-T03
  (PostgreSQL Connection Pool)    (MinIO S3 Client Foundation)
          │                               │
          └───────────────┬───────────────┘
                          │
                          ▼
                     FILES-001-T04
             (Modular Files Service Architecture &
              gRPC mTLS Server Implementation)
                          │
                          ▼
                     FILES-001-T05
             (Dual-Dependency Health Evaluator &
              Bounded Graceful Shutdown)
                          │
                          ▼
                     FILES-001-T06
             (Unit & Integration Test Suite &
              Verification Harness)
```

---

## 3. Implementation Tickets for Developer Louis

### FILES-001-T01 — Protobuf & gRPC Contract Baseline (`files.proto`)

1. **Ticket ID**: `FILES-001-T01`
2. **Title**: Protobuf & gRPC Contract Baseline for Files Service
3. **Objective**: Define the canonical Protobuf schema and gRPC service definitions (`proto/securecloud/files/v1/files.proto`), register in CMake, and verify clean code generation across all supported compilers.
4. **Architectural Purpose**: Establishes the strongly typed IPC contract between API Gateway and Files Service as mandated by ADR-004 (gRPC IPC) and `docs/design/files-design.md` Sections 6.2 and 6.27.
5. **Scope**:
   - Create `proto/securecloud/files/v1/files.proto`.
   - Register in `proto/CMakeLists.txt`.
   - Define 7 authoritative RPC methods on `FilesService`:
     - `CreateFileUpload(CreateFileUploadRequest) returns (CreateFileUploadResponse)`
     - `UploadChunk(UploadChunkRequest) returns (UploadChunkResponse)`
     - `FinalizeFileUpload(FinalizeFileUploadRequest) returns (FinalizeFileUploadResponse)`
     - `GetFileMetadata(GetFileMetadataRequest) returns (GetFileMetadataResponse)`
     - `DownloadChunk(DownloadChunkRequest) returns (DownloadChunkResponse)`
     - `CancelFileUpload(CancelFileUploadRequest) returns (CancelFileUploadResponse)`
     - `DeleteFile(DeleteFileRequest) returns (DeleteFileResponse)`
   - Define status enums:
     - `FileLifecycleState` (`FILE_LIFECYCLE_STATE_UNSPECIFIED = 0`, `CREATED`, `UPLOADING`, `FINALIZING`, `AVAILABLE`, `EXPIRED`, `DELETED`, `FAILED`).
     - `TransferStatus` (`TRANSFER_STATUS_UNSPECIFIED = 0`, `PENDING`, `IN_PROGRESS`, `COMPLETED`, `CANCELLED`, `FAILED`).
   - Define request and response message schemas using canonical UUID strings and `bytes` for encrypted binary chunks.
   - Extend `tests/unit/proto_smoke_test.cpp` to verify compilation and linkage of generated headers.
6. **Explicit Out-of-Scope**: Implementing chunk storage, streaming handlers, or S3 uploads.
7. **Dependencies**: Upstream SC-005. Downstream FILES-001-T04.
8. **Exact Repository Starting Point**: `proto/CMakeLists.txt`, `cmake/modules/SecureCloudProtobuf.cmake`.
9. **Files/Directories to Inspect**: `docs/design/files-design.md` (6.3, 6.19, 6.27), `docs/data-model/04-files-data-model.md` (4.3, 4.4, 4.7).
10. **Files/Directories to Create**: `proto/securecloud/files/v1/files.proto`.
11. **Files/Directories That May Be Modified**: `proto/CMakeLists.txt`, `tests/unit/proto_smoke_test.cpp`.
12. **Files/Directories That MUST NOT Be Modified**: `proto/securecloud/common/v1/health.proto`, `src/*`.
13. **Detailed Implementation Requirements**:
    - Package: `securecloud.files.v1`, `syntax = "proto3"`, `cc_generic_services = false`.
    - Identifier fields (`file_id`, `upload_id`, `owner_user_id`, `owner_device_id`, `conversation_id`) use wire-format `string` representing canonical 36-character hyphenated UUIDv7 strings.
    - Encrypted binary chunks (`encrypted_data`) must use `bytes`.
    - Chunk metadata must include `chunk_index` (uint32), `chunk_size_bytes` (uint32), and `ciphertext_sha256` (bytes/string) for integrity checks.
    - Full service declaration:
      ```protobuf
      service FilesService {
        rpc CreateFileUpload(CreateFileUploadRequest) returns (CreateFileUploadResponse);
        rpc UploadChunk(UploadChunkRequest) returns (UploadChunkResponse);
        rpc FinalizeFileUpload(FinalizeFileUploadRequest) returns (FinalizeFileUploadResponse);
        rpc GetFileMetadata(GetFileMetadataRequest) returns (GetFileMetadataResponse);
        rpc DownloadChunk(DownloadChunkRequest) returns (DownloadChunkResponse);
        rpc CancelFileUpload(CancelFileUploadRequest) returns (CancelFileUploadResponse);
        rpc DeleteFile(DeleteFileRequest) returns (DeleteFileResponse);
      }
      ```
14. **Testing Requirements**: Extend `tests/unit/proto_smoke_test.cpp` to instantiate `CreateFileUploadRequest` and verify default fields.
15. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_proto_smoke_test
    ctest --preset dev-debug -R proto_smoke_test --output-on-failure
    ```
16. **Acceptance Criteria**: Protobuf targets generate cleanly and link without warnings across macOS, MSVC, and MinGW.

---

### FILES-001-T02 — PostgreSQL Connection Pool & Bounded Database Client Foundation

1. **Ticket ID**: `FILES-001-T02`
2. **Title**: PostgreSQL Connection Pool & Bounded Database Client Foundation
3. **Objective**: Implement thread-safe bounded `FilesDbConnectionPool` and RAII `PooledConnection` in `src/files/db/`, providing connection leasing, acquisition timeouts, and an independent health ping connection for `securecloud_files`.
4. **Architectural Purpose**: Establishes safe, concurrent, and bounded access to the Files PostgreSQL database, preventing connection pool starvation and socket leaks (ADR-005, ADR-010).
5. **Scope**:
   - Create `src/files/db/files_connection_pool.{hpp,cpp}` and `src/files/db/pooled_connection.hpp`.
   - Implement `ConnectionPoolConfig` (`min_connections = 2`, `max_connections = 10`, `acquire_timeout = 500ms`, `connect_timeout = 1s`, `statement_timeout = 250ms`).
   - Implement 3-state lifecycle (`OPEN` -> `DRAINING` -> `CLOSED`).
   - Implement RAII move-only lease (`PooledConnection`).
   - Implement dedicated persistent health connection for `ping()` that is immune to application pool exhaustion.
   - Create unit tests in `tests/unit/files/files_connection_pool_test.cpp`.
6. **Explicit Out-of-Scope**: Writing schema DDL migrations or business tables (owned by FILE-002).
7. **Dependencies**: Upstream SC-010, SC-012, `securecloud::libpqxx`. Downstream FILES-001-T04, FILES-001-T05.
8. **Exact Repository Starting Point**: `src/files/files_config.hpp`, `src/files/CMakeLists.txt`.
9. **Files/Directories to Inspect**: `src/files/files_config.hpp`, `src/auth/db/postgres_connection_pool.hpp` (if available, pattern reuse).
10. **Files/Directories to Create**:
    - `src/files/db/files_connection_pool.hpp`
    - `src/files/db/files_connection_pool.cpp`
    - `src/files/db/pooled_connection.hpp`
    - `tests/unit/files/files_connection_pool_test.cpp`
11. **Files/Directories That May Be Modified**: `src/files/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `deploy/compose/*`.
13. **Detailed Implementation Requirements**:
    - **Port 5432 Invariant**: In dev environment, connection string resolves `127.0.0.1:5433` (never host `5432`).
    - **Dedicated Health Connection**: Dedicated connection executes `SELECT 1` within 250ms statement timeout.
    - **Move-Only RAII Lease**: `PooledConnection` returns connection to pool upon destruction.
    - **Safe Credential Handling**: Uses `FilesConfig::db_password` (`SecretString`). Connection strings are cleared from heap after initialization.
14. **Testing Requirements**:
    - Unit tests validate pool queue bounding, acquire timeouts, thread contention, and clean shutdown.
15. **Acceptance Criteria**: Bounded pool with acquisition timeout, safe RAII lease ownership, non-blocking ping, full unit test pass.

---

### FILES-001-T03 — MinIO S3 Object Storage Client Wrapper & Bucket Reachability Probe

1. **Ticket ID**: `FILES-001-T03`
2. **Title**: MinIO S3 Object Storage Client Wrapper & Bucket Reachability Probe
3. **Objective**: Implement a lightweight, non-blocking S3 client wrapper in `src/files/storage/s3_client.{hpp,cpp}` supporting bucket reachability checks, object existence verification (`HEAD`), and AWS SigV4 authorization for MinIO.
4. **Architectural Purpose**: Establishes the storage transport layer to MinIO for encrypted binary objects while maintaining bounded memory and predictable timeouts (ADR-005, Files Design 6.17).
5. **Scope**:
   - Create `src/files/storage/s3_client.{hpp,cpp}`:
     - Encapsulates HTTP communication with MinIO S3 endpoint (`FilesConfig::s3_endpoint`).
     - Implements AWS SigV4 request signing (HMAC-SHA256) for S3 REST API.
     - Implements `ping_bucket(timeout_ms)`: Issues `HEAD /<bucket>` to verify bucket existence and credentials.
     - Implements `object_exists(object_key)`: Issues `HEAD /<bucket>/<object_key>`.
   - Create `src/files/storage/s3_exceptions.hpp`:
     - `S3ClientException`, `S3BucketNotFoundException`, `S3AuthenticationException`.
   - Provide unit tests in `tests/unit/files/s3_client_test.cpp`.
6. **Explicit Out-of-Scope**: Multipart chunk uploads, large file streaming (FILE-003, FILE-005).
7. **Dependencies**: Upstream SC-011, SC-012, `securecloud::httplib`, OpenSSL. Downstream FILES-001-T04, FILES-001-T05.
8. **Exact Repository Starting Point**: `src/files/files_config.hpp`, `src/files/CMakeLists.txt`.
9. **Files/Directories to Create**:
    - `src/files/storage/s3_client.hpp`
    - `src/files/storage/s3_client.cpp`
    - `src/files/storage/s3_exceptions.hpp`
    - `tests/unit/files/s3_client_test.cpp`
10. **Files/Directories That May Be Modified**: `src/files/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Connects to `FilesConfig::s3_endpoint` (default `http://minio:9000` in container, `http://127.0.0.1:9000` on host).
    - `s3_access_key` and `s3_secret_key` (`SecretString`) used to sign headers (`Authorization: AWS4-HMAC-SHA256 ...`).
    - `ping_bucket()` must complete within bounded deadline (default 1000ms) and return boolean `true`/`false` without throwing unhandled exceptions.
    - Zero plaintext logging: S3 secret key and authorization signature headers are never logged to stdout/stderr.
13. **Testing Requirements**:
    - Mock HTTP server validates SigV4 signature formatting and date headers.
    - 200 OK on HEAD returns `true`.
    - 404 Not Found returns `false`.
    - 403 Forbidden throws `S3AuthenticationException`.
14. **Acceptance Criteria**: S3 client signs requests correctly; `ping_bucket` verifies MinIO connectivity.

---

### FILES-001-T04 — Modular Files Service Architecture & gRPC mTLS Server Implementation

1. **Ticket ID**: `FILES-001-T04`
2. **Title**: Modular Files Service Architecture & gRPC mTLS Server Implementation
3. **Objective**: Implement `FilesServiceImpl` registering all 7 proto RPCs returning deterministic `UNIMPLEMENTED`, integrate modular architecture, structured secret-safe logging, and bind to mTLS server with mutual authentication.
4. **Architectural Purpose**: Establishes the core service skeleton and secure IPC transport for encrypted file transfer coordination (ADR-001, ADR-004, Files Design 6.2, 6.27).
5. **Scope**:
   - Create `src/files/service/files_service_impl.{hpp,cpp}`:
     - Implements `securecloud::files::v1::FilesService::Service` interface.
     - Registers all 7 RPCs with deterministic `grpc::StatusCode::UNIMPLEMENTED`.
     - Structures forward declarations for sub-components (`UploadSessionManager`, `DownloadManager`, `StorageEngine`, `MetadataManager`).
   - Extract peer client certificate SAN using `securecloud::common::security::extract_peer_service_identity(*context->auth_context())`.
   - Implement secret-safe operational logging (`[SecureCloud] [files] <event>`).
   - Wire server startup and signal handling in `src/files/main.cpp`.
   - Provide unit tests in `tests/unit/files/files_service_impl_test.cpp`.
6. **Explicit Out-of-Scope**: Storing chunks, assembling files, or writing metadata.
7. **Dependencies**: Upstream FILES-001-T01, SC-010, SC-012. Downstream FILES-001-T05, FILES-001-T06.
8. **Exact Repository Starting Point**: `src/files/main.cpp`, `src/files/CMakeLists.txt`.
9. **Files/Directories to Create**:
    - `src/files/service/files_service_impl.hpp`
    - `src/files/service/files_service_impl.cpp`
    - `tests/unit/files/files_service_impl_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/files/CMakeLists.txt`
    - `src/files/main.cpp`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Implement all 7 virtual methods from generated `FilesService::Service`.
    - Peer certificate SAN extraction: Ensure only authorized clients (Gateway: `DNS:gateway`) can invoke file operations.
    - Operational logging: Log RPC method name, duration, peer identity, and status code. Strict prohibition against logging ciphertext bytes, file encryption keys, or S3 tokens.
    - Server credentials require mutual TLS (`GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`).
13. **Testing Requirements**:
    - In-process gRPC channel test verifies all 7 methods return `UNIMPLEMENTED` with descriptive message `"FilesService method not implemented in FILES-001 skeleton"`.
14. **Acceptance Criteria**: All 7 RPCs registered and callable; mTLS handshake strictly enforced.

---

### FILES-001-T05 — Dual-Dependency Health/Readiness Evaluator & Bounded Graceful Shutdown

1. **Ticket ID**: `FILES-001-T05`
2. **Title**: Dual-Dependency Health/Readiness Evaluator & Bounded Graceful Shutdown
3. **Objective**: Implement `FilesHealthEvaluator` monitoring both PostgreSQL 17 and MinIO S3 reachability, dynamically driving `HealthStatusManager` readiness state, and implement deterministic graceful shutdown.
4. **Architectural Purpose**: Guarantees truthful operational readiness reporting to container orchestrators and Gateway routing layers, ensuring traffic is never routed to a partially degraded Files instance (ADR-009, SC-013).
5. **Scope**:
   - Create `src/files/health/files_health_evaluator.{hpp,cpp}`:
     - Coordinates periodic health evaluations across PostgreSQL pool ping and MinIO S3 bucket ping.
     - Sets readiness `SERVING` if and only if **both** PostgreSQL and MinIO are healthy.
     - Sets readiness `NOT_SERVING` if either dependency fails, with detailed diagnostic logging.
     - Liveness remains `SERVING` unless shutdown is initiated.
   - Implement graceful shutdown sequence:
     1. Signal `set_shutting_down(true)` -> immediately flips readiness to `NOT_SERVING`.
     2. Stop accepting new gRPC calls (`server->Shutdown(deadline)`).
     3. Drain active upload/download leases (bounded 5s).
     4. Close MinIO client connections.
     5. Drain and close PostgreSQL connection pool.
   - Provide unit tests in `tests/unit/files/files_health_evaluator_test.cpp`.
6. **Explicit Out-of-Scope**: Altering common health service contracts.
7. **Dependencies**: Upstream FILES-001-T02, FILES-001-T03, FILES-001-T04, SC-013. Downstream FILES-001-T06.
8. **Exact Repository Starting Point**: `src/files/main.cpp`, `src/common/include/securecloud/health/health_status_manager.hpp`.
9. **Files/Directories to Create**:
    - `src/files/health/files_health_evaluator.hpp`
    - `src/files/health/files_health_evaluator.cpp`
    - `tests/unit/files/files_health_evaluator_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/files/CMakeLists.txt`
    - `src/files/main.cpp`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Health evaluation must not block the gRPC thread. Use background periodic check or cached status with debounce.
    - If PostgreSQL ping fails -> log warning, set readiness `NOT_SERVING`.
    - If MinIO bucket ping fails -> log warning, set readiness `NOT_SERVING`.
    - When both recover -> log info, restore readiness `SERVING`.
13. **Testing Requirements**:
    - Mock DB and Mock S3 probes validate all 4 state permutations:
      - (DB Healthy, S3 Healthy) -> `SERVING`
      - (DB Degraded, S3 Healthy) -> `NOT_SERVING`
      - (DB Healthy, S3 Degraded) -> `NOT_SERVING`
      - (DB Degraded, S3 Degraded) -> `NOT_SERVING`
14. **Acceptance Criteria**: Dual-dependency evaluation truthfully reflects compound health; clean shutdown without thread leaks.

---

### FILES-001-T06 — Unit & Integration Test Suite & Verification Harness

1. **Ticket ID**: `FILES-001-T06`
2. **Title**: Unit & Integration Test Suite & Verification Harness
3. **Objective**: Build a comprehensive integration test suite running against containerized PostgreSQL 17 (`127.0.0.1:5433`) and MinIO S3 (`127.0.0.1:9000`), validating mTLS startup, dual-dependency readiness degradation, RPC baseline behavior, and deterministic teardown.
4. **Architectural Purpose**: Provides automated end-to-end proof of correctness for the Files Service foundation before developing Phase 5 storage and streaming features (SC-014, SC-015).
5. **Scope**:
   - Create `tests/integration/files_integration_test.cpp`:
     - Test 1: Service starts with valid mTLS certificates (`files.crt`, `files.key`, `ca.crt`).
     - Test 2: In-process client with Gateway identity (`gateway.crt`) establishes mTLS channel.
     - Test 3: Unauthenticated or untrusted clients are rejected at TLS handshake.
     - Test 4: All 7 RPCs return deterministic `grpc::StatusCode::UNIMPLEMENTED`.
     - Test 5: Readiness check returns `SERVING` when PostgreSQL (5433) and MinIO (9000) are reachable.
     - Test 6: Readiness degrades when MinIO or PostgreSQL port is unreachable.
     - Test 7: Observational Guard check: Asserts test never connects to host port 5432.
     - Test 8: Deterministic graceful shutdown completes without memory leaks or deadlocks.
   - Register target `securecloud_files_integration_test` in `tests/integration/CMakeLists.txt`.
   - Link `GTest::gtest` and provide custom `main()` using Win32 `::TerminateProcess` on Windows.
6. **Explicit Out-of-Scope**: Testing business file uploads or encryption algorithms.
7. **Dependencies**: Upstream FILES-001-T01 through FILES-001-T05, SC-014, SC-015. Downstream FILE-002.
8. **Exact Repository Starting Point**: `tests/integration/CMakeLists.txt`, `src/files/`.
9. **Files/Directories to Inspect**: `tests/integration/health_integration_test.cpp`, `tests/integration/mtls_integration_test.cpp`.
10. **Files/Directories to Create**:
    - `tests/integration/files_integration_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `tests/integration/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `deploy/compose/*`.
13. **Detailed Implementation Requirements**:
    - **Port 5432 Assertion**:
      ```cpp
      ASSERT_NE(config.db_port, 5432) << "CRITICAL: Tests must NEVER connect to host PostgreSQL on port 5432!";
      EXPECT_EQ(config.db_port, 5433);
      ```
    - **Deterministic Process Teardown**:
      ```cpp
      int main(int argc, char** argv) {
          ::testing::InitGoogleTest(&argc, argv);
          int result = RUN_ALL_TESTS();
      #ifdef _WIN32
          std::fflush(nullptr);
          ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
      #else
          return result;
      #endif
      }
      ```
14. **Validation Commands**:
    ```bash
    python3 scripts/verify-local.py
    ctest --preset dev-debug -R files_integration_test --output-on-failure
    ```
15. **Acceptance Criteria**: 100% test pass; dual-dependency readiness verified against live containers; zero exit latency on Windows/MinGW.
16. **Definition of Done**: All integration scenarios pass in local and CI verification pipelines.

---

## 4. Git Commit Hygiene & Traceability Plan for Louis

Louis must commit work iteratively following conventional commit conventions:

1. `build(deps): define files.proto IPC contract baseline (FILES-001-T01)`
2. `feat(files): implement PostgreSQL connection pool foundation (FILES-001-T02)`
3. `feat(files): implement MinIO S3 client wrapper and bucket ping (FILES-001-T03)`
4. `feat(files): implement modular FilesService skeleton with mTLS (FILES-001-T04)`
5. `feat(files): implement dual-dependency health evaluator and shutdown (FILES-001-T05)`
6. `test(files): add Files integration test suite and verification harness (FILES-001-T06)`

---

## 5. Developer Louis PR Checklist & Gatekeeper Review Gate

Before submitting the PR for Sergey's review:

- [ ] All 7 proto RPCs in `files.proto` return `UNIMPLEMENTED`.
- [ ] No plaintext file handling, decryption logic, or user keys exist in `src/files`.
- [ ] Host PostgreSQL on port `5432` has not been contacted or modified.
- [ ] Files PostgreSQL connects to `127.0.0.1:5433` (`securecloud_files`).
- [ ] MinIO S3 connects to `127.0.0.1:9000` (`securecloud-files-encrypted`).
- [ ] Readiness degrades truthfully if EITHER PostgreSQL or MinIO is down.
- [ ] Server enforces mutual TLS with peer SAN verification (`DNS:gateway`).
- [ ] Integration tests use ephemeral ports and terminate with `TerminateProcess` on Windows.
- [ ] `python3 scripts/verify-local.py` passes all 5 stages in < 30 seconds.
