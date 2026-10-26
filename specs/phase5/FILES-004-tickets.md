# FILES-004 — Implement File Metadata and Lifecycle
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: FILES-004 (or FILE-004)  
**Milestone**: M5 — Secure Files  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-004** implements the authoritative **File Metadata & Lifecycle Management Engine** for the **SecureCloud Files Service** (`securecloud-files`). Building directly upon the PostgreSQL 17 persistence foundation established in **FILES-002** and the MinIO S3 object storage abstraction developed in **FILES-003**, this card delivers the domain service layer, metadata validation engine, ownership and authorization enforcement, lifecycle state machine, immutable versioning semantics, expiration management, and gRPC RPC integration.

### Core Trello Card Requirements
1. **Approved File Lifecycle State Machine**:
   - Primary Path: `CREATED → UPLOADING → FINALIZING → AVAILABLE`
   - Failure Paths: `CREATED → FAILED`, `UPLOADING → FAILED`, `FINALIZING → FAILED`
   - Expiration & Deletion Paths: `CREATED → DELETED`, `UPLOADING → EXPIRED / DELETED`, `AVAILABLE → EXPIRED / DELETED`, `EXPIRED → DELETED`
   - Terminal States: `FAILED`, `DELETED` (no outward transitions permitted).
2. **Domain Operations**:
   - Create logical file (`create_file`)
   - Create file version (`create_file_version`)
   - Retrieve operational & client-encrypted metadata (`get_file_metadata`)
   - Enforce lifecycle transitions with optimistic locking (`transition_file_status`)
   - Ownership and tenant isolation validation
   - Expiration evaluation and logical deletion
   - Metadata schema & constraint validation
   - State-transition validation
3. **Core Invariant**:
   > **Immutable Completed Versions Invariant**:  
   > Once a file version reaches `AVAILABLE`, its encrypted object is **strictly immutable**.  
   > A new version means a **new encrypted object / version** in S3 (`objects/{file_id}/{version_number}`), not mutation of the existing completed object.

---

### Key Invariants & Architectural Boundaries

1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design 6.1, 6.26)**:
   - The Files Service operates **exclusively on pre-encrypted file ciphertext**. It must NEVER receive, decrypt, compress, inspect, or possess:
     - Plaintext file content.
     - User or device private cryptographic keys.
     - Plaintext file-encryption keys.
     - Plaintext filenames or MIME types.
   - Client-side metadata (original filename, MIME type) is stored strictly as pre-encrypted byte vectors (`encrypted_filename`, `encrypted_mime_type`, `metadata_nonce`, `metadata_tag`) in PostgreSQL table `encrypted_file_metadata`.

2. **Immutable Completed Versions Invariant (Files Design 6.3, Initial Backlog Item FILE-004)**:
   - When a version transition reaches `AVAILABLE`, its MinIO object key and checksum become permanently immutable.
   - In-place mutation, overwriting, or truncation of an existing `AVAILABLE` object is strictly prohibited.
   - Updates to a file create a new version (`version_number = N + 1`) with an independent MinIO object key (`objects/{file_id}/{new_version}`) and a new upload transfer lifecycle.

3. **Authoritative Persistence Separation (Files Design 6.17)**:
   - **PostgreSQL 17** (`securecloud_files`): Authoritative source of truth for file metadata, version records, lifecycle states, transfer sessions, access control policies, and transactional outbox.
   - **MinIO S3** (`securecloud-files-encrypted`): Storage engine for encrypted binary objects. Object existence in MinIO does **not** make a file downloadable until PostgreSQL marks its state as `AVAILABLE`.

4. **Atomic Outbox & Domain Event Consistency (ADR-004, Files Design 6.22)**:
   - All lifecycle transitions that require cross-service awareness (`FILE_CREATED`, `FILE_VERSION_CREATED`, `FILE_AVAILABLE`, `FILE_EXPIRED`, `FILE_DELETED`) must be written to `files_outbox` in the **exact same PostgreSQL transaction** (`pqxx::work`) as the domain row update.
   - If the transaction aborts, zero outbox events or orphaned state transitions remain.

5. **Ownership & Tenant Authorization Invariant**:
   - Every file record is permanently bound to `owner_user_id` and `owner_device_id` (UUIDv7).
   - Only the owning user or callers possessing an active grant in `file_access` are permitted to inspect metadata or initiate state modifications.
   - Peer authentication identity extracted from mTLS / gRPC request context is validated on every operation.

6. **M1 Non-Regression Invariant**:
   - Zero compilation warnings or errors across macOS (AppleClang), Windows (MSVC x64), and Windows (MinGW-w64).
   - Host PostgreSQL 14 on port 5432 remains strictly guarded. SecureCloud connects strictly to `127.0.0.1:5433`.

---

## 2. Component Architecture & Lifecycle State Machine

### 2.1 File Lifecycle State Machine

```text
                 ┌──────────────────────────────────────────┐
                 │                 CREATED                  │
                 └──────┬──────────────┬─────────────┬──────┘
                        │              │             │
              upload    │        error │     abort / │
              starts    ▼              │     cancel  │
                 ┌──────────────┐      │             │
                 │  UPLOADING   │      │             │
                 └──────┬──┬────┘      │             │
                        │  │           │             │
       all chunks recv  │  │ error     │             │
       & integrity ok   ▼  │           │             │
                 ┌─────────▼────┐      │             │
                 │  FINALIZING  │      │             │
                 └──────┬──┬────┘      │             │
                        │  │ error     │             │
    hash verified &     │  │           │             │
    outbox committed    ▼  ▼           ▼             │
                 ┌──────────────┐   ┌────────────┐   │
                 │  AVAILABLE   │   │   FAILED   │◄──┘ (terminal)
                 └──────┬───────┘   └────────────┘
                        │
            ┌───────────┴───────────┐
            │                       │
     retention period        user / admin
         exceeded               deletion
            │                       │
            ▼                       ▼
     ┌──────────────┐        ┌──────────────┐
     │   EXPIRED    │───────►│   DELETED    │ (terminal)
     └──────────────┘  purge └──────────────┘
```

### Transition Matrix

| From State | Allowed Target States | Trigger Condition |
| :--- | :--- | :--- |
| **`CREATED`** | `UPLOADING` | Client initiates first chunk upload session. |
| | `FAILED` | Initialization failure, invalid metadata, or unrecoverable error. |
| | `DELETED` | Client or owner aborts/deletes before chunk transfer begins. |
| **`UPLOADING`** | `FINALIZING` | All expected chunks successfully stored and verified. |
| | `FAILED` | Chunk corruption, timeout, or terminal storage failure. |
| | `EXPIRED` | Upload session retention deadline reached prior to completion. |
| | `DELETED` | User cancels or deletes transfer session while in-progress. |
| **`FINALIZING`** | `AVAILABLE` | Final ciphertext SHA-256 matches expectation; outbox event committed. |
| | `FAILED` | Ciphertext integrity hash mismatch or outbox persistence failure. |
| **`AVAILABLE`** | `EXPIRED` | File retention timestamp (`retention_until`) exceeded. |
| | `DELETED` | Logical deletion requested by owner or authorized grantee. |
| **`EXPIRED`** | `DELETED` | Cleanup worker or owner marks expired file for physical purge. |
| **`FAILED`** | *(None)* | Terminal error state. No further transitions permitted. |
| **`DELETED`** | *(None)* | Terminal deletion state. No further transitions permitted. |

---

### 2.2 Component Architecture & Domain Flow

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                         SecureCloud Files Service                      │
 │                                                                        │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │                         FilesServiceImpl                         │  │
 │  │  - mTLS Peer Authorization & RpcScopeLogger                      │  │
 │  │  - gRPC RPC Handlers:                                            │  │
 │  │      CreateFileUpload, GetFileMetadata, DeleteFile,              │  │
 │  │      FinalizeFileUpload                                          │  │
 │  └──────────────────────────────┬───────────────────────────────────┘  │
 │                                 │                                      │
 │  ┌──────────────────────────────▼───────────────────────────────────┐  │
 │  │                   Metadata & Lifecycle Engine                    │  │
 │  │  ┌───────────────────────────┐   ┌────────────────────────────┐  │  │
 │  │  │   MetadataValidator       │   │  LifecycleStateMachine     │  │  │
 │  │  │   - UUIDv7 constraints    │   │  - Transition validity     │  │  │
 │  │  │   - Crypto metadata rules │   │  - Optimistic concurrency  │  │  │
 │  │  │   - Size & chunk bounds   │   │  - Terminal state guards   │  │  │
 │  │  └─────────────┬─────────────┘   └─────────────┬──────────────┘  │  │
 │  │                └──────────────┬────────────────┘                 │  │
 │  │                               ▼                                  │  │
 │  │                   FileLifecycleService                           │  │
 │  │  - create_file (FileEntity + EncryptedFileMetadata + Outbox)     │  │
 │  │  - create_file_version (Version N+1, Immutable snapshot)         │  │
 │  │  - transition_lifecycle (State mutation + Outbox atomicity)      │  │
 │  │  - get_metadata (Aggregated operational + version info)          │  │
 │  │  - check_ownership_and_access (Tenant isolation)                 │  │
 │  │  - evaluate_expirations (Retention expiration scanner)           │  │
 │  └──────────────────────────────┬───────────────────────────────────┘  │
 │                                 │                                      │
 │  ┌──────────────────────────────▼───────────────────────────────────┐  │
 │  │                       Repository Layer                           │  │
 │  │  - FileRepository (files, encrypted_file_metadata)               │  │
 │  │  - FileVersionRepository (file_versions - immutable)             │  │
 │  │  - FileAccessRepository (file_access grants)                     │  │
 │  │  - FilesOutboxRepository (files_outbox atomic events)            │  │
 │  └──────────────────────────────┬───────────────────────────────────┘  │
 └─────────────────────────────────┼──────────────────────────────────────┘
                                   │ pqxx (TCP 5433)
                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      PostgreSQL 17 Database                            │
 │                        (securecloud_files)                             │
 │   files, encrypted_file_metadata, file_versions, file_access,         │
 │   files_outbox                                                         │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Dependency Graph & Implementation Sequence

```text
                                FILES-004-T01
                    (Domain Lifecycle State Machine &
                          Transition Validator)
                                   │
                                   ▼
                                FILES-004-T02
                    (Metadata Validation Engine & DTOs)
                                   │
                                   ▼
                                FILES-004-T03
                    (FileLifecycleService Domain Layer &
                       Immutable Versioning Engine)
                                   │
                                   ▼
                                FILES-004-T04
                    (FilesServiceImpl gRPC Wiring & RPCs)
                                   │
                                   ▼
                                FILES-004-T05
                    (Comprehensive Unit Test Suite & Mocks)
                                   │
                                   ▼
                                FILES-004-T06
                    (Live PostgreSQL Integration Test Suite &
                               Card Sign-Off)
```

---

## 4. Implementation Tickets for Developer Louis

### FILES-004-T01 — Domain Lifecycle State Machine & Transition Validator

1. **Ticket ID**: `FILES-004-T01`
2. **Title**: Domain Lifecycle State Machine & Transition Validator
3. **Objective**: Implement the authoritative lifecycle state machine functions, transition matrix, and conversion helpers between domain `FileStatus` and protobuf `v1::FileLifecycleState`.
4. **Architectural Purpose**: Guarantees that only legally approved state progressions can occur across the system, preventing inconsistent states such as reviving deleted/failed files or bypassing the upload/finalization pipeline (Files Design 6.3, 6.19).
5. **Scope**:
   - Create `src/files/domain/lifecycle_state_machine.hpp` and `src/files/domain/lifecycle_state_machine.cpp`:
     - Reuse `enum class FileStatus` declared in `src/files/domain/file_entity.hpp` (`#include "files/domain/file_entity.hpp"` to avoid duplicate type definitions across compilation units).
     - Provide bidirectional conversion functions:
       ```cpp
       std::string_view to_string(FileStatus status) noexcept;
       std::optional<FileStatus> file_status_from_string(std::string_view str) noexcept;
       v1::FileLifecycleState to_proto(FileStatus status) noexcept;
       FileStatus from_proto(v1::FileLifecycleState proto_state);
       ```
     - Implement authoritative state transition validation:
       ```cpp
       bool is_valid_state_transition(FileStatus from, FileStatus to) noexcept;
       bool is_terminal_state(FileStatus status) noexcept;
       void assert_valid_state_transition(FileStatus from, FileStatus to);
       ```
     - Define typed exception:
       ```cpp
       class InvalidLifecycleTransitionException : public std::runtime_error {
       public:
           InvalidLifecycleTransitionException(FileStatus from, FileStatus to, std::string_view detail = "");
           FileStatus from() const noexcept;
           FileStatus to() const noexcept;
       };
       ```
   - Deduplicate repository code: Remove the ad-hoc local declaration and definition of `is_valid_state_transition` from `src/files/repository/file_repository.{hpp,cpp}` and replace it with `#include "files/domain/lifecycle_state_machine.hpp"` to ensure a single authoritative ODR definition.
   - Implement unit test `tests/unit/files/lifecycle_state_machine_test.cpp` verifying all 49 state combinations (7x7) against the transition matrix.
6. **Explicit Out-of-Scope**: Database persistence (handled in T03).
7. **Dependencies**: Upstream FILES-002-T02. Downstream FILES-004-T03.
8. **Files to Create/Modify**:
   - `src/files/domain/lifecycle_state_machine.hpp` (New)
   - `src/files/domain/lifecycle_state_machine.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `src/files/repository/file_repository.hpp` (Modify to include `domain/lifecycle_state_machine.hpp` and remove redundant function prototype)
   - `src/files/repository/file_repository.cpp` (Modify to delegate to `lifecycle_state_machine`)
   - `tests/unit/files/lifecycle_state_machine_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - All legal transitions evaluate to `true` (see Section 2.1 matrix).
   - Illegal transitions evaluate to `false` and `assert_valid_state_transition` throws `InvalidLifecycleTransitionException`.
   - `Deleted` and `Failed` are strictly recognized as terminal states with zero valid outward transitions.
   - 100% test pass rate across GCC, Clang, and MSVC.

---

### FILES-004-T02 — Metadata Validation Engine & Domain DTOs

1. **Ticket ID**: `FILES-004-T02`
2. **Title**: Metadata Validation Engine & Domain DTOs
3. **Objective**: Implement strong input validation for file creation requests, client-side encrypted metadata payloads, version parameters, ownership claims, and retention timestamps.
4. **Architectural Purpose**: Enforces fail-fast validation at the service boundary so that malformed UUIDs, invalid chunk counts, oversized payloads, non-whitelisted encryption algorithms, and missing cryptographic nonces/tags are rejected before touching the database or storage (Zero-Plaintext Invariant, Files Design 6.13, 6.14).
5. **Scope**:
   - Create `src/files/domain/metadata_validator.hpp` and `src/files/domain/metadata_validator.cpp`:
     - Define validation limits and constants:
       ```cpp
       inline constexpr uint64_t k_max_file_size_bytes = 5ULL * 1024ULL * 1024ULL * 1024ULL; // 5 GiB max
       inline constexpr uint32_t k_standard_chunk_size = 4U * 1024U * 1024U;                  // 4 MiB
       inline constexpr size_t k_xchacha20_nonce_bytes = 24;
       inline constexpr size_t k_poly1305_tag_bytes = 16;
       inline constexpr std::string_view k_approved_encryption_algorithm = "XChaCha20-Poly1305";
       ```
     - Provide DTOs for service requests:
       ```cpp
       struct CreateFileRequestDto {
           std::string file_id;
           std::string owner_user_id;
           std::string owner_device_id;
           std::optional<std::string> conversation_id;
           uint64_t encrypted_size_bytes{0};
           uint32_t expected_chunk_count{0};
           std::string encryption_algorithm{k_approved_encryption_algorithm};
           std::vector<uint8_t> encrypted_filename;
           std::optional<std::vector<uint8_t>> encrypted_mime_type;
           std::vector<uint8_t> metadata_nonce;
           std::vector<uint8_t> metadata_tag;
           std::string client_encryption_metadata_json;
           std::optional<std::chrono::system_clock::time_point> retention_until;
       };

       struct CreateFileVersionRequestDto {
           std::string file_id;
           int32_t version_number{1};
           uint64_t encrypted_size_bytes{0};
           std::string minio_object_key;
           std::string checksum_sha256;
       };
       ```
     - Implement validation functions:
       ```cpp
       struct ValidationResult {
           bool is_valid{true};
           std::string error_message;
       };

       ValidationResult validate_create_file_request(const CreateFileRequestDto& dto,
       ValidationResult validate_create_file_request(const CreateFileRequestDto& dto,
                                                     std::chrono::system_clock::time_point now);
       ValidationResult validate_create_version_request(const CreateFileVersionRequestDto& dto);
       ValidationResult unpack_client_crypto_metadata(const std::string& raw_crypto_metadata_bytes,
                                                      CreateFileRequestDto& out_dto);
       bool is_valid_uuid(std::string_view str) noexcept;
       bool is_valid_sha256_hex(std::string_view hex_str) noexcept;
       uint32_t calculate_expected_chunk_count(uint64_t file_size_bytes, uint32_t chunk_size = k_standard_chunk_size);
       ```
   - Validation Rules:
     - `file_id`, `owner_user_id`, `owner_device_id` must be valid RFC 4122 / UUIDv7 strings.
     - `encrypted_size_bytes` must be > 0 and <= 5 GiB.
     - `expected_chunk_count` must match `calculate_expected_chunk_count(encrypted_size_bytes)`.
     - `encryption_algorithm` must be `"XChaCha20-Poly1305"`.
     - `unpack_client_crypto_metadata`: Parses the Protobuf `bytes client_crypto_metadata` (structured JSON payload with hex-encoded binary fields: `encrypted_filename_hex`, optional `encrypted_mime_type_hex`, `metadata_nonce_hex`, `metadata_tag_hex`, and optional custom client JSON params), decodes them into byte vectors, and validates sizes.
     - `encrypted_filename` must be non-empty (at least 1 byte ciphertext + tag).
     - `metadata_nonce` must be exactly 24 bytes (XChaCha20 nonce requirement).
     - `metadata_tag` must be exactly 16 bytes (Poly1305 authentication tag requirement).
     - `retention_until`, if supplied, must be in the future relative to `now`.
     - `checksum_sha256` must be exactly 64 lowercase/uppercase hex characters.
   - Implement unit test `tests/unit/files/metadata_validator_test.cpp`.
6. **Explicit Out-of-Scope**: Decrypting or inspecting the plaintext filename/content (Zero-Plaintext Invariant).
7. **Dependencies**: Upstream FILES-004-T01. Downstream FILES-004-T03.
8. **Files to Create/Modify**:
   - `src/files/domain/metadata_validator.hpp` (New)
   - `src/files/domain/metadata_validator.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `tests/unit/files/metadata_validator_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - Correctly accepts valid DTOs and calculates expected chunk counts.
   - Rejects invalid UUIDs, oversized files, chunk count mismatches, unsupported algorithms, and bad nonce/tag lengths with descriptive error strings.
   - 100% test pass rate across GCC, Clang, and MSVC.

---

### FILES-004-T03 — FileLifecycleService Domain Layer & Immutable Versioning Engine

1. **Ticket ID**: `FILES-004-T03`
2. **Title**: FileLifecycleService Domain Layer & Immutable Versioning Engine
3. **Objective**: Implement `FileLifecycleService` in `src/files/service/file_lifecycle_service.{hpp,cpp}`, providing transactional operations for creating files, creating immutable versions, retrieving operational metadata, transitioning states, checking ownership, and scanning expirations.
4. **Architectural Purpose**: Encapsulates the domain business logic, coordinating repositories (`FileRepository`, `FileVersionRepository`, `FileAccessRepository`, `FilesOutboxRepository`) and guaranteeing the **Immutable Completed Versions Invariant** and **Outbox Atomicity** (ADR-004, ADR-005, Files Design 6.3, 6.19).
5. **Scope**:
   - Create `src/files/service/file_lifecycle_service.hpp` and `src/files/service/file_lifecycle_service.cpp`:
     ```cpp
     struct FileMetadataSummary {
         FileEntity file;
         EncryptedFileMetadataEntity encrypted_meta;
         std::optional<FileVersionEntity> active_version;
         std::vector<FileVersionEntity> all_versions;
         uint32_t expected_chunk_count{0};
     };

     class FileLifecycleService {
     public:
         explicit FileLifecycleService(
             std::shared_ptr<db::FilesDbConnectionPool> pool,
             std::shared_ptr<FileRepository> file_repo = nullptr,
             std::shared_ptr<FileVersionRepository> version_repo = nullptr,
             std::shared_ptr<FileAccessRepository> access_repo = nullptr,
             std::shared_ptr<FilesOutboxRepository> outbox_repo = nullptr);

         /// Atomically persists a new file in CREATED state with encrypted metadata and an outbox event.
         std::string create_file(const CreateFileRequestDto& dto, std::chrono::system_clock::time_point now);

         /// Creates a new immutable file version (version_number = N+1).
         /// Guarantees that existing AVAILABLE versions remain untouched and immutable.
         FileVersionEntity create_file_version(const CreateFileVersionRequestDto& dto,
                                              const std::string& caller_user_id);

         /// Transitions file lifecycle state using optimistic locking and atomically records the outbox event.
         bool transition_lifecycle(const std::string& file_id,
                                   FileStatus expected_current,
                                   FileStatus new_status,
                                   const std::string& caller_user_id,
                                   const std::string& reason = "");

         /// Retrieves aggregated operational and encrypted metadata for a file.
         std::optional<FileMetadataSummary> get_file_metadata(const std::string& file_id,
                                                             const std::string& caller_user_id);

         /// Validates whether the caller is the file owner or holds an active access grant.
         bool check_ownership_or_access(const std::string& file_id,
                                        const std::string& caller_user_id,
                                        pqxx::work& tx);

         /// Logically deletes a file (AVAILABLE / EXPIRED / CREATED / UPLOADING -> DELETED).
         bool delete_file(const std::string& file_id,
                          const std::string& caller_user_id,
                          const std::string& reason = "");

         /// Scans and transitions files past their retention deadline to EXPIRED.
         size_t evaluate_and_expire_files(std::chrono::system_clock::time_point now, size_t batch_size = 100);
     };
     ```
   - Core Behavioral Invariants to Enforce:
     1. **Immutable Completed Versions Invariant**:
        - Once a file version is created and active with `AVAILABLE` status, its `minio_object_key` and `checksum_sha256` are never modified.
        - Calling `create_file_version` requires an existing file record and automatically calculates next version number (`max_version + 1`).
     2. **Atomic Outbox Events**:
        - `create_file`: writes outbox event `FILE_CREATED`.
        - `create_file_version`: writes outbox event `FILE_VERSION_CREATED`.
        - `transition_lifecycle`:
          - Transition to `AVAILABLE`: writes `FILE_AVAILABLE`.
          - Transition to `FAILED`: writes `FILE_FAILED`.
          - Transition to `EXPIRED`: writes `FILE_EXPIRED`.
          - Transition to `DELETED`: writes `FILE_DELETED`.
     3. **Ownership Checks**:
        - State changes and metadata retrieval verify `file.owner_user_id == caller_user_id` or query `file_access_repo->has_access(file_id, caller_user_id, "READ" / "WRITE")`.
        - Unauthorized calls throw `UnauthorizedFileAccessException`.
     4. **Optimistic Locking**:
        - `update_status` checks `WHERE file_id = $1 AND status = $2`. If status changed concurrently, returns false or throws concurrency conflict.
   - Refactor `src/files/service/metadata_manager.hpp` to forward to or wrap `FileLifecycleService`.
6. **Explicit Out-of-Scope**: Chunk stream handling (owned by FILE-005) and finalization hash calculation (owned by FILE-006).
7. **Dependencies**: Upstream FILES-004-T01, FILES-004-T02, FILES-002-T03, FILES-002-T05. Downstream FILES-004-T04.
8. **Files to Create/Modify**:
   - `src/files/service/file_lifecycle_service.hpp` (New)
   - `src/files/service/file_lifecycle_service.cpp` (New)
   - `src/files/service/metadata_manager.hpp` (Update to interface with `FileLifecycleService`)
   - `src/files/CMakeLists.txt`
9. **Acceptance Criteria**:
   - All file and version creations commit metadata and outbox records in a single atomic transaction.
   - Illegal transitions are rejected prior to database mutation.
   - Existing `AVAILABLE` versions cannot be mutated or overwritten; new versions increment version numbers monotonically.
   - Retention scanner correctly marks files past `retention_until` as `EXPIRED` and emits `FILE_EXPIRED` outbox records.

---

### FILES-004-T04 — FilesServiceImpl gRPC Wiring & RPC Implementation

1. **Ticket ID**: `FILES-004-T04`
2. **Title**: FilesServiceImpl gRPC Wiring & RPC Implementation
3. **Objective**: Replace skeleton unimplemented handlers in `src/files/service/files_service_impl.cpp` with production implementations for `CreateFileUpload`, `GetFileMetadata`, `DeleteFile`, and hook lifecycle checks into `FinalizeFileUpload`.
4. **Architectural Purpose**: Exposes the validated file metadata and lifecycle capabilities over the gRPC transport, authenticated via mTLS, mapping domain exceptions to appropriate gRPC status codes (`INVALID_ARGUMENT`, `NOT_FOUND`, `PERMISSION_DENIED`, `FAILED_PRECONDITION`) (Files Design 6.3, 6.17).
5. **Scope**:
   - Update `src/files/service/files_service_impl.hpp`:
     - Add `std::shared_ptr<FileLifecycleService> lifecycle_service` to `FilesServiceDependencies`.
   - Update `src/files/service/files_service_impl.cpp`:
     - **`CreateFileUpload`**:
       - Verify caller identity via mTLS / `check_peer_authorization`.
       - Map protobuf request into `CreateFileRequestDto`.
       - Call `validator::validate_create_file_request`. If invalid, return `grpc::StatusCode::INVALID_ARGUMENT`.
       - Call `lifecycle_service->create_file(...)`.
       - Generate durable `upload_id` (UUIDv7) and create transfer record in `file_transfers` table.
       - Populate `CreateFileUploadResponse` with `upload_id`, `file_id`, `TRANSFER_STATUS_PENDING`, and expiry timestamp.
     - **`GetFileMetadata`**:
       - Verify caller identity.
       - Validate `file_id` format (UUID).
       - Call `lifecycle_service->get_file_metadata(file_id, caller_user_id)`.
       - If not found or deleted, return `grpc::StatusCode::NOT_FOUND`.
       - Populate `GetFileMetadataResponse`:
         - `lifecycle_state` (mapped to protobuf enum)
         - `encrypted_size_bytes`
         - `chunk_count`
         - `encryption_version`
         - `ciphertext_integrity_hash` (from active version if AVAILABLE)
         - `created_at_unix_ms`, `available_at_unix_ms`, `expires_at_unix_ms`.
     - **`DeleteFile`**:
       - Verify caller identity.
       - Validate `file_id`.
       - Call `lifecycle_service->delete_file(file_id, caller_user_id)`.
       - If file not found, return `grpc::StatusCode::NOT_FOUND`.
       - If unauthorized, return `grpc::StatusCode::PERMISSION_DENIED`.
       - Populate `DeleteFileResponse` with `file_id`, `FILE_LIFECYCLE_STATE_DELETED`, `deleted=true`.
     - **`FinalizeFileUpload` Lifecycle Hook**:
       - Update `FinalizeFileUpload` to check that file status transition `UPLOADING -> FINALIZING` is legal before proceeding.
   - Ensure `RpcScopeLogger` logs operational metrics and never leaks ciphertext bytes or user secrets.
6. **Explicit Out-of-Scope**: Resumable chunk upload streaming (FILE-005) and whole-object S3 assembly (FILE-006).
7. **Dependencies**: Upstream FILES-004-T01, FILES-004-T02, FILES-004-T03. Downstream FILES-004-T05, FILES-004-T06.
8. **Files to Create/Modify**:
   - `src/files/service/files_service_impl.hpp`
   - `src/files/service/files_service_impl.cpp`
   - `src/files/main.cpp` (Initialize `FileLifecycleService` in main dependency injector)
9. **Acceptance Criteria**:
   - `CreateFileUpload` succeeds and returns valid `upload_id` and `file_id`.
   - `GetFileMetadata` returns complete operational metadata for authorized callers and returns `PERMISSION_DENIED` for unauthorized users.
   - `DeleteFile` logically transitions file to `DELETED` and subsequent metadata queries report `DELETED` or `NOT_FOUND`.
   - Invalid requests return structured gRPC errors with clear descriptions.

---

### FILES-004-T05 — Comprehensive Unit Test Suite & Mock Verification

1. **Ticket ID**: `FILES-004-T05`
2. **Title**: Comprehensive Unit Test Suite & Mock Verification
3. **Objective**: Implement comprehensive unit tests in `tests/unit/files/` testing state machine transitions, metadata validation edge cases, version immutability, ownership checks, expiration logic, and gRPC status mappings with mock repositories.
4. **Architectural Purpose**: Provides fast, deterministic unit test coverage that runs without external dependencies (no live database or network required) across all compiler toolchains.
5. **Scope**:
   - Create unit tests:
     - `tests/unit/files/lifecycle_state_machine_test.cpp`:
       - Exhaustive test covering all 49 transitions in the 7x7 matrix.
       - Test string/proto enum conversions and exception properties.
     - `tests/unit/files/metadata_validator_test.cpp`:
       - Boundary tests for UUID strings, chunk count formulas, max file size limits.
       - Verification of cryptographic parameters (24-byte nonce, 16-byte tag, XChaCha20 algorithm string).
       - Timestamp validation (future expiration allowed, past expiration rejected).
     - `tests/unit/files/file_lifecycle_service_test.cpp`:
       - Mock repository tests verifying:
         - Atomic creation of file + encrypted metadata + outbox event.
         - Version creation creating version N+1 and refusing mutation of version N.
         - Rejection of invalid transitions (`AVAILABLE -> CREATED`, `DELETED -> AVAILABLE`).
         - Ownership security: non-owner access without grant throws `UnauthorizedFileAccessException`.
         - Expiration scanner marking expired records and generating `FILE_EXPIRED` events.
     - `tests/unit/files/files_service_impl_test.cpp` (Expand):
       - Test `CreateFileUpload`, `GetFileMetadata`, `DeleteFile` handlers with mock services.
       - Verify gRPC error code mappings (`INVALID_ARGUMENT`, `NOT_FOUND`, `PERMISSION_DENIED`, `FAILED_PRECONDITION`).
   - Register targets in `tests/unit/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Live PostgreSQL database execution (owned by T06).
7. **Dependencies**: Upstream FILES-004-T01 through FILES-004-T04. Downstream FILES-004-T06.
8. **Files to Create/Modify**:
   - `tests/unit/files/lifecycle_state_machine_test.cpp` (New)
   - `tests/unit/files/metadata_validator_test.cpp` (New)
   - `tests/unit/files/file_lifecycle_service_test.cpp` (New)
   - `tests/unit/files/files_service_impl_test.cpp` (Modify)
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - 100% of unit tests pass deterministically without network access.
   - Zero compilation warnings on MSVC, GCC, and Clang.

---

### FILES-004-T06 — Live PostgreSQL Integration Test Suite & Card Sign-Off

1. **Ticket ID**: `FILES-004-T06`
2. **Title**: Live PostgreSQL Integration Test Suite & Card Sign-Off
3. **Objective**: Implement an authoritative live end-to-end integration test suite in `tests/integration/files_lifecycle_integration_test.cpp` validating live PostgreSQL persistence, multi-version creation, immutability, state transitions, retention expiration, logical deletion, and outbox event verification.
4. **Architectural Purpose**: The final quality gate verifying that the full metadata and lifecycle engine operates correctly against real PostgreSQL 17 on `127.0.0.1:5433` under real concurrency, connection pooling, and transactional outbox constraints.
5. **Scope**:
   - Implement `tests/integration/files_lifecycle_integration_test.cpp`:
     - Test fixture with TCP preflight probe against port 5433 (`FilesDbConnectionPool`). Skips cleanly via `GTEST_SKIP()` if container is not running.
     - **TC1: Full Lifecycle Progression**:
       - Create file in `CREATED` state.
       - Transition `CREATED -> UPLOADING -> FINALIZING -> AVAILABLE`.
       - Verify row states and verify outbox contains `FILE_CREATED` and `FILE_AVAILABLE` events.
     - **TC2: Immutable Versioning & Multi-Version Creation**:
       - File v1 reaches `AVAILABLE`.
       - Call `create_file_version` for v2 (`version_number = 2`, new object key, new SHA-256).
       - Verify v1 record remains completely unmodified (immutable).
       - Verify v2 is created and can become active version.
       - Assert that direct modification attempts on v1 fail.
     - **TC3: Invalid State Transition Rejection**:
       - Attempt illegal transition: `AVAILABLE -> UPLOADING` or `DELETED -> AVAILABLE`.
       - Verify transaction aborts and database state remains unchanged.
     - **TC4: Expiration Workflow**:
       - Create file with `retention_until` set to 1 second in the future.
       - Sleep 1.5 seconds.
       - Run `evaluate_and_expire_files`.
       - Verify file status transitions to `EXPIRED` and outbox contains `FILE_EXPIRED`.
     - **TC5: Logical Deletion**:
       - Call `delete_file` on an `AVAILABLE` file.
       - Verify status is `DELETED`, outbox contains `FILE_DELETED`.
       - Subsequent `get_file_metadata` reports `DELETED`.
     - **TC6: Ownership & Access Control Isolation**:
       - User A creates file.
       - User B attempts `delete_file` or `transition_lifecycle` without grant -> rejected with authorization error.
       - User A grants `READ` to User B via `FileAccessRepository`.
       - User B can now inspect metadata.
     - **TC7: End-to-End gRPC Service Test**:
       - Spin up in-process gRPC server with `FilesServiceImpl`.
       - Invoke `CreateFileUpload`, `GetFileMetadata`, and `DeleteFile` via gRPC client over loopback with mTLS.
       - Verify responses match expected protobuf structures.
   - Register target in `tests/integration/CMakeLists.txt`.
   - Update walkthrough documentation (`walkthrough-files-004-*.md`).
6. **Explicit Out-of-Scope**: Resumable multipart chunk uploads to MinIO (FILE-005).
7. **Dependencies**: Upstream FILES-004-T01 through FILES-004-T05.
8. **Files to Create/Modify**:
   - `tests/integration/files_lifecycle_integration_test.cpp` (New)
   - `tests/integration/CMakeLists.txt`
   - `docs/final-reports/walkthrough-files-004.md` (New)
9. **Acceptance Criteria**:
   - All live integration tests pass cleanly when PostgreSQL 17 container is active on port 5433.
   - Non-regression across all existing FILES-001, FILES-002, FILES-003, and Milestone 1 test suites.
   - Full sign-off checklist completed.

---

## 5. Quality Gate & Sign-Off Checklist for Card FILES-004

- [ ] **Zero-Plaintext Invariant**: No plaintext content, plaintext filenames, plaintext MIME types, or cryptographic keys are stored or processed.
- [ ] **Immutable Completed Versions Invariant**: Once a file version reaches `AVAILABLE`, its encrypted object and checksum are permanently immutable; new versions create new version rows (`version_number = N+1`) and new object keys.
- [ ] **Approved Lifecycle Enforcement**: Only legal transitions (`CREATED → UPLOADING → FINALIZING → AVAILABLE`, with approved `FAILED`, `EXPIRED`, and `DELETED` paths) are permitted.
- [ ] **Terminal State Guard**: `FAILED` and `DELETED` states are strictly terminal; any outward transition attempt throws an error.
- [ ] **Metadata Validation**: Strict validation of UUIDv7 identifiers, chunk count calculations, file size limits (<= 5 GiB), algorithm whitelisting, and cryptographic nonce/tag lengths.
- [ ] **Ownership & Tenant Isolation**: Operations enforce ownership (`owner_user_id == caller_user_id`) or verify explicit access grants (`file_access`).
- [ ] **Transactional Outbox Atomicity**: State transitions and corresponding domain events (`FILE_CREATED`, `FILE_VERSION_CREATED`, `FILE_AVAILABLE`, `FILE_EXPIRED`, `FILE_DELETED`) are committed atomically in the same database transaction.
- [ ] **gRPC Service Integration**: `CreateFileUpload`, `GetFileMetadata`, and `DeleteFile` RPCs are fully implemented with mTLS peer authorization.
- [ ] **Unit Test Coverage**: Deterministic unit tests covering all 49 state machine transitions, metadata validation edge cases, ownership logic, and gRPC status mapping.
- [ ] **Live Integration Verification**: Integration test suite passing against live PostgreSQL 17 on `127.0.0.1:5433`.
- [ ] **Cross-Platform Cleanliness**: Clean compilation with zero warnings or errors on Windows (MSVC x64 / MinGW-w64) and macOS (AppleClang).
- [ ] **Non-Regression**: All existing Milestone 1, 2, and Milestone 5 (FILES-001, FILES-002, FILES-003) tests continue to pass without regression.
