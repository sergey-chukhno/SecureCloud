# FILES-005 — Implement Resumable Chunked Uploads
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: `FILES-005` (or `FILE-005`)  
**Milestone**: M5 — Secure Files  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-005** implements the **Resumable Chunked Upload Engine** for the **SecureCloud Files Service** (`securecloud-files`). As emphasized in the project architecture, this is **one of the most critical cards in the Files subsystem**. It bridges the initial upload allocation (`CreateFileUpload` from **FILES-004**) with whole-object finalization and assembly (**FILES-006**).

### Upload Model

```text
                  CreateTransfer (CreateFileUpload)
                                │
                                ▼
                           transfer_id
                                │
        ┌───────────────┬───────┴───────┬───────────────┐
        ▼               ▼               ▼               ▼
     chunk 0         chunk 1         chunk 2         chunk N
 (out-of-order)  (out-of-order)  (duplicate/retry)(out-of-order)
        │               │               │               │
        └───────────────┴───────┬───────┴───────────────┘
                                │
                  All expected chunks received
                        & verified in DB
                                │
                                ▼
                           FINALIZATION
                           (FILES-006)
```

### Core Requirements
1. **Chunk Structure**:
   - Every chunk transfer carries:
     - `transfer_id`: Unique UUIDv7 identifying the active upload transfer session.
     - `chunk_index`: 0-based index of the chunk (`0 <= chunk_index < total_chunks`).
     - `encrypted_data`: Binary ciphertext payload of the chunk.
     - `chunk_size_bytes`: Byte length of the encrypted payload.
     - `ciphertext_sha256`: Client-calculated hex SHA-256 digest of this encrypted chunk.
2. **Robust Transport & Session Support**:
   - **Chunk upload**: Streaming and receiving individual encrypted chunks.
   - **Duplicate chunk requests**: Fully idempotent replay handling.
   - **Out-of-order chunks**: Chunks can arrive in any sequence (e.g., chunk 4, then chunk 0, then chunk 2).
   - **Missing chunks**: Queryable tracking of which chunks have been durably accepted vs. which remain missing.
   - **Interrupted connections & client reconnect**: Clients can disconnect at any point and reconnect without losing progress.
   - **Resume**: Clients can query transfer status and resume from the exact set of unacknowledged chunks.
   - **Durable transfer state**: Transfer progress is committed to PostgreSQL (`file_transfers`, `file_chunks`) and MinIO staging (`staging/{transfer_id}/{chunk_index}`).
   - **Bounded memory**: The server never buffers the entire file in RAM; chunk sizes are strictly bounded (standard 4 MiB, max 8 MiB) and streamed directly to storage.
   - **Cancellation**: Clients can explicitly abort a transfer session (`CancelFileUpload`), marking the transfer as `Cancelled` and staging chunks for cleanup.

### Authoritative Idempotency Semantics
Repeated submission of the same chunk must **never corrupt the transfer**. For any pair `(transfer_id, chunk_index)`:
- **Identical Replay**: If the chunk is already durably accepted with the **identical** SHA-256 hash:
  $$\longrightarrow \text{Return success / already accepted (no duplicate disk/S3 writes; deterministic ACK)}.$$
- **Conflicting Content**: If a chunk with the same `(transfer_id, chunk_index)` has already been accepted but the new request supplies **different content or a differing SHA-256 hash**:
  $$\longrightarrow \text{Strictly reject with integrity conflict (e.g., FAILED\_PRECONDITION / ALREADY\_EXISTS).}$$
- **Zero Silent Overwrite**: The engine must **never** silently overwrite an already accepted chunk.

### Critical Rule: In-Memory Scheduler Is Not Authoritative
> **The in-memory upload scheduler is NOT authoritative.**  
> Transfer state must be durably persisted in PostgreSQL 17 (`file_transfers`, `file_chunks`) and MinIO S3 (`staging/{transfer_id}/{chunk_index}`).  
> **After any Files Service crash or restart, the service reconstructs transfer state directly from durable storage.**

---

## 2. Key Invariants & Architectural Boundaries

1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design §6.1, §6.26)**:
   - Chunks handled by the server are **pre-encrypted ciphertext blocks** prepared exclusively by the client device.
   - The Files Service never receives plaintext chunk bytes, never inspects chunk content, and has no access to user keys or file-encryption keys.
   - Chunk SHA-256 digests (`ciphertext_sha256`) are calculated strictly over the ciphertext bytes.

2. **Durable Authority & Crash Recovery Invariant (Initial Backlog Item FILE-005)**:
   - In-memory data structures (such as `UploadSessionManager` caches or worker queues) are strictly opportunistic and non-authoritative.
   - If the Files Service process terminates or is killed mid-transfer:
     - No accepted chunk is lost.
     - On restart, incoming chunks or resume status queries reload state from PostgreSQL `file_transfers` and `file_chunks`.
     - The client can resume uploading the remaining missing chunks seamlessly.

3. **Strict Chunk Idempotency Invariant**:
   - Network retries, gRPC duplicate deliveries, and concurrent duplicate submissions of `(transfer_id, chunk_index)` with identical SHA-256 hashes produce a deterministic success response (`accepted = true`, matching `received_sha256`).
   - Conflicting content for an accepted index throws a typed `ChunkIntegrityException` and returns a gRPC error. Existing staged data is preserved unaltered.

4. **Bounded Memory & Streaming Invariant**:
   - Maximum chunk size is strictly capped (`k_max_chunk_size = 8 MiB`; standard `k_standard_chunk_size = 4 MiB`).
   - Memory allocation per chunk request is strictly bounded.
   - Chunks are committed directly to MinIO staging (`staging/{transfer_id}/{chunk_index}`) without keeping prior chunks in RAM.

5. **Lifecycle State Coupling**:
   - Arrival of the first accepted chunk transitions the transfer from `TransferStatus::Created` to `TransferStatus::Transferring` and the underlying file from `FileStatus::Created` to `FileStatus::Uploading`.
   - When `accepted_chunks == total_chunks`, the transfer is marked ready for finalization (`TransferStatus::Finalizing`).

6. **mTLS & Tenant Isolation Invariant**:
   - `UploadChunk` and `CancelFileUpload` enforce mTLS peer authentication (`DNS:gateway`).
   - The caller's user and device identity must match the transfer session initiator (`initiator_user_id`, `initiator_device_id`).

---

## 3. Component Architecture & Flow Diagrams

### 3.1 Component Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         SecureCloud Files Service                           │
 │                                                                             │
 │  ┌───────────────────────────────────────────────────────────────────────┐  │
 │  │                          FilesServiceImpl                             │  │
 │  │  - UploadChunk RPC                                                    │  │
 │  │  - CancelFileUpload RPC                                              │  │
 │  │  - Resumable Chunk Tracking (via FileChunkRepository & SessionMgr)    │  │
 │  └───────────────────────────────────┬───────────────────────────────────┘  │
 │                                      │                                      │
 │  ┌───────────────────────────────────▼───────────────────────────────────┐  │
 │  │                     Resumable Upload Engine                           │  │
 │  │  ┌────────────────────────────┐    ┌───────────────────────────────┐  │  │
 │  │  │     ChunkValidator         │    │     UploadSessionManager      │  │  │
 │  │  │  - Bounds checking         │    │  - Crash-recovery loader      │  │  │
 │  │  │  - SHA-256 verification    │    │  - Missing chunk tracking     │  │  │
 │  │  │  - Size matching           │    │  - Session mutex concurrency  │  │  │
 │  │  └─────────────┬──────────────┘    └───────────────┬───────────────┘  │  │
 │  │                │                                   │                  │  │
 │  │  ┌─────────────▼───────────────────────────────────▼───────────────┐  │  │
 │  │  │                        ChunkStorageService                      │  │  │
 │  │  │  - Idempotent conflict resolution                               │  │  │
 │  │  │  - MinIO chunk staging: staging/{transfer_id}/{chunk_index}     │  │  │
 │  │  │  - Atomic PostgreSQL chunk recording                            │  │  │
 │  │  │  - Progress counter & byte aggregation                          │  │  │
 │  │  └─────────────┬───────────────────────────────────┬───────────────┘  │  │
 │  └────────────────┼───────────────────────────────────┼──────────────────┘  │
 │                   │                                   │                     │
 │  ┌────────────────▼───────────────┐   ┌───────────────▼──────────────────┐  │
 │  │        PostgreSQL 17           │   │            MinIO S3              │  │
 │  │  - file_transfers              │   │  - staging/{transfer_id}/0       │  │
 │  │  - file_chunks (ON CONFLICT)   │   │  - staging/{transfer_id}/1       │  │
 │  │  - files (lifecycle status)    │   │  - ...                           │  │
 │  │  (TCP 5433)                    │   │  (TCP 9000)                      │  │
 │  └────────────────────────────────┘   └──────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

### 3.2 Chunk Idempotency & Conflict Decision Tree

```text
Incoming Chunk: (transfer_id, chunk_index, payload, claimed_sha256)
                       │
                       ▼
      Is payload SHA-256 == claimed_sha256?
             │                     │
            NO                    YES
             │                     │
             ▼                     ▼
   Reject: INVALID_ARGUMENT   Query DB / Staging for chunk
   "SHA-256 digest mismatch"       │
                                   ▼
                       Does chunk_index exist?
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                   YES                            NO
                    │                             │
                    ▼                             ▼
       Does existing hash match?       Write payload to MinIO:
             │              │          staging/{transfer_id}/{chunk_index}
            YES             NO                    │
             │              │                     ▼
             ▼              ▼          Commit row to PostgreSQL:
         IDEMPOTENT     CONFLICT       file_chunks (ON CONFLICT DO NOTHING)
           REPLAY       REJECTION                 │
             │              │                     ▼
             ▼              ▼          Increment accepted_chunks counter
          Return         Reject:                  │
          Success        FAILED_PRECONDITION      ▼
        (no re-write)   "Chunk hash conflict"   Return Success
```

---

### 3.3 Crash Recovery & Resume Flow

```text
Client                              Files Service                     PostgreSQL / MinIO
  │                                       │                                   │
  │─── Upload Chunk 0, 1, 2 ─────────────►│                                   │
  │                                       │─── Persist to DB & S3 ───────────►│
  │◄── ACK Chunk 0, 1, 2 ─────────────────│                                   │
  │                                       │                                   │
  │                                  [CRASH / RESTART]                        │
  │                                  (RAM is wiped clean)                     │
  │                                       │                                   │
  │─── Client reconnects & queries status►│                                   │
  │    (or submits Chunk 3)               │                                   │
  │                                       │─── Reconstruct from DB ──────────►│
  │                                       │    SELECT * FROM file_transfers   │
  │                                       │    SELECT chunk_index FROM chunks │
  │                                       │◄── Return accepted=[0, 1, 2] ─────│
  │                                       │                                   │
  │◄── Missing chunks: [3, 4] ────────────│                                   │
  │                                       │                                   │
  │─── Upload Chunk 3 ───────────────────►│─── Persist to DB & S3 ───────────►│
  │◄── ACK Chunk 3 ───────────────────────│                                   │
  │─── Upload Chunk 4 ───────────────────►│─── Persist to DB & S3 ───────────►│
  │◄── ACK Chunk 4 (All received) ────────│                                   │
```

---

## 4. Dependency Graph & Implementation Sequence

```text
                                FILES-005-T01
                     (Chunk Payload Validation Engine &
                      Cryptographic Integrity Verifier)
                                    │
                                    ▼
                                FILES-005-T02
                     (Resumable Upload Session Manager &
                      Crash-Recovery Reconstruction)
                                    │
                                    ▼
                                FILES-005-T03
                     (Idempotent Chunk Storage Engine &
                        MinIO Chunk Staging Pipeline)
                                    │
                                    ▼
                                FILES-005-T04
                     (FilesServiceImpl gRPC Wiring:
                      UploadChunk & CancelFileUpload)
                                    │
                                    ▼
                                FILES-005-T05
                     (Comprehensive Unit Test Suite &
                        Failure Simulation)
                                    │
                                    ▼
                                FILES-005-T06
                     (Live End-to-End Integration Tests:
                      PostgreSQL 5433 + MinIO 9000 & Sign-Off)
```

---

## 5. Implementation Tickets for Developer Louis

---

### FILES-005-T01 — Chunk Payload Validation Engine & Cryptographic Integrity Verifier

1. **Ticket ID**: `FILES-005-T01`
2. **Title**: Chunk Payload Validation Engine & Cryptographic Integrity Verifier
3. **Objective**: Implement `ChunkValidator` in `src/files/domain/chunk_validator.{hpp,cpp}` to perform fail-fast validation of chunk metadata, size bounds, and cryptographic SHA-256 ciphertext integrity.
4. **Architectural Purpose**: Enforces the Zero-Plaintext and fail-fast validation boundaries. Corrupted chunks, mismatched sizes, malformed UUIDs, or tampered digests are rejected at the edge before allocating storage resources or acquiring database transactions (Files Design §6.13, §6.18).
5. **Scope**:
   - Create `src/files/domain/chunk_validator.hpp` and `src/files/domain/chunk_validator.cpp`:
     - Constants:
       ```cpp
       inline constexpr uint32_t k_standard_chunk_size = 4U * 1024U * 1024U;  // 4 MiB
       inline constexpr uint32_t k_max_chunk_size      = 8U * 1024U * 1024U;  // 8 MiB hard limit
       inline constexpr uint32_t k_min_chunk_size      = 1U;                  // 1 byte minimum
       inline constexpr size_t   k_sha256_hex_length   = 64;
       ```
     - Domain DTO:
       ```cpp
       struct ChunkPayloadDto {
           std::string upload_id;
           uint32_t chunk_index{0};
           std::string encrypted_data; // or std::vector<uint8_t>
           uint32_t chunk_size_bytes{0};
           std::string claimed_sha256;
       };
       ```
     - Verification Functions:
       ```cpp
       struct ChunkValidationResult {
           bool is_valid{true};
           std::string error_message;
           std::string computed_sha256;
       };

       ChunkValidationResult validate_chunk_payload(const ChunkPayloadDto& dto,
                                                    uint32_t total_chunks,
                                                    uint64_t total_file_size_bytes);

       std::string compute_sha256_hex(std::string_view data);
       ```
     - Validation Rules:
       - `upload_id` must be a valid UUIDv7 / RFC 4122 string.
       - `chunk_index` must be strictly `< total_chunks`.
       - `chunk_size_bytes` must equal `encrypted_data.size()`.
       - `chunk_size_bytes` must be `>= k_min_chunk_size` and `<= k_max_chunk_size`.
       - For non-terminal chunks (`chunk_index < total_chunks - 1`), `chunk_size_bytes` must equal `k_standard_chunk_size` (unless total file size is smaller than 4 MiB).
       - For the terminal chunk (`chunk_index == total_chunks - 1`), `chunk_size_bytes` must equal the remaining expected bytes: `total_file_size_bytes - (chunk_index * k_standard_chunk_size)`.
       - `claimed_sha256` must be exactly 64 hex characters (case-insensitive).
       - Cryptographic verification: compute SHA-256 over `encrypted_data` and assert case-insensitive equality with `claimed_sha256`.
   - Implement unit test `tests/unit/files/chunk_validator_test.cpp`.
6. **Explicit Out-of-Scope**: Writing chunk bytes to disk or database.
7. **Dependencies**: Upstream FILES-004-T02. Downstream FILES-005-T02.
8. **Files to Create/Modify**:
   - `src/files/domain/chunk_validator.hpp` (New)
   - `src/files/domain/chunk_validator.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `tests/unit/files/chunk_validator_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - Correctly verifies valid chunks with matching SHA-256 digests.
   - Rejects corrupted digests, mismatched sizes, out-of-bounds indices, and malformed UUIDs with descriptive errors.
   - 100% test pass rate across GCC, Clang, and MSVC.

---

### FILES-005-T02 — Resumable Upload Session Manager & Crash-Recovery Reconstruction Engine

1. **Ticket ID**: `FILES-005-T02`
2. **Title**: Resumable Upload Session Manager & Crash-Recovery Reconstruction Engine
3. **Objective**: Implement production `UploadSessionManager` in `src/files/service/upload_session_manager.{hpp,cpp}` with crash recovery reconstruction, missing chunk calculation, lease expiration checking, and concurrent session synchronization.
4. **Architectural Purpose**: Enforces the **In-Memory Non-Authoritative Invariant**. If the Files Service restarts or loses volatile state, this component queries PostgreSQL `file_transfers` and `file_chunks` to rebuild active session progress dynamically, enabling clients to resume interrupted uploads seamlessly without restarting from chunk 0 (Files Design §6.3, §6.19).
5. **Scope**:
   - Refactor `src/files/service/upload_session_manager.hpp` and implement `.cpp`:
     ```cpp
     struct TransferProgress {
         std::string transfer_id;
         std::string file_id;
         TransferStatus status;
         uint32_t total_chunks{0};
         uint32_t accepted_chunks{0};
         int64_t transferred_bytes{0};
         int64_t total_bytes{0};
         std::vector<int32_t> accepted_chunk_indices;
         std::vector<int32_t> missing_chunk_indices;
         std::chrono::system_clock::time_point expires_at;
         bool is_expired{false};
         bool is_complete{false};
     };

     class IUploadSessionManager {
     public:
         virtual ~IUploadSessionManager() = default;
         virtual std::optional<UploadSession> create_session(const v1::CreateFileUploadRequest& request) = 0;
         virtual std::optional<UploadSession> get_session(const std::string& upload_id) = 0;
         virtual TransferProgress get_transfer_progress(const std::string& upload_id) = 0;
         virtual std::vector<int32_t> get_missing_chunk_indices(const std::string& upload_id) = 0;
         virtual bool cancel_session(const std::string& upload_id, const std::string& reason) = 0;
         virtual UploadSession reconstruct_session_from_storage(const std::string& upload_id) = 0;
     };

     class UploadSessionManager : public IUploadSessionManager {
     public:
         explicit UploadSessionManager(
             std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr,
             std::shared_ptr<FileTransferRepository> transfer_repo = nullptr,
             std::shared_ptr<FileChunkRepository> chunk_repo = nullptr);

         std::optional<UploadSession> create_session(const v1::CreateFileUploadRequest& request) override;
         std::optional<UploadSession> get_session(const std::string& upload_id) override;
         TransferProgress get_transfer_progress(const std::string& upload_id) override;
         std::vector<int32_t> get_missing_chunk_indices(const std::string& upload_id) override;
         bool cancel_session(const std::string& upload_id, const std::string& reason) override;
         UploadSession reconstruct_session_from_storage(const std::string& upload_id) override;

     private:
         std::shared_ptr<db::FilesDbConnectionPool> pool_;
         std::shared_ptr<FileTransferRepository> transfer_repo_;
         std::shared_ptr<FileChunkRepository> chunk_repo_;
         mutable std::mutex session_mutex_;
         std::unordered_map<std::string, UploadSession> in_memory_cache_;
     };
     ```
   - Core Behavioral Logic:
     - `reconstruct_session_from_storage`: Queries `file_transfers` by `transfer_id`. If not found, throws `TransferNotFoundException`. Then queries `file_chunks` to obtain the exact list of accepted chunk indices. Rebuilds `UploadSession` and updates cache.
     - `get_missing_chunk_indices`: Computes set difference $[0, \dots, \text{total\_chunks}-1] \setminus \text{accepted\_indices}$. Returns ordered vector of missing chunks for client resume.
     - `cancel_session`: Marks `file_transfers.status = TransferStatus::Cancelled` in PostgreSQL within transaction.
     - Expiration check: If `now > expires_at`, marks transfer as `Expired`.
     - Thread-safety: Protects session state updates with mutex to prevent race conditions during concurrent chunk arrivals.
   - Implement unit test `tests/unit/files/upload_session_manager_test.cpp`.
6. **Explicit Out-of-Scope**: S3 multipart assembly (FILE-006).
7. **Dependencies**: Upstream FILES-005-T01, FILES-002-T04. Downstream FILES-005-T03.
8. **Files to Create/Modify**:
   - `src/files/service/upload_session_manager.hpp` (Modify)
   - `src/files/service/upload_session_manager.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `tests/unit/files/upload_session_manager_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - Cache misses or restarted sessions seamlessly reload transfer progress from PostgreSQL.
   - Accurately reports missing chunk indices for out-of-order and partial uploads.
   - Rejects cancelled and expired transfer sessions.
   - 100% thread-safe under concurrent access.

---

### FILES-005-T03 — Idempotent Chunk Storage Engine & MinIO Chunk Staging Pipeline

1. **Ticket ID**: `FILES-005-T03`
2. **Title**: Idempotent Chunk Storage Engine & MinIO Chunk Staging Pipeline
3. **Objective**: Implement `ChunkStorageService` in `src/files/service/chunk_storage_service.{hpp,cpp}` coordinating chunk payload storage to MinIO staging (`staging/{transfer_id}/{chunk_index}`) and atomic recording in PostgreSQL `file_chunks`.
4. **Architectural Purpose**: Enforces the **Authoritative Idempotency Semantics** and **Out-of-Order Staging**. Handles duplicate network retries gracefully without duplicating S3 storage or corrupting database counters, while detecting and rejecting content hash collisions (Files Design §6.3, §6.18, §6.19).
5. **Scope**:
   - Create `src/files/service/chunk_storage_service.hpp` and `src/files/service/chunk_storage_service.cpp`:
     ```cpp
     struct ChunkStoreResult {
         bool accepted{true};
         bool is_duplicate{false};
         std::string received_sha256;
         uint32_t chunk_index{0};
         int64_t bytes_written{0};
     };

     class ChunkStorageService {
     public:
         explicit ChunkStorageService(
             std::shared_ptr<db::FilesDbConnectionPool> pool,
             std::shared_ptr<storage::S3Client> s3_client,
             std::shared_ptr<FileTransferRepository> transfer_repo = nullptr,
             std::shared_ptr<FileChunkRepository> chunk_repo = nullptr,
             std::shared_ptr<FileRepository> file_repo = nullptr);

         /// Stores and records an individual chunk with strict idempotency semantics.
         ChunkStoreResult store_chunk(const ChunkPayloadDto& chunk_dto,
                                      const std::string& caller_user_id);
     };
     ```
   - Core Storage & Idempotency Pipeline:
     1. **Session & Caller Verification**:
        - Query transfer record from `file_transfers`. Verify caller is initiator (`initiator_user_id == caller_user_id`).
        - Verify transfer status is `Created` or `Transferring`. If `Cancelled`, `Expired`, or `Completed`, reject.
     2. **Idempotency Check via Database**:
        - Check if chunk `(transfer_id, chunk_index)` is already recorded in `file_chunks`.
        - **If present with identical SHA-256**:
          - Safe idempotent replay! Return `ChunkStoreResult{.accepted = true, .is_duplicate = true, .received_sha256 = hash}` immediately. Do NOT re-upload to S3 or increment counters.
        - **If present with conflicting SHA-256**:
          - Throw `ChunkIntegrityException("Conflicting chunk content for index " + chunk_index)`.
     3. **MinIO Object Staging**:
        - Construct MinIO staging key: `staging/{transfer_id}/{chunk_index}`.
        - Upload chunk ciphertext to MinIO bucket via `s3_client->put_object(staging_key, chunk_dto.encrypted_data, "application/octet-stream")`.
     4. **Atomic Database Commit**:
        - In PostgreSQL transaction (`pqxx::work tx`):
          - Record chunk in `file_chunks` with `status = ChunkStatus::Received`.
          - If first chunk received (`transfer.status == TransferStatus::Created`), transition `transfer.status` to `Transferring`, and transition file state `files.status` to `UPLOADING`.
          - Atomically increment `file_transfers.accepted_chunks` by 1 and update `transferred_bytes`.
          - Check if all chunks received: if `accepted_chunks == total_chunks`, transition transfer status to `Finalizing`.
          - Commit transaction.
   - Implement unit test `tests/unit/files/chunk_storage_service_test.cpp`.
6. **Explicit Out-of-Scope**: Concatenating staged chunks into whole file version object (FILE-006).
7. **Dependencies**: Upstream FILES-005-T01, FILES-005-T02, FILES-003-T01. Downstream FILES-005-T04.
8. **Files to Create/Modify**:
   - `src/files/service/chunk_storage_service.hpp` (New)
   - `src/files/service/chunk_storage_service.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `tests/unit/files/chunk_storage_service_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - Chunks stored in MinIO at exact key path `staging/{transfer_id}/{chunk_index}`.
   - Idempotent duplicate submission returns success with zero additional storage mutation.
   - Content hash conflict is strictly rejected without altering existing chunk.
   - Database progress counters increment accurately on new chunk insertions.

---

### FILES-005-T04 — FilesServiceImpl gRPC Wiring: UploadChunk & CancelFileUpload

1. **Ticket ID**: `FILES-005-T04`
2. **Title**: FilesServiceImpl gRPC Wiring: UploadChunk & CancelFileUpload
3. **Objective**: Replace skeleton implementations in `src/files/service/files_service_impl.cpp` with production handlers for `UploadChunk` and `CancelFileUpload`, integrating `ChunkValidator`, `UploadSessionManager`, and `ChunkStorageService`.
4. **Architectural Purpose**: Exposes the chunked upload engine over gRPC mTLS transport, handling transport-level decoding, peer authorization, error mapping, and secret-safe operational logging (Files Design §6.3, §6.17).
5. **Scope**:
   - Update `src/files/service/files_service_impl.hpp`:
     - Add `std::shared_ptr<ChunkStorageService> chunk_storage_service` to `FilesServiceDependencies`.
   - Update `src/files/service/files_service_impl.cpp`:
     - **`UploadChunk` Handler**:
       - Verify caller mTLS identity via `check_peer_authorization`.
       - Map protobuf request into `ChunkPayloadDto`.
       - Validate payload via `ChunkValidator::validate_chunk_payload`. On validation failure, return `grpc::StatusCode::INVALID_ARGUMENT`.
       - Call `chunk_storage_service->store_chunk(dto, peer_identity)`.
       - Error mappings:
         - `ChunkIntegrityException` $\to$ `grpc::StatusCode::FAILED_PRECONDITION` ("Chunk content conflicts with previously accepted chunk").
         - `TransferNotFoundException` $\to$ `grpc::StatusCode::NOT_FOUND` ("Upload transfer session not found").
         - `TransferExpiredException` $\to$ `grpc::StatusCode::DEADLINE_EXCEEDED` ("Upload session lease expired").
         - `TransferCancelledException` $\to$ `grpc::StatusCode::FAILED_PRECONDITION` ("Upload session has been cancelled").
         - `UnauthorizedAccessException` $\to$ `grpc::StatusCode::PERMISSION_DENIED`.
       - Populate `UploadChunkResponse`: `upload_id`, `chunk_index`, `accepted=true`, `received_sha256`.
       - Secret-Safe Logging: Never log chunk ciphertext or plaintext keys; log only `upload_id`, `chunk_index`, `chunk_size_bytes`, and status.
     - **`CancelFileUpload` Handler**:
       - Verify caller mTLS identity.
       - Validate `upload_id` format (UUIDv7).
       - Call `upload_session_manager->cancel_session(upload_id, request->reason())`.
       - If session not found, return `grpc::StatusCode::NOT_FOUND`.
       - Populate `CancelFileUploadResponse` with `upload_id` and `TRANSFER_STATUS_CANCELLED`.
   - Modify `src/files/main.cpp` dependency injection to wire `ChunkStorageService` and `UploadSessionManager`.
6. **Explicit Out-of-Scope**: FinalizeFileUpload assembly (FILE-006).
7. **Dependencies**: Upstream FILES-005-T01 through FILES-005-T03. Downstream FILES-005-T05, FILES-005-T06.
8. **Files to Create/Modify**:
   - `src/files/service/files_service_impl.hpp`
   - `src/files/service/files_service_impl.cpp`
   - `src/files/main.cpp`
9. **Acceptance Criteria**:
   - `UploadChunk` returns `OK` with acknowledged SHA-256 for valid chunks.
   - Idempotent retries return `OK` with `accepted=true`.
   - Conflicting chunk submissions return `FAILED_PRECONDITION`.
   - `CancelFileUpload` cancels the active session and prevents further chunk uploads.
   - Zero ciphertext leakage in application logs.

---

### FILES-005-T05 — Comprehensive Unit Test Suite & Failure Simulation

1. **Ticket ID**: `FILES-005-T05`
2. **Title**: Comprehensive Unit Test Suite & Failure Simulation
3. **Objective**: Implement comprehensive unit test suites in `tests/unit/files/` testing chunk validation boundaries, idempotency replays, out-of-order arrivals, crash recovery simulation, and cancellation logic using mock repositories and mock storage.
4. **Architectural Purpose**: Provides fast, deterministic regression test coverage executing without network or external database dependencies across all compiler toolchains (GCC, Clang, MSVC).
5. **Scope**:
   - Implement unit tests:
     - `tests/unit/files/chunk_validator_test.cpp`:
       - Boundary tests for chunk sizes (0 bytes rejected, 1 byte accepted, 4 MiB accepted, > 8 MiB rejected).
       - Non-terminal chunk size enforcement (must be standard size).
       - Terminal chunk size calculation.
       - Corrupted payload SHA-256 rejection.
       - Malformed UUID rejection.
     - `tests/unit/files/upload_session_manager_test.cpp`:
       - Reconstruct session state from mock storage.
       - Compute missing chunk indices for out-of-order and sparse arrivals (e.g., chunks [0, 2, 4] received -> missing [1, 3]).
       - Verify lease expiration detection.
       - Verify cancellation updates status.
     - `tests/unit/files/chunk_storage_service_test.cpp`:
       - Mock MinIO S3 and mock DB storage.
       - Idempotent duplicate chunk replay returns success without duplicate S3 PUT.
       - Hash conflict on duplicate chunk throws `ChunkIntegrityException`.
       - Out-of-order arrivals update accepted count correctly.
     - Expand `tests/unit/files/files_service_impl_test.cpp`:
       - Test `UploadChunk` and `CancelFileUpload` gRPC handlers with mock services.
       - Verify error mappings (`INVALID_ARGUMENT`, `FAILED_PRECONDITION`, `NOT_FOUND`, `PERMISSION_DENIED`).
   - Register targets in `tests/unit/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Live Docker container execution (FILE-005-T06).
7. **Dependencies**: Upstream FILES-005-T01 through FILES-005-T04. Downstream FILES-005-T06.
8. **Files to Create/Modify**:
   - `tests/unit/files/chunk_validator_test.cpp` (New)
   - `tests/unit/files/upload_session_manager_test.cpp` (New)
   - `tests/unit/files/chunk_storage_service_test.cpp` (New)
   - `tests/unit/files/files_service_impl_test.cpp` (Modify)
   - `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - 100% of unit tests pass deterministically.
   - Complete coverage of idempotency, conflict rejection, and crash recovery logic.
   - Clean compilation with zero warnings on MSVC, GCC, and Clang.

---

### FILES-005-T06 — Live End-to-End Integration Test Suite & Card Sign-Off

1. **Ticket ID**: `FILES-005-T06`
2. **Title**: Live End-to-End Integration Test Suite & Card Sign-Off
3. **Objective**: Implement comprehensive live integration tests in `tests/integration/files_resumable_upload_integration_test.cpp` exercising live PostgreSQL 17 (port 5433) and live MinIO S3 (port 9000) under real network simulation, crash-restart recovery, client disconnect/resume, and cancellation.
4. **Architectural Purpose**: Authoritative verification that the resumable chunked upload engine operates reliably across real distributed storage, connection pools, and process lifecycle boundaries under real-world network failure conditions (Files Design §6.3, §6.18, §6.19).
5. **Scope**:
   - Create `tests/integration/files_resumable_upload_integration_test.cpp`:
     - Test fixture with dual preflight probes (PostgreSQL port 5433 and MinIO port 9000). Skips cleanly via `GTEST_SKIP()` if services are offline.
     - **TC1: Multi-Chunk Out-of-Order Upload Progression**:
       - Allocate 5-chunk upload session via `CreateFileUpload`.
       - Upload chunks in scrambled order: chunk 3, chunk 0, chunk 4, chunk 1, chunk 2.
       - Verify MinIO contains staging keys `staging/{transfer_id}/{0..4}`.
       - Verify PostgreSQL `file_chunks` records all 5 chunks and `file_transfers.accepted_chunks == 5`.
     - **TC2: Idempotent Duplicate Chunk Replay**:
       - Re-submit chunk 2 with identical SHA-256.
       - Assert response indicates `accepted = true`.
       - Verify PostgreSQL accepted chunks count remains 5 (no double increment).
       - Verify MinIO object timestamp/metadata unchanged.
     - **TC3: Content Hash Collision / Conflict Rejection**:
       - Submit chunk 2 with modified ciphertext payload (differing SHA-256).
       - Assert rejection with `FAILED_PRECONDITION`.
       - Verify original chunk 2 data in MinIO staging remains unaltered.
     - **TC4: Service Restart Crash Recovery**:
       - Allocate transfer with 6 chunks.
       - Upload chunks 0, 1, 2.
       - Simulate abrupt service crash: destroy `UploadSessionManager` and `FilesServiceImpl` instances completely.
       - Instantiate brand-new service instances (empty RAM cache).
       - Query transfer progress via `get_transfer_progress`: verify service reconstructs state showing 3 accepted chunks.
       - Upload remaining chunks 3, 4, 5 successfully.
       - Verify transfer reaches `TransferStatus::Finalizing`.
     - **TC5: Client Reconnect & Resume Workflow**:
       - Client disconnect simulation mid-upload.
       - Client reconnects, queries `get_missing_chunk_indices`, receives missing indices list.
       - Client uploads only missing chunks.
       - Verify full completion.
     - **TC6: Explicit Cancellation**:
       - Allocate transfer and upload 2 chunks.
       - Invoke `CancelFileUpload`.
       - Verify transfer status is `Cancelled` in PostgreSQL.
       - Attempting to upload chunk 3 is rejected with `FAILED_PRECONDITION`.
     - **TC7: End-to-End gRPC Client Roundtrip**:
       - Run in-process or loopback gRPC client uploading 4 MiB chunk stream over mTLS channel.
       - Verify responses match expected protobuf structures.
   - Register target in `tests/integration/CMakeLists.txt`.
   - Update walkthrough documentation (`docs/final-reports/walkthrough-files-005.md`).
6. **Explicit Out-of-Scope**: Finalizing whole object to `AVAILABLE` (FILE-006).
7. **Dependencies**: Upstream FILES-005-T01 through FILES-005-T05.
8. **Files to Create/Modify**:
   - `tests/integration/files_resumable_upload_integration_test.cpp` (New)
   - `tests/integration/CMakeLists.txt`
   - `docs/final-reports/walkthrough-files-005.md` (New)
9. **Acceptance Criteria**:
   - All 7 integration test cases pass cleanly against live PostgreSQL and MinIO.
   - Non-regression across all existing Milestone 1, FILES-001, FILES-002, FILES-003, and FILES-004 test suites.
   - Full card quality checklist signed off.

---

## 6. Quality Gate & Sign-Off Checklist for Card FILES-005

- [x] **Zero-Plaintext Invariant**: All chunks processed and staged are pre-encrypted ciphertext; no plaintext files, plaintext metadata, or keys are handled.
- [x] **In-Memory Non-Authoritative**: On service restart or RAM cache eviction, transfer state is reconstructed accurately from PostgreSQL `file_transfers` and `file_chunks`.
- [x] **Exact Chunk Idempotency**: Identical chunk submissions return success without duplicating writes or corrupting counters.
- [x] **Conflict Rejection**: Conflicting content for an accepted chunk index is strictly rejected; no silent overwrites.
- [x] **Out-of-Order Support**: Chunks submitted in any sequence are accepted, staged in MinIO, and tracked in PostgreSQL.
- [x] **Resume Capability**: Missing chunk indices are accurately computed, allowing clients to resume interrupted uploads without re-uploading completed chunks.
- [x] **Bounded Memory**: Memory per chunk request is strictly capped (max 8 MiB); chunks stream directly to storage without full-file buffering in RAM.
- [x] **Transfer Cancellation**: Clients can cancel active upload sessions, preventing further chunk uploads and marking staged chunks for purge.
- [x] **mTLS Peer Authentication**: gRPC endpoints enforce `DNS:gateway` SAN verification and initiator tenant isolation.
- [x] **Unit Test Coverage**: Deterministic unit tests covering validation, idempotency, crash recovery, out-of-order arrivals, and cancellation.
- [x] **Live Integration Verification**: Comprehensive integration test suite passing against PostgreSQL 17 (port 5433) and MinIO (port 9000).
- [x] **Cross-Platform Cleanliness**: Zero compilation warnings on Windows (MSVC x64 / MinGW-w64) and macOS (AppleClang).
- [x] **Non-Regression**: All existing M1, M2, and FILES-001 through FILES-004 tests pass without regression.
