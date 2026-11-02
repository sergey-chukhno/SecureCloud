# FILES-006 — Whole-Object Finalization, Assembly & Integrity Verification Engine
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: `FILES-006` (or `FILE-006`)  
**Milestone**: M5 — Secure Files  
**Document Status**: Proposed Specification for Architectural Review (Louis & Sergey)  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-006** implements the **Whole-Object Finalization, Assembly, and Integrity Verification Engine** for the **SecureCloud Files Service** (`securecloud-files`). It represents the decisive step in the upload pipeline, bridging chunked transfer ingestion (**FILES-005**) to the activation of immutable, queryable, downloadable file versions (**FILES-004**, **FILES-007**).

### Finalization Pipeline Flow

```text
                  UploadChunk (FILES-005)
                             │
                             ▼
            All chunks staged in MinIO & DB
                             │
                             ▼
              Client calls FinalizeFileUpload
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
   State: UPLOADING                 Concurrent Duplicate Request
            │                                 │
            ▼                                 ▼
   State: FINALIZING                 Acquire Lock / Await State
            │                                 │
   Verify Preconditions:                      │
    1. Transfer exists & valid                │
    2. Correct state (Transferring/Finalizing)│
    3. Expected chunks present (count == N)   │
    4. Zero missing chunks ([0..N-1] gapless) │
    5. Chunk sizes sum to total_file_size     │
    6. Staging objects exist in MinIO         │
    7. Whole-ciphertext SHA-256 verified      │
            │                                 │
     Success?                                 │
    ┌───────┴───────┐                         │
   YES              NO                        │
    │                │                        │
    ▼                ▼                        │
Assemble / Promote  Keep durable state safe;  │
to permanent S3     mark FAILED or return     │
object:             error (NEVER AVAILABLE)   │
objects/{file_id}/vN        │                 │
    │                       │                 │
    ▼                       │                 │
Atomic DB Commit:           │                 │
 - file_versions inserted   │                 │
 - file.status = AVAILABLE  │                 │
 - transfer = Completed     │                 │
 - outbox = FILE_AVAILABLE  │                 │
    │                       │                 │
    ▼                       ▼                 ▼
 Return Success         Return Error      Return Idempotent ACK
 (AVAILABLE)            (FAILED/REJECT)   (AVAILABLE, no re-assembly)
```

---

## 2. Key Invariants & Architectural Boundaries

1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design §6.1, §6.26)**:
   - The finalization engine operates exclusively over pre-encrypted ciphertext blocks.
   - Assembly concatenates or composes ciphertext parts into the final encrypted version object in MinIO (`objects/{file_id}/{version_number}`).
   - Integrity verification evaluates SHA-256 strictly over the whole concatenated ciphertext, matching `expected_ciphertext_sha256` supplied by the client. The Files Service has zero access to encryption keys or plaintext.

2. **Strict Verification Preconditions**:
   Before transitioning any state from `FINALIZING` to `AVAILABLE`, the service must verify:
   - **Transfer Existence**: The `transfer_id` exists in PostgreSQL `file_transfers`.
   - **Correct State**: The transfer status is `Transferring` or `Finalizing` (or `Created` if a 0-byte file). If `Cancelled` or `Expired`, immediately reject.
   - **Complete Chunk Set**: `accepted_chunks == total_chunks` and `count(file_chunks) == total_chunks`.
   - **Gapless Sequence**: No missing chunks exist; indices strictly span $0, 1, \dots, N-1$ with no missing gaps.
   - **Metadata Consistency**: The cumulative sum of chunk byte sizes exactly equals `total_file_size_bytes` on the parent file record.
   - **Object/Storage Validity**: All chunk objects exist in MinIO staging: `staging/{transfer_id}/{0..N-1}`.
   - **Whole-Ciphertext Integrity**: The aggregated ciphertext SHA-256 digest exactly matches the client's `expected_ciphertext_sha256`.

3. **Failure Rule — Never Premature `AVAILABLE`**:
   - If any verification or assembly step fails:
     $$\mathbf{AVAILABLE} \text{ must NEVER be reported.}$$
   - The file state must remain in `FAILED` (or revert to retryable state if transient).
   - Staged chunks in MinIO and PostgreSQL must **not** be purged immediately on verification failure, leaving enough durable state for diagnosis, retry, or surgical chunk replacement.

4. **Anti-Split-Brain Concurrency & Strict Idempotency**:
   - Concurrent duplicate `FinalizeFileUpload` requests for the same transfer must never produce race conditions, duplicate version numbers, or corrupted storage.
   - Protected via row-level locking (`SELECT ... FOR UPDATE` in PostgreSQL) or atomic CAS state transition:
     $$\text{UPDATE } file\_transfers \text{ SET status} = 'Finalizing' \text{ WHERE transfer\_id} = ? \text{ AND status} \in ('Created', 'Transferring');$$
   - If a request arrives while finalization is in-flight: awaits or serializes cleanly.
   - If finalization has already succeeded: returns deterministic success immediately (`AVAILABLE`, matching `available_at_unix_ms`).

5. **Atomic Version Promotion & Outbox Event**:
   - Within an atomic PostgreSQL transaction:
     - Insert record into `file_versions` (`version_number = N + 1`, `storage_key = objects/{file_id}/{version_number}`, `checksum_sha256`).
     - Update parent `files` state: `status = FileStatus::Available`, `updated_at = now`.
     - Update `file_transfers`: `status = TransferStatus::Completed`, `transferred_bytes = total_bytes`.
     - Insert outbox event in `files_outbox`: `event_type = FILE_AVAILABLE`.

6. **Staging Cleanup Policy**:
   - Following durable database commit of `AVAILABLE`, staging chunks (`staging/{transfer_id}/*`) are marked for asynchronous cleanup or purged, avoiding orphaned storage overhead.

---

## 3. Component Architecture & Flow Diagrams

### 3.1 Component Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         SecureCloud Files Service                           │
 │                                                                             │
 │  ┌───────────────────────────────────────────────────────────────────────┐  │
 │  │                          FilesServiceImpl                             │  │
 │  │  - FinalizeFileUpload RPC                                             │  │
 │  └───────────────────────────────────┬───────────────────────────────────┘  │
 │                                      │                                      │
 │  ┌───────────────────────────────────▼───────────────────────────────────┐  │
 │  │                     Finalization & Assembly Engine                    │  │
 │  │  ┌────────────────────────────┐    ┌───────────────────────────────┐  │  │
 │  │  │   FinalizationValidator    │    │      ObjectAssemblyEngine     │  │  │
 │  │  │  - Gapless index checking  │    │  - S3 compose / part concat   │  │  │
 │  │  │  - Size sum consistency    │    │  - Final key promotion:       │  │  │
 │  │  │  - Cumulative SHA-256      │    │    objects/{file_id}/{ver}    │  │  │
 │  │  └─────────────┬──────────────┘    └───────────────┬───────────────┘  │  │
 │  │                │                                   │                  │  │
 │  │  ┌─────────────▼───────────────────────────────────▼───────────────┐  │  │
 │  │  │                     FileFinalizationService                     │  │  │
 │  │  │  - Row-level lock / CAS anti-race guard                         │  │  │
 │  │  │  - Atomic version creation & lifecycle transition               │  │  │
 │  │  │  - Transactional outbox event generation: FILE_AVAILABLE        │  │  │
 │  │  │  - Safe failure handling (leaves retryable durable state)       │  │  │
 │  │  └─────────────┬───────────────────────────────────┬───────────────┘  │  │
 │  └────────────────┼───────────────────────────────────┼──────────────────┘  │
 │                   │                                   │                     │
 │  ┌────────────────▼───────────────┐   ┌───────────────▼──────────────────┐  │
 │  │        PostgreSQL 17           │   │            MinIO S3              │  │
 │  │  - file_transfers              │   │  - staging/{transfer_id}/*       │  │
 │  │  - file_chunks                 │   │  - objects/{file_id}/{version}   │  │
 │  │  - files (AVAILABLE)           │   │  (TCP 9000)                      │  │
 │  │  - file_versions (vN)          │   └──────────────────────────────────┘  │
 │  │  - files_outbox                │                                         │
 │  │  (TCP 5433)                    │                                         │
 │  └────────────────────────────────┘                                         │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

### 3.2 Concurrency & Idempotency Decision Matrix

| Current Transfer Status | Current File Status | Action for New `FinalizeFileUpload` Request | Result / Status Returned |
|:---|:---|:---|:---|
| `Transferring` | `UPLOADING` | Acquire row lock, transition to `FINALIZING`, verify and assemble | `OK` (`AVAILABLE`) on success; `FAILED` on error |
| `Finalizing` (Concurrent) | `UPLOADING` / `FINALIZING` | Detect in-flight finalization via CAS / DB row lock; block or serialise safely | Safe synchronization; no duplicate version |
| `Completed` | `AVAILABLE` | Detect already finalized transfer session | **Idempotent Success**: return existing `AVAILABLE` response |
| `Cancelled` | Any | Reject immediately | `FAILED_PRECONDITION` ("Transfer has been cancelled") |
| `Expired` | Any | Reject immediately | `DEADLINE_EXCEEDED` ("Transfer lease expired") |
| `Failed` | `FAILED` | Return failure reason; allow retry if permitted | `FAILED_PRECONDITION` / `INTERNAL` |

---

## 4. Implementation Tickets for Developer Louis

---

### FILES-006-T01 — Finalization Precondition & Integrity Validation Engine

1. **Ticket ID**: `FILES-006-T01`
2. **Title**: Finalization Precondition & Integrity Validation Engine
3. **Objective**: Implement `FinalizationValidator` in `src/files/domain/finalization_validator.{hpp,cpp}` to verify all 7 preconditions (transfer existence, state, completeness, zero gaps, size consistency, storage presence, and whole-object SHA-256 match).
4. **Architectural Purpose**: Enforces the fail-fast boundary before allocating multi-part S3 promotion resources or opening irreversible database commits.
5. **Scope**:
   - Create `src/files/domain/finalization_validator.hpp` and `.cpp`:
     ```cpp
     struct FinalizationValidationInput {
         FileTransferEntity transfer;
         FileEntity file;
         std::vector<FileChunkEntity> chunks;
         std::string expected_ciphertext_sha256;
     };

     struct FinalizationValidationResult {
         bool is_valid{true};
         std::string error_message;
         std::string computed_whole_sha256;

         [[nodiscard]] explicit operator bool() const noexcept { return is_valid; }
         static FinalizationValidationResult success(std::string hash);
         static FinalizationValidationResult failure(std::string message);
     };

     FinalizationValidationResult validate_finalization_preconditions(
         const FinalizationValidationInput& input);
     ```
   - Validation Rules:
     1. `transfer.status` must be `Transferring` or `Finalizing` (or `Created` if 0 chunks).
     2. `transfer.total_chunks == chunks.size()` and `transfer.accepted_chunks == transfer.total_chunks`.
     3. Chunk indices must be strictly contiguous from `0` to `total_chunks - 1` with no missing numbers or duplicates.
     4. Sum of all `chunk.chunk_size` must equal `file.encrypted_size`.
     5. Each chunk must have non-empty `minio_chunk_key` and non-empty `chunk_hash_sha256`.
     6. If `expected_ciphertext_sha256` is provided, validate format (64-char hex).
   - Implement unit test `tests/unit/files/finalization_validator_test.cpp`.
6. **Files to Create/Modify**:
   - `src/files/domain/finalization_validator.hpp` (New)
   - `src/files/domain/finalization_validator.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `tests/unit/files/finalization_validator_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`

---

### FILES-006-T02 — Object Assembly & S3 Promotion Engine

1. **Ticket ID**: `FILES-006-T02`
2. **Title**: Object Assembly & S3 Promotion Engine
3. **Objective**: Implement `ObjectAssemblyEngine` in `src/files/service/object_assembly_engine.{hpp,cpp}` to assemble/promote staged MinIO chunks (`staging/{transfer_id}/{0..N-1}`) into the immutable whole-file version object (`objects/{file_id}/{version_number}`).
4. **Architectural Purpose**: Implements the Zero-Plaintext whole-object assembly pipeline, orchestrating S3 concatenation, streaming hash calculation, and permanent version object promotion.
5. **Scope**:
   - Create `src/files/service/object_assembly_engine.hpp` and `.cpp`:
     ```cpp
     struct AssemblyResult {
         std::string target_object_key;
         uint64_t total_bytes{0};
         std::string computed_sha256;
     };

     class ObjectAssemblyEngine {
     public:
         explicit ObjectAssemblyEngine(std::shared_ptr<storage::S3Client> s3_client);

         AssemblyResult assemble_version_object(
             const std::string& file_id,
             int32_t target_version,
             const std::string& transfer_id,
             const std::vector<FileChunkEntity>& ordered_chunks);

         void cleanup_staging_chunks(
             const std::string& transfer_id,
             const std::vector<FileChunkEntity>& chunks);
     };
     ```
   - Core Behavior:
     - Constructs target permanent object key: `objects/{file_id}/{target_version}`.
     - For small/single-chunk files: reads staged chunk and puts to target key.
     - For multi-chunk files: concatenates chunks (via S3 multipart upload / compose or sequential stream), computing cumulative SHA-256 over ciphertext.
     - Validates that final assembled size matches total chunk size.
     - Provides `cleanup_staging_chunks` to remove staging keys after durable commit.
   - Implement unit test `tests/unit/files/object_assembly_engine_test.cpp`.
6. **Files to Create/Modify**:
   - `src/files/service/object_assembly_engine.hpp` (New)
   - `src/files/service/object_assembly_engine.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `tests/unit/files/object_assembly_engine_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`

---

### FILES-006-T03 — FileFinalizationService & Atomic Lifecycle Promotion Engine

1. **Ticket ID**: `FILES-006-T03`
2. **Title**: FileFinalizationService & Atomic Lifecycle Promotion Engine
3. **Objective**: Implement `FileFinalizationService` in `src/files/service/file_finalization_service.{hpp,cpp}` coordinating precondition validation, anti-split-brain locking, assembly invocation, and atomic PostgreSQL commit.
4. **Architectural Purpose**: Enforces the **Failure Rule** (AVAILABLE must NEVER be reported on failure) and **Anti-Split-Brain Concurrency**.
5. **Scope**:
   - Create `src/files/service/file_finalization_service.hpp` and `.cpp`:
     ```cpp
     struct FinalizeResult {
         std::string file_id;
         int32_t version_number{1};
         FileStatus status{FileStatus::Available};
         std::string checksum_sha256;
         std::chrono::system_clock::time_point available_at;
         bool is_idempotent_replay{false};
     };

     class FileFinalizationService {
     public:
         FileFinalizationService(
             std::shared_ptr<db::FilesDbConnectionPool> pool,
             std::shared_ptr<FileLifecycleService> lifecycle_service,
             std::shared_ptr<ObjectAssemblyEngine> assembly_engine,
             std::shared_ptr<FileTransferRepository> transfer_repo = nullptr,
             std::shared_ptr<FileChunkRepository> chunk_repo = nullptr,
             std::shared_ptr<FileRepository> file_repo = nullptr,
             std::shared_ptr<FileVersionRepository> version_repo = nullptr,
             std::shared_ptr<FilesOutboxRepository> outbox_repo = nullptr);

         FinalizeResult finalize_file_upload(
             const std::string& upload_id,
             const std::string& expected_file_id,
             const std::string& expected_ciphertext_sha256,
             const std::string& caller_user_id);
     };
     ```
   - Transactional & Concurrency Logic:
     1. **Idempotency Check**: If transfer is already `Completed`, retrieve active version and return `FinalizeResult` with `is_idempotent_replay = true` immediately.
     2. **Row Lock & CAS**: Begin transaction, `SELECT ... FOR UPDATE` on `file_transfers`. Verify caller ownership. Transition `transfer.status` to `Transferring → Finalizing`.
     3. **Precondition Validation**: Query all chunks, run `FinalizationValidator`. If invalid:
        - Abort transaction; update transfer to `Failed` if unrecoverable.
        - **Never report AVAILABLE.**
     4. **Object Assembly**: Call `assembly_engine->assemble_version_object(...)`. If assembly fails, throw exception and abort.
     5. **Hash Integrity Assertion**: Assert assembled hash matches `expected_ciphertext_sha256`. If mismatched, throw `ChunkIntegrityException`.
     6. **Atomic DB Commit**:
        - Insert `file_versions` record (version $N+1$).
        - Update `files.status = AVAILABLE`.
        - Update `file_transfers.status = Completed`.
        - Emit `files_outbox` event: `FILE_AVAILABLE`.
        - Commit transaction.
     7. **Asynchronous Cleanup**: Trigger `assembly_engine->cleanup_staging_chunks(...)`.
   - Implement unit test `tests/unit/files/file_finalization_service_test.cpp`.
6. **Files to Create/Modify**:
   - `src/files/service/file_finalization_service.hpp` (New)
   - `src/files/service/file_finalization_service.cpp` (New)
   - `src/files/CMakeLists.txt`
   - `tests/unit/files/file_finalization_service_test.cpp` (New)
   - `tests/unit/CMakeLists.txt`

---

### FILES-006-T04 — FilesServiceImpl gRPC Wiring: FinalizeFileUpload RPC

1. **Ticket ID**: `FILES-006-T04`
2. **Title**: FilesServiceImpl gRPC Wiring: FinalizeFileUpload RPC
3. **Objective**: Replace the `FinalizeFileUpload` skeleton in `src/files/service/files_service_impl.cpp` with the production handler wired to `FileFinalizationService`.
4. **Architectural Purpose**: Exposes finalization over gRPC mTLS, enforcing authentication, parameter decoding, status mappings, and secret-safe logging.
5. **Scope**:
   - Update `src/files/service/files_service_impl.hpp`:
     - Add `std::shared_ptr<FileFinalizationService> finalization_service` to `FilesServiceDependencies`.
   - Update `src/files/service/files_service_impl.cpp`:
     - Implement `FinalizeFileUpload`:
       - Verify caller mTLS identity (`check_peer_authorization`).
       - Validate `upload_id` format (UUIDv7).
       - Validate `file_id` format if supplied.
       - Delegate to `finalization_service->finalize_file_upload(upload_id, file_id, expected_sha256, peer_identity)`.
       - Map domain exceptions to gRPC status codes:
         - Missing chunks / incomplete $\to$ `FAILED_PRECONDITION` ("Required chunks missing for finalization").
         - Hash mismatch $\to$ `FAILED_PRECONDITION` ("Whole-ciphertext SHA-256 integrity mismatch").
         - Transfer not found $\to$ `NOT_FOUND`.
         - Transfer cancelled $\to$ `FAILED_PRECONDITION`.
         - Lease expired $\to$ `DEADLINE_EXCEEDED`.
         - Unauthorized caller $\to$ `PERMISSION_DENIED`.
       - Populate `FinalizeFileUploadResponse`: `file_id`, `lifecycle_state = AVAILABLE`, `available_at_unix_ms`.
       - Secret-Safe Logging: Log `upload_id`, `file_id`, version number, and duration.
   - Update `src/files/main.cpp` dependency wiring.
6. **Files to Create/Modify**:
   - `src/files/service/files_service_impl.hpp`
   - `src/files/service/files_service_impl.cpp`
   - `src/files/main.cpp`

---

### FILES-006-T05 — Comprehensive Unit Test Suite & Concurrency / Idempotency Simulation

1. **Ticket ID**: `FILES-006-T05`
2. **Title**: Comprehensive Unit Test Suite & Concurrency / Idempotency Simulation
3. **Objective**: Implement comprehensive unit test suites in `tests/unit/files/` testing precondition validation, assembly logic, failure rules, and explicit concurrency/idempotency races.
4. **Architectural Purpose**: Provides fast, deterministic regression testing with zero network dependencies.
5. **Scope**:
   - Implement unit tests:
     - `tests/unit/files/finalization_validator_test.cpp`:
       - Tests all 7 preconditions independently.
       - Missing chunk index gap detection (e.g., chunks [0, 2] with total=3 fails).
       - Size discrepancy (chunk byte sum != total file size fails).
       - Unmatched expected SHA-256 fails.
     - `tests/unit/files/object_assembly_engine_test.cpp`:
       - Single-chunk and multi-chunk concatenation via mock S3.
       - Validates target key format `objects/{file_id}/{ver}`.
       - Tests staging cleanup.
     - `tests/unit/files/file_finalization_service_test.cpp`:
       - **Failure Rule**: on simulated failure, verify `AVAILABLE` is never returned.
       - **Concurrency Test**: simulate two concurrent finalization calls on the same transfer session; verify exactly one creates version $N+1$, while the duplicate receives idempotent success with zero duplicate versions.
     - Expand `tests/unit/files/files_service_impl_test.cpp`:
       - Test `FinalizeFileUpload` gRPC handler with mock services and error mappings.
   - Register targets in `tests/unit/CMakeLists.txt`.
6. **Files to Create/Modify**:
   - `tests/unit/files/finalization_validator_test.cpp` (New)
   - `tests/unit/files/object_assembly_engine_test.cpp` (New)
   - `tests/unit/files/file_finalization_service_test.cpp` (New)
   - `tests/unit/files/files_service_impl_test.cpp` (Modify)
   - `tests/unit/CMakeLists.txt`

---

### FILES-006-T06 — Live End-to-End Integration Test Suite & Card Sign-Off

1. **Ticket ID**: `FILES-006-T06`
2. **Title**: Live End-to-End Integration Test Suite & Card Sign-Off
3. **Objective**: Implement live integration tests in `tests/integration/files_finalization_integration_test.cpp` against live PostgreSQL 17 (port 5433) and live MinIO S3 (port 9000).
4. **Architectural Purpose**: Authoritative verification that full-file assembly and lifecycle promotion execute reliably across real distributed storage and databases.
5. **Scope**:
   - Create `tests/integration/files_finalization_integration_test.cpp`:
     - **TC1: Happy Path Chunk Upload and Finalization**:
       - Create upload session, upload all chunks, invoke `FinalizeFileUpload`.
       - Verify file status transitions to `AVAILABLE`.
       - Verify permanent MinIO object exists at `objects/{file_id}/1`.
       - Verify `files_outbox` contains `FILE_AVAILABLE`.
     - **TC2: Concurrent Duplicate Finalization Race**:
       - Fire two simultaneous `FinalizeFileUpload` RPC requests for the same transfer across worker threads.
       - Assert both return success without errors.
       - Verify PostgreSQL contains exactly **one** version 1 record, not two.
     - **TC3: Incomplete Upload Rejection**:
       - Allocate 5-chunk upload; upload only chunks 0, 1, 2.
       - Call `FinalizeFileUpload`.
       - Assert rejection with `FAILED_PRECONDITION`.
       - Assert file state is NOT `AVAILABLE` (Failure Rule satisfied).
       - Verify chunks 0, 1, 2 remain safe in MinIO staging for retry.
     - **TC4: Whole-Ciphertext Hash Integrity Mismatch**:
       - Submit incorrect `expected_ciphertext_sha256`.
       - Assert rejection with `FAILED_PRECONDITION`.
       - Assert file is NOT `AVAILABLE`.
     - **TC5: Cancelled Session Finalization Guard**:
       - Cancel upload session via `CancelFileUpload`.
       - Attempting `FinalizeFileUpload` returns `FAILED_PRECONDITION`.
     - **TC6: Staging Object Cleanup**:
       - Verify staging keys `staging/{transfer_id}/*` are deleted or cleaned after successful finalization.
   - Register target in `tests/integration/CMakeLists.txt`.
   - Update walkthrough documentation (`docs/final-reports/walkthrough-files-006.md`).
6. **Files to Create/Modify**:
   - `tests/integration/files_finalization_integration_test.cpp` (New)
   - `tests/integration/CMakeLists.txt`
   - `docs/final-reports/walkthrough-files-006.md` (New)

---

## 5. Quality Gate & Sign-Off Checklist for Card FILES-006

- [x] **Zero-Plaintext Invariant**: Assembly concatenates pre-encrypted ciphertext only; no plaintext inspection or keys handled.
- [x] **Strict Precondition Verification**: Verifies transfer existence, correct state, chunk completeness, zero gaps, size consistency, storage presence, and whole-ciphertext SHA-256.
- [x] **Failure Rule Enforcement**: If finalization fails for any reason, `AVAILABLE` is never reported.
- [x] **Safe Durable State**: Incomplete or corrupted transfers leave staged chunks intact for diagnosis, recovery, or retry.
- [x] **Anti-Split-Brain Concurrency**: Concurrent finalizations for the same transfer are synchronized; zero duplicate versions or split-brain outbox events.
- [x] **Idempotent Replay**: Re-finalizing an already completed transfer returns immediate deterministic success.
- [x] **Atomic Version Promotion**: File version creation, `AVAILABLE` state update, and `FILE_AVAILABLE` outbox event occur in a single atomic database transaction.
- [x] **Staging Cleanup**: Staging chunks are safely cleaned after promotion to permanent storage.
- [x] **mTLS Peer Authentication**: gRPC endpoint enforces `DNS:gateway` SAN verification and initiator tenant isolation.
- [x] **Unit Test Coverage**: Deterministic unit tests covering validation rules, assembly, failure states, and concurrent races.
- [x] **Live Integration Verification**: Comprehensive integration test suite passing against PostgreSQL 17 (port 5433) and MinIO (port 9000).
- [x] **Cross-Platform Cleanliness**: Zero compilation warnings on Windows (MSVC x64 / MinGW-w64) and macOS (AppleClang).
- [x] **Non-Regression**: All existing M1, M2, and FILES-001 through FILES-005 tests pass without regression.
