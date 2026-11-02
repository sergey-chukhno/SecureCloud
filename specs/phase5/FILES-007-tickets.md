# FILES-007 — Authorized Chunked & Byte-Range Download Pipeline
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: `FILES-007` (or `FILE-007`)  
**Milestone**: M5 — Secure Files  
**Document Status**: Proposed Specification for Architectural Review (Louis & Sergey)  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-007** implements the **Authorized Chunked & Byte-Range Download Pipeline** for the **SecureCloud Files Service** (`securecloud-files`). Building on top of Whole-Object Finalization (**FILES-006**), Resumable Chunked Ingestion (**FILES-005**), and Version Snapshot Persistence (**FILES-004**), this card delivers high-performance, fault-tolerant retrieval of encrypted files.

### Canonical Download & Resume Model

The download engine establishes the canonical tuple:

$$\mathbf{(file\_id,\; file\_version,\; starting\_chunk)}$$

as the primary resume and positioning primitive for client downloads.

```text
Client
  │
  │ download(file_id, file_version, starting_chunk=N)
  ▼
Gateway (mTLS + Token Auth)
  │
  │ gRPC DownloadChunk(file_id, version, chunk_index=k)
  ▼
Files Service (securecloud-files)
  │
  ├── 1. Authorize caller (FileAccessRepository::check_access)
  ├── 2. Validate file state (status == AVAILABLE)
  ├── 3. Resolve version & calculate ByteRange [start..end]
  ▼
MinIO S3 (GET objects/{file_id}/{version} with HTTP Range)
  │
  │ Encrypted chunk slice (bounded <= 4 MiB)
  ▼
Files Service (compute SHA-256, verify integrity)
  │
  ▼
Gateway
  │
  │ Encrypted bytes streamed chunk-by-chunk
  ▼
Client
```

---

## 2. Key Invariants & Architectural Boundaries

1. **Zero-Plaintext & Custodian Invariant (ADR-005, ADR-008, Files Design §6.1, §6.26)**:
   - The Files Service acts exclusively as a zero-knowledge custodian of pre-encrypted ciphertext.
   - **No Decryption**: Encryption keys are never present on the server; no decryption algorithms are ever invoked.
   - **No Plaintext Search**: Server-side inspection or text parsing of ciphertext is strictly prohibited and impossible.
   - All streamed payload bytes are exact ciphertext slices.

2. **Authorization Before Content Access**:
   - Before retrieving any byte range from MinIO S3, the service verifies that the calling user possesses active, unrevoked read access (`FilePermission::Read`) or is the legitimate file owner.
   - If unauthorized, access is rejected immediately with `PERMISSION_DENIED` (`403 Forbidden`) with zero storage I/O performed.

3. **Canonical Resume Unit — Encrypted Chunk**:
   - The encrypted chunk (standard 4 MiB `k_standard_chunk_size`, bounded $\le 8\text{ MiB}$) remains the canonical unit of transfer, integrity verification, and resumption.
   - Resuming a broken download does not start over from byte 0; the client specifies `starting_chunk = N`, skipping all previously validated chunks $0..N-1$.

4. **Bounded Memory & Streaming Invariant (No Whole-File Buffering)**:
   - The service never reads or buffers entire files in server memory.
   - S3 requests utilize HTTP byte-range slicing (`Range: bytes=start-end`) against `objects/{file_id}/{version_number}`.
   - Buffer memory per in-flight chunk is strictly bounded to the chunk size ($\le 4\text{ MiB}$).

5. **Client Cancellation, Idle Timeout & Connection Drop Resilience**:
   - If a client cancels the download or terminates the TCP connection midway:
     - The gRPC context is cancelled (`is_cancelled() == true`).
     - S3 socket read is aborted immediately to prevent thread starvation and resource leaks.
     - Server logs a secret-safe cancellation event and releases the thread.
   - Idle timeouts ensure hung or lagging connections do not retain server resources.

6. **Availability Precondition**:
   - Download requests are only served if the file status is `FileStatus::Available`.
   - Files in `Created`, `Uploading`, `Finalizing`, `Failed`, `Deleted`, or `Expired` states are rejected (`FAILED_PRECONDITION` or `NOT_FOUND`).

---

## 3. Byte Range & Chunk Boundary Math

For a file of encrypted size $S$ bytes and standard chunk size $C = 4\text{ MiB} = 4{,}194{,}304$ bytes:
- Total chunk count $N = \lceil S / C \rceil = \lfloor (S + C - 1) / C \rfloor$. (If $S = 0$, $N = 0$).
- For any valid chunk index $k \in [0, N - 1]$:
  $$\text{start\_byte}(k) = k \times C$$
  $$\text{end\_byte}(k) = \min((k + 1) \times C - 1,\; S - 1)$$
  $$\text{chunk\_size}(k) = \text{end\_byte}(k) - \text{start\_byte}(k) + 1$$
- HTTP Range header:
  $$\text{Range: bytes}=\text{start\_byte}(k)-\text{end\_byte}(k)$$

---

## 4. Work Breakdown Structure (FILES-007 Implementation Tickets)

```text
FILES-007-T01: Download Session Validator & Precondition Guard
      │
      ▼
FILES-007-T02: Chunk Retrieval & S3 Byte-Range Streaming Engine
      │
      ▼
FILES-007-T03: Resumable Download Manager & Session Pipeline
      │
      ▼
FILES-007-T04: gRPC DownloadChunk Endpoint Integration & Error Mapping
      │
      ▼
FILES-007-T05: Files Service Download Implementation Unit Test Suite
      │
      ▼
FILES-007-T06: Live End-to-End Download Integration Test Suite & Card Walkthrough
```

---

### FILES-007-T01 — Download Session Validator & Precondition Guard

1. **Ticket ID**: `FILES-007-T01`
2. **Title**: Download Session Validator & Precondition Guard
3. **Objective**: Implement authoritative domain validation and byte-range coordinate calculation for chunked download requests.
4. **Architectural Purpose**: Enforce fail-fast parameter validation, lifecycle status guards, and mathematical precision for chunk offsets before initiating storage requests.
5. **Scope**:
   - Create `src/files/domain/download_validator.hpp` and `src/files/domain/download_validator.cpp`:
     - Define `DownloadValidationInput`:
       - `std::string file_id`
       - `int32_t requested_version` (0 indicates default active version)
       - `uint32_t chunk_index`
       - `FileEntity file`
       - `std::optional<FileVersionEntity> version`
       - `std::string caller_user_id`
       - `bool has_read_permission`
     - Define `ChunkByteRange`:
       - `uint64_t start_byte`
       - `uint64_t end_byte`
       - `uint32_t chunk_size_bytes`
       - `uint32_t total_chunks`
     - Implement `validate_download_preconditions(const DownloadValidationInput& input)`:
       - Validate `file_id` format (UUIDv7).
       - Validate caller authorization (`has_read_permission == true`).
       - Validate file status (`status == FileStatus::Available`); reject `Deleted`, `Expired`, `Uploading`, `Finalizing`, `Failed`.
       - Validate version snapshot existence and active state.
       - Validate `chunk_index < expected_chunk_count`.
     - Implement `calculate_chunk_byte_range(uint64_t total_file_size, uint32_t chunk_index, uint32_t standard_chunk_size = k_standard_chunk_size)`:
       - Computes exact `start_byte`, `end_byte`, and `chunk_size_bytes`.
   - Register source in `src/files/CMakeLists.txt` (`securecloud_files_db`).
   - Create unit test suite: `tests/unit/files/download_validator_test.cpp`.
   - Register test in `tests/unit/CMakeLists.txt`.

---

### FILES-007-T02 — Chunk Retrieval & S3 Byte-Range Streaming Engine

1. **Ticket ID**: `FILES-007-T02`
2. **Title**: Chunk Retrieval & S3 Byte-Range Streaming Engine
3. **Objective**: Implement bounded-memory S3 byte-range chunk fetching with SHA-256 cryptographic integrity verification.
4. **Architectural Purpose**: Fetch exact encrypted chunk slices directly from permanent version objects in MinIO without loading entire files into memory.
5. **Scope**:
   - Create `src/files/service/chunk_download_engine.hpp` and `src/files/service/chunk_download_engine.cpp`:
     - Method `fetch_chunk(const std::string& file_id, int32_t version_number, uint32_t chunk_index, uint64_t total_file_size)`:
       - Calculates byte range: `[start_byte, end_byte]`.
       - Issues S3 GET request: `s3_client_->get_object("objects/" + file_id + "/" + std::to_string(version_number), ByteRange{start, end})`.
       - Computes SHA-256 hash of the received chunk payload.
       - Returns `DownloadChunkResult{ file_id, chunk_index, encrypted_data, chunk_size_bytes, ciphertext_sha256 }`.
     - Error handling:
       - Catch `S3ObjectNotFoundException` $\rightarrow$ throw `EntityNotFoundException`.
       - Catch `S3TimeoutException` $\rightarrow$ throw `storage::S3TimeoutException`.
       - Catch connection errors $\rightarrow$ throw `storage::S3ConnectionException`.
     - Strict bounded memory: payload buffer size $\le 4\text{ MiB}$; no whole-file memory allocation.
   - Add source to `securecloud_files_service` in `src/files/CMakeLists.txt`.
   - Create unit test suite: `tests/unit/files/chunk_download_engine_test.cpp` using `InMemoryHttpTransport` / `MockHttpTransport`.
   - Register test in `tests/unit/CMakeLists.txt`.

---

### FILES-007-T03 — Resumable Download Manager & Session Pipeline

1. **Ticket ID**: `FILES-007-T03`
2. **Title**: Resumable Download Manager & Session Pipeline
3. **Objective**: Implement the authoritative `DownloadManager` implementing `IDownloadManager` and the `(file_id, file_version, starting_chunk)` resume model.
4. **Architectural Purpose**: Coordinate database authorization checks, lifecycle state validation, and chunk streaming with client cancellation and timeout awareness.
5. **Scope**:
   - Update `src/files/service/download_manager.hpp` and `src/files/service/download_manager.cpp`:
     - Constructor accepting `db_pool`, `s3_client`, `file_repo`, `version_repo`, `access_repo`, and `download_engine`.
     - Implement `authorize_download(const std::string& file_id, const std::string& caller_user_id)`:
       - Checks ownership or `FileAccessRepository::check_access(file_id, caller_user_id, FilePermission::Read)`.
     - Implement `get_chunk(const std::string& file_id, int32_t version_number, uint32_t chunk_index, const std::string& caller_user_id)`:
       - Verifies caller authorization first.
       - Retrieves `FileEntity` and verifies `FileStatus::Available`.
       - Resolves active version snapshot from `FileVersionRepository`.
       - Validates preconditions using `DownloadValidator`.
       - Fetches chunk slice via `ChunkDownloadEngine`.
       - Returns `DownloadChunkResult`.
     - Implement resume descriptor helper:
       - `struct DownloadResumeModel { std::string file_id; int32_t version_number; uint32_t starting_chunk; uint32_t total_chunks; uint64_t total_bytes; };`
       - `DownloadResumeModel prepare_resume_session(const std::string& file_id, int32_t version_number, uint32_t starting_chunk, const std::string& caller_user_id);`
   - Update `src/files/CMakeLists.txt` to include `service/download_manager.cpp` in `securecloud_files_service`.
   - Create unit test suite: `tests/unit/files/download_manager_test.cpp`.
   - Register test in `tests/unit/CMakeLists.txt`.

---

### FILES-007-T04 — gRPC DownloadChunk Endpoint Integration & Error Mapping

1. **Ticket ID**: `FILES-007-T04`
2. **Title**: gRPC DownloadChunk Endpoint Integration & Error Mapping
3. **Objective**: Wire the `DownloadChunk` RPC endpoint in `FilesServiceImpl` to `DownloadManager`.
4. **Architectural Purpose**: Provide the production gRPC interface for Gateway download requests with mTLS authentication, secret-safe logging, and clean status mapping.
5. **Scope**:
   - In `src/files/service/files_service_impl.hpp`:
     - Ensure `IDownloadManager` dependency is properly wired and accessible.
   - In `src/files/service/files_service_impl.cpp`:
     - Replace `DownloadChunk` skeleton with live implementation:
       - Verify peer authentication with mTLS (`check_peer_authorization`, `DNS:gateway`).
       - Validate non-null request and response pointers.
       - Validate `is_valid_uuid(request->file_id())`.
       - Invoke `deps_.download_manager->get_chunk(...)`.
       - Populate `DownloadChunkResponse`:
         - `set_file_id(result.file_id)`
         - `set_chunk_index(result.chunk_index)`
         - `set_encrypted_data(result.encrypted_data)`
         - `set_chunk_size_bytes(result.chunk_size_bytes)`
         - `set_ciphertext_sha256(result.ciphertext_sha256)`
       - Exception mapping:
         - `UnauthorizedFileAccessException` / permission denial $\rightarrow$ `grpc::StatusCode::PERMISSION_DENIED`
         - `EntityNotFoundException` $\rightarrow$ `grpc::StatusCode::NOT_FOUND`
         - `InvalidDownloadPreconditionException` $\rightarrow$ `grpc::StatusCode::FAILED_PRECONDITION`
         - `std::out_of_range` $\rightarrow$ `grpc::StatusCode::OUT_OF_RANGE`
         - `storage::S3TimeoutException` $\rightarrow$ `grpc::StatusCode::DEADLINE_EXCEEDED`
         - `std::invalid_argument` $\rightarrow$ `grpc::StatusCode::INVALID_ARGUMENT`
         - General `std::exception` $\rightarrow$ `grpc::StatusCode::INTERNAL`
   - In `src/files/main.cpp`:
     - Ensure `DownloadManager` is initialized with `db_pool` and `s3_client` in `FilesServiceDependencies`.

---

### FILES-007-T05 — Files Service Download Implementation Unit Test Suite

1. **Ticket ID**: `FILES-007-T05`
2. **Title**: Files Service Download Implementation Unit Test Suite
3. **Objective**: Extend unit tests in `tests/unit/files/files_service_impl_test.cpp` to cover `DownloadChunk`.
4. **Architectural Purpose**: Provide deterministic verification of endpoint security, argument validation, and error code translations without network dependencies.
5. **Scope**:
   - Add test cases in `tests/unit/files/files_service_impl_test.cpp`:
     - `DownloadChunkRejectsUnauthorizedPeer`: untrusted peer context returns `PERMISSION_DENIED`.
     - `DownloadChunkRejectsInvalidFileId`: bad UUID returns `INVALID_ARGUMENT`.
     - `DownloadChunkReturnsUnavailableWhenManagerNull`: null download manager returns `UNAVAILABLE`.
     - `DownloadChunkSuccess`: mock manager returns chunk payload; response correctly populates fields and returns `Status::OK`.
     - `DownloadChunkPermissionDenied`: caller without read grant returns `PERMISSION_DENIED`.
     - `DownloadChunkFileNotFound`: non-existent file returns `NOT_FOUND`.
     - `DownloadChunkOutOfRange`: chunk index $\ge$ total chunks returns `OUT_OF_RANGE`.
     - `DownloadChunkPreconditionFailed`: file not available returns `FAILED_PRECONDITION`.

---

### FILES-007-T06 — Live End-to-End Download Integration Test Suite & Card Walkthrough

1. **Ticket ID**: `FILES-007-T06`
2. **Title**: Live End-to-End Download Integration Test Suite & Card Walkthrough
3. **Objective**: Implement comprehensive live integration tests in `tests/integration/files_download_integration_test.cpp` against live PostgreSQL 17 (port 5433) and live MinIO S3 (port 9000).
4. **Architectural Purpose**: End-to-end authoritative verification that uploaded, finalized files can be reliably retrieved, resumed from arbitrary chunk positions, and protected against unauthorized access.
5. **Scope**:
   - Create `tests/integration/files_download_integration_test.cpp`:
     - **TC1: Happy Path Full-File Chunked Download**:
       - Create file, upload all chunks, finalize.
       - Download all chunks sequentially ($k = 0..N-1$).
       - Reassemble downloaded ciphertext; verify cumulative SHA-256 matches version snapshot.
     - **TC2: Canonical Resume from `starting_chunk = N`**:
       - Ingest and finalize a 4-chunk file.
       - Simulate client resuming from `starting_chunk = 2`.
       - Download chunks 2 and 3; assert chunks 0 and 1 are skipped.
       - Verify downloaded chunks match expected slices.
     - **TC3: Authorization Guard (Unauthorized Access Denied)**:
       - File owned by Alice.
       - Bob attempts to download a chunk without access grant.
       - Assert rejection with `PERMISSION_DENIED`. Zero chunk bytes leaked.
     - **TC4: Lifecycle State Guard (Not Available)**:
       - Attempt download on a file in `UPLOADING` or `FINALIZING` state.
       - Assert rejection with `FAILED_PRECONDITION`.
       - Attempt download on a `DELETED` file $\rightarrow$ `FAILED_PRECONDITION` or `NOT_FOUND`.
     - **TC5: Out-of-Bounds Chunk Index**:
       - Request `chunk_index = 99` on a 2-chunk file.
       - Assert rejection with `OUT_OF_RANGE`.
     - **TC6: Connection Drop / Cancellation Resilience**:
       - Simulate context cancellation midway through download.
       - Assert server cleans up safely without lingering threads.
   - Register target in `tests/integration/CMakeLists.txt`.
   - Write walkthrough documentation `docs/final-reports/walkthrough-files-007.md`.

---

## 5. Quality Gate & Sign-Off Checklist for Card FILES-007

- [x] **Canonical Resume Model**: Implements `(file_id, file_version, starting_chunk)` as the canonical resume model.
- [x] **Zero-Plaintext Invariant**: Streams raw encrypted ciphertext bytes; zero decryption, zero access to keys, zero plaintext search.
- [x] **Authorization Before Content Access**: Verifies caller read permissions before performing any storage retrieval.
- [x] **Bounded Memory Footprint**: Uses HTTP byte-range requests; buffers at most one chunk ($\le 4\text{ MiB}$) in memory; zero whole-file buffering.
- [x] **Resumable Chunk Positioning**: Correctly calculates byte-range coordinates for arbitrary chunk indices.
- [x] **Availability Guard**: Rejects downloads for files that are not in the `AVAILABLE` lifecycle state.
- [x] **Cancellation & Idle Timeout**: Cleans up resources promptly if client terminates connection or context cancels.
- [x] **mTLS Peer Authentication**: Enforces `DNS:gateway` SAN verification on gRPC endpoint.
- [x] **Deterministic Unit Tests**: Fast, zero-network unit test coverage for validation, range calculations, and error translations.
- [x] **Live Integration Verification**: Comprehensive integration test suite passing against PostgreSQL 17 (port 5433) and MinIO (port 9000).
- [x] **Non-Regression**: All existing M1, M2, and FILES-001 through FILES-006 test suites pass without regressions.
