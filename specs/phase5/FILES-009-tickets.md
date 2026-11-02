# FILES-009 — Files Streaming, Resource Controls & Bounded Concurrency Pipeline
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: `FILES-009` (or `FILE-009`)  
**Milestone**: M5 — Secure Files  
**Document Status**: Proposed Specification for Architectural Review (Louis & Sergey)  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-009** implements the authoritative **Files Streaming, Resource Controls, and Bounded Concurrency Pipeline** for the **SecureCloud Files Service** (`securecloud-files`). Building upon Chunk Ingestion (**FILES-005**), Whole-Object Finalization (**FILES-006**), Chunked Downloads (**FILES-007**), and Capability Authorization (**FILES-008**), this card converts abstract performance and resilience requirements (ADR-009, ADR-010) into concrete, enforced runtime behaviors.

### Architectural Bulkheads (Isolated Concurrency Domains)
To prevent cross-domain starvation (e.g. high-volume file downloads starving lightweight metadata queries or upload finalizations), the Files Service partitions operational workloads into three strictly isolated, independently bounded concurrency domains (bulkheads):

```text
Incoming gRPC Requests
          │
          ├──► [ Metadata Operations Bulkhead ]  ──► Bounded Pool (e.g. 50 concurrent)
          │        (GetFileMetadata, Delete, Cancel, Capabilities)
          │
          ├──► [ Uploads Ingestion Bulkhead ]    ──► Bounded Pool (e.g. 20 concurrent)
          │        (CreateUpload, UploadChunk, FinalizeUpload)
          │
          └──► [ Downloads Retrieval Bulkhead ]  ──► Bounded Pool (e.g. 20 concurrent)
                   (DownloadChunk, Range Slicing)
```

Each domain operates under configured capacity ceilings, acquiring RAII-managed permits before touching CPU, database, memory, or S3 object storage.

---

## 2. Resource Ceilings & Bounds Matrix

All initial values are fully externalized in configuration (`FilesResourceConfig`), eliminating hardcoded architectural constants.

| Resource Dimension | Configuration Parameter | Default Limit | Enforcement Mechanism | Failure Policy |
| :--- | :--- | :--- | :--- | :--- |
| **Metadata Operations** | `max_concurrent_metadata_ops` | `50` | `DomainBulkhead::acquire` | `RESOURCE_EXHAUSTED` |
| **Active Uploads** | `max_concurrent_uploads` | `20` | `DomainBulkhead::acquire` | `RESOURCE_EXHAUSTED` |
| **Active Downloads** | `max_concurrent_downloads` | `20` | `DomainBulkhead::acquire` | `RESOURCE_EXHAUSTED` |
| **MinIO/S3 Storage Ops** | `max_concurrent_storage_ops` | `30` | `StoragePermitGuard` | Bounded wait / `RESOURCE_EXHAUSTED` |
| **PostgreSQL DB Connections** | `max_connections` | `10` | `FilesDbConnectionPool` | Bounded wait / `PoolTimeoutException` |
| **Active gRPC Streams** | `max_active_grpc_streams` | `40` | `StreamLimiter` | `RESOURCE_EXHAUSTED` |
| **Memory Buffer Budget** | `max_memory_buffer_bytes` | `64 MiB` | `MemoryBufferTracker` | Fail-fast `RESOURCE_EXHAUSTED` |
| **Chunk Processing Slots**| `max_chunk_processing_slots` | `50` | `ChunkSlotLimiter` | `RESOURCE_EXHAUSTED` |
| **Single Chunk Request Size** | `max_request_payload_bytes`| `5 MiB` | `MetadataValidator` entry guard | `INVALID_ARGUMENT` |
| **Maximum File Size** | `max_total_file_size_bytes`| `10 GiB` | Upload creation guard | `INVALID_ARGUMENT` |

---

## 3. Backpressure Architecture vs. Anti-Patterns

### 3.1 Legitimate Backpressure Flow

```text
Slow Client
    │
    ▼
Download / Upload stream slows down
    │
    ▼
Files Service stops pulling chunks from MinIO (or stops ingesting chunks)
    │
    ▼
Storage and Database pressure remains strictly bounded
    │
    ▼
Memory consumption remains clamped to active in-flight chunks (<= 4 MiB each)
```

### 3.2 Explicitly Forbidden Anti-Patterns (Architectural Violations)
The implementation strictly prohibits and includes automated guards against:
1. **Thread per Transfer**: Spawning an unjoined OS thread per upload/download transfer is strictly forbidden.
2. **Unbounded Queues**: In-memory task queues without fixed capacity limits are strictly forbidden.
3. **Whole-File Buffering**: Accumulating multi-gigabyte files into RAM prior to storage or streaming is strictly forbidden.
4. **Unlimited MinIO Operations**: Direct unbounded S3 socket dispatch is forbidden; all storage requests must acquire a storage bulkhead permit.
5. **Unlimited DB Connections**: Raw unpooled PostgreSQL connections are strictly forbidden.

---

## 4. Implementation Ticket Breakdown

### FILES-009-T01: Files Concurrency & Resource Configuration Model
- **Scope**: Externalize all resource limits into typed configuration with fail-closed validation.
- **Header**: `src/files/concurrency/resource_config.hpp`
- **Source**: `src/files/concurrency/resource_config.cpp` (and integrate into `FilesConfig`)
- **Unit Test**: `tests/unit/files/resource_config_test.cpp`
- **Deliverables**:
  - `FilesResourceConfig` struct with limits for metadata, uploads, downloads, storage, memory, and streams.
  - Environment variable mapping (`FILES_MAX_CONCURRENT_UPLOADS`, `FILES_MAX_CONCURRENT_DOWNLOADS`, `FILES_MAX_MEMORY_BUFFER_BYTES`, etc.).
  - Validation: reject negative, zero, or excessively large values (fail-closed).
  - Unit tests verifying default values, custom overrides, and invalid configurations.

### FILES-009-T02: Bounded Concurrency Bulkhead Engine & Domain Limiter
- **Scope**: Thread-safe RAII-based concurrency bulkheads isolating metadata, uploads, and downloads.
- **Header**: `src/files/concurrency/concurrency_bulkhead.hpp`
- **Source**: `src/files/concurrency/concurrency_bulkhead.cpp`
- **Unit Test**: `tests/unit/files/concurrency_bulkhead_test.cpp`
- **Deliverables**:
  - `ConcurrencyBulkhead` implementing semaphore semantics with configurable capacity and acquisition timeouts.
  - `Permit` RAII guard ensuring deterministic release upon completion, exception, or cancellation.
  - Metrics tracking: active count, available count, peak usage, rejection count.
  - Bulkhead coordinator managing separate domains: Metadata, Uploads, Downloads, Storage.
  - Unit tests verifying capacity clamping, timeout behavior, and RAII release.

### FILES-009-T03: Storage & Database Resource Control Decorator
- **Scope**: Bound MinIO/S3 object operations and coordinate with PostgreSQL connection pool.
- **Header**: `src/files/storage/bounded_storage_engine.hpp`
- **Source**: `src/files/storage/bounded_storage_engine.cpp`
- **Unit Test**: `tests/unit/files/bounded_storage_engine_test.cpp`
- **Deliverables**:
  - Decorator `BoundedStorageEngine` wrapping `IStorageEngine` with storage bulkhead permit acquisition.
  - Enforces `max_concurrent_storage_ops` ceiling on all S3 reads, writes, and deletions.
  - Integrates with S3 retry policy and timeout propagation.
  - Unit tests validating storage concurrency ceiling under concurrent load.

### FILES-009-T04: Chunk Processing & Memory Backpressure Pipeline
- **Scope**: Memory-bounded chunk tracking and backpressure enforcement preventing OOM.
- **Header**: `src/files/concurrency/memory_buffer_tracker.hpp`
- **Source**: `src/files/concurrency/memory_buffer_tracker.cpp`
- **Unit Test**: `tests/unit/files/memory_buffer_tracker_test.cpp`
- **Deliverables**:
  - `MemoryBufferTracker` tracking total live chunk buffer bytes across active transfers.
  - RAII `MemoryReservation` guard reserving and releasing byte budgets.
  - Request size validator: reject chunk requests exceeding `max_request_payload_bytes` (5 MiB).
  - Transfer size validator: reject upload sessions exceeding `max_total_file_size_bytes` (10 GiB).
  - Unit tests verifying memory budget saturation, reservation rejection, and clean release.

### FILES-009-T05: gRPC Service Concurrency Integration & Status Mapping
- **Scope**: Integrate bulkheads and backpressure into `FilesServiceImpl` endpoints.
- **Source**: `src/files/service/files_service_impl.cpp` & `files_service_impl.hpp`
- **Unit Test**: `tests/unit/files/files_service_impl_test.cpp`
- **Deliverables**:
  - Enforce Metadata bulkhead on `GetFileMetadata`, `DeleteFile`, `CancelFileUpload`.
  - Enforce Uploads bulkhead on `CreateFileUpload`, `UploadChunk`, `FinalizeFileUpload`.
  - Enforce Downloads bulkhead on `DownloadChunk`.
  - Strict gRPC status code mapping:
    - Domain saturation $\longrightarrow$ `grpc::StatusCode::RESOURCE_EXHAUSTED`
    - Memory budget exceeded $\longrightarrow$ `grpc::StatusCode::RESOURCE_EXHAUSTED`
    - Payload/file size exceeded $\longrightarrow$ `grpc::StatusCode::INVALID_ARGUMENT`
  - Unit tests verifying service status mappings under bulkhead saturation.

### FILES-009-T06: End-to-End Stress, Saturation & Backpressure Integration Tests & Walkthrough
- **Scope**: Live end-to-end integration test suite validating bulkheads, slow-client backpressure, and resource bounds.
- **Source**: `tests/integration/files_concurrency_integration_test.cpp`
- **CMake**: `tests/integration/CMakeLists.txt`
- **Walkthrough Document**: `docs/final-reports/walkthrough-files-009.md`
- **Deliverables**:
  - Integration test scenarios:
    1. **TC1: Bulkhead Isolation**: Upload/Download saturation leaves Metadata bulkhead completely unaffected.
    2. **TC2: Upload Concurrency Clamping**: Requests beyond `max_concurrent_uploads` receive `RESOURCE_EXHAUSTED`.
    3. **TC3: Download Concurrency Clamping**: Requests beyond `max_concurrent_downloads` receive `RESOURCE_EXHAUSTED`.
    4. **TC4: Storage Concurrency Bounding**: Concurrent S3 operations strictly respect ceiling.
    5. **TC5: Memory Budget Backpressure**: Clamps memory allocations; rejects excess chunks before allocation.
    6. **TC6: Slow Client Backpressure**: Simulates stalled client; verifies zero unrequested chunk fetching and zero memory explosion.
    7. **TC7: Oversized Request Rejection**: Payloads $> 5\text{ MiB}$ rejected immediately.
    8. **TC8: Oversized Transfer Rejection**: Files $> 10\text{ GiB}$ rejected at upload creation.
    9. **TC9: Deterministic RAII Release**: Crashed/cancelled operations return permits immediately.
    10. **TC10: Zero Plaintext / Zero Decryption Verification**: Ciphertext remains strictly encrypted.
  - Comprehensive walkthrough documentation.

---

## 5. Definition of Done & Quality Gate

- [ ] All 6 tickets (T01 through T06) designed, reviewed, and approved.
- [ ] Concurrency domains (Metadata, Uploads, Downloads) are strictly isolated bulkheads.
- [ ] No hardcoded limits: all capacities configured via `FilesResourceConfig`.
- [ ] Strict backpressure: slow clients do not cause memory accumulation or unbounded queues.
- [ ] Explicitly forbidden patterns verified: no thread-per-transfer, no unbounded queues, no whole-file buffering.
- [ ] All 10 integration test scenarios pass with zero memory leaks and clean permit recovery.
- [ ] Code builds cleanly with zero compiler warnings under `-Wall -Wextra -Wpedantic -Werror`.
- [ ] Walkthrough documentation completed in `docs/final-reports/walkthrough-files-009.md`.
