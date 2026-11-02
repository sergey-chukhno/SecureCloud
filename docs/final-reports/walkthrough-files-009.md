# Walkthrough Report: FILES-009 — Files Streaming, Resource Controls & Bounded Concurrency Pipeline

## Executive Summary
This document summarizes the technical design, architectural implementation, and verification for card **FILES-009: Files Streaming, Resource Controls & Bounded Concurrency Pipeline** under ADR-009.

FILES-009 establishes strict runtime resource controls across the Files Service. Concurrency is partitioned into independent domains (bulkheads), S3 operations are bounded via an active permit guard, global memory buffer allocations are capped with RAII reservations, request and transfer sizes are validated before buffer allocation, and backpressure pacing prevents slow clients from exhausting service memory.

---

## 1. Concurrency Bulkhead Architecture

Three bounded concurrency domains are isolated to prevent cross-domain starvation:
1. **Metadata Operations Domain**:
   - Covers `GetFileMetadata`, `DeleteFile`, `CancelFileUpload`, capability verification.
   - Saturated metadata operations fail-fast (`RESOURCE_EXHAUSTED`) without delaying active streaming data paths.
2. **Upload Operations Domain**:
   - Covers `CreateFileUpload`, `UploadChunk`, `FinalizeFileUpload`.
   - Bounded concurrent upload sessions prevent exhaustion of database and file storage threads.
3. **Download Operations Domain**:
   - Covers `DownloadChunk` and byte-range retrieval streams.
   - Ensures saturated download pipelines do not starve upload pipelines or metadata lookups.

All bounds and timeouts are loaded dynamically from environment variables / configuration sources:
- `SECURECLOUD_FILES_METADATA_MAX_CONCURRENCY` (Default: 100)
- `SECURECLOUD_FILES_UPLOAD_MAX_CONCURRENCY` (Default: 20)
- `SECURECLOUD_FILES_DOWNLOAD_MAX_CONCURRENCY` (Default: 50)
- `SECURECLOUD_FILES_STORAGE_MAX_CONCURRENCY` (Default: 30)
- `SECURECLOUD_FILES_MAX_MEMORY_BUFFER_BYTES` (Default: 64 MiB)
- `SECURECLOUD_FILES_MAX_CHUNK_REQUEST_BYTES` (Default: 5 MiB)
- `SECURECLOUD_FILES_MAX_FILE_TRANSFER_BYTES` (Default: 10 GiB)

---

## 2. Component Design & Implementation

### A. Resource Configuration Schema (`FILES-009-T01`)
- **Headers & Source**: `src/files/concurrency/resource_config.hpp`, `resource_config.cpp`
- **Embedding**: Integrated into `FilesConfig` (`src/files/files_config.hpp`, `files_config.cpp`).
- **Validation**: Fails closed if any positive limit is set to zero.

### B. Concurrency Bulkhead & Permit Limiter (`FILES-009-T02`)
- **Headers & Source**: `src/files/concurrency/concurrency_bulkhead.hpp`, `concurrency_bulkhead.cpp`
- **Permit Handle**: `BulkheadPermit` RAII handle decrements the domain counter automatically upon scope exit.
- **Acquire Modes**: Non-blocking `try_acquire()` and timed `acquire_with_timeout()`.

### C. Bounded Storage Engine Decorator (`FILES-009-T03`)
- **Headers & Source**: `src/files/storage/bounded_storage_engine.hpp`, `bounded_storage_engine.cpp`
- **Operation Guard**: Wraps `IStorageEngine` methods (`put_chunk`, `get_chunk`, `delete_chunk`, `put_file_object`, `get_file_object`, `delete_file_objects`, `delete_transfer_chunks`).
- **Timeout Exception**: Throws `StorageCapacityExhaustedException` when storage permits cannot be acquired within timeout.

### D. Global Memory Buffer Tracker & Size Validators (`FILES-009-T04`)
- **Headers & Source**: `src/files/concurrency/memory_buffer_tracker.hpp`, `memory_buffer_tracker.cpp`
- **Budget Tracking**: RAII `MemoryBufferReservation` reserves bytes from the global budget and releases them automatically.
- **Validators**: `validate_chunk_request_size` (<= 5 MiB), `validate_file_transfer_size` (<= 10 GiB).

### E. Service Implementation Integration (`FILES-009-T05`)
- **Source**: `src/files/service/files_service_impl.hpp`, `files_service_impl.cpp`
- **Bulkhead Enforcement**:
  - `CreateFileUpload`: Checks upload bulkhead permit and verifies `encrypted_size_bytes <= max_file_transfer_bytes`.
  - `UploadChunk`: Checks upload bulkhead permit, validates chunk request size <= 5 MiB, and reserves chunk memory from `MemoryBufferTracker`.
  - `FinalizeFileUpload`: Checks upload bulkhead permit.
  - `GetFileMetadata`: Checks metadata bulkhead permit.
  - `DownloadChunk`: Checks download bulkhead permit, validates chunk size, and reserves memory buffer budget.
  - `CancelFileUpload`: Checks metadata bulkhead permit.
  - `DeleteFile`: Checks metadata bulkhead permit.
- **Error Mapping**: Bulkhead saturation and memory exhaustion return `grpc::StatusCode::RESOURCE_EXHAUSTED`.

---

## 3. Verification & Test Matrix

| Test Suite | File | Scenarios Covered |
| :--- | :--- | :--- |
| **ResourceConfigTest** | `tests/unit/files/resource_config_test.cpp` | Default values, custom environment overrides, zero value fail-closed validation |
| **ConcurrencyBulkheadTest** | `tests/unit/files/concurrency_bulkhead_test.cpp` | Max capacity bounding, RAII release, timeout on saturation, concurrent stress test |
| **BoundedStorageEngineTest** | `tests/unit/files/bounded_storage_engine_test.cpp` | Null argument checks, transparent forwarding, concurrency throttling, exception throwing |
| **MemoryBufferTrackerTest** | `tests/unit/files/memory_buffer_tracker_test.cpp` | Budget reservation, RAII scope release, concurrent budget safety, request/transfer validators |
| **FilesServiceImplBulkheadTest** | `tests/unit/files/files_service_impl_test.cpp` | Mapping of metadata, upload, download bulkheads, memory exhaustion, oversized transfer rejection |
| **FilesConcurrencyIntegrationTest** | `tests/integration/files_concurrency_integration_test.cpp` | Bulkhead isolation, saturated download vs metadata, storage limits, non-blocking backpressure pacing |

---

## 4. Compliance with Anti-Pattern Constraints

- ✅ **No thread per transfer**: Transfers use event-driven worker tasks and non-blocking semaphore permits.
- ✅ **No unbounded queues**: Saturated domains reject immediately with `RESOURCE_EXHAUSTED` rather than enqueuing indefinitely.
- ✅ **No whole-file buffering**: Files remain chunk-addressed (4 MiB / 5 MiB chunks) streamed on-demand.
- ✅ **No unlimited MinIO operations**: All S3 operations pass through `BoundedStorageEngine` permit limiter.
- ✅ **No unlimited DB connections**: Pool is constrained via `FilesDbConnectionPool`.
- ✅ **Zero-Plaintext Invariant**: No decryption, no plaintext inspection; only opaque encrypted chunks are handled.
