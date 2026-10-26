# Walkthrough — Card FILES-005: Implement Resumable Chunked Uploads

**Card Identifier**: `FILES-005` (or `FILE-005`)  
**Milestone**: M5 — Secure Files  
**Branch**: `feature/files-005-implement-resumable-chunked-uploads`  
**Developer**: Louis  
**Lead & Security Architect**: Sergey  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary

Card **FILES-005** implements the authoritative **Resumable Chunked Upload Engine** for the **SecureCloud Files Service** (`securecloud-files`). Building upon the metadata and lifecycle subsystem (**FILES-004**), PostgreSQL 17 persistence layer (**FILES-002**), and MinIO S3 object storage foundation (**FILES-003**), this engine provides high-performance, fault-tolerant ingestion of encrypted file chunks.

Key capabilities delivered:
1. **Out-of-Order Chunk Processing**: Encrypted chunks can arrive, be verified, and staged in any arbitrary sequence.
2. **Authoritative Idempotency Semantics**: Repeated submissions of identical chunks produce deterministic success with zero duplicate S3 writes and zero database counter double-increments.
3. **Cryptographic Collision Detection**: Submissions of conflicting payload content for an already accepted chunk index are strictly rejected (`FAILED_PRECONDITION`), with zero silent overwrites.
4. **Crash Recovery & Resume Support**: In-memory state is non-authoritative. Following any service restart or network interruption, transfer progress is reconstructed directly from PostgreSQL (`file_transfers`, `file_chunks`) and MinIO staging (`staging/{transfer_id}/{chunk_index}`). Clients query missing chunks and resume upload without starting over from chunk 0.
5. **Bounded Memory Invariant**: Enforces a strict 8 MiB maximum chunk size (`k_max_chunk_size`), streaming chunks directly to MinIO staging without full-file buffering in RAM.
6. **Cancellation Lifecycle**: Clients can explicitly cancel an upload transfer session (`CancelFileUpload`), transitioning status to `CANCELLED` and rejecting subsequent chunk submissions.

---

## 2. Invariants & Architectural Guarantees

1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design §6.1, §6.26)**:
   - Chunks handled by the server are pre-encrypted ciphertext blocks prepared by the client.
   - The Files Service never inspects plaintext content, has no access to client keys, and computes SHA-256 digests strictly over the ciphertext bytes.

2. **Durable Authority & Crash Recovery Invariant (Backlog Item FILE-005)**:
   - In-memory data structures in `UploadSessionManager` are purely non-authoritative caches.
   - On cold restart or cache misses, transfer progress is reloaded from PostgreSQL `file_transfers` and `file_chunks`.

3. **Authoritative Idempotency Semantics**:
   - `(transfer_id, chunk_index)` with identical SHA-256: returns success with `is_duplicate = true` (idempotent ACK; no redundant S3 writes).
   - `(transfer_id, chunk_index)` with conflicting SHA-256: strictly rejected with `ChunkIntegrityException` / `FAILED_PRECONDITION`.

4. **Bounded Memory & Streaming Invariant**:
   - Chunks are bounded between 1 byte (`k_min_chunk_size`) and 8 MiB (`k_max_chunk_size`). Standard logical chunk size is 4 MiB (`k_standard_chunk_size`).
   - Non-terminal chunks must be exactly 4 MiB; terminal chunks must match the calculated remaining bytes.

5. **mTLS & Tenant Isolation Invariant**:
   - `UploadChunk` and `CancelFileUpload` enforce mTLS peer authentication (`DNS:gateway`).
   - Callers are verified against the transfer session initiator identity.

---

## 3. Tickets Implemented

### FILES-005-T01: Chunk Payload Validation Engine & Cryptographic Integrity Verifier
- Implemented `src/files/domain/chunk_validator.hpp` and `src/files/domain/chunk_validator.cpp`.
- Validation constants:
  - `k_standard_chunk_size = 4 MiB` (4194304 bytes)
  - `k_max_chunk_size = 8 MiB` (8388608 bytes hard limit)
  - `k_min_chunk_size = 1 byte`
  - `k_sha256_hex_length = 64`
- Implemented `validate_chunk_payload`:
  - Validates UUIDv7 / RFC 4122 format for `upload_id`.
  - Enforces `chunk_index < total_chunks`.
  - Asserts `chunk_size_bytes == encrypted_data.size()`.
  - Checks boundary sizes: non-terminal chunks must be 4 MiB, terminal chunk must match `total_file_size - (chunk_index * 4 MiB)`.
  - Computes OpenSSL SHA-256 over ciphertext and enforces case-insensitive match against `claimed_sha256`.
- Author unit test: `tests/unit/files/chunk_validator_test.cpp`.

### FILES-005-T02: Resumable Upload Session Manager & Crash-Recovery Reconstruction Engine
- Implemented `src/files/service/upload_session_manager.hpp` and `src/files/service/upload_session_manager.cpp`.
- Models & DTOs: `UploadSession`, `TransferProgress`.
- Exception hierarchy: `TransferException`, `TransferNotFoundException`, `TransferExpiredException`, `TransferCancelledException`, `UnauthorizedTransferException`.
- Implemented core operations:
  - `create_session`: Creates upload session, persists `FileTransferEntity` in DB, caches in RAM.
  - `reconstruct_session_from_storage`: Rebuilds transfer session dynamically from PostgreSQL `file_transfers` and `file_chunks`.
  - `get_transfer_progress`: Computes accepted vs missing chunk indices ($[0..N-1] \setminus \text{accepted}$). Checks lease expiration.
  - `get_missing_chunk_indices`: Extracts ordered missing chunk list for client resume.
  - `cancel_session`: Updates transfer status to `CANCELLED` in DB and memory.
  - Mutex synchronization for thread-safe concurrent access.
- Author unit test: `tests/unit/files/upload_session_manager_test.cpp`.

### FILES-005-T03: Idempotent Chunk Storage Engine & MinIO Chunk Staging Pipeline
- Implemented `src/files/service/chunk_storage_service.hpp` and `src/files/service/chunk_storage_service.cpp`.
- Canonical MinIO staging object key: `staging/{transfer_id}/{chunk_index}`.
- Storage & Idempotency Pipeline:
  - Verifies transfer session existence, status (`Created` / `Transferring`), and caller initiator identity.
  - Checks lease expiration against `system_clock::now()`.
  - Database idempotency pre-check:
    - Identical hash: returns `is_duplicate = true` immediately without S3 re-upload or counter increments.
    - Conflicting hash: throws `ChunkIntegrityException`.
  - MinIO staging: uploads chunk ciphertext via `s3_client_->put_object`.
  - Atomic PostgreSQL commit: records chunk in `file_chunks`, transitions `Created → Transferring` and file `CREATED → UPLOADING`, increments progress counters, transitions to `Finalizing` when `accepted == total_chunks`.
- Author unit test: `tests/unit/files/chunk_storage_service_test.cpp`.

### FILES-005-T04: FilesServiceImpl gRPC Wiring: UploadChunk & CancelFileUpload
- Updated `src/files/service/files_service_impl.hpp` to include `chunk_storage_service` in `FilesServiceDependencies`.
- Implemented production handlers in `src/files/service/files_service_impl.cpp`:
  - `UploadChunk`:
    - Checks mTLS peer authentication (`DNS:gateway`).
    - Maps protobuf request into `ChunkPayloadDto`.
    - Validates payload metadata and cryptographic SHA-256 via `ChunkValidator`.
    - Coordinates storage via `ChunkStorageService::store_chunk`.
    - Maps domain exceptions to gRPC status codes (`INVALID_ARGUMENT`, `NOT_FOUND`, `FAILED_PRECONDITION`, `DEADLINE_EXCEEDED`, `PERMISSION_DENIED`).
    - Enforces secret-safe operational logging (never logging ciphertext or keys).
  - `CancelFileUpload`:
    - Validates UUIDv7 `upload_id`.
    - Cancels active transfer session via `UploadSessionManager::cancel_session`.
    - Returns `TRANSFER_STATUS_CANCELLED`.
- Updated `src/files/main.cpp` dependency injection.

### FILES-005-T05: Comprehensive Unit Test Suite & Failure Simulation
- Author `tests/unit/files/chunk_validator_test.cpp`:
  - Tests known SHA-256 vectors ("" and "hello").
  - Single-chunk file payload validation.
  - Case-insensitive hex hash matching.
  - Rejection of invalid UUID, zero total chunks, out-of-bounds chunk index, size mismatches, empty chunks, oversized chunks (> 8 MiB), non-standard intermediate chunks, corrupted hashes.
- Author `tests/unit/files/upload_session_manager_test.cpp`:
  - In-memory session creation and retrieval.
  - Missing chunk index calculation for sparse/out-of-order uploads.
  - Session cancellation.
  - Non-existent session handling.
  - Concurrent chunk recording thread safety.
- Author `tests/unit/files/chunk_storage_service_test.cpp`:
  - Canonical staging key construction.
  - Staging chunk to mock S3 transport with payload verification.
- Expanded `tests/unit/files/files_service_impl_test.cpp`:
  - `UploadChunk` success path with verified SHA-256 response.
  - `UploadChunk` rejection of invalid UUID, not-found session, and SHA-256 mismatch.
  - `CancelFileUpload` success, invalid UUID, and not-found rejection.
- Registered all targets in `tests/unit/CMakeLists.txt`.

### FILES-005-T06: Live End-to-End Integration Test Suite & Card Sign-Off
- Implemented `tests/integration/files_resumable_upload_integration_test.cpp`:
  - Dual preflight probes (PostgreSQL 5433, MinIO 9000) with fallback to mock persistence.
  - **TC1: Multi-Chunk Out-of-Order Upload Progression**: 5-chunk upload in scrambled order `[3, 0, 4, 1, 2]` verifying completion and counter tracking.
  - **TC2: Idempotent Duplicate Chunk Replay**: Duplicate submission with matching hash succeeds without double-incrementing counters.
  - **TC3: Content Hash Collision / Conflict Rejection**: Conflicting chunk payload is rejected with `FAILED_PRECONDITION`.
  - **TC4: Service Restart Crash Recovery**: Mid-upload crash after 3 chunks; complete restart of service with clean memory cache successfully reconstructs progress, allows uploading remaining 3 chunks, and reaches completion.
  - **TC5: Client Reconnect & Resume Workflow**: Client disconnect simulation; queries missing indices `[1, 3]`; uploads only missing chunks to reach full completion.
  - **TC6: Explicit Cancellation**: Session cancelled; subsequent chunk submission fails fast with `FAILED_PRECONDITION`.
  - **TC7: End-to-End gRPC Roundtrip**: End-to-end gRPC invocation over mTLS channel verifying response structures.
- Registered `securecloud_files_resumable_upload_integration_test` in `tests/integration/CMakeLists.txt`.

---

## 4. Verification & Quality Checklist

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
