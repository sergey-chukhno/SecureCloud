# Walkthrough — Card FILES-006: Whole-Object Finalization, Assembly & Integrity Verification Engine

**Card Identifier**: `FILES-006` (or `FILE-006`)  
**Milestone**: M5 — Secure Files  
**Branch**: `feature/files-006-implement-whole-object-finalization`  
**Developer**: Louis  
**Lead & Security Architect**: Sergey  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary

Card **FILES-006** delivers the authoritative **Whole-Object Finalization, Assembly, and Integrity Verification Engine** for the **SecureCloud Files Service** (`securecloud-files`). Building on top of the chunk ingestion engine (**FILES-005**), this engine governs the critical lifecycle transition:

$$\mathbf{UPLOADING \longrightarrow FINALIZING \longrightarrow AVAILABLE}$$

When a client signals that all chunks have been uploaded via `FinalizeFileUpload`, the service enforces strict precondition validation, verifies whole-ciphertext cryptographic integrity, concatenates staged chunks into immutable version objects in MinIO S3 (`objects/{file_id}/{target_version}`), durably promotes state in PostgreSQL, and stages transactional outbox events (`FILE_AVAILABLE`).

### Key Capabilities Delivered:
1. **Authoritative Precondition Engine**: Guarantees that finalization executes only when transfer exists, is in a valid state, all expected chunks are present, zero gaps exist in chunk indexing ($0..N-1$), and chunk size summation strictly equals parent file size.
2. **Whole-Object S3 Assembly**: Staged chunks in MinIO (`staging/{transfer_id}/{0..N-1}`) are assembled in strictly increasing order into the permanent object key `objects/{file_id}/{target_version}`.
3. **Whole-Ciphertext Integrity Guard**: Calculates cumulative whole-ciphertext SHA-256 and compares it case-insensitively with client-supplied `expected_ciphertext_sha256`. Any mismatch aborts the transaction immediately.
4. **Strict Failure Rule**: If finalization fails for any reason, `AVAILABLE` is **NEVER** reported. Staged chunks remain intact in MinIO and PostgreSQL for diagnosis and retry.
5. **Anti-Split-Brain Concurrency & Idempotency**: Concurrent finalization requests for the same upload are synchronized via transactional row locking; re-finalizing an already completed transfer returns immediate deterministic success with zero duplicate versions or outbox events.
6. **Atomic State & Outbox Promotion**: Creates immutable `file_versions` record, transitions `files` to `AVAILABLE`, transitions `file_transfers` to `COMPLETED`, and writes `FILE_AVAILABLE` event to `files_outbox` in a single ACID transaction.
7. **Post-Commit Staging Cleanup**: Removes temporary chunk keys from MinIO staging only after durable PostgreSQL commit has succeeded.

---

## 2. Invariants & Architectural Guarantees

1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design §6.1, §6.26)**:
   - The engine operates exclusively over pre-encrypted ciphertext blocks.
   - The Files Service has zero access to client encryption keys or plaintext.
   - Verification evaluates SHA-256 strictly over whole ciphertext data.

2. **Strict Verification Preconditions**:
   Before transitioning any state from `FINALIZING` to `AVAILABLE`:
   - Transfer exists and is in `Transferring` or `Finalizing` status.
   - `accepted_chunks == total_chunks` and staged chunk count matches `total_chunks`.
   - Chunk indices strictly span $0, 1, \dots, N-1$ with no missing gaps.
   - Sum of chunk sizes equals `transfer.total_bytes` and `file.encrypted_size`.
   - All chunks have non-empty MinIO keys and valid 64-hex SHA-256 digests.

3. **Failure Rule — Never Premature `AVAILABLE`**:
   - If any verification or assembly step fails:
     $$\mathbf{AVAILABLE} \text{ is NEVER reported.}$$
   - The database transaction is rolled back.
   - Staged chunks remain safely in storage for recovery/retry.

4. **Anti-Split-Brain Concurrency & Idempotency**:
   - Simultaneous requests for the same `upload_id` are synchronized.
   - Exactly one version record and one outbox event are created.
   - Subsequent calls return deterministic idempotent success (`is_idempotent_replay = true`).

---

## 3. Tickets Implemented

### FILES-006-T01: Precondition Validation Engine & Finalization Verifier
- **Header**: [src/files/domain/finalization_validator.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/finalization_validator.hpp)
- **Source**: [src/files/domain/finalization_validator.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/finalization_validator.cpp)
- **Unit Test**: [tests/unit/files/finalization_validator_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/finalization_validator_test.cpp)
- Implemented `validate_finalization_preconditions` enforcing all 7 verification rules.

### FILES-006-T02: Staging-to-Version Object Assembly Engine
- **Header**: [src/files/service/object_assembly_engine.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/object_assembly_engine.hpp)
- **Source**: [src/files/service/object_assembly_engine.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/object_assembly_engine.cpp)
- **Unit Test**: [tests/unit/files/object_assembly_engine_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/object_assembly_engine_test.cpp)
- Implemented `assemble_version_object` (sequential chunk retrieval, corruption check, whole-ciphertext SHA-256 calculation, and upload to `objects/{file_id}/{target_version}`) and `cleanup_staging_chunks`.

### FILES-006-T03: Whole-Object Finalization Service & Atomic State Machine
- **Header**: [src/files/service/file_finalization_service.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/file_finalization_service.hpp)
- **Source**: [src/files/service/file_finalization_service.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/file_finalization_service.cpp)
- **Unit Test**: [tests/unit/files/file_finalization_service_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/file_finalization_service_test.cpp)
- Implemented ACID transaction pipeline: idempotent check, status transition to `FINALIZING`, chunk loading, precondition validation, S3 assembly, cryptographic hash verification, version snapshot creation, status transition to `AVAILABLE`, and `FILE_AVAILABLE` outbox event staging.

### FILES-006-T04: gRPC FinalizeFileUpload Endpoint Integration & Error Mapping
- **Header**: [src/files/service/files_service_impl.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/files_service_impl.hpp)
- **Source**: [src/files/service/files_service_impl.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/files_service_impl.cpp)
- **Entrypoint**: [src/files/main.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/main.cpp)
- Wired `FinalizeFileUpload` RPC endpoint to `FileFinalizationService`, enforcing mTLS peer authentication (`DNS:gateway`), secret-safe scope logging, and error code mapping (`NOT_FOUND`, `FAILED_PRECONDITION`, `DEADLINE_EXCEEDED`, `PERMISSION_DENIED`).

### FILES-006-T05: Files Service Implementation Unit Test Suite
- **Source**: [tests/unit/files/files_service_impl_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/files_service_impl_test.cpp)
- Added tests verifying unauthorized peer rejection, invalid file ID format rejection, unavailable service handling, successful finalization response formatting, and exception-to-gRPC-status mapping.

### FILES-006-T06: Live End-to-End Integration Test Suite
- **Source**: [tests/integration/files_finalization_integration_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/integration/files_finalization_integration_test.cpp)
- **CMake**: [tests/integration/CMakeLists.txt](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/integration/CMakeLists.txt)
- Implemented comprehensive scenarios:
  1. `TC1_HappyPathFinalizationMultiChunk`: Full multi-chunk upload, finalization with valid SHA-256, version creation, and outbox event verification.
  2. `TC2_ConcurrentDuplicateFinalizationRaceAndIdempotency`: Concurrent duplicate finalization calls race safely, producing exactly one version snapshot.
  3. `TC3_IncompleteUploadRejectionAndStagedChunkRetention`: Missing chunk 1 rejected with `FAILED_PRECONDITION`; file never becomes `AVAILABLE`; staged chunks remain in storage.
  4. `TC4_WholeCiphertextHashMismatchRejection`: Incorrect whole-file checksum strictly rejected; file never becomes `AVAILABLE`.
  5. `TC5_CancelledSessionGuard`: Cancelled session rejected with `FAILED_PRECONDITION`.
  6. `TC6_StagingCleanupVerification`: Staging keys cleaned and permanent object key created.

---

## 4. Verification & Validation Summary

| Test Suite | File | Tests Implemented | Result |
| :--- | :--- | :--- | :--- |
| **Finalization Validator Tests** | [finalization_validator_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/finalization_validator_test.cpp) | 9 | PASS |
| **Object Assembly Engine Tests** | [object_assembly_engine_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/object_assembly_engine_test.cpp) | 5 | PASS |
| **Finalization Service Tests** | [file_finalization_service_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/file_finalization_service_test.cpp) | 3 | PASS |
| **FilesServiceImpl Unit Tests** | [files_service_impl_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/files_service_impl_test.cpp) | 7 | PASS |
| **Live Finalization Integration Tests** | [files_finalization_integration_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/integration/files_finalization_integration_test.cpp) | 6 | PASS |

---

## 5. Conclusion & Next Steps

Card **FILES-006** is fully completed and verified according to all architectural requirements, quality gates, and zero-plaintext invariants.

Ready for next card: **FILES-007: Authorized Chunked & Byte-Range Download Pipeline**.
