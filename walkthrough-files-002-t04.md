# Walkthrough: FILES-002-T04 — Resumable FileTransfer & Idempotent FileChunk Repositories

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-002-T04`  
**Card**: `FILES-002` (Establish Files PostgreSQL Persistence)  
**Branch**: `feature/files-002-establish-files-postgresql-persistence`

Card `FILES-002-T04` establishes the persistence and repository layer for chunked resumable transfers and idempotent chunk uploads in the SecureCloud Files Service (`securecloud-files`). It enforces:
1. **Resumable Transfer Lifecycle Management**: Tracking active upload/download sessions (`file_transfers`), their chunk counts (`total_chunks`, `accepted_chunks`), transfer byte counters (`total_bytes`, `transferred_bytes`), and session expiration timestamps (`expires_at`).
2. **Strict Upload Idempotency**: Using PostgreSQL `ON CONFLICT (transfer_id, chunk_index) DO NOTHING` to safely accommodate network retries, connection drops, and re-sent chunks without duplicating byte counts or chunk records.
3. **Chunk Tampering & Integrity Verification**: On duplicate chunk submission (`ON CONFLICT`), querying the existing chunk record's SHA-256 hash. If identical, confirming idempotent replay (`ChunkRecordResult::AlreadyExistsIdentical`); if mismatched, throwing `ChunkIntegrityException` to abort corrupted or tampered payloads immediately.
4. **Ordered Chunk Progress Inspection**: Querying accepted chunk indices ordered ascending (`get_accepted_chunk_indices`) and chunk counts (`count_accepted_chunks`) to determine resume offsets for interrupted transfers.
5. **Zero-Plaintext Invariant (ADR-005, ADR-008)**: All chunk payloads remain client-encrypted. Chunks store MinIO storage references (`minio_chunk_key`), SHA-256 checksums, and chunk byte offsets without server plaintext access.

---

## 2. Key Components Delivered

### 2.1 FileTransferRepository (`src/files/repository/file_transfer_repository.{hpp,cpp}`)
- **Create Transfer Session (`create_transfer`)**:
  Inserts transfer session tracking records within transaction `tx`:
  ```sql
  INSERT INTO file_transfers (transfer_id, file_id, transfer_type, initiator_user_id, initiator_device_id,
                              status, total_chunks, accepted_chunks, total_bytes, transferred_bytes,
                              created_at, updated_at, expires_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);
  ```
- **Lookup Transfer (`find_by_id`)**:
  Retrieves transfer entity by ID either within a caller-provided transaction or via an autonomous session.
- **Update Status (`update_status`)**:
  Updates transfer session status (`CREATED`, `TRANSFERRING`, `FINALIZING`, `COMPLETED`, `FAILED`, `EXPIRED`, `CANCELLED`) and refreshes `updated_at`:
  ```sql
  UPDATE file_transfers SET status = $1, updated_at = $2 WHERE transfer_id = $3;
  ```
- **Atomic Progress Increment (`increment_chunk_progress`)**:
  Increments accepted chunk count and accumulates transferred byte count atomically:
  ```sql
  UPDATE file_transfers SET accepted_chunks = accepted_chunks + 1, transferred_bytes = transferred_bytes + $1, updated_at = $2
  WHERE transfer_id = $3;
  ```

### 2.2 FileChunkRepository (`src/files/repository/file_chunk_repository.{hpp,cpp}`)
- **Idempotent Chunk Insertion & Verification (`record_chunk`)**:
  Executes conflict-safe insert:
  ```sql
  INSERT INTO file_chunks (chunk_id, transfer_id, chunk_index, byte_offset, chunk_size, chunk_hash_sha256, minio_chunk_key, status, created_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
  ON CONFLICT (transfer_id, chunk_index) DO NOTHING;
  ```
  - **New Insertion**: If affected rows == 1, returns `ChunkRecordResult::NewlyInserted`.
  - **Idempotent Replay**: If affected rows == 0, queries existing record:
    ```sql
    SELECT chunk_hash_sha256 FROM file_chunks WHERE transfer_id = $1 AND chunk_index = $2;
    ```
    If SHA-256 matches: returns `ChunkRecordResult::AlreadyExistsIdentical` (safe, no progress duplication).
  - **Integrity Violation**: If SHA-256 differs: throws `ChunkIntegrityException` detailing expected vs. incoming hash.
- **Ordered Chunk Queries (`get_accepted_chunk_indices`, `list_chunks_for_transfer`)**:
  Queries indices and chunk entities ordered by `chunk_index ASC`.
- **Chunk Existence & Count (`is_chunk_present`, `count_accepted_chunks`)**:
  Fast query checks to support resumption protocols.

---

## 3. Testing & Verification

### 3.1 Unit Test Suite (`tests/unit/files/transfer_chunk_repository_test.cpp`)
16 targeted unit tests covering all operational and edge cases:
1. `CreateAndFindTransfer`: Verifies persistence and extraction of all transfer entity fields.
2. `FindNonExistentTransferReturnsNullopt`: Checks missing/empty ID handling.
3. `UpdateTransferStatus`: Transitions `Created → Transferring → Completed` and verifies timestamp update.
4. `IncrementChunkProgress`: Atomic chunk count and byte accumulation across multiple increments.
5. `CreateTransferValidationFailures`: Validates non-empty transfer_id, file_id, and initiator_user_id.
6. `TransferTransactionRollback`: Validates rollback semantics (`tx.abort()`).
7. `RecordChunkNewlyInserted`: Verifies chunk insertion and presence.
8. `RecordChunkIdempotentReplay`: Retrying chunk with matching hash returns `AlreadyExistsIdentical`.
9. `RecordChunkConflictHashMismatchThrowsIntegrityException`: Tampered hash throws `ChunkIntegrityException`.
10. `GetAcceptedChunkIndicesOrdered`: Out-of-order chunks (2, 0, 1) return ordered list `[0, 1, 2]`.
11. `CountAcceptedChunks`: Accurate chunk counts and zero-counts for non-existent transfers.
12. `IsChunkPresent`: Validates chunk presence, negative indices, and missing transfers.
13. `ListChunksForTransfer`: Verifies chunk entity lists ordered by index ASC with all metadata.
14. `ChunkValidationFailures`: Validates constraints (non-negative index/size, non-empty IDs/hashes).
15. `ChunkTransactionRollback`: Uncommitted chunk insertions abort cleanly.
16. `MultiTransferIsolation`: Verifies transfers A and B do not leak chunks or counts across sessions.

### 3.2 Verification Results
- **Unit Test Execution**:
  ```
  [==========] 16 tests from 1 test suite ran. (4 ms total)
  [  PASSED  ] 16 tests.
  ```
- **Local Dev Orchestrator (`verify-local.py`)**:
  ```
  ================ Verification Summary ================
    [PASSED]    7.85s  1. CMake Configure
    [PASSED]    0.28s  2. Formatting Check (.clang-format)
    [PASSED]   12.97s  3. Native Compilation & Build
    [PASSED]    0.47s  4. Protobuf & gRPC Contracts Validation
    [PASSED]   29.82s  5. CTest Execution Suite
  -----------------------------------------------------
  ALL CHECKS PASSED in 51.39s
  ```
- **CTest Suite**: **190 / 190 tests passing (100%)**.

---

## 4. Invariants Maintained
- **Zero-Plaintext Invariant (ADR-005, ADR-008)**: Transferred chunks and files store ciphertext metadata and hashes only.
- **Port 5432 Hard Invariant**: Development PostgreSQL remains strictly on port `5433`.
- **Idempotency Invariant**: Chunk retries never duplicate progress or corrupt storage state.
