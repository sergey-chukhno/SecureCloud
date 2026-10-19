# Walkthrough: FILES-002-T03 — File, Version & Encrypted Metadata Repositories

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-002-T03`  
**Card**: `FILES-002` (Establish Files PostgreSQL Persistence)  
**Branch**: `feature/files-002-establish-files-postgresql-persistence`

Card `FILES-002-T03` establishes the repository layer for files, immutable versions, and client-side encrypted metadata in the SecureCloud Files Service (`securecloud-files`). It enforces:
1. **Atomic File & Encrypted Metadata Creation**: Writing logical file catalog records and client-side encrypted metadata fields simultaneously within a single atomic PostgreSQL transaction (`pqxx::work`).
2. **Server-Side File Lifecycle Enforcement**: Validating legal status transitions (`CREATED → UPLOADING → FINALIZING → AVAILABLE → EXPIRED/DELETED`) and rejecting illegal jumps (e.g. transitioning an `AVAILABLE` file back to `UPLOADING`) with `InvalidStateTransitionException`.
3. **Optimistic Concurrency Control**: Status transitions require matching the `expected_current` state (`WHERE file_id = $1 AND status = $2`), preventing lost updates and race conditions during multi-chunk finalizing.
4. **Version Immutability & Constraint Tracking**: Enforcing `UNIQUE(file_id, version_number)` and managing active snapshot status flags.
5. **Zero-Plaintext Invariant (ADR-005, ADR-008)**: Persisting client-side metadata strictly as encrypted bytea fields with associated nonces, tags, and KDF metadata.

---

## 2. Key Components Delivered

### 2.1 FileRepository (`src/files/repository/file_repository.{hpp,cpp}`)
- **Atomic File Creation (`create_file`)**:
  Inserts master record into `files` table and client-encrypted metadata into `encrypted_file_metadata` within transaction `tx`:
  ```sql
  INSERT INTO files (file_id, owner_user_id, owner_device_id, conversation_id, encrypted_size, content_type, encryption_algorithm, status, retention_until, created_at, updated_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

  INSERT INTO encrypted_file_metadata (file_id, encrypted_filename, encrypted_mime_type, metadata_nonce, metadata_tag, client_encryption_metadata, updated_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7);
  ```
- **Lifecycle Transition Validation (`is_valid_state_transition`)**:
  Enforces valid state graph:
  - `CREATED` → `UPLOADING` | `FAILED`
  - `UPLOADING` → `FINALIZING` | `FAILED`
  - `FINALIZING` → `AVAILABLE` | `FAILED`
  - `AVAILABLE` → `EXPIRED` | `DELETED`
  - `EXPIRED` → `DELETED`
  - Terminal states (`DELETED`, `FAILED`): No outgoing transitions permitted.
  - Any illegal transition throws `InvalidStateTransitionException`.
- **Optimistic Concurrency Status Update (`update_status`)**:
  ```sql
  UPDATE files SET status = $1, updated_at = $2
  WHERE file_id = $3 AND status = $4;
  ```
  Returns `true` if updated; returns `false` if `expected_current` did not match (preventing race conditions).
- **Logical Deletion (`delete_file_logical`)**:
  Sets status to `DELETED` and updates timestamp without physically deleting metadata until retention scrub.
- **Retention Scrubber Query (`find_expired_files`)**:
  ```sql
  SELECT file_id, owner_user_id, ... FROM files
  WHERE retention_until IS NOT NULL AND retention_until <= $1 AND status != 'DELETED'
  ORDER BY retention_until ASC LIMIT $2;
  ```

### 2.2 FileVersionRepository (`src/files/repository/file_version_repository.{hpp,cpp}`)
- **Immutable Version Creation (`create_version`)**:
  ```sql
  INSERT INTO file_versions (version_id, file_id, version_number, encrypted_size, minio_object_key, checksum_sha256, created_at, is_active)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
  ```
  Enforces `UNIQUE(file_id, version_number)`; throws `UniqueConstraintViolationException` on duplicate.
- **Automatic Version Deactivation**:
  When a new version is marked active (`is_active = true`), previous versions for the file are deactivated:
  ```sql
  UPDATE file_versions SET is_active = FALSE WHERE file_id = $1 AND version_number != $2;
  ```
- **Active Version Lookup (`find_active_version`)**:
  Queries the latest active version for a given `file_id`.
- **Version History Listing (`list_versions`)**:
  Lists all versions ordered by `version_number` ascending.

---

## 3. Verification & Test Results

### 3.1 Unit Test Suite (`tests/unit/files/file_repository_test.cpp`)
Implemented 11 comprehensive unit test cases:
1. `FileRepositoryTest.AtomicCreateAndRetrieveFileAndMetadata`: Tests atomic insertion and retrieval of files and metadata.
2. `FileRepositoryTest.CreateFileRejectsIdMismatch`: Validates rejection when file ID does not match metadata file ID.
3. `FileRepositoryTest.TransactionAbortRollsBackCreation`: Validates that uncommitted transactions leave zero orphaned records.
4. `FileRepositoryTest.FindByIdReturnsNulloptForMissing`: Validates safe handling of non-existent and empty IDs.
5. `FileRepositoryTest.ValidLifecycleTransitionsSucceed`: Validates full sequential lifecycle from `CREATED` to `DELETED`.
6. `FileRepositoryTest.InvalidStateTransitionThrowsException`: Validates that illegal jumps (e.g. `AVAILABLE → UPLOADING`, `DELETED → AVAILABLE`) throw `InvalidStateTransitionException`.
7. `FileRepositoryTest.OptimisticConcurrencyMismatchReturnsFalse`: Validates concurrency failure when current status differs from expected.
8. `FileRepositoryTest.LogicalDeleteSetsStatusToDeleted`: Validates logical deletion.
9. `FileRepositoryTest.FindExpiredFilesRetrievesExpiredNonDeletedOnly`: Validates retention deadline query filters.
10. `FileVersionRepositoryTest.CreateAndQueryVersions`: Validates version creation, active version switching, and version ordering.
11. `FileVersionRepositoryTest.UniqueConstraintViolationOnDuplicateVersion`: Validates unique constraint on duplicate `(file_id, version_number)`.

**Execution Result**:
```text
Running main() from gtest_main.cc
[==========] Running 11 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 9 tests from FileRepositoryTest
[ RUN      ] FileRepositoryTest.AtomicCreateAndRetrieveFileAndMetadata
[       OK ] FileRepositoryTest.AtomicCreateAndRetrieveFileAndMetadata (0 ms)
[ RUN      ] FileRepositoryTest.CreateFileRejectsIdMismatch
[       OK ] FileRepositoryTest.CreateFileRejectsIdMismatch (0 ms)
[ RUN      ] FileRepositoryTest.TransactionAbortRollsBackCreation
[       OK ] FileRepositoryTest.TransactionAbortRollsBackCreation (0 ms)
[ RUN      ] FileRepositoryTest.FindByIdReturnsNulloptForMissing
[       OK ] FileRepositoryTest.FindByIdReturnsNulloptForMissing (0 ms)
[ RUN      ] FileRepositoryTest.ValidLifecycleTransitionsSucceed
[       OK ] FileRepositoryTest.ValidLifecycleTransitionsSucceed (1 ms)
[ RUN      ] FileRepositoryTest.InvalidStateTransitionThrowsException
[       OK ] FileRepositoryTest.InvalidStateTransitionThrowsException (0 ms)
[ RUN      ] FileRepositoryTest.OptimisticConcurrencyMismatchReturnsFalse
[       OK ] FileRepositoryTest.OptimisticConcurrencyMismatchReturnsFalse (0 ms)
[ RUN      ] FileRepositoryTest.LogicalDeleteSetsStatusToDeleted
[       OK ] FileRepositoryTest.LogicalDeleteSetsStatusToDeleted (0 ms)
[ RUN      ] FileRepositoryTest.FindExpiredFilesRetrievesExpiredNonDeletedOnly
[       OK ] FileRepositoryTest.FindExpiredFilesRetrievesExpiredNonDeletedOnly (0 ms)
[----------] 9 tests from FileRepositoryTest (3 ms total)

[----------] 2 tests from FileVersionRepositoryTest
[ RUN      ] FileVersionRepositoryTest.CreateAndQueryVersions
[       OK ] FileVersionRepositoryTest.CreateAndQueryVersions (0 ms)
[ RUN      ] FileVersionRepositoryTest.UniqueConstraintViolationOnDuplicateVersion
[       OK ] FileVersionRepositoryTest.UniqueConstraintViolationOnDuplicateVersion (0 ms)
[----------] 2 tests from FileVersionRepositoryTest (0 ms total)

[----------] Global test environment tear-down
[==========] 11 tests from 2 test suites ran. (5 ms total)
[  PASSED  ] 11 tests.
```

### 3.2 Full Regression Suite (`verify-local.py`)
Executed the repository-level verification pipeline across all 5 verification stages:
```text
================ Verification Summary ================
  [PASSED]    4.62s  1. CMake Configure
  [PASSED]    0.20s  2. Formatting Check (.clang-format)
  [PASSED]    0.66s  3. Native Compilation & Build
  [PASSED]    0.27s  4. Protobuf & gRPC Contracts Validation
  [PASSED]   27.15s  5. CTest Execution Suite (174/174 passed)
-----------------------------------------------------
ALL CHECKS PASSED in 32.90s
```
**Total passing test cases**: **174 / 174 tests passed (100%)**.

---

## 4. Next Ticket
- **Ticket**: `FILES-002-T04` — Resumable FileTransfer & Idempotent FileChunk Repositories (`src/files/repository/file_transfer_repository.{hpp,cpp}`, `src/files/repository/file_chunk_repository.{hpp,cpp}`).
