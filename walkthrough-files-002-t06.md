# Walkthrough: FILES-002-T06 — PostgreSQL Persistence Integration & Lifecycle Restart Test Suite

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-002-T06`  
**Card**: `FILES-002` (Establish Files PostgreSQL Persistence)  
**Branch**: `feature/files-002-establish-files-postgresql-persistence`

Card `FILES-002-T06` concludes the implementation of **FILES-002** by delivering an end-to-end integration and restart durability test suite (`tests/integration/files_postgres_persistence_integration_test.cpp`). It validates:
1. **Database Isolation & Privilege Boundary (ADR-005, Files Design 6.17)**: Proving that `files_user` connects strictly to `securecloud_files` on port `5433`, that host workstation port `5432` is never touched (`PortForbiddenException`), and that `files_user` is strictly denied access to `securecloud_auth`.
2. **Atomic Entity & Metadata Roundtrip**: Verifying atomic creation of `FileEntity` and `EncryptedFileMetadataEntity` in a single transaction, with bit-identical binary validation of bytea fields (`encrypted_filename`, `metadata_nonce`, `metadata_tag`).
3. **Resumable Transfer Lifecycle & Idempotency**: Creating a multi-chunk transfer session, progressively inserting chunks, querying accepted vs. missing chunks, and proving idempotent retry behavior without data duplication.
4. **Atomic Finalization & Transactional Outbox Staging (ADR-005, Files Design 6.22)**: Executing file finalization (transition to `Available`, version #1 creation, transfer completion, and outbox event staging) atomically within `pqxx::work`.
5. **Durable State Across Service Restart**: Simulating complete service teardown (destroying all connection pool and repository instances in memory) followed by cold restart and verification that 100% of persisted entities, versions, chunks, and outbox records remain intact.

---

## 2. Key Components Delivered

### 2.1 Persistence Integration Test Suite (`tests/integration/files_postgres_persistence_integration_test.cpp`)
- **Deterministic Fixture Setup & Winsock Handling**:
  Initializes Winsock on Windows and resets state cleanly across test cases.
- **Test Case 1: DatabaseIsolationAndPrivilegeGuard**:
  - Validates `ConnectionPoolConfig` targeting `127.0.0.1:5433` and `securecloud_files` as `files_user`.
  - Enforces rejection of port `5432` via `PortForbiddenException`.
  - Verifies denial of access when attempting to connect to `securecloud_auth` as `files_user`.
- **Test Case 2: AtomicFileCreationAndMetadataRoundtrip**:
  - Atomically creates `FileEntity` and `EncryptedFileMetadataEntity` in single `pqxx::work`.
  - Asserts bit-identical roundtrip of bytea encrypted filename, 24-byte nonce, 16-byte Poly1305 tag, and JSON client encryption metadata.
- **Test Case 3: ResumableTransferLifecycleAndProgressState**:
  - Establishes a 5-chunk upload session.
  - Ingests chunks 0, 1, 2 while tracking transferred byte counts and accepted chunk counts.
  - Asserts missing chunks are deterministically `{3, 4}`.
  - Simulates duplicate client retry of chunk 1 and asserts `ChunkRecordResult::AlreadyExistsIdentical` without duplicating progress.
- **Test Case 4: AtomicFinalizationAndTransactionalOutboxStage**:
  - Transitions file status to `Available`.
  - Creates active `FileVersionEntity` #1.
  - Updates transfer status to `Completed`.
  - Stages `FILE_UPLOAD_COMPLETED` event in `files_outbox`.
  - Commits in single transaction; verifies outbox record status is `Pending`.
- **Test Case 5: DurableStateSurvivesServiceTeardown**:
  - Populates file, version, transfer, chunks, and outbox records.
  - Commits transaction and explicitly drains, closes, and deallocates the connection pool and repositories.
  - Instantiates completely new pool and repository instances (simulating process restart).
  - Queries all records and confirms 100% state durability and integrity.

### 2.2 CMake Target Registration (`tests/integration/CMakeLists.txt`)
- Registered `securecloud_files_postgres_persistence_integration_test` linked against `securecloud::files_db`, `securecloud::files_config`, `securecloud::common`, and `GTest::gtest` (with `ws2_32` on Windows).

---

## 3. Testing & Verification

### 3.1 Test Execution Results
All 5 persistence integration tests ran and passed:
```
[==========] Running 5 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 5 tests from FilesPostgresPersistenceIntegrationTest
[ RUN      ] FilesPostgresPersistenceIntegrationTest.DatabaseIsolationAndPrivilegeGuard
[       OK ] FilesPostgresPersistenceIntegrationTest.DatabaseIsolationAndPrivilegeGuard (410 ms)
[ RUN      ] FilesPostgresPersistenceIntegrationTest.AtomicFileCreationAndMetadataRoundtrip
[       OK ] FilesPostgresPersistenceIntegrationTest.AtomicFileCreationAndMetadataRoundtrip (411 ms)
[ RUN      ] FilesPostgresPersistenceIntegrationTest.ResumableTransferLifecycleAndProgressState
[       OK ] FilesPostgresPersistenceIntegrationTest.ResumableTransferLifecycleAndProgressState (410 ms)
[ RUN      ] FilesPostgresPersistenceIntegrationTest.AtomicFinalizationAndTransactionalOutboxStage
[       OK ] FilesPostgresPersistenceIntegrationTest.AtomicFinalizationAndTransactionalOutboxStage (409 ms)
[ RUN      ] FilesPostgresPersistenceIntegrationTest.DurableStateSurvivesServiceTeardown
[       OK ] FilesPostgresPersistenceIntegrationTest.DurableStateSurvivesServiceTeardown (826 ms)
[----------] 5 tests from FilesPostgresPersistenceIntegrationTest (2467 ms total)

[----------] Global test environment tear-down
[==========] 5 tests from 1 test suite ran. (2468 ms total)
[  PASSED  ] 5 tests.
```

### 3.2 Full Files Verification Suite Summary
| Test Target | Category | Tests | Status |
|-------------|----------|-------|--------|
| `securecloud_files_schema_migration_test` | Unit / Migration | 8 | PASSED |
| `securecloud_domain_entities_test` | Unit / Entities & Mappers | 25 | PASSED |
| `securecloud_file_repository_test` | Unit / File & Version Repos | 11 | PASSED |
| `securecloud_transfer_chunk_repository_test` | Unit / Transfer & Chunk Repos | 16 | PASSED |
| `securecloud_access_outbox_repository_test` | Unit / Access & Outbox Repos | 16 | PASSED |
| `securecloud_files_postgres_persistence_integration_test` | Integration / Live Postgres & Restart | 5 | PASSED |
| `securecloud_files_integration_test` | Integration / gRPC & Health Service | 8 | PASSED |
| **Total** | | **89** | **100% PASSED** |

---

## 4. Quality Gate & Sign-Off Checklist for Card FILES-002
- [x] All 7 database tables (`files`, `file_versions`, `encrypted_file_metadata`, `file_transfers`, `file_chunks`, `file_access`, `files_outbox`) are defined and managed via migration runner.
- [x] Zero-Plaintext Invariant (ADR-005, ADR-008) is strictly enforced: only client-encrypted metadata and storage references are stored in PostgreSQL.
- [x] Large binary payloads are not stored in PostgreSQL (delegated to S3/MinIO).
- [x] Chunk ingestion is idempotent on `(transfer_id, chunk_index)` with SHA-256 integrity checks.
- [x] Domain mutations and transactional outbox events commit atomically within `pqxx::work`.
- [x] `files_user` database-level privilege isolation is asserted.
- [x] Workstation host PostgreSQL port `5432` remains untouched and is blocked by observational guards.
- [x] State durability survives simulated process shutdown and cold restart.
- [x] Zero compiler warnings or errors across all test suites.
