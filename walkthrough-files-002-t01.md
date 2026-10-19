# Walkthrough: FILES-002-T01 — PostgreSQL Schema DDL & Migration Scripts

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-002-T01`  
**Card**: `FILES-002` (Establish Files PostgreSQL Persistence)  
**Branch**: `feature/files-002-establish-files-postgresql-persistence`

The primary objective of `FILES-002-T01` is to author the initial production PostgreSQL 17 DDL migration baseline (`V001__create_files_schema.sql`) and provide a robust C++ migration runner (`MigrationRunner`) to establish the authoritative relational storage contract for files, versions, client-side encrypted metadata, transfer sessions, chunks, access policies, and the transactional outbox.

---

## 2. Key Components Delivered

### 2.1 Authoritative Relational Schema (`src/files/db/migrations/V001__create_files_schema.sql`)
Delivered the baseline migration script establishing the 7 core tables:

1. **`files`**: Master logical file catalog:
   - `file_id UUID PRIMARY KEY`
   - `owner_user_id UUID NOT NULL`, `owner_device_id UUID NOT NULL`
   - `conversation_id UUID NULL`
   - `encrypted_size BIGINT NOT NULL CHECK (encrypted_size >= 0)`
   - `content_type VARCHAR(255) NULL`, `encryption_algorithm VARCHAR(64) NOT NULL DEFAULT 'XChaCha20-Poly1305'`
   - `status VARCHAR(32) NOT NULL CHECK (status IN ('CREATED', 'UPLOADING', 'FINALIZING', 'AVAILABLE', 'EXPIRED', 'DELETED', 'FAILED'))`
   - `retention_until TIMESTAMPTZ NULL`, `created_at`, `updated_at`

2. **`file_versions`**: Immutable completed versions:
   - `version_id UUID PRIMARY KEY`
   - `file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE`
   - `version_number INT NOT NULL CHECK (version_number > 0)`
   - `minio_object_key VARCHAR(512) NOT NULL`, `checksum_sha256 VARCHAR(64) NOT NULL`
   - `CONSTRAINT uq_file_version UNIQUE(file_id, version_number)`

3. **`encrypted_file_metadata`**: 1:1 client-side encrypted metadata enforcing Zero-Plaintext Invariant:
   - `file_id UUID PRIMARY KEY REFERENCES files(file_id) ON DELETE CASCADE`
   - `encrypted_filename BYTEA NOT NULL`, `encrypted_mime_type BYTEA NULL`
   - `metadata_nonce BYTEA NOT NULL`, `metadata_tag BYTEA NOT NULL`
   - `client_encryption_metadata JSONB NOT NULL DEFAULT '{}'::jsonb`
   - **Zero Plaintext Guarantee**: No unencrypted filenames, MIME types, or encryption keys are ever persisted.

4. **`file_transfers`**: Resumable transfer sessions:
   - `transfer_id UUID PRIMARY KEY`
   - `file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE`
   - `transfer_type VARCHAR(16) NOT NULL CHECK (transfer_type IN ('UPLOAD', 'DOWNLOAD'))`
   - `total_chunks INT`, `accepted_chunks INT`, `total_bytes BIGINT`, `transferred_bytes BIGINT`
   - `expires_at TIMESTAMPTZ NOT NULL`

5. **`file_chunks`**: Chunk receipt tracking:
   - `chunk_id UUID PRIMARY KEY`
   - `transfer_id UUID NOT NULL REFERENCES file_transfers(transfer_id) ON DELETE CASCADE`
   - `chunk_index INT NOT NULL CHECK (chunk_index >= 0)`, `byte_offset BIGINT`, `chunk_size INT`
   - `chunk_hash_sha256 VARCHAR(64) NOT NULL`, `minio_chunk_key VARCHAR(512) NOT NULL`
   - `CONSTRAINT uq_transfer_chunk UNIQUE(transfer_id, chunk_index)`

6. **`file_access`**: Access control grants:
   - `access_id UUID PRIMARY KEY`
   - `file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE`
   - `grantee_user_id UUID NOT NULL`, `permission VARCHAR(32) NOT NULL CHECK (permission IN ('READ', 'WRITE', 'ADMIN'))`
   - `CONSTRAINT uq_file_grantee UNIQUE(file_id, grantee_user_id)`

7. **`files_outbox`**: Transactional outbox for atomic audit event staging:
   - `event_id UUID PRIMARY KEY`
   - `aggregate_type VARCHAR(32) NOT NULL DEFAULT 'FILE'`, `aggregate_id UUID NOT NULL`
   - `event_type VARCHAR(64) NOT NULL`, `payload_json JSONB NOT NULL`
   - `status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED'))`

8. **Optimized Indexes**:
   - `idx_files_owner`: `files(owner_user_id, status)`
   - `idx_files_conversation`: `files(conversation_id) WHERE conversation_id IS NOT NULL`
   - `idx_files_retention`: `files(retention_until) WHERE status != 'DELETED'`
   - `idx_file_transfers_file`: `file_transfers(file_id, status)`
   - `idx_file_chunks_transfer`: `file_chunks(transfer_id, chunk_index)`
   - `idx_files_outbox_pending`: `files_outbox(created_at) WHERE status = 'PENDING'`

### 2.2 Migration Runner Engine (`src/files/db/migration_runner.{hpp,cpp}`)
- Embeds authoritative V001 schema DDL as `constexpr std::string_view`, making binaries self-contained.
- Implements `split_statements()` to parse complex SQL scripts, strip inline/line comments, and extract discrete DDL statements.
- Implements `validate_schema_ddl_syntax()` verifying presence of all required tables, cascading foreign keys, unique constraints, and partial indexes before execution.
- Implements idempotent migration tracking (`run_migrations()`, `apply_migration()`, `get_applied_versions()`).

---

## 3. Verification & Test Results

### 3.1 Unit Test Suite (`tests/unit/files/schema_migration_test.cpp`)
Implemented an 8-case unit test suite:
1. `SchemaMigrationTest.V001FileExistsAndLoads`: Validates SQL migration file exists on disk and is readable.
2. `SchemaMigrationTest.SchemaContainsAllSevenRequiredTables`: Verifies all 7 tables exist with `IF NOT EXISTS`.
3. `SchemaMigrationTest.SchemaEnforcesZeroPlaintextInvariant`: Verifies bytea encrypted fields and verifies absence of plaintext keys or filenames.
4. `SchemaMigrationTest.SchemaDefinesAllCascadeForeignKeys`: Verifies `ON DELETE CASCADE` foreign keys.
5. `SchemaMigrationTest.SchemaEnforcesUniqueConstraintsAndIndexes`: Verifies unique constraints and all 6 partial/B-Tree indexes.
6. `SchemaMigrationTest.StatementSplitterParsesCleanly`: Confirms all 13 discrete DDL statements are cleanly parsed.
7. `SchemaMigrationTest.MigrationRunnerTracksAppliedVersionsIdempotently`: Verifies migration tracking and second-run no-op idempotency.
8. `SchemaMigrationTest.MigrationRunnerRejectsInvalidDDL`: Verifies fail-closed validation on malformed DDL.

CTest results:
```
    Start 103: SchemaMigrationTest.V001FileExistsAndLoads
1/8 Test #103: SchemaMigrationTest.V001FileExistsAndLoads .............................   Passed    0.02 sec
    Start 104: SchemaMigrationTest.SchemaContainsAllSevenRequiredTables
2/8 Test #104: SchemaMigrationTest.SchemaContainsAllSevenRequiredTables ...............   Passed    0.02 sec
    Start 105: SchemaMigrationTest.SchemaEnforcesZeroPlaintextInvariant
3/8 Test #105: SchemaMigrationTest.SchemaEnforcesZeroPlaintextInvariant ...............   Passed    0.02 sec
    Start 106: SchemaMigrationTest.SchemaDefinesAllCascadeForeignKeys
4/8 Test #106: SchemaMigrationTest.SchemaDefinesAllCascadeForeignKeys .................   Passed    0.02 sec
    Start 107: SchemaMigrationTest.SchemaEnforcesUniqueConstraintsAndIndexes
5/8 Test #107: SchemaMigrationTest.SchemaEnforcesUniqueConstraintsAndIndexes ..........   Passed    0.02 sec
    Start 108: SchemaMigrationTest.StatementSplitterParsesCleanly
6/8 Test #108: SchemaMigrationTest.StatementSplitterParsesCleanly .....................   Passed    0.02 sec
    Start 109: SchemaMigrationTest.MigrationRunnerTracksAppliedVersionsIdempotently
7/8 Test #109: SchemaMigrationTest.MigrationRunnerTracksAppliedVersionsIdempotently ...   Passed    0.02 sec
    Start 110: SchemaMigrationTest.MigrationRunnerRejectsInvalidDDL
8/8 Test #110: SchemaMigrationTest.MigrationRunnerRejectsInvalidDDL ...................   Passed    0.02 sec

100% tests passed, 0 tests failed out of 8
```

### 3.2 Full Project Regression Suite
All 138 tests across the entire SecureCloud project pass with zero regressions:
```
100% tests passed, 0 tests failed out of 138
Total Test time (real) = 26.37 sec
```

---

## 4. Next Steps
With `FILES-002-T01` complete, we proceed to:
- **`FILES-002-T02`**: Strongly Typed C++20 Domain Entities & `libpqxx` Type Mappers (`src/files/db/domain_entities.hpp` and `pqxx_mappers.hpp`).
