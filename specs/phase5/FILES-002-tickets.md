# FILES-002 — Establish Files PostgreSQL Persistence
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: FILES-002 (or FILE-002)  
**Milestone**: M5 — Secure Files  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-002** implements the authoritative **PostgreSQL 17 persistence layer** for the **SecureCloud Files Service** (`securecloud-files`). Building directly upon the connection pool and migration harness established in **FILES-001**, this card introduces the relational schema, strongly typed C++20 domain entities, repository pattern abstractions, idempotent chunk tracking, access-control policies, client-encrypted metadata storage, and the transactional outbox engine for asynchronous audit events.

### Key Invariants & Architectural Boundaries
1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design 6.1, 6.26)**:
   - PostgreSQL stores **metadata, transfer state, and encrypted identifiers only**.
   - Plaintext file contents, plaintext filenames, plaintext MIME types, file-encryption keys, and user private keys MUST NEVER enter PostgreSQL.
   - Client-side metadata (original filename, MIME type) is stored strictly as pre-encrypted byte vectors (`encrypted_filename`, `encrypted_mime_type`, `metadata_nonce`, `metadata_tag`).
2. **Dual-Storage Separation of Concerns (Files Design 6.17)**:
   - **PostgreSQL 17** (`securecloud_files`): Structured metadata, transfer lifecycle, chunk receipt tracking, authorization grants, and transactional outbox.
   - **MinIO S3** (`securecloud-files-encrypted`): Large encrypted binary objects and chunk payloads. Binary file content is **never** stored in PostgreSQL columns (no `BYTEA` whole-file blobs).
3. **Database Privilege & Tenant Isolation (Files Design 6.17)**:
   - The Files Service connects to database `securecloud_files` exclusively as unprivileged user `files_user`.
   - Host PostgreSQL 14 running on `localhost:5432` is strictly guarded and protected from any connections. SecureCloud PostgreSQL 17 binds strictly to `127.0.0.1:5433`.
   - Database privileges are locked down: `files_user` has zero access to `securecloud_auth` (and `auth_user` has zero access to `securecloud_files`).
4. **Idempotent Chunk Submission & Resumable Transfer Invariant (Files Design 6.8, 6.9)**:
   - Chunk submissions are uniquely keyed by `(transfer_id, chunk_index)`.
   - Duplicate submissions of an identical chunk (matching SHA-256 hash) must succeed idempotently without creating duplicate rows or erroring.
   - Submissions of a chunk with a conflicting hash must be rejected with an integrity conflict exception.
5. **Atomic State & Outbox Persistence (Files Design 6.22)**:
   - All state transitions that trigger audit events (e.g. `FILE_UPLOAD_CREATED`, `FILE_UPLOAD_COMPLETED`, `FILE_DELETED`) must write the domain state mutation and the corresponding outbox event in a **single atomic PostgreSQL transaction** (`pqxx::work`).
   - If the transaction rolls back, zero orphaned audit events or half-persisted states are left in the database.
6. **M1 Non-Regression Invariant**:
   - All Milestone 1 capabilities, CMake build presets, protobuf generation targets, mTLS credential loaders, and `verify-local.py` orchestration must continue passing cleanly across macOS (AppleClang), Windows (MSVC x64), and Windows (MinGW-w64).

---

## 2. Relational Schema Architecture

```text
  ┌──────────────────────────────────────────────────────────┐
  │                          files                           │
  ├──────────────────────────────────────────────────────────┤
  │ file_id (UUID, PK)                                       │
  │ owner_user_id (UUID)                                     │
  │ owner_device_id (UUID)                                   │
  │ conversation_id (UUID, nullable)                         │
  │ encrypted_size (BIGINT)                                  │
  │ content_type (VARCHAR(255), nullable)                    │
  │ encryption_algorithm (VARCHAR(64))                       │
  │ status (VARCHAR(32)) [CREATED, UPLOADING, AVAILABLE, ...]│
  │ retention_until (TIMESTAMPTZ, nullable)                  │
  │ created_at, updated_at (TIMESTAMPTZ)                     │
  └────────────────────────┬─────────────────────────────────┘
                           │ 1:N
           ┌───────────────┼───────────────┬─────────────────────────┐
           │ 1:1           │ 1:N           │ 1:N                     │ 1:N
           ▼               ▼               ▼                         ▼
┌────────────────────┐ ┌───────────────┐ ┌────────────────┐ ┌────────────────┐
│encrypted_file_meta │ │ file_versions │ │ file_transfers │ │  file_access   │
├────────────────────┤ ├───────────────┤ ├────────────────┤ ├────────────────┤
│file_id (UUID, PK)  │ │version_id(PK) │ │transfer_id(PK) │ │access_id (PK)  │
│encrypted_filename  │ │file_id (FK)   │ │file_id (FK)    │ │file_id (FK)    │
│encrypted_mime_type │ │version_num    │ │transfer_type   │ │grantee_user_id │
│metadata_nonce      │ │minio_obj_key  │ │status          │ │permission      │
│metadata_tag        │ │checksum_sha256│ │total_chunks    │ │granted_by      │
│client_crypto_meta  │ │is_active      │ │accepted_chunks │ │granted_at      │
└────────────────────┘ └───────────────┘ └───────┬────────┘ └────────────────┘
                                                 │ 1:N
                                                 ▼
                                        ┌────────────────┐
                                        │  file_chunks   │
                                        ├────────────────┤
                                        │chunk_id (PK)   │
                                        │transfer_id(FK) │
                                        │chunk_index     │
                                        │byte_offset     │
                                        │chunk_size      │
                                        │chunk_sha256    │
                                        │status          │
                                        └────────────────┘

┌──────────────────────────────────────────────────────────┐
│                      files_outbox                        │
├──────────────────────────────────────────────────────────┤
│ event_id (UUID, PK)                                      │
│ aggregate_type (VARCHAR(32)) ['FILE']                    │
│ aggregate_id (UUID)                                      │
│ event_type (VARCHAR(64))                                 │
│ payload_json (JSONB)                                     │
│ status (VARCHAR(32)) ['PENDING', 'PUBLISHED', 'FAILED']  │
│ retry_count (INT)                                        │
│ created_at, processed_at (TIMESTAMPTZ)                   │
└──────────────────────────────────────────────────────────┘
```

---

## 3. Dependency Graph

```text
               FILES-001-T02 (Postgres Connection Pool & libpqxx)
               SC-011 (Persistence Infrastructure & Docker PG17)
                                   │
                                   ▼
                              FILES-002-T01
               (PostgreSQL Schema DDL & Migration Scripts)
                                   │
                                   ▼
                              FILES-002-T02
               (C++20 Domain Entities & libpqxx Type Mappers)
                                   │
           ┌───────────────────────┴───────────────────────┐
           │                                               │
           ▼                                               ▼
      FILES-002-T03                                   FILES-002-T04
   (File, Version & Encrypted                      (Resumable Transfer &
    Metadata Repositories)                          Idempotent Chunk Repos)
           │                                               │
           └───────────────────────┬───────────────────────┘
                                   │
                                   ▼
                              FILES-002-T05
               (File Access Control & Transactional Outbox)
                                   │
                                   ▼
                              FILES-002-T06
               (Integration Test Suite & Lifecycle Restart)
```

---

## 4. Implementation Tickets for Developer Louis

### FILES-002-T01 — PostgreSQL Schema DDL & Migration Scripts (`V001__create_files_schema.sql`)

1. **Ticket ID**: `FILES-002-T01`
2. **Title**: PostgreSQL Schema DDL & Migration Scripts for Files Service
3. **Objective**: Author the initial production PostgreSQL DDL migration script creating the 7 core tables, foreign keys, unique constraints, and optimized indexes in `src/files/db/migrations/V001__create_files_schema.sql`.
4. **Architectural Purpose**: Establishes the authoritative relational storage contract for files, transfers, chunks, versions, client-encrypted metadata, access grants, and audit events (ADR-005, `docs/design/files-design.md` Sections 6.3, 6.17, 6.22).
5. **Scope**:
   - Create `src/files/db/migrations/V001__create_files_schema.sql` defining:
     - `files`: Master logical file table.
     - `file_versions`: Immutable completed file versions.
     - `encrypted_file_metadata`: 1:1 client-side encrypted metadata fields.
     - `file_transfers`: Resumable transfer sessions.
     - `file_chunks`: Transfer chunk tracking with `UNIQUE(transfer_id, chunk_index)`.
     - `file_access`: Granular file-level access grants with `UNIQUE(file_id, grantee_user_id)`.
     - `files_outbox`: Transactional outbox for asynchronous audit dispatching.
   - Add optimized B-Tree and partial indexes:
     - `idx_files_owner`: `files(owner_user_id, status)`
     - `idx_files_conversation`: `files(conversation_id) WHERE conversation_id IS NOT NULL`
     - `idx_files_retention`: `files(retention_until) WHERE status != 'DELETED'`
     - `idx_file_transfers_file`: `file_transfers(file_id, status)`
     - `idx_file_chunks_transfer`: `file_chunks(transfer_id, chunk_index)`
     - `idx_files_outbox_pending`: `files_outbox(created_at) WHERE status = 'PENDING'`
   - Update `src/files/db/migration_runner.cpp` to execute migrations upon service startup.
   - Create unit/schema migration verification test `tests/unit/files/schema_migration_test.cpp`.
6. **Explicit Out-of-Scope**: Storing large binary file objects in PostgreSQL (owned by MinIO in FILE-003).
7. **Dependencies**: Upstream FILES-001-T02. Downstream FILES-002-T02, FILES-002-T03.
8. **Exact Repository Starting Point**: `src/files/db/migration_runner.hpp`.
9. **Files/Directories to Inspect**: `deploy/compose/postgres/init-databases.sh`, `src/auth/db/`.
10. **Files/Directories to Create**:
    - `src/files/db/migrations/V001__create_files_schema.sql`
    - `tests/unit/files/schema_migration_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `src/files/CMakeLists.txt`
    - `src/files/db/migration_runner.cpp`
    - `tests/unit/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `src/gateway/*`, `deploy/compose/*`.
13. **Detailed Implementation Requirements**:
    ```sql
    -- V001__create_files_schema.sql

    CREATE TABLE IF NOT EXISTS files (
        file_id UUID PRIMARY KEY,
        owner_user_id UUID NOT NULL,
        owner_device_id UUID NOT NULL,
        conversation_id UUID NULL,
        encrypted_size BIGINT NOT NULL CHECK (encrypted_size >= 0),
        content_type VARCHAR(255) NULL,
        encryption_algorithm VARCHAR(64) NOT NULL DEFAULT 'XChaCha20-Poly1305',
        status VARCHAR(32) NOT NULL DEFAULT 'CREATED'
            CHECK (status IN ('CREATED', 'UPLOADING', 'FINALIZING', 'AVAILABLE', 'EXPIRED', 'DELETED', 'FAILED')),
        retention_until TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS file_versions (
        version_id UUID PRIMARY KEY,
        file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
        version_number INT NOT NULL DEFAULT 1 CHECK (version_number > 0),
        encrypted_size BIGINT NOT NULL CHECK (encrypted_size >= 0),
        minio_object_key VARCHAR(512) NOT NULL,
        checksum_sha256 VARCHAR(64) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        CONSTRAINT uq_file_version UNIQUE(file_id, version_number)
    );

    CREATE TABLE IF NOT EXISTS encrypted_file_metadata (
        file_id UUID PRIMARY KEY REFERENCES files(file_id) ON DELETE CASCADE,
        encrypted_filename BYTEA NOT NULL,
        encrypted_mime_type BYTEA NULL,
        metadata_nonce BYTEA NOT NULL,
        metadata_tag BYTEA NOT NULL,
        client_encryption_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS file_transfers (
        transfer_id UUID PRIMARY KEY,
        file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
        transfer_type VARCHAR(16) NOT NULL CHECK (transfer_type IN ('UPLOAD', 'DOWNLOAD')),
        initiator_user_id UUID NOT NULL,
        initiator_device_id UUID NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'CREATED'
            CHECK (status IN ('CREATED', 'TRANSFERRING', 'FINALIZING', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED')),
        total_chunks INT NOT NULL CHECK (total_chunks >= 0),
        accepted_chunks INT NOT NULL DEFAULT 0 CHECK (accepted_chunks >= 0),
        total_bytes BIGINT NOT NULL CHECK (total_bytes >= 0),
        transferred_bytes BIGINT NOT NULL DEFAULT 0 CHECK (transferred_bytes >= 0),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS file_chunks (
        chunk_id UUID PRIMARY KEY,
        transfer_id UUID NOT NULL REFERENCES file_transfers(transfer_id) ON DELETE CASCADE,
        chunk_index INT NOT NULL CHECK (chunk_index >= 0),
        byte_offset BIGINT NOT NULL CHECK (byte_offset >= 0),
        chunk_size INT NOT NULL CHECK (chunk_size > 0),
        chunk_hash_sha256 VARCHAR(64) NOT NULL,
        minio_chunk_key VARCHAR(512) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'RECEIVED' CHECK (status IN ('RECEIVED', 'COMMITTED')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_transfer_chunk UNIQUE(transfer_id, chunk_index)
    );

    CREATE TABLE IF NOT EXISTS file_access (
        access_id UUID PRIMARY KEY,
        file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
        grantee_user_id UUID NOT NULL,
        grantee_device_id UUID NULL,
        permission VARCHAR(32) NOT NULL DEFAULT 'READ' CHECK (permission IN ('READ', 'WRITE', 'ADMIN')),
        granted_by UUID NOT NULL,
        granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked_at TIMESTAMPTZ NULL,
        CONSTRAINT uq_file_grantee UNIQUE(file_id, grantee_user_id)
    );

    CREATE TABLE IF NOT EXISTS files_outbox (
        event_id UUID PRIMARY KEY,
        aggregate_type VARCHAR(32) NOT NULL DEFAULT 'FILE',
        aggregate_id UUID NOT NULL,
        event_type VARCHAR(64) NOT NULL,
        payload_json JSONB NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED')),
        retry_count INT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        processed_at TIMESTAMPTZ NULL
    );
    ```
14. **Testing Requirements**:
    - Validates syntax by applying migration script against test database.
    - Validates idempotency (applying script twice does not error).
    - Validates cascade deletion behavior (deleting a file cascades to version, metadata, transfers, chunks, and access).
15. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_files_schema_migration_test
    ctest --preset dev-debug -R files_schema_migration_test --output-on-failure
    ```
16. **Acceptance Criteria**: Migration applies cleanly with zero SQL errors; tables, constraints, and indexes exist in PostgreSQL schema.

---

### FILES-002-T02 — Strongly Typed C++20 Domain Entities & `libpqxx` Type Mappers

1. **Ticket ID**: `FILES-002-T02`
2. **Title**: Strongly Typed C++20 Domain Entities & `libpqxx` Type Mappers
3. **Objective**: Define immutable/strongly-typed C++20 domain entities, status enums, and bidirectional `libpqxx` serialization/deserialization mappers for all 7 database models.
4. **Architectural Purpose**: Provides type-safe representations of files, transfers, chunks, access rules, and outbox records, eliminating primitive obsession and SQL injection risks (ADR-002, `docs/design/files-design.md` 6.3).
5. **Scope**:
   - Create domain entity headers in `src/files/domain/`:
     - `file_entity.hpp`: `FileEntity`, `FileStatus` enum (`Created`, `Uploading`, `Finalizing`, `Available`, `Expired`, `Deleted`, `Failed`).
     - `file_version_entity.hpp`: `FileVersionEntity`.
     - `encrypted_file_metadata_entity.hpp`: `EncryptedFileMetadataEntity` (`std::vector<uint8_t> encrypted_filename`, `metadata_nonce`, `metadata_tag`, `client_encryption_metadata_json`).
     - `file_transfer_entity.hpp`: `FileTransferEntity`, `TransferType` enum (`Upload`, `Download`), `TransferStatus` enum (`Created`, `Transferring`, `Finalizing`, `Completed`, `Failed`, `Expired`, `Cancelled`).
     - `file_chunk_entity.hpp`: `FileChunkEntity`, `ChunkStatus` enum (`Received`, `Committed`).
     - `file_access_entity.hpp`: `FileAccessEntity`, `FilePermission` enum (`Read`, `Write`, `Admin`).
     - `files_outbox_entity.hpp`: `FilesOutboxEntity`, `OutboxStatus` enum (`Pending`, `Published`, `Failed`).
   - Create `src/files/db/pqxx_mappers.hpp` and `src/files/db/pqxx_mappers.cpp`:
     - Functions converting `pqxx::row` to respective domain entity structs.
     - Functions converting string representations to strong enums with invalid enum guards.
     - Functions converting timestamps between `std::chrono::system_clock::time_point` and PostgreSQL ISO 8601 strings.
     - Functions converting `std::vector<uint8_t>` to PostgreSQL bytea.
   - Create unit tests in `tests/unit/files/domain_entities_test.cpp`.
6. **Explicit Out-of-Scope**: Executing database network calls.
7. **Dependencies**: Upstream FILES-002-T01, FILES-001-T02. Downstream FILES-002-T03, FILES-002-T04.
8. **Exact Repository Starting Point**: `src/files/domain/`.
9. **Files/Directories to Create**:
   - `src/files/domain/file_entity.hpp`
   - `src/files/domain/file_version_entity.hpp`
   - `src/files/domain/encrypted_file_metadata_entity.hpp`
   - `src/files/domain/file_transfer_entity.hpp`
   - `src/files/domain/file_chunk_entity.hpp`
   - `src/files/domain/file_access_entity.hpp`
   - `src/files/domain/files_outbox_entity.hpp`
   - `src/files/db/pqxx_mappers.hpp`
   - `src/files/db/pqxx_mappers.cpp`
   - `tests/unit/files/domain_entities_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/files/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `src/common/*`.
12. **Detailed Implementation Requirements**:
    ```cpp
    namespace securecloud::files {

    enum class FileStatus { Created, Uploading, Finalizing, Available, Expired, Deleted, Failed };
    enum class TransferType { Upload, Download };
    enum class TransferStatus { Created, Transferring, Finalizing, Completed, Failed, Expired, Cancelled };
    enum class ChunkStatus { Received, Committed };
    enum class FilePermission { Read, Write, Admin };
    enum class OutboxStatus { Pending, Published, Failed };

    struct FileEntity {
        std::string file_id;
        std::string owner_user_id;
        std::string owner_device_id;
        std::optional<std::string> conversation_id;
        int64_t encrypted_size{0};
        std::optional<std::string> content_type;
        std::string encryption_algorithm{"XChaCha20-Poly1305"};
        FileStatus status{FileStatus::Created};
        std::optional<std::chrono::system_clock::time_point> retention_until;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point updated_at;
    };

    struct EncryptedFileMetadataEntity {
        std::string file_id;
        std::vector<uint8_t> encrypted_filename;
        std::vector<uint8_t> encrypted_mime_type;
        std::vector<uint8_t> metadata_nonce;
        std::vector<uint8_t> metadata_tag;
        std::string client_encryption_metadata_json{"{}"};
        std::chrono::system_clock::time_point updated_at;
    };

    struct FileChunkEntity {
        std::string chunk_id;
        std::string transfer_id;
        int32_t chunk_index{0};
        int64_t byte_offset{0};
        int32_t chunk_size{0};
        std::string chunk_hash_sha256;
        std::string minio_chunk_key;
        ChunkStatus status{ChunkStatus::Received};
        std::chrono::system_clock::time_point created_at;
    };

    } // namespace securecloud::files
    ```
13. **Testing Requirements**:
    - Validates serialization and deserialization roundtrips.
    - Validates string-to-enum mappings reject unknown strings with explicit exceptions.
    - Validates handling of nullable fields (`conversation_id`, `retention_until`).
14. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_domain_entities_test
    ctest --preset dev-debug -R domain_entities_test --output-on-failure
    ```
15. **Acceptance Criteria**: 100% test coverage for domain entity mappers; zero unhandled deserialization crashes.

---

### FILES-002-T03 — File, Version & Encrypted Metadata Repositories

1. **Ticket ID**: `FILES-002-T03`
2. **Title**: File, Version & Encrypted Metadata Repositories
3. **Objective**: Implement repository classes for `FileRepository` and `FileVersionRepository` managing transactional CRUD operations, status state transitions, and client-encrypted metadata persistence.
4. **Architectural Purpose**: Enforces the server-side file lifecycle (`CREATED → UPLOADING → FINALIZING → AVAILABLE`), version immutability, and atomic metadata storage (Files Design 6.3, 6.18, 6.19).
5. **Scope**:
   - Create `src/files/repository/file_repository.hpp` and `src/files/repository/file_repository.cpp`:
     - `create_file(const FileEntity& file, const EncryptedFileMetadataEntity& metadata, pqxx::work& tx)`: Inserts rows into `files` and `encrypted_file_metadata` atomically.
     - `find_by_id(const std::string& file_id) -> std::optional<FileEntity>`
     - `find_encrypted_metadata(const std::string& file_id) -> std::optional<EncryptedFileMetadataEntity>`
     - `update_status(const std::string& file_id, FileStatus expected_current, FileStatus new_status, pqxx::work& tx) -> bool`: Enforces optimistic concurrency / valid state transitions.
     - `delete_file_logical(const std::string& file_id, pqxx::work& tx)`: Sets status to `DELETED`.
     - `find_expired_files(std::chrono::system_clock::time_point now, size_t limit) -> std::vector<FileEntity>`
   - Create `src/files/repository/file_version_repository.hpp` and `src/files/repository/file_version_repository.cpp`:
     - `create_version(const FileVersionEntity& version, pqxx::work& tx)`: Enforces `UNIQUE(file_id, version_number)`.
     - `find_active_version(const std::string& file_id) -> std::optional<FileVersionEntity>`
     - `list_versions(const std::string& file_id) -> std::vector<FileVersionEntity>`
   - Unit tests in `tests/unit/files/file_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Uploading physical bytes to MinIO (FILE-003).
7. **Dependencies**: Upstream FILES-002-T01, FILES-002-T02, FILES-001-T02. Downstream FILES-002-T05, FILES-002-T06.
8. **Exact Repository Starting Point**: `src/files/repository/`.
9. **Files/Directories to Create**:
   - `src/files/repository/file_repository.hpp`
   - `src/files/repository/file_repository.cpp`
   - `src/files/repository/file_version_repository.hpp`
   - `src/files/repository/file_version_repository.cpp`
   - `tests/unit/files/file_repository_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/files/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `src/gateway/*`.
12. **Detailed Implementation Requirements**:
    - All queries must use parameterized SQL (`$1, $2, ...`) via `pqxx::work::exec_params`.
    - Lifecycle transition validation:
      - Valid transitions: `CREATED → UPLOADING`, `UPLOADING → FINALIZING`, `FINALIZING → AVAILABLE`, `AVAILABLE → EXPIRED`, `AVAILABLE → DELETED`, `UPLOADING → FAILED`, `FINALIZING → FAILED`.
      - Any attempt to transition an `AVAILABLE` file back to `UPLOADING` must throw `InvalidStateTransitionException`.
13. **Testing Requirements**:
    - Tests atomic insert of `files` and `encrypted_file_metadata`.
    - Tests retrieval by ID.
    - Tests state transition rejection when `expected_current` does not match.
    - Tests version increment and uniqueness constraint.
14. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_file_repository_test
    ctest --preset dev-debug -R file_repository_test --output-on-failure
    ```
15. **Acceptance Criteria**: 100% of queries use parameterized statements; atomic creation succeeds; invalid transitions fail closed.

---

### FILES-002-T04 — Resumable FileTransfer & Idempotent FileChunk Repositories

1. **Ticket ID**: `FILES-002-T04`
2. **Title**: Resumable FileTransfer & Idempotent FileChunk Repositories
3. **Objective**: Implement `FileTransferRepository` and `FileChunkRepository` managing upload/download transfer sessions, progress tracking, and strictly idempotent chunk persistence.
4. **Architectural Purpose**: Provides the foundation for resumable uploads, out-of-order chunk handling, connection-loss recovery, and deduplication (Files Design 6.7, 6.8, 6.9, 6.10).
5. **Scope**:
   - Create `src/files/repository/file_transfer_repository.hpp` and `src/files/repository/file_transfer_repository.cpp`:
     - `create_transfer(const FileTransferEntity& transfer, pqxx::work& tx)`
     - `find_by_id(const std::string& transfer_id) -> std::optional<FileTransferEntity>`
     - `update_status(const std::string& transfer_id, TransferStatus status, pqxx::work& tx)`
     - `increment_chunk_progress(const std::string& transfer_id, int64_t bytes_added, pqxx::work& tx)`
   - Create `src/files/repository/file_chunk_repository.hpp` and `src/files/repository/file_chunk_repository.cpp`:
     - `enum class ChunkRecordResult { NewlyInserted, AlreadyExistsIdentical, ConflictHashMismatch }`:
     - `record_chunk(const FileChunkEntity& chunk, pqxx::work& tx) -> ChunkRecordResult`:
       - Executes:
         ```sql
         INSERT INTO file_chunks (chunk_id, transfer_id, chunk_index, byte_offset, chunk_size, chunk_hash_sha256, minio_chunk_key, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (transfer_id, chunk_index) DO NOTHING;
         ```
       - If inserted: returns `NewlyInserted`.
       - If conflict: queries existing row for `chunk_hash_sha256`. If hash matches -> returns `AlreadyExistsIdentical`. If hash differs -> returns `ConflictHashMismatch` and throws `ChunkIntegrityException`.
     - `get_accepted_chunk_indices(const std::string& transfer_id) -> std::vector<int32_t>`: Returns ordered list of accepted chunk indices for resume queries.
     - `count_accepted_chunks(const std::string& transfer_id) -> int32_t`
     - `is_chunk_present(const std::string& transfer_id, int32_t chunk_index) -> bool`
     - `list_chunks_for_transfer(const std::string& transfer_id) -> std::vector<FileChunkEntity>`
   - Unit tests in `tests/unit/files/transfer_chunk_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Receiving HTTP/gRPC streams or computing SHA-256 in memory (FILE-005).
7. **Dependencies**: Upstream FILES-002-T01, FILES-002-T02. Downstream FILES-002-T06, FILE-005.
8. **Exact Repository Starting Point**: `src/files/repository/`.
9. **Files/Directories to Create**:
   - `src/files/repository/file_transfer_repository.hpp`
   - `src/files/repository/file_transfer_repository.cpp`
   - `src/files/repository/file_chunk_repository.hpp`
   - `src/files/repository/file_chunk_repository.cpp`
   - `tests/unit/files/transfer_chunk_repository_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/files/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Chunk index must be non-negative.
    - Duplicate chunk retry must be completely safe and must not double-count `transferred_bytes` or `accepted_chunks`.
13. **Testing Requirements**:
    - Create transfer, insert chunks 0, 1, 2.
    - Re-insert chunk 1 with matching hash -> returns `AlreadyExistsIdentical`, progress untouched.
    - Re-insert chunk 1 with mismatched hash -> throws `ChunkIntegrityException`.
    - Query `get_accepted_chunk_indices()` -> returns `[0, 1, 2]`.
14. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_transfer_chunk_repository_test
    ctest --preset dev-debug -R transfer_chunk_repository_test --output-on-failure
    ```
15. **Acceptance Criteria**: Chunk submission is strictly idempotent; conflicting hashes are detected and rejected; resume indices resolve accurately.

---

### FILES-002-T05 — FileAccess Authorization & Transactional Outbox Repositories

1. **Ticket ID**: `FILES-002-T05`
2. **Title**: FileAccess Authorization & Transactional Outbox Repositories
3. **Objective**: Implement `FileAccessRepository` enforcing granular server-side access control, and `FilesOutboxRepository` providing guaranteed at-least-once audit event dispatching.
4. **Architectural Purpose**: Enforces authorization verification (Gateway Design 3.24 Invariant 6, Files Design 6.15) and guarantees audit events are persisted atomically with file domain state (Files Design 6.22).
5. **Scope**:
   - Create `src/files/repository/file_access_repository.hpp` and `src/files/repository/file_access_repository.cpp`:
     - `grant_access(const FileAccessEntity& grant, pqxx::work& tx)`: Inserts or updates grant.
     - `check_access(const std::string& file_id, const std::string& user_id, FilePermission required) -> bool`:
       - Checks whether user is the file owner (`files.owner_user_id == user_id`) OR has an active, unrevoked grant in `file_access` where `permission >= required`.
     - `revoke_access(const std::string& file_id, const std::string& user_id, pqxx::work& tx)`: Sets `revoked_at = NOW()`.
     - `list_grantees(const std::string& file_id) -> std::vector<FileAccessEntity>`
   - Create `src/files/repository/files_outbox_repository.hpp` and `src/files/repository/files_outbox_repository.cpp`:
     - `stage_event(const FilesOutboxEntity& event, pqxx::work& tx)`: Inserts pending outbox event.
     - `fetch_pending_events(size_t limit, pqxx::work& tx) -> std::vector<FilesOutboxEntity>`:
       - Uses `SELECT ... FOR UPDATE SKIP LOCKED` to support concurrent outbox workers without row contention.
     - `mark_published(const std::string& event_id, pqxx::work& tx)`: Sets `status = 'PUBLISHED'`, `processed_at = NOW()`.
     - `mark_failed(const std::string& event_id, pqxx::work& tx)`: Increments `retry_count`, sets `status = 'FAILED'`.
   - Unit tests in `tests/unit/files/access_outbox_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Publishing outbox events across network to Audit service (M6).
7. **Dependencies**: Upstream FILES-002-T01, FILES-002-T02. Downstream FILES-002-T06.
8. **Exact Repository Starting Point**: `src/files/repository/`.
9. **Files/Directories to Create**:
   - `src/files/repository/file_access_repository.hpp`
   - `src/files/repository/file_access_repository.cpp`
   - `src/files/repository/files_outbox_repository.hpp`
   - `src/files/repository/files_outbox_repository.cpp`
   - `tests/unit/files/access_outbox_repository_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/files/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Outbox payload must be valid JSON; event IDs must be unique UUIDs.
    - Owner permissions: The file creator always has implicit `ADMIN` permission without needing an explicit `file_access` row.
13. **Testing Requirements**:
    - Tests access granted to owner returns true for all permission levels.
    - Tests non-owner without grant returns false.
    - Tests non-owner with READ grant: `READ` succeeds, `WRITE` fails.
    - Tests revoked grant: access returns false.
    - Tests outbox insert within `pqxx::work`, rollback leaves outbox empty.
14. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_access_outbox_repository_test
    ctest --preset dev-debug -R access_outbox_repository_test --output-on-failure
    ```
15. **Acceptance Criteria**: Access control accurately distinguishes owner vs grantee vs stranger; outbox commits atomically with domain transactions.

---

### FILES-002-T06 — PostgreSQL Persistence Integration & Lifecycle Restart Test Suite

1. **Ticket ID**: `FILES-002-T06`
2. **Title**: PostgreSQL Persistence Integration & Lifecycle Restart Test Suite
3. **Objective**: Implement comprehensive end-to-end integration test `tests/integration/files_postgres_persistence_integration_test.cpp` validating live PostgreSQL 17 execution, foreign keys, privilege isolation, and state durability across process restarts.
4. **Architectural Purpose**: Proves that all metadata, transfers, chunks, and access rules persist durably in `securecloud_files` and that database isolation boundaries are rigorously maintained (ADR-005, Files Design 6.17, 6.23).
5. **Scope**:
   - Create `tests/integration/files_postgres_persistence_integration_test.cpp`:
     - Connects to PostgreSQL using `securecloud::files::PostgresConnectionPool` (targeting `127.0.0.1:5433`, db `securecloud_files`, user `files_user`).
     - Test Case 1: **Database Isolation & Privilege Guard**:
       - Asserts `files_user` connects to `securecloud_files`.
       - Asserts `files_user` connection to `securecloud_auth` is strictly denied (`pqxx::broken_connection` / permission denied).
       - Observational check confirms workstation port `5432` was untouched.
     - Test Case 2: **Atomic File Creation & Metadata Roundtrip**:
       - Inserts `FileEntity` and `EncryptedFileMetadataEntity` in single transaction.
       - Retrieves record; verifies binary bytea fields (`encrypted_filename`, `metadata_nonce`, `metadata_tag`) are bit-identical.
     - Test Case 3: **Resumable Transfer Lifecycle & Progress State**:
       - Creates upload transfer session with 5 chunks.
       - Progressively inserts chunks 0, 1, 2.
       - Queries `get_accepted_chunk_indices()`; asserts missing chunks are 3 and 4.
       - Simulates client retry of chunk 1; asserts idempotent success.
     - Test Case 4: **Atomic Finalization & Transactional Outbox Stage**:
       - Begins `pqxx::work`.
       - Transitions file to `AVAILABLE`, creates `FileVersionEntity` #1, and stages `FILE_UPLOAD_COMPLETED` event in `files_outbox`.
       - Commits transaction. Asserts outbox record has status `PENDING`.
     - Test Case 5: **Durable State Survives Service Teardown**:
       - Destroys all repository and connection pool instances in memory.
       - Re-initializes new repository instances from scratch.
       - Queries file, version, transfer, chunks, and outbox; asserts all states are 100% intact and consistent.
   - Register integration test in `tests/integration/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Communicating with MinIO S3 (FILE-003).
7. **Dependencies**: Upstream FILES-002-T01 through FILES-002-T05, FILES-001-T02, SC-011.
8. **Exact Repository Starting Point**: `tests/integration/CMakeLists.txt`.
9. **Files/Directories to Create**:
   - `tests/integration/files_postgres_persistence_integration_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `tests/integration/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `deploy/compose/*`.
12. **Detailed Implementation Requirements**:
    - Must use deterministic cleanup of test fixtures (UUID-prefixed test records deleted in fixture teardown).
    - Under Windows, Winsock must be initialized.
13. **Testing Requirements**:
    - Executable under CTest when Compose PostgreSQL is running on port 5433.
    - Zero leaks, deadlocks, or hangs.
14. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_files_postgres_persistence_integration_test
    ctest --preset dev-debug -R files_postgres_persistence_integration_test --output-on-failure
    ```
15. **Acceptance Criteria**: All 5 integration scenarios pass cleanly; database isolation confirmed; state durability verified across process restart.

---

## 5. Quality Gate & Sign-Off Checklist

Before card **FILES-002** can be submitted for review and merged into `main`, the developer must verify:

- [ ] All 7 database tables (`files`, `file_versions`, `encrypted_file_metadata`, `file_transfers`, `file_chunks`, `file_access`, `files_outbox`) are created via migration script `V001__create_files_schema.sql`.
- [ ] No plaintext file contents, plaintext filenames, or cryptographic private keys are stored in PostgreSQL.
- [ ] Large binary file blobs are NOT stored in PostgreSQL (reserved for MinIO).
- [ ] Chunk ingestion is idempotent on `(transfer_id, chunk_index)`. Duplicate chunks with identical hashes succeed; mismatched hashes fail with an integrity exception.
- [ ] State mutations and outbox events are committed in a single atomic transaction (`pqxx::work`).
- [ ] `files_user` has zero access to `securecloud_auth` (strict database-level privilege isolation).
- [ ] Workstation host PostgreSQL 14 on `127.0.0.1:5432` remains completely untouched.
- [ ] All queries use parameterized statements (`$1, $2, ...`) with zero string concatenation.
- [ ] Metadata, transfer state, and chunk progress survive a complete simulated process restart.
- [ ] All unit and integration tests compile without warnings and pass across macOS, Windows MSVC, and Windows MinGW-w64.
