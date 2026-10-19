# Walkthrough: FILES-002-T02 — Strongly Typed C++20 Domain Entities & `libpqxx` Type Mappers

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-002-T02`  
**Card**: `FILES-002` (Establish Files PostgreSQL Persistence)  
**Branch**: `feature/files-002-establish-files-postgresql-persistence`

The primary objective of `FILES-002-T02` is to establish strongly typed, immutable C++20 domain entities, authoritative status enums, bidirectional PostgreSQL string/bytea/timestamp mappers, and safe `libpqxx` row deserialization routines for all 7 database models in the SecureCloud Files Service.

This provides an authoritative, type-safe representation of files, versions, client-encrypted metadata, resumable transfers, idempotent chunks, access grants, and outbox records—completely eliminating primitive obsession and preventing SQL injection or deserialization failures (ADR-002, ADR-005, `docs/design/files-design.md` Section 6.3).

---

## 2. Key Components Delivered

### 2.1 C++20 Domain Entities (`src/files/domain/`)
Delivered 7 strongly typed domain entities mapping 1:1 to the PostgreSQL schema tables created in `FILES-002-T01`:

1. **`FileEntity` & `FileStatus` (`src/files/domain/file_entity.hpp`)**:
   - Status Enum: `Created`, `Uploading`, `Finalizing`, `Available`, `Expired`, `Deleted`, `Failed`.
   - Fields: `file_id`, `owner_user_id`, `owner_device_id`, optional `conversation_id`, `encrypted_size`, optional `content_type`, `encryption_algorithm`, `status`, optional `retention_until`, `created_at`, `updated_at`.
   - Default equality operator (`==`) for deterministic unit test assertions.

2. **`FileVersionEntity` (`src/files/domain/file_version_entity.hpp`)**:
   - Represents immutable version snapshots.
   - Fields: `version_id`, `file_id`, `version_number`, `encrypted_size`, `minio_object_key`, `checksum_sha256`, `created_at`, `is_active`.

3. **`EncryptedFileMetadataEntity` (`src/files/domain/encrypted_file_metadata_entity.hpp`)**:
   - Strictly enforces the **Zero-Plaintext Invariant (ADR-005, ADR-008)**. Plaintext filenames, MIME types, or encryption keys never touch the storage layer.
   - Fields: `file_id`, `std::vector<uint8_t> encrypted_filename`, optional `encrypted_mime_type`, `metadata_nonce`, `metadata_tag`, `client_encryption_metadata_json`, `updated_at`.

4. **`FileTransferEntity`, `TransferType`, & `TransferStatus` (`src/files/domain/file_transfer_entity.hpp`)**:
   - Enums: `TransferType` (`Upload`, `Download`), `TransferStatus` (`Created`, `Transferring`, `Finalizing`, `Completed`, `Failed`, `Expired`, `Cancelled`).
   - Fields: `transfer_id`, `file_id`, `transfer_type`, `initiator_user_id`, `initiator_device_id`, `status`, `total_chunks`, `accepted_chunks`, `total_bytes`, `transferred_bytes`, `created_at`, `updated_at`, `expires_at`.

5. **`FileChunkEntity` & `ChunkStatus` (`src/files/domain/file_chunk_entity.hpp`)**:
   - Enum: `ChunkStatus` (`Received`, `Committed`).
   - Fields: `chunk_id`, `transfer_id`, `chunk_index`, `byte_offset`, `chunk_size`, `chunk_hash_sha256`, `minio_chunk_key`, `status`, `created_at`.

6. **`FileAccessEntity` & `FilePermission` (`src/files/domain/file_access_entity.hpp`)**:
   - Enum: `FilePermission` (`Read`, `Write`, `Admin`).
   - Fields: `access_id`, `file_id`, `grantee_user_id`, optional `grantee_device_id`, `permission`, `granted_by`, `granted_at`, optional `revoked_at`.

7. **`FilesOutboxEntity` & `OutboxStatus` (`src/files/domain/files_outbox_entity.hpp`)**:
   - Enum: `OutboxStatus` (`Pending`, `Published`, `Failed`).
   - Fields: `event_id`, `aggregate_type`, `aggregate_id`, `event_type`, `payload_json`, `status`, `retry_count`, `created_at`, optional `processed_at`.

### 2.2 libpqxx Compatible Row Layer (`src/files/db/pqxx_compat.hpp`)
- Provides clean, lightweight `pqxx::row` and `pqxx::field` types when `libpqxx` is not bundled on the host environment, allowing identical code to compile and run across Windows MSVC, MinGW, macOS, and Linux without external runtime dependencies.
- When `<pqxx/pqxx>` is available, delegates directly to official `libpqxx` headers.
- Implements `RowBuilder` test helper for constructing deterministic mock rows.

### 2.3 Type Mappers & Conversions (`src/files/db/pqxx_mappers.{hpp,cpp}`)
- **Bidirectional Enum String Mappers**:
  - `to_string(Enum)` and `enum_from_string(std::string_view)` for all 6 enum types.
  - Unknown strings throw explicit `InvalidEnumException` with descriptive error messages.
- **ISO 8601 Timestamp Conversions**:
  - `to_iso8601(time_point)`: Formats UTC timestamp with microsecond precision (`YYYY-MM-DDTHH:MM:SS.ffffffZ`).
  - `from_iso8601(string_view)`: Robust, thread-safe parser implementing Howard Hinnant's civil calendar algorithm; supports UTC (`Z`), PostgreSQL space separators (`2026-09-25 10:30:45+00`), and arbitrary time zone offsets (`+02:00`, `-05:00`). Rejects malformed strings with `TimestampParseException`.
- **PostgreSQL Bytea Conversions**:
  - `to_bytea_hex(bytes)`: Generates standard PostgreSQL bytea hex string (`\x000102...`).
  - `from_bytea_hex(string_view)`: Decodes hex strings with or without `\x` / `\\x` prefix. Rejects odd lengths and invalid hex characters with `ByteaParseException`.
- **Entity Row Deserialization**:
  - 7 specialized functions: `file_from_row`, `file_version_from_row`, `encrypted_metadata_from_row`, `file_transfer_from_row`, `file_chunk_from_row`, `file_access_from_row`, `files_outbox_from_row`.
  - Nullable database columns (`conversation_id`, `retention_until`, `content_type`, `encrypted_mime_type`, `grantee_device_id`, `revoked_at`, `processed_at`) map safely to `std::optional<T>`.

---

## 3. Verification & Test Results

### 3.1 Unit Test Suite (`tests/unit/files/domain_entities_test.cpp`)
Implemented 25 comprehensive test cases covering:
- Roundtrip conversions for all 6 enum types (`FileStatus`, `TransferType`, `TransferStatus`, `ChunkStatus`, `FilePermission`, `OutboxStatus`) and validation that unknown strings throw `InvalidEnumException`.
- ISO 8601 timestamp parsing, fractional seconds, space separators, positive and negative timezone offsets, and malformed input rejection.
- PostgreSQL Bytea hex encoding and decoding, prefix variations (`\x`, `\\x`, raw), and malformed hex rejection.
- Complete and nullable row deserialization across all 7 domain entity types.

**Execution Result**:
```text
Running main() from gtest_main.cc
[==========] Running 25 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 25 tests from DomainEntitiesTest
[ RUN      ] DomainEntitiesTest.FileStatusEnumRoundtrip
[       OK ] DomainEntitiesTest.FileStatusEnumRoundtrip (0 ms)
[ RUN      ] DomainEntitiesTest.TransferTypeEnumRoundtrip
[       OK ] DomainEntitiesTest.TransferTypeEnumRoundtrip (0 ms)
[ RUN      ] DomainEntitiesTest.TransferStatusEnumRoundtrip
[       OK ] DomainEntitiesTest.TransferStatusEnumRoundtrip (0 ms)
[ RUN      ] DomainEntitiesTest.ChunkStatusEnumRoundtrip
[       OK ] DomainEntitiesTest.ChunkStatusEnumRoundtrip (0 ms)
[ RUN      ] DomainEntitiesTest.FilePermissionEnumRoundtrip
[       OK ] DomainEntitiesTest.FilePermissionEnumRoundtrip (0 ms)
[ RUN      ] DomainEntitiesTest.OutboxStatusEnumRoundtrip
[       OK ] DomainEntitiesTest.OutboxStatusEnumRoundtrip (0 ms)
[ RUN      ] DomainEntitiesTest.TimestampRoundtripUtc
[       OK ] DomainEntitiesTest.TimestampRoundtripUtc (0 ms)
[ RUN      ] DomainEntitiesTest.TimestampParsesWithoutFractionalSeconds
[       OK ] DomainEntitiesTest.TimestampParsesWithoutFractionalSeconds (0 ms)
[ RUN      ] DomainEntitiesTest.TimestampParsesSpaceSeparatorAndPostgresFormat
[       OK ] DomainEntitiesTest.TimestampParsesSpaceSeparatorAndPostgresFormat (0 ms)
[ RUN      ] DomainEntitiesTest.TimestampParsesTimezoneOffsetsAccurately
[       OK ] DomainEntitiesTest.TimestampParsesTimezoneOffsetsAccurately (0 ms)
[ RUN      ] DomainEntitiesTest.TimestampRejectsMalformedStrings
[       OK ] DomainEntitiesTest.TimestampRejectsMalformedStrings (0 ms)
[ RUN      ] DomainEntitiesTest.ByteaHexRoundtrip
[       OK ] DomainEntitiesTest.ByteaHexRoundtrip (0 ms)
[ RUN      ] DomainEntitiesTest.ByteaDecodesWithOrWithoutPrefix
[       OK ] DomainEntitiesTest.ByteaDecodesWithOrWithoutPrefix (0 ms)
[ RUN      ] DomainEntitiesTest.ByteaRejectsMalformedHex
[       OK ] DomainEntitiesTest.ByteaRejectsMalformedHex (0 ms)
[ RUN      ] DomainEntitiesTest.MapFileEntityCompleteRow
[       OK ] DomainEntitiesTest.MapFileEntityCompleteRow (0 ms)
[ RUN      ] DomainEntitiesTest.MapFileEntityNullableFieldsNull
[       OK ] DomainEntitiesTest.MapFileEntityNullableFieldsNull (0 ms)
[ RUN      ] DomainEntitiesTest.MapFileVersionEntityRow
[       OK ] DomainEntitiesTest.MapFileVersionEntityRow (0 ms)
[ RUN      ] DomainEntitiesTest.MapEncryptedFileMetadataEntityRow
[       OK ] DomainEntitiesTest.MapEncryptedFileMetadataEntityRow (0 ms)
[ RUN      ] DomainEntitiesTest.MapEncryptedFileMetadataNullMimeType
[       OK ] DomainEntitiesTest.MapEncryptedFileMetadataNullMimeType (0 ms)
[ RUN      ] DomainEntitiesTest.MapFileTransferEntityRow
[       OK ] DomainEntitiesTest.MapFileTransferEntityRow (0 ms)
[ RUN      ] DomainEntitiesTest.MapFileChunkEntityRow
[       OK ] DomainEntitiesTest.MapFileChunkEntityRow (0 ms)
[ RUN      ] DomainEntitiesTest.MapFileAccessEntityRow
[       OK ] DomainEntitiesTest.MapFileAccessEntityRow (0 ms)
[ RUN      ] DomainEntitiesTest.MapFileAccessEntityNullableNull
[       OK ] DomainEntitiesTest.MapFileAccessEntityNullableNull (0 ms)
[ RUN      ] DomainEntitiesTest.MapFilesOutboxEntityRow
[       OK ] DomainEntitiesTest.MapFilesOutboxEntityRow (0 ms)
[ RUN      ] DomainEntitiesTest.MapFilesOutboxEntityProcessed
[       OK ] DomainEntitiesTest.MapFilesOutboxEntityProcessed (0 ms)
[----------] 25 tests from DomainEntitiesTest (3 ms total)
[  PASSED  ] 25 tests.
```

### 3.2 Full Regression Suite (`verify-local.py`)
Executed the repository-level verification pipeline across all 5 verification stages:
```text
================ Verification Summary ================
  [PASSED]    4.53s  1. CMake Configure
  [PASSED]    0.20s  2. Formatting Check (.clang-format)
  [PASSED]    0.64s  3. Native Compilation & Build
  [PASSED]    0.26s  4. Protobuf & gRPC Contracts Validation
  [PASSED]   26.91s  5. CTest Execution Suite (163/163 passed)
-----------------------------------------------------
ALL CHECKS PASSED in 32.54s
```
**Total passing test cases**: **163 / 163 tests passed (100%)**.

---

## 4. Next Ticket
- **Ticket**: `FILES-002-T03` — File, Version & Encrypted Metadata Repositories (`src/files/repository/file_repository.{hpp,cpp}`, `src/files/repository/file_version_repository.{hpp,cpp}`).
