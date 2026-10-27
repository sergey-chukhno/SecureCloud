# Walkthrough — Card FILES-004: Implement File Metadata and Lifecycle

**Card Identifier**: `FILES-004` (or `FILE-004`)  
**Milestone**: M5 — Secure Files  
**Branch**: `feature/files-004-implement-file-metadata-and-lifecycle`  
**Developer**: Louis  
**Lead & Security Architect**: Sergey  

---

## 1. Executive Summary

Card **FILES-004** implements the authoritative **File Metadata & Lifecycle Management Engine** for the **SecureCloud Files Service** (`securecloud-files`). Building on top of the PostgreSQL 17 persistence layer (**FILES-002**) and MinIO S3 object storage foundation (**FILES-003**), this component enforces the formal file lifecycle state machine, client cryptographic metadata validation, multi-version immutable snapshotting, tenant ownership and access control, retention expiration scanning, and gRPC service operations.

All architectural invariants established in **ADR-004**, **ADR-005**, **ADR-008**, and **Files Design §6** have been strictly implemented and validated across both deterministic unit tests and comprehensive integration tests.

---

## 2. Invariants & Architectural Guarantees

1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design §6.1, §6.26)**:
   - The backend operates exclusively on ciphertext and client-encrypted metadata.
   - Client metadata (`encrypted_filename`, `encrypted_mime_type`, `metadata_nonce`, `metadata_tag`) is unpacked and persisted strictly as encrypted byte vectors.
   - The backend never sees, handles, or stores plaintext files, plaintext filenames, plaintext MIME types, or encryption keys.

2. **Immutable Completed Versions Invariant (Files Design §6.3, Backlog Item FILE-004)**:
   - Once a file version transitions to `AVAILABLE`, its MinIO object key (`objects/{file_id}/{version_number}`) and ciphertext checksum (`checksum_sha256`) become permanently immutable.
   - Any modification or update creates a new version (`version_number = N + 1`) with an independent MinIO object key, without mutating completed version records.

3. **Approved Lifecycle State Machine (Files Design §6.3, §6.19)**:
   - Happy path: `CREATED → UPLOADING → FINALIZING → AVAILABLE`.
   - Error paths: `CREATED → FAILED`, `UPLOADING → FAILED`, `FINALIZING → FAILED`.
   - Expiration / Deletion: `AVAILABLE → EXPIRED / DELETED`, `EXPIRED → DELETED`, `CREATED / UPLOADING → DELETED`.
   - Terminal states: `FAILED` and `DELETED` have zero outward transitions.

4. **Transactional Outbox Atomicity (ADR-004, Files Design §6.22)**:
   - Every file lifecycle state change atomically persists a domain event in `files_outbox` (`FILE_CREATED`, `FILE_VERSION_CREATED`, `FILE_AVAILABLE`, `FILE_FAILED`, `FILE_EXPIRED`, `FILE_DELETED`) within the exact same database transaction.

5. **Tenant Isolation & Ownership Enforcement**:
   - Every file is owned by `owner_user_id` and `owner_device_id`.
   - Callers without explicit ownership or an active grant in `file_access` are rejected with `UnauthorizedFileAccessException` (`grpc::StatusCode::PERMISSION_DENIED`).

---

## 3. Tickets Implemented

### FILES-004-T01: Domain Lifecycle State Machine & Transition Validator
- Implemented `src/files/domain/lifecycle_state_machine.hpp` and `.cpp`.
- Provides authoritative state transition matrix checking all 49 combinations (7x7).
- Reuses `FileStatus` enum from `src/files/domain/file_entity.hpp` to prevent duplicate type definitions (ODR).
- Bidirectional string and Protobuf (`v1::FileLifecycleState`) conversion helpers.
- Deduplicated `is_valid_state_transition` in `src/files/repository/file_repository.{hpp,cpp}`.
- Added comprehensive unit test `tests/unit/files/lifecycle_state_machine_test.cpp`.

### FILES-004-T02: Metadata Validation Engine & Domain DTOs
- Implemented `src/files/domain/metadata_validator.hpp` and `.cpp`.
- Validation constants: 5 GiB max file size, 4 MiB standard chunk size, 24-byte nonce (XChaCha20), 16-byte tag (Poly1305), algorithm whitelisting (`XChaCha20-Poly1305`).
- Domain DTOs: `CreateFileRequestDto`, `CreateFileVersionRequestDto`, `ValidationResult`.
- Functions: `validate_create_file_request`, `validate_create_version_request`, `unpack_client_crypto_metadata`, `calculate_expected_chunk_count`, `is_valid_uuid`, `generate_uuid_v7`, `is_valid_sha256_hex`.
- Unit test suite: `tests/unit/files/metadata_validator_test.cpp`.

### FILES-004-T03: FileLifecycleService Domain Layer & Immutable Versioning Engine
- Implemented `src/files/service/file_lifecycle_service.hpp` and `.cpp`.
- Exception hierarchy: `FileServiceException`, `FileNotFoundException`, `UnauthorizedFileAccessException`, `ImmutableVersionException`, `FileLifecycleValidationException`.
- Methods:
  - `create_file`: Atomically persists file entity, encrypted metadata, and outbox event `FILE_CREATED`.
  - `create_file_version`: Calculates next version number (`N + 1`), prevents in-place mutation of active completed versions, and writes `FILE_VERSION_CREATED`.
  - `transition_lifecycle`: Validates transition against state machine, checks ownership/access, and emits state change outbox event.
  - `get_file_metadata`: Aggregates file entity, encrypted metadata, active version, and version history.
  - `delete_file`: Logically transitions file to `DELETED` and writes `FILE_DELETED`.
  - `evaluate_and_expire_files`: Scans past-retention files, marks as `EXPIRED`, and emits `FILE_EXPIRED`.
- Refactored `src/files/service/metadata_manager.hpp` to delegate to `FileLifecycleService`.

### FILES-004-T04: FilesServiceImpl gRPC Wiring & RPC Implementation
- Updated `src/files/service/files_service_impl.hpp` to inject `FileLifecycleService`.
- In `src/files/service/files_service_impl.cpp`:
  - `CreateFileUpload`: Validates request, unpacks crypto metadata, calls `create_file`, persists transfer session, returns `upload_id` and `TRANSFER_STATUS_PENDING`.
  - `GetFileMetadata`: Validates UUID, calls `get_file_metadata`, maps domain entities to protobuf fields.
  - `DeleteFile`: Validates UUID, calls `delete_file`, returns `FILE_LIFECYCLE_STATE_DELETED`.
  - `FinalizeFileUpload`: Added lifecycle transition check (`UPLOADING -> FINALIZING`).

### FILES-004-T05: Comprehensive Unit Test Suite
- `tests/unit/files/lifecycle_state_machine_test.cpp`: Tests all 49 state combinations, conversions, exception throwing.
- `tests/unit/files/metadata_validator_test.cpp`: Tests UUID validation, size boundaries, chunk count formula, nonce/tag lengths, crypto metadata unpacking.
- `tests/unit/files/file_lifecycle_service_test.cpp`: Fail-fast validation tests, mock service testing version immutability, ownership checks, logical deletion, expiration scanner.
- `tests/unit/files/files_service_impl_test.cpp`: Updated to verify gRPC endpoints (`CreateFileUpload`, `GetFileMetadata`, `DeleteFile`, `FinalizeFileUpload`) with mock lifecycle service and authorization context.
- Registered all targets in `tests/unit/CMakeLists.txt`.

### FILES-004-T06: Live PostgreSQL Integration Test Suite
- Implemented `tests/integration/files_lifecycle_integration_test.cpp`:
  - TC1: Full lifecycle progression (`CREATED → UPLOADING → FINALIZING → AVAILABLE`) and outbox verification.
  - TC2: Immutable versioning and multi-version creation (`v1` untouched, `v2` added).
  - TC3: Invalid state transition rejection and terminal state immutability.
  - TC4: Retention expiration workflow with `evaluate_and_expire_files`.
  - TC5: Logical deletion and terminal state guards.
  - TC6: Tenant isolation and access control grants (`READ`/`WRITE`).
  - TC7: End-to-end gRPC service calls with `FilesServiceImpl`.
- Registered `securecloud_files_lifecycle_integration_test` in `tests/integration/CMakeLists.txt`.

---

## 4. Verification & Artifact Summary

| File Path | Description | Ticket |
| :--- | :--- | :--- |
| `specs/phase5/FILES-004-tickets.md` | Authoritative technical specification & ticket definitions | Card Spec |
| `src/files/domain/lifecycle_state_machine.hpp` | Domain lifecycle state machine definitions & transitions | T01 |
| `src/files/domain/lifecycle_state_machine.cpp` | State machine transition matrix & conversion implementations | T01 |
| `src/files/domain/metadata_validator.hpp` | Metadata validation engine, constants, and DTOs | T02 |
| `src/files/domain/metadata_validator.cpp` | Crypto unpacking, UUID validation, chunk math | T02 |
| `src/files/service/file_lifecycle_service.hpp` | FileLifecycleService interface & exception hierarchy | T03 |
| `src/files/service/file_lifecycle_service.cpp` | Transactional domain operations & immutable versioning | T03 |
| `src/files/service/metadata_manager.hpp` | MetadataManager delegating to FileLifecycleService | T03 |
| `src/files/service/files_service_impl.hpp` | FilesServiceDependencies lifecycle service injection | T04 |
| `src/files/service/files_service_impl.cpp` | Production implementations of CreateFileUpload, GetFileMetadata, DeleteFile | T04 |
| `tests/unit/files/lifecycle_state_machine_test.cpp` | Exhaustive 7x7 state machine transition tests | T05 |
| `tests/unit/files/metadata_validator_test.cpp` | Input constraints & crypto metadata unit tests | T05 |
| `tests/unit/files/file_lifecycle_service_test.cpp` | Invariants & mock lifecycle domain tests | T05 |
| `tests/unit/files/files_service_impl_test.cpp` | Updated gRPC service implementation unit tests | T05 |
| `tests/integration/files_lifecycle_integration_test.cpp` | 7-part live PostgreSQL lifecycle integration test suite | T06 |
| `src/files/CMakeLists.txt` | Build configuration for files service domain & service libraries | T01-T04 |
| `tests/unit/CMakeLists.txt` | Target registrations for unit test binaries | T05 |
| `tests/integration/CMakeLists.txt` | Target registration for lifecycle integration test binary | T06 |
