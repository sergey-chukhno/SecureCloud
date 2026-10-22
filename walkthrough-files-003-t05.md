# Walkthrough: FILES-003-T05 — Storage Engine & S3Client Unit Test Suites

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-003-T05`  
**Card**: `FILES-003` (Establish MinIO Object Storage Integration)  
**Branch**: `feature/files-003-Establish-MinIO-object-storage-integration`

`FILES-003-T05` establishes 100% offline, deterministic, zero-network unit test suites for `StorageEngine` and `S3Client`, covering every REST operation, SigV4 signature derivation, retry flow, opaque key derivation, and integrity check.

---

## 2. Test Suites Delivered

### 2.1 `tests/unit/files/storage_engine_test.cpp`
Targets `securecloud::files::service::StorageEngine`:
1. `OpaqueKeyDerivation`:
   - Validates `chunks/{transfer_id}/{chunk_index}` and `objects/{file_id}/{version_number}`.
   - Ensures no plaintexts (emails, filenames, file extensions) leak into keys.
2. `PutAndGetChunkSuccess`:
   - Validates chunk upload with exact SHA-256 and subsequent retrieval.
3. `IntegrityMismatchRejection`:
   - Asserts that corrupted payload / mismatched expected hash throws `S3IntegrityException` without issuing network calls.
4. `GetChunkNotFoundReturnsNullOpt`:
   - Verifies 404 maps to `std::nullopt`.
5. `DeleteChunkSuccess`:
   - Validates deletion targeting specific chunk key.
6. `FileObjectOperations`:
   - Verifies `put_file_object` and byte-range `get_file_object` with `Range: bytes=0-3`.
7. `BatchChunkCleanup`:
   - Verifies `delete_transfer_chunks` lists by prefix and cleans up all uncommitted chunks.
8. `NullS3ClientThrows`:
   - Verifies defensive checking when `StorageEngine` lacks `S3Client` dependency.

### 2.2 `tests/unit/files/s3_client_test.cpp` (Additions)
Targets `securecloud::files::storage::S3Client`:
1. `RetryPolicyTransientRecovery`: Verifies transient 503 recovery on second attempt.
2. `RetryPolicyExhaustion`: Verifies permanent 503 throws `S3ServerException` after 4 attempts (1 initial + 3 retries).
3. `NonRetryableErrorFailsImmediately`: Verifies 404 fails on attempt 1 without retry.
4. `RetryPolicyBackoffCalculation`: Verifies exponential scaling, capping, and status classifications.

### 2.3 Build Integration (`tests/unit/CMakeLists.txt`)
Registered `securecloud_storage_engine_test` target and added to GoogleTest automated discovery.
