# Walkthrough: FILES-003-T06 — MinIO Live Integration Test Suite & Card Sign-Off

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-003-T06`  
**Card**: `FILES-003` (Establish MinIO Object Storage Integration)  
**Branch**: `feature/files-003-Establish-MinIO-object-storage-integration`

`FILES-003-T06` is the final quality gate for Card **FILES-003**, proving end-to-end integration between `StorageEngine`, `S3Client`, and live MinIO S3 instances over real TCP/HTTP sockets.

---

## 2. Test Suite Delivered (`tests/integration/files_minio_storage_integration_test.cpp`)

### 2.1 Automated Preflight Connectivity Probe
To preserve CI stability in environments where MinIO is not running, the test fixture implements a TCP socket preflight check on `127.0.0.1:9000` via `common::health::probe_tcp_connectivity`. When unreachable, the suite cleanly skips via `GTEST_SKIP()`.

### 2.2 Live Integration Test Cases
1. **TC1: Live Bucket Reachability & Credential Validation (`TC1_LiveBucketReachabilityAndPing`)**:
   - Pings bucket `securecloud-files-encrypted` using SigV4 credentials.
2. **TC2: Live Chunk Roundtrip with SHA-256 Verification (`TC2_LiveChunkPutAndGetRoundtrip`)**:
   - Generates 1 MiB ciphertext payload, computes SHA-256 digest, uploads chunk, retrieves chunk, verifies exact byte identity, and deletes chunk.
3. **TC3: Range GET Verification (`TC3_LiveRangeGetVerification`)**:
   - Uploads 16 KiB file object, downloads sub-ranges (`0-1023` and `1024-2047`), and validates byte-for-byte slice matching against MinIO.
4. **TC4: Multipart Chunk Assembly (`TC4_LiveMultipartUploadLifecycle`)**:
   - Initiates multipart upload, uploads 5 MiB part 1 and 1 KiB part 2, completes assembly, verifies content length via `head_object`, and deletes assembled object.
5. **TC5: Live Batch Transfer Cleanup (`TC5_LiveBatchTransferCleanup`)**:
   - Stores multiple chunks for a transfer ID, executes `delete_transfer_chunks`, and verifies complete removal.
6. **TC6: Cold Restart Durability (`TC6_ColdRestartDurability`)**:
   - Stores chunk, destroys `StorageEngine` and `S3Client` instances, spins up fresh instances, and asserts chunk persistence across lifecycles.

### 2.3 Build Integration (`tests/integration/CMakeLists.txt`)
Registered `securecloud_files_minio_storage_integration_test` linked with `securecloud::files_service`, `securecloud::files_storage`, `securecloud::files_config`, and `ws2_32` on Windows.

---

## 3. Card FILES-003 Sign-Off Checklist
All acceptance criteria specified in `specs/phase5/FILES-003-tickets.md` are satisfied:
- [x] **Zero-Plaintext Invariant**: Only pre-encrypted ciphertext is stored or retrieved.
- [x] **Opaque Key Invariant**: Keys strictly follow UUID schemes (`chunks/{transfer_id}/{chunk_index}`, `objects/{file_id}/{version_number}`).
- [x] **End-to-End Cryptographic Integrity**: SHA-256 digests validated on write and read.
- [x] **Bounded Buffering**: Memory buffers bounded at 4 MiB logical chunk size.
- [x] **S3 REST Capabilities**: PUT, GET (with Range), HEAD, DELETE, ListObjectsV2, and Multipart uploads fully operational.
- [x] **Transient Failure Resilience**: Exponential backoff with jitter and Keep-Alive connection pooling.
- [x] **Unit Test Coverage**: Comprehensive offline tests in `s3_client_test.cpp` and `storage_engine_test.cpp`.
- [x] **Live Integration Verification**: Integration suite in `files_minio_storage_integration_test.cpp`.
- [x] **Cross-Platform Cleanliness**: Portable Winsock/BSD socket abstractions and MSVC/MinGW compliance.
