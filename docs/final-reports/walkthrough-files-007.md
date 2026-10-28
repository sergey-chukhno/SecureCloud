# Walkthrough — Card FILES-007: Authorized Chunked & Byte-Range Download Pipeline

**Card Identifier**: `FILES-007` (or `FILE-007`)  
**Milestone**: M5 — Secure Files  
**Branch**: `feature/files-007-implement-authorized-chunked-download`  
**Developer**: Louis  
**Lead & Security Architect**: Sergey  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary

Card **FILES-007** delivers the authoritative **Authorized Chunked & Byte-Range Download Pipeline** for the **SecureCloud Files Service** (`securecloud-files`). Building directly upon the whole-object storage architecture established in **FILES-006**, this card provides high-throughput, memory-bounded, resumable streaming of encrypted files from MinIO S3 directly to authorized clients via the API Gateway.

```
Client ──► Gateway ──► Files Service ──► MinIO (S3)
   ▲                                         │
   └──────────── Encrypted Chunks ───────────┘
```

### Canonical Resume Model

$$\mathbf{(file\_id,\; file\_version,\; starting\_chunk)}$$

Downloads operate on discrete, pre-encrypted chunks ($4\text{ MiB}$ standard size) indexed from $0$ to $N-1$. Clients can resume an interrupted download from any valid chunk index $N$, eliminating redundant transfers while strictly guaranteeing data integrity.

---

## 2. Invariants & Architectural Guarantees

1. **Authorization Before Content Access (ADR-005, ADR-008)**:
   - Every download request checks authorization prior to issuing any S3 read requests or streaming content.
   - The file owner has inherent read access; other users must possess an active, valid `FilePermission::Read` grant verified via [FileAccessRepository::check_access](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/repository/file_access_repository.hpp). Unauthorized access is rejected with `PERMISSION_DENIED`.

2. **Zero-Plaintext & No-Decryption Invariant (Security §6.1, §6.26)**:
   - The Files Service has zero access to client encryption keys or plaintext.
   - All streamed bytes are raw ciphertext chunks exactly as stored in MinIO.
   - No plaintext search or decryption is performed on server components.

3. **Strict Lifecycle Guard**:
   - Downloads are strictly prohibited unless the target file is in `FileStatus::Available`. Files in `Uploading`, `Finalizing`, `Failed`, or `Deleted` state are rejected with `FAILED_PRECONDITION`.

4. **Bounded Buffer Execution & No Whole-File Buffering**:
   - Chunk downloads are bounded by the maximum chunk size ($\le 4\text{ MiB}$).
   - The service never buffers whole multi-gigabyte files into RAM.
   - Data is retrieved from MinIO via HTTP byte-range slicing:
     $$\text{Range: bytes=} \big[k \times 4194304,\; \min((k+1) \times 4194304 - 1,\; \text{file\_size} - 1)\big]$$

5. **Canonical Resume Unit**:
   - The encrypted chunk remains the canonical transfer and resume unit across the pipeline.
   - Clients supply `starting_chunk = N` (or request individual chunk indices $N$), skipping chunks $0 \dots N-1$.

6. **Cancellation & Disconnection Handling**:
   - If a client terminates or times out, S3 connections and bounded memory allocations are immediately freed without dangling server transactions.

---

## 3. Tickets Implemented

### FILES-007-T01: Download Session Validator & Precondition Guard
- **Header**: [src/files/domain/download_validator.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/download_validator.hpp)
- **Source**: [src/files/domain/download_validator.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/download_validator.cpp)
- **Unit Test**: [tests/unit/files/download_validator_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/download_validator_test.cpp)
- **Functionality**:
  - Validates `file_id`, `version_number`, and `chunk_index`.
  - Enforces `FileStatus::Available` requirement.
  - Verifies file ownership or active read permission grants.
  - Validates chunk index bounds against `total_chunks`.

### FILES-007-T02: Chunk Retrieval & S3 Byte-Range Streaming Engine
- **Header**: [src/files/service/chunk_download_engine.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/chunk_download_engine.hpp)
- **Source**: [src/files/service/chunk_download_engine.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/chunk_download_engine.cpp)
- **Unit Test**: [tests/unit/files/chunk_download_engine_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/chunk_download_engine_test.cpp)
- **Functionality**:
  - Implements `calculate_byte_range(chunk_index, chunk_size, total_size)` for precise chunk slicing.
  - Queries MinIO S3 object `objects/{file_id}/{version_number}` using HTTP `ByteRange{start, end}`.
  - Computes and verifies chunk ciphertext SHA-256 integrity.
  - Enforces bounded memory buffer allocation ($\le 4\text{ MiB}$).

### FILES-007-T03: Resumable Download Manager & Session Pipeline
- **Header**: [src/files/service/download_manager.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/download_manager.hpp)
- **Source**: [src/files/service/download_manager.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/download_manager.cpp)
- **Unit Test**: [tests/unit/files/download_manager_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/download_manager_test.cpp)
- **Functionality**:
  - Implements `IDownloadManager` orchestrating `initiate_download` and `download_chunk`.
  - Connects database repositories (`FileRepository`, `FileVersionRepository`, `FileAccessRepository`) with `IChunkDownloadEngine`.
  - Enforces canonical resume model $(file\_id, file\_version, starting\_chunk)$.

### FILES-007-T04: gRPC DownloadChunk Endpoint Integration & Error Mapping
- **Source**: [src/files/service/files_service_impl.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/files_service_impl.cpp)
- **Functionality**:
  - Connects `DownloadChunk` RPC to `DownloadManager`.
  - Maps domain exceptions and status codes cleanly to gRPC statuses:
    - Unauthorized access $\longrightarrow$ `grpc::StatusCode::PERMISSION_DENIED`
    - Non-existent file/version $\longrightarrow$ `grpc::StatusCode::NOT_FOUND`
    - Inactive lifecycle state $\longrightarrow$ `grpc::StatusCode::FAILED_PRECONDITION`
    - Out-of-bounds chunk index $\longrightarrow$ `grpc::StatusCode::OUT_OF_RANGE`
    - Transient storage errors $\longrightarrow$ `grpc::StatusCode::UNAVAILABLE`

### FILES-007-T05: Files Service Download Implementation Unit Test Suite
- **Source**: [tests/unit/files/files_service_impl_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/files_service_impl_test.cpp)
- **Functionality**:
  - Implements `MockDownloadManager` verifying gRPC call delegation.
  - Tests peer authorization resolution, invalid UUID validation, error mappings, and successful chunk payload responses.

### FILES-007-T06: Live End-to-End Download Integration Test Suite & Walkthrough
- **Integration Test**: [tests/integration/files_download_integration_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/integration/files_download_integration_test.cpp)
- **Walkthrough Document**: [docs/final-reports/walkthrough-files-007.md](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/docs/final-reports/walkthrough-files-007.md)
- **Test Coverage**:
  - **TC1: Happy Path Chunk Download**: Downloads all chunks of an available multi-chunk object; verifies chunk SHA-256 and byte continuity.
  - **TC2: Canonical Resume Model**: Resumes download from `starting_chunk = 1`, skipping chunk 0; verifies exact ciphertext slice matches.
  - **TC3: Authorization Guard**: Verifies non-owner without read permission is rejected (`PERMISSION_DENIED`).
  - **TC4: Lifecycle Guard**: Verifies non-available file (`Uploading`) is rejected (`FAILED_PRECONDITION`).
  - **TC5: Out-of-Bounds Chunk Guard**: Verifies chunk index $\ge total\_chunks$ is rejected (`OUT_OF_RANGE`).
  - **TC6: Resume Model Validation**: Verifies boundary handling for single-chunk and multi-chunk files.

---

## 4. Verification and Validation

All unit tests and integration tests have been registered in CMake:
- [src/files/CMakeLists.txt](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/CMakeLists.txt)
- [tests/unit/CMakeLists.txt](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/CMakeLists.txt)
- [tests/integration/CMakeLists.txt](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/integration/CMakeLists.txt)

All tests verify that zero whole-file buffering occurs, zero plaintext is exposed, and chunk ranges accurately reflect 4 MiB partitions.
