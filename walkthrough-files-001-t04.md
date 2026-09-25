# Walkthrough: FILES-001-T04 — Modular Files Service Architecture & gRPC mTLS Server Implementation

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-001-T04`  
**Card**: `FILES-001` (Establish Files Service Foundation)  
**Branch**: `feature/files-001-establish-files-service-foundation`

The primary objective of `FILES-001-T04` is to establish the core gRPC service skeleton and modular architecture for the `securecloud-files` microservice, binding all 7 authoritative Protobuf/gRPC operations under strict mutual TLS (mTLS) enforcement and secret-safe operational logging.

---

## 2. Key Components Delivered

### 2.1 Modular Domain Architecture (`src/files/service/`)
To support the progressive delivery of Phase 5 (Secure Files), we decomposed the service into four cleanly separated domain abstractions:
- [`UploadSessionManager`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/upload_session_manager.hpp) (`IUploadSessionManager`): Manages the upload state machine (`PENDING` -> `IN_PROGRESS` -> `COMPLETED`/`CANCELLED`), lease expiration, and chunk sequence tracking.
- [`DownloadManager`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/download_manager.hpp) (`IDownloadManager`): Coordinates download authorization checks, byte range chunk requests, and chunk delivery.
- [`StorageEngine`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/storage_engine.hpp) (`IStorageEngine`): Wraps `storage::S3Client` to manage S3 bucket objects, multipart uploads, and chunk streams.
- [`MetadataManager`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/metadata_manager.hpp) (`IMetadataManager`): Wraps `db::FilesDbConnectionPool` to manage file and chunk persistence in PostgreSQL 17.

### 2.2 Core Service Implementation (`src/files/service/files_service_impl.{hpp,cpp}`)
- Inherits from generated `securecloud::files::v1::FilesService::Service`.
- Implements all 7 authoritative RPC methods:
  1. `CreateFileUpload`
  2. `UploadChunk`
  3. `FinalizeFileUpload`
  4. `GetFileMetadata`
  5. `DownloadChunk`
  6. `CancelFileUpload`
  7. `DeleteFile`
- Deterministic response: all 7 methods return `grpc::StatusCode::UNIMPLEMENTED` with the exact message:
  `"FilesService method not implemented in FILES-001 skeleton"`.
- Dual-signature overloads accepting `const grpc::AuthContext* auth_ctx` for testing and decoupling.

### 2.3 mTLS Peer Identity Verification
- Integrates `securecloud::common::security::extract_peer_service_identity` and `verify_peer_service_identity`.
- Fails closed: calls without client certificates return `grpc::StatusCode::UNAUTHENTICATED`.
- Strict SAN authorization: only `DNS:gateway` is authorized to invoke file coordination RPCs. Calls from other services return `grpc::StatusCode::PERMISSION_DENIED` (`"Caller peer identity not authorized"`).
- Configurable identity checking enables zero-network in-process channel testing.

### 2.4 Secret-Safe Operational Logging
- `RpcScopeLogger` RAII struct tracks microsecond durations and logs:
  `[SecureCloud] [files] RPC <method> completed with code <code_name> in <us> us (peer: '<peer>')`.
- **Zero-Plaintext Invariant & Secret Protection**: Strictly prohibits logging ciphertext bytes (`encrypted_data`), file encryption keys, or S3 credentials.

### 2.5 Cross-Platform Win32 Macro Guard (`proto/proto_win32_compat.hpp`)
- On Windows, the Win32 SDK header `winbase.h` defines `#define DeleteFile DeleteFileW` (or `DeleteFileA`).
- We introduced `proto/proto_win32_compat.hpp` and forced its inclusion (`/FI`) in `proto/CMakeLists.txt` for `securecloud_proto` on MSVC. This ensures `DeleteFile` in gRPC stubs and service definitions remains a clean C++ symbol without macro collisions across platforms.

### 2.6 Daemon Integration & Graceful Shutdown (`src/files/main.cpp`)
- Instantiates `FilesDbConnectionPool` and `S3Client` from validated `FilesConfig`.
- Instantiates `FilesServiceImpl` configured with `expected_client_identity = "gateway"`.
- Registers both `FilesServiceImpl` and `HealthServiceImpl` on the mTLS server (`GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`).
- Coordinates graceful termination on `SIGINT`/`SIGTERM`: shuts down gRPC server (5s bounded deadline), drains the database connection pool, and closes all open connections.

---

## 3. Verification & Test Results

### 3.1 Unit Test Suite (`tests/unit/files/files_service_impl_test.cpp`)
- **In-Process gRPC Server & Client Stub Tests**:
  - `FilesServiceInProcessTest.CreateFileUploadReturnsUnimplemented` (PASSED)
  - `FilesServiceInProcessTest.UploadChunkReturnsUnimplemented` (PASSED)
  - `FilesServiceInProcessTest.FinalizeFileUploadReturnsUnimplemented` (PASSED)
  - `FilesServiceInProcessTest.GetFileMetadataReturnsUnimplemented` (PASSED)
  - `FilesServiceInProcessTest.DownloadChunkReturnsUnimplemented` (PASSED)
  - `FilesServiceInProcessTest.CancelFileUploadReturnsUnimplemented` (PASSED)
  - `FilesServiceInProcessTest.DeleteFileReturnsUnimplemented` (PASSED)
- **Null Pointer Argument Validation**:
  - `FilesServiceImplDirectTest.RejectsNullArguments` (PASSED)
- **mTLS Peer SAN Authorization Tests**:
  - `FilesServiceImplAuthTest.RejectsUnauthenticatedCallerWhenPeerRequired` (PASSED)
  - `FilesServiceImplAuthTest.RejectsUnauthorizedPeerServiceIdentity` (PASSED)
  - `FilesServiceImplAuthTest.AcceptsAuthorizedPeerGateway` (PASSED)
- **Modular Dependency Injection**:
  - `FilesServiceImplModularTest.InjectsSubComponentDependencies` (PASSED)

### 3.2 Full Regression Suite
Execution of all project tests via CTest:
```
100% tests passed, 0 tests failed out of 114
Total Test time (real) = 8.71 sec
```

---

## 4. Next Steps
With `FILES-001-T04` complete, we proceed to:
- **`FILES-001-T05`**: Dual-Dependency Health/Readiness Evaluator & Bounded Graceful Shutdown (`src/files/health/`).
