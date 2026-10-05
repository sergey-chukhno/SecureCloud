# Walkthrough: FILES-001-T06 — Unit & Integration Test Suite & Verification Harness

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-001-T06`  
**Card**: `FILES-001` (Establish Files Service Foundation)  
**Branch**: `feature/files-001-establish-files-service-foundation`

The primary objective of `FILES-001-T06` is to build an integration test suite and verification harness for the `securecloud-files` microservice, providing end-to-end automated proof of correctness for the service foundation established across `FILES-001-T01` through `FILES-001-T05`.

This is the **final ticket** of Card `FILES-001`.

---

## 2. Key Components Delivered

### 2.1 Files Integration Test Suite (`tests/integration/files_integration_test.cpp`)
Implemented 8 integration test scenarios covering the full service lifecycle:

1. **`ServiceStartsSuccessfullyWithValidMtlsCredentials`**:
   - Boots an in-process gRPC server using development PKI credentials (`deploy/dev-pki/services/files/files.crt`, `files.key`, `ca.crt`).
   - Verifies server starts and binds successfully to an ephemeral port (`127.0.0.1:0`).

2. **`GatewayClientEstablishesMtlsChannelSuccessfully`**:
   - Establishes a client channel with Gateway identity (`deploy/dev-pki/services/gateway/gateway.crt`).
   - Verifies successful mutual TLS handshake and SAN validation.
   - Executes `HealthService.Check()` over the mTLS channel and confirms `SERVING` response.

3. **`RejectsUnauthenticatedOrUntrustedMtlsCallers`**:
   - **Insecure Plaintext Rejection**: Plaintext client fails closed at TLS layer (`grpc::StatusCode::UNAVAILABLE`).
   - **Unauthorized Service Identity Rejection**: Client presenting a valid certificate from another service (e.g., `audit` identity) fails post-handshake authorization with `grpc::StatusCode::PERMISSION_DENIED` (`"Caller peer identity not authorized"`).

4. **`AllSevenRpcMethodsReturnDeterministicUnimplemented`**:
   - Authenticated Gateway client invokes all 7 gRPC operations defined in `files.proto`:
     1. `CreateFileUpload`
     2. `UploadChunk`
     3. `FinalizeFileUpload`
     4. `GetFileMetadata`
     5. `DownloadChunk`
     6. `CancelFileUpload`
     7. `DeleteFile`
   - Confirms all 7 RPCs return `grpc::StatusCode::UNIMPLEMENTED` with the exact message:  
     `"FilesService method not implemented in FILES-001 skeleton"`.

5. **`ReadinessReturnsServingWhenBothDependenciesHealthy`**:
   - Evaluates dual dependency probes using `FilesHealthEvaluator`.
   - Confirms that when both PostgreSQL (port 5433) and MinIO S3 (port 9000) are healthy, readiness probe `Check("readiness")` returns `SERVING`.

6. **`ReadinessDegradesWhenEitherDependencyFailsWhileLivenessRemainsServing`**:
   - Drops the PostgreSQL dependency -> `readiness` degrades immediately to `NOT_SERVING`, while `liveness` (`Check("")`) remains `SERVING`.
   - Drops the MinIO dependency as well -> `readiness` remains `NOT_SERVING`.
   - Re-evaluates -> confirms dynamic degraded state tracking.

7. **`ObservationalGuardEnforcesPort5432Invariant`**:
   - Explicitly asserts that developer workstation port 5432 (reserved for host PostgreSQL 14) is never contacted:
     ```cpp
     ASSERT_NE(config.db_port, 5432)
         << "CRITICAL: Tests and Files service must NEVER connect to host PostgreSQL on port 5432!";
     EXPECT_EQ(config.db_port, 5433);
     ```
   - Confirms `FilesDbConnectionPool` throws `db::PortForbiddenException` when instantiated with port 5432.

8. **`GracefulShutdownCompletesDeterministically`**:
   - Sets `health_manager.set_shutting_down(true)`.
   - Confirms `readiness` drops to `NOT_SERVING` immediately while `liveness` remains `SERVING`.
   - Shuts down gRPC server within a 500ms timeout and cleanly drains the database connection pool.
   - Confirms evaluator background thread stops without deadlocks or hangs.

### 2.2 Fast Deterministic Process Teardown
- Custom `main()` implementation with Win32 `::TerminateProcess` on Windows to eliminate gRPC C++ background thread teardown latency:
  ```cpp
  int main(int argc, char** argv) {
      ::testing::InitGoogleTest(&argc, argv);
      int result = RUN_ALL_TESTS();
  #ifdef _WIN32
      std::fflush(nullptr);
      ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
  #else
      return result;
  #endif
  }
  ```

### 2.3 CMake Integration (`tests/integration/CMakeLists.txt`)
- Target `securecloud_files_integration_test` registered with:
  - `securecloud::files_service`
  - `securecloud::files_health`
  - `securecloud::files_storage`
  - `securecloud::files_db`
  - `securecloud::files_config`
  - `securecloud::common`
  - `securecloud_proto`
  - `ws2_32` (Windows Sockets)
  - `GTest::gtest`
- Registered with `gtest_discover_tests`.

---

## 3. Verification & Test Results

### 3.1 Integration Test Execution (`FilesIntegrationTest`)
All 8 integration scenarios pass:
```
    Start 123: FilesIntegrationTest.ServiceStartsSuccessfullyWithValidMtlsCredentials
1/8 Test #123: FilesIntegrationTest.ServiceStartsSuccessfullyWithValidMtlsCredentials .......................   Passed    2.08 sec
    Start 124: FilesIntegrationTest.GatewayClientEstablishesMtlsChannelSuccessfully
2/8 Test #124: FilesIntegrationTest.GatewayClientEstablishesMtlsChannelSuccessfully .........................   Passed    2.10 sec
    Start 125: FilesIntegrationTest.RejectsUnauthenticatedOrUntrustedMtlsCallers
3/8 Test #125: FilesIntegrationTest.RejectsUnauthenticatedOrUntrustedMtlsCallers ............................   Passed    2.16 sec
    Start 126: FilesIntegrationTest.AllSevenRpcMethodsReturnDeterministicUnimplemented
4/8 Test #126: FilesIntegrationTest.AllSevenRpcMethodsReturnDeterministicUnimplemented ......................   Passed    2.26 sec
    Start 127: FilesIntegrationTest.ReadinessReturnsServingWhenBothDependenciesHealthy
5/8 Test #127: FilesIntegrationTest.ReadinessReturnsServingWhenBothDependenciesHealthy ......................   Passed    2.10 sec
    Start 128: FilesIntegrationTest.ReadinessDegradesWhenEitherDependencyFailsWhileLivenessRemainsServing
6/8 Test #128: FilesIntegrationTest.ReadinessDegradesWhenEitherDependencyFailsWhileLivenessRemainsServing ...   Passed    2.87 sec
    Start 129: FilesIntegrationTest.ObservationalGuardEnforcesPort5432Invariant
7/8 Test #129: FilesIntegrationTest.ObservationalGuardEnforcesPort5432Invariant .............................   Passed    2.04 sec
    Start 130: FilesIntegrationTest.GracefulShutdownCompletesDeterministically
8/8 Test #130: FilesIntegrationTest.GracefulShutdownCompletesDeterministically ..............................   Passed    2.09 sec

100% tests passed, 0 tests failed out of 8
```

### 3.2 Full Project Regression Suite
All 130 tests across the entire SecureCloud project pass with zero regressions:
```
100% tests passed, 0 tests failed out of 130
Total Test time (real) = 26.31 sec
```

### 3.3 Local Verification Script (`scripts/verify-local.py`)
Executed full 5-stage verification orchestrator:
```
================ Verification Summary ================
  [PASSED]    4.59s  1. CMake Configure
  [PASSED]    0.22s  2. Formatting Check (.clang-format)
  [PASSED]   59.84s  3. Native Compilation & Build
  [PASSED]    2.09s  4. Protobuf & gRPC Contracts Validation
  [PASSED]   26.92s  5. CTest Execution Suite
-----------------------------------------------------
ALL CHECKS PASSED in 93.66s
```

---

## 4. Card `FILES-001` Complete Summary

With `FILES-001-T06` finished, **all 6 tickets of Card `FILES-001` (Establish Files Service Foundation)** are completed:

| Ticket ID | Description | Commits / Artifacts |
|---|---|---|
| `FILES-001-T01` | Protobuf & gRPC Contract Baseline (`files.proto`) | Commit `641f7dd` |
| `FILES-001-T02` | PostgreSQL Connection Pool & Port 5432 Guard | Commit `d22f8c1` |
| `FILES-001-T03` | MinIO S3 Client Wrapper & SigV4 Signer | Commit `7ecafcf` |
| `FILES-001-T04` | Modular Files Service Skeleton & mTLS Server | Commit `78c4563` |
| `FILES-001-T05` | Dual-Dependency Health Evaluator & Graceful Shutdown | Commit `bd1add4` |
| `FILES-001-T06` | Integration Test Suite & Verification Harness | Commit Pending (`test(files)`) |

---

## 5. Next Steps
- Commit `FILES-001-T06` locally to feature branch `feature/files-001-establish-files-service-foundation`.
- Card `FILES-001` is now ready to be pushed to remote origin.
