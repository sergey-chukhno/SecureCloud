# Walkthrough: FILES-001-T05 — Dual-Dependency Health Evaluator & Graceful Shutdown

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-001-T05`  
**Card**: `FILES-001` (Establish Files Service Foundation)  
**Branch**: `feature/files-001-establish-files-service-foundation`

The primary objective of `FILES-001-T05` is to implement the dual-dependency health and readiness evaluation subsystem for `securecloud-files`, coordinating real-time health states across both upstream storage dependencies:
1. **PostgreSQL 17** (`FilesDbConnectionPool::ping()`) — File metadata, chunk manifests, upload sessions
2. **MinIO S3** (`S3Client::ping_bucket()`) — Ciphertext blob storage

The evaluator must enforce the compound readiness rule (`SERVING` if and only if both PostgreSQL AND MinIO are healthy), ensure non-blocking gRPC health check evaluations via atomic cached states, maintain the liveness invariant during dependency degradation, and guarantee immediate readiness drop on SIGINT/SIGTERM shutdown.

---

## 2. Key Components Delivered

### 2.1 Files Health Evaluator (`src/files/health/files_health_evaluator.{hpp,cpp}`)
- **Compound Readiness Rule**:
  - `is_ready()` is `true` if and only if both `is_db_healthy()` AND `is_s3_healthy()` are `true`.
  - If either dependency degrades or fails, readiness drops to `NOT_SERVING` immediately.
  - When both dependencies are operational, readiness automatically restores to `SERVING`.
- **Non-Blocking Architecture**:
  - Operates a dedicated background polling thread with configurable interval (default: 500ms).
  - Background thread evaluates probes and updates atomic flags (`db_healthy_`, `s3_healthy_`, `is_ready_`).
  - Incoming gRPC health check requests read cached atomic state with `memory_order_acquire`, guaranteeing zero latency and immunity against slow upstream timeouts blocking health probes.
- **Liveness Invariant**:
  - The evaluator only drives service **readiness**. Service **liveness** remains `SERVING` regardless of dependency degradation, preventing Kubernetes / container orchestrators from entering destructive restart loops during upstream transient outages.
- **Diagnostic Operational Logging**:
  - Emits clear warnings when PostgreSQL degrades (`"WARNING: PostgreSQL dependency degraded (ping failed)"`).
  - Emits clear warnings when MinIO S3 degrades (`"WARNING: MinIO S3 dependency degraded (ping_bucket failed)"`).
  - Logs when compound readiness flips (`"Files service readiness flipped to NOT_SERVING"` and `"All upstream dependencies healthy... readiness restored to SERVING"`).
- **Graceful Lifecycle Management**:
  - RAII `start()` and `stop()` methods with condition variable wakeups (`cv_loop_.notify_all()`), ensuring zero-hang shutdown on signal termination.

### 2.2 Daemon Integration & Graceful Shutdown (`src/files/main.cpp`)
- Replaced basic TCP probes with the production `FilesHealthEvaluator`:
  ```cpp
  securecloud::common::health::HealthStatusManager health_manager(config.common.service_name);
  securecloud::files::health::FilesHealthEvaluator health_evaluator(
      health_manager, db_pool, s3_client);
  securecloud::common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);
  ```
- Evaluator sets the readiness callback on `health_manager` and runs initial synchronous probe on startup before serving traffic.
- On `SIGINT`/`SIGTERM`:
  ```cpp
  health_manager.set_shutting_down(true);
  health_evaluator.stop();
  std::cout << "[SecureCloud] [" << config.common.service_name << "] Shutting down mTLS server...\n";
  server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
  std::cout << "[SecureCloud] [" << config.common.service_name << "] Draining database connection pool...\n";
  db_pool->drain();
  db_pool->close();
  ```
  1. `health_manager.set_shutting_down(true)` immediately drops readiness to `NOT_SERVING` while keeping liveness `SERVING`.
  2. `health_evaluator.stop()` cleanly terminates the background polling thread.
  3. The gRPC server initiates bounded draining (5s timeout).
  4. The PostgreSQL connection pool is drained and closed cleanly.

### 2.3 CMake Targets (`src/files/CMakeLists.txt`)
- Created `securecloud_files_health` static library and `securecloud::files_health` alias.
- Linked to `securecloud-files` and unit test executables.

---

## 3. Verification & Test Results

### 3.1 Unit Test Suite (`tests/unit/files/files_health_evaluator_test.cpp`)
An 8-case comprehensive unit test suite was implemented and registered under `securecloud_files_health_evaluator_test`:
1. `FilesHealthEvaluatorTest.InitialStateManualStart` — Verifies default uninitialized state when manual start is requested.
2. `FilesHealthEvaluatorTest.DualDependencyTruthTable` — Verifies all 4 permutations of dependency states:
   - `DB=false, S3=false` -> `NOT_SERVING`
   - `DB=false, S3=true` -> `NOT_SERVING`
   - `DB=true, S3=false` -> `NOT_SERVING`
   - `DB=true, S3=true` -> `SERVING`
3. `FilesHealthEvaluatorTest.DynamicTransitionsAndRecovery` — Validates sequential degradation and recovery (both up -> DB drops -> S3 drops -> S3 recovers -> DB recovers).
4. `FilesHealthEvaluatorTest.ExceptionSafety` — Verifies probes throwing standard exceptions (`std::runtime_error`, `std::logic_error`) fail closed safely without crashing.
5. `FilesHealthEvaluatorTest.NonStdExceptionSafety` — Verifies non-standard exceptions thrown by probes are caught and handled safely.
6. `FilesHealthEvaluatorTest.NullProbeSafety` — Verifies null/empty probe callbacks fail closed safely without bad function call exceptions.
7. `FilesHealthEvaluatorTest.GracefulShutdownImmediateReadinessDrop` — Verifies `set_shutting_down(true)` drops compound readiness immediately to `NOT_SERVING` while preserving liveness.
8. `FilesHealthEvaluatorTest.BackgroundPollingThreadAutoDetect` — Validates real asynchronous background thread polling, automatic state transition detection, and thread shutdown idempotency.

CTest output for `FilesHealthEvaluatorTest`:
```
    Start  95: FilesHealthEvaluatorTest.InitialStateManualStart
1/8 Test  #95: FilesHealthEvaluatorTest.InitialStateManualStart ..................   Passed    0.03 sec
    Start  96: FilesHealthEvaluatorTest.DualDependencyTruthTable
2/8 Test  #96: FilesHealthEvaluatorTest.DualDependencyTruthTable .................   Passed    0.03 sec
    Start  97: FilesHealthEvaluatorTest.DynamicTransitionsAndRecovery
3/8 Test  #97: FilesHealthEvaluatorTest.DynamicTransitionsAndRecovery ............   Passed    0.03 sec
    Start  98: FilesHealthEvaluatorTest.ExceptionSafety
4/8 Test  #98: FilesHealthEvaluatorTest.ExceptionSafety ..........................   Passed    0.03 sec
    Start  99: FilesHealthEvaluatorTest.NonStdExceptionSafety
5/8 Test  #99: FilesHealthEvaluatorTest.NonStdExceptionSafety ....................   Passed    0.03 sec
    Start 100: FilesHealthEvaluatorTest.NullProbeSafety
6/8 Test #100: FilesHealthEvaluatorTest.NullProbeSafety ..........................   Passed    0.03 sec
    Start 101: FilesHealthEvaluatorTest.GracefulShutdownImmediateReadinessDrop
7/8 Test #101: FilesHealthEvaluatorTest.GracefulShutdownImmediateReadinessDrop ...   Passed    0.03 sec
    Start 102: FilesHealthEvaluatorTest.BackgroundPollingThreadAutoDetect
8/8 Test #102: FilesHealthEvaluatorTest.BackgroundPollingThreadAutoDetect ........   Passed    0.12 sec

100% tests passed, 0 tests failed out of 8
```

### 3.2 Full Project Regression Suite
All 122 tests across the SecureCloud repository executed cleanly on MSVC / Windows:
```
100% tests passed, 0 tests failed out of 122
Total Test time (real) = 8.43 sec
```

---

## 4. Next Steps
With `FILES-001-T05` complete, we proceed to the final ticket for Card `FILES-001`:
- **`FILES-001-T06`**: Comprehensive Unit & Integration Test Suite (`tests/integration/files_integration_test.cpp`).
