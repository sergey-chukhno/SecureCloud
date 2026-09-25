# Walkthrough — `FILES-001-T02`: PostgreSQL Connection Pool & Bounded Database Client Foundation

**Ticket ID**: `FILES-001-T02`  
**Status**: ✅ **COMPLETED & VALIDATED**

---

## 1. Summary of Changes

### PostgreSQL Connection Pool & RAII Lease Foundation (`src/files/db/`)
- [`src/files/db/pooled_connection.hpp`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/db/pooled_connection.hpp):
  - Declares the abstract `IDbConnection` handle interface.
  - Implements the move-only `PooledConnection` RAII lease wrapper (`copy = delete`).
  - Automatically recycles or closes connections upon destruction.
- [`src/files/db/files_connection_pool.hpp`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/db/files_connection_pool.hpp) & [`files_connection_pool.cpp`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/db/files_connection_pool.cpp):
  - Implements `ConnectionPoolConfig` with defaults: `min_connections = 2`, `max_connections = 10`, `acquire_timeout = 500ms`, `connect_timeout = 1000ms`, `statement_timeout = 250ms`, `port = 5433`.
  - **Port 5432 Hard Security Guard**: Enforces that connections targeting loopback addresses (`localhost`, `127.0.0.1`, `::1`, `host.docker.internal`) on port `5432` fail immediately with `PortForbiddenException`, protecting workstation host PostgreSQL 14.
  - **3-State Lifecycle**: `OPEN` → `DRAINING` → `CLOSED`.
  - **Bounded Waiters with Timeout**: `acquire()` blocks up to `acquire_timeout` and throws `PoolTimeoutException` if capacity is exhausted.
  - **Dedicated Health Connection**: `ping()` executes on a separate, dedicated connection protected by `health_mutex_`, remaining fully responsive even under 100% worker pool lease exhaustion.
  - Implements `DefaultDbConnection` leveraging `securecloud::common::health::probe_tcp_connectivity`.
  - Supports pluggable `ConnectionFactory` for test injection.

### Build Registration
- [`src/files/CMakeLists.txt`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/CMakeLists.txt):
  - Created `securecloud_files_db` static library target (aliased to `securecloud::files_db`).
  - Linked `securecloud::files_db` into `securecloud-files`.
- [`tests/unit/CMakeLists.txt`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/CMakeLists.txt):
  - Created and registered `securecloud_files_connection_pool_test` with GoogleTest automatic test discovery.

---

## 2. Test Verification Results

### Unit Test Suite Execution (`FilesDbConnectionPoolTest`)
Executed `ctest --preset ci-windows-msvc -R FilesDbConnectionPool --output-on-failure`:
```text
Test project C:/Users/gamer/Documents/Bachelor IT/B3/Projets/Secure Cloud  projet/SecureCloud/build/ci-windows-msvc
      Start 64: FilesDbConnectionPoolTest.ConfigValidationEnforcesPort5432SecurityInvariant
 1/10 Test #64: FilesDbConnectionPoolTest.ConfigValidationEnforcesPort5432SecurityInvariant ...   Passed    0.02 sec
      Start 65: FilesDbConnectionPoolTest.ConfigPopulatesFromFilesConfig
 2/10 Test #65: FilesDbConnectionPoolTest.ConfigPopulatesFromFilesConfig ......................   Passed    0.02 sec
      Start 66: FilesDbConnectionPoolTest.PoolInitializationPrewarmsMinConnections
 3/10 Test #66: FilesDbConnectionPoolTest.PoolInitializationPrewarmsMinConnections ............   Passed    0.02 sec
      Start 67: FilesDbConnectionPoolTest.RAIIPooledConnectionLeasingAndReturn
 4/10 Test #67: FilesDbConnectionPoolTest.RAIIPooledConnectionLeasingAndReturn ................   Passed    0.02 sec
      Start 68: FilesDbConnectionPoolTest.DynamicExpansionUpToMaxConnections
 5/10 Test #68: FilesDbConnectionPoolTest.DynamicExpansionUpToMaxConnections ..................   Passed    0.02 sec
      Start 69: FilesDbConnectionPoolTest.AcquisitionTimeoutWhenPoolIsExhausted
 6/10 Test #69: FilesDbConnectionPoolTest.AcquisitionTimeoutWhenPoolIsExhausted ...............   Passed    0.08 sec
      Start 70: FilesDbConnectionPoolTest.ConcurrentContentionAcrossMultipleThreads
 7/10 Test #70: FilesDbConnectionPoolTest.ConcurrentContentionAcrossMultipleThreads ...........   Passed    0.54 sec
      Start 71: FilesDbConnectionPoolTest.DedicatedHealthPingImmuneToWorkerPoolExhaustion
 8/10 Test #71: FilesDbConnectionPoolTest.DedicatedHealthPingImmuneToWorkerPoolExhaustion .....   Passed    0.02 sec
      Start 72: FilesDbConnectionPoolTest.LifecycleDrainAndCloseOperations
 9/10 Test #72: FilesDbConnectionPoolTest.LifecycleDrainAndCloseOperations ....................   Passed    0.02 sec
      Start 73: FilesDbConnectionPoolTest.DiscardUnhealthyConnectionUponReturn
10/10 Test #73: FilesDbConnectionPoolTest.DiscardUnhealthyConnectionUponReturn ................   Passed    0.02 sec

100% tests passed, 0 tests failed out of 10
Total Test time (real) = 0.81 sec
```

### Full Proto Smoke Test Regression
Executed `ctest --preset ci-windows-msvc -R ProtoSmokeTest --output-on-failure`:
```text
100% tests passed, 0 tests failed out of 4
```

### Executable Build Linkage
`securecloud-files.exe` built and linked successfully with `securecloud::files_db`.

---

## 3. Recommended Git Commit Message for `FILES-001-T02`

```text
feat(files): implement PostgreSQL connection pool foundation (FILES-001-T02)

- Implement thread-safe bounded FilesDbConnectionPool in src/files/db/
- Implement move-only RAII PooledConnection lease with automatic recycling
- Enforce Port 5432 invariant rejecting connections to host PostgreSQL 14
- Implement dedicated health connection for non-blocking ping() probes
- Implement 3-state lifecycle (OPEN -> DRAINING -> CLOSED)
- Register securecloud_files_db static library target in CMake
- Add comprehensive 10-case unit test suite in tests/unit/files/

Refs: FILES-001, FILES-001-T02
```
