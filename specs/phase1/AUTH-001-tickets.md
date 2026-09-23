# AUTH-001 — Establish Auth Service Foundation
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-001  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Final Baseline  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-001** establishes the foundational architecture, IPC contracts, database client infrastructure, lifecycle management, and testing harness for the **SecureCloud Authentication Service** (`securecloud-auth`).

### Key Invariants & Architectural Boundaries
1. **Zero Business Logic in AUTH-001**:
   AUTH-001 establishes the modular skeleton, transport security, and database connectivity. It does **not** implement password hashing (Argon2id), credential verification, session token issuance, refresh token rotation, MFA challenges, or device crypto directory logic. All 12 authoritative proto RPCs must return deterministic `grpc::StatusCode::UNIMPLEMENTED`.
2. **M1 Non-Regression Invariant**:
   AUTH-001 must strictly preserve all completed Milestone 1 capabilities, CMake build presets, protobuf pipelines, mTLS transport patterns, Docker Compose topologies, and `verify-local.py` orchestration.
3. **Observational Host PostgreSQL 14 Guard**:
   The developer workstation host runs an active PostgreSQL 14 instance on `localhost:5432`. SecureCloud workflows MUST NEVER attempt to connect to, stop, restart, reconfigure, or bind to host port `5432`. SecureCloud PostgreSQL 17 binds strictly to `127.0.0.1:5433` (container port `5432`).
4. **Concrete Readiness Probe Resource Model**:
   Readiness evaluation uses a **dedicated persistent health connection** separate from the application pool queue, guaranteeing that application traffic load or pool queue exhaustion never triggers false-positive database outage alarms.
5. **Technically Precise Readiness Timeouts**:
   Query execution on the established health connection is bounded to 250ms via session `statement_timeout`. Driver-level connection establishment uses `connect_timeout=1` (libpq minimum integer seconds).

---

## 2. Dependency Graph

```text
               SC-005 (Protobuf Pipeline)
                         │
                         ▼
                    AUTH-001-T01
            (Protobuf & gRPC Contract Baseline)
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
    AUTH-001-T02                    AUTH-001-T04  <─── SC-010 (mTLS Transport)
 (libpqxx Dependency)             (gRPC Server Impl)   SC-012 (Common Config)
         │                               │
         ▼                               │
    AUTH-001-T03                         │
 (Connection Pool & Ping)                │
         │                               │
         └───────────────┬───────────────┘
                         │
                         ▼
                    AUTH-001-T05  <─── SC-013 (Health & Readiness)
             (Readiness Evaluator &
              Graceful Shutdown)
                         │
                         ▼
                    AUTH-001-T06  <─── SC-014 (Integration Test Harness)
             (Unit & Integration Tests           SC-015 (Distributed Verification)
               & Verification Evidence)
```

---

## 3. Implementation Tickets

### AUTH-001-T01 — Protobuf & gRPC Contract Baseline

1. **Ticket ID**: `AUTH-001-T01`
2. **Title**: Protobuf & gRPC Contract Baseline for Authentication Service
3. **Objective**: Define the canonical Protobuf schema and gRPC service definitions (`proto/securecloud/auth/v1/auth.proto`), register in CMake, and verify clean code generation across all supported compilers.
4. **Architectural Purpose**: Establishes the strongly typed IPC contract between Gateway and Auth Service as mandated by ADR-004 (gRPC IPC) and `docs/design/auth-design.md` Section 4.18.
5. **Scope**:
   - Create `proto/securecloud/auth/v1/auth.proto`.
   - Register in `proto/CMakeLists.txt`.
   - Define 12 authoritative RPC methods:
     - Authentication & Session: `Authenticate`, `RefreshSession`, `ValidateSession`, `RevokeSession`
     - User & Device: `GetUser`, `GetDevice`, `ListUserDevices`, `RegisterDevice`, `RevokeDevice`
     - Cryptographic Directory: `GetDeviceCryptoDirectory`, `GetCryptoIdentity`, `UpdateCryptoPrekeys`
   - Define status enums with explicit `_UNSPECIFIED = 0` default values: `DeviceStatus`, `AuthenticationLevel`, `KeyType`.
   - Define request and response message schemas using `string` fields for canonical UUID identifiers.
   - Extend `tests/unit/proto_smoke_test.cpp` to verify compilation and linkage of generated headers.
6. **Explicit Out-of-Scope**: Implementing RPC logic, credential verification, or business validation.
7. **Dependencies**: Upstream SC-005. Downstream AUTH-001-T02, AUTH-001-T04.
8. **Exact Repository Starting Point**: `proto/CMakeLists.txt`, `proto/securecloud/common/v1/health.proto`, `cmake/modules/SecureCloudProtobuf.cmake`.
9. **Files/Directories to Inspect**: `docs/design/auth-design.md` (4.4, 4.8-4.13, 4.18), `docs/data-model/02-auth-data-model.md` (2.3, 2.5, 2.7), `proto/CMakeLists.txt`.
10. **Files/Directories to Create**: `proto/securecloud/auth/v1/auth.proto`.
11. **Files/Directories That May Be Modified**: `proto/CMakeLists.txt`, `tests/unit/proto_smoke_test.cpp`.
12. **Files/Directories That MUST NOT Be Modified**: `proto/securecloud/common/v1/health.proto`, `cmake/modules/SecureCloudProtobuf.cmake`, `src/*`.
13. **Detailed Implementation Requirements**:
    - Package: `securecloud.auth.v1`, `syntax = "proto3"`, `cc_generic_services = false`.
    - Identifier fields representing `user_id`, `device_id`, `session_id`, `key_id` are wire-format `string` fields representing canonical 36-character hyphenated UUIDv4 strings.
    - Prekey cryptographic material fields use `bytes` to avoid text encoding corruption.
    - Full service declaration:
      ```protobuf
      service AuthService {
        rpc Authenticate(AuthenticateRequest) returns (AuthenticateResponse);
        rpc RefreshSession(RefreshSessionRequest) returns (RefreshSessionResponse);
        rpc ValidateSession(ValidateSessionRequest) returns (ValidateSessionResponse);
        rpc RevokeSession(RevokeSessionRequest) returns (RevokeSessionResponse);
        rpc GetUser(GetUserRequest) returns (GetUserResponse);
        rpc GetDevice(GetDeviceRequest) returns (GetDeviceResponse);
        rpc ListUserDevices(ListUserDevicesRequest) returns (ListUserDevicesResponse);
        rpc RegisterDevice(RegisterDeviceRequest) returns (RegisterDeviceResponse);
        rpc RevokeDevice(RevokeDeviceRequest) returns (RevokeDeviceResponse);
        rpc GetDeviceCryptoDirectory(GetDeviceCryptoDirectoryRequest) returns (GetDeviceCryptoDirectoryResponse);
        rpc GetCryptoIdentity(GetCryptoIdentityRequest) returns (GetCryptoIdentityResponse);
        rpc UpdateCryptoPrekeys(UpdateCryptoPrekeysRequest) returns (UpdateCryptoPrekeysResponse);
      }
      ```
14. **Concurrency/Lifecycle Requirements**: Protobuf message instances are thread-confined (allocated per RPC call by gRPC runtime); no concurrent cross-thread mutations.
15. **Security Requirements**: Plaintext passwords never exposed in responses. No internal database row IDs or password verifiers in schemas.
16. **Database Isolation Requirements**: Zero SQL/database schema definitions in proto.
17. **API/Contract Requirements**: Backward and forward compatible; strict field numbering without renumbering.
18. **Error-Handling Requirements**: Use standard gRPC status codes (`INVALID_ARGUMENT`, `NOT_FOUND`, `UNAUTHENTICATED`, `PERMISSION_DENIED`, `UNIMPLEMENTED`).
19. **Testing Requirements**: `tests/unit/proto_smoke_test.cpp` instantiates generated request types and service stubs.
20. **Validation Commands**:
    - Windows (MSYS2 / MinGW64 toolchains only) :
    ```shell
    $env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
    ```
    - Build & Test Execution (All platforms & toolchains):
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_proto_smoke_test
    ctest --preset dev-debug -R proto_smoke_test --output-on-failure
    ```
21. **Expected Validation Evidence**: Generated headers (`auth.pb.h`, `auth.grpc.pb.h`) compile without warnings; `verify-contracts` target passes.
22. **Acceptance Criteria**: All 12 RPCs defined and registered; clean compilation with zero warnings.
23. **M1 Regression Requirements**: `securecloud/common/v1/health.proto` remains untouched; `verify-local.py` passes.
24. **Risks/Blockers**: None.

---

### AUTH-001-T02 — PostgreSQL C++ Client Driver (`libpqxx`) Dependency Integration

1. **Ticket ID**: `AUTH-001-T02`
2. **Title**: PostgreSQL C++ Client Driver (`libpqxx`) Dependency Integration
3. **Objective**: Integrate `libpqxx` via existing `vcpkg.json` and `cmake/modules/SecureCloudDependencies.cmake`, exporting `securecloud::libpqxx`.
4. **Architectural Purpose**: Provides foundational C++ PostgreSQL driver for Auth persistence (ADR-005, ADR-006).
5. **Scope**:
   - Add `"libpqxx"` to `vcpkg.json`.
   - Update `cmake/modules/SecureCloudDependencies.cmake` with `find_package(libpqxx CONFIG QUIET)` and fallback.
   - Create interface target `securecloud::libpqxx`.
   - Create unit smoke test `tests/unit/pqxx_smoke_test.cpp`.
6. **Explicit Out-of-Scope**: Implementing connection pool, opening network sockets during build/test.
7. **Dependencies**: Upstream SC-002, SC-003. Downstream AUTH-001-T03.
8. **Exact Repository Starting Point**: `vcpkg.json`, `cmake/modules/SecureCloudDependencies.cmake`, `tests/unit/CMakeLists.txt`.
9. **Files/Directories to Inspect**: `vcpkg.json`, `cmake/modules/SecureCloudDependencies.cmake`, `CMakePresets.json`.
10. **Files/Directories to Create**: `tests/unit/pqxx_smoke_test.cpp`.
11. **Files/Directories That May Be Modified**: `vcpkg.json`, `cmake/modules/SecureCloudDependencies.cmake`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `cmake/modules/SecureCloudProtobuf.cmake`, `deploy/compose/*`, `src/*`.
13. **Detailed Implementation Requirements**: Define `securecloud::libpqxx` as an `INTERFACE` target linking `libpqxx::pqxx` or `pqxx`. Smoke test verifies type visibility (e.g. `pqxx::connection_string`) without socket operations.
14. **Concurrency/Lifecycle Requirements**: Build-system level only.
15. **Security Requirements**: Avoid global header pollution; link `INTERFACE` or `PRIVATE`.
16. **Database Isolation Requirements**: Zero database connection attempted during build or unit tests.
17. **API/Contract Requirements**: Export target name `securecloud::libpqxx`.
18. **Error-Handling Requirements**: Clear fatal diagnostic if `libpqxx` is missing with platform remediation steps.
19. **Testing Requirements**: `securecloud_pqxx_smoke_test` compiles and passes in CTest.
20. **Validation Commands**:
    - Windows (MSYS2 / MinGW64 toolchains only) :
    ```shell
    $env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
    ```
    - Build & Test Execution (All platforms & toolchains):
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_pqxx_smoke_test
    ctest --preset dev-debug -R pqxx_smoke_test --output-on-failure
    ```
21. **Expected Validation Evidence**: Clean build and pass of smoke test across macOS, Linux, MinGW, MSVC.
22. **Acceptance Criteria**: `securecloud::libpqxx` consumable across all supported toolchains.
23. **M1 Regression Requirements**: All existing unit and integration tests continue to pass; no regression in dependency discovery.
24. **Risks/Blockers**: Windows MinGW package installation (`mingw-w64-x86_64-libpqxx`).

---

### AUTH-001-T03 — Thread-Safe Bounded PostgreSQL Connection Pool & Health Ping

1. **Ticket ID**: `AUTH-001-T03`
2. **Title**: Thread-Safe Bounded PostgreSQL Connection Pool & Health Ping
3. **Objective**: Implement bounded `PostgresConnectionPool` and RAII `PooledConnection` in `src/auth/db/`, with explicit 3-state lifecycle (`OPEN`, `DRAINING`, `CLOSED`), acquisition timeouts, and an independent dedicated health ping connection.
4. **Architectural Purpose**: Safe, bounded, concurrent access to `securecloud_auth` (ADR-005, ADR-009, ADR-010).
5. **Scope**:
   - Create `src/auth/db/postgres_connection_pool.{hpp,cpp}` and `src/auth/db/pooled_connection.hpp`.
   - Implement `ConnectionPoolConfig` (`min_connections`, `max_connections`, `acquire_timeout`, `connect_timeout`, `statement_timeout`).
   - Implement 3-state lifecycle (`OPEN` -> `DRAINING` -> `CLOSED`).
   - Implement RAII move-only lease (`PooledConnection`).
   - Implement bounded queue acquire via condition variable.
   - Implement **dedicated persistent health connection** for `ping()` that is immune to application queue exhaustion.
   - Create unit tests in `tests/unit/auth/connection_pool_test.cpp`.
6. **Explicit Out-of-Scope**: User/device schema migrations, business queries, touching host port 5432.
7. **Dependencies**: Upstream AUTH-001-T02, SC-012. Downstream AUTH-001-T05.
8. **Exact Repository Starting Point**: `src/auth/auth_config.hpp`, `src/auth/CMakeLists.txt`.
9. **Files/Directories to Inspect**: `src/auth/auth_config.hpp`, `src/common/include/securecloud/health/health_status_manager.hpp`.
10. **Files/Directories to Create**: `src/auth/db/postgres_connection_pool.{hpp,cpp}`, `src/auth/db/pooled_connection.hpp`, `tests/unit/auth/connection_pool_test.cpp`.
11. **Files/Directories That May Be Modified**: `src/auth/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `deploy/compose/*`.
13. **Detailed Implementation Requirements**:
    - **Lifecycle**: `OPEN` (normal leasing) -> `DRAINING` (rejects new acquires, allows active returns) -> `CLOSED` (all connections disconnected).
    - **Ownership**: `PooledConnection` holds `std::unique_ptr<pqxx::connection>` and safe back-reference to pool. Destruction returns connection to pool queue without dangling pointers.
    - **Timeout Disambiguation**:
      - Queue acquire timeout: Enforced via `cv.wait_for(lock, acquire_timeout)`.
      - Connection establishment timeout: Set in PostgreSQL connection parameters (`connect_timeout=1`, minimum integer seconds in libpq).
      - Statement timeout: Enforced via session options (`-c statement_timeout=250ms`).
    - **Dedicated Health Probe Resource Model**:
      - Pool allocates a dedicated `pqxx::connection` strictly reserved for health checks.
      - `ping(timeout)` executes `SELECT 1` on this dedicated connection.
      - Application pool saturation (all 10 connections leased) has ZERO impact on readiness evaluation.
    - **Credential Lifetime**:
      - `AuthConfig::db_password` (`SecretString`) is passed during initialization.
      - Connection strings are formatted in localized stack scopes and passed directly to `pqxx::connection`. The pool avoids retaining redundant long-lived heap copies of plaintext passwords.
14. **Concurrency/Lifecycle Requirements**: Thread-safe under concurrent multi-threaded acquire/release; bounded `shutdown(drain_timeout)`.
15. **Security Requirements**: Password handled via `SecretString`; never logged to stdout/stderr.
16. **Database Isolation Requirements**: Connects strictly to `AuthConfig` host/port (`127.0.0.1:5433` in dev). Invariant: never connect to `localhost:5432`.
17. **API/Contract Requirements**: Namespace `securecloud::auth::db`. Methods: `acquire()`, `try_acquire(timeout)`, `shutdown(drain_timeout)`, `ping(timeout) noexcept`.
18. **Error-Handling Requirements**: Custom exceptions (`ConnectionAcquisitionTimeoutException`, `PoolShuttingDownException`). `ping()` never throws unhandled exceptions.
19. **Testing Requirements**: `tests/unit/auth/connection_pool_test.cpp` validates queue bounding, timeout expiry, thread contention, RAII release, and state transitions.
20. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_connection_pool_test
    ctest --preset dev-debug -R connection_pool_test --output-on-failure
    ```
21. **Expected Validation Evidence**: Unit tests pass cleanly without deadlocks or memory leaks.
22. **Acceptance Criteria**: Bounded pool with acquisition timeout, safe RAII lease ownership, non-blocking ping, full unit test pass.
23. **M1 Regression Requirements**: Zero changes to existing common components; host port 5432 untouched.
24. **Risks/Blockers**: Move semantics must ensure leases are returned exactly once.

---

### AUTH-001-T04 — Modular Auth Service Architecture & gRPC Server Implementation

1. **Ticket ID**: `AUTH-001-T04`
2. **Title**: Modular Auth Service Architecture & gRPC Server Implementation
3. **Objective**: Implement `AuthServiceImpl` registering all 12 proto RPCs returning deterministic `UNIMPLEMENTED`, integrate modular architecture, structured secret-safe logging, and bind to mTLS server.
4. **Architectural Purpose**: Establishes core service skeleton and transport security (ADR-001, ADR-004, `auth-design.md` 4.19).
5. **Scope**:
   - Create `src/auth/service/auth_service_impl.{hpp,cpp}`.
   - Implement `securecloud::auth::v1::AuthService::Service` interface.
   - Wire all 12 RPCs with deterministic `UNIMPLEMENTED` status.
   - Structure forward declarations for sub-components (AuthenticationController, SessionManager, DeviceManager, CryptoDirectoryManager).
   - Implement structured secret-safe operational logging using `std::cout` / `std::cerr` (`[SecureCloud] [auth] <event>`).
   - Extract peer client certificate SAN using `securecloud::common::security::extract_peer_service_identity(*context->auth_context())`.
   - Register service on mTLS server in `main.cpp`.
6. **Explicit Out-of-Scope**: Argon2id password verification, session DB writes, token signing, MFA logic.
7. **Dependencies**: Upstream AUTH-001-T01, SC-010, SC-012. Downstream AUTH-001-T05.
8. **Exact Repository Starting Point**: `src/auth/main.cpp`, `src/auth/CMakeLists.txt`.
9. **Files/Directories to Inspect**: `docs/design/auth-design.md` (4.18, 4.19), `src/auth/main.cpp`, `src/common/src/security/mtls_config.cpp`.
10. **Files/Directories to Create**: `src/auth/service/auth_service_impl.{hpp,cpp}`.
11. **Files/Directories That May Be Modified**: `src/auth/CMakeLists.txt`, `src/auth/main.cpp`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/include/securecloud/security/*`, `src/common/include/securecloud/health/*`.
13. **Detailed Implementation Requirements**:
    - Implement all 12 virtual methods.
    - Peer certificate SAN extraction: Call `extract_peer_service_identity(*context->auth_context())` (which inspects `x509_subject_alternative_name` with `DNS:` prefix).
    - `context->peer()` is treated strictly as an IP:port transport address string, never as a client identity.
    - Operational logging: Log RPC name, duration, peer SAN, and status code. Strict prohibition against logging passwords, tokens, or prekey bytes.
    - Server credentials require valid client certificates (`GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`).
14. **Concurrency/Lifecycle Requirements**: Thread-safe across concurrent gRPC worker threads.
15. **Security Requirements**: Plaintext or invalid client certificates rejected at TLS handshake before reaching RPC handlers.
16. **Database Isolation Requirements**: Service interacts with DB only through pool abstraction once wired.
17. **API/Contract Requirements**: Implements `securecloud.auth.v1.AuthService`.
18. **Error-Handling Requirements**: Returns `grpc::Status(grpc::StatusCode::UNIMPLEMENTED, ...)`.
19. **Testing Requirements**: Verified via integration test client in T06.
20. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud-auth
    python3 scripts/verify-local.py
    ```
21. **Expected Validation Evidence**: `securecloud-auth` compiles and links cleanly.
22. **Acceptance Criteria**: All 12 RPCs registered, mTLS enforced, zero secrets logged.
23. **M1 Regression Requirements**: `HealthServiceImpl` continues to serve alongside `AuthServiceImpl`.
24. **Risks/Blockers**: None.

---

### AUTH-001-T05 — Signal-Safe Notification, Bounded Readiness Evaluation & Graceful Shutdown

1. **Ticket ID**: `AUTH-001-T05`
2. **Title**: Signal-Safe Notification, Bounded Readiness Evaluation & Graceful Shutdown
3. **Objective**: Implement signal-safe termination notification, attach dedicated database pool health evaluation to `HealthStatusManager`, and implement a deterministic bounded graceful shutdown sequence in `src/auth/main.cpp`.
4. **Architectural Purpose**: Bounded failure resilience and lifecycle compliance (ADR-009, SC-013).
5. **Scope**:
   - Ensure POSIX signal handler performs strictly signal-safe operations (atomic flag store).
   - Bind `pool->ping(250ms)` on dedicated health connection to `HealthStatusManager` readiness evaluator.
    - Implement ordered bounded shutdown in main thread:
      1. `set_shutting_down(true)` -> `NOT_SERVING`.
      2. Bounded `server->Shutdown(deadline)` with 5s timeout (synchronously drains active RPCs up to deadline).
      3. Reset/destroy `server` instance (avoid redundant deadlock-prone `server->Wait()` call after bounded `Shutdown(deadline)`).
      4. Bounded pool drain (2s).
      5. Process termination with exit code 0.
6. **Explicit Out-of-Scope**: Implementing background watcher threads, touching host PG14.
7. **Dependencies**: Upstream AUTH-001-T03, AUTH-001-T04. Downstream AUTH-001-T06.
8. **Exact Repository Starting Point**: `src/auth/main.cpp`, `src/common/include/securecloud/health/health_status_manager.hpp`.
9. **Files/Directories to Inspect**: `src/auth/main.cpp`, `src/common/src/health/health_status_manager.cpp`, ADR-009.
10. **Files/Directories to Create**: None (refactors `main.cpp`).
11. **Files/Directories That May Be Modified**: `src/auth/main.cpp`, `src/auth/auth_config.hpp`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/include/securecloud/health/*`.
13. **Detailed Implementation Requirements**:
    - `signal_handler`: Strictly `g_shutdown_requested.store(true, std::memory_order_relaxed)`. No mutexes, allocations, gRPC calls, or logging.
    - Readiness Evaluator: Calls `pool->ping(250ms)`. Catches all exceptions internally and returns `false` (fail-closed). Liveness remains `is_live = true`.
    - Graceful Shutdown: Explicit sequence using `server->Shutdown(deadline)` followed by `pool->shutdown()`. Standard RAII cleanup; no unachievable "clean memory wipe on termination" claims.
14. **Concurrency/Lifecycle Requirements**: Coordinated termination across main thread, gRPC worker threads, and health evaluation.
15. **Security Requirements**: In-flight requests drain cleanly within deadline without leaking resources.
16. **Database Isolation Requirements**: Drains connections to `securecloud_auth` only.
17. **API/Contract Requirements**: Standard gRPC health protocol (`grpc.health.v1.Health`).
18. **Error-Handling Requirements**: Forced cancellation if shutdown deadline expires; no hangs.
19. **Testing Requirements**: Verified in unit/integration tests.
20. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud-auth
    python3 scripts/verify-local.py
    ```
21. **Expected Validation Evidence**: Service degrades readiness when database is down; terminates cleanly on `SIGTERM` within bounded time.
22. **Acceptance Criteria**: Signal-safe handler, bounded ping in evaluator, deterministic graceful shutdown.
23. **M1 Regression Requirements**: Preserves all SC-013 health probe semantics.
24. **Risks/Blockers**: Use `std::chrono::system_clock` for gRPC shutdown deadline.

---

### AUTH-001-T06 — Unit & Integration Test Suite, mTLS Matrix & Database Failure Verification

1. **Ticket ID**: `AUTH-001-T06`
2. **Title**: Unit & Integration Test Suite, mTLS Matrix & Database Failure Verification
3. **Objective**: Implement comprehensive test suites validating the complete AUTH-001 foundation: proto dispatch, 4-case mTLS security matrix, database readiness degradation/recovery, and graceful shutdown.
4. **Architectural Purpose**: Regression-proof empirical validation of security, operational, and architectural invariants (ADR-008, ADR-009).
5. **Scope**:
   - Unit Tests (`tests/unit/auth/`):
     - `auth_service_test.cpp`: All 12 RPCs return `UNIMPLEMENTED`.
     - `connection_pool_test.cpp`: Queue bounding, acquire timeouts, state transitions.
   - Integration Tests (`tests/integration/auth_integration_test.cpp`):
     - In-process server on dynamic port `127.0.0.1:0`.
     - **4-Case mTLS Matrix**:
       1. Case 1: Valid client cert -> RPC succeeds (`UNIMPLEMENTED`).
       2. Case 2: TLS without client cert -> Handshake rejected fail-closed.
       3. Case 3: Untrusted client cert -> Handshake rejected fail-closed.
       4. Case 4: Plaintext connection -> Rejected fail-closed.
     - **Database Failure Isolation**:
       - Verify readiness is `SERVING` when DB reachable.
       - Inject connection failure (unreachable loopback `127.0.0.1:5439`).
       - Verify readiness degrades to `NOT_SERVING` while liveness remains `SERVING`.
       - Restore configuration -> verify readiness recovers to `SERVING`.
       - **CRITICAL INVARIANT**: Never touch `localhost:5432`.
     - **Shutdown Test**: Bounded drain under simulated client load.
6. **Explicit Out-of-Scope**: Business authentication tests (AUTH-002), modifying Compose containers.
7. **Dependencies**: Upstream AUTH-001-T01 through T05, SC-010, SC-014.
8. **Exact Repository Starting Point**: `tests/integration/mtls_integration_test.cpp`, `tests/integration/health_integration_test.cpp`.
9. **Files/Directories to Inspect**: `tests/integration/mtls_integration_test.cpp`, `scripts/verify-local.py`.
10. **Files/Directories to Create**: `tests/unit/auth/auth_service_test.cpp`, `tests/integration/auth_integration_test.cpp`.
11. **Files/Directories That May Be Modified**: `tests/unit/CMakeLists.txt`, `tests/integration/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `deploy/compose/*`, developer host port 5432.
13. **Detailed Implementation Requirements**:
    - Dynamic port allocation: In-process servers bind to `127.0.0.1:0` to guarantee zero port collisions.
    - Certificate loading: Resolve Dev PKI certificates via `find_pki_root()` helper.
    - Clean teardown: Explicitly shutdown servers and reset stubs/channels in `TearDown()`.
14. **Concurrency/Lifecycle Requirements**: Thread-safe, repeatable execution in CI and local machines.
15. **Security Requirements**: Every negative case explicitly asserts `status.ok() == false`.
16. **Database Isolation Requirements**: Failure simulation via mock/invalid target address; never call `docker stop` on host PG.
17. **API/Contract Requirements**: Validates 12 Auth RPCs and Health API.
18. **Error-Handling Requirements**: Clear assertion diagnostics on failure.
19. **Testing Requirements**: Registered via `gtest_discover_tests`.
20. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_auth_integration_test
    ctest --preset dev-debug -R "auth_" --output-on-failure
    python3 scripts/verify-local.py
    ```
21. **Expected Validation Evidence**: 100% test pass; full `verify-local.py` run passes.
22. **Acceptance Criteria**: All 12 RPC tests pass, 4 mTLS cases pass, DB readiness degradation/recovery verified without touching port 5432.
23. **M1 Regression Requirements**: All existing M1 tests continue to pass; new test targets execute cleanly without regression.
24. **Risks/Blockers**: Destroy client channels before shutting down test servers.

---

## 4. Developer Branching & Commit Strategy

### 1. Branching Model
The developer must implement AUTH-001 on a single dedicated feature branch cut from `main`:
```bash
git checkout main
git pull origin main
git checkout -b feature/auth-001-establish-auth-service-foundation
```
Do NOT open six separate PRs. AUTH-001 will be reviewed, audited, and merged as a coherent architectural unit.

### 2. Commit Strategy
The developer should make incremental commits for each ticket using Conventional Commits:
- `feat(auth): define protobuf & gRPC contract baseline (AUTH-001-T01)`
- `build(deps): integrate libpqxx via vcpkg and cmake (AUTH-001-T02)`
- `feat(auth): implement bounded postgres connection pool (AUTH-001-T03)`
- `feat(auth): establish modular auth service and gRPC server (AUTH-001-T04)`
- `feat(auth): wire bounded readiness evaluator and graceful shutdown (AUTH-001-T05)`
- `test(auth): add unit and integration test suite with mTLS matrix (AUTH-001-T06)`

---

## 5. Developer Handoff Checklist

1. [ ] Inspect authoritative docs: `auth-design.md`, `02-auth-data-model.md`, ADR-004, ADR-005, ADR-009.
2. [ ] Create branch `feature/auth-001-establish-auth-service-foundation`.
3. [ ] **T01**: Create `proto/securecloud/auth/v1/auth.proto`, update `proto/CMakeLists.txt`, extend `tests/unit/proto_smoke_test.cpp`, run `verify-contracts`.
4. [ ] **T02**: Add `libpqxx` to `vcpkg.json`, update `cmake/modules/SecureCloudDependencies.cmake`, create `tests/unit/pqxx_smoke_test.cpp`.
5. [ ] **T03**: Implement `PostgresConnectionPool` and `PooledConnection` in `src/auth/db/` with dedicated health probe connection, add unit tests in `tests/unit/auth/connection_pool_test.cpp`.
6. [ ] **T04**: Implement `AuthServiceImpl` in `src/auth/service/`, wire all 12 RPCs to return `UNIMPLEMENTED`, extract peer SAN via `extract_peer_service_identity()`, bind to mTLS server in `src/auth/main.cpp`.
7. [ ] **T05**: Restructure signal handling to atomic flag, wire dedicated pool ping to readiness evaluator, implement bounded graceful shutdown in `src/auth/main.cpp`.
8. [ ] **T06**: Implement unit tests in `tests/unit/auth/auth_service_test.cpp` and integration tests in `tests/integration/auth_integration_test.cpp` (4 mTLS cases, simulated DB outage).
9. [ ] Run full local verification: `python3 scripts/verify-local.py`.
10. [ ] Push branch and submit Pull Request for Antigravity review.

---

## 6. Antigravity Review Checklist

Antigravity will audit the PR against the following strict classification rules:

### Severity Classification
- **BLOCKER**: Architectural regression, security boundary violation, compilation/test failure, host port 5432 interference, signal-unsafe handler, unbounded wait/hang, secret logging.
- **HIGH**: Missing mTLS test case, missing lease lifecycle protection during pool shutdown, incorrect timeout semantics, memory leak.
- **MEDIUM**: Code style/formatting violation, redundant include, suboptimal lock granularity.
- **LOW**: Minor documentation typo, non-critical comment enhancement.
- **INFO**: Commendation or suggested future optimization for AUTH-002+.

### Inspection Matrix
| Area | Check Item | Severity if Violated |
| :--- | :--- | :--- |
| **Regression** | All existing M1 tests pass without regression | BLOCKER |
| **Regression** | `localhost:5432` untouched and unreferenced | BLOCKER |
| **Security** | Zero logging of passwords, tokens, credentials, or prekeys | BLOCKER |
| **Security** | Peer identity logged from SAN DNS, not `context->peer()` | HIGH |
| **Security** | mTLS strictly enforced (`REQUEST_AND_REQUIRE_AND_VERIFY`) | BLOCKER |
| **Security** | Plaintext, untrusted cert, and missing cert rejected | BLOCKER |
| **Concurrency** | Signal handler calls only signal-safe operations | BLOCKER |
| **Concurrency** | Bounded gRPC server shutdown (no indefinite wait) | BLOCKER |
| **Concurrency** | Pool destruction cannot invalidate active leases | HIGH |
| **Database** | Pool acquisition timeout enforced via condition variable | HIGH |
| **Database** | Dedicated health connection used for readiness ping | HIGH |
| **Database** | Query timeout bounded on health ping connection | HIGH |
| **Architecture** | Zero business logic (Argon2id, token issue) in AUTH-001 | BLOCKER |
| **Architecture** | All 12 proto RPCs registered and return `UNIMPLEMENTED` | HIGH |
| **Verification** | `python3 scripts/verify-local.py` passes 100% | BLOCKER |

---

## 7. AUTH-001 Definition of Done

AUTH-001 is officially complete only when all of the following criteria are satisfied:

- [ ] Auth protobuf contract is defined, registered, and generated cleanly.
- [ ] `libpqxx` is integrated cleanly via vcpkg and CMake target `securecloud::libpqxx`.
- [ ] PostgreSQL connection pool is resource-bounded with explicit `OPEN`, `DRAINING`, `CLOSED` lifecycle.
- [ ] Pool acquisition timeout is strictly bounded.
- [ ] Active RAII leases remain valid or detach safely during pool shutdown.
- [ ] Database timeouts (acquire, connect, statement) are clearly distinguished.
- [ ] Dedicated health probe connection prevents pool exhaustion from causing false outages.
- [ ] `AuthServiceImpl` registers all 12 authoritative RPCs returning `UNIMPLEMENTED`.
- [ ] No AUTH-002+ business logic (Argon2id, tokens, sessions) has leaked into AUTH-001.
- [ ] Service operates exclusively over mTLS.
- [ ] Peer identity extracted via `extract_peer_service_identity()` from SAN DNS.
- [ ] Readiness accurately reflects PostgreSQL dependency availability.
- [ ] Readiness evaluation is strictly bounded.
- [ ] Liveness remains independent of PostgreSQL availability.
- [ ] Signal handling is strictly signal-safe.
- [ ] Graceful shutdown is deterministic, ordered, and bounded.
- [ ] Unit test suite passes 100%.
- [ ] Integration test suite passes 100% (including all 4 mTLS cases).
- [ ] Database failure degradation/recovery test passes without touching port 5432.
- [ ] All completed M1 features and tests continue to pass without regression.
- [ ] `verify-local.py` passes all stages.
- [ ] Developer submits complete implementation and validation evidence.
- [ ] Antigravity completes architectural, security, concurrency, and test review.
- [ ] All BLOCKER and HIGH review findings are resolved.
- [ ] Antigravity issues explicit written approval for merge.
