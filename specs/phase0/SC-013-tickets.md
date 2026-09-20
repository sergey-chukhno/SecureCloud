# SC-013 — Establish Health and Readiness Endpoints

## Executive Summary & Objectives

Card **SC-013** establishes a reusable, deterministic, fail-closed health and readiness foundation for all five SecureCloud backend microservices (`gateway`, `auth`, `messaging`, `files`, `audit`) under Milestone **M1: Buildable Distributed Skeleton**.

It transitions SecureCloud from the build-proving, static `SERVING` health stub introduced in SC-010 to an operational lifecycle foundation adhering strictly to **ADR-009 Section 23 & 24**, clearly separating **Liveness** (*"Is the process functioning?"*) from **Readiness** (*"Is the service capable of accepting the relevant workload?"*).

> [!IMPORTANT]
> **Hard Invariants & Environmental Isolation**:
> 1. **mTLS Peer Authentication**: All health endpoints require and verify valid mTLS peer certificates (`GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`). Plaintext health listeners or unauthenticated bypasses are strictly prohibited.
> 2. **Zero Information Leakage**: Health responses only convey enum `ServingStatus`. No database passwords, tokens, connection strings, stack traces, or internal server paths are ever returned in health responses or logged.
> 3. **Host PostgreSQL Isolation**: Developer workstation operates independent **PostgreSQL 14** on `localhost:5432`. SecureCloud MUST NEVER stop, restart, reconfigure, or bind to host port `5432`. SecureCloud PostgreSQL 17 binds exclusively to `127.0.0.1:5433:5432`.
> 4. **No Premature Architecture**: No external HTTP health ports, no Consul/etcd, no Prometheus/Jaeger, no background polling threads, and no `--probe` CLI flags in service binaries.

---

## Authoritative Architectural Baseline & Semantics

### 1. Protocol Contract & SecureCloud Semantic Conventions
SecureCloud consumes the single protobuf contract defined in [`proto/securecloud/common/v1/health.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/common/v1/health.proto):
```protobuf
syntax = "proto3";
package securecloud.common.v1;

message HealthCheckRequest {
    string service = 1;
}

message HealthCheckResponse {
    enum ServingStatus {
        UNKNOWN = 0;
        SERVING = 1;
        NOT_SERVING = 2;
        SERVICE_UNKNOWN = 3;
    }
    ServingStatus status = 1;
}

service HealthService {
    rpc Check(HealthCheckRequest) returns (HealthCheckResponse);
}
```

SecureCloud establishes the following **authoritative semantic conventions** over this existing protobuf contract:
- **Liveness Convention**:
  - Queried via `request.service() == ""` OR `request.service() == "<canonical_service_name>"`.
  - Answers: *"Is this service process alive, healthy, and capable of serving its basic runtime contract?"*
  - Returns `SERVING` if the process is active, configuration loaded cleanly, and gRPC listener is running.
- **Readiness Convention**:
  - Queried via `request.service() == "readiness"`.
  - Answers: *"Is this service currently able to accept the class of work represented by the readiness contract?"*
  - Returns `SERVING` only if the process is live, local initialization has succeeded, graceful shutdown has not commenced, and all mandatory service-specific transport dependencies are reachable.
  - Returns `NOT_SERVING` if the process is uninitialized, shutting down, or any mandatory dependency is unreachable.
- **Subsystem Convention / Unknown Services**:
  - Any unrecognized string in `request.service()` returns status `SERVICE_UNKNOWN`.

### 2. Explicit Service Name Ownership
`HealthServiceImpl` must possess an explicit, deterministic mechanism to verify the canonical service identity when matching `request.service() == canonical_service_name`.
- `HealthStatusManager` and `HealthServiceImpl` receive the canonical service name (`std::string service_name`) explicitly via constructor:
  ```cpp
  class HealthStatusManager {
    public:
      explicit HealthStatusManager(std::string service_name);
      [[nodiscard]] const std::string& service_name() const noexcept;
      // ...
  };

  class HealthServiceImpl final : public securecloud::common::v1::HealthService::Service {
    public:
      explicit HealthServiceImpl(std::string service_name, HealthStatusManager& status_manager);
      // ...
  };
  ```
- Ownership is explicit, deterministic, and immutable post-initialization.

### 3. M1 Transport-Level Dependency Readiness Definition & Scope
In Milestone M1, dependency readiness is explicitly defined as:
> **"M1 transport-level dependency readiness"**

- **What it proves**: The target dependency network endpoint (`host:port`) is reachable and accepting TCP connections within the configured deadline.
- **What it does NOT claim**: It does **NOT** verify database credentials, authentication, schema existence, migrations, table access, or application-level read/write semantics.
- **Rationale**: Full database client libraries (`libpqxx`, ScyllaDB C++ driver, S3 AWS SDK, ClickHouse client) are scheduled for Milestone M2 (`AUTH-001`, `MSG-001`, `FILES-001`, `AUDIT-001`). M1 establishes the operational lifecycle foundation and network reachability contract without premature application-layer database dependencies.

### 4. Dependency Probe Blocking & Timeout Semantics
- **Bounded Synchronous Probing**: Readiness evaluation executes a synchronous TCP connect probe bounded by a strict deadline.
- **Strict Maximum Timeout**: Configured to **250 ms** (maximum 500 ms under high-latency environments).
- **Socket Implementation**: Sockets use `O_NONBLOCK` + `poll()`/`select()` for up to 250 ms, immediately closing the socket descriptor upon completion.
- **Scope**: The timeout bounds **only** the incoming health RPC execution.
- **Zero Background Polling**: No background health polling threads, cron tasks, or periodic check loops are introduced. Probes run strictly on demand when a gRPC `Check("readiness")` RPC is received.

### 5. Service Dependency & Readiness Boundaries (Preventing Distributed Cascades)
To adhere to the core distributed system invariant (*"Avoid circular or cascading global availability checks"*):
- **Gateway**: Readiness is strictly **local**. It evaluates Gateway configuration validity, server socket binding, and local routing initialization. Gateway readiness **must NOT** synchronously fan out to Auth, Messaging, Files, or Audit.
- **Auth**: Evaluates local initialization + PostgreSQL transport reachability (`config.db_host:config.db_port`).
- **Messaging**: Evaluates local initialization + ScyllaDB transport reachability (`config.scylla_host:config.scylla_port`).
- **Files**: Evaluates local initialization + PostgreSQL transport reachability (`config.db_host:config.db_port`) AND MinIO transport reachability (`config.s3_endpoint_host:config.s3_endpoint_port`).
- **Audit**: Evaluates local initialization + ClickHouse transport reachability (`config.db_host:config.db_port`).

### 6. Graceful Shutdown Lifecycle
1. Process receives `SIGINT` or `SIGTERM`.
2. Signal handler or main loop triggers `health_status_manager.set_shutting_down(true)`.
3. Readiness status **immediately** transitions to `NOT_SERVING`.
4. Upstream routers / callers cease routing new requests to this instance.
5. In-flight requests drain cleanly during a bounded shutdown interval (`SECURECLOUD_SHUTDOWN_TIMEOUT_MS`).
6. `server->Shutdown()` terminates the listener and the process exits with code 0.

### 7. Docker Compose Integration Decision
- **No `--probe` in Service Binaries**: Service executables remain minimal and focused solely on microservice execution.
- **Compose Service Healthchecks Deferred**: The five C++ services in `docker-compose.yml` will not have fake or premature `healthcheck:` blocks added.
- **Empirical Validation**: End-to-end container health and readiness verification is owned by `scripts/verify-health-endpoints.sh`, which executes real mTLS gRPC health checks using the dev-pki certificates against the containerized endpoints.

---

## Ticket Decomposition

```
SC-013-T01 (Lifecycle Model & Specification in specs/phase0)
    │
    ▼
SC-013-T02 (Minimal Common Health & Readiness Infrastructure)
    │
    ├───────────────────────────┐
    ▼                           ▼
SC-013-T03 (Unit Tests)     SC-013-T04 (5 Microservices Integration)
    │                           │
    └─────────────┬─────────────┘
                  ▼
SC-013-T05 (mTLS Health & Readiness Integration Tests)
                  │
                  ▼
SC-013-T06 (Compose Real Outage Verification Script)
                  │
                  ▼
SC-013-T07 (Documentation & Final M1 Gate)
```

---

### SC-013-T01 — Formulate Health and Readiness Lifecycle Model and Specifications

- **Status**: `[COMPLETED & APPROVED]`
- **Objective**: Author the formal specification in `specs/phase0/SC-013-tickets.md` establishing the SecureCloud semantic conventions over `HealthService`, the distinction between liveness and readiness, M1 transport-level dependency readiness semantics and limitations, bounded probe timeouts, explicit service name ownership, and service readiness boundaries.
- **Exact files/directories**:
  - `[NEW] specs/phase0/SC-013-tickets.md`
- **Dependencies**: SC-010, SC-011, SC-012.
- **Implementation approach**:
  - Detail the exact state machine: initial state, startup completion, degraded dependency state, and graceful shutdown transition.
  - Document the convention: `""` / `<name>` = Liveness, `"readiness"` = Readiness, unrecognized = `SERVICE_UNKNOWN`.
  - Document explicit constructor service name ownership.
  - Document M1 scope: TCP connectivity probe only (explicitly noting credentials/schemas are out of scope for M1).
  - Explicitly document Gateway local readiness rule (zero downstream fan-out).
- **Architecture constraints**: Conforms to ADR-001, ADR-004, ADR-009 Section 23/24.
- **Security considerations**: Document mTLS peer authentication requirement and zero-secret exposure.
- **Tests**: Specification document review; no code changes.
- **Validation commands**:
  - Verify file creation and contents in `specs/phase0/SC-013-tickets.md`.
- **Acceptance criteria**:
  - `specs/phase0/SC-013-tickets.md` committed with complete lifecycle model, timeout semantics, explicit service name ownership, and ticket contracts.

---

### SC-013-T02 — Implement Minimal Reusable Health & Readiness Infrastructure in Common Library

- **Status**: `[COMPLETED & APPROVED]`
- **Objective**: Implement `HealthStatusManager`, `HealthServiceImpl`, and `TransportProbe` in `securecloud::common::health`, replacing the duplicated implementations across services.
- **Exact files/directories**:
  - `[NEW] src/common/include/securecloud/health/health_status_manager.hpp`
  - `[NEW] src/common/include/securecloud/health/health_service_impl.hpp`
  - `[NEW] src/common/include/securecloud/health/transport_probe.hpp`
  - `[NEW] src/common/src/health/health_status_manager.cpp`
  - `[NEW] src/common/src/health/health_service_impl.cpp`
  - `[NEW] src/common/src/health/transport_probe.cpp`
  - `[MODIFY] src/common/CMakeLists.txt`
- **Dependencies**: SC-013-T01.
- **Implementation approach**:
  - `HealthStatusManager`: Minimal class with `std::atomic<bool>` for liveness, readiness, and shutdown state, plus an optional `ReadinessEvaluator` (`std::function<bool()>`). Explicitly stores `service_name_`.
  - `HealthServiceImpl`: Implements `securecloud::common::v1::HealthService::Service::Check`:
    - Rejects unauthenticated callers (`!context->auth_context()->IsPeerAuthenticated()`) with `grpc::StatusCode::UNAUTHENTICATED`.
    - Handles `request->service() == ""` or matching `service_name_` -> returns liveness (`SERVING` / `NOT_SERVING`).
    - Handles `request->service() == "readiness"` -> returns readiness (`SERVING` if live, ready, not shutting down, and evaluator returns true; otherwise `NOT_SERVING`).
    - Any other string -> returns `SERVICE_UNKNOWN`.
  - `TransportProbe`: Bounded synchronous TCP connection probe (`probe_tcp_connectivity(host, port, timeout_ms)`).
    - Sets socket `O_NONBLOCK`, issues `connect()`, waits via `poll()` up to `timeout_ms` (default 250 ms), closes socket.
    - Returns `true` on successful connect, `false` on timeout, connection refused, or socket error.
    - Zero credential usage, zero background threads.
- **Architecture constraints**: C++20, minimal dependencies, thread-safe, no memory allocation in steady-state checks.
- **Security considerations**: Strict mTLS verification; fail-closed on socket errors; no error message leakage in response.
- **Tests**: Unit tests in T03.
- **Validation commands**:
  - `cmake --build build --target securecloud_common`
- **Acceptance criteria**:
  - `securecloud_common` compiles cleanly with C++20 flags.
  - Zero duplicated `HealthServiceImpl` code remains needed in services.

---

### SC-013-T03 — Implement Comprehensive Unit Tests for Health Infrastructure

- **Status**: `[COMPLETED & APPROVED]`
- **Objective**: Create unit tests covering `HealthStatusManager`, `HealthServiceImpl`, and `TransportProbe`.
- **Exact files/directories**:
  - `[NEW] tests/unit/health/health_status_manager_test.cpp`
  - `[NEW] tests/unit/health/transport_probe_test.cpp`
  - `[MODIFY] tests/unit/CMakeLists.txt`
- **Dependencies**: SC-013-T02.
- **Implementation approach**:
  - Test initial state: uninitialized service reports `NOT_SERVING`.
  - Test steady-state liveness: reports `SERVING` when live.
  - Test readiness queries: `"readiness"` returns `SERVING` only when live, ready, and evaluator passes.
  - Test simulated dependency failure: evaluator returning `false` causes `"readiness"` to return `NOT_SERVING`, while `""` remains `SERVING`.
  - Test shutdown transition: setting `is_shutting_down(true)` immediately flips readiness to `NOT_SERVING`.
  - Test unrecognized service name returns `SERVICE_UNKNOWN`.
  - Test unauthenticated RPC context returns `grpc::StatusCode::UNAUTHENTICATED`.
  - Test `TransportProbe`:
    - Connect to active local listening socket -> succeeds within the configured probe deadline.
    - Connect to closed port / non-routable address -> fails cleanly within bounded 250 ms timeout.
- **Architecture constraints**: In-process GoogleTest suite, fast and deterministic.
- **Security considerations**: Verify fail-closed behavior for unauthenticated callers.
- **Validation commands**:
  - `ctest --test-dir build -R "health|transport_probe" --output-on-failure`
- **Acceptance criteria**:
  - 100% of unit test assertions pass.

---

### SC-013-T04 — Integrate Health & Readiness Lifecycle into All Five Microservices

- **Status**: `[COMPLETED & APPROVED]`
- **Objective**: Remove the duplicated `HealthServiceImpl` from all 5 microservices, wire `HealthStatusManager` and common `HealthServiceImpl`, configure M1 transport-level readiness probes, and integrate graceful shutdown.
- **Exact files/directories**:
  - `[MODIFY] src/gateway/main.cpp`
  - `[MODIFY] src/auth/main.cpp`
  - `[MODIFY] src/messaging/main.cpp`
  - `[MODIFY] src/files/main.cpp`
  - `[MODIFY] src/audit/main.cpp`
- **Dependencies**: SC-013-T02.
- **Implementation approach**:
  - In each service:
    - Remove local `class HealthServiceImpl` definition.
    - Instantiate `HealthStatusManager health_manager(config.common.service_name)` and `HealthServiceImpl health_service(config.common.service_name, health_manager)`.
    - Register M1 transport-level dependency readiness probes:
      - `gateway`: Local readiness only (router ready, no downstream calls).
      - `auth`: `probe_tcp_connectivity(config.db_host, config.db_port, 250ms)`.
      - `messaging`: `probe_tcp_connectivity(config.scylla_host, config.scylla_port, 250ms)`.
      - `files`: `probe_tcp_connectivity(config.db_host, config.db_port, 250ms) && probe_tcp_connectivity(config.s3_endpoint_host, config.s3_endpoint_port, 250ms)`.
      - `audit`: `probe_tcp_connectivity(config.db_host, config.db_port, 250ms)`.
    - On gRPC server startup: mark `health_manager.set_live(true)` and `health_manager.set_ready(true)`.
    - In `signal_handler` / shutdown loop: immediately mark `health_manager.set_shutting_down(true)` so any incoming readiness probes receive `NOT_SERVING` during drain.
- **Architecture constraints**: Preserve fail-closed configuration and mTLS credential loading.
- **Security considerations**: Zero passwords or sensitive credentials used or logged in health checks.
- **Validation commands**:
  - `cmake --build build --target securecloud-gateway securecloud-auth securecloud-messaging securecloud-files securecloud-audit`
- **Acceptance criteria**:
  - All five microservice binaries compile cleanly with zero warnings.
  - Zero duplicated `HealthServiceImpl` remains in any service.

---

### SC-013-T05 — Implement Real mTLS Health & Readiness Integration Test Suite

- **Status**: `[COMPLETED & APPROVED]`
- **Objective**: Test real mTLS gRPC health and readiness checks across live sockets, validating liveness, readiness, dependency degradation, and peer authentication against the common `HealthServiceImpl`.
- **Exact files/directories**:
  - `[NEW] tests/integration/health_integration_test.cpp`
  - `[MODIFY] tests/integration/CMakeLists.txt`
  - `[MODIFY] tests/integration/mtls_integration_test.cpp` (refactor to consume common `HealthServiceImpl`)
- **Dependencies**: SC-013-T04.
- **Implementation approach**:
  - `health_integration_test.cpp`:
    - Spin up in-process mTLS gRPC server with Dev PKI credentials and `HealthServiceImpl`.
    - Issue real mTLS client `Check("")` -> verify `SERVING`.
    - Issue real mTLS client `Check("readiness")` with healthy transport probe -> verify `SERVING`.
    - Simulate dependency outage (transport probe target closed) -> verify `Check("readiness")` returns `NOT_SERVING` while `Check("")` returns `SERVING`.
    - Trigger shutdown flag -> verify `Check("readiness")` immediately transitions to `NOT_SERVING`.
    - Issue `Check("unknown_subsystem")` -> verify `SERVICE_UNKNOWN`.
    - Negative tests: plaintext client rejected, untrusted CA rejected, unauthenticated client rejected.
  - `mtls_integration_test.cpp`:
    - Remove the local copy-pasted `HealthServiceImpl` and replace it with `securecloud::common::health::HealthServiceImpl`.
- **Architecture constraints**: CTest integration test suite using real sockets and TLS handshakes over loopback.
- **Security considerations**: Proves peer SAN identity and client certificate enforcement.
- **Validation commands**:
  - `ctest --test-dir build -R "HealthIntegrationTest|MtlsIntegrationTest" --output-on-failure`
- **Acceptance criteria**:
  - Both integration test suites pass 100% cleanly.
  - Zero duplicated `HealthServiceImpl` remains in `mtls_integration_test.cpp`.

---

### SC-013-T06 — Docker Compose Real Outage Verification Suite

- **Status**: `[COMPLETED & APPROVED]`
- **Objective**: Create `scripts/verify-health-endpoints.sh` to perform empirical validation against the real containerized services in Docker Compose, verifying mTLS health, readiness, and real dependency-outage degradation/recovery.
- **Exact files/directories**:
  - `[NEW] scripts/verify-health-endpoints.sh`
- **Dependencies**: SC-013-T05.
- **Implementation approach**:
  - Check 1: Verify host PostgreSQL 14 on `localhost:5432` remains untouched and active.
  - Check 2: Start Docker Compose environment (`docker compose up -d`).
  - Check 3: Using a dedicated mTLS gRPC test runner with dev-pki credentials, probe each service:
    - `gateway`: Liveness `SERVING`, Readiness `SERVING`.
    - `auth`: Liveness `SERVING`, Readiness `SERVING`.
    - `messaging`: Liveness `SERVING`, Readiness `SERVING`.
    - `files`: Liveness `SERVING`, Readiness `SERVING`.
    - `audit`: Liveness `SERVING`, Readiness `SERVING`.
  - Check 4: **Real Docker Dependency Outage Test**:
    - Temporarily stop the `postgres` container (`docker compose stop postgres`).
    - Probe `auth` and `files`:
      - Liveness must remain **`SERVING`** (process is alive and running).
      - Readiness must transition to **`NOT_SERVING`** (mandatory transport dependency down).
    - Probe `messaging` and `audit`:
      - Readiness must remain **`SERVING`** (unaffected by PostgreSQL outage).
  - Check 5: **Real Docker Dependency Recovery Test**:
    - Restart the `postgres` container (`docker compose start postgres`).
    - Wait for PostgreSQL healthcheck.
    - Probe `auth` and `files`: Readiness recovers to **`SERVING`**.
  - Check 6: Clean teardown, confirming zero leftover processes.
- **Architecture constraints**: Respect host PostgreSQL 14 on `localhost:5432`; use isolated port `127.0.0.1:5433:5432` for SecureCloud PostgreSQL.
- **Security considerations**: Probe strictly over mTLS with service client certificates.
- **Validation commands**:
  - `./scripts/verify-health-endpoints.sh`
- **Acceptance criteria**:
  - Script passes with 100% green checks when executed from repo root and `scripts/`.
  - Host PostgreSQL 14 remains unaffected.

---

### SC-013-T07 — Documentation Update and SC-013 Milestone Review

- **Status**: `[COMPLETED & VERIFIED]`
- **Objective**: Update backlog and architecture documentation with the approved health/readiness contract and validation logs.
- **Exact files/directories**:
  - `[MODIFY] docs/planning/initial-backlog.md`
  - `[MODIFY] specs/phase0/SC-013-tickets.md`
- **Dependencies**: SC-013-T01 through SC-013-T06.
- **Implementation approach**:
  - Record the completion of SC-013 in `initial-backlog.md`.
  - Mark all tickets completed in `specs/phase0/SC-013-tickets.md` with verification outputs.
  - Run the full regression verification suite (`check-formatting.sh`, `verify-service-config.sh`, `verify-persistence-infra.sh`, `verify-health-endpoints.sh`, and CTest).
- **Acceptance criteria**:
  - All documentation updated and all verification suites pass.

---

## Final Verification Summary & Empirical Evidence (SC-013)

### 1. Automated Health & Readiness Suite (`./scripts/verify-health-endpoints.sh`)
- Executed from repository root and `scripts/`:
  - **Check 1**: Host PostgreSQL 14 baseline on `localhost:5432` verified active and untouched before Compose startup (`[PASS]`).
  - **Check 2**: Started Docker Compose stack with latest binaries (`[PASS]`).
  - **Check 3**: Probed steady-state mTLS liveness and readiness across all 5 services (`gateway`, `auth`, `messaging`, `files`, `audit`) -> all return `SERVING` (`[PASS]`).
  - **Check 4 (Outage)**: Stopped `postgres` container -> `auth` and `files` readiness degraded to `NOT_SERVING` while process liveness remained `SERVING`; `messaging`, `audit`, and `gateway` remained `SERVING` (`[PASS]`).
  - **Check 5 (Recovery)**: Restarted `postgres` container -> `auth` and `files` readiness recovered to `SERVING` (`[PASS]`).
  - **Check 6**: Clean teardown, zero leftover containers, host PostgreSQL 14 verified active on `localhost:5432` (`[PASS]`).

### 2. Service Configuration & Persistence Non-Regression
- `./scripts/verify-service-config.sh`: 10/10 checks passed cleanly (`[PASS]`).
- `./scripts/verify-persistence-infra.sh`: all persistence infrastructure checks and retention verified (`[PASS]`).
- Host PostgreSQL 14 on `localhost:5432`: 100% untouched throughout all tests.

### 3. CTest Suite Regression
- 79/79 unit and integration tests passed (100% pass rate in 6.48 seconds):
  - Unit tests: `HealthStatusManagerTest` (7 tests), `HealthServiceImplTest` (5 tests), `TransportProbeTest` (4 tests).
  - Integration tests: `HealthIntegrationTest` (10 tests), `MtlsIntegrationTest` (7 tests).

### 4. Code Hygiene & Static Analysis
- `./scripts/check-formatting.sh`: 0 errors. Fully compliant with project clang-format and clang-tidy standards.

