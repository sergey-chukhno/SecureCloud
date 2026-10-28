# AUDIT-001 — Establish Audit Service Configuration and Startup Foundation
## Phase 5 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: AUDIT-001  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  
**Date**: October 19, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-001** establishes the production-quality runtime foundation, strongly typed configuration architecture, ClickHouse connectivity parameters, bounded ingestion/query resource controls, strict mTLS 1.3 lifecycle management, and testing harness for the **SecureCloud Audit Service** (`securecloud-audit`).

The Audit Service is the centralized, immutable security and operational auditing authority for SecureCloud (**ADR-001**, **ADR-006**, **ADR-008**, and `docs/design/audit-design.md`). It asynchronously receives audit events from runtime services (Auth, Messaging, Files, Gateway) through their transactional outboxes, validates event schemas, and commits them to **ClickHouse** for high-throughput append-only analytical storage.

### Key Invariants & Architectural Boundaries for AUDIT-001

1. **Decoupled Asynchronous Reliability (ADR-007, ADR-009, Audit Design 7.1, 7.23)**:
   The Audit Service is **not** on the critical acceptance path for messages or files. An Audit Service degradation, network partition, or ClickHouse outage must **never** block Messaging or Files from durably accepting valid client operations. Runtime services stage audit events in their local transactional outboxes and retry transmission asynchronously with backpressure.
2. **Content Confidentiality & Zero Plaintext (ADR-008, Audit Design 7.6)**:
   Audit events must never become a side-channel for sensitive data. The Audit Service must **never** receive, persist, or log:
   - Message plaintext or unencrypted file bytes.
   - User, device, or session private cryptographic keys.
   - Passwords, MFA secrets, refresh tokens, or session tokens.
   - Plaintext file-encryption keys.
   All identity references in audit configurations and event records use opaque SecureCloud identifiers (`UserId`, `DeviceId`, `FileId`, `MessageId`).
3. **Database Ownership & ClickHouse Boundary (ADR-005, ADR-006, SC-011)**:
   The Audit Service is the sole application owner of the **ClickHouse** analytical database (`securecloud_audit`). No other service communicates with ClickHouse directly. Port `8123` (HTTP) and port `9000` (Native, host-mapped to `9009`) are dedicated to Audit. Workstation host PostgreSQL port `5432` and Files PostgreSQL port `5433` are strictly forbidden.
4. **Strict Configuration Naming & Fail-Closed Validation (SC-012)**:
   All Audit configuration keys use the canonical `SECURECLOUD_AUDIT_*` naming scheme. Configurations must fail closed immediately during initialization if required credentials or parameters are missing, malformed, or out of bounded ranges—prior to binding network listeners or spawning workers.
5. **Bounded Concurrency & Dual-Domain Isolation (Audit Design 7.21, ADR-010)**:
   Audit ingestion (write-heavy) and analytical audit queries (read-heavy) must execute in **independent bounded worker domains**. Query load or slow analytical scans must never starve ingestion worker threads or exhaust memory buffers.
6. **Graceful Drain & Deterministic Lifecycle (ADR-009)**:
   On receipt of `SIGINT` or `SIGTERM`, the service immediately marks readiness as `NOT_SERVING` to shed incoming traffic, drains in-flight event buffers within a bounded shutdown budget (`shutdown_grace_period_ms`), terminates the gRPC server, and safely closes database connections.

---

## 2. Dependency Graph

```text
               SC-006 (Service Skeletons)
               SC-010 (mTLS Infrastructure & Dev PKI)
               SC-011 (ClickHouse Persistence Infrastructure)
               SC-012 (Common Configuration Model)
               SC-013 (Health & Readiness Engine)
                           │
                           ▼
                     AUDIT-001-T01
            (AuditConfig Model & ClickHouse
               Connectivity Specification)
                           │
                           ▼
                     AUDIT-001-T02
            (Ingestion, Batching & Query Resource
                 Limits Configuration Engine)
                           │
                           ▼
                     AUDIT-001-T03
            (Deterministic Service Lifecycle Engine,
               mTLS Server & Graceful Drain)
                           │
                           ▼
                     AUDIT-001-T04
            (Comprehensive Unit Test Suite for Audit
                 Configuration & Lifecycle)
                           │
                           ▼
                     AUDIT-001-T05
            (End-to-End Audit Foundation Integration
               Test & Live Readiness Verification)
```

---

## 3. Implementation Tickets for Developer Lorenzo

### AUDIT-001-T01 — Audit Service Configuration Model & ClickHouse Connectivity Specification

1. **Ticket ID**: `AUDIT-001-T01`
2. **Title**: Audit Service Configuration Model & ClickHouse Connectivity Specification
3. **Objective**: Refactor and harden `AuditConfig` (`src/audit/audit_config.{hpp,cpp}`) to support comprehensive ClickHouse cluster connectivity parameters, credential protection, and fail-closed validation adhering to SC-012 and ADR-005.
4. **Architectural Purpose**: Establishes a strongly typed, immutable configuration model for database connectivity, preventing secret leaks in logs/traces and guaranteeing that misconfigured network parameters fail fast before socket binding.
5. **Scope**:
   - In `src/audit/audit_config.hpp`:
     - Define `ClickHouseConfig` struct:
       ```cpp
       struct ClickHouseConfig {
           std::string host{"clickhouse"};
           uint16_t port{8123}; // Default ClickHouse HTTP interface (SC-011)
           std::string db_name{"securecloud_audit"};
           std::string user{"audit_user"};
           common::configuration::SecretString password;
           uint32_t connect_timeout_ms{5000}; // [500, 30000]
           uint32_t request_timeout_ms{3000}; // [500, 30000]
           uint32_t max_connections{16};      // [1, 128]
       };
       ```
     - Embed `ClickHouseConfig clickhouse` inside `AuditConfig`.
   - In `src/audit/audit_config.cpp`:
     - Implement parsing from `ConfigurationSource` for:
       - `SECURECLOUD_AUDIT_DB_HOST` (default: `"clickhouse"`, rejects empty string)
       - `SECURECLOUD_AUDIT_DB_PORT` (default: `8123`, range: `[1, 65535]`, forbids port `5432` and `5433`)
       - `SECURECLOUD_AUDIT_DB_NAME` (default: `"securecloud_audit"`, rejects empty string)
       - `SECURECLOUD_AUDIT_DB_USER` (default: `"audit_user"`, rejects empty string)
       - `SECURECLOUD_AUDIT_DB_PASSWORD` (required, rejects missing or empty string)
       - `SECURECLOUD_AUDIT_DB_CONNECT_TIMEOUT_MS` (default: `5000`, range: `[500, 30000]`)
       - `SECURECLOUD_AUDIT_DB_REQUEST_TIMEOUT_MS` (default: `3000`, range: `[500, 30000]`)
       - `SECURECLOUD_AUDIT_DB_MAX_CONNECTIONS` (default: `16`, range: `[1, 128]`)
     - Enforce secret safety: `password` must be wrapped in `common::configuration::SecretString` so that accidental stream serialization or logging outputs `[REDACTED]`.
6. **Explicit Out-of-Scope**: Establishing live ClickHouse socket connections or executing SQL migrations (handled in AUDIT-002).
7. **Dependencies**: `SC-011`, `SC-012`, `securecloud::common`.
8. **Files to Inspect**:
   - `src/audit/audit_config.hpp`
   - `src/audit/audit_config.cpp`
   - `src/messaging/messaging_config.hpp` (Reference ScyllaConfig pattern)
   - `src/files/files_config.hpp` (Reference database config pattern)
9. **Files to Create/Modify**:
   - `src/audit/audit_config.hpp`
   - `src/audit/audit_config.cpp`

---

### AUDIT-001-T02 — Ingestion, Batching & Query Resource Limits Configuration Engine

1. **Ticket ID**: `AUDIT-001-T02`
2. **Title**: Ingestion, Batching, Query & Retention Resource Limits Configuration Engine
3. **Objective**: Implement strongly typed configuration structures for bounded worker pools, event batching, queue memory caps, analytical query limits, and data retention rules adhering to ADR-009, ADR-010, and Audit Design Sections 7.20–7.22.
4. **Architectural Purpose**: Guarantees bounded resource consumption under high event bursts. Prevents unbounded memory growth and protects analytical query capacity from starving event ingestion.
5. **Scope**:
   - In `src/audit/audit_config.hpp`:
     - Define `IngestionConfig`:
       ```cpp
       struct IngestionConfig {
           uint32_t workers{8};                      // [1, 64]
           uint32_t max_queued_events{10000};         // [100, 100000]
           uint32_t batch_size{500};                  // [1, 5000]
           uint32_t batch_flush_interval_ms{200};     // [10, 5000]
           uint32_t max_event_size_bytes{65536};      // [1024, 1048576] (64KB default, 1MB max)
       };
       ```
     - Define `QueryConfig`:
       ```cpp
       struct QueryConfig {
           uint32_t workers{4};                      // [1, 32]
           uint32_t max_page_limit{1000};             // [10, 10000]
           uint32_t default_page_limit{100};          // [1, max_page_limit]
           uint32_t query_timeout_ms{10000};          // [500, 60000]
       };
       ```
     - Define `RetentionConfig`:
       ```cpp
       struct RetentionConfig {
           uint32_t retention_days{90};              // [1, 3650]
           uint32_t shutdown_grace_period_ms{5000};   // [500, 30000]
       };
       ```
     - Embed `ingestion`, `query`, and `retention` in `AuditConfig`.
   - In `src/audit/audit_config.cpp`:
     - Parse corresponding environment variables:
       - `SECURECLOUD_AUDIT_INGESTION_WORKERS`
       - `SECURECLOUD_AUDIT_MAX_QUEUED_EVENTS`
       - `SECURECLOUD_AUDIT_BATCH_SIZE`
       - `SECURECLOUD_AUDIT_BATCH_FLUSH_INTERVAL_MS`
       - `SECURECLOUD_AUDIT_MAX_EVENT_SIZE_BYTES`
       - `SECURECLOUD_AUDIT_QUERY_WORKERS`
       - `SECURECLOUD_AUDIT_MAX_PAGE_LIMIT`
       - `SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT`
       - `SECURECLOUD_AUDIT_QUERY_TIMEOUT_MS`
       - `SECURECLOUD_AUDIT_RETENTION_DAYS`
       - `SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS`
     - Validate cross-field consistency:
       - `default_page_limit <= max_page_limit`.
       - `batch_size <= max_queued_events`.
       - Add descriptive validation errors to `ValidationResult` on violation.
6. **Explicit Out-of-Scope**: Thread pool allocation or event worker queue execution (handled in AUDIT-003).
7. **Dependencies**: `AUDIT-001-T01`.
8. **Files to Create/Modify**:
   - `src/audit/audit_config.hpp`
   - `src/audit/audit_config.cpp`

---

### AUDIT-001-T03 — Deterministic Service Lifecycle Engine & Graceful Drain Architecture

1. **Ticket ID**: `AUDIT-001-T03`
2. **Title**: Modular Audit Service Lifecycle Engine, Strict mTLS Server & Graceful Drain Architecture
3. **Objective**: Refactor `src/audit/main.cpp` into a modular, testable `AuditServer` / `AuditServiceLifecycle` class that encapsulates deterministic resource initialization, mTLS 1.3 socket binding, health probes, signal handling, and clean graceful drain.
4. **Architectural Purpose**: Separates process entrypoint from service lifecycle orchestration, enabling isolated unit testing of startup, state progression, and failure cleanup without launching child processes.
5. **Scope**:
   - In `src/audit/audit_server.hpp|cpp`:
     - Define `ServiceState` enum:
       - `Uninitialized`, `Configured`, `Starting`, `Running`, `Draining`, `Stopped`, `Failed`.
     - Implement `AuditServer` class:
       ```cpp
       class AuditServer {
       public:
           explicit AuditServer(AuditConfig config);
           ~AuditServer();

           /// Deterministic startup sequence:
           /// 1. Verifies configuration validity.
           /// 2. Loads mTLS server credentials via MtlsCredentialLoader.
           /// 3. Registers HealthServiceImpl with ClickHouse probe.
           /// 4. Binds gRPC mTLS port (50055).
           /// 5. Transitions to Running and marks health SERVING.
           bool start();

           /// Graceful drain sequence:
           /// 1. Transitions to Draining; marks health NOT_SERVING.
           /// 2. Initiates bounded gRPC server shutdown.
           /// 3. Releases database connections and thread resources.
           /// 4. Transitions to Stopped.
           void stop();

           [[nodiscard]] ServiceState state() const noexcept;
           [[nodiscard]] const AuditConfig& config() const noexcept;
           [[nodiscard]] bool is_healthy() const noexcept;

       private:
           AuditConfig config_;
           std::atomic<ServiceState> state_{ServiceState::Uninitialized};
           std::unique_ptr<grpc::Server> server_;
           std::shared_ptr<common::health::HealthStatusManager> health_manager_;
           std::unique_ptr<common::health::HealthServiceImpl> health_service_;
       };
       ```
   - In `src/audit/main.cpp`:
     - Slim down to top-level signal interception (`SIGINT`, `SIGTERM`), environment loading, and delegation to `AuditServer::start()` and `AuditServer::stop()`.
   - Update `src/audit/CMakeLists.txt`:
     - Add `audit_server.cpp` to `securecloud_audit_config` or new `securecloud_audit_server` library.
6. **Explicit Out-of-Scope**: Implementing business audit event submission RPCs (UNIMPLEMENTED stubbed for now).
7. **Dependencies**: `AUDIT-001-T01`, `AUDIT-001-T02`, `securecloud::common`.
8. **Files to Create/Modify**:
   - `src/audit/audit_server.hpp`
   - `src/audit/audit_server.cpp`
   - `src/audit/main.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-001-T04 — Comprehensive Unit Test Suite for Audit Configuration & Lifecycle

1. **Ticket ID**: `AUDIT-001-T04`
2. **Title**: Comprehensive Unit Test Suite for Audit Configuration Models, Validation & State Progression
3. **Objective**: Author exhaustive GoogleTest suites covering valid, boundary, invalid, missing, and secret-redaction scenarios for `AuditConfig` and `AuditServer`.
4. **Architectural Purpose**: Ensures 100% code coverage across configuration parsing, mathematical boundary enforcement, and failure cleanup before network operations occur.
5. **Scope**:
   - Create `tests/unit/audit/audit_config_test.cpp`:
     - **Test 1: DefaultValuesAreValid**: Asserts default ports (`50055`, `8123`), hostnames (`"0.0.0.0"`, `"clickhouse"`), worker counts (`8`, `4`), and batch limits (`500`, `200ms`).
     - **Test 2: CompleteEnvironmentOverride**: Loads a complete set of valid `SECURECLOUD_AUDIT_*` env vars and verifies all fields parse correctly.
     - **Test 3: MissingRequiredPasswordFailsClosed**: Verifies that missing or empty `SECURECLOUD_AUDIT_DB_PASSWORD` triggers a validation error.
     - **Test 4: PortBoundaryValidation**: Tests out-of-range ports (`0`, `65536`) and asserts rejection.
     - **Test 5: ReservedPortProhibition**: Asserts that setting database port to `5432` or `5433` fails validation.
     - **Test 6: IngestionWorkerBounds**: Tests min/max bounds for workers (`0` -> error, `65` -> error, `8` -> OK).
     - **Test 7: BatchSizeAndQueueBounds**: Verifies `batch_size > max_queued_events` is rejected.
     - **Test 8: QueryLimitsValidation**: Verifies `default_page_limit > max_page_limit` is rejected.
     - **Test 9: SecretRedactionVerification**: Asserts that `config.clickhouse.password.value()` is secret, and streaming `SecretString` does not reveal the plaintext password.
   - Create `tests/unit/audit/audit_server_lifecycle_test.cpp`:
     - Tests `AuditServer` state transitions (`Uninitialized -> Configured -> Starting -> Running -> Draining -> Stopped`).
     - Tests invalid configuration rejection without starting network listeners.
     - Tests graceful stop idempotency (calling `stop()` multiple times is safe).
   - Register targets in `tests/unit/CMakeLists.txt`:
     - `securecloud_audit_config_test`
     - `securecloud_audit_server_lifecycle_test`
6. **Explicit Out-of-Scope**: Network socket integration tests with real certificates.
7. **Dependencies**: `AUDIT-001-T01`, `AUDIT-001-T02`, `AUDIT-001-T03`.
8. **Files to Create/Modify**:
   - `tests/unit/audit/audit_config_test.cpp`
   - `tests/unit/audit/audit_server_lifecycle_test.cpp`
   - `tests/unit/CMakeLists.txt`

---

### AUDIT-001-T05 — End-to-End Audit Service Foundation Integration Test & Verification Harness

1. **Ticket ID**: `AUDIT-001-T05`
2. **Title**: End-to-End Audit Foundation Integration Test & Live Health Probe Verification
3. **Objective**: Build a full integration test harness validating live gRPC server startup, mTLS 1.3 certificate validation, standard Health Checking Protocol compliance, ClickHouse connectivity evaluation, and signal-driven shutdown.
4. **Architectural Purpose**: Validates that the Audit service compiles, links, boots, listens on port `50055`, enforces mutual TLS, and cleanly responds to health probes in an environment adhering to ADR-004 and ADR-010.
5. **Scope**:
   - Create `tests/integration/audit_service_lifecycle_integration_test.cpp`:
     - Test Case 1: `AuditServiceStartsAndBindsMtlsPort`:
       - Boots `AuditServer` with development PKI certificates (`deploy/dev-pki/`).
       - Connects via gRPC `HealthClient` over mTLS using client credentials.
       - Asserts `Check("audit")` returns `SERVING`.
     - Test Case 2: `AuditServiceRejectsInsecurePlaintextConnection`:
       - Attempts to connect without mTLS / insecure channel; verifies connection is rejected or fails handshake.
     - Test Case 3: `ClickHouseConnectivityProbeHealthDegradation`:
       - Configures probe to an unreachable ClickHouse port.
       - Verifies that readiness transitions to `NOT_SERVING` while process liveness remains `SERVING`.
     - Test Case 4: `GracefulShutdownDrainsCleanly`:
       - Sends stop signal; verifies readiness immediately degrades, gRPC server terminates, and process exit is clean within 5000ms.
   - Register executable `securecloud_audit_service_lifecycle_integration_test` in `tests/integration/CMakeLists.txt`.
   - Update `CMakeLists.txt` and ensure `ctest -R "audit"` executes cleanly.
6. **Explicit Out-of-Scope**: Querying or ingesting business audit events.
7. **Dependencies**: `AUDIT-001-T01` through `AUDIT-001-T04`.
8. **Files to Create/Modify**:
   - `tests/integration/audit_service_lifecycle_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`

---

## 4. Summary Table: Tickets, Deliverables & Invariant Verification

| Ticket | Scope Summary | Key Deliverables | Verified Invariants |
| :--- | :--- | :--- | :--- |
| **AUDIT-001-T01** | ClickHouse DB Configuration | `ClickHouseConfig`, `SECURECLOUD_AUDIT_DB_*` parsers, `SecretString` | ADR-005 (DB isolation, no port 5432/5433), SC-012 (canonical env names, fail closed) |
| **AUDIT-001-T02** | Ingestion & Query Resource Limits | `IngestionConfig`, `QueryConfig`, `RetentionConfig`, cross-field validation | ADR-010 (bounded worker pools, bounded batching), Audit Design 7.21 (dual-domain isolation) |
| **AUDIT-001-T03** | Modular Server & Lifecycle Engine | `AuditServer`, `ServiceState` machine, deterministic startup & graceful drain | ADR-009 (failure isolation, graceful drain), ADR-004 (strict mTLS 1.3) |
| **AUDIT-001-T04** | Configuration & Lifecycle Unit Tests | `audit_config_test.cpp`, `audit_server_lifecycle_test.cpp` | Comprehensive coverage for valid defaults, boundary violations, secret masking |
| **AUDIT-001-T05** | E2E Foundation Integration Test | `audit_service_lifecycle_integration_test.cpp`, live gRPC mTLS probe | SC-010 (mTLS 1.3 handshake), SC-013 (Health Checking Protocol SERVING / NOT_SERVING) |

---

## 5. Implementation Order & Verification Gateways for Lorenzo

1. **Step 1 (T01)**: Extend `AuditConfig` with `ClickHouseConfig`. Verify compilation and secret redaction.
2. **Step 2 (T02)**: Implement `IngestionConfig`, `QueryConfig`, and `RetentionConfig` with boundary validation.
3. **Step 3 (T03)**: Implement `AuditServer` lifecycle class and update `src/audit/main.cpp`.
4. **Step 4 (T04)**: Write unit tests in `tests/unit/audit/`. Run `ctest -R "securecloud_audit_.*test"` and achieve 100% pass rate.
5. **Step 5 (T05)**: Implement live integration test in `tests/integration/` using dev PKI mTLS. Verify clean shutdown and health reporting.
