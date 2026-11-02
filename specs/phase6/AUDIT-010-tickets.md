# AUDIT-010 — Readiness, Health Checks and Graceful Shutdown
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: `AUDIT-010`  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: November 2, 2026  
**Dependencies**: `AUDIT-001` (Audit Config & Runtime Foundation), `AUDIT-003` (ClickHouse Schema & Repository Layer), `AUDIT-004` (Authenticated gRPC Ingestion Contract), `AUDIT-005` (Bounded Asynchronous Ingestion & Batch Persistence), `AUDIT-006` (Deduplication & Acknowledgement Contract)  
**Related ADRs**: `ADR-005` (Internal Perimeter & mTLS 1.3), `ADR-006` (Canonical Audit Event Schema), `ADR-009` (Service Lifecycle, Failure Isolation & Graceful Drain), `ADR-010` (Bounded Resource Allocation & Overload Defense)

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-010** specifies and implements production-quality **health reporting**, **dynamic readiness management**, and **bounded graceful shutdown** for the **SecureCloud Audit Service** (`securecloud-audit`).

In an enterprise microservice topology, the Audit Service must accurately communicate its operational status to Docker Compose health probes, cluster orchestrators, and upstream producer services (Gateway, Auth, Messaging, Files). A naive health check that merely verifies a listening TCP socket or conflates process liveness with storage readiness causes catastrophic failures: orchestrators may prematurely restart an audit container during a transient ClickHouse compaction pause, or route new audit traffic to a service whose internal queues are saturated, leading to silent event loss or false durability acknowledgements.

### Key Invariants & Architectural Boundaries for AUDIT-010

1. **Strict Semantic Separation of Liveness and Readiness (ADR-009)**:
   - **Liveness (`/liveness` / `is_live`)**: Confirms the `securecloud-audit` process is functioning, its internal worker threads are not deadlocked, and heap memory is within limits. Transient downstream outages (e.g. ClickHouse restart) must **never** degrade liveness or cause the container orchestrator to restart the Audit Service.
   - **Readiness (`/readiness` / `is_ready`)**: Confirms the service can safely accept and durably persist new audit ingestion work. Readiness requires active ClickHouse HTTP query responsiveness (`ClickHouseClient::ping()`) and non-saturated ingestion queues.
2. **Never Acknowledge Unpersisted Work as Durable (ADR-006, ADR-010)**:
   During shutdown or degradation, events that remain uncommitted in memory when the drain deadline expires must **never** be acknowledged as successfully committed (`success = true`). The service must explicitly fail or negatively acknowledge (NACK) uncommitted events so upstream producer outbox relays know to retain and retry them.
3. **Multi-Phase Ordered Shutdown Drain Sequence (ADR-009)**:
   Shutdown proceeds in a deterministic, bounded sequence:
   $$\text{Withdraw Readiness} \longrightarrow \text{Reject New Ingress} \longrightarrow \text{Drain In-Flight Batches} \longrightarrow \text{Terminate Workers} \longrightarrow \text{Release Resources}$$
4. **Non-Blocking Health Check Probing**:
   gRPC Health Checking RPCs (`securecloud.common.v1.HealthService/Check`) must never synchronously execute database network calls. An asynchronous background evaluator maintains cached atomic status flags so health inquiries respond instantaneously without blocking.
5. **Zero Secret & Connection String Exposure**:
   Health and diagnostic endpoints report abstract states (`SERVING`, `NOT_SERVING`, `DEGRADED`) and sanitized error categories. Connection strings, passwords, ClickHouse endpoints, and sensitive event metadata must never be exposed.
6. **Infrastructure & Environment Stability**:
   No changes to Docker Compose topology or external infrastructure. The host PostgreSQL 14 instance on `localhost:5432` must remain untouched.

---

## 2. Health & Readiness State Model

```text
                                LIFECYCLE & READINESS TRANSITION GRAPH

       ┌────────────────────────┐
       │     Uninitialized      │
       └───────────┬────────────┘
                   │ Load Config & Validate
                   ▼
       ┌────────────────────────┐
       │       Configured       │
       └───────────┬────────────┘
                   │ Load mTLS Certs & Initialize Repositories
                   ▼
       ┌────────────────────────┐
       │        Starting        │ ──► Liveness: TRUE | Readiness: FALSE (NOT_SERVING)
       └───────────┬────────────┘
                   │ DDL Schema Verified & Initial ClickHouse Ping Succeeds
                   ▼
       ┌────────────────────────┐
       │     Ready (Serving)    │ ◄───┐
       └─────┬────────────┬─────┘     │
             │            │           │ ClickHouse Recovers &
             │ CH Down    │ Queue     │ Queue Drained Below High-Water
             ▼            ▼           │
       ┌────────────────────────┐     │
       │  Degraded / Not-Ready  │ ────┘
       │     (NOT_SERVING)      │ ──► Liveness: TRUE | Readiness: FALSE
       └───────────┬────────────┘
                   │ SIGINT / SIGTERM / Stop Requested
                   ▼
       ┌────────────────────────┐
       │   Draining (Shutdown)  │ ──► Readiness: FALSE | Reject New Ingress (UNAVAILABLE)
       └───────────┬────────────┘     Allow in-flight batches up to shutdown_grace_period_ms
                   │ In-flight work drained OR Deadline expired
                   ▼
       ┌────────────────────────┐
       │        Stopped         │ ──► Worker pools joined, gRPC server terminated
       └────────────────────────┘
```

### Readiness Evaluation Criteria

Readiness evaluates to `SERVING` if and only if **all** of the following conditions hold:
1. Service state is `Running` (not `Starting`, `Draining`, `Stopped`, or `Failed`).
2. Server shutdown has not been requested (`is_shutting_down_ == false`).
3. ClickHouse HTTP probe succeeds within `probe_timeout_ms` (`ClickHouseClient::ping()` returns `true`).
4. Ingestion queue occupancy is below the high-water saturation threshold ($< 90\%$ capacity).
5. All background ingestion worker threads are active and responsive.

---

## 3. Graceful Shutdown & Drain Execution Sequence

```text
Time (ms)  Shutdown Step & Actions
   │
   ├─► T+0ms:    Signal Received (SIGINT/SIGTERM) or AuditServer::stop() called.
   │             - Atomic flag set: stop_requested_ = true (idempotent; ignores duplicate signals).
   │             - Transition State: ServiceState::Draining.
   │             - Withdraw Readiness: health_manager_->set_ready(false), set_shutting_down(true).
   │             - External load balancers and upstream producers immediately observe NOT_SERVING.
   │
   ├─► T+10ms:   Ingress Rejection Enforced:
   │             - AuditServiceImpl immediately rejects *new* SubmitAuditEvent and BatchSubmitAuditEvents
   │               with grpc::StatusCode::UNAVAILABLE ("Service is draining; retry against outbox").
   │
   ├─► T+50ms:   In-Flight Batch Drain:
   │             - Ingestion pipeline flushes all accepted events in BoundedIngestionQueue into ClickHouse.
   │             - Insertion workers execute final ClickHouse bulk inserts.
   │
   ├─► T+...:    Deadline Monitoring (shutdown_grace_period_ms budget, default 5,000 ms):
   │             - If drain completes within budget: all accepted events acknowledged as durable.
   │             - If deadline expires with pending events: uncommitted events are NOT acknowledged
   │               (marked failed/dropped so producer outboxes will re-transmit upon recovery).
   │
   ├─► T_drain:  gRPC Server & Worker Termination:
   │             - server_->Shutdown(deadline).
   │             - Stop and join Ingestion & Insert worker pools.
   │             - Close ClickHouse HTTP client connection pools.
   │
   └─► T_final:  Transition State: ServiceState::Stopped. Clean exit code 0.
```

---

## 4. Configuration Sizing & Timing Matrix

All timeouts and intervals are configured via `AuditConfig` ([audit_config.hpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/audit/audit_config.hpp)):

| Configuration Parameter | Canonical Environment Variable | Default Value | Valid Range | Architectural Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Health Probe Interval** | `SECURECLOUD_AUDIT_HEALTH_PROBE_INTERVAL_MS` | `1,000 ms` | `[100, 10000]` | Background polling interval for dependency health |
| **Health Probe Timeout** | `SECURECLOUD_AUDIT_HEALTH_PROBE_TIMEOUT_MS` | `500 ms` | `[50, 5000]` | Maximum duration allowed for single ClickHouse ping |
| **Queue Saturation Threshold** | `SECURECLOUD_AUDIT_HEALTH_QUEUE_HIGH_WATER_PCT` | `90%` | `[50, 95]` | Ingestion queue occupancy that triggers readiness withdrawal |
| **Shutdown Grace Period** | `SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS` | `5,000 ms` | `[500, 30000]` | Bounded maximum time budget to drain in-flight batches |
| **Dependency Failure Threshold** | `SECURECLOUD_AUDIT_HEALTH_CONSECUTIVE_FAILURES` | `3` | `[1, 10]` | Consecutive failed pings before withdrawing readiness |

---

## 5. Implementation Tickets for Developer Lorenzo

```text
               AUDIT-001 (Config & Lifecycle Baseline)
               AUDIT-003 (ClickHouse Repository)
               AUDIT-004 (gRPC Ingestion Service)
               AUDIT-005 (Bounded Ingestion Queue)
                             │
                             ▼
                       AUDIT-010-T01
             (AuditHealthEvaluator & Asynchronous
              Non-Blocking Dependency Prober)
                             │
                             ▼
                       AUDIT-010-T02
             (Dynamic Readiness State Machine &
              Hysteresis Failure/Recovery Policy)
                             │
                             ▼
                       AUDIT-010-T03
             (Multi-Phase Graceful Drain Sequence &
              Durability Contract Preservation)
                             │
                             ▼
                       AUDIT-010-T04
             (Idempotent Signal Handler & Thread-Safe
              Resource Teardown Orchestrator)
                             │
                             ▼
                       AUDIT-010-T05
             (Configuration Binding, Validation &
              Docker Healthcheck Harmonization)
                             │
                             ▼
                       AUDIT-010-T06
             (Comprehensive Lifecycle, Degradation,
              Drain & Failure Injection Test Suite)
```

---

### AUDIT-010-T01: AuditHealthEvaluator & Asynchronous Non-Blocking Dependency Prober

1. **Ticket ID**: `AUDIT-010-T01`
2. **Title**: AuditHealthEvaluator & Asynchronous Non-Blocking Dependency Prober
3. **Objective**: Implement `AuditHealthEvaluator`, an asynchronous background evaluator that continuously monitors ClickHouse responsiveness and ingestion queue health, maintaining cached atomic states to drive `HealthStatusManager` without blocking incoming gRPC health check queries.
4. **Scope & Technical Requirements**:
   - Create `src/audit/health/audit_health_evaluator.hpp` and `.cpp`.
   - Define configuration:
     ```cpp
     struct AuditHealthEvaluatorConfig {
         std::chrono::milliseconds check_interval{1000};
         std::chrono::milliseconds probe_timeout{500};
         uint32_t consecutive_failures_threshold{3};
         uint32_t queue_high_water_pct{90};
         bool auto_start{true};
     };
     ```
   - Class `AuditHealthEvaluator`:
     ```cpp
     class AuditHealthEvaluator {
     public:
         using ClickHouseProbeFn = std::function<bool(std::chrono::milliseconds)>;
         using QueueHealthFn = std::function<bool(uint32_t& out_occupancy_pct)>;

         AuditHealthEvaluator(common::health::HealthStatusManager& health_manager,
                              std::shared_ptr<repository::ClickHouseClient> clickhouse_client,
                              QueueHealthFn queue_health_fn,
                              AuditHealthEvaluatorConfig config = {});

         AuditHealthEvaluator(common::health::HealthStatusManager& health_manager,
                              ClickHouseProbeFn clickhouse_probe,
                              QueueHealthFn queue_health_fn,
                              AuditHealthEvaluatorConfig config = {});

         ~AuditHealthEvaluator();

         bool evaluate_once() noexcept;
         void start();
         void stop() noexcept;

         [[nodiscard]] bool is_clickhouse_healthy() const noexcept;
         [[nodiscard]] bool is_queue_healthy() const noexcept;
         [[nodiscard]] bool is_ready() const noexcept;
         [[nodiscard]] bool is_running() const noexcept;
     };
     ```
   - Evaluator probes ClickHouse via `ClickHouseClient::ping(probe_timeout)` and checks ingestion queue occupancy.
   - Updates `health_manager_.set_ready(is_ready)` atomically.
   - Non-blocking guarantee: incoming gRPC health check queries only read cached atomic variables.
5. **Architectural Constraints**:
   - Background thread must cleanly sleep on `std::condition_variable` and wake immediately on `stop()`.
   - Never throw exceptions out of `evaluate_once()` or background thread.
6. **Acceptance Criteria**:
   - When ClickHouse is responsive and queue is normal, `is_ready()` is true and health status is `SERVING`.
   - If ClickHouse ping fails or times out, `is_ready()` transitions to false (`NOT_SERVING`), while `is_live()` remains true.
7. **Dependencies**: `AUDIT-001-T03`, `AUDIT-003-T02`.

---

### AUDIT-010-T02: Dynamic Readiness State Machine & Hysteresis Failure/Recovery Policy

1. **Ticket ID**: `AUDIT-010-T02`
2. **Title**: Dynamic Readiness State Machine & Hysteresis Failure/Recovery Policy
3. **Objective**: Implement state transitions and flapping prevention (hysteresis) for readiness degradation and recovery during transient network or ClickHouse outages.
4. **Scope & Technical Requirements**:
   - Create `src/audit/lifecycle/audit_service_state.hpp` and `.cpp`.
   - Define service state machine:
     ```cpp
     enum class DetailedServiceState {
         Uninitialized,
         Configured,
         Starting,
         Ready,
         Degraded,
         NotReady,
         Draining,
         Stopped,
         Failed
     };
     ```
   - Implement Hysteresis Logic in `AuditHealthEvaluator`:
     - Degradation Trigger: Mark `NOT_SERVING` only after `consecutive_failures_threshold` consecutive failed probes (default: 3 failed probes over 3 seconds) to prevent transient network hiccups from flapping service readiness.
     - Recovery Trigger: Mark `SERVING` only after 2 consecutive successful pings AND queue occupancy $< 80\%$.
   - Queue Saturation Policy:
     - If queue occupancy $\ge 90\%$, immediately withdraw readiness without waiting for failure counter.
     - As queue clears below $80\%$, restore readiness.
5. **Architectural Constraints**:
   - Thread-safe state transitions using `std::atomic` and compare-and-swap semantics.
   - Diagnostic logging on every state transition with reason (e.g. `ClickHousePingTimeout`, `QueueSaturated`).
6. **Acceptance Criteria**:
   - Single isolated network timeout does not flap readiness to `NOT_SERVING`.
   - Sustained outage causes deterministic transition to `NOT_SERVING`.
   - Recovery deterministically restores `SERVING` once health criteria are satisfied.
7. **Dependencies**: `AUDIT-010-T01`.

---

### AUDIT-010-T03: Multi-Phase Graceful Drain Sequence & Durability Contract Preservation

1. **Ticket ID**: `AUDIT-010-T03`
2. **Title**: Multi-Phase Graceful Drain Sequence & Durability Contract Preservation
3. **Objective**: Implement bounded graceful drain orchestration ensuring all in-flight and accepted events are either durably flushed to ClickHouse or explicitly NACKed, with zero false durability acknowledgements.
4. **Scope & Technical Requirements**:
   - Update `src/audit/service/audit_service_impl.hpp` and `.cpp`:
     - Add `void set_draining(bool draining) noexcept;`
     - When `draining_ == true`, all new incoming `SubmitAuditEvent` and `BatchSubmitAuditEvents` calls immediately return `grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service is draining; retry via outbox buffer")`.
   - Update `src/audit/audit_server.hpp` and `.cpp` shutdown flow:
     - Phase 1: Call `health_manager_->set_shutting_down(true)` and `set_ready(false)` (health check becomes `NOT_SERVING`).
     - Phase 2: Call `audit_service_->set_draining(true)` to reject new ingress.
     - Phase 3: Flush existing ingestion queue into ClickHouse within `config.retention.shutdown_grace_period_ms`.
     - Phase 4: Await completion of in-flight ClickHouse batches.
     - Phase 5: Complete durability promises:
       - Committed batches return `success = true` with authoritative `received_at`.
       - If shutdown deadline expires while events remain uncommitted: fail remaining batches with `UNAVAILABLE`. Never falsely acknowledge uncommitted events.
     - Phase 6: Shutdown gRPC server (`server_->Shutdown(deadline)`).
     - Phase 7: Join worker threadpools and close ClickHouse client.
5. **Architectural Constraints**:
   - Hard deadline enforcement: shutdown must never block indefinitely if ClickHouse hangs during drain.
   - Zero memory leaks or dangling pointers during shutdown.
6. **Acceptance Criteria**:
   - Upstream clients receiving `OK` are guaranteed that their events are committed in ClickHouse.
   - In-flight events during drain are successfully flushed if ClickHouse is reachable.
   - Events that fail to flush before deadline expires are returned as failed.
7. **Dependencies**: `AUDIT-010-T02`, `AUDIT-004-T04`, `AUDIT-005-T04`.

---

### AUDIT-010-T04: Idempotent Signal Handler & Thread-Safe Resource Teardown Orchestrator

1. **Ticket ID**: `AUDIT-010-T04`
2. **Title**: Idempotent Signal Handler & Thread-Safe Resource Teardown Orchestrator
3. **Objective**: Implement signal handling for `SIGINT` and `SIGTERM` in `main.cpp` and ensure `AuditServer::stop()` is completely thread-safe, non-reentrant, and idempotent under concurrent or repeated termination requests.
4. **Scope & Technical Requirements**:
   - Update `src/audit/main.cpp`:
     - Register `std::signal(SIGINT, signal_handler)` and `std::signal(SIGTERM, signal_handler)`.
     - Signal handler sets `std::atomic<bool> g_shutdown_requested{false}` using `memory_order_release`.
     - Main event loop monitors `g_shutdown_requested` and cleanly triggers `server.stop()`.
   - Update `AuditServer::stop()` in `src/audit/audit_server.cpp`:
     - Compare-and-swap on internal atomic state:
       ```cpp
       auto expected = ServiceState::Running;
       if (!state_.compare_exchange_strong(expected, ServiceState::Draining, std::memory_order_acq_rel)) {
           // Already draining, stopped, or failed; return safely without redundant work
           return;
       }
       ```
     - Guard against concurrent calls to `stop()` from multiple threads.
     - Ensure destructor `~AuditServer()` safely calls `stop()` if not already stopped.
5. **Architectural Constraints**:
   - Async-signal-safe signal handling: signal handler only modifies atomic flags, performs zero allocations, and invokes no mutexes or I/O.
   - Thread safety: no data races reported under ThreadSanitizer (TSan).
6. **Acceptance Criteria**:
   - Multiple rapid `SIGTERM` or `Ctrl-C` signals do not cause crashes, double-frees, or corrupted state.
   - Program exits cleanly with exit code 0 on termination signals.
7. **Dependencies**: `AUDIT-010-T03`.

---

### AUDIT-010-T05: Configuration Binding, Validation & Docker Healthcheck Harmonization

1. **Ticket ID**: `AUDIT-010-T05`
2. **Title**: Configuration Binding, Validation & Docker Healthcheck Harmonization
3. **Objective**: Expose strongly typed health check and lifecycle configuration parameters in `AuditConfig`, validate them fail-closed at startup, and ensure full compatibility with Docker Compose health probes.
4. **Scope & Technical Requirements**:
   - Update `src/audit/audit_config.hpp` and `.cpp`:
     - Add `HealthConfig` struct:
       ```cpp
       struct HealthConfig {
           uint32_t probe_interval_ms{1000};
           uint32_t probe_timeout_ms{500};
           uint32_t consecutive_failures_threshold{3};
           uint32_t queue_high_water_pct{90};
       };
       ```
     - Parse from environment variables:
       - `SECURECLOUD_AUDIT_HEALTH_PROBE_INTERVAL_MS`
       - `SECURECLOUD_AUDIT_HEALTH_PROBE_TIMEOUT_MS`
       - `SECURECLOUD_AUDIT_HEALTH_CONSECUTIVE_FAILURES`
       - `SECURECLOUD_AUDIT_HEALTH_QUEUE_HIGH_WATER_PCT`
       - `SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS`
     - Validate ranges fail-closed: probe interval $\in [100, 10000]$ ms, probe timeout $\in [50, 5000]$ ms, grace period $\in [500, 30000]$ ms.
   - Verify Docker Compose healthcheck alignment:
     - Health service exposed on port `50055` via standard `securecloud.common.v1.HealthService`.
     - Docker Compose healthcheck command functions cleanly without modification.
5. **Architectural Constraints**:
   - Canonical `SECURECLOUD_*` environment variable prefixes.
   - Zero sensitive configuration data leaked in validation errors.
6. **Acceptance Criteria**:
   - Valid environment variables are loaded and mapped into `AuditConfig::health`.
   - Invalid, negative, or out-of-range values fail closed at startup with descriptive error messages.
7. **Dependencies**: `AUDIT-001-T01`, `AUDIT-001-T02`.

---

### AUDIT-010-T06: Comprehensive Lifecycle, Degradation, Drain & Failure Injection Test Suite

1. **Ticket ID**: `AUDIT-010-T06`
2. **Title**: Comprehensive Lifecycle, Degradation, Drain & Failure Injection Test Suite
3. **Objective**: Construct exhaustive unit, integration, lifecycle, and failure-injection test suites validating liveness/readiness separation, ClickHouse outage/recovery, queue saturation, and bounded graceful drain.
4. **Scope & Technical Requirements**:
   - Create `tests/unit/audit/audit_health_evaluator_test.cpp`:
     - **Test 1: Initial State & Startup Probing**: Verify initial state is `NOT_SERVING` until evaluation succeeds.
     - **Test 2: ClickHouse Responsiveness & Flapping Hysteresis**: Verify single probe timeout does not drop readiness; verify 3 consecutive timeouts trigger `NOT_SERVING`.
     - **Test 3: ClickHouse Outage Recovery**: Verify service transitions back to `SERVING` after 2 consecutive successful pings.
     - **Test 4: Queue Saturation Threshold**: Verify queue $\ge 90\%$ immediately triggers `NOT_SERVING`; clearing $< 80\%$ restores readiness.
     - **Test 5: Non-Blocking Evaluation Property**: Verify probe timeout does not block concurrent status queries.
   - Create `tests/integration/audit_graceful_shutdown_integration_test.cpp`:
     - **Test 6: Readiness Withdrawal on Shutdown**: Verify readiness immediately switches to `NOT_SERVING` upon `stop()` call.
     - **Test 7: Ingress Rejection During Drain**: Verify new RPCs during drain are rejected with `UNAVAILABLE`.
     - **Test 8: In-Flight Batch Flush Under Deadline**: Submit 500 events; initiate `stop()`; verify all 500 events are flushed to ClickHouse and acknowledged before server terminates.
     - **Test 9: Drain Deadline Expiration & NACK Fidelity**: Simulate frozen ClickHouse during drain; verify shutdown terminates within `shutdown_grace_period_ms` and unpersisted events are NOT falsely acknowledged as durable.
     - **Test 10: Repeated & Concurrent Shutdown Signals**: Trigger 10 concurrent threads calling `AuditServer::stop()`; verify thread-safe idempotent termination with zero data races.
   - Register targets in `tests/unit/CMakeLists.txt` and `tests/integration/CMakeLists.txt`.
5. **Architectural Constraints**:
   - Hermetic test execution with zero external dependencies.
   - Clean compilation under `-Wall -Wextra -Werror -Wpedantic`.
6. **Acceptance Criteria**:
   - 100% test pass rate across all new test targets.
   - Strict adherence to `.clang-format`.
7. **Dependencies**: `AUDIT-010-T01` through `AUDIT-010-T05`.

---

## 6. Acceptance Criteria & Definition of Done Matrix

| Ticket ID | Deliverables | Architectural Invariant | Verification Target |
| :--- | :--- | :--- | :--- |
| **AUDIT-010-T01** | `audit_health_evaluator.{hpp,cpp}` | ADR-009, Non-Blocking Health | Unit test verification of asynchronous ClickHouse & queue evaluation |
| **AUDIT-010-T02** | `audit_service_state.{hpp,cpp}` | ADR-009, Flapping Defense | Hysteresis verification: 3 failures to degrade, 2 successes to recover |
| **AUDIT-010-T03** | Multi-phase drain in `AuditServer`, `AuditServiceImpl` | ADR-006, ADR-010, No False ACKs | Integration test verifying in-flight flush and deadline expiration NACK |
| **AUDIT-010-T04** | Signal handling in `main.cpp`, idempotent `stop()` | ADR-009, Thread Safety | Concurrent multi-threaded `stop()` invocation test |
| **AUDIT-010-T05** | `HealthConfig` in `audit_config.{hpp,cpp}` | ADR-001, Canonical Envs | Configuration range validation unit tests |
| **AUDIT-010-T06** | Unit & Integration Test Suites | All Milestone M6 Standards | `ctest -R "audit_health|audit_graceful_shutdown"` passing 100% |

---

## 7. Risk Analysis & Mitigation Matrix

| Identified Risk | Severity | Potential Impact | Architectural Mitigation |
| :--- | :--- | :--- | :--- |
| **False Durability Claim on Shutdown** | **Critical** | Producer drops outbox event believing it was persisted, resulting in silent data loss | Durability promises completed only after ClickHouse HTTP `200 OK`; drain deadline expiration returns explicit error/NACK. |
| **Container Restart Storm (Liveness Flapping)** | **High** | Transient ClickHouse slowdown causes orchestrator to kill Audit daemon in an endless loop | Strict semantic separation: ClickHouse failure ONLY affects readiness (`is_ready = false`); liveness remains true. |
| **Readiness Flapping under Network Jitter** | **Medium** | Single packet loss causes external traffic shifting back and forth | Hysteresis: requires 3 consecutive failures to degrade readiness, and 2 consecutive successes to restore. |
| **Hang during Shutdown (Indefinite Drain)** | **Medium** | Service hangs indefinitely if ClickHouse becomes unresponsive during shutdown | Strict bounded timeout (`shutdown_grace_period_ms`); forcibly halts drain and joins threads when budget expires. |
| **Health Check Thread Starvation** | **Low** | Slow ClickHouse ping blocks gRPC health service threadpool | Background evaluator decouples polling from serving; health RPCs only read cached atomic variables. |

