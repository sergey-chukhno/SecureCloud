# SecureCloud — AUDIT-010 Card Implementation & Validation Report

**Card ID**: `AUDIT-010`  
**Card Title**: *Implement Readiness, Health Checks and Bounded Graceful Shutdown*  
**Branch**: `feature/audit-010-implement-readiness-health-checks-and-graceful-shutdown`  
**Status**: **100% Implemented & Validated**  
**Date**: 2026-11-04  
**Author**: Lorenzo & Engineering Team

---

## 1. Executive Summary

Card **AUDIT-010** specifies, implements, and validates the authoritative **liveness and readiness health reporting**, **dynamic failure degradation with flapping protection**, and **multi-phase bounded graceful shutdown sequence** for the **SecureCloud Audit Service** (`securecloud-audit`).

As a foundational M6 milestone service, the Audit Service must reliably communicate its operational status to Docker Compose health probes, cluster orchestrators, and upstream microservice producers (Gateway, Auth, Messaging, Files). Conflating process liveness with ClickHouse readiness or performing synchronous database pings on gRPC health check calls can lead to container restart storms during transient ClickHouse compactions or silent event loss during shutdown.

`AUDIT-010` resolves these reliability risks by implementing an asynchronous non-blocking health evaluator (`AuditHealthEvaluator`), strict semantic separation between liveness and readiness (ADR-009), a hysteresis-backed failure/recovery state machine (`AuditServiceState`), a 7-phase bounded graceful drain sequence (`AuditServer::stop`), an async-signal-safe OS signal handler (`main.cpp`), and strongly typed configuration validation (`HealthConfig`).

All 6 implementation tickets (`AUDIT-010-T01` through `AUDIT-010-T06`) have been fully completed in C++20, compiled under strict compiler flags (`-Wall -Wextra -Werror -Wpedantic`), and validated with a 100% pass rate across unit, concurrency, idempotency, and graceful drain integration test suites.

---

## 2. Deep Architectural Decisions

### A. Strict Semantic Separation of Liveness and Readiness (ADR-009)
- **Liveness (`/liveness` / `is_live`)**: Confirms the `securecloud-audit` process is executing, its internal threadpool is active, and memory usage is within bounds. Transient database outages or ClickHouse restarts **never** degrade liveness or trigger container restart loops.
- **Readiness (`/readiness` / `is_ready`)**: Confirms the service can safely ingest and durably persist audit events. Readiness requires active ClickHouse HTTP query responsiveness (`ClickHouseClient::ping()`) and non-saturated ingestion queues ($< 90\%$ capacity).

### B. Non-Blocking Health Evaluation & Flapping Hysteresis Defense (ADR-009)
- **Asynchronous Background Evaluator (`AuditHealthEvaluator`)**: Decouples incoming gRPC health probes (`securecloud.common.v1.HealthService/Check`) from database I/O. Health queries read cached atomic flags instantly without blocking worker threads.
- **Flapping Defense Hysteresis**:
  - **Degradation**: Requires $3$ consecutive failed ClickHouse pings (`consecutive_failures_threshold = 3`) before dropping readiness to `NOT_SERVING`, preventing transient network jitter or brief compactions from flipping readiness.
  - **Recovery**: Requires $2$ consecutive successful ClickHouse pings (`consecutive_successes_threshold = 2`) **and** queue occupancy below $80\%$ (`queue_low_water_pct = 80`) to restore `SERVING` status.
- **Immediate Queue Saturation Override**: If ingestion queue occupancy reaches $\ge 90\%$, readiness is withdrawn immediately to trigger upstream load shedding and outbox buffering.

### C. Multi-Phase Ordered Graceful Drain Sequence (ADR-009, ADR-010)
- **Deterministic 7-Phase Teardown**:
  $$\text{Withdraw Readiness} \longrightarrow \text{Reject Ingress} \longrightarrow \text{Flush In-Flight Queue} \longrightarrow \text{Await Batches} \longrightarrow \text{Fulfill Promises} \longrightarrow \text{Stop gRPC} \longrightarrow \text{Join Workers}$$
- **Ingress Rejection**: Upon transition to `ServiceState::Draining`, `AuditServiceImpl` immediately rejects new `SubmitAuditEvent` and `BatchSubmitAuditEvents` calls with `grpc::StatusCode::UNAVAILABLE` ("Audit service is draining; retry via outbox buffer").

### D. Strict No-False-ACKs & Durability Contract Preservation (ADR-006, ADR-010)
- **Durability Guarantee**: Uncommitted events remaining in memory when `shutdown_grace_period_ms` (default: $5,000\text{ ms}$) expires are **never** acknowledged as successful (`success = true`).
- **NACK / Failure Explicit Messaging**: Pending batches that fail to flush before deadline expiration return explicit failure/UNAVAILABLE errors, instructing upstream Transactional Outbox relays to retain and retry events upon service recovery.

### E. Async-Signal-Safe Signal Handler & Thread-Safe CAS Teardown Orchestrator
- **Async-Signal-Safe Signal Handling**: `main.cpp` registers `SIGINT` and `SIGTERM` handlers that only modify a lock-free atomic flag `g_shutdown_requested` using `memory_order_release` / `memory_order_acquire` semantics, performing zero dynamic memory allocations, mutex locks, or I/O operations.
- **Idempotent Thread-Safe Teardown (`AuditServer::stop`)**: Uses `compare_exchange_strong` on internal atomic state (`ServiceState::Running` $\to$ `ServiceState::Draining`). Duplicate, repeated, or concurrent calls to `stop()` across multiple threads or from `~AuditServer()` return safely without redundant work, double-frees, or state corruption.

### F. Fail-Closed Health Configuration Binding & Docker Healthcheck Alignment
- **`HealthConfig` Schema**: Strongly typed struct exposed in `AuditConfig` controlling `probe_interval_ms` ($[100, 10000]$ ms), `probe_timeout_ms` ($[50, 5000]$ ms), `consecutive_failures_threshold` ($[1, 10]$), and `queue_high_water_pct` ($[50, 95]$).
- **Fail-Closed Validation**: Environment variable values (`SECURECLOUD_AUDIT_HEALTH_*` and `SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS`) out of allowed ranges fail fast at startup with descriptive error messages.
- **Docker Compose Compatibility**: Integrates seamlessly with standard gRPC health checks on port `50055` without modifying container topology.

---

## 3. Implementation Tickets & Traceability

| Ticket ID | Description & Focus | Primary Deliverables |
| :--- | :--- | :--- |
| **AUDIT-010-T01** | Asynchronous Dependency Prober & Health Evaluator | `health/audit_health_evaluator.{hpp,cpp}`, background thread polling, non-blocking atomic status reader |
| **AUDIT-010-T02** | Dynamic Readiness State Machine & Flapping Hysteresis | `lifecycle/audit_service_state.{hpp,cpp}`, $3$-failure degradation, $2$-success recovery, queue saturation threshold |
| **AUDIT-010-T03** | Multi-Phase Graceful Drain & Durability Contract | Multi-phase stop sequence in `AuditServer`, ingress rejection with `UNAVAILABLE` in `AuditServiceImpl`, deadline enforcement |
| **AUDIT-010-T04** | Idempotent Signal Handler & CAS Teardown Orchestrator | `SIGINT`/`SIGTERM` handler in `main.cpp`, thread-safe `compare_exchange_strong` state transition in `AuditServer::stop()` |
| **AUDIT-010-T05** | Configuration Binding & Fail-Closed Validation | `HealthConfig` struct in `audit_config.{hpp,cpp}`, canonical `SECURECLOUD_AUDIT_HEALTH_*` environment bindings |
| **AUDIT-010-T06** | Comprehensive Lifecycle, Degradation & Drain Test Suite | `tests/unit/audit/audit_health_evaluator_test.cpp`, `tests/integration/audit_graceful_shutdown_integration_test.cpp` |

---

## 4. Verification Evidence

### A. Unit Test Suite Execution (`securecloud_audit_health_evaluator_test`)
Execution of the unit test suite verifying initial startup probing, hysteresis degradation (3 failures), outage recovery (2 successes), queue saturation, and non-blocking probe execution:

```text
[==========] Running 5 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 5 tests from AuditHealthEvaluatorTest
[ RUN      ] AuditHealthEvaluatorTest.InitialStateIsNotReadyUntilEvaluationSucceeds
[       OK ] AuditHealthEvaluatorTest.InitialStateIsNotReadyUntilEvaluationSucceeds (0 ms)
[ RUN      ] AuditHealthEvaluatorTest.FlappingHysteresisRequiresThreeConsecutiveFailuresToDegrade
[       OK ] AuditHealthEvaluatorTest.FlappingHysteresisRequiresThreeConsecutiveFailuresToDegrade (0 ms)
[ RUN      ] AuditHealthEvaluatorTest.OutageRecoveryRequiresTwoConsecutiveSuccessesToRestore
[       OK ] AuditHealthEvaluatorTest.OutageRecoveryRequiresTwoConsecutiveSuccessesToRestore (0 ms)
[ RUN      ] AuditHealthEvaluatorTest.QueueSaturationThresholdTransitionsImmediately
[       OK ] AuditHealthEvaluatorTest.QueueSaturationThresholdTransitionsImmediately (0 ms)
[ RUN      ] AuditHealthEvaluatorTest.ProbeTimeoutDoesNotBlockConcurrentStatusQueries
[       OK ] AuditHealthEvaluatorTest.ProbeTimeoutDoesNotBlockConcurrentStatusQueries (201 ms)
[----------] 5 tests from AuditHealthEvaluatorTest (201 ms total)

[----------] Global test environment tear-down
[==========] 5 tests from 1 test suite ran. (201 ms total)
[  PASSED  ] 5 tests.
```

### B. Configuration Validation Suite (`securecloud_audit_config_test`)
Execution of configuration unit tests validating `HealthConfig` defaults, environment overrides, and fail-closed out-of-range parameter rejections:

```text
[==========] Running 11 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 11 tests from AuditConfigTest
[ RUN      ] AuditConfigTest.DefaultValuesAreValid
[       OK ] AuditConfigTest.DefaultValuesAreValid (0 ms)
[ RUN      ] AuditConfigTest.CompleteEnvironmentOverride
[       OK ] AuditConfigTest.CompleteEnvironmentOverride (0 ms)
[ RUN      ] AuditConfigTest.MissingRequiredPasswordFailsClosed
[       OK ] AuditConfigTest.MissingRequiredPasswordFailsClosed (0 ms)
[ RUN      ] AuditConfigTest.PortBoundaryValidation
[       OK ] AuditConfigTest.PortBoundaryValidation (0 ms)
[ RUN      ] AuditConfigTest.ReservedPortProhibition
[       OK ] AuditConfigTest.ReservedPortProhibition (0 ms)
[ RUN      ] AuditConfigTest.IngestionWorkerBounds
[       OK ] AuditConfigTest.IngestionWorkerBounds (0 ms)
[ RUN      ] AuditConfigTest.BatchSizeAndQueueBounds
[       OK ] AuditConfigTest.BatchSizeAndQueueBounds (0 ms)
[ RUN      ] AuditConfigTest.QueryLimitsValidation
[       OK ] AuditConfigTest.QueryLimitsValidation (0 ms)
[ RUN      ] AuditConfigTest.RetentionMonthsBounds
[       OK ] AuditConfigTest.RetentionMonthsBounds (0 ms)
[ RUN      ] AuditConfigTest.HealthConfigBoundaryValidation
[       OK ] AuditConfigTest.HealthConfigBoundaryValidation (0 ms)
[ RUN      ] AuditConfigTest.SecretRedactionVerification
[       OK ] AuditConfigTest.SecretRedactionVerification (0 ms)
[----------] 11 tests from AuditConfigTest (2 ms total)

[----------] Global test environment tear-down
[==========] 11 tests from 1 test suite ran. (2 ms total)
[  PASSED  ] 11 tests.
```

### C. Server Stop Idempotency Suite (`securecloud_audit_server_stop_test`)
Execution of concurrent multi-threaded `stop()` invocation tests verifying CAS state machine safety:

```text
[==========] Running 1 test from 1 test suite.
[----------] Global test environment set-up.
[----------] 1 test from AuditServerStopTest
[ RUN      ] AuditServerStopTest.StopIsIdempotentAndThreadSafe
[       OK ] AuditServerStopTest.StopIsIdempotentAndThreadSafe (1 ms)
[----------] 1 test from AuditServerStopTest (1 ms total)

[----------] Global test environment tear-down
[==========] 1 test from 1 test suite ran. (1 ms total)
[  PASSED  ] 1 test.
```

### D. Integration & Graceful Shutdown Suite (`securecloud_audit_graceful_shutdown_integration_test`)
Execution of end-to-end integration tests verifying readiness withdrawal, ingress rejection, batch flush, drain deadline enforcement, and 10-thread concurrent shutdown safety:

```text
[==========] Running 5 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 5 tests from AuditGracefulShutdownIntegrationTest
[ RUN      ] AuditGracefulShutdownIntegrationTest.ReadinessWithdrawsImmediatelyOnShutdown
[       OK ] AuditGracefulShutdownIntegrationTest.ReadinessWithdrawsImmediatelyOnShutdown (0 ms)
[ RUN      ] AuditGracefulShutdownIntegrationTest.IngressRejectedWithUnavailableDuringDrain
[       OK ] AuditGracefulShutdownIntegrationTest.IngressRejectedWithUnavailableDuringDrain (0 ms)
[ RUN      ] AuditGracefulShutdownIntegrationTest.InFlightBatchesFlushedBeforeShutdownTerminates
[       OK ] AuditGracefulShutdownIntegrationTest.InFlightBatchesFlushedBeforeShutdownTerminates (12 ms)
[ RUN      ] AuditGracefulShutdownIntegrationTest.DeadlineExpirationPreventsFalseACKs
[       OK ] AuditGracefulShutdownIntegrationTest.DeadlineExpirationPreventsFalseACKs (514 ms)
[ RUN      ] AuditGracefulShutdownIntegrationTest.ConcurrentStopCallsAreThreadSafeAndIdempotent
[       OK ] AuditGracefulShutdownIntegrationTest.ConcurrentStopCallsAreThreadSafeAndIdempotent (1 ms)
[----------] 5 tests from AuditGracefulShutdownIntegrationTest (574 ms total)

[----------] Global test environment tear-down
[==========] 5 tests from 1 test suite ran. (585 ms total)
[  PASSED  ] 5 tests.
```

---

## 5. Security & Operational Readiness

- [x] Liveness and readiness strictly decoupled per ADR-009; ClickHouse downtime degrades readiness only, preventing container restart loops.
- [x] Non-blocking health checks ensure gRPC health queries never block on slow database pings or thread starvation.
- [x] Flapping defense hysteresis requires 3 consecutive failures to degrade readiness and 2 successes to restore.
- [x] Graceful drain guarantees zero false ACKs: uncommitted events on deadline expiration return explicit errors/NACKs.
- [x] Signal handling (`SIGINT`/`SIGTERM`) is async-signal-safe with zero dynamic allocations or I/O.
- [x] `AuditServer::stop()` uses `compare_exchange_strong` CAS atomic state transitions, guaranteeing thread safety and idempotency under concurrent invocations.
- [x] Strongly typed `HealthConfig` parameters validated fail-closed at startup.
- [x] All 100% test targets passing cleanly under GCC/MinGW C++20 with strict `-Wall -Wextra -Werror -Wpedantic` flags.