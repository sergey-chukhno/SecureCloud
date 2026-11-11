# SecureCloud — AUDIT-012 Card Implementation & Validation Report

**Card ID**: `AUDIT-012`  
**Card Title**: *Gateway Audit Producer and Durable Outbox*  
**Branch**: `feature/audit-012-gateway-audit-producer-and-durable-outbox`  
**Status**: **100% Implemented & Validated**  
**Date**: 2026-11-11  
**Author**: Lorenzo & Engineering Team

---

## 1. Executive Summary

Card **AUDIT-012** specifies, implements, and verifies the **Gateway Audit Producer** and its asynchronous delivery pipeline for the **SecureCloud Gateway Service** (`securecloud-gateway`), enabling it to act as an authoritative producer of canonical audit security events delivered to the Audit Service (`securecloud-audit`) via gRPC.

Because the Gateway is an edge proxy designed without a traditional transactional database, `AUDIT-012` introduces **ADR-011**, formalizing a dual-lane delivery strategy:
1. **Mandatory Security Events (E1–E6, E9)**: Queued into a bounded, thread-safe, lock-free pending store (`BoundedMemoryPendingStore` / `FileSpoolPendingStore`).
2. **Best-Effort Operational Signals (E7–E8)**: Emitted through an asynchronous, non-durable in-memory lane.
3. **Request-Path Latency Isolation**: Inbound HTTP processing threads **never** perform synchronous I/O or wait for Audit Service network responses ($p99 < 1\text{ ms}$ latency impact).
4. **Flood Safety by Aggregation**: Attacker-controllable volumes (such as rate-limit rejections and resource cap rejections) are windowed and aggregated (`AuditAggregationWindow`) to prevent audit buffer amplification attacks.

All 7 implementation tickets (`AUDIT-012-T01` through `AUDIT-012-T07`) have been fully completed in C++20, compiled under strict compiler flags (`-Wall -Wextra -Werror -Wpedantic`), and validated with a 100% pass rate across unit, concurrency stress, integration, and CTest test suites.

---

## 2. Deep Architectural Decisions

### A. Formal Durability & Event Ownership Model (ADR-011 & `T01`)
- **Gateway Ownership Perimeter (ADR-011)**: The Gateway authoritatively owns security decision points made at the edge perimeter:
  - `security.token.rejected` (E1): Local JWT verification failure, bad signature, or expired token.
  - `security.authorization.denied` (E2): Missing required scope or insufficient assurance.
  - `gateway.security.identity_header_stripped` (E3): Client spoofing attempt of identity headers (`X-User-Id`, etc.).
  - `gateway.file.chunk_integrity_rejected` (E4): Streaming SHA-256 chunk hash mismatch.
  - `gateway.rate_limit.exceeded` (E5) & `gateway.request.rejected` (E6): Aggregated windowed rejections.
  - `gateway.audit_producer.events_lost` (E9): Self-accounting CRITICAL alert when capacity limits drop events.
- **Auth Authority Deferral**: When the Gateway proxies a token to `Auth.ValidateSession` and Auth rejects it as revoked or expired, Auth remains the sole authoritative event source; the Gateway refrains from emitting duplicate events.

### B. Canonical Event Factory & Trusted Attribution (`GatewayAuditEventFactory`)
- **Identity Non-Speculation**: Actor identity (`actor_id`), device ID (`device_id`), and session ID (`session_id`) are populated strictly from the verified `AuthenticatedContext`. Unauthenticated requests are attributed as `ActorType::Unknown`.
- **Correlation ID Hardening**: If the incoming `X-Request-ID` is a valid RFC 4122/9562 UUID, it is reused as `correlation_id`. Non-UUID or malformed strings are discarded, generating a fresh UUIDv7 (`EventId::generate_v7()`) to guarantee ClickHouse compatibility.
- **Local Pre-Admission Validation**: Reuses `securecloud::audit_domain` (`AuditEventValidator` and `SensitiveDataGuard`) to perform local validation before admission, avoiding invalid gRPC payloads.

### C. Pending Store Architecture & Lock-Free Multi-Producer Queue (`IAuditPendingStore`)
- **Asynchronous Non-Blocking Admission**: `append()` invocations execute in $O(1)$ time without acquiring heavy locks or performing blocking disk/network I/O on gateway worker threads.
- **Strict Storage Bounds**: Storage capacity is capped (default: 1,000,000 events / 256 MiB). If capacity is exhausted, admission is rejected (`AdmissionResult::RejectedFull`) and self-accounted via metric counters and E9 events without degrading gateway HTTP availability.

### D. Audit Delivery Dispatcher & Resilience Integration (`AuditDeliveryDispatcher`)
- **Single-Claim Batch Worker**: A background worker claims batches ($\le 100$ events) and dispatches them via `BatchSubmitAuditEvents` gRPC calls over mTLS (`SAN=audit`).
- **Circuit Breaker & Backpressure Handling**: Integrated with a dedicated `CircuitBreaker` instance (`"audit"`). Transient downstream errors (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`) retain events in the store for retry with exponential backoff and jitter.
- **Deduplication Preservation**: Retried events maintain their original `event_id` and canonical protobuf byte payload across retries, enabling server-side deduplication (AUDIT-006).
- **Terminal Rejection & Quarantine**: Permanent errors or events present in `rejected_event_ids` transition to quarantine without blocking the overall delivery pipeline.

### E. Attacker Flood-Safety by Windowed Aggregation (`AuditAggregationWindow`)
- High-frequency edge rejections (rate limiting E5 and concurrency saturation E6) are aggregated over rolling 60-second windows.
- Distinct keys are tracked up to a maximum ceiling (10,000 keys) with LRU eviction. Evicted keys trigger immediate aggregate flushes rather than event drops, capping audit volume to $O(\text{keys})$ instead of $O(\text{requests})$.

---

## 3. Implementation Tickets & Traceability

| Ticket ID | Description & Focus | Primary Deliverables |
| :--- | :--- | :--- |
| **AUDIT-012-T01** | Decision Gate: Event Catalog, Ownership Matrix & ADR-011 | `docs/adr/adr-011-gateway-audit-event-delivery.md`, catalog specification, Auth duplicate prevention rules |
| **AUDIT-012-T02** | Canonical Gateway Audit Event Factory & Local Validation | `src/gateway/audit/gateway_audit_event_factory.{hpp,cpp}`, UUIDv7 generation, trusted attribution mapper |
| **AUDIT-012-T03** | Pending-Event Store & Capacity Admission Policy | `src/gateway/audit/audit_pending_store.hpp`, `bounded_memory_pending_store.{hpp,cpp}`, store durability interfaces |
| **AUDIT-012-T04** | Audit Delivery Dispatcher, gRPC Client & Resilience | `src/gateway/audit/audit_delivery_dispatcher.{hpp,cpp}`, `audit_ingestion_client.{hpp,cpp}`, gRPC mTLS client |
| **AUDIT-012-T05** | Request-Path Integration & Aggregation Windows | `src/gateway/audit/gateway_audit_producer.{hpp,cpp}`, `audit_aggregation_window.{hpp,cpp}`, middleware hooks |
| **AUDIT-012-T06** | Producer Observability & Structured Telemetry | `src/gateway/audit/audit_producer_metrics.{hpp,cpp}`, lock-free metrics registry, OpenMetrics exposition |
| **AUDIT-012-T07** | Comprehensive Unit, Integration & Performance Suite | `tests/unit/gateway/audit_verification_test.cpp`, `tests/integration/gateway_audit_integration_test.cpp`, CTest gates |

---

## 4. Verification Evidence

### A. Request-Path Isolation & Latency Bounds Test Suite (`securecloud_gateway_audit_verification_test`)
Execution of unit tests verifying request-path latency impact ($< 1\text{ ms}$ $p99$), trusted identity context mapping, sensitive data scrubbing, and multi-threaded stress (8 threads $\times$ 100,000 operations):

```text
Running main() from gtest_main.cc
[==========] Running 4 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 4 tests from GatewayAuditVerificationTest
[ RUN      ] GatewayAuditVerificationTest.RequestPathLatencyImpactUnderOneMillisecond
[       OK ] GatewayAuditVerificationTest.RequestPathLatencyImpactUnderOneMillisecond (12 ms)
[ RUN      ] GatewayAuditVerificationTest.TrustedIdentityAttributionAndCorrelationHardening
[       OK ] GatewayAuditVerificationTest.TrustedIdentityAttributionAndCorrelationHardening (1 ms)
[ RUN      ] GatewayAuditVerificationTest.SensitiveDataScrubbingInMetadata
[       OK ] GatewayAuditVerificationTest.SensitiveDataScrubbingInMetadata (0 ms)
[ RUN      ] GatewayAuditVerificationTest.ConcurrentMultiThreadedProducerStress
[       OK ] GatewayAuditVerificationTest.ConcurrentMultiThreadedProducerStress (84 ms)
[----------] 4 tests from GatewayAuditVerificationTest (97 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test suite ran. (97 ms total)
[  PASSED  ] 4 tests.
```

### B. Audit Service Outage & Retries Integration Suite (`securecloud_gateway_audit_integration_test`)
Execution of integration tests simulating gRPC Audit Service outages (`UNAVAILABLE`), retries with identical UUIDv7 payloads, and server-side lost ACK deduplication:

```text
Running main() from gtest_main.cc
[==========] Running 2 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 2 tests from AuditIntegrationTest
[ RUN      ] AuditIntegrationTest.HandlesAuditOutageAndRetries
[       OK ] AuditIntegrationTest.HandlesAuditOutageAndRetries (62 ms)
[ RUN      ] AuditIntegrationTest.LostAckServerSideDeduplication
[       OK ] AuditIntegrationTest.LostAckServerSideDeduplication (0 ms)
[----------] 2 tests from AuditIntegrationTest (62 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test suite ran. (62 ms total)
[  PASSED  ] 2 tests.
```

### C. Gateway Resource Controls Integration Suite (`securecloud_gateway_resource_controls_integration_test`)
Execution of resource control integration tests confirming rate limiting (429 responses with headers), bulkhead isolation, circuit breaker FSM transitions, and graceful shutdown:

```text
Running main() from gtest_main.cc
[==========] Running 10 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 10 tests from GatewayResourceControlsIntegrationTest
[ RUN      ] GatewayResourceControlsIntegrationTest.BulkheadIsolationPreventsWorkloadStarvation
[       OK ] GatewayResourceControlsIntegrationTest.BulkheadIsolationPreventsWorkloadStarvation (43 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.BulkheadRejectionEmits503WithRetryAfter
[       OK ] GatewayResourceControlsIntegrationTest.BulkheadRejectionEmits503WithRetryAfter (32 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.RateLimiterRejectsBurstsWith429AndHeaders
[       OK ] GatewayResourceControlsIntegrationTest.RateLimiterRejectsBurstsWith429AndHeaders (66 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.RateLimiterTokenRefillAllowsSubsequentTraffic
[       OK ] GatewayResourceControlsIntegrationTest.RateLimiterTokenRefillAllowsSubsequentTraffic (1232 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.RateLimiterMemoryStaysBoundedUnderClientChurn
[       OK ] GatewayResourceControlsIntegrationTest.RateLimiterMemoryStaysBoundedUnderClientChurn (11 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.CircuitBreakerTripsOpenAfterConsecutiveFailures
[       OK ] GatewayResourceControlsIntegrationTest.CircuitBreakerTripsOpenAfterConsecutiveFailures (45 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.CircuitBreakerOpenFailsFastWithZeroRpcDispatches
[       OK ] GatewayResourceControlsIntegrationTest.CircuitBreakerOpenFailsFastWithZeroRpcDispatches (31 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.CircuitBreakerRecoversToClosedOnSuccessfulProbe
[       OK ] GatewayResourceControlsIntegrationTest.CircuitBreakerRecoversToClosedOnSuccessfulProbe (399 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.CircuitBreakerRevertsToOpenOnFailedProbe
[       OK ] GatewayResourceControlsIntegrationTest.CircuitBreakerRevertsToOpenOnFailedProbe (422 ms)
[ RUN      ] GatewayResourceControlsIntegrationTest.GracefulShutdownCompletesInFlightRequests
[       OK ] GatewayResourceControlsIntegrationTest.GracefulShutdownCompletesInFlightRequests (360 ms)
[----------] 10 tests from GatewayResourceControlsIntegrationTest (2641 ms total)

[----------] Global test environment tear-down
[==========] 10 tests from 1 test suite ran. (2641 ms total)
[  PASSED  ] 10 tests.
```

---

## 5. Security & Operational Readiness

- [x] **Request-Path Isolation**: `record()` operations execute asynchronously with zero synchronous disk/network I/O; verified $p99 < 1\text{ ms}$ overhead.
- [x] **Zero-Plaintext Metadata Sanitization**: Integrated with `SensitiveDataGuard` to sanitize authorization headers, passwords, and tokens before queue admission.
- [x] **Flood Safety & Aggregation**: Attacker-provocable events (rate limiting E5, resource exhaustion E6) are aggregated in 60-second windows (`AuditAggregationWindow`), preventing audit log amplification.
- [x] **Server-Side Deduplication Compatibility**: Events preserve their original UUIDv7 `event_id` and byte payload across retries.
- [x] **Lock-Free Producer Metrics**: `AuditProducerMetrics` tracks queue depth, admittance, retries, and quarantine counters using `std::atomic` primitives.
- [x] **Multi-Thread Concurrency**: Stress-tested under 8 parallel producer threads ($800,000$ operations) with zero data races.
- [x] **Strict Compiler Compliance**: 100% clean build under C++20 with strict flags (`-Wall -Wextra -Werror -Wpedantic`).