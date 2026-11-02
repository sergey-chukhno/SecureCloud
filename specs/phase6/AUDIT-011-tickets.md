# AUDIT-011 — Ingestion Metrics and Diagnostics
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: `AUDIT-011`  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: November 2, 2026  
**Dependencies**: `AUDIT-002` (Canonical Event Model & Validator), `AUDIT-003` (ClickHouse Schema & Repository), `AUDIT-004` (Authenticated gRPC Ingestion Contract), `AUDIT-005` (Bounded Asynchronous Ingestion & Batch Persistence), `AUDIT-006` (Event Deduplication & Retry-Safe Acknowledgements), `AUDIT-010` (Readiness, Health Checks & Graceful Shutdown)  
**Related ADRs**: `ADR-005` (Internal Network Isolation & mTLS 1.3), `ADR-006` (Canonical Audit Event Schema), `ADR-008` (Zero-Plaintext & Content Confidentiality), `ADR-009` (Service Lifecycle & Failure Isolation), `ADR-010` (Bounded Resource Allocation & Overload Defense)

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-011** specifies and implements production-grade, low-overhead **operational metrics** and **structured diagnostic logging** for the **SecureCloud Audit Service** (`securecloud-audit`).

As the centralized compliance and security backbone of SecureCloud, the Audit Service processes high-velocity telemetry from all microservices (Gateway, Auth, Messaging, Files). To ensure the service operates within its provisioned capacity and to detect ingestion bottlenecks or persistence failures before data loss occurs, operators and automated monitors must have real-time visibility into:
1. **Ingestion Volume & Rejection Rates**: Distinguishing gRPC request-level counts from event-level counts, tracking valid admissions, schema rejections, and duplicate drops.
2. **Queue Dynamics & Backpressure**: Tracking bounded ingestion queue depth, high-water saturation, drop counts, and batch formation triggers (count vs. timer flushes).
3. **ClickHouse Persistence Latencies**: Measuring insertion durations, batch sizes, retry counts, bulkhead semaphore saturation, and transient vs. sustained storage outages.
4. **Zero-PII Structured Diagnostics**: Correlating operational logs with correlation IDs and health states without leaking passwords, tokens, encryption keys, or payload contents.

### Core Architectural Invariants for AUDIT-011

1. **Lock-Free, Zero-Contention Hot Path (ADR-010)**:
   Metric recording on the ingestion hot path must use purely lock-free atomic primitives (`std::atomic`). Updating counters, gauges, or latency histograms must never acquire mutexes, execute heap allocations, or block calling gRPC threads.
2. **Strictly Bounded Label Cardinality**:
   Metric labels are strictly confined to small, closed enumerations (e.g. `producer="gateway|auth|messaging|files|audit"`, `status="success|rejected"`, `reason="clock_skew|sensitive_data"`). Dynamic identifiers—such as `event_id`, `user_id`, `device_id`, `correlation_id`, IP addresses, or arbitrary payload keys—are **strictly prohibited** from metric label dimensions to prevent unbounded memory growth.
3. **Zero-Plaintext & Content Confidentiality (ADR-008)**:
   Under no circumstances may passwords, password hashes, access/refresh tokens, private keys, plaintext message bodies, or file contents appear in metric names, label values, or structured diagnostic log messages.
4. **No Heavy External Infrastructure Dependencies**:
   This card must not introduce external monitoring infrastructure (e.g. Prometheus Server, Grafana, OpenTelemetry Collector daemons). The service maintains a lightweight in-process collector exposing standard OpenMetrics / Prometheus text exposition (`/metrics` or internal gRPC query), accessible strictly on the internal microservice network.
5. **Decoupled Telemetry (Never a Hard Dependency)**:
   Telemetry failure, metric formatting errors, or scraping timeouts must never stall, degrade, or reject audit event ingestion.

---

## 2. Ingestion & Persistence Telemetry Pipeline

```text
                                INGESTION & TELEMETRY FLOW

   Incoming gRPC RPC
  (SubmitEvent / Batch)
           │
           ├──► [Metric] audit_ingestion_requests_total{rpc="...", status="..."}
           ▼
   ┌───────────────┐
   │ mTLS & Auth   │ ──► [Metric] audit_rejected_events_total{reason="unauthenticated|producer_mismatch"}
   └───────┬───────┘
           │ (Valid Identity)
           ▼
   ┌───────────────┐
   │ Event Model   │ ──► [Metric] audit_ingested_events_total{producer="...", severity="..."}
   │ & Validation  │ ──► [Metric] audit_rejected_events_total{reason="sensitive_data|clock_skew|malformed"}
   └───────┬───────┘
           │ (Valid Event)
           ▼
   ┌───────────────┐
   │ Deduplication │ ──► [Metric] audit_duplicate_events_total{producer="..."} (AUDIT-006)
   └───────┬───────┘
           │ (Unique Event)
           ▼
   ┌───────────────┐
   │ Bounded Queue │ ──► [Gauge]  audit_queue_depth
   │  (Cap: 10k)   │ ──► [Gauge]  audit_queue_capacity
   └───────┬───────┘ ──► [Metric] audit_queue_saturated_drops_total (on backpressure drop)
           │
           ▼
   ┌───────────────┐
   │ Batch         │ ──► [Metric] audit_batch_flush_total{trigger="count|timer|shutdown"}
   │ Aggregator    │ ──► [Hist]   audit_batch_size_events (1 to 1,000)
   └───────┬───────┘
           │
           ▼
   ┌───────────────┐
   │ ClickHouse    │ ──► [Hist]   audit_clickhouse_insert_duration_seconds
   │ Bulk Inserter │ ──► [Metric] audit_clickhouse_insert_operations_total{outcome="success|failure|timeout"}
   └───────┬───────┘ ──► [Metric] audit_clickhouse_retries_total / bulkhead_rejections
           │
           ▼
   ┌───────────────┐
   │ Persistence   │ ──► [Metric] audit_persisted_events_total{producer="..."}
   │ Ack Manager   │ ──► [Metric] audit_persisted_batches_total
   └───────────────┘
```

---

## 3. Comprehensive Metric Inventory & Specifications

### A. Ingestion Request & Event Counters

| Metric Identifier | Type | Labels | Units | Architectural Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `audit_ingestion_requests_total` | Counter | `rpc`, `status` | requests | Measures RPC call volume and high-level success/error distribution. |
| `audit_ingested_events_total` | Counter | `producer`, `severity` | events | Tracks raw event ingress rate broken down by producer microservice and severity. |
| `audit_rejected_events_total` | Counter | `reason` | events | Measures event admission rejections by failure category (`sensitive_data`, `clock_skew`, etc.). |
| `audit_duplicate_events_total` | Counter | `producer` | events | Tracks deduplicated events detected by cache/bloom filters (AUDIT-006). |
| `audit_persisted_events_total` | Counter | `producer` | events | Authoritative count of events confirmed committed to ClickHouse storage. |
| `audit_persisted_batches_total`| Counter | `outcome` | batches | Total bulk batch insertion operations completed against ClickHouse. |

### B. Ingestion Queue & Worker Dynamics

| Metric Identifier | Type | Labels | Units | Architectural Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `audit_queue_depth` | Gauge | *none* | events | Instantaneous count of events residing in the in-memory bounded queue. |
| `audit_queue_capacity` | Gauge | *none* | events | Static configured hard ceiling (e.g. `10,000`). |
| `audit_queue_saturated_drops_total` | Counter | `producer` | events | Total events discarded or rejected due to queue saturation backpressure. |
| `audit_queue_wait_duration_seconds` | Histogram | *none* | seconds | Time an accepted event spends waiting in the queue before batching. |
| `audit_batch_flush_total` | Counter | `trigger` | flushes | Count of flushes triggered by `count` ($\ge 1000$), `timer` ($100\text{ ms}$), or `shutdown`. |
| `audit_batch_size_events` | Histogram | *none* | events | Distribution of event counts aggregated into ClickHouse insertion batches. |
| `audit_workers_active` | Gauge | `pool` | workers | Active threads in `validation` and `insertion` worker threadpools. |
| `audit_service_draining` | Gauge | *none* | boolean | Set to `1` when shutdown drain sequence is initiated; `0` during normal runtime. |

### C. ClickHouse Persistence & Storage Health

| Metric Identifier | Type | Labels | Units | Architectural Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `audit_clickhouse_insert_duration_seconds` | Histogram | *none* | seconds | End-to-end latency of ClickHouse HTTP bulk insert requests. |
| `audit_clickhouse_insert_operations_total` | Counter | `outcome` | operations | Count of ClickHouse bulk operations by result (`success`, `failure`, `timeout`). |
| `audit_clickhouse_retries_total` | Counter | *none* | retries | Number of retry attempts executed under transient ClickHouse failures. |
| `audit_clickhouse_bulkhead_rejections_total` | Counter | *none* | rejections | Number of insert operations rejected immediately by semaphore bulkhead. |
| `audit_clickhouse_available` | Gauge | *none* | boolean | Binary reachability status (`1` = healthy, `0` = degraded) from `AuditHealthEvaluator`. |

---

## 4. Closed Label Enumerations & Cardinality Bounds

To guarantee $O(1)$ memory consumption and zero memory leakage over unbounded operational runtimes, labels are strictly bounded to the following closed sets:

- **`rpc`**: `SubmitAuditEvent`, `BatchSubmitAuditEvents`
- **`status`**: `success`, `error`, `rejected`
- **`producer`**: `gateway`, `auth`, `messaging`, `files`, `audit`, `unknown`
- **`severity`**: `info`, `warning`, `security`, `critical`
- **`reason`**: `unauthenticated`, `producer_mismatch`, `sensitive_data`, `clock_skew`, `malformed_uuid`, `oversized_payload`, `oversized_batch`, `queue_saturated`
- **`trigger`**: `count`, `timer`, `shutdown`
- **`outcome`**: `success`, `failure`, `timeout`
- **`pool`**: `validation`, `insertion`

---

## 5. Implementation Tickets for Developer Lorenzo

```text
               AUDIT-002 (Canonical Model)
               AUDIT-003 (ClickHouse Repository)
               AUDIT-004 (gRPC Ingestion)
               AUDIT-005 (Bounded Ingestion Queue)
               AUDIT-006 (Deduplication Engine)
               AUDIT-010 (Readiness & Lifecycle)
                             │
                             ▼
                       AUDIT-011-T01
             (Bounded Metric Registry, Lock-Free
              Primitives & OpenMetrics Formatter)
                             │
                             ▼
                       AUDIT-011-T02
             (Ingestion Pipeline & RPC Call Accounting
              Instrumentation)
                             │
                             ▼
                       AUDIT-011-T03
             (Queue Dynamics, Worker Concurrency &
              Batch Formation Telemetry)
                             │
                             ▼
                       AUDIT-011-T04
             (ClickHouse Persistence Performance &
              Storage Latency Histograms)
                             │
                             ▼
                       AUDIT-011-T05
             (Structured Operational Diagnostics &
              Readiness State Correlation)
                             │
                             ▼
                       AUDIT-011-T06
             (Exposition Endpoint, Concurrency, Load
              & Zero-PII Verification Suite)
```

---

### AUDIT-011-T01: Bounded Metric Registry, Lock-Free Primitives & OpenMetrics Formatter

1. **Ticket ID**: `AUDIT-011-T01`
2. **Title**: Bounded Metric Registry, Lock-Free Primitives & OpenMetrics Formatter
3. **Objective**: Implement `AuditMetrics`, a high-performance, thread-safe, lock-free telemetry collector using pure atomic variables and fixed histogram buckets, capable of rendering standard OpenMetrics / Prometheus text output.
4. **Scope & Technical Requirements**:
   - Create `src/audit/telemetry/audit_metrics.hpp` and `.cpp`.
   - Implement singleton / shared instance `AuditMetrics`:
     - Lock-free atomic storage for counters and gauges using `std::atomic<uint64_t>` and `std::atomic<int64_t>`.
     - Static array dimensions for all bounded label combinations (zero dynamic string allocations during recording).
     - Fixed histogram buckets for latency:
       - Persistence & Queue Latency: `[0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0]` seconds.
       - Batch Size: `[1, 10, 50, 100, 250, 500, 750, 1000]` events.
   - Implement `std::string to_prometheus_text() const`:
     - Renders standard `# HELP`, `# TYPE`, and sample lines according to OpenMetrics 1.0 specifications.
   - Implement `void reset() noexcept` for test isolation.
5. **Architectural Constraints**:
   - Updates must use `std::memory_order_relaxed` to minimize cache synchronization overhead on multi-core architectures.
   - Zero heap allocation during counter/gauge increments and histogram observations.
6. **Acceptance Criteria**:
   - `to_prometheus_text()` formats all metrics cleanly adhering to Prometheus text exposition format.
   - `reset()` restores all internal counters, gauges, and histogram buckets to zero.
7. **Dependencies**: `securecloud::common`.

---

### AUDIT-011-T02: Ingestion Pipeline & RPC Call Accounting Instrumentation

1. **Ticket ID**: `AUDIT-011-T02`
2. **Title**: Ingestion Pipeline & RPC Call Accounting Instrumentation
3. **Objective**: Instrument `AuditServiceImpl` and validation layers to record request-level and event-level counts, admission rejections, and duplicate tracking.
4. **Scope & Technical Requirements**:
   - Update `src/audit/service/audit_service_impl.cpp`:
     - Increment `audit_ingestion_requests_total` on every incoming `SubmitAuditEvent` and `BatchSubmitAuditEvents` call with appropriate status.
     - Record `audit_ingested_events_total` for each valid event parsed from the payload, attributed to verified producer and severity.
     - Record `audit_rejected_events_total` when mTLS identity check fails (`unauthenticated`, `producer_mismatch`) or payload validation fails (`sensitive_data`, `clock_skew`, `malformed_uuid`, `oversized_batch`).
   - Integrate with Deduplication Engine (AUDIT-006):
     - Increment `audit_duplicate_events_total` when an incoming event ID has already been persisted or is currently in flight.
5. **Architectural Constraints**:
   - Distinct separation between RPC requests (1 request may contain 100 events) and individual audit events.
   - Producer attribution must use verified transport peer identity where available, falling back to `"unknown"`.
6. **Acceptance Criteria**:
   - Submitting a batch of 50 events increments requests by 1 and ingested events by 50.
   - Rejecting an invalid event increments `audit_rejected_events_total` with the exact corresponding reason label.
7. **Dependencies**: `AUDIT-011-T01`, `AUDIT-004-T04`.

---

### AUDIT-011-T03: Queue Dynamics, Worker Concurrency & Batch Formation Telemetry

1. **Ticket ID**: `AUDIT-011-T03`
2. **Title**: Queue Dynamics, Worker Concurrency & Batch Formation Telemetry
3. **Objective**: Instrument `BoundedIngestionQueue` and `BatchAggregator` (AUDIT-005) to track queue occupancy, saturation drops, worker thread utilization, and batch flush triggers.
4. **Scope & Technical Requirements**:
   - Update `src/audit/ingestion/bounded_ingestion_queue.cpp` (AUDIT-005):
     - Update gauge `audit_queue_depth` on enqueue and dequeue.
     - Static gauge `audit_queue_capacity` initialized from `config.ingestion.max_queued_events`.
     - Increment `audit_queue_saturated_drops_total` whenever `try_enqueue` fails due to capacity limits.
     - Observe `audit_queue_wait_duration_seconds` when an event is popped by an insertion worker.
   - Update `src/audit/ingestion/batch_aggregator.cpp` (AUDIT-005):
     - Increment `audit_batch_flush_total` with label `trigger="count"`, `trigger="timer"`, or `trigger="shutdown"`.
     - Observe `audit_batch_size_events` with the count of events in each constructed batch.
   - Update worker pool threads:
     - Update gauge `audit_workers_active{pool="validation"}` and `{pool="insertion"}`.
5. **Architectural Constraints**:
   - Atomic gauge updates must be $O(1)$ and never lock the bounded queue condition variable.
6. **Acceptance Criteria**:
   - When queue depth reaches high-water mark, queue depth gauge matches actual pending count.
   - Flushes triggered by timer vs. batch size are accurately distinguished in metrics.
7. **Dependencies**: `AUDIT-011-T01`, `AUDIT-005-T01`, `AUDIT-005-T03`.

---

### AUDIT-011-T04: ClickHouse Persistence Performance & Storage Latency Histograms

1. **Ticket ID**: `AUDIT-011-T04`
2. **Title**: ClickHouse Persistence Performance & Storage Latency Histograms
3. **Objective**: Instrument `ClickHouseAuditEventRepository` and `RepositoryResilience` to measure ClickHouse bulk insert latency, success/failure counts, bulkhead semaphore rejections, and retry attempts.
4. **Scope & Technical Requirements**:
   - Update `src/audit/repository/clickhouse_audit_event_repository.cpp`:
     - Measure duration of `insert_batch` calls and observe `audit_clickhouse_insert_duration_seconds`.
     - Increment `audit_clickhouse_insert_operations_total` with `outcome="success"`, `outcome="failure"`, or `outcome="timeout"`.
     - On successful persistence, increment `audit_persisted_events_total` by the batch size and `audit_persisted_batches_total` by 1.
   - Update `src/audit/repository/repository_resilience.hpp`:
     - Increment `audit_clickhouse_retries_total` on retry backoff execution.
     - Increment `audit_clickhouse_bulkhead_rejections_total` when semaphore acquisition times out.
   - Update `AuditHealthEvaluator` (AUDIT-010):
     - Update gauge `audit_clickhouse_available` (`1` or `0`) based on periodic ping outcomes.
5. **Architectural Constraints**:
   - Nanosecond/microsecond timing via `std::chrono::steady_clock`.
   - Never log or capture ClickHouse authentication passwords in error telemetry.
6. **Acceptance Criteria**:
   - Successful insert operations record accurate latency in histogram buckets.
   - Network drop or HTTP 500 increments failure counter and triggers retry metric increment.
7. **Dependencies**: `AUDIT-011-T01`, `AUDIT-003-T04`, `AUDIT-003-T05`.

---

### AUDIT-011-T05: Structured Operational Diagnostics & Readiness State Correlation

1. **Ticket ID**: `AUDIT-011-T05`
2. **Title**: Structured Operational Diagnostics & Readiness State Correlation
3. **Objective**: Implement structured diagnostic logging for significant ingestion, queue, and persistence events, correlating them with correlation IDs and health states while enforcing strict zero-sensitive-data scrubbing.
4. **Scope & Technical Requirements**:
   - Create `src/audit/telemetry/audit_diagnostics.hpp` and `.cpp`.
   - Provide structured diagnostic logging helpers:
     ```cpp
     void log_ingestion_rejection(std::string_view reason,
                                 std::string_view producer,
                                 std::string_view rpc_method,
                                 const std::optional<std::string>& correlation_id,
                                 std::string_view sanitized_detail) noexcept;

     void log_persistence_failure(std::string_view error_code,
                                 size_t batch_size,
                                 std::string_view sanitized_error,
                                 uint32_t retry_attempt) noexcept;

     void log_queue_saturation(size_t current_depth,
                              size_t capacity,
                              std::string_view producer) noexcept;
     ```
   - Diagnostic Sanitization Engine:
     - Scrub all diagnostic strings using `SensitiveDataGuard` patterns before formatting.
     - Prefix log entries with standard ISO-8601 UTC timestamp, `[SecureCloud] [audit]`, severity level, and component tag.
     - Include current `DetailedServiceState` from AUDIT-010.
5. **Architectural Constraints**:
   - Never log raw payloads, tokens, passwords, authorization headers, or private keys.
   - Rate-limit diagnostic error logs to prevent log flooding during sustained downstream outages.
6. **Acceptance Criteria**:
   - Structured logs contain correlation IDs when available without leaking user PII or sensitive keys.
   - Log flooding protection limits repetitive failure logs to at most 1 per second per error category.
7. **Dependencies**: `AUDIT-002-T03`, `AUDIT-010-T02`.

---

### AUDIT-011-T06: Exposition Endpoint, Concurrency, Load & Zero-PII Verification Suite

1. **Ticket ID**: `AUDIT-011-T06`
2. **Title**: Exposition Endpoint, Concurrency, Load & Zero-PII Verification Suite
3. **Objective**: Implement the internal metrics exposition endpoint and construct comprehensive unit, multi-threaded concurrency, stress, and security negative verification suites.
4. **Scope & Technical Requirements**:
   - Metrics Exposure Mechanism:
     - Expose metrics over internal gRPC service or internal HTTP endpoint (e.g. port 50055/metrics or dedicated loopback port), strictly bound to internal interface.
   - Create `tests/unit/audit/audit_metrics_test.cpp`:
     - **Test 1: Counter & Gauge Accuracy**: Verify increment, decrement, and set operations across all defined metrics.
     - **Test 2: Latency & Batch Size Histogram Bucket Accumulation**: Verify samples correctly distribute into exponential buckets.
     - **Test 3: OpenMetrics Text Formatting Fidelity**: Verify `to_prometheus_text()` generates valid OpenMetrics syntax with `# HELP` and `# TYPE`.
     - **Test 4: Reset Semantics**: Verify `reset()` clears all metrics for isolated test runs.
     - **Test 5: Zero Sensitive Data Reflection**: Pass strings containing fake tokens/passwords to diagnostic loggers; assert that outputs redact sensitive content.
   - Create `tests/integration/audit_metrics_concurrency_test.cpp`:
     - **Test 6: High-Concurrency Hot-Path Stress**: 8 producer threads updating counters and latency histograms simultaneously ($100,000$ operations); verify zero data races (TSan clean) and exact count preservation.
     - **Test 7: Bounded Memory & Label Cardinality Invariant**: Verify memory footprint remains strictly static after recording $1,000,000$ events across all valid label permutations.
   - Register targets in `tests/unit/CMakeLists.txt` and `tests/integration/CMakeLists.txt`.
5. **Architectural Constraints**:
   - Clean compilation under `-Wall -Wextra -Werror -Wpedantic`.
   - Zero external daemon dependencies.
6. **Acceptance Criteria**:
   - 100% test pass rate across all new unit and concurrency test binaries.
   - Strict adherence to `.clang-format`.
7. **Dependencies**: `AUDIT-011-T01` through `AUDIT-011-T05`.

---

## 6. Acceptance Criteria & Definition of Done Matrix

| Ticket ID | Deliverables | Architectural Invariant | Verification Target |
| :--- | :--- | :--- | :--- |
| **AUDIT-011-T01** | `audit_metrics.{hpp,cpp}` | ADR-010, Lock-Free Design | Unit test verification of atomic counters and OpenMetrics text formatter |
| **AUDIT-011-T02** | Ingestion accounting in `AuditServiceImpl` | Request vs. Event separation | Verification of request-level vs event-level metric increments |
| **AUDIT-011-T03** | Queue & worker telemetry | Bounded queue observability | Queue depth gauge and saturation drop counter verification |
| **AUDIT-011-T04** | ClickHouse latency histograms | Latency tracking without locks | ClickHouse insert duration and failure count verification |
| **AUDIT-011-T05** | `audit_diagnostics.{hpp,cpp}` | ADR-008, Zero-PII | Structured logging tests confirming redaction of sensitive tokens |
| **AUDIT-011-T06** | Unit & Concurrency Test Suites | Milestone M6 Standards | 8-thread concurrency stress test passing with zero TSan warnings |

---

## 7. Risk Analysis & Mitigation Matrix

| Identified Risk | Severity | Potential Impact | Architectural Mitigation |
| :--- | :--- | :--- | :--- |
| **Ingestion Hot-Path Contention** | **High** | Telemetry locks cause thread contention, degrading throughput below 5,000 msgs/sec | Pure atomic variables (`std::atomic`) with `memory_order_relaxed`; zero mutexes or heap allocations on update path. |
| **Memory Growth (Cardinality Explosion)** | **High** | Using event IDs or correlation IDs as labels causes unbounded memory consumption | Labels strictly limited to closed enumerations (`producer`, `status`, `reason`, `trigger`); dynamic identifiers prohibited. |
| **Sensitive Data Leakage in Logs** | **Critical** | Operator logs expose user passwords or bearer tokens contained in rejected requests | `audit_diagnostics` processes all logged strings through `SensitiveDataGuard` and logs key names only, never payload values. |
| **Log Flooding on Downstream Outage** | **Medium** | Persistent ClickHouse failure generates millions of log lines, exhausting disk space | Diagnostic logging engine implements token-bucket rate-limiting, restricting error logging to 1 line/sec per failure class. |
| **Telemetry Failure Impacting Ingestion** | **Medium** | Metrics formatting bug or memory error blocks client event ingestion | Telemetry is strictly decoupled and fail-safe; metric collection errors never throw out to ingestion handlers. |

