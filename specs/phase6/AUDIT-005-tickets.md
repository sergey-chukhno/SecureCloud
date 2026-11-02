# AUDIT-005 — Implement Bounded Asynchronous Ingestion and Batch Persistence
## Phase 7 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: `AUDIT-005`  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Dependencies**: `AUDIT-003` (ClickHouse Repository), `AUDIT-004` (gRPC Ingestion Endpoint), `AUDIT-006` (Deduplication & Acknowledgement Contract)

---

## 1. Executive Summary & Goal

### Goal
Implement the authoritative, bounded asynchronous ingestion pipeline for the **SecureCloud Audit Service** (`securecloud-audit`). This pipeline bridges authenticated internal gRPC ingestion requests (`SubmitAuditEvent`, `BatchSubmitAuditEvents`) to CPU-bound domain validation, dual-trigger batch construction, and ClickHouse persistence without unbounded memory growth, thread starvation, or silent event loss.

```text
                                  INGESTION & CONCURRENCY PIPELINE
  Incoming gRPC Requests
 (Gateway, Auth, Msg, Files)
            │
            ▼
┌─────────────────────────┐
│ Bounded Ingestion Queue │ ──► Hard Capacity: 10,000 events (Configurable)
│  (Non-blocking Pacing)  │ ──► On Queue Full: Immediate RESOURCE_EXHAUSTED (Backpressure)
└─────────────────────────┘
            │
            ▼
┌─────────────────────────┐
│ Validation Worker Pool  │ ──► 4 Concurrency Lanes (Approved MVP Baseline)
│   (Domain & Identity)   │ ──► AuditEventValidator, ProducerIdentityValidator, Zero-Plaintext Guard
└─────────────────────────┘
            │
            ▼
┌─────────────────────────┐
│     BatchAggregator     │ ──► Dual-Trigger Flush:
│ (Count or Timer Flush)  │       - Condition A: Batch count == 1,000 events
└─────────────────────────┘       - Condition B: Batch timer == 100 ms delay
            │
            ▼
┌─────────────────────────┐
│   Insert Worker Pool    │ ──► 2 Insertion Workers (Approved MVP Baseline)
│  (ClickHouse Bulk I/O)  │ ──► ClickHouseAuditEventRepository::insert_batch()
└─────────────────────────┘
            │
            ▼
┌─────────────────────────┐
│ Acknowledgement Manager │ ──► Synchronous / Asynchronous Durability Promise Completion
│  (No False Durability)  │ ──► ClickHouse Error / Timeout ──► Negative Ack / Producer Outbox Retry
└─────────────────────────┘
```

---

## 2. Approved MVP Baseline & Sizing Matrix

All parameters are fully configurable via `AuditConfig::ingestion` ([audit_config.hpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/audit/audit_config.hpp)), with the approved MVP defaults hardcoded as baseline constraints:

| Pipeline Parameter | Approved MVP Baseline | Valid Range | Configuration Key | Enforcement Point |
| :--- | :--- | :--- | :--- | :--- |
| **Validation Workers** | **4 threads** | `[1, 32]` | `AUDIT_INGESTION_VALIDATION_WORKERS` | `ValidationWorkerPool` |
| **Insert Workers** | **2 threads** | `[1, 16]` | `AUDIT_INGESTION_INSERT_WORKERS` | `InsertWorkerPool` |
| **Maximum Queued Events** | **10,000 events** | `[100, 100000]` | `AUDIT_INGESTION_MAX_QUEUED_EVENTS` | `BoundedIngestionQueue` |
| **Maximum Batch Size** | **1,000 events** | `[10, 5000]` | `AUDIT_INGESTION_BATCH_SIZE` | `BatchAggregator` (Count trigger) |
| **Maximum Batching Delay**| **100 ms** | `[10, 2000]` | `AUDIT_INGESTION_BATCH_FLUSH_INTERVAL_MS` | `BatchAggregator` (Timer trigger) |
| **Max Single Event Payload**| **64 KiB** | `[1024, 1048576]`| `AUDIT_INGESTION_MAX_EVENT_SIZE_BYTES` | Entry gRPC Validator Guard |
| **Shutdown Grace Period** | **5,000 ms** | `[500, 30000]` | `AUDIT_RETENTION_SHUTDOWN_GRACE_PERIOD_MS`| Pipeline Drain Controller |

---

## 3. Core Architectural Invariants & Reliability Constraints

1. **Strictly Bounded In-Memory Footprint (ADR-009, ADR-010)**:
   - The shared queue has a hard capacity ceiling of **10,000 events**.
   - Assuming an average event size of $1\text{ KiB}$ (max $64\text{ KiB}$), maximum volatile memory is bounded between **10 MiB and 640 MiB**.
   - Creating unbounded queues, thread-per-request models, or unbounded per-producer buffers is strictly prohibited.
2. **Explicit Overload Backpressure (No Silent Drops)**:
   - When the queue reaches capacity, requests must **never** be silently dropped.
   - The queue must fail-fast and reject excess requests with gRPC `RESOURCE_EXHAUSTED` and structured details (`Retry-After: 1s`).
   - Because all producers (Auth, Messaging, Files) use the **Transactional Outbox Pattern** (ADR-007), rejected events safely remain in the producer's database outbox for later retry.
3. **No False Durability Acknowledgements**:
   - Volatile memory is **not** durable storage.
   - In synchronous mode, gRPC `OK` is returned **only after** ClickHouse confirms the batch write.
   - If ClickHouse encounters a timeout, connection failure, or query rejection, the pipeline must return an observable failure (`UNAVAILABLE` / `DEADLINE_EXCEEDED`).
4. **Lock Isolation During Database I/O**:
   - Insert workers must **never** hold locks on the shared queue or validation workers while performing HTTP/TCP I/O against ClickHouse. Batches are swapped and decoupled.
5. **Deterministic Graceful Shutdown**:
   - On `SIGTERM` / `SIGINT`, the service stops accepting new requests, drains queued items through validation, flushes active batches to ClickHouse within the 5-second grace period, and rejects uncommitted requests cleanly so producers retry.
6. **Interfacing with AUDIT-006 (Deduplication)**:
   - Card AUDIT-005 defines an explicit temporary deduplication interface `IDeduplicationManager` with a clean mock/no-op implementation. Final deduplication and cross-retry idempotency semantics will be integrated in AUDIT-006.

---

## 4. Ticket Breakdown & Implementation Plan

```text
AUDIT-005-T01 (Bounded Shared Ingestion Queue & Overload Backpressure Engine)
     │
     ▼
AUDIT-005-T02 (Concurrent Validation Worker Pool & Deduplication Hook Interface)
     │
     ▼
AUDIT-005-T03 (Batch Aggregation Engine: Dual-Trigger on Count or Time)
     │
     ▼
AUDIT-005-T04 (ClickHouse Batch Inserter Workers & Fault/Retry Acknowledgement Manager)
     │
     ▼
AUDIT-005-T05 (Pipeline Coordination, Graceful Shutdown, Failure-Injection & Concurrency Suite)
```

---

### AUDIT-005-T01: Bounded Shared Ingestion Queue & Overload Backpressure Engine

#### Objective
Implement a thread-safe, memory-bounded shared queue that buffers incoming validated event envelopes from gRPC workers, provides non-blocking capacity checks, and generates deterministic overload backpressure when saturated.

#### Detailed Requirements
1. **Bounded Ingestion Queue Class (`src/audit/ingestion/bounded_ingestion_queue.hpp` / `.cpp`)**:
   - Thread-safe FIFO queue template/class with fixed capacity (default: `10,000` items).
   - Methods:
     * `bool try_push(IngestionEnvelope item)`: Non-blocking; returns `false` immediately if queue is full.
     * `bool push_with_timeout(IngestionEnvelope item, std::chrono::milliseconds timeout)`: Bounded wait.
     * `std::optional<IngestionEnvelope> pop(std::chrono::milliseconds timeout)`: Blocks worker until an item is available or timeout/shutdown occurs.
     * `std::vector<IngestionEnvelope> pop_batch(size_t max_items, std::chrono::milliseconds timeout)`: Efficient bulk dequeue.
     * `size_t size() const noexcept`: Live occupancy.
     * `size_t capacity() const noexcept`: Maximum capacity.
     * `void shutdown() noexcept`: Wakes all waiting threads and prevents subsequent pushes.
2. **Telemetry & Accounting**:
   - Atomic tracking of live queue size, peak high watermark, total enqueued, and total rejected events.
3. **Backpressure Status Helper**:
   - Helper function generating `grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Audit ingestion queue saturated; backpressure applied")` with trailing metadata `retry-after: 1`.

#### Files to Create / Modify
- `src/audit/ingestion/bounded_ingestion_queue.hpp`
- `src/audit/ingestion/bounded_ingestion_queue.cpp`
- `src/audit/ingestion/ingestion_envelope.hpp`
- `tests/unit/audit/bounded_ingestion_queue_test.cpp`

---

### AUDIT-005-T02: Concurrent Validation Worker Pool & Deduplication Hook Interface

#### Objective
Implement a multi-threaded validation pool (4 workers) that consumes raw ingestion envelopes, performs domain validation, enforces mTLS identity matching, and invokes the provisional deduplication hook before batching.

#### Detailed Requirements
1. **Validation Worker Pool (`src/audit/ingestion/validation_worker_pool.hpp` / `.cpp`)**:
   - Manages exactly `4` worker threads (configurable via `AuditConfig::ingestion`).
   - Continuously dequeues from `BoundedIngestionQueue`.
   - Runs `domain::AuditEventValidator::validate(event)`:
     * UUIDv7 identifier syntax check.
     * Timestamp temporal bounds check (no future timestamps $> 5$ minutes).
     * Authoritative assignment of `received_at = now()` (preserving distinct event vs. ingestion timestamps).
   - Runs `domain::ProducerIdentityValidator::validate(peer_san, declared_producer)`:
     * Ensures mTLS certificate SAN (e.g. `DNS:auth`, `DNS:files`) matches `producer_service`. Mismatches are rejected with `PERMISSION_DENIED`.
   - Runs `domain::SensitiveDataGuard::inspect(event)`:
     * Validates zero passwords, tokens, or encryption keys in metadata (ADR-008).
2. **Provisional Deduplication Interface (`src/audit/ingestion/deduplication_interface.hpp`)**:
   - Defines abstract interface:
     ```cpp
     class IDeduplicationManager {
       public:
         virtual ~IDeduplicationManager() = default;
         [[nodiscard]] virtual bool is_duplicate(const domain::EventId& event_id, uint64_t occurred_at_ms) = 0;
         virtual void record_processed(const domain::EventId& event_id, uint64_t occurred_at_ms) = 0;
     };
     ```
   - Provides `NoopDeduplicationManager` and `InMemoryLruDeduplicationManager` (10,000 entries) for standalone AUDIT-005 testing prior to AUDIT-006 integration.
3. **Dispatch to Aggregator**:
   - Successfully validated and non-duplicate events are forwarded to `BatchAggregator`.
   - Validation failures resolve the request's promise immediately with `INVALID_ARGUMENT`.

#### Files to Create / Modify
- `src/audit/ingestion/validation_worker_pool.hpp`
- `src/audit/ingestion/validation_worker_pool.cpp`
- `src/audit/ingestion/deduplication_interface.hpp`
- `src/audit/ingestion/in_memory_deduplication_manager.hpp`
- `tests/unit/audit/validation_worker_pool_test.cpp`

---

### AUDIT-005-T03: Batch Aggregation Engine (Dual-Trigger on Count or Time)

#### Objective
Implement the `BatchAggregator` that collects validated events into contiguous batches and triggers insertion whenever **1,000 events** accumulate OR **100 ms** elapses, whichever comes first.

#### Detailed Requirements
1. **Batch Aggregator Class (`src/audit/ingestion/batch_aggregator.hpp` / `.cpp`)**:
   - Manages incoming validated events with double-buffering or fine-grained swap.
   - **Threshold 1 (Size / Count)**: `max_batch_size = 1000`. As soon as the 1,000th event enters the current batch, it is immediately sealed and dispatched to the insertion queue.
   - **Threshold 2 (Time / Delay)**: `max_batching_delay_ms = 100`. A dedicated low-overhead timer thread (or condition-variable deadline loop) checks the oldest event's age in the active batch. If older than 100 ms, the batch is sealed and dispatched regardless of event count.
2. **Non-Blocking Swap & Decoupling**:
   - Dispatches sealed batches to an internal `BoundedBatchQueue` (capacity: e.g. 32 batches).
   - Under no circumstances does batch dispatch block validation workers.
3. **Zero Starvation**:
   - Ensures single events under trickle traffic are persisted within $\le 100\text{ ms}$.

#### Files to Create / Modify
- `src/audit/ingestion/batch_aggregator.hpp`
- `src/audit/ingestion/batch_aggregator.cpp`
- `tests/unit/audit/batch_aggregator_test.cpp`

---

### AUDIT-005-T04: ClickHouse Batch Inserter Workers & Fault/Retry Acknowledgement Manager

#### Objective
Implement the insert worker pool (2 workers) that persists sealed event batches to ClickHouse via `ClickHouseAuditEventRepository`, observes database errors/timeouts, and coordinates the durability acknowledgement lifecycle.

#### Detailed Requirements
1. **Insert Worker Pool (`src/audit/ingestion/insert_worker_pool.hpp` / `.cpp`)**:
   - Manages exactly `2` insert worker threads (configurable via `AuditConfig::ingestion`).
   - Dequeues sealed batches from `BatchAggregator`.
   - Calls `repository_->insert_batch(batch.events())`.
2. **Durability Acknowledgement Lifecycle**:
   - Each event or batch carries an `AcknowledgementHandle` (promise/callback).
   - **Success Path**: Once ClickHouse returns HTTP 200 OK, complete promises with success (`SubmitAuditEventResponse { success: true, event_id, received_at_ms }`).
   - **ClickHouse Failure Path**:
     * HTTP 500 / TCP connection refused / ClickHouse timeout $\rightarrow$ complete promises with `UNAVAILABLE` or `DEADLINE_EXCEEDED`.
     * **CRITICAL**: Never acknowledge persistence if ClickHouse failed.
     * Record failure metrics and allow the producer's transactional outbox to retry.
3. **Database Timeout & Connection Bounds**:
   - Enforce bounded ClickHouse request timeouts (`request_timeout_ms = 3000`).
   - Never leak ClickHouse connection strings, raw SQL queries, or passwords in error messages (ADR-008).

#### Files to Create / Modify
- `src/audit/ingestion/insert_worker_pool.hpp`
- `src/audit/ingestion/insert_worker_pool.cpp`
- `src/audit/ingestion/acknowledgement_manager.hpp`
- `src/audit/ingestion/acknowledgement_manager.cpp`
- `tests/unit/audit/insert_worker_pool_test.cpp`

---

### AUDIT-005-T05: Pipeline Coordination, Graceful Shutdown, Failure-Injection & Concurrency Suite

#### Objective
Assemble the complete `AuditIngestionPipeline`, wire it into the `AuditService` gRPC server, implement deterministic drain/shutdown logic, and validate the pipeline under high-concurrency stress and simulated ClickHouse failure injections.

#### Detailed Requirements
1. **Pipeline Coordinator (`src/audit/ingestion/audit_ingestion_pipeline.hpp` / `.cpp`)**:
   - Instantiates and connects `BoundedIngestionQueue`, `ValidationWorkerPool`, `BatchAggregator`, and `InsertWorkerPool`.
   - Wires into `AuditServer` / `AuditServiceImpl` in `src/audit/audit_server.cpp` and `src/audit/main.cpp`.
2. **Deterministic Graceful Shutdown**:
   - `void shutdown(std::chrono::milliseconds timeout)`:
     1. Stop accepting new RPCs (reject new calls with `UNAVAILABLE`).
     2. Wait for `BoundedIngestionQueue` to drain through validation workers.
     3. Flush all remaining batches in `BatchAggregator` immediately to `InsertWorkerPool`.
     4. Wait for insert workers to complete active writes to ClickHouse up to `shutdown_grace_period_ms` (5,000 ms).
     5. Terminate worker threads cleanly.
3. **Concurrency & Failure-Injection Test Suite**:
   - **`audit_ingestion_concurrency_test.cpp`**:
     * 20 concurrent threads pushing 50,000 events.
     * Verifies that peak memory is bounded, no data races occur (ThreadSanitizer clean), and throughput/latency metrics are recorded.
   - **`audit_ingestion_failure_injection_test.cpp`**:
     * Simulates ClickHouse database unreachable $\rightarrow$ verifies queue fills, produces `RESOURCE_EXHAUSTED` backpressure, and zero events are falsely acknowledged.
     * Simulates ClickHouse slow responses (5-second latency injection) $\rightarrow$ verifies timeouts and backpressure propagate to producers.
     * Tests dual-trigger firing: proves flush occurs at exactly 1,000 events under load, and at $\le 100\text{ ms}$ under trickle traffic.
4. **Quality Gates**:
   - `ninja check-format`: 100% adherence to `.clang-format`.
   - `ctest`: 100% pass rate with zero warnings under `-Wall -Wextra -Werror -Wpedantic`.

#### Files to Create / Modify
- `src/audit/ingestion/audit_ingestion_pipeline.hpp`
- `src/audit/ingestion/audit_ingestion_pipeline.cpp`
- `src/audit/audit_server.hpp` & `.cpp`
- `src/audit/main.cpp`
- `tests/unit/audit/ingestion_pipeline_test.cpp`
- `tests/integration/audit_ingestion_concurrency_test.cpp`
- `tests/integration/audit_ingestion_failure_injection_test.cpp`

---

## 5. Verification & Acceptance Validation Checklist

| Verification Check | Target / Metric | Acceptance Criteria |
| :--- | :--- | :--- |
| **Dual-Trigger: Batch Count** | High-throughput ingestion stream | Triggers ClickHouse flush at exactly **1,000 events** |
| **Dual-Trigger: Batch Delay** | Low-traffic / trickle ingestion | Triggers ClickHouse flush within **$\le$ 100 ms** |
| **Queue Capacity Limit** | Ingestion burst exceeding 10,000 items | Rejects excess items with `RESOURCE_EXHAUSTED`; memory bounded |
| **Concurrency Safety** | Multi-threaded stress test (TSan) | Zero data races across 4 validation and 2 insert workers |
| **No False Durability** | ClickHouse outage / timeout injection | Negative ACK returned to producer; zero false positive commits |
| **Deterministic Shutdown** | `SIGTERM` / drain test | In-flight batches flushed within 5s grace period; no leaked threads |
| **Zero-Plaintext Guard** | Payload & log inspection | Zero passwords, tokens, or encryption keys in ClickHouse or logs |
| **Formatting & Linter** | `ninja check-format` | 100% adherence across all new C++ files |
