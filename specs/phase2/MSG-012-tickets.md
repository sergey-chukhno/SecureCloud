# MSG-012 — Messaging Capacity & Correctness Validation
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-012  
**Milestone**: M3 — Secure Messaging Platform (Milestone Final Card)  
**Document Status**: Proposal & Implementation Decomposition (Zero-Drift Architecture)  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 26, 2026  
**Target Path**: `specs/phase2/MSG-012-tickets.md`  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-012** represents the definitive validation, hardening, and verification milestone for the entire **SecureCloud Messaging Subsystem** (`securecloud-messaging`). It encompasses the full spectrum of capabilities established throughout cards **MSG-001** through **MSG-011**, adhering strictly to:
- **ADR-001**: Microservices Architecture & Autonomous Domain Boundaries
- **ADR-004**: gRPC Inter-Process Communication & Bounded Threading
- **ADR-007**: Message Reliability, Ordering & Durability (ScyllaDB-backed append log)
- **ADR-008**: Security & Cryptographic Architecture (Zero-Plaintext, Zero-Server-Decryption)
- **ADR-009**: Distributed Failure Modes, Circuit Breaking & Graceful Degradation
- **ADR-010**: Performance, Capacity, Resource Bounds & Optimization Strategy

As explicitly mandated by the architectural constraints:
> **"This card is a validation and hardening milestone, not an opportunity to introduce new architecture. The objective is to demonstrate that Messaging remains correct under realistic load, concurrency, failures, reconnects and multi-device activity."**

MSG-012 proves through empirical measurement, deterministic chaos testing, and adversarial security audits that the Messaging service sustains enterprise-grade throughput, maintains strict consistency across concurrent distributed operations, survives infrastructure outages without message loss or corruption, and rigorously preserves zero-knowledge cryptographic invariants.

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 MSG-012 VALIDATION PERIMETER                                     │
├───────────────────────────────┬───────────────────────────────┬──────────────────────────────────┤
│ 1. Concurrency & Integrity    │ 2. Scalability & Resilience   │ 3. Security & Non-Conflation     │
├───────────────────────────────┼───────────────────────────────┼──────────────────────────────────┤
│ • Zero message loss           │ • 10,000+ msgs/sec throughput │ • Absolute Zero-Plaintext audit  │
│ • Idempotent deduplication    │ • Reconnect storms (500+ dev) │ • Anti-Impersonation perimeter   │
│ • Non-regressive state machine│ • Bounded scheduler isolation │ • Fail-closed revocation audit   │
│ • Atomic outbox & cursors     │ • Sub-10ms delivery latency   │ • Mutual-peer privacy shielding  │
│ • Monotonic sequence orders   │ • Service restart recovery    │ • Zero server private key access │
└───────────────────────────────┴───────────────────────────────┴──────────────────────────────────┘
```

---

## 2. Re-anchoring on Existing Architecture (Zero Drift & Zero Duplication)

Card MSG-012 introduces **zero new production architectures, zero parallel data models, and zero external brokers**. It exercises and hardens the mature subsystem components developed across MSG-001 through MSG-011:

### 2.1 Inventory of Existing Subsystems Under Test

| Subsystem | Existing Components & Types | Source Location | MSG-012 Validation Focus |
| :--- | :--- | :--- | :--- |
| **Service & Threading** | `MessagingServer`, `MessagingConfig`, `BoundedWorkerPool` | `src/messaging/service/bounded_worker_pool.*` | Thread saturation, queue backpressure, execution deadlines, memory ceilings. |
| **Persistence Engine** | `ScyllaMessageRepository`, `ScyllaDeliveryStateRepository`, `ScyllaSyncCursorRepository` | `src/messaging/repository/` | Partition query efficiency, clustering order scans, partition hot-spotting audit. |
| **Sequencing & Submission** | `MessageSubmissionService`, `InMemorySequenceAllocator`, `MonotonicSequencer` | `src/messaging/service/message_submission_service.*` | Monotonic ordering, concurrent sequence allocation, idempotency cache deduplication. |
| **Cryptographic Envelopes** | `E2EEnvelopeValidator`, `EncryptedPayload`, `PerDeviceEnvelope` | `src/messaging/domain/envelope_types.hpp` | Zero-Plaintext byte audits, invalid algorithm rejection, ciphertext tampering detection. |
| **Fair Scheduling & Dispatch** | `BoundedDeliveryScheduler`, `per_device_queues_` | `src/messaging/delivery/bounded_delivery_scheduler.*` | Per-device queue isolation, max tasks per device, round-robin dispatch under saturation. |
| **Delivery & Read Receipts** | `DeliveryService`, `ReadReceiptService`, `MessageDeliverySummary` | `src/messaging/service/delivery_service.*`, `read_receipt_service.*` | Concurrent ACKs, out-of-order delivery notifications, logical user read aggregation. |
| **Device Synchronization** | `MessageSyncService`, `SyncCursorManager` | `src/messaging/service/message_sync_service.*`, `sync_cursor_manager.*` | Reconnect storms, gapless sequence streaming, cursor monotonicity under races. |
| **Presence & Acceleration** | `ConnectionLifecycleManager`, `PresenceCoordinator`, `RealtimeDeliveryAccelerator` | `src/messaging/delivery/`, `src/messaging/service/` | Ephemeral lease expiry, background reaper passes, fast-track dispatch on reconnect. |
| **Multi-Device Boundaries** | `RecipientDeviceResolutionService` | `src/messaging/service/recipient_device_resolution_service.*` | Sender companion fanout, anti-impersonation, fail-closed revocation quarantine. |
| **Telemetry & Metrics** | `PresenceMetrics`, Prometheus Metrics Engine | `src/messaging/telemetry/presence_metrics.*` | Gauges, counters, latency histograms under high-volume load. |

### 2.2 Rejection of Synthetic Brokers & Non-Conflation Axiom Enforcement

In strict compliance with **ADR-007** (Message Reliability & Durability) and **ADR-010** (Performance & Capacity Strategy):
- **No Global Broker**: No Kafka, RabbitMQ, or Redis cluster is introduced to artificially inflate benchmark scores. All durability relies on ScyllaDB append-only logs and bounded in-memory scheduling.
- **The Non-Conflation Axiom**:
  $$\mathbf{Presence} \neq \mathbf{Delivery\ (Per\text{-}Device)} \neq \mathbf{Read\ (Per\text{-}User)} \neq \mathbf{Synchronization\ (Per\text{-}Device)}$$
  Validation asserts that presence state fluctuations (disconnects, heartbeats, reaper sweeps) never mutate or regress durable delivery (`DELIVERED`) or read (`READ`) states.

---

## 3. Correctness & Invariant Requirements Matrix

Validation in MSG-012 must demonstrably prove the following 7 core correctness invariants:

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 CORE CORRECTNESS INVARIANTS                                      │
├───────────────────────────────┬──────────────────────────────────────────────────────────────────┤
│ 1. No Message Loss            │ All accepted messages with seq > 0 are durably persisted in      │
│                               │ ScyllaDB and retrievable via sync or real-time push.             │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 2. No Unauthorized Delivery   │ Non-participants cannot read, push, or sync messages.            │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 3. No State Regression        │ Delivery states advance monotonically:                           │
│                               │ QUEUED -> DELIVERING -> DELIVERED -> READ. No backward flips.    │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 4. No Duplicate Corruption    │ Duplicate submissions with identical idempotency tokens yield    │
│                               │ the original response without allocating duplicate sequences.    │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 5. No Plaintext Exposure      │ Zero plaintext payloads, encryption keys, or ratchet states      │
│                               │ exist in server memory, logs, ScyllaDB, or wire serialization.   │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 6. No Sync Cursor Regression  │ Client sync cursors advance strictly monotonically per device    │
│                               │ and conversation. Interleaved queries never skip sequences.      │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 7. No Revoked Delivery        │ Devices with DEVICE_STATUS_REVOKED are immediately quarantined:  │
│                               │ zero future deliveries, zero sync pulls, zero ACKs accepted.     │
└───────────────────────────────┴──────────────────────────────────────────────────────────────────┘
```

---

## 4. Performance & Capacity Target Thresholds (ADR-010)

| Metric | Target Threshold (SLA) | Validation Methodology |
| :--- | :--- | :--- |
| **Submission Latency (P50 / P95 / P99)** | $\le 5\text{ ms} / \le 15\text{ ms} / \le 30\text{ ms}$ | High-concurrency benchmark with multi-device fanout. |
| **Online Delivery Latency (P50 / P95)** | $\le 2\text{ ms} / \le 10\text{ ms}$ | Fast-track delivery accelerator via active streams. |
| **Acknowledgement Latency (P50 / P95)** | $\le 3\text{ ms} / \le 12\text{ ms}$ | State mutation in `delivery_state_by_message`. |
| **Synchronization Latency (P50 / P95)** | $\le 5\text{ ms} / \le 20\text{ ms}$ | Monotonic sequence batch reads (100 messages/batch). |
| **ScyllaDB Query Latency (P99)** | $\le 10\text{ ms}$ | Bounded partition scans by `(conversation_id, bucket_epoch)`. |
| **Sustained System Throughput** | $\ge 5,000\text{ msgs/sec}$ single-node | Multi-threaded client driver generating continuous submissions. |
| **Concurrent Active Connections** | $\ge 1,000\text{ streams}$ stable | Connection lifecycle manager maintaining active leases. |
| **Memory Footprint per Connection** | $\le 32\text{ KB}$ per session | Measured RSS during 1,000 active stream connections. |
| **Service Restart Recovery Time** | $\le 500\text{ ms}$ | Reconstitution of pending delivery tasks from disk. |

---

## 5. Implementation Ticket Breakdown (T01–T06)

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 MSG-012 TICKET ROADMAP                                           │
├─────────────┬─────────────────────────────────────────────────────────────┬──────────────────────┤
│ Ticket ID   │ Title                                                       │ Subsystem Target     │
├─────────────┼─────────────────────────────────────────────────────────────┼──────────────────────┤
│ MSG-012-T01 │ Concurrency, Deduplication & State Invariant Stress Harness │ Delivery / Receipts  │
│ MSG-012-T02 │ Reconnect Storms, Sync Watermarks & Backpressure Bounds     │ Sync / Scheduling    │
│ MSG-012-T03 │ Multi-Device Fan-Out & ScyllaDB Access Pattern Load Testing │ ScyllaDB / Transport │
│ MSG-012-T04 │ Chaos, Fault Injection & Service Restart Recovery Suite     │ Resilience / Storage │
│ MSG-012-T05 │ Security Boundary & Zero-Knowledge Cryptographic Audit      │ Security / Privacy   │
│ MSG-012-T06 │ Capacity Benchmark Harness, Hardening & M3 Acceptance Report│ Performance / QA     │
└─────────────┴─────────────────────────────────────────────────────────────┴──────────────────────┘
```

---

### MSG-012-T01: Concurrency, Deduplication & State Invariant Stress Harness

- **Objective**: Establish a high-concurrency race condition testing harness validating atomic sequence allocation, idempotent submission deduplication, non-regressive state machine transitions, and thread-safety under 100+ concurrent worker threads.
- **Files Affected**:
  - `tests/unit/messaging/messaging_concurrency_stress_test.cpp` (NEW)
  - `tests/unit/CMakeLists.txt`
- **Scope & Detailed Tasks**:
  1. **Concurrent Duplicate Submissions**:
     - Dispatch 100 concurrent threads attempting to submit the exact same message with identical `idempotency_token`.
     - Assert that exactly ONE thread assigns a sequence number and persists the message to ScyllaDB.
     - Assert that all remaining 99 threads receive the cached result with identical `message_id`, `sequence_number`, and timestamp.
     - Verify zero sequence gaps and zero duplicate rows in ScyllaDB storage.
  2. **Interleaved Delivery Acknowledgement & Read Receipt Races**:
     - For 1,000 messages, spawn concurrent threads simultaneously executing `AcknowledgeDelivery` and `RecordReadReceipt` across multiple target devices.
     - Assert that `DeliveryState` transitions monotonically: `Queued` $\to$ `Delivering` $\to$ `Delivered` $\to$ `Read`.
     - Enforce that a delayed `AcknowledgeDelivery` ACK never overwrites or regresses a previously recorded `Read` receipt.
  3. **Multi-Threaded Sequence Allocator Stress**:
     - Stress `InMemorySequenceAllocator` across 64 threads allocating 100,000 sequence numbers.
     - Assert strictly monotonic, contiguous sequence allocation with zero duplicates and zero skipped IDs.
- **Verification**: `ninja securecloud_messaging_concurrency_stress_test` 100% pass.

---

### MSG-012-T02: Reconnect Storms, Sync Watermarks & Backpressure Bounds

- **Objective**: Validate the Messaging subsystem under severe network churn, reconnect storms (500+ client devices simultaneously reconnecting), monotonic synchronization watermarks, and scheduler queue backpressure limits.
- **Files Affected**:
  - `tests/unit/messaging/messaging_sync_reconnect_storm_test.cpp` (NEW)
  - `tests/unit/CMakeLists.txt`
- **Scope & Detailed Tasks**:
  1. **Reconnect Storm Simulation**:
     - Simulate 500 client devices suddenly dropping connections, reconnecting concurrently within a 100ms window, and issuing `UpdatePresence` + `SyncDeviceMessages`.
     - Verify that `DeviceConnectionRegistry` cleanly registers new streams, evicts stale handles, and incurs zero thread leaks or mutex deadlocks.
  2. **Sync Watermark Monotonicity Under Churn**:
     - Interleave continuous message submissions with concurrent client sync queries and cursor updates (`UpdateSyncCursor`).
     - Assert that no client device ever misses a message sequence, receives duplicate messages, or observes a regressing sync cursor.
  3. **Scheduler Queue Backpressure & Bounded Worker Protection**:
     - Flood `BoundedDeliveryScheduler` with messages exceeding `max_tasks_per_device` (e.g., 200 tasks for a single device with a limit of 50).
     - Assert that excess tasks trigger bounded backpressure rejection without memory exhaustion or unbounded task queue growth.
     - Verify that tasks for unaffected devices continue dispatching in fair round-robin order without starvation.
- **Verification**: `ninja securecloud_messaging_sync_reconnect_storm_test` 100% pass.

---

### MSG-012-T03: Multi-Device Fan-Out & ScyllaDB Access Pattern Load Testing

- **Objective**: Validate multi-device message fan-out under representative sustained load, and audit ScyllaDB query patterns to ensure optimal partition bounds, clustering order scans, and sub-10ms query performance.
- **Files Affected**:
  - `tests/integration/messaging_capacity_load_test.cpp` (NEW)
  - `tests/integration/CMakeLists.txt`
- **Scope & Detailed Tasks**:
  1. **Multi-Device Fan-Out Workload**:
     - Generate a conversational topology: 50 participants, each with 3 active enrolled devices (150 total target devices).
     - Sender submits messages fanning out to 150 distinct `PerDeviceEnvelope` ciphertexts + sender companion devices.
     - Process 10,000 messages through the pipeline.
     - Measure and report submission throughput, fan-out serialization overhead, and per-device envelope routing latency.
  2. **ScyllaDB Access Pattern Verification**:
     - Audit queries against `messages`, `delivery_state_by_message`, and `sync_state_by_device`:
       - Verify partition key formulation: `(conversation_id, bucket_epoch)` ensures partition sizes remain under 50 MB (ADR-007, ADR-010).
       - Verify clustering key order: `sequence_number ASC` allows efficient range scans without in-memory sorting.
       - Assert that zero queries use unbounded full-table scans or `ALLOW FILTERING`.
  3. **Throughput & Latency Profiling**:
     - Capture P50, P90, P95, and P99 latency percentiles for message submission, online delivery, delivery acknowledgement, and sync batch fetches.
- **Verification**: `ninja securecloud_messaging_capacity_load_test` 100% pass.

---

### MSG-012-T04: Chaos, Fault Injection & Service Restart Recovery Suite

- **Objective**: Subject Messaging to simulated infrastructure failures, mid-flight socket terminations, transient database unreachability, and service restarts to verify deterministic recovery without message loss or corruption.
- **Files Affected**:
  - `tests/integration/messaging_fault_recovery_integration_test.cpp` (NEW)
  - `tests/integration/CMakeLists.txt`
- **Scope & Detailed Tasks**:
  1. **Mid-Flight Transport Disconnection & Lease Expiration**:
     - Disconnect transport socket immediately after a message is dispatched to `Delivering` state before receiving `AcknowledgeDelivery`.
     - Verify that lease timeout expires, `BoundedDeliveryScheduler` retries delivery, and upon device reconnect, the message is immediately redelivered via `RealtimeDeliveryAccelerator`.
  2. **Messaging Service Restart & State Recovery**:
     - Stage 500 messages across various delivery states (`Queued`, `Delivering`).
     - Abruptly tear down `MessagingServiceImpl` and instantiate a fresh service instance against the same ScyllaDB storage.
     - Measure restart recovery duration ($T_{\text{recovery}} \le 500\text{ ms}$).
     - Verify that all pending durable messages are discovered, scheduled, and delivered to reconnecting recipients without state loss or sequence gaps.
  3. **Transient ScyllaDB Storage Fault Injection**:
     - Inject simulated intermittent network delays and timeouts into repository operations.
     - Assert that `MessagingServiceImpl` surfaces structured gRPC errors (`UNAVAILABLE` / `DEADLINE_EXCEEDED`) and recovers cleanly when storage connectivity restores.
- **Verification**: `ninja securecloud_messaging_fault_recovery_integration_test` 100% pass.

---

### MSG-012-T05: Security Boundary & Zero-Knowledge Cryptographic Audit

- **Objective**: Conduct comprehensive security regression testing and cryptographic invariant audits asserting zero-plaintext exposure, caller anti-impersonation, fail-closed device revocation, and non-mutual privacy shielding under heavy concurrency.
- **Files Affected**:
  - `tests/unit/messaging/messaging_security_regression_test.cpp` (NEW)
  - `tests/unit/CMakeLists.txt`
- **Scope & Detailed Tasks**:
  1. **Zero-Plaintext Byte Audit (ADR-008)**:
     - Scan raw byte buffers across `ScyllaMessageRepository`, in-memory scheduler queues, log outputs, and telemetry frames.
     - Assert that zero unencrypted message content, private keys, or ratchet states ever appear in memory outside of opaque `EncryptedPayload` envelopes.
  2. **Adversarial Anti-Impersonation Under Load**:
     - Spawn adversarial worker threads attempting cross-device delivery acknowledgements (`Device A` attempting to ACK for `Device B`).
     - Attempt cross-device message synchronization (`Device A` attempting to pull `Device B`'s envelopes).
     - Assert 100% rejection rate with `MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE` / `PERMISSION_DENIED`.
  3. **Fail-Closed Revocation Quarantine Under Load**:
     - Revoke a device in the Auth directory while high-throughput traffic is actively targeting it.
     - Assert that subsequent submissions targeting the revoked device fail immediately with `MESSAGING_ERROR_CODE_DEVICE_REVOKED`.
     - Assert that in-memory queues for the revoked device in `BoundedDeliveryScheduler` are instantly purged.
     - Assert that the revoked device is blocked from pulling messages via `SyncDeviceMessages`.
  4. **Mutual-Conversation Privacy Shielding**:
     - Assert that presence queries from non-mutual conversation peers strictly return synthetic `OFFLINE` status under load.
- **Verification**: `ninja securecloud_messaging_security_regression_test` 100% pass.

---

### MSG-012-T06: Capacity Benchmark Harness, Hardening & M3 Acceptance Report

- **Objective**: Execute the unified performance benchmark harness across all operational workloads, apply targeted performance hardening within existing architectures, and produce the authoritative Milestone M3 Card Walkthrough Report.
- **Files Affected**:
  - `tests/integration/messaging_capacity_load_test.cpp` (benchmark runner integration)
  - `docs/final-reports/walkthrough-msg-012.md` (NEW, ~1,200+ lines)
- **Scope & Detailed Tasks**:
  1. **Unified Benchmark Execution & Telemetry Capture**:
     - Run the end-to-end benchmark suite measuring:
       - Submission Latency (P50, P90, P95, P99)
       - Real-time Delivery Latency (P50, P95)
       - Delivery Acknowledgement Latency (P50, P95)
       - Synchronization Latency (P50, P95)
       - Peak and Sustained Throughput (msgs/sec)
       - Connection Churn & Reaper Latency
       - Memory footprint (RSS) and CPU utilization
  2. **Performance Hardening (Within Architecture)**:
     - Profile hotspots: eliminate unnecessary object copies, reserve vector capacities, and tune mutex lock scopes in `BoundedDeliveryScheduler` and `DeviceConnectionRegistry`.
  3. **Milestone M3 Authoritative Walkthrough Report**:
     - Author `docs/final-reports/walkthrough-msg-012.md` containing:
       - Executive Summary & Milestone M3 Completion Sign-off
       - Comprehensive empirical latency and throughput tables
       - Workload profiles, environment specifications, and dataset sizes
       - Observed bottlenecks and architectural limitations
       - Full traceability matrix across all 12 Messaging cards (MSG-001 through MSG-012)
       - Formal security and zero-knowledge invariant verification
- **Verification**: Complete test pass across all 2014+ project tests and sign-off report review.

---

## 6. Traceability & Acceptance Matrix

| Acceptance Criterion | Verification Ticket | Test Suite Target |
| :--- | :--- | :--- |
| **Functional regression suite passes** | MSG-012-T01, T06 | Full CTest regression across all 2014+ tests |
| **Security regression suite passes** | MSG-012-T05 | `securecloud_messaging_security_regression_test` |
| **Concurrency tests pass** | MSG-012-T01 | `securecloud_messaging_concurrency_stress_test` |
| **Delivery-state invariants hold under load** | MSG-012-T01, T03 | `messaging_concurrency_stress_test`, `messaging_capacity_load_test` |
| **Read-state invariants hold under load** | MSG-012-T01, T03 | `messaging_concurrency_stress_test`, `messaging_capacity_load_test` |
| **Synchronization correctness is demonstrated** | MSG-012-T02 | `securecloud_messaging_sync_reconnect_storm_test` |
| **Multi-device correctness is demonstrated** | MSG-012-T03 | `securecloud_messaging_capacity_load_test` |
| **Restart/recovery behavior is validated** | MSG-012-T04 | `securecloud_messaging_fault_recovery_integration_test` |
| **Duplicate/retry behavior is validated** | MSG-012-T01, T04 | `messaging_concurrency_stress_test`, `messaging_fault_recovery_integration_test` |
| **ScyllaDB access patterns remain within characteristics** | MSG-012-T03 | `securecloud_messaging_capacity_load_test` |
| **Performance measurements are documented** | MSG-012-T06 | `docs/final-reports/walkthrough-msg-012.md` |
| **Resource limits are validated** | MSG-012-T02, T06 | `messaging_sync_reconnect_storm_test`, `messaging_capacity_load_test` |
| **No plaintext leakage is detected** | MSG-012-T05 | `securecloud_messaging_security_regression_test` |
| **No unauthorized delivery is detected** | MSG-012-T05 | `securecloud_messaging_security_regression_test` |
| **Known bottlenecks are documented** | MSG-012-T06 | `docs/final-reports/walkthrough-msg-012.md` |
| **Critical defects discovered are resolved** | MSG-012-T01..T06 | In-code hardening within existing architecture |
| **M3 Messaging acceptance evidence is complete** | MSG-012-T06 | `docs/final-reports/walkthrough-msg-012.md` |

---

## 7. Approval & Sign-Off

- **Lead Architect**: Antigravity
- **Security & Cryptographic Gatekeeper**: Approved (ADR-008, ADR-007, ADR-010 Zero-Drift, Zero-Duplication compliant)
- **Status**: Ready for Implementation (Tickets T01–T06)
