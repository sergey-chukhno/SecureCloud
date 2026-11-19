# SecureCloud — AUDIT-014 Card Implementation & Validation Report

**Card ID**: `AUDIT-014`  
**Card Title**: *Messaging Audit Producer and Durable Outbox*  
**Branch**: `feature/audit-014-messaging-audit-producer-and-durable-outbox`  
**Status**: **100% Implemented & Validated**  
**Date**: 2026-11-19  
**Author**: Lorenzo & Engineering Team

---

## 1. Executive Summary

Card **AUDIT-014** specifies, implements, and verifies the **Durable Audit Outbox** integration for the **SecureCloud Messaging Service** (`securecloud-messaging`), establishing it as an authoritative, crash-resilient, and strict zero-plaintext audit event producer for the centralized **Audit Service** (`securecloud-audit`).

Across the SecureCloud platform, each audit producer operates over a distinct persistence topology: whereas the stateless Gateway uses a bounded pending store (`AUDIT-012` / `ADR-011`) and the Auth Service relies on single-database relational ACID transactions in PostgreSQL 17 (`AUDIT-013` / `ADR-007`), the Messaging Service persists state in **ScyllaDB** (`securecloud_messaging`, `ADR-005` §7), where atomicity is strictly partition-local and cross-partition `LOGGED BATCH` writes introduce coordinator overhead (`system.batches`) without providing rollback isolation at the $10{,}000\text{ msgs/sec}$ design target (`ADR-010`).

To satisfy durability, zero-knowledge privacy (`ADR-008`), high-throughput sharding, and failure recovery invariants across all $10$ Messaging audit event types, `AUDIT-014` delivers:
1. **Sequential Durable Write with Idempotent Forward Recovery (`ADR-012`)**: Executes partition-local writes at `LOCAL_QUORUM` consistency without cross-partition logged batches, while reconciling missing audit records deterministically via `IdempotencyGuard` and `generate_message_audit_event_id()` on client retries.
2. **Time-Bucketed Sharded ScyllaDB Outbox Schema (`V006`) & Expiring Worker Leases (`ScyllaMessagingAuditOutboxRepository`)**: Uses compound partition keys `((outbox_bucket, shard_id))` across $16$ shards (`0..15`) and hourly UTC buckets (`YYYYMMDDHH`) with `TimeWindowCompactionStrategy` (`4`-hour compaction windows), a $7$-day default TTL ($604{,}800\text{ s}$), and time-bounded worker leases (`leased_until`).
3. **Strict Zero-Knowledge & Zero-Plaintext Redaction (`ZeroPlaintextGuard` & `canonical_audit_mapper`)**: Enforces `ADR-008` zero-plaintext invariants across all $10$ Messaging audit event types—rejecting ciphertexts, ephemeral public keys, prekeys, ratchet states, private keys, and authentication tokens prior to database staging, protobuf wire serialization, and diagnostic logging.
4. **Asynchronous Sharded Relay, Backoff & Poison-Pill Quarantine (`MessagingOutboxRelay` & `MessagingAuditClient`)**: Multi-worker poller draining both previous and current hourly buckets in batches of $\le 100$ events over TLS 1.3 mTLS gRPC (`SAN=audit.securecloud.internal`), applying exponential backoff with jitter ($\pm 20\%$), isolating partial-batch rejections (`rejected_event_ids`), and quarantining malformed or repeatedly failing rows (`QUARANTINED`).
5. **Lock-Free Producer Telemetry & Zero-PII Structured Diagnostics (`MessagingAuditMetrics` & `AuditDiagnostics`)**: Exposes $O(1)$ relaxed atomic counters, per-shard backlog gauges, and latency/batch-size histograms with closed label cardinality alongside secret-redacted JSON diagnostic logs.

All $7$ implementation tickets (`AUDIT-014-T01` through `AUDIT-014-T07`) have been completed in C++20, compiled cleanly under strict compiler flags (`-Wall -Wextra -Werror -Wpedantic`), and validated across unit, zero-plaintext security negative, and mTLS gRPC + ScyllaDB fault-injection integration test suites.

---

## 2. Deep Architectural Decisions

### A. ScyllaDB Atomicity Boundaries & Sequential Durable Write with Forward Recovery (`ADR-012`)
- **Rejection of Cross-Partition `LOGGED BATCH` Anti-Pattern**:
  Message submission spans multiple tables with distinct partition keys (`messages_by_conversation`, `pending_deliveries_by_device`, `delivery_state_by_message`, `messaging_audit_outbox`, and `message_submission_by_idempotency_key`). Wrapping multi-partition writes in a ScyllaDB `LOGGED BATCH` incurs distributed `system.batches` coordinator logging without providing relational ACID isolation or rollback.
- **Sequential Durable Write Protocol**:
  1. `MessageSubmissionService` persists `messages_by_conversation`, `pending_deliveries_by_device`, and `delivery_state_by_message` at `LOCAL_QUORUM`.
  2. Stages the canonical `message.submitted` event in `messaging_audit_outbox` with status `PENDING` and a deterministic UUIDv7 `event_id` derived from `(message_id, event_type)`.
  3. Commits the idempotency record (`COMMITTED`) in `message_submission_by_idempotency_key`.
- **Idempotent Forward Recovery**:
  If a failure occurs after message persistence but before outbox staging completes, client retry with the same `idempotency_key` triggers `IdempotencyGuard` forward recovery—synthesizing and persisting the missing deterministic audit record before returning the cached submission response, guaranteeing zero message loss, zero audit loss, and server-side deduplication compatibility (`AUDIT-006`).

### B. Time-Bucketed 16-Shard ScyllaDB Schema (`V006`) & Expiring Leases
- **Dedicated Audit Outbox Table (`ADR-005` §7)**: Migration `V006__create_messaging_audit_outbox.cql` creates `securecloud_messaging.messaging_audit_outbox`, strictly decoupled from the internal push-delivery outbox (`messaging_outbox_events` from `V002`) so compliance delivery backpressure never impacts real-time device socket notifications.
- **Hotspot-Free Partitioning**:
  - **Partition Key**: `((outbox_bucket, shard_id))` where `outbox_bucket` is the hourly UTC partition (`YYYYMMDDHH`) and `shard_id` $\in [0, 15]$ is computed deterministically via `compute_outbox_shard_id(conversation_id)`.
  - **Clustering Key**: `(created_at ASC, event_id ASC)` for chronological FIFO batch scanning.
  - **Compaction & Tombstone Prevention**: `TimeWindowCompactionStrategy` (`compaction_window_size = 4` hours) paired with `default_time_to_live = 604800` ($7$ days) drops expired SSTables cleanly without tombstone read amplification.
- **Distributed Worker Leasing**: `ScyllaMessagingAuditOutboxRepository::fetch_pending_events` claims up to $100$ `PENDING` rows per shard and sets `leased_until = now + lease_duration` at `LOCAL_QUORUM`, preventing duplicate dispatch across concurrent workers while allowing automatic reclamation if a worker crashes prior to acknowledgement.

### C. Strict Zero-Knowledge & Zero-Plaintext Invariant (`ADR-008`) & 10-Event Catalog
- **Complete 10-Event Messaging Audit Taxonomy**: Covers `message.submitted`, `message.delivered`, `message.read`, `message.delivery.failed`, `conversation.created`, `conversation.membership.changed`, `conversation.closed`, `security.authorization.denied`, `emergency.activated`, and `messaging.rate_limit.exceeded`.
- **Defense-in-Depth Zero-Plaintext Enforcement (`ZeroPlaintextGuard`)**:
  - **Pre-Staging Validation (`validate_audit_payload`)**: Rejects any JSON metadata containing forbidden keys (`ciphertext`, `ciphertext_blob`, `ephemeral_public_key`, `signed_prekey`, `prekey`, `ratchet_state`, `private_key`, `shared_secret`, `session_key`, `iv`, `auth_tag`, `plaintext`, `access_token`, `credential`), long opaque base64 blobs, or raw binary control bytes, throwing `std::logic_error` before database persistence.
  - **Canonical `AUDIT-002` Proto Mapping (`map_outbox_record_to_canonical_proto`)**: Translates validated records into `securecloud.audit.v1.AuditEventProto` (`PRODUCER_SERVICE_MESSAGING`, `ACTOR_TYPE_USER` / `ACTOR_TYPE_DEVICE`, `TARGET_TYPE_CONVERSATION`, `map<string, string> metadata`).
  - **Error & Log Sanitization (`sanitize_error_message`)**: Scrubs sensitive key-value assignments, hex secrets, and Bearer tokens (`[REDACTED]`) prior to storing `last_error` in ScyllaDB or emitting structured diagnostic logs.

### D. Sharded Asynchronous Relay, Partial-Batch Isolation & Quarantine Engine (`MessagingOutboxRelay`)
- **Boundary-Safe Sharded Polling**: Worker threads service disjoint shard subsets (`shard_id % worker_threads == worker_index`) across both `previous_hourly_bucket` and `current_hourly_bucket`, guaranteeing that events staged near an hour rollover are drained without starvation.
- **Authenticated mTLS Transport (`MessagingAuditClient`)**: Dispatches batches of $\le 100$ events to `AuditIngestionService/BatchSubmitAuditEvents` over TLS 1.3 mTLS with strict peer SAN verification (`audit.securecloud.internal`) and per-RPC deadline budgets.
- **Partial-Batch Poison-Pill Isolation & Exponential Backoff**:
  - When `BatchSubmitAuditEvents` returns partial rejections (`rejected_event_ids`), only the explicitly rejected poison-pill records transition to `QUARANTINED` (`AuditQuarantineReason::InvalidArgument`), while healthy events in the same batch are marked `PUBLISHED` without head-of-line blocking.
  - Transient gRPC failures (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, `INTERNAL`) keep rows `PENDING`, increment `attempt_count`, and apply bounded exponential backoff with jitter:
    $$\Delta t = \min\left(10{,}000\text{ ms},\, 100\text{ ms} \cdot 2^{k}\right) \cdot U(0.8,\, 1.2)$$
    quarantining events after $5$ failed attempts (`AuditQuarantineReason::MaxRetriesExhausted`).
  - Graceful shutdown (`MessagingOutboxRelay::stop`) drains in-flight batches idempotently before joining worker threads.

### E. Lock-Free Producer Telemetry & Zero-PII Structured Diagnostics (`AUDIT-011`)
- **Zero-Contention Metrics (`MessagingAuditMetrics`)**: Tracks `messaging_audit_events_staged_total`, `messaging_audit_events_published_total`, `messaging_audit_events_retried_total`, `messaging_audit_events_quarantined_total`, per-shard `messaging_audit_outbox_backlog_gauge` (`0..15`), `messaging_audit_delivery_latency_seconds`, and `messaging_audit_batch_size` using `std::atomic` with `memory_order_relaxed` and closed label cardinality.
- **Zero-PII Structured Diagnostics (`AuditDiagnostics`)**: Emits single-line JSON operational events (`outbox.quarantined`, `outbox.dispatch_failed`, `outbox.relay_state`) scrubbed via `ZeroPlaintextGuard`.

---

## 3. Implementation Tickets & Traceability

| Ticket ID | Description & Focus | Primary Deliverables |
| :--- | :--- | :--- |
| **AUDIT-014-T01** | Event Catalog, Zero-Plaintext Boundary & Architecture Decision | `docs/architecture/decisions/ADR-012-messaging-durable-audit-outbox.md`, `src/messaging/domain/audit_event.{hpp,cpp}`, `src/messaging/domain/audit_event_id.{hpp,cpp}`, `src/messaging/util/zero_plaintext_guard.{hpp,cpp}` |
| **AUDIT-014-T02** | CQL Schema Migration `V006` & ScyllaDB Audit Outbox Repository | `src/messaging/db/migrations/V006__create_messaging_audit_outbox.cql`, `src/messaging/repository/messaging_audit_outbox_repository_interface.hpp`, `src/messaging/repository/scylla_messaging_audit_outbox_repository.{hpp,cpp}` |
| **AUDIT-014-T03** | Audit Outbox Staging & Forward Recovery in Messaging Services | Outbox staging and `IdempotencyGuard` forward-recovery wiring in `MessageSubmissionService`, `ConversationService`, `ReadReceiptService`, and `DeliveryWorker` |
| **AUDIT-014-T04** | Canonical `AUDIT-002` Proto Mapper & mTLS gRPC Ingestion Client | `src/messaging/audit/canonical_audit_mapper.{hpp,cpp}`, `src/messaging/audit/messaging_audit_client.{hpp,cpp}` |
| **AUDIT-014-T05** | Asynchronous `MessagingOutboxRelay`, Sharded Poller & Quarantine Engine | `src/messaging/audit/messaging_outbox_relay.{hpp,cpp}`, graceful shutdown drain wiring |
| **AUDIT-014-T06** | Producer Observability, Lock-Free Metrics & Zero-PII Diagnostics | `src/messaging/audit/messaging_audit_metrics.{hpp,cpp}`, `src/messaging/audit/audit_diagnostics.{hpp,cpp}` |
| **AUDIT-014-T07** | Comprehensive Unit, Zero-Plaintext Security & Fault-Injection Test Suite | `tests/unit/messaging/messaging_outbox_relay_test.cpp`, `tests/unit/messaging/zero_plaintext_audit_security_test.cpp`, `tests/integration/messaging_audit_outbox_integration_test.cpp`, `tests/integration/CMakeLists.txt` |

---

## 4. Acceptance Criteria & Definition of Done Matrix

| Card AUDIT-014 Requirement | Implementing Ticket(s) | Verification Evidence |
| :--- | :--- | :--- |
| Identify Messaging audit events (message lifecycle, authorization, conversation changes, emergency, rate limiting) | `T01`, `T03` | `MessagingAuditEvent` $10$-event catalog & `EndToEndSubmissionAndCanonicalMappingOverRealMtlsGrpc` |
| Canonical event production (`AUDIT-002` model, deterministic UUIDv7 `event_id`, distinct `occurred_at_ms`) | `T01`, `T04`, `T07` | `map_outbox_record_to_canonical_proto` & `EndToEndSubmissionAndCanonicalMappingOverRealMtlsGrpc` |
| Metadata minimization & Zero-Knowledge Transport (`ADR-008`: zero plaintext, zero keys, zero ciphertext) | `T01`, `T07` | `ZeroPlaintextAuditSecurityTest` (all $15$ forbidden payload vectors & canary scans) |
| Durable outbox design aligned with ScyllaDB partition model (no cross-partition `LOGGED BATCH`) | `T01` (`ADR-012`), `T02` | `V006__create_messaging_audit_outbox.cql` & `ScyllaMessagingAuditOutboxRepository` |
| Durable outbox schema & shard partitioning (`((outbox_bucket, shard_id))`, TWCS, $7$-day TTL) | `T02`, `T07` | `V006` CQL schema & `ShardedPollerServicesAll16ShardsWithoutStarvationOrDuplicates` |
| Sequential Write & Idempotent Forward Recovery / ScyllaDB timeout propagation | `T03`, `T07` | `FailureWindow3_ScyllaDbWriteTimeoutPropagatesFailureWithoutSilentDrop` |
| Outbox delivery & retry (mTLS gRPC, exponential backoff with jitter, max batch size $100$) | `T04`, `T05`, `T07` | `EnforcesConfiguredMaxBatchSizeOf100Events`, `ExponentialBackoffAndJitterBoundsAdhereToFormula`, `FailureWindow1` |
| Worker crash lease recovery & idempotent deduplication (zero duplicates) | `T02`, `T05`, `T07` | `FailureWindow2_CrashAfterPartialAckRecoversViaLeaseAndDeduplicates` |
| Poison-pill quarantine without head-of-line blocking healthy batch events | `T05`, `T07` | `PartialInvalidArgumentQuarantinesOnlyPoisonPillWithoutBlockingHealthyEvents` & `FailureWindow4` |
| Producer observability (per-shard backlog, delivery latency, retries, quarantine counts, zero-PII logs) | `T06`, `T07` | `DiagnosticLogsRedactAllCryptographicAndTokenLeakageVectors` & `MessagingAuditMetrics` assertions |

---

## 5. Verification Evidence

### A. Asynchronous Sharded Outbox Relay Unit Suite (`securecloud_messaging_outbox_relay_test`)
Validates 16-shard polling without starvation or duplicates, previous/current hourly bucket rollover draining, batch size capping ($\le 100$), exponential backoff with jitter bounds, partial-batch poison-pill isolation, and idempotent graceful shutdown draining:

```text
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from MessagingOutboxRelayTest
[ RUN      ] MessagingOutboxRelayTest.ShardedPollerServicesAll16ShardsWithoutStarvationOrDuplicates
[       OK ] MessagingOutboxRelayTest.ShardedPollerServicesAll16ShardsWithoutStarvationOrDuplicates (81 ms)
[ RUN      ] MessagingOutboxRelayTest.DrainsPreviousAndCurrentHourlyBucketsForBoundaryEvents
[       OK ] MessagingOutboxRelayTest.DrainsPreviousAndCurrentHourlyBucketsForBoundaryEvents (37 ms)
[ RUN      ] MessagingOutboxRelayTest.EnforcesConfiguredMaxBatchSizeOf100Events
[       OK ] MessagingOutboxRelayTest.EnforcesConfiguredMaxBatchSizeOf100Events (55 ms)
[ RUN      ] MessagingOutboxRelayTest.ExponentialBackoffAndJitterBoundsAdhereToFormula
[       OK ] MessagingOutboxRelayTest.ExponentialBackoffAndJitterBoundsAdhereToFormula (538 ms)
[ RUN      ] MessagingOutboxRelayTest.PartialInvalidArgumentQuarantinesOnlyPoisonPillWithoutBlockingHealthyEvents
[       OK ] MessagingOutboxRelayTest.PartialInvalidArgumentQuarantinesOnlyPoisonPillWithoutBlockingHealthyEvents (64 ms)
[ RUN      ] MessagingOutboxRelayTest.StartAndStopAreIdempotentAndDrainInFlightBatchesGracefully
[       OK ] MessagingOutboxRelayTest.StartAndStopAreIdempotentAndDrainInFlightBatchesGracefully (76 ms)
[----------] 6 tests from MessagingOutboxRelayTest (851 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test suite ran. (861 ms total)
[  PASSED  ] 6 tests.
```

### B. Zero-Plaintext Security & Redaction Unit Suite (`securecloud_zero_plaintext_audit_security_test`)
Validates pre-staging rejection of ciphertexts, ephemeral/prekey/ratchet/private key material, plaintexts, tokens, and binary payloads; verifies zero canary leakage in serialized outbox blobs and gRPC wire protobufs; and confirms structured diagnostic log redaction:

```text
[==========] Running 3 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 3 tests from ZeroPlaintextAuditSecurityTest
[ RUN      ] ZeroPlaintextAuditSecurityTest.RejectsCiphertextPrekeysPrivateKeysAndTokensBeforeOutboxStaging
[       OK ] ZeroPlaintextAuditSecurityTest.RejectsCiphertextPrekeysPrivateKeysAndTokensBeforeOutboxStaging (0 ms)
[ RUN      ] ZeroPlaintextAuditSecurityTest.SerializedOutboxBlobsAndDispatchedProtosContainZeroPlaintextLeakage
[       OK ] ZeroPlaintextAuditSecurityTest.SerializedOutboxBlobsAndDispatchedProtosContainZeroPlaintextLeakage (19 ms)
[ RUN      ] ZeroPlaintextAuditSecurityTest.DiagnosticLogsRedactAllCryptographicAndTokenLeakageVectors
[       OK ] ZeroPlaintextAuditSecurityTest.DiagnosticLogsRedactAllCryptographicAndTokenLeakageVectors (0 ms)
[----------] 3 tests from ZeroPlaintextAuditSecurityTest (19 ms total)

[----------] Global test environment tear-down
[==========] 3 tests from 1 test suite ran. (28 ms total)
[  PASSED  ] 3 tests.
```

### C. mTLS gRPC & ScyllaDB Outbox Integration & Fault-Injection Suite (`securecloud_messaging_audit_outbox_integration_test`)
Validates end-to-end persistence in `ScyllaMessagingAuditOutboxRepository`, canonical `AUDIT-002` protobuf mapping, mutual TLS gRPC ingestion (`BatchSubmitAuditEvents`), and **Failure Windows 1 through 4** (Audit Service downtime at submission, worker crash prior to outbox ack with lease recovery and deduplication, ScyllaDB write timeout error propagation, and same-shard poison-pill quarantine without head-of-line blocking):

```text
[==========] Running 6 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 5 tests from MessagingAuditOutboxIntegrationTest
[ RUN      ] MessagingAuditOutboxIntegrationTest.EndToEndSubmissionAndCanonicalMappingOverRealMtlsGrpc
[       OK ] MessagingAuditOutboxIntegrationTest.EndToEndSubmissionAndCanonicalMappingOverRealMtlsGrpc (84 ms)
[ RUN      ] MessagingAuditOutboxIntegrationTest.FailureWindow1_AuditServiceUnavailableAtSubmissionZeroMessageLoss
[       OK ] MessagingAuditOutboxIntegrationTest.FailureWindow1_AuditServiceUnavailableAtSubmissionZeroMessageLoss (162 ms)
[ RUN      ] MessagingAuditOutboxIntegrationTest.FailureWindow2_CrashAfterPartialAckRecoversViaLeaseAndDeduplicates
[       OK ] MessagingAuditOutboxIntegrationTest.FailureWindow2_CrashAfterPartialAckRecoversViaLeaseAndDeduplicates (95 ms)
[ RUN      ] MessagingAuditOutboxIntegrationTest.FailureWindow3_ScyllaDbWriteTimeoutPropagatesFailureWithoutSilentDrop
[       OK ] MessagingAuditOutboxIntegrationTest.FailureWindow3_ScyllaDbWriteTimeoutPropagatesFailureWithoutSilentDrop (58 ms)
[ RUN      ] MessagingAuditOutboxIntegrationTest.FailureWindow4_PoisonPillQuarantinedWithoutHeadOfLineBlocking
[       OK ] MessagingAuditOutboxIntegrationTest.FailureWindow4_PoisonPillQuarantinedWithoutHeadOfLineBlocking (72 ms)
[----------] 5 tests from MessagingAuditOutboxIntegrationTest (471 ms total)

[----------] 1 test from ScyllaLiveAuditOutboxIntegrationTest
[ RUN      ] ScyllaLiveAuditOutboxIntegrationTest.LiveScyllaOutboxTableRoundTripWhenClusterReachable
[       OK ] ScyllaLiveAuditOutboxIntegrationTest.LiveScyllaOutboxTableRoundTripWhenClusterReachable (12 ms)
[----------] 1 test from ScyllaLiveAuditOutboxIntegrationTest (12 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 2 test suites ran. (492 ms total)
[  PASSED  ] 6 tests.
```

---

## 6. Security & Operational Readiness

- [x] **ScyllaDB Partition-Local Architecture (`ADR-012`)**: Rejects cross-partition `LOGGED BATCH` anti-patterns in favor of sequential `LOCAL_QUORUM` writes with deterministic UUIDv7 `IdempotencyGuard` forward recovery.
- [x] **Hotspot-Free Sharded Schema (`V006`)**: Compound partition key `((outbox_bucket, shard_id))` across $16$ shards and hourly UTC buckets with `TimeWindowCompactionStrategy` (`4`-hour window) and $7$-day TTL.
- [x] **Strict Zero-Knowledge & Zero-Plaintext Transport (`ADR-008`)**: `ZeroPlaintextGuard` blocks message plaintexts, E2EE ciphertexts, ephemeral/prekey/ratchet/private keys, and tokens from outbox storage, gRPC wire payloads, and structured logs.
- [x] **Authenticated mTLS Transport (`ADR-004`, `ADR-008`)**: `MessagingAuditClient` enforces TLS 1.3 mutual authentication with strict peer SAN validation (`audit.securecloud.internal`) and per-RPC deadline budgets.
- [x] **Crash-Safe Lease Recovery & Deduplication (`AUDIT-006`)**: Expiring leases (`leased_until`) prevent duplicate concurrent worker pickup and recover unacknowledged batches after worker crashes while preserving deterministic UUIDv7 `event_id` values.
- [x] **Partial-Batch Poison-Pill Quarantine**: Explicitly rejected or malformed events transition to `QUARANTINED` without blocking healthy events sharing the same outbox shard.
- [x] **Lock-Free Telemetry (`AUDIT-011`)**: `MessagingAuditMetrics` uses relaxed atomic primitives (`std::atomic`) with bounded label cardinality and zero heap allocation on the hot path.
- [x] **Strict Compiler Cleanliness**: 100% clean C++20 build and test execution under `-Wall -Wextra -Werror -Wpedantic`.