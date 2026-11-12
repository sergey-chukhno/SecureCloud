# SecureCloud — AUDIT-013 Card Implementation & Validation Report

**Card ID**: `AUDIT-013`  
**Card Title**: *Auth Audit Producer and Transactional Outbox*  
**Branch**: `feature/audit-013-auth-audit-producer-and-transactional-outbox`  
**Status**: **100% Implemented & Validated**  
**Date**: 2026-11-12  
**Author**: Lorenzo & Engineering Team

---

## 1. Executive Summary

Card **AUDIT-013** specifies, implements, and verifies the **Transactional Outbox** integration for the **SecureCloud Authentication Service** (`securecloud-auth`), establishing it as an authoritative, crash-resilient, and zero-secret audit event producer for the centralized **Audit Service** (`securecloud-audit`).

In contrast to `AUDIT-012`—where the stateless API Gateway relies on a bounded memory pending store (`ADR-011`)—the Auth Service exclusively owns the primary relational database (`securecloud_auth` on PostgreSQL 17, per `ADR-005` §6). Under `ADR-007` (§18–§23), every state-mutating authentication operation must commit its audit record atomically with the business state change inside the same PostgreSQL transaction (`pqxx::work`), eliminating dual-write inconsistencies and guaranteeing zero phantom audit events upon transaction rollback.

To satisfy durability, concurrency, security, and observability invariants across all 23 Auth audit event types, `AUDIT-013` delivers:
1. **Two-Category Transactional Durability Model**: Atomically stages state-mutating operations (`Category A`) inside the active business `pqxx::work` transaction while committing non-mutating security rejections (`Category B`) via dedicated autonomous transactions.
2. **PostgreSQL Outbox Schema (`V005`) & `SKIP LOCKED` Leasing (`PostgresAuthOutboxRepository`)**: Uses partial indexes and `SELECT ... FOR UPDATE SKIP LOCKED` with expiring leases (`leased_until`) so concurrent Auth instances and background workers process disjoint batches with zero lock contention or duplicate delivery.
3. **Canonical `AUDIT-002` Mapping & Defense-in-Depth Secret Scrubbing (`OutboxEventMapper` & `AuthAuditMapper`)**: Translates all 23 Auth domain event types into validated RFC 9562 UUIDv7 `AuditEventProto` messages while redacting passwords, Argon2id/bcrypt hashes, bearer tokens, PEM keys, and embedded JWTs prior to both database staging and gRPC serialization.
4. **Asynchronous Relay, Backoff & Quarantine Engine (`AuthOutboxRelay` & `AuthAuditClient`)**: Delivers batches over mTLS (`SAN=audit`), applies exponential backoff with jitter (`±25%`) on transient failures, drains pending events on graceful shutdown, purges expired `PUBLISHED` rows, and quarantines malformed or permanently rejected poison events (`QUARANTINED`).
5. **Lock-Free Prometheus Telemetry & Rate-Limited Diagnostics (`AuthOutboxMetrics` & `AuthOutboxDiagnostics`)**: Exposes $O(1)$ atomic counters and gauges with closed label cardinality alongside zero-PII structured logs.

All 7 implementation tickets (`AUDIT-013-T01` through `AUDIT-013-T07`) have been completed in C++20, compiled cleanly under strict compiler flags (`-Wall -Wextra -Werror -Wpedantic`), and validated across unit, concurrency, failure-injection, security negative, and live PostgreSQL 17 transactional integration test suites.

---

## 2. Deep Architectural Decisions

### A. Dual-Write Elimination & Category A / Category B Durability Semantics (`ADR-007` §18–§23)
- **Category A — State-Mutating Operations (Transactional Staging)**:
  Operations that mutate relational state (`auth.login.succeeded`, `auth.session.revoked`, `auth.token.refreshed`, `auth.token.reuse_detected`, MFA enrollment/confirmation/disabling/challenge success/recovery code usage, device enrollment/pairing/authorization/revocation, and prekey updates/rotations) invoke `OutboxAuditEventPublisher::publish_in_tx(event, tx)` inside the active `pqxx::work` business transaction.
  - **Atomicity**: Both the business entity mutation and the `INSERT INTO auth_outbox` commit together.
  - **Zero Phantom Events**: If any business invariant fails or `tx.abort()` is invoked, PostgreSQL rolls back the outbox row automatically.
  - **Zero Network Blocking**: Business transactions never perform gRPC I/O or block on Audit Service availability.
- **Category B — Non-State-Mutating Operations (Autonomous Staging)**:
  Security-relevant rejections (`auth.login.failed`, `auth.account.disabled_attempt`, `auth.session.expired_attempt`, `auth.session.revoked_attempt`, `auth.mfa.challenge_failed`, `auth.device.prekey_inventory_low`, `auth.device.prekey_inventory_exhausted`) invoke `OutboxAuditEventPublisher::publish(event)`, committing immediately in an autonomous PostgreSQL transaction without altering user, device, or session state.

### B. PostgreSQL Outbox Persistence (`V005`) & Zero-Contention `SKIP LOCKED` Leasing
- **Dedicated Auth-Owned Schema (`ADR-005` §6)**: Migration `V005__create_auth_outbox_table.sql` creates `auth_outbox` inside `securecloud_auth` with strict `CHECK` constraints on `severity` (`INFO`, `WARNING`, `SECURITY`, `CRITICAL`) and `status` (`PENDING`, `PUBLISHED`, `FAILED`, `QUARANTINED`).
- **Targeted Partial Indexes**:
  - `idx_auth_outbox_pending_polling` on `(created_at ASC) WHERE status = 'PENDING'` for fast FIFO batch acquisition.
  - `idx_auth_outbox_leased` on `(leased_until) WHERE status = 'PENDING' AND leased_until IS NOT NULL` for crash lease recovery.
  - `idx_auth_outbox_cleanup` on `(processed_at) WHERE status = 'PUBLISHED'` for non-blocking retention purges.
- **Row-Level Leasing & Crash Recovery**: `PostgresAuthOutboxRepository::fetch_and_lease_pending_batch` atomically claims up to $N \le 100$ rows using `FOR UPDATE SKIP LOCKED`, increments `retry_count`, and sets `leased_until = NOW() + lease_duration` ($30\text{ s}$ default). If a worker crashes mid-dispatch, leased rows automatically become reclaimable once `leased_until < NOW()`.

### C. Canonical `AUDIT-002` Proto Mapping & Defense-in-Depth Secret Scrubbing (`ADR-008`)
- **Complete 23-Event Coverage**: `OutboxEventMapper` and `AuthAuditMapper` translate all 23 `AuditEventType` variants into `securecloud.audit.v1.AuditEventProto`, enforcing RFC 9562 UUIDv7 validation on `event_id`, clock-skew bounds on `occurred_at_ms`, `PRODUCER_SERVICE_AUTH`, verified actor/target attribution, and strict field length ceilings.
- **Two-Stage Zero-Secret Sanitization**:
  - **Stage 1 (Pre-Persistence in `OutboxEventMapper`)**: Sanitizes `credential_identifier` and `failure_reason` prior to serializing `payload_json`, ensuring raw secrets never touch PostgreSQL disk or WAL logs.
  - **Stage 2 (Pre-Wire in `AuthAuditMapper`)**: Strips forbidden metadata keys (`password`, `secret`, `token`, `credential`, `private_key`, `recovery_code`, `salt`, etc.) and redacts values containing Bearer headers, PEM private key blocks, Argon2id/bcrypt password hashes, credential key-value assignments, or embedded 3-segment JWTs (`[REDACTED]`).

### D. Asynchronous mTLS Relay, Exponential Backoff & Poison-Pill Quarantine (`AUDIT-004`, `AUDIT-006`)
- **Authenticated mTLS Transport (`AuthAuditClient`)**: Uses `MtlsCredentialLoader` to establish TLS 1.3 mutual authentication with peer SAN verification against the Audit Service (`audit` / `audit.securecloud.internal`) and enforces per-RPC deadline budgets.
- **Retry & Idempotency Semantics (`AuthOutboxRelay`)**:
  - Acknowledged events transition to `PUBLISHED` with `processed_at = NOW()`.
  - Transient gRPC failures (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`) clear `leased_until`, record `last_error`, and trigger exponential backoff with jitter:
    $$\Delta t = \min\left(t_{\text{max}},\, t_{\text{init}} \cdot m^{k - 1}\right) \cdot \left(1 + U(-j, +j)\right)$$
    preserving the exact original UUIDv7 `event_id` and payload for server-side deduplication (`AUDIT-006`).
  - Malformed payloads or events listed in `rejected_event_ids` transition immediately to `QUARANTINED`, preventing poison pills from blocking healthy queue throughput.
  - Graceful shutdown (`AuthOutboxRelay::stop`) executes a bounded final drain before joining the background thread.

### E. Lock-Free Telemetry & Rate-Limited Zero-PII Diagnostics (`AUDIT-011`)
- **Zero-Contention Metrics (`AuthOutboxMetrics`)**: Tracks `auth_outbox_pending_events`, `auth_outbox_events_staged_total{category}`, `auth_outbox_events_delivered_total`, `auth_outbox_delivery_batches_total{outcome}`, `auth_outbox_retries_total`, `auth_outbox_quarantined_total{reason}`, `auth_outbox_purged_total`, and `auth_outbox_oldest_pending_age_seconds` using `std::atomic` with `memory_order_relaxed` and closed label cardinality.
- **Zero-PII Diagnostics (`AuthOutboxDiagnostics`)**: Emits structured operational logs with correlation IDs, per-category token-bucket rate limiting, and mandatory secret/email scrubbing (`[REDACTED_SENSITIVE_DATA]`).

---

## 3. Implementation Tickets & Traceability

| Ticket ID | Description & Focus | Primary Deliverables |
| :--- | :--- | :--- |
| **AUDIT-013-T01** | Auth Audit Event Inventory, Ownership Boundaries & Canonical Schema | `docs/design/auth-audit-producer.md`, `docs/data-model/02-auth-data-model.md`, `docs/design/auth-design.md` |
| **AUDIT-013-T02** | PostgreSQL Outbox Schema Migration `V005` & `AuthOutboxRepository` | `src/auth/db/migrations/V005__create_auth_outbox_table.sql`, `domain/auth_outbox_entity.hpp`, `repository/auth_outbox_repository.{hpp,cpp}` |
| **AUDIT-013-T03** | Transactional Outbox Staging Integration across Auth Services | `service/audit_event_publisher.{hpp,cpp}`, `service/outbox_event_mapper.{hpp,cpp}`, transactional wiring across `AuthServiceImpl`, `SessionManager`, `TokenManager`, `MfaManager`, `DeviceManager`, `PrekeyManager` |
| **AUDIT-013-T04** | Canonical Audit Proto Mapper & mTLS gRPC Ingestion Client | `audit/auth_audit_mapper.{hpp,cpp}`, `audit/auth_audit_client.{hpp,cpp}` |
| **AUDIT-013-T05** | Asynchronous `AuthOutboxRelay`, Lease Management & Quarantine Engine | `audit/auth_outbox_relay.{hpp,cpp}`, `auth_config.{hpp,cpp}`, `src/auth/main.cpp` graceful shutdown wiring |
| **AUDIT-013-T06** | Producer Observability, Lock-Free Metrics & Zero-PII Diagnostics | `audit/auth_outbox_metrics.{hpp,cpp}`, `audit/auth_outbox_diagnostics.{hpp,cpp}` |
| **AUDIT-013-T07** | Comprehensive Unit, Transaction, Concurrency & Security Test Suite | `tests/unit/auth/auth_outbox_test.cpp`, `tests/unit/auth/auth_outbox_relay_test.cpp`, `tests/unit/auth/auth_outbox_metrics_test.cpp`, `tests/integration/auth_outbox_transaction_test.cpp` |

---

## 4. Acceptance Criteria & Definition of Done Matrix

| Card Acceptance Criterion | Implementing Ticket(s) | Verification Evidence |
| :--- | :--- | :--- |
| Auth-owned audit event categories & boundaries documented | `T01` | `docs/design/auth-audit-producer.md` & 23-event catalog |
| Canonical `AUDIT-002` model reused with stable UUIDv7 `event_id` | `T01`, `T02`, `T04`, `T07` | `AuthOutboxTest.CanonicalProtoMappingFidelity_All23EventTypes` |
| Outbox stored in Auth-owned PostgreSQL DB (`securecloud_auth`) | `T02`, `T07` | Migration `V005` verified via `MigrationRunner` on port `5433` |
| Auth state changes & outbox records committed atomically | `T03`, `T07` | `AuthOutboxTransactionIntegrationTest.AtomicCommit_SessionAndOutboxRecordBothCommitted` |
| Rollbacks leave zero phantom audit events | `T03`, `T07` | `AuthOutboxTransactionIntegrationTest.AtomicRollback_AbortedTransactionLeavesZeroPhantomEvents` |
| Explicit durability semantics for non-transactional rejections | `T01`, `T03`, `T07` | `AuthOutboxTransactionIntegrationTest.AutonomousStaging_FailedLoginCommitsOutboxEventIndependently` |
| Crash & restart recovery without event loss | `T02`, `T05`, `T07` | `AuthOutboxTransactionIntegrationTest.CrashAndRestartRecovery_DeliversAll100PendingEvents` |
| Concurrent workers never double-process rows (`SKIP LOCKED`) | `T02`, `T05`, `T07` | `AuthOutboxTransactionIntegrationTest.MultiWorkerConcurrency_FourWorkersProcess1000EventsWithZeroDuplicates` |
| Outage retention & recovery backlog drain (`AUDIT-004`/`006`) | `T04`, `T05`, `T07` | `AuthOutboxTransactionIntegrationTest.AuditUnavailability_RetainsBacklogAndDrainsUponRecovery` |
| Poison-pill quarantine & 7-day published retention purge | `T02`, `T05`, `T07` | `PermanentRejectionQuarantine` & `RetentionPurge` integration tests |
| Zero secrets / PII in outbox payloads, gRPC metadata & logs | `T01`, `T04`, `T06`, `T07` | `SensitiveDataScrubbing_StripsPasswordsTokensHashesAndSecrets` & `ScrubsAllSecretsPiiAndCredentialsFromLogs` |

---

## 5. Verification Evidence

### A. Comprehensive Outbox Unit Verification Suite (`securecloud_auth_outbox_test`)
Validates canonical Proto mapping across all 23 Auth audit event types, two-stage sensitive-data scrubbing (outbox JSONB, Proto metadata, and diagnostic logs), lock-free Prometheus exposition, and exponential backoff jitter bounds:

```text
[==========] Running 4 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 4 tests from AuthOutboxTest
[ RUN      ] AuthOutboxTest.CanonicalProtoMappingFidelity_All23EventTypes
[       OK ] AuthOutboxTest.CanonicalProtoMappingFidelity_All23EventTypes (25 ms)
[ RUN      ] AuthOutboxTest.SensitiveDataScrubbing_StripsPasswordsTokensHashesAndSecrets
[       OK ] AuthOutboxTest.SensitiveDataScrubbing_StripsPasswordsTokensHashesAndSecrets (1 ms)
[ RUN      ] AuthOutboxTest.LockFreeMetricsAccuracyAndPrometheusExposition
[       OK ] AuthOutboxTest.LockFreeMetricsAccuracyAndPrometheusExposition (0 ms)
[ RUN      ] AuthOutboxTest.ExponentialBackoffCalculationAndJitterBounds
[       OK ] AuthOutboxTest.ExponentialBackoffCalculationAndJitterBounds (0 ms)
[----------] 4 tests from AuthOutboxTest (26 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test suite ran. (26 ms total)
[  PASSED  ] 4 tests.
```

### B. Relay Worker & Configuration Unit Suite (`securecloud_auth_outbox_relay_test`)
Validates dependency guards, batch size clamping ($\le 100$), batch dispatch, local/remote poison-pill quarantine, transient gRPC retry handling, exponential backoff, retention purge, graceful shutdown drain, and `AuthConfig` environment loading:

```text
[==========] Running 8 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 7 tests from AuthOutboxRelayTest
[ RUN      ] AuthOutboxRelayTest.Constructor_RejectsNullDependenciesAndClampsBatchSize
[       OK ] AuthOutboxRelayTest.Constructor_RejectsNullDependenciesAndClampsBatchSize (0 ms)
[ RUN      ] AuthOutboxRelayTest.PollAndDispatch_ValidBatch_MapsSanitizesAndMarksPublished
[       OK ] AuthOutboxRelayTest.PollAndDispatch_ValidBatch_MapsSanitizesAndMarksPublished (0 ms)
[ RUN      ] AuthOutboxRelayTest.PollAndDispatch_PermanentRejectionsAndMalformedPayload_QuarantinesWithoutBlockingValid
[       OK ] AuthOutboxRelayTest.PollAndDispatch_PermanentRejectionsAndMalformedPayload_QuarantinesWithoutBlockingValid (0 ms)
[ RUN      ] AuthOutboxRelayTest.PollAndDispatch_TransientGrpcFailure_MarksFailedAndRetainsPendingForIdempotentRetry
[       OK ] AuthOutboxRelayTest.PollAndDispatch_TransientGrpcFailure_MarksFailedAndRetainsPendingForIdempotentRetry (0 ms)
[ RUN      ] AuthOutboxRelayTest.ComputeBackoffDelay_AppliesExponentialGrowthCeilingAndJitter
[       OK ] AuthOutboxRelayTest.ComputeBackoffDelay_AppliesExponentialGrowthCeilingAndJitter (0 ms)
[ RUN      ] AuthOutboxRelayTest.PurgeOldPublishedRecords_UsesConfiguredRetentionAndBatchSize
[       OK ] AuthOutboxRelayTest.PurgeOldPublishedRecords_UsesConfiguredRetentionAndBatchSize (0 ms)
[ RUN      ] AuthOutboxRelayTest.StartAndStop_DrainsPendingEventsOnGracefulShutdown
[       OK ] AuthOutboxRelayTest.StartAndStop_DrainsPendingEventsOnGracefulShutdown (72 ms)
[----------] 7 tests from AuthOutboxRelayTest (73 ms total)

[----------] 1 test from AuthConfigOutboxTest
[ RUN      ] AuthConfigOutboxTest.Load_ParsesAuditAndOutboxRelayEnvironmentVariables
[       OK ] AuthConfigOutboxTest.Load_ParsesAuditAndOutboxRelayEnvironmentVariables (0 ms)
[----------] 1 test from AuthConfigOutboxTest (0 ms total)

[----------] Global test environment tear-down
[==========] 8 tests from 2 test suites ran. (74 ms total)
[  PASSED  ] 8 tests.
```

### C. Producer Metrics & Diagnostics Unit Suite (`securecloud_auth_outbox_metrics_test`)
Validates OpenMetrics/Prometheus text rendering, end-to-end publisher/relay metric updates, oldest pending event age tracking, and diagnostic credential/PII scrubbing:

```text
[==========] Running 3 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 2 tests from AuthOutboxMetricsTest
[ RUN      ] AuthOutboxMetricsTest.ToPrometheusText_ExportsAllRequiredMetricsAndBoundedLabels
[       OK ] AuthOutboxMetricsTest.ToPrometheusText_ExportsAllRequiredMetricsAndBoundedLabels (0 ms)
[ RUN      ] AuthOutboxMetricsTest.PublisherAndRelay_AccuratelyTrackLifecycleMetricsAndAge
[       OK ] AuthOutboxMetricsTest.PublisherAndRelay_AccuratelyTrackLifecycleMetricsAndAge (0 ms)
[----------] 2 tests from AuthOutboxMetricsTest (1 ms total)

[----------] 1 test from AuthOutboxDiagnosticsTest
[ RUN      ] AuthOutboxDiagnosticsTest.ScrubsAllSecretsPiiAndCredentialsFromLogs
[       OK ] AuthOutboxDiagnosticsTest.ScrubsAllSecretsPiiAndCredentialsFromLogs (0 ms)
[----------] 1 test from AuthOutboxDiagnosticsTest (0 ms total)

[----------] Global test environment tear-down
[==========] 3 tests from 2 test suites ran. (2 ms total)
[  PASSED  ] 3 tests.
```

### D. Live PostgreSQL 17 Transactional Integration Suite (`securecloud_auth_outbox_transaction_test`)
Validates port `5432` protection, atomic commit, atomic rollback (`tx.abort()` leaving zero phantom records), autonomous failed-login staging, 100-event crash/restart recovery, 4-worker `SKIP LOCKED` concurrency over 1,000 events with zero duplicates, Audit Service unavailability & backlog drain, permanent rejection quarantine, and 7-day retention purge:

```text
[==========] Running 9 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 1 test from AuthOutboxPreflightTest
[ RUN      ] AuthOutboxPreflightTest.StrictPort5432Protection
[       OK ] AuthOutboxPreflightTest.StrictPort5432Protection (0 ms)
[----------] 1 test from AuthOutboxPreflightTest (1 ms total)

[----------] 8 tests from AuthOutboxTransactionIntegrationTest
[ RUN      ] AuthOutboxTransactionIntegrationTest.AtomicCommit_SessionAndOutboxRecordBothCommitted
[       OK ] AuthOutboxTransactionIntegrationTest.AtomicCommit_SessionAndOutboxRecordBothCommitted (142 ms)
[ RUN      ] AuthOutboxTransactionIntegrationTest.AtomicRollback_AbortedTransactionLeavesZeroPhantomEvents
[       OK ] AuthOutboxTransactionIntegrationTest.AtomicRollback_AbortedTransactionLeavesZeroPhantomEvents (138 ms)
[ RUN      ] AuthOutboxTransactionIntegrationTest.AutonomousStaging_FailedLoginCommitsOutboxEventIndependently
[       OK ] AuthOutboxTransactionIntegrationTest.AutonomousStaging_FailedLoginCommitsOutboxEventIndependently (146 ms)
[ RUN      ] AuthOutboxTransactionIntegrationTest.CrashAndRestartRecovery_DeliversAll100PendingEvents
[       OK ] AuthOutboxTransactionIntegrationTest.CrashAndRestartRecovery_DeliversAll100PendingEvents (94 ms)
[ RUN      ] AuthOutboxTransactionIntegrationTest.MultiWorkerConcurrency_FourWorkersProcess1000EventsWithZeroDuplicates
[       OK ] AuthOutboxTransactionIntegrationTest.MultiWorkerConcurrency_FourWorkersProcess1000EventsWithZeroDuplicates (418 ms)
[ RUN      ] AuthOutboxTransactionIntegrationTest.AuditUnavailability_RetainsBacklogAndDrainsUponRecovery
[       OK ] AuthOutboxTransactionIntegrationTest.AuditUnavailability_RetainsBacklogAndDrainsUponRecovery (52 ms)
[ RUN      ] AuthOutboxTransactionIntegrationTest.PermanentRejectionQuarantine_QuarantinesBadEventsAndContinues
[       OK ] AuthOutboxTransactionIntegrationTest.PermanentRejectionQuarantine_QuarantinesBadEventsAndContinues (19 ms)
[ RUN      ] AuthOutboxTransactionIntegrationTest.RetentionPurge_RemovesOnlyExpiredPublishedRecords
[       OK ] AuthOutboxTransactionIntegrationTest.RetentionPurge_RemovesOnlyExpiredPublishedRecords (16 ms)
[----------] 8 tests from AuthOutboxTransactionIntegrationTest (1025 ms total)

[----------] Global test environment tear-down
[==========] 9 tests from 2 test suites ran. (1028 ms total)
[  PASSED  ] 9 tests.
```

---

## 6. Security & Operational Readiness

- [x] **Dual-Write Elimination (`ADR-007`)**: All state-mutating Auth operations commit business updates and `auth_outbox` rows atomically in a single `pqxx::work` transaction.
- [x] **Zero-Phantom Rollback Guarantee**: Aborted transactions roll back staged outbox records 100% of the time.
- [x] **Two-Stage Secret & PII Sanitization (`ADR-008`)**: Passwords, Argon2id/bcrypt hashes, refresh/access tokens, PEM keys, and JWTs are stripped prior to PostgreSQL JSONB persistence, Proto serialization, and diagnostic logging.
- [x] **Zero-Contention Multi-Worker Concurrency**: `SELECT ... FOR UPDATE SKIP LOCKED` with expiring leases (`leased_until`) eliminates row lock contention and duplicate deliveries across horizontal Auth replicas.
- [x] **Authenticated mTLS Transport (`ADR-004`, `ADR-008`)**: `AuthAuditClient` enforces mTLS peer SAN verification and strict RPC deadline budgets.
- [x] **Poison-Pill Quarantine & Bounded Retention**: Permanently rejected or malformed rows transition to `QUARANTINED` without blocking healthy events, and `PUBLISHED` rows older than 7 days are pruned in bounded batches.
- [x] **Lock-Free Telemetry (`AUDIT-011`)**: `AuthOutboxMetrics` uses relaxed atomic primitives with bounded label cardinality and zero heap allocation on the hot path.
- [x] **Strict Compiler Cleanliness**: 100% clean C++20 build and test execution under `-Wall -Wextra -Werror -Wpedantic`.