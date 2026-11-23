# SecureCloud — AUDIT-015 Card Implementation & Validation Report

**Card ID**: `AUDIT-015`

**Card Title**: *Files Audit Producer and Production Transactional Outbox*

**Milestone**: M6 — Centralized Audit & Compliance

**Status**: **Implementation complete; focused validation passed**

**Date**: 2026-11-23

**Author**: Lorenzo & Engineering Team

---

## 1. Executive Summary

Card **AUDIT-015** upgrades the Files Service from its M5 audit-outbox prototype to a durable producer for the centralized Audit Service. The implementation preserves the Files-owned PostgreSQL boundary and the zero-knowledge storage model while adding canonical event mapping, leased delivery, retry and quarantine handling, producer observability, and verification coverage.

The completed work provides:

1. **A canonical Files audit contract**: `docs/design/files-audit-producer.md` documents the E01–E16 taxonomy, ownership and deduplication boundaries, metadata allowlists, Category A/B durability, legacy normalization, and zero-plaintext/zero-filename rules.
2. **A hardened PostgreSQL outbox**: Migration `V002` adds severity, quarantine state, leases, last-error storage, and partial indexes. `FilesOutboxRepository` atomically leases with `FOR UPDATE SKIP LOCKED`, keeps transient failures `PENDING`, recovers expired leases, and purges published rows in bounded batches.
3. **Transactional and autonomous event staging**: Files service event publishing supports staging inside business transactions or in an independent transaction for rejection/security events. Gateway request IDs flow as correlation IDs into Files and Audit events.
4. **Validated, scrubbed Audit delivery**: `FilesAuditMapper` normalizes legacy names, constructs canonical `AuditEventProto` messages, scrubs sensitive metadata, and pre-validates events. `GrpcAuditClient` uses bounded mTLS requests and verifies the configured peer identity.
5. **A resilient relay and typed configuration**: The relay classifies Audit acknowledgements, retries transient failures with bounded exponential backoff and jitter, isolates permanent rejections, wakes on notifications, drains on shutdown, and purges old published rows.
6. **Producer metrics and diagnostics**: Atomic metrics expose bounded-label OpenMetrics text. Diagnostics emit single-line JSON with per-category token-bucket limiting and sensitive-data scrubbing.
7. **Focused verification**: Unit tests cover mapping, validation, redaction, configuration, relay behavior, and metrics. PostgreSQL integration tests cover rollback, multi-worker leasing, expired-lease recovery, retry/recovery, quarantine, and retention. The Gateway E2E scenario validates request correlation, canonical lifecycle events, and one download event for ten chunks.

---

## 2. Architectural Decisions and Durability Boundaries

### A. Files-Owned PostgreSQL Outbox (`ADR-005`, `ADR-007`)

`files_outbox` remains in `securecloud_files`; Files does not write directly to Audit storage. Category A lifecycle events are staged with the business `pqxx::work`, so an aborted transaction leaves no outbox row. Category B events use autonomous staging so rejected or security-sensitive operations can be recorded independently of the rejected business operation.

Migration `V002__harden_files_outbox_table.sql` upgrades the baseline table with `severity`, `QUARANTINED`, `leased_until`, `last_error`, and pending/cleanup indexes. A claimed batch is updated and committed before dispatch. `FOR UPDATE SKIP LOCKED` and lease expiry allow workers to process disjoint rows and reclaim work after a worker crash.

### B. Canonical Events and Privacy Boundary (`AUDIT-002`, `ADR-008`)

The Files producer contract defines 16 canonical `file.*` events with explicit actor, target, severity, metadata, and durability rules. `FilesAuditMapper` translates legacy event names for rolling upgrades, enforces mapper bounds, removes forbidden and nested sensitive fields, and invokes the real Audit validator through a pimpl facade. Invalid rows are quarantined before they can poison a valid batch.

Sensitive filenames, encrypted filenames, keys, tokens, passwords, ciphertext, nonces, tags, PEM material, Bearer credentials, and JWT-shaped values are excluded or scrubbed before Audit serialization and diagnostic output. The audit validator is isolated behind `securecloud_files_audit_validator`, keeping the conflicting `auth/domain` and `audit/domain` headers out of the same implementation translation unit.

### C. Retry-Safe Relay (`AUDIT-006`, `ADR-009`)

Accepted events transition to `PUBLISHED`; per-event rejected IDs and permanent schema/conflict rejections transition to `QUARANTINED`. `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, transport exceptions, and mTLS identity failures are recorded as transient failures while the row stays `PENDING` and its lease is cleared. The relay applies bounded exponential backoff with jitter, caps gRPC batches at 100, and drains available work within its configured shutdown deadline.

Files health remains based on its own required dependencies. Audit availability does not become a Files readiness dependency; the outbox retains work for later delivery.

### D. Lock-Free Metrics and Zero-PII Diagnostics (`AUDIT-011`)

`FilesOutboxMetrics` uses relaxed atomic updates and fixed label sets for staging category, delivery outcome, and quarantine reason. Its exposition includes pending count and oldest-pending age gauges, delivery and retry counters, and published retention purges. `FilesOutboxDiagnostics` emits structured single-line JSON and applies rate limits per closed diagnostic category. Dynamic event and user identifiers are not Prometheus labels.

---

## 3. Implementation Ticket Traceability

| Ticket | Delivered scope | Primary artifacts |
| :--- | :--- | :--- |
| **AUDIT-015-T01** | Files event catalog, ownership boundaries, legacy mapping, privacy contract | `docs/design/files-audit-producer.md`; Files design and data-model documentation |
| **AUDIT-015-T02** | `V002`, leasing repository, quarantine/retry states, `pqxx_compat` support | `src/files/db/migrations/V002__harden_files_outbox_table.sql`; `FilesOutboxRepository`; `MigrationRunner` |
| **AUDIT-015-T03** | Caller and correlation context; transactional/autonomous staging | `FilesCallerContext`; `FilesAuditEventPublisher`; Gateway Files proxy metadata; Files service call sites |
| **AUDIT-015-T04** | Canonical mapping, two-stage scrubber, real validator facade, mTLS client | `FilesAuditMapper`; `FilesAuditProtoValidator`; `GrpcAuditClient`; `securecloud_files_audit_validator` |
| **AUDIT-015-T05** | Leased relay, acknowledgement matrix, config, backoff, drain, purge | `FilesOutboxRelay`; `FilesConfig`; Files service startup/shutdown wiring |
| **AUDIT-015-T06** | OpenMetrics metrics and scrubbed, rate-limited diagnostics | `files_outbox_metrics.{hpp,cpp}`; `files_outbox_diagnostics.{hpp,cpp}`; relay and publisher instrumentation |
| **AUDIT-015-T07** | Mapper/security, relay/config, telemetry, PostgreSQL, and Gateway E2E tests | New Files outbox unit and integration targets; updated Gateway→Files→Audit scenario |

---

## 4. Verification Evidence

The affected targets compiled in the Windows MinGW build using the project’s strict warning flags. The focused test executables were run directly from `build/ci-windows-mingw`.

### A. Mapper, Validator, and Security Unit Suite

`securecloud_files_outbox_audit_test`: **4 passed**. Covers all 16 documented canonical event names, legacy lifecycle aliases, validation through the real Audit validator, nested sensitive-data removal, and the auth/files audit-header compile guard.

### B. Metrics and Diagnostics Unit Suite

`securecloud_files_outbox_metrics_test`: **3 passed**. Covers OpenMetrics exposition with closed labels, redaction of synthetic database-error secrets/tokens/filenames, single-line JSON output, and per-category token-bucket rate limiting.

### C. Relay and Configuration Unit Suite

`securecloud_files_outbox_relay_test`: **14 passed**. Covers successful dispatch, transient RPC errors and exceptions, `UNAVAILABLE`/`DEADLINE_EXCEEDED`/`RESOURCE_EXHAUSTED`, partial rejection, poison-row quarantine, invalid-argument isolation, security identity faults, batch limits, backoff jitter, purge, shutdown drain, and Files audit configuration defaults/bounds.

### D. PostgreSQL 17 Transactional Integration Suite

`securecloud_files_outbox_transaction_test`, connected to the Compose PostgreSQL 17 service on `127.0.0.1:5433`: **4 passed**.

- Port 5432 preflight protection.
- Transactional commit and rollback with no phantom row.
- Four workers leasing 1,000 events with no duplicate claims.
- Expired lease recovery, retained `PENDING` state during simulated Audit outage, successful backlog delivery after recovery, malformed-event quarantine, and published-row retention purge.

The fixture uses a PostgreSQL advisory lock, refuses to operate on a database that already has pending outbox rows, and tracks/cleans the test rows it creates.

### E. Gateway-to-Files-to-Audit E2E Scenario

`FilesE2EGatewayAuditIntegrationTest.Scenario6_OutboxAuditDispatchVerification`: **1 passed**. The test sends an HTTP `X-Request-ID` through Gateway to the Files mock, dispatches generated outbox rows through the Audit service double, verifies correlation and canonical lifecycle event names, validates every captured proto, and confirms ten chunk downloads produce exactly one `file.download.initiated` event.

This scenario uses an in-memory Audit client to keep the E2E assertion focused on event flow and correlation. mTLS and peer-SAN behavior are covered separately by the Files gRPC Audit client tests.

### F. Formatting and Build Checks

- Targeted AUDIT-015 test targets built successfully.
- `clang-format --dry-run --Werror` passed on the modified C++ files.
- `git diff --check` passed.

### G. Auth Outbox Migration Regression Checks

The Auth migration runner now registers V005 (`create_auth_outbox_table`) in its standard migration list. The corresponding migration-structure unit test and the PostgreSQL persistence idempotency test were updated for schema version 5 and both passed (**1 test each**).

---

## 5. Validation Boundaries

The live PostgreSQL tests require the `postgres` service from `deploy/compose/docker-compose.yml` to be running and published on host port `5433`. They skip when the service is unreachable; with the service running, all four integration test cases passed.

The focused test executables passed. A full sanitizer matrix (ASan, UBSan, and TSan) is not recorded in this report. CTest-wide discovery was also not used as the final evidence because the configured Windows build had an unrelated `securecloud_proto_smoke_test.exe` loader error (`0xc0000139`); the affected AUDIT-015 executables were built and run directly.

---

## 6. Final Result

The AUDIT-015 implementation and focused verification are complete. Files now stages canonical audit events durably, validates and scrubs them before delivery, retains events safely during Audit outages, exposes bounded operational telemetry, and has passing unit, Gateway E2E, and live PostgreSQL verification evidence. Gatekeeper review/sign-off remains with Sergey.
