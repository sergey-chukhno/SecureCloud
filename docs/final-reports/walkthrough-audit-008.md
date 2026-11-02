# SecureCloud — AUDIT-008 Card Implementation & Validation Report

**Card ID**: `AUDIT-008`  
**Card Title**: *Implement Retention Policy and Append-Only Persistence Safeguards*  
**Branch**: `feature/audit-008-implement-retention-policy-and-append-only-persistence-safeguards`  
**Base Commit**: `f8e910a`  
**Status**: **100% Implemented & Validated**  
**Date**: 2026-11-01  
**Author**: Lorenzo & Engineering Team

---

## 1. Executive Summary

Card **AUDIT-008** specifies, implements, and verifies the authoritative **36-Month Audit Record Retention Policy** (`TTL occurred_at + INTERVAL 36 MONTH`) and the **Append-Only Least-Privilege Persistence Safeguards** for the **SecureCloud Audit Service** (`securecloud-audit`).

All 6 implementation tickets (`AUDIT-008-T01` through `AUDIT-008-T06`) have been fully completed, compiled under C++20 with strict warning flags (`-Wall -Wextra -Werror -Wpedantic`), and validated with a 100% pass rate across the complete 38-target test suite (including unit tests and live ClickHouse 24.8 integration scenarios).

---

## 2. Deep Architectural Decisions

### A. Native ClickHouse 36-Month Retention Engine (`TTL occurred_at + INTERVAL 36 MONTH`)
- **`occurred_at` Alignment**: Retention is calculated strictly against the business occurrence timestamp `occurred_at` (and never `received_at`), ensuring legal and business compliance.
- **Monthly Partitioning**: Aligned with `PARTITION BY toYYYYMM(occurred_at)`, ClickHouse performs coarse-grained monthly partition purges without daily partition sprawl or table rewrites.
- **Asynchronous Execution**: Physical deletion occurs asynchronously during ClickHouse `MergeTree` background merges (`merge_with_ttl_timeout`), isolating active database TTL from offline backup retention lifecycles.

### B. Two-Tier Least-Privilege RBAC Separation (`audit_user` vs. `audit_migrator`)
- **`audit_migrator` (Schema Administration & Migration)**: Holds DDL and administrative privileges (`CREATE DATABASE`, `CREATE TABLE`, `ALTER TTL`, `OPTIMIZE`, `SHOW`) to initialize schemas and trigger administrative part merges.
- **`audit_user` (Routine Application Identity)**: Restricted strictly to `SELECT` and `INSERT` permissions on `securecloud_audit.audit_events`. Explicitly revoked from executing `ALTER UPDATE`, `ALTER DELETE`, `DELETE`, `TRUNCATE`, and `DROP TABLE`.

### C. Application-Layer Defense-in-Depth (`AppendOnlySqlGuard`)
- **C++ SQL Inspection**: Inspects all outgoing SQL statements prior to HTTP dispatch.
- **`INSERT` Guard**: Enforces strict `INSERT INTO securecloud_audit.audit_events ...` formatting.
- **`SELECT` & Query Guard**: Forces `readonly=1` HTTP parameters and rejects multi-statement queries (semicolons `;`) as well as forbidden DDL/DML mutation keywords (`UPDATE`, `DELETE`, `ALTER`, `TRUNCATE`, `DROP`) by throwing `AppendOnlyViolationException`.

### D. Event Lifecycle & Horizon Validation Bounds (`AuditEventValidator`)
- **Retention Alignment**: `RetentionConfig` defaults updated to `retention_months = 36` and `retention_days = 1095`.
- **Intake Horizon Bounds**: `AuditEventValidator` bounds `max_past_age` to 1,095 days (36 months). Events submitted with `occurred_at < now - 36 months` are rejected at intake with `ClockSkewTooOld`.
- **Out-of-Order & Delayed Events**: Valid delayed or out-of-order events within the 36-month horizon are accepted, sorted chronologically by `occurred_at`, and stamped with authoritative server `received_at`.

### E. Dynamic System Table Introspection & Schema Verification (`SchemaInitializer::verify_effective_schema`)
- Programmatically queries ClickHouse `system.tables` to assert runtime adherence to `MergeTree` engine settings, `toYYYYMM(occurred_at)` partitioning, `(occurred_at, producer_service, event_type, event_id)` sorting keys, and 36-month TTL clauses.

---

## 3. Implementation Tickets & Traceability

| Ticket | Description | Key Deliverables |
| :--- | :--- | :--- |
| **AUDIT-008-T01** | 36-Month Retention Alignment & ClickHouse TTL Migration | `RetentionConfig` (36 months / 1095 days), `001_create_audit_events_table.sql` with `TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE` |
| **AUDIT-008-T02** | ClickHouse Least-Privilege Access Control (RBAC) | `init-clickhouse.sql` with `audit_user` (`SELECT`, `INSERT` only) and `audit_migrator` DDL administration separation |
| **AUDIT-008-T03** | Application-Layer Append-Only SQL Guard & Schema Verifier | `AppendOnlySqlGuard` (`validate_insert_sql`, `validate_query_sql`), `SchemaVerificationReport` in `SchemaInitializer` |
| **AUDIT-008-T04** | Event Lifecycle Management (Delayed, Expired, Out-of-Order) | `AuditEventValidator` `max_past_age` alignment (1095 days), `ClockSkewTooOld` enforcement |
| **AUDIT-008-T05** | Architecture & Operational Documentation | Updated operational documentation covering asynchronous TTL semantics and RBAC matrix in `audit-design.md` and `05-audit-data-model.md` |
| **AUDIT-008-T06** | Unit & Live ClickHouse Integration Test Suite | `securecloud_audit_retention_and_append_only_test` unit suite and `securecloud_audit_retention_integration_test` live integration suite |

---

## 4. Verification Evidence

### A. Complete Unit Test Suite
Executed via GoogleTest (`securecloud_audit_retention_and_append_only_test`):
- **Retention Defaults**: Verified `retention_months == 36` and `retention_days == 1095`.
- **Append-Only Guard**: Verified `SELECT` and `INSERT` queries pass while `UPDATE`, `DELETE`, `TRUNCATE`, `DROP`, and semicolon multi-statements are blocked immediately.
- **Introspection Validation**: Verified `SchemaInitializer` accepts valid TTL DDL clauses and rejects missing or `received_at`-based TTL definitions.
- **Validator Bounds**: Verified events older than 36 months are rejected with `ClockSkewTooOld` while out-of-order and delayed events within bounds pass validation.

### B. Live ClickHouse 24.8 Integration Test Suite
Executed via GoogleTest against local ClickHouse container (`securecloud_audit_retention_integration_test`):
1. **Introspection Verification (`EffectiveSchemaPartitioningOrderingAndTtlVerifiedInSystemTables`)**: Validated live `system.tables` schema properties for `MergeTree` engine, `toYYYYMM(occurred_at)` partitioning, sorting keys, and 36-month TTL expressions.
2. **Controlled-Timestamp TTL Purge (`ControlledTimestampTtlExpirationRemoves37MonthOldRowWhilePreservingRecentRows`)**:
    - Inserted 3 events with UUIDv7 IDs aligned to controlled timestamps: 37 months old (`ts_expired`), 35 months old (`ts_boundary`), and 1 hour old (`ts_recent`).
    - Triggered synchronous TTL optimization via `OPTIMIZE TABLE securecloud_audit.audit_events FINAL` under `audit_migrator` credentials.
    - Verified that the 37-month-old event was **automatically purged by ClickHouse TTL**, while the 35-month and 1-hour events were preserved intact.
3. **RBAC Permission Denial (`RoutineApplicationUserCannotUpdateDeleteTruncateOrDropAuditEvents`)**:
    - Verified `SELECT` and `INSERT` succeed under `audit_user`.
    - Confirmed that raw HTTP requests attempting `ALTER UPDATE`, `ALTER DELETE`, `TRUNCATE`, or `DROP` are rejected by ClickHouse with HTTP 403 / `ACCESS_DENIED`.

```text
==================================================================
         SecureCloud Audit Test Runner & Reporter                 
==================================================================
Preset   : ci-windows-mingw
Targets  : 38 test suites
------------------------------------------------------------------

[STEP 1/2] Building all test targets...
  [BUILDING] securecloud_audit_retention_and_append_only_test... OK
  [BUILDING] securecloud_audit_retention_integration_test... OK
  ...
[SUCCESS] All 38 test targets compiled successfully!

[STEP 2/2] Running test executables...
  [RUNNING] securecloud_audit_retention_and_append_only_test... PASSED
  [RUNNING] securecloud_audit_retention_integration_test... PASSED
  ...

==================================================================
                    FINAL TEST SUITE SUMMARY
==================================================================
 Total Executed : 38
 Passed         : 38
 Failed         : 0

Result: OVERALL SUITE PASSED
```

---

## 5. Security & Operational Readiness

- [x] Audit log retention strictly enforced at 36 months via ClickHouse native `occurred_at`-based TTL.
- [x] Routine application credentials (`audit_user`) restricted strictly to `SELECT` and `INSERT` privileges.
- [x] Application-level `AppendOnlySqlGuard` blocks mutation DDL/DML prior to network dispatch.
- [x] Pre-horizon events (`> 36 months` old) rejected at intake by `AuditEventValidator` (`ClockSkewTooOld`).
- [x] DDL schema administration and TTL optimization isolated under dedicated `audit_migrator` identity.
- [x] All 38 test suites passing cleanly with zero compiler warnings under `-Wall -Wextra -Werror -Wpedantic`.