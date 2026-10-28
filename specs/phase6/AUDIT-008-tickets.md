# AUDIT-008 — Implement Retention Policy and Append-Only Persistence Safeguards
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: AUDIT-008  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: October 28, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-008** specifies, implements, and verifies the authoritative **36-Month Audit Record Retention Policy** (`TTL occurred_at + INTERVAL 36 MONTH`) and the **Append-Only Least-Privilege Persistence Safeguards** for the **SecureCloud Audit Service** (`securecloud-audit`).

As established in **ADR-001**, **ADR-006**, **ADR-008**, **ADR-010**, `docs/design/audit-design.md` (Sections 7.20, 7.21, 7.24), and `docs/data-model/05-audit-data-model.md` (Sections 5.15–5.18, 5.26–5.28), the Audit Service stores security and operational records in ClickHouse (`securecloud_audit.audit_events`). Two fundamental compliance invariants govern the audit data lifecycle:

1. **Append-Only Historical Immutability (`05-audit-data-model.md` §5.15, §5.26)**:
   - Audit events are immutable facts. Once persisted, normal application operations must **never** modify (`ALTER TABLE ... UPDATE`), delete (`ALTER TABLE ... DELETE` / `DELETE FROM`), or truncate (`TRUNCATE TABLE` / `DROP TABLE`) historical audit records.
   - Routine application database access must be restricted via ClickHouse SQL-driven Role-Based Access Control (RBAC) so that even if a runtime code path or query handler were compromised, the routine application identity lacks database privileges to mutate or delete rows in `securecloud_audit.audit_events`.
2. **Bounded 36-Month Storage Lifecycle via ClickHouse Native TTL (`05-audit-data-model.md` §5.27–5.28)**:
   - The approved MVP retention period is **36 months** (`1,095 days` / `INTERVAL 36 MONTH`), evaluated strictly against the business/security occurrence timestamp **`occurred_at`** (and **never** `received_at`).
   - Retention is enforced natively by the ClickHouse `MergeTree` storage engine (`TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE`), aligned with the monthly partition key `PARTITION BY toYYYYMM(occurred_at)`, avoiding any independent background polling/cleanup microservice.

### Key Architectural Findings in Current Codebase (Re-Anchoring Audit)

Inspecting the repository prior to designing `AUDIT-008` revealed three concrete gaps between the current bootstrap/specification files and `docs/data-model/05-audit-data-model.md` (§5.26–5.28) that `AUDIT-008` directly resolves:

1. **Gap 1 — Missing `TTL` Clause in `AUDIT-003-T01` DDL**:
   - In `specs/phase6/AUDIT-003-tickets.md` (lines 89–110), `001_create_audit_events_table.sql` omitted the `TTL toDateTime(occurred_at) + INTERVAL 36 MONTH` clause mandated by `docs/data-model/05-audit-data-model.md` §5.28 (lines 1090–1123).
2. **Gap 2 — `RetentionConfig` Default Mismatch in `src/audit/audit_config.hpp`**:
   - In [`src/audit/audit_config.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/audit/audit_config.hpp#L39-L42), `RetentionConfig::retention_days` defaulted to `90` days instead of `1095` days (`36 months`, matching `05-audit-data-model.md` §5.27).
3. **Gap 3 — Over-Privileged `GRANT ALL` in `deploy/compose/clickhouse/init-clickhouse.sql`**:
   - In [`deploy/compose/clickhouse/init-clickhouse.sql`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/deploy/compose/clickhouse/init-clickhouse.sql#L6), line 6 currently executes:
     ```sql
     GRANT ALL ON securecloud_audit.* TO audit_user;
     ```
     which grants `audit_user` full permission to execute `ALTER TABLE securecloud_audit.audit_events DELETE`, `ALTER TABLE securecloud_audit.audit_events UPDATE`, `TRUNCATE TABLE`, and `DROP TABLE`!
   - Furthermore, [`scripts/verify-persistence-infra.sh`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/scripts/verify-persistence-infra.sh#L212-L246) (Check 10) uses `audit_user` to create and drop the temporary table `securecloud_audit.persistent_marker`.
   - Therefore, `AUDIT-008` hardens ClickHouse RBAC by separating **Schema Migration / Admin privileges** (`audit_migrator` or initial bootstrap DDL) from **Routine Application privileges** (`audit_user`), explicitly **revoking** `ALTER UPDATE`, `ALTER DELETE`, `DELETE`, `TRUNCATE`, and `DROP TABLE` on `securecloud_audit.audit_events` from `audit_user` while preserving `audit_user`'s `SELECT, INSERT` on `securecloud_audit.audit_events` and full compatibility with `scripts/verify-persistence-infra.sh` on `securecloud_audit.persistent_marker`!

---

## 2. Architectural Deep-Dive: Retention Lifecycle & Append-Only Safeguards

### 2.1 Authoritative ClickHouse Table Definition & `DateTime64` TTL Mechanics

In `docs/data-model/05-audit-data-model.md` §5.28, `occurred_at` has type `DateTime64(3, 'UTC')`.
In ClickHouse 24.8 `MergeTree`, table-level `TTL` expressions require a `Date` or `DateTime` (32-bit second-precision) expression (`toDateTime(occurred_at) + INTERVAL 36 MONTH`). Because `PARTITION BY toYYYYMM(occurred_at)` organizes data into monthly partitions by `occurred_at`:

```sql
CREATE TABLE IF NOT EXISTS securecloud_audit.audit_events
(
    event_id UUID,

    occurred_at DateTime64(3, 'UTC'),
    received_at DateTime64(3, 'UTC'),

    event_type LowCardinality(String),
    severity LowCardinality(String),

    producer_service LowCardinality(String),
    producer_instance String,

    actor_type LowCardinality(String),
    actor_id String,

    target_type LowCardinality(String),
    target_id String,

    correlation_id UUID,
    causation_id UUID,

    event_data String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY
(
    occurred_at,
    producer_service,
    event_type,
    event_id
)
TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE
SETTINGS ttl_only_drop_parts = 0;
```

#### Why `occurred_at` (and Never `received_at`) Governs Retention:
1. **Business & Legal Compliance Semantics (`05-audit-data-model.md` §5.7, §5.27)**:
   - `occurred_at` records when the security-relevant action actually took place; `received_at` records when the Audit Service ingested the event from the producer outbox.
   - Partitioning (`PARTITION BY toYYYYMM(occurred_at)`), primary sorting (`ORDER BY (occurred_at, ...)`), and retention (`TTL toDateTime(occurred_at) + INTERVAL 36 MONTH`) **all** align on `occurred_at`.
   - When an entire monthly partition `YYYYMM` falls past the 36-month horizon, ClickHouse can drop or merge the expired data parts cleanly along partition boundaries without rewriting active partitions.

---

### 2.2 Lifecycle Behavior for Old, Delayed, Out-of-Order & Duplicate Events

```text
  Producer Outbox Event               AuditEventValidator (AUDIT-002)          ClickHouse MergeTree (AUDIT-008)
  (occurred_at, event_id)                           │                                         │
            │                                       │                                         │
            ├─► Case A: Normal / Slightly Delayed   │                                         │
            │   (now - occurred_at <= max_past_age) ├────► Validated & Batch Inserted ───────►│ Stored in partition
            │                                       │      (Appended; never overwrites)       │ toYYYYMM(occurred_at);
            │                                       │                                         │ Retained until
            ├─► Case B: Out-of-Order Arrival        │                                         │ occurred_at + 36 MONTHS
            │   (Event T1 arrives after Event T2)   ├────► Validated & Batch Inserted ───────►│ MergeTree sorts by
            │                                       │      (No global arrival order required) │ (occurred_at, ..., id)
            │                                       │                                         │
            ├─► Case C: Older Than Retention Horizon│                                         │
            │   (occurred_at < now - 36 months)     ├────► Rejected at Domain Gate!           │ Never written to disk
            │                                       │      (ClockSkewTooOld / ExpiredEvent)   │ (prevents zombie part
            │                                       │                                         │  creation & churn)
            └─► Case D: Duplicate event_id Retry    │                                         │
                (Handled in coordination w/ T06)    ├────► Caught by BoundedDeduplicationCache│ Append-only if outside
                                                           (or appended as immutable row;     │ cache window; deduplicated
                                                            never executes UPDATE on history) │ by LIMIT 1 BY event_id
```

1. **Delayed & Out-of-Order Events (`docs/design/audit-design.md` §7.23)**:
   - Because runtime services publish via independent asynchronous outboxes, an event from `Files` at $t = 10{:}00{:}01$ may arrive after an event from `Auth` at $t = 10{:}00{:}03$.
   - The Audit Service accepts valid out-of-order events without requiring global arrival ordering. ClickHouse `MergeTree` places each event into its `toYYYYMM(occurred_at)` partition and sorts background parts by `(occurred_at, producer_service, event_type, event_id)`.
2. **Events Already Past the Retention Horizon (`ClockSkewTooOld`)**:
   - In `AuditEventValidator` (`AUDIT-002`), `max_past_age` is aligned with the configured retention horizon (or bounded outbox replay window). Any event submitted with `occurred_at < now - retention_period` is rejected at intake with `AuditValidationErrorCode::ClockSkewTooOld`, preventing producers from creating already-expired historical partitions in ClickHouse.
3. **Coordination with `AUDIT-006` (Duplicate Event IDs Without Historical Overwrites)**:
   - Standard `MergeTree` (not `ReplacingMergeTree`) is intentionally used (`05-audit-data-model.md` §5.28) so background compactions cannot silently overwrite an earlier security event with a later forged or mutated row sharing the same key.
   - `AUDIT-006`'s `BoundedDeduplicationCache` (`100,000` IDs, `10-minute` TTL) suppresses normal retry duplicates before insertion, and `AUDIT-007`'s `LIMIT 1 BY event_id` deduplicates any post-restart duplicate rows at read time—preserving 100% append-only storage semantics.
4. **Asynchronous Semantics of ClickHouse TTL Deletion**:
   - ClickHouse `TTL ... DELETE` removes expired rows asynchronously during background `MergeTree` part merges (controlled by `merge_with_ttl_timeout`, default `14,400 seconds` / `4 hours`, or triggered explicitly during verification testing via `OPTIMIZE TABLE ... FINAL`).
   - Physical deletion is **eventual and asynchronous**, not an exact-to-the-millisecond real-time purge, and deleting expired rows from active ClickHouse storage is distinct from offline backup lifecycle management (`docs/design/audit-design.md` §7.20).

---

### 2.3 Least-Privilege ClickHouse Access Model & Append-Only Safeguards

To guarantee that routine Audit Service operations are physically incapable of modifying or deleting historical audit records, `AUDIT-008` establishes a two-tier privilege separation in ClickHouse (`deploy/compose/clickhouse/init-clickhouse.sql`) supplemented by a compile-time/runtime C++ SQL guard:

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                       CLICKHOUSE TWO-TIER PRIVILEGE SEPARATION (AUDIT-008)                      │
├────────────────────────────────────────────────┬────────────────────────────────────────────────┤
│ 1. Schema Initializer / Admin Identity         │ 2. Routine Application Identity                │
│    (`audit_migrator` / Bootstrap Admin)        │    (`audit_user` used by `securecloud-audit`)  │
├────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ • Executes `001_create_audit_events_table.sql` │ • Used by `ClickHouseAuditEventRepository`     │
│ • Permitted: `CREATE DATABASE`, `CREATE TABLE`,│   for all runtime ingestion & queries          │
│   `ALTER TABLE ... MODIFY TTL`, `SHOW CREATE`, │ • Permitted on `securecloud_audit.audit_events`│
│   `OPTIMIZE TABLE` (for administrative/test    │   ONLY: `SELECT`, `INSERT`, `SHOW TABLES`,     │
│   TTL verification)                            │   `CHECK TABLE`                                │
│ • Never used by runtime gRPC ingestion or      │ • EXPLICITLY REVOKED / DENIED on `audit_events`│
│   query worker pools                           │   `ALTER UPDATE`, `ALTER DELETE`, `DELETE`,    │
│                                                │   `TRUNCATE`, `DROP TABLE`, `ALTER COLUMN`     │
└────────────────────────────────────────────────┴────────────────────────────────────────────────┘
```

#### Concrete ClickHouse RBAC Provisioning (`deploy/compose/clickhouse/init-clickhouse.sql`):
```sql
CREATE DATABASE IF NOT EXISTS securecloud_audit;

-- 1. Dedicated schema migration / administrative user for DDL & TTL lifecycle verification
CREATE USER IF NOT EXISTS audit_migrator IDENTIFIED WITH sha256_password BY 'audit_migrator_dev_secret';
GRANT CREATE DATABASE, CREATE TABLE, ALTER TTL, OPTIMIZE, SHOW, SELECT, INSERT
    ON securecloud_audit.* TO audit_migrator;

-- 2. Routine Audit Service application user (least-privilege append + read on audit_events)
CREATE USER IF NOT EXISTS audit_user IDENTIFIED WITH sha256_password BY 'audit_dev_db_secret';
GRANT SELECT, INSERT, SHOW TABLES, DICTGET ON securecloud_audit.* TO audit_user;
-- Preserve compatibility with scripts/verify-persistence-infra.sh Check 10 marker table:
GRANT CREATE TABLE, DROP TABLE ON securecloud_audit.persistent_marker TO audit_user;
-- Strictly forbid any mutation, deletion, truncation, or drop on audit_events:
REVOKE ALTER, DELETE, TRUNCATE, DROP TABLE ON securecloud_audit.audit_events FROM audit_user;
```

#### Application-Layer Defense-in-Depth (`AppendOnlySqlGuard`):
In addition to ClickHouse RBAC enforcement, `ClickHouseClient` in `src/audit/repository/clickhouse_client.hpp|.cpp` enforces an application-level **Append-Only SQL Guard**:
- `ClickHouseClient::execute_insert` only accepts statements matching `INSERT INTO securecloud_audit.audit_events ...`.
- `ClickHouseClient::execute_query` runs with HTTP parameter `readonly=1` and rejects any SQL string containing forbidden mutation keywords (`ALTER`, `UPDATE`, `DELETE`, `TRUNCATE`, `DROP`, `RENAME`, `REPLACE`, `ATTACH`, `DETACH`) with `AppendOnlyViolationException` before any network packet leaves the Audit Service process!

---

## 3. Configuration Model Alignment (`AuditConfig::RetentionConfig`)

In `src/audit/audit_config.hpp` and `src/audit/audit_config.cpp`, `RetentionConfig` is updated to reflect the approved **36-month** (`1,095-day`) default retention policy:

| Parameter | C++ Field (`RetentionConfig`) | Environment Variable | Default Value | Validated Range | Architectural Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Retention Months | `retention_months` | `SECURECLOUD_AUDIT_RETENTION_MONTHS` | `36` | `[1, 120]` (1 month to 10 years) | `05-audit-data-model.md` §5.27 (`INTERVAL 36 MONTH`) |
| Retention Days | `retention_days` | `SECURECLOUD_AUDIT_RETENTION_DAYS` | `1095` ($36 \times 30.4375$) | `[1, 3650]` | Backward-compatible day representation |
| Shutdown Grace Period (ms) | `shutdown_grace_period_ms` | `SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS` | `5000` | `[500, 30000]` | Graceful drain of in-flight batches on `SIGTERM` |

---

## 4. Dependency Graph

```text
                AUDIT-001 (AuditConfig & RetentionConfig)
                AUDIT-002 (AuditEvent, occurred_at vs received_at, Validator)
                AUDIT-003 (ClickHouse Schema, Client & Repository)
                AUDIT-006 (Event Deduplication & Idempotency Coordination)
                AUDIT-007 (Read-Only Query Execution Plane)
                SC-011 (ClickHouse Docker Compose & Persistence Verification)
                                          │
                                          ▼
                                    AUDIT-008-T01
                        (RetentionConfig 36-Month Alignment &
                         Authoritative ClickHouse DDL Migration with
                         `TTL toDateTime(occurred_at) + INTERVAL 36 MONTH`)
                                          │
                                          ▼
                                    AUDIT-008-T02
                        (ClickHouse Least-Privilege RBAC Provisioning:
                         `audit_user` Append-Only Restrictions vs.
                         `audit_migrator` Schema Administration)
                                          │
                                          ▼
                                    AUDIT-008-T03
                        (Application-Layer Append-Only SQL Guard &
                         Schema / TTL Introspection Verifier in
                         `SchemaInitializer` & `ClickHouseClient`)
                                          │
                                          ▼
                                    AUDIT-008-T04
                        (Data Lifecycle Enforcement: Delayed, Out-of-Order,
                         and Expired-Horizon Event Handling in Validator
                         & Repository)
                                          │
                                          ▼
                                    AUDIT-008-T05
                        (Architecture & Operational Documentation:
                         Asynchronous TTL Semantics, RBAC Model &
                         Backup vs. Active Retention Boundaries)
                                          │
                                          ▼
                                    AUDIT-008-T06
                        (Unit, RBAC Permission Denial, Controlled-Timestamp
                         TTL Expiration & Schema Repeatability Test Suite)
```

---

## 5. Implementation Tickets for Developer Lorenzo

### AUDIT-008-T01 — 36-Month Retention Configuration & Authoritative ClickHouse TTL Schema

1. **Ticket ID**: `AUDIT-008-T01`
2. **Title**: 36-Month `RetentionConfig` Alignment & Authoritative ClickHouse `audit_events` TTL Migration
3. **Objective**: Update `AuditConfig::RetentionConfig` to the approved 36-month (`1,095-day`) baseline and update `src/audit/migrations/001_create_audit_events_table.sql` and `SchemaInitializer` to enforce `TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE` alongside `PARTITION BY toYYYYMM(occurred_at)` and `ORDER BY (occurred_at, producer_service, event_type, event_id)`.
4. **Architectural Purpose**: Ensures that the authoritative ClickHouse schema and service configuration implement the exact 36-month `occurred_at`-based retention lifecycle specified in `docs/data-model/05-audit-data-model.md` §5.27–5.28.
5. **Scope**:
   - **Update `src/audit/audit_config.hpp` and `src/audit/audit_config.cpp`**:
     - Update `RetentionConfig`:
       ```cpp
       struct RetentionConfig {
           uint32_t retention_months{36};           // [1, 120] (36 months default per 05-audit-data-model.md §5.27)
           uint32_t retention_days{1095};           // [1, 3650] (36 months = 1095 days)
           uint32_t shutdown_grace_period_ms{5000}; // [500, 30000]
       };
       ```
     - Parse optional `SECURECLOUD_AUDIT_RETENTION_MONTHS` (`[1, 120]`) in `AuditConfig::load()`.
   - **Update/Create `src/audit/migrations/001_create_audit_events_table.sql`**:
     - Include `TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE`.
     - Provide idempotent migration support in `SchemaInitializer::initialize_schema()` so if `audit_events` already exists without a TTL clause, `ALTER TABLE securecloud_audit.audit_events MODIFY TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE` is applied cleanly by the schema initializer.
   - **Update `tests/unit/audit/audit_config_test.cpp`**:
     - Verify default `retention_months == 36` and `retention_days == 1095`, plus boundary validation tests.
6. **Explicit Out-of-Scope**: ClickHouse user RBAC changes (handled in T02).
7. **Dependencies**: `AUDIT-001`, `AUDIT-003`.
8. **Files to Create/Modify**:
   - `src/audit/audit_config.hpp`
   - `src/audit/audit_config.cpp`
   - `src/audit/migrations/001_create_audit_events_table.sql`
   - `src/audit/repository/schema_initializer.hpp`
   - `src/audit/repository/schema_initializer.cpp`
   - `tests/unit/audit/audit_config_test.cpp`

---

### AUDIT-008-T02 — ClickHouse Least-Privilege RBAC & Separation of Routine vs. Admin Identities

1. **Ticket ID**: `AUDIT-008-T02`
2. **Title**: ClickHouse Least-Privilege Access Control (`audit_user` vs. `audit_migrator`) & Append-Only RBAC Enforcement
3. **Objective**: Replace `GRANT ALL ON securecloud_audit.* TO audit_user` in `deploy/compose/clickhouse/init-clickhouse.sql` with a least-privilege RBAC model that restricts routine `audit_user` access on `securecloud_audit.audit_events` strictly to `SELECT` and `INSERT`, while provisioning `audit_migrator` for schema initialization and TTL administration.
4. **Architectural Purpose**: Enforces at the database engine level that routine application credentials cannot execute `ALTER ... UPDATE`, `ALTER ... DELETE`, `DELETE`, `TRUNCATE`, or `DROP TABLE` against `securecloud_audit.audit_events`.
5. **Scope**:
   - **Update `deploy/compose/clickhouse/init-clickhouse.sql`**:
     - Create `audit_migrator` user for schema DDL and TTL maintenance (`GRANT CREATE DATABASE, CREATE TABLE, ALTER TTL, OPTIMIZE, SHOW, SELECT, INSERT ON securecloud_audit.* TO audit_migrator`).
     - Restrict `audit_user` to `GRANT SELECT, INSERT, SHOW TABLES, DICTGET ON securecloud_audit.* TO audit_user;` plus `GRANT CREATE TABLE, DROP TABLE ON securecloud_audit.persistent_marker TO audit_user;` (preserving 100% compatibility with `scripts/verify-persistence-infra.sh` Check 10), and explicitly `REVOKE ALTER, DELETE, TRUNCATE, DROP TABLE ON securecloud_audit.audit_events FROM audit_user;`.
     - Also execute `001_create_audit_events_table.sql` during ClickHouse container initialization so `securecloud_audit.audit_events` is present immediately upon startup with its 36-month TTL.
   - **Extend `scripts/verify-persistence-infra.sh` (or add `scripts/verify-audit-retention.sh`)**:
     - Verify that `audit_user` can `INSERT` and `SELECT` on `securecloud_audit.audit_events`, and that `ALTER TABLE securecloud_audit.audit_events DELETE WHERE 1=1` and `TRUNCATE TABLE securecloud_audit.audit_events` executed as `audit_user` fail closed with ClickHouse `ACCESS_DENIED` (Code 497).
6. **Explicit Out-of-Scope**: Modifying PostgreSQL, ScyllaDB, or MinIO configurations (strictly forbidden by card constraints).
7. **Dependencies**: `AUDIT-008-T01`, `SC-011`.
8. **Files to Create/Modify**:
   - `deploy/compose/clickhouse/init-clickhouse.sql`
   - `scripts/verify-persistence-infra.sh`

---

### AUDIT-008-T03 — Application-Layer Append-Only SQL Guard & Schema/TTL Introspection Verifier

1. **Ticket ID**: `AUDIT-008-T03`
2. **Title**: `AppendOnlySqlGuard` & Runtime ClickHouse Schema/TTL Introspection Verifier
3. **Objective**: Implement deterministic application-layer safeguards (`AppendOnlySqlGuard`) in `ClickHouseClient` and `ClickHouseAuditEventRepository` that prohibit any mutating or destructive SQL statement, and implement `SchemaInitializer::verify_effective_schema()` to inspect `system.tables` and `system.columns` at startup/test time.
4. **Architectural Purpose**: Provides defense-in-depth in C++ code so ordinary ingestion and query paths can never emit `UPDATE`, `DELETE`, `ALTER`, `TRUNCATE`, or `DROP` statements, and programmatically verifies that the live table uses `MergeTree`, `toYYYYMM(occurred_at)` partitioning, `(occurred_at, producer_service, event_type, event_id)` sorting, and `occurred_at`-based 36-month TTL (never `received_at`).
5. **Scope**:
   - **Create `src/audit/repository/append_only_sql_guard.hpp` and `.cpp`**:
     - `AppendOnlySqlGuard::validate_query_sql(std::string_view sql)`:
       - Verifies statement begins with `SELECT` (ignoring leading whitespace) and contains no semicolon-chained statements (`;`) and no forbidden DDL/DML keywords (`INSERT`, `UPDATE`, `DELETE`, `ALTER`, `TRUNCATE`, `DROP`, `CREATE`, `RENAME`, `OPTIMIZE`, `GRANT`, `REVOKE`, `ATTACH`, `DETACH`).
     - `AppendOnlySqlGuard::validate_insert_sql(std::string_view sql)`:
       - Verifies statement strictly matches `INSERT INTO securecloud_audit.audit_events ...` with zero semicolon-chained statements or mutation clauses.
     - Wire into `ClickHouseClient::execute_query()` and `ClickHouseClient::execute_insert()` so any violation throws `AppendOnlyViolationException` immediately before network transmission.
   - **Implement `SchemaVerificationReport` in `src/audit/repository/schema_initializer.hpp|.cpp`**:
     - Queries ClickHouse `system.tables` (`SELECT engine, partition_key, sorting_key, create_table_query FROM system.tables WHERE database = 'securecloud_audit' AND name = 'audit_events'`):
       - Verifies `engine == "MergeTree"`.
       - Verifies `partition_key == "toYYYYMM(occurred_at)"`.
       - Verifies `sorting_key == "occurred_at, producer_service, event_type, event_id"`.
       - Verifies `create_table_query` contains `TTL toDateTime(occurred_at) + toIntervalMonth(36)` (or `INTERVAL 36 MONTH`) and does **not** reference `received_at` in the `TTL` clause!
6. **Explicit Out-of-Scope**: External archival or cold-storage export services.
7. **Dependencies**: `AUDIT-008-T01`, `AUDIT-003-T02`.
8. **Files to Create/Modify**:
   - `src/audit/repository/append_only_sql_guard.hpp`
   - `src/audit/repository/append_only_sql_guard.cpp`
   - `src/audit/repository/clickhouse_client.cpp`
   - `src/audit/repository/schema_initializer.hpp`
   - `src/audit/repository/schema_initializer.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-008-T04 — Data Lifecycle Enforcement for Old, Delayed, Out-of-Order & Duplicate Events

1. **Ticket ID**: `AUDIT-008-T04`
2. **Title**: Lifecycle Enforcement for Delayed, Out-of-Order, Pre-Retention-Horizon & Duplicate Events
3. **Objective**: Align `AuditEventValidator` (`max_past_age`) with the 36-month retention horizon, ensure delayed and out-of-order events within the retention window are ingested and sorted accurately by `occurred_at` while preserving distinct `received_at`, and verify that duplicate `event_id` handling never triggers historical updates.
4. **Architectural Purpose**: Guarantees predictable lifecycle behavior across normal, delayed, out-of-order, and expired-timestamp submissions without weakening the append-only invariant.
5. **Scope**:
   - **Update `AuditEventValidationLimits` in `src/audit/domain/audit_event_validator.hpp`**:
     - Align `max_past_age` default with the 36-month retention horizon (`std::chrono::hours{24 * 1095}` = `26,280 hours` / `36 months`, configurable from `RetentionConfig::retention_days`).
     - Events with `occurred_at < now - max_past_age` are rejected deterministically with `AuditValidationErrorCode::ClockSkewTooOld` before entering the ingestion queue or creating already-expired historical partitions in ClickHouse.
     - Delayed or out-of-order events within `[now - max_past_age, now + 5 min]` are accepted with their original producer `occurred_at` and authoritative server `received_at = now`.
6. **Explicit Out-of-Scope**: Changing the ClickHouse engine from `MergeTree` to `ReplacingMergeTree` (strictly preserving `MergeTree` per `05-audit-data-model.md` §5.28).
7. **Dependencies**: `AUDIT-002-T02`, `AUDIT-006`, `AUDIT-008-T01`.
8. **Files to Create/Modify**:
   - `src/audit/domain/audit_event_validator.hpp`
   - `src/audit/domain/audit_event_validator.cpp`
   - `tests/unit/audit/audit_event_validator_test.cpp`

---

### AUDIT-008-T05 — Operational & Architecture Documentation for Retention & Least-Privilege Model

1. **Ticket ID**: `AUDIT-008-T05`
2. **Title**: Documentation of 36-Month TTL Asynchronous Semantics, RBAC Model & Lifecycle Boundaries
3. **Objective**: Document the operational permissions model (`audit_user` vs. `audit_migrator`), the `occurred_at`-based 36-month TTL behavior, the asynchronous nature of ClickHouse MergeTree TTL merges, out-of-order/delayed event handling, and development environment verification methodology in `docs/design/audit-design.md` and `docs/data-model/05-audit-data-model.md`.
4. **Architectural Purpose**: Satisfies all documentation acceptance criteria of `AUDIT-008`, ensuring operators and security auditors have an accurate reference of what ClickHouse TTL guarantees and how routine credentials are locked down.
5. **Scope**:
   - Update `docs/design/audit-design.md` (§7.20) and `docs/data-model/05-audit-data-model.md` (§5.26–5.28) with:
     - **Least-Privilege Access Matrix**: Table comparing `audit_user` (runtime service: `SELECT`, `INSERT` only on `audit_events`) vs. `audit_migrator` (schema initializer: `CREATE TABLE`, `ALTER TTL`, `OPTIMIZE`).
     - **Asynchronous TTL Execution Semantics**: Explicit explanation that ClickHouse `TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE` reclaims expired rows during background `MergeTree` merges (`merge_with_ttl_timeout`) rather than providing instantaneous, exact-to-the-second physical deletion, and that active database TTL is distinct from encrypted backup retention.
     - **Out-of-Order & Delayed Event Semantics**: How `occurred_at` vs. `received_at` behave when producer outboxes replay delayed events after a network partition.
6. **Explicit Out-of-Scope**: Cryptographic checkpoints (explicitly deferred per `05-audit-data-model.md` §5.30).
7. **Dependencies**: `AUDIT-008-T01` through `AUDIT-008-T04`.
8. **Files to Create/Modify**:
   - `docs/design/audit-design.md`
   - `docs/data-model/05-audit-data-model.md`

---

### AUDIT-008-T06 — Schema Introspection, Append-Only Guard, RBAC Denial & Controlled-Timestamp TTL Test Suite

1. **Ticket ID**: `AUDIT-008-T06`
2. **Title**: Unit & Live ClickHouse Integration Suite for 36-Month TTL Expiration, RBAC Denial & Append-Only Safeguards
3. **Objective**: Implement automated unit and live ClickHouse integration tests verifying effective schema/TTL introspection, `AppendOnlySqlGuard` enforcement, controlled-timestamp 36-month TTL expiration without waiting 36 months, and ClickHouse RBAC rejection of `UPDATE`/`DELETE`/`TRUNCATE`/`DROP` under `audit_user`.
4. **Architectural Purpose**: Provides empirical, reproducible proof that the 36-month retention policy and append-only safeguards function as specified.
5. **Scope**:
   - **Unit Test Suite: `tests/unit/audit/audit_retention_and_append_only_test.cpp`**:
     - **Test 1 (`RetentionConfigDefaultsTo36Months1095Days`)**: Verifies `AuditConfig` defaults and validation bounds for `retention_months` (`36`) and `retention_days` (`1095`).
     - **Test 2 (`AppendOnlySqlGuardPermitsSelectAndInsertOnly`)**: Verifies valid `SELECT ... FROM securecloud_audit.audit_events` and `INSERT INTO securecloud_audit.audit_events` pass.
     - **Test 3 (`AppendOnlySqlGuardBlocksUpdateDeleteTruncateDropAndMultiStatement`)**: Verifies `ALTER TABLE ... UPDATE`, `ALTER TABLE ... DELETE`, `DELETE FROM ...`, `TRUNCATE TABLE ...`, `DROP TABLE ...`, and `; DROP TABLE` throw `AppendOnlyViolationException` before reaching the HTTP client.
     - **Test 4 (`SchemaVerificationReportRejectsMissingTtlOrReceivedAtTtl`)**: Verifies `SchemaInitializer::verify_create_table_ddl()` accepts `TTL toDateTime(occurred_at) + INTERVAL 36 MONTH` and rejects DDL missing `TTL` or using `TTL toDateTime(received_at) + ...`.
     - **Test 5 (`DelayedAndOutOfOrderEventsAcceptedWhilePreHorizonEventsRejected`)**: Verifies events with `occurred_at` 6 months in the past (delayed replay) or out-of-order sequence pass validation and preserve `occurred_at != received_at`, whereas events with `occurred_at` 37 months in the past (`> 36 months`) are rejected with `ClockSkewTooOld`.
   - **Live ClickHouse Integration Test Suite: `tests/integration/audit_retention_integration_test.cpp`**:
     - **Test 1 (`EffectiveSchemaPartitioningOrderingAndTtlVerifiedInSystemTables`)**: Connects to ClickHouse 24.8, runs `SchemaInitializer::initialize_schema()` twice (verifying idempotent repeatability), and queries `system.tables` to assert `engine == "MergeTree"`, `partition_key == "toYYYYMM(occurred_at)"`, `sorting_key == "occurred_at, producer_service, event_type, event_id"`, and `TTL` expression `toDateTime(occurred_at) + toIntervalMonth(36)`.
     - **Test 2 (`ControlledTimestampTtlExpirationRemoves37MonthOldRowWhilePreservingRecentRows`)**:
       - Inserts 3 isolated test events into a test/isolated `audit_events` table (or partition) using controlled `occurred_at` timestamps while `received_at` is set to `now()`:
         1. Event $E_{\text{expired}}$: `occurred_at = now() - 37 months` (`received_at = now()`).
         2. Event $E_{\text{boundary}}$: `occurred_at = now() - 35 months` (`received_at = now()`).
         3. Event $E_{\text{recent}}$: `occurred_at = now() - 1 hour` (`received_at = now()`).
       - Triggers ClickHouse TTL merge evaluation (`OPTIMIZE TABLE ... FINAL` via `audit_migrator`).
       - Queries the table and verifies:
         - $E_{\text{expired}}$ (`37 months` old by `occurred_at`, even though `received_at` is `now()`) has been **automatically removed by ClickHouse TTL**! (Proving both that 36-month TTL works and that it uses `occurred_at`, not `received_at`.)
         - $E_{\text{boundary}}$ (`35 months` old) and $E_{\text{recent}}$ (`1 hour` old) remain intact and queryable.
     - **Test 3 (`RoutineApplicationUserCannotUpdateDeleteTruncateOrDropAuditEvents`)**:
       - Using `audit_user` credentials, verifies `insert_batch` and `query_by_time_range` succeed, while raw HTTP requests attempting `ALTER TABLE securecloud_audit.audit_events UPDATE actor_id = 'forged' WHERE 1=1`, `ALTER TABLE securecloud_audit.audit_events DELETE WHERE 1=1`, `TRUNCATE TABLE securecloud_audit.audit_events`, and `DROP TABLE securecloud_audit.audit_events` are rejected by ClickHouse with HTTP 403 / error code `497 (ACCESS_DENIED)`.
6. **Explicit Out-of-Scope**: Waiting 36 real-time calendar months in CI.
7. **Dependencies**: `AUDIT-008-T01` through `AUDIT-008-T05`.
8. **Files to Create/Modify**:
   - `tests/unit/audit/audit_retention_and_append_only_test.cpp`
   - `tests/integration/audit_retention_integration_test.cpp`
   - `tests/unit/CMakeLists.txt`
   - `tests/integration/CMakeLists.txt`

---

## 6. Traceability Matrix: Card Requirements to Tickets

| Card Scope / Acceptance Requirement | Enforcing Ticket(s) | Key Verification Mechanism |
| :--- | :--- | :--- |
| **Effective ClickHouse schema implements the approved 36-month TTL using `occurred_at` (never `received_at`)** | `AUDIT-008-T01`, `T03`, `T06` | `001_create_audit_events_table.sql` (`TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE`) + `system.tables` introspection test |
| **Monthly partitioning (`toYYYYMM(occurred_at)`) and ordering remain consistent with the Audit data model** | `AUDIT-008-T01`, `T03`, `T06` | Verified in `SchemaInitializer::verify_effective_schema()` against `system.tables` |
| **Routine application permissions (`audit_user`) limited to required operations (`SELECT`, `INSERT`)** | `AUDIT-008-T02`, `T06` | `init-clickhouse.sql` RBAC separation (`audit_user` vs `audit_migrator`) + live ClickHouse `ACCESS_DENIED` negative tests |
| **Normal application paths cannot update or delete historical records** | `AUDIT-008-T02`, `T03`, `T06` | `AppendOnlySqlGuard` in `ClickHouseClient` + ClickHouse `REVOKE ALTER, DELETE, TRUNCATE, DROP` on `audit_events` |
| **Define & test behavior for old, delayed, out-of-order, and duplicate events** | `AUDIT-008-T04`, `T06` | `AuditEventValidator` (`max_past_age = 36 months`) + out-of-order/delayed unit tests + coordination with `AUDIT-006` |
| **Verify retention behavior using controlled timestamps without waiting 36 months** | `AUDIT-008-T06` | `ControlledTimestampTtlExpirationRemoves37MonthOldRowWhilePreservingRecentRows` integration test (`occurred_at = now - 37m`, `received_at = now`) |
| **Document asynchronous TTL semantics and operational permissions** | `AUDIT-008-T05` | Updated `docs/design/audit-design.md` and `docs/data-model/05-audit-data-model.md` |
| **Schema initialization and migration are reproducible and tested; no unrelated persistence modified** | `AUDIT-008-T01`, `T02`, `T06` | Idempotent `SchemaInitializer` + `scripts/verify-persistence-infra.sh` pass |

---

## 7. Implementation & Verification Protocol for Lorenzo

1. **Sequential Ticket Execution**:
   - Execute `AUDIT-008-T01` $\to$ `T02` $\to$ `T03` $\to$ `T04` $\to$ `T05` $\to$ `T06` in order, presenting an implementation plan before each ticket and awaiting explicit approval.
2. **Full Repository Verification Gate**:
   - Run `python3 scripts/verify-local.py` (and `scripts/verify-persistence-infra.sh` when testing live ClickHouse containers) before proposing a commit message.
3. **Strict Commit Governance**:
   - Never execute `git commit` or `git push` until the proposed commit message has been explicitly validated by Sergey.

