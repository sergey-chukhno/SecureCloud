# AUDIT-003 — Implement ClickHouse Schema and Repository
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: AUDIT-003  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: October 22, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-003** establishes the authoritative **ClickHouse 24.8** analytical storage schema, database migration tooling, client connectivity engine, and repository abstraction (`ClickHouseAuditEventRepository`) for the **SecureCloud Audit Service** (`securecloud-audit`).

As defined in **ADR-001**, **ADR-006**, **ADR-010**, and `docs/data-model/05-audit-data-model.md`, the Audit Service owns the centralized, immutable security and operational audit trail for SecureCloud. ClickHouse is selected as the dedicated persistence technology because the audit workload is append-heavy, chronologically ordered, high-volume, and primarily queried by time-range filtering and analytical aggregations rather than relational joins.

### Key Invariants & Architectural Boundaries for AUDIT-003

1. **Sole Database Ownership (ADR-006, Audit Data Model 5.1, 5.4)**:
   The Audit Service is the sole application owner of the ClickHouse database (`securecloud_audit`). No other runtime microservice (Gateway, Auth, Messaging, Files) possesses credentials or network permissions to connect to or query ClickHouse.
2. **Append-Only Immutability (Audit Data Model 5.15, 5.16)**:
   Audit records are immutable upon creation. The underlying table uses the ClickHouse `MergeTree` engine. Normal application operations must **never** execute `UPDATE`, `ALTER ... DELETE`, or `TRUNCATE` operations on historical audit records.
3. **Partitioning & Ordering Key Alignment (Audit Data Model 5.17, 5.18)**:
   - Partitioning: `PARTITION BY toYYYYMM(occurred_at)` to enable coarse-grained monthly data lifecycle and retention management without daily partition sprawl.
   - Ordering Key: `ORDER BY (occurred_at, producer_service, event_type, event_id)`. `occurred_at` provides primary chronological scan efficiency; `producer_service` and `event_type` provide investigation locality; `event_id` (UUIDv7) ensures deterministic tie-breaking.
4. **Hexagonal Repository Decoupling (ADR-002, SC-011)**:
   Domain entities (`AuditEvent`, `EventId`) and application services depend strictly on a pure abstract repository interface (`IAuditEventRepository`). Zero SQL strings, ClickHouse-specific headers, or network transport types may leak into domain logic.
5. **Connection Management & Bounded Operation Deadlines (ADR-010, SC-011)**:
   ClickHouse is accessed via its HTTP interface (default port `8123`) using HTTP/1.1 persistent connections, parameterized query execution, bounded connection timeouts (`connect_timeout_ms`), and request execution deadlines (`request_timeout_ms`).
6. **Zero Plaintext & Failure Sanitization Guard (ADR-008)**:
   Database failure logs, serialization error traces, and exception messages must **never** dump full event payloads or sensitive metadata into standard error or application log files.
7. **Parameterized & Escaped Query Execution**:
   All dynamic query filters (time boundaries, producer names, event types) must be safely parameterized or formatted using typed value converters to prevent SQL injection vulnerabilities.

---

## 2. Dependency Graph

```text
               AUDIT-001 (Audit Config & Startup Foundation)
               AUDIT-002 (Canonical Audit Event Model & Validation)
               SC-011 (ClickHouse Persistence Infrastructure)
                            │
                            ▼
                      AUDIT-003-T01
            (ClickHouse DDL Migration Script &
             Reproducible Database Initializer)
                            │
                            ▼
                      AUDIT-003-T02
            (Low-Level ClickHouse HTTP Client &
             Connection Pool Abstraction)
                            │
                            ▼
                      AUDIT-003-T03
            (ClickHouse TabSeparated / JSON Row
             Serializer & Deserializer Engine)
                            │
                            ▼
                      AUDIT-003-T04
            (ClickHouseAuditEventRepository Port
             & Standard Analytical Query Patterns)
                            │
                            ▼
                      AUDIT-003-T05
            (Repository Error Taxonomy, Retry Policy
             & Bulkhead Deadline Protection)
                            │
                            ▼
                      AUDIT-003-T06
            (Unit Test Mocks & Hermetic Live ClickHouse
             24.8 Integration Test Suite)
```

---

## 3. Implementation Tickets for Developer Lorenzo

### AUDIT-003-T01 — ClickHouse DDL Migration Script & Reproducible Database Initializer

1. **Ticket ID**: `AUDIT-003-T01`
2. **Title**: ClickHouse DDL Migration Script & Database Schema Versioning Engine
3. **Objective**: Create the authoritative ClickHouse schema DDL migration script for `securecloud_audit.audit_events` and an automated schema initializer compatible with both local development and Docker Compose test harnesses.
4. **Scope**:
   - Create migration directory `src/audit/migrations/` and initial migration `001_create_audit_events_table.sql`.
   - Implement the exact table DDL specified in `docs/data-model/05-audit-data-model.md`:
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
     ORDER BY (occurred_at, producer_service, event_type, event_id);
     ```
   - Implement `SchemaInitializer` utility in `src/audit/repository/schema_initializer.hpp` and `.cpp` that executes idempotent DDL on startup or test setup.
   - Support `IF NOT EXISTS` semantics and database existence validation.
5. **Acceptance Criteria**:
   - The schema is reproducibly applied against ClickHouse 24.8.
   - Verification script `scripts/verify-persistence-infra.sh` confirms table creation.
   - Correct data types, partition key, and sorting keys are confirmed via `system.tables` and `system.columns`.

---

### AUDIT-003-T02 — Low-Level ClickHouse HTTP Client & Connection Pool Abstraction

1. **Ticket ID**: `AUDIT-003-T02`
2. **Title**: Low-Level ClickHouse HTTP Client & Connection Lifecycle Manager
3. **Objective**: Implement a high-performance C++20 HTTP client abstraction tailored for ClickHouse's HTTP interface (port 8123) with connection pooling, keep-alive, authentication, and bounded timeout enforcement.
4. **Scope**:
   - Create `src/audit/repository/clickhouse_client.hpp` and `.cpp`.
   - Leverage `securecloud::httplib` (already available in `SecureCloudDependencies.cmake`) to communicate with ClickHouse over HTTP/1.1.
   - Configure basic auth using `config.clickhouse.user` and `config.clickhouse.password.value()`.
   - Implement `execute_query(const std::string& query, std::chrono::milliseconds timeout)`.
   - Implement `execute_insert(const std::string& query, const std::string& body_data, std::chrono::milliseconds timeout)`.
   - Support HTTP compression (`gzip` or `lz4` if supported by client, or plain raw stream).
   - Implement connection health check `ping()`: executes `SELECT 1` with a sub-second deadline.
5. **Acceptance Criteria**:
   - Bounded connection and request deadlines are strictly respected; hanging queries abort cleanly.
   - Basic authentication headers are transmitted securely without leaking credentials into error messages.
   - Connection pool reuses sockets across sequential requests, minimizing TCP handshake overhead.

---

### AUDIT-003-T03 — ClickHouse Row Serializer & Deserializer Engine

1. **Ticket ID**: `AUDIT-003-T03`
2. **Title**: High-Throughput Row Serializer & Deserializer for Canonical Audit Events
3. **Objective**: Implement fast, zero-allocation-focused serialization of `AuditEvent` instances into ClickHouse `TabSeparated` / `JSONCompactEachRow` format, and deserialization of query response streams back into `AuditEvent` domain objects.
4. **Scope**:
   - Create `src/audit/repository/clickhouse_event_serializer.hpp` and `.cpp`.
   - Implement `serialize_for_insert(const std::vector<AuditEvent>& events) -> std::string`:
     - Format: `TabSeparated` or `JSONEachRow`. `TabSeparated` is recommended for ClickHouse ingest throughput.
     - Escape tabs, newlines, and backslashes in string fields (`producer_instance`, `actor_id`, `target_id`, `event_data`).
     - Format `DateTime64(3, 'UTC')` as `YYYY-MM-DD HH:MM:SS.mmm`.
     - Format UUIDv7 as standard 36-character hyphenated UUID strings (`018f6e-xxxx...`).
   - Implement `deserialize_from_query(const std::string& response_body) -> std::vector<AuditEvent>`:
     - Parses ClickHouse `JSONCompact` or `TabSeparatedWithNames` response streams.
     - Reconstructs strongly typed `AuditEvent` domain objects using `EventId::from_string` and ISO-8601 timestamps.
5. **Acceptance Criteria**:
   - Escaping correctly handles quotes, backslashes, tabs, and multiline JSON in `event_data`.
   - Round-trip serialization $\to$ insertion $\to$ query $\to$ deserialization preserves all canonical fields with zero loss of precision.

---

### AUDIT-003-T04 — Authoritative Audit Event Repository Implementation

1. **Ticket ID**: `AUDIT-003-T04`
2. **Title**: ClickHouseAuditEventRepository Implementation & Standard Query Patterns
3. **Objective**: Implement the authoritative repository class `ClickHouseAuditEventRepository` implementing `IAuditEventRepository` to support batch insertions and approved compliance query patterns.
4. **Scope**:
   - Create interface `src/audit/repository/audit_event_repository_interface.hpp`:
     ```cpp
     class IAuditEventRepository {
     public:
         virtual ~IAuditEventRepository() = default;
         virtual bool insert_batch(const std::vector<AuditEvent>& events) = 0;
         virtual std::vector<AuditEvent> query_by_time_range(
             std::chrono::system_clock::time_point start,
             std::chrono::system_clock::time_point end,
             uint32_t limit) = 0;
         virtual std::vector<AuditEvent> query_by_producer(
             const std::string& producer_service,
             std::chrono::system_clock::time_point start,
             std::chrono::system_clock::time_point end,
             uint32_t limit) = 0;
         virtual std::vector<AuditEvent> query_by_correlation_id(
             const CorrelationId& correlation_id,
             uint32_t limit) = 0;
         virtual std::optional<AuditEvent> find_by_event_id(const EventId& event_id) = 0;
     };
     ```
   - Implement `src/audit/repository/clickhouse_audit_event_repository.hpp` and `.cpp`.
   - Construct queries adhering to the sorting key prefix (`occurred_at`, `producer_service`, `event_type`, `event_id`).
   - Apply `LIMIT` clamping (default max 1000 items per query) to prevent memory exhaustion during analytical queries.
5. **Acceptance Criteria**:
   - `insert_batch` executes single-query batch insertions into ClickHouse.
   - All 4 standard query patterns execute efficiently and return chronologically ordered records.
   - Zero database logic or SQL constructs leak into domain services.

---

### AUDIT-003-T05 — Repository Error Taxonomy, Retry Policy & Bulkhead Protection

1. **Ticket ID**: `AUDIT-003-T05`
2. **Title**: ClickHouse Error Mapping, Exponential Backoff Retries & Bulkhead Protection
3. **Objective**: Map low-level HTTP/ClickHouse response errors into strongly typed domain exceptions and implement transient outage resilience with bulkhead backpressure.
4. **Scope**:
   - Create `src/audit/repository/audit_repository_exceptions.hpp`:
     - `ClickHouseException` (base)
     - `ClickHouseConnectionException` (network drops, connection refused)
     - `ClickHouseTimeoutException` (deadline exceeded)
     - `ClickHouseQueryException` (syntax, invalid table, server error)
   - Implement retry policy for idempotent reads and batch inserts with exponential backoff and jitter for transient connection drops.
   - Implement Bulkhead concurrency limiter on repository queries (e.g. max 16 concurrent database queries per `config.clickhouse.max_connections`).
   - Log database failure status codes and error reasons without reflecting raw event contents.
5. **Acceptance Criteria**:
   - HTTP 4xx, 5xx, socket timeouts, and connection refused map deterministically into explicit exception types.
   - Transient network glitches trigger bounded retries; permanent errors fail fast without retry storms.
   - Error logs contain zero event payloads or user secrets.

---

### AUDIT-003-T06 — Hermetic Unit Test Suite & Live ClickHouse 24.8 Integration Test Suite

1. **Ticket ID**: `AUDIT-003-T06`
2. **Title**: Unit Mocks & Live ClickHouse 24.8 E2E Integration Test Suite
3. **Objective**: Build an exhaustive test suite covering serializer edge cases, mock repository operations, and live end-to-end database integration tests against ClickHouse 24.8.
4. **Scope**:
   - Create unit tests in `tests/unit/audit/clickhouse_event_serializer_test.cpp`:
     - Escaping special characters (`\t`, `\n`, `\0`, `\`, quotes, Unicode).
     - Timestamp formatting and sub-millisecond precision.
     - Empty batch handling.
   - Create unit tests in `tests/unit/audit/clickhouse_client_test.cpp` with mocked HTTP responses.
   - Create live integration test `tests/integration/audit_clickhouse_integration_test.cpp`:
     - Test 1: Schema creation and idempotent re-initialization.
     - Test 2: Single event insert and exact read-back verification.
     - Test 3: Large batch insert (e.g. 500 events) and partition boundary validation (`toYYYYMM`).
     - Test 4: Time-range chronological query ordering.
     - Test 5: Producer-filtered query performance and accuracy.
     - Test 6: Correlation ID distributed trace reconstruction.
     - Test 7: Connection timeout and database outage recovery.
   - Register targets in `tests/unit/CMakeLists.txt` and `tests/integration/CMakeLists.txt`.
5. **Acceptance Criteria**:
   - All unit tests pass in under 5 seconds.
   - Live integration tests against ClickHouse container pass 100%.
   - Full clang-format adherence with zero violations.
