# AUDIT-007 — Implement Audit Query and Investigation API
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: AUDIT-007  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)   
**Date**: October 28, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-007** specifies and implements the authoritative, **read-only Audit Query & Security Investigation API** (`AuditQueryService`) for the **SecureCloud Audit Service** (`securecloud-audit`).

As defined in **ADR-001**, **ADR-004**, **ADR-005**, **ADR-006**, **ADR-008**, **ADR-010**, `docs/design/audit-design.md` (Sections 7.18, 7.19, 7.21, 7.24), and `docs/data-model/05-audit-data-model.md` (Sections 5.17–5.19), the Audit Service owns the centralized ClickHouse analytical audit store (`securecloud_audit.audit_events`). While `AUDIT-004`–`AUDIT-006` establish the write-path ingestion pipeline, `AUDIT-007` establishes the **isolated, read-only investigation plane** enabling authorized internal callers to filter, inspect, and paginate historical security and operational events without risking full-table scans, memory exhaustion, SQL injection, unauthorized cross-service data exposure, or ingestion starvation.

### Key Architectural Invariants & Non-Negotiable Constraints

1. **Strict Read-Only Execution Plane (`docs/data-model/05-audit-data-model.md` §5.26, Card Constraint)**:
   - The query API is **strictly read-only**. No query handler, service method, or repository query path may ever issue `INSERT`, `ALTER`, `UPDATE`, `DELETE`, `TRUNCATE`, or `OPTIMIZE` statements.
   - All ClickHouse query requests executed by `AuditQueryRepository` run with ClickHouse HTTP query setting `readonly=1` and bounded execution deadlines (`max_execution_time`, `max_result_rows`, `max_result_bytes`).
2. **Isolated Query Concurrency Bulkhead (`docs/design/audit-design.md` §7.21, `AuditConfig::QueryConfig`)**:
   - Query execution operates in a dedicated concurrency domain (`QueryConfig::workers = 4`, `query_timeout_ms = 10000`, `QueryBulkheadLimiter`) completely decoupled from the ingestion worker pool (`IngestionConfig::workers = 8`).
   - Slow or concurrent analytical queries **cannot** starve or block audit event ingestion. When all query worker slots are saturated, additional query requests fail fast with `grpc::StatusCode::RESOURCE_EXHAUSTED`.
3. **Mandatory Bounded Time-Range Window & Scan Prevention (`05-audit-data-model.md` §5.17–5.19)**:
   - The ClickHouse table `audit_events` is partitioned by `toYYYYMM(occurred_at)` and ordered by `(occurred_at, producer_service, event_type, event_id)`.
   - Unrestricted full-table scans are prohibited:
     - Every general filter query (`QueryAuditEvents`) **must** specify a valid half-open time window `[start_occurred_at_ms, end_occurred_at_ms)` where `start_occurred_at_ms < end_occurred_at_ms` and `(end - start) <= max_query_window_ms` (default: `7 days`, maximum configurable: `31 days` = 1 monthly partition). If omitted, a bounded default window (e.g., last `24 hours` up to `now`) is applied.
     - Even for `GetAuditEventById(event_id)` and `QueryByCorrelationId(correlation_id)`, queries enforce a bounded time window: for `event_id` (UUIDv7), the embedded 48-bit UTC millisecond timestamp (`event_id.timestamp_ms()`) automatically bounds `occurred_at` to `[ts - 10 min, ts + 10 min]`, turning a full-table scan into a single-granule primary-key range lookup!
4. **Deterministic Keyset Pagination Over ClickHouse Ordering Key**:
   - Standard `OFFSET N` pagination in analytical databases degrades linearly ($O(N)$) and suffers from row duplication or omission when concurrent batches are inserted.
   - `AUDIT-007` implements **deterministic keyset cursor pagination** aligned with the exact ClickHouse sorting key `(occurred_at, producer_service, event_type, event_id)` (ascending or descending chronological order). An opaque, HMAC/structured Base64URL `page_token` encodes the last seen tuple `(occurred_at_ms, producer_service, event_type, event_id)` plus a SHA-256 digest of the immutable query filter parameters (preventing filter tampering across pages).
5. **Parameterized / Escaped SQL Binding — Zero Arbitrary SQL Execution**:
   - User- or caller-supplied filter strings (`event_type`, `actor_id`, `target_id`, `correlation_id`) are **never** interpolated raw into SQL queries.
   - All filters are first validated against strict domain regex/length rules (`AuditQueryFilterValidator`) and bound via ClickHouse native HTTP parameterized query parameters (`param_<name>=...` with `{name:Type}` placeholders in the SQL template).
6. **Least-Privilege mTLS Caller Authorization & Scope Enforcement**:
   - There is **no public unauthenticated query endpoint**. All callers must authenticate over internal mTLS 1.3 (`SC-010`).
   - Authorization is enforced by `AuditQueryAuthorizer` before any query is executed:
     - **`audit.securecloud.internal` (Internal Audit / Security Investigation Tooling)**: Authorized for global cross-service investigation across all producers, event types, actors, targets, and correlation IDs.
     - **`gateway.securecloud.internal` (API Gateway Administrative Proxy)**:
       - *Documented Dependency / Blocker Gate*: Because SecureCloud's human Security Administrator RBAC claim/role contract at the Gateway is not yet finalized in an approved ADR, `AuditQueryAuthorizer` rejects Gateway-proxied query requests by default (`PERMISSION_DENIED`: `"Human operator audit query role contract not yet enabled"`) unless explicitly enabled with a verified internal admin mTLS identity/context, preventing any premature exposure of audit queries on public Gateway routes.
     - **Runtime Producer Services (`auth`, `messaging`, `files`)**: By default restricted from arbitrary cross-service browsing; if permitted for self-service operational diagnostics, strictly scoped to `producer_service == caller_service` (attempts to query another service's audit trail fail closed with `PERMISSION_DENIED`).
7. **Self-Auditing of Investigation Queries (`docs/design/audit-design.md` §7.19)**:
   - Every audit query execution (whether authorized or rejected for `PERMISSION_DENIED`) emits an internal audit record (`audit.query.executed` or `audit.query.denied` with `producer_service = "audit"`, caller identity, filter summary, and result count) so administrative investigation is itself auditable.

---

## 2. Architectural Deep-Dive: Query Model, Pagination & ClickHouse Alignment

### 2.1 End-to-End Query Execution Pipeline

```text
  Authenticated mTLS Caller
  (e.g., audit.securecloud.internal)
                 │
                 │ gRPC over mTLS 1.3 (Port 50055)
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 1. AuditQueryServiceImpl (gRPC Transport & Deadline Guard)              │
  │    • Checks ServerContext cancellation & extracts remaining deadline    │
  │    • Extracts PeerIdentity (SAN/CN) from mTLS auth_context              │
  └──────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 2. AuditQueryAuthorizer (Access Control & Scope Boundary)               │
  │    • Verifies authenticated mTLS service identity                       │
  │    • Enforces global vs. producer-scoped vs. denied caller rules        │
  │    • Rejects unauthorized scope with PERMISSION_DENIED                  │
  └──────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 3. AuditQueryValidator (Filter, Window & Cursor Bounds Enforcer)        │
  │    • Validates [start_occurred_at_ms, end_occurred_at_ms) <= max_window │
  │    • Clamps page_size to [1, max_page_limit] (default 100, max 1000)    │
  │    • Validates identifier charsets (no control chars, SQL metachars)    │
  │    • Verifies page_token filter-hash integrity                          │
  └──────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 4. QueryBulkheadLimiter (Workload Isolation from Ingestion)             │
  │    • Acquires 1 of N=4 query worker slots (non-blocking / bounded wait) │
  │    • Fails fast with RESOURCE_EXHAUSTED if query bulkhead saturated     │
  └──────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 5. ClickHouseAuditEventRepository (Parameterized Read-Only Query)       │
  │    • Binds {start_ms:Int64}, {end_ms:Int64}, etc. via HTTP params       │
  │    • Enforces readonly=1, max_execution_time, LIMIT (page_size + 1)     │
  │    • Streams & deserializes up to page_size AuditEvent domain records   │
  └──────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 6. Response Mapper & Self-Audit Emitter                                 │
  │    • Constructs next_page_token if (rows_returned == page_size + 1)     │
  │    • Maps canonical AuditEvent records to AuditEventRecordProto         │
  │    • Records internal audit.query.executed telemetry/audit event        │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

### 2.2 Supported Investigation Query Patterns & ClickHouse Index Alignment

In `docs/data-model/05-audit-data-model.md` (§5.17–5.19), the ClickHouse table definition is:
```sql
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (occurred_at, producer_service, event_type, event_id)
```

All 7 required filter dimensions in `AUDIT-007` are mapped to parameterized SQL predicates aligned with this physical layout:

| Filter Dimension | Request Field(s) | ClickHouse Parameterized Predicate | Partition / Primary Index Utilization |
| :--- | :--- | :--- | :--- |
| **1. Time Range (Mandatory)** | `start_occurred_at_ms`, `end_occurred_at_ms` | `occurred_at >= fromUnixTimestamp64Milli({start_ms:Int64}) AND occurred_at < fromUnixTimestamp64Milli({end_ms:Int64})` | Prunes monthly partitions (`toYYYYMM`) and narrows primary key index range on `occurred_at`. |
| **2. Producer Service** | `repeated ProducerServiceProto producer_services` | `producer_service IN {producers:Array(String)}` (or `= {producer:String}`) | Matches 2nd column of sorting key `(occurred_at, producer_service, ...)`. |
| **3. Event Type** | `repeated string event_types` | `event_type IN {event_types:Array(String)}` (exact canonical match, e.g. `'auth.login.failed'`) | Matches 3rd column of sorting key `(occurred_at, producer_service, event_type, ...)`. |
| **4. Severity** | `repeated SeverityProto severities` | `severity IN {severities:Array(String)}` (e.g. `['SECURITY', 'CRITICAL']`) | Filtered via `LowCardinality(String)` dictionary encoding. |
| **5. Actor Identity** | `optional ActorTypeProto actor_type`, `optional string actor_id` | `actor_type = {actor_type:String} AND actor_id = {actor_id:String}` | Filtered within the bounded `[start_occurred_at, end_occurred_at)` granules. |
| **6. Target Identity** | `optional TargetTypeProto target_type`, `optional string target_id` | `target_type = {target_type:String} AND target_id = {target_id:String}` | Filtered within the bounded `[start_occurred_at, end_occurred_at)` granules. |
| **7. Correlation ID** | `optional string correlation_id` | `correlation_id = {correlation_id:UUID}` (combined with bounded time window `[start_occurred_at, end_occurred_at)`) | Bounded time range prevents full-history scan across all 36 monthly partitions. |
| **8. Single Event Lookup** | `string event_id` (`GetAuditEventById`) | `occurred_at >= fromUnixTimestamp64Milli({uuid_ts_min:Int64}) AND occurred_at <= fromUnixTimestamp64Milli({uuid_ts_max:Int64}) AND event_id = {event_id:UUID}` | Extracts 48-bit timestamp from UUIDv7 `event_id` ($\pm 10\text{ min}$ skew window) for $O(1)$ granule lookup! |

#### Deduplication Awareness at Query Time (Coordination with `AUDIT-006`):
- Because `AUDIT-006` documents that rare duplicate `event_id` rows can occur in ClickHouse after an Audit Service restart or ambiguous write timeout, `AuditQueryRepository` uses deterministic `LIMIT 1 BY event_id` (or `argMin` / `DISTINCT ON (occurred_at, producer_service, event_type, event_id)`) within the page query so duplicate physical rows for the same logical `event_id` are never returned twice to investigation callers!

---

### 2.3 Deterministic Keyset Cursor Pagination (`AuditPageCursor`)

To guarantee deterministic ordering without duplicates or omissions across pages:

1. **Canonical Sort Order**:
   - Ascending (`SORT_ORDER_ASC`):
     ```sql
     ORDER BY occurred_at ASC, producer_service ASC, event_type ASC, event_id ASC
     ```
   - Descending (`SORT_ORDER_DESC`, default for security investigations):
     ```sql
     ORDER BY occurred_at DESC, producer_service DESC, event_type DESC, event_id DESC
     ```
2. **Keyset Seek Predicate**:
   - When `page_token` is provided, it decodes to `AuditPageCursor`:
     - `last_occurred_at_ms` (`int64_t`)
     - `last_producer_service` (`std::string`)
     - `last_event_type` (`std::string`)
     - `last_event_id` (`EventId`)
     - `filter_fingerprint` (`std::array<uint8_t, 16>` — truncated SHA-256 of the query filter parameters & sort direction)
   - If the caller modifies any filter parameter while reusing an old `page_token`, `filter_fingerprint` mismatches and `AuditQueryValidator` immediately rejects the request with `INVALID_ARGUMENT` (`"Pagination token does not match query filter parameters"`).
   - For `SORT_ORDER_ASC`, the SQL query appends the tuple inequality:
     ```sql
     AND (occurred_at, producer_service, event_type, event_id) >
         (fromUnixTimestamp64Milli({cursor_ts:Int64}), {cursor_prod:String}, {cursor_type:String}, {cursor_id:UUID})
     ```
     (and `<` for `SORT_ORDER_DESC`).
3. **`page_size + 1` Lookahead**:
   - Requesting `page_size = L` executes `LIMIT L + 1` in ClickHouse.
   - If `<= L` rows are returned, `has_more = false` and `next_page_token = ""`.
   - If `L + 1` rows are returned, the $(L+1)$-th row is popped, `has_more = true`, and `next_page_token` is encoded from the $L$-th row's `(occurred_at, producer_service, event_type, event_id)`.

---

### 2.4 Caller Authorization Matrix & Human Operator Dependency Gate

| Authenticated mTLS Peer SAN / CN | Mapped Identity | Permitted Query Scope | Enforcement Behavior |
| :--- | :--- | :--- | :--- |
| `audit.securecloud.internal` | `ServiceRole::AuditInternal` | **Full Investigation Scope**: All producers, event types, severities, actors, targets, and correlation IDs. | Permitted when mTLS peer certificate is verified by `ProducerIdentityValidator`. |
| `auth.securecloud.internal` | `ServiceRole::RuntimeProducer(Auth)` | **Self-Producer Scope Only** (if operational self-query enabled): `producer_service` filter must equal `PRODUCER_SERVICE_AUTH`. | Any query omitting `producer_service = AUTH` or requesting another producer is rejected with `PERMISSION_DENIED`. |
| `messaging.securecloud.internal` | `ServiceRole::RuntimeProducer(Messaging)` | **Self-Producer Scope Only**: `producer_service` filter must equal `PRODUCER_SERVICE_MESSAGING`. | Cross-service queries rejected with `PERMISSION_DENIED`. |
| `files.securecloud.internal` | `ServiceRole::RuntimeProducer(Files)` | **Self-Producer Scope Only**: `producer_service` filter must equal `PRODUCER_SERVICE_FILES`. | Cross-service queries rejected with `PERMISSION_DENIED`. |
| `gateway.securecloud.internal` | `ServiceRole::GatewayEdge` | **Blocked by Default (Documented Blocker Gate)**: Human operator RBAC/MFA token claims are not yet specified in an approved ADR. | Rejected with `PERMISSION_DENIED` (`"Operator query access via Gateway requires an approved Admin RBAC contract"`), unless `producer_service = GATEWAY` self-scope. Never exposed as a public REST endpoint! |
| Unauthenticated / Unknown SAN | `Unauthorized` | **None** | Rejected at perimeter with `UNAUTHENTICATED` / `PERMISSION_DENIED`. |

---

## 3. Configuration Model Extensions (`AuditConfig::QueryConfig`)

In `src/audit/audit_config.hpp` and `src/audit/audit_config.cpp`, `QueryConfig` already defines:
- `workers{4}` (`[1, 32]`, env `SECURECLOUD_AUDIT_QUERY_WORKERS`)
- `max_page_limit{1000}` (`[10, 10000]`, env `SECURECLOUD_AUDIT_MAX_PAGE_LIMIT`)
- `default_page_limit{100}` (`[1, max_page_limit]`, env `SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT`)
- `query_timeout_ms{10000}` (`[500, 60000]`, env `SECURECLOUD_AUDIT_QUERY_TIMEOUT_MS`)

`AUDIT-007` extends `QueryConfig` with explicit time-window bounds to prevent unbounded multi-year scans:

| Parameter | C++ Field (`QueryConfig`) | Environment Variable | Default Value | Validated Range | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Default Query Window (hours) | `default_time_window_hours` | `SECURECLOUD_AUDIT_DEFAULT_QUERY_WINDOW_HOURS` | `24` (1 day) | `[1, max_time_window_hours]` | Applied when caller omits `start_occurred_at_ms` / `end_occurred_at_ms` |
| Max Query Window (hours) | `max_time_window_hours` | `SECURECLOUD_AUDIT_MAX_QUERY_WINDOW_HOURS` | `744` (31 days) | `[1, 2160]` (up to 90 days) | Prevents unrestricted multi-partition full-table scans |
| Max Result Bytes | `max_result_bytes` | `SECURECLOUD_AUDIT_QUERY_MAX_RESULT_BYTES` | `16777216` (16 MiB) | `[1048576, 67108864]` | Bounds ClickHouse HTTP response size in memory |

---

## 4. Dependency Graph

```text
                AUDIT-001 (AuditConfig & QueryConfig Bounds)
                AUDIT-002 (AuditEvent, EventId UUIDv7, ProducerIdentityValidator)
                AUDIT-003 (ClickHouseClient, Serializer & ClickHouseAuditEventRepository)
                AUDIT-004 (Authenticated mTLS gRPC Server Foundation)
                AUDIT-006 (Event Deduplication & Canonical Event Semantics)
                                          │
                                          ▼
                                    AUDIT-007-T01
                        (Protobuf Query Contract `AuditQueryService`,
                         Domain Filter Models & Keyset Page Cursor Codec)
                                          │
                                          ▼
                                    AUDIT-007-T02
                        (Deterministic Query Filter Validator, Time-Window
                         Bounds Enforcer & Authorization Policy Engine)
                                          │
                                          ▼
                                    AUDIT-007-T03
                        (Parameterized ClickHouse Query Builder &
                         Read-Only Repository Execution with UUIDv7
                         Partition Pruning & Keyset Pagination)
                                          │
                                          ▼
                                    AUDIT-007-T04
                        (Application Query Service, Query Bulkhead
                         Concurrency Limiter & Self-Audit Telemetry)
                                          │
                                          ▼
                                    AUDIT-007-T05
                        (gRPC `AuditQueryServiceImpl`, Deadline/Cancellation
                         Propagation & Sanitized Error Mapping)
                                          │
                                          ▼
                                    AUDIT-007-T06
                        (Exhaustive Unit, SQL-Injection Defense, Pagination,
                         Authorization & Live ClickHouse Integration Suite)
```

---

## 5. Implementation Tickets for Developer Lorenzo

### AUDIT-007-T01 — Protobuf Query Contract, Domain Filter Models & Keyset Cursor Codec

1. **Ticket ID**: `AUDIT-007-T01`
2. **Title**: Protobuf Query Contract (`AuditQueryService`), Domain Filter Value Objects & Keyset Pagination Cursor Codec
3. **Objective**: Extend `proto/securecloud/audit/v1/audit.proto` with the read-only `AuditQueryService` contract, define strongly typed C++20 query filter and result structs, and implement the tamper-evident keyset pagination cursor encoder/decoder (`AuditPageCursorCodec`).
4. **Architectural Purpose**: Establishes the canonical wire contract for security investigations (including `received_at_ms` in returned records) and deterministic cursor pagination without exposing internal ClickHouse offsets.
5. **Scope**:
   - **Extend `proto/securecloud/audit/v1/audit.proto`**:
     ```protobuf
     enum SortOrderProto {
       SORT_ORDER_UNSPECIFIED = 0;
       SORT_ORDER_DESC = 1; // Default: newest occurred_at first
       SORT_ORDER_ASC = 2;  // Oldest occurred_at first
     }

     // Read-only wire representation of a persisted audit event (includes received_at_ms).
     message PersistedAuditEventProto {
       AuditEventProto event = 1;
       int64 received_at_ms = 2;
     }

     message QueryAuditEventsRequest {
       optional int64 start_occurred_at_ms = 1;
       optional int64 end_occurred_at_ms = 2;
       repeated ProducerServiceProto producer_services = 3;
       repeated string event_types = 4;
       repeated SeverityProto severities = 5;
       optional ActorTypeProto actor_type = 6;
       optional string actor_id = 7;
       optional TargetTypeProto target_type = 8;
       optional string target_id = 9;
       optional string correlation_id = 10;
       uint32 page_size = 11;
       string page_token = 12;
       SortOrderProto sort_order = 13;
     }

     message QueryAuditEventsResponse {
       repeated PersistedAuditEventProto events = 1;
       string next_page_token = 2;
       bool has_more = 3;
       uint32 effective_page_size = 4;
     }

     message GetAuditEventByIdRequest {
       string event_id = 1; // RFC 9562 UUIDv7
     }

     message GetAuditEventByIdResponse {
       optional PersistedAuditEventProto event = 1;
     }

     service AuditQueryService {
       rpc QueryAuditEvents(QueryAuditEventsRequest) returns (QueryAuditEventsResponse);
       rpc GetAuditEventById(GetAuditEventByIdRequest) returns (GetAuditEventByIdResponse);
     }
     ```
   - **Extend `src/audit/audit_config.hpp` and `src/audit/audit_config.cpp`**:
     - Add `default_time_window_hours{24}`, `max_time_window_hours{744}`, and `max_result_bytes{16777216}` to `QueryConfig` with fail-closed validation (`default_time_window_hours <= max_time_window_hours`).
   - **Create `src/audit/query/audit_query_types.hpp` and `src/audit/query/audit_page_cursor.hpp|.cpp`**:
     - Define `SortOrder`, `AuditQueryFilter`, `AuditPageCursor`, and `AuditQueryPageResult`.
     - Implement `AuditPageCursorCodec::encode(const AuditPageCursor& cursor)` and `decode(std::string_view token, const std::array<uint8_t, 16>& expected_filter_hash)`:
       - Serializes `(occurred_at_ms, producer_service, event_type, event_id, sort_order, filter_hash)` into Base64URL and verifies `expected_filter_hash` in constant time (`CRYPTO_memcmp`) upon decoding so tampered or mismatched cursors fail closed.
6. **Explicit Out-of-Scope**: ClickHouse SQL generation (T03) and gRPC service handlers (T05).
7. **Dependencies**: `AUDIT-001`, `AUDIT-002`.
8. **Files to Create/Modify**:
   - `proto/securecloud/audit/v1/audit.proto`
   - `src/audit/audit_config.hpp`
   - `src/audit/audit_config.cpp`
   - `src/audit/domain/audit_event_mapper.hpp`
   - `src/audit/domain/audit_event_mapper.cpp`
   - `src/audit/query/audit_query_types.hpp`
   - `src/audit/query/audit_page_cursor.hpp`
   - `src/audit/query/audit_page_cursor.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-007-T02 — Deterministic Query Filter Validator & Caller Authorization Engine

1. **Ticket ID**: `AUDIT-007-T02`
2. **Title**: Query Filter Validator, Time-Window Enforcer & mTLS Query Authorization Engine
3. **Objective**: Implement `AuditQueryValidator` to enforce time-range bounds, filter format rules, and pagination limits, and implement `AuditQueryAuthorizer` to enforce mTLS caller authorization and scope isolation before any database query is executed.
4. **Architectural Purpose**: Protects ClickHouse against unrestricted multi-partition scans, malformed filter strings, and unauthorized cross-service data snooping.
5. **Scope**:
   - **Create `src/audit/query/audit_query_validator.hpp` and `.cpp`**:
     - Enforces:
       1. **Time Window Validation**:
          - If both `start_occurred_at` and `end_occurred_at` are omitted, defaults to `[now - default_time_window_hours, now + 5 min]`.
          - If only one bound is provided without the other, rejects with `MissingTimeRangeBound` (`INVALID_ARGUMENT`).
          - If `start_occurred_at >= end_occurred_at`, rejects with `InvalidTimeRangeOrder`.
          - If `(end_occurred_at - start_occurred_at) > max_time_window_hours`, rejects with `TimeWindowExceeded` (`INVALID_ARGUMENT`: `"Requested time window exceeds maximum allowed duration"`).
       2. **Pagination Limit Validation**:
          - If `page_size == 0`, sets `effective_page_size = config.query.default_page_limit` (`100`).
          - If `page_size > config.query.max_page_limit` (`1000`), rejects explicitly with `PageSizeExceeded` (`INVALID_ARGUMENT`).
       3. **Filter Field Sanity & Injection Defense**:
          - `event_types`: max 20 items; each item must match `^[a-z0-9_]+(\\.[a-z0-9_]+)+$` (length $\le 64$).
          - `actor_id` / `target_id`: if specified, corresponding `actor_type` / `target_type` must not be `Unspecified`; length $\le 128$, strictly printable ASCII without control characters, null bytes, or quotes.
          - `correlation_id`: if specified, length $\le 64$, valid UUID or printable ASCII correlation token.
          - `page_token`: if non-empty, decodes via `AuditPageCursorCodec::decode()` and verifies filter fingerprint match.
   - **Create `src/audit/query/audit_query_authorizer.hpp` and `.cpp`**:
     - Evaluates `PeerIdentity` (from mTLS certificate SAN/CN):
       - Unauthenticated peer $\to$ `QueryAuthStatus::Unauthenticated` (`UNAUTHENTICATED`).
       - `audit.securecloud.internal` $\to$ `QueryAuthStatus::AuthorizedGlobal`.
       - `auth.securecloud.internal`, `messaging.securecloud.internal`, `files.securecloud.internal` $\to$ `QueryAuthStatus::AuthorizedProducerScoped`:
         - Verifies that `filter.producer_services` is non-empty and contains **only** the caller's own `ProducerService`. Otherwise rejects with `QueryAuthStatus::ForbiddenScope` (`PERMISSION_DENIED`).
       - `gateway.securecloud.internal` $\to$ rejects cross-service queries with `QueryAuthStatus::ForbiddenOperatorContractNotEnabled` (`PERMISSION_DENIED`) unless querying `ProducerService::Gateway` self-scope, enforcing the card's architectural constraint that human operator access is not exposed without an approved operator RBAC specification.
6. **Explicit Out-of-Scope**: Executing SQL against ClickHouse (T03).
7. **Dependencies**: `AUDIT-007-T01`, `AUDIT-002-T04`.
8. **Files to Create/Modify**:
   - `src/audit/query/audit_query_validator.hpp`
   - `src/audit/query/audit_query_validator.cpp`
   - `src/audit/query/audit_query_authorizer.hpp`
   - `src/audit/query/audit_query_authorizer.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-007-T03 — Parameterized ClickHouse Query Builder & Read-Only Repository Implementation

1. **Ticket ID**: `AUDIT-007-T03`
2. **Title**: Parameterized ClickHouse Query Builder, Keyset Pagination & UUIDv7 Partition Pruning
3. **Objective**: Implement `ClickHouseQueryBuilder` and extend `ClickHouseAuditEventRepository` to execute read-only (`readonly=1`), parameterized (`param_<name>`) queries aligned with `(occurred_at, producer_service, event_type, event_id)` and bounded memory limits.
4. **Architectural Purpose**: Guarantees that user-supplied filter values can never become executable SQL syntax, prevents full-table scans, and ensures deterministic keyset pagination and duplicate suppression (`LIMIT 1 BY event_id`).
5. **Scope**:
   - **Create `src/audit/repository/clickhouse_query_builder.hpp` and `.cpp`**:
     - Produces a `ParameterizedClickHouseQuery`:
       ```cpp
       struct ParameterizedClickHouseQuery {
           std::string sql_template;
           std::map<std::string, std::string> bind_params; // Sent as HTTP query params param_<key>=<url_encoded_val>
       };
       ```
     - **`build_filter_query(const ValidatedAuditQuery& query)`**:
       - Constructs `SELECT event_id, occurred_at, received_at, event_type, severity, producer_service, producer_instance, actor_type, actor_id, target_type, target_id, correlation_id, causation_id, event_data FROM securecloud_audit.audit_events`.
       - Always includes `WHERE occurred_at >= fromUnixTimestamp64Milli({start_ms:Int64}) AND occurred_at < fromUnixTimestamp64Milli({end_ms:Int64})`.
       - Appends typed placeholder predicates (`{producer_0:String}`, `{event_type_0:String}`, `{severity_0:String}`, `{actor_type:String}`, `{actor_id:String}`, `{target_type:String}`, `{target_id:String}`, `{correlation_id:String}`) only for active filters.
       - Appends keyset tuple predicate when `cursor.has_value()`:
         ```sql
         AND (occurred_at, producer_service, event_type, event_id) <
             (fromUnixTimestamp64Milli({cursor_ts:Int64}), {cursor_prod:String}, {cursor_type:String}, {cursor_id:UUID})
         ```
         (for `DESC`, or `>` for `ASC`).
       - Appends `ORDER BY occurred_at DESC, producer_service DESC, event_type DESC, event_id DESC` (or `ASC`), `LIMIT 1 BY event_id`, and `LIMIT {limit_plus_one:UInt32}`.
     - **`build_get_by_id_query(const domain::EventId& event_id)`**:
       - Extracts `ts_ms = event_id.timestamp_ms()` and bounds `occurred_at` to `[ts_ms - 600000, ts_ms + 600000]` ($\pm 10\text{ minutes}$, exceeding the 5-minute max clock skew enforced by `AuditEventValidator`) so ClickHouse prunes all partitions and granules outside that 20-minute window before matching `AND event_id = {event_id:UUID} LIMIT 1`.
   - **Extend `ClickHouseClient` & `ClickHouseAuditEventRepository`**:
     - Pass `readonly=1`, `max_execution_time=<seconds>`, and `max_result_bytes=<bytes>` on all `execute_query` HTTP requests.
     - Enforce response body size cap (`config.query.max_result_bytes`) during HTTP stream reading to prevent unbounded memory allocation.
6. **Explicit Out-of-Scope**: Threadpool bulkhead management (T04).
7. **Dependencies**: `AUDIT-003`, `AUDIT-007-T01`, `AUDIT-007-T02`.
8. **Files to Create/Modify**:
   - `src/audit/repository/clickhouse_query_builder.hpp`
   - `src/audit/repository/clickhouse_query_builder.cpp`
   - `src/audit/repository/audit_event_repository_interface.hpp`
   - `src/audit/repository/clickhouse_audit_event_repository.hpp`
   - `src/audit/repository/clickhouse_audit_event_repository.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-007-T04 — Application Query Service, Query Bulkhead Limiter & Self-Audit Telemetry

1. **Ticket ID**: `AUDIT-007-T04`
2. **Title**: `AuditQueryApplicationService`, Query Concurrency Bulkhead & Self-Auditing Telemetry
3. **Objective**: Implement `AuditQueryApplicationService` orchestrating authorization, validation, bulkhead concurrency acquisition (`QueryConfig::workers`), repository execution, pagination token construction, and self-auditing telemetry.
4. **Architectural Purpose**: Enforces strict separation of concerns (`Authorization -> Validation -> Bulkhead -> Repository -> Response Mapping`) and ensures query workloads are isolated from ingestion capacity.
5. **Scope**:
   - **Create `src/audit/query/query_bulkhead_limiter.hpp`**:
     - RAII semaphore/counter bounding concurrent in-flight queries to `config.query.workers` (default `4`).
     - If all slots are occupied, `try_acquire()` returns an invalid lease immediately and increments `audit_query_bulkhead_rejections_total`, allowing the caller to receive `RESOURCE_EXHAUSTED` without queuing unbounded threads.
   - **Create `src/audit/query/audit_query_application_service.hpp` and `.cpp`**:
     - `execute_query(const domain::PeerIdentity& caller, const AuditQueryFilter& raw_filter, std::chrono::milliseconds deadline)`
     - `get_event_by_id(const domain::PeerIdentity& caller, std::string_view event_id_str, std::chrono::milliseconds deadline)`
     - Emits structured self-audit log/metric events (`audit_queries_executed_total`, `audit_queries_denied_total`, `audit_query_latency_ms`) containing caller SAN, filter dimensions used (without logging sensitive values), and row count returned.
6. **Explicit Out-of-Scope**: gRPC server registration (T05).
7. **Dependencies**: `AUDIT-007-T01`, `AUDIT-007-T02`, `AUDIT-007-T03`.
8. **Files to Create/Modify**:
   - `src/audit/query/query_bulkhead_limiter.hpp`
   - `src/audit/query/audit_query_application_service.hpp`
   - `src/audit/query/audit_query_application_service.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-007-T05 — gRPC `AuditQueryServiceImpl`, Deadline Propagation & Sanitized Error Mapping

1. **Ticket ID**: `AUDIT-007-T05`
2. **Title**: gRPC `AuditQueryServiceImpl`, Deadline/Cancellation Propagation & Sanitized Status Mapping
3. **Objective**: Implement `securecloud::audit::v1::AuditQueryService::Service` in `AuditQueryServiceImpl`, register it on `AuditServer` (mTLS port `50055`), propagate client deadlines to ClickHouse queries, and map all domain/repository errors to sanitized gRPC status codes.
4. **Architectural Purpose**: Exposes the internal mTLS gRPC query endpoint with deterministic error handling that never leaks ClickHouse connection strings, internal SQL templates, or stack traces.
5. **Scope**:
   - **Create `src/audit/service/audit_query_service_impl.hpp` and `.cpp`**:
     - Implements `QueryAuditEvents` and `GetAuditEventById`.
     - Checks `context->IsCancelled()` before and after query execution.
     - Computes effective timeout as `min(remaining_grpc_deadline, config.query.query_timeout_ms)`.
     - Deterministic gRPC status mapping:
       - `Unauthenticated` $\to$ `grpc::StatusCode::UNAUTHENTICATED`
       - `ForbiddenScope` / `ForbiddenOperatorContractNotEnabled` $\to$ `grpc::StatusCode::PERMISSION_DENIED`
       - `ValidationError` (invalid window, malformed filter, tampered cursor, page_size > max) $\to$ `grpc::StatusCode::INVALID_ARGUMENT`
       - `BulkheadExhausted` $\to$ `grpc::StatusCode::RESOURCE_EXHAUSTED`
       - `ClickHouseTimeoutException` / deadline expired $\to$ `grpc::StatusCode::DEADLINE_EXCEEDED`
       - `ClickHouseConnectionException` / `ClickHouseQueryException` $\to$ `grpc::StatusCode::UNAVAILABLE` (with generic message `"Audit storage temporarily unavailable"`).
   - **Register `AuditQueryServiceImpl` in `src/audit/audit_server.hpp` and `.cpp`**.
6. **Explicit Out-of-Scope**: Public HTTP Gateway routes (explicitly prohibited until human operator RBAC is specified).
7. **Dependencies**: `AUDIT-004`, `AUDIT-007-T04`.
8. **Files to Create/Modify**:
   - `src/audit/service/audit_query_service_impl.hpp`
   - `src/audit/service/audit_query_service_impl.cpp`
   - `src/audit/audit_server.hpp`
   - `src/audit/audit_server.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-007-T06 — Exhaustive Unit, SQL-Injection Defense, Pagination, Authorization & Integration Test Suite

1. **Ticket ID**: `AUDIT-007-T06`
2. **Title**: Unit, SQL-Injection Defense, Keyset Pagination, Authorization & Live ClickHouse Integration Suite
3. **Objective**: Build a comprehensive unit and integration test suite verifying every filter dimension, combination queries, keyset pagination stability, SQL injection prevention, caller authorization scope, bulkhead isolation, and live ClickHouse query execution.
4. **Architectural Purpose**: Proves that `AUDIT-007` meets all security, functional, and performance acceptance criteria.
5. **Scope**:
   - **Unit Test Suite 1: `tests/unit/audit/audit_query_validator_and_cursor_test.cpp`**:
     - **Test 1 (`ValidFilterAndDefaultWindowPasses`)**: Omitted timestamps default to `[now - 24h, now + 5m]`; omitted `page_size` defaults to `100`.
     - **Test 2 (`RejectsInvertedAndExcessiveTimeWindows`)**: `start >= end` and `(end - start) > 31 days` rejected with `INVALID_ARGUMENT`.
     - **Test 3 (`RejectsOversizedPageLimit`)**: `page_size = 1001` (> `max_page_limit = 1000`) rejected explicitly.
     - **Test 4 (`CursorRoundtripAndFilterTamperDetection`)**: Valid cursor decodes cleanly; changing `producer_service` or `severity` while reusing `page_token` fails with `CursorFilterMismatch`.
     - **Test 5 (`SqlMetacharacterAndInjectionStringsRejectedAtValidationAndBoundSafely`)**: Payloads such as `actor_id = "user1' OR '1'='1; DROP TABLE audit_events; --"` are rejected by validator charset rules and, even in `ClickHouseQueryBuilder`, are bound strictly as out-of-line `param_actor_id` values rather than interpolated into SQL.
   - **Unit Test Suite 2: `tests/unit/audit/audit_query_authorizer_test.cpp`**:
     - **Test 1 (`AuditInternalIdentityPermittedGlobalQueries`)**: `audit.securecloud.internal` allowed to query across all producers.
     - **Test 2 (`RuntimeProducerPermittedSelfScopeOnly`)**: `auth.securecloud.internal` allowed when `producer_services == {AUTH}`, rejected with `PERMISSION_DENIED` when querying `MESSAGING` or omitting producer filter.
     - **Test 3 (`GatewayCallerBlockedFromGlobalOperatorQueriesByDefault`)**: `gateway.securecloud.internal` rejected with `PERMISSION_DENIED` when attempting cross-service investigation.
     - **Test 4 (`UnauthenticatedCallerRejected`)**: Missing mTLS identity rejected with `UNAUTHENTICATED`.
   - **Unit Test Suite 3: `tests/unit/audit/audit_query_service_test.cpp`**:
     - Tests each filter independently and in combination (`occurred_at`, `producer_service`, `event_type`, `severity`, `actor_type` + `actor_id`, `target_type` + `target_id`, `correlation_id`).
     - Tests multi-page keyset pagination (`DESC` and `ASC`) across 250 events (3 pages of 100, 100, 50) verifying zero duplicates and zero omitted events, including when multiple events share the exact same `occurred_at_ms`.
     - Tests `GetAuditEventById` UUIDv7 timestamp window pruning and non-existent ID empty response.
     - Tests `QueryBulkheadLimiter` saturation (`RESOURCE_EXHAUSTED`), ClickHouse timeout (`DEADLINE_EXCEEDED`), and ClickHouse unavailability (`UNAVAILABLE` with sanitized error).
   - **Live Integration Suite: `tests/integration/audit_query_integration_test.cpp`**:
     - Seeds live ClickHouse 24.8 with multi-service events (`auth`, `messaging`, `files`, `gateway`) across multiple timestamps and severities, and verifies end-to-end mTLS gRPC `QueryAuditEvents` and `GetAuditEventById`, pagination, and read-only immutability (`readonly=1`).
6. **Explicit Out-of-Scope**: Retention TTL expiration tests (covered in `AUDIT-008`).
7. **Dependencies**: `AUDIT-007-T01` through `AUDIT-007-T05`.
8. **Files to Create/Modify**:
   - `tests/unit/audit/audit_query_validator_and_cursor_test.cpp`
   - `tests/unit/audit/audit_query_authorizer_test.cpp`
   - `tests/unit/audit/audit_query_service_test.cpp`
   - `tests/integration/audit_query_integration_test.cpp`
   - `tests/unit/CMakeLists.txt`
   - `tests/integration/CMakeLists.txt`

---

## 6. Traceability Matrix: Card Requirements to Tickets

| Card Scope / Acceptance Requirement | Enforcing Ticket(s) | Key Verification Mechanism |
| :--- | :--- | :--- |
| **Support filtering by `occurred_at`, `producer_service`, `event_type`, `severity`, `actor`, `target`, `correlation_id`** | `AUDIT-007-T01`, `T03`, `T06` | `QueryAuditEventsRequest` + `ClickHouseQueryBuilder` + individual & combined filter unit/integration tests |
| **Enforce time-range, page-size, and result limits; prevent unrestricted full-table scans** | `AUDIT-007-T01`, `T02`, `T03` | `AuditQueryValidator` (`max_time_window_hours = 744`, `max_page_limit = 1000`) + UUIDv7 timestamp pruning on `GetAuditEventById` |
| **Deterministic pagination & ordering without duplicates or omissions** | `AUDIT-007-T01`, `T03`, `T06` | Keyset cursor over `(occurred_at, producer_service, event_type, event_id)` + `LIMIT 1 BY event_id` + 250-event multi-page test |
| **Enforce query authorization before data is returned; document human operator dependency** | `AUDIT-007-T02`, `T06` | `AuditQueryAuthorizer` mTLS SAN binding + producer self-scope restriction + Gateway operator blocker gate |
| **User-supplied filters cannot become arbitrary SQL** | `AUDIT-007-T02`, `T03`, `T06` | Strict charset/format validation + ClickHouse native HTTP `param_<name>` parameterized placeholders |
| **Audit queries are strictly read-only and isolated from ingestion capacity** | `AUDIT-007-T03`, `T04`, `T06` | ClickHouse `readonly=1` query setting + `QueryBulkheadLimiter` (`QueryConfig::workers = 4`) |
| **Handle query timeouts and ClickHouse failures predictably without leaking internal details** | `AUDIT-007-T05`, `T06` | Deadline propagation + sanitized `DEADLINE_EXCEEDED` / `UNAVAILABLE` mapping |

---

## 7. Implementation & Verification Protocol for Lorenzo

1. **Sequential Ticket Execution**:
   - Execute `AUDIT-007-T01` $\to$ `T02` $\to$ `T03` $\to$ `T04` $\to$ `T05` $\to$ `T06` in order, presenting an implementation plan before each ticket and awaiting explicit approval.
2. **Full Repository Verification Gate**:
   - Run `python3 scripts/verify-local.py` after each ticket before proposing a commit message.
3. **Strict Commit Governance**:
   - Never execute `git commit` or `git push` until the proposed commit message has been explicitly validated by Sergey.
