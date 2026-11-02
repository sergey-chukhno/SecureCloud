# AUDIT-006 — Implement Event Deduplication and Retry-Safe Acknowledgements
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: AUDIT-006  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: October 28, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-006** specifies and implements **event deduplication**, **payload conflict detection**, and **retry-safe durability acknowledgements** for the **SecureCloud Audit Service** (`securecloud-audit`).

As established in **ADR-006**, **ADR-007**, **ADR-008**, **ADR-010**, `docs/design/audit-design.md` (Sections 8.8–8.11), and `docs/data-model/05-audit-data-model.md` (Sections 5.6, 5.20–5.25), runtime microservices (`Gateway`, `Auth`, `Messaging`, `Files`) publish security and operational audit events asynchronously via their **Transactional Outbox** (`at-least-once` delivery). Because network connections can drop, gRPC calls can time out, outbox publishers can restart, or acknowledgements can be lost in transit, producers will legitimately re-submit the same logical audit event using its canonical producer-generated **UUIDv7** `event_id`.

`AUDIT-006` completes the ingestion reliability boundary started in `AUDIT-002`–`AUDIT-005` by replacing the provisional `IDeduplicationManager` stub from `AUDIT-005` with an authoritative, concurrency-safe **Two-Phase Idempotency & Deduplication Engine** (`BoundedDeduplicationCache` + `EventPayloadFingerprint`) tightly coordinated with the ClickHouse batch insertion pipeline (`BatchAggregator`, `InsertWorkerPool`, `ClickHouseAuditEventRepository`) and the gRPC acknowledgement contract (`AcknowledgementManager` / `AuditIngestionService`).

### Key Architectural Invariants & Non-Negotiable Constraints

1. **Canonical UUIDv7 Logical Identity (`docs/data-model/05-audit-data-model.md` §5.6, §5.24)**:
   - Every audit event carries a producer-generated RFC 9562 **UUIDv7** `event_id` (`securecloud::audit::domain::EventId`).
   - Producers **must** reuse the exact same `event_id` across all outbox retry attempts for the same logical event.
2. **At-Least-Once Delivery Without False Global Exactly-Once Claims (`docs/design/audit-design.md` §8.8)**:
   - Producer delivery is **at-least-once**.
   - ClickHouse (`ENGINE = MergeTree`) is an append-oriented analytical store without transactional `UNIQUE` constraints on `event_id`.
   - The in-memory deduplication cache is a **bounded optimization** (`100,000` recent IDs, `10-minute` TTL baseline) that eliminates ordinary retry duplicates within the active window. It is **not** an unbounded store and **not** the authoritative record of event durability.
   - Across Audit Service process restarts, cache eviction under extreme churn, or ambiguous database timeouts where ClickHouse committed a batch after client disconnect, rare duplicate rows in ClickHouse are an explicitly documented and accepted property of the MVP architecture, detectable analytically via `GROUP BY event_id HAVING count() > 1` (`05-audit-data-model.md` §5.25).
3. **Never Acknowledge Volatile Queue Insertion as Durable Acceptance (`RULES.md` §4, Card Constraint)**:
   - Enqueueing an event into the volatile `BoundedIngestionQueue` or `BatchAggregator` **never** constitutes durable acceptance and **never** marks the event as `COMMITTED` in the deduplication cache.
   - A positive durability acknowledgement (`SubmitAuditEventResponse{success=true}` or accepted status in `BatchSubmitAuditEventsResponse`) is emitted **if and only if**:
     1. The event's batch has been confirmed written by ClickHouse (`HTTP 200 OK`), **or**
     2. The event matches an already `COMMITTED` entry in the deduplication cache with an **identical payload fingerprint** (allowing the producer outbox to safely retire a previously persisted event whose original ACK was lost).
4. **Payload Conflict Detection — Never Silently Equate Materially Different Events**:
   - If a producer submits an `event_id` that already exists in the deduplication cache (`IN_FLIGHT` or `COMMITTED`)—or appears twice within the same batch—with a **different canonical payload fingerprint** (`SHA-256` over immutable domain fields, excluding service-assigned `received_at`), the Audit Service must **reject** the conflicting submission explicitly (`IdempotencyConflict` $\to$ `grpc::StatusCode::ALREADY_EXISTS` for single-event RPCs, or explicit per-item rejection in batch RPCs) and increment a security/integrity metric (`audit_dedup_payload_conflicts_total`). It must never silently treat conflicting payloads as idempotent successes.
5. **Concurrency-Safe In-Flight Coordination & Rollback on Persistence Failure**:
   - Concurrent requests carrying the same `event_id` (across gRPC threads or within the same `BatchSubmitAuditEventsRequest`) must be serialized atomically at the shard lock boundary so two copies cannot race past deduplication into ClickHouse.
   - While the primary submission is queued/inserting (`IN_FLIGHT`), concurrent duplicate submissions with the **same fingerprint** either coalesce onto the shared `AckPromise` (awaiting the primary batch's ClickHouse commit outcome) or, if deadline-constrained, receive a retryable status (`UNAVAILABLE` / `ABORTED`) so the producer outbox retains the event until durability is proven.
   - If a ClickHouse batch insert **fails** or results in an **ambiguous outcome** (e.g., socket timeout or connection reset after sending the HTTP POST), all `IN_FLIGHT` reservations for that batch **must be rolled back (evicted)** from the deduplication cache and all waiting callers notified with a retryable error (`UNAVAILABLE` or `DEADLINE_EXCEEDED`). An unconfirmed write must never leave a poisoned `COMMITTED` cache entry that would cause subsequent producer retries to be falsely acknowledged and dropped!
6. **Zero-Plaintext & Diagnostic Sanitization (`ADR-008`, `RULES.md` §7)**:
   - Payload conflict logs, deduplication traces, and error statuses must log only `event_id`, `producer_service`, `event_type`, and hex fingerprint digests—**never** raw `metadata` values or unvalidated input strings.

---

## 2. Architectural Deep-Dive & State Machine Specification

### 2.1 Canonical Payload Fingerprinting (`EventPayloadFingerprint`)

To detect buggy or malicious producers reusing an `event_id` for a materially different event while remaining insensitive to legitimate retry differences (such as `received_at`, which is assigned by the Audit Service on each intake attempt, or ` std::unordered_map` bucket ordering in `metadata`), `AUDIT-006` defines a deterministic **256-bit (`32-byte`) SHA-256 Canonical Payload Fingerprint** over `securecloud::audit::domain::AuditEvent`:

```text
SHA-256 Canonical Input Stream (Length-Prefixed Binary Encoding):
  1. event_id.bytes()                      (16 bytes, RFC 9562 UUIDv7)
  2. occurred_at_ms                        (int64 big-endian, UTC epoch milliseconds)
  3. event_type                            (uint32 length + UTF-8 bytes)
  4. severity                              (uint8 enum value)
  5. producer_service                      (uint8 enum value)
  6. producer_instance                     (uint32 length + UTF-8 bytes)
  7. actor_type                            (uint8 enum value)
  8. actor_id                              (uint32 length + UTF-8 bytes)
  9. target_type                           (uint8 enum value)
 10. target_id                             (uint32 length + UTF-8 bytes)
 11. correlation_id                        (uint32 length + UTF-8 bytes)
 12. causation_id_present + causation_id   (uint8 flag + optional uint32 length + UTF-8 bytes)
 13. sorted(metadata)                      (uint32 count + lexicographically sorted [key_len, key, val_len, val])
```

- **Excluded Field**: `received_at` is intentionally **excluded** from the fingerprint because `AuditEventMapper::to_domain` stamps `received_at = clock->now()` when each request arrives at the Audit Service.
- **Canonical Metadata Ordering**: Because `AuditEvent::metadata` is an `std::unordered_map<std::string, std::string>`, keys are sorted lexicographically prior to hashing so map iteration order never causes false conflicts.

---

### 2.2 Per-`EventId` Deduplication Lifecycle State Machine

Every `EventId` tracked by `BoundedDeduplicationCache` transitions through a strict, mutex-guarded state machine:

```text
                        ┌──────────────────────┐
                        │       UNSEEN         │
                        │ (Not in cache or     │
                        │  TTL-expired)        │
                        └──────────┬───────────┘
                                   │
                    try_acquire()  │  First valid submission
                    (reserves slot │  creates IN_FLIGHT entry
                     + fingerprint)│  with shared AckFuture
                                   ▼
                        ┌──────────────────────┐
        ┌───────────────┤      IN_FLIGHT       ├───────────────┐
        │               │ (Queued in pipeline  │               │
        │               │  or inserting into   │               │
        │               │  ClickHouse)         │               │
        │               └──────────┬───────────┘               │
        │                          │                           │
        │ Batch insert fails       │ ClickHouse HTTP 200 OK    │ Same event_id arrives
        │ OR ambiguous timeout     │ commit_batch()            │ while IN_FLIGHT:
        │ OR queue full rollback   │ (records committed_at     │  - Same fingerprint:
        │ abort_batch()            │  + server received_at +   │    attach to shared
        │                          │  starts 10-min TTL)       │    AckFuture (coalesce)
        ▼                          ▼                           │  - Diff fingerprint:
┌───────────────┐       ┌──────────────────────┐               │    REJECT immediately
│   EVICTED /   │       │      COMMITTED       │               │    (IdempotencyConflict)
│    UNSEEN     │       │ (Durably persisted   │               └───────────────┐
│ (Safe for     │       │  in ClickHouse;      │                               │
│  outbox retry)│       │  TTL = 10 minutes,   │◄──────────────────────────────┘
└───────────────┘       │  Capacity = 100,000) │
                        └───────┬──────┬───────┘
                                │      │
           Same event_id        │      │  TTL expires (> 10 min)
           arrives after commit:│      │  OR LRU eviction when
           - Same fingerprint:  │      │  COMMITTED count > 100,000
             Return cached      │      ▼
             Acknowledgement    │   ┌───────────────┐
             immediately (OK)   │   │   EVICTED /   │
           - Diff fingerprint:  │   │    UNSEEN     │
             REJECT immediately │   └───────────────┘
             (IdempotencyConflict)
```

#### Crucial State Machine Invariants:
1. **`IN_FLIGHT` Entries Are Pin-Protected Against Silent LRU Eviction**:
   - Only `COMMITTED` (or expired) entries may be evicted by LRU capacity pressure.
   - Because `max_queued_events = 10,000` (`AUDIT-005`) and `dedup_cache_capacity = 100,000`, `IN_FLIGHT` entries can never exceed `10%` of the cache capacity (`10,000 / 100,000`). Pinning `IN_FLIGHT` entries guarantees that in-flight deduplication and conflict detection can never be bypassed by cache churn while an event is still in the pipeline.
2. **Intra-Batch & Cross-Thread Coalescing**:
   - **Within a single `BatchSubmitAuditEventsRequest`**: If `event_id` $E$ appears at index $i$ and again at index $j$ ($i < j$):
     - If `fingerprint(E_i) == fingerprint(E_j)`: Only $E_i$ is enqueued for ClickHouse insertion; $E_j$ is coalesced onto $E_i$'s outcome and counted as idempotently accepted once $E_i$'s batch commits (preventing duplicate rows in the same ClickHouse `INSERT` block).
     - If `fingerprint(E_i) != fingerprint(E_j)`: $E_j$ is immediately rejected with `IDEMPOTENCY_CONFLICT` (`rejected_count++`, `rejected_event_ids.push_back(E)`).
   - **Across concurrent RPCs (`SubmitAuditEvent` / `BatchSubmitAuditEvents`)**:
     - If Producer Thread B submits $E$ with the **same fingerprint** while Producer Thread A's submission of $E$ is `IN_FLIGHT`, Thread B receives a `std::shared_future<PersistAckResult>` bound to Thread A's in-flight pipeline entry and waits (up to Thread B's gRPC deadline) for the exact same ClickHouse commit outcome.

---

### 2.3 Bounded Memory Footprint & Sharded Concurrency Design

To eliminate global lock contention across the 4 validation workers, 2 insert workers, and gRPC ingestion threads while strictly enforcing the **100,000-ID** capacity bound (`docs/data-model/05-audit-data-model.md` §5.24):

- **Sharded Architecture (`64` Lock-Striped Shards)**:
  - `BoundedDeduplicationCache` partitions the keyspace into `K = 64` independent shards indexed by the upper bits of `EventId` hash (`std::hash<EventId>{}(id) & 63`).
  - Each shard owns its own `std::mutex`, hash table (`std::unordered_map<EventId, std::list<CacheEntry>::iterator>`), and doubly linked LRU list (`std::list<CacheEntry>`), giving strict $O(1)$ lookup, $O(1)$ promotion/insertion, and $O(1)$ eviction with near-zero lock contention.
- **Exact Memory Footprint Calculation**:
  - Per `CacheEntry`:
    - `EventId` (`16 bytes`)
    - `EventPayloadFingerprint` (`32 bytes` SHA-256 digest)
    - `DedupState` (`1 byte` enum + padding)
    - `committed_received_at_ms` (`8 bytes` `int64_t`)
    - `expires_at` (`8 bytes` `std::chrono::steady_clock::time_point`)
    - `std::shared_future<PersistAckResult>` (`16 bytes`, non-null only while `IN_FLIGHT`)
    - `std::list` & `std::unordered_map` node pointers (~`64 bytes`)
  - Total per entry $\approx 144\text{ bytes}$.
  - At full capacity (`100,000` entries): $100,000 \times 144\text{ bytes} \approx \mathbf{14.4\text{ MiB}}$, well within container memory budgets and completely immune to unbounded growth.

---

### 2.4 Retry-Safe Persistence & Complete Outcome Taxonomy

The table below defines the authoritative behavior of the Audit Service across all ingestion, deduplication, persistence, and failure scenarios:

| Scenario | Cache State Before | ClickHouse Action | Cache State After | gRPC Response (`SubmitAuditEvent`) | Batch Response (`BatchSubmitAuditEvents`) | Producer Outbox Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. New Valid Event — Commit Succeeds** | `UNSEEN` $\to$ `IN_FLIGHT` | `INSERT INTO audit_events` returns `HTTP 200 OK` | `COMMITTED` (TTL `10m`) | `Status::OK` (`success=true`, `event_id`, `received_at_ms`) | `accepted_count++` | Mark event published / delete from outbox |
| **2. Duplicate Event (Same Payload) — Already Committed** | `COMMITTED` (Fingerprint matches) | **Skipped** (Zero DB write) | `COMMITTED` (LRU promoted) | `Status::OK` (`success=true`, `event_id`, original `received_at_ms`) | `accepted_count++` | Mark event published (recovers lost ACK!) |
| **3. Duplicate Event (Same Payload) — Currently In-Flight** | `IN_FLIGHT` (Fingerprint matches) | **Coalesced** (Awaits active batch insert) | Mirrors primary batch (`COMMITTED` on OK, `UNSEEN` on fail) | `Status::OK` if primary commits; `UNAVAILABLE` / `DEADLINE_EXCEEDED` if primary fails/times out | `accepted_count++` if primary commits; RPC fails/retries if batch write fails | Mark published on `OK`; retry on `UNAVAILABLE` |
| **4. Conflicting Payload with Same `event_id`** | `IN_FLIGHT` or `COMMITTED` (**Fingerprint mismatch**) | **Rejected** before queue/DB | Unchanged (`IN_FLIGHT` or `COMMITTED` preserved) | `Status::ALREADY_EXISTS` (`"Idempotency conflict: event_id already exists with different payload"`) | `rejected_count++`, `rejected_event_ids.push_back(id)` | Quarantine / mark permanent conflict error (do not retry infinitely) |
| **5. Domain / Schema / Sensitive-Data Validation Failure** | Not inserted (`UNSEEN`) | **Rejected** before queue/DB | `UNSEEN` | `Status::INVALID_ARGUMENT` (or `PERMISSION_DENIED` on mTLS mismatch) | `rejected_count++`, `rejected_event_ids.push_back(id)` | Quarantine permanent validation failure |
| **6. Ingestion Queue Full (Backpressure)** | Rolled back to `UNSEEN` | Not queued | `UNSEEN` | `Status::RESOURCE_EXHAUSTED` (`"Ingestion queue at capacity"`) | `Status::RESOURCE_EXHAUSTED` (entire batch RPC retried by outbox) | Keep in outbox; retry with exponential backoff |
| **7. ClickHouse Connection Refused / HTTP 5xx Failure** | `IN_FLIGHT` | `INSERT` fails before commit | **Rolled back to `UNSEEN`** (`abort_batch`) | `Status::UNAVAILABLE` | `Status::UNAVAILABLE` | Keep in outbox; retry with same `event_id` |
| **8. Ambiguous ClickHouse Outcome (Socket Timeout / Reset During POST)** | `IN_FLIGHT` | HTTP POST sent, response lost / timed out (commit unknown) | **Rolled back to `UNSEEN`** (`abort_batch`); metric `audit_ambiguous_writes_total++` | `Status::DEADLINE_EXCEEDED` or `Status::UNAVAILABLE` | `Status::DEADLINE_EXCEEDED` or `Status::UNAVAILABLE` | Keep in outbox; retry with same `event_id` (safe under at-least-once MergeTree model) |

#### Recovery from Ambiguous ClickHouse Outcomes & Process Restarts:
- **Why Ambiguous Writes Must Roll Back Cache State to `UNSEEN`**:
  When ClickHouse times out (`ClickHouseTimeoutException`) or drops the HTTP connection mid-POST, the Audit Service cannot know with certainty whether ClickHouse flushed the part to disk before the timeout or aborted it.
  - If the Audit Service marked the batch `COMMITTED` and returned `OK`, and ClickHouse had *not* committed the batch, **security audit events would be permanently lost** (violating the `Security -> Correctness -> Durability` hierarchy of `RULES.md`).
  - Therefore, the Audit Service **must** roll back the `IN_FLIGHT` cache entries to `UNSEEN` and return a retryable failure (`UNAVAILABLE` / `DEADLINE_EXCEEDED`) to the producer outbox.
  - When the producer retries with the same `event_id`, the Audit Service re-ingests the batch. If ClickHouse had failed the first write, the retry restores full durability. If ClickHouse had silently succeeded on the first write, the retry appends a second row with the identical `event_id`, which is benign in ClickHouse `MergeTree` and explicitly identifiable via the operational duplicate detection query (`05-audit-data-model.md` §5.25) or deduplicated at analytical query time (`FINAL` / `argMax` / `DISTINCT ON (event_id)`).

---

## 3. Configuration Model Extensions (`AuditConfig::IngestionConfig`)

In `src/audit/audit_config.hpp` and `src/audit/audit_config.cpp`, `IngestionConfig` is extended with bounded, validated deduplication parameters aligned with `docs/data-model/05-audit-data-model.md` (§5.21, §5.22, §5.24):

| Parameter | C++ Field (`IngestionConfig`) | Environment Variable | Default Value | Validated Range | Architectural Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Deduplication Cache Capacity | `dedup_cache_capacity` | `AUDIT_INGESTION_DEDUP_CACHE_CAPACITY` | `100000` | `[1000, 1000000]` | `05-audit-data-model.md` §5.24 (`100,000` recent IDs) |
| Deduplication Cache TTL (ms) | `dedup_cache_ttl_ms` | `AUDIT_INGESTION_DEDUP_CACHE_TTL_MS` | `600000` (10 min) | `[10000, 86400000]` (10s to 24h) | `05-audit-data-model.md` §5.24 (`10 minutes`) |
| Deduplication Shard Count | `dedup_cache_shards` | `AUDIT_INGESTION_DEDUP_CACHE_SHARDS` | `64` | Power of two in `[1, 256]` | Lock-striped concurrency isolation |
| In-Flight Wait Timeout (ms) | `in_flight_ack_timeout_ms` | `AUDIT_INGESTION_IN_FLIGHT_ACK_TIMEOUT_MS` | `5000` (5s) | `[500, 30000]` | Bounded wait for durable ClickHouse batch flush |

Additionally, `AuditConfig::load()` enforces the cross-field invariant:
- `dedup_cache_capacity >= max_queued_events` (ensuring `IN_FLIGHT` entries can never exhaust the deduplication cache capacity).

---

## 4. Dependency Graph

```text
                AUDIT-001 (AuditConfig & Startup Validation)
                AUDIT-002 (AuditEvent, EventId UUIDv7, AuditEventValidator, audit.proto)
                AUDIT-003 (ClickHouseAuditEventRepository & Error Taxonomy)
                AUDIT-004 (Authenticated gRPC Ingestion Endpoint)
                AUDIT-005 (Bounded Ingestion Queue, BatchAggregator & InsertWorkerPool)
                                          │
                                          ▼
                                    AUDIT-006-T01
                        (Canonical Event Payload Fingerprinting &
                         Idempotency Domain Contract / Config Bounds)
                                          │
                                          ▼
                                    AUDIT-006-T02
                        (Sharded Bounded Deduplication Cache:
                         IN_FLIGHT / COMMITTED State Machine,
                         100k LRU Eviction & 10-Min TTL Expiration)
                                          │
                                          ▼
                                    AUDIT-006-T03
                        (Retry-Safe Persistence Coordination &
                         Durable Acknowledgement Manager with
                         Batch Rollback & Ambiguous Write Handling)
                                          │
                                          ▼
                                    AUDIT-006-T04
                        (gRPC Ingestion Pipeline Wiring, Intra-Batch
                         Deduplication, Coalescing & Outbox-Compatible
                         Status Code Mapping)
                                          │
                                          ▼
                                    AUDIT-006-T05
                        (Observability Telemetry, Duplicate Detection
                         Verification Helper & Architecture Documentation
                         for Restart / Ambiguous Outcome Limits)
                                          │
                                          ▼
                                    AUDIT-006-T06
                        (Exhaustive Unit, Concurrency, Conflict,
                         Cache-Bound & Failure-Injection Test Suite)
```

---

## 5. Implementation Tickets for Developer Lorenzo

### AUDIT-006-T01 — Canonical Event Payload Fingerprinting & Idempotency Domain Contract

1. **Ticket ID**: `AUDIT-006-T01`
2. **Title**: Canonical Event Payload Fingerprinting, Idempotency Result Taxonomy & Configuration Bounds
3. **Objective**: Implement deterministic SHA-256 payload fingerprinting (`EventPayloadFingerprint`) over canonical `AuditEvent` fields (excluding `received_at`), define the strongly typed idempotency/acknowledgement domain contracts, and extend `AuditConfig::IngestionConfig` with validated deduplication bounds (`100,000` capacity, `10-minute` TTL).
4. **Architectural Purpose**: Provides the cryptographic/structural equivalence primitive required to distinguish legitimate producer retries (identical payload, same `event_id`) from conflicting payload submissions (materially different payload, same `event_id`) without retaining full 64 KB event bodies inside the deduplication cache.
5. **Scope**:
   - **Extend `src/audit/audit_config.hpp` and `src/audit/audit_config.cpp`**:
     - Add to `IngestionConfig`:
       ```cpp
       uint32_t dedup_cache_capacity{100000};     // [1000, 1000000] (100k baseline per 05-audit-data-model.md §5.24)
       uint32_t dedup_cache_ttl_ms{600000};       // [10000, 86400000] (10 minutes default)
       uint32_t dedup_cache_shards{64};           // Power of 2 in [1, 256]
       uint32_t in_flight_ack_timeout_ms{5000};   // [500, 30000]
       ```
     - Enforce fail-closed validation in `AuditConfig::load()`, including `dedup_cache_capacity >= max_queued_events`.
   - **Create `src/audit/domain/event_payload_fingerprint.hpp` and `.cpp`**:
     - Define `EventPayloadFingerprint`:
       ```cpp
       namespace securecloud::audit::domain {

       class EventPayloadFingerprint {
         public:
           using digest_type = std::array<uint8_t, 32>; // SHA-256

           constexpr EventPayloadFingerprint() noexcept = default;
           constexpr explicit EventPayloadFingerprint(const digest_type& digest) noexcept
               : digest_(digest) {}

           /// Computes canonical SHA-256 digest over all immutable AuditEvent fields
           /// (event_id, occurred_at_ms, event_type, severity, producer_service,
           ///  producer_instance, actor_type, actor_id, target_type, target_id,
           ///  correlation_id, causation_id, and lexicographically sorted metadata).
           /// Explicitly excludes service-assigned received_at.
           [[nodiscard]] static EventPayloadFingerprint compute(const AuditEvent& event);

           [[nodiscard]] constexpr const digest_type& bytes() const noexcept { return digest_; }
           [[nodiscard]] std::string to_hex_prefix(size_t byte_count = 8) const;

           constexpr bool operator==(const EventPayloadFingerprint& other) const noexcept = default;
           constexpr auto operator<=>(const EventPayloadFingerprint& other) const noexcept = default;

         private:
           digest_type digest_{};
       };

       } // namespace securecloud::audit::domain
       ```
     - Use OpenSSL `EVP_DigestInit_ex` / `EVP_sha256()` (already linked via `OpenSSL::Crypto`) with length-prefixed framing for every variable-length string and sorted metadata key-value pairs so no field concatenation ambiguity (`"ab" + "c"` vs `"a" + "bc"`) is possible.
   - **Create `src/audit/ingestion/idempotency_types.hpp`**:
     - Define strongly typed deduplication and persistence outcome enums and structs:
       ```cpp
       namespace securecloud::audit::ingestion {

       enum class DedupState : uint8_t {
           Unseen = 0,
           InFlight = 1,
           Committed = 2
       };

       enum class IngestionOutcomeStatus : uint8_t {
           PersistedNew = 0,          // Durably inserted into ClickHouse on this attempt
           DuplicateCommitted = 1,    // Already durably committed in ClickHouse; idempotent ACK
           DuplicateCoalesced = 2,    // Coalesced onto an in-flight batch that subsequently committed
           IdempotencyConflict = 3,   // Same event_id submitted with different payload fingerprint
           ValidationRejected = 4,    // Failed schema, UUIDv7, skew, or sensitive-data validation
           UnauthorizedProducer = 5,  // Failed mTLS producer identity binding
           QueueOverloaded = 6,       // BoundedIngestionQueue full (backpressure)
           PersistenceFailed = 7,     // ClickHouse insert failed deterministically (connection refused, 5xx)
           PersistenceAmbiguous = 8   // ClickHouse timeout/disconnect after send; commit unknown
       };

       struct PersistAckResult {
           IngestionOutcomeStatus status{IngestionOutcomeStatus::PersistenceFailed};
           domain::EventId event_id{};
           std::chrono::system_clock::time_point received_at{};
           std::string error_code;
           std::string diagnostic_message; // Strictly sanitized; zero raw payloads
       };

       } // namespace securecloud::audit::ingestion
       ```
   - Add `std::hash<securecloud::audit::domain::EventId>` specialization in `src/audit/domain/event_id.hpp` (using 64-bit mixing over the 16-byte UUIDv7 array).
6. **Explicit Out-of-Scope**: Cache storage structures (T02) and ClickHouse worker execution (T03).
7. **Dependencies**: `AUDIT-001`, `AUDIT-002`, `OpenSSL::Crypto`.
8. **Files to Create/Modify**:
   - `src/audit/audit_config.hpp`
   - `src/audit/audit_config.cpp`
   - `src/audit/domain/event_id.hpp`
   - `src/audit/domain/event_payload_fingerprint.hpp`
   - `src/audit/domain/event_payload_fingerprint.cpp`
   - `src/audit/ingestion/idempotency_types.hpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-006-T02 — Sharded Bounded Deduplication Cache (`IN_FLIGHT` & `COMMITTED` State Machine)

1. **Ticket ID**: `AUDIT-006-T02`
2. **Title**: Sharded Bounded Recent-Event Deduplication Cache with Two-Phase State Machine, TTL & LRU Eviction
3. **Objective**: Implement `IDeduplicationCache` and `BoundedDeduplicationCache` supporting `100,000` recent `EventId` entries across lock-striped shards, atomic `UNSEEN -> IN_FLIGHT -> COMMITTED` transitions, payload fingerprint verification, `IN_FLIGHT` coalescing futures, `10-minute` TTL expiration, and `IN_FLIGHT`-pinning LRU eviction.
4. **Architectural Purpose**: Enforces concurrency-safe deduplication so simultaneous duplicate RPCs cannot race past checks, while bounding memory strictly and preventing unconfirmed `IN_FLIGHT` events from being falsely treated as durable before ClickHouse commits.
5. **Scope**:
   - **Create `src/audit/ingestion/deduplication_cache.hpp` and `.cpp`**:
     - Define abstract interface `IDeduplicationCache` and concrete implementation `BoundedDeduplicationCache`:
       ```cpp
       struct DedupAcquireResult {
           enum class Decision : uint8_t {
               AcquiredNewInFlight = 0,      // Caller owns the primary pipeline slot and AckPromise
               CoalescedInFlight = 1,        // Another thread is currently processing identical event; attach to shared_future
               AlreadyCommitted = 2,         // Event already durably persisted with identical fingerprint
               PayloadConflict = 3           // Event exists (InFlight or Committed) with DIFFERENT fingerprint!
           };

           Decision decision{Decision::AcquiredNewInFlight};
           std::chrono::system_clock::time_point committed_received_at{};
           std::shared_future<PersistAckResult> in_flight_future{};
           std::shared_ptr<std::promise<PersistAckResult>> primary_promise{};
       };

       class IDeduplicationCache {
         public:
           virtual ~IDeduplicationCache() = default;

           /// Atomically inspects or reserves event_id in the cache.
           virtual DedupAcquireResult try_acquire(
               const domain::EventId& event_id,
               const domain::EventPayloadFingerprint& fingerprint,
               std::chrono::steady_clock::time_point now) = 0;

           /// Transitions an IN_FLIGHT entry to COMMITTED after ClickHouse confirms durable insert,
           /// starts the 10-minute TTL window, and fulfills the shared AckFuture for any coalesced waiters.
           virtual void mark_committed(
               const domain::EventId& event_id,
               std::chrono::system_clock::time_point received_at,
               std::chrono::steady_clock::time_point now) = 0;

           /// Rolls back and removes an IN_FLIGHT entry when queuing fails, ClickHouse insert fails,
           /// or a timeout produces an ambiguous outcome, notifying coalesced waiters with failure_result.
           virtual void rollback_in_flight(
               const domain::EventId& event_id,
               const PersistAckResult& failure_result) = 0;

           /// Evicts expired COMMITTED entries across shards.
           virtual size_t evict_expired(std::chrono::steady_clock::time_point now) = 0;

           [[nodiscard]] virtual size_t size() const noexcept = 0;
           [[nodiscard]] virtual size_t in_flight_count() const noexcept = 0;
           [[nodiscard]] virtual size_t committed_count() const noexcept = 0;
       };
       ```
     - **Sharded Implementation Details (`BoundedDeduplicationCache`)**:
       - Distributes `dedup_cache_capacity` (`100,000`) evenly across `dedup_cache_shards` (`64` shards $\to$ `1,562`–`1,563` capacity per shard).
       - On `try_acquire(event_id, fingerprint, now)`:
         1. Lock shard mutex for `event_id`.
         2. If entry exists in shard map:
            - If `state == DedupState::Committed` and `now >= entry.expires_at`: lazily evict the expired entry and treat as `UNSEEN`.
            - Otherwise (`InFlight` or non-expired `Committed`), compare `entry.fingerprint == fingerprint`:
              - If **different**: increment conflict counter and return `Decision::PayloadConflict` immediately without mutating the existing entry.
              - If **equal** and `state == DedupState::Committed`: promote entry to front of shard LRU list and return `Decision::AlreadyCommitted` with `entry.committed_received_at`.
              - If **equal** and `state == DedupState::InFlight`: return `Decision::CoalescedInFlight` with a copy of `entry.in_flight_future`.
         3. If `UNSEEN`:
            - If shard size $\ge$ shard capacity:
              - First evict any expired `Committed` entry at the tail of the `Committed` LRU list; if none expired, evict the least-recently-used `Committed` entry.
              - **Pin Invariant**: `InFlight` entries are held in a separate shard map/set (or pinned list) and are **never** evicted by LRU capacity pressure.
            - Create `std::promise<PersistAckResult>` and corresponding `std::shared_future<PersistAckResult>`, insert `InFlight` entry with `fingerprint`, and return `Decision::AcquiredNewInFlight`.
       - On `mark_committed(event_id, received_at, now)`:
         - Under shard lock, transition entry from `InFlight` to `Committed`, record `committed_received_at = received_at`, set `expires_at = now + ttl`, move to front of `Committed` LRU list, and fulfill the `promise` with `PersistAckResult{IngestionOutcomeStatus::DuplicateCoalesced, event_id, received_at, "", ""}` so any coalesced threads wake up immediately with success.
       - On `rollback_in_flight(event_id, failure_result)`:
         - Under shard lock, remove the `InFlight` entry from the shard completely (restoring `UNSEEN` state so the next producer outbox retry can re-acquire cleanly) and fulfill the `promise` with `failure_result`.
6. **Explicit Out-of-Scope**: Direct ClickHouse HTTP execution (handled in T03).
7. **Dependencies**: `AUDIT-006-T01`.
8. **Files to Create/Modify**:
   - `src/audit/ingestion/deduplication_cache.hpp`
   - `src/audit/ingestion/deduplication_cache.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-006-T03 — Retry-Safe Persistence Coordination & Durable Acknowledgement Manager

1. **Ticket ID**: `AUDIT-006-T03`
2. **Title**: Retry-Safe Persistence Coordinator, Batch Commit/Rollback Lifecycle & Ambiguous Write Handling
3. **Objective**: Implement `AcknowledgementManager` and coordinate `BatchAggregator` + `InsertWorkerPool` + `ClickHouseAuditEventRepository` so events are marked `COMMITTED` and acknowledged to callers **only** after ClickHouse confirms durable persistence, with automatic cache rollback and explicit classification of deterministic failures vs. ambiguous write timeouts.
4. **Architectural Purpose**: Enforces the core durability invariant of `AUDIT-006`: volatile queue admission is never acknowledged as durability, failed or ambiguous writes never poison the deduplication cache as `COMMITTED`, and batch outcomes propagate deterministically to all waiting producer threads.
5. **Scope**:
   - **Define Repository Write Outcome Classification in `src/audit/repository/audit_event_repository_interface.hpp`**:
     - Ensure batch insertion distinguishes deterministic pre-commit failure from ambiguous timeout/disconnect:
       ```cpp
       enum class RepositoryWriteStatus : uint8_t {
           Committed = 0,          // ClickHouse returned HTTP 200 OK
           DeterministicFailure = 1, // Connection refused, auth error, syntax/4xx/5xx before commit
           AmbiguousOutcome = 2    // Socket timeout or connection reset after sending HTTP POST body
       };

       struct RepositoryBatchWriteResult {
           RepositoryWriteStatus status{RepositoryWriteStatus::DeterministicFailure};
           std::string error_code;
           std::string sanitized_reason;
       };
       ```
   - **Implement `src/audit/ingestion/acknowledgement_manager.hpp` and `.cpp`**:
     - Coordinates per-batch `IN_FLIGHT` tickets between `BoundedDeduplicationCache`, `InsertWorkerPool`, and waiting gRPC server threads:
       - `on_batch_persisted(const std::vector<AuditEvent>& batch, std::chrono::steady_clock::time_point now)`:
         - Iterates every event in `batch`:
           1. Calls `dedup_cache_->mark_committed(event.event_id, *event.received_at, now)`.
           2. Fulfills the primary caller's `PersistAckResult` with `IngestionOutcomeStatus::PersistedNew` and `received_at`.
       - `on_batch_failed(const std::vector<AuditEvent>& batch, const RepositoryBatchWriteResult& write_result)`:
         - Maps `RepositoryWriteStatus::AmbiguousOutcome` $\to$ `IngestionOutcomeStatus::PersistenceAmbiguous` (and increments `audit_ambiguous_writes_total`).
         - Maps `RepositoryWriteStatus::DeterministicFailure` $\to$ `IngestionOutcomeStatus::PersistenceFailed`.
         - Iterates every event in `batch`:
           1. Calls `dedup_cache_->rollback_in_flight(event.event_id, failure_ack)` so the `event_id` is immediately evicted from `IN_FLIGHT` back to `UNSEEN`.
           2. Fulfills the primary caller's `PersistAckResult` with `failure_ack`.
   - **Exception-Safe RAII Guard (`InFlightReservationGuard`)**:
     - If an event acquires an `IN_FLIGHT` slot in `BoundedDeduplicationCache` and subsequently fails to enter `BoundedIngestionQueue` (e.g., queue full $\to$ backpressure, or worker shutdown drain), `InFlightReservationGuard` automatically invokes `dedup_cache_->rollback_in_flight(event_id, ...)` in its destructor unless `release()` is called upon batch worker handoff. This guarantees **zero leaked `IN_FLIGHT` entries** under any exception or overload path.
6. **Explicit Out-of-Scope**: gRPC protobuf translation (handled in T04).
7. **Dependencies**: `AUDIT-006-T01`, `AUDIT-006-T02`, `AUDIT-003`, `AUDIT-005`.
8. **Files to Create/Modify**:
   - `src/audit/repository/audit_event_repository_interface.hpp`
   - `src/audit/ingestion/acknowledgement_manager.hpp`
   - `src/audit/ingestion/acknowledgement_manager.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-006-T04 — gRPC Ingestion Pipeline Wiring, Intra-Batch Deduplication & Outbox-Compatible Status Mapping

1. **Ticket ID**: `AUDIT-006-T04`
2. **Title**: End-to-End Ingestion Coordinator, Intra-Batch Deduplication & Producer Outbox Contract Integration
3. **Objective**: Wire `EventPayloadFingerprint`, `BoundedDeduplicationCache`, and `AcknowledgementManager` into the `SubmitAuditEvent` and `BatchSubmitAuditEvents` execution pipeline, handling intra-batch duplicates, cross-batch duplicates, payload conflicts, and producer outbox-compatible gRPC status responses.
4. **Architectural Purpose**: Ensures that single-event and batch gRPC endpoints strictly honor the idempotency and durability acknowledgement contract required by runtime producer outboxes (`Gateway`, `Auth`, `Messaging`, `Files`).
5. **Scope**:
   - **Implement/Update `src/audit/ingestion/audit_ingestion_pipeline.hpp` and `.cpp`**:
     - **Single-Event Flow (`submit_event(const PeerIdentity& peer, const AuditEventProto& proto)`)**:
       1. Verify mTLS producer authorization via `ProducerIdentityValidator::validate_producer_authorization(...)`. On mismatch $\to$ return `UnauthorizedProducer` (`PERMISSION_DENIED`).
       2. Map wire proto to domain `AuditEvent` (`AuditEventMapper::to_domain(proto, clock_->now())`) and validate via `AuditEventValidator::validate(...)`. On failure $\to$ return `ValidationRejected` (`INVALID_ARGUMENT`).
       3. Compute `fingerprint = EventPayloadFingerprint::compute(event)`.
       4. Call `dedup_cache_->try_acquire(event.event_id, fingerprint, steady_now)`:
          - **`AlreadyCommitted`**: Return `PersistAckResult{IngestionOutcomeStatus::DuplicateCommitted, event.event_id, committed_received_at}` immediately (`grpc::Status::OK`, `success = true`, `received_at_ms = committed_received_at`).
          - **`PayloadConflict`**: Return `PersistAckResult{IngestionOutcomeStatus::IdempotencyConflict, event.event_id, ...}` (`grpc::StatusCode::ALREADY_EXISTS`).
          - **`CoalescedInFlight`**: Wait on `in_flight_future` up to `min(rpc_deadline, in_flight_ack_timeout_ms)`. If committed $\to$ return `OK`; if failed/timed out $\to$ return `UNAVAILABLE` / `DEADLINE_EXCEEDED`.
          - **`AcquiredNewInFlight`**: Wrap reservation in `InFlightReservationGuard`, enqueue into `BoundedIngestionQueue` (or flush via `BatchAggregator`). If queue is full, guard rolls back `IN_FLIGHT` and returns `QueueOverloaded` (`grpc::StatusCode::RESOURCE_EXHAUSTED`). Otherwise, await durable ClickHouse batch completion via `AcknowledgementManager` and return the resulting `PersistAckResult`.
     - **Batch Flow (`submit_batch(const PeerIdentity& peer, const BatchSubmitAuditEventsRequest& req)`)**:
       1. Enforce max batch size (`<= 100` events; reject oversized requests with `INVALID_ARGUMENT`).
       2. For each item $i \in [0, N)$:
          - Validate producer identity and domain rules (`AuditEventValidator`). Invalid items are immediately recorded as rejected (`rejected_count++`, `rejected_event_ids.push_back(id)`) without aborting valid siblings in the batch.
          - Compute `fingerprint_i = EventPayloadFingerprint::compute(event_i)`.
          - Acquire in `dedup_cache_->try_acquire(event_i.event_id, fingerprint_i, steady_now)`:
            - **`AlreadyCommitted`**: Mark item $i$ as accepted (`accepted_count++`) without re-inserting into ClickHouse.
            - **`PayloadConflict`** (either against a previously cached event or an earlier item $j < i$ in the **same batch** with the same `event_id` but different payload): Mark item $i$ as rejected (`rejected_count++`, `rejected_event_ids.push_back(id)`) and increment conflict metrics.
            - **`CoalescedInFlight`** (including an earlier identical item $j < i$ in the **same batch** or a concurrent RPC): Attach item $i$ to the shared `in_flight_future` without enqueuing a duplicate row for ClickHouse insertion.
            - **`AcquiredNewInFlight`**: Enqueue item $i$ for ClickHouse batch insertion.
       3. Await ClickHouse completion for all newly acquired and coalesced items in the batch:
          - If all enqueued items commit durably (or were already `Committed`), return `grpc::Status::OK` with accurate `accepted_count`, `rejected_count`, and `rejected_event_ids`.
          - If the ClickHouse insert fails (`PersistenceFailed`), times out ambiguously (`PersistenceAmbiguous`), or the ingestion queue is full (`QueueOverloaded`), `AcknowledgementManager` rolls back all newly acquired `IN_FLIGHT` reservations and the RPC returns `grpc::StatusCode::UNAVAILABLE`, `DEADLINE_EXCEEDED`, or `RESOURCE_EXHAUSTED` so the producer outbox retries the unacknowledged events safely.
   - **Deterministic gRPC Status Code Mapping (`AuditIngestionServiceImpl`)**:
     - `PersistedNew` / `DuplicateCommitted` / `DuplicateCoalesced` $\to$ `grpc::Status::OK`
     - `IdempotencyConflict` $\to$ `grpc::StatusCode::ALREADY_EXISTS` (single RPC) / `rejected_event_ids` (batch RPC)
     - `ValidationRejected` $\to$ `grpc::StatusCode::INVALID_ARGUMENT` (single RPC) / `rejected_event_ids` (batch RPC)
     - `UnauthorizedProducer` $\to$ `grpc::StatusCode::PERMISSION_DENIED` / `UNAUTHENTICATED`
     - `QueueOverloaded` $\to$ `grpc::StatusCode::RESOURCE_EXHAUSTED` (retryable by producer outbox with backoff)
     - `PersistenceFailed` $\to$ `grpc::StatusCode::UNAVAILABLE` (retryable by producer outbox)
     - `PersistenceAmbiguous` $\to$ `grpc::StatusCode::DEADLINE_EXCEEDED` or `UNAVAILABLE` (retryable by producer outbox)
6. **Explicit Out-of-Scope**: Analytical compliance query endpoints (`AUDIT-007`).
7. **Dependencies**: `AUDIT-006-T01`, `AUDIT-006-T02`, `AUDIT-006-T03`, `AUDIT-004`, `AUDIT-005`.
8. **Files to Create/Modify**:
   - `src/audit/ingestion/audit_ingestion_pipeline.hpp`
   - `src/audit/ingestion/audit_ingestion_pipeline.cpp`
   - `src/audit/service/audit_ingestion_service_impl.hpp`
   - `src/audit/service/audit_ingestion_service_impl.cpp`
   - `src/audit/CMakeLists.txt`

---

### AUDIT-006-T05 — Observability Telemetry, Duplicate Detection Helper & Architecture Documentation

1. **Ticket ID**: `AUDIT-006-T05`
2. **Title**: Deduplication Telemetry Counters, Analytical Duplicate Verification Query & Documentation of Restart/Ambiguous Limits
3. **Objective**: Instrument the deduplication and acknowledgement pipeline with atomic operational/security telemetry counters, provide the analytical duplicate detection query helper (`05-audit-data-model.md` §5.25), and document the exact idempotency guarantees, process restart behavior, and ambiguous write recovery semantics in `docs/design/audit-design.md`.
4. **Architectural Purpose**: Makes duplicate rates, payload conflicts, cache evictions, and ambiguous database writes observable to operators while ensuring documentation accurately states what is and is not guaranteed (no false global exactly-once claim).
5. **Scope**:
   - **Create/Extend `src/audit/ingestion/deduplication_metrics.hpp`**:
     - Thread-safe atomic counters (`std::atomic<uint64_t>`):
       - `audit_events_persisted_new_total`: Events newly inserted and confirmed in ClickHouse.
       - `audit_dedup_hits_committed_total`: Duplicate submissions short-circuited from `COMMITTED` cache state.
       - `audit_dedup_hits_inflight_coalesced_total`: Concurrent or intra-batch duplicate submissions coalesced onto an `IN_FLIGHT` write.
       - `audit_dedup_payload_conflicts_total`: Submissions rejected due to conflicting payload fingerprint for an existing `event_id` (security/integrity anomaly signal).
       - `audit_dedup_cache_evictions_ttl_total`: Cache entries evicted due to 10-minute TTL expiration.
       - `audit_dedup_cache_evictions_lru_total`: Cache entries evicted due to reaching the 100,000 capacity ceiling.
       - `audit_dedup_inflight_rollbacks_total`: `IN_FLIGHT` reservations rolled back due to queue overload or ClickHouse write failure.
       - `audit_persistence_ambiguous_outcomes_total`: ClickHouse write timeouts/disconnects where commit status was unknown and `IN_FLIGHT` state was rolled back to preserve at-least-once durability.
   - **Analytical Duplicate Verification Query Helper (`05-audit-data-model.md` §5.25)**:
     - Add operational verification query builder/method in `ClickHouseAuditEventRepository` (`find_duplicate_event_counts`) executing:
       ```sql
       SELECT event_id, count() AS occurrences
       FROM securecloud_audit.audit_events
       GROUP BY event_id
       HAVING occurrences > 1
       ORDER BY occurrences DESC
       LIMIT {limit}
       ```
       for integration verification and operator diagnostics (strictly off the ingestion hot path).
   - **Update `docs/design/audit-design.md` (Sections 8.8–8.11)**:
     - Document the exact two-phase (`IN_FLIGHT` $\to$ `COMMITTED`) deduplication contract, SHA-256 payload conflict rejection, acknowledgement boundary, and the two explicit boundaries where duplicate rows can still occur in ClickHouse:
       1. **Audit Service Process Restart / Cache Eviction**: Because `BoundedDeduplicationCache` is in-memory (`100,000` IDs, `10-minute` TTL), if the Audit daemon restarts after committing to ClickHouse but before the gRPC ACK reaches the producer outbox, the producer's post-restart retry will be ingested as `UNSEEN`.
       2. **Ambiguous ClickHouse Write Timeout**: When an HTTP `INSERT` times out after transmission, the Audit Service rolls back `IN_FLIGHT` state and returns a retryable error rather than risking silent event loss.
6. **Explicit Out-of-Scope**: External Prometheus scraper deployment (handled in `OBS-*` cards).
7. **Dependencies**: `AUDIT-006-T01` through `AUDIT-006-T04`.
8. **Files to Create/Modify**:
   - `src/audit/ingestion/deduplication_metrics.hpp`
   - `src/audit/repository/clickhouse_audit_event_repository.hpp`
   - `src/audit/repository/clickhouse_audit_event_repository.cpp`
   - `docs/design/audit-design.md`

---

### AUDIT-006-T06 — Exhaustive Unit, Concurrency, Conflict, Cache-Bound & Failure-Injection Test Suite

1. **Ticket ID**: `AUDIT-006-T06`
2. **Title**: Unit, Concurrency, Payload Conflict, Cache Eviction & Failure-Injection Verification Suite
3. **Objective**: Implement comprehensive automated test suites verifying every functional, concurrency, memory-bound, conflict-detection, and failure-injection requirement of `AUDIT-006`.
4. **Architectural Purpose**: Provides deterministic, reproducible verification that deduplication, conflict rejection, batch rollback, and retry-safe acknowledgements behave accurately under normal load, high concurrency, database failures, and service restarts.
5. **Scope**:
   - **Unit Test Suite 1: `tests/unit/audit/event_payload_fingerprint_test.cpp`**:
     - **Test 1 (`DeterministicAcrossIdenticalEvents`)**: Two `AuditEvent` instances with identical fields produce identical 32-byte SHA-256 fingerprints.
     - **Test 2 (`InsensitiveToReceivedAtDifferences`)**: Retrying the same event with a different service-assigned `received_at` produces the **exact same** fingerprint.
     - **Test 3 (`InsensitiveToMetadataInsertionOrder`)**: Two events with 20 metadata keys inserted into `std::unordered_map` in opposite orders produce the **exact same** fingerprint.
     - **Test 4 (`SensitiveToEveryImmutableFieldMutation`)**: Mutating any single immutable field (`occurred_at`, `event_type`, `severity`, `producer_service`, `producer_instance`, `actor_type`, `actor_id`, `target_type`, `target_id`, `correlation_id`, `causation_id`, or any metadata key/value) produces a distinct fingerprint.
     - **Test 5 (`LengthPrefixPreventsConcatenationCollision`)**: Verifies `actor_id="ab", target_id="c"` vs `actor_id="a", target_id="bc"` produce distinct digests.
   - **Unit Test Suite 2: `tests/unit/audit/bounded_deduplication_cache_test.cpp`**:
     - **Test 1 (`UnseenToInFlightToCommittedLifecycle`)**: Verifies state transitions `AcquiredNewInFlight` $\to$ `mark_committed` $\to$ `AlreadyCommitted` returning the original `committed_received_at`.
     - **Test 2 (`PayloadConflictRejectedWhileInFlightAndWhenCommitted`)**: Submitting the same `EventId` with a modified fingerprint returns `Decision::PayloadConflict` in both `IN_FLIGHT` and `COMMITTED` states without corrupting the stored entry.
     - **Test 3 (`TtlExpirationEvictsCommittedEntry`)**: Advancing simulated `steady_clock` past `10 minutes` (`600,000 ms`) causes a previously `COMMITTED` entry to expire and re-acquire as `AcquiredNewInFlight`.
     - **Test 4 (`BoundedCapacity100kLruEviction`)**: Inserting `100,000` `COMMITTED` entries fills the cache; inserting entry `100,001` evicts the least-recently-used entry while keeping `size() <= 100,000`. Accessing an entry promotes it in LRU order and protects it from eviction.
     - **Test 5 (`InFlightEntriesPinnedAgainstLruEviction`)**: Verifies `IN_FLIGHT` reservations are never evicted even when `COMMITTED` entries churn past shard capacity.
     - **Test 6 (`RollbackInFlightRestoresUnseenState`)**: Calling `rollback_in_flight` after a failed write immediately allows the next retry with the same `EventId` to acquire a fresh `AcquiredNewInFlight` slot.
   - **Concurrency & Failure-Injection Suite 3: `tests/unit/audit/audit_deduplication_pipeline_test.cpp`**:
     - **Test 1 (`IntraBatchDuplicateSamePayloadPersistedOnce`)**: A `BatchSubmitAuditEventsRequest` containing 3 copies of `event_id` $E$ with identical payloads writes **1 row** to the repository and returns `accepted_count = 3, rejected_count = 0`.
     - **Test 2 (`IntraBatchConflictingPayloadRejected`)**: A batch containing `event_id` $E$ at index 0 and a modified payload with `event_id` $E$ at index 1 persists index 0 and rejects index 1 (`accepted_count = 1, rejected_count = 1, rejected_event_ids = {E}`).
     - **Test 3 (`CrossBatchDuplicateShortCircuitedWithoutDatabaseWrite`)**: Re-submitting an already-persisted event in a subsequent batch or single RPC returns `OK` with the original `received_at_ms` and performs **zero** additional repository `insert_batch` calls (simulating a lost ACK retry from the producer outbox).
     - **Test 4 (`ConcurrentSubmissionsOfSameEventCoalesceWithoutRace`)**: 32 threads simultaneously submit the exact same `AuditEvent`. Exactly **1** database insert is executed; all 32 threads receive `OK` once the single batch commits.
     - **Test 5 (`VolatileQueueAdmissionNeverAcknowledgedBeforeCommit`)**: With the mock repository paused before `insert_batch` returns, verifies no caller receives an `OK` acknowledgement and the cache entry is not `COMMITTED` while the event sits in `BoundedIngestionQueue` or `BatchAggregator`.
     - **Test 6 (`DatabaseFailureAndTimeoutRollbackAllowsCleanRetry`)**:
       - Attempt 1: Mock ClickHouse throws `ClickHouseConnectionException` (or `ClickHouseTimeoutException` simulating an ambiguous outcome). Verifies RPC returns `UNAVAILABLE` / `DEADLINE_EXCEEDED`, `audit_persistence_ambiguous_outcomes_total` / rollback counters increment, and cache entry is rolled back.
       - Attempt 2: Producer retries with the exact same `event_id`. Mock ClickHouse succeeds (`HTTP 200 OK`). Verifies the event is persisted to ClickHouse and acknowledged with `OK`.
     - **Test 7 (`SimulatedServiceRestartBehavior`)**: Event $E$ is persisted and acknowledged, then a new `AuditIngestionPipeline` instance (empty `BoundedDeduplicationCache`, same underlying storage) receives a retry of $E$ (simulating lost ACK across Audit Service restart). Verifies the service accepts the retry predictably and `find_duplicate_event_counts()` accurately identifies the duplicate `event_id` analytically.
   - **Live Integration Test Extension (`tests/integration/audit_clickhouse_integration_test.cpp` or `audit_ingestion_integration_test.cpp`)**:
     - End-to-end mTLS gRPC $\to$ Deduplication Cache $\to$ ClickHouse 24.8 verification of duplicate suppression, conflicting payload rejection, and analytical duplicate detection query execution.
6. **Explicit Out-of-Scope**: Multi-node distributed ClickHouse ZooKeeper replication testing (out of MVP scope).
7. **Dependencies**: `AUDIT-006-T01` through `AUDIT-006-T05`.
8. **Files to Create/Modify**:
   - `tests/unit/audit/event_payload_fingerprint_test.cpp`
   - `tests/unit/audit/bounded_deduplication_cache_test.cpp`
   - `tests/unit/audit/audit_deduplication_pipeline_test.cpp`
   - `tests/unit/CMakeLists.txt`
   - `tests/integration/CMakeLists.txt`

---

## 6. Traceability Matrix: Card Requirements to Tickets

| Card Scope / Acceptance Requirement | Enforcing Ticket(s) | Key Verification Mechanism |
| :--- | :--- | :--- |
| **Use producer-generated UUIDv7 `event_id` as logical identity; require reuse across retries** | `AUDIT-006-T01`, `AUDIT-006-T04` | `EventId` (`UUIDv7` validator) + `BoundedDeduplicationCache` keyed by `EventId` |
| **Handle `event_id` already observed (both `IN_FLIGHT` queued/persisting and `COMMITTED`)** | `AUDIT-006-T02`, `AUDIT-006-T04` | `DedupState::InFlight` coalescing futures & `DedupState::Committed` fast-path ACK |
| **Detect & reject conflicting payloads sharing the same `event_id`** | `AUDIT-006-T01`, `AUDIT-006-T02`, `AUDIT-006-T04` | `EventPayloadFingerprint` (SHA-256 over canonical fields) $\to$ `ALREADY_EXISTS` / batch item rejection |
| **Bounded recent-event cache of 100,000 IDs with explicit TTL (`10m`) & LRU eviction** | `AUDIT-006-T01`, `AUDIT-006-T02`, `AUDIT-006-T06` | `BoundedDeduplicationCache` (`64` lock-striped shards, `100,000` capacity, `600,000 ms` TTL, ~`14.4 MiB` ceiling) |
| **Concurrent requests cannot race past deduplication checks** | `AUDIT-006-T02`, `AUDIT-006-T06` | Atomic shard-locked `try_acquire()` + 32-thread concurrency stress test |
| **Never mark an event permanently successful merely because it entered the volatile queue** | `AUDIT-006-T02`, `AUDIT-006-T03`, `AUDIT-006-T06` | `mark_committed()` called strictly inside `AcknowledgementManager::on_batch_persisted()` after ClickHouse `200 OK` |
| **Handle failed inserts, timeouts, and ambiguous outcomes without false durability ACKs** | `AUDIT-006-T03`, `AUDIT-006-T04`, `AUDIT-006-T06` | `AcknowledgementManager::on_batch_failed()` rolls back `IN_FLIGHT` entries to `UNSEEN` and returns `UNAVAILABLE` / `DEADLINE_EXCEEDED` |
| **Document limits around process restarts and ambiguous database outcomes (no global exactly-once claim)** | `AUDIT-006-T05`, Section 1 & 2.4 | `docs/design/audit-design.md` update + `find_duplicate_event_counts()` analytical query helper |
| **Full verification pass (`clang-format`, `clang-tidy`, `CTest`, `python3 scripts/verify-local.py`)** | `AUDIT-006-T06` | Automated verification gate across all unit and integration suites |

---

## 7. Implementation & Verification Protocol for Lorenzo

1. **Sequential Ticket Execution**:
   - Execute `AUDIT-006-T01` $\to$ `T02` $\to$ `T03` $\to$ `T04` $\to$ `T05` $\to$ `T06` in order, presenting an implementation plan before each ticket and awaiting explicit approval.
2. **Full Repository Verification Gate**:
   - For every ticket, run `python3 scripts/verify-local.py` (verifying formatting, static analysis, compilation, and the entire CTest suite) before proposing a commit message.
3. **Strict Commit Governance**:
   - Never execute `git commit` or `git push` until the proposed commit message has been explicitly validated by Sergey.
