# ADR-012 — Messaging Durable Audit Outbox and Sequential Forward Recovery

**Status:** Accepted  
**Date:** 2026-11-13  
**Decision Scope:** Messaging audit outbox persistence, ScyllaDB partitioning model, cross-table durability protocol, and zero-plaintext invariants  
**Decision Gatekeeper / Approval:** Sergey (Technical Lead & Security Architect)  
**Related ADRs:** ADR-001 (Five Microservices), ADR-003 (Distributed Architecture First), ADR-004 (IPC Model), ADR-005 (Database Ownership Model — §7 Messaging Database), ADR-006 (Persistence Technology Selection), ADR-007 (Message Reliability & Durability), ADR-008 (Security & Cryptographic Architecture), ADR-009 (Distributed Failure & Resilience), ADR-010 (Performance, Capacity & Optimization), ADR-011 (Gateway-Owned Audit Spool)

---

# 1. Context and Problem Statement

Card **`AUDIT-014`** mandates that the **SecureCloud Messaging Service** (`securecloud-messaging`) integrate with the Centralized **Audit Service** (`securecloud-audit`) as a durable, zero-knowledge-compliant audit event producer.

Unlike the API Gateway (stateless reverse proxy using a local append-only WAL spool under **ADR-011**) and the Authentication Service (backed by PostgreSQL 17 single-node ACID transactions under **`AUDIT-013`**), the Messaging Service persists all communication state in **ScyllaDB** (`securecloud_messaging`, per **ADR-005 §7** and **ADR-006**), a distributed wide-column NoSQL store partitioned across a consistent-hash token ring.

When a message submission is processed, Messaging writes across multiple distinct tables with disjoint partition keys:
- `messages_by_conversation`: partition key `((conversation_id, message_bucket))`
- `pending_deliveries_by_device`: partition key `((device_id, delivery_bucket))`
- `delivery_state_by_message`: partition key `((message_id))`
- `message_submission_by_idempotency_key`: partition key `((sender_device_id))`
- `messaging_audit_outbox`: partition key `((outbox_bucket, shard_id))`

### 1.1 Architectural Constraints
1. **No Multi-Partition ACID Transactions in ScyllaDB**: ScyllaDB guarantees atomicity only within a single partition. Multi-partition `LOGGED BATCH` statements write uncoordinated mutation logs to `system.batches`, incur high coordinator latency, do not provide isolation or rollback, and violate the 10,000 messages/second peak throughput target (**ADR-010**).
2. **Decoupling from Real-Time Push Outbox**: The existing `messaging_outbox_events` table (`V002`) drives immediate real-time socket delivery (`OutboxDeliveryConsumer`). Sharing that table with external compliance audit relay (`AUDIT-014`) would couple push latency to Audit Service availability and create tombstone/compaction contention.
3. **Strict Zero-Knowledge & Zero-Plaintext Invariant (`ADR-008`, `RULES.md` §5)**: Messaging acts as a blind relay. Audit records must never capture plaintext messages, E2E ciphertext envelopes, ephemeral keys, prekeys, ratchet state, or authentication tokens.

---

# 2. Options Evaluated

| Option | Mechanism | Durability & Consistency | Throughput & Latency Impact | Architectural Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **Option A: Cross-Partition `LOGGED BATCH`** | Wrap message, delivery, idempotency, and audit outbox inserts in a single ScyllaDB `LOGGED BATCH` | No isolation or rollback; coordinator replays mutations asynchronously without transactional semantics | Severe coordinator overhead, distributed write timeouts under 10k msg/s load | **Rejected.** Anti-pattern in ScyllaDB/Cassandra across distinct partition keys. |
| **Option B: Reuse `messaging_outbox_events` (V002)** | Add compliance audit events into the real-time device delivery outbox table | Couples compliance audit relay with socket push delivery | Tombstone contention and backpressure interference during Audit outages | **Rejected.** Violates separation of concerns and fault isolation (`ADR-009`). |
| **Option C: Dedicated Sharded Outbox + Sequential Durable Write with Idempotent Forward Recovery** *(Accepted)* | Dedicated `messaging_audit_outbox` table (`V006`) partitioned by `((outbox_bucket, shard_id))` + deterministic UUIDv7 recovery driven by `IdempotencyGuard` | **At-Least-Once Durable Delivery**. Surviving crashes at any step either rolls back cleanly on retry or deterministically reconstructs the missing audit event | Partition-local `LOCAL_QUORUM` writes; 16 independent shards per hourly bucket eliminate hotspots | **Selected.** Aligns natively with ScyllaDB's storage engine, preserves 10k msg/s throughput, and guarantees zero lost audit events. |
| **Option D: Synchronous gRPC Call to Audit Service** | Call `AuditIngestionService` inline during `SendMessage` | Direct confirmation before client response | Couples message acceptance latency and availability to Audit Service | **Strictly Rejected.** Violates `ADR-004` and `ADR-009`. |

---

# 3. Decision

1. **Dedicated Time-Bucketed & Sharded Outbox Table (`V006`)**:
    - Introduce `securecloud_messaging.messaging_audit_outbox` with compound partition key `((outbox_bucket, shard_id))` and clustering key `(created_at ASC, event_id ASC)`, where:
        - `outbox_bucket` is the hourly UTC bucket (`YYYYMMDDHH`), bounding partition size.
        - `shard_id` is `FNV1a64(routing_key) % 16` (`0..15`), distributing write load evenly across 16 token ranges per hour.
    - Configure `TimeWindowCompactionStrategy` (4-hour windows) and a 7-day safety TTL (`default_time_to_live = 604800`) to prevent unbounded disk growth and tombstone accumulation.
2. **Sequential Durable Write with Idempotent Forward Recovery**:
    - Business and audit mutations execute sequentially at `LOCAL_QUORUM`:
        1. `IdempotencyGuard::mark_processing(key)`
        2. `save_message()` in `messages_by_conversation`
        3. `save_deliveries()` in `pending_deliveries_by_device` & `delivery_state_by_message`
        4. `save_audit_outbox()` in `messaging_audit_outbox` (`status = PENDING`)
        5. `IdempotencyGuard::mark_committed(key, message_id)`
    - Audit event identifiers for message lifecycle transitions are derived deterministically via `generate_message_audit_event_id(message_id, event_type)` (SHA-256-seeded RFC 9562 UUIDv7 preserving the message's 48-bit millisecond timestamp).
    - If a crash occurs after message persistence (Step 2) but before outbox persistence (Step 4), the client retry triggers `IdempotencyGuard` forward recovery, which deterministically regenerates and persists the exact same `event_id` before completing commit.
3. **Mandatory `ZeroPlaintextGuard` Pre-Staging Gate**:
    - Every `MessagingAuditEvent` payload must pass `ZeroPlaintextGuard::validate_audit_payload()` prior to ScyllaDB insertion, rejecting any forbidden cryptographic keys, ciphertext blobs, tokens, or raw binary bytes.

---

# 4. Failure Windows & Forward Recovery Matrix

| Failure Point | ScyllaDB State at Crash | Recovery Protocol & Guarantee |
| :--- | :--- | :--- |
| **Before Step 2 (`save_message`)** | Idempotency state is `PROCESSING`; no message or outbox row exists | Client retry finds no persisted message and executes a clean submission. Zero phantom audit records. |
| **Between Step 2 and Step 4 (`save_audit_outbox`)** | Message and delivery rows committed; outbox row missing; idempotency state `PROCESSING` | Client retry detects existing message in `messages_by_conversation`, deterministically synthesizes `event_id = generate_message_audit_event_id(message_id, MessageSubmitted)`, persists it to `messaging_audit_outbox`, and transitions idempotency to `COMMITTED`. Zero lost messages, zero lost audit events. |
| **Between Step 4 and Step 5 (`mark_committed`)** | Message, delivery, and outbox rows exist; idempotency state `PROCESSING` | Client retry observes existing message and transitions idempotency to `COMMITTED`. Outbox relay dispatches the already-staged record; `AUDIT-006` deduplicates any duplicate RPC by `event_id`. |
| **Audit Service Outage** | All message, delivery, and outbox rows committed (`PENDING`) | Real-time messaging continues unaffected. `MessagingOutboxRelay` retains `PENDING` rows and drains them with exponential backoff once Audit recovers. |

---

# 5. Consequences and Compliance

### Positive Consequences
- **Native ScyllaDB Scalability**: Eliminates cross-partition `LOGGED BATCH` coordinator overhead and write hotspots via 16-way hourly sharding.
- **Zero-Loss Audit Durability**: Deterministic UUIDv7 derivation combined with `IdempotencyGuard` closes the non-transactional crash window between message persistence and outbox staging.
- **Cryptographic Privacy Enforcement**: `ZeroPlaintextGuard` enforces compile/runtime rejection of ciphertext envelopes and key material before disk persistence.

### Negative / Trade-Off Consequences
- **Eventual Audit Visibility on Crash**: If a client crashes permanently after Step 2 and never retries, an un-retried submission without a background reconciliation sweep would remain without an audit record; client retry policies and delivery sweeps mitigate this window.
- **Sharded Polling Complexity**: The background relay worker (`MessagingOutboxRelay`) must poll across all 16 shards (`0..15`) for active hourly buckets rather than scanning a single table.

---

# 6. Sign-Off and Approvals

| Role | Name | Status | Date |
| :--- | :--- | :--- | :--- |
| **Technical Lead & Security Architect** | Sergey | **Approved** | 2026-11-13 |
| **Messaging & Audit Engineer** | Lorenzo | **Accepted** | 2026-11-13 |