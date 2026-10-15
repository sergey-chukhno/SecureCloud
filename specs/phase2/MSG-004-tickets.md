# MSG-004 — Messaging Persistence & ScyllaDB Model
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-004  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Distributed Systems Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 15, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-004** establishes the authoritative persistence model and storage architecture for the SecureCloud Messaging Service (`securecloud-messaging`) using **ScyllaDB**, in strict compliance with **ADR-006** (Concrete Persistence Technologies), **ADR-007** (Messaging Reliability & Durability), **ADR-009** (Distributed Failure & Resilience), **ADR-010** (Performance & Bounded Concurrency), and **03-messaging-data-model.md** (Messaging Service Data Model).

While Card **MSG-001** built the service foundation, thread pools, and health probes, Card **MSG-002** established the 17-RPC Protobuf contracts and caller context, and Card **MSG-003** implemented the core domain model and authorization engine for conversations and membership (using in-memory repositories for hermetic isolation), **MSG-004 establishes the durable, distributed persistence foundation**.

Subsequent cards—specifically Message Submission & Idempotency (`MSG-005`), Online Message Delivery (`MSG-007`), Read Receipts & Delivery State (`MSG-008`), and Online Synchronization (`MSG-009`)—strictly rely on MSG-004 to provide the durable storage primitives, time-bucketed partitions, and recipient-device indexed tables without requiring any structural redesign of the persistence layer.

```
       MSG-001 (Foundation & Tri-Pool)
       MSG-002 (Protobuf Contracts & Error Mapping)
       MSG-003 (Conversation Domain & Auth Engine)
                           │
                           ▼
              MSG-004: ScyllaDB Persistence
  ┌───────────────────────────────────────────────────┐
  │  • Keyspace & CQL Schema Initializer / Migrations  │
  │  • Session Pool & Bound Query Abstraction         │
  │  • Conversation & Membership ScyllaDB Repositories │
  │  • Time-Bucketed Message & Outbox Persistence     │
  │  • Per-Device Delivery State & Sync Cursors       │
  │  • Idempotent Submission Deduplication Records    │
  └───────────────────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
      MSG-005           MSG-007           MSG-008 / MSG-009
  (Message Submit)  (Online Delivery)  (Receipts & Sync)
```

---

## 2. Core Architectural Invariants & State Boundaries

The ScyllaDB persistence model is derived strictly from **distributed access patterns**, not relational normalization. To preserve scalability, fault isolation, and correctness, the model enforces six non-negotiable boundaries:

### 2.1 Explicit Messaging State Boundaries

| State Category | Purpose | Durability & Partitioning Boundary | Prohibited Anti-Patterns |
| :--- | :--- | :--- | :--- |
| **Conversation & Metadata** | Canonical conversation identity, group title, status (`ACTIVE`/`CLOSED`), direct pairs | Keyed by `((conversation_id))` or canonical direct pair `((user_a_id, user_b_id))` | Do not mix message bodies into conversation metadata rows. |
| **Membership & User Inbox** | Who belongs to a conversation, role (`MEMBER`/`ADMIN`), status, and user conversation lists | Keyed by `((conversation_id), user_id)` and `((user_id), last_activity_at DESC, conversation_id)` | Do not perform distributed table scans to find user conversations. |
| **Message History** | Immutable encrypted envelopes and metadata | Keyed by `((conversation_id, message_bucket), message_sequence, message_id)` | No unbucketed partitions; no global message sequence. |
| **Per-Device Delivery State** | Recipient device lifecycle (`PENDING` $\to$ `DELIVERED` $\to$ `READ`) | Keyed by `((device_id, delivery_bucket), accepted_at, message_id)` | **No global delivery queue table**; no queue scans. |
| **Device Sync Cursors** | Device synchronization progress per conversation | Keyed by `((device_id), conversation_id)` | Do not calculate sync progress by scanning historical messages. |
| **Idempotent Submission** | Deduplicate client retries | Keyed by `((sender_device_id), idempotency_key)` | Do not rely on ephemeral caches for deduplication. |
| **Presence State** | Real-time client connectivity / ephemeral availability | **Transient (In-Memory / Gateway)** | **NEVER write presence heartbeats into ScyllaDB delivery tables.** |

### 2.2 Key Architectural Invariants

1. **No Global Hot Partitions or Global Queues**:
   - There is no single "messages" or "pending_deliveries" partition.
   - Message partitions are partitioned by `(conversation_id, message_bucket)`.
   - Delivery queues are partitioned by `(device_id, delivery_bucket)`.
   - Horizontally scalable delivery workers poll or stream delivery events partitioned by device affinity, avoiding database-level contention.
2. **Predictable Partition Sizes via Time-Bucketing**:
   - Long-lived conversations or high-throughput channels partition messages by **monthly UTC buckets** (`YYYYMM`).
   - Active device delivery queues partition by monthly buckets (`YYYYMM`) to bound tombstones and partition size.
3. **Decoupled User Identity vs. Device Identity**:
   - Conversations and memberships are established at the logical `UserId` level.
   - Delivery and synchronization states are tracked at the concrete `DeviceId` level.
4. **Authoritative Storage vs. In-Memory Schedulers**:
   - ScyllaDB durable state is authoritative. In-memory scheduling queues, ring buffers, and caches are disposable optimizations; correctness and recovery are always reconstructed from durable ScyllaDB records.
5. **Zero Crypto Plaintext Exposure (ADR-008)**:
   - Message payloads are opaque binary/text ciphertext envelopes (`ciphertext_envelope`).
   - The persistence layer treats ciphertext as opaque bytes and never stores private keys, ratchet state, or plaintext.
6. **No Distributed Transactions or Cross-Service Access (ADR-005)**:
   - Messaging exclusively owns the `securecloud_messaging` keyspace.
   - Dual-writes (e.g. conversation + user inbox entry) are handled via application-level coordination, batch statements within the same partition, or the transactional outbox pattern.

---

## 3. ScyllaDB Schema & Access Pattern Specification

### 3.1 Keyspace Definition

```sql
CREATE KEYSPACE IF NOT EXISTS securecloud_messaging
WITH replication = {
    'class': 'SimpleStrategy',
    'replication_factor': 1
};
```
*(In staging/production multi-DC topologies, this transitions to `NetworkTopologyStrategy` without schema changes).*

---

### 3.2 Authoritative Tables & Partitioning Strategy

#### 1. `conversations_by_id`
* **Access Pattern**: Retrieve conversation metadata by `ConversationId`.
* **Partition Key**: `conversation_id` (UUIDv7)
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.conversations_by_id (
    conversation_id text,
    conversation_type text,
    created_at timestamp,
    created_by_user_id text,
    metadata_version int,
    PRIMARY KEY (conversation_id)
);
```

#### 2. `direct_conversation_by_users`
* **Access Pattern**: O(1) idempotent resolution of 1:1 conversation for a canonical pair of users.
* **Partition Key**: `((user_a_id, user_b_id))` where `user_a_id < user_b_id` lexicographically.
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.direct_conversation_by_users (
    user_a_id text,
    user_b_id text,
    conversation_id text,
    created_at timestamp,
    PRIMARY KEY ((user_a_id, user_b_id))
);
```

#### 3. `group_metadata_by_conversation`
* **Access Pattern**: Retrieve and update group title and lifecycle state (`ACTIVE`, `CLOSED`).
* **Partition Key**: `conversation_id`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.group_metadata_by_conversation (
    conversation_id text,
    group_name text,
    group_status text,
    created_by_user_id text,
    created_at timestamp,
    updated_at timestamp,
    metadata_version int,
    PRIMARY KEY (conversation_id)
);
```

#### 4. `conversation_members_by_conversation`
* **Access Pattern**: List all participants for a conversation; query participant role and status.
* **Partition Key**: `conversation_id`
* **Clustering Key**: `user_id ASC`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.conversation_members_by_conversation (
    conversation_id text,
    user_id text,
    membership_status text,
    role text,
    joined_at timestamp,
    left_at timestamp,
    membership_version int,
    PRIMARY KEY ((conversation_id), user_id)
);
```

#### 5. `conversations_by_user`
* **Access Pattern**: Paginated query of recent conversations for a user's inbox list.
* **Partition Key**: `user_id`
* **Clustering Key**: `last_activity_at DESC, conversation_id ASC`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.conversations_by_user (
    user_id text,
    last_activity_at timestamp,
    conversation_id text,
    conversation_type text,
    membership_status text,
    unread_state_version int,
    PRIMARY KEY ((user_id), last_activity_at, conversation_id)
) WITH CLUSTERING ORDER BY (last_activity_at DESC, conversation_id ASC);
```

#### 6. `messages_by_conversation`
* **Access Pattern**: Chronological retrieval of conversation history; bounded pagination.
* **Partition Key**: `((conversation_id, message_bucket))` where `message_bucket` is `YYYYMM` (UTC).
* **Clustering Key**: `message_sequence ASC, message_id ASC`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.messages_by_conversation (
    conversation_id text,
    message_bucket text,
    message_sequence bigint,
    message_id text,
    sender_user_id text,
    sender_device_id text,
    message_priority text,
    accepted_at timestamp,
    ciphertext_envelope text,
    envelope_version int,
    file_reference_ids list<text>,
    PRIMARY KEY ((conversation_id, message_bucket), message_sequence, message_id)
) WITH CLUSTERING ORDER BY (message_sequence ASC, message_id ASC);
```

#### 7. `pending_deliveries_by_device`
* **Access Pattern**: Device-oriented active delivery queue; fetch undelivered envelopes for `DeviceId`.
* **Partition Key**: `((device_id, delivery_bucket))` where `delivery_bucket` is `YYYYMM` (UTC).
* **Clustering Key**: `accepted_at ASC, message_id ASC`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.pending_deliveries_by_device (
    device_id text,
    delivery_bucket text,
    accepted_at timestamp,
    message_id text,
    conversation_id text,
    message_sequence bigint,
    message_priority text,
    delivery_state text,
    attempt_count int,
    next_retry_at timestamp,
    PRIMARY KEY ((device_id, delivery_bucket), accepted_at, message_id)
) WITH CLUSTERING ORDER BY (accepted_at ASC, message_id ASC);
```

#### 8. `delivery_state_by_message`
* **Access Pattern**: Fan-out status tracking; query delivery status across all recipient devices for a message.
* **Partition Key**: `message_id`
* **Clustering Key**: `recipient_device_id ASC`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.delivery_state_by_message (
    message_id text,
    recipient_device_id text,
    recipient_user_id text,
    delivery_state text,
    delivered_at timestamp,
    read_at timestamp,
    PRIMARY KEY ((message_id), recipient_device_id)
);
```

#### 9. `sync_state_by_device`
* **Access Pattern**: Get/set incremental synchronization cursor for a device in a conversation.
* **Partition Key**: `device_id`
* **Clustering Key**: `conversation_id ASC`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.sync_state_by_device (
    device_id text,
    conversation_id text,
    last_synced_sequence bigint,
    last_sync_at timestamp,
    sync_version int,
    PRIMARY KEY ((device_id), conversation_id)
);
```

#### 10. `message_submission_by_idempotency_key`
* **Access Pattern**: Enforce atomic deduplication for client message retries.
* **Partition Key**: `((sender_device_id), idempotency_key)`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.message_submission_by_idempotency_key (
    sender_device_id text,
    idempotency_key text,
    message_id text,
    conversation_id text,
    message_sequence bigint,
    submission_status text,
    created_at timestamp,
    PRIMARY KEY ((sender_device_id), idempotency_key)
);
```

#### 11. `messaging_outbox_events`
* **Access Pattern**: Transactional outbox for event publishing (membership changes, message events).
* **Partition Key**: `outbox_bucket` (e.g. `YYYYMMDDHH` or shard key)
* **Clustering Key**: `created_at ASC, event_id ASC`
```sql
CREATE TABLE IF NOT EXISTS securecloud_messaging.messaging_outbox_events (
    outbox_bucket text,
    created_at timestamp,
    event_id text,
    conversation_id text,
    event_type text,
    payload_json text,
    published_at timestamp,
    publish_status text,
    PRIMARY KEY ((outbox_bucket), created_at, event_id)
) WITH CLUSTERING ORDER BY (created_at ASC, event_id ASC);
```

---

## 4. Dependency Graph & Ticket Decomposition

```text
               MSG-001 (Service Foundation & Worker Pools)
               MSG-002 (API Contracts & Error Mappers)
               MSG-003 (Conversation Domain & In-Memory Repos)
                                    │
                                    ▼
                               MSG-004-T01
               (ScyllaDB Schema, CQL Migrations & Keyspace Lifecycle)
                                    │
                                    ▼
                               MSG-004-T02
               (ScyllaDB Session Abstraction, Driver Pool & Query Execution)
                                    │
                                    ▼
                               MSG-004-T03
               (ScyllaDB Conversation & Membership Repositories)
                                    │
                                    ▼
                               MSG-004-T04
               (Message & Outbox Domain Models, Time-Bucketing & Repositories)
                                    │
                                    ▼
                               MSG-004-T05
               (Per-Device Delivery State, Sync Cursors & Idempotency Repos)
                                    │
                                    ▼
                               MSG-004-T06
               (ScyllaDB Persistence Integration Suite & Verification)
```

---

## 5. Detailed Implementation Tickets

### MSG-004-T01 — ScyllaDB Schema, CQL Migrations & Keyspace Lifecycle

1. **Ticket ID**: `MSG-004-T01`
2. **Title**: ScyllaDB Schema, CQL Migrations & Keyspace Lifecycle Runner
3. **Objective**: Define the complete CQL schema migrations for `securecloud_messaging` and implement an automated, idempotent schema initialization and migration runner.
4. **Architectural Purpose**: Establishes reproducible database provisioning across local development, Docker Compose, CI runners, and production clusters with SHA-256 script checksum validation.
5. **Scope**:
   - In `deploy/compose/scylla/` and `src/messaging/db/migrations/`:
     - Create `V001__create_messaging_keyspace.cql`: Keyspace definition with replication settings.
     - Create `V002__create_messaging_tables.cql`: Define all 11 tables (`conversations_by_id`, `direct_conversation_by_users`, `group_metadata_by_conversation`, `conversation_members_by_conversation`, `conversations_by_user`, `messages_by_conversation`, `pending_deliveries_by_device`, `delivery_state_by_message`, `sync_state_by_device`, `message_submission_by_idempotency_key`, `messaging_outbox_events`).
     - Create `V003__create_schema_version_tracking.cql`: Internal schema migration log table `schema_migrations` tracking `version`, `script_name`, `checksum`, `applied_at`.
   - In `src/messaging/db/migration_runner.hpp|cpp`:
     - Implement `ScyllaMigrationRunner` capable of:
       - Reading embedded or file-based CQL migrations.
       - Computing canonical SHA-256 checksums (CRLF normalized).
       - Executing statements sequentially against ScyllaDB.
       - Skipping already applied migrations; failing loudly on checksum mismatch.
   - In `scripts/init-scylladb-schema.sh`:
     - Shell script utilizing `docker compose exec -T scylladb cqlsh` to apply schema during automated compose boots.
   - In `scripts/verify-persistence-infra.sh`:
     - Add Check 10: Validate that all 11 messaging tables exist in `securecloud_messaging`.
   - Unit tests in `tests/unit/messaging/scylla_migration_runner_test.cpp`.
6. **Explicit Out-of-Scope**: Domain entity CRUD operations; driver connection pooling.
7. **Dependencies**: `MSG-001`, `ScyllaConfig`.
8. **Files to Create/Modify**:
   - `src/messaging/db/migrations/V001__create_messaging_keyspace.cql`
   - `src/messaging/db/migrations/V002__create_messaging_tables.cql`
   - `src/messaging/db/migrations/V003__create_schema_version_tracking.cql`
   - `src/messaging/db/migration_runner.hpp`
   - `src/messaging/db/migration_runner.cpp`
   - `scripts/init-scylladb-schema.sh`
   - `scripts/verify-persistence-infra.sh`
   - `tests/unit/messaging/scylla_migration_runner_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-004-T02 — ScyllaDB Session Abstraction, Driver Pool & Query Execution Layer

1. **Ticket ID**: `MSG-004-T02`
2. **Title**: ScyllaDB Client Session Abstraction, Connection Pool & Bound Statement Execution
3. **Objective**: Implement a resilient, non-blocking C++ driver session abstraction and connection pool for ScyllaDB supporting prepared statements, parameter binding, result decoding, and timeout handling.
4. **Architectural Purpose**: Decouples concrete driver details from repositories (ADR-005), prevents statement re-parsing via prepared statements cache, and translates database faults into `DomainErrorCode`s (ADR-009).
5. **Scope**:
   - In `src/messaging/db/`:
     - Define `IScyllaSession`:
       - `execute(const std::string& cql) -> Result<ScyllaQueryResult>`
       - `prepare(const std::string& query_id, const std::string& cql) -> Result<PreparedStatementId>`
       - `execute_prepared(PreparedStatementId id, const ScyllaParams& params) -> Result<ScyllaQueryResult>`
       - `execute_batch(const std::vector<BoundStatement>& batch, BatchType type) -> Result<void>`
       - `ping() -> bool`
       - `close() -> void`
     - Implement `ScyllaSession` and `ScyllaSessionPool`:
       - Wraps driver connection handle with configurable min/max connections, acquire timeouts, and request timeouts from `ScyllaConfig`.
       - Prepared statement cache avoiding redundant network roundtrips.
       - Consistency levels: Default `LOCAL_QUORUM` for strong read/write operations; `ONE` for latency-tolerant operations.
     - Implement `MockScyllaSession`:
       - In-memory mock implementing `IScyllaSession` for hermetic testing without running a live ScyllaDB daemon.
     - Error mapping:
       - Transient timeouts $\to$ `DomainErrorCode::Unavailable` / `ResourceExhausted`.
       - Invalid syntax / schema $\to$ `DomainErrorCode::Internal`.
       - Uniqueness conflict (LWT / duplicate) $\to$ `DomainErrorCode::AlreadyExists`.
   - Unit tests in `tests/unit/messaging/scylla_session_test.cpp`.
6. **Explicit Out-of-Scope**: Writing business domain repositories.
7. **Dependencies**: `MSG-004-T01`, `ScyllaConfig`.
8. **Files to Create/Modify**:
   - `src/messaging/db/scylla_session_interface.hpp`
   - `src/messaging/db/scylla_session.hpp`
   - `src/messaging/db/scylla_session.cpp`
   - `src/messaging/db/scylla_session_pool.hpp`
   - `src/messaging/db/scylla_session_pool.cpp`
   - `src/messaging/db/mock_scylla_session.hpp`
   - `src/messaging/db/scylla_error_mapper.hpp`
   - `src/messaging/db/scylla_error_mapper.cpp`
   - `tests/unit/messaging/scylla_session_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-004-T03 — ScyllaDB Conversation & Membership Repositories

1. **Ticket ID**: `MSG-004-T03`
2. **Title**: ScyllaDB Conversation and Membership Persistence Adapters
3. **Objective**: Implement production `ScyllaConversationRepository` and `ScyllaMembershipRepository` fulfilling the existing abstract contracts (`IConversationRepository` and `IMembershipRepository`) created in MSG-003.
4. **Architectural Purpose**: Transitions conversation metadata and participant rosters from ephemeral in-memory storage to authoritative, partitioned ScyllaDB tables without altering business logic or gRPC service contracts.
5. **Scope**:
   - In `src/messaging/repository/`:
     - Implement `ScyllaConversationRepository` (implements `IConversationRepository`):
       - `create_conversation`: Inserts row into `conversations_by_id`.
       - `find_by_id`: Queries `conversations_by_id` by partition key `conversation_id`.
       - `find_direct_pair`: Queries `direct_conversation_by_users` by composite partition key `((user_a_id, user_b_id))`.
       - `save_direct_pair`: Inserts row into `direct_conversation_by_users`.
       - `update_group_metadata`: Upserts into `group_metadata_by_conversation`.
       - `get_group_metadata`: Queries `group_metadata_by_conversation` by `conversation_id`.
     - Implement `ScyllaMembershipRepository` (implements `IMembershipRepository`):
       - `add_participant`: Inserts into `conversation_members_by_conversation` and updates `conversations_by_user`.
       - `update_participant_status`: Updates participant row and user's inbox list.
       - `get_participant`: Queries single row from `conversation_members_by_conversation` where `conversation_id = ? AND user_id = ?`.
       - `list_active_participants`: Queries partition `conversation_id` filtering for `ACTIVE`.
       - `list_conversations_for_user`: Paginated clustering key scan on `conversations_by_user` ordered by `last_activity_at DESC`.
   - Unit tests in `tests/unit/messaging/scylla_conversation_repository_test.cpp` using `MockScyllaSession`.
6. **Explicit Out-of-Scope**: Message body storage; delivery tracking.
7. **Dependencies**: `MSG-004-T02`, `MSG-003-T02` (`IConversationRepository`, `IMembershipRepository`).
8. **Files to Create/Modify**:
   - `src/messaging/repository/scylla_conversation_repository.hpp`
   - `src/messaging/repository/scylla_conversation_repository.cpp`
   - `src/messaging/repository/scylla_membership_repository.hpp`
   - `src/messaging/repository/scylla_membership_repository.cpp`
   - `tests/unit/messaging/scylla_conversation_repository_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-004-T04 — Message & Outbox Domain Models, Time-Bucketing & ScyllaDB Repositories

1. **Ticket ID**: `MSG-004-T04`
2. **Title**: Message Entity, Monthly Time-Bucketing, Outbox Persistence & ScyllaDB Message Repository
3. **Objective**: Establish the strongly-typed `MessageEntity`, monthly UTC time-bucket calculator (`MessageBucket`), outbox event storage, and implement `ScyllaMessageRepository` and `ScyllaOutboxRepository`.
4. **Architectural Purpose**: Implements the immutable message persistence tier conforming to ADR-007, bounding ScyllaDB partition sizes using monthly buckets (`YYYYMM`) and guaranteeing canonical per-conversation sequence ordering (`message_sequence ASC`).
5. **Scope**:
   - In `src/messaging/domain/`:
     - Value Objects & Entities:
       - `MessageId`: UUIDv7 value object.
       - `MessageSequence`: Monotonically increasing per-conversation `uint64_t`.
       - `MessagePriority`: `NORMAL`, `URGENT`, `EMERGENCY`.
       - `MessageBucket`: Formats and validates UTC `YYYYMM` bucket strings (e.g., `202610`) from timestamps.
       - `CiphertextEnvelope`: Opaque byte/string container for encrypted payload with envelope version.
       - `MessageEntity`: Aggregates `message_id`, `conversation_id`, `message_bucket`, `message_sequence`, `sender_user_id`, `sender_device_id`, `priority`, `accepted_at`, `envelope`, `file_reference_ids`.
   - In `src/messaging/repository/`:
     - Define `IMessageRepository`:
       - `save_message(const MessageEntity& msg) -> Result<void>`
       - `find_by_id(const ConversationId& conv_id, const MessageBucket& bucket, const MessageId& id) -> Result<std::optional<MessageEntity>>`
       - `list_messages_by_sequence_range(const ConversationId& conv_id, const MessageBucket& bucket, uint64_t from_seq, uint64_t to_seq, int limit) -> Result<std::vector<MessageEntity>>`
       - `get_last_sequence(const ConversationId& conv_id) -> Result<uint64_t>`
     - Implement `ScyllaMessageRepository`:
       - Bound write query targeting `((conversation_id, message_bucket), message_sequence, message_id)`.
       - Range clustering scan: `WHERE conversation_id = ? AND message_bucket = ? AND message_sequence >= ? ORDER BY message_sequence ASC LIMIT ?`.
     - Define and implement `IOutboxRepository` and `ScyllaOutboxRepository`:
       - `enqueue_event(const ConversationOutboxEvent& event) -> Result<void>`
       - `fetch_pending_events(const std::string& bucket, int limit) -> Result<std::vector<ConversationOutboxEvent>>`
       - `mark_event_published(const std::string& bucket, const std::string& event_id) -> Result<void>`
   - Unit tests in `tests/unit/messaging/scylla_message_repository_test.cpp` and `tests/unit/messaging/message_bucket_test.cpp`.
6. **Explicit Out-of-Scope**: End-to-end cryptographic decryption; sequence allocation worker (MSG-005).
7. **Dependencies**: `MSG-004-T02`, `MSG-003-T01`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/message_types.hpp`
   - `src/messaging/domain/message_bucket.hpp`
   - `src/messaging/domain/message_bucket.cpp`
   - `src/messaging/domain/message_entity.hpp`
   - `src/messaging/repository/message_repository_interface.hpp`
   - `src/messaging/repository/scylla_message_repository.hpp`
   - `src/messaging/repository/scylla_message_repository.cpp`
   - `src/messaging/repository/outbox_repository_interface.hpp`
   - `src/messaging/repository/scylla_outbox_repository.hpp`
   - `src/messaging/repository/scylla_outbox_repository.cpp`
   - `tests/unit/messaging/message_bucket_test.cpp`
   - `tests/unit/messaging/scylla_message_repository_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-004-T05 — Per-Device Delivery State, Sync Cursors & Idempotency Repositories

1. **Ticket ID**: `MSG-004-T05`
2. **Title**: Per-Device Delivery State, Device Synchronization Cursors & Submission Idempotency Repositories
3. **Objective**: Implement persistence repositories for recipient-device delivery queues (`pending_deliveries_by_device`), message delivery status history (`delivery_state_by_message`), synchronization cursors (`sync_state_by_device`), and client idempotency deduplication records (`message_submission_by_idempotency_key`).
4. **Architectural Purpose**: Establishes the durable primitives required by the online delivery engine (`MSG-007`), read receipt pipeline (`MSG-008`), and incremental sync engine (`MSG-009`) without creating global bottlenecks or unpartitioned tables.
5. **Scope**:
   - In `src/messaging/domain/`:
     - Entities & Value Objects:
       - `DeviceId`: Opaque device identifier.
       - `DeviceDeliveryStatus`: `QUEUED`, `DELIVERING`, `DELIVERED`, `RETRY_WAIT`, `EXPIRED`.
       - `DeviceDeliveryRecord`: `device_id`, `delivery_bucket`, `accepted_at`, `message_id`, `conversation_id`, `sequence`, `priority`, `status`, `attempt_count`, `next_retry_at`.
       - `DeviceSyncCursor`: `device_id`, `conversation_id`, `last_synced_sequence`, `last_sync_at`, `version`.
       - `IdempotencyRecord`: `sender_device_id`, `idempotency_key`, `message_id`, `conversation_id`, `message_sequence`, `status`, `created_at`.
   - In `src/messaging/repository/`:
     - Define `IDeliveryStateRepository`:
       - `create_pending_deliveries(const std::vector<DeviceDeliveryRecord>& records) -> Result<void>`
       - `fetch_pending_for_device(const DeviceId& device_id, const std::string& bucket, int limit) -> Result<std::vector<DeviceDeliveryRecord>>`
       - `update_delivery_status(const DeviceId& device_id, const std::string& bucket, const MessageId& msg_id, DeviceDeliveryStatus status, int attempts, std::optional<Timestamp> next_retry) -> Result<void>`
       - `record_device_delivery_ack(const MessageId& msg_id, const DeviceId& device_id, Timestamp delivered_at) -> Result<void>`
       - `record_device_read_ack(const MessageId& msg_id, const DeviceId& device_id, Timestamp read_at) -> Result<void>`
       - `get_delivery_states_for_message(const MessageId& msg_id) -> Result<std::vector<DeviceDeliveryRecord>>`
     - Define `ISyncCursorRepository`:
       - `get_sync_cursor(const DeviceId& device_id, const ConversationId& conv_id) -> Result<std::optional<DeviceSyncCursor>>`
       - `advance_sync_cursor(const DeviceId& device_id, const ConversationId& conv_id, uint64_t new_sequence) -> Result<void>`
     - Define `IIdempotencyRepository`:
       - `find_submission(const DeviceId& sender_device_id, const std::string& idempotency_key) -> Result<std::optional<IdempotencyRecord>>`
       - `record_submission(const IdempotencyRecord& record) -> Result<void>`
     - Implement ScyllaDB persistence adapters:
       - `ScyllaDeliveryStateRepository`
       - `ScyllaSyncCursorRepository`
       - `ScyllaIdempotencyRepository`
   - Unit tests in `tests/unit/messaging/scylla_delivery_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Background scheduler worker threads; push notification dispatch.
7. **Dependencies**: `MSG-004-T02`, `MSG-004-T04`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/delivery_types.hpp`
   - `src/messaging/domain/sync_types.hpp`
   - `src/messaging/domain/idempotency_types.hpp`
   - `src/messaging/repository/delivery_state_repository_interface.hpp`
   - `src/messaging/repository/scylla_delivery_state_repository.hpp`
   - `src/messaging/repository/scylla_delivery_state_repository.cpp`
   - `src/messaging/repository/sync_cursor_repository_interface.hpp`
   - `src/messaging/repository/scylla_sync_cursor_repository.hpp`
   - `src/messaging/repository/scylla_sync_cursor_repository.cpp`
   - `src/messaging/repository/idempotency_repository_interface.hpp`
   - `src/messaging/repository/scylla_idempotency_repository.hpp`
   - `src/messaging/repository/scylla_idempotency_repository.cpp`
   - `tests/unit/messaging/scylla_delivery_repository_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-004-T06 — ScyllaDB Persistence Integration Suite & Verification

1. **Ticket ID**: `MSG-004-T06`
2. **Title**: Comprehensive Messaging ScyllaDB Persistence Integration Suite & Failure Verification
3. **Objective**: Validate the full persistence layer against containerized ScyllaDB under realistic concurrency, partition boundaries, monthly bucket rollover, and failure simulation.
4. **Architectural Purpose**: Certifies that all 11 tables perform according to the documented partition and clustering design, verifies zero regressions across the codebase, and prevents hot partitions.
5. **Scope**:
   - Create `tests/integration/messaging_persistence_integration_test.cpp`:
     - Test Fixture with `GTEST_SKIP()` guard when ScyllaDB container on `127.0.0.1:9042` is offline.
     - **Test Case 1: Keyspace Schema & Migration Verification**:
       - Runs `ScyllaMigrationRunner`, validates idempotent re-application, and confirms table metadata.
     - **Test Case 2: Conversation & Canonical Direct Pair Dual-Write**:
       - Creates direct conversation, verifies `conversations_by_id` and `direct_conversation_by_users` persistence.
       - Queries with reversed user order `(user_b, user_a)` and verifies idempotent match.
     - **Test Case 3: Paginated User Conversation Inbox Ordering**:
       - Seeds multiple conversations with varying timestamps for `user_1`.
       - Queries `conversations_by_user` and verifies descending order by `last_activity_at`.
     - **Test Case 4: Message Monthly Bucket Partitioning & Sequence Ordering**:
       - Seeds messages across month boundary (`202609` and `202610`).
       - Verifies that messages reside in distinct physical partitions while ordering remains monotonically increasing within each bucket.
     - **Test Case 5: Recipient Device Delivery Fan-Out & Ack Transitions**:
       - Simulates message sent to 3 devices: writes pending delivery records for `device_1`, `device_2`, `device_3`.
       - Transitions `device_1` $\to$ `DELIVERED`, `device_2` $\to$ `READ`.
       - Verifies `pending_deliveries_by_device` and `delivery_state_by_message` consistency.
     - **Test Case 6: Submission Idempotency Under Retry**:
       - Records submission with `idempotency_key = "idem-100"`.
       - Subsequent query with identical key retrieves stored `MessageId` without secondary inserts.
     - **Test Case 7: Transient Failure & Disconnect Handling**:
       - Validates timeout behavior and error mapping when connection limits or request timeouts trigger.
   - Run complete test suite across all cumulative tests with `python3 scripts/verify-local.py --preset dev-debug`.
6. **Explicit Out-of-Scope**: End-to-end WebSocket client delivery (Cards MSG-007, MSG-009).
7. **Dependencies**: `MSG-004-T01` through `MSG-004-T05`.
8. **Files to Create/Modify**:
   - `tests/integration/messaging_persistence_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`
   - `specs/phase2/MSG-004-tickets.md`

---

## 6. Acceptance Criteria & Card Validation Matrix

| Criterion | Target Specification | Validation Mechanism |
| :--- | :--- | :--- |
| **Messaging Keyspace & Schema** | `securecloud_messaging` keyspace and all 11 tables defined with exact partition/clustering keys | `tests/integration/messaging_persistence_integration_test.cpp` |
| **Schema Migration Tooling** | Idempotent migration runner with SHA-256 script hashing | `tests/unit/messaging/scylla_migration_runner_test.cpp` |
| **Driver & Session Abstraction** | `IScyllaSession` with prepared statement caching and pool management | `tests/unit/messaging/scylla_session_test.cpp` |
| **Conversation Persistence** | `ScyllaConversationRepository` and `ScyllaMembershipRepository` satisfy `IConversationRepository`/`IMembershipRepository` | `tests/unit/messaging/scylla_conversation_repository_test.cpp` |
| **Time-Bucketed Message Storage** | Messages partitioned by `((conversation_id, message_bucket))` with monthly UTC buckets (`YYYYMM`) | `tests/unit/messaging/message_bucket_test.cpp` & integration test |
| **Device-Oriented Delivery** | `pending_deliveries_by_device` partitioned by `((device_id, delivery_bucket))` | `tests/unit/messaging/scylla_delivery_repository_test.cpp` |
| **Delivery History & Receipts** | `delivery_state_by_message` tracks fan-out delivery and read receipts | `tests/integration/messaging_persistence_integration_test.cpp` |
| **Device Synchronization Cursors** | `sync_state_by_device` stores resumable incremental sync state | Unit and integration persistence tests |
| **Idempotent Submission Records** | `message_submission_by_idempotency_key` deduplicates client retries | `tests/integration/messaging_persistence_integration_test.cpp` |
| **Outbox Event Persistence** | `messaging_outbox_events` enables transactional event publication | `tests/unit/messaging/scylla_message_repository_test.cpp` |
| **No Hot / Global Partitions** | No global delivery table, no unbucketed message partitions | Architectural review & query inspection |
| **Failure & Timeout Resilience** | Database errors mapped cleanly to `DomainErrorCode` without leaking raw driver errors | `tests/unit/messaging/scylla_session_test.cpp` |
| **Hermetic & Integration Test Safety** | Mocks enable 100% offline unit tests; live tests use `GTEST_SKIP()` when ScyllaDB is offline | CI test runner & `verify-local.py` |
| **Zero Regressions** | All existing unit and integration tests (1,391+) continue to pass | `ctest --preset dev-debug` |

---

## 7. Architectural Invariants & Verification Checklist

- [ ] **Authoritative ScyllaDB Ownership**: Messaging exclusively owns the `securecloud_messaging` keyspace; no other service accesses ScyllaDB directly (ADR-005, ADR-006).
- [ ] **No Global Delivery Queue**: Delivery state is partitioned by recipient `DeviceId` and bucket; there is no shared global queue table.
- [ ] **Monthly Time-Bucketed Partitions**: Message partitions are bounded using monthly UTC buckets (`YYYYMM`) preventing unbounded partition growth (ADR-007, ADR-010).
- [ ] **Canonical Sequence Order**: Messages are clustered by `message_sequence ASC`; client timestamps never dictate ordering.
- [ ] **Separation of Repository Interfaces**: Repositories expose abstract C++ domain interfaces (`IConversationRepository`, `IMembershipRepository`, `IMessageRepository`, `IDeliveryStateRepository`, `ISyncCursorRepository`); domain logic is insulated from ScyllaDB specifics.
- [ ] **Prepared Statements Everywhere**: All query execution uses parameterized prepared statements to prevent injection and avoid re-parsing overhead.
- [ ] **Idempotent Submission Deduplication**: Submission records preserve message identity across network retry boundaries.
- [ ] **Transient Presence Decoupled**: Ephemeral presence heartbeats are never persisted into durable delivery state tables.
- [ ] **Ciphertext Envelope Opacity**: Message content remains opaque encrypted ciphertext; zero private key material is stored (ADR-008).
- [ ] **No In-Memory Authority**: In-memory queues are ephemeral; all state required for delivery recovery is durably persisted in ScyllaDB.
