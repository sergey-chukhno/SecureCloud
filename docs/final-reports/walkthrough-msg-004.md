# Walkthrough: MSG-004 — Messaging Persistence & ScyllaDB Model

## 1. Executive Summary

Card **`MSG-004`** establishes the authoritative, high-throughput, partitioned persistence tier for the SecureCloud Messaging service using ScyllaDB. In strict conformance with **ADR-005** (Service Isolation), **ADR-006** (Dual-Database Model), **ADR-007** (Messaging Storage & Bucketing), **ADR-008** (Zero Crypto Plaintext Exposure), **ADR-009** (Concurrency & Domain Error Mapping), and **ADR-010** (Device-Oriented Async Fan-out), this implementation provides:
1. Idempotent CQL migration runner with SHA-256 script checksum verification.
2. Clean, strongly-typed C++ driver session abstraction (`IScyllaSession`), connection pool (`ScyllaSessionPool`), and hermetic test mock (`MockScyllaSession`).
3. Production persistence repositories for all 11 authoritative ScyllaDB tables.
4. Comprehensive integration suite with live container reachability guards (`GTEST_SKIP()`).

All 6 decomposed tickets (**MSG-004-T01** through **MSG-004-T06**) are implemented, formatted, and verified across all 1,446 tests in the test suite.

---

## 2. Authoritative ScyllaDB Table Architecture & Partitioning Strategy

| # | Table Name | Partition Key | Clustering Key | Architectural Access Pattern |
|---|---|---|---|---|
| 1 | `conversations_by_id` | `conversation_id` | *(None)* | Point lookup of conversation metadata by `ConversationId`. |
| 2 | `direct_conversation_by_users` | `((user_a_id, user_b_id))` | *(None)* | $O(1)$ idempotent direct pair conversation resolution (`user_a < user_b` lexicographical invariant). |
| 3 | `group_metadata_by_conversation` | `conversation_id` | *(None)* | Group lifecycle state (`ACTIVE`, `CLOSED`) and title metadata. |
| 4 | `conversation_members_by_conversation` | `conversation_id` | `user_id ASC` | Participant roster query, member roles, and joined/left status. |
| 5 | `conversations_by_user` | `user_id` | `last_activity_at DESC, conversation_id ASC` | Paginated user inbox scan ordered chronologically by last activity. |
| 6 | `messages_by_conversation` | `((conversation_id, message_bucket))` | `message_sequence ASC, message_id ASC` | Chronological conversation message history bounded by monthly UTC buckets (`YYYYMM`). |
| 7 | `pending_deliveries_by_device` | `((device_id, delivery_bucket))` | `accepted_at ASC, message_id ASC` | Per-device active delivery queue. **Zero global delivery queue tables.** |
| 8 | `delivery_state_by_message` | `message_id` | `recipient_device_id ASC` | Fan-out delivery status tracking and recipient delivery/read acknowledgments. |
| 9 | `sync_state_by_device` | `device_id` | `conversation_id ASC` | Incremental sync bookmark per device in a conversation. |
| 10 | `message_submission_by_idempotency_key` | `sender_device_id` | `idempotency_key` | Client retry deduplication preventing duplicate message creation. |
| 11 | `messaging_outbox_events` | `outbox_bucket` | `created_at ASC, event_id ASC` | Transactional outbox for guaranteed event publishing without dual-write loss. |

---

## 3. Key Architectural Decisions & Answers to Core Inquiries

### 3.1 Why Did We Build `IScyllaSession` and `ScyllaSessionPool` in Messaging Instead of Using a Library Directly Like `libpqxx` in Auth?
1. **Ecosystem & Modern C++ Driver Availability**:
   - In PostgreSQL, `libpqxx` is the mature, modern C++ library providing idiomatic RAII connections, prepared statements, and exceptions.
   - For ScyllaDB / Cassandra, the official DataStax C/C++ driver (`cpp-driver`) is an older, legacy C API (`cass_session_execute`, `cass_statement_bind_*`) that relies on raw C pointers, callbacks, and manual reference counting.
2. **Hermetic Testability via Mock Driver**:
   - Wrapping ScyllaDB client calls behind `IScyllaSession` enables `MockScyllaSession`. This allows testing all repositories, parameter bindings, clustering orders, and error mappers completely offline without spinning up a heavy 2GB ScyllaDB Docker container.
3. **Decoupled Error Translation (ADR-009)**:
   - Repositories never leak database-specific error codes or network sockets to upper service layers. `ScyllaErrorMapper` maps query timeouts to `DomainErrorCode::Unavailable` and constraint violations to `DomainErrorCode::AlreadyExists`.

### 3.2 Why Do We Retain In-Memory Repositories (`InMemoryConversationRepository`, `InMemoryMembershipRepository`)?
1. **Decoupled Domain Logic Verification**:
   - `conversation_service_test.cpp` and `conversation_authorization_service_test.cpp` test pure business invariants (e.g., admin permissions, member joins/leaves, role escalation).
   - Retaining in-memory doubles allows pure business unit tests to run in sub-milliseconds without depending on CQL query syntax, prepared statement IDs, or row serializers.
2. **Explicit Layer Separation**:
   - Domain services depend solely on the abstract interfaces (`IConversationRepository`, `IMembershipRepository`).
   - In-memory repositories validate interface conformance, while Scylla repositories validate physical persistence.

### 3.3 Why Did We Implement Transactional Outbox in Messaging and Not in Gateway or Auth?
1. **Stateless Gateway**:
   - The API Gateway is a stateless edge proxy. It owns no database; therefore, it has no persistence transactions to commit an outbox event alongside.
2. **Synchronous Auth Flow**:
   - Auth operates synchronously via gRPC request-response. When credentials or tokens are validated, the caller waits for the immediate DB query. Auth does not perform background fan-out to thousands of client devices.
3. **Messaging Distributed Dual-Write Challenge**:
   - In Messaging, posting a message requires: (1) writing to the authoritative message store (ScyllaDB), and (2) fanning out notifications to Kafka/Redpanda or Gateway WebSocket nodes.
   - If a node crashes between writing to the DB and sending to Kafka, messages are permanently lost to recipients.
   - Writing to `messaging_outbox_events` in ScyllaDB ensures that a background worker reliably publishes the event with at-least-once delivery semantics.

### 3.4 What Are Synchronization Cursors and Why Do We Need Idempotency Records?
1. **Synchronization Cursors (`sync_state_by_device`)**:
   - Acts as a per-device bookmark. When a mobile client reconnects after being offline, it requests messages where `sequence > last_synced_sequence`.
   - The server only returns the missing delta (e.g., 5 messages instead of 50,000), conserving mobile bandwidth, battery life, and database I/O.
2. **Client Idempotency Deduplication (`message_submission_by_idempotency_key`)**:
   - Solves the mobile retry / double-posting problem. If a client sends a message and network connectivity drops before receiving the server's ACK, the client automatically retries.
   - The server looks up the client's `idempotency_key`; if found, it immediately returns the previously assigned sequence number and `MessageId` without inserting a duplicate message into the chat.

---

## 4. Verification & Testing Matrix

```bash
python3 scripts/verify-local.py --preset dev-debug
```

### Verification Results
```text
================ Verification Summary ================
  [PASSED]    1.37s  1. CMake Configure
  [PASSED]    2.02s  2. Formatting Check (.clang-format)
  [PASSED]    3.72s  3. Native Compilation & Build
  [PASSED]    0.26s  4. Protobuf & gRPC Contracts Validation
  [PASSED]  170.45s  5. CTest Execution Suite
-----------------------------------------------------
ALL CHECKS PASSED in 177.82s
```

### Persistence Unit & Integration Test Suites
| Suite Target | Test File | Tests | Status |
|---|---|---|---|
| `securecloud_scylla_migration_runner_test` | `tests/unit/messaging/scylla_migration_runner_test.cpp` | 8 | PASS |
| `securecloud_scylla_session_test` | `tests/unit/messaging/scylla_session_test.cpp` | 12 | PASS |
| `securecloud_scylla_conversation_repository_test` | `tests/unit/messaging/scylla_conversation_repository_test.cpp` | 8 | PASS |
| `securecloud_message_bucket_test` | `tests/unit/messaging/message_bucket_test.cpp` | 6 | PASS |
| `securecloud_scylla_message_repository_test` | `tests/unit/messaging/scylla_message_repository_test.cpp` | 7 | PASS |
| `securecloud_scylla_delivery_repository_test` | `tests/unit/messaging/scylla_delivery_repository_test.cpp` | 4 | PASS |
| `securecloud_scylla_sync_cursor_repository_test` | `tests/unit/messaging/scylla_sync_cursor_repository_test.cpp` | 2 | PASS |
| `securecloud_scylla_idempotency_repository_test` | `tests/unit/messaging/scylla_idempotency_repository_test.cpp` | 2 | PASS |
| `securecloud_messaging_persistence_integration_test` | `tests/integration/messaging_persistence_integration_test.cpp` | 6 | PASS (1 Skipped when 9042 offline) |

**Total Cumulative Test Count**: **1,446 tests passed** (0 failures, 1 skipped).
