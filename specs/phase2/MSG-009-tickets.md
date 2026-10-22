# MSG-009 — Online Message Synchronization
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-009  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Proposal & Decomposition Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 22, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-009** establishes the authoritative, durable **Online Message Synchronization** engine for SecureCloud Messaging (`securecloud-messaging`), adhering strictly to **ADR-007** (Messaging Reliability & Durability), **ADR-008** (Security & Cryptographic Architecture), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance, Capacity & Optimization Strategy).

While **MSG-005** established durable message submission and sequence allocation, **MSG-007** established active online dispatch, and **MSG-008** established multi-device delivery state tracking and read receipts, **MSG-009 provides the pull-based and reconnect-based synchronization protocol**. It allows connected and reconnecting client devices to deterministically recover missed encrypted messages and authoritative delivery/read status updates, advance checkpoints without loss, resume interrupted transfers, and maintain local SQLite replica consistency.

### 1.1 The Fundamental Architectural Decoupling
As formalized in MSG-008, SecureCloud enforces strict decoupling across all state dimensions:
$$\text{Presence} \neq \text{Delivery} \neq \text{Read} \neq \text{Synchronization}$$

- **Presence** (`IDeviceConnectionRegistry`): Ephemeral transport socket connection status.
- **Delivery** (`delivery_state_by_message`): Per-device receipt verification (`QUEUED` $\to$ `DELIVERING` $\to$ `DELIVERED`).
- **Read** (`delivery_state_by_message`): Logical user UI display verification.
- **Synchronization** (`sync_state_by_device`): Per-device durable cursor sequence watermark (`last_synced_sequence`). Synchronizing ciphertext to local storage does **not** imply delivery acknowledgement or user read.

### 1.2 Non-Negotiable Architectural Boundaries
1. **Zero Plaintext Invariant (ADR-008)**: The Messaging backend synchronizes opaque ciphertext envelopes (`EncryptedPayload`) only. It never possesses message encryption keys, never decrypts payloads, and logs only structured metadata (`MessageId`, `ConversationId`, `Sequence`, `SenderId`).
2. **Authoritative Persistence (ADR-007)**: All synchronization state is backed durably by ScyllaDB (`messages_by_conversation`, `sync_state_by_device`, `delivery_state_by_message`). No transient in-memory buffers are treated as authoritative checkpoints.
3. **Strict Boundary Authorization**: Synchronization requests require verified caller authentication, active conversation membership, and active (non-revoked) device status.
4. **No Premature Brokers**: No Kafka, RabbitMQ, or Redis is introduced. Synchronization queries execute directly against optimized ScyllaDB partition clusters.

---

## 2. Core Invariants & Synchronization Protocol Design

```text
 Client Device (Reconnect)               Gateway Proxy                    Messaging Service                  ScyllaDB Cluster
       │                                       │                                   │                                 │
       │ 1. GET /conversations/{id}/messages?  │                                   │                                 │
       │    since_sequence=85&limit=50         │                                   │                                 │
       ├──────────────────────────────────────►│                                   │                                 │
       │                                       │ 2. gRPC SyncDeviceMessages()      │                                 │
       │                                       ├──────────────────────────────────►│                                 │
       │                                       │                                   │ 3. Validate membership & device │
       │                                       │                                   │    (AuthService / ScyllaDB)     │
       │                                       │                                   │                                 │
       │                                       │                                   │ 4. Read messages (seq 86..100)  │
       │                                       │                                   ├────────────────────────────────►│
       │                                       │                                   │◄────────────────────────────────┤
       │                                       │                                   │ 5. Hydrate delivery/read states │
       │                                       │                                   ├────────────────────────────────►│
       │                                       │                                   │◄────────────────────────────────┤
       │                                       │ 6. Return MessageEnvelopes &      │                                 │
       │                                       │    next_sequence=100              │                                 │
       │                                       │◄──────────────────────────────────┤                                 │
       │ 7. Return 200 OK (JSON batch)         │                                   │                                 │
       │◄──────────────────────────────────────┤                                   │                                 │
       │                                                                           │                                 │
       │ 8. Local Durability Phase (SQLite):                                       │                                 │
       │    Write ciphertext to local storage; commit transaction.                 │                                 │
       │                                                                           │                                 │
       │ 9. PUT /devices/{id}/cursor (advances cursor to 100)                      │                                 │
       ├──────────────────────────────────────────────────────────────────────────►│ 10. UpdateSyncCursor(seq=100)   │
       │                                                                           ├────────────────────────────────►│
       │                                                                           │    (Updates ScyllaDB cursor)    │
```

### 2.1 The Two-Phase Persistence Rule
To prevent data loss during client crashes, the client **must durably persist** received ciphertext into local SQLite **before** sending an updated synchronization cursor to the server:
1. Client fetches batch `[seq_start, seq_end]`.
2. Client persists messages into local database.
3. Client issues `UpdateSyncCursor(last_synced_sequence = seq_end)`.
If a client crashes or disconnects between steps 2 and 3, upon reconnect it replays from `seq_start`; since submission and storage are idempotent, duplicate retrieval produces no side-effects.

### 2.2 Cursor Monotonicity and Validation
- **Initial Sync**: `since_sequence == 0`. Server returns messages from sequence 1 up to batch limit.
- **Incremental Sync**: `since_sequence > 0`. Server queries `messages_by_conversation` where `message_sequence > since_sequence`.
- **Out of Bounds**: If `since_sequence > current_highest_sequence`, server rejects with `MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS`.
- **Monotonic Advancement**: Server rejects cursor updates where `new_sequence < existing_stored_sequence` (preventing regressions from out-of-order client requests).

---

## 3. Implementation Tickets Decomposition

### Summary of Tickets

| Ticket ID | Title | Primary Components | Estimated Scope |
| :--- | :--- | :--- | :--- |
| **MSG-009-T01** | Protobuf & Domain Synchronization Contracts Alignment | `messaging.proto`, `domain/sync_types.hpp`, `sync_commands.hpp` | Contracts & Types |
| **MSG-009-T02** | Cursor Management Engine & Monotonic Checkpoint Guard | `SyncCursorManager`, `ISyncCursorRepository` | Core Logic / Storage |
| **MSG-009-T03** | Bounded Message Sync & State Hydration Service | `MessageSyncService`, `IMessageRepository`, `IDeliveryStateRepository` | Core Engine |
| **MSG-009-T04** | Gateway HTTP Proxy Message Sync Route Integration | `MessagingProxyHandler`, `GatewayConfig`, Router | Gateway API |
| **MSG-009-T05** | MessagingService gRPC Sync RPCs & Threadpool Offloading | `MessagingServiceImpl`, `MessagingServiceConfig` | gRPC Server |
| **MSG-009-T06** | Unit & Integration Test Suite for Online Synchronization | Unit tests, Integration tests, Restart Verification | Quality & Validation |

---

### MSG-009-T01 — Protobuf & Domain Synchronization Contracts Alignment

1. **Ticket ID**: `MSG-009-T01`
2. **Objective**:
   - Align gRPC Protobuf definitions and C++20 domain command/result structures to support both conversation-scoped message retrieval (`GetMessages`) and device-scoped synchronization (`SyncDeviceMessages`, `GetSyncCursor`, `UpdateSyncCursor`).
   - Ensure backward compatibility while adding optional conversation scoping to device sync.
3. **Files Expected to Change**:
   - `proto/securecloud/messaging/v1/messaging.proto`
   - `src/messaging/domain/sync_types.hpp`
   - `src/messaging/service/sync_commands.hpp` (New)
4. **Dependencies**:
   - `MSG-002` (Protobuf baseline)
   - `MSG-004` (Domain primitives)
5. **Implementation Approach**:
   - In `proto/securecloud/messaging/v1/messaging.proto`:
     - Add `string conversation_id = 4;` to `SyncCursor` and `SyncDeviceMessagesRequest` (optional field).
     - Add `int64 latest_sequence = 6;` to `SyncDeviceMessagesResponse` to indicate stream ceiling.
   - In `src/messaging/domain/sync_types.hpp`:
     - Enhance `DeviceSyncCursor` with validation helpers (`is_valid()`, `can_advance_to(new_seq)`).
   - In `src/messaging/service/sync_commands.hpp`:
     - Define `SyncDeviceMessagesCommand`, `SyncMessagesResult`, `GetSyncCursorCommand`, `UpdateSyncCursorCommand`.
     - Define typed batch limits (`k_default_sync_batch_size = 50`, `k_max_sync_batch_size = 500`).
6. **Tests & Validation**:
   - Compile target `securecloud_proto` and ensure zero generation warnings.
   - Add unit tests verifying serialization, default sequence values, and equality comparisons.
7. **Security & Privacy Considerations**:
   - All message payloads remain `EncryptedPayload`.
   - Error messages redact sensitive metadata.
8. **Explicit Acceptance Criteria**:
   - Protobuf generation passes on GCC/Clang/MSVC.
   - Domain structures enforce C++20 standard constraints (`constexpr`, `noexcept` where applicable).

---

### MSG-009-T02 — Cursor Management Engine & Monotonic Checkpoint Guard

1. **Ticket ID**: `MSG-009-T02`
2. **Objective**:
   - Implement `SyncCursorManager` governing per-device synchronization cursors backed by `ISyncCursorRepository` (`securecloud_messaging.sync_state_by_device`).
   - Enforce strict monotonic progression, boundary validation against conversation sequence ceilings, and safe initial-sync handling.
3. **Files Expected to Change**:
   - `src/messaging/service/sync_cursor_manager.hpp` (New)
   - `src/messaging/service/sync_cursor_manager.cpp` (New)
   - `src/messaging/repository/sync_cursor_repository_interface.hpp`
   - `src/messaging/repository/scylla_sync_cursor_repository.hpp` / `.cpp`
   - `src/messaging/CMakeLists.txt`
4. **Dependencies**:
   - `MSG-009-T01` (Command types)
   - `MSG-004` (`ScyllaSyncCursorRepository`)
5. **Implementation Approach**:
   - Implement `SyncCursorManager` with dependencies:
     - `std::shared_ptr<repository::ISyncCursorRepository>`
     - `std::shared_ptr<repository::IMessageRepository>` (to verify sequence ceiling)
   - Operations:
     - `get_cursor(device_id, conversation_id)`: returns persisted cursor or initial default (sequence = 0).
     - `update_cursor(device_id, conversation_id, new_sequence)`:
       - Fails closed if `new_sequence > latest_allocated_sequence` (`MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS`).
       - Fails closed if `new_sequence < current_persisted_sequence` (prevents regression, returns conflict or false).
       - Persists atomically via `upsert_sync_cursor`.
6. **Tests & Validation**:
   - Unit tests in `tests/unit/messaging/sync_cursor_manager_test.cpp`:
     - Initial cursor retrieval on clean device returns sequence 0.
     - Sequential cursor advancement (`0 -> 10 -> 25`).
     - Regression rejection (`25 -> 10` returns error).
     - Duplicate update (`25 -> 25` returns idempotent success).
     - Out of bounds rejection (`new_sequence > conversation_max`).
7. **Security & Privacy Considerations**:
   - Devices cannot update cursors for conversations they do not belong to.
8. **Explicit Acceptance Criteria**:
   - Cursors are strictly monotonic per `(device_id, conversation_id)`.
   - All unit tests pass 100%.

---

### MSG-009-T03 — Bounded Message Sync & State Hydration Service

1. **Ticket ID**: `MSG-009-T03`
2. **Objective**:
   - Implement `MessageSyncService` executing initial and incremental synchronization queries against `IMessageRepository` and hydrating authoritative delivery/read status from `IDeliveryStateRepository`.
3. **Files Expected to Change**:
   - `src/messaging/service/message_sync_service.hpp` (New)
   - `src/messaging/service/message_sync_service.cpp` (New)
   - `src/messaging/CMakeLists.txt`
4. **Dependencies**:
   - `MSG-009-T01`, `MSG-009-T02`
   - `MSG-003` (`IConversationAuthorizationService`)
   - `MSG-004` (`IMessageRepository`)
   - `MSG-008` (`IDeliveryStateRepository`)
5. **Implementation Approach**:
   - `MessageSyncService::sync_messages(caller_user_id, device_id, conversation_id, since_sequence, limit)`:
     1. **Authorization**: Verify caller user is an active participant in `conversation_id`.
     2. **Bounds Enforcement**: Clamp requested `limit` to `[1, k_max_sync_batch_size]`.
     3. **Query Range**: Compute query range `[since_sequence + 1, since_sequence + limit]`. Query `IMessageRepository::list_messages_by_sequence_range`.
     4. **Delivery State Hydration**: For each retrieved message entity, fetch delivery and read statuses from `IDeliveryStateRepository::get_delivery_states_for_message` to populate `PerDeviceDeliveryTarget::state` and timestamps.
     5. **Envelope Assembly**: Map entity to Protobuf `MessageEnvelope` adhering strictly to Zero Plaintext (unaltered ciphertext bytes).
     6. **Pagination Metadata**: Determine `has_more` and `next_sequence`.
6. **Tests & Validation**:
   - Unit tests in `tests/unit/messaging/message_sync_service_test.cpp`:
     - Empty conversation returns empty list, `has_more = false`.
     - Initial sync returns sequential messages 1..N.
     - Incremental sync returns only messages after `since_sequence`.
     - Non-participant caller rejected with `MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT`.
     - Hydrated delivery states match ScyllaDB records (`DELIVERED`, `READ`).
7. **Security & Privacy Considerations**:
   - Zero Plaintext: No decryption, inspection, or plaintext logging.
   - Non-participants receive no messages or envelopes.
8. **Explicit Acceptance Criteria**:
   - Responses are strictly bounded.
   - Ordering is guaranteed by sequence number ASC.

---

### MSG-009-T04 — Gateway HTTP Proxy Message Sync Route Integration

1. **Ticket ID**: `MSG-009-T04`
2. **Objective**:
   - Expose RESTful synchronization and cursor endpoints on the API Gateway via `MessagingProxyHandler`.
   - Forward requests to downstream Messaging Service via `IMessagingClient` with full resilience (deadlines, circuit breaker, bulkhead).
3. **Files Expected to Change**:
   - `src/gateway/http/proxy/messaging_proxy_handler.hpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.cpp`
   - `tests/unit/gateway/messaging_proxy_sync_test.cpp` (New)
4. **Dependencies**:
   - `MSG-009-T01` (Protobuf definitions)
   - `GW-006` / `GW-008` / `GW-009` (Gateway Routing & Resilience)
5. **Implementation Approach**:
   - Add routes:
     - `GET /v1/conversations/{id}/messages?since_sequence=X&limit=Y` -> calls `GetMessages` / `SyncDeviceMessages`.
     - `GET /v1/devices/{device_id}/cursor?conversation_id={id}` -> calls `GetSyncCursor`.
     - `PUT /v1/devices/{device_id}/cursor` -> calls `UpdateSyncCursor`.
   - Enforce authentication context (`AuthenticatedContext::user_id()`, `device_id()`).
   - Propagate `x-correlation-id` and timeout deadlines.
6. **Tests & Validation**:
   - Unit tests verifying query parameter parsing, input clamping, error status code mapping (400, 401, 403, 404, 503).
   - Mock tests validating gRPC invocation forwarding.
7. **Security & Privacy Considerations**:
   - AuthenticatedContext must match the requesting device identity.
   - Token scopes must permit messaging read/sync.
8. **Explicit Acceptance Criteria**:
   - Gateway acts as pure reverse proxy; never interacts with ScyllaDB directly (ADR-005).

---

### MSG-009-T05 — MessagingService gRPC Sync RPCs & Threadpool Offloading

1. **Ticket ID**: `MSG-009-T05`
2. **Objective**:
   - Implement the authoritative gRPC endpoints in `MessagingServiceImpl`:
     - `SyncDeviceMessages`
     - `GetMessages`
     - `GetSyncCursor`
     - `UpdateSyncCursor`
   - Offload ScyllaDB queries and hydration to the bounded worker threadpool (`messaging_pool_`).
3. **Files Expected to Change**:
   - `src/messaging/service/messaging_service_impl.hpp`
   - `src/messaging/service/messaging_service_impl.cpp`
   - `tests/unit/messaging/messaging_service_impl_sync_test.cpp` (New)
4. **Dependencies**:
   - `MSG-009-T02`, `MSG-009-T03`
5. **Implementation Approach**:
   - Wire `MessageSyncService` and `SyncCursorManager` into `MessagingServiceImpl`.
   - In each RPC method:
     1. Extract and validate `caller_context` (`user_id`, `device_id`, `correlation_id`).
     2. Check mTLS peer authorization (`is_authorized_peer`).
     3. Check gRPC context cancellation and deadline.
     4. Dispatch asynchronous task to `messaging_pool_` with `std::promise` / `std::future`.
     5. Map domain `ServiceResult` to gRPC `Status` and protobuf response.
6. **Tests & Validation**:
   - Comprehensive unit test suite covering:
     - Successful `SyncDeviceMessages` and `GetMessages`.
     - Cursor fetch and update flows.
     - Cancellation handling (client disconnect during query).
     - Threadpool exhaustion / capacity exceeded behavior.
7. **Security & Privacy Considerations**:
   - mTLS SAN verification guarantees only Gateway or internal services can invoke RPCs.
8. **Explicit Acceptance Criteria**:
   - Zero `UNIMPLEMENTED` status codes remain for sync RPCs.
   - All tests pass with 100% assertions satisfied.

---

### MSG-009-T06 — Comprehensive Unit & Integration Test Suite

1. **Ticket ID**: `MSG-009-T06`
2. **Objective**:
   - Build an end-to-end multi-scenario integration test suite verifying synchronization across initial sync, incremental sync, reconnects, service restarts, concurrent message submission, and race conditions.
3. **Files Expected to Change**:
   - `tests/integration/messaging_online_sync_integration_test.cpp` (New)
   - `tests/integration/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`
4. **Dependencies**:
   - `MSG-009-T01` through `MSG-009-T05`
5. **Implementation Approach**:
   - Implement 12 distinct test scenarios in `messaging_online_sync_integration_test.cpp`:
     1. **Scenario 1: Clean Initial Sync**: Fresh device synchronizes from sequence 0; receives full bounded backlog.
     2. **Scenario 2: Incremental Progression**: Advancing cursor returns only delta messages.
     3. **Scenario 3: Multi-Batch Pagination**: Large backlog correctly paged with `has_more = true` and valid `next_sequence`.
     4. **Scenario 4: Interrupted Sync & Replay Safety**: Client crashes before cursor update; re-syncs identical batch without duplicates or data loss.
     5. **Scenario 5: Cursor Out of Bounds Rejection**: Requesting sequence ahead of ceiling rejected cleanly.
     6. **Scenario 6: Cursor Monotonicity**: Attempt to rewind cursor sequence is rejected.
     7. **Scenario 7: Authorization Isolation**: Non-member device receives permission denied; unauthorized conversation sync blocked.
     8. **Scenario 8: Concurrent Submission & Sync**: New messages submitted during an active sync batch are picked up in subsequent batch without omissions.
     9. **Scenario 9: Delivery and Read State Reflection**: Messages retrieved during sync reflect latest ACKed delivery and read states.
     10. **Scenario 10: Multi-Device Sync Independence**: Device A at sequence 100 and Device B at sequence 50 sync independently without interference.
     11. **Scenario 11: Service Restart & Durability**: Synchronization progress and cursors survive full simulated service restart.
     12. **Scenario 12: Zero Plaintext Invariant Verification**: All payload buffers inspected in transit confirm non-plaintext, high-entropy ciphertexts.
6. **Tests & Validation**:
   - Execute CTest preset `ci-macos` and verify 100% pass rate.
   - Run clang-format to ensure 0 violations.
7. **Security & Privacy Considerations**:
   - Validates that revoked devices cannot resume synchronization.
8. **Explicit Acceptance Criteria**:
   - 12/12 integration scenarios pass deterministically without race conditions or memory leaks.

---

## 4. Execution Sequence & Dependency Graph

```text
               MSG-009-T01 (Contracts & Types)
                     │
                     ▼
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
    MSG-009-T02             MSG-009-T03
(Cursor Manager)       (Message Sync Service)
         │                       │
         └───────────┬───────────┘
                     │
                     ▼
               MSG-009-T05
         (gRPC Service Integration)
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
    MSG-009-T04             MSG-009-T06
 (Gateway Proxy)        (Integration Test Suite)
```

---

## 5. Potential Conflicts & Architectural Decisions

1. **Cursor Granularity: Per-Device vs. Per-Device-Per-Conversation**:
   - *Resolution*: The approved ScyllaDB schema `sync_state_by_device` uses primary key `(device_id, conversation_id)`. We align protobuf contracts by including optional `conversation_id` in `SyncCursor`, allowing clients to synchronize per conversation (efficient, targeted) while supporting device-level queries.
2. **Delivery State vs. Sync State**:
   - *Resolution*: Synchronizing a message envelope down to a client device does **not** mark it `DELIVERED`. The client must separately issue `AcknowledgeDelivery` after local SQLite durability is confirmed.
3. **Message Ordering**:
   - *Resolution*: Strictly ordered by `MessageSequence ASC` per conversation. Global cross-conversation absolute ordering is not guaranteed or claimed (per ADR-007).
