# MSG-008 — Delivery State & Read Receipts
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-008  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 21, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-008** establishes the authoritative, durable **delivery-state and read-receipt lifecycle** for SecureCloud Messaging (`securecloud-messaging`), adhering strictly to **ADR-007** (Messaging Reliability & Durability), **ADR-008** (Security & Cryptographic Architecture), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance, Capacity & Optimization Strategy).

While **MSG-007** established the online delivery pipeline and basic recipient device delivery acknowledgements, **MSG-008 solidifies the complete state model, multi-device delivery independence, logical-recipient read semantics, monotonic state transitions, and concurrency guards** required by the client and downstream synchronization workstreams.

### 1.1 The Fundamental Semantic Invariant
The architecture strictly enforces the decoupling of four distinct state planes:
$$\text{Presence} \neq \text{Delivery} \neq \text{Read} \neq \text{Synchronization}$$

| State Dimension | Authoritative Source | Granularity | Meaning |
| :--- | :--- | :--- | :--- |
| **PresenceState** | `IDeviceConnectionRegistry` (In-Memory Lease) | Per-Device | Ephemeral transport connectivity / availability. A device being online does **not** mean a message has been delivered or read. |
| **DeliveryState** | `delivery_state_by_message` (ScyllaDB) | **Per-Device** | Durable network delivery lifecycle (`QUEUED` $\to$ `DELIVERING` $\to$ `DELIVERED`). `DELIVERED` means the recipient device durably accepted the ciphertext. |
| **ReadState** | `delivery_state_by_message` / Aggregated | **Logical Recipient (User)** | The message was presented/opened in the UI. Tracked per logical recipient user. Distinct from delivery. |
| **SyncState** | `sync_state_by_device` (ScyllaDB) | Per-Device Stream | Device synchronization watermark (`last_synced_sequence`). Synchronizing local storage does **not** imply the user has read the message. |
| **DeviceState** | `securecloud_auth.devices` (Auth Service) | Per-Device | Security status (`ACTIVE`, `REVOKED`). Revoked devices cannot generate valid delivery or read state. |

---

## 2. Core Architectural Invariants & State Lifecycles

### 2.1 Authoritative Delivery State Lifecycle (Device-Specific)
Delivery state is tracked **independently per recipient device**. The authoritative lifecycle follows the state machine:

```text
              ┌────────────────────────┐
              │         QUEUED         │
              └───────────┬────────────┘
                          │ Worker initiates dispatch
                          ▼
              ┌────────────────────────┐
              │       DELIVERING       │
              └─────┬────────────┬─────┘
                    │            │
   Affirmative ACK  │            │ Transient Network Error / Reset
   from recipient   │            ▼
   device           │   ┌────────────────────────┐
                    │   │       RETRY_WAIT       │
                    │   └───────────┬────────────┘
                    │               │ Backoff elapses; worker retries
                    │               ▼
                    │   ┌────────────────────────┐
                    └──►│       DELIVERED        │ (Terminal Success)
                        └────────────────────────┘

   TTL / Expiry Condition:
   QUEUED / DELIVERING / RETRY_WAIT ──(expires_at reached)──► EXPIRED (Terminal Failure)
```

#### Monotonicity Rules:
1. **No Regressions**: Transitions are strictly monotonic. Once a device's delivery state reaches `DELIVERED`, it **must never** regress to `QUEUED`, `DELIVERING`, or `RETRY_WAIT` (e.g., from late retry workers, out-of-order network packets, or stale background sweeps).
2. **Terminal Expiry**: Once `EXPIRED`, late delivery acknowledgements must be rejected with `v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED`.
3. **Idempotency**: Duplicate delivery acknowledgements for an already `DELIVERED` device return `OK` deterministically without updating the delivery timestamp or re-emitting outbox events.
4. **READ is NOT a Delivery State**: Read status is deliberately removed from the delivery-state progression. A message can be `DELIVERED` without being read, and device delivery tracking terminates at `DELIVERED`.

---

### 2.2 Logical-Recipient Read Receipt Semantics (User-Specific)
Read receipts are submitted by a specific recipient device on behalf of the user when the message is presented in the UI.

```text
Logical Recipient: User B (in Group Conversation with User A and User C)
   ├── Device B1: DELIVERED ──(User opens message)──► ReadReceipt(B1, T_read) ──► Recorded
   └── Device B2: QUEUED (Device offline)

Authoritative User Read State:
   - User B: READ (recorded at T_read, reported via Device B1)
   - User C: UNREAD
   - User A (Sender): Originator
```

#### Read Semantics Invariants:
1. **Logical Recipient Rule (MVP)**: A recipient user is considered to have read a message when **at least one active recipient device** of that user reports `READ`.
2. **Device-Level Audit Preservation**: The database preserves which device and timestamp reported the read (`read_at`, `reader_device_id`) for cryptographic accountability and audit.
3. **Group Conversations**: Read status is tracked **per logical recipient user**, never as a global conversation flag. In a group conversation with $N$ participants, the message status reflects which users have read it and which have not.
4. **Authentication & Authorization Guard**:
   - `caller_user_id == reader_user_id`: A user can only submit read receipts for themselves. Impersonation of other recipients is rejected with `v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT` or `PERMISSION_DENIED`.
   - Reader must be an active participant in the conversation.
   - Reader device must belong to `caller_user_id` and must **not** be in `DEVICE_STATUS_REVOKED`.
5. **Idempotency**: Duplicate read receipts for the same message from the same device (or other devices of the same user) succeed idempotently.
6. **Zero Plaintext Invariant (ADR-008)**: Read receipts contain no plaintext and require no decryption.

---

### 2.3 Concurrency & Race Condition Resolution Matrix

| Concurrency Scenario | Potential Hazard | Architectural Resolution |
| :--- | :--- | :--- |
| **Duplicate Delivery ACK** | Double outbox emission, duplicate timestamps | Idempotency guard: if device is already `DELIVERED`, return success with existing `delivered_at`, suppress outbox event. |
| **Late Retry vs. Delivery ACK Race** | Worker thread retries dispatching after client already ACKed to another node | Atomic conditional / timestamped update in repository; `DELIVERED` state rejects retry regressions (`RETRY_WAIT` / `QUEUED`). |
| **Concurrent ACKs for Multi-Device User** | Race on user-level read aggregation | Device delivery states are partitioned by `recipient_device_id`. Concurrent device updates are completely orthogonal and non-conflicting. |
| **Read Receipt Before Delivery ACK** | Out-of-order network packet arriving for read before delivery ACK | If a read receipt arrives, the device evidently possesses the message; system authoritatively transitions device to `DELIVERED` if pending, and commits `read_at`. |
| **Device Revoked During Delivery/Read** | Security bypass by compromised/revoked device | Token / session validation plus fail-closed device status check rejects ACKs or read receipts from revoked devices (`DEVICE_REVOKED`). |
| **Service Restart During Transition** | Lost in-memory state or half-committed update | ScyllaDB durable state is authoritative. On restart, scheduler sweeps `pending_deliveries_by_device`. Stale retry sweeps cannot overwrite durable `DELIVERED` in `delivery_state_by_message`. |

---

### 2.4 Deep Architectural Analysis: Group Chat Read Semantics & Multi-Device Scenarios

#### 2.4.1 Group Chat Read Semantics (No "Global Read")
**In SecureCloud, a message is never considered "globally read" when a single member reads it.** Read state is tracked strictly **per logical recipient user**, not as a single global flag on the message or conversation.

Consider a group conversation with **Alice (Sender)**, **Bob (Recipient)**, and **Charlie (Recipient)**:
```text
Message M1 sent by Alice
├── Bob:
│   ├── Device B1 ──(Bob opens message)──► SendReadReceipt ──► Bob: READ (T_bob)
│   └── Device B2
└── Charlie:
    └── Device C1 ───────────────────────────────────────────► Charlie: UNREAD
```
1. **Independent Per-User Read States**:
   - When Bob reads message $M_1$ on his phone, **only Bob's logical state transitions to `READ`**.
   - Charlie's state remains **`UNREAD`**.
2. **Sender & Group Visibility**:
   - When Alice (or any group participant) queries the delivery/read status of $M_1$, the API returns a per-recipient breakdown:
     - `read_by: [{ user_id: "Bob", read_at: T_bob }]`
     - `unread_by: ["Charlie"]`
     - Summary count: `1 of 2 read`.
3. **Recipient Client UI Semantics**:
   - In Charlie’s client, $M_1$ remains visibly marked as **unread** with an unread badge, because Charlie has not personally opened it.
   - In Bob’s client, $M_1$ is marked as read.
   - In Alice’s client, the double checkmark / receipt indicator shows partial read status (e.g., "Read by Bob, delivered to Charlie").

#### 2.4.2 Multi-Device User Scenarios (Read on Phone, Not Yet Delivered to Laptop)
This exact scenario illustrates why SecureCloud strictly enforces:
$$\text{Delivery (Per-Device)} \neq \text{Read (Per-User)}$$

Consider **Bob** with two devices: **Phone ($B_1$)** (Online) and **Laptop ($B_2$)** (Offline / in bag):
```text
Message M1
├── Device B1 (Phone):  DELIVERED ──(Bob opens)──► ReadState: READ
└── Device B2 (Laptop): QUEUED (Undelivered, offline in pending_deliveries_by_device)

Authoritative System State:
- Logical User State:  User Bob is READ
- Device B1 Delivery:  DELIVERED
- Device B2 Delivery:  QUEUED (obligation preserved)
```
1. **Device-Level Delivery Independence**:
   - **Phone ($B_1$)**: Successfully delivered and acknowledged $\to$ `DELIVERED`.
   - **Laptop ($B_2$)**: Offline $\to$ Remains `QUEUED` in `pending_deliveries_by_device`. 
   - **Invariant**: The server’s delivery obligation to Laptop $B_2$ is **not canceled or abandoned**. Laptop $B_2$ still needs its own cryptographic envelope (encrypted for $B_2$'s prekey/identity key) so that $B_2$'s local storage contains the full conversation history.
2. **User-Level Read State (Logical Recipient Rule)**:
   - Because Bob opened the message on Phone $B_1$, $B_1$ submits `SendReadReceipt`.
   - Per ADR-007 / 03-messaging-data-model: *"A recipient user is considered to have read a message when at least one active recipient device reports READ."*
   - Therefore, **User Bob is authoritatively marked as `READ`**.
   - Senders and group members see that **Bob has read the message**, even though his laptop has not yet received its ciphertext.
3. **What Happens When Laptop ($B_2$) Later Connects / Synchronizes?**:
   - When Laptop $B_2$ boots up, it pulls its pending envelope from `pending_deliveries_by_device` (or via incremental sync stream).
   - $B_2$ decrypts and stores the message locally, and sends `AcknowledgeDelivery`.
   - $B_2$'s delivery state transitions `QUEUED -> DELIVERING -> DELIVERED`.
   - Crucially:
     - $B_2$'s late delivery **does not overwrite** Bob's already-committed `READ` status.
     - Laptop $B_2$ receives the read receipt watermark from the server, so Laptop $B_2$'s local UI knows Bob already read this message on his phone—preventing a false "new unread message" badge when opening the laptop.
4. **Monotonicity Guard**:
   - If a background delivery retry worker for Laptop $B_2$ runs while Bob is reading on Phone $B_1$, the retry worker only touches $B_2$'s record. It can **never** regress Phone $B_1$ or Bob's user-level `READ` state.

---

## 3. Detailed Implementation Tickets

```text
┌────────────────────────────────────────────────────────────────────────────────┐
│                       MSG-008 TICKET DEPENDENCY GRAPH                          │
└────────────────────────────────────────────────────────────────────────────────┘
                                        
   [MSG-008-T01] Domain Models, State Transition Engine & Regression Guard
         │
         ├──► [MSG-008-T02] Read Receipt Domain Service & Group Read Semantics
         │         │
         └──► [MSG-008-T03] ScyllaDB Repository Extensions & Concurrent Updates
                   │
                   ▼
         [MSG-008-T04] gRPC MessagingService RPCs & Status Query APIs
                   │
                   ▼
         [MSG-008-T05] Gateway REST Routes, Reverse Proxy & Bulkhead Resilience
                   │
                   ▼
         [MSG-008-T06] Concurrency, Monotonicity & Multi-Device Test Suite & Report
```

---

### MSG-008-T01: Delivery & Read Domain Models, State Transition Engine & Regression Guard

1. **Objective**: Define domain value types and an immutable state transition engine (`DeliveryStateTransitionGuard`) that enforces monotonic delivery state lifecycles and rejects invalid state regressions.
2. **Scope**:
   - Update `domain::DeliveryState` and decouple `ReadState` into a distinct domain type:
     - `DeliveryState`: `Queued`, `Delivering`, `Delivered`, `RetryWait`, `Expired`.
     - `ReadState`: `Unread`, `Read`.
   - Implement `DeliveryStateTransitionGuard`:
     - Method `can_transition(DeliveryState from, DeliveryState to) -> bool`.
     - Method `validate_transition(DeliveryState current, DeliveryState next) -> Result<void, DomainError>`.
     - Enforce valid edges:
       - `QUEUED -> DELIVERING | EXPIRED`
       - `DELIVERING -> DELIVERED | RETRY_WAIT | EXPIRED`
       - `RETRY_WAIT -> DELIVERING | EXPIRED`
       - `DELIVERED -> (none)` (terminal)
       - `EXPIRED -> (none)` (terminal)
     - Disallow regressions: `DELIVERED -> QUEUED`, `DELIVERED -> RETRY_WAIT`, `EXPIRED -> DELIVERING`.
   - Implement `LogicalRecipientReadStatus`:
     - Struct holding `user_id`, `read_state` (`Unread` | `Read`), `optional<time_point> read_at`, `optional<DeviceId> reader_device_id`.
   - Update `src/messaging/service/delivery_lifecycle.hpp|cpp` to reflect the decoupled `DeliveryState` vs `ReadState` contracts.
3. **Interfaces to Create / Modify**:
   - `src/messaging/domain/delivery_types.hpp`
   - `src/messaging/domain/read_receipt_types.hpp` (New)
   - `src/messaging/service/delivery_state_transition_guard.hpp|cpp` (New)
   - `src/messaging/service/delivery_lifecycle.hpp|cpp`
4. **Test Criteria**:
   - Unit tests in `tests/unit/messaging/delivery_state_transition_guard_test.cpp`:
     - Validate every valid forward transition.
     - Validate rejection of every regressive transition (`DELIVERED -> QUEUED`, `DELIVERED -> RETRY_WAIT`, `EXPIRED -> DELIVERED`).
     - Validate idempotency checks (`DELIVERED -> DELIVERED`).

---

### MSG-008-T02: Read Receipt Domain Service & Logical-Recipient Group Semantics

1. **Objective**: Implement the authoritative `ReadReceiptService` that processes read receipts, authorizes callers, aggregates logical-recipient read states for 1:1 and group conversations, and publishes transactional outbox events.
2. **Scope**:
   - Create `ReadReceiptService`:
     - Method `record_read_receipt(const ReadReceiptCommand& cmd) -> ServiceResult<ReadReceiptResponse>`:
       1. Validate caller owns the reporting device (`caller_user_id == target_device_user_id`).
       2. Validate reporting device is not revoked (`DEVICE_STATUS_ACTIVE`).
       3. Validate caller is an active participant in the conversation.
       4. Fetch existing delivery/read states for `cmd.message_id`.
       5. Verify message exists and was dispatched to this user.
       6. Check idempotency: if already read by this device, return OK with original timestamp.
       7. Update durable read state in ScyllaDB via `IDeliveryStateRepository`.
       8. Emit `ConversationOutboxEventType::MessageRead` via `IOutboxRepository`.
     - Method `get_message_read_status(const MessageId& message_id, const UserId& caller_user_id) -> ServiceResult<MessageReadStatusResponse>`:
       1. Validate caller is a participant of the conversation.
       2. Aggregate per-recipient read states across all logical participants.
       3. Return per-user read breakdown (`user_id`, `is_read`, `read_at`).
   - Add `ConversationOutboxEventType::MessageRead` to `src/messaging/domain/outbox_event.hpp`.
   - Outbox payload includes: `message_id`, `conversation_id`, `reader_user_id`, `reader_device_id`, `read_at_unix_ms`.
3. **Interfaces to Create / Modify**:
   - `src/messaging/domain/outbox_event.hpp`
   - `src/messaging/service/read_receipt_service.hpp|cpp` (New)
   - `src/messaging/service/read_receipt_commands.hpp` (New)
4. **Test Criteria**:
   - Unit tests in `tests/unit/messaging/read_receipt_service_test.cpp`:
     - Authorized user successfully submits read receipt.
     - Unauthorized caller attempting to mark read for another user is rejected with `NOT_A_PARTICIPANT`.
     - Non-participant in conversation is rejected.
     - Revoked device submitting read receipt is rejected with `DEVICE_REVOKED`.
     - Duplicate read receipt succeeds idempotently without duplicate outbox event.
     - Group conversation aggregates read status per logical recipient correctly.

---

### MSG-008-T03: ScyllaDB Repository Extensions & Concurrent Monotonic Updates

1. **Objective**: Extend `IDeliveryStateRepository` and `ScyllaDeliveryStateRepository` to support atomic, monotonic delivery-state updates and logical-recipient read-status queries.
2. **Scope**:
   - Extend `IDeliveryStateRepository` interface:
     - `record_read_receipt(const MessageId& message_id, const DeviceId& reader_device_id, const UserId& reader_user_id, const time_point& read_at) -> void`.
     - `get_delivery_and_read_states_for_message(const MessageId& message_id) -> std::vector<domain::RecipientDeliveryState>`.
     - `get_message_delivery_summary(const MessageId& message_id) -> domain::MessageDeliverySummary`.
     - `update_delivery_state_monotonic(const MessageId& message_id, const DeviceId& device_id, DeliveryState new_state, const time_point& updated_at) -> bool`:
       - Employs state-guarded write preventing regressions (e.g. will not overwrite `DELIVERED` with `RETRY_WAIT` or `QUEUED`).
   - Implement repository enhancements in `ScyllaDeliveryStateRepository`:
     - Prepared statement for setting `read_at` on `delivery_state_by_message`.
     - Querying all delivery and read records for a given `message_id`.
     - Unit/mock tests ensuring thread safety and idempotency.
3. **Interfaces to Create / Modify**:
   - `src/messaging/repository/delivery_state_repository_interface.hpp`
   - `src/messaging/repository/scylla_delivery_state_repository.hpp|cpp`
4. **Test Criteria**:
   - Unit tests in `tests/unit/messaging/scylla_delivery_state_repository_test.cpp`:
     - Monotonic guard rejects regressive state writes.
     - Concurrent delivery ACK and retry write leaves state in `DELIVERED`.
     - Read receipt recording updates `read_at` timestamp.
     - Querying message delivery summary correctly groups per-device and per-user states.

---

### MSG-008-T04: gRPC MessagingService RPCs & Status Query APIs

1. **Objective**: Wire `SendReadReceipt` and status query RPCs in `MessagingServiceImpl`, mapping domain models, handling errors, and validating security context.
2. **Scope**:
   - Review and update protobuf definitions in `proto/securecloud/messaging/v1/messaging.proto`:
     - Ensure `SendReadReceiptRequest` and `SendReadReceiptResponse` conform to requirements.
     - Add `GetMessageDeliveryStatusRequest` and `GetMessageDeliveryStatusResponse`:
       - Request: `message_id`, `conversation_id`.
       - Response: `message_id`, `delivery_summary` (total targets, delivered count, pending count, expired count), `repeated DeviceDeliveryStatus device_statuses`, `repeated LogicalRecipientReadStatus recipient_read_statuses`.
     - Define `LogicalRecipientReadStatus`: `string user_id = 1; bool is_read = 2; int64 read_at_unix_ms = 3;`.
   - Implement `MessagingServiceImpl::SendReadReceipt`:
     - Extract `caller_user_id` and `device_id` from metadata headers.
     - Delegate to `ReadReceiptService::record_read_receipt`.
     - Return `SendReadReceiptResponse` with monotonic state and recording timestamp.
   - Implement `MessagingServiceImpl::GetMessageDeliveryStatus`:
     - Extract `caller_user_id`.
     - Delegate to `ReadReceiptService` / `DeliveryService` to assemble delivery status and read breakdown.
     - Return `GetMessageDeliveryStatusResponse`.
   - Update error mapper (`messaging_error_mapper.cpp`) for all MSG-008 status codes.
3. **Interfaces to Create / Modify**:
   - `proto/securecloud/messaging/v1/messaging.proto`
   - `src/messaging/service/messaging_service_impl.hpp|cpp`
   - `src/messaging/service/messaging_error_mapper.hpp|cpp`
4. **Test Criteria**:
   - Unit tests in `tests/unit/messaging/messaging_service_impl_delivery_state_test.cpp`:
     - End-to-end gRPC RPC execution of `SendReadReceipt`.
     - End-to-end gRPC RPC execution of `GetMessageDeliveryStatus`.
     - Error mapping: invalid message ID, non-participant, expired message, revoked device.

---

### MSG-008-T05: Gateway REST Routes, Reverse Proxy & Bulkhead Resilience

1. **Objective**: Expose read receipts and delivery status inspection on the Gateway HTTP reverse proxy adhering to ADR-005 (Zero Database) and ADR-010 (Bulkhead Isolation & Circuit Breaker).
2. **Scope**:
   - Update `IMessagingClient` and `MessagingServiceClient` in `src/gateway/grpc`:
     - Add `get_message_delivery_status(const GetMessageDeliveryStatusRequest& req, ClientCallContext& ctx) -> Result<GetMessageDeliveryStatusResponse>`.
   - Update `MessagingProxyHandler`:
     - Add `handle_send_read_receipt`:
       - Route: `POST /v1/conversations/:conversation_id/messages/:message_id/read`
       - Parse request payload: `read_at_unix_ms` (optional, defaults to server now).
       - Inject caller context: JWT `user_id` and `device_id`, request ID, correlation ID.
       - Execute via `bulkhead_manager_->acquire("messaging_read_receipt")`.
       - Handle response: HTTP 200 with `{ "message_id": "...", "state": "READ", "recorded_at_unix_ms": 123456789 }`.
     - Add `handle_get_delivery_status`:
       - Route: `GET /v1/conversations/:conversation_id/messages/:message_id/delivery-status`
       - Forward to gRPC `GetMessageDeliveryStatus`.
       - Return HTTP 200 with delivery counts, per-device statuses, and per-user read breakdown.
     - Register routes in `MessagingProxyHandler::register_routes(Router& router)`.
3. **Interfaces to Create / Modify**:
   - `src/gateway/grpc/messaging_client_interface.hpp`
   - `src/gateway/grpc/messaging_service_client.hpp|cpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.hpp|cpp`
4. **Test Criteria**:
   - Unit tests in `tests/unit/gateway/messaging_proxy_handler_test.cpp`:
     - REST route dispatching and parameter extraction.
     - Unauthorized/missing JWT header returns HTTP 401.
     - Non-participant returns HTTP 403.
     - Bulkhead saturation returns HTTP 429.
     - Circuit breaker open returns HTTP 503.

---

### MSG-008-T06: Concurrency, Monotonicity & Multi-Device Test Suite & Card Validation Report

1. **Objective**: Author a rigorous integration test suite validating all 13 core scenarios and compile the comprehensive Card Validation Report.
2. **Scope**:
   - Integration test suite `tests/integration/messaging_delivery_state_read_receipts_integration_test.cpp`:
     1. **Normal Delivery Transition**: `QUEUED -> DELIVERING -> DELIVERED` verified.
     2. **Invalid Transition Rejection**: Direct jumps (`QUEUED -> DELIVERED`) and regressions (`DELIVERED -> QUEUED`, `DELIVERED -> RETRY_WAIT`) rejected.
     3. **Duplicate Delivery ACK**: Multiple identical ACKs return OK and preserve initial `delivered_at`.
     4. **Concurrent Delivery ACKs**: Multiple worker threads acknowledging different devices concurrently run cleanly without race conditions.
     5. **Retry vs ACK Race**: Delivery ACK arriving while retry worker is running guarantees authoritative state remains `DELIVERED`; late retry write is rejected.
     6. **Message Expiry**: Expiry window elapses; delivery transitions to `EXPIRED`; subsequent ACK attempts are rejected with `MESSAGE_EXPIRED`.
     7. **Duplicate Read Receipt**: Duplicate read receipts from same device return OK idempotently without duplicate outbox events.
     8. **Unauthorized Read Receipt**: User B attempting to mark message read on behalf of User C is rejected (`NOT_A_PARTICIPANT`).
     9. **Group Read State**: In a 3-user group (A, B, C), User B reading results in User B marked read, User C remaining unread; user-facing state is not globally read.
     10. **Multi-Device Delivery Independence**: User B with devices B1, B2, B3: B1 is `DELIVERED`, B2 is `QUEUED`, B3 is `REVOKED`. B1 reading marks User B as read while B2 remains queued.
     11. **Device Revocation Race**: Revoked device attempting delivery ACK or read receipt is rejected with `DEVICE_REVOKED`.
     12. **Service Restart & Recovery**: In-memory state lost; ScyllaDB durable state rehydrates correctly without state loss or regression.
     13. **Semantic Distinction (Non-Conflation)**: Assert that presence connection/disconnection does not alter delivery or read state, and synchronization cursor updates do not alter read state.
   - Generate full Card Validation Report artifact (`walkthrough-msg-008.md`).
3. **Interfaces to Create / Modify**:
   - `tests/integration/messaging_delivery_state_read_receipts_integration_test.cpp` (New)
   - `tests/integration/CMakeLists.txt`
   - `docs/walkthrough-msg-008.md`
4. **Test Criteria**:
   - 100% of integration test scenarios pass.
   - Zero memory leaks, race conditions, or regressions in existing suite.

---

## 4. Ticket Summary & Execution Order

| Ticket ID | Title | Primary Focus | Dependencies | Est. Complexity |
| :--- | :--- | :--- | :--- | :--- |
| **MSG-008-T01** | Delivery & Read Domain Models, State Transition Engine & Regression Guard | Domain state machine, monotonic transition guard, `ReadState` decoupling | MSG-007 | Medium |
| **MSG-008-T02** | Read Receipt Domain Service & Logical-Recipient Group Semantics | Read receipt processing, caller authorization, group read aggregation, transactional outbox | MSG-008-T01 | Medium-High |
| **MSG-008-T03** | ScyllaDB Repository Extensions & Concurrent Monotonic Updates | ScyllaDB queries, monotonic update statements, delivery/read queries | MSG-008-T01, T02 | Medium |
| **MSG-008-T04** | gRPC MessagingService RPCs & Status Query APIs | `SendReadReceipt`, `GetMessageDeliveryStatus` gRPC RPCs, error mapping | MSG-008-T02, T03 | Medium |
| **MSG-008-T05** | Gateway REST Routes, Reverse Proxy & Bulkhead Resilience | REST endpoints, JWT context injection, Bulkhead & Circuit Breaker | MSG-008-T04 | Medium |
| **MSG-008-T06** | Concurrency, Monotonicity & Multi-Device Test Suite & Report | 13 integration test scenarios, regression verification, card validation report | MSG-008-T01 - T05 | High |

---

## 5. Architectural Quality Gate Checklist

- [ ] **Decoupled State Planes**: No coupling between `Presence`, `Delivery`, `Read`, and `Synchronization`.
- [ ] **Monotonicity Enforced**: Invalid state regressions (`DELIVERED -> QUEUED`, `DELIVERED -> RETRY_WAIT`, `EXPIRED -> DELIVERING`) are strictly rejected.
- [ ] **Multi-Device Independence**: Delivery is tracked independently per device (`Device A1 != Device A2`).
- [ ] **Logical-Recipient Read**: User read status requires $\ge 1$ active device read; group conversations report per-recipient read states.
- [ ] **Security & Authorization**: Caller cannot acknowledge or read for other users; revoked devices cannot modify state.
- [ ] **Dual-Write Safety**: Outbox events (`MessageDelivered`, `MessageRead`) emitted without synchronous audit blocking.
- [ ] **Zero Database on Gateway**: Gateway acts strictly as a stateless, resilient reverse proxy (ADR-005, ADR-010).
- [ ] **Zero Plaintext Invariant**: No plaintext exposed or decrypted in delivery ACKs or read receipts (ADR-008).
