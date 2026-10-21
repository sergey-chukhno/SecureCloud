# feat(messaging): Implement Delivery State & Read Receipts Pipeline (Card MSG-008)

## 1. Overview & Strategic Objective

This PR implements the production-grade **Delivery State & Read Receipts** subsystem for Milestone M3 (Card **MSG-008**).

Building upon the real-time online message dispatch pipeline (MSG-007), Card MSG-008 manages the distributed state lifecycle once an end-to-end encrypted envelope is pushed over network channels. It enforces the foundational non-conflation axiom separating ephemeral socket presence, per-device delivery confirmations, per-user conversation read receipts, and device synchronization cursors:

$$\mathbf{Presence} \neq \mathbf{Delivery\ (Per\text{-}Device)} \neq \mathbf{Read\ (Per\text{-}User)} \neq \mathbf{Synchronization}$$

All 6 engineering tickets (**MSG-008-T01** through **MSG-008-T06**) are complete, strictly formatted with `.clang-format`, and verified with a **100% test pass rate** across all 13 integration scenarios and all 1,747 tests in the platform test suite.

---

## 2. Ticket-by-Ticket Summary of Changes

### MSG-008-T01: Protobuf v1 Contracts & Monotonic State Transition Guard
- **Protobuf v1 Schemas**: Defined authoritative `DeliveryState` enum (`QUEUED`, `DELIVERING`, `DELIVERED`, `READ`, `EXPIRED`, `DEAD_LETTER`) and RPCs: `AcknowledgeDelivery`, `SendReadReceipt`, and `GetMessageDeliveryStatus`.
- **Domain Transition Machine**: Implemented `DeliveryStateTransitionGuard` enforcing forward-monotonic progression on the poset $(\mathcal{S}, \le)$.
- **Anti-Regression Invariant**: Prohibits backward state rollbacks (e.g., `DELIVERED` $\to$ `DELIVERING`) and classifies self-transitions as idempotent no-ops.
- **Verification**: 36 unit test permutations in `delivery_state_transition_guard_test.cpp`.

### MSG-008-T02: ScyllaDB Partitioned Persistence Layer & Repository Ports
- **Repository Ports**: Defined pure abstract interfaces `IMessageDeliveryStateRepository` and `IConversationReadStateRepository`.
- **ScyllaDB Tables**:
  - `message_delivery_state`: Partitioned by `((message_id), recipient_device_id)` with Time-Window Compaction Strategy (TWCS).
  - `conversation_read_state`: Partitioned by `((conversation_id), user_id)` with Size-Tiered Compaction Strategy (STCS).
- **CQL Migration Script**: Created migration `src/messaging/migrations/005_delivery_state_and_read_receipts.cql`.
- **Verification**: Atomic CAS update tests and partition key alignment unit tests.

### MSG-008-T03: Delivery State Update Service & Atomic ACK Processing
- **Domain Service**: Implemented `DeliveryStateService::acknowledge_delivery()`:
  - Validates recipient device registration against device directory.
  - Enforces `DeliveryStateTransitionGuard` before executing database writes.
  - Returns structured domain error code `MESSAGING_ERROR_CODE_INVALID_STATE_TRANSITION` on regression attempts.
- **Verification**: Unit tests covering happy path, duplicate ACK idempotency, and out-of-order race conditions.

### MSG-008-T04: Read Receipt Service, Authorization & Cursor Invariants
- **Domain Service**: Implemented `ReadReceiptService::record_read_receipt()`:
  - Enforces conversation membership authorization via `IConversationMemberRepository`.
  - Enforces fail-closed device revocation checks via active device registry.
  - Rejects read receipts on expired messages (`MESSAGING_ERROR_CODE_MESSAGE_EXPIRED`).
  - Advances conversation watermark monotonically: $\text{watermark}_{\text{new}} = \max(\text{watermark}_{\text{current}}, \text{seq}_{\text{msg}})$.
  - Cascades read status to all recipient device delivery records for that user.
- **Verification**: 9 unit test suites covering membership checks, device revocation, watermark progression, and dual-write outbox event emission.

### MSG-008-T05: In-Process gRPC MessagingService Endpoints & Gateway REST Reverse Proxy
- **In-Process gRPC Handlers**: Wired `AcknowledgeDelivery`, `SendReadReceipt`, and `GetMessageDeliveryStatus` in `MessagingServiceImpl` to worker thread pools.
- **Gateway Reverse Proxy Routes**:
  - `POST /api/v1/messages/:id/delivery-ack` $\to$ `AcknowledgeDelivery`
  - `POST /api/v1/conversations/:id/messages/:id/read` $\to$ `SendReadReceipt`
  - `GET /api/v1/messages/:id/delivery-status` $\to$ `GetMessageDeliveryStatus`
- **Error Mapping & RFC-7807**: Integrated perimeter JWT claims extraction and mapped downstream gRPC errors into RFC-7807 Problem Details HTTP envelopes.
- **Verification**: In-process gRPC tests and Gateway HTTP routing tests with mock downstream channels.

### MSG-008-T06: Concurrency, Monotonicity & Multi-Device Integration Test Suite & Card Validation Report
- **13-Scenario Integration Test Suite**: Implemented in `tests/integration/messaging_delivery_state_read_receipts_integration_test.cpp`:
  1. *Scenario 1*: Normal Delivery Transition Sequence (`QUEUED` $\to$ `DELIVERING` $\to$ `DELIVERED` $\to$ `READ`)
  2. *Scenario 2*: Invalid Transition & Regression Rejection
  3. *Scenario 3*: Duplicate Delivery ACK Idempotency
  4. *Scenario 4*: Concurrent Delivery ACKs Race Condition Under Multi-Threading (10 concurrent threads)
  5. *Scenario 5*: Retry Worker vs. Client ACK Race Condition
  6. *Scenario 6*: Message Expiry Semantics & Terminal State Enforcement
  7. *Scenario 7*: Duplicate Read Receipt Idempotency & Monotonic Cursor Advancement
  8. *Scenario 8*: Unauthorized Read Receipt Rejection (Perimeter 401 & Membership 403)
  9. *Scenario 9*: Group Conversation Read State Decoupling
  10. *Scenario 10*: Multi-Device Independent Delivery States (Phone vs. Tablet vs. Laptop)
  11. *Scenario 11*: Device Revocation Race Condition
  12. *Scenario 12*: Service Restart, Recovery & Re-Hydration Across Simulated Reboot
  13. *Scenario 13*: Semantic Non-Conflation Invariant Verification ($\text{Presence} \neq \text{Delivery} \neq \text{Read} \neq \text{Sync}$)
- **Comprehensive Card Validation Report**: Authored 1,184-line architectural report in `walkthrough-msg-008.md`.

---

## 3. Key Architectural Proofs

### A. The Non-Conflation Axiom
$$\mathbf{Presence} \neq \mathbf{Delivery\ (Per\text{-}Device)} \neq \mathbf{Read\ (Per\text{-}User)} \neq \mathbf{Synchronization}$$
- **Presence**: TCP/WebSocket connection in Gateway.
- **Delivery**: Confirmed receipt of opaque ciphertext on specific physical device hardware.
- **Read**: Human user viewed the conversation; recorded as monotonic cursor per conversation.
- **Sync**: High-watermark sequence number pulled into local offline database.

### B. Anti-Regression & Terminal Absorption Guarantees
- The transition guard operates on the strict partial order of states $(\mathcal{S}, \le)$.
- By theorem of antisymmetry, $\forall s_1, s_2 \in \mathcal{S}$ with $s_1 \prec^* s_2$ and $s_1 \neq s_2$, $\text{can\_transition}(s_2, s_1) = \text{false}$. Late retry workers or out-of-order packets can never overwrite client ACKs.
- States `READ`, `EXPIRED`, and `DEAD_LETTER` are terminal absorbing states with out-degree zero.

### C. Zero Plaintext Invariance (ADR-008)
- Delivery ACKs operate strictly upon `(message_id, recipient_device_id)`.
- Read receipts operate strictly upon `(conversation_id, user_id, message_id, sequence_number)`.
- Zero plaintext payloads, encryption keys, or decrypted contents exist in the data models, gRPC messages, or database tables.

---

## 4. Verification Matrix & Quality Gates

| Verification Dimension | Metric / Standard | Result | Status |
|:---|:---|:---|:---:|
| **Platform CTest Suite** | 1,799 Registered Tests | 1,747 Passed / 0 Failed (52 skipped for external DBs) | **100% PASSED** |
| **MSG-008 Integration Suite** | 13 Scenarios (`securecloud_messaging_delivery_state_read_receipts_integration_test`) | 13 Passed / 0 Failed | **100% PASSED** |
| **Code Formatting** | `.clang-format` compliance | 534/534 C++ files compliant | **100% COMPLIANT** |
| **Card Validation Report** | Platform Standard $\ge 1000$ lines | `walkthrough-msg-008.md` (1,184 lines) | **PASSED** |
| **Architecture Compliance** | ADR-001, ADR-002, ADR-005, ADR-008, ADR-010 | Zero Plaintext, Hexagonal Ports, mTLS, Monotonic Guard | **COMPLIANT** |
