# MSG-005 — Message Submission & Idempotency
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-005  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 15, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-005** implements the authoritative, durable **Message Submission and Idempotency** pipeline for the SecureCloud Messaging Service (`securecloud-messaging`), adhering strictly to **ADR-005** (Service Isolation), **ADR-007** (Message Reliability & Durability), **ADR-008** (Security & Cryptographic Architecture), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance, Capacity & Optimization Strategy).

While **MSG-003** established conversation and participant membership authority and **MSG-004** delivered the partitioned ScyllaDB persistence tier (all 11 authoritative tables, session pooling, and repository adapters), **MSG-005 establishes the mission-critical write path for message ingestion**:
- Accepting authenticated message submission requests via gRPC (`SendMessage`) and HTTP Gateway proxy (`POST /api/v1/messages`).
- Verifying sender authorization and conversation membership state.
- Enforcing strict client-driven idempotency with payload fingerprinting to differentiate identical network retries from conflicting key reuse.
- Allocating monotonically increasing per-conversation sequence numbers within monthly UTC partitions (`YYYYMM`).
- Enforcing the **Critical Durability Boundary**: atomically persisting the message envelope, per-device active delivery records, message delivery tracking status, and the transactional outbox event before returning success to the caller.
- Guaranteeing that asynchronous delivery itself remains strictly decoupled (delegated to `MSG-007`).

---

## 2. Core Architectural Invariants & Durability Rules

### 2.1 The Critical Durability Rule
> **Invariant**: The service must NEVER report successful message acceptance to the caller before the required durable state has been committed to ScyllaDB.

The authoritative acceptance boundary requires that the following four persistence items succeed:
1. **Message Envelope**: Durably stored in `messages_by_conversation` under `((conversation_id, message_bucket), sequence, message_id)`.
2. **Initial Recipient Delivery State**: Durably stored in `pending_deliveries_by_device` under `((device_id, delivery_bucket), accepted_at, message_id)` and `delivery_state_by_message` under `((message_id), recipient_device_id)`.
3. **Transactional Outbox Event**: Durably written to `messaging_outbox_events` with status `PENDING` to trigger asynchronous notification and fan-out.
4. **Idempotency Record**: Durably marked `COMMITTED` in `message_submission_by_idempotency_key` with the allocated `message_id` and sequence number.

Only after this boundary is committed does the service return `SendMessageResponse` with `accepted_at` and `initial_state = PENDING`.

### 2.2 Idempotency Semantics & Fingerprint Matching
Clients operating over unreliable mobile connections (4G/5G/Wi-Fi transitions) frequently retry message submissions after transport timeouts. The system strictly distinguishes two cases:

1. **Same Request Repeated (Identical Retry)**:
   - Evaluated by matching `(sender_device_id, client_idempotency_token)` and comparing the cryptographic request fingerprint (SHA-256 over conversation ID, priority, and sorted recipient delivery target ciphertexts).
   - Returns the original `SendMessageResponse` associated with the previously accepted submission.
   - **Zero Secondary Writes**: Must NOT create another message, duplicate delivery states, or duplicate outbox events.
2. **Conflicting Reuse of Idempotency Token**:
   - If `(sender_device_id, client_idempotency_token)` matches an existing record but the request fingerprint differs (different conversation, different recipient targets, or modified payload).
   - Must be **rejected deterministically** with `MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT` (mapped to HTTP 409 / gRPC `ALREADY_EXISTS`).
   - Must NOT mutate the original message or treat the request as a new submission.

### 2.3 Logical Participants vs. Physical Device Targets
- Conversations and authorization are established at the logical `UserId` level (`ConversationAuthorizationService::can_send_message`).
- Delivery is fundamentally per physical `DeviceId` (`PerDeviceDeliveryTarget`).
- A submission must specify delivery targets for active, authorized recipient devices. Revoked or unauthorized devices must never receive delivery records.

### 2.4 Zero Plaintext & Cryptographic Opacity (ADR-008)
- The server stores only opaque `EncryptedPayload` ciphertexts (`ciphertext_blob`, `ephemeral_public_key`, `iv`, `auth_tag`, `algorithm`).
- The backend never possesses message decryption keys, never parses plaintext, and uses no custom cryptography.

### 2.5 Asynchronous Audit & No Cross-Service Transactions
- Audit events are emitted asynchronously via the outbox/worker pipelines; there is **no synchronous dependency on the Audit service** for message acceptance.
- No distributed transactions or two-phase commits across services.

---

## 3. Dependency Graph & Ticket Decomposition

```text
               MSG-001 (Service Foundation & Tri-Pool Concurrency)
               MSG-002 (API Contracts, Caller Context & Error Mappers)
               MSG-003 (Conversation Domain & Authorization Services)
               MSG-004 (ScyllaDB Repositories & Partitioned Tables)
                                     │
                                     ▼
                                MSG-005-T01
            (Submission Domain Model, Envelope Validation & Fingerprinting)
                                     │
                                     ▼
                                MSG-005-T02
            (Per-Conversation Sequence Allocation & Time-Bucketing Engine)
                                     │
                                     ▼
                                MSG-005-T03
            (Idempotency Enforcement & Conflict Resolution Engine)
                                     │
                                     ▼
                                MSG-005-T04
            (Durable Atomic Submission Orchestrator & Outbox Persistence)
                                     │
                                     ▼
                                MSG-005-T05
            (gRPC SendMessage Handler, Concurrency Pools & Gateway Proxy)
                                     │
                                     ▼
                                MSG-005-T06
            (End-to-End Submission & Idempotency Integration Suite)
```

---

## 4. Detailed Implementation Tickets

### MSG-005-T01 — Submission Domain Model, Envelope Validation & Fingerprinting

1. **Ticket ID**: `MSG-005-T01`
2. **Title**: Message Submission Domain Command, Validation Rules & Payload Fingerprinting
3. **Objective**: Define strongly-typed submission domain models, request validators, and deterministic SHA-256 request payload fingerprinting for idempotency conflict detection.
4. **Architectural Purpose**: Establishes strict validation boundaries preventing malformed or unencrypted envelopes from reaching persistence, and creates the cryptographic fingerprint needed to detect conflicting reuse of client idempotency tokens.
5. **Scope**:
   - In `src/messaging/domain/submission_types.hpp`:
     - Define `MessageSubmissionCommand`:
       - `caller_user_id`: `UserId`
       - `sender_device_id`: `DeviceId`
       - `conversation_id`: `ConversationId`
       - `client_idempotency_token`: `std::string`
       - `priority`: `MessagePriority`
       - `expires_at`: `std::optional<time_point>`
       - `delivery_targets`: `std::vector<DeviceDeliveryTarget>`
     - Define `DeviceDeliveryTarget`:
       - `recipient_user_id`: `UserId`
       - `recipient_device_id`: `DeviceId`
       - `envelope`: `CiphertextEnvelope`
       - `algorithm`: `std::string`
       - `ephemeral_public_key`: `std::vector<uint8_t>`
       - `iv`: `std::vector<uint8_t>`
       - `auth_tag`: `std::vector<uint8_t>`
     - Define `SubmissionValidationResult`: holds status, field name, and `MessagingErrorCode`.
   - In `src/messaging/service/submission_validator.hpp|cpp`:
     - Implement `SubmissionValidator`:
       - Validates non-empty `conversation_id` (RFC 9562 UUIDv7 format).
       - Validates non-empty `sender_device_id` (matches caller context).
       - Validates non-empty `client_idempotency_token` (length $\le 128$ chars, valid ASCII/printable).
       - Validates `delivery_targets`: non-empty, contains $\le 256$ targets, enforces unique `(recipient_user_id, recipient_device_id)` pairs.
       - Enforces ADR-008: validates `ciphertext_blob` non-empty, `auth_tag` $\ge 16$ bytes, approved algorithm (`XChaCha20-Poly1305` or `AES-256-GCM`).
   - In `src/messaging/domain/submission_fingerprint.hpp|cpp`:
     - Implement `calculate_submission_fingerprint(const MessageSubmissionCommand& cmd) -> std::string`:
       - Computes canonical SHA-256 over:
         `conversation_id` + `|` + `sender_device_id` + `|` + `priority` + `|` + sorted recipient targets `(recipient_device_id + ":" + SHA256(ciphertext))`.
       - Produces a 64-character hex string representing the exact semantic content of the submission.
   - Unit tests in `tests/unit/messaging/submission_validator_test.cpp` and `tests/unit/messaging/submission_fingerprint_test.cpp`.
6. **Explicit Out-of-Scope**: Database lookups; gRPC handler logic.
7. **Dependencies**: `MSG-002`, `MSG-004-T04`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/submission_types.hpp`
   - `src/messaging/domain/submission_fingerprint.hpp`
   - `src/messaging/domain/submission_fingerprint.cpp`
   - `src/messaging/service/submission_validator.hpp`
   - `src/messaging/service/submission_validator.cpp`
   - `tests/unit/messaging/submission_validator_test.cpp`
   - `tests/unit/messaging/submission_fingerprint_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-005-T02 — Per-Conversation Sequence Allocation & Time-Bucketing Engine

1. **Ticket ID**: `MSG-005-T02`
2. **Title**: Monotonic Sequence Number Allocation & Monthly Partition Rollover Engine
3. **Objective**: Implement a thread-safe, monotonic sequence number allocator per conversation within monthly UTC partitions (`YYYYMM`).
4. **Architectural Purpose**: Enforces the canonical ordering invariant (`message_sequence ASC`) required by ScyllaDB clustering keys, ADR-007, and incremental sync cursors without relying on client timestamps or distributed locking.
5. **Scope**:
   - In `src/messaging/service/sequence_allocator_interface.hpp`:
     - Define `ISequenceAllocator`:
       - `allocate_sequence(const ConversationId& conv_id, const MessageBucket& bucket) -> Result<uint64_t, DomainError>`
       - `peek_sequence(const ConversationId& conv_id, const MessageBucket& bucket) -> uint64_t`
   - In `src/messaging/service/conversation_sequence_allocator.hpp|cpp`:
     - Implement `ConversationSequenceAllocator` (implements `ISequenceAllocator`):
       - Tracks active atomic sequence counters per `(ConversationId, MessageBucket)` in an in-memory cache protected by striped mutexes.
       - **Cold Start Recovery**: If a counter is uninitialized, queries `IMessageRepository::get_last_sequence(conv_id, bucket)` to initialize from authoritative ScyllaDB state.
       - Monotonically increments and returns the next sequence number.
       - Bounded cache with LRU eviction for inactive conversations.
   - Unit tests in `tests/unit/messaging/sequence_allocator_test.cpp`:
     - Concurrency tests: multiple concurrent allocations for the same conversation yield strictly increasing sequential numbers without gaps or duplicates.
     - Cold recovery test: verifies initialization from repository max sequence.
     - Monthly bucket rollover test: transitions from `202610` to `202611`.
6. **Explicit Out-of-Scope**: Writing message envelopes to database.
7. **Dependencies**: `MSG-004-T04` (`IMessageRepository`).
8. **Files to Create/Modify**:
   - `src/messaging/service/sequence_allocator_interface.hpp`
   - `src/messaging/service/conversation_sequence_allocator.hpp`
   - `src/messaging/service/conversation_sequence_allocator.cpp`
   - `tests/unit/messaging/sequence_allocator_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-005-T03 — Idempotency Enforcement & Conflict Resolution Engine

1. **Ticket ID**: `MSG-005-T03`
2. **Title**: Client Idempotency Guard & Conflicting Submission Conflict Resolver
3. **Objective**: Implement the authoritative idempotency verification service to handle duplicate client submissions, detect conflicting payload reuse, and manage concurrent in-flight retries.
4. **Architectural Purpose**: Guarantees at-most-once message creation and at-least-once delivery recovery across mobile network timeouts without duplicating messages or delivery queues.
5. **Scope**:
   - In `src/messaging/service/idempotency_guard.hpp|cpp`:
     - Define `IdempotencyEvaluationResult`:
       - `Action`: `ProceedNew`, `ReturnCached`, `RejectConflict`, `RetryWait`
       - `cached_record`: `std::optional<IdempotencyRecord>`
       - `error_reason`: `std::string`
     - Implement `MessageSubmissionIdempotencyGuard`:
       - Evaluates `IIdempotencyRepository::find_submission(sender_device_id, idempotency_key)`.
       - **Case 1: No Existing Record**:
         - Returns `ProceedNew`.
       - **Case 2: Existing Record Found with Status COMMITTED**:
         - Compares stored `message_id` and checks fingerprint consistency.
         - If consistent: returns `ReturnCached` with the stored `IdempotencyRecord`.
         - If conflicting (payload hash mismatch or different conversation): returns `RejectConflict` with `MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT`.
       - **Case 3: Existing Record Found with Status PROCESSING (Concurrent In-Flight Duplicate)**:
         - Bounded exponential backoff or short wait to allow the primary request to complete.
         - Returns `ReturnCached` if transition succeeds, or `RetryWait` / `Unavailable` if deadline reached.
   - Extend `IdempotencyRecord` in `src/messaging/domain/idempotency_types.hpp`:
     - Add `request_fingerprint` (`std::string`) field to store the SHA-256 payload hash for tamper and conflict detection.
   - Unit tests in `tests/unit/messaging/idempotency_guard_test.cpp`:
     - Exact replay of identical request $\to$ returns cached result.
     - Conflicting payload with same key $\to$ rejects with conflict error.
     - New key $\to$ proceeds.
     - Status processing transition.
6. **Explicit Out-of-Scope**: Executing gRPC calls.
7. **Dependencies**: `MSG-004-T05` (`IIdempotencyRepository`), `MSG-005-T01`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/idempotency_types.hpp`
   - `src/messaging/service/idempotency_guard.hpp`
   - `src/messaging/service/idempotency_guard.cpp`
   - `tests/unit/messaging/idempotency_guard_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-005-T04 — Durable Atomic Message Submission Orchestrator

1. **Ticket ID**: `MSG-005-T04`
2. **Title**: Message Submission Application Service & Atomic Durability Boundary
3. **Objective**: Implement the authoritative `MessageSubmissionService` orchestrating the complete submission pipeline and enforcing the atomic durable commit boundary.
4. **Architectural Purpose**: Coordinates validation, membership authorization, idempotency checks, sequence allocation, durable message insertion, per-device delivery queues, and transactional outbox event publication under strict failure boundaries.
5. **Scope**:
   - In `src/messaging/service/message_submission_service.hpp|cpp`:
     - Implement `MessageSubmissionService`:
       - Dependencies:
         - `ConversationAuthorizationService&`
         - `SubmissionValidator&`
         - `MessageSubmissionIdempotencyGuard&`
         - `ISequenceAllocator&`
         - `IMessageRepository&`
         - `IDeliveryStateRepository&`
         - `IIdempotencyRepository&`
         - `IOutboxRepository&`
       - Method: `submit_message(const MessageSubmissionCommand& cmd) -> Result<MessageSubmissionResponse, DomainError>`
       - Pipeline Execution Steps:
         1. **Context & Membership Authorization**:
            - Calls `ConversationAuthorizationService::can_send_message(caller_user_id, conversation_id)`.
            - If unauthorized: aborts immediately with `UNAUTHORIZED` or `NOT_FOUND`.
         2. **Syntax & Envelope Validation**:
            - Calls `SubmissionValidator::validate(cmd)`. Aborts on invalid fields.
         3. **Idempotency Guard Check**:
            - Evaluates `IdempotencyGuard::evaluate(cmd)`.
            - If `ReturnCached`: constructs response directly from cached record (**zero DB mutations**).
            - If `RejectConflict`: aborts with `IDEMPOTENCY_CONFLICT`.
         4. **Identity & Sequence Allocation**:
            - Generates `MessageId` (UUIDv7).
            - Computes `MessageBucket::from_time_point(now)`.
            - Allocates monotonic `MessageSequence` via `ISequenceAllocator`.
         5. **Authoritative Durable Commit Boundary**:
            - **Step A**: Record idempotency record with status `PROCESSING`.
            - **Step B**: Save `MessageEntity` in `IMessageRepository`.
            - **Step C**: For each delivery target device, construct and persist `DeviceDeliveryRecord` in `pending_deliveries_by_device` and `RecipientDeliveryState` in `delivery_state_by_message`.
            - **Step D**: Construct `ConversationOutboxEvent` (`event_type = MessageSent`, payload containing message ID, conversation ID, sequence, sender device, target device list) and persist to `IOutboxRepository`.
            - **Step E**: Update idempotency record status to `COMMITTED`.
         6. **Return Success**:
            - Returns `MessageSubmissionResponse` (`message_id`, `conversation_id`, `sequence`, `accepted_at_unix_ms`, `target_count`).
     - Error Handling & Durability:
       - If any step in the durable commit boundary fails, maps to `DomainErrorCode` (ADR-009) and aborts without reporting success.
   - Unit tests in `tests/unit/messaging/message_submission_service_test.cpp`:
     - Full happy path with repository call verifications.
     - Membership rejection (unauthorized caller).
     - Idempotent deduplication without secondary DB writes.
     - Conflicting idempotency key rejection.
     - Database failure during message write, delivery state write, or outbox write.
6. **Explicit Out-of-Scope**: Asynchronous worker execution of outbox events (MSG-007).
7. **Dependencies**: `MSG-003`, `MSG-004`, `MSG-005-T01` through `MSG-005-T03`.
8. **Files to Create/Modify**:
   - `src/messaging/service/message_submission_service.hpp`
   - `src/messaging/service/message_submission_service.cpp`
   - `tests/unit/messaging/message_submission_service_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-005-T05 — gRPC SendMessage Handler, Concurrency Pools & Gateway Proxy Integration

1. **Ticket ID**: `MSG-005-T05`
2. **Title**: gRPC SendMessage Endpoint, Concurrency Worker Pool & Gateway REST Routing
3. **Objective**: Implement the live `SendMessage` RPC in `MessagingServiceImpl` utilizing `submission_pool_`, enforce deadlines/cancellation, and activate the Gateway REST proxy route `POST /api/v1/messages`.
4. **Architectural Purpose**: Connects the message submission application service to the external network boundary, applying bounded concurrency (ADR-010) and comprehensive error mapping (ADR-009).
5. **Scope**:
   - In `src/messaging/service/messaging_service_impl.hpp|cpp`:
     - Update constructor to accept `std::shared_ptr<MessageSubmissionService>`.
     - Implement `SendMessage(ServerContext* context, const SendMessageRequest* request, SendMessageResponse* response)`:
       - Extracts `MessagingCallerContext` and validates `user_id` and `device_id`.
       - Checks context deadline and cancellation (`context->IsCancelled()`).
       - Dispatches execution to `submission_pool_->enqueue(...)`.
       - Converts protobuf `SendMessageRequest` into domain `MessageSubmissionCommand`.
       - Calls `MessageSubmissionService::submit_message(...)`.
       - Maps domain results to `SendMessageResponse` or returns structured `grpc::Status` via `MessagingErrorMapper`.
       - Bounded concurrency: if worker queue is saturated, returns `RESOURCE_EXHAUSTED` / `MESSAGING_ERROR_CODE_SERVER_BUSY`.
   - In `src/gateway/http/proxy/messaging_proxy_handler.cpp`:
     - Activate `POST /api/v1/messages`:
       - Extracts authenticated context (`AuthenticatedContext`).
       - Translates JSON body (`conversation_id`, `priority`, `idempotency_token`, `delivery_targets`) to protobuf `SendMessageRequest`.
       - Injects `X-Caller-User-Id`, `X-Caller-Device-Id`, `X-Correlation-Id`.
       - Calls `IMessagingClient::send_message(...)`.
       - Returns HTTP 201 Created on success, HTTP 409 on idempotency conflict, HTTP 403 on authorization failure.
   - Unit tests in `tests/unit/messaging/messaging_service_submission_test.cpp` and `tests/unit/gateway/messaging_proxy_handler_test.cpp`.
6. **Explicit Out-of-Scope**: WebSocket real-time frame dispatch.
7. **Dependencies**: `MSG-005-T04`, `GatewayProxyHandler`.
8. **Files to Create/Modify**:
   - `src/messaging/service/messaging_service_impl.hpp`
   - `src/messaging/service/messaging_service_impl.cpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.cpp`
   - `tests/unit/messaging/messaging_service_submission_test.cpp`
   - `tests/unit/gateway/messaging_proxy_handler_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-005-T06 — End-to-End Submission & Idempotency Integration Suite

1. **Ticket ID**: `MSG-005-T06`
2. **Title**: Comprehensive Message Submission & Idempotency Integration Suite
3. **Objective**: Verify the entire message submission path under realistic end-to-end scenarios, including concurrent duplicate retries, idempotency conflicts, membership authorization, and ScyllaDB persistence.
4. **Architectural Purpose**: Certifies that the durable message write boundary holds under concurrency and network failures, guaranteeing zero duplicate messages and safe retries.
5. **Scope**:
   - Create `tests/integration/messaging_submission_integration_test.cpp`:
     - **Test 1: Happy Path Submission**: Authenticated user submits encrypted message envelope with 2 recipient device targets $\to$ verifies message persisted in ScyllaDB, pending delivery records created for both devices, outbox event enqueued, and success returned.
     - **Test 2: Idempotent Replay**: Same client resends exact same request with same idempotency token $\to$ receives identical `message_id` and sequence; verifies no secondary rows created in `messages_by_conversation` or `messaging_outbox_events`.
     - **Test 3: Conflicting Idempotency Token Reuse**: Client sends different message body / different conversation with previously used idempotency token $\to$ receives deterministic `MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT` (HTTP 409).
     - **Test 4: Concurrent Duplicate Submissions**: 10 threads submit the exact same request simultaneously $\to$ exactly 1 message is created in the database; all 10 callers receive the identical valid `message_id`.
     - **Test 5: Unauthorized Sender Rejection**: Non-member or removed participant attempts submission $\to$ rejected with `UNAUTHORIZED` or `NOT_FOUND`; zero database writes.
     - **Test 6: Closed Conversation Rejection**: Sender attempts submission to a `CLOSED` group $\to$ rejected with `CONVERSATION_CLOSED`.
     - **Test 7: Bounded Queue Saturation**: Overload submission pool beyond capacity $\to$ rejects with `RESOURCE_EXHAUSTED` / `SERVER_BUSY`.
     - **Test 8: Gateway HTTP E2E Integration**: `POST /api/v1/messages` via HTTP proxy through Gateway to Messaging gRPC service.
   - Run full verification suite across all repository tests with `python3 scripts/verify-local.py --preset dev-debug`.
6. **Explicit Out-of-Scope**: Push notification delivery.
7. **Dependencies**: `MSG-005-T01` through `MSG-005-T05`.
8. **Files to Create/Modify**:
   - `tests/integration/messaging_submission_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`
   - `specs/phase2/MSG-005-tickets.md`

---

## 5. Acceptance Criteria & Validation Matrix

| Criterion | Target Specification | Validation Mechanism |
| :--- | :--- | :--- |
| **Authenticated Submission** | Caller context extracted and validated; rejects unauthenticated calls | `messaging_service_submission_test.cpp` |
| **Membership Authorization** | Sender must be an active participant; closed conversations rejected | Unit & Integration tests |
| **Encrypted Envelope Integrity** | Opaque ciphertext validated (ADR-008); zero plaintext stored | `submission_validator_test.cpp` |
| **Monotonic Sequence Numbers** | Sequences monotonically increase per conversation bucket | `sequence_allocator_test.cpp` |
| **Identical Retry Idempotency** | Exact replay returns cached `message_id` without secondary DB writes | `messaging_submission_integration_test.cpp` |
| **Conflicting Idempotency Rejection** | Reusing token with modified payload is rejected deterministically | Unit & Integration tests |
| **Concurrent Race Safety** | Concurrent identical retries yield exactly one created message | Concurrency test in integration suite |
| **Atomic Durability Boundary** | Message, pending delivery queues, outbox event, and idempotency committed before ACK | Architecture review & test assertions |
| **Zero Global Queue** | Delivery records partitioned strictly by `((device_id, delivery_bucket))` | `scylla_delivery_repository_test.cpp` |
| **Transactional Outbox Event** | Enqueues `MessageSent` event to `messaging_outbox_events` | Integration suite assertions |
| **Bounded Worker Pool Concurrency** | Submissions executed via `submission_pool_` with deadline enforcement | `bounded_worker_pool_test.cpp` |
| **Gateway REST Integration** | `POST /api/v1/messages` activated and proxied to Messaging gRPC | `messaging_proxy_handler_test.cpp` |
| **Zero Codebase Regressions** | All cumulative tests (1,446+) continue to pass cleanly | `verify-local.py --preset dev-debug` |

---

## 6. Architectural Invariants Checklist

- [x] **Critical Durability Boundary**: Message + per-device delivery state + outbox event + idempotency record must be durably committed before acknowledging success.
- [x] **No Decryption on Server**: Message envelopes remain opaque ciphertexts (ADR-008); zero plaintext stored or inspected.
- [x] **Deterministic Idempotency**: Identical retries return original submission; conflicting payloads with duplicate token are deterministically rejected.
- [x] **No Global Delivery Queue**: Delivery records partitioned strictly by recipient `((device_id, delivery_bucket))`; no queue scans.
- [x] **No Synchronous Audit Dependency**: Audit logging is asynchronous via outbox events; no cross-service transactions.
- [x] **Bounded Concurrency**: All submission tasks routed through bounded worker pools with request deadlines and cancellation checks.
- [x] **Zero Regressions**: Cumulative test suite passes 100% across all platforms.
