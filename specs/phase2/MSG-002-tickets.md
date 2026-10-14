# MSG-002 — Messaging API & Protobuf Contracts
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-002  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-002** defines the authoritative service-to-service and client-facing API contracts required by the SecureCloud Messaging Service (`securecloud-messaging`), adhering strictly to **ADR-004** (gRPC/Protobuf IPC), **ADR-007** (Message Reliability & Durability), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance & Bounded Concurrency).

While MSG-001 established the service foundation, mTLS harness, configuration system, and bounded tri-pool worker architecture, **MSG-002 establishes the semantic and domain contract boundaries** for all message operations, conversation lifecycles, delivery state transitions, synchronization cursors, presence signaling, metadata correlation, and idempotency guarantees.

### Key Invariants & Architectural Boundaries for MSG-002

1. **Domain Contract Ownership Principle**:
   Messaging exclusively owns the domain contract and semantic definitions (`proto/securecloud/messaging/v1/messaging.proto`). The API Gateway and endpoint Clients consume this contract as clients and must never independently define, fork, or duplicate Messaging domain types (following the architectural boundary established in GW-003 and GW-010).
2. **Zero Plaintext & Zero Private Key Exposure (ADR-008)**:
   All message payloads in protobuf contracts remain strictly opaque encrypted ciphertext (`EncryptedPayload` containing `ciphertext_blob`, `ephemeral_public_key`, `initialization_vector`, `auth_tag`, `algorithm`). The backend contracts must never contain fields for decrypted content, session keys, or private cryptographic credentials.
3. **Strict Separation of Delivery and Read States (ADR-007, Design 5.13-5.14)**:
   `DELIVERED` (durable receipt acknowledgment by a target device) and `READ` (client UI presentation acknowledgment by the user) are distinct states and must never be conflated in data structures, RPC requests, or response payloads.
4. **Idempotency & Monotonic Nonce Guarantees (ADR-007, Design 5.7)**:
   Message submission contracts mandate a client-supplied unique `client_idempotency_token`. Duplicate submissions with identical tokens and sender identities must yield deterministic, deduplicated responses without creating redundant messages.
5. **No Database Schema Leakage (ADR-005, Design 5.9)**:
   No ScyllaDB table names, partition keys, clustering keys, or internal persistence artifacts are exposed in protobuf contracts. Contracts operate exclusively over domain entities (`MessageEnvelope`, `ConversationMetadata`, `SyncCursor`, `DeliveryState`).
6. **No Global Ordering Dependency (ADR-007, Design 5.22)**:
   The contract assumes sequence ordering is scoped to individual conversations and device streams. No global sequence numbers or distributed locks are introduced.
7. **Presence Decoupling (Design 5.25)**:
   Presence status (`ONLINE`, `OFFLINE`, `AWAY`, `BUSY`) is an ephemeral operational signal. It is never the authoritative source of truth for message durability or offline queuing.

---

## 2. Dependency Graph

```text
               MSG-001 (Messaging Service Foundation)
               SC-005 (Protobuf + gRPC Generation)
               SC-010 (mTLS Infrastructure)
                          │
                          ▼
                     MSG-002-T01
       (Domain Contract Refinement & Presence Protocol)
                          │
           ┌──────────────┴──────────────┐
           │                             │
           ▼                             ▼
      MSG-002-T02                   MSG-002-T03
(Identifier, Idempotency &     (Delivery Lifecycle, Receipts
 Metadata Context Validation)   & Sync Cursor Semantics)
           │                             │
           └──────────────┬──────────────┘
                          │
                          ▼
                     MSG-002-T04
      (Deadlines, Cancellation & Canonical Error Status Mapping)
                          │
                          ▼
                     MSG-002-T05
      (Gateway & Client Consumer Boundary Integration)
                          │
                          ▼
                     MSG-002-T06
      (Contract Verification Harness & Multi-Platform Integration)
```

---

## 3. Implementation Tickets

### MSG-002-T01 — Domain Contract Refinement & Presence Protocol

1. **Ticket ID**: `MSG-002-T01`
2. **Title**: Domain Contract Schema Refinement, Presence Protocol & Error Details in `messaging.proto`
3. **Objective**: Expand and refine `proto/securecloud/messaging/v1/messaging.proto` to incorporate complete M3 messaging capabilities, adding presence signaling RPCs, conversation lifecycle enhancements, and rich structured domain error detail messages.
4. **Architectural Purpose**: Completes the core Protobuf schema baseline, ensuring all client and service interactions (presence, conversation management, delivery status, and error signaling) are formally defined without REST leakage or ad-hoc metadata.
5. **Scope**:
   - In `proto/securecloud/messaging/v1/messaging.proto`:
     - **Presence Protocol**:
       - Define `enum PresenceStatus`: `PRESENCE_STATUS_UNSPECIFIED = 0`, `PRESENCE_STATUS_ONLINE = 1`, `PRESENCE_STATUS_AWAY = 2`, `PRESENCE_STATUS_BUSY = 3`, `PRESENCE_STATUS_OFFLINE = 4`.
       - Define `message UserPresence`: `string user_id = 1;`, `PresenceStatus status = 2;`, `int64 last_active_unix_ms = 3;`, `string custom_status_message = 4;`.
       - Define `UpdatePresenceRequest`: `PresenceStatus status = 1;`, `string custom_status_message = 2;`.
       - Define `UpdatePresenceResponse`: `UserPresence presence = 1;`.
       - Define `GetPresenceRequest`: `string user_id = 1;`.
       - Define `GetPresenceResponse`: `UserPresence presence = 1;`.
       - Define `BatchGetPresenceRequest`: `repeated string user_ids = 1;`.
       - Define `BatchGetPresenceResponse`: `repeated UserPresence presences = 1;`.
       - Add RPCs to `MessagingService`: `UpdatePresence`, `GetPresence`, `BatchGetPresence`.
     - **Conversation Operations Expansion**:
       - Define `LeaveConversationRequest`: `string conversation_id = 1;`.
       - Define `LeaveConversationResponse`: `string conversation_id = 1;`, `bool success = 2;`.
       - Define `UpdateConversationMetadataRequest`: `string conversation_id = 1;`, `string title = 2;`.
       - Define `UpdateConversationMetadataResponse`: `ConversationMetadata conversation = 1;`.
       - Add RPCs to `MessagingService`: `LeaveConversation`, `UpdateConversationMetadata`.
     - **Structured Domain Error Details**:
       - Define `enum MessagingErrorCode`:
         - `MESSAGING_ERROR_CODE_UNSPECIFIED = 0;`
         - `MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND = 1;`
         - `MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT = 2;`
         - `MESSAGING_ERROR_CODE_DEVICE_REVOKED = 3;`
         - `MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT = 4;`
         - `MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE = 5;`
         - `MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED = 6;`
         - `MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS = 7;`
         - `MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE = 8;`
         - `MESSAGING_ERROR_CODE_MESSAGE_EXPIRED = 9;`
       - Define `message MessagingErrorDetail`: `MessagingErrorCode error_code = 1;`, `string reason = 2;`, `string correlation_id = 3;`, `map<string, string> metadata = 4;`.
   - Update `src/messaging/service/messaging_service_impl.hpp` and `.cpp` to declare and stub all newly added RPCs returning `{::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message}`.
   - Maintain cross-platform macro safety via `proto/proto_win32_compat.hpp` and explicit `#undef` guards.
6. **Explicit Out-of-Scope**: Implementing business logic for presence storage or conversation persistence (deferred to MSG-003+).
7. **Dependencies**: `MSG-001-T01` (Baseline proto), `SC-005` (Protobuf generation). Downstream `MSG-002-T02`.
8. **Exact Repository Starting Point**: `proto/securecloud/messaging/v1/messaging.proto`.
9. **Files/Directories to Inspect**:
   - `docs/design/messaging-design.md` (Sections 5.4, 5.5, 5.25, 5.33)
   - `proto/securecloud/auth/v1/auth.proto` (Pattern consistency)
10. **Files/Directories to Create**: None.
11. **Files/Directories That May Be Modified**:
    - `proto/securecloud/messaging/v1/messaging.proto`
    - `src/messaging/service/messaging_service_impl.hpp`
    - `src/messaging/service/messaging_service_impl.cpp`
    - `tests/unit/proto_smoke_test.cpp`
12. **Files/Directories That MUST NOT Be Modified**:
    - `proto/securecloud/auth/v1/*`, `proto/securecloud/files/v1/*`, `proto/securecloud/common/v1/*`.
13. **Detailed Implementation Requirements**:
    - Package: `securecloud.messaging.v1`, `syntax = "proto3"`, `cc_generic_services = false`.
    - Preserve zero-value enums `*_UNSPECIFIED = 0`.
    - Field numbers must follow strict incrementing order without reuse or gaps.
    - Code generation must compile warning-free under Clang, GCC, and MSVC.

---

### MSG-002-T02 — Identifier, Idempotency & Metadata Context Specification

1. **Ticket ID**: `MSG-002-T02`
2. **Title**: Canonical Identifiers, Idempotency Token Semantics & gRPC Metadata Context Contract
3. **Objective**: Formalize the metadata propagation contract between Gateway and Messaging Service, specify canonical UUID format validation, and define idempotency token collision handling rules.
4. **Architectural Purpose**: Establishes end-to-end trace correlation and deduplication guarantees across distributed services (**ADR-004**, **ADR-007**, **ADR-009**), preventing duplicate message injection during network retries.
5. **Scope**:
   - Define authoritative gRPC metadata headers expected on internal mTLS channels:
     - `x-correlation-id`: Canonical RFC 4122 UUIDv7 string for distributed call tracing.
     - `x-user-id`: Authenticated caller user UUIDv4/v7 extracted by Gateway from JWT.
     - `x-device-id`: Authenticated caller device UUIDv4/v7.
     - `x-idempotency-token`: Client-supplied idempotency key (16 to 64 ASCII characters).
   - In `src/messaging/service/messaging_service_impl.hpp` and `.cpp`:
     - Implement metadata extraction and validation helpers:
       - `extract_caller_context(const ::grpc::ServerContext* context, CallerContext& out)`
       - Validate presence and non-emptiness of caller identity when handling protected RPCs.
       - Implement canonical UUID syntax validation helper (`is_valid_uuid(std::string_view)`).
     - Define `CallerContext` structure:
       ```cpp
       struct CallerContext {
           std::string user_id;
           std::string device_id;
           std::string correlation_id;
           std::string idempotency_token;
           std::string peer_identity; // e.g. "gateway"
       };
       ```
   - Unit tests verifying:
     - Extraction of all headers from gRPC `client_metadata`.
     - Rejection of invalid UUID strings or malformed idempotency tokens.
     - Fallback handling when optional idempotency tokens are omitted.
6. **Explicit Out-of-Scope**: Distributed cache/ScyllaDB storage of idempotency tokens (deferred to MSG-004).
7. **Dependencies**: `MSG-002-T01`. Downstream `MSG-002-T04`.
8. **Exact Repository Starting Point**: `src/messaging/service/messaging_service_impl.hpp|cpp`.
9. **Files/Directories to Inspect**:
   - `docs/design/messaging-design.md` (Sections 5.7, 5.37)
   - `src/common/include/securecloud/security/mtls_config.hpp`
10. **Files/Directories to Create**:
    - `src/messaging/service/caller_context.hpp` (or define within `messaging_service_impl.hpp`)
11. **Files/Directories That May Be Modified**:
    - `src/messaging/service/messaging_service_impl.hpp`
    - `src/messaging/service/messaging_service_impl.cpp`
    - `tests/unit/messaging/messaging_service_test.cpp`
12. **Files/Directories That MUST NOT Be Modified**:
    - Gateway proxy handlers or Auth service sources.
13. **Detailed Implementation Requirements**:
    - Zero plain text logging: metadata logs must never output payload bytes or user-identifying credentials.
    - Idempotency token format: alphanumeric plus hyphen and underscore (`[a-zA-Z0-9_-]{16,64}`).

---

### MSG-002-T03 — Delivery Lifecycle, Read-Receipt Separation & Sync Cursor Semantics

1. **Ticket ID**: `MSG-002-T03`
2. **Title**: Delivery Lifecycle Transitions, Read-Receipt Independence & Cursor Synchronization Semantics
3. **Objective**: Formalize the lifecycle state machine contracts for message delivery, specify non-conflated read receipt contracts, and define incremental synchronization pagination and cursor behaviors.
4. **Architectural Purpose**: Enforces the architectural requirements of **ADR-007** and **Design Sections 5.13–5.14, 5.23–5.24**, ensuring multi-device message delivery and synchronization are decoupled from UI read states and global ordering.
5. **Scope**:
   - In `proto/securecloud/messaging/v1/messaging.proto`:
     - Clarify comments and specifications on `DeliveryState` transitions:
       - `QUEUED -> DELIVERING -> DELIVERED -> READ`
       - `DELIVERING -> RETRY_WAIT -> DELIVERING`
       - `QUEUED | RETRY_WAIT -> EXPIRED`
     - Formalize `SyncCursor`:
       - `string device_id = 1;`
       - `int64 last_delivered_sequence = 2;` (strictly monotonic 64-bit integer per-device)
       - `int64 last_sync_timestamp_unix_ms = 3;`
     - Formalize `SyncDeviceMessagesRequest` & `SyncDeviceMessagesResponse`:
       - Add `int32 limit = 3;` with bounded defaults (default 50, max 200).
       - Explicit `bool has_more = 4;` and `int64 next_sequence = 5;`.
     - Formalize `GetMessagesRequest` & `GetMessagesResponse`:
       - Pagination bounds: `uint32 max_results` capped to 100.
       - Monotonic boundary check `since_sequence >= 0`.
   - Add unit test suite in `tests/unit/messaging/messaging_contract_semantics_test.cpp`:
     - Test delivery state valid vs invalid transition assertions.
     - Test cursor advance invariance: cursor advances monotonically; duplicate/stale sequence updates are rejected.
     - Test read receipt independence: receiving `SendReadReceipt` for an un-delivered message does not retroactively forge delivery sequence.
6. **Explicit Out-of-Scope**: ScyllaDB partition reads/writes (deferred to MSG-003/004).
7. **Dependencies**: `MSG-002-T01`. Downstream `MSG-002-T04`.
8. **Exact Repository Starting Point**: `proto/securecloud/messaging/v1/messaging.proto`.
9. **Files/Directories to Inspect**:
   - `docs/design/messaging-design.md` (Sections 5.13, 5.14, 5.23, 5.24)
   - `docs/adr/adr-007-message-reliability-durability.md`
10. **Files/Directories to Create**:
    - `tests/unit/messaging/messaging_contract_semantics_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `proto/securecloud/messaging/v1/messaging.proto`
    - `tests/unit/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**:
    - `src/auth/*`, `src/files/*`.
13. **Detailed Implementation Requirements**:
    - Ensure zero-copy string views and deterministic validation in contract assertions.
    - Validate that Protobuf generated classes integrate seamlessly with `std::chrono` and standard C++20 structures.

---

### MSG-002-T04 — Deadlines, Cancellation & Canonical Error Status Mapping

1. **Ticket ID**: `MSG-002-T04`
2. **Title**: Bounded Deadlines, Cancellation Propagation & Canonical gRPC Status Code Mapping
3. **Objective**: Implement a centralized error and status mapping engine that translates Messaging domain errors into canonical `grpc::Status` with attached `MessagingErrorDetail` metadata, honoring request deadlines and cancellation signals.
4. **Architectural Purpose**: Implements **ADR-004** (Section 9) and **ADR-009** (Distributed Failure Resilience), ensuring no call blocks indefinitely, client timeouts are cooperatively honored, and failures communicate actionable error codes without leaking backend internals.
5. **Scope**:
   - Implement `src/messaging/service/messaging_error_mapper.hpp` and `.cpp`:
     - Function `::grpc::Status to_grpc_status(MessagingErrorCode code, std::string_view message, std::string_view correlation_id)`:
       - `CONVERSATION_NOT_FOUND` -> `grpc::StatusCode::NOT_FOUND`
       - `NOT_A_PARTICIPANT` -> `grpc::StatusCode::PERMISSION_DENIED`
       - `DEVICE_REVOKED` -> `grpc::StatusCode::PERMISSION_DENIED`
       - `IDEMPOTENCY_CONFLICT` -> `grpc::StatusCode::ALREADY_EXISTS`
       - `PAYLOAD_TOO_LARGE` -> `grpc::StatusCode::INVALID_ARGUMENT`
       - `QUEUE_CAPACITY_EXCEEDED` -> `grpc::StatusCode::RESOURCE_EXHAUSTED`
       - `CURSOR_OUT_OF_BOUNDS` -> `grpc::StatusCode::OUT_OF_RANGE`
       - `INVALID_TARGET_DEVICE` -> `grpc::StatusCode::FAILED_PRECONDITION`
       - `MESSAGE_EXPIRED` -> `grpc::StatusCode::DEADLINE_EXCEEDED`
     - Serializes `MessagingErrorDetail` into the trailing metadata or error message.
   - Implement deadline and cancellation check helper:
     - `bool check_deadline_and_cancellation(const ::grpc::ServerContext* context, ::grpc::Status& out_status)`:
       - Checks `context->IsCancelled()` -> returns `grpc::StatusCode::CANCELLED`.
       - Checks `context->raw_deadline()` expiration -> returns `grpc::StatusCode::DEADLINE_EXCEEDED`.
   - Unit tests covering:
     - 100% mapping coverage across all `MessagingErrorCode` enum values.
     - Simulated context cancellation returning `StatusCode::CANCELLED`.
     - Expired deadline detection returning `StatusCode::DEADLINE_EXCEEDED`.
6. **Explicit Out-of-Scope**: Gateway circuit breaker integration (handled in T05).
7. **Dependencies**: `MSG-002-T01`, `MSG-002-T02`. Downstream `MSG-002-T05`.
8. **Exact Repository Starting Point**: `src/messaging/service/`.
9. **Files/Directories to Inspect**:
   - `docs/adr/adr-004-inter-process-communication-model.md` (Section 9)
   - `docs/adr/adr-009-distributed-failure-resilience.md` (Section 4)
10. **Files/Directories to Create**:
    - `src/messaging/service/messaging_error_mapper.hpp`
    - `src/messaging/service/messaging_error_mapper.cpp`
    - `tests/unit/messaging/messaging_error_mapper_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `src/messaging/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**:
    - `src/common/include/securecloud/security/*`.
13. **Detailed Implementation Requirements**:
    - Strict noexcept or strong exception-safety for status translation.
    - Zero plain text leakage in error reasons.

---

### MSG-002-T05 — Gateway & Client Consumer Boundary Integration

1. **Ticket ID**: `MSG-002-T05`
2. **Title**: Gateway Messaging Client Interface & Direct Contract Consumption
3. **Objective**: Define the Gateway downstream client interface (`MessagingClientInterface`) and implementation skeleton (`MessagingServiceClient`) consuming `securecloud_proto` directly, verifying that Gateway and Client never duplicate Messaging contracts.
4. **Architectural Purpose**: Enforces the contract ownership rule: Messaging owns the domain contract; Gateway and Client consume it without redefining domain objects (ADR-004, GW-003, GW-010).
5. **Scope**:
   - In `src/gateway/grpc/`:
     - Create `messaging_client_interface.hpp`:
       - Pure virtual interface `MessagingClientInterface`:
         - `send_message(const v1::SendMessageRequest& req, ClientCallContext& ctx) -> Result<v1::SendMessageResponse>`
         - `get_messages(const v1::GetMessagesRequest& req, ClientCallContext& ctx) -> Result<v1::GetMessagesResponse>`
         - `acknowledge_delivery(const v1::AcknowledgeDeliveryRequest& req, ClientCallContext& ctx) -> Result<v1::AcknowledgeDeliveryResponse>`
         - `send_read_receipt(const v1::SendReadReceiptRequest& req, ClientCallContext& ctx) -> Result<v1::SendReadReceiptResponse>`
         - `create_conversation(const v1::CreateConversationRequest& req, ClientCallContext& ctx) -> Result<v1::CreateConversationResponse>`
         - `get_conversation(const v1::GetConversationRequest& req, ClientCallContext& ctx) -> Result<v1::GetConversationResponse>`
         - `list_conversations(const v1::ListConversationsRequest& req, ClientCallContext& ctx) -> Result<v1::ListConversationsResponse>`
         - `sync_device_messages(const v1::SyncDeviceMessagesRequest& req, ClientCallContext& ctx) -> Result<v1::SyncDeviceMessagesResponse>`
         - `get_presence(const v1::GetPresenceRequest& req, ClientCallContext& ctx) -> Result<v1::GetPresenceResponse>`
         - `update_presence(const v1::UpdatePresenceRequest& req, ClientCallContext& ctx) -> Result<v1::UpdatePresenceResponse>`
     - Create `messaging_service_client.hpp` and `.cpp`:
       - Implements `MessagingClientInterface` wrapping `v1::MessagingService::StubInterface`.
       - Integrates `ClientCallContext`, deadline enforcement (`messaging_timeout_ms`), and correlation ID header injection.
   - Register new client classes in `src/gateway/CMakeLists.txt`.
   - Add unit test suite in `tests/unit/gateway/messaging_service_client_test.cpp` verifying stub delegation and deadline propagation using mock stubs.
6. **Explicit Out-of-Scope**: Implementing full HTTP REST proxy handlers for messaging in Gateway (deferred to GW messaging integration phase).
7. **Dependencies**: `MSG-002-T01`, `MSG-002-T04`. Downstream `MSG-002-T06`.
8. **Exact Repository Starting Point**: `src/gateway/grpc/files_client_interface.hpp` and `files_service_client.hpp`.
9. **Files/Directories to Inspect**:
   - `src/gateway/grpc/files_client_interface.hpp`
   - `src/gateway/grpc/files_service_client.hpp|cpp`
   - `src/gateway/grpc/channel_manager.hpp|cpp`
10. **Files/Directories to Create**:
    - `src/gateway/grpc/messaging_client_interface.hpp`
    - `src/gateway/grpc/messaging_service_client.hpp`
    - `src/gateway/grpc/messaging_service_client.cpp`
    - `tests/unit/gateway/messaging_service_client_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**:
    - `src/gateway/http/proxy/files_proxy_handler.*`.
13. **Detailed Implementation Requirements**:
    - Gateway links directly against `securecloud_proto` without intermediate DTO re-declarations.
    - Preserve existing Gateway resilience patterns: bulkhead acquisition, circuit breaker query, timeout propagation.

---

### MSG-002-T06 — Contract Verification Harness, Backward Compatibility & Integration Suite

1. **Ticket ID**: `MSG-002-T06`
2. **Title**: Comprehensive Protobuf Contract Verification, Wire Compatibility & Live Lifecycle Integration
3. **Objective**: Build an end-to-end verification harness confirming schema wire compatibility, descriptor reflection, and live mTLS client-server invocation across all 15+ Messaging RPCs.
4. **Architectural Purpose**: Ensures strict contract adherence, forward/backward wire serialization stability, and platform non-regression across all supported environments (AppleClang macOS, GCC Linux, MSVC 2022 Windows).
5. **Scope**:
   - Expand `tests/unit/proto_smoke_test.cpp`:
     - Test message serialization and deserialization for all newly added types (`UserPresence`, `UpdatePresenceRequest`, `LeaveConversationRequest`, `MessagingErrorDetail`).
     - Test enum default values (`_UNSPECIFIED == 0`).
     - Test stub type linkage and method signature reflection.
   - Expand `tests/integration/messaging_service_lifecycle_integration_test.cpp`:
     - Update Gateway test client to invoke all 15+ RPCs over a live mTLS channel with valid SAN credentials (`DNS:gateway`).
     - Verify deterministic `StatusCode::UNIMPLEMENTED` responses for every method.
     - Verify that metadata correlation headers (`x-correlation-id`, `x-user-id`, `x-device-id`) are received and processed by `MessagingServiceImpl`.
   - Verify backward compatibility:
     - Verify that optional new fields do not break older serialized message payloads.
     - Verify field numbering consistency and absence of conflicting tags.
   - Run complete regression suite across all 1,247+ tests.
6. **Explicit Out-of-Scope**: Testing database persistence or cryptographic ratchets.
7. **Dependencies**: `MSG-002-T01` through `MSG-002-T05`.
8. **Exact Repository Starting Point**: `tests/unit/proto_smoke_test.cpp`, `tests/integration/messaging_service_lifecycle_integration_test.cpp`.
9. **Files/Directories to Inspect**:
   - `tests/unit/proto_smoke_test.cpp`
   - `tests/integration/messaging_service_lifecycle_integration_test.cpp`
10. **Files/Directories to Create**: None.
11. **Files/Directories That May Be Modified**:
    - `tests/unit/proto_smoke_test.cpp`
    - `tests/integration/messaging_service_lifecycle_integration_test.cpp`
12. **Files/Directories That MUST NOT Be Modified**:
    - Phase 1 integration tests (`tests/integration/gateway_*`, `tests/integration/auth_*`).
13. **Detailed Implementation Requirements**:
    - 100% test pass rate across `python3 scripts/verify-local.py --preset dev-debug`.
    - `check-format` zero violations.
    - Clang-Tidy zero warnings under `-warnings-as-errors`.

---

## 4. Acceptance Criteria & Card Validation Matrix

| Criterion | Target Specification | Validation Mechanism |
|---|---|---|
| **Protobuf Contract Completeness** | RPCs and messages cover messages, conversations, presence, delivery, receipts, sync | `tests/unit/proto_smoke_test.cpp` |
| **Authentication/Authorization Context** | Metadata headers (`x-user-id`, `x-device-id`, `x-correlation-id`) defined & parsed | `tests/unit/messaging/messaging_service_test.cpp` |
| **Idempotency Guarantees** | Client idempotency token defined and validated across submissions | `tests/unit/messaging/messaging_contract_semantics_test.cpp` |
| **Cursor & Sync Semantics** | Monotonic sequence, device-scoped ordering, bounded pagination | `tests/unit/messaging/messaging_contract_semantics_test.cpp` |
| **Delivery vs Read Separation** | `DELIVERED` and `READ` maintained as strictly independent states | `tests/unit/messaging/messaging_contract_semantics_test.cpp` |
| **Canonical Error Mapping** | `MessagingErrorCode` maps deterministically to `grpc::StatusCode` | `tests/unit/messaging/messaging_error_mapper_test.cpp` |
| **Deadline & Cancellation** | Request timeouts and cooperative cancellation handled | `tests/unit/messaging/messaging_error_mapper_test.cpp` |
| **Gateway Contract Ownership** | Gateway consumes `securecloud_proto` via `MessagingClientInterface` | `tests/unit/gateway/messaging_service_client_test.cpp` |
| **Live mTLS Verification** | All 15+ RPCs executable over live secure mTLS channel | `tests/integration/messaging_service_lifecycle_integration_test.cpp` |
| **Zero Plaintext Exposure** | No plaintext payload fields or private keys in any contract | Schema audit & test assertions |
| **Cross-Platform Clean Build** | Compiles cleanly on AppleClang, GCC 14, and MSVC 2022 | `verify-local.py` & CI matrix |
| **Zero Regressions** | Cumulative suite passes 100% (>= 1,247 tests) | `ctest --preset dev-debug` |

---

## 5. Architectural Invariants & Verification Checklist

- [ ] **No Business Logic**: In MSG-002, all RPCs return deterministic status codes; contract schemas and interface boundaries are finalized without prematurely binding to ScyllaDB logic.
- [ ] **No Plaintext Invariant**: All messages transport ciphertext within `EncryptedPayload`.
- [ ] **No REST Semantics in gRPC**: RPC signatures use typed request/response messages, not HTTP verbs or query parameters.
- [ ] **Opaque Identifiers**: All user, device, conversation, and message IDs are RFC 4122 UUID strings.
- [ ] **No Global Queue or Ordering**: Ordering is constrained to individual device streams and conversations.
- [ ] **Contract Ownership Maintained**: Messaging defines the proto; Gateway and Client consume it without redefining data structures.
