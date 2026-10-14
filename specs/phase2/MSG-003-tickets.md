# MSG-003 — Conversation & Membership Management
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-003  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 14, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-003** defines and implements the authoritative **Conversation & Membership Management** domain for the SecureCloud Messaging Service (`securecloud-messaging`), adhering strictly to **ADR-004** (gRPC/Protobuf IPC), **ADR-005** (Microservice Data Isolation), **ADR-007** (Message Reliability & Durability), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance & Bounded Concurrency).

While Card **MSG-001** established the buildable service lifecycle, tri-pool concurrency engine, and configuration system, and Card **MSG-002** finalized the 17-RPC Protobuf contracts, caller context abstractions, and error mappers, **MSG-003 builds the foundational core domain model, authorization rules, persistence repositories, and service orchestrators for conversations and participants**.

Subsequent cards in the Phase 2 backlog—including Message Submission & Idempotency (`MSG-005`), E2E Envelope Integration (`MSG-006`), Online Message Delivery (`MSG-007`), Read Receipts (`MSG-008`), and Multi-Device Support (`MSG-011`)—strictly depend upon MSG-003 to authenticate conversation existence, determine authorized participant recipient rosters, and validate sender authorization.

### Key Architectural Invariants & Boundaries for MSG-003

1. **Authoritative State Ownership**:
   - The Messaging Service is the single authoritative source of truth for conversation topology (`DIRECT`, `GROUP`), conversation lifecycle state (`ACTIVE`, `CLOSED`), and participant membership status (`ACTIVE`, `LEFT`, `REMOVED`).
   - Messaging does not access Auth, Gateway, or Files databases directly (ADR-005).
2. **Logical Participant vs. Device Separation (Critical Multi-Device Constraint)**:
   - A user (`UserId`) and a device (`DeviceId`) must not be conflated into the same domain entity.
   - Conversation membership is modeled strictly at the **logical participant level (`UserId`)**.
   - Per-device resolution (`UserId` $\to$ set of active `DeviceId`s) is decoupled and handled exclusively during downstream message routing and delivery (Cards MSG-006 and MSG-011).
3. **Canonical Direct Conversation Identity**:
   - A direct (1:1) conversation between two users $U_A$ and $U_B$ is deterministic, unique, and idempotent.
   - Enforced by ordering user identifiers lexicographically: `smaller(UserId) -> user_a_id`, `larger(UserId) -> user_b_id`.
   - Creating a direct conversation between Alice and Bob when one already exists returns the existing canonical `ConversationId` idempotently.
4. **Group Conversation Lifecycle & Fine-Grained Role Authorization**:
   - Group conversations have explicit lifecycle states: `ACTIVE` and `CLOSED`.
   - Participants hold explicit roles: `MEMBER` or `ADMIN`.
   - Only participants with role `ADMIN` may add participants, remove participants, or close the conversation.
   - Voluntary exit (`LeaveConversation`) is permitted for any active participant (`MEMBER` or `ADMIN`).
   - Closing a group freezes membership and prevents subsequent message dispatch.
5. **No Cross-Service Distributed Transactions**:
   - Membership mutations are durably persisted in Messaging's persistence store before being acknowledged as successful.
   - No two-phase commit (2PC) or global locks are introduced.
6. **Domain Outbox Pattern for Asynchronous Events**:
   - Membership mutations (participant joined, participant left, participant removed) produce transactional outbox/domain event records within Messaging to allow downstream push notification or audit pipelines to consume them reliably without dual-write inconsistency.
7. **Zero Plaintext & Zero Crypto Key Exposure (ADR-008)**:
   - Conversation metadata stores titles, timestamps, roles, and status. It never stores encryption keys, ratchet parameters, or decrypted message content.
8. **Gateway Integration Boundary**:
   - Activates the real HTTP REST proxy routes in the Gateway (`POST /api/v1/conversations`, `GET /api/v1/conversations`, `GET /api/v1/conversations/:id`, `POST /api/v1/conversations/:id/participants`, `DELETE /api/v1/conversations/:id/participants/:userId`, `POST /api/v1/conversations/:id/leave`), transitioning them from protected HTTP 501 stubs to live proxies calling `IMessagingClient`.

---

## 2. Dependency Graph & Ticket Decomposition

```text
               MSG-001 (Service Foundation & Worker Pools)
               MSG-002 (API Contracts, Caller Context & Error Mappers)
                                    │
                                    ▼
                               MSG-003-T01
                (Conversation Domain Model, Value Objects &
                       Lifecycle State Machine)
                                    │
                                    ▼
                               MSG-003-T02
                 (Conversation & Membership Repository Interfaces
                    & In-Memory / ScyllaDB Driver Stubs)
                                    │
                                    ▼
                               MSG-003-T03
                 (Conversation Authorization Engine & Granular
                         Role Evaluation Service)
                                    │
                                    ▼
                               MSG-003-T04
                (Conversation Domain Service & Membership Manager
                      with Idempotency & Outbox Events)
                                    │
                                    ▼
                               MSG-003-T05
                 (MessagingServiceImpl RPC Handler Binding &
                     Gateway HTTP REST Route Activation)
                                    │
                                    ▼
                               MSG-003-T06
                 (Conversation & Membership Integration Suite,
                    E2E Gateway Testing & Failure Verification)
```

---

## 3. Implementation Tickets

### MSG-003-T01 — Conversation Domain Model, Value Objects & Lifecycle State Machine

1. **Ticket ID**: `MSG-003-T01`
2. **Title**: Conversation Domain Model, Value Objects, Participant Roles & State Machine
3. **Objective**: Implement the strongly-typed domain model entities, value objects, and lifecycle state machines for conversations and membership in `src/messaging/domain/`.
4. **Architectural Purpose**: Establishes the authoritative in-memory representation of conversations and membership, completely decoupled from storage schemas or protobuf transport types, enforcing DDD (Domain-Driven Design) integrity.
5. **Scope**:
   - In `src/messaging/domain/`:
     - **Value Objects**:
       - `ConversationId`: Strongly-typed UUIDv7 wrapper with RFC 4122 validation.
       - `UserId`: Opaque user identifier value object.
       - `DirectPair`: Canonical lexicographical pair `(user_a_id, user_b_id)` ensuring `user_a_id < user_b_id`.
     - **Enums**:
       - `ConversationType`: `Direct`, `Group`.
       - `GroupStatus`: `Active`, `Closed`.
       - `MembershipStatus`: `Active`, `Left`, `Removed`.
       - `ParticipantRole`: `Member`, `Admin`.
     - **Entities**:
       - `ConversationEntity`: `conversation_id`, `type`, `created_by_user_id`, `created_at`, `version`.
       - `GroupMetadataEntity`: `conversation_id`, `title`, `status`, `created_at`, `updated_at`, `version`.
       - `ConversationParticipantEntity`: `conversation_id`, `user_id`, `role`, `status`, `joined_at`, `left_at`, `version`.
     - **Lifecycle State Machine**:
       - `ConversationLifecycleManager`: Implements transition logic:
         - Direct conversations cannot be closed (they simply exist).
         - Group conversations transition `Active` $\to$ `Closed`. Once `Closed`, no further mutations or message insertions are valid.
         - Participant status transitions: `Active` $\to$ `Left`, `Active` $\to$ `Removed`. Rejoining transitions `Left`/`Removed` $\to$ `Active`.
   - Add unit test suite in `tests/unit/messaging/conversation_domain_test.cpp`.
6. **Explicit Out-of-Scope**: Persistence I/O, database drivers, network serialization.
7. **Dependencies**: `MSG-002-T01` (Protobuf enums), `securecloud::common`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/conversation_types.hpp`
   - `src/messaging/domain/conversation_entity.hpp`
   - `src/messaging/domain/conversation_participant_entity.hpp`
   - `src/messaging/domain/conversation_lifecycle.hpp`
   - `src/messaging/domain/conversation_lifecycle.cpp`
   - `tests/unit/messaging/conversation_domain_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-003-T02 — Conversation & Membership Repository Interfaces & Storage Abstraction

1. **Ticket ID**: `MSG-003-T02`
2. **Title**: Conversation & Membership Repository Contract Interfaces and Query Model
3. **Objective**: Define the abstract repository contracts for conversation metadata, direct user pair mappings, membership rosters, and user conversation inboxes, conforming to ScyllaDB denormalization patterns.
4. **Architectural Purpose**: Preserves strict separation between domain business logic and database persistence (ADR-005), enabling unit testing via in-memory mock repositories and production execution via ScyllaDB persistence.
5. **Scope**:
   - In `src/messaging/repository/`:
     - Define `IConversationRepository`:
       - `create_conversation(const ConversationEntity& conv)`
       - `find_by_id(const ConversationId& id) -> std::optional<ConversationEntity>`
       - `find_direct_pair(const UserId& user_a, const UserId& user_b) -> std::optional<ConversationId>`
       - `save_direct_pair(const UserId& user_a, const UserId& user_b, const ConversationId& id)`
       - `update_group_metadata(const GroupMetadataEntity& meta)`
       - `get_group_metadata(const ConversationId& id) -> std::optional<GroupMetadataEntity>`
     - Define `IMembershipRepository`:
       - `add_participant(const ConversationParticipantEntity& participant)`
       - `update_participant_status(const ConversationId& conv_id, const UserId& user_id, MembershipStatus status, ParticipantRole role)`
       - `get_participant(const ConversationId& conv_id, const UserId& user_id) -> std::optional<ConversationParticipantEntity>`
       - `list_active_participants(const ConversationId& conv_id) -> std::vector<ConversationParticipantEntity>`
       - `list_conversations_for_user(const UserId& user_id, int limit, std::string_view cursor) -> UserConversationsPage`
     - Implement `InMemoryConversationRepository` and `InMemoryMembershipRepository` for hermetic testing and early integration.
   - Add unit test suite in `tests/unit/messaging/conversation_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Writing CQL ScyllaDB C++ driver bindings (formalized in MSG-004).
7. **Dependencies**: `MSG-003-T01`.
8. **Files to Create/Modify**:
   - `src/messaging/repository/conversation_repository_interface.hpp`
   - `src/messaging/repository/membership_repository_interface.hpp`
   - `src/messaging/repository/in_memory_conversation_repository.hpp`
   - `src/messaging/repository/in_memory_conversation_repository.cpp`
   - `src/messaging/repository/in_memory_membership_repository.hpp`
   - `src/messaging/repository/in_memory_membership_repository.cpp`
   - `tests/unit/messaging/conversation_repository_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-003-T03 — Conversation Authorization Engine & Granular Role Evaluator

1. **Ticket ID**: `MSG-003-T03`
2. **Title**: Conversation Authorization Engine, Membership Boundaries & Role Policy Evaluator
3. **Objective**: Implement the authoritative resource-level authorization engine that evaluates whether a requesting caller (`MessagingCallerContext`) has permission to perform operations on a conversation.
4. **Architectural Purpose**: Enforces the security boundary that Gateway establishes *who* the caller is, while Messaging authoritatively establishes *what* the caller can do within a specific conversation.
5. **Scope**:
   - In `src/messaging/service/conversation_authorization_service.hpp|cpp`:
     - Implement `ConversationAuthorizationService`:
       - `can_view_conversation(caller, conv_id) -> Result<void>`:
         - Verifies caller is an `ACTIVE` participant.
       - `can_send_message(caller, conv_id) -> Result<void>`:
         - Verifies caller is an `ACTIVE` participant and conversation status is `ACTIVE` (not `CLOSED`).
       - `can_add_participant(caller, conv_id) -> Result<void>`:
         - Rejects on direct conversations (direct conversations cannot have members added).
         - For group conversations: verifies group is `ACTIVE` and caller role is `ADMIN`.
       - `can_remove_participant(caller, conv_id, target_user_id) -> Result<void>`:
         - Rejects on direct conversations.
         - For group: verifies group is `ACTIVE`, caller role is `ADMIN` (or admin removing non-admin/admin).
       - `can_leave_conversation(caller, conv_id) -> Result<void>`:
         - Rejects on direct conversations.
         - For group: allows any active member to leave. If the last remaining `ADMIN` leaves and other members remain, validates admin succession rules or flags conversation for admin delegation.
       - `can_update_metadata(caller, conv_id) -> Result<void>`:
         - Verifies group is `ACTIVE` and caller is `ADMIN`.
   - Add unit test suite in `tests/unit/messaging/conversation_authorization_service_test.cpp` verifying normal and unauthorized edge cases.
6. **Explicit Out-of-Scope**: Gateway JWT validation (already performed at edge).
7. **Dependencies**: `MSG-003-T01`, `MSG-003-T02`, `MSG-002-T02` (`MessagingCallerContext`).
8. **Files to Create/Modify**:
   - `src/messaging/service/conversation_authorization_service.hpp`
   - `src/messaging/service/conversation_authorization_service.cpp`
   - `tests/unit/messaging/conversation_authorization_service_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-003-T04 — Conversation Domain Service & Membership Manager with Idempotency & Outbox Events

1. **Ticket ID**: `MSG-003-T04`
2. **Title**: Conversation Domain Service, Idempotent Creation & Outbox Domain Event Generation
3. **Objective**: Implement the core domain orchestration service (`ConversationService`) managing conversation lifecycle, participant operations, idempotent duplicate handling, and transactional outbox event production.
4. **Architectural Purpose**: Centralizes all mutating conversation workflows behind a clean domain service boundary, ensuring atomic state updates, duplicate request safety, and event notifications.
5. **Scope**:
   - In `src/messaging/service/conversation_service.hpp|cpp`:
     - Implement `ConversationService`:
       - `create_direct_conversation(caller, recipient_user_id) -> Result<ConversationEntity>`:
         - Canonical ordering check: `DirectPair(caller.user_id(), recipient_user_id)`.
         - If exists, return existing `ConversationId` idempotently.
         - If not, create `ConversationEntity` + two `ConversationParticipantEntity` (`MEMBER`) + store direct pair + produce `ConversationCreatedEvent`.
       - `create_group_conversation(caller, title, initial_participant_user_ids) -> Result<ConversationEntity>`:
         - Generates canonical `ConversationId`.
         - Adds caller as `ADMIN`.
         - Adds initial participants as `MEMBER`.
         - Stores group metadata (`ACTIVE`).
         - Produces `ConversationCreatedEvent` and `ParticipantJoinedEvent`.
       - `add_participant(caller, conv_id, user_id) -> Result<void>`:
         - Evaluates `can_add_participant`.
         - Checks idempotency: if user is already `ACTIVE`, returns success.
         - Adds participant with role `MEMBER` + produces `ParticipantJoinedEvent`.
       - `remove_participant(caller, conv_id, user_id) -> Result<void>`:
         - Evaluates `can_remove_participant`.
         - Sets status `REMOVED` + records `left_at` + produces `ParticipantRemovedEvent`.
       - `leave_conversation(caller, conv_id) -> Result<void>`:
         - Evaluates `can_leave_conversation`.
         - Sets status `LEFT` + records `left_at` + produces `ParticipantLeftEvent`.
       - `update_group_metadata(caller, conv_id, title) -> Result<GroupMetadataEntity>`:
         - Evaluates `can_update_metadata`.
         - Updates title and bumps version.
     - Outbox Event Structure:
       - `ConversationOutboxEvent`: `event_id`, `conversation_id`, `event_type`, `payload_json`, `created_at`.
       - Stored transactionally to support reliable downstream notifications without dual-writes.
   - Add unit test suite in `tests/unit/messaging/conversation_service_test.cpp`.
6. **Explicit Out-of-Scope**: External message brokers (Kafka/RabbitMQ).
7. **Dependencies**: `MSG-003-T01`, `MSG-003-T02`, `MSG-003-T03`.
8. **Files to Create/Modify**:
   - `src/messaging/service/conversation_service.hpp`
   - `src/messaging/service/conversation_service.cpp`
   - `src/messaging/domain/outbox_event.hpp`
   - `tests/unit/messaging/conversation_service_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-003-T05 — MessagingServiceImpl RPC Handler Binding & Gateway HTTP Route Activation

1. **Ticket ID**: `MSG-003-T05`
2. **Title**: gRPC Service Implementation Binding & Gateway HTTP Proxy Handler Route Activation
3. **Objective**: Wire `ConversationService` into `MessagingServiceImpl` gRPC handlers for all conversation RPCs, and activate the Gateway HTTP proxy handlers replacing HTTP 501 stubs.
4. **Architectural Purpose**: Connects the end-to-end stack from external HTTP clients through the Gateway down to the Messaging gRPC service for all conversation operations.
5. **Scope**:
   - In `src/messaging/service/messaging_service_impl.cpp`:
     - Bind `CreateConversation`: Delegates to `ConversationService::create_direct_conversation` or `create_group_conversation`.
     - Bind `GetConversation`: Retrieves metadata and active participant user IDs.
     - Bind `ListConversations`: Queries paginated user conversations.
     - Bind `AddParticipant`: Invokes `ConversationService::add_participant`.
     - Bind `RemoveParticipant`: Invokes `ConversationService::remove_participant`.
     - Bind `LeaveConversation`: Invokes `ConversationService::leave_conversation`.
     - Bind `UpdateConversationMetadata`: Invokes `ConversationService::update_group_metadata`.
     - Uses `MessagingCallerContext` and `MessagingErrorMapper` for context extraction and error mapping.
   - In `src/gateway/http/routing/gateway_route_registrar.cpp`:
     - Replace stubs with live handlers calling `IMessagingClient`:
       - `POST /api/v1/conversations`: Maps JSON to `CreateConversationRequest` and forwards.
       - `GET /api/v1/conversations/:id`: Maps path parameter to `GetConversationRequest`.
       - `GET /api/v1/conversations`: (Replaces `/api/v1/messages/conversations` stub) Maps to `ListConversationsRequest`.
       - `POST /api/v1/conversations/:id/participants`: Maps to `AddParticipantRequest`.
       - `DELETE /api/v1/conversations/:id/participants/:userId`: Maps to `RemoveParticipantRequest`.
       - `POST /api/v1/conversations/:id/leave`: Maps to `LeaveConversationRequest`.
       - `PATCH /api/v1/conversations/:id/metadata`: Maps to `UpdateConversationMetadataRequest`.
   - Add unit tests for Gateway conversation routing in `tests/unit/gateway/gateway_conversation_routing_test.cpp`.
6. **Explicit Out-of-Scope**: Activating `/api/v1/messages/send` or `/api/v1/messages/inbox` (deferred to MSG-005/MSG-009).
7. **Dependencies**: `MSG-003-T04`, `MSG-002-T05` (`IMessagingClient`).
8. **Files to Create/Modify**:
   - `src/messaging/service/messaging_service_impl.hpp`
   - `src/messaging/service/messaging_service_impl.cpp`
   - `src/gateway/http/routing/gateway_route_registrar.cpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.hpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.cpp`
   - `tests/unit/gateway/gateway_conversation_routing_test.cpp`
   - `src/gateway/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-003-T06 — End-to-End Conversation Integration Suite & Authorization Failure Testing

1. **Ticket ID**: `MSG-003-T06`
2. **Title**: Comprehensive Conversation Integration Suite, Multi-Device Roster Verification & Load Safety
3. **Objective**: Validate the full end-to-end conversation and membership flows across mTLS client-server channels and Gateway HTTP endpoints under normal and hostile authorization failure scenarios.
4. **Architectural Purpose**: Ensures that conversation creation, direct pair deduplication, admin-only controls, voluntary exit, and multi-device logical separation are certified with zero regressions.
5. **Scope**:
   - Create `tests/integration/messaging_conversation_integration_test.cpp`:
     - **Test Case 1: Direct Conversation Idempotency & Reuse**:
       - User A creates direct conversation with User B $\to$ receives `ConvId_1`.
       - User B creates direct conversation with User A $\to$ receives `ConvId_1` (idempotent match).
       - Adding a 3rd participant to direct conversation is rejected (`FAILED_PRECONDITION`).
     - **Test Case 2: Group Conversation Lifecycle & Admin Hierarchy**:
       - Admin creates group "Alpha" with Members B, C.
       - Non-admin Member B attempts to add Member D $\to$ rejected (`PERMISSION_DENIED`).
       - Admin adds Member D $\to$ succeeds; roster includes A, B, C, D.
       - Admin removes Member C $\to$ succeeds; Member C status becomes `REMOVED`.
       - Member C attempts to query conversation $\to$ rejected (`PERMISSION_DENIED`).
     - **Test Case 3: Voluntary Participant Exit (`LeaveConversation`)**:
       - Member D voluntarily leaves conversation $\to$ succeeds; status becomes `LEFT`.
     - **Test Case 4: Group Close & Mutation Lockout**:
       - Admin closes group conversation $\to$ status transitions to `CLOSED`.
       - Any subsequent `AddParticipant` or metadata update is rejected (`FAILED_PRECONDITION`).
     - **Test Case 5: Multi-Device Participant Invariance**:
       - Validates that participants in a conversation roster represent unique logical `UserId`s regardless of how many devices are registered to each user in Auth.
     - **Test Case 6: Gateway HTTP Proxy End-to-End**:
       - Client sends HTTPS `POST /api/v1/conversations` with JWT Bearer token $\to$ Gateway proxies through `MessagingServiceClient` over mTLS $\to$ returns HTTP 201 Created.
   - Run complete regression suite across all 1,344+ tests with `python3 scripts/verify-local.py --preset dev-debug`.
6. **Explicit Out-of-Scope**: Testing ScyllaDB cluster partition failovers (MSG-004/MSG-012).
7. **Dependencies**: `MSG-003-T01` through `MSG-003-T05`.
8. **Files to Create/Modify**:
   - `tests/integration/messaging_conversation_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`
   - `specs/phase2/MSG-003-tickets.md`

---

## 4. Acceptance Criteria & Card Validation Matrix

| Criterion | Target Specification | Validation Mechanism |
| :--- | :--- | :--- |
| **Conversation Domain Modeling** | `ConversationEntity`, `GroupMetadataEntity`, `ConversationParticipantEntity` formalize domain | `tests/unit/messaging/conversation_domain_test.cpp` |
| **Direct Conversation Uniqueness** | Lexicographical direct pair canonicalization ensures idempotent direct conversation reuse | `tests/integration/messaging_conversation_integration_test.cpp` |
| **Group Lifecycle & State Transitions** | `ACTIVE` $\to$ `CLOSED` lifecycle state machine strictly enforced | `tests/unit/messaging/conversation_domain_test.cpp` |
| **Authoritative Authorization** | Granular admin checks for add/remove/close; member check for viewing | `tests/unit/messaging/conversation_authorization_service_test.cpp` |
| **Voluntary Exit Support** | `LeaveConversation` permits self-removal without admin privileges | `tests/integration/messaging_conversation_integration_test.cpp` |
| **Logical Participant Multi-Device Separation** | Roster models logical `UserId`s; per-device targeting is decoupled | Domain model audit & unit tests |
| **Outbox Domain Events** | Participant joined/left/removed produces transactional outbox events | `tests/unit/messaging/conversation_service_test.cpp` |
| **Gateway HTTP Route Activation** | `/api/v1/conversations` routes transition from 501 stubs to live proxies | `tests/unit/gateway/gateway_conversation_routing_test.cpp` |
| **Zero Service Boundary Leaks** | Messaging does not access Auth or Gateway databases (ADR-005) | Architecture & code review audit |
| **Clean Compilation & Build** | Compiles with zero warnings on AppleClang, GCC, MSVC with `-Werror` | `verify-local.py` & CI |
| **Zero Regressions** | 100% pass rate across cumulative test suite (>= 1,344 tests) | `ctest --preset dev-debug` |

---

## 5. Architectural Invariants & Verification Checklist

- [x] **Authoritative Conversation Ownership**: Messaging exclusively manages conversation and participant state without external database joins.
- [x] **Logical Participant Invariant**: Membership represents `UserId`; device expansion is strictly deferred to downstream message delivery.
- [x] **Direct Conversation Pair Invariant**: Alice + Bob and Bob + Alice resolve deterministically to the same direct conversation UUID.
- [x] **No Direct Conversation Member Additions**: Attempts to add members to a direct conversation are rejected with `FAILED_PRECONDITION`.
- [x] **Admin Privilege Enforced**: Only participants with role `ADMIN` may add/remove participants or close group conversations.
- [x] **Closed Group Invariant**: Closed group conversations reject membership mutations and freeze roster state.
- [x] **Transactional Outbox Maintained**: State mutations write outbox events for downstream notification and audit integration.
- [x] **Gateway Stubs Replaced Cleanly**: Gateway conversation routes delegate to `IMessagingClient` with bulkhead protection.
- [x] **No Plaintext or Crypto Keys in Conversation Domain**: Conversation entities contain zero cryptographic session material.
