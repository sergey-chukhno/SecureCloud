# AUTH-004 — Implement Device-Specific Session Management & Lifecycle
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-004  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Technical Specification  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Sergey  
**Date**: 2026-10-06  

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-004** implements durable, device-specific application session management for the SecureCloud Auth service. It builds directly upon the primary authentication pipeline delivered in **AUTH-003**, managing the complete lifecycle of authenticated sessions across creation, validation, activity tracking, sliding window touches, expiration evaluation, and revocation.

### Core Session Lifecycle & Device Association Pipeline

```text
       Client / Gateway Request (session_id, [device_id], [reason])
                                     │
                                     ▼
        ┌─────────────────────────────────────────────────────────┐
        │ 1. gRPC Boundary & Request Validator                    │
        │    (ValidateSession / RevokeSession RPCs)               │
        │    - Validates UUID syntax (UUIDv7 canonical format)    │
        │    - Validates string length & control character safety │
        └────────────────────────────┬────────────────────────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
       [ValidateSession Request]           [RevokeSession Request]
                     │                               │
                     ▼                               ▼
        ┌─────────────────────────┐     ┌─────────────────────────┐
        │ 2. Session Validation   │     │ 3. Session Revocation   │
        │    (SessionManager)     │     │    (SessionManager)     │
        └────────────┬────────────┘     └────────────┬────────────┘
                     │                               │
       ┌─────────────┴─────────────┐                 │
       ▼                           ▼                 ▼
[Query Session via]        [State Check]    ┌─────────────────────────┐
[SessionRepository]        - Active         │ Atomic Status Update    │
                           - Revoked        │ - Single session        │
                           - Expired        │ - Device-wide bulk      │
                                            │ - User-wide bulk        │
                                            └────────────┬────────────┘
                                                         │
                     ┌───────────────────────────────────┘
                     ▼
        ┌─────────────────────────┐
        │ 4. Audit Event Pipeline │ (auth.session.revoked /
        │    (AuditEventPublisher)│  auth.session.expired_attempt /
        └────────────┬────────────┘  auth.session.revoked_attempt)
                     │
                     ▼
        ┌─────────────────────────┐
        │ 5. Response Formatter   │
        │    (gRPC Wire Payload)  │
        └─────────────────────────┘
```

### Key Invariants & Architectural Boundaries

1. **Strict Device Association (Data Model Section 2.9, ADR-005)**:
   - Every session is immutably bound to an opaque `user_id` and an opaque `device_id`.
   - A session cannot be transferred or reassigned across devices or users.
   - If a caller presents a session with an mismatched claimed device ID, validation immediately fails.
2. **Durability Across Service Restarts (Acceptance Criteria 2 & 5)**:
   - Session state is persisted to PostgreSQL 17 (`sessions` table) with immediate transactional durability.
   - If the Auth service crashes, restarts, or scales horizontally, all active, revoked, and expired session states remain identical and queryable.
3. **Deterministic Lifecycle Progression (`ACTIVE` $\to$ `REVOKED` / `EXPIRED`)**:
   - `ACTIVE`: Session is valid, within its 24-hour expiration window, and bound to an active device.
   - `REVOKED`: Explicitly terminated (user logout, security revocation, device revocation). Irreversible.
   - `EXPIRED`: Wall-clock time has exceeded `expires_at` timestamp. Irreversible.
   - Revoked sessions **NEVER** authenticate subsequent requests (`ValidateSession` returns `is_valid = false`).
   - Expired sessions are strictly rejected (`ValidateSession` returns `is_valid = false`).
4. **Concurrent-Session Handling & Race-Condition Safety (Acceptance Criteria 6 & 7)**:
   - Multiple concurrent sessions per device/user are supported and isolated.
   - Concurrent validations, touches, and revocations against the same session execute deterministically using atomic conditional SQL (`WHERE session_id = $1 AND session_status = 'Active'`).
   - If thread A revokes a session while thread B validates it, the outcome is strictly linearizable.
5. **Fail-Safe Security Telemetry (SOC 2 CC6.8, ISO 27001 A.8.5)**:
   - Session revocations and unauthorized access attempts against revoked or expired sessions produce structured security audit records (`noexcept` non-blocking guarantee).
6. **Explicit Out-of-Scope for AUTH-004**:
   - E2E cryptographic sessions / Signal Protocol Double Ratchet sessions (owned by Messaging Service).
   - Refresh-token rotation and issuance (owned by **AUTH-005**).
   - Multi-Factor Authentication step-up (owned by **AUTH-006**).
   - Device enrollment and prekey publication (owned by **AUTH-007** / Device Registration).

---

## 2. Dependency Graph

```text
               AUTH-003 (Primary Credential Authentication)
               ├── Domain Credentials & UUIDv7 Infrastructure
               ├── ISessionRepository & PostgresSessionRepository
               ├── IDeviceRepository & PostgresDeviceRepository
               └── IAuditEventPublisher & AuditEvent
                            │
                            ▼
                       AUTH-004-T01
         (Session Lifecycle Domain Model & State Machine)
                            │
                            ▼
                       AUTH-004-T02
      (Enhanced PostgreSQL Session Repository & Atomic Ops)
                            │
                            ▼
                       AUTH-004-T03
        (Session Validation & Device Association Engine)
                            │
                            ▼
                       AUTH-004-T04
     (Session Revocation Engine & Concurrency Control)
                            │
                            ▼
                       AUTH-004-T05
        (Security Audit Telemetry for Session Lifecycle)
                            │
                            ▼
                       AUTH-004-T06
       (gRPC ValidateSession/RevokeSession & E2E Tests)
```

---

## 3. Implementation Tickets

### AUTH-004-T01 — Session Lifecycle Domain Model, State Machine & Result Types

1. **Ticket ID**: `AUTH-004-T01`
2. **Title**: Session Lifecycle Domain Model, State Machine & Result Types
3. **Objective**: Formalize the session lifecycle state machine, define state transition rules, and create strongly-typed domain result models for session validation and revocation.
4. **Architectural Purpose**: Enforces type-safe domain invariants ensuring that session lifecycle transitions (`Active` $\to$ `Revoked`, `Active` $\to$ `Expired`) are monotonic and that validation/revocation operations return rich, diagnostic-safe result structures.
5. **Scope**:
   - Create `src/auth/domain/session_result.hpp`:
     - Define `SessionValidationStatus`: `Valid`, `NotFound`, `Revoked`, `Expired`, `DeviceMismatch`, `DeviceRevoked`, `InternalError`.
     - Define `SessionValidationResult`:
       - `SessionValidationStatus status;`
       - `std::optional<SessionEntity> session;`
       - `std::string diagnostic_message;`
       - Helper methods: `is_valid()`, `valid(session)`, `not_found()`, `revoked()`, `expired()`, `device_mismatch()`, `device_revoked()`, `internal_error()`.
     - Define `SessionRevocationStatus`: `Success`, `NotFound`, `AlreadyRevoked`, `InternalError`.
     - Define `SessionRevocationResult`:
       - `SessionRevocationStatus status;`
       - `uint64_t revoked_count;`
       - `std::string diagnostic_message;`
       - Helper methods: `success(count)`, `not_found()`, `already_revoked()`, `internal_error()`.
   - Update `src/auth/domain/enums.hpp`:
     - Validate `SessionStatus` enum: `Active`, `Revoked`, `Expired`.
     - Add `is_terminal(SessionStatus)` helper (`Revoked` and `Expired` are terminal states).
     - Add `can_transition(SessionStatus from, SessionStatus to)` predicate.
   - Comprehensive unit test suite in `tests/unit/auth/session_lifecycle_test.cpp`:
     - Test valid and invalid status transitions.
     - Test all `SessionValidationResult` factory methods and invariant checks.
     - Test all `SessionRevocationResult` factory methods.
6. **Explicit Out-of-Scope**: Database SQL queries; network RPC handlers.
7. **Dependencies**: `securecloud::auth::domain` (`entities.hpp`, `enums.hpp`, `uuid.hpp`). Downstream: `AUTH-004-T02`.
8. **Exact Repository Starting Point**: `src/auth/domain/`.
9. **Files to Create / Modify**:
   - `src/auth/domain/session_result.hpp` (create)
   - `src/auth/domain/enums.hpp` (modify)
   - `tests/unit/auth/session_lifecycle_test.cpp` (create)
   - `tests/unit/CMakeLists.txt` (modify)
10. **Acceptance Criteria**:
    - Full coverage of `SessionStatus` state transition invariants.
    - Zero dynamic allocations in status evaluation; thread-safe value semantics.
    - 10 unit tests passing cleanly in `session_lifecycle_test.cpp`.

---

### AUTH-004-T02 — Enhanced PostgreSQL Session Repository Queries & Atomic State Transitions

1. **Ticket ID**: `AUTH-004-T02`
2. **Title**: Enhanced PostgreSQL Session Repository Queries & Atomic State Transitions
3. **Objective**: Expand `PostgresSessionRepository` to provide sliding activity window timestamp updates, batch expiration sweeps, and atomic conditional state transitions.
4. **Architectural Purpose**: Guarantees database-level concurrency control and durable persistence across Auth service restarts, utilizing atomic `UPDATE ... WHERE session_status = 'Active'` queries to eliminate race conditions.
5. **Scope**:
   - Update `src/auth/repository/session_repository.hpp`:
     - Add `virtual bool touch_session_activity(const domain::Uuid& session_id, domain::time_point now) = 0;`
     - Add `virtual uint64_t expire_stale_sessions(domain::time_point now) = 0;`
     - Add `virtual bool revoke_session_atomic(const domain::Uuid& session_id, domain::time_point revoked_at) = 0;`
     - Add `virtual uint64_t revoke_all_device_sessions_atomic(const domain::Uuid& device_id, domain::time_point revoked_at) = 0;`
     - Add `virtual uint64_t revoke_all_user_sessions_atomic(const domain::Uuid& user_id, domain::time_point revoked_at) = 0;`
   - Implement in `src/auth/repository/session_repository.cpp`:
     - `touch_session_activity`: Executes `UPDATE sessions SET last_used_at = $1 WHERE session_id = $2 AND session_status = 'Active' AND expires_at > $1;` returning `affected_rows() > 0`.
     - `expire_stale_sessions`: Executes `UPDATE sessions SET session_status = 'Expired' WHERE session_status = 'Active' AND expires_at <= $1;` returning `affected_rows()`.
     - Atomic revocations returning affected counts.
   - Comprehensive unit test suite in `tests/unit/auth/session_repository_test.cpp` (using GMock transactions and result validation).
6. **Explicit Out-of-Scope**: Higher-level service orchestration; audit event production.
7. **Dependencies**: `AUTH-004-T01`, `db::PostgresConnectionPool`, `libpqxx`. Downstream: `AUTH-004-T03`.
8. **Exact Repository Starting Point**: `src/auth/repository/`.
9. **Files to Create / Modify**:
   - `src/auth/repository/session_repository.hpp` (modify)
   - `src/auth/repository/session_repository.cpp` (modify)
   - `tests/unit/auth/session_repository_test.cpp` (create)
   - `tests/unit/CMakeLists.txt` (modify)
10. **Acceptance Criteria**:
    - Atomic SQL statements prevent lost updates and race conditions during concurrent modifications.
    - Accurately tracks `last_used_at` timestamps on active sessions.
    - 10 unit tests passing cleanly in `session_repository_test.cpp`.

---

### AUTH-004-T03 — Session Validation & Device Association Engine

1. **Ticket ID**: `AUTH-004-T03`
2. **Title**: Session Validation & Device Association Engine
3. **Objective**: Implement comprehensive session validation, device association verification, and activity tracking in `SessionManager`.
4. **Architectural Purpose**: Enforces runtime security policy: validating that a requested session is active, has not passed its expiration deadline, is bound to an active registered device, and updating its activity timestamp.
5. **Scope**:
   - Update interface `ISessionManager` in `src/auth/service/session_manager.hpp`:
     - Add `virtual SessionValidationResult validate_session(const domain::Uuid& session_id, std::optional<domain::Uuid> claimed_device_id = std::nullopt) = 0;`
     - Add `virtual std::vector<domain::SessionEntity> list_active_sessions_for_user(const domain::Uuid& user_id) = 0;`
     - Add `virtual std::vector<domain::SessionEntity> list_active_sessions_for_device(const domain::Uuid& device_id) = 0;`
   - Implement in `src/auth/service/session_manager.cpp`:
     - Query session via `session_repo_->find_by_id(session_id)`.
     - Check non-existence $\implies$ `SessionValidationResult::not_found()`.
     - Check `session_status == Revoked` $\implies$ `SessionValidationResult::revoked()`.
     - Check `session_status == Expired` OR `now >= session.expires_at` $\implies$ `SessionValidationResult::expired()`.
     - Check device association: if `claimed_device_id` is supplied, verify `session.device_id == *claimed_device_id` $\implies$ if mismatched, `SessionValidationResult::device_mismatch()`.
     - Verify device status: query `device_repo_->find_by_id(session.device_id)` $\implies$ if device revoked, `SessionValidationResult::device_revoked()`.
     - If valid: touch activity via `session_repo_->touch_session_activity(session_id, now)` and return `SessionValidationResult::valid(session)`.
   - Comprehensive unit test suite in `tests/unit/auth/session_validation_test.cpp`:
     - Valid session succeeds and updates activity timestamp.
     - Unknown session ID returns `NotFound`.
     - Revoked session returns `Revoked`.
     - Expired session returns `Expired`.
     - Claimed device mismatch returns `DeviceMismatch`.
     - Revoked device returns `DeviceRevoked`.
     - Database exceptions caught and return `InternalError` (fail-closed).
6. **Explicit Out-of-Scope**: Session revocation mutation logic (covered in T04); gRPC transport.
7. **Dependencies**: `AUTH-004-T01`, `AUTH-004-T02`, `IDeviceRepository`. Downstream: `AUTH-004-T04`.
8. **Exact Repository Starting Point**: `src/auth/service/`.
9. **Files to Create / Modify**:
   - `src/auth/service/session_manager.hpp` (modify)
   - `src/auth/service/session_manager.cpp` (modify)
   - `tests/unit/auth/session_validation_test.cpp` (create)
   - `tests/unit/CMakeLists.txt` (modify)
10. **Acceptance Criteria**:
    - Valid sessions return valid payload with active device binding.
    - Expired and revoked sessions are deterministically rejected.
    - 10 unit tests passing cleanly in `session_validation_test.cpp`.

---

### AUTH-004-T04 — Session Revocation Engine & Concurrency Control

1. **Ticket ID**: `AUTH-004-T04`
2. **Title**: Session Revocation Engine & Concurrency Control
3. **Objective**: Implement single-session, device-scoped, and user-scoped session revocation with strict determinism and concurrent race safety in `SessionManager`.
4. **Architectural Purpose**: Ensures that access revocation is immediate, durable, and idempotent, preventing race conditions where revoked sessions could temporarily authenticate in concurrent environments.
5. **Scope**:
   - Update interface `ISessionManager` in `src/auth/service/session_manager.hpp`:
     - Add `virtual SessionRevocationResult revoke_session(const domain::Uuid& session_id, std::string_view reason) = 0;`
     - Add `virtual SessionRevocationResult revoke_all_device_sessions(const domain::Uuid& device_id, std::string_view reason) = 0;`
     - Add `virtual SessionRevocationResult revoke_all_user_sessions(const domain::Uuid& user_id, std::string_view reason) = 0;`
   - Implement in `src/auth/service/session_manager.cpp`:
     - Single session revocation: atomicity via `session_repo_->revoke_session_atomic`. If already revoked, operation succeeds idempotently.
     - Device-wide bulk revocation: terminates all active sessions for a stolen or decommissioned device.
     - User-wide bulk revocation: terminates all active sessions across all devices for an account during password change or security lockdown.
     - Multi-threaded concurrency handling: multi-threaded simulated test proving that concurrent validations and revocations against the same session resolve deterministically.
   - Comprehensive unit test suite in `tests/unit/auth/session_revocation_test.cpp`:
     - Revoke active session succeeds.
     - Revoke already revoked session is idempotent.
     - Revoke unknown session returns `NotFound`.
     - Device-wide bulk revocation terminates multiple sessions.
     - User-wide bulk revocation terminates all user sessions.
     - Concurrent validation vs. revocation multi-threaded race simulation.
6. **Explicit Out-of-Scope**: Audit event emission (covered in T05); gRPC layer.
7. **Dependencies**: `AUTH-004-T03`. Downstream: `AUTH-004-T05`.
8. **Exact Repository Starting Point**: `src/auth/service/`.
9. **Files to Create / Modify**:
   - `src/auth/service/session_manager.hpp` (modify)
   - `src/auth/service/session_manager.cpp` (modify)
   - `tests/unit/auth/session_revocation_test.cpp` (create)
   - `tests/unit/CMakeLists.txt` (modify)
10. **Acceptance Criteria**:
    - Revoked sessions are immediately rendered incapable of authenticating.
    - Operations are idempotent and thread-safe.
    - 10 unit tests passing cleanly in `session_revocation_test.cpp`.

---

### AUTH-004-T05 — Security Audit Telemetry for Session Lifecycle

1. **Ticket ID**: `AUTH-004-T05`
2. **Title**: Security Audit Telemetry for Session Lifecycle
3. **Objective**: Expand the security audit event pipeline to record session revocations, expired access attempts, and revoked session reuse attempts.
4. **Architectural Purpose**: Enforces enterprise compliance (SOC 2 CC6.8, ISO 27001 A.8.5) by capturing complete audit trails for security-sensitive session events with zero sensitive data leakage.
5. **Scope**:
   - Update `src/auth/domain/audit_event.hpp`:
     - Add `AuditEventType` entries: `SessionRevoked`, `SessionExpiredAttempt`, `SessionRevokedAttempt`.
     - Update `to_string(AuditEventType)`: `"auth.session.revoked"`, `"auth.session.expired_attempt"`, `"auth.session.revoked_attempt"`.
     - Add factory helper methods:
       - `static AuditEvent session_revoked(const Uuid& session_id, const Uuid& user_id, const Uuid& device_id, std::string_view reason, std::string_view client_ip = "unknown");`
       - `static AuditEvent session_expired_attempt(const Uuid& session_id, std::string_view client_ip = "unknown");`
       - `static AuditEvent session_revoked_attempt(const Uuid& session_id, std::string_view client_ip = "unknown");`
   - Wire audit event publishing inside `SessionManager`:
     - Publish `auth.session.revoked` when a session is revoked.
     - Publish `auth.session.expired_attempt` when an expired session is used.
     - Publish `auth.session.revoked_attempt` when a revoked session is used.
   - Comprehensive unit test suite in `tests/unit/auth/session_audit_test.cpp`:
     - Test JSON serialization of all new session audit event types.
     - Test bit-level string assertions ensuring zero password or secret leakage.
     - Test non-blocking `noexcept` sink error tolerance.
6. **Explicit Out-of-Scope**: Centralized Audit service persistence (consumed asynchronously in later phases).
7. **Dependencies**: `AUTH-004-T04`, `IAuditEventPublisher`. Downstream: `AUTH-004-T06`.
8. **Exact Repository Starting Point**: `src/auth/domain/` and `src/auth/service/`.
9. **Files to Create / Modify**:
   - `src/auth/domain/audit_event.hpp` (modify)
   - `src/auth/service/session_manager.cpp` (modify)
   - `tests/unit/auth/session_audit_test.cpp` (create)
   - `tests/unit/CMakeLists.txt` (modify)
10. **Acceptance Criteria**:
    - Structured JSON audit records emitted for all session state changes.
    - Zero secrets or token values present in raw JSON serialization.
    - 10 unit tests passing cleanly in `session_audit_test.cpp`.

---

### AUTH-004-T06 — gRPC `ValidateSession` & `RevokeSession` RPCs, Main Wiring & E2E Integration Suite

1. **Ticket ID**: `AUTH-004-T06`
2. **Title**: gRPC `ValidateSession` & `RevokeSession` RPCs, Main Wiring & E2E Integration Suite
3. **Objective**: Implement the authoritative gRPC endpoints `ValidateSession` and `RevokeSession` in `AuthServiceImpl`, wire in `src/auth/main.cpp`, and deliver an exhaustive unit and live PostgreSQL 17 integration test suite.
4. **Architectural Purpose**: Exposes session validation and revocation over the mTLS gRPC service boundary and verifies session durability across service restarts and concurrent execution.
5. **Scope**:
   - Update `src/auth/service/auth_service_impl.cpp`:
     - Implement `ValidateSession`:
       - Validate request non-null and syntax: `Uuid::from_string(request->session_id())`.
       - Delegate to `session_manager_->validate_session(session_id)`.
       - If valid: populate `response->set_is_valid(true)`, `user_id`, `device_id`, `authentication_level`, `expires_at_epoch_ms`.
       - If invalid: populate `response->set_is_valid(false)`.
       - Return `grpc::Status::OK`.
     - Implement `RevokeSession`:
       - Validate request non-null and syntax: `Uuid::from_string(request->session_id())`.
       - Delegate to `session_manager_->revoke_session(session_id, request->reason())`.
       - Populate `response->set_revoked(result.is_success())`.
       - Return `grpc::Status::OK`.
   - Update `src/auth/main.cpp`:
     - Ensure `AuthServiceImpl` receives fully-wired `SessionManager`.
   - Comprehensive unit test suite in `tests/unit/auth/auth_service_session_test.cpp` (11 unit tests):
     - `ValidateSession` null pointers return `INVALID_ARGUMENT`.
     - `ValidateSession` invalid UUID returns `INVALID_ARGUMENT`.
     - `ValidateSession` active session returns `is_valid = true` with full response payload.
     - `ValidateSession` expired session returns `is_valid = false`.
     - `ValidateSession` revoked session returns `is_valid = false`.
     - `ValidateSession` unconfigured service returns `UNIMPLEMENTED`.
     - `RevokeSession` null pointers return `INVALID_ARGUMENT`.
     - `RevokeSession` invalid UUID returns `INVALID_ARGUMENT`.
     - `RevokeSession` active session succeeds and returns `revoked = true`.
     - `RevokeSession` unknown session returns appropriate status.
     - `RevokeSession` unconfigured service returns `UNIMPLEMENTED`.
   - Live PostgreSQL 17 integration test suite in `tests/integration/auth_session_integration_test.cpp` (3 tests):
     - `StrictPort5432Protection`: Asserts `PortForbiddenException` on port 5432.
     - `SessionDurabilityAcrossServiceRestart`: Creates session on instance 1, destroys instance 1, starts instance 2 with the same database, validates session remains valid and active.
     - `ConcurrentSessionRevocationAndValidationRace`: Concurrent multi-threaded stress test against live database ensuring deterministic serialization.
6. **Explicit Out-of-Scope**: Access token issuance (`AUTH-005`).
7. **Dependencies**: `AUTH-004-T01` through `AUTH-004-T05`.
8. **Exact Repository Starting Point**: `src/auth/service/`, `tests/unit/auth/`, `tests/integration/`.
9. **Files to Create / Modify**:
   - `src/auth/service/auth_service_impl.cpp` (modify)
   - `src/auth/main.cpp` (modify)
   - `tests/unit/auth/auth_service_session_test.cpp` (create)
   - `tests/unit/CMakeLists.txt` (modify)
   - `tests/integration/auth_session_integration_test.cpp` (create)
   - `tests/integration/CMakeLists.txt` (modify)
10. **Acceptance Criteria**:
    - `ValidateSession` and `RevokeSession` RPCs functional and conforming to `auth.proto`.
    - Sessions survive service restart with zero data corruption.
    - All unit and integration tests passing; verification script `verify-local.py` passing 100%.

---

## 4. Implementation Plan & Sequencing Rules

1. **Strict Dependency Order**:
   - T01 must be completed and tested before T02 and T03.
   - T02 provides enhanced SQL primitives required by T03 and T04.
   - T03 and T04 establish the domain service logic required by T05 and T06.
   - T06 wires the gRPC interface and delivers the live database integration suite.
2. **Quality Gates per Ticket**:
   - Every ticket must contain dedicated unit tests (minimum 10 tests per ticket).
   - Code formatting (`clang-format`) and contract verification must pass before committing each ticket.
   - All commits must follow Conventional Commits format (`feat(auth): ... (AUTH-004-T0X)`).
3. **Database Guard Invariant**:
   - All tests must strictly target containerized PostgreSQL 17 on port 5433. Connecting to host port 5432 is forbidden.

---

## 5. Definition of Done & Acceptance Verification Matrix

| Acceptance Criterion | Enforcing Ticket(s) | Verification Evidence |
| :--- | :--- | :--- |
| **Every session associated with correct opaque device/user identity** | T01, T03, T06 | `SessionValidationResult::device_mismatch()` unit tests and database assertions. |
| **Session state is durable** | T02, T06 | PostgreSQL 17 `sessions` table persistence verified via live integration tests. |
| **Revoked sessions cannot authenticate subsequent requests** | T03, T04, T06 | `ValidateSession` returns `is_valid = false` after revocation. |
| **Expired sessions are rejected** | T02, T03, T06 | `ValidateSession` returns `is_valid = false` when `expires_at <= now()`. |
| **Session state survives Auth restart** | T06 | Integration test `SessionDurabilityAcrossServiceRestart` passes against PostgreSQL 17. |
| **Concurrent session operations behave deterministically** | T02, T04, T06 | Multi-threaded race condition tests pass with atomic conditional SQL. |
| **Tests cover lifecycle and race-sensitive cases** | T01–T06 | Minimum 61 unit tests + 3 integration tests covering all branches. |
