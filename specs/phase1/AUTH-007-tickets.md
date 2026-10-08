# AUTH-007 — Implement Device Lifecycle and Authorization
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-007  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Proposed Implementation-Ready Technical Specification  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Sergey  
**Date**: 2026-10-08  

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-007** implements the end-to-end device lifecycle, enrollment, pairing, authorization, and revocation engine for the SecureCloud zero-trust distributed storage platform.

Building upon primary credential verification (**AUTH-003**), multi-device stateful sessions (**AUTH-004**), asymmetric Ed25519 token lifecycles (**AUTH-005**), and multi-factor authentication with sensitive assurance elevation (**AUTH-006**), this card addresses the critical trust boundary between client hardware endpoints and the SecureCloud core services:

1. **Defense Against Rogue Device Enrollment**:
   - An ordinary valid access token (JWT / Ed25519 compact envelope with `Primary` assurance) **must not be sufficient** to register a new device.
   - Enrolling a new device requires an approved stronger authentication/pairing mechanism:
     - **Direct Registration with MFA Step-Up**: Caller must present `MFA_VERIFIED` assurance (`AuthenticationLevel::MfaVerified` established via TOTP / recovery code in AUTH-006).
     - **Cross-Device Cryptographic Pairing**: An untrusted new device initiates pairing, receiving an ephemeral pairing challenge and short verification code; an already-enrolled trusted device with `MFA_VERIFIED` assurance explicitly approves and authorizes the pending device.
2. **Device State Machine & Persistence**:
   - Devices transition through deterministic lifecycle states: `PendingAuthorization` $\to$ `Active` $\to$ `Revoked`.
   - All state transitions, timestamps, public keys, and revocation reasons are persisted in PostgreSQL 17 (`devices` and `device_public_keys` tables) and survive complete service restarts.
3. **Cascading Device Revocation & Session Severing**:
   - Revoking a device immediately and irreversibly invalidates all current application sessions and refresh tokens tied to that device (`ISessionManager::revoke_all_device_sessions`).
   - The revoked device cannot establish future application sessions; subsequent attempts to call `Authenticate` or `RefreshSession` are rejected with `PERMISSION_DENIED` / `UNAUTHENTICATED`.
4. **Preservation of Local Offline Encrypted Content**:
   - Revocation terminates server-side authorization and future session/prekey distribution; however, the server does not attempt remote destructive wiping of client hardware, ensuring existing offline encrypted ciphertext on the device is not retroactively destroyed.
5. **Zero Private Key Invariant**:
   - The Authentication Service strictly ingests and stores **public cryptographic keys** (Identity Public Key, Signed Prekey, and One-Time Prekeys). No private cryptographic key ever reaches Auth.

---

### Device Lifecycle & Trust Boundary Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                           API Gateway (Perimeter)                           │
 │                                                                             │
 │  Incoming Request (Bearer <Access-Token>)                                   │
 │        │                                                                    │
 │        ▼                                                                    │
 │  LocalTokenVerifier (Offline Ed25519)                                       │
 │  - Extracts claims: user_id, device_id, session_id, authentication_level    │
 │        │                                                                    │
 │        ▼                                                                    │
 │  GatewaySecurityPolicy Evaluator                                            │
 │  - POST /api/v1/devices/register  --> RouteAccess::Sensitive (MFA_VERIFIED) │
 │  - POST /api/v1/devices/authorize --> RouteAccess::Sensitive (MFA_VERIFIED) │
 │  - POST /api/v1/devices/revoke    --> RouteAccess::Sensitive (MFA_VERIFIED) │
 │  - GET  /api/v1/devices           --> RouteAccess::Protected (PRIMARY)      │
 │        │                                                                    │
 │        ├── If Sensitive route and token is PRIMARY_ONLY:                    │
 │        │   └── Rejects with 403 Forbidden ("INSUFFICIENT_ASSURANCE")        │
 │        └── If token satisfies route policy:                                 │
 │            └── Forwards to Auth microservice with metadata:                 │
 │                x-auth-level, x-user-id, x-device-id                         │
 └─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼ (gRPC over mTLS)
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                        Auth Microservice (Authority)                        │
 │                                                                             │
 │  1. Register Device:                                                        │
 │     RegisterDevice(user_id, identity_key, signed_prekey, prekeys)           │
 │     - Enforces MFA_VERIFIED or generates Pending Pairing Challenge          │
 │     - Validates public key formats (strictly 32-byte Ed25519 / X25519)      │
 │     - Stores in PostgreSQL 17: devices & device_public_keys                 │
 │                                                                             │
 │  2. Authorize / Pair Device:                                                │
 │     AuthorizeDevice(device_id, pairing_code)                                │
 │     - Validates caller has MFA_VERIFIED assurance                           │
 │     - Verifies pairing challenge TTL and code match                         │
 │     - Promotes device status: PendingAuthorization -> Active                │
 │     - Emits AuditEvent::DeviceAuthorized                                    │
 │                                                                             │
 │  3. Revoke Device:                                                          │
 │     RevokeDevice(device_id, user_id, reason)                                │
 │     - Validates caller has MFA_VERIFIED assurance                           │
 │     - Sets device status = Revoked in PostgreSQL 17                         │
 │     - Cascades: Revokes all active sessions & refresh tokens for device     │
 │     - Future Authenticate / RefreshSession RPCs for device are rejected     │
 │     - Emits AuditEvent::DeviceRevoked                                       │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Existing Foundations (Reused Without Duplication)

The following database tables, domain entities, and service interfaces already exist in the codebase and will be leveraged directly:

1. **Database Schema & Migrations ([`src/auth/db/migrations/V002__create_auth_tables.sql`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/db/migrations/V002__create_auth_tables.sql))**:
   - `devices` table: `device_id UUID PRIMARY KEY`, `user_id UUID REFERENCES users`, `device_status VARCHAR(32)`, `registered_at`, `revoked_at`, `revocation_reason`, `last_authenticated_at`, `created_at`, `updated_at`.
   - `device_public_keys` table: `key_id UUID PRIMARY KEY`, `device_id UUID REFERENCES devices`, `key_type VARCHAR(64)`, `public_key BYTEA`, `key_status VARCHAR(32)`, `created_at`, `revoked_at`, `replaced_by_key_id`.
   - `sessions` & `refresh_tokens` tables: Foreign key relationships referencing `devices(device_id)` with `ON DELETE RESTRICT`.
2. **Repository Abstractions**:
   - [`IDeviceRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_repository.hpp) & [`PostgresDeviceRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_repository.cpp): Implements `register_device`, `find_by_id`, `list_active_by_user_id`, `revoke_device`, `update_last_authenticated`.
   - [`IDevicePublicKeyRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.hpp) & [`PostgresDevicePublicKeyRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.cpp): Implements `store_public_key`, `find_by_id`, `list_active_keys_by_device_id`, `replace_key`, `revoke_all_device_keys`.
3. **Session Management & Cascading Revocation**:
   - [`ISessionManager::revoke_all_device_sessions`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/session_manager.hpp): Already tested and operational for atomic bulk session revocation and refresh token revocation upon device compromise.
4. **MFA Assurance Verification**:
   - [`AuthServiceImpl::is_caller_mfa_verified`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.hpp): Validates incoming gRPC metadata `x-auth-level` for `MFA_VERIFIED` assurance.
   - [`GatewaySecurityPolicy`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.hpp) & [`AuthorizationMiddleware`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/authorization_middleware.hpp): Perimeter route matching, assurance evaluation, and RFC 7807 problem details generation.

---

## 3. Detailed Ticket Breakdown

### Ticket AUTH-007-T01: Device Domain Models, Lifecycle States & Cryptographic Key Validation

- **Focus**: Core domain models, state definitions, cryptographic public key validation, and database repository extensions.
- **Components to Implement**:
  - Domain Model Enhancements ([`src/auth/domain/enums.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/enums.hpp)):
    - Extend `DeviceStatus` enum:
      - `PendingAuthorization` (`"PendingAuthorization"` / `"PENDING_AUTHORIZATION"`): Registered but awaiting explicit MFA approval / pairing confirmation.
      - `Active` (`"Active"` / `"ACTIVE"`): Authorized and capable of establishing authenticated sessions.
      - `Revoked` (`"Revoked"` / `"REVOKED"`): Permanently deactivated; barred from establishing sessions.
    - Update `parse_enum<DeviceStatus>` and `to_string(DeviceStatus)`.
  - Cryptographic Public Key Validator:
    - Validate Ed25519 Identity Public Key: strictly 32 bytes (`kEd25519PublicKeySize`).
    - Validate X25519 Signed Prekey: strictly 32 bytes (`kX25519KeySize`).
    - Validate Signed Prekey Signature: strictly 64 bytes (`kEd25519SignatureSize`).
    - Validate One-Time Prekeys: collection of 32-byte X25519 keys (bounded to max 100 per registration).
    - **Zero Private Key Invariant**: Explicitly reject any input containing private key markers or invalid buffer lengths.
  - Repository Extensions ([`src/auth/repository/device_repository.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_repository.hpp), [`.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_repository.cpp)):
    - Add `list_all_by_user_id(user_id, include_revoked, tx)`: Enables listing active and optionally revoked devices for user management dashboards.
    - Add `authorize_device(device_id, authorized_at, tx)`: Atomically updates `device_status = 'Active'` where status is `PendingAuthorization`.
- **Testing**:
  - Unit tests in `tests/unit/auth/device_domain_test.cpp`:
    - Enums serialization and deserialization across all variants.
    - Cryptographic key validation accepting valid 32/64 byte keys and rejecting malformed or oversized keys.
    - Repository tests verifying `list_all_by_user_id` filtering and `authorize_device` state transitions.

---

### Ticket AUTH-007-T02: Device Pairing & Strong Authorization Engine (`DeviceManager`)

- **Focus**: Device orchestration service, pairing challenge lifecycle, and strong authentication enforcement.
- **Components to Implement**:
  - Service Interface [`IDeviceManager`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/device_manager.hpp):
    - `enroll_device(user_id, identity_key, signed_prekey, sig, one_time_prekeys, caller_auth_level) -> DeviceEnrollmentResult`
    - `initiate_device_pairing(user_id, pending_device_id) -> DevicePairingChallenge`
    - `authorize_device(user_id, device_id, pairing_code, caller_auth_level) -> DeviceAuthorizationResult`
    - `get_device(device_id) -> std::optional<DeviceEntity>`
    - `list_user_devices(user_id, include_revoked) -> std::vector<DeviceEntity>`
  - Concrete Implementation `DeviceManager` ([`src/auth/service/device_manager.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/device_manager.cpp)):
    - **Strong Authorization Invariant**:
      - If caller presents `AuthenticationLevel::MfaVerified`, device can be enrolled directly into `DeviceStatus::Active`.
      - If caller presents `AuthenticationLevel::Primary` or is unauthenticated during pairing initiation, device is enrolled strictly into `DeviceStatus::PendingAuthorization`.
      - An ordinary `PrimaryOnly` JWT cannot activate a device without solving the pairing challenge or providing MFA proof.
    - Pairing Challenge Lifecycle:
      - Generates an 8-character alphanumeric pairing PIN / pairing token with 10-minute TTL.
      - Tracks active pairing challenges per user with thread-safe anti-brute-force rate limiting (max 3 failed attempts).
    - Audit Trail Integration:
      - Emits `AuditEvent::device_enrolled`, `AuditEvent::device_pairing_initiated`, `AuditEvent::device_authorized`.
- **Testing**:
  - Unit tests in `tests/unit/auth/device_manager_test.cpp`:
    - Direct enrollment with `MfaVerified` succeeds into `Active`.
    - Enrollment without MFA creates `PendingAuthorization` device.
    - Pairing challenge code generation, verification, and expiration.
    - 3-attempt brute-force lockout on pairing verification.

---

### Ticket AUTH-007-T03: Cascading Device Revocation & Application Session Invalidation

- **Focus**: Atomic device revocation, cascading session invalidation, and blocking revoked endpoints from future authentication.
- **Components to Implement**:
  - Device Revocation Orchestration in `DeviceManager`:
    - `revoke_device(device_id, user_id, reason, caller_auth_level) -> DeviceRevocationResult`
    - Enforces that caller must possess `AuthenticationLevel::MfaVerified` assurance (or administrative override).
    - Transitions `devices.device_status = 'Revoked'`, sets `revoked_at = NOW()`, `revocation_reason`.
    - Invokes `ISessionManager::revoke_all_device_sessions`:
      * Marks all active sessions tied to `device_id` as `SessionStatus::Revoked`.
      * Revokes all active refresh tokens tied to `device_id` in `refresh_tokens`.
    - Invokes `IDevicePublicKeyRepository::revoke_all_device_keys`.
  - Enforcement in Existing Auth Workflows:
    - **Primary Login Invariant** ([`src/auth/service/auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp)):
      - `Authenticate` RPC verifies device status before issuing session.
      - If `devices.device_status == Revoked`, immediately returns gRPC `PERMISSION_DENIED` ("Device has been revoked").
    - **Refresh Token Invariant**:
      - `RefreshSession` RPC verifies associated `device_id`. If revoked, fails with `PERMISSION_DENIED`.
    - **Session Validation Invariant**:
      - `ValidateSession` RPC confirms device is active; revoked device invalidates the session.
  - Preservation of Encrypted Content Invariant:
    - Server terminates credentials, sessions, and future message distribution without executing remote client filesystem wipes.
- **Testing**:
  - Unit tests in `tests/unit/auth/device_revocation_test.cpp`:
    - Revoking device severs all active sessions and refresh tokens.
    - Subsequent `Authenticate` with revoked `device_id` fails with `PERMISSION_DENIED`.
    - Subsequent `RefreshSession` fails with `PERMISSION_DENIED`.
    - Revoking a device without `MfaVerified` assurance fails with `PERMISSION_DENIED`.

---

### Ticket AUTH-007-T04: gRPC Protocol Contracts & Auth Service Implementation

- **Focus**: Protobuf contracts, RPC implementation in `AuthServiceImpl`, and end-to-end gRPC service unit tests.
- **Components to Implement**:
  - Protocol Buffer Contract Updates ([`proto/securecloud/auth/v1/auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto)):
    - Update `DeviceStatus` proto enum to include `DEVICE_STATUS_PENDING_AUTHORIZATION = 3`.
    - Enhance `RegisterDeviceRequest` / `RegisterDeviceResponse`:
      ```protobuf
      message RegisterDeviceRequest {
          string user_id = 1;
          bytes identity_key = 2;
          bytes signed_prekey = 3;
          bytes signed_prekey_signature = 4;
          repeated bytes one_time_prekeys = 5;
          string device_name = 6;
      }
      ```
    - Add `InitiateDevicePairing`:
      ```protobuf
      message InitiateDevicePairingRequest {
          string user_id = 1;
          string device_id = 2;
      }
      message InitiateDevicePairingResponse {
          string pairing_code = 1;
          int64 expires_at_epoch_ms = 2;
      }
      ```
    - Add `AuthorizeDevice`:
      ```protobuf
      message AuthorizeDeviceRequest {
          string user_id = 1;
          string device_id = 2;
          string pairing_code = 3;
      }
      message AuthorizeDeviceResponse {
          bool authorized = 1;
          DeviceStatus status = 2;
          int64 authorized_at_epoch_ms = 3;
      }
      ```
  - Service RPC Implementation ([`src/auth/service/auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp)):
    - Implement `RegisterDevice`: Enforces strong assurance / pairing state; delegates to `DeviceManager`.
    - Implement `InitiateDevicePairing`: Generates pairing PIN; returns expiration.
    - Implement `AuthorizeDevice`: Enforces `MFA_VERIFIED` caller; authorizes device.
    - Implement `GetDevice`: Returns device details and status.
    - Implement `ListUserDevices`: Returns filtered or full list of devices.
    - Update `RevokeDevice`: Dispatches revocation and session invalidation via `DeviceManager`.
- **Testing**:
  - Unit tests in `tests/unit/auth/auth_service_device_test.cpp`:
    - Tests all 6 device RPCs using mock repositories and contexts.
    - Tests assurance validation (`PERMISSION_DENIED` when caller lacks `MFA_VERIFIED`).

---

### Ticket AUTH-007-T05: Gateway Perimeter Integration & Route Security Policy

- **Focus**: API Gateway perimeter authorization policy, route access classification, and offline assurance enforcement.
- **Components to Implement**:
  - Gateway Security Policy ([`src/gateway/http/auth/gateway_security_policy.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.cpp)):
    - Register device perimeter routes:
      * `POST /api/v1/devices/register` $\to$ `RouteAccess::Sensitive` (`min_auth_level = MFA_VERIFIED`).
      * `POST /api/v1/devices/authorize` $\to$ `RouteAccess::Sensitive` (`min_auth_level = MFA_VERIFIED`).
      * `POST /api/v1/devices/revoke` $\to$ `RouteAccess::Sensitive` (`min_auth_level = MFA_VERIFIED`).
      * `GET /api/v1/devices` $\to$ `RouteAccess::Protected` (`min_auth_level = PRIMARY`).
      * `GET /api/v1/devices/:id` $\to$ `RouteAccess::Protected` (`min_auth_level = PRIMARY`).
  - Authorization Middleware Updates ([`src/gateway/http/auth/authorization_middleware.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/authorization_middleware.cpp)):
    - Ensure requests to sensitive device management routes without `is_mfa_verified()` return HTTP 403 Forbidden with problem details (`assurance_error = "INSUFFICIENT_AUTHENTICATION_ASSURANCE"`).
    - Propagate verified caller metadata (`x-auth-level`, `x-user-id`, `x-device-id`) downstream to Auth service.
- **Testing**:
  - Unit tests in `tests/unit/gateway/gateway_device_assurance_policy_test.cpp`:
    - Unauthenticated requests rejected with HTTP 401.
    - Primary-only tokens accessing `POST /api/v1/devices/register` rejected with HTTP 403.
    - Primary-only tokens accessing `POST /api/v1/devices/revoke` rejected with HTTP 403.
    - `MfaVerified` tokens successfully authorized for all device operations.

---

### Ticket AUTH-007-T06: Production Daemon Wiring, Live E2E Integration Suite & Validation Report

- **Focus**: Production wiring in `src/auth/main.cpp`, live integration tests against containerized PostgreSQL 17 on port 5433, and card validation report.
- **Components to Implement**:
  - Production Wiring ([`src/auth/main.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/main.cpp)):
    - Instantiate `DeviceManager` with `PostgresDeviceRepository`, `PostgresDevicePublicKeyRepository`, `SessionManager`, and `AuditEventPublisher`.
    - Wire `device_manager` into `AuthServiceImpl`.
  - Integration Test Suite ([`tests/integration/auth_device_integration_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/auth_device_integration_test.cpp)):
    - Live tests against containerized PostgreSQL 17 on port 5433 (with strict port 5432 preflight protection):
      1. **Strict Port 5432 Protection**: Verifies connection pool immediately throws `PortForbiddenException` on port 5432.
      2. **Registration Rejects Ordinary JWT**: Demonstrates that an ordinary `PrimaryOnly` access token cannot register or activate a device.
      3. **Full Device Enrollment & MFA Authorization E2E**: Registration with `MFA_VERIFIED` token successfully activates device and stores public key directory records.
      4. **Cross-Device Pairing Flow**: Device 2 registers in `PendingAuthorization`; Device 1 (MFA-verified) approves pairing using pairing PIN; Device 2 becomes `Active`.
      5. **Device Listing Active and Revoked**: Lists active devices; includes revoked devices when `include_revoked = true`.
      6. **Cascading Revocation & Session Invalidation**: Revoking device terminates all its active sessions and refresh tokens; future logins from device fail immediately.
      7. **Durability Across Service Restart**: Device status and public keys persist across complete Auth daemon destruction and reconstitution.
      8. **Concurrent Authorization & Revocation**: Optimistic concurrency handles simultaneous approvals and revocations safely.
  - Comprehensive Card Validation Report (`walkthrough-auth-007.md`):
    - Detailed validation report ($\ge 1,000$ lines) covering device cryptographic threat models, zero private key enforcement, cascading session severing, pairing PIN security, and complete test execution evidence.
- **Testing**:
  - Full execution of `ctest -E "Integration"` verifying 0 unit test regressions.
  - Execution of `securecloud_auth_device_integration_test` against PostgreSQL 17 on port 5433.

---

## 4. Work Breakdown & Ticket Sequencing

```text
AUTH-007-T01 (Device Domain Models, Lifecycle States & Cryptographic Key Validation)
     │
     ▼
AUTH-007-T02 (Device Pairing & Strong Authorization Engine - DeviceManager)
     │
     ▼
AUTH-007-T03 (Cascading Device Revocation & Application Session Invalidation)
     │
     ▼
AUTH-007-T04 (gRPC Protocol Contracts & Auth Service Implementation)
     │
     ▼
AUTH-007-T05 (Gateway Perimeter Integration & Route Security Policy)
     │
     ▼
AUTH-007-T06 (Production Wiring, Live E2E Integration Suite & Validation Report)
```

---

## 5. Traceability Matrix against Acceptance Criteria

| Acceptance Criterion | Primary Implementing Ticket(s) | Verification Target |
| :--- | :--- | :--- |
| **A new device cannot register using only an ordinary valid JWT** | AUTH-007-T02, AUTH-007-T04, AUTH-007-T05 | `gateway_device_assurance_policy_test`, `RegistrationRejectsOrdinaryJwt` |
| **Device authorization requires approved stronger authentication/pairing** | AUTH-007-T02, AUTH-007-T04, AUTH-007-T06 | `device_manager_test`, `DevicePairingAndStrongAuthorizationE2E` |
| **Revoked devices cannot establish/use future application sessions** | AUTH-007-T03, AUTH-007-T04, AUTH-007-T06 | `device_revocation_test`, `DeviceRevocationCascadesToSessions` |
| **Device state survives restart** | AUTH-007-T01, AUTH-007-T06 | `auth_device_integration_test` (Durability across restart) |
| **Revocation propagates to security-sensitive authorization decisions** | AUTH-007-T03, AUTH-007-T05 | `gateway_device_assurance_policy_test`, `device_revocation_test` |
| **Existing encrypted content on a revoked device is not retroactively destroyed** | AUTH-007-T03, Architectural Invariants | Architectural verification (Zero remote-wipe code in Auth) |
| **No private device cryptographic key reaches Auth** | AUTH-007-T01, AUTH-007-T04 | `device_domain_test`, Protobuf contract inspection |
| **Tests cover registration, authorization, revocation, replay, and concurrency** | AUTH-007-T01 through AUTH-007-T06 | Unit test suites & `auth_device_integration_test` |

---

## 6. Technical Invariants & Security Defenses

1. **Zero Private Key Invariant**:
   - The platform strictly handles public keys: 32-byte Ed25519 identity signing keys, 32-byte X25519 signed prekeys, 64-byte signatures, and 32-byte one-time prekeys. Private keys reside exclusively in the client's local secure enclave or keychain.
2. **Deterministic Cascading Revocation**:
   - Device revocation is an atomic database transaction that transitions the device to `Revoked`, marks all active sessions as `Revoked`, invalidates all outstanding refresh tokens, and marks active public keys as `Revoked`.
3. **Optimistic Concurrency Control**:
   - Device status updates leverage PostgreSQL atomic row versioning and status guards (`WHERE device_id = $1 AND device_status = 'PendingAuthorization'`), preventing race conditions during concurrent pairing attempts.
4. **Strict Database Port Isolation**:
   - All tests enforce strict preflight isolation: port 5432 throws `PortForbiddenException`; integration tests connect exclusively to containerized PostgreSQL 17 on port 5433.
