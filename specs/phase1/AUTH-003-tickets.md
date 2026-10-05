# AUTH-003 — Implement Primary Credential Authentication & Verification
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-003  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Technical Specification  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Sergey  

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-003** implements primary user credential authentication against Auth-owned storage. It establishes the authoritative credential validation pipeline, cryptographic password hashing via Argon2id, timing-attack defense, security state authorization rules, session establishment, and security audit event production.

### Core Credential Verification Pipeline

```text
       Client AuthenticateRequest (credential_identifier, password, device_id)
                                    │
                                    ▼
                      ┌───────────────────────────┐
                      │ 1. Credential Validator   │  (Format, Length, Character Set)
                      └─────────────┬─────────────┘
                                    │ sanitized credentials
                                    ▼
                      ┌───────────────────────────┐
                      │ 2. CredentialVerifier     │  (User Lookup via UserRepository)
                      └─────────────┬─────────────┘
                                    │
                ┌───────────────────┴───────────────────┐
                ▼                                       ▼
       [User Not Found]                           [User Found]
                │                                       │
     Dummy Argon2id Verify                    Check Account Status
     (Constant-Time Defense)                  (Active vs. Disabled)
                │                                       │
                ▼                                       ▼
     InvalidCredentials                       Argon2id Password Verify
                                              (IPasswordHasher via OpenSSL 3)
                                                        │
                                    ┌───────────────────┴───────────────────┐
                                    ▼                                       ▼
                             [Password Mismatch]                    [Password Valid]
                                    │                                       │
                           InvalidCredentials                         Success(User)
                                                                            │
                                                                            ▼
                                                              ┌───────────────────────────┐
                                                              │ 3. Session Establishment  │ (Device active?
                                                              └─────────────┬─────────────┘  SessionRepository)
                                                                            │
                                                                            ▼
                                                              ┌───────────────────────────┐
                                                              │ 4. Audit Event Production │ (auth.login.succeeded /
                                                              └─────────────┬─────────────┘  auth.login.failed)
                                                                            │
                                                                            ▼
                                                              Client AuthenticateResponse
```

### Key Invariants & Architectural Boundaries
1. **Cryptographic Password Security (ADR-008, Data Model Section 2.4)**:
   - Plaintext passwords are **NEVER** persisted, cached, or emitted to logs, traces, or audit payloads.
   - Password verifiers use **Argon2id** (RFC 9106) with parameters tuned for high memory/time hardness (64 MiB memory, 3 iterations, 1 lane) and 16-byte cryptographically secure random salts.
   - Verification uses constant-time byte comparison (`CRYPTO_memcmp`).
2. **Timing Side-Channel & User Enumeration Resistance**:
   - Authentication must **never** disclose whether an account exists or not.
   - When a requested `credential_identifier` does not exist in the database, `CredentialVerifier` executes a dummy Argon2id verification using a fixed/deterministic dummy verifier so that response latency is computationally indistinguishable from an existing user with an incorrect password.
3. **Fail-Closed Security State Enforcement (ADR-009, Detailed Design 4.21)**:
   - Accounts with `account_status != AccountStatus::Active` (e.g. `Disabled`) fail immediately.
   - Devices with `device_status != DeviceStatus::Active` (e.g. `Revoked`) fail session creation.
4. **Primary Authentication Assurance Level**:
   - Primary credential verification produces sessions with `AuthenticationLevel::PrimaryOnly`.
   - MFA progression to `AuthenticationLevel::MfaVerified` is decoupled and owned by **AUTH-006**.
5. **Durable Session Establishment**:
   - Successful authentication establishes an active `SessionEntity` in PostgreSQL via `ISessionRepository`.
   - Updates the associated device's `last_authenticated_at` timestamp.
6. **Explicit Out-of-Scope for AUTH-003**:
   - Multi-Factor Authentication (MFA / TOTP) verification (owned by **AUTH-006**).
   - Asymmetric Ed25519 JWT access token generation and signing (owned by **AUTH-005**).
   - Refresh token rotation and generation (owned by **AUTH-005**).
   - Client device registration and crypto key directory publication (owned by **AUTH-004**).

---

## 2. Dependency Graph

```text
               AUTH-002 (Auth PostgreSQL Persistence)
               ├── IUserRepository & PostgresUserRepository
               ├── IDeviceRepository & PostgresDeviceRepository
               └── ISessionRepository & PostgresSessionRepository
                           │
                           ▼
                      AUTH-003-T01
            (Argon2id Cryptographic Hasher)
                           │
                           ▼
                      AUTH-003-T02
         (Credential Validation & Sanitized Types)
                           │
                           ▼
                      AUTH-003-T03
           (CredentialVerifier & Security Rules)
                           │
           ┌───────────────┴───────────────┐
           │                               │
           ▼                               ▼
      AUTH-003-T04                    AUTH-003-T05
(Session Establishment Flow)     (Security & Audit Event Sink)
           │                               │
           └───────────────┬───────────────┘
                           │
                           ▼
                      AUTH-003-T06
       (gRPC Authenticate RPC & End-to-End Tests)
```

---

## 3. Implementation Tickets

### AUTH-003-T01 — Cryptographic Argon2id Password Hasher Engine

1. **Ticket ID**: `AUTH-003-T01`
2. **Title**: Cryptographic Argon2id Password Hasher Engine
3. **Objective**: Implement an enterprise-grade C++ password hashing and verification component using OpenSSL 3 native `EVP_KDF` Argon2id, standard PHC string formatting, and timing-attack defense.
4. **Architectural Purpose**: Enforces state-of-the-art password storage security (ADR-008, RFC 9106) with zero plaintext retention, constant-time verification, and dummy hash execution for user enumeration prevention.
5. **Scope**:
   - Define interface `IPasswordHasher` in `src/auth/crypto/password_hasher.hpp`:
     - `virtual std::string hash_password(const common::configuration::SecretString& password) = 0;`
     - `virtual bool verify_password(const common::configuration::SecretString& password, std::string_view stored_verifier) = 0;`
     - `virtual void execute_dummy_verification() = 0;`
   - Implement `OpenSslArgon2idHasher` in `src/auth/crypto/argon2id_hasher.{hpp,cpp}`:
     - Leverages OpenSSL 3 `EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr)`.
     - Standard parameters: Memory cost `m=65536` (64 MiB), Time iterations `t=3`, Parallelism/lanes `p=1`, Salt length 16 bytes (via `RAND_bytes`), Hash length 32 bytes.
     - Formats output according to the standard PHC (Password Hashing Competition) string specification:
       `$argon2id$v=19$m=65536,t=3,p=1$<salt_base64>$<hash_base64>`
     - Parses PHC strings to dynamically extract parameters and compare using `CRYPTO_memcmp`.
     - Pre-initializes a valid dummy verifier at construction for `execute_dummy_verification()`, guaranteeing constant-time behavior when a requested username does not exist.
   - Comprehensive unit tests in `tests/unit/auth/argon2id_hasher_test.cpp`:
     - Verify correct hashing and verification round-trip.
     - Verify rejection of incorrect password.
     - Verify rejection of corrupted/malformed PHC strings.
     - Verify `execute_dummy_verification()` runs with equivalent computational cost without crashing or leaking memory.
6. **Explicit Out-of-Scope**: Database storage; external dependencies beyond OpenSSL 3 `libcrypto`.
7. **Dependencies**: Upstream AUTH-001 (`securecloud::common`), OpenSSL 3 `Crypto`. Downstream AUTH-003-T03.
8. **Exact Repository Starting Point**: `src/auth/crypto/`.
9. **Files to Create**:
   - `src/auth/crypto/password_hasher.hpp`
   - `src/auth/crypto/argon2id_hasher.hpp`
   - `src/auth/crypto/argon2id_hasher.cpp`
   - `tests/unit/auth/argon2id_hasher_test.cpp`
10. **Acceptance Criteria**:
    - Generates standard RFC 9106 PHC Argon2id strings.
    - Constant-time verification passes for valid passwords and fails for invalid passwords.
    - Zero memory leaks under Valgrind/ASan; compiles with `-Wall -Wextra -Werror -Wpedantic`.

---

### AUTH-003-T02 — Credential Validation, Normalization & Sanitized Input Value Types

1. **Ticket ID**: `AUTH-003-T02`
2. **Title**: Credential Validation, Normalization & Sanitized Input Value Types
3. **Objective**: Implement strongly typed domain primitives for credential identifiers and passwords that enforce validation rules, prevent memory retention, and guarantee zero credential logging.
4. **Architectural Purpose**: Prevents injection attacks, malformed authentication attempts, DoS attacks against CPU-intensive hashing algorithms, and inadvertent leakage of credentials into application logs (ADR-008).
5. **Scope**:
   - Implement `CredentialIdentifier` value object in `src/auth/domain/credentials.hpp`:
     - Normalizes input: trims leading/trailing whitespace, validates length [3..255] characters.
     - Validates allowed character set (printable ASCII or email/username characters, disallows ASCII control characters).
     - Explicit conversion or view for database querying.
   - Implement `PasswordCredential` wrapper in `src/auth/domain/credentials.hpp`:
     - Wraps raw password buffer in a secure container that calls `OPENSSL_cleanse` upon destruction.
     - Enforces max password length (e.g. 1024 bytes) to prevent algorithmic complexity DoS against Argon2id.
     - Overloads `operator<<` to emit `"[REDACTED_PASSWORD]"` ensuring passwords never leak to `std::cout`, `std::cerr`, or log formatters.
   - Unit tests in `tests/unit/auth/credentials_test.cpp`:
     - Test valid username/email formatting.
     - Test boundary lengths (too short < 3, too long > 255, excessive password > 1024).
     - Test control character rejection and newline rejection.
     - Test redaction formatting in streams.
6. **Explicit Out-of-Scope**: Database lookups; password policy enforcement (e.g. uppercase/symbol rules belong to registration).
7. **Dependencies**: Upstream AUTH-002 (`src/auth/domain/`). Downstream AUTH-003-T03.
8. **Exact Repository Starting Point**: `src/auth/domain/`.
9. **Files to Create**:
   - `src/auth/domain/credentials.hpp`
   - `tests/unit/auth/credentials_test.cpp`
10. **Acceptance Criteria**:
    - Rejects malformed and excessive input deterministically.
    - Stream output strictly emits redaction placeholders.
    - Memory sanitized via `OPENSSL_cleanse`.

---

### AUTH-003-T03 — Domain CredentialVerifier Component & Account State Rules

1. **Ticket ID**: `AUTH-003-T03`
2. **Title**: Domain CredentialVerifier Component & Account State Rules
3. **Objective**: Implement the core `CredentialVerifier` domain service orchestrating credential normalization, user database lookup, Argon2id verification, account lifecycle state validation, and uniform failure response.
4. **Architectural Purpose**: Enforces the security boundary between client credentials and persistent user accounts, preventing account enumeration via timing equalization and enforcing account lock/disabled policies (Detailed Design 4.20, 4.21).
5. **Scope**:
   - Define authentication result model in `src/auth/domain/auth_result.hpp`:
     - `enum class AuthenticationStatus`: `Success`, `InvalidCredentials`, `AccountDisabled`, `DeviceRevoked`, `DeviceNotFound`, `InternalError`.
     - `struct AuthenticationResult`: Contains status, optional `UserEntity`, failure diagnostic reason (never exposed to external clients).
   - Implement `ICredentialVerifier` and `CredentialVerifier` in `src/auth/service/credential_verifier.{hpp,cpp}`:
     - Injected with `IUserRepository` and `IPasswordHasher`.
     - `AuthenticationResult verify(const CredentialIdentifier& cred_id, const PasswordCredential& password);`
     - Execution steps:
       1. Query `IUserRepository::find_by_credential_identifier(cred_id.value())`.
       2. If user **not found**: call `hasher_->execute_dummy_verification()`, return `AuthenticationStatus::InvalidCredentials`.
       3. If user **found**:
          a. Check `user.account_status`: if `AccountStatus::Disabled`, return `AuthenticationStatus::AccountDisabled`.
          b. Execute `hasher_->verify_password(password, user.password_verifier)`.
          c. If password does not match: return `AuthenticationStatus::InvalidCredentials`.
          d. If valid: return `AuthenticationStatus::Success` with `UserEntity`.
   - Comprehensive unit tests in `tests/unit/auth/credential_verifier_test.cpp`:
     - Test valid credentials return `Success`.
     - Test incorrect password returns `InvalidCredentials`.
     - Test non-existent user returns `InvalidCredentials` and triggers dummy verification.
     - Test disabled account returns `AccountDisabled`.
     - Test database failure returns `InternalError` (fails closed).
6. **Explicit Out-of-Scope**: Session establishment; token generation; gRPC transports.
7. **Dependencies**: Upstream AUTH-003-T01 (`IPasswordHasher`), AUTH-003-T02 (`CredentialIdentifier`), AUTH-002 (`IUserRepository`). Downstream AUTH-003-T04.
8. **Exact Repository Starting Point**: `src/auth/service/`.
9. **Files to Create**:
   - `src/auth/domain/auth_result.hpp`
   - `src/auth/service/credential_verifier.hpp`
   - `src/auth/service/credential_verifier.cpp`
   - `tests/unit/auth/credential_verifier_test.cpp`
10. **Acceptance Criteria**:
    - Zero distinction in return status between missing user and wrong password.
    - Timing equalization verified through dummy hasher invocation.
    - Disabled accounts blocked unconditionally.

---

### AUTH-003-T04 — Session Establishment & Device Association Pipeline

1. **Ticket ID**: `AUTH-003-T04`
2. **Title**: Session Establishment & Device Association Pipeline
3. **Objective**: Implement the session establishment pipeline that validates client device eligibility, constructs a persistent `SessionEntity`, associates it with the authenticated user, and updates device authentication timestamps.
4. **Architectural Purpose**: Transforms successful primary credential verification into a durable, device-bound database session record with `PrimaryOnly` assurance level (ADR-005, Data Model Section 2.9).
5. **Scope**:
   - Implement `SessionManager` in `src/auth/service/session_manager.{hpp,cpp}`:
     - Injected with `ISessionRepository` and `IDeviceRepository`.
     - `struct SessionEstablishmentResult`: `SessionEntity session`, `DeviceEntity device`.
     - `SessionEstablishmentResult establish_session(const domain::UserEntity& user, const domain::Uuid& device_id);`
     - Device verification:
       1. Lookup device via `IDeviceRepository::find_by_id(device_id)`.
       2. Validate device exists and `device.user_id == user.user_id`. If not, throw `DeviceNotFoundException` / return `DeviceNotFound`.
       3. Validate `device.device_status == DeviceStatus::Active`. If `Revoked`, return `DeviceRevoked`.
     - Session creation:
       1. Generate canonical UUIDv7 `session_id`.
       2. Set `authentication_level = AuthenticationLevel::PrimaryOnly`.
       3. Set `created_at = now`, `expires_at = now + session_ttl` (configurable, default 24h), `last_used_at = now`.
       4. Persist via `ISessionRepository::create_session(session)`.
     - Device touch:
       1. Update `last_authenticated_at` via `IDeviceRepository::update_last_authenticated(device_id, now)`.
   - Unit tests in `tests/unit/auth/session_manager_test.cpp`:
     - Test valid device produces active session with `PrimaryOnly` level.
     - Test foreign device (owned by another user) is rejected.
     - Test revoked device is rejected with `DeviceRevoked`.
     - Test non-existent device is rejected.
6. **Explicit Out-of-Scope**: Refresh token generation (AUTH-005); JWT signing (AUTH-005).
7. **Dependencies**: Upstream AUTH-002 (`ISessionRepository`, `IDeviceRepository`), AUTH-003-T03. Downstream AUTH-003-T06.
8. **Exact Repository Starting Point**: `src/auth/service/`.
9. **Files to Create**:
   - `src/auth/service/session_manager.hpp`
   - `src/auth/service/session_manager.cpp`
   - `tests/unit/auth/session_manager_test.cpp`
10. **Acceptance Criteria**:
    - Creates durable session in repository with UUIDv7 ID and `PrimaryOnly` level.
    - Rejects revoked or mismatched devices.
    - Updates device authentication timestamp.

---

### AUTH-003-T05 — Security & Audit Event Production Pipeline

1. **Ticket ID**: `AUTH-003-T05`
2. **Title**: Security & Audit Event Production Pipeline
3. **Objective**: Implement a structured security and audit event publisher for authentication lifecycle events (`auth.login.succeeded`, `auth.login.failed`), guaranteeing strict sanitization of sensitive credential data.
4. **Architectural Purpose**: Fulfills the security compliance requirement to produce immutable, structured audit records for all authentication attempts (ADR-008, Data Model Section 5.8) without leaking passwords.
5. **Scope**:
   - Define canonical audit event records in `src/auth/audit/audit_event.hpp`:
     - `AuditEvent` struct matching `05-audit-data-model.md`: `event_id` (UUIDv7), `occurred_at`, `event_type`, `severity`, `producer_service: "auth"`, `actor_type`, `actor_id`, `target_type`, `target_id`, `event_data` (JSON).
     - Event types: `auth.login.succeeded`, `auth.login.failed`.
   - Implement `IAuditEventPublisher` interface and in-memory test publisher in `src/auth/audit/audit_publisher.{hpp,cpp}`:
     - `virtual void publish(const AuditEvent& event) = 0;`
     - `void publish_login_succeeded(const domain::Uuid& user_id, const domain::Uuid& device_id, const domain::Uuid& session_id);`
     - `void publish_login_failed(std::string_view attempted_identifier, AuthenticationStatus reason, const std::optional<domain::Uuid>& device_id);`
   - Invariant enforcement:
     - Plaintext passwords and password verifiers are **never** present in `event_data`.
     - Sensitive identifiers are sanitized.
   - Unit tests in `tests/unit/auth/audit_publisher_test.cpp`:
     - Test successful login event schema and fields.
     - Test failed login event schema for each failure status.
     - Verify zero credentials in serialized event payloads.
6. **Explicit Out-of-Scope**: ClickHouse storage (owned by Audit service M6); network gRPC transport to Audit daemon.
7. **Dependencies**: Upstream AUTH-001 (`securecloud::json`), AUTH-002 (`Uuid`, `timestamp`). Downstream AUTH-003-T06.
8. **Exact Repository Starting Point**: `src/auth/audit/`.
9. **Files to Create**:
   - `src/auth/audit/audit_event.hpp`
   - `src/auth/audit/audit_publisher.hpp`
   - `src/auth/audit/audit_publisher.cpp`
   - `tests/unit/auth/audit_publisher_test.cpp`
10. **Acceptance Criteria**:
    - Publishes compliant audit events matching Data Model Section 5.8.
    - Zero sensitive credential data present in event payloads.

---

### AUTH-003-T06 — gRPC Authenticate RPC Wiring & End-to-End Integration Suite

1. **Ticket ID**: `AUTH-003-T06`
2. **Title**: gRPC Authenticate RPC Wiring & End-to-End Integration Suite
3. **Objective**: Wire the complete credential verification and session establishment flow into the `AuthServiceImpl::Authenticate` gRPC handler and create a comprehensive integration test suite against containerized PostgreSQL 17.
4. **Architectural Purpose**: Delivers the completed, production-ready primary user authentication endpoint for SecureCloud, validating the entire chain against the live database with full failure case coverage.
5. **Scope**:
   - Implement `AuthenticationController` in `src/auth/service/authentication_controller.{hpp,cpp}`:
     - Coordinates `CredentialVerifier`, `SessionManager`, and `IAuditEventPublisher`.
     - Maps domain results to gRPC status codes:
       - `Success` -> `grpc::Status::OK` (populates `session_id`, `user_id`, `authentication_level = PRIMARY`, `expires_at_epoch_ms`).
       - `InvalidCredentials` -> `grpc::Status(StatusCode::UNAUTHENTICATED, "Invalid credentials")`.
       - `AccountDisabled` -> `grpc::Status(StatusCode::PERMISSION_DENIED, "Account is disabled")`.
       - `DeviceRevoked` -> `grpc::Status(StatusCode::PERMISSION_DENIED, "Device has been revoked")`.
       - `DeviceNotFound` -> `grpc::Status(StatusCode::NOT_FOUND, "Device not registered")`.
       - `InvalidArgument` -> `grpc::Status(StatusCode::INVALID_ARGUMENT, "Malformed request")`.
   - Update `src/auth/service/auth_service_impl.cpp`:
     - Replace `IMPLEMENT_UNIMPLEMENTED_RPC(Authenticate, ...)` with active call to `AuthenticationController::authenticate`.
   - Create end-to-end integration test suite `tests/integration/auth_credential_authentication_integration_test.cpp`:
     - Runs against containerized PostgreSQL 17 on `127.0.0.1:5433` (skipping gracefully if container is offline).
     - Test 1: Valid user credentials -> returns `OK`, session persisted in DB, audit success emitted.
     - Test 2: Incorrect password -> returns `UNAUTHENTICATED`, zero sessions created, audit failure emitted.
     - Test 3: Non-existent username -> returns `UNAUTHENTICATED`, dummy hash executed, zero sessions created.
     - Test 4: Disabled account -> returns `PERMISSION_DENIED`, zero sessions created, audit failure emitted.
     - Test 5: Revoked device -> returns `PERMISSION_DENIED`, zero sessions created.
     - Test 6: Malformed credentials (empty password, invalid UUID) -> returns `INVALID_ARGUMENT`.
     - Test 7: Concurrency test: multiple simultaneous authentication requests for the same user succeed without lock contention.
6. **Explicit Out-of-Scope**: Gateway routing; MFA challenge issuance (AUTH-006).
7. **Dependencies**: Upstream AUTH-003-T01 through AUTH-003-T05, AUTH-002-T06.
8. **Exact Repository Starting Point**: `src/auth/service/`, `tests/integration/`.
9. **Files to Modify/Create**:
   - `src/auth/service/authentication_controller.hpp`
   - `src/auth/service/authentication_controller.cpp`
   - `src/auth/service/auth_service_impl.hpp`
   - `src/auth/service/auth_service_impl.cpp`
   - `tests/integration/auth_credential_authentication_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`
10. **Acceptance Criteria**:
    - All 7 integration test scenarios pass against PostgreSQL 17 container on port 5433.
    - `python3 scripts/verify-local.py --preset dev-debug` passes 100%.

---

## 4. Work Breakdown & Ticket Summary Table

| Ticket ID | Component / Focus | Deliverables | Key Test Verification |
| :--- | :--- | :--- | :--- |
| **AUTH-003-T01** | `Argon2idHasher` | `password_hasher.hpp`, `argon2id_hasher.{hpp,cpp}` | RFC 9106 PHC string generation, constant-time compare, dummy verify |
| **AUTH-003-T02** | `CredentialPrims` | `credentials.hpp` (`CredentialIdentifier`, `PasswordCredential`) | Redaction in streams, length boundaries, control char rejection |
| **AUTH-003-T03** | `CredentialVerifier` | `auth_result.hpp`, `credential_verifier.{hpp,cpp}` | Account enumeration defense, disabled account check, failure uniformity |
| **AUTH-003-T04** | `SessionManager` | `session_manager.{hpp,cpp}` | Device validation, active session creation, last authenticated timestamp |
| **AUTH-003-T05** | `AuditPublisher` | `audit_event.hpp`, `audit_publisher.{hpp,cpp}` | Event schema compliance, zero plaintext secrets in audit records |
| **AUTH-003-T06** | `Authenticate RPC` | `authentication_controller.{hpp,cpp}`, `auth_service_impl.cpp`, integration tests | End-to-end integration against live PostgreSQL 17 (port 5433) |

---

## 5. Security & Verification Checklist

- [ ] **No Plaintext Passwords at Rest**: All stored credentials use Argon2id verifiers with 16-byte random salts.
- [ ] **No Credential Logging**: `PasswordCredential` stream operators strictly output `"[REDACTED_PASSWORD]"`.
- [ ] **No User Enumeration**: Response status and latency are uniform whether the account exists or does not exist.
- [ ] **Port 5432 Isolation Guard**: Verification tests enforce port 5433 container binding and reject host port 5432.
- [ ] **Audit Compliance**: All authentication outcomes emit structured audit events conforming to `05-audit-data-model.md`.
- [ ] **Memory Hygiene**: Raw password buffers are cleansed using `OPENSSL_cleanse` upon destruction.
