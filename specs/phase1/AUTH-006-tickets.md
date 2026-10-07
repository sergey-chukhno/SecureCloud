# AUTH-006 — Implement MFA / TOTP
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-006  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Technical Specification  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Sergey  
**Date**: 2026-10-07  

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-006** implements multi-factor authentication (MFA) for the SecureCloud platform. Building on primary credential authentication (**AUTH-003**), device session management (**AUTH-004**), and the signed/rotating token lifecycle (**AUTH-005**), this card introduces:
- **Time-Based One-Time Passwords (TOTP, RFC 6238)** as the initial approved MVP second factor.
- **Strict Cryptographic Abstraction for Future Authenticators**: Decoupling the authentication service from TOTP specifics via an extensible `IMfaAuthenticator` boundary, enabling seamless future addition of WebAuthn / FIDO2 security keys and platform authenticators without altering the core session architecture.
- **Two Discrete Assurance Levels**:
  - `PRIMARY_ONLY`: Session established solely with primary password credentials.
  - `MFA_VERIFIED`: Session where the user has successfully solved an in-flight second-factor challenge.
- **Enforcement for Sensitive Operations**: Gateways and protected internal operations can demand `MFA_VERIFIED` assurance, triggering step-up challenges when incoming requests only present `PRIMARY_ONLY`.
- **At-Rest Secret Protection & Zero Telemetry Leakage**: TOTP shared secrets encrypted with authenticated AES-256-GCM at rest, with memory zeroization and strict audit redaction.

### MFA Architecture & Trust Boundary

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                           API Gateway (Perimeter)                           │
 │                                                                             │
 │  Incoming Request (Bearer <Access-Token>)                                   │
 │        │                                                                    │
 │        ▼                                                                    │
 │  LocalTokenVerifier                                                         │
 │  - Inspects token claim: "lvl" == "primary" vs "mfa_verified"               │
 │  - Evaluates Route Policy (e.g. DELETE /api/v1/user requires MFA_VERIFIED)  │
 │        │                                                                    │
 │        ├── If route requires MFA_VERIFIED and token is PRIMARY_ONLY:        │
 │        │   └── Rejects with 403 Forbidden ("MFA_VERIFIED_REQUIRED")         │
 │        └── If assurance meets route policy:                                 │
 │            └── Forwards request to downstream services                      │
 └─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼ (MFA Step-Up or Primary Login)
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                        Auth Microservice (Authority)                        │
 │                                                                             │
 │  1. Login with MFA:                                                         │
 │     Authenticate(email, password, device_id)                                │
 │     - Password verified -> User has active MFA?                             │
 │     - YES -> Create session (PRIMARY_ONLY), issue MfaChallengeEntity        │
 │     - Return AuthenticateResponse(mfa_required=true, mfa_challenge_id)      │
 │                                                                             │
 │  2. Solve Challenge:                                                        │
 │     VerifyMfaChallenge(challenge_id, code)                                  │
 │     - Validate challenge is Pending and not expired                         │
 │     - Decrypt TOTP secret via MfaSecretProtector (AES-256-GCM)              │
 │     - Verify code via TotpEngine (RFC 6238, +/- 1 window drift)             │
 │     - Check replay prevention (same code cannot be re-used in window)       │
 │     - Complete challenge in PostgreSQL 17                                   │
 │     - Upgrade session to MFA_VERIFIED in PostgreSQL 17                      │
 │     - Mint new TokenPair with lvl = "mfa_verified"                          │
 │     - Emit AuditEventType::MfaChallengeCompleted                            │
 └─────────────────────────────────────────────────────────────────────────────┘
```

### Key Invariants & Architectural Boundaries

1. **Decoupled Factor Abstraction (`IMfaAuthenticator`)**:
   - The core MFA service interacts with factors solely through the `IMfaAuthenticator` interface contract.
   - The initial MVP concrete factor is `TotpAuthenticator` (RFC 6238).
   - Future WebAuthn / FIDO2 authenticators will implement `IMfaAuthenticator` without modifying session models, assurance level transitions, or challenge handling.
2. **Deterministic Assurance Level Promotion**:
   - Every session starts at `AuthenticationLevel::PrimaryOnly`.
   - Only successful completion of a verified MFA challenge through `MfaManager` promotes the session to `AuthenticationLevel::MfaVerified`.
   - When a session is promoted, the Auth Service issues an upgraded `TokenPair` containing an access token signed with `"lvl": "mfa_verified"`.
3. **Protection of MFA Secrets at Rest & In Memory**:
   - Plaintext TOTP shared secrets are **never stored unencrypted** in PostgreSQL.
   - Secrets are encrypted using AES-256-GCM with a server-managed Key Encryption Key (KEK).
   - Plaintext secrets and verification codes are wrapped in RAII redaction types (`SecretMfaString`), preventing accidental emission to logs, error responses, or telemetry.
4. **Time Drift Tolerance & Anti-Replay Invariants**:
   - TOTP evaluation permits a time-drift window of $\pm 1$ time-step ($\pm 30$ seconds, 90-second total validity window) to account for client device clock skew.
   - A verified TOTP code cannot be replayed for another challenge within the same 30-second time-step.
5. **Brute-Force & Denial-of-Service Defense**:
   - Challenges have a strict 5-minute time-to-live (`expires_at`).
   - A maximum of 3 failed verification attempts transitions the challenge to `Failed`, preventing brute-force enumeration of 6-digit codes.
6. **Disaster Recovery via Single-Use Backup Codes**:
   - Enrollment confirmation generates a set of 8 single-use cryptographically random backup recovery codes.
   - Recovery codes are stored hashed (Argon2id or SHA-256) in PostgreSQL.
   - Presenting a valid recovery code satisfies the challenge and automatically marks that individual recovery code as consumed.

---

## 2. Existing Foundations (Reused Without Duplication)

The following components and schemas are already implemented in the codebase and will be leveraged directly:

1. **Database Schema & Migrations (`V002__create_auth_tables.sql`, `V003__create_auth_indexes.sql`)**:
   - `mfa_configurations` table already exists: `mfa_configuration_id`, `user_id`, `factor_type`, `encrypted_secret`, `status`, `created_at`, `enabled_at`, `disabled_at`, `version`.
   - `mfa_challenges` table already exists: `mfa_challenge_id`, `user_id`, `session_id`, `challenge_purpose`, `challenge_status`, `created_at`, `expires_at`, `completed_at`.
   - Indexes `idx_mfa_config_user_status` already exist.
2. **Repository Layer ([`PostgresMfaRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/mfa_repository.hpp))**:
   - Full CRUD operations: `store_mfa_configuration`, `find_mfa_config_by_user_id`, `enable_mfa`, `disable_mfa`, `create_challenge`, `find_challenge_by_id`, `complete_challenge`, `fail_challenge`.
3. **Domain Enums & Entities ([`src/auth/domain/enums.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/enums.hpp), [`entities.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/entities.hpp))**:
   - `MfaFactorType::Totp`, `MfaStatus` (`Pending`, `Enabled`, `Disabled`), `MfaChallengePurpose` (`Login`, `StepUp`), `MfaChallengeStatus` (`Pending`, `Completed`, `Expired`, `Failed`).
   - `AuthenticationLevel::PrimaryOnly` and `AuthenticationLevel::MfaVerified`.
4. **Token Engine & Signer ([`TokenEnvelopeSerializer`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/token_envelope.hpp), [`LocalTokenVerifier`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/local_token_verifier.hpp))**:
   - Already serialize and verify `"lvl": "mfa_verified"` vs `"primary"`, populating `AuthenticatedContext::authentication_level()`.
5. **Protobuf Contract ([`auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto))**:
   - `AuthenticateResponse` already defines `bool mfa_required = 7;` and `string mfa_challenge_id = 8;`.
   - `AuthenticationLevel` enum already contains `AUTHENTICATION_LEVEL_PRIMARY` and `AUTHENTICATION_LEVEL_MFA_VERIFIED`.

---

## 3. Ticket Breakdown

### Ticket AUTH-006-T01: RFC 6238 TOTP Engine, Base32 Codec & At-Rest Secret Protector

- **Focus**: High-precision cryptographic algorithms for TOTP code generation, verification with time-step drift tolerance, Base32 encoding/decoding, and AES-256-GCM authenticated encryption for secrets at rest.
- **Components to Implement**:
  - `src/auth/crypto/totp_engine.hpp` & `totp_engine.cpp`:
    - `TotpConfig`: 30-second time-step, 6 digits, HMAC-SHA1 default with HMAC-SHA256 support, $\pm 1$ time-step drift window.
    - `TotpEngine`:
      - `generate_secret(size_t num_bytes = 20)`: Generates 160-bit cryptographically secure random bytes via OpenSSL `RAND_bytes`.
      - `compute_code(std::string_view secret_bytes, uint64_t timestamp_seconds)`: Calculates 6-digit TOTP code per RFC 6238 / RFC 4226 (HOTP).
      - `verify_code(std::string_view secret_bytes, std::string_view code, uint64_t timestamp_seconds, int window_steps = 1)`: Verifies code in constant time over $[T - \text{window}, T + \text{window}]$.
      - `generate_otpauth_uri(std::string_view issuer, std::string_view account_name, std::string_view base32_secret)`: Formats standard `otpauth://totp/...` URI for Google Authenticator / 1Password.
  - `src/auth/crypto/base32.hpp` & `base32.cpp`:
    - RFC 4648 Base32 encoder and decoder with constant-time parsing and strict padding validation.
  - `src/auth/crypto/mfa_secret_protector.hpp` & `mfa_secret_protector.cpp`:
    - `MfaSecretProtector`:
      - Symmetrically encrypts TOTP secrets using AES-256-GCM with a 256-bit KEK (from environment/config).
      - Wire layout of `encrypted_secret`: `12-byte random IV || ciphertext || 16-byte GCM authentication tag`.
      - Decrypts and verifies authentication tag; throws on tampering.
  - `src/auth/domain/secret_mfa_string.hpp`:
    - RAII wrapper redacting TOTP secrets and codes in stream operators (`[REDACTED_MFA_SECRET]`).
- **Testing**:
  - Unit tests in `tests/unit/auth/totp_engine_test.cpp`:
    - RFC 6238 standard test vector validation.
    - Code verification within current step, previous step ($-30\text{s}$), and next step ($+30\text{s}$).
    - Rejection of invalid codes and expired steps ($> \pm 1$ window).
    - Base32 encoding/decoding round-trips.
    - AES-256-GCM encryption/decryption round-trip and tampering rejection.
    - Stream operator redaction test.

---

### Ticket AUTH-006-T02: MFA Authenticator Abstraction, Domain Models & Recovery Code Engine

- **Focus**: Decoupled multi-factor authenticator interface contract, domain models for challenges and enrollment, and one-time disaster recovery code generation.
- **Components to Implement**:
  - `src/auth/service/mfa_authenticator_interface.hpp`:
    - Abstract `IMfaAuthenticator` interface:
      - `MfaFactorType factor_type() const noexcept`
      - `bool verify_factor(const std::vector<uint8_t>& encrypted_secret, std::string_view credential, uint64_t timestamp)`
    - `TotpAuthenticator` implementing `IMfaAuthenticator` (delegates to `MfaSecretProtector` and `TotpEngine`).
    - *Extensibility Guarantee*: WebAuthn/FIDO2 authenticators will plug into this interface without altering service workflows.
  - `src/auth/domain/mfa_result.hpp`:
    - Domain models:
      - `MfaEnrollmentInitiation`: `mfa_configuration_id`, `base32_secret`, `otpauth_uri`.
      - `MfaEnrollmentConfirmationResult`: `success`, `recovery_codes`, `error_message`.
      - `MfaVerificationResult`: `status` (`Success`, `InvalidCode`, `ExpiredChallenge`, `MaxAttemptsExceeded`, `ChallengeFailed`), `error_message`.
  - `src/auth/crypto/recovery_code_generator.hpp` & `recovery_code_generator.cpp`:
    - Generates 8 single-use cryptographically random backup recovery codes (e.g., `ABCD-1234-EFGH`).
    - Hashes recovery codes using SHA-256 for secure persistence in `MfaConfigurationEntity` or dedicated recovery store.
    - Verifies recovery code and burns consumed code atomically.
- **Testing**:
  - Unit tests in `tests/unit/auth/mfa_authenticator_test.cpp`:
    - `TotpAuthenticator` verification success and failure via `IMfaAuthenticator` interface.
    - Recovery code generation randomness, formatting, and hashing verification.
    - Recovery code single-use burn mechanics.

---

### Ticket AUTH-006-T03: Stateful MFA Lifecycle & Challenge Management Engine (`MfaManager`)

- **Focus**: Core domain service managing MFA enrollment, activation, challenge creation, time-drift anti-replay, and brute-force attempt throttling.
- **Components to Implement**:
  - `src/auth/service/mfa_manager.hpp` & `mfa_manager.cpp`:
    - `MfaManager` implementing `IMfaManager`.
    - Dependencies: `IMfaRepository`, `ISessionRepository`, `IUserRepository`, `IMfaAuthenticator`, `TotpEngine`, `MfaSecretProtector`, `IAuditEventPublisher`.
    - `initiate_enrollment(const Uuid& user_id)`:
      - Checks if user already has an `Enabled` MFA configuration; rejects duplicate active configs.
      - Generates fresh 160-bit secret, encrypts with `MfaSecretProtector`.
      - Stores `MfaConfigurationEntity` with status `Pending`.
      - Returns Base32 secret and OTPAuth URI.
    - `confirm_enrollment(const Uuid& user_id, std::string_view code)`:
      - Looks up pending config, decrypts secret, verifies TOTP code.
      - On success: marks config `Enabled`, generates 8 recovery codes, sets user `mfa_enabled = true` in PostgreSQL.
      - Emits `AuditEvent::mfa_enabled`.
    - `disable_mfa(const Uuid& user_id, std::string_view code_or_recovery)`:
      - Verifies active TOTP code or recovery code.
      - Transitions configuration to `Disabled`, clears user `mfa_enabled = false`.
      - Emits `AuditEvent::mfa_disabled`.
    - `create_challenge(const Uuid& user_id, const Uuid& session_id, MfaChallengePurpose purpose)`:
      - Inserts `MfaChallengeEntity` with status `Pending` and 5-minute TTL.
    - `verify_challenge(const Uuid& challenge_id, std::string_view code)`:
      - Validates challenge exists, is `Pending`, and not expired.
      - Tracks attempt counter (max 3 attempts). If attempts exceed 3, marks challenge `Failed` (`MaxAttemptsExceeded`).
      - Anti-replay check: rejects code if already verified within the same time-step window.
      - On verification success: marks challenge `Completed`, upgrades session status to `AuthenticationLevel::MfaVerified`, touches session activity timestamp.
      - Emits `AuditEvent::mfa_challenge_completed` or `AuditEvent::mfa_challenge_failed`.
- **Testing**:
  - Unit tests in `tests/unit/auth/mfa_manager_test.cpp`:
    - Enrollment initiation and successful confirmation.
    - Confirmation with invalid code rejected; config remains pending.
    - Challenge creation, verification success, and session upgrade to `MfaVerified`.
    - Expired challenge rejection.
    - 3-attempt brute-force lockout: 3rd failed attempt fails the challenge.
    - Anti-replay rejection of identical code within the same time window.
    - MFA disable flow requiring valid code.

---

### Ticket AUTH-006-T04: Primary Authentication Integration & Session Assurance Upgrade

- **Focus**: Integrating MFA challenge generation into `Authenticate`, blocking unverified sessions, and issuing upgraded tokens upon challenge completion.
- **Components to Implement**:
  - Update `src/auth/service/auth_service_impl.cpp`:
    - **`Authenticate` Step-Up Branching**:
      - After password verification and session establishment:
      - Check if user has an active `MfaConfiguration` with status `Enabled`.
      - If MFA is NOT enabled:
        - Issue full tokens with `AuthenticationLevel::PrimaryOnly` (existing behavior).
      - If MFA IS enabled:
        - Session created with status `Active`, but `AuthenticationLevel::PrimaryOnly`.
        - Create `MfaChallengeEntity` via `MfaManager::create_challenge`.
        - Populate `AuthenticateResponse` with:
          - `mfa_required = true`
          - `mfa_challenge_id = challenge.mfa_challenge_id.to_string()`
          - Blank `access_token` and `refresh_token` (preventing perimeter access until second factor is satisfied).
          - `authentication_level = AUTHENTICATION_LEVEL_PRIMARY`
    - **`VerifyMfaChallenge` gRPC RPC Handler**:
      - Accepts `challenge_id` and `code`.
      - Validates input formats (`INVALID_ARGUMENT`).
      - Invokes `MfaManager::verify_challenge`.
      - On success:
        - Session in DB is now `MfaVerified`.
        - Invokes `TokenManager::issue_initial_tokens` for the verified session.
        - Returns `VerifyMfaChallengeResponse` with `session_id`, `access_token` (signed with `lvl = "mfa_verified"`), `refresh_token`, and `authentication_level = AUTHENTICATION_LEVEL_MFA_VERIFIED`.
- **Testing**:
  - Unit tests in `tests/unit/auth/auth_service_mfa_test.cpp`:
    - `Authenticate` for user without MFA returns tokens directly (`mfa_required = false`).
    - `Authenticate` for user with MFA returns `mfa_required = true` and `mfa_challenge_id` with empty tokens.
    - `VerifyMfaChallenge` with correct TOTP returns upgraded tokens with `MFA_VERIFIED`.
    - `VerifyMfaChallenge` with invalid code returns `UNAUTHENTICATED`.
    - `VerifyMfaChallenge` with expired challenge returns `DEADLINE_EXCEEDED` / `UNAUTHENTICATED`.

---

### Ticket AUTH-006-T05: Sensitive Operations Assurance Enforcement & Gateway Policy Integration

- **Focus**: Enforcing `MFA_VERIFIED` assurance levels at the API Gateway perimeter and within Auth sensitive service RPCs.
- **Components to Implement**:
  - `src/gateway/http/middleware/security_policy.hpp` & `security_policy.cpp`:
    - Add minimum assurance level requirement to route configurations:
      - `RequiredAssuranceLevel`: `PrimaryOnly` vs `MfaVerified`.
    - Configure high-risk routes requiring `MfaVerified`:
      - `/api/v1/auth/mfa/disable`
      - `/api/v1/auth/devices/revoke`
      - `/api/v1/user/delete`
      - Admin management endpoints.
    - In `AuthorizationMiddleware`:
      - If route requires `MfaVerified` and incoming `AuthenticatedContext::authentication_level()` is `PrimaryOnly`:
        - Reject immediately with `403 Forbidden` (`INSUFFICIENT_AUTHENTICATION_ASSURANCE`, `"Operation requires multi-factor authentication"`).
  - Auth Service Internal Checks:
    - Sensitive RPCs (`DisableMfa`, `RevokeDevice`) verify that caller context possesses `AuthenticationLevel::MfaVerified`.
- **Testing**:
  - Unit tests in `tests/unit/gateway/gateway_mfa_assurance_policy_test.cpp`:
    - Standard routes allow `PrimaryOnly` tokens.
    - Sensitive routes allow `MfaVerified` tokens.
    - Sensitive routes reject `PrimaryOnly` tokens with `403 Forbidden`.
    - Unauthenticated requests rejected with `401`.

---

### Ticket AUTH-006-T06: gRPC Protocol Contracts, Service Wiring & Live E2E Integration Suite

- **Focus**: gRPC protobuf contracts, daemon dependency injection in `src/auth/main.cpp`, and full live integration tests against containerized PostgreSQL 17 on port 5433.
- **Components to Implement**:
  - Protobuf Contract Updates (`proto/securecloud/auth/v1/auth.proto`):
    - `rpc InitiateMfaEnrollment(InitiateMfaEnrollmentRequest) returns (InitiateMfaEnrollmentResponse);`
    - `rpc ConfirmMfaEnrollment(ConfirmMfaEnrollmentRequest) returns (ConfirmMfaEnrollmentResponse);`
    - `rpc VerifyMfaChallenge(VerifyMfaChallengeRequest) returns (VerifyMfaChallengeResponse);`
    - `rpc DisableMfa(DisableMfaRequest) returns (DisableMfaResponse);`
  - Production Wiring (`src/auth/main.cpp`):
    - Instantiate `MfaSecretProtector`, `TotpEngine`, `TotpAuthenticator`, `PostgresMfaRepository`, and `MfaManager`.
    - Wire `MfaManager` into `AuthServiceImpl`.
  - Integration Test Suite (`tests/integration/auth_mfa_integration_test.cpp`):
    - Live tests against containerized PostgreSQL 17 on port 5433 (with strict port 5432 preflight protection):
      1. **Full Enrollment & Challenge E2E**: User registers $\to$ initiates MFA $\to$ confirms with live TOTP $\to$ logs in via primary credentials (`mfa_required = true`) $\to$ verifies challenge $\to$ receives `MFA_VERIFIED` access token.
      2. **Gateway Perimeter Assurance Validation**: Gateway `LocalTokenVerifier` verifies `MFA_VERIFIED` token; sensitive route allows request.
      3. **Invalid Code & Lockout Protection**: 3 wrong codes lock the challenge; subsequent attempts rejected.
      4. **Anti-Replay Window Enforcement**: Presenting same code twice in 30-second window is rejected.
      5. **Durability Across Service Restart**: MFA configuration and challenge state survive complete Auth process restart.
- **Testing**:
  - Contract validation via `verify-contracts`.
  - Unit tests in `tests/unit/auth/auth_service_mfa_test.cpp`.
  - Integration tests in `tests/integration/auth_mfa_integration_test.cpp`.

---

## 4. Work Breakdown & Ticket Sequencing

```text
AUTH-006-T01 (TOTP Engine, Base32 Codec & AES-256-GCM Secret Protector)
     │
     ▼
AUTH-006-T02 (MFA Authenticator Abstraction, Domain Models & Recovery Codes)
     │
     ▼
AUTH-006-T03 (Stateful MFA Lifecycle & Challenge Management Engine - MfaManager)
     │
     ▼
AUTH-006-T04 (Primary Authentication Integration & Session Assurance Upgrade)
     │
     ▼
AUTH-006-T05 (Sensitive Operations Assurance Enforcement & Gateway Policy Integration)
     │
     ▼
AUTH-006-T06 (gRPC Protocol Contracts, Service Wiring & Live E2E Integration Suite)
```

---

## 5. Traceability Matrix against Acceptance Criteria

| Acceptance Criterion | Primary Implementing Ticket(s) | Verification Target |
| :--- | :--- | :--- |
| **Valid TOTP can establish `MFA_VERIFIED`** | AUTH-006-T01, AUTH-006-T03, AUTH-006-T04 | `totp_engine_test`, `auth_service_mfa_test`, `auth_mfa_integration_test` |
| **Invalid/expired codes fail safely** | AUTH-006-T01, AUTH-006-T03 | `totp_engine_test`, `mfa_manager_test` |
| **MFA state is durable** | AUTH-006-T03, AUTH-006-T06 | `mfa_manager_test`, `auth_mfa_integration_test` (Restart durability) |
| **Sensitive operations can require `MFA_VERIFIED`** | AUTH-006-T05 | `gateway_mfa_assurance_policy_test` |
| **TOTP secrets are protected appropriately** | AUTH-006-T01 | `totp_engine_test` (AES-256-GCM encryption at rest) |
| **MFA secrets are never logged** | AUTH-006-T01, AUTH-006-T03 | Secret redaction stream tests, audit payload scrubbing tests |
| **Design allows future WebAuthn/FIDO2 integration** | AUTH-006-T02 | `IMfaAuthenticator` abstraction tests |
| **Tests cover success, failure, replay/time-window, and disabled MFA** | AUTH-006-T01 through AUTH-006-T06 | Full CTest execution suite across all unit & integration tests |
