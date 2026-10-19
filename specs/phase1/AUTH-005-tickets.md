# AUTH-005 — Implement Access and Refresh Token Lifecycles
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-005  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Technical Specification  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Sergey  
**Date**: 2026-10-06  

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-005** implements the short-lived signed access token and stateful rotating refresh token model for the SecureCloud platform. It builds upon the session lifecycle established in **AUTH-004** and primary credential authentication in **AUTH-003**, enabling high-throughput stateless access token verification at the API Gateway perimeter while maintaining instantaneous stateful revocation and breach detection at the core Auth service.

### Token Lifecycle & Trust Boundary Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                           API Gateway (Perimeter)                           │
 │                                                                             │
 │  Incoming HTTP Request (Bearer <Access-Token>)                              │
 │        │                                                                    │
 │        ▼                                                                    │
 │  LocalTokenVerifier (Holds ONLY Auth Public Key)                            │
 │  - Verifies Ed25519 signature locally in < 0.05ms (zero DB / zero RPC)      │
 │  - Validates iss, aud, exp, nbf, scopes, token_version                      │
 │  - Extracts request AuthenticatedContext (user_id, device_id, session_id)   │
 └─────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ (On Access Token Expiration / 401)
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                        Auth Microservice (Authority)                        │
 │                                                                             │
 │  RefreshSession gRPC RPC (refresh_token, device_id)                         │
 │        │                                                                    │
 │        ▼                                                                    │
 │  TokenManager                                                               │
 │  - Hashes incoming secret refresh token with SHA-256                        │
 │  - Looks up verifier in PostgreSQL 17 (refresh_tokens table)                 │
 │  - Validates session & device active status (SessionManager)                │
 │        │                                                                    │
 │        ├── [Valid Active Token]:                                            │
 │        │   - Rotates refresh token atomically (Old: Rotated, New: Active)   │
 │        │   - Issues new short-lived signed access token (Ed25519 Private)   │
 │        │   - Emits audit telemetry (TokenRotated)                           │
 │        │                                                                    │
 │        └── [Compromise / Token Reuse Detected]:                             │
 │            - Stolen token replay detected!                                  │
 │            - Atomically revokes session & all sibling refresh tokens        │
 │            - Emits critical security audit event (TokenReuseCompromise)     │
 │            - Returns UNAUTHENTICATED to caller                              │
 └─────────────────────────────────────────────────────────────────────────────┘
```

### Key Invariants & Architectural Boundaries

1. **Asymmetric Key Boundary (ADR-008, Zero-Trust Principle)**:
   - Auth Service exclusively generates, stores, and uses the **private signing key** (Ed25519).
   - Auth Service exposes **only the public verification key** to the API Gateway.
   - Private key material is never logged, serialized into responses, or accessible across process boundaries.
2. **Access Token Immutability & Claims Invariants**:
   - Short-lived lifetime (default: 15 minutes / 900 seconds).
   - Strict standard claims: `iss` (`https://auth.securecloud.io`), `aud` (`https://gateway.securecloud.io`), `sub` (`user_id`), `device_id`, `session_id`, `iat`, `exp`, `jti` (UUIDv7), `scopes`, `token_version` (1), `authentication_level` (`PRIMARY` or `MFA_VERIFIED`).
   - Contains **zero plaintext passwords, secrets, or file payload data**.
3. **Stateful Single-Use Refresh Token Rotation**:
   - High-entropy cryptographic random secret (256-bit secure random bytes, Base64URL encoded).
   - Plaintext secrets are **never stored** in the database; only constant-time SHA-256 verifier hashes (`token_verifier`) are persisted.
   - Each refresh token can be used exactly once. Upon rotation, the old token transitions to `Rotated`, linked to `replaced_by_token_id`.
4. **Token Reuse Breach Detection & Immediate Security Response**:
   - If an incoming refresh token presents a verifier hash that is already marked `Rotated`, the engine immediately recognizes a token compromise event (e.g., man-in-the-middle or credential exfiltration).
   - The engine automatically revokes the entire underlying session and all active sibling tokens for that session.
5. **Secret Redaction & Telemetry Hygiene**:
   - Refresh token secrets and verifiers are strictly excluded from logs, error messages, and audit payloads (`SecretString` / scrubbing invariants).
6. **Persistence Durability Across Service Restarts**:
   - All refresh token states survive service restarts and process termination via transactional PostgreSQL 17 persistence.

---

## 2. Existing Foundations (Reused Without Duplication)

The following core components have already been implemented, reviewed, and tested in prior cards, and will be directly leveraged by **AUTH-005**:

- [`IRefreshTokenRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/refresh_token_repository.hpp) & [`PostgresRefreshTokenRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/refresh_token_repository.cpp):
  - Database schema (`refresh_tokens` table), atomic insertion, lookup by verifier, `rotate_token_atomic`, and `handle_token_reuse` are already implemented and tested against PostgreSQL 17.
- [`SessionManager`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/session_manager.hpp):
  - Validates session state, active status, device binding, and handles session revocation.
- [`AuditEventPublisher`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/audit_event_publisher.hpp):
  - Publishes audit events to telemetry sinks.
- `proto/securecloud/auth/v1/auth.proto`:
  - `AuthenticateResponse` (`access_token`, `refresh_token`), `RefreshSessionRequest`, and `RefreshSessionResponse` messages are already defined in the contract.

---

## 3. Ticket Breakdown

### Ticket AUTH-005-T01: Cryptographic Token Signer, Verifier & Secret Generator
- **Focus**: Asymmetric Ed25519 cryptographic signer/verifier and high-entropy secret token generation.
- **Components to Implement**:
  - `src/auth/crypto/token_crypto.hpp` & `token_crypto.cpp`:
    - `Ed25519TokenSigner`: Generates/loads Ed25519 private key, creates signatures, exports public key (PEM / raw format).
    - `Ed25519TokenVerifier`: Verifies signatures using public key.
    - `SecureRandomTokenGenerator`: Generates 256-bit cryptographically secure random refresh token strings with prefix (e.g., `sc_rt_...`).
    - `TokenHasher`: Computes constant-time SHA-256 hash of refresh token secrets for `token_verifier` matching.
  - Base64URL encoding/decoding utilities conforming to RFC 7515 with constant-time comparison.
- **Testing**:
  - Unit tests in `tests/unit/auth/token_crypto_test.cpp`:
    - Keypair generation, signing, and signature verification.
    - Signature tampering rejection (corrupted payload or signature bits).
    - Secret generation randomness and entropy verification.
    - SHA-256 verifier computation determinism and constant-time behavior.

---

### Ticket AUTH-005-T02: Access Token Domain Model, Claims Engine & Serialization
- **Focus**: Type-safe domain models for access tokens, signed token serialization, claims validation, and secret sanitization.
- **Components to Implement**:
  - `src/auth/domain/token_claims.hpp` & `token_claims.cpp`:
    - `AccessTokenClaims` struct with fields: `issuer`, `audience`, `user_id`, `device_id`, `session_id`, `issued_at`, `expires_at`, `jti`, `scopes`, `token_version`, `authentication_level`.
    - Signed Access Token serialization: compact envelope combining Header (`{"alg":"EdDSA","typ":"SC-Token"}`) + Claims Payload + Ed25519 signature.
    - Deserialization: parse token envelope, validate syntax, verify timestamps (`exp`, `iat`, clock skew allowance), and verify strict device and session bindings.
  - `src/auth/domain/token_result.hpp`:
    - `TokenPair` (`access_token`, `refresh_token`, `expires_at`).
    - `TokenRefreshResult` and `TokenValidationResult` discriminated unions.
  - Secret sanitization wrapper for refresh tokens (`SecretTokenString`) to guarantee no accidental logging.
- **Testing**:
  - Unit tests in `tests/unit/auth/token_claims_test.cpp`:
    - Signed Access Token round-trip serialization and deserialization.
    - Rejection of expired tokens, invalid issuers, invalid audiences, missing claims, malformed payloads.
    - Secret wrapper logging test: verify stream operators scrub secrets.

---

### Ticket AUTH-005-T03: Stateful Refresh Token Rotation & Token Management Engine (`TokenManager`)
- **Focus**: Core business logic orchestrating access token issuance and stateful single-use refresh token rotation.
- **Components to Implement**:
  - `src/auth/service/token_manager.hpp` & `token_manager.cpp`:
    - `TokenManager` class implementing `ITokenManager`.
    - Dependencies: `ITokenSigner`, `IRefreshTokenRepository`, `ISessionRepository`, `IDeviceRepository`, `AuditEventPublisher`.
    - `issue_initial_tokens(const SessionEntity& session)`: Creates initial `TokenPair` for a newly established session.
    - `refresh_tokens(std::string_view refresh_token_secret, const Uuid& device_id)`:
      - Hashes secret to obtain `token_verifier`.
      - Validates refresh token exists, status is `Active`, and not expired.
      - Verifies session exists, is `Active`, and device ID matches.
      - Calls `IRefreshTokenRepository::rotate_token_atomic`.
      - Issues newly signed access token + new active refresh token secret.
- **Testing**:
  - Unit tests in `tests/unit/auth/token_manager_test.cpp`:
    - Successful initial token pair issuance.
    - Successful token rotation flow with mock repositories.
    - Expired refresh token rejection.
    - Device mismatch rejection (`device_id` in request does not match token's bound device).
    - Revoked session rejection.

---

### Ticket AUTH-005-T04: Token Compromise & Reuse Detection Engine
- **Focus**: Security response when an already-rotated or revoked refresh token is presented.
- **Components to Implement**:
  - Extend `TokenManager` to handle reuse detection:
    - If `find_by_verifier` returns a token with status `Rotated` or `Revoked`, execute compromise protocol:
      - Call `IRefreshTokenRepository::handle_token_reuse(verifier_hash)` to revoke the session and all sibling refresh tokens.
      - Emit high-severity security audit event (`AuditEvent::token_reuse_detected` / `AuditEvent::token_compromised`).
      - Return `TokenRefreshStatus::CompromiseDetected`.
    - Provide concurrency resilience when two requests attempt to rotate the same refresh token simultaneously.
- **Testing**:
  - Unit tests in `tests/unit/auth/token_reuse_test.cpp`:
    - Simulating replay of a previously rotated refresh token.
    - Verifying underlying session and sibling tokens transition to `Revoked`.
    - Verifying audit telemetry event emission with correct metadata (user ID, device ID, session ID) and zero secret leakage.
    - Concurrent rotation race simulation.

---

### Ticket AUTH-005-T05: Gateway Local Token Verification Engine & Public Key Verification
- **Focus**: Demonstrating Gateway perimeter access token validation using only Auth's public verification key without Auth private key exposure.
- **Components to Implement**:
  - `src/gateway/http/auth/local_token_verifier.hpp` & `local_token_verifier.cpp`:
    - Implements `ITokenValidator`.
    - Configured with Auth's public verification key (loaded from config or key file).
    - Cryptographically validates JWT signatures locally with `Ed25519TokenVerifier`.
    - Validates standard claims (`exp`, `iss`, `aud`, `scopes`).
    - Produces `AuthenticatedContext` on success; returns `TokenValidationError` on failure.
    - Guarantees zero RPC overhead and zero database connectivity.
- **Testing**:
  - Unit tests in `tests/unit/gateway/local_token_verifier_test.cpp`:
    - Valid tokens signed by Auth pass validation and map to `AuthenticatedContext`.
    - Expired tokens fail validation (`TokenExpired`).
    - Forged tokens with invalid signatures fail validation (`InvalidSignature`).
    - Verifying Auth never exposes private key to the Gateway verifier.

---

### Ticket AUTH-005-T06: gRPC RefreshSession Implementation, Main Wiring & E2E Integration Suite
- **Focus**: gRPC RPC implementation, production daemon wiring, and end-to-end integration tests with live PostgreSQL 17.
- **Components to Implement**:
  - `src/auth/service/auth_service_impl.cpp`:
    - Implement `RefreshSession` gRPC RPC handler.
    - Update `Authenticate` RPC handler to issue and populate `access_token` and `refresh_token` in `AuthenticateResponse`.
    - Translate domain statuses to canonical gRPC status codes (`OK`, `UNAUTHENTICATED`, `PERMISSION_DENIED`, `INVALID_ARGUMENT`).
  - `src/auth/main.cpp`:
    - Instantiate `Ed25519TokenSigner`, `PostgresRefreshTokenRepository`, and `TokenManager`.
    - Wire `TokenManager` into `AuthServiceImpl`.
  - Integration test suite in `tests/integration/auth_token_integration_test.cpp`:
    - Live tests against containerized PostgreSQL 17 on port 5433 (with preflight port 5432 protection):
      1. Complete End-to-End lifecycle: `Authenticate` $\to$ Validate Access Token $\to$ `RefreshSession` $\to$ Validate New Access Token.
      2. Durability across service restart: Authenticate, destroy Auth service instance, recreate Auth service instance, rotate refresh token successfully against DB.
      3. Live Token Reuse Attack: Stolen token replay against live database revokes session immediately.
- **Testing**:
  - Unit tests in `tests/unit/auth/auth_service_token_test.cpp` (100% mocked gRPC tests).
  - Integration tests in `tests/integration/auth_token_integration_test.cpp` (Live DB).

---

## 4. Work Breakdown & Ticket Sequencing

```text
AUTH-005-T01 (Token Crypto & Signer/Verifier)
     │
     ▼
AUTH-005-T02 (Token Domain Model & Claims)
     │
     ▼
AUTH-005-T03 (TokenManager & Single-Use Rotation)
     │
     ▼
AUTH-005-T04 (Compromise & Reuse Detection Engine)
     │
     ▼
AUTH-005-T05 (Gateway Local Token Verifier Contract)
     │
     ▼
AUTH-005-T06 (gRPC RefreshSession, Main Wiring & E2E Integration Suite)
```

---

## 5. Traceability Matrix against Acceptance Criteria

| Acceptance Criterion | Primary Implementing Ticket(s) | Verification Target |
| :--- | :--- | :--- |
| **Gateway validates access tokens using Auth's public key** | AUTH-005-T01, AUTH-005-T05 | `local_token_verifier_test.cpp` |
| **Auth never exposes its private signing key** | AUTH-005-T01, AUTH-005-T05 | Interface boundary isolation tests |
| **Expired access tokens are rejected** | AUTH-005-T02, AUTH-005-T05 | `token_claims_test.cpp`, `local_token_verifier_test.cpp` |
| **Refresh tokens rotate successfully** | AUTH-005-T03, AUTH-005-T06 | `token_manager_test.cpp`, `auth_token_integration_test.cpp` |
| **Reuse of an old refresh token is detected** | AUTH-005-T04, AUTH-005-T06 | `token_reuse_test.cpp`, `auth_token_integration_test.cpp` |
| **Refresh-token state survives restart** | AUTH-005-T03, AUTH-005-T06 | `auth_token_integration_test.cpp` |
| **Token secrets are not logged or persisted insecurely** | AUTH-005-T01, AUTH-005-T02, AUTH-005-T04 | Audit sanitization & Secret wrapper tests |
| **Tests cover expiration, rotation, reuse, concurrency, invalid tokens** | AUTH-005-T01 through AUTH-005-T06 | Full CTest test suite |
