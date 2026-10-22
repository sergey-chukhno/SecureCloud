# Specification & Ticket Decomposition: Card AUTH-010

**Card ID:** `AUTH-010`  
**Card Title:** Integrate Auth with Gateway  
**Phase:** Phase 1 — Authentication, Session Lifecycle, Multi-Factor Authentication & Cryptographic Identity  
**Dependencies:** `AUTH-005`, `AUTH-006`, `AUTH-007`, `AUTH-008`, `GW-004`, `GW-005`, `GW-007`  
**Status:** PROPOSED & READY FOR IMPLEMENTATION  

---

## 1. Executive Summary & Goal

### Goal
Complete the authoritative, hardened Gateway-to-Auth authentication and authorization path, integrating primary credentials, offline public signing-key token validation, stepped-up Multi-Factor Authentication (MFA) assurance, device lifecycle/session state management, and resilience controls.

### Scope
- **Credentials & Login Pipeline:** External HTTPS client authentication dispatching to downstream gRPC `AuthService::Authenticate`.
- **Offline Public Signing-Key Token Verification:** Gateway perimeter token validation via `LocalTokenVerifier` using Auth's Ed25519 public key (zero RPC overhead, zero private key exposure).
- **Stepped-Up MFA Assurance:** Enforcement of `MFA_REQUIRED` (HTTP 403) on sensitive endpoints, with perimeter routing for enrollment, challenges, and TOTP/recovery verification.
- **Device Lifecycle & Cross-Device Pairing:** Perimeter endpoints for device listing, pairing initiation, cross-device authorization, and cascading revocation.
- **Resilience & Fault Isolation:** Bulkhead concurrency isolation, circuit breakers, dynamic deadline budgets, and RFC 7807 Problem Details error translation.
- **Live End-to-End Integration:** Full integration test suite exercising the live HTTP/HTTPS Gateway against the live gRPC AuthService daemon backed by containerized PostgreSQL 17.

### Acceptance Criteria
1. **Valid and invalid flows behave correctly end-to-end:** Primary credentials, token refresh, session revocation, MFA verification, and device pairing function correctly through the external HTTP API.
2. **Gateway never receives Auth's private signing key:** Gateway is provisioned strictly with Auth's 32-byte Ed25519 public key (or PEM public key) for offline verification, guaranteeing the **Zero Private Key Ingress** invariant.
3. **Offline token validation is cryptographically sound:** Tokens with expired timestamps, invalid signatures, malformed payloads, or mismatched issuers/audiences are rejected at the perimeter without network calls to AuthService.
4. **MFA assurance levels are strictly enforced:** Routes marked `RouteAccess::Sensitive` requiring `MFA_VERIFIED` reject `PRIMARY` sessions with HTTP 403 and `code: MFA_REQUIRED`. Subsequent verification over `/mfa/verify` upgrades the session and permits access.
5. **Revoked device and compromised session states fail closed:** Revoking a device or detecting refresh token reuse immediately halts access at the perimeter.
6. **Perimeter resilience safeguards downstream Auth:** Gateway bulkhead prevents traffic spikes from exhausting Auth resources; circuit breakers fail fast during Auth outages.
7. **Tests cover end-to-end valid and invalid flows:** Automated test suite executes live scenarios across Gateway, AuthService, and PostgreSQL 17.

### Out of Scope
- Implementing Phase 2 service proxies (Files, Chunk Sync, Messaging) — this card focuses strictly on completing the Auth perimeter integration.

---

## 2. Architecture & Delta Analysis

### What is ALREADY Implemented (Do NOT Re-Implement):
1. **Downstream AuthService Core & Persistence:**
   - Full domain engines: `CredentialVerifier`, `SessionManager`, `TokenManager`, `MfaManager`, `DeviceManager`, and `CryptoDirectoryManager`.
   - Complete PostgreSQL 17 persistence and migrations (V1 through V4).
   - Production daemon (`src/auth/main.cpp`) serving gRPC mTLS on port 50051.
2. **Gateway Foundations & Middleware:**
   - HTTP/HTTPS engine with strict TLS 1.3 listener and cleartext 308 redirect.
   - Deterministic middleware pipeline: `RequestIdMiddleware`, `LoggingMiddleware`, `DrainMiddleware`, `ResourceLimiterMiddleware`, `AuthenticationMiddleware`, `RateLimiterMiddleware`, `AuthorizationMiddleware`.
   - Resilience primitives: `BulkheadManager`, `CircuitBreaker`, `DeadlineManager`, `RetryPolicy`.
   - Core `AuthProxyHandler` routes:
     * `POST /api/v1/auth/login`
     * `POST /api/v1/auth/refresh`
     * `POST /api/v1/auth/revoke`
     * `GET /api/v1/users/me`
     * `POST /api/v1/devices`
     * `GET /api/v1/users/:user_id/devices/crypto-directory`
     * `GET /api/v1/devices/:device_id/crypto-identity`
     * `POST /api/v1/devices/:device_id/prekeys`
3. **Local Token Verifier Prototype:**
   - `LocalTokenVerifier` class in [`src/gateway/http/auth/local_token_verifier.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/local_token_verifier.hpp) implementing offline Ed25519 verification.

### What is MISSING & Targeted by AUTH-010:
1. **Public Signing Key Provisioning & Gateway Verifier Mode Integration:**
   - Gateway currently hardcodes `AuthServiceTokenValidator` (remote gRPC calls) in `src/gateway/main.cpp`.
   - Needs configuration-driven support for `LocalTokenVerifier` (offline public key verification) or hybrid caching verifier.
   - Mechanism for Gateway to load or discover Auth's Ed25519 public verification key (via configuration, PEM file, or JWKS endpoint).
2. **MFA Perimeter Handlers in Gateway:**
   - `GatewaySecurityPolicy` defines rules for `/api/v1/auth/mfa/enroll`, `/api/v1/auth/mfa/confirm`, `/api/v1/auth/mfa/challenge`, `/api/v1/auth/mfa/verify`, `/api/v1/auth/mfa/disable`.
   - However, `AuthServiceClient` lacks gRPC methods for MFA, and `AuthProxyHandler` lacks handlers for these routes!
3. **Device Management & Pairing Handlers in Gateway:**
   - `AuthServiceClient` lacks methods for `GetDevice`, `ListUserDevices`, `InitiateDevicePairing`, `AuthorizeDevice`, `RevokeDevice`.
   - `AuthProxyHandler` lacks routes for:
     * `GET /api/v1/devices` (list user devices)
     * `GET /api/v1/devices/:device_id` (device details)
     * `POST /api/v1/devices/pairing` (initiate pairing code)
     * `POST /api/v1/devices/:device_id/authorize` (authorize device with pairing code)
     * `DELETE /api/v1/devices/:device_id` (revoke device)
4. **Live End-to-End Integration Test Suite:**
   - A dedicated live test suite spinning up both the HTTP Gateway server and the gRPC AuthService server, executing real HTTP client requests over TCP/TLS against PostgreSQL 17 to prove end-to-end integration.

---

## 3. Ticket Breakdown & Implementation Plan

```text
AUTH-010-T01 (Public Signing Key Distribution & Offline LocalTokenVerifier Integration)
     │
     ▼
AUTH-010-T02 (MFA Perimeter Route Handlers & Stepped-Up Assurance Integration)
     │
     ▼
AUTH-010-T03 (Device Lifecycle, Pairing & Revocation Perimeter Handlers)
     │
     ▼
AUTH-010-T04 (Perimeter Resilience, Bulkhead & RFC 7807 Error Mapping Harmonization)
     │
     ▼
AUTH-010-T05 (Live Gateway-Auth End-to-End Integration Suite & Card Validation Report)
```

---

### Ticket AUTH-010-T01: Public Signing Key Distribution & Offline `LocalTokenVerifier` Integration

- **Focus**: Enable Gateway to validate JWT access tokens offline at the perimeter using Auth's public Ed25519 key, completely eliminating synchronous validation RPCs and guaranteeing that Gateway never receives Auth's private key.
- **Components to Implement**:
  - **Auth Public Key Exposure** ([`proto/securecloud/auth/v1/auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto)):
    - Add RPC `GetPublicSigningKey(GetPublicSigningKeyRequest) returns (GetPublicSigningKeyResponse)`:
      ```protobuf
      message GetPublicSigningKeyRequest {}
      message GetPublicSigningKeyResponse {
          string key_id = 1;
          string algorithm = 2; // "Ed25519"
          bytes public_key_raw = 3; // 32 bytes
          string public_key_pem = 4;
      }
      ```
    - Implement `GetPublicSigningKey` in [`src/auth/service/auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp).
  - **Gateway Configuration & Factory** ([`src/gateway/gateway_config.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/gateway_config.hpp)):
    - Add token verification mode: `token_verification_mode = "local" | "remote_rpc"`.
    - Add `auth_public_key_pem` or `auth_public_key_path` configuration.
  - **Gateway Main Wiring** ([`src/gateway/main.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/main.cpp)):
    - Instantiate `LocalTokenVerifier` when local mode is configured, using Auth's public key.
    - Fall back to `AuthServiceTokenValidator` for remote RPC validation if configured.
- **Testing**:
  - Unit tests in `tests/unit/gateway/local_token_verifier_test.cpp`:
    - Offline token verification with Ed25519 public key.
    - Rejection of forged signatures, expired tokens, invalid audiences, and tampered claims.
  - Unit tests in `tests/unit/auth/auth_service_key_test.cpp`:
    - Verification that `GetPublicSigningKey` exposes public key bytes and never private key material.

---

### Ticket AUTH-010-T02: MFA Perimeter Route Handlers & Stepped-Up Assurance Integration

- **Focus**: Implement Gateway perimeter routing and proxying for all Multi-Factor Authentication operations, enforcing stepped-up assurance (`MFA_REQUIRED`).
- **Components to Implement**:
  - **gRPC Client Extension** ([`src/gateway/grpc/auth_client_interface.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/auth_client_interface.hpp) & [`auth_service_client.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/auth_service_client.cpp)):
    - Add methods:
      * `initiate_mfa_enrollment(req, ctx)`
      * `confirm_mfa_enrollment(req, ctx)`
      * `verify_mfa_challenge(req, ctx)`
      * `disable_mfa(req, ctx)`
  - **Gateway Proxy Handlers** ([`src/gateway/http/proxy/auth_proxy_handler.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.hpp) & [`auth_proxy_handler.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.cpp)):
    - Implement route handlers:
      * `POST /api/v1/auth/mfa/enroll`: Calls `InitiateMfaEnrollment`, returns secret & OTP URI.
      * `POST /api/v1/auth/mfa/confirm`: Calls `ConfirmMfaEnrollment` with TOTP code, returns recovery codes.
      * `POST /api/v1/auth/mfa/verify`: Calls `VerifyMfaChallenge`, returns stepped-up token with `authentication_level = MFA_VERIFIED`.
      * `POST /api/v1/auth/mfa/disable`: Calls `DisableMfa` (requires `MFA_VERIFIED` assurance).
    - Register routes in `AuthProxyHandler::register_routes(Router& router)`.
  - **Stepped-Up Assurance Enforcement**:
    - Verify that routes marked `RouteAccess::Sensitive` reject primary sessions with HTTP 403 `MFA_REQUIRED`.
    - Verify that after successful verification over `/mfa/verify`, the issued token succeeds.
- **Testing**:
  - Unit tests in `tests/unit/gateway/auth_proxy_handler_mfa_test.cpp`:
    - Full coverage of all 4 MFA perimeter endpoints.
    - Verification of 403 `MFA_REQUIRED` challenge triggers.

---

### Ticket AUTH-010-T03: Device Lifecycle, Pairing & Revocation Perimeter Handlers

- **Focus**: Implement Gateway perimeter routing for device management, cross-device pairing, and cascading revocation.
- **Components to Implement**:
  - **gRPC Client Extension** ([`src/gateway/grpc/auth_client_interface.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/auth_client_interface.hpp) & [`auth_service_client.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/auth_service_client.cpp)):
    - Add methods:
      * `get_device(req, ctx)`
      * `list_user_devices(req, ctx)`
      * `initiate_device_pairing(req, ctx)`
      * `authorize_device(req, ctx)`
      * `revoke_device(req, ctx)`
  - **Gateway Proxy Handlers** ([`src/gateway/http/proxy/auth_proxy_handler.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.hpp) & [`auth_proxy_handler.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.cpp)):
    - Implement route handlers:
      * `GET /api/v1/devices`: Calls `ListUserDevices`, returns user's active and revoked devices.
      * `GET /api/v1/devices/:device_id`: Calls `GetDevice`, returns specific device state.
      * `POST /api/v1/devices/pairing`: Calls `InitiateDevicePairing`, generates short-lived pairing code.
      * `POST /api/v1/devices/:device_id/authorize`: Calls `AuthorizeDevice` with pairing code and primary/MFA credentials.
      * `DELETE /api/v1/devices/:device_id`: Calls `RevokeDevice`, executing cascading session and prekey revocation.
    - Register routes in `AuthProxyHandler::register_routes(Router& router)`.
  - **Perimeter Policy Updates** ([`src/gateway/http/auth/gateway_security_policy.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.cpp)):
    - Register parameterized rules for `/api/v1/devices/:device_id` (`GET`, `DELETE`, `POST`).
- **Testing**:
  - Unit tests in `tests/unit/gateway/auth_proxy_handler_device_test.cpp`:
    - Full coverage of device lifecycle routes.
    - Verification of cross-user boundary enforcement.

---

### Ticket AUTH-010-T04: Perimeter Resilience, Bulkhead & RFC 7807 Error Mapping Harmonization

- **Focus**: Harmonize error mapping, resilience safeguards, and downstream header propagation across all Auth proxy endpoints.
- **Components to Implement**:
  - **Bulkhead & Circuit Breaker Harmonization**:
    - Ensure all newly added MFA and Device routes acquire permits from `BulkheadManager` (category `WorkloadCategory::Auth`).
    - Record downstream gRPC errors in `CircuitBreaker`.
    - Enforce request deadline budgets via `DeadlineManager`.
  - **RFC 7807 Problem Details Transformation**:
    - Ensure all downstream gRPC statuses map cleanly:
      * `OK` $\to$ 200
      * `INVALID_ARGUMENT` $\to$ 400 (`BAD_REQUEST`)
      * `UNAUTHENTICATED` $\to$ 401 (`UNAUTHENTICATED`)
      * `PERMISSION_DENIED` $\to$ 403 (`FORBIDDEN` / `MFA_REQUIRED` / `DEVICE_MISMATCH`)
      * `NOT_FOUND` $\to$ 404 (`NOT_FOUND`)
      * `ALREADY_EXISTS` $\to$ 409 (`CONFLICT`)
      * `RESOURCE_EXHAUSTED` $\to$ 429 (`TOO_MANY_REQUESTS`)
      * `UNAVAILABLE` $\to$ 503 (`SERVICE_UNAVAILABLE`)
      * `DEADLINE_EXCEEDED` $\to$ 504 (`GATEWAY_TIMEOUT`)
  - **Downstream Header Propagation**:
    - Propagate `x-user-id`, `x-device-id`, `x-auth-level`, and `x-request-id` into downstream gRPC calls.
- **Testing**:
  - Unit tests in `tests/unit/gateway/gateway_error_mapper_test.cpp` and `tests/unit/gateway/gateway_route_registrar_test.cpp`.

---

### Ticket AUTH-010-T05: Live Gateway-Auth End-to-End Integration Suite & Card Validation Report

- **Focus**: Implement the authoritative live E2E integration test suite connecting the live HTTP/HTTPS Gateway to the live gRPC AuthService over mTLS against PostgreSQL 17, and author the card validation report.
- **Components to Implement**:
  - **Live E2E Test Suite** ([`tests/integration/gateway_auth_e2e_integration_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/gateway_auth_e2e_integration_test.cpp)):
    - Target registered in [`tests/integration/CMakeLists.txt`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/CMakeLists.txt).
    - Executed against PostgreSQL 17 on port 5433 with strict port 5432 protection:
      1. **Strict Port 5432 Protection Preflight**: Confirms immediate failure if port 5432 is referenced.
      2. **Full End-to-End Primary Login Flow**: External HTTP client posts credentials to `/api/v1/auth/login`; receives JWT and refresh token; Gateway verifies JWT offline via `LocalTokenVerifier` using Auth's public key; calls `/api/v1/users/me` successfully.
      3. **Stepped-Up MFA Challenge Flow**: Client accesses sensitive endpoint; Gateway returns 403 `MFA_REQUIRED`. Client calls `/api/v1/auth/mfa/verify` with valid TOTP; receives upgraded token; sensitive call succeeds.
      4. **Zero Private Key Exposure Audit**: Cryptographic test inspecting Gateway configuration, memory structures, and HTTP headers to assert that Auth's Ed25519 private signing key never enters Gateway.
      5. **Device Enrollment & Cascading Revocation Flow**: Client registers secondary device, pairs it, queries directory. Primary user revokes device $\to$ Gateway immediately rejects revoked device calls with 401/403.
      6. **Token Refresh & Token Reuse Detection**: Refresh token rotation via `/api/v1/auth/refresh`; replaying old token triggers compromise detection and invalidates all user sessions.
      7. **Resilience Under Downstream Outage**: Simulates downstream gRPC outage; verifies Gateway circuit breaker trips and returns RFC 7807 503 Problem Details with `Retry-After`.
  - **Comprehensive Card Validation Report** (`walkthrough-auth-010.md`):
    - Author exhaustive $\ge 1,000$-line final validation report summarizing the complete Phase 1 Authentication series, architectural verification, traceability matrix, and full test logs.
- **Testing**:
  - Complete repository test run (100% pass rate, zero regressions).
  - Clean `ninja check-format`.

---

## 4. Traceability Matrix against Acceptance Criteria

| Acceptance Criterion | Primary Implementing Ticket(s) | Verification Target |
| :--- | :--- | :--- |
| **Valid and invalid flows behave correctly end-to-end** | AUTH-010-T01 through AUTH-010-T05 | `gateway_auth_e2e_integration_test.*` |
| **Gateway never receives Auth's private signing key** | AUTH-010-T01, AUTH-010-T05 | `ZeroPrivateKeyExposureAudit`, Codebase Architecture Audit |
| **Offline token validation is cryptographically sound** | AUTH-010-T01, AUTH-010-T05 | `LocalTokenVerifierTest.*`, `OfflineTokenVerificationE2E` |
| **MFA assurance levels are strictly enforced** | AUTH-010-T02, AUTH-010-T05 | `AuthProxyHandlerMfaTest.*`, `SteppedUpMfaChallengeFlowE2E` |
| **Revoked device and compromised session states fail closed** | AUTH-010-T03, AUTH-010-T05 | `DeviceEnrollmentAndCascadingRevocationFlowE2E` |
| **Perimeter resilience safeguards downstream Auth** | AUTH-010-T04, AUTH-010-T05 | `ResilienceUnderDownstreamOutageE2E`, Bulkhead Tests |
| **Tests cover end-to-end valid and invalid flows** | AUTH-010-T05 | `securecloud_gateway_auth_e2e_integration_test` |

---

## 5. Architectural Invariants & Security Defenses

1. **Zero Private Key Ingress:** Gateway is strictly provisioned with Auth's 32-byte Ed25519 public key. Gateway performs offline asymmetric verification without needing or receiving the private signing key.
2. **Fail-Closed Perimeter Policy:** Routes default to `RouteAccess::Protected` (`min_auth_level = PRIMARY`), preventing unauthorized data leakage.
3. **Defense-in-Depth Assurance:** MFA requirements are verified at both the Gateway perimeter (`AuthorizationMiddleware`) and downstream domain engines (`AuthServiceImpl`).
4. **Environment Isolation:** Containerized PostgreSQL 17 on port 5433 with strict port 5432 prohibition.
