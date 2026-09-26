# GW-004 — Implement Access-Token Authentication Middleware
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: GW-004  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Sergey  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **GW-004** implements the SecureCloud API Gateway's **Access-Token Authentication Middleware** and establishes the request-scoped **`AuthenticatedContext`** boundary.

The Gateway serves as the single external HTTPS entry point for the entire SecureCloud platform. It intercepts all incoming client requests and enforces authentication at the external perimeter before request routing to any downstream backend microservice—including **Authentication** (`securecloud-auth`), **Messaging** (`securecloud-messaging`), and **Files** (`securecloud-files`).

```text
                                  External HTTPS / TLS 1.3
                                              │
                                              ▼
                        ┌───────────────────────────────────────────┐
                        │          SecureCloud API Gateway          │
                        │                                           │
                        │   HTTP Server / Router (GW-001, GW-002)   │
                        │   Request ID & Resource Limiters          │
                        │                                           │
                        │   ┌───────────────────────────────────┐   │
                        │   │   GW-004 Authentication Layer     │   │
                        │   │   - BearerTokenExtractor          │   │
                        │   │   - GatewaySecurityPolicy         │   │
                        │   │   - ITokenValidator               │   │
                        │   │   - AuthenticationMiddleware      │   │
                        │   │   - AuthenticatedContext          │   │
                        │   └─────────────────┬─────────────────┘   │
                        └─────────────────────┼─────────────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
     Internal mTLS  │          Internal mTLS  │          Internal mTLS  │
     DNS:gateway    │          DNS:gateway    │          DNS:gateway    │
     Target: auth   │          Target: msgs   │          Target: files  │
                    ▼                         ▼                         ▼
      ┌──────────────────────────┐ ┌────────────────────┐ ┌────────────────────┐
      │  Authentication Service  │ │ Messaging Service  │ │   Files Service    │
      │   (Session Authority)    │ │ (Conversations/E2E)│ │ (Encrypted Blobs)  │
      └──────────────────────────┘ └────────────────────┘ └────────────────────┘
```

### Strict Separation of Concerns: Gateway vs. Downstream Services

1. **Authentication Enforcement Point vs. Authentication Authority (Gateway Design 3.4)**:
   - **Gateway is the Enforcement Point**: Gateway intercepts requests, extracts credentials, enforces token validity, verifies minimum authentication assurance level (Primary vs. MFA), and blocks unauthorized traffic with standard RFC 7807 JSON errors (`401 Unauthorized`, `403 Forbidden`).
   - **Auth Service is the Authority**: Auth microservice (`securecloud-auth`) generates keys, hashes credentials, manages sessions, issues tokens, and verifies credentials. Gateway never performs password verification, database queries, or token issuance.
2. **Universal Downstream Protection**:
   - The Gateway protects **all** microservices uniformly. Whether a client requests:
     - `POST /api/v1/auth/mfa/verify` (Auth)
     - `POST /api/v1/messages/send` (Messaging)
     - `POST /api/v1/files/upload/chunk` (Files)
   - The Gateway executes the identical authentication enforcement pipeline and constructs a trusted `AuthenticatedContext` (`user_id`, `device_id`, `session_id`, `scopes`, `authentication_level`). Downstream microservices receive this trusted context over internal gRPC and never re-parse or re-authenticate raw Bearer tokens.
3. **Coarse-Grained vs. Fine-Grained Authorization (Gateway Design 3.9)**:
   - **Gateway**: Enforces coarse-grained rules (Is this route public? Does the caller possess a valid token? Does this route require `MFA_VERIFIED`? Does the token possess the required scope?).
   - **Backend Services**: Enforce fine-grained domain authorization (e.g. Messaging checks if `user_id` is a member of conversation $X$; Files checks if `user_id` is authorized to access file $Y$).

---

## 2. Key Invariants & Architectural Boundaries

1. **Zero Database Invariant on Gateway (ADR-005, Gateway Design 3.1)**:
   - Gateway owns **zero business data persistence**.
   - No database driver (`libpqxx`, `scylla`, `aws-sdk`, `clickhouse`) may be linked, included, or referenced in Gateway targets. Gateway relies entirely on in-memory validation and IPC delegation via `IAuthClient`.
2. **Observational Host PostgreSQL 14 Guard**:
   - Developer workstation host runs an active PostgreSQL 14 instance on `localhost:5432`. No Gateway test or client process may connect to, touch, or bind to port `5432`.
3. **Decoupled Parallel Development (No Hard Dependency on Lorenzo's AUTH-005)**:
   - In `GW-003`, the authoritative IPC contract `proto/securecloud/auth/v1/auth.proto` and the abstract C++ interface `IAuthClient` were finalized and committed into `main`.
   - Gateway implementation of `GW-004` interacts strictly with `IAuthClient` and the `ITokenValidator` abstraction.
   - Gateway unit tests and integration tests use mock stubs and controllable in-process gRPC test servers (`ControllableAuthService`), completely unblocking Gateway development without waiting for Lorenzo's implementation of `AUTH-005`.
4. **Fail-Closed Security Default**:
   - Routes default to **Protected**. Any route not explicitly declared in `GatewaySecurityPolicy` as public requires authentication.
   - Any missing, malformed, expired, tampered, or revoked token immediately terminates the pipeline with standard RFC 7807 problem details before reaching terminal route handlers.

---

## 3. Detailed Ticket Decomposition

```text
  GW-004-T01: RFC 6750 Bearer Token Extractor & Normalizer
       │
       ▼
  GW-004-T02: AuthenticatedContext & Token Claims Domain Model
       │
       ▼
  GW-004-T03: Token Validator Abstraction & AuthService gRPC Adapter
       │
       ▼
  GW-004-T04: Gateway Security Policy & Declarative Route Authorization
       │
       ▼
  GW-004-T05: Access Token Authentication Middleware & Pipeline Integration
       │
       ▼
  GW-004-T06: End-to-End HTTPS Authentication Integration Test Suite
```

---

### GW-004-T01 — RFC 6750 Bearer Token Extractor & Normalizer

1. **Ticket ID**: `GW-004-T01`
2. **Title**: RFC 6750 Bearer Token Extractor & Normalizer
3. **Objective**: Implement robust, zero-allocation-optimized parsing and extraction of the HTTP `Authorization: Bearer <token>` header from `httplib::Request`.
4. **Architectural Purpose**: Ensures safe, standardized ingestion of bearer tokens, shielding the rest of the authentication pipeline from malformed headers, header injection attacks, whitespace spoofing, and invalid character sets.
5. **Scope**:
   - Create `src/gateway/http/bearer_token_extractor.hpp` and `.cpp`:
     - Inspect `Authorization` header according to RFC 6750 Section 2.1.
     - Case-insensitive scheme detection (`Bearer` or `bearer`).
     - Rejection criteria:
       - Missing header (`MissingAuthorizationHeader`)
       - Unsupported authorization scheme, e.g. `Basic`, `Digest` (`InvalidScheme`)
       - Empty token string or whitespace-only token (`EmptyToken`)
       - Multiple `Authorization` headers in request (`DuplicateAuthorizationHeader`)
       - Forbidden control characters or characters outside RFC 6750 `b64token` set (`MalformedToken`)
       - Token exceeding maximum plausible length (e.g. > 4096 bytes) (`TokenTooLarge`)
     - Return monadic result: `Result<std::string, TokenExtractionError>`.
6. **Explicit Out-of-Scope**: Cryptographic signature verification or session lookup.
7. **Dependencies**: None (uses standard library and `httplib`).
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/bearer_token_extractor.hpp`
   - `src/gateway/http/bearer_token_extractor.cpp`
   - `tests/unit/gateway/bearer_token_extractor_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `proto/*`.
12. **Detailed Implementation Requirements**:
    - Constant-time or bounded search for scheme delimiter.
    - Zero throw of C++ exceptions across the interface.
13. **Testing Requirements**:
    - Comprehensive unit test suite covering valid tokens, lowercase scheme, excessive whitespace, missing header, `Basic` scheme, empty token, non-ASCII characters, and boundary lengths.
14. **Validation Commands**:
    ```bash
    cmake --build --preset dev-debug --target securecloud_bearer_token_extractor_test
    ctest --preset dev-debug -R "bearer_token_extractor_test" --output-on-failure
    ```
15. **Acceptance Criteria**: 100% test pass rate; all malformed inputs fail closed with explicit, typed error codes.

---

### GW-004-T02 — AuthenticatedContext & Token Claims Domain Model

1. **Ticket ID**: `GW-004-T02`
2. **Title**: AuthenticatedContext & Token Claims Domain Model
3. **Objective**: Define the core domain structures representing verified caller identity and claims passed to downstream route handlers and microservices.
4. **Architectural Purpose**: Establishes the authoritative internal trust boundary. Downstream handlers rely on this validated context rather than re-parsing raw credentials, preventing identity spoofing and claim tampering.
5. **Scope**:
   - Create `src/gateway/http/authenticated_context.hpp`:
     - Struct `AuthenticatedContext`:
       - `user_id`: opaque user identifier (`std::string`)
       - `device_id`: opaque device identifier (`std::string`)
       - `session_id`: active session identifier (`std::string`)
       - `authentication_level`: `AuthenticationLevel` enum (`AUTHENTICATION_LEVEL_PRIMARY`, `AUTHENTICATION_LEVEL_MFA_VERIFIED`)
       - `scopes`: list of authorized scopes (`std::vector<std::string>`)
       - `expires_at_epoch_ms`: expiration timestamp (`int64_t`)
       - Helper methods: `is_mfa_verified() const`, `has_scope(std::string_view scope) const`, `is_expired(int64_t now_epoch_ms) const`.
   - Create `src/gateway/http/token_validation_result.hpp`:
     - Monadic result representing success (`AuthenticatedContext`) or failure reason (`TokenExpired`, `SessionRevoked`, `InvalidSignature`, `MfaRequired`, `ServiceUnavailable`, `InternalError`).
6. **Explicit Out-of-Scope**: Network IPC or database queries.
7. **Dependencies**: `securecloud_proto` (for `AuthenticationLevel` enum).
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/authenticated_context.hpp`
   - `src/gateway/http/authenticated_context.cpp`
   - `src/gateway/http/token_validation_result.hpp`
   - `tests/unit/gateway/authenticated_context_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Immutable value semantics; thread-safe for concurrent read access.
    - Clean string representation for audit logging and tracing (excluding sensitive tokens).
13. **Testing Requirements**:
    - Unit tests validating scope checking, MFA status evaluation, expiration calculation, and serialization helpers.
14. **Validation Commands**:
    ```bash
    cmake --build --preset dev-debug --target securecloud_authenticated_context_test
    ctest --preset dev-debug -R "authenticated_context_test" --output-on-failure
    ```
15. **Acceptance Criteria**: 100% test pass rate; zero leaks, complete coverage of context query helpers.

---

### GW-004-T03 — Token Validator Abstraction & AuthService gRPC Adapter

1. **Ticket ID**: `GW-004-T03`
2. **Title**: Token Validator Abstraction & AuthService gRPC Adapter
3. **Objective**: Implement the `ITokenValidator` interface and its concrete adapter delegating session and token verification to `IAuthClient` over internal mTLS.
4. **Architectural Purpose**: Decouples token validation logic from HTTP handling and provides a pluggable boundary for mock testing, local cryptographic caching, and resilient gRPC error handling.
5. **Scope**:
   - Create `src/gateway/http/token_validator_interface.hpp`:
     - Pure virtual interface:
       ```cpp
       class ITokenValidator {
       public:
           virtual ~ITokenValidator() = default;
           virtual Result<AuthenticatedContext, TokenValidationError> validate(
               const std::string& token,
               const std::string& session_id = "") = 0;
       };
       ```
   - Create `src/gateway/http/auth_service_token_validator.hpp` and `.cpp`:
     - Injects `std::shared_ptr<IAuthClient>` (from GW-003).
     - Calls `IAuthClient::validate_session()` with bounded `ClientCallContext` (e.g. 500ms timeout).
     - Implements thread-safe short-lived TTL cache (bounded size, e.g. 10 seconds TTL) to reduce gRPC traffic on repeated requests while maintaining rapid revocation propagation.
     - Translates gRPC responses and errors into typed `TokenValidationError`:
       - `is_valid == true` -> returns `AuthenticatedContext`
       - `is_valid == false` -> returns `SessionRevoked` or `InvalidToken`
       - gRPC `DEADLINE_EXCEEDED` / `UNAVAILABLE` -> returns `ServiceUnavailable`
6. **Explicit Out-of-Scope**: Handling HTTP headers or writing HTTP response bodies.
7. **Dependencies**: GW-003 (`IAuthClient`, `ClientCallContext`, `DependencyError`).
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/token_validator_interface.hpp`
   - `src/gateway/http/auth_service_token_validator.hpp`
   - `src/gateway/http/auth_service_token_validator.cpp`
   - `tests/unit/gateway/token_validator_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/gateway/grpc/*`.
12. **Detailed Implementation Requirements**:
    - Cache eviction is thread-safe (`std::mutex`).
    - Cache entries store expiration timestamp and invalidate proactively.
13. **Testing Requirements**:
    - Google Mock tests verifying: valid session conversion, invalid session failure, cache hit avoiding second gRPC call, cache expiration triggering gRPC call, and Auth service outage returning `ServiceUnavailable`.
14. **Validation Commands**:
    ```bash
    cmake --build --preset dev-debug --target securecloud_token_validator_test
    ctest --preset dev-debug -R "token_validator_test" --output-on-failure
    ```
15. **Acceptance Criteria**: 100% test pass rate; all error codes mapped accurately without leaking exceptions.

---

### GW-004-T04 — Gateway Security Policy & Declarative Route Authorization

1. **Ticket ID**: `GW-004-T04`
2. **Title**: Gateway Security Policy & Declarative Route Authorization
3. **Objective**: Implement declarative route authorization policy configuring authentication requirements, minimum assurance levels, and required scopes per route.
4. **Architectural Purpose**: Provides a centralized, auditable security policy rule engine that determines whether an endpoint is public, protected, or MFA-sensitive, preventing accidental exposure of sensitive routes.
5. **Scope**:
   - Create `src/gateway/http/gateway_security_policy.hpp` and `.cpp`:
     - Route security categories:
       - `RouteAccess::Public`: Anonymous access allowed (e.g. `/health/live`, `/health/ready`, `/api/v1/auth/login`, `/api/v1/auth/register`).
       - `RouteAccess::Protected`: Requires valid `AuthenticatedContext` (e.g. `/api/v1/user/profile`, `/api/v1/messages/*`, `/api/v1/files/*`).
       - `RouteAccess::Sensitive`: Requires valid token with `AUTHENTICATION_LEVEL_MFA_VERIFIED` (e.g. `/api/v1/auth/device/register`, `/api/v1/auth/security/keys`).
     - Scope requirement configuration (e.g. requires scope `files:read`, `messages:write`).
     - Prefix matching and exact path matching rules.
     - **Fail-closed default**: Unregistered paths default to `RouteAccess::Protected`.
     - Policy evaluation method: `evaluate(method, path) -> RouteSecurityRule`.
6. **Explicit Out-of-Scope**: Fine-grained business logic authorization (e.g. group membership, file ownership).
7. **Dependencies**: None.
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/gateway_security_policy.hpp`
   - `src/gateway/http/gateway_security_policy.cpp`
   - `tests/unit/gateway/gateway_security_policy_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Thread-safe rule evaluation.
    - Zero regex compilation overhead on hot request path (efficient prefix/path matching).
13. **Testing Requirements**:
    - Unit tests validating exact route match, wildcard/prefix match, public bypass, MFA requirement verification, scope evaluation, and default fail-closed behavior for unknown paths.
14. **Validation Commands**:
    ```bash
    cmake --build --preset dev-debug --target securecloud_gateway_security_policy_test
    ctest --preset dev-debug -R "gateway_security_policy_test" --output-on-failure
    ```
15. **Acceptance Criteria**: 100% test pass rate; unknown paths fail closed to protected status.

---

### GW-004-T05 — Access Token Authentication Middleware & Pipeline Integration

1. **Ticket ID**: `GW-004-T05`
2. **Title**: Access Token Authentication Middleware & Pipeline Integration
3. **Objective**: Implement `AuthenticationMiddleware` and integrate it into the Gateway's `Router` pipeline, binding verified `AuthenticatedContext` to the request execution scope.
4. **Architectural Purpose**: Enforces the authentication boundary on live HTTP traffic. Invalid requests are terminated immediately with RFC 7807 problem details; valid requests pass downstream enriched with authoritative caller identity.
5. **Scope**:
   - Create `src/gateway/http/authentication_middleware.hpp` and `.cpp`:
     - Inherits from `securecloud::gateway::http::Middleware`.
     - Injects `std::shared_ptr<GatewaySecurityPolicy>` and `std::shared_ptr<ITokenValidator>`.
     - Intercepts incoming `httplib::Request`:
       1. Evaluates path against `GatewaySecurityPolicy`.
       2. If `RouteAccess::Public`: calls `next(req, res)` immediately.
       3. If `RouteAccess::Protected` or `Sensitive`:
          - Extracts token via `BearerTokenExtractor`.
          - Validates token via `ITokenValidator`.
          - Asserts required `AuthenticationLevel` (returns 403 Forbidden with `INSUFFICIENT_AUTHENTICATION_LEVEL` if route requires MFA but token is primary-only).
          - Asserts required scopes (returns 403 Forbidden with `INSUFFICIENT_SCOPE` if required scope missing).
          - On failure: writes RFC 7807 JSON error response via `ErrorMapper`:
            - 401 Unauthorized (`UNAUTHENTICATED`, `INVALID_TOKEN`, `TOKEN_EXPIRED`, `SESSION_REVOKED`)
            - 403 Forbidden (`MFA_REQUIRED`, `FORBIDDEN`)
            - 503 Service Unavailable (`SERVICE_UNAVAILABLE` on backend outage)
          - On success: binds `AuthenticatedContext` to request context storage and invokes `next(req, res)`.
   - Update `src/gateway/http/router.{hpp,cpp}`:
     - Provide context-aware route registration helper or request context lookup helper `get_authenticated_context(req)`.
6. **Explicit Out-of-Scope**: Microservice dispatch (owned by GW-006).
7. **Dependencies**: GW-004-T01 through GW-004-T04, GW-001 (`Middleware`, `Router`, `ErrorMapper`).
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/authentication_middleware.hpp`
   - `src/gateway/http/authentication_middleware.cpp`
   - `tests/unit/gateway/authentication_middleware_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/http/router.hpp`
    - `src/gateway/http/router.cpp`
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `proto/*`.
12. **Detailed Implementation Requirements**:
    - Thread-safe context storage and lookup.
    - Correct propagation of `x-request-id` on all error responses.
13. **Testing Requirements**:
    - Unit tests covering: public bypass, missing token rejection, invalid token rejection, expired token rejection, MFA requirement enforcement, scope enforcement, context availability in route handler, and backend 503 handling.
14. **Validation Commands**:
    ```bash
    cmake --build --preset dev-debug --target securecloud_authentication_middleware_test
    ctest --preset dev-debug -R "authentication_middleware_test" --output-on-failure
    ```
15. **Acceptance Criteria**: 100% test pass rate; protected routes impossible to reach without valid authentication.

---

### GW-004-T06 — End-to-End HTTPS Authentication Integration Test Suite

1. **Ticket ID**: `GW-004-T06`
2. **Title**: End-to-End HTTPS Authentication Integration Test Suite
3. **Objective**: Implement comprehensive live integration tests in `tests/integration/gateway_auth_middleware_integration_test.cpp` validating the complete authentication pipeline over live TLS 1.3 and mTLS network sockets.
4. **Architectural Purpose**: Proves that external HTTPS clients authenticate seamlessly against the Gateway, that the Gateway verifies tokens against an Auth microservice over internal mTLS, and that downstream services (Files, Messaging, User) receive verified context without security leaks.
5. **Scope**:
   - Create `tests/integration/gateway_auth_middleware_integration_test.cpp`:
     - Spawns live `HttpsServer` (TLS 1.3) on ephemeral loopback port (`127.0.0.1:0`).
     - Spawns live in-process `AuthService` gRPC server (mTLS) on ephemeral port (`127.0.0.1:0`).
     - Configures Gateway `Router` with `AuthenticationMiddleware` and mock protected/sensitive route handlers.
     - **Test Case 1 (Valid Access Token on Protected Route)**:
       - Client sends HTTPS GET with `Authorization: Bearer <valid-token>`.
       - Gateway validates via Auth gRPC, binds `AuthenticatedContext`.
       - Handler receives request, echoes back `user_id` and `session_id`; returns 200 OK.
     - **Test Case 2 (Public Endpoint Access Without Credentials)**:
       - Client sends HTTPS GET to `/health/live` without `Authorization` header; returns 200 OK.
     - **Test Case 3 (Missing Authorization Header on Protected Route)**:
       - Client sends HTTPS GET to protected endpoint without credentials; returns 401 Unauthorized with RFC 7807 JSON.
     - **Test Case 4 (Unsupported Scheme Rejection)**:
       - Client sends `Authorization: Basic dXNlcjpwYXNz`; returns 401 Unauthorized.
     - **Test Case 5 (Malformed / Tampered Token Rejection)**:
       - Client sends corrupted token string; returns 401 Unauthorized (`INVALID_TOKEN`).
     - **Test Case 6 (Revoked / Expired Session Rejection)**:
       - Server marks session invalid/revoked; returns 401 Unauthorized (`SESSION_REVOKED`).
     - **Test Case 7 (MFA Assurance Level Enforcement)**:
       - Sensitive route requires `AUTHENTICATION_LEVEL_MFA_VERIFIED`.
       - Primary-only token rejected with 403 Forbidden.
       - MFA-verified token accepted with 200 OK.
     - **Test Case 8 (Downstream Auth Service Outage Fail-Closed)**:
       - Auth service shut down; subsequent protected request fails closed with 503 Service Unavailable without hanging Gateway worker threads.
     - **Test Case 9 (Zero Database / Host Port 5432 Invariant Verification)**.
   - Register target in `tests/integration/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Real database writes in Auth (in-process mock server provides controlled state).
7. **Dependencies**: GW-004-T01 through GW-004-T05, GW-002, GW-003.
8. **Exact Repository Starting Point**: `tests/integration/CMakeLists.txt`.
9. **Files/Directories to Create**:
   - `tests/integration/gateway_auth_middleware_integration_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `tests/integration/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `deploy/compose/*`.
12. **Detailed Implementation Requirements**:
    - Ephemeral loopback ports (`127.0.0.1:0`).
    - Clean teardown with zero thread leaks.
13. **Testing Requirements**:
    - Automated execution under CTest across macOS, Linux, and Windows (MSVC/MinGW).
14. **Validation Commands**:
    ```bash
    cmake --build --preset dev-debug --target securecloud_gateway_auth_middleware_integration_test
    ctest --preset dev-debug -R "gateway_auth_middleware_integration_test" --output-on-failure
    python3 scripts/verify-local.py --preset dev-debug
    ```
15. **Acceptance Criteria**: All 9 integration tests pass 100% reliably; zero hangs, zero database linking.

---

## 4. Quality Gate & Sign-Off Checklist

Before Card **GW-004** can be submitted for review and merged into `main`, the developer must verify:

- [ ] RFC 6750 Bearer token parsing strictly rejects invalid schemes, multi-headers, control characters, and oversize headers (`GW-004-T01`).
- [ ] `AuthenticatedContext` is immutable and provides clean query helpers for identity, scopes, and MFA level (`GW-004-T02`).
- [ ] `ITokenValidator` abstracts validation and delegates to `IAuthClient` with bounded timeout and short-lived caching (`GW-004-T03`).
- [ ] `GatewaySecurityPolicy` defaults to protected status (fail-closed) and accurately identifies public and MFA-sensitive routes (`GW-004-T04`).
- [ ] `AuthenticationMiddleware` blocks unauthorized requests before reaching terminal route handlers (`GW-004-T05`).
- [ ] Live integration test suite verifies HTTPS TLS 1.3 to internal mTLS gRPC pipeline across all status codes (`GW-004-T06`).
- [ ] Zero database headers, libraries, or connection strings are present in Gateway source files (ADR-005).
- [ ] Host PostgreSQL on `localhost:5432` remains completely untouched and unreferenced.
- [ ] All 261 existing tests plus all new GW-004 tests pass cleanly via `python3 scripts/verify-local.py`.
- [ ] Code is 100% compliant with `.clang-format` and passes with zero compiler warnings under `-Wall -Wextra -Werror`.
