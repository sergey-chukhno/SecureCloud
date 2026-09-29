# GW-007: Implement Route/Scope Authorization — Ticket Decomposition

**Milestone**: `GW-007`  
**Card Title**: Implement route/scope authorization  
**Goal**: Implement coarse scope and assurance-level authorization at the Gateway perimeter while preserving backend fine-grained authorization.  
**Dependencies**: `GW-005` (AuthenticatedContext), `AUTH-006` (Token/Assurance Level Definitions)  
**Status**: Ready for Implementation  

---

## 1. Architectural Analysis: Existing Components vs. GW-007 Scope

### What Has Already Been Implemented (GW-001 through GW-006)
To avoid redundant code and build coherently on existing abstractions, we recognize:
1. **HTTP Routing & Pipeline Engine (`GW-001`, `GW-002`)**:
   - `Router` (`src/gateway/http/router.hpp`) supporting pre-routing handlers, middleware pipelines, and endpoint routing.
   - `HttpsServer` and `HttpRedirectServer` with strict TLS 1.3 configuration and port 80 -> 443 redirection.
2. **mTLS Downstream Client Infrastructure (`GW-003`)**:
   - `GrpcChannelManager` establishing authenticated mTLS channels with downstream microservices.
   - `AuthServiceClient` wrapping `securecloud::auth::v1::AuthService` RPCs.
3. **Perimeter Authentication Middleware (`GW-004`)**:
   - `GatewaySecurityPolicy` (`src/gateway/http/auth/gateway_security_policy.hpp`) classifying routes (`Public`, `Protected`, `Sensitive`).
   - `AuthenticationMiddleware` (`src/gateway/http/auth/authentication_middleware.hpp`) performing cryptographic token verification and extracting claims into `AuthenticatedContext`.
4. **Authoritative Request Context & Anti-Fabrication (`GW-005`)**:
   - `AuthenticatedContext` (`src/gateway/http/auth/authenticated_context.hpp`) carrying verified caller identities (`user_id`, `device_id`, `session_id`, `auth_level`, `scopes`).
   - `RequestContext` and `ScopedRequestContext` managing thread-local request lifecycle.
   - `HeaderSanitizer` stripping spoofed perimeter identity headers.
5. **Gateway Routing & Reverse Proxying (`GW-006`)**:
   - `AuthProxyHandler` dispatching HTTP requests to gRPC backend with context propagation.
   - `GatewayRouteRegistrar` assembling production route endpoints into `Router`.

---

### What GW-007 Delivers: Coarse Perimeter Authorization vs. Backend Fine-Grained Authorization

While authentication establishes **who the caller is** (`AuthenticatedContext`), the Gateway currently forwards all authenticated requests regardless of whether the token grants permission for the target route.

**GW-007 implements Coarse Scope and Assurance Authorization at the API Gateway perimeter**:
1. **Separation of Concerns (ADR-001, ADR-005)**:
   - **Gateway Responsibility (Coarse Perimeter Gatekeeper)**: Rejects requests immediately at the network edge if the caller lacks required permission scopes (e.g., `messages:write`, `files:upload`, `admin:*`), fails minimum assurance level (`BASIC_AUTHENTICATED` vs `MFA_AUTHENTICATED`), or misses required device attestation binding. This shields downstream services and databases from unprivileged traffic.
   - **Microservice Responsibility (Fine-Grained Domain Logic)**: Once the request passes the Gateway, the owning backend microservice evaluates fine-grained business logic (e.g., "Is user A a participant in chat room X?", "Has user B blocked user A?", "Does tenant Y have storage quota for file Z?").
2. **Enterprise Route Authorization Matrix**:
   - A centralized, declarative routing security policy extending `GatewaySecurityPolicy` that maps every public, protected, and sensitive route to explicit required scopes, alternative scopes, assurance levels, and device binding constraints.
3. **Hierarchical & Wildcard Scope Matching (`ScopeMatcher`)**:
   - Supports namespaced scopes (`<domain>:<action>`), domain wildcards (`messages:*`), global superuser wildcard (`*`), and compound Boolean logic (AND / OR).
4. **Standardized RFC 7807 Perimeter Rejection**:
   - Emits structured problem details for `403 Forbidden` (`insufficient_scope`, `mfa_required`, `device_binding_required`) before any backend gRPC call is dispatched.
5. **Zero Database & Zero Business Logic Invariants**:
   - Preserves ADR-005: the Gateway performs authorization purely against in-memory claims in `AuthenticatedContext` and route security rules, without database queries or business state.

---

## 2. Detailed Ticket Breakdown

### GW-007-T01 — Hierarchical & Wildcard Scope Evaluator (`ScopeMatcher`)

1. **Ticket ID**: `GW-007-T01`
2. **Title**: Hierarchical & Wildcard Scope Evaluator (`ScopeMatcher`)
3. **Objective**: Implement a high-performance in-memory scope evaluation engine supporting exact matching, domain wildcards (`<domain>:*`), global wildcards (`*`), and compound requirements (all-of / any-of).
4. **Architectural Purpose**: Provides the core policy evaluation primitive used by `AuthorizationMiddleware` to verify caller scopes against route requirements.
5. **Scope**:
   - Create `src/gateway/http/auth/scope_matcher.hpp` and `scope_matcher.cpp`:
     - Scope syntax: `<domain>:<action>` (e.g., `messages:read`, `messages:send`, `files:upload`, `auth:revoke`, `audit:read`).
     - Global wildcard `*`: Matches any requested scope.
     - Domain wildcard `<domain>:*`: Matches any action within the specified domain (e.g., `messages:*` satisfies `messages:read`, `messages:send`, `messages:delete`).
     - Exact match: `domain:action` matches only identical `domain:action`.
     - Evaluation functions:
       - `bool matches(std::string_view granted_scope, std::string_view required_scope)`
       - `bool has_scope(const std::vector<std::string>& granted_scopes, std::string_view required_scope)`
       - `bool has_all_scopes(const std::vector<std::string>& granted_scopes, const std::vector<std::string>& required_scopes)`
       - `bool has_any_scope(const std::vector<std::string>& granted_scopes, const std::vector<std::string>& alternative_scopes)`
   - Constant-time safety where appropriate; zero dynamic heap allocations during evaluation when feasible.
6. **Explicit Out-of-Scope**: HTTP middleware integration (covered in `GW-007-T03`).
7. **Dependencies**: None (self-contained security utility).
8. **Exact Repository Starting Point**: `src/gateway/http/auth/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/auth/scope_matcher.hpp`
   - `src/gateway/http/auth/scope_matcher.cpp`
   - `tests/unit/gateway/scope_matcher_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Testing Requirements**:
    - Unit tests covering:
      - Exact match evaluation (positive and negative).
      - Domain wildcard matching (`messages:*` grants `messages:read` but rejects `files:read`).
      - Global wildcard matching (`*` grants any scope).
      - Multi-level / compound scope requirements (all-of AND, any-of OR).
      - Edge cases: empty scope lists, malformed syntax (missing colon, whitespace), case sensitivity.
12. **Acceptance Criteria**: 100% test pass rate in CTest; clean memory sanitizers; zero allocations in tight loops.

---

### GW-007-T02 — Enterprise Route Authorization Matrix (`GatewaySecurityPolicy`)

1. **Ticket ID**: `GW-007-T02`
2. **Title**: Enterprise Route Authorization Matrix in `GatewaySecurityPolicy`
3. **Objective**: Expand `GatewaySecurityPolicy` with the canonical Enterprise Route Authorization Matrix specifying required scopes, alternative scopes, minimum assurance level (`AuthLevel`), and device binding requirements for every route.
4. **Architectural Purpose**: Serves as the declarative single source of truth for Gateway perimeter security enforcement.
5. **Scope**:
   - Update `src/gateway/http/auth/gateway_security_policy.hpp` and `.cpp`:
     - Define `RouteSecurityRule`:
       - `RouteClassification classification` (`PUBLIC`, `PROTECTED`, `SENSITIVE`)
       - `std::vector<std::string> required_scopes` (caller must possess all of these, unless satisfied by wildcard)
       - `std::vector<std::string> alternative_scopes` (caller must possess at least one of these, if specified)
       - `AuthLevel min_auth_level` (`NONE`, `BASIC_AUTHENTICATED`, `MFA_AUTHENTICATED`)
       - `bool require_device_bound` (requires valid non-empty `device_id` in context)
     - Implement canonical Enterprise Route Authorization Matrix covering all platform domains:
       - **Auth Service**:
         - `POST /api/v1/auth/login`: `PUBLIC`, `min_auth_level = NONE`
         - `POST /api/v1/auth/refresh`: `PUBLIC`, `min_auth_level = NONE`
         - `POST /api/v1/auth/revoke`: `PROTECTED`, `required_scopes = {"auth:revoke"}`, `min_auth_level = BASIC_AUTHENTICATED`
         - `GET /api/v1/auth/me`: `PROTECTED`, `required_scopes = {"user:profile"}`, `min_auth_level = BASIC_AUTHENTICATED`
         - `POST /api/v1/auth/device/register`: `SENSITIVE`, `required_scopes = {"device:manage"}`, `min_auth_level = MFA_AUTHENTICATED`, `require_device_bound = true`
       - **Messaging Service**:
         - `POST /api/v1/messages/send`: `PROTECTED`, `required_scopes = {"messages:send"}`, `min_auth_level = BASIC_AUTHENTICATED`
         - `GET /api/v1/messages/inbox`: `PROTECTED`, `required_scopes = {"messages:read"}`, `min_auth_level = BASIC_AUTHENTICATED`
         - `GET /api/v1/messages/history`: `PROTECTED`, `required_scopes = {"messages:read"}`, `min_auth_level = BASIC_AUTHENTICATED`
       - **Files Service**:
         - `POST /api/v1/files/upload`: `PROTECTED`, `required_scopes = {"files:upload"}`, `min_auth_level = BASIC_AUTHENTICATED`
         - `GET /api/v1/files/download`: `PROTECTED`, `required_scopes = {"files:read"}`, `min_auth_level = BASIC_AUTHENTICATED`
         - `DELETE /api/v1/files/delete`: `PROTECTED`, `required_scopes = {"files:delete"}`, `min_auth_level = BASIC_AUTHENTICATED`
       - **Audit Service**:
         - `GET /api/v1/audit/logs`: `SENSITIVE`, `required_scopes = {"audit:read"}`, `min_auth_level = MFA_AUTHENTICATED`
     - Provide prefix and exact route rule resolution: `std::optional<RouteSecurityRule> match_rule(std::string_view method, std::string_view path) const`.
6. **Explicit Out-of-Scope**: Fine-grained data ownership checks (owned by microservices).
7. **Dependencies**: `GW-007-T01` (`ScopeMatcher`), `GW-004` (`GatewaySecurityPolicy`).
8. **Exact Repository Starting Point**: `src/gateway/http/auth/gateway_security_policy.hpp`.
9. **Files/Directories That May Be Modified**:
   - `src/gateway/http/auth/gateway_security_policy.hpp`
   - `src/gateway/http/auth/gateway_security_policy.cpp`
   - `tests/unit/gateway/gateway_security_policy_test.cpp`
10. **Testing Requirements**:
    - Unit tests verifying:
      - Rule lookup for exact routes and path prefixes.
      - Default-deny semantics for unregistered protected/sensitive paths.
      - Accurate rule retrieval for Public, Protected, and Sensitive endpoints across all 4 services.
11. **Acceptance Criteria**: 100% test pass rate; all enterprise routes covered in matrix.

---

### GW-007-T03 — Scope & Assurance Authorization Middleware (`AuthorizationMiddleware`)

1. **Ticket ID**: `GW-007-T03`
2. **Title**: Scope & Assurance Authorization Middleware (`AuthorizationMiddleware`)
3. **Objective**: Implement `AuthorizationMiddleware` that evaluates `AuthenticatedContext` against `RouteSecurityRule`, rejecting unauthorized requests with RFC 7807 problem details before backend proxy invocation.
4. **Architectural Purpose**: Enforces the coarse security boundary between authentication verification and backend dispatching in the Gateway pipeline.
5. **Scope**:
   - Create `src/gateway/http/auth/authorization_middleware.hpp` and `.cpp`:
     - Executes after `AuthenticationMiddleware` in the `Router` pipeline.
     - Retrieves `RouteSecurityRule` from `GatewaySecurityPolicy`.
     - If route is `PUBLIC`: passes request downstream immediately.
     - If route is `PROTECTED` or `SENSITIVE`:
       - Retrieves `AuthenticatedContext` from `RequestContext`. If missing, aborts with `401 Unauthorized`.
       - **Assurance Level Evaluation**: If `ctx.auth_level() < rule.min_auth_level`, aborts with `403 Forbidden` (`mfa_required` RFC 7807 problem details: `"title": "MFA Required"`, `"detail": "This route requires multi-factor authentication"`).
       - **Device Attestation Evaluation**: If `rule.require_device_bound && ctx.device_id().empty()`, aborts with `403 Forbidden` (`device_binding_required` RFC 7807 problem details).
       - **Scope Evaluation**: Uses `ScopeMatcher` to check `required_scopes` and `alternative_scopes`. If unsatisfied, aborts with `403 Forbidden` (`insufficient_scope` RFC 7807 problem details including missing scopes).
     - If all checks pass, invokes next handler in chain.
   - Wire `AuthorizationMiddleware` into `GatewayRouteRegistrar` / `Router` pipeline.
6. **Explicit Out-of-Scope**: Rate limiting (deferred to `GW-009`).
7. **Dependencies**: `GW-007-T01`, `GW-007-T02`, `GW-005` (`AuthenticatedContext`).
8. **Exact Repository Starting Point**: `src/gateway/http/auth/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/auth/authorization_middleware.hpp`
   - `src/gateway/http/auth/authorization_middleware.cpp`
   - `tests/unit/gateway/authorization_middleware_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/http/gateway_route_registrar.cpp`
    - `src/gateway/CMakeLists.txt`
    - `tests/unit/CMakeLists.txt`
11. **Testing Requirements**:
    - Unit tests validating:
      - Public routes bypass authorization without token.
      - Protected route passes with exact scope and basic auth level.
      - Protected route passes with wildcard scope (`messages:*` or `*`).
      - Rejection with 403 `insufficient_scope` when caller lacks required scope.
      - Rejection with 403 `mfa_required` when accessing Sensitive route with basic auth level.
      - Rejection with 403 `device_binding_required` when device bound route lacks device ID.
      - RFC 7807 problem details format conformity on all rejection responses.
12. **Acceptance Criteria**: 100% test pass rate in CTest; downstream handlers never invoked on 403 rejections.

---

### GW-007-T04 — End-to-End Scope & Route Authorization Integration Test Suite

1. **Ticket ID**: `GW-007-T04`
2. **Title**: End-to-End Scope & Route Authorization Integration Test Suite
3. **Objective**: Implement comprehensive end-to-end integration tests over live TLS 1.3 verifying that insufficient scope or assurance is rejected before forwarding to mock backend services.
4. **Architectural Purpose**: Proves that the Gateway perimeter gatekeeper operates correctly across the real HTTPS transport stack under multi-platform environments (macOS, Linux, Windows MinGW, Windows MSVC).
5. **Scope**:
   - Create `tests/integration/gateway_authorization_integration_test.cpp`:
     - Spawns live `HttpsServer` on loopback with ephemeral port and TLS 1.3.
     - Spawns mock backend `AuthService` on ephemeral gRPC port over mTLS.
     - Wires `AuthenticationMiddleware`, `AuthorizationMiddleware`, and `AuthProxyHandler`.
     - Test Scenarios:
       1. **Valid Token + Exact Scope (`auth:revoke`)**: Returns HTTP 200 OK; backend gRPC receives request.
       2. **Valid Token + Wildcard Scope (`auth:*` or `*`)**: Returns HTTP 200 OK.
       3. **Valid Token + Insufficient Scope (e.g. token only has `messages:read`)**: Returns HTTP 403 Forbidden with `insufficient_scope` problem details; backend gRPC receives zero calls.
       4. **Sensitive Endpoint (`/api/v1/auth/device/register`) with Basic Auth Level**: Returns HTTP 403 Forbidden with `mfa_required`; backend receives zero calls.
       5. **Sensitive Endpoint with MFA Auth Level & Device ID**: Returns HTTP 200 OK.
       6. **Public Endpoint (`/api/v1/auth/login`) with no credentials**: Returns expected public response or 400 Bad Request on empty payload, never 401 or 403.
     - Use custom `main()` calling `::TerminateProcess(::GetCurrentProcess(), exit_code)` on `_WIN32` to guarantee clean CRT exit without thread hangs.
6. **Explicit Out-of-Scope**: Backend fine-grained database checks.
7. **Dependencies**: `GW-007-T01`, `GW-007-T02`, `GW-007-T03`.
8. **Exact Repository Starting Point**: `tests/integration/`.
9. **Files/Directories to Create**:
   - `tests/integration/gateway_authorization_integration_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `tests/integration/CMakeLists.txt`
11. **Testing Requirements**:
    - Run under CTest and `verify-local.py`.
    - Zero memory leaks, clean teardown, 100% test pass rate.
12. **Acceptance Criteria**: All authorization scenarios verified over live TLS; zero leaks or crashes.

---

## 3. Summary of Deliverables & Verification Matrix

| Ticket | Deliverable | Primary Component | Tests |
|---|---|---|---|
| **GW-007-T01** | `ScopeMatcher` | `src/gateway/http/auth/scope_matcher.{hpp,cpp}` | `tests/unit/gateway/scope_matcher_test.cpp` |
| **GW-007-T02** | Enterprise Route Authorization Matrix | `src/gateway/http/auth/gateway_security_policy.{hpp,cpp}` | `tests/unit/gateway/gateway_security_policy_test.cpp` |
| **GW-007-T03** | `AuthorizationMiddleware` | `src/gateway/http/auth/authorization_middleware.{hpp,cpp}` | `tests/unit/gateway/authorization_middleware_test.cpp` |
| **GW-007-T04** | End-to-End Authorization Integration Suite | `tests/integration/gateway_authorization_integration_test.cpp` | CTest integration test suite |
