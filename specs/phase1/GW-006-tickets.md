# GW-006: Implement Gateway Routing — Ticket Decomposition

**Milestone**: `GW-006`  
**Card Title**: Implement Gateway routing  
**Goal**: Route requests to owning services without backend business logic or database access.  
**Dependencies**: `GW-003` (Gateway-to-Auth mTLS Client), `GW-005` (AuthenticatedContext)  
**Status**: Ready for Implementation  

---

## 1. Architectural Analysis: Existing Components vs. GW-006 Scope

### What Has Already Been Implemented (GW-001 through GW-005)
To prevent code duplication and avoid re-implementing what already exists, we recognize the following established foundation:
1. **HTTP Routing & Middleware Infrastructure (`GW-001`, `GW-002`)**:
   - `Router` (`src/gateway/http/router.hpp`) supporting HTTP methods (`GET`, `POST`, `PUT`, `DELETE`), middleware pipelines, and custom route handlers.
   - `HttpsServer` and `HttpRedirectServer` with strict TLS 1.3 configuration and port 80 -> 443 redirection.
2. **mTLS Downstream Channel Management (`GW-003`)**:
   - `GrpcChannelManager` (`src/gateway/grpc/channel_manager.hpp`) establishing authenticated mTLS channels with downstream microservices (`auth`, `messaging`, `files`, `audit`).
   - `AuthServiceClient` (`src/gateway/grpc/auth_service_client.hpp`) wrapping `securecloud::auth::v1::AuthService` RPCs.
3. **Perimeter Authentication & Security Policy (`GW-004`)**:
   - `GatewaySecurityPolicy` (`src/gateway/http/auth/gateway_security_policy.hpp`) classifying routes as Public, Protected, or Sensitive.
   - `AuthenticationMiddleware` (`src/gateway/http/auth/authentication_middleware.hpp`) performing token validation and route authorization before dispatch.
4. **Request-Scoped Authenticated Context (`GW-005`)**:
   - `AuthenticatedContext` (`src/gateway/http/auth/authenticated_context.hpp`) carrying opaque caller identities (`user_id`, `device_id`, `session_id`, `auth_level`, `scopes`).
   - `RequestContext` & `ScopedRequestContext` managing request lifecycle and thread-local state.
   - `Router::current_authenticated_context()` and `Router::current_request_context()` accessors.
   - `HeaderSanitizer` stripping perimeter identity headers.

### What GW-006 Delivers
While the transport, authentication, and context foundations are complete, **the Gateway currently lacks production request dispatching to owning backend microservices**:
1. **HTTP-to-gRPC Service Proxy Handlers**: Translating external REST/JSON HTTP calls into internal strongly-typed mTLS gRPC calls, propagating request correlation ID and authenticated caller identity into `ClientCallContext`.
2. **Centralized Gateway Route Registrar**: Assembling the production route registry in `Router` and wiring it into `src/gateway/main.cpp`.
3. **Deterministic Error & Status Mapping**: Translating gRPC status codes into RFC 7807 problem details via `ErrorMapper`.
4. **End-to-End Live Routing Integration Tests**: Verifying that HTTP requests to public and protected endpoints route through the Gateway to the backend service and return expected responses over live HTTPS and mTLS.
5. **Zero Backend Logic & Zero Database Invariants**: Preserving ADR-001 and ADR-005: Gateway contains zero business logic, zero persistence libraries, and zero access to database port 5432.

---

## 2. Detailed Ticket Breakdown

### GW-006-T01 — Auth Microservice HTTP-to-gRPC Proxy Handler (`AuthProxyHandler`)

1. **Ticket ID**: `GW-006-T01`
2. **Title**: Auth Microservice HTTP-to-gRPC Proxy Handler
3. **Objective**: Implement the HTTP-to-gRPC dispatching handler for Auth microservice endpoints, mapping JSON request/response payloads to gRPC messages with correlation ID and authenticated context propagation.
4. **Architectural Purpose**: Acts as the reverse proxy boundary translating client HTTP/JSON interactions into internal `IAuthClient` gRPC calls without containing business logic or database access.
5. **Scope**:
   - Create `src/gateway/http/proxy/auth_proxy_handler.hpp` and `auth_proxy_handler.cpp`:
     - **Public Routes**:
       - `POST /api/v1/auth/login`: Parses `{ "identifier", "credential", "device_id" }`, invokes `IAuthClient::authenticate()`, maps response to HTTP 200 with tokens or HTTP 401 on bad credentials.
       - `POST /api/v1/auth/refresh`: Parses `{ "refresh_token" }`, invokes `IAuthClient::refresh_session()`, returns HTTP 200 with fresh tokens.
     - **Protected Routes**:
       - `POST /api/v1/auth/revoke`: Uses `ctx.session_id()`, invokes `IAuthClient::revoke_session()`, returns HTTP 200.
       - `GET /api/v1/auth/me`: Uses `ctx.user_id()`, invokes `IAuthClient::get_user()`, returns user profile summary.
     - **Sensitive Routes**:
       - `POST /api/v1/auth/device/register`: Uses `ctx.user_id()`, parses device registration metadata, invokes `IAuthClient::register_device()`, returns HTTP 200.
   - Enforce JSON validation (HTTP 400 Bad Request on malformed JSON).
   - Propagate `request_id` from `RequestContext` into `ClientCallContext`.
   - Map gRPC errors to RFC 7807 problem details via `ErrorMapper`.
6. **Explicit Out-of-Scope**: Database access, user authentication credential hashing, password verification (all executed inside `AuthService`).
7. **Dependencies**: `GW-003` (`IAuthClient`), `GW-005` (`AuthenticatedContext`, `RequestContext`).
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files to Create / Modify**:
   - `src/gateway/http/proxy/auth_proxy_handler.hpp` (create)
   - `src/gateway/http/proxy/auth_proxy_handler.cpp` (create)
   - `src/gateway/CMakeLists.txt` (modify)
10. **Testing Requirements**:
    - Dedicated unit tests with mock `IAuthClient` in `tests/unit/gateway/auth_proxy_handler_test.cpp`.
    - Validate JSON parsing, error mapping, request ID propagation, and context extraction.
11. **Acceptance Criteria**: 100% test pass rate; all auth proxy routes execute and propagate context accurately.

---

### GW-006-T02 — Gateway Route Registrar & Main Pipeline Assembly (`GatewayRouteRegistrar`)

1. **Ticket ID**: `GW-006-T02`
2. **Title**: Gateway Route Registrar & Main Pipeline Assembly
3. **Objective**: Create a centralized route registrar wiring all perimeter routes, proxy handlers, and middlewares into `Router`, and integrate the complete pipeline into `src/gateway/main.cpp`.
4. **Architectural Purpose**: Provides a single authoritative route registration entry point for Gateway initialization, ensuring consistent security policy, middleware ordering, and backend routing.
5. **Scope**:
   - Create `src/gateway/http/gateway_route_registrar.hpp` and `gateway_route_registrar.cpp`:
     - Registers health routes (`/health/live`, `/health/ready`).
     - Registers Auth proxy routes via `AuthProxyHandler`.
     - Registers stubbed protected routes for future microservices (`/api/v1/messages/*`, `/api/v1/files/*`) returning HTTP 501 Unimplemented or approved placeholder proxy.
   - Update `src/gateway/main.cpp` to assemble the complete pipeline:
     - `ResourceLimiterMiddleware` -> `AuthenticationMiddleware` -> `Router` -> `GatewayRouteRegistrar`.
   - Update `src/gateway/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Streaming file transfer (owned by GW-010).
7. **Dependencies**: `GW-006-T01`, `GW-004`, `GW-005`.
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files to Create / Modify**:
   - `src/gateway/http/gateway_route_registrar.hpp` (create)
   - `src/gateway/http/gateway_route_registrar.cpp` (create)
   - `src/gateway/main.cpp` (modify)
   - `src/gateway/CMakeLists.txt` (modify)
10. **Testing Requirements**:
    - Unit tests in `tests/unit/gateway/gateway_route_registrar_test.cpp` verifying route table configuration and handler invocation.
11. **Acceptance Criteria**: 100% test pass rate; main pipeline cleanly initializes and routes requests.

---

### GW-006-T03 — Live Gateway Routing Integration Test Suite

1. **Ticket ID**: `GW-006-T03`
2. **Title**: Live Gateway Routing Integration Test Suite
3. **Objective**: Construct an end-to-end integration test suite exercising the live HTTPS Gateway server routing requests over mTLS to a backend service.
4. **Architectural Purpose**: Proves that public and protected routes reach the owning service through the approved path under realistic network, TLS, and gRPC conditions.
5. **Scope**:
   - Create `tests/integration/gateway_routing_integration_test.cpp`:
     - Starts mock gRPC `AuthService` with mTLS server credentials.
     - Initializes Gateway HTTPS server with `GatewayRouteRegistrar` and mTLS channel manager.
     - Live HTTPS client executes:
       - Public login (`POST /api/v1/auth/login`) -> verifies gRPC invocation and token receipt.
       - Public session refresh (`POST /api/v1/auth/refresh`) -> verifies token refresh.
       - Protected session revocation (`POST /api/v1/auth/revoke`) -> verifies context session ID forwarded to gRPC service.
       - Protected profile query (`GET /api/v1/auth/me`) -> verifies user ID forwarded and response mapped to JSON.
       - Sensitive device registration (`POST /api/v1/auth/device/register`) -> verifies MFA enforcement and device registration.
       - Malformed JSON body handling -> verifies HTTP 400 Bad Request.
       - Backend outage / timeout handling -> verifies deterministic fail-closed HTTP 503 error.
     - Verifies Zero Database Invariant on Gateway (ADR-005) and workstation port 5432 isolation.
   - Register target in `tests/integration/CMakeLists.txt` with cross-platform termination support.
6. **Explicit Out-of-Scope**: Testing internal database logic of backend services.
7. **Dependencies**: `GW-006-T01`, `GW-006-T02`.
8. **Exact Repository Starting Point**: `tests/integration/`.
9. **Files to Create / Modify**:
   - `tests/integration/gateway_routing_integration_test.cpp` (create)
   - `tests/integration/CMakeLists.txt` (modify)
10. **Testing Requirements**:
    - 100% test pass rate in CTest and `verify-local.py`.
11. **Acceptance Criteria**: All routing scenarios verified over live TLS; zero leaks or crashes.

---

## 3. Summary of Deliverables & Timeline

| Ticket | Deliverable | Tests |
|---|---|---|
| **GW-006-T01** | `AuthProxyHandler` (HTTP-to-gRPC dispatch, JSON mapping) | `tests/unit/gateway/auth_proxy_handler_test.cpp` |
| **GW-006-T02** | `GatewayRouteRegistrar` & `main.cpp` pipeline assembly | `tests/unit/gateway/gateway_route_registrar_test.cpp` |
| **GW-006-T03** | Live HTTPS-to-gRPC routing integration test suite | `tests/integration/gateway_routing_integration_test.cpp` |
