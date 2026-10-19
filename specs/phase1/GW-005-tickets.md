# GW-005: Implement AuthenticatedContext — Ticket Decomposition

**Milestone**: `GW-005`  
**Card Title**: Implement AuthenticatedContext  
**Goal**: Create the request-scoped authenticated identity context used throughout Gateway request processing.  
**Dependencies**: `GW-004` (Access-Token Authentication Middleware)  
**Status**: Ready for Implementation  

---

## 1. Architectural Analysis: Existing Components vs. GW-005 Scope

During **GW-004**, initial foundational elements of the authenticated identity were created to support authentication middleware testing:
- **Existing**: `AuthenticatedContext` struct in `src/gateway/http/auth/authenticated_context.hpp` holding `user_id`, `device_id`, `session_id`, `auth_level`, `scopes`, and `expires_at_epoch_ms`.
- **Existing**: Basic thread-local context pointer in `AuthenticationMiddleware`.

**What GW-005 delivers (to avoid redundancy while achieving 100% acceptance criteria)**:
1. **Anti-Fabrication & Perimeter Header Sanitization**:
   - Prevent attackers from forging caller identity by injecting spoofed headers (`X-User-Id`, `X-Device-Id`, `X-Authenticated-Scope`). The Gateway must sanitize/strip untrusted perimeter identity headers and ensure `AuthenticatedContext` can *only* be created through cryptographic token validation.
2. **Secret Isolation & Zero Plaintext Invariant**:
   - Enforce the explicit requirement: *"Context cannot contain E2E private keys or plaintext message content"*. Provide compile-time structural guarantees and safe audit/logging serialization (`to_audit_info()`) with zero credential exposure.
3. **Request-Scoped Context Lifecycle Manager (`RequestContext`)**:
   - Upgrade the bare thread-local pointer into a unified, request-scoped `RequestContext` holding correlation ID, client TLS metadata, and authoritative `AuthenticatedContext`, with strict RAII lifecycle guarantees even in the presence of handler exceptions.
4. **Context Accessor & Comprehensive Test Coverage**:
   - Provide clean downstream handler ergonomics (`IRequestContextAccessor` / `Router` context lookup).
   - Dedicated test suite validating missing, malformed, and valid contexts, anti-spoofing header stripping, and zero secret containment.

---

## 2. Detailed Ticket Breakdown

### GW-005-T01 — Perimeter Anti-Fabrication & Header Sanitization

1. **Ticket ID**: `GW-005-T01`
2. **Title**: Perimeter Anti-Fabrication & Identity Header Sanitization
3. **Objective**: Implement perimeter header sanitization stripping untrusted caller-supplied identity headers and guaranteeing that `AuthenticatedContext` cannot be fabricated by unauthenticated requests.
4. **Architectural Purpose**: Ensures that untrusted clients cannot spoof user identity or elevate privilege by injecting synthetic identity headers.
5. **Scope**:
   - In `AuthenticationMiddleware`:
     - Sanitize/strip any incoming client headers matching `x-authenticated-*`, `x-user-id`, `x-device-id`, `x-session-id`, `x-auth-level`, `x-scopes`.
     - Enforce that `AuthenticatedContext` can strictly be constructed from authoritative `ITokenValidator` verification results.
     - Ensure unauthenticated requests have zero access to fabricated contexts.
6. **Explicit Out-of-Scope**: Downstream microservice dispatch (GW-006).
7. **Dependencies**: GW-004 (`AuthenticationMiddleware`).
8. **Exact Repository Starting Point**: `src/gateway/http/auth/`.
9. **Files/Directories That May Be Modified**:
   - `src/gateway/http/auth/authentication_middleware.cpp`
   - `src/gateway/http/auth/authentication_middleware.hpp`
10. **Testing Requirements**:
    - Unit tests proving that incoming requests containing spoofed identity headers have those headers neutralized, and unauthenticated requests cannot access any context.
11. **Acceptance Criteria**: 100% test pass rate; zero identity fabrication possible.

---

### GW-005-T02 — Request-Scoped Context Lifecycle & Secret Isolation Guard

1. **Ticket ID**: `GW-005-T02`
2. **Title**: Request-Scoped Context Lifecycle & Secret Isolation Guard
3. **Objective**: Implement unified request context lifecycle management with RAII exception-safety, secret isolation guarantees, and safe audit serialization.
4. **Architectural Purpose**: Guarantees that request execution scope is cleanly managed, that no E2E private keys or plaintext payloads can ever enter the context, and that identity logging is safe.
5. **Scope**:
   - Create `src/gateway/http/auth/request_context.hpp` and `.cpp`:
     - Holds request-scoped metadata: `request_id`, `client_ip`, `request_timestamp_ms`, and optional `AuthenticatedContext`.
     - RAII lifecycle scope manager (`ScopedRequestContext`) ensuring cleanup on handler return or exception unwind.
   - In `src/gateway/http/auth/authenticated_context.hpp` & `.cpp`:
     - Add `to_audit_info()` generating safe JSON/string representations with opaque IDs and zero sensitive data.
     - Document and assert the Secret Isolation Invariant: zero fields for E2E private keys (`identity_key`, `signed_prekey`, `one_time_prekey`) or plaintext payloads.
6. **Explicit Out-of-Scope**: Business authorization rules.
7. **Dependencies**: GW-004-T02 (`AuthenticatedContext`).
8. **Exact Repository Starting Point**: `src/gateway/http/auth/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/auth/request_context.hpp`
   - `src/gateway/http/auth/request_context.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/http/auth/authenticated_context.hpp`
    - `src/gateway/http/auth/authenticated_context.cpp`
    - `src/gateway/CMakeLists.txt`
11. **Testing Requirements**:
    - Unit tests validating RAII lifecycle cleanup, exception safety, and `to_audit_info()` sanitization.
12. **Acceptance Criteria**: Context scope cleaned up deterministically; zero cryptographic private keys held.

---

### GW-005-T03 — Context Accessor Ergonomics & Comprehensive Lifecycle Test Suite

1. **Ticket ID**: `GW-005-T03`
2. **Title**: Context Accessor Ergonomics & Comprehensive Lifecycle Test Suite
3. **Objective**: Implement clean downstream handler context accessors in `Router` and a comprehensive unit/integration test suite covering missing, malformed, and valid contexts.
4. **Architectural Purpose**: Ensures downstream handlers access verified context effortlessly without token re-parsing, with 100% test coverage over missing, invalid, and valid states.
5. **Scope**:
   - Update `src/gateway/http/router.hpp` and `.cpp`:
     - Provide `Router::current_request_context()` and `Router::current_authenticated_context()`.
   - Create `tests/unit/gateway/authenticated_context_lifecycle_test.cpp`:
     - Test valid context access in route handlers without token re-parsing.
     - Test missing context behavior on unauthenticated routes.
     - Test malformed / invalid context rejection.
     - Test anti-spoofing header stripping.
     - Test secret isolation and safe audit serialization.
   - Register target in `tests/unit/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Database or user profile loading.
7. **Dependencies**: GW-005-T01, GW-005-T02.
8. **Exact Repository Starting Point**: `tests/unit/gateway/`.
9. **Files/Directories to Create**:
   - `tests/unit/gateway/authenticated_context_lifecycle_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/http/router.hpp`
    - `src/gateway/http/router.cpp`
    - `tests/unit/CMakeLists.txt`
11. **Validation Commands**:
    ```bash
    cmake --build --preset dev-debug --target securecloud_authenticated_context_lifecycle_test
    ctest --preset dev-debug -R "AuthenticatedContextLifecycleTest" --output-on-failure
    python3 scripts/verify-local.py
    ```
12. **Acceptance Criteria**: 100% test pass rate; all acceptance criteria of GW-005 satisfied.

---

## 3. Summary of Deliverables & Timeline

| Ticket | Deliverable | Tests |
|---|---|---|
| **GW-005-T01** | Perimeter Anti-Fabrication & Header Sanitization | Unit tests in `authentication_middleware_test.cpp` |
| **GW-005-T02** | RequestContext Lifecycle Manager & Secret Isolation Guard | Unit tests for `RequestContext` & `AuthenticatedContext` |
| **GW-005-T03** | Router Accessor Ergonomics & Comprehensive Lifecycle Test Suite | Dedicated `authenticated_context_lifecycle_test.cpp` |
