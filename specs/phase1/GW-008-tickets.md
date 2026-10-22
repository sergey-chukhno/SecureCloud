# GW-008: Implement Gateway Error, Deadline, and Cancellation Handling — Ticket Decomposition

**Milestone**: `GW-008`  
**Card Title**: Implement Gateway error, deadline, and cancellation handling  
**Goal**: Implement robust, deterministic perimeter resilience including downstream deadline management, client cancellation propagation, standardized RFC 7807 error translation, and approved retry behavior adhering strictly to ADR-009 and the system resilience model.  
**Dependencies**: `GW-003` (Gateway gRPC Client Foundation), `GW-006` (Gateway Routing Engine), `GW-007` (Route/Scope Authorization)  
**Status**: Ready for Implementation  

---

## 1. Architectural Analysis: Existing Components vs. GW-008 Scope

### What Has Already Been Implemented (GW-001 through GW-007)
To prevent duplicate implementations and leverage existing foundations, we recognize:
1. **gRPC Client Foundation & Call Context (`GW-003`)**:
   - `ClientCallContext` (`src/gateway/grpc/client_call_context.hpp`):
     - Wraps `::grpc::ClientContext`.
     - Supports `set_deadline()`, `cancel()` (`TryCancel()`), and tracks `is_cancelled()`.
     - Computes `deadline_remaining()` and `is_deadline_expired()`.
     - Propagates metadata headers (`x-request-id`, `x-client-service`).
   - `AuthServiceClient` (`src/gateway/grpc/auth_service_client.hpp`):
     - Concrete gRPC client delegating calls to `AuthService::StubInterface`.
2. **Preliminary Error Mapping (`GW-006`)**:
   - `ErrorMapper` (`src/gateway/http/error_mapper.hpp`, `error_mapper.cpp`):
     - Maps common `::grpc::StatusCode` values to HTTP statuses (e.g. `INVALID_ARGUMENT` -> 400, `UNAUTHENTICATED` -> 401, `NOT_FOUND` -> 404, `UNAVAILABLE` -> 503, `DEADLINE_EXCEEDED` -> 504).
     - Formats basic JSON error payloads: `{"error": {"code": "...", "message": "...", "request_id": "..."}}`.
3. **Perimeter Authentication & Authorization (`GW-004`, `GW-007`)**:
   - `AuthenticationMiddleware` & `AuthorizationMiddleware` (`src/gateway/http/auth/`):
     - Format RFC 7807 problem details payloads for perimeter security rejections (`insufficient-scope`, `mfa-required`, `device-binding-required`).
4. **Configuration & Resource Limits (`GW-002`)**:
   - `GatewayConfig` (`src/gateway/gateway_config.hpp`):
     - Defines `request_timeout_ms{5000}`, max payload sizes, and connection limits.
5. **Proxy Handlers (`GW-006`)**:
   - `AuthProxyHandler` (`src/gateway/http/proxy/auth_proxy_handler.cpp`):
     - Dispatches HTTP requests to downstream gRPC endpoints using `ClientCallContext`.

---

### What GW-008 Delivers: Deterministic Distributed Failure Semantics

Currently, the Gateway lacks:
1. **Configurable & Enforced Per-Service Deadlines**:
   - `AuthProxyHandler` uses a hard-coded fallback timeout (`k_default_timeout = 5000ms`), ignoring service-specific latency budgets (e.g., Auth simple requests = 1s, Messaging = 2s, Files metadata = 2s as specified in ADR-009 / Section 10).
2. **Inbound Deadline Ingestion & Downstream Budget Propagation**:
   - The Gateway does not parse client-supplied deadline headers (e.g., `X-Request-Timeout` or `Request-Timeout`).
   - Downstream deadlines do not account for elapsed perimeter processing time, violating the rule: *"A child operation must never receive a deadline later than the parent operation's remaining deadline"*.
   - If a request's deadline has already elapsed before gRPC dispatch, the Gateway does not fast-fail, causing unnecessary downstream network traffic.
3. **Client Disconnection & Cancellation Propagation**:
   - If an external HTTP client disconnects or aborts during a long-running downstream call, the Gateway does not actively trigger `ClientCallContext::cancel()`.
   - Backend services remain unaware of caller abandonment, wasting CPU, database, and memory resources.
4. **Approved, Idempotency-Aware Retry Engine**:
   - Transparent retries currently do not exist.
   - The Gateway must strictly enforce the **Retryability Matrix** (ADR-009 / Section 3 & 4):
     - **Safe to retry**: Read-only queries and explicitly idempotent calls (e.g., `GetUser`, `/api/v1/users/me`) on transient errors (`UNAVAILABLE`, transient socket resets) within remaining deadline budget.
     - **NEVER transparently retry**: Non-idempotent operations (e.g., `login`, `register_device`, `revoke_session`, `send_message`) must fail immediately to avoid duplicate side effects.
     - Bounded exponential backoff with jitter (initial 100ms, 2x backoff, max 1000ms, ±25% jitter).
5. **Uniform RFC 7807 Problem Details across all Gateway Errors**:
   - Upgrade `ErrorMapper` to emit compliant RFC 7807 problem details with `type`, `title`, `status`, `detail`, `request_id`, and embedded error code across all transport, timeout, cancellation, and backend failures.

---

## 2. Architectural Invariants & Constraints

1. **Zero Database Invariant on Gateway (ADR-005)**:
   - The Gateway must never link database libraries or access port 5432. Error handling and retry logic operate purely on gRPC responses and in-memory timers.
2. **Strict Deadline Precedence Invariant**:
   - Downstream deadlines and retry backoffs are strictly bounded by the overall request deadline. A retry must never extend an operation beyond its deadline budget.
3. **Idempotency Invariant for Automatic Retries**:
   - The Gateway must never automatically retry non-idempotent state mutations. Only designated safe/idempotent endpoints may be retried on transient failures.
4. **Immediate Fast-Fail on Expired Budget**:
   - If `remaining_deadline <= 0` prior to downstream dispatch or subsequent retry, the Gateway must immediately return `504 Gateway Timeout` without touching downstream sockets.
5. **Prompt Downstream Cancellation Propagation**:
   - When an HTTP client aborts or a timeout expires, `::grpc::ClientContext::TryCancel()` must be promptly triggered to abort the backend RPC.
6. **Standardized RFC 7807 Problem Details**:
   - All client-visible error responses must use `Content-Type: application/json` adhering to RFC 7807 schema with machine-readable error codes.

---

## 3. Detailed Ticket Breakdown

### GW-008-T01 — RFC 7807 Error Mapper Harmonization & gRPC Status Translator

1. **Ticket ID**: `GW-008-T01`
2. **Title**: RFC 7807 Error Mapper Harmonization & gRPC Status Translator
3. **Objective**: Standardize `ErrorMapper` to translate all gRPC status codes into comprehensive RFC 7807 problem details payloads with deterministic HTTP status codes, canonical URI types, titles, details, correlation IDs, and structured error metadata.
4. **Architectural Purpose**: Guarantees that every downstream failure (timeout, network outage, cancellation, validation) produces a predictable, contract-compliant JSON response at the Gateway perimeter.
5. **Scope**:
   - Update `src/gateway/http/error_mapper.hpp` and `src/gateway/http/error_mapper.cpp`:
     - Extend gRPC status mappings:
       - `::grpc::StatusCode::CANCELLED` -> HTTP 499 (Client Closed Request) or HTTP 504 (Gateway Timeout) depending on origin; error code `CLIENT_CANCELLED` / `UPSTREAM_CANCELLED`.
       - `::grpc::StatusCode::UNKNOWN` -> HTTP 500 (`INTERNAL_ERROR`).
       - `::grpc::StatusCode::DATA_LOSS` -> HTTP 500 (`DATA_LOSS`).
       - `::grpc::StatusCode::OUT_OF_RANGE` -> HTTP 400 (`OUT_OF_RANGE`).
     - Standardize problem details URI types:
       - 400: `https://securecloud.internal/errors/bad-request`
       - 401: `https://securecloud.internal/errors/unauthenticated`
       - 403: `https://securecloud.internal/errors/forbidden`
       - 404: `https://securecloud.internal/errors/not-found`
       - 409: `https://securecloud.internal/errors/conflict`
       - 412: `https://securecloud.internal/errors/precondition-failed`
       - 429: `https://securecloud.internal/errors/rate-limited`
       - 499: `https://securecloud.internal/errors/client-cancelled`
       - 500: `https://securecloud.internal/errors/internal-error`
       - 501: `https://securecloud.internal/errors/not-implemented`
       - 503: `https://securecloud.internal/errors/service-unavailable`
       - 504: `https://securecloud.internal/errors/gateway-timeout`
     - Provide overload for RFC 7807 problem details formatting with optional type URI, title, and additional fields.
     - Ensure backward-compatible `error` JSON object is preserved within the root RFC 7807 object.
6. **Explicit Out-of-Scope**: Downstream timeout configuration and retry scheduling (covered in T02 and T03).
7. **Dependencies**: None (self-contained error mapping component).
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files/Directories to Create**:
   - `tests/unit/gateway/error_mapper_test.cpp` (dedicated unit test suite)
10. **Files/Directories That May Be Modified**:
    - `src/gateway/http/error_mapper.hpp`
    - `src/gateway/http/error_mapper.cpp`
    - `tests/unit/CMakeLists.txt`
11. **Test Targets & Acceptance Criteria**:
    - Build: `securecloud_gateway_error_mapper_test`
    - Verify all 16 gRPC status codes map to deterministic HTTP status codes and RFC 7807 payloads.
    - Verify presence of `type`, `title`, `status`, `detail`, `request_id`, and `error.code`.

---

### GW-008-T02 — Configurable Service Deadlines & Downstream Budget Propagation

1. **Ticket ID**: `GW-008-T02`
2. **Title**: Configurable Service Deadlines & Downstream Budget Propagation (`DeadlineManager`)
3. **Objective**: Implement a centralized `DeadlineManager` and per-service timeout configuration in `GatewayConfig`, enabling client deadline header ingestion and strict downstream budget propagation.
4. **Architectural Purpose**: Prevents requests from lingering indefinitely and ensures downstream microservices receive only the remaining latency budget.
5. **Scope**:
   - Update `src/gateway/gateway_config.hpp`:
     - Add `GatewayServiceDeadlinesConfig` with defaults from ADR-009 Section 10:
       - `auth_timeout_ms{1000}` (1 second default)
       - `messaging_timeout_ms{2000}` (2 seconds default)
       - `files_metadata_timeout_ms{2000}` (2 seconds default)
       - `audit_timeout_ms{1000}` (1 second default)
       - `max_request_deadline_ms{10000}` (10 seconds upper bound)
     - Validate configuration bounds at startup.
   - Create `src/gateway/http/deadline_manager.hpp` and `deadline_manager.cpp`:
     - Ingest client deadline headers (`X-Request-Timeout` or `Request-Timeout` in milliseconds or seconds).
     - Calculate effective overall deadline: `effective = clamp(client_timeout, min_timeout, max_request_deadline)`.
     - Calculate downstream call budget: `downstream_budget = min(service_timeout, remaining_request_budget)`.
     - Fast-fail check: If `remaining_request_budget <= 0`, immediately return `false` so the handler emits `504 Gateway Timeout` without calling gRPC.
   - Integrate `DeadlineManager` into `AuthProxyHandler` and route handlers.
6. **Explicit Out-of-Scope**: Automatic retry execution (covered in T03).
7. **Dependencies**: `GW-008-T01`.
8. **Exact Repository Starting Point**: `src/gateway/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/deadline_manager.hpp`
   - `src/gateway/http/deadline_manager.cpp`
   - `tests/unit/gateway/deadline_manager_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/gateway_config.hpp`
    - `src/gateway/gateway_config.cpp`
    - `src/gateway/http/proxy/auth_proxy_handler.hpp`
    - `src/gateway/http/proxy/auth_proxy_handler.cpp`
    - `tests/unit/CMakeLists.txt`
11. **Test Targets & Acceptance Criteria**:
    - Build: `securecloud_gateway_deadline_manager_test`
    - Verify client header parsing, clamping to max bounds, and remaining budget calculation.
    - Verify zero downstream invocation when deadline is already expired upon handler entry.

---

### GW-008-T03 — Approved Retry Policy Engine & Idempotency Evaluator

1. **Ticket ID**: `GW-008-T03`
2. **Title**: Approved Retry Policy Engine & Idempotency Evaluator
3. **Objective**: Implement a robust retry policy engine that enforces the ADR-009 Retryability Matrix, executing bounded retries with exponential backoff and jitter strictly for safe/idempotent operations within remaining deadline budgets.
4. **Architectural Purpose**: Improves Gateway availability against transient network blips while rigorously preventing duplicate execution of non-idempotent operations.
5. **Scope**:
   - Create `src/gateway/http/retry_policy.hpp` and `retry_policy.cpp`:
     - Classification:
       - `OperationIdempotency`: `SAFE_READONLY` (e.g. `GetUser`, `/api/v1/users/me`), `IDEMPOTENT_MUTATION`, `NON_IDEMPOTENT` (e.g. `Authenticate`, `RegisterDevice`, `RevokeSession`).
     - Retry Policy configuration:
       - `max_attempts{3}`
       - `initial_backoff_ms{100}`
       - `backoff_multiplier{2.0}`
       - `max_backoff_ms{1000}`
       - `jitter_ratio{0.25}` (±25%)
     - Retry evaluation logic:
       - Is status retryable? (Only `::grpc::StatusCode::UNAVAILABLE`, transient connection resets, or `DEADLINE_EXCEEDED` if explicitly permitted).
       - Is operation retry-safe? (Only `SAFE_READONLY` or `IDEMPOTENT_MUTATION`).
       - Is remaining deadline sufficient? (`remaining_budget > backoff_delay + min_call_time`).
     - Backoff calculator with pseudo-random jitter.
   - Implement `RetryInvoker` or helper executing the retry loop around gRPC client invocations.
   - Update `AuthProxyHandler` to apply retry policy:
     - `handle_get_me`: Configured as `SAFE_READONLY` (retries on transient failure).
     - `handle_login`, `handle_refresh`, `handle_revoke`, `handle_register_device`: Configured as `NON_IDEMPOTENT` (no automatic retry).
6. **Explicit Out-of-Scope**: Circuit breaker tripping and global bulkheads (assigned to `GW-009`).
7. **Dependencies**: `GW-008-T01`, `GW-008-T02`.
8. **Exact Repository Starting Point**: `src/gateway/http/`.
9. **Files/Directories to Create**:
   - `src/gateway/http/retry_policy.hpp`
   - `src/gateway/http/retry_policy.cpp`
   - `tests/unit/gateway/retry_policy_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/gateway_config.hpp`
    - `src/gateway/http/proxy/auth_proxy_handler.cpp`
    - `tests/unit/CMakeLists.txt`
11. **Test Targets & Acceptance Criteria**:
    - Build: `securecloud_gateway_retry_policy_test`
    - Unit test verification of backoff calculations, jitter distribution, non-retry on non-idempotent calls, and budget exhaustion stopping retries.

---

### GW-008-T04 — Client Cancellation Propagation & Live End-to-End Resilience Integration Tests

1. **Ticket ID**: `GW-008-T04`
2. **Title**: Client Cancellation Propagation & Live End-to-End Resilience Integration Tests
3. **Objective**: Implement client cancellation detection/propagation to active gRPC calls and construct a comprehensive live TLS 1.3 / mTLS integration test suite verifying timeouts, cancellation, downstream outages, and retry behavior.
4. **Architectural Purpose**: Proves end-to-end resilience of the Gateway under simulated latency, server faults, client disconnects, and transient failures.
5. **Scope**:
   - Cancellation propagation:
     - Detect client connection abort/socket close during HTTP request handling.
     - Trigger `ClientCallContext::cancel()` (`::grpc::ClientContext::TryCancel()`) to promptly abort downstream backend processing.
   - Create `tests/integration/gateway_resilience_integration_test.cpp`:
     - Test 1: `DownstreamTimeoutReturns504WithProblemDetails`: Upstream call exceeding deadline triggers HTTP 504 Gateway Timeout.
     - Test 2: `DownstreamServiceOutageReturns503`: Unreachable downstream service returns HTTP 503 Service Unavailable.
     - Test 3: `ClientSuppliedDeadlineHeaderEnforced`: Client header `X-Request-Timeout: 150` clamps downstream budget and times out early.
     - Test 4: `ExpiredBudgetFastFailsWithoutDownstreamCall`: Request arriving with expired budget fast-fails with 504 without invoking backend RPC.
     - Test 5: `SafeReadOnlyOperationRetriesAndSucceeds`: Simulated transient failure on attempt 1 of `GET /api/v1/users/me` succeeds on attempt 2.
     - Test 6: `SafeReadOnlyOperationExhaustsRetriesReturns503`: Persistent transient failure stops after 3 attempts and returns 503.
     - Test 7: `NonIdempotentOperationDoesNotRetryOnFailure`: `POST /api/v1/auth/login` failing with transient error executes exactly 1 attempt and never retries.
     - Test 8: `RetryAbortsWhenRemainingDeadlineExhausted`: Retry loop terminates early when remaining deadline is smaller than backoff delay.
     - Test 9: `ClientCancellationAbortsDownstreamRpc`: Client closing connection aborts active gRPC call on downstream service.
     - Test 10: `DeterministicRfc7807StructureAcrossAllFailureModes`: All failure responses (400, 401, 403, 404, 499/504, 503) strictly conform to RFC 7807 schema.
   - Register target `securecloud_gateway_resilience_integration_test` in `tests/integration/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Bounded memory bulkheads and concurrency rate limiting (`GW-009`).
7. **Dependencies**: `GW-008-T01`, `GW-008-T02`, `GW-008-T03`.
8. **Exact Repository Starting Point**: `tests/integration/`.
9. **Files/Directories to Create**:
   - `tests/integration/gateway_resilience_integration_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/http/proxy/auth_proxy_handler.cpp`
    - `tests/integration/CMakeLists.txt`
11. **Test Targets & Acceptance Criteria**:
    - Build: `securecloud_gateway_resilience_integration_test`
    - All 10 live integration test scenarios pass deterministically over live TLS 1.3 / mTLS sockets.
    - Zero hangs on exit across platforms (Linux, macOS, Windows).

---

## 4. Summary of Planned Deliverables

| Ticket ID | Primary Component | Target Location | Test Target |
|:---|:---|:---|:---|
| **GW-008-T01** | RFC 7807 Error Mapper & Translator | `src/gateway/http/error_mapper.*` | `securecloud_gateway_error_mapper_test` |
| **GW-008-T02** | Deadline Manager & Budget Propagation | `src/gateway/http/deadline_manager.*` | `securecloud_gateway_deadline_manager_test` |
| **GW-008-T03** | Retry Policy & Idempotency Engine | `src/gateway/http/retry_policy.*` | `securecloud_gateway_retry_policy_test` |
| **GW-008-T04** | Cancellation & Live Resilience Suite | `tests/integration/gateway_resilience_integration_test.cpp` | `securecloud_gateway_resilience_integration_test` |

---

## 5. Architectural Invariants Verification Matrix

| Invariant / Requirement | Mechanism in GW-008 | Verification Method |
|:---|:---|:---|
| **ADR-005: Zero Database Invariant** | No database headers, connections, or libraries included in Gateway. | Link inspection, build checks. |
| **Port 5432 Isolation** | Gateway interacts only with HTTP (8443) and gRPC (50051-50055). | Port audit, integration assertions. |
| **Strict Deadline Precedence** | Downstream deadline = $\min(\text{service\_deadline}, \text{remaining\_request\_budget})$. Retries bounded by deadline. | Unit tests in T02, integration tests in T04. |
| **No Transparent Non-Idempotent Retries** | Retry engine checks `OperationIdempotency`. Non-idempotent operations fail immediately. | Unit tests in T03, integration test #7 in T04. |
| **RFC 7807 Problem Details** | All errors produce `Content-Type: application/json` with standard problem details schema. | Unit tests in T01, integration test #10 in T04. |
| **Client Cancellation Propagation** | `ClientCallContext::cancel()` triggers `::grpc::ClientContext::TryCancel()`. | Integration test #9 in T04. |
