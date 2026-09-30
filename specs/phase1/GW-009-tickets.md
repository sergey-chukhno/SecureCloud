# GW-009: Implement Gateway Resilience and Resource Controls — Ticket Decomposition

**Milestone**: `GW-009`  
**Card Title**: Implement Gateway resilience and resource controls  
**Goal**: Implement bounded concurrency, rate/resource limiting, backpressure, bulkheads, circuit breakers, and coordinated graceful shutdown on the API Gateway, strictly adhering to ADR-009 (Distributed Failure & Resilience) and ADR-010 (Performance & Capacity Optimization).  
**Dependencies**: `GW-008` (Perimeter Error, Deadline, and Cancellation Handling)  
**Status**: Ready for Planning / Implementation  

---

## 1. Architectural Analysis: Existing Components vs. GW-009 Scope

### What Has Already Been Implemented (GW-001 through GW-008)
To prevent redundant work and preserve architectural continuity, we explicitly identify the components already implemented:
1. **Transport-Level Resource Limiting (`GW-002`)**:
   - `ResourceLimiterMiddleware` (`src/gateway/http/middleware/resource_limiter_middleware.*`):
     - Enforces `max_header_bytes` (HTTP 431 `REQUEST_HEADER_FIELDS_TOO_LARGE`).
     - Enforces `max_body_bytes` (HTTP 413 `PAYLOAD_TOO_LARGE`).
     - Enforces global `max_concurrent_connections` (HTTP 503 `RESOURCE_EXHAUSTED`).
2. **RFC 7807 Problem Details Error Translation (`GW-008-T01`)**:
   - `ErrorMapper` (`src/gateway/http/error_mapper.*`):
     - Translates all 16 gRPC status codes to HTTP statuses with RFC 7807 problem details schema (`type`, `title`, `status`, `detail`, `request_id`, `error.code`).
3. **Deadline Management & Budget Propagation (`GW-008-T02`)**:
   - `DeadlineManager` (`src/gateway/http/deadline_manager.*`):
     - Ingests `X-Request-Timeout` headers, enforces min ($50\text{ms}$) and max ($10\text{000ms}$) clamps, calculates shrinking downstream call budgets, and fast-fails on expired budgets.
4. **Retry Policy Engine & Cancellation (`GW-008-T03`, `GW-008-T04`)**:
   - `RetryPolicy` (`src/gateway/http/retry_policy.*`):
     - Enforces exponential backoff and jitter for `SAFE_READONLY` operations; forbids retrying `NON_IDEMPOTENT` mutations.
   - `ActiveCallGuard` & `cancel_request()`:
     - Cancels active downstream gRPC calls via `::grpc::ClientContext::TryCancel()`, mapped to HTTP 499 `CLIENT_CANCELLED`.
5. **Health Status Lifecycle Foundation (`SC-013`)**:
   - `HealthStatusManager` (`src/common/include/securecloud/health/health_status_manager.hpp`):
     - Tracks liveness and readiness independently.

---

### What GW-009 Delivers: Advanced Resource Controls & Bulkhead Isolation

While the Gateway currently protects transport limits (header/body sizes) and manages deadlines, it lacks **workload isolation**, **fine-grained rate limiting**, and **cascading outage protection**:

1. **Workload Bulkhead Concurrency Partitioning (ADR-009 Section 9)**:
   - Currently, all requests share a single global connection counter. A burst of file transfers or messaging traffic can saturate the Gateway, completely starving critical user authentication or health check requests.
   - The Gateway must establish **isolated concurrency pools**:
     - `Auth` pool (e.g., max 100 concurrent requests).
     - `Messaging` pool (e.g., max 200 concurrent requests).
     - `Files` pool (e.g., max 50 concurrent requests).
     - `Emergency` tier (reserved perimeter capacity for health/operator probes; not a microservice).
   - When a specific pool is saturated, the Gateway must reject only requests targeting that workload with HTTP 503 `SERVICE_UNAVAILABLE` or HTTP 429 (RFC 7807 `BULKHEAD_LIMIT_EXCEEDED` and `Retry-After`), leaving other workloads entirely unaffected.

2. **Per-Client / Per-IP Token-Bucket Rate Limiter (ADR-009, ADR-010)**:
   - A single abusive client or automated bot can currently consume the entire Gateway's capacity.
   - The Gateway needs a token-bucket rate limiter that throttles requests based on client identity (authenticated `user_id` or client IP address).
   - Must emit standard RFC 6585 headers:
     - `Retry-After: <seconds>`
     - `X-RateLimit-Limit: <burst>`
     - `X-RateLimit-Remaining: <tokens>`
     - `X-RateLimit-Reset: <seconds>`
   - Must enforce **bounded memory consumption** via periodic pruning / LRU eviction so tracking client states cannot cause an out-of-memory (OOM) attack.

3. **Downstream Service Circuit Breaker (ADR-009 Section 8)**:
   - When a downstream microservice is down, repeatedly dispatching requests and waiting for timeouts consumes Gateway threads, sockets, and memory, while hammering the struggling backend.
   - The Gateway must implement a finite-state machine (FSM) circuit breaker (`CLOSED` $\leftrightarrow$ `OPEN` $\leftrightarrow$ `HALF_OPEN`) per downstream service:
     - `CLOSED`: Normal operation; tracks consecutive transient failures (`UNAVAILABLE`, `DEADLINE_EXCEEDED`).
     - `OPEN`: Trips after $N$ consecutive failures (e.g., 5). Fails fast immediately at the perimeter with HTTP 503 `SERVICE_UNAVAILABLE` and `Retry-After` without dispatching downstream calls.
     - `HALF_OPEN`: After recovery timeout (e.g., 5s), permits limited probe requests to test backend health before resetting to `CLOSED` or reverting to `OPEN`.

4. **Coordinated Graceful Drain & Shutdown (ADR-009)**:
   - On shutdown signal (`SIGINT`, `SIGTERM`), the Gateway must:
     1. Immediately mark readiness as `NOT_SERVING` so upstream load balancers stop forwarding new traffic.
     2. Refuse new inbound requests with HTTP 503 `SERVER_SHUTTING_DOWN`.
     3. Permit in-flight requests to complete cleanly within a configurable drain timeout window (e.g., 5s).
     4. Terminate HTTP/HTTPS listener threads with zero dangling connections.

---

## 2. Invariants & Guardrails

1. **ADR-005 Zero Database Invariant**:
   - The Gateway must NEVER link to PostgreSQL (`libpq`, `libpqxx`), include database headers, or communicate on port 5432.
2. **Explicit Bounded Concurrency & Queues**:
   - No unbounded queues or thread-per-request models. Every resource queue and bulkhead pool has an explicit, configurable ceiling.
3. **RFC 7807 Problem Details Compliance**:
   - All rate limit rejections (HTTP 429), bulkhead rejections (HTTP 503), and circuit breaker rejections (HTTP 503) must emit standard RFC 7807 problem details.
4. **Memory-Bounded Client Tracking**:
   - Tracking states for per-IP or per-client rate limiters must enforce an upper bound on entries (LRU eviction + idle cleanup).
5. **Deterministic Circuit Breaker State Transitions**:
   - Circuit breakers must transition deterministically without race conditions or memory corruption under multi-threaded load.

---

## 3. Ticket Decomposition

```
[GW-009: Resilience & Resource Controls]
  ├── GW-009-T01: Workload Bulkhead Concurrency Partitioning (Pools for Auth, Messaging, Files, Emergency)
  ├── GW-009-T02: Per-Client / Per-IP Token-Bucket Rate Limiter & Memory Bounds
  ├── GW-009-T03: Downstream Service Circuit Breaker Engine (CLOSED, OPEN, HALF_OPEN)
  └── GW-009-T04: Coordinated Graceful Drain & Live End-to-End Resource Controls Integration Suite
```

---

### GW-009-T01 — Workload Bulkhead Concurrency Partitioning

1. **Ticket ID**: `GW-009-T01`
2. **Title**: Workload Bulkhead Concurrency Partitioning
3. **Objective**: Implement service-isolated concurrency bulkhead pools preventing noisy-neighbor starvation across distinct workload classes (Auth, Messaging, Files, Emergency).
4. **Architectural Purpose**: Guarantees that a surge in large file transfers or high-volume messaging cannot starve sensitive authentication requests or administrative health checks (ADR-009 Section 9).
5. **Scope**:
   - Add `GatewayBulkheadConfig` to `src/gateway/gateway_config.hpp`:
     ```cpp
     struct GatewayBulkheadConfig {
         uint32_t auth_max_concurrent{100};
         uint32_t messaging_max_concurrent{200};
         uint32_t files_max_concurrent{50};
         uint32_t emergency_reserved_slots{10}; // Reserved perimeter capacity for health/ops probes (not a microservice)
     };
     ```
   - Create `src/gateway/http/bulkhead_manager.hpp` and `bulkhead_manager.cpp`:
     - Define `enum class WorkloadCategory { Auth, Messaging, Files, Emergency }`.
     - `WorkloadBulkhead`: thread-safe concurrency counter with atomic reservation and RAII `BulkheadLease`.
     - `BulkheadManager`: maps requests to workloads and attempts lease acquisition.
     - When a pool is saturated, returns `false` $\to$ handler emits HTTP 503 `SERVICE_UNAVAILABLE` with RFC 7807 problem details (`type: "https://securecloud.internal/errors/bulkhead-limit-exceeded"`, `error.code: "BULKHEAD_LIMIT_EXCEEDED"`, and `Retry-After: 5`).
   - Integrate bulkhead leases into `AuthProxyHandler` (and routing layer).
   - Create unit test suite: `tests/unit/gateway/bulkhead_manager_test.cpp`.
6. **Explicit Out-of-Scope**: Rate limiting (assigned to `GW-009-T02`) and circuit breakers (`GW-009-T03`).
7. **Dependencies**: `GW-008`.
8. **Files to Create/Modify**:
   - `src/gateway/gateway_config.hpp`, `src/gateway/gateway_config.cpp`
   - `src/gateway/http/bulkhead_manager.hpp`, `src/gateway/http/bulkhead_manager.cpp`
   - `src/gateway/http/proxy/auth_proxy_handler.cpp`
   - `tests/unit/gateway/bulkhead_manager_test.cpp`
   - `src/gateway/CMakeLists.txt`, `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - Saturating the `Files` pool rejects file requests with 503 without affecting `Auth` requests.
   - Saturated pool emits RFC 7807 problem details with `Retry-After` header.
   - RAII lease release returns slots cleanly on normal exit, exception, or cancellation.

---

### GW-009-T02 — Per-Client / Per-IP Token-Bucket Rate Limiter & Memory Bounds

1. **Ticket ID**: `GW-009-T02`
2. **Title**: Per-Client / Per-IP Token-Bucket Rate Limiter & Memory Bounds
3. **Objective**: Implement a high-performance token-bucket rate limiter middleware that throttles excessive traffic per client identity/IP with bounded memory overhead.
4. **Architectural Purpose**: Protects the perimeter from credential stuffing, brute force, and Denial-of-Service attacks while adhering to RFC 6585 rate limiting standards (ADR-009, ADR-010).
5. **Scope**:
   - Add `GatewayRateLimitingConfig` to `src/gateway/gateway_config.hpp`:
     ```cpp
     struct GatewayRateLimitingConfig {
         bool enabled{true};
         double refill_rate_per_sec{50.0};
         uint32_t burst_capacity{100};
         size_t max_tracked_clients{10000};
         std::chrono::seconds client_ttl{300};
     };
     ```
   - Create `src/gateway/http/middleware/rate_limiter_middleware.hpp` and `rate_limiter_middleware.cpp`:
     - Token bucket implementation: calculates fractional token regeneration based on `std::chrono::steady_clock`.
     - Key resolution: extracts authenticated `user_id` if present; falls back to client IP (`req.remote_addr`).
     - Memory boundedness: prunes idle client entries exceeding `client_ttl` or evicts LRU entries when `max_tracked_clients` is exceeded.
     - When rate limit is exceeded: emits HTTP 429 `TOO_MANY_REQUESTS` with:
       - `Retry-After: <seconds>`
       - `X-RateLimit-Limit: <burst>`
       - `X-RateLimit-Remaining: 0`
       - `X-RateLimit-Reset: <seconds>`
       - RFC 7807 problem details (`type: "https://securecloud.internal/errors/rate-limit-exceeded"`, `error.code: "RATE_LIMIT_EXCEEDED"`).
   - Create unit test suite: `tests/unit/gateway/rate_limiter_middleware_test.cpp`.
6. **Explicit Out-of-Scope**: Distributed Redis rate-limiting (single-node perimeter model per ADR-002/ADR-009).
7. **Dependencies**: `GW-009-T01`.
8. **Files to Create/Modify**:
   - `src/gateway/gateway_config.hpp`, `src/gateway/gateway_config.cpp`
   - `src/gateway/http/middleware/rate_limiter_middleware.hpp`, `src/gateway/http/middleware/rate_limiter_middleware.cpp`
   - `tests/unit/gateway/rate_limiter_middleware_test.cpp`
   - `src/gateway/CMakeLists.txt`, `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - Bursts exceeding capacity are rejected with HTTP 429 and standard headers.
   - Refill rate restores tokens predictably over time.
   - Tracking 50,000 distinct client IPs does not cause memory to grow beyond `max_tracked_clients`.

---

### GW-009-T03 — Downstream Service Circuit Breaker Engine

1. **Ticket ID**: `GW-009-T03`
2. **Title**: Downstream Service Circuit Breaker Engine
3. **Objective**: Implement a finite-state machine (FSM) circuit breaker (`CLOSED`, `OPEN`, `HALF_OPEN`) per downstream microservice, failing fast at the perimeter during backend outages.
4. **Architectural Purpose**: Shields struggling downstream microservices from repeated failing requests, prevents Gateway thread exhaustion, and provides explicit recovery probing (ADR-009 Section 8).
5. **Scope**:
   - Add `GatewayCircuitBreakerConfig` to `src/gateway/gateway_config.hpp`:
     ```cpp
     struct GatewayCircuitBreakerConfig {
         uint32_t failure_threshold{5};         // 5 consecutive failures trips breaker
         uint32_t recovery_timeout_ms{5000};     // 5s recovery window before HALF_OPEN
         uint32_t half_open_probe_count{1};     // 1 probe request in HALF_OPEN
     };
     ```
   - Create `src/gateway/http/circuit_breaker.hpp` and `circuit_breaker.cpp`:
     - States: `CircuitState::Closed`, `CircuitState::Open`, `CircuitState::HalfOpen`.
     - `CircuitBreaker`: thread-safe FSM tracking consecutive transient failures (`UNAVAILABLE`, `DEADLINE_EXCEEDED`).
     - `CircuitBreakerRegistry`: manages distinct circuit breakers for `auth`, `messaging`, `files`, `audit`.
     - Execution hook in `RetryPolicy` / `AuthProxyHandler`:
       - Before making downstream call: check `circuit_breaker.allow_request()`.
       - If `Open`: immediately fail fast with HTTP 503 `SERVICE_UNAVAILABLE`, `Retry-After: <seconds>`, and RFC 7807 problem details (`CIRCUIT_BREAKER_OPEN`).
       - On RPC completion: record success or transient failure to update FSM.
   - Create unit test suite: `tests/unit/gateway/circuit_breaker_test.cpp`.
6. **Explicit Out-of-Scope**: Distributed gossip-based circuit synchronization.
7. **Dependencies**: `GW-009-T01`, `GW-009-T02`.
8. **Files to Create/Modify**:
   - `src/gateway/gateway_config.hpp`, `src/gateway/gateway_config.cpp`
   - `src/gateway/http/circuit_breaker.hpp`, `src/gateway/http/circuit_breaker.cpp`
   - `src/gateway/http/proxy/auth_proxy_handler.cpp`
   - `tests/unit/gateway/circuit_breaker_test.cpp`
   - `src/gateway/CMakeLists.txt`, `tests/unit/CMakeLists.txt`
9. **Acceptance Criteria**:
   - 5 consecutive downstream `UNAVAILABLE` errors transitions breaker from `CLOSED` to `OPEN`.
   - In `OPEN` state, calls fail fast immediately with 0 downstream gRPC calls.
   - After recovery timeout, state transitions to `HALF_OPEN` and permits a probe call.
   - Successful probe resets state to `CLOSED`; failed probe reverts to `OPEN`.

---

### GW-009-T04 — Coordinated Graceful Drain & Live End-to-End Resource Controls Suite

1. **Ticket ID**: `GW-009-T04`
2. **Title**: Coordinated Graceful Drain & Live End-to-End Resource Controls Suite
3. **Objective**: Implement coordinated readiness drain and build a comprehensive live TLS 1.3 / mTLS integration test suite validating bulkheads, rate limiting, circuit breaking, and graceful shutdown under concurrent load.
4. **Architectural Purpose**: Empirically validates that perimeter resource controls prevent system collapse and that shutdown completes with zero dropped in-flight requests (ADR-009, ADR-010).
5. **Scope**:
   - Graceful drain coordination:
     - On shutdown signal (`SIGINT`, `SIGTERM`), mark `health_manager_->set_ready(false)` (`NOT_SERVING`).
     - Enter draining phase: reject new inbound requests with HTTP 503 `SERVER_SHUTTING_DOWN`.
     - Await completion of active requests with bounded timeout (e.g., 5s).
   - Create live integration test suite: `tests/integration/gateway_resource_controls_integration_test.cpp`:
     - Test 1: `BulkheadIsolationPreventsWorkloadStarvation`: Saturated Files pool does not prevent Auth login from succeeding.
     - Test 2: `BulkheadRejectionEmits503WithRetryAfter`: Saturated pool returns HTTP 503 and RFC 7807 schema.
     - Test 3: `RateLimiterRejectsBurstsWith429AndHeaders`: Exceeding token bucket capacity emits HTTP 429 with `Retry-After` and `X-RateLimit-*` headers.
     - Test 4: `RateLimiterTokenRefillAllowsSubsequentTraffic`: Waiting allows token bucket regeneration.
     - Test 5: `RateLimiterMemoryStaysBoundedUnderClientChurn`: Rapid client IP churn does not leak memory.
     - Test 6: `CircuitBreakerTripsOpenAfterConsecutiveFailures`: 5 consecutive backend failures transitions breaker to `OPEN`.
     - Test 7: `CircuitBreakerOpenFailsFastWithZeroRpcDispatches`: Requests in `OPEN` fail fast in <5ms without calling downstream gRPC.
     - Test 8: `CircuitBreakerRecoversToClosedOnSuccessfulProbe`: Breaker transitions `HALF_OPEN` $\to$ `CLOSED` when backend recovers.
     - Test 9: `CircuitBreakerRevertsToOpenOnFailedProbe`: Breaker reverts `HALF_OPEN` $\to$ `OPEN` if probe fails.
     - Test 10: `GracefulShutdownCompletesInFlightRequests`: In-flight request finishes HTTP 200 during drain while new request gets 503.
   - Register target `securecloud_gateway_resource_controls_integration_test` in `tests/integration/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Kernel socket buffer tuning (deferred to deployment / infrastructure).
7. **Dependencies**: `GW-009-T01`, `GW-009-T02`, `GW-009-T03`.
8. **Files to Create/Modify**:
   - `src/gateway/main.cpp`
   - `tests/integration/gateway_resource_controls_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`
9. **Acceptance Criteria**:
   - All 10 live integration test scenarios pass cleanly over live TLS 1.3 / mTLS sockets.
   - Zero hangs or memory leaks on process exit.

---

## 4. Summary of Planned Deliverables

| Ticket ID | Primary Component | Target Location | Test Target |
|:---|:---|:---|:---|
| **GW-009-T01** | Workload Bulkhead Concurrency Partitioning | `src/gateway/http/bulkhead_manager.*` | `securecloud_gateway_bulkhead_manager_test` |
| **GW-009-T02** | Per-Client / Per-IP Rate Limiter & Memory Bounds | `src/gateway/http/middleware/rate_limiter_middleware.*` | `securecloud_gateway_rate_limiter_test` |
| **GW-009-T03** | Downstream Service Circuit Breaker Engine | `src/gateway/http/circuit_breaker.*` | `securecloud_gateway_circuit_breaker_test` |
| **GW-009-T04** | Coordinated Graceful Drain & Live Controls Suite | `tests/integration/gateway_resource_controls_integration_test.cpp` | `securecloud_gateway_resource_controls_integration_test` |

---

## 5. Architectural Invariants Verification Matrix

| Invariant / Requirement | Mechanism in GW-009 | Verification Method |
|:---|:---|:---|
| **ADR-005: Zero Database Invariant** | No database headers, connections, or libraries included in Gateway. | Link inspection, build checks. |
| **Workload Bulkhead Isolation** | Concurrency partitioned across Auth, Messaging, Files, and Emergency. | Integration test #1 & #2 in T04. |
| **Bounded Memory Rate Limiting** | Token bucket with max tracked clients ceiling and idle client eviction. | Unit tests in T02, integration test #5 in T04. |
| **RFC 6585 Rate Limiting Headers** | `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`. | Integration test #3 in T04. |
| **Fail-Fast Circuit Breaking** | `CLOSED` $\leftrightarrow$ `OPEN` $\leftrightarrow$ `HALF_OPEN` FSM per downstream service. | Unit tests in T03, integration tests #6-#9 in T04. |
| **Safe Coordinated Drain** | Transition readiness to `NOT_SERVING`, drain active requests, reject new requests with 503. | Integration test #10 in T04. |
