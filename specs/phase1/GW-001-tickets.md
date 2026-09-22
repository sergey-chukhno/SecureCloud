# GW-001 — Establish Gateway Service Foundation
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: GW-001  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **GW-001** establishes the foundational HTTP runtime, routing infrastructure, lifecycle management, downstream gRPC client foundation, dual-stack health/readiness engine, and testing harness for the **SecureCloud API Gateway** (`securecloud-gateway`).

### Key Invariants & Architectural Boundaries
1. **Strict No-Database Invariant (ADR-005, Gateway Design 3.1, 3.24)**:
   The Gateway owns **zero business data persistence**. It must NEVER configure, connect to, or bundle drivers for PostgreSQL, ScyllaDB, MinIO, or ClickHouse. Any attempt to introduce database clients into `src/gateway` will be rejected at code review.
2. **Strict Observational Host PostgreSQL 14 Guard**:
   The developer workstation host runs an active PostgreSQL 14 instance on `localhost:5432`. Gateway developers must ensure no tests or scripts attempt to connect to, stop, or reconfigure port `5432`.
3. **Security & Protocol Boundary (Gateway Design 3.1, 3.2)**:
   The Gateway is the single external entry point. It terminates external client traffic (REST/JSON over HTTP/HTTPS) and translates requests into internal service calls (gRPC/Protobuf over mTLS). It does not hold E2E encryption keys or message plaintext.
4. **Dual-Stack Health & Readiness**:
   Gateway exposes operational health through two interfaces:
   - **Internal gRPC mTLS Health Service**: Standard `grpc.health.v1.Health` service for internal container orchestration and probe CLI (`SC-013`).
   - **External HTTP Health Endpoints**: `/health/live` and `/health/ready` returning JSON `{"status": "SERVING"}` (HTTP 200) or `503 Service Unavailable` for external load balancers.
5. **Zero Backend Business Logic in GW-001**:
   GW-001 creates the HTTP and gRPC transport skeleton, routing engine, and health evaluation. It does **not** implement JWT verification (GW-004), request routing to backend business RPCs (GW-006), or streaming file transfers (GW-007).
6. **M1 Non-Regression Invariant**:
   All Milestone 1 capabilities, CMake build presets, protobuf generation targets, mTLS credential loaders, and `verify-local.py` orchestration must continue passing cleanly across macOS (AppleClang), Windows (MSVC x64), and Windows (MinGW-w64).

---

## 2. Dependency Graph

```text
               SC-006 (Base Framework & Logging)
               SC-010 (mTLS Transport & Credentials)
               SC-012 (Common Configuration Model)
               SC-013 (Health & Readiness Contracts)
                          │
                          ▼
                     GW-001-T01
          (HTTP & JSON Dependencies: httplib, nlohmann-json)
                          │
                          ▼
                     GW-001-T02
          (GatewayConfig & Strict No-DB Model)
                          │
          ┌───────────────┴───────────────┐
          │                               │
          ▼                               ▼
     GW-001-T03                      GW-001-T05
  (HTTP Server Engine &           (Downstream gRPC Client
   Lifecycle Management)           Manager & mTLS Channels)
          │                               │
          ▼                               │
     GW-001-T04                           │
  (Routing Dispatcher,                    │
   Middleware & Error Mapper)             │
          │                               │
          └───────────────┬───────────────┘
                          │
                          ▼
                     GW-001-T06
          (Dual-Stack Health/Readiness &
           Integration Verification Suite)
```

---

## 3. Implementation Tickets for Developer Louis

### GW-001-T01 — External HTTP & JSON Dependencies Integration (`cpp-httplib`, `nlohmann-json`)

1. **Ticket ID**: `GW-001-T01`
2. **Title**: External HTTP & JSON Dependencies Integration (`cpp-httplib`, `nlohmann-json`)
3. **Objective**: Add `cpp-httplib` and `nlohmann-json` to `vcpkg.json`, integrate discovery into `cmake/modules/SecureCloudDependencies.cmake`, export interface targets, and verify clean compilation across MSVC (x64), MinGW-w64, and AppleClang.
4. **Architectural Purpose**: Establishes modern, cross-platform HTTP networking and JSON serialization libraries required for the Gateway REST API (ADR-004, `docs/design/gateway-design.md` 3.3).
5. **Scope**:
   - Update `vcpkg.json` to declare `"cpp-httplib"` and `"nlohmann-json"`.
   - Update `cmake/modules/SecureCloudDependencies.cmake`:
     - Discover `nlohmann_json` via `find_package(nlohmann_json CONFIG QUIET)` with interface target `securecloud::json`.
     - Discover `httplib` via `find_package(httplib CONFIG QUIET)` with interface target `securecloud::httplib`.
     - Support fallback definitions for MSYS2/MinGW (`CPPHTTPLIB_OPENSSL_SUPPORT`).
   - Create smoke test `tests/unit/gateway/http_smoke_test.cpp` verifying JSON serialization and HTTP request/response object creation.
6. **Explicit Out-of-Scope**: Writing server listeners, network sockets, or routing logic.
7. **Dependencies**: Upstream SC-002. Downstream GW-001-T02, GW-001-T03.
8. **Exact Repository Starting Point**: `vcpkg.json`, `cmake/modules/SecureCloudDependencies.cmake`, `src/gateway/CMakeLists.txt`.
9. **Files/Directories to Inspect**: `vcpkg.json`, `cmake/modules/SecureCloudDependencies.cmake`, `src/common/CMakeLists.txt`.
10. **Files/Directories to Create**:
    - `tests/unit/gateway/http_smoke_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `vcpkg.json`
    - `cmake/modules/SecureCloudDependencies.cmake`
    - `tests/unit/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `src/common/*`, `deploy/compose/*`.
13. **Detailed Implementation Requirements**:
    - **vcpkg Manifest**: Add dependencies in `vcpkg.json`:
      ```json
      "dependencies": [
        "grpc",
        "gtest",
        "protobuf",
        "nlohmann-json",
        "cpp-httplib"
      ]
      ```
    - **CMake Targets**:
      - `securecloud::json` linking `nlohmann_json::nlohmann_json`.
      - `securecloud::httplib` linking `httplib::httplib` and OpenSSL (`OpenSSL::SSL`, `OpenSSL::Crypto`).
      - Compile definition `CPPHTTPLIB_OPENSSL_SUPPORT` enabled on `securecloud::httplib`.
    - **MSVC & MinGW Compatibility**:
      - On Windows, ensure `WIN32_LEAN_AND_MEAN` and include order protection so `<windows.h>` does not conflict with `<winsock2.h>`.
14. **Testing Requirements**:
    - `tests/unit/gateway/http_smoke_test.cpp`:
      - Validates JSON parse and emit roundtrip.
      - Validates instantiating `httplib::Request` and `httplib::Response`.
15. **Validation Commands**:
    ```bash
    cmake --preset dev-debug
    cmake --build --preset dev-debug --target securecloud_http_smoke_test
    ctest --preset dev-debug -R http_smoke_test --output-on-failure
    ```
16. **Acceptance Criteria**: Both libraries discoverable and build without warnings on macOS, MSVC, and MinGW.

---

### GW-001-T02 — Gateway Configuration Model & Strict No-DB Architectural Invariant

1. **Ticket ID**: `GW-001-T02`
2. **Title**: Gateway Configuration Model & Strict No-DB Architectural Invariant
3. **Objective**: Expand `GatewayConfig` with typed HTTP server settings, request limits, and downstream endpoints, enforcing strict validation and asserting the zero-database architectural invariant.
4. **Architectural Purpose**: Provides validated, type-safe configuration for Gateway runtime and protects system architecture against illegal database dependencies (ADR-005, Gateway Design 3.1).
5. **Scope**:
   - Update `src/gateway/gateway_config.{hpp,cpp}`:
     - `http_listen_address` (default `127.0.0.1`).
     - `http_listen_port` (default `8080`, environment `SECURECLOUD_GATEWAY_HTTP_PORT`).
     - `max_payload_bytes` (default `10485760` / 10MB, environment `SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES`).
     - `request_timeout_ms` (default `5000` ms, environment `SECURECLOUD_GATEWAY_REQUEST_TIMEOUT_MS`).
     - `server_threads` (default `4`, environment `SECURECLOUD_GATEWAY_SERVER_THREADS`).
     - Downstream service endpoints (`auth_endpoint`, `messaging_endpoint`, `files_endpoint`, `audit_endpoint`).
   - Add negative architectural unit test asserting `GatewayConfig` contains no database fields (`db_host`, `db_port`, `db_name`, `db_password`).
   - Create unit tests in `tests/unit/gateway/gateway_config_test.cpp`.
6. **Explicit Out-of-Scope**: Parsing TLS certificates for client-side HTTPS (owned by GW-002).
7. **Dependencies**: Upstream GW-001-T01, SC-012. Downstream GW-001-T03.
8. **Exact Repository Starting Point**: `src/gateway/gateway_config.hpp`, `src/gateway/gateway_config.cpp`.
9. **Files/Directories to Inspect**: `src/common/include/securecloud/configuration/common_service_config.hpp`.
10. **Files/Directories to Create**:
    - `tests/unit/gateway/gateway_config_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `src/gateway/gateway_config.hpp`
    - `src/gateway/gateway_config.cpp`
    - `tests/unit/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**: `src/auth/*`, `src/common/*`.
13. **Detailed Implementation Requirements**:
    - Validation rules:
      - `http_listen_port`: Must be between `1` and `65535`.
      - `max_payload_bytes`: Must be between `1024` (1KB) and `104857600` (100MB).
      - `request_timeout_ms`: Must be between `100` and `60000` (100ms - 60s).
      - `server_threads`: Must be between `1` and `128`.
      - `auth_endpoint`: Must not be empty.
    - Architectural Assertion: Code comments and static test assertions confirming Gateway has no database connection string or credentials.
14. **Testing Requirements**:
    - Validates default values.
    - Validates loading from `MapConfigurationSource`.
    - Validates boundary failures (invalid port `0`, negative timeouts, oversized payloads).
15. **Acceptance Criteria**: 100% config validation coverage; invalid environments fail with actionable error messages.

---

### GW-001-T03 — Modular HTTP Server Lifecycle, Thread Pool & Graceful Shutdown

1. **Ticket ID**: `GW-001-T03`
2. **Title**: Modular HTTP Server Lifecycle, Thread Pool & Graceful Shutdown
3. **Objective**: Implement `HttpServer` class wrapping the HTTP engine in `src/gateway/http/http_server.{hpp,cpp}` with explicit 3-state lifecycle (`Stopped`, `Running`, `Draining`), configurable thread pool, signal handling, and deterministic graceful shutdown.
4. **Architectural Purpose**: Provides robust, non-blocking HTTP server lifecycle and clean teardown without socket leaks or unhandled thread aborts (ADR-001, ADR-010).
5. **Scope**:
   - Create `src/gateway/http/http_server.{hpp,cpp}`:
     - Encapsulates `httplib::Server`.
     - Configures listen host/port, payload limits, keep-alive, and worker thread pool count.
     - Implements `start_async()` (spawns listening worker thread) and `stop()` (triggers graceful drain and socket close).
     - Tracks server state (`is_running()`).
   - Integrate with process signal handling in `src/gateway/main.cpp`.
   - Provide unit tests in `tests/unit/gateway/http_server_lifecycle_test.cpp`.
6. **Explicit Out-of-Scope**: TLS termination (GW-002); complex route dispatching.
7. **Dependencies**: Upstream GW-001-T01, GW-001-T02. Downstream GW-001-T04, GW-001-T06.
8. **Exact Repository Starting Point**: `src/gateway/main.cpp`, `src/gateway/CMakeLists.txt`.
9. **Files/Directories to Create**:
    - `src/gateway/http/http_server.hpp`
    - `src/gateway/http/http_server.cpp`
    - `tests/unit/gateway/http_server_lifecycle_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/CMakeLists.txt`
    - `src/gateway/main.cpp`
    - `tests/unit/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Server must bind to `config.http_listen_address` and `config.http_listen_port`.
    - `stop()` must unblock the listening socket and join the worker thread cleanly within bounded timeout (maximum 2 seconds).
    - Under Windows, ensure Winsock is initialized via `ensure_integration_winsock()` or `WSAStartup`.
13. **Testing Requirements**:
    - Start server on random ephemeral port (`127.0.0.1:0`).
    - Verify client connection succeeds.
    - Call `stop()` and verify thread joins cleanly and subsequent requests are refused.
14. **Acceptance Criteria**: Clean start/stop cycle; zero socket leaks; passes thread sanitizer and valgrind where available.

---

### GW-001-T04 — HTTP Routing Dispatcher, Middleware Pipeline & Standard Error Mapper

1. **Ticket ID**: `GW-001-T04`
2. **Title**: HTTP Routing Dispatcher, Middleware Pipeline & Standard Error Mapper
3. **Objective**: Implement a modular HTTP `Router`, composable `Middleware` chain, and `ErrorMapper` producing standardized RFC 7807 / SecureCloud JSON error envelopes.
4. **Architectural Purpose**: Enforces consistent request pre-processing, structured error responses, and prevents leaking internal backend topology to external clients (Gateway Design 3.20, 3.23).
5. **Scope**:
   - Create `src/gateway/http/router.{hpp,cpp}`:
     - Method + exact path matching (`GET`, `POST`, `PUT`, `DELETE`).
     - Handler function signature: `std::function<void(const HttpRequest&, HttpResponse&)>`.
   - Create `src/gateway/http/middleware.{hpp,cpp}`:
     - `Middleware` interface with `process(HttpRequest&, HttpResponse&, NextHandler)`.
     - `RequestIdMiddleware`: Generates/propagates `X-Request-Id` (UUIDv7 or UUIDv4).
     - `LoggingMiddleware`: Logs method, path, status, duration, and request ID. Secret-safe (never logs bodies of auth endpoints).
   - Create `src/gateway/http/error_mapper.{hpp,cpp}`:
     - Formats standard error payload:
       ```json
       {
         "error": {
           "code": "BAD_REQUEST",
           "message": "Invalid JSON body",
           "request_id": "018d3a7e-..."
         }
       }
       ```
     - Maps gRPC status codes (`NOT_FOUND`, `UNAUTHENTICATED`, `PERMISSION_DENIED`, `UNAVAILABLE`) to HTTP status codes (`404`, `401`, `403`, `503`).
   - Provide unit tests in `tests/unit/gateway/router_middleware_test.cpp`.
6. **Explicit Out-of-Scope**: Authentication token extraction (GW-004).
7. **Dependencies**: Upstream GW-001-T01, GW-001-T03. Downstream GW-001-T06.
8. **Exact Repository Starting Point**: `src/gateway/http/http_server.hpp`.
9. **Files/Directories to Create**:
    - `src/gateway/http/router.hpp`
    - `src/gateway/http/router.cpp`
    - `src/gateway/http/middleware.hpp`
    - `src/gateway/http/middleware.cpp`
    - `src/gateway/http/error_mapper.hpp`
    - `src/gateway/http/error_mapper.cpp`
    - `tests/unit/gateway/router_middleware_test.cpp`
10. **Files/Directories That May Be Modified**: `src/gateway/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - 404 handler for unregistered routes returning `{"error": {"code": "NOT_FOUND", ...}}`.
    - 405 handler for unsupported HTTP methods.
    - Catch-all exception handler converting unhandled exceptions into HTTP 500 with generic safe error message (no stack traces, no internal IP disclosure).
13. **Testing Requirements**:
    - Middleware execution ordering (pre-processing -> handler -> post-processing).
    - `X-Request-Id` header injection and preservation.
    - Error mapper JSON schema validation.
14. **Acceptance Criteria**: All router tests pass; standard error envelope conforms to specification.

---

### GW-001-T05 — Downstream gRPC Channel Manager & mTLS Client Foundation

1. **Ticket ID**: `GW-001-T05`
2. **Title**: Downstream gRPC Channel Manager & mTLS Client Foundation
3. **Objective**: Implement `GrpcChannelManager` in `src/gateway/grpc/channel_manager.{hpp,cpp}` managing authenticated mTLS channels to internal microservices (Auth, Messaging, Files, Audit) with channel caching, connectivity monitoring, and deadline configuration.
4. **Architectural Purpose**: Establishes secure internal transport from Gateway to backend microservices using mutual TLS with service SAN verification (ADR-004, ADR-010, `auth-design.md` 4.19).
5. **Scope**:
   - Create `src/gateway/grpc/channel_manager.{hpp,cpp}`:
     - Manages channels for `"auth"`, `"messaging"`, `"files"`, `"audit"`.
     - Creates channels using `securecloud::common::security::MtlsCredentialLoader::create_mtls_channel`.
     - Configures channel arguments (keepalive pings, timeouts, user-agent `securecloud-gateway/1.0`).
     - Exposes channel connectivity probe (`check_connectivity(service_name, timeout)`).
   - Integrate with Gateway shutdown to drain and reset channels cleanly.
   - Provide unit tests in `tests/unit/gateway/channel_manager_test.cpp`.
6. **Explicit Out-of-Scope**: Calling business RPCs (Authenticate, SendMessage, etc.).
7. **Dependencies**: Upstream GW-001-T01, GW-001-T02, SC-010. Downstream GW-001-T06.
8. **Exact Repository Starting Point**: `src/gateway/gateway_config.hpp`, `src/common/include/securecloud/security/mtls_config.hpp`.
9. **Files/Directories to Create**:
    - `src/gateway/grpc/channel_manager.hpp`
    - `src/gateway/grpc/channel_manager.cpp`
    - `tests/unit/gateway/channel_manager_test.cpp`
10. **Files/Directories That May Be Modified**: `src/gateway/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
12. **Detailed Implementation Requirements**:
    - Gateway uses its own service identity certificate (`gateway.crt`, `gateway.key`, `ca.crt`).
    - Downstream expected SAN identities:
      - Auth: `DNS:auth`
      - Messaging: `DNS:messaging`
      - Files: `DNS:files`
      - Audit: `DNS:audit`
    - Channel caching: Reuses existing channel per target rather than recreating on each request.
13. **Testing Requirements**:
    - Validates channel creation with dev PKI certs.
    - Validates connectivity check returns false when service target is down without throwing exceptions.
14. **Acceptance Criteria**: Channels created with mTLS credentials; clean reset on shutdown.

---

### GW-001-T06 — Dual-Stack Health/Readiness & Integration Verification Suite

1. **Ticket ID**: `GW-001-T06`
2. **Title**: Dual-Stack Health/Readiness & Integration Verification Suite
3. **Objective**: Implement dual-stack health and readiness monitoring (external HTTP `/health/live`, `/health/ready` and internal gRPC `HealthServiceImpl`), wire the Gateway executable in `src/gateway/main.cpp`, and build a comprehensive integration test suite.
4. **Architectural Purpose**: Delivers production-grade operational observability for both container orchestrators and external load balancers, verifying the complete Gateway foundation (SC-013, GW-001 Acceptance).
5. **Scope**:
   - Create `src/gateway/health/gateway_health_evaluator.{hpp,cpp}`:
     - Evaluates downstream dependency connectivity (Auth reachability via `GrpcChannelManager`).
     - Degrades readiness when downstream dependencies are unreachable while maintaining liveness.
   - Wire HTTP endpoints in `Router`:
     - `GET /health/live` -> 200 OK `{"status": "SERVING"}`.
     - `GET /health/ready` -> 200 OK `{"status": "SERVING"}` when healthy; 503 `{"status": "NOT_SERVING"}` when dependencies fail.
   - Retain internal gRPC mTLS server on internal port for container probe CLI (`SC-013-T06`).
   - Wire `src/gateway/main.cpp` to start both servers concurrently.
   - Create `tests/integration/gateway_integration_test.cpp`:
     - Test 1: External HTTP `/health/live` returns 200 OK with valid JSON.
     - Test 2: External HTTP `/health/ready` returns 200 OK when downstream mock is healthy.
     - Test 3: External HTTP `/health/ready` degrades to 503 when downstream dependency fails.
     - Test 4: Internal gRPC mTLS health check succeeds via probe CLI.
     - Test 5: Unknown HTTP route returns 404 with standard error JSON.
     - Test 6: Bounded graceful shutdown terminates both HTTP and gRPC listeners without deadlocks.
6. **Explicit Out-of-Scope**: Reverse-proxying business requests.
7. **Dependencies**: Upstream GW-001-T01 through GW-001-T05, SC-013, SC-014. Downstream GW-002, GW-003.
8. **Exact Repository Starting Point**: `src/gateway/main.cpp`, `tests/integration/CMakeLists.txt`.
9. **Files/Directories to Create**:
    - `src/gateway/health/gateway_health_evaluator.hpp`
    - `src/gateway/health/gateway_health_evaluator.cpp`
    - `tests/integration/gateway_integration_test.cpp`
10. **Files/Directories That May Be Modified**:
    - `src/gateway/main.cpp`
    - `src/gateway/CMakeLists.txt`
    - `tests/integration/CMakeLists.txt`
11. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `deploy/compose/*`.
12. **Detailed Implementation Requirements**:
    - Integration test must use custom `main()` calling `::TerminateProcess` on Windows after `RUN_ALL_TESTS()` to prevent `winpthreads` exit hangs:
      ```cpp
      int main(int argc, char** argv) {
          ::testing::InitGoogleTest(&argc, argv);
          int result = RUN_ALL_TESTS();
      #ifdef _WIN32
          std::fflush(nullptr);
          ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
      #else
          return result;
      #endif
      }
      ```
    - Server ports must use loopback `127.0.0.1` and ephemeral ports (`0`) during tests to avoid port conflicts.
13. **Validation Commands**:
    ```bash
    python3 scripts/verify-local.py
    ctest --preset dev-debug -R gateway_integration_test --output-on-failure
    ```
14. **Acceptance Criteria**: Gateway runs independently; HTTP and gRPC health checks pass; no database dependencies; zero deadlocks on test process termination.
15. **Definition of Done**: All 6 integration scenarios pass; code formatted and checked with clang-tidy; zero regressions in Milestone 1 tests.

---

## 4. Git Commit Hygiene & Traceability Plan for Louis

Louis must commit work iteratively following conventional commit conventions:

1. `build(deps): integrate cpp-httplib and nlohmann-json dependencies (GW-001-T01)`
2. `feat(gateway): implement typed GatewayConfig with strict no-db invariant (GW-001-T02)`
3. `feat(gateway): implement modular HttpServer lifecycle and thread pool (GW-001-T03)`
4. `feat(gateway): implement HTTP router, middleware pipeline, and error mapper (GW-001-T04)`
5. `feat(gateway): implement downstream gRPC channel manager with mTLS (GW-001-T05)`
6. `test(gateway): implement dual-stack health readiness and integration test suite (GW-001-T06)`

---

## 5. Developer Louis PR Checklist & Gatekeeper Review Gate

Before submitting the PR for Sergey's review:

- [ ] `vcpkg.json` and CMake build cleanly on Windows (MSVC x64 Native Tools).
- [ ] No database drivers (`libpqxx`, etc.) or DB configs exist in `src/gateway`.
- [ ] Host PostgreSQL on port `5432` has not been contacted or modified.
- [ ] HTTP server graceful shutdown unblocks and joins in < 2 seconds.
- [ ] JSON errors follow standard SecureCloud schema (`{"error": {"code": "...", "message": "..."}}`).
- [ ] Downstream gRPC channels use mutual TLS with strict SAN identity verification.
- [ ] Integration tests use ephemeral ports and terminate cleanly without MinGW deadlocks.
- [ ] `python3 scripts/verify-local.py` passes all 5 stages in < 30 seconds.
