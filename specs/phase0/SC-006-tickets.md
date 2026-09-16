# SC-006 Implementation Tickets — Create Service Executable Skeletons (Revised Specification)

**Card ID:** SC-006  
**Title:** Create service executable skeletons  
**Milestone:** M1 — Buildable Distributed Skeleton  
**Owner:** Sergey  
**Status:** Approved Specification Baseline  


### SC006-T01 — Establish Five Backend Service Entry Points

- **Objective:** Establish minimal, deterministic C++20 `main.cpp` process entry points for the five SecureCloud backend services (`gateway`, `auth`, `messaging`, `files`, `audit`), displaying human-readable service name identity and version information.
- **Exact Files Affected:**
  - `src/gateway/main.cpp`
  - `src/auth/main.cpp`
  - `src/messaging/main.cpp`
  - `src/files/main.cpp`
  - `src/audit/main.cpp`
- **Dependencies:** SC-001, SC-002, SC-003, SC-004, SC-005
- **Implementation Approach:**
  - Inspect existing `main.cpp` files under `src/gateway/`, `src/auth/`, `src/messaging/`, `src/files/`, and `src/audit/`.
  - Define explicit human-readable string constants (e.g. `SERVICE_NAME`) in each service entry point.
  - Output structured process startup log using human-readable service name and `securecloud::common::get_version_string()`.
  - Return clean exit code `0`.
  - Keep entry points lightweight and deterministic: NO networking, NO authentication, NO persistence, NO async runtimes, NO thread pools, NO cryptographic identity, NO business logic.
- **Relevant Project Rules:** `docs/implementation/repository-structure.md` Section 4, `docs/implementation/coding-rules.md`.
- **Security Considerations:** Identity refers strictly to human-readable service naming for process output. No secrets, credentials, mock authentication, certificates, CA, or mTLS identities (which belong to SC-009/SC-010).
- **Tests & Validation:** Compile service entry points via `cmake --build --preset dev-debug` and execute each binary manually to verify process startup stdout and exit code `0`.
- **Acceptance Criteria:**
  - All 5 backend service executables display distinct human-readable service identity and version information upon execution and exit cleanly with code `0`.

---

### SC006-T02 — Create and Integrate Five Service Executable Targets

- **Objective:** Verify and integrate CMake executable target definitions for the five backend services (`securecloud-gateway`, `securecloud-auth`, `securecloud-messaging`, `securecloud-files`, `securecloud-audit`), ensuring target boundary isolation and clean CMake dependency graph integration.
- **Exact Files Affected:**
  - `src/gateway/CMakeLists.txt`
  - `src/auth/CMakeLists.txt`
  - `src/messaging/CMakeLists.txt`
  - `src/files/CMakeLists.txt`
  - `src/audit/CMakeLists.txt`
  - `src/CMakeLists.txt`
- **Dependencies:** SC06-T01
- **Implementation Approach:**
  - Inspect `src/*/CMakeLists.txt` files and `src/CMakeLists.txt`.
  - Enforce executable target names (`securecloud-gateway`, `securecloud-auth`, `securecloud-messaging`, `securecloud-files`, `securecloud-audit`).
  - Verify target link rules: no service target may depend directly on another service's private implementation or internal headers.
  - Link shared targets (`securecloud_common`, `securecloud::compiler_flags`) as required.
  - Do NOT link `securecloud_proto` to service skeletons unless directly required by the executable skeleton.
  - Preserve SC-005's Protobuf/gRPC generation architecture in `proto/CMakeLists.txt`.
- **Relevant Project Rules:** `docs/implementation/repository-structure.md` Section 2 & 4 (Service boundary isolation; independent service executables).
- **Security Considerations:** Build-level target boundary isolation prevents accidental cross-service implementation linkage or shared business state.
- **Tests & Validation:** Configure `cmake --preset dev-debug` and build `cmake --build --preset dev-debug` to verify Ninja target graph generation.
- **Acceptance Criteria:**
  - Each of the 5 backend service targets builds independently into a distinct binary artifact.
  - No service executable target links another service's business implementation.

---

### SC006-T03 — Service Skeleton Validation

- **Objective:** Perform end-to-end build, execution, formatting, and test validation across all five backend service skeletons, confirming target buildability, clean process execution, SC-004 formatting compliance, SC-005 Protobuf integration, and CTest suite integrity.
- **Exact Files Affected:**
  - Validation commands & scripts (no code changes unless fixing validation issues).
- **Dependencies:** SC06-T01, SC06-T02
- **Implementation Approach:**
  - Execute full validation sequence:
    1. Clean CMake configure (`cmake --preset dev-debug`)
    2. Clean project build (`cmake --build --preset dev-debug`)
    3. Verify existence of all 5 backend binaries in `build/dev-debug/src/<service>/securecloud-<service>`
    4. Run each of the 5 backend binaries independently to confirm clean stdout logging and exit code `0`
    5. Run `./scripts/check-formatting.sh` to confirm 100% compliance with SC-004 rules
    6. Run `ctest --preset dev-debug` to confirm test suite passes 100%
    7. Confirm SC-005 Protobuf/gRPC generation remains fully functional.
- **Relevant Project Rules:** `docs/implementation/development-workflow.md` & `docs/implementation/testing-strategy.md`.
- **Security Considerations:** Validates process execution boundaries without network socket or IPC dependencies.
- **Tests & Validation:** `cmake --build --preset dev-debug`, binary startup runs, `./scripts/check-formatting.sh`, and `ctest --preset dev-debug`.
- **Acceptance Criteria:**
  - All five backend service executables build and run cleanly.
  - `./scripts/check-formatting.sh` passes 100%.
  - `ctest --preset dev-debug` passes 100%.
  - SC-005 Protobuf pipeline remains green.

---

## 5. Dependency Graph

```
  SC06-T01 (Five Backend Service Entry Points)
       │
       ▼
  SC06-T02 (Five Service Executable Targets)
       │
       ▼
  SC06-T03 (Service Skeleton Validation)
```

---

## 6. Scope Boundaries & Explicit Non-Goals

SC-006 establishes backend executable boundaries ONLY. It explicitly does NOT implement:
- TLS / mTLS
- Service certificates or CA
- Authentication or MFA
- Authorization or JWTs
- Databases (PostgreSQL, ScyllaDB, ClickHouse, MinIO)
- Persistence or data repositories
- HTTP server or REST API
- Service-to-service gRPC server/client communication
- Health / readiness endpoints
- Docker or Docker Compose
- Configuration framework or secrets management
- Production logging framework
- Resilience / rate-limiting / circuit breakers
- Messaging, file transfer, or audit ingestion business logic
- Business APIs or domain logic

---

## 7. Risks & Blockers

- **Architectural Risks:** None. Scope is strictly confined to 5 backend executable skeletons.
- **Build-System Risks:** None. Builds directly on SC-001 through SC-005.
- **Dependency Risks:** None.

---

## 8. Expected Final State

Upon completion of SC-006:
1. Five backend service executables (`securecloud-gateway`, `securecloud-auth`, `securecloud-messaging`, `securecloud-files`, `securecloud-audit`) exist under `build/dev-debug/src/<service>/` and build independently.
2. Each backend service executable has a clean C++20 `main.cpp` process entry point printing human-readable service name identity and version string, exiting cleanly with code `0`.
3. No service executable target links another service's private code or implementation.
4. `./scripts/check-formatting.sh` passes 100%.
5. `ctest --preset dev-debug` passes 100%.
