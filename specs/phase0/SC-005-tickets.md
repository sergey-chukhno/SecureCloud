# SC-005 Implementation Tickets — Configure Protobuf + gRPC generation (Revised Specification)

**Card ID:** SC-005  
**Title:** Configure Protobuf + gRPC generation  
**Milestone:** M1 — Buildable Distributed Skeleton  
**Owner:** Sergey  
**Status:** Approved Specification Baseline  


### SC005-T01 — Establish Protobuf & gRPC Dependency Discovery Pipeline

- **Objective:** Extend `cmake/modules/SecureCloudDependencies.cmake` to discover `Protobuf` and `gRPC` libraries, `protoc` compiler binary, and `grpc_cpp_plugin` compiler plugin binary across host/package manager toolchains cleanly without machine-specific hardcoded paths.
- **Exact Files Affected:**
  - `cmake/modules/SecureCloudDependencies.cmake`
  - `vcpkg.json` (only if dependencies need manifest declaration)
- **Dependencies:** SC-001, SC-002
- **Implementation Approach:**
  - Inspect host toolchain and package manager discovery mechanisms.
  - Use `find_package(Protobuf REQUIRED)` to locate `Protobuf::libprotobuf` and `protobuf::protoc` (or `Protobuf_PROTOC_EXECUTABLE`).
  - Use `find_package(gRPC REQUIRED)` or `find_program` for `grpc_cpp_plugin` (checking standard paths/hints such as `/opt/homebrew/bin`, `/usr/local/bin`) to locate `gRPC::grpc++` and the C++ gRPC plugin binary (`GRPC_CPP_PLUGIN_BIN`).
  - Verify that `protoc` and `grpc_cpp_plugin` originate from a compatible, consistent toolchain installation.
  - Provide explicit, clear CMake error messages if Protobuf or gRPC components cannot be resolved reproducibly.
  - Avoid hardcoding machine-specific absolute paths.
- **Relevant Project Rules:** `docs/implementation/repository-structure.md`, `docs/implementation/api-and-contracts.md` Section 3.2.
- **Security Considerations:** Ensures network RPC dependencies originate from verified, version-controlled package manager/host baselines.
- **Tests & Validation:** Run `cmake --preset dev-debug` to verify clean discovery of `Protobuf::libprotobuf`, `gRPC::grpc++`, `protoc`, and `grpc_cpp_plugin`.
- **Acceptance Criteria:**
  - CMake configure finds Protobuf and gRPC libraries and compiler plugins reproducibly with explicit status logging.
  - Missing dependencies trigger an informative CMake error rather than silent fallback.
  - No machine-specific hardcoded paths exist in CMake modules.

---

### SC005-T02 — Create CMake Code-Generation Module (`SecureCloudProtobuf.cmake`)

- **Objective:** Create `cmake/modules/SecureCloudProtobuf.cmake` defining a reusable CMake function (`securecloud_add_proto_library`) using `add_custom_command(OUTPUT ...)` to invoke `protoc` with C++ and gRPC plugins, preserving the source directory tree out-of-source under `${CMAKE_BINARY_DIR}/generated/proto/`.
- **Exact Files Affected:**
  - `cmake/modules/SecureCloudProtobuf.cmake`
  - `CMakeLists.txt`
- **Dependencies:** SC005-T01
- **Implementation Approach:**
  - Define `securecloud_add_proto_library(TARGET_NAME PROTO_FILES ...)` in `cmake/modules/SecureCloudProtobuf.cmake`.
  - For each input `.proto` file (e.g. `proto/securecloud/common/v1/health.proto`), compute its output path preserving directory structure: `${CMAKE_BINARY_DIR}/generated/proto/securecloud/common/v1/health.pb.h`, `health.pb.cc`, `health.grpc.pb.h`, `health.grpc.pb.cc`.
  - Configure `add_custom_command(OUTPUT ... DEPENDS ${PROTO_FILE} ${PROTOC_BIN} ${GRPC_CPP_PLUGIN_BIN})` executing:
    ```bash
    protoc --proto_path=${CMAKE_SOURCE_DIR}/proto \
           --cpp_out=${CMAKE_BINARY_DIR}/generated/proto \
           --grpc_out=${CMAKE_BINARY_DIR}/generated/proto \
           --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_BIN} \
           ${PROTO_FILE_ABS_PATH}
    ```
  - Wrap generated `.pb.cc` and `.grpc.pb.cc` source files into a CMake static library target (`add_library(${TARGET_NAME} STATIC ...)`).
  - Configure `target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_BINARY_DIR}/generated/proto)`.
  - Configure `target_link_libraries(${TARGET_NAME} PUBLIC Protobuf::libprotobuf gRPC::grpc++)`.
  - Ensure CMake recognizes generated files as proper build outputs, enabling incremental regeneration when `.proto` files change and clean builds without manual `protoc` execution.
- **Relevant Project Rules:** `docs/implementation/api-and-contracts.md` Section 5 (Generated code in build/generated/ location; nested proto directory structure preserved; never manually edited).
- **Security Considerations:** Out-of-source generation prevents dirty workspace trees and prevents accidental committing of generated artifacts.
- **Tests & Validation:** Verify custom command dependency graph via `cmake --preset dev-debug` and inspect generated CMake build rules in Ninja build file.
- **Acceptance Criteria:**
  - Preserves proto directory hierarchy under `${CMAKE_BINARY_DIR}/generated/proto/` (e.g., `securecloud/common/v1/`).
  - Generated files are recognized by CMake as build outputs.
  - Generated static library exports `${CMAKE_BINARY_DIR}/generated/proto` as a `PUBLIC` include directory and links `Protobuf::libprotobuf` and `gRPC::grpc++`.
  - Second `cmake --build` without modifying `.proto` files does not trigger unnecessary re-generation.

---

### SC005-T03 — Establish Baseline Representative Protobuf & gRPC Service Contracts

- **Objective:** Establish the repository `.proto` layout under `proto/securecloud/` and create a minimal representative build-proving contract `proto/securecloud/common/v1/health.proto` defining health check RPC messages and service interface, registered in `proto/CMakeLists.txt`.
- **Exact Files Affected:**
  - `proto/securecloud/common/v1/health.proto`
  - `proto/CMakeLists.txt`
  - `CMakeLists.txt`
- **Dependencies:** SC005-T01, SC005-T02
- **Implementation Approach:**
  - Create minimal `proto/securecloud/common/v1/health.proto` using `syntax = "proto3";`, package `securecloud.common.v1;`, defining `HealthCheckRequest`, `HealthCheckResponse`, `ServingStatus` enum, and `HealthService` gRPC service interface (`rpc Check(HealthCheckRequest) returns (HealthCheckResponse);`).
  - Clarify that `health.proto` is a build-proving baseline contract for SC-005, not the production health/readiness architecture (which is implemented in SC-013).
  - Create `proto/CMakeLists.txt` invoking `securecloud_add_proto_library(securecloud_proto PROTO_FILES securecloud/common/v1/health.proto)`.
  - Register `proto` directory in top-level `CMakeLists.txt` via `add_subdirectory(proto)`.
- **Relevant Project Rules:** `docs/implementation/api-and-contracts.md` Section 3.2 & Section 5.
- **Security Considerations:** Transport security (TLS 1.3 / mTLS) is handled by service security architecture (SC-009/SC-010), not Protobuf/gRPC generation.
- **Tests & Validation:** Execute `cmake --build --preset dev-debug` to generate `.pb.h`, `.pb.cc`, `.grpc.pb.h`, `.grpc.pb.cc` under `build/dev-debug/generated/proto/securecloud/common/v1/` and compile static library `libsecurecloud_proto.a`.
- **Acceptance Criteria:**
  - `health.proto` parses cleanly with `protoc` and `grpc_cpp_plugin`.
  - `securecloud_proto` target builds out-of-source into static library `libsecurecloud_proto.a`.
  - Generated header location matches `#include "securecloud/common/v1/health.pb.h"` and `#include "securecloud/common/v1/health.grpc.pb.h"`.

---

### SC005-T04 — Consumer Integration, Formatting Validation & Incremental Build Test

- **Objective:** Link representative consumer targets (`src/common` and unit test target `securecloud_proto_smoke_test`) against `securecloud_proto`, verify C++ compilation/linkage of generated types, confirm SC-004 `check-format` ignores generated code, and validate incremental build behavior.
- **Exact Files Affected:**
  - `src/common/CMakeLists.txt`
  - `tests/unit/proto_smoke_test.cpp`
  - `tests/unit/CMakeLists.txt`
- **Dependencies:** SC005-T01, SC005-T02, SC005-T03
- **Implementation Approach:**
  - Update `src/common/CMakeLists.txt` to link `securecloud_proto` (propagating proto includes/linkage to services depending on `securecloud_common`).
  - Create `tests/unit/proto_smoke_test.cpp` verifying that:
    1. `#include "securecloud/common/v1/health.pb.h"` and `#include "securecloud/common/v1/health.grpc.pb.h"` compile cleanly.
    2. `securecloud::common::v1::HealthCheckRequest` and `HealthCheckResponse` can be constructed, fields set/read, and serialized/deserialized to binary string.
    3. `securecloud::common::v1::HealthService::Stub` and `Service` class definitions compile and link successfully.
  - Register `securecloud_proto_smoke_test` target in `tests/unit/CMakeLists.txt` linked to `securecloud_proto` and `GTest::gtest_main`, discovered via `gtest_discover_tests`.
  - Execute `./scripts/check-formatting.sh` to confirm generated code in `build/` is completely excluded from `clang-format` checks.
  - Execute full 7-step incremental build test procedure:
    1. Clean configure (`cmake --preset dev-debug`)
    2. Clean build (`cmake --build --preset dev-debug`)
    3. Verify generated output files in `build/dev-debug/generated/proto/`
    4. Compile generated C++ code
    5. Run `cmake --build --preset dev-debug` again (verify 0 unnecessary re-compilations)
    6. Touch `proto/securecloud/common/v1/health.proto` and re-run build (verify target re-generates and re-compiles)
    7. Execute `ctest --preset dev-debug` (verify test passes 100%).
- **Relevant Project Rules:** `docs/implementation/development-workflow.md` & `docs/implementation/testing-strategy.md`.
- **Security Considerations:** Ensures inter-service contract types can be safely compiled and linked without network socket operations.
- **Tests & Validation:** `cmake --build --preset dev-debug` builds cleanly, `./scripts/check-formatting.sh` exits with 0, `ctest --preset dev-debug` passes 100%.
- **Acceptance Criteria:**
  - `securecloud_proto_smoke_test` compiles, links, and passes CTest.
  - No generated files exist in handwritten source paths (`src/`, `proto/`).
  - SC-004 `check-format` passes 100% (confirming SC-004 generated code exclusion works).
  - Incremental build behavior correctly triggers `protoc` re-generation only when `.proto` is modified.

---

## 5. Dependency Graph

```
  SC005-T01 (Dependency Discovery Pipeline)
       │
       ▼
  SC005-T02 (CMake Code-Gen Module)
       │
       ▼
  SC005-T03 (Baseline Proto Contracts)
       │
       ▼
  SC005-T04 (Consumer Linkage & Validation)
```

---

## 6. Engineering Analysis & Handoff Criteria

### Parallelization Opportunities
- **SC005-T01** and **SC005-T02** must run sequentially to establish discovery before building the custom command generator.
- **SC005-T03** and **SC005-T04** run sequentially after T02.

### Blockers
- None. Host system has `protoc` and package manager toolchains available.

### Risks & Mitigations
- **Risk**: Path collisions if generated files are flattened in output directory.
  - **Mitigation**: T02 explicitly computes nested directory structure (`build/.../generated/proto/securecloud/common/v1/`) matching input `.proto` relative path.
- **Risk**: SC-004 `check-format` accidentally scanning generated C++ files.
  - **Mitigation**: T04 explicitly validates `./scripts/check-formatting.sh` to ensure `PROJECT_TOOLING_FILES` filter in `SecureCloudFormatting.cmake` ignores `build/` and generated code.

### Assumptions
- Protobuf 3 (`proto3`) syntax is used for all inter-service RPC contracts.
- Generated code is never manually edited or committed to git.

### Definition of Done for SC-005
Card **SC-005** is Done when:
1. `Protobuf` and `gRPC` dependencies and plugins (`protoc`, `grpc_cpp_plugin`) are discovered reproducibly via CMake.
2. `cmake/modules/SecureCloudProtobuf.cmake` generates `.pb.h`, `.pb.cc`, `.grpc.pb.h`, `.grpc.pb.cc` out-of-source into `${CMAKE_BINARY_DIR}/generated/proto/` while preserving directory hierarchy.
3. Baseline contract `proto/securecloud/common/v1/health.proto` generates and builds into `securecloud_proto` static library.
4. Unit smoke test verifies compilation, linkage, and binary serialization/deserialization.
5. `check-format` passes 100% and ignores generated code.
6. Incremental rebuild triggers `protoc` re-generation only when `.proto` files change.
7. `ctest --preset dev-debug` passes 100%.
