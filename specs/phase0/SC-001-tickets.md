# SC-001 Implementation Tickets — Initialize CMake Project

**Card ID:** SC-001  
**Title:** Initialize CMake project  
**Milestone:** M1 — Buildable Distributed Skeleton  
**Owner:** Sergey  
**Status:** Decomposed Specification (Awaiting Approval)  

---

## Ticket Specifications

### SC001-T01: Root CMake Configuration & C++20 Compiler Toolchain Setup

- **Ticket ID:** SC001-T01
- **Objective:** Establish root `CMakeLists.txt` and `cmake/modules/SecureCloudCompilerFlags.cmake` establishing CMake 3.28+ baseline requirement, strict C++20 standard enforcement, hardened compiler flags (`-Wall -Wextra -Werror -Wpedantic` on GCC/Clang, `/W4 /WX` on MSVC), build types (Debug, Release, RelWithDebInfo), position-independent code (PIE), and default symbol visibility (`-fvisibility=hidden`).
- **Exact Files Affected:**
  - `CMakeLists.txt`
  - `cmake/modules/SecureCloudCompilerFlags.cmake`
- **Dependencies:** None
- **Implementation Approach:**
  - `cmake_minimum_required(VERSION 3.28)`
  - `project(SecureCloud VERSION 0.1.0 LANGUAGES CXX)`
  - Enforce `CMAKE_CXX_STANDARD 20` and `CMAKE_CXX_STANDARD_REQUIRED ON`, `CMAKE_CXX_EXTENSIONS OFF`.
  - Create interface library `securecloud_compiler_flags` providing compiler options, hardening definitions, and warning configurations target-linked across all subprojects.
- **Relevant Project Rules:** `.antigravity/RULES.md` Rule #1 & #3, C++20 requirement, target-based CMake, no global variable mutation.
- **Tests & Validation:** `cmake -B build -S .` configures cleanly without warnings or standard decay.
- **Acceptance Criteria:**
  - `cmake -B build` succeeds on macOS (Clang) and Linux (GCC).
  - Target `securecloud_compiler_flags` exists and enforces C++20 and `-Werror`.

---

### SC001-T02: Build Presets Configuration (`CMakePresets.json`)

- **Ticket ID:** SC001-T02
- **Objective:** Create standardized `CMakePresets.json` implementing configuration, build, and test presets for developer workflows and CI pipelines.
- **Exact Files Affected:**
  - `CMakePresets.json`
- **Dependencies:** SC001-T01
- **Implementation Approach:**
  - Presets schema version 6.
  - Define `dev-debug` preset (Debug build type, `build/dev-debug` generator directory, verbose build options).
  - Define `dev-release` preset (Release build type, optimizations enabled).
  - Define `ci-linux`, `ci-macos`, and `ci-windows` presets enforcing strict warnings and CTest integration.
  - Define corresponding `buildPresets` and `testPresets` matching configure presets.
- **Relevant Project Rules:** `docs/implementation/development-workflow.md` CMake presets standard.
- **Tests & Validation:** `cmake --preset dev-debug`, `cmake --build --preset dev-debug`, and `ctest --preset dev-debug`.
- **Acceptance Criteria:**
  - `cmake --preset dev-debug` configures into `build/dev-debug`.
  - `cmake --build --preset dev-debug` compiles cleanly.

---

### SC001-T03: Shared Technical Common Infrastructure CMake Wiring

- **Ticket ID:** SC001-T03
- **Objective:** Wire `src/common/` build target (`securecloud::common`) containing technical utility baseline (e.g. version header, baseline types) without business logic.
- **Exact Files Affected:**
  - `src/common/CMakeLists.txt`
  - `src/common/include/securecloud/common/version.hpp`
  - `src/common/src/version.cpp`
- **Dependencies:** SC001-T01
- **Implementation Approach:**
  - Define `add_library(securecloud_common static ...)` with alias `securecloud::common`.
  - Export public include directory `src/common/include`.
  - Link `securecloud_compiler_flags`.
  - Provide macro/constexpr version definition `SECURECLOUD_VERSION_STRING`.
- **Relevant Project Rules:** `docs/implementation/repository-structure.md` Section 9 & 10 (no business logic in common).
- **Tests & Validation:** `securecloud::common` compiles into `libsecurecloud_common.a`.
- **Acceptance Criteria:**
  - Target `securecloud::common` builds successfully and exports standard C++20 header.

---

### SC001-T04: Core Microservices & Client Executable Scaffolding Wireup

- **Ticket ID:** SC001-T04
- **Objective:** Wire CMake subdirectories for all 6 runtime executable targets (`securecloud-client`, `securecloud-gateway`, `securecloud-auth`, `securecloud-messaging`, `securecloud-files`, `securecloud-audit`) with standard main entry points logging service startup.
- **Exact Files Affected:**
  - `src/CMakeLists.txt`
  - `src/client/CMakeLists.txt`, `src/client/main.cpp`
  - `src/gateway/CMakeLists.txt`, `src/gateway/main.cpp`
  - `src/auth/CMakeLists.txt`, `src/auth/main.cpp`
  - `src/messaging/CMakeLists.txt`, `src/messaging/main.cpp`
  - `src/files/CMakeLists.txt`, `src/files/main.cpp`
  - `src/audit/CMakeLists.txt`, `src/audit/main.cpp`
- **Dependencies:** SC001-T01, SC001-T03
- **Implementation Approach:**
  - `add_subdirectory` calls in `src/CMakeLists.txt`.
  - For each service: `add_executable(securecloud-<service> main.cpp)`, link `securecloud::common`, apply `securecloud_compiler_flags`.
  - `main.cpp` outputs clean startup log and returns 0 using idiomatic C++20 `<iostream>` / `<format>`.
- **Relevant Project Rules:** `docs/implementation/repository-structure.md` Section 4 & 5 (Executable components & clean main wrappers).
- **Tests & Validation:** `cmake --build --preset dev-debug` produces all 6 executable binaries in build target directory.
- **Acceptance Criteria:**
  - All 6 executables build without warnings and run, printing initial startup log and exiting cleanly with code 0.

---

### SC001-T05: Test Directory CMake Wiring & CTest Smoke Test Integration

- **Ticket ID:** SC001-T05
- **Objective:** Configure top-level test runner via `tests/CMakeLists.txt`, enable CTest, and add baseline smoke tests for each service category (`unit`, `integration`, `contract`, `e2e`, `security`, `resilience`, `performance`).
- **Exact Files Affected:**
  - `tests/CMakeLists.txt`
  - `tests/unit/CMakeLists.txt`
  - `tests/unit/smoke_test.cpp`
- **Dependencies:** SC001-T01, SC001-T04
- **Implementation Approach:**
  - `enable_testing()` in top-level or `tests/CMakeLists.txt`.
  - Create minimal smoke test binary target `securecloud_unit_smoke_test`.
  - Register test using `add_test(NAME unit_smoke_test COMMAND securecloud_unit_smoke_test)`.
- **Relevant Project Rules:** `docs/implementation/testing-strategy.md`, CTest integration requirement.
- **Tests & Validation:** Running `ctest --preset dev-debug` or `ctest --output-on-failure` executes `unit_smoke_test` and passes 100%.
- **Acceptance Criteria:**
  - `ctest` runs, finds registered tests, passes, and exits with 0 return code.
