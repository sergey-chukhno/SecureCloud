# SC-002 Implementation Tickets — Configure Project Dependencies (Revised)

**Card ID:** SC-002  
**Title:** Configure project dependencies  
**Milestone:** M1 — Buildable Distributed Skeleton  
**Owner:** Sergey  
**Status:** Approved Specification  

---

## 1. Dependency Classification for SC-002

To preserve service boundaries and avoid premature implementation bloat, proposed dependencies are classified as follows:

| Dependency | Classification | Justification / Owning Card |
| :--- | :--- | :--- |
| **vcpkg Baseline Manifest** | `required for SC-002 now` | Package management infrastructure baseline required by SC-002. |
| **GoogleTest** | `required by a later card` | Specifically owned and configured by **SC-003** (*Configure GoogleTest + CTest*). |
| **Protobuf / gRPC** | `required by a later card` | Specifically owned and configured by **SC-005** (*Configure Protobuf + gRPC generation*). |
| **OpenSSL** | `required by a later card` | Owned by security/TLS platform cards (Gateway TLS, Auth mTLS). |
| **libsodium** | `required by a later card` | Owned by M2/M3 Cryptographic cards (Signal Protocol primitives). |
| **nlohmann-json** | `required by a later card` | Owned by REST API / Gateway cards. |
| **spdlog / fmt** | `required by a later card` | Owned by operational logging cards. |
| **libpqxx** | `required by a later card` | Owned by Auth PostgreSQL persistence cards (M2). |
| **aws-sdk-cpp-s3** | `not yet justified` | Files service uses MinIO (S3 API compatibility); full SDK selection (AWS C++ SDK vs lightweight S3 client) is deferred to M5 files card after design verification. |

---

## 2. Evaluation of vcpkg

- **Why vcpkg is appropriate:** Native C++ package manager supported by CMake 3.28+, supported by Microsoft on Windows (MSVC), AppleClang on macOS, and GCC/Clang on Linux.
- **Manifest Mode:** Uses repository-root `vcpkg.json` manifest file to declare exact dependencies declaratively rather than requiring manual global installation.
- **Version & Reproducibility Strategy:** Controlled via `builtin-baseline` Git commit SHA in `vcpkg.json` (or `vcpkg-configuration.json`). All developers and CI build agents resolve identical source versions.
- **macOS Compatibility:** Supports AppleClang (`arm64-osx` and `x64-osx` triplets).
- **Linux & Docker Compatibility:** Compiles cleanly in Linux GCC/Clang environments and inside lightweight Docker containers (`x64-linux` triplet).
- **CI Compatibility:** Native integration into GitHub Actions, GitLab CI, and CMakePresets via `CMAKE_TOOLCHAIN_FILE`.
- **Baseline Control:** Upstream dependency versions are locked by pinning the `builtin-baseline` SHA, eliminating floating package versions and supply-chain drift.

---

## 3. Approved Ticket Specifications

### SC002-T01 — Establish dependency manager

- **Objective:** Establish the `vcpkg` package manager foundation in manifest mode (`vcpkg.json`) with a pinned `builtin-baseline` Git commit SHA for reproducible dependency management across macOS, Linux, and Windows, and integrate the toolchain via `CMakePresets.json`.
- **Exact Files Affected:**
  - `vcpkg.json`
  - `vcpkg-configuration.json`
  - `CMakePresets.json`
  - `.gitignore` (add `vcpkg_installed/` to ignore build artifacts)
- **Dependencies:** SC-001 (Build system baseline)
- **Implementation Approach:**
  - Define manifest schema v1.0 in `vcpkg.json` with pinned `builtin-baseline`.
  - Configure toolchain variables (`CMAKE_TOOLCHAIN_FILE`, `VCPKG_TARGET_TRIPLET`) in `CMakePresets.json`.
  - Ensure `vcpkg_installed/` directory is added to `.gitignore`.
- **Security / Supply-Chain Considerations:** Pinned `builtin-baseline` Git SHA locks upstream package commits, preventing unvetted dependency updates or supply-chain drift.
- **Validation:** Running `cmake --preset dev-debug` initializes vcpkg in manifest mode and generates build files reproducibly.
- **Acceptance Criteria:**
  - `vcpkg.json` exists at workspace root with pinned baseline SHA.
  - `vcpkg_installed/` is listed in `.gitignore`.
  - `cmake --preset dev-debug` runs vcpkg manifest resolution reproducibly on macOS, Linux, and Windows.

---

### SC002-T02 — Establish CMake dependency discovery

- **Objective:** Create `cmake/modules/SecureCloudDependencies.cmake` providing a modern, target-based CMake discovery pattern (`find_package`) for external dependencies without hardcoded machine paths or global include/link pollution.
- **Exact Files Affected:**
  - `cmake/modules/SecureCloudDependencies.cmake`
  - `CMakeLists.txt`
- **Dependencies:** SC002-T01
- **Implementation Approach:**
  - Write `SecureCloudDependencies.cmake` using target-based `find_package(...)` calls.
  - Provide clear, descriptive `FATAL_ERROR` diagnostic messages if a required package or target is missing.
  - Avoid global `include_directories()`, global `link_libraries()`, or artificial interface wrapper targets.
  - Include `SecureCloudDependencies` in top-level `CMakeLists.txt`.
- **Security / Supply-Chain Considerations:** Verifies imported target presence before linking; prevents silent fallbacks to unverified system libraries.
- **Validation:** `cmake --preset dev-debug` includes `SecureCloudDependencies.cmake` and completes target discovery cleanly.
- **Acceptance Criteria:**
  - `SecureCloudDependencies.cmake` is loaded by root `CMakeLists.txt`.
  - Target-based discovery is enforced without global scope pollution.
  - Informative diagnostic errors are emitted if dependency discovery fails.

---

### SC002-T03 — Dependency smoke validation

- **Objective:** Implement a minimal dependency discovery and compilation smoke test target (`securecloud_dependency_smoke_test`) verifying that the dependency manager and CMake discovery pipeline configure, compile, link, and run a minimal baseline program under CTest.
- **Exact Files Affected:**
  - `tests/unit/CMakeLists.txt`
  - `tests/unit/dependency_smoke_test.cpp`
- **Dependencies:** SC002-T01, SC002-T02
- **Implementation Approach:**
  - Create `tests/unit/dependency_smoke_test.cpp` containing a minimal C++20 entry point validating header inclusion and basic symbol availability.
  - Target-link to compiler flags and discovery targets in `tests/unit/CMakeLists.txt`.
  - Register `dependency_smoke_test` with CTest via `add_test()`.
  - Do NOT implement logger wrappers, JSON utilities, crypto SHA-256 suites, DB drivers, gRPC/Proto, S3/MinIO, or business logic.
- **Security / Supply-Chain Considerations:** Confirms target ABI compatibility and linker flag validity on the host toolchain without executing untrusted code.
- **Validation:** `cmake --build --preset dev-debug` compiles `securecloud_dependency_smoke_test` and `ctest --preset dev-debug` passes with return code 0.
- **Acceptance Criteria:**
  - `securecloud_dependency_smoke_test` target builds without warnings under `-Werror`.
  - `ctest --preset dev-debug` executes the smoke test and passes 100%.
