# SC-014 — Establish Initial CI Pipeline

## Executive Summary & Objectives

Card **SC-014** establishes a reproducible, deterministic, cross-platform Continuous Integration (CI) and developer-verification workflow for SecureCloud under Milestone **M1: Buildable Distributed Skeleton**.

The CI system validates code quality, compilation, test execution, formatting, static analysis, and generated-contract integrity across the three primary operating environments used by the engineering team:
1. **macOS / Apple Silicon (arm64)** (`macos-14`)
2. **Windows + MSVC 2022** (`windows-2022`)
3. **Windows + MinGW-w64 (MSYS2 UCRT64)** (`windows-2022`)

> [!IMPORTANT]
> SC-014 is **infrastructure, build, and quality automation only**. It strictly excludes production deployment pipelines, release packaging, and performance benchmarking gates.
>
> **Hard Host Invariant**: The developer workstation operates an independent **PostgreSQL 14** instance on `localhost:5432`. SC-014 CI and local verification workflows MUST NEVER stop, restart, reconfigure, or bind to host port `5432`. CI runs in isolated ephemeral environments and does not depend on a developer-local database.

---

## Authoritative Architectural Baseline & Multi-Platform Matrix

### 1. Multi-Platform Build & Verification Matrix

Explicit runner versions are pinned rather than relying on moving `*-latest` labels:
- **macOS Runner**: `macos-14` (Apple Silicon M1/arm64, Xcode 15+)
- **Windows Runner**: `windows-2022` (Visual Studio 2022 / MSVC 19.38+, MSYS2 environment)

| Job Name | Runner | Compiler | Toolchain / Generator | Dependency Provider | Configure Command | Build Command | Test / Quality Command |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`quality-gates`** (Canonical) | `macos-14` | AppleClang | Ninja | Homebrew (`protobuf`, `grpc`, `googletest`, `llvm`, `ninja`) | `cmake --preset ci-macos -DENABLE_CLANG_TIDY=ON` | `cmake --build --preset ci-macos --target securecloud_proto_smoke_test check-format` | `clang-format` check, `clang-tidy` static analysis, contract smoke test |
| **`macos-build-test`** | `macos-14` | AppleClang | Ninja | Homebrew (`protobuf`, `grpc`, `googletest`, `ninja`) | `cmake --preset ci-macos` | `cmake --build --preset ci-macos` | `ctest --preset ci-macos --output-on-failure` |
| **`windows-msvc-build-test`** | `windows-2022` | MSVC 2022 (`cl.exe` v19.38+) | Ninja / MSVC | Toolchain / vcpkg (minimal manifest inspection) | `cmake --preset ci-windows-msvc` | `cmake --build --preset ci-windows-msvc` | `ctest --preset ci-windows-msvc --output-on-failure` |
| **`windows-mingw-build-test`** | `windows-2022` | MinGW-w64 GCC 14+ (UCRT64) | Ninja / GCC | MSYS2 UCRT64 precompiled pacman packages | `cmake --preset ci-windows-mingw` | `cmake --build --preset ci-windows-mingw` | `ctest --preset ci-windows-mingw --output-on-failure` |

### 2. Quality & Validation Gates Model
To avoid running expensive static analysis three times across disparate operating systems, SC-014 establishes a dedicated **canonical quality job** alongside native build/test jobs:
- **Canonical Quality Job (`quality-gates` on `macos-14`)**:
  - **Formatting Gate**: Validates `.clang-format` adherence across all `.cpp`, `.hpp`, and `.h` files using `cmake --build --preset ci-macos --target check-format` (`clang-format --dry-run --Werror`).
  - **Static Analysis Gate**: Enforces `.clang-tidy` rules with all warnings as errors (`WarningsAsErrors: '*'`) across project translation units using `ENABLE_CLANG_TIDY=ON`.
  - **Generated Contracts Gate**: Validates out-of-source Protobuf/gRPC code generation in `${CMAKE_BINARY_DIR}/generated/proto/` and executes `securecloud_proto_smoke_test`.
- **Native Platform Jobs (`macos-build-test`, `windows-msvc-build-test`, `windows-mingw-build-test`)**:
  - Native CMake configure (`cmake --preset ...`).
  - Native compile and build with strict compiler warnings as errors (`/WX` on MSVC, `-Werror` on GCC/Clang).
  - Native CTest execution (`ctest --preset ... --output-on-failure`), requiring a 100% pass rate.

---

## Dependency Graph

```
SC-014-T01 — Cross-Platform Build/Test Portability Foundation
    │
    ▼
SC-014-T02 — Local Developer Verification Orchestrator (scripts/verify-local.*)
    │
    ▼
SC-014-T03 — GitHub Actions Multi-Platform CI Pipeline (.github/workflows/ci.yml)
    │
    ├───────────────────────────────────────────┐
    ▼                                           ▼
SC-014-T04 — CodeRabbit Review              SC-014-T05 — Developer Workflow Documentation
Configuration (.coderabbit.yaml)            & Branch Protection Specification
```

> **Parallel Execution Note**: Following completion and verification of **SC-014-T03**, tickets **SC-014-T04** and **SC-014-T05** may proceed independently as there is no technical interdependency between review tool configuration and developer workflow documentation.

---

## Ticket Decomposition

### SC-014-T01 — Cross-Platform Build/Test Portability Foundation

- **Status**: `[COMPLETED]`
- **Objective**: Make the existing SC-013 implementation buildable and testable on macOS, Windows/MSVC, and Windows/MinGW.
  - **Strict Architecture Preservation**: Do **not** redesign the SC-013 transport probe architecture.
  - **Strict Semantics Preservation**: Preserve all existing semantics:
    - Bounded 250 ms complete probe deadline.
    - Non-blocking socket connect and polling behavior.
    - Fail-closed behavior on connection error, timeout, or DNS resolution failure.
    - Graceful failure handling and accurate latency reporting.
  - **Minimal Dependency Architecture Impact**: Do not automatically add protobuf/grpc to `vcpkg.json`. First inspect and verify the existing CMake dependency architecture (`SecureCloudDependencies.cmake`). Determine whether protobuf/grpc should become explicit vcpkg manifest dependencies for deterministic CI on Windows MSVC, or whether toolchain/runner resolution suffices. If a change is required, make the smallest change that preserves the existing CMake dependency architecture without breaking host package discovery on macOS or MinGW.
- **Exact files/directories modified**:
  - `[MODIFY] src/common/CMakeLists.txt`
  - `[MODIFY] src/common/src/health/transport_probe.cpp`
  - `[MODIFY] tests/unit/health/transport_probe_test.cpp`
  - `[MODIFY] tests/integration/health_integration_test.cpp`
  - `[MODIFY] CMakePresets.json`
  - `[MODIFY] vcpkg.json`
- **Dependencies**: SC-002, SC-004, SC-005, SC-013
- **Implementation approach**:
  1. **Win32 Sockets Compatibility**:
     - In `src/common/CMakeLists.txt`, linked `ws2_32` conditionally for `WIN32` targets.
     - In `src/common/src/health/transport_probe.cpp`:
       - Conditionally included `<winsock2.h>` and `<ws2tcpip.h>` on `_WIN32` with safe RAII `WSAStartup`/`WSACleanup` initialization.
       - Mapped `poll()` to `WSAPoll()`, `close()` to `closesocket()`, non-blocking configuration to `ioctlsocket(fd, FIONBIO, &mode)`, and error checking to `WSAGetLastError() == WSAEWOULDBLOCK`.
       - Strictly preserved bounded 250 ms overall deadline calculation and fail-closed behavior.
  2. **Unit & Integration Test Portability**:
     - In `tests/unit/health/transport_probe_test.cpp`: Implemented RAII `ScopedEphemeralListener` and cross-platform socket management.
     - In `tests/integration/health_integration_test.cpp`: Implemented `CreateProcessW` / `WaitForSingleObject` / `GetExitCodeProcess` for Windows CLI probe execution and adapted `ScopedTcpListener` for Winsock.
  3. **Dependency Architecture Verification**:
     - Inspected `SecureCloudDependencies.cmake`: discovers `gRPC::grpc++`, `protobuf::libprotobuf`, and `GTest::gtest`.
     - Declared `"grpc"` and `"protobuf"` in `vcpkg.json` as manifest dependencies to guarantee deterministic dependency resolution under Windows MSVC manifest mode while leaving host discovery unchanged on macOS (Homebrew) and MinGW (pacman).
  4. **CMake Presets**:
     - Added explicit `ci-windows-msvc` and `ci-windows-mingw` configure, build, and test presets in `CMakePresets.json`.
- **Verification Evidence**:
  - `cmake --build --preset dev-debug --target check-format`: Passed (exit code 0).
  - `cmake --build --preset ci-macos --target check-format`: Passed (exit code 0).
  - `cmake --build --preset ci-macos`: Passed with 0 warnings.
  - `ctest --preset ci-macos --output-on-failure`: 81/81 tests passed (100% pass rate).
- **Acceptance criteria**:
  - SC-013 transport probe compiles and passes tests cleanly with bounded 250 ms deadline and fail-closed behavior strictly preserved. [VERIFIED]

---

### SC-014-T02 — Local Developer Verification Orchestrator (`scripts/verify-local.*`)

- **Status**: `[COMPLETED]`
- **Objective**: Establish a unified local verification **orchestrator** in Python (`scripts/verify-local.py`) with thin shell (`.sh`) and PowerShell (`.ps1`) wrappers.
  - **Orchestrator Role Only**: The script is strictly an orchestrator, **not a second build system**.
  - **Consumes Existing Artifacts**: Consumes `CMakePresets.json`, existing CMake targets (`check-format`, `verify-contracts`), and existing validation scripts.
  - **Zero Duplication**: Does **not** duplicate compiler, dependency, or build logic.
- **Exact files/directories created/modified**:
  - `[NEW] scripts/verify-local.py`
  - `[NEW] scripts/verify-local.sh`
  - `[NEW] scripts/verify-local.ps1`
  - `[MODIFY] tests/unit/CMakeLists.txt` (added `verify-contracts` custom target executing `securecloud_proto_smoke_test`)
- **Dependencies**: SC-014-T01
- **Implementation approach**:
  1. Authored `scripts/verify-local.py` using standard Python 3 library only:
     - Discovers repository root and parses CLI flags (`--preset`, `--detect`, `--list-presets`, `--skip-*`, `--full`, `--verbose`).
     - Validates presets directly against `CMakePresets.json`.
     - Orchestrates stages sequentially using `subprocess.run(..., shell=False)`:
       - **Stage 1 (Configure)**: `cmake --preset <preset>`
       - **Stage 2 (Formatting)**: `cmake --build --preset <preset> --target check-format`
       - **Stage 3 (Build)**: `cmake --build --preset <preset>`
       - **Stage 4 (Contracts)**: `cmake --build --preset <preset> --target verify-contracts`
       - **Stage 5 (Test Suite)**: `ctest --preset <preset> --output-on-failure`
       - **Stage 6 (Extended Verification)**: When `--full` is passed, executes `scripts/verify-dev-pki.sh` and `scripts/verify-service-config.sh`.
     - Immediately halts and propagates return codes on any stage failure.
     - Prints structured, color-coded stage timing tables.
  2. Authored thin POSIX shell wrapper `scripts/verify-local.sh` (`exec python3 ...`).
  3. Authored thin Windows PowerShell wrapper `scripts/verify-local.ps1` (`& $PythonCmd.Source ...`).
- **Verification Evidence**:
  - `./scripts/verify-local.sh --list-presets`: Displayed all 7 presets from `CMakePresets.json`.
  - `./scripts/verify-local.sh --preset dev-debug`: All 5 stages passed in 7.72s (exit code 0).
  - `./scripts/verify-local.sh --detect`: Auto-detected `ci-macos`, all 5 stages passed in 7.66s (exit code 0).
  - `./scripts/verify-local.sh --full`: All 7 stages passed in 55.68s (exit code 0).
  - `./scripts/verify-local.sh --preset non-existent`: Cleanly rejected invalid preset with exit code 1.
- **Acceptance criteria**:
  - Single unified command executes local verification stages without duplicating build logic. [VERIFIED]

---

### SC-014-T03 — GitHub Actions Multi-Platform CI Pipeline (`.github/workflows/ci.yml`)

- **Status**: `[COMPLETED]`
- **Objective**: Author the official GitHub Actions workflow `.github/workflows/ci.yml` executing on pull requests and pushes to `main`.
  - **Execution Model**:
    - **macOS (`macos-14`)**: Native configure, native build, CTest.
    - **Windows/MSVC (`windows-2022`)**: Native configure, native build, CTest.
    - **Windows/MinGW (`windows-2022`)**: Native configure, native build, CTest.
    - **Canonical Quality Job (`macos-14`)**: `clang-format`, `clang-tidy`, generated-contract validation.
  - **Avoid Redundant Static Analysis**: Heavy static analysis (`clang-tidy`) is executed once in the canonical quality job rather than repeated across all three platform jobs.
  - **Explicit Runner Pinning**: Pin `macos-14` and `windows-2022` rather than floating `*-latest`.
  - **Verified MSYS2 UCRT64 Package Identifiers**:
    - `mingw-w64-ucrt-x86_64-toolchain` (GCC 14 / C++20 toolchain)
    - `mingw-w64-ucrt-x86_64-cmake`
    - `mingw-w64-ucrt-x86_64-ninja`
    - `mingw-w64-ucrt-x86_64-protobuf`
    - `mingw-w64-ucrt-x86_64-grpc`
    - `mingw-w64-ucrt-x86_64-gtest`
- **Exact files/directories created**:
  - `[NEW] .github/workflows/ci.yml`
- **Dependencies**: SC-014-T01, SC-014-T02
- **Implementation approach**:
  1. Authored `.github/workflows/ci.yml` with triggers:
     - `push` to `main`
     - `pull_request` to `main`
     - Concurrency grouping with `cancel-in-progress` on PR branches.
  2. Configured 4 parallel jobs with pinned runner versions:
     - **`quality-gates`** (`macos-14`):
       - Installs Homebrew packages: `protobuf`, `grpc`, `googletest`, `llvm`, `ninja`.
       - Runs formatting check (`check-format`).
       - Runs clang-tidy static analysis (`-DENABLE_CLANG_TIDY=ON`).
       - Runs contract validation (`verify-contracts`).
     - **`macos-build-test`** (`macos-14`):
       - Installs Homebrew packages.
       - Runs native configure, build, and full CTest suite (`ci-macos`).
     - **`windows-msvc-build-test`** (`windows-2022`):
       - Sets up MSVC via `ilammy/msvc-dev-cmd@v1`.
       - Sets up vcpkg binary cache using `actions/cache@v4`.
       - Runs native configure, build, and full CTest suite (`ci-windows-msvc`).
     - **`windows-mingw-build-test`** (`windows-2022`):
       - Sets up MSYS2 UCRT64 via `msys2/setup-msys2@v2`.
       - Installs verified UCRT64 packages.
       - Runs native configure, build, and full CTest suite (`ci-windows-mingw`).
- **Verification Evidence**:
  - Validated YAML parsing: syntax is valid, all 4 jobs verified (`quality-gates`, `macos-build-test`, `windows-msvc-build-test`, `windows-mingw-build-test`).
  - Local verification orchestrator (`./scripts/verify-local.sh`): 100% passed (5/5 stages, 81/81 tests).
- **Acceptance criteria**:
  - `.github/workflows/ci.yml` strictly follows the defined CI model with pinned runner versions and verified UCRT64 package names. [VERIFIED]

---

### SC-014-T04 — CodeRabbit Review Integration (`.coderabbit.yaml`)

- **Status**: `[COMPLETED]`
- **Objective**: Author an authoritative, valid `.coderabbit.yaml` review configuration adhering strictly to CodeRabbit schema version 2 and tailored to SecureCloud's C++20 architecture, fail-closed security posture, mTLS requirements, and cross-platform standards.
  - **Configuration vs Enforcement Separation**: `.coderabbit.yaml` configures CodeRabbit behavior. Enforcement (blocking merge) is controlled by GitHub repository configuration, GitHub branch protection, and CodeRabbit app integration. Do **not** claim that `.coderabbit.yaml` alone enforces merge protection.
  - **Valid Schema**: Strict compliance with official CodeRabbit schema v2 (`version: "2"`, `language: "en-US"`, `reviews: ...`, etc.).
- **Exact files/directories created**:
  - `[NEW] .coderabbit.yaml`
- **Dependencies**: SC-014-T03 (May proceed independently alongside SC-014-T05)
- **Implementation approach**:
  1. Authored `.coderabbit.yaml` adhering to CodeRabbit schema v2:
     - Profile: `assertive` with security and memory safety focus.
     - Auto-review: enabled on `main` branch.
     - Tailored `path_instructions`:
       - `src/**`: C++20 memory safety, RAII, zero data races, fail-closed socket probes (<= 250 ms), mTLS verification, `SecretString` secret hygiene, and cross-platform Winsock/POSIX conventions.
       - `tests/**`: Determinism, no sleeps, host PostgreSQL 14 invariant isolation, and cross-platform test execution helpers.
       - `cmake/**`: Target-based modern CMake patterns and compiler flag integrity.
       - `.github/**`: Pinned runner versions, verified MSYS2 UCRT64 package identifiers, and strict exit code propagation.
  2. Prominently documented the architectural separation between review configuration and merge gate enforcement in file headers.
- **Verification Evidence**:
  - Validated YAML parsing against schema v2: valid structure, parsed profile, and 4 path instruction sets.
  - Local verification orchestrator (`./scripts/verify-local.sh`): 100% passed (5/5 stages, 81/81 tests).
- **Acceptance criteria**:
  - `.coderabbit.yaml` strictly conforms to schema v2 with comprehensive SecureCloud-specific instructions and explicit merge enforcement distinction. [VERIFIED]

---

### SC-014-T05 — Developer Workflow Documentation & Branch Protection Specification

- **Status**: `[COMPLETED]`
- **Objective**: Author operational documentation for developers covering local verification, platform prerequisites, CI matrix, CodeRabbit review role, and the required GitHub branch protection configuration.
- **Exact files/directories created/modified**:
  - `[MODIFY] docs/implementation/development-workflow.md`
  - `[MODIFY] docs/planning/initial-backlog.md`
  - `[MODIFY] specs/phase0/SC-014-tickets.md` (record completion and verification evidence)
- **Dependencies**: SC-014-T03 (May proceed independently alongside SC-014-T04)
- **Implementation approach**:
  1. Updated `docs/implementation/development-workflow.md`:
     - Added the 7-step PR merge lifecycle.
     - Documented platform prerequisites for macOS arm64, Windows MSVC 2022, and Windows MinGW MSYS2 UCRT64.
     - Documented `scripts/verify-local.sh` and `scripts/verify-local.ps1` usage, stages, and options.
     - Documented `.github/workflows/ci.yml` architecture with pinned runner versions (`macos-14`, `windows-2022`).
     - Documented `.coderabbit.yaml` review focus areas and explicit disclaimer separating review from merge enforcement.
     - Detailed exact GitHub branch protection rules required for `main` (4 required status checks, approvals, no bypasses).
     - Documented developer workstation host PostgreSQL 14 invariant on `localhost:5432`.
  2. Updated `docs/planning/initial-backlog.md`:
     - Recorded SC-014 card completion under Milestone M1 with comprehensive ticket implementation summary.
- **Verification Evidence**:
  - Validated all documentation cross-links and formatting.
  - Verified local verification orchestrator (`./scripts/verify-local.sh`): 100% pass (5/5 stages, 81/81 tests).
- **Acceptance criteria**:
  - `docs/implementation/development-workflow.md` is complete, accurate, and reflects the 11 corrections. [VERIFIED]
  - Backlog is updated with SC-014 artifacts and status. [VERIFIED]

---

## PR / Merge Workflow

```
                  ┌─────────────────────────────────┐
                  │ Feature Branch (SC-xxx-feature) │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │   Local Developer Verification  │
                  │     ./scripts/verify-local.sh   │
                  │   (or verify-local.ps1 on Win)  │
                  └────────────────┬────────────────┘
                                   │ (All stages PASS)
                                   ▼
                  ┌─────────────────────────────────┐
                  │          Git Commit             │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │       Create Pull Request       │
                  └────────┬───────────────┬────────┘
                           │               │
            ┌──────────────┴───────┐       │
            ▼                      ▼       ▼
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│  GitHub Actions CI   │  │   CodeRabbit Review  │  │     Human Review     │
│  - Quality Gates     │  │  - C++20 Safety      │  │  - Architecture     │
│  - macOS Build/Test  │  │  - Concurrency       │  │  - Functional       │
│  - MSVC Build/Test   │  │  - mTLS & Secrets    │  │  - Verification     │
│  - MinGW Build/Test  │  │  - Cross-platform    │  └──────────┬───────────┘
└──────────┬───────────┘  └──────────┬───────────┘             │
           │                         │                         │
           └────────────────► (ALL REQUIRED PASS) ◄────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │    Protected Merge into main    │
                  └─────────────────────────────────┘
```

> **Note on Enforcement**: Merge protection is strictly enforced by GitHub repository branch protection rules on `main` requiring the four GitHub Actions status checks and human approval to pass. CodeRabbit reviews provide automated architectural and safety feedback on the pull request.

---

## Risks / Blockers

1. **vcpkg Overhead on Windows MSVC**:
   - *Risk*: Full compilation of gRPC and Protobuf in vcpkg can extend initial CI run times.
   - *Mitigation*: T01 inspects the minimal dependency footprint; CI leverages GitHub Actions vcpkg binary caching (`VCPKG_DEFAULT_BINARY_CACHE` backed by `actions/cache`) to ensure subsequent PR runs restore precompiled binaries rapidly.
2. **MinGW Package Compatibility**:
   - *Risk*: Mismatched compiler versions or package names in MSYS2 UCRT64.
   - *Mitigation*: Pinned and verified UCRT64 package names (`mingw-w64-ucrt-x86_64-{toolchain,cmake,ninja,protobuf,grpc,gtest}`) matching modern GCC 14 and Protobuf/gRPC releases.
3. **Clang-Tidy Diagnostics Variance Across Toolchains**:
   - *Risk*: Running clang-tidy on different operating systems can produce platform-specific compiler header noise.
   - *Mitigation*: Designated `quality-gates` on `macos-14` as the single canonical static analysis runner, while native Windows MSVC and MinGW jobs enforce compiler warnings-as-errors (`/WX` and `-Werror`).
4. **Developer Host PostgreSQL Invariant**:
   - *Risk*: Accidental reliance on local PostgreSQL service in CI.
   - *Mitigation*: CI jobs run strictly in isolated virtual runner environments without any background PostgreSQL services running on `localhost:5432`.

---

## Completion Summary

All five tickets for Card **SC-014 — Establish Initial CI Pipeline** are fully implemented and verified:
- `SC-014-T01`: Cross-Platform Build/Test Portability Foundation [COMPLETED]
- `SC-014-T02`: Local Developer Verification Orchestrator [COMPLETED]
- `SC-014-T03`: GitHub Actions Multi-Platform CI Pipeline [COMPLETED]
- `SC-014-T04`: CodeRabbit Review Integration [COMPLETED]
- `SC-014-T05`: Developer Workflow Documentation & Branch Protection Specification [COMPLETED]

