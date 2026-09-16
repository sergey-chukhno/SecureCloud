# SC-004 Implementation Tickets — Configure clang-format + clang-tidy (Final Specification)

**Card ID:** SC-004  
**Title:** Configure clang-format + clang-tidy  
**Milestone:** M1 — Buildable Distributed Skeleton  
**Owner:** Sergey  
**Status:** Approved Specification Baseline


### SC004-T01 — Establish `.clang-format` Configuration & Rules

- **Objective:** Populate root `.clang-format` with modern C++20 formatting rules (`IndentWidth: 4`, `ColumnLimit: 120`, `Standard: c++20`, `IncludeBlocks: Regroup`, `PointerAlignment: Left`, `DerivePointerAlignment: false`), establishing baseline formatting rules for project-owned C++ files.
- **Exact Files Affected:**
  - `.clang-format`
- **Dependencies:** None
- **Implementation Approach:**
  - Base configuration on `Language: Cpp`, `BasedOnStyle: LLVM`.
  - Set `IndentWidth: 4`, `ColumnLimit: 120`, `Standard: c++20`, `PointerAlignment: Left`, `DerivePointerAlignment: false`, `IncludeBlocks: Regroup`.
  - Exclusions of non-project directories (`build/`, `vcpkg_installed/`, generated code) are managed by the CMake file selection mechanism in T03.
- **Relevant Project Rules:** `docs/implementation/coding-rules.md` Section 3 (Modern C++ style consistency).
- **Security Considerations:** None.
- **Tests & Validation:** `clang-format --dry-run --Werror` runs on project files, parses rules cleanly, and confirms zero syntax errors.
- **Acceptance Criteria:**
  - `.clang-format` exists at workspace root, sets `DerivePointerAlignment: false`, and parses without errors.
  - Formatting rules distinguish project C++ files from third-party/generated code when invoked via CMake.

---

### SC004-T02 — Establish `.clang-tidy` Static Analysis Configuration

- **Objective:** Populate root `.clang-tidy` with deliberate C++20 static analysis checks, setting `HeaderFilterRegex: ".*/(src|tests)/.*\\.(hpp|h)$"` based on actual workspace layout to analyze all project headers while excluding third-party and system headers.
- **Exact Files Affected:**
  - `.clang-tidy`
- **Dependencies:** SC004-T01
- **Implementation Approach:**
  - Apply the approved check inventory (`bugprone-*`, `performance-*`, `portability-*`, `readability-*`, `modernize-*`, `concurrency-*`, `clang-analyzer-*`).
  - Disable explicit high-noise checks (`-modernize-use-trailing-return-type`, `-readability-implicit-bool-conversion`, `-readability-identifier-length`, `-bugprone-easily-swappable-parameters`).
  - Set `HeaderFilterRegex: ".*/(src|tests)/.*\\.(hpp|h)$"` to capture project headers across all subdirectories (including `src/common/include/securecloud/common/`).
  - Set `WarningsAsErrors: "*"` for configured checks.
  - Verify and log host `clang-tidy` binary version.
- **Relevant Project Rules:** `docs/implementation/coding-rules.md` Section 2 & 3 (Security, correctness, modern C++ safety).
- **Security Considerations:** Enables static security rules detecting memory corruption, bounds errors, and thread-safety bugs.
- **Tests & Validation:** Run `clang-tidy` against project targets to verify configuration parsing and header filtering.
- **Acceptance Criteria:**
  - `.clang-tidy` exists at workspace root and configures approved check inventory.
  - `HeaderFilterRegex` captures all project-owned headers while ignoring third-party/system headers.

---

### SC004-T03 — Integrate Formatting & Static Analysis into CMake

- **Objective:** Create `cmake/modules/SecureCloudFormatting.cmake` establishing read-only `check-format` target, modifying `format` target, and optional `ENABLE_CLANG_TIDY` compiler integration using `find_program()`.
- **Exact Files Affected:**
  - `cmake/modules/SecureCloudFormatting.cmake`
  - `CMakeLists.txt`
- **Dependencies:** SC004-T01, SC004-T02
- **Implementation Approach:**
  - Use `find_program(CLANG_FORMAT_BIN clang-format)` and `find_program(CLANG_TIDY_BIN clang-tidy)`.
  - Define authoritative CMake tooling source file selection mechanism excluding `build/`, `vcpkg_installed/`, and generated code.
  - Define `check-format` target: read-only, executes `clang-format --dry-run --Werror`, returns non-zero exit code on formatting mismatch.
  - Define `format` target: convenience target executing `clang-format -i` in-place.
  - Define `option(ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" OFF)`. When `ON`, set `CMAKE_CXX_CLANG_TIDY`.
  - Include module in top-level `CMakeLists.txt`.
- **Relevant Project Rules:** `docs/implementation/repository-structure.md` (Clean CMake modular architecture, no hardcoded machine paths).
- **Security Considerations:** Production binaries do not depend on formatters/linters at runtime; non-zero exit code enables strict CI quality gates.
- **Tests & Validation:** `cmake --preset dev-debug` configures `check-format` and `format` targets; `check-format` returns non-zero when formatting violates rules.
- **Acceptance Criteria:**
  - `check-format` is strictly read-only and returns non-zero on unformatted code.
  - `format` modifies project files in-place.
  - `ENABLE_CLANG_TIDY` integrates cleanly without hardcoded machine paths.

---

### SC004-T04 — Format Baseline Codebase & Verify Tooling Pipeline

- **Objective:** Format baseline project source files, verify `check-format` and `clang-tidy` pass cleanly, classify baseline findings, and create thin developer helper `scripts/check-formatting.sh`.
- **Exact Files Affected:**
  - `src/` files
  - `tests/` files
  - `scripts/check-formatting.sh`
- **Dependencies:** SC004-T01, SC004-T02, SC004-T03
- **Implementation Approach:**
  - Execute `cmake --build --preset dev-debug --target format` on baseline project files.
  - Verify `cmake --build --preset dev-debug --target check-format` passes with exit code 0.
  - Run `cmake --preset dev-debug -DENABLE_CLANG_TIDY=ON && cmake --build --preset dev-debug` to evaluate static analysis.
  - Classify findings according to approved protocol (zero unexplained findings; resolve baseline issues cleanly).
  - Create thin convenience wrapper `scripts/check-formatting.sh` executing `cmake --build --preset dev-debug --target check-format`.
- **Relevant Project Rules:** `docs/implementation/development-workflow.md` (Developer pre-PR verification).
- **Security Considerations:** Ensures baseline codebase is free of unexplained static analysis warnings before feature development.
- **Tests & Validation:** `check-format` passes 100%, `ENABLE_CLANG_TIDY=ON` build succeeds, and `ctest --preset dev-debug` passes.
- **Acceptance Criteria:**
  - All project C++ source/header files pass `check-format`.
  - No unexplained `clang-tidy` findings remain after applying approved baseline policy.
  - `scripts/check-formatting.sh` executes successfully.

---

## 5. Dependency Graph

```
  SC004-T01 (.clang-format)
       │
       ▼
  SC004-T02 (.clang-tidy)
       │
       ▼
  SC004-T03 (CMake Integration)
       │
       ▼
  SC004-T04 (Validation & Script)
```
