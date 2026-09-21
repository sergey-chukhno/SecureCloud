# SecureCloud — Development Workflow

**Status:** Implementation baseline
**Scope:** Team workflow, branches, pull requests, reviews, integration, and change management

---

## 1. Purpose

This document defines how the SecureCloud team turns approved design into integrated code.

It covers:

* work assignment
* branches
* commits
* pull requests
* reviews
* CI
* integration
* design changes
* completion criteria

It does not redefine architecture or implementation rules.

---

# 2. Team Ownership

Initial ownership:

| Developer   | Primary ownership                                                                                    |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| Sergey      | Gateway, Messaging, ScyllaDB, distributed integration, resilience, performance, security integration |
| Developer 2 | Auth, PostgreSQL, MFA, sessions/tokens, devices, crypto directory                                    |
| Developer 3 | Files, PostgreSQL metadata, MinIO, transfers, file-access capabilities                               |

Shared responsibilities:

* API/Protobuf contracts
* architecture reviews
* security review
* integration testing
* E2E testing
* CI
* final MVP validation

Ownership means **primary implementation responsibility**, not exclusive knowledge.

---

# 3. Trello → Branch → PR

Every implementation task starts from a Trello card.

Recommended branch format:

```text id="xq3m1p"
feature/<short-name>
fix/<short-name>
security/<short-name>
test/<short-name>
refactor/<short-name>
```

Examples:

```text id="1y7k9z"
feature/auth-refresh-rotation
feature/messaging-idempotency
feature/file-resumable-upload
security/device-revocation
test/messaging-delivery-recovery
```

One branch should represent **one coherent engineering outcome**.

Do not create branches containing several unrelated features.

---

# 4. Before Starting Implementation

A developer may start implementation when:

* the relevant design decision exists
* required API/Protobuf contract is defined
* data model is sufficiently defined
* dependencies are known
* acceptance criteria are clear
* required tests are identifiable

If a required decision is missing, **stop and raise the issue** rather than inventing architecture locally.

---

# 5. Commit Rules

Commits should be:

* small enough to review
* logically coherent
* buildable when practical
* free of unrelated changes

Recommended format:

```text
<type>: <short description>
```

Examples:

```text
feat: add refresh token rotation
fix: reject revoked device
test: cover duplicate message submission
security: enforce MFA for device registration
refactor: isolate delivery scheduler
```

Do not commit:

* generated build artifacts
* credentials
* private keys
* temporary debugging code
* unrelated formatting changes

---

# 6. Pull Requests

Every PR must contain:

### Description

* what changed
* why it changed
* Trello card
* affected services/components
* relevant design/API documents

### Validation

State:

* tests executed
* sanitizer used, if applicable
* integration tests used
* known limitations

### Security impact

Explicitly state:

```text
Security impact: none
```

or describe the security-relevant change.

### Database/API changes

Clearly identify:

* schema changes
* migration requirements
* OpenAPI changes
* Protobuf changes
* compatibility impact

---

# 7. PR Size

Prefer:

```text
one feature
→ several focused commits
→ one reviewable PR
```

Avoid very large PRs combining:

```text
database + API + unrelated refactoring + UI + deployment
```

If a feature is genuinely large, split it into independently reviewable PRs while keeping the system buildable.

---

# 8. Required Review

At least **one other developer** reviews every PR.

Security-sensitive changes require review by another developer with particular attention to:

* authentication
* authorization
* device lifecycle
* cryptographic integration
* secret handling
* sensitive logging
* persistence/durability
* trust-boundary changes

The author remains responsible for correctness; the reviewer verifies assumptions and integration impact.

---

# 9. CI, CodeRabbit & Merge Gates

### 9.1 Merge Workflow Lifecycle

Every contribution strictly follows the 7-step merge lifecycle:

```text
feature branch
    ↓
local verification (./scripts/verify-local.sh)
    ↓
commit
    ↓
Pull Request
    ↓
GitHub Actions CI
    ↓
CodeRabbit Automated Review
    ↓
Human Review (1+ approval)
    ↓
Protected main
```

---

### 9.2 Developer Platform Prerequisites

The project natively supports three primary developer environments:

#### 1. macOS / Apple Silicon (`arm64`)
- macOS 14+ with Xcode 15+ Command Line Tools (`xcode-select --install`)
- Homebrew packages:
  ```bash
  brew install cmake ninja protobuf grpc googletest llvm
  ```
- Toolchain: AppleClang, Ninja, Homebrew LLVM (`clang-format`, `clang-tidy`).

#### 2. Windows 11 / Server 2022 with MSVC
- Visual Studio 2022 (Community, Professional, or Enterprise) with "Desktop development with C++".
- CMake 3.28+ and Ninja installed and available on `PATH`.
- vcpkg installation (`VCPKG_INSTALLATION_ROOT` environment variable configured).
- Toolchain: MSVC `cl.exe` (v19.38+), Ninja, vcpkg manifest mode.

#### 3. Windows with MinGW-w64 (MSYS2 UCRT64)
- MSYS2 installed with `UCRT64` environment:
  ```bash
  pacman -S --noconfirm --needed \
    mingw-w64-ucrt-x86_64-toolchain \
    mingw-w64-ucrt-x86_64-cmake \
    mingw-w64-ucrt-x86_64-ninja \
    mingw-w64-ucrt-x86_64-protobuf \
    mingw-w64-ucrt-x86_64-grpc \
    mingw-w64-ucrt-x86_64-gtest
  ```
- Toolchain: GCC 14+ (C++20 baseline), Ninja.

---

### 9.3 Local Developer Verification Orchestrator

Before committing changes, developers execute the unified local verification orchestrator:

- **POSIX (macOS / Linux / MSYS2)**:
  ```bash
  ./scripts/verify-local.sh
  ```
- **Windows (PowerShell)**:
  ```powershell
  .\scripts\verify-local.ps1
  ```

#### Orchestrator Architectural Role
`scripts/verify-local.py` is strictly an **orchestrator**, not a secondary build system. It discovers and validates targets directly from `CMakePresets.json` and invokes CMake and CTest targets:

1. **Stage 1 (Configure)**: `cmake --preset <preset>`
2. **Stage 2 (Formatting)**: `cmake --build --preset <preset> --target check-format`
3. **Stage 3 (Native Build)**: `cmake --build --preset <preset>`
4. **Stage 4 (Contracts Validation)**: `cmake --build --preset <preset> --target verify-contracts`
5. **Stage 5 (CTest Suite)**: `ctest --preset <preset> --output-on-failure`
6. **Stage 6 (Extended Verification)**: Executed when `--full` is passed (`verify-dev-pki.sh`, `verify-service-config.sh`).

#### Useful Flags
```bash
./scripts/verify-local.sh --help             # Display all options
./scripts/verify-local.sh --list-presets     # List presets from CMakePresets.json
./scripts/verify-local.sh --detect           # Auto-detect platform preset (e.g. ci-macos)
./scripts/verify-local.sh --full             # Run full suite including PKI & config scripts
./scripts/verify-local.sh --skip-format      # Skip formatting stage during rapid iteration
./scripts/verify-local.sh --tidy             # Enable clang-tidy static analysis
```

#### Formatting Remediation
If the formatting check fails in Stage 2, apply `.clang-format` rules in-place via:
```bash
cmake --build --preset <preset> --target format
```

---

### 9.4 Continuous Integration Architecture

The official CI pipeline is authored in `.github/workflows/ci.yml`. It uses explicitly pinned runner versions and a deduplicated quality gate structure:

| Job Name | Runner Version | Responsibilities |
| :--- | :--- | :--- |
| **`quality-gates`** | `macos-14` | Canonical quality gate: `.clang-format` check, `clang-tidy` static analysis (`WarningsAsErrors: '*'`), Protobuf/gRPC contract smoke test. Avoids running expensive static analysis three times. |
| **`macos-build-test`** | `macos-14` | Native AppleClang build (`ci-macos`) and 81/81 CTest suite execution. |
| **`windows-msvc-build-test`** | `windows-2022` | Native MSVC 2022 build (`ci-windows-msvc`) with vcpkg binary cache restore and CTest suite execution. |
| **`windows-mingw-build-test`** | `windows-2022` | Native MinGW GCC build (`ci-windows-mingw`) using precompiled MSYS2 UCRT64 packages and CTest suite execution. |

---

### 9.5 CodeRabbit Automated Review

- CodeRabbit is configured via `.coderabbit.yaml` (schema version 2).
- It provides automated architectural, security, and C++20 memory safety analysis on pull requests targeting `main`.
- **Review Scope**:
  - `src/**`: C++20 memory safety (RAII, zero raw owning pointers), concurrency/thread safety, fail-closed socket probes (<= 250 ms), mutual TLS client certificate verification, `SecretString` secret hygiene, and cross-platform Winsock/POSIX conventions.
  - `tests/**`: Determinism, no arbitrary sleeps, and strict developer host PostgreSQL isolation.
  - `cmake/**`: Modern target-based CMake idioms.
  - `.github/**`: Runner pinning and MSYS2 UCRT64 package integrity.
- **Architectural Disclaimer**: `.coderabbit.yaml` configures automated review commentary. Pull request merge protection is enforced separately by GitHub branch protection rules on `main`.

---

### 9.6 GitHub Branch Protection Specification for `main`

To ensure no broken or unreviewed code reaches production, the repository administrator must configure the following GitHub Branch Protection Rules for the `main` branch under **Repository Settings → Branches → Branch protection rules**:

1. **Branch Name Pattern**:
   ```text
   main
   ```

2. **Protect Matching Branches Settings**:
   - **Require a pull request before merging**:
     - Check: *Require approvals* (Minimum: **1 approval**).
     - Check: *Dismiss stale pull request approvals when new commits are pushed*.
     - Check: *Require review from Code Owners* (optional/recommended).
   - **Require status checks to pass before merging**:
     - Check: *Require branches to be up to date before merging*.
     - Search and select the exact 4 required status checks:
       1. `Quality Gates (Formatting, Clang-Tidy, Contracts)`
       2. `macOS (AppleClang / arm64)`
       3. `Windows (MSVC 2022 / vcpkg)`
       4. `Windows (MinGW-w64 UCRT64 / GCC 14+)`
   - **Do not allow bypassing the above settings**:
     - Check: Enforce rules for administrators.
   - **Restrict who can push to matching branches**:
     - Enable to prohibit direct `git push origin main`.

---

### 9.7 Developer Workstation Host Invariant

> [!CAUTION]
> **Hard Invariant**: The developer workstation operates an independent **PostgreSQL 14** instance on `localhost:5432`.
>
> CI workflows, unit test suites, integration tests, and local verification scripts (`verify-local.sh`) MUST NEVER stop, restart, reconfigure, or attempt to bind to host port `5432`. Ephemeral CI environments execute in isolated virtual machines, and local development testing uses designated non-conflicting ports.

---

# 10. Integration Order

When several services are developed in parallel:

```text
Contracts
   ↓
Service implementation
   ↓
Service integration tests
   ↓
Cross-service integration
   ↓
E2E validation
```

Prefer integrating changes in dependency order.

Example:

```text
Auth contract
    ↓
Auth implementation
    ↓
Gateway authentication integration
    ↓
Messaging authorization integration
    ↓
E2E authentication + messaging
```

---

# 11. Contract Changes

If implementation requires an API or Protobuf change:

1. Stop implementation at the affected boundary.
2. Explain why the existing contract is insufficient.
3. Update the contract.
4. Review compatibility impact.
5. Update affected tests.
6. Then continue implementation.

Do not silently modify contracts inside an unrelated PR.

---

# 12. Design Problems Discovered During Implementation

If code reveals a problem with the approved architecture/design:

### Do not

* silently redesign the service
* introduce a new database
* bypass another service
* create a hidden shared dependency
* weaken a security requirement
* change an invariant locally

### Do

1. Document the concrete problem.
2. Identify the affected decision/document.
3. Propose the smallest viable change.
4. Review it with the team.
5. Update the source-of-truth document.
6. Implement against the updated decision.

Existing ADRs are amended when an architectural decision genuinely changes.

---

# 13. Cross-Developer Dependencies

If Developer A requires work from Developer B:

```text
A identifies dependency
        ↓
dependency documented in Trello
        ↓
B implements contract/foundation
        ↓
B opens PR
        ↓
A integrates after review
```

Do not duplicate another developer's implementation simply to avoid waiting.

Temporary mocks/stubs are allowed when they do not change the real contract.

---

# 14. Merge Strategy

Use protected `main`.

Rules:

* no direct pushes to `main`
* PR required
* CI required
* review required
* branch must be up to date before merge where practical
* resolve merge conflicts before approval
* do not merge known broken code

After merge, the author is responsible for checking that the integrated system remains healthy.

---

# 15. Definition of Ready

A Trello card is **Ready** when:

* objective is clear
* owner is assigned
* relevant design reference exists
* dependencies are identified
* API/data changes are known or explicitly unnecessary
* acceptance criteria are defined
* tests can be identified

---

# 16. Definition of Done

A card is **Done** only when:

* implementation is complete
* relevant tests pass
* security requirements are satisfied
* API/contracts are updated if necessary
* documentation is updated if a decision/interface changed
* code has been reviewed
* CI passes
* changes are merged
* no known critical defect remains

"Code works locally" is not sufficient for Done.

---

# 17. Daily Development Rule

Developers should continuously keep the integration surface small.

When blocked by another component:

> **Expose the dependency early rather than implementing around it.**

When uncertain about architecture:

> **Ask before coding.**

When changing a decision:

> **Update the source of truth before relying on the new decision.**

When fixing a bug:

> **Add a regression test whenever practical.**

The goal is to keep three developers working in parallel without creating three incompatible versions of SecureCloud.
