# CLIENT-001 — Client Application Foundation
## Client Phase 1 (UI & Endpoint Foundation) Technical Specification & Implementation Tickets

**Card Identifier**: CLIENT-001  
**Milestone**: Client Phase 1 — Desktop Client Foundation & Core User Interface  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: November 3, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **CLIENT-001** establishes the reproducible, buildable, production-quality architectural foundation for the **SecureCloud Desktop Client** (`securecloud-client`) using **C++20**, **Qt 6 / Qt Quick (QML)**, and **CMake**.

As defined in **ADR-001** (§Runtime vs Client), **ADR-004** (§6 External Client Communication), **ADR-007**, **ADR-008**, and `docs/design/detailed-design.md` (§2 Client Architecture), the client is a **security-critical endpoint**, not a backend microservice:
- It is the sole trusted boundary where message/file plaintext is handled and where device private cryptographic keys reside.
- It must never allow UI code (QML/JavaScript) to directly access cryptographic keys, local SQLite databases, or raw network sockets.
- It must communicate with the SecureCloud backend exclusively through the **API Gateway** over HTTPS/REST and WebSockets (never directly connecting to internal services like Auth, Messaging, Files, or ClickHouse).

```text
┌─────────────────────────────────────────────────────────────┐
│                    SecureCloud Desktop Client               │
│                                                             │
│  UI (QML / Qt Quick)                                        │
│         │                                                   │
│         ▼                                                   │
│  Application (Managers / Use Cases / Navigation Router)     │
│         │                                                   │
│         ▼                                                   │
│  Domain (User, Device, Session, Message, Conversation)      │
│         │                                                   │
│         ▼                                                   │
│  Infrastructure (Gateway HTTP Client, SQLite, OS Keychain)  │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTPS / REST (Port 8443)
                               ▼
                        SecureCloud Gateway
```

---

## 2. Key Architectural Invariants & Non-Negotiable Boundaries

1. **Strict Four-Layer Separation (`detailed-design.md` §2.3)**:
   - **UI Layer (`src/client/ui/`)**: Presentation only (QML + C++ ViewModels). Strictly **zero** business logic, cryptographic operations, or database queries in QML.
   - **Application Layer (`src/client/application/`)**: Use cases and workflows encapsulated in **Managers** (`AuthManager`, `MessagingManager`, `ContactManager`, `DeviceManager`, `FileManager`, `EmergencyManager`, `SyncManager`). Coordinators only—not network microservices.
   - **Domain Layer (`src/client/domain/`)**: Pure C++20 business entities and rules (`User`, `Device`, `CryptoIdentity`, `Session`, `Contact`, `Conversation`, `Message`, `DeliveryState`). Pure domain logic that **never** depends on Qt Network, SQLite, OS APIs, or concrete cryptographic libraries.
   - **Infrastructure Layer (`src/client/infrastructure/`)**: Concrete adapters implementing application/domain interfaces (`IGatewayClient`, `ILocalStore`, `ISecureStorage`).
2. **Explicit Dependency Injection — Zero Global Mutable Singletons**:
   - All manager and adapter dependencies must be explicitly wired via constructors in an application bootstrap composition root (`ClientBootstrap` / `ClientContainer`).
   - Global mutable state, hidden service-locator lookups, and ad-hoc singletons are strictly forbidden.
3. **Single Network Path via Gateway (`ADR-004` §6)**:
   - The client communicates solely with the Gateway via HTTPS/REST. Direct network calls to internal microservices (Auth, Messaging, Files, Audit) or internal persistence nodes (Postgres, ScyllaDB, MinIO, ClickHouse) are strictly prohibited.
4. **Zero-Plaintext & Secret Isolation (`ADR-008` §14, §15)**:
   - Never log passwords, recovery codes, tokens, session keys, plaintext messages, or plaintext file data.
   - Strongly typed error handling (`ClientResult<T>`, `ClientError`) must sanitize all user-facing diagnostics.
5. **Cross-Platform Reproducible Build Baseline**:
   - Modern CMake targets adhering to repository compiler settings (`-Wall -Wextra -Werror -Wpedantic` on GCC/Clang, `/WX` on MSVC).
   - Qt 6 modular target linkage (`Qt6::Core`, `Qt6::Gui`, `Qt6::Qml`, `Qt6::Quick`, `Qt6::QuickControls2`, `Qt6::Network`).
   - Headless CI / test compatibility allowing domain, application, and infrastructure logic to be built and verified without requiring a live display server or GPU.

---

## 3. Dependency Graph

```text
                  SC-001 (CMake Project Baseline)
                  SC-004 (Clang-Format & Static Analysis)
                  SC-006 (Client Skeleton)
                  detailed-design.md (§2 Client Architecture)
                               │
                               ▼
                         CLIENT-001-T01
             (CMake Modularization, Qt 6 Integration &
              Compilation Target Topologies)
                               │
                               ▼
                         CLIENT-001-T02
             (Client Configuration Engine, Sanitized Logging
              & Type-Safe Error Framework)
                               │
                               ▼
                         CLIENT-001-T03
             (Four-Layer Architectural Skeletons, Canonical
              Domain Models & Core Interfaces)
                               │
                               ▼
                         CLIENT-001-T04
             (Explicit Composition Root, Application Lifecycle
              & Graceful Shutdown Engine)
                               │
                               ▼
                         CLIENT-001-T05
             (Navigation Controller, View Router State Machine
              & QML Presentation Shell)
                               │
                               ▼
                         CLIENT-001-T06
             (Unit Test Suite, Headless Verification Harness &
              Startup/Shutdown Lifecycle Smoke Tests)
```

---

## 4. Implementation Tickets for Developer Lorenzo

### CLIENT-001-T01 — CMake Modularization, Qt 6 Integration & Target Topologies

1. **Ticket ID**: `CLIENT-001-T01`
2. **Title**: Modular CMake Project Structure & Qt 6 Component Discovery
3. **Objective**: Refactor `src/client/CMakeLists.txt` into modern, decoupled static library targets (`securecloud_client_domain`, `securecloud_client_app`, `securecloud_client_infra`, `securecloud_client_ui`) and the executable `securecloud-client`. Integrate `Qt6` discovery (`Core`, `Gui`, `Qml`, `Quick`, `QuickControls2`, `Network`) with clean fallback for headless testing.
4. **Architectural Purpose**: Enforces physical build boundaries between UI, application, domain, and infrastructure layers, guaranteeing that domain models cannot accidentally link against Qt GUI or network libraries.
5. **Scope & Files to Change**:
   - `cmake/modules/SecureCloudDependencies.cmake`: Add discovery for `Qt6` components (`Core`, `Gui`, `Qml`, `Quick`, `QuickControls2`, `Network`) with clear diagnostic remediation messages.
   - `src/client/CMakeLists.txt`: Define target hierarchy:
     - `securecloud_client_domain`: Pure C++20, links only to `securecloud::compiler_flags`.
     - `securecloud_client_infra`: Implements adapters, links to `Qt6::Core`, `Qt6::Network`, `securecloud_client_domain`, `securecloud::common`.
     - `securecloud_client_app`: Application managers, links to `securecloud_client_domain`, `securecloud_client_infra`, `Qt6::Core`.
     - `securecloud_client_ui`: QML module via `qt_add_qml_module` or Qt Quick resources, ViewModels, links to `securecloud_client_app`, `Qt6::Quick`, `Qt6::QuickControls2`.
     - `securecloud-client`: Application executable entry point.
6. **Dependencies**: `SC-001`, `SC-004`, `detailed-design.md` §2.2.
7. **Implementation Approach**:
   - Use target-based CMake (`target_include_directories`, `target_link_libraries`).
   - Enable `AUTOMOC`, `AUTORCC`, `AUTOUIC` strictly on targets that require Qt meta-object compilation.
   - Maintain strict compiler warning flags (`-Wall -Wextra -Werror -Wpedantic`).
8. **Tests & Validation**:
   - `cmake --preset dev-debug`: Verify clean Qt 6 discovery without warnings.
   - `cmake --build build/dev-debug --target securecloud-client`: Verify successful build.
9. **Acceptance Criteria**:
   - Qt 6 components are discovered cleanly on macOS, Linux, and Windows.
   - Layer targets enforce clean dependency boundaries at the compiler/linker level.
   - Domain target compiles with zero Qt GUI/Network symbols.

---

### CLIENT-001-T02 — Client Configuration Engine, Sanitized Logging & Type-Safe Error Framework

1. **Ticket ID**: `CLIENT-001-T02`
2. **Title**: Client Configuration Model, Sanitized Logging & Type-Safe Error Framework
3. **Objective**: Implement strongly typed, validated client configuration (`ClientConfig`) and a robust, secret-safe error handling and logging architecture (`ClientResult<T>`, `ClientError`).
4. **Architectural Purpose**: Prevents accidental leakage of tokens, passwords, private keys, or plaintext messages into application logs, while ensuring runtime parameters (Gateway URL, timeouts, storage paths) are strictly validated on startup.
5. **Scope & Files to Change**:
   - `src/client/application/client_config.hpp` & `.cpp`:
     - Gateway connection settings (URL, port, TLS CA path, connection timeout).
     - Storage paths (local database directory, secure keychain identifier).
     - Session & sync settings (heartbeat interval, sync poll interval, retry bounds).
     - Validation logic with fail-safe defaults and secret redaction (`to_safe_string()`).
   - `src/client/application/client_error.hpp` & `.cpp`:
     - Strongly typed error categories: `Network`, `Authentication`, `Storage`, `Validation`, `Crypto`, `Internal`.
     - `ClientError` containing sanitized user-facing messages, debug codes, and correlation IDs.
     - `ClientResult<T>` (monadic / `std::expected`-style value-or-error wrapper).
   - `src/client/infrastructure/client_logger.hpp` & `.cpp`:
     - Structured logging bridge ensuring sensitive fields (tokens, keys, passwords) are automatically redacted.
6. **Dependencies**: `CLIENT-001-T01`, `detailed-design.md` §2.2.
7. **Implementation Approach**:
   - Utilize `securecloud::common::configuration::SecretString` for sensitive credentials.
   - Disallow unbounded string concatenation in log paths.
8. **Tests & Validation**:
   - `ClientConfigTest`: Verify environment overrides, default values, and port/URL range checks.
   - `ClientErrorTest`: Verify that formatted errors and debug representations redact credentials and tokens.
9. **Acceptance Criteria**:
   - Invalid Gateway URLs or negative timeouts fail validation immediately.
   - `ClientConfig::to_safe_string()` redacts all secret fields.
   - Error categories correctly map failure domains without leaking sensitive content.

---

### CLIENT-001-T03 — Four-Layer Architectural Skeletons, Canonical Domain Models & Core Interfaces

1. **Ticket ID**: `CLIENT-001-T03`
2. **Title**: Canonical Client Domain Model Entities & Abstraction Interfaces
3. **Objective**: Implement pure C++20 domain entities, value objects, and abstraction interfaces in `src/client/domain/` matching `detailed-design.md` §2.4, alongside abstract repository/adapter interfaces in `src/client/application/` and `src/client/infrastructure/`.
4. **Architectural Purpose**: Establishes the core business vocabulary and interface contracts, isolating domain rules from infrastructure implementations (SQLite, Gateway HTTP client, OS Keychain).
5. **Scope & Files to Change**:
   - Domain Layer (`src/client/domain/`):
     - `user.hpp` & `user_id.hpp`: Represents the logical identity (`UserId`).
     - `device.hpp` & `device_id.hpp`: Device endpoint representations (`DeviceId`, status).
     - `crypto_identity.hpp`: Device public keys and verification state.
     - `contact.hpp`: Client-side address book and verification state.
     - `conversation.hpp` & `conversation_id.hpp`: Channel model (`DIRECT`, `GROUP`, participants).
     - `message.hpp` & `message_id.hpp`: Logical message item, delivery state, timestamps.
     - `delivery_state.hpp`: Delivery lifecycle (`Pending`, `Sent`, `Delivered`, `Read`, `Failed`).
   - Abstraction Interfaces:
     - `src/client/application/interfaces/i_gateway_client.hpp`: Gateway REST/WebSocket boundary.
     - `src/client/application/interfaces/i_local_store.hpp`: Durable SQLite storage contract.
     - `src/client/application/interfaces/i_secure_storage.hpp`: OS Keychain / DPAPI contract.
     - `src/client/application/interfaces/i_crypto_provider.hpp`: E2EE Signal protocol contract.
6. **Dependencies**: `CLIENT-001-T01`, `detailed-design.md` §2.3, §2.4.
7. **Implementation Approach**:
   - Domain entities use modern C++20 value semantics, `std::string`, `std::chrono`, and `std::optional`.
   - Zero Qt classes or OS headers inside `src/client/domain/`.
8. **Tests & Validation**:
   - `DomainModelTest`: Verify value semantics, immutability, copy/move constructors, equality operators, and ID generation for all domain models.
9. **Acceptance Criteria**:
   - Domain models compile with zero Qt dependencies.
   - Abstract interfaces cover all required Gateway, storage, and cryptographic operations needed by Phase 1 UI and Phase 2 features.

---

### CLIENT-001-T04 — Explicit Composition Root, Application Lifecycle & Clean Shutdown Engine

1. **Ticket ID**: `CLIENT-001-T04`
2. **Title**: Explicit Composition Root, Application Lifecycle & Clean Shutdown Engine
3. **Objective**: Implement `ClientBootstrap` (composition root), `ClientApplication` (lifecycle coordinator), and manager coordination stubs, enforcing explicit constructor dependency injection and deterministic graceful shutdown.
4. **Architectural Purpose**: Replaces ad-hoc singletons and global state with an explicit, reviewable dependency wiring graph, guaranteeing clean teardown and resource flushing upon application exit.
5. **Scope & Files to Change**:
   - `src/client/application/client_bootstrap.hpp` & `.cpp`:
     - Assembles configuration, infrastructure adapters, and application managers.
     - Owns dependency graph lifecycle with deterministic destruction order.
   - `src/client/application/client_application.hpp` & `.cpp`:
     - Coordinates application lifecycle: `initialize()`, `start()`, `shutdown()`.
     - Listens to OS signals (`SIGINT`, `SIGTERM`, Qt `aboutToQuit`).
     - Handles graceful drain of active requests and flushes local storage before exit.
   - `src/client/application/managers/`:
     - Stubs for `AuthManager`, `MessagingManager`, `ContactManager`, `DeviceManager`, `FileManager`, `EmergencyManager`, `SyncManager`.
6. **Dependencies**: `CLIENT-001-T02`, `CLIENT-001-T03`, `detailed-design.md` §2.3.
7. **Implementation Approach**:
   - Constructor-based dependency injection.
   - RAII resource management for all background threads and network workers.
8. **Tests & Validation**:
   - `ClientBootstrapTest`: Verify container wires mock adapters and managers correctly.
   - `ClientLifecycleSmokeTest`: Test startup -> run -> clean shutdown sequence.
9. **Acceptance Criteria**:
   - No global mutable state or service locator patterns used.
   - All managers are instantiated and cleanly destroyed in reverse order without leaks or deadlocks.
   - Shutdown completes within bounded timeout.

---

### CLIENT-001-T05 — Navigation Controller, View Router State Machine & QML Presentation Shell

1. **Ticket ID**: `CLIENT-001-T05`
2. **Title**: Navigation Controller, View Router State Machine & QML Presentation Shell
3. **Objective**: Implement the application's view routing state machine (`NavigationController`, `NavigationState`) and Qt Quick/QML shell (`Main.qml`, `AppWindow.qml`), establishing extension points for CLIENT-002 (Auth), CLIENT-003 (Workspace Shell), and CLIENT-004 (Gateway).
4. **Architectural Purpose**: Guarantees that view transitions are driven by deterministic C++ application state rather than unvalidated QML scripts, strictly maintaining the UI/Application layer boundary.
5. **Scope & Files to Change**:
   - `src/client/ui/navigation_controller.hpp` & `.cpp`:
     - `NavigationState` enum: `Unauthenticated` (Login/Register), `MfaVerification`, `MainWorkspace` (Conversations/Contacts), `Settings`, `EmergencyMode`.
     - Exposes `currentView`, `canNavigateBack`, `navigate(ViewId)` as `Q_PROPERTY` and `Q_INVOKABLE`.
     - Guards restricted routes when unauthenticated.
   - `src/client/ui/app_view_model.hpp` & `.cpp`:
     - Exposes application connection status, active view, and user banner info to QML.
   - QML Presentation Foundation (`src/client/ui/qml/`):
     - `Main.qml`: Root application window, theme constants, responsive window geometry.
     - `NavigationShell.qml`: Stack/loader routing between authentication, workspace, and settings.
     - Placeholder views: `LoginPlaceholder.qml`, `WorkspacePlaceholder.qml`, `SettingsPlaceholder.qml`.
   - `src/client/main.cpp`:
     - Wires `QGuiApplication`, initializes `ClientBootstrap`, loads QML root via `QQmlApplicationEngine`.
6. **Dependencies**: `CLIENT-001-T04`, `detailed-design.md` §2.3.
7. **Implementation Approach**:
   - Register C++ ViewModels and NavigationController with QML engine via `qmlRegisterSingletonInstance` or `QML_ELEMENT`.
   - Keep QML strictly declarative: UI reflects C++ ViewModel properties and emits signals to C++ controllers.
8. **Tests & Validation**:
   - `NavigationControllerTest`: Verify route transitions, unauthenticated access blocking, and navigation history stack.
9. **Acceptance Criteria**:
   - Root QML window launches cleanly without QML syntax errors or missing property bindings.
   - Navigation controller transitions correctly between states and enforces authentication boundaries.
   - Zero business logic resides in QML files.

---

### CLIENT-001-T06 — Exhaustive Unit Test Suite, Headless Verification Harness & Architecture Build Note

1. **Ticket ID**: `CLIENT-001-T06`
2. **Title**: Comprehensive Unit Test Suite, Headless Verification Harness & Build Documentation
3. **Objective**: Establish comprehensive automated unit test coverage across all client foundation modules, a headless test execution harness suitable for CI runners, and architectural documentation for client module extension.
4. **Architectural Purpose**: Guarantees repeatable local and CI verification without requiring a physical monitor or GPU, ensuring subsequent client feature cards (CLIENT-002 through CLIENT-004) build on a battle-tested base.
5. **Scope & Files to Change**:
   - `tests/unit/client/`:
     - `client_config_test.cpp`: Configuration parsing, environment overrides, boundaries.
     - `client_error_test.cpp`: Error categorization, formatting, secret redaction.
     - `domain_model_test.cpp`: Domain value semantics, invariants, ID types.
     - `client_bootstrap_test.cpp`: Composition root, dependency graph wiring.
     - `navigation_controller_test.cpp`: View routing, state transitions, authentication guards.
     - `client_lifecycle_smoke_test.cpp`: Headless startup/shutdown lifecycle.
   - `tests/unit/CMakeLists.txt`: Register `securecloud_client_*_test` targets.
   - `docs/architecture/client-architecture-and-foundation.md`: Document module structure, layer boundaries, and feature onboarding guide for CLIENT-002+.
6. **Dependencies**: `CLIENT-001-T01` through `CLIENT-001-T05`.
7. **Implementation Approach**:
   - Tests execute headlessly using `QCoreApplication` or offscreen Qt platform plugin (`-platform offscreen`).
   - Integrated into CTest and developer verification scripts (`cmake --build build/dev-debug --target test`).
8. **Tests & Validation Commands**:
   - `cmake --build build/dev-debug --target check-format`: Verify 100% adherence to `.clang-format`.
   - `ctest --test-dir build/dev-debug -R "Client" --output-on-failure`: Run all client unit tests.
   - `build/dev-debug/src/client/securecloud-client --smoke-test` (or offscreen run): Verify clean startup and shutdown.
9. **Acceptance Criteria**:
   - 100% pass rate across all client unit and lifecycle smoke tests.
   - All tests run cleanly headlessly without requiring a window manager or display server.
   - Architecture note documents how new client feature modules plug into Managers and ViewModels without violating layering.

---

## 5. Traceability Matrix to Acceptance Criteria

| Acceptance Criterion | Ticket(s) | Verification Method |
| :--- | :--- | :--- |
| **Reproducible local build & CMake structure** | `T01` | `cmake --preset dev-debug && cmake --build build/dev-debug` |
| **Existing targets remain functional** | `T01`, `T06` | CTest pass rate across all existing service test suites |
| **Four-layer separation (UI / App / Domain / Infra)** | `T01`, `T03` | Separate CMake targets & compiler linkage enforcement |
| **Explicit composition & dependency wiring** | `T04` | `ClientBootstrapTest` verifying constructor DI |
| **Minimal application clean startup & shutdown** | `T04`, `T05`, `T06` | `ClientLifecycleSmokeTest` / startup-shutdown verification |
| **Consistent error handling with zero secret leaks** | `T02`, `T06` | `ClientErrorTest` & `ClientConfigTest` |
| **Documented test framework & verification** | `T06` | Documented commands in `specs/client-phase1/CLIENT-001-tickets.md` |
| **Supports navigation & entry points for CLIENT-002–004** | `T05` | `NavigationControllerTest` & QML Shell routing |
| **Zero unauthorized crypto / persistence decisions** | `T03`, `T04` | Abstract interfaces only; concrete storage deferred to feature cards |
| **Concise architecture note & documentation** | `T06` | `docs/architecture/client-architecture-and-foundation.md` |

---

## 6. Implementation Gate & Next Steps

> [!IMPORTANT]
> In accordance with project instructions, all code modifications remain paused until the Technical Lead and Security Architect explicitly review and approve this specification.
> 
> Once approved:
> 1. Implementation will proceed strictly on feature branch `feature/client-001-client-application-foundation`.
> 2. Tickets will be executed in topological order: `T01` $\to$ `T02` $\to$ `T03` $\to$ `T04` $\to$ `T05` $\to$ `T06`.
> 3. Each ticket will maintain zero compiler warnings (`-Wall -Wextra -Werror -Wpedantic`), 100% `.clang-format` conformance, and comprehensive unit tests.

