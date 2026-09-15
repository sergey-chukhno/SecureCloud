# SecureCloud — Repository Structure

## 1. Purpose

This document defines the physical repository structure and dependency boundaries for SecureCloud.

It translates the approved architecture into a concrete C++ project layout.

It defines:

* where application and service code lives;
* how CMake projects are organized;
* where shared infrastructure belongs;
* how tests are organized;
* which dependencies are permitted;
* how service isolation is preserved;
* how the repository can support independent service builds and deployment.

This document does not redefine service responsibilities or architectural decisions.

---

# 2. Repository Principles

The repository must make architectural boundaries visible in the filesystem and build system.

The structure should enforce:

* service isolation;
* explicit dependencies;
* database ownership;
* separation between domain/application/infrastructure code;
* test isolation;
* reusable infrastructure without shared business logic;
* independent service executables;
* independent container images.

A developer should be able to determine from the repository structure whether a dependency is architecturally legitimate.

---

# 3. Top-Level Structure

The initial repository structure is:

```text id="h6m9g1"
SecureCloud/
│
├── .antigravity/
│   └── RULES.md
│
├── docs/
│   ├── architecture/
│   ├── design/
│   ├── diagrams/
│   ├── api/
│   └── implementation/
│
├── cmake/
│   ├── modules/
│   └── toolchains/
│
├── src/
│   ├── client/
│   ├── gateway/
│   ├── auth/
│   ├── messaging/
│   ├── files/
│   ├── audit/
│   └── common/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   ├── e2e/
│   ├── security/
│   ├── resilience/
│   └── performance/
│
├── proto/
│   └── securecloud/
│
├── openapi/
│   └── openapi.yaml
│
├── config/
│   ├── development/
│   ├── test/
│   └── production/
│
├── deploy/
│   ├── docker/
│   └── compose/
│
├── scripts/
│
├── benchmarks/
│
├── CMakeLists.txt
├── CMakePresets.json
├── .clang-format
├── .clang-tidy
├── .gitignore
└── README.md
```

The exact contents of individual directories may evolve during implementation, but the architectural boundaries defined here must remain stable.

---

# 4. Executable Components

SecureCloud contains six primary executable applications:

```text id="9u6p5a"
securecloud-client
securecloud-gateway
securecloud-auth
securecloud-messaging
securecloud-files
securecloud-audit
```

The five backend executables correspond exactly to the approved runtime services:

```text id="4b5v4d"
Gateway
Auth
Messaging
Files
Audit
```

The client is a separate endpoint application.

Infrastructure/deployment tooling is not a runtime executable.

---

# 5. Service Directory Structure

Each backend service follows a consistent internal structure.

Example:

```text id="y0qj8q"
src/auth/
├── main.cpp
├── CMakeLists.txt
│
├── api/
│   ├── grpc/
│   └── internal/
│
├── application/
│   ├── services/
│   └── use_cases/
│
├── domain/
│   ├── entities/
│   ├── value_objects/
│   ├── policies/
│   └── errors/
│
├── infrastructure/
│   ├── persistence/
│   ├── grpc/
│   ├── security/
│   ├── configuration/
│   └── audit/
│
└── runtime/
    ├── workers/
    ├── lifecycle/
    └── resources/
```

The same structural pattern applies to:

```text id="w5v2cx"
gateway/
auth/
messaging/
files/
audit/
```

A service does not have to contain every directory if a particular layer is genuinely unnecessary.

Do not create empty architectural layers merely for symmetry.

---

# 6. Layer Responsibilities

## 6.1 Domain

Contains business concepts and rules belonging to the service.

Domain code should not depend on:

* PostgreSQL;
* ScyllaDB;
* MinIO;
* ClickHouse;
* gRPC;
* HTTP;
* Qt;
* Docker;
* operating-system-specific infrastructure.

The domain should be testable without starting external infrastructure.

---

## 6.2 Application

Coordinates use cases and business workflows.

It may depend on domain abstractions and interfaces.

It must not directly embed database or transport implementation details.

Example:

```text id="x4u4hf"
MessageSubmissionUseCase
        ↓
MessageRepository interface
        ↓
ScyllaDB implementation
```

rather than:

```text id="g8v7w2"
MessageSubmissionUseCase
        ↓
ScyllaDB API
```

---

## 6.3 API

Contains external/service-facing interface definitions and adapters.

Examples:

* gRPC controllers;
* request validation;
* response mapping;
* protocol adapters.

API code translates transport-level requests into application use cases.

It must not contain large amounts of business logic.

---

## 6.4 Infrastructure

Contains implementations of external dependencies.

Examples:

* database repositories;
* MinIO client;
* gRPC clients;
* service PKI/mTLS integration;
* configuration;
* external storage;
* audit publishing.

Infrastructure implements interfaces required by the application/domain layers.

---

## 6.5 Runtime

Contains execution-management concerns such as:

* worker pools;
* lifecycle;
* graceful shutdown;
* resource management;
* bounded concurrency;
* service startup;
* runtime coordination.

Runtime code may connect the application layer to infrastructure.

It must not become a second business-logic layer.

---

# 7. Client Structure

The Qt/C++ client follows the approved four-layer architecture:

```text id="0j3v5a"
src/client/
├── main.cpp
├── CMakeLists.txt
│
├── ui/
│   ├── qml/
│   └── presentation/
│
├── application/
│   ├── managers/
│   └── workflows/
│
├── domain/
│   ├── identity/
│   ├── messaging/
│   ├── files/
│   └── synchronization/
│
└── infrastructure/
    ├── networking/
    ├── persistence/
    ├── crypto/
    ├── secure_storage/
    └── configuration/
```

The principal client Managers are:

```text id="g7p5jt"
AuthManager
ContactManager
MessagingManager
SyncManager
DeviceManager
FileManager
EmergencyManager
```

Client components are **Managers**, not backend Services.

---

# 8. Client Layer Rules

The dependency direction is:

```text id="s4e7p2"
UI
 ↓
Application
 ↓
Domain
 ↓
Infrastructure
```

UI must not directly:

* access SQLite;
* call gRPC;
* perform cryptographic operations;
* manipulate backend protocol objects.

Application Managers coordinate workflows.

Domain contains client-side business concepts.

Infrastructure handles:

* networking;
* SQLite;
* cryptographic implementation;
* platform secure storage;
* external APIs.

The domain must not depend on Qt-specific infrastructure unless explicitly justified by an existing design decision.

---

# 9. Common Code

`src/common/` is reserved for **technical infrastructure that is genuinely shared**.

Allowed examples:

```text id="i5crp4"
common/
├── logging/
├── configuration/
├── error/
├── serialization/
├── networking/
├── observability/
├── security/
└── utilities/
```

Common code must not become a shared business-logic layer.

Do not put service-specific concepts such as:

```text id="2r9m0q"
MessageRepository
ConversationService
UserRepository
FileService
AuditPolicy
```

into `common/`.

A useful rule is:

> If the code expresses a business rule owned by one service, it belongs to that service.

---

# 10. Common Library Rules

Shared libraries must have a clear reason to exist.

Before adding something to `common/`, verify:

1. Is it genuinely shared?
2. Is it technical rather than business-specific?
3. Does sharing reduce duplication without coupling service ownership?
4. Does it preserve independent service evolution?

Avoid creating a "common" library simply to make unrelated services compile against the same abstractions.

---

# 11. Service Dependency Rules

The intended dependency structure is:

```text id="5rj6z7"
                 ┌──────────┐
                 │  Common  │
                 └────┬─────┘
                      │
       ┌──────────────┼──────────────┐
       ↓              ↓              ↓
    Gateway         Auth        Messaging
       │              │              │
       │              │              │
       └──────────────┼──────────────┘
                      │
                 Files / Audit
```

This diagram represents shared **technical infrastructure**, not business dependencies.

Actual service-to-service interaction occurs through network contracts.

For example:

```text id="n8n0yp"
Gateway
   ↓ gRPC
Auth
```

not:

```text id="2f0a5k"
Gateway
   ↓ C++ library call
Auth
```

---

# 12. Forbidden Dependencies

The following dependencies are prohibited:

### Service → another service's source code

```text id="c1w5c4"
Messaging → Auth business implementation
```

### Service → another service's database

```text id="f6r8v9"
Messaging → Auth PostgreSQL
```

### Service → another service's repository

```text id="q5e4p1"
Files → Messaging repository
```

### Shared business model

Do not create a giant:

```text
common/domain/
```

containing all SecureCloud entities.

Service-owned domain models must remain service-owned.

### Shared database models

Do not create common ORM/DB entities representing tables owned by different services.

---

# 13. Service Contracts

Generated protocol code belongs to the contract/build layer rather than individual business domains.

Recommended structure:

```text id="8q1g5v"
proto/
└── securecloud/
    ├── auth.proto
    ├── messaging.proto
    ├── files.proto
    ├── audit.proto
    └── common.proto
```

Generated C++ protobuf/gRPC code should be produced into the build tree or a clearly isolated generated-code directory.

Do not manually edit generated files.

Services consume contracts through generated interfaces.

---

# 14. API Ownership

Each contract has an explicit owner.

| Contract                    | Owner                   |
| --------------------------- | ----------------------- |
| Client ↔ Gateway REST       | Gateway                 |
| Gateway ↔ Auth gRPC         | Auth                    |
| Gateway ↔ Messaging gRPC    | Messaging               |
| Gateway ↔ Files gRPC        | Files                   |
| Gateway ↔ Audit integration | Audit                   |
| Messaging ↔ Auth gRPC       | Auth/Messaging boundary |
| Files ↔ Auth gRPC           | Auth/Files boundary     |

The owning service is responsible for maintaining the semantic contract.

Changes must be reviewed by both producer and consumer when they affect compatibility.

---

# 15. Database Code Placement

Database implementation belongs inside the owning service.

Examples:

```text id="8q7j8r"
src/auth/infrastructure/persistence/
src/messaging/infrastructure/persistence/
src/files/infrastructure/persistence/
src/audit/infrastructure/persistence/
```

Do not create:

```text id="3c9x5h"
src/common/database/
```

for shared business persistence logic.

Technical database utilities may be shared only when they do not introduce ownership coupling.

---

# 16. Tests Structure

Tests are separated by purpose.

```text id="5f1v2e"
tests/
├── unit/
│   ├── client/
│   ├── gateway/
│   ├── auth/
│   ├── messaging/
│   ├── files/
│   └── audit/
│
├── integration/
│   ├── auth/
│   ├── messaging/
│   ├── files/
│   └── audit/
│
├── contract/
│   ├── rest/
│   └── grpc/
│
├── e2e/
│
├── security/
│
├── resilience/
│
└── performance/
```

---

# 17. Unit Tests

Unit tests should primarily target:

* domain rules;
* application use cases;
* validation;
* state transitions;
* authorization decisions;
* idempotency logic;
* retry decisions;
* resource-management logic.

Unit tests should avoid requiring live infrastructure whenever possible.

Use mocks/fakes at architectural boundaries where appropriate.

Do not mock everything merely to increase test isolation.

---

# 18. Integration Tests

Integration tests verify real infrastructure behavior.

Examples:

### Auth

```text
Auth
 ↓
PostgreSQL
```

### Messaging

```text
Messaging
 ↓
ScyllaDB
```

### Files

```text
Files
 ├── PostgreSQL
 └── MinIO
```

### Audit

```text
Audit
 ↓
ClickHouse
```

These tests should run against reproducible test infrastructure.

---

# 19. Contract Tests

Contract tests verify that implementations conform to:

* OpenAPI;
* gRPC/Protobuf;
* request/response semantics;
* error contracts;
* compatibility requirements.

Contract tests must detect accidental breaking changes before integration.

---

# 20. Security and Resilience Tests

Security and resilience tests are separate from ordinary unit tests because they validate architectural properties.

Security tests include:

* authentication;
* MFA;
* authorization;
* token lifecycle;
* service identity;
* E2E boundaries;
* device revocation;
* replay/tampering;
* secret leakage.

Resilience tests include:

* network interruption;
* timeout;
* service crash;
* dependency outage;
* lost response;
* duplicate request;
* retry behavior;
* database failure;
* reconnect behavior.

---

# 21. Performance Tests

Performance-specific workloads belong under:

```text id="6njw5p"
tests/performance/
benchmarks/
```

Performance code must not alter production semantics to obtain better numbers.

The benchmark environment must use the approved architecture and relevant security/durability mechanisms.

---

# 22. CMake Structure

The root `CMakeLists.txt` is responsible for composing the repository.

Conceptually:

```text id="q6o1mp"
Root CMake
   │
   ├── common
   ├── client
   ├── gateway
   ├── auth
   ├── messaging
   ├── files
   └── audit
```

Each major component has its own `CMakeLists.txt`.

The root build should support:

* building all components;
* building individual components;
* running tests;
* enabling sanitizers;
* enabling static analysis;
* development builds;
* release builds.

The exact CMake target names should remain stable and descriptive.

---

# 23. CMake Dependency Enforcement

CMake target dependencies should reflect architectural dependencies.

Prefer:

```text id="g3c6w0"
target_link_libraries(
    securecloud-auth
    PRIVATE
    securecloud-common
)
```

over manually manipulating compiler/linker flags.

A service must not accidentally link another service executable/library.

For example, this is forbidden:

```text id="m0v9y2"
securecloud-messaging
    → securecloud-auth
```

Messaging communicates with Auth through the approved gRPC contract.

---

# 24. Generated Code

Generated code includes, where applicable:

* protobuf;
* gRPC;
* Qt generated artifacts;
* other build-generated sources.

Generated code must:

* have a clearly defined generation step;
* not be manually edited;
* be reproducible;
* have versioned generation inputs.

The repository should clearly distinguish handwritten code from generated code.

---

# 25. Configuration

Configuration is separated from source code.

Use:

```text id="9v5j2x"
config/
├── development/
├── test/
└── production/
```

Do not commit real production secrets.

Configuration must not contain cryptographic private keys or production credentials.

Environment-specific secrets must be injected through the deployment/runtime environment.

---

# 26. Deployment Structure

Deployment configuration belongs outside `src/`.

Initial deployment:

```text id="7r5k9w"
deploy/
├── docker/
└── compose/
```

Dockerfiles should produce independently deployable images for:

```text id="9n1g5c"
gateway
auth
messaging
files
audit
```

The client has its own packaging strategy and is not required to use the backend container model.

Docker Compose is the initial distributed deployment environment.

The repository structure must not assume that all services will permanently run on one host.

---

# 27. Scripts

`scripts/` contains developer and CI automation such as:

* environment setup;
* database initialization;
* code generation;
* test orchestration;
* linting;
* local service startup;
* benchmark execution.

Scripts must call the same underlying build/test mechanisms used by CI where practical.

Do not hide important architectural behavior inside undocumented scripts.

---

# 28. Ownership by Team

The repository structure should support the initial three-developer ownership model.

### Sergey

Primary areas:

```text id="v9r1q0"
src/gateway/
src/messaging/
src/common/security/
tests/resilience/
tests/performance/
```

### Developer 2

Primary areas:

```text id="7c2w8h"
src/auth/
tests/unit/auth/
tests/integration/auth/
```

### Developer 3

Primary areas:

```text id="w1d6a5"
src/files/
tests/unit/files/
tests/integration/files/
```

Client work and cross-service integration remain shared responsibilities and may be assigned through Trello as the implementation progresses.

Ownership does not grant permission to violate architectural boundaries.

---

# 29. One Owner Per Service

Each service should have a primary developer responsible for:

* implementation;
* tests;
* local documentation;
* contract correctness;
* review preparation.

Other developers may modify the service when required.

The owner is not the sole person allowed to review or change the code.

Security-sensitive and cross-service changes should receive review from another developer.

---

# 30. Pull Request Boundaries

A pull request should normally represent one coherent engineering outcome.

Prefer:

```text id="8n5q5k"
Implement Auth TOTP verification
```

over:

```text id="2w6p1r"
Implement Auth
```

Avoid mixing unrelated service changes in the same PR unless they are required by one contract or integration change.

Cross-service PRs are appropriate when a contract change requires coordinated implementation.

---

# 31. Repository Structure Invariants

The following must remain true:

1. Each runtime service has an independent executable.
2. Services do not directly access another service's database.
3. Services do not link against another service's business implementation.
4. Service communication uses approved contracts.
5. Service-owned domain logic remains inside the owning service.
6. Shared code is technical infrastructure, not shared business logic.
7. Client and backend code remain separate.
8. Database implementations remain inside their owning service.
9. Generated code is clearly separated from handwritten code.
10. Tests are organized according to their purpose.
11. Deployment configuration remains outside application source.
12. The repository structure must not require services to run on the same host.

---

# 32. When the Structure May Change

The repository structure may evolve when implementation reveals a genuine need.

Examples:

* a service becomes large enough to require additional internal modules;
* a shared technical component is proven genuinely reusable;
* build times require CMake restructuring;
* deployment requirements require additional packaging structure.

Such changes must preserve the architectural boundaries.

Do not restructure the repository merely for aesthetic reasons during active feature development.

---

# 33. Final Principle

The repository should make the architecture **visible and enforceable**.

A developer should be able to answer these questions simply by looking at the repository:

* Which service owns this code?
* Which layer does it belong to?
* Which dependencies are allowed?
* Which database does it own?
* Which API contract does it implement?
* Where are its tests?
* Can it be built and deployed independently?

If the repository structure makes these questions difficult to answer, the structure is not doing its job.
