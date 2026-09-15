# SecureCloud — Implementation Plan

## 1. Purpose

This document defines the implementation order for SecureCloud.

It translates the approved architecture, ADRs, detailed design, data model, API contracts, and diagrams into a practical construction roadmap.

It answers:

* what must be implemented;
* in what order;
* what can be implemented in parallel;
* what dependencies exist;
* what constitutes completion of each phase;
* when the system becomes progressively usable.

This document does **not** redefine architecture.

Architectural decisions remain authoritative in the architecture and ADR documents.

---

# 2. Implementation Strategy

SecureCloud is implemented as a sequence of **working vertical slices**, not as isolated services developed completely independently and integrated only at the end.

The implementation should progressively move from:

```text
Foundation
    ↓
Service skeletons + contracts
    ↓
Authentication
    ↓
Gateway
    ↓
Messaging
    ↓
Files
    ↓
Audit
    ↓
Client integration
    ↓
Distributed failure handling
    ↓
Security hardening
    ↓
Performance validation
```

At every major stage, the system should remain buildable and testable.

Avoid building large amounts of code that cannot be integrated until the final weeks.

---

# 3. Implementation Principles

## 3.1 Design Before Code

Before implementing a component, verify:

* relevant architecture;
* applicable ADRs;
* detailed design;
* data model;
* API contract;
* relevant sequence diagram.

If the required behavior is not sufficiently defined, resolve the design question before implementing it.

Do not use implementation as a substitute for architectural design.

---

## 3.2 Contract-First Development

External and inter-service contracts must be established before dependent implementations.

Primary contracts:

```text
Client ↔ Gateway
Gateway ↔ Auth
Gateway ↔ Messaging
Gateway ↔ Files
Gateway ↔ Audit
Messaging ↔ Auth
Files ↔ Auth
```

REST/OpenAPI and gRPC/Protobuf definitions are the contract sources.

Implement contract tests alongside service implementations.

---

## 3.3 Vertical Integration

Each major capability should progress through:

```text
Contract
   ↓
Data model
   ↓
Service implementation
   ↓
Tests
   ↓
Integration
   ↓
Client usage
```

Do not consider a service complete merely because its internal API works.

---

## 3.4 Security From the Beginning

Security is implemented incrementally from the first service-to-service communication.

Do not initially implement insecure communication and "add security later" if doing so would establish an architecture that must subsequently be rewritten.

The implementation baseline includes:

* TLS;
* service identity;
* mTLS;
* authentication;
* authorization;
* MFA;
* E2E encryption boundary;
* secure secret handling;
* device identity;
* revocation;
* audit security events.

---

# 4. Phase 0 — Repository and Development Foundation

## Objective

Create the project foundation required for all subsequent development.

### Work

Establish:

* repository structure;
* CMake configuration;
* C++20 configuration;
* dependency management;
* common build configuration;
* compiler warnings;
* formatting;
* static analysis;
* sanitizer configuration;
* test framework;
* CI pipeline;
* Docker development environment;
* Docker Compose skeleton;
* environment/configuration conventions;
* basic documentation structure.

Create buildable skeletons for:

```text
client
gateway
auth
messaging
files
audit
```

The services do not need business functionality yet.

### Completion gate

The repository must:

* build successfully;
* run unit-test infrastructure;
* run static analysis;
* run configured sanitizers where applicable;
* build service containers;
* start the basic Compose topology;
* expose basic health/readiness endpoints;
* allow developers to reproduce the build locally.

---

# 5. Phase 1 — Contracts and Service Communication Foundation

## Objective

Establish the communication mechanisms that all services will use.

### Work

Implement the foundations for:

* REST/OpenAPI;
* gRPC/Protobuf;
* HTTP/2;
* service configuration;
* connection management;
* deadlines;
* cancellation;
* structured error mapping;
* request-size limits;
* response-size limits;
* streaming support where required;
* service health/readiness.

Establish service-to-service mTLS using the SecureCloud service PKI.

Each service receives its own service identity.

### Completion gate

At least one authenticated test RPC must successfully travel through:

```text
Gateway
   ↓ mTLS/gRPC
Backend Service
```

with:

* certificate verification;
* service identity verification;
* authorization;
* timeout/deadline;
* explicit error handling.

No service should depend on insecure localhost-only communication.

---

# 6. Phase 2 — Authentication Service

## Objective

Implement the authoritative application authentication and device/security state service.

### Primary implementation

Implement:

* PostgreSQL 17 schema;
* migrations;
* user identity;
* credential storage/verification;
* MFA/TOTP;
* authentication assurance level;
* session lifecycle;
* access-token issuance;
* refresh-token lifecycle;
* token rotation;
* token reuse detection;
* device registration;
* device authorization/pairing;
* device revocation;
* public cryptographic directory;
* prekey management;
* authorization policies;
* Auth gRPC API;
* transactional audit outbox.

### Security requirements

Verify:

* passwords are never stored in plaintext;
* refresh tokens are protected;
* access tokens contain only approved claims;
* MFA cannot be bypassed;
* device registration cannot be performed using only an arbitrary valid session;
* revoked devices cannot authenticate for future operations;
* private cryptographic keys never reach Auth.

### Completion gate

A client/test client can:

```text
Register/login
    ↓
Complete MFA
    ↓
Receive access + refresh tokens
    ↓
Refresh session
    ↓
Register/authorize device
    ↓
Publish public crypto material
    ↓
Revoke device
    ↓
Verify revocation
```

All critical state is durable in PostgreSQL.

---

# 7. Phase 3 — Gateway

## Objective

Implement the single external entry point.

### Primary implementation

Implement:

* HTTPS/TLS 1.3;
* REST API;
* request validation;
* access-token middleware;
* token verification;
* authenticated context;
* coarse scope authorization;
* routing;
* gRPC client layer;
* deadlines;
* cancellation;
* rate/resource limiting;
* streaming proxy;
* error mapping;
* bounded request/concurrency resources.

Gateway remains stateless.

### Authentication flow

Implement:

```text
Client
  ↓ HTTPS
Gateway
  ↓ gRPC
Auth
  ↓
Authentication result
  ↓
Gateway
  ↓
Client
```

Unauthenticated requests must never be redirected to internal services.

### Completion gate

A client can authenticate through the Gateway and access an authenticated protected endpoint without knowing any backend service address.

Gateway must correctly reject:

* missing credentials;
* invalid signatures;
* expired tokens;
* wrong issuer/audience;
* revoked/token-version-invalid sessions;
* insufficient scope.

---

# 8. Phase 4 — Messaging Persistence and Domain

## Objective

Implement the durable Messaging core before real-time delivery.

### Primary implementation

Implement:

* ScyllaDB schema;
* message model;
* conversation model;
* participant model;
* device-level delivery targets;
* delivery state;
* idempotency state;
* synchronization cursor;
* outbox state;
* repository layer;
* message validation;
* conversation authorization;
* durable acceptance.

### Durable acceptance

`SendMessage` succeeds only after the required state is durably persisted:

```text
Encrypted message
       +
Initial delivery state
       +
Required metadata
       +
Outbox event
       ↓
Atomic durable acceptance
```

### Completion gate

The service can:

* accept valid encrypted envelopes;
* reject invalid envelopes;
* create conversations;
* enforce membership authorization;
* persist messages durably;
* handle duplicate submissions;
* recover accepted messages after restart;
* create delivery targets;
* create audit outbox events.

No recipient delivery is required yet.

---

# 9. Phase 5 — Messaging Delivery and Synchronization

## Objective

Implement reliable online/offline message delivery.

### Primary implementation

Implement:

* delivery scheduler;
* delivery workers;
* retry scheduler;
* durable offline queues;
* device-level delivery;
* delivery state transitions;
* delivery ACK;
* read receipts;
* synchronization;
* incremental cursors;
* reconnect handling;
* bounded worker pools;
* bounded queues;
* priority scheduling;
* backpressure.

### Delivery model

```text
QUEUED
   ↓
DELIVERING
   ↓
DELIVERED
   ↓
READ
```

Retry path:

```text
DELIVERING
   ↓
RETRY_WAIT
   ↓
DELIVERING
```

Terminal expiration:

```text
RETRY_WAIT
   ↓
EXPIRED
```

### Completion gate

The system must demonstrate:

1. recipient online → delivery;
2. recipient offline → durable queue;
3. recipient reconnects → recovery;
4. duplicate delivery → client deduplication;
5. lost ACK → safe retry;
6. lost response → idempotent resolution;
7. revoked device → no future delivery;
8. multiple recipient devices → independent delivery;
9. restart → durable state recovery.

---

# 10. Phase 6 — End-to-End Cryptographic Integration

## Objective

Integrate the approved endpoint cryptographic architecture with Messaging.

### Client implementation

Implement:

* device cryptographic identity;
* secure private-key storage;
* public-key directory interaction;
* prekey retrieval/publication;
* session establishment;
* vetted Signal-family protocol integration;
* message encryption;
* message decryption;
* key lifecycle;
* identity verification/change detection;
* device-specific sessions;
* message-key lifecycle.

### Backend boundary

Messaging must treat ciphertext and cryptographic metadata as opaque.

The backend must not implement message decryption.

### Completion gate

Demonstrate:

```text
Alice Device
    ↓ encrypt
Ciphertext
    ↓
Gateway
    ↓
Messaging
    ↓
Bob Device
    ↓ decrypt
Plaintext
```

and verify that backend components never receive the plaintext.

Test:

* tampering;
* replay;
* invalid ciphertext;
* key changes;
* device revocation;
* multiple devices.

---

# 11. Phase 7 — Files Service

## Objective

Implement secure encrypted file storage and resumable transfer.

### Primary implementation

Implement:

* PostgreSQL metadata schema;
* transfer state;
* MinIO integration;
* encrypted object storage;
* chunking;
* resumable upload;
* resumable download;
* chunk-level idempotency;
* integrity verification;
* file-access capability validation;
* streaming;
* bounded transfer concurrency;
* upload/download isolation;
* cleanup;
* immutable completed objects;
* zstd client-side compression support;
* Files gRPC API;
* audit outbox.

### File lifecycle

```text
CREATED
   ↓
UPLOADING
   ↓
FINALIZING
   ↓
AVAILABLE
```

Failure/retention states are handled according to the approved Files design.

### Completion gate

Demonstrate:

* encrypted upload;
* interrupted upload;
* upload resume;
* completed object finalization;
* encrypted download;
* interrupted download;
* download resume;
* integrity failure detection;
* concurrent uploads/downloads;
* bounded memory;
* authorization failure.

---

# 12. Phase 8 — Audit Service

## Objective

Implement durable application/security/communication auditing without coupling it to message acceptance.

### Primary implementation

Implement:

* ClickHouse schema;
* audit event model;
* event ingestion;
* event validation;
* idempotent event processing;
* outbox consumers;
* event retention;
* audit queries required by the application;
* relevant security/application/communication events.

Audit must not become generic telemetry.

### Completion gate

Demonstrate:

```text
Service
   ↓
Transactional Outbox
   ↓
Audit Event
   ↓
Audit Service
   ↓
ClickHouse
```

and verify:

* duplicate events do not create duplicate logical audit records;
* Audit outage does not prevent durable message acceptance;
* events contain no plaintext/private keys;
* application/security events can be queried.

---

# 13. Phase 9 — Client Integration

## Objective

Connect the Qt/C++ client to the complete backend.

### Implement/integrate

* AuthManager;
* ContactManager;
* MessagingManager;
* SyncManager;
* DeviceManager;
* FileManager;
* EmergencyManager.

Integrate:

* authentication;
* MFA;
* device lifecycle;
* cryptographic identity;
* contact verification;
* conversations;
* encrypted messaging;
* delivery/read state;
* synchronization;
* offline recovery;
* file transfer;
* emergency priority;
* error/retry behavior.

### Completion gate

The primary user journey works end-to-end:

```text
Login
  ↓
MFA
  ↓
Device authorized
  ↓
Crypto identity established
  ↓
Contact verified
  ↓
Conversation created
  ↓
Encrypted message sent
  ↓
Recipient receives message
  ↓
Delivery acknowledged
  ↓
Message read
  ↓
Read receipt synchronized
```

---

# 14. Phase 10 — Distributed Resilience

## Objective

Validate behavior under realistic distributed failures.

Test:

* Gateway failure;
* Auth failure;
* Messaging failure;
* Files failure;
* Audit failure;
* PostgreSQL failure;
* ScyllaDB node/service failure;
* MinIO failure;
* ClickHouse failure;
* network interruption;
* timeout;
* delayed response;
* lost response;
* duplicate request;
* lost ACK;
* service restart;
* reconnect storm;
* retry storm;
* resource exhaustion.

### Completion gate

For every tested failure:

1. the system produces a defined result;
2. no security bypass occurs;
3. accepted durable data is not silently lost;
4. retries remain bounded;
5. recovery is deterministic;
6. the system returns to healthy operation.

---

# 15. Phase 11 — Security Hardening

## Objective

Perform dedicated security verification after the complete architecture is operational.

### Areas

Test:

* authentication;
* MFA;
* authorization;
* token lifecycle;
* refresh-token reuse;
* device authorization;
* device revocation;
* service mTLS;
* certificate validation;
* E2E encryption boundary;
* cryptographic identity changes;
* replay/tampering;
* secret storage;
* secret leakage;
* logging;
* administrator privilege boundaries;
* file-access capabilities;
* input validation;
* resource exhaustion;
* protocol downgrade attempts.

### Completion gate

Security invariants defined by the architecture and ADRs are verified by automated or documented tests wherever practical.

---

# 16. Phase 12 — Performance and Capacity Validation

## Objective

Measure the actual system against the approved performance architecture.

### Primary target

Messaging:

```text
10,000 accepted messages/second peak
```

The benchmark must use the real architecture.

Do not disable:

* persistence;
* ScyllaDB;
* transactional outbox;
* mTLS;
* E2E encryption;
* message padding when enabled;
* Gateway;
* durability semantics;
* delivery semantics.

### Measure

* accepted messages/sec;
* sustained throughput;
* peak throughput;
* latency;
* saturation point;
* CPU;
* memory;
* network;
* DB load;
* queue depth;
* retry rate;
* error rate.

Also benchmark:

* concurrent file transfers;
* synchronization;
* multi-device delivery;
* failure under load;
* endurance.

### Completion gate

Produce a reproducible benchmark report containing:

* hardware;
* software versions;
* configuration;
* topology;
* workload;
* security configuration;
* persistence configuration;
* results;
* bottlenecks;
* profiling evidence;
* optimization changes.

---

# 17. Parallel Work Strategy

The project has three developers.

Work should be divided by **bounded ownership areas**, while integration remains shared.

A practical initial split is:

### Developer 1 — Sergey

Primary ownership:

* Gateway;
* Messaging;
* ScyllaDB;
* service-to-service security;
* distributed integration;
* synchronization;
* resilience;
* performance;
* final security/integration work.

### Developer 2

Primary ownership:

* Auth;
* PostgreSQL;
* MFA;
* sessions/tokens;
* device lifecycle;
* public cryptographic directory;
* Auth API;
* Auth tests.

### Developer 3

Primary ownership:

* Files;
* PostgreSQL metadata;
* MinIO;
* resumable transfers;
* file-access capabilities;
* Files API;
* Files tests.

### Shared responsibility

All developers participate in:

* contract definition;
* code review;
* security review;
* integration testing;
* failure testing;
* final E2E testing.

The ownership model does **not** mean that developers work in isolation.

---

# 18. Parallelization

After Phase 1 establishes common foundations, several tracks can proceed concurrently.

```text
                    Phase 0
                       ↓
                    Phase 1
                       ↓
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
      Auth          Gateway        Files
        │              │              │
        └──────────────┼──────────────┘
                       ↓
                  Messaging
                       ↓
              Crypto Integration
                       ↓
              Client Integration
                       ↓
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
     Resilience     Security      Performance
        └──────────────┼──────────────┘
                       ↓
                  Final MVP
```

Messaging depends on Auth interfaces for authorization/device state, but its persistence/domain work can begin before Auth is fully complete using contract-driven mocks.

Files can similarly progress against stable Auth contracts.

Gateway can be developed against service contract stubs while backend services are under construction.

---

# 19. Integration Milestones

The project should have the following major milestones.

## M1 — Buildable Distributed Skeleton

All services and client build.

Docker Compose starts the topology.

Health/readiness works.

---

## M2 — Authenticated Platform

Client can:

* authenticate;
* complete MFA;
* receive tokens;
* manage device state.

Gateway is enforcing authentication.

---

## M3 — Secure Messaging

Client can:

* establish cryptographic identity;
* encrypt a message;
* submit it through Gateway;
* persist it in Messaging;
* deliver it to another device;
* decrypt it.

---

## M4 — Offline Messaging

The system supports:

* durable offline delivery;
* reconnect;
* synchronization;
* delivery/read receipts;
* retries;
* multi-device delivery.

---

## M5 — Secure Files

Client can:

* encrypt;
* upload;
* resume;
* download;
* resume;
* verify integrity.

---

## M6 — Auditable Platform

Security/application/communication events reach Audit reliably without blocking core durable operations.

---

## M7 — Resilient Platform

The complete system survives the defined distributed failure scenarios with correct behavior.

---

## M8 — Validated MVP

Security and performance tests have been executed.

The system has reproducible evidence for its important architectural and performance claims.

---

# 20. Definition of Phase Completion

A phase is complete only when:

* implementation is complete for its defined scope;
* relevant unit tests pass;
* relevant integration/contract tests pass;
* security behavior is checked;
* failure behavior is checked where applicable;
* no known architectural violation exists;
* documentation affected by the implementation is updated;
* code has passed review;
* CI passes.

"Code exists" is not a completion criterion.

---

# 21. Trello Mapping

Each implementation phase will later be converted into concrete Trello cards.

A card should represent one meaningful engineering outcome.

Example:

```text
AUTH — Implement TOTP MFA
```

not:

```text
AUTH SERVICE
```

Each card should contain:

* objective;
* scope;
* relevant design reference;
* dependencies;
* acceptance criteria;
* required tests;
* Definition of Done.

The Trello board must represent **execution**, not duplicate the architecture documentation.

---

# 22. Change Management

If implementation reveals that an approved architectural decision is inadequate:

1. stop the affected implementation;
2. document the observed problem;
3. identify the affected architecture/ADR/design decision;
4. propose the smallest viable correction;
5. obtain approval;
6. update the authoritative document;
7. update affected implementation tasks;
8. continue implementation.

Do not use Trello tasks to silently redefine architecture.

---

# 23. Final Implementation Principle

SecureCloud should reach a working, secure vertical slice as early as possible.

The goal is not:

```text
Build every service
      ↓
Integrate everything
      ↓
Discover problems
```

The goal is:

```text
Build
  ↓
Integrate
  ↓
Test
  ↓
Fail
  ↓
Fix
  ↓
Extend
  ↓
Integrate again
```

Every major capability should become executable, testable, and reviewable before the project moves substantially further.

**Architecture defines what SecureCloud is.
This plan defines how we build it.**
