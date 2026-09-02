# SecureCloud — System Architecture

**Document status:** v0.2
**Document type:** System Architecture
**Architecture status:** Selected baseline; detailed technology decisions remain subject to ADRs.
**Related documents:** Architectural Drivers, System Context, Trust Boundaries, Architecture Alternatives

---

# 1. Purpose

This document defines the baseline system architecture of SecureCloud.

It translates the approved architectural drivers, system context and trust boundaries into a concrete system structure.

It defines:

* runtime components;
* service responsibilities;
* service boundaries;
* communication principles;
* deployment topology;
* data ownership;
* reliability patterns;
* security boundaries;
* testing strategy;
* database investigation;
* performance strategy;
* future optimization boundaries.

It intentionally does not finalize cryptographic protocols, database technology beyond currently established constraints, or every communication protocol. Those decisions belong in dedicated ADRs.

---

# 2. Architectural Principles

SecureCloud follows these principles:

1. **Security before convenience**
2. **Minimize trust**
3. **Server blindness**
4. **Independent service boundaries**
5. **Distributed-first architecture**
6. **Network-based service communication**
7. **Failure isolation**
8. **Durability before throughput**
9. **Measure before optimizing**
10. **No premature complexity**
11. **Explicit data ownership**
12. **Defensible security claims**

---

# 3. High-Level Architecture

```text
                         ┌──────────────────┐
                         │   Qt/C++ Client  │
                         │                  │
                         │ Plaintext +      │
                         │ private keys     │
                         └────────┬─────────┘
                                  │
                         Secure client transport
                                  │
                                  ▼
                         ┌──────────────────┐
                         │     Gateway      │
                         │                  │
                         │ Routing          │
                         │ Rate limiting    │
                         │ Token handling   │
                         └────────┬─────────┘
                                  │
                  ┌───────────────┼────────────────┐
                  │               │                │
                  ▼               ▼                ▼
          ┌─────────────┐ ┌──────────────┐ ┌─────────────┐
          │    Auth     │ │  Messaging   │ │    Files    │
          │   Service   │ │   Service    │ │   Service   │
          └─────────────┘ └───────┬──────┘ └──────┬──────┘
                                  │               │
                                  │               │
                                  └───────┬───────┘
                                          ▼
                                  ┌─────────────┐
                                  │    Audit    │
                                  │   Service   │
                                  └─────────────┘
```

Each service is an independent process and independently deployable container.

---

# 4. Distributed-First Principle

SecureCloud is designed as a distributed system from the beginning.

This does **not** require multiple physical machines during development.

For example, Docker Compose may run:

```text
Host
│
├── Gateway container
├── Auth container
├── Messaging container
├── Files container
├── Audit container
└── PostgreSQL
```

These remain independent services.

The important architectural property is that service communication uses explicit network contracts rather than relying on local process memory.

Therefore the architecture can later become:

```text
Kubernetes Cluster

Node A
 ├── Gateway
 └── Auth

Node B
 ├── Messaging-1
 └── Files-1

Node C
 ├── Messaging-2
 └── Audit
```

without redefining service boundaries.

---

# 5. Runtime Components

## 5.1 Qt/C++ Client

The native client is the primary trusted environment for protected content.

Responsibilities include:

* user interface;
* local authentication/session handling;
* cryptographic identity;
* message encryption/decryption;
* file encryption/decryption;
* local encrypted history;
* device-specific key material;
* secure local storage;
* offline operation;
* emergency interaction;
* location-sharing controls.

Private cryptographic keys must never be transmitted to backend services.

---

# 6. Gateway Service

The Gateway is the external entry point for client traffic.

Responsibilities:

* accept client connections;
* validate requests;
* route requests;
* apply rate limiting;
* enforce connection limits;
* handle authentication tokens according to the selected authentication architecture;
* provide controlled API exposure;
* protect backend services from direct untrusted access.

The Gateway must not become a message decryption authority.

It should operate on opaque identifiers and encrypted application payloads wherever applicable.

The Gateway should remain as stateless as practical.

---

# 7. Authentication Service

Responsibilities:

* authentication;
* MFA;
* session/token issuance;
* token refresh;
* token validation;
* token revocation;
* authorization-related identity information.

Authentication and cryptographic identity remain separate security domains.

The Authentication Service must not possess users' private communication keys.

Compromise of authentication infrastructure must not automatically provide access to historical encrypted communications.

---

# 8. Messaging Service

The Messaging Service is the core communication service.

Responsibilities include:

* accepting encrypted messages;
* validating message envelopes;
* routing ciphertext;
* durable message storage;
* offline delivery;
* delivery acknowledgement;
* retry management;
* duplicate handling;
* ordering according to defined guarantees;
* multi-device delivery coordination;
* emergency-message prioritization;
* bounded queue management.

The Messaging Service must never require message plaintext.

---

# 9. Files Service

Responsibilities:

* encrypted file upload;
* encrypted file download;
* file metadata;
* streaming;
* resumable transfer mechanisms where required;
* integrity verification;
* retention management.

The Files Service operates on ciphertext.

It must not possess the private cryptographic material required to decrypt protected files.

Large-file transfer must avoid unnecessary memory amplification.

---

# 10. Audit Service

The Audit Service provides security and operational auditing.

Potential events include:

* authentication events;
* authorization events;
* message acceptance;
* delivery status;
* file operations;
* administrative operations;
* security-relevant failures;
* service events.

Audit data must not contain unnecessary message/file plaintext.

Communication metadata may be recorded according to the approved trust model.

The exact audit schema and retention policy remain open.

---

# 11. Emergency Unit

The Emergency Unit is **not a separate backend microservice**.

It is an authorized user/group with a special operational role.

Emergency functionality should provide:

* elevated message priority;
* acknowledgement;
* retry/escalation;
* operational delivery guarantees;
* controlled location sharing.

Location is shared only with the Emergency Unit according to the established trust model.

The architecture must ensure that emergency functionality does not introduce an administrator decryption backdoor.

---

# 12. Deploy / Control Plane

The original project specification identifies Deploy Service as one of its five microservices.

SecureCloud instead separates deployment infrastructure from the runtime application architecture.

Deployment responsibilities belong to:

* CI/CD;
* Docker;
* Docker Compose;
* Kubernetes in future environments;
* infrastructure/control-plane tooling;
* health verification;
* deployment automation;
* rollback mechanisms.

The runtime communication path therefore consists of:

```text
Gateway
Auth
Messaging
Files
Audit
```

rather than exposing a Deploy Service as an ordinary application microservice.

This reduces the trusted runtime attack surface.

This architectural deviation should be recorded in an ADR.

---

# 13. Inter-Service Communication

The default communication mechanism is **network-based communication**.

Services must not depend on:

* shared process memory;
* Unix-domain sockets;
* named pipes;
* shared-memory queues.

for correctness.

The exact network protocol remains an ADR.

Candidates include:

* REST/HTTP;
* gRPC;
* another explicitly selected RPC protocol.

The protocol must be evaluated against:

* latency;
* throughput;
* serialization cost;
* observability;
* security;
* C++ support;
* operational complexity;
* testing.

---

# 14. Synchronous and Asynchronous Communication

SecureCloud should use a hybrid communication model at the semantic level.

## Synchronous RPC

Use when the caller needs an immediate result.

Examples:

```text
Gateway → Auth
Gateway → Messaging
Messaging → Files
```

## Asynchronous events

Use where loose coupling and independent processing are advantageous.

Examples:

```text
Messaging → message.accepted → Audit
Files → file.uploaded → Audit
Auth → authentication.event → Audit
```

Events must respect the trust boundaries and must not leak protected plaintext.

---

# 15. Service Contracts

Every service should expose explicit contracts defining:

* request structure;
* response structure;
* errors;
* authentication;
* authorization;
* timeout expectations;
* idempotency;
* versioning;
* compatibility rules.

Contracts should be testable independently of implementation.

---

# 16. Service-to-Service Security

Internal services must not automatically trust each other.

The architecture should support:

```text
Service A
   │
   │ authenticated + authorized
   │ encrypted transport
   ▼
Service B
```

Each service receives only the privileges necessary for its responsibilities.

A compromise of one service should not automatically grant:

* database-wide access;
* private cryptographic keys;
* message plaintext;
* unrelated service privileges.

---

# 17. Data Ownership

SecureCloud follows the **Database-per-Service principle**.

A service owns its data.

For example:

```text
Auth
 └── authentication/account data

Messaging
 └── encrypted messages + delivery state

Files
 └── file metadata + encrypted storage references

Audit
 └── audit events

Gateway
 └── preferably no persistent business database
```

A service must not directly manipulate another service's tables.

---

# 18. Database Architecture

PostgreSQL is an explicit project technology constraint/candidate.

The architecture does not yet mandate a single physical PostgreSQL instance.

Three levels should be evaluated.

### Phase 1 — Logical separation

One PostgreSQL deployment:

```text
PostgreSQL
├── Auth schema
├── Messaging schema
├── Files schema
└── Audit schema
```

with strict ownership.

### Phase 2 — Physical separation

Where justified:

```text
Auth DB
Messaging DB
Files DB
Audit DB
```

### Phase 3 — Polyglot persistence

If workload analysis demonstrates a need:

```text
Auth       → SQL
Messaging  → SQL / specialized storage
Files      → object/file storage + SQL metadata
Audit      → SQL / append-oriented NoSQL
```

NoSQL is therefore an **investigation target**, not an automatic requirement.

---

# 19. Reliability Patterns

SecureCloud incorporates the following patterns where appropriate.

## Timeout

All remote calls have explicit limits.

## Retry

Retries are:

* bounded;
* selective;
* idempotency-aware;
* exponential;
* jittered.

## Circuit Breaker

Repeated failures stop unnecessary calls to an unavailable dependency.

## Bulkhead

Separate resources prevent one workload from consuming all system capacity.

## Backpressure

Queues and buffers are bounded.

## Idempotency

Retryable operations can safely detect duplicate requests.

## Transactional Outbox

Reliable persistence and event publication can be coordinated without requiring distributed transactions.

## Graceful Shutdown

Services safely drain or persist work before termination.

## Health / Readiness

Services distinguish process liveness from operational readiness.

---

# 20. Failure Isolation

SecureCloud explicitly assumes component failures.

Examples:

```text
Audit DOWN
   ↓
Messaging continues accepting messages
   ↓
bounded event/outbox mechanism
   ↓
Audit recovers
```

Similarly:

```text
Files DOWN
   ↓
Messaging must fail in a controlled way
   ↓
no indefinite blocking
```

The exact dependency policy will be defined per workflow.

Emergency workloads should receive resource isolation from normal traffic where appropriate.

---

# 21. Offline Messaging

Offline delivery is based on durable encrypted storage.

Conceptually:

```text
Sender
   │
   ▼
Messaging
   │
   ├── validate
   ├── persist ciphertext
   └── acknowledge durable acceptance
              │
              ▼
        Recipient offline
              │
              ▼
        recipient returns
              │
              ▼
          delivery
```

The exact definition of "durably accepted" remains an open architectural decision.

---

# 22. Cryptographic Boundary

The architecture maintains the following fundamental boundary:

```text
                    TRUSTED ENDPOINT

Plaintext
    │
    ▼
Encrypt
    │
    ▼
Ciphertext
    │
    ▼
════════════════════════════════════
         UNTRUSTED / LESS TRUSTED
              INFRASTRUCTURE
════════════════════════════════════
    │
    ▼
Messaging / Files / Database
    │
    ▼
Ciphertext
    │
════════════════════════════════════
             TRUSTED ENDPOINT
════════════════════════════════════
    │
    ▼
Decrypt
    │
    ▼
Plaintext
```

Backend services do not receive private communication keys.

---

# 23. Multi-Device Architecture

A logical user may possess multiple devices.

Each device has an independent cryptographic identity.

Conceptually:

```text
User
│
├── Device A → Crypto Identity A
├── Device B → Crypto Identity B
└── Device C → Crypto Identity C
```

The backend may maintain opaque identifiers and public cryptographic material but must not receive private keys.

Device revocation affects future authorization and cryptographic delivery.

A revoked device may retain the ability to decrypt content that was already encrypted for it.

It must not receive newly authorized protected communications after revocation.

---

# 24. Metadata Model

The backend should operate using opaque identifiers rather than human identities.

Hard requirement:

> Backend services must not expose human sender/recipient identity as ordinary service data.

Metadata such as timing, size and frequency is treated as an optimization objective rather than an absolute confidentiality guarantee.

The system should nevertheless investigate:

* padding;
* batching;
* timing strategies;
* encrypted routing metadata;
* traffic-analysis resistance.

Message size should be actively minimized/obscured where practical.

---

# 25. Performance Architecture

The architecture targets:

**10,000 messages/second peak**

as specified by the project, but the benchmark must define:

* message size;
* fan-out;
* persistence guarantee;
* concurrent connections;
* hardware;
* encryption workload;
* acceptable latency;
* acceptable error rate.

Performance measurements should include:

* throughput;
* p50;
* p95;
* p99;
* CPU;
* memory;
* allocations;
* queue depth;
* connection count;
* error rate.

---

# 26. Performance Optimization Policy

SecureCloud follows:

```text
Baseline
   ↓
Benchmark
   ↓
Profile
   ↓
Find bottleneck
   ↓
Optimize
   ↓
Benchmark
   ↓
Compare
```

No low-level optimization is accepted solely because it is theoretically faster.

---

# 27. Post-MVP IPC / Shared Memory Investigation

After the core MVP is operational and measurable, IPC may be investigated.

Possible candidates:

* Unix domain sockets;
* shared-memory ring buffers;
* zero-copy data paths;
* memory pools;
* specialized serialization.

The goal would be to answer experimentally:

> Does replacing network communication with local IPC materially improve the identified bottleneck?

The optimized path must remain optional.

The system must retain a correct network-based distributed path.

Therefore:

```text
Correctness
    │
    ▼
Network architecture
    │
    ▼
Benchmark
    │
    ▼
IPC experiment
    │
    ├── beneficial → optional optimization
    │
    └── not beneficial → remove/reject
```

---

# 28. Testing Architecture

Testing is a first-class architectural concern.

## 28.1 Unit Testing

Every service should test:

* business logic;
* state transitions;
* validation;
* error handling;
* serialization;
* cryptographic integration boundaries.

---

## 28.2 Integration Testing

Validate:

* service + database;
* service + service;
* persistence;
* transaction behaviour;
* recovery.

---

## 28.3 Contract Testing

Service contracts must be validated independently.

A change in one service should detect incompatible consumers before deployment.

---

## 28.4 End-to-End Testing

Critical workflows should be tested from the client boundary.

Examples:

### Message

```text
Client
 → Gateway
 → Messaging
 → persistence
 → recipient
```

### File

```text
Client
 → Gateway
 → Files
 → encrypted storage
 → recipient
```

### Authentication

```text
Client
 → Gateway
 → Auth
 → authenticated session
```

---

# 29. Security Testing

Security tests should verify:

* authentication;
* authorization;
* token revocation;
* device revocation;
* replay resistance;
* input validation;
* service authorization;
* least privilege;
* encrypted storage;
* absence of plaintext in backend storage;
* metadata leakage;
* administrative limitations;
* emergency access boundaries.

A critical invariant should be tested:

> **Compromising Messaging, Files or the database must not automatically provide the capability to decrypt protected message/file content.**

---

# 30. Distributed Failure Testing

The system should explicitly test:

* service crash;
* container restart;
* dependency outage;
* database outage;
* network timeout;
* network partition;
* duplicate request;
* retry storm;
* queue saturation;
* backpressure;
* recovery;
* partial deployment;
* rollback.

The purpose is to verify that failures remain contained rather than becoming system-wide failures.

---

# 31. Performance Testing

Performance testing should include:

### Throughput

```text
messages/sec
```

### Latency

```text
p50
p95
p99
```

### Saturation

Increase load until:

* latency becomes unacceptable;
* queues saturate;
* CPU saturates;
* memory becomes constrained;
* error rate increases.

### Endurance

Run sustained workloads to detect:

* memory leaks;
* resource exhaustion;
* queue growth;
* connection leaks;
* fragmentation.

---

# 32. CI/CD

The deployment pipeline follows the project specification's structure:

```text
Build
  ↓
Test
  ↓
Package
  ↓
Deploy
  ↓
Verify
```

The specification explicitly describes automated build, testing, Docker image packaging, deployment and post-deployment health verification.

Verification should include:

* container health;
* service readiness;
* dependency connectivity;
* smoke tests;
* relevant security checks.

Rollback should be supported.

---

# 33. Docker Compose

Docker Compose is the initial integration/development environment.

Conceptually:

```text
services:

  gateway
  auth
  messaging
  files
  audit
  postgres
```

Each runtime service has:

* its own container;
* its own configuration;
* its own lifecycle;
* explicit network dependencies;
* resource limits where appropriate.

Docker Compose is a deployment topology, not the definition of the service architecture.

---

# 34. Kubernetes Evolution

Kubernetes is a future orchestration environment.

The architecture should remain compatible with:

* multiple replicas;
* service discovery;
* rolling deployment;
* readiness/liveness probes;
* resource limits;
* horizontal scaling;
* node failure;
* workload isolation.

The application should not depend on a particular physical topology.

---

# 35. Observability

Observability should provide enough information to diagnose:

* latency;
* failures;
* queue saturation;
* resource exhaustion;
* service communication;
* deployment problems;
* security-relevant events.

Observability must never become an accidental plaintext leakage channel.

Logs should not contain:

* message plaintext;
* private keys;
* decrypted file contents;
* unnecessary sensitive user information.

---

# 36. Architectural Trade-offs

The selected architecture intentionally accepts:

### Network overhead

In exchange for:

* distribution;
* isolation;
* scalability;
* topology independence.

### Distributed-system complexity

In exchange for:

* failure isolation;
* independent deployment;
* realistic scalability.

### Delayed low-level optimization

In exchange for:

* simpler MVP;
* measurable optimization;
* lower architectural risk.

### Database investigation

In exchange for:

* avoiding premature NoSQL adoption;
* evidence-based persistence decisions.

---

# 37. Academic MVP Boundary

The academic MVP should prioritize:

* five runtime service boundaries;
* network-based communication;
* authentication;
* E2E encrypted messaging;
* encrypted file transfer;
* offline delivery;
* auditing;
* Docker Compose;
* PostgreSQL-based initial persistence where appropriate;
* CI/CD;
* unit/integration/E2E/security tests;
* baseline performance measurements.

The MVP should **not** require:

* shared-memory transport;
* zero-copy transport;
* service mesh;
* Kafka-scale infrastructure;
* multi-region deployment;
* tactical networking;
* sophisticated traffic-analysis resistance;
* full production-scale Kubernetes operations.

---

# 38. Portfolio Roadmap

After the MVP, the architecture can evolve toward:

* IPC/zero-copy experiments;
* advanced metadata protection;
* stronger traffic-analysis resistance;
* advanced group messaging;
* advanced key lifecycle management;
* Kubernetes;
* horizontal scaling;
* stronger resilience;
* advanced observability;
* specialized SQL/NoSQL storage;
* edge/mesh networking;
* disconnected operation;
* satellite/tactical transport integration.

Each capability requires an explicit architectural justification.

---

# 39. Architectural Decisions Required Next

The following ADRs should be created next:

| ADR     | Decision                                     |
| ------- | -------------------------------------------- |
| ADR-001 | Five runtime service architecture            |
| ADR-002 | Runtime vs infrastructure/control plane      |
| ADR-003 | Network-based inter-service communication    |
| ADR-004 | Synchronous RPC vs asynchronous events       |
| ADR-005 | Service-to-service authentication            |
| ADR-006 | Database-per-Service and PostgreSQL strategy |
| ADR-007 | SQL vs NoSQL evaluation                      |
| ADR-008 | Messaging durability model                   |
| ADR-009 | Reliability/failure model                    |
| ADR-010 | Transactional Outbox                         |
| ADR-011 | IPC/shared-memory post-MVP optimization      |
| ADR-012 | Cryptographic identity and key distribution  |
| ADR-013 | End-to-end messaging cryptography            |
| ADR-014 | Multi-device and device revocation           |
| ADR-015 | Metadata-minimizing routing                  |
| ADR-016 | Secure file architecture                     |
| ADR-017 | Performance benchmark methodology            |

---

# 40. Architecture Status

This document represents the **selected baseline architecture**, not the final implementation design.

The most important architectural decisions are now established:

> **SecureCloud is a distributed-first microservices system composed of independently deployable networked services.**

> **Network communication is the correctness baseline.**

> **IPC/shared memory is explicitly deferred until after the MVP and may only be introduced as a measured optimization.**

> **Microservice resilience patterns, explicit data ownership, comprehensive distributed testing, and SQL/NoSQL evaluation are architectural concerns rather than afterthoughts.**

Further architectural detail must be introduced through dedicated ADRs, experiments and benchmarks.
