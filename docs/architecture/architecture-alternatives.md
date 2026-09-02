# SecureCloud — Architecture Alternatives

**Document status:** v0.2
**Document type:** Architecture Analysis
**Baseline:** Architectural Drivers v0.1, System Context, Trust Boundaries
**Decision status:** Architecture direction selected; detailed implementation decisions remain subject to ADRs and validation.

---

# 1. Purpose

This document evaluates the principal architectural alternatives for SecureCloud and establishes the selected architectural direction.

The analysis considers:

* security and trust boundaries;
* independent service deployment;
* distributed-system requirements;
* performance;
* reliability;
* scalability;
* operational complexity;
* database architecture;
* service communication;
* microservice patterns;
* testing;
* future optimization through IPC/shared memory;
* Docker Compose and future Kubernetes deployment.

The objective is not to select technologies merely because they are modern or theoretically faster.

Architectural decisions must be justified by:

1. requirements;
2. constraints;
3. security analysis;
4. measurable performance;
5. operational consequences;
6. testability;
7. maintainability.

---

# 2. Architectural Context

SecureCloud is a professional secure communications platform intended for sensitive environments.

The architecture must support:

* end-to-end encrypted messaging;
* encrypted file sharing;
* offline delivery;
* multi-device users;
* device revocation;
* group messaging as a future capability;
* metadata minimization;
* emergency communications;
* auditing;
* predictable performance;
* failure isolation;
* automated deployment.

The project specification targets a peak messaging throughput of **10,000 messages/second**, although the precise benchmark conditions remain to be defined.

The specification also identifies C++ microservices, Qt, PostgreSQL, Docker/Docker Compose and CI/CD as core technologies.

---

# 3. Architectural Evaluation Criteria

Alternatives are evaluated against the following criteria.

| Criterion                         |  Importance |
| --------------------------------- | ----------: |
| End-to-end confidentiality        |    Critical |
| Backend plaintext isolation       |    Critical |
| Human-identity confidentiality    |    Critical |
| Service isolation                 |    Critical |
| Failure containment               |    Critical |
| Durable messaging                 |    Critical |
| Distributed deployment capability |        High |
| Horizontal scalability            |        High |
| Predictable performance           |        High |
| 10k msg/s target                  |        High |
| Metadata minimization             |        High |
| Testability                       |        High |
| Operational simplicity            |        High |
| Three-month MVP feasibility       |        High |
| Future optimization               | Medium/High |
| Kubernetes compatibility          | Medium/High |

---

# 4. Alternative A — Modular Monolith

## Description

A single backend process containing logically separated modules:

```text
                    Backend
┌──────────────────────────────────────────────┐
│                                              │
│ Gateway │ Auth │ Messaging │ Files │ Audit   │
│                                              │
└──────────────────────────────────────────────┘
                     │
                 PostgreSQL
```

Modules would have logical boundaries but share one runtime.

## Advantages

* simplest deployment;
* simple local debugging;
* low communication overhead;
* easy transactional operations;
* easier initial development;
* fewer distributed-system failure modes.

## Disadvantages

* weak runtime isolation;
* one process failure can affect all modules;
* independent scaling is difficult;
* service compromise has a larger blast radius;
* does not demonstrate genuine independent service deployment;
* poor fit for the intended distributed architecture;
* future Kubernetes scaling becomes less natural.

## Security assessment

The architecture can provide strong cryptographic security, but process-level isolation is weaker.

A compromise of one module may provide access to resources belonging to other modules.

## Decision

**Rejected.**

The security and distributed-system requirements justify independent service boundaries.

---

# 5. Alternative B — Independent Microservices with Network Communication

## Description

Each service runs as an independent process/container and communicates using network protocols.

```text
                       Qt Client
                           │
                        Network
                           │
                     ┌─────▼─────┐
                     │  Gateway  │
                     └─────┬─────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
           Auth        Messaging        Files
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                         Audit
```

Each service can be independently:

* built;
* tested;
* packaged;
* deployed;
* restarted;
* scaled.

Docker Compose can run all services on one physical host during development while preserving independent service boundaries.

The architecture remains compatible with multi-node deployment.

## Advantages

* clear service isolation;
* natural distributed architecture;
* independent deployment;
* independent scaling;
* failure isolation;
* Kubernetes compatibility;
* explicit network contracts;
* easier service-level security boundaries;
* service discovery can be introduced naturally;
* communication does not depend on physical topology.

## Disadvantages

* network latency;
* serialization/deserialization overhead;
* distributed failure modes;
* more complex testing;
* retries and idempotency become important;
* observability becomes more important;
* distributed transactions must be avoided or carefully designed.

## Security assessment

Strong fit.

Network boundaries reinforce the trust model:

```text
Service A
   │
   │ encrypted/authenticated service communication
   ▼
Service B
```

No service needs to share process memory with another service.

## Decision

**Selected as the baseline architecture.**

---

# 6. Alternative C — Independent Microservices with Local IPC

## Description

Services remain independent processes but communicate using mechanisms such as:

* Unix domain sockets;
* named pipes;
* local IPC mechanisms.

The original project specification explicitly proposed IPC mechanisms such as named pipes/domain sockets.

## Advantages

* lower local communication overhead;
* potentially lower latency;
* reduced networking stack overhead;
* useful for tightly coupled colocated workloads.

## Disadvantages

* topology dependent;
* cannot directly communicate between different hosts;
* complicates Kubernetes scheduling;
* introduces platform-specific mechanisms;
* service communication semantics become dependent on deployment topology;
* makes distributed testing more complicated.

## Decision

**Rejected as the primary communication architecture.**

IPC may be investigated later as an optimization.

---

# 7. Alternative D — Microservices + IPC + Network Fallback

## Description

A service selects IPC when another service is colocated and network communication when it is remote.

Example:

```text
Local:

Messaging ─── IPC ─── Audit


Distributed:

Messaging ─── Network ─── Audit
```

## Advantages

* potentially combines local performance with distributed deployment;
* allows low-level optimization;
* services remain independently deployable.

## Disadvantages

The communication layer becomes significantly more complex.

It must handle:

* local/remote detection;
* transport selection;
* fallback;
* service discovery;
* IPC lifecycle;
* network lifecycle;
* different failure modes;
* multiple transport implementations;
* additional testing.

It also risks making correctness depend on deployment topology.

## Decision

**Rejected as the MVP architecture.**

The potential performance benefit does not justify the additional complexity before a real bottleneck has been demonstrated.

---

# 8. Alternative E — Microservices + Shared Memory

## Description

Services use shared-memory regions or ring buffers for high-throughput local data exchange.

```text
Messaging
     │
     ▼
┌─────────────────────┐
│ Shared-memory ring  │
│      buffer         │
└─────────────────────┘
     ▲
     │
    Audit
```

## Advantages

Potentially excellent local throughput and low copying overhead.

Could become relevant for:

* high-volume event ingestion;
* large data movement;
* zero-copy paths;
* specialized performance-critical workloads.

## Disadvantages

Shared memory introduces coupling around:

* memory layout;
* synchronization;
* ownership;
* lifecycle;
* crash recovery;
* ABI compatibility;
* versioning;
* corruption;
* concurrency.

It is also inherently local to a host.

## Decision

**Deferred.**

Shared memory and zero-copy mechanisms may be investigated **after the core MVP**, only after profiling identifies a meaningful bottleneck.

The architectural drivers already require such optimizations to be evidence-based.

---

# 9. Selected Architecture

SecureCloud will use:

> **Independent networked microservices from day one, with local IPC/shared memory explicitly deferred as an optional post-MVP optimization.**

The architecture must remain correct and fully functional without IPC/shared memory.

This is a fundamental architectural principle.

---

# 10. Deployment Topology Principle

Deployment topology must not define service boundaries.

### Development

```text
                 Docker Compose
┌─────────────────────────────────────┐
│                                     │
│ Gateway     Auth      Messaging     │
│                                     │
│ Files       Audit    PostgreSQL     │
│                                     │
└─────────────────────────────────────┘
```

All services may initially run on one physical machine.

### Kubernetes / distributed environment

```text
             Kubernetes cluster

        ┌──────────┬──────────┬──────────┐
        │ Node A   │ Node B   │ Node C   │
        │          │          │          │
        │ Gateway  │ Messaging│ Files   │
        │ Auth     │ Messaging│ Audit   │
        │          │          │          │
        └──────────┴──────────┴──────────┘
```

The service contracts remain network-based.

A service does not need to know whether its dependency is:

* in the same container;
* on the same host;
* on another node;
* eventually in another infrastructure environment.

---

# 11. Runtime Services

The selected runtime architecture contains five application-facing services:

1. Gateway Service
2. Authentication Service
3. Messaging Service
4. Files Service
5. Audit Service

The original specification lists Deploy Service as one of five microservices.

SecureCloud instead treats deployment as an **infrastructure/control-plane responsibility**, because deployment management should not be part of the trusted runtime communication path.

This architectural deviation should be documented as an ADR.

---

# 12. Service Communication Strategy

The preferred model is hybrid at the **communication semantics** level, not hybrid at the IPC level.

### Synchronous communication

Use synchronous request/response when an immediate answer is required.

Examples:

```text
Gateway → Auth
Gateway → Messaging
Messaging → Files
```

Potential mechanisms include:

* REST;
* gRPC;
* another explicitly selected RPC protocol.

The exact protocol remains an ADR.

### Asynchronous communication

Use asynchronous events when loose coupling is beneficial.

Examples:

```text
Messaging ──► message.accepted ──► Audit
Files ──────► file.uploaded ─────► Audit
Auth ───────► authentication.event ► Audit
```

Events must never contain unnecessary plaintext or sensitive information.

---

# 13. Microservice Patterns

The following patterns are selected as relevant to SecureCloud.

## 13.1 API Gateway

The Gateway provides the controlled external entry point.

Responsibilities include:

* connection termination;
* request routing;
* rate limiting;
* authentication-token handling;
* request validation;
* protection against abusive clients.

It must not decrypt application message content.

---

## 13.2 Database-per-Service

Each service should own its persistent data.

Logical ownership should exist even if multiple databases initially run inside one PostgreSQL deployment.

Example:

```text
PostgreSQL instance
│
├── Auth data
├── Messaging data
├── Files metadata
└── Audit data
```

Services must not directly access another service's tables.

Physical database separation can be introduced later where justified.

---

## 13.3 Bulkhead

Independent resource pools should prevent one workload from exhausting resources needed by another.

Particularly important for:

* emergency messages;
* normal messaging;
* file transfers;
* audit ingestion.

---

## 13.4 Circuit Breaker

Repeated dependency failures should not create cascading failures.

Example:

```text
Messaging
    │
    ▼
  Audit
    │
   DOWN
    │
    ▼
Circuit breaker
    │
    └── prevent repeated failing calls
```

---

## 13.5 Timeout

Every remote call should have explicit timeout behaviour.

No distributed call should be allowed to block indefinitely.

---

## 13.6 Retry with Backoff and Jitter

Retries should be:

* bounded;
* selective;
* idempotency-aware;
* exponentially backed off;
* randomized with jitter.

Retries must not amplify an outage into a retry storm.

---

## 13.7 Idempotency

Operations that may be retried must support duplicate detection where appropriate.

This is particularly important for:

* message submission;
* acknowledgements;
* file operations;
* event processing.

---

## 13.8 Backpressure

Queues and buffers must be bounded.

The system should have explicit behaviour when downstream capacity is exhausted.

This supports predictable performance and protects against resource exhaustion.

---

## 13.9 Transactional Outbox

Where reliable persistence and event publication are both required:

```text
Database transaction
       │
       ├── business state
       │
       └── outbox event
                 │
                 ▼
          event publisher
```

This prevents a state change from succeeding while its corresponding event is silently lost.

---

## 13.10 Health and Readiness Checks

Services should distinguish:

* process alive;
* ready to receive traffic;
* dependencies operational.

---

## 13.11 Graceful Shutdown

Services should stop accepting new work, finish or safely persist in-flight operations, and close resources cleanly.

This is particularly important for durable messaging.

---

## 13.12 Service-to-Service Security

Internal network communication must not automatically be trusted merely because it occurs inside the infrastructure.

The final mechanism remains an ADR, but the architecture should support:

* service authentication;
* authorization;
* authenticated/encrypted transport;
* least privilege.

---

# 14. Patterns Explicitly Deferred or Conditional

The following patterns should not be introduced merely for architectural fashion.

| Pattern                         | Status               |
| ------------------------------- | -------------------- |
| Saga                            | Conditional          |
| CQRS                            | Investigate          |
| Event Sourcing                  | Not required for MVP |
| Service Mesh                    | Future               |
| Distributed Cache               | Investigate          |
| Kafka/RabbitMQ/NATS             | Investigate          |
| Shared Memory                   | Post-MVP             |
| Zero-copy transport             | Post-MVP             |
| Multi-region deployment         | Future               |
| Tactical/mesh edge architecture | Future               |

Each requires a concrete problem and measurable justification.

---

# 15. Database Architecture Alternatives

The database architecture remains an explicit decision area.

### Option A — One PostgreSQL instance, logically separated data ownership

**Initial candidate.**

Advantages:

* simple operations;
* compatible with project specification;
* transactional;
* mature tooling;
* easy Docker Compose deployment.

The database remains physically centralized but logically owned by services.

### Option B — PostgreSQL database per service

Services receive stronger physical isolation.

Advantages:

* stronger service boundaries;
* independent schema lifecycle;
* reduced accidental coupling.

Disadvantages:

* more operational complexity;
* more connections;
* more backup/recovery concerns.

### Option C — SQL + NoSQL polyglot persistence

Different services may use different storage technologies.

Potential examples:

```text
Auth       → relational SQL
Messaging  → SQL / specialized store
Files      → object/file storage + metadata DB
Audit      → SQL / append-oriented NoSQL
```

NoSQL should only be introduced if its characteristics solve a demonstrated workload problem.

### Decision

**No final NoSQL selection is made in v0.2.**

Database architecture will be investigated through workload analysis and benchmarks.

---

# 16. Testing Strategy as an Architectural Requirement

Because SecureCloud is distributed, testing must validate not only individual services but also interactions and failure behaviour.

The architecture therefore anticipates:

### Unit tests

* business logic;
* validation;
* cryptographic wrappers;
* serialization;
* state machines;
* error handling.

### Integration tests

* service/database interaction;
* service-to-service communication;
* persistence;
* transactions;
* recovery.

### Contract tests

Validate that service interfaces remain compatible.

### End-to-end tests

Validate workflows such as:

```text
Client
  ↓
Gateway
  ↓
Auth
  ↓
Messaging
  ↓
encrypted persistence
  ↓
recipient
```

### Security tests

Test:

* authorization;
* authentication;
* replay;
* revoked devices;
* ciphertext-only backend behaviour;
* metadata leakage;
* service isolation;
* privilege escalation.

### Failure tests

Test:

* service crash;
* dependency failure;
* network timeout;
* network partition;
* database failure;
* duplicate request;
* retry;
* queue saturation;
* recovery.

### Performance tests

Measure:

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

The project specification itself identifies unit and integration testing as part of the delivery expectations.

---

# 17. Performance Optimization Strategy

The project shall follow:

```text
Implement
    ↓
Measure
    ↓
Profile
    ↓
Identify bottleneck
    ↓
Form hypothesis
    ↓
Optimize
    ↓
Benchmark again
    ↓
Keep optimization only if beneficial
```

IPC/shared memory must not be implemented simply because it is theoretically faster.

After the MVP, potential experiments include:

* Unix domain sockets;
* shared-memory ring buffers;
* zero-copy;
* memory pooling;
* reduced serialization;
* specialized binary protocols.

Any optimization must preserve:

* security;
* correctness;
* distributed compatibility;
* testability;
* maintainability.

---

# 18. Architectural Decision Summary

| Decision                        | Result                                                                 |
| ------------------------------- | ---------------------------------------------------------------------- |
| Architecture style              | Independent microservices                                              |
| Distribution model              | Distributed-first                                                      |
| Primary inter-service transport | Network                                                                |
| IPC                             | Deferred optimization                                                  |
| Shared memory                   | Deferred optimization                                                  |
| Deployment                      | Docker Compose initially                                               |
| Future orchestration            | Kubernetes-compatible                                                  |
| Runtime services                | Gateway, Auth, Messaging, Files, Audit                                 |
| Deploy                          | Infrastructure/control plane                                           |
| Communication semantics         | Sync RPC + async events where justified                                |
| DB strategy                     | SQL/NoSQL investigation                                                |
| Database ownership              | Database-per-Service principle                                         |
| Reliability                     | Bulkhead, timeout, retry, circuit breaker, idempotency, backpressure   |
| Reliability events              | Transactional Outbox where appropriate                                 |
| Testing                         | Unit + integration + contract + E2E + security + failure + performance |
| Optimization                    | Measurement/profiling first                                            |

---

# 19. Result

The selected architecture provides a strong balance between:

* security;
* distributed-system realism;
* performance;
* reliability;
* testability;
* academic feasibility;
* future scalability.

The architecture deliberately avoids premature low-level optimization while keeping a clear path toward advanced C++ performance work after the core MVP.

**Next step:** formalize the selected architecture in `architecture.md` and create ADRs for the most consequential decisions.
