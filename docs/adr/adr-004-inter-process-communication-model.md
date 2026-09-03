# ADR-004 — Inter-Service Communication Model

**Status:** Approved
**Version:** v0.2
**Date:** 2026-09-02
**Decision Type:** Architecture / Communication

---

## 1. Context

SecureCloud consists of five independently deployable runtime services:

1. Gateway
2. Authentication
3. Messaging
4. Files
5. Audit

As established by ADR-003, these services are logically distributed and communicate through network-accessible service contracts. Physical co-location on the same host during MVP deployment with Docker Compose must not change the communication model.

SecureCloud requires two fundamentally different communication patterns:

* **Synchronous communication** when the caller requires an immediate result before continuing.
* **Asynchronous communication** when the producer reports that something happened and the consumer can process that information independently.

The architecture must therefore define:

* which interactions are synchronous;
* which interactions are asynchronous;
* which network protocols are used;
* serialization formats;
* timeout/deadline behavior;
* retry behavior;
* idempotency;
* error handling;
* asynchronous delivery semantics;
* ordering expectations;
* backpressure.

The project must not introduce a production-grade message broker merely because asynchronous communication exists. However, postponing the definition of the asynchronous model itself would leave a significant architectural decision unresolved.

---

# 2. Decision Drivers

The communication architecture is evaluated against:

1. **Security**

   * encrypted service-to-service communication;
   * explicit service identity;
   * least-privilege authorization;
   * no plaintext message/file data between services;
   * no human identity exposure.

2. **Performance**

   * low latency for request/response operations;
   * efficient binary serialization;
   * high throughput;
   * bounded resource usage.

3. **Reliability**

   * bounded failures;
   * explicit timeouts;
   * safe retries;
   * duplicate handling;
   * durable asynchronous processing.

4. **Distributed-first architecture**

   * communication must work across hosts;
   * localhost/IPC must not be a hidden dependency.

5. **Operational simplicity**

   * appropriate for the three-month MVP;
   * avoid premature infrastructure such as Kafka/RabbitMQ/NATS.

6. **Future scalability**

   * communication contracts must support independent service scaling and eventual migration to stronger distributed infrastructure.

7. **Testability**

   * communication must be testable independently through contract, integration, failure and performance tests.

---

# 3. Considered Alternatives

## A. HTTP/REST for all communication

Use HTTP/REST with JSON for both synchronous requests and asynchronous events.

### Advantages

* simple;
* widely understood;
* easy debugging;
* easy integration with external clients.

### Disadvantages

* JSON adds serialization/deserialization overhead;
* larger payloads;
* weaker interface contracts unless additional tooling is introduced;
* less suitable for high-frequency internal service communication;
* does not naturally distinguish request/response RPC from event communication.

### Decision

**Rejected as the internal communication standard.**

REST/HTTP remains appropriate for the external client-facing API where interoperability and simplicity are valuable.

---

## B. gRPC for all communication

Use gRPC + Protocol Buffers for both synchronous calls and event delivery.

### Advantages

* strongly typed contracts;
* efficient binary serialization;
* HTTP/2 transport;
* deadlines;
* streaming support;
* generated client/server interfaces;
* suitable for internal service communication.

### Disadvantages

* event durability and delivery semantics are not provided automatically;
* long-lived event streaming can introduce unnecessary coupling;
* gRPC itself is not a durable message broker.

### Decision

**Selected for synchronous internal RPC.**

It is not sufficient by itself to define the asynchronous delivery architecture.

---

## C. REST + gRPC + message broker

Use REST externally, gRPC internally, and Kafka/RabbitMQ/NATS for asynchronous events.

### Advantages

* mature asynchronous infrastructure;
* durable queues/events;
* independent producers and consumers;
* strong scalability potential.

### Disadvantages

* introduces another distributed infrastructure component;
* additional operational complexity;
* additional deployment and security surface;
* unnecessary for the initial MVP workload;
* risks premature optimization.

### Decision

**Deferred.**

A broker may be introduced later if benchmarks or operational requirements demonstrate that the MVP event mechanism is insufficient.

---

## D. gRPC + durable database-backed asynchronous events

Use:

* HTTPS/REST for external client communication;
* gRPC/Protobuf for synchronous internal RPC;
* durable database-backed events for asynchronous communication;
* Transactional Outbox for reliable event publication.

### Advantages

* concrete synchronous and asynchronous model;
* no premature broker;
* durable events;
* compatible with independently deployed services;
* straightforward MVP deployment;
* naturally integrates with the service-owned database architecture;
* can later be replaced by a broker without changing the logical event contracts.

### Disadvantages

* database-backed event delivery has lower scalability than a specialized event platform;
* event polling/dispatch introduces additional work;
* requires careful implementation of idempotency and backpressure.

### Decision

**Selected for MVP.**

The detailed transactional outbox mechanism is defined separately in **ADR-008**.

---

# 4. Decision

SecureCloud adopts the following communication architecture:

> **External communication uses HTTPS. Internal synchronous communication uses gRPC with Protocol Buffers. Internal asynchronous communication uses durable application events backed by a transactional outbox during MVP.**

The logical communication model is therefore:

```text
                    ┌───────────────┐
                    │ Qt/C++ Client │
                    └───────┬───────┘
                            │
                     HTTPS / REST
                            │
                            ▼
                    ┌───────────────┐
                    │    Gateway    │
                    └───────┬───────┘
                            │
                  gRPC / Protobuf
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          ┌───────┐    ┌───────────┐   ┌───────┐
          │ Auth  │    │ Messaging │   │ Files │
          └───┬───┘    └─────┬─────┘   └───┬───┘
              │              │             │
              │              │             │
              └──────────────┼─────────────┘
                             │
                     asynchronous events
                             │
                             ▼
                       ┌───────────┐
                       │   Audit   │
                       └───────────┘
```

The diagram represents the **logical communication model**, not necessarily every possible communication path.

---

# 5. Concrete Communication Matrix

The following matrix defines the default communication mode and protocol for every runtime interaction.

| Source    | Destination | Purpose                                          | Mode                        | Protocol / Format |
| --------- | ----------- | ------------------------------------------------ | --------------------------- | ----------------- |
| Client    | Gateway     | Authentication request                           | Synchronous                 | HTTPS + REST/JSON |
| Client    | Gateway     | Send encrypted message                           | Synchronous                 | HTTPS + REST/JSON |
| Client    | Gateway     | Retrieve messages                                | Synchronous                 | HTTPS + REST/JSON |
| Client    | Gateway     | File operations                                  | Synchronous / streaming     | HTTPS             |
| Client    | Gateway     | Device management                                | Synchronous                 | HTTPS + REST/JSON |
| Client    | Gateway     | Emergency operations                             | Synchronous                 | HTTPS + REST/JSON |
| Gateway   | Auth        | Authenticate / validate authorization            | Synchronous                 | gRPC + Protobuf   |
| Gateway   | Messaging   | Send encrypted message                           | Synchronous                 | gRPC + Protobuf   |
| Gateway   | Messaging   | Retrieve / acknowledge delivery                  | Synchronous                 | gRPC + Protobuf   |
| Gateway   | Files       | Upload / download / file metadata                | Synchronous / streaming     | gRPC + Protobuf   |
| Gateway   | Audit       | Gateway security/operational audit               | Asynchronous where possible | Event             |
| Messaging | Auth        | Validate device/user authorization when required | Synchronous                 | gRPC + Protobuf   |
| Files     | Auth        | Validate access authorization when required      | Synchronous                 | gRPC + Protobuf   |
| Messaging | Audit       | Message lifecycle/security events                | Asynchronous                | Event             |
| Files     | Audit       | File lifecycle/security events                   | Asynchronous                | Event             |
| Auth      | Audit       | Authentication/security events                   | Asynchronous                | Event             |
| Gateway   | Audit       | Gateway security/operational events              | Asynchronous                | Event             |

This matrix is normative for the MVP unless a subsequent ADR explicitly changes a particular interaction.

---

# 6. External Client Communication

The client communicates exclusively with the Gateway.

The client must not directly connect to:

* Authentication;
* Messaging;
* Files;
* Audit.

The external API uses:

* **HTTPS**
* **HTTP**
* **REST-style resources**
* **JSON for ordinary control/API messages**
* streaming HTTP mechanisms for large file transfers where appropriate.

The Gateway is therefore the controlled external entry point.

The Gateway must not become a business-logic monolith.

It performs:

* connection handling;
* authentication delegation;
* request routing;
* protocol/version negotiation;
* request validation;
* rate limiting;
* request-size limits;
* backpressure;
* external API policy.

It does not decrypt message or file content.

---

# 7. Internal Synchronous Communication

All runtime service-to-service request/response communication uses:

> **gRPC + Protocol Buffers over HTTP/2**

This is the canonical synchronous internal protocol.

## 7.1 Why gRPC

gRPC provides:

* strongly typed contracts;
* generated client/server interfaces;
* binary Protocol Buffer serialization;
* HTTP/2;
* deadlines;
* streaming;
* explicit status codes;
* efficient internal communication.

This is preferable to JSON/REST for high-frequency internal service communication.

---

# 8. Protocol Buffer Contracts

Every gRPC service exposes an explicit versioned contract.

Contracts define:

* request;
* response;
* fields;
* errors/status;
* service methods;
* compatibility rules.

Example logical contract:

```text
MessagingService
    SendMessage(...)
    GetMessages(...)
    AcknowledgeDelivery(...)
```

The exact `.proto` schemas are implementation artifacts and are not defined by this ADR.

However:

> No service may rely on undocumented RPC behavior.

Contracts must be version controlled and tested.

---

# 9. Synchronous Communication Rules

Every synchronous RPC must have:

* an explicit deadline/timeout;
* bounded request size;
* bounded response size;
* authentication;
* authorization;
* explicit error handling;
* cancellation behavior.

A caller must never wait indefinitely for another service.

### Example

```text
Gateway
   │
   │ SendMessage()
   │ deadline = bounded
   ▼
Messaging
   │
   ├── success → response
   │
   └── timeout/error → explicit failure
```

A timeout does **not** necessarily mean that the server did not process the operation.

Therefore operations that can safely be repeated must use an **idempotency mechanism**.

---

# 10. Retry Policy

Retries are not automatic for every RPC.

The default rule is:

> **Retry only when the operation is known to be safe to retry.**

Retries must use:

* bounded retry count;
* exponential backoff;
* jitter;
* deadline awareness;
* cancellation;
* no infinite retry loops.

For example:

```text
attempt 1
    │
    └── failure
         │
         ▼
       backoff
         │
         ▼
attempt 2
         │
         └── failure
              │
              ▼
            backoff
              │
              ▼
           attempt 3
              │
              ▼
           fail
```

The system must avoid retry storms during service outages.

---

# 11. Idempotency

Operations that may be retried or duplicated must have an explicit idempotency strategy.

This is particularly important for:

* message submission;
* delivery acknowledgement;
* file operations;
* event processing.

For example:

```text
Request
    idempotency_key = X

Messaging
    ├── first X → process
    └── second X → recognize duplicate
```

The exact persistence mechanism for idempotency state belongs to the relevant service architecture and database decisions.

---

# 12. Asynchronous Communication

Asynchronous communication is used when the producer does not require an immediate response from the consumer.

The primary MVP examples are:

* Messaging → Audit;
* Files → Audit;
* Auth → Audit;
* Gateway → Audit.

The conceptual model is:

```text
Service
   │
   │ "Something happened"
   ▼
Event
   │
   ▼
Durable outbox
   │
   ▼
Asynchronous delivery
   │
   ▼
Consumer
```

The producer does not synchronously wait for Audit to finish processing the event.

---

# 13. MVP Asynchronous Transport

SecureCloud will **not require Kafka, RabbitMQ, NATS, or another production message broker for the MVP**.

Instead, asynchronous events will initially use a durable application-level event mechanism based on the service-owned database and **Transactional Outbox**.

The detailed implementation and correctness rules are defined in:

> **ADR-008 — Transactional Outbox**

This allows SecureCloud to have genuine asynchronous semantics without prematurely introducing another infrastructure dependency.

The logical event contract is intentionally independent of the physical transport.

Therefore:

```text
Producer
   │
   │ Event
   ▼
MVP Outbox ──────────────► Consumer
                             
              future:
                 │
                 ▼
           Kafka/NATS/etc.
```

A future broker can replace the MVP transport without changing the fundamental producer/consumer event contract.

---

# 14. Event Design

Events represent facts that have already happened.

Examples:

```text
MessageAccepted
MessageDelivered
MessageDeliveryFailed
FileUploaded
FileDownloaded
AuthenticationSucceeded
AuthenticationFailed
DeviceRevoked
SecurityPolicyViolation
```

Events should contain only the information required by consumers.

They must:

* use opaque identifiers;
* avoid human identity;
* never contain message plaintext;
* never contain file plaintext;
* never contain private cryptographic keys;
* include an event identifier;
* include sufficient information for idempotent processing;
* be versioned.

---

# 15. Event Delivery Semantics

The MVP asynchronous model provides:

> **At-least-once processing semantics.**

Therefore an event may be delivered more than once.

Consumers must be idempotent.

Example:

```text
Event ID: E123

Audit receives E123
    → processes it

Audit receives E123 again
    → recognizes E123
    → does not create a duplicate logical audit record
```

Exactly-once processing is **not required**.

It is generally preferable to provide reliable at-least-once delivery plus idempotent consumers rather than attempt to build an unnecessarily complex exactly-once distributed system.

---

# 16. Event Ordering

SecureCloud does not assume global event ordering.

Ordering must be defined only where the business operation requires it.

Examples:

```text
Device A:
    MessageAccepted(M1)
    MessageAccepted(M2)
```

may require ordering within a specific logical stream.

However, SecureCloud does not require:

```text
M1 globally before M2 globally
```

across all users, devices, services and events.

Any required ordering must therefore be explicitly scoped.

---

# 17. Backpressure

Every communication path must have bounded resources.

This includes:

* connections;
* concurrent RPCs;
* request sizes;
* response sizes;
* event queues;
* pending asynchronous work;
* retries.

When downstream capacity is exhausted, the system must apply backpressure rather than allowing unlimited memory growth.

For example:

```text
Messaging
    │
    ▼
bounded event queue
    │
    ├── capacity available → accept
    │
    └── capacity exhausted
             │
             ▼
       apply backpressure
```

This is particularly important for the 10,000 messages/sec performance target.

---

# 18. Audit Communication Rule

Audit is deliberately asynchronous for normal security and operational events.

For example:

```text
Messaging
    │
    │ message accepted
    ▼
Messaging commits operation
    │
    ▼
Audit event becomes durable
    │
    ▼
Audit processes event
```

Messaging must not normally block the user's message submission waiting for Audit to finish processing.

However, this does **not** mean that an audit event may simply be dropped.

The durability relationship between the business operation and the audit event is defined by **ADR-008**.

Certain security-critical operations may later require synchronous audit confirmation if the threat model demonstrates that requirement. Such exceptions must be explicitly documented rather than introduced implicitly.

---

# 19. Authentication Communication

Authentication decisions required to process a synchronous request use synchronous gRPC.

Example:

```text
Gateway
   │
   │ Validate authorization
   ▼
Auth
   │
   └── authorization result
```

Auth does not provide cryptographic private keys to other services.

Authentication credentials and cryptographic identity remain separate architectural concepts.

The exact service-to-service authentication mechanism is defined by:

> **ADR-010 — Service-to-Service Authentication**

---

# 20. Messaging Communication

Message submission is synchronous from the client's perspective.

```text
Client
   │
   │ encrypted message
   ▼
Gateway
   │
   │ gRPC SendMessage()
   ▼
Messaging
   │
   └── durable acceptance
```

The client receives a response indicating whether Messaging accepted the operation according to the durability contract.

Delivery to the recipient is a separate process.

Therefore:

> **Message submission is synchronous; recipient delivery is asynchronous.**

This distinction is fundamental.

```text
SEND

Client ─────sync────► Messaging
                         │
                         │ durable
                         ▼
                       stored
                         │
                         │ async
                         ▼
                     Recipient
```

---

# 21. File Communication

File operations are synchronous from the client's perspective:

* initiate upload;
* upload encrypted content;
* query file metadata;
* download encrypted content;
* resume transfer.

Large payloads may use streaming rather than loading the entire file into memory.

The Files service receives encrypted content and therefore does not require access to plaintext.

File lifecycle events are asynchronously delivered to Audit.

---

# 22. Gateway Communication Rule

Gateway acts as the boundary between external and internal protocols.

```text
External:
    HTTPS / REST / JSON

Internal:
    gRPC / Protobuf
```

This deliberately prevents the internal service architecture from being tightly coupled to the external API representation.

---

# 23. Service-to-Service Database Access

Services communicate through service contracts, not through databases.

Therefore:

> **No service may directly query another service's database.**

Forbidden:

```text
Messaging ─────SQL────► Auth DB
```

Required:

```text
Messaging ───gRPC────► Auth
```

This preserves service ownership and allows services to change their persistence implementation independently.

---

# 24. Security Requirements

All service-to-service communication must provide:

* encrypted transport;
* authenticated service identity;
* authorization;
* least privilege;
* bounded request/resource usage.

The exact service identity and credential mechanism is defined by ADR-010.

The communication layer must never become a mechanism for bypassing the cryptographic architecture.

In particular:

* Gateway cannot decrypt messages;
* Auth cannot decrypt messages;
* Messaging cannot decrypt messages;
* Files cannot decrypt files;
* Audit cannot decrypt messages;
* no service receives endpoint private keys.

---

# 25. Metadata Minimization

Communication infrastructure must use opaque identifiers.

Services must not require human names or other unnecessary human-identifying information to route internal operations.

Communication metadata such as:

* timestamps;
* request IDs;
* event IDs;
* service IDs;
* latency;
* retry counts;

may be recorded for reliability, debugging and audit purposes according to the metadata policy defined elsewhere.

These identifiers must not silently become human identities.

---

# 26. Observability

Distributed communication must expose enough telemetry to diagnose failures.

At minimum:

* request correlation ID;
* event ID;
* service identity;
* RPC latency;
* RPC success/failure;
* timeout count;
* retry count;
* queue depth;
* event processing latency.

Observability must respect SecureCloud's metadata-minimization requirements.

Correlation identifiers must not contain human-readable identity information.

---

# 27. Failure Model

The communication architecture explicitly assumes:

* service unavailable;
* network interruption;
* timeout;
* connection reset;
* delayed response;
* duplicate request;
* duplicate event;
* consumer unavailable;
* partial service failure;
* temporary overload.

Services must remain correct under these conditions.

A failure in Audit must not automatically make Messaging unavailable.

A failure in Files must not automatically make Messaging unavailable.

A failure in Auth may prevent operations requiring authorization, but must not cause unrelated services to lose their stored data.

---

# 28. Performance Considerations

The architecture is designed around the project's performance objective, including the stated target of approximately 10,000 messages/sec peak.

The internal use of gRPC + Protobuf is intended to reduce serialization and protocol overhead compared with JSON-based internal RPC.

However:

> **The protocol choice itself does not prove the 10,000 messages/sec requirement.**

Performance must be validated experimentally.

Benchmarking must measure:

* end-to-end latency;
* internal RPC latency;
* throughput;
* CPU;
* memory;
* network utilization;
* database latency;
* queue depth;
* retry behavior;
* behavior under overload.

The optimization process remains:

```text
baseline
   ↓
benchmark
   ↓
profile
   ↓
identify bottleneck
   ↓
optimize
   ↓
benchmark again
```

Shared memory, zero-copy and other IPC optimizations remain deferred to ADR-018.

---

# 29. Versioning and Compatibility

All service contracts must be version controlled.

Backward-compatible evolution should be preferred.

A service must not silently deploy an incompatible contract that breaks another service.

Contract compatibility must be validated in CI.

At minimum:

* protobuf schema compatibility;
* API compatibility;
* event schema compatibility;
* consumer compatibility.

---

# 30. Testing

The communication architecture requires:

### Unit tests

* retry policy;
* timeout handling;
* idempotency;
* event serialization;
* backpressure logic.

### Contract tests

Verify that service implementations conform to their gRPC/Protobuf contracts.

### Integration tests

Verify real communication between services.

### Failure tests

Simulate:

* timeout;
* service unavailable;
* connection interruption;
* duplicate request;
* duplicate event;
* overloaded consumer.

### End-to-end tests

Validate:

```text
Client
  → Gateway
  → Auth
  → Messaging
  → durable acceptance
  → asynchronous delivery
  → Audit
```

### Performance tests

Measure the actual throughput and latency of the communication architecture.

---

# 31. MVP Boundary

## Required

* HTTPS for client ↔ Gateway;
* REST/JSON external API;
* gRPC + Protobuf for internal synchronous RPC;
* explicit communication matrix;
* versioned service contracts;
* bounded RPC deadlines;
* safe retry policy;
* idempotency;
* asynchronous event model;
* durable MVP event mechanism;
* at-least-once event processing;
* idempotent event consumers;
* bounded queues/concurrency;
* backpressure;
* contract/integration/failure testing.

## Not required

* Kafka;
* RabbitMQ;
* NATS;
* service mesh;
* global event ordering;
* exactly-once processing;
* event sourcing;
* distributed transactions;
* shared-memory IPC;
* zero-copy inter-service communication.

These may be considered later based on measured requirements.

---

# 32. Consequences

## Positive

* Clear communication architecture;
* developers know which protocol to use;
* synchronous and asynchronous responsibilities are explicit;
* efficient internal communication;
* strongly typed service contracts;
* no premature message broker;
* asynchronous processing remains durable;
* services remain independently deployable;
* architecture can evolve toward a broker later.

## Negative

* two communication models must be implemented;
* gRPC introduces additional tooling and contract management;
* database-backed asynchronous events may eventually become a scalability bottleneck;
* at-least-once delivery requires idempotent consumers;
* the Gateway must translate between external REST and internal gRPC representations.

These costs are accepted because they provide a good balance between architectural correctness and MVP complexity.

---

# 33. Related ADRs

* **ADR-001** — Five Runtime Microservices
* **ADR-002** — Runtime vs Infrastructure Control Plane
* **ADR-003** — Distributed-First Architecture
* **ADR-005** — Database Ownership / Database-per-Service
* **ADR-007** — Messaging Durability Model
* **ADR-008** — Transactional Outbox
* **ADR-009** — Distributed Failure & Resilience Model
* **ADR-010** — Service-to-Service Authentication
* **ADR-017** — Performance Benchmark Methodology
* **ADR-018** — IPC / Shared Memory Optimization

---

# 34. Final Decision Summary

SecureCloud adopts:

> **HTTPS + REST/JSON for external client communication.**

> **gRPC + Protocol Buffers over HTTP/2 for synchronous internal service communication.**

> **Durable application-level events with a Transactional Outbox for asynchronous internal communication during MVP.**

> **At-least-once asynchronous processing with idempotent consumers.**

> **No Kafka, RabbitMQ, NATS, service mesh, shared-memory IPC, or other additional communication infrastructure is required for MVP.**

The communication mode is determined by the operation:

**“I need an answer before continuing.” → synchronous gRPC/RPC.**

**“Something happened and another service can process it independently.” → asynchronous event.**

For SecureCloud specifically:

**Message submission → synchronous.**

**Recipient delivery → asynchronous.**

**Authentication/authorization decision → synchronous.**

**Audit notification → asynchronous.**

**File operation → synchronous.**

**Security/operational audit event → asynchronous.**

This decision establishes the concrete inter-service communication baseline for SecureCloud.
