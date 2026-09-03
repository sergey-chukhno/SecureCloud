# ADR-010 — Performance, Capacity & Optimization Strategy

**Status:** Proposed
**Date:** 2026-09-03
**Decision Scope:** System-wide runtime performance and scalability
**Related ADRs:** ADR-003, ADR-004, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009

---

## 1. Context

SecureCloud targets security-critical communication environments where performance must remain predictable under normal, degraded, and high-load conditions.

The project specification establishes a target of approximately **10,000 messages/second peak throughput** and explicitly requires evidence-based profiling and optimization.

Performance therefore cannot be treated as a final implementation concern. Architectural choices directly affect:

* message throughput;
* end-to-end latency;
* durability latency;
* CPU and memory consumption;
* database pressure;
* network utilization;
* queue growth;
* retry amplification;
* failure recovery;
* horizontal scalability.

The architecture must support the target without weakening the security and durability guarantees defined by the previous ADRs.

In particular:

* accepted messages must satisfy ADR-007 durability semantics;
* encrypted payloads must remain opaque to backend services;
* service boundaries from ADR-001/003 must remain intact;
* service-to-service communication uses gRPC;
* Messaging uses ScyllaDB;
* Audit uses ClickHouse;
* Files uses PostgreSQL + MinIO;
* service failures must be isolated according to ADR-009.

Performance optimization must therefore operate **inside the existing architectural boundaries**, rather than bypassing them.

---

# 2. Decision

SecureCloud adopts the following concrete performance architecture:

1. **The primary scalability unit is the individual runtime service.**
2. **Messaging is the primary throughput-critical service and is designed for horizontal scaling from the beginning.**
3. **Gateway, Messaging, Files and Audit are designed to be horizontally scalable; Auth is designed to scale horizontally while preserving a single logical source of authentication state.**
4. **Services remain stateless wherever their responsibilities do not require durable state.**
5. **No service relies on process-local memory for correctness or durability.**
6. **Messaging persistence is partition-oriented and optimized around recipient/device delivery streams in ScyllaDB.**
7. **Network communication remains the canonical service boundary even when services are colocated.**
8. **Connection reuse, bounded concurrency and streaming are preferred over repeated connection establishment.**
9. **Every performance-sensitive path uses bounded queues and explicit concurrency limits.**
10. **The 10,000 msg/s target is measured using the real durability semantics from ADR-007, not an in-memory benchmark.**
11. **Performance testing uses separate throughput, latency, saturation, endurance and failure-under-load scenarios.**
12. **Profiling precedes low-level optimization.**
13. **Shared memory, zero-copy transport and custom IPC are not part of the baseline architecture.**
14. **If profiling demonstrates that network serialization or copying is a dominant bottleneck, optimization may be introduced behind an unchanged service contract.**
15. **Security, durability and correctness requirements take precedence over raw throughput.**

---

# 3. Performance Objectives

SecureCloud uses four primary performance dimensions.

### 3.1 Throughput

The principal system target is:

> **10,000 accepted messages/second peak system throughput.**

For this target, a message is considered accepted only when the Messaging service has completed the durable acceptance semantics defined by ADR-007.

Therefore:

```text
Client
  ↓
Gateway
  ↓
Messaging
  ↓
ScyllaDB durable write
  +
delivery state
  +
outbox state
  ↓
ACK to client
```

An implementation that processes 10,000 messages/s entirely in memory but cannot durably persist them does **not** satisfy this target.

---

## 3.2 Latency

Throughput alone is insufficient.

Benchmarks MUST report at least:

* p50 latency;
* p95 latency;
* p99 latency;
* maximum observed latency;
* error/timeout rate.

Latency measurements must distinguish:

### Client submission latency

```text
client → Gateway → Messaging → durable persistence → response
```

### Delivery latency

```text
durable acceptance → recipient device ACK
```

### Internal service latency

Individual RPC and persistence operations must also be measurable.

The system must avoid optimizing average latency at the expense of pathological tail latency.

---

# 4. Capacity Model

The architecture assumes that a production deployment may distribute services across multiple hosts.

The logical topology is:

```text
                    ┌──────────────┐
                    │   Clients    │
                    └──────┬───────┘
                           │ HTTPS
                           ▼
                    ┌──────────────┐
                    │   Gateway    │
                    └──────┬───────┘
                           │ gRPC
              ┌────────────┼─────────────┐
              ▼            ▼             ▼
          ┌───────┐   ┌───────────┐  ┌────────┐
          │ Auth  │   │ Messaging │  │ Files  │
          └───────┘   └─────┬─────┘  └────────┘
                             │
                             ▼
                         ScyllaDB

                         ┌───────┐
                         │ Audit │
                         └───────┘
                             │
                             ▼
                         ClickHouse
```

The architecture must permit additional instances of a service without changing its public contract.

Example:

```text
Gateway-1 ─┐
Gateway-2 ─┼──→ Messaging-1
Gateway-3 ─┘       │
                   ├──→ Messaging-2
                   │
                   └──→ Messaging-3
```

Scaling a service must not require scaling unrelated services by the same factor.

---

# 5. Service-Specific Performance Decisions

## 5.1 Gateway

Gateway is designed to be **stateless**.

It MUST NOT maintain correctness-critical session or message state only in process memory.

Gateway performance decisions:

* persistent HTTP connections;
* connection reuse;
* bounded request body sizes;
* bounded concurrent requests;
* bounded outbound gRPC concurrency;
* asynchronous/non-blocking network handling where appropriate;
* streaming for large file transfers;
* minimal request transformation;
* no business persistence;
* no message plaintext processing.

Gateway should perform routing, authentication propagation, policy enforcement and transport handling, but must not become a centralized business-logic bottleneck.

### Scaling

Gateway instances may be added horizontally behind a load balancer.

---

# 6. Messaging Performance Architecture

Messaging is the primary throughput-critical component.

Its design is therefore explicitly optimized for:

* high write throughput;
* predictable key-based reads;
* durable offline queues;
* concurrent delivery;
* horizontal scaling.

## 6.1 Partition-Oriented Storage

Messaging uses ScyllaDB according to ADR-006.

Data access patterns must determine table design.

The primary access patterns are:

```text
submit message
    ↓
message_id

retrieve pending messages
    ↓
recipient_device_id + delivery state

acknowledge delivery
    ↓
message_id + recipient_device_id

retry pending delivery
    ↓
delivery stream / scheduled retry
```

ScyllaDB partition keys must be selected to distribute load rather than concentrating all messages for the entire system into a single partition.

A single global queue is explicitly prohibited.

---

## 6.2 Delivery Queues

Offline delivery queues are durable.

They MUST NOT be implemented as only:

```text
std::queue<Message>
```

or another process-local queue.

In-memory queues may exist as bounded performance buffers, but the durable database state remains authoritative.

Recommended flow:

```text
ScyllaDB
   │
   ▼
bounded in-memory delivery queue
   │
   ▼
recipient connection
```

If the process crashes:

```text
in-memory queue → lost
durable state   → remains
```

The system reconstructs delivery work from durable state.

---

# 7. Concurrency Model

SecureCloud uses **bounded concurrency**.

Unbounded thread creation, unbounded asynchronous tasks and unbounded queues are prohibited.

Each service must define explicit limits for:

* worker concurrency;
* outbound RPC concurrency;
* database connections;
* queue depth;
* request size;
* response size;
* streaming transfers;
* retry concurrency.

A simplified model is:

```text
Incoming requests
       │
       ▼
 bounded queue
       │
       ▼
 worker pool
       │
       ├── database
       ├── RPC
       └── event publication
```

When capacity is exhausted, the service applies explicit backpressure rather than continuing to allocate memory.

---

# 8. Threading Strategy

Services should use a bounded worker/concurrency model rather than one OS thread per request.

The implementation may use:

* thread pools;
* asynchronous I/O;
* event-driven processing;
* coroutine-based concurrency;

provided that the resulting implementation maintains bounded resource usage.

The architecture does **not** mandate a specific C++ concurrency framework.

The selection must be driven by benchmark evidence and maintainability.

However, the following architectural constraint is mandatory:

> Concurrency must be bounded and observable.

---

# 9. gRPC Performance Decisions

Internal communication uses gRPC/Protocol Buffers according to ADR-004.

The following decisions are made:

### Connection reuse

Services MUST reuse long-lived gRPC channels/connections rather than establish a new connection for every RPC.

### Deadlines

Every internal RPC MUST have an explicit deadline.

### Message size limits

Internal RPCs MUST have configured maximum request and response sizes.

### Streaming

Streaming SHOULD be used for:

* large file transfers;
* potentially large batches;
* long-lived delivery streams where appropriate.

Unary RPCs remain preferred for small control-plane operations.

### Serialization

Protocol Buffers remain the canonical wire format.

Replacing them with a custom binary protocol is not justified by architecture alone.

---

# 10. Client Connection Strategy

Gateway should support long-lived client connections where this materially improves delivery latency and reconnect behavior.

For messaging, the preferred model is:

```text
Client
   │
   │ authenticated persistent connection
   ▼
Gateway
   │
   ▼
Messaging
```

The exact client transport mechanism remains an implementation/API decision, but the architecture must support:

* reconnect;
* server-side delivery;
* bounded connection state;
* backpressure;
* offline synchronization.

A disconnected client must never cause unbounded server-side resource consumption.

---

# 11. Database Performance Decisions

Each service uses its database according to ADR-006.

The performance architecture explicitly prohibits cross-service database optimization.

For example:

```text
Messaging ──X──→ Auth PostgreSQL
Messaging ──X──→ Audit ClickHouse
Files    ──X──→ Messaging ScyllaDB
```

If a service needs information owned by another service, it uses the service contract.

This preserves independent scalability.

---

# 12. Database Connection Pooling

Each service must use bounded database connection pools.

The number of connections must be configurable.

Connection pool sizing must be benchmarked rather than maximized.

Increasing connections indefinitely can make performance worse through:

* context switching;
* database contention;
* CPU saturation;
* lock contention;
* memory consumption;
* network congestion.

The target is the smallest pool that sustains required throughput without becoming the bottleneck.

---

# 13. Audit Performance

Audit is deliberately decoupled from the critical message-acceptance path.

According to ADR-007:

```text
Messaging
   │
   ├── durable message state
   │
   └── durable outbox event
              │
              ▼
         Audit publisher
              │
              ▼
          ClickHouse
```

Therefore:

> Audit latency MUST NOT determine whether a message is durably accepted.

Audit processing is asynchronous and independently scalable.

ClickHouse is optimized for append-heavy historical data and analytical queries rather than transactional message processing.

---

# 14. Files Performance

Files are separated into:

```text
File metadata → PostgreSQL
File content  → MinIO
```

Large encrypted file content MUST NOT pass through unnecessary buffering in application memory.

The preferred architecture is streaming:

```text
Client
  │
  │ encrypted stream
  ▼
Gateway
  │
  │ streaming RPC
  ▼
Files
  │
  │ streaming/object upload
  ▼
MinIO
```

The implementation must avoid loading entire files into RAM.

File transfer concurrency and maximum transfer sizes must be bounded.

---

# 15. Memory Management

Memory usage must be bounded for all network-facing services.

The following are architectural requirements:

* no unbounded request buffering;
* no unbounded message queues;
* no entire-file buffering;
* bounded retry queues;
* bounded connection state;
* explicit maximum payload sizes;
* explicit resource exhaustion behavior.

For large payloads, streaming is preferred over accumulation.

Memory pressure must result in controlled backpressure or rejection rather than process instability.

---

# 16. Message Size Protection vs Performance

ADR-008 requires attempts to hide message size through padding.

Padding introduces a deliberate performance/storage/network tradeoff.

Therefore:

* padding policy is configurable;
* benchmark payloads MUST include padded messages;
* benchmarks MUST measure both CPU and network overhead;
* padding MUST NOT be silently disabled for performance benchmarks.

The benchmark must therefore measure:

```text
plaintext size
     ↓
padding
     ↓
encrypted size
     ↓
network transfer
     ↓
storage
```

This ensures that performance claims reflect the actual security configuration.

---

# 17. Cryptographic Performance

Cryptography is part of the real workload.

Benchmarks must not measure only:

```text
receive ciphertext
→ write ciphertext
```

when the actual client performs:

```text
plaintext
→ encryption
→ padding
→ network
→ persistence
```

Client-side benchmarks must include representative:

* encryption;
* decryption;
* session establishment;
* message key derivation;
* multi-device encryption;
* file encryption.

Backend benchmarks must verify that backend services never decrypt message content.

The selected vetted cryptographic library remains the source of cryptographic implementation decisions.

Performance optimization must never replace it with custom cryptography.

---

# 18. Horizontal Scaling

Services must be designed to scale horizontally.

The baseline strategy is:

### Gateway

```text
Gateway × N
```

stateless replicas behind a load balancer.

### Messaging

```text
Messaging × N
```

with workload distributed through ScyllaDB partitioning and service-level concurrency control.

### Files

```text
Files × N
```

with shared durable object storage.

### Audit

```text
Audit × N
```

with durable event consumption and idempotent processing.

### Auth

```text
Auth × N
```

with PostgreSQL as the shared durable authority.

No service may assume that all requests from a user reach the same process.

---

# 19. No Sticky Sessions as a Correctness Requirement

Sticky sessions may be used as an optimization where useful.

They MUST NOT be required for correctness.

For example:

```text
Client
   │
   ├── Gateway-1
   │
   ├── Gateway-2
   │
   └── Gateway-3
```

Any Gateway instance must be able to continue the protocol using durable/shared state and authenticated service contracts.

This is important for failover and Kubernetes evolution.

---

# 20. Caching

Caching is permitted only when correctness does not depend on stale cached data.

Initial caching decisions:

### Allowed candidates

* relatively static configuration;
* service discovery metadata;
* non-security-critical immutable metadata;
* cryptographic public-key material where freshness/revocation semantics are explicitly enforced.

### Not allowed as authoritative state

* message durability;
* delivery state;
* device revocation;
* authentication state;
* authorization decisions whose freshness is security-critical.

A cache must never cause a revoked device to receive future messages.

---

# 21. Backpressure

Backpressure is part of the architecture rather than an optional optimization.

Every major pipeline must have a bounded capacity:

```text
network
  ↓
request queue
  ↓
workers
  ↓
database
```

If downstream capacity decreases:

```text
database slower
      ↓
worker queue grows
      ↓
queue reaches limit
      ↓
request rejected/deferred
```

The system must not respond to downstream slowdown by allocating unlimited memory or workers.

Emergency messages receive higher scheduling priority according to ADR-007, but they remain subject to system-wide safety bounds.

---

# 22. Retry Amplification

Retries are treated as a performance and availability risk.

For an overloaded dependency:

```text
100 requests
   ↓
failure
   ↓
100 retries
   ↓
failure
   ↓
100 retries
```

can become a retry storm.

Therefore retries MUST:

* be bounded;
* use exponential backoff;
* include jitter;
* respect deadlines;
* be limited by operation semantics;
* cooperate with circuit breakers and backpressure.

Retry budgets should be observable.

---

# 23. Performance Isolation

Each service must have independent resource limits.

For containerized deployments this includes, where practical:

* CPU limits/reservations;
* memory limits;
* connection limits;
* worker limits;
* queue limits.

A runaway Audit workload must not consume all resources required by Messaging.

This reinforces the bulkhead model from ADR-009.

---

# 24. Benchmark Architecture

Performance validation uses a dedicated benchmark environment.

The benchmark system must contain:

```text
Load Generator
      │
      ▼
   Gateway
      │
      ▼
  Messaging
      │
      ▼
  ScyllaDB
```

and, for relevant tests:

```text
Messaging
   │
   ▼
Outbox
   │
   ▼
Audit
   │
   ▼
ClickHouse
```

The benchmark environment must use the same major runtime technologies and durability semantics as the target implementation.

---

# 25. Benchmark Workloads

At minimum, the project must define these workloads.

## Workload A — Sustained Throughput

Purpose:

Determine sustainable message throughput.

Measure:

* messages/s;
* p50/p95/p99 submission latency;
* CPU;
* memory;
* ScyllaDB utilization;
* network bandwidth;
* error rate.

---

## Workload B — Peak Throughput

Target:

**10,000 messages/s**

Measure whether the system can sustain the target without violating:

* durability;
* correctness;
* latency budget;
* error budget;
* resource limits.

---

## Workload C — Saturation

Increase load progressively:

```text
1k
2k
4k
6k
8k
10k
12k
...
```

Identify:

* throughput ceiling;
* latency knee;
* CPU saturation;
* database saturation;
* network saturation;
* queue growth.

The goal is not simply to find the largest number before crashing.

The goal is to identify the **operationally safe capacity**.

---

## Workload D — Endurance

Run sustained traffic for an extended period.

Detect:

* memory leaks;
* queue growth;
* connection leaks;
* database compaction effects;
* resource fragmentation;
* latency drift.

---

## Workload E — Failure Under Load

Inject failures while maintaining traffic:

* Messaging restart;
* ScyllaDB node failure;
* Gateway restart;
* Auth unavailable;
* Audit unavailable;
* network delay;
* packet loss;
* connection interruption.

Measure recovery time and whether throughput/latency recover without violating ADR-007 or ADR-009 guarantees.

---

# 26. Benchmark Correctness Rules

A benchmark result is invalid if it changes architectural guarantees to improve numbers.

Examples of invalid optimizations:

* disabling durable persistence;
* disabling the outbox;
* disabling mTLS;
* disabling message padding;
* bypassing Gateway;
* bypassing service boundaries;
* disabling retries;
* removing ACK semantics;
* using plaintext;
* replacing ScyllaDB with memory;
* using a single process instead of distributed services.

Performance claims must correspond to the actual architecture.

---

# 27. Benchmark Environment

Benchmark results must record:

* CPU model;
* number of cores;
* RAM;
* storage type;
* network bandwidth;
* operating system;
* compiler;
* compiler version;
* optimization flags;
* C++ standard/library versions;
* database versions;
* service configuration;
* container/runtime configuration;
* number of service replicas;
* database topology;
* workload parameters.

Without this information, performance results are not considered reproducible.

---

# 28. Profiling Strategy

Optimization follows this sequence:

```text
Measure
   ↓
Benchmark
   ↓
Profile
   ↓
Identify bottleneck
   ↓
Form hypothesis
   ↓
Implement optimization
   ↓
Benchmark again
   ↓
Compare
```

Optimizations must be justified by measurements.

Potential profiling areas include:

* CPU hotspots;
* allocation frequency;
* lock contention;
* context switching;
* network serialization;
* TLS/mTLS overhead;
* Protocol Buffer serialization;
* database latency;
* ScyllaDB partition distribution;
* queue contention;
* cache misses;
* system calls;
* disk I/O;
* memory usage.

---

# 29. Optimization Priority Order

Optimization should proceed from architectural bottlenecks to lower-level details.

Preferred order:

### Level 1 — Architecture

* service topology;
* database access patterns;
* partitioning;
* batching;
* asynchronous processing;
* unnecessary network hops.

### Level 2 — Concurrency

* worker pools;
* queue contention;
* connection pools;
* scheduling;
* lock contention.

### Level 3 — I/O

* network buffering;
* disk I/O;
* database access;
* connection reuse;
* streaming.

### Level 4 — Memory

* allocations;
* copies;
* buffer sizes;
* object lifetimes.

### Level 5 — CPU

* serialization;
* cryptographic overhead;
* parsing;
* compression/padding.

### Level 6 — Low-level optimization

Only after profiling:

* custom allocators;
* lock-free structures;
* zero-copy techniques;
* shared memory;
* specialized data structures;
* CPU-specific optimization.

---

# 30. Zero-Copy and Shared Memory

Shared memory, zero-copy transport and local IPC are explicitly **not baseline architectural requirements**.

They may be investigated only when profiling demonstrates a significant bottleneck attributable to:

```text
serialization
      +
memory copies
      +
local network transport
```

If introduced, the optimization must:

1. preserve the logical service boundary;
2. preserve security isolation;
3. preserve correctness;
4. preserve a network-compatible fallback;
5. be measurable against the baseline.

Therefore:

> No optimization may make correctness dependent on services being colocated.

This preserves ADR-003.

---

# 31. Batching

Batching may be used where it improves throughput without violating latency requirements.

Potential candidates:

* database writes;
* outbox publication;
* audit ingestion;
* delivery scheduling.

Batch size and maximum batching delay must be bounded.

For example:

```text
collect up to N events
OR
wait up to T milliseconds
whichever occurs first
```

This prevents batching from creating unbounded latency.

---

# 32. Message Ordering and Performance

ADR-007 deliberately avoids global message ordering.

This is also a performance decision.

The architecture does not require:

```text
global sequence
     ↓
single serialization point
```

Instead, ordering may be maintained within the smallest required scope, such as a sender/recipient-device stream.

This allows independent partitions and parallel processing.

---

# 33. Multi-Device Performance

A message sent to a user with multiple devices may require multiple encrypted delivery targets.

Therefore:

```text
Message
  ├── Device A ciphertext
  ├── Device B ciphertext
  └── Device C ciphertext
```

must be represented as independent delivery work.

The system must avoid serializing all device deliveries unnecessarily.

Where safe, device-target processing may occur concurrently.

The benchmark workload must include multi-device recipients because single-device benchmarks can significantly underestimate real workload.

---

# 34. Emergency Traffic

Emergency messages receive elevated scheduling priority according to ADR-007.

The implementation must use a bounded priority mechanism.

For example:

```text
Priority queue

Emergency ────────┐
                  ├──→ bounded workers
Normal ───────────┘
```

Emergency traffic must not create an unlimited starvation condition for normal traffic.

The exact scheduling policy must therefore include bounded fairness.

Emergency priority does not bypass:

* durability;
* authentication;
* authorization;
* encryption;
* resource limits;
* retry bounds.

---

# 35. Performance and Security Tradeoff Rule

When a performance optimization conflicts with a security invariant from ADR-008, the security invariant wins.

Examples:

* disabling mTLS → prohibited;
* storing plaintext for faster processing → prohibited;
* bypassing E2E encryption → prohibited;
* keeping revoked-device authorization cached indefinitely → prohibited;
* exposing human identity to improve routing → prohibited.

Performance improvements must occur within the security architecture.

---

# 36. Performance and Durability Tradeoff Rule

When a performance optimization conflicts with ADR-007 durability semantics, durability wins.

For example:

```text
Fast:
write to RAM → ACK
```

is invalid.

The valid model remains:

```text
durable message state
+
required delivery state
+
outbox state
        ↓
      ACK
```

The implementation may optimize how efficiently this is achieved, but may not weaken the acceptance condition.

---

# 37. Operational Capacity

The system must distinguish:

### Maximum measured throughput

The highest throughput observed in a benchmark.

### Sustainable throughput

The throughput that can be maintained without:

* unbounded queue growth;
* increasing latency;
* resource exhaustion;
* unacceptable error rates.

### Target operating capacity

The capacity selected for normal operation with safety headroom.

The operational target should therefore be lower than the absolute saturation point.

The exact production headroom percentage is an implementation/operations configuration and must be established from benchmark results.

---

# 38. Performance Observability

The following metrics are mandatory for performance analysis.

### Gateway

* requests/s;
* request latency;
* active connections;
* rejected requests;
* queue depth;
* outbound RPC latency.

### Messaging

* messages accepted/s;
* messages delivered/s;
* queue depth;
* retry count;
* retry delay;
* durable-write latency;
* ScyllaDB latency;
* delivery latency;
* active delivery streams.

### Files

* bytes/s;
* active transfers;
* transfer latency;
* failed transfers;
* memory usage.

### Auth

* authentication requests/s;
* authentication latency;
* authorization latency;
* database latency.

### Audit

* events/s;
* event processing latency;
* outbox lag;
* ClickHouse ingestion latency.

### System

* CPU;
* memory;
* network;
* disk;
* open connections;
* thread count;
* allocation rate where measurable.

---

# 39. Performance Regression Policy

Performance becomes part of CI/CD quality control.

The project should maintain a baseline benchmark for critical paths.

A change that causes a significant regression must trigger investigation.

The benchmark system should eventually track:

```text
commit
  ↓
benchmark
  ↓
compare against baseline
```

Performance regression thresholds should be introduced after an initial baseline has been established.

The first objective is to establish trustworthy measurements rather than invent arbitrary thresholds without data.

---

# 40. MVP Performance Scope

The MVP MUST implement:

* distributed service architecture;
* network communication;
* bounded concurrency;
* bounded queues;
* connection reuse;
* database connection pooling;
* ScyllaDB partition-aware messaging persistence;
* durable offline queues;
* asynchronous audit processing;
* streaming file transfers;
* horizontal service deployment capability;
* performance instrumentation;
* repeatable benchmark harness;
* sustained throughput benchmark;
* peak throughput benchmark;
* failure-under-load benchmark.

The MVP does NOT require:

* Kubernetes production deployment;
* multi-region deployment;
* service mesh;
* custom kernel networking;
* io_uring-specific implementation;
* custom zero-copy transport;
* shared-memory IPC;
* custom memory allocator;
* lock-free architecture;
* GPU acceleration.

These may be investigated only if measurements justify them.

---

# 41. Performance Invariants

The following invariants are mandatory:

1. **Performance optimization MUST NOT weaken E2E confidentiality.**
2. **Performance optimization MUST NOT weaken message durability.**
3. **Performance optimization MUST NOT make correctness depend on service colocation.**
4. **No accepted message may be silently dropped to maintain throughput.**
5. **No queue may grow without a configured bound.**
6. **No request may consume unbounded memory.**
7. **No service may require another service's database for local correctness.**
8. **No performance benchmark may bypass the real persistence path.**
9. **10,000 msg/s claims must be reproducible and configuration-specific.**
10. **Optimizations must be supported by profiling evidence.**
11. **A failed optimization must be measurable and revertible.**
12. **Tail latency must be considered alongside throughput.**

---

# 42. Decision Summary

| Area                      | Decision                                                  |
| ------------------------- | --------------------------------------------------------- |
| Primary scalability unit  | Individual service                                        |
| Gateway                   | Stateless, horizontally scalable                          |
| Messaging                 | Primary throughput-critical service                       |
| Messaging DB              | ScyllaDB                                                  |
| Messaging scaling         | Horizontal + partition-oriented                           |
| Auth DB                   | PostgreSQL                                                |
| Files metadata            | PostgreSQL                                                |
| File content              | MinIO                                                     |
| Audit DB                  | ClickHouse                                                |
| Internal transport        | gRPC/Protobuf                                             |
| Connections               | Reused/persistent                                         |
| Concurrency               | Bounded                                                   |
| Queues                    | Bounded                                                   |
| Backpressure              | Mandatory                                                 |
| Retries                   | Bounded exponential backoff + jitter                      |
| Large payloads            | Streaming                                                 |
| Global ordering           | Not required                                              |
| Multi-device delivery     | Parallelizable                                            |
| Emergency traffic         | Bounded priority                                          |
| Caching                   | Only where stale data cannot violate correctness/security |
| Shared memory             | Not baseline                                              |
| Zero-copy                 | Post-MVP/profile-driven                                   |
| Custom IPC                | Not baseline                                              |
| Target peak               | ~10,000 msg/s                                             |
| Throughput benchmark      | Real durable acceptance path                              |
| Latency metrics           | p50/p95/p99 + max                                         |
| Failure benchmarks        | Required                                                  |
| Profiling                 | Required before low-level optimization                    |
| Security vs performance   | Security wins                                             |
| Durability vs performance | Durability wins                                           |

---

# 43. Consequences

### Positive

* The architecture has a concrete scaling model.
* Messaging can scale independently.
* Performance testing corresponds to actual system semantics.
* Resource exhaustion becomes predictable rather than emergent.
* Low-level optimizations remain possible without destroying service boundaries.
* The 10k msg/s target becomes measurable and defensible.
* Security and durability cannot accidentally be optimized away.
* The architecture remains compatible with future Kubernetes and distributed deployment.

### Negative

* gRPC, mTLS and database durability introduce measurable overhead.
* Distributed services are more expensive than a monolith.
* Bounded queues may reject work during overload instead of absorbing unlimited traffic.
* Multi-device encryption increases computational and storage cost.
* Message padding increases bandwidth and storage usage.
* Realistic benchmarks are considerably more complex than microbenchmarks.
* ScyllaDB requires careful partition/data-model design.

These costs are accepted because predictable secure operation is more important than maximizing raw benchmark numbers.

---

# 44. Final Architectural Principle

SecureCloud does not optimize for the largest number that a benchmark can produce.

It optimizes for:

> **the highest predictable throughput that preserves confidentiality, durability, correctness and failure isolation.**

The architecture therefore follows:

```text
Correctness
    ↓
Security
    ↓
Durability
    ↓
Predictability
    ↓
Performance
    ↓
Micro-optimization
```

Performance improvements are considered successful only when they improve measured system behavior without violating the guarantees established by ADR-001 through ADR-009.
