# Card Validation Report: MSG-001 — Messaging Service Foundation & Concurrency Architecture

**Card ID:** `MSG-001`  
**Card Title:** Messaging Service Foundation  
**Phase:** Phase 2 — Messaging Service Foundation, Persistent Queue Topology & End-to-End Cryptography  
**Repository:** `SecureCloud`  
**Branch:** `feature/msg-001-service-foundation`  
**Status:** VALIDATED & COMPLETE  
**Verification Result:** **100% Passing** across all unit and integration test suites (1,247 / 1,247 tests passing)

---

## Table of Contents

1. [Executive Summary & Strategic Objective](#1-executive-summary--strategic-objective)
   - 1.1 [The Genesis of Phase 2: Card MSG-001's Foundational Role](#11-the-genesis-of-phase-2-card-msg-001s-foundational-role)
   - 1.2 [Zero-Knowledge & End-to-End Encryption Boundary (ADR-008)](#12-zero-knowledge--end-to-end-encryption-boundary-adr-008)
   - 1.3 [Absolute Architectural Invariants & ADR Compliance Matrix](#13-architectural-invariants--adr-compliance-matrix)
2. [Architectural Decisions & Platform Foundations](#2-architectural-decisions--platform-foundations)
   - 2.1 [ADR-003 & ADR-007: Rejection of External Brokers in Favor of ScyllaDB](#21-adr-003--adr-007-rejection-of-external-brokers-in-favor-of-scylladb)
   - 2.2 [ADR-004: Pure gRPC Service-to-Service mTLS Transport](#22-adr-004-pure-grpc-service-to-service-mtls-transport)
   - 2.3 [ADR-008: Zero Plaintext & Zero Private Key Access Invariant](#23-adr-008-zero-plaintext--zero-private-key-access-invariant)
   - 2.4 [ADR-009: Bounded Concurrency & Queue Backpressure Architecture](#24-adr-009-bounded-concurrency--queue-backpressure-architecture)
   - 2.5 [ADR-010: Graceful Drain & Zero-Downtime Rolling Deployments](#25-adr-010-graceful-drain--zero-downtime-rolling-deployments)
3. [Comprehensive Concurrency Architecture: BoundedWorkerPool Deep Dive](#3-comprehensive-concurrency-architecture-boundedworkerpool-deep-dive)
   - 3.1 [The Fundamental Flaws of Unbounded In-Memory Queues](#31-the-fundamental-flaws-of-unbounded-in-memory-queues)
   - 3.2 [Mathematical Formulation of Queue Dynamics: Little's Law & Kingman's Formula](#32-mathematical-formulation-of-queue-dynamics-littles-law--kingmans-formula)
   - 3.3 [Tri-Pool Segregation: Submission, Delivery, and Synchronization Pools](#33-tri-pool-segregation-submission-delivery-and-synchronization-pools)
   - 3.4 [Rejection Policies, Backpressure Mechanisms & Non-Blocking Submissions](#34-rejection-policies-backpressure-mechanisms--non-blocking-submissions)
   - 3.5 [Timed Submissions, Timeout Budgets, and Head-of-Line Blocking Mitigation](#35-timed-submissions-timeout-budgets-and-head-of-line-blocking-mitigation)
   - 3.6 [Thread Synchronization Mechanics: Mutexes, Condition Variables, and Atomic States](#36-thread-synchronization-mechanics-mutexes-condition-variables-and-atomic-states)
   - 3.7 [Graceful Drain Protocol: Two-Phase Shutdown and Zero Task Loss](#37-graceful-drain-protocol-two-phase-shutdown-and-zero-task-loss)
   - 3.8 [Exception Safety, Worker Survival, and RAII Lifecycle Protection](#38-exception-safety-worker-survival-and-raii-lifecycle-protection)
4. [Message Priority & Delivery Scheduling Semantics](#4-message-priority--delivery-scheduling-semantics)
   - 4.1 [The Priority Continuum: NORMAL vs. URGENT vs. EMERGENCY](#41-the-priority-continuum-normal-vs-urgent-vs-emergency)
   - 4.2 [Deep Semantic Comparison: URGENT vs. EMERGENCY](#42-deep-semantic-comparison-urgent-vs-emergency)
   - 4.3 [Concrete Enterprise Scenarios & User-Flagged Alerts for URGENT Priority](#43-concrete-enterprise-scenarios--user-flagged-alerts-for-urgent-priority)
   - 4.4 [Bulkhead Reservation & Emergency Unit Isolation](#44-bulkhead-reservation--emergency-unit-isolation)
5. [Protobuf & gRPC Interface Architecture (MSG-001-T01)](#5-protobuf--grpc-interface-architecture-msg-001-t01)
   - 5.1 [Package Topology & Versioning (`securecloud.messaging.v1`)](#51-package-topology--versioning-securecloudmessagingv1)
   - 5.2 [Message Envelopes & Opaque Encrypted Payloads (`MessageEnvelope`, `EncryptedPayload`)](#52-message-envelopes--opaque-encrypted-payloads-messageenvelope-encryptedpayload)
   - 5.3 [Device-Level Targeting & Dual-State Tracking (`PerDeviceDeliveryTarget`)](#53-device-level-targeting--dual-state-tracking-perdevicedeliverytarget)
   - 5.4 [Complete 12-RPC Interface Declaration & Method Semantics](#54-complete-12-rpc-interface-declaration--method-semantics)
   - 5.5 [CMake Integration & Protobuf Code Generation Pipeline](#55-cmake-integration--protobuf-code-generation-pipeline)
6. [Typed Service Configuration & Persistence Boundaries (MSG-001-T02)](#6-typed-service-configuration--persistence-boundaries-msg-001-t02)
   - 6.1 [Configuration Hierarchy: Common, ScyllaDB, and Worker Concurrency](#61-configuration-hierarchy-common-scylladb-and-worker-concurrency)
   - 6.2 [ScyllaConfig & Cluster Connection Topology](#62-scyllaconfig--cluster-connection-topology)
   - 6.3 [WorkerPoolConfig & Numerical Boundary Constraints](#63-workerpoolconfig--numerical-boundary-constraints)
   - 6.4 [Strict Persistence Isolation: Zero PostgreSQL (Port 5432) Invariant](#64-strict-persistence-isolation-zero-postgresql-port-5432-invariant)
7. [Concurrency Engine Implementation: BoundedWorkerPool (MSG-001-T03)](#7-concurrency-engine-implementation-boundedworkerpool-msg-001-t03)
   - 7.1 [Memory Layout & Thread Coordination Primitives](#71-memory-layout--thread-coordination-primitives)
   - 7.2 [Task Lifecycle: Submission, Enqueueing, Worker Dequeue, Execution](#72-task-lifecycle-submission-enqueueing-worker-dequeue-execution)
   - 7.3 [BoundedWorkerPool Unit Verification Suite](#73-boundedworkerpool-unit-verification-suite)
8. [gRPC Service Implementation: MessagingServiceImpl Skeleton (MSG-001-T04)](#8-grpc-service-implementation-messagingserviceimpl-skeleton-msg-001-t04)
   - 8.1 [RPC Handling Strategy: Deterministic UNIMPLEMENTED Semantics](#81-rpc-handling-strategy-deterministic-unimplemented-semantics)
   - 8.2 [In-Place Correlation ID Extraction (`x-correlation-id` / `x-request-id`)](#82-in-place-correlation-id-extraction-x-correlation-id--x-request-id)
   - 8.3 [Peer Identity Verification via mTLS AuthContext](#83-peer-identity-verification-via-mtls-authcontext)
   - 8.4 [In-Process gRPC Testing & Dependency Injection Verification](#84-in-process-grpc-testing--dependency-injection-verification)
9. [Production Lifecycle, Health Probing & Graceful Drain (MSG-001-T05)](#9-production-lifecycle-health-probing--graceful-drain-msg-001-t05)
   - 9.1 [Executable Entry Point Architecture (`src/messaging/main.cpp`)](#91-executable-entry-point-architecture-srcmessagingmaincpp)
   - 9.2 [Async-Signal-Safe Signal Interception (`SIGINT`, `SIGTERM`)](#92-async-signal-safe-signal-interception-sigint-sigterm)
   - 9.3 [Health & Readiness Probing Topology (`HealthStatusManager` / `HealthServiceImpl`)](#93-health--readiness-probing-topology-healthstatusmanager--healthserviceimpl)
   - 9.4 [Four-Stage Deterministic Graceful Drain Sequence](#94-four-stage-deterministic-graceful-drain-sequence)
10. [Comprehensive Verification & Integration Suite (MSG-001-T06)](#10-comprehensive-verification--integration-suite-msg-001-t06)
    - 10.1 [Live Loopback mTLS Handshake & Ephemeral Port Negotiation](#101-live-loopback-mtls-handshake--ephemeral-port-negotiation)
    - 10.2 [Full 12-RPC End-to-End Over-the-Wire Verification](#102-full-12-rpc-end-to-end-over-the-wire-verification)
    - 10.3 [TLS Handshake Failure & Unauthenticated Caller Rejection](#103-tls-handshake-failure--unauthenticated-caller-rejection)
    - 10.4 [Readiness Transition Dynamics During Shutdown](#104-readiness-transition-dynamics-during-shutdown)
    - 10.5 [Multi-Threaded Task Drain Under Load](#105-multi-threaded-task-drain-under-load)
    - 10.6 [Observational Guard & Architectural Invariant Audit](#106-observational-guard--architectural-invariant-audit)
11. [Architectural Sequence Diagrams](#11-architectural-sequence-diagrams)
    - 11.1 [Diagram 1: Service Initialization, Worker Pool Wiring & mTLS Socket Bind](#111-diagram-1-service-initialization-worker-pool-wiring--mtls-socket-bind)
    - 11.2 [Diagram 2: Gateway-to-Messaging RPC Invocation & Metadata Extraction](#112-diagram-2-gateway-to-messaging-rpc-invocation--metadata-extraction)
    - 11.3 [Diagram 3: Worker Pool Backpressure, Rejection & Timed Submission](#113-diagram-3-worker-pool-backpressure-rejection--timed-submission)
    - 11.4 [Diagram 4: Four-Stage Graceful Drain & Clean Process Termination](#114-diagram-4-four-stage-graceful-drain--clean-process-termination)
12. [Traceability Matrix against Acceptance Criteria](#12-traceability-matrix-against-acceptance-criteria)
13. [Empirical Verification Evidence & Full Test Run Artifacts](#13-empirical-verification-evidence--full-test-run-artifacts)
    - 13.1 [Unit Test Execution Evidence (`securecloud_messaging_config_test`)](#131-unit-test-execution-evidence-securecloud_messaging_config_test)
    - 13.2 [Concurrency Test Execution Evidence (`securecloud_bounded_worker_pool_test`)](#132-concurrency-test-execution-evidence-securecloud_bounded_worker_pool_test)
    - 13.3 [Contract Test Execution Evidence (`securecloud_proto_smoke_test`)](#133-contract-test-execution-evidence-securecloud_proto_smoke_test)
    - 13.4 [Service Handler Execution Evidence (`securecloud_messaging_service_test`)](#134-service-handler-execution-evidence-securecloud_messaging_service_test)
    - 13.5 [Lifecycle Integration Execution Evidence (`securecloud_messaging_service_lifecycle_integration_test`)](#135-lifecycle-integration-execution-evidence-securecloud_messaging_service_lifecycle_integration_test)
    - 13.6 [Full Repository Regression Suite Execution Evidence (1,247 Tests Passed)](#136-full-repository-regression-suite-execution-evidence-1247-tests-passed)
    - 13.7 [Static Analysis & Code Formatting Verification](#137-static-analysis--code-formatting-verification)
14. [Conclusion & Readiness for Card MSG-002](#14-conclusion--readiness-for-card-msg-002)

---

## 1. Executive Summary & Strategic Objective

### 1.1 The Genesis of Phase 2: Card MSG-001's Foundational Role
With Phase 1 (Perimeter Gateway and Authoritative Identity Service) fully validated, hardened, and merged into `main`, SecureCloud transitions to Phase 2: the asynchronous, zero-knowledge, end-to-end encrypted messaging engine.

Card `MSG-001` serves as the bedrock foundation for all downstream messaging cards (`MSG-002` through `MSG-012`). In software architecture, the foundation defines the boundary conditions, concurrency primitives, operational contracts, and security topology under which all subsequent business logic operates. If the runtime foundation is compromised by unbounded queues, insecure communication protocols, or leaky abstractions, the entire service degrades under enterprise load.

Card `MSG-001` accomplishes four architectural objectives:
1. **Contract Formalization**: Establishes the authoritative Protobuf 3 and gRPC v1 service schema (`proto/securecloud/messaging/v1/messaging.proto`) specifying 12 RPC methods, 3 priority classes, device-targeted payloads, and synchronization cursors.
2. **Persistence Boundary Isolation**: Establishes typed configuration for ScyllaDB (port 9042) while rigorously enforcing the architectural invariant of zero PostgreSQL (port 5432) dependencies.
3. **Resilient Concurrency Infrastructure**: Implements a dedicated, lock-free/mutex-bounded thread pool engine (**`BoundedWorkerPool`**) designed to enforce queue backpressure, prevent Out-Of-Memory (OOM) crashes, and guarantee zero task loss during rolling deployments.
4. **End-to-End mTLS Runtime**: Configures the C++20 service executable (`securecloud-messaging`) with mutual TLS authentication, dual-state health probing (Liveness vs. Readiness), and a deterministic 4-stage graceful drain shutdown sequence.

### 1.2 Zero-Knowledge & End-to-End Encryption Boundary (ADR-008)
SecureCloud operates on a non-negotiable security invariant:
$$\text{Messaging Service Plaintext Access} = \emptyset$$
$$\text{Messaging Service Private Key Access} = \emptyset$$

In accordance with **ADR-008**, the Messaging backend operates strictly as a blind, zero-knowledge routing and synchronization engine. Message payloads are transported across the perimeter and stored in the database exclusively as opaque binary ciphertext blobs (`bytes ciphertext_blob`). Ephemeral public keys, initialization vectors, and authentication tags are bundled alongside the ciphertext, but the backend possesses neither the mathematical ability nor the architectural privilege to decrypt payloads.

Furthermore, message envelope routing is performed using opaque UUID identifiers for conversations, users, and devices. The backend does not inspect, parse, or evaluate user content.

### 1.3 Absolute Architectural Invariants & ADR Compliance Matrix

| Architecture Decision Record | Core Requirement | MSG-001 Implementation & Enforcement |
|:---|:---|:---|
| **ADR-001** | Strict C++20 Standard & Modern Tooling | Built with Clang/GCC on C++20 with `-Wall -Wextra -Werror -Wpedantic`, concepts, and RAII. |
| **ADR-002** | CMake Multi-Preset Configuration | Integrated into CMake build system with presets (`dev-debug`, `dev-release`, `ci-macos`). |
| **ADR-003** | Service-to-Database Isolation | Messaging service binds exclusively to ScyllaDB (port 9042). Port 5432 is strictly forbidden. |
| **ADR-004** | Pure gRPC & mTLS Inter-Service Comms | Inter-service traffic runs strictly over HTTP/2 gRPC with mutual TLS and SAN verification. |
| **ADR-007** | No External Message Brokers | No Kafka, RabbitMQ, or NATS. All queues and delivery tracking are handled natively. |
| **ADR-008** | Zero Plaintext & Zero Private Keys | Message payloads are typed as opaque `bytes`. Backend has zero key exposure. |
| **ADR-009** | Bounded Concurrency & Backpressure | All asynchronous execution is bounded via `BoundedWorkerPool`. Unbounded queues are forbidden. |
| **ADR-010** | Graceful Drain & Zero-Downtime Deployments | SIGTERM triggers readiness degradation, gRPC drain deadline, and worker task completion. |

---

## 2. Architectural Decisions & Platform Foundations

### 2.1 ADR-003 & ADR-007: Rejection of External Brokers in Favor of ScyllaDB
Enterprise messaging systems frequently rely on distributed message brokers such as Apache Kafka, RabbitMQ, or NATS. In SecureCloud, **ADR-007** explicitly and deliberately rejects external brokers in favor of ScyllaDB (a C++ implementation of Apache Cassandra):

```
                        ┌────────────────────────────────────────────────────────┐
                        │             REJECTED ARCHITECTURE (ADR-007)            │
                        │                                                        │
                        │  Gateway ───► Messaging Service ───► Apache Kafka      │
                        │                                            │           │
                        │                                            ▼           │
                        │  Storage Engine ◄── Consumer Group ◄── Zookeeper / KRaft│
                        └────────────────────────────────────────────────────────┘

                        ┌────────────────────────────────────────────────────────┐
                        │             APPROVED ARCHITECTURE (ADR-007)            │
                        │                                                        │
                        │  Gateway ───► Messaging Service ───► ScyllaDB Cluster  │
                        │               (BoundedWorkerPool)    (LWT / Partitions)│
                        │               (Zero External Broker) (CQL Port 9042)   │
                        └────────────────────────────────────────────────────────┘
```

The rationale for this architecture is multifaceted:
1. **Operational Surface Minimization**: Operating Kafka or RabbitMQ introduces an entirely separate distributed consensus cluster (ZooKeeper/KRaft), JVM memory overhead, partition rebalancing latency, and bespoke security audit requirements.
2. **Zero-Knowledge Multi-Device Sync**: Messaging in SecureCloud requires multi-device synchronization where offline devices pull historical messages upon reconnection. Kafka's log retention and offset tracking model is fundamentally mismatched with per-device cursor synchronization across millions of mobile endpoints.
3. **Storage-Tier Unified Latency**: ScyllaDB provides sub-millisecond p99 write latency using a thread-per-core, lockless architecture written in modern C++. Storing message queues directly as time-series partition rows in ScyllaDB unifies immediate queue delivery and long-term offline device synchronization into a single, highly partitionable data layer.

### 2.2 ADR-004: Pure gRPC Service-to-Service mTLS Transport
In conformance with **ADR-004**, all inter-service communications between Gateway, Auth, Files, and Messaging occur strictly over gRPC backed by HTTP/2 and mTLS:
- Every service presents an X.509 certificate signed by the internal development or production Certificate Authority (`deploy/dev-pki/ca/ca.crt`).
- Inbound connections are verified using `GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`.
- Peer identities are evaluated exclusively via Subject Alternative Name (SAN) DNS entries (`DNS:gateway`, `DNS:auth`, `DNS:messaging`, `DNS:files`). Common Name (CN) fallback is explicitly forbidden and disabled.

### 2.3 ADR-008: Zero Plaintext & Zero Private Key Access Invariant
Under **ADR-008**, the Messaging service acts as a zero-knowledge conduit:
- Payloads are submitted by clients as pre-encrypted ciphertext blocks using Signal-protocol-style Double Ratchet or sender keys.
- The `EncryptedPayload` message carries:
  - `ciphertext_blob`: Opaque bytes of ciphertext.
  - `ephemeral_public_key`: Client's Curve25519 ephemeral key used for ratchet derivation.
  - `initialization_vector`: 12-byte or 16-byte nonce.
  - `auth_tag`: Poly1305 or AES-GCM authentication tag.
  - `algorithm`: Standard cryptographic suite indicator (e.g., `xchacha20poly1305`).
- The backend never parses or stores plaintext content, and backend logs strictly scrub or omit ciphertext payloads, logging only metadata, correlation IDs, and UUID routing identifiers.

### 2.4 ADR-009: Bounded Concurrency & Queue Backpressure Architecture
Unbounded thread generation or unbounded task queues represent a primary vector for catastrophic service failure under load. **ADR-009** mandates that all concurrency in the Messaging service must be strictly bounded.

In Card `MSG-001`, this is realized through the `BoundedWorkerPool` engine:
- Each functional pipeline has a fixed number of worker threads.
- Each queue has a strictly enforced hard capacity limit (`max_queue_capacity`).
- When the queue is full, the system exerts immediate backpressure via non-blocking submission rejection (`try_submit() -> false`) or bounded timeout waits (`submit_with_timeout()`).

### 2.5 ADR-010: Graceful Drain & Zero-Downtime Rolling Deployments
In modern containerized deployments (Kubernetes, ECS), pods receive `SIGTERM` when being replaced during rolling upgrades. A naive service abruptly severs active TCP streams and drops in-flight transactions.

**ADR-010** mandates a deterministic 4-stage graceful drain protocol:
1. Signal Interception: Async-signal-safe capture of `SIGINT` or `SIGTERM`.
2. Readiness Degradation: Mark readiness health probe as `NOT_SERVING` while keeping liveness `SERVING`. Load balancers immediately cease routing new traffic to the container.
3. gRPC Server Drain: Allow currently in-flight gRPC streams to finish within a bounded timeout deadline (`server->Shutdown(deadline)`).
4. Worker Pool Drain: Bounded worker pools complete all queued tasks (`drain_and_stop()`) before shutting down and joining worker threads.

---

## 3. Comprehensive Concurrency Architecture: BoundedWorkerPool Deep Dive

### 3.1 The Fundamental Flaws of Unbounded In-Memory Queues
A widespread anti-pattern in concurrent server design is the reliance on unbounded in-memory queues (such as `std::queue<Task>` guarded by a mutex without a maximum capacity check). While deceptively simple during low-traffic testing, unbounded queues exhibit fatal failure modes in production:

1. **Unbounded Latency Accumulation (Bufferbloat)**: When the inbound arrival rate $\lambda$ exceeds the processing service rate $\mu$, the queue length $L_q$ grows monotonically toward infinity. A task enqueued during a traffic spike may wait minutes before execution, long after the calling client has timed out and abandoned the HTTP/gRPC request. The server consumes CPU cycles executing stale, useless work.
2. **Memory Exhaustion & Catastrophic OOM Panic**: Each queued task allocates heap memory for closures, captured parameters, and buffers. Under sustained load, heap usage grows until the Linux Out-Of-Memory killer abruptly terminates the process, dropping all in-flight work indiscriminately.
3. **Loss of Backpressure Signal**: Without queue limits, upstream callers (the API Gateway and clients) have no visibility into downstream saturation. The system accepts requests it cannot process until it collapses.

### 3.2 Mathematical Formulation of Queue Dynamics: Little's Law & Kingman's Formula
The behavior of the `BoundedWorkerPool` is rooted in classical queueing theory:

#### Little's Law
$$L = \lambda W$$
Where:
- $L$ is the average number of tasks in the system (queue + active workers).
- $\lambda$ is the average task arrival rate (requests per second).
- $W$ is the average total time a task spends in the system (wait time + execution time).

If $L$ is allowed to grow without bound while the service capacity $\mu = c \cdot \mu_{\text{thread}}$ remains constant, the latency $W$ approaches infinity:
$$\lim_{L \to \infty} W = \infty$$

By establishing an absolute upper bound $L_{\text{max}} = K + N$ (where $K$ is the maximum queue depth and $N$ is the thread count), `BoundedWorkerPool` guarantees an upper bound on worst-case task latency:
$$W_{\text{worst-case}} \le \frac{K}{\mu} + T_{\text{max\_task\_exec}}$$

#### Kingman's Formula for Queue Wait Time
In an $M/G/c$ or $G/G/c$ system near saturation (where utilization $\rho = \frac{\lambda}{c \mu} \to 1$), the expected waiting time in queue $W_q$ is given by:
$$W_q \approx \left(\frac{\rho}{1 - \rho}\right) \left(\frac{C_a^2 + C_s^2}{2}\right) \frac{1}{\mu}$$
Where $C_a$ and $C_s$ are the coefficients of variation for arrival and service times. As utilization $\rho$ approaches 1, the factor $\frac{\rho}{1 - \rho}$ diverges.

`BoundedWorkerPool` prevents this divergence by truncating the state space. Once queue length hits $K$, excess arrivals are rejected immediately, forcing the effective arrival rate $\lambda_{\text{effective}} \le \mu$ and keeping the system fundamentally stable.

### 3.3 Tri-Pool Segregation: Submission, Delivery, and Synchronization Pools
A single shared worker pool across distinct operational workloads creates resource starvation: a deluge of heavy device synchronization queries could consume all worker threads, starving real-time message submissions.

To achieve strict bulkhead isolation, Card `MSG-001` segregates messaging concurrency into three specialized, independently configured bounded worker pools:

```
┌────────────────────────────────────────────────────────────────────────┐
│               TRI-POOL BULKHEAD ARCHITECTURE (MSG-001)                 │
├────────────────────────┬───────────────────────┬───────────────────────┤
│    SUBMISSION POOL     │     DELIVERY POOL     │      SYNC POOL        │
├────────────────────────┼───────────────────────┼───────────────────────┤
│ Inbound message intake │ Recipient dispatch    │ Multi-device catch-up │
│ Idempotency validation │ Push notification fwd │ Historical cursors    │
│ Envelope verification  │ Delivery ACK tracking │ Bulk sync paging      │
├────────────────────────┼───────────────────────┼───────────────────────┤
│ Workers: [1..128]      │ Workers: [1..256]     │ Workers: [1..128]     │
│ Default: 8 threads     │ Default: 16 threads   │ Default: 8 threads    │
│ Queue: [16..65536]     │ Queue: [16..65536]    │ Queue: [16..65536]    │
│ Default: 1024 capacity │ Default: 4096 capacity│ Default: 1024 capacity│
└────────────────────────┴───────────────────────┴───────────────────────┘
```

1. **Submission Worker Pool (`submission_pool_`)**:
   - Handles client message ingress (`SendMessage`).
   - Validates envelope integrity, verifies cryptographic signatures, and generates server-side sequence numbers.
   - Requires rapid, deterministic execution to provide sub-10ms ingress acknowledgment to sending clients.
2. **Delivery Worker Pool (`delivery_pool_`)**:
   - Handles asynchronous routing to online recipients (`AcknowledgeDelivery`, Push Notifications).
   - Higher thread allocation (default 16 threads, 4,096 queue capacity) to handle the 1-to-N fan-out required for group conversations.
3. **Synchronization Worker Pool (`sync_pool_`)**:
   - Handles multi-device synchronization queries (`SyncDeviceMessages`, `GetSyncCursor`, `UpdateSyncCursor`).
   - Dedicated bounds ensure heavy paging requests from reconnecting devices never interfere with active message transmission.

### 3.4 Rejection Policies, Backpressure Mechanisms & Non-Blocking Submissions
`BoundedWorkerPool::try_submit` provides lock-contention-minimized, non-blocking task submission:

```cpp
bool BoundedWorkerPool::try_submit(std::function<void()> task) {
    if (!task) {
        return false;
    }

    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (state_ != State::Running) {
            return false;
        }
        if (tasks_.size() >= max_queue_capacity_) {
            return false; // Queue full: immediate backpressure signal
        }
        tasks_.push(std::move(task));
    }

    cv_task_available_.notify_one();
    return true;
}
```

#### The Backpressure Contract
When `try_submit()` returns `false`:
- If `state_ != State::Running`: The pool is shutting down. The caller knows the system is terminating and immediately returns `UNAVAILABLE` to the caller.
- If `tasks_.size() >= max_queue_capacity_`: The pool is saturated. The caller immediately returns `RESOURCE_EXHAUSTED` (HTTP 429 / HTTP 503) to the upstream Gateway with a `Retry-After` header. No memory is allocated, no latency is accumulated, and the caller is informed instantly.

### 3.5 Timed Submissions, Timeout Budgets, and Head-of-Line Blocking Mitigation
In situations where an ingress RPC possesses an allotted deadline budget (e.g., a Gateway deadline of 250ms), dropping the request immediately upon momentary saturation may be overly aggressive.

`BoundedWorkerPool::submit_with_timeout` allows callers to block waiting for queue capacity up to a caller-specified deadline:

```cpp
bool BoundedWorkerPool::submit_with_timeout(std::function<void()> task, std::chrono::milliseconds timeout) {
    if (!task) {
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    // Wait until queue space is available or pool stops running
    const bool space_available = cv_space_available_.wait_until(lock, deadline, [this]() {
        return state_ != State::Running || tasks_.size() < max_queue_capacity_;
    });

    if (!space_available || state_ != State::Running || tasks_.size() >= max_queue_capacity_) {
        return false; // Timed out or shutting down
    }

    tasks_.push(std::move(task));
    lock.unlock();

    cv_task_available_.notify_one();
    return true;
}
```

This dual-condition synchronization ensures that:
- Callers absorb brief sub-millisecond traffic spikes without dropping requests.
- If the downstream workers remain saturated beyond the timeout budget, the wait expires deterministically without causing head-of-line blocking across the server.

### 3.6 Thread Synchronization Mechanics: Mutexes, Condition Variables, and Atomic States
The concurrency control within `BoundedWorkerPool` utilizes a dual condition-variable design:
1. `cv_task_available_`: Notifies idle worker threads that work has arrived in the queue.
2. `cv_space_available_`: Notifies enqueuing threads that a worker has popped a task, freeing a queue slot.
3. `cv_drained_`: Notifies the shutdown coordinator that the queue depth has reached zero and all active workers have finished.

#### Worker Thread Loop
```cpp
void BoundedWorkerPool::worker_loop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);

            // Wait for a task or a state change
            cv_task_available_.wait(lock, [this]() {
                if (state_ == State::Shutdown) {
                    return true;
                }
                if (state_ == State::Draining && tasks_.empty()) {
                    return true;
                }
                return !tasks_.empty();
            });

            // Termination condition
            if (state_ == State::Shutdown && tasks_.empty()) {
                break;
            }
            if (state_ == State::Draining && tasks_.empty()) {
                break;
            }

            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
                active_workers_++;
                cv_space_available_.notify_one(); // Signal queue space available
            }
        }

        if (task) {
            try {
                task();
            } catch (const std::exception& ex) {
                std::cerr << "[ERROR] [messaging::pool:" << name_ << "] Worker task exception: "
                          << ex.what() << "\n";
            } catch (...) {
                std::cerr << "[ERROR] [messaging::pool:" << name_ << "] Unknown worker task exception\n";
            }

            {
                std::unique_lock<std::mutex> lock(mutex_);
                active_workers_--;
                if ((state_ == State::Draining || state_ == State::Shutdown) &&
                    tasks_.empty() && active_workers_ == 0) {
                    cv_drained_.notify_all(); // Signal complete drain
                }
            }
        }
    }
}
```

### 3.7 Graceful Drain Protocol: Two-Phase Shutdown and Zero Task Loss
When `drain_and_stop()` is invoked:
1. **Phase 1: Ingress Closure**: The internal state transitions to `State::Draining`. Subsequent calls to `try_submit()` or `submit_with_timeout()` are rejected immediately.
2. **Phase 2: Queue Evacuation**: All previously queued tasks remain in the queue. Worker threads continue popping and executing tasks until `tasks_.empty()` is achieved.
3. **Phase 3: Worker Convergence**: Active workers decrement `active_workers_`. The last worker to finish fires `cv_drained_.notify_all()`.
4. **Phase 4: Thread Join**: The coordinator thread waiting on `cv_drained_` wakes up, signals workers to terminate, and joins all `std::thread` instances via `thread.join()`.

This protocol guarantees that **zero accepted tasks are lost or dropped** during process shutdown.

### 3.8 Exception Safety, Worker Survival, and RAII Lifecycle Protection
A common failure in custom thread pool implementations is worker death caused by unhandled exceptions escaping user tasks. If a task throws an uncaught exception, the thread terminates; if all threads throw, the pool silently becomes a dead zombie holding an unresponsive queue.

`BoundedWorkerPool` implements strict exception isolation:
- User task execution is enclosed in `try ... catch (const std::exception& ex) ... catch (...)`.
- Any exception thrown by a user task is caught, logged with pool identity, and neutralized.
- The worker thread decrements `active_workers_` and returns cleanly to the dequeue loop, preserving 100% of thread capacity for subsequent tasks.

---

## 4. Message Priority & Delivery Scheduling Semantics

### 4.1 The Priority Continuum: NORMAL vs. URGENT vs. EMERGENCY
`proto/securecloud/messaging/v1/messaging.proto` formalizes three discrete message priority classes:

```protobuf
enum MessagePriority {
  MESSAGE_PRIORITY_UNSPECIFIED = 0;
  MESSAGE_PRIORITY_NORMAL = 1;
  MESSAGE_PRIORITY_URGENT = 2;
  MESSAGE_PRIORITY_EMERGENCY = 3;
}
```

Each priority class maps to specific scheduling behaviors, queue lease reservations, push notification channels, and client-side presentation paradigms:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      MESSAGE PRIORITY CLASSIFICATION MATRIX                      │
├─────────────────┬───────────────────┬───────────────────┬────────────────────────┤
│ Priority Class  │ Target Audience   │ Bulkhead Quota    │ Client Notification    │
├─────────────────┼───────────────────┼───────────────────┼────────────────────────┤
│ NORMAL (1)      │ General Users     │ General Queue     │ Standard push, quiet   │
├─────────────────┼───────────────────┼───────────────────┼────────────────────────┤
│ URGENT (2)      │ General Users     │ Expedited Queue   │ High APNs/FCM priority,│
│                 │ (Time-sensitive)  │ (No starvation)   │ Amber alert banner     │
├─────────────────┼───────────────────┼───────────────────┼────────────────────────┤
│ EMERGENCY (3)   │ Emergency Unit /  │ Isolated Bulkhead │ Critical Alert bypass, │
│                 │ Crisis Responders │ (10 leases saved) │ Red flashing banner    │
└─────────────────┴───────────────────┴───────────────────┴────────────────────────┘
```

### 4.2 Deep Semantic Comparison: URGENT vs. EMERGENCY

| Dimension | `MESSAGE_PRIORITY_URGENT` | `MESSAGE_PRIORITY_EMERGENCY` |
|:---|:---|:---|
| **Primary Actors** | Regular end-users, team leads, on-call engineers, security liaisons. | Dedicated Emergency Operations Center (EOC), crisis responders, first responders. |
| **System Isolation** | Competes within general message worker queues with expedited scheduling priority. | Dispatched through an **isolated Gateway bulkhead** reserving 10 dedicated connection leases. |
| **Push Notification Priority** | Apple APNs Priority 10 / Google FCM High Priority (bypasses device battery optimizations). | **Apple Critical Alert entitlement** (bypasses hardware mute switch and Do Not Disturb). |
| **Client UI Presentation** | Prominent amber border, persistent unread banner, distinct audio chime. | Full-screen flashing red modal, continuous override alarm tone, biometric acknowledgment. |
| **Audit Requirement** | Standard audit event logging. | High-fidelity tamper-evident audit logging with mandatory geographic/cellular telemetry. |

### 4.3 Concrete Enterprise Scenarios & User-Flagged Alerts for URGENT Priority
`MESSAGE_PRIORITY_URGENT` is designated for critical, time-sensitive communications between regular users where delays could compromise operational integrity or security:

1. **Active Security Incident Alerts & P1 Escalations**:
   - *Scenario*: A security analyst discovers an active credential compromise on a corporate account and sends an immediate lockdown alert to the affected user.
   - *Behavior*: Sent as `URGENT`. The client device sounds a high-priority chime and flags the message with an amber priority badge.
2. **Production Outage Escalation & On-Call Handoff**:
   - *Scenario*: Site Reliability Engineers coordinating a severity-1 outage handover across timezones.
   - *Behavior*: Messages tagged `URGENT` bypass client background refresh throttling, ensuring incoming updates are displayed instantly on lock screens.
3. **Cryptographic Key Verification Alerts**:
   - *Scenario*: A contact's identity key fingerprint changes unexpectedly during an active session (potential Man-In-The-Middle or device theft).
   - *Behavior*: Automated system notification tagged `URGENT` halts normal message submission until the user manually confirms the out-of-band safety number.
4. **Time-Sensitive Legal & Compliance Holds**:
   - *Scenario*: General Counsel issues an immediate litigation hold demanding cessation of automated ephemeral message deletion on specific conversations.
   - *Behavior*: Tagged `URGENT`, prompting immediate client-side UI acknowledgment.

### 4.4 Bulkhead Reservation & Emergency Unit Isolation
In extreme disaster recovery or hostage situations, normal enterprise traffic can spike by 1,000%, completely saturating standard Gateway and Messaging queues.

Under `MESSAGE_PRIORITY_EMERGENCY`:
- The API Gateway reserves a dedicated bulkhead partition with 10 reserved concurrent leases (`BulkheadManager`).
- Even if general user queues are 100% saturated and rejecting `NORMAL` and `URGENT` messages with HTTP 429 / 503, emergency messages pass unimpeded through the reserved leases directly to the Emergency Unit.

---

## 5. Protobuf & gRPC Interface Architecture (MSG-001-T01)

### 5.1 Package Topology & Versioning (`securecloud.messaging.v1`)
The messaging contract is declared in `proto/securecloud/messaging/v1/messaging.proto` under the package `securecloud.messaging.v1`. This follows platform naming conventions established by `securecloud.auth.v1` and `securecloud.files.v1`:

```protobuf
syntax = "proto3";

package securecloud.messaging.v1;

option cc_generic_services = false;
```

### 5.2 Message Envelopes & Opaque Encrypted Payloads (`MessageEnvelope`, `EncryptedPayload`)
The core message structure separates cryptographic payload data from transport routing headers:

```protobuf
message EncryptedPayload {
  bytes ciphertext_blob = 1;
  bytes ephemeral_public_key = 2;
  bytes initialization_vector = 3;
  bytes auth_tag = 4;
  string algorithm = 5;
}

message MessageEnvelope {
  string message_id = 1;                    // Canonical UUIDv7
  string conversation_id = 2;              // Canonical UUIDv4
  string sender_user_id = 3;                // Canonical UUIDv4
  string sender_device_id = 4;              // Canonical UUIDv4
  MessagePriority priority = 5;
  int64 created_at_unix_ms = 6;
  int64 expires_at_unix_ms = 7;
  string client_idempotency_token = 8;
  repeated PerDeviceDeliveryTarget delivery_targets = 9;
}
```

### 5.3 Device-Level Targeting & Dual-State Tracking (`PerDeviceDeliveryTarget`)
Because each recipient device possesses distinct cryptographic keys, messages must carry per-device encrypted payloads:

```protobuf
message PerDeviceDeliveryTarget {
  string recipient_user_id = 1;
  string recipient_device_id = 2;
  EncryptedPayload encrypted_payload = 3;
  DeliveryState state = 4;
  int64 updated_at_unix_ms = 5;
}
```

The delivery lifecycle tracks explicit states:
- `DELIVERY_STATE_QUEUED`: Accepted and stored in partition queue.
- `DELIVERY_STATE_DELIVERING`: In-flight push or direct delivery stream.
- `DELIVERY_STATE_DELIVERED`: Device ACK received from recipient.
- `DELIVERY_STATE_READ`: Read receipt ACK received from recipient.
- `DELIVERY_STATE_RETRY_WAIT`: Exponential backoff retry state.
- `DELIVERY_STATE_EXPIRED`: Message TTL reached prior to delivery.

### 5.4 Complete 12-RPC Interface Declaration & Method Semantics
The service contract exposes 12 authoritative RPC methods:

```protobuf
service MessagingService {
  // Message submission & retrieval
  rpc SendMessage(SendMessageRequest) returns (SendMessageResponse);
  rpc GetMessages(GetMessagesRequest) returns (GetMessagesResponse);
  rpc AcknowledgeDelivery(AcknowledgeDeliveryRequest) returns (AcknowledgeDeliveryResponse);
  rpc SendReadReceipt(SendReadReceiptRequest) returns (SendReadReceiptResponse);

  // Conversations & membership
  rpc CreateConversation(CreateConversationRequest) returns (CreateConversationResponse);
  rpc GetConversation(GetConversationRequest) returns (GetConversationResponse);
  rpc ListConversations(ListConversationsRequest) returns (ListConversationsResponse);
  rpc AddParticipant(AddParticipantRequest) returns (AddParticipantResponse);
  rpc RemoveParticipant(RemoveParticipantRequest) returns (RemoveParticipantResponse);

  // Device synchronization
  rpc SyncDeviceMessages(SyncDeviceMessagesRequest) returns (SyncDeviceMessagesResponse);
  rpc GetSyncCursor(GetSyncCursorRequest) returns (GetSyncCursorResponse);
  rpc UpdateSyncCursor(UpdateSyncCursorRequest) returns (UpdateSyncCursorResponse);
}
```

### 5.5 CMake Integration & Protobuf Code Generation Pipeline
In `proto/CMakeLists.txt`, `securecloud/messaging/v1/messaging.proto` was added to `securecloud_proto`. Compilation automatically emits:
- `build/dev-debug/generated/proto/securecloud/messaging/v1/messaging.pb.h`
- `build/dev-debug/generated/proto/securecloud/messaging/v1/messaging.pb.cc`
- `build/dev-debug/generated/proto/securecloud/messaging/v1/messaging.grpc.pb.h`
- `build/dev-debug/generated/proto/securecloud/messaging/v1/messaging.grpc.pb.cc`

Verified via `tests/unit/proto_smoke_test.cpp`.

---

## 6. Typed Service Configuration & Persistence Boundaries (MSG-001-T02)

### 6.1 Configuration Hierarchy: Common, ScyllaDB, and Worker Concurrency
In `src/messaging/messaging_config.hpp` and `.cpp`, the configuration model is structured into three strongly typed sub-configs:

```cpp
struct MessagingConfig {
    common::configuration::CommonServiceConfig common;
    ScyllaConfig scylla;
    WorkerPoolConfig workers;
    uint32_t shutdown_grace_period_ms{10000};
    ...
};
```

### 6.2 ScyllaConfig & Cluster Connection Topology
ScyllaDB settings are loaded from environment variables with safe defaults:

```cpp
struct ScyllaConfig {
    std::string host{"scylladb"};           // SECURECLOUD_MESSAGING_SCYLLA_HOST
    uint16_t port{9042};                    // SECURECLOUD_MESSAGING_SCYLLA_PORT
    std::string keyspace{"securecloud_messaging"}; // SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE
    uint32_t connect_timeout_ms{5000};      // [100, 30000]
    uint32_t request_timeout_ms{2000};      // [100, 30000]
    uint32_t connection_pool_size{16};      // [1, 128]
};
```

### 6.3 WorkerPoolConfig & Numerical Boundary Constraints
Thread counts and queue limits are strictly validated against production boundaries:
- `submission_workers`: default 8, allowed range `[1..128]`
- `delivery_workers`: default 16, allowed range `[1..256]`
- `sync_workers`: default 8, allowed range `[1..128]`
- `max_queued_submissions`: default 1,024, allowed range `[16..65536]`
- `max_queued_deliveries`: default 4,096, allowed range `[16..65536]`
- `max_queued_syncs`: default 1,024, allowed range `[16..65536]`
- `shutdown_grace_period_ms`: default 10,000ms, allowed range `[500..60000]`

Any out-of-range value or non-numeric string causes `MessagingConfig::load` to populate `ValidationResult` with errors and fail fast.

### 6.4 Strict Persistence Isolation: Zero PostgreSQL (Port 5432) Invariant
In accordance with **ADR-003**, the Messaging configuration parser strictly ignores and excludes PostgreSQL environment variables (`SECURECLOUD_AUTH_DB_HOST`, `SECURECLOUD_FILES_DB_PORT`, etc.). Unit test `IsolationFromOtherServicesDatabaseVariables` asserts that database credentials from Auth or Files cannot cross the service boundary.

---

## 7. Concurrency Engine Implementation: BoundedWorkerPool (MSG-001-T03)

### 7.1 Memory Layout & Thread Coordination Primitives
The implementation is contained in `src/messaging/concurrency/bounded_worker_pool.hpp` and `.cpp`:
- `std::vector<std::thread> workers_`: Dedicated OS worker threads.
- `std::queue<std::function<void()>> tasks_`: FIFO task queue.
- `std::mutex mutex_`: Guards queue, active worker counters, and state transitions.
- `std::condition_variable cv_task_available_`: Worker wakeup notification.
- `std::condition_variable cv_space_available_`: Enqueue backpressure release notification.
- `std::condition_variable cv_drained_`: Shutdown completion notification.

### 7.2 Task Lifecycle: Submission, Enqueueing, Worker Dequeue, Execution
```
1. Caller invokes try_submit(task)
   ├─► Acquires lock
   ├─► Check state == Running
   ├─► Check queue.size() < max_capacity
   │     ├─► If Full: release lock, return false (BACKPRESSURE)
   │     └─► If Space: push task, release lock, notify_one()
   └─► Returns true

2. Idle Worker wakes up
   ├─► Pops task from queue
   ├─► Increments active_workers
   ├─► Signals cv_space_available
   ├─► Releases lock
   ├─► Executes task() inside try/catch
   ├─► Re-acquires lock
   ├─► Decrements active_workers
   └─► Checks drain condition
```

### 7.3 BoundedWorkerPool Unit Verification Suite
Verified via `tests/unit/messaging/bounded_worker_pool_test.cpp` across 7 test cases:
1. `ConstructorValidations`: Validates thread count $\ge 1$ and capacity $\ge 1$.
2. `ExecuteBasicTasksInParallel`: Verifies concurrent multi-threaded execution across 4 threads.
3. `QueueCapacityBackpressureAndRejection`: Fills queue to limit and verifies subsequent `try_submit()` returns `false`.
4. `SubmitWithTimeout`: Verifies that `submit_with_timeout` succeeds when space frees up before timeout, and returns `false` on expiration.
5. `DrainAndStopCompletesQueuedTasks`: Verifies that `drain_and_stop()` executes 100% of queued tasks before joining threads.
6. `ShutdownAbortsQueuedTasks`: Verifies that `shutdown()` aborts unstarted tasks immediately.
7. `ExceptionSafetyDoesNotKillWorkerThread`: Verifies that a throwing task does not terminate the worker thread.

---

## 8. gRPC Service Implementation: MessagingServiceImpl Skeleton (MSG-001-T04)

### 8.1 RPC Handling Strategy: Deterministic UNIMPLEMENTED Semantics
`src/messaging/service/messaging_service_impl.hpp` and `.cpp` implement the gRPC service skeleton. Since Card `MSG-001` establishes only the runtime foundation, all 12 RPC methods return deterministic `grpc::StatusCode::UNIMPLEMENTED`:

```cpp
::grpc::Status MessagingServiceImpl::SendMessage(::grpc::ServerContext* context,
                                                 const ::securecloud::messaging::v1::SendMessageRequest* /*request*/,
                                                 ::securecloud::messaging::v1::SendMessageResponse* /*response*/) {
    log_rpc_invocation("SendMessage", context);
    return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, k_unimplemented_message);
}
```

Where `k_unimplemented_message` is `"RPC not implemented in MSG-001 foundation"`.

### 8.2 In-Place Correlation ID Extraction (`x-correlation-id` / `x-request-id`)
Correlation IDs are extracted directly from client metadata:
```cpp
std::string MessagingServiceImpl::extract_correlation_id(const ::grpc::ServerContext* context) {
    if (!context) return "";
    const auto& metadata = context->client_metadata();
    auto it = metadata.find("x-correlation-id");
    if (it != metadata.end()) {
        return std::string(it->second.data(), it->second.size());
    }
    it = metadata.find("x-request-id");
    if (it != metadata.end()) {
        return std::string(it->second.data(), it->second.size());
    }
    return "";
}
```

### 8.3 Peer Identity Verification via mTLS AuthContext
Peer certificate SAN identity is extracted and verified using `securecloud::common::security`:
```cpp
std::string MessagingServiceImpl::extract_peer_identity(const ::grpc::AuthContext* auth_context) {
    if (!auth_context || !auth_context->IsPeerAuthenticated()) {
        return "anonymous";
    }
    auto identity = securecloud::common::security::extract_peer_service_identity(*auth_context);
    return identity.value_or("unknown_peer");
}
```

Authorized callers are strictly restricted to internal microservices:
```cpp
bool MessagingServiceImpl::is_authorized_peer(const ::grpc::AuthContext* auth_context) {
    if (!auth_context || !auth_context->IsPeerAuthenticated()) {
        return false;
    }
    return securecloud::common::security::verify_peer_service_identity(*auth_context, "gateway") ||
           securecloud::common::security::verify_peer_service_identity(*auth_context, "auth") ||
           securecloud::common::security::verify_peer_service_identity(*auth_context, "messaging") ||
           securecloud::common::security::verify_peer_service_identity(*auth_context, "files");
}
```

### 8.4 In-Process gRPC Testing & Dependency Injection Verification
Verified in `tests/unit/messaging/messaging_service_test.cpp` across 24 unit tests:
- In-process `ServerBuilder` testing for all 12 RPCs.
- Correlation ID extraction across multiple header configurations.
- Peer SAN extraction and authorization tests.
- Dependency injection verification for `submission_pool`, `delivery_pool`, `sync_pool`.
- `MtlsCredentialLoader` server credential construction and fail-closed tests.

---

## 9. Production Lifecycle, Health Probing & Graceful Drain (MSG-001-T05)

### 9.1 Executable Entry Point Architecture (`src/messaging/main.cpp`)
The main entry point organizes the complete runtime lifecycle:
1. Signal installation (`std::signal`).
2. Config loading (`MessagingConfig::load`).
3. mTLS credential generation (`MtlsCredentialLoader::create_server_credentials`).
4. Worker pool allocation (`submission_pool`, `delivery_pool`, `sync_pool`).
5. Service implementation creation (`MessagingServiceImpl`).
6. Health manager & service instantiation (`HealthStatusManager`, `HealthServiceImpl`).
7. gRPC server assembly (`grpc::ServerBuilder`).
8. Serving loop (`std::this_thread::sleep_for(100ms)`).
9. Graceful drain execution.

### 9.2 Async-Signal-Safe Signal Interception (`SIGINT`, `SIGTERM`)
POSIX signal handling strictly avoids undefined behavior by performing a relaxed atomic store:
```cpp
std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_shutdown_requested.store(true, std::memory_order_relaxed);
    }
}
```
No mutexes, memory allocations, or I/O operations are invoked inside the signal handler.

### 9.3 Health & Readiness Probing Topology (`HealthStatusManager` / `HealthServiceImpl`)
The service exposes standard `grpc.health.v1.Health`:
- Liveness (`service = ""` or `service = "messaging"`): Reflects process responsiveness (`is_live()`).
- Readiness (`service = "readiness"`): Dynamically evaluates TCP connectivity to ScyllaDB (`config.scylla.host:config.scylla.port`). If ScyllaDB is unreachable or the service is shutting down, readiness returns `NOT_SERVING`.

### 9.4 Four-Stage Deterministic Graceful Drain Sequence
```
┌────────────────────────────────────────────────────────────────────────┐
│                   DETERMINISTIC GRACEFUL DRAIN (T05)                   │
├─────────┬───────────────────────────┬──────────────────────────────────┤
│ Stage 1 │ Readiness Degradation     │ health_manager.set_shutting_down │
│         │                           │ (Readiness drops to NOT_SERVING) │
├─────────┼───────────────────────────┼──────────────────────────────────┤
│ Stage 2 │ gRPC Server Drain         │ server->Shutdown(deadline)       │
│         │                           │ (In-flight RPCs complete)        │
├─────────┼───────────────────────────┼──────────────────────────────────┤
│ Stage 3 │ Worker Pool Drain         │ pool->drain_and_stop()           │
│         │                           │ (Queued tasks finish execution)  │
├─────────┼───────────────────────────┼──────────────────────────────────┤
│ Stage 4 │ Clean Process Exit        │ Return code 0                    │
└─────────┴───────────────────────────┴──────────────────────────────────┘
```

---

## 10. Comprehensive Verification & Integration Suite (MSG-001-T06)

### 10.1 Live Loopback mTLS Handshake & Ephemeral Port Negotiation
`tests/integration/messaging_service_lifecycle_integration_test.cpp` spins up an ephemeral mTLS gRPC server on `"127.0.0.1:0"`. Port negotiation is dynamic, guaranteeing zero TCP port contention during concurrent parallel test runs.

### 10.2 Full 12-RPC End-to-End Over-the-Wire Verification
A real Gateway mTLS client channel (`gateway.crt` / `gateway.key`) connects to the ephemeral port and calls all 12 RPCs over live TLS sockets, verifying that each returns `StatusCode::UNIMPLEMENTED`.

### 10.3 TLS Handshake Failure & Unauthenticated Caller Rejection
Integration test `RejectsUnauthenticatedOrUntrustedMtlsCallers`:
- An insecure plaintext client calling the server is rejected during the TLS handshake, returning `grpc::StatusCode::UNAVAILABLE`.
- Valid authenticated callers with authorized SAN identities succeed.

### 10.4 Readiness Transition Dynamics During Shutdown
Integration test `ReadinessTransitionsDuringGracefulShutdown`:
- Before shutdown: `Check("readiness")` returns `SERVING`.
- Trigger shutdown: `set_shutting_down(true)`.
- After shutdown: `Check("readiness")` returns `NOT_SERVING`.
- Liveness check `Check("")` remains `SERVING`.

### 10.5 Multi-Threaded Task Drain Under Load
Integration test `DeterministicGracefulDrainAndWorkerPoolCompletion`:
- Submits 60 concurrent tasks across `submission_pool`, `delivery_pool`, `sync_pool`.
- Initiates `drain_and_stop()` concurrently.
- Verifies that all 60 tasks complete without loss or deadlock.

### 10.6 Observational Guard & Architectural Invariant Audit
Integration test `ObservationalGuardEnforcesZeroDatabaseConnectionPort5432Invariant`:
- Verifies that Messaging configuration strictly points to ScyllaDB (port 9042).
- Asserts that port 5432 is not configured.

---

## 11. Architectural Sequence Diagrams

### 11.1 Diagram 1: Service Initialization, Worker Pool Wiring & mTLS Socket Bind

```mermaid
sequenceDiagram
    autonumber
    participant OS as OS / Environment
    participant Main as Messaging main()
    participant Cfg as MessagingConfig
    participant Pools as BoundedWorkerPools
    participant Svc as MessagingServiceImpl
    participant Health as HealthStatusManager
    participant gRPC as grpc::ServerBuilder
    participant TLS as MtlsCredentialLoader

    OS->>Main: Process Launch (securecloud-messaging)
    Main->>Cfg: MessagingConfig::load(env_source)
    Cfg-->>Main: Validated Config (Scylla:9042, WorkerBounds)
    Main->>TLS: create_server_credentials(tls_config)
    TLS-->>Main: std::shared_ptr<ServerCredentials>
    Main->>Pools: Instantiate Tri-Pool (sub:8, del:16, sync:8)
    Main->>Svc: MessagingServiceImpl(sub, del, sync)
    Main->>Health: Instantiate HealthStatusManager("messaging")
    Health->>Health: set_readiness_evaluator(probe_tcp(Scylla))
    Main->>gRPC: AddListeningPort("0.0.0.0:50053", server_creds)
    Main->>gRPC: RegisterService(&messaging_service)
    Main->>gRPC: RegisterService(&health_service)
    Main->>gRPC: BuildAndStart()
    gRPC-->>Main: std::unique_ptr<Server>
    Main->>Health: set_live(true)
    Main->>Health: set_ready(true)
    Main->>OS: Enter Polling Loop (wait for SIGINT/SIGTERM)
```

### 11.2 Diagram 2: Gateway-to-Messaging RPC Invocation & Metadata Extraction

```mermaid
sequenceDiagram
    autonumber
    participant GW as Gateway Service (Client)
    participant TLS as mTLS Handshake Layer
    participant Svc as MessagingServiceImpl
    participant Logger as Structured Logger

    GW->>TLS: gRPC SendMessage (TLS Client Hello with gateway.crt)
    TLS->>TLS: Verify Client Cert against ca.crt
    TLS->>TLS: Extract SAN: "DNS:gateway"
    TLS-->>GW: Handshake Complete (mTLS Established)
    GW->>Svc: SendMessageRequest (x-correlation-id: "corr-101")
    Svc->>Svc: extract_correlation_id() -> "corr-101"
    Svc->>Svc: extract_peer_identity() -> "gateway"
    Svc->>Svc: is_authorized_peer() -> true
    Svc->>Logger: [DEBUG] [messaging] SendMessage invoked (corr="corr-101", peer="gateway")
    Svc-->>GW: grpc::Status(UNIMPLEMENTED, "RPC not implemented in MSG-001 foundation")
```

### 11.3 Diagram 3: Worker Pool Backpressure, Rejection & Timed Submission

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Ingress Pipeline
    participant Pool as BoundedWorkerPool
    participant Queue as std::queue<Task> (Capacity: K)
    participant Worker as Worker Thread

    Note over Caller,Pool: Scenario A: Normal Submission
    Caller->>Pool: try_submit(task_1)
    Pool->>Queue: size < K -> push(task_1)
    Pool->>Worker: cv_task_available_.notify_one()
    Pool-->>Caller: true (Accepted)
    Worker->>Queue: pop(task_1)
    Worker->>Worker: execute task_1()

    Note over Caller,Pool: Scenario B: Saturated Queue (Backpressure)
    Caller->>Pool: try_submit(task_K_plus_1)
    Pool->>Queue: size == K (Queue Full)
    Pool-->>Caller: false (Immediate Rejection)
    Caller->>Caller: Return RESOURCE_EXHAUSTED / Retry-After

    Note over Caller,Pool: Scenario C: Timed Submission Wait
    Caller->>Pool: submit_with_timeout(task_new, 50ms)
    Pool->>Pool: cv_space_available_.wait_until(deadline)
    Worker->>Queue: pop(task_old) -> free space
    Worker->>Pool: cv_space_available_.notify_one()
    Pool->>Queue: push(task_new)
    Pool-->>Caller: true (Enqueued within budget)
```

### 11.4 Diagram 4: Four-Stage Graceful Drain & Clean Process Termination

```mermaid
sequenceDiagram
    autonumber
    participant OS as OS Kernel (SIGTERM)
    participant Handler as signal_handler()
    participant Main as Messaging Service main()
    participant Health as HealthStatusManager
    participant gRPC as grpc::Server
    participant Pools as BoundedWorkerPools

    OS->>Handler: SIGTERM Signal
    Handler->>Handler: g_shutdown_requested.store(true, relaxed)
    Main->>Main: Detects shutdown request in loop
    Note over Main,Health: Stage 1: Readiness Degradation
    Main->>Health: set_shutting_down(true)
    Note right of Health: Readiness probe returns NOT_SERVING<br/>Load balancer stops ingress routing
    Note over Main,gRPC: Stage 2: gRPC Server Drain
    Main->>gRPC: Shutdown(deadline = now + 10s)
    Note right of gRPC: In-flight RPCs finish; new RPCs rejected
    gRPC-->>Main: Server Stopped
    Note over Main,Pools: Stage 3: Worker Pool Drain
    Main->>Pools: submission_pool->drain_and_stop()
    Main->>Pools: delivery_pool->drain_and_stop()
    Main->>Pools: sync_pool->drain_and_stop()
    Note right of Pools: All queued tasks execute to completion;<br/>Threads joined via thread.join()
    Note over Main,OS: Stage 4: Process Exit
    Main->>OS: Exit Code 0 (Clean Shutdown)
```

---

## 12. Traceability Matrix against Acceptance Criteria

| Spec Requirement / Ticket ID | Scope / Architectural Target | Implementation File(s) | Verification Target | Status |
|:---|:---|:---|:---|:---|
| **MSG-001-T01** | Protobuf 3 & gRPC contract formalization | `proto/.../messaging.proto` | `securecloud_proto_smoke_test` | **PASSED** |
| **MSG-001-T02** | Typed config & persistence isolation | `src/messaging/messaging_config.*` | `securecloud_messaging_config_test` | **PASSED** |
| **MSG-001-T03** | BoundedWorkerPool concurrency engine | `src/.../bounded_worker_pool.*` | `securecloud_bounded_worker_pool_test` | **PASSED** |
| **MSG-001-T04** | MessagingServiceImpl 12-RPC skeleton | `src/.../messaging_service_impl.*` | `securecloud_messaging_service_test` | **PASSED** |
| **MSG-001-T05** | Service lifecycle, health & graceful drain | `src/messaging/main.cpp` | Process launch & SIGTERM validation | **PASSED** |
| **MSG-001-T06** | End-to-end mTLS integration verification | `tests/integration/..._test.cpp` | `securecloud_messaging_service_lifecycle_integration_test` | **PASSED** |
| **ADR-003** | Strict zero-PostgreSQL (5432) isolation | `messaging_config.cpp` | `IsolationFromOtherServicesDatabaseVariables` | **PASSED** |
| **ADR-004** | mTLS with SAN DNS peer verification | `messaging_service_impl.cpp` | `RejectsUnauthenticatedOrUntrustedMtlsCallers` | **PASSED** |
| **ADR-008** | Zero plaintext & opaque bytes payload | `messaging.proto` | `MessageEnvelopeSerialization` | **PASSED** |
| **ADR-009** | Hard queue limits & backpressure | `bounded_worker_pool.cpp` | `QueueCapacityBackpressureAndRejection` | **PASSED** |
| **ADR-010** | Deterministic graceful drain sequence | `main.cpp`, `bounded_worker_pool.cpp` | `DeterministicGracefulDrainAndWorkerPoolCompletion` | **PASSED** |

---

## 13. Empirical Verification Evidence & Full Test Run Artifacts

### 13.1 Unit Test Execution Evidence (`securecloud_messaging_config_test`)
```text
[==========] Running 9 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 9 tests from MessagingConfigTest
[ RUN      ] MessagingConfigTest.DefaultConfigurationValues
[       OK ] MessagingConfigTest.DefaultConfigurationValues (0 ms)
[ RUN      ] MessagingConfigTest.EnvironmentVariableOverrides
[       OK ] MessagingConfigTest.EnvironmentVariableOverrides (0 ms)
[ RUN      ] MessagingConfigTest.InvalidScyllaPortValidation
[       OK ] MessagingConfigTest.InvalidScyllaPortValidation (0 ms)
[ RUN      ] MessagingConfigTest.EmptyScyllaHostOrKeyspaceRejected
[       OK ] MessagingConfigTest.EmptyScyllaHostOrKeyspaceRejected (0 ms)
[ RUN      ] MessagingConfigTest.InvalidWorkerBoundsValidation
[       OK ] MessagingConfigTest.InvalidWorkerBoundsValidation (0 ms)
[ RUN      ] MessagingConfigTest.InvalidQueueCapacityValidation
[       OK ] MessagingConfigTest.InvalidQueueCapacityValidation (0 ms)
[ RUN      ] MessagingConfigTest.InvalidTimeoutAndGracePeriodValidation
[       OK ] MessagingConfigTest.InvalidTimeoutAndGracePeriodValidation (0 ms)
[ RUN      ] MessagingConfigTest.NonNumericInputsRejected
[       OK ] MessagingConfigTest.NonNumericInputsRejected (0 ms)
[ RUN      ] MessagingConfigTest.IsolationFromOtherServicesDatabaseVariables
[       OK ] MessagingConfigTest.IsolationFromOtherServicesDatabaseVariables (0 ms)
[----------] 9 tests from MessagingConfigTest (0 ms total)
[==========] 9 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 9 tests.
```

### 13.2 Concurrency Test Execution Evidence (`securecloud_bounded_worker_pool_test`)
```text
[==========] Running 7 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 7 tests from BoundedWorkerPoolTest
[ RUN      ] BoundedWorkerPoolTest.ConstructorValidations
[       OK ] BoundedWorkerPoolTest.ConstructorValidations (0 ms)
[ RUN      ] BoundedWorkerPoolTest.ExecuteBasicTasksInParallel
[       OK ] BoundedWorkerPoolTest.ExecuteBasicTasksInParallel (0 ms)
[ RUN      ] BoundedWorkerPoolTest.QueueCapacityBackpressureAndRejection
[       OK ] BoundedWorkerPoolTest.QueueCapacityBackpressureAndRejection (6 ms)
[ RUN      ] BoundedWorkerPoolTest.SubmitWithTimeout
[       OK ] BoundedWorkerPoolTest.SubmitWithTimeout (37 ms)
[ RUN      ] BoundedWorkerPoolTest.DrainAndStopCompletesQueuedTasks
[       OK ] BoundedWorkerPoolTest.DrainAndStopCompletesQueuedTasks (25 ms)
[ RUN      ] BoundedWorkerPoolTest.ShutdownAbortsQueuedTasks
[       OK ] BoundedWorkerPoolTest.ShutdownAbortsQueuedTasks (6 ms)
[ RUN      ] BoundedWorkerPoolTest.ExceptionSafetyDoesNotKillWorkerThread
[       OK ] BoundedWorkerPoolTest.ExceptionSafetyDoesNotKillWorkerThread (0 ms)
[----------] 7 tests from BoundedWorkerPoolTest (76 ms total)
[==========] 7 tests from 1 test suite ran. (76 ms total)
[  PASSED  ] 7 tests.
```

### 13.3 Contract Test Execution Evidence (`securecloud_proto_smoke_test`)
```text
[==========] Running 8 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 8 tests from ProtoSmokeTest
[ RUN      ] ProtoSmokeTest.MessageConstructionAndSerialization
[       OK ] ProtoSmokeTest.MessageConstructionAndSerialization (0 ms)
[ RUN      ] ProtoSmokeTest.ServiceStubTypeLinkage
[       OK ] ProtoSmokeTest.ServiceStubTypeLinkage (0 ms)
[ RUN      ] ProtoSmokeTest.AuthMessageConstructionAndSerialization
[       OK ] ProtoSmokeTest.AuthMessageConstructionAndSerialization (0 ms)
[ RUN      ] ProtoSmokeTest.AuthServiceStubTypeLinkage
[       OK ] ProtoSmokeTest.AuthServiceStubTypeLinkage (0 ms)
[ RUN      ] ProtoSmokeTest.FilesMessageConstructionAndSerialization
[       OK ] ProtoSmokeTest.FilesMessageConstructionAndSerialization (0 ms)
[ RUN      ] ProtoSmokeTest.FilesServiceStubTypeLinkage
[       OK ] ProtoSmokeTest.FilesServiceStubTypeLinkage (0 ms)
[ RUN      ] ProtoSmokeTest.MessagingMessageConstructionAndSerialization
[       OK ] ProtoSmokeTest.MessagingMessageConstructionAndSerialization (0 ms)
[ RUN      ] ProtoSmokeTest.MessagingServiceStubTypeLinkage
[       OK ] ProtoSmokeTest.MessagingServiceStubTypeLinkage (0 ms)
[----------] 8 tests from ProtoSmokeTest (0 ms total)
[==========] 8 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 8 tests.
```

### 13.4 Service Handler Execution Evidence (`securecloud_messaging_service_test`)
```text
[==========] Running 24 tests from 5 test suites.
[----------] Global test environment set-up.
[----------] 12 tests from MessagingServiceInProcessTest
[ RUN      ] MessagingServiceInProcessTest.SendMessageReturnsUnimplemented
[DEBUG] [messaging] SendMessage invoked (correlation_id='corr-send-msg-001', peer='anonymous')
[       OK ] MessagingServiceInProcessTest.SendMessageReturnsUnimplemented (5 ms)
[ RUN      ] MessagingServiceInProcessTest.GetMessagesReturnsUnimplemented
[DEBUG] [messaging] GetMessages invoked (correlation_id='req-get-msg-002', peer='anonymous')
[       OK ] MessagingServiceInProcessTest.GetMessagesReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.AcknowledgeDeliveryReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.AcknowledgeDeliveryReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.SendReadReceiptReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.SendReadReceiptReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.CreateConversationReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.CreateConversationReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.GetConversationReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.GetConversationReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.ListConversationsReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.ListConversationsReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.AddParticipantReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.AddParticipantReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.RemoveParticipantReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.RemoveParticipantReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.SyncDeviceMessagesReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.SyncDeviceMessagesReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.GetSyncCursorReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.GetSyncCursorReturnsUnimplemented (0 ms)
[ RUN      ] MessagingServiceInProcessTest.UpdateSyncCursorReturnsUnimplemented
[       OK ] MessagingServiceInProcessTest.UpdateSyncCursorReturnsUnimplemented (0 ms)
[----------] 12 tests from MessagingServiceInProcessTest (12 ms total)
[----------] 2 tests from MessagingServiceImplTest
[ RUN      ] MessagingServiceImplTest.ExtractCorrelationIdFromNullContextReturnsEmpty
[       OK ] MessagingServiceImplTest.ExtractCorrelationIdFromNullContextReturnsEmpty (0 ms)
[ RUN      ] MessagingServiceImplTest.ExtractCorrelationIdFromEmptyContextReturnsEmpty
[       OK ] MessagingServiceImplTest.ExtractCorrelationIdFromEmptyContextReturnsEmpty (0 ms)
[----------] 2 tests from MessagingServiceImplTest (0 ms total)
[----------] 7 tests from MessagingServiceImplAuthTest
[ RUN      ] MessagingServiceImplAuthTest.ExtractPeerIdentityNullContextReturnsAnonymous
[       OK ] MessagingServiceImplAuthTest.ExtractPeerIdentityNullContextReturnsAnonymous (0 ms)
[ RUN      ] MessagingServiceImplAuthTest.ExtractPeerIdentityUnauthenticatedReturnsAnonymous
[       OK ] MessagingServiceImplAuthTest.ExtractPeerIdentityUnauthenticatedReturnsAnonymous (0 ms)
[ RUN      ] MessagingServiceImplAuthTest.ExtractsGatewayPeerIdentityAndAuthorizes
[       OK ] MessagingServiceImplAuthTest.ExtractsGatewayPeerIdentityAndAuthorizes (0 ms)
[ RUN      ] MessagingServiceImplAuthTest.ExtractsRawGatewayPeerIdentityAndAuthorizes
[       OK ] MessagingServiceImplAuthTest.ExtractsRawGatewayPeerIdentityAndAuthorizes (0 ms)
[ RUN      ] MessagingServiceImplAuthTest.ExtractsAuthAndMessagingPeersAndAuthorizes
[       OK ] MessagingServiceImplAuthTest.ExtractsAuthAndMessagingPeersAndAuthorizes (0 ms)
[ RUN      ] MessagingServiceImplAuthTest.RejectsUnknownOrUnauthorizedPeerIdentity
[       OK ] MessagingServiceImplAuthTest.RejectsUnknownOrUnauthorizedPeerIdentity (0 ms)
[ RUN      ] MessagingServiceImplAuthTest.RejectsMissingSanIdentity
[       OK ] MessagingServiceImplAuthTest.RejectsMissingSanIdentity (0 ms)
[----------] 7 tests from MessagingServiceImplAuthTest (0 ms total)
[----------] 1 test from MessagingServiceImplDependencyTest
[ RUN      ] MessagingServiceImplDependencyTest.InjectsWorkerPoolDependencies
[       OK ] MessagingServiceImplDependencyTest.InjectsWorkerPoolDependencies (0 ms)
[----------] 1 test from MessagingServiceImplDependencyTest (0 ms total)
[----------] 2 tests from MessagingServiceMtlsTest
[ RUN      ] MessagingServiceMtlsTest.CreateServerCredentialsSucceedsForDevPkiOrMock
[       OK ] MessagingServiceMtlsTest.CreateServerCredentialsSucceedsForDevPkiOrMock (0 ms)
[ RUN      ] MessagingServiceMtlsTest.CreateServerCredentialsFailsClosedForMissingFiles
[       OK ] MessagingServiceMtlsTest.CreateServerCredentialsFailsClosedForMissingFiles (0 ms)
[----------] 2 tests from MessagingServiceMtlsTest (0 ms total)
[==========] 24 tests from 5 test suites ran. (13 ms total)
[  PASSED  ] 24 tests.
```

### 13.5 Lifecycle Integration Execution Evidence (`securecloud_messaging_service_lifecycle_integration_test`)
```text
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from MessagingServiceLifecycleIntegrationTest
[ RUN      ] MessagingServiceLifecycleIntegrationTest.ServiceStartsSuccessfullyWithValidMtlsCredentialsAndHealthServing
[       OK ] MessagingServiceLifecycleIntegrationTest.ServiceStartsSuccessfullyWithValidMtlsCredentialsAndHealthServing (18 ms)
[ RUN      ] MessagingServiceLifecycleIntegrationTest.GatewayClientEstablishesMtlsChannelAndCallsAll12RpcMethods
[DEBUG] [messaging] SendMessage invoked (correlation_id='corr-integ-send-01', peer='gateway')
[DEBUG] [messaging] GetMessages invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] AcknowledgeDelivery invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] SendReadReceipt invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] CreateConversation invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] GetConversation invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] ListConversations invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] AddParticipant invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] RemoveParticipant invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] SyncDeviceMessages invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] GetSyncCursor invoked (correlation_id='', peer='gateway')
[DEBUG] [messaging] UpdateSyncCursor invoked (correlation_id='', peer='gateway')
[       OK ] MessagingServiceLifecycleIntegrationTest.GatewayClientEstablishesMtlsChannelAndCallsAll12RpcMethods (7 ms)
[ RUN      ] MessagingServiceLifecycleIntegrationTest.RejectsUnauthenticatedOrUntrustedMtlsCallers
[DEBUG] [messaging] SendMessage invoked (correlation_id='', peer='auth')
[       OK ] MessagingServiceLifecycleIntegrationTest.RejectsUnauthenticatedOrUntrustedMtlsCallers (5 ms)
[ RUN      ] MessagingServiceLifecycleIntegrationTest.ReadinessTransitionsDuringGracefulShutdown
[       OK ] MessagingServiceLifecycleIntegrationTest.ReadinessTransitionsDuringGracefulShutdown (4 ms)
[ RUN      ] MessagingServiceLifecycleIntegrationTest.DeterministicGracefulDrainAndWorkerPoolCompletion
[       OK ] MessagingServiceLifecycleIntegrationTest.DeterministicGracefulDrainAndWorkerPoolCompletion (31 ms)
[ RUN      ] MessagingServiceLifecycleIntegrationTest.ObservationalGuardEnforcesZeroDatabaseConnectionPort5432Invariant
[       OK ] MessagingServiceLifecycleIntegrationTest.ObservationalGuardEnforcesZeroDatabaseConnectionPort5432Invariant (0 ms)
[----------] 6 tests from MessagingServiceLifecycleIntegrationTest (67 ms total)
[==========] 6 tests from 1 test suite ran. (67 ms total)
[  PASSED  ] 6 tests.
```

### 13.6 Full Repository Regression Suite Execution Evidence (1,247 Tests Passed)
```text
Test project /Users/sergeychukhno/Desktop/C:C++/SecureCloud/build/dev-debug
      Start    1: GoogleTestFrameworkTest.FrameworkInitializationAndAssertion
      ...
      Start 1247: MessagingServiceLifecycleIntegrationTest.ObservationalGuardEnforcesZeroDatabaseConnectionPort5432Invariant

100% tests passed, 0 tests failed out of 1247

Total Test time (real) =  29.25 sec
```

### 13.7 Static Analysis & Code Formatting Verification
```text
$ cmake --build build/dev-debug --target check-format
[0/2] Re-checking globbed directories...
[1/2] Checking project C++ formatting (read-only)...
Format checking passed: 0 formatting violations found.
```

---

## 14. Conclusion & Readiness for Card MSG-002

Card **`MSG-001`** has established a mathematically grounded, highly performant, and architecturally compliant runtime foundation for the SecureCloud Messaging service:
1. **The Protobuf / gRPC interface contract** is defined across 12 distinct RPCs with opaque payload isolation (**ADR-008**).
2. **The concurrency architecture** is protected by `BoundedWorkerPool` enforcing queue backpressure and Little's Law stability (**ADR-009**).
3. **The runtime lifecycle** enforces strict mutual TLS with SAN DNS identity verification and zero PostgreSQL ingress (**ADR-003**, **ADR-004**).
4. **The shutdown mechanics** provide zero task loss through a deterministic four-stage graceful drain sequence (**ADR-010**).
5. **The regression safety** is empirically certified by 1,247 passing tests across the entire platform.

The Messaging service foundation is **VALIDATED & COMPLETE**, establishing all architectural prerequisites required to proceed to **`MSG-002: Messaging Persistence & ScyllaDB Driver Integration`**.
