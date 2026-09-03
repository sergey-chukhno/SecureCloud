# ADR-009 — Distributed Failure & Resilience

**Status:** Approved
**Date:** 2026-09-02
**Decision scope:** Runtime service failures, network failures, dependency failures, overload, recovery, graceful shutdown, degraded operation, cascading-failure prevention

---

# 1. Context

SecureCloud consists of independently deployed runtime services communicating over the network:

```text
Qt/C++ Client
      │
    HTTPS
      │
      ▼
   Gateway
      │
      ├──── gRPC ────► Auth
      │
      ├──── gRPC ────► Messaging
      │
      └──── gRPC ────► Files

Messaging ── async ──► Audit
Files     ── async ──► Audit
Auth      ── async ──► Audit
```

Because services communicate over a network, failures are expected rather than exceptional.

Possible failures include:

* service crashes;
* network interruption;
* network partitions;
* connection resets;
* request timeouts;
* dependency overload;
* database unavailability;
* storage failure;
* duplicate requests;
* delayed responses;
* delayed asynchronous events;
* service restarts;
* partial infrastructure failure;
* resource exhaustion;
* prolonged client disconnection;
* cascading failures.

ADR-007 already establishes messaging durability, idempotency, retry behavior, durable offline queues and transactional outbox semantics.

ADR-008 establishes security and cryptographic boundaries.

ADR-009 therefore defines the **system-level resilience model** that sits above these decisions.

---

# 2. Decision

SecureCloud adopts a **failure-isolation and graceful-degradation architecture** based on:

* explicit deadlines/timeouts;
* bounded retries;
* exponential backoff with jitter;
* idempotency;
* circuit breakers;
* bulkheads;
* bounded queues;
* backpressure;
* health/readiness checks;
* graceful shutdown;
* durable recovery;
* dependency-aware degraded operation;
* no unbounded resource consumption;
* no silent loss of accepted durable data.

The system must prefer:

```text
controlled failure
      >
unbounded retry
      >
cascading failure
```

---

# 3. Failure classification

SecureCloud classifies failures into four broad categories.

## 3.1 Local service failure

Example:

```text
Messaging crashes
```

The service becomes temporarily unavailable while other services continue operating.

---

## 3.2 Dependency failure

Example:

```text
Messaging
    │
    └──► ScyllaDB unavailable
```

Messaging remains alive but cannot complete operations requiring persistence.

---

## 3.3 Network failure

Example:

```text
Gateway ───── X ───── Messaging
```

The services themselves are healthy, but communication between them fails.

---

## 3.4 Resource exhaustion

Example:

```text
10k msg/s
     │
     ▼
Messaging
     │
     ├── CPU saturation
     ├── memory pressure
     ├── queue growth
     └── DB saturation
```

The system must actively control overload rather than allowing queues and memory usage to grow without bound.

---

# 4. Failure semantics

Every remote operation must have an explicit outcome.

Conceptually:

```text
        Request
           │
           ▼
    ┌───────────────┐
    │ Remote call   │
    └───────┬───────┘
            │
     ┌──────┼──────────┐
     ▼      ▼          ▼
  Success Timeout   Rejected
     │      │          │
     ▼      ▼          ▼
 Continue  bounded   explicit
           retry     failure
```

A service must never wait indefinitely for another service.

Every remote operation therefore has a bounded deadline.

---

# 5. Timeouts

All network calls must use explicit deadlines.

No internal request may have an infinite timeout.

For example:

```text
Gateway
   │
   │ deadline = T
   ▼
Messaging
   │
   └──► operation must finish before T
```

When the deadline expires:

```text
operation → cancelled/failed
```

The caller must not continue consuming resources indefinitely.

Timeouts must propagate through nested calls where possible.

For example:

```text
Gateway
  │ deadline 2s
  ▼
Messaging
  │ remaining deadline 1.7s
  ▼
Auth
```

A downstream service must not start a 5-second operation when only 200 ms remain on the original request deadline.

---

# 6. Retry policy

Retries are permitted only when they are safe and useful.

The default retry strategy is:

```text
attempt 1
   │
   └── failure
        ↓
   backoff + jitter
        ↓
attempt 2
        │
        └── failure
             ↓
        larger backoff
             ↓
         attempt 3
```

Backoff is exponential and bounded.

Jitter is mandatory for retry storms.

Retries must respect the original operation deadline.

---

# 7. Idempotency and retries

Retries must not accidentally create duplicate logical operations.

This is especially important for:

```text
SendMessage
CreateFileTransfer
AcknowledgeDelivery
```

ADR-007 already establishes stable identifiers and idempotent message submission.

Therefore:

```text
Client
  │
  │ SendMessage(message_id=X)
  ▼
Messaging
  │
  │ persists message
  │
  └── response lost
          │
          ▼
Client retries X
          │
          ▼
Messaging detects X
          │
          ▼
return existing logical result
```

A lost response must not cause duplicate logical messages.

---

# 8. Circuit breakers

Circuit breakers protect healthy services from repeatedly calling a failing dependency.

Conceptually:

```text
             ┌──────────────┐
             │   CLOSED     │
             │ normal calls │
             └──────┬───────┘
                    │ repeated failures
                    ▼
             ┌──────────────┐
             │     OPEN     │
             │ fail fast    │
             └──────┬───────┘
                    │ after recovery delay
                    ▼
             ┌──────────────┐
             │ HALF-OPEN    │
             │ test request │
             └──────┬───────┘
                    │
             ┌──────┴──────┐
             ▼             ▼
          success        failure
             │             │
             ▼             ▼
          CLOSED          OPEN
```

Circuit breakers are applied to remote dependencies where repeated failures could otherwise consume large amounts of:

* threads;
* connections;
* CPU;
* memory;
* queue capacity.

Circuit breakers must not silently discard already accepted durable messages.

---

# 9. Bulkheads

Each service must isolate resource pools so that one workload cannot consume all resources.

Examples:

```text
Messaging
 ├── client request concurrency
 ├── Auth dependency calls
 ├── delivery workers
 ├── outbox publishing
 └── database connections
```

A failure or overload in one category must not automatically consume the entire service's capacity.

The same principle applies at the Gateway:

```text
Gateway
 ├── authentication requests
 ├── messaging requests
 ├── file transfers
 └── emergency traffic
```

Large file transfers must not starve normal messaging operations.

---

# 10. Backpressure

SecureCloud uses explicit backpressure rather than unlimited buffering.

When a downstream dependency cannot keep up:

```text
Producer
   │
   ▼
bounded queue
   │
   │ full
   ▼
backpressure
```

Possible responses include:

* temporarily reject new work;
* slow acceptance;
* reduce concurrency;
* return explicit overload status;
* allow higher-priority work to proceed according to policy.

The system must never allow unbounded queue growth.

---

# 11. Emergency traffic

Emergency messages receive elevated priority but do not bypass durability or security.

Under overload:

```text
Normal messages
       │
       ▼
bounded capacity

Emergency messages
       │
       ▼
reserved / prioritized capacity
```

Emergency priority must not become an unlimited bypass.

The exact capacity allocation is a performance/configuration decision and must be validated through ADR-010 benchmarks.

---

# 12. Messaging failure behavior

Messaging is the critical durable communication service.

If Messaging temporarily fails:

```text
Client
  │
  X
Messaging
```

the client must not assume that a message was accepted unless it received the appropriate successful durable-acceptance result.

If Messaging has already durably accepted the message but the response is lost:

```text
message_id = X
```

allows the client to safely retry.

Once accepted, the message must remain protected by ADR-007's durability guarantees.

---

# 13. Messaging database failure

Messaging uses ScyllaDB as established by ADR-006.

If ScyllaDB becomes unavailable:

```text
Messaging
    │
    X
ScyllaDB
```

Messaging must not falsely report successful durable acceptance.

Therefore:

```text
DB unavailable
     ↓
cannot establish required durability
     ↓
SendMessage cannot succeed
```

The client receives an explicit temporary failure.

The service must avoid accepting data into an unbounded in-memory queue as a substitute for durable persistence.

---

# 14. Auth failure

If Auth becomes unavailable:

```text
Gateway
   │
   X
 Auth
```

operations requiring fresh authentication/authorization may temporarily fail.

However, Auth failure must not automatically cause:

* loss of already persisted messages;
* deletion of Messaging state;
* corruption of Files;
* loss of Audit data.

Existing services continue operating according to their dependency requirements and previously established authorization state.

No service may bypass authorization merely because Auth is unavailable.

---

# 15. Files failure

If Files or MinIO becomes unavailable:

```text
Client
  │
  ▼
Gateway
  │
  X
Files / MinIO
```

file operations fail or pause explicitly.

Messaging must remain operational for normal text communication where possible.

A file-storage outage must not cascade into complete messaging outage.

---

# 16. Audit failure

Audit is intentionally non-blocking for core message acceptance.

If Audit becomes unavailable:

```text
Messaging
    │
    ├──► Audit     X
    │
    └──► durable message state ✓
```

Message acceptance must continue when the required Messaging durability conditions are satisfied.

Audit events are retained through the appropriate durable event/outbox mechanism and published later.

This follows ADR-007.

Audit failure therefore degrades observability rather than destroying core messaging availability.

---

# 17. Outbox failure

The Transactional Outbox is part of Messaging's durable state.

When a message is accepted:

```text
Message state
     +
Outbox event
     │
     └── atomic durable commit
```

If the publisher crashes afterward:

```text
message = durable ✓
event = durable ✓
publisher = crashed ✗
```

the publisher can restart and publish the event later.

Therefore publisher failure must not cause message loss.

---

# 18. Duplicate events

As established by ADR-007, event publication is at-least-once.

Therefore:

```text
Outbox
   │
   ├── event X → Audit
   │
   └── retry → event X → Audit
```

Consumers must be idempotent.

The same event must not create duplicate logical effects.

Exactly-once distributed processing is not required.

---

# 19. Network partition

A network partition is treated as a normal distributed-system failure.

Example:

```text
Gateway                 Messaging
   │                        │
   │       NETWORK X        │
   │                        │
```

The system must not attempt to "guess" whether a request succeeded.

Instead it relies on:

* deadlines;
* explicit operation IDs;
* idempotency;
* durable state;
* retry;
* reconciliation where necessary.

This is particularly important for message submission.

---

# 20. Lost response

The system explicitly distinguishes:

```text
request failed
```

from:

```text
request outcome unknown
```

For example:

```text
Client
  │ SendMessage(X)
  ▼
Messaging
  │
  │ persists X
  │
  ▼
network failure
  │
  X response
  │
  ▼
Client
```

The client does not know whether X was accepted.

It therefore retries using the same idempotency identifier.

Messaging resolves the ambiguity by consulting durable state.

This is a core distributed-systems invariant.

---

# 21. Service restart

Services must be restart-safe.

After restart:

```text
Process
   │
   ▼
load durable state
   │
   ▼
recover pending work
   │
   ▼
resume normal operation
```

Messaging must recover:

* pending deliveries;
* retry state;
* outbox events;
* durable message state.

The service must not depend on process memory for authoritative state.

---

# 22. Graceful shutdown

Services must support graceful shutdown.

Conceptually:

```text
RUNNING
   │
   │ shutdown signal
   ▼
STOP ACCEPTING NEW WORK
   │
   ▼
FINISH / CANCEL IN-FLIGHT WORK
   │
   ▼
PERSIST REQUIRED STATE
   │
   ▼
CLOSE CONNECTIONS
   │
   ▼
STOP
```

Shutdown must respect operation deadlines.

A service must not wait indefinitely for a broken dependency during shutdown.

---

# 23. Health and readiness

Each service exposes health information suitable for orchestration.

Two concepts are distinguished:

### Liveness

> Is the process functioning?

### Readiness

> Is the service capable of accepting the relevant workload?

Example:

```text
Process alive       ✓
Database available  ✗
        │
        ▼
Service not ready
```

A temporarily unhealthy dependency must not necessarily imply process termination.

Health checks must therefore avoid creating additional cascading load.

---

# 24. Startup dependency handling

Services must tolerate dependency startup order.

Docker Compose may start:

```text
Messaging
```

before:

```text
ScyllaDB
```

is fully ready.

Messaging should:

1. start;
2. report not-ready;
3. retry dependency initialization with bounded backoff;
4. become ready once required dependencies are healthy.

The architecture must not depend on fragile fixed startup sleeps.

---

# 25. Database recovery

Persistent data stores are authoritative for their respective services.

After a database restart:

```text
Service
   │
   ▼
database unavailable
   │
   ▼
temporary degraded state
   │
   ▼
database recovered
   │
   ▼
service readiness restored
```

The service must not reconstruct authoritative state solely from logs or memory.

Database recovery procedures must preserve the durability guarantees established by ADR-005 through ADR-007.

---

# 26. Cascading-failure prevention

The system explicitly prevents failure amplification.

Without controls:

```text
Auth slow
  ↓
Gateway threads blocked
  ↓
Gateway queue grows
  ↓
memory increases
  ↓
Gateway becomes slow
  ↓
clients retry
  ↓
more requests
  ↓
system collapse
```

SecureCloud instead uses:

```text
Auth slow
  ↓
timeout
  ↓
bounded retry
  ↓
circuit breaker
  ↓
fail fast
  ↓
release resources
  ↓
Gateway remains healthy
```

This is one of the primary objectives of ADR-009.

---

# 27. Retry storms

Retries themselves can become an outage amplifier.

Therefore:

```text
failure
   ↓
retry
   ↓
failure
   ↓
retry
   ↓
retry storm
```

is explicitly prohibited.

Controls include:

* exponential backoff;
* jitter;
* maximum attempts;
* maximum retry duration;
* deadline propagation;
* circuit breakers;
* bounded concurrency;
* backpressure.

---

# 28. Overload behavior

When a service reaches its safe operating capacity, it must fail predictably.

It must not:

* allocate unlimited memory;
* create unlimited threads;
* create unlimited database connections;
* accept unlimited queued work;
* retry indefinitely.

Instead it should:

```text
healthy capacity
      │
      ▼
near capacity
      │
      ▼
backpressure
      │
      ▼
explicit overload response
```

The precise thresholds are configuration/performance parameters to be established and validated under ADR-010.

---

# 29. Client behavior during outages

The client must distinguish:

### Accepted

```text
server confirmed durable acceptance
```

from:

### Unknown

```text
network failure before result
```

from:

### Rejected

```text
server explicitly rejected request
```

This distinction is critical for correct retry behavior.

The client must not blindly create a new message when the result is unknown.

It retries using the same stable identifier.

---

# 30. Offline operation

SecureCloud supports prolonged client disconnection.

During recipient offline periods:

```text
Sender
   │
   ▼
Messaging
   │
   ▼
durable recipient queue
   │
   │ recipient offline
   │
   │ ...
   ▼
Recipient reconnects
   │
   ▼
delivery resumes
```

This behavior is governed primarily by ADR-007.

ADR-009 adds the system-level failure behavior around:

* reconnect storms;
* service restarts;
* network interruptions;
* dependency failures;
* bounded synchronization.

---

# 31. Reconnection storms

When a network or service returns after an outage, thousands of clients may reconnect simultaneously.

SecureCloud must avoid:

```text
service recovery
      ↓
10,000 clients reconnect
      ↓
10,000 authentication requests
      ↓
DB overload
      ↓
service fails again
```

The architecture therefore requires:

* client-side reconnect backoff;
* jitter;
* server-side connection/concurrency limits;
* bounded synchronization;
* rate limiting;
* controlled recovery.

Exact values belong to performance testing under ADR-010.

---

# 32. Data-loss principle

The system distinguishes between:

```text
accepted durable data
```

and:

```text
not-yet-accepted data
```

Once Messaging reports successful durable acceptance:

> the system must not silently lose the message because of a process crash, retry, or transient dependency failure.

Before durable acceptance:

> the system is allowed to report temporary failure and require client retry.

This is the fundamental availability/durability boundary.

---

# 33. Control-plane failure

The runtime plane must not depend continuously on the control plane.

If:

```text
CI/CD / deployment / orchestration
```

fails, already-running services should continue operating.

Control-plane failure must not automatically cause:

* message deletion;
* database deletion;
* service shutdown;
* loss of encryption state.

This follows ADR-002.

---

# 34. Security during failure

Failure handling must never weaken security.

Examples:

```text
Auth unavailable
     ≠
disable authorization
```

```text
TLS failure
     ≠
fall back to plaintext
```

```text
crypto verification failure
     ≠
attempt unauthenticated decryption
```

```text
database unavailable
     ≠
pretend message was durably stored
```

```text
certificate invalid
     ≠
accept insecure connection
```

Security failures are fail-closed unless a specifically designed degraded mode has been approved.

---

# 35. Observability requirements

Resilience requires visibility into failure behavior.

Services should expose:

* request latency;
* error rate;
* timeout count;
* retry count;
* circuit-breaker state;
* queue depth;
* active connections;
* resource utilization;
* database latency;
* failed dependencies;
* message delivery backlog;
* outbox backlog;
* recovery time.

Observability data must respect ADR-008's security restrictions.

No plaintext message content or private cryptographic material is logged.

---

# 36. Recovery model

Recovery follows:

```text
FAILURE
   │
   ▼
DETECT
   │
   ▼
ISOLATE
   │
   ▼
FAIL / DEGRADE SAFELY
   │
   ▼
RECOVER DEPENDENCY
   │
   ▼
RECONCILE DURABLE STATE
   │
   ▼
RESUME
```

Durable state is the source of truth.

Transient in-memory state is disposable.

---

# 37. Resilience invariants

The following invariants are mandatory:

1. **No remote operation may wait indefinitely.**
2. **Retries are bounded and deadline-aware.**
3. **Retries use exponential backoff and jitter.**
4. **Retryable operations must be idempotent or otherwise proven safe.**
5. **Queues and concurrency are bounded.**
6. **One dependency failure must not automatically exhaust another service's resources.**
7. **Accepted durable messages must not be silently lost.**
8. **A lost response must be recoverable through idempotency.**
9. **Audit failure must not block durable message acceptance.**
10. **Database failure must not be hidden by pretending data was persisted.**
11. **Services must recover from process restarts using durable state.**
12. **Services must support graceful shutdown.**
13. **Readiness must be distinguished from liveness.**
14. **Control-plane failure must not automatically destroy runtime state.**
15. **Failure handling must never bypass security controls.**
16. **No fallback to plaintext or weaker cryptography is permitted.**
17. **Overload must produce controlled degradation rather than unbounded resource consumption.**

---

# 38. Testing requirements

ADR-009 requires distributed failure testing.

At minimum:

### Service failures

* Gateway crash;
* Auth crash;
* Messaging crash;
* Files crash;
* Audit crash.

### Dependency failures

* PostgreSQL unavailable;
* ScyllaDB unavailable;
* MinIO unavailable;
* ClickHouse unavailable.

### Network failures

* connection reset;
* packet loss;
* high latency;
* timeout;
* service unreachable;
* temporary partition;
* prolonged partition.

### Messaging failures

* lost response;
* duplicate submission;
* duplicate delivery;
* lost ACK;
* publisher crash;
* outbox replay;
* recipient reconnect.

### Overload

* bounded queue saturation;
* database saturation;
* connection exhaustion;
* CPU saturation;
* memory pressure;
* retry storm;
* reconnect storm.

### Recovery

* restart during active workload;
* restart after durable acceptance;
* dependency recovery;
* outbox recovery;
* delivery recovery;
* database recovery;
* graceful shutdown.

The tests must verify both:

```text
availability behavior
```

and:

```text
security + durability invariants
```

---

# 39. Implementation boundary

ADR-009 establishes the architectural resilience model.

Detailed implementation configuration will define:

* timeout values;
* retry counts;
* backoff limits;
* circuit-breaker thresholds;
* queue capacities;
* connection limits;
* rate limits;
* reconnect delays;
* health-check intervals;
* graceful-shutdown deadlines;
* emergency traffic reservation;
* recovery thresholds.

These values will be validated through benchmarks and failure testing rather than treated as architectural constants.

---

# 40. Consequences

## Positive

### Failure isolation

A failure in one component is less likely to become a system-wide outage.

### Predictable behavior

Requests fail explicitly instead of hanging indefinitely.

### Durable messaging

Accepted messages retain the guarantees established by ADR-007.

### Controlled overload

The system protects itself when demand exceeds capacity.

### Recoverability

Services can restart and reconstruct their authoritative state.

### Security preservation

Failure handling cannot silently bypass E2E security or authorization.

### Distributed-first consistency

The architecture explicitly assumes network and dependency failures rather than treating them as unusual edge cases.

---

## Negative

### Increased complexity

Timeouts, retries, circuit breakers, queues and recovery logic make the system more complex.

### More failure states

The system must distinguish:

* success;
* failure;
* timeout;
* unknown outcome;
* degraded operation;
* retry;
* recovery.

### Operational tuning

Thresholds cannot be chosen purely theoretically; they require testing.

### Potential temporary unavailability

Failing safely may mean rejecting requests rather than accepting data that cannot be durably persisted.

This is intentional.

---

# 41. Final decision summary

| Area                    | Decision                                       |
| ----------------------- | ---------------------------------------------- |
| Remote calls            | Explicit deadlines/timeouts                    |
| Retries                 | Bounded exponential backoff + jitter           |
| Retry safety            | Idempotency required                           |
| Circuit breakers        | Required where dependency failure can cascade  |
| Bulkheads               | Required                                       |
| Queues                  | Bounded                                        |
| Backpressure            | Required                                       |
| Overload                | Explicit controlled rejection/degradation      |
| Messaging durability    | ADR-007 guarantees preserved                   |
| Audit outage            | Must not block durable message acceptance      |
| Database outage         | No false durable acceptance                    |
| Lost response           | Resolve through stable idempotency identifiers |
| Service restart         | Recover from durable state                     |
| Shutdown                | Graceful                                       |
| Health                  | Liveness + readiness                           |
| Network partitions      | First-class failure                            |
| Offline operation       | Durable queues + reconnect                     |
| Reconnect storms        | Backoff + jitter + server limits               |
| Retry storms            | Explicitly prevented                           |
| Emergency traffic       | Prioritized but still bounded/durable          |
| Control-plane outage    | Runtime continues independently                |
| Security during failure | Fail closed; no insecure fallback              |
| Observability           | Required, without plaintext/secrets            |
| Exact thresholds        | Validated through ADR-010                      |

---

# 42. Architectural principle

> **SecureCloud must fail safely, fail predictably, and recover from durable state.**

A distributed failure may temporarily reduce availability.

It must not silently destroy accepted data, exhaust the entire system, bypass authorization, weaken cryptography, or cross service trust boundaries.

The goal is therefore not:

> "Never fail."

It is:

> **"When something fails, contain it, degrade safely, preserve durable state, and recover."**
