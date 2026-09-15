# SecureCloud Error Handling and Retry Rules

**Status:** Implementation Standard
**Applies to:** Gateway, Auth, Messaging, Files, Audit and client/backend communication
**Purpose:** Concrete failure, timeout, retry and recovery behavior for implementation

---

# 1. Purpose

This document defines the concrete failure-handling behavior to implement in SecureCloud.

It answers:

* what errors are retryable;
* what errors are never retryable;
* how long operations may wait;
* how retries are scheduled;
* how idempotency is enforced;
* when circuit breakers open;
* how bulkheads are implemented;
* how backpressure works;
* what happens during service failure;
* what the client receives;
* what happens after restart.

This document is an implementation policy.

It does not introduce new architecture.

---

# 2. Failure Classification

Every failure encountered by application code must be classified into one of these categories:

```text
VALIDATION
AUTHENTICATION
AUTHORIZATION
NOT_FOUND
CONFLICT
RATE_LIMITED
RESOURCE_EXHAUSTED
TRANSIENT
TIMEOUT
CANCELLED
DEPENDENCY_UNAVAILABLE
PERMANENT
INTERNAL
```

The classification determines whether the operation:

* stops immediately;
* can be retried;
* must be retried by the caller;
* should trigger circuit-breaker accounting;
* should release/requeue work.

Do not retry based only on an exception class or generic `INTERNAL` status.

---

# 3. Retryability Matrix

The following is the default policy.

| Failure                          |                   Retry internally? |              Client retry? |
| -------------------------------- | ----------------------------------: | -------------------------: |
| Validation error                 |                                  No |                         No |
| Authentication failure           |                                  No |                         No |
| Authorization failure            |                                  No |                         No |
| Not found                        |                                  No |                         No |
| Conflict                         |                                  No |                 Usually no |
| Rate limited                     |                  No immediate retry | Yes, after server guidance |
| Resource exhausted               |                  No immediate retry |         Yes, after backoff |
| Transient network failure        |               Yes if operation safe |                    Depends |
| Timeout                          | Yes only if operation is retry-safe |                    Depends |
| Connection reset before response | Yes only if operation is idempotent |                    Depends |
| Dependency unavailable           |        Yes only within retry budget |             Yes where safe |
| Permanent dependency error       |                                  No |                         No |
| Cancellation                     |                                  No |                         No |
| Internal programming error       |                                  No |                         No |

A retry must satisfy **both**:

```text
transient failure
+
operation is safely retryable
```

A transient failure alone is not sufficient.

---

# 4. Retryable Operations

## 4.1 Automatically retryable

The following may be automatically retried:

* read-only operations;
* idempotent queries;
* explicitly idempotent operations;
* idempotent file-chunk operations;
* operations where the API contract explicitly defines retry safety.

Examples:

```text
GetConversation
GetMessage
Sync
GetFileMetadata
UploadChunk
```

The implementation must still respect the retry budget and deadline.

---

## 4.2 Never transparently retry

The Gateway must not transparently retry:

```text
SendMessage
CreateConversation
AddParticipant
RegisterDevice
RevokeDevice
UploadFile
EmergencyMessageSubmission
```

unless the operation is explicitly designed with an idempotency mechanism and the implementation is using that mechanism.

The client may retry these operations using the same stable idempotency identifier.

---

# 5. Initial Retry Configuration

Unless a service has a specific documented requirement, use these initial values:

```text
max_attempts = 3
initial_backoff = 100 ms
backoff_multiplier = 2
max_backoff = 1 second
jitter = ±25%
```

Therefore, the nominal retry delays are approximately:

```text
attempt 1 → immediate
attempt 2 → ~100 ms
attempt 3 → ~200 ms
```

Random jitter is applied to avoid synchronized retries.

The overall operation deadline always takes precedence.

A retry must never extend the operation beyond its deadline.

---

# 6. Retry Algorithm

Conceptually:

```text
attempt operation

if success:
    return success

if failure is permanent:
    return failure

if operation is not retry-safe:
    return failure

if deadline exhausted:
    return timeout/failure

if retry budget exhausted:
    return failure

sleep(backoff + jitter)

retry
```

Never implement:

```text
while (!success)
    retry();
```

There must always be:

* maximum attempts;
* maximum delay;
* overall deadline.

---

# 7. Jitter

Use bounded random jitter.

For a nominal delay `D`:

```text
jittered_delay = D × random(0.75, 1.25)
```

The delay must remain bounded by the remaining deadline.

Jitter must use an appropriate random source for its purpose; it does not need to be cryptographic unless used for a security-sensitive purpose.

---

# 8. Retry Budgets

Retries consume a bounded retry budget.

A request must not independently create unlimited downstream work.

Example:

```text
Client
  ↓
Gateway
  ↓ retry
Auth
  ↓ retry
Database
```

Do not allow each layer to perform three retries independently, potentially producing nine or more attempts.

For a request path, the effective deadline and retry budget must be propagated downward.

---

# 9. Retry Amplification Rule

Avoid multiplicative retries.

Prefer:

```text
Gateway
  └── one bounded retry policy
       ↓
Auth
  └── bounded dependency retry where necessary
```

rather than:

```text
Gateway: 3 retries
Auth: 3 retries
DB: 3 retries
```

which can amplify one request into many operations.

Each layer should normally retry only failures it directly understands and owns.

---

# 10. Deadlines

Every remote operation must have a deadline.

Initial implementation defaults:

| Operation class                |                                             Initial deadline |
| ------------------------------ | -----------------------------------------------------------: |
| Gateway → Auth simple request  |                                                          1 s |
| Gateway → Messaging command    |                                                          2 s |
| Gateway → Messaging read/query |                                                          2 s |
| Gateway → Files metadata       |                                                          2 s |
| Gateway → Audit                |                                                          1 s |
| Internal service request       |                                                        1–2 s |
| File streaming                 | No fixed whole-transfer timeout; use inactivity/idle timeout |
| Database operation             |                                 ≤ remaining request deadline |

These are starting implementation values.

They must be configurable and validated at startup.

Performance/resilience testing may tune them.

---

# 11. Deadline Propagation

A downstream deadline must never exceed the remaining upstream deadline.

Example:

```text
Client deadline:       2000 ms
        ↓
Gateway remaining:     1800 ms
        ↓
Messaging RPC:         1700 ms
        ↓
Scylla operation:      ≤ remaining budget
```

Do not reset the timer at every layer.

Bad:

```text
Gateway timeout = 2 s
Messaging timeout = 2 s
Scylla timeout = 2 s
```

This can cause a request to remain alive much longer than intended.

---

# 12. Timeout Semantics

A timeout means:

> The caller no longer waits for the operation.

A timeout does **not** necessarily mean:

> The operation definitely did not happen.

This distinction is critical for non-idempotent operations.

Example:

```text
Client → SendMessage
           ↓
Messaging persists message
           ↓
network response lost
           ↓
Client sees timeout
```

The client must assume the outcome is **unknown**, not automatically failed.

The client retries using the same idempotency ID.

---

# 13. Unknown Outcome

For operations with possible durable side effects, distinguish:

```text
SUCCESS
FAILURE
UNKNOWN
```

`UNKNOWN` occurs when:

* the request may have reached the server;
* the server may have completed it;
* the response was lost;
* the client cannot determine the result.

Do not automatically create a second logical operation.

Use the operation's idempotency key to recover the original result.

---

# 14. Idempotency Storage

For idempotent commands, the owning service maintains the idempotency record according to the service's persistence model.

Conceptually:

```text
idempotency_key
        ↓
existing result?
   ↙          ↘
 yes           no
 ↓             ↓
return       execute
stored       operation
result          ↓
             store result
```

Concurrent requests using the same key must not execute the operation twice.

The implementation must provide atomic protection against:

```text
Request A checks key → absent
Request B checks key → absent
Request A executes
Request B executes
```

---

# 15. Idempotency Conflict

If the same idempotency key is reused with a materially different request, reject it.

Example:

```text
key = ABC

first request:
message = ciphertext X

second request:
message = ciphertext Y
```

The second request must not be treated as the same operation.

Return a stable conflict error.

---

# 16. Idempotency Retention

Idempotency records must be retained long enough to cover realistic client retries and delayed duplicate submissions.

The exact retention period is configurable.

Initial implementation target:

```text
24 hours
```

For security-sensitive operations such as device lifecycle operations, retention must follow the operation's security semantics and must not be shorter than the required replay-protection window.

---

# 17. Circuit Breakers

Circuit breakers protect a service from repeatedly calling an unhealthy dependency.

Each important outbound dependency should have its own circuit state.

Example:

```text
Gateway → Auth
Gateway → Messaging
Gateway → Files
```

Do not use one global circuit breaker for all dependencies.

---

# 18. Circuit States

Use:

```text
CLOSED
OPEN
HALF_OPEN
```

### CLOSED

Normal operation.

Failures are counted.

### OPEN

Calls fail immediately without contacting the dependency.

### HALF_OPEN

A limited number of probe requests are allowed.

If healthy:

```text
HALF_OPEN → CLOSED
```

If unhealthy:

```text
HALF_OPEN → OPEN
```

---

# 19. Initial Circuit-Breaker Configuration

Use these initial values:

```text
failure window = 10 seconds
minimum requests before evaluation = 20
open threshold = 50% failures
open duration = 5 seconds
half-open probes = 2
```

A circuit should not open because of one isolated failure.

Only count failures that indicate dependency unavailability/transient failure.

Do not count:

* validation errors;
* authentication errors;
* authorization errors;
* not-found responses;
* expected business conflicts

as dependency failures.

---

# 20. Circuit Breaker Behavior

When the circuit is OPEN:

```text
request
  ↓
circuit breaker
  ↓
reject immediately
```

Do not wait for the dependency timeout.

Return an appropriate dependency-unavailable error.

For security-sensitive operations, fail closed.

---

# 21. Half-Open Protection

Only a small number of probe requests may pass during HALF_OPEN.

All other requests fail fast.

Do not allow a recovering dependency to receive a sudden full production load.

---

# 22. Bulkheads

Resource pools must be isolated by workload.

At minimum, Messaging separates:

```text
submission
delivery
synchronization
```

Files separates:

```text
metadata
upload
download
```

A flood of file uploads must not consume every worker needed for metadata operations.

A delivery backlog must not prevent new message submission from being processed.

---

# 23. Bulkhead Configuration

Initial implementation should use independently bounded pools/permits.

Example conceptual configuration:

```text
Messaging
    submission permits       64
    delivery permits        128
    synchronization permits 32

Files
    metadata permits         32
    upload permits           32
    download permits        32
```

These values are **initial implementation defaults**, not final capacity claims.

They must be configurable and measured during performance testing.

The important invariant is:

> one workload class cannot consume all resources belonging to another workload class.

---

# 24. Backpressure

Backpressure is mandatory wherever producers can generate work faster than consumers can process it.

Pipeline:

```text
Producer
   ↓
bounded buffer
   ↓
worker
   ↓
downstream dependency
```

If the buffer is full:

```text
stop accepting more work
        OR
reject/defer according to operation semantics
```

Never respond by increasing memory indefinitely.

---

# 25. Message Backpressure

Messaging must prioritize durable acceptance over optional downstream delivery work.

Conceptually:

```text
Message submission
      ↓
durable acceptance
      ↓
delivery scheduling
```

Delivery overload must not prevent the system from persisting accepted messages unless the service's bounded resource policy explicitly reaches its global safety limit.

Do not block the entire submission path behind an unbounded delivery queue.

---

# 26. Delivery Backpressure

Delivery workers must operate on bounded scheduling capacity.

When delivery capacity is exhausted:

```text
message remains durably queued
        ↓
delivery scheduler retries later
```

The authoritative state remains persistent.

In-memory scheduling structures are not the source of truth.

---

# 27. Priority Handling

Messaging priorities:

```text
NORMAL
URGENT
EMERGENCY
```

Priority may influence scheduling.

Priority must **not**:

* bypass authorization;
* bypass encryption;
* bypass durability;
* bypass resource limits;
* create unlimited emergency work;
* starve normal traffic indefinitely.

Use bounded fairness.

A practical implementation may use weighted scheduling or reserved capacity.

---

# 28. Files Backpressure

File transfers use bounded streaming buffers.

Conceptually:

```text
HTTP receive
   ↓
bounded Gateway buffer
   ↓
gRPC stream
   ↓
bounded Files buffer
   ↓
MinIO
```

When MinIO/storage slows:

```text
storage slows
   ↓
Files slows
   ↓
gRPC stream applies backpressure
   ↓
Gateway slows
   ↓
client upload slows
```

Do not buffer the complete file in memory.

---

# 29. Connection Pool Exhaustion

Database and storage connection pools must be bounded.

When a pool is exhausted:

* wait only within a bounded timeout;
* then return `RESOURCE_EXHAUSTED` or dependency-unavailable semantics as appropriate.

Never create a new connection for every request when the pool is exhausted.

---

# 30. Service Unavailability

When a backend service is unavailable:

### Gateway

Return a stable dependency-unavailable error.

Do not:

* fabricate success;
* fabricate message IDs;
* pretend a message was accepted;
* bypass authorization;
* fall back to another service that does not own the data.

---

# 31. Auth Unavailability

Auth is authoritative for:

* authentication;
* sessions;
* token state;
* device authorization/revocation;
* security-sensitive authorization state.

If required Auth information cannot be obtained:

* authentication fails;
* security-sensitive authorization fails closed;
* device lifecycle operations fail closed.

Do not assume that a stale cache proves that a revoked device is still authorized.

---

# 32. Messaging Unavailability

If Messaging is unavailable:

```text
Gateway → Messaging
          X
```

Gateway returns dependency-unavailable.

The client may retry according to the operation's retry semantics.

For `SendMessage`, the client must reuse the same idempotency identifier.

---

# 33. Files Unavailability

If Files is unavailable:

* metadata operations fail with dependency-unavailable;
* uploads/downloads terminate or pause according to transfer semantics;
* resumable transfers retain their durable state where already persisted.

The client must be able to resume an interrupted transfer.

---

# 34. Audit Unavailability

Audit processing must not normally block message durable acceptance.

If Audit is unavailable:

```text
business operation
      ↓
outbox event persisted
      ↓
business operation succeeds
      ↓
Audit processes later
```

The outbox is the durability boundary.

Do not discard an audit event merely because Audit is temporarily unavailable.

---

# 35. Outbox Retry

Outbox processing uses a separate bounded retry policy.

Initial values:

```text
max attempts per scheduling cycle = 3
initial delay = 250 ms
multiplier = 2
max delay = 30 s
jitter = ±25%
```

If the event remains unavailable after retries:

```text
persist event
keep pending
retry later
```

Do not spin continuously on one failed event.

---

# 36. Dead-Letter / Poison Events

If an event repeatedly fails because of malformed or incompatible data, it must not create an infinite retry loop.

The implementation must provide a controlled terminal handling mechanism.

At minimum:

```text
PENDING
  ↓
PROCESSING
  ↓
SUCCESS

or

PENDING
  ↓
RETRY_WAIT
  ↓
...
  ↓
FAILED / QUARANTINED
```

Quarantined events must remain observable for operational investigation.

Never silently delete a durable event because processing failed.

---

# 37. Graceful Shutdown

Shutdown sequence:

```text
1. stop accepting new external work
2. stop creating new internal work
3. signal cancellation
4. stop schedulers
5. finish safe in-flight operations
6. persist required state
7. flush/retain outbox work
8. close streams
9. stop workers
10. close DB/storage connections
11. exit
```

Do not terminate worker threads abruptly while they may be modifying durable state.

---

# 38. In-Flight Requests During Shutdown

Each service has a bounded shutdown grace period.

Initial default:

```text
10 seconds
```

After the grace period:

* remaining cancellable operations are cancelled;
* durable state already committed remains authoritative;
* unfinished non-durable work is discarded/retried by the appropriate higher-level mechanism.

The service must not claim success for work that was not completed.

---

# 39. Restart Recovery

After restart:

### Messaging

Recover from persistent:

* messages;
* delivery state;
* retry state;
* synchronization state;
* outbox events.

In-memory scheduling state may be reconstructed.

### Files

Recover from:

* transfer state;
* file metadata;
* MinIO object state.

Incomplete transfers remain resumable where their durable state permits.

### Auth

Recover:

* sessions;
* refresh-token state;
* device state;
* MFA/security state;
* crypto directory;
* revocation state.

### Audit

Recover pending outbox/audit processing.

---

# 40. No Memory as Source of Truth

Do not make correctness depend on in-memory state.

Examples:

Forbidden:

```text
message queue exists only in RAM
delivery state exists only in RAM
revocation exists only in RAM
file transfer state exists only in RAM
```

Memory may accelerate processing.

Persistent state determines correctness.

---

# 41. Duplicate Delivery

Messaging uses at-least-once delivery.

Therefore duplicates are expected.

The recipient client must deduplicate using:

```text
message_id
```

The backend must not assume that a delivery attempt is exactly-once.

A successful delivery ACK means:

> the recipient device durably accepted the encrypted message.

It does not mean that every network hop delivered exactly once.

---

# 42. Delivery Retry

Delivery worker behavior:

```text
load durable pending delivery
        ↓
attempt delivery
        ↓
success?
   ↙          ↘
 yes           no
 ↓             ↓
DELIVERED   classify error
              ↓
          retryable?
           ↙      ↘
         yes       no
          ↓         ↓
      RETRY_WAIT  terminal state
```

Retry scheduling is persistent enough to survive service restart.

In-memory timers are only scheduling optimizations.

---

# 43. Delivery Retry Backoff

Initial delivery retry policy:

```text
attempt 1 → immediate
attempt 2 → 1 s
attempt 3 → 5 s
attempt 4 → 30 s
attempt 5 → 2 min
```

After that, continue with a bounded configurable policy until:

* delivery succeeds;
* message expires;
* recipient/device is permanently unavailable;
* policy-defined terminal state is reached.

Add bounded jitter to avoid synchronized retries.

Exact long-term retry duration is configurable.

---

# 44. Revoked Device

If a device is revoked:

* new deliveries to that device must stop;
* pending future deliveries must not be sent to it;
* the device may retain/decrypt content it already legitimately received;
* revocation must not retroactively erase already-delivered ciphertext.

Delivery workers must re-check the authoritative device state before performing a security-sensitive delivery.

A stale cache must never override a known revocation.

---

# 45. Network Partition

During a network partition:

```text
service A
   X
service B
```

Do not invent local success for operations requiring the unavailable service.

Use:

* bounded waiting;
* timeout;
* circuit breaker;
* retry if safe;
* durable local state if the operation's design permits it.

The system must remain internally consistent even if availability temporarily decreases.

---

# 46. Dependency Recovery

When a circuit transitions:

```text
OPEN → HALF_OPEN
```

only probe requests are allowed.

After successful probes:

```text
HALF_OPEN → CLOSED
```

Normal traffic resumes gradually according to the resource limits.

Do not immediately remove all limits after recovery.

---

# 47. Client Behavior

The client must classify responses.

### Immediate failure

Examples:

```text
AUTHENTICATION_ERROR
AUTHORIZATION_ERROR
VALIDATION_ERROR
NOT_FOUND
CONFLICT
```

Do not automatically retry.

### Temporary failure

Examples:

```text
TIMEOUT
DEPENDENCY_UNAVAILABLE
RESOURCE_EXHAUSTED
RATE_LIMITED
```

Retry according to the operation contract.

### Unknown result

For commands with possible side effects:

```text
request timed out / connection lost
```

The client must recover using the operation's idempotency identifier or status/query mechanism.

---

# 48. User-Visible Error Handling

Internal failures must be converted to concise user-facing states.

Do not display:

```text
Scylla timeout
gRPC UNAVAILABLE
PostgreSQL connection refused
std::runtime_error(...)
```

Instead display an appropriate application-level message such as:

```text
"SecureCloud is temporarily unavailable. Please try again."
```

Detailed technical information belongs in protected logs/telemetry.

---

# 49. Logging Failure Events

A retryable failure should normally log:

```text
service
operation
dependency
failure_category
attempt
request_id
duration
```

Do not log:

* plaintext messages;
* file plaintext;
* authentication secrets;
* private keys;
* tokens.

Avoid logging the same failure at every layer at high severity.

The layer that makes the final decision should provide the principal operational log.

---

# 50. Metrics

The implementation should expose metrics for:

### Requests

```text
request_total
request_failure_total
request_duration
```

### Retries

```text
retry_total
retry_exhausted_total
```

### Circuit breakers

```text
circuit_open_total
circuit_state
```

### Resources

```text
worker_utilization
queue_depth
connection_pool_usage
buffer_usage
resource_exhaustion_total
```

### Messaging

```text
accepted_messages
delivery_attempts
delivery_failures
delivery_latency
pending_deliveries
```

### Files

```text
active_uploads
active_downloads
transfer_failures
bytes_transferred
```

Metrics must not contain message plaintext or sensitive cryptographic material.

---

# 51. Failure-Injection Requirements

Before considering resilience implementation complete, test at least:

* dependency unavailable;
* connection refused;
* connection reset;
* request timeout;
* response timeout;
* service restart;
* database unavailable;
* storage unavailable;
* circuit opening;
* circuit recovery;
* queue/resource exhaustion;
* duplicate command;
* lost response after durable acceptance;
* cancellation during operation;
* shutdown during operation.

---

# 52. Concrete Failure Scenarios

## Scenario A — SendMessage response lost

```text
Client
  ↓ SendMessage(idempotency=A)
Gateway
  ↓
Messaging
  ↓
message durably accepted
  ↓
response lost
  X
Client
```

Client state:

```text
UNKNOWN
```

Client retries:

```text
SendMessage(idempotency=A)
```

Messaging finds existing idempotency record and returns the original result.

No duplicate logical message is created.

---

## Scenario B — Messaging unavailable

```text
Client
  ↓
Gateway
  ↓
Messaging
  X
```

Gateway:

1. detects unavailable dependency;
2. does not retry unsafe command transparently;
3. returns dependency-unavailable;
4. client may retry using the same idempotency key.

---

## Scenario C — Files storage slows down

```text
MinIO
  ↓ slow
Files
  ↓ backpressure
gRPC
  ↓ backpressure
Gateway
  ↓
Client
```

Memory usage remains bounded.

The upload becomes slower rather than causing unlimited buffering.

---

## Scenario D — Auth unavailable

```text
Gateway
  ↓
Auth
  X
```

Gateway does not invent authentication success.

Security-sensitive requests fail closed.

---

## Scenario E — Audit unavailable

```text
Messaging
  ↓
transaction
 ├── message
 ├── delivery state
 └── outbox event
       ↓
   COMMIT

Audit
  X

outbox remains pending
```

Message acceptance succeeds.

Audit processing resumes later.

---

# 53. Implementation Components

The following components should own the corresponding behavior where appropriate:

```text
RetryPolicy
RetryExecutor
DeadlineManager
CircuitBreaker
Bulkhead
BackpressureController
IdempotencyStore
FailureClassifier
CancellationHandler
OutboxRetryScheduler
DeliveryRetryScheduler
```

Do not create separate implementations of the same retry/circuit logic in every service if a common technical abstraction can safely provide the mechanism.

Business decisions remain service-owned.

---

# 54. Implementation Order

Implement resilience in this order:

### Step 1 — Failure types

Create a consistent internal failure/error representation.

### Step 2 — Deadlines

Implement deadline propagation for gRPC/database/storage operations.

### Step 3 — Retry policy

Implement:

* retry classification;
* attempt limit;
* exponential backoff;
* jitter;
* deadline awareness.

### Step 4 — Idempotency

Implement the idempotency mechanism for command operations.

### Step 5 — Cancellation

Propagate request cancellation.

### Step 6 — Bulkheads

Create independent bounded resource domains.

### Step 7 — Backpressure

Enforce bounded queues/buffers and streaming flow control.

### Step 8 — Circuit breakers

Add dependency-specific circuit breakers.

### Step 9 — Recovery

Implement restart recovery for durable schedulers/outboxes/transfers.

### Step 10 — Failure tests

Inject failures and verify the behavior described in this document.

---

# 55. Initial Configuration Summary

The following values are the starting implementation configuration:

```text
General retry:
    attempts:              3
    initial backoff:       100 ms
    multiplier:            2
    maximum backoff:       1 s
    jitter:                ±25%

Circuit breaker:
    evaluation window:    10 s
    minimum requests:     20
    failure threshold:    50%
    open duration:         5 s
    half-open probes:      2

Shutdown:
    grace period:         10 s

Idempotency:
    initial retention:    24 h

Messaging delivery:
    retry delays:
        immediate
        1 s
        5 s
        30 s
        2 min

Outbox:
    initial retry:        250 ms
    multiplier:            2
    maximum delay:        30 s
    jitter:               ±25%
```

These values are intentionally configurable.

They are the **baseline for implementation**, not values that developers should postpone implementation waiting to benchmark.

---

# 56. Rules Developers Must Not Violate

A developer must not introduce:

* unlimited retries;
* retry loops without deadlines;
* thread creation per retry;
* unbounded queues;
* unbounded buffering;
* transparent retry of unsafe commands;
* success responses after uncertain durability;
* fabricated success when a dependency is unavailable;
* stale authorization overriding revocation;
* memory-only authoritative state;
* retry amplification across service layers;
* circuit breakers shared indiscriminately across unrelated dependencies;
* cancellation that silently breaks durability;
* deletion of durable work because processing failed.

---

# 57. Definition of Done

Error-handling implementation is complete when:

* [ ] Every remote call has a deadline.
* [ ] Retryability is explicitly classified.
* [ ] Retry attempts are bounded.
* [ ] Backoff and jitter are implemented.
* [ ] Unsafe operations are not transparently retried.
* [ ] Idempotent commands handle duplicate requests.
* [ ] Unknown outcomes are handled correctly.
* [ ] Circuit breakers exist for required dependencies.
* [ ] Workloads have bounded resource pools.
* [ ] Queues/buffers are bounded.
* [ ] Backpressure propagates correctly.
* [ ] Cancellation propagates.
* [ ] Durable state survives restart.
* [ ] Outbox processing survives dependency failure.
* [ ] Delivery retries survive restart.
* [ ] Service shutdown is graceful.
* [ ] Failure-injection tests cover the critical scenarios.
* [ ] Metrics exist for retries, failures, resources and recovery.
* [ ] No sensitive data appears in failure logs.

---

# 58. Final Implementation Rule

When a failure occurs, the implementation must make an explicit decision:

```text
FAIL FAST
RETRY
WAIT
QUEUE
REJECT
DEGRADE
OR RECOVER
```

There must be no accidental behavior such as:

```text
catch (...)
{
    // try again
}
```

or:

```text
catch (...)
{
    // ignore
}
```

Every failure path must have a defined owner, bounded resource cost, and observable outcome.
