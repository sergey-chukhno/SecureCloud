# SecureCloud Coding Rules

**Status:** Implementation Standard
**Applies to:** C++20 client and backend services
**Primary goal:** Secure, correct, maintainable, predictable and testable implementation

---

## 1. Purpose

This document defines the coding and implementation rules for SecureCloud.

It translates the approved architecture, ADRs and detailed design into concrete engineering rules for developers.

These rules apply to:

* Gateway
* Auth
* Messaging
* Files
* Audit
* C++20 client
* shared technical infrastructure in `src/common`

This document does **not** redefine:

* service boundaries;
* persistence technology choices;
* API contracts;
* cryptographic protocols;
* architectural decisions;
* product requirements.

If a coding rule conflicts with an approved architectural decision, the architectural source of truth wins and the conflict must be raised explicitly.

---

# 2. Engineering Priorities

When engineering concerns conflict, use this priority order:

1. **Security**
2. **Correctness**
3. **Durability**
4. **Failure isolation**
5. **Predictable performance**
6. **Maintainability**
7. **Optimization**
8. **Convenience**

Never sacrifice security or correctness for a benchmark result.

Never introduce an optimization that changes a required security, durability or correctness invariant without an explicit architectural review.

---

# 3. C++ Standard and General Rules

## 3.1 Language standard

SecureCloud uses:

* C++20
* modern standard-library facilities
* RAII
* strong type usage
* const-correctness
* deterministic resource ownership

Compiler warnings must be enabled and treated as errors where practical.

The codebase must remain portable across the supported development/build environments.

---

## 3.2 Prefer simple modern C++

Prefer:

* `std::unique_ptr`
* `std::shared_ptr` only when shared ownership is genuinely required
* `std::string`
* `std::string_view`
* `std::span`
* `std::optional`
* `std::variant`
* `std::expected` where the selected toolchain/library strategy provides it
* containers from the standard library
* scoped enums
* `constexpr`
* concepts where they materially improve interfaces
* ranges where they improve readability

Avoid unnecessary abstraction.

Do not introduce templates, concepts or generic frameworks merely to demonstrate advanced C++.

---

# 4. Ownership and Lifetime

## 4.1 RAII is mandatory

Resources must be owned by objects whose destructors release them.

This applies to:

* files
* sockets
* database connections
* gRPC streams
* locks
* threads
* memory
* cryptographic resources
* temporary resources

Do not manually pair `new`/`delete` in application code.

Bad:

```text
resource = acquire();
...
release(resource);
```

Preferred:

```text
Resource resource = acquire();
```

with deterministic destruction.

---

## 4.2 Ownership must be explicit

Use:

* `std::unique_ptr` for exclusive ownership.
* `std::shared_ptr` only when multiple components genuinely share lifetime ownership.
* references/pointers for non-owning relationships.

Do not use `shared_ptr` as a default replacement for understanding ownership.

Every `shared_ptr` should have an identifiable ownership reason.

---

## 4.3 Raw pointers

Raw pointers may represent:

* nullable non-owning references;
* interoperability with external libraries;
* low-level infrastructure where ownership is explicitly documented.

Raw owning pointers are forbidden in normal application code.

---

# 5. Const-Correctness and Immutability

Prefer immutable data where practical.

Use:

* `const`
* `constexpr`
* `const` references
* immutable value objects

when mutation is not required.

Do not expose mutable internal state unnecessarily.

Prefer:

```text
const Message&
```

over:

```text
Message&
```

when the callee does not modify the object.

---

# 6. Strong Types

Avoid representing security-sensitive concepts as interchangeable primitive values.

For example, do not casually pass:

```text
std::string user_id
std::string device_id
std::string session_id
```

through a large API where they can be confused.

Prefer explicit domain/value types where the distinction matters:

```text
UserId
DeviceId
SessionId
MessageId
ConversationId
TransferId
```

The same principle applies to:

* authentication levels;
* message priority;
* delivery states;
* device states;
* transfer states;
* cryptographic identifiers;
* authorization capabilities.

Enums must normally be `enum class`.

---

# 7. Error Handling

## 7.1 Errors must be explicit

Every operation that can fail must have defined failure semantics.

Do not silently ignore:

* authentication failures;
* authorization failures;
* database failures;
* network failures;
* serialization failures;
* cryptographic failures;
* persistence failures;
* resource-limit failures.

---

## 7.2 Exceptions

Exceptions may be used internally where the selected library/API design uses them naturally.

However:

* do not use exceptions for normal control flow;
* do not allow unexpected exceptions to cross service boundaries;
* convert failures into defined application/API error semantics at boundaries;
* never catch an exception and silently continue;
* preserve the security-sensitive distinction between failure classes.

---

## 7.3 Error propagation

Errors should be handled at the layer capable of making the correct decision.

Typical flow:

```text
Infrastructure failure
        ↓
Infrastructure error
        ↓
Application decision
        ↓
API/domain error
        ↓
Transport response
```

Do not expose:

* SQL errors;
* filesystem paths;
* stack traces;
* cryptographic internals;
* internal service topology;
* secrets

to clients.

---

# 8. Input Validation

All externally controlled input is untrusted.

Validate at service boundaries before processing.

Validation includes:

* size;
* format;
* required fields;
* ranges;
* enum values;
* identifiers;
* authorization context;
* protocol version;
* state transitions.

Do not rely exclusively on client-side validation.

Backend validation remains authoritative.

---

## 8.1 Validate before expensive work

Reject invalid requests before:

* database operations;
* large allocations;
* cryptographic operations;
* file processing;
* expensive serialization;
* spawning asynchronous work.

Resource limits are part of validation.

---

## 8.2 Never trust metadata from clients

Client-provided:

* user IDs;
* device IDs;
* ownership information;
* roles;
* permissions;
* timestamps;
* message state;
* file state

must not be treated as authoritative.

Derive authoritative security context from authenticated server-side state.

---

# 9. Authentication and Authorization

Authentication and authorization must never be confused.

Authentication answers:

> Who is this authenticated principal?

Authorization answers:

> Is this principal allowed to perform this operation?

Gateway performs coarse route/scope authorization.

Services perform resource and business authorization.

Never rely on the Gateway alone for service-level authorization.

---

## 9.1 Fail closed

Security failures must fail closed.

Examples:

* invalid token → reject;
* expired token → reject;
* revoked device → reject;
* insufficient authentication level → reject;
* unknown authorization state → reject;
* failed crypto operation → reject;
* unavailable critical authorization dependency → reject where required by the operation.

Never fabricate successful authorization because a dependency is unavailable.

---

# 10. Secrets

Secrets must never be committed to the repository.

Never place in:

* source code;
* test fixtures;
* logs;
* exception messages;
* Git history;
* API responses;
* configuration committed to Git.

Examples include:

* passwords;
* private keys;
* signing keys;
* service private certificates;
* refresh tokens;
* access tokens;
* encryption keys.

Development secrets must use an explicit local/development mechanism and must not become production credentials.

---

# 11. Cryptographic Rules

## 11.1 No custom cryptography

SecureCloud must use vetted cryptographic libraries and the approved Signal Protocol-family design.

Do not implement:

* custom encryption;
* custom key exchange;
* custom ratchets;
* custom MAC constructions;
* custom password hashing;
* homemade random generators.

Do not modify cryptographic primitives without an explicit security review.

---

## 11.2 Private keys

Private device keys:

* remain on the endpoint;
* must never be sent to backend services;
* must never be logged;
* must never be included in telemetry;
* must never be persisted in ordinary application databases.

Use platform secure storage where available.

---

## 11.3 Cryptographic failure

Cryptographic failure is a hard failure.

Never:

* fall back to plaintext;
* downgrade silently;
* accept unverifiable ciphertext;
* continue after failed authentication/integrity verification.

---

## 11.4 Randomness

Security-sensitive randomness must come from a cryptographically secure random source.

Never use:

* `rand()`;
* timestamps;
* predictable counters;
* UUID generation intended only for identification

as a substitute for cryptographic randomness.

---

# 12. Sensitive Data Handling

SecureCloud handles sensitive information.

Code must follow data minimization.

Do not log:

* plaintext messages;
* decrypted files;
* private keys;
* passwords;
* access tokens;
* refresh tokens;
* encryption keys;
* complete authentication secrets.

Avoid logging sensitive metadata unless explicitly required.

When logging identifiers, prefer opaque identifiers and controlled redaction.

---

# 13. Logging

Logs must be:

* structured;
* useful for diagnosis;
* bounded;
* security-conscious.

Log:

* service/component;
* operation;
* outcome;
* error category;
* correlation/request identifier where appropriate;
* safe opaque identifiers.

Do not log entire request/response bodies by default.

Debug logging must not accidentally expose secrets or plaintext.

---

# 14. Concurrency

Concurrency must be explicit and bounded.

Never create unbounded concurrency based directly on external input.

Avoid:

```text
one request → one permanent thread
one transfer → one permanent thread
one message → one permanent thread
```

Use bounded:

* worker pools;
* asynchronous I/O;
* task queues;
* concurrency limits;
* resource pools.

---

## 14.1 No unbounded queues

Every queue or buffer must have a bounded capacity or an explicitly bounded resource model.

When capacity is exhausted:

* apply backpressure;
* reject;
* defer;
* shed lower-priority work where the approved policy allows it.

Never allow memory usage to grow without bound.

---

## 14.2 Mutex discipline

Locks must have:

* clear ownership;
* narrow scope;
* documented invariants where non-obvious.

Never hold a mutex while performing unnecessary:

* network I/O;
* database I/O;
* filesystem I/O;
* blocking external calls.

Avoid nested locks.

If multiple locks are unavoidable, establish and consistently follow a lock ordering.

---

## 14.3 Data races

Data races are bugs.

Use:

* immutable data;
* ownership transfer;
* message passing;
* mutexes;
* atomics

according to the actual synchronization requirement.

Do not use atomics simply to avoid designing proper ownership.

---

# 15. Worker Pools and Runtime Resources

Each service must explicitly define its bounded runtime resources.

Examples:

* worker count;
* DB connections;
* gRPC streams;
* concurrent transfers;
* concurrent deliveries;
* memory buffers;
* queued tasks;
* storage operations.

Do not allow thread pools or connection pools to grow automatically without a defined limit.

Runtime resource limits must be configurable where appropriate.

---

# 16. Cancellation, Deadlines and Timeouts

Blocking operations must have defined timeout/deadline behavior where supported.

This applies especially to:

* gRPC;
* database calls;
* external storage;
* network operations.

Cancellation must propagate through the operation chain.

Example:

```text
Client disconnect
      ↓
Gateway cancellation
      ↓
gRPC cancellation
      ↓
Service operation cancellation
      ↓
Storage/network cancellation
```

Do not continue expensive work after the caller has definitively cancelled it unless the operation is explicitly required for durability or consistency.

---

# 17. Retry Rules

Retries must be deliberate.

Retry only when:

1. the error is transient;
2. the operation is safe to retry;
3. the remaining deadline permits it;
4. the retry is bounded.

Use:

* exponential backoff;
* jitter;
* maximum attempts;
* overall deadline.

Never create retry storms.

Do not automatically retry non-idempotent operations unless the operation has an explicit idempotency mechanism.

---

# 18. Idempotency

Operations that may be retried must have deterministic duplicate handling.

Important examples:

* message submission;
* conversation creation;
* participant changes;
* device registration;
* device revocation;
* file upload/chunk submission.

Use stable identifiers/idempotency keys where specified by the design.

Duplicate requests must not silently create duplicate domain effects.

---

# 19. Database Rules

## 19.1 Ownership

Each service accesses only its own persistence.

Forbidden:

```text
Messaging → Auth database
Gateway → Messaging database
Files → Auth database
```

Inter-service communication must use the defined service API.

---

## 19.2 Transactions

Use transactions to protect local invariants.

Do not introduce distributed transactions as the normal mechanism.

For durable event publication, follow the approved transactional-outbox design.

---

## 19.3 Query discipline

Database operations must be:

* parameterized;
* bounded;
* observable;
* cancellable/timeout-aware where supported;
* reviewed for indexing and query complexity.

Never construct SQL through unsafe string concatenation.

---

## 19.4 N+1 operations

Avoid accidental N+1 database access.

For any high-volume path, explicitly consider:

* query count;
* batch operations;
* indexes;
* partitioning;
* pagination;
* consistency requirements.

---

# 20. ScyllaDB / Messaging Rules

Messaging is designed around recipient/device-oriented access patterns.

Code must respect the approved partitioning model.

Do not introduce:

* one global message queue;
* one global partition;
* global ordering requirements;
* scans across the complete message dataset

for normal message delivery.

Queries must match known access patterns.

Avoid unbounded partitions and hot partitions.

---

# 21. PostgreSQL Rules

PostgreSQL is used by:

* Auth;
* Files metadata.

Keep database logic inside the owning service's infrastructure layer.

Use:

* explicit transactions;
* prepared/parameterized statements;
* indexes matching real access patterns;
* bounded queries;
* pagination for potentially large result sets.

Do not rely on accidental query planner behavior for correctness.

---

# 22. Files and Streaming

File processing must be streaming-oriented.

Do not load an entire large file into memory unless the file size is explicitly bounded and the operation requires it.

Use:

```text
Client
  ↓
Gateway streaming
  ↓
gRPC streaming
  ↓
Files
  ↓
MinIO
```

with bounded buffers and backpressure.

---

## 22.1 File encryption

Files are encrypted client-side.

Backend code must treat file content as opaque ciphertext.

The Files service must not contain logic that assumes it can decrypt user file content.

---

## 22.2 Chunk processing

Chunk operations must be:

* bounded;
* independently addressable;
* idempotent;
* resumable.

Never assume that a transfer completes in one network connection.

---

# 23. gRPC and Protobuf

Generated Protobuf/gRPC code must not be manually modified.

Contracts are authoritative.

Validate:

* request size;
* required fields;
* enum/state validity;
* authorization context;
* protocol assumptions.

Do not expose internal implementation classes directly through RPC interfaces.

RPC handlers should:

1. validate request;
2. authenticate/authorize where required;
3. translate transport data to application/domain input;
4. execute the use case;
5. map the result to the transport contract.

Do not place large business workflows directly in RPC handlers.

---

# 24. REST / Gateway Rules

Gateway handlers must remain thin.

Typical flow:

```text
HTTP request
    ↓
TLS / transport handling
    ↓
Request validation
    ↓
Access token verification
    ↓
Route/scope authorization
    ↓
Application/service call
    ↓
Response mapping
```

Do not put business logic or database access in HTTP handlers.

---

# 25. State Machines

Security- and reliability-sensitive state transitions must be explicit.

Examples:

### Message

```text
QUEUED
  ↓
DELIVERING
  ↓
DELIVERED
  ↓
READ
```

with appropriate retry/expiry transitions.

### File

```text
CREATED
  ↓
UPLOADING
  ↓
FINALIZING
  ↓
AVAILABLE
```

Invalid state transitions must be rejected.

Do not represent important state machines as scattered boolean flags.

---

# 26. Memory Management

Avoid unnecessary allocations in hot paths.

Pay particular attention to:

* message delivery;
* serialization;
* network buffers;
* file streaming;
* database result processing;
* cryptographic operations.

Prefer:

* move semantics;
* references;
* views/spans;
* reusable bounded buffers

where correctness remains clear.

Do not optimize allocations prematurely.

Measure first.

---

# 27. Performance Rules

The target of **10,000 accepted messages/second peak** is an architectural capacity target, not a justification for unsafe shortcuts.

Performance work follows:

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
Optimize
  ↓
Benchmark again
  ↓
Verify correctness/security
```

Never optimize based only on intuition.

---

## 27.1 Hot-path discipline

Identify hot paths explicitly.

Examples:

* message acceptance;
* message persistence;
* message delivery;
* synchronization;
* authentication token validation;
* file chunk transfer.

Hot-path optimizations must preserve:

* security;
* durability;
* ordering guarantees where required;
* idempotency;
* failure semantics.

---

# 28. Caching

Caches are optimizations, not authorities, unless explicitly designed otherwise.

A cache must never silently override authoritative security state.

Especially:

* device revocation;
* MFA state;
* critical authorization;
* credential state.

Cache invalidation behavior must be defined.

---

# 29. Common Code

`src/common` may contain only genuinely shared technical infrastructure.

Examples:

* logging;
* error primitives;
* configuration utilities;
* transport helpers;
* common serialization utilities;
* technical resource-management utilities.

Do not put shared business/domain models in `common` merely to avoid duplication.

Avoid creating a "god library" that every service depends on.

---

# 30. Dependency Rules

Dependencies must point toward stable abstractions and domain logic.

Backend:

```text
API
 ↓
Application
 ↓
Domain
 ↑
Infrastructure
```

Infrastructure implements interfaces required by application/domain layers.

Domain code must not depend on:

* PostgreSQL;
* ScyllaDB;
* MinIO;
* gRPC;
* HTTP;
* Qt;
* Docker;
* Kubernetes.

---

# 31. Client Architecture Rules

The client follows:

```text
UI
 ↓
Application
 ↓
Domain
 ↓
Infrastructure
```

UI code must not directly:

* access SQLite;
* access cryptographic keys;
* call backend services directly;
* implement business workflows.

Managers coordinate application workflows.

Infrastructure implements:

* networking;
* persistence;
* crypto;
* secure storage;
* configuration.

Private cryptographic material remains within the appropriate client security boundary.

---

# 32. Testing During Implementation

Code is not considered complete because it compiles.

Every implementation must have tests appropriate to its risk.

At minimum, consider:

* normal behavior;
* invalid input;
* authorization failure;
* dependency failure;
* timeout;
* cancellation;
* retry;
* duplicate request;
* resource exhaustion;
* concurrent execution;
* restart/recovery.

Security-sensitive code requires negative tests.

Detailed testing requirements are defined in:

`docs/implementation/testing-strategy.md`

---

# 33. Static Analysis and Tooling

The project should use:

* compiler warnings;
* `clang-format`;
* `clang-tidy`;
* AddressSanitizer;
* UndefinedBehaviorSanitizer;
* ThreadSanitizer where compatible;
* relevant compiler/runtime hardening options;
* dependency vulnerability scanning.

Static-analysis warnings must not simply be suppressed to make CI green.

If suppression is genuinely necessary:

1. understand the warning;
2. document why it is safe;
3. scope the suppression narrowly;
4. avoid disabling the rule globally.

---

# 34. Undefined Behavior

Undefined behavior is unacceptable.

Pay particular attention to:

* lifetime violations;
* use-after-free;
* iterator invalidation;
* signed integer overflow;
* buffer boundaries;
* data races;
* invalid casts;
* uninitialized values;
* dangling references;
* incorrect synchronization.

Do not assume undefined behavior is harmless because it "works on my machine."

---

# 35. Assertions

Assertions are useful for programmer invariants.

Do not use assertions as the only validation mechanism for untrusted input.

Bad:

```text
assert(request.user_id != empty)
```

as the only protection for external input.

Use explicit validation for externally controlled data.

---

# 36. Comments and Documentation

Comments should explain:

* why something is necessary;
* security invariants;
* concurrency assumptions;
* non-obvious lifetime/ownership rules;
* performance constraints;
* protocol assumptions.

Do not write comments that merely restate obvious code.

Bad:

```text
// Increment counter
counter++;
```

Good:

```text
// Increment only after durable acceptance so the metric
// cannot report messages that were subsequently rejected.
```

---

# 37. Naming

Names must communicate intent.

Prefer:

```text
DeliveryScheduler
SyncCursorRepository
DeviceRevocationManager
FileTransfer
```

over vague names such as:

```text
Manager
Helper
Utils
Processor
Data
Service
```

unless the broader context makes the responsibility unambiguous.

Avoid abbreviations except established technical terms.

Examples:

* HTTP
* TLS
* gRPC
* MFA
* E2E
* ID

---

# 38. Function and Class Size

Functions should have one clear responsibility.

Split code when a function simultaneously performs:

* validation;
* authorization;
* persistence;
* network communication;
* transformation;
* business decisions

without a clear reason.

Classes should have a focused responsibility.

Do not create classes merely to satisfy a preferred pattern.

---

# 39. Dependency Injection

Use dependency injection where it improves:

* testability;
* separation of concerns;
* replacement of infrastructure;
* lifecycle management.

Do not build a global service locator.

Avoid hidden global dependencies.

Dependencies should be visible from constructors or explicit configuration.

---

# 40. Global State

Avoid mutable global state.

Forbidden in normal application logic:

* global mutable caches;
* global mutable service clients;
* global singleton databases;
* global authentication state;
* global crypto state.

If process-wide state is genuinely required, its ownership, initialization, shutdown and thread-safety must be explicit.

---

# 41. Configuration

Configuration must be externalized.

Separate:

* code;
* environment-specific configuration;
* secrets.

Configuration must have:

* validation;
* defaults where safe;
* explicit required fields;
* startup failure for invalid critical configuration.

Do not silently use insecure defaults for security-sensitive settings.

---

# 42. Graceful Shutdown

Every service must support controlled shutdown.

Shutdown should:

1. stop accepting new work;
2. signal cancellation;
3. stop scheduling new work;
4. allow safe in-flight work to finish where appropriate;
5. flush required durable operations;
6. close resources;
7. terminate workers deterministically.

Shutdown must not silently lose already-accepted durable work.

---

# 43. Security-Sensitive Code Review

Code touching any of the following requires additional review:

* authentication;
* authorization;
* MFA;
* device registration/revocation;
* cryptography;
* token handling;
* file access capabilities;
* message acceptance;
* persistence/durability;
* secret management;
* service-to-service authentication;
* resource limits.

Reviewers should explicitly ask:

1. Can an attacker bypass this?
2. Can malformed input crash it?
3. Can it leak sensitive information?
4. Can a retry duplicate the operation?
5. What happens when its dependency fails?
6. Can resources grow without bound?
7. Does it fail closed?
8. Does it preserve the approved architecture?

---

# 44. Forbidden Patterns

The following are forbidden unless an explicit architectural decision changes them:

* custom cryptography;
* backend decryption of E2E message content;
* backend storage of client private keys;
* administrator decryption/backdoor;
* plaintext message logging;
* shared service private keys;
* direct cross-service database access;
* global messaging queue;
* global message ordering;
* unbounded worker creation;
* unbounded queues;
* thread-per-transfer;
* thread-per-message;
* silent retry of non-idempotent operations;
* retry without deadlines;
* plaintext fallback after crypto failure;
* security downgrade after dependency failure;
* global mutable authentication state;
* SQL string concatenation with untrusted input;
* manually modified generated Protobuf/gRPC code;
* ignoring compiler/static-analysis errors without justification.

---

# 45. Code Review Checklist

Before requesting review, the developer should verify:

### Architecture

* [ ] Correct service owns the functionality.
* [ ] No cross-service database access.
* [ ] No architecture bypass.
* [ ] Approved interfaces are used.

### Security

* [ ] Inputs are validated.
* [ ] Authorization is enforced.
* [ ] Secrets are protected.
* [ ] No sensitive information is logged.
* [ ] Crypto uses approved libraries/protocols.
* [ ] Failure paths fail closed where required.

### Reliability

* [ ] Timeouts/deadlines are defined.
* [ ] Cancellation is handled.
* [ ] Retry behavior is bounded.
* [ ] Idempotency is preserved.
* [ ] Durable operations cannot silently disappear.

### Concurrency

* [ ] No unbounded concurrency.
* [ ] Queues/buffers are bounded.
* [ ] Shared state is synchronized.
* [ ] Lock scope is reasonable.
* [ ] No obvious deadlock/data-race risk.

### Performance

* [ ] No unnecessary large allocations.
* [ ] Streaming is used for large data.
* [ ] Database queries are bounded.
* [ ] Hot-path behavior is understood.
* [ ] Optimization is supported by measurement.

### Testing

* [ ] Unit tests added where appropriate.
* [ ] Failure cases tested.
* [ ] Security-negative cases tested.
* [ ] Concurrency behavior tested where relevant.
* [ ] Relevant sanitizers/static analysis pass.

---

# 46. Definition of Coding Compliance

An implementation is coding-rule compliant when:

* it respects the approved architecture;
* ownership and lifetimes are explicit;
* failures are handled deliberately;
* external input is validated;
* concurrency and resources are bounded;
* security boundaries are preserved;
* sensitive data is protected;
* persistence and idempotency rules are respected;
* tests cover meaningful behavior and failure modes;
* static analysis does not reveal unexplained critical issues;
* the implementation does not introduce undocumented architectural changes.

If a developer believes an existing rule is technically wrong or blocks a necessary implementation, they must **raise the issue before bypassing the rule**.

Rules are changed deliberately; they are not silently ignored.
