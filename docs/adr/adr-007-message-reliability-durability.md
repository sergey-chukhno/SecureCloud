# ADR-007 — Messaging Reliability & Durability

**Status:** Approved
**Version:** 1.0
**Date:** 2026-09-02
**Decision Scope:** Message acceptance, durability, delivery, acknowledgement, retry, ordering, offline storage, failure handling, and reliable event publication.

---

# 1. Context

SecureCloud must provide reliable asynchronous messaging while operating in a distributed environment.

The Messaging service must support:

* normal messaging;
* emergency/priority messaging;
* offline recipients;
* multiple devices per logical user;
* durable message storage;
* retries;
* duplicate requests;
* partial service failures;
* recipient delivery acknowledgement;
* bounded queues and backpressure;
* asynchronous audit events.

The architecture does **not** require exactly-once distributed processing.

Instead, SecureCloud will use:

> **durable persistence + at-least-once delivery + idempotency**

as its reliability model.

Messaging uses **ScyllaDB**, selected in ADR-006.

The Messaging service is therefore the authoritative owner of message persistence and delivery state.

---

# 2. Decision

SecureCloud adopts the following Messaging reliability model:

1. A message is accepted only after successful durable persistence in Messaging.
2. Messaging generates a globally unique message identifier.
3. The client supplies an idempotency identifier for message submission.
4. Duplicate submissions are detected and do not create duplicate logical messages.
5. Messages are durably queued per recipient device.
6. Recipient delivery is asynchronous.
7. Delivery uses **at-least-once semantics**.
8. The recipient client must be capable of detecting duplicate message delivery.
9. Delivery acknowledgement is persisted by Messaging.
10. Failed delivery is retried using bounded exponential backoff with jitter.
11. Messages have bounded retention and eventually expire.
12. Ordering is guaranteed only within a defined sender/recipient-device stream where required; there is no global ordering.
13. Messaging uses a **Transactional Outbox** to reliably publish asynchronous events after persistence.
14. Audit/event consumers use idempotent processing.
15. No distributed transaction is used between Messaging, Audit, Auth or other services.
16. Backpressure and queue limits prevent unbounded resource consumption.

The resulting model is:

```text
Client
  │
  │ SendMessage
  ▼
Gateway
  │
  ▼
Messaging
  │
  ├──────────────► ScyllaDB
  │                 │
  │                 ├── message
  │                 ├── delivery state
  │                 └── outbox event
  │
  ▼
Response: ACCEPTED
       
       asynchronous
       
ScyllaDB Outbox
  │
  ▼
Event Publisher
  │
  ├──────────────► Audit
  │
  └──────────────► future consumers
```

---

# 3. Message Lifecycle

A message follows the following logical lifecycle:

```text
SUBMITTED
    │
    ▼
VALIDATING
    │
    ▼
ACCEPTED / DURABLE
    │
    ▼
QUEUED
    │
    ├──────────────► DELIVERING
    │                     │
    │                     ├── success ──► DELIVERED
    │                     │
    │                     └── failure
    │                           │
    │                           ▼
    │                         RETRY
    │                           │
    │                           └──► DELIVERING
    │
    └── retention exceeded ──► EXPIRED
```

The important distinction is:

> **Accepted is not the same as Delivered.**

A successful `SendMessage` operation means that Messaging has accepted responsibility for durable storage and subsequent delivery.

It does not mean that the recipient has received the message.

---

# 4. Message Acceptance

## Decision

`SendMessage` succeeds only after Messaging has durably persisted the message and its required initial delivery state.

Conceptually:

```text
Client
  │
  │ SendMessage
  ▼
Gateway
  │
  ▼
Messaging
  │
  ├── validate
  ├── authorize
  ├── persist message
  ├── persist delivery state
  ├── persist outbox event
  │
  ▼
SUCCESS
```

The client must **not** receive a successful acceptance response before the required durable state has been committed.

This prevents the following failure:

```text
Messaging → "success"
      │
      X
process crashes
      │
      X
message was never persisted
```

---

# 5. What "Durable" Means

For SecureCloud:

> **Durable means that Messaging has successfully committed the message to its persistent datastore using the configured ScyllaDB durability/replication guarantees.**

Durability therefore does not mean:

* recipient received the message;
* recipient decrypted the message;
* recipient read the message;
* Audit received the event.

Those are separate lifecycle stages.

The exact ScyllaDB replication and consistency configuration must satisfy the application's durability requirement and will be part of the deployment configuration.

---

# 6. Message Identifier

Every logical message receives a globally unique:

> `message_id`

The identifier is generated before or during persistence and remains stable throughout the message's lifecycle.

It is used for:

* delivery tracking;
* acknowledgement;
* retry;
* duplicate detection;
* audit correlation;
* client-side deduplication.

The identifier must not contain human identity information.

---

# 7. Idempotent Message Submission

Distributed systems commonly encounter:

```text
Client
  │
  │ SendMessage
  ▼
Messaging
  │
  │ persists successfully
  │
  X response lost
  │
Client timeout
  │
  ▼
Client retries
```

Without idempotency, the same logical message could be stored twice.

Therefore, message submission uses an idempotency identifier.

Conceptually:

```text
client_message_id
        ↓
idempotency key
        ↓
existing?
   ┌────┴────┐
   │         │
  yes        no
   │         │
return       persist
existing     message
result
```

If the same submission is received again, Messaging returns the result associated with the existing logical message rather than creating a second message.

The exact idempotency-key representation is an implementation detail, but the behavior is mandatory.

---

# 8. Recipient Device Queues

Messages are queued against **device-specific cryptographic recipients**.

This is required because one logical user may have multiple devices.

Conceptually:

```text
User B
│
├── Device B1
│     └── queue
│
├── Device B2
│     └── queue
│
└── Device B3
      └── queue
```

The Messaging service therefore treats a device as an independent delivery target.

The cryptographic message envelope must already be appropriate for the target device.

Messaging does not decrypt or re-encrypt the message.

---

# 9. Offline Messaging

If a recipient device is offline:

```text
Sender
  │
  ▼
Messaging
  │
  ▼
durable queue
  │
  │ recipient offline
  │
  │
  └───────────────┐
                  │
             recipient
               reconnects
                  │
                  ▼
             delivery
```

The message remains in durable storage until one of the following occurs:

1. successful delivery and acknowledgement;
2. explicit deletion according to an authorized operation;
3. retention expiration;
4. another defined terminal failure condition.

The Messaging service must not rely on process memory for offline queues.

---

# 10. Delivery Semantics

## Decision

SecureCloud uses:

> **At-least-once delivery.**

A message may therefore be delivered more than once.

This is intentional.

The architecture prefers:

> duplicate delivery

over:

> silent message loss.

For example:

```text
Messaging
   │
   │ message
   ▼
Client
   │
   │ receives message
   │
   X ACK lost
   │
Messaging thinks delivery failed
   │
   ▼
retry
   │
   ▼
Client receives duplicate
```

The client must recognize the existing `message_id` and avoid presenting the same logical message as a new message.

---

# 11. Delivery Acknowledgement

The MVP defines a **delivery acknowledgement** separately from a read receipt.

A delivery acknowledgement means:

> The recipient device has successfully received and durably accepted the encrypted message into its local message store.

It does **not** mean:

* the user opened the conversation;
* the user read the message;
* the user understood the message.

Read receipts are outside the core durability mechanism.

The recipient client sends an acknowledgement containing the `message_id`.

Messaging then records the delivery state.

Conceptually:

```text
Messaging
   │
   │ encrypted message
   ▼
Recipient
   │
   ├── persist locally
   │
   └── ACK(message_id)
          │
          ▼
      Messaging
          │
          ▼
      DELIVERED
```

---

# 12. Delivery State

Messaging maintains explicit delivery state.

The logical states are:

```text
QUEUED
   │
   ▼
DELIVERING
   │
   ├── success + ACK ──► DELIVERED
   │
   └── failure ────────► RETRY_WAIT
                              │
                              ▼
                         DELIVERING

QUEUED / RETRY_WAIT
   │
   └── retention exceeded ──► EXPIRED
```

The implementation may represent these states differently internally, but their semantics must remain equivalent.

---

# 13. Retry Policy

Transient delivery failures are retried.

Examples:

* recipient temporarily offline;
* network interruption;
* Gateway connection failure;
* temporary client failure;
* temporary Messaging dependency failure.

Retries use:

* exponential backoff;
* jitter;
* bounded retry intervals;
* an overall retention/deadline boundary.

Conceptually:

```text
attempt 1
   ↓
short delay
   ↓
attempt 2
   ↓
longer delay
   ↓
attempt 3
   ↓
...
```

The system must avoid synchronized retry storms.

Therefore jitter is mandatory.

---

# 14. Permanent Failure and Expiration

Not every message can be delivered forever.

A message eventually reaches a terminal state when its configured retention period expires.

```text
QUEUED
  │
  │ retries
  ▼
RETRY
  │
  │ retention exceeded
  ▼
EXPIRED
```

Expiration is necessary to prevent unbounded storage growth.

The MVP uses a **bounded configurable retention policy**.

The default retention value is an implementation/configuration decision rather than a protocol invariant and must be explicitly configured in deployment.

Expired messages cannot subsequently be delivered.

---

# 15. Ordering

SecureCloud does not provide global message ordering.

Global ordering would introduce unnecessary coordination and reduce scalability.

Instead, ordering is scoped.

The MVP guarantees ordering only where the application explicitly requires it, using a logical message sequence within a sender/recipient-device stream.

Conceptually:

```text
Sender A
   │
   ├── message 101
   ├── message 102
   ├── message 103
   │
   ▼
Recipient Device B
```

The system attempts to preserve:

```text
101 → 102 → 103
```

within the defined stream.

Messages belonging to unrelated conversations or devices do not participate in a shared global order.

The exact sequence mechanism will be defined during Messaging implementation.

---

# 16. Emergency Messages

Emergency messages use the same durability architecture as normal messages.

They are not stored in a completely separate messaging system.

They receive elevated delivery priority.

Conceptually:

```text
Messaging
│
├── Emergency queue      ← higher priority
│
└── Normal queue
```

Emergency priority must not bypass durability.

An emergency message is still considered accepted only after durable persistence.

Priority affects scheduling and delivery, not the fundamental durability guarantee.

---

# 17. Backpressure

Messaging must prevent unbounded resource consumption.

Limits apply to:

* incoming requests;
* concurrent message submissions;
* per-device queues;
* retry queues;
* message size;
* outstanding delivery attempts;
* internal buffers.

When capacity is exhausted, Messaging must apply explicit backpressure rather than accepting unlimited work.

Possible outcomes include:

* request rejection;
* temporary throttling;
* retryable error;
* connection-level flow control.

The system must never silently discard an accepted durable message because of overload.

---

# 18. Transactional Outbox

## Decision

Messaging uses the **Transactional Outbox pattern**.

The outbox exists to solve the dual-write problem between:

1. persistent Messaging state; and
2. asynchronous event publication.

Without an outbox:

```text
Messaging
   │
   ├── write message → ScyllaDB
   │
   └── publish event → Audit
```

there is a dangerous failure window:

```text
write message
     │
     ▼
ScyllaDB SUCCESS
     │
     X
Messaging crashes
     │
     X
event never published
```

The message exists, but Audit never learns about it.

---

# 19. Outbox Atomicity

The message state and its corresponding outbox event are committed as one logical persistence operation.

Conceptually:

```text
Messaging persistence
┌───────────────────────────────┐
│                               │
│  Message record               │
│       +                       │
│  Initial delivery state       │
│       +                       │
│  Outbox event                 │
│                               │
│       ATOMIC COMMIT           │
│                               │
└───────────────────────────────┘
```

Therefore:

### Commit succeeds

Both message state and event are persisted.

### Commit fails

Neither is considered accepted.

This guarantees that a successfully accepted message has a durable corresponding event waiting for publication.

---

# 20. Outbox Event Publication

A separate publisher/worker inside the Messaging service reads pending outbox events and publishes them to their destinations.

Conceptually:

```text
ScyllaDB
   │
   │ pending outbox events
   ▼
Outbox Publisher
   │
   ▼
Audit
```

After successful publication, the outbox event is marked as processed.

If publication fails:

```text
Outbox
   │
   ▼
publish
   │
   X failure
   │
   ▼
remain pending
   │
   ▼
retry
```

Therefore, a temporary Audit outage does not prevent Messaging from accepting and durably storing messages.

---

# 21. Outbox Delivery Semantics

Outbox event delivery is:

> **At least once.**

The publisher may publish the same event more than once if it crashes after publication but before recording successful completion.

Therefore:

> **Consumers must be idempotent.**

Every event contains a unique event identifier.

Audit uses this identifier to detect and safely ignore duplicate processing.

---

# 22. No Distributed Transaction

SecureCloud explicitly rejects a distributed transaction between Messaging and Audit.

The following is **not** used:

```text
Messaging DB
     │
     ├──── distributed transaction ────► Audit DB
     │
     ▼
commit both
```

Instead:

```text
Messaging DB
     │
     └── atomic message + outbox commit
                    │
                    ▼
              async publication
                    │
                    ▼
                  Audit
```

This keeps Messaging available even when Audit is temporarily unavailable.

---

# 23. What the Outbox Guarantees

The outbox guarantees:

> If Messaging accepts a message, the corresponding asynchronous event is durably recorded and will remain available for publication.

It does **not** guarantee:

* immediate Audit delivery;
* exactly-once event processing;
* global ordering;
* Audit availability;
* transactionality across services.

The system instead guarantees:

> **durable local commit + eventual at-least-once event publication.**

---

# 24. Failure Scenarios

## Scenario A — Messaging crashes before persistence

```text
Client → Messaging
          │
          X crash
```

No successful response is returned.

The client retries using its idempotency identifier.

No accepted message is lost.

---

## Scenario B — Database commit succeeds, response is lost

```text
Messaging
   │
   ├── commit SUCCESS
   │
   X response lost
   │
Client timeout
```

Client retries.

Messaging detects the existing idempotency identifier and returns the existing message result.

No duplicate logical message is created.

---

## Scenario C — Messaging crashes after message commit

```text
message + outbox
       │
       ▼
   committed
       │
       X
   process crash
```

On recovery, the pending outbox event is still present.

It is published later.

---

## Scenario D — Audit is unavailable

```text
Messaging
   │
   ▼
ScyllaDB
   │
   ▼
Outbox
   │
   X
Audit unavailable
```

Messaging continues operating.

The event remains pending and is retried.

Audit unavailability therefore does not cause message loss.

---

## Scenario E — Delivery ACK is lost

```text
Client receives message
       │
       ▼
Client stores message
       │
       ▼
ACK
       │
       X network failure
```

Messaging retries delivery.

The client sees the same `message_id` and ignores the duplicate logical message.

---

## Scenario F — Messaging database node failure

The ScyllaDB deployment must be configured with appropriate replication so that failure of an individual storage node does not automatically result in loss of acknowledged messages.

The exact replication configuration is deployment-specific but must satisfy the durability guarantees defined here.

---

# 25. Multi-Device Behavior

Each registered device is an independent delivery target.

For example:

```text
User B
├── Laptop
├── Phone
└── Tablet
```

A message encrypted for a particular device cannot be decrypted by another device unless the cryptographic protocol explicitly creates a recipient envelope for that device.

Device revocation follows the existing architectural rule:

> A revoked device may still decrypt messages that were already encrypted for it, but it must not receive/decrypt future messages.

Messaging therefore stops future delivery to revoked devices.

It does not attempt to retroactively make previously delivered ciphertext undecryptable.

---

# 26. Message Deletion

Deletion is separate from delivery acknowledgement.

A message may be:

```text
DELIVERED
```

while still being retained according to the configured retention policy.

The Messaging service remains responsible for enforcing retention and deletion semantics.

Deletion must not be interpreted as proof that the recipient no longer possesses a previously delivered ciphertext.

SecureCloud cannot remotely erase ciphertext already stored on an endpoint unless a separate endpoint deletion mechanism is explicitly implemented.

---

# 27. Security Requirements

Messaging reliability mechanisms must not weaken the cryptographic architecture.

The Messaging service stores:

* encrypted message envelopes;
* opaque identifiers;
* delivery state;
* retry metadata;
* required operational metadata.

It does not store:

* message plaintext;
* recipient private keys;
* sender private keys;
* message decryption keys.

The outbox must follow the same rule.

An outbox event must never contain message plaintext merely for convenience of downstream consumers.

---

# 28. Metadata Requirements

The reliability model does not change the existing metadata policy.

Human sender and recipient identities remain hidden behind opaque identifiers.

The following may be persisted where operationally required:

* opaque device identifiers;
* message identifiers;
* timestamps;
* delivery state;
* retry state;
* expiration information;
* required communication metadata.

Timestamp, message size and communication-frequency privacy remain optimization goals rather than hard confidentiality requirements.

Message size hiding remains an architectural optimization to be handled by the cryptographic/message-envelope design.

---

# 29. Performance Consequences

The reliability model deliberately introduces work:

* durable database writes;
* replicated persistence;
* delivery state updates;
* acknowledgements;
* retries;
* outbox persistence;
* outbox processing.

This overhead is accepted.

SecureCloud must not claim its throughput target by disabling durability.

The performance target of approximately **10,000 messages/second** must therefore be measured under the actual reliability semantics defined here.

Performance optimization follows:

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

Potential future optimizations include:

* batching;
* connection pooling;
* efficient serialization;
* partition tuning;
* asynchronous processing;
* zero-copy techniques where justified;
* IPC/shared-memory optimizations under ADR-018's future scope.

None of these may weaken the reliability guarantees.

---

# 30. MVP Requirements

The MVP implementation must provide:

### Message acceptance

* durable persistence before success response;
* unique message ID;
* idempotent submission.

### Offline delivery

* durable recipient-device queues;
* reconnect handling;
* asynchronous delivery.

### Reliability

* at-least-once delivery;
* client-side duplicate detection;
* persisted delivery state;
* retry with exponential backoff and jitter.

### Durability

* replicated ScyllaDB deployment;
* explicit durability configuration;
* recovery procedure.

### Outbox

* atomic message + outbox persistence;
* asynchronous publisher;
* retry;
* at-least-once event publication;
* idempotent consumers.

### Backpressure

* bounded queues;
* request limits;
* explicit overload behavior.

### Testing

* duplicate submission;
* lost response;
* client reconnect;
* lost ACK;
* Messaging restart;
* ScyllaDB node failure;
* Audit outage;
* publisher restart;
* duplicate event;
* retry storm;
* retention expiration;
* concurrent delivery.

---

# 31. Rejected Alternatives

## At-Most-Once Delivery

Rejected.

It reduces duplicate handling but risks silent message loss.

For a secure communication platform, message loss is considered more harmful than duplicate delivery.

---

## Exactly-Once Distributed Delivery

Rejected for the MVP.

True exactly-once semantics across independently failing distributed components introduce significant complexity and do not provide sufficient benefit for the project's scope.

Idempotent processing provides the required practical behavior.

---

## In-Memory Offline Queues

Rejected.

A process restart or service failure could lose accepted messages.

Offline queues must be durable.

---

## Redis as the Source of Truth

Rejected.

Redis may be considered later as an optimization/cache, but it must not be the authoritative store for durable messaging.

---

## Distributed Transactions Between Messaging and Audit

Rejected.

Messaging must remain operational even when Audit is unavailable.

Transactional Outbox provides the required reliability without distributed transactions.

---

## Synchronous Audit Before Message Acceptance

Rejected.

The client should not depend on Audit availability for successful message submission.

Audit is asynchronous.

---

## Global Message Ordering

Rejected.

Global ordering creates unnecessary coordination and scalability constraints.

Ordering is scoped to the streams where the application requires it.

---

# 32. Consequences

## Positive

### No silent loss after acceptance

Once Messaging reports successful acceptance, the message is durably owned by the Messaging service.

### Strong offline behavior

Recipients can disconnect for extended periods without immediately losing messages.

### Resilience to lost responses

Idempotency prevents network failures from creating duplicate logical messages.

### Resilience to lost ACKs

At-least-once delivery prevents silent message loss.

### Audit decoupling

Audit outages do not block core messaging.

### Failure isolation

Messaging, Audit and clients can fail independently.

### Clear semantics

The distinction between accepted, durable, delivered and acknowledged is explicit.

---

## Negative

The model introduces:

* duplicate deliveries;
* duplicate event publication;
* additional database writes;
* outbox processing;
* retry traffic;
* acknowledgement traffic;
* additional storage for delivery state;
* more complex client logic.

These costs are deliberately accepted in exchange for reliability.

---

# 33. Final Reliability Contract

The SecureCloud Messaging service follows this contract:

> **If `SendMessage` succeeds, the message has been durably persisted by Messaging and will be retained for delivery according to the configured retention policy.**

> **Delivery is asynchronous and at-least-once.**

> **A recipient device acknowledges delivery only after durably accepting the encrypted message locally.**

> **Duplicate delivery is possible and must be safely handled using `message_id`.**

> **Message submission is idempotent.**

> **Transient failures trigger bounded retries with exponential backoff and jitter.**

> **Messaging does not depend synchronously on Audit for message acceptance.**

> **The Transactional Outbox guarantees that accepted messages have corresponding durable asynchronous events.**

> **Outbox publication is at-least-once and consumers must be idempotent.**

> **No distributed transaction is used between Messaging and other services.**

---

# 34. Final Decision

**APPROVED RELIABILITY MODEL**

```text
                 CLIENT
                    │
                    │ SendMessage
                    ▼
                GATEWAY
                    │
                    ▼
                MESSAGING
                    │
          ┌─────────┴─────────┐
          │                   │
          ▼                   ▼
     Message State         Outbox Event
          │                   │
          └─────────┬─────────┘
                    │
              ATOMIC COMMIT
                    │
                    ▼
                SCYLLADB
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
   Delivery Queue         Outbox Publisher
        │                       │
        ▼                       ▼
  Recipient Device            AUDIT
        │
        ▼
       ACK
        │
        ▼
   DELIVERED
```

SecureCloud therefore adopts:

**Durable persistence + idempotent submission + durable offline queues + at-least-once delivery + client deduplication + bounded retries + Transactional Outbox + at-least-once event publication.**

---

# 35. Relationship to Other ADRs

### Depends on

* ADR-001 — Five Runtime Microservices
* ADR-003 — Distributed-First Architecture
* ADR-004 — Inter-Service Communication Model
* ADR-005 — Database Ownership / Database-per-Service
* ADR-006 — Concrete Persistence Technologies

### Consolidates

The Transactional Outbox decision that was previously planned as **ADR-008** is incorporated into this ADR.

**A separate ADR-008 for Transactional Outbox is therefore removed from the roadmap.**

### Next

**ADR-008 — Distributed Failure & Resilience**

This ADR will cover cross-service failure behavior, timeouts, circuit breakers, service isolation, graceful degradation and recovery.

It will **not repeat the Messaging durability rules already established here.**
