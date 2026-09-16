# Section 5 — Messaging Service Design

## 5.1 Purpose

The Messaging Service is the core backend service responsible for the server-side lifecycle of encrypted messages.

Its responsibilities are:

* accepting encrypted message submissions;
* validating message envelopes and routing metadata;
* maintaining conversations and group membership;
* creating and maintaining device-level delivery targets;
* durably storing encrypted messages;
* managing offline delivery;
* delivering encrypted messages asynchronously;
* tracking delivery and read-receipt state;
* handling retries and duplicate submissions;
* synchronizing message state with clients;
* applying bounded concurrency and backpressure;
* publishing messaging audit events.

The Messaging Service **never decrypts message content**.

---

# 5.2 Responsibility Boundary

Messaging owns the authoritative server-side communication state:

* conversations;
* participants;
* encrypted message envelopes;
* delivery targets;
* delivery state;
* read-receipt state;
* synchronization state;
* messaging outbox events.

It does not own:

* authentication credentials;
* user sessions;
* device authorization;
* device private keys;
* E2E session keys;
* file content;
* audit storage.

The fundamental boundary is:

```text
Messaging
│
├── Communication state
├── Encrypted message data
├── Delivery state
├── Synchronization state
│
└── NO plaintext
    NO private cryptographic keys
```

Auth remains authoritative for user/device authentication and authorization state.

Messaging remains authoritative for communication state and message delivery.

---

# 5.3 Core Domain Model

The conceptual Messaging domain contains:

```text
User
Device
Conversation
Participant
Message
MessageEnvelope
DeliveryTarget
DeliveryState
ReadReceipt
SyncCursor
OutboxEvent
```

The critical distinction is:

```text
User
 └── multiple Devices
          │
          └── independent delivery targets
```

A conversation participant is normally represented at user level.

Message delivery occurs at device level.

Example:

```text
Conversation
 ├── Alice
 │    ├── Alice-phone
 │    └── Alice-laptop
 │
 └── Bob
      ├── Bob-phone
      └── Bob-tablet
```

This model supports multi-device communication, independent delivery, synchronization and device revocation.

---

# 5.4 Conversation Model

Messaging owns the authoritative server-side conversation representation.

A conversation contains:

* `conversation_id`;
* `type`;
* participant membership;
* membership state;
* creation/update metadata;
* synchronization information.

Conversation types:

```text
DIRECT
GROUP
```

Messaging manages logical membership but does not possess group encryption keys.

Cryptographic group state remains an endpoint responsibility governed by the E2E cryptographic architecture.

Adding a new device to an existing user must not automatically grant that device access to historical encrypted content.

---

# 5.5 Group Membership

Messaging manages:

* conversation creation;
* participant addition;
* participant removal;
* membership state;
* membership synchronization.

The service knows:

```text
Alice is a participant.
Bob is a participant.
```

It does not know:

```text
group encryption key
message plaintext
private cryptographic state
```

Membership changes therefore affect server-side routing and authorization without exposing E2E group secrets.

---

# 5.6 Message Envelope

Messaging accepts an encrypted `MessageEnvelope`.

Conceptually:

```text
MessageEnvelope
 ├── message_id
 ├── conversation_id
 ├── sender_device_id
 ├── recipient/delivery metadata
 ├── client timestamp
 ├── protocol version
 ├── padding information
 └── ciphertext
```

The exact representation is defined in the API contracts.

Messaging treats ciphertext as opaque bytes.

It may validate structural and routing metadata, but must never:

* decrypt ciphertext;
* inspect plaintext;
* transform plaintext;
* log plaintext;
* require plaintext to perform normal message routing.

---

# 5.7 Message Identity and Idempotency

Every message has a globally unique, stable `message_id`.

The client also provides an idempotency identifier when submitting a message.

This handles the distributed failure where:

```text
Client
   │
   │ SendMessage
   ▼
Messaging
   │
   ├── persist
   │
   └── response
        X lost
```

The client may retry.

Messaging must recognize the retry as the same logical submission.

Therefore:

```text
same idempotency key
+
same authenticated sender/device
        │
        ▼
same logical submission result
```

Duplicate submissions must not create duplicate logical messages.

---

# 5.8 Durable Message Acceptance

A message is accepted only after the required durable state has been committed.

Conceptually:

```text
BEGIN

  persist encrypted message
  persist initial delivery state
  persist required metadata
  persist outbox event

COMMIT
```

Only after the durability boundary is reached does Messaging report successful acceptance.

Therefore:

```text
Successful SendMessage
        =
message durably accepted
```

not merely:

```text
request received
```

No process-local memory is authoritative for message durability.

---

# 5.9 Persistence Model

Messaging uses **ScyllaDB**.

The data model is designed around the actual messaging access patterns.

The primary access pattern is:

> Retrieve and process encrypted messages and delivery state for a particular recipient device or delivery stream.

The storage model therefore uses recipient/device-oriented partitions rather than one global message collection.

Conceptually:

```text
ScyllaDB
│
├── Device A delivery partition
├── Device B delivery partition
├── Device C delivery partition
└── ...
```

The exact partition and clustering keys are defined in `data-model.md`.

The design must avoid:

```text
ONE GLOBAL MESSAGE PARTITION
```

because all message operations would contend on the same storage partition.

---

# 5.10 Concurrency Architecture

Concurrency is part of the Messaging design and is defined now at the architectural level.

Exact worker counts, queue sizes and concurrency limits remain benchmark-tuned parameters.

A Messaging instance uses separate bounded execution paths for major workloads:

```text
                    Messaging Instance
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
 Submission           Delivery             Sync
 Workers              Workers              Workers
        │                  │                  │
        ▼                  ▼                  ▼
 Message             Delivery             Sync
 Processing          Scheduler             Coordinator
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                       ScyllaDB
```

### Submission workers

Process:

* request validation;
* idempotency;
* authorization;
* durable message submission.

Multiple submissions can execute concurrently.

### Delivery workers

Process:

* selection of pending deliveries;
* scheduling;
* network transmission;
* delivery ACK processing;
* retry transitions.

Independent device streams can execute concurrently.

### Synchronization workers

Process:

* initial synchronization;
* incremental synchronization;
* cursor handling;
* bounded result batches.

Different clients/devices can synchronize concurrently.

### Ordering constraint

Only work belonging to an ordering scope that actually requires serialization is coordinated.

Unrelated conversations and device streams must not be unnecessarily serialized.

---

# 5.11 No Global Queue

Messaging must not use a single global delivery queue as its correctness or scalability mechanism.

A naïve architecture would be:

```text
All messages
     │
     ▼
GLOBAL QUEUE
     │
     ▼
Worker Pool
```

This creates a central contention point.

Instead, work is associated with independent delivery streams:

```text
             Delivery Scheduler
               /      |      \
              /       |       \
             ▼        ▼        ▼
         Device A  Device B  Device C
             │        │        │
             ▼        ▼        ▼
          workers  workers  workers
```

The durable state remains in ScyllaDB.

In-memory scheduling structures are bounded working buffers, not the authoritative queue.

This allows unrelated device streams to progress concurrently.

---

# 5.12 Delivery Targets

Each logical recipient may have multiple device-level delivery targets.

Example:

```text
Message: Alice → Bob

Bob
 ├── Bob-phone
 └── Bob-laptop
```

Messaging manages the delivery state independently for each target.

For a group:

```text
Message
 ├── Bob-phone
 ├── Bob-laptop
 ├── Charlie-phone
 └── Charlie-tablet
```

The exact E2E ciphertext/envelope supplied for each target is an endpoint cryptographic concern.

Messaging stores and routes the encrypted data it receives.

---

# 5.13 Delivery State Machine

Delivery state is separate from synchronization, presence and device state.

The server-side delivery lifecycle is:

```text
QUEUED
   │
   ▼
DELIVERING
   │
   ├──────────────► RETRY_WAIT
   │                    │
   │                    └──► DELIVERING
   │
   ▼
DELIVERED
   │
   ▼
READ

QUEUED / RETRY_WAIT
   │
   ▼
EXPIRED
```

### `QUEUED`

The encrypted message is durably stored and waiting for delivery.

### `DELIVERING`

A delivery attempt is in progress.

### `DELIVERED`

The recipient device has durably accepted the encrypted message locally and acknowledged it.

### `READ`

The recipient client has reported that the message was presented/read according to the MVP read semantics.

### `RETRY_WAIT`

A transient delivery failure occurred and the next attempt is scheduled.

### `EXPIRED`

The configured retention/deadline has been reached without successful delivery.

---

# 5.14 Read Receipt Semantics

Read receipts are generated by the recipient client.

For the MVP:

> A message becomes `READ` when the client presents it to the user in the active conversation according to the application's UI semantics.

The Messaging Service does not attempt to determine whether a human actually read a message.

The flow is:

```text
Recipient Client
       │
       │ message presented
       │
       │ READ(message_id)
       ▼
Messaging
       │
       ├── validate recipient
       ├── persist READ state
       └── expose state through synchronization
```

`DELIVERED` and `READ` remain separate.

No separate configurable read-policy engine is required for the MVP.

A future product requirement may introduce different read policies without changing the core delivery architecture.

---

# 5.15 Multi-Device Delivery

Messaging treats each device as an independent delivery endpoint.

For example:

```text
Alice
 ├── Alice-phone
 ├── Alice-laptop
 └── Alice-tablet
```

Messages can therefore be delivered concurrently to authorized devices.

The service tracks:

* device-specific delivery state;
* device-specific ACKs;
* device-specific synchronization;
* device-specific failures.

This allows one device to be offline without preventing delivery to another authorized device.

---

# 5.16 Device Revocation

Auth is authoritative for device revocation.

Messaging must prevent future delivery to a revoked device.

The security rule is:

```text
Already delivered
       │
       └── remains on device

Future message
       │
       └── must not be delivered
```

Messaging must not allow stale cached authorization state to override a security-sensitive revocation decision.

Previously delivered encrypted data cannot be remotely erased by Messaging.

---

# 5.17 Offline Delivery

Offline delivery is a first-class capability.

When a device is unavailable:

```text
Message
   │
   ▼
Messaging
   │
   ▼
ScyllaDB
   │
   └── durable pending state
```

When the device reconnects:

```text
ScyllaDB
   │
   ▼
Delivery Scheduler
   │
   ▼
Delivery Worker
   │
   ▼
Recipient Device
```

The offline queue is therefore fundamentally **durable storage state**, not an unbounded RAM queue.

In-memory structures contain only bounded working sets.

This is important for scalability:

```text
Offline for hours
       │
       ▼
Messages remain in ScyllaDB

RAM
└── only bounded active delivery work
```

---

# 5.18 Delivery Retry

Transient failures use bounded retries:

```text
failure
   │
   ▼
RETRY_WAIT
   │
   ├── exponential backoff
   ├── jitter
   └── bounded retry budget/deadline
   │
   ▼
next attempt
```

Retry scheduling must be bounded so that large-scale failures cannot create unbounded retry work.

The retry system must also respect:

* message retention;
* delivery deadline;
* device availability;
* service capacity;
* retry budgets.

---

# 5.19 Message Priority

Messaging supports three priority classes:

```text
NORMAL
URGENT
EMERGENCY
```

### `NORMAL`

Regular communication.

### `URGENT`

Higher-priority communication to normal users.

### `EMERGENCY`

Operationally critical communication involving the Emergency Unit.

Priority affects **delivery scheduling only**.

It does not bypass:

* E2E encryption;
* authorization;
* durable persistence;
* integrity;
* retry limits;
* resource bounds.

---

# 5.20 Priority Scheduling

The Delivery Scheduler uses **bounded priority scheduling with fairness**.

Conceptually:

```text
                Delivery Scheduler
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      EMERGENCY      URGENT       NORMAL
       highest        high         normal
       priority      priority      priority
```

Emergency messages are preferred over urgent messages, and urgent messages over normal messages.

However, lower-priority traffic must continue receiving bounded service.

The exact scheduling weights and quotas are runtime parameters to be benchmarked.

The architecture therefore guarantees:

* priority differentiation;
* bounded emergency preference;
* no unlimited starvation of normal traffic.

---

# 5.21 Emergency Unit

The Emergency Unit remains a normal SecureCloud user/role, not a separate Messaging service.

An emergency message therefore follows the same fundamental lifecycle:

```text
E2E encrypt
    ↓
durable acceptance
    ↓
priority scheduling
    ↓
delivery
    ↓
ACK
    ↓
READ
```

The difference is its scheduling priority and associated operational policy.

Emergency messages do not bypass the normal durability or security model.

---

# 5.22 Ordering

SecureCloud does not require global message ordering.

Global ordering would create unnecessary coordination and contention.

Ordering is scoped to streams where it is required.

For example:

```text
Alice → Bob-phone

M1
M2
M3
```

may require:

```text
M1 < M2 < M3
```

while:

```text
Alice → Bob-phone
Alice → Charlie-phone
David → Bob-laptop
```

can progress independently.

The exact ordering token/cursor is defined in `data-model.md`.

---

# 5.23 Synchronization

Messaging is authoritative for server-side message synchronization.

The client maintains its own `SyncState`.

Synchronization operates in two modes.

### Initial synchronization

Used to construct the client's local synchronized message state.

### Incremental synchronization

Used to retrieve changes after a previously stored cursor.

Conceptually:

```text
Client
  │
  │ cursor = N
  ▼
Messaging
  │
  └── changes after N
```

The client must not repeatedly retrieve complete history when incremental synchronization is possible.

---

# 5.24 Synchronization Cursor

The client stores the last successfully processed synchronization position.

Conceptually:

```text
SyncCursor = N
```

After successful processing:

```text
N → N + Δ
```

The cursor advances only after the corresponding data has been successfully processed.

This prevents message loss caused by:

* interrupted connections;
* client crashes;
* partial synchronization;
* process restart.

---

# 5.25 Presence

Presence is separate from delivery and synchronization.

Possible presence states include:

```text
ONLINE
OFFLINE
AWAY
```

Presence is not the source of truth for message durability.

Therefore:

```text
Presence = OFFLINE
+
Message accepted
=
Message remains QUEUED
```

Presence information must be minimized and exposed according to the security/product policy.

---

# 5.26 Real-Time Delivery

Real-time delivery is an optimization over the durable messaging model.

The fundamental flow remains:

```text
             Message accepted
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      device online       device offline
          │                   │
          ▼                   ▼
       immediate          durable queue
       delivery               │
                              ▼
                           reconnect
```

A persistent client connection can improve latency, but it is never the authoritative storage mechanism.

---

# 5.27 Bounded Resource Model

Messaging must use bounded resources.

The following are architectural bounds:

| Resource                   | Bound required | Purpose                                | When exhausted     |
| -------------------------- | -------------- | -------------------------------------- | ------------------ |
| Incoming requests          | Yes            | Protect service resources              | Reject/throttle    |
| Concurrent submissions     | Yes            | Protect CPU/DB                         | Backpressure       |
| Delivery workers           | Yes            | Protect CPU/network                    | Queue/defer        |
| In-memory delivery buffers | Yes            | Prevent memory exhaustion              | Backpressure       |
| Synchronization batch size | Yes            | Prevent oversized operations           | Batch/paginate     |
| Retry work                 | Yes            | Prevent retry storms                   | Defer/backoff      |
| Database connections       | Yes            | Protect ScyllaDB                       | Queue/backpressure |
| Network buffers            | Yes            | Prevent memory growth                  | Flow control       |
| Priority work queues       | Yes            | Prevent starvation/resource exhaustion | Backpressure       |

The **fact that these resources are bounded is an architectural decision**.

Their exact numerical limits are implementation parameters.

---

# 5.28 Backpressure

When capacity is exhausted before durable acceptance:

```text
request
   │
   ▼
capacity available?
   │
   ├── YES → process
   │
   └── NO → reject/throttle
```

The client may retry according to the applicable retry policy.

Once a message has been durably accepted, resource pressure must not silently discard it.

Instead:

```text
ScyllaDB
   │
   └── durable pending state
           │
           ▼
       wait for capacity
```

This creates an essential distinction:

> **Backpressure may reject work that has not been accepted; it must not silently lose work that has already been durably accepted.**

---

# 5.29 Horizontal Scaling

Messaging instances are interchangeable.

A request may reach any healthy instance.

Correctness must not depend on:

* sticky sessions;
* process-local message ownership;
* a particular instance owning a conversation;
* local RAM being the only copy of a message.

Conceptually:

```text
                 Gateway
                /   |   \
               /    |    \
             Msg1  Msg2  Msg3
               \    |    /
                \   |   /
                 ScyllaDB
```

Any healthy Messaging instance can recover required durable state and continue processing.

---

# 5.30 Throughput and Performance Design

Messaging is the primary throughput-critical service.

The project target is approximately:

**10,000 accepted messages/second peak.**

The performance architecture is therefore designed now around:

* horizontal service scaling;
* partition-oriented ScyllaDB access;
* concurrent processing of independent streams;
* bounded worker pools;
* persistent gRPC connections;
* asynchronous delivery;
* asynchronous Audit;
* bounded queues;
* efficient serialization;
* connection pooling;
* concurrent multi-device delivery;
* bounded batching where useful;
* bounded memory usage.

The benchmark determines the numerical parameters.

It does not determine whether the architecture should be concurrency-oriented.

---

# 5.31 Concurrency Parameters

The following values are intentionally **not hardcoded architecturally**:

* number of submission workers;
* number of delivery workers;
* number of synchronization workers;
* maximum concurrent submissions;
* maximum concurrent deliveries;
* queue capacities;
* synchronization batch size;
* ScyllaDB concurrency;
* connection-pool sizes;
* priority scheduling weights.

These values are established through controlled benchmarks.

The optimization process is:

```text
Initial engineering values
        ↓
Benchmark
        ↓
Profile
        ↓
Identify bottleneck
        ↓
Tune parameter
        ↓
Benchmark again
```

The architecture itself does not change simply because one worker count changes.

---

# 5.32 Internal Components

Messaging components use responsibility-oriented names rather than the `Manager` terminology used by the client.

```text
Messaging Service
│
├── API
│   ├── MessageController
│   ├── ConversationController
│   ├── SynchronizationController
│   └── DeliveryController
│
├── Message Processing
│   ├── MessageValidator
│   ├── EnvelopeProcessor
│   └── IdempotencyStore
│
├── Conversation
│   ├── ConversationRepository
│   └── MembershipRepository
│
├── Persistence
│   ├── MessageRepository
│   └── DeliveryRepository
│
├── Delivery
│   ├── DeliveryScheduler
│   ├── DeliveryWorker
│   └── RetryScheduler
│
├── Synchronization
│   ├── SynchronizationCoordinator
│   └── SyncCursorRepository
│
├── Receipts
│   └── ReadReceiptHandler
│
├── Presence
│   └── PresenceCoordinator
│
├── Runtime Protection
│   └── BackpressureController
│
├── Dependencies
│   └── AuthorizationClient
│
└── Events
    └── AuditOutboxPublisher
```

These are internal components, not additional microservices.

The naming distinction is intentional:

* Client → feature/application `Manager`s.
* Messaging backend → controllers, repositories, schedulers, workers, coordinators and handlers.

---

# 5.33 Authorization

Messaging does not treat authentication as sufficient authorization.

For protected operations it verifies that the authenticated user/device is authorized to perform the requested operation.

Examples:

```text
SendMessage
    → authorized sender/device
    → participant in conversation

GetConversation
    → authorized participant

AddParticipant
    → appropriate conversation privilege

MarkMessageRead
    → authorized recipient
```

Auth remains authoritative for account/device state.

Messaging remains authoritative for conversation-level authorization.

---

# 5.34 Audit Integration

Messaging publishes operational/security events asynchronously through its transactional outbox.

Possible events include:

* message accepted;
* delivery failure;
* message delivered;
* message read;
* conversation created;
* membership change;
* delivery blocked by device revocation;
* abnormal retry behaviour;
* resource-limit violations.

Audit receives metadata, not plaintext.

Audit availability is not required synchronously for message acceptance.

---

# 5.35 Failure Handling

### Messaging process crash

Durable messages and delivery state survive the restart.

Workers reconstruct their working state from durable storage.

### ScyllaDB failure

Messaging must not report successful durable acceptance unless the configured durability boundary has been achieved.

### Recipient disconnects

The message remains durable and returns to an appropriate retry state.

### Delivery ACK is lost

Messaging may retry.

The client deduplicates using `message_id`.

### Client request times out after successful persistence

The client retries with the same idempotency identifier.

Messaging returns the existing logical result.

### Audit unavailable

Message acceptance continues.

The outbox publisher retries later.

### Auth unavailable

Operations requiring authoritative authorization fail explicitly.

Messaging does not bypass Auth.

---

# 5.36 Security Boundary

A compromise of Messaging must not automatically expose E2E plaintext or private cryptographic identities.

Messaging must never possess:

* authentication credentials;
* device private keys;
* E2E session keys;
* message plaintext;
* file plaintext.

It may possess operational metadata required for communication routing and persistence.

The service therefore operates under a containment model:

> **Compromise of Messaging exposes only the information and capabilities belonging to the Messaging trust boundary.**

---

# 5.37 Metadata Handling

Messaging necessarily processes operational metadata such as:

* opaque user/device identifiers;
* conversation identifiers;
* message identifiers;
* timestamps;
* delivery state;
* synchronization positions;
* message-size information required for transport/storage.

Human identities remain represented by opaque identifiers.

Ciphertext remains opaque.

Messaging must not unnecessarily increase metadata exposure through:

* verbose payload logging;
* plaintext diagnostics;
* redundant identity information;
* unnecessary correlation fields.

Message-size protection follows the padding strategy established by the cryptographic architecture.

---

# 5.38 Local History and Search

Conversation history is synchronized to authorized clients as encrypted message data.

Server-side search must not require message plaintext.

The intended model is:

```text
Encrypted messages
       │
       ▼
Client local encrypted storage
       │
       ▼
Local search/index
```

The Messaging Service may query non-sensitive operational metadata but must not decrypt content to implement search.

---

# 5.39 Complete Message Flow

```text
Client
  │
  │ plaintext locally
  │
  │ E2E encryption
  ▼
Gateway
  │
  │ opaque encrypted envelope
  ▼
Messaging
  │
  ├── validate
  ├── authorize
  ├── check idempotency
  ├── persist message
  ├── persist delivery state
  └── persist outbox event
  │
  ▼
DURABLY ACCEPTED
  │
  ├── recipient online
  │       │
  │       ▼
  │    scheduler
  │       │
  │       ▼
  │    delivery worker
  │       │
  │       ▼
  │    DELIVERED
  │
  └── recipient offline
          │
          ▼
       durable queue
          │
          │ reconnect
          ▼
       delivery worker
          │
          ▼
       DELIVERED
          │
          │ message presented
          ▼
          READ
```

At no point does the backend require message plaintext.

---

# 5.40 Security and Reliability Invariants

The following are mandatory:

1. Messaging never decrypts message content.
2. Messaging never stores message plaintext.
3. Messaging never possesses device private cryptographic keys.
4. Successful message acceptance means durable acceptance.
5. Every message has a stable unique `message_id`.
6. Duplicate submissions are idempotently handled.
7. Offline messages are durably persisted.
8. Delivery is at-least-once.
9. Clients deduplicate duplicate deliveries.
10. `DELIVERED` and `READ` are distinct states.
11. Read state is generated by the client and recorded by Messaging.
12. Revoked devices receive no future authorized messages.
13. Previously delivered encrypted content remains on the device.
14. No global queue is required for correctness.
15. No global ordering is required.
16. Independent delivery streams can execute concurrently.
17. All major runtime resources are bounded.
18. Accepted durable messages are never silently discarded because of runtime backpressure.
19. Priority scheduling cannot bypass durability or security.
20. Audit failure cannot silently lose an accepted message.
21. Security-sensitive authorization cannot be bypassed because Auth is unavailable.
22. Performance optimization cannot weaken confidentiality, durability or correctness.
23. Backend compromise does not automatically provide message plaintext.

---

# 5.41 Implementation Boundary

The architecture is now concrete enough for implementation.

The next artifacts define the remaining implementation-level details.

### `data-model.md`

Will specify:

* ScyllaDB tables;
* partition keys;
* clustering keys;
* consistency choices;
* TTL/retention;
* delivery-state representation;
* idempotency records;
* synchronization cursors;
* read receipts;
* conversation/membership storage;
* outbox representation;
* exact ordering representation.

### API contracts

Will specify:

* REST endpoints exposed through Gateway;
* Messaging protobuf definitions;
* request/response structures;
* streaming interfaces;
* error codes;
* idempotency semantics;
* synchronization semantics;
* delivery acknowledgements.

### Performance benchmark

Will establish:

* worker counts;
* concurrency limits;
* queue capacities;
* batch sizes;
* connection-pool sizes;
* ScyllaDB concurrency;
* priority scheduling parameters.

These parameters are tuned through measurement rather than treated as architectural uncertainty.

---

# 5.42 Design Summary

The Messaging Service can be summarized as:

```text
                    Messaging
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
     ACCEPT           STORE            DELIVER
        │               │                │
        └───────────────┼────────────────┘
                        ▼
                  SYNCHRONIZE
                        │
                        ▼
                    ScyllaDB
```

Its concurrency model is:

```text
       Messaging Instance
              │
     ┌────────┼────────┐
     ▼        ▼        ▼
 Submission Delivery   Sync
 Workers    Workers   Workers
     │        │        │
     └────────┼────────┘
              ▼
          ScyllaDB
```

Its delivery model is:

```text
Durably accepted
       │
       ▼
   QUEUED
       │
       ▼
  DELIVERING
       │
       ├── retry ──► RETRY_WAIT
       │
       ▼
  DELIVERED
       │
       ▼
     READ
```

Its priority model is:

```text
EMERGENCY
    ↓
URGENT
    ↓
NORMAL

bounded priority + fairness
```

Its fundamental architectural principle is:

> **Messaging owns communication state and delivery, not communication plaintext.**

The service is therefore designed from the beginning for **durability, offline operation, multi-device delivery, bounded concurrency, horizontal scaling and predictable high throughput**, while keeping E2E confidentiality outside the backend trust boundary.
