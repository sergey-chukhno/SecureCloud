# 7. Audit Service Design

## 7.1 Purpose

The Audit Service provides centralized security and operational auditing for SecureCloud.

Its responsibilities are:

* receive audit events from runtime services;
* durably store audit records;
* provide security and operational investigation capabilities;
* support time-range and actor/resource-based queries;
* preserve audit-event integrity and provenance;
* enforce bounded ingestion and storage resources;
* apply retention policies;
* remain independent from critical message/file acceptance paths.

The Audit Service is **not** part of the critical path for accepting messages or files.

Its failure must not prevent Messaging or Files from durably accepting otherwise valid operations.

---

## 7.2 Architectural Position

Audit receives events from other services through their transactional outboxes.

```text
                    Runtime Services
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
      Auth           Messaging          Files
        │                │                │
        └───────┬────────┴────────┬───────┘
                │                 │
          Transactional      Transactional
             Outbox             Outbox
                │                 │
                └────────┬────────┘
                         ▼
                 Audit ingestion
                         │
                         ▼
                    ClickHouse
```

The Gateway may also generate operational/security events when appropriate.

Audit events are delivered asynchronously.

The Audit Service never reads another service's database directly.

---

## 7.3 Audit Event Model

The canonical unit is an immutable `AuditEvent`.

Conceptually:

```text id="8k3m0s"
AuditEvent
├── event_id
├── event_type
├── event_version
├── timestamp
├── source_service
├── source_instance
├── actor
├── device
├── resource
├── outcome
├── correlation_id
├── request_id
└── metadata
```

### Required properties

`event_id` is globally unique and immutable.

`event_type` identifies the semantic operation.

`event_version` allows the event schema to evolve without ambiguity.

`timestamp` records when the originating service generated the event.

`source_service` identifies the service responsible for the event.

`source_instance` may identify the runtime instance when operational troubleshooting requires it.

`correlation_id` connects related operations across services.

`request_id` identifies the individual request where applicable.

`outcome` represents the result, for example:

```text id="1tx1c5"
SUCCESS
FAILURE
DENIED
```

The exact event taxonomy is defined by the API/data-model contracts.

---

## 7.4 Actor and Identity Representation

Audit records use SecureCloud's opaque identifiers.

Where applicable, an event may contain:

* opaque `user_id`;
* opaque `device_id`;
* service identity;
* resource identifier.

Audit must not unnecessarily store human-readable identity information.

For example, it should not require:

```text id="b1q7b4"
email
full name
phone number
```

when an opaque identifier is sufficient.

This preserves the architectural principle that backend services do not need human identity to perform their technical functions.

---

## 7.5 What Audit Records

Audit focuses on security-relevant and operationally significant events.

Examples include:

### Authentication

* successful login;
* failed login;
* MFA success/failure;
* token/session events;
* refresh-token reuse detection;
* session revocation.

### Device security

* device registration;
* device authorization;
* device revocation;
* device authentication failures;
* cryptographic identity/key-state changes where operationally relevant.

### Messaging

* message accepted;
* message submission rejected;
* delivery failures;
* delivery expiration;
* suspicious/repeated failures;
* relevant emergency-message events.

### Files

* upload created;
* upload completed;
* upload failed;
* download initiated/completed where required;
* access denied;
* expiration;
* deletion.

### Security

* authorization denial;
* invalid credentials;
* service authentication failure;
* certificate/service-identity failures;
* rate-limit/security-policy violations.

### Operations

* service startup/shutdown;
* dependency failures;
* storage failures;
* significant recovery events;
* configuration/security-policy changes where appropriate.

The exact event list is defined in the API/data-model layer rather than by creating additional architectural documents.

---

## 7.6 Content Confidentiality

Audit must never become a side channel for protected application content.

Audit events must not contain:

* plaintext messages;
* plaintext file contents;
* E2E private keys;
* plaintext file-encryption keys;
* session private keys;
* authentication secrets;
* passwords;
* MFA secrets;
* refresh tokens;
* access-token signing private keys.

For messaging events, Audit may contain operational metadata such as:

```text id="4l8r5a"
message_id
conversation_id
sender_device_id
recipient/device identifiers where required
timestamp
delivery outcome
```

but not message plaintext.

For files, Audit may contain:

```text id="h7r5cs"
file_id
transfer_id
operation
timestamp
outcome
```

but not file contents or decryption keys.

---

## 7.7 Audit Metadata and Privacy

Audit is explicitly allowed to retain communication metadata for security and operational purposes.

However, metadata collection remains minimized.

The service should collect only what is required for:

* security investigation;
* operational troubleshooting;
* compliance requirements applicable to the deployment;
* system reliability analysis.

Audit therefore does not become a justification for collecting every piece of metadata available to runtime services.

Where a field is not required for a defined audit purpose, it should not be persisted.

---

## 7.8 Event Generation

Audit events are generated by the service performing the operation.

For example:

```text id="6v0y2m"
Messaging
   │
   │ message accepted
   ▼
Messaging DB transaction
   ├── message state
   └── audit outbox event
```

The event is committed atomically with the relevant business state where transactional outbox semantics apply.

This prevents:

```text id="1f3j4k"
business operation committed
        +
audit event lost
```

The originating service therefore owns the correctness of event creation.

Audit is responsible for ingestion and durable analytical storage, not reconstructing missing business events by querying other services' databases.

---

## 7.9 Transactional Outbox

Runtime services use a Transactional Outbox for audit events.

Conceptually:

```text id="x7h5cw"
Business Transaction
       │
       ├── business state
       │
       └── audit outbox event
              │
              ▼
          COMMIT
              │
              ▼
        Outbox Publisher
              │
              ▼
        Audit Service
```

The event is therefore published **at least once**.

The Audit Service must tolerate duplicate events.

`event_id` provides the stable identity required for deduplication.

Exactly-once distributed delivery is not required.

---

## 7.10 Ingestion Model

Audit ingestion is asynchronous.

The Audit Service exposes an internal authenticated ingestion interface.

Runtime services authenticate to Audit using the service-to-service mTLS architecture defined in ADR-008.

The ingestion path is:

```text id="7s6qwf"
Service Outbox
     ↓
Publisher
     ↓
mTLS
     ↓
Audit Ingestion
     ↓
Validation
     ↓
Deduplication
     ↓
ClickHouse
```

Audit validates:

* event schema/version;
* event identity;
* source service;
* required fields;
* acceptable timestamp constraints;
* authorization of the sending service.

Invalid events are rejected explicitly and must not silently become valid audit records.

---

## 7.11 Idempotency and Duplicate Events

Audit ingestion is at-least-once.

Therefore duplicate events are expected.

Example:

```text id="5r5c2u"
Messaging
   │
   │ event E123
   ▼
Audit
   │
   │ persisted
   │
   X response lost
   │
Messaging retries E123
   ▼
Audit
   │
   └── E123 already known
```

The Audit Service must not create multiple logical audit records solely because the same event was delivered more than once.

`event_id` is the canonical deduplication identity.

Deduplication must not require an unbounded in-memory cache.

---

## 7.12 Persistence — ClickHouse

Audit records are stored in **ClickHouse**.

ClickHouse is authoritative for Audit's persisted analytical event history.

The storage model is optimized for:

* append-heavy ingestion;
* time-range queries;
* operational/security analysis;
* aggregation;
* large historical datasets.

The Audit Service does not use ClickHouse as a transactional source for runtime business state.

No other service directly queries Audit's ClickHouse database.

---

## 7.13 ClickHouse Data Organization

The primary logical organization is by time and event characteristics.

The physical schema should support queries such as:

```text id="z2h4n7"
events for device X
during time range T1–T2
```

or:

```text id="e7k2q3"
all authorization failures
for service S
during time range T1–T2
```

or:

```text id="p5x4w8"
all events associated with correlation_id C
```

The physical table/partition/order-key design belongs in `data-model.md`.

The implementation must prioritize the query patterns actually required by SecureCloud rather than creating a generic event warehouse schema.

---

## 7.14 Ordering

Audit does **not** provide a global total ordering across all services.

Distributed services can generate events concurrently and clocks can differ.

The system therefore preserves:

* event timestamp;
* event ID;
* source service;
* correlation ID where applicable.

When causal ordering matters, the originating service's event relationships and correlation identifiers are used.

Audit queries must not assume that:

```text
event A timestamp < event B timestamp
```

necessarily means:

```text
A happened before B
```

across independent machines.

---

## 7.15 Timestamp Semantics

Each event contains an originating timestamp.

The Audit Service also has ingestion/storage timestamps where operationally useful.

Conceptually:

```text id="df7p5z"
event_timestamp
    = time generated by source service

ingested_at
    = time received by Audit
```

This distinction is important for diagnosing:

* network delays;
* retry delays;
* out-of-order events;
* service clock differences.

The system should use synchronized system clocks where operationally possible.

---

## 7.16 Integrity and Provenance

Audit records must provide trustworthy provenance.

Each event identifies its originating service.

The internal mTLS connection authenticates the sending service.

The Audit Service must not accept arbitrary events claiming to originate from another service.

For higher-assurance deployments, event integrity can additionally use service-level signing, but this is not required for the MVP if authenticated mTLS plus controlled ingestion provides the required trust model.

The MVP therefore relies on:

```text id="5z2d8p"
service identity
      +
mTLS
      +
authenticated ingestion
      +
immutable event_id
```

rather than introducing a separate event-signing system.

---

## 7.17 Audit Immutability

Audit records are logically append-only.

Normal application operations must not modify historical audit events.

Correction of an incorrect event should be represented by a new event rather than silently modifying history.

Administrative users may have permission to query audit data, but must not receive unrestricted mutation capabilities through the normal Audit API.

Physical database administration remains a separate infrastructure concern and is outside the application-level audit API.

---

## 7.18 Query Model

The Audit Service exposes controlled query operations for authorized administrative/security users and internal tooling.

Queries should support:

* time range;
* event type;
* source service;
* opaque user/device ID;
* resource ID;
* outcome;
* correlation ID;
* request ID.

Queries must have bounded limits.

The API must prevent unrestricted requests that could attempt to return the entire audit history into application memory.

Large result sets use:

* pagination;
* bounded batches;
* streaming where appropriate.

---

## 7.19 Administrative Access

The Application Administrator may access audit information according to authorization policy.

However, audit access does not grant:

* message decryption;
* file decryption;
* access to device private keys;
* access to file-encryption keys.

Audit therefore provides visibility without creating a cryptographic privilege escalation path.

Administrative access itself is auditable.

---

## 7.20 Retention

Audit retention is explicitly bounded.

Retention policies determine how long audit events remain queryable.

Expired data is removed according to a controlled lifecycle process.

Retention must be implemented in a way compatible with ClickHouse's partitioning/TTL capabilities.

Exact retention duration is deployment configuration rather than an architectural decision.

The system must distinguish:

```text id="3l9n1e"
retention policy
```

from:

```text id="8k6b2r"
backup/recovery policy
```

Deleting an expired event from the active analytical store does not automatically imply that all backup copies have been deleted.

---

## 7.21 Concurrency Model

Audit is an ingestion- and query-oriented service.

It therefore uses separate bounded execution domains:

```text id="g7q1p3"
                         Audit
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
        Ingestion                    Query
         workers                    workers
             │                           │
             ▼                           ▼
        ClickHouse                  ClickHouse
             │
             ▼
       Retention/Cleanup
```

### Ingestion

Multiple audit events may be ingested concurrently.

The ingestion path must use bounded:

* request concurrency;
* event batch sizes;
* memory buffers;
* ClickHouse connections;
* pending writes.

### Queries

Query execution has independent resource limits.

A slow analytical query must not consume all ingestion capacity.

### Retention

Cleanup/retention work is isolated from normal ingestion.

Exact worker counts and batch sizes are performance parameters.

---

## 7.22 Backpressure

Audit must protect itself against event bursts.

If ClickHouse or the Audit Service cannot ingest at the current rate:

```text id="w9c7h1"
Runtime service
      ↓
Outbox
      ↓
Audit unavailable/overloaded
      ↓
events remain in source outbox
      ↓
retry later
```

The originating runtime service remains responsible for retaining unpublished audit events according to its outbox/retention policy.

Audit must not require unbounded buffering.

The Audit Service may reject or throttle incoming ingestion when its bounded capacity is exhausted.

---

## 7.23 Failure Handling

### Audit Service unavailable

Runtime services continue their normal critical operations.

Audit events remain in their transactional outboxes and are published later.

### ClickHouse unavailable

Audit ingestion does not falsely report durable persistence.

Events remain retryable.

### Audit restart

Audit reconstructs required state from ClickHouse and its durable configuration/state rather than relying on process-local event history.

### Duplicate event

The event is handled idempotently using `event_id`.

### Out-of-order event

The event is accepted if valid.

Audit does not require global ordering.

### Event schema mismatch

Unsupported or invalid events are rejected explicitly.

They must not be silently interpreted using an incompatible schema.

### Query overload

Queries are bounded and isolated from ingestion.

### Storage exhaustion

Audit must apply explicit backpressure/retention behavior rather than silently discarding new security events.

---

## 7.24 Security Invariants

The Audit Service must preserve these invariants:

1. Audit never stores message plaintext.
2. Audit never stores file plaintext.
3. Audit never stores E2E private keys.
4. Audit never stores plaintext file-encryption keys.
5. Audit never provides a decryption mechanism.
6. Runtime services authenticate to Audit using service identity/mTLS.
7. A service cannot submit events while impersonating another service.
8. Audit events are immutable at the application level.
9. Duplicate event delivery cannot create inconsistent logical history.
10. Audit failure does not block durable message acceptance.
11. Audit failure does not block otherwise valid file persistence.
12. Audit ingestion uses bounded resources.
13. Audit queries cannot exhaust ingestion resources.
14. Audit retention is explicit and bounded.
15. Administrative audit access does not grant cryptographic privileges.
16. Audit records use opaque SecureCloud identifiers rather than unnecessary human identity.
17. Event provenance and timestamps are preserved.

---

## 7.25 Performance Architecture

Audit is optimized for:

* sustained append throughput;
* burst tolerance;
* efficient analytical queries;
* bounded ingestion memory;
* isolation between ingestion and query workloads.

The main performance decisions are:

1. ClickHouse for append-heavy analytical storage;
2. asynchronous ingestion;
3. transactional outbox at event producers;
4. at-least-once delivery;
5. event-id-based idempotency;
6. bounded ingestion batches;
7. independent query resources;
8. time-oriented data organization;
9. retention through storage lifecycle mechanisms;
10. no synchronous Audit dependency in critical business operations.

Benchmarking must measure realistic:

* event ingestion throughput;
* event size;
* batching;
* ClickHouse write performance;
* query latency;
* concurrent queries;
* burst behavior;
* storage growth;
* retention/cleanup behavior.

The benchmark must not disable event durability or transactional outbox semantics.

---

## 7.26 Internal Components

The Audit Service is organized around:

### Ingestion

* `AuditEventController`
* `AuditEventValidator`
* `AuditEventDeduplicator`

### Persistence

* `AuditRepository`
* `ClickHouseClient`
* `AuditBatchWriter`

### Query

* `AuditQueryController`
* `AuditQueryService`
* `AuditQueryRepository`

### Lifecycle

* `RetentionManager`
* `CleanupWorker`

### Runtime Protection

* `BackpressureController`
* `ResourceLimiter`

These are internal components of the Audit Service, not additional services.

---

## 7.27 Implementation Boundary

The following decisions are fixed for implementation:

* Audit is an independent runtime service.
* Runtime services publish audit events asynchronously.
* Transactional Outbox is the producer-side durability mechanism.
* Audit ingestion is at-least-once.
* `event_id` is globally unique and is the canonical deduplication identifier.
* Audit uses ClickHouse for persistent event storage.
* Audit records are logically append-only.
* Audit provides controlled analytical/security queries.
* Audit uses opaque user/device/resource identifiers.
* Audit never stores plaintext messages or files.
* Audit never stores private cryptographic keys or plaintext file-encryption keys.
* Audit never provides a decryption mechanism.
* Service-to-service authentication uses mTLS/service identity.
* No service may impersonate another service when submitting events.
* Audit has separate bounded ingestion and query concurrency domains.
* Audit queries cannot exhaust ingestion capacity.
* Backpressure is mandatory.
* Audit outage does not block critical Messaging or Files persistence.
* Out-of-order events are permitted.
* No global event ordering is assumed.
* Event timestamps and ingestion timestamps are distinct.
* Retention is bounded and configurable.
* Administrative audit access does not grant cryptographic privileges.
* Exact ClickHouse schema, partitioning/order keys, event taxonomy, API messages, retention values and batch sizes are defined in `data-model.md` and API contracts.
