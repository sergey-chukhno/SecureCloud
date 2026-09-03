# ADR-006 — Concrete Persistence Technology Selection

**Status:** Approved
**Version:** 0.4
**Date:** 2026-09-02
**Decision Scope:** Concrete persistence technologies for the SecureCloud MVP

---

# 1. Context

SecureCloud is a distributed, security-sensitive communication platform composed of independently deployable runtime services.

Following ADR-005, each service owns its persistent data and is the sole authority responsible for modifying that data.

The project has intentionally different persistence workloads:

* Authentication requires transactional relational state.
* Messaging requires high-volume, predictable, key-oriented access and durable offline queues.
* Files require structured metadata as well as large encrypted binary objects.
* Audit requires append-heavy historical storage and efficient analytical queries.
* Gateway should remain stateless.

Therefore, using one database technology everywhere would unnecessarily constrain the architecture.

SecureCloud will use **polyglot persistence**, with a concrete technology selected for every persistent component required by the MVP.

---

# 2. Decision

The following technologies are selected for the SecureCloud MVP:

| Component      | Technology                            | Decision  |
| -------------- | ------------------------------------- | --------- |
| Gateway        | **No database**                       | Stateless |
| Authentication | **PostgreSQL 17**                     | Selected  |
| Messaging      | **ScyllaDB**                          | Selected  |
| Files metadata | **PostgreSQL 17**                     | Selected  |
| Files content  | **MinIO using the S3-compatible API** | Selected  |
| Audit          | **ClickHouse**                        | Selected  |

These choices are implementation decisions.

They are not merely technology categories or future candidates.

The project will therefore proceed with these technologies.

If future benchmarks demonstrate that a selected technology cannot satisfy a hard requirement, this ADR may be amended. Until such evidence exists, implementation proceeds with the technologies selected here.

---

# 3. Persistence Architecture

The resulting persistence architecture is:

```text
                         SecureCloud
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
     Gateway                Auth               Messaging
   stateless            PostgreSQL 17           ScyllaDB
                             
        │
        │
        ├──────────────────► Files
        │                    │
        │                    ├── PostgreSQL 17
        │                    │     metadata
        │                    │
        │                    └── MinIO
        │                          encrypted objects
        │
        └──────────────────► Audit
                             │
                             └── ClickHouse
```

Each persistence technology serves a specific workload.

No service directly accesses another service's datastore.

---

# 4. Authentication — PostgreSQL 17

## Decision

The Authentication service will use **PostgreSQL 17**.

## Why PostgreSQL?

Authentication contains strongly related and security-sensitive state.

Examples include:

* accounts;
* authentication state;
* credentials and credential metadata;
* registered devices;
* device state;
* revocation state;
* authorization relationships;
* security policies.

These entities benefit from:

* ACID transactions;
* relational constraints;
* unique constraints;
* foreign-key relationships within the Auth database;
* transactional updates;
* mature indexing;
* predictable consistency;
* mature backup and recovery tooling.

PostgreSQL is therefore the appropriate persistence technology for Auth.

## Example

A device revocation operation may require several pieces of state to change consistently.

The operation should either commit completely or not commit at all.

PostgreSQL transactions provide the appropriate primitive for this type of state.

## Security boundary

PostgreSQL stores authentication-related state.

It does **not** store:

* message plaintext;
* file plaintext;
* users' private messaging keys;
* message decryption keys.

Authentication credentials and cryptographic messaging identity remain separate concerns.

---

# 5. Messaging — ScyllaDB

## Decision

The Messaging service will use **ScyllaDB**.

This is a concrete MVP technology choice.

We are not selecting "NoSQL" as an abstract category and postponing the real decision.

---

## Why ScyllaDB?

Messaging has a fundamentally different workload from Authentication.

The dominant operations are expected to be:

```text
SEND
  │
  ▼
store encrypted message
  │
  ▼
recipient/device partition
  │
  ├── retrieve pending messages
  │
  ├── acknowledge delivery
  │
  ├── update retry state
  │
  └── expire message
```

The workload is characterized by:

* high write volume;
* predictable key-based reads;
* recipient/device-oriented partitioning;
* durable offline queues;
* frequent state updates;
* horizontal scalability;
* no requirement for arbitrary relational joins over the message store.

ScyllaDB's distributed, partition-oriented architecture is a strong fit for this workload.

---

## Why not PostgreSQL for Messaging?

PostgreSQL could technically store messages.

However, using it as the primary high-throughput Messaging datastore would make the architecture less aligned with the workload we are deliberately designing for.

The Messaging service needs to support:

* large numbers of concurrent message writes;
* recipient-specific queues;
* offline delivery;
* horizontal scaling;
* predictable key-based access;
* distributed failure handling.

ScyllaDB gives Messaging a datastore whose fundamental data model is closer to these access patterns.

PostgreSQL remains where relational consistency provides significant value.

---

# 6. Messaging Data Model Principle

The ScyllaDB data model will be designed from **query/access patterns**, not from traditional relational normalization.

The primary access pattern is conceptually:

```text
recipient_device_id
        │
        ├── pending message 1
        ├── pending message 2
        ├── pending message 3
        └── ...
```

A message record will conceptually contain information such as:

* message ID;
* opaque sender/device identifier;
* recipient device identifier;
* encrypted message envelope;
* creation/acceptance timestamp;
* delivery state;
* retry state;
* expiration information;
* ordering information where required.

The exact table schema will be defined during implementation.

---

# 7. Messaging Security

ScyllaDB must never become a decryption authority.

Stored message data is encrypted before reaching the Messaging service.

Therefore:

```text
Client A
   │
   │ encrypted message
   ▼
Gateway
   │
   ▼
Messaging
   │
   │ ciphertext
   ▼
ScyllaDB
```

ScyllaDB stores ciphertext and associated delivery metadata.

A compromise of ScyllaDB must not provide access to message plaintext.

Private cryptographic keys remain on endpoint devices.

---

# 8. Files Metadata — PostgreSQL 17

## Decision

The Files service will use **PostgreSQL 17** for metadata and transfer state.

## Why?

File metadata is structured and relational.

Potential state includes:

* file ID;
* encrypted object ID;
* owner/device references;
* access relationships;
* transfer state;
* resumable-upload state;
* retention information;
* timestamps;
* lifecycle state.

Transactions and relational constraints are useful for maintaining this state correctly.

PostgreSQL therefore provides a better fit than introducing a distributed NoSQL database for this portion of the Files service.

---

# 9. Files Content — MinIO

## Decision

Encrypted file contents will be stored in **MinIO**, using its S3-compatible object-storage API.

MinIO is the concrete MVP object-storage implementation.

The architecture intentionally separates:

```text
File metadata
     │
     ▼
PostgreSQL 17

Encrypted file content
     │
     ▼
MinIO
```

## Why object storage?

Large binary objects should not be stored directly inside PostgreSQL as ordinary relational records.

Object storage provides a better model for:

* large files;
* streaming;
* resumable transfers;
* object identifiers;
* lifecycle management;
* independent storage scaling.

## Security

The file is encrypted at the endpoint before storage.

MinIO therefore stores encrypted content.

The Files service does not receive the plaintext file as part of the storage architecture.

Detailed encryption, object naming, access control and transfer security will be defined in the Files security architecture.

---

# 10. Audit — ClickHouse

## Decision

The Audit service will use **ClickHouse**.

This is a concrete MVP technology choice.

---

## Why ClickHouse?

Audit has a substantially different workload from Messaging.

The expected pattern is:

```text
event
  │
  ▼
append
  │
  ▼
retain
  │
  ▼
query by:
    timestamp
    event type
    actor/device
    operation
    service
    security event
```

Audit is naturally:

* append-heavy;
* time-oriented;
* potentially large;
* historical;
* query-intensive;
* analytical.

ClickHouse is particularly well suited to large-scale analytical workloads over structured event data.

It allows SecureCloud to keep the transactional databases focused on transactional workloads instead of using PostgreSQL as both operational storage and an increasingly large audit-analysis database.

---

# 11. Why Audit Does Not Use ScyllaDB

Although both Messaging and Audit can involve high write volume, their access patterns differ.

### Messaging

Optimized around:

```text
device → pending messages → delivery state
```

### Audit

Optimized around:

```text
time range → event type → actor/device → operational/security analysis
```

Therefore, using ScyllaDB simply because it has already been selected for Messaging would be premature reuse.

The architecture favors workload-specific technology when the difference is significant enough to justify it.

---

# 12. Audit Security

Audit may contain communication metadata because the architecture explicitly permits the recording of such metadata.

However, ClickHouse must not contain:

* message plaintext;
* file plaintext;
* private cryptographic keys;
* message decryption keys.

Audit is an observability/security-recording system, not a message-recovery mechanism.

The metadata stored must respect the metadata-minimization requirements defined elsewhere in the architecture.

---

# 13. Gateway — No Persistent Business Database

## Decision

The Gateway has no primary business database in the MVP.

It remains stateless.

Its responsibilities include:

* client connections;
* request routing;
* protocol negotiation;
* request limits;
* transport policies;
* backpressure;
* forwarding requests to backend services.

Persistent business state belongs to the appropriate backend service.

This allows Gateway instances to be:

* horizontally scaled;
* replaced;
* restarted;
* load-balanced.

without migrating Gateway-owned business state.

---

# 14. Database Ownership

The concrete technology decisions in this ADR do not change ADR-005.

Each service remains the sole owner of its persistence.

```text
Auth       → PostgreSQL 17
Messaging  → ScyllaDB
Files      → PostgreSQL 17 + MinIO
Audit      → ClickHouse
Gateway    → none
```

No service may directly access another service's datastore.

Therefore:

* no cross-service SQL;
* no cross-service database credentials;
* no cross-service foreign keys;
* no direct database integration;
* no shared tables.

Services communicate through their APIs and events defined by ADR-004.

---

# 15. PostgreSQL Deployment

For the MVP, PostgreSQL 17 may initially run as a shared PostgreSQL deployment while maintaining logical ownership separation.

Conceptually:

```text
PostgreSQL 17
│
├── Auth database
│
└── Files database
```

Each service uses its own credentials and connection configuration.

This is an implementation convenience, not a relaxation of the service boundary.

The architecture remains compatible with:

```text
Auth PostgreSQL
       +
Files PostgreSQL
```

as independently deployed databases later.

---

# 16. MVP Deployment

The selected technologies must be runnable through the project's initial Docker Compose environment.

The MVP persistence stack is therefore:

```text
PostgreSQL 17
ScyllaDB
MinIO
ClickHouse
```

alongside:

```text
Gateway
Auth
Messaging
Files
Audit
```

This gives the project a concrete, reproducible distributed persistence environment from the beginning.

---

# 17. Durability

The database choices do not by themselves define the application's durability semantics.

The Messaging service must provide application-level guarantees above the database.

In particular, ADR-007 will define precisely:

* when a message is accepted;
* when it is considered durable;
* when it enters the recipient's offline queue;
* what acknowledgement means;
* retry behavior;
* duplicate handling;
* ordering;
* expiration;
* failure semantics.

The selected ScyllaDB deployment must be configured to satisfy those guarantees.

A benchmark that achieves higher throughput by violating the durability requirements is not considered a successful benchmark.

---

# 18. Performance Validation

The project target includes approximately **10,000 messages/second peak throughput**.

The database architecture is designed to make this target technically plausible, but the target is not considered achieved until measured.

Benchmarking will evaluate:

* throughput;
* p50 latency;
* p95 latency;
* p99 latency;
* CPU;
* memory;
* network utilization;
* storage I/O;
* behavior under concurrent clients;
* behavior under offline recipients;
* retry traffic;
* database failures;
* recovery.

The benchmark methodology will be defined in the performance architecture.

The important principle is:

> **We choose the technology now; we validate the technology through measurements later.**

---

# 19. Consequences

## Positive

### Concrete implementation path

The engineering team can immediately begin implementing against known technologies.

There is no unresolved database-selection dependency.

### Workload alignment

Each persistence technology is selected for a specific workload.

### Distributed architecture

Messaging uses a datastore designed around distributed, partitioned workloads.

### Strong transactional state

Auth and Files metadata retain PostgreSQL's relational guarantees.

### Appropriate file storage

Large encrypted objects are separated from relational metadata.

### Efficient audit analysis

Audit data can be stored independently from transactional workloads.

### Service isolation

Each service retains ownership of its own data.

---

## Negative

Polyglot persistence increases operational complexity.

The MVP must operate:

* PostgreSQL;
* ScyllaDB;
* MinIO;
* ClickHouse.

The team therefore accepts additional:

* deployment complexity;
* monitoring requirements;
* backup/recovery responsibilities;
* operational knowledge requirements;
* integration testing.

This complexity is accepted because each technology has a clearly defined purpose.

---

# 20. Rejected Alternatives

## PostgreSQL Everywhere

Rejected.

It would simplify infrastructure but unnecessarily force high-volume Messaging and analytical Audit workloads onto a relational operational database.

---

## NoSQL Everywhere

Rejected.

Authentication and file metadata benefit significantly from PostgreSQL's transactional relational model.

---

## ScyllaDB Everywhere

Rejected.

ScyllaDB is appropriate for Messaging but does not provide sufficient architectural justification for replacing PostgreSQL's relational workload or ClickHouse's analytical workload.

---

## ClickHouse for Messaging

Rejected.

Messaging requires operational key-oriented reads, writes, delivery-state mutation and offline queue semantics rather than primarily analytical queries.

---

## PostgreSQL for Audit

Rejected as the primary Audit datastore.

Audit is expected to grow as an append-heavy historical dataset and requires efficient time-oriented analytical querying.

---

## MongoDB for Messaging

Rejected.

The Messaging workload is better represented by a partition-oriented wide-column/key-value model with predictable access patterns.

---

## Redis as the primary Messaging database

Rejected.

Redis may be considered later as an optimization/cache, but it is not the source of truth for durable offline messaging.

---

## Kafka as the Messaging database

Rejected.

Kafka may be considered later as an event-streaming infrastructure component, but the Messaging service requires durable application state and recipient-oriented retrieval semantics rather than treating an event log as its primary message database.

---

# 21. Security Requirements

All selected persistence systems must follow the same security principles.

### Least privilege

Each service receives only the permissions it needs.

### Credential isolation

Auth, Messaging, Files and Audit use separate credentials.

### Network isolation

Databases are not publicly exposed.

### Encryption in transit

Service-to-database communication uses appropriate transport protection.

### Encryption at rest

Persistent storage uses appropriate encryption-at-rest mechanisms.

### No plaintext secrets

Cryptographic private keys and message/file plaintext are not stored in these databases.

### Compromise containment

Compromise of one datastore should not automatically compromise the data held by other services.

---

# 22. Backup and Recovery

Each persistent technology must have a defined backup and recovery procedure before the MVP is considered operationally complete.

At minimum:

* PostgreSQL backups;
* ScyllaDB recovery strategy;
* MinIO/object-storage backup or replication strategy;
* ClickHouse backup/recovery strategy.

Recovery testing is required.

A backup that has never been successfully restored is not considered a validated backup.

---

# 23. Technology Version Policy

The ADR selects:

* **PostgreSQL 17**
* **ScyllaDB**
* **MinIO**
* **ClickHouse**

Exact patch/minor versions are implementation configuration and may be updated for security fixes, compatibility or operational reasons without requiring a new ADR.

A major technology replacement requires an ADR amendment.

---

# 24. Decision Philosophy

SecureCloud explicitly adopts the following architectural rule:

> **Make concrete technology decisions when the architecture provides enough information to make a defensible choice.**

The project does not create additional ADRs merely to postpone implementation decisions.

Likewise:

> **Benchmarking is validation, not indecision.**

If measurements demonstrate that the selected technology cannot satisfy a hard requirement, the existing ADR will be revised.

Until that happens, the selected technologies are the implementation baseline.

---

# 25. Final Decision

**APPROVED TECHNOLOGY BASELINE FOR MVP**

```text
┌──────────────────────────────────────────────┐
│              SecureCloud MVP                 │
├──────────────────────────────────────────────┤
│ Gateway       → Stateless                    │
│ Auth          → PostgreSQL 17                │
│ Messaging     → ScyllaDB                     │
│ Files         → PostgreSQL 17 + MinIO        │
│ Audit         → ClickHouse                   │
└──────────────────────────────────────────────┘
```

These technologies are now considered **selected**, not candidates.

The implementation proceeds using this persistence stack.

Future benchmarks may tune configuration, schemas, partitioning, indexes, replication and deployment topology.

A fundamental technology replacement requires an explicit amendment to this ADR.

---

# 26. Related ADRs

### Previous

* ADR-001 — Five Runtime Microservices
* ADR-002 — Runtime vs Infrastructure Control Plane
* ADR-003 — Distributed-First Architecture
* ADR-004 — Inter-Service Communication Model
* ADR-005 — Database Ownership / Database-per-Service

---

**Status: APPROVED — implementation baseline established.**
