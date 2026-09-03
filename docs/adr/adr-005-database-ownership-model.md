# ADR-005 — Database Ownership / Database-per-Service

**Status:** Approved
**Version:** v0.1
**Date:** 2026-09-02
**Decision Type:** Architecture / Data Management

---

# 1. Context

SecureCloud consists of five independently deployable runtime services:

1. Gateway
2. Authentication
3. Messaging
4. Files
5. Audit

ADR-001 established independent service ownership.

ADR-003 established that service boundaries are logical boundaries independent of physical deployment topology.

ADR-004 established that services communicate through explicit network contracts and that:

> **No service may directly access another service's database.**

The persistence architecture must therefore establish:

* which service owns which data;
* how databases are isolated;
* whether services may share database schemas;
* whether cross-service SQL is permitted;
* how transactions are scoped;
* how migrations are managed;
* how failures affect services;
* how the architecture can evolve from the MVP to a more distributed deployment.

The project specification identifies PostgreSQL as an intended technology, but the architecture must not prematurely assume that every future workload must use PostgreSQL.

The broader SQL vs NoSQL decision is therefore addressed separately by:

> **ADR-006 — SQL vs NoSQL Evaluation**

---

# 2. Decision Drivers

The database architecture is evaluated against:

1. **Service isolation**
2. **Security and least privilege**
3. **Independent deployment**
4. **Data ownership**
5. **Transactional consistency**
6. **Durability**
7. **Performance**
8. **Operational simplicity**
9. **Offline messaging**
10. **Failure isolation**
11. **Future scalability**
12. **Future database technology migration**
13. **Testing and backup/restore**

---

# 3. Core Decision

SecureCloud adopts the following principle:

> **Each runtime service owns its persistent data and is the sole authority allowed to modify that data.**

Each service accesses its own persistence layer.

No service accesses another service's database directly.

The canonical logical architecture is:

```text id="7u8k3m"
                  ┌───────────┐
                  │  Gateway  │
                  └─────┬─────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
              ▼         ▼         ▼
           ┌──────┐ ┌─────────┐ ┌───────┐
           │ Auth │ │Messaging│ │ Files │
           └──┬───┘ └────┬────┘ └───┬───┘
              │          │          │
              ▼          ▼          ▼
          Auth DB   Messaging DB  Files DB
                         
                         │
                         │ events
                         ▼
                     ┌───────┐
                     │ Audit │
                     └───┬───┘
                         │
                         ▼
                      Audit DB
```

The physical deployment may initially place these databases on the same PostgreSQL server or cluster, but **logical ownership remains separate**.

---

# 4. Database Ownership

The ownership model is:

| Service   | Owned Persistent Data                                                                 |
| --------- | ------------------------------------------------------------------------------------- |
| Gateway   | No primary business database                                                          |
| Auth      | Accounts, authentication state, device authorization state, credential metadata       |
| Messaging | Encrypted message envelopes, message lifecycle/delivery state, durable message queues |
| Files     | Encrypted file metadata, transfer state, storage references                           |
| Audit     | Audit events and authorized communication/security metadata                           |

The exact schemas are defined by the individual service architecture and are not part of this ADR.

---

# 5. Gateway Persistence

Gateway should remain as stateless as reasonably possible.

It must not become the owner of core business data.

Gateway may require limited ephemeral state for mechanisms such as:

* rate limiting;
* connection/session management;
* temporary request state;
* abuse protection.

Such state must not become a hidden shared database dependency.

If persistent Gateway-specific state becomes necessary, it must be explicitly owned by Gateway and documented through a subsequent architectural decision.

Gateway must never directly access:

* Auth DB;
* Messaging DB;
* Files DB;
* Audit DB.

---

# 6. Authentication Database

Auth owns authentication-related persistent data.

Examples include:

* account identifiers;
* authentication credentials or credential references;
* authentication state;
* authorization state;
* device registration state;
* device revocation state;
* security policy state.

Auth does **not** own message cryptographic private keys.

Auth does not become a cryptographic decryption authority.

Cryptographic identity and key distribution are addressed by:

> **ADR-011 — Cryptographic Identity and Key Distribution**

---

# 7. Messaging Database

Messaging owns persistent state required for reliable messaging.

Examples include:

* encrypted message envelopes;
* opaque sender/device identifiers;
* opaque recipient/device identifiers;
* message identifiers;
* delivery state;
* acknowledgement state;
* retry state;
* offline delivery state;
* message priority;
* emergency message state;
* expiration/retention state where applicable;
* asynchronous event/outbox state.

The Messaging database must never contain message plaintext.

The database is a storage mechanism, not a decryption authority.

---

# 8. Files Database

Files owns file-related metadata and transfer state.

Examples include:

* opaque file identifiers;
* encrypted file metadata;
* encrypted file storage references;
* upload state;
* download state;
* resumable-transfer state;
* access-control references;
* retention state.

File contents themselves do not necessarily need to reside inside PostgreSQL.

The architecture permits a dedicated encrypted blob/object storage mechanism.

The exact file-storage architecture is addressed by:

> **ADR-015 — Secure File Architecture**

Regardless of physical storage technology, Files remains the logical owner.

---

# 9. Audit Database

Audit owns persistent audit information.

Examples include:

* security events;
* authentication events;
* communication metadata authorized by the architecture;
* message lifecycle events;
* file lifecycle events;
* device-security events;
* operational security events;
* event identifiers;
* timestamps;
* integrity-related information.

Audit may contain communication metadata, as explicitly permitted by the SecureCloud trust model.

Audit must never contain:

* message plaintext;
* file plaintext;
* endpoint private keys;
* cryptographic secrets enabling message decryption.

---

# 10. Database-per-Service Principle

SecureCloud adopts **database-per-service as a logical ownership principle**.

This does not require five independent physical PostgreSQL servers during MVP.

The MVP may use:

```text id="kq2lxa"
                 PostgreSQL deployment
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       Auth DB      Messaging DB     Files DB
          │              │              │
          └──────────────┼──────────────┘
                         │
                      Audit DB
```

Each database has:

* independent ownership;
* independent credentials;
* independent migrations;
* independent access policy.

This provides logical isolation while keeping MVP infrastructure manageable.

---

# 11. Physical Database Topology

The architecture distinguishes:

### Logical isolation

Who owns the data?

### Physical isolation

Where does the data physically run?

These are intentionally independent.

Therefore the following are both valid deployments:

### MVP

```text id="m0j1s9"
Host
└── PostgreSQL
    ├── auth_db
    ├── messaging_db
    ├── files_db
    └── audit_db
```

### Future distributed deployment

```text id="s4p7bx"
Host A
└── Auth PostgreSQL

Host B
└── Messaging PostgreSQL

Host C
└── Files storage

Host D
└── Audit PostgreSQL
```

The services do not need to change their architectural ownership model when moving between these deployments.

---

# 12. Why Not One Shared Database?

The following model is explicitly rejected:

```text id="x4s8kz"
Auth ─────┐
Messaging ├──► Shared DB ◄── Files
Audit ────┘
```

where every service can directly query and modify shared tables.

Although operationally simple, this creates significant coupling.

Problems include:

* services depend on each other's schemas;
* migrations become coordinated;
* least-privilege boundaries become weaker;
* accidental cross-service access becomes possible;
* database schema becomes a hidden integration API;
* independent deployment becomes more difficult;
* service compromise can expose unrelated data;
* database transactions can silently cross service boundaries.

This contradicts the distributed-first architecture.

---

# 13. No Cross-Service SQL

The following is forbidden:

```text id="y8w2dc"
Messaging ──SQL──► Auth DB
```

The following is required:

```text id="a5j3rm"
Messaging ──gRPC──► Auth
```

If Messaging requires information owned by Auth, it requests that information through the Auth service contract.

This keeps ownership explicit.

---

# 14. No Cross-Service Foreign Keys

Foreign keys must not cross service boundaries.

For example, Messaging may store:

```text id="f6z2yq"
recipient_device_id = opaque identifier
```

but must not define a database-level foreign key to an Auth table.

Instead, the relationship is represented through the service contract.

This allows each service to evolve independently.

---

# 15. Transactions

Transactions are local to a service's database.

A normal transaction must follow:

```text id="7g9t3e"
Service operation
       │
       ▼
Service DB transaction
       │
       ▼
Commit / rollback
```

SecureCloud will not use distributed database transactions across services as a normal architectural mechanism.

For example:

```text id="q2m6vx"
Messaging DB transaction
          │
          X
          │
          X ── no distributed transaction ──► Auth DB
```

Cross-service consistency is achieved through service contracts, asynchronous events, idempotency and explicit workflow design.

The Transactional Outbox mechanism is defined by:

> **ADR-008 — Transactional Outbox**

---

# 16. PostgreSQL Strategy

PostgreSQL is adopted as the **initial MVP persistence technology candidate for transactional service data**, consistent with the project specification.

The MVP should initially use PostgreSQL unless a specific service demonstrates a justified requirement for another persistence technology.

However:

> **ADR-005 does not mandate PostgreSQL for every future workload.**

The architecture deliberately separates:

* database ownership;
* database placement;
* database technology.

This allows a service to evolve independently.

---

# 17. SQL vs NoSQL

The decision between SQL and NoSQL is intentionally not finalized by this ADR.

It will be evaluated in:

> **ADR-006 — SQL vs NoSQL Evaluation**

The evaluation must consider actual SecureCloud workloads, including:

* message persistence;
* delivery state;
* offline queues;
* audit/event storage;
* file metadata;
* consistency requirements;
* query patterns;
* throughput;
* durability;
* operational complexity.

NoSQL must not be introduced merely because the architecture is distributed.

---

# 18. Service Database Credentials

Every service must have its own database credentials.

Example logical model:

```text id="v8k5nr"
Auth Service
    │
    └── auth_db credentials

Messaging Service
    │
    └── messaging_db credentials

Files Service
    │
    └── files_db credentials

Audit Service
    │
    └── audit_db credentials
```

Messaging credentials must not grant access to Auth tables.

Files credentials must not grant access to Messaging tables.

Audit credentials must not grant access to private service data.

Least privilege is mandatory.

---

# 19. Database Administration vs Application Authority

Database administration privileges and application cryptographic authority are separate.

A database administrator may technically have powerful access to stored data depending on deployment configuration.

However:

> **Access to encrypted database records must not provide the ability to decrypt SecureCloud messages or files.**

This is because:

* messages are encrypted at the endpoint;
* files are encrypted at the endpoint;
* private keys remain at endpoints;
* backend services do not possess decryption keys.

Therefore database compromise and cryptographic compromise are intentionally separated.

---

# 20. Encryption at Rest

Database encryption at rest is an additional security layer.

It protects against threats such as:

* stolen storage media;
* unauthorized access to database files;
* certain infrastructure-level compromise scenarios.

However, encryption at rest is not considered a substitute for end-to-end encryption.

The security hierarchy is:

```text id="n1j6cv"
Endpoint encryption
       ↓
E2E confidentiality

Database encryption at rest
       ↓
Infrastructure/storage protection
```

The two mechanisms solve different problems.

---

# 21. Failure Domains

During MVP, multiple logical databases may reside on one PostgreSQL deployment.

This means:

> **Logical database isolation does not imply physical failure isolation.**

For example:

```text id="8m4r2x"
             PostgreSQL
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
     Auth    Messaging    Audit
       │         │         │
       └─────────┼─────────┘
                 X
        PostgreSQL unavailable
```

A PostgreSQL outage could therefore affect several services simultaneously.

This is an accepted MVP operational tradeoff.

The architecture retains the ability to move individual services to independent database deployments later.

---

# 22. Database Resource Contention

Separate logical databases on the same PostgreSQL deployment still share:

* CPU;
* memory;
* disk;
* I/O;
* connection capacity;
* PostgreSQL instance resources.

Therefore database-per-service does not automatically eliminate performance interference.

The system must measure:

* database CPU;
* I/O;
* connection pool utilization;
* query latency;
* lock contention;
* transaction duration;
* storage growth;
* throughput.

Physical database separation may become necessary if measured workloads justify it.

---

# 23. Connection Management

Each service manages its own database connection pool.

A service must not:

* share another service's connection pool;
* use another service's credentials;
* connect directly to another service's database.

Connection limits must be bounded.

This prevents a single service from exhausting all database connections.

---

# 24. Migrations

Database schemas are owned by their respective services.

Therefore:

```text id="n3z7qc"
Auth
 └── Auth migrations

Messaging
 └── Messaging migrations

Files
 └── Files migrations

Audit
 └── Audit migrations
```

A service owns:

* schema definition;
* migrations;
* indexes;
* constraints;
* database-specific optimizations.

Deployments must not require another service to manually modify its database.

Migration compatibility must be considered during rolling deployments in future distributed environments.

---

# 25. Backups and Recovery

Each owned persistence domain must have a defined:

* backup strategy;
* restore procedure;
* retention policy;
* integrity verification;
* recovery procedure.

Messaging persistence is particularly important because offline messaging requires durable storage.

A database backup must preserve encrypted message data without introducing a new decryption capability.

Database recovery must therefore restore ciphertext and metadata, not plaintext.

---

# 26. Offline Messaging

The database ownership model directly supports offline communication.

When a recipient is offline:

```text id="w5s2je"
Sender
   │
   ▼
Messaging
   │
   ▼
Messaging DB
   │
   │ encrypted message retained
   ▼
Recipient reconnects
   │
   ▼
Delivery
```

The Messaging service remains responsible for:

* durable storage;
* pending delivery;
* retry state;
* acknowledgement state;
* device-specific delivery state.

The exact durability guarantee and retention semantics are defined by:

> **ADR-007 — Messaging Durability Model**

---

# 27. Audit Persistence

Audit is intentionally separated from operational service databases.

Audit events are not stored by directly inserting into Messaging, Auth or Files databases.

Instead:

```text id="t8c1zp"
Messaging
    │
    │ asynchronous event
    ▼
Audit
    │
    ▼
Audit DB
```

This preserves the service boundary and allows Audit to evolve independently.

The exact reliability relationship between a business transaction and its audit event is defined by ADR-008.

---

# 28. Security and Compromise Containment

Database ownership contributes directly to the compromise-containment objective.

If Messaging is compromised:

```text id="j4w6sp"
Messaging compromise
       │
       ▼
Messaging DB access
       │
       ├── encrypted messages
       ├── delivery metadata
       └── Messaging-owned state

       X
       │
       X── Auth DB
       X── Files DB
       X── Audit DB
```

The attacker should not automatically obtain access to unrelated service databases.

This does not eliminate the consequences of service compromise, but reduces its blast radius.

---

# 29. Performance Considerations

The database architecture must support the project's performance objective, including the approximately 10,000 messages/sec peak target.

However, database technology and topology must be validated experimentally.

Important measurements include:

* inserts/sec;
* reads/sec;
* transaction latency;
* connection pool saturation;
* lock contention;
* disk I/O;
* WAL throughput;
* queue growth;
* database CPU;
* storage growth;
* p95/p99 latency.

The database must not become an unmeasured bottleneck hidden behind the messaging service.

Performance optimization follows:

```text id="h7c3bn"
Baseline
   ↓
Benchmark
   ↓
Profile
   ↓
Identify DB bottleneck
   ↓
Optimize
   ↓
Benchmark again
```

---

# 30. Testing

The architecture requires database-specific testing.

### Unit tests

Test repository/data-access behavior independently of the database where practical.

### Integration tests

Run each service against its actual database technology.

Verify:

* migrations;
* transactions;
* constraints;
* indexes;
* connection handling;
* persistence behavior.

### Isolation tests

Verify:

* Messaging cannot access Auth DB;
* Files cannot access Messaging DB;
* Audit cannot access private service databases;
* credentials have only required privileges.

### Failure tests

Test:

* database unavailable;
* connection exhaustion;
* transaction rollback;
* timeout;
* disk/storage failure scenarios where practical;
* service restart;
* database restart.

### Recovery tests

Test:

* backup;
* restore;
* data integrity;
* encrypted message recovery;
* offline message recovery.

---

# 31. MVP Boundary

## Required

* database-per-service logical ownership;
* no cross-service SQL;
* no cross-service foreign keys;
* service-specific credentials;
* service-owned migrations;
* transactions scoped to individual services;
* PostgreSQL as initial MVP persistence candidate;
* separate logical databases for services where PostgreSQL is used;
* database connection limits/pooling;
* backup and restore strategy;
* integration testing;
* database isolation testing.

## Not required

* separate PostgreSQL server for every service;
* multi-region databases;
* distributed database transactions;
* database sharding;
* read replicas;
* automatic database failover;
* polyglot persistence;
* NoSQL;
* globally distributed databases.

These may be introduced later based on demonstrated requirements.

---

# 32. Consequences

## Positive

* Strong service ownership;
* reduced coupling;
* better compromise containment;
* independent migrations;
* independent database evolution;
* no hidden database-based service integration;
* compatible with distributed deployment;
* PostgreSQL remains operationally manageable during MVP;
* future physical database separation remains possible.

## Negative

* Cross-service queries become service-to-service calls;
* joins across services are impossible by design;
* distributed workflows become more complex;
* duplicated/reference data may sometimes be necessary;
* one PostgreSQL deployment still represents a shared failure/resource domain during MVP.

These tradeoffs are intentional.

---

# 33. Important Architectural Rule

The following rule is normative:

> **A service owns its data. Other services do not access that data directly.**

If another service requires information, it must request it through an explicit service contract or consume an appropriate asynchronous event.

This rule remains valid even if two services run on the same physical machine.

Physical co-location must never become an excuse to bypass the architecture.

---

# 34. Related ADRs

* **ADR-001** — Five Runtime Microservices
* **ADR-002** — Runtime vs Infrastructure Control Plane
* **ADR-003** — Distributed-First Architecture
* **ADR-004** — Inter-Service Communication Model
* **ADR-006** — SQL vs NoSQL Evaluation
* **ADR-007** — Messaging Durability Model
* **ADR-008** — Transactional Outbox
* **ADR-009** — Distributed Failure & Resilience Model
* **ADR-011** — Cryptographic Identity and Key Distribution
* **ADR-015** — Secure File Architecture
* **ADR-017** — Performance Benchmark Methodology

---

# 35. Final Decision Summary

SecureCloud adopts:

> **Database-per-service as a logical ownership principle.**

> **Each service is the sole owner and authority over its persistent data.**

> **No cross-service SQL, shared tables, or cross-service foreign keys are permitted.**

> **Services communicate through explicit network contracts rather than database access.**

> **PostgreSQL is the initial MVP persistence candidate, with separate logical databases and service-specific credentials.**

> **Multiple logical databases may initially share one PostgreSQL deployment to reduce MVP operational complexity.**

> **Physical database separation remains possible without changing service boundaries.**

> **The choice between SQL and NoSQL remains an explicit investigation in ADR-006 rather than being prematurely imposed by this ADR.**

The resulting architectural principle is:

**Logical ownership first. Physical separation when justified.**

**Service API, not database, is the integration boundary.**
