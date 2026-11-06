# ADR-011 — Gateway-Owned Audit Spool and Durable Event Delivery

**Status:** Accepted  
**Date:** 2026-11-05  
**Decision Scope:** Gateway perimeter audit event persistence, delivery durability, and failure boundaries  
**Decision Gatekeeper / Approval:** Sergey (Technical Lead & Security Architect)  
**Related ADRs:** ADR-001 (Five Microservices), ADR-003 (Distributed Architecture First), ADR-004 (IPC Model), ADR-005 (Database Ownership Model — §5 Gateway Persistence), ADR-007 (Message Reliability & Durability), ADR-008 (Security & Cryptographic Architecture), ADR-009 (Distributed Failure & Resilience), ADR-010 (Performance, Capacity & Optimization)  

---

# 1. Context and Problem Statement

Card **`AUDIT-012`** mandates that the **SecureCloud API Gateway** (`securecloud-gateway`) integrate with the Centralized **Audit Service** (`securecloud-audit`) as a reliable audit event producer.

The Gateway sits at the perimeter of the SecureCloud platform. It terminates client TLS connections, inspects tokens, enforces IP/tenant rate limits, evaluates routing policies, and defends downstream services against denial-of-service and malformed requests. Consequently, the Gateway observes critical security events that no internal service ever sees:
- TLS handshake failures and cipher suite rejections;
- Corrupted, forged, or expired client bearer tokens rejected before reaching the Authentication Service;
- Route-level and tenant-level rate limit exhaustion;
- Schema violations, oversized payloads, and perimeter admission rejections;
- Downstream service circuit breaker state transitions.

### 1.1 The Architectural Constraints

Under existing architectural decisions:
1. **No Synchronous Coupling (`ADR-004`, `ADR-009`)**: Gateway request routing must never synchronously depend on the availability or latency of the Audit Service. An Audit Service outage or performance degradation must not impact user message ingestion or API availability.
2. **Gateway Persistence Boundary (`ADR-005` §5)**:
   > *"Gateway should remain as stateless as reasonably possible. It must not become the owner of core business data... If persistent Gateway-specific state becomes necessary, it must be explicitly owned by Gateway and documented through a subsequent architectural decision. Gateway must never directly access Auth DB, Messaging DB, Files DB, or Audit DB."*
3. **No Unapproved Infrastructure Dependencies (`ADR-001`, `ADR-003`)**: Card `AUDIT-012` explicitly forbids silently introducing an unapproved database, message broker (e.g. Kafka, RabbitMQ), or distributed queue.
4. **No Fictitious Durability Claims**: Under `ADR-007` and `RULES.md`, an in-memory queue must never be described as a durable outbox, nor can a non-transactional disk spool be described as a transactional outbox.

The Gateway does not own a relational database and does not execute business transactions. It cannot implement a conventional database transactional outbox like Auth (`AUDIT-013` on PostgreSQL). Therefore, a formal architecture decision is required to define how the Gateway durably captures and delivers its perimeter audit events.

---

# 2. Options Evaluated

| Option | Mechanism | Durability Guarantee | New Dependencies / Infrastructure | Operational & Architectural Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **Option A: Bounded In-Memory Queue Only** | Lock-free bounded ring buffer in RAM (e.g. 50,000 events) + asynchronous gRPC dispatcher threads | **Process-Lifetime Only**. Survives Audit Service downtime while the Gateway process lives. **100% data loss on crash, OOM-kill, `SIGKILL`, or node replacement.** | None | **Rejected for mandatory security events.** Under security audit regulations, process crashes or restarts coinciding with an attack would destroy perimeter audit evidence. Cannot be termed durable. |
| **Option B: Gateway-Owned Append-Only Disk Spool on Persistent Volume** *(Accepted)* | Segmented append-only WAL log files (`length + CRC32C + protobuf payload`) on a dedicated volume, group-commit `fsync`, ack checkpointing, background gRPC dispatcher | **Durable Asynchronous Delivery**. Survives process crash, OOM-kill, and container restart as long as the instance volume is reattached. Bounded group-commit window ($\le 20$ ms). | Docker Compose / K8s per-instance persistent volume mount (`/var/spool/securecloud-gateway/audit`). No new external libraries. | **Selected as the optimal strategy.** Balances zero synchronous request latency, high throughput, bounded resource usage, and survivability across process crashes without adding third-party infrastructure. |
| **Option C: Embedded SQLite with WAL Mode** | Embedded SQLite database file mounted on persistent volume per Gateway instance | Durable storage across crashes; SQL querying of outbox table. | Requires adding SQLite third-party library to Gateway dependencies. | **Rejected.** Heavier operational footprint, write amplification, and library bloat compared to a purpose-built binary append-only spool for an append/ack sequential pipeline. |
| **Option D: Shift Perimeter Event Ownership Downstream** | Eliminate Gateway event production; require downstream services (Auth, Messaging) to record perimeter events | Strong transactional durability in Auth/Messaging databases. | Substantial cross-service contract changes; does not solve perimeter rejections. | **Infeasible.** Downstream services never see perimeter rejections (e.g. invalid TLS, malformed JSON, rate limit drops, invalid JWT signatures). The Gateway is the sole authoritative witness. |
| **Option E: Synchronous External Broker (Kafka / RabbitMQ)** | Gateway publishes directly to a central message broker cluster | High durability across broker cluster. | Violates `ADR-001`, `ADR-004`, `ADR-005`. Adds heavy external distributed middleware. | **Strictly Rejected.** Explicitly forbidden by project constraints. |

---

# 3. Decision

1. **Adopt Option B for Mandatory Security Events** combined with **Option A for Best-Effort Diagnostics**:
   - **Mandatory Security Events** (token rejections, rate limiting, admission rejection, circuit breaker trips, audit loss alarms) are staged into the Gateway-owned **Persistent Disk Spool**.
   - **High-Frequency Diagnostic Events** (successful request admittance, transient forwarding errors) are routed through a bounded in-memory ring buffer with best-effort delivery semantics.
2. **Amend ADR-005 (§5 Gateway Persistence)**:
   - The Gateway is granted explicit architectural authority to own a local, bounded, append-only persistent storage spool directory (`/var/spool/securecloud-gateway/audit`) on a dedicated persistent volume.
   - This storage holds **producer delivery state only**, never core business state. The Gateway remains logically stateless with respect to platform business data.
3. **Explicitly Non-Transactional**:
   - The Gateway audit delivery mechanism is officially designated as a **Gateway-Owned Durable Audit Spool**, not a "Transactional Outbox".
4. **Canonical Event Model Compliance (`AUDIT-002`)**:
   - All events emitted by the Gateway use the canonical `securecloud.audit.v1.AuditEvent` format, RFC 9562 UUIDv7 identifiers, microsecond `occurred_at` timestamps, verified producer identity (`securecloud-gateway`), and bounded structured metadata.

---

# 4. Technical Design of the Gateway Audit Spool

```text
Incoming Client Request
         │
         ▼
┌─────────────────────────────────┐
│ Gateway Request Pipeline        │
│ (TLS / Token / Rate Limiter)    │
└────────┬────────────────────────┘
         │
         │ (Audit Event Produced)
         ▼
┌─────────────────────────────────┐
│ SensitiveDataGuard & Validator  │ (Zero secrets, zero tokens, UUIDv7)
└────────┬────────────────────────┘
         │
         ├────────────────────────────────────────┐
         ▼ (Mandatory Security Events)            ▼ (Best-Effort Diagnostics)
┌──────────────────────────────────┐     ┌──────────────────────────────────┐
│ Durable Spool Ingestion Channel  │     │ Bounded In-Memory Ring Buffer    │
└────────┬─────────────────────────┘     └────────┬─────────────────────────┘
         │                                        │
         ▼                                        ▼
┌──────────────────────────────────┐     ┌──────────────────────────────────┐
│ Background Spool Writer Thread   │     │ Asynchronous gRPC Dispatcher     │
│ (Group-commit fsync <= 20ms)     │     └────────┬─────────────────────────┘
└────────┬─────────────────────────┘              │
         │                                        │
         ▼                                        │
┌──────────────────────────────────┐              │
│ Segmented Append-Only Spool      │              │
│ (/var/spool/gateway/audit/*.wal) │              │
└────────┬─────────────────────────┘              │
         │                                        │
         ▼                                        │
┌──────────────────────────────────┐              │
│ Background Outbox Relay Worker   │              │
└────────┬─────────────────────────┘              │
         │                                        │
         ▼                                        │
┌─────────────────────────────────────────────────┴┐
│ Authenticated gRPC Client with mTLS (AUDIT-004) │
└────────┬─────────────────────────────────────────┘
         │
         ▼ IngestAuditEvents (Batch RPC)
┌─────────────────────────────────┐
│ Centralized Audit Service       │
└─────────────────────────────────┘
```

### 4.1 Segmented Append-Only Binary WAL
- The spool writes fixed-sized or bounded segment files (e.g. 16 MB per segment, with a hard maximum spool limit of 100 MB / 500,000 events).
- Record framing format:
  ```text
  [Magic: 4 bytes (0x53434153)] [Record Length: 4 bytes] [CRC32C: 4 bytes] [UUIDv7 Event ID: 16 bytes] [Payload: Protobuf binary]
  ```
- **Group-Commit Flush**: Staging threads push events into a lock-free queue. A dedicated background writer drains the queue and issues `fsync()` at bounded intervals ($\le 20$ ms or when 256 records accumulate), amortizing disk I/O costs to sub-millisecond latencies per request.

### 4.2 Checkpoint and Acknowledgement Protocol
- Confirmed ingestion by the Audit Service is recorded in a separate `checkpoint.json` file on the persistent volume via atomic write (`write_temp() + rename()`).
- Fully acknowledged segment files are purged immediately from disk, maintaining constant-bound disk utilization.

### 4.3 Aggregation Windows for Abuse Protection
To prevent denial-of-service floods (e.g., massive rate-limiting spikes or SYN floods) from filling the Gateway disk spool:
- High-frequency perimeter events (`gateway.rate_limit.exceeded`, `gateway.auth.token_invalid`) are aggregated in a thread-safe window (e.g., 1-second buckets per client IP / tenant).
- The spool persists a summarized event (`{"window_seconds": 1, "rejected_count": 450, "sample_reason": "TOKEN_EXPIRED"}`) rather than individual records, neutralizing disk-fill attacks.

---

# 5. Explicit Non-Guarantees and Failure Boundaries

In strict compliance with Card `AUDIT-012` requirements, the durability boundaries and failure cases of this architecture are explicitly enumerated:

1. **Un-Fsynced Crash Window**: Events submitted to the Gateway during the active group-commit window (up to 20 ms) immediately prior to a kernel crash, sudden physical power loss, or host hardware destruction are **not guaranteed to be durable**.
2. **Persistent Volume Destruction**: If the underlying physical volume attached to the Gateway instance is permanently destroyed, deleted, or corrupted without underlying storage replication, all un-replayed spooled events on that volume are lost.
3. **Spool Capacity Exhaustion (Disk Full / Volume Failure)**:
   - The Gateway spool enforces a strict maximum disk capacity bound (default: 100 MB).
   - If the Audit Service suffers prolonged downtime and the spool reaches maximum capacity, **the Gateway prioritizes platform availability**: it will never block incoming user traffic or cause client request failure.
   - Incoming audit events that cannot be spooled will be dropped at admission, incrementing the lock-free atomic counter `gateway_audit_events_dropped_total`.
   - When capacity permits or connectivity is restored, the Gateway synthesizes and dispatches an aggregated alarm event `gateway.audit.events_lost` recording the exact drop count and duration window.
4. **Not a Transactional Outbox**: The Gateway mechanism cannot provide rollback synchronization with client HTTP requests. If a downstream service fails after Gateway admission, the Gateway's admission event remains recorded.

---

# 6. Security and Data Protection Invariants (`ADR-008`, `RULES.md` §5)

1. **Zero-Secret / Zero-Credential Invariant**:
   - The Gateway audit producer must never write sensitive credentials to the spool or audit payloads.
   - Forbidden fields: passwords, password hashes, plaintext bearer tokens, refresh tokens, session cookies, TLS private keys, query parameter authorization codes, and E2E encrypted message ciphertexts.
   - Every event passes through `SensitiveDataGuard` before reaching the spool writer. Bearer tokens are converted strictly to safe truncated fingerprints (`SHA-256(token)[0..8]`).
2. **File System Security & Permissions**:
   - The spool directory permissions are strictly initialized to `0700` (`rwx------`).
   - Spool segment and checkpoint files are created with mode `0600` (`rw-------`).
   - Spool files are owned exclusively by the `securecloud` non-root service process UID/GID.
3. **No Cross-Instance Sharing**:
   - A spool directory/volume is strictly private to a single Gateway instance. Spool files are never shared across a distributed file system or mounted concurrently by multiple Gateway containers.

---

# 7. Operational Lifecycle & Horizontal Scaling

1. **Instance Retirement & Scale-Down Drain Runbook**:
   - When a Gateway instance is scheduled for termination (e.g. Kubernetes pod termination or auto-scaling down):
     1. Gateway enters the draining state (`readiness` probe returns unhealthy; Perimeter ingress stops sending new traffic).
     2. Gateway dispatcher thread is granted a termination grace period (default: 10 seconds) to flush the group-commit buffer and drain all remaining spooled WAL files to the Audit Service.
     3. Once the spool is empty (`pending_records == 0`), the process exits cleanly.
   - If a pod or instance is forcefully terminated (`SIGKILL`), its persistent volume must be reattached to the replacement instance or drained by an offline salvage tool.
2. **Observability & Diagnostics**:
   - Internal Prometheus metrics exposed on the internal listener (`/metrics`):
     - `gateway_audit_spool_bytes_gauge`: Current spool disk consumption in bytes.
     - `gateway_audit_spool_records_pending_gauge`: Count of records awaiting Audit ACK.
     - `gateway_audit_spool_events_enqueued_total{event_type, severity}`: Counter of accepted events.
     - `gateway_audit_spool_events_dropped_total{reason}`: Counter of dropped events due to spool capacity exhaustion.
     - `gateway_audit_delivery_latency_seconds`: Histogram of latency between event creation and Audit Service ACK.

---

# 8. Consequences and Compliance

### Positive Consequences
- **Reliable Perimeter Visibility**: Security-critical perimeter rejections, token forgeries, and abuse attempts are reliably recorded and survive temporary Audit Service downtime or Gateway restarts.
- **Strict Decoupling**: API Gateway routing and client response latencies are completely unaffected by Audit Service performance.
- **Zero Unapproved Dependencies**: Achieves robust durability using standard POSIX file I/O on persistent volumes without deploying external message brokers or third-party database engines.
- **Strict Privacy**: Strong redaction guards ensure compliance with zero-knowledge and zero-secret platform rules.

### Negative / Trade-Off Consequences
- **Storage Management**: Gateway instances require dedicated persistent volume mounts in Kubernetes / Docker Compose, slightly increasing deployment configuration complexity compared to purely stateless containers.
- **Scale-Down Drain Requirements**: Infrastructure orchestration must support termination grace periods to drain un-forwarded audit logs during cluster scale-in events.

---

# 9. Sign-Off and Approvals

| Role | Name | Status | Date |
| :--- | :--- | :--- | :--- |
| **Technical Lead & Security Architect** | Sergey | **Approved** | 2026-11-05 |
| **Gateway & Audit Engineer** | Lorenzo | **Accepted** | 2026-11-05 |

