# AUDIT-012 — Gateway Audit Producer and Durable Outbox
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: `AUDIT-012`  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Ticket Decomposition — **Decisions D1–D8 approved; formalised in ADR-011 (`docs/adr/adr-011-gateway-audit-event-delivery.md`)**  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey
**Date**: November 5, 2026  
**Dependencies**: `AUDIT-002` (Canonical Event Model & Validator), `AUDIT-004` (Authenticated gRPC Ingestion Contract), `AUDIT-005` (Bounded Asynchronous Ingestion), `AUDIT-006` (Deduplication & Retry-Safe Acknowledgements), `AUDIT-010` (Readiness & Graceful Shutdown), `AUDIT-011` (Ingestion Metrics & Diagnostics), `GW-001`–`GW-010` (Gateway perimeter)  
**Related ADRs**: `ADR-004` (IPC model), `ADR-005` (Database Ownership — §5 Gateway Persistence), `ADR-007` (Reliability & Transactional Outbox), `ADR-008` (Security / Service PKI), `ADR-009` (Failure Resilience), `ADR-010` (Bounded Resources)

---

## 1. Executive Summary

`AUDIT-012` makes the Gateway a producer of canonical audit events, delivered to the Audit Service through the existing authenticated gRPC ingestion contract (`securecloud.audit.v1.AuditIngestionService`) **without** making normal request processing synchronously dependent on Audit availability.

The card's central difficulty is architectural, not mechanical:

> **The Gateway has no persistence resource and no transactional boundary.** The approved architecture defines it as stateless (`gateway-design.md` §3.22, `ADR-005` §5, `RULES.md` §6 "Gateway — Stateless"). A *transactional* outbox in the sense of `ADR-007` §18–§19 is therefore **impossible** for the Gateway, and any *durable* pending-event mechanism requires a new, explicitly approved architectural decision (`ADR-005` §5: *"If persistent Gateway-specific state becomes necessary, it must be explicitly owned by Gateway and documented through a subsequent architectural decision."*).

Consequently this decomposition starts with a **mandatory decision ticket (`T01`)** that produces the event catalog, the ownership matrix and a durability ADR. **No implementation ticket (`T02`–`T07`) may start until `T01` is approved.** Tickets `T03`–`T04` are written against an abstract `IAuditPendingStore` so they remain valid for whichever option is approved.

---

## 2. Verified Current State (what already exists)

### 2.1 Gateway (`src/gateway/`)

| Fact | Evidence | Consequence for AUDIT-012 |
| :--- | :--- | :--- |
| Gateway links **no database, filesystem-state or broker library**; CMake targets: `gateway_config`, `gateway_tls`, `gateway_grpc`, `gateway_http`, `gateway_health` | [CMakeLists.txt](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/CMakeLists.txt) | No existing store to commit an outbox record atomically with. |
| No business state; Gateway observations are **rejections/decisions**, not state changes | `gateway-design.md` §3.22 | There is **no business operation to be atomic with**. "Transactional outbox" must not be claimed. |
| Audit endpoint and channel already configured: `audit_endpoint{"audit:50055"}`, `deadlines.audit_timeout_ms{1000}`, `GrpcChannelManager::get_audit_channel()` (SAN-verified mTLS) | [gateway_config.hpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/gateway_config.hpp#L39), [channel_manager.hpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/channel_manager.hpp#L40) | Delivery transport + service identity (`DNS:gateway` client cert) are reusable; no new PKI. |
| Resilience primitives exist: `RetryPolicy` (exp. backoff, ±25% jitter), `CircuitBreakerRegistry`, `DrainManager` | `src/gateway/http/resilience/` | Reuse for dispatcher; do not duplicate retry logic (`error-handing-and-retry.md` §53). |
| Audit-relevant decision points exist: `AuthenticationMiddleware` (401/403/503), `AuthorizationMiddleware` (MFA, assurance, device binding, scope), `RateLimiterMiddleware` (429), `ResourceLimiterMiddleware` (413/431/503), `HeaderSanitizer` (spoofed identity headers), `StreamingSha256Validator` (`CHUNK_INTEGRITY_MISMATCH`), `CircuitBreaker` state changes | `src/gateway/http/**` | These are the Gateway-owned observation points (§3). |
| No Gateway metrics registry; observability = `LoggingMiddleware` structured access logs | `gateway-architecture-and-functioning.md` §22 | Producer metrics need a lightweight registry (AUDIT-011 pattern) + an exposure decision (`T01` D5). |
| `RequestIdMiddleware` generates **UUIDv4** and propagates client-supplied `X-Request-ID` | [request_id_middleware.hpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/middleware/request_id_middleware.hpp#L14) | `correlation_id` must not blindly trust client input; ClickHouse column is `UUID` (`05-audit-data-model.md` §5.15). Handled in `T02`. |
| Gateway readiness = Auth connectivity only | [gateway_health_evaluator.hpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/health/gateway_health_evaluator.hpp) | Audit unavailability must **not** withdraw Gateway readiness (§3.21 "Audit unavailable"). |
| Gateway does **not** currently emit any audit event | `grep -ri audit src/gateway` → config/channel/route stubs only | Greenfield producer. |

### 2.2 Audit Service (receiving side)

| Fact | Evidence |
| :--- | :--- |
| Contract: `AuditIngestionService.SubmitAuditEvent` / `BatchSubmitAuditEvents`; `AuditEventProto` with `event_id`, `occurred_at_ms`, `event_type`, enums, `correlation_id`, `optional causation_id`, `map<string,string> metadata` | [audit.proto](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/audit/v1/audit.proto) |
| Batch response returns `accepted_count`, `rejected_count`, `rejected_event_ids` (**no per-item reason**) | audit.proto L81–85 |
| `received_at` assigned by Audit only; producer cannot set it | AUDIT-002 §1 inv. 4, AUDIT-004-T03 |
| Producer identity bound to mTLS SAN `gateway.securecloud.internal` → `gateway` | [producer_identity_validator.cpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/audit/domain/producer_identity_validator.cpp#L33) |
| Ack semantics (AUDIT-006 §2.4): `OK` ⇔ committed to ClickHouse or duplicate of committed identical payload; `RESOURCE_EXHAUSTED`/`UNAVAILABLE`/`DEADLINE_EXCEEDED` ⇒ retain & retry; `ALREADY_EXISTS` ⇒ payload conflict (terminal); `INVALID_ARGUMENT`/`PERMISSION_DENIED` ⇒ terminal | AUDIT-006 §2.4 |
| Draining Audit returns `UNAVAILABLE` and never ACKs uncommitted events | AUDIT-010 §3 |
| Validator: UUIDv7 + variant, `occurred_at ∈ [now−max_past_age, now+5 min]`, event-type format `^[a-z0-9_]+(\.[a-z0-9_]+)+$` (**no producer-namespace binding**), metadata ≤ 50 entries / key ≤ 64 / value ≤ 1024, `SensitiveDataGuard` | `src/audit/domain/audit_event_validator.cpp`, `sensitive_data_guard.cpp` |
| `EventId::generate_v7()`, `AuditEventValidator`, `SensitiveDataGuard` live in the pure library `securecloud_audit_domain` | AUDIT-002-T01..T03 |

### 2.3 Other producers (duplicate-ownership context)

- **Auth** defines `auth.login.*`, `auth.session.revoked_attempt`, `auth.session.expired_attempt`, `auth.token.reuse_detected`, `auth.mfa.*`, `auth.device.*` ([audit_event.hpp](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/audit_event.hpp#L15-L91)); its `AuditEventPublisher` currently writes to a log sink only (Auth → Audit delivery is a separate card and **out of scope here**).
- **Messaging / Files** own genuine transactional outboxes (ScyllaDB `messaging_outbox_events`, PostgreSQL `files_outbox`).

> [!IMPORTANT]
> Documentation drift to resolve in `T01`: `audit-design.md` §7.2/§7.9 and `05-audit-data-model.md` §5.20/§5.23/invariant 37 state that *"runtime services persist audit events through their durable [transactional] outbox"*. This is not achievable for the stateless Gateway. `T01` must amend these documents to describe the Gateway's approved, explicitly qualified mechanism.

---

## 3. Gateway Audit Event Catalog & Ownership Matrix

### 3.1 Ownership rules

1. **Gateway owns perimeter decisions it makes itself** (header/body/concurrency limits, rate limiting, local token rejection, coarse authorization, spoofed-header detection, chunk integrity rejection).
2. **Auth owns authentication-authority outcomes** (login, MFA, refresh, session revocation/expiry determined by Auth). When the Gateway forwards a token to `Auth.ValidateSession` and Auth rejects it as revoked/expired, **Auth's `auth.session.*_attempt` event is authoritative; the Gateway does not emit a second event** — it only increments a metric.
3. **Backends own fine-grained business authorization and business events** (`message.*`, `conversation.*`, `file.*`). The Gateway never emits success events for proxied business operations.
4. **Successful requests are not audit events** — they belong to the access log (`LoggingMiddleware`).
5. Event-type names already in the canonical contract (`05-audit-data-model.md` §5.8) are reused verbatim; new names use the `gateway.` namespace and are added to §5.8 by `T01`.

### 3.2 Catalog

| # | `event_type` | Severity | Class | Source component | Actor / Target | Bounded metadata (examples) |
| :-- | :--- | :--- | :--- | :--- | :--- | :--- |
| E1 | `security.token.rejected` | SECURITY | **Mandatory** | `AuthenticationMiddleware` — missing/malformed `Authorization`, local verifier signature/expiry/structure failure | `UNKNOWN` (no actor_id) / `SERVICE`=`gateway` | `reason` ∈ {`missing`, `malformed`, `invalid_signature`, `expired_local`}, `route_class`, `method`, `client_ip` |
| E2 | `security.authorization.denied` | SECURITY | **Mandatory** | `AuthenticationMiddleware` / `AuthorizationMiddleware` — insufficient scope, MFA required, insufficient assurance, device binding required | `USER`=verified `user_id` / `SERVICE`=target backend (`auth`/`messaging`/`files`) | `reason`, `route_class`, `method`, `device_id` (verified), `required_scope` (static name only) |
| E3 | `gateway.security.identity_header_stripped` | SECURITY | **Mandatory** | `HeaderSanitizer` (client attempted to inject `X-User-Id` etc.) | `UNKNOWN` or verified `USER` / `SERVICE`=`gateway` | `header_names` (closed-set names, never values), `count` |
| E4 | `gateway.file.chunk_integrity_rejected` | SECURITY | **Mandatory** | `StreamingSha256Validator` via `FilesProxyHandler` | `USER` / `FILE`=`file_id` or upload id | `chunk_index`, `reason=CHUNK_INTEGRITY_MISMATCH` (never digests of content) |
| E5 | `gateway.rate_limit.exceeded` | WARNING | **Mandatory, aggregated** | `RateLimiterMiddleware` | `USER` or `UNKNOWN` / `SERVICE`=`gateway` | `window_start`, `window_seconds`, `rejected_count`, `key_type` ∈ {`user`,`ip`} |
| E6 | `gateway.request.rejected` | WARNING | **Mandatory, aggregated** | `ResourceLimiterMiddleware` (431/413/503 concurrency cap) | `UNKNOWN` / `SERVICE`=`gateway` | `reason` ∈ {`header_too_large`,`payload_too_large`,`concurrency_cap`}, `rejected_count`, window |
| E7 | `gateway.dependency.circuit_opened` / `gateway.dependency.circuit_closed` | WARNING / INFO | Best-effort | `CircuitBreaker` transitions | `SERVICE`=`gateway` / `SERVICE`=dependency | `dependency`, `failure_count` |
| E8 | `gateway.lifecycle.started` / `gateway.lifecycle.drain_started` / `gateway.lifecycle.stopped` | INFO | Best-effort | `main.cpp`, `DrainManager` | `SYSTEM` / `SERVICE`=`gateway` | `version`, `pending_audit_events` (stop only) |
| E9 | `gateway.audit_producer.events_lost` | CRITICAL | **Mandatory (self-accounting)** | Producer itself, after capacity exhaustion or unrecoverable loss | `SYSTEM` / `SERVICE`=`gateway` | `lost_count`, `class`, `reason` ∈ {`store_full`,`store_unavailable`,`crash_recovery_gap`}, window |

**Explicitly not Gateway-owned:** `auth.login.*`, `auth.mfa.*`, `auth.session.*`, `auth.device.*`, `message.*`, `conversation.*`, `file.upload.completed`/`file.deleted`, TLS handshake failures (occur inside OpenSSL before HTTP; infra observability), successful requests.

### 3.3 Flood-safety by aggregation (mandatory)

E5/E6 (and E1 when exceeding a per-key threshold) are attacker-controllable volumes. Emitting one event per rejected request would let an attacker convert a request flood into a disk/network flood. Therefore these are emitted as **windowed aggregate events** by a bounded `AuditAggregationWindow` (default 60 s window, ≤ 10,000 tracked keys with LRU eviction; evicted keys are flushed immediately as an aggregate, never dropped). This keeps audit volume `O(distinct keys per window)` rather than `O(requests)`, while preserving the security fact (who, what, how many, when).

### 3.4 Trusted attribution rules

- `actor_id`, `device_id`, `session_id` come **only** from the verified `AuthenticatedContext`; never from headers, query or body.
- `client_ip` uses `req.remote_addr`; `X-Forwarded-For` is recorded only when a trusted-proxy setting is configured (otherwise ignored for attribution).
- `correlation_id`: if the request ID is a syntactically valid UUID it is used; otherwise (client-supplied garbage or overlong value) a fresh UUIDv7 is generated and the client value is **not** copied into the event.
- `route_class` is a closed enum derived from the matched route pattern (never the raw path, which may contain IDs or attacker input).
- Never included: `Authorization` header, tokens, passwords, MFA codes, request/response bodies, ciphertext, chunk digests, raw query strings.

---

## 4. Durability Strategy — Mandatory Architecture Decision

### 4.1 Findings

1. **No Gateway-owned persistence** exists and none is approved (`ADR-005` §5, `RULES.md` §6).
2. **No atomic boundary is available**: Gateway events describe rejected requests; there is no business write to commit the event with. ⇒ *Transactional outbox guarantees cannot be claimed for any Gateway event, under any option.*
3. **Audit synchronous submission in the request path is forbidden** (`gateway-design.md` §3.21, card constraint).
4. Gateway instances are horizontally interchangeable with no sticky state (§3.22) — any per-instance durable state introduces a scale-down/drain obligation.

### 4.2 Options

| Option | Mechanism | Actual durability guarantee | New infra / ADR | Risks |
| :--- | :--- | :--- | :--- | :--- |
| **A — Bounded in-memory pending queue, explicitly non-durable** | Lock-bounded ring buffer (e.g. 50,000 events) + dispatcher | Survives Audit outages up to buffer capacity **while the process lives**. **Lost on crash, OOM-kill, `SIGKILL`, container replacement.** Must be labelled *"best-effort, at-most-once on process loss"*. **Not an outbox.** | None | Mandatory events can be lost on process loss; must be documented as a limitation. |
| **B — Gateway-owned, per-instance, bounded append-only spool on a persistent volume** *(recommended)* | Segmented append-only log files (`len + CRC32C + record`), group-commit `fsync`, ack checkpoint, compaction of fully-acked segments, bounded total bytes | Event is *durably queued* only **after fsync** (group-commit window, default ≤ 20 ms / 256 records). Survives process crash/restart **if the same volume is reattached**. Lost if the volume is lost (node failure without replicated storage) or within the un-fsynced window. Still **not transactional**. | **New ADR-011** amending ADR-005 §5; Docker Compose named volume for `gateway` (per instance); no new library (std filesystem + OpenSSL/CRC) | Disk-fill attack (mitigated by §3.3 aggregation + byte cap); scale-down must drain or hand-off volume; adds operational state to a "stateless" service. |
| **C — Embedded SQLite (WAL) per instance** | Same as B using SQLite | Same as B | New ADR + **new third-party dependency** | Heavier than B for an append/ack workload; card forbids unapproved DB. |
| **D — Shift ownership to a service with a real outbox** (e.g. Auth records rejections it observes) | Reduce Gateway-owned catalog | Strong for shifted events only | Cross-service contract changes | Auth never sees requests rejected before reaching it (E3–E6); does not solve the problem. |
| **E — Synchronous submit / shared DB / broker (Kafka, RabbitMQ)** | — | — | — | **Rejected** by card constraints and ADR-004/005. |

### 4.3 Recommendation (subject to explicit approval)

**Option B for Mandatory events + Option A semantics for Best-effort diagnostics**, formalised in a new **`ADR-011 — Gateway-Owned Audit Spool`**:

- Mandatory events (E1–E6, E9) → durable spool (fsync'd); Best-effort events (E7, E8) → bounded in-memory lane, explicitly non-durable.
- The producer API returns a tri-state admission result: `DurablyQueued` (only after fsync completes — used by tests/shutdown), `AcceptedPendingSync` (normal hot-path result; the request thread never waits for fsync), `Rejected{reason}`.
- **Explicitly non-guaranteed** (documented in ADR-011 and the data model):
  1. events created within the un-fsynced group-commit window at the moment of a crash;
  2. all spooled events if the per-instance volume is destroyed;
  3. events refused because the spool is full or unavailable (accounted for by E9 + metrics, never silently).
- If Option B is **rejected**, the fallback is Option A, and `audit-design.md` / data model must state that Gateway audit delivery is *best-effort with process-lifetime buffering*.

### 4.4 Decision items requiring sign-off in `T01`

| ID | Decision | Proposed default |
| :-- | :--- | :--- |
| D1 | Durability option | B (mandatory) + A (best-effort) via ADR-011 |
| D2 | Event catalog & mandatory/best-effort classes | §3.2 |
| D3 | Behaviour when spool full/unavailable | Never block or fail the client request; refuse admission, count, emit aggregated E9 when possible; Gateway readiness unaffected; producer health = `DEGRADED` |
| D4 | Reuse of `securecloud_audit_domain` (UUIDv7, `AuditEventValidator`, `SensitiveDataGuard`) from the Gateway | Link the pure domain library (no ClickHouse/server deps — to be verified) rather than duplicating; alternative: extract `EventId` into `securecloud::common` |
| D5 | Metrics exposure | Lock-free registry (AUDIT-011 pattern); exposed **only** on the internal mTLS listener (never on the public HTTPS port) + rate-limited periodic structured log snapshot |
| D6 | Capacities | Spool 256 MiB / 1,000,000 events max, segment 8 MiB, quarantine 16 MiB; best-effort lane 10,000 events; batch ≤ 100 (Audit limit) |
| D7 | Retry policy | `error-handing-and-retry.md` §55 *Outbox*: initial 250 ms, ×2, max 30 s, ±25% jitter, per-attempt deadline = `deadlines.audit_timeout_ms` (1 s); **no max-attempt drop** for retryable failures (retained until delivered/terminal), bounded by spool capacity |
| D8 | Scale-down handling for Option B | `drain_started` → flush within grace budget; remaining records stay on volume; re-attached instance replays; orphaned-volume runbook documented |

### 4.5 Decision Record (approved)

| ID | Approved decision |
| :-- | :--- |
| D1 | **Option B + A**: per-instance, bounded, append-only fsync'd spool on a Gateway-owned persistent volume for **Mandatory** events; bounded in-memory, explicitly non-durable lane for **Best-effort** events. Formalised as **ADR-011**. |
| D2 | Event catalog §3.2 and ownership rules §3.1 approved as written. |
| D3 | Spool full/unavailable: never block or fail the client request; refuse admission, count it, emit aggregated `gateway.audit_producer.events_lost` (CRITICAL); Gateway readiness unaffected; producer health `DEGRADED`. |
| D4 | **Link the existing `securecloud::audit_domain` library** for `EventId::generate_v7()`, `AuditEventValidator` and `SensitiveDataGuard` (no extraction to `common`). |
| D5 | Producer metrics exposed **only** on the Gateway's internal mTLS listener; never on the public HTTPS port. |
| D6 | Spool 256 MiB / 1,000,000 events, segment 8 MiB, quarantine 16 MiB; best-effort lane 10,000 events; batch ≤ 100. |
| D7 | Backoff 250 ms initial, ×2, max 30 s, ±25% jitter; per-attempt deadline 1 s; retryable events retained until delivered or terminal, bounded by spool capacity. |
| D8 | Drain-flush within 3 s budget; leftovers remain on the volume and are replayed by the re-attached instance; orphaned-volume runbook in ADR-011. |

#### D4 verification result

`securecloud_audit_domain` ([src/audit/CMakeLists.txt](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/audit/CMakeLists.txt#L1-L23)) links only `securecloud::common`, `securecloud_proto`, `securecloud::compiler_flags` and `OpenSSL::Crypto` — **no ClickHouse client, no gRPC server, no `AuditConfig`**. Linking it from the Gateway introduces no persistence or server dependency. ✅

> [!WARNING]
> **Include-path collision discovered (must be handled in `T02`).** `securecloud_audit_domain` exports `src/audit/` as its include root (headers addressed as `"domain/audit_event.hpp"`, `"domain/enums.hpp"`), while `securecloud::auth` — already linked by `securecloud_gateway_http` — exports `src/auth/` (and `src/`), which contains **identically named** `domain/audit_event.hpp`, `domain/enums.hpp`, `domain/uuid.hpp`. A translation unit seeing both include roots would resolve `"domain/…"` by include order, silently mixing Auth and Audit types (ODR/compile hazards).
>
> **Mitigation (binding for `T02`/`T05`):**
> 1. New target `securecloud_gateway_audit` links `securecloud::audit_domain`, `securecloud::common`, `securecloud_proto` and `gateway_grpc` only — **never** `securecloud::auth` / `gateway_http`.
> 2. The public façade header `gateway_audit_producer.hpp` exposes only Gateway-owned types (`GatewayAuditObservation`, `IGatewayAuditProducer`) and **includes no `domain/…` header** (pimpl / forward declarations); middlewares in `gateway_http` depend only on that façade.
> 3. A CTest compile-guard test includes the façade together with Auth headers to prove there is no collision.

---

## 5. Delivery & Acknowledgement Semantics (applies to every option)

| Audit response | Classification | Producer action |
| :--- | :--- | :--- |
| `BatchSubmit` `OK`, id **not** in `rejected_event_ids` | Committed (AUDIT-006 scenario 1/2) | Mark delivered (ack checkpoint) |
| `BatchSubmit` `OK`, id **in** `rejected_event_ids` | Permanent rejection (validation, sensitive data, or payload conflict — not distinguishable in batch) | Move to **quarantine** (retained, never auto-deleted); optional single `SubmitAuditEvent` re-probe once to obtain the precise status for diagnostics |
| `ALREADY_EXISTS` (single) | Payload conflict — producer bug | Quarantine + CRITICAL diagnostic |
| `INVALID_ARGUMENT` | Malformed — producer bug (should be caught by local validation) | Quarantine |
| `PERMISSION_DENIED` / `UNAUTHENTICATED` | Identity/PKI misconfiguration — **not** an event fault | Retain all, open producer circuit, alert, retry with max backoff |
| `RESOURCE_EXHAUSTED` | Audit backpressure | Retain, backoff (honour longer delay) |
| `UNAVAILABLE` (incl. Audit draining) | Transient | Retain, backoff |
| `DEADLINE_EXCEEDED`, connection reset, lost response | **Ambiguous** | Retain and resend **same `event_id` + byte-identical payload** (dedup/at-least-once per AUDIT-006 scenario 8) |
| Quarantine full | — | Stop quarantining, keep record in main spool flagged `terminal_unstored`, count + log `event_id` only (never silent) |

**Payload stability:** the record is serialised once at admission (canonical proto bytes); retries resend exactly those bytes, so the AUDIT-006 SHA-256 fingerprint is identical across retries and restarts.

**Single-claim concurrency:** one dispatcher thread per Gateway instance owns the spool cursor (default). If `dispatcher_workers > 1` is ever configured, batches are claimed through an in-process lease table keyed by segment offset range; a record is never in two in-flight batches. Spools are per-instance, so cross-instance double-processing is impossible by construction.

---

## 6. Ticket Decomposition

```text
                 AUDIT-002 / 004 / 005 / 006 / 010 / 011   GW-001..GW-010
                                     │
                                     ▼
                              AUDIT-012-T01
           (Decision Gate: Event Catalog, Ownership Matrix,
            ADR-011 Durability Decision, Doc Amendments)
                                     │  ◄── explicit approval required
                                     ▼
                              AUDIT-012-T02
          (Canonical Gateway Audit Event Factory: UUIDv7, trusted
           context mapping, local validation & sensitive-data guard)
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
              AUDIT-012-T03                   AUDIT-012-T04
   (Pending-Event Store per approved   (Audit Delivery Dispatcher: gRPC
    option, capacity & admission        batch client, ack classification,
    policy, crash recovery)             backoff, circuit, quarantine, drain)
                     └───────────────┬───────────────┘
                                     ▼
                              AUDIT-012-T05
        (Request-Path Integration: non-blocking emit hooks,
         aggregation windows, config & main.cpp wiring)
                                     │
                                     ▼
                              AUDIT-012-T06
        (Producer Observability, Diagnostics & Lifecycle Integration)
                                     │
                                     ▼
                              AUDIT-012-T07
        (Unit, Integration, Failure-Injection, Restart, Concurrency,
         Latency & Security Test Suite + CI gates)
```

---

### AUDIT-012-T01 — Decision Gate: Event Catalog, Ownership Matrix & Gateway Durability ADR

1. **Ticket ID**: `AUDIT-012-T01`
2. **Objective**: Produce and obtain explicit approval for the Gateway audit event catalog, the cross-service ownership/duplication rules, and the durability strategy, before any code is written.
3. **Scope**:
   - Create `docs/adr/adr-011-gateway-audit-spool.md` (or `adr-011-gateway-audit-best-effort-delivery.md` if Option A is chosen) containing: context (§4.1), options (§4.2) with real guarantees, decision, explicitly non-guaranteed events, capacity & failure behaviour (D3, D6, D8), security of on-disk data (directory `0700`, files `0600`, no secrets by construction, volume not shared between instances).
   - Amend `docs/design/gateway-design.md` (§3.21 Audit unavailable, §3.22 Statelessness — the spool is producer-delivery state, not business state), `docs/design/audit-design.md` (§7.2, §7.9), `docs/data-model/05-audit-data-model.md` (§5.8 new `gateway.*` types, §5.20/§5.23, invariant 37 qualification), `docs/adr/adr-005-database-ownership-model.md` §5 (reference ADR-011).
   - Publish §3 catalog and §5 acknowledgement matrix as `docs/design/gateway-audit-producer.md`.
   - ~~Verify D4~~ — **done** (§4.5): `securecloud_audit_domain` has no ClickHouse/server/config dependency; include-path collision with `securecloud::auth` recorded with binding mitigation.
   - ADR-011 title: `docs/adr/adr-011-gateway-audit-event-delivery.md` (`Status: Proposed` → `Accepted` on review).
4. **Out of scope**: any C++/CMake/Compose change.
5. **Acceptance Criteria**:
   - Ownership matrix approved; each catalog entry has owner, class, severity, actor/target, metadata whitelist.
   - ADR states in plain words which events are **not** durably guaranteed; no document describes an in-memory mechanism as durable or the Gateway mechanism as "transactional".
   - Reviewer sign-off recorded in the ADR (`Status: Accepted`).
6. **Dependencies**: none.

---

### AUDIT-012-T02 — Canonical Gateway Audit Event Factory & Local Validation

1. **Ticket ID**: `AUDIT-012-T02`
2. **Objective**: Build pure, I/O-free construction of canonical `AuditEvent`s from trusted Gateway context, validated before admission.
3. **Scope**:
   - `src/gateway/audit/gateway_audit_event_types.hpp` — closed enum of catalog entries (§3.2) → canonical `event_type`, severity, class (`Mandatory`/`BestEffort`).
   - `src/gateway/audit/gateway_audit_event_factory.{hpp,cpp}`:
     - `EventId::generate_v7()` at logical creation; `occurred_at` = decision time (`system_clock`); `producer_service = Gateway`; `producer_instance` = configured instance name (bounded ≤ 64).
     - Actor/target mapping from `AuthenticatedContext` / `RequestContext` only (§3.4); `route_class` enum; correlation-ID hardening (valid UUID or fresh UUIDv7).
     - Metadata whitelist per event type; values truncated to limits *before* validation; no free-text from clients.
   - `GatewayAuditEventValidator` = `AuditEventValidator` + `SensitiveDataGuard` (per D4) with Audit's limits mirrored in config; validation failure → event not admitted, counter `gateway_audit_events_invalid_total{event_type}` (closed set), diagnostic logs field names only.
   - Canonical serialisation helper: `AuditEvent` → `AuditEventProto` bytes (deterministic map ordering) used once at admission.
   - New CMake target `securecloud_gateway_audit` linking `securecloud::audit_domain` (D4) and **not** `securecloud::auth` / `gateway_http`; façade header free of `domain/…` includes (see §4.5 include-path collision mitigation) + compile-guard test.
4. **Acceptance Criteria**:
   - Every catalog event produced by the factory passes the Audit validator; injected token/password/`Authorization`-looking values are rejected locally.
   - Client-supplied identity headers and non-UUID request IDs never appear in events.
   - Serialisation is byte-stable for the same event (fingerprint-stable).
5. **Dependencies**: `T01`.

---

### AUDIT-012-T03 — Pending-Event Store, Capacity & Admission Policy

1. **Ticket ID**: `AUDIT-012-T03`
2. **Objective**: Implement the approved pending-event mechanism behind an interface that makes its durability class explicit.
3. **Scope**:
   - `src/gateway/audit/audit_pending_store.hpp`:
     ```cpp
     enum class StoreDurability { NonDurable, DurableAfterSync };
     enum class AdmissionResult { DurablyQueued, AcceptedPendingSync, AcceptedNonDurable,
                                  RejectedFull, RejectedUnavailable, RejectedInvalid };
     class IAuditPendingStore {
       public:
         virtual ~IAuditPendingStore() = default;
         [[nodiscard]] virtual StoreDurability durability() const noexcept = 0;
         [[nodiscard]] virtual AdmissionResult append(PendingRecord record) noexcept = 0; // never blocks on I/O
         [[nodiscard]] virtual std::vector<PendingRecord> claim_batch(size_t max) = 0;
         virtual void mark_delivered(std::span<const EventId>) = 0;
         virtual void mark_terminal(const EventId&, TerminalReason) = 0;
         virtual void release(std::span<const EventId>) = 0;   // retry later
         [[nodiscard]] virtual PendingStats stats() const noexcept = 0;
     };
     ```
   - `BoundedMemoryPendingStore` (always built; used for best-effort lane, and as the whole store if Option A) — reports `NonDurable`, returns `AcceptedNonDurable`.
   - **If Option B approved** — `FileSpoolPendingStore`:
     - Segmented append-only files, record = `magic | version | length | CRC32C | proto bytes | attempt metadata`; dedicated writer thread with bounded hand-off queue; group-commit `fsync` (≤ 20 ms or 256 records); ack checkpoint file written atomically (`write tmp → fsync → rename → fsync dir`); compaction removes segments whose records are all delivered/terminal.
     - Crash recovery: scan segments, truncate torn tail at first CRC failure (counted), rebuild pending index from checkpoint; replay preserves original `event_id` and bytes.
     - Hard byte/record caps (D6); quarantine segment for terminal records (never auto-deleted).
     - Startup failure of the spool directory → store `Unavailable`: mandatory events `RejectedUnavailable` + E9 accounting; Gateway still starts and serves (D3).
   - Admission policy: Mandatory → durable store; BestEffort → memory lane; when the best-effort lane is full the oldest best-effort events are dropped and counted (allowed only for best-effort).
4. **Acceptance Criteria**:
   - `append()` never performs blocking disk I/O on the caller thread (measured in `T07`).
   - No code path returns `DurablyQueued` before fsync; `BoundedMemoryPendingStore` can never report `DurableAfterSync`.
   - Restart with N pending records replays exactly N with identical bytes; torn tail is detected and accounted.
   - Store size never exceeds configured caps.
5. **Dependencies**: `T01`, `T02`.

---

### AUDIT-012-T04 — Audit Delivery Dispatcher (gRPC, Acknowledgements, Retry, Quarantine, Drain)

1. **Ticket ID**: `AUDIT-012-T04`
2. **Objective**: Deliver pending events to Audit over the existing authenticated contract and retire them strictly per AUDIT-004/006 semantics.
3. **Scope**:
   - `src/gateway/grpc/audit_ingestion_client.{hpp,cpp}` + `audit_client_interface.hpp` — `BatchSubmitAuditEvents` / `SubmitAuditEvent` over `GrpcChannelManager::get_audit_channel()` (mTLS, SAN `audit`), per-call deadline `deadlines.audit_timeout_ms`; mapped to `DependencyError`.
   - `src/gateway/audit/audit_delivery_dispatcher.{hpp,cpp}`:
     - Single worker thread (configurable, single-claim per §5), batches ≤ 100 and ≤ Audit `max_event_size_bytes` aggregate.
     - Ack classification table exactly as §5 (including ambiguous outcomes and batch `rejected_event_ids` → quarantine).
     - Backoff per D7 using the existing `RetryPolicy` jitter math (outbox profile); dedicated `CircuitBreaker` instance `"audit"`; pause dispatch while Audit health is `NOT_SERVING` (AUDIT-010) using `HealthService.Check` on the audit channel at backoff boundaries.
     - Condition-variable wake on new records; never holds a lock across the RPC.
     - Graceful drain: on `DrainManager` start, flush until empty or `audit_drain_budget_ms` (default 3,000 ms, within the Gateway 5 s drain); remaining records stay in the durable store (B) or are reported via `gateway.lifecycle.stopped.pending_audit_events` + metric (A).
4. **Acceptance Criteria**:
   - Events are marked delivered only on the success conditions of §5.
   - Timeouts/resets resend the same `event_id` with identical bytes.
   - `PERMISSION_DENIED`/`UNAUTHENTICATED` never quarantine or delete events.
   - Dispatcher never exceeds one in-flight batch per claim slot; memory bounded by batch size.
5. **Dependencies**: `T02`, `T03`.

---

### AUDIT-012-T05 — Request-Path Integration, Aggregation Windows & Configuration

1. **Ticket ID**: `AUDIT-012-T05`
2. **Objective**: Emit catalog events from Gateway decision points without adding synchronous dependency or unbounded cost to request processing.
3. **Scope**:
   - `src/gateway/audit/gateway_audit_producer.{hpp,cpp}` — façade: `void record(GatewayAuditObservation) noexcept` (factory → validation → admission); never throws, never blocks on I/O or the network; O(1) amortised.
   - `AuditAggregationWindow` for E5/E6/E1-threshold (§3.3): bounded key map, periodic flush thread, LRU-evicted keys flushed (not dropped).
   - Hooks (minimal, injected via `std::shared_ptr<IGatewayAuditProducer>`; null-object default keeps existing tests unchanged): `AuthenticationMiddleware` (E1, E2; skip when Auth authoritative per §3.1 rule 2), `AuthorizationMiddleware` (E2), `HeaderSanitizer` caller (E3 — sanitizer returns stripped names), `FilesProxyHandler` (E4), `RateLimiterMiddleware` (E5), `ResourceLimiterMiddleware` (E6), `CircuitBreaker` state listener (E7), `main.cpp`/`DrainManager` (E8).
   - `GatewayAuditProducerConfig` in `gateway_config.{hpp,cpp}` with env vars `SECURECLOUD_GATEWAY_AUDIT_*` (enabled, mode, spool_dir, caps, batch size, backoff, drain budget, aggregation window, instance name) + validation; `main.cpp` wiring and shutdown ordering (stop accepting HTTP → drain dispatcher → stop channels).
   - Docker Compose: per-instance named volume for `gateway` **only if Option B approved**.
4. **Acceptance Criteria**:
   - With Audit down, all Gateway endpoints behave and respond exactly as before (status codes, bodies, latency budget).
   - No existing Gateway response, header, TLS, auth, routing or error-mapping behaviour changes.
   - A 10,000-request rate-limit flood from one key produces ≤ 1 aggregate event per window.
5. **Dependencies**: `T02`, `T03`, `T04`.

---

### AUDIT-012-T06 — Producer Observability, Diagnostics & Lifecycle Integration

1. **Ticket ID**: `AUDIT-012-T06`
2. **Objective**: Make producer health and backlog visible without high-cardinality labels or sensitive data.
3. **Scope**:
   - `src/gateway/audit/audit_producer_metrics.{hpp,cpp}` (lock-free, AUDIT-011 pattern, OpenMetrics text):
     - `gateway_audit_pending_events{class}` (gauge), `gateway_audit_pending_bytes`, `gateway_audit_oldest_pending_age_seconds`,
     - `gateway_audit_events_admitted_total{class,result}`, `gateway_audit_delivery_batches_total{outcome}`, `gateway_audit_events_delivered_total`,
     - `gateway_audit_delivery_retries_total{reason}`, `gateway_audit_events_quarantined_total{reason}`, `gateway_audit_events_lost_total{class,reason}`,
     - `gateway_audit_spool_unsynced_events`, `gateway_audit_spool_torn_records_total`, `gateway_audit_circuit_state`.
     - Closed label sets only (`class` ∈ {mandatory,best_effort}; `outcome` ∈ {success,retryable,terminal,ambiguous}; …). No `event_id`, user, IP or path labels.
   - Exposure per D5 (internal mTLS listener only) + rate-limited (1/s per category) structured diagnostics: `event_id`, `event_type`, status category — never payload/metadata values.
   - Producer health state (`HEALTHY` / `DEGRADED` / `UNAVAILABLE`) exposed via the internal health detail; **does not** change Gateway readiness.
4. **Acceptance Criteria**:
   - Metrics reflect backlog growth during an Audit outage and drain after recovery.
   - No metric label or log line contains tokens, credentials, IPs as labels, or metadata values.
5. **Dependencies**: `T03`, `T04`, `T05`.

---

### AUDIT-012-T07 — Verification Suite & CI Gates

1. **Ticket ID**: `AUDIT-012-T07`
2. **Objective**: Prove every acceptance criterion of the card with automated tests.
3. **Scope** (`tests/unit/gateway/`, `tests/integration/`):
   - **Mapping & model**: every catalog type → valid canonical event; actor/target/metadata rules; correlation hardening; sensitive-data exclusion (tokens, `Authorization`, passwords, MFA codes, bodies).
   - **Stable IDs**: same `event_id` and identical bytes across retries **and** across process restart (B) / documented loss (A).
   - **Audit unavailable**: in-process fake `AuditIngestionService` over mTLS returning `UNAVAILABLE`, `RESOURCE_EXHAUSTED`, `DEADLINE_EXCEEDED` (server sleeps past deadline), connection reset, `OK` with partial `rejected_event_ids`, `ALREADY_EXISTS`, `PERMISSION_DENIED`.
   - **Duplicate delivery**: lost-ack simulation → resend → fake server dedups; delivered exactly once in the fake's committed set.
   - **Restart with pending events**, torn-tail recovery, checkpoint corruption (B).
   - **Capacity exhaustion**: spool/lane full → `Rejected*`, E9 accounting, request path unaffected.
   - **Concurrent workers**: multi-producer `record()` stress (8 threads × 100k) + multi-claim dispatcher test; TSan-clean; no record in two batches.
   - **Invalid/permanent rejections**: quarantined, never deleted, counted.
   - **Request-path isolation**: middleware tests with a store whose I/O blocks indefinitely / an Audit fake that never responds — p99 request latency delta within budget (e.g. < 1 ms over baseline) and identical responses.
   - **Flood aggregation**: bounded event count under attack-style load.
   - Real end-to-end (optional, tagged `integration`): Gateway → real `securecloud-audit` → ClickHouse in dev Compose.
   - CI: `clang-format`, `clang-tidy`, `-Wall -Wextra -Wpedantic -Werror`, full CTest, Windows/MSVC build.
4. **Acceptance Criteria**: all tests pass; zero new warnings; no unrelated file changes.
5. **Dependencies**: `T02`–`T06`.

---

## 7. Card Acceptance Criteria Traceability

| Card acceptance criterion | Ticket(s) |
| :--- | :--- |
| Gateway-owned categories & ownership boundaries documented | T01 |
| Duplicate ownership with Auth/others addressed | T01 (§3.1), T05 (rule 2 enforcement) |
| Canonical AUDIT-002 model | T02 |
| UUIDv7 stable across retries | T02, T03, T04, T07 |
| Producer authenticated with established service identity | T04 (existing mTLS channel, SAN `gateway`) |
| Durability strategy documented & approved **before** implementation | T01 (gate) |
| No in-memory mechanism presented as durable | T01, T03 (`StoreDurability`) |
| No cross-service DB / unapproved infra | T01, T03, T05 |
| Existing authenticated gRPC ingestion contract | T04 |
| Delivered only per agreed ack semantics | T04 (§5) |
| Timeouts, outages, overload, ambiguous acks handled | T04, T07 |
| Bounded storage & retry | T03, T04, T05 (aggregation) |
| No synchronous dependency on Audit persistence | T03, T05, T07 |
| Mandatory-event failure behaviour & limitations documented | T01 (ADR-011), T03 |
| Metrics/diagnostics follow conventions | T06 |
| Unit, integration, failure, restart, security tests | T07 |
| Formatting, static analysis, build, CTest clean | T07 |
| No unrelated changes | all (review checklist) |

---

## 8. Risk Register

| Risk | Severity | Mitigation |
| :--- | :--- | :--- |
| Claiming durability that does not exist | **Critical** | `T01` ADR lists non-guaranteed cases; `StoreDurability` type; `DurablyQueued` only after fsync. |
| Attacker converts request flood into audit/disk flood | **High** | Aggregation windows (§3.3), byte caps, best-effort lane droppable, E9 self-accounting. |
| Audit outage degrades Gateway latency/availability | **High** | Non-blocking admission, writer/dispatcher threads, circuit breaker, readiness unaffected. |
| Double-recording with Auth | Medium | Ownership rule §3.1 #2; tests assert no Gateway event when Auth is authoritative. |
| Per-instance spool breaks "stateless" scaling | Medium | ADR-011 scale-down/drain runbook (D8); spool holds delivery state only, never business state. |
| Torn writes / corruption | Medium | CRC32C per record, tail truncation, atomic checkpoint rename. |
| Sensitive data in spool files | Medium | Local validation + `SensitiveDataGuard` before write; `0600` files; no secrets by construction. |
| Coupling Gateway to Audit internals | Low | D4: link only the pure domain library or extract `EventId` to common. |

