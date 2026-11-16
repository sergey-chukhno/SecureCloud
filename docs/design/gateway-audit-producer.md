# Gateway Audit Producer Specification & Event Catalog

## 1. Context and Architectural Foundation

Under **ADR-011**[cite: 21] and **ADR-005 (§5 Amendment)**[cite: 22], the Gateway microservice acts as an asynchronous producer of perimeter audit events delivered to the Centralized Audit Service via gRPC (`securecloud.audit.v1.AuditIngestionService`)[cite: 23].

Because the Gateway has no business database, it does **not** implement a database transactional outbox[cite: 21]. Instead, it uses a **Gateway-Owned Durable Audit Spool**[cite: 21]:
* **Mandatory Security Events (E1–E6, E9)**: Written to a per-instance, binary segmented WAL spool (`/var/spool/securecloud-gateway/audit`) with group-commit `fsync` ($\le 20\text{ ms}$)[cite: 21].
* **Best-Effort Diagnostics (E7, E8)**: Routed to a bounded in-memory ring buffer (10,000 events max) with process-lifetime durability[cite: 21].

---

## 2. Domain Ownership Rules

1. **Perimeter Decisions**: The Gateway owns events describing decisions made directly at its boundary (token verification failures, coarse authorization denials, header sanitization, payload/concurrency rejections, rate limiting)[cite: 23].
2. **No Duplicate Event Generation**: When the Gateway forwards a request to Auth (e.g., `Auth.ValidateSession`) and Auth rejects the session, Auth emits the authoritative `auth.session.*` event[cite: 23]. The Gateway does NOT emit a duplicate event[cite: 23].
3. **Backend Operations**: Backend business successes and failures (`message.*`, `file.*`) are owned by Messaging and Files[cite: 23].
4. **Access Logs vs. Audit**: Successful HTTP requests belong to the structured access log (`LoggingMiddleware`), not the audit trail[cite: 23].

---

## 3. Gateway Audit Event Catalog

| # | `event_type` | Severity | Class | Source Component | Actor / Target Attribution | Bounded Metadata Whitelist |
| :-- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E1** | `security.token.rejected` | SECURITY | Mandatory | `AuthenticationMiddleware` | `UNKNOWN` / `SERVICE=gateway` | `reason` ∈ {`missing`, `malformed`, `invalid_signature`, `expired_local`}, `route_class`, `method`, `client_ip`[cite: 23] |
| **E2** | `security.authorization.denied` | SECURITY | Mandatory | `AuthorizationMiddleware` | `USER=user_id` / `SERVICE=target` | `reason`, `route_class`, `method`, `device_id`, `required_scope`[cite: 23] |
| **E3** | `gateway.security.identity_header_stripped` | SECURITY | Mandatory | `HeaderSanitizer` | `UNKNOWN` or `USER` / `SERVICE=gateway` | `header_names` (closed-set names only), `count`[cite: 23] |
| **E4** | `gateway.file.chunk_integrity_rejected` | SECURITY | Mandatory | `StreamingSha256Validator` | `USER=user_id` / `FILE=file_id` | `chunk_index`, `reason=CHUNK_INTEGRITY_MISMATCH`[cite: 23] |
| **E5** | `gateway.rate_limit.exceeded` | WARNING | Mandatory (Aggregated) | `RateLimiterMiddleware` | `USER` or `UNKNOWN` / `SERVICE=gateway` | `window_start`, `window_seconds`, `rejected_count`, `key_type` ∈ {`user`,`ip`}[cite: 23] |
| **E6** | `gateway.request.rejected` | WARNING | Mandatory (Aggregated) | `ResourceLimiterMiddleware` | `UNKNOWN` / `SERVICE=gateway` | `reason` ∈ {`header_too_large`, `payload_too_large`, `concurrency_cap`}, `rejected_count`, `window`[cite: 23] |
| **E7** | `gateway.dependency.circuit_opened` / `gateway.dependency.circuit_closed` | WARNING / INFO | Best-effort | `CircuitBreaker` | `SERVICE=gateway` / `SERVICE=target` | `dependency`, `failure_count`[cite: 23] |
| **E8** | `gateway.lifecycle.started` / `gateway.lifecycle.drain_started` / `gateway.lifecycle.stopped` | INFO | Best-effort | `main.cpp`, `DrainManager` | `SYSTEM` / `SERVICE=gateway` | `version`, `pending_audit_events`[cite: 23] |
| **E9** | `gateway.audit_producer.events_lost` | CRITICAL | Mandatory | Producer Core | `SYSTEM` / `SERVICE=gateway` | `lost_count`, `reason` ∈ {`spool_full`, `io_error`, `quarantine_full`}[cite: 23] |

---

## 4. Trusted Attribution & Aggregation Rules

### 4.1 Trusted Attribution
* `actor_id`, `device_id`, `session_id` are populated **only** from the cryptographically verified `AuthenticatedContext`[cite: 23]. They are never extracted from untrusted HTTP headers, query parameters, or request bodies[cite: 23].
* `client_ip` uses `req.remote_addr`[cite: 23]. `X-Forwarded-For` is processed only when `trusted_proxies` is explicitly configured[cite: 23].
* `correlation_id`: If the incoming `X-Request-ID` is a valid UUID, it is reused[cite: 23]. Otherwise, a fresh UUIDv7 is generated to prevent injection of invalid format strings into ClickHouse `UUID` columns[cite: 23].

### 4.2 Flood Protection via Aggregation
High-frequency rejection points (E5 Rate Limiter, E6 Resource Limiter) use a thread-safe `AuditAggregationWindow`[cite: 21, 23]. Summarized events are emitted periodically (e.g., 1-second/60-second buckets) per key[cite: 21, 23]. This guarantees that attacker-driven request floods generate $O(\text{distinct keys per window})$ aggregate audit events rather than $O(\text{requests})$ storage amplification[cite: 23].

---

## 5. Spool Storage & Framing Specification (ADR-011)

* **Directory Location**: `/var/spool/securecloud-gateway/audit` (Permissions `0700`, files `0600`)[cite: 21].
* **Capacity Limits**: 100 MB maximum spool capacity / 500,000 records max[cite: 21]. Segment file size: 16 MB[cite: 21].
* **Binary WAL Framing**:
  `[Magic: 4B (0x53434153)] [Record Length: 4B] [CRC32C: 4B] [UUIDv7 Event ID: 16B] [Payload: Protobuf binary]`[cite: 21]
* **Checkpointing**: Atomic write + rename of `checkpoint.json` on the persistent volume[cite: 21].

---

## 6. Acknowledgement & Status Classification Matrix

| gRPC Status / Response | Classification | Producer Action |
| :--- | :--- | :--- |
| `BatchSubmit` `OK` (ID not in `rejected_event_ids`) | Success | Advance checkpoint; purge acknowledged segment records[cite: 21, 23]. |
| `BatchSubmit` `OK` (ID in `rejected_event_ids`) | Terminal Rejection | Move record to quarantine directory (`/quarantine/`)[cite: 23]. |
| `ALREADY_EXISTS` / `INVALID_ARGUMENT` | Terminal Error | Quarantine record + log CRITICAL diagnostic event[cite: 23]. |
| `PERMISSION_DENIED` / `UNAUTHENTICATED` | Auth/PKI Error | Retain events in spool, pause dispatcher, open circuit breaker[cite: 23]. |
| `RESOURCE_EXHAUSTED` / `UNAVAILABLE` | Retryable Failure | Retain events in spool, apply exponential backoff[cite: 23]. |
| `DEADLINE_EXCEEDED` / Connection Reset | Ambiguous Outcome | Retain events in spool, resend identical byte payload + `event_id`[cite: 23]. |
