# AUDIT-009 — Internal Audit Security-Event Recording
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: `AUDIT-009`  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: November 2, 2026  
**Dependencies**: `AUDIT-001` (Audit Config & Runtime Foundation), `AUDIT-002` (Canonical Audit Event Model & Validator), `AUDIT-003` (ClickHouse Schema & Repository Layer), `AUDIT-004` (Authenticated gRPC Ingestion Contract), `AUDIT-005` (Bounded Asynchronous Ingestion & Batch Persistence)  
**Related ADRs**: `ADR-005` (Internal Perimeter & mTLS 1.3), `ADR-006` (Canonical Audit Event Schema), `ADR-008` (Zero-Plaintext & Sensitive Data Defense), `ADR-009` (Service Lifecycle & Failure Isolation), `ADR-010` (Bounded Resource Allocation & Overload Defense)

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-009** specifies and implements the internal security-event recording subsystem for the **SecureCloud Audit Service** (`securecloud-audit`).

While other microservices (**Gateway**, **Auth**, **Messaging**, **Files**) produce security events through their dedicated outbox and gRPC clients (covered in `AUDIT-012` through `AUDIT-015`), the **Audit Service itself is a high-value security boundary**. It must authoritatively, reliably, and safely detect and record security-relevant events that occur within its own runtime, including:
1. **Transport & Authentication Violations**: Unauthenticated connections, untrusted TLS certificates, and invalid/spoofed producer identities at mTLS ingestion boundaries.
2. **Payload & Input Anomalies**: Prohibited sensitive data injections (passwords, tokens, private keys), corrupted UUIDv7 identifiers, excessive clock skew tampering, and oversized ingestion requests.
3. **Resource & Capacity Protections**: Queue saturation drops under backpressure, rate-limit threshold violations, and ClickHouse persistence failures.
4. **Service Lifecycle & Security State Changes**: Daemon startup under verified mTLS identity, graceful draining, and operational degradation.

### Core Architectural Invariants for AUDIT-009

1. **Zero Alternative Persistence Paths (ADR-006, Audit Invariant 5.1)**:
   All internal security events are persisted exclusively into the authoritative **ClickHouse 24.8** `audit.audit_events` table using the existing canonical persistence pipeline (`IAuditEventRepository`). No sidecar database, SQLite instance, Kafka topic, or secondary storage mechanism may be introduced.
2. **Strict Anti-Recursion Boundary (Audit Invariant 5.3)**:
   Under no circumstances may the processing, recording, validation, or persistence failure of an internal security event trigger another security event. The event recording engine must enforce a non-reentrant, fail-closed guard preventing recursive event amplification loops.
3. **Non-Blocking Asynchronous Isolation (ADR-009, ADR-010)**:
   Internal security event recording must never introduce a synchronous blocking dependency on ClickHouse or block incoming client RPC threads. Events are submitted to the established bounded ingestion queue via non-blocking, drop-safe semantics.
4. **Authoritative Context Attribution Without Invented Identities (ADR-005, Audit Data Model 5.10)**:
   Event actors and targets must strictly reflect verified runtime context (e.g., peer SAN/CN, socket peer IP). The service must never invent synthetic or speculative identity strings when an unauthenticated client connects.
5. **Zero-Plaintext & Sensitive Data Exclusion (ADR-008)**:
   Internal security events generated in response to rejected requests must never include the offending sensitive tokens, credentials, or unbounded raw request payloads in metadata. Only sanitized, bounded diagnostic metadata (e.g., offending key name, UUID, error code) is permitted.

---

## 2. System Architecture & Ingestion Flow

```text
                  AUDIT SERVICE SECURITY PERIMETER & RECURSION GUARD

   Incoming gRPC Connection / RPC
 (Port 50055: Ingestion / Query)
                │
                ▼
   ┌───────────────────────────┐
   │ mTLS & Transport Boundary │ ──► Unauthenticated / Untrusted Cert / SAN Mismatch
   └────────────┬──────────────┘
                │ (Valid mTLS)
                ▼
   ┌───────────────────────────┐
   │ Event Validation Pipeline │ ──► Sensitive Data / UUIDv7 / Skew / Size Violation
   └────────────┬──────────────┘
                │
                ├───────────────────────────────────────┐
                ▼ (On Security Violation)                │ (Normal Event)
   ┌────────────────────────────────────────┐           │
   │  InternalSecurityEventRecorder         │           │
   │  ┌──────────────────────────────────┐  │           │
   │  │ Anti-Recursion Re-entrancy Guard │  │           │
   │  └──────────────────┬───────────────┘  │           │
   │                     ▼                  │           │
   │  ┌──────────────────────────────────┐  │           │
   │  │ InternalSecurityEventFactory     │  │           │
   │  │  (Canonical AuditEvent DTO)      │  │           │
   │  └──────────────────┬───────────────┘  │           │
   │                     ▼                  │           │
   │  ┌──────────────────────────────────┐  │           │
   │  │ Non-Blocking Enqueue Dispatcher  │  │           │
   │  └──────────────────┬───────────────┘  │           │
   └─────────────────────┼──────────────────┘           │
                         │                              │
                         ▼                              ▼
            ┌───────────────────────────────────────────────┐
            │   Existing Bounded Ingestion Queue (M6)       │
            │          (Hard Ceiling: 10,000)               │
            └───────────────────────┬───────────────────────┘
                                    │
                                    ▼
            ┌───────────────────────────────────────────────┐
            │ Batch Aggregator & ClickHouse Repository (CH) │
            │          audit.audit_events Table             │
            └───────────────────────────────────────────────┘
```

---

## 3. Internal Security Event Catalog & Mapping Rules

Each internal security event maps deterministically to the canonical `domain::AuditEvent` model (`AUDIT-002`) with `producer_service = ProducerService::Audit`:

| Event Type | Triggering Condition | Canonical Severity | Actor Type / ID | Target Type / ID | Bounded Metadata Keys |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `audit.security.auth.unauthenticated_connection` | Caller connects without valid mTLS client certificate | `Severity::Security` | `ActorType::Unknown` / Peer IP or `"unauthenticated"` | `TargetType::Service` / `"securecloud-audit"` | `transport_security`, `peer_address`, `rpc_method` |
| `audit.security.auth.producer_identity_mismatch` | Client certificate SAN does not match declared `producer_service` | `Severity::Security` | `ActorType::Service` / Verified Cert SAN (e.g. `gateway.securecloud.internal`) | `TargetType::Service` / `"securecloud-audit"` | `declared_producer`, `verified_san`, `rpc_method` |
| `audit.security.auth.untrusted_client_cert` | Client certificate fails Root CA chain verification | `Severity::Security` | `ActorType::Unknown` / `"untrusted_certificate"` | `TargetType::Service` / `"securecloud-audit"` | `tls_error`, `peer_address` |
| `audit.security.payload.sensitive_data_detected` | Ingestion payload rejected by `SensitiveDataGuard` | `Severity::Critical` | `ActorType::Service` / Verified Producer SAN | `TargetType::Service` / `"securecloud-audit"` | `prohibited_key`, `detection_rule`, `event_id` |
| `audit.security.payload.malformed_structure` | Extreme structural corruption or malformed UUIDv7 | `Severity::Warning` | `ActorType::Service` / Verified Producer SAN | `TargetType::Service` / `"securecloud-audit"` | `validation_error`, `field_name`, `rejected_id` |
| `audit.security.payload.excessive_clock_skew` | Event timestamp exceeds $|occurred\_at - now| > 5\text{ min}$ | `Severity::Warning` | `ActorType::Service` / Verified Producer SAN | `TargetType::Service` / `"securecloud-audit"` | `occurred_at_ms`, `skew_seconds`, `event_id` |
| `audit.security.payload.oversized_batch_rejected` | Ingestion batch exceeds 100 events ceiling | `Severity::Warning` | `ActorType::Service` / Verified Producer SAN | `TargetType::Service` / `"securecloud-audit"` | `batch_size`, `max_allowed`, `rpc_method` |
| `audit.security.capacity.queue_saturated` | Bounded ingestion queue full, event dropped | `Severity::Critical` | `ActorType::System` / `"securecloud-audit"` | `TargetType::Service` / `"securecloud-audit"` | `queue_depth`, `max_capacity`, `dropped_count` |
| `audit.security.storage.persistence_failure` | ClickHouse cluster unreachable or batch insert fails | `Severity::Critical` | `ActorType::System` / `"securecloud-audit"` | `TargetType::Service` / `"clickhouse"` | `error_code`, `batch_size`, `retry_attempts` |
| `audit.security.lifecycle.service_started` | Daemon successfully bound mTLS port and healthy | `Severity::Info` | `ActorType::System` / `"securecloud-audit"` | `TargetType::Service` / `"securecloud-audit"` | `service_version`, `listen_port`, `environment` |
| `audit.security.lifecycle.service_draining` | Daemon initiated graceful drain on SIGINT/SIGTERM | `Severity::Info` | `ActorType::System` / `"securecloud-audit"` | `TargetType::Service` / `"securecloud-audit"` | `in_flight_batches`, `grace_period_ms` |

---

## 4. Anti-Recursion & Circuit Breaking Architecture

To guarantee that the audit service never suffers cascading recursive crashes or memory exhaustion loops, the recording engine enforces three strict structural barriers:

1. **Producer Isolation Filter**:
   The validation pipeline checks `if (event.producer_service == domain::ProducerService::Audit)`. If an event produced by `Audit` fails validation or cannot be persisted, it is rejected and logged diagnostically. It **NEVER** calls the internal security event recorder.
2. **Thread-Local Re-entrancy Lock (`AntiRecursionScope`)**:
   A thread-local flag `thread_local bool t_in_audit_recording{false};` is set upon entry to `record_internal_event()`. If another security event is triggered within the same thread call stack, the recorder fails silent and safe (increments an atomic dropped counter and returns immediately).
3. **Bounded Non-Blocking Dispatch with Drop-Safe Semantics**:
   Internal security events are dispatched to the existing `AuditIngestionService` or `BoundedIngestionQueue` using non-blocking submission (`try_ingest` / `try_enqueue`). If the queue is saturated, the event is counted via `audit_internal_events_dropped_total` and discarded rather than blocking the calling gRPC thread.

---

## 5. Implementation Tickets for Developer Lorenzo

```text
               AUDIT-001 (Config & Lifecycle)
               AUDIT-002 (Canonical Model & Validator)
               AUDIT-003 (ClickHouse Repository)
               AUDIT-004 (gRPC Ingestion Service)
               AUDIT-005 (Bounded Ingestion Queue)
                             │
                             ▼
                       AUDIT-009-T01
             (Internal Security Event Taxonomy,
              Types & Bounded Metadata Schema)
                             │
                             ▼
                       AUDIT-009-T02
             (Canonical Event Factory & Verified
              Context Attribution Engine)
                             │
                             ▼
                       AUDIT-009-T03
             (Anti-Recursion Re-entrancy Guard &
              Drop-Safe Circuit Breaker)
                             │
                             ▼
                       AUDIT-009-T04
             (Asynchronous Non-Blocking Dispatcher &
              Persistence Integration)
                             │
                             ▼
                       AUDIT-009-T05
             (Audit Pipeline & Interceptor
              Instrumentation Hooks)
                             │
                             ▼
                       AUDIT-009-T06
             (Comprehensive Unit, Security Negative,
              Anti-Recursion & Concurrency Suite)
```

---

### AUDIT-009-T01: Internal Security Event Taxonomy, Types & Bounded Metadata Schema

1. **Ticket ID**: `AUDIT-009-T01`
2. **Title**: Internal Audit Security Event Taxonomy, Types & Bounded Metadata Schema
3. **Objective**: Define strongly typed enumerations and constants for all internal Audit Service security event types and enforce strict structural metadata key/value schemas.
4. **Scope & Technical Requirements**:
   - Create `src/audit/security/internal_security_event_types.hpp` and `.cpp`.
   - Define enum class `InternalSecurityEventType`:
     ```cpp
     enum class InternalSecurityEventType : uint16_t {
         UnauthenticatedConnection = 1,
         ProducerIdentityMismatch = 2,
         UntrustedClientCertificate = 3,
         SensitiveDataDetected = 4,
         MalformedPayloadStructure = 5,
         ExcessiveClockSkew = 6,
         OversizedBatchRejected = 7,
         IngestionQueueSaturated = 8,
         PersistenceStorageFailure = 9,
         ServiceStarted = 10,
         ServiceDraining = 11
     };
     ```
   - Implement `to_event_type_string(InternalSecurityEventType) noexcept -> std::string_view` returning canonical strings (`audit.security.auth.unauthenticated_connection`, etc.).
   - Implement `to_severity(InternalSecurityEventType) noexcept -> domain::Severity`.
   - Implement metadata key whitelist and bounds checker:
     - Maximum allowed metadata pairs: $\le 10$.
     - Maximum key length: $\le 64$ bytes.
     - Maximum value length: $\le 256$ bytes.
     - Prohibit any key matching credentials (`token`, `auth`, `password`, `key`, `secret`).
5. **Architectural Constraints**:
   - Header must be pure C++20 and depend only on `src/audit/domain/enums.hpp`.
   - Zero dynamic heap allocations in enumeration mapping functions.
6. **Acceptance Criteria**:
   - All 11 event types map to distinct, canonical hierarchical strings starting with `audit.security.`.
   - Metadata key validation rejects prohibited keys and oversized values.
7. **Dependencies**: `AUDIT-002-T01`.

---

### AUDIT-009-T02: Canonical Event Factory & Verified Context Attribution Engine

1. **Ticket ID**: `AUDIT-009-T02`
2. **Title**: Canonical Event Factory & Verified Context Attribution Engine
3. **Objective**: Implement the authoritative factory class that transforms internal security events into fully validated `domain::AuditEvent` instances without inventing speculative identity data.
4. **Scope & Technical Requirements**:
   - Create `src/audit/security/internal_security_event_factory.hpp` and `.cpp`.
   - Define structured parameters for internal events:
     ```cpp
     struct SecurityEventContext {
         std::optional<std::string> verified_peer_identity; // Extracted from mTLS SAN
         std::string peer_socket_address;                   // IP:port from context->peer()
         std::string rpc_method;                            // e.g. "SubmitAuditEvent"
         std::optional<std::string> correlation_id;         // Extracted from gRPC header
         std::unordered_map<std::string, std::string> metadata;
     };
     ```
   - Implement `InternalSecurityEventFactory::create_event`:
     - Assigns new RFC 9562 UUIDv7 via `domain::EventId::generate_v7()`.
     - Assigns `occurred_at = std::chrono::system_clock::now()`.
     - Sets `producer_service = domain::ProducerService::Audit`.
     - Sets `producer_instance = config.common.service_name` (e.g. `audit-node-01`).
     - Sets `target_type = domain::TargetType::Service` and `target_id = "securecloud-audit"`.
     - **Attribution Policy (No Speculation)**:
       - If `verified_peer_identity` is present: `actor_type = ActorType::Service`, `actor_id = *verified_peer_identity`.
       - If unauthenticated but socket address present: `actor_type = ActorType::Unknown`, `actor_id = peer_socket_address`.
       - If no context: `actor_type = ActorType::Unknown`, `actor_id = "unauthenticated"`.
       - Never invent user IDs or speculative roles.
     - Passes metadata through `SensitiveDataGuard` before attaching.
5. **Architectural Constraints**:
   - Zero sensitive token/credential leakage in generated metadata.
   - Preserves correlation ID propagation from gRPC metadata where available.
6. **Acceptance Criteria**:
   - Factory outputs valid `domain::AuditEvent` that passes `AuditEventValidator::validate()`.
   - Missing actor identity cleanly defaults to `"unauthenticated"` or socket address without inventing identity strings.
7. **Dependencies**: `AUDIT-009-T01`, `AUDIT-002-T02`, `AUDIT-002-T03`.

---

### AUDIT-009-T03: Anti-Recursion Re-entrancy Guard & Drop-Safe Circuit Breaker

1. **Ticket ID**: `AUDIT-009-T03`
2. **Title**: Anti-Recursion Re-entrancy Guard & Drop-Safe Circuit Breaker
3. **Objective**: Implement thread-local and producer-level anti-recursion mechanisms guaranteeing that internal security event recording can never cause recursive event cascading loops.
4. **Scope & Technical Requirements**:
   - Create `src/audit/security/anti_recursion_guard.hpp` and `.cpp`.
   - Implement RAII re-entrancy guard:
     ```cpp
     class AntiRecursionGuard {
     public:
         [[nodiscard]] static bool is_recording_in_progress() noexcept;
         explicit AntiRecursionGuard();
         ~AntiRecursionGuard();
         AntiRecursionGuard(const AntiRecursionGuard&) = delete;
         AntiRecursionGuard& operator=(const AntiRecursionGuard&) = delete;
     private:
         bool acquired_{false};
     };
     ```
   - Maintain `thread_local bool t_recording_active{false};`.
   - If `is_recording_in_progress()` is true when entering a recording site:
     - Immediately abort recording.
     - Increment atomic counter `audit_internal_recursion_prevented_total`.
     - Emit safe fallback debug log (rate-limited).
   - Implement event filter:
     - `bool should_record_internal_event(const domain::AuditEvent& candidate) noexcept`:
       - If `candidate.producer_service == domain::ProducerService::Audit`, return `false` for any secondary security event trigger.
5. **Architectural Constraints**:
   - RAII guarantee: `t_recording_active` must be reset even if an exception is thrown.
   - Non-allocating, zero overhead on normal non-security execution paths.
6. **Acceptance Criteria**:
   - Re-entrant calls to the security recorder on the same thread are completely rejected.
   - Recursive cascade depth is strictly bounded to 0.
7. **Dependencies**: `securecloud::common`.

---

### AUDIT-009-T04: Asynchronous Non-Blocking Dispatcher & Persistence Integration

1. **Ticket ID**: `AUDIT-009-T04`
2. **Title**: Asynchronous Non-Blocking Dispatcher & Persistence Integration
3. **Objective**: Implement `InternalSecurityEventRecorder` providing non-blocking asynchronous dispatch of internal security events into the existing audit ingestion pipeline.
4. **Scope & Technical Requirements**:
   - Create `src/audit/security/internal_security_event_recorder.hpp` and `.cpp`.
   - Class `InternalSecurityEventRecorder`:
     ```cpp
     class InternalSecurityEventRecorder {
     public:
         explicit InternalSecurityEventRecorder(
             std::shared_ptr<service::AuditIngestionService> ingestion_service,
             std::string service_instance_name);

         /// Asynchronously records an internal security event. Non-blocking.
         bool record_event(InternalSecurityEventType type,
                           const SecurityEventContext& context) noexcept;

         [[nodiscard]] uint64_t events_recorded_count() const noexcept;
         [[nodiscard]] uint64_t events_dropped_count() const noexcept;
         [[nodiscard]] uint64_t recursion_prevented_count() const noexcept;
     };
     ```
   - Interaction with `AuditIngestionService`:
     - Invokes `ingestion_service_->ingest_single(event)` inside `AntiRecursionGuard`.
     - Catches all exceptions: failures increment `events_dropped_count_` and return `false`.
     - Under no circumstances throws out to the caller.
     - Enforces non-blocking return so gRPC worker thread latency is unaffected.
5. **Architectural Constraints**:
   - No separate storage backend or alternative outbox table.
   - Never blocks waiting for ClickHouse HTTP round-trips.
6. **Acceptance Criteria**:
   - Ingestion failures or ClickHouse outages do not crash or block the caller.
   - Dropped events are accurately tracked via atomic counters.
7. **Dependencies**: `AUDIT-009-T02`, `AUDIT-009-T03`, `AUDIT-004-T03`.

---

### AUDIT-009-T05: Audit Pipeline & Interceptor Instrumentation Hooks

1. **Ticket ID**: `AUDIT-009-T05`
2. **Title**: Audit Pipeline & Interceptor Instrumentation Hooks
3. **Objective**: Instrument `AuditServiceImpl`, `GrpcProducerIdentityValidator`, and `AuditServer` to reliably trigger internal security event recording at observed security boundaries.
4. **Scope & Technical Requirements**:
   - Update `src/audit/service/audit_service_impl.hpp` and `.cpp`:
     - Inject `std::shared_ptr<security::InternalSecurityEventRecorder>`.
     - Hook 1: When `validate_peer_context` returns `UNAUTHENTICATED`, record `UnauthenticatedConnection`.
     - Hook 2: When `validate_peer_context` returns `PERMISSION_DENIED`, record `ProducerIdentityMismatch`.
     - Hook 3: When `ingest_single` or `ingest_batch` detects `SensitiveDataDetected`, record `SensitiveDataDetected`.
     - Hook 4: When request is rejected for clock skew, record `ExcessiveClockSkew`.
     - Hook 5: When batch size exceeds 100, record `OversizedBatchRejected`.
   - Update `src/audit/audit_server.hpp` and `.cpp`:
     - Instantiate `InternalSecurityEventRecorder` during server configuration.
     - Record `ServiceStarted` once server enters `Running` state and health probe is active.
     - Record `ServiceDraining` when `AuditServer::stop()` initiates shutdown.
5. **Architectural Constraints**:
   - Do not record ordinary operational debug/trace logs as security events.
   - Maintain zero overhead on happy-path valid ingestion requests.
6. **Acceptance Criteria**:
   - Each security boundary violation triggers exactly one internal security event.
   - Valid producer requests proceed with zero interference.
7. **Dependencies**: `AUDIT-009-T04`, `AUDIT-004-T04`, `AUDIT-004-T05`.

---

### AUDIT-009-T06: Comprehensive Unit, Security Negative, Anti-Recursion & Concurrency Suite

1. **Ticket ID**: `AUDIT-009-T06`
2. **Title**: Comprehensive Unit, Security Negative, Anti-Recursion & Concurrency Suite
3. **Objective**: Develop complete unit and integration tests verifying event taxonomy, safe attribution, anti-recursion prevention, queue saturation resilience, and zero sensitive data leakage.
4. **Scope & Technical Requirements**:
   - Create `tests/unit/audit/internal_security_event_recorder_test.cpp`:
     - **Test 1: Event Classification & Canonical Mapping**: Verify each of the 11 internal events maps to valid `domain::AuditEvent` and passes `AuditEventValidator`.
     - **Test 2: Context Attribution & Missing Identity**: Verify unauthenticated callers map to `"unauthenticated"` or peer IP without synthetic user invention.
     - **Test 3: Anti-Recursion Prevention**: Force an internal security event to fail validation and assert that recursion depth is 0 and no secondary events are emitted.
     - **Test 4: Sensitive Data Exclusion**: Verify that payloads containing passwords/tokens do NOT leak those secrets into the resulting `SensitiveDataDetected` security event metadata.
     - **Test 5: Queue Saturation & Non-Blocking Drop**: Simulate full ingestion queue; verify recorder returns immediately, increments drop counter, and does not hang.
   - Create `tests/integration/audit_internal_security_integration_test.cpp`:
     - **Test 6: End-to-End mTLS Identity Mismatch Recording**: Send request with `gateway` cert declaring `auth`; verify `ProducerIdentityMismatch` event is persisted in ClickHouse.
     - **Test 7: End-to-End Sensitive Data Ingestion Rejection Recording**: Submit event with prohibited key; verify original event rejected and `SensitiveDataDetected` event persisted.
     - **Test 8: Concurrent Multi-Threaded Internal Event Emission**: 8 concurrent worker threads firing security events simultaneously; verify thread safety, zero data races, and exact count preservation.
   - Register targets in `tests/unit/CMakeLists.txt` and `tests/integration/CMakeLists.txt`.
5. **Architectural Constraints**:
   - Hermetic tests with zero external daemon dependencies (mock repository for unit tests).
   - Clean compilation under `-Wall -Wextra -Werror -Wpedantic`.
6. **Acceptance Criteria**:
   - 100% test pass rate across all new unit and integration test binaries.
   - Strict .clang-format compliance.
7. **Dependencies**: `AUDIT-009-T01` through `AUDIT-009-T05`.

---

## 6. Acceptance Criteria & Definition of Done Matrix

| Ticket ID | Deliverables | Architectural Invariant | Verification Target |
| :--- | :--- | :--- | :--- |
| **AUDIT-009-T01** | `internal_security_event_types.{hpp,cpp}` | ADR-006, Audit Invariant 5.1 | Unit test verification of 11 event types and string conversions |
| **AUDIT-009-T02** | `internal_security_event_factory.{hpp,cpp}` | ADR-008, Audit Data Model 5.10 | Factory test verifying zero-plaintext and no invented identities |
| **AUDIT-009-T03** | `anti_recursion_guard.{hpp,cpp}` | Audit Invariant 5.3 | Re-entrancy stress test proving recursion depth ceiling of 0 |
| **AUDIT-009-T04** | `internal_security_event_recorder.{hpp,cpp}` | ADR-009, ADR-010 | Mocked queue saturation test verifying non-blocking drop-safe behavior |
| **AUDIT-009-T05** | Hooks in `AuditServiceImpl`, `AuditServer` | ADR-005, ADR-006 | Integration tests verifying mTLS & sensitive data triggers |
| **AUDIT-009-T06** | Unit & Integration Test Suites | All Milestone M6 Standards | `ctest -R "internal_security"` 100% passing without warnings |

---

## 7. Risk Analysis & Mitigation Matrix

| Identified Risk | Severity | Potential Impact | Architectural Mitigation |
| :--- | :--- | :--- | :--- |
| **Infinite Recursion Storm** | **Critical** | Service stack overflow or OOM crash when recording a rejected event triggers another event | `AntiRecursionGuard` thread-local re-entrancy lock + explicit filter ignoring events where `producer_service == Audit`. |
| **Ingestion Pipeline Starvation** | **High** | High volume of invalid requests causes internal security events to fill queue, starving valid client traffic | Priority pacing and drop-safe non-blocking submission; security events share bounded queue and drop first on saturation. |
| **PII / Secret Reflection** | **High** | Attacker injects password in metadata; security event copies the bad metadata into ClickHouse | `InternalSecurityEventFactory` sanitizes metadata through `SensitiveDataGuard` and only captures key names, never values. |
| **Caller Blocking on DB Outage** | **Medium** | ClickHouse downtime stalls internal event recording, hanging caller gRPC connection | Fully decoupled asynchronous dispatch; recorder returns immediately without waiting for ClickHouse HTTP I/O. |
| **Identity Impersonation / Spoofing** | **Medium** | Attacker supplies arbitrary actor/producer name in payload | Security event attribution strictly uses authenticated mTLS SAN/CN from transport context; never trusts unverified payload fields. |

