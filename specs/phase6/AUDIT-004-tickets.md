# AUDIT-004 — Implement Authenticated gRPC Ingestion Contract and Endpoint
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: AUDIT-004  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)    
**Date**: October 22, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-004** defines and implements the authoritative, authenticated internal **gRPC Ingestion Service** (`AuditService`) for the SecureCloud Audit daemon (`securecloud-audit`).

Through this endpoint, internal microservices (**Gateway**, **Auth**, **Messaging**, **Files**, and internal **Audit**) submit validated security and operational audit events, either individually or in bounded transactional batches.

### Key Invariants & Architectural Boundaries for AUDIT-004

1. **Internal Microservice Perimeter Only (ADR-005, Audit Data Model 5.2)**:
   The audit ingestion endpoint is exposed strictly on the internal microservice network (default port `50055`). It is **never** exposed to public clients via the API Gateway. Public users and devices have zero direct access to audit ingestion RPCs.
2. **Mutual TLS 1.3 Identity Binding (ADR-005, SC-010)**:
   Authentication is enforced strictly at the transport layer via mTLS with client certificate validation. The Audit daemon verifies the client certificate against the cluster Root CA and extracts the peer Subject Alternative Name (SAN) or Common Name (CN).
3. **Never Trust Unverified Producer Strings (Audit Data Model 5.10)**:
   A request's payload declaring `producer_service: "auth"` is never trusted on its own. The ingestion pipeline strictly enforces that the declared `producer_service` matches the cryptographically verified mTLS peer identity (`ctx.peer_identity()`). Mismatches are rejected with `PERMISSION_DENIED`.
4. **Explicit Durability Contract & Acknowledgement Boundary**:
   A successful gRPC response (`OK`) guarantees that the service has accepted responsibility for the event under a clearly defined durability contract:
   - Synchronous Mode: The batch has been committed to ClickHouse.
   - Asynchronous / Buffer Mode: The event has been accepted into a bounded, backpressured queue with affirmative acknowledgement semantics.
   - Events held only in transient, lossy buffers must **never** be acknowledged as durably committed.
5. **Domain Validation Gate Integration (AUDIT-002)**:
   Before persisting or acknowledging any event, the payload must pass strict validation via `AuditEventValidator`:
   - Valid RFC 9562 UUIDv7 event identifier.
   - Valid temporal bounds on `occurred_at` (no future timestamps $>5$ minutes).
   - Authoritative assignment of `received_at = now()`.
   - Content confidentiality guard: strict zero-plaintext enforcement rejecting passwords, tokens, private keys, or message/file content.
6. **Bounded Request Sizing & Overload Protection (ADR-010)**:
   Hard limits are enforced before deserializing large payloads:
   - Max single event size: 64 KB (absolute limit: 1 MB).
   - Max batch count: 100 events per RPC.
   - Oversized requests are rejected immediately with `INVALID_ARGUMENT` or `RESOURCE_EXHAUSTED`.
7. **Clean Sanitized Error Taxonomy**:
   gRPC status codes map deterministically without exposing internal database connection strings, schema details, or raw rejected payloads.

---

## 2. Dependency Graph

```text
               AUDIT-001 (Audit Config & Runtime Foundation)
               AUDIT-002 (Canonical Audit Event Model & Validator)
               AUDIT-003 (ClickHouse Schema & Repository Layer)
               SC-005 (Protobuf & gRPC Contract Foundation)
               SC-010 (mTLS Peer Identity & Dev PKI)
                            │
                            ▼
                      AUDIT-004-T01
            (Protobuf Ingestion Contracts &
             Strongly-Typed Domain Data Transfer Objects)
                            │
                            ▼
                      AUDIT-004-T02
            (Mutual TLS Peer Identity Extractor &
             Producer Authorization Interceptor)
                            │
                            ▼
                      AUDIT-004-T03
            (Bounded Ingestion Command Engine &
             AuditEventValidator Integration Pipeline)
                            │
                            ▼
                      AUDIT-004-T04
            (In-Process gRPC AuditServiceImpl &
             Deterministic Error Translation Layer)
                            │
                            ▼
                      AUDIT-004-T05
            (AuditServer Registration, Threadpool
             Dispatch & Graceful Shutdown Drain)
                            │
                            ▼
                      AUDIT-004-T06
            (Contract Verification, Integration &
             Security Negative Test Suite)
```

---

## 3. Implementation Tickets for Developer Lorenzo

### AUDIT-004-T01 — Protobuf Ingestion Contracts & Strongly-Typed DTOs

1. **Ticket ID**: `AUDIT-004-T01`
2. **Title**: Protobuf Ingestion Contracts & Domain Data Transfer Objects
3. **Objective**: Define the authoritative v1 Protobuf ingestion contract in `proto/securecloud/audit/v1/audit_service.proto` and bidirectional mapping helpers to `AuditEvent`.
4. **Scope**:
   - Create `proto/securecloud/audit/v1/audit_service.proto`:
     ```protobuf
     syntax = "proto3";

     package securecloud.audit.v1;

     import "google/protobuf/timestamp.proto";

     enum EventSeverity {
       EVENT_SEVERITY_UNSPECIFIED = 0;
       EVENT_SEVERITY_INFO = 1;
       EVENT_SEVERITY_WARNING = 2;
       EVENT_SEVERITY_SECURITY = 3;
       EVENT_SEVERITY_CRITICAL = 4;
     }

     message AuditEventPayload {
       string event_id = 1;                    // RFC 9562 UUIDv7
       google.protobuf.Timestamp occurred_at = 2;
       string event_type = 3;
       EventSeverity severity = 4;
       string producer_service = 5;
       string producer_instance = 6;
       string actor_type = 7;
       string actor_id = 8;
       string target_type = 9;
       string target_id = 10;
       string correlation_id = 11;
       string causation_id = 12;
       string event_data_json = 13;            // Bounded JSON metadata
     }

     message SubmitEventRequest {
       AuditEventPayload event = 1;
     }

     message SubmitEventResponse {
       string event_id = 1;
       google.protobuf.Timestamp received_at = 2;
     }

     message SubmitBatchRequest {
       repeated AuditEventPayload events = 1;  // Max 100 events
     }

     message BatchItemStatus {
       string event_id = 1;
       bool success = 2;
       string error_code = 3;
       string error_message = 4;
     }

     message SubmitBatchResponse {
       uint32 accepted_count = 1;
       uint32 rejected_count = 2;
       repeated BatchItemStatus results = 3;
     }

     service AuditService {
       rpc SubmitEvent(SubmitEventRequest) returns (SubmitEventResponse);
       rpc SubmitBatch(SubmitBatchRequest) returns (SubmitBatchResponse);
     }
     ```
   - Register the proto file in `proto/CMakeLists.txt` and ensure `securecloud_proto` generates C++ stubs cleanly.
   - Implement mapping utilities in `src/audit/service/audit_proto_mapper.hpp` and `.cpp` converting between Protobuf messages and canonical `AuditEvent` domain objects.
5. **Acceptance Criteria**:
   - Protobuf compiles without warnings under `-std=c++20`.
   - Bidirectional mapping preserves all timestamps with millisecond accuracy and correctly translates enumerations.

---

### AUDIT-004-T02 — Mutual TLS Peer Identity Extractor & Producer Authorization Interceptor

1. **Ticket ID**: `AUDIT-004-T02`
2. **Title**: Mutual TLS Peer Identity Extractor & Producer Authorization Interceptor
3. **Objective**: Implement gRPC server interceptor or context extractor that inspects client mTLS peer certificates, validates peer SAN/CN against permitted internal producers, and enforces identity binding.
4. **Scope**:
   - Create `src/audit/security/producer_identity_validator.hpp` and `.cpp`.
   - Extract peer certificate credentials from `grpc::ServerContext::auth_context()`:
     - Property: `x509_subject_alternative_name` or `x509_common_name`.
   - Allowed producer identities:
     - `gateway.securecloud.internal` $\to$ `gateway`
     - `auth.securecloud.internal` $\to$ `auth`
     - `messaging.securecloud.internal` $\to$ `messaging`
     - `files.securecloud.internal` $\to$ `files`
     - `audit.securecloud.internal` $\to$ `audit`
   - Implement `validate_producer_identity(const std::string& cert_identity, const std::string& declared_producer) -> bool`.
   - If peer identity does not match declared `producer_service`, reject immediately with `grpc::StatusCode::PERMISSION_DENIED` ("Producer identity mismatch: mTLS identity does not match declared producer_service").
   - Reject unauthenticated callers with `grpc::StatusCode::UNAUTHENTICATED`.
5. **Acceptance Criteria**:
   - Requests without valid mTLS peer certificates are rejected with `UNAUTHENTICATED`.
   - Requests where declared `producer_service` conflicts with certificate SAN are rejected with `PERMISSION_DENIED`.
   - Zero sensitive identity credentials or tokens are exposed in error messages.

---

### AUDIT-004-T03 — Bounded Ingestion Command Engine & AuditEventValidator Pipeline

1. **Ticket ID**: `AUDIT-004-T03`
2. **Title**: Bounded Ingestion Command Engine & Domain Validation Pipeline
3. **Objective**: Implement the application-level ingestion service (`AuditIngestionService`) that enforces batch limits, executes `AuditEventValidator` (AUDIT-002), and assigns authoritative ingestion timestamps.
4. **Scope**:
   - Create `src/audit/service/audit_ingestion_service.hpp` and `.cpp`.
   - Define ingestion command structures:
     ```cpp
     struct IngestionResult {
         bool success{false};
         std::string error_code;
         std::string error_message;
         std::chrono::system_clock::time_point received_at;
     };

     struct BatchIngestionResult {
         uint32_t accepted_count{0};
         uint32_t rejected_count{0};
         std::vector<std::pair<EventId, IngestionResult>> item_results;
     };
     ```
   - Enforce batch clamping: max 100 events per batch (reject immediately if `batch.size() > 100`).
   - Validate each event via `AuditEventValidator::validate(event)`:
     - UUIDv7 validity.
     - Timestamp drift: $|occurred\_at - now| \le 5\,\text{minutes}$.
     - Sensitive data defense: zero-plaintext inspection.
     - Metadata limits: key count $\le 50$, key length $\le 64$, value length $\le 1024$.
   - Assign authoritative ingestion timestamp: `event.set_received_at(std::chrono::system_clock::now())`.
   - Forward validated events to `IAuditEventRepository::insert_batch(validated_events)`.
5. **Acceptance Criteria**:
   - Single invalid event in a batch does not corrupt or silently discard other valid events in atomic-rejection or partial-acceptance modes.
   - `received_at` is always set by the ingestion engine and cannot be spoofed by producer payloads.
   - Validation failure details are cleanly captured and structured without reflecting prohibited secret contents.

---

### AUDIT-004-T04 — In-Process gRPC AuditServiceImpl & Deterministic Error Translation

1. **Ticket ID**: `AUDIT-004-T04`
2. **Title**: gRPC AuditServiceImpl Implementation & Deterministic Status Translation
3. **Objective**: Implement the `v1::AuditService::Service` gRPC server class handling `SubmitEvent` and `SubmitBatch`, deadline management, and error translation.
4. **Scope**:
   - Create `src/audit/service/audit_service_impl.hpp` and `.cpp`.
   - Inherit from `securecloud::audit::v1::AuditService::Service`.
   - Implement `SubmitEvent(ServerContext*, const SubmitEventRequest*, SubmitEventResponse*)`:
     - Checks `context->IsCancelled()`.
     - Validates mTLS identity via `ProducerIdentityValidator`.
     - Maps proto to domain `AuditEvent`.
     - Invokes `AuditIngestionService::ingest_event`.
     - Returns `grpc::Status::OK` on success with populated `received_at`.
   - Implement `SubmitBatch(ServerContext*, const SubmitBatchRequest*, SubmitBatchResponse*)`:
     - Validates batch count $\le 100$.
     - Validates mTLS identity.
     - Ingests batch and populates `accepted_count`, `rejected_count`, and per-item results.
   - Implement `map_error_to_grpc_status(const IngestionError& err) -> grpc::Status`:
     - Validation failure $\to$ `INVALID_ARGUMENT`
     - Auth failure $\to$ `UNAUTHENTICATED` / `PERMISSION_DENIED`
     - Overload / capacity $\to$ `RESOURCE_EXHAUSTED`
     - Repository failure $\to$ `UNAVAILABLE`
5. **Acceptance Criteria**:
   - RPC deadline exceeded or client disconnect cleanly halts processing without leaking resources.
   - All failure cases return well-defined, standard gRPC status codes.

---

### AUDIT-004-T05 — AuditServer Registration, Threadpool Dispatch & Graceful Drain

1. **Ticket ID**: `AUDIT-004-T05`
2. **Title**: AuditServer Registration, Worker Threadpool Dispatch & Graceful Drain
3. **Objective**: Wire `AuditServiceImpl` into `AuditServer`, configure mTLS 1.3 server credentials from `AuditConfig`, isolate ingestion worker threads, and implement graceful shutdown draining.
4. **Scope**:
   - Update `src/audit/audit_server.hpp` and `.cpp`.
   - Configure `grpc::ServerBuilder` with mTLS credentials:
     - Server cert: `config.tls.cert_chain_path`
     - Server private key: `config.tls.private_key_path`
     - Client CA: `config.tls.root_ca_path`
     - Client auth: `GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`
   - Bind listener to `config.server.host:config.server.port` (port 50055).
   - Offload ingestion database operations to a bounded worker threadpool (`ingestion_pool_`), avoiding blocking gRPC synchronous worker threads.
   - Implement graceful drain on shutdown:
     - Mark readiness as `NOT_SERVING`.
     - Stop accepting new RPCs.
     - Allow in-flight batches up to `config.server.shutdown_grace_period_ms` to flush to ClickHouse.
     - Shutdown gRPC server cleanly.
5. **Acceptance Criteria**:
   - `AuditServer::start()` initializes and serves the ingestion endpoint alongside the existing health service.
   - `SIGTERM` triggers graceful drain with zero dropped in-flight events.
   - Readiness status reflects ClickHouse availability and worker pool health.

---

### AUDIT-004-T06 — Contract Verification, Integration & Security Negative Test Suite

1. **Ticket ID**: `AUDIT-004-T06`
2. **Title**: Contract Tests, Ingestion Integration Suite & Security Negative Tests
3. **Objective**: Implement comprehensive unit, contract, and integration tests verifying happy-path ingestion, multi-producer validation, mTLS perimeter rejection, and resilience under failure.
4. **Scope**:
   - Create `tests/unit/audit/audit_service_impl_test.cpp`:
     - Test 1: Single event submission happy path.
     - Test 2: Bounded batch submission (100 events) success.
     - Test 3: Oversized batch rejection (>100 events) with `INVALID_ARGUMENT`.
     - Test 4: Schema validation failure mapping to `INVALID_ARGUMENT`.
     - Test 5: Clock skew rejection (>5 min in future) mapping to `INVALID_ARGUMENT`.
     - Test 6: Zero-plaintext violation rejection.
   - Create `tests/integration/audit_ingestion_integration_test.cpp` (with loopback mTLS):
     - Test 7: Valid mTLS handshake from simulated `auth` service producer.
     - Test 8: Producer identity mismatch (cert SAN `gateway` declaring `auth` payload) rejected with `PERMISSION_DENIED`.
     - Test 9: Untrusted / self-signed certificate rejected with `UNAUTHENTICATED`.
     - Test 10: Downstream ClickHouse outage mapped to `UNAVAILABLE` with retry headers.
     - Test 11: End-to-end ingestion verifying event persisted in ClickHouse.
     - Test 12: Concurrent ingestion from multiple simulated producer threads (Gateway, Auth, Messaging, Files).
   - Register targets in `tests/unit/CMakeLists.txt` and `tests/integration/CMakeLists.txt`.
5. **Acceptance Criteria**:
   - All tests pass deterministically.
   - Negative security tests confirm strict fail-closed authorization.
   - Complete clang-format adherence across all test code.
