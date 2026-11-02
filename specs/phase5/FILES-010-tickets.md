# FILES-010 — Integrate Files with Gateway and Audit
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: `FILES-010` (or `FILE-010`)  
**Milestone**: M5 — Secure Files (Final Card)  
**Document Status**: Proposed Specification for Architectural Review (Louis & Sergey)  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Dependencies**: `FILES-001` through `FILES-009`, `GW-004`, `GW-005`, `GW-010`, `AUDIT-001`, `AUDIT-002`

---

## 1. Executive Summary & Goal

### Goal
Complete the authoritative, hardened integration of the **Files Microservice** (`securecloud-files`) with the **API Gateway** (`securecloud-gateway`) and the **Audit Microservice** (`securecloud-audit`). 

This final card completes Milestone 5 by establishing:
1. End-to-end REST/HTTP proxying over TLS 1.3 with caller context (`user_id`, `device_id`) and Ed25519 capability token propagation.
2. A non-buffering chunk streaming download pipeline that respects bounded memory.
3. The Transactional Outbox Relay engine that asynchronously extracts staged events from PostgreSQL (`files_outbox`) and delivers tamper-evident audit records to the Audit Microservice over mTLS gRPC.
4. Comprehensive live integration tests validating protocol translation, resilience (bulkheads, circuit breaking), and zero-plaintext guarantees.

```text
                                      ┌─────────────────────────────────────────────────────────┐
                                      │                   EXTERNAL PERIMETER                    │
                                      └─────────────────────────────────────────────────────────┘
                                                                   │
                                                HTTPS / TLS 1.3 (REST / Streaming)
                                                Headers: Authorization: Bearer <jwt>
                                                         X-File-Capability: <ed25519_token>
                                                                   │
                                                                   ▼
                                      ┌─────────────────────────────────────────────────────────┐
                                      │                      API GATEWAY                        │
                                      │  - TLS 1.3 Termination & Request ID (UUIDv7)            │
                                      │  - AuthenticatedContext Extraction (user_id, device_id) │
                                      │  - FilesProxyHandler (Bulkheads & Circuit Breakers)     │
                                      │  - Non-buffering Chunk Streaming Download               │
                                      └─────────────────────────────────────────────────────────┘
                                                                   │
                                                     mTLS gRPC (DNS:gateway SAN)
                                                     Metadata: x-user-id, x-device-id
                                                               x-file-capability
                                                                   │
                                                                   ▼
                                      ┌─────────────────────────────────────────────────────────┐
                                      │                     FILES SERVICE                       │
                                      │  - FilesServiceImpl (Isolated Bulkheads)                │
                                      │  - Capability Authorization (ADR-005)                   │
                                      │  - Zero-Plaintext Storage (MinIO S3)                    │
                                      │  - Transactional Outbox (PostgreSQL files_outbox)       │
                                      └─────────────────────────────────────────────────────────┘
                                                                   │
                                                      Asynchronous Outbox Relay
                                                      (SKIP LOCKED Batch Polling)
                                                                   │
                                                                   ▼
                                      ┌─────────────────────────────────────────────────────────┐
                                      │                     AUDIT SERVICE                       │
                                      │  - AuditIngestionService::BatchSubmitAuditEvents        │
                                      │  - Tamper-Evident SHA-256 Chained Ledger (ClickHouse)   │
                                      └─────────────────────────────────────────────────────────┘
```

---

## 2. Architecture & Delta Analysis

### What ALREADY Exists in the Codebase (Do NOT Re-Implement):

1. **Downstream Files Microservice Core (FILES-001 through FILES-009)**:
   - Full PostgreSQL domain repositories (`FileRepository`, `FileVersionRepository`, `FileChunkRepository`, `FileTransferRepository`, `FileAccessRepository`, `FilesOutboxRepository`).
   - S3 Storage integration (`S3Client`, `StorageEngine`, `BoundedStorageEngine`).
   - Domain logic: `UploadSessionManager` (resumable uploads), `FileFinalizationService` (whole-object assembly & hash check), `DownloadManager` & `ChunkDownloadEngine` (range-based reads), `FileCapabilityManager` (Ed25519 capability signing & verification).
   - Concurrency & Resource Controls (`FilesResourceConfig`, `ConcurrencyBulkhead`, `MemoryBufferTracker`).
   - Transactional Outbox staging: `FileLifecycleService` and `FileFinalizationService` already write `FILE_CREATED`, `FILE_VERSION_CREATED`, `FILE_FINALIZED`, `FILE_DELETED`, and `TRANSFER_CANCELLED` events to `files_outbox`.

2. **Gateway Foundations & Streaming Framework (GW-001 through GW-010)**:
   - `FilesProxyHandler` in `src/gateway/http/proxy/files_proxy_handler.hpp` / `.cpp` with registered endpoints:
     * `POST /api/v1/files/upload/init`
     * `POST /api/v1/files/upload/chunk`
     * `POST /api/v1/files/upload/finalize`
     * `POST /api/v1/files/upload/cancel`
     * `GET  /api/v1/files/:file_id/metadata`
     * `GET  /api/v1/files/:file_id/chunks/:chunk_index`
     * `GET  /api/v1/files/:file_id/download`
     * `DELETE /api/v1/files/:file_id`
   - `FilesServiceClient` in `src/gateway/grpc/files_service_client.hpp` / `.cpp`.
   - Resilience primitives: `BulkheadManager` (`WorkloadCategory::Files`), `CircuitBreaker`, `DeadlineManager`, and `ActiveCallGuard` (connection cancellation propagation).

3. **Audit Service Contracts (AUDIT-001, AUDIT-002)**:
   - `proto/securecloud/audit/v1/audit.proto` defining `AuditIngestionService` with `SubmitAuditEvent` and `BatchSubmitAuditEvents`.
   - Enums in `src/audit/domain/enums.hpp`:
     * `ProducerService::Files = 4` (`PRODUCER_SERVICE_FILES`)
     * `TargetType::File = 4` (`TARGET_TYPE_FILE`)

---

### What is MISSING & Targeted by FILES-010:

1. **Gateway Caller Identity & Capability Token Propagation**:
   - `FilesProxyHandler` currently ignores `AuthenticatedContext ctx` (commented out as `/*ctx*/`).
   - It does NOT inject `x-user-id` or `x-device-id` into `ClientCallContext`.
   - It does NOT extract the `X-File-Capability` (or `X-File-Access-Capability`) HTTP request header or query parameter, leaving downstream `FilesServiceImpl::DownloadChunk` unable to verify caller capability tokens.
2. **True Non-Buffering Streaming Download in Gateway**:
   - `FilesProxyHandler::handle_streaming_download` needs to stream chunk-by-chunk using `httplib::Response::set_content_provider` without accumulating the entire file in Gateway memory (ADR-008).
3. **Transactional Outbox Relay Worker (`FilesOutboxRelay`)**:
   - While events are staged in `files_outbox`, there is currently no background worker polling `files_outbox` (`SELECT ... FOR UPDATE SKIP LOCKED`) and dispatching them to `securecloud-audit`.
4. **Audit gRPC Ingestion Client in Files Service**:
   - The Files Service lacks a dedicated gRPC client to invoke `securecloud.audit.v1.AuditIngestionService::BatchSubmitAuditEvents`.
5. **OpenAPI REST Documentation**:
   - `openapi/openapi.yaml` currently only documents presence endpoints; all Files REST endpoints must be formally documented with schemas, error codes, and headers.
6. **Live End-to-End Integration Test Suite**:
   - A complete end-to-end integration test suite exercising the live HTTP Gateway server against the live gRPC Files Service, live PostgreSQL, MinIO storage, and live gRPC Audit Ingestion service.

---

## 3. Detailed Ticket Decomposition

```text
FILES-010-T01 (Gateway Caller Identity & Capability Token Forwarding)
     │
     ▼
FILES-010-T02 (Gateway Non-Buffering Chunked Streaming Download)
     │
     ▼
FILES-010-T03 (Audit Ingestion gRPC Client & Files Audit Event Mapping)
     │
     ▼
FILES-010-T04 (Transactional Outbox Relay Background Worker)
     │
     ▼
FILES-010-T05 (OpenAPI Specification, Live E2E Integration Suite & Quality Gates)
```

---

### FILES-010-T01: Gateway Caller Identity & Capability Token Forwarding

#### Objective
Ensure that the Gateway's `FilesProxyHandler` extracts verified caller identity and capability tokens and transparently propagates them via gRPC metadata to `FilesService`.

#### Detailed Requirements
1. **Metadata Injection in `FilesProxyHandler`**:
   - In all route handlers (`handle_upload_init`, `handle_upload_chunk`, `handle_upload_finalize`, `handle_upload_cancel`, `handle_get_metadata`, `handle_download_chunk`, `handle_streaming_download`, `handle_delete_file`):
     * Extract `ctx.user_id` and `ctx.device_id` from `const AuthenticatedContext& ctx`.
     * Inject metadata into `grpc::ClientCallContext`:
       ```cpp
       call_ctx.add_metadata("x-user-id", ctx.user_id);
       if (!ctx.device_id.empty()) {
           call_ctx.add_metadata("x-device-id", ctx.device_id);
       }
       ```
2. **Capability Token Extraction**:
   - In `handle_download_chunk` and `handle_streaming_download`:
     * Check for `X-File-Capability` or `X-File-Access-Capability` HTTP headers.
     * Check query parameter `capability_token` as fallback (e.g. for browser direct downloads).
     * If present, inject:
       ```cpp
       call_ctx.add_metadata("x-file-capability", capability_token);
       ```
3. **Payload Owner Injection in `handle_upload_init`**:
   - For `POST /api/v1/files/upload/init`, if `owner_user_id` is omitted in the JSON request body, automatically default it to `ctx.user_id`. If `owner_user_id` is supplied, verify that it matches `ctx.user_id` (preventing impersonation).

#### Files to Touch
- `src/gateway/http/proxy/files_proxy_handler.cpp`
- `tests/unit/gateway/files_proxy_handler_test.cpp`

---

### FILES-010-T02: Gateway Non-Buffering Chunked Streaming Download

#### Objective
Implement memory-bounded HTTP chunked streaming download in `FilesProxyHandler::handle_streaming_download` that retrieves chunks sequentially from `FilesService` and flushes them directly to the HTTP socket.

#### Detailed Requirements
1. **Metadata Retrieval & Pre-flight**:
   - Fetch file metadata via `files_client_->get_file_metadata()` to determine total chunk count, total encrypted size, and encryption version.
   - Return appropriate error (404 Not Found, 403 Forbidden, 410 Gone) if the file is not in `AVAILABLE` lifecycle state.
2. **HTTP Chunked Transfer Streaming**:
   - Use `httplib::Response::set_content_provider` with chunked transfer encoding (`Transfer-Encoding: chunked`).
   - Iterate sequentially through chunks: `chunk_index = 0 .. total_chunks - 1`.
   - In each iteration, call `files_client_->download_chunk(file_id, chunk_index, call_ctx)`.
   - Write the received encrypted chunk bytes directly to the `httplib::DataSink`.
   - Verify client connectivity via `DataSink::is_writable()` before each chunk; if the client disconnects, break immediately and invoke `ActiveCallGuard` to cancel downstream gRPC storage I/O.
3. **Memory Bounding & Zero Plaintext**:
   - At no point may the entire file be accumulated in RAM. Only a single chunk ($<= 5\text{ MiB}$) may reside in Gateway memory at any instant.
   - Never inspect, log, or decrypt chunk payload bytes (Zero-Plaintext Invariant ADR-005, ADR-008).

#### Files to Touch
- `src/gateway/http/proxy/files_proxy_handler.cpp`
- `tests/unit/gateway/files_streaming_download_test.cpp`

---

### FILES-010-T03: Audit Ingestion gRPC Client & Files Audit Event Mapping

#### Objective
Implement the Files service audit client that establishes an mTLS gRPC connection to `securecloud-audit` and maps transactional outbox domain records into standard `AuditEventProto` messages.

#### Detailed Requirements
1. **Audit Client Interface & Implementation**:
   - Create `src/files/audit/audit_client_interface.hpp`:
     ```cpp
     class IFilesAuditClient {
       public:
         virtual ~IFilesAuditClient() = default;
         virtual bool submit_batch(const std::vector<audit::v1::AuditEventProto>& events) = 0;
     };
     ```
   - Implement `src/files/audit/grpc_audit_client.hpp` / `.cpp`:
     * Uses `securecloud.audit.v1.AuditIngestionService::Stub`.
     * Configures mTLS credentials (client cert `DNS:files`, CA root).
     * Implements `BatchSubmitAuditEvents` with deadline and error handling.
2. **Audit Event Mapper**:
   - Create `src/files/audit/files_audit_mapper.hpp` / `.cpp`:
     * Translates `FilesOutboxEntity` to `securecloud.audit.v1.AuditEventProto`:
       - `event_id`: UUIDv7 from outbox.
       - `occurred_at_ms`: Milliseconds since epoch from outbox `created_at`.
       - `event_type`: `FILE_CREATED`, `FILE_CHUNK_UPLOADED`, `FILE_FINALIZED`, `FILE_DELETED`, `FILE_ACCESS_REVOKED`.
       - `severity`: `SEVERITY_INFO` for normal lifecycle, `SEVERITY_SECURITY` for capability rejections/deletions.
       - `producer_service`: `PRODUCER_SERVICE_FILES`.
       - `actor_type`: `ACTOR_TYPE_USER` (extracted from payload JSON).
       - `target_type`: `TARGET_TYPE_FILE`.
       - `target_id`: `aggregate_id` (file_id).
       - `metadata`: Safe attributes only (e.g. `size_bytes`, `chunk_count`, `encryption_version`).
       - **Strict Invariant**: NEVER include encryption keys, plaintext filenames, or ciphertext bytes in audit metadata.

#### Files to Touch
- `src/files/CMakeLists.txt`
- `src/files/audit/audit_client_interface.hpp`
- `src/files/audit/grpc_audit_client.hpp` & `.cpp`
- `src/files/audit/files_audit_mapper.hpp` & `.cpp`
- `tests/unit/files/files_audit_mapper_test.cpp`

---

### FILES-010-T04: Transactional Outbox Relay Background Worker

#### Objective
Implement the production `FilesOutboxRelay` background worker that continuously monitors `files_outbox` in PostgreSQL, batches pending events, publishes them to the Audit Service, and updates outbox status with at-least-once reliability.

#### Detailed Requirements
1. **Relay Engine Implementation (`src/files/audit/files_outbox_relay.hpp` & `.cpp`)**:
   - Background thread worker with thread-safe start, stop, and flush lifecycle:
     ```cpp
     class FilesOutboxRelay {
       public:
         FilesOutboxRelay(std::shared_ptr<FilesOutboxRepository> outbox_repo,
                          std::shared_ptr<IFilesAuditClient> audit_client,
                          FilesOutboxRelayConfig config = {});
         ~FilesOutboxRelay();
         void start();
         void stop();
         size_t poll_and_dispatch(size_t batch_size);
     };
     ```
2. **Relay Configuration (`FilesOutboxRelayConfig`)**:
   - `poll_interval_ms`: Polling interval when idle (default: `1000 ms`).
   - `batch_size`: Max events per dispatch (default: `50`).
   - `max_retries`: Maximum consecutive retry attempts before marking `FAILED` (default: `5`).
3. **Execution Semantics**:
   - Queries pending events via `outbox_repo_->fetch_pending_events(batch_size)` (utilizing `FOR UPDATE SKIP LOCKED` to allow multiple concurrent worker instances).
   - Maps events via `FilesAuditMapper`.
   - Dispatches batch via `audit_client_->submit_batch(events)`.
   - On success: Calls `outbox_repo_->mark_published(event_id)`.
   - On failure: Increments retry count via `outbox_repo_->mark_failed(event_id)`.
4. **Daemon Integration**:
   - Wire `FilesOutboxRelay` into `src/files/main.cpp` with graceful shutdown handling.

#### Files to Touch
- `src/files/audit/files_outbox_relay.hpp` & `.cpp`
- `src/files/main.cpp`
- `tests/unit/files/files_outbox_relay_test.cpp`

---

### FILES-010-T05: OpenAPI Specification, Live E2E Integration Suite & Quality Gates

#### Objective
Formally document the Files REST API in `openapi/openapi.yaml`, create an authoritative live end-to-end integration test suite, and verify all quality gates.

#### Detailed Requirements
1. **OpenAPI Specification**:
   - In `openapi/openapi.yaml`, add all 8 Files endpoints with complete request/response schemas, bearer token security, `X-File-Capability` header descriptions, and RFC 7807 error responses.
2. **End-to-End Live Integration Test (`tests/integration/files_e2e_gateway_audit_integration_test.cpp`)**:
   - Starts:
     * Live HTTP Gateway server on random ephemeral port.
     * Live gRPC Files Service with PostgreSQL and MinIO backing.
     * Mock / In-memory Audit Ingestion service.
   - Executes live end-to-end scenarios over HTTP:
     1. **Full Resumable Upload Lifecycle**: `upload/init` $\rightarrow$ `upload/chunk` (multiple chunks) $\rightarrow$ `upload/finalize` $\rightarrow$ verifies 200 OK and file `AVAILABLE`.
     2. **Capability-Authorized Download**: Issue Ed25519 capability token $\rightarrow$ request `GET /api/v1/files/:file_id/chunks/0` with `X-File-Capability` $\rightarrow$ verifies payload returned.
     3. **Unauthorized Access Rejection**: Request chunk download without capability token or with expired/tampered capability $\rightarrow$ verifies HTTP 401/403.
     4. **Chunked Streaming Download**: Request `GET /api/v1/files/:file_id/download` $\rightarrow$ verifies complete streamed reconstruction.
     5. **Deletion & Metadata Lifecycle**: Request `DELETE /api/v1/files/:file_id` $\rightarrow$ verifies file marked `TOMBSTONE` / `DELETED`.
     6. **Outbox Audit Verification**: Trigger outbox relay $\rightarrow$ verify all lifecycle events (`FILE_CREATED`, `FILE_FINALIZED`, `FILE_DELETED`) arrive at Audit Service with `PRODUCER_SERVICE_FILES` and correct file IDs.
     7. **Resilience & Circuit Breaking**: Simulate downstream failure $\rightarrow$ Gateway returns HTTP 503 RFC 7807 problem details without leaking internal trace details.
3. **Quality Gates**:
   - Ensure 100% adherence to `.clang-format` (`ninja check-format`).
   - Ensure 100% test pass rate across all unit and integration targets (`ctest`).
   - Zero compiler warnings with `-Wall -Wextra -Werror -Wpedantic`.

#### Files to Touch
- `openapi/openapi.yaml`
- `tests/integration/CMakeLists.txt`
- `tests/integration/files_e2e_gateway_audit_integration_test.cpp`

---

## 4. Verification & Validation Checklist

| Test Dimension | Validation Method | Target Result |
| :--- | :--- | :--- |
| **Gateway REST Proxying** | `files_e2e_gateway_audit_integration_test` | All 8 REST endpoints route and serialize correctly |
| **Capability Forwarding** | Gateway unit & integration tests | `X-File-Capability` forwarded in gRPC metadata and enforced |
| **Streaming Download** | Chunked download integration test | Streamed chunk-by-chunk; max memory footprint $< 5\text{ MiB}$ |
| **Transactional Outbox** | Database inspection | Every mutation stages an event in `files_outbox` in same SQL TX |
| **Audit Relay Worker** | `files_outbox_relay_test` | Events dispatched to Audit; outbox records marked `Published` |
| **Resilience & Circuit Breaker** | Gateway proxy unit test | Downstream outage trips circuit breaker; returns RFC 7807 HTTP 503 |
| **Zero Plaintext Invariant** | Log & audit payload verification | Ciphertext and decryption keys never logged or stored in audit |
| **Formatting & Linter** | `ninja check-format` | 100% of C++ files strictly conform |
