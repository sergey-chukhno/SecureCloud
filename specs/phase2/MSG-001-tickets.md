# MSG-001 — Establish Messaging Service Foundation
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-001  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-001** establishes the foundational runtime architecture, gRPC/mTLS IPC contracts, configuration system, concurrency foundation, health/readiness engine, and testing harness for the **SecureCloud Messaging Service** (`securecloud-messaging`).

The Messaging Service is the authoritative server-side subsystem responsible for encrypted message acceptance, durable pending state, multi-device delivery routing, read-receipt tracking, and synchronization (**ADR-001**, **ADR-007**). 

### Key Invariants & Architectural Boundaries for MSG-001
1. **Zero Business Logic in MSG-001**:
   MSG-001 establishes the runtime skeleton, transport security, configuration, and worker pool infrastructure. It does **not** implement message envelope parsing, ciphertext storage, conversation membership, E2E crypto session management, delivery state machines, or synchronization cursors. All authoritative gRPC RPC methods defined in `proto/securecloud/messaging/v1/messaging.proto` must return deterministic `grpc::StatusCode::UNIMPLEMENTED`.
2. **Zero Plaintext & Zero Private Key Access (ADR-008)**:
   The Messaging Service never inspects, decrypts, or persists message plaintext, and never holds device private cryptographic keys. All message payloads are treated as opaque binary ciphertext.
3. **No External Message Broker (ADR-003, ADR-007)**:
   The architecture strictly forbids Kafka, RabbitMQ, NATS, or other external message brokers for MVP. Durable pending state resides strictly in ScyllaDB, and concurrency is managed via internal bounded workers.
4. **No Global In-Memory Queue (ADR-007, ADR-010)**:
   There is no unbounded in-memory message queue. In-memory structures contain only bounded working sets. Offline messages are persisted durably, and workers operate within fixed capacity bounds.
5. **Phase 1 Non-Regression Invariant**:
   All completed Phase 1 capabilities (Gateway `GW-001`–`GW-010` and Auth `AUTH-001`–`AUTH-010`), CMake presets, protobuf pipelines, and `verify-local.py` orchestration must continue passing cleanly with zero regressions.
6. **Platform-Consistent Health, Readiness & mTLS**:
   The Messaging Service must utilize the existing common infrastructure (`securecloud::common`): `MtlsCredentialLoader`, `HealthStatusManager`, `HealthServiceImpl`, and `CommonServiceConfig`.

---

## 2. Dependency Graph

```text
               SC-005 (Protobuf Pipeline)
               SC-010 (mTLS Infrastructure)
               SC-012 (Common Configuration)
               SC-013 (Health & Readiness Engine)
                         │
                         ▼
                    MSG-001-T01
       (Protobuf & gRPC Contract Baseline: messaging.proto)
                         │
          ┌──────────────┴──────────────┐
          │                             │
          ▼                             ▼
     MSG-001-T02                   MSG-001-T03
(MessagingConfig Model &       (Bounded Worker Pool &
 Validation Hardening)          Concurrency Foundation)
          │                             │
          └──────────────┬──────────────┘
                         │
                         ▼
                    MSG-001-T04
     (gRPC Service Skeleton & mTLS Server Integration)
                         │
                         ▼
                    MSG-001-T05
     (Service Lifecycle, Structured Logging & Graceful Drain)
                         │
                         ▼
                    MSG-001-T06
     (Comprehensive Unit & Integration Test Suite)
```

---

## 3. Implementation Tickets

### MSG-001-T01 — Protobuf & gRPC Contract Baseline

1. **Ticket ID**: `MSG-001-T01`
2. **Title**: Protobuf & gRPC Contract Baseline for Messaging Service
3. **Objective**: Define the canonical Protobuf schema and gRPC service definitions (`proto/securecloud/messaging/v1/messaging.proto`), register in CMake, and verify clean code generation across AppleClang, GCC, and MSVC.
4. **Architectural Purpose**: Establishes the strongly typed IPC contract between API Gateway and Messaging Service as mandated by **ADR-004** (gRPC IPC) and `docs/design/messaging-design.md` Section 5.41.
5. **Scope**:
   - Create `proto/securecloud/messaging/v1/messaging.proto`.
   - Register the new proto file in `proto/CMakeLists.txt`.
   - Define authoritative RPC methods covering the full Messaging domain lifecycle:
     - **Message Submission & Query**: `SendMessage`, `GetMessages`, `AcknowledgeDelivery`, `SendReadReceipt`
     - **Conversations & Membership**: `CreateConversation`, `GetConversation`, `ListConversations`, `AddParticipant`, `RemoveParticipant`
     - **Device Synchronization**: `SyncDeviceMessages`, `GetSyncCursor`, `UpdateSyncCursor`
   - Define status and priority enums with explicit zero-value defaults (`_UNSPECIFIED = 0`):
     - `MessagePriority`: `MESSAGE_PRIORITY_UNSPECIFIED = 0`, `MESSAGE_PRIORITY_NORMAL = 1`, `MESSAGE_PRIORITY_URGENT = 2`, `MESSAGE_PRIORITY_EMERGENCY = 3`.
     - `DeliveryState`: `DELIVERY_STATE_UNSPECIFIED = 0`, `DELIVERY_STATE_QUEUED = 1`, `DELIVERY_STATE_DELIVERING = 2`, `DELIVERY_STATE_DELIVERED = 3`, `DELIVERY_STATE_READ = 4`, `DELIVERY_STATE_RETRY_WAIT = 5`, `DELIVERY_STATE_EXPIRED = 6`.
     - `ConversationType`: `CONVERSATION_TYPE_UNSPECIFIED = 0`, `CONVERSATION_TYPE_DIRECT = 1`, `CONVERSATION_TYPE_GROUP = 2`.
   - Use canonical 36-character hyphenated UUID `string` fields for `conversation_id`, `message_id`, `sender_user_id`, `sender_device_id`, `recipient_user_id`, `recipient_device_id`.
   - Use `bytes` for encrypted ciphertext payloads (`ciphertext_blob`, `ephemeral_public_key`, `initialization_vector`).
   - Extend `tests/unit/proto_smoke_test.cpp` to verify compilation, linkage, and descriptor reflection of generated messaging headers.
6. **Explicit Out-of-Scope**: Implementing RPC logic, cryptographic verification, or database storage.
7. **Dependencies**: Upstream `proto/CMakeLists.txt`, `cmake/modules/SecureCloudProtobuf.cmake`. Downstream `MSG-001-T04`.
8. **Exact Repository Starting Point**: `proto/CMakeLists.txt`, `proto/securecloud/auth/v1/auth.proto`.
9. **Files/Directories to Inspect**:
   - `docs/design/messaging-design.md` (Sections 5.3, 5.13, 5.19, 5.32, 5.41)
   - `docs/data-model/03-messaging-data-model.md` (Sections 3.1, 3.3)
   - `proto/securecloud/auth/v1/auth.proto`
10. **Files/Directories to Create**:
    - `proto/securecloud/messaging/v1/messaging.proto`
11. **Files/Directories That May Be Modified**:
    - `proto/CMakeLists.txt`
    - `tests/unit/proto_smoke_test.cpp`
12. **Files/Directories That MUST NOT Be Modified**:
    - `proto/securecloud/auth/v1/*`, `proto/securecloud/common/v1/*`.
13. **Detailed Implementation Requirements**:
    - Package: `securecloud.messaging.v1`, `syntax = "proto3"`, `cc_generic_services = false`.
    - Message schemas must support idempotency tokens (`string client_idempotency_token`).
    - Enforce proper C++ Windows DLL export macro compatibility via `proto/proto_win32_compat.hpp`.

---

### MSG-001-T02 — Configuration Model & Environment Validation

1. **Ticket ID**: `MSG-001-T02`
2. **Title**: Messaging Service Configuration Model Expansion & Validation Hardening
3. **Objective**: Expand `MessagingConfig` (`src/messaging/messaging_config.hpp|cpp`) to support structured ScyllaDB cluster settings, bounded worker pool concurrency configurations, and strict security isolation validation.
4. **Architectural Purpose**: Establishes externalized configuration compliance (**ADR-012**, **ADR-010**) ensuring worker limits, queue bounds, and database connection settings are configurable via environment variables without hardcoding.
5. **Scope**:
   - Expand `MessagingConfig` struct with:
     - Common service configuration (`CommonServiceConfig common`).
     - ScyllaDB connection parameters: `scylla_host`, `scylla_port`, `scylla_keyspace`, `scylla_connect_timeout_ms` (default 5000), `scylla_request_timeout_ms` (default 2000), `scylla_connection_pool_size` (default 16).
     - Worker pool dimensions: `submission_workers` (default 8, range [1, 128]), `delivery_workers` (default 16, range [1, 256]), `sync_workers` (default 8, range [1, 128]).
     - Queue capacity limits: `max_queued_submissions` (default 1024), `max_queued_deliveries` (default 4096), `max_queued_syncs` (default 1024).
     - Shutdown timeout: `shutdown_grace_period_ms` (default 10000).
   - Implement strict validation in `MessagingConfig::load`:
     - Validate that ScyllaDB host is non-empty and port is within valid range [1, 65535].
     - Validate that all worker counts and queue limits are within valid non-zero bounds.
     - **Strict Database Boundary Guard**: Verify that no Auth PostgreSQL variables (`SECURECLOUD_AUTH_DB_*`, `POSTGRES_*`) or Files MinIO variables are ingested or required.
   - Add unit tests in `tests/unit/messaging/messaging_config_test.cpp`.
6. **Explicit Out-of-Scope**: Establishing live ScyllaDB connections or parsing business entity configurations.
7. **Dependencies**: `src/common/include/securecloud/configuration/common_service_config.hpp`. Downstream `MSG-001-T03`, `MSG-001-T04`.
8. **Exact Repository Starting Point**: `src/messaging/messaging_config.hpp`, `src/messaging/messaging_config.cpp`.
9. **Files/Directories to Inspect**:
   - `src/auth/auth_config.hpp`, `src/auth/auth_config.cpp`
   - `docs/design/messaging-design.md` (Sections 5.30, 5.31)
10. **Files/Directories to Create**:
    - `tests/unit/messaging/messaging_config_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `src/messaging/messaging_config.hpp`
    - `src/messaging/messaging_config.cpp`
12. **Files/Directories That MUST NOT Be Modified**:
    - `src/auth/*`, `src/gateway/*`.
13. **Detailed Implementation Requirements**:
    - Configuration keys adhere to standard prefix: `SECURECLOUD_MESSAGING_*` (e.g. `SECURECLOUD_MESSAGING_SCYLLA_HOST`, `SECURECLOUD_MESSAGING_SUBMISSION_WORKERS`).
    - Validation failures append clear diagnostic messages to `ValidationResult`.

---

### MSG-001-T03 — Bounded Worker Pool & Concurrency Foundation

1. **Ticket ID**: `MSG-001-T03`
2. **Title**: Bounded Worker Pool & Concurrency Infrastructure
3. **Objective**: Implement a high-performance, bounded C++20 thread pool (`BoundedWorkerPool`) providing task submission, queue capacity backpressure, and deterministic RAII lifecycle shutdown adhering to **ADR-009** and **ADR-010**.
4. **Architectural Purpose**: Establishes the bounded concurrency primitive required by the Messaging Service foundation so that subsequent cards (`MSG-002` onwards) can partition submission, delivery, and sync workloads into isolated bulkheads without unbounded memory growth.
5. **Scope**:
   - Design and implement `src/messaging/concurrency/bounded_worker_pool.hpp|cpp`:
     - Constructor accepting `size_t thread_count`, `size_t max_queue_capacity`, and `std::string pool_name`.
     - Non-blocking task submission: `bool try_submit(std::function<void()> task)`. Returns `false` immediately when queue is full (fail-fast / backpressure).
     - Blocking/timed submission: `bool submit_with_timeout(std::function<void()> task, std::chrono::milliseconds timeout)`.
     - Graceful drain and shutdown: `void shutdown()`, `void drain_and_stop()`.
     - Inspection metrics: `size_t active_threads()`, `size_t queued_tasks()`, `size_t capacity()`, `bool is_shutdown()`.
   - Implement RAII destructor ensuring all worker threads are joined cleanly.
   - Leverage C++20 `std::jthread` and `std::stop_token` where applicable.
   - Comprehensive unit tests in `tests/unit/messaging/bounded_worker_pool_test.cpp` verifying execution, saturation backpressure, rejection, and thread joining.
6. **Explicit Out-of-Scope**: Implementing messaging queues, priority schedulers, or delivery state tracking.
7. **Dependencies**: Upstream `MSG-001-T02`. Downstream `MSG-001-T04`, `MSG-001-T05`.
8. **Exact Repository Starting Point**: `src/messaging/`.
9. **Files/Directories to Inspect**:
   - `docs/design/messaging-design.md` (Sections 5.19, 5.20, 5.30, 5.31)
   - `docs/adr/adr-009-distributed-failure-resilience.md`
   - `docs/adr/adr-010-performance-capacity-optimization.md`
10. **Files/Directories to Create**:
    - `src/messaging/concurrency/bounded_worker_pool.hpp`
    - `src/messaging/concurrency/bounded_worker_pool.cpp`
    - `tests/unit/messaging/bounded_worker_pool_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `src/messaging/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**:
    - `src/common/*`, `src/auth/*`.
13. **Detailed Implementation Requirements**:
    - Thread names set for debugging (e.g. `sc-msg-sub-0`, `sc-msg-del-0`).
    - Thread-safe synchronization using `std::mutex` and `std::condition_variable`.
    - Zero allocations on task submission beyond `std::function` storage.

---

### MSG-001-T04 — gRPC Service Implementation Skeleton & mTLS Server Integration

1. **Ticket ID**: `MSG-001-T04`
2. **Title**: Messaging Service gRPC Implementation Skeleton & mTLS Integration
3. **Objective**: Implement `MessagingServiceImpl` inheriting from generated `securecloud::messaging::v1::MessagingService::Service`, providing deterministic `UNIMPLEMENTED` responses for all RPCs, and integrate into gRPC server with strict mTLS SAN verification.
4. **Architectural Purpose**: Establishes the authoritative gRPC service boundary as mandated by **ADR-004** and `docs/design/messaging-design.md`, allowing API Gateway and integration tests to interact over authenticated mTLS channels.
5. **Scope**:
   - Implement `src/messaging/service/messaging_service_impl.hpp|cpp`:
     - Inherits from `securecloud::messaging::v1::MessagingService::Service`.
     - Overrides all 12 RPC methods declared in `messaging.proto`.
     - Each method logs invocation details (correlation ID, peer identity) at `DEBUG` level and returns `grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "RPC not implemented in MSG-001 foundation")`.
   - Update `src/messaging/CMakeLists.txt` to compile `messaging_service_impl.cpp` into `securecloud_messaging`.
   - Integrate mTLS server credentials loader using `securecloud::common::security::MtlsCredentialLoader::create_server_credentials`.
   - Add unit tests in `tests/unit/messaging/messaging_service_test.cpp` verifying that every RPC returns `UNIMPLEMENTED` and verifies mTLS certificate loading.
6. **Explicit Out-of-Scope**: Any business logic execution, database queries, or message envelope processing.
7. **Dependencies**: Upstream `MSG-001-T01`, `MSG-001-T02`. Downstream `MSG-001-T05`.
8. **Exact Repository Starting Point**: `src/messaging/`, `proto/securecloud/messaging/v1/messaging.proto`.
9. **Files/Directories to Inspect**:
   - `src/auth/service/auth_service_impl.hpp|cpp`
   - `src/common/include/securecloud/security/mtls_config.hpp`
10. **Files/Directories to Create**:
    - `src/messaging/service/messaging_service_impl.hpp`
    - `src/messaging/service/messaging_service_impl.cpp`
    - `tests/unit/messaging/messaging_service_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `src/messaging/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**:
    - `src/auth/*`, `src/gateway/*`.
13. **Detailed Implementation Requirements**:
    - In-place extraction of `x-correlation-id` and `x-request-id` from `grpc::ServerContext` metadata.
    - Peer certificate identity extraction (verifying peer SAN matches `gateway` or internal services).

---

### MSG-001-T05 — Service Lifecycle, Structured Logging, Health/Readiness & Graceful Drain

1. **Ticket ID**: `MSG-001-T05`
2. **Title**: Messaging Service Lifecycle, Structured Logging, Health/Readiness & Graceful Drain
3. **Objective**: Refactor `src/messaging/main.cpp` into a production-grade service executable featuring structured logging, signal handling (`SIGINT`, `SIGTERM`), dual health/readiness integration (`HealthServiceImpl`), and coordinated graceful drain.
4. **Architectural Purpose**: Guarantees zero-downtime rolling deployment support and clean process lifecycle management conforming to **ADR-009** and platform standards.
5. **Scope**:
   - Refactor `src/messaging/main.cpp`:
     - Replace raw `std::cout`/`std::cerr` with structured logging using project conventions.
     - Set up signal handling with `std::atomic<bool>` / `std::stop_source` for `SIGINT` and `SIGTERM`.
     - Initialize `MessagingConfig` from environment.
     - Instantiate and wire `HealthStatusManager` and `HealthServiceImpl`.
     - Register both `HealthServiceImpl` and `MessagingServiceImpl` with `grpc::ServerBuilder`.
     - Bind to configured `listen_address` strictly via mTLS server credentials.
     - Initialize bounded worker pools (`submission_workers`, `delivery_workers`, `sync_workers`) via `BoundedWorkerPool`.
     - Implement clean shutdown sequence:
       1. Transition health status: `health_manager.set_shutting_down(true)`.
       2. Begin gRPC server drain with configured timeout (`server->Shutdown(deadline)`).
       3. Drain and stop worker pools (`worker_pool->drain_and_stop()`).
       4. Log clean shutdown confirmation.
6. **Explicit Out-of-Scope**: Establishing ScyllaDB driver connections (owned by later persistence card).
7. **Dependencies**: Upstream `MSG-001-T02`, `MSG-001-T03`, `MSG-001-T04`. Downstream `MSG-001-T06`.
8. **Exact Repository Starting Point**: `src/messaging/main.cpp`.
9. **Files/Directories to Inspect**:
   - `src/auth/main.cpp`
   - `src/gateway/server/https_server.cpp`
   - `src/common/include/securecloud/health/health_service_impl.hpp`
10. **Files/Directories to Create**: None (refactors existing `main.cpp`).
11. **Files/Directories That May Be Modified**:
    - `src/messaging/main.cpp`
    - `src/messaging/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**:
    - `src/common/*`, `src/auth/*`.
13. **Detailed Implementation Requirements**:
    - Catch all standard exceptions in `main()` and return non-zero exit codes with diagnostic logs.
    - Zero hangs on shutdown: shutdown must complete within `shutdown_grace_period_ms`.

---

### MSG-001-T06 — Comprehensive Unit & Integration Test Suite

1. **Ticket ID**: `MSG-001-T06`
2. **Title**: Messaging Service Foundation Unit & Integration Verification Suite
3. **Objective**: Build and execute an exhaustive test suite covering configuration validation, worker pool concurrency, gRPC service stubs, mTLS communication, and service lifecycle over live sockets.
4. **Architectural Purpose**: Provides complete verification evidence proving that the Messaging Service runtime skeleton is rock-solid, buildable, testable, and ready for Phase 2 business capabilities.
5. **Scope**:
   - Implement unit tests:
     - `tests/unit/messaging/messaging_config_test.cpp`: tests default values, environment variable overrides, invalid inputs, and port range validation.
     - `tests/unit/messaging/bounded_worker_pool_test.cpp`: tests concurrent execution, task completion, queue saturation backpressure, rejection behavior, and clean teardown.
     - `tests/unit/messaging/messaging_service_test.cpp`: tests `MessagingServiceImpl` direct invocations, verifying that all RPC methods return `grpc::StatusCode::UNIMPLEMENTED`.
   - Implement live integration test:
     - `tests/integration/messaging_service_lifecycle_integration_test.cpp`: launches the Messaging service gRPC server on an ephemeral port with test mTLS certificates, connects via `grpc.health.v1.Health` client, validates `SERVING` status, calls a `MessagingService` RPC (verifying `UNIMPLEMENTED`), triggers graceful shutdown, and verifies clean exit.
   - Register all test targets in `tests/unit/CMakeLists.txt` and `tests/integration/CMakeLists.txt`.
   - Verify 100% clean build and test pass via canonical project build.
6. **Explicit Out-of-Scope**: Testing database tables or client E2E encryption.
7. **Dependencies**: Upstream `MSG-001-T01` through `MSG-001-T05`.
8. **Exact Repository Starting Point**: `tests/unit/messaging/`, `tests/integration/`.
9. **Files/Directories to Inspect**:
   - `tests/unit/auth/`
   - `tests/integration/gateway_auth_e2e_integration_test.cpp`
10. **Files/Directories to Create**:
    - `tests/unit/messaging/messaging_config_test.cpp`
    - `tests/unit/messaging/bounded_worker_pool_test.cpp`
    - `tests/unit/messaging/messaging_service_test.cpp`
    - `tests/integration/messaging_service_lifecycle_integration_test.cpp`
11. **Files/Directories That May Be Modified**:
    - `tests/unit/CMakeLists.txt`
    - `tests/integration/CMakeLists.txt`
12. **Files/Directories That MUST NOT Be Modified**:
    - Existing Auth and Gateway tests.
13. **Detailed Implementation Requirements**:
    - Integration tests use isolated ephemeral ports (`0` or dynamic high ports) to prevent port collisions.
    - All tests must pass under AddressSanitizer and ThreadSanitizer.

---

## 4. Cross-Cutting Invariants Checklist

| Invariant | Enforcement Mechanism | Verification Target |
| :--- | :--- | :--- |
| **Zero Business Logic in Foundation** | All RPCs return `grpc::StatusCode::UNIMPLEMENTED`. | `messaging_service_test` |
| **Zero Plaintext Access (ADR-008)** | Proto messages model payloads strictly as opaque `bytes`. | `proto_smoke_test` |
| **No External Message Broker (ADR-003)** | No Kafka, RabbitMQ, or NATS client dependencies linked. | `CMakeLists.txt` inspection |
| **Bounded Concurrency (ADR-009, ADR-010)** | `BoundedWorkerPool` enforces strict capacity ceilings and backpressure. | `bounded_worker_pool_test` |
| **Strict Service mTLS (ADR-004)** | gRPC server only accepts connections authenticated with valid internal cluster mTLS. | `messaging_service_lifecycle_integration_test` |
| **Clean Graceful Shutdown** | Signal handler sets health to `NOT_SERVING`, drains gRPC server and worker pools. | `messaging_service_lifecycle_integration_test` |
| **Externalized Configuration (ADR-012)** | All ports, worker counts, and timeouts loaded from environment variables with bounds checking. | `messaging_config_test` |

---

## 5. Verification & Acceptance Criteria

1. **Compilation**: `securecloud-messaging` and all messaging test executables compile cleanly without warnings under `-Wall -Wextra -Werror` across macOS (AppleClang), Linux (GCC), and Windows (MSVC).
2. **mTLS Handshake**: Live client connection with internal test CA establishes successfully; rogue client without client certificate is rejected.
3. **Health Check**: `grpc.health.v1.Health/Check` returns `SERVING` while active, and transitions to `NOT_SERVING` upon initiation of shutdown.
4. **gRPC RPC Stubs**: Calling any RPC on `securecloud.messaging.v1.MessagingService` returns `grpc::StatusCode::UNIMPLEMENTED`.
5. **No Regressions**: All existing Gateway and Auth test targets continue to execute with 100% pass rate.
