# MSG-007 — Online Message Delivery
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-007  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 19, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-007** implements the durable **Online Message-Delivery Pipeline** for the SecureCloud Messaging Service (`securecloud-messaging`), adhering strictly to **ADR-007** (Messaging Reliability & Durability), **ADR-008** (Security & Cryptographic Architecture), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance, Capacity & Optimization Strategy).

While **MSG-005** established the durable write boundary (monotonic sequence allocation, idempotency guard, ScyllaDB durability commit) and **MSG-006** integrated the server-side End-to-End (E2E) encrypted envelope model, **MSG-007 delivers the opaque ciphertext asynchronously to authorized recipient devices that are currently connected and eligible for online delivery**.

### The Fundamental Guarantees of MSG-007:
1. **Durable Authority vs. Ephemeral Scheduling**: The ScyllaDB tables (`pending_deliveries_by_device` and `delivery_state_by_message`) remain the authoritative single source of truth for delivery obligations. In-memory scheduling queues are strictly a bounded optimization. Losing any in-memory scheduler item due to crash, eviction, or saturation must **never** cause message loss or abandon a delivery obligation.
2. **At-Least-Once Delivery**: Network delivery guarantees at-least-once semantics. Clients deduplicate received messages using the stable, globally unique `message_id`. Retries must not create duplicate logical messages.
3. **Explicit Acknowledgement Semantics**: A successful network socket write alone does **not** signify `DELIVERED`. The recipient client must affirmatively acknowledge receipt and local persistence via `AcknowledgeDelivery`. Only then does the durable state transition to `DELIVERED`.
4. **Bounded Concurrency & Head-of-Line Blocking Prevention**: Delivery workers run within a dedicated, bounded worker pool (`delivery_pool_`). Per-device dispatch queues and bounded global scheduler buffers ensure that slow, offline, or misbehaving devices cannot starve or head-of-line block delivery to other devices or unrelated conversations.
5. **No Decryption Invariant**: Delivery workers transport the encrypted `PerDeviceEnvelope` payloads verbatim. Workers do not possess private keys, do not decrypt message content, and do not log or inspect ciphertexts.
6. **Crash Recovery**: On service restart or worker recovery, unacknowledged pending deliveries are reliably reconstructed and re-scheduled from ScyllaDB durable state.
7. **No Heavy External Brokers**: Adhering strictly to ADR-007, no Kafka, RabbitMQ, or NATS brokers are introduced for MVP. ScyllaDB + Transactional Outbox + Bounded In-Memory Scheduling provides the complete delivery engine.

---

## 2. Core Architectural Invariants & Delivery Lifecycle

### 2.1 The Two-Tier Delivery Model

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               TIER 1: DURABLE STATE                              │
│                            (Authoritative Source of Truth)                       │
│                                                                                  │
│   ScyllaDB Tables:                                                               │
│   - securecloud_messaging.pending_deliveries_by_device ((device_id, bucket))     │
│   - securecloud_messaging.delivery_state_by_message   (message_id)               │
│   - securecloud_messaging.messaging_outbox_events     (outbox_bucket)            │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │ Hydration on boot
          Event-driven trigger         │ & Periodic sweep
        (MessageSent outbox event)     │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                        TIER 2: BOUNDED IN-MEMORY SCHEDULER                       │
│                      (Ephemeral Performance Optimization)                        │
│                                                                                  │
│   - Bounded global scheduler queue (max_global_items = 10,000)                   │
│   - Per-device fair dispatch ring buffers (max_per_device = 50)                  │
│   - Priority scheduling (Emergency > Urgent > Normal)                            │
│   - Backpressure drop policy (overflow drops to Tier 1; recovered by sweep)      │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │ Dequeue item
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             DELIVERY WORKER PIPELINE                             │
│                  (BoundedWorkerPool: delivery_pool_, 16-32 threads)              │
│                                                                                  │
│   1. Inspect online status via IDeviceConnectionRegistry                         │
│   2. If offline: retain durable QUEUED status, defer dispatch                    │
│   3. If online: transition QUEUED -> DELIVERING in memory/repo                   │
│   4. Dispatch opaque ciphertext via IDeviceDeliveryChannel                       │
│   5. On transient error: transition to RETRY_WAIT with exponential jitter        │
│   6. On terminal error: transition to EXPIRED / terminal failure                 │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │ Push to client
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                RECIPIENT CLIENT                                  │
│                                                                                  │
│   1. Receives ciphertext envelope                                                │
│   2. Deduplicates against local SQLite using stable message_id                   │
│   3. Durably commits ciphertext to local store                                   │
│   4. Sends affirmative gRPC AcknowledgeDelivery(message_id, recipient_device_id) │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │ RPC response
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             DURABLE ACK COMMITMENT                               │
│                                                                                  │
│   - ScyllaDB: delivery_state_by_message -> DELIVERED                             │
│   - ScyllaDB: pending_deliveries_by_device status updated / pruned               │
│   - Outbox: MessageDelivered event enqueued for Audit and read tracking          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Canonical Delivery State Transitions (ADR-007)

```text
             ┌────────────────────────┐
             │         QUEUED         │
             └───────────┬────────────┘
                         │ Worker picks up item & initiates push
                         ▼
             ┌────────────────────────┐
             │       DELIVERING       │
             └──────┬───────────┬─────┘
                    │           │
     Client ACK     │           │ Transient network failure
     received       │           │ or connection reset
                    │           ▼
                    │    ┌──────────────┐
                    │    │  RETRY_WAIT  │
                    │    └──────┬───────┘
                    │           │ Exponential backoff + jitter expires
                    │           └───────────┐
                    ▼                       ▼
             ┌──────────────┐        ┌──────────────┐
             │  DELIVERED   │        │  DELIVERING  │
             └──────┬───────┘        └──────────────┘
                    │ (MSG-008 Read State)
                    ▼
             ┌──────────────┐
             │     READ     │
             └──────────────┘

Terminal Expiration (ADR-007 §14):
QUEUED | DELIVERING | RETRY_WAIT ──(TTL / Max Attempts Exceeded)──► EXPIRED
```

### 2.3 Strict Invariants & Anti-Patterns

| Category | Invariant | Strictly Prohibited Anti-Pattern |
| :--- | :--- | :--- |
| **Durability** | Ephemeral queues must never become the source of truth. Crash recovery scans ScyllaDB. | Relying on in-memory queue state for delivery obligations; dropping messages when queue overflows. |
| **Security** | Zero Plaintext: Delivery workers forward ciphertext blobs untouched. | Inspecting, logging, or decrypting message payloads in delivery workers. |
| **Concurrency** | Bounded concurrency pools. Per-device isolation prevents head-of-line blocking. | Unbounded `std::thread` spawning; single slow recipient blocking the global delivery loop. |
| **Ordering** | Stream ordering preserved per recipient device where required. | Global cross-device total ordering locks. |
| **Delivery ACKs**| `DELIVERED` status requires affirmative client acknowledgement. | Marking a message delivered immediately upon socket write. |
| **Idempotency** | Duplicate delivery ACKs are safe, idempotent no-ops. | Returning errors on duplicate ACKs or duplicating logical deliveries. |
| **Backpressure**| Scheduler queues are bounded. Excess items are dropped to durable state. | Unbounded in-memory queue growth causing out-of-memory crashes. |

---

## 3. Dependency Graph & Implementation Tickets

```text
               MSG-005 (Durable Write Pipeline & Transactional Outbox)
               MSG-006 (E2E Message Envelope Integration & Zero Plaintext)
                                       │
                                       ▼
                                  MSG-007-T01
       (Delivery Domain Model, Extended State Machine & Decorrelated Jitter Retry)
                                       │
                                       ▼
                                  MSG-007-T02
       (Connected Device Registry, Channel Routing Port & Push Adapter)
                                       │
                                       ▼
                                  MSG-007-T03
       (Bounded In-Memory Delivery Scheduler & Per-Device Fairness Queue)
                                       │
                                       ▼
                                  MSG-007-T04
       (Delivery Worker Pipeline, Transient Failure Handling & Outbox Listener)
                                       │
                                       ▼
                                  MSG-007-T05
       (Authoritative Delivery Acknowledgement RPC & ScyllaDB Durable Commit)
                                       │
                                       ▼
                                  MSG-007-T06
       (Durable Recovery Engine & Comprehensive E2E Online Delivery Test Suite)
```

---

## 4. Detailed Implementation Tickets

### MSG-007-T01 — Delivery Domain Model, Extended State Machine & Decorrelated Jitter Retry

1. **Ticket ID**: `MSG-007-T01`
2. **Title**: Online Delivery Domain Model, Lifecycle Transition Guards & Decorrelated Jitter Retry Policy
3. **Objective**: Formalize the delivery execution domain models, enforce canonical state machine transitions, and implement the production-grade exponential retry engine with decorrelated jitter adhering to ADR-007 and ADR-009.
4. **Architectural Purpose**: Establishes strong types and validated mathematical foundations for delivery retry timings, preventing retry storms, thundering herds, and invalid delivery state transitions.
5. **Scope**:
   - In `src/messaging/domain/delivery_types.hpp`:
     - Refine `DeliveryState`:
       - `Queued = 1`
       - `Delivering = 2`
       - `Delivered = 3`
       - `Read = 4`
       - `RetryWait = 5`
       - `Expired = 6`
     - Align `to_string(DeliveryState)` and `delivery_state_from_string` with protobuf `v1::DeliveryState`.
     - Define `DeliveryAttemptResult` enum:
       - `Success = 1`: Recipient device accepted envelope and provided ACK.
       - `RecipientOffline = 2`: Recipient device is not currently connected.
       - `TransientFailure = 3`: Connection reset, network timeout, or socket failure.
       - `TerminalFailure = 4`: Device revoked, invalid protocol, or message retention expired.
     - Define `DeliveryTask`:
       - `MessageId message_id`
       - `ConversationId conversation_id`
       - `DeviceId recipient_device_id`
       - `UserId recipient_user_id`
       - `MessagePriority priority`
       - `int32_t attempt_count`
       - `std::chrono::system_clock::time_point accepted_at`
       - `std::chrono::system_clock::time_point scheduled_at`
       - `std::optional<std::chrono::system_clock::time_point> expires_at`
       - `domain::PerDeviceEnvelope envelope`
   - In `src/messaging/service/delivery_retry_policy.hpp|cpp`:
     - Implement `DeliveryRetryPolicy`:
       - Configuration parameters:
         - `initial_backoff_ms` (default: 500ms)
         - `max_backoff_ms` (default: 60,000ms / 1 min)
         - `backoff_multiplier` (default: 2.0)
         - `max_retry_attempts` (default: 10)
         - `jitter_factor` (default: 0.25)
       - `compute_next_delay(int32_t attempt_count) -> std::chrono::milliseconds`:
         - Uses full decorrelated jitter formula:
           $$T_{\text{backoff}} = \min(T_{\text{max}}, T_{\text{initial}} \times 2^{\text{attempt}})$$
           $$T_{\text{jittered}} = \text{UniformRandom}((1 - \alpha) \times T_{\text{backoff}}, (1 + \alpha) \times T_{\text{backoff}})$$
       - `is_retryable(DeliveryAttemptResult result, int32_t attempt_count, std::chrono::system_clock::time_point expires_at) -> bool`:
         - Returns `false` if `result == TerminalFailure`, `attempt_count >= max_retry_attempts`, or `now >= expires_at`.
   - In `src/messaging/service/delivery_lifecycle.hpp|cpp`:
     - Update `is_valid_delivery_transition` to support all canonical paths:
       - `QUEUED -> DELIVERING`
       - `DELIVERING -> DELIVERED`
       - `DELIVERING -> RETRY_WAIT`
       - `RETRY_WAIT -> DELIVERING`
       - `QUEUED | DELIVERING | RETRY_WAIT -> EXPIRED`
       - `DELIVERED -> READ`
     - Verify idempotent transition checks (`is_idempotent_delivery_state`).
   - Unit tests in `tests/unit/messaging/delivery_retry_policy_test.cpp` and `tests/unit/messaging/delivery_lifecycle_test.cpp`.
6. **Explicit Out-of-Scope**: Active socket I/O; ScyllaDB queries.
7. **Dependencies**: `MSG-002`, `MSG-005`, `MSG-006`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/delivery_types.hpp`
   - `src/messaging/service/delivery_retry_policy.hpp`
   - `src/messaging/service/delivery_retry_policy.cpp`
   - `src/messaging/service/delivery_lifecycle.hpp`
   - `src/messaging/service/delivery_lifecycle.cpp`
   - `tests/unit/messaging/delivery_retry_policy_test.cpp`
   - `tests/unit/messaging/delivery_lifecycle_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-007-T02 — Connected Device Registry & Delivery Channel Routing Port

1. **Ticket ID**: `MSG-007-T02`
2. **Title**: Connected Device Registry, Device Delivery Channel Port & Multi-Device Routing
3. **Objective**: Implement the device connection registry abstraction and channel routing port that tracks active client connections and dispatches encrypted envelopes to connected endpoints.
4. **Architectural Purpose**: Decouples the Messaging delivery engine from concrete transport protocols (gRPC streaming, WebSocket, or testing mock channels), while authoritatively tracking online presence without violating service boundaries or requiring sticky sessions.
5. **Scope**:
   - In `src/messaging/delivery/device_delivery_channel_interface.hpp`:
     - Define `IDeviceDeliveryChannel`:
       ```cpp
       class IDeviceDeliveryChannel {
       public:
           virtual ~IDeviceDeliveryChannel() = default;
           [[nodiscard]] virtual DeviceId device_id() const noexcept = 0;
           [[nodiscard]] virtual UserId user_id() const noexcept = 0;
           [[nodiscard]] virtual bool is_active() const noexcept = 0;
           virtual DeliveryAttemptResult send_envelope(
               const domain::DeliveryTask& task,
               std::chrono::milliseconds timeout) = 0;
       };
       ```
   - In `src/messaging/delivery/device_connection_registry_interface.hpp`:
     - Define `IDeviceConnectionRegistry`:
       ```cpp
       class IDeviceConnectionRegistry {
       public:
           virtual ~IDeviceConnectionRegistry() = default;
           virtual void register_channel(std::shared_ptr<IDeviceDeliveryChannel> channel) = 0;
           virtual void unregister_channel(const domain::DeviceId& device_id) = 0;
           [[nodiscard]] virtual std::shared_ptr<IDeviceDeliveryChannel>
               get_channel(const domain::DeviceId& device_id) const = 0;
           [[nodiscard]] virtual bool is_online(const domain::DeviceId& device_id) const = 0;
           [[nodiscard]] virtual std::vector<domain::DeviceId>
               filter_online_devices(const std::vector<domain::DeviceId>& device_ids) const = 0;
           [[nodiscard]] virtual size_t connected_device_count() const noexcept = 0;
       };
       ```
   - In `src/messaging/delivery/device_connection_registry.hpp|cpp`:
     - Implement thread-safe `DeviceConnectionRegistry`:
       - Internal concurrency: `std::shared_mutex` for read-heavy channel lookup.
       - Heartbeat / liveness tracking: channels have a last-seen timestamp and configurable lease timeout (e.g., 60 seconds).
       - Channel eviction on disconnect or stale lease.
       - Disconnect callback notification support for clean scheduler descheduling.
   - In `src/messaging/delivery/mock_device_delivery_channel.hpp`:
     - Implement high-fidelity mock channel for unit and stress testing (supports simulated latency, dropped packets, disconnection, and synthetic ACKs).
   - Unit tests in `tests/unit/messaging/device_connection_registry_test.cpp`.
6. **Explicit Out-of-Scope**: Gateway HTTP SSE/WebSocket proxy implementation (gateway route handled in T05).
7. **Dependencies**: `MSG-007-T01`.
8. **Files to Create/Modify**:
   - `src/messaging/delivery/device_delivery_channel_interface.hpp`
   - `src/messaging/delivery/device_connection_registry_interface.hpp`
   - `src/messaging/delivery/device_connection_registry.hpp`
   - `src/messaging/delivery/device_connection_registry.cpp`
   - `src/messaging/delivery/mock_device_delivery_channel.hpp`
   - `tests/unit/messaging/device_connection_registry_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-007-T03 — Bounded In-Memory Delivery Scheduler & Per-Device Fairness Queue

1. **Ticket ID**: `MSG-007-T03`
2. **Title**: Bounded In-Memory Delivery Scheduler, Per-Device Fairness Queue & Drop-to-Durable Backpressure
3. **Objective**: Implement a bounded, priority-aware, starvation-free in-memory delivery scheduler that isolates device queues and applies drop-to-durable backpressure under load.
4. **Architectural Purpose**: Enforces ADR-010 and ADR-007 concurrency rules. Prevents one slow or unresponsive recipient from exhausting global delivery capacity (head-of-line blocking prevention) and ensures process memory remains bounded regardless of message volume.
5. **Scope**:
   - In `src/messaging/delivery/delivery_scheduler_config.hpp`:
     - Define `DeliverySchedulerConfig`:
       - `max_global_queued_tasks` (default: 10,000 tasks)
       - `max_tasks_per_device` (default: 50 tasks)
       - `emergency_queue_reserved_slots` (default: 1,000 slots)
       - `fairness_quanta_per_device` (default: 5 tasks per round-robin turn)
   - In `src/messaging/delivery/bounded_delivery_scheduler.hpp|cpp`:
     - Implement `BoundedDeliveryScheduler`:
       - Multi-tier queue hierarchy:
         1. **Emergency Priority Queue**: Preempts normal and urgent traffic, strictly bounded.
         2. **Urgent & Normal Per-Device Queues**: Hash map of `DeviceId -> std::deque<DeliveryTask>`.
       - **Round-Robin Fair Dispatcher**:
         - Workers pull tasks using round-robin iteration over active device queues.
         - A device that has slow ACKs or many pending messages yields after its quantum (`fairness_quanta_per_device`), allowing other devices fair access to worker threads.
       - **Bounded Capacity & Drop-to-Durable Backpressure**:
         - If a specific device queue exceeds `max_tasks_per_device`, incoming scheduling attempts return `SchedulerStatus::DeviceQueueFull`.
         - If total in-memory tasks exceed `max_global_queued_tasks`, return `SchedulerStatus::GlobalCapacityExhausted`.
         - **Durable Safety Invariant**: Rejection from in-memory scheduler does NOT fail the message. Because the message was durably committed to ScyllaDB in MSG-005/006, dropping the in-memory item simply defers delivery to the background durable recovery engine (T06).
       - Cancellation and eviction:
         - When a device disconnects, its in-memory queue can be pruned/drained without data loss.
         - Thread-safe synchronization with `std::mutex` and `std::condition_variable`.
   - Unit tests in `tests/unit/messaging/bounded_delivery_scheduler_test.cpp`:
     - Verify FIFO ordering within single device.
     - Verify fairness: 1 slow recipient does not starve 10 fast recipients.
     - Verify capacity limits: 10,001st task rejected with backpressure status.
     - Verify priority: Emergency message dispatched ahead of normal queue.
6. **Explicit Out-of-Scope**: Worker execution loop (handled in T04).
7. **Dependencies**: `MSG-007-T01`, `MSG-007-T02`.
8. **Files to Create/Modify**:
   - `src/messaging/delivery/delivery_scheduler_config.hpp`
   - `src/messaging/delivery/bounded_delivery_scheduler.hpp`
   - `src/messaging/delivery/bounded_delivery_scheduler.cpp`
   - `tests/unit/messaging/bounded_delivery_scheduler_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-007-T04 — Delivery Worker Pipeline, Transient Failure Handling & Outbox Consumer

1. **Ticket ID**: `MSG-007-T04`
2. **Title**: DeliveryWorker Execution Pipeline, Exponential Retry Scheduling & Transactional Outbox Consumer
3. **Objective**: Implement the active `DeliveryWorker` processing loop operating on `BoundedWorkerPool` (`delivery_pool_`), wire the Transactional Outbox event listener, and manage transient failure recovery.
4. **Architectural Purpose**: Executes the asynchronous push pipeline from message acceptance through network dispatch, ensuring transient failures back off cleanly with jitter without losing durable state.
5. **Scope**:
   - In `src/messaging/delivery/delivery_worker.hpp|cpp`:
     - Implement `DeliveryWorker`:
       - Bound to the existing `delivery_pool_` in `MessagingServiceImpl`.
       - Worker execution steps:
         1. Poll/wait for `DeliveryTask` from `BoundedDeliveryScheduler`.
         2. Lookup channel in `IDeviceConnectionRegistry`:
            - If device offline: update durable state to `QUEUED` / `PENDING` (no retry backoff penalty), drop from memory queue.
         3. Update durable state: `delivery_repo_->update_device_delivery_status` -> `DELIVERING`.
         4. Invoke `channel->send_envelope(task, timeout)`.
         5. Evaluate `DeliveryAttemptResult`:
            - **Success / Synchronous ACK**:
              - Update durable state: `DELIVERED`.
              - Remove from pending ScyllaDB table.
              - Enqueue `MessageDelivered` outbox event.
            - **Recipient Disconnected during transmission**:
              - Retain in ScyllaDB as `QUEUED`.
            - **Transient Failure (Timeout / Connection Dropped)**:
              - Increment `attempt_count`.
              - Check retry policy: if retryable:
                - Calculate delay $T_{\text{jittered}}$ via `DeliveryRetryPolicy`.
                - Update ScyllaDB: state = `RETRY_WAIT`, `next_retry_at = now + delay`.
                - Schedule re-enqueue timer (or hand off to delayed retry queue).
              - Else (retries exhausted or retention expired):
                - Update ScyllaDB: state = `EXPIRED`.
            - **Terminal Failure (Revoked Device / Auth Failure)**:
              - Update ScyllaDB: state = `EXPIRED`.
   - In `src/messaging/delivery/outbox_delivery_consumer.hpp|cpp`:
     - Implement `OutboxDeliveryConsumer`:
       - Subscribes to / polls `IOutboxRepository` for `ConversationOutboxEventType::MessageSent` events.
       - Parses outbox event payload: extracts `message_id`, `conversation_id`, recipient targets.
       - Queries `IDeviceConnectionRegistry` for online recipient devices.
       - Enqueues delivery tasks for online devices into `BoundedDeliveryScheduler`.
       - Non-blocking: if scheduler queue is full, logs backpressure metric and relies on durable recovery.
   - Graceful shutdown:
     - Worker loop cleanly drains in-flight items or safely reverts in-flight tasks to `QUEUED` before terminating.
   - Unit tests in `tests/unit/messaging/delivery_worker_test.cpp` and `tests/unit/messaging/outbox_delivery_consumer_test.cpp`.
6. **Explicit Out-of-Scope**: Client-side decryption; ScyllaDB schema changes.
7. **Dependencies**: `MSG-007-T01`, `MSG-007-T02`, `MSG-007-T03`.
8. **Files to Create/Modify**:
   - `src/messaging/delivery/delivery_worker.hpp`
   - `src/messaging/delivery/delivery_worker.cpp`
   - `src/messaging/delivery/outbox_delivery_consumer.hpp`
   - `src/messaging/delivery/outbox_delivery_consumer.cpp`
   - `tests/unit/messaging/delivery_worker_test.cpp`
   - `tests/unit/messaging/outbox_delivery_consumer_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-007-T05 — Authoritative Delivery Acknowledgement (`AcknowledgeDelivery`) & ScyllaDB State Commit

1. **Ticket ID**: `MSG-007-T05`
2. **Title**: Authoritative Delivery Acknowledgement gRPC Handler, ScyllaDB State Commit & Gateway REST Route
3. **Objective**: Implement the authoritative `AcknowledgeDelivery` gRPC endpoint in `MessagingServiceImpl`, commit delivery receipts to ScyllaDB, emit `MessageDelivered` outbox events, and wire the Gateway REST proxy route.
4. **Architectural Purpose**: Completes the delivery loop by processing affirmative recipient device receipts, updating durable ScyllaDB records (`delivery_state_by_message`), and exposing the delivery receipt interface to clients through Gateway.
5. **Scope**:
   - In `src/messaging/service/delivery_service.hpp|cpp`:
     - Implement `DeliveryService`:
       - `acknowledge_delivery(const domain::MessageId& message_id, const domain::DeviceId& device_id, const domain::UserId& caller_user_id, std::chrono::system_clock::time_point delivered_at) -> Result<DeliveryAcknowledgementResult, ServiceError>`:
         1. Authorize: Verify caller `caller_user_id` owns `recipient_device_id`.
         2. Read current delivery state for `(message_id, device_id)` from `delivery_repo_`.
         3. Idempotency check: if state is already `DELIVERED` or `READ`:
            - Return success immediately with `recorded_at` (idempotent no-op).
         4. State machine validation: verify valid transition (`DELIVERING -> DELIVERED` or `QUEUED -> DELIVERED` in case of direct fetch).
         5. Commit durable updates:
            - `delivery_repo_->record_delivery_ack(message_id, device_id, delivered_at)` on `delivery_state_by_message`.
            - `delivery_repo_->update_device_delivery_status` -> `DELIVERED`.
         6. Enqueue transactional outbox event:
            - `ConversationOutboxEventType::MessageDelivered`
            - Payload contains `message_id`, `recipient_device_id`, `recipient_user_id`, `delivered_at`.
   - In `src/messaging/service/messaging_service_impl.cpp`:
     - Implement `AcknowledgeDelivery` gRPC RPC:
       - Validate inputs (`message_id`, `recipient_device_id`, `delivered_at_unix_ms`).
       - Delegate to `delivery_pool_` and `DeliveryService`.
       - Map domain results to `v1::AcknowledgeDeliveryResponse`.
   - In `src/gateway/http/proxy/messaging_proxy_handler.cpp|hpp`:
     - Add route `POST /api/v1/messages/:id/ack`:
       - Extracts `x-user-id`, `x-device-id`, `message_id` from URL.
       - Dispatches via `messaging_client_->acknowledge_delivery(...)`.
       - Writes 200 OK JSON response with `message_id` and `state = DELIVERED`.
   - Unit tests in `tests/unit/messaging/delivery_service_test.cpp` and `tests/unit/gateway/messaging_proxy_ack_test.cpp`.
6. **Explicit Out-of-Scope**: Read receipts (MSG-008).
7. **Dependencies**: `MSG-007-T01`, `MSG-007-T04`.
8. **Files to Create/Modify**:
   - `src/messaging/service/delivery_service.hpp`
   - `src/messaging/service/delivery_service.cpp`
   - `src/messaging/service/messaging_service_impl.hpp`
   - `src/messaging/service/messaging_service_impl.cpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.hpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.cpp`
   - `tests/unit/messaging/delivery_service_test.cpp`
   - `tests/unit/gateway/messaging_proxy_ack_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-007-T06 — Durable Recovery Engine & Comprehensive E2E Online Delivery Test Suite

1. **Ticket ID**: `MSG-007-T06`
2. **Title**: Durable Delivery Recovery Engine & Comprehensive Online Delivery Integration Test Suite
3. **Objective**: Implement the startup and periodic crash-recovery engine that hydrates pending deliveries from ScyllaDB, and build an end-to-end integration test suite verifying all delivery invariants and failure scenarios.
4. **Architectural Purpose**: Guarantees that no delivery obligations are lost after service restart, worker crash, or ephemeral queue saturation, and proves compliance with ADR-007, ADR-009, and ADR-010.
5. **Scope**:
   - In `src/messaging/delivery/durable_delivery_recovery_service.hpp|cpp`:
     - Implement `DurableDeliveryRecoveryService`:
       - **Startup Recovery Scan**:
         - Queries `delivery_repo_->fetch_pending_for_device` across active devices.
         - Hydrates unacknowledged pending tasks into `BoundedDeliveryScheduler` up to capacity.
       - **Delayed Retry Poller / Sweeper**:
         - Periodically checks for records in `RETRY_WAIT` where `next_retry_at <= now`.
         - Re-enqueues ready retry tasks into the delivery scheduler.
       - **Expired Delivery Purger**:
         - Identifies tasks exceeding expiration timestamps and marks them `EXPIRED`.
   - In `tests/unit/messaging/online_delivery_pipeline_test.cpp`:
     - Comprehensive unit and integration test suite covering:
       1. **Successful Online Delivery**: End-to-end message submission -> outbox -> scheduler -> worker -> channel push -> client ACK -> `DELIVERED`.
       2. **Offline Recipient**: Message accepted, recipient offline; verified durable record preserved in ScyllaDB; recipient connects; delivery triggered.
       3. **Transient Failure & Backoff**: Channel returns transient network failure; verifies transition `DELIVERING -> RETRY_WAIT -> DELIVERING`; verifies delay conforms to exponential backoff with jitter.
       4. **Terminal Failure**: Revoked recipient device transitions immediately to `EXPIRED` without infinite retry.
       5. **Duplicate Delivery & Idempotent ACKs**: Duplicate delivery attempt received by client (deduplicated by `message_id`); duplicate `AcknowledgeDelivery` RPC succeeds idempotently without error.
       6. **Multi-Device Concurrent Delivery**: Single message addressed to Device A (online) and Device B (offline); Device A receives immediately; Device B remains pending.
       7. **Slow Recipient Fairness**: Device A has high latency / delays ACKs; Device B continues receiving messages with zero head-of-line blocking.
       8. **Worker Saturation & Backpressure**: Scheduler capacity saturated; excess items dropped from memory; verified zero data loss from ScyllaDB; recovery engine sweeps remaining tasks.
       9. **Crash Recovery**: Populate pending items, crash/reset in-memory scheduler, run recovery service; all pending items successfully hydrated and delivered.
       10. **Zero Plaintext Invariant**: Assert that no delivery worker logs, memory buffers, or error messages expose unencrypted plaintext.
   - Verify all existing regression tests pass.
6. **Explicit Out-of-Scope**: Kafka/RabbitMQ adapters.
7. **Dependencies**: `MSG-007-T01` through `MSG-007-T05`.
8. **Files to Create/Modify**:
   - `src/messaging/delivery/durable_delivery_recovery_service.hpp`
   - `src/messaging/delivery/durable_delivery_recovery_service.cpp`
   - `tests/unit/messaging/durable_delivery_recovery_service_test.cpp`
   - `tests/unit/messaging/online_delivery_pipeline_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

## 5. Summary Table: Tickets, Deliverables & Invariant Verification

| Ticket | Scope Summary | Key Deliverables | Verified Invariants |
| :--- | :--- | :--- | :--- |
| **MSG-007-T01** | Delivery Domain & Retry Engine | `DeliveryTask`, `DeliveryRetryPolicy`, decorrelated jitter formula, lifecycle guards | ADR-007 §12, §13 (bounded exponential backoff, jitter, canonical state machine) |
| **MSG-007-T02** | Device Connection Registry | `IDeviceDeliveryChannel`, `IDeviceConnectionRegistry`, thread-safe presence registry | ADR-007 §8, §9 (multi-device targeting, offline tracking, no sticky-session requirement) |
| **MSG-007-T03** | Bounded Delivery Scheduler | `BoundedDeliveryScheduler`, per-device fairness ring buffers, drop-to-durable backpressure | ADR-007 §17, ADR-010 §7 (bounded memory, head-of-line blocking prevention) |
| **MSG-007-T04** | DeliveryWorker & Outbox Consumer | `DeliveryWorker`, `OutboxDeliveryConsumer`, transient failure loop, retry delay scheduler | ADR-007 §6, §10, ADR-008 §2.1 (at-least-once push, zero plaintext, outbox integration) |
| **MSG-007-T05** | Delivery Acknowledgement & Scylla Commit | `DeliveryService`, `AcknowledgeDelivery` gRPC, Gateway REST `POST /messages/:id/ack` | ADR-007 §10, §11 (DELIVERED requires client ACK, idempotent receipts) |
| **MSG-007-T06** | Durable Recovery & E2E Test Suite | `DurableDeliveryRecoveryService`, crash recovery sweep, comprehensive 10-scenario test suite | ADR-007 §5, ADR-009 §2 (durable state authoritative, crash survival, no message loss) |

---

## 6. Implementation Order & Verification Gateways

To ensure zero regression and continuous integration correctness across Phase 2:
1. **Gate 1 (MSG-007-T01)**: Mathematical verification of jitter distribution and state machine transition rules. Unit tests must pass 100%.
2. **Gate 2 (MSG-007-T02)**: Multi-threaded registry safety under concurrent connect/disconnect bursts.
3. **Gate 3 (MSG-007-T03)**: Fairness benchmark: 1 stalled device with 1,000 pending items must not degrade throughput of 10 concurrent active devices.
4. **Gate 4 (MSG-007-T04)**: Outbox event fan-out verification and worker error isolation under network dropped packets.
5. **Gate 5 (MSG-007-T05)**: ScyllaDB delivery receipt consistency check; Gateway REST route verification.
6. **Gate 6 (MSG-007-T06)**: Simulated node crash recovery test: crash process, reboot, verify 100% of pending deliveries reach `DELIVERED` with zero message loss.
