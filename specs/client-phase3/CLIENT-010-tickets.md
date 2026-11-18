# CLIENT-010 Ticket Decomposition: Real-Time Delivery & Read Receipts

- **Milestone Card:** `CLIENT-010` — Real-Time Delivery & Read Receipts
- **Phase:** Desktop Client Phase 3
- **Branch:** `feature/client-010-realtime-delivery-and-read-receipts`
- **Owner:** Sergey
- **Dependencies:** `CLIENT-004` (Workspace UI), `CLIENT-009` (Direct & Group Messaging Engine, Sender Keys, `SqlCipherLocalStore`), `ADR-007` (Messaging Reliability & Durability), `ADR-008` (Security & Cryptographic Architecture), `proto/securecloud/messaging/v1/messaging.proto`

---

## 1. Executive Summary & Scope

`CLIENT-010` establishes the real-time event pipeline, monotonic delivery state machine, bounded exponential-backoff retry engine, and privacy-preserving read-receipt policy for the SecureCloud Desktop Client:

```text
┌─────────────────────────────┐     ┌─────────────────────────────┐     ┌─────────────────────────────┐
│  Gateway HTTPS REST/JSON    │     │  MessagingManager &         │     │  WorkspaceViewModel & QML   │
│  (MessagingProxyHandler +   │────▶│  DeliveryRetryEngine        │────▶│  (Live Delivery Ticks,      │
│   SyncManager Polling-to-   │     │  - Monotonic State Machine  │     │   Unread Badges, Settings   │
│   Event Dispatcher)         │◀────│  - Backoff + Jitter Retry   │◀────│   Read-Receipt Toggle)      │
└─────────────────────────────┘     │  - Idempotency Dedupe       │     └─────────────────────────────┘
                                    │  - Async Ack / Read Policy  │
                                    └──────────────┬──────────────┘
                                                   │
                                    ┌──────────────▼──────────────┐
                                    │  SqlCipherLocalStore        │
                                    │  (Encrypted State, Seq #,   │
                                    │   Idempotency Keys, Policy) │
                                    └─────────────────────────────┘
```

### Ticket Status Matrix

| Ticket | Title | Status | Target Scope |
|---|---|---|---|
| **CLIENT-010-T01** | Real-Time Event Models, Retry/Receipt Policy & `IGatewayClient` REST/Event Contracts | **Completed** | `RealtimeEvent`, `DeliveryAckEvent`, `ReadReceiptEvent`, `ReadReceiptPolicy`, `RetryPolicyConfig`, `IGatewayClient` REST endpoints (`ack`, `read`, `delivery-status`, `messages?since_sequence=`) & event subscription |
| **CLIENT-010-T02** | Monotonic Delivery State Machine, Sequence Tracking & Idempotent Deduplication | **Completed** | Monotonic `DeliveryState` transitions (`LocalPending -> Submitting -> Accepted -> Delivering -> Delivered -> Read`, `Failed`), `server_sequence_number` tracking, `idempotency_key` deduplication |
| **CLIENT-010-T03** | Exponential-Backoff Retry Engine with Mandatory Jitter & Expiration | **Completed** | `DeliveryRetryEngine`: bounded exponential backoff with jitter (`ADR-007 §13`), idempotent retry queue, deadline/attempt expiration to `DeliveryState::Failed` (`ADR-007 §14`) |
| **CLIENT-010-T04** | Asynchronous Delivery Acknowledgements & Privacy-Gated Read Receipts | **Completed** | Auto-dispatch `POST /api/v1/messages/:id/ack` on inbound decrypt+persist (`ADR-007 §11`), privacy-gated `POST .../read` on `mark_conversation_read`, inbound status/receipt handling |
| **CLIENT-010-T05** | `SyncManager` Polling-to-Event Dispatcher, `WorkspaceViewModel` Live Updates & Settings Toggle | **Completed** | `SyncManager` REST polling (`GET /api/v1/conversations/:id/messages`, `delivery-status`, `presence/batch`) -> queued `WorkspaceViewModel` updates, `readReceiptsEnabled` property + `SettingsPlaceholder.qml` toggle |
| **CLIENT-010-T06** | Real-Time Delivery, Retry & Read Receipt Integration Suite & Walkthrough Report | **Completed** | 5-scenario E2E integration suite (`realtime_delivery_and_receipts_integration_test.cpp`), 100% test/format/warning gate, `--smoke-test`, `walkthrough-client-010.md` |

---

## 2. Repository & Architecture Audit: What Already Exists vs. Net-New Scope

### Already Implemented (Baseline on `main` after `CLIENT-009`)
- **Domain States & Sequence Fields**:
  - `src/client/domain/delivery_state.hpp/.cpp` defines `DeliveryState` (`LocalPending`, `Submitting`, `Accepted`, `Delivering`, `Delivered`, `Read`, `Failed`) and string serialization.
  - `src/client/domain/message.hpp/.cpp` already stores `idempotency_key_` (`client_message_id()`), `server_sequence_number_`, and `delivery_state_` with JSON round-trip in `SqlCipherLocalStore`.
- **Proto Contracts (`proto/securecloud/messaging/v1/messaging.proto`)**:
  - Defines `DeliveryReceipt`, `AcknowledgeDeliveryRequest/Response`, `SendReadReceiptRequest/Response`, `GetMessageDeliveryStatusRequest/Response`, `SyncCursor`, and `UpdatePresenceRequest/Response`.
- **UI Delivery Rendering (`src/client/ui/qml/WorkspacePlaceholder.qml`)**:
  - Message bubbles already render icons and labels for `LocalPending`, `Submitting`, `Accepted`, `Delivered`, `Read`, and `Failed`, plus `Retry` / `Discard` actions for failed messages.
- **Manager Foundations**:
  - `MessagingManager` already provides `stage_outbound_message`, `retry_failed_message`, `update_message_delivery_state`, `discard_failed_message`, `mark_conversation_read`, `process_inbound_message`, and `process_inbound_group_message`.

### Net-New Scope Required by `CLIENT-010`
1. **No Receipt/Status/Poll-to-Event Contracts on `IGatewayClient`**: `IGatewayClient` currently has only `probe_gateway`, `submit_encrypted_message`, and `sync_messages`; it lacks REST wrappers for `POST /api/v1/messages/:id/ack`, `POST /api/v1/conversations/:cid/messages/:mid/read`, `GET .../delivery-status`, `GET /api/v1/conversations/:id/messages?since_sequence=...`, and event-dispatcher subscription (`subscribe_realtime_events`).
2. **No Monotonic Transition Guard or Inbound Deduplication**: `update_message_delivery_state` overwrites `delivery_state_` unconditionally without guarding against out-of-order regressions (e.g. `Read -> Delivered`), and inbound message processing does not deduplicate re-delivered `idempotency_key` / `message_id` packets (`ADR-007 §2`).
3. **No Automatic Exponential-Backoff Retry Engine**: Transient submission failures remain static without a jittered exponential-backoff retry queue (`ADR-007 §13`) or bounded expiration (`ADR-007 §14`).
4. **No Automatic Delivery ACKs or Read-Receipt Privacy Policy**: `MessagingManager` does not automatically emit transport delivery ACKs upon local persistence, nor does `mark_conversation_read` emit/suppress `SendReadReceipt` according to a user-configurable privacy setting.
5. **No REST Polling-to-Event Dispatcher or Settings Toggle**: `SyncManager` does not yet dispatch polled REST events (`messages`, `delivery-status`, `presence`) into `MessagingManager`/`WorkspaceViewModel` via `Qt::QueuedConnection`, and `SettingsPlaceholder.qml` lacks the `Read Receipts` privacy toggle.

---

## 3. Detailed Ticket Specifications (`CLIENT-010-T01` – `CLIENT-010-T06`)

### CLIENT-010-T01: Real-Time Event Models, Retry/Receipt Policy & `IGatewayClient` REST/Event Contracts
- **Component:** `src/client/domain/`, `src/client/application/interfaces/i_gateway_client.hpp`, `src/client/infrastructure/adapters/default_gateway_client.*`
- **Architectural Scope:**
  1. Define internal event structures (`InboundDirectEvent`, `InboundGroupEvent`, `InboundSenderKeyEvent`, `DeliveryAckEvent`, `ReadReceiptEvent`, `PresenceUpdateEvent`, wrapped in a `RealtimeEvent` variant/struct with `server_sequence_number`).
  2. Define `RetryPolicyConfig` (`max_attempts`, `initial_backoff_ms`, `max_backoff_ms`, `jitter_ratio`, `expiration_ttl`) and `ReadReceiptPolicy` (`send_read_receipts_enabled`, persisted under `ISecureStorage`).
  3. Extend `IGatewayClient` and `DefaultGatewayClient` (aligned with `ADR-004` HTTPS REST/JSON & `MessagingProxyHandler`) with:
     - `acknowledge_delivery(const domain::MessageId&, const domain::DeviceId&, int64_t delivered_at_ms)` (`POST /api/v1/messages/:id/ack`)
     - `send_read_receipt(const domain::ConversationId&, const domain::MessageId&, const domain::DeviceId&, int64_t read_at_ms)` (`POST /api/v1/conversations/:conversationId/messages/:messageId/read`)
     - `get_message_delivery_status(const domain::ConversationId&, const domain::MessageId&)` (`GET /api/v1/conversations/:conversationId/messages/:messageId/delivery-status`)
     - `fetch_conversation_messages(const domain::ConversationId&, const domain::DeviceId&, uint64_t since_sequence, std::size_t max_results)` (`GET /api/v1/conversations/:id/messages`)
     - `subscribe_realtime_events(RealtimeEventCallback)` / `unsubscribe_realtime_events()` and deterministic test/simulation event injection on `DefaultGatewayClient`.
- **Deliverables:** Updated `i_gateway_client.hpp`, `default_gateway_client.hpp/.cpp`, domain/policy models, unit tests.

### CLIENT-010-T02: Monotonic Delivery State Machine, Sequence Tracking & Idempotent Deduplication
- **Component:** `src/client/domain/delivery_state.*`, `src/client/application/managers/messaging_manager.*`
- **Architectural Scope:**
  1. Define monotonic state rank (`LocalPending < Submitting < Accepted < Delivering < Delivered < Read`, with `Failed` allowed from pre-delivery states and recoverable back to `Submitting` on retry).
  2. Enforce monotonic `update_message_delivery_state` (reject/ignore stale regressions such as `Read -> Delivered` or `Delivered -> Accepted`) and persist updated `server_sequence_number` in `ILocalStore`.
  3. Enforce `idempotency_key` / `message_id` deduplication on inbound `process_inbound_message` and `process_inbound_group_message` so `at-least-once` Gateway delivery produces `exactly-once` persisted UI messages (`ADR-007 §2`).
- **Deliverables:** Monotonic helper in `delivery_state.hpp/.cpp`, deduplication & sequence tracking in `MessagingManager`, unit tests.

### CLIENT-010-T03: Exponential-Backoff Retry Engine with Mandatory Jitter & Expiration
- **Component:** `src/client/application/managers/delivery_retry_engine.hpp/.cpp`, `MessagingManager`
- **Architectural Scope:**
  1. Implement `DeliveryRetryEngine` tracking pending/transiently-failed outbound messages with attempt count, next-retry timestamp, and expiration deadline.
  2. Compute bounded exponential backoff with mandatory randomized jitter (`ADR-007 §13`): `delay = min(max_backoff, base * 2^attempt) * (1 ± jitter_ratio)`.
  3. Re-submit queued messages idempotently via `MessagingManager` reusing the original `idempotency_key` (`ClientMessageId`).
  4. Transition messages exceeding `max_attempts` or `expiration_ttl` permanently to `DeliveryState::Failed` (`ADR-007 §14`) while preserving manual `retry_failed_message` / `discard_failed_message` recovery.
- **Deliverables:** `delivery_retry_engine.hpp/.cpp`, `MessagingManager` integration, unit tests verifying jittered backoff bounds, idempotent retry, and expiration.

### CLIENT-010-T04: Asynchronous Delivery Acknowledgements & Privacy-Gated Read Receipts
- **Component:** `src/client/application/managers/messaging_manager.*`
- **Architectural Scope:**
  1. Upon successful decryption and `ILocalStore` persistence of an inbound 1:1 or group message, automatically dispatch `gateway_.acknowledge_delivery(...)` asynchronously (separately from read receipts per `ADR-007 §11`).
  2. Persist and expose `set_read_receipts_enabled(bool)` / `read_receipts_enabled()` via `ISecureStorage`.
  3. In `mark_conversation_read(conversation_id, local_device_id)`: always clear local `unread_count` to `0`, and dispatch `gateway_.send_read_receipt(...)` for unread peer messages **only** when `read_receipts_enabled()` is `true`; suppress all outbound read receipts when `false`.
  4. Handle inbound `DeliveryAckEvent` and `ReadReceiptEvent` from the push stream to advance matching outbound messages to `Delivered` / `Read` monotonically.
- **Deliverables:** `MessagingManager` receipt dispatch & inbound handlers, unit tests for both enabled and privacy-suppressed modes.

### CLIENT-010-T05: `SyncManager` Polling-to-Event Dispatcher, `WorkspaceViewModel` Live Updates & Settings Toggle
- **Component:** `src/client/application/managers/sync_manager.*`, `src/client/ui/workspace_view_model.*`, `src/client/ui/qml/SettingsPlaceholder.qml`, `src/client/application/client_bootstrap.*`
- **Architectural Scope:**
  1. Wire `SyncManager` REST polling (`fetch_conversation_messages` via `since_sequence`, `get_message_delivery_status` for in-flight outbound messages, and presence batching) to emit `RealtimeEvent`s into `MessagingManager`, and marshal updates onto the Qt UI thread (`QMetaObject::invokeMethod(..., Qt::QueuedConnection)`) so incoming messages, live delivery ticks (`Accepted` -> `Delivered` -> `Read`), presence changes, and retry/failure updates reflect immediately in `WorkspaceViewModel` without QML polling.
  2. Expose `Q_PROPERTY(bool readReceiptsEnabled READ readReceiptsEnabled WRITE setReadReceiptsEnabled NOTIFY readReceiptsEnabledChanged)` on `WorkspaceViewModel`.
  3. Add a **Privacy & Read Receipts** toggle switch in `SettingsPlaceholder.qml` bound to `workspaceViewModel.readReceiptsEnabled`.
- **Deliverables:** Updated `sync_manager.hpp/.cpp`, `workspace_view_model.hpp/.cpp`, `SettingsPlaceholder.qml`, `client_bootstrap.cpp`, ViewModel tests.

### CLIENT-010-T06: Real-Time Delivery, Retry & Read Receipt Integration Suite & Walkthrough Report
- **Component:** `tests/unit/client/`, `docs/final-reports/`
- **Architectural Scope:**
  1. End-to-end integration suite (`tests/unit/client/realtime_delivery_and_receipts_integration_test.cpp`) covering 5 scenarios:
     - **Scenario 1**: Live push stream 1:1 & group delivery with real-time tick progression (`LocalPending -> Accepted -> Delivered -> Read`) without polling.
     - **Scenario 2**: Transient network failures triggering exponential-backoff retry with jitter + idempotent deduplication (zero duplicate messages).
     - **Scenario 3**: Out-of-order receipt & sequence monotonicity (`Read` never regresses to `Delivered`/`Accepted`).
     - **Scenario 4**: Read-receipt privacy toggle (`readReceiptsEnabled = false` suppresses `SendReadReceipt` while preserving `AcknowledgeDelivery` and local unread clearing).
     - **Scenario 5**: Retry expiration -> `Failed`, manual `retryMessage` / `discardFailedMessage`, and SQLCipher restart durability of delivery states & policy.
  2. Pass `100%` of `securecloud_client_foundation_test`, `0` compiler warnings (`-Werror`), `check-format`, and offscreen `--smoke-test`.
  3. Author `docs/final-reports/walkthrough-client-010.md` (including dedicated architecture sections on: (a) the REST polling-to-event-dispatcher MVP design vs. the post-MVP upgrade path to HTTP Long-Polling / SSE / WebSockets, (b) the complementary backend-vs-client responsibility split under `ADR-007 §2.8`, and (c) future enhancement: optional per-conversation read-receipt override policy) and mark `CLIENT-010-T01` – `CLIENT-010-T06` Completed.
- **Deliverables:** `realtime_delivery_and_receipts_integration_test.cpp`, `tests/unit/CMakeLists.txt`, `docs/final-reports/walkthrough-client-010.md`.

---

## 4. Implementation Rules & Non-Functional Requirements

1. **Boundary Between `CLIENT-010` and `CLIENT-011` / `CLIENT-012`**:
   - `CLIENT-010` owns real-time push event handling, monotonic delivery state transitions, bounded in-session retry with jitter, transport delivery ACKs, and privacy-gated read receipts.
   - 1 MiB AEAD chunked file streaming belongs to **`CLIENT-011`**.
   - Durable offline outbox persistence across full network outages, connectivity observers (`Offline`/`Syncing`/`Online`), and cursor-based catch-up sync (`GET /api/v1/sync?cursor=`) remain scoped to **`CLIENT-012`**.
2. **Zero Plaintext on Disk & Over Wire**:
   - Delivery ACKs and read receipts carry only opaque IDs (`message_id`, `conversation_id`, `device_id`, `timestamp_unix_ms`) — never message plaintext or user-identifying content.
3. **Zero Docker / External Daemon Dependency for Unit & Integration Gates**:
   - All `CLIENT-010` unit and integration tests run in-process with `DefaultGatewayClient`, `OpenSslCryptoProvider`, and `SqlCipherLocalStore`.
4. **Code Hygiene**:
   - Zero compiler warnings (`-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`) and `100%` `.clang-format` compliance.
