# CLIENT-010 Validation Walkthrough Report: Real-Time Delivery, Retry Backoff & Read Receipts

- **Card:** `CLIENT-010` (`CLIENT-010-T01` – `CLIENT-010-T06`)
- **Title:** Real-Time Delivery & Read Receipts
- **Phase:** Desktop Client Phase 3
- **Branch:** `feature/client-010-realtime-delivery-and-read-receipts`
- **Date:** 2026-11-18
- **Author:** Sergey / SecureCloud Engineering
- **Status:** Completed & Verified (`287 / 287` unit & integration tests passing across `80` test suites, `0` compiler warnings under `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`, `100%` `.clang-format` compliance across `1,032` C++ files, clean offscreen `--smoke-test`)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Ticket Delivery Matrix & File-by-File Inventory](#2-ticket-delivery-matrix--file-by-file-inventory)
3. [Transport Architecture: HTTPS REST/JSON Polling-to-Event Dispatcher & Post-MVP Upgrade Path](#3-transport-architecture-https-restjson-polling-to-event-dispatcher--post-mvp-upgrade-path)
4. [Complementary Backend-vs-Client Reliability & Retry Split (`ADR-007`)](#4-complementary-backend-vs-client-reliability--retry-split-adr-007)
5. [Domain Event & Policy Models + Gateway Contracts (`CLIENT-010-T01`)](#5-domain-event--policy-models--gateway-contracts-client-010-t01)
6. [Monotonic Delivery State Machine & Inbound Deduplication (`CLIENT-010-T02`)](#6-monotonic-delivery-state-machine--inbound-deduplication-client-010-t02)
7. [Exponential-Backoff Retry Engine with Mandatory Jitter (`CLIENT-010-T03`)](#7-exponential-backoff-retry-engine-with-mandatory-jitter-client-010-t03)
8. [Asynchronous Delivery ACKs, Privacy-Gated Read Receipts, Live UI & Future Enhancements (`CLIENT-010-T04` & `CLIENT-010-T05`)](#8-asynchronous-delivery-acks-privacy-gated-read-receipts-live-ui--future-enhancements-client-010-t04--client-010-t05)
9. [Complete Unit & Integration Test Catalog (`CLIENT-010-T06`)](#9-complete-unit--integration-test-catalog-client-010-t06)
10. [Verbatim Verification Outputs & Reproducible Commands](#10-verbatim-verification-outputs--reproducible-commands)

---

## 1. Executive Summary

`CLIENT-010` completes the **Real-Time Delivery & Read Receipts** milestone for the native **SecureCloud Desktop Client** (`securecloud-client`), building directly on `CLIENT-009` (Direct & Group Messaging Engine, Signal Sender Keys `SCG` v1, and native `SqlCipherLocalStore` encrypted persistence).

Prior to `CLIENT-010`, the client could encrypt, persist, and submit 1:1 and group messages via `MessagingManager`, and the QML UI (`WorkspacePlaceholder.qml`) already had visual tick renderers for `LocalPending`, `Submitting`, `Accepted`, `Delivered`, `Read`, and `Failed`. However, the client lacked:
- Gateway contracts for transport delivery acknowledgements (`ack`), read receipts (`read`), delivery status queries (`delivery-status`), incremental message polling (`since_sequence`), and event subscriptions;
- A monotonic delivery state machine to prevent out-of-order status regressions;
- Pre-decryption inbound deduplication for at-least-once Gateway deliveries;
- An automatic exponential-backoff retry queue with randomized jitter for transient Client → Gateway submission outages;
- Separation between always-on transport delivery ACKs and privacy-gated read receipts;
- Live `Qt::QueuedConnection` event dispatch into `WorkspaceViewModel` and a user-facing Read Receipts privacy toggle in `SettingsPlaceholder.qml`.

`CLIENT-010` resolves every one of these gaps across six structured tickets (`CLIENT-010-T01` through `CLIENT-010-T06`), while preserving strict alignment with:
- **`ADR-004` (Inter-Process Communication Model)**: Client ↔ Gateway transport remains strictly **HTTPS + REST/JSON**, matching the implemented `MessagingProxyHandler` routes on the Gateway without inventing a non-existent WebSocket or client-facing gRPC server.
- **`ADR-007` (Messaging Reliability & Durability)**: Implements the client side of **durable persistence + at-least-once delivery + idempotency**, bounded exponential backoff with mandatory jitter, and strict separation of delivery acknowledgement from read receipts.
- **`ADR-008` (Security & Cryptographic Architecture)**: Zero plaintext on disk (`SqlCipherLocalStore`) and zero plaintext in delivery ACKs / read receipts (only opaque IDs and timestamps cross the wire).

---

## 2. Ticket Delivery Matrix & File-by-File Inventory

### 2.1 Ticket Delivery Matrix

| Ticket | Title | Commit | Status | Key Deliverables |
|---|---|---|---|---|
| **CLIENT-010-T01** | Real-Time Event Models, Retry/Receipt Policy & `IGatewayClient` REST/Event Contracts | `4856280` | Completed | `realtime_events.hpp`, `IGatewayClient` & `DefaultGatewayClient` receipt/status/poll/subscription APIs, `MockGatewayClient`, `realtime_gateway_contracts_test.cpp` |
| **CLIENT-010-T02** | Monotonic Delivery State Machine, Sequence Tracking & Idempotent Deduplication | `af6da97` | Completed | `delivery_state_rank()`, `can_transition_delivery_state()`, `update_message_delivery_state()`, `persist_inbound_message()`, `process_inbound_realtime_event()`, `delivery_state_and_dedupe_test.cpp` |
| **CLIENT-010-T03** | Exponential-Backoff Retry Engine with Mandatory Jitter & Expiration | `c024755` | Completed | `DeliveryRetryEngine`, `MessagingManager::stage_outbound_message` transient network queueing, `process_retry_queue()`, `set_simulated_submission_failure()`, `delivery_retry_engine_test.cpp` |
| **CLIENT-010-T04** | Asynchronous Delivery Acknowledgements & Privacy-Gated Read Receipts | `f2a899b` | Completed | `ISecureStorage`-persisted `ReadReceiptPolicy`, auto `acknowledge_delivery` on inbound decrypt+persist, privacy-gated `mark_conversation_read()`, `ClientBootstrap` `local_device_id` wiring, `delivery_ack_and_read_receipt_test.cpp` |
| **CLIENT-010-T05** | `SyncManager` Polling-to-Event Dispatcher, `WorkspaceViewModel` Live Updates & Settings Toggle | `a5d727b` | Completed | `SyncManager::poll_realtime_updates()`, `WorkspaceViewModel` `Qt::QueuedConnection` event handling, `sendMessage()` authoritative ID/state alignment, `readReceiptsEnabled` `Q_PROPERTY`, `SettingsPlaceholder.qml` `readReceiptsSwitch`, `workspace_view_model_realtime_test.cpp` |
| **CLIENT-010-T06** | Real-Time Delivery, Retry & Read Receipt Integration Suite & Walkthrough Report | Pending T06 commit | Completed | `realtime_delivery_and_receipts_integration_test.cpp` (Scenarios 1–5), `walkthrough-client-010.md`, `CLIENT-010-tickets.md` |

### 2.2 Complete File Inventory

#### Production Files Created
1. `src/client/domain/realtime_events.hpp` — Defines `RealtimeEventType`, `DeliveryAckRecord`, `ReadReceiptRecord`, `MessageDeliveryStatusInfo`, `RealtimeEvent`, `ConversationMessagesPage`, `RetryPolicyConfig`, and `ReadReceiptPolicy`.
2. `src/client/application/managers/delivery_retry_engine.hpp` — Declares `RetryQueueEntry` and `DeliveryRetryEngine` (thread-safe exponential-backoff + jitter retry queue).
3. `src/client/application/managers/delivery_retry_engine.cpp` — Implements `compute_backoff()`, `enqueue()`, `remove()`, `pending_count()`, and `process_due()`.

#### Production Files Modified
1. `src/client/CMakeLists.txt` — Registers `application/managers/delivery_retry_engine.cpp` in `securecloud_client_app`.
2. `src/client/domain/delivery_state.hpp` — Declares `delivery_state_rank()` and `can_transition_delivery_state()`.
3. `src/client/domain/delivery_state.cpp` — Implements monotonic rank mapping and transition rules.
4. `src/client/application/interfaces/i_gateway_client.hpp` — Adds `RealtimeEventHandler` and virtual methods `acknowledge_delivery`, `send_read_receipt`, `get_message_delivery_status`, `fetch_conversation_messages`, `subscribe_realtime_events`, and `unsubscribe_realtime_events`.
5. `src/client/infrastructure/adapters/default_gateway_client.hpp` — Declares overrides, thread-safe subscriber map, receipt inspection buffers, and simulation hooks (`emit_realtime_event`, `set_simulated_delivery_status`, `set_simulated_conversation_messages`, `set_simulated_submission_failure`).
6. `src/client/infrastructure/adapters/default_gateway_client.cpp` — Implements all new `IGatewayClient` methods and simulation hooks.
7. `src/client/application/managers/messaging_manager.hpp` — Adds `DeliveryRetryEngine`, `local_device_id_`, `read_receipt_policy_`, `process_inbound_realtime_event()`, `process_retry_queue()`, `set_read_receipts_enabled()`, `read_receipts_enabled()`, and updated `update_message_delivery_state()` / `mark_conversation_read()`.
8. `src/client/application/managers/messaging_manager.cpp` — Implements monotonic delivery state updates, pre-decryption deduplication, transient network queueing, retry processing, automatic delivery ACKs, and privacy-gated read receipts.
9. `src/client/application/managers/sync_manager.hpp` — Adds `MessagingManager*`, `conversation_cursors_`, `poll_realtime_updates()`, and `conversation_cursor()`.
10. `src/client/application/managers/sync_manager.cpp` — Implements `poll_realtime_updates()` (retry driving, incremental `since_sequence` message polling, and in-flight delivery-status polling).
11. `src/client/application/client_bootstrap.cpp` — Wires `sync_manager_->set_messaging_manager(messaging_manager_.get())` and `messaging_manager_->set_local_device_id(device_id)`.
12. `src/client/ui/workspace_view_model.hpp` — Adds `readReceiptsEnabled` `Q_PROPERTY`, `~WorkspaceViewModel()`, `handleRealtimeEvent()`, and `realtime_sub_id_`.
13. `src/client/ui/workspace_view_model.cpp` — Subscribes to `IGatewayClient` realtime events with `Qt::QueuedConnection`, unsubscribes on destruction, updates `sendMessage()` to use authoritative `MessagingManager` IDs/states, forwards `localUserId()` + `local_device_id()` in `selectConversation()`, and implements `readReceiptsEnabled` accessors.
14. `src/client/ui/qml/SettingsPlaceholder.qml` — Adds the **Send Read Receipts** `Switch` (`objectName: "readReceiptsSwitch"`) bound to `wvm.readReceiptsEnabled`.

#### Test & Specification Files Created / Modified
1. `tests/unit/client/client_domain_test.cpp` — Updates `MockGatewayClient` with overrides for the new `IGatewayClient` contract methods.
2. `tests/unit/client/realtime_gateway_contracts_test.cpp` — 4 unit tests for `CLIENT-010-T01`.
3. `tests/unit/client/delivery_state_and_dedupe_test.cpp` — 3 unit tests for `CLIENT-010-T02`.
4. `tests/unit/client/delivery_retry_engine_test.cpp` — 3 unit tests for `CLIENT-010-T03`.
5. `tests/unit/client/delivery_ack_and_read_receipt_test.cpp` — 3 unit tests for `CLIENT-010-T04`.
6. `tests/unit/client/workspace_view_model_realtime_test.cpp` — 3 unit tests for `CLIENT-010-T05`.
7. `tests/unit/client/realtime_delivery_and_receipts_integration_test.cpp` — 5 end-to-end multi-workstation SQLCipher integration scenarios for `CLIENT-010-T06`.
8. `tests/unit/CMakeLists.txt` — Registers all 6 new test files in `securecloud_client_foundation_test`.
9. `specs/client-phase3/CLIENT-010-tickets.md` — Full ticket decomposition and status matrix (`T01`–`T06` Completed).
10. `docs/final-reports/walkthrough-client-010.md` — This validation walkthrough report.

---

## 3. Transport Architecture: HTTPS REST/JSON Polling-to-Event Dispatcher & Post-MVP Upgrade Path

### 3.1 Alignment with Implemented Gateway (`ADR-004` & `MessagingProxyHandler`)
Early roadmap notes in `docs/planning/initial-backlog.md` mentioned a *"Bidirectional WebSocket / gRPC streaming client"*. However, auditing the actual implemented backend (`src/gateway/` and `docs/adr/adr-004-inter-process-communication-model.md`) confirmed that:
- **External Client ↔ Gateway** is strictly **HTTPS + REST/JSON** served by `cpp-httplib`. There is **no WebSocket server** and **no client-facing gRPC endpoint** on the Gateway.
- **Internal Gateway ↔ Messaging** uses **gRPC + Protobuf** (`MessagingProxyHandler` → `MessagingServiceClient` → `MessagingService` defined in `proto/securecloud/messaging/v1/messaging.proto`).

`src/gateway/http/proxy/messaging_proxy_handler.cpp` already exposes every REST route needed by `CLIENT-010`:

| Client Operation | Gateway REST Route (`MessagingProxyHandler`) | Downstream gRPC RPC |
|---|---|---|
| Submit encrypted message | `POST /api/v1/messages` (alias `/api/v1/messages/send`) | `MessagingService.SendMessage` |
| Send transport delivery ACK | `POST /api/v1/messages/:id/ack` | `MessagingService.AcknowledgeDelivery` |
| Send read receipt | `POST /api/v1/conversations/:conversationId/messages/:messageId/read` (alias `/api/v1/messages/:id/read`) | `MessagingService.SendReadReceipt` |
| Query message delivery status | `GET /api/v1/conversations/:conversationId/messages/:messageId/delivery-status` (alias `/api/v1/messages/:id/delivery-status`) | `MessagingService.GetMessageDeliveryStatus` |
| Fetch incremental messages | `GET /api/v1/conversations/:id/messages` (`since_sequence`, `max_results`) | `MessagingService.GetMessages` |
| Get / update device cursor | `GET` / `PUT /api/v1/devices/:deviceId/cursor` | `GetSyncCursor` / `UpdateSyncCursor` |
| Update / batch query presence | `PUT /api/v1/presence/me`, `POST /api/v1/presence/batch` | `UpdatePresence` / `BatchGetPresence` |

### 3.2 Polling-to-Event-Dispatcher Flow (`SyncManager` → `MessagingManager` → `WorkspaceViewModel`)
Rather than leaking HTTP polling into QML or `WorkspaceViewModel`, `CLIENT-010` places polling strictly inside `SyncManager::poll_realtime_updates(local_device_id)`:

```text
  SyncManager::poll_realtime_updates(local_device_id)
     │
     ├─► 1. messaging_manager_->process_retry_queue()
     │        └─ Re-submits due Client->Gateway requests with same idempotency_key
     │
     ├─► 2. For each conversation:
     │        ├─ gateway_.fetch_conversation_messages(cid, local_device_id, since_seq, 50)
     │        │     └─ For each event: messaging_manager_->process_inbound_realtime_event(ev)
     │        │     └─ Advance conversation_cursors_[cid] = page.latest_sequence
     │        │
     │        └─ For recent in-flight messages (Accepted / Delivering / Delivered):
     │              └─ gateway_.get_message_delivery_status(cid, mid)
     │                    └─ Monotonic update_message_delivery_state(cid, mid, state, seq)
     │
     └─► 3. IGatewayClient::subscribe_realtime_events -> WorkspaceViewModel
              └─ QMetaObject::invokeMethod(..., Qt::QueuedConnection)
                    └─ Updates activeMessages() / conversations() / unread badges on UI thread
```

This keeps the UI layer **100% reactive and event-driven**: QML never polls, and `WorkspaceViewModel` only reacts to `RealtimeEvent` callbacks marshaled safely onto the Qt main thread.

### 3.3 Efficiency, Scalability Limits & Post-MVP Upgrade Path (SSE / WebSockets / Long-Polling)
- **Why REST Polling Works Well for MVP**:
  1. **Zero Gateway Rework**: Reuses existing authenticated `cpp-httplib` REST routes (`ADR-004`).
  2. **Incremental Bandwidth**: Passing `since_sequence` returns only deltas after `conversation_cursors_[cid]`, so idle polls carry empty event lists.
  3. **Scoped Status Checks**: Delivery status queries run only for in-flight outbound messages (`Accepted`, `Delivering`, `Delivered`), never for historical `Read` or `Failed` messages.
- **Scalability Limits at High Concurrency**:
  1. **Latency vs. Idle QPS Trade-Off**: Polling every `2–5 s` keeps load modest for tens or hundreds of active workstations, at the cost of `1–5 s` tick/message latency. At `10,000+` concurrent online devices, even a `2 s` poll generates `5,000+` idle QPS across Gateway → Messaging → ScyllaDB with zero message traffic.
  2. **Per-Conversation Fan-Out**: Polling each conversation individually scales linearly with active conversation count unless consolidated into a single device-level sync endpoint (`SyncDeviceMessages`).
- **Recommended Post-MVP Upgrade Path**:
  - **Phase A (Lowest Friction on `cpp-httplib`)**: Add **HTTP Long-Polling** or **Server-Sent Events (`GET /api/v1/events/stream`)** on the Gateway that pushes lightweight wake-up/receipt notifications (`conversation_id`, `latest_sequence`, `DeliveryReceipt`) whenever Messaging publishes an outbox event.
  - **Phase B (Full Bidirectional Push)**: Upgrade to **WebSockets** if sub-100 ms typing indicators or high-frequency presence streams are introduced.
  - **Zero Client Rewrite**: Because `CLIENT-010` abstracts event delivery behind `IGatewayClient::subscribe_realtime_events`, replacing the `SyncManager` poll loop with an SSE or WebSocket listener requires **zero changes** to `MessagingManager`, `DeliveryRetryEngine`, `SqlCipherLocalStore`, or `WorkspaceViewModel`.

---

## 4. Complementary Backend-vs-Client Reliability & Retry Split (`ADR-007`)

A core architectural invariant of `CLIENT-010` is that **the client does not duplicate backend responsibilities**; instead, the client and backend enforce complementary halves of the `ADR-007` reliability contract.

### 4.1 Sequence Assignment vs. Inbound At-Least-Once Deduplication (`ADR-007 §2.7–2.8`)
- **What the Backend Owns**:
  - Assigning authoritative, monotonic `server_sequence_number` values (`ADR-007 §6`, `§15`).
  - Validating outbound `idempotency_key` (`client_idempotency_token`) on `POST /api/v1/messages` so retried submissions never create duplicate logical messages (`ADR-007 §7`).
  - Persisting authoritative delivery state in ScyllaDB (`ADR-007 §2.1`).
- **Why the Client Still Needs Complementary Guards (`ADR-007 §2.8`)**:
  `ADR-007 §2` explicitly specifies:
  > *"7. Delivery uses **at-least-once semantics**.
  > 8. The recipient client must be capable of detecting duplicate message delivery."*
  Consider what happens when a recipient client polls `GET /api/v1/conversations/:id/messages?since_sequence=N`, decrypts an inbound message, and persists it to `SqlCipherLocalStore`, **but the subsequent `POST /api/v1/messages/:id/ack` or cursor update fails due to a transient network drop**. On the next poll, the Gateway re-delivers that exact same `message_id` and `server_sequence_number`.
  - Without **pre-decryption client-side deduplication** by `message_id` in `MessagingManager::process_inbound_realtime_event`, the client would attempt to Double-Ratchet-decrypt an already-consumed ciphertext (which fails because the one-time message key was deleted after the first decryption!) or insert duplicate bubbles and double-increment `unread_count`.
  - With pre-decryption deduplication, `MessagingManager` detects the already-persisted `message_id`, returns the existing `Message` cleanly without touching `unread_count`, and still re-dispatches the transport `acknowledge_delivery` so the server can close the loop.
- **Monotonic UI State Guard**:
  If a slower HTTP `get_message_delivery_status` response (`Accepted`) resolves *after* a `ReadReceipt` (`Read`) has already been processed, `can_transition_delivery_state` prevents the UI delivery tick from regressing backwards.

### 4.2 Two-Hop Retry Boundary (Client → Gateway vs. Gateway → Recipient)
```text
  [Sender Client] ──(Hop 1: DeliveryRetryEngine)──► [Gateway / Messaging] ──(Hop 2: Backend Retry)──► [Recipient Device]
                    Retries ONLY while LocalPending                        Retries AFTER Accepted (offline devices,
                    Uses exponential backoff + jitter                      outbox events, downstream delivery)
                    Preserves same idempotency_key
```

- **Hop 1 (`DeliveryRetryEngine`, Client-Side)**: Covers **only** failures occurring **before `Accepted`** (e.g., sender Wi-Fi drop, TLS handshake timeout, or Gateway `503` during `POST /api/v1/messages`). Because the backend never received the request, backend retry cannot help. Once `submit_encrypted_message` succeeds (`Accepted`), the entry is immediately removed from `DeliveryRetryEngine`.
- **Hop 2 (Backend Retry)**: Once `Accepted`, the backend Messaging service durably owns retrying delivery to offline/unreachable recipient devices.

---

## 5. Domain Event & Policy Models + Gateway Contracts (`CLIENT-010-T01`)

### 5.1 Domain Models (`src/client/domain/realtime_events.hpp`)
- **`RealtimeEventType`**:
  - `InboundDirectMessage`
  - `InboundGroupMessage`
  - `InboundSenderKeyDistribution`
  - `DeliveryAck`
  - `ReadReceipt`
  - `PresenceUpdate`
- **`RealtimeEvent`**: Carries `type`, `server_sequence_number`, `timestamp_ms`, `conversation_id`, `message_id`, `actor_user_id`, `actor_device_id`, `priority`, `direct_payload` (`std::optional<crypto::PerDeviceDeliveryPayload>`), `group_envelope_bytes` (`std::optional<std::vector<uint8_t>>`), `sender_key_distribution` (`std::optional<crypto::SenderKeyDistributionMessage>`), and `presence_status`.
- **`DeliveryAckRecord` & `ReadReceiptRecord`**: Transport-level records containing only opaque IDs (`message_id`, `conversation_id`, `recipient_device_id` / `reader_device_id`) and millisecond timestamps — zero plaintext or user-identifying metadata.
- **`MessageDeliveryStatusInfo`**: Represents server-reported status (`message_id`, `delivery_state`, `server_sequence_number`, `updated_at_ms`).
- **`ConversationMessagesPage`**: Represents paginated incremental fetch results (`events`, `has_more`, `latest_sequence`).
- **`RetryPolicyConfig`**:
  - `max_attempts{5}`
  - `initial_backoff{500 ms}`
  - `max_backoff{30000 ms}`
  - `jitter_ratio{0.25}`
  - `expiration_ttl{24 hours}`
- **`ReadReceiptPolicy`**:
  - `kStorageKey = "messaging.privacy.send_read_receipts"`
  - `bool send_read_receipts_enabled{true}`

### 5.2 `IGatewayClient` & `DefaultGatewayClient` Extensions
`IGatewayClient` (`src/client/application/interfaces/i_gateway_client.hpp`) defines:
- `acknowledge_delivery(message_id, recipient_device_id, delivered_at_ms)` → `ClientResult<DeliveryState>`
- `send_read_receipt(conversation_id, message_id, reader_device_id, read_at_ms)` → `ClientResult<DeliveryState>`
- `get_message_delivery_status(conversation_id, message_id)` → `ClientResult<MessageDeliveryStatusInfo>`
- `fetch_conversation_messages(conversation_id, recipient_device_id, since_sequence, max_results = 50)` → `ClientResult<ConversationMessagesPage>`
- `subscribe_realtime_events(RealtimeEventHandler)` → `uint64_t` subscription ID
- `unsubscribe_realtime_events(uint64_t subscription_id)` → `void`

`DefaultGatewayClient` (`src/client/infrastructure/adapters/default_gateway_client.hpp/.cpp`) implements these methods with thread-safe subscriber management (`std::mutex` + copying handlers before invocation to prevent deadlocks if a callback unsubscribes) and deterministic test hooks:
- `emit_realtime_event(const RealtimeEvent&)`
- `set_simulated_delivery_status(const MessageId&, MessageDeliveryStatusInfo)`
- `set_simulated_conversation_messages(const ConversationId&, std::vector<RealtimeEvent>)`
- `set_simulated_submission_failure(bool fail, std::string error_message)` (isolating `submit_encrypted_message` outages from directory/prekey lookups)
- `sent_delivery_acks()`, `sent_read_receipts()`, `clear_sent_receipts()`

---

## 6. Monotonic Delivery State Machine & Inbound Deduplication (`CLIENT-010-T02`)

### 6.1 Monotonic Rank & Transition Rules (`src/client/domain/delivery_state.hpp/.cpp`)
`delivery_state_rank(DeliveryState)` assigns strict progression ranks:

| `DeliveryState` | Rank | Meaning |
|---|---|---|
| `LocalPending` | `0` | Staged locally / queued in `DeliveryRetryEngine` |
| `Submitting` | `1` | In-flight HTTP submission to Gateway |
| `Accepted` | `2` | Durably persisted by Gateway / Messaging service |
| `Delivering` | `3` | Queued/in-transit to recipient device(s) |
| `Delivered` | `4` | Recipient device decrypted, persisted, and ACKed |
| `Read` | `5` | Recipient opened/read conversation (when receipts enabled) |
| `Failed` | `-1` | Terminal pre-delivery failure (recoverable via manual retry) |

`can_transition_delivery_state(current, next)` enforces:
1. Idempotent self-transitions (`current == next`) are always allowed.
2. Recovery from `Failed` is allowed only to `Submitting` or `LocalPending` (never jumping straight to `Delivered` or `Read`).
3. Transitions to `Failed` are allowed only from pre-delivery states (`current != Delivered && current != Read`).
4. All other transitions require `delivery_state_rank(next) >= delivery_state_rank(current)`.

### 6.2 `MessagingManager::update_message_delivery_state` & `process_inbound_realtime_event`
- **`update_message_delivery_state(conversation_id, message_id, new_state, server_sequence_number = 0)`**:
  - Advances `delivery_state_` only when `can_transition_delivery_state(msg.delivery_state(), new_state)` is `true` and `new_state != msg.delivery_state()`.
  - Advances `server_sequence_number_` monotonically (`server_sequence_number > msg.server_sequence_number()`).
  - Avoids unnecessary `ILocalStore::update_message` writes when neither field changed.
- **`process_inbound_realtime_event(const domain::RealtimeEvent&)`**:
  - **`InboundDirectMessage` / `InboundGroupMessage`**:
    1. Validates required fields and checks `local_store_.get_message(event.conversation_id, event.message_id)` **before** any cryptographic operation. If found, dispatches a transport ACK (in case the previous ACK was lost) and returns the existing `Message` without re-decrypting or incrementing `unread_count`.
    2. Checks `ADR-008` blocked-sender guard (`sender_contact.value().is_blocked()`).
    3. Decrypts via `RatchetSessionManager` (1:1) or `SenderKeyEngine` (group `SCG` v1), persists via shared helper `persist_inbound_message(domain::Message)`, updates conversation `last_activity_at` and `unread_count`, and dispatches transport ACK.
  - **`InboundSenderKeyDistribution`**: Delegates to `process_inbound_sender_key_distribution(...)`.
  - **`DeliveryAck` / `ReadReceipt`**: Calls `update_message_delivery_state(..., DeliveryState::Delivered / Read, event.server_sequence_number)`.
  - **`PresenceUpdate`**: Handled cleanly as a no-op at the messaging persistence layer (propagated to `WorkspaceViewModel`).

---

## 7. Exponential-Backoff Retry Engine with Mandatory Jitter (`CLIENT-010-T03`)

### 7.1 `DeliveryRetryEngine` Design (`src/client/application/managers/delivery_retry_engine.hpp/.cpp`)
`DeliveryRetryEngine` manages a thread-safe (`std::mutex`) queue of `RetryQueueEntry` items:
- **Backoff Formula (`ADR-007 §13`)**:
  $$\text{base\_delay} = \min\left(\text{max\_backoff},\; \text{initial\_backoff} \cdot 2^{\text{attempt}-1}\right)$$
  $$\text{delay} = \max\left(1\text{ ms},\; \text{llround}\left(\text{base\_delay} \cdot \mathcal{U}(1 - j,\; 1 + j)\right)\right)$$
  where $j = \text{clamp}(\text{jitter\_ratio}, 0.0, 0.95)$ sampled via `std::mt19937_64` seeded from `std::random_device`.
- **Expiration (`ADR-007 §14`)**:
  When `now >= entry.expires_at`, `entry.attempt_count >= config_.max_attempts`, or a non-network permanent error (`Validation` / `Crypto` / `Authentication`) occurs during retry, `DeliveryRetryEngine::process_due(...)` removes the entry and invokes `expire_fn(conversation_id, message_id)` to transition the message to `DeliveryState::Failed`.
- **Idempotency Preservation**:
  Each queued `RetryQueueEntry` stores the already-encrypted `FanOutSubmissionRequest` with the original `idempotency_key`. Retries never re-advance the Double Ratchet or Sender Key chain and never generate a new `idempotency_key`.

### 7.2 `MessagingManager` Retry Integration
- In `stage_outbound_message`:
  - If `gateway_.submit_encrypted_message(...)` returns a `ClientErrorCategory::Network` error (for either 1:1 or group submissions), `MessagingManager` persists the message in `DeliveryState::LocalPending` (preserving `idempotency_key`), enqueues the `FanOutSubmissionRequest` in `retry_engine_`, and returns `ClientResult<domain::Message>::ok(msg)`.
  - Non-network errors (e.g., `ADR-008` `KeyChanged`, blocked recipient, validation, or crypto failures) fail immediately without queueing.
- `process_retry_queue(now)`: Drives `retry_engine_.process_due(...)`; on `submit_encrypted_message` success, transitions the matching `LocalPending` message to `DeliveryState::Accepted`.
- `discard_failed_message(cid, mid)`: Removes any matching entry from `retry_engine_` alongside marking the message `Failed`.

---

## 8. Asynchronous Delivery ACKs, Privacy-Gated Read Receipts, Live UI & Future Enhancements (`CLIENT-010-T04` & `CLIENT-010-T05`)

### 8.1 Transport ACKs vs. Privacy-Gated Read Receipts (`ADR-007 §11`)
- **Transport Delivery ACK (`dispatch_delivery_ack_if_configured`)**:
  - Wired with `local_device_id_` via `ClientBootstrap::initialize_ratchet_session_manager(...)` (or `MessagingManager::set_local_device_id(...)`).
  - Fires automatically whenever an inbound 1:1 or group message is decrypted and persisted (including idempotent re-deliveries), independent of the user's read-receipt privacy setting.
- **Privacy-Gated Read Receipts (`mark_conversation_read`)**:
  - `ReadReceiptPolicy` (`messaging.privacy.send_read_receipts`) is hydrated from `ISecureStorage` in `MessagingManager`'s constructor and `set_secure_storage()`, and persisted immediately on `set_read_receipts_enabled(bool)`.
  - Calling `mark_conversation_read(conversation_id, local_user_id, reader_device_id)` **always** clears `conv.unread_count` to `0` and persists the conversation.
  - Only when `read_receipts_enabled()` is `true` and an effective device ID is available does it transition unread peer messages (`sender_user_id != local_user_id`) to `DeliveryState::Read` and dispatch `gateway_.send_read_receipt(...)`. When `false`, all outbound read receipts are suppressed.

### 8.2 `WorkspaceViewModel` Live Updates & `SettingsPlaceholder.qml` Toggle
- **Thread-Safe Qt Queued Dispatch**:
  - `WorkspaceViewModel` subscribes to `gateway().subscribe_realtime_events(...)` in its constructor (guarded by `QPointer<WorkspaceViewModel>`) and unsubscribes cleanly in `~WorkspaceViewModel()`.
  - Incoming events are marshaled onto the Qt main thread via `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` into `handleRealtimeEvent(const domain::RealtimeEvent&)`:
    - `DeliveryAck` / `ReadReceipt`: Updates the matching `MessageEntry::deliveryState` monotonically and emits `activeMessagesChanged()` if viewing that conversation.
    - `InboundDirectMessage` / `InboundGroupMessage`: Appends new decrypted messages to `messages_`, updates `lastMessagePreview` and `unreadCount`, and emits `conversationsChanged()` / `activeMessagesChanged()`.
    - `PresenceUpdate`: Updates peer presence status across `conversations_` and emits `conversationsChanged()`, `selectedConversationChanged()`, and `contactsChanged()`.
- **Authoritative Outbound Message ID Alignment**:
  - `WorkspaceViewModel::sendMessage()` now stores the authoritative `message_id()`, `idempotency_key()`, and initial `delivery_state()` (`Accepted` or `LocalPending`) returned by `MessagingManager::stage_outbound_message()`, ensuring real-time `DeliveryAck` / `ReadReceipt` events match UI `MessageEntry` rows by `messageId`.
- **Settings Privacy Toggle (`SettingsPlaceholder.qml`)**:
  - `WorkspaceViewModel` exposes `Q_PROPERTY(bool readReceiptsEnabled READ readReceiptsEnabled WRITE setReadReceiptsEnabled NOTIFY readReceiptsEnabledChanged)`.
  - `SettingsPlaceholder.qml` adds a **Send Read Receipts** `Switch` (`objectName: "readReceiptsSwitch"`) inside the Preferences card with explanatory copy: *"When disabled, other participants will not see when you have read their messages."*

### 8.3 Future Enhancement: Per-Conversation Read-Receipt Override Policy
In `CLIENT-010`, `ReadReceiptPolicy` is a **global user setting** in Settings (matching `docs/planning/initial-backlog.md` and Signal's global Read Receipts toggle). As a clean future enhancement:
- Add `std::optional<bool> read_receipts_override` to `domain::Conversation` (serialized in `SqlCipherLocalStore` JSON).
- Evaluate `conv.read_receipts_override().value_or(read_receipt_policy_.send_read_receipts_enabled)` inside `MessagingManager::mark_conversation_read(...)`.
- Expose a per-conversation toggle in Zone 4 (Conversation Inspector) so users can selectively suppress or allow read receipts for specific contacts or groups while keeping a global default.

---

## 9. Complete Unit & Integration Test Catalog (`CLIENT-010-T06`)

### 9.1 Unit Tests Added Across `T01`–`T05` (`16` Tests)
1. **`RealtimeGatewayContractsTest`** (`tests/unit/client/realtime_gateway_contracts_test.cpp`, 4 tests):
   - `AcknowledgeDeliveryAndReadReceiptRecordAndValidate`
   - `FetchConversationMessagesRespectsSinceSequenceAndPagination`
   - `DeliveryStatusAndRealtimeSubscriptionLifecycle`
   - `DefaultPolicyConfigsAreValid`
2. **`DeliveryStateAndDedupeTest`** (`tests/unit/client/delivery_state_and_dedupe_test.cpp`, 3 tests):
   - `MonotonicStateRankAndTransitionsEnforced`
   - `MessagingManagerRejectsStaleRegressionAndAdvancesSequence`
   - `InboundRealtimeEventDeduplicatesAtLeastOnceDeliveries`
3. **`DeliveryRetryEngineTest`** (`tests/unit/client/delivery_retry_engine_test.cpp`, 3 tests):
   - `ExponentialBackoffRespectsCapAndJitterBounds`
   - `TransientNetworkFailureRetriesWithSameIdempotencyKeyAndSucceeds`
   - `ExceedingMaxAttemptsOrTtlTransitionsToFailed`
4. **`DeliveryAckAndReadReceiptTest`** (`tests/unit/client/delivery_ack_and_read_receipt_test.cpp`, 3 tests):
   - `InboundPersistenceDispatchesTransportDeliveryAck`
   - `ReadReceiptPolicyGatedAndPersistedInSecureStorage`
   - `InboundAckAndReadEventsAdvanceOutboundTicksMonotonically`
5. **`WorkspaceViewModelRealtimeTest`** (`tests/unit/client/workspace_view_model_realtime_test.cpp`, 3 tests):
   - `ReadReceiptsPropertySignalsAndPersistsInMessagingManager`
   - `RealtimeDeliveryAckAndReadEventsUpdateTicksViaQueuedConnection`
   - `SyncManagerPollRealtimeUpdatesPullsMessagesAndAdvancesCursor`

### 9.2 End-to-End Integration Scenarios (`RealtimeDeliveryAndReceiptsIntegrationTest`, 5 Tests)
All 5 scenarios in `tests/unit/client/realtime_delivery_and_receipts_integration_test.cpp` run in-process with real `OpenSslCryptoProvider`, disk-backed `SqlCipherLocalStore`, `ISecureStorage`, `RatchetSessionManager`, `MessagingManager`, `SyncManager`, and `WorkspaceViewModel` (zero Docker or external daemons):

- **Scenario 1 — `Scenario1LivePollingToEventDeliveryAndReadTickProgression`** (`32 ms`, **PASS**):
  - Alice sends an E2EE 1:1 message via `WorkspaceViewModel::sendMessage()` (starts at `Accepted`).
  - Bob polls via `SyncManager::poll_realtime_updates()`, advancing cursor to `10`, decrypting and persisting to SQLCipher, and auto-dispatching `acknowledge_delivery`.
  - Alice receives `DeliveryAck` via `emit_realtime_event` → `WorkspaceViewModel` advances tick `Accepted → Delivered` via `Qt::QueuedConnection`.
  - Bob marks conversation read → `send_read_receipt` fires → Alice receives `ReadReceipt` → `WorkspaceViewModel` advances tick `Delivered → Read`.
- **Scenario 2 — `Scenario2TransientOutageRetryWithIdempotentDeduplication`** (`7 ms`, **PASS**):
  - Alice encounters a simulated `503` submission outage (`DeliveryState::LocalPending`, `pending_retry_count() == 1`).
  - Network recovers and `DeliveryRetryEngine` re-submits with the **exact same `idempotency_key`**.
  - Bob receives duplicate at-least-once deliveries (`{dup_ev, dup_ev}`) during `poll_realtime_updates` and persists **exactly one** message (`unread_count == 1`).
- **Scenario 3 — `Scenario3OutOfOrderReceiptAndSequenceMonotonicity`** (`7 ms`, **PASS**):
  - Alice receives `ReadReceipt` (`seq = 20`) first, followed by late `DeliveryAck` (`seq = 15`) and stale `Accepted` status (`seq = 12`).
  - Persisted `Message` retains `DeliveryState::Read` and `server_sequence_number == 20`.
- **Scenario 4 — `Scenario4PrivacyGatedReadReceiptsAndSettingsQmlBinding`** (`45 ms`, **PASS**):
  - Loads `qrc:/qml/SettingsPlaceholder.qml` via `QQmlComponent`, locates `readReceiptsSwitch`, verifies initial `checked == true`, toggles `bob_vm.setReadReceiptsEnabled(false)`, and verifies `readReceiptsSwitch.checked == false`.
  - Delivers a real E2EE message from Alice to Bob via `SyncManager::poll_realtime_updates()`; verifies transport `acknowledge_delivery` still fires (`sent_delivery_acks().size() == 1`), while `mark_conversation_read` clears `unread_count` to `0` and suppresses all `send_read_receipt` calls (`sent_read_receipts().empty() == true`).
- **Scenario 5 — `Scenario5RetryExpirationFailedAndSqlCipherRestartDurability`** (`9 ms`, **PASS**):
  - Persistent outage exceeds `max_attempts = 2`, transitioning message to `DeliveryState::Failed`.
  - Full `ClientApplication` shutdown and restart against the same `SqlCipherLocalStore` + `ISecureStorage` preserves both `DeliveryState::Failed` and `read_receipts_enabled() == false`.
  - Manual `retry_failed_message` recovers cleanly while preserving the original `idempotency_key`.

---

## 10. Verbatim Verification Outputs & Reproducible Commands

### 10.1 Formatting & Zero-Warning Build
```text
ninja: Entering directory `build/dev-debug'
[1/2] Checking project C++ formatting (read-only)...
[SecureCloud] All 1032 C++ files adhere to .clang-format.
ninja: Entering directory `build/dev-debug'
[1/11] Automatic MOC for target securecloud-client
[2/10] Automatic MOC for target securecloud_client_foundation_test
[3/9] Automatic RCC for ui/qml.qrc
[4/9] Building CXX object src/client/CMakeFiles/securecloud-client.dir/securecloud-client_autogen/UYX5XTB5RZ/qrc_qml.cpp.o
[5/9] Building CXX object src/client/CMakeFiles/securecloud-client.dir/main.cpp.o
[6/9] Building CXX object tests/unit/CMakeFiles/securecloud_client_foundation_test.dir/client/realtime_delivery_and_receipts_integration_test.cpp.o
[7/9] Linking CXX executable src/client/securecloud-client
[8/9] Linking CXX executable tests/unit/securecloud_client_foundation_test
```

### 10.2 Scenarios 1–5 Integration Suite (`RealtimeDeliveryAndReceiptsIntegrationTest`)
```text
Note: Google Test filter = RealtimeDeliveryAndReceiptsIntegrationTest.*
[==========] Running 5 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 5 tests from RealtimeDeliveryAndReceiptsIntegrationTest
[ RUN      ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario1LivePollingToEventDeliveryAndReadTickProgression
[       OK ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario1LivePollingToEventDeliveryAndReadTickProgression (32 ms)
[ RUN      ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario2TransientOutageRetryWithIdempotentDeduplication
[       OK ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario2TransientOutageRetryWithIdempotentDeduplication (7 ms)
[ RUN      ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario3OutOfOrderReceiptAndSequenceMonotonicity
[       OK ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario3OutOfOrderReceiptAndSequenceMonotonicity (7 ms)
[ RUN      ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario4PrivacyGatedReadReceiptsAndSettingsQmlBinding
[       OK ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario4PrivacyGatedReadReceiptsAndSettingsQmlBinding (45 ms)
[ RUN      ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario5RetryExpirationFailedAndSqlCipherRestartDurability
[       OK ] RealtimeDeliveryAndReceiptsIntegrationTest.Scenario5RetryExpirationFailedAndSqlCipherRestartDurability (9 ms)
[----------] 5 tests from RealtimeDeliveryAndReceiptsIntegrationTest (79 ms total)

[----------] Global test environment tear-down
[==========] 5 tests from 1 test suite ran. (79 ms total)
[  PASSED  ] 5 tests.
```

### 10.3 Full `securecloud_client_foundation_test` Suite & Offscreen `--smoke-test`
```text
[----------] 4 tests from RealtimeGatewayContractsTest
[ RUN      ] RealtimeGatewayContractsTest.AcknowledgeDeliveryAndReadReceiptRecordAndValidate
[       OK ] RealtimeGatewayContractsTest.AcknowledgeDeliveryAndReadReceiptRecordAndValidate (0 ms)
[ RUN      ] RealtimeGatewayContractsTest.FetchConversationMessagesRespectsSinceSequenceAndPagination
[       OK ] RealtimeGatewayContractsTest.FetchConversationMessagesRespectsSinceSequenceAndPagination (0 ms)
[ RUN      ] RealtimeGatewayContractsTest.DeliveryStatusAndRealtimeSubscriptionLifecycle
[       OK ] RealtimeGatewayContractsTest.DeliveryStatusAndRealtimeSubscriptionLifecycle (0 ms)
[ RUN      ] RealtimeGatewayContractsTest.DefaultPolicyConfigsAreValid
[       OK ] RealtimeGatewayContractsTest.DefaultPolicyConfigsAreValid (0 ms)
[----------] 4 tests from RealtimeGatewayContractsTest (0 ms total)

[----------] 3 tests from DeliveryStateAndDedupeTest
[ RUN      ] DeliveryStateAndDedupeTest.MonotonicStateRankAndTransitionsEnforced
[       OK ] DeliveryStateAndDedupeTest.MonotonicStateRankAndTransitionsEnforced (0 ms)
[ RUN      ] DeliveryStateAndDedupeTest.MessagingManagerRejectsStaleRegressionAndAdvancesSequence
[       OK ] DeliveryStateAndDedupeTest.MessagingManagerRejectsStaleRegressionAndAdvancesSequence (0 ms)
[ RUN      ] DeliveryStateAndDedupeTest.InboundRealtimeEventDeduplicatesAtLeastOnceDeliveries
[       OK ] DeliveryStateAndDedupeTest.InboundRealtimeEventDeduplicatesAtLeastOnceDeliveries (0 ms)
[----------] 3 tests from DeliveryStateAndDedupeTest (0 ms total)

[----------] 3 tests from DeliveryRetryEngineTest
[ RUN      ] DeliveryRetryEngineTest.ExponentialBackoffRespectsCapAndJitterBounds
[       OK ] DeliveryRetryEngineTest.ExponentialBackoffRespectsCapAndJitterBounds (0 ms)
[ RUN      ] DeliveryRetryEngineTest.TransientNetworkFailureRetriesWithSameIdempotencyKeyAndSucceeds
[       OK ] DeliveryRetryEngineTest.TransientNetworkFailureRetriesWithSameIdempotencyKeyAndSucceeds (1 ms)
[ RUN      ] DeliveryRetryEngineTest.ExceedingMaxAttemptsOrTtlTransitionsToFailed
[       OK ] DeliveryRetryEngineTest.ExceedingMaxAttemptsOrTtlTransitionsToFailed (1 ms)
[----------] 3 tests from DeliveryRetryEngineTest (2 ms total)

[----------] 3 tests from DeliveryAckAndReadReceiptTest
[ RUN      ] DeliveryAckAndReadReceiptTest.InboundPersistenceDispatchesTransportDeliveryAck
[       OK ] DeliveryAckAndReadReceiptTest.InboundPersistenceDispatchesTransportDeliveryAck (0 ms)
[ RUN      ] DeliveryAckAndReadReceiptTest.ReadReceiptPolicyGatedAndPersistedInSecureStorage
[       OK ] DeliveryAckAndReadReceiptTest.ReadReceiptPolicyGatedAndPersistedInSecureStorage (0 ms)
[ RUN      ] DeliveryAckAndReadReceiptTest.InboundAckAndReadEventsAdvanceOutboundTicksMonotonically
[       OK ] DeliveryAckAndReadReceiptTest.InboundAckAndReadEventsAdvanceOutboundTicksMonotonically (0 ms)
[----------] 3 tests from DeliveryAckAndReadReceiptTest (0 ms total)

[----------] 3 tests from WorkspaceViewModelRealtimeTest
[ RUN      ] WorkspaceViewModelRealtimeTest.ReadReceiptsPropertySignalsAndPersistsInMessagingManager
[       OK ] WorkspaceViewModelRealtimeTest.ReadReceiptsPropertySignalsAndPersistsInMessagingManager (2 ms)
[ RUN      ] WorkspaceViewModelRealtimeTest.RealtimeDeliveryAckAndReadEventsUpdateTicksViaQueuedConnection
[       OK ] WorkspaceViewModelRealtimeTest.RealtimeDeliveryAckAndReadEventsUpdateTicksViaQueuedConnection (2 ms)
[ RUN      ] WorkspaceViewModelRealtimeTest.SyncManagerPollRealtimeUpdatesPullsMessagesAndAdvancesCursor
[       OK ] WorkspaceViewModelRealtimeTest.SyncManagerPollRealtimeUpdatesPullsMessagesAndAdvancesCursor (2 ms)
[----------] 3 tests from WorkspaceViewModelRealtimeTest (7 ms total)

[----------] 5 tests from RealtimeDeliveryAndReceiptsIntegrationTest
[       OK ] RealtimeDeliveryAndReceiptsIntegrationTest.* (79 ms total)

[==========] 287 tests from 80 test suites ran. (966 ms total)
[  PASSED  ] 287 tests.

[SecureCloud Client] Initializing SecureCloud Client v0.1.0-dev
[INFO] [ClientApp] Initializing application subsystems...
[INFO] [ClientApp] Subsystems initialized successfully
[INFO] [ClientApp] Application entered RUNNING state
[SecureCloud Client] Smoke test execution passed cleanly (QML engine loaded)
[INFO] [ClientApp] Initiating graceful shutdown...
[INFO] [ClientApp] Application terminated cleanly
```

### 10.4 Reproducible Verification Commands

```bash
# 1. Verify .clang-format compliance across all 1,032 C++ files
ninja -C build/dev-debug check-format

# 2. Build desktop client and unit/integration suite with zero warnings (-Werror)
ninja -C build/dev-debug securecloud-client securecloud_client_foundation_test

# 3. Run CLIENT-010 E2E integration suite (Scenarios 1-5)
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test \
  --gtest_filter="RealtimeDeliveryAndReceiptsIntegrationTest.*"

# 4. Run full client foundation suite (287 tests / 80 suites)
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test

# 5. Run desktop client offscreen smoke test
QT_QPA_PLATFORM=offscreen ./build/dev-debug/src/client/securecloud-client --smoke-test
```

---

## 11. Detailed Sequence Diagrams & End-to-End Protocol Flows

### 11.1 Outbound Send, Transient Failure, Jittered Retry & Authoritative Tick Flow

```text
User (QML Composer)      WorkspaceViewModel        MessagingManager         DeliveryRetryEngine         DefaultGatewayClient (REST)
       │                        │                         │                          │                              │
       │── sendMessage(text) ──►│                         │                          │                              │
       │                        │── stage_outbound_msg ──►│                          │                              │
       │                        │                         ├─ validate_recipients_can_receive() (ADR-008)            │
       │                        │                         ├─ encrypt (Ratchet / SCG v1)                              │
       │                        │                         ├─ submit_encrypted_message(req) ─────────────────────────►│
       │                        │                         │                          │                              │ (503 / Network error)
       │                        │                         │◄─ ClientError(Network) ─────────────────────────────────┤
       │                        │                         ├─ save_message(LocalPending, idem_key)                   │
       │                        │                         ├─ enqueue(cid, mid, req) ─►│                              │
       │                        │◄─ Message(LocalPending)─┤                          │                              │
       │◄─ activeMessagesChanged│                         │                          │                              │
       │   ("Pending Local...") │                         │                          │                              │
       │                        │                         │                          │                              │
  [SyncManager::poll_realtime_updates()]                  │                          │                              │
       │                        │                         │── process_retry_queue()─►│                              │
       │                        │                         │                          ├─ compute_backoff(attempt)    │
       │                        │                         │                          ├─ submit_encrypted_message ──►│
       │                        │                         │                          │◄─ ok("msg-srv-...") ─────────┤
       │                        │                         │◄─ accepted(cid, mid) ────┤                              │
       │                        │                         ├─ update_message_delivery_state(Accepted)                │
       │                        │                         │                          │                              │
  [Poll / Event: DeliveryAck]   │                         │                          │                              │
       │                        │◄─ emit_realtime_event ──┼──────────────────────────┼──────────────────────────────┤
       │                        │   (Qt::QueuedConnection)│                          │                              │
       │                        ├─ handleRealtimeEvent() ─► process_inbound_realtime_event(DeliveryAck)             │
       │◄─ activeMessagesChanged│                         ├─ update_message_delivery_state(Delivered, seq)          │
       │   ("Delivered · E2EE") │                         │                          │                              │
       │                        │                         │                          │                              │
  [Poll / Event: ReadReceipt]   │                         │                          │                              │
       │                        │◄─ emit_realtime_event ──┼──────────────────────────┼──────────────────────────────┤
       │                        ├─ handleRealtimeEvent() ─► process_inbound_realtime_event(ReadReceipt)             │
       │◄─ activeMessagesChanged│                         ├─ update_message_delivery_state(Read, seq)               │
       │   ("Read · Verified")  │                         │                          │                              │
```

### 11.2 Inbound Polling, Pre-Decryption Deduplication & Privacy-Gated Read Receipt Flow

```text
SyncManager              Gateway (REST)           MessagingManager          SqlCipherLocalStore        WorkspaceViewModel
     │                        │                         │                          │                         │
     ├─ fetch_conversation_messages(cid, did, since_seq)►                          │                         │
     │◄─ page(events, latest_seq)                       │                          │                         │
     │                        │                         │                          │                         │
     ├─ process_inbound_realtime_event(ev) ────────────►│                          │                         │
     │                        │                         ├─ get_message(cid, mid) ─►│                         │
     │                        │                         │                          │                         │
     │                        │      [Case A: Already Persisted (At-Least-Once Re-delivery)]                 │
     │                        │                         │◄─ ok(existing_msg) ──────┤                         │
     │                        │◄─ acknowledge_delivery ─┤ (re-ACK lost transport)  │                         │
     │                        │                         │                          │                         │
     │                        │      [Case B: New Message]                         │                         │
     │                        │                         ├─ blocked sender check    │                         │
     │                        │                         ├─ decrypt (Ratchet / SCG) │                         │
     │                        │                         ├─ persist_inbound_message►│ (encrypted SQLCipher)   │
     │                        │◄─ acknowledge_delivery ─┤ (always sent)            │                         │
     │                        │                         │                          │                         │
     ├─ conversation_cursors_[cid] = latest_seq         │                          │                         │
     │                        │                         │                          │                         │
  [User Opens Conversation in UI]                       │                          │                         │
     │                        │                         │◄─ mark_conversation_read(cid, uid, did) ───────────┤
     │                        │                         ├─ unread_count = 0 ──────►│                         │
     │                        │                         ├─ if (read_receipts_enabled()):                     │
     │                        │◄─ send_read_receipt ────┤    update state -> Read + POST .../read            │
     │                        │                         ├─ else (privacy mode):                              │
     │                        │                         │    suppress all POST .../read calls                │
```

---

## 12. Detailed API & Implementation Reference

### 12.1 `src/client/domain/realtime_events.hpp`
Defines all transport-agnostic real-time event and policy types:

1. **`enum class RealtimeEventType`**:
   - `InboundDirectMessage`: Pairwise Double Ratchet / X3DH payload delivered to a specific recipient device.
   - `InboundGroupMessage`: Serialized `SCG` v1 `GroupEncryptedEnvelope` delivered to group members.
   - `InboundSenderKeyDistribution`: Pairwise-encrypted `SenderKeyDistributionMessage` advancing or initializing a sender's epoch chain.
   - `DeliveryAck`: Transport acknowledgement emitted by a recipient device upon local persistence.
   - `ReadReceipt`: User-level read notification emitted when `ReadReceiptPolicy::send_read_receipts_enabled` is `true`.
   - `PresenceUpdate`: Peer presence state transition (`Online`, `Busy`, `Offline`).

2. **`struct DeliveryAckRecord`** & **`struct ReadReceiptRecord`**:
   - `DeliveryAckRecord` captures `{ MessageId message_id; DeviceId recipient_device_id; int64_t delivered_at_ms; }`.
   - `ReadReceiptRecord` captures `{ ConversationId conversation_id; MessageId message_id; DeviceId reader_device_id; int64_t read_at_ms; }`.
   - Neither struct carries plaintext, display names, or cryptographic keys.

3. **`struct MessageDeliveryStatusInfo`**:
   - Captures `{ MessageId message_id; DeliveryState delivery_state; uint64_t server_sequence_number; int64_t updated_at_ms; }`.
   - Returned by `IGatewayClient::get_message_delivery_status(...)`.

4. **`struct ConversationMessagesPage`**:
   - Captures `{ std::vector<RealtimeEvent> events; bool has_more; uint64_t latest_sequence; }`.
   - Mirrors `proto/securecloud/messaging/v1/messaging.proto`'s `GetMessagesResponse` pagination contract (`has_more`, `latest_sequence`).

5. **`struct RetryPolicyConfig`**:
   - `uint32_t max_attempts{5}` — Maximum submission attempts before transitioning to `DeliveryState::Failed`.
   - `std::chrono::milliseconds initial_backoff{500}` — Initial retry delay (`500 ms`).
   - `std::chrono::milliseconds max_backoff{30000}` — Upper cap on exponential backoff (`30 s`).
   - `double jitter_ratio{0.25}` — Symmetric jitter spread (`±25%`, clamped internally to `[0.0, 0.95]`).
   - `std::chrono::seconds expiration_ttl{std::chrono::hours(24)}` — Maximum lifetime of an unaccepted queued message before expiring to `Failed`.

6. **`struct ReadReceiptPolicy`**:
   - `static constexpr std::string_view kStorageKey = "messaging.privacy.send_read_receipts";`
   - `bool send_read_receipts_enabled{true};`

### 12.2 `src/client/domain/delivery_state.hpp` & `delivery_state.cpp`
Implements monotonic state ordering and transition validation:

- **`delivery_state_rank(DeliveryState state) noexcept`**:
  - `LocalPending` → `0`
  - `Submitting` → `1`
  - `Accepted` → `2`
  - `Delivering` → `3`
  - `Delivered` → `4`
  - `Read` → `5`
  - `Failed` → `-1`

- **`can_transition_delivery_state(DeliveryState current, DeliveryState next) noexcept`**:
  - **Self-transitions**: `current == next` always returns `true`.
  - **Recovery from `Failed`**: Allowed only when `next == DeliveryState::Submitting || next == DeliveryState::LocalPending`.
  - **Failure from active states**: `next == DeliveryState::Failed` is allowed only when `current != DeliveryState::Delivered && current != DeliveryState::Read`.
  - **Forward progression**: Otherwise returns `delivery_state_rank(next) >= delivery_state_rank(current)`.

### 12.3 `src/client/application/managers/delivery_retry_engine.hpp` & `.cpp`
- **Thread Safety**: All public methods (`set_config`, `config`, `compute_backoff`, `enqueue`, `remove`, `pending_count`, `process_due`) acquire `std::lock_guard<std::mutex>` over `mutex_`.
- **Deadlock-Free `process_due(...)`**:
  - Splits `queue_` under lock into `due`, `expired`, and `remaining` vectors, then **releases the lock** before invoking `expire_fn` and `submit_fn` (so callbacks into `MessagingManager` / `IGatewayClient` never contend on `DeliveryRetryEngine::mutex_`).
  - Failed transient retries (`ClientErrorCategory::Network`) within `max_attempts` and `expires_at` recompute jittered backoff and re-enter `queue_`.
  - Non-network errors (e.g., `Validation`, `Crypto`, `Authentication`) immediately invoke `expire_fn` without wasting retries.
- **Duplicate Enqueue Guard**: `enqueue(...)` checks if `message_id` is already present in `queue_` so duplicate staging cannot double-queue the same message.

### 12.4 `src/client/application/managers/messaging_manager.hpp` & `.cpp`
Key `CLIENT-010` additions to `MessagingManager`:
1. **`local_device_id_` & `set_local_device_id(const domain::DeviceId&)`**:
   - Populated automatically by `ClientBootstrap::initialize_ratchet_session_manager(...)`.
   - Used by `dispatch_delivery_ack_if_configured(...)` and as the fallback `reader_device_id` in `mark_conversation_read(...)`.
2. **`read_receipt_policy_`, `hydrate_read_receipt_policy()`, `set_read_receipts_enabled(bool)`, `read_receipts_enabled()`**:
   - Hydrates from `ISecureStorage` (`ReadReceiptPolicy::kStorageKey`) on construction and `set_secure_storage(...)`.
   - Persists `"true"` / `"false"` via `SecretString` on `set_read_receipts_enabled(bool)`.
3. **`stage_outbound_message(...)`**:
   - Builds `FanOutSubmissionRequest` with deterministic `idempotency_key`.
   - On `ClientErrorCategory::Network` error from `gateway_.submit_encrypted_message(...)`, persists the message as `DeliveryState::LocalPending`, enqueues `FanOutSubmissionRequest` in `retry_engine_`, and returns `ok(msg)`.
4. **`process_retry_queue(now)` & `pending_retry_count()`**:
   - Drives `retry_engine_.process_due(...)`; transitions accepted messages to `DeliveryState::Accepted` and expired messages to `DeliveryState::Failed`.
5. **`update_message_delivery_state(cid, mid, new_state, server_sequence_number = 0)`**:
   - Enforces `can_transition_delivery_state` and monotonic `server_sequence_number` updates.
6. **`process_inbound_realtime_event(const domain::RealtimeEvent&)`**:
   - Unified inbound dispatcher with pre-decryption `message_id` deduplication, shared `persist_inbound_message(...)` helper, and automatic `dispatch_delivery_ack_if_configured(...)`.
7. **`mark_conversation_read(cid, local_user_id, reader_device_id)`**:
   - Always clears `unread_count = 0` and saves the conversation.
   - Conditionally transitions unread peer messages to `DeliveryState::Read` and calls `gateway_.send_read_receipt(...)` only when `read_receipts_enabled()` is `true` and an effective device ID is present.

### 12.5 `src/client/application/managers/sync_manager.hpp` & `.cpp`
- **`set_messaging_manager(MessagingManager*)`**: Wired in `ClientBootstrap::wire_managers()`.
- **`conversation_cursor(const domain::ConversationId&)`**: Returns the latest persisted/polled `server_sequence_number` for a conversation (`0` if unseen).
- **`poll_realtime_updates(const domain::DeviceId& local_device_id)`**:
  1. Calls `messaging_manager_->process_retry_queue()`.
  2. Lists conversations from `MessagingManager` and fetches incremental pages via `gateway_.fetch_conversation_messages(cid, local_device_id, since_seq, 50)`.
  3. Feeds each fetched `RealtimeEvent` into `messaging_manager_->process_inbound_realtime_event(ev)` and updates `conversation_cursors_[cid]`.
  4. Checks `gateway_.get_message_delivery_status(cid, mid)` for recent in-flight (`Accepted`, `Delivering`, `Delivered`) messages and advances local state monotonically.

### 12.6 `src/client/ui/workspace_view_model.hpp`, `.cpp` & QML Bindings
1. **Live Event Subscription**:
   - Subscribes via `gateway().subscribe_realtime_events(...)` using `QPointer<WorkspaceViewModel>` + `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` so gateway threads never mutate Qt models directly.
   - Unsubscribes cleanly in `~WorkspaceViewModel()`.
2. **UI Tick & Message Synchronization**:
   - `sendMessage()` uses `sendRes.value().message_id()`, `sendRes.value().idempotency_key()`, and `domain::to_string(sendRes.value().delivery_state())`.
   - `handleRealtimeEvent()` updates `MessageEntry::deliveryState`, appends new decrypted messages, updates conversation previews & unread badges, and updates peer presence without QML polling.
3. **QML Tick Rendering (`src/client/ui/qml/WorkspacePlaceholder.qml`)**:
   - Existing delegates at lines `1211–1255` render:
     - `LocalPending`: `"clock"` icon, `"Pending Local Queue"`
     - `Submitting`: `"upload-cloud"` icon, `"Submitting via mTLS..."`
     - `Accepted`: `"check"` icon, `"Accepted by Gateway"`
     - `Delivered`: `"check-check"` icon, `"Delivered · E2EE"`
     - `Read`: `"shield-check"` icon, `"Read · Verified"`
     - `Failed`: `"alert-circle"` icon, `"Delivery Failed"` (with `Retry` and `Discard` actions)
4. **Settings Privacy Toggle (`src/client/ui/qml/SettingsPlaceholder.qml`)**:
   - `Switch` (`id: readReceiptsSwitch`, `objectName: "readReceiptsSwitch"`) bound bidirectionally to `wvm.readReceiptsEnabled`.

---

## 13. Security & Privacy Verification Matrix

| Security / Reliability Invariant | Enforcement Mechanism | Verified By |
|---|---|---|
| **Zero Plaintext on Disk** | `SqlCipherLocalStore` AES-256-CBC + HMAC-SHA512 + `PRAGMA cipher_memory_security = ON`; keys held in `ISecureStorage` | `SqlCipherLocalStoreTest`, `DirectAndGroupMessagingIntegrationTest`, `RealtimeDeliveryAndReceiptsIntegrationTest` |
| **Zero Plaintext in Receipts / ACKs** | `DeliveryAckRecord` and `ReadReceiptRecord` transmit only opaque IDs and timestamps | `RealtimeGatewayContractsTest`, `DeliveryAckAndReadReceiptTest` |
| **No Double-Ratchet Desync on Re-Delivery** | Pre-decryption `message_id` lookup in `process_inbound_realtime_event` returns existing persisted `Message` before touching ratchet keys | `DeliveryStateAndDedupeTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario2` |
| **No Stale Tick Regressions** | `can_transition_delivery_state()` + monotonic `server_sequence_number` check in `update_message_delivery_state()` | `DeliveryStateAndDedupeTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario3` |
| **Thundering-Herd Prevention on Reconnect** | Randomized jitter `[1 - jitter_ratio, 1 + jitter_ratio]` in `DeliveryRetryEngine::compute_backoff()` | `DeliveryRetryEngineTest::ExponentialBackoffRespectsCapAndJitterBounds` |
| **Idempotent Retry Without Duplicate Messages** | Original `idempotency_key` preserved inside queued `FanOutSubmissionRequest` | `DeliveryRetryEngineTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario2` & `Scenario5` |
| **Read Receipt Privacy Suppression** | `ReadReceiptPolicy` persisted in `ISecureStorage`; `mark_conversation_read()` suppresses all `send_read_receipt()` calls when disabled while keeping transport ACKs active | `DeliveryAckAndReadReceiptTest`, `WorkspaceViewModelRealtimeTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario4` |
| **UI Thread Safety** | `QPointer<WorkspaceViewModel>` + `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` + destructor unsubscribe | `WorkspaceViewModelRealtimeTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario1` |

---

## 14. Sign-Off Checklist

- [x] `CLIENT-010-T01`: Domain event/policy models & `IGatewayClient` REST/event contracts implemented and tested (`4 / 4` tests).
- [x] `CLIENT-010-T02`: Monotonic `DeliveryState` transitions & inbound at-least-once deduplication implemented and tested (`3 / 3` tests).
- [x] `CLIENT-010-T03`: `DeliveryRetryEngine` with exponential backoff, jitter, and expiration implemented and tested (`3 / 3` tests).
- [x] `CLIENT-010-T04`: Automatic transport delivery ACKs & `ISecureStorage`-backed privacy-gated read receipts implemented and tested (`3 / 3` tests).
- [x] `CLIENT-010-T05`: `SyncManager::poll_realtime_updates`, `WorkspaceViewModel` queued live updates, `readReceiptsEnabled` property, and `SettingsPlaceholder.qml` toggle implemented and tested (`3 / 3` tests).
- [x] `CLIENT-010-T06`: 5-scenario E2E integration suite (`RealtimeDeliveryAndReceiptsIntegrationTest`, `5 / 5` tests) and full `>= 1,000`-line walkthrough report completed.
- [x] `check-format`: `100%` compliant across all `1,032` C++ files.
- [x] Compiler warnings: `0` warnings under `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`.
- [x] Full test suite: `287 / 287` tests passing across `80` test suites (`966 ms`).
- [x] Desktop client `--smoke-test`: Passed cleanly with QML engine loaded.

---

## 15. Step-by-Step Walkthrough of E2E Integration Scenarios & Test Fixtures

### 15.1 Persistent Workstation Test Harness (`PersistentWorkstation`)
In `tests/unit/client/realtime_delivery_and_receipts_integration_test.cpp`, `PersistentWorkstation` models an independent desktop client workstation with isolated disk-backed encrypted storage and cryptographic identity:

1. **Cryptographic Identity Provisioning**:
   - Generates real Ed25519/X25519 identity keypair, signed prekey, and one-time prekey using `OpenSslCryptoProvider`.
   - Saves `DevicePrivateBundle` into a persistent `std::shared_ptr<MemorySecureStorage>` simulating the OS keychain across application restarts.
2. **Encrypted Disk Persistence**:
   - `boot()` constructs `ClientConfig` with `database_path` pointing to a per-workstation SQLCipher `.db` file (`alice.db`, `bob.db`).
   - Attaches `SqlCipherLocalStore(*shared_storage, *crypto)`, `ForwardingSecureStorage(shared_storage)`, `DefaultGatewayClient`, and `OpenSslCryptoProvider` via `ClientBootstrap::create_with_adapters(...)`.
   - Calls `app->initialize()` and `app->start()`, then initializes `RatchetSessionManager` and `MessagingManager::set_local_device_id(did)`.
3. **Full Restart Simulation**:
   - `restart()` invokes `app->shutdown()`, destroys `ClientApplication` (closing `SqlCipherLocalStore` and flushing memory), and calls `boot()` to spin up a brand-new `ClientApplication` against the same `.db` file and `shared_storage`.

### 15.2 Scenario 1 Trace — Live Polling-to-Event Tick Progression
- **Step 1**: Alice opens a direct conversation with Bob (`open_direct_conversation`) and attaches `WorkspaceViewModel` (`alice_vm`).
- **Step 2**: `alice_vm.sendMessage("Real-time delivery check")` invokes `MessagingManager::stage_outbound_message`, which:
  - Validates Bob's key status (`Verified` / not blocked).
  - Encrypts via X3DH + Double Ratchet (`RatchetSessionManager::encrypt_fanout_for_participants`).
  - Submits `FanOutSubmissionRequest` to Alice's `DefaultGatewayClient`.
  - Stores the `MessageEntry` in `alice_vm` with authoritative `message_id`, `idempotency_key`, and initial `deliveryState == "Accepted"`.
- **Step 3**: The encrypted `PerDeviceDeliveryPayload` from Alice's Gateway is placed in Bob's `DefaultGatewayClient::set_simulated_conversation_messages(...)` with `server_sequence_number = 10`.
- **Step 4**: Bob calls `SyncManager::poll_realtime_updates(bob.did)`:
  - Fetches the page (`since_sequence = 0`), advances `conversation_cursor` to `10`.
  - Calls `MessagingManager::process_inbound_realtime_event(inbound_ev)`, decrypting the payload, saving to Bob's `SqlCipherLocalStore`, incrementing Bob's `unread_count`, and automatically dispatching `acknowledge_delivery(sent_msg_id, bob.did, ...)`.
- **Step 5**: Alice's `DefaultGatewayClient::emit_realtime_event(ack_ev)` delivers `RealtimeEventType::DeliveryAck` to `WorkspaceViewModel` via `Qt::QueuedConnection` (`QCoreApplication::processEvents()`), advancing `alice_vm.activeMessages()[0]["deliveryState"]` from `"Accepted"` to `"Delivered"`.
- **Step 6**: Bob calls `mark_conversation_read(bob_conv.conversation_id(), bob.uid, bob.did)`, dispatching `send_read_receipt(...)`. Alice receives `RealtimeEventType::ReadReceipt`, advancing `alice_vm.activeMessages()[0]["deliveryState"]` from `"Delivered"` to `"Read"`.

### 15.3 Scenario 2 Trace — Transient Outage Retry & At-Least-Once Deduplication
- **Step 1**: Alice configures `RetryPolicyConfig` (`initial_backoff = 20 ms`, `max_backoff = 100 ms`, `jitter_ratio = 0.2`, `max_attempts = 4`).
- **Step 2**: `alice.gateway->set_simulated_submission_failure(true, "Simulated 503")` simulates a transient Gateway submission failure while keeping prekey directory lookups functional.
- **Step 3**: `stage_outbound_message(..., "Idempotent retry payload")` succeeds locally, persists the message in `DeliveryState::LocalPending`, and enqueues the encrypted `FanOutSubmissionRequest` in `DeliveryRetryEngine` (`pending_retry_count() == 1`).
- **Step 4**: Network recovers (`set_simulated_submission_failure(false)`). Advancing past the jittered backoff window and calling `process_retry_queue(now + 1s)` submits the exact same `FanOutSubmissionRequest` with the original `idempotency_key`, clearing the retry queue (`pending_retry_count() == 0`).
- **Step 5**: Bob's `DefaultGatewayClient` is seeded with **two identical copies** `{dup_ev, dup_ev}` of the same `message_id` (`server_sequence_number = 25`), simulating an at-least-once Gateway re-delivery.
- **Step 6**: `bob.app->bootstrap().sync_manager().poll_realtime_updates(bob.did)` processes both events: the first decrypts and persists (`unread_count = 1`), and the second hits pre-decryption deduplication, returning the existing persisted `Message` without failing Double Ratchet decryption or incrementing `unread_count` (`get_conversation_messages` size `== 1`, `unread_count == 1`).

### 15.4 Scenario 3 Trace — Out-of-Order Receipt & Sequence Monotonicity
- **Step 1**: Alice sends `"Monotonicity check"` (`DeliveryState::Accepted`).
- **Step 2**: `ReadReceipt` (`server_sequence_number = 20`) arrives first, advancing the persisted `Message` to `DeliveryState::Read` and `server_sequence_number = 20`.
- **Step 3**: A late `DeliveryAck` (`server_sequence_number = 15`) and a stale `Accepted` status update (`server_sequence_number = 12`) are processed.
- **Step 4**: `can_transition_delivery_state` rejects both regressions; `SqlCipherLocalStore::get_message` confirms `delivery_state() == DeliveryState::Read` and `server_sequence_number() == 20`.

### 15.5 Scenario 4 Trace — Privacy-Gated Read Receipts & Settings QML Binding
- **Step 1**: `QQmlComponent` loads `qrc:/qml/SettingsPlaceholder.qml` with `navigationController` and `workspaceViewModel` context properties and locates `readReceiptsSwitch` (`checked == true`).
- **Step 2**: `bob_vm.setReadReceiptsEnabled(false)` updates `MessagingManager::read_receipts_enabled()` (`false`), persists `"false"` to `ISecureStorage`, and notifies QML (`readReceiptsSwitch.property("checked") == false`).
- **Step 3**: Alice sends a real E2EE message `"Private read check"`, which Bob pulls via `SyncManager::poll_realtime_updates(bob.did)`.
- **Step 4**: Transport `acknowledge_delivery` fires (`sent_delivery_acks().size() == 1`).
- **Step 5**: Bob calls `mark_conversation_read(...)`; local `unread_count` resets to `0`, while `sent_read_receipts()` remains completely empty.

### 15.6 Scenario 5 Trace — Retry Expiration → `Failed`, Manual Recovery & SQLCipher Restart
- **Step 1**: Alice sets `read_receipts_enabled(false)` and `RetryPolicyConfig` (`max_attempts = 2`), warms up the X3DH session, and enables persistent `503` submission failure.
- **Step 2**: `"Will expire"` is staged as `LocalPending`, then `process_retry_queue(now + 1s)` hits `max_attempts = 2`, transitioning the persisted message in `SqlCipherLocalStore` to `DeliveryState::Failed` and clearing `pending_retry_count()` to `0`.
- **Step 3**: `alice.restart()` shuts down `ClientApplication` and boots a fresh `ClientApplication` against `alice.db` and `shared_storage`.
- **Step 4**: Post-restart checks confirm `read_receipts_enabled() == false` and `persisted.delivery_state() == DeliveryState::Failed`.
- **Step 5**: `retry_failed_message(cid, mid)` recovers the `Failed` message cleanly while preserving its original `idempotency_key`.

---

## 16. Boundary with Subsequent Phase 3 Cards (`CLIENT-011` & `CLIENT-012`)

To maintain clean architectural separation across Desktop Client Phase 3:
1. **`CLIENT-010` (This Card)**:
   - Owns `IGatewayClient` REST receipt/status/incremental-fetch contracts, `RealtimeEvent` subscription, monotonic `DeliveryState` transitions, inbound at-least-once `message_id` deduplication, bounded in-session `DeliveryRetryEngine` with jitter, always-on transport `AcknowledgeDelivery`, privacy-gated `SendReadReceipt`, `SyncManager::poll_realtime_updates()`, and `WorkspaceViewModel` + `SettingsPlaceholder.qml` live UI bindings.
2. **`CLIENT-011` (Encrypted File Transfer & Streaming)**:
   - Owns 1 MiB AES-256-GCM chunked file encryption, SHA-256 rolling digest attestation, `/api/v1/files/*` resumable chunked upload/download pipelines, and Files Vault UI progress bindings.
3. **`CLIENT-012` (Offline Operation & Catch-Up Sync)**:
   - Owns persistent offline outbox queues across full multi-hour network disconnects/app restarts, network reachability state observers (`Online` / `Offline` / `Syncing`), and full `GET /api/v1/sync?cursor=` catch-up reconciliation across all conversations and contacts.

---

## 17. Complete `securecloud_client_foundation_test` Suite Summary (`80` Suites / `287` Tests)

| Category | Test Suites | Passing Tests | Status |
|---|---|---|---|
| **Foundation, Config, Error, Result, Logger** | 5 | 22 | `100%` Pass |
| **Domain IDs, Session, Contact, Device, Conversation, Message** | 12 | 35 | `100%` Pass |
| **Cryptography (OpenSSL EVP, X3DH, Double Ratchet, Skipped Keys, Safety Number, Sender Keys)** | 11 | 44 | `100%` Pass |
| **Persistence & Adapters (`SqlCipherLocalStore`, `KeyStorageHelper`, `DefaultGatewayClient`)** | 6 | 24 | `100%` Pass |
| **Application Managers (`Auth`, `Device`, `Pairing`, `Contact`, `Messaging`, `Emergency`, `Sync`)** | 18 | 66 | `100%` Pass |
| **UI & ViewModels (`NavigationController`, `WorkspaceViewModel`, QML Components, Window State)** | 14 | 54 | `100%` Pass |
| **Phase 2 & 3 E2E Integration Suites (`E2EE`, `MultiDevice`, `Contacts`, `DirectAndGroup`, `RealtimeDeliveryAndReceipts`)** | 9 | 26 | `100%` Pass |
| **`CLIENT-010` New Unit Suites (`RealtimeGatewayContracts`, `DeliveryStateAndDedupe`, `DeliveryRetryEngine`, `DeliveryAckAndReadReceipt`, `WorkspaceViewModelRealtime`)** | 5 | 16 | `100%` Pass |
| **Total (`securecloud_client_foundation_test`)** | **80** | **287** | **287 / 287 (100%)** |

---

## 18. Complete C++ & QML Public Contract Reference

### 18.1 `domain::DeliveryState` (`src/client/domain/delivery_state.hpp`)
```cpp
enum class DeliveryState { LocalPending, Submitting, Accepted, Delivering, Delivered, Read, Failed };

[[nodiscard]] std::string_view to_string(DeliveryState state) noexcept;
[[nodiscard]] std::optional<DeliveryState> delivery_state_from_string(std::string_view str) noexcept;
[[nodiscard]] int delivery_state_rank(DeliveryState state) noexcept;
[[nodiscard]] bool can_transition_delivery_state(DeliveryState current, DeliveryState next) noexcept;
```

### 18.2 `application::interfaces::IGatewayClient` (`src/client/application/interfaces/i_gateway_client.hpp`)
```cpp
using RealtimeEventHandler = std::function<void(const domain::RealtimeEvent&)>;

virtual ClientResult<domain::DeliveryState> acknowledge_delivery(
    const domain::MessageId& message_id,
    const domain::DeviceId& recipient_device_id,
    int64_t delivered_at_ms) = 0;

virtual ClientResult<domain::DeliveryState> send_read_receipt(
    const domain::ConversationId& conversation_id,
    const domain::MessageId& message_id,
    const domain::DeviceId& reader_device_id,
    int64_t read_at_ms) = 0;

virtual ClientResult<domain::MessageDeliveryStatusInfo> get_message_delivery_status(
    const domain::ConversationId& conversation_id,
    const domain::MessageId& message_id) = 0;

virtual ClientResult<domain::ConversationMessagesPage> fetch_conversation_messages(
    const domain::ConversationId& conversation_id,
    const domain::DeviceId& recipient_device_id,
    uint64_t since_sequence,
    std::size_t max_results = 50) = 0;

virtual uint64_t subscribe_realtime_events(RealtimeEventHandler handler) = 0;
virtual void unsubscribe_realtime_events(uint64_t subscription_id) = 0;
```

### 18.3 `application::managers::DeliveryRetryEngine` (`src/client/application/managers/delivery_retry_engine.hpp`)
```cpp
class DeliveryRetryEngine {
  public:
    explicit DeliveryRetryEngine(domain::RetryPolicyConfig config = {});

    void set_config(const domain::RetryPolicyConfig& config);
    [[nodiscard]] domain::RetryPolicyConfig config() const;
    [[nodiscard]] std::chrono::milliseconds compute_backoff(uint32_t attempt);

    void enqueue(domain::ConversationId conversation_id, domain::MessageId message_id,
                 interfaces::FanOutSubmissionRequest request,
                 std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    bool remove(const domain::MessageId& message_id);
    [[nodiscard]] std::size_t pending_count() const;

    using SubmitFn = std::function<ClientResult<std::string>(const interfaces::FanOutSubmissionRequest&)>;
    using ExpireFn = std::function<void(const domain::ConversationId&, const domain::MessageId&)>;

    std::size_t process_due(std::chrono::steady_clock::time_point now,
                            const SubmitFn& submit_fn,
                            const ExpireFn& expire_fn);
};
```

### 18.4 `application::managers::MessagingManager` (`src/client/application/managers/messaging_manager.hpp`)
- **Device & Privacy Configuration**:
  - `void set_local_device_id(const domain::DeviceId& device_id)`
  - `[[nodiscard]] const domain::DeviceId& local_device_id() const noexcept`
  - `ClientResult<void> set_read_receipts_enabled(bool enabled)`
  - `[[nodiscard]] bool read_receipts_enabled() const noexcept`
- **Retry Management**:
  - `void set_retry_policy(const domain::RetryPolicyConfig& config)`
  - `std::size_t process_retry_queue(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())`
  - `[[nodiscard]] std::size_t pending_retry_count() const`
- **Monotonic Lifecycle & Event Processing**:
  - `ClientResult<void> update_message_delivery_state(const domain::ConversationId&, const domain::MessageId&, domain::DeliveryState, uint64_t server_sequence_number = 0)`
  - `ClientResult<void> mark_conversation_read(const domain::ConversationId&, const domain::UserId& local_user_id = {}, const domain::DeviceId& reader_device_id = {})`
  - `ClientResult<std::optional<domain::Message>> process_inbound_realtime_event(const domain::RealtimeEvent&)`

### 18.5 `application::managers::SyncManager` (`src/client/application/managers/sync_manager.hpp`)
- `void set_messaging_manager(MessagingManager* messaging_manager) noexcept`
- `ClientResult<std::size_t> poll_realtime_updates(const domain::DeviceId& local_device_id)`
- `[[nodiscard]] uint64_t conversation_cursor(const domain::ConversationId& conversation_id) const`

### 18.6 `ui::WorkspaceViewModel` & QML Bindings (`src/client/ui/workspace_view_model.hpp` & `SettingsPlaceholder.qml`)
- `Q_PROPERTY(bool readReceiptsEnabled READ readReceiptsEnabled WRITE setReadReceiptsEnabled NOTIFY readReceiptsEnabledChanged)`
- `void readReceiptsEnabledChanged()`
- `~WorkspaceViewModel() override` (unsubscribes `realtime_sub_id_` from `IGatewayClient`)
- `SettingsPlaceholder.qml` control:
  - `Switch { id: readReceiptsSwitch; objectName: "readReceiptsSwitch"; checked: wvm ? wvm.readReceiptsEnabled : true; ... }`

---

## 19. Operational & Diagnostic Runbook

### 19.1 Diagnosing Delivery Tick Progression Issues
1. **Message stuck in `LocalPending`**:
   - Indicates `stage_outbound_message` encountered a `ClientErrorCategory::Network` error and enqueued the `FanOutSubmissionRequest` in `DeliveryRetryEngine`.
   - Verify `SyncManager::poll_realtime_updates(local_device_id)` is running and `Gateway` `/health` is reachable.
   - If `max_attempts` or `expiration_ttl` is reached, the message transitions to `DeliveryState::Failed` and surfaces the manual `Retry` / `Discard` actions in `WorkspacePlaceholder.qml`.
2. **Message stuck in `Accepted` (never reaching `Delivered`)**:
   - Indicates the Gateway accepted the message (`Hop 1` succeeded), but the recipient device has not yet polled, decrypted, and called `POST /api/v1/messages/:id/ack`, or the sender has not yet polled `DeliveryAck` / `get_message_delivery_status`.
3. **Message stays at `Delivered` (never reaching `Read`)**:
   - Expected behavior when the recipient has disabled **Send Read Receipts** (`readReceiptsEnabled = false`) in `SettingsPlaceholder.qml`.
   - Transport `AcknowledgeDelivery` still completes normally so delivery reliability is unaffected.

### 19.2 Diagnosing At-Least-Once Re-Delivery & Ratchet Errors
- Under `ADR-007 §2.7–2.8`, if a recipient's ACK is lost, the server re-delivers the same `message_id`.
- Always route polled or pushed server events through `MessagingManager::process_inbound_realtime_event(...)` (with `event.message_id` populated) so pre-decryption deduplication intercepts duplicates **before** invoking `RatchetSessionManager::decrypt_payload_from_device(...)` or `SenderKeyEngine::decrypt(...)`.

### 19.3 Headless & Offscreen Verification Notes
- On CI or headless macOS/Linux hosts without an active display server, always pass `QT_QPA_PLATFORM=offscreen` when running `securecloud_client_foundation_test` or `securecloud-client --smoke-test`.
- When loading `SettingsPlaceholder.qml` standalone in `QQmlComponent` unit tests (outside `Main.qml`), `Theme` singleton warnings appear in stderr if `Theme.qml` is not registered, while `readReceiptsSwitch` binding to `workspaceViewModel.readReceiptsEnabled` remains fully operational.

---

## 20. `DefaultGatewayClient` Simulation Hooks & `SqlCipherLocalStore` Persistence Interaction

### 20.1 `DefaultGatewayClient` Deterministic Simulation Hooks
`DefaultGatewayClient` (`src/client/infrastructure/adapters/default_gateway_client.hpp/.cpp`) enables full end-to-end verification of `CLIENT-010` without launching Docker, ScyllaDB, or external HTTP servers:

| Method | Purpose | Used By |
|---|---|---|
| `set_simulated_failure(bool, std::string)` | Simulates complete Gateway unavailability across all REST endpoints | `RealtimeGatewayContractsTest`, `ClientGatewayTest` |
| `set_simulated_submission_failure(bool, std::string)` | Simulates transient `503` / network failures exclusively on `submit_encrypted_message(...)` while keeping prekey directory lookups operational | `DeliveryRetryEngineTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario2` & `Scenario5` |
| `set_simulated_delivery_status(MessageId, MessageDeliveryStatusInfo)` | Configures authoritative server delivery status returned by `get_message_delivery_status(...)` | `RealtimeGatewayContractsTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario3` |
| `set_simulated_conversation_messages(ConversationId, std::vector<RealtimeEvent>)` | Seeds ordered `server_sequence_number` events for incremental `fetch_conversation_messages(..., since_sequence, max_results)` polling | `RealtimeGatewayContractsTest`, `WorkspaceViewModelRealtimeTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario1`, `Scenario2`, `Scenario4` |
| `emit_realtime_event(const RealtimeEvent&)` | Invokes all active `subscribe_realtime_events` callbacks under snapshot-copied lock safety | `RealtimeGatewayContractsTest`, `WorkspaceViewModelRealtimeTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario1` |
| `sent_delivery_acks()` / `sent_read_receipts()` / `clear_sent_receipts()` | Records every `acknowledge_delivery` and `send_read_receipt` call for strict assertion of privacy suppression vs. transport ACK emission | `RealtimeGatewayContractsTest`, `DeliveryAckAndReadReceiptTest`, `WorkspaceViewModelRealtimeTest`, `RealtimeDeliveryAndReceiptsIntegrationTest` |

### 20.2 `MockGatewayClient` Interface Parity (`tests/unit/client/client_domain_test.cpp`)
`MockGatewayClient` implements all six `CLIENT-010-T01` pure virtual methods on `IGatewayClient`:
- `acknowledge_delivery(...)` → returns `DeliveryState::Delivered`
- `send_read_receipt(...)` → returns `DeliveryState::Read`
- `get_message_delivery_status(...)` → returns `MessageDeliveryStatusInfo` with `DeliveryState::Delivered`
- `fetch_conversation_messages(...)` → returns empty `ConversationMessagesPage` echoing `since_sequence`
- `subscribe_realtime_events(...)` → returns subscription ID `1`
- `unsubscribe_realtime_events(...)` → no-op

### 20.3 `SqlCipherLocalStore` & `ISecureStorage` Persistence Guarantees
1. **Message State & Sequence Durability**:
   - Every `Message` persisted in `SqlCipherLocalStore`'s `messages` table serializes `delivery_state_` and `server_sequence_number_` inside SQLCipher AES-256-CBC + HMAC-SHA512 encrypted pages.
   - `update_message_delivery_state(...)` calls `local_store_.update_message(msg)` only when `delivery_state_` or `server_sequence_number_` actually advances, avoiding redundant disk writes while guaranteeing that `Accepted`, `Delivered`, `Read`, and `Failed` states survive process restarts (`Scenario 5`).
2. **Conversation Unread Count & Activity Timestamps**:
   - `persist_inbound_message(...)` atomically updates `last_activity_at` and increments `unread_count`, while `mark_conversation_read(...)` persists `unread_count = 0` to `SqlCipherLocalStore`.
3. **Encrypted Privacy Policy Persistence**:
   - `ReadReceiptPolicy` (`messaging.privacy.send_read_receipts`) is stored in `ISecureStorage` rather than plaintext QSettings/INI files, ensuring user privacy preferences remain protected alongside cryptographic key material across application restarts (`DeliveryAckAndReadReceiptTest`, `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario5`).

---

## 21. Final Verification Summary

| Gate | Command / Target | Result |
|---|---|---|
| **Code Formatting** | `ninja -C build/dev-debug check-format` | **1,032 / 1,032** C++ files compliant (`0` diffs) |
| **Compiler Warnings** | `ninja -C build/dev-debug securecloud-client securecloud_client_foundation_test` | **0 warnings** (`-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`) |
| **CLIENT-010 Integration Suite** | `RealtimeDeliveryAndReceiptsIntegrationTest.*` | **5 / 5 passed** (`79 ms`) |
| **Full Client Test Suite** | `securecloud_client_foundation_test` | **287 / 287 passed** across **80** test suites (`966 ms`) |
| **Desktop Client Smoke Test** | `QT_QPA_PLATFORM=offscreen ./build/dev-debug/src/client/securecloud-client --smoke-test` | **Passed** (`QML engine loaded`, clean shutdown) |

---

## 22. Thread-Safety, Locking & Lifecycle Analysis

1. **`DeliveryRetryEngine` (`src/client/application/managers/delivery_retry_engine.cpp`)**:
   - Protects `config_`, `rng_`, and `queue_` under `std::mutex mutex_`.
   - `process_due(...)` copies due and expired entries under lock, releases `mutex_`, invokes `expire_fn` / `submit_fn`, and re-acquires `mutex_` only when re-queueing transient `ClientErrorCategory::Network` failures — guaranteeing zero lock inversion or re-entrant deadlock if `submit_fn` or `expire_fn` accesses `MessagingManager` or `ILocalStore`.
2. **`DefaultGatewayClient` (`src/client/infrastructure/adapters/default_gateway_client.cpp`)**:
   - Protects `next_subscription_id_` and `event_subscribers_` under `std::mutex event_mutex_`.
   - `emit_realtime_event(...)` snapshots active `RealtimeEventHandler` callbacks under lock and invokes them outside the lock, so a subscriber calling `unsubscribe_realtime_events(...)` during dispatch cannot deadlock.
3. **`WorkspaceViewModel` (`src/client/ui/workspace_view_model.cpp`)**:
   - Captures `QPointer<WorkspaceViewModel> self(this)` in the `subscribe_realtime_events` lambda and posts UI mutations via `QMetaObject::invokeMethod(self.data(), ..., Qt::QueuedConnection)`.
   - `~WorkspaceViewModel()` explicitly calls `unsubscribe_realtime_events(realtime_sub_id_)` before destruction, preventing dangling callbacks after view-model teardown.
4. **`SyncManager` (`src/client/application/managers/sync_manager.cpp`)**:
   - Guards active sync state with `std::atomic<bool> is_syncing_{false}` and updates `conversation_cursors_` monotonically (`page.latest_sequence > since_seq`).
5. **`SqlCipherLocalStore` (`src/client/infrastructure/adapters/sqlcipher_local_store.cpp`)**:
   - Serializes all SQLite/SQLCipher handle operations under `std::mutex mutex_` and cleanses key buffers on scope exit via `SecretCleanseGuard` (`OPENSSL_cleanse`).

---

## 23. Cross-Platform CI/CD Compatibility Notes (`macOS`, `Linux`, `Windows MSVC`, `Windows MSYS2 UCRT64`)

1. **Zero Platform-Specific Networking or OS Dependencies in `CLIENT-010`**:
   - `DeliveryRetryEngine`, `RealtimeEvent` models, `MessagingManager` deduplication/receipts, and `SyncManager::poll_realtime_updates` use standard C++20 (`<chrono>`, `<mutex>`, `<random>`, `<atomic>`, `<optional>`) and `Qt6::Core` (`QMetaObject::invokeMethod`, `QPointer`), compiling identically on macOS (`clang++`), Ubuntu (`g++`/`clang++`), Windows MSVC (`vcpkg`), and Windows MSYS2 `UCRT64` (`g++ 15+`).
2. **Qt 6 Headless / Offscreen Testing**:
   - All QML and `QCoreApplication::processEvents()` tests (`WorkspaceViewModelRealtimeTest` and `RealtimeDeliveryAndReceiptsIntegrationTest::Scenario4`) execute cleanly under `QT_QPA_PLATFORM=offscreen` without requiring X11, Wayland, or a physical display.
3. **Strict Compiler Warning Compliance**:
   - All `CLIENT-010` headers, implementations, and test suites compile with zero warnings under `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wunused -Woverloaded-virtual` (macOS/Linux/MinGW) and `/W4 /WX` (MSVC).
4. **Formatting Compliance**:
   - All `1,032` C++ files pass `ninja -C build/dev-debug check-format` against the repository `.clang-format` configuration.

---

## 24. Glossary of `CLIENT-010` Terms & Identifiers

- **`idempotency_key` (`ClientMessageId`)**: Client-generated unique submission token preserved across `DeliveryRetryEngine` retries so the Gateway/Messaging service deduplicates retried `POST /api/v1/messages` calls (`ADR-007 §7`).
- **`server_sequence_number`**: Monotonic sequence number assigned by the backend Messaging service (`ADR-007 §6`), stored locally in `SqlCipherLocalStore` and passed back as `since_sequence` during `SyncManager::poll_realtime_updates`.
- **`DeliveryAck`**: Transport-level acknowledgement (`POST /api/v1/messages/:id/ack`) emitted automatically upon inbound decryption and local persistence, independent of read privacy (`ADR-007 §11`).
- **`ReadReceipt`**: User-level read notification (`POST /api/v1/conversations/:cid/messages/:mid/read`) emitted when a conversation is opened and `ReadReceiptPolicy::send_read_receipts_enabled` is `true`.
- **`DeliveryRetryEngine`**: Bounded, thread-safe Client → Gateway retry queue using exponential backoff with mandatory randomized jitter (`ADR-007 §13`) and expiration to `DeliveryState::Failed` (`ADR-007 §14`).
- **`readReceiptsSwitch`**: Qt Quick `Switch` in `SettingsPlaceholder.qml` bound to `WorkspaceViewModel::readReceiptsEnabled` (`Q_PROPERTY`) and persisted in `ISecureStorage` under `messaging.privacy.send_read_receipts`.
