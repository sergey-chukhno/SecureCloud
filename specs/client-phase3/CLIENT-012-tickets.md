# CLIENT-012 Ticket Decomposition: Offline Operation & Catch-Up Sync

- **Milestone Card:** `CLIENT-012` — Offline Operation & Catch-Up Sync (Desktop Client Phase 3 Finale)
- **Phase:** Desktop Client Phase 3 (`CLIENT-009` – `CLIENT-012`)
- **Target Branch:** `feature/client-012-offline-operation-and-catch-up-sync`
- **Owner:** Sergey
- **Dependencies:** `CLIENT-008` (Contact Directory & Key Verification), `CLIENT-009` (Direct & Group Messaging Engine, `SqlCipherLocalStore`), `CLIENT-010` (Real-Time Delivery, `DeliveryRetryEngine`, Read Receipts), `CLIENT-011` (Encrypted File Transfer & Resumable Checkpoints), `MSG-009` (`SyncDeviceMessages`, `GetSyncCursor`, `UpdateSyncCursor`), `GW-009` (`MessagingProxyHandler`), `ADR-004` (HTTPS REST/JSON external, gRPC internal), `ADR-007` (Message Reliability, Ordering & Idempotency), `ADR-008` (Zero-Plaintext & Double Ratchet Safety), `ADR-009` (Distributed Failure Resilience)

---

## 1. Executive Summary & Architectural Overview

`CLIENT-012` completes **Desktop Client Phase 3** by making the SecureCloud Desktop Client (`securecloud-client`) resilient to network outages, intermittent drops, and application restarts while offline. Users can compose 1:1 and group messages, read conversations, and stage file transfers while disconnected; all pending outbound operations and per-conversation sequence cursors are persisted inside the encrypted `SqlCipherLocalStore`. When connectivity returns, `SyncManager` automatically transitions through `Offline -> Syncing -> Online`, drains the durable offline outbox in priority and chronological order, executes paginated catch-up synchronization against the Gateway, and reconciles missed messages, delivery/read states, conversations, contacts, and interrupted file transfers without duplicates or data loss.

```text
┌──────────────────────────────────┐     ┌──────────────────────────────────┐     ┌──────────────────────────────────┐
│   WorkspaceViewModel & QML UI    │     │  SyncManager & Connectivity FSM  │     │  Gateway MessagingProxyHandler   │
│  - Connectivity Banner & Badge   │◀───▶│  - Online / Offline / Syncing    │────▶│  - GET /health                   │
│    (Online / Syncing / Offline)  │     │  - Gateway Reachability Observer │     │  - GET /api/v1/conversations     │
│  - Offline Message Drafting      │     │  - Paginated Catch-Up Engine     │     │  - GET .../messages?since_seq=   │
│  - Pending Outbox Counter Badge  │     │  - Conflict-Free Reconciliation  │◀────│  - GET/PUT /api/v1/devices/      │
│  - One-Click Reconnect & Sync    │     └────────┬────────────────┬────────┘     │            :deviceId/cursor      │
└──────────────────────────────────┘              │                │              └──────────────────────────────────┘
                                                  ▼                ▼
                                    ┌───────────────────┐  ┌───────────────────┐
                                    │ MessagingManager  │  │    FileManager    │
                                    │ & ContactManager  │  │ (Auto-Resume /    │
                                    │ (Pre-Encrypted    │  │  Key Envelope     │
                                    │  Outbox Replay &  │  │  Outbox Replay)   │
                                    │  Idempotent Merge)│  └─────────┬─────────┘
                                    └─────────┬─────────┘            │
                                              └──────────┬───────────┘
                                                         ▼
                                    ┌──────────────────────────────────────────┐
                                    │  SqlCipherLocalStore (AES-256 + HMAC)    │
                                    │  - conversations, messages, contacts     │
                                    │  - file_transfers (CLIENT-011)           │
                                    │  - offline_outbox (NEW: durable queue)   │
                                    │  - sync_cursors   (NEW: sequence state)  │
                                    └──────────────────────────────────────────┘
```

### Ticket Status Matrix

| Ticket | Title | Status | Target Scope |
|---|---|---|---|
| **CLIENT-012-T01** | Connectivity State, Durable Outbox & Sync Cursor Domain Models + `IGatewayClient` Catch-Up Sync Contracts | **Completed** | `ConnectivityState`, `OfflineOutboxOperationType`, `OfflineOutboxRecord`, `SyncCursorRecord`, `CatchUpSyncReport`, `IGatewayClient` & `DefaultGatewayClient` cursor/conversation/pagination sync contracts |
| **CLIENT-012-T02** | Durable Offline Outbox & Sync Cursor Persistence in `ILocalStore` & `SqlCipherLocalStore` | **Completed** | `offline_outbox` and `sync_cursors` tables in `SqlCipherLocalStore` (and `MemoryLocalStore`), `ILocalStore` CRUD interfaces, zero-plaintext `.db` verification |
| **CLIENT-012-T03** | Durable Offline Outbox Queueing & Ordered Replay in `MessagingManager`, `DeliveryRetryEngine` & `FileManager` | **Completed** | Persist pre-encrypted outbound messages, delivery ACKs, read receipts, and file key envelopes in `offline_outbox`; hydrate on startup; priority + FIFO replay without ratchet re-stepping |
| **CLIENT-012-T04** | Connectivity Observer (`Online` / `Offline` / `Syncing`) & Paginated Catch-Up Reconciliation Engine in `SyncManager` | **Completed** | Gateway probe observer, `Online`/`Offline`/`Syncing` state machine, multi-page `has_more` catch-up loop, remote conversation/contact reconciliation, durable cursor checkpointing |
| **CLIENT-012-T05** | `WorkspaceViewModel` & `AppViewModel` Connectivity/Outbox Bindings & QML Offline/Syncing Banner UI | **Completed** | `connectivityState`, `isOffline`, `isSyncing`, `pendingOutboxCount`, `setSimulatedOfflineMode`, `triggerCatchUpSync`, Workspace Offline/Syncing banner & footer indicators |
| **CLIENT-012-T06** | Offline Operation & Catch-Up Sync E2E Integration Suite, Tier 1/2 Smoke Tests & Walkthrough Report | **Planned** | 5-scenario E2E integration suite (`offline_catchup_sync_integration_test.cpp`), Tier 1 `--smoke-test`, Tier 2 `--capture-screenshots`, `walkthrough-client-012.md`, `docs/pull_requests/CLIENT-012.md` |

---

## 2. Architecture, Backend & Codebase Audit: What Already Exists vs. Net-New Scope

### 2.1 Crucial Backend & Gateway Alignment Finding (`MSG-009` Routes vs. Early Backlog Note)

Early notes in `docs/planning/initial-backlog.md` (line 758) used shorthand `GET /api/v1/sync?cursor=<cursor>`, whereas the **actual implemented backend** (`MessagingProxyHandler` in `src/gateway/http/proxy/messaging_proxy_handler.cpp` lines 239–413, 1315–1600 and `proto/securecloud/messaging/v1/messaging.proto` lines 293–329, 419–423) implements **MSG-009 Device Synchronization and Resumption** through per-conversation sequence cursors:

1. **Paginated Device Message Catch-Up (`MessagingService::SyncDeviceMessages`)**:
   - **Gateway Route**: `GET /api/v1/conversations/:id/messages?since_sequence=<seq>&max_messages=<limit>&device_id=<device_id>` (`MessagingProxyHandler::handle_sync_messages`).
   - **Response JSON**:
     ```json
     {
       "device_id": "dev-...",
       "conversation_id": "conv-...",
       "has_more": true,
       "next_sequence": 51,
       "latest_sequence": 120,
       "messages": [ ... ],
       "cursor": {
         "device_id": "dev-...",
         "conversation_id": "conv-...",
         "last_delivered_sequence": 50,
         "last_sync_timestamp_unix_ms": 1763590000000
       }
     }
     ```
2. **Remote Sync Cursor Retrieval (`MessagingService::GetSyncCursor`)**:
   - **Gateway Route**: `GET /api/v1/devices/:deviceId/cursor?conversation_id=<cid>` (`MessagingProxyHandler::handle_get_sync_cursor`).
   - **Response JSON**: `{"device_id": "...", "conversation_id": "...", "last_delivered_sequence": 50, "last_sync_timestamp_unix_ms": ...}`.
3. **Remote Sync Cursor Checkpoint Update (`MessagingService::UpdateSyncCursor`)**:
   - **Gateway Route**: `PUT /api/v1/devices/:deviceId/cursor` (`MessagingProxyHandler::handle_update_sync_cursor`).
   - **Request JSON**: `{"conversation_id": "...", "last_delivered_sequence": 120, "last_sync_timestamp_unix_ms": ...}`.
4. **Remote Conversation Discovery (`MessagingService::ListConversations`)**:
   - **Gateway Route**: `GET /api/v1/conversations?max_results=<limit>&page_token=<token>` (`MessagingProxyHandler::handle_list_conversations`).

**Design Solution (`CLIENT-012-T01` & `T04`)**:
- Extend `IGatewayClient` and `DefaultGatewayClient` with `get_sync_cursor`, `update_sync_cursor`, and `list_remote_conversations`, and enhance `domain::ConversationMessagesPage` with `next_sequence` and optional `SyncCursorRecord` so `SyncManager` matches the implemented `MessagingProxyHandler` JSON contract 1:1.
- Retain and wire `IGatewayClient::sync_messages(cursor)` as a convenience cross-conversation delta wrapper so callers using either per-conversation cursors or an encoded composite cursor token are supported cleanly.

---

### 2.2 Already Implemented on Client (Do NOT Re-Implement)

1. **In-Memory Session Retry Queue (`DeliveryRetryEngine`, `CLIENT-010-T03`)**:
   - `src/client/application/managers/delivery_retry_engine.{hpp,cpp}` already computes bounded exponential backoff with mandatory `±25%` randomized jitter (`ADR-007 §13`), tracks `attempt_count` and `expires_at` (`ADR-007 §14`), and executes `process_due(...)`.
   - **How `CLIENT-012` Reuses It**: `DeliveryRetryEngine` remains the in-memory backoff scheduler; `CLIENT-012` backs it with durable `offline_outbox` persistence in `ILocalStore` so queued entries survive app restarts and extend to offline delivery ACKs, read receipts, and file key envelopes.
2. **Monotonic Delivery State Machine & Inbound Deduplication (`CLIENT-010-T02`)**:
   - `domain::can_transition_delivery_state` (`src/client/domain/delivery_state.cpp`) already blocks backward state regressions (`Read -> Delivered` or `Delivered -> Accepted`).
   - `MessagingManager::persist_inbound_message` (`src/client/application/managers/messaging_manager.cpp`) already deduplicates re-delivered messages by `message_id` and `idempotency_key` (`ADR-007 §2`).
3. **Encrypted SQLCipher Local Database (`SqlCipherLocalStore`, `CLIENT-009-T02` & `CLIENT-011-T03`)**:
   - `src/client/infrastructure/adapters/sqlcipher_local_store.{hpp,cpp}` already manages an AES-256-CBC + HMAC-SHA512 database (`conversations`, `messages`, `contacts`, `file_transfers`) keyed by `local_store.sqlcipher.master_key` in `ISecureStorage`.
   - **How `CLIENT-012` Reuses It**: Add `offline_outbox` and `sync_cursors` tables to `SqlCipherLocalStore::initialize_schema_locked()` (and `MemoryLocalStore`) instead of creating any separate database file.
4. **Resumable Encrypted File Transfers (`FileManager`, `CLIENT-011-T04`)**:
   - `src/client/application/managers/file_manager.{hpp,cpp}` already persists `FileTransferRecord` chunk progress (`completed_chunks`, `upload_id`, `file_id`, `status`) in `ILocalStore` and provides `resume_transfer(transfer_id)`.
5. **Contact Directory & Identity Key Change Detection (`ContactManager`, `CLIENT-008`)**:
   - `src/client/application/managers/contact_manager.{hpp,cpp}` already provides `sync_contacts()`, `evaluate_contact_key_change(...)`, and `resolve_contact_presence(...)`.
6. **Existing `SyncManager` Polling Dispatcher (`src/client/application/managers/sync_manager.{hpp,cpp}`, `CLIENT-010-T05`)**:
   - Already wired in `ClientBootstrap::wire_managers()` (`src/client/application/client_bootstrap.cpp:72-73`) with `poll_realtime_updates(local_device_id)`.

---

### 2.3 Net-New Scope & Concrete Gaps Closed by `CLIENT-012`

1. **Volatile In-Memory Retry Queue & Dropped Offline Receipts**:
   - Currently, `DeliveryRetryEngine::queue_` lives only in RAM (`delivery_retry_engine.hpp:54`). If the user composes messages while offline and closes the app, the encrypted `FanOutSubmissionRequest` envelopes in `queue_` are lost (leaving orphan `LocalPending` messages in `messages` without their pre-encrypted per-device payloads).
   - Furthermore, `MessagingManager::dispatch_delivery_ack_if_configured` (`messaging_manager.cpp:153`) and `MessagingManager::mark_conversation_read` (`messaging_manager.cpp:376`) ignore return values from `gateway_.acknowledge_delivery(...)` and `gateway_.send_read_receipt(...)`. If called while offline, delivery ACKs and read receipts are silently dropped and never re-sent on reconnect.
2. **Critical Cryptographic Invariant — Never Re-Step Ratchets on Outbox Replay (`ADR-008`)**:
   - When `MessagingManager::stage_outbound_message` encrypts a 1:1 message (`RatchetSessionManager::encrypt_fanout_for_participants`) or group message (`SenderKeyEngine::encrypt`), the Double Ratchet / Sender Key sending chain advances immediately and is saved to `ISecureStorage`.
   - Therefore, the durable `offline_outbox` record **must store the already-encrypted `FanOutSubmissionRequest` ciphertext bundle** (and `idempotency_key`) inside SQLCipher, so replaying the outbox after an app restart transmits the exact original ciphertext and idempotency key without stepping the ratchet a second time!
3. **Volatile Sync Cursors & Single-Page (`50`-Event) Truncation in `SyncManager`**:
   - `SyncManager::conversation_cursors_` (`sync_manager.hpp:40`) is an in-memory `std::unordered_map` that resets to `0` on every application restart.
   - `SyncManager::poll_realtime_updates` (`sync_manager.cpp:55`) fetches at most 1 page of 50 events (`fetch_conversation_messages(cid, local_device_id, since_seq, 50)`) and ignores `page.has_more`, leaving behind missed events when more than 50 messages accumulated during an offline period, and never checkpoints the cursor to `ILocalStore` or Gateway `PUT /api/v1/devices/:deviceId/cursor`.
4. **No Connectivity State Machine (`Online` / `Offline` / `Syncing`) or Reconnection Trigger**:
   - `SyncManager` has only a boolean `is_syncing_` flag. There is no `ConnectivityState` (`Online`, `Offline`, `Syncing`), no Gateway health/error observer that flips to `Offline` on `ClientErrorCategory::Network` and triggers `Offline -> Syncing -> Online` catch-up when connectivity returns, and no coordination with `ContactManager`, `FileManager`, or remote conversation discovery (`list_remote_conversations`).
5. **No Offline / Syncing UI Banner or Outbox Status Bindings**:
   - `AppViewModel::connectionStatus_` (`app_view_model.hpp:69`) is hardcoded to `"Connected"` after login, and `WorkspaceViewModel` / `WorkspacePlaceholder.qml` do not expose `connectivityState`, `isOffline`, `isSyncing`, `pendingOutboxCount`, an offline drafting/syncing banner, or a reconnect/sync action.

---

## 3. Detailed Ticket Specifications (`CLIENT-012-T01` – `CLIENT-012-T06`)

### CLIENT-012-T01: Connectivity State, Durable Outbox & Sync Cursor Domain Models + `IGatewayClient` Catch-Up Sync Contracts

- **Component:** `src/client/domain/offline_sync_models.hpp/.cpp`, `src/client/domain/realtime_events.hpp`, `src/client/application/interfaces/i_gateway_client.hpp`, `src/client/infrastructure/adapters/default_gateway_client.hpp/.cpp`, `tests/unit/client/offline_sync_contracts_test.cpp`
- **Objective:** Define strongly typed domain models for connectivity states, durable offline outbox records, per-conversation device sync cursors, and reconciliation reports, and extend `IGatewayClient` / `DefaultGatewayClient` with the MSG-009 cursor and conversation catch-up contracts.
- **Architectural Scope:**
  1. Create `src/client/domain/offline_sync_models.hpp` and `.cpp`:
     - `enum class ConnectivityState { Online, Offline, Syncing };` with `to_string` / `connectivity_state_from_string` and valid transition validation.
     - `enum class OfflineOutboxOperationType { EncryptedMessageSubmission, DeliveryAck, ReadReceipt, FileKeyEnvelopeSubmission };` with string conversions.
     - `struct OfflineOutboxRecord`:
       - `std::string outbox_id`
       - `OfflineOutboxOperationType operation_type`
       - `ConversationId conversation_id`
       - `MessageId message_id`
       - `std::string transfer_id`
       - `std::string idempotency_key`
       - `int32_t priority{0}` (`0/1` = Normal, `2` = Urgent, `3` = Emergency)
       - `std::string payload_json` (serialized `FanOutSubmissionRequest`, `DeliveryAckRecord`, or `ReadReceiptRecord`)
       - `uint32_t attempt_count{0}`
       - `int64_t created_at_ms{0}`
       - `int64_t next_retry_at_ms{0}`
       - `int64_t expires_at_ms{0}`
       - `std::string last_error`
       - `to_json()` / `from_json()` round-trip serialization.
     - `struct SyncCursorRecord`:
       - `DeviceId device_id`
       - `ConversationId conversation_id`
       - `uint64_t last_delivered_sequence{0}`
       - `int64_t last_sync_timestamp_ms{0}`
       - `int32_t sync_version{1}`
       - `to_json()` / `from_json()` round-trip serialization.
     - `struct RemoteConversationSummary`:
       - `ConversationId conversation_id`
       - `ConversationType type{ConversationType::Direct}`
       - `std::string title`
       - `UserId creator_user_id`
       - `int64_t created_at_ms{0}`
       - `std::vector<UserId> participant_user_ids`
     - `struct CatchUpSyncReport`:
       - `std::size_t outbox_flushed_count{0}`
       - `std::size_t outbox_remaining_count{0}`
       - `std::size_t messages_merged_count{0}`
       - `std::size_t duplicates_skipped_count{0}`
       - `std::size_t conversations_reconciled_count{0}`
       - `std::size_t contacts_reconciled_count{0}`
       - `std::size_t transfers_resumed_count{0}`
  2. Enhance `domain::ConversationMessagesPage` (`src/client/domain/realtime_events.hpp`):
     - Add `uint64_t next_sequence{0};` and `std::optional<SyncCursorRecord> cursor{std::nullopt};` (backward-compatible default initializers).
  3. Extend `IGatewayClient` (`src/client/application/interfaces/i_gateway_client.hpp`), `DefaultGatewayClient` (`src/client/infrastructure/adapters/default_gateway_client.{hpp,cpp}`), and `MockGatewayClient` (`tests/unit/client/client_domain_test.cpp`):
     - `get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id)` (`GET /api/v1/devices/:deviceId/cursor?conversation_id=...`)
     - `update_sync_cursor(const domain::SyncCursorRecord& cursor)` (`PUT /api/v1/devices/:deviceId/cursor`)
     - `list_remote_conversations(const domain::UserId& user_id, std::size_t max_results = 100)` (`GET /api/v1/conversations`)
     - Enhance `DefaultGatewayClient::fetch_conversation_messages` to support multi-page slicing (`since_sequence`, `max_results`, `has_more`, `next_sequence`, `latest_sequence`) over `simulated_conversation_messages_`, and add test hooks `set_simulated_remote_conversations(...)` and `set_simulated_sync_cursor(...)`.
- **Acceptance Criteria:**
  - `OfflineOutboxRecord` and `SyncCursorRecord` serialize/deserialize losslessly via JSON, including full `FanOutSubmissionRequest` per-device payloads and group envelope bytes.
  - `DefaultGatewayClient::fetch_conversation_messages` paginates arbitrarily large event vectors (`> 100` events) deterministically via `since_sequence` and `max_results`.
  - All existing unit tests compile and pass with zero regressions.

---

### CLIENT-012-T02: Durable Offline Outbox & Sync Cursor Persistence in `ILocalStore` & `SqlCipherLocalStore`

- **Component:** `src/client/application/interfaces/i_local_store.hpp`, `src/client/infrastructure/adapters/sqlcipher_local_store.hpp/.cpp`, `src/client/infrastructure/adapters/memory_local_store.hpp/.cpp`, `tests/unit/client/offline_outbox_persistence_test.cpp`
- **Objective:** Persist offline outbox operations and per-conversation device sync cursors inside the encrypted SQLCipher database (`SqlCipherLocalStore`) and in-memory test adapter (`MemoryLocalStore`).
- **Architectural Scope:**
  1. Extend `SqlCipherLocalStore::initialize_schema_locked()` (`src/client/infrastructure/adapters/sqlcipher_local_store.cpp`):
     ```sql
     CREATE TABLE IF NOT EXISTS offline_outbox (
         outbox_id TEXT PRIMARY KEY,
         operation_type TEXT NOT NULL,
         conversation_id TEXT NOT NULL,
         priority INTEGER NOT NULL DEFAULT 0,
         created_at_ms INTEGER NOT NULL,
         payload_json TEXT NOT NULL
     );
     CREATE INDEX IF NOT EXISTS idx_offline_outbox_order
         ON offline_outbox(priority DESC, created_at_ms ASC);

     CREATE TABLE IF NOT EXISTS sync_cursors (
         device_id TEXT NOT NULL,
         conversation_id TEXT NOT NULL,
         last_delivered_sequence INTEGER NOT NULL DEFAULT 0,
         updated_at_ms INTEGER NOT NULL,
         payload_json TEXT NOT NULL,
         PRIMARY KEY (device_id, conversation_id)
     );
     ```
  2. Extend `ILocalStore` (`src/client/application/interfaces/i_local_store.hpp`) with:
     - `save_outbox_record(const domain::OfflineOutboxRecord& record)`
     - `get_outbox_record(std::string_view outbox_id)`
     - `list_outbox_records(std::size_t limit = 500)` (ordered deterministically by `priority DESC, created_at_ms ASC, outbox_id ASC`)
     - `delete_outbox_record(std::string_view outbox_id)`
     - `save_sync_cursor(const domain::SyncCursorRecord& cursor)` (enforcing monotonic `last_delivered_sequence >= existing.last_delivered_sequence` guard)
     - `get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id)`
     - `list_sync_cursors(const domain::DeviceId& device_id)`
  3. Implement all 7 methods in both `SqlCipherLocalStore` and `MemoryLocalStore`.
- **Acceptance Criteria:**
  - Outbox records and sync cursors persist across `SqlCipherLocalStore::close()` and `open()` cycles.
  - `save_sync_cursor` enforces monotonic sequence advancement (`ADR-007`: a stale sequence `< existing` never regresses the stored cursor).
  - Raw file inspection of the `.db` file on disk confirms zero plaintext substring leakage of `outbox_id`, `conversation_id`, or `idempotency_key`.

---

### CLIENT-012-T03: Durable Offline Outbox Queueing & Ordered Replay in `MessagingManager`, `DeliveryRetryEngine` & `FileManager`

- **Component:** `src/client/application/managers/messaging_manager.hpp/.cpp`, `src/client/application/managers/delivery_retry_engine.hpp/.cpp`, `src/client/application/managers/file_manager.hpp/.cpp`, `tests/unit/client/offline_outbox_replay_test.cpp`
- **Objective:** Ensure all outbound operations initiated while offline (or during transient network failure) are durably queued in `ILocalStore`, hydrated across restarts, and flushed in priority + FIFO order upon reconnection without re-stepping cryptographic ratchets.
- **Architectural Scope:**
  1. **Pre-Encrypted Message Outbox Persistence (`MessagingManager::stage_outbound_message`)**:
     - When `gateway_.submit_encrypted_message(req)` fails with `ClientErrorCategory::Network` (or when `MessagingManager` is notified that connectivity is `Offline`), save the message with `DeliveryState::LocalPending` in `messages` **and** persist an `OfflineOutboxRecord` (`EncryptedMessageSubmission`) containing the pre-encrypted `FanOutSubmissionRequest` and `idempotency_key` into `local_store_.save_outbox_record(...)` as well as `retry_engine_`.
     - **Cryptographic Safety Invariant (`ADR-008`)**: Because `req` already holds the encrypted per-device Double Ratchet / Sender Key payloads, replaying the outbox record after an app restart submits `req` directly to `gateway_.submit_encrypted_message(req)` without re-invoking `RatchetSessionManager` or `SenderKeyEngine`.
  2. **Durable Offline Delivery ACKs & Privacy-Gated Read Receipts**:
     - In `MessagingManager::dispatch_delivery_ack_if_configured`: if `gateway_.acknowledge_delivery(...)` returns a `Network` error, enqueue an `OfflineOutboxRecord` (`DeliveryAck`) in `local_store_`.
     - In `MessagingManager::mark_conversation_read`: always reset local `unread_count` to `0` immediately; if `read_receipts_enabled()` is `true` and `gateway_.send_read_receipt(...)` fails with a `Network` error, enqueue an `OfflineOutboxRecord` (`ReadReceipt`) in `local_store_`. (If `read_receipts_enabled()` is subsequently toggled `false` before flush, discard queued `ReadReceipt` outbox records to honor user privacy).
  3. **Startup Hydration & Ordered Outbox Drain (`MessagingManager::flush_offline_outbox` / `hydrate_offline_outbox`)**:
     - On `MessagingManager` construction / store open, hydrate pending `OfflineOutboxRecord` rows from `local_store_.list_outbox_records()`.
     - Implement `flush_offline_outbox(std::chrono::steady_clock::time_point now)` (and integrate with `process_retry_queue`):
       - Iterates pending outbox records ordered by `priority DESC, created_at_ms ASC`.
       - Dispatches `EncryptedMessageSubmission` / `FileKeyEnvelopeSubmission` via `gateway_.submit_encrypted_message(...)`, `DeliveryAck` via `gateway_.acknowledge_delivery(...)`, and `ReadReceipt` via `gateway_.send_read_receipt(...)`.
       - On success: deletes the `OfflineOutboxRecord` from `local_store_`, removes from `retry_engine_`, and transitions the message's `DeliveryState` monotonically (`LocalPending -> Accepted`).
       - On transient `Network` failure: increments `attempt_count`, computes jittered backoff via `retry_engine_.compute_backoff(attempt_count)`, updates `next_retry_at_ms` in `local_store_`, and stops flushing if the Gateway is unreachable.
       - On expiration (`attempt_count >= max_attempts` or `now > expires_at`): marks message `DeliveryState::Failed` and removes from active auto-retry while keeping manual `retry_failed_message` working (re-using the stored `OfflineOutboxRecord` payload so manual retry after restart also works!).
  4. **Interrupted File Transfer Coordination (`FileManager`)**:
     - Add `FileManager::resume_interrupted_transfers()` which inspects `list_transfers()` for transfers left in `InProgress` or `Pending` with network errors and resumes them (`resume_transfer(transfer_id)`) when called by `SyncManager` upon reconnection.
- **Acceptance Criteria:**
  - Outbound 1:1 and group messages composed while offline survive destroying and recreating `MessagingManager` against the same `SqlCipherLocalStore`, flushing with their original `idempotency_key` and ciphertext without advancing the Double Ratchet or Sender Key step counter twice.
  - Read receipts and delivery ACKs generated while offline flush automatically on reconnect (and queued read receipts are suppressed if `read_receipts_enabled` was turned off before reconnect).
  - High-priority (`Emergency` / `Urgent`) queued messages flush ahead of `Normal` queued messages across conversations, while preserving strict chronological order within each conversation.

---

### CLIENT-012-T04: Connectivity Observer (`Online` / `Offline` / `Syncing`) & Paginated Catch-Up Reconciliation Engine in `SyncManager`

- **Component:** `src/client/application/managers/sync_manager.hpp/.cpp`, `src/client/application/client_bootstrap.hpp/.cpp`, `tests/unit/client/catchup_sync_reconciliation_test.cpp`
- **Objective:** Transform `SyncManager` into an authoritative connectivity state machine (`Online` / `Offline` / `Syncing`) and multi-page catch-up synchronization coordinator across `MessagingManager`, `ContactManager`, and `FileManager`.
- **Architectural Scope:**
  1. **Dependency Wiring (`ClientBootstrap::wire_managers`)**:
     - Wire `SyncManager` with `ILocalStore*`, `MessagingManager*`, `ContactManager*`, and `FileManager*`.
  2. **Connectivity Observer & State Machine (`SyncManager`)**:
     - Maintain `domain::ConnectivityState connectivity_state_{domain::ConnectivityState::Online}` and support `subscribe_connectivity_state(ConnectivityStateCallback)` / `unsubscribe_connectivity_state(...)`.
     - Implement `check_connectivity()` (probing `gateway_.probe_gateway("/health")`) and `set_simulated_offline(bool offline)`:
       - When transitioning from `Online -> Offline`: emit `ConnectivityState::Offline`.
       - When transitioning from `Offline -> Online` (probe succeeds after outage or `set_simulated_offline(false)`): automatically transition `Offline -> Syncing`, execute `execute_catch_up_sync(local_user_id, local_device_id)`, and upon success transition `Syncing -> Online` (or revert `Syncing -> Offline` if a network failure occurs mid-sync).
  3. **Four-Phase Catch-Up Synchronization & Reconciliation Protocol (`SyncManager::execute_catch_up_sync`)**:
     - **Phase 1 — Cursor Hydration & Remote Floor Check**:
       - Load all local `SyncCursorRecord` entries for `local_device_id` from `local_store_->list_sync_cursors(local_device_id)` into `conversation_cursors_`.
       - For any known conversation lacking a local cursor, query `gateway_.get_sync_cursor(local_device_id, cid)` and persist the baseline cursor.
     - **Phase 2 — Durable Offline Outbox Flush & Transfer Resumption**:
       - Call `messaging_manager_->flush_offline_outbox()` to drain all due queued messages, delivery ACKs, and read receipts.
       - If `file_manager_` is wired, invoke `file_manager_->resume_interrupted_transfers()`.
     - **Phase 3 — Remote Conversation & Contact Reconciliation**:
       - Query `gateway_.list_remote_conversations(local_user_id)` and merge with `local_store_->list_conversations()`:
         - New remote conversations are inserted into `ILocalStore`.
         - Existing conversations update their title and participant roster while **preserving** local `unread_count`, `sender_key_epoch` (`max(local, remote)`), and last activity timestamps.
       - If `contact_manager_` is wired, invoke `contact_manager_->sync_contacts()` (which preserves local verification badges and triggers `KeyChanged` alerts per `ADR-008` if any peer identity key rotated while the client was offline).
     - **Phase 4 — Multi-Page Per-Conversation Delta Catch-Up**:
       - For each conversation, loop `gateway_.fetch_conversation_messages(cid, local_device_id, since_seq, page_limit)`:
         - Process every `RealtimeEvent` in chronological sequence order via `messaging_manager_->process_inbound_realtime_event(ev)` (and if an inbound message contains a `FileAttachmentKeyEnvelope` JSON payload, auto-register the inbound file transfer in `file_manager_->ingest_inbound_key_envelope_json(...)`).
         - Track `messages_merged_count` vs. `duplicates_skipped_count`.
         - Advance `since_seq` monotonically to `std::max(since_seq, page.next_sequence > 0 ? page.next_sequence : page.latest_sequence)`.
         - Persist updated `SyncCursorRecord` to `local_store_->save_sync_cursor(...)` and `gateway_.update_sync_cursor(...)` after each committed page.
         - Continue looping while `page.has_more == true` (bounded by a safety max-pages cap per sync cycle, e.g., `100` pages, to prevent infinite loops on malformed server responses).
- **Acceptance Criteria:**
  - `SyncManager` transitions `Online -> Offline -> Syncing -> Online` deterministically and notifies all registered callbacks.
  - Multi-page catch-up (`> 3` pages with `has_more = true`) fetches every page without gaps, persists the final `SyncCursorRecord` to `ILocalStore` and Gateway, and resumes from that exact cursor on subsequent sync cycles.
  - Concurrent contact/conversation updates merge without overwriting local verification status (`Verified` / `KeyChanged`) or losing local unread counts.

---

### CLIENT-012-T05: `WorkspaceViewModel` & `AppViewModel` Connectivity/Outbox Bindings & QML Offline/Syncing Banner UI

- **Component:** `src/client/ui/workspace_view_model.hpp/.cpp`, `src/client/ui/app_view_model.hpp/.cpp`, `src/client/ui/qml/Main.qml`, `src/client/ui/qml/WorkspacePlaceholder.qml`, `tests/unit/client/workspace_view_model_offline_sync_test.cpp`
- **Objective:** Expose live connectivity state (`Online` / `Offline` / `Syncing`), pending offline outbox counts, and manual reconnect/offline toggle controls to QML, and render an intuitive Offline / Catch-Up Sync banner and status indicators in the desktop UI.
- **Architectural Scope:**
  1. **Extend `WorkspaceViewModel` (`src/client/ui/workspace_view_model.{hpp,cpp}`)**:
     - Add properties:
       - `Q_PROPERTY(QString connectivityState READ connectivityState NOTIFY connectivityStateChanged)` (`"Online"`, `"Offline"`, `"Syncing"`)
       - `Q_PROPERTY(bool isOffline READ isOffline NOTIFY connectivityStateChanged)`
       - `Q_PROPERTY(bool isSyncing READ isSyncing NOTIFY connectivityStateChanged)`
       - `Q_PROPERTY(int pendingOutboxCount READ pendingOutboxCount NOTIFY pendingOutboxCountChanged)`
       - `Q_PROPERTY(QString syncStatusSummary READ syncStatusSummary NOTIFY connectivityStateChanged)`
     - Add QML-invokable actions:
       - `Q_INVOKABLE void setSimulatedOfflineMode(bool offline)` (connects `SyncManager::set_simulated_offline` and `DefaultGatewayClient::set_simulated_failure`, triggering automatic catch-up sync when toggled back to `false`!)
       - `Q_INVOKABLE bool triggerCatchUpSync()` (runs `SyncManager::execute_catch_up_sync` and refreshes conversations, messages, contacts, file transfers, and outbox counters)
     - Subscribe `WorkspaceViewModel` to `SyncManager::subscribe_connectivity_state(...)` using `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` so connectivity and outbox updates marshal safely onto the Qt UI thread.
  2. **Synchronize `AppViewModel` (`src/client/ui/app_view_model.{hpp,cpp}`)**:
     - Reflect `SyncManager` connectivity state in `AppViewModel::connectionStatus()` (`"Online"`, `"Offline"`, `"Syncing"`) and `sessionStatusText()` so the application window header and footer in `Main.qml` stay in sync with the workspace.
  3. **Update `WorkspacePlaceholder.qml` & `Main.qml`**:
     - Add a compact, high-contrast **Connectivity & Offline Outbox Banner** at the top of Zone 3 in `WorkspacePlaceholder.qml` (visible when `wvm.isOffline || wvm.isSyncing || wvm.pendingOutboxCount > 0`):
       - When `isOffline`: amber warning banner showing `"Offline Mode — Messages & receipts are encrypted and queued locally (%1 in outbox)"` with a `"Reconnect & Sync"` button (`wvm.setSimulatedOfflineMode(false)`).
       - When `isSyncing`: accent info banner showing `"Catch-Up Sync Active — Reconciling encrypted outbox & missed sequence delta..."`.
     - Add a quick Connectivity Status / Offline Mode toggle pill in the Zone 2 / Zone 3 header (and `Main.qml` footer status indicator) so operators can inspect pending outbox counts or trigger catch-up sync with one click.
- **Acceptance Criteria:**
  - Composing messages while `isOffline == true` appends them immediately to `activeMessages` with `deliveryState == "LocalPending"`, increments `pendingOutboxCount`, and displays the Offline Outbox banner in QML.
  - Calling `setSimulatedOfflineMode(false)` (or clicking `"Reconnect & Sync"`) transitions `connectivityState` through `"Syncing"` to `"Online"`, drains `pendingOutboxCount` to `0`, advances queued messages to `"Accepted"`, and merges any missed remote messages into `activeMessages`.
  - Zero QML engine warnings or binding loops in headless offscreen tests.

---

### CLIENT-012-T06: Offline Operation & Catch-Up Sync E2E Integration Suite, Tier 1/2 Smoke Tests & Walkthrough Report

- **Component:** `tests/unit/client/offline_catchup_sync_integration_test.cpp`, `tests/unit/client/CMakeLists.txt`, `docs/final-reports/walkthrough-client-012.md`, `docs/pull_requests/CLIENT-012.md`
- **Objective:** Validate the complete offline operation and catch-up sync architecture end-to-end across multi-workstation simulation, SQLCipher persistence restarts, multi-page catch-up, conflict reconciliation, and real client Tier 1/Tier 2 smoke tests.
- **Architectural Scope:**
  1. Create `tests/unit/client/offline_catchup_sync_integration_test.cpp` covering 5 end-to-end scenarios:
     - **Scenario 1 — Offline Drafting, App Restart & Ordered Pre-Encrypted Outbox Flush**:
       - Alice goes `Offline`, composes 3 direct messages (including 1 `Urgent` and 1 `Emergency` message), 1 group message, and marks a conversation read (`ReadReceipt` queued).
       - Destroy Alice's `MessagingManager` and `SyncManager` and reopen against the same `SqlCipherLocalStore` `.db` file on disk.
       - Reconnect Alice (`set_simulated_offline(false)`): verify all queued operations flush in priority + FIFO order using their original pre-encrypted ciphertexts and `idempotency_key`s, Bob decrypts all messages with his Double Ratchet / Sender Key session (proving zero double-ratchet stepping!), and Alice's outbox table becomes empty.
     - **Scenario 2 — Multi-Page Catch-Up Synchronization (`has_more = true`) & Durable Cursor Checkpointing**:
       - While Alice is offline, 125 encrypted events ( across 3 pages of 50, 50, 25) accumulate on the Gateway across multiple conversations.
       - On reconnect, `SyncManager` loops through all 3 pages using `since_sequence`, decrypts all 125 events in exact order, updates `SyncCursorRecord` in `SqlCipherLocalStore` and on Gateway (`PUT /api/v1/devices/:deviceId/cursor`), and a subsequent sync cycle fetches `0` redundant events.
     - **Scenario 3 — Idempotent Deduplication & Monotonic Delivery/Read State Merge**:
       - Re-deliver overlapping events via both real-time push and catch-up sync pages, plus out-of-order `Delivered` after `Read`; assert zero duplicate messages in `ILocalStore` and zero backward state regressions.
     - **Scenario 4 — Remote Conversation, Group Membership, Contact Key-Change & Interrupted File Transfer Reconciliation**:
       - While offline, a new remote group conversation is created, an existing contact rotates their identity key (`ADR-008` `KeyChanged`), and an active encrypted file upload was interrupted at chunk `2/4`.
       - On reconnect catch-up sync: verify the new group conversation appears locally, the contact transitions to `KeyChanged` (blocking further unverified sends until acknowledged), and the interrupted file transfer resumes cleanly from chunk `2` to `4/4` (`Completed`).
     - **Scenario 5 — Full `WorkspaceViewModel` & `AppViewModel` Reactive UI Lifecycle**:
       - Drive offline drafting → outbox counter increment → reconnect → `Offline -> Syncing -> Online` transition → merged incoming messages through `WorkspaceViewModel` and `AppViewModel`, verifying all Qt signals and properties.
  2. Execute **Tier 1 (`--smoke-test`)** and **Tier 2 (`--capture-screenshots`)** verification on the real `securecloud-client` binary (`0` QML warnings, `24/24` screenshots).
  3. Author `docs/final-reports/walkthrough-client-012.md` (with plain-language objective & architecture explanations for each ticket `T01`–`T06` and embedded smoke test verification) and `docs/pull_requests/CLIENT-012.md`.
- **Acceptance Criteria:**
  - All 5 E2E scenarios in `offline_catchup_sync_integration_test.cpp` and 100% of repository CTest suites pass.
  - Tier 1 `--smoke-test` exits `0` and Tier 2 `--capture-screenshots` renders all views cleanly with zero QML warnings.
  - `check-format` (`100%` `.clang-format` adherence) and `-Wall -Wextra -Wpedantic -Werror` build pass with `0` warnings.

---

## 4. Architectural Invariants & Non-Goals

1. **Zero Ratchet Re-Stepping on Offline Replay (`ADR-008`)**:
   - Outbound messages composed offline are encrypted once at composition time; `offline_outbox` stores the resulting `FanOutSubmissionRequest` ciphertext bundle and `idempotency_key`. Replaying the outbox after a network drop or application restart never re-encrypts or advances the Double Ratchet / Sender Key chain a second time.
2. **Monotonic Cursors & Monotonic Delivery States (`ADR-007`)**:
   - Per-conversation `SyncCursorRecord::last_delivered_sequence` and message `DeliveryState` advance strictly monotonically. Re-delivered catch-up packets never create duplicate UI messages or regress `Read -> Delivered`.
3. **Zero Plaintext Outside SQLCipher (`ADR-008 §22`)**:
   - `offline_outbox` and `sync_cursors` reside inside the encrypted `SqlCipherLocalStore` database keyed by `ISecureStorage`. No plaintext drafts, message bodies, or metadata are ever written to unencrypted files.
4. **Phase Boundary Between Phase 3 (`CLIENT-012`) and Phase 4 (`CLIENT-013`–`CLIENT-016`)**:
   - `CLIENT-012` completes Phase 3 (offline outbox durability, connectivity state machine, paginated catch-up sync, and state reconciliation).
   - Forensic panic destruction / duress wipe belongs to **`CLIENT-013`**, full user profile & settings persistence to **`CLIENT-014`**, live backend E2E hardening & CPU/RAM performance benchmarking to **`CLIENT-015`**, and signed desktop release installers to **`CLIENT-016`**.
5. **Code Hygiene & Host Isolation**:
   - All unit and integration tests run completely in-process with `DefaultGatewayClient`, `OpenSslCryptoProvider`, and `SqlCipherLocalStore` (zero external Docker containers or host ports required).
   - Zero compiler warnings (`-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`) and `100%` `.clang-format` compliance.

---

## 5. Verification & Completion Gate Commands

```bash
# 1. Configure & build all client + test targets with -Werror
cmake --build build --parallel

# 2. Run all CLIENT-012 unit & E2E integration suites
ctest --test-dir build --output-on-failure -R "offline_sync_contracts_test|offline_outbox_persistence_test|offline_outbox_replay_test|catchup_sync_reconciliation_test|workspace_view_model_offline_sync_test|offline_catchup_sync_integration_test"

# 3. Run full repository CTest gate + Tier 1 & Tier 2 real-binary smoke tests
ctest --test-dir build --output-on-failure
./build/src/client/securecloud-client --smoke-test
./build/src/client/securecloud-client --capture-screenshots /tmp/sc-client012-shots

# 4. Verify 100% clang-format compliance
cmake --build build --target check-format
```
