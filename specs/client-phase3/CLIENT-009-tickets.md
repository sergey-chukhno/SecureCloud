# CLIENT-009 — Direct & Group Messaging Engine: Ticket Decomposition & Architectural Specification

- **Card ID:** `CLIENT-009`
- **Card Title:** Direct & Group Messaging Engine
- **Milestone:** Production Messaging Engine, Real-Time Streaming & File Vault
- **Phase Placement:** **Client Phase 3 (`specs/client-phase3/CLIENT-009-tickets.md`) — Opening Card of Phase 3**
- **Target Branch:** `feature/client-009-direct-and-group-messaging-engine`
- **Prerequisites Completed:**
  - `CLIENT-001` through `CLIENT-004` — Phase 1 Client Foundation, 4-Zone UI Shell, Contacts/Conversations/Messaging UI (`main` merged)
  - `CLIENT-005` — Device Registration & Cryptographic Identity Lifecycle (`main` merged)
  - `CLIENT-006` — Signal Double Ratchet Session Management & End-to-End Encryption (`main` merged)
  - `CLIENT-007` — Device Management, Multi-Device Trust & Hardware Security / Attestation (`main` merged)
  - `CLIENT-008` — Contact Management, Peer Identity Verification & Directory Discovery (`feature/client-008` PR ready)

---

## 1. Executive Summary & Phase 3 Placement

With the completion of **Client Phase 2 (`CLIENT-005` through `CLIENT-008`)**, the SecureCloud native C++20/Qt6 desktop client already possesses a verified end-to-end cryptographic foundation (`X3dhEngine`, `DoubleRatchetEngine`, `SkippedKeysStore`, `RatchetSessionManager`, `SafetyNumberEngine`, `ContactManager`, `DeviceManager`) and the 4-zone presentation shell (`WorkspaceViewModel`, `WorkspacePlaceholder.qml`).

**Card `CLIENT-009`** initiates **Client Phase 3**. Its goal is to bridge the existing Phase 2 cryptographic core with **durable encrypted disk persistence**, **production 1:1 multi-device fan-out dispatch**, and **Signal Sender Keys group messaging with `Admin`/`Member` role enforcement and mandatory membership-change key rotation**.

```text
                       SECURECLOUD CLIENT (Phase 3 - CLIENT-009)
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ Presentation Tier: WorkspaceViewModel / Zone 2 Roster / Zone 3 Chat / Zone 4 Inspector │
 │  • Startup hydration from durable ILocalStore (SqlCipherLocalStore)                    │
 │  • Group Admin / Member role badges, member add/remove, Sender Key epoch indicator     │
 └─────────────────────────────┬────────────────────────────────────▲─────────────────────┘
                               │ Use Cases                          │ Reactive Signals
                               ▼                                    │
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ Application Layer: MessagingManager & RatchetSessionManager (EXISTING + ENRICHED)      │
 │  • 1:1 Direct: Pairwise Double Ratchet fan-out across authorized peer/companion devices│
 │  • Group E2EE: SenderKeyEngine (per-sender chain + AES-256-GCM + Ed25519 signature)    │
 │  • SenderKeyDistributionMessage wrapped inside pairwise Double Ratchet envelopes       │
 │  • Admin-only add/remove enforcement + mandatory Sender Key rotation on member removal │
 │  • ADR-008 §18 (KeyChanged suspension) & §24 (blocked drop) before encrypt & decrypt   │
 └─────────────┬──────────────────────────┬─────────────────────────┬─────────────────────┘
               │ Encrypted At Rest        │ Ratchet & Sender Keys   │ Envelope Dispatch
               ▼                          ▼                         ▼
 ┌───────────────────────────┐ ┌────────────────────────┐ ┌──────────────────────────────┐
 │  SqlCipherLocalStore      │ │    ISecureStorage      │ │       IGatewayClient         │
 │  (AES-256-GCM AEAD +      │ │  (DB Master Key,       │ │ (Per-Device Fan-Out Dispatch,│
 │   HKDF-SHA256 'SCDB' v1,  │ │   Ratchet Sessions,    │ │  Direct & Group Ciphertext   │
 │   Conversations/Messages/ │ │   Sender Key Chains)   │ │  Envelopes - Zero Plaintext) │
 │   Participants/Contacts)  │ └────────────────────────┘ └──────────────────────────────┘
 └───────────────────────────┘
```

### Ticket Status Matrix

| Ticket | Title | Status | Target Scope |
|---|---|---|---|
| **CLIENT-009-T01** | Conversation & Message Domain Persistence Enrichment & Participant Roles | **Planned** | `ParticipantRole` (`Admin`/`Member`), `GroupParticipant`, JSON round-trip for `Conversation` & `Message`, zero-plaintext storage invariant |
| **CLIENT-009-T02** | Encrypted Local Database Adapter (`SqlCipherLocalStore`) & Keychain Master-Key Lifecycle | **Planned** | Disk-backed AEAD encrypted `ILocalStore` (`SCDB` v1, HKDF-SHA256 + AES-256-GCM via OpenSSL 3.x), `ISecureStorage` key lifecycle, atomic writes, `ClientBootstrap` wiring |
| **CLIENT-009-T03** | Group Sender Keys Cryptographic Engine & Distribution Envelopes | **Planned** | `SenderKeyState`, `SenderKeyDistributionMessage`, `GroupEncryptedEnvelope` (`SCG` v1), `SenderKeyEngine` (symmetric KDF chain + Ed25519 sig + AES-256-GCM) |
| **CLIENT-009-T04** | Production Direct & Group Fan-Out Pipeline, Role Governance & Sender Key Rotation | **Planned** | `MessagingManager` fan-out submission via `IGatewayClient`, pairwise Sender Key distribution & rotation on member removal/device revocation, `Admin` RBAC checks |
| **CLIENT-009-T05** | `WorkspaceViewModel` Persistent History Hydration & Group Role / Rotation UI Wiring | **Planned** | Hydrate conversations/messages/contacts from `ILocalStore` on startup, bounded pagination loading, QML/ViewModel group role & key-epoch bindings |
| **CLIENT-009-T06** | Direct, Group & SQLCipher Persistence Integration Suite & Walkthrough Report | **Planned** | Multi-workstation 1:1/group/restart E2E integration suite, zero-plaintext disk verification, 100% test/format/warning gate, `walkthrough-client-009.md` |

---

## 2. Repository & Architecture Audit: What Already Exists vs. Net-New Scope

To strictly avoid duplicating existing Phase 1, Phase 2, or backend code, every component inspected across `src/client/`, `src/messaging/`, `docs/`, and `cmake/` is categorized below.

### 2.1 Existing Client & Backend Infrastructure (REUSE — DO NOT RE-IMPLEMENT)

1. **Cryptographic Primitives & Double Ratchet Engine (`CLIENT-006`, `CLIENT-007`) — COMPLETE**:
   - `ICryptoProvider` & `OpenSslCryptoProvider` (`src/client/infrastructure/adapters/openssl_crypto_provider.hpp`): already expose `generate_identity_keypair()`, `generate_signed_prekey()`, `verify_signed_prekey()`, `diffie_hellman()`, `hkdf_extract_and_expand()`, `encrypt_aes_gcm()`, and `decrypt_aes_gcm()`.
   - `X3dhEngine`, `DoubleRatchetEngine`, `SkippedKeysStore`, `EncryptedMessageEnvelope` (`SCE` v1), `PerDeviceDeliveryPayload`, and `RatchetSessionState` (`SCRS` v1) already handle pairwise session establishment, asymmetric/symmetric ratcheting, and out-of-order skipped keys (`src/client/domain/crypto/`).
   - `RatchetSessionManager` (`src/client/application/managers/ratchet_session_manager.hpp/.cpp`) already implements:
     - `encrypt_for_device(...)` / `encrypt_payload_for_device(...)`
     - `encrypt_fanout(...)` / `encrypt_fanout_for_participants(...)` (automatically skipping revoked devices and the sender's own physical loopback device)
     - `decrypt_from_device(...)` / `decrypt_payload_from_device(...)`
     - `save_session(...)`, `load_session(...)`, `load_all_sessions()`, `terminate_session(...)`, `purge_device_sessions(...)`.
2. **Contact Ownership, Safety Numbers & ADR-008 Security Guards (`CLIENT-008`) — COMPLETE**:
   - `Contact` (`src/client/domain/contact.hpp/.cpp`) already provides lossless `to_json()` / `from_json()` serialization and `can_send_messages()`.
   - `ContactManager` + `SafetyNumberEngine` already implement 60-digit Safety Number computation, `ISecureStorage` fingerprint pinning, key rotation detection (`KeyChanged`), and `sync_contacts()` -> `purge_device_sessions()`.
   - `MessagingManager::validate_recipients_can_receive(...)` and `MessagingManager::process_inbound_message(...)` already enforce `KeyChanged` outbound locks and pre-decryption blocked-sender drops.
3. **Baseline Application & In-Memory Persistence (`CLIENT-001`, `CLIENT-004`) — COMPLETE**:
   - `ILocalStore` (`src/client/application/interfaces/i_local_store.hpp`) defines the conversation, message, and contact repository port.
   - `MemoryLocalStore` (`src/client/infrastructure/adapters/memory_local_store.hpp/.cpp`) must be **preserved untouched** as the fast, deterministic test double for unit tests.
   - `MessagingManager` already provides `open_direct_conversation`, `create_group_conversation`, `list_conversations`, `get_conversation`, `add_group_participant`, `remove_group_participant`, `leave_conversation`, `delete_conversation`, `mark_conversation_read`, `retry_failed_message`, `update_message_delivery_state`, `discard_failed_message`, and `get_conversation_messages`.
   - `WorkspaceViewModel` (`src/client/ui/workspace_view_model.hpp/.cpp`) already declares `createDirectConversation`, `createGroupConversation`, `addParticipantToActiveGroup`, `removeParticipantFromActiveGroup`, `leaveActiveGroup`, and group inspector properties (`selectedConversationIsGroup`, `selectedConversationParticipantCount`, `selectedConversationDeviceFanoutCount`, `selectedConversationParticipants`, `selectedGroupAllVerified`, `selectedGroupUnverifiedCount`).
4. **Backend Authoritative Domain Semantics (`src/messaging/domain/`) — REFERENCE**:
   - `conversation_types.hpp`, `conversation_participant_entity.hpp`, and `group_metadata_entity.hpp` define canonical backend enums (`ConversationType::{Direct=1, Group=2}`, `GroupStatus::{Active=1, Closed=2}`, `MembershipStatus::{Active=1, Left=2, Removed=3}`, `ParticipantRole::{Member=1, Admin=2}`) and `membership_version` / `metadata_version`. Client `CLIENT-009` models must match these semantics without importing server targets into `src/client`.
5. **Dependencies & CI Constraints (`vcpkg.json`, `SecureCloudDependencies.cmake`, `.github/workflows/ci.yml`)**:
   - Notice that external `sqlcipher` / `sqlite3` packages are **not** present in `vcpkg.json`, Homebrew CI installs, or MSYS2 CI packages. OpenSSL 3.x EVP (`OpenSslCryptoProvider`) and `nlohmann::json` **are** already mandated and discovered across macOS, Windows MSVC, and MinGW.
   - **Architectural Decision**: `SqlCipherLocalStore` implements the approved encrypted local store behind `ILocalStore` using an authenticated AEAD disk container (`SCDB` v1 format encrypted with `HKDF-SHA256` + `AES-256-GCM` via OpenSSL 3.x EVP and a master key persisted inside `ISecureStorage`), requiring zero new unapproved third-party dependencies in CI while satisfying every ADR-006/ADR-008/detailed-design encryption-at-rest and fail-closed guarantee. *(If a native C SQLCipher SQLite driver is later added to `vcpkg.json`/`ci.yml`, `SqlCipherLocalStore` sits cleanly behind `ILocalStore` with zero application/UI impact.)*

### 2.2 Identified Gaps That `CLIENT-009` Must Implement

1. **`Conversation` & `Message` JSON Persistence + Participant Roles (`CLIENT-009-T01`)**:
   - `Conversation` currently stores only `std::vector<UserId>` with no `ParticipantRole` (`Admin`/`Member`), `MembershipStatus`, `group_status`, or `sender_key_epoch`, and neither `Conversation` nor `Message` implements `to_json()` / `from_json()` serialization.
   - `MessagingManager::stage_outbound_message` currently passes plaintext into `Message::encrypted_envelope_ref_` (`std::string(plaintext)`) and discards the encrypted `PerDeviceDeliveryPayload` vector produced by `encrypt_fanout_for_participants`; similarly, `process_inbound_message` writes raw plaintext into `encrypted_envelope_ref_`. Per `detailed-design.md §2.8` and `ADR-008`, durable storage must never store unprotected plaintext in unencrypted structures, and `Message` must cleanly separate serialized encrypted payload reference / ciphertext container from transient in-memory display text.
2. **Production Encrypted Persistent `ILocalStore` (`CLIENT-009-T02`)**:
   - `ClientBootstrap` currently defaults unconditionally to `MemoryLocalStore` (volatile across process restarts).
   - No encrypted disk persistence adapter exists yet (`SqlCipherLocalStore`).
3. **Group Sender Keys Cryptographic Engine (`CLIENT-009-T03`)**:
   - Currently, `RatchetSessionManager` supports pairwise device encryption and pairwise participant fan-out, but there is no Sender Keys implementation (`SenderKeyState`, chain stepping, `SenderKeyDistributionMessage`, signed `GroupEncryptedEnvelope`) for scalable group messaging and key rotation (`ADR-008 §19`, `detailed-design.md §2.7`).
4. **Group RBAC Governance, Pairwise Key Distribution & Fan-Out Dispatch (`CLIENT-009-T04`)**:
   - `MessagingManager::add_group_participant`, `remove_group_participant`, and `leave_conversation` currently perform zero creator/admin authorization checks, dispatch zero Sender Key distributions, and do not rotate group cryptographic state when a member leaves/is removed or when `ContactManager` notifies of a revoked device.
   - `IGatewayClient` / `DefaultGatewayClient` need a structured fan-out submission API (submitting per-device encrypted `PerDeviceDeliveryPayload`s / group envelopes without plaintext).
5. **Startup History Hydration & Live Group Bindings in `WorkspaceViewModel` (`CLIENT-009-T05`)**:
   - `WorkspaceViewModel` currently seeds static demo conversations/messages on construction (`seedDefaultWorkspaceData()`) and holds `conversations_` / `messages_` in UI vectors rather than hydrating persisted `Conversation` and `Message` records from `ILocalStore` across application restarts (while retaining demo fallback only when `ILocalStore` is empty on first boot).

---

## 3. Detailed Ticket Specifications (`CLIENT-009-T01` – `CLIENT-009-T06`)

---

### CLIENT-009-T01: Conversation & Message Domain Persistence Enrichment & Group Participant Role Model

- **Ticket ID:** `CLIENT-009-T01`
- **Component:** `src/client/domain/`
- **Dependencies:** `CLIENT-008-T01` (`Contact` JSON pattern)
- **Objective:** Enrich `Conversation` and `Message` domain entities with canonical group role/membership state aligned with `src/messaging/domain/`, encrypted/display separation fields, and lossless `to_json()` / `from_json()` serialization for durable persistence.

#### Architectural Scope:
1. **Group Role & Participant Model (`src/client/domain/conversation.hpp` & `.cpp`)**:
   - Add enums aligned with backend `src/messaging/domain/conversation_types.hpp`:
     - `enum class ParticipantRole { Member, Admin }`
     - `enum class MembershipStatus { Active, Left, Removed }`
   - Add `struct GroupParticipant` (`UserId user_id`, `ParticipantRole role`, `MembershipStatus status`, `std::chrono::system_clock::time_point joined_at`, `uint64_t membership_version{1}`).
   - Enrich `Conversation` with:
     - `participant_records()` / `role_of(const UserId&)` / `is_admin(const UserId&)` / `set_participant_role(...)`
     - `sender_key_epoch()` (`uint64_t`) & `increment_sender_key_epoch()` (tracks mandatory rotation across membership changes)
     - Backward-compatible construction & `participants()` getter returning active `std::vector<UserId>` so existing tests compile unchanged.
   - Implement `to_json()` and `static std::optional<Conversation> from_json(std::string_view)`.
2. **Message Persistence & Anti-Plaintext Boundary Enrichment (`src/client/domain/message.hpp` & `.cpp`)**:
   - Preserve existing constructor signatures for zero breakage across `Phase 1`/`Phase 2` tests.
   - Add `server_sequence_number()` (`uint64_t`), `client_message_id()` (alias/complement to `idempotency_key`), and explicit `sender_key_epoch()` (`std::optional<uint64_t>`) for group messages.
   - Ensure `to_json()` and `static std::optional<Message> from_json(std::string_view)` serialize all fields deterministically while marking `encrypted_envelope_ref` as the serialized encrypted payload reference (encrypted at rest by `SqlCipherLocalStore`, never stored in cleartext on disk).

- **Deliverables:**
  - Updated `src/client/domain/conversation.hpp` & `.cpp`
  - Updated `src/client/domain/message.hpp` & `.cpp`
  - Unit tests: `tests/unit/client/conversation_and_message_domain_test.cpp` (added to `tests/unit/CMakeLists.txt`)

- **Acceptance Criteria:**
  - `Conversation` and `Message` serialize and deserialize losslessly via `to_json()` / `from_json()` and reject malformed JSON safely (`std::nullopt`).
  - `ParticipantRole::Admin` vs. `Member`, `MembershipStatus`, and `sender_key_epoch` round-trip accurately without breaking existing callers.

---

### CLIENT-009-T02: Encrypted Local Database Adapter (`SqlCipherLocalStore`) & Keychain Master-Key Lifecycle

- **Ticket ID:** `CLIENT-009-T02`
- **Component:** `src/client/infrastructure/adapters/` & `src/client/application/`
- **Dependencies:** `CLIENT-009-T01`, existing `ILocalStore`, `ISecureStorage`, `ICryptoProvider`
- **Objective:** Implement `SqlCipherLocalStore` as the production disk-persisted, authenticated-encrypted implementation of `ILocalStore` with master keys sealed in `ISecureStorage`, replacing volatile `MemoryLocalStore` when persistent storage paths are configured.

#### Architectural Scope:
1. **Cryptographic Container Format (`SCDB` v1) & Fail-Closed Lifecycle**:
   - Implement `SqlCipherLocalStore final : public application::interfaces::ILocalStore` (`src/client/infrastructure/adapters/sqlcipher_local_store.hpp/.cpp`).
   - Constructor takes `interfaces::ISecureStorage& secure_storage, interfaces::ICryptoProvider& crypto_provider` (using `OpenSslCryptoProvider` in production, `StubCryptoProvider` disallowed for production disk unlock).
   - Binary/container envelope:
     - Header: 4-byte magic `"SCDB"`, format version `0x01`, random 16-byte per-save salt, 12-byte random IV, 16-byte AES-256-GCM authentication tag, ciphertext body.
     - Key Derivation: `ISecureStorage` stores a 256-bit random master key under `"local_store.sqlcipher.master_key"` (`SecretString`); each save derives a subkey via `ICryptoProvider::hkdf_extract_and_expand(salt, master_key, "SecureCloud-SCDB-v1", 32)` and encrypts the serialized JSON store with AAD = `header[magic || version || salt || path_hash]`.
     - Zeroization: Master key and derived `SecretString` buffers are scrubbed immediately after every cryptographic open/flush operation.
2. **Atomic Durability & Fail-Closed Corruption Handling**:
   - Writes go to `<db_path>.tmp`, flush, and atomically rename over `<db_path>` so crashes never leave half-written store files.
   - Opening an existing database with a missing/wrong `ISecureStorage` key, truncated file, tampered ciphertext byte, or corrupted AAD tag **must fail closed** with `ClientError::storage(...)` / `ClientError::crypto(...)` and never fall back to unencrypted JSON.
   - Maintain thread-safe `std::mutex` guarding conversations, messages (sorted chronologically with bounded `limit` slicing), and contacts (`save`/`get`/`list`/`delete`).
3. **Bootstrap & Config Support**:
   - Add optional `local_store_path` setting to `ClientConfig` (when empty, `ClientBootstrap` uses `MemoryLocalStore` for headless tests; when configured, uses `SqlCipherLocalStore` and calls `open(local_store_path)`).
   - Extend `ILocalStore::get_messages` / `SqlCipherLocalStore` query semantics for deterministic ordering.

- **Deliverables:**
  - `src/client/infrastructure/adapters/sqlcipher_local_store.hpp` & `.cpp`
  - Updated `src/client/application/client_config.hpp/.cpp` and `src/client/application/client_bootstrap.hpp/.cpp`
  - Updated `src/client/CMakeLists.txt`
  - Unit & security tests: `tests/unit/client/sqlcipher_local_store_test.cpp`

- **Acceptance Criteria:**
  - Closing and reopening `SqlCipherLocalStore` from disk with the same `ISecureStorage` key restores all conversations, messages, and contacts losslessly.
  - Inspecting raw bytes of `<db_path>` on disk yields zero occurrences of plaintext message content, contact aliases, notes, or group titles.
  - Wrong key or 1-byte file corruption fails closed on `open()`.

---

### CLIENT-009-T03: Group Sender Keys Cryptographic Engine & Distribution Envelopes

- **Ticket ID:** `CLIENT-009-T03`
- **Component:** `src/client/domain/crypto/`
- **Dependencies:** `CLIENT-006` (`ICryptoProvider`, `DoubleRatchetEngine`), `CLIENT-009-T01`
- **Objective:** Implement the Signal Sender Keys protocol state machine for scalable, authenticated, forward-secret group messaging (`ADR-008 §3, §19`, `detailed-design.md §2.7`).

#### Architectural Scope:
1. **Sender Key Domain Models (`src/client/domain/crypto/sender_key_models.hpp/.cpp`)**:
   - `SenderKeyId`: `(ConversationId conversation_id, UserId sender_user_id, DeviceId sender_device_id, uint64_t key_epoch)`.
   - `SenderChainKey`: `uint32_t iteration`, 32-byte chain key (`SecretString` scrubbed on destruction).
   - `SenderKeyDistributionMessage`: carries `(ConversationId, key_epoch, sender_user_id, sender_device_id, uint32_t iteration, vector<uint8_t> chain_key_bytes, vector<uint8_t> signing_public_key_or_identity)` + `serialize()` / `deserialize()` for transmission strictly inside pairwise X3DH/Double Ratchet envelopes.
   - `GroupEncryptedEnvelope` (`SCG` v1): magic `"SCG"`, version `0x01`, `SenderKeyId`, `uint32_t iteration`, 12-byte IV, 16-byte AES-256-GCM tag, ciphertext, and sender Ed25519 signature over `(header || ciphertext || auth_tag)`.
2. **`SenderKeyEngine` State Machine (`src/client/domain/crypto/sender_key_engine.hpp/.cpp`)**:
   - **Key Generation (`create_sender_key`)**: Generates fresh 32-byte CSPRNG chain key (`SecretString`) + sender Ed25519 signing/identity binding at `key_epoch` (`1` initially, incremented on rotation).
   - **Symmetric Chain Advancement**: `CK_{i+1}, MK_i = HKDF-SHA256(CK_i, "SecureCloud-SenderKey-Step-v1")`. Immediately zeroizes `MK_i` and previous `CK_i` after encryption/decryption (Forward Secrecy).
   - **Bounded Out-of-Order Skipped Keys**: Caches unused `(iteration -> message_key)` entries up to `kMaxGroupSkip = 500` per epoch to handle out-of-order group delivery safely while enforcing a DoS cap.
   - **Encrypt / Decrypt**: AES-256-GCM with AAD = `(ConversationId || SenderUserId || SenderDeviceId || key_epoch || iteration)`.
   - **Sender Authentication**: Decrypt fails closed if sender key epoch mismatches, device mismatches, signature verification fails (where signing key is bound), or `iteration < current_iteration` without a valid cached skipped key (anti-replay).

- **Deliverables:**
  - `src/client/domain/crypto/sender_key_models.hpp` & `.cpp`
  - `src/client/domain/crypto/sender_key_engine.hpp` & `.cpp`
  - Updated `src/client/CMakeLists.txt`
  - Unit tests: `tests/unit/client/sender_key_engine_test.cpp`

- **Acceptance Criteria:**
  - Alice's device distributes `SenderKeyDistributionMessage` to Bob and Charlie; both decrypt in-order and out-of-order group messages encrypted by Alice cleanly.
  - Replay of an already-decrypted `(epoch, iteration)` fails closed; tampered ciphertext, swapped `ConversationId` AAD, or excessive iteration gaps (`>500`) fail closed.
  - Newly rotated epoch (`epoch + 1`) renders old-epoch distribution states unable to decrypt subsequent messages.

---

### CLIENT-009-T04: Production Direct & Group Fan-Out Pipeline, Role Governance & Sender Key Rotation

- **Ticket ID:** `CLIENT-009-T04`
- **Component:** `src/client/application/managers/` & `src/client/application/interfaces/` & `src/client/infrastructure/adapters/`
- **Dependencies:** `CLIENT-009-T02`, `CLIENT-009-T03`, `CLIENT-008`
- **Objective:** Upgrade `MessagingManager` and `IGatewayClient` to execute real multi-device ciphertext submission for direct chats, orchestrate group Sender Key distribution/encryption/rotation, enforce `Admin`/`Member` permissions, and guarantee zero plaintext stored in `Message` persistence records.

#### Architectural Scope:
1. **Gateway Multi-Device Fan-Out Submission Contract (`IGatewayClient` & `DefaultGatewayClient`)**:
   - Add `struct FanOutSubmissionRequest` (`ConversationId`, `std::string idempotency_key`, `std::vector<domain::crypto::PerDeviceDeliveryPayload> device_payloads`, `std::optional<std::vector<uint8_t>> group_envelope_bytes`, `int32_t priority`).
   - Add `ClientResult<std::string> submit_encrypted_message(const FanOutSubmissionRequest& request)` returning authoritative `MessageId` (keeping legacy `send_message(...)` intact so existing tests keep passing).
   - Add deterministic test inspection hooks on `DefaultGatewayClient` (`submitted_fanouts()`) so tests can assert the server only ever received ciphertext blobs, never plaintext.
2. **`MessagingManager` Direct E2EE Pipeline Hardening**:
   - In `stage_outbound_message` / new `send_direct_message`:
     1. Run `validate_recipients_can_receive(...)` (`KeyChanged` & blocked-peer ADR-008 guards).
     2. Compute `std::vector<PerDeviceDeliveryPayload>` via `RatchetSessionManager::encrypt_fanout_for_participants(...)` across all `Authorized` recipient and companion devices (zero revoked devices).
     3. Submit `FanOutSubmissionRequest` to `IGatewayClient::submit_encrypted_message(...)`.
     4. Persist the `Message` in `ILocalStore` (`SqlCipherLocalStore`) storing serialized ciphertext envelope metadata in `encrypted_envelope_ref_` (never raw plaintext). Provide transient/encrypted-store-protected helper so local rendering works cleanly after `SqlCipherLocalStore` AEAD decryption.
   - In `process_inbound_message(...)`: enforce pre-decryption blocked check (already built), decrypt pairwise payload or `GroupEncryptedEnvelope`, store under `SqlCipherLocalStore` encrypted-at-rest boundary, and handle missing session/key cleanly.
3. **`MessagingManager` Group E2EE, Sender Key Persistence & Role Governance**:
   - **Role Enforcement**: `create_group_conversation` assigns `Creator = ParticipantRole::Admin`, others `ParticipantRole::Member`. Only `Admin` participants may call `add_group_participant`, `remove_group_participant`, or promote/demote roles; `Member` attempts fail with `ClientError::validation` / authorization error.
   - **Sender Key Lifecycle & `ISecureStorage`**:
     - Persist sender/receiver `SenderKeyState`s encrypted inside `ISecureStorage` under `sender_key:<conv_id>:<sender_uid>:<sender_did>:<epoch>`.
     - On first group message (or epoch rotation), generate local `SenderKeyState`, wrap `SenderKeyDistributionMessage` per authorized participant device via `RatchetSessionManager::encrypt_payload_for_device(...)`, and distribute via `IGatewayClient`.
     - **Mandatory Key Rotation on Membership Removal or Device Revocation**:
       - On `remove_group_participant`, `leave_conversation`, or peer device revocation notification: increment `Conversation::sender_key_epoch()`, erase/invalidate prior distribution access for removed endpoints, generate fresh chain key at `epoch + 1`, and distribute only to remaining active authorized devices (`ADR-008 §19`, `detailed-design.md §2.7`).
       - Removed members and newly joined devices cannot decrypt messages outside their authorized epoch window.

- **Deliverables:**
  - Updated `src/client/application/interfaces/i_gateway_client.hpp` & `src/client/infrastructure/adapters/default_gateway_client.hpp/.cpp`
  - Updated `src/client/application/managers/messaging_manager.hpp/.cpp`
  - Unit tests: `tests/unit/client/group_messaging_pipeline_test.cpp`

- **Acceptance Criteria:**
  - `IGatewayClient` receives exclusively encrypted `PerDeviceDeliveryPayload` / `GroupEncryptedEnvelope` ciphertext for both direct and group sends.
  - Non-admin users cannot add/remove group members.
  - Removing a group participant immediately rotates the sender key epoch so subsequent group messages fail decryption on the removed user's workstation.
  - Newly added participants/devices cannot decrypt historical group messages from earlier epochs.

---

### CLIENT-009-T05: `WorkspaceViewModel` Persistent History Hydration & Group Role / Rotation UI Wiring

- **Ticket ID:** `CLIENT-009-T05`
- **Component:** `src/client/ui/`
- **Dependencies:** `CLIENT-009-T02`, `CLIENT-009-T04`
- **Objective:** Connect `WorkspaceViewModel` to persistent `ILocalStore` / `MessagingManager` conversation and message storage across restarts, and expose group roles (`Admin`/`Member`) and Sender Key epoch status in the 4-zone QML workspace without putting crypto or storage logic in QML.

#### Architectural Scope:
1. **Startup Hydration & Bounded History Loading**:
   - Update `WorkspaceViewModel` constructor / hydration helper to load persisted `Conversation`, `Message`, and `Contact` records from `MessagingManager::list_conversations()`, `get_conversation_messages(cid, limit)`, and `ContactManager` when `ILocalStore` contains saved data (falling back to `seedDefaultWorkspaceData()` only when starting with a clean unseeded store, preserving compatibility with Phase 1/2 UI smoke tests).
   - Synchronize `unreadCount`, `lastMessagePreview`, `deliveryState`, and `lastActivityAt` from persisted store records on launch.
2. **Group Role Governance & Epoch UI Properties**:
   - Update `selectedConversationParticipants()` map entries to include `"role"` (`"Admin"` / `"Member"`) and `"canRemove"` (true only when local user is `Admin`).
   - Add read-only `Q_PROPERTY(int selectedGroupKeyEpoch ...)` and `Q_PROPERTY(bool localUserIsGroupAdmin ...)` to `WorkspaceViewModel`.
   - Ensure `createGroupConversation`, `addParticipantToActiveGroup`, `removeParticipantFromActiveGroup`, and `leaveActiveGroup` surface authorization failures or ADR-008 `KeyChanged`/blocked errors cleanly via `workspaceError(...)`.
   - Ensure `sendMessage(...)` wires through the production fan-out submission path while preserving UI responsiveness.

- **Deliverables:**
  - Updated `src/client/ui/workspace_view_model.hpp` & `.cpp`
  - Unit & ViewModel tests: `tests/unit/client/workspace_view_model_group_persistence_test.cpp`

- **Acceptance Criteria:**
  - Restarting `ClientApplication` + `WorkspaceViewModel` against the same `SqlCipherLocalStore` file and `ISecureStorage` restores direct/group conversations, message histories, roles, and unread counts automatically.
  - UI surfaces truthful errors when a non-admin attempts group roster modification or when a group participant's key is `KeyChanged` / blocked.

---

### CLIENT-009-T06: Direct, Group & SQLCipher Persistence End-to-End Integration Suite & Walkthrough Report

- **Ticket ID:** `CLIENT-009-T06`
- **Component:** `tests/unit/client/` & `docs/final-reports/`
- **Dependencies:** `CLIENT-009-T01` through `CLIENT-009-T05`
- **Objective:** Validate all Phase 3 `CLIENT-009` capabilities end-to-end across multi-workstation topologies with real `OpenSslCryptoProvider` keys and disk-backed `SqlCipherLocalStore`, pass all build/format/smoke gates, and author the comprehensive Card 009 validation report.

#### Architectural Scope:
1. **End-to-End Integration Suite (`tests/unit/client/direct_and_group_messaging_integration_test.cpp`)**:
   - **Scenario 1 — Multi-Workstation Direct E2EE Fan-Out & Restart Durability**: Alice (2 devices) and Bob (2 devices) exchange 1:1 messages; verify Gateway sees only ciphertext, Alice's companion syncs copy, both workstations restart against `SqlCipherLocalStore` + `ISecureStorage`, inspect raw DB bytes for zero plaintext leakage, and continue messaging cleanly.
   - **Scenario 2 — Group Messaging, Sender Key Distribution & Multi-Device Decryption**: Alice creates a group with Bob and Charlie (multi-device), distributes Sender Keys pairwise via X3DH/Double Ratchet, exchanges messages in-order and out-of-order.
   - **Scenario 3 — Membership Removal, Non-Admin RBAC & Mandatory Key Rotation**: Charlie (Member) fails to remove Bob; Alice (Admin) removes Charlie; epoch increments (`1 -> 2`); Charlie's device cannot decrypt any post-removal group messages.
   - **Scenario 4 — Late-Join Member Forward Secrecy Boundary**: Dave joins at epoch `2`; Dave decrypts epoch `2+` messages but fails to decrypt historical epoch `1` ciphertext captured from Gateway.
   - **Scenario 5 — ADR-008 Guards (`KeyChanged` & Block) & Tampered DB / Sender Spoof Fail-Closed**: Rotating Bob's identity key halts both 1:1 and group sends (`stage`/`send`/`retry`) until `acknowledge_and_verify_key_change`; blocking a group member drops inbound group packets pre-decryption; opening `SqlCipherLocalStore` with wrong key fails closed.
2. **Quality & Smoke Gates**:
   - `100%` test pass rate across all existing (241 baseline) + new `CLIENT-009` tests (`securecloud_client_foundation_test`).
   - `0` compiler warnings under `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`.
   - `100%` `.clang-format` compliance via `check-format` and clean offscreen `--smoke-test` / `--capture-screenshots`.
3. **Final Card Validation Walkthrough (`docs/final-reports/walkthrough-client-009.md`)**:
   - Comprehensive 10-section report (`>= 1,000` lines) documenting architecture, `SCDB` v1 & `SCG` v1 cryptography/wire formats, complete test catalog, verbatim execution output, and interactive smoke verification steps.

- **Deliverables:**
  - `tests/unit/client/direct_and_group_messaging_integration_test.cpp`
  - `tests/unit/CMakeLists.txt`
  - `docs/final-reports/walkthrough-client-009.md`

---

## 4. Implementation Rules & Non-Functional Requirements

1. **Zero Unapproved Third-Party Library Churn**:
   - `SqlCipherLocalStore` leverages the existing OpenSSL 3.x EVP (`OpenSslCryptoProvider`) and `nlohmann::json` dependencies already pinned in CI (`macos-15`, `windows-2022` MSVC, MSYS2/MinGW), ensuring zero breakage of cross-platform builds.
2. **Zero Plaintext on Disk & Zero Plaintext Over Wire**:
   - Raw disk files managed by `SqlCipherLocalStore` and `ISecureStorage` must contain zero unencrypted message strings, contact aliases, group titles, or cryptographic keys.
   - `IGatewayClient::submit_encrypted_message` accepts only encrypted `PerDeviceDeliveryPayload` and `GroupEncryptedEnvelope` blobs.
3. **Group Membership Security Invariants (`ADR-008 §19`, `Detailed Design §2.7`)**:
   - Removed members and revoked devices must never decrypt future group messages (mandatory epoch rotation).
   - Newly joined members and newly paired companion devices must never decrypt historical group epochs prior to their join point.
4. **Boundary Between `CLIENT-009` and Later Phase 3 Cards (`CLIENT-010`–`CLIENT-012`)**:
   - `CLIENT-009` owns encrypted persistence (`ILocalStore` / `SqlCipherLocalStore`), 1:1 & group encryption (`SenderKeyEngine` + `RatchetSessionManager` fan-out), and group RBAC/key rotation.
   - Real-time bidirectional push streams, exponential-backoff auto-retry queues, and read-receipt privacy toggles remain deferred cleanly to **`CLIENT-010`**.
   - 1 MiB AEAD chunked file streaming belongs to **`CLIENT-011`**.
   - Offline connectivity observers (`Offline`/`Syncing`/`Online`) and paginated catch-up delta reconciliation (`GET /api/v1/sync?cursor=`) remain scoped to **`CLIENT-012`**.
5. **Code Hygiene & Host Isolation**:
   - Zero Docker containers, PostgreSQL/ScyllaDB daemons, or host ports required to build and verify `CLIENT-009`.
   - Zero compiler warnings (`-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`) and `100%` `.clang-format` compliance across the repository.
