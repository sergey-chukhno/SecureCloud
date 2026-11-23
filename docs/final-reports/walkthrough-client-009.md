# CLIENT-009 Validation Walkthrough Report: Direct & Group Messaging Engine, Sender Keys & SQLCipher Persistence

- **Card:** `CLIENT-009` (`CLIENT-009-T01` – `CLIENT-009-T06`)
- **Branch:** `feature/client-009-direct-and-group-messaging-engine`
- **Date:** 2026-11-17
- **Status:** Completed & Verified (`266 / 266` unit & integration tests passing, `0` compiler warnings, `100%` `.clang-format` compliance across `1,023` C++ files, clean offscreen `--smoke-test`)

---

## 1. Executive Summary

`CLIENT-009` upgrades the SecureCloud desktop client from in-memory messaging prototypes to an end-to-end encrypted, disk-persistent 1:1 and multi-party group messaging engine:

1. **Domain Persistence & Governance (`CLIENT-009-T01`)**: Enriched `Conversation`, `GroupParticipant` (`ParticipantRole::Admin` / `ParticipantRole::Member`, `MembershipStatus`), and `Message` with deterministic JSON serialization (`to_json()` / `from_json()`), `sender_key_epoch`, and zero-plaintext storage invariants.
2. **Native SQLCipher Persistence (`CLIENT-009-T02`)**: Implemented `SqlCipherLocalStore` backed by native `libsqlcipher` (`4.20.0`) with AES-256-CBC page encryption, HMAC-SHA512 page authentication, `PRAGMA cipher_memory_security = ON`, `WAL` journal mode, and a CSPRNG 256-bit master key managed exclusively in `ISecureStorage` (`local_store.sqlcipher.master_key`).
3. **Group Sender Keys Cryptographic Engine (`CLIENT-009-T03`)**: Implemented Signal-aligned Sender Keys (`SenderKeyState`, `SenderKeyDistributionMessage`, `GroupEncryptedEnvelope` `SCG` v1, and `SenderKeyEngine`) using HMAC-SHA256 symmetric ratcheting (`0x01` message key, `0x02` chain advance), AES-256-GCM payload encryption, Ed25519 sender authentication, and bounded skipped-key caching for out-of-order group delivery.
4. **Production Fan-Out, RBAC & Key Rotation (`CLIENT-009-T04`)**: Connected `MessagingManager` to `IGatewayClient::submit_encrypted_message` (`FanOutSubmissionRequest`), pairwise Sender Key distribution via `RatchetSessionManager`, `Admin`-only group membership mutations, mandatory Sender Key epoch rotation on member removal/device revocation, and ADR-008 `KeyChanged` / `Blocked` guards.
5. **ViewModel Persistent Hydration & UI Wiring (`CLIENT-009-T05`)**: Wired `WorkspaceViewModel` to hydrate strictly from `ILocalStore` / `MessagingManager` when `ClientConfig::database_path` is set or persisted data exists (zero mock `seedDefaultWorkspaceData()` fallback in persistent mode), exposed `selectedGroupKeyEpoch`, `localUserIsGroupAdmin`, `reloadFromLocalStore()`, and participant `"role"` / `"canRemove"` metadata, and fixed `ClientBootstrap::create_with_adapters` to avoid pre-opening a throwaway SQLCipher store.
6. **Multi-Workstation E2E Integration & Walkthrough (`CLIENT-009-T06`)**: Added `DirectAndGroupMessagingIntegrationTest` covering Scenarios 1–5 across multi-device workstations, disk-backed SQLCipher restarts, raw `.db` zero-plaintext verification, out-of-order group decryption, RBAC/epoch rotation, late-join forward secrecy, and fail-closed ADR-008 / tampered-DB checks.

---

## 2. Ticket Delivery & Commit History

| Ticket | Scope | Commit | Status |
|---|---|---|---|
| **CLIENT-009-T01** | `ParticipantRole`, `GroupParticipant`, `Conversation` & `Message` JSON round-trip | `0a83e80` | Completed |
| **CLIENT-009-T02** | Native `SqlCipherLocalStore` (`libsqlcipher`), `ISecureStorage` 256-bit key lifecycle, `ClientBootstrap` wiring | `3837b84` | Completed |
| **CLIENT-009-T03** | `SenderKeyState`, `SenderKeyDistributionMessage`, `GroupEncryptedEnvelope` (`SCG` v1), `SenderKeyEngine` | `6562be2` | Completed |
| **CLIENT-009-T04** | `FanOutSubmissionRequest`, `MessagingManager` 1:1/group fan-out, RBAC & Sender Key rotation | `7629c3c` | Completed |
| **CLIENT-009-T05** | `WorkspaceViewModel` persistent hydration, group RBAC/epoch QML bindings, `AdapterInitTag` fix | `053eb82` | Completed |
| **CLIENT-009-T06** | `DirectAndGroupMessagingIntegrationTest` (Scenarios 1–5) & `walkthrough-client-009.md` | Pending T06 commit | Completed |

---

## 3. Architecture Overview

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6 / QML)                      │
│  WorkspaceViewModel                                                        │
│   - Hydrates from ILocalStore when database_path != "" or DB non-empty     │
│   - Exposes selectedGroupKeyEpoch, localUserIsGroupAdmin, reloadFromLocalStore │
│   - Emits workspaceError on RBAC / ADR-008 / crypto failures               │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼──────────────────────────────────────┐
│                         Application Layer (Managers)                       │
│  MessagingManager                                                          │
│   - 1:1 Fan-Out -> RatchetSessionManager (X3DH + Double Ratchet)           │
│   - Group Fan-Out -> SenderKeyEngine (SCG v1) + pairwise SKD distribution  │
│   - Admin RBAC (add/remove participant) & mandatory Sender Key epoch rot.  │
│   - ADR-008 guards: KeyChanged halts sends; Blocked drops inbound packets  │
└──────────────┬───────────────────────────────────────────┬─────────────────┘
               │                                           │
┌──────────────▼───────────────────────┐   ┌───────────────▼─────────────────┐
│     Encrypted Local Persistence      │   │     Zero-Plaintext Transport    │
│  SqlCipherLocalStore (libsqlcipher)  │   │  IGatewayClient                 │
│   - 256-bit CSPRNG key in            │   │   - submit_encrypted_message(   │
│     ISecureStorage                   │   │       FanOutSubmissionRequest)  │
│   - AES-256-CBC + HMAC-SHA512 pages  │   │   - PerDeviceDeliveryPayload +  │
│   - PRAGMA cipher_memory_security=ON │   │     GroupEncryptedEnvelope      │
└──────────────────────────────────────┘   └─────────────────────────────────┘
```

---

## 4. Cryptography & Storage Design

### 4.1 Native SQLCipher Encrypted Local Store (`SqlCipherLocalStore`)
- **Key Lifecycle**: On first `open(path)`, if `ISecureStorage` does not hold `local_store.sqlcipher.master_key`, `SqlCipherLocalStore` generates a 256-bit CSPRNG hex key via `RAND_bytes` and stores it in `ISecureStorage`. If an existing non-empty database file is opened without a matching key in `ISecureStorage` (or with an invalid key), `SELECT count(*) FROM sqlite_master;` fails closed before any query runs.
- **Memory Hygiene**: Key material and `PRAGMA key` command buffers are wrapped in `SecretCleanseGuard` (`OPENSSL_cleanse` on scope exit), and `PRAGMA cipher_memory_security = ON` is enabled.
- **Schema**: Indexed tables `conversations`, `messages` (`idx_messages_conv_time`), and `contacts`, storing serialized domain JSON inside SQLCipher-encrypted pages.

### 4.2 Group Sender Keys (`SCG` v1)
- **Chain Key Derivation**: Symmetric HMAC-SHA256 KDF advancing chain key $CK_{n+1} = \text{HMAC}(CK_n, \text{0x02})$ and deriving message key $MK_n = \text{HMAC}(CK_n, \text{0x01})$.
- **Payload Encryption & Authentication**: Message payloads are encrypted with AES-256-GCM under $MK_n$ and signed with the sender device's Ed25519 Sender Key signing key inside `GroupEncryptedEnvelope` (`SCG` v1).
- **Out-of-Order & Anti-Replay**: `SenderKeyEngine` caches skipped message keys up to a bounded window (`kMaxSkippedKeys`) for out-of-order group delivery and rejects replayed counters, wrong epochs, or invalid Ed25519 signatures.
- **Pairwise Distribution**: `SenderKeyDistributionMessage` is distributed only to authorized devices of active group members via pairwise X3DH / Double Ratchet sessions (`RatchetSessionManager`).

---

## 5. Group RBAC, Epoch Rotation & ADR-008 Security Invariants

1. **Admin-Only Membership Mutation**: `MessagingManager::add_group_participant` and `remove_group_participant` verify `conv.is_admin(actor_user_id)`. Non-admin `Member` callers receive a validation error (`"Only group admins can ..."`), and `WorkspaceViewModel` surfaces this via `workspaceError`.
2. **Mandatory Key Rotation**: Removing a participant increments `sender_key_epoch`, clears the active Sender Key chain, and forces fresh pairwise `SenderKeyDistributionMessage` generation excluding the removed member/device.
3. **Late-Join Forward/Backward Secrecy**: Newly added members receive only the current epoch's `SenderKeyDistributionMessage` and cannot decrypt captured `SCG` v1 envelopes from prior epochs.
4. **ADR-008 Verification & Block Guards**:
   - `KeyVerificationStatus::KeyChanged` on any recipient halts outbound 1:1 and group sends (`stage_outbound_message` / `distribute_sender_key`) until identity key verification is acknowledged.
   - Blocked senders (`is_blocked() == true`) have inbound group distributions and `SCG` v1 envelopes dropped pre-decryption.

---

## 6. ViewModel Persistence & Zero-Mock Startup

In `WorkspaceViewModel`:
- **Persistent Mode**: Whenever `!app_.bootstrap().config().database_path.empty()` OR `messaging_manager().list_conversations()` returns persisted entries, `WorkspaceViewModel` calls `hydrateFromLocalStore()` and **never** falls back to `seedDefaultWorkspaceData()`.
- **Headless Test Mode**: When `database_path` is empty and `local_store()` has no conversations, `seedDefaultWorkspaceData()` seeds default UI fixtures (persisting `Admin` role and `senderKeyEpoch` on seeded groups so RBAC operations remain consistent).
- **QML Bindings**: Exposes `selectedGroupKeyEpoch`, `localUserIsGroupAdmin`, `reloadFromLocalStore()`, and participant `"role"` (`"Admin"` / `"Member"`) + `"canRemove"` metadata.

---

## 7. Integration Scenarios & Results (`DirectAndGroupMessagingIntegrationTest`)

All 5 end-to-end scenarios in `tests/unit/client/direct_and_group_messaging_integration_test.cpp` run **in-process** with zero Docker containers, external databases, or host ports required, using real `OpenSslCryptoProvider`, disk-backed `SqlCipherLocalStore`, persistent `MemorySecureStorage`, `RatchetSessionManager`, `MessagingManager`, and `DefaultGatewayClient`:

### Scenario 1 — Multi-Workstation Direct E2EE Fan-Out & Restart Durability
- **Test**: `Scenario1MultiWorkstationDirectFanOutAndRestartDurability`
- **Setup**: Alice (`alice-dev-1`, `alice-dev-2`) and Bob (`bob-dev-1`, `bob-dev-2`) each backed by disk `SqlCipherLocalStore` + `MemorySecureStorage`.
- **Verified**:
  - `stage_outbound_message` fans out 3 encrypted payloads (`alice-dev-2` companion sync, `bob-dev-1`, `bob-dev-2`) with zero plaintext in `FanOutSubmissionRequest::device_payloads`.
  - All 3 target devices decrypt the original message cleanly.
  - Both `alice1` and `bob1` close and restart against their SQLCipher `.db` files; raw `.db` bytes on disk contain zero plaintext; persisted conversation history survives restart; post-restart 1:1 messaging continues without error.
- **Result**: **PASS** (`50 ms`)

### Scenario 2 — Group Messaging, Sender Key Distribution & Out-of-Order Multi-Device Decryption
- **Test**: `Scenario2GroupMessagingDistributionAndOutOfOrderMultiDeviceDecryption`
- **Setup**: Alice creates `"SecOps Alpha"` with Bob (2 devices: `bob-dev-1`, `bob-dev-2`) and Charlie (`charlie-dev-1`), and stages 2 consecutive group messages (`msg1`, `msg2`).
- **Verified**:
  - Pairwise X3DH/Double Ratchet `SenderKeyDistributionMessage` delivery succeeds across all 3 recipient devices.
  - `bob1` and `charlie1` decrypt `msg1` and `msg2` in order; `bob2` decrypts `msg2` *before* `msg1` (out-of-order) using bounded skipped-key derivation.
- **Result**: **PASS** (`17 ms`)

### Scenario 3 — Membership Removal, Non-Admin RBAC & Mandatory Key Rotation
- **Test**: `Scenario3MembershipRemovalNonAdminRbacAndMandatoryRotation`
- **Setup**: Alice (`Admin`) creates `"RBAC Ops"` with Bob (`Member`) and Charlie (`Member`), sends Epoch 1, then removes Charlie.
- **Verified**:
  - Charlie (`Member`) fails to remove Bob (`remove_group_participant` returns error).
  - Alice (`Admin`) removes Charlie, rotating `sender_key_epoch` from `1` to `2`.
  - Epoch 2 `SenderKeyDistributionMessage` excludes `charlie-dev-1`; Bob decrypts Epoch 2 while Charlie's device fails closed on Epoch 2 `SCG` v1 ciphertext.
- **Result**: **PASS** (`14 ms`)

### Scenario 4 — Late-Join Member Forward Secrecy Boundary
- **Test**: `Scenario4LateJoinMemberForwardSecrecyBoundary`
- **Setup**: Alice sends Epoch 1 (`grp1_bytes`), removes Charlie, adds Dave (`dave-dev-1`) at Epoch 2 (`sender_key_epoch == 2`), and sends Epoch 2 (`grp2_bytes`).
- **Verified**:
  - Dave decrypts Epoch 2 (`SCENARIO_4_EPOCH2_LATE_JOIN_OK`) after receiving Epoch 2 `SenderKeyDistributionMessage`.
  - Dave fails closed when attempting to decrypt captured historical Epoch 1 `grp1_bytes`.
- **Result**: **PASS** (`18 ms`)

### Scenario 5 — ADR-008 Guards (`KeyChanged` & Block) & Tampered DB / Envelope Fail-Closed
- **Test**: `Scenario5Adr008GuardsAndTamperedDbOrEnvelopeFailClosed`
- **Verified**:
  - Setting Bob's contact status to `KeyVerificationStatus::KeyChanged` halts both 1:1 and group `stage_outbound_message` calls until restored to `Verified`.
  - Flipping a byte in a serialized `SCG` v1 `GroupEncryptedEnvelope` fails Ed25519/AEAD verification on Bob.
  - Blocking Alice on Bob's contact list drops inbound group `SCG` v1 packets pre-decryption.
  - Opening Alice's existing `SqlCipherLocalStore` file with an incorrect 256-bit key in `ISecureStorage` fails closed.
- **Result**: **PASS** (`9 ms`)

---

## 8. Key Deliverables & Modified Files

- `src/client/domain/conversation.hpp`, `src/client/domain/conversation.cpp`, `src/client/domain/message.hpp`, `src/client/domain/message.cpp`
- `src/client/infrastructure/adapters/sqlcipher_local_store.hpp`, `src/client/infrastructure/adapters/sqlcipher_local_store.cpp`
- `src/client/domain/crypto/sender_key_models.hpp`, `src/client/domain/crypto/sender_key_models.cpp`
- `src/client/application/managers/sender_key_engine.hpp`, `src/client/application/managers/sender_key_engine.cpp`
- `src/client/application/interfaces/i_gateway_client.hpp`, `src/client/infrastructure/adapters/default_gateway_client.hpp`, `src/client/infrastructure/adapters/default_gateway_client.cpp`
- `src/client/application/managers/messaging_manager.hpp`, `src/client/application/managers/messaging_manager.cpp`
- `src/client/application/client_bootstrap.hpp`, `src/client/application/client_bootstrap.cpp`
- `src/client/ui/workspace_view_model.hpp`, `src/client/ui/workspace_view_model.cpp`
- `tests/unit/client/sqlcipher_local_store_test.cpp`
- `tests/unit/client/sender_key_engine_test.cpp`
- `tests/unit/client/group_messaging_pipeline_test.cpp`
- `tests/unit/client/workspace_view_model_group_persistence_test.cpp`
- `tests/unit/client/direct_and_group_messaging_integration_test.cpp`
- `tests/unit/CMakeLists.txt`
- `specs/client-phase3/CLIENT-009-tickets.md`
- `docs/final-reports/walkthrough-client-009.md`

---

## 9. Verbatim Verification Output

### 9.1 Formatting & Zero-Warning Build
```text
ninja: Entering directory `build/dev-debug'
[1/2] Checking project C++ formatting (read-only)...
[SecureCloud] All 1023 C++ files adhere to .clang-format.
[1/5] Automatic MOC for target securecloud_client_foundation_test
[2/4] Building CXX object tests/unit/CMakeFiles/securecloud_client_foundation_test.dir/client/direct_and_group_messaging_integration_test.cpp.o
[3/4] Linking CXX executable tests/unit/securecloud_client_foundation_test
```

### 9.2 Scenarios 1–5 Integration Suite (`DirectAndGroupMessagingIntegrationTest`)
```text
Note: Google Test filter = DirectAndGroupMessagingIntegrationTest.*
[==========] Running 5 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 5 tests from DirectAndGroupMessagingIntegrationTest
[ RUN      ] DirectAndGroupMessagingIntegrationTest.Scenario1MultiWorkstationDirectFanOutAndRestartDurability
[       OK ] DirectAndGroupMessagingIntegrationTest.Scenario1MultiWorkstationDirectFanOutAndRestartDurability (50 ms)
[ RUN      ] DirectAndGroupMessagingIntegrationTest.Scenario2GroupMessagingDistributionAndOutOfOrderMultiDeviceDecryption
[       OK ] DirectAndGroupMessagingIntegrationTest.Scenario2GroupMessagingDistributionAndOutOfOrderMultiDeviceDecryption (17 ms)
[ RUN      ] DirectAndGroupMessagingIntegrationTest.Scenario3MembershipRemovalNonAdminRbacAndMandatoryRotation
[       OK ] DirectAndGroupMessagingIntegrationTest.Scenario3MembershipRemovalNonAdminRbacAndMandatoryRotation (14 ms)
[ RUN      ] DirectAndGroupMessagingIntegrationTest.Scenario4LateJoinMemberForwardSecrecyBoundary
[       OK ] DirectAndGroupMessagingIntegrationTest.Scenario4LateJoinMemberForwardSecrecyBoundary (18 ms)
[ RUN      ] DirectAndGroupMessagingIntegrationTest.Scenario5Adr008GuardsAndTamperedDbOrEnvelopeFailClosed
[       OK ] DirectAndGroupMessagingIntegrationTest.Scenario5Adr008GuardsAndTamperedDbOrEnvelopeFailClosed (9 ms)
[----------] 5 tests from DirectAndGroupMessagingIntegrationTest (110 ms total)

[----------] Global test environment tear-down
[==========] 5 tests from 1 test suite ran. (110 ms total)
[  PASSED  ] 5 tests.
```

### 9.3 Full `securecloud_client_foundation_test` Suite
```text
[==========] Running 266 tests from 74 test suites. (1638 ms total)
[  PASSED  ] 266 tests.
```

### 9.4 Offscreen Desktop Client Smoke Test (`--smoke-test`)
```text
[SecureCloud Client] Initializing SecureCloud Client v0.1.0-dev
[INFO] [ClientApp] Initializing application subsystems...
[INFO] [ClientApp] Subsystems initialized successfully
[INFO] [ClientApp] Application entered RUNNING state
[SecureCloud Client] Smoke test execution passed cleanly (QML engine loaded)
[INFO] [ClientApp] Initiating graceful shutdown...
[INFO] [ClientApp] Application terminated cleanly
```

---

## 10. Reproducible Verification Commands

```bash
# 1. Verify formatting across all C++ files
ninja -C build/dev-debug check-format

# 2. Build client and unit/integration test suite (zero warnings enforced via -Werror)
ninja -C build/dev-debug securecloud-client securecloud_client_foundation_test

# 3. Run Scenarios 1-5 E2E integration suite
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test \
  --gtest_filter="DirectAndGroupMessagingIntegrationTest.*"

# 4. Run full client foundation suite (266 tests)
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test

# 5. Run desktop client offscreen smoke test
QT_QPA_PLATFORM=offscreen ./build/dev-debug/src/client/securecloud-client --smoke-test
```
