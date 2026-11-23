# CLIENT-013 Ticket Decomposition: Emergency Panic & Data Wipe

- **Milestone Card:** `CLIENT-013` — Emergency Panic & Data Wipe (Desktop Client Phase 4)
- **Phase:** Desktop Client Phase 4 (`CLIENT-013` – `CLIENT-016`)
- **Target Branch:** `feature/client-013-emergency-panic-and-data-wipe`
- **Owner:** Sergey
- **Dependencies:** `CLIENT-003` (Navigation Shell & Confirmation Dialog), `CLIENT-005` (Device Identity & `SecretString` Zeroization), `CLIENT-006` (`RatchetSessionManager`), `CLIENT-009` (`SqlCipherLocalStore` & `MessagingManager`), `CLIENT-011` (`FileManager` `.part` staging & file keys), `CLIENT-012` (`SyncManager` & `offline_outbox`), `ADR-007` (Emergency Priority & Operator Acknowledgement), `ADR-008 §21-22, §27-28` (No Emergency Backdoor, Encrypted Location Payload, Endpoint Key Storage & Zero Secret Logging), `Detailed Design §2.5` (`EmergencyManager`)

---

## 1. Executive Summary & Architectural Overview

`CLIENT-013` launches **Desktop Client Phase 4** by hardening the SecureCloud Desktop Client (`securecloud-client`) with forensic-grade local data destruction, multi-channel panic triggers, and an optional pre-wipe E2EE emergency broadcast workflow. Operators in high-risk environments can trigger a panic wipe via global hotkey (`Cmd+Shift+E` / `Ctrl+Shift+E`), an in-app UI panic action (`Main.qml` / `NavigationShell.qml`), or a silent **Login Duress PIN** on `LoginPlaceholder.qml`. Once triggered, `EmergencyManager` optionally dispatches an encrypted `Emergency` (`priority = 3`) broadcast alert with bounded operator acknowledgement wait (`ADR-007`, `ADR-008 §21-22`) — without introducing any server or admin decryption backdoor — then executes a `< 500 ms` destruction sequence: zeroizing volatile manager/crypto caches (`RatchetSessionManager`, `MessagingManager`, `FileManager`, `SyncManager`, `AuthManager`, `WorkspaceViewModel`), purging **all** secret keys across `ISecureStorage`, crypto-shredding and 3-pass forensic-shredding local SQLCipher databases (`.db`, `-wal`, `-shm`), `.part` staging artifacts, and log files, and resetting the application either to a locked `EmergencyMode` view or a plausible empty **Decoy Workspace**.

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                   Panic Triggers (UI / Auth / Shortcut)                    │
│  1. Global Hotkey (Cmd+Shift+E / Ctrl+Shift+E)                             │
│  2. NavigationShell Danger Action -> Main.qml Confirm / Broadcast Modal    │
│  3. LoginPlaceholder.qml Duress PIN (Salted PBKDF2-HMAC-SHA256 Check)      │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                  EmergencyManager Orchestration (< 500 ms)                 │
│                                                                            │
│  [Optional Phase 0] Pre-Wipe E2EE Emergency Broadcast (ADR-008 §21-22)     │
│   └─ Encrypt priority=3 alert via normal Double Ratchet / Sender Key       │
│   └─ Bounded operator acknowledgement wait (configurable timeout)          │
│                                                                            │
│  [Phase 1] Volatile Memory Zeroization                                     │
│   ├─ RatchetSessionManager::wipe_all_sessions()                            │
│   ├─ MessagingManager / FileManager / SyncManager / AuthManager purge      │
│   └─ WorkspaceViewModel / AppViewModel UI state reset                      │
│                                                                            │
│  [Phase 2] Endpoint Key & Secret Destruction (ISecureStorage)              │
│   └─ Purge ALL key namespaces (session, identity bundle, SQLCipher MK,     │
│      ratchet sessions, sender keys, file keys, safety numbers, duress PIN) │
│                                                                            │
│  [Phase 3] Forensic On-Disk Shredding (FileShredder)                       │
│   └─ SqlCipherLocalStore::destroy_and_shred():                             │
│      close DB -> 3-pass overwrite (0x00, 0xFF, RAND_bytes) + flush +       │
│      truncate(0) + unlink on .db, -wal, -shm, .part transfers & log files  │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     ▼
          ┌──────────────────────────┴──────────────────────────┐
          ▼                                                     ▼
┌───────────────────────────┐                         ┌───────────────────────────┐
│ PostWipeMode::            │                         │ PostWipeMode::            │
│   EmergencyLocked         │                         │   DecoyWorkspace          │
│ - EmergencyPlaceholder    │                         │ - Benign empty Workspace  │
│ - Non-secret Wipe Report  │                         │ - Normal-looking chrome   │
│ - Return to Login / Reset │                         │ - Zero forensic traces    │
└───────────────────────────┘                         └───────────────────────────┘
```

### Ticket Status Matrix

| Ticket | Title | Status | Target Scope |
|---|---|---|---|
| **CLIENT-013-T01** | Emergency Panic Domain Models & Complete `ISecureStorage` / `ILocalStore` Purge Contracts | **Completed** | `PanicTriggerSource`, `PostWipeMode`, `WipeStepStatus`, `EmergencyWipeReport`, `EmergencyBroadcastRequest/Result`, `DuressPinConfig`; `ISecureStorage::list_secret_keys()` / `purge_all_secrets()`, `ILocalStore::database_path()` |
| **CLIENT-013-T02** | Forensic `FileShredder` Utility & SQLCipher/Cache/Log Artifact Destruction | **Completed** | 3-pass overwrite (`0x00`, `0xFF`, `RAND_bytes`) + flush + truncate + unlink utility; `SqlCipherLocalStore::destroy_and_shred()` covering `.db`, `-wal`, `-shm`, `.part` files, and log artifacts |
| **CLIENT-013-T03** | Production `EmergencyManager` Cryptographic Destruction Pipeline & Pre-Wipe E2EE Broadcast | **Completed** | `< 500 ms` 3-phase wipe pipeline; volatile wipe methods across `RatchetSessionManager`, `MessagingManager`, `FileManager`, `SyncManager`, `AuthManager`; pre-wipe `priority=3` E2EE broadcast + bounded ACK wait |
| **CLIENT-013-T04** | Login Duress PIN Verification & Silent Plausible Decoy Session Engine | **Completed** | Salted PBKDF2-HMAC-SHA256 (`>= 100,000` iter, constant-time `CRYPTO_memcmp`) duress PIN management; silent login interception in `AuthManager` / `EmergencyManager` triggering wipe + `PostWipeMode::DecoyWorkspace` |
| **CLIENT-013-T05** | `AppViewModel`, `WorkspaceViewModel` & QML Emergency Panic, Duress & Decoy UX | **Completed** | Hotkey & Instant vs Broadcast-then-Wipe modal (`Main.qml`); silent duress login & Decoy Workspace routing; post-wipe audit card in `EmergencyPlaceholder.qml`; Duress PIN & Post-Wipe policy controls in `SettingsPlaceholder.qml` |
| **CLIENT-013-T06** | Emergency Panic & Forensic Wipe E2E Integration Suite, Tier 1/2 Smoke Tests & Walkthrough | **Planned** | 5-scenario E2E integration suite (`emergency_panic_wipe_integration_test.cpp`), `< 500 ms` latency + disk sector audit, Tier 1 `--smoke-test`, Tier 2 `--capture-screenshots`, `walkthrough-client-013.md`, `docs/pull_requests/CLIENT-013.md` |

---

## 2. Architecture, ADR & Codebase Audit: What Already Exists vs. Net-New Scope

### 2.1 Already Implemented on Client (Reuse, Do NOT Re-Implement)

1. **`EmergencyManager` Skeleton (`src/client/application/managers/emergency_manager.{hpp,cpp}`):**
   - Already wired in `ClientBootstrap::wire_managers()` (`src/client/application/client_bootstrap.cpp:71`).
   - Already implements `is_wiped()`, `acknowledge_emergency_message(...)`, and `unacknowledged_emergency_count(...)`.
2. **Global Hotkey, Navigation Shell & Modal Confirmation Dialog (`NavigationShell.qml` & `Main.qml`):**
   - `NavigationShell.qml` (L63–67, L410–419) already defines `Shortcut { sequence: "Ctrl+Shift+E" ... }` (automatically mapped to `Cmd+Shift+E` on macOS by Qt) and the red danger `SidebarNavItem` (`"Emergency Wipe"`), both emitting `emergencyWipeRequested()`.
   - `Main.qml` (L281–289) already renders `emergencyConfirmDialog` (`SCDialog` with `isDanger: true`) invoking `appViewModel.triggerEmergencyWipe()`.
3. **Post-Wipe View & ViewModel Hooks (`EmergencyPlaceholder.qml`, `AppViewModel`, `WorkspaceViewModel`):**
   - `EmergencyPlaceholder.qml` renders the locked wipe confirmation view and `"Return to Login"` reset button (`navigationController.reset(0)`).
   - `AppViewModel::triggerEmergencyWipe()` (`src/client/ui/app_view_model.cpp:232-245`) clears pending credentials, logs out `AuthManager`, invokes `EmergencyManager`, and resets `NavigationController` to `NavigationState::EmergencyMode`.
   - `WorkspaceViewModel::resetForEmergencyWipe()` (`src/client/ui/workspace_view_model.hpp:207`) clears active workspace state.
4. **Best-Effort Volatile Secret Zeroization (`SecretString`, `src/common/include/securecloud/configuration/secret_string.hpp`):**
   - Already wipes underlying buffers via `OPENSSL_cleanse` on destruction and move assignment (`SecretString::wipe_buffer()`).

### 2.2 Critical Security & Architectural Gaps Closed by `CLIENT-013`

1. **High-Risk Gap — Incomplete `ISecureStorage` Key Wipe:**
   - Currently, `EmergencyManager::trigger_emergency_wipe()` (`emergency_manager.cpp:11-12`) deletes only two hardcoded keys (`"session_auth_token"` and `"device_private_identity_key"`).
   - Across Phases 2 and 3, the desktop client actually stores **seven+ distinct secret key namespaces** in `ISecureStorage`:
     - `local_device_id` (`device_manager.cpp`)
     - `device_private_bundle:<device_id>` (`key_storage_helper.cpp`)
     - `local_store.sqlcipher.master_key` (`sqlcipher_local_store.cpp`)
     - `ratchet_session:<user_id>:<device_id>` and `ratchet_session_index` (`ratchet_session_manager.cpp`)
     - `sender_key:<conv_id>:<sender_user>:<sender_device>` and `messaging.sender_key_...` (`messaging_manager.cpp`)
     - `file_transfer.key.<file_id>` (`file_manager.cpp`)
     - `safety_number:...`, `pairing:...`, and `privacy.read_receipts_enabled`
   - Leaving `local_store.sqlcipher.master_key`, `ratchet_session_index`, or `file_transfer.key.<file_id>` behind compromises forward secrecy and local vault crypto-shredding. `ISecureStorage` must support full enumeration (`list_secret_keys()`) and atomic full wipe (`purge_all_secrets()`).
2. **No On-Disk Forensic Shredding (`FileShredder` Missing):**
   - `EmergencyManager` only calls `local_store_.close()`, leaving the SQLCipher `.db`, `-wal`, `-shm`, unfinished `.part` download files, and local client log files intact on disk.
   - `CLIENT-013` adds a reusable 3-pass `FileShredder` (`0x00` -> `0xFF` -> OpenSSL `RAND_bytes` -> flush -> truncate to `0` -> unlink) and `SqlCipherLocalStore::destroy_and_shred()`, while clearly documenting SSD/CoW filesystem physical sector caveats (making `SQLCipher` master-key destruction + file shredding complementary layers).
3. **Volatile Cross-Manager State Not Explicitly Zeroized:**
   - `RatchetSessionManager::sessions_`, `MessagingManager::retry_engine_`, `SyncManager::conversation_cursors_`, `FileManager` active transfer guards, `AuthManager::current_user_`, and `WorkspaceViewModel` vectors remain populated in memory unless explicitly wiped by `EmergencyManager`.
4. **No Pre-Wipe E2EE Emergency Broadcast Workflow (`ADR-007` & `ADR-008 §21-22`):**
   - Operators under duress may need to dispatch a final `priority = 3` (`Emergency`) E2EE alert (e.g., encrypted distress status or location coordinates per `ADR-008 §21`) and optionally wait briefly for server/operator delivery acknowledgement before local destruction begins — using standard X3DH/Double Ratchet or Sender Key encryption with **zero** emergency decryption backdoors.
5. **No Login Duress PIN or Plausible Decoy Workspace:**
   - Entering a preconfigured Duress PIN/passphrase on the login screen (`LoginPlaceholder.qml`) must silently verify against a salted PBKDF2-HMAC-SHA256 hash stored locally (`ISecureStorage`), execute the full forensic wipe cleanly, and open an unconfigured/benign **Decoy Workspace** (`PostWipeMode::DecoyWorkspace`) with no visible panic banner or wiped-state indicator.

---

## 3. Detailed Ticket Specifications (`CLIENT-013-T01` – `CLIENT-013-T06`)

### CLIENT-013-T01: Emergency Panic Domain Models & Complete `ISecureStorage` / `ILocalStore` Purge Contracts

- **Component:** `src/client/domain/emergency_models.{hpp,cpp}`, `src/client/application/interfaces/i_secure_storage.hpp`, `src/client/infrastructure/adapters/memory_secure_storage.{hpp,cpp}`, `src/client/application/interfaces/i_local_store.hpp`, `src/client/infrastructure/adapters/sqlcipher_local_store.{hpp,cpp}`, `src/client/infrastructure/adapters/memory_local_store.{hpp,cpp}`, `src/client/CMakeLists.txt`, `tests/unit/client/emergency_domain_and_storage_test.cpp`
- **Objective:** Define strongly typed emergency panic, forensic report, duress configuration, and broadcast domain models, and extend `ISecureStorage` and `ILocalStore` so `EmergencyManager` can discover and destroy every local secret and database artifact without relying on hardcoded key lists.
- **Architectural Scope:**
  1. Create `src/client/domain/emergency_models.hpp` and `.cpp`:
     - `enum class PanicTriggerSource { Hotkey, UiPanicButton, DuressPin, Programmatic };`
     - `enum class PostWipeMode { EmergencyLocked, UnconfiguredReset, DecoyWorkspace };`
     - `enum class WipeStepStatus { Succeeded, Skipped, Failed };`
     - `struct WipeArtifactResult`: `std::string artifact_category`, `std::size_t items_processed{0}`, `WipeStepStatus status`, `std::string detail`
     - `struct EmergencyWipeReport`:
       - `PanicTriggerSource trigger_source`
       - `PostWipeMode post_wipe_mode`
       - `bool broadcast_attempted{false}`, `bool broadcast_acknowledged{false}`
       - `std::size_t secrets_purged_count{0}`
       - `std::size_t files_shredded_count{0}`
       - `std::size_t volatile_caches_cleared{0}`
       - `int64_t duration_ms{0}`
       - `bool all_critical_steps_succeeded{false}`
       - `std::vector<WipeArtifactResult> step_results`
       - Note: Contains **strictly non-secret operational metadata** (counts, categories, elapsed ms — never key IDs with secret values or file contents).
     - `struct EmergencyBroadcastRequest`:
       - `ConversationId conversation_id`
       - `UserId sender_user_id`
       - `DeviceId sender_device_id`
       - `std::string alert_plaintext` (e.g. distress message)
       - `std::optional<std::string> encrypted_location_json` (optional GPS/zone JSON bundled into E2EE plaintext per `ADR-008 §21`)
       - `bool wait_for_acknowledgement{false}`
       - `std::chrono::milliseconds ack_timeout{std::chrono::milliseconds(1500)}`
     - `struct EmergencyBroadcastResult`: `bool submitted{false}`, `bool acknowledged{false}`, `MessageId message_id`, `std::string error_detail`
     - `struct DuressPinConfig`: `bool enabled{false}`, `PostWipeMode post_wipe_mode{PostWipeMode::DecoyWorkspace}`, `uint32_t pbkdf2_iterations{100000}`, `std::string salt_hex`, `std::string derived_hash_hex`, `int64_t configured_at_ms{0}` (`to_json()` / `from_json()` serialization).
  2. Extend `ISecureStorage` (`src/client/application/interfaces/i_secure_storage.hpp`):
     - `virtual ClientResult<std::vector<std::string>> list_secret_keys() = 0;`
     - `virtual ClientResult<std::size_t> purge_all_secrets() = 0;` (implementations must cleanse secret buffers in memory before removal and return total keys destroyed).
     - Implement both in `MemorySecureStorage` (`memory_secure_storage.{hpp,cpp}`), explicitly cleansing each `SecretString` element before erasing/clearing `secrets_`.
  3. Extend `ILocalStore` (`src/client/application/interfaces/i_local_store.hpp`):
     - `[[nodiscard]] virtual std::string database_path() const = 0;`
     - Implement in `SqlCipherLocalStore` and `MemoryLocalStore` (returns empty string for pure in-memory store).
- **Acceptance Criteria:**
  - `MemorySecureStorage::purge_all_secrets()` destroys keys across every client namespace (`ratchet_session:`, `file_transfer.key.`, `local_store.sqlcipher.master_key`, `device_private_bundle:`, etc.) and returns `0` remaining keys via `list_secret_keys()` and `has_secret(...) == false`.
  - All `emergency_models` enums and `DuressPinConfig` JSON round-trips validate cleanly under strict `-Werror -Wconversion`.

---

### CLIENT-013-T02: Forensic `FileShredder` Utility & SQLCipher/Cache/Log Artifact Destruction

- **Component:** `src/client/infrastructure/adapters/file_shredder.{hpp,cpp}`, `src/client/infrastructure/adapters/sqlcipher_local_store.{hpp,cpp}`, `src/client/infrastructure/client_logger.{hpp,cpp}`, `tests/unit/client/forensic_file_shredder_test.cpp`
- **Objective:** Implement a cross-platform forensic file shredding utility (macOS, Linux, Windows MSYS2 UCRT64) and integrate it with `SqlCipherLocalStore` and log/cache cleanup so deleted local files leave zero recoverable plaintext or ciphertext sectors on disk.
- **Architectural Scope:**
  1. Create `src/client/infrastructure/adapters/file_shredder.hpp` and `.cpp`:
     - `struct ShredOptions`: `uint32_t overwrite_passes{3}` (Pass 1: `0x00`, Pass 2: `0xFF`, Pass 3+: OpenSSL `RAND_bytes`), `std::size_t buffer_size_bytes{65536}`, `bool flush_to_disk{true}`.
     - `struct ShredResult`: `std::size_t files_shredded{0}`, `std::size_t bytes_overwritten{0}`, `std::vector<std::string> failed_paths`.
     - `static application::ClientResult<void> shred_file(const std::filesystem::path& path, const ShredOptions& options = {})`:
       - Safely handles non-existent files as a no-op success (idempotent).
       - Rejects directory targets; checks file size bounded by streaming chunk writes (`64 KiB` stack/reused buffer — zero whole-file RAM allocation!).
       - Opens file in binary read/write mode, rewinds to offset `0` before each pass, overwrites exact byte length (`0x00` -> `0xFF` -> `RAND_bytes`), flushes OS buffers (`fflush` / POSIX `fsync` or Win32 `_commit`), resizes to `0` (`std::filesystem::resize_file`), and unlinks (`std::filesystem::remove`).
     - `static application::ClientResult<ShredResult> shred_directory_artifacts(const std::filesystem::path& dir, const std::vector<std::string>& extensions_or_prefixes, const ShredOptions& options = {})` (e.g., `.part`, `.log`, `-wal`, `-shm`, `.db`).
  2. Extend `SqlCipherLocalStore` (`sqlcipher_local_store.{hpp,cpp}`):
     - Add `ClientResult<std::size_t> destroy_and_shred()`:
       - Locks `mutex_`, captures `db_path_`, closes SQLite handle cleanly (`close_locked()`), collects `<db_path>`, `<db_path>-wal`, `<db_path>-shm`, and `<db_path>-journal`, invokes `FileShredder::shred_file` on each existing artifact, and invokes `secure_storage_.delete_secret(kMasterKeyId)`.
  3. Add optional log file path tracking / flush-and-unlink hook on `ClientLogger` so any disk log sink configured in Phase 4 can also be shredded on panic wipe.
- **Acceptance Criteria:**
  - `forensic_file_shredder_test.cpp` creates synthetic files and live `SqlCipherLocalStore` databases with populated messages, file transfers, and `-wal`/`-shm` sidecar files; inspects overwrite pass buffers via hook/read-before-unlink to verify 3-pass destruction and `truncate(0) + remove`; confirms original bytes and SQLCipher header magic (`SQLite format 3` / ciphertext) are completely gone and files no longer exist on disk.
  - Explicitly documents SSD wear-leveling / APFS CoW semantics in comments & docs (multi-pass overwrite + `SQLCipher` `256,000`-iter master key purge = defense in depth).

---

### CLIENT-013-T03: Production `EmergencyManager` Cryptographic Destruction Pipeline & Pre-Wipe E2EE Broadcast

- **Component:** `src/client/application/managers/emergency_manager.{hpp,cpp}`, `src/client/application/managers/ratchet_session_manager.{hpp,cpp}`, `src/client/application/managers/messaging_manager.{hpp,cpp}`, `src/client/application/managers/file_manager.{hpp,cpp}`, `src/client/application/managers/sync_manager.{hpp,cpp}`, `src/client/application/managers/auth_manager.{hpp,cpp}`, `src/client/application/client_bootstrap.cpp`, `tests/unit/client/emergency_wipe_pipeline_test.cpp`
- **Objective:** Replace the minimal `EmergencyManager::trigger_emergency_wipe()` stub with the full deterministic 3-phase destruction sequence (`< 500 ms`) across all client managers, storage adapters, and filesystem artifacts, plus an optional E2EE pre-wipe emergency broadcast workflow.
- **Architectural Scope:**
  1. **Add Clean Volatile Wipe Methods to Peer Managers:**
     - `RatchetSessionManager::wipe_all_sessions()`: clears `sessions_` map after zeroizing serialized state and purges `ratchet_session:*` + `ratchet_session_index` from `ISecureStorage`.
     - `MessagingManager::wipe_volatile_state()`: clears `DeliveryRetryEngine`, resets `offline_mode_`, clears cached local device ID.
     - `FileManager::wipe_volatile_state()`: signals cancel on active transfers and clears in-memory control sets (`active_transfers_`, `pause_requested_transfers_`, `cancel_requested_transfers_`), collecting tracked `.part` destination paths for shredding.
     - `SyncManager::wipe_volatile_state()`: clears `conversation_cursors_` and unsubscribe/reset callbacks cleanly without initiating network calls.
     - `AuthManager::force_clear_session()`: resets `is_authenticated_ = false`, clears `current_user_`, deletes `"session_auth_token"`.
  2. **Enhance `EmergencyManager` & `ClientBootstrap::wire_managers()`:**
     - Wire optional manager pointers (`MessagingManager*`, `RatchetSessionManager*`, `FileManager*`, `SyncManager*`, `AuthManager*`, `IGatewayClient*`) and shred target paths (database path, attachment cache dir, log paths) into `EmergencyManager`.
     - Maintain backward compatibility with existing zero-arg `trigger_emergency_wipe()` signature while adding:
       - `ClientResult<domain::EmergencyWipeReport> execute_panic_wipe(domain::PanicTriggerSource source, domain::PostWipeMode mode = domain::PostWipeMode::EmergencyLocked)`
       - `ClientResult<domain::EmergencyWipeReport> execute_broadcast_and_wipe(const domain::EmergencyBroadcastRequest& request, domain::PanicTriggerSource source, domain::PostWipeMode mode = domain::PostWipeMode::EmergencyLocked)`
     - **Pre-Wipe Emergency Broadcast Workflow (`ADR-007` & `ADR-008 §21-22`):**
       - Calls `MessagingManager::stage_outbound_message(...)` with `priority = 3` (`Emergency`) using the existing Double Ratchet / Sender Key channel (never weakening E2EE or using an admin backdoor).
       - If `wait_for_acknowledgement == true`, polls `IGatewayClient::get_message_delivery_status(...)` up to `request.ack_timeout` (bounded!) before **always** proceeding to Phase 1–3 local destruction (even if network/ACK fails or times out — network failure must never block panic wipe!).
     - **Destruction Sequence Ordering (`< 500 ms` Budget):**
       - Phase 1: Wipe volatile manager caches & active ratchet sessions (`RatchetSessionManager`, `MessagingManager`, `FileManager`, `SyncManager`, `AuthManager`).
       - Phase 2: Call `secure_storage_.purge_all_secrets()` (and verify `list_secret_keys().empty()`).
       - Phase 3: Shred SQLCipher DB artifacts (`.db`, `-wal`, `-shm` via `destroy_and_shred()` if `SqlCipherLocalStore` or `FileShredder`), registered cache/download `.part` files, and log artifacts; emit `EmergencyWipeReport` with high-resolution `std::chrono::steady_clock` duration measurement.
- **Acceptance Criteria:**
  - End-to-end `execute_panic_wipe` across a populated `SqlCipherLocalStore` + active Double Ratchet sessions + staged offline outbox + cached file keys completes in `< 500 ms` and leaves `0` keys in `ISecureStorage` and `0` recoverable `.db`/`.part` files on disk.
  - Pre-wipe E2EE broadcast encrypts `priority = 3` ciphertext via `MessagingManager`, succeeds on healthy Gateway, and still executes full local wipe cleanly when Gateway is offline or ACK times out.

---

### CLIENT-013-T04: Login Duress PIN Verification & Silent Plausible Decoy Session Engine

- **Component:** `src/client/application/managers/emergency_manager.{hpp,cpp}`, `src/client/application/managers/auth_manager.{hpp,cpp}`, `tests/unit/client/duress_pin_and_decoy_test.cpp`
- **Objective:** Enable users to configure an optional salted PBKDF2-HMAC-SHA256 Duress PIN whose entry at login silently triggers full forensic data destruction and launches a plausible empty Decoy Workspace without alerting an observer.
- **Architectural Scope:**
  1. **Cryptographic Duress PIN Storage (`EmergencyManager`):**
     - `ClientResult<void> configure_duress_pin(const common::configuration::SecretString& duress_pin, domain::PostWipeMode mode = domain::PostWipeMode::DecoyWorkspace)`:
       - Validates Option A bounds (`6..1024` exact UTF-8 bytes matching `PasswordCredential::kMaxLength`, no whitespace trimming so both short PINs and full password-style passphrases work).
       - Generates 16-byte random salt via `OpenSSL RAND_bytes`, derives 32-byte verifier via `PKCS5_PBKDF2_HMAC` (SHA-256, `100,000` iterations), wraps inside `DuressPinConfig` (stored exclusively in `ISecureStorage` under `"emergency.duress_pin_config"`, never logged or stored in plaintext!).
     - `ClientResult<void> clear_duress_pin()` and `[[nodiscard]] bool has_duress_pin() const`.
     - `ClientResult<bool> verify_duress_credential(const common::configuration::SecretString& candidate) const`:
       - Uses OpenSSL `CRYPTO_memcmp` for constant-time comparison so timing side-channels cannot distinguish normal failed passwords from duress checks.
  2. **Silent Login Duress Interception (`AuthManager` & `EmergencyManager`):**
     - Wire optional `EmergencyManager*` on `AuthManager` (`set_emergency_manager(...)`).
     - Extend `AuthManager::authenticate` / add `AuthResult { Authenticated, DuressWipeTriggered }`:
       - When `candidate` matches the locally stored duress PIN hash **or** dedicated duress trigger API is invoked:
         1. Immediately invokes `emergency_manager_->execute_panic_wipe(PanicTriggerSource::DuressPin, config.post_wipe_mode)` — including wiping `"emergency.duress_pin_config"` itself along with all vault keys and databases!
         2. **Does NOT transmit the duress PIN to the backend Auth service** and does **NOT** surface an error or red warning banner.
         3. Marks `AuthManager` state cleanly so `AppViewModel` transitions into a benign, empty **Decoy Workspace** (`is_decoy_session_ == true`) when `PostWipeMode::DecoyWorkspace` is configured (or unconfigured login reset if `UnconfiguredReset`).
- **Acceptance Criteria:**
  - Constant-time verification accepts the exact duress PIN and rejects similar strings (`1-char` mismatch) cleanly.
  - Entering the duress PIN during login performs **0** network auth requests containing the PIN, completes full wipe in `< 500 ms` (leaving no real conversations, messages, contacts, files, or keys in RAM or disk), and enters a clean Decoy Workspace with zero visible indication that a wipe just occurred.

---

### CLIENT-013-T05: `AppViewModel`, `WorkspaceViewModel` & QML Emergency Panic, Duress & Decoy UX

- **Component:** `src/client/ui/app_view_model.{hpp,cpp}`, `src/client/ui/workspace_view_model.{hpp,cpp}`, `src/client/ui/qml/Main.qml`, `src/client/ui/qml/NavigationShell.qml`, `src/client/ui/qml/EmergencyPlaceholder.qml`, `src/client/ui/qml/LoginPlaceholder.qml`, `src/client/ui/qml/SettingsPlaceholder.qml`, `tests/unit/client/workspace_view_model_emergency_test.cpp`
- **Objective:** Expose forensic panic controls, optional pre-wipe emergency broadcast modal options, decoy mode handling, non-secret wipe verification telemetry, and duress PIN setup UI across Qt ViewModels and QML with zero QML runtime warnings.
- **Architectural Scope:**
  1. **Extend `AppViewModel` (`app_view_model.{hpp,cpp}`):**
     - New `Q_PROPERTY`s:
       - `bool isDecoySession` (`NOTIFY emergencyWipedChanged`)
       - `bool hasDuressPinConfigured` (`NOTIFY duressPolicyChanged`)
       - `QVariantMap lastWipeReportSummary` (`NOTIFY emergencyWipedChanged` — duration ms, secrets purged count, files shredded count, step status badges, trigger source, zero sensitive data)
     - New `Q_INVOKABLE`s:
       - `void triggerInstantPanicWipe(int postWipeMode = 0)`
       - `void triggerBroadcastAndPanicWipe(const QString& conversationId, const QString& alertText, const QString& locationJson = QString(), bool waitForAck = true)`
       - `bool configureDuressPin(const QString& pin, int postWipeMode = 2)`
       - `bool clearDuressPin()`
       - `void resetClientAfterWipe()` (transitions `NavigationController` back to unconfigured login and resets UI state cleanly).
     - Update `requestLogin(...)` and `triggerEmergencyWipe()` so `WorkspaceViewModel::resetForEmergencyWipe()` is invoked directly (clearing `conversations_`, `messages_`, `file_transfers_`, `devices_`, and search state), and duress logins silently open an empty **Decoy Workspace** (`showAuthenticatedChrome` renders benign workspace UI with zero leaked real messages or wipe alerts!).
  2. **Extend `WorkspaceViewModel` (`workspace_view_model.{hpp,cpp}`):**
     - Implement full `resetForEmergencyWipe()` clearing every cached vector, search query, active selection, and emergency counter (`seedDecoyWorkspace()` helper populates benign empty/default non-sensitive decoy placeholders when in decoy mode, or cleanly resets to empty).
  3. **Update QML Screens (`Main.qml`, `EmergencyPlaceholder.qml`, `SettingsPlaceholder.qml`):**
     - **`Main.qml`:** Upgrade `emergencyConfirmDialog` (`objectName: "emergencyPanicModal"`) to let the operator either trigger **Instant Forensic Wipe** or check **"Send Encrypted Emergency Broadcast Before Wipe"** (with conversation selector / optional distress note) while preserving 1-click keyboard/button immediacy.
     - **`EmergencyPlaceholder.qml`:** Upgrade into a comprehensive forensic wipe confirmation card showing elapsed wipe time (`"<duration> ms"`), secrets purged count, files shredded count, volatile caches cleared count, and a `"Reset to Clean Unconfigured State"` button.
     - **`SettingsPlaceholder.qml`:** Add a compact **Emergency Defense & Duress Policy** sub-section enabling the user to configure/remove the Login Duress PIN (with an Option A helper hint recommending a `12+` character password-style passphrase while allowing `>= 6` characters) and choose post-wipe behavior (`EmergencyLocked` vs `DecoyWorkspace`).
- **Acceptance Criteria:**
  - `workspace_view_model_emergency_test.cpp` verifies headless QML loading of `Main.qml` / `EmergencyPlaceholder.qml` with `0` QML warnings, tests instant panic wipe, broadcast-then-wipe, and silent duress login routing to an empty Decoy Workspace with `0` real messages remaining.

---

### CLIENT-013-T06: Emergency Panic & Forensic Wipe E2E Integration Suite, Tier 1/2 Smoke Tests & Walkthrough

- **Component:** `tests/unit/client/emergency_panic_wipe_integration_test.cpp`, `tests/unit/CMakeLists.txt`, `src/client/main.cpp`, `docs/final-reports/walkthrough-client-013.md`, `docs/pull_requests/CLIENT-013.md`
- **Objective:** Validate all emergency panic triggers, cryptographic & forensic destruction guarantees (`< 500 ms`), pre-wipe E2EE emergency broadcast, silent duress decoy mode, and desktop UI states end-to-end.
- **Architectural Scope:**
  1. Create `tests/unit/client/emergency_panic_wipe_integration_test.cpp` with **5 E2E Scenarios**:
     - **Scenario 1 — `< 500 ms` Forensic Wipe Across Active Vault, Ratchets, Files & Logs:**
       - Populate real `SqlCipherLocalStore`, Double Ratchet sessions, Sender Keys, `offline_outbox` drafts, unfinished `.part` file downloads, active `FileTransferRecord`s, and synthetic client log file; invoke panic wipe via `EmergencyManager::execute_panic_wipe`; assert elapsed time `< 500 ms`, `ISecureStorage::list_secret_keys()` empty, `.db`/`-wal`/`-shm`/`.part`/`.log` completely shredded and unlinked, and volatile manager caches empty.
     - **Scenario 2 — Pre-Wipe E2EE Emergency Broadcast + Operator Acknowledgement Then Forensic Wipe (`ADR-007`, `ADR-008 §21-22`):**
       - Stage `priority = 3` E2EE alert (including encrypted location JSON) to Bob's device; verify Bob decrypts authentic ciphertext via normal Double Ratchet (zero backdoor keys on Gateway!), acknowledge delivery on Gateway, then confirm Alice's local store and keys are immediately shredded afterward; also verify offline-Gateway timeout bound (`ack_timeout`) does **not** stall destruction.
     - **Scenario 3 — Login Duress PIN Silent Wipe -> Plausible Decoy Workspace:**
       - Configure Duress PIN on Alice's workstation with populated vault; simulate attacker forcing login on `AppViewModel::requestLogin(user, duress_pin)`; assert `< 500 ms` complete destruction of Alice's real data, `0` failed auth/duress alerts sent to Gateway, and `AppViewModel` landing cleanly on `DecoyWorkspace` with `conversations().empty()` or benign non-sensitive state and `isDecoySession == true`.
     - **Scenario 4 — Clean Unconfigured Reset & Fresh Re-Onboarding After Panic Wipe:**
       - Execute panic wipe (`UnconfiguredReset` mode), call `resetClientAfterWipe()`, verify fresh device identity registration + new `SqlCipherLocalStore` initialization succeeds cleanly without leftover wiped artifacts or stale locks.
     - **Scenario 5 — Headless QML Panic Dialog, `EmergencyPlaceholder.qml` & Decoy UI Lifecycle:**
       - Instantiate real QML components (`Main.qml` / `EmergencyPlaceholder.qml`), verify zero QML runtime warnings, confirm panic modal & post-wipe audit report bindings render cleanly in both Dark and Light themes.
  2. Extend `src/client/main.cpp` `--capture-screenshots` to capture dark & light post-wipe / panic modal states into `docs/final-reports/assets/client-013/`.
  3. Execute Tier 1 (`--smoke-test`), Tier 2 (`--capture-screenshots`), `check-format`, and full test suite, and author `docs/final-reports/walkthrough-client-013.md` (recording Option A `6..1024` byte duress policy, `DuressPinConfig` one-shot fuse, `FileShredder` / CoW defense-in-depth, `ClientLogger` disk log closure/redaction, and Phase 0 user-flow / fail-safe resilience) and `docs/pull_requests/CLIENT-013.md`.
- **Acceptance Criteria:**
  - All 5 scenarios pass cleanly under strict `-Werror` with observed panic wipe latency `< 500 ms`.
  - Tier 1 and Tier 2 smoke runs pass with `0` QML warnings.
  - `check-format` (`100%` `.clang-format` compliance) passes.

---

## 4. Architectural Invariants & Non-Goals

1. **No Emergency Decryption Backdoor (`ADR-008 §22`):**
   - Pre-wipe emergency broadcasts strictly reuse standard endpoint-to-endpoint X3DH/Double Ratchet or Sender Key encryption (`priority = 3`). There is no server-side or administrator decryption key.
2. **Fail-Safe Destruction Priority (Network Failures Never Block Local Wipe):**
   - If pre-wipe emergency broadcast fails or acknowledgement times out (`ack_timeout`), `EmergencyManager` must immediately proceed to volatile zeroization, `ISecureStorage` purge, and `FileShredder` disk destruction.
3. **Sub-500 ms Forensic Wipe Budget & Honest Media Caveats:**
   - All normal vaults, ratchets, `.part` caches, and key stores must wipe within `< 500 ms`. Multi-pass file shredding (`0x00`, `0xFF`, `RAND_bytes`) + SQLCipher master-key destruction (`kMasterKeyId` purge) work together as defense-in-depth while documenting SSD wear-leveling / copy-on-write filesystem semantics transparently.
4. **Zero Secret Logging (`ADR-008 §28`):**
   - Neither duress PINs, PBKDF2 hashes, SQLCipher master keys, nor plaintext distress payloads may ever be logged or placed into `EmergencyWipeReport`.
5. **Phase Boundary (`CLIENT-013` vs. `CLIENT-014`–`CLIENT-016`, Option A):**
   - User profile, settings persistence, accessibility, proxy/TLS pinning, disappearing timers, BIP-39 recovery, and the live TLS 1.3 `QtHttpGatewayClient` network adapter belong to **`CLIENT-014`**; local hash-chained audit logging, cryptographic boot self-tests, live telemetry, CPU/RAM benchmark harness (`client-performance-benchmark-report.md`), and the live Client ↔ Gateway/Backend E2E integration suite (`tests/integration/client_gateway_backend_integration_test.cpp` + Docker Compose validation) to **`CLIENT-015`**; and cross-platform installers (macOS `.dmg`, Windows MSI/MSIX, Linux AppImage/`.deb`), native OS Keychain / DPAPI / SecretService `ISecureStorage` adapter, and Ed25519-signed auto-update to **`CLIENT-016`**.

---

## 5. Verification & Completion Gate Commands

```bash
# 1. Configure & build all client + test targets with -Werror
cmake --build build/dev-debug --target securecloud_client_foundation_test securecloud-client --parallel

# 2. Run all CLIENT-013 unit & E2E integration suites
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test \
  --gtest_filter="*Emergency*:*FileShredder*:*Duress*"

# 3. Run full client test suite + Tier 1 & Tier 2 real-binary smoke tests
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test --gtest_brief=1
QT_QPA_PLATFORM=offscreen ./build/dev-debug/src/client/securecloud-client --smoke-test
QT_QPA_PLATFORM=offscreen ./build/dev-debug/src/client/securecloud-client --capture-screenshots /tmp/sc-client013-shots

# 4. Verify 100% clang-format compliance
cmake --build build/dev-debug --target check-format
```
