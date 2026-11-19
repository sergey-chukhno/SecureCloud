# CLIENT-011 Ticket Decomposition: Encrypted File Transfer & Streaming

- **Milestone Card:** `CLIENT-011` — Encrypted File Transfer & Streaming
- **Phase:** Desktop Client Phase 3
- **Target Branch:** `feature/client-011-encrypted-file-transfer-and-streaming`
- **Owner:** Sergey
- **Dependencies:** `CLIENT-006` (X3DH / Double Ratchet), `CLIENT-009` (Direct & Group Messaging + `SqlCipherLocalStore`), `FILE-001` – `FILE-010` (`proto/securecloud/files/v1/files.proto`, `src/files/`), `GW-010` (`src/gateway/http/proxy/files_proxy_handler.cpp`), `ADR-004` (HTTPS REST/JSON external, gRPC internal), `ADR-008 §20` (File Encryption), `ADR-010` (Bounded Streaming & Resource Controls)

---

## 1. Executive Summary & Scope

`CLIENT-011` delivers end-to-end encrypted, resumable chunked file transfers and streaming verification for the SecureCloud Desktop Client (`securecloud-client`), integrating the client application and UI cleanly with the implemented `FilesService` (`FILE-001`–`FILE-010`) and Gateway `FilesProxyHandler` (`GW-010`):

```text
┌─────────────────────────────┐     ┌─────────────────────────────┐     ┌─────────────────────────────┐
│  WorkspaceViewModel & QML   │     │  FileManager &              │     │  Gateway FilesProxyHandler  │
│  (Qt Quick FileDialog,      │────▶│  FileCryptoEngine           │────▶│  (HTTPS REST/JSON           │
│   Files Vault Ledger,       │     │  - 4 MiB Framed AES-256-GCM │     │   /api/v1/files/upload/*,   │
│   0..100% Progress Bars,    │◀────│  - HKDF IV + Chunk AAD      │◀────│   /:id/chunks/:idx,         │
│   Pause / Resume / Cancel)  │     │  - Dual SHA-256 Attestation │     │   /:id/metadata)            │
└─────────────────────────────┘     │  - Key Envelope -> Messaging│     └──────────────┬──────────────┘
                                    └──────────────┬──────────────┘                    │ (gRPC)
                                                   │                          ┌────────▼────────┐
                                    ┌──────────────▼──────────────┐           │  FilesService   │
                                    │  SqlCipherLocalStore &      │           │  (PostgreSQL +  │
                                    │  ISecureStorage             │           │   MinIO - Zero  │
                                    │  (file_transfers table +    │           │   Plaintext/Key)│
                                    │   per-file 256-bit key)     │           └─────────────────┘
                                    └─────────────────────────────┘
```

### Ticket Status Matrix

| Ticket | Title | Status | Target Scope |
|---|---|---|---|
| **CLIENT-011-T01** | File Transfer Domain Models, Key Envelope & `IGatewayClient` Files REST Contracts | **Completed** | `FileTransferDirection`, `FileTransferStatus`, `FileTransferRecord`, `FileAttachmentKeyEnvelope`, `IGatewayClient` & `DefaultGatewayClient` 7 Files REST contracts |
| **CLIENT-011-T02** | Streaming AEAD Chunk Encryption/Decryption Engine & Dual SHA-256 Attestation | **Planned** | `FileCryptoEngine` (`4 MiB` wire chunks = `4 MiB - 28 B` plaintext + `12 B IV` + `16 B GCM tag`), HKDF per-chunk IV, AAD binding, `StreamingSha256` |
| **CLIENT-011-T03** | Resumable Transfer Checkpoints in `ILocalStore` & `SqlCipherLocalStore` | **Planned** | `file_transfers` table in `SqlCipherLocalStore`, `ILocalStore` transfer CRUD methods, zero-plaintext `.db` invariant |
| **CLIENT-011-T04** | Production `FileManager` Resumable Upload/Download Pipeline & E2EE Key Distribution | **Planned** | Streaming upload/download in `FileManager`, `ISecureStorage` key storage (`file_transfer.key.<file_id>`), Pause/Resume/Cancel, ADR-008 guarded `FileAttachmentKeyEnvelope` dispatch via `MessagingManager`, atomic `.part` download verification |
| **CLIENT-011-T05** | `WorkspaceViewModel` Vault Progress/Controls & QML Native File Picker / Progress UI | **Planned** | Startup hydration of `file_transfers`, `uploadLocalFile`, `downloadEncryptedFile`, `pauseFileTransfer`, `resumeFileTransfer`, `cancelFileTransfer`, `ProgressBar` & Qt Quick `FileDialog` in `WorkspacePlaceholder.qml` |
| **CLIENT-011-T06** | Encrypted File Transfer & Streaming E2E Integration Suite & Walkthrough Report | **Planned** | 5-scenario E2E integration suite (`encrypted_file_transfer_integration_test.cpp`), 100% test/format/warning gate, `--smoke-test`, `walkthrough-client-011.md` |

---

## 2. Architecture, Backend & Codebase Audit: What Already Exists vs. Net-New Scope

### 2.1 Critical Backend Alignment Finding (`4 MiB` Wire Chunk Contract vs. Early Backlog "1MB")
Early notes in `docs/planning/initial-backlog.md` (line 742) referenced `1MB` blocks, **whereas the actual implemented backend (`FilesService` and `Gateway`) strictly enforces a `4 MiB` wire chunk contract**:
- `src/files/domain/metadata_validator.hpp`:
  - `k_standard_chunk_size = 4U * 1024U * 1024U` (`4 MiB` = `4,194,304` bytes)
  - `k_max_file_size_bytes = 5 GiB` (`5ULL * 1024ULL * 1024ULL * 1024ULL`)
  - `k_approved_encryption_algorithm = "XChaCha20-Poly1305"`
- `src/files/domain/chunk_validator.cpp`:
  - Non-terminal chunks **must** equal `k_standard_chunk_size` (`// Non-terminal chunks must be exactly k_standard_chunk_size (4 MiB)`), with `chunk_size_bytes` matching the encrypted chunk byte length (`encrypted_data.size()`), within `[k_min_chunk_size (1 B), k_max_chunk_size (8 MiB)]`.
- `src/gateway/gateway_config.hpp`:
  - `max_chunk_size_bytes = 4194304` (`4 MiB` default)
- `proto/securecloud/files/v1/files.proto`:
  - `CreateFileUploadRequest.expected_chunk_count` (`// Number of 4 MiB chunks`) and `encryption_version` (e.g., `"v1"`).

**Framing Solution (`CLIENT-011-T02`)**:
To satisfy both AES-256-GCM per-chunk framing and the backend's exact `4 MiB` wire chunk size requirement without rejection on `UploadChunk`:
- Each non-terminal framed wire chunk is `12 B IV || ciphertext || 16 B GCM tag` = **exactly `4,194,304` bytes (`4 MiB`)**.
- Therefore, each non-terminal plaintext slice read from disk is `4 MiB - 28 bytes` (`4,194,276` bytes), so `12 + 4,194,276 + 16 == 4,194,304` bytes on the wire.
- `FileCryptoEngine` accepts a configurable wire chunk size parameter (defaulting to `4 MiB` in production) so multi-chunk unit and integration tests can also exercise multi-chunk streaming rapidly with smaller synthetic sizes.

### 2.2 Implemented Gateway & `FilesService` Endpoints (`src/gateway/http/proxy/files_proxy_handler.cpp`)
Per `ADR-004`, Client ↔ Gateway uses HTTPS REST/JSON and binary chunk bodies across these implemented routes in `FilesProxyHandler::register_routes`:
1. `POST /api/v1/files/upload/init` — Request JSON: `file_id`, `owner_user_id`, `owner_device_id`, `conversation_id`, `encrypted_size_bytes`, `expected_chunk_count`, `encryption_version` (`"v1"`). Response `201`: `upload_id`, `file_id`, `status` (`"TRANSFER_STATUS_PENDING"`), `expires_at_unix_ms`.
2. `POST /api/v1/files/upload/chunk` — Headers: `Upload-Id` (or `X-Upload-Id`), `Chunk-Index` (or `X-Chunk-Index`), `X-Ciphertext-SHA256` (optional/verified against body), binary body `<= max_chunk_size_bytes`. Response `200`: `upload_id`, `chunk_index`, `accepted`, `received_sha256`.
3. `POST /api/v1/files/upload/finalize` — JSON: `upload_id`, `file_id`, `expected_ciphertext_sha256`. Response `200`: `file_id`, `lifecycle_state` (`"FILE_LIFECYCLE_STATE_AVAILABLE"`), `available_at_unix_ms`.
4. `POST /api/v1/files/upload/cancel` — JSON: `upload_id`, `reason`. Response `200`: `upload_id`, `status`.
5. `GET /api/v1/files/:file_id/metadata` — Returns file metadata, `lifecycle_state`, `encrypted_size_bytes`, `chunk_count`, `encryption_version`, `ciphertext_integrity_hash`, timestamps.
6. `GET /api/v1/files/:file_id/chunks/:chunk_index` — Returns encrypted chunk bytes and `ciphertext_sha256`.
7. `GET /api/v1/files/:file_id/download` — Streaming download route.
8. `DELETE /api/v1/files/:file_id` — Logical deletion.

*Cipher Suite & Algorithm Agility (`ADR-008 §31`)*: `OpenSslCryptoProvider` already provides hardware-accelerated AES-256-GCM (`encrypt_aes_gcm`, `decrypt_aes_gcm`) and HKDF-SHA256 (`hkdf_extract_and_expand`). `FilesProxyHandler` forwards `encryption_version` (`"v1"`) and opaque ciphertext bytes without decrypting. `FileAttachmentKeyEnvelope` and `client_crypto_metadata` will explicitly version `cipher_suite` (e.g., `"AES-256-GCM-v1"`, preserving algorithm agility alongside `metadata_validator.hpp`'s `"XChaCha20-Poly1305"` metadata constant).

### 2.3 Already Implemented on Client (Do NOT Re-Implement)
1. **Cryptographic Primitives (`src/client/application/interfaces/i_crypto_provider.hpp` & `src/client/infrastructure/adapters/openssl_crypto_provider.cpp`)**:
   - `encrypt_aes_gcm`, `decrypt_aes_gcm`, `hkdf_extract_and_expand`, OpenSSL 3.x `RAND_bytes`, and `EVP_sha256`.
2. **E2EE Messaging & Key Distribution (`MessagingManager`, `CLIENT-006`/`CLIENT-009`/`CLIENT-010`)**:
   - 1:1 Double Ratchet & Group Sender Keys (`SCG` v1) fan-out with ADR-008 `KeyChanged` and blocked-user guards.
   - `domain::Message` already carries `attachment_name_`, `attachment_size_`, and `attachment_hash_`.
3. **Encrypted Local SQLite Database (`SqlCipherLocalStore`, `CLIENT-009-T02`)**:
   - Native `libsqlcipher` AES-256-CBC + HMAC-SHA512 database managed via `ISecureStorage` 256-bit key lifecycle — extend with a `file_transfers` table rather than introducing a second database.
4. **`FileManager` Service Shell (`src/client/application/managers/file_manager.hpp/.cpp`)**:
   - Already constructed and wired inside `ClientBootstrap::wire_managers()`. Must be evolved in place.
5. **UI / ViewModel Scaffolding (`WorkspaceViewModel` & `WorkspacePlaceholder.qml`)**:
   - `WorkspaceViewModel` already declares `fileTransfers`, `activeFileTransferCount`, `sharedFilesForSelectedPeer`, `selectedTransferId`, `selectedTransferDetails`, `selectTransfer`, `stageEncryptedFileTransfer`, `cancelFileTransfer`, `FileTransferEntry`, and `MessageEntry::isFileTransfer` / `transferId` / `fileName` / `fileSizeText` / `cipherSuite` / `sha256Short`.
   - `WorkspacePlaceholder.qml` already renders the Files Vault view (`fileTransfers` Repeater, selected manifest card, Open Thread & Revoke Transfer buttons, and inline file attachment bubbles).

### 2.4 Net-New Scope Required by `CLIENT-011`
1. **No File Transfer Domain Models or Gateway Files Contracts**: `IGatewayClient` and `DefaultGatewayClient` have no methods for `/api/v1/files/*`, and no `FileTransferRecord` / `FileAttachmentKeyEnvelope` domain models exist yet.
2. **No Streaming Chunk AEAD Engine or Dual SHA-256 Attestation**: `FileManager::prepare_encrypted_upload` only probes `/health` and returns `"transfer-id-001"`; no constant-memory chunk encryptor/decryptor or whole-file SHA-256 verifier exists.
3. **No Persistent Resumable Transfer Checkpoints**: `ILocalStore` / `SqlCipherLocalStore` only store `conversations`, `messages`, and `contacts` — no `file_transfers` checkpoint table exists yet.
4. **No Resumable Upload/Download State Machine or Key Distribution Pipeline**: `FileManager` cannot encrypt chunks, upload/download chunks, pause/resume from `completed_chunks`, store `file_key` in `ISecureStorage`, dispatch `FileAttachmentKeyEnvelope` via `MessagingManager`, or verify downloads before atomic rename.
5. **No Live Transfer Progress (`0..100%`) or Native File Picker Binding in `WorkspaceViewModel` / QML**: `stageEncryptedFileTransfer` currently stubs a hardcoded hash (`"e3b0c442...98fc1c14"`) and status (`"Encrypted & Verified"`) without real file I/O, Pause/Resume/Download controls, or `FileDialog` wiring.
6. **No E2E File Transfer Integration Suite**: Needs full multi-workstation upload → key delivery → download, pause/restart resume, tamper/AAD/corruption fail-closed, and UI binding tests.

---

## 3. Detailed Ticket Specifications (`CLIENT-011-T01` – `CLIENT-011-T06`)

### CLIENT-011-T01: File Transfer Domain Models, Key Envelope & `IGatewayClient` Files REST Contracts
- **Component:** `src/client/domain/file_transfer.hpp/.cpp`, `src/client/application/interfaces/i_gateway_client.hpp`, `src/client/infrastructure/adapters/default_gateway_client.*`, `tests/unit/client/client_domain_test.cpp`, `tests/unit/client/file_gateway_contracts_test.cpp`
- **Objective:** Establish typed domain models, wire/envelope serialization, and Gateway Files REST abstractions aligned with `FilesProxyHandler` and `files.proto`.
- **Architectural Scope:**
  1. Define `FileTransferDirection` (`Outbound`, `Inbound`) and `FileTransferStatus` (`Pending`, `InProgress`, `Paused`, `Finalizing`, `Completed`, `Cancelled`, `Failed`) with `to_string` / `from_string`.
  2. Define `FileTransferRecord` holding `transfer_id`, `file_id`, `upload_id`, `conversation_id`, `peer_user_id`, `local_path`, `file_name`, `mime_type`, `cipher_suite`, `direction`, `status`, `plaintext_size_bytes`, `encrypted_size_bytes`, `chunk_size_bytes`, `total_chunks`, `completed_chunks` (checkpoint count / bitmask or contiguous index), `plaintext_sha256`, `ciphertext_sha256`, `created_at`, `updated_at`, with `to_json()` / `from_json()` round-trip.
  3. Define `FileAttachmentKeyEnvelope` (JSON `serialize()` / `deserialize()`) carrying `file_id`, `file_key_b64` / hex secret key, `file_name`, `mime_type`, `plaintext_size_bytes`, `encrypted_size_bytes`, `chunk_size_bytes`, `chunk_count`, `ciphertext_sha256`, `plaintext_sha256`, `cipher_suite`.
  4. Extend `IGatewayClient` and `DefaultGatewayClient` (and update `MockGatewayClient` in `client_domain_test.cpp`) with the 7 Files REST contracts:
     - `init_file_upload(const FileUploadInitRequest&)` → `FileUploadInitResult`
     - `upload_file_chunk(const FileChunkUploadRequest&)` → `FileChunkUploadResult`
     - `finalize_file_upload(const FileUploadFinalizeRequest&)` → `FileUploadFinalizeResult`
     - `cancel_file_upload(std::string_view upload_id, std::string_view reason)` → `ClientResult<void>`
     - `get_file_metadata(std::string_view file_id)` → `RemoteFileMetadata`
     - `download_file_chunk(std::string_view file_id, uint32_t chunk_index)` → `FileChunkDownloadResult`
     - `delete_file(std::string_view file_id)` → `ClientResult<void>`
  5. Implement deterministic in-memory chunk storage & simulation hooks on `DefaultGatewayClient` (upload sessions, stored ciphertext chunks per `file_id`, SHA-256 verification mirroring `FilesProxyHandler`, and failure simulation hooks).
- **Deliverables:** `file_transfer.hpp/.cpp`, updated `i_gateway_client.hpp`, `default_gateway_client.hpp/.cpp`, `MockGatewayClient`, `file_gateway_contracts_test.cpp`, `tests/unit/CMakeLists.txt`.

### CLIENT-011-T02: Streaming AEAD Chunk Encryption/Decryption Engine & Dual SHA-256 Attestation
- **Component:** `src/client/domain/crypto/file_crypto_engine.hpp/.cpp`, `src/client/CMakeLists.txt`, `tests/unit/client/file_crypto_engine_test.cpp`
- **Objective:** Provide constant-memory streaming encryption, decryption, and cryptographic integrity verification compatible with `4 MiB` backend chunk rules.
- **Architectural Scope:**
  1. Constants: `kDefaultWireChunkSize = 4U * 1024U * 1024U` (`4 MiB`), `kIvBytes = 12`, `kTagBytes = 16`, `kChunkOverheadBytes = 28`, `kDefaultPlaintextChunkSize = kDefaultWireChunkSize - kChunkOverheadBytes`. Support configurable `wire_chunk_size` (must be `> kChunkOverheadBytes` and `<= 8 MiB`) for fast multi-chunk unit tests.
  2. CSPRNG `generate_file_key()` producing a 256-bit `SecretString` via OpenSSL `RAND_bytes` (`OPENSSL_cleanse` on destruction).
  3. Deterministic per-chunk 96-bit IV derivation via `ICryptoProvider::hkdf_extract_and_expand` with domain separator `"SC-FILE-CHUNK-IV-v1"` + `file_id` + big-endian `chunk_index` (unique IV per chunk, zero IV reuse across chunks).
  4. Structured AAD binding: `"SC-FILE-CHUNK-v1" || file_id || uint32_be(chunk_index) || uint8(is_final)` preventing chunk reordering, cross-file splicing, or stream truncation.
  5. Framed `encrypt_chunk(...)` (`12 B IV || ciphertext || 16 B GCM tag`, so non-terminal encrypted chunks are **exact** multiples matching `FilesService` `k_standard_chunk_size` when configured to `4 MiB`) and `decrypt_chunk(...)`.
  6. `StreamingSha256` incremental OpenSSL `EVP_MD_CTX` wrapper computing both per-chunk `ciphertext_sha256` and rolling whole-file `ciphertext_sha256` & `plaintext_sha256` in constant memory (`O(chunk_size)` RAM regardless of total file size up to `5 GiB`).
- **Deliverables:** `file_crypto_engine.hpp/.cpp`, `src/client/CMakeLists.txt`, `file_crypto_engine_test.cpp`.

### CLIENT-011-T03: Resumable Transfer Checkpoints in `ILocalStore` & `SqlCipherLocalStore`
- **Component:** `src/client/application/interfaces/i_local_store.hpp`, `src/client/infrastructure/adapters/memory_local_store.*`, `src/client/infrastructure/adapters/sqlcipher_local_store.*`, `tests/unit/client/file_transfer_persistence_test.cpp`
- **Objective:** Persist file transfer state, progress checkpoints (`completed_chunks`), and integrity digests in encrypted SQLCipher storage so transfers survive restarts without plaintext leakage on disk.
- **Architectural Scope:**
  1. Extend `ILocalStore` with:
     - `save_file_transfer(const domain::FileTransferRecord& record)`
     - `get_file_transfer(std::string_view transfer_id)`
     - `list_file_transfers(const domain::ConversationId& conversation_id = {})`
     - `delete_file_transfer(std::string_view transfer_id)`
  2. Implement the 4 methods in `MemoryLocalStore`, `SqlCipherLocalStore` (adding `CREATE TABLE IF NOT EXISTS file_transfers (transfer_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, updated_at_ms INTEGER NOT NULL, payload_json TEXT NOT NULL)` + index on `updated_at_ms DESC`), and any existing mock `ILocalStore` test doubles.
  3. Unit test CRUD round-trip, SQLCipher restart durability, and raw `.db` byte inspection confirming zero plaintext filenames, hashes, or local paths on disk.
- **Deliverables:** Updated `i_local_store.hpp`, `memory_local_store.*`, `sqlcipher_local_store.*`, `file_transfer_persistence_test.cpp`.

### CLIENT-011-T04: Production `FileManager` Resumable Upload/Download Pipeline & E2EE Key Distribution
- **Component:** `src/client/application/managers/file_manager.hpp/.cpp`, `src/client/application/client_bootstrap.cpp`, `tests/unit/client/file_manager_pipeline_test.cpp`
- **Objective:** Replace the stub `FileManager` with a complete, resumable, fail-closed encrypted transfer pipeline integrated with `MessagingManager` and `ISecureStorage`.
- **Architectural Scope:**
  1. Wire `ILocalStore*`, `ISecureStorage*`, and `MessagingManager*` into `FileManager` in `ClientBootstrap::wire_managers()`.
  2. Store each transfer's 256-bit `file_key` exclusively in `ISecureStorage` under `"file_transfer.key.<file_id>"` (deleted/zeroized on cancel; kept only as needed for authorized local access or removed cleanly per lifecycle).
  3. **Upload Pipeline (`start_upload`, `resume_transfer`)**:
     - Validate file existence, non-empty / `<= 5 GiB` size, and ADR-008 recipient eligibility before transferring.
     - Pre-compute `expected_chunk_count` and stream plaintext chunks through `FileCryptoEngine` (`encrypt_chunk`) while accumulating rolling plaintext + ciphertext SHA-256 digests.
     - On fresh start: call `gateway_.init_file_upload(...)`, store `upload_id`, and save initial `FileTransferRecord` checkpoint (`InProgress`).
     - Loop `chunk_index` from `record.completed_chunks` to `total_chunks - 1`: check pause/cancel flags before each chunk; upload via `gateway_.upload_file_chunk(...)`; update and persist `record.completed_chunks` in `ILocalStore` after each acknowledged chunk; emit progress callback (`0..100%`).
     - On completion of all chunks: call `gateway_.finalize_file_upload(...)` with `expected_ciphertext_sha256`; mark `Completed`; serialize `FileAttachmentKeyEnvelope` and dispatch E2EE to conversation participants via `MessagingManager::stage_outbound_message(...)`.
  4. **Download Pipeline (`start_download`, `resume_download`)**:
     - Receive `FileAttachmentKeyEnvelope` (from decrypted `MessagingManager` attachment message), store `file_key` in `ISecureStorage`, query `gateway_.get_file_metadata(file_id)`, verify chunk count / size consistency.
     - Download chunk-by-chunk (`chunk_index` from `record.completed_chunks` to `chunk_count - 1`) to a staging `<destination>.part` file, verifying per-chunk `ciphertext_sha256`, AEAD GCM auth tag + `(file_id, chunk_index, is_final)` AAD, and decrypting in streaming constant memory.
     - After all chunks: verify rolling `ciphertext_sha256` and `plaintext_sha256` against the trusted E2EE `FileAttachmentKeyEnvelope`; fail closed (delete `.part` and mark `Failed`) on any mismatch; only on 100% verification atomically rename `.part` to final destination path.
  5. **Pause & Cancel Controls (`pause_transfer`, `cancel_transfer`)**:
     - `pause_transfer` transitions active upload/download cleanly to `Paused` at chunk boundary while preserving `completed_chunks` checkpoint in `ILocalStore` and `file_key` in `ISecureStorage`.
     - `cancel_transfer` transitions to `Cancelled`, calls `gateway_.cancel_file_upload(...)` for active uploads, deletes temporary `.part` files, and removes `file_transfer.key.<file_id>` from `ISecureStorage`.
- **Deliverables:** Updated `file_manager.hpp/.cpp`, `client_bootstrap.cpp`, `file_manager_pipeline_test.cpp`.

### CLIENT-011-T05: `WorkspaceViewModel` Vault Progress/Controls & QML Native File Picker / Progress UI
- **Component:** `src/client/ui/workspace_view_model.hpp/.cpp`, `src/client/ui/qml/WorkspacePlaceholder.qml`, `tests/unit/client/workspace_view_model_files_test.cpp`
- **Objective:** Expose real transfer progress (`0..100%`), Pause/Resume/Download/Cancel actions, and native OS file picker selection to the Files Vault and conversation composer while keeping existing UI tests green.
- **Architectural Scope:**
  1. Hydrate `file_transfers_` from `ILocalStore::list_file_transfers()` inside `WorkspaceViewModel::hydrateFromLocalStore()` when in persistent DB mode (preserving seeded mock transfers only when in headless in-memory test mode with no persisted data).
  2. Extend `FileTransferEntry` (and `fileTransfers()` / `selectedTransferDetails()`) with `progressPercent` (`int`, `0..100`), `completedChunks`, `totalChunks`, `status` (`Pending`/`InProgress`/`Paused`/`Finalizing`/`Completed`/`Cancelled`/`Failed`), `fileId`, `localPath`, `canPause`, `canResume`, `canDownload`.
  3. Wire `FileManager` progress/state callbacks into `WorkspaceViewModel` via `QPointer<WorkspaceViewModel>` + `QMetaObject::invokeMethod(..., Qt::QueuedConnection)`.
  4. Implement `Q_INVOKABLE` methods on `WorkspaceViewModel`:
     - `uploadLocalFile(const QString& localFilePathOrUrl)` (normalizes `file://` URLs from Qt `FileDialog` and drives `FileManager::start_upload(...)` for `selected_conversation_id_`)
     - `downloadEncryptedFile(const QString& transferId, const QString& destinationPathOrUrl)`
     - `pauseFileTransfer(const QString& transferId)`
     - `resumeFileTransfer(const QString& transferId)`
     - Keep `stageEncryptedFileTransfer(...)` & `cancelFileTransfer(...)` compatible with existing `UiComponentsTest` / `WorkspaceViewModelGroupAndRetryTest` calls while integrating real `FileManager` cancellation when applicable.
  5. Enhance `src/client/ui/qml/WorkspacePlaceholder.qml`:
     - Wire Qt Quick `QtQuick.Dialogs` (`FileDialog` for picking a local upload file and save destination) alongside graceful fallback triggers in headless mode.
     - Add inline & Vault `ProgressBar` (`0..100%`, chunk readout `"3 / 8 chunks"`) plus **Pause**, **Resume**, **Download**, and **Cancel** buttons in the Vault manifest card & chat attachment bubbles.
- **Deliverables:** Updated `workspace_view_model.hpp/.cpp`, `WorkspacePlaceholder.qml`, `workspace_view_model_files_test.cpp`, `tests/unit/CMakeLists.txt`.

### CLIENT-011-T06: Encrypted File Transfer & Streaming E2E Integration Suite & Walkthrough Report
- **Component:** `tests/unit/client/encrypted_file_transfer_integration_test.cpp`, `tests/unit/CMakeLists.txt`, `docs/final-reports/walkthrough-client-011.md`
- **Objective:** Validate all Phase 3 `CLIENT-011` capabilities end-to-end across multi-workstation SQLCipher topologies, pass all build/format/smoke gates, and author the comprehensive Card 011 walkthrough report.
- **Architectural Scope:**
  1. End-to-End Integration Suite (`tests/unit/client/encrypted_file_transfer_integration_test.cpp`, 5 scenarios running in-process with zero Docker):
     - **Scenario 1 — Multi-Chunk Encrypted Upload → E2EE Key Envelope Delivery → Verified Download**: Alice encrypts a multi-chunk file, uploads chunks via `DefaultGatewayClient`, delivers `FileAttachmentKeyEnvelope` to Bob via `MessagingManager` Double Ratchet, Bob downloads & verifies dual SHA-256 + GCM tags; assert bit-identical reconstructed file and zero plaintext bytes in Gateway chunk store or SQLCipher `.db` files.
     - **Scenario 2 — Mid-Transfer Pause & Full Application Restart Resume**: Upload pauses after 2/5 chunks; Alice shuts down and restarts `ClientApplication` against `SqlCipherLocalStore` + `ISecureStorage`; `resume_transfer` uploads strictly chunks 2–4 without re-uploading chunks 0–1; similarly verify download pause + restart resume from `.part` file.
     - **Scenario 3 — Tampered Chunk, Swapped Index (AAD), Truncated Stream & Wrong Key Fail-Closed**: Mutate 1 ciphertext byte (fails SHA-256/GCM), swap chunk 0 and chunk 1 (fails AAD `chunk_index`), truncate terminal chunk (fails `is_final` AAD / whole-file SHA-256), decrypt with wrong `file_key` (fails GCM tag) — confirm destination file is never committed.
     - **Scenario 4 — Multi-Megabyte Constant-Memory Streaming, Cancellation & ADR-008 Guard**: Stream a multi-MiB file in chunks verifying exact `4 MiB` wire chunk sizing compatibility, verify `cancel_transfer` aborts remote upload session and deletes keys/`.part`, and verify `KeyChanged` peer state halts `FileAttachmentKeyEnvelope` dispatch until safety number re-verification.
     - **Scenario 5 — `WorkspaceViewModel` & `WorkspacePlaceholder.qml` Files Vault Progress, Pause/Resume/Cancel & Restart Hydration**: Verify QML `fileTransfers` bindings, progress updates (`0..100%`), Pause/Resume/Cancel actions, and transfer ledger hydration across restart.
  2. Quality & Smoke Gates: `100%` pass rate in `securecloud_client_foundation_test`, `0` compiler warnings (`-Werror`), `100%` `check-format`, and clean offscreen `securecloud-client --smoke-test`.
  3. Author comprehensive `docs/final-reports/walkthrough-client-011.md` (`>= 1,000` lines) and mark `CLIENT-011-T01`–`T06` **Completed**.
- **Deliverables:** `encrypted_file_transfer_integration_test.cpp`, `tests/unit/CMakeLists.txt`, `docs/final-reports/walkthrough-client-011.md`, updated `specs/client-phase3/CLIENT-011-tickets.md`.

---

## 4. Implementation Rules, Security Invariants & Boundary with `CLIENT-012`

1. **Zero Unapproved Third-Party Library Churn**:
   - All chunk encryption, HKDF derivation, and streaming SHA-256 hashing reuse OpenSSL 3.x EVP (`OpenSslCryptoProvider`), `libsqlcipher`, `nlohmann::json`, and Qt 6 (`QtQuick.Dialogs` standard module) already pinned in CI (`macos-15`, `ubuntu`, `windows-2022` MSVC/`vcpkg`, and MSYS2 `UCRT64`).
2. **Backend `4 MiB` Wire Chunk Compatibility**:
   - Non-terminal encrypted wire chunks transmitted to `/api/v1/files/upload/chunk` strictly match `k_standard_chunk_size = 4 MiB` (`4,194,304` bytes = `12 B IV + 4,194,276 B plaintext + 16 B GCM tag`), while exposing a configurable wire chunk size to `FileCryptoEngine` for fast multi-chunk unit tests.
3. **Zero Plaintext on Server & Zero Plaintext Checkpoints on Disk (`ADR-008 §20`)**:
   - Gateway, `FilesService`, and MinIO only ever receive ciphertext chunks, encrypted SHA-256 hashes, and opaque transfer IDs — never plaintext file bytes, plaintext filenames, or `file_key`s.
   - `SqlCipherLocalStore` encrypts `file_transfers` metadata at rest, while `file_key`s reside exclusively in `ISecureStorage`.
   - Incomplete downloads stage strictly into `<dest>.part` and are deleted on corruption or cancellation; final destination files appear only after full AEAD + dual SHA-256 verification.
4. **Boundary Between `CLIENT-011` and `CLIENT-012`**:
   - **`CLIENT-011`** owns streaming AEAD chunk crypto, `FileManager` resumable upload/download checkpoints (`Pause`/`Resume`/`Cancel`), `FileAttachmentKeyEnvelope` E2EE delivery, and Files Vault UI controls.
   - **`CLIENT-012`** owns application-wide offline connectivity observers (`Online` / `Offline` / `Syncing`), queued offline outbox draining across extended disconnects, and paginated `GET /api/v1/sync?cursor=` catch-up state reconciliation.
5. **Code Hygiene & Host Isolation**:
   - All unit and integration tests run completely in-process with zero Docker containers, PostgreSQL/MinIO daemons, or host ports required.
   - Zero compiler warnings (`-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`) and `100%` `.clang-format` compliance across the repository.
