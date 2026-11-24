# CLIENT-014 Ticket Decomposition: Settings, User Profile Management & Live TLS 1.3 Gateway Transport

- **Milestone Card:** `CLIENT-014` — Settings, User Profile Management & Live TLS 1.3 Gateway Transport (Desktop Client Phase 4)
- **Phase:** Desktop Client Phase 4 (`CLIENT-013` – `CLIENT-016`)
- **Target Branch:** `feature/client-014-settings-and-user-profile`
- **Owner:** Sergey
- **Date:** 2026-11-24
- **Dependencies:** `CLIENT-002` (`UiTheme` & `SC*` Controls), `CLIENT-003` (`SettingsPlaceholder.qml`), `CLIENT-007` (Device Management & Hardware Security), `CLIENT-009` (`SqlCipherLocalStore`), `CLIENT-010` (Read Receipt Policy), `CLIENT-011` (`FileManager` Encrypted Avatar Transfer), `CLIENT-012` (`SyncManager` & `MSG-009`), `CLIENT-013` (`EmergencyManager` Forensic Wipe & Duress Policy Integration — verified at `382 / 382` tests), `GW-001`–`010`, `AUTH-001`–`010`, `MSG-001`–`009`, `FILES-001`–`009`, `AUDIT-014`, `AUDIT-015`, `ADR-004` (HTTPS REST/JSON External Transport), `ADR-005` (Service Data Ownership), `ADR-007` (Durability & Outbox Semantics), `ADR-008 §7, §20, §22, §27, §28` (Human Identity Confidentiality, File Encryption, Endpoint-Only Recovery Key Material, Zero Secret Logging), `ADR-009` (Failure Resilience), `ADR-010` (Bounded Memory & Latency), `Detailed Design §2.8, §2.10, §2.13`

---

## 1. Executive Summary & Architectural Overview

`CLIENT-014` delivers complete, durably encrypted user profile management, runtime accessibility/appearance controls, network/proxy & TLS certificate pin inspection, disappearing message lifecycle enforcement, an endpoint-only BIP-39 cryptographic recovery phrase workflow, **and the production live TLS 1.3 `QtHttpGatewayClient` network adapter** for the SecureCloud Desktop Client (`securecloud-client`).

All preferences and profile metadata persist inside new encrypted SQLCipher tables (`user_settings`, `user_profile`) rather than volatile memory or plaintext config files, while sensitive credentials (proxy passwords, BIP-39 mnemonic/recovery seeds, verification digests) remain wrapped in `SecretString` / `ISecureStorage` and **never** traverse backend networks or logs (`ADR-008 §7, §27, §28`). Permitted public profile updates integrate with `IGatewayClient` (hydrating from `GET /api/v1/users/me` and degrading cleanly via `ProfileSyncStatus` where Auth does not yet expose a profile-mutation RPC), avatars encrypt locally via `FileCryptoEngine` / `FileManager` before chunked upload, and Dark/Light/System themes, dynamic font scaling (`0.85x–1.40x`), and WCAG AAA High-Contrast mode apply instantaneously across the QML UI without application restart. At the transport boundary, `QtHttpGatewayClient` replaces simulation when live Gateway mode is enabled, connecting `IGatewayClient` over TLS 1.3 HTTPS with SPKI SHA-256 certificate pinning and HTTP/SOCKS5 proxy support directly to the live Gateway `AuthProxyHandler`, `MessagingProxyHandler`, and `FilesProxyHandler` routes.

```text
┌────────────────────────────────────────────────────────────────────────────┐
│           SettingsPlaceholder.qml (7-Card Security & Settings Shell)       │
│  1. Local Workstation Crypto Identity  2. Linked Devices & Revocation      │
│  3. MFA & Hardware Token Policy        4. User Profile & E2EE Avatar       │
│  5. Appearance & Accessibility (Theme, Font Scale 0.85–1.40x, HighContrast)│
│  6. Network, Proxy & TLS Pin Inspector (Host/Port, HTTP/SOCKS5, Live TLS)  │
│  7. Privacy/Security & Recovery (Expiry Timers, Duress Summary, BIP-39)    │
└─────────────────────────┬───────────────────────────────┬──────────────────┘
                          │                               │
                          ▼                               ▼
            ┌───────────────────────────┐   ┌───────────────────────────┐
            │      SettingsManager      │   │          UiTheme          │
            │  - Load / Save Settings   │   │  - Dynamic fontMicro..    │
            │  - Profile & E2EE Avatar  │   │  - High-Contrast Palettes │
            │  - Proxy & TLS Pin Check  │   │  - Zero-Restart Notify    │
            │  - Default Expiry Policy  │   └───────────────────────────┘
            │  - Panic Wipe Hook (C-13) │
            └─────┬──────────┬──────────┘
                  │          │
       ┌──────────┘          └───────────┐
       ▼                                 ▼
┌────────────────────────────┐  ┌────────────────────────────────────────────┐
│   RecoveryPhraseEngine     │  │   MessagingManager & FileManager           │
│  - 2048-word BIP-39 List   │  │  - Disappearing message expires_at_ms &    │
│  - CSPRNG + SHA256 Checksum│  │    purge_expired_messages(now_ms)          │
│  - PBKDF2-HMAC-SHA512 Seed │  │  - Encrypted Avatar upload (key_env=false) │
│  - STRICTLY ENDPOINT-ONLY  │  └──────────────────┬─────────────────────────┘
└──────────────┬─────────────┘                     │
               ▼                                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  SqlCipherLocalStore (AES-256-CBC + HMAC-SHA512) & ISecureStorage          │
│  - user_settings & user_profile tables (encrypted at rest)                 │
│  - messages (expires_at_ms column + partial idx) & conv disappearing_ttl   │
│  - ISecureStorage: network.proxy.password & recovery.phrase.verifier       │
└──────────────────────────────────┬─────────────────────────────────────────┘
                                   │ (Live TLS 1.3 or Deterministic Sim Mode)
                                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│               QtHttpGatewayClient (Qt6::Network / TLS 1.3)                 │
│  - Thread-safe QNetworkAccessManager + QSslConfiguration (TLS 1.3 + SPKI)  │
│  - QNetworkProxy (None / HTTP / SOCKS5 + ISecureStorage Credentials)       │
│  - Verified Wire REST Mapping: /health/live, AuthProxyHandler,             │
│    MessagingProxyHandler (/api/v1/messages), FilesProxyHandler             │
│  * Recovery Phrase NEVER transmitted to Gateway / Auth *                   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Ticket Status Matrix

| Ticket | Title | Status | Target Scope |
|---|---|---|---|
| **CLIENT-014-T01** | User Profile, Settings, Proxy/TLS Pin & Expiry Domain Models + `IGatewayClient` Contracts | **Completed (`6c3f5a6`)** | `UserProfile`, `UserSettings`, `ProxyConfig`, `TlsPinConfig`, `DisappearingTimerPreset`, `ProfileSyncStatus`, `ClientConfig` live-transport/proxy/pin flags, `IGatewayClient` profile & TLS inspection contracts + `DefaultGatewayClient` + 7 existing test doubles |
| **CLIENT-014-T02** | Encrypted `user_settings` & `user_profile` Persistence + Disappearing Message Schema | **Completed (`41bed45`)** | `user_settings` & `user_profile` tables in `SqlCipherLocalStore` & `MemoryLocalStore`; `Conversation::disappearing_ttl_seconds`, `Message::expires_at_ms`, `PRAGMA table_info` migration, `delete_expired_messages(now_ms)` |
| **CLIENT-014-T03** | Endpoint-Only BIP-39 Cryptographic Recovery Phrase Engine | **Completed (`0f1ea15`)** | `RecoveryPhraseEngine` + canonical 2048-word English BIP-39 list; 12/24-word generation, SHA-256 checksum validation, word confirmation challenge, PBKDF2-HMAC-SHA512 seed derivation (`0` network calls) |
| **CLIENT-014-T04** | Production `SettingsManager` (Profile Sync, Encrypted Avatar, Network Policy, Auto-Expiry & Panic-Wipe Wiring) | **Completed (`3243ba7`)** | `SettingsManager` in `ClientBootstrap`; E2EE avatar upload via `FileManager`; graceful Auth profile sync; proxy/TLS pin check + runtime reload hook; `MessagingManager::purge_expired_messages()`; `EmergencyManager` Phase-1 hook |
| **CLIENT-014-T05** | Production Live TLS 1.3 `QtHttpGatewayClient` Adapter (`QNetworkAccessManager`, SPKI Pinning & Proxy Routing) | **Completed (`5aa8897`)** | Thread-safe `QtHttpGatewayClient` over `Qt6::Network` mapped 1:1 to live Gateway REST/JSON routes, TLS 1.3 + SPKI pinning, `QNetworkProxy`, `ClientBootstrap` live toggle & loopback TLS unit suite |
| **CLIENT-014-T06** | `UiTheme` Dynamic Font Scaling & High-Contrast Mode + `SettingsPlaceholder.qml` Overhaul | **Completed (`df08dff`)** | Dynamic `fontScale` (`0.85x–1.40x`) & WCAG AAA `highContrastEnabled` in `UiTheme`; `UiTheme*` injected into `WorkspaceViewModel` via `main.cpp`; 7-card `SettingsPlaceholder.qml` preserving `CLIENT-007`/`010`/`013` hooks |
| **CLIENT-014-T07** | Settings, Profile & Live TLS Gateway E2E Integration Suite, Qt 6.8 `Basic` Style Fix, Tier 1/2 Smoke Tests & Walkthrough | **Completed (Pending commit)** | 6-scenario E2E suite (`settings_and_profile_integration_test.cpp`) incl. Scenario 6 (Live Loopback TLS 1.3 `QtHttpGatewayClient` + SPKI Pin + Hot Reload), Windows Qt 6.8 `QQuickStyle::setStyle("Basic")` + `:/qtquickcontrols2.conf`, Tier 1/2 smoke (`40 / 40` PNGs, `8` curated `CLIENT-014`), `walkthrough-client-014.md`, `docs/pull_requests/CLIENT-014.md` |

---

## 2. Verified Architecture, ADR & Codebase Audit

### 2.1 Already Implemented on Client & Backend (Reuse, Do NOT Re-Implement)

1. **`SettingsPlaceholder.qml` 5-Card Baseline (`src/client/ui/qml/SettingsPlaceholder.qml`, 843 lines):**
   - Already renders 5 styled `SCCard` sections:
     - Card 1: Local Workstation Cryptographic Identity & Signed Prekey Rotation (`rotateSignedPrekey()`)
     - Card 2: Linked Devices, Pairing Activation & Revocation (`approveDevice`, `revokeDevice`, `pairNewDevice`)
     - Card 3: Multi-Factor Authentication (MFA) & Hardware Token Policy (`mfaRequiredOnLogin`, `hardwareKeyEnforced`, `totpEnrollmentSecret`)
     - Card 4: Appearance, Read Receipts & Transport Security (Dark/Light/System buttons, `readReceiptsSwitch` `objectName`, static `"mTLS Active"` badge)
     - Card 5: Emergency Defense & Login Duress Policy (`duressPolicyCard`, `duressStatusBadge`, `duressPinField`, `duressPinConfirmField`, `saveDuressPinButton`, `clearDuressPinButton` added in `CLIENT-013`).
   - Also exposes `settingsScrollView.scrollToBottom()` used by `--capture-screenshots` in `src/client/main.cpp`.
   - `CLIENT-014` must **preserve every existing card, controller interaction, and `objectName` test hook** while integrating persisted Settings, User Profile, Dynamic Appearance, Live TLS/Proxy Controls, Disappearing Timers, and BIP-39 Recovery.
2. **Theme Palette Engine (`UiTheme`, `src/client/ui/ui_theme.{hpp,cpp}`):**
   - Already manages `ThemeMode::System`, `ThemeMode::Dark`, and `ThemeMode::Light` with `themeChanged()` / `themeModeChanged()` signals.
   - Note: `UiTheme` exposes `fontHeader` as an alias for `fontSubtitle`, and `accentSecondary` as an alias for `accentHover`; all `fontMicro`..`fontDisplay` properties are currently declared `CONSTANT` and must switch to `NOTIFY themeChanged`.
   - Note: `src/client/main.cpp` currently constructs `uiTheme` locally alongside `workspaceViewModel` and registers both on QML context, but does **not** inject `&uiTheme` into `workspaceViewModel` yet.
3. **Configuration Baseline (`ClientConfig`, `src/client/application/client_config.{hpp,cpp}`):**
   - Already defines `gateway_url` (`"https://127.0.0.1"`), `gateway_port` (`8443`), `tls_ca_cert_path`, timeouts (`connect_timeout_ms`, `request_timeout_ms`), `SecretString auth_token`, `validate()`, and redacted `to_safe_string()`.
4. **Privacy Read-Receipt Policy (`MessagingManager`, `CLIENT-010-T05`):**
   - Already persists `ReadReceiptPolicy` via `ISecureStorage` (`privacy.read_receipts_enabled`) and suppresses/purges offline queued receipts cleanly (`set_read_receipts_enabled(bool)`).
5. **Forensic Emergency Wipe & Secret Destruction (`EmergencyManager`, `CLIENT-013`):**
   - `EmergencyManager::run_destruction_phases()` runs Phase-1 volatile wipe across sibling managers (`file_manager_`, `ratchet_session_manager_`, `messaging_manager_`, `sync_manager_`, `auth_manager_`), Phase-2 `secure_storage_.purge_all_secrets()`, and Phase-3 `local_store_.destroy_and_shred()`.
   - Adding `set_settings_manager(SettingsManager*)` to `EmergencyManager` ensures in-memory settings/profile/BIP-39 caches are wiped cleanly in Phase 1 while Phase 2 purges `"network.proxy.password"` and `"recovery.phrase.verifier"` automatically.
6. **E2EE Avatar Transfer Baseline (`FileManager::start_upload`, `CLIENT-011`):**
   - `FileUploadRequest` already supports `bool dispatch_key_envelope{true};`. Passing `dispatch_key_envelope = false` uploads ciphertext chunks cleanly to Files (`/api/v1/files/upload/*`) and stores the content key in `ISecureStorage` without injecting a spurious chat message.
7. **Backend Gateway Live Proxy Handlers & Qt Networking:**
   - `Qt6::Network` is **already linked `PUBLIC`** on `securecloud_client_infra` (`src/client/CMakeLists.txt:75`).
   - Exact verified HTTP routes currently registered across `src/gateway/http/`:
     - **Health (`gateway_route_registrar.cpp`):** `GET /health/live`, `GET /health/ready` *(Note: `/health` is NOT registered by `GatewayRouteRegistrar`; use `/health/live` or `/health/ready`!)*.
     - **Auth (`AuthProxyHandler` + `GatewayRouteRegistrar`):** `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/revoke` (alias `POST /api/v1/auth/logout`), `GET /api/v1/users/me` (alias `GET /api/v1/auth/me`), `POST /api/v1/devices` (alias `POST /api/v1/auth/device/register`), `GET /api/v1/devices`, `GET /api/v1/devices/:device_id`, `GET /api/v1/users/:user_id/devices/crypto-directory`, `GET /api/v1/devices/:device_id/crypto-identity`, `POST /api/v1/devices/:device_id/prekeys`, `GET /api/v1/devices/:device_id/prekeys/inventory`, `POST /api/v1/devices/:device_id/prekeys/claim`, `POST /api/v1/devices/pairing` (`/api/v1/devices/pair`), `POST /api/v1/devices/:device_id/authorize`, `POST /api/v1/devices/:device_id/revoke` (`DELETE /api/v1/devices/:device_id`), and `/api/v1/auth/mfa/{enroll,confirm,verify,challenge,disable}`.
     - **Messaging (`MessagingProxyHandler`):** Canonical `POST /api/v1/messages` *(important: `gateway_route_registrar.cpp:175` registers a `501` stub on `/api/v1/messages/send` unconditionally, so `QtHttpGatewayClient` MUST submit to `POST /api/v1/messages`)*, `POST /api/v1/messages/:id/ack`, `POST /api/v1/conversations/:conversation_id/messages/:message_id/read`, `GET /api/v1/conversations/:conversation_id/messages/:message_id/delivery-status`, `POST /api/v1/conversations`, `GET /api/v1/conversations`, `GET /api/v1/conversations/:id`, `GET /api/v1/conversations/:conversation_id/messages`, `GET/PUT /api/v1/devices/:device_id/cursor`, presence routes.
     - **Files (`FilesProxyHandler`):** `POST /api/v1/files/upload/init`, `POST /api/v1/files/upload/chunk`, `POST /api/v1/files/upload/finalize`, `POST /api/v1/files/upload/cancel`, `GET /api/v1/files/:file_id/metadata`, `GET /api/v1/files/:file_id/chunks/:chunk_index`, `GET /api/v1/files/:file_id/download`, `DELETE /api/v1/files/:file_id`.

### 2.2 Net-New Scope & Gaps Closed by `CLIENT-014`

1. **No Durable Encrypted Settings or Profile Storage (`SqlCipherLocalStore`):**
   - Currently `WorkspaceViewModel::mfa_required_on_login_`, `hardware_key_enforced_`, and `UiTheme::theme_mode_` reset on every launch, and there is no `UserProfile` entity (`display_name`, `bio_status`, `public_handle`, `avatar_file_id`, `allow_handle_discovery`).
2. **Auth Service Profile Mutation Gap (`proto/securecloud/auth/v1/auth.proto`):**
   - `AuthService` exposes `GetUser` (`GET /api/v1/users/me` returning `user_id` and `credential_identifier`) and has **no** dedicated `UpdateUserProfile` RPC yet. `CLIENT-014` handles this cleanly via `ProfileSyncStatus` (`Synced`, `LocalOnlyServerUnsupported`, `SyncDisabledByPrivacyPolicy`) rather than hard-failing local profile saves against a live backend returning `404`/`405`/`501`.
3. **Fixed `CONSTANT` Font Tokens & Missing High-Contrast Palette in `UiTheme`:**
   - `UiTheme::fontMicro`..`fontDisplay` (and `fontHeader`) are `CONSTANT` integers (`10..28`) and cannot scale at runtime, nor is there a WCAG AAA high-contrast palette (`highContrastEnabled`).
4. **No User-Configurable Proxy or TLS Pin Inspection (`ClientConfig` & `IGatewayClient`):**
   - Users behind enterprise/field proxies need custom Gateway host/port overrides, HTTP/SOCKS5 proxy settings (with `ISecureStorage`-backed `SecretString` credentials), and visible TLS server SPKI SHA-256 fingerprint inspection/pinning.
5. **No Disappearing Message Timers (`Conversation`, `Message`, `MessagingManager`):**
   - Currently messages persist indefinitely until deleted or panic-wiped. `CLIENT-014` adds per-conversation & default disappearing TTLs (`Off`, `1h`, `24h`, `7d`) with deterministic `expires_at_ms` stamps and SQLCipher purge sweeps (`delete_expired_messages`).
6. **No Endpoint-Only BIP-39 Recovery Phrase Engine:**
   - There is no 2048-word mnemonic generation, checksum verification, confirmation challenge, or PBKDF2-HMAC-SHA512 recovery key derivation for offline disaster recovery.
7. **No Live HTTP/TLS Transport Adapter (`DefaultGatewayClient` Is Simulator-Only):**
   - `DefaultGatewayClient` is an in-memory simulator with zero `Qt6::Network` usage. Production desktop connectivity requires `QtHttpGatewayClient` speaking HTTPS TLS 1.3 + SPKI pinning + proxy routing against Gateway.
8. **Seven Existing `IGatewayClient` Mock Adapters in Unit/Integration Tests:**
   - Extending `IGatewayClient` requires updating `DefaultGatewayClient` plus all 7 existing test doubles under `tests/unit/client/` so the whole `securecloud_client_foundation_test` suite compiles with zero `-Werror` errors.

### 2.3 Confirmed Architectural Decisions & Design Rationale (Mandatory for Final Card Report)

> [!IMPORTANT]
> Per owner directive, the six design decisions below MUST be preserved and documented in a dedicated **"Architectural Decisions & Security Rationale"** section inside `docs/final-reports/walkthrough-client-014.md` (`CLIENT-014-T07`), **mandatorily** including the comparison between client BIP-39 recovery phrases and backend MFA recovery codes, `"network.proxy.password"`, `SPKI SHA-256` pinning, and live vs. simulated gateway transport switching.

1. **`domain::User` vs. `domain::UserProfile` vs. `domain::UserSettings` Ownership & Backend Separation:**
   - [`domain::User`](src/client/domain/user.hpp) (`CLIENT-001`) models the account/device aggregate (`user_id`, `devices`, `created_at`) used by domain foundation tests and remains untouched for backward compatibility.
   - `domain::UserProfile` is the single runtime source of truth for editable user identity (`display_name`, `public_handle`, `bio_status`, E2EE `avatar_file_id` + `avatar_sha256`, `allow_handle_discovery`), persisted in encrypted local SQLCipher (`user_profile`), hydrated on login from Auth's `GET /api/v1/users/me` (`auth.v1.User`), and backed for avatars exclusively as opaque ciphertext in the Files service (`/api/v1/files/upload/*`).
   - `domain::UserSettings` is strictly **endpoint-local** workstation policy (theme, font scale, high contrast, read receipts, disappearing message default, MFA/hardware toggles, proxy, TLS pin, live transport switch) and is never transmitted to any backend service (`ADR-008`).
2. **Mandatory Distinction — Client Cryptographic Recovery Phrases (BIP-39) vs. Backend MFA Recovery Codes (`AuthService`):**
   - **Backend MFA Recovery Codes** (`src/auth/crypto/recovery_code_generator.hpp`, `auth.proto` `ConfirmMfaEnrollmentResponse.recovery_codes`): Single-use, server-hashed (`SHA-256`) 2FA backup codes used solely to authenticate or disable TOTP MFA on the Auth server if the user loses their authenticator app.
   - **Client Cryptographic Recovery Phrase (BIP-39)** (`CLIENT-014`, `initial-backlog.md:795`, `ADR-008 §27, §28`): Endpoint-only 12/24-word mnemonic phrase (**12 words by default** for practical human backup accuracy, with an explicit **24-word option** in the Settings UI and `RecoveryPhraseEngine`) deriving a deterministic `PBKDF2-HMAC-SHA512` master recovery seed strictly on the user's workstation (**0 bytes ever transmitted to Auth or Gateway**) for offline E2EE cryptographic key/vault disaster recovery, because `ADR-008` strictly forbids server-side plaintext or key recovery.
   - Because MFA recovery codes only restore account login (not local E2EE keys), both mechanisms solve orthogonal problems; `SettingsPlaceholder.qml` (`CLIENT-014-T06`) must label this explicitly as **"Cryptographic Identity Recovery Phrase (Local / Offline)"** so it is never confused with Auth MFA Backup Codes.
3. **Dropping `has_password` from `ProxyConfig` / `UserSettings` & Role of `"network.proxy.password"`:**
   - `"network.proxy.password"` is **strictly the optional authentication password for an external HTTP or SOCKS5 proxy server** (e.g., corporate firewall or field-ops relay proxy) — **not** the SecureCloud account password and **not** the SQLCipher vault master key. It is stored only when an authenticated proxy is configured, consumed solely by `QtHttpGatewayClient` (`T05`) via `QNetworkProxy::setPassword(...)` during the proxy handshake before opening TLS 1.3 to Gateway (Gateway never sees it), and automatically zeroized during an `EmergencyManager` panic wipe.
   - `ProxyConfig` deliberately omits `bool has_password` so SQLCipher `user_settings` never duplicates credential-presence state owned by `ISecureStorage` (`"network.proxy.password"`), eliminating SQLCipher-vs-Keychain state drift. `SettingsManager::has_saved_proxy_password()` queries `ISecureStorage` live as the single source of truth.
4. **TLS SPKI SHA-256 Certificate Pinning & Disappearing Message Defaults:**
   - **What `SPKI SHA-256` Is:** `SPKI` = **Subject Public Key Info** (the server certificate's public key algorithm + DER-encoded raw public key bytes, excluding volatile metadata such as serial number, validity dates, and CA signature); `SPKI SHA-256` is the 64-character lowercase hexadecimal `SHA256(DER(SPKI))` digest of that public key.
   - **Why SPKI Pinning Beyond Standard HTTPS:** Standard HTTPS trusts ~150+ OS/system Certificate Authorities — if any CA is compromised or a corporate/network proxy installs a rogue root CA, standard TLS silently transmits `Authorization: Bearer` tokens to the imposter. Pinning SPKI SHA-256 enforces a second lock verified before transmitting any HTTP headers/body, while **surviving routine TLS certificate renewals** that reuse the server keypair (unlike full-certificate pinning) and blocking attacker keypairs in fail-closed fashion via `QtHttpGatewayClient` (`T05`) paired with live `inspect_tls_certificate`.
   - **Disappearing Message Default (`default_disappearing_timer`):** Workspace-level TTL default (`Off`, `1h`, `24h`, `7d`) inherited by conversations; messages are stamped `expires_at_ms = created_at_ms + ttl * 1000` in SQLCipher, hidden on reads once expired, and deleted by `delete_expired_messages(now_ms)` to bound forensic exposure on disk.
5. **Deferral of Backend `UpdateUserProfile` RPC:**
   - `CLIENT-014` is strictly client-scoped (`src/client/`) and does **not** expose an `UpdateUserProfile` RPC in `proto/securecloud/auth/v1/auth.proto`, Auth PostgreSQL migrations, or Gateway yet. `IGatewayClient::update_user_profile()` returns `ProfileSyncStatus` (`Synced`, `LocalOnlyServerUnsupported`, `SyncDisabledByPrivacyPolicy`) so local encrypted profile persistence succeeds gracefully when a live Gateway returns `404`/`405`/`501`, staying forward-compatible if a future backend card adds `UpdateUserProfile`.
6. **Live Runtime Transport Switching (`SwitchableGatewayClient`), Real TLS 1.3 Verification, & Ongoing Role of `DefaultGatewayClient`:**
   - **What `CLIENT-014-T05` Tests Prove vs. `CLIENT-015-T06` Full-Stack Docker Compose E2E:**
     - **Real client transport tested over real localhost sockets without Docker Compose:** In [`qt_http_gateway_client_test.cpp`](tests/unit/client/qt_http_gateway_client_test.cpp), an in-process TLS 1.3 test server (`LoopbackSslServer` via `QTcpServer` + `QSslSocket` on its own `QThread`) with OpenSSL-generated ephemeral Root CA and two distinct P-256 leaf certificates (`leaf_a`, `leaf_b`) exercises the production `QtHttpGatewayClient` over real `127.0.0.1` TCP/TLS 1.3 sockets. That **proves** client-side TLS 1.3 handshakes, CA chain validation, fail-closed `SPKI SHA-256` pinning before any `Authorization: Bearer` header or payload bytes leave the client, HTTP/SOCKS5 proxy routing, connect/request deadlines, multi-threaded thread-safety, and HTTP/JSON/binary wire formats contract-matched against Gateway's C++ proxy handlers (`AuthProxyHandler`, `MessagingProxyHandler`, `FilesProxyHandler`, `GatewayRouteRegistrar`).
     - **408 offline tests & `--smoke-test`:** Keep `use_live_gateway_transport = false` and talk solely to in-memory `DefaultGatewayClient` (opening zero sockets).
     - **Deferred to `CLIENT-015-T06`:** Live multi-container end-to-end communication with the actual 5 microservices + 4 datastores (`Gateway` -> gRPC mTLS -> `Auth`, `Messaging`, `Files`, `Audit` + PostgreSQL/ScyllaDB/ClickHouse/MinIO) is explicitly validated in `CLIENT-015-T06` once Docker Compose wiring is complete.
   - **Why `DefaultGatewayClient` Stays Alongside Production `QtHttpGatewayClient`:** The 408 offline client unit tests, `--smoke-test`, and `--capture-screenshots` execute standalone without Docker Compose running. `DefaultGatewayClient` remains strictly as the fast, deterministic offline simulator and fault-injection test double (analogous to `MemoryLocalStore` alongside `SqlCipherLocalStore`), while `QtHttpGatewayClient` serves production live TLS 1.3 traffic.
   - **Why `SwitchableGatewayClient` Enables Live Runtime Switching:** `ClientBootstrap` injects `IGatewayClient&` references into every manager (`AuthManager`, `MessagingManager`, `FileManager`, `SyncManager`, `SettingsManager`, etc.) at startup *before* `SettingsManager::load_settings()` reads persisted SQLCipher preferences (`UserSettings::use_live_gateway_transport`) and before a user toggles live mode, proxy, or TLS pins in Settings. Delegating via `SwitchableGatewayClient` lets the desktop client hot-switch between simulated mode and live TLS 1.3 immediately with zero app restart and without invalidating manager references.

---

## 3. Detailed Ticket Specifications (`CLIENT-014-T01` – `CLIENT-014-T07`)

### CLIENT-014-T01: User Profile, Settings, Proxy/TLS Pin & Expiry Domain Models + `IGatewayClient` Contracts

- **Component:** `src/client/domain/user_profile.{hpp,cpp}`, `src/client/domain/user_settings.{hpp,cpp}`, `src/client/application/client_config.{hpp,cpp}`, `src/client/application/interfaces/i_gateway_client.hpp`, `src/client/infrastructure/adapters/default_gateway_client.{hpp,cpp}`, `src/client/CMakeLists.txt`, 7 test doubles in `tests/unit/client/`, `tests/unit/client/user_settings_and_profile_domain_test.cpp`
- **Objective:** Model all user profile fields, persisted preferences, proxy & TLS pinning parameters, live transport toggles, and disappearing timer presets, and extend `IGatewayClient` for profile retrieval/sync and TLS fingerprint inspection.
- **Architectural Scope:**
  1. Create `src/client/domain/user_profile.{hpp,cpp}`:
     - `struct UserProfile`:
       - `UserId user_id`
       - `std::string public_handle` (validated slug: `[a-z0-9_.-]{3,64}` when non-empty)
       - `std::string display_name` (bounded `<= 128` bytes, control-char sanitized)
       - `std::string bio_status` (bounded `<= 512` bytes)
       - `std::string avatar_file_id` (reference to E2EE-encrypted avatar blob in Files service — never unencrypted URL)
       - `std::string avatar_sha256` (optional 64-char hex digest)
       - `bool allow_handle_discovery{true}` (explicit opt-in gate prior to remote sync)
       - `int64_t updated_at_ms{0}`
       - `validate()` & lossless `to_json()` / `from_json()` (excluding any private secrets).
  2. Create `src/client/domain/user_settings.{hpp,cpp}`:
     - `enum class ProxyType { None = 0, Http = 1, Socks5 = 2 };`
     - `enum class DisappearingTimerPreset : int64_t { Off = 0, OneHour = 3600, TwentyFourHours = 86400, SevenDays = 604800 };`
     - `struct ProxyConfig`: `ProxyType type{ProxyType::None}`, `std::string host`, `uint16_t port{0}`, `std::string username` (deliberately no `has_password` boolean in SQLCipher settings to avoid state drift with `ISecureStorage`; password presence is queried live via `SettingsManager::has_saved_proxy_password()` against key `"network.proxy.password"`, **never** in settings JSON!). Validates `host` + `1..65535` port when `type != None`.
     - `struct TlsPinConfig`: `std::string custom_gateway_host`, `uint16_t custom_gateway_port{8443}`, `std::string pinned_spki_sha256_hex`, `bool enforce_strict_pinning{true}` (validates empty or 64-char hex digest, normalized lowercase).
     - `struct UserSettings`:
       - Appearance & Accessibility: `int theme_mode{1}` (`0=System, 1=Dark, 2=Light`), `double font_scale{1.0}` (clamped/validated `[0.85, 1.40]`), `bool high_contrast_enabled{false}`
       - Security & Privacy: `bool read_receipts_enabled{true}`, `DisappearingTimerPreset default_disappearing_timer{DisappearingTimerPreset::Off}`, `bool mfa_required_on_login{true}`, `bool hardware_key_enforced{true}`, `bool recovery_phrase_verified{false}`
       - Network & TLS: `bool use_live_gateway_transport{false}`, `ProxyConfig proxy`, `TlsPinConfig tls`
       - `uint32_t schema_version{1}`, `int64_t updated_at_ms{0}`, `validate()`, `to_json()`, `from_json()`.
  3. Extend `ClientConfig` (`client_config.{hpp,cpp}`):
     - Add `bool use_live_gateway_transport{false}` (`SECURECLOUD_USE_LIVE_GATEWAY`), `domain::ProxyType proxy_type{domain::ProxyType::None}` (`SECURECLOUD_PROXY_TYPE`), `std::string proxy_host` (`SECURECLOUD_PROXY_HOST`), `uint16_t proxy_port{0}` (`SECURECLOUD_PROXY_PORT`), `std::string proxy_username` (`SECURECLOUD_PROXY_USER`), `securecloud::common::configuration::SecretString proxy_password` (`SECURECLOUD_PROXY_PASS`), `std::string pinned_tls_spki_sha256` (`SECURECLOUD_TLS_PIN_SPKI_SHA256`), `bool enforce_tls_pinning{true}`.
     - Validate proxy host/port when `proxy_type != None` and SPKI SHA-256 hex length when non-empty; print `[REDACTED]` for `proxy_password` in `to_safe_string()`.
  4. Extend `IGatewayClient` & `DefaultGatewayClient` (+ update the 7 existing test doubles in `client_domain_test.cpp`, `file_manager_pipeline_test.cpp`, `workspace_view_model_files_test.cpp`, `encrypted_file_transfer_integration_test.cpp`, `emergency_wipe_pipeline_test.cpp`, `duress_pin_and_decoy_test.cpp`, `emergency_panic_wipe_integration_test.cpp`):
     - `enum class ProfileSyncStatus { Synced, LocalOnlyServerUnsupported, SyncDisabledByPrivacyPolicy };`
     - `struct UserProfileSyncResult { domain::UserProfile profile; ProfileSyncStatus sync_status{ProfileSyncStatus::Synced}; };`
     - `struct TlsCertificateInfo { std::string host; uint16_t port{8443}; std::string subject_cn; std::string issuer_cn; std::string spki_sha256_hex; int64_t valid_from_ms{0}; int64_t valid_until_ms{0}; bool matches_pinned_key{true}; bool has_pinned_key{false}; };`
     - Add virtual methods on `IGatewayClient`:
       - `virtual ClientResult<domain::UserProfile> get_user_profile(const domain::UserId& user_id) = 0;`
       - `virtual ClientResult<UserProfileSyncResult> update_user_profile(const domain::UserProfile& public_profile) = 0;`
       - `virtual ClientResult<TlsCertificateInfo> inspect_tls_certificate(std::string_view host, uint16_t port) = 0;`
     - Implement deterministic simulation & pin/cert override helpers in `DefaultGatewayClient`.
- **Acceptance Criteria:**
  - Out-of-bounds `font_scale`, invalid proxy ports/hosts, invalid SHA-256 pins, and oversized handles fail validation cleanly.
  - `UserProfile` & `UserSettings` JSON serialization is lossless and never contains proxy passwords, BIP-39 words, or recovery keys.
  - All existing `382` tests compile cleanly with zero `-Werror` warnings.

---

### CLIENT-014-T02: Encrypted `user_settings` & `user_profile` Persistence + Disappearing Message Schema

- **Component:** `src/client/domain/conversation.{hpp,cpp}`, `src/client/domain/message.{hpp,cpp}`, `src/client/application/interfaces/i_local_store.hpp`, `src/client/infrastructure/adapters/sqlcipher_local_store.{hpp,cpp}`, `src/client/infrastructure/adapters/memory_local_store.{hpp,cpp}`, `tests/unit/client/settings_and_expiry_persistence_test.cpp`
- **Objective:** Persist encrypted user profiles and settings in `SqlCipherLocalStore` and add disappearing message TTL columns, indexes, read filtering, and expiration sweeps.
- **Architectural Scope:**
  1. Extend domain models:
     - `Conversation`: add `int64_t disappearing_ttl_seconds{0}` (`0` = disabled) serialized in `to_json()` / `from_json()` cleanly alongside existing optional fields.
     - `Message`: add `int64_t expires_at_ms{0}` (`0` = does not expire; helper `[[nodiscard]] bool is_expired(int64_t now_ms) const noexcept`) serialized in `to_json()` / `from_json()`.
  2. Extend `SqlCipherLocalStore::initialize_schema_locked()`:
     ```sql
     CREATE TABLE IF NOT EXISTS user_profile (
         user_id TEXT PRIMARY KEY,
         updated_at_ms INTEGER NOT NULL,
         payload_json TEXT NOT NULL
     );

     CREATE TABLE IF NOT EXISTS user_settings (
         profile_key TEXT PRIMARY KEY,
         updated_at_ms INTEGER NOT NULL,
         payload_json TEXT NOT NULL
     );
     ```
     - Execute idempotent `PRAGMA table_info(messages);` check; if column `expires_at_ms` is absent (for existing `CLIENT-009`–`CLIENT-013` vaults upgraded on disk), execute:
       ```sql
       ALTER TABLE messages ADD COLUMN expires_at_ms INTEGER NOT NULL DEFAULT 0;
       ```
     - Create partial expiration index unconditionally afterwards:
       ```sql
       CREATE INDEX IF NOT EXISTS idx_messages_expires_at
           ON messages(expires_at_ms) WHERE expires_at_ms > 0;
       ```
  3. Extend `ILocalStore`, `SqlCipherLocalStore`, and `MemoryLocalStore`:
     - `save_user_profile(const domain::UserProfile& profile)`
     - `get_user_profile(const domain::UserId& user_id)` (returns `NotFound` / `std::nullopt` cleanly)
     - `save_user_settings(std::string_view profile_key, const domain::UserSettings& settings)`
     - `get_user_settings(std::string_view profile_key)`
     - `delete_expired_messages(int64_t now_ms)` returning `ClientResult<std::size_t>` (`sqlite3_changes(db_)` after `DELETE FROM messages WHERE expires_at_ms > 0 AND expires_at_ms <= ?;`).
     - Update `save_message` / `update_message` / `get_messages` / `get_message` to persist `expires_at_ms` and enforce defense-in-depth read exclusion for already-expired rows before periodic cleanup runs.
- **Acceptance Criteria:**
  - Opening a pre-existing encrypted SQLCipher DB without `expires_at_ms` migrates cleanly without losing existing messages/conversations.
  - Profile, settings, conversation TTLs, and message `expires_at_ms` survive full `close()` -> `open()` cycles.
  - Raw `.db` binary scan confirms zero plaintext leakage of profile display names, bios, handles, proxy hosts, or expiring message metadata.

---

### CLIENT-014-T03: Endpoint-Only BIP-39 Cryptographic Recovery Phrase Engine

- **Component:** `src/client/domain/crypto/bip39_wordlist.hpp`, `src/client/domain/crypto/recovery_phrase_engine.{hpp,cpp}`, `src/client/CMakeLists.txt`, `tests/unit/client/recovery_phrase_engine_test.cpp`
- **Objective:** Implement a specification-compliant, strictly endpoint-only BIP-39 mnemonic generator, validator, word-confirmation verifier, and deterministic recovery key deriver using OpenSSL 3.x EVP.
- **Architectural Scope:**
  1. Create `src/client/domain/crypto/bip39_wordlist.hpp`:
     - Canonical immutable `constexpr std::array<std::string_view, 2048> kBip39EnglishWords` in lexicographical order matching BIP-39 (`"abandon"` .. `"zoo"`) + O(log N) binary lookup helper `find_bip39_word_index(std::string_view word)`.
  2. Create `src/client/domain/crypto/recovery_phrase_engine.{hpp,cpp}`:
     - `enum class RecoveryPhraseLength { Words12 = 128, Words24 = 256 };`
     - `struct RecoveryVerificationChallenge { std::vector<std::size_t> word_indices; };`
     - `static ClientResult<SecretString> generate_mnemonic(RecoveryPhraseLength length = RecoveryPhraseLength::Words12)`:
       - Generates `16` or `32` random bytes via `RAND_bytes` (defaulting to 12 words / 128-bit entropy, with 24 words / 256-bit fully supported), appends `4`-bit or `8`-bit `SHA-256` checksum bits, encodes 11-bit indices into space-separated words inside `SecretString`, and cleanses entropy/index buffers via `OPENSSL_cleanse`.
     - `static ClientResult<SecretString> entropy_to_mnemonic(std::span<const uint8_t> entropy)` (deterministic internal/test-vector entry point supporting `16` and `32` byte official vectors).
     - `static ClientResult<bool> validate_mnemonic(const SecretString& mnemonic)`:
       - Normalizes whitespace cleanly, verifies `12` or `24` word count, wordlist membership, and exact `SHA-256` checksum match (`false` or error on swapped/tampered/unknown words).
     - `static ClientResult<std::vector<uint8_t>> derive_recovery_seed(const SecretString& mnemonic, const SecretString& passphrase = SecretString(""))`:
       - Validates checksum first, then executes `PKCS5_PBKDF2_HMAC` with `EVP_sha512()`, `2048` iterations, salt `"mnemonic" + passphrase` (`NFKD` ASCII baseline / UTF-8 pass-through), producing a `64`-byte master recovery seed cleanly.
     - `static ClientResult<std::string> compute_salted_verification_digest(const SecretString& mnemonic)` and `verify_against_digest(const SecretString& mnemonic, std::string_view stored_digest)`:
       - Stores a `16`-byte random salt + PBKDF2/HMAC-SHA256 verification digest inside `ISecureStorage` (`"recovery.phrase.verifier"`) using `CRYPTO_memcmp`, allowing local backup re-verification **without** keeping the raw 24-word mnemonic persisted in SQLite!
     - `static RecoveryVerificationChallenge build_challenge(std::size_t word_count, std::size_t sample_count = 3)` & `static ClientResult<bool> verify_challenge_words(...)`.
- **Acceptance Criteria:**
  - Published official BIP-39 12-word & 24-word test vectors (entropy -> mnemonic -> `PBKDF2-HMAC-SHA512` 64-byte seed) match **byte-for-byte**.
  - Tampered checksums, non-wordlist words, or wrong challenge answers fail closed (`CRYPTO_memcmp` / `validate_mnemonic`), intermediate stack buffers are zeroized with `OPENSSL_cleanse`, and **0** network calls occur.

---

### CLIENT-014-T04: Production `SettingsManager` (Profile Sync, Encrypted Avatar, Network Policy, Auto-Expiry & Panic-Wipe Wiring)

- **Component:** `src/client/application/managers/settings_manager.{hpp,cpp}`, `src/client/application/managers/messaging_manager.{hpp,cpp}`, `src/client/application/managers/emergency_manager.{hpp,cpp}`, `src/client/application/client_bootstrap.{hpp,cpp}`, `src/client/CMakeLists.txt`, `tests/unit/client/settings_manager_pipeline_test.cpp`
- **Objective:** Coordinate encrypted settings/profile management, E2EE avatar uploads, live proxy/TLS configuration reload, disappearing message expiry enforcement, endpoint-only BIP-39 lifecycle, and `EmergencyManager` panic-wipe clearing.
- **Architectural Scope:**
  1. Create `src/client/application/managers/settings_manager.{hpp,cpp}`:
     - Inject `ILocalStore&`, `ISecureStorage&`, `IGatewayClient&`, `ClientConfig&`, optional `FileManager*`, optional `MessagingManager*`, and `NetworkConfigReloadCallback` (`std::function<void(const ClientConfig&)>`).
     - **Settings & Secrets Lifecycle:**
       - `load_settings()` / `save_settings(domain::UserSettings settings, std::optional<SecretString> proxy_password = std::nullopt)`:
         - Validates settings, saves non-secret JSON via `ILocalStore::save_user_settings("active", ...)`, stores/deletes optional proxy password solely inside `ISecureStorage` (`"network.proxy.password"`), propagates `read_receipts_enabled` into `MessagingManager::set_read_receipts_enabled`, applies gateway host/port, proxy, SPKI pin, and `use_live_gateway_transport` into `ClientConfig`, and invokes `NetworkConfigReloadCallback` when live transport is active!
       - `has_saved_proxy_password()` / `load_proxy_password()` helper reading `"network.proxy.password"` from `ISecureStorage`.
     - **Profile & E2EE Avatar Workflow (`ADR-008 §7, §20`):**
       - `load_profile(const domain::UserId& user_id)` (merges local SQLCipher profile with non-fatal `GET /api/v1/users/me` handle hydration when reachable).
       - `update_profile(domain::UserProfile profile, bool sync_public_fields_to_gateway)`:
         - Always persists locally in `ILocalStore`; pushes permitted public fields only when `sync_public_fields_to_gateway && profile.allow_handle_discovery` (`ProfileSyncStatus::LocalOnlyServerUnsupported` returned gracefully if server lacks `UpdateUserProfile` RPC yet).
       - `upload_encrypted_avatar(const domain::UserId& user_id, const domain::DeviceId& device_id, std::string_view local_image_path)`:
         - Validates extension (`.png`, `.jpg`, `.jpeg`, `.webp`) and size (`1 .. 5 MiB`), delegates encryption + chunked upload to `FileManager::start_upload(FileUploadRequest{.owner_user_id = user_id, .owner_device_id = device_id, .local_file_path = ..., .mime_type = ..., .dispatch_key_envelope = false})`, and updates local `UserProfile::avatar_file_id` + `avatar_sha256` (retaining file key inside `ISecureStorage`).
     - **Network & TLS Fingerprint Inspection:**
       - `inspect_and_optionally_pin_gateway_tls(std::string_view host, uint16_t port, bool save_pin)`.
     - **Endpoint-Only BIP-39 Recovery Lifecycle (`ADR-008 §27, §28`):**
       - `generate_recovery_phrase(RecoveryPhraseLength length = RecoveryPhraseLength::Words12)` (defaults to 12 words while supporting optional 24 words; never logged, never sent to `IGatewayClient`).
       - `confirm_recovery_phrase_backup(const SecretString& mnemonic, const std::vector<std::pair<std::size_t, std::string>>& challenge_answers)`: validates answers + stores salted verifier digest under `"recovery.phrase.verifier"` + updates `UserSettings::recovery_phrase_verified = true`.
       - `verify_existing_recovery_phrase(const SecretString& candidate)` against `"recovery.phrase.verifier"`.
     - **Panic Wipe Cleanup (`CLIENT-013` Integration):**
       - `void wipe_volatile_state() noexcept;` clearing cached active settings, profile, and any temporary mnemonic state; wired into `EmergencyManager::set_settings_manager(...)` in `ClientBootstrap::wire_managers()`.
  2. **Disappearing Message Enforcement (`MessagingManager`):**
     - Add `MessagingManager::set_default_disappearing_ttl_seconds(int64_t ttl_seconds)` (clamped valid presets/non-negative), `set_conversation_disappearing_timer(const domain::ConversationId& cid, int64_t ttl_seconds)`, and `std::size_t purge_expired_messages(int64_t now_ms = current_unix_ms())` calling `local_store_.delete_expired_messages(now_ms)`.
     - In `stage_outbound_message` and `persist_inbound_message`, look up conversation `disappearing_ttl_seconds` (or global default if `conversation.disappearing_ttl_seconds() > 0` or configured policy) and stamp `msg.set_expires_at_ms(sent_ms + ttl_sec * 1000)` cleanly.
  3. Wire `SettingsManager` inside `ClientBootstrap` (`ClientBootstrap::settings_manager()` + `ClientBootstrap::wire_managers()`).
- **Acceptance Criteria:**
  - Disappearing messages stamped under `1h` / `24h` / `7d` policies expire deterministically once `now_ms >= expires_at_ms` and are deleted from SQLCipher via `purge_expired_messages()`.
  - Avatar upload transfers encrypted chunks without leaking plaintext image bytes or private keys.
  - BIP-39 generation/confirmation/verification performs **0** `IGatewayClient` calls.
  - Emergency panic wipe clears `SettingsManager` volatile caches alongside `"network.proxy.password"` and `"recovery.phrase.verifier"`.

---

### CLIENT-014-T05: Production Live TLS 1.3 `QtHttpGatewayClient` Adapter (`QNetworkAccessManager`, SPKI Pinning & Proxy Routing)

- **Component:** `src/client/infrastructure/adapters/qt_http_gateway_client.{hpp,cpp}`, `src/client/application/client_bootstrap.{hpp,cpp}`, `src/client/CMakeLists.txt`, `tests/unit/client/qt_http_gateway_client_test.cpp`
- **Objective:** Implement the production live network transport adapter (`QtHttpGatewayClient`) on `IGatewayClient` using `Qt6::Network`, speaking real HTTPS TLS 1.3 + SPKI SHA-256 certificate pinning + HTTP/SOCKS5 proxy routing to Gateway REST handlers.
- **Architectural Scope:**
  1. Create `src/client/infrastructure/adapters/qt_http_gateway_client.{hpp,cpp}`:
     - **Qt Thread-Affinity Safety (Critical Requirement):** Because `SyncManager` and `FileManager` may call `IGatewayClient` from background worker threads while `QNetworkAccessManager` cannot safely share a single instance across threads without marshaling, execute HTTP operations using either a dedicated internal worker thread (`QThread` + event loop owning `QNetworkAccessManager`) or per-request thread-local/stack `QNetworkAccessManager` + local `QEventLoop` guarded cleanly by mutex-protected configuration snapshots and `QCoreApplication::instance()` lifecycle safety.
     - **TLS 1.3 & SPKI SHA-256 Pinning Security Layer (`ADR-008 §30, §35`):**
       - Configure `QSslConfiguration` with `setProtocol(QSsl::TlsV1_3OrLater)`, optional custom CA certificate parsed from `ClientConfig::tls_ca_cert_path` (supporting self-signed/dev-PKI CAs explicitly via `QSslConfiguration::setCaCertificates(...)` when CA path is set, never globally disabling peer verification unless test-explicit, and always enforcing SPKI pin check before sending HTTP payloads).
       - Intercept `QSslSocket::encrypted` / `QNetworkReply::encrypted` (via pre-connected/monitored TLS socket or reply SSL verification) to compute SHA-256 hex digest of leaf `peerCertificate().publicKey().toDer()`. **Fail closed immediately** (`reply->abort()`, `ClientError::network` / TLS pin mismatch) if `pinned_tls_spki_sha256` is configured and does not match (`CRYPTO_memcmp` / constant-case-normalized comparison).
       - Implement `inspect_tls_certificate(std::string_view host, uint16_t port)` via `QSslSocket::connectToHostEncrypted` returning Subject CN, Issuer CN, UTC validity epoch ms, SPKI SHA-256 hex digest, `has_pinned_key`, and `matches_pinned_key`.
     - **Proxy, Timeout & Bounded Read Discipline (`ADR-009`, `ADR-010`):**
       - Apply `QNetworkProxy` (`NoProxy`, `HttpProxy`, `Socks5Proxy`) using `ClientConfig` proxy fields + runtime `ISecureStorage`-backed proxy password (`"network.proxy.password"`); never pass credentials to `ClientLogger`.
       - Enforce bounded `connect_timeout_ms` / `request_timeout_ms` (`QNetworkRequest::setTransferTimeout` / `QTimer::singleShot`) and bounded response read cap (reject oversized responses safely).
       - Expose `reconfigure(const ClientConfig& config)` invoked live by `SettingsManager`'s reload callback without restarting the client.
       - Implement non-blocking adaptive delta polling (`subscribe_realtime_events` / `unsubscribe_realtime_events`) dispatching incoming messages cleanly when live transport is enabled.
     - **1:1 Verified Gateway Wire REST/JSON Contract Mapping:**
       - Health & Auth: `GET /health/live` (and fallback `/health/ready`), `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/revoke`
       - Profile & Devices (`AuthProxyHandler`): `GET /api/v1/users/me` (`user` JSON -> `UserProfile`), `PUT /api/v1/users/me` (maps HTTP `404`/`405`/`501` gracefully to `ProfileSyncStatus::LocalOnlyServerUnsupported`), `POST /api/v1/devices`, `GET /api/v1/devices`, `POST /api/v1/devices/pairing`, `POST /api/v1/devices/:device_id/authorize`, `POST /api/v1/devices/:device_id/revoke`, `GET /api/v1/users/:user_id/devices/crypto-directory`, `POST /api/v1/devices/:device_id/prekeys`, `GET /api/v1/devices/:device_id/prekeys/inventory`
       - Messaging & Sync (`MessagingProxyHandler`): `POST /api/v1/messages` *(canonical live route avoiding the `/api/v1/messages/send` stub)*, `GET /api/v1/conversations`, `POST /api/v1/conversations`, `GET /api/v1/conversations/:id/messages`, `GET/PUT /api/v1/devices/:device_id/cursor`, `POST /api/v1/messages/:id/ack`, `POST /api/v1/conversations/:conversation_id/messages/:message_id/read`, `GET /api/v1/conversations/:conversation_id/messages/:message_id/delivery-status`
       - Files (`FilesProxyHandler`): `POST /api/v1/files/upload/init`, `POST /api/v1/files/upload/chunk`, `POST /api/v1/files/upload/finalize`, `POST /api/v1/files/upload/cancel`, `GET /api/v1/files/:file_id/metadata`, `GET /api/v1/files/:file_id/chunks/:chunk_index`, `DELETE /api/v1/files/:file_id`
       - Attach `Authorization: Bearer <token>` and unique `X-Request-ID` headers; map HTTP `400/401/403/404/409/5xx` & SSL/network errors cleanly into typed `ClientError`.
  2. Wire `ClientBootstrap`:
     - When `config_.use_live_gateway_transport == true`, instantiate `QtHttpGatewayClient`; otherwise retain `DefaultGatewayClient` for deterministic offline unit tests and default local simulation.
     - Note runtime switching (`set_live_transport_enabled`): either delegate via a thin switchable `IGatewayClient` proxy wrapper in `ClientBootstrap` or reconfigure `QtHttpGatewayClient` cleanly so Settings toggles work without restarting. *(Using a lightweight `SwitchableGatewayClient` delegating between `DefaultGatewayClient` and `QtHttpGatewayClient` lets `ClientBootstrap` toggle simulator ↔ live TLS 1.3 seamlessly at runtime without invalidating existing manager references!)*
  3. Create `tests/unit/client/qt_http_gateway_client_test.cpp`:
     - Build an in-process `LoopbackSslServer` using `QTcpServer` + `QSslSocket::startServerEncryption()` (standard across Qt 6.4+ without requiring `QSslServer` version checks) and ephemeral certs generated via OpenSSL 3.6-safe `X509_NAME_new()` + `X509_set_subject_name(...)`:
       - Verify TLS 1.3 handshake + `GET /health/live` + authenticated JSON REST calls (`submit_encrypted_message` -> `POST /api/v1/messages`, `fetch_conversation_messages`, `upload_file_chunk`, `get_user_profile`, `update_user_profile` 404/501 graceful fallback, `inspect_tls_certificate`).
       - Verify matching SPKI SHA-256 pin succeeds and rotated/mismatched pin **fails closed** before Bearer token transmission.
       - Verify `request_timeout_ms` deadline cancellation returns `ClientErrorCategory::Network` and HTTP/SOCKS5 proxy configuration wires into `QNetworkProxy` cleanly.
- **Acceptance Criteria:**
  - All loopback TLS 1.3, SPKI pinning, proxy config, timeout, HTTP error mapping, thread-safety, and JSON wire tests pass cleanly with zero `-Werror` warnings.
  - All existing simulated tests on `DefaultGatewayClient` remain fast and green.

---

### CLIENT-014-T06: `UiTheme` Dynamic Font Scaling & High-Contrast Mode + `SettingsPlaceholder.qml` Overhaul

- **Component:** `src/client/ui/ui_theme.{hpp,cpp}`, `src/client/ui/workspace_view_model.{hpp,cpp}`, `src/client/ui/qml/SettingsPlaceholder.qml`, `src/client/main.cpp`, `tests/unit/client/workspace_view_model_settings_test.cpp`
- **Objective:** Add dynamic runtime accessibility font scaling (`0.85x–1.40x`) and WCAG AAA High-Contrast palettes to `UiTheme`, inject `UiTheme*` into `WorkspaceViewModel`, persist theme/security/profile/network preferences via `SettingsManager`, and upgrade `SettingsPlaceholder.qml` into the complete 7-card settings center.
- **Architectural Scope:**
  1. **Extend `UiTheme` (`src/client/ui/ui_theme.{hpp,cpp}`):**
     - Add `Q_PROPERTY(double fontScale READ fontScale WRITE setFontScale NOTIFY themeChanged)` (clamped `[0.85, 1.40]`, default `1.0`) and `Q_PROPERTY(bool highContrastEnabled READ highContrastEnabled WRITE setHighContrastEnabled NOTIFY themeChanged)`.
     - Change `fontMicro`, `fontCaption`, `fontBody`, `fontSubtitle`, `fontHeader`, `fontTitle`, `fontHeadline`, and `fontDisplay` from `CONSTANT` to `NOTIFY themeChanged`, scaling via `std::max(8, static_cast<int>(std::lround(base * font_scale_)))`.
     - Add `highContrastDarkPalette()` (`#000000` background, `#FFFFFF` text, high-luminance borders/accents `>= 7:1` WCAG AAA contrast) and `highContrastLightPalette()` (`#FFFFFF` background, `#000000` text, deep contrast accents `>= 7:1`), selected whenever `high_contrast_enabled_` is true.
  2. **Extend `WorkspaceViewModel` & `src/client/main.cpp`:**
     - Add `void setUiTheme(UiTheme* theme) noexcept;` and call `workspaceViewModel.setUiTheme(&uiTheme)` in `src/client/main.cpp` right after constructing both objects (hydrating `UiTheme` immediately from persisted `UserSettings`!).
     - Persist `mfaRequiredOnLogin`, `hardwareKeyEnforced`, `readReceiptsEnabled`, `themeMode`, `fontScale`, `highContrastEnabled` via `SettingsManager` so preferences survive full restarts (replacing volatile-only fields).
     - Expose typed QML properties & signals:
       - Profile: `profileDisplayName`, `profileHandle`, `profileBio`, `profileAvatarFileId`, `profileAllowDiscovery`, `profileSyncStatusText` (`NOTIFY profileSettingsChanged`)
       - Accessibility: `fontScale`, `highContrastEnabled`, `themeMode` (`NOTIFY appearanceSettingsChanged`)
       - Network/TLS: `useLiveGatewayTransport`, `gatewayHost`, `gatewayPort`, `proxyType`, `proxyHost`, `proxyPort`, `proxyUsername`, `hasProxyPassword` (queried live from `SettingsManager::has_saved_proxy_password()` against `ISecureStorage`, never stored in `UserSettings`), `tlsPinnedFingerprint`, `tlsEnforceStrictPinning`, `tlsLastInspectedInfo`, `tlsPinMatches` (`NOTIFY networkSettingsChanged`)
       - Privacy/Security: `defaultDisappearingTtlSeconds`, `activeConversationDisappearingTtlSeconds`, `recoveryPhraseVerified`, `recoveryPhraseStatusText` (`NOTIFY privacySecuritySettingsChanged`)
     - Expose `Q_INVOKABLE` slots: `saveUserProfile(...)`, `uploadAvatarImage(fileUrl)`, `applyAndSaveAppearance(themeMode, fontScale, highContrast)`, `saveNetworkAndProxyConfig(...)`, `inspectGatewayTlsFingerprint()`, `setDefaultDisappearingTimer(ttlSec)`, `setConversationDisappearingTimer(cid, ttlSec)`, `generateRecoveryPhraseWords(use24Words = false)`, `confirmRecoveryPhraseChallenge(wordIndices, userWords)`, `verifyRecoveryPhraseInput(words)`.
     - Update `resetForEmergencyWipe()` / `enterDecoyWorkspace()` to clear cached profile/BIP-39/network fields cleanly.
  3. **Upgrade `SettingsPlaceholder.qml` (7 Cards Preserving All Existing Cards & `objectName` Hooks):**
     - Preserve existing Cards 1–3 (`Local Identity`, `Linked Devices`, `MFA & Hardware Policy`) + Card 4 `readReceiptsSwitch` + Card 5 `duressPolicyCard` (`duressPinField`, `duressPinConfirmField`, `saveDuressPinButton`, `clearDuressPinButton`, `duressStatusBadge`) intact, and integrate cleanly into 7 structured `SCCard` sections:
       - Card 1: **User Profile & Encrypted Avatar** (`objectName` hooks for display name, handle, bio, avatar picker, discovery toggle, save & sync status).
       - Card 2: **Local Workstation Cryptographic Identity** (`CLIENT-007` preserved).
       - Card 3: **Linked Devices, Pairing & Revocation** (`CLIENT-007` preserved).
       - Card 4: **Security, Privacy, MFA, Disappearing Timers & Duress Policy** (persisted MFA/hardware toggles, `readReceiptsSwitch`, `Off`/`1h`/`24h`/`7d` default & active conversation disappearing timer buttons, and preserved `duressPolicyCard`).
       - Card 5: **Appearance & Accessibility** (Dark/Light/System buttons, Font Scale presets `85%` / `100%` / `120%` / `140%`, WCAG AAA High-Contrast Mode `Switch` — instant zero-restart updates).
       - Card 6: **Network, Live TLS 1.3 Gateway, Proxy & Certificate Pinning** (Live TLS 1.3 vs Simulator switch, custom Gateway host/port, Proxy Type `None`/`HTTP`/`SOCKS5` + host/port/username/password, TLS Fingerprint Inspect button & SPKI SHA-256 pin field + Verified/Mismatch badge).
       - Card 7: **Endpoint-Only Cryptographic Recovery Phrase (BIP-39)** (12-word default generator modal with optional 24-word selector, show/hide toggle, 3-word confirmation spot-check, Verified backup badge, explicit `"Never transmitted to servers"` banner).
- **Acceptance Criteria:**
  - Switching Dark/Light/High-Contrast or `fontScale` (`0.85–1.40`) updates `UiTheme` and QML text/palette bindings instantaneously with `0` QML console warnings or binding loops.
  - All existing `CLIENT-007` / `CLIENT-010` / `CLIENT-013` QML & ViewModel tests continue passing untouched.

---

### CLIENT-014-T07: Settings, Profile & Live TLS Gateway E2E Integration Suite, Tier 1/2 Smoke Tests & Walkthrough

- **Component:** `tests/unit/client/settings_and_profile_integration_test.cpp`, `tests/unit/CMakeLists.txt`, `src/client/main.cpp`, `docs/final-reports/walkthrough-client-014.md`, `docs/pull_requests/CLIENT-014.md`
- **Objective:** Validate every settings, encrypted profile, E2EE avatar, disappearing message, runtime accessibility, proxy/TLS, live TLS 1.3 Gateway transport, and BIP-39 recovery workflow end-to-end across SQLCipher restarts and headless QML views.
- **Architectural Scope:**
  1. Create `tests/unit/client/settings_and_profile_integration_test.cpp` with **6 E2E Scenarios**:
     - **Scenario 1 — Encrypted Settings, MFA/Proxy Policy & Profile Persistence Across SQLCipher Restart:**
       - Configure profile display name, bio, handle, HTTP proxy with `SecretString` password, TLS SPKI pin, High-Contrast/`1.25x` font scale, and MFA toggle; close and reopen `SqlCipherLocalStore` + recreate `SettingsManager` + `WorkspaceViewModel` + `UiTheme`; verify exact hydration and run raw `.db` binary scan confirming zero plaintext settings/profile/proxy-password leakage.
     - **Scenario 2 — E2EE Avatar Encryption/Upload & Graceful Profile Sync (`ADR-008 §7, §20`):**
       - Upload local `.png` avatar via `SettingsManager::upload_encrypted_avatar`, confirm Gateway receives strictly encrypted chunks (`SHA-256` verified) without plaintext image bytes, verify Auth directory privacy gate respects `allow_handle_discovery`, and verify `ProfileSyncStatus` reports cleanly when server lacks profile mutation endpoint.
     - **Scenario 3 — Runtime Theme, High-Contrast Mode & Dynamic Font Scaling Without Restart:**
       - Load `SettingsPlaceholder.qml` in headless `QQmlEngine`, drive `UiTheme` + `WorkspaceViewModel` through Dark -> Light -> High-Contrast Dark (`1.3x` font scale), verify immediate pixel size changes and `0` QML runtime warnings.
     - **Scenario 4 — Disappearing Message Timers (`1h` / `24h` / `7d`) & Automatic Purge Enforcement:**
       - Enable `1h` disappearing timer, send/receive 1:1 and group messages, confirm `expires_at_ms` stamps, run `purge_expired_messages(sent_ms + 3601 * 1000)`, verify expired messages vanish from `SqlCipherLocalStore` and `WorkspaceViewModel::activeMessages` while non-expiring messages persist.
     - **Scenario 5 — Endpoint-Only BIP-39 12-Word (Default) & 24-Word Recovery Phrase Lifecycle With Zero Network Transmission:**
       - Generate default 12-word (and optional 24-word) mnemonic, pass 3-word confirmation spot-check quiz, reject tampered checksum/word, derive deterministic 64-byte recovery seed, inspect Gateway request counters to assert **0** network calls with any BIP-39 word/digest, and trigger `EmergencyManager::execute_panic_wipe` to verify full purge of `"recovery.phrase.verifier"` and `"network.proxy.password"`.
     - **Scenario 6 — Live Loopback TLS 1.3 `QtHttpGatewayClient` Handshake, SPKI Pin Enforcement & Hot Reload:**
       - Point `ClientBootstrap` (`use_live_gateway_transport = true`) at an in-process loopback TLS 1.3 server, run `SettingsPlaceholder` TLS inspect (`inspectGatewayTlsFingerprint`), save real SPKI SHA-256 pin, execute authenticated messaging/profile requests cleanly over TLS 1.3, then rotate server cert and confirm pin mismatch fails closed immediately.
  2. Extend `src/client/main.cpp` `--capture-screenshots` to capture Settings Profile/Accessibility, Network/TLS Inspector, High-Contrast Dark/Light, and BIP-39 Recovery modal screenshots into `docs/final-reports/assets/client-014/`.
  3. Run Tier 1 (`--smoke-test`), Tier 2 (`--capture-screenshots`), `check-format`, and full client suite, and author `docs/final-reports/walkthrough-client-014.md` & `docs/pull_requests/CLIENT-014.md`.
     - **Mandatory Final Card Report Section:** `docs/final-reports/walkthrough-client-014.md` MUST contain an explicit **"Architectural Decisions & Security Rationale"** section recording all 6 Section 2.3 decisions — **mandatorily** documenting **Client Cryptographic Recovery Phrases (BIP-39) vs. Backend MFA Recovery Codes (`AuthService`)**, `User` / `UserProfile` / `UserSettings` separation & backend usage, dropping `has_password` from `ProxyConfig` + `"network.proxy.password"`, `SPKI SHA-256` pinning & disappearing message defaults, deferral of backend `UpdateUserProfile` RPC, and **what `CLIENT-014-T05` loopback TLS 1.3 tests prove vs. `CLIENT-015-T06` live Docker Compose E2E** + `SwitchableGatewayClient` / `DefaultGatewayClient` roles.
- **Acceptance Criteria:**
  - All 6 scenarios and 100% of `securecloud_client_foundation_test` tests pass with `0` `-Werror` warnings.
  - Tier 1 `--smoke-test` and Tier 2 `--capture-screenshots` pass with `0` QML warnings.
  - `check-format` passes across 100% of C++ files (`clang-format`).
  - `docs/final-reports/walkthrough-client-014.md` includes the mandatory Section 2.3 architectural decisions & BIP-39 vs. MFA recovery-codes rationale.

---

## 4. Architectural Invariants, Implementation Pitfalls & Phase Boundaries

### 4.1 Hard Architectural Invariants
1. **Endpoint-Only BIP-39 Recovery (`ADR-008 §27, §28`):**
   - BIP-39 mnemonic words, raw entropy, and derived recovery seeds must never leave the endpoint (`0` Gateway calls), never be persisted in plaintext SQLite, and never be written to `ClientLogger`.
2. **Human Identity Confidentiality (`ADR-008 §7`):**
   - Messaging, Files, and Audit services remain strictly pseudonymous on opaque UUIDs; profile sharing uses explicit `allow_handle_discovery` opt-in.
3. **E2EE Avatars & Fail-Closed TLS 1.3 SPKI Pinning (`ADR-008 §20, §30, §35`):**
   - Avatars are encrypted client-side via `FileCryptoEngine` (`dispatch_key_envelope = false`).
   - `QtHttpGatewayClient` enforces `TlsV1_3OrLater` and fails closed on SPKI SHA-256 mismatch before sending Bearer tokens or request bodies.
4. **Zero-Restart UI Reactivity:**
   - Palette switches (`Dark`, `Light`, `System`, `HighContrast`) and `fontScale` (`0.85–1.40`) propagate live via `UiTheme::themeChanged()`.
5. **Phase Boundary (`CLIENT-014` vs. `CLIENT-015`–`CLIENT-016`):**
   - `CLIENT-014` delivers the `QtHttpGatewayClient` TLS 1.3 adapter + loopback TLS verification alongside settings/profile/BIP-39.
   - Multi-service Docker Compose live E2E (`tests/integration/client_gateway_backend_integration_test.cpp`), local hash-chained audit logs, boot crypto self-tests, and CPU/RAM benchmark reports belong to **`CLIENT-015`** (`specs/client-phase4/CLIENT-015-tickets.md`).
   - Cross-platform OS Keychain / DPAPI / SecretService `ISecureStorage` adapters, signed installers (`.dmg`, MSI/MSIX, AppImage/`.deb`), and Ed25519 auto-updates belong to **`CLIENT-016`**.

### 4.2 Verified Repository Pitfalls to Avoid During Implementation
1. **`QNetworkAccessManager` Thread Affinity:** Do not share an un-marshaled `QNetworkAccessManager` across `SyncManager` / `FileManager` background threads (`QObject` thread affinity triggers Qt assertions or dropped signals). Use a dedicated internal network worker thread or per-call stack `QNetworkAccessManager` inside `QtHttpGatewayClient`.
2. **`POST /api/v1/messages` vs `/api/v1/messages/send`:** `src/gateway/http/routing/gateway_route_registrar.cpp:175` mounts a `501 NOT_IMPLEMENTED` stub on `/api/v1/messages/send`; map message submission in `QtHttpGatewayClient` to `POST /api/v1/messages` (`MessagingProxyHandler`) and `GET /health/live` (not `/health`).
3. **OpenSSL 3.6 & `llvm@18` `clang-format` Compatibility:**
   - Generate loopback test certificates using `X509_NAME_new()` + `X509_set_subject_name()` rather than mutating the pointer returned by `X509_get_subject_name()` (which became `const X509_NAME*` in OpenSSL 3.6).
   - Avoid multi-line chained braced initializers such as `nlohmann::json{...}.dump()`, where CI `llvm@18` and newer local Homebrew `clang-format` versions disagree.
4. **Preserve `CLIENT-013` QML Hooks:** Keep `duressPolicyCard`, `duressPinField`, `duressPinConfirmField`, `saveDuressPinButton`, `clearDuressPinButton`, `duressStatusBadge`, `readReceiptsSwitch`, and `settingsScrollView` intact in `SettingsPlaceholder.qml`.

---

## 5. Verification & Completion Gate Commands

```bash
# 1. Configure & build all client + test targets with -Werror
cmake --build build/dev-debug --target securecloud_client_foundation_test securecloud-client --parallel

# 2. Run all CLIENT-014 unit & E2E integration suites
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test \
  --gtest_filter="*UserSettings*:*SettingsAndExpiry*:*RecoveryPhrase*:*SettingsManager*:*QtHttpGateway*:*WorkspaceViewModelSettings*:*SettingsAndProfile*"

# 3. Run full client test suite + Tier 1 & Tier 2 real-binary smoke tests
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_foundation_test --gtest_brief=1
QT_QPA_PLATFORM=offscreen ./build/dev-debug/src/client/securecloud-client --smoke-test
QT_QPA_PLATFORM=offscreen ./build/dev-debug/src/client/securecloud-client --capture-screenshots /tmp/sc-client014-shots

# 4. Verify 100% clang-format compliance
cmake --build build/dev-debug --target check-format
```
