# CLIENT-008 — Contact Management, Peer Identity Verification & Directory Discovery: Ticket Decomposition & Architectural Specification

- **Card ID:** `CLIENT-008`
- **Card Title:** Contact Management, Peer Identity Verification & Directory Discovery
- **Milestone:** M4 — SecureCloud Native Desktop Client (`securecloud-client`)
- **Phase Placement:** **Client Phase 2 (`specs/client-phase2/CLIENT-008-tickets.md`) — Final Phase 2 Milestone Card**
- **Target Branch:** `feature/client-008-contact-management-and-peer-identity-verification`
- **Prerequisites Completed:**
  - `CLIENT-001` — Client Application Foundation & Layered C++20/Qt6 Architecture (`main` merged)
  - `CLIENT-002` — UI Design System, Theme Engine, Reusable QML Controls & Navigation Shell (`main` merged)
  - `CLIENT-003` — Authentication Flow, 4-Zone Workspace Shell, Files Vault & Device/MFA Trust Center (`main` merged)
  - `CLIENT-004` — Contacts, Conversations & Messaging UI (`main` merged)
  - `CLIENT-005` — Device Registration & Cryptographic Identity Lifecycle (`main` merged)
  - `CLIENT-006` — Signal Double Ratchet Session Management & End-to-End Encryption (`main` merged)
  - `CLIENT-007` — Device Management, Multi-Device Trust & Hardware Security / Attestation (`main` merged)

---

## 1. Executive Summary & Phase Classification

With the completion of **Cards `CLIENT-005` through `CLIENT-007`**, the SecureCloud native client possesses a hardened cryptographic foundation:
- Device registration, prekey lifecycle, and inventory replenishment (`CLIENT-005`).
- Complete Signal Double Ratchet state machine, X3DH key agreement engine, and bounded skipped key recovery (`CLIENT-006`).
- Multi-device pairing via out-of-band Short Authentication String (SAS), remote device revocation with Double Ratchet session purging, and hardware FIDO2 attestation (`CLIENT-007`).

**Card `CLIENT-008` represents the final milestone card of Client Phase 2**. It connects the cryptographic engine (`RatchetSessionManager`, `SafetyNumberEngine`, `ICryptoProvider`) to the contact and address-book domain (`ContactManager`, `IGatewayClient`, `ILocalStore`, `WorkspaceViewModel`), establishing:

1. **Client-Owned Contact Address Book**: As dictated by **Detailed Design §2.6 & §2.14**, contacts are client-owned. There is no backend contact microservice; the client locally manages contact relationships, human-readable aliases, role notes, and verification statuses in encrypted storage (`ILocalStore`).
2. **Directory Identity Discovery & Resolution**: The client queries the authoritative backend Auth directory via the Gateway API (`IGatewayClient`) to search users, resolve public identities, discover active device endpoints, and inspect cryptographic fingerprints.
3. **Mutual Out-of-Band Safety Number Verification**: Derives commutative 60-digit safety numbers (`SHA-512` over sorted identity keys and user IDs) and formats scannable QR verification URIs (`securecloud://verify?...`) for instant visual or physical barcode verification.
4. **Automated Identity Key Change Detection (`KeyChanged` state)**: Synchronizes contacts with the remote directory; upon detecting an unannounced identity key replacement (e.g. contact reinstall, device replacement, or active MITM substitution), the client immediately transitions the contact to `KeyVerificationStatus::KeyChanged`, surfaces prominent UI warning banners, and strictly suspends outbound message dispatch (`ADR-008 §18`).
5. **Contact Blocking, Anti-Harassment & Presence Privacy**: Enforces contact blocking at the cryptographic boundary: blocked contacts are suppressed from outbound encryption, inbound messages are discarded without ratchet decryption, and online status is shielded using synthetic offline responses (Mutual-Conversation Privacy Shield, ADR-008 §24).
6. **Workspace Presentation Layer Integration**: Connects `WorkspaceViewModel` to real `ContactManager` APIs, replacing mock vectors with live contacts, interactive QR code verification dialogs, and real-time reactive signals.

### Ticket Status Matrix

| Ticket | Description | Status | Target Scope |
|---|---|---|---|
| **CLIENT-008-T01** | Contact Domain Model Enrichment & Gateway Directory Discovery Contracts | **Completed** | Enriched `Contact`, `DirectoryUserEntry`, Gateway client directory search/lookup methods, unit tests |
| **CLIENT-008-T02** | Contact Directory Synchronization, Discovery & Presence Resolution Engine | **Completed** | `ContactManager`: Directory reconciliation, multi-device count updates, presence privacy shield integration |
| **CLIENT-008-T03** | Out-of-Band 60-Digit Safety Number Verification & Cryptographic State Pinning | **Completed** | Mutual 60-digit safety number lazy derivation & caching, verified key fingerprint pinning in `ISecureStorage` |
| **CLIENT-008-T04** | Automated Identity Key Change Detection, Alerting & Messaging Suspension | **Completed** | Key rotation detection, `KeyChanged` transition, `MessagingManager` outbound suspension guard, alert event dispatch |
| **CLIENT-008-T05** | Contact Blocking, Anti-Harassment Privacy Controls & ViewModel Integration | **Completed** | Inbound/outbound blocking enforcement, presence masking, `WorkspaceViewModel` production wiring & `Q_INVOKABLE` bindings |
| **CLIENT-008-T06** | Contact Management Integration Suite & Comprehensive Verification | **Completed** | End-to-end integration test suite, offscreen visual smoke tests, 100% test pass, final card walkthrough report |

```text
                            SECURECLOUD CLIENT (Phase 2 - CLIENT-008)
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ Presentation Tier: WorkspaceViewModel / Zone 2 Contact List / Zone 4 Security Inspector│
 │                                                                                        │
 │  1. Search Directory / Add Contact By Handle / View Contact Profile                    │
 │  2. Display 60-digit Safety Number & Scannable QR Code (securecloud://verify)          │
 │  3. Display "Key Changed" Security Alert Banner (ADR-008)                              │
 │  4. Toggle Verified / Block / Unblock Controls                                         │
 └─────────────────────────────┬────────────────────────────────────▲─────────────────────┘
                               │ User Actions                       │ Reactive Signals
                               ▼                                    │
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ Application Layer: ContactManager                                                      │
 │                                                                                        │
 │  • Local Address Book CRUD (Client-owned aliases, notes, blocked status)              │
 │  • Directory Resolution & Sync (Auth directory lookup via Gateway)                     │
 │  • SafetyNumberEngine Integration (60-digit SAS, scannable QR verification)            │
 │  • KeyChanged Detection & MessagingManager Suspension Guard                           │
 └─────────────┬──────────────────────────┬─────────────────────────┬─────────────────────┘
               │ Local Storage            │ Cryptographic Verify    │ Directory Discovery
               ▼                          ▼                         ▼
 ┌───────────────────────────┐ ┌────────────────────────┐ ┌──────────────────────────────┐
 │   ILocalStore / Storage   │ │   SafetyNumberEngine   │ │    Gateway Directory API     │
 │ (Contacts, Aliases, Notes,│ │ (SHA-512 60-digit SAS, │ │ (GET /users/search,          │
 │  Blocked List, Metadata)  │ │  ISecureStorage State) │ │  GET /users/:id/directory)   │
 └───────────────────────────┘ └────────────────────────┘ └──────────────────────────────┘
```

---

## 2. Architectural Analysis & Invariants

### 2.1 ADR-008 & Detailed Design Alignment

1. **Client-Owned Contacts vs. Authoritative Backend Directory (Detailed Design §2.6, §2.14):**
   - The desktop client owns the user's local contact relationships, aliases, notes, and verification statuses.
   - There is intentionally **no backend Contact microservice**.
   - The backend Auth service is the authoritative source for user identity, opaque user identifiers (`UserId`), and authorized device public cryptographic material.
   - Contacts reference opaque user identifiers; human-readable aliases remain client-side only and are never uploaded to the server in plaintext.

2. **Four Identity Verification Paradigms (ADR-008 §18.1):**
   - **Baseline Out-of-Band Safety Number Verification (MVP)**:
     - 60 decimal digits (12 blocks of 5 digits) derived from $\text{SHA-512}(\text{canonical\_sort}(IK_A, IK_B) \parallel \text{User IDs})$.
     - Scannable QR code encoding `securecloud://verify?v=1&u1=...&u2=...&sn=...`.
     - Non-blocking: messaging functions immediately; verification provides out-of-band cryptographic proof against active MITM adversaries.
   - **Automated Key Transparency & PKI (Roadmap Integration)**:
     - Prepares hooks for enterprise OIDC/PKI key attestation where corporate CA signatures automate verified status.

3. **Automated Identity Key Change Detection (ADR-008 §18, Detailed Design §2.6):**
   - When synchronizing contacts or preparing messages:
     - If a peer's identity key differs from the stored verified fingerprint:
       - Transition contact state to `KeyVerificationStatus::KeyChanged`.
       - Suspend trusted outbound message transmission to that contact (`ClientError::validation("Outbound messaging suspended: recipient identity key changed (ADR-008)")`).
       - Require the user to acknowledge the key change and explicitly re-verify the safety number before resuming trusted communication.

4. **Mutual-Conversation Privacy Shield & Contact Blocking (ADR-008 §24, Messaging Assessment):**
   - Blocking a contact immediately halts all outbound cryptographic encryption for that recipient.
   - Inbound messages from a blocked sender are dropped at the client boundary prior to Double Ratchet decryption, preventing replay or harassment.
   - Presence tracking queries for non-mutual contacts or blocked contacts return synthetic `OFFLINE` status, preventing third-party tracking.

---

## 3. Detailed Ticket Specifications

---

### CLIENT-008-T01: Contact Domain Model Enrichment & Gateway Directory Discovery Contracts

- **Ticket ID:** `CLIENT-008-T01`
- **Component:** `src/client/domain/` & `src/client/application/interfaces/`
- **Objective:** Enrich the `Contact` domain aggregate, model directory search entities, and expand `IGatewayClient` with user directory discovery and lookup APIs.
- **Architectural Scope:**
  1. **`domain::Contact` Model Enrichment:**
     - Fields: `user_id`, `alias`, `verification_status`, `identity_fingerprint`, `is_blocked`, `safety_number`, `role_note`, `presence_status`, `authorized_device_count`, `last_seen_at`, `updated_at`.
     - Methods: `is_verified()`, `has_key_changed()`, `can_send_messages()`.
     - Serialization / deserialization to JSON / local store representation.
  2. **`domain::DirectoryUserEntry` Structure:**
     - Models backend directory discovery search results:
       - `user_id`: Opaque UUID.
       - `username` / `handle`: Normalized handle (e.g. `@frances.swann`).
       - `display_name`: Server-provided profile name.
       - `identity_public_key`: Ed25519 public key bytes.
       - `identity_fingerprint`: SHA-256 hex string.
       - `active_device_count`: Number of authorized devices currently registered.
       - `created_at`: Account creation timestamp.
  3. **Gateway Client Directory API Expansion:**
     - Update `interfaces::IGatewayClient` and `infrastructure::adapters::DefaultGatewayClient`:
       - `ClientResult<std::vector<domain::DirectoryUserEntry>> search_directory_users(std::string_view query, std::size_t limit = 20);`
       - `ClientResult<domain::DirectoryUserEntry> lookup_user_identity(const domain::UserId& user_id);`
       - Test doubles and deterministic simulation hooks for directory searches.

- **Deliverables:**
  - Enriched `src/client/domain/contact.hpp` & `.cpp`
  - `src/client/domain/directory_user_entry.hpp`
  - Updated `src/client/application/interfaces/i_gateway_client.hpp`
  - Updated `src/client/infrastructure/adapters/default_gateway_client.hpp` & `.cpp`
  - Unit tests: `tests/unit/client/contact_domain_and_directory_test.cpp`

---

### CLIENT-008-T02: Contact Directory Synchronization, Discovery & Presence Resolution Engine

- **Ticket ID:** `CLIENT-008-T02`
- **Component:** `src/client/application/managers/`
- **Objective:** Implement the contact directory reconciliation engine in `ContactManager`, synchronizing local contact state with authoritative backend directory entries and updating active device rosters.
- **Architectural Scope:**
  1. **Directory Search & Contact Onboarding:**
     - `ClientResult<std::vector<domain::DirectoryUserEntry>> search_contacts(std::string_view query);`
     - `ClientResult<domain::Contact> add_contact_from_directory(const domain::DirectoryUserEntry& entry, std::string_view local_alias = "", std::string_view role_note = "");`
     - Automatically invokes `SafetyNumberEngine::compute_safety_number` using the local device identity key and the peer's resolved public key.
     - Persists new contact into `ILocalStore`.
  2. **Contact Directory Synchronization (`sync_contacts`):**
     - `ClientResult<std::size_t> sync_contacts();`
     - Iterates through local contacts, queries `IGatewayClient::get_device_crypto_directory` for each peer:
       - Updates `authorized_device_count`.
       - Detects revoked devices and instructs `RatchetSessionManager` to purge obsolete sessions.
       - Updates presence indicator under the Mutual-Conversation Privacy Shield (ADR-008 §24).
  3. **Local Store Persistence:**
     - Uses `ILocalStore` (`MemoryLocalStore` in tests, SQLCipher in Phase 3) for contact persistence.
     - Guarantees transactional consistency during batch contact updates.

- **Deliverables:**
  - Updated `src/client/application/managers/contact_manager.hpp` & `.cpp`
  - Unit tests: `tests/unit/client/contact_directory_sync_test.cpp`

---

### CLIENT-008-T03: Out-of-Band 60-Digit Safety Number Verification & Cryptographic State Pinning

- **Ticket ID:** `CLIENT-008-T03`
- **Component:** `src/client/application/managers/`
- **Objective:** Implement the focused out-of-band 60-digit Safety Number peer verification pipeline (aligned with the `CLIENT-007-T04` desktop decision — no QR scanner UI), connecting `SafetyNumberEngine` into `ContactManager` for on-demand safety number resolution and cryptographic fingerprint pinning in `ISecureStorage`.
- **Architectural Scope:**
  1. **Pairwise Safety Number Resolution & Caching:**
     - `ClientResult<std::string> get_or_compute_safety_number(const domain::UserId& peer_user_id);`
     - Resolves peer Ed25519 identity key (`lookup_user_identity` with fallback to `get_device_crypto_directory`), computes commutative 60-digit number formatted as 12 blocks of 5 digits (71 characters), and caches it in `ILocalStore`.
  2. **Verification State Persistence & Key Pinning:**
     - `ClientResult<void> set_contact_verified(const domain::UserId& peer_user_id, bool verified);`
     - Persists (or clears) the verified peer identity key fingerprint in `ISecureStorage` under `identity.verified.<peer_uid>`.
     - Updates contact `verification_status` and `identity_fingerprint` in `ILocalStore`.
     - Updates `verify_contact_key` to delegate to `set_contact_verified` while preserving compatibility with locally seeded contacts.

- **Deliverables:**
  - Extended `src/client/application/managers/contact_manager.hpp` & `.cpp`
  - Unit tests: `tests/unit/client/contact_verification_pipeline_test.cpp`

---

### CLIENT-008-T04: Automated Identity Key Change Detection, Alerting & Messaging Suspension

- **Ticket ID:** `CLIENT-008-T04`
- **Component:** `src/client/application/managers/` & `src/client/application/interfaces/`
- **Objective:** Implement the automated identity key change detection pipeline, triggering ADR-008 messaging suspension guards and UI security alert notifications.
- **Architectural Scope:**
  1. **Key Change Detection During Sync & Prekey Fetch:**
     - When fetching prekeys in `RatchetSessionManager` or syncing in `ContactManager`:
       - Invokes `SafetyNumberEngine::evaluate_key_verification_status(peer_user_id, peer_identity_key)`.
       - If the peer's public key fingerprint differs from stored verified fingerprint:
         - Contact transitions to `KeyVerificationStatus::KeyChanged`.
         - Recalculates new 60-digit safety number.
         - Persists updated contact state in `ILocalStore`.
  2. **ADR-008 Messaging Suspension Guard:**
     - In `MessagingManager::stage_outbound_message`:
       - Asserts that target recipient does NOT have `KeyVerificationStatus::KeyChanged`.
       - If key changed: rejects with `ClientError::validation("Outbound messaging suspended: recipient identity key changed (ADR-008)")`.
       - Guarantees zero messages are encrypted under an unacknowledged or substituted key.
  3. **Peer Key Change Acknowledgment & Re-Verification:**
     - `ClientResult<void> acknowledge_and_verify_key_change(const domain::UserId& peer_user_id);`
     - Overwrites stored verified fingerprint in `ISecureStorage` with new key fingerprint.
     - Transitions status back to `KeyVerificationStatus::Verified`.
     - Resumes outbound message sending.

- **Deliverables:**
  - Updated `src/client/application/managers/contact_manager.hpp` & `.cpp`
  - Updated `src/client/application/managers/messaging_manager.cpp`
  - Unit tests: `tests/unit/client/identity_key_change_alert_test.cpp`

---

### CLIENT-008-T05: Contact Blocking, Anti-Harassment Privacy Controls & ViewModel Integration

- **Ticket ID:** `CLIENT-008-T05`
- **Component:** `src/client/ui/` & `src/client/application/`
- **Objective:** Implement cryptographic contact blocking, anti-harassment safeguards, and bind `WorkspaceViewModel` to real `ContactManager` APIs for production presentation.
- **Architectural Scope:**
  1. **Contact Blocking & Privacy Safeguards:**
     - `ClientResult<void> set_contact_blocked(const domain::UserId& user_id, bool blocked);`
     - Outbound Guard: `MessagingManager::stage_outbound_message` rejects messages to blocked contacts (`ClientError::validation("Cannot send message to blocked contact")`).
     - Inbound Guard: Inbound messages from blocked senders are dropped at the client perimeter before Double Ratchet decryption.
     - Presence Masking: Blocked contacts always receive synthetic `Offline` presence.
  2. **`WorkspaceViewModel` Production Wiring:**
     - Synchronize `contacts()` property with live `ContactManager` records.
     - Wire `Q_INVOKABLE bool addContactByHandle(const QString& handle, const QString& displayName = QString(), const QString& roleNote = QString());`
     - Wire `Q_INVOKABLE bool verifyContactSafetyNumber(const QString& userId, bool verified);`
     - Wire `Q_INVOKABLE bool blockContact(const QString& userId, bool blocked);`
     - Wire `Q_INVOKABLE void syncContacts();`
     - Wire `Q_INVOKABLE bool acknowledgeKeyChange(const QString& userId);`
  3. **Reactive UI Event & Property Synchronization:**
     - Emit `contactsChanged()`, `conversationsChanged()`, `selectedConversationChanged()` on all contact transitions.
     - Ensure Zone 2 (Contact List), Zone 3 (Chat Header), and Zone 4 (Peer Security Inspector) update synchronously.

- **Deliverables:**
  - Updated `src/client/ui/workspace_view_model.hpp` & `.cpp`
  - Unit tests: `tests/unit/client/workspace_view_model_contacts_test.cpp`

---

### CLIENT-008-T06: Contact Management Integration Suite & Comprehensive Verification

- **Ticket ID:** `CLIENT-008-T06`
- **Component:** `tests/integration/` & `docs/final-reports/`
- **Objective:** Implement the end-to-end contact management and peer verification integration test suite, verify 100% test pass, zero warnings, `.clang-format` compliance, and compile the final Card 008 walkthrough report.
- **Architectural Scope:**
  1. **End-to-End Contact Integration Tests (`ContactManagementIntegrationTest`):**
     - **Contact Discovery, Onboarding & Mutual 60-Digit Verification**: Two independent workstations search directory, onboard with local aliases, derive identical commutative 60-digit safety numbers, and pin Ed25519 fingerprints in `ISecureStorage`.
     - **Identity Key Change & Suspension Lifecycle**: Peer rotates identity key; directory sync detects mismatch; transitions to `KeyChanged`; asserts `MessagingManager` rejects outbound messages across stage/send/retry; peer acknowledges and re-verifies to resume messaging.
     - **Contact Blocking & Harassment Shield**: Exercises ADR-008 §24 Mutual-Conversation Privacy Shield and contact blocking; asserts outbound sends blocked, inbound Double Ratchet packets dropped before decryption, and presence masked `Offline`.
     - **Multi-Device Directory Reconciliation**: Establishes sessions across 3 peer devices; revokes 1 device; directory sync reconciles count `3 -> 2`, purges revoked Double Ratchet session, and excludes revoked device from fan-out encryption.
     - **WorkspaceViewModel Full User Journey**: Drives `addContactByHandle` -> `verifyContactSafetyNumber` -> `sendMessage` -> directory key rotation -> `syncContacts` -> `acknowledgeKeyChange` -> `blockContact` -> `removeContact`.
  2. **Codebase Hygiene & Quality Gates:**
     - 100% passing tests across all unit and integration test suites.
     - Zero compiler warnings (`-Wall -Wextra -Wpedantic -Werror`).
     - Complete `.clang-format` compliance across all modified files.
  3. **Final Card Walkthrough Report:**
     - Comprehensive Markdown validation report in `docs/final-reports/walkthrough-client-008.md`.

- **Deliverables:**
  - `tests/unit/client/contact_management_integration_test.cpp`
  - `docs/final-reports/walkthrough-client-008.md`

---

## 4. Implementation Rules & Non-Functional Requirements

1. **Host Isolation Invariant:**
   - Zero PostgreSQL, Redis, or Gateway processes started on host ports.
   - All tests run in-process using deterministic test doubles (`DefaultGatewayClient`, `MemorySecureStorage`, `MemoryLocalStore`, `OpenSslCryptoProvider`, `SimulatedHardwareAuthenticator`).

2. **Cryptographic Safety Invariant:**
   - Zero custom cryptographic primitives. All safety number calculations must use `SafetyNumberEngine` and OpenSSL 3.x EVP primitives.
   - Verified fingerprints must reside in `ISecureStorage`.
   - Contact aliases and role notes remain client-owned; never upload address book in plaintext.

3. **ADR-008 §18 Outbound Suspension Invariant:**
   - When a peer identity key changes, the client MUST refuse to encrypt outbound messages until explicit user acknowledgment and re-verification.

4. **Codebase Formatting & Cleanliness:**
   - Strict compliance with project `.clang-format` and `.clang-tidy`.
   - Zero warnings under `-Wall -Wextra -Wpedantic -Werror`.

