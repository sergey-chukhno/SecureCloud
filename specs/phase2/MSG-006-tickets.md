# MSG-006 — E2E Message Envelope Integration
## Phase 2 (M3: Secure Messaging Platform) Technical Specification & Implementation Tickets

**Card Identifier**: MSG-006  
**Milestone**: M3 — Secure Messaging Platform  
**Document Status**: Implementation-Ready Final Specification  
**Role**: Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Author**: Antigravity  
**Date**: October 16, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-006** implements the authoritative, secure **End-to-End (E2E) Message Envelope Integration** for the SecureCloud Messaging Service (`securecloud-messaging`), adhering strictly to **ADR-005** (Service Isolation), **ADR-007** (Message Reliability & Durability), **ADR-008** (Security & Cryptographic Architecture), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance, Capacity & Optimization Strategy).

While **MSG-005** established the durable write pipeline (monotonic sequence allocation, idempotency guard, and ScyllaDB durability commit boundary), **MSG-006 integrates the messaging service with the approved client-side end-to-end encryption model**. Under this card:
- The Messaging service acts strictly as a **ciphertext transport and durable messaging authority**, never as a plaintext processor or cryptographic endpoint.
- Server-side domain representations for multi-device encrypted message envelopes are formalized, validated, and persisted.
- Recipient device targeting is authoritatively validated against the **Auth service's public crypto directory**, ensuring delivery targets match registered, active devices.
- Cryptographic metadata (protocol version, algorithm, IV, auth tag, ephemeral public key) is strictly validated without decrypting message content.
- Protocol versioning is enforced to prevent cryptographic downgrade attacks, while unsupported or unsafe protocol versions fail closed.
- Zero plaintext guarantees are enforced across storage, logging, tracing, metrics, and error reporting.

This card establishes the server-side envelope handling required for subsequent delivery (**MSG-007**) and synchronization (**MSG-009**) subsystems.

---

## 2. Core Architectural Invariants & Security Boundaries

### 2.1 The Critical Security Boundary
> **Invariant (ADR-008)**: The Messaging service must NEVER decrypt E2E message content.

The intended data flow is strictly unidirectional regarding ciphertext:
```text
Client (Encrypt) ──► Gateway ──► Messaging ──► Persist Ciphertext ──► Deliver Ciphertext ──► Recipient Client (Decrypt)
```
- The backend inspects and validates routing and security metadata (sender ID, device ID, conversation ID, recipient device IDs, protocol versions, IV sizes, auth tag sizes), but **never requires plaintext message content** to perform normal messaging operations.
- Under no circumstances does the backend act as a key escrow, decryption oracle, or message inspection proxy.

### 2.2 Cryptographic Ownership Principle
- The cryptographic protocol itself remains an **endpoint/client responsibility** (Signal Protocol family of designs: Double Ratchet, PQXDH, Sesame multi-device architecture).
- The server-side Messaging implementation integrates with this architecture **without implementing its own cryptographic protocol**:
  1. **No custom encryption algorithms** (strictly standard `XChaCha20-Poly1305` or `AES-256-GCM`).
  2. **No custom ratchet implementation** on the server.
  3. **No server-held recipient private keys** (only public keys and prekey bundles in Auth).
  4. **No server-side plaintext fallback**.
  5. **No administrative or emergency decryption backdoor**.
  6. **No cryptographic downgrade** when expected protocols cannot be used.

### 2.3 Recipient-Device Model (Multi-Device Encryption)
A logical recipient (`UserId`) may own multiple authorized physical devices (`DeviceId`):
```text
Message
 ├── Recipient Device A1 ──► Encrypted Envelope A1 (Session Key A1)
 ├── Recipient Device A2 ──► Encrypted Envelope A2 (Session Key A2)
 └── Recipient Device B1 ──► Encrypted Envelope B1 (Session Key B1)
```
- The sender encrypts the payload independently for each authorized recipient device using that device's active ratchet session.
- The Messaging service preserves the association between the logical message (`message_id`) and its device-specific encrypted delivery targets without exposing plaintext.
- Delivery queues (`pending_deliveries_by_device`) store the device-specific ciphertext so that each device receives only its dedicated encrypted envelope.

### 2.4 Auth Crypto-Directory Integration & Authority Boundary
- **Auth Service Authority**: Auth owns the public key directory (`GetDeviceCryptoDirectory`, `GetCryptoIdentity`). It tracks enrolled devices, public identity keys, signed prekeys, and device lifecycle states (`ACTIVE`, `REVOKED`).
- **Messaging Service Authority**: Messaging owns conversation topology, participant membership, message sequence ordering, and delivery state tracking.
- **Directory Validation**: During message submission, Messaging validates recipient device targets against Auth's directory. If a target device is revoked or does not belong to the recipient user, the submission is rejected with `MESSAGING_ERROR_CODE_DEVICE_REVOKED` or `MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE`.

### 2.5 Protocol Versioning & No-Downgrade Invariant
- Every envelope specifies a protocol version (e.g., `SignalProtocol_V1`, `PQXDH_DoubleRatchet_V1`).
- The server validates the protocol version against an approved whitelist.
- Any attempt to submit an obsolete, unapproved, or unknown protocol version must be rejected deterministically with `MESSAGING_ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION`.
- Cryptographic negotiation failures **fail closed**.

### 2.6 Zero Plaintext & Redaction Policy
- Plaintext message content must never appear in ScyllaDB rows, log statements, distributed traces, Prometheus metrics, or gRPC error details.
- Logging wrappers must sanitize payloads: only metadata (message ID, conversation ID, recipient device ID, payload byte length, algorithm, protocol version) may be logged.
- Heuristic anti-plaintext guards detect and reject accidental or malicious submission of raw unencrypted ASCII/JSON payloads.

---

## 3. Dependency Graph & Ticket Decomposition

```text
               MSG-001 (Service Foundation & Tri-Pool Concurrency)
               MSG-002 (API Contracts, Protobuf & Error Mappers)
               MSG-003 (Conversation Authority & Authorization)
               MSG-004 (ScyllaDB Repositories & Partitioned Tables)
               MSG-005 (Message Submission & Idempotency Pipeline)
                                      │
                                      ▼
                                 MSG-006-T01
            (E2E Message Envelope Domain Model & Protocol Versioning)
                                      │
                                      ▼
                                 MSG-006-T02
            (Auth Crypto-Directory Client Port & Device Resolution)
                                      │
                                      ▼
                                 MSG-006-T03
            (Strict Envelope Security & Cryptographic Metadata Validator)
                                      │
                                      ▼
                                 MSG-006-T04
            (Per-Recipient-Device Envelope Persistence Integration)
                                      │
                                      ▼
                                 MSG-006-T05
            (End-to-End Pipeline Integration & Zero-Plaintext Audit Guard)
                                      │
                                      ▼
                                 MSG-006-T06
            (Comprehensive E2E Envelope Integration & Security Test Suite)
```

---

## 4. Detailed Implementation Tickets

### MSG-006-T01 — E2E Message Envelope Domain Model & Protocol Versioning Engine

1. **Ticket ID**: `MSG-006-T01`
2. **Title**: Server-Side E2E Message Envelope Domain Model, Value Objects & Protocol Versioning
3. **Objective**: Define strongly-typed server-side representations of end-to-end encrypted message envelopes, per-device delivery targets, and protocol versioning specifications.
4. **Architectural Purpose**: Establishes domain boundaries for opaque ciphertext representations, separating physical transport envelopes from internal cryptographic details, and enforces protocol version whitelisting to eliminate cryptographic downgrade vulnerabilities.
5. **Scope**:
   - In `src/messaging/domain/envelope_types.hpp`:
     - Define `E2EProtocolVersion` enum:
       - `V1_Signal_PQXDH_DoubleRatchet = 1`
       - `V2_Hybrid_PostQuantum = 2`
     - Define `E2EAlgorithm` enum:
       - `XChaCha20_Poly1305 = 1`
       - `AES_256_GCM = 2`
     - Define `PerDeviceEnvelope`:
       - `recipient_user_id`: `UserId`
       - `recipient_device_id`: `DeviceId`
       - `protocol_version`: `E2EProtocolVersion`
       - `algorithm`: `E2EAlgorithm`
       - `ciphertext_blob`: `std::string` (binary/opaque)
       - `ephemeral_public_key`: `std::vector<uint8_t>`
       - `iv`: `std::vector<uint8_t>`
       - `auth_tag`: `std::vector<uint8_t>`
       - `one_time_prekey_id`: `std::optional<std::string>`
     - Define `E2EMessageEnvelope`:
       - `message_id`: `MessageId`
       - `conversation_id`: `ConversationId`
       - `sender_user_id`: `UserId`
       - `sender_device_id`: `DeviceId`
       - `protocol_version`: `E2EProtocolVersion`
       - `priority`: `MessagePriority`
       - `created_at`: `time_point`
       - `expires_at`: `std::optional<time_point>`
       - `per_device_envelopes`: `std::vector<PerDeviceEnvelope>`
   - In `src/messaging/service/protocol_version_policy.hpp|cpp`:
     - Implement `ProtocolVersionPolicy`:
       - `is_supported_protocol_version(int32_t version) -> bool`
       - `is_approved_algorithm(std::string_view algo) -> bool`
       - `get_minimum_iv_size(E2EAlgorithm algo) -> size_t` (24 for XChaCha20, 12 for AES-GCM)
       - `get_minimum_auth_tag_size(E2EAlgorithm algo) -> size_t` (16 bytes)
       - Rejects unapproved, deprecated, or future unsupported versions (fails closed).
   - Unit tests in `tests/unit/messaging/protocol_version_policy_test.cpp` and `tests/unit/messaging/envelope_types_test.cpp`.
6. **Explicit Out-of-Scope**: Database persistence; gRPC network transport.
7. **Dependencies**: `MSG-002`, `MSG-005-T01`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/envelope_types.hpp`
   - `src/messaging/service/protocol_version_policy.hpp`
   - `src/messaging/service/protocol_version_policy.cpp`
   - `tests/unit/messaging/envelope_types_test.cpp`
   - `tests/unit/messaging/protocol_version_policy_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-006-T02 — Auth Crypto-Directory Client Port & Recipient Device Resolution Service

1. **Ticket ID**: `MSG-006-T02`
2. **Title**: Auth Public Crypto-Directory Client Port & Active Recipient Device Resolution Service
3. **Objective**: Implement the integration boundary between Messaging and Auth's public cryptographic directory to authoritatively discover and validate active recipient devices.
4. **Architectural Purpose**: Guarantees that message submissions only target currently enrolled, non-revoked devices belonging to authorized participants, preventing message delivery to revoked or rogue endpoints.
5. **Scope**:
   - In `src/messaging/client/auth_crypto_directory_client_interface.hpp`:
     - Define `IAuthCryptoDirectoryClient`:
       - `get_user_device_crypto_records(const UserId& user_id) -> Result<std::vector<DeviceCryptoRecord>, DependencyError>`
       - `get_device_crypto_identity(const DeviceId& device_id) -> Result<DeviceCryptoRecord, DependencyError>`
   - In `src/messaging/client/auth_crypto_directory_client.hpp|cpp`:
     - Implement gRPC client wrapper communicating with Auth service over mTLS:
       - Calls `AuthService.GetDeviceCryptoDirectory` with deadline enforcement.
       - Maps gRPC status codes to `DependencyError` (ADR-009).
   - In `src/messaging/service/recipient_device_resolution_service.hpp|cpp`:
     - Implement `RecipientDeviceResolutionService`:
       - Resolves all active enrolled devices for a given list of conversation participant `UserId`s.
       - Validates that every target device in an incoming submission:
         1. Belongs to the declared `recipient_user_id`.
         2. Has lifecycle status `DEVICE_STATUS_ACTIVE`.
         3. Rejects revoked (`DEVICE_STATUS_REVOKED`) or pending devices with `MESSAGING_ERROR_CODE_DEVICE_REVOKED`.
       - Validates completeness: warns or enforces that the sender included envelopes for all active recipient devices in the conversation (preventing selective device omission).
       - Bounded in-memory LRU cache (`DeviceDirectoryCache`) with short TTL (e.g., 30 seconds) to prevent Auth directory thundering herd during bursts.
   - Unit tests in `tests/unit/messaging/recipient_device_resolution_service_test.cpp` with mock client.
6. **Explicit Out-of-Scope**: Private key operations (Auth owns only public material).
7. **Dependencies**: `proto/securecloud/auth/v1/auth.proto`, `MSG-003`.
8. **Files to Create/Modify**:
   - `src/messaging/client/auth_crypto_directory_client_interface.hpp`
   - `src/messaging/client/auth_crypto_directory_client.hpp`
   - `src/messaging/client/auth_crypto_directory_client.cpp`
   - `src/messaging/service/recipient_device_resolution_service.hpp`
   - `src/messaging/service/recipient_device_resolution_service.cpp`
   - `tests/unit/messaging/recipient_device_resolution_service_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-006-T03 — Strict Envelope Security & Cryptographic Metadata Validator

1. **Ticket ID**: `MSG-006-T03`
2. **Title**: Comprehensive E2E Envelope Security, Cryptographic Metadata & Anti-Plaintext Validator
3. **Objective**: Implement the authoritative `E2EEnvelopeValidator` to enforce structural integrity, cryptographic header compliance, and anti-plaintext injection guards.
4. **Architectural Purpose**: Protects the persistence tier from malformed, tampered, or unencrypted envelopes, ensuring fail-closed security without decrypting ciphertext.
5. **Scope**:
   - In `src/messaging/service/e2e_envelope_validator.hpp|cpp`:
     - Implement `E2EEnvelopeValidator`:
       - **Rule 1: Sender Context Integrity**:
         - Sender `user_id` and `device_id` must match authenticated caller context (`MessagingCallerContext`).
       - **Rule 2: Protocol Version Whitelist**:
         - Enforces `ProtocolVersionPolicy`: rejects unknown or deprecated protocol versions (`MESSAGING_ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION`).
       - **Rule 3: Recipient & Device Integrity**:
         - Validates against `RecipientDeviceResolutionService`: all recipients must be active participants; all devices must be active enrolled devices.
       - **Rule 4: Cryptographic Parameter Bounds**:
         - Validates AEAD algorithm (`XChaCha20-Poly1305` or `AES-256-GCM`).
         - Validates IV size ($\ge 24$ bytes for XChaCha20, $\ge 12$ bytes for AES-GCM).
         - Validates Auth Tag size ($\ge 16$ bytes).
         - Validates Ephemeral Public Key non-empty ($\ge 32$ bytes for Curve25519/Kyber).
         - Validates ciphertext blob non-empty and $\le 16\text{ MB}$.
       - **Rule 5: Anti-Plaintext Injection Guard**:
         - Heuristic inspection to detect and reject accidental or malicious submission of raw JSON or ASCII plaintext disguised as ciphertext:
           - Checks printable ASCII ratio (if $\ge 90\%$ printable ASCII with valid JSON delimiters `{"`, fails validation with `MESSAGING_ERROR_CODE_UNENCRYPTED_PLAINTEXT_REJECTED`).
           - Ensures ciphertexts exhibit pseudo-random entropy distribution.
       - Returns strongly-typed `EnvelopeValidationResult`.
   - Unit tests in `tests/unit/messaging/e2e_envelope_validator_test.cpp`:
     - Valid envelopes pass.
     - Short IV, short auth tag, empty public key fail.
     - Unapproved algorithm fails.
     - Plaintext injection fails.
     - Mismatched sender device fails.
     - Revoked device fails.
6. **Explicit Out-of-Scope**: Decrypting or inspecting valid ciphertexts.
7. **Dependencies**: `MSG-006-T01`, `MSG-006-T02`.
8. **Files to Create/Modify**:
   - `src/messaging/service/e2e_envelope_validator.hpp`
   - `src/messaging/service/e2e_envelope_validator.cpp`
   - `tests/unit/messaging/e2e_envelope_validator_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-006-T04 — Per-Recipient-Device Envelope Persistence Integration

1. **Ticket ID**: `MSG-006-T04`
2. **Title**: Per-Recipient-Device Encrypted Envelope ScyllaDB Persistence Integration
3. **Objective**: Extend the ScyllaDB persistence tier to durably store and retrieve device-specific encrypted envelopes in alignment with MSG-004.
4. **Architectural Purpose**: Ensures that when downstream delivery (MSG-007) and sync (MSG-009) fetch messages for a specific device, the device receives its exact dedicated encrypted envelope without cross-device leakage.
5. **Scope**:
   - In `src/messaging/domain/delivery_types.hpp`:
     - Extend `DeviceDeliveryRecord` to include `PerDeviceEnvelope` (or device-specific ciphertext, IV, auth tag, ephemeral key, algorithm, protocol version).
   - In `src/messaging/repository/delivery_state_repository_interface.hpp`:
     - Update `save_pending_deliveries` and `fetch_pending_for_device` to support the complete device-specific envelope payload.
   - In `src/messaging/repository/scylla_delivery_state_repository.hpp|cpp`:
     - Update CQL queries and parameter bindings for `pending_deliveries_by_device`:
       - Bind and store `ciphertext_blob`, `ephemeral_public_key`, `iv`, `auth_tag`, `algorithm`, `protocol_version`.
       - Map row fields back to `DeviceDeliveryRecord`.
   - In `src/messaging/repository/in_memory_delivery_state_repository.hpp`:
     - Update in-memory repository to preserve full per-device envelopes for unit/integration testing.
   - Unit tests in `tests/unit/messaging/scylla_delivery_repository_envelope_test.cpp` and update `tests/unit/messaging/scylla_delivery_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Offline push notification dispatch.
7. **Dependencies**: `MSG-004-T03`, `MSG-006-T01`.
8. **Files to Create/Modify**:
   - `src/messaging/domain/delivery_types.hpp`
   - `src/messaging/repository/delivery_state_repository_interface.hpp`
   - `src/messaging/repository/scylla_delivery_state_repository.hpp`
   - `src/messaging/repository/scylla_delivery_state_repository.cpp`
   - `src/messaging/repository/in_memory_delivery_state_repository.hpp`
   - `tests/unit/messaging/scylla_delivery_repository_envelope_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-006-T05 — End-to-End Pipeline Integration & Zero-Plaintext Audit Guard

1. **Ticket ID**: `MSG-006-T05`
2. **Title**: Submission Pipeline Integration, Critical Durability Boundary Update & Zero-Plaintext Guard
3. **Objective**: Wire the E2E envelope validator and per-device persistence into `MessageSubmissionService`, enforce MSG-005 idempotency invariants, and implement zero-plaintext logging/redaction guards.
4. **Architectural Purpose**: Completes the live server-side envelope ingestion pipeline while guaranteeing that no plaintext fragments or sensitive cryptographic material leak into logs, traces, or metrics.
5. **Scope**:
   - In `src/messaging/service/message_submission_service.hpp|cpp`:
     - Integrate `E2EEnvelopeValidator` and `RecipientDeviceResolutionService` into `submit_message`:
       - Validates envelope structure and protocol versions before sequence allocation.
       - Enforces per-device target validation against Auth crypto directory.
       - Durably commits per-device encrypted envelopes into `IDeliveryStateRepository` alongside `MessageEntity` in the atomic durability boundary.
       - Preserves idempotency semantics (identical retries return cached result; conflicting payloads rejected with HTTP 409).
   - In `src/messaging/util/zero_plaintext_guard.hpp|cpp`:
     - Implement `ZeroPlaintextGuard`:
       - Provides safe logging formatters: `format_safe_envelope_log(...)` outputs only metadata (message ID, target device IDs, byte counts, algorithm names), strictly redacting ciphertext blobs and key bytes.
       - Sanitizes error messages to ensure no ciphertext or payload fragments are reflected in gRPC `Status` or HTTP error responses.
   - In `src/gateway/http/proxy/messaging_proxy_handler.cpp`:
     - Ensure Gateway REST route `POST /api/v1/messages` properly maps and validates protocol version and per-device envelope fields.
   - Unit tests in `tests/unit/messaging/message_submission_envelope_integration_test.cpp` and `tests/unit/messaging/zero_plaintext_guard_test.cpp`.
6. **Explicit Out-of-Scope**: Client-side encryption implementation.
7. **Dependencies**: `MSG-005-T04`, `MSG-006-T01` through `MSG-006-T04`.
8. **Files to Create/Modify**:
   - `src/messaging/service/message_submission_service.hpp`
   - `src/messaging/service/message_submission_service.cpp`
   - `src/messaging/util/zero_plaintext_guard.hpp`
   - `src/messaging/util/zero_plaintext_guard.cpp`
   - `src/gateway/http/proxy/messaging_proxy_handler.cpp`
   - `tests/unit/messaging/message_submission_envelope_integration_test.cpp`
   - `tests/unit/messaging/zero_plaintext_guard_test.cpp`
   - `src/messaging/CMakeLists.txt`
   - `tests/unit/CMakeLists.txt`

---

### MSG-006-T06 — Comprehensive E2E Envelope Integration & Security Test Suite

1. **Ticket ID**: `MSG-006-T06`
2. **Title**: Comprehensive E2E Message Envelope Integration & Security Test Suite
3. **Objective**: Validate the complete end-to-end envelope handling, cryptographic metadata validation, multi-device fan-out persistence, and anti-tamper boundaries under realistic multi-device scenarios.
4. **Architectural Purpose**: Certifies that the Messaging service operates as an authoritative, zero-knowledge ciphertext transport and storage engine without regression across the platform.
5. **Scope**:
   - Create `tests/integration/messaging_e2e_envelope_integration_test.cpp`:
     - **Test 1: Valid Multi-Device Encrypted Submission**: Sender submits message targeting 3 devices across 2 recipients $\to$ verifies message persisted, 3 distinct per-device encrypted envelopes persisted with correct ciphertexts, outbox event enqueued, success returned.
     - **Test 2: Malformed Cryptographic Metadata Rejection**: Envelopes with short IV (< 24B for XChaCha20), short auth tag (< 16B), or empty ephemeral key $\to$ rejected with `INVALID_ARGUMENT`, zero database writes.
     - **Test 3: Unsupported Protocol Version Rejection**: Submission with unapproved protocol version $\to$ rejected with `UNSUPPORTED_PROTOCOL_VERSION` (no downgrade).
     - **Test 4: Revoked Device Target Rejection**: Target device marked `REVOKED` in Auth crypto directory $\to$ rejected with `DEVICE_REVOKED`, zero database writes.
     - **Test 5: Unauthorized Sender Rejection**: Non-member sender $\to$ rejected with `PERMISSION_DENIED`.
     - **Test 6: Plaintext Injection Attempt Rejection**: Attempt to submit raw JSON/plaintext in ciphertext blob $\to$ detected and rejected by anti-plaintext guard.
     - **Test 7: Idempotent Replay with Per-Device Envelopes**: Mobile client retry with identical token and envelopes $\to$ returns original message ID without duplicate writes.
     - **Test 8: Conflicting Payload Tamper Rejection**: Client reuses token but alters one device's ciphertext $\to$ rejected with `IDEMPOTENCY_CONFLICT` (HTTP 409).
     - **Test 9: Zero Plaintext Audit Verification**: Intercept all log outputs and error payloads during submission and verify zero ciphertext/plaintext bytes leaked.
   - Run full verification suite with `python3 scripts/verify-local.py --preset dev-debug`.
6. **Explicit Out-of-Scope**: Offline push notification dispatching (MSG-007).
7. **Dependencies**: `MSG-006-T01` through `MSG-006-T05`.
8. **Files to Create/Modify**:
   - `tests/integration/messaging_e2e_envelope_integration_test.cpp`
   - `tests/integration/CMakeLists.txt`
   - `specs/phase2/MSG-006-tickets.md`

---

## 5. Acceptance Criteria & Validation Matrix

| Criterion | Target Specification | Validation Mechanism |
| :--- | :--- | :--- |
| **Opaque Ciphertext Acceptance** | Backend accepts encrypted envelope without decrypting | `e2e_envelope_validator_test.cpp` |
| **Protocol Version Enforcement** | Approved versions accepted; unsupported/downgrade rejected | `protocol_version_policy_test.cpp` |
| **Cryptographic Parameter Bounds** | IV $\ge 24$B (XChaCha20) / $12$B (AES), Tag $\ge 16$B enforced | `e2e_envelope_validator_test.cpp` |
| **Crypto-Directory Resolution** | Active devices resolved; revoked devices rejected | `recipient_device_resolution_service_test.cpp` |
| **Multi-Device Target Mapping** | Distinct per-device envelopes stored per recipient device | `messaging_e2e_envelope_integration_test.cpp` |
| **Anti-Plaintext Injection** | Raw JSON/ASCII in ciphertext detected and rejected | `e2e_envelope_validator_test.cpp` |
| **Zero Plaintext Leakage** | Logs, metrics, and error responses contain zero payload text | `zero_plaintext_guard_test.cpp` |
| **Durability Boundary Integrity** | Message + per-device envelopes + outbox + idempotency atomic | `message_submission_envelope_integration_test.cpp` |
| **Idempotency Consistency** | Identical retries return cached; tampered payload rejected | Integration suite scenarios 7 & 8 |
| **Zero Codebase Regressions** | All cumulative tests (1,454+) continue to pass cleanly | `verify-local.py --preset dev-debug` |

---

## 6. Architectural Invariants Checklist

- [x] **Critical Security Boundary**: Messaging service never decrypts E2E message content; operates purely as opaque ciphertext transport.
- [x] **No Server-Held Private Keys (ADR-008)**: Backend possesses zero recipient private keys and zero decryption capability.
- [x] **No Insecure Protocol Downgrade**: Unapproved or deprecated protocol versions fail closed.
- [x] **Auth Crypto-Directory Authority**: Recipient devices validated against Auth's public directory; revoked devices rejected.
- [x] **Per-Device Delivery Isolation**: Each recipient device receives its own dedicated encrypted envelope.
- [x] **Zero Plaintext Logging**: Ciphertext and plaintext bytes strictly redacted from logs, traces, and metrics.
- [x] **Zero Regressions**: Cumulative test suite passes 100% across all platforms.
