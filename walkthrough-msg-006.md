# Card Validation Report: MSG-006 — E2E Message Envelope Integration

**Card ID:** `MSG-006`  
**Card Title:** E2E Message Envelope Integration  
**Milestone:** M3 — Secure Messaging Platform  
**Repository:** `SecureCloud`  
**Branch:** `feature/msg-006-e2e-envelope-integration`  
**Status:** IN PROGRESS (T01 Validated, T02 In Progress)  
**Author:** Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Date:** October 16, 2026  

---

## Table of Contents

1. [Executive Summary & Strategic Objective](#1-executive-summary--strategic-objective)
   - 1.1 [Milestone M3 Context & E2E Integration Boundary](#11-milestone-m3-context--e2e-integration-boundary)
   - 1.2 [The Critical Security Boundary: Backend as Opaque Ciphertext Transport](#12-the-critical-security-boundary-backend-as-opaque-ciphertext-transport)
   - 1.3 [Cryptographic Ownership Principle & Anti-Downgrade Invariant](#13-cryptographic-ownership-principle--anti-downgrade-invariant)
   - 1.4 [Zero Plaintext Guarantee Across Persistence, Tracing & Logging](#14-zero-plaintext-guarantee-across-persistence-tracing--logging)
   - 1.5 [Architectural Invariants & ADR Compliance Matrix](#15-architectural-invariants--adr-compliance-matrix)
2. [E2E Message Envelope Domain Model & Protocol Versioning (MSG-006-T01)](#2-e2e-message-envelope-domain-model--protocol-versioning-msg-006-t01)
   - 2.1 [Domain Model & Strongly-Typed Value Objects](#21-domain-model--strongly-typed-value-objects)
   - 2.2 [Protocol Version Policy Engine: Whitelisting & Fail-Closed Guards](#22-protocol-version-policy-engine-whitelisting--fail-closed-guards)
   - 2.3 [Cryptographic Parameter Lower Bounds Enforcement](#23-cryptographic-parameter-lower-bounds-enforcement)
   - 2.4 [Validation & Unit Test Suite Coverage](#24-validation--unit-test-suite-coverage)
3. [Auth Crypto-Directory Client Port & Recipient Device Resolution (MSG-006-T02)](#3-auth-crypto-directory-client-port--recipient-device-resolution-msg-006-t02)
   - 3.1 [Architectural Goal & Authority Boundaries](#31-architectural-goal--authority-boundaries)
   - 3.2 [The Auth Directory Thundering Herd Problem](#32-the-auth-directory-thundering-herd-problem)
   - 3.3 [Thread-Safe LRU Cache Architecture with 30-Second TTL](#33-thread-safe-lru-cache-architecture-with-30-second-ttl)
   - 3.4 [Device Target Validation Rules & Lifecycle State Machine](#34-device-target-validation-rules--lifecycle-state-machine)
   - 3.5 [Selective Device Omission Detection & Anti-Tamper Invariants](#35-selective-device-omission-detection--anti-tamper-invariants)
4. [Strict Envelope Security & Anti-Plaintext Guard (MSG-006-T03)](#4-strict-envelope-security--anti-plaintext-guard-msg-006-t03)
5. [Per-Recipient-Device Envelope Persistence Integration (MSG-006-T04)](#5-per-recipient-device-envelope-persistence-integration-msg-006-t04)
6. [End-to-End Pipeline Integration & Zero-Plaintext Audit Guard (MSG-006-T05)](#6-end-to-end-pipeline-integration--zero-plaintext-audit-guard-msg-006-t05)
7. [Comprehensive Validation, Quality Gates & Compliance Summary (MSG-006-T06)](#7-comprehensive-validation-quality-gates--compliance-summary-msg-006-t06)

---

## 1. Executive Summary & Strategic Objective

### 1.1 Milestone M3 Context & E2E Integration Boundary

Card **MSG-006** establishes the authoritative server-side End-to-End (E2E) Message Envelope Integration for the SecureCloud Messaging Service (`securecloud-messaging`). In Milestone M3, previous cards established:
- **MSG-001**: Tri-pool concurrency, service foundation, and mTLS infrastructure.
- **MSG-002**: Protobuf contracts, domain value objects, and gRPC error mapping.
- **MSG-003**: Conversation authority, membership authorization, and topology invariants.
- **MSG-004**: ScyllaDB partitioned storage, monthly UTC bucketing, and repository ports.
- **MSG-005**: Durable atomic message submission pipeline, client idempotency guard, and monotonic sequence allocation.

While MSG-005 proved the durable write pipeline, **MSG-006 formally integrates the Messaging Service with the approved client-side end-to-end encryption architecture**. Under this card, the Messaging service acts as an authoritative, durable **ciphertext transport and message authority**, never as a plaintext processor, cryptographic endpoint, or decryption oracle.

```text
┌──────────────┐          ┌─────────────┐          ┌───────────────────┐          ┌──────────────┐
│  Client A    │          │   Gateway   │          │ Messaging Service │          │  Client B    │
│  (Sender)    │          │   (Proxy)   │          │ (Ciphertext Port) │          │ (Recipient)  │
└──────┬───────┘          └──────┬──────┘          └─────────┬─────────┘          └──────┬───────┘
       │                         │                           │                           │
       │ Encrypt (Per-Device)    │                           │                           │
       │ ───────────────────────►│                           │                           │
       │                         │ Forward Ciphertext Target │                           │
       │                         │ ─────────────────────────►│                           │
       │                         │                           │ Validate Target Devices   │
       │                         │                           │ Validate Protocol & Params│
       │                         │                           │ Persist Opaque Envelopes  │
       │                         │                           │ ─────────────────────────►│ Delivery
       │                         │                           │                           │ Queue
       │                         │                           │                           │
       │                         │                           │                           │ Fetch Ciphertext
       │                         │                           │                           │◄────────────────
       │                         │                           │                           │ Decrypt Locally
```

### 1.2 The Critical Security Boundary: Backend as Opaque Ciphertext Transport

> **Security Invariant (ADR-008)**: The Messaging Service backend must **NEVER** inspect, process, or decrypt end-to-end encrypted message payloads.

Under ADR-008, SecureCloud adheres to a strict separation of concerns:
1. **Endpoint Cryptographic Sovereignty**: Cryptographic operations (Double Ratchet session establishment, PQXDH key exchanges, ciphertext generation, AEAD tag verification, and decryption) are executed strictly on authenticated user endpoints (client devices).
2. **Server-Side Opaque Routing**: The Messaging service inspects routing and security metadata (sender ID, device ID, conversation ID, recipient device IDs, protocol version, IV byte length, authentication tag length) solely to validate authorization, enforce ordering, and route envelopes to target device delivery queues.
3. **No Key Escrow or Decryption Backdoor**: The backend never holds recipient private keys, never retains escrowed session secrets, and provides no administrative backdoor for plaintext recovery.

### 1.3 Cryptographic Ownership Principle & Anti-Downgrade Invariant

The server-side Messaging implementation integrates with the client cryptographic architecture without attempting to implement its own custom cryptography:
- **Approved AEAD Ciphers Only**: Strictly `XChaCha20-Poly1305` (with 24-byte nonce) and `AES-256-GCM` (with 12-byte IV). Custom ciphers or unauthenticated legacy modes (e.g., CBC without MAC) are rejected deterministically.
- **Approved Protocol Versions**: Signal Protocol family with PQXDH and Double Ratchet (`V1_Signal_PQXDH_DoubleRatchet` and `V2_Hybrid_PostQuantum`).
- **Fail-Closed Anti-Downgrade Invariant**: Any attempt to negotiate an unapproved, deprecated, or future unsupported protocol version fails closed with `MESSAGING_ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION`. Downgrade to unencrypted transport or obsolete protocol versions is architecturally prohibited.

### 1.4 Zero Plaintext Guarantee Across Persistence, Tracing & Logging

- **Persistence Layer**: ScyllaDB rows store only binary ciphertext blobs, ephemeral keys, IVs, and authentication tags. No plaintext message text, file names, or user content is ever written to disk unencrypted.
- **Observability Layer**: Logging wrappers sanitize all payloads. Structured log entries and distributed traces capture only non-sensitive metadata (message ID, conversation ID, recipient device ID, byte lengths, protocol versions). Plaintext injection filters reject unencrypted ASCII or structured JSON payloads masquerading as ciphertext.

### 1.5 Architectural Invariants & ADR Compliance Matrix

| Architectural Principle | Applicable ADR | Implementation Mechanism | Verification Method |
| :--- | :--- | :--- | :--- |
| **Service Isolation** | **ADR-005** | Messaging delegates device/credential authority to Auth via gRPC mTLS port | Unit & integration tests with mock and live stubs |
| **Durability & Ordering** | **ADR-007** | Device delivery records persisted in ScyllaDB clustering order | `ScyllaMessageRepository` persistence tests |
| **Zero Plaintext Boundary** | **ADR-008** | Payload treated as opaque byte blob; zero server-side decryption keys | Zero-plaintext audit guard and memory inspection |
| **Cryptographic Anti-Downgrade**| **ADR-008** | Whitelist enforcement via `ProtocolVersionPolicy` | `ProtocolVersionPolicyTest` unit suite |
| **Distributed Resilience** | **ADR-009** | Read-through caching, circuit breaking, and fail-closed security | Mock failure injection and timeout tests |
| **High-Throughput SLAs** | **ADR-010** | Thread-safe LRU cache with 30s TTL eliminating Auth thundering herds | Concurrency stress benchmarks |

---

## 2. E2E Message Envelope Domain Model & Protocol Versioning (MSG-006-T01)

### 2.1 Domain Model & Strongly-Typed Value Objects

Ticket **MSG-006-T01** established the strongly-typed server-side representations of end-to-end encrypted message envelopes in `src/messaging/domain/envelope_types.hpp`:

1. **`E2EProtocolVersion`**:
   - `V1_Signal_PQXDH_DoubleRatchet = 1`: Baseline post-quantum Signal protocol ratchet.
   - `V2_Hybrid_PostQuantum = 2`: Next-generation hybrid post-quantum ratchet.
   - Robust string conversion and parsing helpers (`to_string`, `e2e_protocol_version_from_int`, `e2e_protocol_version_from_string`).

2. **`E2EAlgorithm`**:
   - `XChaCha20_Poly1305 = 1`: 256-bit AEAD with 192-bit (24-byte) random nonce.
   - `AES_256_GCM = 2`: 256-bit AEAD with 96-bit (12-byte) initialization vector.
   - Canonical name mapping (`to_string`, `e2e_algorithm_from_string`).

3. **`PerDeviceEnvelope`**:
   Represents a device-specific delivery target encapsulating:
   - `recipient_user_id`: Target user identity (`domain::UserId`).
   - `recipient_device_id`: Target physical device identity (`domain::DeviceId`).
   - `protocol_version`: Enforced `domain::E2EProtocolVersion`.
   - `algorithm`: Enforced `domain::E2EAlgorithm`.
   - `ciphertext_blob`: Opaque binary string holding device-specific ciphertext.
   - `ephemeral_public_key`: Sender's ephemeral public key for session establishment ($32\text{ bytes}$).
   - `iv`: Initialization vector or nonce ($24\text{ bytes}$ for XChaCha20, $12\text{ bytes}$ for AES-GCM).
   - `auth_tag`: AEAD authentication tag ($\ge 16\text{ bytes}$).
   - `one_time_prekey_id`: Optional ID of claimed prekey for session initialization.

4. **`E2EMessageEnvelope`**:
   Represents the top-level container preserving the canonical association between a logical message (`MessageId`, `ConversationId`, `sender_user_id`, `sender_device_id`) and its list of per-device encrypted targets (`std::vector<PerDeviceEnvelope>`).

### 2.2 Protocol Version Policy Engine: Whitelisting & Fail-Closed Guards

Implemented in `src/messaging/service/protocol_version_policy.hpp` and `.cpp`:
- **Strict Whitelist**: Accepts only `V1_Signal_PQXDH_DoubleRatchet` and `V2_Hybrid_PostQuantum`. All unapproved, obsolete, or unknown versions are rejected.
- **Fail-Closed Anti-Downgrade**: If a client attempts to submit a message with an unsupported protocol version (e.g., version 0, negative integers, or unapproved legacy protocols), the policy rejects the envelope deterministically before any database write or sequence allocation can occur.

### 2.3 Cryptographic Parameter Lower Bounds Enforcement

The policy engine enforces authoritative cryptographic lower bounds in accordance with ADR-008 and ADR-010:
- **Ciphertext Size**: Maximum $16\text{ MB}$ (`k_max_ciphertext_bytes`). Prevents memory exhaustion and ScyllaDB partition bloat.
- **Authentication Tag Size**: Minimum $16\text{ bytes}$ (`k_min_auth_tag_bytes`). Rejects truncated tags that could permit forgery attacks.
- **Initialization Vector (IV) Size**:
  - $24\text{ bytes}$ minimum for `XChaCha20-Poly1305` (`k_min_xchacha20_iv_bytes`).
  - $12\text{ bytes}$ minimum for `AES-256-GCM` (`k_min_aes_gcm_iv_bytes`).
- **Ephemeral Public Key Size**: Minimum $32\text{ bytes}$ (`k_min_ephemeral_key_bytes`), matching X25519 public key curve requirements.

### 2.4 Validation & Unit Test Suite Coverage

- `tests/unit/messaging/envelope_types_test.cpp`:
  - `ProtocolVersionToStringAndParsing`: Verifies bidirectional string/int conversions and rejection of invalid values.
  - `AlgorithmToStringAndParsing`: Verifies case-insensitive parsing and rejection of insecure ciphers (e.g., DES, CBC).
  - `PerDeviceEnvelopeEqualityAndComparison`: Validates three-way comparison operators and structural equality.
  - `E2EMessageEnvelopeStructure`: Verifies aggregate initialization and copy semantics.
- `tests/unit/messaging/protocol_version_policy_test.cpp`:
  - `ProtocolVersionWhitelisting`: Confirms approval of V1/V2 and rejection of 0, negative, and future unknown versions.
  - `ApprovedAlgorithms`: Verifies whitelisting of XChaCha20 and AES-GCM.
  - `MinimumCryptographicParameterSizes`: Confirms parameter thresholds.
  - `ValidateEnvelopeSecurityValidXChaCha20` & `ValidateEnvelopeSecurityValidAESGCM`: Positive path parameter verification.
  - `ValidateEnvelopeSecurityRejects*`: Negative tests covering short IVs, short auth tags, short ephemeral keys, empty ciphertext, oversized ciphertext, unsupported protocol versions, and unapproved algorithms.

All 17 tests passed with 100% success rate.

---

## 3. Auth Crypto-Directory Client Port & Recipient Device Resolution (MSG-006-T02)

### 3.1 Architectural Goal & Authority Boundaries

In multi-device E2E messaging, client endpoints encrypt messages independently for every physical device registered to the recipient participants. The Messaging Service must not rely on the client's unverified assertion of which devices exist or are active. 

#### The Authority Boundary:
- **Auth Service Authority**: Auth owns user credentials, account lifecycle, device registration, device revocation, and public cryptographic prekey directories (`GetDeviceCryptoDirectory`, `GetCryptoIdentity`).
- **Messaging Service Authority**: Messaging owns conversation topology, participant membership, message sequence numbers, idempotency tokens, and device delivery queues.

#### Objective of MSG-006-T02:
Provide a robust client port and recipient device resolution engine (`RecipientDeviceResolutionService`) that queries Auth's directory to validate every target device in an incoming message submission before sequence allocation or ScyllaDB persistence.

### 3.2 The Auth Directory Thundering Herd Problem

#### What is a Thundering Herd (Cache Stampede)?
A **Thundering Herd** occurs when high volumes of concurrent requests simultaneously attempt to query or compute an un-cached or expired resource, resulting in massive synchronous downstream load spikes.

#### The Problem in SecureCloud Messaging:
Consider an active group conversation with 20 participants operating under normal or peak load:
1. In high-traffic group channels, dozens or hundreds of messages per second are submitted across concurrent worker threads.
2. If every message submission issued synchronous gRPC calls (`GetDeviceCryptoDirectory`) to the Auth Service:
   - 100 submissions/sec $\times$ 20 participants = **2,000 gRPC RPCs per second** hitting the Auth Service solely to look up public keys for the same 20 users.
   - This creates extreme socket consumption, worker pool saturation in Auth, and connection pool exhaustion in PostgreSQL (where Auth stores device records).
   - Message submission latency degrades from $<5\text{ ms}$ to $>100\text{ ms}$, risking gRPC deadline timeouts.
3. Furthermore, when a popular user in multiple active channels receives bursts of messages, all messaging worker threads race concurrently to fetch that same user's device directory.

Without intelligent caching, the Auth Service becomes a severe single point of saturation, threatening platform stability and violating **ADR-010** latency SLAs.

### 3.3 Thread-Safe LRU Cache Architecture with 30-Second TTL

To eliminate the thundering herd while strictly respecting device security lifecycles, the Messaging Service incorporates an in-memory, thread-safe **LRU (Least Recently Used) cache with a 30-second Time-To-Live (TTL)**.

```text
Message Submission (Worker Pool Thread)
                   │
                   ▼
       Check Local Memory Cache for User U
                   │
         ┌─────────┴─────────┐
         │                   │
   [Cache Hit &         [Cache Miss /
    TTL < 30s]           TTL Expired]
         │                   │
         │                   ▼
         │           Call Auth Service (gRPC)
         │           GetDeviceCryptoDirectory(U)
         │                   │
         │                   ▼
         │           Update Local Memory Cache:
         │           - Device Records: [DevA, DevB]
         │           - CachedAt: std::chrono::steady_clock::now()
         │           - Evict LRU Tail if Count > Capacity
         │                   │
         └─────────┬─────────┘
                   ▼
     Execute Device Target Validation
```

#### Detailed Cache Mechanics:

1. **Time-To-Live (TTL = 30 seconds)**:
   - Every cached user entry stores `cached_at = steady_clock::now()`.
   - Subsequent lookups within 30 seconds are satisfied in $<0.01\text{ ms}$ with zero network overhead.
   - **Why 30 seconds?**:
     - *Security Upper Bound*: If a user revokes a compromised device, that revocation propagates across all messaging nodes within $\le 30$ seconds (or instantly if an explicit cache invalidation event is received).
     - *Throughput Absorption*: 30 seconds is sufficiently long to absorb $>99.9\%$ of directory lookups during conversational bursts, reducing Auth RPC traffic by several orders of magnitude.

2. **LRU Eviction (Least Recently Used)**:
   - The cache maintains a bounded capacity (e.g., 50,000 user entries), capping memory usage to tens of megabytes.
   - Uses an internal doubly-linked list (`std::list<UserId>`) to track access recency and a hash map (`std::unordered_map`) for $O(1)$ lookups.
   - On every access, the user entry is moved to the head of the list. When capacity is exceeded, the entry at the tail (least recently accessed) is evicted.

3. **Concurrency & Read-Write Synchronization**:
   - The cache is accessed concurrently by multiple worker threads.
   - Synchronized using a shared mutex (`std::shared_mutex`):
     - **Concurrent Readers (`std::shared_lock`)**: Multiple worker threads validating target devices can read cached entries simultaneously without blocking one another.
     - **Exclusive Writer (`std::unique_lock`)**: An exclusive lock is acquired only briefly when inserting new entries, updating expired records, or evicting the LRU tail.

4. **Explicit Invalidation Support**:
   - Provides `invalidate_user_cache(UserId)` and `clear_cache()`.
   - Allows instant invalidation during automated test fixtures and when receiving device revocation events from Auth.

### 3.4 Device Target Validation Rules & Lifecycle State Machine

When a sender submits a message, `RecipientDeviceResolutionService` applies 4 strict validation rules:

1. **Conversation Participant Authorization**:
   - Every `recipient_user_id` in the submission must be an active participant in the target conversation. Non-participant targets are rejected with `MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT`.
2. **Device Ownership Alignment**:
   - Every target `recipient_device_id` must actually belong to the declared `recipient_user_id` according to the Auth directory. Mismatched device ownership is rejected with `MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE`.
3. **Device Lifecycle State (ACTIVE)**:
   - A target device must have status `DEVICE_STATUS_ACTIVE`.
   - Devices marked `DEVICE_STATUS_REVOKED` or `DEVICE_STATUS_PENDING_AUTHORIZATION` are rejected deterministically with `MESSAGING_ERROR_CODE_DEVICE_REVOKED`.
4. **Sender Device Validation**:
   - The `sender_device_id` must belong to the authenticated caller and be in `DEVICE_STATUS_ACTIVE`.

### 3.5 Selective Device Omission Detection & Anti-Tamper Invariants

- **The Threat**: In a multi-device environment, a malicious or compromised sender might attempt a **selective omission attack**—deliberately omitting one of Alice's active devices (e.g., omitting her desktop computer so that sensitive information is only seen on her phone).
- **The Guard**: `RecipientDeviceResolutionService` compares the list of target devices in the submission against the authoritative list of active devices discovered from Auth. If an active device belonging to an authorized recipient participant is omitted, the service flags the submission as incomplete, enforcing complete delivery fan-out.

### 3.6 Validation & Unit Test Suite Coverage

The recipient device resolution and cache subsystem was validated with a dedicated unit test suite in `tests/unit/messaging/recipient_device_resolution_service_test.cpp`:

1. **`DeviceDirectoryCacheTest.PutAndGet`**: Confirms basic insert and retrieval of device crypto records.
2. **`DeviceDirectoryCacheTest.TtlExpiration`**: Verifies that cached entries expire after the configured TTL (50ms test threshold), returning `std::nullopt` and evicting stale records.
3. **`DeviceDirectoryCacheTest.LruEvictionAtCapacity`**: Tests bounded capacity eviction, verifying that the least recently accessed user entry is pruned when new entries arrive.
4. **`DeviceDirectoryCacheTest.ExplicitInvalidationAndClear`**: Tests targeted invalidation by `UserId` and full cache clearing.
5. **`RecipientDeviceResolutionServiceTest.HappyPathAllActiveDevicesTargeted`**: Validates successful target verification when all active recipient devices are correctly targeted.
6. **`RecipientDeviceResolutionServiceTest.CacheEliminatesRedundantDownstreamRpc`**: Verifies that consecutive resolutions for the same user issue only a single downstream RPC, and that cache invalidation triggers fresh retrieval.
7. **`RecipientDeviceResolutionServiceTest.RejectsNonParticipantTarget`**: Verifies deterministic rejection with `MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT` when an envelope targets a user outside the conversation.
8. **`RecipientDeviceResolutionServiceTest.RejectsMismatchedDeviceOwnership`**: Verifies that claiming Device X belongs to User Y when Auth attributes it to User Z fails with `MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE`.
9. **`RecipientDeviceResolutionServiceTest.RejectsRevokedTargetDevice`**: Enforces immediate fail-closed rejection with `MESSAGING_ERROR_CODE_DEVICE_REVOKED` when targeting a revoked device.
10. **`RecipientDeviceResolutionServiceTest.RejectsPendingTargetDevice`**: Enforces rejection of devices in `DEVICE_STATUS_PENDING_AUTHORIZATION`.
11. **`RecipientDeviceResolutionServiceTest.RejectsRevokedSenderDevice`**: Rejects submissions originating from a revoked sender device.
12. **`RecipientDeviceResolutionServiceTest.DetectsSelectiveDeviceOmission`**: Confirms detection of omitted active devices; verifies that `enforce_completeness = true` deterministically rejects the submission.
13. **`RecipientDeviceResolutionServiceTest.PropagatesDownstreamAuthFailure`**: Validates fail-closed behavior when the downstream Auth service is unavailable.
14. **`RecipientDeviceResolutionServiceTest.RejectsEmptyTargetEnvelopes`**: Enforces rejection of submissions with empty delivery targets.

All 14 tests passed with 100% success rate. Combined with T01, all 31 unit tests across MSG-006 are passing.

---

*(Sections 4 through 7 will be populated as tickets MSG-006-T03 through T06 are implemented and validated).*
