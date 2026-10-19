# AUTH-008 — Implement Public Cryptographic Identity & Directory
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-008  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Proposed Implementation-Ready Technical Specification  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Sergey  
**Date**: 2026-10-08  

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-008** provides the authoritative backend directory of public device cryptographic information required to establish asynchronous end-to-end (E2E) encrypted messaging and file-sharing sessions across the SecureCloud platform.

Building directly upon:
- Primary credential verification and Argon2id password hashing (**AUTH-003**),
- Multi-device stateful sessions (**AUTH-004**),
- Asymmetric Ed25519 token signatures and local Gateway verification (**AUTH-005**),
- Multi-factor authentication with sensitive assurance elevation (**AUTH-006**),
- Device lifecycle state machine (`PendingAuthorization` $\to$ `Active` $\to$ `Revoked`) and strong pairing (**AUTH-007**),

this card fulfills the cryptographic directory layer defined in **ADR-008** (*Security & Cryptographic Architecture*), resolving how devices discover each other's cryptographic endpoints without compromising end-to-end secrecy.

### Core Architectural Invariants

1. **Zero Private Key Invariant**:
   - The backend stores **exclusively public cryptographic material** (Ed25519 identity public keys, X25519 signed prekeys, prekey signatures, and X25519 one-time prekeys).
   - Under no circumstances does a private cryptographic key enter the Auth microservice or cross the network boundary.
2. **Authoritative Directory for E2E Session Establishment**:
   - In accordance with ADR-008 and Signal-style asynchronous key agreement (X3DH / PQXDH design principles), initiating endpoints must discover public prekey bundles for all approved recipient devices of a user.
   - For multi-device users (e.g. Bob having Phone, Laptop, and Tablet), the directory supplies active public bundles for all active devices so Alice can fan out encrypted messages.
3. **Correct Representation of Revoked & Pending Devices**:
   - Revoked devices (`DeviceStatus::Revoked`) must be omitted from active recipient directory queries to prevent future messages from being encrypted for compromised endpoints (ADR-008 §16).
   - Direct queries for a specific revoked device explicitly reflect its `Revoked` status, preventing stale cached trust.
   - Pending devices (`DeviceStatus::PendingAuthorization`) cannot distribute keys until authorized.
4. **Detectable Key Changes & Fingerprinting**:
   - Every public key identity exposes a canonical cryptographic fingerprint (SHA-256 digest of the 32-byte Ed25519 identity key).
   - Public keys and signed prekeys include timestamps and version IDs, enabling clients to detect unexpected key rotations, identity substitutions, or potential MITM attempts.
5. **Atomic One-Time Prekey (OTK) Claiming**:
   - To maintain cryptographic forward secrecy, each one-time prekey bundle returned by the directory is claimed single-use. Concurrent claiming of the same OTK is prevented via atomic database selection.
   - If OTKs are depleted, the directory gracefully returns the signed prekey bundle while signaling low OTK reserves, allowing the recipient device to replenish its pool.
6. **Authorization & Cryptographic Proof for Key Management**:
   - Only the authenticated owner of the device (`caller_user_id == dev.user_id && caller_device_id == dev.device_id`) can rotate signed prekeys or upload new OTKs.
   - When rotating a signed prekey, the caller must present a valid cryptographic signature verified against the device's registered Ed25519 Identity Key.
7. **Strict Database Port Isolation**:
   - Preflight port 5432 isolation continues to be enforced (`PortForbiddenException`); integration tests run against PostgreSQL 17 on port 5433.

---

### E2E Cryptographic Directory Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                           API Gateway (Perimeter)                           │
 │                                                                             │
 │  1. Public Prekey Directory Discovery (Alice querying Bob's devices)        │
 │     GET /api/v1/users/:user_id/devices/crypto-directory                     │
 │     - RouteAccess::Protected (Requires valid Bearer token)                 │
 │     - Proxies to Auth gRPC: GetDeviceCryptoDirectory                        │
 │                                                                             │
 │  2. Specific Device Identity Query                                          │
 │     GET /api/v1/devices/:device_id/crypto-identity                          │
 │     - RouteAccess::Protected                                                │
 │     - Proxies to Auth gRPC: GetCryptoIdentity                               │
 │                                                                             │
 │  3. Device Prekey Pool Replenishment & Signed Prekey Rotation               │
 │     POST /api/v1/devices/:device_id/prekeys                                 │
 │     - RouteAccess::Protected (Enforces device ownership claims)             │
 │     - Proxies to Auth gRPC: UpdateCryptoPrekeys                             │
 └─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼ (gRPC over mTLS)
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                        Auth Microservice (Authority)                        │
 │                                                                             │
 │  CryptoDirectoryManager                                                     │
 │  ├── GetDeviceCryptoDirectory(user_id, optional device_ids)                 │
 │  │   - Filters devices: device_status == 'Active'                           │
 │  │   - Fetches Identity Public Key (Ed25519) + Fingerprint                  │
 │  │   - Fetches Active Signed Prekey (X25519) + Signature                    │
 │  │   - Atomically claims 1 One-Time Prekey (X25519) per active device       │
 │  │   - Excludes Revoked & Pending devices                                  │
 │  │                                                                          │
 │  ├── GetCryptoIdentity(device_id)                                           │
 │  │   - Returns device crypto record with explicit DeviceStatus              │
 │  │   - If Revoked: returns status=Revoked, omitting active prekeys          │
 │  │                                                                          │
 │  └── UpdateCryptoPrekeys(user_id, device_id, signed_prekey, sig, otks)      │
 │      - Enforces caller authorization (caller owns device_id)                │
 │      - If signed_prekey present: VERIFIES signature using identity_key      │
 │      - Atomically replaces old signed prekey (marks status = 'Replaced')    │
 │      - Inserts batch of new One-Time Prekeys (up to 100)                    │
 │      - Emits AuditEvent::PrekeysUpdated                                     │
 └─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼ (PostgreSQL 17 on Port 5433)
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                                PostgreSQL 17                                │
 │                                                                             │
 │  - devices: status, timestamps, user_id                                     │
 │  - device_public_keys: key_id, device_id, key_type, public_key,             │
 │                        key_status (Active/Replaced/Revoked/Claimed),        │
 │                        created_at, replaced_by_key_id                       │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Existing Foundations (Reused Without Duplication)

The following components and infrastructure already exist in the codebase and will be leveraged directly:

1. **Database Tables & Repositories**:
   - `devices` & `device_public_keys` tables in [`src/auth/db/migrations/V002__create_auth_tables.sql`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/db/migrations/V002__create_auth_tables.sql).
   - [`IDeviceRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_repository.hpp) & [`PostgresDeviceRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_repository.cpp): `find_by_id`, `list_active_by_user_id`, `list_all_by_user_id`.
   - [`IDevicePublicKeyRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.hpp) & [`PostgresDevicePublicKeyRepository`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.cpp): `store_public_key`, `find_by_id`, `list_active_keys_by_device_id`, `replace_key`, `revoke_all_device_keys`.
2. **Cryptographic Key Format Validation**:
   - [`src/auth/crypto/key_validator.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/key_validator.hpp): Validates 32-byte Ed25519 public keys, 32-byte X25519 prekeys, 64-byte signatures, and bounds OTKs to 100.
3. **Existing gRPC Protocol Contracts**:
   - [`proto/securecloud/auth/v1/auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto): Defines `DeviceCryptoRecord`, `GetDeviceCryptoDirectory`, `GetCryptoIdentity`, and `UpdateCryptoPrekeys` (currently returning `UNIMPLEMENTED`).
4. **Gateway gRPC Client Interface**:
   - [`src/gateway/grpc/auth_service_client.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/auth_service_client.hpp): Already defines stubs for `get_crypto_identity` and `get_device_crypto_directory`.
5. **Auditing & Event Publishing**:
   - [`AuditEventPublisher`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/audit/audit_event_publisher.hpp): For emitting cryptographic directory and prekey rotation events.

---

## 3. Detailed Ticket Breakdown

### Ticket AUTH-008-T01: Cryptographic Domain Entities, Key Fingerprinting & Prekey Repository Extensions

- **Focus**: Key models, key fingerprint calculations, atomic single-use OTK consumption, and database repository extensions.
- **Components to Implement**:
  - **Key Fingerprint Computation** ([`src/auth/crypto/key_fingerprint.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/key_fingerprint.hpp)):
    - Computes canonical SHA-256 digest of 32-byte Ed25519 identity key using OpenSSL `EVP_DigestInit_ex`/`EVP_DigestUpdate`.
    - Formats fingerprint into standard colon-delimited hex string (e.g. `SHA256:7a:3f:...`) or base64 representation.
    - Utility to detect identity changes and compare fingerprints.
  - **Signature Verifier Utility** ([`src/auth/crypto/prekey_signature_verifier.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/prekey_signature_verifier.hpp)):
    - Verifies Ed25519 signature over X25519 Signed Prekey bytes using public identity key via OpenSSL `EVP_PKEY_verify`.
    - Ensures newly rotated signed prekeys are cryptographically authentic before persisting.
  - **Domain Entities & Enum Updates** ([`src/auth/domain/enums.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/enums.hpp), [`entities.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/entities.hpp)):
    - Extend `KeyStatus`: add `Claimed` (`"Claimed"` / `"CLAIMED"`) for consumed one-time prekeys.
    - Define domain model `PrekeyBundle` containing identity key, fingerprint, signed prekey, signature, optional claimed OTK, timestamps, and active status.
  - **Repository Extensions** ([`src/auth/repository/device_public_key_repository.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.hpp), [`.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.cpp)):
    - `claim_one_time_prekey(device_id, tx)`: Atomically selects 1 active OTK using `SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1`, updates its status to `'Claimed'`, and returns it. Returns `nullopt` if none remain.
    - `count_active_one_time_prekeys(device_id, tx)`: Returns count of remaining active OTKs.
    - `find_active_identity_key(device_id, tx)`: Retrieves the active Ed25519 identity signing key.
    - `find_active_signed_prekey(device_id, tx)`: Retrieves the active X25519 signed prekey.
    - `store_one_time_prekeys(device_id, keys, tx)`: Batch inserts newly uploaded one-time prekeys.
- **Testing**:
  - Unit tests in `tests/unit/auth/key_fingerprint_test.cpp`:
    - SHA-256 fingerprint generation matches known test vectors.
    - Ed25519 prekey signature verification accepts valid signatures and rejects invalid/tampered signatures.
  - Unit tests in `tests/unit/auth/device_public_key_repository_test.cpp`:
    - Single-use OTK claiming transitions state to `Claimed`.
    - Successive claims exhaust the OTK pool cleanly without race conditions.
    - Batch OTK storage and counting.

---

### Ticket AUTH-008-T02: Cryptographic Directory Manager (`CryptoDirectoryManager`)

- **Focus**: Authoritative service engine orchestrating public prekey directory lookups, multi-device bundle assembly, and prekey rotation.
- **Components to Implement**:
  - **Service Interface** ([`src/auth/service/crypto_directory_manager.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/crypto_directory_manager.hpp)):
    - `get_crypto_identity(device_id) -> CryptoIdentityResult`
    - `get_device_crypto_directory(user_id, optional device_ids) -> DeviceCryptoDirectoryResult`
    - `update_crypto_prekeys(caller_user_id, caller_device_id, target_device_id, signed_prekey_opt, signature_opt, new_otks) -> UpdatePrekeysResult`
  - **Concrete Service Implementation** ([`src/auth/service/crypto_directory_manager.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/crypto_directory_manager.cpp)):
    - **Single Device Identity Lookup (`get_crypto_identity`)**:
      * Queries device status via `IDeviceRepository`.
      * If device is non-existent: returns not found error.
      * If device is `Revoked`: returns result with `status = Revoked`, omitting active prekeys so callers know never to encrypt for it.
      * If device is `Active`: gathers identity key, calculates fingerprint, fetches active signed prekey and signature.
    - **Recipient Directory Discovery (`get_device_crypto_directory`)**:
      * Fetches active devices for `user_id` via `device_repo_->list_active_by_user_id(user_id)`.
      * Filters by `device_ids` if explicitly requested.
      * Strictly excludes `Revoked` or `PendingAuthorization` devices.
      * For each active device: builds bundle with identity key, fingerprint, signed prekey, signature, and atomically claims 1 OTK via `claim_one_time_prekey`.
      * Reports remaining OTK count.
    - **Prekey Pool Replenishment & Rotation (`update_crypto_prekeys`)**:
      * **Authorization Invariant**: Verifies `caller_user_id == dev.user_id` and `caller_device_id == target_device_id`. If mismatched, fails with `PERMISSION_DENIED`.
      * If signed prekey provided: validates format, verifies Ed25519 signature against stored identity key; rotates signed prekey via `replace_key`.
      * If new OTKs provided: validates each key (32 bytes X25519, max 100); batch inserts into database.
      * Emits audit events (`AuditEvent::prekeys_updated`, `AuditEvent::signed_prekey_rotated`).
- **Testing**:
  - Unit tests in `tests/unit/auth/crypto_directory_manager_test.cpp`:
    - Multi-device prekey bundle assembly with OTK claiming.
    - Handling depleted OTKs (falls back gracefully to signed prekey only).
    - Revoked devices omitted from directory queries and flagged correctly in identity queries.
    - Signed prekey rotation with valid cryptographic signature.
    - Rejection of invalid signature or mismatched caller authorization.

---

### Ticket AUTH-008-T03: Protocol Buffer Updates & AuthService gRPC Handler Implementation

- **Focus**: Refined protobuf wire messages, gRPC method implementations in `AuthServiceImpl`, and unit test verification.
- **Components to Implement**:
  - **Protobuf Updates** ([`proto/securecloud/auth/v1/auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto)):
    - Enhance `DeviceCryptoRecord`:
      ```protobuf
      message DeviceCryptoRecord {
          string device_id = 1;
          bytes identity_key = 2;
          bytes signed_prekey = 3;
          bytes signed_prekey_signature = 4;
          bytes one_time_prekey = 5;
          string one_time_prekey_id = 6;
          DeviceStatus status = 7;
          string identity_key_fingerprint = 8;
          int64 signed_prekey_created_at_epoch_ms = 9;
          int32 remaining_one_time_prekeys = 10;
      }
      ```
    - Enhance `GetCryptoIdentityResponse`:
      ```protobuf
      message GetCryptoIdentityResponse {
          string device_id = 1;
          string user_id = 2;
          bytes identity_key = 3;
          bytes signed_prekey = 4;
          bytes signed_prekey_signature = 5;
          DeviceStatus status = 6;
          string identity_key_fingerprint = 7;
          int64 signed_prekey_created_at_epoch_ms = 8;
      }
      ```
  - **Service RPC Implementations** ([`src/auth/service/auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp)):
    - Replace `IMPLEMENT_UNIMPLEMENTED_RPC` macros with production handlers:
      1. `GetDeviceCryptoDirectory`: Dispatches to `CryptoDirectoryManager::get_device_crypto_directory`. Handles empty lists, user validation, and error translation.
      2. `GetCryptoIdentity`: Dispatches to `CryptoDirectoryManager::get_crypto_identity`. Returns device crypto profile or `NOT_FOUND` / `Revoked` status.
      3. `UpdateCryptoPrekeys`: Extracts caller identity (`x-user-id`, `x-device-id`) from metadata, enforces ownership, delegates to `CryptoDirectoryManager::update_crypto_prekeys`.
- **Testing**:
  - Unit tests in `tests/unit/auth/auth_service_crypto_test.cpp`:
    - Full coverage of all 3 RPCs with mock managers.
    - Parameter validation (empty IDs, malformed UUIDs, invalid key lengths).
    - Unauthenticated / unauthorized caller handling (`UNAUTHENTICATED` vs `PERMISSION_DENIED`).

---

### Ticket AUTH-008-T04: Gateway Perimeter Integration, Route Registration & Forwarding

- **Focus**: API Gateway perimeter authorization policy, route access classification, metadata extraction, and error translation.
- **Components to Implement**:
  - **Gateway Security Policy** ([`src/gateway/http/auth/gateway_security_policy.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.cpp)):
    - Register crypto directory routes:
      * `GET /api/v1/users/:user_id/devices/crypto-directory` $\to$ `RouteAccess::Protected` (`min_auth_level = PRIMARY`).
      * `GET /api/v1/devices/:device_id/crypto-identity` $\to$ `RouteAccess::Protected` (`min_auth_level = PRIMARY`).
      * `POST /api/v1/devices/:device_id/prekeys` $\to$ `RouteAccess::Protected` (`min_auth_level = PRIMARY`).
  - **Gateway Client & Proxy Handlers** ([`src/gateway/grpc/auth_service_client.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/auth_service_client.cpp), [`src/gateway/http/controllers/`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/)):
    - Implement `update_crypto_prekeys` in `AuthServiceClient`.
    - Propagate caller metadata (`x-user-id`, `x-device-id`, `x-auth-level`) downstream.
    - Translate gRPC errors to RFC 7807 problem details (e.g. `NOT_FOUND` $\to$ 404, `PERMISSION_DENIED` $\to$ 403).
- **Testing**:
  - Unit tests in `tests/unit/gateway/gateway_crypto_directory_policy_test.cpp`:
    - Unauthenticated requests rejected with HTTP 401.
    - Authenticated requests authorized and metadata injected.
    - Device ownership mismatch rejected at perimeter or downstream with 403 Forbidden.

---

### Ticket AUTH-008-T05: Production Daemon Wiring, Live PostgreSQL 17 E2E Integration Suite & Card Validation Report

- **Focus**: Wire `CryptoDirectoryManager` into `src/auth/main.cpp`, author live integration test suite against containerized PostgreSQL 17 on port 5433, and create comprehensive card validation report.
- **Components to Implement**:
  - **Production Daemon Wiring** ([`src/auth/main.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/main.cpp)):
    - Instantiate `CryptoDirectoryManager` with `device_repo`, `public_key_repo`, and `audit_publisher`.
    - Inject `crypto_directory_manager` into `AuthServiceImpl`.
  - **Live Integration Test Suite** ([`tests/integration/auth_crypto_identity_integration_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/auth_crypto_identity_integration_test.cpp)):
    - Registered target in [`tests/integration/CMakeLists.txt`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/CMakeLists.txt).
    - Live scenarios executed against PostgreSQL 17 on port 5433:
      1. **Strict Port 5432 Preflight Protection**: Immediate `PortForbiddenException` on host port.
      2. **Full Multi-Device Prekey Directory Discovery**: User with 3 devices; queries directory; verifies all 3 active bundles returned with valid public keys and fingerprints.
      3. **Single-Use OTK Claiming & Depletion Fallback**: Successive directory calls claim unique OTKs; when pool exhausts, directory gracefully returns signed prekey only with count 0.
      4. **Revoked Device Handling**: Revoked device is omitted from multi-device directory; direct query returns `DeviceStatus::Revoked`.
      5. **Signed Prekey Rotation with Cryptographic Signature Verification**: Generates new X25519 prekey, signs with Ed25519 identity key, verifies rotation succeeds. Verifies tampered signature is rejected.
      6. **One-Time Prekey Replenishment**: Uploads 25 new OTKs; verifies pool restored.
      7. **Unauthorized Key Management Rejection**: Device A attempting to update Device B prekeys rejected with `PERMISSION_DENIED`.
      8. **Key Change Detectability**: Verifies client observes fingerprint and timestamp differences upon key rotation.
      9. **Durability Across Service Restart**: Public directory and prekey states survive complete Auth daemon restart.
  - **Comprehensive Card Validation Report** (`walkthrough-auth-008.md`):
    - Author exhaustive $\ge 1,000$-line validation report detailing cryptographic threat models, Signal/X3DH alignment, signature verification, traceability matrix, and full test execution evidence.
- **Testing**:
  - Verification of 0 regressions across entire test suite (`ctest -E "Integration"`).
  - Clean execution of `securecloud_auth_crypto_identity_integration_test`.

---

## 4. Work Breakdown & Ticket Sequencing

```text
AUTH-008-T01 (Domain Entities, Key Fingerprinting & Prekey Repository Extensions)
     │
     ▼
AUTH-008-T02 (Cryptographic Directory Manager Engine - CryptoDirectoryManager)
     │
     ▼
AUTH-008-T03 (Protobuf Contracts & AuthService gRPC Handler Implementations)
     │
     ▼
AUTH-008-T04 (Gateway Perimeter Integration, Route Registration & Forwarding)
     │
     ▼
AUTH-008-T05 (Production Wiring, Live E2E Integration Suite & Card Validation Report)
```

---

## 5. Traceability Matrix against Acceptance Criteria

| Acceptance Criterion | Primary Implementing Ticket(s) | Verification Target |
| :--- | :--- | :--- |
| **Backend stores only public cryptographic material** | AUTH-008-T01, AUTH-008-T02 | `key_validator_test`, database schema audit |
| **Device private keys never enter Auth** | AUTH-008-T01, AUTH-008-T03 | Protobuf contract inspection, architectural review |
| **Clients can retrieve approved public device identity information** | AUTH-008-T02, AUTH-008-T03, AUTH-008-T05 | `auth_service_crypto_test`, `FullMultiDeviceDirectoryDiscoveryE2E` |
| **Revoked devices are represented correctly** | AUTH-008-T02, AUTH-008-T03, AUTH-008-T05 | `crypto_directory_manager_test`, `RevokedDeviceHandling` |
| **Key changes are detectable by clients** | AUTH-008-T01, AUTH-008-T03, AUTH-008-T05 | `key_fingerprint_test`, `KeyChangeDetectability` |
| **Authorization protects key-management operations** | AUTH-008-T02, AUTH-008-T03, AUTH-008-T04 | `gateway_crypto_directory_policy_test`, `UnauthorizedKeyManagementRejection` |
| **Tests cover registration, retrieval, replacement, revocation, and unauthorized access** | AUTH-008-T01 through AUTH-008-T05 | Unit test suites & `auth_crypto_identity_integration_test` |

---

## 6. Technical Invariants & Security Defenses

1. **Zero Private Key Invariant**:
   - Only Ed25519 identity public keys (32 bytes), X25519 signed prekeys (32 bytes), Ed25519 signatures (64 bytes), and X25519 one-time prekeys (32 bytes) are stored. Private keys remain exclusively inside client hardware enclaves.
2. **Cryptographic Proof of Signed Prekey Ownership**:
   - Signed prekey rotation strictly verifies that `signed_prekey_signature` is a valid Ed25519 signature over the prekey bytes created by the device's registered identity key.
3. **Atomic Single-Use Prekey Claiming**:
   - `SELECT ... FOR UPDATE SKIP LOCKED` guarantees that concurrent sessions never receive duplicate one-time prekeys, preserving forward secrecy.
4. **Opaque Identifiers Across Boundaries**:
   - Services and directories communicate exclusively via opaque UUIDs (`user_id`, `device_id`), preserving human identity confidentiality per ADR-008 §7.
5. **Strict Database Port Isolation**:
   - All tests enforce preflight checks: port 5432 throws `PortForbiddenException`; integration tests connect exclusively to containerized PostgreSQL 17 on port 5433.
