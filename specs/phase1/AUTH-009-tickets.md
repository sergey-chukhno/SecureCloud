# Specification & Ticket Decomposition: Card AUTH-009

**Card ID:** `AUTH-009`  
**Card Title:** Implement Prekey Management  
**Phase:** Phase 1 — Authentication, Session Lifecycle, Multi-Factor Authentication & Cryptographic Identity  
**Dependencies:** `AUTH-008` (Public Cryptographic Identity & Directory)  
**Status:** PROPOSED & READY FOR IMPLEMENTATION  

---

## 1. Executive Summary & Goal

### Goal
Provide the authoritative public prekey inventory management, monitoring, and consumption infrastructure required for asynchronous End-to-End Encrypted (E2EE) session establishment (Signal X3DH / PQXDH).

### Scope
- **Signed Prekey Lifecycle:** Cryptographic verification, maximum age tracking, and rotation policies.
- **One-Time Prekey (OTK) Inventory:** Batch registration, validation, duplicate prevention, and inventory threshold monitoring.
- **Retrieval & Consumption Semantics:** Atomic single-use claiming semantics with concurrency guarantees.
- **Replenishment & Pool Sizing:** Secure device-authorized pool replenishment.
- **Explicit Exhaustion Handling:** Concrete exhaustion reporting, low-inventory threshold alerting (`LOW_INVENTORY`, `EXHAUSTED`), and non-silent degradation policies.
- **Device Revocation Interaction:** Revoked devices strictly prohibited from publishing, rotating, or consuming prekeys.

### Acceptance Criteria
1. **A client can publish its public prekeys:** Device publishes signed prekeys with valid Ed25519 signatures and batches of X25519 one-time prekeys.
2. **One-time prekeys cannot be consumed twice:** Strict single-use guarantee; status transitions to `Claimed`.
3. **Concurrent consumption is safe:** High-concurrency race-free claiming via PostgreSQL row locking (`FOR UPDATE SKIP LOCKED`).
4. **Revoked devices cannot publish/use future prekeys:** Revocation immediately rejects any upload, rotation, or claim operations with `PERMISSION_DENIED` or `DEVICE_REVOKED`.
5. **Private key material never reaches the backend:** Zero Private Key Invariant maintained across all APIs and persistence layers.
6. **Exhaustion is handled explicitly rather than silently falling back to insecure behavior:** System monitors thresholds, emits warning audit events, and reports explicit exhaustion status in API payloads.
7. **Tests cover concurrent consumption and exhaustion:** Multi-threaded integration tests verify zero duplicate claims under heavy concurrent load and deterministic behavior upon pool depletion.

### Out of Scope
- Implementing the client-side cryptographic ratchet (PQXDH / Double Ratchet session state machine) — this card provides the public backend key inventory required by clients.

---

## 2. Architecture & Delta Analysis (Building on AUTH-008)

### What is ALREADY Implemented (Do NOT Re-Implement):
1. **Persistence & Schema:**
   - Table `device_public_keys` with columns: `key_id`, `device_id`, `key_type` (`IDENTITY_SIGNING`, `SIGNED_PREKEY`, `ONE_TIME_PREKEY`), `public_key`, `key_status` (`Active`, `Claimed`, `Replaced`, `Revoked`), `signature`, and timestamps.
   - Partial index `idx_device_public_keys_active_otk` on `(device_id, created_at ASC) WHERE key_type = 'ONE_TIME_PREKEY' AND key_status = 'Active'`.
   - Migration `V4__create_device_prekey_bundles.sql`.
2. **Repository Baseline:**
   - `PostgresDevicePublicKeyRepository` methods: `claim_one_time_prekey`, `count_active_one_time_prekeys`, `store_one_time_prekeys`, `replace_key`, `revoke_all_device_keys`.
3. **Core Crypto Verifiers:**
   - `KeyFingerprint`: Canonical SHA-256 fingerprint generation.
   - `PrekeySignatureVerifier`: OpenSSL EVP-based Ed25519 signature verification over X25519 prekey bytes.
4. **Baseline Directory & Gateway:**
   - `CryptoDirectoryManager::get_device_crypto_directory` and `update_crypto_prekeys`.
   - Gateway routes: `GET /api/v1/users/:user_id/devices/crypto-directory`, `GET /api/v1/devices/:device_id/crypto-identity`, `POST /api/v1/devices/:device_id/prekeys`.

### What is MISSING & Targeted by AUTH-009:
1. **Dedicated Prekey Inventory Domain Abstraction (`PrekeyManager`):**
   - Decouple inventory management from general directory discovery.
   - Introduce `PrekeyInventoryStatus` tracking: `active_count`, `claimed_count`, `is_low_inventory` (threshold $\le 20$), `is_exhausted`, `signed_prekey_age_seconds`, `signed_prekey_needs_rotation` ($> 7$ days).
2. **Explicit Inventory Query & Low-Stock Alerting:**
   - Devices need an authoritative endpoint to query their own inventory health and know when to replenish: `GetPrekeyInventoryStatus` (`GET /api/v1/devices/:device_id/prekeys/inventory`).
   - Audit event emission for inventory thresholds: `AuditEvent::prekey_inventory_low` and `AuditEvent::prekey_inventory_exhausted`.
3. **Batch Prekey Validation & Strict Key Hygiene:**
   - Validate incoming OTKs: exactly 32 bytes, not all zeros, unique within the batch, no duplicates against currently active keys.
   - Reject batches exceeding max batch size (100) or containing duplicate keys.
4. **Single-Device Prekey Claiming RPC (`ClaimPrekeyBundle`):**
   - Provide a dedicated single-device claim RPC returning explicit exhaustion state metadata (`INVENTORY_HEALTHY`, `INVENTORY_LOW`, `INVENTORY_EXHAUSTED`).
5. **High-Concurrency Stress & Exhaustion Test Suite:**
   - 50+ concurrent worker threads racing to claim keys from a finite pool to prove zero duplicate keys under stress.
   - Concurrency tests verifying simultaneous claims and replenishments without deadlock.

---

## 3. Ticket Breakdown & Implementation Plan

```text
AUTH-009-T01 (Domain Entities, Inventory Status Models & Batch Key Validators)
     │
     ▼
AUTH-009-T02 (Authoritative Prekey Management Service Engine - PrekeyManager)
     │
     ▼
AUTH-009-T03 (Protobuf Contracts & AuthService gRPC Handler Implementations)
     │
     ▼
AUTH-009-T04 (API Gateway Perimeter Routing, Inventory Policy & Handler)
     │
     ▼
AUTH-009-T05 (Production Daemon Wiring, Live PostgreSQL 17 Concurrency Suite & Card Validation Report)
```

---

### Ticket AUTH-009-T01: Domain Entities, Inventory Status Models & Batch Key Validators

- **Focus**: Define domain models for inventory health, exhaustion states, batch validation logic, and repository count helpers.
- **Components to Implement**:
  - **Domain Entities** ([`src/auth/domain/entities.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/entities.hpp)):
    - Add `PrekeyInventoryStatus`:
      ```cpp
      struct PrekeyInventoryStatus {
          Uuid device_id{};
          int32_t active_one_time_prekeys{0};
          int32_t claimed_one_time_prekeys{0};
          int32_t low_inventory_threshold{20};
          bool is_low_inventory{false};
          bool is_exhausted{false};
          time_point signed_prekey_created_at{};
          int64_t signed_prekey_age_seconds{0};
          bool signed_prekey_needs_rotation{false};
      };
      ```
    - Add `PrekeyExhaustionState` enum in [`src/auth/domain/enums.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/enums.hpp):
      ```cpp
      enum class PrekeyExhaustionState {
          InventoryHealthy,
          InventoryLow,
          InventoryExhausted,
      };
      ```
  - **Batch Prekey Validator Utility** ([`src/auth/crypto/prekey_validator.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/prekey_validator.hpp)):
    - Validates prekey collections:
      * Every key must be exactly 32 bytes.
      * No all-zero keys ($0x00 \times 32$) or trivial invalid points.
      * No intra-batch duplicates (each key in batch must be unique).
      * Enforces minimum (1) and maximum (100) batch sizes.
  - **Repository Enhancements** ([`src/auth/repository/device_public_key_repository.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.hpp)):
    - `count_claimed_one_time_prekeys(device_id)`: Counts historical claimed keys for inventory analytics.
    - `has_active_key_conflict(device_id, public_key_bytes)`: Guards against duplicate prekey reuse.
- **Testing**:
  - Unit tests in `tests/unit/auth/prekey_validator_test.cpp`:
    - Validates valid batches of X25519 keys.
    - Rejects invalid key sizes, all-zero keys, intra-batch duplicates, and oversized batches (> 100).
  - Unit tests in `tests/unit/auth/device_public_key_repository_test.cpp`:
    - Validates claimed key count tracking.

---

### Ticket AUTH-009-T02: Authoritative Prekey Management Service Engine (`PrekeyManager`)

- **Focus**: Implement the core service orchestrating inventory monitoring, single-device claiming, threshold alerting, and replenishment validation.
- **Components to Implement**:
  - **Service Interface** ([`src/auth/service/prekey_manager.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/prekey_manager.hpp)):
    - `get_inventory_status(device_id) -> PrekeyInventoryStatusResult`
    - `claim_device_prekey_bundle(device_id) -> ClaimPrekeyBundleResult`
    - `replenish_one_time_prekeys(caller_user_id, caller_device_id, target_device_id, new_otks, client_ip) -> ReplenishPrekeysResult`
    - `rotate_signed_prekey(caller_user_id, caller_device_id, target_device_id, new_spk, new_sig, client_ip) -> RotatePrekeyResult`
  - **Service Implementation** ([`src/auth/service/prekey_manager.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/prekey_manager.cpp)):
    - **Inventory Status Calculation**:
      * Queries active OTK count and claimed OTK count.
      * Evaluates `is_low_inventory = (active_count <= low_inventory_threshold)`.
      * Evaluates `is_exhausted = (active_count == 0)`.
      * Queries active signed prekey timestamp; evaluates `signed_prekey_needs_rotation = (age > 7 days)`.
    - **Threshold Alerting & Audit Events**:
      * Emits `AuditEvent::prekey_inventory_low` when count drops below threshold.
      * Emits `AuditEvent::prekey_inventory_exhausted` when pool reaches 0.
    - **Single-Device Bundle Claiming**:
      * Verifies device is `Active`. If `Revoked`, fails immediately.
      * Fetches identity key, computes fingerprint, fetches signed prekey and signature.
      * Atomically claims 1 OTK via `claim_one_time_prekey`.
      * Attaches explicit `PrekeyExhaustionState`.
    - **Revocation Enforcement**:
      * Any attempt to replenish or claim for a revoked device strictly returns `DeviceRevoked` or `PermissionDenied`.
- **Testing**:
  - Unit tests in `tests/unit/auth/prekey_manager_test.cpp`:
    - Inventory status evaluation and threshold detection.
    - Single-device bundle claiming with explicit exhaustion states.
    - Strict rejection of revoked devices.
    - Batch replenishment with validator enforcement.

---

### Ticket AUTH-009-T03: Protocol Buffer Contracts & AuthService gRPC Handler Implementations

- **Focus**: Protobuf contract definitions, wire structures, and production gRPC handler implementation in `AuthServiceImpl`.
- **Components to Implement**:
  - **Protobuf Updates** ([`proto/securecloud/auth/v1/auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto)):
    - Add `PrekeyExhaustionState` enum:
      ```protobuf
      enum PrekeyExhaustionState {
          PREKEY_EXHAUSTION_STATE_UNSPECIFIED = 0;
          PREKEY_EXHAUSTION_STATE_HEALTHY = 1;
          PREKEY_EXHAUSTION_STATE_LOW = 2;
          PREKEY_EXHAUSTION_STATE_EXHAUSTED = 3;
      }
      ```
    - Add `GetPrekeyInventoryStatusRequest` & `GetPrekeyInventoryStatusResponse`:
      ```protobuf
      message GetPrekeyInventoryStatusRequest {
          string device_id = 1;
      }

      message GetPrekeyInventoryStatusResponse {
          string device_id = 1;
          int32 active_one_time_prekeys = 2;
          int32 claimed_one_time_prekeys = 3;
          int32 low_inventory_threshold = 4;
          bool is_low_inventory = 5;
          bool is_exhausted = 6;
          int64 signed_prekey_created_at_epoch_ms = 7;
          int64 signed_prekey_age_seconds = 8;
          bool signed_prekey_needs_rotation = 9;
      }
      ```
    - Add `ClaimPrekeyBundleRequest` & `ClaimPrekeyBundleResponse`:
      ```protobuf
      message ClaimPrekeyBundleRequest {
          string device_id = 1;
      }

      message ClaimPrekeyBundleResponse {
          DeviceCryptoRecord bundle = 1;
          PrekeyExhaustionState exhaustion_state = 2;
      }
      ```
  - **Service RPC Implementations** ([`src/auth/service/auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp)):
    - Implement `GetPrekeyInventoryStatus` and `ClaimPrekeyBundle` handlers in `AuthServiceImpl`.
    - Extract and enforce caller authentication.
- **Testing**:
  - Unit tests in `tests/unit/auth/auth_service_prekey_test.cpp`:
    - Full coverage of `GetPrekeyInventoryStatus` and `ClaimPrekeyBundle`.
    - Verification of error translation (`UNAUTHENTICATED`, `NOT_FOUND`, `PERMISSION_DENIED`).

---

### Ticket AUTH-009-T04: API Gateway Perimeter Routing, Inventory Policy & Handler Integration

- **Focus**: Gateway perimeter routing, route authorization policy, and reverse proxy forwarding for prekey inventory endpoints.
- **Components to Implement**:
  - **Gateway Security Policy** ([`src/gateway/http/auth/gateway_security_policy.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.cpp)):
    - Register new routes:
      * `GET /api/v1/devices/:device_id/prekeys/inventory` $\to$ `RouteAccess::Protected` (`min_auth_level = PRIMARY`).
      * `POST /api/v1/devices/:device_id/prekeys/claim` $\to$ `RouteAccess::Protected` (`min_auth_level = PRIMARY`).
  - **Gateway Client & Proxy Handlers** ([`src/gateway/http/proxy/auth_proxy_handler.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.cpp)):
    - Implement `handle_get_prekey_inventory` and `handle_claim_device_prekey`.
    - Enforce device ownership on inventory query (`ctx.device_id() == path_device_id`).
    - Bulkhead permit acquisition, circuit breaker accounting, and RFC 7807 error formatting.
- **Testing**:
  - Unit tests in `tests/unit/gateway/gateway_prekey_inventory_policy_test.cpp`:
    - Verify perimeter policy evaluates inventory routes as protected.
    - Unauthenticated requests rejected with 401.
    - Device mismatch rejected with 403 `DEVICE_MISMATCH`.

---

### Ticket AUTH-009-T05: Production Daemon Wiring, Live PostgreSQL 17 Concurrency Suite & Card Validation Report

- **Focus**: Wire `PrekeyManager` into `src/auth/main.cpp`, author live PostgreSQL 17 multi-threaded stress suite testing concurrent consumption and exhaustion, and author comprehensive validation report.
- **Components to Implement**:
  - **Production Daemon Wiring** ([`src/auth/main.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/main.cpp)):
    - Instantiate `PrekeyManager` with `device_repo`, `public_key_repo`, and `audit_publisher`.
    - Inject `prekey_manager` into `AuthServiceImpl`.
  - **Live Concurrency & Stress Integration Suite** ([`tests/integration/auth_prekey_concurrency_integration_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/auth_prekey_concurrency_integration_test.cpp)):
    - Target registered in [`tests/integration/CMakeLists.txt`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/CMakeLists.txt).
    - Executed against PostgreSQL 17 on port 5433 with strict port 5432 preflight protection:
      1. **Strict Port 5432 Protection Preflight**.
      2. **Heavy Multi-Threaded Concurrent Consumption Race**: 50 concurrent client threads simultaneously claim OTKs from a device with 50 OTKs. Assert that exactly 50 distinct keys are dispensed, zero duplicate keys returned, and final active count is 0.
      3. **Concurrent Claim vs. Replenishment Race**: Worker threads continuously claiming while device thread replenishes new batches of OTKs simultaneously; assert zero deadlocks, zero lost updates.
      4. **Deterministic Pool Depletion & Explicit Exhaustion**: Test claims past exhaustion; assert `PrekeyExhaustionState::InventoryExhausted` reported explicitly, audit event emitted, and system does not crash or fail closed silently.
      5. **Revoked Device Immediate Prohibition**: Revoked device immediately rejected from claiming or replenishment under concurrent traffic.
      6. **Inventory Health & Age Metrics**: Validate accurate calculation of active counts, claimed counts, and signed prekey age across database reconnects.
  - **Comprehensive Card Validation Report** (`walkthrough-auth-009.md`):
    - Author exhaustive validation report documenting concurrency proofs, database query plans, exhaustion semantics, traceability matrix, and full test logs.
- **Testing**:
  - Complete test suite clean execution (0 failures, 100% pass rate).
  - Clean `ninja check-format`.

---

## 4. Traceability Matrix against Acceptance Criteria

| Acceptance Criterion | Primary Implementing Ticket(s) | Verification Target |
| :--- | :--- | :--- |
| **A client can publish its public prekeys** | AUTH-009-T01, AUTH-009-T02, AUTH-009-T03 | `PrekeyValidatorTest.*`, `AuthPrekeyConcurrencyIntegrationTest.Replenishment` |
| **One-time prekeys cannot be consumed twice** | AUTH-009-T02, AUTH-009-T05 | `AuthPrekeyConcurrencyIntegrationTest.HeavyConcurrentConsumptionRace` |
| **Concurrent consumption is safe** | AUTH-009-T02, AUTH-009-T05 | `AuthPrekeyConcurrencyIntegrationTest.HeavyConcurrentConsumptionRace` |
| **Revoked devices cannot publish/use future prekeys** | AUTH-009-T02, AUTH-009-T04, AUTH-009-T05 | `PrekeyManagerTest.RevokedDeviceRejection`, `RevokedDeviceImmediateProhibition` |
| **Private key material never reaches the backend** | AUTH-009-T01, AUTH-009-T03, AUTH-009-T04 | Protobuf contract audit, Architectural Invariant |
| **Exhaustion is handled explicitly rather than silently falling back to insecure behavior** | AUTH-009-T01, AUTH-009-T02, AUTH-009-T05 | `DeterministicPoolDepletionAndExplicitExhaustion`, Audit Event asserts |
| **Tests cover concurrent consumption and exhaustion** | AUTH-009-T05 | `securecloud_auth_prekey_concurrency_integration_test` (50 threads) |

---

## 5. Architectural Invariants & Security Defenses

1. **Zero Private Key Ingress:** Backend handles exclusively 32-byte public keys and 64-byte Ed25519 signatures.
2. **Pessimistic Skip-Locked Concurrency:** `SELECT ... FOR UPDATE SKIP LOCKED` guarantees $O(1)$ single-use key claiming without lock contention or deadlocks.
3. **Explicit Exhaustion Visibility:** Clients receive deterministic exhaustion state flags (`INVENTORY_EXHAUSTED`) allowing client-side policy decisions rather than opaque silent fallbacks.
4. **Environment Isolation:** Containerized PostgreSQL 17 on port 5433 with strict port 5432 prohibition.
