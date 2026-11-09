# Pull Request: Implement Device Registration & Cryptographic Identity Lifecycle (CLIENT-005)

## Summary

This pull request implements the complete **Device Registration & Cryptographic Identity Lifecycle** for the native **SecureCloud Desktop Client** (`securecloud-client`) using **C++20**, **Qt 6 / Qt Quick (QML)**, **OpenSSL 3.x EVP**, and **CMake**, opening **Desktop Client Phase 2** as specified in milestone card **CLIENT-005**.

Card `CLIENT-005` transitions the native desktop client from mock cryptographic stubs (`StubCryptoProvider`) and simulated placeholder identities to **production cryptographic identity generation, X3DH prekey publication, device registration with the backend Auth service via the Gateway, secure private key handling, automated prekey replenishment/rotation, and Settings Trust Center integration**.

The feature branch has been validated across all 6 tickets (`CLIENT-005-T01` through `CLIENT-005-T06`), compiles cleanly with **zero warnings** under `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wnon-virtual-dtor -Wconversion`, maintains 100% style compliance via `.clang-format`, and passes **100% of the 125 automated client unit tests** (`securecloud_client_foundation_test`), the client `--smoke-test`, and **24/24 live Docker integration tests** against PostgreSQL 17 on isolated container port 5433 (strictly protecting host port 5432).

---

## Tickets Addressed

| Ticket | Description | Status | Commit |
| :--- | :--- | :--- | :--- |
| **CLIENT-005-T01** | Cryptographic Domain Models & Value Objects (`PrekeyBundle`, `OneTimePrekeyRecord`, `PrekeyInventoryStatus`, `PrekeyPolicy`) | Completed | `11266ec` |
| **CLIENT-005-T02** | OpenSSL 3.x EVP Cryptographic Provider (`OpenSslCryptoProvider`: Ed25519 identity, X25519 signed prekey, 100 OTPKs, SHA-256 fingerprinting) | Completed | `ddccf27` |
| **CLIENT-005-T03** | Secure Private Key Storage & Secret Zeroization (`DevicePrivateBundle`, `KeyStorageHelper` SCPB v1 binary format, `OPENSSL_cleanse`) | Completed | `74acdec` |
| **CLIENT-005-T04** | Gateway Client Protocol Extensions for Device & Prekeys (`register_device`, `update_crypto_prekeys`, `get_prekey_inventory_status`) | Completed | `ab7b9af` |
| **CLIENT-005-T05** | Device Lifecycle, Registration & Prekey Replenishment Pipeline (`DeviceManager`, `PrekeyLifecycleCoordinator`, 7-day rotation, low watermark) | Completed | `41800bd` |
| **CLIENT-005-T06** | Settings Trust Center ViewModel Integration & Comprehensive Test Suite (`WorkspaceViewModel` wiring, 125/125 unit tests, 1084-line report) | Completed | `de3d95f` |

---

## Architectural Highlights

### 1. Pure C++20 Cryptographic Domain Models (`CLIENT-005-T01`)
- **`PrekeyPolicy`**: Centralized policy constants defining exact cryptographic sizes (32-byte Ed25519 public/private keys, 64-byte signatures, 32-byte X25519 public/private keys) and replenishment watermarks (initial batch: 100, low threshold: 20, replenishment batch: 50, signed prekey rotation: 7 days).
- **`PrekeyBundle`**: Immutable value object aggregating Ed25519 identity key, X25519 signed prekey, 64-byte Ed25519 signature, timestamp, and collection of one-time prekeys.
- **`OneTimePrekeyRecord` & `PrekeyInventoryStatus`**: Value objects tracking ephemeral prekeys, active inventory counts, and rotation necessity.
- **`CryptoIdentity`**: Augmented with uppercase colon-separated fingerprint format validation (`SHA256:XX:XX:...`).

### 2. OpenSSL 3.x EVP Cryptographic Provider (`CLIENT-005-T02`)
- **Strictly No Hand-Rolled Cryptography**: Employs pure OpenSSL 3.x EVP primitives (`EVP_PKEY_ED25519`, `EVP_PKEY_X25519`, `EVP_DigestSign`, `EVP_DigestVerify`, `EVP_Q_digest`).
- **RFC 8032 Ed25519 Signing & Verification**: Signed prekey signatures are generated via `EVP_DigestSignInit` with `nullptr` message digest per RFC 8032 pure Ed25519, producing deterministic 64-byte signatures verified on demand.
- **Deterministic Fingerprints**: Formatted into canonical uppercase 32-hex colon-separated strings (`SHA256:XX:XX:...`) matching the backend `KeyFingerprint` format with 100% parity.

### 3. Secure Private Key Storage & Zeroization (`CLIENT-005-T03`)
- **`DevicePrivateBundle`**: Encapsulates identity private key, signed prekey private key, and OTPK private map in `SecretString`. Exposes `take_one_time_prekey` and `clear()`.
- **Memory Cleansing**: Destructors and explicit `clear()` calls invoke `OPENSSL_cleanse` over memory buffers before deallocation.
- **`KeyStorageHelper` SCPB Container**: Compact binary serialization format (`SCPB` magic bytes `0x53, 0x43, 0x50, 0x42`, version 1, length-prefixed fields) stored securely under `device.bundle.<device_id>`.

### 4. Gateway Protocol Extensions (`CLIENT-005-T04`)
- **Contract Parity**: Extended `IGatewayClient` and `DefaultGatewayClient` to support `register_device`, `update_crypto_prekeys`, `get_prekey_inventory_status`, and `get_device_crypto_directory` matching `auth.proto`.
- **Status Code Mapping**: Maps HTTP 200, 400, 401, 409 (Conflict / already registered), and network errors directly to canonical `ClientError` types.

### 5. Automated Device Lifecycle & Prekey Replenishment (`CLIENT-005-T05`)
- **`DeviceManager`**:
  - `initialize_or_load_device`: Loads existing bundle from secure storage if present; generates fresh keypairs and enrolls with the backend on first boot.
  - `revoke_device`: Securely wipes local key bundle and resets device state.
- **`PrekeyLifecycleCoordinator`**:
  - Automatically queries inventory watermark. If active OTPKs drop $\le 20$, generates and uploads 50 new OTPKs.
  - Automatically triggers signed prekey rotation if active key age exceeds 7 days.

### 6. Settings Trust Center ViewModel Integration & Test Suites (`CLIENT-005-T06`)
- **Reactive UI Wiring**: `WorkspaceViewModel::localDeviceIdentity` reflects live device public key, colon-separated fingerprint, and verification status. Exposes `prekeyCount` and `prekeyHealthStatus` ("Healthy", "Low", "Exhausted").
- **Manual Rotation Trigger**: `WorkspaceViewModel::rotateSignedPrekey` triggers live OpenSSL rotation, updates local storage, and emits reactive UI signals.
- **Comprehensive Unit Testing**: Added `ClientCryptoIdentityTest` (key sizes, bit-flip tampering rejection, private key isolation) and `ClientDeviceRegistrationTest` (registration, replenishment, and ViewModel integration).

---

## Verification & Test Results

1. **Compilation Standard**:
   - Zero warnings under `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wnon-virtual-dtor -Wconversion` across all platforms.
2. **Client Foundation Unit Tests**:
   - **125 / 125 tests passed (100% success rate)** in `securecloud_client_foundation_test` across 40 test suites in 1.8 seconds.
3. **Smoke Test**:
   - `securecloud-client --smoke-test` initializes the Qt Quick / QML engine and terminates cleanly.
4. **Backend Live Docker Integration Tests**:
   - Executed against Docker PostgreSQL 17 on `127.0.0.1:5433` (host port 5432 strictly protected):
     - `securecloud_auth_device_integration_test`: **8/8 PASSED**
     - `securecloud_auth_crypto_identity_integration_test`: **9/9 PASSED**
     - `securecloud_gateway_auth_e2e_integration_test`: **7/7 PASSED**
   - **Total: 24/24 live integration tests passed (100% success rate)**.
5. **Documentation**:
   - Comprehensive **1,084-line** card validation walkthrough report in `docs/final-reports/walkthrough-client-005.md`.

---

## Security Invariants Confirmed

- [x] **ADR-008 §4, §6**: Private keys never leave the client boundary and are never transmitted over the network.
- [x] **ADR-008 §3**: Zero hand-rolled cryptography; OpenSSL 3.x EVP used exclusively for Ed25519 and X25519.
- [x] **ADR-008 §5**: Account authentication (JWT) is decoupled from physical cryptographic device identity.
- [x] **Memory Safety**: `OPENSSL_cleanse` actively zeroizes private key buffers upon destruction and explicit clear.
- [x] **Port Safety**: Host PostgreSQL on port 5432 is strictly protected; containerized tests bind exclusively to 5433.
