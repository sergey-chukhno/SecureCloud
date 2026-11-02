# Walkthrough — Card FILES-008: Capability-Based File Access Authorization Engine

**Card Identifier**: `FILES-008` (or `FILE-008`)  
**Milestone**: M5 — Secure Files  
**Branch**: `feature/files-008-implement-file-access-capabilities`  
**Developer**: Louis  
**Lead & Security Architect**: Sergey  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary

Card **FILES-008** delivers the authoritative **Capability-Based File Access Authorization Engine** for the **SecureCloud Files Service** (`securecloud-files`). Building directly upon the chunked streaming download pipeline (**FILES-007**), this engine replaces coarse session permissions with short-lived, cryptographically signed, tamper-evident **File-Access Capabilities**.

```text
Recipient Client
       │
       │ 1. Receives FILE conversation item via Messaging sync
       ▼
    file_id
       │
       │ 2. Obtains short-lived signed capability
       ▼
File-Access Capability:
       ├── user_id:       UUIDv7 (caller user)
       ├── device_id:     UUIDv7 (caller device)
       ├── file_id:       UUIDv7 (target file)
       ├── file_version:  int32  (optional version pin)
       ├── operation:     READ   (or WRITE / DELETE)
       ├── expires_at:    UNIX ms (short-lived TTL)
       └── signature:     Ed25519 (asymmetric cryptographic signature)
       │
       ▼
Recipient Client
       │
       │ 3. DownloadChunk(file_id, chunk_index)
       │    Metadata:
       │      x-user-id: <user_id>
       │      x-device-id: <device_id>
       │      x-file-access-capability: <token>
       ▼
    Gateway (mTLS perimeter)
       ▼
  Files Service (securecloud-files)
       │
       ├── 1. Cryptographically verify Ed25519 signature
       ├── 2. Verify caller matches capability user_id & device_id
       ├── 3. Verify target matches capability file_id & operation
       ├── 4. Verify capability has not expired (now <= expires_at)
       ├── 5. Verify device is NOT revoked (active status check)
       └── 6. Authorize retrieval of pre-encrypted ciphertext
       │
       ▼
   MinIO S3 (HTTP Range byte slice)
       │
       ▼
Recipient Client (decrypts locally on endpoint — server never sees plaintext)
```

---

## 2. Invariants & Security Guarantees

1. **Zero-Plaintext Invariant (ADR-005, ADR-008, Files Design §6.1, §6.26)**:
   - The Files Service has zero access to client encryption keys or plaintext.
   - Enforcing capabilities authorizes access **strictly to encrypted ciphertext slices**.
   - Decryption occurs exclusively on authorized client endpoints.

2. **Strict User Binding (User A $\ne$ User B Guard)**:
   - A capability issued to `user A` must **never** authorize access for `user B`.
   - If caller `x-user-id` $\ne$ `capability.user_id`, request is rejected with `PERMISSION_DENIED`.
   - A user cannot use a capability issued for their own file to access another user's file.

3. **Strict Device Binding (Device A $\ne$ Device B Guard)**:
   - A capability issued to `device A` must **never** authorize access for `device B`.
   - If caller `x-device-id` $\ne$ `capability.device_id`, request is rejected with `PERMISSION_DENIED`.
   - Compromising or intercepting device A's capability provides zero access to device B.

4. **Strict File & Operation Scoping**:
   - A capability issued for `file_1` cannot be reused for `file_2`.
   - A capability issued for `read` cannot be used for `write` or `delete`.
   - If `file_version` is pinned in the capability ($> 0$), requesting any other version is rejected.

5. **Temporal Lifetime & Replay Protection**:
   - Capabilities are strictly short-lived (default TTL: 15 minutes, configurable down to 5 minutes).
   - Any capability presented after `expires_at` is immediately rejected with `PERMISSION_DENIED`.
   - Any capability with `issued_at` significantly in the future (clock skew $> 30\text{s}$) is rejected.
   - Replay attacks outside the valid lifetime window are mathematically impossible.

6. **Revoked Device Enforcement**:
   - If a device has been revoked (e.g. lost phone, stolen laptop), any capability presented by or issued to that device ID is rejected immediately, even if the cryptographic signature is mathematically valid.

7. **Cryptographic Tamper-Evidence**:
   - Asymmetric Ed25519 signature protects the entire claim payload:
     $$\text{Token} = \text{base64url}(\text{header}) \,.\, \text{base64url}(\text{claims}) \,.\, \text{base64url}(\text{signature})$$
   - Any alteration to `user_id`, `device_id`, `file_id`, `operation`, or `expires_at` invalidates the signature and causes instant rejection (`UNAUTHENTICATED` / `INVALID_ARGUMENT`).

---

## 3. Tickets Implemented

### FILES-008-T01: File Access Capability Domain Model & Ed25519 Wire Serializer
- **Header**: [src/files/domain/file_capability_entity.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/file_capability_entity.hpp)
- **Serializer**: [src/files/domain/file_capability_serializer.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/file_capability_serializer.hpp) & [file_capability_serializer.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/file_capability_serializer.cpp)
- **Unit Test**: [tests/unit/files/file_capability_serializer_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/file_capability_serializer_test.cpp)
- **Functionality**:
  - Defined `FileAccessCapabilityClaims` struct and `FileCapabilityOperation` enum (`Read`, `Write`, `Delete`, `Metadata`).
  - Implemented RFC 7515 Base64URL envelope serialization and deserialization.
  - Applied OpenSSL 3 Ed25519 asymmetric signature generation and verification.

### FILES-008-T02: Capability Validation Engine & Security Guard
- **Header**: [src/files/domain/capability_validator.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/capability_validator.hpp)
- **Source**: [src/files/domain/capability_validator.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/domain/capability_validator.cpp)
- **Unit Test**: [tests/unit/files/capability_validator_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/capability_validator_test.cpp)
- **Functionality**:
  - Enforced all 6 binding invariants: user match, device match, file match, operation match, version match, and active device status.
  - Enforced strict temporal bounds (rejecting expired and premature replay tokens).

### FILES-008-T03: Device Status & Revocation Verification Provider
- **Header**: [src/files/repository/device_revocation_provider.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/repository/device_revocation_provider.hpp)
- **Source**: [src/files/repository/device_revocation_provider.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/repository/device_revocation_provider.cpp)
- **Unit Test**: [tests/unit/files/device_revocation_provider_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/device_revocation_provider_test.cpp)
- **Functionality**:
  - Implemented thread-safe `IDeviceRevocationProvider` with in-memory caching and database verification fallback.
  - Ensures revoked devices cannot exercise capabilities even if the cryptographic signature is mathematically valid.

### FILES-008-T04: Capability Manager & Issuance Service
- **Header**: [src/files/service/file_capability_manager.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/file_capability_manager.hpp)
- **Source**: [src/files/service/file_capability_manager.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/file_capability_manager.cpp)
- **Unit Test**: [tests/unit/files/file_capability_manager_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/file_capability_manager_test.cpp)
- **Functionality**:
  - Created `IFileCapabilityManager` orchestrating `issue_capability` and `authorize_capability`.
  - Links capability issuance to PostgreSQL `FileAccessRepository` permissions.

### FILES-008-T05: gRPC Service Integration & Metadata Pipeline
- **Source**: [src/files/service/files_service_impl.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/files_service_impl.cpp)
- **Header**: [src/files/service/files_service_impl.hpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/service/files_service_impl.hpp)
- **Unit Test**: [tests/unit/files/files_service_impl_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/files/files_service_impl_test.cpp)
- **Functionality**:
  - Extracted `x-user-id`, `x-device-id`, and `x-file-access-capability` from incoming gRPC `ServerContext` metadata.
  - Mapped capability validation failures to standard gRPC error codes:
    - Tampered / malformed token $\longrightarrow$ `grpc::StatusCode::UNAUTHENTICATED`
    - Expired token / wrong user / wrong device / wrong file / revoked device $\longrightarrow$ `grpc::StatusCode::PERMISSION_DENIED`

### FILES-008-T06: End-to-End Capability Security Integration Tests & Walkthrough
- **Integration Test**: [tests/integration/files_capability_integration_test.cpp](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/integration/files_capability_integration_test.cpp)
- **CMake**: [tests/integration/CMakeLists.txt](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/integration/CMakeLists.txt)
- **Walkthrough Document**: [docs/final-reports/walkthrough-files-008.md](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/docs/final-reports/walkthrough-files-008.md)

---

## 4. Security Test Matrix & Verification Results

| Test Case ID | Test Scenario Description | Expected Outcome | Security Principle |
| :--- | :--- | :--- | :--- |
| **TC1** | **Valid Capability**: Matching user, device, file, read op | **`grpc::Status::OK`** | Legitimate authorized retrieval |
| **TC2** | **Expired Capability**: `now > expires_at` | **`grpc::StatusCode::PERMISSION_DENIED`** | Temporal confinement |
| **TC3** | **Wrong User**: User A capability presented by User B | **`grpc::StatusCode::PERMISSION_DENIED`** | User isolation (User A $\ne$ B) |
| **TC4** | **Wrong Device**: Device A capability presented by Device B | **`grpc::StatusCode::PERMISSION_DENIED`** | Device isolation (Device A $\ne$ B) |
| **TC5** | **Wrong File**: Capability for File 1 presented for File 2 | **`grpc::StatusCode::PERMISSION_DENIED`** | Object scoping |
| **TC6** | **Wrong Operation**: Write capability presented for download | **`grpc::StatusCode::PERMISSION_DENIED`** | Least-privilege operation scoping |
| **TC7** | **Revoked Device**: Device marked revoked after issuance | **`grpc::StatusCode::PERMISSION_DENIED`** | Immediate revocation enforcement |
| **TC8** | **Malformed Capability**: Garbage signature / broken base64 | **`grpc::StatusCode::UNAUTHENTICATED`** | Cryptographic integrity |
| **TC9** | **Replay Outside Lifetime**: Future `iat` premature token | **`grpc::StatusCode::PERMISSION_DENIED`** | Anti-replay guard |
| **TC10**| **Zero Decryption Invariant**: Raw ciphertext returned intact | **`Zero Decryption`** | Zero-knowledge storage custodian |

All 10 security invariants pass and are strictly verified.
