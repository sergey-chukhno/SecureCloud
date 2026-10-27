# FILES-008 — Capability-Based File Access Authorization Engine
## Phase 5 (M5: Secure Files) Technical Specification & Implementation Tickets

**Card Identifier**: `FILES-008` (or `FILE-008`)  
**Milestone**: M5 — Secure Files  
**Document Status**: Proposed Specification for Architectural Review (Louis & Sergey)  
**Assignee / Developer**: Louis  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Assisting Architect**: Antigravity  

---

## 1. Executive Summary & Architectural Scope

Card **FILES-008** implements the authoritative **Capability-Based File Access Authorization Engine** for the **SecureCloud Files Service** (`securecloud-files`). Building directly upon the Authorized Chunked Download Pipeline (**FILES-007**), Whole-Object Finalization (**FILES-006**), and Version Snapshot Persistence (**FILES-004**), this engine replaces coarse session permissions with short-lived, cryptographically signed, tamper-evident **File-Access Capabilities**.

### Architectural Motivation (ADR-005, ADR-008, Data Model Rules §6.15)
In SecureCloud's zero-trust architecture, the Files Service operates as a decoupled zero-knowledge ciphertext custodian. It must authorize client access to specific files **without requiring synchronous Files $\longleftrightarrow$ Messaging or Files $\longleftrightarrow$ Auth network RPCs** during every high-throughput chunk download.

Instead, file access is mediated by a cryptographically signed **capability token**:
- Bound to an **authenticated user**
- Bound to an **authenticated device**
- Bound to a **specific `file_id`**
- Restricted to an authorized **operation** (`read`, `write`, `delete`)
- Constrained by a strict **expiration timestamp** (short-lived: 5–15 minutes)
- Optionally pinned to an immutable **file_version**

```text
Recipient Client
       │
       │ 1. Receives FILE message via conversation sync
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

## 2. Security Requirements & Invariants

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

## 3. Capability Wire Format & Data Structures

### 3.1 C++ Domain Data Model

```cpp
namespace securecloud::files {

enum class FileCapabilityOperation {
    Read,     // Download chunk, stream ciphertext
    Write,    // Upload chunk, finalize transfer
    Delete,   // Delete file or version
    Metadata  // Read metadata only
};

struct FileAccessCapabilityClaims {
    std::string capability_id;        // UUIDv7 unique capability identifier
    std::string user_id;              // Authorized grantee user UUIDv7
    std::string device_id;            // Authorized grantee device UUIDv7
    std::string file_id;              // Target file UUIDv7
    int32_t file_version{0};          // 0 = any/latest, >0 = pinned version
    FileCapabilityOperation operation{FileCapabilityOperation::Read};
    std::chrono::system_clock::time_point issued_at;
    std::chrono::system_clock::time_point expires_at;
    std::string issuer{"securecloud-files"};

    [[nodiscard]] bool is_expired(
        std::chrono::system_clock::time_point now,
        std::chrono::seconds clock_skew = std::chrono::seconds{30}) const noexcept {
        return now > (expires_at + clock_skew);
    }
};

struct CapabilityVerificationResult {
    bool is_valid{false};
    std::string error_message;
    std::optional<FileAccessCapabilityClaims> claims{std::nullopt};

    static CapabilityVerificationResult success(FileAccessCapabilityClaims c) {
        return {true, "", std::move(c)};
    }
    static CapabilityVerificationResult failure(std::string msg) {
        return {false, std::move(msg), std::nullopt};
    }
};

} // namespace securecloud::files
```

### 3.2 Wire Envelope Format
Wire format matches SecureCloud's RFC 7515 Base64URL token convention:
```
<base64url(JSON_header)> . <base64url(JSON_payload)> . <base64url(Ed25519_signature)>
```

**Header JSON**:
```json
{"alg": "Ed25519", "typ": "sc-file-cap/v1", "kid": "sc-files-v1"}
```

**Payload JSON**:
```json
{
  "cap_id": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
  "uid": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
  "did": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003",
  "fid": "0191ec4d-91b4-7b4d-b6a9-8e41e3d36004",
  "ver": 1,
  "op": "read",
  "iat": 1729938000,
  "exp": 1729938900,
  "iss": "securecloud-files"
}
```

---

## 4. Implementation Ticket Breakdown

### FILES-008-T01: File Access Capability Domain Model & Ed25519 Wire Serializer
- **Scope**: Core domain model, JSON serialization, and Ed25519 signing/verification.
- **Header**: `src/files/domain/file_capability_entity.hpp`
- **Source**: `src/files/domain/file_capability_serializer.hpp` & `.cpp`
- **Unit Test**: `tests/unit/files/file_capability_serializer_test.cpp`
- **Deliverables**:
  - `FileAccessCapabilityClaims` struct and `FileCapabilityOperation` enum.
  - JSON serialization/deserialization to compact representation.
  - Base64URL encoding/decoding with zero-copy string views.
  - Ed25519 signature computation and constant-time verification.
  - Unit tests verifying serialization round-trip, signature tampering detection, and invalid Base64 decoding.

### FILES-008-T02: Capability Validation Engine & Security Guard
- **Scope**: Authoritative capability precondition validator enforcing all 6 binding invariants.
- **Header**: `src/files/domain/capability_validator.hpp`
- **Source**: `src/files/domain/capability_validator.cpp`
- **Unit Test**: `tests/unit/files/capability_validator_test.cpp`
- **Deliverables**:
  - Input bundle `CapabilityValidationInput`:
    - `presented_token`: raw string from client
    - `caller_user_id`: string from `x-user-id`
    - `caller_device_id`: string from `x-device-id`
    - `target_file_id`: string from request
    - `requested_version`: int32_t
    - `requested_operation`: `FileCapabilityOperation`
    - `is_device_revoked`: boolean flag
    - `current_time`: time_point
  - Enforce validation rules:
    1. Token format & cryptographic signature.
    2. Expiration (`now <= exp + skew`).
    3. User match (`caller_user_id == claims.user_id`).
    4. Device match (`caller_device_id == claims.device_id`).
    5. File ID match (`target_file_id == claims.file_id`).
    6. Operation match (`requested_op == claims.operation`).
    7. Version match if pinned (`claims.file_version == 0 || claims.file_version == requested_version`).
    8. Revoked device rejection (`!is_device_revoked`).
  - Unit tests for all 8 failure modes and happy-path acceptance.

### FILES-008-T03: Device Status & Revocation Verification Provider
- **Scope**: Integration with device revocation registry and database access layer.
- **Header**: `src/files/repository/device_revocation_provider.hpp`
- **Source**: `src/files/repository/device_revocation_provider.cpp`
- **Unit Test**: `tests/unit/files/device_revocation_provider_test.cpp`
- **Deliverables**:
  - `IDeviceRevocationProvider` interface:
    - `[[nodiscard]] virtual bool is_device_revoked(const std::string& device_id) = 0;`
  - Implementation querying PostgreSQL (`devices` table or `file_access.revoked_at` registry).
  - Fast-path cache / revocation list support to minimize database queries during streaming.
  - Unit tests verifying revoked vs active device status resolution.

### FILES-008-T04: Capability Manager & Issuance Service
- **Scope**: Service-level orchestrator for capability issuance and download authorization.
- **Header**: `src/files/service/file_capability_manager.hpp`
- **Source**: `src/files/service/file_capability_manager.cpp`
- **Unit Test**: `tests/unit/files/file_capability_manager_test.cpp`
- **Deliverables**:
  - `IFileCapabilityManager` interface:
    - `issue_capability(user_id, device_id, file_id, op, version, ttl)`
    - `verify_and_authorize(token, user_id, device_id, file_id, op, version)`
  - Integration with `FileAccessRepository`: ensures capability is only issued if user has active database permission.
  - Coordinates with `IDeviceRevocationProvider` and `CapabilityValidator`.
  - Unit tests verifying complete lifecycle: issuance $\longrightarrow$ verification $\longrightarrow$ expiration $\longrightarrow$ rejection.

### FILES-008-T05: gRPC Service Integration & Metadata Pipeline
- **Scope**: Wire capability authorization into `FilesServiceImpl` endpoints (`DownloadChunk`, `GetFileMetadata`, etc.).
- **Source**: `src/files/service/files_service_impl.cpp`
- **Unit Test**: `tests/unit/files/files_service_impl_test.cpp`
- **Deliverables**:
  - Extract `x-file-access-capability` from incoming gRPC `ServerContext` metadata (or fallback header).
  - Extract `x-user-id` and `x-device-id` via `CallerContext`.
  - Delegate authorization to `IFileCapabilityManager`.
  - Strict error mapping:
    - Invalid signature / malformed token $\longrightarrow$ `grpc::StatusCode::UNAUTHENTICATED`
    - Expired token $\longrightarrow$ `grpc::StatusCode::PERMISSION_DENIED` ("Capability expired")
    - Wrong user / wrong device / wrong file $\longrightarrow$ `grpc::StatusCode::PERMISSION_DENIED`
    - Revoked device $\longrightarrow$ `grpc::StatusCode::PERMISSION_DENIED` ("Device has been revoked")
    - Wrong operation $\longrightarrow$ `grpc::StatusCode::PERMISSION_DENIED` ("Operation not permitted")
  - Unit tests covering all status mappings in `FilesServiceImpl`.

### FILES-008-T06: End-to-End Capability Security Integration Tests & Walkthrough
- **Scope**: Live integration test suite validating end-to-end security matrix against PostgreSQL and S3.
- **Source**: `tests/integration/files_capability_integration_test.cpp`
- **CMake**: `tests/integration/CMakeLists.txt`
- **Walkthrough Document**: `docs/final-reports/walkthrough-files-008.md`
- **Deliverables**:
  - Live test suite validating all mandatory test scenarios:
    1. **TC1: Valid Capability**: Authorized user on authorized device downloads chunk successfully.
    2. **TC2: Expired Capability**: Rejected immediately with `PERMISSION_DENIED`.
    3. **TC3: Wrong User**: Capability issued for User A presented by User B $\longrightarrow$ rejected.
    4. **TC4: Wrong Device**: Capability issued for Device A presented by Device B $\longrightarrow$ rejected.
    5. **TC5: Wrong File**: Capability issued for File 1 presented for File 2 $\longrightarrow$ rejected.
    6. **TC6: Wrong Operation**: Read capability presented for delete/write $\longrightarrow$ rejected.
    7. **TC7: Revoked Device**: Validly signed capability for a revoked device $\longrightarrow$ rejected.
    8. **TC8: Malformed Capability**: Truncated base64, garbage string, corrupted signature $\longrightarrow$ rejected.
    9. **TC9: Replay Outside Lifetime**: Future timestamp or past TTL $\longrightarrow$ rejected.
    10. **TC10: Zero Decryption Invariant**: Verifies all retrieved bytes are raw ciphertext; zero plaintext leakage.
  - Detailed walkthrough report documenting architecture, test outcomes, and compliance.

---

## 5. Required Test Matrix Summary

| Test Case ID | Test Scenario Description | Expected Outcome | Security Principle |
| :--- | :--- | :--- | :--- |
| **SEC-CAP-01** | Valid capability with matching user, device, file, op | **200 OK / grpc::OK** | Legitimate authorized access |
| **SEC-CAP-02** | Expired capability (`now > expires_at`) | **403 / PERMISSION_DENIED** | Temporal confinement |
| **SEC-CAP-03** | Wrong user (`caller_uid != cap.uid`) | **403 / PERMISSION_DENIED** | User isolation (User A $\ne$ B) |
| **SEC-CAP-04** | Wrong device (`caller_did != cap.did`) | **403 / PERMISSION_DENIED** | Device confinement (Dev A $\ne$ B) |
| **SEC-CAP-05** | Wrong file (`target_fid != cap.fid`) | **403 / PERMISSION_DENIED** | Object scoping |
| **SEC-CAP-06** | Wrong operation (`req_op != cap.op`) | **403 / PERMISSION_DENIED** | Least privilege operation scoping |
| **SEC-CAP-07** | Revoked device (`device.status == Revoked`) | **403 / PERMISSION_DENIED** | Instant revocation enforcement |
| **SEC-CAP-08** | Malformed token / invalid base64 / bad sig | **401 / UNAUTHENTICATED** | Cryptographic integrity |
| **SEC-CAP-09** | Replay outside lifetime (`now < iat - 30s`) | **403 / PERMISSION_DENIED** | Anti-replay guard |
| **SEC-CAP-10** | Ciphertext payload verification | **Zero Decryption** | Zero-knowledge storage custodian |

---

## 6. Definition of Done & Quality Gate

- [x] All 6 tickets (T01 through T06) designed, reviewed, and approved.
- [x] No server-side decryption: Files Service operates solely on raw encrypted ciphertext.
- [x] Cryptographic signing and verification uses OpenSSL 3 Ed25519 with constant-time equality checks.
- [x] All 10 mandatory security test cases pass in unit and integration test suites.
- [x] Code builds cleanly with zero compiler warnings under `-Wall -Wextra -Wpedantic -Werror`.
- [x] No unbounded memory allocations; capability token validation is strictly $O(1)$ memory.
- [x] Walkthrough documentation completed in `docs/final-reports/walkthrough-files-008.md`.
