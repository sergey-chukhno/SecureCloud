# Walkthrough: FILES-003-T03 — StorageEngine Domain Abstraction Layer

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-003-T03`  
**Card**: `FILES-003` (Establish MinIO Object Storage Integration)  
**Branch**: `feature/files-003-Establish-MinIO-object-storage-integration`

The primary objective of `FILES-003-T03` is to deliver the domain storage abstraction `StorageEngine` in `src/files/service/storage_engine.{hpp,cpp}`. This layer decouples the higher-level transfer and file services from low-level S3 REST mechanics and enforces the following architectural invariants:
1. **Zero-Plaintext Invariant (ADR-005, Files Design 6.1, 6.2, 6.17)**: Only pre-encrypted ciphertext is stored or retrieved.
2. **Opaque Object Key Invariant (Files Design 6.17)**: Object keys are strictly derived from UUIDs and indices:
   - Chunks: `chunks/{transfer_id}/{chunk_index}`
   - Finalized files: `objects/{file_id}/{version_number}`
   - Plaintext filenames, emails, and usernames are strictly prohibited from appearing in keys.
3. **Cryptographic Integrity (Files Design 6.8, 6.9)**: Inbound data is checked against expected SHA-256 digests; mismatches immediately throw `S3IntegrityException` without touching storage.

---

## 2. Key Components Delivered

### 2.1 Interface & Class Definition (`src/files/service/storage_engine.hpp`)
Defines `IStorageEngine` and `StorageEngine`:
```cpp
class IStorageEngine {
  public:
    virtual ~IStorageEngine() = default;

    virtual bool put_chunk(const std::string& transfer_id, uint32_t chunk_index,
                           std::string_view encrypted_data, const std::string& expected_sha256) = 0;

    virtual std::optional<std::string> get_chunk(const std::string& transfer_id,
                                                 uint32_t chunk_index) = 0;

    virtual bool delete_chunk(const std::string& transfer_id, uint32_t chunk_index) = 0;

    virtual bool put_file_object(const std::string& file_id, uint32_t version_number,
                                 std::string_view encrypted_data, const std::string& expected_sha256) = 0;

    virtual std::optional<std::string> get_file_object(const std::string& file_id,
                                                       uint32_t version_number,
                                                       std::optional<storage::ByteRange> range = std::nullopt) = 0;

    virtual bool delete_file_objects(const std::string& file_id) = 0;

    virtual bool delete_transfer_chunks(const std::string& transfer_id) = 0;
};
```

### 2.2 Domain Logic Implementation (`src/files/service/storage_engine.cpp`)
- `derive_chunk_key`: Produces `chunks/<transfer_id>/<chunk_index>`.
- `derive_file_object_key`: Produces `objects/<file_id>/<version_number>`.
- `put_chunk` & `put_file_object`: Computes `SigV4Signer::sha256_hex(data)`, validates case-insensitively against `expected_sha256`, throws `S3IntegrityException` on mismatch, and delegates to `s3_client_->put_object`.
- `get_chunk` & `get_file_object`: Catches `S3ObjectNotFoundException` and returns `std::nullopt` gracefully.
- `delete_transfer_chunks` & `delete_file_objects`: Uses `s3_client_->list_objects` to enumerate objects by prefix and deletes them iteratively across continuation tokens.

---

## 3. Verification & Acceptance Criteria
- Full test suite verified in `tests/unit/files/storage_engine_test.cpp`.
- Opaque keys validated against information leakage.
- Checksum mismatches reject uploads before network transmission.
