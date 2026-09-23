# Walkthrough — `FILES-001-T01`: Protobuf & gRPC Contract Baseline

**Ticket ID**: `FILES-001-T01`  
**Status**: ✅ **COMPLETED & VALIDATED**

---

## 1. Summary of Changes

### Canonical IPC Interface Contract (`proto/securecloud/files/v1/`)
- [`proto/securecloud/files/v1/files.proto`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/proto/securecloud/files/v1/files.proto):
  - Defined syntax `proto3` under package `securecloud.files.v1` with `option cc_generic_services = false;`.
  - Registered all **7 authoritative RPC methods** on `FilesService`:
    1. `CreateFileUpload(CreateFileUploadRequest) returns (CreateFileUploadResponse)`
    2. `UploadChunk(UploadChunkRequest) returns (UploadChunkResponse)`
    3. `FinalizeFileUpload(FinalizeFileUploadRequest) returns (FinalizeFileUploadResponse)`
    4. `GetFileMetadata(GetFileMetadataRequest) returns (GetFileMetadataResponse)`
    5. `DownloadChunk(DownloadChunkRequest) returns (DownloadChunkResponse)`
    6. `CancelFileUpload(CancelFileUploadRequest) returns (CancelFileUploadResponse)`
    7. `DeleteFile(DeleteFileRequest) returns (DeleteFileResponse)`
  - Defined lifecycle and transfer state enums with explicit zero-value specifications:
    - `FileLifecycleState`: `FILE_LIFECYCLE_STATE_UNSPECIFIED = 0`, `CREATED = 1`, `UPLOADING = 2`, `FINALIZING = 3`, `AVAILABLE = 4`, `EXPIRED = 5`, `DELETED = 6`, `FAILED = 7`.
    - `TransferStatus`: `TRANSFER_STATUS_UNSPECIFIED = 0`, `PENDING = 1`, `IN_PROGRESS = 2`, `COMPLETED = 3`, `CANCELLED = 4`, `FAILED = 5`.
  - **Zero-Plaintext Invariant Enforced**:
    - Strictly omitted fields for plaintext file contents, plaintext filenames, plaintext MIME types, or cryptographic keys.
    - Encrypted binary chunks use `bytes encrypted_data`.
    - Identifiers (`file_id`, `upload_id`, `owner_user_id`, `owner_device_id`, `conversation_id`) represented as canonical 36-character hyphenated UUIDv7 strings.
    - Chunk integrity verified using `uint32 chunk_index`, `uint32 chunk_size_bytes`, and `string ciphertext_sha256`.

### Build & Target Registration
- [`proto/CMakeLists.txt`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/proto/CMakeLists.txt):
  - Added `securecloud/files/v1/files.proto` to `PROTO_FILES`.
  - Automatically compiles to `files.pb.h`, `files.pb.cc`, `files.grpc.pb.h`, and `files.grpc.pb.cc` during build.

### Unit & Linkage Verification
- [`tests/unit/proto_smoke_test.cpp`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/proto_smoke_test.cpp):
  - Added `ProtoSmokeTest.FilesMessageConstructionAndSerialization`: validates construction, serialization, deserialization, and field fidelity for `CreateFileUploadRequest`, `CreateFileUploadResponse`, and `GetFileMetadataResponse`.
  - Added `ProtoSmokeTest.FilesServiceStubTypeLinkage`: statically verifies compilation and linkage of `securecloud::files::v1::FilesService::Service` and `securecloud::files::v1::FilesService::Stub`.

---

## 2. Test Verification Results

### Smoke Test Suite Execution (`ProtoSmokeTest`)
Executed `ctest --preset ci-windows-msvc -R ProtoSmokeTest --output-on-failure`:
```text
Test project C:/Users/gamer/Documents/Bachelor IT/B3/Projets/Secure Cloud  projet/SecureCloud/build/ci-windows-msvc
    Start 2: ProtoSmokeTest.MessageConstructionAndSerialization
1/4 Test #2: ProtoSmokeTest.MessageConstructionAndSerialization ........   Passed    0.03 sec
    Start 3: ProtoSmokeTest.ServiceStubTypeLinkage
2/4 Test #3: ProtoSmokeTest.ServiceStubTypeLinkage .....................   Passed    0.02 sec
    Start 4: ProtoSmokeTest.FilesMessageConstructionAndSerialization
3/4 Test #4: ProtoSmokeTest.FilesMessageConstructionAndSerialization ...   Passed    0.02 sec
    Start 5: ProtoSmokeTest.FilesServiceStubTypeLinkage
4/4 Test #5: ProtoSmokeTest.FilesServiceStubTypeLinkage ................   Passed    0.02 sec

100% tests passed, 0 tests failed out of 4 (Total Test time: 0.12s)
```

### Generated Contracts Target
Executed `cmake --build --preset ci-windows-msvc --target verify-contracts`:
```text
[1/1] Executing Protobuf & gRPC generated-contracts validation smoke test...
[==========] Running 4 tests from 1 test suite.
[----------] 4 tests from ProtoSmokeTest
[ RUN      ] ProtoSmokeTest.MessageConstructionAndSerialization
[       OK ] ProtoSmokeTest.MessageConstructionAndSerialization (1 ms)
[ RUN      ] ProtoSmokeTest.ServiceStubTypeLinkage
[       OK ] ProtoSmokeTest.ServiceStubTypeLinkage (0 ms)
[ RUN      ] ProtoSmokeTest.FilesMessageConstructionAndSerialization
[       OK ] ProtoSmokeTest.FilesMessageConstructionAndSerialization (1 ms)
[ RUN      ] ProtoSmokeTest.FilesServiceStubTypeLinkage
[       OK ] ProtoSmokeTest.FilesServiceStubTypeLinkage (0 ms)
[----------] 4 tests from ProtoSmokeTest (2 ms total)
[  PASSED  ] 4 tests.
```

---

## 3. Recommended Git Commit Message for `FILES-001-T01`

```text
build(deps): define files.proto IPC contract baseline (FILES-001-T01)

- Create canonical Protobuf schema and gRPC service definitions in proto/securecloud/files/v1/files.proto
- Declare all 7 authoritative FilesService RPCs and FileLifecycleState/TransferStatus enums
- Enforce Zero-Plaintext Invariant: opaque UUID strings and bytes ciphertext only
- Register files.proto in proto/CMakeLists.txt
- Extend tests/unit/proto_smoke_test.cpp with message serialization and service stub linkage checks

Refs: FILES-001, FILES-001-T01
```
