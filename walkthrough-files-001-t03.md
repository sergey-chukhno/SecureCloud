# Walkthrough — `FILES-001-T03`: MinIO S3 Object Storage Client Wrapper & Bucket Reachability Probe

**Ticket ID**: `FILES-001-T03`  
**Status**: ✅ **COMPLETED & VALIDATED**

---

## 1. Summary of Changes

### MinIO S3 Client Wrapper & SigV4 Signer (`src/files/storage/`)
- [`src/files/storage/s3_exceptions.hpp`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/storage/s3_exceptions.hpp):
  - Declared `S3ClientException`, `S3BucketNotFoundException`, `S3AuthenticationException`, `S3ObjectNotFoundException`, `S3ConnectionException`.
- [`src/files/storage/s3_client.hpp`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/storage/s3_client.hpp) & [`s3_client.cpp`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/storage/s3_client.cpp):
  - **AWS Signature Version 4 (SigV4) Signer**:
    - Implemented with standard OpenSSL (`EVP_sha256`, `HMAC`).
    - Standard canonical request hashing, credential scope (`<DateStamp>/<region>/s3/aws4_request`), and 5-stage key derivation (`kSecret` → `kDate` → `kRegion` → `kService` → `kSigning`).
    - Produces canonical `Authorization` header (`AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...`).
  - **Bucket Reachability & Existence Checks**:
    - `ping_bucket(timeout_ms)`: Issues `HEAD /<bucket>` within bounded timeout (default 1000ms), returns boolean `true`/`false`, without throwing unhandled exceptions.
    - `object_exists(object_key)`: Issues `HEAD /<bucket>/<object_key>`, returns `true` on 200 OK, `false` on 404 Not Found, throws `S3AuthenticationException` on 403 Forbidden.
  - **Transport Abstraction**:
    - `IHttpTransport` interface allows zero-network deterministic mocking.
    - `DefaultHttpTransport` implements raw socket HTTP/1.1 communication for live MinIO endpoints.
  - **Zero-Plaintext & Secret Safety**:
    - Uses `SecretString` for `s3_secret_key`. Secret key and signature headers are never logged to stdout/stderr.

### Build Registration
- [`src/files/CMakeLists.txt`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/src/files/CMakeLists.txt):
  - Created `securecloud_files_storage` static library target (aliased to `securecloud::files_storage`).
  - Linked `securecloud::files_storage` into `securecloud-files`.
- [`tests/unit/CMakeLists.txt`](file:///c:/Users/gamer/Documents/Bachelor%20IT/B3/Projets/Secure%20Cloud%20%20projet/SecureCloud/tests/unit/CMakeLists.txt):
  - Created and registered `securecloud_s3_client_test` with GoogleTest automatic test discovery.

---

## 2. Test Verification Results

### Unit Test Suite Execution (`S3ClientTest`)
Executed `tests\unit\securecloud_s3_client_test.exe`:
```text
[==========] Running 9 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 9 tests from S3ClientTest
[ RUN      ] S3ClientTest.SigV4Sha256AndHmacDerivation
[       OK ] S3ClientTest.SigV4Sha256AndHmacDerivation (21 ms)
[ RUN      ] S3ClientTest.SigV4HeaderFormatting
[       OK ] S3ClientTest.SigV4HeaderFormatting (0 ms)
[ RUN      ] S3ClientTest.ConfigValidationAndExtraction
[       OK ] S3ClientTest.ConfigValidationAndExtraction (0 ms)
[ RUN      ] S3ClientTest.PingBucketSuccessOn200OK
[       OK ] S3ClientTest.PingBucketSuccessOn200OK (0 ms)
[ RUN      ] S3ClientTest.PingBucketFailureReturnsFalseWithoutThrowing
[       OK ] S3ClientTest.PingBucketFailureReturnsFalseWithoutThrowing (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsSuccessOn200OK
[       OK ] S3ClientTest.ObjectExistsSuccessOn200OK (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsNotFoundReturnsFalse
[       OK ] S3ClientTest.ObjectExistsNotFoundReturnsFalse (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsForbiddenThrowsAuthenticationException
[       OK ] S3ClientTest.ObjectExistsForbiddenThrowsAuthenticationException (0 ms)
[ RUN      ] S3ClientTest.ObjectExistsConnectionFailureThrowsConnectionException
[       OK ] S3ClientTest.ObjectExistsConnectionFailureThrowsConnectionException (0 ms)
[----------] 9 tests from S3ClientTest (23 ms total)
[----------] Global test environment tear-down
[==========] 9 tests from 1 test suite ran. (25 ms total)
[  PASSED  ] 9 tests.
```

### Full Cumulative Phase 5 Regression (23 Tests)
Executed `ctest --preset ci-windows-msvc -R "(ProtoSmokeTest|FilesDbConnectionPool|S3Client)" --output-on-failure`:
```text
Test project C:/Users/gamer/Documents/Bachelor IT/B3/Projets/Secure Cloud  projet/SecureCloud/build/ci-windows-msvc
      Start  2: ProtoSmokeTest.MessageConstructionAndSerialization ............................   Passed    0.03 sec
      Start  3: ProtoSmokeTest.ServiceStubTypeLinkage .........................................   Passed    0.02 sec
      Start  4: ProtoSmokeTest.FilesMessageConstructionAndSerialization .......................   Passed    0.02 sec
      Start  5: ProtoSmokeTest.FilesServiceStubTypeLinkage ....................................   Passed    0.02 sec
      Start 64: FilesDbConnectionPoolTest.ConfigValidationEnforcesPort5432SecurityInvariant ...   Passed    0.02 sec
      Start 65: FilesDbConnectionPoolTest.ConfigPopulatesFromFilesConfig ......................   Passed    0.02 sec
      Start 66: FilesDbConnectionPoolTest.PoolInitializationPrewarmsMinConnections ............   Passed    0.02 sec
      Start 67: FilesDbConnectionPoolTest.RAIIPooledConnectionLeasingAndReturn ................   Passed    0.02 sec
      Start 68: FilesDbConnectionPoolTest.DynamicExpansionUpToMaxConnections ..................   Passed    0.02 sec
      Start 69: FilesDbConnectionPoolTest.AcquisitionTimeoutWhenPoolIsExhausted ...............   Passed    0.08 sec
      Start 70: FilesDbConnectionPoolTest.ConcurrentContentionAcrossMultipleThreads ...........   Passed    0.48 sec
      Start 71: FilesDbConnectionPoolTest.DedicatedHealthPingImmuneToWorkerPoolExhaustion .....   Passed    0.02 sec
      Start 72: FilesDbConnectionPoolTest.LifecycleDrainAndCloseOperations ....................   Passed    0.02 sec
      Start 73: FilesDbConnectionPoolTest.DiscardUnhealthyConnectionUponReturn ................   Passed    0.02 sec
      Start 74: S3ClientTest.SigV4Sha256AndHmacDerivation .....................................   Passed    0.02 sec
      Start 75: S3ClientTest.SigV4HeaderFormatting ............................................   Passed    0.04 sec
      Start 76: S3ClientTest.ConfigValidationAndExtraction ....................................   Passed    0.03 sec
      Start 77: S3ClientTest.PingBucketSuccessOn200OK .........................................   Passed    0.03 sec
      Start 78: S3ClientTest.PingBucketFailureReturnsFalseWithoutThrowing .....................   Passed    0.03 sec
      Start 79: S3ClientTest.ObjectExistsSuccessOn200OK .......................................   Passed    0.02 sec
      Start 80: S3ClientTest.ObjectExistsNotFoundReturnsFalse .................................   Passed    0.02 sec
      Start 81: S3ClientTest.ObjectExistsForbiddenThrowsAuthenticationException ...............   Passed    0.02 sec
      Start 82: S3ClientTest.ObjectExistsConnectionFailureThrowsConnectionException ...........   Passed    0.03 sec

100% tests passed, 0 tests failed out of 23 (Total Test time: 1.11s)
```

---

## 3. Recommended Git Commit Message for `FILES-001-T03`

```text
feat(files): implement MinIO S3 client wrapper & SigV4 signing (FILES-001-T03)

- Implement lightweight S3Client in src/files/storage/ with bounded ping_bucket() and object_exists()
- Implement OpenSSL AWS Signature Version 4 (SigV4) HMAC-SHA256 request signer
- Implement mockable IHttpTransport and DefaultHttpTransport socket client
- Declare S3 exception hierarchy in src/files/storage/s3_exceptions.hpp
- Register securecloud_files_storage library target in CMake
- Add 9-case unit test suite in tests/unit/files/s3_client_test.cpp

Refs: FILES-001, FILES-001-T03
```
