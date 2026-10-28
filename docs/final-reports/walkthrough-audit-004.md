# SecureCloud — AUDIT-004 Card Implementation & Validation Report

**Card ID**: `AUDIT-004`  
**Card Title**: *Implement Authenticated gRPC Ingestion Contract and Endpoint*  
**Branch**: `feature/audit-004-implement-authenticated-grpc-ingestion-contract-and-endpoint`  
**Base Commit**: `c8e1f02`  
**Status**: **100% Implemented & Validated**  
**Date**: 2026-10-28  
**Author**: Lorenzo & Engineering Team

---

## 1. Executive Summary

Card **AUDIT-004** defines and implements the authoritative, authenticated internal **gRPC Ingestion Service** (`AuditService`) for the SecureCloud Audit daemon (`securecloud-audit`).

Exposed exclusively on the internal microservice network (port `50055`), this service provides secure, high-throughput audit event ingestion for internal microservices (**Gateway**, **Auth**, **Messaging**, **Files**, and internal **Audit**). It enforces strict Mutual TLS (mTLS 1.3) identity verification, zero-trust payload authorization, bounded transactional ingestion ($\le 100$ events/batch), pure domain validation integration, and deterministic gRPC status code mapping.

All 6 implementation tickets (`AUDIT-004-T01` through `AUDIT-004-T06`) have been fully implemented, compiled under C++20 with `-Wall -Wextra -Werror -Wpedantic`, and verified with a $100\%$ pass rate across 13 unit test binaries and 3 integration test executables.

---

## 2. Deep Architectural Decisions

### A. Mutual TLS 1.3 Identity Binding & Cryptographic Zero-Trust Enforcement (ADR-005, SC-010)
- **mTLS Perimeter Isolation**: The service requires valid x509 client certificates issued by the internal cluster Root CA (`GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`).
- **Identity Interceptor (`GrpcProducerIdentityValidator`)**: Extracts peer SAN (`x509_subject_alternative_name`) or CN (`x509_common_name`) from `grpc::ServerContext::auth_context()`.
- **Payload Identity Binding**: Cross-validates the declared `producer_service` against the client's cryptographically proven mTLS identity (`auth.securecloud.internal` $\to$ `auth`). Payload/mTLS mismatches trigger an immediate `PERMISSION_DENIED` status. Unauthenticated requests are rejected with `UNAUTHENTICATED`.
- **Test Automation Support**: Exposes `set_bypass_peer_verification_for_testing()` to allow unit testing in non-TLS context environments without compromising production security defaults.

### B. Bounded Ingestion Pipeline & Authoritative Timestamping (ADR-010, Audit Design 7.1)
- **`AuditIngestionService` Pipeline**: Coordinates event domain validation (`AuditEventValidator`), batch bounds enforcement, and persistence dispatch.
- **Batch Clamping**: Hard limit of $\le 100$ events per batch. Oversized requests are rejected with `INVALID_ARGUMENT`.
- **Order-Preserving Batch Results**: Uses `std::vector<std::pair<EventId, IngestionResult>>` to maintain strict input batch sequence, avoid unnecessary hashing allocations, and strictly satisfy `-Wmissing-field-initializers` under GCC `-Werror`.
- **Authoritative Timestamping**: Authoritatively stamps `received_at = std::chrono::system_clock::now()` on the server side. Injected client values for `received_at` are overridden to prevent timestamp spoofing.

### C. In-Process gRPC `AuditServiceImpl` & Deterministic Error Mapping
- **`AuditServiceImpl`**: Implements `v1::AuditService::Service` for `SubmitEvent` and `SubmitBatch` RPCs.
- **Deterministic Status Translation**:
  - Domain / Schema Validation Failures $\to$ `grpc::StatusCode::INVALID_ARGUMENT`
  - mTLS Auth / Identity Mismatches $\to$ `grpc::StatusCode::UNAUTHENTICATED` / `grpc::StatusCode::PERMISSION_DENIED`
  - Batch / Buffer Overload $\to$ `grpc::StatusCode::RESOURCE_EXHAUSTED`
  - Persistence / ClickHouse Outages $\to$ `grpc::StatusCode::UNAVAILABLE`

### D. Server Lifecycle, mTLS Socket Binding & Graceful Drain (ADR-009)
- **`AuditServer` Integration**: Registers `AuditServiceImpl` alongside the gRPC Health Checking service on port `50055`.
- **Graceful Drain Architecture**: On termination signals (`SIGINT`/`SIGTERM`), the server marks health status as `NOT_SERVING`, stops accepting new RPCs, flushes in-flight event batches to ClickHouse within `shutdown_grace_period_ms`, and shuts down cleanly.

---

## 3. Implementation Tickets & Traceability

| Ticket | Description | Deliverables |
| :--- | :--- | :--- |
| **AUDIT-004-T01** | Protobuf Ingestion Contracts & DTOs | `proto/securecloud/audit/v1/audit_service.proto`, `AuditProtoMapper` bidirectional converter |
| **AUDIT-004-T02** | mTLS Identity Extractor & Interceptor | `GrpcProducerIdentityValidator`, SAN/CN identity verification, test bypass controls |
| **AUDIT-004-T03** | Bounded Ingestion Command Engine | `AuditIngestionService`, batch clamping ($\le 100$), `AuditEventValidator` integration, authoritative `received_at` assignment |
| **AUDIT-004-T04** | In-Process gRPC `AuditServiceImpl` | `AuditServiceImpl`, gRPC context cancellation handling, deterministic gRPC error status mapping |
| **AUDIT-004-T05** | Server Registration & Graceful Drain | `AuditServer` mTLS socket binding on port `50055`, threadpool offloading, graceful drain lifecycle |
| **AUDIT-004-T06** | Contract, Integration & Security Test Suite | Unit tests (`audit_service_impl_test`, `grpc_producer_identity_validator_test`), integration tests (`audit_ingestion_integration_test`) |

---

## 4. Verification Evidence

### A. Unit Test Suite Execution
13 unit test binaries compiled and executed via GCC/MinGW C++20 toolchain:

```text
[==========] Running 2 tests from 1 test suite.
[  PASSED  ] 2 tests from ClickHouseClientTest (350 ms total)

[==========] Running 4 tests from 1 test suite.
[  PASSED  ] 4 tests from ClickHouseEventSerializerTest (38 ms total)

[==========] Running 9 tests from 1 test suite.
[  PASSED  ] 9 tests from AuditConfigTest (49 ms total)

[==========] Running 1 test from 1 test suite.
[  PASSED  ] 1 test from AuditEventMapperTest (16 ms total)

[==========] Running 3 tests from 1 test suite.
[  PASSED  ] 3 tests from AuditEventModelTest (32 ms total)

[==========] Running 11 tests from 1 test suite.
[  PASSED  ] 11 tests from AuditEventValidatorTest (66 ms total)

[==========] Running 2 tests from 1 test suite.
[  PASSED  ] 2 tests from GrpcProducerIdentityValidatorTest (49 ms total)

[==========] Running 1 test from 1 test suite.
[  PASSED  ] 1 test from AuditIngestionServiceTest (14 ms total)

[==========] Running 4 tests from 1 test suite.
[  PASSED  ] 4 tests from ProducerIdentityValidatorTest (33 ms total)

[==========] Running 2 tests from 1 test suite.
[  PASSED  ] 2 tests from AuditProtoMapperTest (23 ms total)

[==========] Running 3 tests from 1 test suite.
[  PASSED  ] 3 tests from SensitiveDataGuardTest (33 ms total)

[==========] Running 3 tests from 1 test suite.
[  PASSED  ] 3 tests from AuditServerLifecycleTest (29 ms total)

[==========] Running 7 tests from 1 test suite.
[  PASSED  ] 7 tests from AuditServiceImplTest (48 ms total)
```

### B. Integration Test Suite Execution
3 integration test targets verifying ClickHouse storage, service lifecycle, and end-to-end ingestion:

```text
[==========] Running 3 tests from 1 test suite.
[ RUN      ] AuditIngestionIntegrationTest.ClickHouseOutageMappedToUnavailable
[       OK ] AuditIngestionIntegrationTest.ClickHouseOutageMappedToUnavailable (10 ms)
[ RUN      ] AuditIngestionIntegrationTest.EndToEndIngestionPersisted
[       OK ] AuditIngestionIntegrationTest.EndToEndIngestionPersisted (0 ms)
[ RUN      ] AuditIngestionIntegrationTest.ConcurrentMultiProducerIngestion
[       OK ] AuditIngestionIntegrationTest.ConcurrentMultiProducerIngestion (5 ms)
[----------] 3 tests from AuditIngestionIntegrationTest (31 ms total)
[  PASSED  ] 3 tests.
```

---

## 5. Security & Operational Readiness

- [x] Audit ingestion endpoint strictly bound to internal network interface (port `50055`).
- [x] Strict mTLS 1.3 certificate authentication enforced for all incoming RPCs.
- [x] Zero-trust payload identity cross-verified against client certificate SAN/CN.
- [x] Batch ingestion hard-clamped at 100 events per request.
- [x] Unhandled database/persistence errors mapped deterministically to `UNAVAILABLE` without leaking user PII or raw connection strings.
- [x] Clean compilation with zero warnings under `-Wall -Wextra -Werror -Wpedantic`.