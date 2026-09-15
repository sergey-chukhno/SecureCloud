# SecureCloud — Testing Strategy

**Status:** Implementation baseline
**Scope:** Automated testing, security testing, resilience testing, integration testing, performance validation

---

## 1. Purpose

This document defines **what must be tested, at which level, and what constitutes a passing implementation**.

It does not redefine architecture or functional requirements. Those are defined by:

* `docs/architecture/`
* `docs/design/`
* `docs/api/`
* `docs/implementation/`

The objective is to detect:

* incorrect business behavior
* persistence/durability failures
* concurrency bugs
* contract incompatibilities
* security regressions
* distributed failure handling errors
* resource exhaustion
* performance regressions

---

# 2. Test Stack

| Area               | Tool                                               |
| ------------------ | -------------------------------------------------- |
| C++ unit tests     | GoogleTest                                         |
| Qt/client tests    | Qt Test + GoogleTest where appropriate             |
| Test execution     | CTest                                              |
| Static analysis    | clang-tidy                                         |
| Formatting         | clang-format                                       |
| Memory errors      | AddressSanitizer                                   |
| Undefined behavior | UBSan                                              |
| Threading errors   | ThreadSanitizer                                    |
| Coverage           | llvm-cov / gcov-compatible tooling                 |
| Fuzzing            | libFuzzer                                          |
| HTTP/API           | OpenAPI-generated/client test tooling where useful |
| gRPC               | Native gRPC test clients + GoogleTest              |
| PostgreSQL         | Isolated test database                             |
| ScyllaDB           | Isolated test instance/container                   |
| MinIO              | Isolated test instance/container                   |
| ClickHouse         | Isolated test instance/container                   |

Tests must run against **isolated test infrastructure**. Production credentials, keys, databases, or data must never be used.

---

# 3. Test Repository Structure

```text
tests/
├── unit/
│   ├── common/
│   ├── gateway/
│   ├── auth/
│   ├── messaging/
│   ├── files/
│   ├── audit/
│   └── client/
│
├── integration/
│   ├── gateway/
│   ├── auth/
│   ├── messaging/
│   ├── files/
│   └── audit/
│
├── contract/
│   ├── rest/
│   └── grpc/
│
├── security/
│   ├── authentication/
│   ├── authorization/
│   ├── crypto/
│   ├── device/
│   ├── input-validation/
│   └── data-leakage/
│
├── resilience/
│   ├── auth/
│   ├── messaging/
│   ├── files/
│   └── infrastructure/
│
├── e2e/
│
└── performance/
    ├── messaging/
    ├── synchronization/
    └── files/
```

Test code follows the same ownership boundaries as production code.

---

# 4. Test Levels

## 4.1 Unit Tests

Test isolated domain/application components without real network or external infrastructure.

Required for:

* validators
* state machines
* authorization policies
* idempotency logic
* retry calculations
* deadline handling
* token validation
* MFA verification logic
* message envelope processing
* delivery state transitions
* synchronization cursor logic
* file transfer state transitions
* chunk validation
* resource-limit calculations
* error mapping

Unit tests must cover:

* normal case
* invalid input
* boundary values
* invalid state transition
* dependency failure
* cancellation where applicable

---

# 5. Service Integration Tests

Integration tests use the real service plus its owned infrastructure.

## Gateway

Test:

* valid access token → request accepted
* expired token → rejected
* invalid signature → rejected
* insufficient scope → rejected
* missing authentication → rejected
* Auth unavailable → request fails closed
* downstream timeout → correct mapped error
* idempotent request with repeated request ID
* streaming request respects resource limits
* client cancellation propagates downstream

Gateway must never return success when the downstream operation has not been durably confirmed.

---

## Auth

Test:

* valid credentials
* invalid credentials
* account/session state
* access-token expiration
* access-token signature validation
* refresh-token rotation
* refresh-token reuse detection
* revoked session
* TOTP success
* TOTP failure
* MFA-required operation without MFA
* device registration authorization
* device revocation
* revoked device rejected
* crypto-directory updates
* prekey consumption
* concurrent refresh attempts

Particularly important:

> Two concurrent uses of the same refresh token must not both successfully rotate it.

---

## Messaging

Test:

### Message acceptance

```text
request
 → validation
 → authorization
 → persistence
 → delivery state
 → outbox
 → durable success
```

Verify that success is returned **only after the required durable state exists**.

Test failures injected at each persistence step.

### Idempotency

Send the same logical command multiple times with the same idempotency key.

Expected:

```text
first request  → message created
duplicate      → same logical result
no duplicate message
no duplicate delivery
```

Same key + different payload must be rejected as a conflict.

### Delivery

Test:

* online recipient
* offline recipient
* reconnecting recipient
* delivery timeout
* temporary recipient failure
* permanent failure
* delivery retry
* recipient ACK
* duplicate ACK
* duplicate delivery
* client deduplication
* read receipt
* revoked device

### Concurrency

Test:

* multiple messages to same recipient
* multiple recipients
* multiple devices
* simultaneous delivery workers
* simultaneous synchronization
* simultaneous read receipts
* concurrent updates of delivery state

The test suite must detect races using ThreadSanitizer.

---

# 6. Synchronization Tests

Test:

* initial synchronization
* empty synchronization
* incremental synchronization
* valid cursor
* stale cursor
* invalid cursor
* cursor after reconnect
* duplicate synchronization request
* concurrent synchronization requests
* messages arriving during synchronization
* client disconnect during synchronization
* server restart during synchronization

Verify that the client never silently skips a durable message.

---

# 7. Files Tests

## Upload

Test:

* small file
* large file
* multiple chunks
* missing chunk
* duplicate chunk
* out-of-order chunks
* invalid chunk index
* corrupted chunk
* interrupted upload
* resumed upload
* client cancellation
* storage failure
* finalization failure

Expected property:

```text
duplicate chunk ≠ duplicate stored content
```

## Download

Test:

* complete download
* partial download
* resumed download
* invalid starting chunk
* unavailable file
* deleted/expired file
* interrupted stream
* slow client
* storage timeout

## Resource limits

Test behavior when:

* maximum uploads reached
* maximum downloads reached
* memory buffer limit reached
* stream limit reached
* storage connection pool exhausted

The service must reject or apply backpressure rather than allocate unbounded resources.

---

# 8. Audit Tests

Test:

* security event generated
* audit event generated through outbox
* audit dependency unavailable
* outbox retry
* service restart with pending events
* duplicate event processing
* malformed event
* poison event handling

Critical property:

> Audit failure must not cause loss of an operation that has already satisfied its durable acceptance requirements.

---

# 9. Contract Tests

Contract tests verify that implementations conform to:

* `openapi/openapi.yaml`
* `proto/securecloud/`

Required checks:

* request schema
* response schema
* required fields
* field types
* enum values
* error codes
* authentication requirements
* idempotency behavior
* streaming semantics
* backward compatibility

For Protobuf:

* never reuse field numbers
* never silently change field meaning
* test compatibility between supported client/server versions

Contract tests run independently from business-logic unit tests.

---

# 10. Security Test Matrix

At minimum:

| Test                                  | Expected result                |
| ------------------------------------- | ------------------------------ |
| Missing token                         | Reject                         |
| Expired token                         | Reject                         |
| Invalid token signature               | Reject                         |
| Wrong audience/issuer                 | Reject                         |
| Revoked session                       | Reject                         |
| Insufficient scope                    | Reject                         |
| MFA bypass attempt                    | Reject                         |
| Revoked device                        | Reject future operations       |
| Unauthorized participant access       | Reject                         |
| Malformed message envelope            | Reject safely                  |
| Oversized request                     | Reject                         |
| Oversized file/chunk                  | Reject                         |
| Invalid IDs                           | Reject                         |
| Invalid state transition              | Reject                         |
| Invalid ciphertext                    | Fail closed                    |
| Crypto failure                        | No insecure fallback           |
| TLS/mTLS identity failure             | Reject                         |
| Service with wrong certificate        | Reject                         |
| Service authorization violation       | Reject                         |
| Private key sent to backend           | Reject / test never permits it |
| Plaintext message accidentally logged | Must not occur                 |
| Credential/token logged               | Must not occur                 |
| Secrets in configuration              | Must not occur                 |

Security tests must also verify that rejected requests do not leave unauthorized durable state.

---

# 11. Fuzz Testing

Use libFuzzer where the input surface is suitable.

Initial fuzz targets:

* REST request parsing
* Protobuf message parsing
* message-envelope parsing
* identifier parsing
* token parsing/validation
* file metadata parsing
* chunk metadata
* synchronization requests
* error-response parsing

Fuzz tests must verify:

* no crash
* no sanitizer violation
* no infinite loop
* no uncontrolled memory growth
* invalid input produces controlled failure

Crypto primitives themselves are not reimplemented or fuzzed as custom algorithms; the project uses the selected vetted library.

---

# 12. Resilience / Failure-Injection Tests

Tests must explicitly reproduce failures defined in:

`docs/implementation/error-handling-and-retry.md`

Required cases:

### Network

* connection refused
* connection reset
* timeout
* delayed response
* unavailable service
* dropped connection during streaming

### Database

* database unavailable
* connection pool exhausted
* transaction failure
* transaction timeout
* temporary database failure

### Messaging

* worker failure
* delivery timeout
* duplicate delivery
* service restart during delivery
* service restart after durable acceptance but before response

### Files

* MinIO unavailable
* interrupted upload
* interrupted download
* restart during finalization
* missing chunk
* storage timeout

### Audit

* Audit unavailable
* outbox delivery failure
* service restart with pending events

For each failure, verify the expected result rather than merely checking that an error occurred.

---

# 13. Restart / Recovery Tests

Every stateful service must be tested across restart.

### Messaging

```text
persist message
→ restart service
→ recover state
→ continue delivery/synchronization
```

Verify:

* no accepted message disappears
* no delivery state is silently lost
* pending outbox events remain available
* duplicate processing is safe

### Auth

Verify:

* sessions
* refresh-token state
* device revocation
* MFA state
* crypto-directory state

survive restart.

### Files

Verify:

* transfer state
* chunk state
* finalized objects
* pending cleanup/finalization

survive restart.

---

# 14. Concurrency Tests

Concurrency tests are mandatory for:

* idempotency
* token rotation
* message submission
* delivery state updates
* synchronization
* read receipts
* file chunk upload
* resource limits
* shutdown

Typical pattern:

```text
N concurrent operations
        ↓
same resource / same key
        ↓
verify invariant
```

Examples:

* 100 concurrent requests with the same idempotency key → exactly one creation.
* Multiple workers processing the same delivery → no incorrect duplicate state.
* Concurrent refresh-token use → only valid rotation wins.
* Concurrent chunk uploads → final transfer remains consistent.

Run concurrency tests under ThreadSanitizer.

---

# 15. Performance Tests

Performance tests are **validation/benchmark tests**, not substitutes for correctness tests.

Initial targets come from the architecture:

* peak target: **10,000 accepted messages/s**
* bounded memory
* predictable latency
* no unbounded queues
* no thread-per-message
* no hot global delivery queue

Measure separately:

### Messaging

* acceptance throughput
* p50/p95/p99 acceptance latency
* delivery throughput
* synchronization throughput
* CPU
* memory
* DB utilization
* connection pools
* queue depth

### Files

* upload throughput
* download throughput
* concurrent transfers
* memory usage
* chunk processing rate

Performance tests must record the exact configuration and workload.

A performance regression is not fixed by weakening correctness or security guarantees.

---

# 16. CI Gates

## Every Pull Request

Must pass:

1. build
2. unit tests
3. contract tests affected by changes
4. clang-tidy
5. formatting check
6. AddressSanitizer tests
7. basic integration tests

## Main Branch

Additionally:

* full integration suite
* security tests
* resilience tests
* ThreadSanitizer suite
* restart/recovery tests

## Release / MVP Validation

Additionally:

* full E2E suite
* fuzzing campaign
* performance benchmarks
* failure-injection suite
* final security regression suite

A failed security or correctness test blocks merge.

---

# 17. Test Data Rules

Tests must use deterministic synthetic data where possible.

Never commit:

* real passwords
* production tokens
* production certificates
* private keys
* real user data
* real message content
* production database dumps

Crypto tests must generate dedicated test keys.

Tests involving encryption must verify both:

```text
correct key → successful operation
wrong/revoked key → failure
```

---

# 18. Definition of Done for Tests

A feature is test-complete when:

* normal behavior is tested
* invalid input is tested
* important boundary conditions are tested
* persistence behavior is tested where applicable
* failure behavior is tested where applicable
* security-sensitive paths have negative tests
* concurrency-sensitive paths have concurrency tests
* relevant API contracts are tested
* sanitizers pass
* tests are deterministic and isolated
* CI executes the appropriate test suite

For critical security/durability behavior, **happy-path tests alone are never sufficient**.

---

# 19. Implementation Order

Implement the test infrastructure in this order:

```text
1. CTest + GoogleTest foundation
2. Unit-test structure
3. Test database/container infrastructure
4. Auth integration tests
5. Gateway integration + contract tests
6. Messaging durability/idempotency tests
7. Messaging delivery/synchronization tests
8. Files transfer/resume tests
9. Audit/outbox tests
10. Security regression tests
11. Failure-injection tests
12. Restart/recovery tests
13. Sanitizer CI
14. Fuzzing
15. Performance benchmarks
16. Full E2E suite
```

Tests are implemented **alongside the corresponding feature**, not after the entire service has been completed.
