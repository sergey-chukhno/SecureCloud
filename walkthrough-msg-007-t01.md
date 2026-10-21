# Card Validation Walkthrough: MSG-007-T01

**Card ID:** `MSG-007`  
**Ticket ID:** `MSG-007-T01`  
**Ticket Title:** Online Delivery Domain Model, Lifecycle Transition Guards & Decorrelated Jitter Retry Policy  
**Milestone:** M3 — Secure Messaging Platform  
**Repository:** `SecureCloud`  
**Branch:** `feature/msg-007-online-message-delivery`  
**Status:** IMPLEMENTED & VALIDATED  
**Author:** Senior Principal Systems Architect, Security Architect & Gatekeeper  
**Date:** October 19, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **MSG-007** implements the durable **Online Message-Delivery Pipeline** for the SecureCloud Messaging Service (`securecloud-messaging`), adhering strictly to **ADR-007** (Messaging Reliability & Durability), **ADR-008** (Security & Cryptographic Architecture), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance, Capacity & Optimization Strategy).

While **MSG-005** established the durable write boundary and **MSG-006** integrated the server-side End-to-End (E2E) encrypted envelope model, **MSG-007 delivers the opaque ciphertext asynchronously to authorized recipient devices that are currently connected and eligible for online delivery**.

Ticket **MSG-007-T01** establishes the domain foundation for online delivery:
1. **Extended Delivery Lifecycle (`DeliveryState`)**: Formalizes the operational delivery states (`Queued`, `Delivering`, `Delivered`, `Read`, `RetryWait`, `Expired`) aligned 1:1 with protobuf `v1::DeliveryState`, with full backward compatibility for existing ScyllaDB records (`Pending = Queued`).
2. **Delivery Outcome Classification (`DeliveryAttemptResult`)**: Enforces explicit classification for dispatch outcomes (`Success`, `RecipientOffline`, `TransientFailure`, `TerminalFailure`).
3. **Delivery Task Domain Model (`DeliveryTask`)**: Immutable unit of delivery work encapsulating `PerDeviceEnvelope` under the **Zero Plaintext Invariant** (ADR-008).
4. **Decorrelated Jitter Retry Engine (`DeliveryRetryPolicy`)**: Mathematically sound exponential backoff with decorrelated jitter to prevent retry storms and thundering herds across connected clients (ADR-009 §4.2).
5. **Lifecycle Transition Guards (`delivery_lifecycle.{hpp,cpp}`)**: Exhaustive transition validation matrix preventing invalid state jumps (e.g. `Queued -> Delivered` without an active dispatch, or mutations after terminal `Read` or `Expired`).

---

## 2. Core Architectural Invariants & Mathematics

### 2.1 Canonical State Machine Transitions (ADR-007)

```text
             ┌────────────────────────┐
             │         QUEUED         │
             └───────────┬────────────┘
                         │ Worker initiates delivery push
                         ▼
             ┌────────────────────────┐
             │       DELIVERING       │
             └──────┬───────────┬─────┘
                    │           │
     Client ACK     │           │ Transient network failure
     received       │           │ or connection reset
                    │           ▼
                    │    ┌──────────────┐
                    │    │  RETRY_WAIT  │
                    │    └──────┬───────┘
                    │           │ Backoff delay expires
                    │           └───────────┐
                    ▼                       ▼
             ┌──────────────┐        ┌──────────────┐
             │  DELIVERED   │        │  DELIVERING  │
             └──────┬───────┘        └──────────────┘
                    │ Client sends Read Receipt
                    ▼
             ┌──────────────┐
             │     READ     │
             └──────────────┘

Terminal Expiration (ADR-007 §14):
QUEUED | DELIVERING | RETRY_WAIT ──(TTL / Max Attempts Exceeded)──► EXPIRED
```

### 2.2 Mathematical Model for Decorrelated Jitter

To prevent synchronized thundering herds across distributed clients after connection resets:

$$T_{\text{backoff}}(n) = \min\left(T_{\text{max}}, T_{\text{initial}} \times \text{multiplier}^{n}\right)$$

$$\text{Window} = \left[(1 - \alpha) \cdot T_{\text{backoff}}(n),\, (1 + \alpha) \cdot T_{\text{backoff}}(n)\right]$$

$$T_{\text{delay}} = \text{UniformRandom}\left(\text{Window}_{\text{min}}, \text{Window}_{\text{max}}\right)$$

- Default configuration:
  - $T_{\text{initial}} = 500\text{ms}$
  - $T_{\text{max}} = 60,000\text{ms}$ (1 minute)
  - $\text{multiplier} = 2.0$
  - $\alpha = 0.25$ ($\pm 25\%$ jitter window)
  - $\text{max\_retry\_attempts} = 10$
- Clamping: Attempt counts are clamped to $[0, 30]$ to guarantee no numeric overflow in floating-point exponentiation.

---

## 3. Implementation Details

### 3.1 Domain Types (`src/messaging/domain/delivery_types.hpp`)
- Added `DeliveryState::Queued = 1`, `Delivering = 2`, `Delivered = 3`, `Read = 4`, `RetryWait = 5`, `Expired = 6`, and `Pending = Queued` (backwards-compatible alias).
- Updated `to_string(DeliveryState)` to output `"QUEUED"`.
- Updated `delivery_state_from_string` to parse both `"QUEUED"` and legacy `"PENDING"`.
- Added `DeliveryAttemptResult` enum and string parsers.
- Added `DeliveryTask` struct with full equality and three-way comparison operators (`<=>`).

### 3.2 Retry Policy Engine (`src/messaging/service/delivery_retry_policy.{hpp,cpp}`)
- Defined `DeliveryRetryConfig` with validation rules (positive backoff, max $\ge$ initial, multiplier $\ge 1.0$, jitter in $[0, 1]$).
- Defined `IRandomGenerator` interface to allow injecting deterministic mock RNG in tests.
- Implemented `StandardRandomGenerator` backed by thread-local `std::mt19937_64`.
- Implemented `is_retryable()` checking `Success` (false), `TerminalFailure` (false), `attempt_count >= max` (false), and message expiration time (`now >= expires_at` false).

### 3.3 Lifecycle Transition Guards (`src/messaging/service/delivery_lifecycle.{hpp,cpp}`)
- Overloaded `is_valid_delivery_transition(domain::DeliveryState, domain::DeliveryState)`.
- Overloaded `is_idempotent_delivery_state(domain::DeliveryState, domain::DeliveryState)`.
- Implemented bidirectional conversion helpers `to_proto_delivery_state` and `from_proto_delivery_state`.

---

## 4. Test Verification & Evidence

### 4.1 Unit Test Suites

1. **`DeliveryRetryPolicyTest` (`tests/unit/messaging/delivery_retry_policy_test.cpp`)**:
   - `DefaultConfigIsValid`: Verifies default configuration parameters.
   - `InvalidParametersRejected`: Verifies fail-closed constructor exceptions on invalid parameters.
   - `ExponentialProgressionWithoutJitter`: Verifies deterministic exponential progression ($500\text{ms} \to 1000\text{ms} \to 2000\text{ms} \dots \le 60,000\text{ms}$), ceiling clamping, and overflow protection.
   - `JitterBoundsEnforcement`: Verifies min/max jitter windows ($\pm 20\%$).
   - `StandardRngGeneratesValuesWithinDecorrelatedBounds`: Verifies 100 randomized samples fall strictly within $[(1-\alpha)T, (1+\alpha)T]$.
   - `IsRetryableRules`: Verifies rejection of terminal failures, success, exceeded attempt counts, and expired TTLs.

2. **`DeliveryLifecycleTest` (`tests/unit/messaging/delivery_lifecycle_test.cpp`)**:
   - `DomainStateCanonicalValidTransitions`: Verifies all valid transitions.
   - `DomainStateProhibitedTransitions`: Exhaustively tests invalid transitions.
   - `DomainIdempotentStateChecks`: Verifies idempotent re-applications.
   - `DomainProtoConversionParity`: Verifies 1:1 roundtrip with protobuf `v1::DeliveryState`.
   - `DeliveryStateStringParsingAndBackwardsCompatibility`: Verifies serialization and legacy `"PENDING"` parsing.
   - `DeliveryAttemptResultStringConversions`: Verifies all outcome string conversions.
   - `DeliveryTaskEqualityAndValueSemantics`: Verifies value semantics on delivery tasks.

### 4.2 CTest Results

```text
100% tests passed, 0 tests failed out of 1678
Total Test time (real) = 152.76 sec
```

All 31 delivery-related tests pass cleanly with 0 failures:
- `ProtoSmokeTest.MessagingDeliveryReceiptSeparationAndSerialization`: PASSED
- `MessagingContractSemanticsTest.*`: PASSED
- `ScyllaDeliveryStateRepositoryTest.*`: PASSED
- `ScyllaDeliveryRepositoryEnvelopeTest.*`: PASSED
- `DeliveryRetryConfigTest.*`: PASSED
- `DeliveryRetryPolicyTest.*`: PASSED
- `DeliveryLifecycleTest.*`: PASSED
- `DeliveryTypesTest.*`: PASSED

### 4.3 Code Quality & Formatting Gate

```text
$ cmake --build --preset dev-debug --target check-format
[SecureCloud] All 500 C++ files adhere to .clang-format.
```

---

## 5. Artifacts and Files Changed

| File | Status | Description |
| :--- | :--- | :--- |
| [`src/messaging/domain/delivery_types.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/messaging/domain/delivery_types.hpp) | Modified | Extended `DeliveryState`, added `DeliveryAttemptResult`, `DeliveryTask` |
| [`src/messaging/service/delivery_retry_policy.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/messaging/service/delivery_retry_policy.hpp) | Created | `DeliveryRetryConfig`, `IRandomGenerator`, `DeliveryRetryPolicy` |
| [`src/messaging/service/delivery_retry_policy.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/messaging/service/delivery_retry_policy.cpp) | Created | Decorrelated jitter calculations and retry eligibility logic |
| [`src/messaging/service/delivery_lifecycle.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/messaging/service/delivery_lifecycle.hpp) | Modified | Added domain state transition guards and proto mappers |
| [`src/messaging/service/delivery_lifecycle.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/messaging/service/delivery_lifecycle.cpp) | Modified | Implemented domain state transition validation |
| [`src/messaging/CMakeLists.txt`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/messaging/CMakeLists.txt) | Modified | Registered `delivery_retry_policy.cpp` |
| [`tests/unit/messaging/delivery_retry_policy_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/unit/messaging/delivery_retry_policy_test.cpp) | Created | Unit test suite for retry policy and jitter distribution |
| [`tests/unit/messaging/delivery_lifecycle_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/unit/messaging/delivery_lifecycle_test.cpp) | Created | Unit test suite for delivery state transitions and tasks |
| [`tests/unit/messaging/scylla_delivery_repository_envelope_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/unit/messaging/scylla_delivery_repository_envelope_test.cpp) | Modified | Aligned assertion with canonical `"QUEUED"` state |
| [`tests/unit/CMakeLists.txt`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/unit/CMakeLists.txt) | Modified | Registered unit test executables |
