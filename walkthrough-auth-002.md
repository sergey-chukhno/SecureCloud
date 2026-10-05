# SecureCloud — AUTH-002 Card Implementation & Validation Report

**Card ID**: `AUTH-002`  
**Card Title**: *Establish Auth PostgreSQL Persistence*  
**Branch**: `feature/auth-002-establish-auth-postgresql-persistence`  
**Base Commit**: `6e4200a` (`main`)  
**Status**: **100% Implemented & Validated**  
**Date**: 2026-10-05  

---

## 1. Executive Summary

Card **AUTH-002** establishes the authoritative persistence infrastructure for the SecureCloud Auth service, enforcing strict separation of concerns, cryptographic data model invariants, monotonic lifecycle progression, optimistic concurrency control (OCC), single-use refresh token rotation, compromise reuse containment, and host isolation.

All 6 implementation tickets (`AUTH-002-T01` through `AUTH-002-T06`) have been completed, unit-tested, and verified against a live containerized PostgreSQL 17 database (`127.0.0.1:5433`).

---

## 2. Deep Architectural Decisions

### A. Optimistic Concurrency Control (OCC) vs. Pessimistic Locking

#### How OCC Operates in SecureCloud:
1. **Monotonic Version Counter**: Every mutable state entity (`users`, `mfa_configurations`) contains a `version BIGINT NOT NULL DEFAULT 1` column.
2. **Version Retrieval**: When an application thread queries a record, it retrieves the current version (e.g. `expected_version = 1`).
3. **Atomic Conditional Mutation**: When mutating the record, the repository executes a conditional `UPDATE`:
   ```sql
   UPDATE users 
   SET credential_identifier = $1, password_verifier = $2, password_algorithm = $3,
       password_updated_at = $4, account_status = $5, updated_at = $6, version = version + 1
   WHERE user_id = $7 AND version = $8;
   ```
4. **Collision Detection**:
   - PostgreSQL executes the `WHERE user_id = $7 AND version = $8` check atomically under row lock during statement execution.
   - If another thread updated the row in the interim, `version` has already incremented to `2`, so `affected_rows() == 0`.
   - The repository verifies if the row exists in the database. If it exists, an `OptimisticLockException` is thrown; if not found, an `EntityNotFoundException` is thrown.

#### Why We Choose OCC over Pessimistic Locking (`SELECT ... FOR UPDATE`):
- **Zero Read Lock Overhead**: In authentication services, reads heavily outnumber writes. OCC eliminates lock contention on read queries, maximizing query throughput and connection pool efficiency.
- **Deadlock Elimination**: Pessimistic row locking requires holding locks across transaction spans. If concurrent operations lock rows in differing order or encounter network jitter, connection exhaustion and deadlocks occur.
- **Stateless gRPC Microservice Compatibility**: In distributed microservices, client interactions span independent, stateless RPC requests. OCC detects concurrent modifications without keeping database transactions open across network RPC round-trips while users type or think.

#### Real-World Origins of Concurrent User Mutations:
- **Multi-Device / Multi-Tab Actions**: A user changes their password on mobile while a background browser tab triggers an account sync or token refresh.
- **Multi-Threaded gRPC Worker Pool**: Two concurrent RPC requests for the same user landing on different worker threads simultaneously.
- **Admin / Security Action vs. User Mutation Race**: An administrative watchdog disables an account (`account_status = Disabled`) while the user simultaneously updates profile settings. OCC prevents the user's thread from overwriting the security lock ("Lost Update" prevention).
- **Network Retries / Duplicated RPCs**: Duplicate requests sent over flaky connections are safely resolved; the first commits, the second encounters an OCC collision.

---

### B. Forward-Only Schema Migrations vs. Rollback Scripts

#### Why Forward-Only Migrations are Required:
1. **Irreversibility of Real Production Data**: In distributed cloud databases, rollback scripts (`DOWN.sql`) are an anti-pattern. If a column or table is dropped in production, rolling back the schema destroys all customer data written since the migration applied.
2. **Deterministic Forward Progress (Roll-Forward)**: When a bug or unexpected behavior occurs in a newly deployed schema, the only safe operational path is **rolling forward** with an explicit corrective migration (e.g. `V004__fix_constraints.sql`).
3. **Immutable SHA-256 Checksums**: Every migration script is normalized (CRLF $\to$ LF) and hashed using SHA-256. `MigrationRunner` verifies that existing recorded checksums in `schema_migrations` match the current codebase, preventing silent drift or out-of-order execution.
4. **Advisory Lock Serialization**: Migrations acquire a 64-bit PostgreSQL advisory lock (`0x5343415554483031LL` / `'SCAUTH01'`) before execution, guaranteeing that multiple autoscaling Auth replicas starting simultaneously serialize cleanly without schema corruption.

---

### C. Refresh Token Rotation Atomicity & Compromise Reuse Detection

#### The Single-Use Invariant:
Refresh tokens are strictly single-use credentials. Rotation executes inside a single atomic `pqxx::work` transaction:
```
+---------------------------------------------------------------------------------------+
|                                ATOMIC TRANSACTION                                     |
|                                                                                       |
|  1. Verify old token is 'Active' (WHERE id = $old AND status = 'Active')             |
|  2. Insert new token with status = 'Active'                                           |
|  3. Update old token to status = 'Rotated', set rotated_at, link replaced_by_id       |
|                                                                                       |
|  [COMMIT] -> Both succeed simultaneously; NO intermediate or orphaned state possible |
|  [ROLLBACK on failure] -> Old token remains Active; No new token created              |
+---------------------------------------------------------------------------------------+
```
If any error occurs, the transaction rolls back completely. The old token remains active, no orphaned child token exists, and zero valid tokens are lost.

#### Compromise Reuse Detection (RFC 6819 & OAuth 2.0 Security BCP):
1. **Tokens are Retired, Never Deleted**: When a refresh token is rotated, it is not removed. Its status is changed to `TokenStatus::Rotated`, and it points to its replacement via `replaced_by_token_id`.
2. **Replay Detection**: If a client presents a token verifier whose database status is **already `Rotated`**, this is an unambiguous cryptographic indicator of an active breach:
   - Either **the attacker is replaying an old token** that the legitimate user already rotated, or
   - **The attacker already used the token**, and now the legitimate user is attempting to use the same token.
3. **Immediate Automated Quarantine (`handle_token_reuse`)**:
   The moment reuse is detected, the repository immediately triggers emergency revocation in a single transaction:
   ```sql
   -- 1. Terminate the compromised session immediately
   UPDATE sessions SET session_status = 'Revoked', revoked_at = NOW() WHERE session_id = $session_id;

   -- 2. Revoke the active child token that was granted during the previous rotation!
   UPDATE refresh_tokens SET token_status = 'Revoked', revoked_at = NOW() 
   WHERE session_id = $session_id AND token_status = 'Active';
   ```
   The attacker's stolen access is killed instantly across all devices, the breach is quarantined, and the user is forced to re-authenticate with primary credentials and MFA.

---

## 3. Implementation Tickets & Traceability

Commits on `feature/auth-002-establish-auth-postgresql-persistence` adhere strictly to the ticket sequence:

| Ticket | Description | Commits |
| :--- | :--- | :--- |
| **AUTH-002-T01** | PostgreSQL schema migrations (`V001`, `V002`, `V003`), SHA-256 checksums, advisory locking (`0x5343415554483031`), and `MigrationRunner` | `09d1001` |
| **AUTH-002-T02** | Strong enums (11 enum classes), RFC 9562 `Uuid` (UUIDv7 value type with CSPRNG), `timestamp.hpp` (UTC ISO-8601), domain entity structs, and `libpqxx` row mappers | `5ac4552` |
| **AUTH-002-T03** | `PostgresUserRepository` and `PostgresDeviceRepository` with optimistic concurrency control (`version`), unique constraint mapping, device revocation cascading, and port 5432 guards | `332e42f` |
| **AUTH-002-T04** | `PostgresSessionRepository` and `PostgresRefreshTokenRepository` with monotonic step-up, atomic token rotation, and compromise reuse detection | `ed96eda` |
| **AUTH-002-T05** | `PostgresDevicePublicKeyRepository` (raw binary `BYTEA` public keys, key replacement linking) and `PostgresMfaRepository` (encrypted secrets, OCC status transitions, ephemeral challenge lifecycle) | `47ac136` |
| **AUTH-002-T06** | End-to-end integration test suite & pool contention harness running against live containerized PostgreSQL 17 on `127.0.0.1:5433` | `c15eb8b` |

---

## 4. Verification Evidence

### A. All 11 Live Integration Tests Passed (`tests/integration/auth_persistence_integration_test.cpp`)

Executed against containerized PostgreSQL 17 on `127.0.0.1:5433`:

```text
[==========] Running 11 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 11 tests from AuthPersistenceIntegrationTest
[ RUN      ] AuthPersistenceIntegrationTest.StrictPort5432Protection
[       OK ] AuthPersistenceIntegrationTest.StrictPort5432Protection (80 ms)
[ RUN      ] AuthPersistenceIntegrationTest.MigrationRunnerAppliesAllMigrationsAndIsIdempotent
[       OK ] AuthPersistenceIntegrationTest.MigrationRunnerAppliesAllMigrationsAndIsIdempotent (21 ms)
[ RUN      ] AuthPersistenceIntegrationTest.UserRepositoryCrudAndOptimisticConcurrency
[       OK ] AuthPersistenceIntegrationTest.UserRepositoryCrudAndOptimisticConcurrency (29 ms)
[ RUN      ] AuthPersistenceIntegrationTest.DeviceRepositoryRegistrationAndRevocation
[       OK ] AuthPersistenceIntegrationTest.DeviceRepositoryRegistrationAndRevocation (25 ms)
[ RUN      ] AuthPersistenceIntegrationTest.SessionRepositoryLifecycleAndStepUp
[       OK ] AuthPersistenceIntegrationTest.SessionRepositoryLifecycleAndStepUp (23 ms)
[ RUN      ] AuthPersistenceIntegrationTest.SessionRepositoryBulkRevocation
[       OK ] AuthPersistenceIntegrationTest.SessionRepositoryBulkRevocation (26 ms)
[ RUN      ] AuthPersistenceIntegrationTest.RefreshTokenRepositoryAtomicRotation
[       OK ] AuthPersistenceIntegrationTest.RefreshTokenRepositoryAtomicRotation (25 ms)
[ RUN      ] AuthPersistenceIntegrationTest.RefreshTokenRepositoryCompromiseReuseDetection
[       OK ] AuthPersistenceIntegrationTest.RefreshTokenRepositoryCompromiseReuseDetection (23 ms)
[ RUN      ] AuthPersistenceIntegrationTest.DevicePublicKeyRepositoryFidelityAndReplacement
[       OK ] AuthPersistenceIntegrationTest.DevicePublicKeyRepositoryFidelityAndReplacement (24 ms)
[ RUN      ] AuthPersistenceIntegrationTest.MfaRepositoryLifecycleAndChallengeExpiration
[       OK ] AuthPersistenceIntegrationTest.MfaRepositoryLifecycleAndChallengeExpiration (24 ms)
[ RUN      ] AuthPersistenceIntegrationTest.ConnectionPoolContentionUnderConcurrentLoad
[       OK ] AuthPersistenceIntegrationTest.ConnectionPoolContentionUnderConcurrentLoad (86 ms)
[----------] 11 tests from AuthPersistenceIntegrationTest (392 ms total)
[----------] Global test environment tear-down
[==========] 11 tests from 1 test suite ran. (392 ms total)
[  PASSED  ] 11 tests.
```

### B. Verification Orchestrator Summary (`python3 scripts/verify-local.py --preset dev-debug`)

```text
================ Verification Summary ================
  [PASSED]    0.42s  1. CMake Configure
  [PASSED]    0.48s  2. Formatting Check (.clang-format)
  [PASSED]    1.84s  3. Native Compilation & Build
  [PASSED]    0.11s  4. Protobuf & gRPC Contracts Validation
  [PASSED]   33.17s  5. CTest Execution Suite
-----------------------------------------------------
ALL CHECKS PASSED in 36.03s
```

---

## 5. Review & Quality Gate Checklist

- [x] Host PostgreSQL 14 on `localhost:5432` has **never** been contacted or modified (guarded by `PortForbiddenException`).
- [x] Schema DDL exactly mirrors `docs/data-model/02-auth-data-model.md`.
- [x] `pg_advisory_lock` (`0x5343415554483031`) protects all migration executions.
- [x] Passwords and refresh tokens are stored strictly as verifiers, never plaintext.
- [x] MFA secrets are stored as encrypted bytes (`BYTEA`).
- [x] Auth stores only public keys; private keys are never present.
- [x] Optimistic concurrency control (`version`) is enforced on `users` and `mfa_configurations`.
- [x] Refresh token rotation is atomic in a single SQL transaction.
- [x] Refresh token reuse triggers immediate session and token family revocation.
- [x] All timestamps use `TIMESTAMPTZ` and are generated/stored in UTC.
- [x] `tests/integration/auth_persistence_integration_test` passes all 11 tests with 0 timeouts.
- [x] `python3 scripts/verify-local.py` passes all 5 stages cleanly under `-Wall -Wextra -Werror -Wpedantic`.
