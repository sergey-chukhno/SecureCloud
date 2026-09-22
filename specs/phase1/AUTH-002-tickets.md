# AUTH-002 — Establish Auth PostgreSQL Persistence
## Phase 1 (M2: Authenticated Platform) Technical Specification & Implementation Tickets

**Card Identifier**: AUTH-002  
**Milestone**: M2 — Authenticated Platform  
**Document Status**: Implementation-Ready Technical Specification  
**Role**: Senior C++ Systems Architect, Security Architect, DevSecOps Reviewer & Technical Lead  
**Reviewer & Gatekeeper**: Sergey 

---

## 1. Executive Summary & Architectural Scope

Card **AUTH-002** establishes the authoritative relational persistence model, database schema migrations, strongly typed domain entities, transactional repository layer, and concurrency controls for the **SecureCloud Authentication Service** (`securecloud-auth`).

### Key Invariants & Architectural Boundaries
1. **Persistence Ownership (ADR-005)**:
   Auth exclusively owns its PostgreSQL database (`securecloud_auth`). No other service may access, query, or bind foreign keys to Auth tables. All cross-service entity references use opaque identifiers (UUIDv7).
2. **Strict Observational Host PostgreSQL 14 Guard**:
   The developer workstation host runs an active PostgreSQL 14 instance on `localhost:5432`. SecureCloud workflows MUST NEVER attempt to connect to, stop, restart, reconfigure, or bind to host port `5432`. SecureCloud PostgreSQL 17 binds strictly to `127.0.0.1:5433` (container port `5432`).
3. **Zero Plaintext Secrets at Rest (ADR-008, Data Model 2.4, 2.10, 2.12)**:
   - Plaintext passwords are **never** persisted. Auth stores only Argon2id password verifiers.
   - Plaintext refresh tokens are **never** persisted. Auth stores only cryptographic token verifiers (e.g. SHA-256 hash digests).
   - MFA secrets (TOTP) are stored encrypted at rest.
   - Auth **never** stores end-to-end device private keys.
4. **Deterministic Forward-Only Transactional Migrations**:
   Schema evolution is managed through embedded/versioned SQL migrations applied transactionally using PostgreSQL advisory locks (`pg_advisory_lock`), guaranteeing zero race conditions even if multiple service instances start concurrently.
5. **Optimistic Concurrency Control (OCC)**:
   Concurrent mutations on mutating entities (`users`, `mfa_configurations`) enforce optimistic concurrency via an explicit `version BIGINT` column (`UPDATE ... WHERE version = expected_version`).
6. **Explicit Out-of-Scope for AUTH-002**:
   - Argon2id hashing algorithm execution (owned by **AUTH-003**).
   - JWT access token generation and Ed25519 asymmetric signing (owned by **AUTH-005**).
   - TOTP RFC 6238 time-step algorithm calculation (owned by **AUTH-006**).
   - Full gRPC business RPC wiring (remains `UNIMPLEMENTED` from AUTH-001 until AUTH-003/004/005/006 connect the layers).

---

## 2. Dependency Graph

```text
               AUTH-001 (Auth Service Foundation)
               ├── securecloud::libpqxx
               ├── PostgresConnectionPool & PooledConnection
               └── AuthConfig (Database Credentials)
                          │
                          ▼
                     AUTH-002-T01
             (Schema DDL & Migration Runner)
                          │
                          ▼
                     AUTH-002-T02
             (Domain Entities, Enums & Value Types)
                          │
          ┌───────────────┴───────────────┐
          │                               │
          ▼                               ▼
     AUTH-002-T03                    AUTH-002-T04
(User & Device Repositories)   (Session & Refresh Token Repositories)
          │                               │
          └───────────────┬───────────────┘
                          │
                          ▼
                     AUTH-002-T05
             (Device Crypto Key & MFA Repositories)
                          │
                          ▼
                     AUTH-002-T06
             (Persistence Integration Test Suite &
              Concurrency Verification Harness)
```

---

## 3. Implementation Tickets

### AUTH-002-T01 — PostgreSQL Schema DDL Migrations & Transactional Migration Runner

1. **Ticket ID**: `AUTH-002-T01`
2. **Title**: PostgreSQL Schema DDL Migrations & Transactional Migration Runner
3. **Objective**: Author the baseline PostgreSQL 17 DDL migrations implementing the approved Auth Data Model (`docs/data-model/02-auth-data-model.md`) and implement an automated, transactional C++ migration runner with advisory locking.
4. **Architectural Purpose**: Guarantees deterministic, reproducible, and version-controlled schema setup across local development, CI test containers, and production deployments (ADR-005).
5. **Scope**:
   - Create migration directory `src/auth/db/migrations/` containing:
     - `V001__create_schema_migrations.sql`: Tracks applied versions, script checksums, execution times.
     - `V002__create_auth_tables.sql`: Tables `users`, `devices`, `device_public_keys`, `sessions`, `refresh_tokens`, `mfa_configurations`, `mfa_challenges`.
     - `V003__create_auth_indexes.sql`: Secondary indexes as specified in `02-auth-data-model.md` Section 2.16.
   - Implement `MigrationRunner` class in `src/auth/db/migration_runner.{hpp,cpp}`:
     - Acquires `pg_advisory_lock(0x5343415554483031)` (`SCAUTH01`) to serialize concurrent migration runners.
     - Checks applied versions in `schema_migrations`.
     - Executes pending migrations within individual transactions (`pqxx::work`).
     - Releases advisory lock upon completion or error.
   - Embed migration scripts into the binary or configure deterministic discovery via CMake resource paths.
   - Provide unit tests in `tests/unit/auth/migration_runner_test.cpp`.
6. **Explicit Out-of-Scope**: Altering existing M1 Compose volumes; writing data queries.
7. **Dependencies**: Upstream AUTH-001-T02 (`securecloud::libpqxx`), AUTH-001-T03 (`PostgresConnectionPool`). Downstream AUTH-002-T02, AUTH-002-T03.
8. **Exact Repository Starting Point**: `src/auth/db/`, `src/auth/CMakeLists.txt`.
9. **Files/Directories to Inspect**: `docs/data-model/02-auth-data-model.md` (Sections 2.3, 2.5, 2.7, 2.9, 2.10, 2.12, 2.13, 2.16), `src/auth/db/postgres_connection_pool.hpp`.
10. **Files/Directories to Create**:
    - `src/auth/db/migrations/V001__create_schema_migrations.sql`
    - `src/auth/db/migrations/V002__create_auth_tables.sql`
    - `src/auth/db/migrations/V003__create_auth_indexes.sql`
    - `src/auth/db/migration_runner.hpp`
    - `src/auth/db/migration_runner.cpp`
    - `tests/unit/auth/migration_runner_test.cpp`
11. **Files/Directories That May Be Modified**: `src/auth/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `deploy/compose/*`.
13. **Detailed Implementation Requirements**:
    - **DDL Tables & Constraints**:
      - `schema_migrations`: `version INT PRIMARY KEY`, `description VARCHAR(255) NOT NULL`, `checksum VARCHAR(64) NOT NULL`, `installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`.
      - `users`: `user_id UUID PRIMARY KEY`, `credential_identifier VARCHAR(255) NOT NULL UNIQUE`, `password_verifier VARCHAR(255) NOT NULL`, `password_algorithm VARCHAR(64) NOT NULL`, `password_updated_at TIMESTAMPTZ NOT NULL`, `account_status VARCHAR(32) NOT NULL`, `created_at TIMESTAMPTZ NOT NULL`, `updated_at TIMESTAMPTZ NOT NULL`, `version BIGINT NOT NULL DEFAULT 1`.
      - `devices`: `device_id UUID PRIMARY KEY`, `user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT`, `device_status VARCHAR(32) NOT NULL`, `registered_at TIMESTAMPTZ NOT NULL`, `revoked_at TIMESTAMPTZ`, `revocation_reason VARCHAR(255)`, `last_authenticated_at TIMESTAMPTZ NOT NULL`, `created_at TIMESTAMPTZ NOT NULL`, `updated_at TIMESTAMPTZ NOT NULL`.
      - `device_public_keys`: `key_id UUID PRIMARY KEY`, `device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT`, `key_type VARCHAR(64) NOT NULL`, `public_key BYTEA NOT NULL`, `key_status VARCHAR(32) NOT NULL`, `created_at TIMESTAMPTZ NOT NULL`, `revoked_at TIMESTAMPTZ`, `replaced_by_key_id UUID REFERENCES device_public_keys(key_id)`.
      - `sessions`: `session_id UUID PRIMARY KEY`, `user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT`, `device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT`, `session_status VARCHAR(32) NOT NULL`, `authentication_level VARCHAR(32) NOT NULL`, `created_at TIMESTAMPTZ NOT NULL`, `expires_at TIMESTAMPTZ NOT NULL`, `revoked_at TIMESTAMPTZ`, `last_used_at TIMESTAMPTZ NOT NULL`.
      - `refresh_tokens`: `refresh_token_id UUID PRIMARY KEY`, `session_id UUID NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT`, `device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT`, `token_verifier VARCHAR(128) NOT NULL UNIQUE`, `token_status VARCHAR(32) NOT NULL`, `issued_at TIMESTAMPTZ NOT NULL`, `expires_at TIMESTAMPTZ NOT NULL`, `revoked_at TIMESTAMPTZ`, `rotated_at TIMESTAMPTZ`, `replaced_by_token_id UUID REFERENCES refresh_tokens(refresh_token_id)`.
      - `mfa_configurations`: `mfa_configuration_id UUID PRIMARY KEY`, `user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT`, `factor_type VARCHAR(32) NOT NULL`, `encrypted_secret BYTEA NOT NULL`, `status VARCHAR(32) NOT NULL`, `created_at TIMESTAMPTZ NOT NULL`, `enabled_at TIMESTAMPTZ`, `disabled_at TIMESTAMPTZ`, `version BIGINT NOT NULL DEFAULT 1`.
      - `mfa_challenges`: `mfa_challenge_id UUID PRIMARY KEY`, `user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT`, `session_id UUID NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT`, `challenge_purpose VARCHAR(32) NOT NULL`, `challenge_status VARCHAR(32) NOT NULL`, `created_at TIMESTAMPTZ NOT NULL`, `expires_at TIMESTAMPTZ NOT NULL`, `completed_at TIMESTAMPTZ`.
    - **Indexes**:
      - `idx_devices_user_status` ON `devices(user_id, device_status)`
      - `idx_device_keys_device_status` ON `device_public_keys(device_id, key_status)`
      - `idx_sessions_user_status` ON `sessions(user_id, session_status)`
      - `idx_sessions_device_status` ON `sessions(device_id, session_status)`
      - `idx_refresh_tokens_session_status` ON `refresh_tokens(session_id, token_status)`
      - `idx_refresh_tokens_device_status` ON `refresh_tokens(device_id, token_status)`
      - `idx_mfa_config_user_status` ON `mfa_configurations(user_id, status)`
      - `idx_mfa_challenges_user_status` ON `mfa_challenges(user_id, challenge_status)`
      - `idx_mfa_challenges_session_status` ON `mfa_challenges(session_id, challenge_status)`
    - **Advisory Lock Key**: A distinct 64-bit bigint identifier constant `k_auth_migration_advisory_lock = 0x5343415554483031LL` (`SCAUTH01`) to protect migration runs.
14. **Concurrency/Lifecycle Requirements**: Migration runner is idempotent and safe against multiple concurrent service instances attempting migrations simultaneously.
15. **Security Requirements**: Invariant: All timestamps stored in UTC (`TIMESTAMPTZ`). Secrets strictly stored as verifiers (`password_verifier`, `token_verifier`) or ciphertext (`encrypted_secret`).
16. **Database Isolation Requirements**: Connects strictly to `AuthConfig::db_port` (`5433` in dev). Never touch host `5432`.
17. **API/Contract Requirements**:
    ```cpp
    namespace securecloud::auth::db {
    class MigrationRunner {
    public:
        explicit MigrationRunner(PostgresConnectionPool& pool);
        MigrationResult run_migrations();
        int get_current_schema_version();
    };
    }
    ```
18. **Error-Handling Requirements**: `MigrationFailedException` with detailed SQL error, failed script name, and failed transaction rollback.
19. **Testing Requirements**: Unit test validates script parsing, checksum calculation, and sequence ordering. Integration test validates applying migrations to clean database and verifying idempotency when re-run.
20. **Acceptance Criteria**: All 3 DDL scripts apply cleanly without error; re-running reports 0 pending migrations; schema matches `02-auth-data-model.md` exactly.
21. **Definition of Done**: DDL files and `MigrationRunner` created, tested, and passing all quality gates.
22. **Risks/Blockers**: Windows line endings (`CRLF` vs `LF`) affecting migration checksum calculation (must normalize `\r\n` to `\n` before hashing).

---

### AUTH-002-T02 — Persistence Domain Entities, Strong Enums, UUIDv7 & Timestamp Mappers

1. **Ticket ID**: `AUTH-002-T02`
2. **Title**: Persistence Domain Entities, Strong Enums, UUIDv7 & Timestamp Mappers
3. **Objective**: Define strongly typed C++20 domain entities, status enums, UUID value types, and bidirectional `libpqxx` serialization/deserialization mappers.
4. **Architectural Purpose**: Establishes type-safe domain boundary between raw SQL result sets and C++ business logic, preventing stringly-typed data bugs and timezone corruption (ADR-001, ADR-009).
5. **Scope**:
   - Create `src/auth/domain/` directory containing:
     - `enums.hpp`: Strongly typed `enum class` for `AccountStatus`, `DeviceStatus`, `KeyType`, `KeyStatus`, `SessionStatus`, `AuthenticationLevel`, `TokenStatus`, `MfaFactorType`, `MfaStatus`, `MfaChallengePurpose`, `MfaChallengeStatus`.
     - `uuid.hpp`: Moveable, copyable, hashable `Uuid` value type supporting UUIDv7 generation, RFC 9562 compliance, and string conversion (`to_string()`, `from_string()`).
     - `timestamp.hpp`: UTC time point conversions between `std::chrono::system_clock::time_point` and PostgreSQL ISO-8601 strings.
     - Entity structs: `UserEntity`, `DeviceEntity`, `DevicePublicKeyEntity`, `SessionEntity`, `RefreshTokenEntity`, `MfaConfigurationEntity`, `MfaChallengeEntity`.
   - Implement `libpqxx` custom type traits or explicit `from_row(const pqxx::row&)` / `to_params()` mapping functions.
   - Provide comprehensive unit tests in `tests/unit/auth/domain_entities_test.cpp`.
6. **Explicit Out-of-Scope**: Database I/O, network calls, query construction.
7. **Dependencies**: Upstream AUTH-002-T01. Downstream AUTH-002-T03, AUTH-002-T04, AUTH-002-T05.
8. **Exact Repository Starting Point**: `src/auth/CMakeLists.txt`.
9. **Files/Directories to Inspect**: `docs/data-model/01-global-data-modeling-rules.md` (1.3, 1.4), `docs/data-model/02-auth-data-model.md`.
10. **Files/Directories to Create**:
    - `src/auth/domain/enums.hpp`
    - `src/auth/domain/uuid.hpp`
    - `src/auth/domain/timestamp.hpp`
    - `src/auth/domain/entities.hpp`
    - `src/auth/domain/mappers.hpp`
    - `src/auth/domain/mappers.cpp`
    - `tests/unit/auth/domain_entities_test.cpp`
11. **Files/Directories That May Be Modified**: `src/auth/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
13. **Detailed Implementation Requirements**:
    - **Strong Enums**:
      ```cpp
      enum class AccountStatus { Active, Disabled };
      enum class DeviceStatus { Active, Revoked };
      enum class KeyStatus { Active, Revoked, Replaced };
      enum class SessionStatus { Active, Revoked, Expired };
      enum class AuthenticationLevel { PrimaryOnly, MfaVerified };
      enum class TokenStatus { Active, Rotated, Revoked, Expired };
      enum class MfaStatus { Pending, Enabled, Disabled };
      enum class MfaChallengePurpose { Login, StepUp };
      enum class MfaChallengeStatus { Pending, Completed, Expired, Failed };
      ```
      Provide lossless `to_string(Enum)` and `parse_enum<Enum>(std::string_view)` helpers.
    - **Entity Definitions**:
      - `UserEntity`: `Uuid user_id`, `std::string credential_identifier`, `std::string password_verifier`, `std::string password_algorithm`, `time_point password_updated_at`, `AccountStatus account_status`, `time_point created_at`, `time_point updated_at`, `uint64_t version`.
      - `DeviceEntity`: `Uuid device_id`, `Uuid user_id`, `DeviceStatus device_status`, `time_point registered_at`, `std::optional<time_point> revoked_at`, `std::optional<std::string> revocation_reason`, `time_point last_authenticated_at`, `time_point created_at`, `time_point updated_at`.
      - `RefreshTokenEntity`: `Uuid refresh_token_id`, `Uuid session_id`, `Uuid device_id`, `std::string token_verifier`, `TokenStatus token_status`, `time_point issued_at`, `time_point expires_at`, `std::optional<time_point> revoked_at`, `std::optional<time_point> rotated_at`, `std::optional<Uuid> replaced_by_token_id`.
    - **UUIDv7 Specification**:
      - 48-bit Unix epoch millisecond timestamp prefix, 4-bit version (`0b0111`), 12-bit rand_a, 2-bit variant (`0b10`), 62-bit rand_b.
      - Lexicographically sortable by time.
14. **Concurrency/Lifecycle Requirements**: All entities and value types are thread-safe for reading, move-constructible, and default-constructible where appropriate.
15. **Security Requirements**: Zero sensitive data formatting in default debug output (e.g. `password_verifier` truncated or omitted in logger formatting).
16. **Testing Requirements**: `tests/unit/auth/domain_entities_test.cpp` validates:
    - UUIDv7 time-ordering and uniqueness.
    - Enum round-trip string serialization.
    - `pqxx::row` mapping with valid, null, and invalid enum values.
17. **Acceptance Criteria**: 100% unit test coverage for entity mappers and UUID value types.
18. **Definition of Done**: Domain entities and mappers compilable under `-Werror` across macOS, MSVC, and MinGW.

---

### AUTH-002-T03 — User & Device Repositories with Optimistic Concurrency Control

1. **Ticket ID**: `AUTH-002-T03`
2. **Title**: User & Device Repositories with Optimistic Concurrency Control
3. **Objective**: Implement `PostgresUserRepository` and `PostgresDeviceRepository` with prepared statements, atomic transactions, credential normalization lookup, and optimistic concurrency version checking.
4. **Architectural Purpose**: Provides authoritative, thread-safe data access interfaces for account credentials and device authorization state (ADR-005, `auth-design.md` 4.8, 4.10).
5. **Scope**:
   - Create `src/auth/repository/user_repository.{hpp,cpp}`:
     - `create_user(UserEntity)` -> inserts new user with version 1.
     - `find_by_id(Uuid)` -> returns `std::optional<UserEntity>`.
     - `find_by_credential_identifier(std::string_view)` -> returns `std::optional<UserEntity>`.
     - `update_user(UserEntity)` -> updates with `WHERE version = expected_version`, increments version, throws `OptimisticLockException` on version collision.
     - `set_account_status(Uuid, AccountStatus, uint64_t expected_version)`.
   - Create `src/auth/repository/device_repository.{hpp,cpp}`:
     - `register_device(DeviceEntity)` -> inserts new device with `DeviceStatus::Active`.
     - `find_by_id(Uuid)` -> returns `std::optional<DeviceEntity>`.
     - `list_active_by_user_id(Uuid)` -> returns `std::vector<DeviceEntity>`.
     - `revoke_device(Uuid device_id, std::string_view reason, time_point revoked_at)` -> updates device to `Revoked`, records `revoked_at` and `revocation_reason`.
     - `update_last_authenticated(Uuid device_id, time_point auth_time)`.
   - Implement `src/auth/repository/exceptions.hpp`:
     - `EntityNotFoundException`, `DuplicateEntityException`, `OptimisticLockException`, `DatabaseExecutionException`.
   - Provide unit tests in `tests/unit/auth/user_device_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Password hashing verification; device crypto key directory queries.
7. **Dependencies**: Upstream AUTH-002-T01, AUTH-002-T02. Downstream AUTH-002-T06.
8. **Exact Repository Starting Point**: `src/auth/db/postgres_connection_pool.hpp`, `src/auth/domain/entities.hpp`.
9. **Files/Directories to Inspect**: `docs/data-model/02-auth-data-model.md` (Sections 2.3, 2.5, 2.6).
10. **Files/Directories to Create**:
    - `src/auth/repository/exceptions.hpp`
    - `src/auth/repository/user_repository.hpp`
    - `src/auth/repository/user_repository.cpp`
    - `src/auth/repository/device_repository.hpp`
    - `src/auth/repository/device_repository.cpp`
    - `tests/unit/auth/user_device_repository_test.cpp`
11. **Files/Directories That May Be Modified**: `src/auth/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
13. **Detailed Implementation Requirements**:
    - **Prepared Statements**: All queries must use parameterized SQL (`$1, $2, ...`) via `pqxx::work::exec_params` to prevent SQL injection vulnerabilities.
    - **Optimistic Locking**:
      ```sql
      UPDATE users 
      SET credential_identifier = $1, password_verifier = $2, password_algorithm = $3,
          password_updated_at = $4, account_status = $5, updated_at = $6, version = version + 1
      WHERE user_id = $7 AND version = $8;
      ```
      If rows affected == 0: Query if user exists. If yes -> throw `OptimisticLockException`; if no -> throw `EntityNotFoundException`.
    - **Duplicate Handling**: Catch `pqxx::unique_violation`. If constraint is `users_credential_identifier_key`, throw `DuplicateEntityException("Credential identifier already registered")`.
    - **Device Revocation Invariant**: A revoked device cannot be reactivated. If `device.device_status == Revoked`, attempting to re-register or set to `Active` is rejected.
14. **Concurrency/Lifecycle Requirements**: Repositories accept `PostgresConnectionPool&` and check out connections per method or accept an explicit active `pqxx::transaction_base&` for multi-repository transactional operations.
15. **Security Requirements**: Invariant: `credential_identifier` lookup must be exact match on pre-normalized input. Passwords never logged.
16. **Database Isolation Requirements**: Strictly connects to `127.0.0.1:5433` via pool.
17. **Testing Requirements**: Unit test validates SQL formatting, parameter binding, exception mapping on constraint violation, and OCC version collision detection.
18. **Acceptance Criteria**: Full CRUD on Users and Devices; OCC rejects concurrent updates with stale version; duplicates throw `DuplicateEntityException`.
19. **Definition of Done**: Clean build, tests passing, zero memory leaks.

---

### AUTH-002-T04 — Session & Refresh Token Repositories with Atomic Token Rotation & Reuse Detection

1. **Ticket ID**: `AUTH-002-T04`
2. **Title**: Session & Refresh Token Repositories with Atomic Token Rotation & Reuse Detection
3. **Objective**: Implement `PostgresSessionRepository` and `PostgresRefreshTokenRepository` supporting session lifecycle, atomic single-use refresh token rotation, and compromise reuse detection.
4. **Architectural Purpose**: Provides bulletproof transactional guarantees for session assurance levels and token rotation invariants mandated by ADR-008 and `02-auth-data-model.md` Section 2.11.
5. **Scope**:
   - Create `src/auth/repository/session_repository.{hpp,cpp}`:
     - `create_session(SessionEntity)` -> persists new session (`Active`, `PrimaryOnly`).
     - `find_by_id(Uuid)` -> returns `std::optional<SessionEntity>`.
     - `list_active_by_user_id(Uuid)` -> returns `std::vector<SessionEntity>`.
     - `list_active_by_device_id(Uuid)` -> returns `std::vector<SessionEntity>`.
     - `update_authentication_level(Uuid, AuthenticationLevel)` (e.g. step up to `MfaVerified`).
     - `revoke_session(Uuid session_id, time_point revoked_at)`.
     - `revoke_all_user_sessions(Uuid user_id, time_point revoked_at)`.
     - `revoke_all_device_sessions(Uuid device_id, time_point revoked_at)`.
   - Create `src/auth/repository/refresh_token_repository.{hpp,cpp}`:
     - `create_token(RefreshTokenEntity)` -> stores token verifier.
     - `find_by_verifier(std::string_view verifier_hash)` -> returns `std::optional<RefreshTokenEntity>`.
     - `rotate_token_atomic(Uuid old_token_id, RefreshTokenEntity new_token)` -> executes in a single `pqxx::work` transaction:
       1. Verifies old token is `Active`.
       2. Inserts `new_token` with status `Active`.
       3. Updates old token to `Rotated`, sets `rotated_at`, sets `replaced_by_token_id = new_token.refresh_token_id`.
     - `handle_token_reuse(std::string_view verifier_hash)`:
       - Identifies token whose status is already `Rotated`.
       - In a single transaction: revokes the associated session and all active refresh tokens for that session/device.
       - Returns `TokenReuseDetectedResult` detailing revoked session and device.
   - Provide unit tests in `tests/unit/auth/session_token_repository_test.cpp`.
6. **Explicit Out-of-Scope**: Bearer token signing, JWT encoding, HTTP cookie handling.
7. **Dependencies**: Upstream AUTH-002-T01, AUTH-002-T02. Downstream AUTH-002-T06.
8. **Exact Repository Starting Point**: `src/auth/repository/user_repository.hpp`, `src/auth/domain/entities.hpp`.
9. **Files/Directories to Inspect**: `docs/data-model/02-auth-data-model.md` (Sections 2.9, 2.10, 2.11).
10. **Files/Directories to Create**:
    - `src/auth/repository/session_repository.hpp`
    - `src/auth/repository/session_repository.cpp`
    - `src/auth/repository/refresh_token_repository.hpp`
    - `src/auth/repository/refresh_token_repository.cpp`
    - `tests/unit/auth/session_token_repository_test.cpp`
11. **Files/Directories That May Be Modified**: `src/auth/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
13. **Detailed Implementation Requirements**:
    - **Atomic Token Rotation Contract**:
      ```cpp
      struct TokenRotationResult {
          RefreshTokenEntity old_token;
          RefreshTokenEntity new_token;
      };
      ```
      If old token status is not `Active` (e.g. `Rotated`, `Revoked`, `Expired`), rotation must fail atomically without inserting `new_token`.
    - **Compromise Reuse Detection**:
      If a client presents a token verifier that evaluates to `TokenStatus::Rotated`, it indicates an attacker or victim is attempting to replay a consumed refresh token. The repository immediately revokes the session and all sibling tokens to prevent session hijacking:
      ```sql
      UPDATE sessions SET session_status = 'Revoked', revoked_at = $1 WHERE session_id = $2;
      UPDATE refresh_tokens SET token_status = 'Revoked', revoked_at = $1 WHERE session_id = $2 AND token_status = 'Active';
      ```
    - **Single-Use Guarantee**: Refresh tokens are strictly single-use.
14. **Concurrency/Lifecycle Requirements**: High concurrency safety. Multiple simultaneous attempts to rotate the same refresh token must result in exactly one success and subsequent attempts triggering reuse detection.
15. **Security Requirements**: Invariant: Plaintext refresh tokens are never passed to or stored by the repository; only the cryptographic verifier hash (`token_verifier`) is stored and queried.
16. **Database Isolation Requirements**: All operations run strictly on `127.0.0.1:5433`.
17. **Testing Requirements**:
    - Concurrent rotation race condition test.
    - Reuse of rotated token triggers revocation of session and active tokens.
    - Device revocation cascades to revoking all active sessions and refresh tokens.
18. **Acceptance Criteria**: Atomic rotation guarantees zero token loss; reuse detection invalidates compromised session immediately.
19. **Definition of Done**: Clean build, tests passing, zero memory leaks.

---

### AUTH-002-T05 — Device Cryptographic Key Directory & MFA State Repositories

1. **Ticket ID**: `AUTH-002-T05`
2. **Title**: Device Cryptographic Key Directory & MFA State Repositories
3. **Objective**: Implement `PostgresDevicePublicKeyRepository` and `PostgresMfaRepository` for public key discovery, prekey rotation, encrypted MFA secret persistence, and challenge tracking.
4. **Architectural Purpose**: Enables public cryptographic key identity lookups for end-to-end messaging and persists multi-factor authentication enrollment and step-up challenge states (ADR-005, `02-auth-data-model.md` 2.7, 2.8, 2.12, 2.13).
5. **Scope**:
   - Create `src/auth/repository/device_public_key_repository.{hpp,cpp}`:
     - `store_public_key(DevicePublicKeyEntity)` -> stores public key bytes.
     - `list_active_keys_by_device_id(Uuid)` -> retrieves active public keys for device discovery.
     - `replace_key(Uuid old_key_id, DevicePublicKeyEntity new_key)` -> atomically marks old key `Replaced`, links replacement.
     - `revoke_all_device_keys(Uuid device_id, time_point revoked_at)`.
   - Create `src/auth/repository/mfa_repository.{hpp,cpp}`:
     - `store_mfa_configuration(MfaConfigurationEntity)` -> stores factor type, encrypted secret, status `Pending`.
     - `find_mfa_config_by_user_id(Uuid)` -> returns `std::optional<MfaConfigurationEntity>`.
     - `enable_mfa(Uuid config_id, time_point enabled_at, uint64_t expected_version)` -> transitions `Pending` to `Enabled` under OCC.
     - `disable_mfa(Uuid config_id, time_point disabled_at, uint64_t expected_version)` -> transitions to `Disabled`.
     - `create_challenge(MfaChallengeEntity)` -> persists challenge (`Login` or `StepUp`, status `Pending`).
     - `find_challenge_by_id(Uuid)` -> returns `std::optional<MfaChallengeEntity>`.
     - `complete_challenge(Uuid challenge_id, time_point completed_at)` -> marks `Completed`.
     - `fail_challenge(Uuid challenge_id)` -> marks `Failed`.
   - Provide unit tests in `tests/unit/auth/crypto_key_mfa_repository_test.cpp`.
6. **Explicit Out-of-Scope**: End-to-end cryptographic encryption/decryption; TOTP verification algorithms.
7. **Dependencies**: Upstream AUTH-002-T01, AUTH-002-T02. Downstream AUTH-002-T06.
8. **Exact Repository Starting Point**: `src/auth/domain/entities.hpp`, `src/auth/repository/exceptions.hpp`.
9. **Files/Directories to Inspect**: `docs/data-model/02-auth-data-model.md` (Sections 2.7, 2.8, 2.12, 2.13, 2.14).
10. **Files/Directories to Create**:
    - `src/auth/repository/device_public_key_repository.hpp`
    - `src/auth/repository/device_public_key_repository.cpp`
    - `src/auth/repository/mfa_repository.hpp`
    - `src/auth/repository/mfa_repository.cpp`
    - `tests/unit/auth/crypto_key_mfa_repository_test.cpp`
11. **Files/Directories That May Be Modified**: `src/auth/CMakeLists.txt`, `tests/unit/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`.
13. **Detailed Implementation Requirements**:
    - **Public Key Discovery Invariant**:
      - Auth stores only **public** key material (`public_key BYTEA`).
      - Invariant: Private keys are NEVER stored in `device_public_keys`.
      - When querying device keys for public discovery, only keys with `KeyStatus::Active` are returned.
    - **MFA Secret Protection**:
      - Invariant: `encrypted_secret` column stores ciphertext bytes, never plaintext TOTP base32 seeds.
    - **MFA Challenge Expiration**:
      - Challenges store `expires_at`. Repository query for valid pending challenge must enforce `WHERE challenge_status = 'Pending' AND expires_at > NOW()`.
14. **Concurrency/Lifecycle Requirements**: Thread-safe execution using pooled database connections.
15. **Security Requirements**: Invariant: MFA secrets and private keys are never exposed in SQL logs or error messages.
16. **Database Isolation Requirements**: Connects strictly to `127.0.0.1:5433`.
17. **Testing Requirements**:
    - Store and retrieve binary public keys with exact byte fidelity.
    - Replace public key marks old key `Replaced` and sets `replaced_by_key_id`.
    - Expired MFA challenges rejected.
18. **Acceptance Criteria**: Key directory returns active public keys; MFA configuration state transitions obey OCC.
19. **Definition of Done**: Clean build, tests passing, zero memory leaks.

---

### AUTH-002-T06 — Persistence Integration Test Suite & Concurrency Verification Harness

1. **Ticket ID**: `AUTH-002-T06`
2. **Title**: Persistence Integration Test Suite & Concurrency Verification Harness
3. **Objective**: Build a comprehensive integration test suite running against the containerized PostgreSQL 17 database (`127.0.0.1:5433`), validating migrations, full entity CRUD lifecycles, constraint enforcement, atomic transactions, and concurrent pool contention.
4. **Architectural Purpose**: Verifies end-to-end database durability, data model integrity, and failure-mode resiliency before wiring business logic in AUTH-003+ (ADR-005, ADR-010).
5. **Scope**:
   - Create `tests/integration/auth_persistence_integration_test.cpp`:
     - Test 1: `MigrationRunner` executes all DDL scripts against clean database; verifies idempotency on repeated runs.
     - Test 2: `UserRepository` full CRUD, unique constraint violation on duplicate `credential_identifier`, optimistic lock collision.
     - Test 3: `DeviceRepository` registration, active listing, and revocation cascading.
     - Test 4: `SessionRepository` lifecycle, authentication level step-up, device-scoped revocation.
     - Test 5: `RefreshTokenRepository` atomic single-use rotation, ensuring old token is `Rotated` and new token is `Active`.
     - Test 6: Compromise reuse detection: presenting a `Rotated` token revokes the session and sibling tokens.
     - Test 7: `DevicePublicKeyRepository` binary byte preservation, active key filtering, key replacement linking.
     - Test 8: `MfaRepository` configuration OCC versioning, challenge creation, expiration, and completion.
     - Test 9: Multi-threaded connection pool contention: 20 concurrent threads executing repository transactions against a 5-connection pool without deadlocks, leaks, or connection exhaustion.
   - Integrate with `gtest_discover_tests` and ensure clean process termination via `TerminateProcess` on Windows / `return` on POSIX.
   - Add verification target in `tests/integration/CMakeLists.txt`.
6. **Explicit Out-of-Scope**: Touching host port 5432; modifying non-auth tests.
7. **Dependencies**: Upstream AUTH-002-T01 through AUTH-002-T05, SC-015. Downstream Phase 1 AUTH-003.
8. **Exact Repository Starting Point**: `tests/integration/CMakeLists.txt`, `src/auth/db/`, `src/auth/repository/`.
9. **Files/Directories to Inspect**: `tests/integration/health_integration_test.cpp`, `src/auth/auth_config.hpp`.
10. **Files/Directories to Create**:
    - `tests/integration/auth_persistence_integration_test.cpp`
11. **Files/Directories That May Be Modified**: `tests/integration/CMakeLists.txt`.
12. **Files/Directories That MUST NOT Be Modified**: `src/common/*`, `deploy/compose/*`.
13. **Detailed Implementation Requirements**:
    - **Port 5432 Protection**: The test fixture must explicitly assert:
      ```cpp
      ASSERT_NE(config.db_port, 5432) << "CRITICAL ERROR: Tests must NEVER connect to host PostgreSQL on port 5432!";
      EXPECT_EQ(config.db_port, 5433);
      ```
    - **Test Isolation**: Each test case runs within an isolated transaction that rolls back, or uses an isolated test schema/tenant to ensure test idempotency without leaving dirty state.
    - **Deterministic Process Teardown**: Use the proven pattern from `health_integration_test.cpp` to guarantee 0ms exit time on MinGW and prevent loader lock deadlocks:
      ```cpp
      int main(int argc, char** argv) {
          ::testing::InitGoogleTest(&argc, argv);
          int result = RUN_ALL_TESTS();
      #ifdef _WIN32
          std::fflush(nullptr);
          ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
      #else
          return result;
      #endif
      }
      ```
14. **Concurrency/Lifecycle Requirements**: Bounded pool contention test runs across `std::thread` pool with `std::atomic<bool>` error flags.
15. **Security Requirements**: Invariant: Credentials used are strictly local development defaults (`auth_user` / `auth_dev_db_secret`).
16. **Validation Commands**:
    ```bash
    python3 scripts/verify-local.py
    ctest --preset dev-debug -R auth_persistence_integration_test --output-on-failure
    ```
17. **Expected Validation Evidence**: All 9 integration test scenarios pass cleanly with 0 timeouts and 0 memory leaks.
18. **Acceptance Criteria**: 100% test pass on live PostgreSQL 17 container; host port 5432 untouched; all data model invariants verified.
19. **Definition of Done**: Automated execution in CI and local verification pipelines.
20. **Risks/Blockers**: Live PostgreSQL container must be running during integration test stage (`scripts/verify-persistence-infra.sh` or Compose).

---

## 4. Git Commit Hygiene & Traceability Plan

To ensure clean traceability across PR reviews, commits for AUTH-002 must strictly adhere to the following sequence:

1. `feat(auth): add PostgreSQL schema migrations and transactional migration runner (AUTH-002-T01)`
2. `feat(auth): define domain entities, strong enums, and UUIDv7 mappers (AUTH-002-T02)`
3. `feat(auth): implement user and device repositories with optimistic concurrency (AUTH-002-T03)`
4. `feat(auth): implement session and refresh token repositories with atomic rotation (AUTH-002-T04)`
5. `feat(auth): implement device public key directory and MFA repositories (AUTH-002-T05)`
6. `test(auth): add persistence integration test suite and concurrency harness (AUTH-002-T06)`

---

## 5. PR Checklist & Review Gate

Before any PR for AUTH-002 can be approved and merged into `main`:

- [ ] Host PostgreSQL 14 on `localhost:5432` has **never** been contacted or modified.
- [ ] Schema DDL exactly mirrors `docs/data-model/02-auth-data-model.md`.
- [ ] `pg_advisory_lock` protects all migration executions.
- [ ] Passwords and refresh tokens are stored strictly as verifiers, never plaintext.
- [ ] MFA secrets are encrypted at rest.
- [ ] Auth stores only public keys; private keys are never present.
- [ ] Optimistic concurrency control (`version`) is enforced on `users` and `mfa_configurations`.
- [ ] Refresh token rotation is atomic in a single SQL transaction.
- [ ] Refresh token reuse triggers immediate session and token revocation.
- [ ] All timestamps use `TIMESTAMPTZ` and are generated/stored in UTC.
- [ ] `tests/integration/auth_persistence_integration_test` passes with 0 timeouts.
- [ ] `python3 scripts/verify-local.py` passes all stages across macOS, MSVC, and MinGW.
