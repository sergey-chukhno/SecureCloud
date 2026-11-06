# AUDIT-013 — Auth Audit Producer and Transactional Outbox
## Phase 6 (M6: Centralized Audit & Compliance) Technical Specification & Implementation Tickets

**Card Identifier**: `AUDIT-013`  
**Milestone**: M6 — Centralized Audit & Compliance  
**Document Status**: Implementation-Ready Technical Specification & Ticket Decomposition  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: November 5, 2026  
**Dependencies**: `AUDIT-002` (Canonical Event Model & Validator), `AUDIT-004` (Authenticated gRPC Ingestion Contract), `AUDIT-005` (Bounded Asynchronous Ingestion & Batch Persistence), `AUDIT-006` (Event Deduplication & Retry-Safe Acknowledgements), `AUDIT-010` (Readiness, Health Checks & Graceful Shutdown), `AUDIT-011` (Ingestion Metrics & Diagnostics), `AUTH-001`–`AUTH-010` (Auth Service & PostgreSQL Repository Layer)  
**Related ADRs**: `ADR-004` (Inter-Process Communication Model), `ADR-005` (Database Ownership — §6 Auth Database), `ADR-007` (Message Reliability & Transactional Outbox — §18–§23), `ADR-008` (Security & Service PKI), `ADR-009` (Distributed Failure Resilience), `ADR-010` (Performance & Bounded Capacity Optimization)

---

## 1. Executive Summary & Architectural Scope

Card **AUDIT-013** specifies and implements the **Transactional Outbox** integration for the **SecureCloud Authentication Service** (`securecloud-auth`), establishing it as an authoritative, reliable, and fault-tolerant audit event producer for the centralized **Audit Service** (`securecloud-audit`).

### 1.1 The Architectural Contrast with Gateway (AUDIT-012)

In `AUDIT-012`, the API Gateway was recognized as a strictly stateless perimeter boundary owning no database. Consequently, the Gateway cannot implement a *transactional* outbox because it has no business transactions to be atomic with.

In sharp contrast, the **Auth Service exclusively owns the primary relational database** (`securecloud_auth` on PostgreSQL 17, per `ADR-005` §6). Auth executes critical state transitions:
- User credential verification and password hashing updates
- Device registration, pairing authorization, and cryptographic key enrollment
- Session creation, refresh token rotation, and immediate session revocation
- Multi-Factor Authentication (MFA) enrollment, TOTP verification, and recovery code consumption
- X3DH prekey and signed prekey inventory management

Under `ADR-007` (§18–§23) and `RULES.md` (§6, §9), **every state-mutating Auth operation must commit its audit record atomically with the business state change inside the same PostgreSQL transaction**. If an operation rolls back, no phantom audit event may ever be recorded. If an operation commits, a process crash, network partition, or Audit Service outage must **never** cause the audit event to be lost.

### 1.2 Core Architectural Invariants for AUDIT-013

1. **Dual-Write Elimination via Transactional Outbox (`ADR-007` §18–§23)**:
   Auth business mutations and their corresponding audit outbox records are executed in a single atomic PostgreSQL transaction (`pqxx::work`). A network call to the Audit Service is **never** made within the business transaction.
2. **Explicit Two-Category Event Classification**:
   - **Category A (State-Mutating Operations)**: Atomically staged in the active business transaction (`pqxx::transaction_base& tx`).
   - **Category B (Non-State-Mutating / Rejection Operations)**: Staged via a dedicated autonomous transaction with immediate commit (e.g. invalid credential submissions, expired session presentation), ensuring durable capture without falsifying business state.
3. **Canonical Event Model Compliance (`AUDIT-002`)**:
   Every event carries an RFC 9562 **UUIDv7** `event_id`, producer-side `occurred_at`, `producer_service = "auth"`, verified actor/target identities, and bounded metadata. The original `event_id` and payload bytes are strictly immutable across all retries.
4. **At-Least-Once Delivery with AUDIT-006 Acknowledgement Semantics**:
   The asynchronous background relay (`AuthOutboxRelay`) delivers batches of pending events over mTLS to `securecloud.audit.v1.AuditIngestionService`. Events are marked `PUBLISHED` only when affirmative acknowledgement is received. Ambiguous outcomes or transient failures trigger exponential backoff with jitter.
5. **Zero-Contention Multi-Worker Concurrency (`SELECT ... FOR UPDATE SKIP LOCKED`)**:
   Outbox polling utilizes PostgreSQL row-level locks with `SKIP LOCKED`, allowing multiple Auth service instances or worker threads to concurrently claim disjoint batches with zero lock contention or duplicate dispatch.
6. **Strict Zero-Secret & Zero-PII Invariant (`ADR-008`, `RULES.md` §5)**:
   Under no circumstances may passwords, password hashes, bearer tokens, refresh tokens, MFA TOTP secrets, recovery codes, or private cryptographic keys enter the outbox table, audit payloads, or diagnostic logs.
7. **Complete Service Isolation (`ADR-005`)**:
   Auth accesses only its own PostgreSQL database (`securecloud_auth`). It never writes directly to ClickHouse or any other service's data store.

---

## 2. Event Inventory & Ownership Boundary

### 2.1 Event Ownership Principles: Auth vs. Gateway vs. Downstream Services

1. **Auth owns security and identity lifecycle authority**: Auth is the sole authority for whether credentials are valid, whether a user is disabled, whether an MFA code is correct, whether a session is active, and whether a device is authorized.
2. **Gateway vs. Auth duplication rule**:
   - Gateway records *perimeter rejections* (e.g. request body too large, rate limit exceeded, missing `Authorization` header, local JWT signature corruption).
   - When Gateway routes a login or token validation request to Auth, **Auth owns the authoritative authentication result**. Gateway does **not** record a second audit event for the same business outcome.
3. **Internal vs. External Attribution**:
   - `client_ip` is extracted from verified transport context (forwarded by Gateway or direct).
   - `user_id`, `device_id`, and `session_id` are populated strictly from verified database records, never from untrusted client-supplied JSON headers.

### 2.2 Comprehensive Auth Audit Event Catalog

| # | `event_type` | Severity | Transaction Category | Triggering Condition & Component | Target & Actor | Bounded Metadata Keys |
| :-- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E01** | `auth.login.succeeded` | `INFO` | **Category A** (Atomic with session & token insertion) | Password & credentials verified; new session & refresh token persisted | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `credential_identifier`, `device_id`, `client_ip` |
| **E02** | `auth.login.failed` | `SECURITY` | **Category B** (Autonomous outbox transaction) | Bad password, invalid device UUID, malformed format, revoked device | Actor: `USER` (or `UNKNOWN`), Target: `SERVICE` (`auth`) | `credential_identifier`, `failure_reason`, `client_ip` (no password!) |
| **E03** | `auth.account.disabled_attempt` | `SECURITY` | **Category B** (Autonomous outbox transaction) | Login attempt on an account marked `DISABLED` or `LOCKED` | Actor: `USER` (`user_id`), Target: `USER` (`user_id`) | `credential_identifier`, `failure_reason`, `client_ip` |
| **E04** | `auth.session.revoked` | `INFO` | **Category A** (Atomic with session update `REVOKED`) | User explicitly logs out or administrator revokes session | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `device_id`, `reason`, `client_ip` |
| **E05** | `auth.session.expired_attempt` | `WARNING` | **Category B** (Autonomous outbox transaction) | Caller presents a session past its expiration timestamp | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `device_id`, `client_ip` |
| **E06** | `auth.session.revoked_attempt` | `SECURITY` | **Category B** (Autonomous outbox transaction) | Caller presents an already revoked session token | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `device_id`, `client_ip` |
| **E07** | `auth.token.refreshed` | `INFO` | **Category A** (Atomic with token rotation in `refresh_tokens`) | Valid refresh token exchanged for new access & refresh token | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `device_id`, `client_ip` |
| **E08** | `auth.token.reuse_detected` | `CRITICAL` | **Category A** (Atomic with immediate cascade revocation of all device sessions) | Revoked or expired refresh token presented again (token replay attack) | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `session_id`, `client_ip` |
| **E09** | `auth.mfa.enrollment_initiated` | `INFO` | **Category A** (Atomic with pending TOTP insertion) | User initiates TOTP secret generation | Actor: `USER` (`user_id`), Target: `USER` (`user_id`) | `mfa_type="totp"`, `client_ip` (no secret!) |
| **E10** | `auth.mfa.enrollment_confirmed` | `INFO` | **Category A** (Atomic with MFA activation & recovery code generation) | User successfully verifies first TOTP code | Actor: `USER` (`user_id`), Target: `USER` (`user_id`) | `mfa_type="totp"`, `recovery_codes_count`, `client_ip` |
| **E11** | `auth.mfa.disabled` | `SECURITY` | **Category A** (Atomic with MFA configuration deletion) | MFA disabled by authorized user or recovery flow | Actor: `USER` (`user_id`), Target: `USER` (`user_id`) | `client_ip` |
| **E12** | `auth.mfa.challenge_created` | `INFO` | **Category A** (Atomic with challenge record creation) | MFA prompt generated during login flow | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `challenge_id`, `client_ip` |
| **E13** | `auth.mfa.challenge_succeeded` | `INFO` | **Category A** (Atomic with session elevation to `MFA_VERIFIED`) | Correct TOTP code submitted | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `challenge_id`, `client_ip` |
| **E14** | `auth.mfa.challenge_failed` | `SECURITY` | **Category B** (Autonomous transaction, or atomic with attempt increment) | Invalid TOTP code or expired challenge | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `challenge_id`, `failure_reason`, `client_ip` |
| **E15** | `auth.mfa.recovery_code_used` | `SECURITY` | **Category A** (Atomic with recovery code hash invalidation) | Backup recovery code consumed for login | Actor: `USER` (`user_id`), Target: `SESSION` (`session_id`) | `remaining_recovery_codes`, `client_ip` |
| **E16** | `auth.device.enrolled` | `INFO` | **Category A** (Atomic with `devices` row insertion) | Device registered with public identity keys | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `is_primary`, `client_ip` |
| **E17** | `auth.device.pairing_initiated` | `INFO` | **Category A** (Atomic with pairing request insertion) | Secondary device requests authorization | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `client_ip` |
| **E18** | `auth.device.authorized` | `INFO` | **Category A** (Atomic with device status update `AUTHORIZED`) | Primary device approves secondary device pairing | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `authorizing_device_id`, `client_ip` |
| **E19** | `auth.device.revoked` | `SECURITY` | **Category A** (Atomic with device status update `REVOKED` and session termination) | Device access revoked by user | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `reason`, `client_ip` |
| **E20** | `auth.device.prekeys_updated` | `INFO` | **Category A** (Atomic with `device_public_keys` insertion) | One-time prekey bundle uploaded | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `prekey_count` |
| **E21** | `auth.device.signed_prekey_rotated`| `INFO` | **Category A** (Atomic with signed prekey update) | Cryptographic signed prekey rotated | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `key_id` |
| **E22** | `auth.device.prekey_inventory_low` | `WARNING` | **Category B** (Autonomous transaction) | Prekey count falls below configured threshold | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `remaining_count`, `threshold` |
| **E23** | `auth.device.prekey_inventory_exhausted`| `CRITICAL`| **Category B** (Autonomous transaction) | All one-time prekeys consumed; X3DH falls back | Actor: `USER` (`user_id`), Target: `DEVICE` (`device_id`) | `remaining_count=0` |

---

## 3. Database Schema & Migration Specification

### 3.1 Migration `V005__create_auth_outbox_table.sql`

The Auth transactional outbox table is integrated into PostgreSQL via Flyway-style SQL migration in `src/auth/db/migrations/`:

```sql
-- Migration: V005__create_auth_outbox_table.sql
-- Purpose: Transactional Outbox for SecureCloud Auth Service (AUDIT-013)

CREATE TABLE IF NOT EXISTS auth_outbox (
    event_id UUID PRIMARY KEY,
    aggregate_type VARCHAR(32) NOT NULL,
    aggregate_id UUID,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'SECURITY', 'CRITICAL')),
    payload_json JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED', 'QUARANTINED')),
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    leased_until TIMESTAMPTZ
);

-- Index for high-velocity outbox polling and worker leasing
CREATE INDEX IF NOT EXISTS idx_auth_outbox_pending_polling
    ON auth_outbox (created_at ASC)
    WHERE status = 'PENDING';

-- Index for lease expiration recovery
CREATE INDEX IF NOT EXISTS idx_auth_outbox_leased
    ON auth_outbox (leased_until)
    WHERE status = 'PENDING' AND leased_until IS NOT NULL;

-- Index for safe background retention cleanup
CREATE INDEX IF NOT EXISTS idx_auth_outbox_cleanup
    ON auth_outbox (processed_at)
    WHERE status = 'PUBLISHED';
```

### 3.2 Concurrency & Worker Leasing Model

To support horizontal scaling of the Auth Service across multiple container instances without message loss or race conditions:

1. **Claiming Batch with Row-Level Skip Locking**:
   ```sql
   UPDATE auth_outbox
   SET leased_until = NOW() + INTERVAL '30 SECONDS',
       retry_count = retry_count + 1
   WHERE event_id IN (
       SELECT event_id
       FROM auth_outbox
       WHERE status = 'PENDING'
         AND (leased_until IS NULL OR leased_until < NOW())
       ORDER BY created_at ASC
       LIMIT $1
       FOR UPDATE SKIP LOCKED
   )
   RETURNING event_id, aggregate_type, aggregate_id, event_type, severity, payload_json, status, retry_count, created_at;
   ```
2. **Crash Resilience**:
   If an Auth instance crashes while holding leased rows, the rows become reclaimable automatically after `30 seconds` by any surviving worker because `leased_until < NOW()`.

---

## 4. Architecture & Dependency Flow

```text
                               AUTH SERVICE BOUNDARY
   ┌────────────────────────────────────────────────────────────────────────┐
   │                                                                        │
   │  Client RPC Request (e.g. Authenticate / RevokeSession / EnrollMFA)     │
   │                                │                                       │
   │                                ▼                                       │
   │                 ┌─────────────────────────────┐                        │
   │                 │       AuthServiceImpl       │                        │
   │                 └──────────────┬──────────────┘                        │
   │                                │                                       │
   │                                ▼                                       │
   │                 ┌─────────────────────────────┐                        │
   │                 │    Domain Service Layer     │                        │
   │                 │ (SessionMgr / MfaMgr / etc) │                        │
   │                 └──────┬───────────────┬──────┘                        │
   │                        │               │                               │
   │      Category A:       │               │ Category B:                   │
   │      State Change      │               │ Non-Mutating Rejection        │
   │                        ▼               ▼                               │
   │       ┌──────────────────────┐   ┌──────────────────────┐              │
   │       │   pqxx::work tx      │   │ Autonomous Outbox tx │              │
   │       │  ├── Business Update │   │ └── Stage Event      │              │
   │       │  └── Stage Outbox    │   │     Commit           │              │
   │       │      Commit          │   └──────────┬───────────┘              │
   │       └──────────┬───────────┘              │                          │
   │                  │                          │                          │
   │                  ▼                          ▼                          │
   │       ═════════════════════════════════════════════════                │
   │             PostgreSQL Table: securecloud_auth.auth_outbox             │
   │       ═════════════════════════════════════════════════                │
   │                                ▲                                       │
   │                                │ SELECT ... FOR UPDATE SKIP LOCKED     │
   │                                │                                       │
   │                 ┌──────────────┴──────────────┐                        │
   │                 │      AuthOutboxRelay        │ (Background Worker)    │
   │                 │   (Poller & Retry Engine)   │                        │
   │                 └──────────────┬──────────────┘                        │
   │                                │                                       │
   │                                ▼                                       │
   │                 ┌─────────────────────────────┐                        │
   │                 │       AuthAuditClient       │                        │
   │                 │  (gRPC Stub over mTLS 1.3)  │                        │
   │                 └──────────────┬──────────────┘                        │
   └────────────────────────────────┼───────────────────────────────────────┘
                                    │ SubmitBatch (gRPC)
                                    ▼
                       ┌─────────────────────────┐
                       │   securecloud-audit     │
                       │ (AuditIngestionService) │
                       └─────────────────────────┘
```

---

## 5. Ticket Decomposition (`AUDIT-013-T01` to `AUDIT-013-T07`)

```text
               AUDIT-002 (Canonical Event Model)
               AUDIT-004 (gRPC Ingestion Contract)
               AUDIT-006 (Deduplication & Acknowledgement Semantics)
               AUTH-001..010 (Auth Domain & Repositories)
                               │
                               ▼
                         AUDIT-013-T01
            (Event Inventory, Ownership Matrix &
             Transactional vs Autonomous Contract)
                               │
                               ▼
                         AUDIT-013-T02
            (PostgreSQL Outbox Schema Migration V005
             & AuthOutboxRepository Implementation)
                               │
                               ▼
                         AUDIT-013-T03
            (Transactional Outbox Staging Integration
             across Auth Business Services)
                               │
                               ▼
                         AUDIT-013-T04
            (Canonical Audit Proto Mapper & Authenticated
             gRPC Ingestion Client with mTLS Binding)
                               │
                               ▼
                         AUDIT-013-T05
            (Asynchronous AuthOutboxRelay Worker,
             Lease Management & Quarantine Engine)
                               │
                               ▼
                         AUDIT-013-T06
            (Producer Observability, Lock-Free Metrics
             & Structured Zero-PII Diagnostics)
                               │
                               ▼
                         AUDIT-013-T07
            (Exhaustive Test Suite: Atomicity, Rollback,
             Concurrency, Restarts & Sensitive-Data Guard)
```

---

### AUDIT-013-T01 — Auth Audit Event Inventory, Ownership Boundaries & Canonical Schema Specification

1. **Ticket ID**: `AUDIT-013-T01`
2. **Title**: Auth Audit Event Inventory, Ownership Boundaries & Canonical Schema Specification
3. **Objective**: Specify the comprehensive Auth audit event inventory, delineate strict ownership boundaries with the API Gateway, and document the dual Category A (transactional) and Category B (autonomous) durability semantics.
4. **Scope & Technical Requirements**:
   - Create `docs/design/auth-audit-producer.md` documenting:
     - The complete catalog of 23 Auth audit events (§2.2).
     - Ownership boundaries: Auth is the sole authority for authentication credentials, session revocation, token reuse, MFA validation, device enrollment, and prekeys.
     - Delineation from Gateway: Gateway records perimeter rejections; Auth records authoritative credential and session evaluations.
     - Event payload schema specification adhering to `AUDIT-002`: RFC 9562 UUIDv7 `event_id`, millisecond UTC `occurred_at`, `producer_service = "auth"`, `actor_type`, `actor_id`, `target_type`, `target_id`, `correlation_id`, and bounded JSON metadata.
     - The Category A vs. Category B durability boundary:
       - **Category A**: Event staged in the active business `pqxx::work` transaction.
       - **Category B**: Non-mutating events staged via an autonomous transaction committed immediately to PostgreSQL.
   - Update `docs/data-model/02-auth-data-model.md` and `docs/design/auth-design.md` with the new `auth_outbox` table and event lifecycle.
5. **Acceptance Criteria**:
   - Complete documentation of all 23 event types, severities, trigger conditions, and metadata whitelists.
   - Clear architectural justification for Category A vs. Category B durability boundaries.
   - Explicit zero-secret checklist barring passwords, hashes, tokens, MFA secrets, and private keys from all audit metadata.
6. **Dependencies**: `AUDIT-002`.

---

### AUDIT-013-T02 — PostgreSQL Outbox Schema Migration V005 & AuthOutboxRepository Implementation

1. **Ticket ID**: `AUDIT-013-T02`
2. **Title**: PostgreSQL Outbox Schema Migration V005 & AuthOutboxRepository Implementation
3. **Objective**: Implement the PostgreSQL database migration for `auth_outbox` and create the C++20 `AuthOutboxRepository` supporting transactional staging, row-level lease acquisition (`FOR UPDATE SKIP LOCKED`), and acknowledgement state updates.
4. **Scope & Technical Requirements**:
   - Create `src/auth/db/migrations/V005__create_auth_outbox_table.sql` per §3.1.
   - Create `src/auth/domain/auth_outbox_entity.hpp`:
     ```cpp
     enum class OutboxStatus { Pending, Published, Failed, Quarantined };

     struct AuthOutboxEntity {
         domain::Uuid event_id;
         std::string aggregate_type;
         std::optional<domain::Uuid> aggregate_id;
         std::string event_type;
         domain::Severity severity{domain::Severity::Info};
         std::string payload_json;
         OutboxStatus status{OutboxStatus::Pending};
         int32_t retry_count{0};
         std::chrono::system_clock::time_point created_at;
         std::optional<std::chrono::system_clock::time_point> processed_at{std::nullopt};
         std::optional<std::string> last_error{std::nullopt};
         std::optional<std::chrono::system_clock::time_point> leased_until{std::nullopt};
     };
     ```
   - Create `src/auth/repository/auth_outbox_repository.hpp` and `.cpp`:
     ```cpp
     class IAuthOutboxRepository {
     public:
         virtual ~IAuthOutboxRepository() = default;
         virtual void stage_event(const AuthOutboxEntity& event, pqxx::transaction_base& tx) = 0;
         virtual void stage_event(const AuthOutboxEntity& event) = 0; // Autonomous transaction
         virtual std::vector<AuthOutboxEntity> fetch_and_lease_pending_batch(size_t limit, std::chrono::seconds lease_duration) = 0;
         virtual bool mark_published(const domain::Uuid& event_id) = 0;
         virtual bool mark_failed(const domain::Uuid& event_id, std::string_view error) = 0;
         virtual bool mark_quarantined(const domain::Uuid& event_id, std::string_view reason) = 0;
         virtual size_t purge_published_older_than(std::chrono::system_clock::time_point cutoff, size_t batch_size) = 0;
         virtual size_t count_pending() = 0;
     };
     ```
   - Implement `fetch_and_lease_pending_batch` using `SELECT ... FOR UPDATE SKIP LOCKED` and update `leased_until = NOW() + lease_duration`.
   - Update `src/auth/CMakeLists.txt` to include the new repository.
5. **Acceptance Criteria**:
   - Migration `V005` executes cleanly via `MigrationRunner` against PostgreSQL 17.
   - Staging an event inside a `pqxx::work` transaction successfully rolls back if `tx.abort()` is called.
   - `fetch_and_lease_pending_batch` returns at most `limit` rows and sets `leased_until` atomically.
6. **Dependencies**: `AUDIT-013-T01`, `src/auth/db/`.

---

### AUDIT-013-T03 — Transactional Outbox Staging Integration across Auth Business Services

1. **Ticket ID**: `AUDIT-013-T03`
2. **Title**: Transactional Outbox Staging Integration across Auth Business Services
3. **Objective**: Refactor Auth services and `AuditEventPublisher` so that all state-mutating operations stage audit records in their shared PostgreSQL business transaction, and non-mutating rejection operations stage records autonomously.
4. **Scope & Technical Requirements**:
   - Refactor `src/auth/service/audit_event_publisher.hpp` and `.cpp`:
     ```cpp
     class IAuditEventPublisher {
     public:
         virtual ~IAuditEventPublisher() = default;
         virtual void publish(const domain::AuditEvent& event, pqxx::transaction_base& tx) = 0;
         virtual void publish(const domain::AuditEvent& event) noexcept = 0; // Autonomous
     };
     ```
   - Implement `AuditEventPublisher` backed by `std::shared_ptr<IAuthOutboxRepository>`:
     - Converts `domain::AuditEvent` to `AuthOutboxEntity`.
     - Validates payload against zero-secret invariants before inserting into PostgreSQL.
   - Integrate transactional staging across Auth domain services:
     - `SessionManager`: `revoke_session` and `revoke_all_device_sessions` commit `auth.session.revoked` in `tx`.
     - `TokenManager`: `refresh_token` commits `auth.token.refreshed` in `tx`; `token_reuse_detected` commits `auth.token.reuse_detected` in `tx`.
     - `MfaManager`: `enroll_mfa`, `confirm_mfa`, `disable_mfa`, `verify_mfa_challenge`, and `consume_recovery_code` commit respective events in `tx`.
     - `DeviceManager`: `enroll_device`, `authorize_device`, `revoke_device` commit respective events in `tx`.
     - `PrekeyManager`: `upload_prekeys`, `rotate_signed_prekey` commit events in `tx`.
     - `AuthServiceImpl`: `login_succeeded` commits in `tx`; `login_failed` and `account_disabled_attempt` call autonomous `publish(event)`.
5. **Acceptance Criteria**:
   - If a business transaction fails (e.g. database unique constraint violation or forced exception), the staged outbox record is rolled back 100% of the time.
   - No Auth business operation calls external network endpoints or waits for Audit delivery.
   - All 23 catalog event types are wired to their corresponding service trigger points.
6. **Dependencies**: `AUDIT-013-T02`.

---

### AUDIT-013-T04 — Canonical Audit Proto Mapper & Authenticated gRPC Ingestion Client with mTLS Binding

1. **Ticket ID**: `AUDIT-013-T04`
2. **Title**: Canonical Audit Proto Mapper & Authenticated gRPC Ingestion Client with mTLS Binding
3. **Objective**: Implement the Protobuf serialization mapper translating `AuthOutboxEntity` to `securecloud::audit::v1::AuditEventProto`, and implement the authenticated gRPC client communicating with the Audit Service over mTLS.
4. **Scope & Technical Requirements**:
   - Create `src/auth/audit/auth_audit_mapper.hpp` and `.cpp`:
     - Translates `AuthOutboxEntity` to `securecloud::audit::v1::AuditEventProto`.
     - Sets `producer_service = PRODUCER_SERVICE_AUTH`.
     - Sets `producer_instance = config.common.service_name` (or hostname).
     - Extracts `actor_type`, `actor_id`, `target_type`, `target_id`, `correlation_id` from JSON payload.
     - Runs metadata keys and values through sanitization to guarantee zero secrets (passwords, tokens, keys) are mapped.
   - Create `src/auth/audit/auth_audit_client.hpp` and `.cpp`:
     ```cpp
     struct AuthAuditClientConfig {
         std::string target_endpoint{"audit:50055"};
         std::chrono::milliseconds timeout{2000};
         common::security::SecurityCredentialsConfig tls_credentials;
     };

     struct AuditBatchSubmitResult {
         bool rpc_success{false};
         grpc::Status status;
         uint32_t accepted_count{0};
         uint32_t rejected_count{0};
         std::vector<std::string> rejected_event_ids;
     };

     class IAuthAuditClient {
     public:
         virtual ~IAuthAuditClient() = default;
         virtual AuditBatchSubmitResult submit_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) = 0;
     };
     ```
   - Implement `AuthAuditClient` using `MtlsCredentialLoader::create_client_credentials` with mTLS client certificate verification (SAN `DNS:audit` / `audit.securecloud.internal`).
5. **Acceptance Criteria**:
   - Serialized `AuditEventProto` satisfies all validation rules of `AUDIT-002` (valid UUIDv7, occurred_at within skew bounds, valid namespaces).
   - Peer identity is cryptographically verified as the Audit Service via mTLS.
   - Client call context strictly enforces configured deadline budget (`timeout`).
6. **Dependencies**: `AUDIT-002`, `AUDIT-004`, `AUDIT-013-T02`.

---

### AUDIT-013-T05 — Asynchronous AuthOutboxRelay Worker, Lease Management & Quarantine Engine

1. **Ticket ID**: `AUDIT-013-T05`
2. **Title**: Asynchronous AuthOutboxRelay Worker, Lease Management & Quarantine Engine
3. **Objective**: Implement the background outbox poller and relay engine (`AuthOutboxRelay`) that batches pending events, manages leasing, handles retries with exponential backoff and jitter, quarantines permanently rejected events, and executes safe retention cleanup.
4. **Scope & Technical Requirements**:
   - Create `src/auth/audit/auth_outbox_relay.hpp` and `.cpp`:
     ```cpp
     struct AuthOutboxRelayConfig {
         std::chrono::milliseconds poll_interval{500};
         size_t batch_size{50};                     // Max 100 per AUDIT-004
         std::chrono::seconds lease_duration{30};   // Row lease duration
         std::chrono::milliseconds initial_backoff{250};
         std::chrono::milliseconds max_backoff{30000};
         double backoff_multiplier{2.0};
         double jitter_ratio{0.25};                 // ±25% jitter
         std::chrono::hours published_retention{24 * 7}; // 7 days retention
         size_t purge_batch_size{1000};
     };

     class AuthOutboxRelay {
     public:
         AuthOutboxRelay(std::shared_ptr<IAuthOutboxRepository> repository,
                         std::shared_ptr<IAuthAuditClient> audit_client,
                         AuthOutboxRelayConfig config = {});
         ~AuthOutboxRelay();

         void start();
         void stop();
         [[nodiscard]] bool is_running() const noexcept;
         size_t poll_and_dispatch();
         size_t purge_old_published_records();
     };
     ```
   - Acknowledgement & Response Handling:
     - When `submit_batch` returns `rpc_success == true`:
       - Events **not** in `rejected_event_ids`: mark `PUBLISHED`.
       - Events **in** `rejected_event_ids`: mark `QUARANTINED` with error detail (permanent rejection per AUDIT-006; do not retry infinitely).
     - When `submit_batch` returns transient error (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`):
       - Do **not** mark published. Increment `retry_count`, record `last_error`, sleep with exponential backoff + jitter.
     - Ambiguous outcomes (timeout / socket reset): retain events in `PENDING`; retry sends the exact same `event_id` and payload.
   - Periodic Retention Purge:
     - Worker thread periodically executes `purge_published_older_than(now - published_retention, purge_batch_size)`.
   - Update `AuthConfig` to load outbox and audit parameters; wire `AuthOutboxRelay` into `src/auth/main.cpp` with graceful shutdown drain.
5. **Acceptance Criteria**:
   - Pending events are reliably fetched, batched, and delivered to the Audit Service.
   - Multiple instances running concurrently never process the same row simultaneously due to `FOR UPDATE SKIP LOCKED`.
   - Permanent rejections are cleanly quarantined without blocking the delivery of other valid events.
   - Published records older than 7 days are pruned without locking the table.
6. **Dependencies**: `AUDIT-013-T02`, `AUDIT-013-T04`.

---

### AUDIT-013-T06 — Producer Observability, Lock-Free Metrics & Structured Zero-PII Diagnostics

1. **Ticket ID**: `AUDIT-013-T06`
2. **Title**: Producer Observability, Lock-Free Metrics & Structured Zero-PII Diagnostics
3. **Objective**: Implement high-performance lock-free operational metrics and structured diagnostic logging for the Auth outbox pipeline adhering to AUDIT-011 and platform observability conventions.
4. **Scope & Technical Requirements**:
   - Create `src/auth/audit/auth_outbox_metrics.hpp` and `.cpp`:
     - Atomic counters and gauges using `std::atomic`:
       - `auth_outbox_pending_events`: instantaneous pending queue count.
       - `auth_outbox_events_staged_total{category="transactional|autonomous"}`: total events staged.
       - `auth_outbox_events_delivered_total`: total events acknowledged by Audit.
       - `auth_outbox_delivery_batches_total{outcome="success|retryable|rejected"}`: batch RPC counts.
       - `auth_outbox_retries_total`: transient retry attempts.
       - `auth_outbox_quarantined_total{reason}`: permanently rejected events.
       - `auth_outbox_purged_total`: cleaned up historical published records.
       - `auth_outbox_oldest_pending_age_seconds`: age of the oldest pending event in the outbox.
     - Strictly bounded label cardinality (no dynamic user IDs or event IDs).
     - Standard `to_prometheus_text()` rendering.
   - Structured Operational Logging:
     - Log outbox batch outcomes, circuit trips, and quarantine actions with correlation IDs.
     - Zero PII / Zero Secret guard: scrub all strings to prevent passwords, tokens, or codes from appearing in logs.
5. **Acceptance Criteria**:
   - Metrics accurately reflect outbox queue depth, delivery velocity, and retry counts.
   - Zero heap allocation on the metric recording path.
   - No sensitive authentication secrets appear in logs or metric dimensions.
6. **Dependencies**: `AUDIT-013-T05`.

---

### AUDIT-013-T07 — Comprehensive Verification Suite (Transactions, Rollback, Restarts, Concurrency, Security)

1. **Ticket ID**: `AUDIT-013-T07`
2. **Title**: Comprehensive Verification Suite (Transactions, Rollback, Restarts, Concurrency, Security)
3. **Objective**: Implement comprehensive automated unit, integration, transactional, failure-injection, concurrency, and security negative test suites validating all acceptance criteria.
4. **Scope & Technical Requirements**:
   - Create `tests/unit/auth/auth_outbox_test.cpp`:
     - Test 1: Canonical Proto mapping fidelity for all 23 event types.
     - Test 2: Sensitive-data scrubbing (tokens, hashes, passwords stripped from metadata).
     - Test 3: Lock-free metrics accuracy and Prometheus exposition formatting.
     - Test 4: Exponential backoff calculation and jitter bounds.
   - Create `tests/integration/auth_outbox_transaction_test.cpp` (against live PostgreSQL):
     - Test 5: **Atomic Commit**: Session creation + outbox event commit together; both exist in DB.
     - Test 6: **Atomic Rollback**: Business operation forced to abort (`tx.abort()`); asserts *neither* the session nor the outbox record exists in DB (zero phantom events).
     - Test 7: **Autonomous Staging**: Failed login attempt stages outbox event independently and commits.
     - Test 8: **Crash & Restart Recovery**: Stage 100 pending events, instantiate `AuthOutboxRelay` and verify all 100 are delivered and marked `PUBLISHED`.
     - Test 9: **Multi-Worker Concurrency (`SKIP LOCKED`)**: 4 concurrent worker threads polling 1,000 pending events; verify exactly 1,000 events processed with zero duplicate delivery attempts.
     - Test 10: **Audit Unavailability & Backlog Drain**: Simulate Audit down (gRPC `UNAVAILABLE`); verify outbox retains all records; bring Audit up; verify complete drain.
     - Test 11: **Permanent Rejection Quarantine**: Ingest event that Audit rejects (`ALREADY_EXISTS` / schema error); verify event transitions to `QUARANTINED` and poller continues.
     - Test 12: **Retention Purge**: Create records with `processed_at < NOW() - 8 DAYS`; verify `purge_old_published_records` removes only expired published records.
   - Register test targets in `tests/unit/CMakeLists.txt` and `tests/integration/CMakeLists.txt`.
5. **Acceptance Criteria**:
   - 100% test pass rate across all new unit and integration test binaries.
   - Valgrind/ASan clean (zero memory leaks), TSan clean (zero data races in multi-worker tests).
   - Clean compilation under `-Wall -Wextra -Wpedantic -Werror`.
6. **Dependencies**: `AUDIT-013-T01` through `AUDIT-013-T06`.

---

## 6. Acceptance Criteria & Definition of Done Traceability Matrix

| Card Acceptance Criterion | Implementing Ticket(s) | Verification Target |
| :--- | :--- | :--- |
| **Auth-owned audit event categories & boundaries documented** | `T01` | `docs/design/auth-audit-producer.md` review & sign-off |
| **Canonical AUDIT-002 model reused** | `T01`, `T04` | Event schema & proto mapper unit tests |
| **UUIDv7 event IDs stable across retries** | `T02`, `T04`, `T05` | Outbox repository & relay retry tests |
| **Outbox stored in Auth-owned relational DB** | `T02` | PostgreSQL migration `V005` in `securecloud_auth` |
| **Auth state changes & outbox records committed atomically** | `T03`, `T07` | `auth_outbox_transaction_test.cpp` (atomic commit test) |
| **Rollbacks do not leave misleading audit events** | `T03`, `T07` | `auth_outbox_transaction_test.cpp` (rollback abort test) |
| **Committed operations do not lose outbox records on crash** | `T02`, `T05`, `T07` | Daemon restart & replay integration test |
| **Explicit durability semantics for events without business transactions** | `T01`, `T03`, `T07` | Autonomous staging tests for login failures |
| **Delivery uses existing authenticated gRPC contract** | `T04`, `T05` | `AuditIngestionService` mTLS client tests |
| **Acknowledgement handling follows AUDIT-004 & AUDIT-006** | `T04`, `T05` | Batch status & deduplication handling tests |
| **Retries handle outages, timeouts, overload & ambiguous outcomes** | `T05`, `T07` | Network failure & ambiguous write injection tests |
| **Concurrent workers / instances cannot double-process records** | `T02`, `T05`, `T07` | `FOR UPDATE SKIP LOCKED` 4-thread concurrency test |
| **Pending events survive process restarts** | `T05`, `T07` | Process termination & resumption tests |
| **Outbox growth, cleanup & quarantine handled explicitly** | `T02`, `T05`, `T07` | Retention purge & quarantine engine tests |
| **Outbox protected by appropriate DB access controls** | `T02` | PostgreSQL table permissions restricted to `auth_user` |
| **Authentication secrets & unnecessary personal data excluded** | `T01`, `T04`, `T07` | Zero-secret automated negative scanner tests |
| **Unit, integration, transaction, concurrency & security tests pass** | `T07` | CTest execution passing with 0 errors |
| **Formatting, static analysis, build & CTest pass with no new warnings** | `T07` | `.clang-format`, `-Werror` build gate |
| **No unrelated Auth, database or infrastructure changes introduced** | All | Git diff verification against `origin/main` |

---

## 7. Risk Analysis & Mitigation Matrix

| Identified Architectural Risk | Severity | Potential Impact | Architectural Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Dual-Write Inconsistency** | **Critical** | Database state updates succeed, but audit event is dropped on crash | Outbox record is written in the exact same `pqxx::work` transaction as the business change. Zero distributed transactions. |
| **Phantom Audit Records on Rollback** | **High** | Outbox event committed while user registration or password change failed | Business transaction rollback automatically rolls back the outbox record in PostgreSQL. Zero phantom events. |
| **Row Lock Contention Under Load** | **High** | Multiple Auth instances or relay workers block each other querying pending rows | `fetch_and_lease_pending_batch` uses `SELECT ... FOR UPDATE SKIP LOCKED`, allowing workers to immediately skip locked rows without waiting. |
| **Sustained Audit Service Outage** | **Medium** | Outbox table grows unbounded during prolonged downstream downtime | Outbox uses indexed queries and bounded batch sizes. Table growth has no impact on business transaction latency. Exponential backoff prevents database connection thrashing. |
| **Deadlock between Business Tx and Outbox** | **Medium** | Service transactions deadlock when locking rows in outbox | Outbox rows are pure inserts (`INSERT INTO auth_outbox`) during business transactions; polling workers only lock existing pending rows. Deadlock between insert and select is impossible. |
| **Sensitive Secret Exfiltration via Outbox** | **Critical** | Operator or attacker inspects PostgreSQL outbox and extracts passwords or MFA keys | `AuthAuditMapper` and `AuditEventPublisher` pass all payloads through strict whitelisting. Automated negative tests assert secrets are never written. |
| **Poison Event Blocking Outbox Relay** | **Medium** | A malformed event repeatedly fails Audit validation, stalling the entire queue | Permanent rejections (`rejected_event_ids` in batch response) are immediately marked `QUARANTINED`, allowing the worker to advance to subsequent pending events. |

