# SecureCloud — Service Implementation Guide

**Status:** Implementation baseline
**Purpose:** Practical implementation map for developers

This document is an index into the approved architecture, design, contracts, and implementation rules.

It does **not** redefine those documents.

---

# 1. Implementation Order

Build in this order:

```text
Foundation
    ↓
Contracts
    ↓
Auth
    ↓
Gateway
    ↓
Messaging persistence
    ↓
Messaging delivery + synchronization
    ↓
E2E crypto integration
    ↓
Files
    ↓
Audit
    ↓
Resilience + recovery
    ↓
Security hardening
    ↓
Performance validation
    ↓
E2E validation
```

Detailed sequencing: `implementation-plan.md`.

---

# 2. Gateway

### Location

```text
src/gateway/
```

### Implement

```text
api/
application/
domain/
infrastructure/
runtime/
```

Main components:

```text
HTTPS Server
TLS Handler
Request Validator
AccessTokenMiddleware
Route/Scope Authorizer
Router
gRPC Client Layer
Rate/Resource Limiter
Deadline/Cancellation Handler
Streaming Proxy
Error Mapper
```

### Consult

* `architecture/architecture.md`
* `design/detailed-design.md`
* `docs/implementation/error-handling-and-retry.md`
* `docs/implementation/api-and-contracts.md`

### Tests

```text
tests/unit/gateway/
tests/integration/gateway/
tests/security/authentication/
tests/security/authorization/
tests/contract/
```

Priority tests:

* token validation
* scope rejection
* downstream timeout
* Auth unavailable
* idempotent command forwarding
* cancellation propagation
* streaming/backpressure

---

# 3. Auth

### Location

```text
src/auth/
```

### Implement

```text
AuthenticationController
CredentialVerifier
MfaManager
SecondFactorVerifier
SessionManager
AccessTokenIssuer
RefreshTokenManager
DeviceManager
DeviceAuthorizationManager
DeviceRevocationManager
CryptoDirectoryManager
PrekeyManager
AuthorizationPolicy
PostgreSQLRepository
TransactionManager
AuditOutboxPublisher
```

### Persistence

PostgreSQL 17.

Keep:

* credentials
* sessions
* refresh-token state
* MFA state
* device state
* crypto-directory state
* prekeys

inside Auth-owned persistence.

### Consult

* `design/data-model.md`
* Auth section of `design/detailed-design.md`
* `openapi/openapi.yaml`
* relevant `proto/securecloud/`

### Tests

Priority:

* credential verification
* TOTP
* MFA enforcement
* token expiration
* refresh rotation
* refresh-token reuse
* concurrent refresh
* device authorization
* device revocation
* prekey handling
* PostgreSQL transaction behavior

---

# 4. Messaging

### Location

```text
src/messaging/
```

### Persistence

ScyllaDB.

Repositories:

```text
MessageRepository
DeliveryRepository
ConversationRepository
MembershipRepository
IdempotencyStore
SyncCursorRepository
```

### Main implementation components

```text
MessageController
ConversationController
SynchronizationController
DeliveryController
MessageValidator
EnvelopeProcessor
DeliveryScheduler
DeliveryWorker
RetryScheduler
SynchronizationCoordinator
ReadReceiptHandler
PresenceCoordinator
BackpressureController
AuthorizationClient
AuditOutboxPublisher
```

### Implement in this order

```text
1. domain entities/state machines
2. Scylla repositories
3. idempotency
4. durable message acceptance
5. outbox
6. delivery persistence
7. delivery scheduler
8. delivery workers
9. retries
10. synchronization
11. read receipts
12. presence
13. resource/backpressure controls
```

Do not start with delivery workers before durable acceptance and delivery persistence are working.

### Tests

Priority:

```text
tests/unit/messaging/
tests/integration/messaging/
tests/security/
tests/resilience/
tests/performance/messaging/
```

Critical scenarios:

* durable acceptance
* duplicate submission
* same idempotency key + different payload
* offline recipient
* retry
* duplicate delivery
* client deduplication
* device revocation
* synchronization cursor
* restart recovery
* concurrent delivery workers

---

# 5. E2E Crypto Integration

### Location

Primarily:

```text
src/client/infrastructure/crypto/
src/client/application/
src/auth/
```

Backend crypto-directory functionality belongs to Auth.

### Client implementation

Integrate the selected vetted Signal-family library.

Implement:

```text
CryptoIdentity
Session
Prekey management
Identity verification
Key-change detection
Message encryption/decryption
Per-device encryption
Device key storage
```

Private keys remain client-side.

### Do not implement

```text
custom encryption algorithm
custom ratchet
custom key exchange
custom cryptographic primitive
```

### Tests

Priority:

* valid encrypt/decrypt
* wrong identity key
* invalid ciphertext
* key change
* revoked device
* multiple recipient devices
* session establishment
* persistence/recovery of local crypto state

---

# 6. Files

### Location

```text
src/files/
```

### Main components

Implement around:

```text
FileController
FileTransferManager
FileMetadataRepository
TransferRepository
ChunkManager
UploadManager
DownloadManager
FinalizationManager
FileAccessAuthorizer
StorageClient
AuditOutboxPublisher
```

Names may be adapted to the final approved detailed design.

### Persistence

```text
PostgreSQL → metadata + transfer state
MinIO      → encrypted file objects
```

### Implement in this order

```text
1. metadata/state model
2. transfer creation
3. chunk upload
4. chunk idempotency
5. resumable upload
6. finalization
7. download
8. download resume
9. access capability
10. resource limits/backpressure
11. cleanup/recovery
```

### Tests

Priority:

* chunk upload
* duplicate chunk
* missing chunk
* interrupted upload
* resumed upload
* corrupted data
* finalization
* interrupted download
* resumed download
* storage unavailable
* resource exhaustion

---

# 7. Audit

### Location

```text
src/audit/
```

### Implement

```text
AuditController
AuditEventProcessor
AuditRepository
OutboxConsumer
AuditStorageWriter
```

Persistence:

```text
ClickHouse
```

Audit ingestion must consume events produced by the services' outboxes.

### Tests

* valid event
* malformed event
* duplicate event
* Audit unavailable
* retry
* pending event after restart
* poison event handling

---

# 8. Client

### Location

```text
src/client/
```

### Main managers

```text
AuthManager
ContactManager
MessagingManager
SyncManager
DeviceManager
FileManager
EmergencyManager
```

### Implementation order

```text
1. application/domain foundations
2. authentication
3. local SQLite persistence
4. contacts/devices
5. synchronization
6. messaging UI/workflows
7. E2E crypto integration
8. files
9. emergency workflow
```

The client must never persist plaintext messages/files intentionally.

### Tests

```text
tests/unit/client/
tests/integration/client/
tests/e2e/
```

Priority:

* authentication workflow
* local encrypted-state handling
* sync/reconnect
* outgoing message lifecycle
* incoming message lifecycle
* deduplication
* read receipts
* device changes
* file transfer resume

---

# 9. Common Infrastructure

### Location

```text
src/common/
```

Allowed content:

* logging infrastructure
* configuration loading
* common error infrastructure
* networking utilities
* time/deadline utilities
* resource-limit utilities
* tracing/metrics infrastructure
* technical serialization helpers

Do **not** place:

* Message
* User
* Conversation
* File
* Device
* business policies
* service-specific repositories

in `common/`.

If a component contains business rules, it belongs to the owning service/client domain.

---

# 10. Contracts

### REST

Source of truth:

```text
openapi/openapi.yaml
```

### gRPC

Source of truth:

```text
proto/securecloud/
```

When implementing an endpoint:

```text
contract
   ↓
generated types/stubs
   ↓
API adapter
   ↓
application use case
   ↓
domain
   ↓
infrastructure
```

Generated code is never manually edited.

---

# 11. Database Implementation

## PostgreSQL

Used by:

```text
Auth
Files
```

Each service owns its tables and migrations.

Database code stays inside:

```text
src/<service>/infrastructure/persistence/
```

Use parameterized queries and explicit transactions.

## ScyllaDB

Used by:

```text
Messaging
```

Implement queries from the approved access patterns rather than designing relational-style queries first.

Before adding a table/index, identify:

```text
query
partition key
clustering order
expected cardinality
hot-partition risk
```

## MinIO

Used by:

```text
Files
```

Store only encrypted objects.

## ClickHouse

Used by:

```text
Audit
```

Optimize for append-oriented audit ingestion and analytical queries rather than transactional behavior.

---

# 12. Error / Retry Integration

Use:

```text
docs/implementation/error-handling-and-retry.md
```

Do not create local retry policies inside individual components.

When implementing a dependency call, explicitly determine:

```text
deadline
retryable?
idempotent?
cancellable?
failure mapping?
circuit-breaker domain?
```

Commands with unknown outcomes must use their idempotency mechanism rather than blindly retrying.

---

# 13. Testing Integration

For every implemented component, add tests at the appropriate levels:

```text
domain/application change
        → unit tests

database/network integration
        → integration tests

API/protobuf change
        → contract tests

security-sensitive change
        → security tests

distributed failure behavior
        → resilience tests

cross-service workflow
        → E2E tests

performance-sensitive change
        → benchmark/regression test
```

See `testing-strategy.md`.

---

# 14. When a Developer Is Unsure Where Code Belongs

Use this decision sequence:

```text
Is it business/domain behavior?
        → domain/

Does it coordinate a use case?
        → application/

Is it an HTTP/gRPC/API adapter?
        → api/

Does it talk to DB, network, MinIO, crypto library, OS, etc.?
        → infrastructure/

Is it worker/concurrency/lifecycle/resource management?
        → runtime/

Is it shared technical infrastructure?
        → common/
```

If the answer crosses a service boundary, use its API contract instead of importing its implementation.

---

# 15. Feature Implementation Checklist

Before opening a PR, verify:

```text
[ ] Correct service owns the implementation
[ ] Existing design document consulted
[ ] Existing API/Protobuf contract used
[ ] No architecture bypass introduced
[ ] State transitions implemented explicitly
[ ] Persistence behavior implemented
[ ] Error/retry behavior implemented
[ ] Resource limits respected
[ ] Relevant tests added
[ ] Security-negative tests added where applicable
[ ] Logging contains no sensitive data
[ ] Documentation updated if an interface/decision changed
[ ] CI passes
```

---

# 16. Source-of-Truth Navigation

When implementing:

| Question                              | Document                          |
| ------------------------------------- | --------------------------------- |
| Why does the system look this way?    | `architecture/`                   |
| What exactly was decided?             | `architecture/adr/`               |
| How does a component behave?          | `design/detailed-design.md`       |
| What data does it own?                | `design/data-model.md`            |
| What does the API look like?          | `openapi/openapi.yaml` / `proto/` |
| How should C++ be written?            | `coding-rules.md`                 |
| What happens on failure?              | `error-handling-and-retry.md`     |
| How do we test it?                    | `testing-strategy.md`             |
| How does the team work?               | `development-workflow.md`         |
| What should be implemented next?      | `implementation-plan.md`          |
| Where does the code belong?           | `repository-structure.md`         |
| What do I implement for this service? | **This document**                 |

---

# 17. Final Rule

This document is a **navigation and implementation checklist**, not a second architecture document.

When implementation conflicts with an approved decision:

**stop → identify the conflict → resolve/update the source of truth → implement.**
