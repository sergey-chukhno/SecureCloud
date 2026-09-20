# SecureCloud --- Initial Implementation Backlog

**Status:** Implementation baseline\
**Current backlog:** 46 cards\
**Purpose:** Engineering specification for the current Trello backlog.

> Trello tracks execution/status. This document defines the intended
> outcome, scope, dependencies, tests, and acceptance criteria. It does
> not redesign the approved architecture.

## 1. Frozen milestone definitions

  Milestone   Meaning
  ----------- --------------------------------
  M1          Buildable Distributed Skeleton
  M2          Authenticated Platform
  M3          Secure Messaging
  M4          Offline Messaging
  M5          Secure Files
  M6          Auditable Platform
  M7          Resilient Platform
  M8          Validated MVP

These meanings are frozen. Future cards must preserve them unless the
user explicitly requests a formal redefinition.

## 2. Backlog rules

-   Card IDs are stable.
-   One card represents one meaningful engineering outcome.
-   Antigravity decomposes a selected card into implementation tickets;
    it does not redesign the architecture.
-   Owners are primary implementation owners.
-   Trello is the execution board; this file is the engineering
    specification.
-   Future milestones are deliberately not designed yet. We implement
    the current backlog first and plan the next slice just in time.

## 3. M1 --- Buildable Distributed Skeleton

### SC-001 --- Initialize CMake project

**Labels:** Infrastructure, Feature, M1\
**Owner:** Sergey\
**Dependencies:** None

Create the C++20/CMake foundation, root build configuration, initial
source/test structure, `CMakePresets.json`, and clean configure/build
workflow.

**Acceptance:** clean checkout configures and builds using the
documented CMake workflow.

### SC-002 --- Configure project dependencies

**Labels:** Infrastructure, Feature, M1\
**Owner:** Sergey\
**Dependencies:** SC-001

Configure and version-control the approved C++/gRPC/Protobuf,
database/storage, TLS/crypto, testing, and tooling dependencies without
unnecessary additions.

**Acceptance:** dependencies resolve reproducibly and no undocumented
manual setup is required.

### SC-003 --- Configure GoogleTest + CTest

**Labels:** Infrastructure, Test, M1\
**Owner:** Sergey\
**Dependencies:** SC-001, SC-002

Integrate GoogleTest, CTest, test discovery, and an initial
deterministic test target.

**Acceptance:** `ctest` runs successfully and failures propagate
correctly.

### SC-004 --- Configure clang-format + clang-tidy

**Labels:** Infrastructure, Refactor, M1\
**Owner:** Sergey\
**Dependencies:** SC-001, SC-002

Create `.clang-format` and `.clang-tidy` and establish consistent
invocation/CI checks.

**Acceptance:** formatting and static analysis run consistently.

### SC-005 --- Configure Protobuf + gRPC generation

**Labels:** Infrastructure, Feature, M1\
**Owner:** Sergey\
**Dependencies:** SC-001, SC-002

Integrate `proto/securecloud/`, protoc, the gRPC plugin, generated-code
output, and CMake wiring.

**Acceptance:** representative contracts generate and compile; generated
code is never manually edited.

### SC-006 --- Create service executable skeletons

**Labels:** Infrastructure, Feature, M1\
**Owner:** Sergey\
**Dependencies:** SC-001, SC-002, SC-005

Create independently buildable Gateway, Auth, Messaging, Files, Audit,
and Client targets with basic lifecycle entry points.

**Acceptance:** every service target builds independently and no service
executable links another service's business implementation.

### SC-007 --- Create service Dockerfiles

**Labels:** Infrastructure, Feature, M1\
**Owner:** Dev 3\
**Dependencies:** SC-006

Create independent service images with external configuration and no
secrets embedded in images.

**Acceptance:** all backend service images build and start with external
configuration.

### SC-008 --- Create Docker Compose development environment

**Labels:** Infrastructure, Feature, M1\
**Owner:** Dev 3\
**Dependencies:** SC-007

Compose Gateway, Auth, Messaging, Files, Audit, PostgreSQL, ScyllaDB,
MinIO, and ClickHouse with networks, health checks, configuration, and
development volumes.

**Acceptance:** one documented Compose workflow starts the distributed
development environment.

### SC-009 --- Establish development CA and service certificates

**Labels:** Infrastructure, Security, M1\
**Owner:** Sergey\
**Dependencies:** SC-006

Create the private SecureCloud development CA and unique service
certificates/private keys.

**Acceptance:** every service has a distinct development identity;
service private keys are never shared.

### SC-010 --- Establish service-to-service mTLS foundation

**Labels:** Infrastructure, Security, M1\
**Owner:** Sergey\
**Dependencies:** SC-009, SC-005

Configure TLS 1.3/mTLS for internal gRPC with explicit certificate
verification and fail-closed behavior.

**Acceptance:** valid service identity succeeds; invalid/untrusted
identity fails.

### SC-011 --- Establish development persistence and storage infrastructure

**Labels:** Infrastructure, Feature, M1\
**Owner:** Dev 2 + Dev 3\
**Dependencies:** SC-008

Provide PostgreSQL 17, ScyllaDB, MinIO, and ClickHouse with development
initialization and connectivity checks.

**Acceptance:** required services can reach only the persistence/storage
systems they need.

### SC-012 --- Establish service configuration foundation

**Labels:** Common, Feature, M1\
**Owner:** Sergey\
**Dependencies:** SC-006, SC-008

Implement external configuration loading/validation,
environment-specific configuration, and resource/deadline configuration
foundations.

**Acceptance:** invalid required configuration fails clearly; secrets
are not committed.

### SC-013 --- Establish health and readiness endpoints

**Status:** Completed (Milestone M1)\
**Labels:** Infrastructure, Feature, M1\
**Owner:** Sergey + Dev 2 + Dev 3\
**Dependencies:** SC-008, SC-011, SC-012

Implement liveness/readiness and relevant dependency health checks adhering to ADR-009 Section 23/24.

**Implementation Summary:**
- Implemented reusable `HealthStatusManager`, `HealthServiceImpl`, and `TransportProbe` in `securecloud::common::health`.
- Explicit service name ownership passed into constructors.
- Protocol semantic convention: `""` or `<service_name>` = Liveness, `"readiness"` = Readiness, unknown string = `SERVICE_UNKNOWN`.
- Bounded M1 transport-level TCP connectivity probes with a strict 250 ms maximum probe deadline.
- Enforced strict Gateway local readiness (zero downstream fan-out / zero cascading failure).
- Enforced fail-closed mTLS peer authentication (`GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY`).
- Verified real Docker dependency outage: PostgreSQL container down causes `auth` and `files` readiness to degrade to `NOT_SERVING` while process liveness remains `SERVING`, and other services (`messaging`, `audit`, `gateway`) remain `SERVING`.
- Verified graceful shutdown immediately degrades readiness to `NOT_SERVING`.
- All 5 microservices migrated to common health infrastructure, deleting 6 duplicated `HealthServiceImpl` classes.
- Full verification suite: unit tests (`HealthStatusManagerTest`, `HealthServiceImplTest`, `TransportProbeTest`), mTLS integration tests (`HealthIntegrationTest`, `MtlsIntegrationTest`), and automated Docker Compose test suite (`scripts/verify-health-endpoints.sh`).
- CodeRabbit review findings resolved (SC-013-C01 through SC-013-C04):
  - SC-013-C01: Enforced monotonic 250 ms budget across complete transport probe operation and fail-closed non-positive timeout handling.
  - SC-013-C02: Strict validation of `--timeout-ms` in health probe CLI rejecting invalid/out-of-range inputs with exit code 3.
  - SC-013-C03: Reliable EXIT/INT/TERM cleanup in `verify-health-endpoints.sh` with post-outage failure resilience check.
  - SC-013-C04: Configurable Compose host ports (`GATEWAY_HOST_PORT` through `AUDIT_HOST_PORT`) exercised with non-default port overrides.

**Acceptance:** process startup is not treated as readiness when
required dependencies are unavailable. Fully verified with 100% passing tests.

### SC-014 --- Establish initial CI pipeline

**Labels:** Infrastructure, Test, M1\
**Owner:** Sergey\
**Dependencies:** SC-003, SC-004, SC-005, SC-006

Automate configure/build, CTest, formatting, and static-analysis gates.

**Acceptance:** required failures block the CI result.

### SC-015 --- Validate distributed development environment

**Labels:** Infrastructure, Test, M1\
**Owner:** All 3\
**Dependencies:** SC-008, SC-009, SC-010, SC-011, SC-012, SC-013, SC-014

Validate clean checkout, build, Compose startup, health/readiness,
persistence, representative mTLS/gRPC, tests, and CI.

**Acceptance:** each developer reproduces the environment without
undocumented fixes.

### SC-016 --- M1 Foundation validation and handoff

**Labels:** Infrastructure, Test, M1\
**Owner:** All 3\
**Dependencies:** SC-015

Close M1 after acceptance criteria, CI, repository boundaries, and
known-issue recording are complete.

**Acceptance:** foundation is explicitly ready for vertical-slice
implementation.

## 4. M2 --- Authenticated Platform

### AUTH-001 --- Establish Auth service foundation

**Labels:** Auth, Feature, M2\
**Owner:** Dev 2\
**Dependencies:** SC-010, SC-011, SC-012, SC-013

Create the Auth runtime, gRPC/mTLS server, PostgreSQL foundation,
lifecycle, health/readiness, and graceful shutdown.

**Acceptance:** Auth runs independently and securely exposes its
approved internal contract.

### AUTH-002 --- Establish Auth PostgreSQL persistence

**Labels:** Auth, Feature, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-001

Implement the approved Auth model for users/credentials, devices, device
public keys, sessions, refresh-token state, MFA, crypto directory, and
prekeys, including migrations, indexes, repositories, transactions, and
concurrency handling.

**Acceptance:** approved persistence tests pass; no other service
accesses Auth PostgreSQL directly.

### AUTH-003 --- Implement credential authentication

**Labels:** Auth, Feature, Security, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-002

Implement credential lookup/normalization, Argon2id verification,
account-status checks, safe failures, and audit-outbox event production.

**Acceptance:** valid credentials authenticate; invalid credentials do
not disclose account existence; disabled accounts cannot authenticate.

### AUTH-004 --- Implement device-specific session management

**Labels:** Auth, Feature, Security, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-003

Implement durable device-specific ACTIVE/REVOKED/EXPIRED sessions and
authentication assurance.

**Acceptance:** session state is durable, device-specific, and enforced
where required.

### AUTH-005 --- Implement access and refresh token lifecycle

**Labels:** Auth, Feature, Security, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-004

Implement short-lived signed access tokens, Auth-owned private signing
key, Gateway public verification material, stateful rotated refresh
tokens, and reuse detection.

**Acceptance:** Gateway validates tokens without possessing Auth's
private signing key; refresh reuse is detected safely.

### AUTH-006 --- Implement MFA / TOTP

**Labels:** Auth, Feature, Security, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-005

Implement TOTP, MFA challenge/verification,
`PRIMARY_ONLY`/`MFA_VERIFIED`, sensitive-operation enforcement, and
secure MFA-secret storage.

**Acceptance:** sensitive operations require the correct assurance
level; MFA secrets never enter logs/API/audit.

### AUTH-007 --- Implement device lifecycle and authorization

**Labels:** Auth, Feature, Security, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-005, AUTH-006

Implement explicit device pairing/approval, authorization, revocation,
associated session/token revocation, and future-message exclusion.

**Acceptance:** JWT alone cannot register a new device; revoked devices
cannot authenticate future requests or receive new messages.

### AUTH-008 --- Implement public cryptographic identity directory

**Labels:** Auth, Feature, Security, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-007

Implement opaque UserId/DeviceId, public identity keys, signed prekeys,
key versioning/replacement, and revocation state.

**Acceptance:** only public cryptographic material is exposed.

### AUTH-009 --- Implement prekey management

**Labels:** Auth, Feature, Security, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-008

Implement signed/one-time prekey registration, retrieval, atomic
consumption, replenishment, exhaustion handling, and concurrency
protection.

**Acceptance:** one-time prekeys cannot be consumed successfully twice
concurrently.

### AUTH-010 --- Integrate Auth with Gateway

**Labels:** Auth, Gateway, Feature, Security, Test, M2\
**Owner:** Dev 2\
**Dependencies:** AUTH-005, AUTH-006, AUTH-007, AUTH-008, GW-004,
GW-005, GW-007

Complete the Gateway/Auth authentication path including credentials,
token validation, MFA assurance, device/session state, and public
signing-key verification.

**Acceptance:** valid/invalid flows behave correctly end-to-end and
Gateway never receives Auth's private signing key.

## 5. Gateway platform slice

Gateway has no separate milestone: it is shared platform infrastructure
used by M2 and later service integrations.

### GW-001 --- Establish Gateway service foundation

**Labels:** Gateway, Feature, M2\
**Owner:** Sergey\
**Dependencies:** SC-006, SC-010, SC-012, SC-013

Create HTTP server, configuration, lifecycle, routing foundation, gRPC
client foundation, health/readiness, and no-DB architecture.

**Acceptance:** Gateway runs independently and has no business-data
persistence.

### GW-002 --- Establish external HTTPS/TLS endpoint

**Labels:** Gateway, Feature, Security, M2\
**Owner:** Sergey\
**Dependencies:** GW-001, SC-009

Implement HTTPS/TLS 1.3, certificate/key configuration, request/resource
limits, and no insecure downgrade.

**Acceptance:** invalid TLS/security configuration is rejected.

### GW-003 --- Establish Gateway internal gRPC client layer

**Labels:** Gateway, Feature, Security, M2\
**Owner:** Sergey\
**Dependencies:** GW-001, SC-010, SC-005

Implement reusable internal gRPC channels with mTLS, connection
management, deadlines, and cancellation.

**Acceptance:** Gateway makes authenticated gRPC calls and propagates
deadline/cancellation correctly.

### GW-004 --- Implement access-token authentication middleware

**Labels:** Gateway, Security, M2\
**Owner:** Sergey\
**Dependencies:** GW-003, AUTH-005

Validate token signature, issuer, audience, expiry, required claims,
token version, and authentication level where applicable.

**Acceptance:** invalid/expired/tampered tokens are rejected before
protected route execution.

### GW-005 --- Implement AuthenticatedContext

**Labels:** Gateway, Feature, Security, M2\
**Owner:** Sergey\
**Dependencies:** GW-004

Create request-scoped
`{user_id, device_id, session_id, scopes, authentication_level}`.

**Acceptance:** downstream handlers use trusted request context rather
than reparsing credentials.

### GW-006 --- Implement Gateway routing

**Labels:** Gateway, Feature, M2\
**Owner:** Sergey\
**Dependencies:** GW-003, GW-005

Route requests to owning services without backend business logic or
database access.

**Acceptance:** public/protected routes reach the owning service through
the approved path.

### GW-007 --- Implement route/scope authorization

**Labels:** Gateway, Security, M2\
**Owner:** Sergey\
**Dependencies:** GW-005, AUTH-006

Implement coarse scope/assurance authorization while preserving backend
fine-grained authorization.

**Acceptance:** insufficient scope/assurance is rejected before
forwarding.

### GW-008 --- Implement Gateway error, deadline, and cancellation handling

**Labels:** Gateway, Feature, Test, M2\
**Owner:** Sergey\
**Dependencies:** GW-003, GW-006

Implement deadlines, cancellation propagation, error mapping, and
approved retry behavior.

**Acceptance:** downstream timeout/failure/cancellation has
deterministic client-visible semantics.

### GW-009 --- Implement Gateway resilience and resource controls

**Labels:** Gateway, Performance, Security, M2\
**Owner:** Sergey\
**Dependencies:** GW-008

Implement bounded concurrency, rate/resource limiting, backpressure,
bulkheads, circuit breakers, and graceful shutdown.

**Acceptance:** resource exhaustion is explicit/bounded; no unbounded
request queues or thread-per-request model.

### GW-010 --- Implement Gateway streaming proxy

**Labels:** Gateway, Files, Feature, Performance, Security, M5\
**Owner:** Sergey\
**Dependencies:** GW-008, GW-009, FILE-005, FILE-007

Implement HTTP streaming ↔ gRPC streaming for Files with bounded
buffers, backpressure, cancellation, idle timeout, and transfer limits.

**Acceptance:** large transfers do not require whole-file buffering and
slow clients propagate pressure upstream.

## 6. M5 --- Secure Files

### FILE-001 --- Establish Files service foundation

**Labels:** Files, Feature, M5\
**Owner:** Dev 3\
**Dependencies:** SC-010, SC-011, SC-012, SC-013

Create Files runtime/lifecycle, gRPC/mTLS server,
PostgreSQL/object-storage client foundations, health/readiness, and
graceful shutdown.

**Acceptance:** Files runs independently and never decrypts file
content.

### FILE-002 --- Establish Files PostgreSQL persistence

**Labels:** Files, Feature, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-001

Implement approved File, FileVersion, FileTransfer, FileChunk,
FileAccess, EncryptedFileMetadata, and transactional-outbox persistence.

**Acceptance:** metadata/lifecycle/transfer state survives restart and
other services cannot access Files PostgreSQL directly.

### FILE-003 --- Establish MinIO object storage integration

**Labels:** Files, Feature, Security, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-001, SC-011

Implement bounded MinIO/S3-compatible operations for encrypted
objects/chunks, reads, existence/metadata, integrity-related operations,
and cleanup.

**Acceptance:** ciphertext can be stored/retrieved without Files or
MinIO decrypting it.

### FILE-004 --- Implement file metadata and lifecycle

**Labels:** Files, Feature, Security, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-002

Implement file/version creation, metadata retrieval, lifecycle
validation, expiration, logical deletion, and immutable completed
versions.

Primary lifecycle: `CREATED → UPLOADING → FINALIZING → AVAILABLE`, with
approved failure/expiration/deletion paths.

**Acceptance:** invalid transitions are rejected and AVAILABLE versions
are immutable.

### FILE-005 --- Implement resumable chunked uploads

**Labels:** Files, Feature, Performance, Security, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-002, FILE-003, FILE-004

Implement durable UploadId, 4 MiB maximum logical chunk model, chunk
progress, duplicate/out-of-order/missing chunks, reconnect/resume,
cancellation, bounded memory, and idempotency.

Logical chunk identity: `UploadId + ChunkIndex`. Same encrypted chunk
retries are idempotent; conflicting hashes are rejected.

**Acceptance:** interrupted uploads resume without re-uploading accepted
chunks and concurrent duplicates cannot corrupt state.

### FILE-006 --- Implement upload finalization and integrity

**Labels:** Files, Security, Test, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-005

Verify transfer state, all expected chunks, metadata consistency,
storage state, integrity, and durable final state before `AVAILABLE`.

**Acceptance:** AVAILABLE is never reported unless finalization
requirements pass; concurrent finalization is deterministic/idempotent.

### FILE-007 --- Implement resumable downloads

**Labels:** Files, Feature, Performance, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-003, FILE-004, FILE-008

Implement encrypted streaming and resume using `file_id`,
`file_version`, and `starting_chunk`, with bounded buffers,
cancellation, idle timeout, and no whole-file buffering.

**Acceptance:** interrupted downloads resume from the requested
encrypted chunk.

### FILE-008 --- Implement file access authorization

**Labels:** Files, Security, Test, M5\
**Owner:** Dev 3\
**Dependencies:** AUTH-007, FILE-004

Enforce the approved short-lived file-access capability bound to
authenticated user/device, file, operation, expiration, and version
where required.

**Acceptance:** expired, malformed, wrong-user/device/file/operation,
and revoked-device access is rejected.

### FILE-009 --- Implement Files streaming and resource controls

**Labels:** Files, Performance, Security, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-005, FILE-007

Implement separate bounded concurrency for metadata/uploads/downloads
and limits for active transfers, streams, DB connections, MinIO
operations, memory, chunk processing, and request/transfer sizes.

Implement backpressure; forbid thread-per-transfer and unbounded queues.

**Acceptance:** slow clients cannot cause unbounded resource growth and
one device cannot consume unlimited transfer capacity.

### FILE-010 --- Integrate Files with Gateway and audit-outbox production

**Labels:** Files, Gateway, Feature, Security, Test, M5\
**Owner:** Dev 3\
**Dependencies:** FILE-006, FILE-007, FILE-008, FILE-009, GW-010

Complete
create/upload/finalize/metadata/download/resume/delete/expiration
through Gateway → Files → PostgreSQL/MinIO and establish durable Files
audit-event production through the transactional outbox.

**Important:** actual Audit Service ingestion is not a dependency of M5.
M6 implements Audit ingestion.

**Acceptance:** end-to-end Files workflows pass through Gateway and
required audit events survive temporary Audit unavailability via the
Files outbox.

## 7. Cross-backlog review results

### Must fix before implementation

1.  **FILE-003 authority wording:** PostgreSQL is authoritative for file
    metadata, lifecycle, and transfer state. MinIO is authoritative for
    encrypted binary object storage only.
2.  **FILE-010 Audit dependency:** Files must not wait for the future
    Audit Service. Produce durable outbox events now; M6 consumes them.

### Should adjust

1.  Gateway has no standalone milestone; its cards support platform
    milestones and later integrations.
2.  FILE-008 consumes Auth's approved identity/device/revocation
    semantics rather than creating an independent identity model.
3.  Resource limits remain configurable where the approved design
    specifies configuration; concrete baseline values come from
    `error-handling-and-retry.md` and the Files design/data model.

## 8. Implementation readiness

The 46-card backlog is sufficient to begin implementation.

**Ready now:** - SC-001 → SC-016 - AUTH-001 → AUTH-010 - GW-001 →
GW-009 - FILE-001 → FILE-009

**Ready after the stated dependency corrections:** - GW-010 - FILE-010

**Not yet designed intentionally:** - M3 Secure Messaging - M4 Offline
Messaging - M6 Auditable Platform - M7 Resilient Platform - M8 Validated
MVP

These are deliberately deferred so planning does not become a blocker to
implementation.

## 9. Antigravity workflow

For each selected card:

1.  Read `.antigravity/RULES.md`.
2.  Read the relevant architecture/design/data-model/API/implementation
    documents.
3.  Read this card in `docs/planning/initial-backlog.md`.
4.  Inspect the current repository state.
5.  Decompose the card into concrete implementation
    tickets/files/tests/dependencies.
6.  Do not redesign approved architecture.
7.  Do not write implementation code until the decomposition is reviewed
    and approved.
8.  After approval, implement and test.
9.  Move the Trello card through
    `IN PROGRESS → CODE REVIEW → TESTING / INTEGRATION → DONE`.

## 10. Definition of Ready

A card is ready when its objective, dependencies, owner, relevant
references, security constraints, tests, and acceptance criteria are
sufficiently clear for Antigravity to produce an implementation
decomposition without inventing architecture.

## 11. Definition of Done

A card is done when implementation, required tests, relevant
failure/security cases, formatting/static analysis,
architecture-boundary checks, documentation/contract updates where
necessary, CI, code review, and acceptance criteria are complete.

## 12. Guiding principle

> **Plan enough to implement safely; then implement. Do not design the
> entire future backlog before starting work.**
