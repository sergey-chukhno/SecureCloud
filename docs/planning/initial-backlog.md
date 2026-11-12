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

**Status:** Completed (Milestone M1)\
**Labels:** Infrastructure, Test, M1\
**Owner:** Sergey\
**Dependencies:** SC-003, SC-004, SC-005, SC-006

Automate configure/build, CTest, formatting, and static-analysis gates.

**Implementation Summary:**
- **SC-014-T01 (Cross-Platform Portability Foundation)**:
  - Adapted transport probe and unit/integration test helpers for native compatibility across macOS, Windows MSVC, and Windows MinGW (Win32 sockets, WSAStartup/WSACleanup, CreateProcessW, ws2_32 linking).
  - Preserved bounded 250 ms deadline, non-blocking polling, and fail-closed handling.
  - Injected explicit manifest dependencies into `vcpkg.json` for deterministic Windows MSVC resolution while leaving macOS/MinGW host package managers untouched.
  - Defined explicit `ci-windows-msvc` and `ci-windows-mingw` CMake presets.
- **SC-014-T02 (Local Developer Verification Orchestrator)**:
  - Authored `scripts/verify-local.py` strictly as an orchestrator consuming `CMakePresets.json`, `check-format`, `verify-contracts`, and `ctest`. Zero duplicated build/compiler logic.
  - Provided thin POSIX (`verify-local.sh`) and Windows PowerShell (`verify-local.ps1`) wrappers.
  - Added `verify-contracts` CMake custom target.
- **SC-014-T03 (GitHub Actions Multi-Platform CI Pipeline)**:
  - Authored `.github/workflows/ci.yml` with pinned runner versions (`macos-14`, `windows-2022`).
  - Implemented 4 parallel jobs: `quality-gates` (canonical runner for clang-format, clang-tidy, and contracts), `macos-build-test`, `windows-msvc-build-test`, and `windows-mingw-build-test` (using verified UCRT64 package identifiers).
- **SC-014-T04 (CodeRabbit Review Integration)**:
  - Configured `.coderabbit.yaml` adhering strictly to schema v2 with assertive profile and SecureCloud-specific path instructions.
  - Clearly separated review configuration from GitHub branch protection enforcement.
- **SC-014-T05 (Developer Workflow Documentation & Branch Protection Spec)**:
  - Authored comprehensive developer documentation in `docs/implementation/development-workflow.md`.
  - Detailed GitHub repository branch protection rules for `main`.

**Acceptance:** required failures block the CI result; all local verification stages pass 100%. Fully verified.

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

## 7. Client Desktop Application (Native C++20 / Qt6)

### Overview & The 4 Phases of Client Development

The SecureCloud Native Desktop Client roadmap spans **16 milestone cards structured into 4 cohesive phases (4 cards per phase)**:

| Phase | Focus & Milestones | Cards | Status |
|:---|:---|:---|:---|
| **Phase 1** | **Foundation & Presentation Shell** | `CLIENT-001` → `CLIENT-004` | **100% Completed** (merged into `main`) |
| **Phase 2** | **Cryptographic Identity, Session Ratchets & Multi-Device Trust** | `CLIENT-005` → `CLIENT-008` | **In Progress** (`005`, `006` completed; `007` ready; `008` planned) |
| **Phase 3** | **Production Messaging Engine, Real-Time Streaming & File Vault** | `CLIENT-009` → `CLIENT-012` | **Roadmap-Planned** |
| **Phase 4** | **Emergency Defense, User Settings, Diagnostics & Release Packaging** | `CLIENT-013` → `CLIENT-016` | **Roadmap-Planned** (includes official CPU/RAM benchmarking & impact audit in `CLIENT-015`) |

---

### Phase 1: Foundation & Presentation Shell (`CLIENT-001` — `CLIENT-004`) [COMPLETED]

| Card ID | Title | Status | Primary Focus |
|:---|:---|:---|:---|
| **CLIENT-001** | Client Application Foundation & Layered Architecture | Completed | C++20/Qt6 4-layer architecture (`UI -> Application -> Domain <- Infrastructure`), CMake, domain skeletons, test harness |
| **CLIENT-002** | UI Design System, Theme Engine & Reusable Controls | Completed | Dark/Light semantic palettes, 8 reusable `SC*` controls, navigation shell |
| **CLIENT-003** | Auth Flow, 4-Zone Shell, Files Vault & Settings Center | Completed | Login/MFA challenge, 4-zone workspace shell, Encrypted Files Vault, Settings Trust Center |
| **CLIENT-004** | Contacts, Conversations & Messaging UI | Completed | Direct/Group conversations, delivery lifecycle, Contact CRUD, ADR-007/008 UI bindings |

---

### Phase 2: Cryptographic Identity, Session Ratchets & Multi-Device Trust (`CLIENT-005` — `CLIENT-008`) [IN PROGRESS]

| Card ID | Title | Status | Primary Focus |
|:---|:---|:---|:---|
| **CLIENT-005** | Device Registration & Cryptographic Identity Lifecycle | Completed | Ed25519/X25519 keypairs, X3DH prekeys, Auth registration via Gateway, `SecretString` zeroization |
| **CLIENT-006** | Signal Double Ratchet Session Management & E2EE | Completed | Full Double Ratchet state machine, HKDF chains, out-of-order skipped key store, AES-256-GCM |
| **CLIENT-007** | Device Management, Multi-Device Trust & Hardware Security | Specified (`specs/client-phase2/`) | Companion device pairing (QR/SAS), remote revocation, Double Ratchet purge, hardware MFA |
| **CLIENT-008** | Contact Management & Peer Identity Verification | Planned | Peer contact directory sync, 60-digit safety numbers, automated identity key change alerts |

---

### Phase 3: Production Messaging Engine, Real-Time Streaming & File Vault (`CLIENT-009` — `CLIENT-012`) [ROADMAP]

#### CLIENT-009 --- Direct & Group Messaging Engine

**Labels:** Client, Feature, Messaging, E2EE, Phase 3\
**Owner:** Sergey\
**Dependencies:** CLIENT-006, CLIENT-007, CLIENT-008

Implement production 1:1 direct and multi-party group messaging with durable encrypted persistence:
- **Direct Messaging Pipeline:** Wire `MessagingManager` to `RatchetSessionManager` for automatic X3DH session initiation, ratchet stepping, and AEAD encryption/decryption.
- **Multi-Device & Group Fan-Out:** Implement pairwise multi-recipient fan-out per participant device (ADR-008 §4, §14) and integrate Sender Keys state machine for high-occupancy groups.
- **Encrypted Local Persistence (`ILocalStore`):** Implement SQLCipher encrypted SQLite database adapter, securing conversations, messages, participant lists, and delivery states with keys derived from the user passphrase/OS keychain.
- **Group Lifecycle:** Group creation, member addition/removal, role permissions (Admin, Member), and participant key updates.

**Acceptance:** Direct and group messages encrypt and decrypt flawlessly across multiple endpoints; all message entities persist securely in SQLCipher; zero unencrypted plaintext on disk.

#### CLIENT-010 --- Real-Time Delivery & Read Receipts

**Labels:** Client, Feature, Real-Time, Gateway, Phase 3\
**Owner:** Sergey\
**Dependencies:** CLIENT-004, CLIENT-009

Establish the real-time event pipeline and delivery acknowledgement state machine:
- **Gateway Push Stream:** Bidirectional WebSocket / gRPC streaming client connecting to the Gateway event dispatcher for incoming messages, delivery receipts, and presence updates.
- **Delivery State Lifecycle:** Model state transitions (`Pending -> Sent -> Delivered -> Read -> Failed`) with monotonic server sequence tracking (ADR-007 §4).
- **Asynchronous Acknowledgements:** Ephemeral signed delivery receipts dispatched per device upon payload reception and decryption.
- **Read Receipt Policy:** Configurable read receipt toggle in Settings (enabling or suppressing outbound read receipts for privacy).
- **Idempotency & Retry Engine:** Message retry queue with exponential backoff and unique `ClientMessageId` to ensure exactly-once delivery semantics (ADR-007 §3).

**Acceptance:** UI displays live message delivery ticks (Sent, Delivered, Read) in real time without polling; idempotent retry guarantees zero duplicate messages during intermittent network drops.

#### CLIENT-011 --- Encrypted File Transfer & Streaming

**Labels:** Client, Feature, Files, E2EE, Phase 3\
**Owner:** Sergey\
**Dependencies:** CLIENT-006, CLIENT-009, FILE-001 → FILE-010

Implement end-to-end encrypted file attachments and resumable chunked transfers:
- **Local AEAD Chunking:** Chunk large files into 1MB blocks, encrypting each block with AES-256-GCM using an ephemeral symmetric file key transmitted via pairwise Double Ratchet envelope (ADR-008 §9).
- **Resumable Gateway Pipeline:** Integrate with Gateway `/api/v1/files/transfers` for chunked uploads and streaming downloads against MinIO object storage.
- **Integrity Attestation:** Calculate and verify SHA-256 rolling digest and AEAD authentication tags across all chunks before local file assembly.
- **UI Vault & Progress Bindings:** Native OS file picker dialogs, inline chat progress bars (`0..100%`), pause/resume controls, and ledger management in the Files Vault zone.

**Acceptance:** Upload and download of multi-megabyte files (e.g. >100MB) succeed with verified SHA-256 integrity, pause/resume capability, and real-time UI progress feedback.

#### CLIENT-012 --- Offline Operation & Catch-Up Sync

**Labels:** Client, Feature, Resilience, Sync, Phase 3\
**Owner:** Sergey\
**Dependencies:** CLIENT-009, CLIENT-010

Enable offline message drafting, persistent queued operations, and catch-up synchronization:
- **Durable Offline Outbox:** Queue outbound messages, file transfer metadata, and read receipts in encrypted SQLCipher storage when the network is unreachable.
- **Connectivity Observer:** Monitor network interface state and Gateway reachability, automatically transitioning between `Online`, `Offline`, and `Syncing` states.
- **Catch-Up Synchronization Protocol:** On reconnect, query Gateway with the latest client sequence cursor (`GET /api/v1/sync?cursor=<cursor>`), receiving missed incoming events.
- **Reconciliation State Machine:** Merge missed messages, deduplicate re-delivered packets, and resolve concurrent contact/conversation updates without data loss.

**Acceptance:** Users can compose messages offline; upon network reconnection, queued operations flush automatically in correct order and remote updates merge cleanly.

---

### Phase 4: Emergency Defense, User Settings, Diagnostics & Release Packaging (`CLIENT-013` — `CLIENT-016`) [ROADMAP]

#### CLIENT-013 --- Emergency Panic & Data Wipe

**Labels:** Client, Security, Privacy, Emergency, Phase 4\
**Owner:** Sergey\
**Dependencies:** CLIENT-003, CLIENT-005, CLIENT-009

Implement forensic-grade data destruction and emergency broadcast workflows:
- **Panic Triggers:** Dual trigger mechanisms: global hotkey (`Cmd+Shift+E` / `Ctrl+Shift+E`), UI panic button, or login duress PIN.
- **Cryptographic Destruction Sequence:**
  1. Immediate volatile memory zeroization (`SecretString::wipe`, OpenSSL context clearing).
  2. Wiping private identity keys, prekeys, and ratchet sessions from OS Keychain/Secure Storage.
  3. Secure shredding (multi-pass overwrite and unlink) of local SQLCipher database files, cached attachments, and log files.
  4. Application reset to unconfigured initial state or launch of a clean decoy screen.
- **Emergency Broadcast Workflow:** Optional high-priority emergency alert transmission with operator acknowledgement prior to local data destruction (ADR-007, Detailed Design §2.5).

**Acceptance:** Emergency panic trigger completely wipes all cryptographic keys and local databases within <500ms; disk sectors are sanitized against forensic recovery.

#### CLIENT-014 --- Settings & User Profile Management

**Labels:** Client, Feature, Settings, UI, Phase 4\
**Owner:** Sergey\
**Dependencies:** CLIENT-003, CLIENT-007

Deliver full user preference customization, profile editing, and identity backup:
- **Profile Configuration:** Display name, bio/status, avatar image encryption and upload, and public handle discovery.
- **Visual & Accessibility Settings:** Runtime switching between Dark and Light palettes, dynamic font scaling, and high-contrast accessibility mode.
- **Network & Proxy Controls:** Custom Gateway host/port, HTTP/SOCKS5 proxy configuration, and TLS certificate fingerprint inspection.
- **Security & Privacy Policies:** Disappearing message timers (e.g. 1 hour, 24 hours, 7 days), read receipt suppression toggle, and hardware key enforcement.
- **Cryptographic Recovery Phrase:** Endpoint-only BIP-39 mnemonic phrase generation and verification for device disaster recovery (never transmitted to backend).

**Acceptance:** User settings persist locally in encrypted storage; permitted public profile fields sync to Auth; theme and appearance apply instantly without application restart.

#### CLIENT-015 --- Client Diagnostics, Audit, Telemetry & Performance Benchmarking

**Labels:** Client, Observability, Audit, Diagnostics, Performance, Phase 4\
**Owner:** Sergey\
**Dependencies:** CLIENT-001, CLIENT-010, CLIENT-014

Implement local audit logging, real-time diagnostics, cryptographic self-testing, and the official client performance profiling suite (measuring CPU, RAM, startup latency, and battery/power impact):
- **Local Secure Audit Trail:** Record security-critical events (device pairing, prekey rotation, failed decrypts, revocation) in an append-only, tamper-evident hash chain stored locally.
- **Cryptographic Self-Test Suite:** Startup self-test verifying OpenSSL 3.x EVP primitives (Ed25519, X25519, AES-256-GCM, HKDF), OS entropy source quality, and Keychain read/write access.
- **Live Resource Diagnostics & Telemetry:** Real-time metrics surfacing stream latency, message processing time, active Double Ratchet session count, resident set size (RSS), and thread pool activity.
- **Official Client Performance Benchmarking Harness (CPU, RAM, Startup & System Impact):**
  - **Memory Footprint (Resident Set Size — RSS):** Baseline idle RAM $< 80$ MB; sustained loaded state (50 active conversations, 5,000 cached SQLCipher messages) $< 150$ MB; peak chunked file streaming strictly bounded with $< 32$ MB buffer overhead; verified zero heap memory leaks via sanitizers / leak tools.
  - **CPU & Energy Impact:** Idle state $< 1\%$ CPU utilization; active scrolling & message rendering $< 5\%$ CPU utilization maintaining consistent 60 fps (zero UI main-thread jank); burst Double Ratchet decryption executing asynchronously in worker threads.
  - **Startup Latency:** Cold application launch to interactive 4-zone workspace shell $< 1.5$ seconds.
  - **Cryptographic Throughput (ADR-010 §17):** Pairwise Double Ratchet ratchet step + AES-256-GCM message encryption $< 2$ ms per message; burst throughput $> 500$ messages/s in local benchmarks.
- **Sanitized Diagnostic Exporter:** One-click bug report bundler generating an encrypted diagnostic archive with all PII, plaintext, and private keys strictly redacted.
- **Official Performance & Impact Report:** Compile an authoritative validation report (`docs/final-reports/client-performance-benchmark-report.md`) detailing official measurements across macOS, Windows, and Linux.

**Acceptance:** Cryptographic self-tests execute on boot with fail-closed protection; automated benchmark harness validates CPU, RAM, and startup thresholds; diagnostics view displays live performance metrics; log exporter scrubs all sensitive material; official client performance benchmark report is compiled and signed off.

#### CLIENT-016 --- Packaging, Distribution & Auto-Update

**Labels:** Client, Release, Packaging, Distribution, Phase 4\
**Owner:** Sergey\
**Dependencies:** CLIENT-001 → CLIENT-015

Establish cross-platform packaging, code-signing, and secure automated updates:
- **Multi-Platform Installers:**
  - **macOS:** Universal `.dmg` bundle, hardened runtime entitlements (Keychain, Camera for QR), and Apple Notarization pipeline.
  - **Windows:** MSI / MSIX installer package with Authenticode code-signing and DPAPI hardware access.
  - **Linux:** AppImage and Debian `.deb` packages with Secret Service daemon integration.
- **Secure Auto-Update Pipeline:**
  - Background update checker querying signed update manifests from release servers.
  - Cryptographic verification of update binary via Ed25519 signature and SHA-256 checksum before execution.
  - Atomic in-place binary replacement with automatic rollback on launch failure.

**Acceptance:** Automated build scripts generate signed, notarized installers for macOS, Windows, and Linux; client verifies update signatures and executes atomic in-place updates cleanly.

---

## 8. Cross-backlog review results

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

## 9. Implementation readiness

The 62-card backlog (46 backend platform cards + 16 desktop client cards) is sufficient to guide implementation across all phases.

**Backend Platform:**
- **Ready now:** SC-001 → SC-016, AUTH-001 → AUTH-010, GW-001 → GW-009, FILE-001 → FILE-009
- **Ready after stated dependency corrections:** GW-010, FILE-010
- **Not yet designed intentionally:** M3 Secure Messaging, M4 Offline Messaging, M6 Auditable Platform, M7 Resilient Platform, M8 Validated MVP (deferred so backend planning does not block implementation).

**Desktop Client Application:**
- **Completed:** CLIENT-001 → CLIENT-006 (Layered Qt6 Architecture, Design System, Workspace & Settings Trust Center, Contacts/Conversations UI, Device Registration & Prekey Lifecycle, Signal Double Ratchet Session Management & E2EE).
- **Ready now:** CLIENT-007 (Device Management, Multi-Device Trust & Hardware Security / Attestation — fully specified in `specs/client-phase2/CLIENT-007-tickets.md`).
- **Roadmap-Aligned & Planned:** CLIENT-008 → CLIENT-016 (Contact Verification, Direct/Group Messaging Engine, Real-Time Delivery & Read Receipts, Encrypted File Transfer & Streaming, Offline Catch-Up Sync, Emergency Panic & Data Wipe, Settings & Profile Management, Diagnostics & Telemetry, Multi-Platform Packaging & Auto-Update).

## 10. Antigravity workflow

For each selected card:

1.  Read `.antigravity/RULES.md`.
2.  Read the relevant architecture/design/data-model/API/implementation documents.
3.  Read this card in `docs/planning/initial-backlog.md` or its corresponding phase ticket specification in `specs/`.
4.  Inspect the current repository state.
5.  Decompose the card into concrete implementation tickets/files/tests/dependencies.
6.  Do not redesign approved architecture.
7.  Do not write implementation code until the decomposition is reviewed and approved.
8.  After approval, implement and test.
9.  Move the Trello card through `IN PROGRESS → CODE REVIEW → TESTING / INTEGRATION → DONE`.

## 11. Definition of Ready

A card is ready when its objective, dependencies, owner, relevant references, security constraints, tests, and acceptance criteria are sufficiently clear for Antigravity to produce an implementation decomposition without inventing architecture.

## 12. Definition of Done

A card is done when implementation, required tests, relevant failure/security cases, formatting/static analysis, architecture-boundary checks, documentation/contract updates where necessary, CI, code review, and acceptance criteria are complete.

## 13. Guiding principle

> **Plan enough to implement safely; then implement. Do not design the entire future backlog before starting work.**
