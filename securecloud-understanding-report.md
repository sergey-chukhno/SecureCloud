# SecureCloud Understanding Report

**Author**: Senior C++ Systems Architect, Security Architect, Distributed Systems Architect  
**Audience**: Louis (Developer), Sergey (Technical Lead / Security Architect)  
**Scope**: SecureCloud Platform Overview & Deep Architectural Analysis of the **Files Service**  
**Repository Source of Truth Inspected**:
* Authoritative Architecture: [`docs/architecture/`](docs/architecture) (`system-context.md`, `trust-boundaries.md`, `architecture.md`, `architectural-drivers.md`)
* Authoritative ADRs: [`docs/adr/`](docs/adr) (`adr-001` through `adr-010`)
* Authoritative Files Design & Data Models: [`docs/design/files-design.md`](docs/design/files-design.md), [`docs/data-model/04-files-data-model.md`](docs/data-model/04-files-data-model.md), [`docs/data-model/files/files-mpd-notes.md`](docs/data-model/files/files-mpd-notes.md)
* Implementation Specifications & Rules: [`specs/phase5/FILES-001-tickets.md`](specs/phase5/FILES-001-tickets.md), [`specs/phase5/FILES-002-tickets.md`](specs/phase5/FILES-002-tickets.md), [`docs/implementation/`](docs/implementation)
* Existing Code & Infrastructure: [`src/files/`](src/files), [`src/common/`](src/common), [`deploy/compose/docker-compose.yml`](deploy/compose/docker-compose.yml), [`scripts/verify-local.py`](scripts/verify-local.py)

---

## A. System Architecture

SecureCloud is a high-security, distributed communication platform designed for hostile environments where infrastructure compromise must not leak message or file contents.

```text
                    ┌─────────────────────────┐
                    │      Qt/C++ Client      │ (Endpoint: Plaintext, Private Keys,
                    └────────────┬────────────┘  Local DB, Compression & Encryption)
                                 │ HTTPS / REST (External Client API)
                                 ▼
                    ┌─────────────────────────┐
                    │     Gateway Service     │ (Port 50051: Routing, Rate Limiting,
                    └────────────┬────────────┘  Stateless Token Validation; No Decryption)
                                 │
                 gRPC / mTLS     │ (Internal Network Contracts)
       ┌─────────────────────────┼─────────────────────────┐
       ▼                         ▼                         ▼
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│    Auth     │           │  Messaging  │           │    Files    │
│   Service   │           │   Service   │           │   Service   │
│(Port 50052) │           │(Port 50053) │           │(Port 50054) │
└──────┬──────┘           └──────┬──────┘           └──────┬──────┘
       │                         │                         │
PostgreSQL 17                 ScyllaDB               PostgreSQL 17 + MinIO
(Auth DB)                  (Messaging DB)             (Files DB & S3 Bucket)
       │                         │                         │
       └─────────────────────────┼─────────────────────────┘
                                 │ Asynchronous Events (Transactional Outbox)
                                 ▼
                          ┌─────────────┐
                          │    Audit    │
                          │   Service   │
                          │(Port 50055) │
                          └──────┬──────┘
                                 │ ClickHouse (Audit DB)
```

The system comprises **five independently deployable runtime microservices** ([ADR-001](docs/adr/adr-001-five-microservices.md)):

1. **Gateway (`src/gateway`)**: External entry point for client traffic. Exposes external REST APIs via HTTPS, enforces rate limits and connection budgets, validates authentication tokens statelessly, and proxies traffic internally. **Never decrypts application payloads**.
2. **Auth (`src/auth`)**: Manages identity authentication, sessions, device registration, and the public cryptographic prekey directory (Identity Keys, Signed Prekeys, One-Time Prekeys). Backed by PostgreSQL 17. **Never stores private keys or message/file decryption keys**.
3. **Messaging (`src/messaging`)**: Handles real-time and offline end-to-end encrypted message delivery, recipient/device partitioning, acknowledgements, and retry tracking. Backed by ScyllaDB. Operates exclusively on opaque encrypted envelopes.
4. **Files (`src/files`)**: Owns the server-side lifecycle of encrypted files, resumable chunked upload/download sessions, transfer state tracking, operational metadata, and storage coordination between PostgreSQL 17 and MinIO S3.
5. **Audit (`src/audit`)**: Asynchronously ingests security and operational events published via Transactional Outbox from other services into ClickHouse for immutable analytics.

**The Client is an endpoint, not a backend service**. Control-plane/deployment tooling is infrastructure, not runtime service logic.

---

## B. Files Service Responsibility

### What the Files Service OWNS:
* **The Server-Side Lifecycle of Encrypted Files**: Managing states (`UPLOAD_CREATED` → `UPLOADING` → `FINALIZING` → `AVAILABLE` → `EXPIRED` / `DELETED`).
* **Resumable Transfer Sessions**: Tracking `upload_id`, expected chunks, completed chunks, and transfer progress.
* **Authoritative Operational Metadata**: Opaque `file_id` (UUIDv7), `upload_id`, encrypted byte size, total chunk count, encryption format version, SHA-256 ciphertext integrity hash, and lifecycle timestamps.
* **Dual Persistence Coordination**: Storing relational state in PostgreSQL 17 and encrypted binary chunks/objects in MinIO S3.
* **Integrity and Finalization Gates**: Verifying chunk presence and verifying ciphertext SHA-256 digests before marking files `AVAILABLE`.
* **Streaming and Bounded Buffering**: Transporting encrypted data chunks without loading whole files into memory.
* **Asynchronous Audit Event Generation**: Emitting domain events (`FILE_UPLOAD_CREATED`, `FILE_AVAILABLE`, `FILE_EXPIRED`, `FILE_DELETED`) via the Transactional Outbox.

### What the Files Service DOES NOT OWN:
* **Plaintext Content**: Never touches unencrypted file data.
* **Encryption / Decryption**: All cryptographic key generation and transformations belong strictly to client endpoints.
* **Cryptographic Keys**: Never receives or stores user private keys, prekeys, or symmetric file encryption keys.
* **User Authentication**: Does not validate passwords, MFA, or JWT tokens directly (Gateway validates tokens and passes authenticated context).
* **Conversation Membership**: Messaging is the sole authority for who belongs to a conversation.
* **Human Identities**: Operates strictly on opaque UUIDs (`user_id`, `device_id`, `conversation_id`).
* **Original File Metadata in Plaintext**: Filenames and MIME types are never stored in plaintext by the backend; they are client-encrypted inside application metadata.
* **Compression**: The Files Service performs zero server-side compression.

---

## C. Data Ownership

Following [ADR-005](docs/adr/adr-005-database-ownership-model.md) and [ADR-006](docs/adr/adr-006-persistance-technology-selection.md), the Files Service enforces strict polyglot persistence ownership:

```text
                            Files Service
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
   PostgreSQL 17                                       MinIO S3
(securecloud_files)                          (securecloud-files-encrypted)
         │                                                 │
 ├── files (metadata, lifecycle)                   └── files/{FileId}/content
 ├── upload_sessions (transfer state)                 (encrypted binary object only)
 ├── upload_chunks (chunk receipts)
 └── outbox_events (audit events)
```

1. **PostgreSQL 17 (`securecloud_files` on host port `5433`, container port `5432`)**:
   * Authoritative for structured relational state: file metadata, upload sessions, chunk receipt indices, SHA-256 verification hashes, and outbox events.
   * **Invariant**: Large binary file payloads must **never** be stored in PostgreSQL columns (no `BYTEA` blobs).
2. **MinIO S3 Object Storage (`securecloud-files-encrypted` on port `9000`)**:
   * Authoritative storage for encrypted binary objects and chunk payloads.
   * Objects use deterministically derived opaque keys: `files/{FileId}/content`.
   * **Invariant**: MinIO is an object store, **never** the authoritative source for structured application lifecycle state. An object existing in MinIO does not make it downloadable unless PostgreSQL marks it `AVAILABLE`.
3. **Database Security & Isolation**:
   * Files connects via dedicated unprivileged user `files_user` (`files_dev_db_secret`).
   * No direct cross-service queries or shared schemas.
   * **Workstation Isolation**: Host PostgreSQL 14 running on `localhost:5432` is strictly guarded and off-limits.

---

## D. Security Model

1. **Client-Side Encryption & Server Blindness ([ADR-008](docs/adr/adr-008-security-cryptographic-architecture.md), TB-01)**:
   * The client generates a random 256-bit symmetric file encryption key.
   * The client optionally compresses (zstd) then encrypts (AEAD) the file in fixed 4 MiB chunks, padding the final chunk to mitigate size leakage.
   * The file key is encrypted for authorized recipients using the Signal Protocol (Double Ratchet / Sesame) and passed via Messaging envelopes.
   * The Files backend receives, handles, and persists **only ciphertext**.
2. **Backend Ciphertext Handling**:
   * Plaintext file contents, plaintext filenames, plaintext MIME types, and file encryption keys are completely absent from backend memory, disks, and logs.
   * There are no administrative backdoors, escrow keys, or emergency decryption mechanisms.
3. **Internal Transport Security (mTLS)**:
   * All gRPC communication uses mTLS with certificates issued by a private internal CA (`ca.crt`).
   * Files runs as `DNS:files`. Peer certificates are validated to ensure only authorized callers (e.g. Gateway `DNS:gateway`) can invoke Files RPCs.
4. **Context & Capability Authorization**:
   * Gateway passes opaque authenticated context (`owner_user_id`, `owner_device_id`).
   * Client-supplied ownership claims are never trusted blindly.
   * File access can be granted via short-lived, signed, device-bound, file-bound capability tokens validated server-side.
5. **Secret Handling**:
   * Database passwords and MinIO secret keys are held in memory using `securecloud::common::configuration::SecretString` (clearing memory on destruction).
   * Secrets are loaded from environment variables and never logged or exposed via RPC responses.

---

## E. Complete Upload Flow

```text
Client                  Gateway                 Files Service            PostgreSQL 17            MinIO S3
  │                        │                          │                        │                     │
  │ 1. CreateFileUpload    │                          │                        │                     │
  ├───────────────────────►│ 2. CreateFileUpload(RPC) │                        │                     │
  │                        ├─────────────────────────►│ 3. INSERT files        │                     │
  │                        │                          │    INSERT session      │                     │
  │                        │                          ├───────────────────────►│                     │
  │                        │                          │◄───────────────────────┤                     │
  │                        │◄─────────────────────────┤ (Returns upload_id)    │                     │
  │◄───────────────────────┤ (Returns upload_id)      │                        │                     │
  │                        │                          │                        │                     │
  │ 4. UploadChunk(0..N)   │                          │                        │                     │
  ├───────────────────────►│ 5. UploadChunk(stream)   │                        │                     │
  │                        ├─────────────────────────►│ 6. PutObject (Chunk)   │                     │
  │                        │                          ├─────────────────────────────────────────────►│
  │                        │                          │◄─────────────────────────────────────────────┤
  │                        │                          │ 7. INSERT upload_chunk │                     │
  │                        │                          ├───────────────────────►│                     │
  │                        │                          │◄───────────────────────┤                     │
  │                        │◄─────────────────────────┤ (ACK chunk)            │                     │
  │◄───────────────────────┤ (ACK chunk)              │                        │                     │
  │                        │                          │                        │                     │
  │ 8. FinalizeFileUpload  │                          │                        │                     │
  ├───────────────────────►│ 9. FinalizeFileUpload    │                        │                     │
  │                        ├─────────────────────────►│ 10. Verify all chunks │                     │
  │                        │                          │     Verify object      │                     │
  │                        │                          │     Verify SHA-256     │                     │
  │                        │                          ├─────────────────────────────────────────────►│
  │                        │                          │◄─────────────────────────────────────────────┤
  │                        │                          │ 11. BEGIN TX           │                     │
  │                        │                          │     state = AVAILABLE  │                     │
  │                        │                          │     INSERT outbox      │                     │
  │                        │                          │     COMMIT             │                     │
  │                        │                          ├───────────────────────►│                     │
  │                        │                          │◄───────────────────────┤                     │
  │                        │◄─────────────────────────┤ (Status: AVAILABLE)    │                     │
  │◄───────────────────────┤ (Status: AVAILABLE)      │                        │                     │
```

1. **Initiation**: Client requests upload creation. Files generates opaque `FileId` (UUIDv7) and `UploadId`, inserting records into `files` (`status = UPLOAD_CREATED`) and `upload_sessions`.
2. **Chunk Streaming**: Client sends encrypted 4 MiB chunks. Gateway streams them to Files. Files writes each chunk to MinIO S3, verifies chunk SHA-256, and durably records chunk index in PostgreSQL `upload_chunks`. Files updates status to `UPLOADING`.
3. **Finalization Gate**: Client triggers finalization. Files verifies that all chunks `0 .. N-1` exist, verifies the combined encrypted object in MinIO, and matches the calculated SHA-256 digest against the client's expected ciphertext hash.
4. **Atomic Availability**: Inside a single PostgreSQL transaction (`pqxx::work`), Files sets `files.lifecycle_state = AVAILABLE` and inserts a `FILE_AVAILABLE` event into `outbox_events`. Only now is the file downloadable.

---

## F. Complete Download Flow

```text
Client                  Gateway                 Files Service            PostgreSQL 17            MinIO S3
  │                        │                          │                        │                     │
  │ 1. DownloadRequest     │                          │                        │                     │
  ├───────────────────────►│ 2. DownloadChunk(RPC)    │                        │                     │
  │                        ├─────────────────────────►│ 3. SELECT file & state │                     │
  │                        │                          ├───────────────────────►│                     │
  │                        │                          │◄───────────────────────┤                     │
  │                        │                          │ (Assert: AVAILABLE)    │                     │
  │                        │                          │                        │                     │
  │                        │                          │ 4. GetObject (Stream)  │                     │
  │                        │                          ├─────────────────────────────────────────────►│
  │                        │                          │◄─────────────────────────────────────────────┤
  │                        │◄─────────────────────────┤ (Stream encrypted bytes)                     │
  │◄───────────────────────┤ (Stream encrypted bytes) │                        │                     │
  │                        │                          │                        │                     │
  │ 5. Client AEAD Verify  │                          │                        │                     │
  │    & Decrypt           │                          │                        │                     │
```

1. **Request & Authentication**: Client requests download of `FileId` (or specific starting chunk). Gateway validates token and forwards authenticated device context.
2. **Availability & Access Check**: Files queries PostgreSQL. If state is not `AVAILABLE` (e.g. `UPLOAD_CREATED`, `UPLOADING`, `EXPIRED`, or `DELETED`), the request is rejected immediately (`NOT_FOUND` / `FAILED_PRECONDITION`). Files validates capability / authorization grants.
3. **Streaming Retrieval**: Files streams encrypted chunks from MinIO through gRPC to Gateway, which streams over HTTPS to the client with bounded buffers and backpressure.
4. **Client Decryption**: Client receives ciphertext chunks, validates AEAD tags, and decrypts using the locally stored file encryption key.

---

## G. Resumability & Idempotency

* **Durable Transfer Identity**: Every upload is identified by `upload_id`. Progress is recorded row-by-row in `upload_chunks` in PostgreSQL.
* **Resuming Interrupted Uploads**: If disconnected at chunk 45/100, the client reconnects with `upload_id`. Files queries `upload_chunks` and returns the set of completed chunks. The client resumes by sending only missing chunks.
* **Idempotent Chunk Submission**: The identity of a chunk is `(upload_id, chunk_index)`.
  * If chunk retry has a matching SHA-256 hash → accepted idempotently.
  * If chunk retry has a differing SHA-256 hash → rejected with integrity conflict.
* **Resuming Interrupted Downloads**: Client sends `DownloadChunkRequest` specifying `file_id` and `starting_chunk`. Files streams starting from the requested chunk offset; clients never restart large downloads from zero.

---

## H. Concurrency Model & Backpressure

1. **Bounded Concurrency Domains (Bulkheads)**:
   * Metadata workers, Upload workers, and Download workers run in separate bounded capacity pools.
   * Large downloads cannot starve incoming metadata requests or file uploads.
   * PostgreSQL connection pool is strictly bounded (default 2 to 10 connections, 500ms acquisition timeout).
   * Concurrent S3 operations to MinIO are bounded.
   * Per-device transfer limits prevent a single client from monopolizing server capacity.
2. **Execution Model**:
   * **Never one thread per transfer**.
   * Asynchronous I/O pipelines with bounded buffers (4 MiB per chunk).
3. **End-to-End Backpressure**:
   * Flow: `MinIO` ⇄ `Files` ⇄ `Gateway` ⇄ `Client`.
   * If MinIO slows down, Files buffers fill, pausing gRPC reads. Gateway pauses reading client HTTPS stream, shrinking the client's TCP window. Memory consumption remains strictly bounded at $O(\text{active transfers} \times \text{buffer size})$ regardless of file size.

---

## I. Failure & Resilience Model

| Failure Scenario | Files Service Behavior & Recovery |
| :--- | :--- |
| **PostgreSQL Fails** | Operations requiring metadata or transfer state fail closed (`UNAVAILABLE`). In-memory state is never treated as authoritative. Readiness drops immediately to `NOT_SERVING`. |
| **MinIO Fails** | Chunk writes and object downloads fail closed. Transfers remain retryable. Readiness drops immediately to `NOT_SERVING`. |
| **Network / Client Disconnect** | gRPC stream detects cancellation / broken connection. In-flight uncommitted chunk is discarded. Committed chunks remain durable in PostgreSQL and MinIO. Client resumes later. |
| **Files Service Restarts** | Unfinished uploads remain in `UPLOADING` in PostgreSQL. When the client reconnects, state is reloaded from PostgreSQL. No state lost. |
| **Finalization Fails** | If chunk count, object existence, or final SHA-256 hash check fails, the transaction aborts. The file remains in `UPLOADING` or transitions to `FAILED`. It is **never** made `AVAILABLE`. |
| **Service Shutdown** | Deterministic 5-step sequence: (1) set readiness `NOT_SERVING`, (2) stop accepting new gRPC calls (`server->Shutdown(deadline)`), (3) drain active transfers (5s), (4) close MinIO connections, (5) drain and close PostgreSQL pool. |
| **Duplicate Requests Arrival** | Deduplicated via `upload_id` and `(upload_id, chunk_index)` uniqueness constraints. Duplicate finalization is idempotent. |

---

## J. Architectural Constraints (What a Files Developer Must NEVER Do)

1. **NEVER decrypt file content on the backend** or handle plaintext file encryption keys.
2. **NEVER implement administrative backdoors**, escrow keys, or emergency decryption.
3. **NEVER connect to, modify, or bind to host PostgreSQL on `localhost:5432`** (SecureCloud PostgreSQL 17 is on port `5433`).
4. **NEVER store binary file content (large `BYTEA` blobs) in PostgreSQL**.
5. **NEVER treat MinIO as authoritative for application lifecycle state**.
6. **NEVER mark a file `AVAILABLE` before all chunks exist and ciphertext integrity is verified**.
7. **NEVER mutate an `AVAILABLE` file version in place** (completed files are immutable; new versions require new records/objects).
8. **NEVER load entire files into memory**; streaming and chunking are mandatory.
9. **NEVER spawn unbounded threads** (no thread-per-transfer model).
10. **NEVER query another service's database directly** (e.g. `securecloud_auth`) or share credentials.
11. **NEVER log plaintext, ciphertext payloads, encryption keys, tokens, or S3 credentials**.
12. **NEVER trust client-claimed identities** without verified gateway authenticated context.
13. **NEVER perform server-side file compression**.
14. **NEVER execute destructive global Docker commands** (`docker system prune`, `docker volume prune`, `docker compose down -v`).

---

## K. Existing Repository Patterns to Reuse

* **Configuration**: Use `securecloud::common::configuration::CommonServiceConfig`, `ConfigParser`, and `SecretString` from [`src/common/include/securecloud/configuration/`](src/common/include/securecloud/configuration).
* **Transport Security (mTLS)**: Use `securecloud::common::security::MtlsCredentialLoader` and peer SAN extraction (`DNS:gateway`) from [`src/common/include/securecloud/security/mtls_config.hpp`](src/common/include/securecloud/security/mtls_config.hpp).
* **Health & Readiness**: Use `HealthStatusManager` and `HealthServiceImpl` from [`src/common/include/securecloud/health/`](src/common/include/securecloud/health) to implement the dual-dependency evaluator.
* **Testing Harness**: Follow existing patterns in [`tests/integration/health_integration_test.cpp`](tests/integration/health_integration_test.cpp) and [`tests/integration/mtls_integration_test.cpp`](tests/integration/mtls_integration_test.cpp), including the custom Windows test teardown (`::TerminateProcess`) to avoid runner deadlocks on Windows/MinGW.

---

## L. Genuine Contradictions & Ambiguities Identified in the Repository

During inspection of the documentation and code, two architectural discrepancies and one implementation ambiguity were identified:

1. **Schema & Domain Entities Discrepancy between Data Model and Phase 5 Tickets**:
   * In [`docs/data-model/04-files-data-model.md`](docs/data-model/04-files-data-model.md) and [`docs/data-model/files/files-mpd-notes.md`](docs/data-model/files/files-mpd-notes.md), the authoritative MVP relational model consists of **4 core tables**:
     * `files`
     * `upload_sessions`
     * `upload_chunks`
     * `outbox_events`
     with deterministic object key `files/{FileId}/content` and UUIDv7 `file_id`.
   * In [`specs/phase5/FILES-002-tickets.md`](specs/phase5/FILES-002-tickets.md) (and [`docs/design/files-design.md`](docs/design/files-design.md) Section 6.3), the schema is expanded to **7 tables**:
     * `files`, `file_versions` (with `minio_obj_key`), `encrypted_file_metadata` (1:1), `file_transfers`, `file_chunks`, `file_access`, and `files_outbox`.
   * *Question for Louis & Sergey*: Should Phase 5 stick strictly to the streamlined 4-table data model from `04-files-data-model.md` for MVP, or implement the 7-table normalized version from `FILES-002-tickets.md`? (Note: FILES-001 foundation is completely unaffected by this choice).
2. **Current Contract Files State**:
   * [`openapi/openapi.yaml`](openapi/openapi.yaml) is currently empty (0 bytes).
   * [`proto/securecloud/files/v1/files.proto`](proto/securecloud) does not yet exist.
   * `FILES-001-T01` is the exact ticket tasked with introducing `proto/securecloud/files/v1/files.proto`.
3. **S3 Client Implementation Approach**:
   * [`vcpkg.json`](vcpkg.json) does not include the heavy AWS C++ SDK.
   * `FILES-001-T03` specifies a lightweight in-tree S3 client using HTTP and OpenSSL HMAC-SHA256 for AWS SigV4 signing, which is far simpler and faster to build across MSVC, MinGW, and AppleClang. We confirm this is the optimal approach.
