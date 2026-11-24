# Files Audit Producer Specification & Event Catalog (AUDIT-015)

## 1. Context and Architectural Foundation

Under **ADR-005 (§8)**, **ADR-007 (§18–§23)**, **ADR-008**, **ADR-009**, and **RULES.md (§5, §6, §9)**, the Files Service (`securecloud-files`) is the authoritative owner of encrypted file lifecycle metadata, resumable transfer sessions, chunk integrity verification, file-level ACLs, and Ed25519 file capability authorization backed by PostgreSQL 17 (`securecloud_files`) and MinIO S3-compatible object storage.

To eliminate dual-write inconsistencies between PostgreSQL state transitions and centralized compliance logging (`securecloud-audit`), **every audit event emitted by the Files Service is staged in the `files_outbox` PostgreSQL table** (upgraded in migration `V002`) and delivered asynchronously over mutual TLS gRPC (`securecloud.audit.v1.AuditIngestionService/BatchSubmitAuditEvents`).

* **Availability Decoupling (ADR-009)**: Audit Service unavailability or slow ingestion never blocks file uploads, downloads, finalization, or readiness probes (`compound_ready = db_ok && s3_ok`). Pending events remain durable in `files_outbox` until acknowledged.
* **Canonical Contract Compliance (AUDIT-002 / AUDIT-006)**: Every event carries a deterministic or newly generated RFC 9562 UUIDv7 `event_id` that remains immutable across retries, a dot-separated lowercase `event_type` (`^[a-z0-9_]+(\.[a-z0-9_]+)+$`), distinct `occurred_at` and `received_at` timestamps, verified caller attribution, and bounded metadata.

---

## 2. Domain Ownership Boundaries & Anti-Duplication Rules

### 2.1 Cross-Service Ownership Matrix

| Responsibility Boundary | Authoritative Producer | Non-Emitting Service(s) |
| :--- | :--- | :--- |
| Edge rate limiting (`429`), header/payload size caps (`413`/`431`), concurrency limits (`503`), malformed/expired JWT rejection (`401`/`403`) | **Gateway (`AUDIT-012`)** (`gateway.rate_limit.exceeded`, `gateway.request.rejected`, `security.token.rejected`) | Files |
| Streaming chunk SHA-256 mismatch caught at HTTP ingress proxy | **Gateway (`AUDIT-012`)** (`gateway.file.chunk_integrity_rejected`) | Files (unless request also reaches Files gRPC directly) |
| Device enrollment and primary/secondary device revocation | **Auth (`AUDIT-013`)** (`auth.device.enrolled`, `auth.device.revoked`) | Files (Files emits `file.capability.rejected` if a revoked device presents a file capability) |
| File creation, versioning, upload session lifecycle, chunk storage integrity, finalization, download initiation, ACLs, capabilities, deletion & expiration | **Files (`AUDIT-015`)** (`file.*` catalog `E01`–`E16`) | Gateway, Auth |

### 2.2 Download Audit Flood-Avoidance Rule (ADR-010)

A large encrypted file transfer (e.g., 1 GiB split into 4 MiB chunks) spans hundreds of sequential `DownloadChunk` RPCs. To prevent audit amplification attacks and outbox saturation:

* `DownloadManager` / `FilesServiceImpl::DownloadChunk` **MUST ONLY** emit `file.download.initiated` (`E09`) when starting a transfer session (`chunk_index == 0`) or initializing an explicit resume session (`prepare_resume_session`).
* Subsequent sequential chunk reads (`chunk_index > 0`) **MUST NOT** emit individual audit events. Audit volume therefore scales with transfer sessions ($O(\text{transfers})$) rather than chunk volume ($O(\text{chunks})$).

---

## 3. Event Durability Categories (ADR-007 §18–§23)

### Category A — State-Mutating Business Operations (Transactional Outbox)
Events triggered by operations that mutate `files`, `file_versions`, `file_transfers`, or `file_access` are inserted into `files_outbox` **inside the active business PostgreSQL transaction (`pqxx::work& tx`)**:

* **Events**: `E01`, `E02`, `E03`, `E04`, `E05`, `E06`, `E10`, `E11`, `E15`, `E16`.
* **Atomicity Invariant**: If `tx.abort()` or a database constraint failure occurs, **zero** phantom audit records commit. If `tx.commit()` succeeds, the outbox row is guaranteed durable before returning to the caller.
* **No Network I/O Inside `tx`**: gRPC calls to `securecloud-audit` and S3 operations never execute inside the database commit window.

### Category B — Non-State-Mutating & Security Rejection Operations (Autonomous Outbox)
Events triggered by read-only operations or security rejections (ACL denials, capability verification failures, chunk SHA-256 mismatches, failed finalizations) do not commit business state mutations:

* **Events**: `E07`, `E08`, `E09`, `E12`, `E13`, `E14`.
* **Autonomous Fail-Safe Invariant**: Staged via `FilesAuditEventPublisher::publish_autonomous(event)` using a dedicated short-lived `pqxx::work` transaction. If autonomous audit staging encounters a transient database failure, the failure is logged via `FilesOutboxDiagnostics` and counted in `FilesOutboxMetrics` without crashing the worker or masking the primary gRPC status returned to the client.

---

## 4. Canonical Files Audit Event Catalog (`E01`–`E16`)

| # | Canonical `event_type` | Severity | Cat. | Legacy M5 Name | Triggering Service & Method | Actor / Target | Whitelisted Metadata Keys |
| :-- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E01** | `file.created` | `INFO` | A | `FILE_CREATED` | `FileLifecycleService::create_file` | `USER=owner_user_id` / `FILE=file_id` | `owner_device_id`, `encrypted_size_bytes`, `chunk_count`, `encryption_algorithm`, `conversation_id` |
| **E02** | `file.version.created` | `INFO` | A | `FILE_VERSION_CREATED` | `FileLifecycleService::create_file_version` | `USER=caller_user_id` / `FILE=file_id` | `version_id`, `version_number`, `encrypted_size_bytes` |
| **E03** | `file.upload.initiated` | `INFO` | A | `FILE_UPLOADING` | `UploadSessionManager::create_session` | `USER=owner_user_id` / `FILE=file_id` | `upload_id`, `owner_device_id`, `expected_chunk_count`, `encrypted_size_bytes` |
| **E04** | `file.upload.completed` | `INFO` | A | `FILE_AVAILABLE` | `FileFinalizationService::finalize_file_upload` | `USER=caller_user_id` (or `owner_user_id`) / `FILE=file_id` | `upload_id`, `version_number`, `total_bytes`, `chunk_count`, `checksum_sha256` |
| **E05** | `file.upload.cancelled` | `INFO` | A | `TRANSFER_CANCELLED` | `UploadSessionManager::cancel_session` | `USER=caller_user_id` / `FILE=file_id` | `upload_id`, `reason` |
| **E06** | `file.upload.expired` | `WARNING` | A | *(New)* | `UploadSessionManager::get_transfer_progress` / `ChunkStorageService` lease expiry | `SYSTEM=files` / `FILE=file_id` | `upload_id`, `accepted_chunks`, `total_chunks` |
| **E07** | `file.chunk.integrity_failed` | `SECURITY` | B | *(New)* | `FilesServiceImpl::UploadChunk` / `ChunkStorageService::store_chunk` | `USER=caller_user_id` (or `UNKNOWN`) / `FILE=file_id` | `upload_id`, `chunk_index`, `reason` (`sha256_mismatch` \| `chunk_conflict` \| `size_mismatch`) |
| **E08** | `file.finalization.failed` | `SECURITY` / `WARNING` | B | `FILE_FAILED` | `FileFinalizationService::finalize_file_upload` (`chunk_hash_tamper`=`SECURITY`; `missing_chunks`/`s3_error`=`WARNING`) | `USER=caller_user_id` / `FILE=file_id` | `upload_id`, `reason`, `accepted_chunks`, `expected_chunks` |
| **E09** | `file.download.initiated` | `INFO` | B | *(New)* | `DownloadManager::get_chunk_versioned` (`chunk_index == 0`) / `prepare_resume_session` | `USER=caller_user_id` / `FILE=file_id` | `version_number`, `starting_chunk`, `total_chunks`, `device_id` |
| **E10** | `file.access.granted` | `INFO` | A | *(New)* | `FileAccessService` / `FileAccessRepository::grant_access` | `USER=granted_by` / `FILE=file_id` | `grantee_user_id`, `grantee_device_id`, `permission` |
| **E11** | `file.access.revoked` | `SECURITY` | A | `FILE_ACCESS_REVOKED` | `FileAccessService` / `FileAccessRepository::revoke_access` | `USER=caller_user_id` / `FILE=file_id` | `grantee_user_id`, `reason` |
| **E12** | `file.access.denied` | `SECURITY` | B | *(New)* | `FilesServiceImpl`, `DownloadManager`, `FileLifecycleService`, `ChunkStorageService` | `USER=caller_user_id` (or `UNKNOWN`) / `FILE=file_id` | `operation`, `reason`, `device_id` |
| **E13** | `file.capability.issued` | `INFO` | B | *(New)* | `FileCapabilityManager::issue_capability` | `USER=grantee_user_id` / `FILE=file_id` | `capability_id`, `grantee_device_id`, `operation`, `file_version`, `ttl_seconds` |
| **E14** | `file.capability.rejected` | `SECURITY` | B | `CAPABILITY_REJECTED` | `FileCapabilityManager::authorize_capability` / `issue_capability` | `USER=caller_user_id` (or `UNKNOWN`) / `FILE` or `SERVICE=files` | `reason` (`invalid_signature` \| `expired` \| `device_revoked` \| `scope_mismatch` \| `missing`), `requested_operation`, `device_id` |
| **E15** | `file.deleted` | `INFO` | A | `FILE_DELETED` | `FileLifecycleService::delete_file` | `USER=caller_user_id` / `FILE=file_id` | `previous_status`, `reason` |
| **E16** | `file.expired` | `INFO` | A | `FILE_EXPIRED` | `FileLifecycleService::evaluate_and_expire_files` | `SYSTEM=files` / `FILE=file_id` | `retention_until_ms` |

---

## 5. Rolling-Upgrade Legacy Event Normalization (`V001` → `V002`)

To ensure zero stranded rows or poison-pill rejections during rolling upgrades from the M5 baseline (`V001`) to M6 (`V002`), `FilesAuditMapper::to_proto` normalizes any pre-existing uppercase legacy `event_type` values before `AuditEventValidator` evaluation:

| Legacy `V001` `event_type` | Normalized Canonical `event_type` | Default Normalized Severity |
| :--- | :--- | :--- |
| `FILE_CREATED` | `file.created` (`E01`) | `INFO` |
| `FILE_VERSION_CREATED` | `file.version.created` (`E02`) | `INFO` |
| `FILE_UPLOADING` | `file.upload.initiated` (`E03`) | `INFO` |
| `FILE_AVAILABLE` | `file.upload.completed` (`E04`) | `INFO` |
| `FILE_FINALIZING` | `file.upload.completed` (`E04`) | `INFO` |
| `TRANSFER_CANCELLED` | `file.upload.cancelled` (`E05`) | `INFO` |
| `FILE_FAILED` | `file.finalization.failed` (`E08`) | `WARNING` |
| `FILE_ACCESS_REVOKED` | `file.access.revoked` (`E11`) | `SECURITY` |
| `CAPABILITY_REJECTED` | `file.capability.rejected` (`E14`) | `SECURITY` |
| `FILE_DELETED` | `file.deleted` (`E15`) | `INFO` |
| `FILE_EXPIRED` | `file.expired` (`E16`) | `INFO` |

---

## 6. Strict Zero-Plaintext, Zero-Metadata-Leakage & Secret Isolation Rules

Under **ADR-008**, **RULES.md (§5)**, and **Files Design (§6.22, §6.26)**, `files_outbox` rows, serialized `AuditEventProto` payloads, and diagnostic logs must **NEVER** contain:

1. **File Content & Cryptographic Keys**:
    * Plaintext file bytes, encrypted chunk bytes, or base64-encoded file payloads (`data`, `encrypted_data`, `ciphertext`, `chunk_data`).
    * Content encryption keys (CEKs), XChaCha20-Poly1305 / AES-GCM keys, or asymmetric private keys (`encryption_key`, `file_key`, `private_key`, `signing_key`).
2. **Client-Encrypted File Metadata Secrets**:
    * `encrypted_filename`, `encrypted_mime_type`, `metadata_nonce`, `metadata_tag`, `client_encryption_metadata`, or any plaintext filename / MIME type. Clients encrypt filenames specifically so backend storage and audit trails never learn file names or content types.
3. **Authentication & Capability Tokens**:
    * Signed Ed25519 file capability token strings (`capability_token`), `Authorization` headers, `Bearer` credentials, JWTs (`eyJ...`), or refresh tokens (`token`, `secret`, `password`).
4. **Infrastructure Credentials**:
    * PostgreSQL passwords (`db_password`) or MinIO S3 access/secret keys (`s3_access_key`, `s3_secret_key`).

### Two-Stage Defense-in-Depth Enforcement
* **Stage 1 (Pre-Persistence — `FilesAuditEventPublisher`)**: Validates and strips forbidden keys recursively before `INSERT INTO files_outbox`, ensuring prohibited fields never touch PostgreSQL WAL or heap pages.
* **Stage 2 (Pre-Wire — `FilesAuditMapper`)**: Recursively scrubs nested JSON objects/arrays and redacts any string matching PEM private key headers (`-----BEGIN ... PRIVATE KEY-----`), `Bearer <token>`, or 3-segment JWT patterns (`eyJ...`) prior to populating `AuditEventProto::metadata`.

---

## 7. Multi-Worker Leasing, Delivery & Quarantine Semantics

* **Atomic Lease Acquisition (`FOR UPDATE SKIP LOCKED`)**: `FilesOutboxRepository::fetch_and_lease_pending_batch` claims up to $N \le 100$ rows where `status = 'PENDING' AND (leased_until IS NULL OR leased_until < NOW())`, sets `leased_until = NOW() + lease_duration` (default `30s`), and increments `retry_count` inside a short atomic transaction that commits immediately before network gRPC dispatch.
* **Crash Self-Healing**: If a Files instance terminates unexpectedly mid-RPC, expired leases (`leased_until < NOW()`) are automatically reclaimed by surviving workers without duplicate business mutations, relying on `AUDIT-006` server-side deduplication by `event_id`.
* **Acknowledgement & Error Classification**:
    * **Accepted (`OK` and `event_id` not in `rejected_event_ids`)**: Transition `status = 'PUBLISHED'`, `processed_at = NOW()`, `leased_until = NULL`.
    * **Transient Failure (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, network timeout)**: Retain `status = 'PENDING'`, clear `leased_until = NULL`, record sanitized `last_error`, and back off exponentially with jitter (`±25%`).
    * **Permanent Rejection (`INVALID_ARGUMENT`, `ALREADY_EXISTS`, local schema failure, `event_id` in `rejected_event_ids`, or `retry_count > max_retries`)**: Transition `status = 'QUARANTINED'`, `processed_at = NOW()`, record sanitized `last_error`, and continue dispatching healthy events without head-of-line blocking.
* **Bounded Retention Purge**: `PUBLISHED` records older than `published_retention_hours` (default `168h` / 7 days) are purged in bounded batches using partial index `idx_files_outbox_cleanup`.