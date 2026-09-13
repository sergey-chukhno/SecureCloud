# 4. Files Service Data Model

## 4.1 Purpose and Ownership

The Files Service owns persistence and lifecycle management for:

* encrypted file objects;
* file operational metadata;
* file lifecycle state;
* resumable upload sessions;
* upload progress;
* file availability;
* file expiration and deletion;
* ciphertext integrity verification;
* Files Service domain events.

The Files Service does not own:

* conversation membership;
* message ordering;
* message delivery state;
* human-readable identity information;
* passwords;
* MFA secrets;
* private cryptographic keys;
* message content;
* audit-event persistence.

The Files Service uses opaque identifiers owned by other domains:

```text id="t1qx3r"
UserId
DeviceId
ConversationId
```

The Files Service owns:

```text id="w8f4dk"
FileId
UploadId
```

The canonical relationship is:

```text id="znzsj7"
Encrypted File
      │
      ▼
Files Service
      │
      │ FileId
      ▼
Messaging Service
      │
      ▼
Encrypted Message Envelope
```

Messaging stores only opaque `FileId` references.

The Files Service never stores file binary content inside PostgreSQL.

---

# 4.2 Persistence Architecture

The Files Service uses two persistence technologies.

## PostgreSQL

PostgreSQL is the authoritative transactional database for:

* file metadata;
* lifecycle state;
* upload sessions;
* upload progress;
* expiration state;
* deletion state;
* ciphertext integrity metadata;
* Files Service transactional outbox events.

## S3-Compatible Object Storage

Encrypted file bytes are stored in:

> **S3-compatible object storage.**

For local development and local Kubernetes environments, the implementation uses:

> **MinIO.**

The production architecture remains compatible with an S3-compatible storage provider.

The persistence architecture is:

```text id="ap99ah"
Files Service
│
├── PostgreSQL
│   │
│   ├── file metadata
│   ├── lifecycle state
│   ├── upload sessions
│   ├── upload progress
│   ├── integrity metadata
│   └── transactional outbox
│
└── S3-Compatible Object Storage
    │
    └── encrypted file bytes
```

PostgreSQL is the authoritative source for the file lifecycle.

Object storage contains encrypted binary objects.

---

# 4.3 File Identity

Every file receives an opaque identifier:

```text id="cvw0j2"
FileId
```

The Files Service generates `FileId`.

The MVP uses:

> **UUIDv7**

UUIDv7 provides:

* global uniqueness;
* opaque identifiers;
* time-ordered generation;
* efficient ordering characteristics.

`FileId` must not encode:

* human identity;
* user name;
* device name;
* conversation identity;
* file name;
* file content.

Example:

```text id="ojv3ss"
FileId = 019...
```

`FileId` is the canonical application-level identifier.

Messaging and clients refer to files exclusively through `FileId`.

---

# 4.4 Object Storage Key

The object storage key is an infrastructure implementation detail.

It is not a second domain identifier.

For the MVP, the object storage key is derived deterministically from `FileId`.

The canonical format is:

```text id="wl9nc2"
files/{FileId}/content
```

Example:

```text id="23hw6a"
files/019abc.../content
```

Therefore PostgreSQL does not store an independent `object_key`.

The Files Service derives:

```text id="3ys5l2"
ObjectKey = ObjectKey(FileId)
```

This prevents unnecessary mapping state.

The client never receives or depends on the object storage key.

The conceptual model is:

```text id="rcs8l1"
FileId
   │
   │ Domain identifier
   ▼
Files Service
   │
   │ deterministic derivation
   ▼
Object Storage Key
   │
   ▼
Encrypted Object
```

---

# 4.5 File Confidentiality Model

The file content is encrypted on the client before it enters the backend.

The backend receives:

```text id="u5dmx9"
Ciphertext
```

not:

```text id="hh3zax"
Plaintext file
```

The flow is:

```text id="o7tgh0"
Plaintext File
      │
      ▼
Client-side Encryption
      │
      ▼
Encrypted File Object
      │
      ▼
Gateway
      │
      ▼
Files Service
      │
      ▼
Object Storage
```

Gateway does not decrypt the file.

Files Service does not decrypt the file.

Object storage never stores plaintext file content.

The cryptographic construction and file-key distribution are governed by ADR-008.

---

# 4.6 File Metadata Confidentiality

Not all file metadata is treated equally.

The design distinguishes:

## Operational metadata

The backend requires some metadata to operate the file service.

Examples:

```text id="54s7s9"
FileId
LifecycleState
EncryptedSizeBytes
ChunkCount
CiphertextIntegrityHash
CreatedAt
AvailableAt
ExpiresAt
```

For the MVP, this metadata is stored as ordinary PostgreSQL data.

It is protected through:

* database access control;
* service authentication;
* network encryption;
* infrastructure encryption at rest;
* backup protection.

It is not individually end-to-end encrypted because the Files Service requires it for operation.

---

## User-visible and sensitive metadata

The backend must not store the following as readable operational metadata:

```text id="2czvrc"
Original filename
Plaintext MIME type
Human-readable description
```

If clients require this information, it must be carried inside encrypted application metadata.

Conceptually:

```text id="wb9jzh"
Encrypted file/message metadata
│
├── original filename
├── MIME type
└── optional description
```

Only authorized clients can decrypt this information.

The Files Service does not interpret it.

---

# 4.7 File Size Metadata

The backend necessarily observes some approximate file size information because it transports and stores encrypted bytes.

The Files Service stores:

```text id="mjcd8p"
EncryptedSizeBytes
ChunkCount
```

The Files Service does not need to store the plaintext file size for MVP operation.

Therefore:

> **`OriginalSizeBytes` is not stored as readable backend metadata.**

Clients may include original plaintext size inside encrypted metadata if required.

---

# 4.8 File Chunking and Size Leakage

Files are processed in bounded encrypted chunks.

The MVP chunk size is:

> **4 MiB**

The logical representation is:

```text id="mq6ph4"
FileId
│
├── Chunk 0
├── Chunk 1
├── Chunk 2
└── Chunk N
```

The final chunk is padded before encryption.

Conceptually:

```text id="gbzw8o"
Plaintext
   │
   ▼
Fixed-size chunking
   │
   ▼
Padding of final chunk
   │
   ▼
Encryption
   │
   ▼
Encrypted chunks
```

This reduces fine-grained file-size leakage.

It does not completely hide the approximate total size because the backend can observe:

```text id="qmy0q9"
ChunkCount × ChunkSize
```

The MVP explicitly accepts this residual metadata leakage.

---

# 4.9 Compression Decision

The Files Service performs:

> **No server-side compression.**

Reasons:

1. the Files Service does not access plaintext;
2. ciphertext generally does not compress effectively;
3. server-side plaintext compression would violate the end-to-end confidentiality architecture.

If compression is used, it occurs:

```text id="ijy4sd"
Client
│
├── Optional compression
│
├── Encryption
│
└── Upload encrypted bytes
```

For the MVP:

> **Automatic compression is not required.**

No backend component performs file compression.

---

# 4.10 File Lifecycle

The canonical externally visible lifecycle is:

```text id="e90onl"
UPLOAD_CREATED
       │
       ▼
UPLOADING
       │
       ▼
AVAILABLE
       │
       ├──► EXPIRED
       │
       └──► DELETED
```

---

## `UPLOAD_CREATED`

The Files Service has:

* generated `FileId`;
* created an upload session;
* persisted initial metadata.

No complete file is yet available.

---

## `UPLOADING`

Encrypted chunks are being transferred.

The operation may be interrupted.

The upload remains resumable until:

* completion;
* expiration;
* explicit cancellation.

---

## `AVAILABLE`

The encrypted file:

1. exists completely in object storage;
2. passed ciphertext integrity verification;
3. has durable `AVAILABLE` state in PostgreSQL.

Only files in this state may be downloaded.

The transition to `AVAILABLE` is transactional with the Files Service outbox event.

---

## `EXPIRED`

The configured retention period has ended.

The file is no longer available for normal download.

Physical object deletion may occur asynchronously.

---

## `DELETED`

The file was logically deleted.

It is immediately unavailable through the Files Service.

Physical deletion from object storage is performed asynchronously and may be retried.

---

# 4.11 Canonical File Metadata

## Table: `files`

```text id="qzty8e"
files
├── file_id
├── lifecycle_state
├── encrypted_size_bytes
├── chunk_count
├── encryption_version
├── ciphertext_integrity_hash
├── created_at
├── available_at
├── expires_at
├── deleted_at
└── metadata_version
```

### Primary key

```text id="5l7cl5"
PRIMARY KEY (file_id)
```

---

## `file_id`

Canonical Files Service identifier.

---

## `lifecycle_state`

One of:

```text id="lwx9w4"
UPLOAD_CREATED
UPLOADING
AVAILABLE
EXPIRED
DELETED
```

---

## `encrypted_size_bytes`

Total size of the encrypted object.

This is operational metadata.

---

## `chunk_count`

Number of encrypted chunks.

Used for:

* resumable uploads;
* resumable downloads;
* transfer validation.

---

## `encryption_version`

Identifies the file encryption/envelope format.

Cryptographic details remain governed by ADR-008.

---

## `ciphertext_integrity_hash`

A SHA-256 digest of the final encrypted file representation.

Conceptually:

```text id="d9gw0g"
SHA-256(final encrypted object)
```

The Files Service uses it for operational verification that:

```text id="36mxw4"
stored encrypted object
=
expected encrypted object
```

It is not a replacement for cryptographic authentication provided by the end-to-end encryption scheme.

The distinction is:

```text id="vchsv1"
AEAD authentication
       │
       ▼
Cryptographic authenticity and integrity
```

versus:

```text id="ru9si1"
CiphertextIntegrityHash
       │
       ▼
Operational transfer and storage consistency
```

For MVP:

> **Ciphertext integrity hash = SHA-256 over the final encrypted object.**

---

# 4.12 Upload Session

Every upload has an explicit durable upload session.

## Table: `upload_sessions`

```text id="h3rzqy"
upload_sessions
├── upload_id
├── file_id
├── lifecycle_state
├── expected_chunk_count
├── encrypted_size_bytes
├── created_at
├── updated_at
└── expires_at
```

### Primary key

```text id="1d7q6l"
PRIMARY KEY (upload_id)
```

### Unique relationship

```text id="7b8qke"
upload_id → file_id
```

Each upload session belongs to one file.

The MVP creates one active upload session per file.

---

# 4.13 Upload Progress

Upload progress must survive:

* client disconnect;
* Gateway restart;
* Files Service restart;
* network interruption.

Therefore completed chunk information is stored durably.

## Table: `upload_chunks`

```text id="t72pv1"
upload_chunks
├── upload_id
├── chunk_index
├── encrypted_chunk_size
├── chunk_integrity_hash
└── uploaded_at
```

### Primary key

```text id="8zby2a"
PRIMARY KEY (
    upload_id,
    chunk_index
)
```

Each chunk is uniquely identified by:

```text id="lpry5b"
UploadId + ChunkIndex
```

Example:

```text id="dzv31a"
UploadId = U100
ChunkIndex = 42
```

This provides durable upload progress.

---

# 4.14 Chunk Integrity

Each uploaded chunk has an optional operational integrity digest:

```text id="g58b6h"
SHA-256(encrypted chunk)
```

stored as:

```text id="kq8vka"
chunk_integrity_hash
```

This allows the Files Service to verify:

* correct chunk transmission;
* idempotent retry consistency;
* resumable upload correctness.

The final file-level:

```text id="btpnkk"
ciphertext_integrity_hash
```

verifies the complete encrypted object.

The chunk hash and file hash have different scopes.

```text id="0fb6mn"
Chunk hash
    │
    └── verifies one encrypted chunk

File hash
    │
    └── verifies final encrypted file representation
```

---

# 4.15 Resumable Upload

The upload protocol is:

```text id="czumw3"
1. Client requests upload creation
        │
        ▼
2. Files Service creates
        │
        ├── FileId
        └── UploadId
        │
        ▼
3. PostgreSQL transaction commits
        │
        ▼
4. Client uploads encrypted chunks
        │
        ▼
5. Files Service records completed chunks
        │
        ▼
6. Client reconnects if interrupted
        │
        ▼
7. Files Service returns completed chunks
        │
        ▼
8. Client uploads missing chunks
```

Example:

```text id="4h3p3e"
Expected chunks:

0
1
2
3
4
5

Completed:

0
1
2
4
```

The client resumes with:

```text id="cx0y1c"
Chunk 3
Chunk 5
```

The complete file is never uploaded again solely because the connection was interrupted.

---

# 4.16 Idempotent Chunk Upload

Chunk upload retries are idempotent.

The identity of a logical chunk upload is:

```text id="wjp7ub"
UploadId + ChunkIndex
```

If the client retries an already completed chunk:

```text id="qqtul2"
U100 + 42
```

the Files Service:

1. checks existing chunk metadata;
2. compares the supplied encrypted chunk integrity hash;
3. accepts the retry only if it represents the same encrypted chunk.

The operation does not create a duplicate logical chunk.

If the existing and retried chunk hashes differ:

> The upload is rejected as inconsistent.

---

# 4.17 Upload Completion

An upload is complete when:

```text id="xpjmk1"
all expected chunks exist
```

and:

```text id="l07p11"
final encrypted object exists
```

and:

```text id="wovd59"
final SHA-256 verification succeeds
```

The completion workflow is:

```text id="9cwh00"
All chunks uploaded
       │
       ▼
Finalize encrypted object
       │
       ▼
Verify ciphertext_integrity_hash
       │
       ▼
Begin PostgreSQL transaction
       │
       ├── files.state = AVAILABLE
       │
       └── INSERT FILE_AVAILABLE event
           into transactional_outbox
       │
       ▼
Commit
       │
       ▼
File is AVAILABLE
```

The file cannot become `AVAILABLE` before successful final object verification.

---

# 4.18 Transactional Outbox

The Files Service uses the Transactional Outbox pattern.

The outbox guarantees atomicity between:

```text id="b9oz7x"
Files Service database state
+
Domain event creation
```

The canonical table is:

## Table: `outbox_events`

```text id="x5w8ea"
outbox_events
├── event_id
├── aggregate_type
├── aggregate_id
├── event_type
├── payload
├── created_at
├── published_at
└── publication_status
```

For the Files Service:

```text id="tgmby4"
aggregate_type = FILE
aggregate_id   = FileId
```

---

# 4.19 File Availability and Outbox Atomicity

The most important Files Service outbox transition is:

```text id="ygxrrj"
File becomes AVAILABLE
```

The PostgreSQL transaction performs:

```text id="lmmw24"
UPDATE files
SET lifecycle_state = AVAILABLE
```

and:

```text id="zeykyz"
INSERT INTO outbox_events
(
    aggregate_type = FILE,
    aggregate_id = FileId,
    event_type = FILE_AVAILABLE
)
```

in the same transaction.

Therefore:

```text id="qysu5t"
File AVAILABLE committed
        ⇔
FILE_AVAILABLE outbox event committed
```

The outbox publisher later publishes the event using the architecture defined in ADR-004.

The Files Service does not depend on synchronous event publication to complete the database transaction.

---

# 4.20 Object Storage and Database Consistency

PostgreSQL and object storage do not share a distributed transaction.

Therefore:

> Object storage operations are never considered atomically committed with PostgreSQL.

The design explicitly avoids pretending that they are.

The safe ordering is:

```text id="y6pn6b"
1. Create durable PostgreSQL metadata
       │
       ▼
2. Upload encrypted bytes to object storage
       │
       ▼
3. Verify final encrypted object
       │
       ▼
4. Transactionally mark file AVAILABLE
   + create outbox event
```

A database record does not claim that a file is `AVAILABLE` until the object already exists and has been verified.

---

# 4.21 Object Storage Orphans

A failure can still leave an object stored without a final `AVAILABLE` metadata state.

Example:

```text id="eexb07"
Object successfully uploaded
        │
        ▼
Files Service crashes
        │
        ▼
PostgreSQL AVAILABLE transaction never commits
```

The encrypted object is then an orphan.

The recovery model is:

```text id="r1p8zu"
PostgreSQL lifecycle state
        │
        ▼
Authoritative file state
        │
        ▼
Periodic reconciliation
        │
        ▼
Delete or recover orphaned objects
```

The object must never become downloadable merely because it exists in object storage.

PostgreSQL lifecycle state remains authoritative.

---

# 4.22 Resumable Download

Downloads are resumable.

The client maintains local progress.

For the MVP, resumption is chunk-based.

Example:

```text id="44et2s"
Chunk 0 ✓
Chunk 1 ✓
Chunk 2 ✓
Chunk 3 ✓
Chunk 4 ✗
Chunk 5 ✗
```

After interruption, the client requests:

```text id="z5v5pa"
FileId
StartingChunk = 4
```

The Files Service retrieves the required encrypted bytes from object storage.

The Files Service does not infer client progress.

The client explicitly provides the required range.

---

# 4.23 Download Authorization

The Gateway authenticates the client and establishes the authenticated request context.

The Files Service receives:

```text id="d0uqx0"
Authenticated UserId
Authenticated DeviceId
Request context
```

as opaque identifiers.

The Files Service does not authenticate passwords or JWTs itself.

The Files Service does not own conversation membership.

Where access depends on conversation membership, the Files Service uses the defined internal Messaging API.

Conceptually:

```text id="z9us50"
Client
   │
   ▼
Gateway
   │ authentication enforcement
   ▼
Files Service
   │
   ├── File lifecycle authority
   │
   └── Membership check when required
            │
            ▼
       Messaging Service
```

Messaging remains authoritative for conversation membership.

Files remains authoritative for file existence and lifecycle.

---

# 4.24 File Streaming

File upload and download use streaming.

The complete file is never loaded into Gateway or Files Service memory.

The path is:

```text id="5s3tug"
Client
  │
  │ encrypted stream
  ▼
Gateway
  │
  │ bounded forwarding
  ▼
Files Service
  │
  │ bounded chunk processing
  ▼
Object Storage
```

For downloads:

```text id="swxf4x"
Object Storage
      │
      ▼
Files Service
      │ bounded streaming
      ▼
Gateway
      │ bounded streaming
      ▼
Client
```

Gateway and Files Service propagate:

* backpressure;
* cancellation;
* stream failure.

---

# 4.25 Concurrent Transfer Model

The Files Service uses bounded concurrency.

The model has three levels.

## Level 1 — Global Service Capacity

The service has configurable limits for:

```text id="omk6q8"
Maximum concurrent uploads
Maximum concurrent downloads
Maximum concurrent object-storage operations
```

The limits are deployment configuration.

The implementation must not create unbounded queues.

When capacity is exhausted:

* requests may wait only within bounded queues;
* additional requests receive explicit overload behavior.

---

## Level 2 — Per-Device Capacity

Each authenticated device has bounded concurrent transfer capacity.

Conceptually:

```text id="gsvonx"
Device A
├── Upload 1
├── Upload 2
└── Additional upload → rejected or delayed
```

This prevents one device from consuming unlimited service resources.

---

## Level 3 — Per-Transfer Resources

Every transfer uses:

```text id="wttgtf"
bounded buffer
+
4 MiB maximum logical chunk
+
bounded object-storage operations
```

Memory consumption must not grow proportionally with total file size.

---

# 4.26 Transfer Execution Model

The implementation must not create:

```text id="q4wq5s"
one unbounded thread per transfer
```

The concrete model is:

```text id="y2c3n8"
Asynchronous / non-blocking stream handling
        │
        ▼
Bounded transfer coordination
        │
        ▼
Bounded object-storage I/O concurrency
```

The exact C++ runtime primitives may depend on the chosen implementation stack.

The architectural decision is concrete:

> **Transfer concurrency is bounded, asynchronous I/O is preferred, and total process resources remain bounded independently of the number of connected clients.**

---

# 4.27 File Expiration

Files may have a retention deadline.

The authoritative expiration value is:

```text id="qf2k0v"
expires_at
```

A Files Service lifecycle worker identifies expired records.

The transition is:

```text id="jmv0zg"
AVAILABLE
    │
    ▼
EXPIRED
```

The database transition may create:

```text id="d8c0ny"
FILE_EXPIRED
```

through the transactional outbox.

Physical object deletion occurs after the logical transition.

The object is no longer available for download once PostgreSQL records `EXPIRED`.

---

# 4.28 File Deletion

Deletion is logical before physical.

The transition is:

```text id="kjufsu"
AVAILABLE
    │
    ▼
DELETED
    │
    ▼
Asynchronous physical deletion
```

The PostgreSQL transaction:

```text id="esdzhd"
updates lifecycle_state = DELETED
+
creates FILE_DELETED outbox event
```

Physical object deletion is retried if necessary.

The file remains unavailable even if object deletion temporarily fails.

---

# 4.29 Failure Recovery

The Files Service must recover from:

* client disconnect;
* Gateway restart;
* Files Service restart;
* object-storage timeout;
* partial upload;
* duplicate chunk upload;
* interrupted download;
* upload completion failure;
* PostgreSQL failure;
* object storage orphan creation.

Recovery relies on:

```text id="c8eeo1"
Durable PostgreSQL state
+
Idempotent chunk operations
+
Explicit lifecycle states
+
Transactional Outbox
+
Resumable transfers
+
Object-storage reconciliation
```

In-memory transfer state is never authoritative.

After a restart:

```text id="geve5j"
Files Service restart
       │
       ▼
Reload PostgreSQL state
       │
       ▼
Continue or expire resumable uploads
```

---

# 4.30 Files Service Data Invariants

The Files Service must preserve the following invariants:

1. Every file has one opaque `FileId`.
2. The MVP uses UUIDv7 for `FileId`.
3. `FileId` does not encode human identity.
4. Object storage keys are derived deterministically from `FileId`.
5. `object_key` is not stored as independent domain metadata.
6. File binary content is encrypted before reaching the backend.
7. Gateway does not decrypt file content.
8. Files Service does not decrypt file content.
9. Object storage never stores plaintext file content.
10. PostgreSQL is the authoritative database for file metadata and lifecycle.
11. Object storage is authoritative only for encrypted binary object storage.
12. The backend does not store readable original filenames.
13. The backend does not store readable plaintext MIME types.
14. Human-readable file metadata remains inside encrypted application metadata.
15. Plaintext file size is not stored as readable backend metadata.
16. Encrypted size and chunk count are operational metadata.
17. Files are processed using 4 MiB chunks.
18. The final chunk is padded before encryption.
19. File size leakage is reduced but not eliminated.
20. Files Service performs no server-side compression.
21. Any compression occurs before encryption on the client.
22. Every upload has a durable `UploadId`.
23. Upload progress is persisted in PostgreSQL.
24. Chunk upload identity is `UploadId + ChunkIndex`.
25. Chunk retries are idempotent.
26. Inconsistent duplicate chunks are rejected.
27. SHA-256 chunk hashes verify encrypted chunk consistency.
28. SHA-256 final hash verifies the final encrypted object.
29. Operational integrity hashes do not replace AEAD authentication.
30. A file is downloadable only when lifecycle state is `AVAILABLE`.
31. A partially uploaded file is never available.
32. PostgreSQL `AVAILABLE` transition occurs only after object existence and verification.
33. File state transition and Files Service outbox event are committed atomically.
34. Object storage and PostgreSQL are not treated as a distributed transaction.
35. PostgreSQL lifecycle state remains authoritative even when an object exists.
36. Orphaned encrypted objects are reconciled asynchronously.
37. Uploads are resumable.
38. Downloads are resumable.
39. The complete file is never loaded into Gateway memory.
40. The complete file is never loaded into Files Service memory.
41. File streaming propagates backpressure and cancellation.
42. Upload concurrency is bounded.
43. Download concurrency is bounded.
44. Object-storage I/O concurrency is bounded.
45. Per-device transfer concurrency is bounded.
46. The implementation does not create one unbounded thread per transfer.
47. Transfer resource consumption is bounded independently of total file size.
48. Files Service does not own conversation membership.
49. Messaging remains authoritative for conversation membership.
50. Files Service uses opaque authenticated identity references.
51. Logical deletion occurs before physical object deletion.
52. Physical deletion may be asynchronous and retried.
53. Expiration is governed by PostgreSQL lifecycle metadata.
54. File lifecycle changes that require cross-service visibility are emitted through the Transactional Outbox.
55. In-memory state is never the authoritative source for resumable transfer durability.

---

# 4.31 Files Service Data Model Summary

| Storage / Table              | Responsibility                                        |
| ---------------------------- | ----------------------------------------------------- |
| `files`                      | Canonical file metadata and lifecycle                 |
| `upload_sessions`            | Durable resumable upload session state                |
| `upload_chunks`              | Completed encrypted chunk metadata                    |
| `outbox_events`              | Transactionally committed Files Service domain events |
| S3-compatible object storage | Encrypted file binary objects                         |

The final Files Service persistence architecture is:

```text id="svl5fm"
                    Files Service
                         │
          ┌──────────────┴──────────────┐
          │                             │
          ▼                             ▼
      PostgreSQL                  Object Storage
          │                             │
          │                             │
   FileId + lifecycle              Encrypted bytes
   Upload sessions                 only
   Upload progress
   Integrity metadata
   Transactional Outbox
```

The Files Service therefore combines:

* PostgreSQL transactional consistency for domain state;
* Transactional Outbox reliability for domain events;
* S3-compatible object storage for scalable encrypted binary storage;
* client-side encryption for file confidentiality;
* bounded streaming and concurrency for predictable resource usage.
