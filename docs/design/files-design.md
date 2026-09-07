# 6. Files Service Design

## 6.1 Purpose

The Files Service provides secure storage and transfer of files exchanged through SecureCloud.

Its responsibilities are:

* create and manage file-transfer sessions;
* receive encrypted file data;
* store encrypted file content durably;
* support resumable uploads and downloads;
* maintain file metadata and transfer state;
* enforce file-level access control;
* validate transfer and storage integrity;
* support large files without loading them entirely into memory;
* apply bounded concurrency and backpressure;
* emit audit events asynchronously.

The Files Service operates exclusively on **encrypted file content**.

It must never possess:

* plaintext file content;
* user/device private cryptographic keys;
* plaintext file-encryption keys;
* an administrative mechanism for decrypting stored files.

File encryption and decryption are endpoint responsibilities.

---

## 6.2 Architectural Responsibility

The Files Service owns the server-side lifecycle of an encrypted file.

```text
Qt/C++ Client
     │
     │ HTTPS streaming
     ▼
API Gateway
     │
     │ gRPC streaming
     ▼
Files Service
     │
     ├── PostgreSQL 17
     │     metadata + transfer state
     │
     └── MinIO
           encrypted file objects
```

The Files Service does not perform application-level file encryption or decryption.

The security boundary is therefore:

```text
Client
 ├── plaintext file
 ├── optional compression
 ├── file encryption
 └── file key
          │
          │ encrypted stream
          ▼
Files Service
 ├── ciphertext
 ├── metadata
 └── transfer state
          │
          ▼
       MinIO
```

A compromise of the Files Service or its object storage must not provide the plaintext contents of stored files.

---

## 6.3 File Domain Model

The primary domain concepts are:

* `File`
* `FileVersion`
* `FileTransfer`
* `FileChunk`
* `FileAccess`
* `EncryptedFileMetadata`

### File

Represents a logical file shared through SecureCloud.

Conceptual attributes include:

* `file_id`
* `owner_device_id`
* `conversation_id` when associated with a conversation
* filename metadata where required
* MIME/content-type metadata where required
* encrypted size
* creation timestamp
* retention/expiration state
* encryption protocol version
* lifecycle state

`file_id` is globally unique and opaque.

It must not encode usernames, email addresses, filenames or other unnecessary sensitive information.

### FileVersion

The MVP treats completed file objects as immutable.

If a logical file must be replaced, a new version/object is created rather than modifying an existing encrypted object in place.

This simplifies:

* integrity verification;
* resumable transfers;
* concurrent downloads;
* lifecycle management;
* recovery.

### FileTransfer

Represents an upload or download operation.

For uploads:

```text
CREATED
   ↓
TRANSFERRING
   ↓
FINALIZING
   ↓
COMPLETED
```

Failure states may be:

```text
TRANSFERRING → FAILED
TRANSFERRING → EXPIRED
FINALIZING   → FAILED
```

An upload is not considered complete until the encrypted object has reached the defined durable state and integrity checks have succeeded.

### FileChunk

Represents a logical portion of an encrypted file.

Chunks have stable sequence numbers within a transfer.

Conceptually:

```text
FileTransfer T123
 ├── chunk 0
 ├── chunk 1
 ├── chunk 2
 ├── ...
 └── chunk N
```

Chunking is the canonical mechanism for transfer progress and resumption.

The exact chunk size is an implementation/performance parameter.

---

## 6.4 Client-Side Compression and Encryption

The client performs optional compression before encryption.

The canonical pipeline is:

```text
plaintext
    ↓
compression decision
    │
    ├── no compression ──────┐
    │                        │
    └── compression          │
             │              │
             ▼              │
       compressed data      │
             │              │
             └──────┬───────┘
                    ▼
                encryption
                    ↓
              encrypted stream
                    ↓
               Files Service
```

### Compression decision

Compression is **not performed by the Files Service**.

The MVP uses a content-aware client-side policy:

* compress known compressible data;
* skip formats that are already strongly compressed;
* avoid unnecessary CPU/battery consumption when compression provides little benefit.

Typical examples:

| Content                                      | MVP policy   |
| -------------------------------------------- | ------------ |
| Text / source code / JSON / CSV / XML / logs | Compress     |
| JPEG / MP4 / MP3                             | Skip         |
| ZIP / 7z / gzip                              | Skip         |
| PNG                                          | Usually skip |
| PDF                                          | Conditional  |

The policy must not rely exclusively on filename extensions where reliable content-type information is available.

### Compression algorithm

The MVP uses **Zstandard (zstd)** for client-side compression.

The compression level is configurable and should be selected according to deployment requirements and benchmark results.

Compression occurs **before encryption** because encrypted ciphertext should not be expected to compress effectively.

The backend never receives the uncompressed plaintext representation.

---

## 6.5 File Encryption

File encryption follows ADR-008.

The client generates a random file-specific encryption key and encrypts the file before transmission.

The Files Service receives only the encrypted representation.

The encrypted representation contains the cryptographic metadata necessary for an authorized client to decrypt the file using the selected vetted cryptographic construction.

Private keys and plaintext file-encryption keys never enter the Files Service.

The exact cryptographic construction is not redefined here; ADR-008 is authoritative.

---

## 6.6 Streaming Architecture

Large files are transferred using streaming.

The complete file must not be held simultaneously in memory by the client, Gateway, Files Service or storage adapter.

Upload:

```text
Local File
    ↓
Client compression
    ↓
Client encryption
    ↓
HTTPS stream
    ↓
Gateway
    ↓
gRPC stream
    ↓
Files Service
    ↓
MinIO
```

Download:

```text
MinIO
    ↓
Files Service
    ↓
gRPC stream
    ↓
Gateway
    ↓
HTTPS stream
    ↓
Client
    ↓
decryption
    ↓
local file
```

Every stage uses bounded buffers.

The architectural rule is:

> Large-file transfers are streaming I/O pipelines with bounded memory, not whole-object buffering operations.

---

## 6.7 Chunking and Transfer Progress

Transfers use explicit encrypted chunks.

Conceptually:

```text
Chunk {
    transfer_id
    chunk_index
    encrypted_payload
    integrity_metadata
}
```

`chunk_index` provides a stable logical position within a transfer.

The Files Service durably records which chunks have been accepted.

This allows the service to distinguish:

```text
received:
0, 1, 2, 3, 4, 5, 6

missing:
7
```

from:

```text
received:
0, 1, 2, 4, 5, 6

missing:
3
```

The exact physical representation of chunk state in PostgreSQL/MinIO is an implementation detail, but the logical model is explicit and durable.

---

## 6.8 Resumable Uploads

Uploads are resumable.

Each upload receives a stable `transfer_id`.

The client does not have to restart an entire large file after a temporary connection failure.

Example:

```text
Client
   │
   │ CreateUpload
   ▼
Files
   │
   └── transfer_id = T123
          │
          ▼
      PostgreSQL
```

The client uploads:

```text
chunk 0
chunk 1
...
chunk 127
```

The connection then fails.

After reconnecting:

```text
Client
   │
   │ ResumeUpload(T123)
   ▼
Files
   │
   ▼
durable transfer state
```

The service determines which chunks have already been durably accepted and returns the required resume information.

The client then continues with the missing chunks.

---

## 6.9 Idempotent Chunk Submission

Chunk uploads are idempotent.

A client may retry a chunk when the previous response was lost.

For example:

```text
Client                    Files
   │                         │
   │ UploadChunk #25         │
   ├────────────────────────►│
   │                         │
   │                         │ persisted
   │                         │
   X response lost           │
   │                         │
   │ UploadChunk #25         │
   ├────────────────────────►│
   │                         │
   │                         │ already exists
   │◄────────────────────────┤
```

The second request must not create duplicate logical data or corrupt the transfer.

The combination of:

* stable `transfer_id`;
* stable `chunk_index`;
* chunk integrity information;
* durable transfer state;

provides the basis for safe retry and resume.

---

## 6.10 Resumable Downloads

Downloads are also resumable.

The client identifies the file and the point from which it requires data.

The canonical resume unit is the encrypted chunk.

Conceptually:

```text
DownloadResume {
    file_id
    file_version
    starting_chunk
}
```

Example:

```text
Client
   │
   │ received chunks 0–127
   │
   X connection interrupted
   │
   │ ResumeDownload(file, chunk=128)
   ▼
Files
   │
   ▼
MinIO
   │
   │ stream from chunk 128
   ▼
Client
```

The server does not need to retransmit the already received portion.

The client remains responsible for final integrity verification and decryption.

---

## 6.11 Concurrent Transfer Model

The Files Service uses **separate bounded concurrency domains** for different workloads.

```text
                         Files Service
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
     Metadata              Upload              Download
      workers              workers              workers
          │                   │                   │
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
                              ▼
                        Storage adapters
                       PostgreSQL / MinIO
```

The service must not use one shared unlimited worker pool for all operations.

### Metadata concurrency

Metadata operations include:

* create file;
* create transfer;
* retrieve metadata;
* authorize access;
* finalize;
* cancel;
* query transfer state.

These operations use bounded concurrency and must remain responsive even when large transfers are active.

### Upload concurrency

Uploads use a bounded pool of active transfer resources.

Multiple uploads may progress concurrently.

Each upload uses:

* bounded input buffering;
* asynchronous/streaming I/O;
* bounded storage operations;
* durable transfer state.

### Download concurrency

Downloads use an independent bounded capacity.

Multiple downloads may progress concurrently.

A large or slow download must not consume all service capacity.

### Upload/download isolation

Upload and download capacity are intentionally isolated.

For example:

```text
100 large downloads
```

must not automatically consume all resources needed for:

```text
a new upload
```

and vice versa.

This is a service-level bulkhead.

---

## 6.12 Execution Model

The Files Service does **not** use one OS thread per active transfer.

A large number of concurrent I/O streams must be supported using a bounded number of execution resources.

Conceptually:

```text
Many active transfers
        │
        ▼
asynchronous I/O / streaming
        │
        ▼
bounded execution resources
```

Therefore:

```text
1000 active transfers
```

does not imply:

```text
1000 OS threads
```

The exact C++ asynchronous I/O implementation is an implementation decision consistent with the project's networking stack.

The architectural requirement is:

> Active transfer count and execution-thread count are independent resources.

---

## 6.13 Resource Limits

The following resources are explicitly bounded:

* active uploads;
* active downloads;
* concurrent metadata requests;
* concurrent gRPC streams;
* memory buffers;
* database connections;
* MinIO connections;
* storage operations;
* cleanup work;
* request sizes;
* transfer sizes;
* chunk-processing capacity.

The service must never respond to load by creating unbounded:

* threads;
* queues;
* memory buffers;
* database connections;
* storage requests.

Exact numerical limits are benchmark/configuration parameters.

The boundedness model itself is fixed by this design.

---

## 6.14 Backpressure

Backpressure must propagate through the entire transfer pipeline.

Example:

```text
MinIO
  ↓
Files Service
  ↓
buffer becomes full
  ↓
gRPC stream cannot accept more
  ↓
Gateway slows
  ↓
client stream slows
```

A slow client must therefore not cause the Files Service to accumulate an unbounded amount of encrypted data in memory.

Similarly, if storage cannot accept data quickly enough:

```text
Client
   ↓
Gateway
   ↓
Files
   ↓
storage capacity exhausted
```

the service must throttle or reject work rather than continuously buffering data.

Before durable acceptance, the service may:

* reject the request;
* throttle the transfer;
* return an explicit retryable error.

After a chunk has been durably accepted, the service must retain its durable state and must not silently discard it.

---

## 6.15 File Access Control

The Files Service enforces authorization for file operations.

The Gateway provides authenticated context.

The Files Service verifies that the authenticated user/device is authorized to:

* create the file;
* upload;
* resume;
* download;
* cancel;
* delete when permitted.

Client-supplied ownership information is not trusted as an authorization source.

For example, a client cannot simply claim another user's identifier as the file owner.

Authorization is derived from:

* authenticated identity;
* server-side file state;
* conversation/access state;
* applicable application authorization rules.

---

## 6.16 File Sharing Through Messaging

A file shared through a conversation is represented by a stable `file_id`.

The message contains a reference to the file rather than the complete file content.

```text
Message
 ├── message_id
 ├── conversation_id
 └── attachment
       └── file_id
```

The Files Service manages:

```text
file_id → encrypted object
```

while the client cryptographic layer manages:

```text
file_id → cryptographic access to decrypt the file
```

The file-encryption key is never exposed to the Files Service as plaintext.

---

## 6.17 Object Storage

MinIO is the authoritative storage system for encrypted file content.

PostgreSQL 17 is the authoritative storage system for structured metadata and transfer state.

```text
PostgreSQL
├── file metadata
├── transfer state
├── access state
├── lifecycle state
├── object reference
├── integrity/finalization metadata
└── idempotency state

MinIO
└── opaque object key
       ↓
   encrypted content
```

The object key must be opaque.

It must not expose:

* usernames;
* email addresses;
* conversation names;
* plaintext filenames;
* other unnecessary sensitive information.

No other SecureCloud runtime service directly accesses Files' PostgreSQL database or MinIO storage.

---

## 6.18 File Finalization

Uploading chunks and completing a file are distinct operations.

The finalization process verifies that:

1. the expected transfer exists;
2. all required chunks are present;
3. transfer state is valid;
4. integrity requirements are satisfied;
5. the encrypted object is durably stored;
6. metadata can safely transition to `AVAILABLE`.

Only after successful finalization is the file exposed as a completed downloadable object.

A partially uploaded file must never appear as a valid completed file.

---

## 6.19 File Lifecycle

The server-side lifecycle is:

```text
CREATED
   │
   ▼
UPLOADING
   │
   ▼
FINALIZING
   │
   ▼
AVAILABLE
   │
   ├──────────────► EXPIRED
   │
   └──────────────► DELETED
```

Failure paths include:

```text
UPLOADING  → FAILED
FINALIZING → FAILED
```

Cleanup of failed or expired transfers is asynchronous and idempotent.

---

## 6.20 Retention and Cleanup

File retention is bounded.

The service must prevent abandoned uploads and expired objects from accumulating indefinitely.

Cleanup is performed by a dedicated bounded cleanup worker.

Conceptually:

```text
PostgreSQL
     │
     │ expired transfer
     ▼
CleanupWorker
     │
     ▼
MinIO object deletion
     │
     ▼
metadata finalization
```

Cleanup must be safe to retry.

A cleanup failure must not erase the database's knowledge of the object.

Exact retention periods and quotas are configuration parameters.

---

## 6.21 Integrity

The system must detect:

* corrupted chunks;
* modified ciphertext;
* missing chunks;
* truncated transfers;
* incomplete objects;
* inconsistent finalization state.

Cryptographic integrity is provided by the vetted encryption construction selected under ADR-008.

The Files Service additionally verifies transfer completeness and storage consistency.

Receiving the expected number of bytes alone is insufficient to declare a file valid.

---

## 6.22 Audit Events

The Files Service publishes audit events asynchronously through its transactional outbox.

Possible events include:

* `FILE_UPLOAD_CREATED`
* `FILE_UPLOAD_COMPLETED`
* `FILE_UPLOAD_FAILED`
* `FILE_DOWNLOAD_STARTED`
* `FILE_DOWNLOAD_COMPLETED`
* `FILE_ACCESS_DENIED`
* `FILE_EXPIRED`
* `FILE_DELETED`

Events contain only the metadata required for security and operational auditing.

They must never contain:

* plaintext file contents;
* file-encryption keys;
* private cryptographic keys.

Audit publication is not part of the critical file-persistence transaction.

Therefore:

```text
Audit unavailable
      ↓
File persistence continues
      ↓
Audit event remains in outbox
      ↓
Publication resumes later
```

---

## 6.23 Failure Handling

### MinIO unavailable

The service must not report durable file completion when the encrypted object has not reached the required durable state.

The transfer remains retryable or fails explicitly.

### PostgreSQL unavailable

Operations requiring authoritative metadata or transfer state fail explicitly.

The service must not invent state from process-local memory.

### Gateway unavailable

Active transfers may be interrupted.

The client resumes them later using the durable transfer identifier.

### Files Service restart

Transfer state is reconstructed from PostgreSQL and storage state rather than relying on process-local transfer state.

### Network interruption

Uploads and downloads resume using the durable transfer/file state and chunk position.

### Lost upload response

The client retries the chunk or operation using its stable identifiers.

The Files Service returns the existing result rather than creating duplicate logical state.

### Duplicate chunk

An already accepted chunk is treated idempotently.

### Partial upload

The partial transfer remains represented by durable state and is eventually cleaned up according to retention policy.

### Cleanup failure

Cleanup is retried without losing lifecycle state.

---

## 6.24 Performance Architecture

The Files Service is optimized primarily for:

* large-object throughput;
* concurrent transfers;
* predictable latency;
* bounded memory consumption;
* efficient storage/network utilization.

The principal performance decisions are:

1. streaming rather than whole-file buffering;
2. asynchronous I/O rather than thread-per-transfer;
3. separate upload/download concurrency domains;
4. bounded active transfers;
5. bounded buffers;
6. persistent database/storage connections;
7. MinIO for large encrypted objects;
8. resumable transfers;
9. asynchronous audit;
10. backpressure throughout the pipeline;
11. horizontal scalability without process-local correctness dependencies.

Performance testing must include the real security and persistence architecture.

Benchmarks must not disable:

* client-side encryption;
* integrity protection;
* Gateway;
* gRPC streaming;
* PostgreSQL;
* MinIO;
* access control;
* bounded resource controls.

The following are benchmark/configuration parameters rather than architectural decisions:

* chunk size;
* number of active uploads;
* number of active downloads;
* worker counts;
* buffer sizes;
* database connection-pool size;
* MinIO connection-pool size;
* compression level;
* bandwidth limits.

The optimization process follows ADR-010:

```text
measure
  ↓
benchmark
  ↓
profile
  ↓
identify bottleneck
  ↓
form hypothesis
  ↓
optimize
  ↓
benchmark again
```

---

## 6.25 Horizontal Scaling

Files Service instances are interchangeable.

Correctness must not depend on:

* a specific instance;
* process-local transfer state;
* sticky sessions;
* local filesystem state.

Durable state resides in PostgreSQL and MinIO.

Therefore:

```text
                 Gateway
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       Files-1   Files-2   Files-3
          │         │         │
          └─────────┼─────────┘
                    ▼
             PostgreSQL / MinIO
```

A transfer may reconnect through another Files Service instance.

The durable `transfer_id` and persistent state allow the new instance to continue the operation.

---

## 6.26 Security Invariants

The Files Service must preserve these invariants:

1. Plaintext file content never enters the backend.
2. File encryption occurs on the client.
3. Private cryptographic keys never enter the backend.
4. Plaintext file-encryption keys never enter the Files Service.
5. MinIO stores encrypted objects only.
6. PostgreSQL stores metadata and transfer state, not large plaintext file content.
7. File identifiers and object keys are opaque.
8. Client-supplied ownership information is never trusted without server-side authorization.
9. Incomplete uploads are never exposed as completed files.
10. Successful completion means the encrypted object has reached the defined durable state.
11. Duplicate operations cannot create inconsistent logical state.
12. Storage failures cannot produce false durable success.
13. Interrupted transfers can resume without requiring complete retransmission.
14. Resource exhaustion cannot produce unbounded memory, threads or queues.
15. Slow clients cannot cause unbounded server-side buffering.
16. Audit failure cannot invalidate otherwise valid file persistence.
17. Administrators have no decryption backdoor.
18. Cryptographic operations follow the vetted mechanisms defined by ADR-008.

---

## 6.27 Implementation Boundary

The following decisions are fixed for implementation:

* Files is an independent runtime service.
* External client communication goes through the Gateway.
* Internal communication uses gRPC streaming.
* PostgreSQL 17 owns metadata and transfer state.
* MinIO owns encrypted file objects.
* Encryption happens on the client.
* Compression, when used, happens on the client before encryption.
* MVP compression uses Zstandard with configurable compression level.
* The backend never compresses/decompresses plaintext file content.
* Large transfers use streaming.
* Files are transferred using explicit encrypted chunks.
* Uploads and downloads are resumable.
* Chunk submission is idempotent.
* Durable chunk/transfer state is the basis for resume.
* Upload and download concurrency are independently bounded.
* Metadata, upload and download workloads have separate concurrency domains.
* Active transfers use asynchronous/streaming I/O rather than one OS thread per transfer.
* Buffers, workers, streams, connections and queues are bounded.
* Backpressure propagates through the streaming pipeline.
* Completed file objects are immutable.
* File access is authorized server-side.
* Cleanup is durable, bounded and retryable.
* Audit publication is asynchronous.
* Files Service instances are horizontally interchangeable.
* Exact numerical resource limits are determined through benchmarking/configuration.

The detailed PostgreSQL schema, MinIO object mapping, gRPC messages, REST endpoints, error codes and exact transfer parameters belong in `data-model.md` and the API contracts.
