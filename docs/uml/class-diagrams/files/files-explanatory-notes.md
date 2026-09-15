Files Service UML Class Diagram — Explanatory Note
1. Purpose

This UML diagram describes the implementation responsibilities of the C++ Files Service.

It is based on the approved physical model:

PostgreSQL
│
├── files
├── upload_sessions
├── upload_chunks
└── outbox_events

S3-compatible object storage
└── encrypted file bytes

PostgreSQL is authoritative for file metadata and lifecycle. Object storage contains encrypted binary objects.

The UML diagram therefore deliberately distinguishes:

domain/lifecycle state;
PostgreSQL persistence;
encrypted binary storage;
streaming transfer execution;
membership authorization;
integrity verification;
transactional outbox publication.

2. The four approved PostgreSQL persistence models

The Files Service UML has explicit representations for all four approved tables.

PostgreSQL table	UML model	Repository
files	File	FileRepository
upload_sessions	UploadSession	UploadSessionRepository
upload_chunks	UploadChunk	UploadChunkRepository
outbox_events	OutboxEvent	OutboxEventRepository

This is different from Messaging because Files uses a relational transactional database rather than ScyllaDB.

3. File — canonical lifecycle authority

File corresponds to the files table and represents the authoritative lifecycle state of the file.

Important properties include:

fileId
lifecycleState
encryptedSizeBytes
chunkCount
encryptionVersion
ciphertextIntegrityHash
createdAt
availableAt
expiresAt
deletedAt
metadataVersion

The approved externally visible lifecycle is:

UPLOAD_CREATED
       ↓
UPLOADING
       ↓
AVAILABLE
     ↙     ↘
EXPIRED   DELETED

Only AVAILABLE files may be downloaded.

Why File does not contain objectKey

This is intentional.

The approved design states that the object storage key is derived deterministically from FileId:

files/{FileId}/content

Therefore object_key is not stored as independent metadata.

That is why the UML contains:

FileId
   ↓
ObjectKeyResolver
   ↓
ObjectKey

rather than:

File
└── objectKey

FileId is the canonical domain identifier; the storage key is an infrastructure derivation.

4. UploadSession — durable resumable upload state

Every upload has a durable UploadSession.

Its main responsibilities are:

identifying the upload through UploadId;
linking the upload to FileId;
recording expected chunk count;
recording encrypted transfer size;
tracking upload lifecycle;
surviving disconnects and service restarts.

The approved model creates one active upload session per file.

The UML relationship is:

File
  │
  └── 0..1 active UploadSession

This does not mean that historical lifecycle information must disappear; it reflects the approved MVP concept of one active upload session per file.

5. UploadChunk — durable upload progress

UploadChunk represents a successfully recorded encrypted chunk.

Its logical identity is:

UploadId + ChunkIndex

This is crucial for resumability and idempotency.

For example:

UploadId = U100
ChunkIndex = 42

identifies one logical encrypted chunk.

The approved model stores:

encryptedChunkSize
chunkIntegrityHash
uploadedAt

and allows the client to resume by asking which chunks have already been completed.

6. UploadService

UploadService coordinates the resumable upload path.

Its main flow is:

Client encrypted chunk
        ↓
UploadService
        ↓
Check UploadSession
        ↓
Check existing UploadChunk
        ↓
Upload to ObjectStorage
        ↓
Persist UploadChunk metadata

For a retry:

UploadId + ChunkIndex
        ↓
Already exists?
     ┌────┴────┐
     │         │
    No        Yes
     │         │
 upload     compare hash
             │
       same ─┴─ different
        │          │
     idempotent   reject
      success   inconsistent retry

This matches the approved rule that duplicate chunks are accepted only when they represent the same encrypted chunk.

7. FileIntegrityService

This service centralizes the two approved integrity scopes.

Chunk-level integrity
SHA-256(encrypted chunk)

This supports:

retry consistency;
transmission verification;
resumable upload correctness.
Final-object integrity
SHA-256(final encrypted object)

This verifies the complete encrypted representation.

The two are deliberately separate because they have different scopes.

Importantly, these operational hashes do not replace AEAD authentication. The data model explicitly distinguishes operational storage/transfer consistency from cryptographic authenticity and integrity.

8. Upload completion and FileLifecycleService

FileLifecycleService owns important lifecycle transitions.

The most critical transition is:

UPLOADING
    ↓
AVAILABLE

The approved sequence is:

All expected chunks exist
        ↓
Final encrypted object exists
        ↓
Final SHA-256 verification succeeds
        ↓
PostgreSQL transaction
        ├── files.state = AVAILABLE
        └── INSERT FILE_AVAILABLE
            into outbox_events
        ↓
COMMIT

The file cannot become AVAILABLE before final object verification succeeds.

9. FileTransactionManager

This abstraction exists because Files has a capability that Messaging does not have in the same form.

Files uses PostgreSQL and can atomically perform:

UPDATE files
+
INSERT outbox_events
+
COMMIT

The transaction boundary is therefore explicit in the UML.

The key invariant is:

File AVAILABLE committed
        ⇔
FILE_AVAILABLE event committed

This is the approved Files Service Transactional Outbox model.

The object storage operation itself is not part of this PostgreSQL transaction.

10. Object storage consistency

ObjectStorage represents the S3-compatible encrypted binary store.

The UML deliberately does not imply:

PostgreSQL transaction
        +
Object storage
        =
one atomic transaction

That would contradict the approved architecture.

The safe ordering is:

1. Create PostgreSQL metadata
        ↓
2. Upload encrypted bytes
        ↓
3. Verify final encrypted object
        ↓
4. PostgreSQL transaction
       ├── mark AVAILABLE
       └── create Outbox event

PostgreSQL remains authoritative for file lifecycle even if an object exists in storage.

11. ObjectReconciliationWorker

Because PostgreSQL and object storage are not part of one distributed transaction, orphaned objects are possible.

For example:

Object uploaded successfully
        ↓
Files Service crashes
        ↓
AVAILABLE transaction never commits
        ↓
Orphan encrypted object

ObjectReconciliationWorker periodically compares object-storage state with authoritative PostgreSQL lifecycle state and deletes or recovers orphaned objects according to recovery rules.

This worker is intentionally asynchronous.

12. Download authorization

FileAccessService is responsible for determining whether access is permitted.

The Files Service receives opaque:

Authenticated UserId
Authenticated DeviceId
RequestContext

It does not authenticate passwords or JWTs itself.

Where access depends on conversation membership, Files asks Messaging through the defined internal API boundary.

Therefore the UML contains:

FileAccessService
        ↓
MessagingMembershipClient

The responsibility boundary is:

Messaging
    │
    └── authoritative conversation membership

Files
    │
    └── authoritative file lifecycle and existence

The Files Service must not become an owner of conversation membership.

13. DownloadService

Downloads are:

encrypted;
streamed;
resumable;
bounded.

The complete file is never loaded into Files Service memory.

The flow is:

Object Storage
      ↓
Files Service
  bounded stream
      ↓
Gateway
  bounded stream
      ↓
Client

The client explicitly provides the required starting chunk when resuming.

14. TransferCapacityController

This class represents the approved bounded concurrency policy.

The Files Service must limit:

Maximum concurrent uploads
Maximum concurrent downloads
Maximum concurrent object-storage operations

and also enforce bounded per-device capacity.

The purpose is to prevent:

one device
     ↓
unlimited transfers
     ↓
resource exhaustion

The implementation must not create one unbounded thread per transfer. Instead, asynchronous/non-blocking streaming with bounded resource coordination is preferred.

The exact C++ primitives remain an implementation decision, as approved:

asynchronous I/O is preferred, bounded concurrency is mandatory, and process resources must remain bounded independently of the number of connected clients.

This is why the UML models the policy abstraction without prematurely selecting a specific C++ runtime or library.

15. OutboxEvent and reliable publication

OutboxEvent corresponds directly to the approved outbox_events PostgreSQL table:

eventId
aggregateType
aggregateId
eventType
payload
createdAt
publishedAt
publicationStatus

For Files:

aggregateType = FILE
aggregateId   = FileId

The Outbox records significant lifecycle events such as:

FILE_AVAILABLE
FILE_EXPIRED
FILE_DELETED

when the corresponding lifecycle transition requires cross-service visibility.

16. FilesOutboxPublisher

The publisher works asynchronously:

outbox_events
      ↓
find unpublished events
      ↓
ApplicationEventPublisher
      ↓
successful publication
      ↓
mark published

The file operation itself does not synchronously depend on downstream event consumption.

This is important for resilience:

Files operation
     │
     ├── PostgreSQL state committed
     └── Outbox event committed

Downstream service temporarily unavailable
     │
     ↓
Outbox publisher retries later
17. File expiration and deletion
Expiration

The approved transition is:

AVAILABLE
    ↓
EXPIRED

FileExpirationWorker identifies files whose authoritative:

expiresAt

has been reached.

The logical state changes before eventual physical object deletion.

Deletion

Deletion follows:

AVAILABLE
    ↓
DELETED
    ↓
asynchronous physical deletion

The logical PostgreSQL state becomes authoritative immediately.

If physical deletion temporarily fails, the file remains unavailable and object deletion can be retried.

18. Main upload flow represented by the UML
FilesRequestHandler
        ↓
FileLifecycleService
        ↓
Create File + UploadSession
        ↓
PostgreSQL commit
        ↓
UploadService
        ↓
TransferCapacityController
        ↓
FileIntegrityService
        ↓
ObjectStorage
        ↓
UploadChunkRepository
        ↓
...
        ↓
completeUpload()
        ↓
Verify final encrypted object
        ↓
PostgreSQL transaction
        ├── File = AVAILABLE
        └── OutboxEvent = FILE_AVAILABLE
        ↓
COMMIT
        ↓
FilesOutboxPublisher
        ↓
ApplicationEventPublisher