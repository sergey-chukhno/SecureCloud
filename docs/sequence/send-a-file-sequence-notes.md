Core architectural flow

The essential model is:

File plaintext
      │
      ▼
SecureCloud Client
      │
      │ Encrypt locally
      ▼
Encrypted file ciphertext
      │
      ▼
Files Service
      │
      │ Store ciphertext
      ▼
file_id
      │
      ▼
Messaging Service
      │
      │ Conversation item references file_id
      ▼
Recipient synchronization

The critical distinction is:

Encrypted file
    ≠
Encrypted message payload

Messaging stores the reference:

file_reference_ids

while Files owns:

Encrypted file content
File metadata
Upload lifecycle
Encrypted object storage
File-specific Outbox
Recipient download and access capability

The sender-side flow above is only half of file communication. The recipient obtains the file_id through conversation synchronization.

The approved access model is:

Recipient Client
       │
       │ receives conversation item
       ▼
file_id
       │
       ▼
Request file access
       │
       ▼
Short-lived signed capability
       │
       ├── bound to authenticated user
       ├── bound to device
       └── bound to specific file_id

Then:

Recipient Client
       │
       │ valid file-access capability
       ▼
Gateway
       ▼
Files Service
       │
       │ validates capability
       ▼
Encrypted file ciphertext
       │
       ▼
Recipient Client
       │
       │ decrypt locally
       ▼
Plaintext available only at endpoint

The important security property is that authorization is file-specific and short-lived, rather than giving a recipient a broad, permanent credential for arbitrary file access.

Why the file must be uploaded before Messaging accepts the reference

We want to avoid this invalid state:

Conversation contains:

file_id = ABC123

             ↓

But the encrypted file does not exist

Therefore the sequence is deliberately:

1. Encrypt file locally
        ↓
2. Upload ciphertext to Files
        ↓
3. Files durably accepts the file
        ↓
4. file_id becomes available
        ↓
5. Messaging accepts conversation item referencing file_id

This gives Messaging a reference to an already-established Files resource.

Files ↔ Messaging clarification

There is deliberately no direct synchronous Files → Messaging call in the normal flow.

The client coordinates the two user-facing operations:

Client
  │
  ├── Files Service
  │       ↓
  │    obtain file_id
  │
  └── Messaging Service
          ↓
     submit file_id reference

This keeps service ownership clean.

The backend services communicate only where required by explicit runtime contracts; neither service accesses the other's database.

Audit behavior

As with Messaging, Audit receives significant application events, not infrastructure telemetry.

The Files Outbox exists because a successful durable Files operation must not permanently lose a required application event because publication failed immediately afterward.

Conceptually:

Files durable state
       +
Files Outbox event
       ↓
PostgreSQL transaction commits
       ↓
Asynchronous publisher
       ↓
Audit Service

The client does not wait for Audit before considering the file upload operation successful.