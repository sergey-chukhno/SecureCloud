SecureCloud Client UML Class Diagram — Explanatory Notes
1. Purpose

The SecureCloud Client is a native C++20 / Qt 6 application and a security-critical trusted endpoint.

Unlike the backend architecture, its internal components are not independent runtime services.

The client uses:

UI
 │
 ▼
Application
Managers / Use Cases
 │
 ▼
Domain
 │
 ▼
Infrastructure
 ├── Gateway
 ├── SQLite
 ├── Crypto
 ├── Secure Key Storage
 ├── Encrypted File Storage
 └── Platform APIs

The Client UML Class Diagram documents the main implementation-level responsibilities and dependencies required by this architecture.

The most important security principle remains:

The client owns plaintext and private cryptographic state; the backend owns authoritative communication state and encrypted data.

2. UI Layer
2.1 ClientApplication

ClientApplication represents the main client application boundary.

Its responsibilities are limited to application lifecycle coordination:

startup;
initialization of major application components;
controlled shutdown.

It is not responsible for:

cryptographic operations;
SQLite queries;
HTTP implementation;
message processing rules.

Those responsibilities belong to lower layers.

2.2 View Models

The diagram represents the primary UI interaction boundaries through:

AuthenticationViewModel
ContactsViewModel
ConversationsViewModel
FilesViewModel
EmergencyViewModel

These represent the Qt/QML presentation boundary.

They:

expose observable application state;
receive user interaction;
delegate use cases to Application Managers.

For example:

ConversationsViewModel
        │
        ▼
MessagingManager

The View Model must not directly call:

SQLite
CryptoProvider
SecureKeyStore
Backend services

This preserves the approved rule that UI code does not directly control cryptographic keys, persistence, or network protocols.

3. Application Layer — Managers

The Application layer contains the seven approved client Managers:

AuthManager
ContactManager
MessagingManager
SyncManager
DeviceManager
FileManager
EmergencyManager

A Manager is an in-process application component.

It is deliberately distinguished from a backend Service.

3.1 AuthManager

AuthManager coordinates:

login;
logout;
authentication state;
credential/token handling;
session establishment through the Gateway;
authentication-related errors.

A critical architectural rule is:

Authentication state
        ≠
Cryptographic identity

Therefore:

AuthManager

does not own the private device cryptographic identity.

That responsibility belongs to:

DeviceManager
        +
CryptoManager
3.2 ContactManager

ContactManager owns the user's local contact relationship.

It coordinates:

creation/removal of contacts;
local aliases;
identity lookup;
device discovery;
public cryptographic identity information;
identity verification;
identity-change detection.

The key relationship is:

Local Contact
      │
      ▼
Opaque User ID
      │
      ▼
Auth discovery through Gateway
      │
      ├── Authorized devices
      └── Public cryptographic material

Contacts remain client-owned.

There is no Contact backend service.

3.3 MessagingManager

MessagingManager is the primary client-side communication coordinator.

It handles both conversation and message management for the MVP.

Responsibilities include:

direct conversation creation;
group conversation creation;
participant workflows;
message composition;
encryption coordination;
local encrypted persistence;
submission;
incoming message processing;
delivery state;
read state;
retry.

The diagram intentionally does not introduce:

ConversationManager

because the approved architecture explicitly states that a separate manager is unnecessary for the MVP.

3.4 SyncManager

SyncManager coordinates synchronization between:

Backend authoritative state
          │
          ▼
Client durable local state
          │
          ▼
UI representation

Its responsibilities include:

initial synchronization;
incremental synchronization;
reconnect;
synchronization after offline operation;
duplicate handling;
pending-operation reconciliation;
interrupted synchronization recovery.

SyncManager does not become a backend synchronization service.

It is purely client-side orchestration.

3.5 DeviceManager

DeviceManager coordinates the lifecycle of the current endpoint as a SecureCloud device.

Responsibilities include:

device registration;
pairing/onboarding;
authorization state;
revocation;
device-specific synchronization;
cryptographic identity lifecycle.

The diagram reflects:

User
 │
 └── 0..* Devices
          │
          └── 1 CryptoIdentity

Each device is an independent cryptographic endpoint.

This is essential for the approved multi-device model.

3.6 FileManager

FileManager coordinates the client-side lifecycle of files.

Responsibilities:

file selection;
encryption;
upload;
download;
resumable transfer;
local encrypted storage;
attachment to messages.

The critical flow is:

File plaintext
      │
      ▼
Client encryption
      │
      ▼
Encrypted file
      │
      ▼
Gateway
      │
      ▼
Files Service

The Files Service never receives plaintext.

3.7 EmergencyManager

EmergencyManager coordinates emergency workflows.

It does not introduce a separate communication architecture.

Emergency communication continues to use:

MessagingManager
        │
        ▼
Normal E2E cryptographic architecture
        │
        ▼
Messaging backend

Its responsibilities include:

emergency message creation;
priority;
acknowledgement tracking;
retry/escalation;
explicitly authorized location-sharing workflows.

The relationship:

EmergencyManager
        │
        ▼
MessagingManager

makes this reuse explicit.

4. Domain Layer

The Domain layer contains the canonical concepts approved in the Client Architecture.

It must not directly depend on:

Qt networking;
SQLite;
platform APIs;
concrete cryptographic libraries.
4.1 User → Device → CryptoIdentity

The central device relationship is:

User
 │
 └── 0..* Device
            │
            └── 1 CryptoIdentity

A logical User can therefore own multiple independent cryptographic endpoints.

For example:

Alice
 ├── Phone
 │     └── CryptoIdentity A
 │
 ├── Laptop
 │     └── CryptoIdentity B
 │
 └── Tablet
       └── CryptoIdentity C

This supports:

device-level cryptographic addressing;
device-level delivery;
independent device revocation.
4.2 Contact

A Contact represents a local client-owned relationship.

It can contain:

opaque user ID;
local alias;
verification status;
locally stored public identity information;
identity-change state.

It is intentionally distinct from User.

User
   = SecureCloud logical identity

Contact
   = this client's local relationship
     with that identity
4.3 Conversation and Participant

A Conversation represents a logical communication channel.

The relationship is:

Conversation
      │
      └── Participants
              │
              ▼
             User

Participants are logical Users rather than devices.

Therefore:

Group
 ├── Alice
 ├── Bob
 └── Charlie

remains the user-facing representation even if each participant owns multiple devices.

Devices remain relevant underneath this abstraction for:

cryptographic addressing;
delivery;
synchronization.
4.4 Message and MessageEnvelope

Message represents the logical communication item.

MessageEnvelope represents its encrypted representation.

The relationship is:

Message
    │
    └── MessageEnvelope
            │
            ├── Ciphertext
            ├── Protocol metadata
            └── Envelope version

This distinction is important because the backend handles:

MessageEnvelope

rather than plaintext message content.

4.5 DeliveryState

DeliveryState represents local delivery/read presentation state.

The approved client states include:

LOCAL_PENDING
SUBMITTING
ACCEPTED
DELIVERING
DELIVERED
READ
FAILED

The client state is not required to be identical to backend operational state.

For example:

Client state
        ≠
Messaging persistence implementation

The client translates backend communication outcomes into appropriate local state.

4.6 File and FileTransfer

These concepts are intentionally separate.

File
  │
  └── logical encrypted attachment

FileTransfer
  │
  └── operational upload/download lifecycle
      including resumable state

A file can therefore exist independently of one currently active transfer.

4.7 SyncState

SyncState represents the client's synchronization progress and connection state.

The approved state model is:

OFFLINE
   │
   ▼
CONNECTING
   │
   ▼
AUTHENTICATING
   │
   ▼
SYNCING
   │
   ▼
ONLINE

Failures return the client to an appropriate recoverable state.

4.8 PendingOperation

PendingOperation represents locally durable work that requires retry or reconciliation.

Examples include:

Message submitted
        │
        ▼
Backend accepted it
        │
        ▼
Response lost

The client cannot safely assume whether the operation succeeded.

The PendingOperation stores enough durable information to reconcile or retry using a stable idempotency identifier.

This supports the approved rule:

The client must not retry an operation blindly when its outcome is unknown.

5. Cryptographic Subsystem

The approved cryptographic structure is represented directly:

CryptoManager
 │
 ├── IdentityManager
 ├── SessionManager
 └── MessageCipher
          │
          ▼
     CryptoProvider

Private key storage is separate:

IdentityManager
        │
        ▼
SecureKeyStore
5.1 CryptoManager

CryptoManager is the main client-side cryptographic integration boundary.

Application Managers depend on this boundary rather than on a concrete cryptographic library.

It coordinates:

message encryption;
message decryption;
cryptographic initialization.
5.2 IdentityManager

IdentityManager manages:

device cryptographic identity creation;
loading;
lifecycle.

Private material remains local.

The relationship:

IdentityManager
        │
        ▼
SecureKeyStore

means that private device keys are accessed through secure platform-backed storage abstractions.

5.3 SessionManager

SessionManager manages cryptographic session state for:

remote devices;
group cryptographic state.

It depends on CryptoProvider, which encapsulates the vetted protocol implementation.

The application must not implement its own messaging encryption protocol.

5.4 MessageCipher

MessageCipher provides the application-level:

encrypt()
decrypt()

boundary.

It delegates actual protocol/library operations to CryptoProvider.

5.5 CryptoProvider

CryptoProvider is an abstraction around the selected vetted Signal Protocol-family implementation.

This preserves the rule:

Application code
      │
      ▼
Crypto abstraction
      │
      ▼
Vetted implementation

The application therefore does not directly implement:

cryptographic primitives;
key exchange protocols;
ratchet mechanisms;
group encryption algorithms.
5.6 SecureKeyStore

SecureKeyStore abstracts operating-system secure storage.

Its role is to:

store private keys;
retrieve private keys when required;
remove keys during device lifecycle operations.

The backend never receives these private keys.

6. Infrastructure Layer

The Infrastructure layer contains concrete integrations with external systems.

6.1 GatewayClient

GatewayClient is the client's sole backend networking boundary.

It provides:

HTTPS/TLS communication;
request handling;
deadlines;
cancellation;
serialization;
response parsing;
idempotency identifiers;
bounded retry behavior;
connection reuse.

The architecture is:

Client Manager
      │
      ▼
GatewayClient
      │
      │ HTTPS / TLS
      ▼
Gateway
      │
      ▼
Backend runtime services

The client does not directly connect to:

Auth Service
Messaging Service
Files Service
Audit Service

This is one of the most important architectural boundaries represented by the diagram.

6.2 LocalStateStore

LocalStateStore represents the SQLite-backed durable local application state boundary.

It persists local representations of:

Users;
Contacts;
Conversations;
Participants;
encrypted message envelopes;
delivery state;
synchronization state;
pending operations.

The diagram intentionally treats this as a persistence abstraction rather than exposing every SQLite repository implementation.

The detailed implementation can later split it into concrete repositories without changing the architectural class model.

6.3 EncryptedFileStore

EncryptedFileStore handles durable local encrypted file storage.

Its responsibilities are:

storing encrypted file data;
loading encrypted file data;
removal.

It must not intentionally persist file plaintext.

6.4 PlatformIntegration

PlatformIntegration abstracts operating-system capabilities other than secure key storage.

This keeps platform-specific code outside:

UI;
Domain;
Application use-case logic.
6.5 StructuredLogger

StructuredLogger provides infrastructure-level logging.

The local security rules apply strictly:

Never log:
    plaintext
    private keys
    authentication secrets

Sensitive values must never cross into ordinary debug or diagnostic logs.

7. Important dependency rules

The diagram enforces the following direction:

UI
 ↓
Application Managers
 ↓
Domain
 ↓
Infrastructure

With infrastructure implementing required external capabilities.

The forbidden direction is:

UI
 ├── SQLite
 ├── CryptoProvider
 ├── SecureKeyStore
 └── Backend runtime service

Likewise, domain objects should not depend directly on:

Qt Network
SQLite APIs
Operating system APIs
Concrete crypto library APIs
8. Key architectural relationships

The most important relationships shown by the Client Class Diagram are:

User
 └── Device
       └── CryptoIdentity
Conversation
 └── Participant
       └── User
Conversation
 └── Message
       └── MessageEnvelope
Message
 └── encrypted File references
MessagingManager
 ├── CryptoManager
 ├── GatewayClient
 └── LocalStateStore
FileManager
 ├── CryptoManager
 ├── GatewayClient
 └── EncryptedFileStore
ContactManager
 ├── GatewayClient
 └── CryptoManager
SyncManager
 ├── GatewayClient
 └── LocalStateStore
DeviceManager
 ├── GatewayClient
 ├── CryptoManager
 └── SecureKeyStore
9. Final architectural principle

The Client Class Diagram should be interpreted together with the previously approved Client Component Architecture.

The class diagram makes implementation responsibilities more concrete, but does not introduce new backend services, persistence ownership, or cryptographic protocols.

The final boundary remains:

┌───────────────────────────────────────────┐
│           SECURECLOUD CLIENT              │
│                                           │
│  Plaintext may exist here                 │
│  Private keys remain here                 │
│  E2E encryption/decryption happens here   │
│                                           │
└───────────────────────┬───────────────────┘
                        │
                   HTTPS / TLS
                        │
                        ▼
┌───────────────────────────────────────────┐
│                 BACKEND                   │
│                                           │
│  Gateway                                 │
│  Auth                                    │
│  Messaging → ciphertext                  │
│  Files → encrypted bytes                 │
│  Audit → application events              │
│                                           │
│  No plaintext                             │
│  No private device keys                   │
└───────────────────────────────────────────┘