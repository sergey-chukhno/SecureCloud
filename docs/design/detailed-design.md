**Document:** `detailed-design.md`
**Version:** 0.1
**Status:** Draft
**Decision Owners:** SecureCloud Architecture Team

1. Design Objectives
1.1 Purpose

This document translates the approved SecureCloud architecture and ADRs into a concrete implementation design.

It defines the internal structure, responsibilities, interfaces, state, data flows, security boundaries, persistence behavior, concurrency model, and failure handling required to implement SecureCloud without introducing architectural decisions implicitly during coding.

The document is subordinate to:

project requirements;
architectural drivers;
system-context.md;
trust-boundaries.md;
architecture-alternatives.md;
architecture.md;
ADR-001 through ADR-010.

Where an implementation detail is not explicitly covered by an ADR, this document makes the concrete engineering decision.


1.2 Design principles

The detailed design follows these rules:

1.Concrete decisions over unresolved alternatives.
Implementation-critical choices are decided here using the requirements, architectural drivers, security model, existing ADRs, and engineering judgment.
2. Security and durability take precedence over performance. Performance optimizations must not weaken E2E confidentiality, durability, correctness, or failure isolation.
3. The endpoint owns plaintext and private cryptographic state.
Backend services operate on encrypted application data and opaque identifiers.
4. Services communicate through explicit contracts.
No service accesses another service's database.
5. Durable state is authoritative.
Process-local memory is used only for bounded caching, buffering, or transient execution state.
6. Failures are explicit states.
Timeouts, retries, reconnects, duplicate requests, unavailable dependencies, and partial failures are represented by defined behavior rather than implicit assumptions.
7. The design is distributed-first.
Service correctness must not depend on services being colocated on the same machine.
8. The client is a security-critical endpoint.
UI code does not directly control cryptographic keys, persistence, or network protocols.
9. Implementation should follow vertical slices.
The design must support incremental construction and end-to-end validation rather than requiring the entire system to be implemented before it becomes testable.


1.3 Scope

This detailed design covers:

- the Qt/C++ client;
- Gateway;
- Authentication;
- Messaging;
- Files;
- Audit;
- service-to-service communication;
- client synchronization;
- cryptographic integration;
- persistence;
- failure handling;
- concurrency;
- performance-critical paths;
- security boundaries.

Infrastructure implementation details such a CI/CD internals, production deployment automation, and operational runbooks are outside the scope of this document unless they directly affect runtime behavior.

# 2. Client Architecture

## 2.1 Purpose and Design Boundary

The SecureCloud client is the trusted endpoint where message and file plaintext is handled and where device cryptographic state is maintained.

The client is a native C++/Qt application. It is not a backend microservice and its internal components must not be confused with the five backend runtime services defined by ADR-001.

The client is responsible for:

* presenting the user interface;
* maintaining the local representation of users, contacts, conversations and messages;
* authenticating the user;
* managing the local device identity and device lifecycle;
* performing end-to-end cryptographic operations;
* encrypting outgoing messages and files before persistence/transmission;
* decrypting incoming content only on the endpoint;
* maintaining durable local encrypted state;
* synchronizing local state with the backend;
* handling offline operation and reconnection;
* managing local delivery/read state;
* providing emergency communication workflows;
* interacting with the operating system for secure key storage and other platform capabilities.

The client must never rely on the backend to decrypt message or file content.

The architectural boundary is:

```text
┌──────────────────────────────────────────────┐
│                 SecureCloud Client            │
│                                              │
│  UI → Application → Domain → Infrastructure │
│                         │                    │
│                         ├── Crypto           │
│                         ├── SQLite           │
│                         ├── Gateway          │
│                         └── Platform APIs    │
└───────────────────────┬──────────────────────┘
                        │
                  HTTPS / REST
                        │
                     Gateway
                        │
              ┌─────────┼─────────┐
              │         │         │
             Auth    Messaging   Files
                        │
                       Audit
```

The client is therefore the boundary at which plaintext and private cryptographic material may exist.

---

## 2.2 Client Technology Baseline

The MVP client uses:

* **C++20**
* **Qt 6**
* **Qt Quick / QML** for the UI
* **CMake** for build configuration
* **Qt Network** for HTTPS communication
* **SQLite** for local durable application state
* **GoogleTest / Qt Test** for automated testing
* **clang-format** for formatting
* **clang-tidy** for static analysis

The cryptographic subsystem must integrate a vetted Signal Protocol-family implementation rather than implement cryptographic primitives or messaging protocols from scratch.

Platform secure-storage APIs are accessed through an abstraction so that private device keys are stored using the strongest appropriate mechanism available on the target operating system.

---

# 2.3 Client Layering

The client follows four logical layers:

```text
┌──────────────────────────────┐
│             UI               │
│          Qt / QML            │
└──────────────┬───────────────┘
               │
┌──────────────▼───────────────┐
│        Application           │
│      Managers / Use Cases    │
└──────────────┬───────────────┘
               │
┌──────────────▼───────────────┐
│           Domain             │
│  Users / Contacts / Messages │
│  Conversations / Devices     │
└──────────────┬───────────────┘
               │
┌──────────────▼───────────────┐
│       Infrastructure         │
│ Gateway / SQLite / Crypto    │
│ Secure Storage / Platform    │
└──────────────────────────────┘
```

### UI layer

Responsible only for presentation and user interaction.

It:

* displays conversations, contacts and messages;
* displays synchronization and connection state;
* collects user actions;
* exposes emergency and file-transfer workflows;
* observes application state.

The UI must not directly access SQLite, cryptographic keys, or HTTP/gRPC infrastructure.

### Application layer

The Application layer implements user-facing use cases and coordinates domain objects and infrastructure components.

Client application components are named **Managers**, deliberately distinguishing them from backend microservices.

The main managers are:

* `AuthManager`
* `ContactManager`
* `MessagingManager`
* `SyncManager`
* `DeviceManager`
* `FileManager`
* `EmergencyManager`

A Manager is an in-process application component. It is not a network service and does not own an independent backend database.

### Domain layer

The Domain layer contains the application's core communication concepts and rules.

It should not depend directly on Qt networking, SQLite, operating-system APIs, or concrete cryptographic libraries.

The canonical domain vocabulary is defined in Section 2.4.

### Infrastructure layer

The Infrastructure layer provides concrete implementations of external dependencies:

* Gateway communication;
* local SQLite persistence;
* cryptographic provider integration;
* platform secure key storage;
* encrypted local file storage;
* platform integration;
* structured logging.

Infrastructure implements interfaces required by the Application and Domain layers.

---

# 2.4 Canonical Client Domain Model

The client uses the following canonical domain model.

```text
User
 ├── Device
 │     └── CryptoIdentity
 │
 ├── Contact
 │
 └── Conversation
       ├── DIRECT
       │     └── Participants
       │
       └── GROUP
             └── Participants
                    │
                    └── Messages
                           ├── MessageEnvelope
                           └── DeliveryState
```

The concepts have distinct responsibilities.

## User

Represents a logical SecureCloud identity.

A User is identified throughout the backend by an opaque identifier.

The client may display a human-readable name or alias, but backend services must not require human identity information where the architecture does not require it.

A User may own multiple devices.

## Device

Represents one concrete endpoint belonging to a User.

A device has:

* a unique device identifier;
* its own cryptographic identity;
* device authorization/revocation state;
* local synchronization state;
* its own delivery endpoint.

A User with multiple devices therefore has multiple independent device-level cryptographic endpoints.

## CryptoIdentity

Represents the cryptographic identity associated with a device.

Private cryptographic material remains on the device.

The backend may maintain the public cryptographic directory required for identity discovery and session establishment, but never receives the corresponding private keys.

## Session

Represents cryptographic session state required for secure communication with another device or according to the selected group protocol.

Session state is maintained by the client cryptographic subsystem.

## Contact

Represents a user's local relationship/address-book entry.

A Contact may contain:

* an opaque SecureCloud user identifier;
* locally chosen display name/alias;
* local verification status;
* locally stored identity/key information;
* identity-change state.

Contacts are client-owned.

There is no backend `Contact` microservice.

Auth provides authoritative identity and device discovery.

## Conversation

Represents a logical communication channel.

A Conversation has:

* a stable conversation identifier;
* a type;
* participants;
* local synchronization state;
* messages;
* local presentation state.

Conversation types are:

```text
DIRECT
GROUP
```

A direct conversation normally contains two logical users.

A group conversation contains multiple logical users.

Conversation is a shared conceptual domain object between client and Messaging backend, but each side owns a different representation:

* the client owns its local synchronized representation;
* Messaging owns authoritative server-side conversation state.

## Participant

Represents a logical User participating in a Conversation.

A participant is normally a User, not an individual device.

For example:

```text
Conversation: Field Team

Participants:
    Alice
    Bob
    Charlie
```

If Alice has three authorized devices:

```text
Alice
 ├── Alice-phone
 ├── Alice-laptop
 └── Alice-tablet
```

Alice remains one conversation participant.

The individual devices become delivery and cryptographic targets underneath that logical participant.

This distinction is mandatory for multi-device group support.

## Message

Represents the logical communication item from the client's point of view.

A Message contains application-level information such as:

* stable `message_id`;
* conversation identifier;
* sender/participant reference;
* local state;
* timestamps where available;
* priority;
* references to its encrypted content.

The plaintext content itself must never be persisted unencrypted.

## MessageEnvelope

Represents the encrypted transport/storage representation of a message.

The envelope contains ciphertext and the cryptographic/protocol metadata required for the selected protocol implementation.

The backend stores and routes this representation.

The backend must not receive message plaintext.

## DeliveryState

Represents delivery progress for a message.

The client may track states such as:

```text
LOCAL_PENDING
SUBMITTING
ACCEPTED
DELIVERING
DELIVERED
READ
FAILED
```

Server-side delivery state and client-side presentation state are not assumed to be identical.

## File

Represents a logical file attachment.

The file is encrypted on the client before it is uploaded.

The backend receives encrypted content and associated metadata only.

## FileTransfer

Represents the state of an upload/download operation, including resumable transfer state.

## SyncState

Represents the client's synchronization state.

The canonical connection/synchronization state machine is:

```text
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
   │
   └──────────────► OFFLINE
```

Failures during connection, authentication or synchronization return the client to an appropriate recoverable state.

## PendingOperation

Represents a locally durable operation that must be retried or reconciled with the backend.

Examples include a message submission that has not yet received a definitive response.

Pending operations must be idempotent and must not cause duplicate logical messages when retried.

---

# 2.5 Client Application Managers

## AuthManager

Coordinates:

* login/logout;
* authentication credentials/tokens;
* authentication state;
* session establishment with Gateway;
* authentication-related errors.

It does not own the device's private cryptographic identity.

Authentication credentials and cryptographic identity are separate concerns.

## ContactManager

Coordinates:

* creation/removal of local contacts;
* local aliases;
* identity lookup;
* device discovery through Auth;
* cryptographic identity information;
* identity verification;
* identity-change detection.

The ContactManager does not become a backend directory.

The authoritative backend directory is owned by Auth.

## MessagingManager

Coordinates:

* conversation creation;
* direct conversations;
* group conversations;
* participant management workflows;
* message composition;
* message encryption;
* local message persistence;
* message submission;
* incoming message processing;
* delivery state;
* read state;
* message retry.

Conversation management and message management intentionally belong to the same application component for the MVP.

A separate `ConversationManager` is not required.

## SyncManager

Coordinates:

* initial synchronization;
* incremental synchronization;
* reconnect;
* pending-operation reconciliation;
* incoming message synchronization;
* conversation/participant state synchronization;
* device-state synchronization;
* local/server state reconciliation.

SyncManager is client-side orchestration.

It is not equivalent to the backend Messaging service.

## DeviceManager

Coordinates:

* current-device identity;
* device registration;
* device pairing/onboarding;
* device authorization state;
* device revocation;
* device-specific synchronization;
* local cryptographic identity lifecycle.

A revoked device must not receive future messages, while messages already received and encrypted for that device remain decryptable according to ADR-008.

## FileManager

Coordinates:

* file selection;
* local encryption;
* upload/download;
* resumable transfer;
* local encrypted file storage;
* file attachment to messages.

## EmergencyManager

Coordinates emergency workflows such as:

* emergency message creation;
* emergency priority;
* acknowledgement;
* retry/escalation state;
* location-sharing workflow where explicitly authorized.

Emergency communication uses the normal messaging and E2E cryptographic architecture.

Emergency is not a separate backend microservice.

---

# 2.6 Contacts and Identity Discovery

Contacts and identity discovery are intentionally separated.

```text
Local Contact
     │
     │ references
     ▼
Opaque User ID
     │
     │ discovery
     ▼
Auth Service
     │
     ├── User identity
     ├── Authorized devices
     └── Public cryptographic material
```

The client stores the user's local contact relationship.

Auth is the authoritative source for:

* opaque user identifiers;
* authorized device identifiers;
* public identity keys;
* signed prekeys;
* one-time prekeys;
* cryptographic key state;
* device revocation state.

Private device keys are never returned by Auth and never leave the endpoint.

Device discovery therefore means:

1. identify the target opaque User ID;
2. request the user's authorized device set from Auth;
3. obtain the required public cryptographic material;
4. verify identity/key state;
5. establish or update client-side cryptographic sessions;
6. encrypt messages for the appropriate authorized devices.

The client must detect relevant identity/key changes and expose them to the user according to the verification policy defined by ADR-008.

---

# 2.7 Multi-Device and Group Model

A logical User may have multiple participating devices.

However, group membership is modeled at the **User level**, while delivery and cryptographic addressing operate at the **Device level**.

Example:

```text
Group Conversation
│
├── Alice
│    ├── Device A1
│    ├── Device A2
│    └── Device A3
│
├── Bob
│    ├── Device B1
│    └── Device B2
│
└── Charlie
     └── Device C1
```

This model provides:

* one logical participant per User;
* multiple authorized device endpoints;
* independent device cryptographic identities;
* device-level delivery;
* correct revocation semantics;
* support for users joining the same group from multiple devices.

The Messaging backend therefore maintains:

```text
Conversation
    ├── logical participants
    ├── membership state
    └── device-level delivery targets
```

The client presents the logical participants to the user while maintaining device information where required for cryptographic and synchronization operations.

Group cryptographic state is handled by the vetted group-capable implementation selected under ADR-008.

The application must not implement its own group encryption algorithm.

When group membership changes, the cryptographic state is updated according to the selected protocol implementation.

A newly authorized device must not automatically gain access to historical group messages merely because its User already belongs to the group. Historical access requires the appropriate cryptographic state to be securely established.

---

# 2.8 Local Persistence

SQLite provides durable client-side application state.

The local database may contain:

* users and opaque identifiers;
* contacts;
* conversations;
* participants;
* encrypted message envelopes;
* delivery state;
* synchronization state;
* pending operations;
* encrypted file metadata;
* encrypted local file references.

The database must **never intentionally persist plaintext message or file content**.

The outgoing message lifecycle is:

```text
COMPOSING
    │
    ▼
ENCRYPTING
    │
    ▼
LOCAL_PERSISTENCE
    │
    ▼
SUBMITTING
    │
    ▼
ACCEPTED
```

Plaintext may exist temporarily in endpoint memory while the user is composing or while cryptographic operations are performed, but persistence occurs only after encryption.

For incoming messages:

```text
RECEIVED
    │
    ▼
PERSIST_ENCRYPTED
    │
    ▼
LOCAL_DURABLE
    │
    ▼
ACK
    │
    ▼
DECRYPT
    │
    ▼
PRESENT_TO_UI
```

The client must not acknowledge durable receipt before the encrypted message has been durably stored locally according to the delivery semantics defined by ADR-007.

---

# 2.9 Cryptographic Integration

The client contains the cryptographic integration boundary.

The logical components are:

```text
CryptoManager
 ├── IdentityManager
 ├── SessionManager
 ├── MessageCipher
 └── CryptoProvider
```

Responsibilities:

### IdentityManager

Manages the device's cryptographic identity and associated lifecycle.

### SessionManager

Manages cryptographic sessions with remote devices or group cryptographic state through the selected vetted protocol implementation.

### MessageCipher

Provides application-level encryption/decryption operations through the vetted protocol implementation.

### CryptoProvider

Abstracts the concrete cryptographic library.

Application code must not implement cryptographic primitives directly when a vetted implementation exists.

Private keys are stored through `SecureKeyStore`.

The cryptographic subsystem must fail closed on:

* invalid authentication;
* invalid signatures;
* replay;
* key mismatch;
* malformed ciphertext;
* unsupported protocol versions;
* cryptographic state corruption;
* insecure downgrade attempts.

---

# 2.10 Networking

The client communicates with the backend through the Gateway.

External client communication uses:

```text
Client
  │
  │ HTTPS / TLS
  ▼
Gateway
```

The client does not directly access Auth, Messaging, Files or Audit.

`GatewayClient` provides:

* connection management;
* HTTPS/TLS;
* authentication token handling;
* request serialization;
* response parsing;
* request deadlines;
* cancellation;
* bounded request/response sizes;
* retry behavior for explicitly retryable operations;
* idempotency identifiers;
* connection reuse.

The client must not retry an operation blindly when its outcome is unknown.

Operations that can be safely retried use stable idempotency identifiers.

---

# 2.11 Synchronization

The client maintains a durable local representation of server-authoritative state.

The general synchronization model is:

```text
Backend authoritative state
          │
          │ synchronization
          ▼
Client local state
          │
          ▼
UI representation
```

The backend is authoritative for server-owned state such as:

* conversation membership;
* server message acceptance;
* delivery state;
* device authorization/revocation;
* server-side synchronization position.

The client is authoritative for purely local state such as:

* contact aliases;
* local presentation preferences;
* local UI state;
* locally maintained verification presentation.

Synchronization must support:

* initial synchronization;
* incremental synchronization;
* offline operation;
* reconnect;
* duplicate data;
* interrupted synchronization;
* lost responses;
* pending operations;
* idempotent replay.

Synchronization must never assume continuous connectivity.

---

# 2.12 Client Concurrency Model

The UI thread is reserved for UI work.

Network, persistence, cryptographic and potentially blocking operations execute outside the UI thread.

The client uses Qt's event-driven model together with worker contexts/pools where appropriate.

Concurrency must remain bounded.

The client must not create:

* unbounded worker threads;
* unbounded message queues;
* unbounded request buffering;
* unbounded file buffering.

Large files are processed as streams/chunks rather than loading the complete encrypted or plaintext file into memory.

Cryptographic operations must be integrated without blocking the UI for unbounded periods.

---

# 2.13 Local Security Rules

The client is the highest-trust application component and therefore has the strictest local security requirements.

Mandatory rules:

1. Private cryptographic keys never leave the device.
2. Plaintext messages never enter backend APIs.
3. Plaintext messages and files are not stored persistently.
4. Sensitive key material is never written to application logs.
5. Authentication credentials are stored using appropriate secure mechanisms.
6. Platform secure storage is used for private keys where available.
7. Cryptographic failures fail closed.
8. Unsupported/insecure protocol versions are rejected.
9. No downgrade to plaintext or weaker security mode is permitted.
10. Revoked devices receive no future messages.
11. Local encrypted data remains protected when the application is offline.
12. Sensitive plaintext lifetime in memory is minimized.
13. Debug logging must not expose plaintext, private keys or authentication secrets.

---

# 2.14 Client ↔ Backend Responsibility Summary

| Concern                      | Client                    | Backend                              |
| ---------------------------- | ------------------------- | ------------------------------------ |
| Human-readable contact alias | Owns                      | —                                    |
| Opaque User ID               | Caches                    | Auth authoritative                   |
| User authentication          | Uses                      | Auth authoritative                   |
| Device identity              | Owns local private state  | Auth registers/authorizes            |
| Device public crypto data    | Caches/uses               | Auth authoritative directory         |
| Private crypto keys          | **Owns**                  | **Never stored**                     |
| Conversation UI/state        | Local representation      | Messaging authoritative              |
| Group membership             | Local synchronized copy   | Messaging authoritative              |
| Group participant            | User                      | User                                 |
| Delivery target              | Device                    | Device                               |
| Message plaintext            | **Handles**               | **Never sees**                       |
| Message ciphertext           | Stores locally            | Stores/routes                        |
| Message durability           | Local durable copy        | Messaging durable acceptance         |
| Offline queue                | Local pending operations  | Messaging authoritative queue        |
| File plaintext               | Encrypts/decrypts         | Never sees                           |
| File ciphertext              | Stores/transfers          | Files stores/transfers               |
| Audit events                 | Generates relevant events | Audit authoritative                  |
| Emergency workflow           | Presents/orchestrates     | Messaging supports priority/delivery |

The central principle is:

> **The client owns plaintext and private cryptographic state; the backend owns authoritative communication state and encrypted data.**

---

# 2.15 Implementation Constraints

The following constraints are implementation requirements derived from the approved architecture and ADRs:

* Client and backend services communicate through explicit contracts.
* Client components must not directly access backend databases.
* Client code must not contain backend service implementations.
* Client local persistence must not store plaintext message/file content.
* Device identity must remain distinct from account authentication.
* User, Device and CryptoIdentity must remain separate domain concepts.
* Conversation must remain the canonical abstraction for both direct and group communication.
* Group membership is User-level; delivery and cryptographic addressing may be Device-level.
* Contacts remain client-owned; identity/device discovery is provided by Auth.
* `MessagingManager` is a client application component and must not be confused with the backend Messaging service.
* `SyncManager` is a client application component and must not be confused with a backend synchronization microservice.
* No separate Conversation microservice or Contact microservice is introduced.
* Emergency communication reuses the normal messaging architecture.
* No custom cryptographic protocol is introduced.
* No correctness-critical behavior depends on process-local memory.
* Network communication remains the canonical distributed architecture.
* Local IPC/shared memory is not required for correctness.
* All persistent sensitive state must have explicit ownership and protection rules.
