# ADR-008 — Security & Cryptographic Architecture

**Status:** Approved
**Date:** 2026-09-02
**Decision scope:** Runtime services, client endpoints, service-to-service authentication, end-to-end messaging, files, multi-device security, emergency communication

---

## 1. Context

SecureCloud is designed for communication in critical environments where compromise of infrastructure, individual services, network traffic, or administrators must not result in disclosure of message or file contents.

The architecture established by ADR-001 through ADR-007 already provides:

* five independently deployable runtime services;
* distributed-first network communication;
* strict service data ownership;
* encrypted message persistence;
* durable offline delivery;
* multi-device delivery;
* no direct cross-service database access;
* service compromise containment;
* no administrator decryption capability.

ADR-008 establishes the cryptographic architecture that protects the confidentiality, authenticity, integrity, and forward secrecy of communications.

The architecture must distinguish two fundamentally different security domains:

1. **Service identity** — authenticating infrastructure components to one another.
2. **Device cryptographic identity** — authenticating and encrypting communication between users/devices.

These identities must never be conflated.

---

# 2. Decision

SecureCloud adopts a **two-plane cryptographic architecture**:

```text
                    SECURECLOUD
                         │
          ┌──────────────┴──────────────┐
          │                             │
          ▼                             ▼
   SERVICE IDENTITY              DEVICE IDENTITY
          │                             │
        mTLS                    E2E messaging protocol
          │                             │
   Gateway/Auth/etc.             User/device keys
          │                             │
          ▼                             ▼
  Service authentication       Message/file encryption
```

## 2.1 Service-to-service authentication

All internal service-to-service communication uses:

**mTLS + unique per-service cryptographic identities + private SecureCloud CA.**

Each runtime service receives its own identity:

```text
gateway
auth
messaging
files
audit
```

Each identity has its own private key and certificate.

Services never share private keys.

mTLS provides mutual authentication:

```text
Messaging ───────────────► Auth
          TLS handshake
          + client certificate
          + server certificate

Messaging verifies Auth
Auth verifies Messaging
```

Authentication and authorization remain separate.

mTLS establishes:

> "This is the legitimate Messaging service."

Application-level authorization establishes:

> "Messaging is allowed to perform this operation."

No long-lived shared service secret is used as the primary service identity mechanism.

---

# 3. Cryptographic library and protocol principle

SecureCloud will **not implement a new cryptographic protocol**.

Cryptographic protocol design is considered security-critical infrastructure and must rely on established, externally reviewed specifications and implementations wherever practical.

For end-to-end messaging, SecureCloud adopts the **Signal Protocol family of designs**, with the concrete protocol profile based on:

* asynchronous initial key agreement;
* PQXDH where supported by the selected implementation;
* Double Ratchet for ongoing 1:1 sessions;
* multi-device session management following the same architectural principles as Sesame;
* authenticated encryption;
* explicit identity verification and key-change detection.

Signal's specifications define PQXDH for asynchronous key agreement and Double Ratchet for deriving fresh message keys and providing forward-secrecy properties.

The project must use a vetted implementation/library rather than reimplementing these protocols from primitives.

If the selected implementation cannot provide a required protocol capability, that capability must not be replaced with an ad-hoc cryptographic construction.

---

# 4. Device cryptographic identity

Every physical device is treated as a separate cryptographic endpoint.

A logical user therefore has:

```text
User A
 ├── Device A1
 │    └── cryptographic identity
 │
 ├── Device A2
 │    └── cryptographic identity
 │
 └── Device A3
      └── cryptographic identity
```

The server does not possess device private keys.

Device private keys remain exclusively under endpoint control.

The backend stores only the public material required for asynchronous session establishment and device discovery.

---

# 5. Separation between authentication and cryptographic identity

A user's SecureCloud account authentication and cryptographic identity are separate concepts.

```text
Account authentication
        │
        ▼
"Is this user allowed to access SecureCloud?"
        │
        │
        ▼
Device cryptographic identity
        │
        ▼
"Which cryptographic endpoint is participating?"
```

Authentication credentials must never be used directly as message-encryption keys.

Compromise of an authentication credential must therefore not automatically expose historical encrypted messages.

Likewise, compromise of a messaging session must not provide the user's account password or authentication credential.

---

# 6. Public-key directory

The Auth service owns the authenticated directory of user/device cryptographic public material.

This does **not** make Auth a decryption service.

The directory may contain:

* opaque user identifier;
* opaque device identifier;
* device identity public key;
* signed prekey;
* prekey signature;
* one-time prekeys;
* key version/state;
* device status;
* revocation state.

The directory contains **public cryptographic material only**.

Private keys never enter the service boundary.

The architecture follows the asynchronous model where an offline recipient can publish public key material to a server and another device can use that material to establish an encrypted session.

---

# 7. Human identity confidentiality

Services other than the authentication boundary must not receive unnecessary human identity information.

Internal communication uses opaque identifiers:

```text
user_id       = opaque identifier
device_id     = opaque identifier
message_id    = opaque identifier
file_id       = opaque identifier
```

Human-readable identity information is not propagated through Messaging, Files, or Audit unless explicitly required by a future architectural decision.

Messaging therefore operates primarily on:

```text
opaque_user_id
opaque_device_id
message_id
ciphertext
delivery_state
```

rather than names, email addresses, phone numbers, or other human identifiers.

---

# 8. Initial session establishment

For 1:1 asynchronous messaging, the initiating device retrieves the recipient device's public prekey material through the backend.

Conceptually:

```text
Alice Device
     │
     │ request Bob's public prekey bundle
     ▼
  Gateway
     │
     ▼
   Auth
     │
     │ public cryptographic material
     ▼
  Gateway
     │
     ▼
Alice Device
```

The backend can transport the public key material but cannot calculate the resulting private session state.

The initiating device then establishes the encrypted session using the selected secure-messaging protocol.

Bob does not need to be online at the moment Alice initiates the conversation.

This asynchronous property is essential to SecureCloud's offline-messaging requirement.

---

# 9. Forward secrecy

SecureCloud requires forward secrecy for message sessions.

The ongoing 1:1 session uses a ratcheting mechanism in which message keys are continuously advanced.

Conceptually:

```text
Root Key
   │
   ├── Chain Key
   │      │
   │      ├── Message Key 1 → delete
   │      ├── Message Key 2 → delete
   │      ├── Message Key 3 → delete
   │      └── ...
   │
   └── new DH contribution
          │
          ▼
      new Root Key
```

The Double Ratchet specification explicitly derives new message keys as messages are processed and combines symmetric-key and DH ratchets to protect past and future messages against certain key-compromise scenarios.

Old message keys must be deleted as soon as operationally possible.

SecureCloud must not maintain a permanent archive of historical session/message keys.

---

# 10. Post-quantum security

SecureCloud adopts a **hybrid post-quantum strategy** rather than inventing a custom construction.

The initial architecture uses PQXDH-compatible key establishment where the selected implementation supports it.

For the ongoing ratchet, the project will prefer a vetted hybrid construction when supported by the selected implementation.

The current Signal specifications describe PQXDH and a hybrid Triple Ratchet combining an elliptic-curve Double Ratchet with a sparse post-quantum ratchet.

The design goal is:

```text
classical security
        +
post-quantum security
        ↓
hybrid protection
```

An attacker should not be able to compromise the resulting session merely by breaking one of the two cryptographic assumptions.

The exact supported protocol profile must follow the capabilities of the selected vetted implementation rather than a SecureCloud-specific cryptographic invention.

---

# 11. Authenticated encryption

Message plaintext is encrypted using authenticated encryption.

The cryptographic construction must provide:

* confidentiality;
* ciphertext integrity;
* authentication of associated data;
* nonce safety;
* resistance to ciphertext modification.

The application must never reuse an AEAD nonce with the same encryption key.

The selected secure-messaging implementation is responsible for protocol-level key/nonce management.

SecureCloud application code must not manually construct message encryption using raw AES/ChaCha primitives.

---

# 12. Message authentication and tamper detection

A message must be cryptographically authenticated.

Modification of:

* ciphertext;
* authenticated metadata;
* protocol headers;
* cryptographic session information;

must cause verification failure.

A failed authentication must result in rejection of the message.

The system must never attempt to "best effort" decrypt an unauthenticated ciphertext.

---

# 13. Replay protection

SecureCloud must prevent attackers from successfully replaying previously accepted encrypted messages.

Replay protection exists at two complementary levels:

### Cryptographic layer

The secure messaging protocol maintains ratchet/session state and message counters.

### Application layer

Every message also has a globally unique:

```text
message_id
```

and the Messaging service maintains the necessary idempotency/delivery state established by ADR-007.

Therefore:

```text
same network request
        ↓
same message_id
        ↓
duplicate detected
        ↓
existing result returned
```

A duplicate delivery must not create a second logical message.

---

# 14. Multi-device encryption

Each recipient device is an independent cryptographic destination.

Suppose Bob has:

```text
Bob Device 1
Bob Device 2
Bob Device 3
```

Alice's message must be encrypted such that each authorized device can independently decrypt its copy.

Conceptually:

```text
                    Message
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Session 1    Session 2    Session 3
          │            │            │
          ▼            ▼            ▼
      Device B1    Device B2    Device B3
```

The Messaging service stores encrypted delivery material but cannot derive plaintext.

This integrates directly with ADR-007's recipient-device delivery model.

---

# 15. Device onboarding

A newly added device receives its own cryptographic identity.

It does not inherit the private key of another device through the backend.

Preferred onboarding model:

```text
Existing trusted device
          │
          │ authenticated device pairing
          ▼
     New device
          │
          ▼
New cryptographic identity
```

The backend records the new device's public cryptographic material.

Private cryptographic material remains endpoint-controlled.

A new device is therefore treated as a new cryptographic endpoint rather than simply another login session.

---

# 16. Device revocation

Device revocation is enforced at the cryptographic and delivery layers.

When a device is revoked:

```text
Revoked Device
      │
      ├── existing encrypted messages
      │        ↓
      │   may remain decryptable
      │
      └── future messages
               ↓
        must not be encrypted
        for the revoked device
```

This follows the decision already established in the trust model and ADR-007.

Revocation therefore does not magically erase ciphertext that the device already possesses.

The security objective is to prevent future access, not retroactively destroy information already delivered to the device.

---

# 17. Key rotation

Long-lived cryptographic material must have a defined lifecycle.

The system supports rotation of:

* device identity-related public material;
* signed prekeys;
* one-time prekeys;
* session/ratchet keys;
* service certificates.

Rotating public/prekey material must not require access to historical private keys by backend services.

Service certificate rotation is independent from device cryptographic-key rotation.

---

# 18. Identity verification

The backend's public-key directory is not considered sufficient by itself for high-assurance identity verification.

A malicious or compromised key-directory component could otherwise attempt to substitute public keys before a device has established trust.

SecureCloud therefore supports explicit device identity verification.

Conceptually:

```text
Alice Device                    Bob Device
     │                              │
     │   identity fingerprint       │
     ├─────────────────────────────►│
     │                              │
     │◄─────────────────────────────┤
     │                              │
     └──── verified / trusted ──────┘
```

The client must detect unexpected identity-key changes and warn the user.

For high-risk deployments, explicit out-of-band verification should be supported.

Key transparency is not required for the initial MVP architecture but remains a possible future strengthening mechanism.

---

# 19. Group messaging

Group communication must preserve the same fundamental security model:

* backend never receives plaintext;
* backend never receives group encryption private keys;
* membership changes affect cryptographic authorization;
* removed members must not receive future group messages.

For group messaging, SecureCloud will use a **vetted group-messaging construction** compatible with the selected secure-messaging implementation rather than creating a custom group encryption protocol.

The group cryptographic state must be rotated when membership changes require it.

The Messaging service remains responsible for encrypted message routing and durable delivery, not group plaintext processing.

---

# 20. File encryption

Files follow the same end-to-end confidentiality principle as messages.

The file itself is encrypted on the client before upload.

Conceptually:

```text
Client
  │
  │ plaintext file
  ▼
Generate random file encryption key
  │
  ▼
Encrypt file
  │
  │ ciphertext
  ▼
Files service
  │
  ▼
MinIO
```

The Files service receives:

```text
encrypted content
encrypted file metadata where applicable
opaque identifiers
transfer state
```

It does not receive the plaintext file encryption key.

The file encryption key is distributed only to authorized recipient devices through the secure cryptographic mechanism.

---

# 21. Location sharing

Location data is treated as sensitive application data.

Location is not sent in plaintext to the backend merely because the backend routes the message.

For Emergency Unit communication:

```text
User Device
     │
     │ encrypted location payload
     ▼
SecureCloud backend
     │
     │ ciphertext only
     ▼
Emergency Unit Device
```

The backend may route and audit the operation according to the existing system policy, but cannot decrypt the location payload.

Emergency Unit remains a normal authorized user/device role and does not receive a cryptographic backdoor.

---

# 22. Emergency communications

Emergency messages use the same fundamental cryptographic architecture as ordinary messages.

There is **no emergency decryption key**.

There is:

```text
normal E2E encryption
        +
priority
        +
delivery acknowledgement
        +
retry/escalation
```

Emergency status affects:

* delivery priority;
* operational handling;
* acknowledgement;
* retry;
* escalation.

It does not weaken:

* E2E encryption;
* key ownership;
* device authentication;
* administrator restrictions.

---

# 23. Administrator capabilities

Administrators have no exceptional cryptographic privilege.

Administrators cannot:

* decrypt messages;
* decrypt files;
* obtain device private keys;
* obtain historical message keys;
* force a server-side plaintext recovery;
* bypass E2E encryption;
* create an emergency decryption session.

Administrative authority and cryptographic authority are deliberately separated.

```text
Administrator
      │
      ├── manage infrastructure      ✓
      ├── manage users/devices        ✓
      ├── revoke devices              ✓
      ├── inspect operational audit   ✓
      │
      └── decrypt messages            ✗
```

---

# 24. Service compromise model

A compromised service must not automatically compromise all cryptographic domains.

### Compromised Gateway

Potential impact:

* traffic manipulation;
* request interception;
* denial of service;
* metadata exposure within its visibility.

It cannot decrypt E2E message contents.

### Compromised Messaging

Potential impact:

* ciphertext manipulation;
* delivery manipulation;
* denial of service;
* metadata exposure;
* replay attempts.

It cannot derive message plaintext from stored ciphertext.

### Compromised Files

Potential impact:

* encrypted file deletion;
* transfer manipulation;
* ciphertext exposure.

It cannot decrypt stored files.

### Compromised Audit

Potential impact:

* audit metadata exposure/manipulation.

It cannot decrypt messages.

### Compromised Auth

This is especially sensitive because Auth controls the public cryptographic directory.

A compromise could potentially affect future key-distribution decisions.

However, Auth still does not possess device private keys or historical message keys.

Identity verification and key-change detection are therefore essential defenses.

---

# 25. Metadata protection

SecureCloud distinguishes:

### Hard confidentiality requirements

* message plaintext;
* file plaintext;
* device private keys;
* cryptographic session secrets;
* human identity where not operationally required.

### Metadata optimization goals

* exact message size;
* communication frequency;
* communication timing;
* traffic patterns.

The MVP therefore does not claim complete metadata anonymity.

However, the system should minimize metadata wherever practical.

Identifiers must be opaque and non-semantic.

Timestamp-bearing identifiers such as timestamp-derived sequential IDs must not be used where they unnecessarily expose timing information.

---

# 26. Message-size protection

SecureCloud should attempt to reduce exposure of exact plaintext message size.

Messages are therefore represented using a padding strategy before transport/storage.

The initial implementation should use fixed-size padding blocks rather than exposing exact plaintext length.

The exact padding configuration must be benchmarked against the project's throughput and storage requirements.

Padding is a metadata-protection optimization, not a replacement for encryption.

---

# 27. Key material storage on endpoints

Private cryptographic material must remain endpoint-controlled.

The client should use the platform's secure credential/key-storage facilities where available.

Conceptually:

```text
Qt Client
   │
   ├── application state
   │
   └── secure key storage
           │
           └── device private keys
```

Private keys must not be stored in plaintext configuration files, logs, databases, or source-controlled files.

Backend services must never persist endpoint private keys.

---

# 28. Logging restrictions

No service may log:

* message plaintext;
* file plaintext;
* private keys;
* session secrets;
* message encryption keys;
* authentication secrets;
* raw cryptographic key material.

Logs must use:

* opaque identifiers;
* operation IDs;
* error classifications;
* security event identifiers;
* non-sensitive metadata.

Debug logging must not provide a mechanism for accidentally bypassing the cryptographic boundary.

---

# 29. Cryptographic randomness

All security-sensitive random values must come from a cryptographically secure operating-system/library random source.

This applies to:

* key generation;
* nonces where applicable;
* identifiers when cryptographically random;
* prekeys;
* file encryption keys;
* session material.

Application-level pseudo-random generators must never be used for cryptographic secrets.

---

# 30. Cryptographic failure behavior

Cryptographic verification failure is a security failure.

The client/service must:

1. reject the invalid data;
2. avoid plaintext processing;
3. avoid silently retrying with weaker security;
4. produce a safe diagnostic/security event;
5. avoid exposing secret material in the error.

There is no:

```text
"decrypt normally, then try another algorithm"
```

fallback.

Cryptographic downgrade is prohibited.

---

# 31. Protocol versioning and algorithm agility

Cryptographic protocols must be explicitly versioned.

A message/session must identify enough protocol information for the recipient to determine how it should be processed.

However, algorithm agility must not become arbitrary downgrade capability.

Supported algorithms/protocol versions are explicitly configured and negotiated.

Unknown or deprecated insecure protocol versions must be rejected.

---

# 32. Service PKI lifecycle

The internal service PKI follows:

```text
Private CA
   │
   ├── Gateway certificate
   ├── Auth certificate
   ├── Messaging certificate
   ├── Files certificate
   └── Audit certificate
```

Certificates must be:

* service-specific;
* short-lived where practical;
* rotated automatically;
* validated during every mTLS connection;
* rejected when expired or invalid.

Service PKI and device E2E cryptographic keys remain independent.

Compromise of the service CA does not provide access to endpoint private keys.

---

# 33. Security boundaries

The final cryptographic trust model is:

```text
┌───────────────────────────────────────────────────┐
│                    ENDPOINT                        │
│                                                   │
│  plaintext                                        │
│  device private keys                              │
│  session state                                    │
│  message keys                                     │
│  file encryption keys                             │
│                                                   │
└───────────────────────┬───────────────────────────┘
                        │
                     E2E crypto
                        │
                        ▼
┌───────────────────────────────────────────────────┐
│                  SECURECLOUD                      │
│                                                   │
│  Gateway      → routing                           │
│  Auth         → authentication + public keys      │
│  Messaging    → ciphertext + delivery             │
│  Files        → encrypted files                   │
│  Audit        → security/operational metadata     │
│                                                   │
│  NO endpoint private keys                         │
│  NO message plaintext                             │
│  NO file plaintext                                │
└───────────────────────────────────────────────────┘
```

---

# 34. Consequences

## Positive consequences

### Strong confidentiality

A compromised backend service cannot directly decrypt stored messages or files.

### Forward secrecy

Compromise of current session material does not automatically expose all historical messages.

### Offline compatibility

Recipients can remain offline while senders establish sessions using published public key material.

### Multi-device support

Each physical device receives its own cryptographic identity.

### Service containment

Infrastructure authentication is separated from message cryptography.

### No administrator backdoor

Operational control does not become cryptographic decryption authority.

### Future post-quantum evolution

The architecture can adopt hybrid post-quantum ratcheting without redesigning the service boundaries.

---

## Negative consequences

### Cryptographic complexity

Secure messaging protocols are substantially more complex than basic public-key encryption.

### Key lifecycle complexity

Device registration, revocation, rotation, recovery and multi-device synchronization require careful implementation.

### Operational PKI complexity

mTLS introduces certificate issuance, rotation, validation and CA lifecycle management.

### Metadata remains partially visible

Encryption does not automatically hide all traffic patterns, timing, routing or sizes.

### Endpoint compromise remains critical

If an endpoint is compromised while plaintext is accessible, E2E encryption cannot protect plaintext already exposed on that endpoint.

### Protocol-library dependency

SecureCloud becomes dependent on a vetted cryptographic implementation rather than owning the entire cryptographic stack.

This is considered a benefit for security despite the dependency.

---

# 35. Security invariants

The following invariants are mandatory:

1. **Private device keys never leave endpoints.**
2. **Message plaintext never enters backend services.**
3. **File plaintext never enters the Files service.**
4. **Service private keys are never shared between services.**
5. **Service authentication and device cryptographic identity are separate.**
6. **Administrators cannot decrypt user content.**
7. **Revoked devices receive no future encrypted messages.**
8. **Historical messages already delivered to a device are not assumed recoverable/revocable.**
9. **Cryptographic verification failures are fatal for the affected operation.**
10. **No insecure cryptographic downgrade is permitted.**
11. **No custom secure-messaging protocol is implemented when an appropriate vetted protocol/library exists.**
12. **No cryptographic secret may appear in logs.**

---

# 36. Testing requirements

ADR-008 requires security testing covering at least:

### Service identity

* invalid certificate;
* expired certificate;
* wrong service identity;
* unknown CA;
* revoked certificate;
* certificate rotation;
* unauthorized RPC.

### Messaging

* modified ciphertext;
* modified authenticated metadata;
* replay;
* duplicate delivery;
* out-of-order delivery;
* lost message;
* lost acknowledgement;
* invalid session state;
* invalid key material.

### Device lifecycle

* new device;
* device revocation;
* revoked device attempting future delivery;
* key rotation;
* unexpected identity-key change;
* multi-device session establishment.

### Backend compromise

Test that compromising:

* Gateway;
* Messaging;
* Files;
* Audit;
* Auth;

does not directly provide endpoint private keys or message plaintext.

### Key protection

Tests must verify that:

* private keys are not written to service databases;
* private keys are not logged;
* private keys are not transmitted through service APIs;
* cryptographic secrets are not included in audit events.

---

# 37. Implementation boundary

ADR-008 establishes the architectural decision.

Detailed implementation specifications will subsequently define:

* exact secure-messaging library/version;
* exact protocol profile supported by that library;
* key bundle formats;
* message envelope format;
* device registration API;
* identity verification UX;
* key rotation schedules;
* certificate issuance mechanism;
* endpoint key-store integration;
* file encryption envelope;
* padding configuration;
* cryptographic test vectors.

These are implementation/design specifications, not additional core ADRs unless they require changing an architectural decision made here.

---

# 38. Final decision summary

| Area                               | Decision                                                               |
| ---------------------------------- | ---------------------------------------------------------------------- |
| Service authentication             | mTLS                                                                   |
| Service identity                   | Unique identity per service                                            |
| Service PKI                        | Private SecureCloud CA                                                 |
| Service authorization              | Explicit application-level authorization                               |
| Device identity                    | Unique cryptographic identity per device                               |
| Device private keys                | Endpoint only                                                          |
| E2E messaging                      | Vetted Signal Protocol-family implementation                           |
| Initial asynchronous key agreement | PQXDH-compatible profile where supported                               |
| Session ratchet                    | Double Ratchet / vetted post-quantum hybrid where supported            |
| Forward secrecy                    | Required                                                               |
| Message authentication             | Authenticated encryption + protocol authentication                     |
| Replay protection                  | Protocol state + message idempotency                                   |
| Multi-device                       | Device-specific cryptographic sessions                                 |
| Device revocation                  | No future delivery; previously received ciphertext remains decryptable |
| Group messaging                    | Vetted group-messaging construction                                    |
| File encryption                    | Client-side E2E encryption                                             |
| Location sharing                   | E2E encrypted                                                          |
| Emergency encryption               | Same E2E model; no emergency backdoor                                  |
| Administrator decryption           | Prohibited                                                             |
| Backend plaintext                  | Prohibited                                                             |
| Key directory                      | Auth-owned public cryptographic directory                              |
| Identity verification              | Key-change detection + explicit verification                           |
| Metadata                           | Minimized; not fully anonymous                                         |
| Message-size protection            | Padding                                                                |
| Secret logging                     | Prohibited                                                             |
| Custom crypto protocol             | Prohibited                                                             |
| Algorithm downgrade                | Prohibited                                                             |

---

## Architectural principle

> **SecureCloud infrastructure may authenticate, authorize, route, persist, deliver, and audit encrypted data — but it never becomes the cryptographic owner of user content.**

The endpoint owns the plaintext and private cryptographic state.

The backend owns the infrastructure required to transport and durably store ciphertext.

That separation is the central security invariant of SecureCloud.
