# SecureCloud — Trust Boundaries

**Document:** `trust-boundaries.md`
**Version:** 0.2
**Status:** Approved
**Related documents:**

* `architectural-drivers.md`
* `system-context.md`

---

# 1. Purpose

This document defines the trust boundaries of SecureCloud.

Its purpose is to establish:

* which components and actors are trusted;
* which components are only partially trusted;
* which information each component may access;
* which information must remain inaccessible;
* what information may cross each trust boundary;
* what happens if a component or actor is compromised;
* how trust is separated between users, backend services, infrastructure, administrators, and external environments.

This document is intentionally independent of specific cryptographic protocols and implementation technologies.

The trust model established here constrains:

* architecture alternatives;
* security architecture;
* cryptographic architecture;
* messaging architecture;
* file architecture;
* authentication architecture;
* key-management architecture;
* audit architecture;
* future ADRs.

---

# 2. Core Trust Principles

## TB-01 — End-to-End Content Confidentiality

Message plaintext must be accessible only to authorized endpoints.

The backend must not require access to message plaintext for:

* transport;
* routing;
* durable storage;
* offline delivery;
* synchronization.

The same principle applies to file plaintext.

---

## TB-02 — Backend Must Not Know Human Communication Identities

SecureCloud has a hard confidentiality requirement concerning the human identities of communication participants.

Backend services must therefore operate using **opaque identifiers** wherever possible.

The architecture must prevent backend services from learning:

> "Sergey is communicating with Alice."

while still allowing them to perform:

> "opaque endpoint A → opaque endpoint B."

The mapping between opaque identifiers and human identities must therefore be carefully isolated.

This is a **hard architectural requirement**, not merely an optimization.

---

## TB-03 — Metadata Minimization

SecureCloud distinguishes between information that must be strongly protected and information whose exposure should instead be minimized.

### Hard confidentiality requirements

* human sender identity;
* human recipient identity.

### Metadata minimization / optimization goals

* message timestamp;
* message size;
* communication frequency;
* traffic patterns.

The architecture should reduce unnecessary metadata exposure without allowing metadata protection goals to compromise the primary security and availability requirements.

---

## TB-04 — Message Size Protection

Although message size is categorized as an optimization goal rather than a hard confidentiality requirement, SecureCloud should actively attempt to hide or normalize message sizes.

The architecture should investigate mechanisms such as:

* padding;
* size buckets;
* fixed-size envelopes;
* batching;
* other appropriate techniques.

The exact mechanism belongs to the messaging/cryptographic architecture.

Performance and storage costs must be evaluated explicitly.

---

## TB-05 — Least Privilege

Every component should receive only the information and authority required for its responsibility.

Being part of the SecureCloud backend does not imply unrestricted access to other services' information.

---

## TB-06 — Compartmentalization

A compromise of one component must not automatically compromise:

* all messages;
* all files;
* all users;
* all devices;
* all cryptographic identities;
* all audit information.

The architecture should minimize the blast radius of individual compromises.

---

## TB-07 — Containment Over Propagation

If a backend service becomes compromised, the architecture should prioritize **containment**.

A compromised service should not automatically be able to:

* impersonate unrelated services;
* access unrelated data;
* obtain unrestricted credentials;
* access private cryptographic material;
* move laterally through the infrastructure.

The system should prefer isolating a compromised component even if doing so temporarily reduces functionality or availability.

---

## TB-08 — Authentication Is Not Cryptographic Identity

Authentication and cryptographic identity represent different trust domains.

Authentication establishes that an entity is authorized to access a SecureCloud account or service.

Cryptographic identity establishes the identity associated with cryptographic operations and protected communication.

Compromise of authentication infrastructure must not automatically provide:

* private cryptographic keys;
* message plaintext;
* file plaintext;
* historical message decryption capability.

The exact mechanism is deferred to the security and cryptographic architectures.

---

## TB-09 — Administrative Authority Does Not Imply Content Access

The Application Administrator has significant operational authority.

However, administrative authority must not automatically grant access to:

* message plaintext;
* file plaintext;
* private cryptographic keys.

There is **no administrator emergency backdoor**.

This remains true even during a critical operational incident.

---

## TB-10 — Device-Specific Trust

A user may have multiple authorized devices.

Each device represents an independent cryptographic and trust principal.

Compromise or revocation of one device must not automatically compromise every other device belonging to the same user.

---

## TB-11 — Persistent Storage Is Not a Decryption Authority

Persistent storage may contain highly sensitive encrypted information.

Possession of database/storage access must not automatically provide the ability to decrypt:

* messages;
* files;
* private cryptographic identities.

---

# 3. Trust Zones

SecureCloud is divided into the following conceptual trust zones.

| Zone                         | Description                                                   | Trust Model                              |
| ---------------------------- | ------------------------------------------------------------- | ---------------------------------------- |
| Z1 — User Device             | Authorized endpoint controlled by a user                      | Trusted endpoint, but compromiseable     |
| Z2 — SecureCloud Backend     | Five backend microservices                                    | Limited and compartmentalized trust      |
| Z3 — Persistent Storage      | Databases and durable storage                                 | Limited trust                            |
| Z4 — Administration          | Application administration and operations                     | Highly privileged but content-restricted |
| Z5 — Network / Transport     | Internet, cellular, Wi-Fi, mesh, satellite, tactical networks | Untrusted                                |
| Z6 — Emergency Unit          | Normal user with emergency operational role                   | Trusted according to authorization       |
| Z7 — External Environment    | GPS/positioning and other external infrastructure             | External / limited trust                 |
| Z8 — Adversarial Environment | Attackers and hostile infrastructure                          | Untrusted                                |

These zones are logical trust boundaries.

They do not necessarily correspond to individual machines, containers, processes, or physical networks.

---

# 4. User Device Boundary

The user device is the primary location where protected content becomes plaintext.

For example:

```text
Alice's Device
      |
      | plaintext
      ↓
Alice
```

and:

```text
Bob's Device
      |
      | plaintext
      ↓
Bob
```

Backend services should instead see protected representations.

---

## 4.1 Device may access

A device may access:

* the user's message plaintext;
* authorized file plaintext;
* device-specific private cryptographic material;
* device cryptographic identity;
* local encrypted state;
* local encrypted outbox;
* synchronization information.

---

## 4.2 Device compromise

A device must be considered potentially compromiseable.

If an attacker obtains control of a device, the attacker may potentially access information available to that device.

The architecture must therefore distinguish:

```text
User identity
```

from:

```text
Device identity
```

A compromised device must not automatically imply compromise of all other devices belonging to the same user.

---

# 5. Backend Boundary

SecureCloud consists of five backend microservices:

1. Gateway
2. Auth
3. Messaging
4. Files
5. Audit

These services do **not** form one unrestricted trust domain.

Each service has a specific responsibility and information boundary.

---

# 6. Gateway Trust Boundary

## Responsibility

Gateway provides the external entry point into SecureCloud.

It may handle:

* network connections;
* transport-level protection;
* request routing;
* session/connection management;
* forwarding of requests.

## Restrictions

Gateway must not require:

* message plaintext;
* file plaintext;
* user private cryptographic keys;
* human sender identity;
* human recipient identity.

Gateway may process opaque routing identifiers.

The exact mechanism for generating, resolving, and protecting those identifiers belongs to later architecture work.

---

# 7. Authentication Service Trust Boundary

## Responsibility

Auth manages authentication and authorization.

It may handle:

* authentication;
* authorization;
* account state;
* authentication credentials;
* session/access state;
* device registration;
* device authorization;
* device revocation.

## Restrictions

Auth must not automatically receive:

* message plaintext;
* file plaintext;
* user private cryptographic keys;
* the plaintext mapping between communication participants.

Auth's knowledge of human identity is limited to what is necessary for authentication/account management.

Authentication must not provide a direct path to end-to-end content decryption.

---

# 8. Messaging Service Trust Boundary

## Responsibility

Messaging is responsible for:

* receiving protected messages;
* routing messages;
* durable message storage;
* offline delivery;
* delivery state;
* retries;
* synchronization.

## Information available to Messaging

Messaging may process:

* encrypted message payloads;
* opaque sender identifiers;
* opaque recipient identifiers;
* opaque device identifiers;
* delivery state;
* synchronization information;
* timestamp information required by the architecture.

Messaging must not require:

* message plaintext;
* user private cryptographic keys;
* human sender identity;
* human recipient identity.

The architectural target is:

```text
opaque_A → opaque_B
```

rather than:

```text
Alice → Bob
```

---

# 9. File Service Trust Boundary

## Responsibility

Files handles:

* upload;
* storage;
* retrieval;
* transfer;
* offline availability.

## Content restriction

Files must not require access to file plaintext.

The service should operate on protected file representations.

A compromise of Files should therefore primarily expose:

* encrypted files;
* permitted metadata;
* transfer/storage information.

It must not automatically provide file decryption capability.

---

# 10. Audit Service Trust Boundary

## Responsibility

Audit provides security and operational audit capabilities.

It may record:

* authentication events;
* authorization events;
* device registration;
* device revocation;
* security events;
* operational events;
* communication metadata.

---

## 10.1 Communication metadata

Audit **may** record communication metadata.

However, this metadata must use opaque identifiers.

For example:

```text
opaque_device_A
        ↓
opaque_device_B
        ↓
timestamp
        ↓
message_id
```

is permitted.

The following is prohibited:

```text
Alice
  ↓
Bob
  ↓
timestamp
```

if this requires Audit to know the mapping between the opaque identifiers and human identities.

Therefore:

> Audit may know that two opaque endpoints communicated, but must not know which humans those endpoints represent.

---

## 10.2 Audit restrictions

Audit must not receive:

* message plaintext;
* file plaintext;
* private cryptographic keys;
* the human-identity mapping associated with communication metadata.

Audit logs themselves are sensitive data and must therefore be treated as another protected information source.

---

# 11. Persistent Storage Boundary

Persistent storage may contain:

* encrypted messages;
* encrypted files;
* delivery state;
* synchronization state;
* account information;
* device information;
* audit records;
* timestamps;
* operational metadata.

Storage must not possess the private cryptographic material required to decrypt end-to-end content.

---

## 11.1 Storage compromise

A storage compromise may expose:

* ciphertext;
* stored metadata;
* delivery state;
* synchronization information;
* timestamps;
* audit information.

It should not automatically expose:

* plaintext;
* private keys;
* human sender identity;
* human recipient identity.

---

# 12. Administration Boundary

The Application Administrator combines:

* application administration;
* security/audit operations;
* infrastructure/platform operations.

The role is operationally privileged.

However:

```text
Administrative privilege
        ≠
Content decryption authority
```

Administrators may:

* manage users;
* manage devices;
* revoke devices;
* configure policies;
* inspect operational state;
* inspect authorized audit data;
* operate infrastructure.

Administrators may not automatically:

* decrypt messages;
* decrypt files;
* obtain private cryptographic keys;
* translate opaque communication identifiers into human communication identities.

---

## 12.1 No Emergency Backdoor

SecureCloud deliberately rejects an administrator emergency-decryption mechanism.

There is no:

```text
Administrator
      ↓
Emergency override
      ↓
Message plaintext
```

path.

Emergency operational authority must therefore be implemented through normal authorization and endpoint-level access, not privileged decryption of users' protected content.

---

# 13. Network / Transport Boundary

All underlying communication networks are untrusted.

This includes:

* Internet;
* cellular networks;
* Wi-Fi;
* mesh networks;
* satellite links;
* disconnected/store-and-forward networks;
* future tactical networks.

The system must not assume that transport is:

* confidential;
* reliable;
* available;
* correctly routed;
* non-malicious.

A network adversary may potentially:

* observe traffic;
* capture traffic;
* replay traffic;
* inject traffic;
* modify traffic;
* drop traffic;
* delay traffic;
* reorder traffic;
* perform traffic analysis.

Exact defenses are outside this document.

---

# 14. Emergency Unit Boundary

The Emergency Unit is **not a dedicated backend microservice**.

It is a normal SecureCloud user or group of users with a special operational role.

This means the Emergency Unit remains inside the normal endpoint security model.

An emergency message can therefore follow the conceptual model:

```text
Sender Device
      |
      | encrypted emergency message
      ↓
SecureCloud infrastructure
      |
      ↓
Emergency Unit Device
      |
      ↓
plaintext
```

Infrastructure does not receive plaintext merely because the message is classified as emergency.

---

## 14.1 Emergency authorization

The Emergency Unit may receive:

* emergency message content;
* emergency-related operational information;
* explicitly shared location.

It should not automatically receive unrelated user information.

---

# 15. Location Trust Boundary

Location information is considered sensitive.

When a user explicitly shares location during an emergency:

```text
User Device
     |
     | protected location
     ↓
Emergency Unit
```

The intended recipient of the location is the Emergency Unit.

The location must not automatically become available to:

* Gateway;
* Messaging;
* Files;
* Audit;
* administrators;
* unrelated users.

The exact mechanism for achieving this property belongs to the security and messaging architecture.

---

# 16. Device Revocation Boundary

Every device has an independent authorization state.

A device can transition from:

```text
AUTHORIZED
```

to:

```text
REVOKED
```

After revocation:

* the device must not receive/decrypt future messages;
* new communication must not be encrypted for the revoked device;
* its authorization for future participation must be invalidated.

### MVP policy

A revoked device **may still decrypt messages that were already encrypted for that device before revocation**.

This is an intentional MVP decision.

Therefore:

```text
Before revocation
       |
       ↓
Messages encrypted for Device A
       |
       ↓
Device A revoked
       |
       ├── Old messages → MAY decrypt
       |
       └── Future messages → MUST NOT decrypt
```

A stronger historical-content revocation model may be investigated later.

---

# 17. Perfect Forward Secrecy Boundary

SecureCloud requires Perfect Forward Secrecy.

The architectural objective is that compromise of current/future device secrets does not automatically provide unrestricted access to protected communication from other cryptographic periods.

The exact ratchet/session/key lifecycle is intentionally deferred to the cryptographic architecture.

The MVP revocation rule remains:

> Revocation prevents future protected communication but does not retroactively remove access to messages already encrypted for the device.

---

# 18. Key Management Boundary

SecureCloud requires backend capabilities for public-key discovery/distribution.

Key-management infrastructure may therefore handle:

* public cryptographic information;
* device public identities;
* key metadata;
* key lifecycle information.

It must not centrally possess users' private cryptographic material by default.

A compromise of key-distribution infrastructure should not automatically enable decryption of historical protected content.

Exact:

* key exchange;
* key rotation;
* device enrollment;
* key verification;
* compromise recovery;
* group key management

belong to the cryptographic architecture.

---

# 19. Offline Delivery Boundary

SecureCloud distinguishes:

```text
Message creation
       ↓
Submission
       ↓
Durable acceptance
       ↓
Delivery
       ↓
Synchronization
       ↓
Acknowledgement
```

The important architectural boundary is **durable acceptance**.

A message should only be considered durably accepted once the system has persisted sufficient information to satisfy its defined durability guarantee.

"Guaranteed delivery" must therefore be defined against an explicit failure model.

SecureCloud cannot literally guarantee delivery if, for example:

* the recipient device is permanently destroyed;
* every communication path is permanently unavailable;
* all copies of the infrastructure are destroyed beyond the recovery model.

The exact durability and availability guarantees remain to be specified.

---

# 20. Service-to-Service Trust Boundaries

The five microservices do not automatically trust one another.

Service-to-service access should follow:

```text
Service A
   |
   | explicitly authorized capability
   ↓
Service B
```

rather than:

```text
All services
      |
      ↓
Shared unrestricted trust
```

Examples:

* Messaging should not obtain Auth's authentication secrets.
* Auth should not obtain message plaintext.
* Files should not obtain message plaintext.
* Audit should not automatically receive all information from Messaging.
* Gateway should not obtain application plaintext.
* No service should obtain another service's private cryptographic material without an explicit architectural requirement.

Service-to-service authentication and authorization mechanisms remain undecided.

---

# 21. Shared Memory Boundary

Shared memory may be considered as a future performance optimization.

However, shared memory must not automatically cross trust boundaries.

The rule is:

> Shared memory is acceptable only when all participants sharing the memory belong to an explicitly compatible trust zone and the shared-memory design does not bypass service isolation.

For example:

```text
Trusted Zone
 ┌───────────────┐
 │ Service A     │
 │      ↕        │
 │ Shared Memory │
 │      ↕        │
 │ Service B     │
 └───────────────┘
```

may be acceptable if explicitly justified.

Using shared memory to bypass an intended security boundary would be prohibited.

The exact use of shared memory requires an ADR based on:

* performance;
* isolation;
* failure behavior;
* memory ownership;
* security;
* observability;
* operational complexity.

---

# 22. Compromise and Blast Radius

## 22.1 Gateway compromise

Potential exposure:

* network metadata;
* connection information;
* opaque routing information;
* traffic patterns visible to Gateway.

Should **not** automatically expose:

* message plaintext;
* file plaintext;
* private keys;
* human communication identities.

---

## 22.2 Auth compromise

Potential exposure:

* authentication state;
* account authorization;
* device authorization;
* authentication-related information.

Should **not** automatically expose:

* message plaintext;
* file plaintext;
* private keys;
* historical protected content.

---

## 22.3 Messaging compromise

Potential exposure:

* message ciphertext;
* delivery metadata;
* synchronization state;
* opaque routing identifiers;
* timestamps available to Messaging.

Should **not** automatically expose:

* message plaintext;
* private keys;
* human sender identity;
* human recipient identity.

---

## 22.4 Files compromise

Potential exposure:

* encrypted files;
* file metadata;
* transfer/storage information.

Should **not** automatically expose:

* file plaintext;
* private keys.

---

## 22.5 Audit compromise

Potential exposure:

* intentionally recorded audit information;
* communication metadata represented through opaque identifiers;
* security events;
* timestamps.

Should **not** automatically expose:

* plaintext;
* private keys;
* human identity mapping.

---

## 22.6 Storage compromise

Potential exposure:

* ciphertext;
* stored metadata;
* timestamps;
* delivery state;
* synchronization state;
* audit records.

Should **not** automatically provide:

* content decryption capability;
* private keys.

---

## 22.7 Administrator compromise

A compromised administrator represents a high-impact threat because of operational privileges.

Nevertheless, administrator compromise should not automatically provide:

* message plaintext;
* file plaintext;
* private cryptographic keys;
* human identity mappings hidden from the administrator.

The system must rely on compartmentalization rather than trusting administrators absolutely.

---

## 22.8 Device compromise

A compromised device may expose information accessible to that device.

However, the compromise should not automatically expose:

* other devices belonging to the same user;
* their private keys;
* their future communication.

Device revocation and cryptographic key evolution provide additional containment.

---

# 23. Trust Boundary Invariants

The following are architectural invariants unless explicitly changed through an ADR.

### Invariant 1

Backend services must not require message plaintext.

### Invariant 2

File Service must not require file plaintext.

### Invariant 3

Backend services must operate using opaque communication identifiers rather than human sender/recipient identities.

### Invariant 4

Human sender and recipient identity confidentiality is a hard requirement.

### Invariant 5

Message-size protection should be actively pursued.

### Invariant 6

Authentication and cryptographic identity remain separate trust domains.

### Invariant 7

Administrators have no emergency content-decryption backdoor.

### Invariant 8

Private cryptographic keys must not be centrally stored by default.

### Invariant 9

Devices represent independent trust relationships.

### Invariant 10

Persistent storage must not automatically possess content-decryption capability.

### Invariant 11

The network is untrusted.

### Invariant 12

Audit may record communication metadata only through opaque identifiers.

### Invariant 13

Emergency Unit is an operational user role rather than a mandatory backend microservice.

### Invariant 14

Emergency location is intended only for the Emergency Unit.

### Invariant 15

Revocation prevents future protected communication but does not retroactively invalidate messages already encrypted for the revoked device in the MVP.

### Invariant 16

Compromised backend services should be contained rather than allowed unrestricted lateral access.

### Invariant 17

Shared memory must not bypass an intended trust boundary.

---

# 24. Deliberately Undecided Topics

This document intentionally does not decide:

* encryption algorithms;
* key-exchange protocols;
* session-key protocols;
* ratcheting;
* group encryption;
* exact PFS implementation;
* anonymous routing;
* traffic-analysis resistance;
* opaque identifier generation;
* mapping between opaque identifiers and human identities;
* database schema;
* service-to-service protocol;
* authentication protocol;
* token format;
* device enrollment;
* device private-key storage;
* key rotation;
* key recovery;
* emergency escalation protocol;
* message retention;
* synchronization limits;
* mesh protocol;
* satellite protocol;
* tactical networking protocol;
* location privacy mechanisms;
* exact shared-memory implementation;
* exact durability SLA.

These require dedicated architecture work or ADRs.

---

# 25. Architectural Consequences

The trust model creates the following constraints for architecture design.

## 25.1 Identity architecture

The architecture must separate:

```text
Human identity
        ↓
opaque identity
        ↓
device identity
```

without allowing backend services to freely reconstruct the human communication graph.

---

## 25.2 Messaging architecture

Messaging must be able to route messages without learning human sender/recipient identities.

This is likely to be one of the most technically challenging parts of SecureCloud.

---

## 25.3 Metadata architecture

Encryption of payloads alone is insufficient.

The architecture must explicitly consider:

* identifiers;
* routing;
* timestamps;
* sizes;
* frequency;
* logs;
* delivery metadata;
* synchronization metadata.

---

## 25.4 Microservice architecture

The five-service requirement must not result in five services that effectively form one unrestricted trust domain.

Service boundaries must correspond to meaningful information and authority boundaries.

---

## 25.5 Security architecture

The security architecture must provide defense in depth so that compromise of:

```text
one service
```

does not immediately become:

```text
entire system compromise
```

---

## 25.6 Emergency architecture

Emergency communication must improve:

* priority;
* durability;
* acknowledgement;
* escalation;
* operational visibility;

without weakening:

* endpoint confidentiality;
* administrator separation;
* identity confidentiality.

---

## 25.7 Extreme-connectivity architecture

Different transport technologies must be replaceable around the same trust model.

The security properties must not depend on the Internet being available.

---

# 26. Review Checklist

Before freezing this document, verify:

* [ ] Human sender identity is protected.
* [ ] Human recipient identity is protected.
* [ ] Backend operates with opaque identifiers.
* [ ] Audit never receives the human identity mapping.
* [ ] Message plaintext remains endpoint-only.
* [ ] File plaintext remains endpoint-only.
* [ ] Message-size hiding is explicitly considered.
* [ ] Timestamp visibility is intentionally broad.
* [ ] Delivery metadata exposure is controlled.
* [ ] Administrators have no emergency decryption path.
* [ ] Emergency Unit is correctly modeled as an operational role.
* [ ] Emergency location is restricted to the Emergency Unit.
* [ ] Device revocation semantics are explicit.
* [ ] PFS remains a required property.
* [ ] Service compromise is handled through containment.
* [ ] Shared memory cannot bypass trust boundaries.
* [ ] Database compromise does not automatically expose plaintext.
* [ ] Five microservices have meaningful trust separation.
* [ ] Network is treated as untrusted.
* [ ] Remaining undecided topics are explicitly deferred.

---

# 27. Status

**Version 0.2 — Approved

`architecture-alternatives.md`
