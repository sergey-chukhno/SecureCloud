# SecureCloud — Architectural Drivers

**Document status:** v0.1
**Document type:** Architecture Foundation

---

## 1. Purpose

This document defines the architectural drivers that will guide the design and implementation of SecureCloud.

It establishes:

* what the system must accomplish;
* the security properties the architecture must provide;
* the performance and reliability objectives;
* the constraints imposed by the project specification;
* the threat model;
* the engineering principles governing architectural decisions;
* assumptions and unresolved questions.

This document intentionally does **not** define detailed implementation choices.

Technology selections, protocols, cryptographic constructions, IPC mechanisms, database structures, and other concrete architectural decisions must be evaluated separately and recorded through Architecture Decision Records (ADRs) when appropriate.

---

# 2. Architectural Vision

SecureCloud is intended to become a professional-grade secure communications platform designed for organizations handling highly sensitive information, including investigative journalism, international NGOs, sensitive enterprises, and administrations.

The system shall prioritize:

1. confidentiality;
2. protection against interception and infrastructure compromise;
3. metadata minimization;
4. secure multi-device communication;
5. reliable asynchronous delivery;
6. predictable performance;
7. strong testing and verification;
8. maintainability and architectural clarity.

The project specifies a five-microservice C++ architecture with a Qt native client, PostgreSQL, Docker/Docker Compose and CI/CD.

The long-term vision may extend beyond the academic MVP into a more complete portfolio-grade security and performance project.

---

# 3. Architectural Scope

The initial system is composed of:

* Qt/C++ client;
* API Gateway;
* Authentication Service;
* Messaging Service;
* Files Service;
* Audit Service;
* Deploy Service;
* PostgreSQL;
* Docker/Docker Compose;
* CI/CD pipeline.

The project specification explicitly identifies five C++ microservices and describes their orchestration alongside PostgreSQL.

The final boundaries, responsibilities, communication mechanisms and data ownership of these components remain subject to architectural analysis.

---

# 4. Functional Architectural Drivers

## FD-01 — Secure real-time messaging

The platform shall provide real-time professional messaging.

The messaging subsystem is identified as the core of the platform and is expected to support a peak target of 10,000 messages per second.

The exact workload definition for this target remains OPEN.

---

## FD-02 — End-to-end encrypted messaging

Message content shall be encrypted on the authorized sending endpoint and decrypted only by authorized receiving endpoint(s).

The server shall operate on encrypted message data and shall not possess the cryptographic capability required to decrypt message content.

The project specification explicitly states that the server should never see message content and should only route encrypted packets.

---

## FD-03 — Conversation management

The system shall support:

* conversation history;
* conversation threads;
* secure presence/status information;
* local encrypted-history search.

The exact implementation and synchronization mechanisms remain OPEN.

---

## FD-04 — Offline message delivery

Messages shall be capable of being stored in encrypted form while a recipient is offline and delivered when the recipient becomes available.

The system shall define explicit policies for:

* message retention;
* expiration;
* mailbox limits;
* long-term offline users;
* delivery acknowledgement;
* retry behaviour;
* failure recovery.

These policies are currently OPEN.

---

## FD-05 — Secure file sharing

The system shall support secure file sharing for sensitive information and large data volumes.

The project specification identifies:

* file operations;
* streaming encryption;
* data compression;
* encrypted filesystem/storage;
* potentially terabytes of sensitive data.

---

## FD-06 — Server-blind file storage

The Files Service shall operate on encrypted file data and shall not possess the cryptographic capability required to decrypt the protected file contents.

The detailed file-encryption and key-distribution architecture remains OPEN.

---

## FD-07 — Centralized authentication

The system shall provide centralized authentication.

The project specification identifies:

* MFA;
* token issuance;
* token refresh;
* token validation;
* token revocation;
* permission verification.

The exact authentication protocol and credential mechanisms remain OPEN.

---

## FD-08 — Authorization

The system shall distinguish authentication from authorization.

Being authenticated does not automatically grant permission to perform an operation.

Authorization shall govern access to protected resources and operations.

The detailed authorization model remains OPEN.

---

## FD-09 — Audit

The platform shall provide security and operational auditing.

Audit events shall be designed so that they do not unnecessarily expose protected message or file content.

The exact event taxonomy, retention, storage and access-control model remain OPEN.

---

## FD-10 — Automated deployment

The project shall support automated build, test, packaging, deployment and post-deployment verification.

The project specification describes the following pipeline:

1. Build;
2. Test;
3. Package;
4. Deploy;
5. Verify.

---

# 5. Security Architectural Drivers

Security is a primary architectural concern rather than a feature added after implementation.

---

## SD-01 — End-to-end confidentiality

Sensitive message content shall remain confidential from infrastructure components that do not require plaintext access.

Plaintext message content should exist only where required on authorized endpoints.

---

## SD-02 — Server blindness

The SecureCloud infrastructure shall not automatically become a decryption authority.

In particular:

* Messaging Service must not be able to decrypt message content;
* Files Service must not be able to decrypt protected file content;
* database compromise must not directly expose plaintext protected content.

---

## SD-03 — Authentication/cryptographic identity separation

Account authentication credentials and cryptographic communication identities shall be treated as separate security domains.

Authentication answers:

> "Who is authenticated?"

Cryptographic identity answers:

> "Which cryptographic entity am I communicating with?"

Compromise of authentication infrastructure must not automatically imply compromise of users' historical encrypted communications.

---

## SD-04 — Multi-device security

A logical user shall be able to securely authorize multiple devices.

Each device should have an independent device-level cryptographic identity rather than requiring one universal private key to be copied across all devices.

The precise key hierarchy and provisioning mechanism remain OPEN.

---

## SD-05 — Device revocation

Individual devices shall be revocable.

After revocation, the revoked device shall not be authorized to access future protected communications.

The system shall define how revocation interacts with:

* active sessions;
* cached credentials;
* offline messages;
* group membership;
* cryptographic keys;
* previously downloaded data.

---

## SD-06 — Forward secrecy

The cryptographic architecture shall aim to provide Perfect Forward Secrecy (PFS), such that compromise of long-term key material does not automatically permit retrospective decryption of protected past communications.

The exact cryptographic protocol/construction remains OPEN.

---

## SD-07 — Post-compromise considerations

The architecture should consider protection and recovery after compromise of an individual device or cryptographic state.

This includes investigation of:

* key rotation;
* session/key evolution;
* device re-enrollment;
* compromised-device recovery;
* group membership changes.

The exact security properties and mechanisms remain OPEN.

---

## SD-08 — Metadata minimization

SecureCloud should expose as little communication metadata as technically and operationally possible.

The desired objective is to minimize exposure of:

* communicating parties;
* communication relationships;
* timing;
* message sizes;
* frequency;
* routing information;
* other traffic metadata.

This is an architectural goal, not yet a claim of complete anonymity.

---

## SD-09 — Metadata privacy must be threat-model driven

The system shall not claim protection against traffic analysis without defining:

* the adversary;
* available observations;
* available capabilities;
* information being protected;
* unavoidable information leakage;
* measurable security objectives.

Potential future mechanisms may include encrypted routing metadata, opaque identifiers, padding, batching, timing obfuscation or relay mechanisms.

No such mechanism is selected by this document.

---

## SD-10 — Secure key distribution

The system shall provide a mechanism for distributing/discovering public cryptographic material without making the infrastructure a decryption authority.

The mechanism must support the future possibility of:

* multi-device users;
* group conversations;
* device revocation;
* key rotation;
* offline users.

The exact architecture is OPEN.

---

## SD-11 — Group-chat security

The cryptographic architecture shall eventually support secure group conversations.

The design must consider:

* group membership;
* adding devices/users;
* removing devices/users;
* key rotation;
* forward secrecy;
* post-compromise security;
* offline members;
* scalability.

The exact group-messaging protocol is OPEN.

---

## SD-12 — Secure local storage

Sensitive information stored locally on client devices shall be protected against unauthorized access.

The architecture shall consider:

* message history;
* cryptographic keys;
* authentication/session material;
* temporary files;
* downloaded files;
* caches.

The exact local-storage mechanism is OPEN.

---

## SD-13 — Defense in depth

No single security mechanism should be treated as sufficient protection.

Security should be established through multiple independent layers including, as appropriate:

* endpoint cryptography;
* authentication;
* authorization;
* secure transport;
* secure storage;
* isolation;
* least privilege;
* input validation;
* auditing;
* monitoring;
* secure deployment;
* dependency management.

---

# 6. Threat Model

SecureCloud's initial threat model includes the following adversaries and failure conditions.

## T-01 — Network attacker

An attacker capable of intercepting, observing, modifying, delaying or replaying network traffic.

Priority: **Critical**

Primary concerns:

* message confidentiality;
* message integrity;
* authentication;
* replay;
* traffic analysis;
* metadata exposure.

---

## T-02 — Compromised or malicious server

An attacker gains control of, or maliciously operates, one or more SecureCloud backend components.

Priority: **Critical**

The architecture should assume that backend compromise does not automatically provide plaintext access to protected message/file content.

---

## T-03 — Database compromise

An attacker obtains unauthorized access to the database or a database backup.

Priority: **Critical**

Protected message/file content must remain protected if stored as ciphertext.

Metadata exposure must be explicitly evaluated.

---

## T-04 — Stolen device

An attacker obtains physical access to an authorized user's device.

Priority: **Critical**

The architecture shall consider:

* device revocation;
* local encrypted storage;
* credential protection;
* key protection;
* session invalidation;
* cryptographic compromise containment.

---

## T-05 — Malicious authenticated user

A legitimate user abuses their authorized access.

Priority: **High**

The system should enforce least privilege and explicit authorization.

---

## T-06 — Compromised client

Malware or an attacker compromises a user's operating environment.

Priority: **Critical**

SecureCloud cannot assume that plaintext is safe once an endpoint itself is compromised.

The architecture should instead aim to limit the blast radius and provide recovery mechanisms.

---

## T-07 — Global/passive surveillance

An adversary capable of observing large-scale network traffic.

Priority: **Critical**

The architecture shall investigate metadata and traffic-analysis resistance.

SecureCloud shall not claim protection beyond the capabilities explicitly defined in its threat model.

---

## T-08 — Malicious insider/administrator

An authorized administrator abuses privileged access.

Priority: **Critical**

Administrative privileges must not automatically imply access to protected message/file plaintext.

---

## T-09 — Availability attack

An attacker attempts to disrupt availability through resource exhaustion, flooding or denial-of-service techniques.

Priority: **High**

The system shall consider:

* rate limiting;
* resource quotas;
* connection limits;
* backpressure;
* isolation;
* graceful degradation;
* recovery.

---

# 7. Performance Drivers

## PD-01 — Messaging throughput

The architecture shall target a peak throughput of:

**10,000 messages/second**

as stated in the project specification.

The following measurement conditions remain OPEN:

* message size;
* message distribution;
* number of concurrent connections;
* hardware;
* persistence guarantees;
* encryption workload;
* fan-out;
* geographic distribution;
* acceptable error rate.

---

## PD-02 — Predictable performance

Performance shall prioritize predictable behaviour under load.

Important metrics should include:

* throughput;
* p50 latency;
* p95 latency;
* p99 latency;
* p99.9 latency where useful;
* CPU utilization;
* memory consumption;
* allocation rate;
* queue depth;
* connection count;
* error rate.

---

## PD-03 — Low latency

The messaging system should provide low and predictable latency for interactive communication.

The exact latency objectives are OPEN.

---

## PD-04 — Large-file performance

The file subsystem shall support efficient large-file operations.

Performance considerations include:

* sequential I/O;
* streaming;
* encryption overhead;
* compression overhead;
* memory consumption;
* copying;
* allocation;
* network throughput.

---

## PD-05 — Evidence-based optimization

Performance optimizations shall be justified through:

1. measurement;
2. profiling;
3. benchmark comparison;
4. analysis of trade-offs.

The project shall avoid optimization based solely on intuition.

---

## PD-06 — Zero-copy / shared-memory optimization

Advanced techniques such as shared memory or zero-copy data paths may be investigated where benchmarks demonstrate a meaningful bottleneck.

They are not architectural requirements merely because they may be faster in theory.

Any such mechanism must be evaluated against:

* security;
* complexity;
* portability;
* correctness;
* failure handling;
* maintainability;
* testability;
* measurable performance benefit.

---

# 8. Reliability & Availability Drivers

## RD-01 — Durable message acceptance

Once the system declares a message durably accepted, the message should survive temporary service/client unavailability according to the defined durability model.

The exact durability semantics remain OPEN.

---

## RD-02 — Asynchronous delivery

The system shall support delivery to temporarily offline recipients.

The delivery model must define:

* retries;
* acknowledgements;
* duplicate handling;
* ordering;
* expiration;
* failure states.

---

## RD-03 — Retention policy

The system shall define explicit retention policies to prevent unbounded accumulation of undelivered messages.

Policies should address:

* maximum retention period;
* mailbox size;
* message count;
* expiration;
* user/admin configuration;
* long-term offline accounts.

---

## RD-04 — Failure isolation

Failure of one service should not unnecessarily cause total system failure.

The architecture shall explicitly model service dependencies and failure propagation.

---

## RD-05 — Recovery

Services must have defined recovery behaviour after:

* process crash;
* network failure;
* database failure;
* temporary dependency failure;
* container restart.

---

## RD-06 — Availability

The specification describes the messaging system as having "zero tolerance to failure."

This requirement must be translated into measurable availability objectives.

OPEN:

* uptime target;
* RTO;
* RPO;
* acceptable message loss;
* acceptable degradation.

---

# 9. Operational Drivers

## OD-01 — Reproducible builds

Builds should be reproducible and controlled.

---

## OD-02 — Automated testing

Testing shall be integrated into CI/CD.

---

## OD-03 — Automated deployment

Deployment should be automated rather than manually performed.

The project specification identifies Docker/Docker Compose as the deployment approach.

---

## OD-04 — Health verification

Successful deployment shall require more than container startup.

Verification should eventually include:

* process health;
* dependency connectivity;
* service health checks;
* smoke tests;
* relevant security checks.

---

## OD-05 — Rollback

The deployment architecture should support controlled rollback.

---

## OD-06 — Observability

The architecture should provide sufficient observability to diagnose:

* failures;
* latency problems;
* resource exhaustion;
* service communication failures;
* security-relevant events.

Observability must not become a mechanism for leaking protected message/file content.

---

# 10. Architectural Constraints

## AC-01 — C++

The backend services are required by the project specification to be implemented in C++.

---

## AC-02 — Five microservices

The project specification defines five backend microservices:

* Auth Service;
* Messaging Service;
* Files Service;
* Audit Service;
* Deploy Service.

This is treated as a project constraint.

The internal boundaries and exact responsibilities still require architectural validation.

---

## AC-03 — Qt native client

The specification proposes a native Qt/C++ client rather than an Electron/web-based client.

---

## AC-04 — PostgreSQL

PostgreSQL is specified as the database component.

The final data model, ownership and persistence strategy remain OPEN.

---

## AC-05 — Docker / Docker Compose

Docker and Docker Compose are specified as deployment/orchestration technologies for the project.

---

## AC-06 — Three-month academic delivery

The assignment describes a three-month implementation period.

The architecture must therefore remain sufficiently understandable, testable and maintainable for a student team.

---

# 11. Engineering Principles

## EP-01 — Security is an architectural property

Security shall be considered during architectural design rather than added after implementation.

---

## EP-02 — Minimize trust

Components should receive the minimum privileges and plaintext access necessary to perform their responsibilities.

---

## EP-03 — Do not invent cryptography

SecureCloud shall use established cryptographic constructions and reputable implementations.

The project shall not invent proprietary cryptographic primitives.

---

## EP-04 — Measure before optimizing

Performance decisions should be supported by benchmarks and profiling.

---

## EP-05 — Complexity must be justified

Architectural complexity must have a corresponding benefit.

---

## EP-06 — Innovation must be evidence-based

Innovative technologies or mechanisms should be introduced when they provide a demonstrable security, performance, reliability or engineering advantage.

"Modern" or "innovative" alone is not sufficient justification.

---

## EP-07 — Explicit trade-offs

Important architectural decisions shall document:

* problem;
* alternatives;
* constraints;
* decision;
* rationale;
* consequences;
* validation strategy.

---

## EP-08 — Failure is part of the design

Every critical component shall be designed with failure scenarios in mind.

---

## EP-09 — Security claims must be defensible

SecureCloud shall not claim properties stronger than those demonstrated by its architecture, implementation, testing and threat model.

---

# 12. Academic MVP vs Portfolio Roadmap

SecureCloud shall distinguish between:

### Academic MVP

The minimum coherent system required for:

* demonstration;
* evaluation;
* review;
* testing;
* presentation.

### Portfolio Roadmap

Advanced capabilities that may continue after the academic deadline.

Potential future areas include:

* advanced metadata minimization;
* stronger traffic-analysis resistance;
* sophisticated group messaging;
* advanced key lifecycle management;
* advanced IPC;
* zero-copy data paths;
* high-scale performance optimization;
* stronger resilience;
* advanced observability;
* distributed deployment.

The existence of a portfolio roadmap must not justify compromising the security or engineering quality of the academic MVP.

---

# 13. Assumptions

The following are working assumptions rather than final architectural decisions.

### A-01

The backend should be treated as potentially compromised with respect to protected content.

### A-02

Clients are the primary trusted environment for plaintext message/file content.

### A-03

Users may possess multiple authorized devices.

### A-04

Devices should have independent cryptographic identities.

### A-05

Offline delivery is required.

### A-06

Group messaging is a target capability.

### A-07

Metadata minimization is a major security objective.

### A-08

Authentication and cryptographic identity are separate security domains.

### A-09

Advanced performance mechanisms may be justified after measurement.

---

# 14. Open Architectural Questions

The following questions must be resolved before corresponding architecture areas are finalized.

## Identity & cryptography

* What cryptographic identity model will be used?
* What key hierarchy will be used?
* How are device keys generated?
* How are public keys distributed?
* How are keys verified?
* How are devices enrolled?
* How are devices revoked?
* How are keys rotated?
* How is recovery handled?
* What happens after device compromise?
* What protocol provides forward secrecy?
* What protocol provides group messaging security?

---

## Metadata privacy

* What metadata must the server know?
* What metadata can be hidden?
* What metadata is inherently unavoidable?
* What traffic-analysis attacker are we defending against?
* Can sender/recipient relationships be hidden from the server?
* Can message timing be obscured?
* Can message sizes be obscured?
* What are the performance/UX costs?

---

## Messaging

* What are the message delivery guarantees?
* What does "durably accepted" mean?
* What ordering guarantees are required?
* How are duplicates handled?
* How are acknowledgements represented?
* How are offline messages retained?
* How are expired messages handled?
* How are multi-device deliveries synchronized?

---

## Group messaging

* What cryptographic group protocol should be used?
* How are members added?
* How are members removed?
* How are devices added/removed?
* How are keys rotated?
* How is forward secrecy maintained?
* How is post-compromise security handled?

---

## Performance

* What exactly constitutes the 10k msg/s benchmark?
* What message size?
* What concurrency?
* What hardware?
* What latency target?
* What persistence guarantee?
* What fan-out?
* What resource limits?

---

## Reliability

* What availability target?
* What RTO?
* What RPO?
* What constitutes message loss?
* How much degradation is acceptable?
* What happens during database failure?
* What happens when individual services fail?

---

## Files

* Maximum file size?
* Maximum concurrent transfers?
* Required throughput?
* Retention policy?
* File integrity model?
* Resumable uploads?
* Chunking?
* Deduplication?
* Encryption/compression ordering?

---

## Architecture

* Exact responsibilities of the five services?
* Which service owns which data?
* What communication mechanism is used internally?
* REST, RPC, sockets, or other mechanism?
* Is shared memory justified?
* Where does the API Gateway terminate connections?
* How is backpressure implemented?
* How are service failures isolated?

---

# 15. Architectural Decision Classification

SecureCloud shall distinguish the following concepts:

### Requirement

A property imposed by the project/product.

### Constraint

A limitation or mandatory technology/structure.

### Assumption

A statement accepted temporarily until validated.

### Architectural Driver

A requirement that materially influences architecture.

### Decision

A chosen architectural approach.

### ADR

A documented significant architectural decision including rationale and consequences.

### Benchmark

Experimental evidence used to validate performance-related decisions.

---

# 16. Initial ADR Candidates

The following topics are candidates for future ADRs.

| ADR     | Topic                                               | Status    |
| ------- | --------------------------------------------------- | --------- |
| ADR-001 | Five-service architecture                           | Candidate |
| ADR-002 | Authentication vs cryptographic identity separation | Candidate |
| ADR-003 | Device-specific cryptographic identities            | Candidate |
| ADR-004 | Key distribution architecture                       | Candidate |
| ADR-005 | End-to-end messaging cryptographic architecture     | Candidate |
| ADR-006 | Forward secrecy strategy                            | Candidate |
| ADR-007 | Group messaging cryptographic architecture          | Candidate |
| ADR-008 | Metadata-minimizing routing                         | Candidate |
| ADR-009 | Offline message durability model                    | Candidate |
| ADR-010 | Internal service communication                      | Candidate |
| ADR-011 | Shared memory / zero-copy IPC                       | Candidate |
| ADR-012 | Secure file architecture                            | Candidate |
| ADR-013 | Local secure storage                                | Candidate |
| ADR-014 | Authentication/token architecture                   | Candidate |
| ADR-015 | Reliability/failure model                           | Candidate |

These are candidates, not decisions.

---

# 17. Traceability to Project Specification

| Specification requirement          | Architectural driver |
| ---------------------------------- | -------------------- |
| Professional secure communications | FD-01, SD-01         |
| End-to-end encrypted messaging     | FD-02, SD-01, SD-02  |
| Server routes encrypted packets    | SD-02                |
| 10,000 messages/sec peak           | PD-01                |
| Local encrypted-history search     | FD-03                |
| Secure presence                    | FD-03                |
| Secure file sharing                | FD-05, FD-06         |
| Streaming encryption               | FD-05                |
| Data compression                   | FD-05                |
| Encrypted filesystem/storage       | FD-05                |
| MFA authentication                 | FD-07                |
| Token validation/revocation        | FD-07                |
| Permission verification            | FD-08                |
| Audit events                       | FD-09                |
| Five C++ microservices             | AC-01, AC-02         |
| Qt native application              | AC-03                |
| PostgreSQL                         | AC-04                |
| Docker/Docker Compose              | AC-05                |
| Automated CI/CD                    | FD-10, OD-01–OD-05   |
| Unit/integration testing           | OD-02                |
| Three-month project                | AC-06                |

---

# 18. Status

This document is **not a final architecture**.

It establishes the drivers from which the architecture will be derived.

No implementation technology should be considered mandatory merely because it appears as an idea in this document.

All significant architectural choices must be validated through appropriate reasoning, experimentation, security analysis, benchmarks and/or testing.

**Next architectural phase:**

> **System Context → Actors → Trust Boundaries → Data Flows → Architecture Alternatives**





