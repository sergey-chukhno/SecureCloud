# ADR-001 — Five Runtime Microservices

**Status:** Approved
**Date:** 2026-09-02
**Decision Owners:** SecureCloud Architecture Team

## Context

SecureCloud is designed as an ultra-secure communication platform for critical environments such as humanitarian operations, investigative journalism, and sensitive organizations.

The platform must support:

* end-to-end encrypted messaging;
* encrypted file transfer;
* authentication and authorization;
* offline and degraded-network communication;
* emergency communication;
* multiple devices per logical user;
* metadata minimization;
* strong service isolation;
* independent deployment and scaling;
* predictable performance under load;
* future evolution toward distributed and potentially hostile-network environments.

The initial project specification describes a set of backend services, including Authentication, Messaging, Files, Audit, and Deploy, while also depicting an API Gateway.

During architectural analysis, it was determined that the API Gateway is a runtime component that belongs to the communication path of the system, whereas deployment and infrastructure management belong to the operational/control plane.

The architecture therefore requires an explicit decision about which components constitute the runtime microservice architecture.

## Decision Drivers

The decision is primarily driven by:

1. **Security isolation**

   * Compromise of one service must not automatically compromise the entire platform.
   * Each service must receive only the minimum data and privileges required.

2. **End-to-end confidentiality**

   * Backend services must never require access to message or file plaintext.
   * Private cryptographic keys must remain on client devices.

3. **Independent deployment**

   * Services must be independently deployable and restartable.
   * A service boundary must not depend on whether services happen to run on the same physical host.

4. **Independent scalability**

   * Messaging, file transfer, authentication, and auditing have different workload characteristics.
   * Components should be scalable independently where required.

5. **Failure isolation**

   * Failure or overload of one subsystem should not unnecessarily bring down unrelated functionality.

6. **Operational clarity**

   * Runtime communication services must be separated conceptually from infrastructure and deployment tooling.

7. **Distributed-first evolution**

   * The architecture must work when services are deployed on different hosts.
   * Local IPC or shared memory must not be required for correctness.

8. **Academic feasibility**

   * The architecture must remain implementable and testable within the project scope.

## Considered Alternatives

### Alternative A — Modular Monolith

Implement the entire backend as one deployable application containing authentication, messaging, files, audit, and gateway functionality.

**Advantages**

* Simple deployment.
* Simple local development.
* Low network communication overhead.
* Easier initial debugging.

**Disadvantages**

* Weak runtime isolation.
* Independent scaling is difficult.
* A failure can affect the entire backend.
* Security boundaries become primarily logical rather than deployment boundaries.
* Does not satisfy the desired distributed-first architecture.

**Decision:** Rejected.

---

### Alternative B — Five Independent Runtime Microservices

Define the following five independently deployable runtime services:

1. Gateway
2. Authentication
3. Messaging
4. Files
5. Audit

The Qt/C++ client is a client application, not a backend microservice.

Deployment, CI/CD, infrastructure management, and operational control are treated separately as control-plane concerns.

**Advantages**

* Clear security boundaries.
* Independent deployment.
* Independent scaling.
* Failure isolation.
* Natural evolution toward Kubernetes.
* Clear ownership of service data.
* Compatible with distributed deployment from the beginning.

**Disadvantages**

* Additional operational complexity.
* Network communication between services.
* More complicated integration testing.
* Requires explicit service contracts.
* Requires distributed-systems reliability mechanisms.

**Decision:** **Selected.**

---

### Alternative C — Five Backend Services Without Gateway

Expose the backend services directly to the client.

**Advantages**

* Fewer runtime components.
* Slightly simpler request path.
* No dedicated gateway layer.

**Disadvantages**

* Authentication, routing, rate limiting, connection management, and external API concerns become distributed across services.
* Enlarges the externally exposed attack surface.
* Makes API evolution more difficult.
* Weakens the architectural role of a controlled external entry point.

**Decision:** Rejected.

---

### Alternative D — Gateway Plus Four Runtime Services, With Deploy as the Fifth

Treat Deploy as one of the five primary services and keep the Gateway outside the service count.

**Advantages**

* Matches one interpretation of the original project specification.
* Provides an explicit deployment component.

**Disadvantages**

* Conflates runtime communication architecture with infrastructure/control-plane functionality.
* Gateway remains architecturally significant but is not represented as a runtime service.
* Deployment functionality does not belong in the normal user communication path.
* Makes the runtime architecture less coherent.

**Decision:** Rejected.

## Decision

SecureCloud will consist of **five runtime microservices**:

```text
                    ┌──────────────────────┐
                    │   Qt / C++ Client    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │       Gateway        │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
      ┌────────────┐    ┌────────────┐    ┌────────────┐
      │    Auth    │    │ Messaging  │    │   Files    │
      └────────────┘    └────────────┘    └────────────┘
                               │
                               ▼
                         ┌───────────┐
                         │   Audit   │
                         └───────────┘
```

The five runtime services are:

### 1. Gateway

The controlled external entry point into the backend.

Responsibilities include:

* accepting client connections;
* routing requests;
* enforcing transport-level policies;
* applying request limits and backpressure;
* exposing the external API;
* performing protocol/version negotiation where applicable.

The Gateway must not become a business-logic monolith.

It must not possess message or file plaintext merely because traffic passes through it.

---

### 2. Authentication Service

Responsible for authentication and authorization-related backend functionality.

Responsibilities include:

* authenticating clients;
* managing authentication state;
* issuing or validating appropriate authentication credentials;
* enforcing authorization policies;
* managing account/device authorization state.

Authentication credentials and cryptographic messaging identities remain conceptually separate.

The Authentication service must not possess users' private messaging keys.

---

### 3. Messaging Service

Responsible for message transport, persistence, delivery, and synchronization.

Responsibilities include:

* accepting encrypted messages;
* durable message storage;
* recipient/device delivery;
* offline message handling;
* retry and delivery semantics;
* message ordering where required;
* priority handling for emergency communication;
* bounded queues and backpressure.

The Messaging service operates on encrypted message data and associated metadata required for delivery.

It must not require message plaintext.

---

### 4. Files Service

Responsible for encrypted file storage and transfer.

Responsibilities include:

* accepting encrypted file objects;
* storing ciphertext;
* retrieving ciphertext;
* supporting resumable or interrupted transfers where required;
* enforcing storage and access policies;
* handling file metadata required by the system.

The Files service must not possess file decryption keys or require file plaintext.

---

### 5. Audit Service

Responsible for security and operational audit information.

Responsibilities include:

* recording authorized audit events;
* recording relevant communication metadata;
* recording security-relevant events;
* supporting investigation and operational monitoring;
* maintaining audit integrity.

Audit data must respect the platform's metadata-minimization requirements.

The Audit service must not become a mechanism for recovering message or file plaintext.

## Runtime vs Client vs Control Plane

The architecture distinguishes three categories.

### Client

The Qt/C++ application is the trusted endpoint where:

* message plaintext exists;
* file plaintext exists;
* private cryptographic keys exist;
* encryption and decryption occur.

It is not a microservice.

### Runtime Plane

The runtime plane contains the five services defined by this ADR:

* Gateway
* Authentication
* Messaging
* Files
* Audit

These services participate directly in serving application functionality.

### Infrastructure / Control Plane

Deployment and infrastructure management are not part of the five runtime microservices.

This includes concerns such as:

* deployment;
* service lifecycle management;
* CI/CD;
* container orchestration;
* infrastructure configuration;
* operational administration.

The exact control-plane architecture is defined separately by **ADR-002 — Runtime vs Infrastructure Control Plane**.

## Service Boundary Principles

The five services follow these principles.

### Independent deployment

Each service must be capable of being built, deployed, restarted, and upgraded independently.

### Network-independent topology

A service must communicate through defined service contracts rather than relying on local process relationships.

Services may eventually run:

* on the same host;
* on separate hosts;
* in Docker containers;
* in Kubernetes pods;
* across different network segments.

The service boundary must remain valid in all cases.

### Least privilege

Each service receives only the permissions and data required for its responsibilities.

### Explicit contracts

Inter-service communication must use explicit, versioned contracts.

Implementation details of one service must not become implicit dependencies of another.

### Service-owned data

Each service owns the data necessary for its responsibility.

Other services must access that information through explicit service interfaces rather than directly manipulating another service's storage.

The exact database strategy is deferred to later ADRs.

### No implicit plaintext sharing

The existence of a service boundary must never become a justification for sharing message or file plaintext between backend services.

## Security Implications

This decomposition establishes important security boundaries.

A compromise of the Messaging service should not automatically provide:

* authentication credentials;
* private cryptographic keys;
* file decryption keys;
* unrestricted administrative privileges.

Similarly, compromise of the Files service should not automatically provide access to message plaintext.

The Gateway is treated as an untrusted backend component with respect to end-to-end encrypted content.

The architecture therefore aims for **containment rather than assumed universal trust**.

Administrative privileges do not create an exceptional decryption path.

## Performance Implications

Five independent services introduce network hops and serialization overhead compared with a monolith.

This cost is accepted because security isolation, independent scaling, and distributed deployment are higher architectural priorities.

Performance optimization must therefore be evidence-driven.

The initial implementation should establish measurable baselines before introducing optimizations such as:

* binary protocols;
* connection pooling;
* batching;
* zero-copy techniques;
* shared memory;
* local IPC.

Shared-memory or IPC optimizations are explicitly not required for correctness and are deferred to a later architectural decision.

## Reliability Implications

Independent services introduce distributed failure modes.

The architecture therefore requires explicit handling of:

* service unavailability;
* timeouts;
* retries;
* duplicate requests;
* partial failures;
* queue saturation;
* graceful shutdown;
* degraded operation;
* offline delivery.

These mechanisms will be formalized by subsequent ADRs, particularly the communication and resilience decisions.

## Testing and Validation

The five-service decomposition must be validated at several levels.

### Unit Testing

Each service must test its own business and security-critical logic independently.

### Contract Testing

Service interfaces must be tested to ensure that independently deployed versions remain compatible.

### Integration Testing

Services must be tested communicating through their actual service interfaces.

### Failure Testing

The system must test scenarios including:

* Messaging unavailable;
* Files unavailable;
* Authentication unavailable;
* Audit unavailable;
* Gateway overload;
* network partition;
* service restart;
* duplicate delivery;
* delayed responses.

### Security Testing

Testing must verify that service compromise does not automatically cross intended trust boundaries.

In particular:

* Messaging must not access private client keys.
* Files must not decrypt files.
* Gateway must not decrypt messages.
* Audit must not become a plaintext recovery mechanism.

### Performance Testing

The service decomposition must be evaluated against the project's performance objectives, including the stated target of approximately **10,000 messages/second peak**, with the exact benchmark methodology defined separately.

## Consequences

### Positive

* Clear service ownership.
* Stronger security isolation.
* Independent deployment.
* Independent scaling.
* Better failure containment.
* Natural Kubernetes evolution.
* Clear separation between runtime and infrastructure.
* Supports the distributed-first architecture.
* Provides a strong foundation for future extreme-environment deployments.

### Negative

* Higher operational complexity.
* More network communication.
* More difficult debugging.
* More distributed failure modes.
* Requires explicit contracts and compatibility management.
* Requires more sophisticated testing.

### Risks

#### Distributed-system complexity

Five services can introduce unnecessary complexity if boundaries are poorly designed.

**Mitigation:** keep responsibilities narrow and avoid premature distributed patterns.

#### Excessive network overhead

Too many synchronous service calls could increase latency.

**Mitigation:** define communication patterns explicitly and benchmark before optimizing.

#### Service-boundary leakage

Services may gradually acquire responsibilities belonging to other services.

**Mitigation:** maintain explicit ownership rules and architectural reviews.

#### Security-boundary erosion

Operational shortcuts could cause services to receive data outside their intended trust boundary.

**Mitigation:** enforce least privilege, explicit contracts, and security-focused integration tests.

## Related Decisions

* **ADR-002 — Runtime vs Infrastructure Control Plane**
* **ADR-003 — Distributed-First Architecture**
* **ADR-004 — Inter-Service Communication Model**
* **ADR-005 — Database Ownership / Database-per-Service**
* **ADR-009 — Distributed Failure & Resilience Model**
* **ADR-010 — Service-to-Service Authentication & Authorization**
* **ADR-012 — End-to-End Messaging Encryption**
* **ADR-015 — Secure File Architecture**
* **ADR-017 — Performance Benchmark Methodology**
* **ADR-018 — Post-MVP IPC / Shared Memory Optimization**

## Final Decision Summary

**SecureCloud will use five independently deployable runtime microservices:**

1. **Gateway**
2. **Authentication**
3. **Messaging**
4. **Files**
5. **Audit**

The **Qt/C++ client is an endpoint, not a microservice**.

**Deploy and infrastructure management belong to the control plane, not the runtime microservice set.**

Services communicate through explicit network-based contracts. Local IPC/shared memory may be investigated later as an optimization, but must never be required for correctness or service interoperability.

The architecture prioritizes **security containment, independent deployment, failure isolation, and distributed evolution**, while accepting the additional complexity inherent to a distributed system.
