# ADR-002 — Runtime vs Infrastructure Control Plane

**Status:** Approved
**Date:** 2026-09-02
**Decision Owners:** SecureCloud Architecture Team

## Context

SecureCloud is designed as a distributed system composed of independently deployable runtime services.

ADR-001 established the five runtime microservices:

1. Gateway
2. Authentication
3. Messaging
4. Files
5. Audit

The project specification also identifies a **Deploy** component/service.

However, deployment is fundamentally different from application runtime functionality.

The runtime plane exists to provide SecureCloud's communication capabilities to users.

The infrastructure/control plane exists to build, deploy, configure, observe, operate, and maintain those runtime components.

Treating deployment as an ordinary runtime microservice would mix two fundamentally different concerns and would create an unnecessary dependency between the communication platform and the infrastructure responsible for operating it.

A formal architectural decision is therefore required.

## Decision Drivers

The decision is driven by:

1. **Separation of concerns**

   * Application functionality must remain separate from infrastructure management.

2. **Security**

   * Deployment and infrastructure privileges are highly sensitive.
   * Runtime services should not automatically possess deployment authority.

3. **Blast-radius reduction**

   * Compromise of a runtime service must not provide control over the infrastructure running the platform.

4. **Independent lifecycle**

   * Runtime services and deployment infrastructure have different lifecycles.

5. **Distributed deployment**

   * Runtime services may eventually run across multiple hosts, clusters, regions, or constrained environments.

6. **Operational clarity**

   * Operators should be able to reason separately about application behavior and infrastructure behavior.

7. **Kubernetes evolution**

   * The architecture should map naturally to container orchestration without making Kubernetes-specific concepts part of the application domain.

8. **Academic feasibility**

   * The MVP should retain a simple operational model while preserving a path toward a more sophisticated production architecture.

## Considered Alternatives

### Alternative A — Deploy as a Runtime Microservice

Treat Deploy as one of the primary SecureCloud services.

The service would participate in the same architectural model as Authentication, Messaging, Files, and Audit.

**Advantages**

* Matches the literal interpretation of the original five-service specification.
* Provides an explicit application-level endpoint for deployment operations.

**Disadvantages**

* Mixes application functionality with infrastructure management.
* Potentially gives a runtime-accessible component highly privileged infrastructure capabilities.
* Creates a very large security boundary.
* A compromise of the Deploy service could potentially affect the entire platform.
* Deployment does not belong to the normal user communication lifecycle.
* Makes the runtime service model conceptually inconsistent.

**Decision:** Rejected.

---

### Alternative B — Separate Infrastructure/Control Plane

Keep deployment, CI/CD, orchestration, configuration, and operational management outside the runtime service architecture.

The control plane manages the lifecycle of the five runtime services but is not itself part of the user-facing communication path.

**Advantages**

* Strong separation of responsibilities.
* Smaller runtime attack surface.
* Better privilege isolation.
* Clear security boundary.
* Natural mapping to Docker Compose and later Kubernetes.
* Runtime services remain independent of the deployment implementation.
* Infrastructure can evolve without changing the application architecture.

**Disadvantages**

* Requires a separate operational model.
* Some deployment functionality may initially be implemented through simple scripts or CI/CD rather than a dedicated service.
* Operational tooling becomes another architectural concern that must be documented.

**Decision:** **Selected.**

---

### Alternative C — Hybrid Deploy Service

Expose a limited deployment API while keeping most infrastructure management outside the runtime.

**Advantages**

* Could provide convenient programmatic deployment operations.
* Potentially useful for highly automated environments.

**Disadvantages**

* Still introduces infrastructure authority into the runtime environment.
* Creates ambiguity about which operations belong to the application and which belong to infrastructure.
* Increases the attack surface.
* Requires careful privilege separation and authorization.

**Decision:** Deferred.

A future control-plane API could be introduced if a demonstrated operational requirement exists, but it must remain outside the runtime service architecture.

## Decision

SecureCloud will explicitly separate:

```text
┌─────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE                            │
│                                                             │
│  Source Control                                             │
│       │                                                     │
│       ▼                                                     │
│  CI/CD ──► Build ──► Test ──► Package ──► Deploy            │
│                                             │               │
│                                             ▼               │
│                                      Runtime Environment    │
└─────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    RUNTIME PLANE                            │
│                                                             │
│  Gateway ──► Auth                                           │
│       │                                                     │
│       ├────► Messaging                                      │
│       │                                                     │
│       ├────► Files                                           │
│       │                                                     │
│       └────► Audit                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

The **five runtime microservices remain exactly those established by ADR-001**.

Deployment is not a runtime microservice.

## Control Plane Responsibilities

The control plane is responsible for infrastructure and operational concerns such as:

### Build

* compiling services;
* producing artifacts;
* building container images;
* validating build reproducibility.

### Verification

* unit tests;
* integration tests;
* contract tests;
* security checks;
* static analysis;
* performance checks where applicable.

### Deployment

* deploying runtime services;
* updating service versions;
* managing deployment configuration;
* performing controlled rollouts.

### Infrastructure Management

Depending on the deployment environment:

* Docker Compose management;
* container orchestration;
* Kubernetes resources;
* networking configuration;
* storage infrastructure;
* secrets management infrastructure;
* service discovery infrastructure.

### Operational Management

* health monitoring;
* metrics collection;
* log collection;
* alerting;
* incident response;
* controlled shutdown and restart.

These capabilities do not become responsibilities of Gateway, Auth, Messaging, Files, or Audit.

## Runtime Plane Responsibilities

The runtime plane is responsible only for providing SecureCloud functionality.

### Gateway

Handles external client connectivity and request routing.

### Authentication

Handles authentication and authorization functionality.

### Messaging

Handles encrypted message acceptance, persistence, delivery, and synchronization.

### Files

Handles encrypted file storage and transfer.

### Audit

Handles authorized security and operational auditing.

None of these services should be responsible for deploying or upgrading another service.

## Security Model

The control-plane separation is particularly important because infrastructure privileges are substantially more powerful than ordinary application privileges.

A runtime service compromise must not automatically provide:

* container-orchestration privileges;
* host-level privileges;
* arbitrary deployment capabilities;
* unrestricted access to infrastructure secrets;
* authority to modify other runtime services.

The control plane should therefore follow a **separate trust boundary**.

### Principle of least privilege

Runtime services receive only the permissions required for their application responsibilities.

Control-plane components receive infrastructure permissions only where necessary.

### No runtime self-deployment

A compromised runtime service must not be able to deploy a modified version of itself or another service.

### No implicit infrastructure trust

Running inside the same cluster, host, or network does not imply that a runtime service is trusted with infrastructure privileges.

## Relationship with the Administrator

The Application Administrator may have operational responsibilities involving the platform, but administrative authority must remain separated conceptually into:

* application administration;
* infrastructure administration.

The administrator's ability to operate infrastructure does **not** create a cryptographic decryption capability.

In particular:

> Infrastructure authority must never be used as an alternative path to message or file plaintext.

This preserves the end-to-end confidentiality model established by the architecture.

## Deployment Environments

The architecture is intentionally independent of a specific deployment technology.

### MVP

The initial deployment environment may use:

* Docker;
* Docker Compose;
* CI/CD automation;
* PostgreSQL;
* simple operational scripts.

### Future

The same runtime architecture should be deployable using:

* Kubernetes;
* Minikube for local development;
* managed Kubernetes;
* multiple hosts;
* potentially distributed or geographically separated infrastructure.

The application services must not depend directly on Kubernetes-specific APIs.

## CI/CD

CI/CD belongs to the control plane.

A conceptual pipeline is:

```text
Source
  │
  ▼
Build
  │
  ▼
Unit Tests
  │
  ▼
Static / Security Analysis
  │
  ▼
Integration / Contract Tests
  │
  ▼
Container Image
  │
  ▼
Deployment
  │
  ▼
Health / Readiness Verification
```

A failed validation stage must prevent promotion of an invalid artifact.

The exact CI/CD architecture is an operational concern and may evolve independently from the runtime services.

## Service Lifecycle

The control plane is responsible for service lifecycle operations such as:

* start;
* stop;
* restart;
* upgrade;
* rollback;
* health verification.

Runtime services must nevertheless implement their own lifecycle behavior, including:

* initialization;
* readiness reporting;
* graceful shutdown;
* recovery from transient failures.

The distinction is important:

**The control plane decides when and where a service runs.**

**The service decides how it safely starts, operates, and shuts down.**

## Failure and Recovery

Control-plane failure should not automatically imply runtime data loss.

For example, if CI/CD or the deployment controller becomes temporarily unavailable:

* already-running services should continue operating;
* persisted messages should remain durable;
* encrypted files should remain available;
* existing communication should not require continuous deployment-plane availability.

This creates an important availability boundary between application runtime and infrastructure management.

Conversely, runtime failure should not automatically compromise the control plane.

## Performance Implications

Separating the control plane from runtime introduces negligible impact on the normal communication path because deployment operations do not participate in message delivery.

This is preferable to introducing deployment APIs or infrastructure orchestration into the critical request path.

Runtime performance therefore remains focused on:

* connection handling;
* encrypted message transport;
* message persistence;
* file transfer;
* delivery;
* audit operations.

The control plane can perform heavier operational tasks without competing directly with normal user traffic.

## Reliability Implications

The separation creates useful independence.

### Control plane unavailable

Runtime services should continue serving users as long as their existing runtime dependencies remain healthy.

### Runtime service unavailable

The control plane should remain capable of diagnosing, restarting, replacing, or rolling back the affected service.

### Deployment failure

A failed deployment must not automatically destroy the previous healthy runtime state.

This motivates future mechanisms such as:

* health-gated deployment;
* rollback;
* readiness checks;
* graceful shutdown;
* versioned artifacts.

The exact deployment strategy is outside this ADR.

## Testing and Validation

The architecture should validate the control-plane/runtime separation.

### Security tests

Verify that runtime service identities cannot:

* deploy containers;
* modify Kubernetes resources;
* access host-level infrastructure;
* retrieve unrelated infrastructure secrets.

### Failure tests

Verify that:

* control-plane outage does not unnecessarily terminate runtime services;
* deployment failure does not destroy durable messaging data;
* runtime service failure does not compromise deployment infrastructure.

### Deployment tests

Verify that a runtime service can be:

1. built;
2. tested;
3. packaged;
4. deployed;
5. health-checked;
6. rolled back if required.

### Operational tests

Verify that operators can determine:

* which service version is running;
* whether a service is healthy;
* whether deployment succeeded;
* whether rollback is required.

## Consequences

### Positive

* Clear separation of runtime and infrastructure responsibilities.
* Reduced runtime attack surface.
* Stronger privilege isolation.
* Smaller blast radius from runtime compromise.
* Cleaner Kubernetes evolution.
* Independent evolution of CI/CD and infrastructure.
* No deployment functionality in the critical communication path.
* Better operational reasoning.

### Negative

* Two architectural planes must be documented and understood.
* Infrastructure management becomes an explicit discipline.
* More operational concepts must be introduced.
* A sophisticated control-plane API may eventually be desirable for large deployments.

### Risks

#### Overengineering the control plane

The project could spend too much effort building deployment infrastructure rather than the secure communication platform.

**Mitigation:** keep the MVP control plane intentionally simple.

Docker Compose and CI/CD automation are sufficient initially.

#### Excessive administrator privileges

Infrastructure operators may have broad operational access.

**Mitigation:** enforce least privilege and maintain a strict distinction between operational authority and cryptographic authority.

#### Tight coupling to Kubernetes

Application services could accidentally depend on orchestration-specific behavior.

**Mitigation:** keep Kubernetes and container-orchestration concerns outside service business logic.

## Consequences for the MVP

For the academic MVP, the control plane should remain deliberately lightweight.

The project does **not** need to build a custom "Deploy microservice."

A reasonable initial model is:

```text
Git
 │
 ▼
CI/CD
 │
 ├── Build
 ├── Test
 ├── Security checks
 └── Package
       │
       ▼
Docker Compose
       │
       ├── Gateway
       ├── Auth
       ├── Messaging
       ├── Files
       └── Audit
```

The architecture nevertheless preserves a clean evolution path toward Kubernetes and more sophisticated infrastructure automation.

## Related Decisions

* **ADR-001 — Five Runtime Microservices**
* **ADR-003 — Distributed-First Architecture**
* **ADR-004 — Inter-Service Communication Model**
* **ADR-009 — Distributed Failure & Resilience Model**
* **ADR-010 — Service-to-Service Authentication & Authorization**
* **ADR-017 — Performance Benchmark Methodology**
* **ADR-018 — Post-MVP IPC / Shared Memory Optimization**

## Final Decision Summary

SecureCloud will maintain a strict separation between:

### Runtime Plane

Five independently deployable application services:

1. Gateway
2. Authentication
3. Messaging
4. Files
5. Audit

### Infrastructure / Control Plane

Responsible for:

* build;
* CI/CD;
* deployment;
* orchestration;
* infrastructure;
* configuration;
* monitoring;
* operational lifecycle.

**Deploy is therefore not a sixth runtime service and is not part of the five-service runtime architecture.**

The control plane may manage the runtime services, but runtime services must not inherently control the infrastructure that runs them.

Most importantly, **infrastructure or administrator authority must never become an exceptional cryptographic decryption path**.

This separation establishes a fundamental SecureCloud security principle:

> **The component capable of operating the infrastructure is not automatically capable of reading the data protected by the application.**
