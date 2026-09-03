# ADR-003 — Distributed-First Architecture

**Status:** Approved
**Date:** 2026-09-02
**Decision Owners:** SecureCloud Architecture Team

## Context

ADR-001 established SecureCloud's five runtime microservices:

1. Gateway
2. Authentication
3. Messaging
4. Files
5. Audit

ADR-002 established the separation between the runtime plane and the infrastructure/control plane.

The next architectural question is how these runtime services are expected to behave with respect to their physical deployment topology.

SecureCloud is intended to evolve from an academic MVP toward a production-oriented architecture capable of operating in distributed and potentially constrained environments.

The services may initially run together on a development machine using Docker Compose. However, the architecture must not assume that services will always be colocated.

In a future deployment, services may run:

* in different containers;
* on different hosts;
* on different availability zones;
* on different network segments;
* in Kubernetes;
* in geographically separated environments;
* potentially across constrained or alternative network infrastructures.

This creates an important architectural distinction:

> **The logical service architecture must not depend on the physical topology in which the services happen to run.**

Without this decision, the project could gradually become a collection of "microservices" that only work efficiently or correctly when deployed together on the same machine.

This ADR therefore establishes the distributed-first principle.

## Decision Drivers

The decision is driven by:

1. **Independent deployment**

   * Services must remain independently deployable regardless of physical location.

2. **Topology independence**

   * Moving a service to another host must not require redesigning the service boundary.

3. **Failure isolation**

   * Network failures and service failures must be treated as normal distributed-system conditions.

4. **Scalability**

   * Services should be independently scalable when workload characteristics require it.

5. **Security isolation**

   * A service should not gain additional trust merely because it happens to run on the same host as another service.

6. **Future Kubernetes deployment**

   * The architecture should naturally support Kubernetes without requiring application-level redesign.

7. **Extreme-environment evolution**

   * SecureCloud may eventually need to operate across degraded, intermittent, disconnected, satellite, mesh, or tactical network environments.

8. **Performance optimization without architectural coupling**

   * Low-level optimizations such as IPC or shared memory should improve performance without becoming architectural dependencies.

## Considered Alternatives

### Alternative A — Colocated Services

Run all runtime services together on the same host and optimize communication around local execution.

```text
┌─────────────────────────────────────────┐
│                  Host                   │
│                                         │
│ Gateway ── Auth ── Messaging ── Files  │
│                    │                    │
│                   Audit                  │
│                                         │
└─────────────────────────────────────────┘
```

Communication could rely heavily on local networking, Unix sockets, IPC, or shared memory.

**Advantages**

* Low communication latency.
* Simple initial deployment.
* Potentially high throughput.
* Easier local debugging.
* Shared-memory optimizations are possible.

**Disadvantages**

* Strong physical-topology dependency.
* Difficult independent scaling.
* Host failure can affect the entire platform.
* Local IPC cannot naturally cross hosts.
* Kubernetes distribution becomes more complicated.
* Deployment topology becomes part of the application architecture.
* Security assumptions may accidentally depend on colocation.

**Decision:** Rejected as the architectural baseline.

---

### Alternative B — Distributed-First Architecture

Design every runtime service as an independently deployable component that communicates through explicit network-accessible contracts.

Services may be colocated initially, but the architecture does not depend on colocation.

```text
             ┌─────────┐
             │ Gateway │
             └────┬────┘
                  │
          Network contracts
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
     Auth     Messaging     Files
                  │
                  ▼
                Audit
```

The same architecture remains valid whether services run on one host or many.

**Advantages**

* Topology independence.
* Natural distributed deployment.
* Independent scaling.
* Strong service boundaries.
* Natural Kubernetes evolution.
* Better failure isolation.
* Compatible with future constrained-network deployments.
* Allows local performance optimizations without making them mandatory.

**Disadvantages**

* Network latency.
* Network failures.
* More complex service coordination.
* More complex testing.
* Requires distributed-systems resilience mechanisms.

**Decision:** **Selected.**

---

### Alternative C — Hybrid IPC + Network Fallback

Use IPC/shared memory when services are colocated and network communication when they are separated.

```text
Same host:
    Messaging ── IPC ── Files

Different hosts:
    Messaging ── Network ── Files
```

**Advantages**

* Potentially combines local performance with distributed deployment.
* Can exploit shared memory for high-throughput workloads.
* Network communication remains available for remote deployments.

**Disadvantages**

* Two communication mechanisms must be maintained.
* Behavior can differ depending on deployment topology.
* More complex testing.
* More complex observability.
* More complex failure semantics.
* IPC can become a hidden architectural dependency.
* Performance characteristics may differ significantly between environments.
* Optimization can influence service design prematurely.

**Decision:** Rejected as the MVP architecture.

IPC/shared memory may be reconsidered later as an optimization under a separate ADR.

---

### Alternative D — Distributed Architecture Only for Production

Build the MVP as a colocated architecture and redesign it for distribution later.

**Advantages**

* Potentially simpler academic implementation.
* Less distributed-systems complexity during the initial phase.

**Disadvantages**

* Migration from colocated assumptions can require major architectural changes.
* Early interfaces may become incompatible with distributed deployment.
* Security and failure assumptions may need to be redesigned.
* IPC or direct database access could become deeply embedded in the implementation.

**Decision:** Rejected.

The architecture should establish the distributed boundary from the beginning, even if the initial deployment is simple.

## Decision

SecureCloud adopts a **distributed-first architecture**.

The five runtime services must be designed as independently deployable components whose correctness does not depend on physical colocation.

The fundamental rule is:

> **Deployment topology must not define service boundaries.**

A service must therefore be able to communicate with another service through its defined service contract regardless of whether the target service is:

* in the same container environment;
* on the same host;
* on another host;
* in another cluster;
* in another network segment.

For the MVP, Docker Compose may run all services on a single development machine.

This is a deployment convenience, not an architectural dependency.

## Network Communication as the Baseline

Inter-service communication will use network-accessible service contracts as the architectural baseline.

Conceptually:

```text
┌─────────────┐
│   Gateway   │
└──────┬──────┘
       │
       │ network
       ▼
┌─────────────┐
│     Auth    │
└─────────────┘

┌─────────────┐
│  Messaging  │
└──────┬──────┘
       │
       │ network
       ▼
┌─────────────┐
│    Files    │
└─────────────┘
```

The precise protocols, serialization formats, synchronous/asynchronous patterns, and potential message broker will be determined by **ADR-004 — Inter-Service Communication Model**.

This ADR intentionally does not select a specific protocol.

## Deployment Topology

The architecture supports multiple deployment topologies.

### Development

```text
Single developer machine

┌─────────────────────────────────┐
│          Docker Compose         │
│                                 │
│ Gateway                         │
│ Auth                            │
│ Messaging                       │
│ Files                           │
│ Audit                           │
└─────────────────────────────────┘
```

### Distributed deployment

```text
Host A             Host B             Host C

Gateway ─────────► Auth
   │
   └─────────────► Messaging ───────► Files
                         │
                         └──────────► Audit
```

Both deployments implement the same logical architecture.

The application must not contain logic equivalent to:

> "If the service is running locally, use a fundamentally different service contract."

Topology may affect configuration and performance, but must not change the architectural meaning of the interaction.

## Failure Model

Once services are treated as distributed components, network failure becomes a first-class architectural condition.

The architecture must assume that:

* a service may be unavailable;
* a network connection may fail;
* requests may time out;
* responses may be delayed;
* a connection may be interrupted;
* a request may be retried;
* duplicate requests may occur;
* one service may be healthy while another is unavailable.

This does not mean every service must always remain available.

Instead, services must fail in controlled and observable ways.

Detailed resilience mechanisms are deferred to later ADRs.

## Security Implications

Distributed-first architecture strengthens the security model by preventing implicit trust based on physical colocation.

Two services running on the same machine must not automatically be considered trusted merely because they share a host.

Likewise, two services running on different hosts must use the same explicit service-level security model.

This supports:

* service authentication;
* service authorization;
* least privilege;
* encrypted inter-service communication;
* bounded trust relationships;
* containment of compromised services.

These mechanisms will be formally addressed by later security ADRs.

### No host-based trust shortcut

The architecture must not rely on assumptions such as:

> "This service is safe because it runs on localhost."

Localhost is a network location, not a security identity.

## Performance Implications

Distributed communication introduces unavoidable overhead:

* serialization/deserialization;
* network transmission;
* kernel/network processing;
* scheduling;
* latency;
* connection management.

This cost is accepted as part of the architectural model.

Performance optimizations must therefore be evaluated against measured bottlenecks.

The optimization process is:

```text
Baseline
   │
   ▼
Benchmark
   │
   ▼
Profile
   │
   ▼
Identify bottleneck
   │
   ▼
Optimize
   │
   ▼
Benchmark again
```

Potential future optimizations include:

* connection reuse;
* batching;
* binary serialization;
* reduced copies;
* asynchronous processing;
* zero-copy techniques;
* local IPC;
* shared memory.

However:

> **An optimization must not become a prerequisite for correctness.**

## IPC and Shared Memory

IPC and shared memory are explicitly **not part of the baseline architecture**.

They may be introduced later if profiling demonstrates that network communication creates a significant bottleneck for a specific interaction.

Such an optimization must satisfy three requirements:

1. Network communication remains a valid architectural path.
2. The optimization is justified by measured performance data.
3. Removing the optimization does not invalidate the service architecture.

This topic will be addressed separately by **ADR-018 — Post-MVP IPC / Shared Memory Optimization**.

## Reliability Implications

The distributed-first decision requires the system to explicitly address partial failures.

For example:

### Messaging → Files failure

Messaging must not assume Files is always available.

### Gateway → Auth failure

Gateway must have defined behavior when authentication is unavailable.

### Messaging → Audit failure

The architecture must define whether audit recording is:

* synchronous;
* asynchronous;
* buffered;
* durable before acknowledgment;
* allowed to degrade temporarily.

These details are deliberately deferred to the communication and resilience ADRs.

The important decision here is that **partial failure must be expected rather than treated as an exceptional architectural violation**.

## Offline and Degraded Environments

Distributed-first architecture is particularly important for SecureCloud because the platform is intended to evolve toward environments where connectivity may be unreliable.

Potential future environments include:

* intermittent Internet;
* cellular networks;
* Wi-Fi;
* mesh networking;
* satellite communication;
* disconnected operation;
* store-and-forward networks;
* future tactical networking.

The architecture therefore must not assume:

> "All services are always reachable with low latency."

Instead, service contracts and reliability mechanisms must allow the system to evolve toward degraded and intermittent connectivity.

The detailed offline architecture will be addressed separately.

## Testing and Validation

The distributed-first decision must be validated through deployment and failure testing.

### Topology tests

The same services should be tested in at least:

1. single-host Docker Compose;
2. distributed multi-container topology;
3. simulated network latency;
4. simulated network failure.

### Failure tests

Test:

* service unavailable;
* connection refused;
* connection timeout;
* delayed response;
* connection interruption;
* service restart;
* network partition.

### Security tests

Verify that:

* local deployment does not bypass service authentication;
* service identity is independent of host identity;
* network boundaries do not expose plaintext;
* one compromised service cannot automatically access another service's protected resources.

### Performance tests

Measure the cost of distributed communication and establish a baseline before introducing IPC/shared-memory optimizations.

## Consequences

### Positive

* Strong topology independence.
* Distributed deployment from the beginning.
* Easier Kubernetes evolution.
* Independent service scaling.
* Better failure isolation.
* Clear security boundaries.
* Compatibility with future constrained-network environments.
* Prevents premature coupling to local IPC.

### Negative

* Increased architectural complexity.
* Network overhead.
* More difficult local debugging.
* Distributed failure modes.
* More demanding integration and failure testing.
* Greater operational complexity.

### Risks

#### Premature distributed complexity

A student project can become unnecessarily complex if distributed-system mechanisms are introduced everywhere.

**Mitigation:** establish distributed boundaries now but implement only the mechanisms justified by actual requirements.

#### Performance degradation

Network communication may become a bottleneck.

**Mitigation:** benchmark first, profile bottlenecks, and optimize only where evidence justifies it.

#### Overuse of asynchronous communication

Distributed-first architecture might encourage unnecessary event-driven complexity.

**Mitigation:** choose synchronous or asynchronous communication based on the semantics of each interaction. This is addressed in ADR-004.

#### Future IPC complexity

Local IPC may eventually be attractive for performance.

**Mitigation:** keep network contracts as the canonical architectural interface and treat IPC as an optional optimization.

## MVP Boundary

The MVP does **not** need to demonstrate deployment across multiple physical machines.

It must, however, preserve the architecture necessary to support such deployment.

Therefore:

**Required for MVP:**

* independently deployable services;
* network-based service communication;
* explicit service contracts;
* Docker Compose deployment;
* service-level configuration;
* failure-aware communication;
* health/readiness behavior.

**Not required for MVP:**

* Kubernetes production deployment;
* multi-region deployment;
* service mesh;
* multi-cluster deployment;
* mesh networking;
* satellite networking;
* tactical networking;
* shared-memory service communication.

These remain evolution paths rather than MVP requirements.

## Related Decisions

* **ADR-001 — Five Runtime Microservices**
* **ADR-002 — Runtime vs Infrastructure Control Plane**
* **ADR-004 — Inter-Service Communication Model**
* **ADR-009 — Distributed Failure & Resilience Model**
* **ADR-010 — Service-to-Service Authentication & Authorization**
* **ADR-017 — Performance Benchmark Methodology**
* **ADR-018 — Post-MVP IPC / Shared Memory Optimization**

## Final Decision Summary

SecureCloud adopts a **distributed-first architecture**.

The five runtime services are independently deployable and communicate through network-accessible service contracts.

The architecture remains valid whether services are colocated or distributed across multiple hosts.

Docker Compose is an initial deployment convenience, not an architectural constraint.

Local IPC and shared memory are explicitly deferred to a post-MVP optimization decision and must never become required for correctness.

The fundamental architectural principle is:

> **SecureCloud's service boundaries are logical boundaries, not physical boundaries.**
