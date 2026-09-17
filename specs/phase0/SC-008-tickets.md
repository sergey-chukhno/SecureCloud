# SC-008 Implementation Tickets — Create Docker Compose Development Environment (Approved Specification)

**Card ID:** SC-008  
**Title:** Create Docker Compose Development Environment  
**Milestone:** M1 — Buildable Distributed Skeleton  
**Owner:** Sergey  
**Status:** Approved Specification Baseline  

---

### SC008-T01 — Define Development Docker Compose Configuration (deploy/compose/docker-compose.yml)

- **Objective:** Create `deploy/compose/docker-compose.yml` to orchestrate the five SecureCloud backend runtime services (`gateway`, `auth`, `messaging`, `files`, `audit`) into a coherent local development environment reflecting the approved distributed architecture.
- **Repository files/directories:**
  - `deploy/compose/docker-compose.yml` [NEW]
- **Dependencies:** SC-001 through SC-007
- **Implementation Approach:**
  - Define `deploy/compose/docker-compose.yml` utilizing Compose Specification format.
  - Define service entries using standard Compose service names and service DNS resolution: `gateway`, `auth`, `messaging`, `files`, `audit`. (Do NOT use explicit `container_name:` directives).
  - Configure build context pointing to repository root (`../../`) and specify respective SC-007 Dockerfile paths (`dockerfile: deploy/docker/<service>/Dockerfile`).
  - Define an isolated internal Compose bridge network (`securecloud-dev`).
  - Set `internal: true` on the `securecloud-dev` network, reflecting that current backend process skeletons have no outbound internet or external host network dependencies.
  - Preserve SC-007 non-root container identity (`USER 10001:10001`) natively defined in the image definitions without overriding `user` in Compose.
  - Do NOT expose fictional host ports (`ports:` omitted as backend services currently have no network listeners).
  - Do NOT configure restart policies (`restart: "no"` or omitted) as current service skeletons intentionally terminate cleanly with exit code 0 after process startup logging.
  - Do NOT configure fake healthchecks or readiness probes.
- **Architecture / security rules:**
  - Service isolation: Each service is built and deployed as an independent container.
  - Standard service naming & DNS: Services are referenced by service key (`gateway`, `auth`, `messaging`, `files`, `audit`).
  - No root containers: Preserves SC-007 `USER 10001:10001` identity.
  - Network isolation: Services attach to isolated bridge network (`securecloud-dev`). Network isolation is a deployment boundary, not an application security boundary replacing future TLS/mTLS/Auth.
  - No baked-in secrets, CA certificates, or TLS keys (owned by SC-009 / SC-010).
  - No database containers or storage volumes (owned by SC-011).
  - No fake health endpoints or readiness probes (owned by SC-013).
  - Client (`src/client`) is excluded (desktop application).
- **Validation:**
  - Validate syntax via `docker compose -f deploy/compose/docker-compose.yml config`.
- **Acceptance Criteria:**
  - `deploy/compose/docker-compose.yml` exists and validates cleanly with `docker compose config`.
  - All 5 backend services are defined using SC-007 Dockerfiles, root build context `../../`, standard service keys, and no explicit `container_name:`.
  - Services attach to `securecloud-dev` internal bridge network.
- **Out of scope:**
  - Client containerization, database containers, volumes, CA certificates, mTLS configuration, health endpoints, ports, restart policies.

---

### SC008-T02 — Validate Compose Build, Service Execution, and Network Topology

- **Objective:** Perform end-to-end empirical validation of the Docker Compose development environment, verifying image builds, service startup execution, non-root execution identity, network isolation, exit-code-0 lifecycle behavior, and host test suite integrity.
- **Repository files/directories:**
  - `specs/phase0/SC-008-tickets.md` (Specification baseline document)
- **Dependencies:** SC008-T01
- **Implementation Approach:**
  - Execute `docker compose -f deploy/compose/docker-compose.yml build` to build all 5 service images via Compose.
  - Execute `docker compose -f deploy/compose/docker-compose.yml up` to instantiate all 5 containers and verify process startup stdout logging:
    - `gateway` $\rightarrow$ `[SecureCloud] Starting Gateway Service (gateway) v0.1.0-dev` (Exit 0)
    - `auth` $\rightarrow$ `[SecureCloud] Starting Auth Service (auth) v0.1.0-dev` (Exit 0)
    - `messaging` $\rightarrow$ `[SecureCloud] Starting Messaging Service (messaging) v0.1.0-dev` (Exit 0)
    - `files` $\rightarrow$ `[SecureCloud] Starting Files Service (files) v0.1.0-dev` (Exit 0)
    - `audit` $\rightarrow$ `[SecureCloud] Starting Audit Service (audit) v0.1.0-dev` (Exit 0)
  - Verify container status and exit code 0 via `docker compose -f deploy/compose/docker-compose.yml ps -a`.
  - Verify non-root user identity (`UID 10001`) across all 5 containers via `docker inspect`.
  - Verify network creation and IP allocation on `securecloud-dev` network via `docker network inspect`.
  - Clean up environment via `docker compose -f deploy/compose/docker-compose.yml down`.
  - Run `./scripts/check-formatting.sh` and `ctest --preset dev-debug`.
- **Architecture / security rules:**
  - Empirically verifies non-root user execution inside Compose containers.
  - Confirms zero root capabilities and zero volume mounts required for Compose development environment.
- **Validation:**
  - `docker compose build`, `docker compose up`, `docker compose ps -a`, `docker network inspect`, `./scripts/check-formatting.sh`, `ctest --preset dev-debug`.
- **Acceptance Criteria:**
  - `docker compose build` succeeds for all 5 services.
  - `docker compose up` instantiates all 5 containers, logs process startup identity, and exits cleanly with status `0`.
  - Non-root user identity (`UID 10001:10001`) is verified for all 5 services.
  - Isolated bridge network `securecloud-dev` is created and used by all 5 services.
  - Formatting and host CTest test suite remain 100% green.
- **Out of scope:**
  - Long-running daemons, fake network listeners, fake health checks.

---

## Ticket Dependency Graph

```
  SC08-T01 (Define deploy/compose/docker-compose.yml)
       │
       ▼
  SC08-T02 (Validate Compose Build, Execution & Topology)
```

---

## Implementation Order & Parallelization

1. **SC08-T01**: Create `deploy/compose/docker-compose.yml` configuration file.
2. **SC08-T02**: Perform end-to-end `docker compose` build, startup execution, non-root user verification, network inspection, and CTest/formatting checks.

*Note: Tickets must be executed sequentially. SC08-T02 depends directly on the configuration produced by SC08-T01.*

---

## Potential Blockers & Risks

- **Exit-Code-0 Skeleton Behavior**: Current SC-006 service skeletons execute startup logging and exit immediately with status 0. In Docker Compose, running `docker compose up` will start all 5 containers, print startup logs, and exit status 0. This is the honest representation of the current application state. No artificial restart policies or sleep loops will be added.
- **No Fictional Network Listeners or Ports**: Backend services currently do not open network ports. `ports:` directives are omitted from `docker-compose.yml` to prevent exposing fictional ports before network listeners are implemented in subsequent cards.

---

## Approved Architectural Decisions Baseline

1. **Compose File Path**: `deploy/compose/docker-compose.yml` (located inside the established `deploy/compose/` directory).
2. **Build Context Path**: Root directory `../../` relative to `deploy/compose/docker-compose.yml`.
3. **Bridge Network Name**: `securecloud-dev` (internal bridge network `internal: true`).
4. **Standard Service Naming**: `gateway`, `auth`, `messaging`, `files`, `audit` (no explicit `container_name:`).
5. **Honest Skeleton Lifecycle**: Services terminate with exit code 0 after startup logging. Compose runs with default `restart: "no"`.
