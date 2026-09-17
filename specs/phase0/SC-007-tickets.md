# SC-007 Implementation Tickets — Create Service Dockerfiles (Revised Specification)

**Card ID:** SC-007  
**Title:** Create service Dockerfiles  
**Milestone:** M1 — Buildable Distributed Skeleton  
**Owner:** Sergey  
**Status:** Approved Specification Baseline  

---

### SC007-T01 — Establish Root Build Context Rules (.dockerignore)

- **Objective:** Configure repository-wide `.dockerignore` to restrict Docker build context size, optimize layer caching, and prevent inclusion of build trees, developer tooling artifacts, git history, IDE settings, and potential local secrets/credentials.
- **Exact Files Affected:**
  - `.dockerignore` [NEW]
- **Dependencies:** SC-001, SC-002, SC-006
- **Implementation Approach:**
  - Create `.dockerignore` in repository root directory.
  - Exclude build output trees: `build/`, `cmake-build-*/`, `.cache/`, `vcpkg_installed/`.
  - Exclude local IDE and system files: `.vscode/`, `.idea/`, `.antigravity/`, `.DS_Store`.
  - Exclude version control metadata: `.git/`, `.gitignore`, `.gitattributes`.
  - Exclude secret patterns and private material: `*.pem`, `*.crt`, `*.key`, `.env*`, `*.log`.
  - Exclude non-build documentation and metadata: `docs/`, `specs/`, `benchmarks/`, `*.md`.
- **Security Considerations:** Excludes sensitive developer assets (SSH/TLS keys, `.env` files, build logs, cache directories) from being transferred to the Docker daemon build context or copied into image layers.
- **Build/Runtime Considerations:** Reduces Docker build context size from hundreds of megabytes to a few kilobytes, ensuring fast and reproducible Docker builds.
- **Tests & Validation:** Verify build context filtering by running `docker build` dry-run checks and inspecting context transfer size.
- **Acceptance Criteria:**
  - `.dockerignore` exists in repository root.
  - Docker build context excludes `.git`, `build/`, IDE directories, documentation, and secret/key patterns.

---

### SC007-T02 — Define Multi-Stage Dockerfiles for Five Backend Services

- **Objective:** Create secure, minimal, reproducible baseline container images for the five backend runtime services (`gateway`, `auth`, `messaging`, `files`, `audit`) under `deploy/docker/<service>/Dockerfile`.
- **Exact Files Affected:**
  - `deploy/docker/gateway/Dockerfile` [NEW]
  - `deploy/docker/auth/Dockerfile` [NEW]
  - `deploy/docker/messaging/Dockerfile` [NEW]
  - `deploy/docker/files/Dockerfile` [NEW]
  - `deploy/docker/audit/Dockerfile` [NEW]
- **Dependencies:** SC007-T01, SC-005, SC-006
- **Toolchain & Base Image Justification:**
  - **Builder Image (`ubuntu:24.04` version-tagged candidate)**: Selected because `ubuntu:24.04` natively satisfies project build requirements established in SC-001 through SC-006: GCC 13+ with full C++20 support (`cxx_std_20`), CMake 3.28+, Ninja generator, Protobuf 3.21+ (`libprotobuf-dev`), `protoc` compiler (`protobuf-compiler`), gRPC 1.51+ (`libgrpc++-dev`), and `grpc_cpp_plugin` (`protobuf-compiler-grpc`). Preserves existing `SecureCloudDependencies.cmake` and `SecureCloudProtobuf.cmake` discovery pipelines without altering build architecture.
  - **Runtime Image (`ubuntu:24.04` minimal baseline candidate)**: Provides glibc and C++ runtime library ABI compatibility (`libstdc++6`, `libc6`). Installs only exact runtime shared-library packages required for dynamic execution, excluding headers, development tooling, compilers (`g++`, `clang`), `protoc`, and static build libraries. Package caches are cleaned via `rm -rf /var/lib/apt/lists/*`.
  - **Version-Tag Pinning**: Uses explicit version-tag pinning (`ubuntu:24.04`) for build reproducibility across environments, avoiding floating `latest` tags while omitting manual image digest hash pinning complexity.
- **Implementation Approach:**
  - Create distinct, service-isolated Dockerfiles under `deploy/docker/<service>/Dockerfile` for each backend service (`gateway`, `auth`, `messaging`, `files`, `audit`).
  - Structure each Dockerfile with a two-stage build architecture:
    1. **Builder Stage (`builder`)**:
       - `FROM ubuntu:24.04 AS builder`
       - Install required build packages via `apt-get --no-install-recommends`: `build-essential`, `g++`, `cmake`, `ninja-build`, `pkg-config`, `libprotobuf-dev`, `protobuf-compiler`, `libgrpc++-dev`, `protobuf-compiler-grpc`.
       - Copy repository source tree into container workspace `/workspace`.
       - Configure CMake out-of-source using Release configuration: `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release`.
       - Compile target service executable: `cmake --build build --target securecloud-<service>`.
    2. **Runtime Stage (`runtime`)**:
       - `FROM ubuntu:24.04 AS runtime`
       - Install only required runtime dynamic library packages (`libprotobuf32t64`, `libgrpc++1.51t64`, `libstdc++6`, `libc6` or minimal dynamic library equivalents) with `--no-install-recommends` and remove package caches (`rm -rf /var/lib/apt/lists/*`).
       - Create dedicated non-system non-root user and group: `securecloud:securecloud` with fixed UID/GID `10001:10001`.
       - Copy compiled binary from builder stage `/workspace/build/src/<service>/securecloud-<service>` to `/usr/local/bin/securecloud-<service>`.
       - Apply strict file ownership (`securecloud:securecloud`) and read/execute permissions (`0555`).
       - Switch runtime identity: `USER 10001:10001`.
       - Configure exec-form entry point: `ENTRYPOINT ["/usr/local/bin/securecloud-<service>"]`.
- **Security Considerations:**
  - Non-root container execution (`USER 10001:10001`).
  - Strict removal of compilers, CMake, headers, `protoc`, and static libraries from final runtime container.
  - Cleaned package manager caches (`/var/lib/apt/lists/*`).
  - Executable permissions restricted to read-and-execute only (`0555`).
  - Read-only root filesystem compatible (no write access required).
  - Exec form ENTRYPOINT ensures direct POSIX signal delivery to service binary without shell wrapper (`PID 1`).
  - No embedded secrets, TLS keys, mock certificates, host paths, or `.env` files.
- **Build/Runtime Considerations:**
  - Each backend service image is independently deployable without cross-service image or source dependencies.
  - Preserves existing SC-005 CMake Protobuf/gRPC generation pipeline.
  - No custom abstraction frameworks or generic Docker build scripts introduced.
- **Tests & Validation:** Validate Dockerfile syntax and multi-stage build execution for each backend service.
- **Acceptance Criteria:**
  - Distinct Dockerfile exists for each of the five backend services under `deploy/docker/<service>/Dockerfile`.
  - Multi-stage build structure isolates build toolchain from runtime image.
  - Runtime image runs under non-root user `10001:10001` with exec-form `ENTRYPOINT`.

---

### SC007-T03 — Docker Build and Runtime Container Validation

- **Objective:** Validate the five backend service Docker images by executing end-to-end container builds, verifying non-root container instantiation across all five services, confirming clean process startup logging and exit status 0 (reflecting current SC-006 skeleton behavior), and confirming SC-004 formatting and SC-005/SC-006 test suite compliance.
- **Exact Files Affected:**
  - Validation commands & verification suite.
- **Dependencies:** SC007-T01, SC007-T02
- **Implementation Approach:**
  - Execute Docker build commands for all 5 service images from repository root:
    - `docker build -f deploy/docker/gateway/Dockerfile -t securecloud-gateway:test .`
    - `docker build -f deploy/docker/auth/Dockerfile -t securecloud-auth:test .`
    - `docker build -f deploy/docker/messaging/Dockerfile -t securecloud-messaging:test .`
    - `docker build -f deploy/docker/files/Dockerfile -t securecloud-files:test .`
    - `docker build -f deploy/docker/audit/Dockerfile -t securecloud-audit:test .`
  - Instantiate containers and verify process startup logging and exit code 0:
    - `docker run --rm securecloud-gateway:test` -> expect startup stdout and exit code `0`.
    - `docker run --rm securecloud-auth:test` -> expect startup stdout and exit code `0`.
    - `docker run --rm securecloud-messaging:test` -> expect startup stdout and exit code `0`.
    - `docker run --rm securecloud-files:test` -> expect startup stdout and exit code `0`.
    - `docker run --rm securecloud-audit:test` -> expect startup stdout and exit code `0`.
    *(Note: Exit code 0 validation reflects the current SC-006 process skeleton entry point behavior, where main functions log identity and return 0. It is a validation of the current skeleton executable behavior, not a permanent service lifecycle requirement.)*
  - Empirically validate non-root user identity (`UID 10001`) across **all five** service containers:
    - `docker run --rm --entrypoint id securecloud-gateway:test` -> expect `uid=10001(securecloud) gid=10001(securecloud)`.
    - `docker run --rm --entrypoint id securecloud-auth:test` -> expect `uid=10001(securecloud) gid=10001(securecloud)`.
    - `docker run --rm --entrypoint id securecloud-messaging:test` -> expect `uid=10001(securecloud) gid=10001(securecloud)`.
    - `docker run --rm --entrypoint id securecloud-files:test` -> expect `uid=10001(securecloud) gid=10001(securecloud)`.
    - `docker run --rm --entrypoint id securecloud-audit:test` -> expect `uid=10001(securecloud) gid=10001(securecloud)`.
  - Run `./scripts/check-formatting.sh` to confirm formatting compliance.
  - Run `ctest --preset dev-debug` to confirm host test suite integrity.
- **Security Considerations:** Empirically verifies container user isolation, signal execution, and non-root execution inside runtime container environments across all 5 services.
- **Tests & Validation:** `docker build`, `docker run`, `./scripts/check-formatting.sh`, and `ctest --preset dev-debug`.
- **Acceptance Criteria:**
  - All 5 Docker service images build successfully.
  - All 5 containers run, log process startup string, and exit with code `0`.
  - Non-root user identity (`10001:10001`) is verified for all 5 backend service containers.
  - Formatting and host CTest test suite remain 100% green.

---

## Dependency Graph

```
  SC007-T01 (Establish .dockerignore)
       │
       ▼
  SC007-T02 (Five Multi-Stage Service Dockerfiles)
       │
       ▼
  SC007-T03 (Docker Build & Runtime Container Validation)
```

---

## Scope Boundaries & Explicit Non-Goals

SC-007 creates service Dockerfiles ONLY. It explicitly does NOT implement:
- Client (`src/client`) Dockerfile (Client is a desktop application, not a backend runtime service)
- Docker Compose setup (SC-008)
- Kubernetes manifests, Helm charts, Kustomize, or service mesh
- TLS certificates, CA infrastructure, or mTLS configuration (SC-009 / SC-010)
- Database containers or persistence storage (SC-011)
- Configuration management framework (SC-012)
- Network listeners, fake HTTP/gRPC ports, or fake health endpoints (SC-013)
- CI/CD container registry integration or image signing infrastructure
- Vulnerability scanning or runtime observability stack

---

## Risks, Assumptions & Blockers

- **Base Image Candidate Justification:** Using `ubuntu:24.04` natively satisfies GCC 13+, C++20 runtime support, CMake 3.28+, Protobuf 3.21+, gRPC 1.51+, and `grpc_cpp_plugin`.
- **Host Docker Environment:** Requires Docker daemon running on host system to perform SC007-T03 container validation.
- **No Fictional Ports or Healthchecks:** Services currently execute startup logic and terminate cleanly with code 0. Dockerfiles honestly reflect this state.
