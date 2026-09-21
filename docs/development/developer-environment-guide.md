# SecureCloud Developer Environment Guide

Welcome to the SecureCloud distributed engineering workspace. This guide provides the canonical onboarding instructions, architectural prerequisites, daily workflows, and verification procedures for building and running the SecureCloud distributed skeleton.

---

## 1. Supported Platform Matrix

SecureCloud is continuously built and verified across three primary developer platforms:

| Platform | Recommended Preset | Compiler | Dependency Source | Shell / CLI |
| :--- | :--- | :--- | :--- | :--- |
| **macOS (arm64 / x86_64)** | `dev-debug` or `ci-macos` | AppleClang 15+ / Clang 18 | Homebrew | zsh / bash |
| **Windows (MSVC)** | `ci-windows-msvc` | MSVC 2022 (`cl.exe` 19.38+) | vcpkg manifest mode | Developer PowerShell / cmd |
| **Windows (MinGW / GCC)** | `ci-windows-mingw` | MinGW-w64 GCC 14+ (UCRT64 / MINGW64) | MSYS2 pacman | PowerShell / MSYS2 bash |
| **Linux (x86_64 / arm64)** | `ci-linux` or `dev-debug` | GCC 13+ / Clang 17+ | System packages | bash |

For platform-specific toolchain installation and configuration, see:
- [macOS Platform Setup](platform-macos.md)
- [Windows MSVC Setup](platform-windows-msvc.md)
- [Windows MinGW / MSYS2 Setup](platform-windows-mingw.md)

---

## 2. Core Architectural Prerequisites

Before working with SecureCloud, ensure your workstation satisfies:
1. **Git**: Git 2.30+ with CRLF handling set to `input` (`git config --global core.autocrlf input`).
2. **CMake**: CMake 3.28+ (`cmake --version`).
3. **Ninja**: Ninja 1.11+ build system (`ninja --version`).
4. **Python**: Python 3.9+ (`python3 --version` or `py --version`).
5. **Docker & Docker Compose**:
   - Docker Desktop 4.25+ or Docker Engine with Docker Compose v2.20+.
   - Docker Compose must be accessible via `docker compose`.
   - WSL2 backend enabled on Windows.

> [!IMPORTANT]
> **Workstation Host PostgreSQL 14 Invariant**:
> If your developer workstation runs an active PostgreSQL 14 (or other DB) on `localhost:5432`:
> - SecureCloud **NEVER** binds to host port `5432`.
> - SecureCloud's containerized PostgreSQL 17 binds strictly to `127.0.0.1:5433:5432`.
> - The verification orchestrators use **purely observational** socket guards that never stop, restart, or alter host port `5432`.

---

## 3. Quickstart: Clone, Build & Local Verification

### Step 1: Clone the Repository
```bash
git clone https://github.com/sergey-chukhno/SecureCloud.git
cd SecureCloud
```

### Step 2: Generate Development PKI Certificates
SecureCloud uses mutual TLS (mTLS) for all service-to-service communication:
```bash
# On POSIX (macOS/Linux/MSYS2/Git Bash):
bash scripts/generate-dev-pki.sh

# On Windows PowerShell:
.\scripts\verify-local.ps1  # Automatically generates certificates if missing
```

### Step 3: Run Local Native Verification
Run the unified developer verification orchestrator to configure, format check, compile, validate Protobuf contracts, and run the CTest test suite:

```bash
# Auto-detects active platform preset (MinGW, MSVC, macOS, or Linux):
python3 scripts/verify-local.py

# Or on Windows PowerShell:
.\scripts\verify-local.ps1
```

**Expected Stage Output**:
```text
================ Verification Summary ================
  [PASSED]    0.43s  1. CMake Configure
  [PASSED]    0.17s  2. Formatting Check (.clang-format)
  [PASSED]   55.03s  3. Native Compilation & Build
  [PASSED]    0.12s  4. Protobuf & gRPC Contracts Validation
  [PASSED]    7.24s  5. CTest Execution Suite
-----------------------------------------------------
ALL CHECKS PASSED in 63.00s
```

---

## 4. Distributed Runtime & Container Infrastructure

SecureCloud utilizes Docker Compose for its distributed persistence and microservice skeleton.

### Topology & Effective Host Port Bindings

All exposed ports are strictly restricted to loopback (`127.0.0.1`):

| Service | Container Role | Container Port | Host Port Binding | Protocol |
| :--- | :--- | :--- | :--- | :--- |
| **`gateway`** | Entrypoint Reverse Proxy | 50051 | `127.0.0.1:50051` | gRPC mTLS |
| **`auth`** | Authentication Service | 50052 | `127.0.0.1:50052` | gRPC mTLS |
| **`messaging`**| Messaging Service | 50053 | `127.0.0.1:50053` | gRPC mTLS |
| **`files`** | Files Service | 50054 | `127.0.0.1:50054` | gRPC mTLS |
| **`audit`** | Audit Logging Service | 50055 | `127.0.0.1:50055` | gRPC mTLS |
| **`postgres`** | Relational DB (Auth & Files) | 5432 | `127.0.0.1:5433` | PostgreSQL 17.0 |
| **`scylladb`** | Distributed NoSQL (Messaging) | 9042 | `127.0.0.1:9042` | CQL |
| **`clickhouse`**| Append-Only OLAP (Audit) | 8123 / 9000 | `127.0.0.1:8123`, `127.0.0.1:9009` | HTTP / Native |
| **`minio`** | Object Storage (Files S3) | 9000 / 9001 | `127.0.0.1:9000`, `127.0.0.1:9001` | S3 API / Web Console |

### Starting the Distributed Environment
```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

### Stopping the Distributed Environment
```bash
# Non-destructive stop (preserves persistent volumes):
docker compose -f deploy/compose/docker-compose.yml down

# Destructive reset (wipes database volumes):
docker compose -f deploy/compose/docker-compose.yml down -v
```

---

## 5. Automated Distributed Verification

Run the full distributed development orchestrator to validate the complete lifecycle:
```bash
# On POSIX:
python3 scripts/verify-distributed-dev.py

# On Windows PowerShell:
.\scripts\verify-distributed-dev.ps1
```

### Orchestrator Lifecycle Stages
1. **Pre-flight Host PG14 Observational Guard**: Verifies `127.0.0.1:5432` without interfering.
2. **Port Bindings Audit**: Confirms all 11 exposed ports bind to `127.0.0.1` and container `postgres` maps strictly to host port `5433`.
3. **Local Native Verification**: Executes `verify-local.py` (build and test).
4. **Dev PKI Validation**: Verifies certificate SANs, validity, and CA signatures.
5. **Persistence Infrastructure Validation**: Verifies database-per-service isolation (`auth_user` vs `files_user`), role hardening, and volume retention across container recreation.
6. **Health & mTLS Probes & Outage Resilience**: Verifies all 5 microservices via `securecloud_health_probe`, tests fail-closed rejection on invalid SANs/CAs, and validates automatic readiness degradation and recovery during simulated container outages.
7. **Clean Infrastructure Teardown**: Stops and removes Compose containers.
8. **Post-flight Observational Guard**: Confirms host PostgreSQL 14 remains healthy and untouched.

---

## 6. Daily Development Workflows

### In-Place Code Formatting
```bash
# Format C++ code with clang-format:
cmake --build --preset dev-debug --target format

# Check formatting in read-only mode:
cmake --build --preset dev-debug --target check-format
# or:
bash scripts/check-formatting.sh
```

### Running CTest Suites
```bash
# Run all unit and integration tests:
ctest --preset dev-debug --output-on-failure

# Run a specific test suite:
ctest --preset dev-debug -R MtlsIntegrationTest --output-on-failure
ctest --preset dev-debug -R HealthIntegrationTest --output-on-failure
```

### Probing a Microservice Manually
```bash
# Probe auth service liveness over mTLS:
./build/dev-debug/tests/integration/securecloud_health_probe \
    --target 127.0.0.1:50052 \
    --server-name auth \
    --service-name "" \
    --ca deploy/dev-pki/ca/ca.crt \
    --cert deploy/dev-pki/services/gateway/gateway.crt \
    --key deploy/dev-pki/services/gateway/gateway.key \
    --expected-status SERVING

# Probe auth service readiness:
./build/dev-debug/tests/integration/securecloud_health_probe \
    --target 127.0.0.1:50052 \
    --server-name auth \
    --service-name "readiness" \
    --ca deploy/dev-pki/ca/ca.crt \
    --cert deploy/dev-pki/services/gateway/gateway.crt \
    --key deploy/dev-pki/services/gateway/gateway.key \
    --expected-status SERVING
```

---

## 7. Troubleshooting & Common Pitfalls

### 1. `gRPCConfig.cmake` or `protobuf-config.cmake` not found
- On Windows MinGW: Ensure `cmake/modules/SecureCloudDependencies.cmake` can locate MSYS2 (paths `C:/msys64/mingw64` or `C:/msys64/ucrt64`). If installed elsewhere, set `CMAKE_PREFIX_PATH=C:/your/msys64/mingw64`.
- On Windows MSVC: Ensure vcpkg manifest mode is active by specifying `CMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake`.
- On macOS: Ensure Homebrew is in PATH (`eval $(/opt/homebrew/bin/brew shellenv)`).

### 2. Port Conflict on 5432
SecureCloud binds container PostgreSQL to port `5433` specifically to prevent conflicts with workstation PostgreSQL 14. If you observe port binding errors, ensure no external process is listening on `5433`.

### 3. OpenSSL Certificate Errors during mTLS Handshake
- Regrow dev-pki certificates: `bash scripts/generate-dev-pki.sh --force`.
- Verify certificates: `bash scripts/verify-dev-pki.sh`.
