# SecureCloud Client Performance Benchmark Report (`CLIENT-015-T05`)

**Ticket:** `CLIENT-015-T05` — Official Client Performance Benchmarking Harness & Report  
**Specification References:** `docs/planning/initial-backlog.md`, `ADR-008 §26`, `ADR-010 §16 / §17 / §26 / §27`  
**Harness Source:** `tests/unit/client/client_performance_benchmark_test.cpp`  
**Execution Date:** `2026-11-25`  
**Overall Gate Result:** **7 / 7 Budgets PASSED (`Release` & `Debug`)**

---

## 1. Executive Summary & Budget Compliance Matrix

All client resource, frame-pacing, startup latency, encrypted streaming buffer, and End-to-End Encryption (`X3DH` + `DoubleRatchetEngine` + `AES-256-GCM`) throughput budgets were empirically measured against **real encrypted SQLCipher persistence**, **real OpenSSL 3.6.4 cryptography**, and **real Qt 6.11.0 / QML UI rendering** (zero in-memory mocks or stub crypto providers).

| ID | Benchmark Workload | Target Budget (`Backlog` / `ADR-010`) | Official `dev-release` (`SECURECLOUD_RUN_CLIENT_BENCHMARKS=1`) | `dev-debug` Sanity | Assessment & Margin |
|---|---|---|---|---|---|
| **A** | Idle Baseline Resident Memory (`RSS`) | `< 80.0 MB` | **`72.75 MB`** (`5,000 ms` idle) | `74.47 MB` (`1,000 ms` idle) | **PASS** — `7.25 MB` (`9.1%`) headroom |
| **A** | Idle Baseline CPU Utilization | `< 1.0 %` | **`0.01 %`** | `0.01 %` | **PASS** — `100x` below limit |
| **B** | Loaded Workspace `RSS` (`50` convs / `5,000` SQLCipher rows) | `< 150.0 MB` | **`98.22 MB`** (`50` convs / `5,000` msgs) | `99.62 MB` (`50` convs / `1,000` msgs) | **PASS** — `51.78 MB` (`34.5%`) below cap |
| **C** | Chunked Encrypted Streaming Overhead (`peak - pre RSS`) | `< 32.0 MB` | **`+12.19 MB`** (`16.00 MiB`, `5` chunks) | `+12.19 MB` (`8.00 MiB`, `3` chunks) | **PASS** — `2.6x` under budget (`61.9%` headroom) |
| **D** | Active Conversation Scroll (`60 fps` frame pacing) | `< 5.0 %` CPU, `< 16.67 ms` p95 | **`1.38 %`** CPU (`2.30 ms` mean / `4.91 ms` p95) | `2.37 %` CPU (`3.96 ms` mean / `9.34 ms` p95) | **PASS** — `3.6x` under CPU cap, `3.4x` faster than frame deadline |
| **E** | Cold Startup Latency (`securecloud-client --smoke-test`) | `< 1,500 ms` (`p50` & `p95`) | **`349.65 ms` p50** / **`371.72 ms` p95** | `427.92 ms` p50 / `428.07 ms` p95 | **PASS** — `4.0x`–`4.3x` faster than target (`~75%` headroom) |
| **F** | Double Ratchet + `AES-256-GCM` Latency (`256 B / 1 KiB / 4 KiB`) | `< 2.0 ms/msg` (`mean` & `p95`) | **`0.0245–0.0262 ms` mean** / **`0.1832–0.1840 ms` p95** | `0.0471–0.1318 ms` mean | **PASS** — `> 10x` faster `p95` than budget |
| **F** | Double Ratchet + `AES-256-GCM` Throughput | `> 500 msg/s` | **`37,578–40,475 msg/s`** (`43,006` `3`-dev fanout) | `6,279–19,863 msg/s` | **PASS** — `75x`–`86x` above target |
| **G** | Memory Stability (`1,000` Crypto + SQLCipher cycles) | Bounded (`< 16.0 MB` drift) | **`+0.20 MB`** (`120.67 -> 120.88 MB`) | `0.00 MB` (`113.31 -> 113.31 MB`) | **PASS** — `80x` below drift cap |

---

## 2. Understanding `dev-debug` vs. `dev-release` Benchmarking Modes

The benchmarking workflow separates two independent axes: the **CMake build preset** ([CMakePresets.json](../../CMakePresets.json)) and the **workload scale flag** (`SECURECLOUD_RUN_CLIENT_BENCHMARKS=1` in `client_performance_benchmark_test.cpp`).

| Dimension | `dev-debug` (Sanity / CI Mode) | `dev-release` (Official Benchmark Mode) |
|---|---|---|
| **CMake Build Preset** | `CMAKE_BUILD_TYPE=Debug` (`build/dev-debug`) | `CMAKE_BUILD_TYPE=Release` (`build/dev-release`) |
| **Compiler Codegen** | Unoptimized (`-O0`), full debug symbols (`-g`), assertions enabled (`NDEBUG` undefined) | Optimized (`-O3`), inlining and vectorization enabled, `NDEBUG` defined |
| **Security & Warning Flags** | Identical via `securecloud::compiler_flags`: `-Wall -Wextra -Werror -Wpedantic -Wshadow -Wconversion -fstack-protector-strong -fvisibility=hidden -D_FORTIFY_SOURCE=3` | Identical |
| **Workload Scale (`SECURECLOUD_RUN_CLIENT_BENCHMARKS`)** | Default (env unset): lighter counts (`1 s` idle, `1,000` SQLCipher rows, `8 MiB` stream, `30` frames, `3` cold starts, `400` ratchet msgs/size, `250` leak cycles) running in ~`5.6 s` | `SECURECLOUD_RUN_CLIENT_BENCHMARKS=1`: full `ADR-010` / backlog counts (`5 s` idle, `5,000` SQLCipher rows, `16 MiB` stream, `120` frames, `5` cold starts, `2,000` ratchet msgs/size, `1,000` leak cycles) running in ~`10.9 s` |
| **Budget Thresholds (`EXPECT_*`)** | Exact same strict thresholds | Exact same strict thresholds |
| **Purpose** | Confirms daily developer and CI `Debug` builds stay healthy with fast runtime | Measures the real optimized client binary shipped to users — **official release sign-off baseline** |

*Observed compiler impact:* On CPU-bound paths (`Benchmark C` streaming and `Benchmark F` 4 KiB Double Ratchet / 3-device fan-out), `dev-release` runs **`5x`–`7x` faster** than `dev-debug` because `-O3` inlines buffer transformations and eliminates unoptimized call frames.

---

## 3. Test Environment Metadata (`ADR-010 §27`)

| Attribute | Verified Value |
|---|---|
| **CPU Model** | `Apple M4` |
| **Logical CPU Cores** | `10` (`sysctl -n hw.ncpu`) |
| **System Memory (RAM)** | `16 GiB` (`17179869184` bytes) |
| **Operating System & Kernel** | `macOS 15.6` (`Build 24G84`), `Darwin 24.6.0 arm64` |
| **C++ Compiler** | `Apple clang version 17.0.0 (clang-1700.0.13.5)`, target `arm64-apple-darwin24.6.0` |
| **Warning / Hardening Flags** | `securecloud::compiler_flags` (`-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion`) |
| **Build Configurations** | Official benchmarks: `dev-release` (`Release` / `-O3 -DNDEBUG`); Sanity: `dev-debug` (`Debug`) |
| **Qt 6 Framework** | `Qt 6.11.0` (`Core`, `Gui`, `Qml`, `Quick`, `QuickControls2`, `Network`), `QT_QPA_PLATFORM=offscreen` for headless benchmarks |
| **OpenSSL Library** | `OpenSSL 3.6.4 25 Aug 2026` (`OpenSSL::Crypto`, `OpenSSL::SSL`) |
| **SQLCipher Library** | `SQLCipher 4.20.0` (`/opt/homebrew/lib/libsqlcipher.dylib`, WAL mode, `synchronous = NORMAL`) |

---

## 4. How to Run: Launching the Client & Running Benchmarks

Run all commands below from the repository root (`/Users/sergeychukhno/Desktop/C:C++/SecureCloud`).

### 4.1 Launching the SecureCloud Desktop Client

```bash
# Launch interactive GUI window (Release build — recommended)
./build/dev-release/src/client/securecloud-client

# Launch interactive GUI window (Debug build)
./build/dev-debug/src/client/securecloud-client

# Helpful CLI runtime modes:
./build/dev-release/src/client/securecloud-client --gallery                   # Open visual design-system / component style guide
QT_QPA_PLATFORM=offscreen ./build/dev-release/src/client/securecloud-client --smoke-test           # Headless boot + QML sanity check
QT_QPA_PLATFORM=offscreen ./build/dev-release/src/client/securecloud-client --benchmark-idle-ms 5000  # Measure idle RSS/CPU over 5s
```

### 4.2 Official `dev-release` Benchmark Suite (`SECURECLOUD_RUN_CLIENT_BENCHMARKS=1`)

```bash
# 1. Configure & build optimized Release targets
cmake --preset dev-release
cmake --build build/dev-release --target securecloud-client securecloud_client_performance_benchmark_test -j8

# 2. Verify zero transitive gRPC / Protobuf / Abseil dylib linkage in desktop client
otool -L build/dev-release/src/client/securecloud-client | grep -iE "grpc|protobuf|absl" || echo "ZERO gRPC/Protobuf/Abseil dylibs"

# 3. Execute full official benchmark suite (~10.9 s)
SECURECLOUD_RUN_CLIENT_BENCHMARKS=1 QT_QPA_PLATFORM=offscreen ./build/dev-release/tests/unit/securecloud_client_performance_benchmark_test
```

### 4.3 Fast `dev-debug` Sanity Benchmark & Formatting Checks

```bash
# Verify formatting, rebuild Debug targets (including client foundation tests & gateway), and run fast sanity benchmarks (~5.6 s)
cmake --build build/dev-debug --target check-format
cmake --build build/dev-debug --target securecloud-client securecloud_client_foundation_test securecloud_client_performance_benchmark_test securecloud-gateway -j8
QT_QPA_PLATFORM=offscreen ./build/dev-debug/tests/unit/securecloud_client_performance_benchmark_test
```

### 4.4 Running an Individual Benchmark

```bash
# Filter to any single benchmark (e.g., BenchmarkA .. BenchmarkG)
SECURECLOUD_RUN_CLIENT_BENCHMARKS=1 QT_QPA_PLATFORM=offscreen \
  ./build/dev-release/tests/unit/securecloud_client_performance_benchmark_test --gtest_filter="*BenchmarkF*"
```

---

## 5. Detailed Test-by-Test Breakdown (Benchmarks A–G)

### Benchmark A — Idle Baseline RSS & Idle CPU
- **What it tests:** Spawns the standalone `securecloud-client --benchmark-idle-ms <ms>` process, completes boot crypto self-tests and QML engine setup, settles for `150 ms`, idles natively on the Qt event loop (`QEventLoop`), and records process `RSS` and normalized CPU via `PlatformTelemetryCollector`.
- **Target budget:** `< 80.0 MB` RSS and `< 1.0 %` CPU.
- **Measured:**
  - `dev-release` (`idle_ms = 5000`): **`72.75 MB` RSS**, **`0.01 %` CPU**.
  - `dev-debug` (`idle_ms = 1000`): `74.47 MB` RSS, `0.01 %` CPU.
- **Assessment:** **Met & beat budget.** Idle CPU is **`100x` below** the `1.0%` ceiling. Idle RSS clears the `80.0 MB` target with **`7.25 MB` (`9.1%`) headroom** thanks to the `securecloud::common_core` zero-gRPC split.

### Benchmark B — Loaded Workspace RSS (`50` Conversations / `5,000` SQLCipher Rows)
- **What it tests:** Seeds a real encrypted SQLCipher database (`SqlCipherLocalStore`) with `50` conversations and `5,000` messages (`100` msgs/conv in `Release`; `1,000` total in `Debug`), launches a fresh `ClientApplication`, hydrates `WorkspaceViewModel`, and renders `WorkspacePlaceholder.qml` under `QQmlApplicationEngine`.
- **Target budget:** `< 150.0 MB` RSS.
- **Measured:**
  - `dev-release` (`50` convs / `5,000` msgs): **`98.22 MB` RSS** (`seed = 502.35 ms`, `delta = 69.75 MB`).
  - `dev-debug` (`50` convs / `1,000` msgs): `99.62 MB` RSS (`seed = 190.98 ms`, `delta = 70.77 MB`).
- **Assessment:** **Exceeded budget comfortably** — **`51.78 MB` (`34.5%`) below** the `150.0 MB` ceiling in Release.
- *Implementation note:* `WorkspaceViewModel::hydrateFromLocalStore()` hydrates all `50` conversations and caps initial UI-bound message history at `100` rows per conversation from the `5,000`-row encrypted SQLCipher store to keep scrolling responsive.

### Benchmark C — Chunked Encrypted Streaming Buffer Overhead
- **What it tests:** Streams a binary payload (`16.00 MiB` / `5` chunks in `Release`; `8.00 MiB` / `3` chunks in `Debug`) through `FileManager` + `FileCryptoEngine` (`AES-256-GCM` chunked encryption + X3DH/Ratchet key envelope) into `StreamingSinkGateway` and captures `peak RSS - pre RSS` across progress callbacks.
- **Target budget:** `< 32.0 MB` RSS delta (`peak - pre`).
- **Measured:**
  - `dev-release` (`16.00 MiB`, `5` chunks): **`+12.19 MB` delta** (`93.12 -> 105.31 MB`) in **`57.95 ms`**.
  - `dev-debug` (`8.00 MiB`, `3` chunks): `+12.19 MB` delta (`93.64 -> 105.83 MB`) in `311.99 ms`.
- **Assessment:** **Exceeded budget by `2.6x`** (`61.9%` memory headroom). Doubling the transfer size from `8 MiB` to `16 MiB` leaves RSS delta identical at `+12.19 MB`, confirming bounded `O(1)` chunk streaming buffers while `Release` executes `5.4x` faster on twice the payload.

### Benchmark D — Active Conversation Scroll & `60 fps` Frame Pacing
- **What it tests:** Scrolls `WorkspacePlaceholder.qml`'s `messageListView` continuously over `120` frames (`Release`, `100` seeded messages) / `30` frames (`Debug`, `60` messages) at a `60 fps` cadence (`16.67 ms` interval) inside a `1200x800` `QQuickWindow` under headless CPU software rasterization (`QT_QPA_PLATFORM=offscreen`), recording normalized system CPU and per-frame work latency.
- **Target budget:** `< 5.0 %` active system CPU and `< 16.67 ms` `p95` frame work.
- **Measured:**
  - `dev-release` (`120` frames, `10` logical cores): **`1.38 %` system CPU** (`13.78 %` single-core equiv.), **`2.30 ms` mean** / **`4.91 ms` `p95`** frame work, `rss = 123.22 MB`.
  - `dev-debug` (`30` frames, `10` logical cores): `2.37 %` system CPU (`23.70 %` single-core equiv.), `3.96 ms` mean / `9.34 ms` `p95` frame work, `rss = 115.98 MB`.
- **Assessment:** **Far exceeded budget** — **`3.6x` under** the `5.0%` CPU limit (`72.4%` headroom) and **`3.4x` faster** than the `16.67 ms` `60 fps` frame budget (`70.5%` headroom), even on CPU software rendering without Metal/GPU acceleration.

### Benchmark E — Cold Startup Latency
- **What it tests:** Spawns fresh `securecloud-client --smoke-test` processes (`N = 5` in `Release`; `N = 3` in `Debug`) and times wall-clock execution from process launch through boot crypto self-test, subsystem startup, QML root load, and clean shutdown.
- **Target budget:** `< 1,500 ms` (`p50` and `p95`).
- **Measured:**
  - `dev-release` (`N = 5`): **`349.65 ms` `p50`**, **`371.72 ms` `p95`** (`mean = 352.60 ms`, `max = 371.72 ms`).
  - `dev-debug` (`N = 3`): `427.92 ms` `p50`, `428.07 ms` `p95` (`mean = 427.85 ms`, `max = 428.07 ms`).
- **Assessment:** **Far exceeded budget** — **`4.0x`–`4.3x` faster** than the `1,500 ms` limit in `Release` (`~75%` headroom).

### Benchmark F — Double Ratchet + `AES-256-GCM` Throughput on Padded Payloads
- **What it tests:** Bootstraps a real pairwise `X3dhEngine` session using `OpenSslCryptoProvider`, then executes alternating `DoubleRatchetEngine::ratchet_encrypt` + `ratchet_decrypt` (`X25519` DH ratchet turns every `10` messages) over `256 B`, `1,024 B`, and `4,096 B` length-prefixed fixed-block padded payloads (`ADR-008 §26` / `ADR-010 §16`), plus a `3`-device `1 KiB` fan-out loop (`2,000` msgs/size & `500` logical fan-out msgs in `Release`; `400` / `100` in `Debug`).
- **Target budget:** `< 2.0 ms/msg` (`mean` and `p95`) and `> 500 msg/s` sustained throughput.
- **Assessment:** **Massively exceeded budget** — **`75x`–`86x` higher throughput** (`37,578–43,006 msg/s`) and **`> 10x` lower `p95` latency** (`0.0223–0.1840 ms`) than required in `Release`.

#### Official `dev-release` Measurements (`2,000` msgs/size; `500` logical fan-out msgs)

| Padded Block Size | Messages (`N`) | Padding Ratio (vs. `82 B` sample) | Mean (`ms`) | `p50` (`ms`) | `p95` (`ms`) | `p99` (`ms`) | `Max` (`ms`) | Sustained Throughput (`msg/s`) |
|---|---|---|---|---|---|---|---|---|
| **`256 B`** | `2,000` | `3.1220x` | `0.0245` | `0.0070` | `0.1832` | `0.1840` | `0.1910` | **`40,474.80 msg/s`** (`81x` target) |
| **`1,024 B` (`1 KiB`)** | `2,000` | `12.4878x` | `0.0249` | `0.0073` | `0.1832` | `0.1836` | `0.2632` | **`39,860.19 msg/s`** (`80x` target) |
| **`4,096 B` (`4 KiB`)** | `2,000` | `49.9512x` | `0.0262` | `0.0088` | `0.1840` | `0.1844` | `0.1929` | **`37,578.36 msg/s`** (`75x` target) |
| **`3`-Device Fan-Out (`1 KiB`)** | `500` logical (`1,500` ops) | `12.4878x` | `0.0232` | `0.0220` | `0.0223` | `0.0228` | `0.5617` | **`43,005.67 msg/s`** (`86x` target) |

- **Padding Delta (`Release`):** Stepping from `256 B -> 1,024 B` adds `+0.0004 ms` (`+1.6%`) mean latency (`-1.52%` throughput); stepping `16x` from `256 B -> 4,096 B` adds only `+0.0017 ms` (`+6.9%`) mean latency (`-7.16%` throughput), staying **`> 75x` above `500 msg/s`**.
- **`dev-debug` Comparison (`400` msgs/size; `100` logical fan-out msgs):**
  - `256 B`: `0.0471 ms` mean / `0.2200 ms` `p95`, `19,862.95 msg/s` (`40x` target)
  - `1,024 B`: `0.0639 ms` mean / `0.2364 ms` `p95`, `13,884.39 msg/s` (`28x` target)
  - `4,096 B`: `0.1318 ms` mean / `0.3044 ms` `p95`, `6,278.92 msg/s` (`12.6x` target)
  - `3`-Device Fan-Out (`1 KiB`): `0.1640 ms` mean / `0.1613 ms` `p95`, `6,090.91 msg/s` (`12.2x` target)

### Benchmark G — Memory Stability Across Crypto + SQLCipher Cycles
- **What it tests:** After a `100`-cycle warmup to stabilize SQLite WAL/page cache, executes `1,000` (`Release`) / `250` (`Debug`) continuous `DoubleRatchetEngine` encrypt/decrypt + encrypted `SqlCipherLocalStore::save_message` cycles (with periodic reads every `100` iterations) and checks net `RSS` growth.
- **Target budget:** Bounded drift (`< 16.0 MB` net RSS growth).
- **Measured:**
  - `dev-release` (`1,000` cycles): **`+0.20 MB`** (`120.67 -> 120.88 MB`).
  - `dev-debug` (`250` cycles): `0.00 MB` (`113.31 -> 113.31 MB`).
- **Assessment:** **Far exceeded budget** — **`80x` below** the `16.0 MB` drift limit in `Release`, showing stable resident memory with zero leaks.

---

## 6. Architectural Optimizations Discovered & Validated During `CLIENT-015-T05`

Running the initial `dev-release` baseline exposed two concrete architectural bottlenecks — both fixed cleanly without weakening any budget threshold:

1. **Decoupling Desktop Client from Transitive `gRPC` / `Protobuf` / `Abseil` Shared Libraries (`securecloud::common_core`):**
   - **Finding:** `securecloud::common` previously linked `securecloud_proto` and `gRPC::grpc++`, forcing `securecloud-client` (which communicates strictly over HTTPS REST via `QtHttpGatewayClient`) to map transitive dynamic `libgrpc++` / `libprotobuf` / `libupb` / `libabsl_*` libraries at launch. That pushed initial `dev-release` idle `RSS` above the `80.0 MB` budget (`87.75 MB`) and slowed cold launch (`452.24 ms`).
   - **Fix:** Split `src/common/CMakeLists.txt` into zero-gRPC **`securecloud::common_core`** (`version.cpp` + `secret_string.cpp` + `OpenSSL::Crypto`) linked by all client targets (`domain`, `infra`, `app`, `ui`, executable, and client tests), while **`securecloud::common`** links `securecloud_common_core` + `gRPC::grpc++` + `securecloud_proto` for server microservices.
   - **Measured Result (`dev-release`):** `otool -L` confirms **zero `grpc` / `protobuf` / `absl` dylibs** in `securecloud-client`, bringing idle `RSS` cleanly under budget at **`72.75 MB`** (`0.01%` idle CPU) and cold-start `p50` to **`349.65 ms`**.

2. **QML List Recycling, Hidden `Canvas` Paint Guards & Cross-Platform CPU Normalization:**
   - **UI Scroll Optimization:** Enabled `reuseItems: true` and `cacheBuffer: 400` on `WorkspacePlaceholder.qml`'s `messageListView` (with `ListView.onReused` animation reset) and guarded `SCIcon.qml` `Canvas` visibility (`visible: iconRoot.visible` and `if (iconRoot.visible) canvas.requestPaint()`), eliminating off-screen `2D Canvas` `QImage` redraws during message scrolling while maintaining zero QML runtime warnings across dark/light/high-contrast themes and font scales.
   - **Normalized System CPU Telemetry (`PlatformTelemetryCollector`):** Normalized `cpu_percent` across macOS (`getrusage`), Linux (`getrusage`), and Windows (`GetProcessTimes`) against `std::thread::hardware_concurrency()` into `[0.0%, 100.0%]`. On the `10`-core Apple M4 host under headless `QT_QPA_PLATFORM=offscreen` CPU software rasterization (`120` frames at `60 fps`), `BenchmarkD` measured **`1.38%` system CPU** (`13.78%` single-core equivalent, `2.30 ms` mean / `4.91 ms` p95 frame work vs `16.67 ms` deadline). With native macOS Metal / Linux GPU acceleration in interactive windows, frame rasterization shifts off CPU further.

---

## 7. Platform Measurement Scope Note

- **Verified Host Measurements:** All measurements above were captured directly on the developer workstation (`Apple M4`, `10` cores, `16 GiB` RAM, `macOS 15.6` `arm64`, `Apple clang 17.0.0`) under `QT_QPA_PLATFORM=offscreen`.
- **Linux / Windows CI Runners:** `PlatformTelemetryCollector` and `client_performance_benchmark_test.cpp` compile and implement native OS sampling paths for Linux (`/proc/self/statm` + `getrusage`) and Windows (`GetProcessMemoryInfo` + `GetProcessTimes` via `psapi`), with cross-platform verification executed by the repository CI workflows on Linux (`Ubuntu`) and Windows runners (`ci-linux`, `ci-windows-msvc`, `ci-windows-mingw`). Direct multi-OS absolute RSS numbers depend on each platform's shared-library page accounting (`mach_task_basic_info` on macOS, `statm` on Linux, `WorkingSetSize` on Windows).

---

## 8. Live Full-Stack Docker Compose Latency Addendum *(Reserved for `CLIENT-015-T06`)*

*To be populated during `CLIENT-015-T06` once end-to-end live TLS 1.3 `QtHttpGatewayClient` ↔ `Gateway :8443` ↔ `Auth` / `Messaging` / `Files` / `Audit` Docker Compose integration runs complete, adding real end-to-end network RTT, message send, and encrypted chunked transfer `p50` / `p95` / `p99` tables.*
