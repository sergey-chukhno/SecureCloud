# SecureCloud Client Performance Benchmark Report (`CLIENT-015-T05`)

**Ticket:** `CLIENT-015-T05` — Official Client Performance Benchmarking Harness & Report  
**Specification References:** `docs/planning/initial-backlog.md`, `ADR-008 §26`, `ADR-010 §16 / §17 / §26 / §27`  
**Harness Source:** `tests/unit/client/client_performance_benchmark_test.cpp`  
**Execution Date:** `2026-11-25`  
**Overall Gate Result:** **7 / 7 Budgets PASSED (`Release` & `Debug`, `10/10` `BenchmarkC` stability)**

---

## 1. Executive Summary & Budget Compliance Matrix

All client resource, frame-pacing, startup latency, encrypted streaming buffer, and End-to-End Encryption (`X3DH` + `DoubleRatchetEngine` + `AES-256-GCM`) throughput budgets were empirically measured against **real encrypted SQLCipher persistence**, **real OpenSSL 3.6.4 cryptography**, and **real Qt 6.11.0 / QML UI rendering** (zero in-memory mocks or stub crypto providers).

| ID | Benchmark Workload | Target Budget (`Backlog` / `ADR-010`) | Official `dev-release` (`SECURECLOUD_RUN_CLIENT_BENCHMARKS=1`) | `dev-debug` Sanity | Assessment & Margin |
|---|---|---|---|---|---|
| **A** | Idle Baseline Resident Memory (`RSS`) | `< 80.0 MB` | **`73.19 MB`** (`5,000 ms` idle) | `74.17 MB` (`1,000 ms` idle) | **PASS** — `6.81 MB` (`8.5%`) headroom |
| **A** | Idle Baseline CPU Utilization | `< 1.0 %` | **`0.01 %`** | `0.01 %` | **PASS** — `100x` below limit |
| **B** | Loaded Workspace `RSS` (`50` convs / `5,000` SQLCipher rows) | `< 150.0 MB` | **`98.78 MB`** (`50` convs / `5,000` msgs) | `96.50 MB` (`50` convs / `1,000` msgs) | **PASS** — `51.22 MB` (`34.1%`) below cap |
| **C** | Chunked Encrypted Streaming Overhead (`peak - pre RSS`) | `< 32.0 MB` | **`+8.19 MB`** (`16.00 MiB`, `5` chunks; `10/10` runs) | `+8.20 MB` (`8.00 MiB`, `3` chunks) | **PASS** — `3.9x` under budget (`74.4%` headroom) |
| **D** | Active Conversation Scroll (`60 fps` frame pacing) | `< 5.0 %` CPU, `< 16.67 ms` p95 | **`1.78 %`** CPU (`2.97 ms` mean / `5.04 ms` p95) | `1.75 %` CPU (`2.91 ms` mean / `6.97 ms` p95) | **PASS** — `2.8x` under CPU cap, `3.3x` faster than frame deadline |
| **E** | Cold Startup Latency (`securecloud-client --smoke-test`) | `< 1,500 ms` (`p50` & `p95`) | **`171.59 ms` p50** / **`214.44 ms` p95** | `217.55 ms` p50 / `222.01 ms` p95 | **PASS** — `7.0x`–`8.7x` faster than target (`85.7%` headroom) |
| **F** | Double Ratchet + `AES-256-GCM` Latency (`256 B / 1 KiB / 4 KiB`) | `< 2.0 ms/msg` (`mean` & `p95`) | **`0.0129–0.0213 ms` mean** / **`0.0946–0.0976 ms` p95** | `0.0259–0.0679 ms` mean | **PASS** — `> 20x` faster `p95` than budget |
| **F** | Double Ratchet + `AES-256-GCM` Throughput | `> 500 msg/s` | **`46,581–76,567 msg/s`** (`82,945` `3`-dev fanout) | `12,193–36,255 msg/s` | **PASS** — `93x`–`166x` above target |
| **G** | Memory Stability (`1,000` Crypto + SQLCipher cycles) | Bounded (`< 16.0 MB` drift) | **`+0.00 MB`** (`119.55 -> 119.55 MB`) | `0.00 MB` (`112.73 -> 112.73 MB`) | **PASS** — Zero measurable drift |

---

## 2. Understanding `dev-debug` vs. `dev-release` Benchmarking Modes

The benchmarking workflow separates two independent axes: the **CMake build preset** ([CMakePresets.json](../../CMakePresets.json)) and the **workload scale flag** (`SECURECLOUD_RUN_CLIENT_BENCHMARKS=1` in `client_performance_benchmark_test.cpp`).

| Dimension | `dev-debug` (Sanity / CI Mode) | `dev-release` (Official Benchmark Mode) |
|---|---|---|
| **CMake Build Preset** | `CMAKE_BUILD_TYPE=Debug` (`build/dev-debug`) | `CMAKE_BUILD_TYPE=Release` (`build/dev-release`) |
| **Compiler Codegen** | Unoptimized (`-O0`), full debug symbols (`-g`), assertions enabled (`NDEBUG` undefined) | Optimized (`-O3`), inlining and vectorization enabled, `NDEBUG` defined |
| **Security & Warning Flags** | Identical via `securecloud::compiler_flags`: `-Wall -Wextra -Werror -Wpedantic -Wshadow -Wconversion -fstack-protector-strong -fvisibility=hidden -D_FORTIFY_SOURCE=3` | Identical |
| **Workload Scale (`SECURECLOUD_RUN_CLIENT_BENCHMARKS`)** | Default (env unset): lighter counts (`1 s` idle, `1,000` SQLCipher rows, `8 MiB` stream, `30` frames, `3` cold starts, `400` ratchet msgs/size, `250` leak cycles) running in ~`3.6 s` | `SECURECLOUD_RUN_CLIENT_BENCHMARKS=1`: full `ADR-010` / backlog counts (`5 s` idle, `5,000` SQLCipher rows, `16 MiB` stream, `120` frames, `5` cold starts, `2,000` ratchet msgs/size, `1,000` leak cycles) running in ~`9.3 s` |
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

# 3. Execute full official benchmark suite (~9.3 s)
SECURECLOUD_RUN_CLIENT_BENCHMARKS=1 QT_QPA_PLATFORM=offscreen ./build/dev-release/tests/unit/securecloud_client_performance_benchmark_test
```

### 4.3 Fast `dev-debug` Sanity Benchmark & Formatting Checks

```bash
# Verify formatting, rebuild Debug targets (including client foundation tests & gateway), and run fast sanity benchmarks (~3.6 s)
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
  - `dev-release` (`idle_ms = 5000`): **`73.19 MB` RSS**, **`0.01 %` CPU**.
  - `dev-debug` (`idle_ms = 1000`): `74.17 MB` RSS, `0.01 %` CPU.
- **Assessment:** **Met & beat budget.** Idle CPU is **`100x` below** the `1.0%` ceiling. Idle RSS clears the `80.0 MB` target with **`6.81 MB` (`8.5%`) headroom** thanks to the `securecloud::common_core` zero-gRPC split.

### Benchmark B — Loaded Workspace RSS (`50` Conversations / `5,000` SQLCipher Rows)
- **What it tests:** Seeds a real encrypted SQLCipher database (`SqlCipherLocalStore`) with `50` conversations and `5,000` messages (`100` msgs/conv in `Release`; `1,000` total in `Debug`), launches a fresh `ClientApplication`, hydrates `WorkspaceViewModel`, and renders `WorkspacePlaceholder.qml` under `QQmlApplicationEngine`.
- **Target budget:** `< 150.0 MB` RSS.
- **Measured:**
  - `dev-release` (`50` convs / `5,000` msgs): **`98.78 MB` RSS** (`seed = 265.78 ms`, `delta = 70.05 MB`).
  - `dev-debug` (`50` convs / `1,000` msgs): `96.50 MB` RSS (`seed = 108.12 ms`, `delta = 67.39 MB`).
- **Assessment:** **Exceeded budget comfortably** — **`51.22 MB` (`34.1%`) below** the `150.0 MB` ceiling in Release.
- *Implementation note:* `WorkspaceViewModel::hydrateFromLocalStore()` hydrates all `50` conversations and caps initial UI-bound message history at `100` rows per conversation from the `5,000`-row encrypted SQLCipher store to keep scrolling responsive.

### Benchmark C — Chunked Encrypted Streaming Buffer Overhead
- **What it tests:** Streams a binary payload (`16.00 MiB` / `5` chunks in `Release`; `8.00 MiB` / `3` chunks in `Debug`) through `FileManager` + `FileCryptoEngine::encrypt_chunk_into` + `OpenSslCryptoProvider::encrypt_aes_gcm_into` (`AES-256-GCM` chunked encryption + X3DH/Ratchet key envelope) into `StreamingSinkGateway` using reused buffers, capturing `peak RSS - pre RSS` across progress callbacks.
- **Target budget:** `< 32.0 MB` RSS delta (`peak - pre`).
- **Measured:**
  - `dev-release` (`16.00 MiB`, `5` chunks): **`+8.19 MB` delta** (`93.66 -> 101.84 MB`) in **`27.94 ms`**. Across **10 consecutive standalone runs**, every single run measured **`+8.19 MB`** (`27.08–27.78 ms`) with zero variance.
  - `dev-debug` (`8.00 MiB`, `3` chunks): `+8.20 MB` delta (`91.52 -> 99.72 MB`) in `75.89 ms`.
- **Assessment:** **Exceeded budget by `3.9x`** (`74.4%` memory headroom). Doubling the transfer size from `8 MiB` to `16 MiB` leaves RSS delta essentially flat (`8.20 MB -> 8.19 MB`), proving bounded `O(1)` streaming buffers while `Release` executes `2.7x` faster on twice the payload.

### Benchmark D — Active Conversation Scroll & `60 fps` Frame Pacing
- **What it tests:** Scrolls `WorkspacePlaceholder.qml`'s `messageListView` continuously over `120` frames (`Release`, `100` seeded messages) / `30` frames (`Debug`, `60` messages) at a `60 fps` cadence (`16.67 ms` interval) inside a `1200x800` `QQuickWindow` under headless CPU software rasterization (`QT_QPA_PLATFORM=offscreen`), recording normalized system CPU and per-frame work latency.
- **Target budget:** `< 5.0 %` active system CPU and `< 16.67 ms` `p95` frame work.
- **Measured:**
  - `dev-release` (`120` frames, `10` logical cores): **`1.78 %` system CPU** (`17.82 %` single-core equiv.), **`2.97 ms` mean** / **`5.04 ms` `p95`** frame work, `rss = 122.12 MB`.
  - `dev-debug` (`30` frames, `10` logical cores): `1.75 %` system CPU (`17.47 %` single-core equiv.), `2.91 ms` mean / `6.97 ms` `p95` frame work, `rss = 115.55 MB`.
- **Assessment:** **Far exceeded budget** — **`2.8x` under** the `5.0%` CPU limit (`64.4%` headroom) and **`3.3x` faster** than the `16.67 ms` `60 fps` frame budget (`69.8%` headroom), even on CPU software rendering without Metal/GPU acceleration.

### Benchmark E — Cold Startup Latency
- **What it tests:** Spawns fresh `securecloud-client --smoke-test` processes (`N = 5` in `Release`; `N = 3` in `Debug`) and times wall-clock execution from process launch through boot crypto self-test, subsystem startup, QML root load, and clean shutdown.
- **Target budget:** `< 1,500 ms` (`p50` and `p95`).
- **Measured:**
  - `dev-release` (`N = 5`): **`171.59 ms` `p50`**, **`214.44 ms` `p95`** (`mean = 180.24 ms`, `max = 214.44 ms`).
  - `dev-debug` (`N = 3`): `217.55 ms` `p50`, `222.01 ms` `p95` (`mean = 217.03 ms`, `max = 222.01 ms`).
- **Assessment:** **Far exceeded budget** — **`7.0x`–`8.7x` faster** than the `1,500 ms` limit in `Release` (`85.7%` headroom).

### Benchmark F — Double Ratchet + `AES-256-GCM` Throughput on Padded Payloads
- **What it tests:** Bootstraps a real pairwise `X3dhEngine` session using `OpenSslCryptoProvider`, then executes alternating `DoubleRatchetEngine::ratchet_encrypt` + `ratchet_decrypt` (`X25519` DH ratchet turns every `10` messages) over `256 B`, `1,024 B`, and `4,096 B` length-prefixed fixed-block padded payloads (`ADR-008 §26` / `ADR-010 §16`), plus a `3`-device `1 KiB` fan-out loop (`2,000` msgs/size & `500` logical fan-out msgs in `Release`; `400` / `100` in `Debug`).
- **Target budget:** `< 2.0 ms/msg` (`mean` and `p95`) and `> 500 msg/s` sustained throughput.
- **Assessment:** **Massively exceeded budget** — **`93x`–`166x` higher throughput** (`46,581–82,945 msg/s`) and **`> 20x` lower `p95` latency** (`0.0116–0.0976 ms`) than required in `Release`.

#### Official `dev-release` Measurements (`2,000` msgs/size; `500` logical fan-out msgs)

| Padded Block Size | Messages (`N`) | Padding Ratio (vs. `82 B` sample) | Mean (`ms`) | `p50` (`ms`) | `p95` (`ms`) | `p99` (`ms`) | `Max` (`ms`) | Sustained Throughput (`msg/s`) |
|---|---|---|---|---|---|---|---|---|
| **`256 B`** | `2,000` | `3.1220x` | `0.0213` | `0.0037` | `0.0976` | `0.3004` | `2.1512` | **`46,581.45 msg/s`** (`93x` target) |
| **`1,024 B` (`1 KiB`)** | `2,000` | `12.4878x` | `0.0129` | `0.0037` | `0.0946` | `0.0987` | `0.1165` | **`76,566.50 msg/s`** (`153x` target) |
| **`4,096 B` (`4 KiB`)** | `2,000` | `49.9512x` | `0.0137` | `0.0046` | `0.0953` | `0.0981` | `0.1121` | **`71,776.35 msg/s`** (`144x` target) |
| **`3`-Device Fan-Out (`1 KiB`)** | `500` logical (`1,500` ops) | `12.4878x` | `0.0120` | `0.0114` | `0.0116` | `0.0144` | `0.2863` | **`82,944.53 msg/s`** (`166x` target) |

- **Padding Delta (`Release`):** Median (`p50`) round-trip latency rises by only `+0.0009 ms` across the `16x` jump from `256 B -> 4,096 B` (`0.0037 -> 0.0046 ms`). Comparing steady-state `1,024 B -> 4,096 B` (`+3,072 B`), mean latency shifts by `+0.0008 ms` (`+6.2%`) and throughput shifts by `-6.26%` (`76,567 -> 71,776 msg/s`), staying **`> 143x` above `500 msg/s`** (`256 B` included a single `2.15 ms` OS scheduler preemption blip that pulled its batch throughput to `46,581 msg/s`, still `93x` above target).
- **`dev-debug` Comparison (`400` msgs/size; `100` logical fan-out msgs):**
  - `256 B`: `0.0259 ms` mean / `0.1155 ms` `p95`, `36,255.01 msg/s` (`73x` target)
  - `1,024 B`: `0.0326 ms` mean / `0.1215 ms` `p95`, `27,211.89 msg/s` (`54x` target)
  - `4,096 B`: `0.0679 ms` mean / `0.1571 ms` `p95`, `12,193.09 msg/s` (`24x` target)
  - `3`-Device Fan-Out (`1 KiB`): `0.0853 ms` mean / `0.0858 ms` `p95`, `11,712.63 msg/s` (`23x` target)

### Benchmark G — Memory Stability Across Crypto + SQLCipher Cycles
- **What it tests:** After a `100`-cycle warmup to stabilize SQLite WAL/page cache, executes `1,000` (`Release`) / `250` (`Debug`) continuous `DoubleRatchetEngine` encrypt/decrypt + encrypted `SqlCipherLocalStore::save_message` cycles (with periodic reads every `100` iterations) and checks net `RSS` growth.
- **Target budget:** Bounded drift (`< 16.0 MB` net RSS growth).
- **Measured:**
  - `dev-release` (`1,000` cycles): **`+0.00 MB`** (`119.55 -> 119.55 MB`).
  - `dev-debug` (`250` cycles): `0.00 MB` (`112.73 -> 112.73 MB`).
- **Assessment:** **Far exceeded budget** — `0.00 MB` measured drift vs. the `16.0 MB` cap, showing stable resident memory with zero leaks.

---

## 6. Architectural Optimizations Discovered & Validated During `CLIENT-015-T05`

Running the `dev-release` suite exposed three concrete bottlenecks — all fixed in production code without weakening any budget threshold:

1. **Decoupling Desktop Client from Transitive `gRPC` / `Protobuf` / `Abseil` Shared Libraries (`securecloud::common_core`):**
   - **Finding:** `securecloud::common` previously linked `securecloud_proto` and `gRPC::grpc++`, forcing `securecloud-client` (which communicates strictly over HTTPS REST via `QtHttpGatewayClient`) to map transitive dynamic `libgrpc++` / `libprotobuf` / `libupb` / `libabsl_*` libraries at launch. That pushed initial `dev-release` idle `RSS` above the `80.0 MB` budget (`87.75 MB`) and slowed cold launch (`452.24 ms`).
   - **Fix:** Split `src/common/CMakeLists.txt` into zero-gRPC **`securecloud::common_core`** (`version.cpp` + `secret_string.cpp` + `OpenSSL::Crypto`) linked by all client targets (`domain`, `infra`, `app`, `ui`, executable, and client tests), while **`securecloud::common`** links `securecloud_common_core` + `gRPC::grpc++` + `securecloud_proto` for server microservices.
   - **Measured Result (`dev-release`):** `otool -L` confirms **zero `grpc` / `protobuf` / `absl` dylibs** in `securecloud-client`, bringing idle `RSS` cleanly under budget at **`73.19 MB`** (`0.01%` idle CPU) and cold-start `p50` to **`171.59 ms`**.

2. **QML List Recycling, Hidden `Canvas` Paint Guards & Cross-Platform CPU Normalization:**
   - **UI Scroll Optimization:** Enabled `reuseItems: true` and `cacheBuffer: 400` on `WorkspacePlaceholder.qml`'s `messageListView` (with `ListView.onReused` animation reset) and guarded `SCIcon.qml` `Canvas` visibility (`visible: iconRoot.visible` and `if (iconRoot.visible) canvas.requestPaint()`), eliminating off-screen `2D Canvas` `QImage` redraws during message scrolling while maintaining zero QML runtime warnings across dark/light/high-contrast themes and font scales.
   - **Normalized System CPU Telemetry (`PlatformTelemetryCollector`):** Normalized `cpu_percent` across macOS (`getrusage`), Linux (`getrusage`), and Windows (`GetProcessTimes`) against `std::thread::hardware_concurrency()` into `[0.0%, 100.0%]`. On the `10`-core Apple M4 host under headless `QT_QPA_PLATFORM=offscreen` CPU software rasterization (`120` frames at `60 fps`), `BenchmarkD` measured **`1.78%` system CPU** (`17.82%` single-core equivalent, `2.97 ms` mean / `5.04 ms` p95 frame work vs `16.67 ms` deadline). With native macOS Metal / Linux GPU acceleration in interactive windows, frame rasterization shifts off CPU further.

3. **Zero-Churn Single-Buffer Chunked Streaming (`ICryptoProvider::encrypt_aes_gcm_into` & `FileCryptoEngine::encrypt_chunk_into`):**
   - **Finding:** `FileManager::execute_upload_loop()` previously churned three separate `4 MiB` heap allocations plus a `const` vector copy per chunk (`chunk_buffer` + `encrypt_aes_gcm` ciphertext vector + `framed_bytes` vector + temporary `FileChunkUploadRequest::encrypted_data`). On macOS, `libmalloc` keeps recently freed large blocks in a lazy `MADV_FREE_REUSABLE` cache still counted by `MACH_TASK_BASIC_INFO::resident_size`, causing occasional `BenchmarkC` spikes up to `32.19 MB`.
   - **Fix:** Added zero-allocation `ICryptoProvider::encrypt_aes_gcm_into()` / `OpenSslCryptoProvider::encrypt_aes_gcm_into()` writing ciphertext and GCM auth tag directly into caller spans, `FileCryptoEngine::encrypt_chunk_into()` formatting `[IV || ciphertext || tag]` into a pre-reserved vector, and one reused `FileChunkUploadRequest` buffer across chunks in `FileManager::execute_upload_loop()` (plus reused `replay_framed_buf` in `execute_download_loop()`).
   - **Measured Result (`dev-release`):** Across **10 consecutive runs** (`SECURECLOUD_RUN_CLIENT_BENCHMARKS=1`), `BenchmarkC` held an identical **`+8.19 MB` delta (`10/10 PASS`, `27.08–27.78 ms`)**, cutting streaming buffer delta by **`32.8%`** (`12.19 -> 8.19 MB`) and cutting `16 MiB` elapsed upload time by **`~2.1x`** (`~59 ms -> 27.94 ms`).

---

## 7. Platform Measurement Scope Note

- **Verified Host Measurements:** All measurements above were captured directly on the developer workstation (`Apple M4`, `10` cores, `16 GiB` RAM, `macOS 15.6` `arm64`, `Apple clang 17.0.0`) under `QT_QPA_PLATFORM=offscreen`.
- **Linux / Windows CI Runners:** `PlatformTelemetryCollector` and `client_performance_benchmark_test.cpp` compile and implement native OS sampling paths for Linux (`/proc/self/statm` + `getrusage`) and Windows (`GetProcessMemoryInfo` + `GetProcessTimes` via `psapi`), with cross-platform verification executed by the repository CI workflows on Linux (`Ubuntu`) and Windows runners (`ci-linux`, `ci-windows-msvc`, `ci-windows-mingw`). Direct multi-OS absolute RSS numbers depend on each platform's shared-library page accounting (`mach_task_basic_info` on macOS, `statm` on Linux, `WorkingSetSize` on Windows).

---

## 8. Live Full-Stack Docker Compose Latency Addendum (`CLIENT-015-T06`)

End-to-end live TLS 1.3 latency metrics were captured during `CLIENT-015-T06` (`Scenario5_EmergencyPanicWipeAuditContinuityAndLiveLatencyMetrics`) with `QtHttpGatewayClient` communicating over HTTPS (`127.0.0.1:8443`, TLS 1.3 + SPKI SHA-256 pinning) against the 5-service Docker Compose stack (`gateway` -> `auth`, `messaging`, `files`, `audit`) backed by PostgreSQL, ScyllaDB, MinIO, and ClickHouse (`build/dev-debug` client + Debian Trixie Release backend containers):

| Metric | Scope | Observed Value |
|---|---|---|
| TLS 1.3 Gateway `/health` Probe (`n = 20`) | Mean / p50 / p95 / p99 / Max | `3.15 ms` / `3.12 ms` / `4.06 ms` / `4.06 ms` / `4.06 ms` |
| Live E2EE Message Send (`msg_send_ms`) | `Client -> Gateway -> Messaging -> ScyllaDB` | `45.66 ms` |
| Live Encrypted File Upload (`file_upload_ms`) | `4 KiB` AES-256-GCM + `FileKeyEnvelope` (`Client -> Gateway -> Files -> MinIO/Postgres`) | `65.89 ms` |
| Client Diagnostics Gateway RTT (`gateway_avg_rtt_ms`) | Rolling average across `34` live requests | `7 ms` (`34` requests) |

**Reproduction command:**

```bash
SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1 QT_QPA_PLATFORM=offscreen \
  ./build/dev-debug/tests/integration/securecloud_client_gateway_backend_integration_test
```

All 5 end-to-end scenarios (`Scenario1`–`Scenario5`) passed (`5/5 PASS`, `5,559 ms` total), including zero-plaintext verification across ScyllaDB, PostgreSQL, MinIO, and cross-service ClickHouse `AuditQueryService` continuity (`GATEWAY`, `AUTH`, `MESSAGING`, `FILES`).
