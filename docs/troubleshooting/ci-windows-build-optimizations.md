# Windows CI Build Optimization Plan (Tier 1 & Tier 2)

## 1. Executive Summary & Impact Projections

| Pipeline Phase | Current Baseline | Optimized (Tier 1) | Optimized (Tier 1 + Tier 2) | Cumulative Savings |
| :--- | :--- | :--- | :--- | :--- |
| **MinGW Dependency Fetch** | 6–8 min (uncached pacman) | 30–45 sec (cached pkg) | 30–45 sec | **~6–7 min** |
| **MSVC Compilation (Cold)** | 12–15 min | 8–10 min (no AV scan) | 5–6 min (`/Zi`, sccache) | **~7–9 min** |
| **MSVC Compilation (Warm PR)** | 10–12 min | 2–3 min (sccache hit) | 1–2 min | **~9–10 min** |
| **Linking (211 Executables)** | 12–14 min | 9–10 min (no AV scan) | 3–4 min (`lld`, `no-applocal`) | **~9–10 min** |
| **Total Pipeline Wall Time** | **25–30 min** | **~14–16 min** | **~7–10 min** | **~65–70% speedup** |

---

## 2. Root Cause Analysis

1. **Windows Defender Overhead (`MsMpEng.exe`)**:
   Standard GitHub Actions `windows-2022` runners have 2 vCPUs. Windows Defender intercepts every file create/write event for `.obj`, `.lib`, `.pdb`, and `.exe`, consuming 25–30% of total CPU cycles during compilation and linking.
2. **MinGW Ephemeral Package Downloads**:
   Every MinGW run invokes `pacman -S` for ~1.5 GB of toolchain and dependency packages (`protobuf`, `grpc`, `openssl`, `libpqxx`) from public mirrors without caching.
3. **vcpkg Serialized Applocal DLL Copying (`applocal.ps1`)**:
   With 211 separate executables (175 unit + 36 integration tests), `vcpkg` invokes `applocal.ps1` 211 times. Because `-DX_VCPKG_APPLOCAL_DEPS_SERIALIZED=ON` was enabled to prevent parallel file lock races, this introduces sequential PowerShell process spawning overhead.
4. **Linker Contention with Full Debug Information**:
   - MSVC uses `/Z7` (`Embedded`), causing huge `.obj` files with redundant debug types across all 211 link operations.
   - MinGW uses default `-g` with GNU `ld.exe`, which is single-threaded on Windows and struggles with multi-gigabyte DWARF debug tables.

---

## 3. Tier 1 Optimizations (CI Workflow Level — No Code Changes)

### T1.1: Windows Defender Exclusion on Workspace and Build Trees
Add an elevated setup step at the beginning of both Windows jobs in `.github/workflows/ci.yml`:

```yaml
- name: Configure Windows Defender Exclusions
  shell: pwsh
  run: |
    Write-Host "Disabling Windows Defender Realtime Monitoring for CI build performance..."
    Set-MpPreference -DisableRealtimeMonitoring $true
    Add-MpPreference -ExclusionPath "${{ github.workspace }}", "C:\vcpkg", "C:\msys64", "D:\a", "$env:TEMP"
```

### T1.2: MSYS2 Pacman Package Caching for MinGW
Cache the MSYS2 local pacman package repository (`C:\msys64\var\cache\pacman\pkg`) so packages are downloaded once and reinstalled from disk:

```yaml
- name: Restore MSYS2 Pacman Cache
  uses: actions/cache@v4
  with:
    path: C:\msys64\var\cache\pacman\pkg
    key: msys2-pacman-${{ runner.os }}-${{ hashFiles('.github/workflows/ci.yml') }}
    restore-keys: |
      msys2-pacman-${{ runner.os }}-
```

### T1.3: Compiler Caching with `sccache`
Integrate Mozilla’s `sccache` using GitHub Actions Cache as the storage backend:

```yaml
- name: Setup sccache
  uses: mozilla-actions/sccache-action@v0.0.8
  with:
    version: "v0.8.1"

- name: Configure sccache Environment
  shell: pwsh
  run: |
    echo "SCCACHE_GHA_ENABLED=true" >> $env:GITHUB_ENV
    echo "CMAKE_C_COMPILER_LAUNCHER=sccache" >> $env:GITHUB_ENV
    echo "CMAKE_CXX_COMPILER_LAUNCHER=sccache" >> $env:GITHUB_ENV
```

---

## 4. Tier 2 Optimizations (CMake Presets & Linker Tuning)

### T2.1: Disable `VCPKG_APPLOCAL_DEPS` in Favor of PATH Discovery
In `tests/CMakeLists.txt`, CTest **already** dynamically adds the vcpkg DLL directories to the test runtime `PATH`:
```cmake
list(APPEND _TEST_ENV_MODS
    "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/debug/bin"
    "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/bin"
)
```
Therefore, copying DLLs into each of the 211 test output directories is redundant!
In `CMakePresets.json`:
```json
"cacheVariables": {
  "VCPKG_APPLOCAL_DEPS": "OFF",
  "X_VCPKG_APPLOCAL_DEPS_SERIALIZED": "OFF"
}
```
*Eliminates 211 sequential `applocal.ps1` PowerShell copy operations, saving ~3–4 minutes of disk I/O.*

### T2.2: Fast Linker & Debug Info Tuning for MSVC
Update the `ci-windows-msvc` preset in `CMakePresets.json`:
1. **Debug Format**: Switch from `Embedded` (`/Z7`) to `ProgramDatabase` (`/Zi`).
2. **Fastlink**: Pass `/DEBUG:FASTLINK` to `CMAKE_EXE_LINKER_FLAGS_DEBUG`. This creates an indexed PDB referencing the object files instead of copying and merging full debug type records across 211 test binaries.
3. **Incremental Linking Off**: Add `/INCREMENTAL:NO` to avoid link padding bloat.

### T2.3: Fast LLVM LLD Linker & Stripped Debug Lines for MinGW
Update the `ci-windows-mingw` job and preset:
1. **Install LLVM LLD in MSYS2**:
   Add `mingw-w64-x86_64-lld` to `PACKAGES` array in `ci.yml`.
2. **Use LLD as Linker**:
   Pass `-fuse-ld=lld` in `CMAKE_EXE_LINKER_FLAGS`. LLD is multi-threaded and links Windows PE-COFF binaries ~4x faster than GNU `ld`.
3. **Line-Tables-Only Debug Symbols**:
   Replace `-g` with `-gline-tables-only` (or `-g1`) for CI. This retains full line numbers and file names for assertion failures and gtest stack traces while reducing `.obj` debug section size by ~80%.

---

## 5. Rollout Plan (When PR Merges)

1. **Step 1: Create Branch from Updated `main`**:
   `feature/ci-windows-build-optimizations`
2. **Step 2: Implement Tier 1 (`.github/workflows/ci.yml`)**:
   - Add Windows Defender exclusion step.
   - Add MSYS2 package cache step.
   - Configure `sccache-action`.
3. **Step 3: Implement Tier 2 (`CMakePresets.json`)**:
   - Set `VCPKG_APPLOCAL_DEPS: OFF`.
   - Configure `/DEBUG:FASTLINK` on MSVC.
   - Configure `-fuse-ld=lld` and `-gline-tables-only` on MinGW.
4. **Step 4: Verify Local & Push PR**:
   - Confirm test discovery and execution pass on both toolchains.
   - Monitor CI pipeline duration to verify build time drop from ~28 min down to ~8–10 min.
