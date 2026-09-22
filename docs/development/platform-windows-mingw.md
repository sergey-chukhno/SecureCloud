# Windows MinGW / MSYS2 Development Environment Guide

This guide details the setup and configuration of the SecureCloud development environment on Windows using MinGW-w64 GCC and MSYS2.

---

## 1. MSYS2 Toolchain & Package Installation

Install **MSYS2** from [msys2.org](https://www.msys2.org/) (defaults to `C:\msys64`).

SecureCloud supports both the **MinGW64** environment (`C:\msys64\mingw64`) and the **UCRT64** environment (`C:\msys64\ucrt64`).

### Option A: MinGW64 Environment (Traditional MSVCRT)
Open the **MSYS2 MINGW64** shell and install dependencies:
```bash
pacman -Syu
pacman -S --needed \
    mingw-w64-x86_64-toolchain \
    mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-ninja \
    mingw-w64-x86_64-openssl \
    mingw-w64-x86_64-protobuf \
    mingw-w64-x86_64-grpc \
    mingw-w64-x86_64-gtest \
    git python3
```

Or run directly from Windows **PowerShell** (single command):
```powershell
C:\msys64\usr\bin\pacman.exe -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-openssl mingw-w64-x86_64-protobuf mingw-w64-x86_64-grpc mingw-w64-x86_64-gtest git python3
```

### Option B: UCRT64 Environment (Universal CRT, Recommended)
Open the **MSYS2 UCRT64** shell and install dependencies:
```bash
pacman -Syu
pacman -S --needed \
    mingw-w64-ucrt-x86_64-toolchain \
    mingw-w64-ucrt-x86_64-cmake \
    mingw-w64-ucrt-x86_64-ninja \
    mingw-w64-ucrt-x86_64-openssl \
    mingw-w64-ucrt-x86_64-protobuf \
    mingw-w64-ucrt-x86_64-grpc \
    mingw-w64-ucrt-x86_64-gtest \
    git python3
```

Or run directly from Windows **PowerShell** (single command):
```powershell
C:\msys64\usr\bin\pacman.exe -S --needed mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-protobuf mingw-w64-ucrt-x86_64-grpc mingw-w64-ucrt-x86_64-gtest git python3
```

---

## 2. Windows Environment Variable Configuration

To compile directly from standard Windows **PowerShell** or **Command Prompt** without opening the MSYS2 shell:

Add your active MSYS2 binary directory to your User `PATH`:
```powershell
# For MinGW64:
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

# For UCRT64:
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
```

Set MSYS2 path conversion flag:
```powershell
[System.Environment]::SetEnvironmentVariable('MSYS_NO_PATHCONV', '1', 'User')
$env:MSYS_NO_PATHCONV = "1"
```

---

## 3. Automatic Discovery Fallback (SC-015)

In SecureCloud, `cmake/modules/SecureCloudDependencies.cmake` includes an automatic prefix discovery pipeline:
- Derives the toolchain prefix directly from `CMAKE_CXX_COMPILER` (e.g. `C:/msys64/mingw64/bin/g++.exe` -> `C:/msys64/mingw64`).
- Automatically scans and adds `C:/msys64/mingw64`, `C:/msys64/ucrt64`, and `C:/msys64/clang64` to `CMAKE_PREFIX_PATH`.
- Adds discovery hints for `grpc_cpp_plugin.exe` and `protoc.exe`.

This allows standard CMake commands and scripts to resolve `gRPCConfig.cmake` and `protobuf-config.cmake` without manual path overrides.

---

## 4. CMake Preset & Verification

Use the `ci-windows-mingw` preset in `CMakePresets.json`:

```powershell
cd C:\Path\To\SecureCloud

# Configure with MinGW preset:
cmake --preset ci-windows-mingw

# Build:
cmake --build --preset ci-windows-mingw

# Validate Protobuf and gRPC contracts:
cmake --build --preset ci-windows-mingw --target verify-contracts

# Run tests:
ctest --preset ci-windows-mingw --output-on-failure
```

---

## 5. Running Verification Orchestrators

### Local Verification
`scripts/verify-local.py` automatically detects MinGW when `gcc`/`g++` is in PATH or when `MSYSTEM` is active:

```powershell
# Auto-detects MinGW and runs full 5-stage verification:
py scripts\verify-local.py

# Or using the PowerShell wrapper:
.\scripts\verify-local.ps1
```

### Distributed Development Orchestrator
```powershell
py scripts\verify-distributed-dev.py

# Or using the PowerShell wrapper:
.\scripts\verify-distributed-dev.ps1
```

---

## 6. MinGW-Specific Troubleshooting

### Issue 1: `Could not find a package configuration file provided by "gRPC"`
This error indicates that while the base GCC compiler (`g++`) is present, the **gRPC C++ development package** has not been installed in MSYS2 yet.
- Verify whether gRPC is installed:
  ```powershell
  C:\msys64\usr\bin\pacman.exe -Qs grpc
  ```
- If not installed, install the full development dependencies:
  ```powershell
  # For MinGW64 environment:
  C:\msys64\usr\bin\pacman.exe -S --needed mingw-w64-x86_64-grpc mingw-w64-x86_64-protobuf mingw-w64-x86_64-openssl mingw-w64-x86_64-gtest mingw-w64-x86_64-ninja

  # For UCRT64 environment:
  C:\msys64\usr\bin\pacman.exe -S --needed mingw-w64-ucrt-x86_64-grpc mingw-w64-ucrt-x86_64-protobuf mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-gtest mingw-w64-ucrt-x86_64-ninja
  ```
- Verify that `gRPCConfig.cmake` is now present:
  ```powershell
  Test-Path "C:\msys64\mingw64\lib\cmake\grpc\gRPCConfig.cmake"
  ```
- If MSYS2 is installed in a non-standard directory (e.g. `D:\msys64`), specify the prefix:
  ```powershell
  cmake --preset ci-windows-mingw -DCMAKE_PREFIX_PATH="D:/msys64/mingw64"
  ```

### Issue 2: Posix Path Conversion in Shells
If git or docker commands fail with path conversion errors in MSYS2 bash:
```bash
export MSYS_NO_PATHCONV=1
```

### Issue 3: Linker Errors on Windows Socket APIs (`WSAStartup`)
SecureCloud automatically links `ws2_32` on Windows platforms via target definitions in `cmake/modules/SecureCloudCompilerFlags.cmake`.
