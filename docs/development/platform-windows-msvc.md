# Windows MSVC Development Environment Guide

This guide details the setup and configuration of the SecureCloud development environment using the Microsoft Visual C++ (MSVC) toolchain and vcpkg.

---

## 1. Toolchain & Prerequisites

### 1. Visual Studio 2022
Install **Visual Studio 2022** (Community, Professional, or Enterprise) with the following workloads:
- **Desktop development with C++**
- Individual components:
  - MSVC v143 - VS 2022 C++ x64/x86 build tools (latest)
  - Windows 10/11 SDK (10.0.22621.0 or newer)
  - C++ CMake tools for Windows
  - C++ Clang tools for Windows (optional)

### 2. Ninja Build System
```powershell
winget install Ninja-build.Ninja
# or:
choco install ninja
```

### 3. vcpkg Dependency Manager
Clone and bootstrap vcpkg if not already installed:
```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg
.\bootstrap-vcpkg.bat
```
Set the environment variable:
```powershell
[System.Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\vcpkg', 'User')
$env:VCPKG_ROOT = "C:\vcpkg"
```

### 4. Git & Python
```powershell
winget install Git.Git
winget install Python.Python.3.12
```

---

## 2. CMake Preset & vcpkg Manifest Mode

SecureCloud specifies its dependencies in `vcpkg.json` (manifest mode). The `ci-windows-msvc` preset in `CMakePresets.json` uses the `x64-windows` triplet and `cl.exe`:

```powershell
# Open "Developer PowerShell for VS 2022" or "x64 Native Tools Command Prompt"
cd C:\Path\To\SecureCloud

# Configure with vcpkg manifest mode:
cmake --preset ci-windows-msvc -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"

# Build all targets:
cmake --build --preset ci-windows-msvc

# Validate generated contracts:
cmake --build --preset ci-windows-msvc --target verify-contracts

# Run CTest suite:
ctest --preset ci-windows-msvc --output-on-failure
```

---

## 3. Running Verification Orchestrators

### Local Verification
```powershell
# Using the PowerShell wrapper:
.\scripts\verify-local.ps1 -Preset ci-windows-msvc

# Or via Python directly:
py scripts\verify-local.py --preset ci-windows-msvc
```

### Distributed Development Orchestrator
```powershell
# Using the PowerShell wrapper:
.\scripts\verify-distributed-dev.ps1 -Preset ci-windows-msvc

# Or via Python directly:
py scripts\verify-distributed-dev.py --preset ci-windows-msvc
```

---

## 4. Docker Desktop on Windows

Ensure Docker Desktop is running with the **WSL2-based engine**:
1. Open Docker Desktop Settings -> General -> **Use the WSL 2 based engine**.
2. Open Docker Desktop Settings -> Resources -> WSL Integration -> Enable integration with your default WSL distro.
3. Test daemon accessibility from PowerShell:
   ```powershell
   docker compose version
   ```

---

## 5. MSVC-Specific Troubleshooting

### Issue 1: `/WX` (Warnings as Errors) & Unreachable Code
SecureCloud enables `/W4 /WX /permissive-` on MSVC. All code must be warning-free. In particular, ensure lambdas or functions ending with an unconditional exception (`throw`) do not include redundant return statements (`warning C4702: unreachable code`).

### Issue 2: DLL Consumption Flags
When compiling code against vcpkg shared/static libraries, ensure:
- `-DPROTOBUF_USE_DLLS`
- `-DABSL_CONSUME_DLL`
- `-DGTEST_LINKED_AS_SHARED_LIBRARY=1`
These definitions are configured automatically in `SecureCloudCompilerFlags.cmake` and target configurations.

### Issue 3: Line Endings (CRLF vs LF)
Ensure git preserves LF for repository files:
```powershell
git config --global core.autocrlf input
```
