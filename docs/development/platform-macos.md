# macOS Development Environment Guide

This guide details the setup and configuration of the SecureCloud development environment on macOS (Apple Silicon arm64 and Intel x86_64).

---

## 1. Toolchain & Package Installation

Install required dependencies via Homebrew:

```bash
# Update Homebrew
brew update

# Install Core Toolchain & Build Utilities
brew install cmake ninja git python3

# Install Development Dependencies
brew install openssl@3 protobuf grpc googletest llvm
```

### Keg-Only OpenSSL Configuration
Homebrew installs `openssl@3` as a keg-only package. Ensure OpenSSL 3 headers and binaries take precedence in your terminal shell (`~/.zshrc` or `~/.bash_profile`):

```bash
export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig"
```

> [!TIP]
> On Intel Macs, the Homebrew prefix is `/usr/local` rather than `/opt/homebrew`. Use `brew --prefix openssl@3` to verify the active prefix.

---

## 2. CMake Presets for macOS

The project includes two primary presets for macOS in `CMakePresets.json`:
- `dev-debug`: Standard local development preset with debug symbols (`-g`), compile commands export, and strict hardening warnings.
- `ci-macos`: Mirror of the GitHub Actions CI environment.

### Configure and Build
```bash
# Configure with Ninja and Debug symbols:
cmake --preset dev-debug

# Build all targets:
cmake --build --preset dev-debug

# Verify contracts target:
cmake --build --preset dev-debug --target verify-contracts

# Run tests:
ctest --preset dev-debug --output-on-failure
```

---

## 3. Clang-Tidy & Clang-Format Setup

SecureCloud enforces zero formatting violations via `.clang-format` (Clang-Format 18+).

```bash
# Point to Homebrew LLVM clang-format and clang-tidy:
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

# Enable Clang-Tidy static analysis during configure:
cmake --preset dev-debug -DENABLE_CLANG_TIDY=ON

# Format in-place:
cmake --build --preset dev-debug --target format

# Check formatting:
cmake --build --preset dev-debug --target check-format
```

---

## 4. Running Verification Orchestrator

Execute `scripts/verify-local.py` for comprehensive local pre-commit checks:
```bash
python3 scripts/verify-local.py
```

Execute `scripts/verify-distributed-dev.py` for complete distributed container and mTLS validation:
```bash
python3 scripts/verify-distributed-dev.py
```

---

## 5. macOS-Specific Troubleshooting

### Issue 1: `AppleClang` vs Homebrew LLVM
If CMake discovers Homebrew Clang instead of AppleClang and you prefer Apple's compiler, unset `CC` and `CXX` or explicitly configure:
```bash
cmake --preset dev-debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
```

### Issue 2: Docker Desktop Socket on macOS
If `docker compose` fails to connect to Docker daemon:
```bash
# Ensure Docker Desktop is running
open -a Docker

# Verify daemon socket
docker info
```
