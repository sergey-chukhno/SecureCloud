#!/usr/bin/env bash
set -euo pipefail

# SecureCloud Formatting Check Script
# Convenience wrapper delegating to CMake check-format target.

PRESET="${1:-dev-debug}"

echo "[SecureCloud] Running formatting check using preset: ${PRESET}..."
cmake --build --preset "${PRESET}" --target check-format
