#!/usr/bin/env bash
# ==============================================================================
# SecureCloud Local Verification POSIX Wrapper
# ==============================================================================
# Delegates execution directly to the Python orchestrator.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$(command -v python3 || command -v python || true)"

if [[ -z "${PYTHON_BIN}" ]]; then
    echo "[SecureCloud] Error: python3 is required for local verification orchestrator." >&2
    exit 1
fi

exec "${PYTHON_BIN}" "${SCRIPT_DIR}/verify-local.py" "$@"
