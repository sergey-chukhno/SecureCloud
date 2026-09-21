#!/usr/bin/env bash
set -euo pipefail

# SecureCloud Distributed Development Environment Orchestrator Wrapper (SC-015)
# Thin shell wrapper invoking verify-distributed-dev.py

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Discover python3
PYTHON_BIN=""
for CANDIDATE in python3 py python; do
    if command -v "${CANDIDATE}" >/dev/null 2>&1; then
        PYTHON_BIN="${CANDIDATE}"
        break
    fi
done

if [ -z "${PYTHON_BIN}" ]; then
    echo "[ERROR] Python 3 was not found in PATH." >&2
    exit 1
fi

exec "${PYTHON_BIN}" "${SCRIPT_DIR}/verify-distributed-dev.py" "$@"
