#!/usr/bin/env bash
set -euo pipefail

# One-command full-lifecycle runner for SecureCloud Full-Stack Live Compose E2E Tests.
# Performs:
#   1. Clean Docker Compose wipe (down -v)
#   2. Fresh Compose startup + dev PKI verification + service readiness (demo-mvp-reset.sh)
#   3. Execution of all 5 live Compose E2E scenarios (SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1)
#   4. Guaranteed cleanup (trap EXIT): wipes containers and volumes (unless --keep-stack)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/compose/docker-compose.yml"

KEEP_STACK=0
BUILD_FIRST=0
PRESET="dev-debug"
EXTRA_ARGS=()

for arg in "$@"; do
    case "${arg}" in
        --keep-stack)
            KEEP_STACK=1
            ;;
        --build)
            BUILD_FIRST=1
            ;;
        --release)
            PRESET="dev-release"
            ;;
        --debug)
            PRESET="dev-debug"
            ;;
        --help|-h)
            cat <<'EOF'
Usage: scripts/run-compose-e2e-tests.sh [options] [-- <gtest args>]

Options:
  --keep-stack       Keep Docker Compose running after tests finish
  --build            Build the E2E test binary before running
  --debug            Use build/dev-debug binary (default)
  --release          Use build/dev-release binary
  -h, --help         Show this help message

Examples:
  ./scripts/run-compose-e2e-tests.sh
  ./scripts/run-compose-e2e-tests.sh --gtest_filter="*Scenario5*"
  ./scripts/run-compose-e2e-tests.sh --build --keep-stack
EOF
            exit 0
            ;;
        *)
            EXTRA_ARGS+=("${arg}")
            ;;
    esac
done

TEST_BIN="${REPO_ROOT}/build/${PRESET}/tests/integration/securecloud_client_gateway_backend_integration_test"

if [[ "${BUILD_FIRST}" -eq 1 || ! -x "${TEST_BIN}" ]]; then
    echo "[run-compose-e2e] Building securecloud_client_gateway_backend_integration_test (${PRESET})..."
    cmake --preset "${PRESET}" >/dev/null
    cmake --build "${REPO_ROOT}/build/${PRESET}" --target securecloud_client_gateway_backend_integration_test -j8
fi

cleanup() {
    local exit_code=$?
    echo ""
    if [[ "${KEEP_STACK}" -eq 1 ]]; then
        echo "[run-compose-e2e] Stack kept running (--keep-stack)."
    else
        echo "[run-compose-e2e] Wiping E2E containers and volumes (docker compose down -v)..."
        docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
        echo "[run-compose-e2e] Clean teardown complete."
    fi
    exit "${exit_code}"
}
trap cleanup EXIT

echo "[run-compose-e2e] 1/3 Wiping previous Docker Compose state..."
docker compose -f "${COMPOSE_FILE}" down -v

echo "[run-compose-e2e] 2/3 Starting fresh 5-service Docker Compose stack..."
"${REPO_ROOT}/scripts/demo-mvp-reset.sh" --keep-client-dbs

echo "[run-compose-e2e] 3/3 Running Full-Stack Live Compose E2E suite (5 scenarios)..."
cd "${REPO_ROOT}"
SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1 QT_QPA_PLATFORM=offscreen "${TEST_BIN}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}

echo ""
echo "[run-compose-e2e] Live Compose E2E suite PASSED."
