#!/usr/bin/env bash
set -euo pipefail

# One-command full-lifecycle runner for SecureCloud Backend Performance Benchmarks.
# Performs:
#   1. Clean Docker Compose wipe (down -v)
#   2. Fresh Compose startup + Alice/Bob Argon2id user seeding (demo-mvp-reset.sh)
#   3. Ephemeral Gateway override disabling single-IP rate limit (for uncapped capacity)
#   4. Execution of all 6 benchmark groups (scripts/benchmark_backend_compose.py)
#   5. Guaranteed cleanup (trap EXIT): removes ephemeral override and wipes volumes
#      (or restores default rate-limited Gateway when --keep-stack is passed)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/compose/docker-compose.yml"

KEEP_STACK=0
WITH_RATE_LIMIT=0
JSON_OUT="/tmp/backend_bench_results.json"

for arg in "$@"; do
    case "${arg}" in
        --keep-stack)
            KEEP_STACK=1
            ;;
        --with-rate-limit)
            WITH_RATE_LIMIT=1
            ;;
        --json-out=*)
            JSON_OUT="${arg#--json-out=}"
            ;;
        --help|-h)
            cat <<'EOF'
Usage: scripts/run-backend-benchmarks.sh [options]

Options:
  --keep-stack          Keep Docker Compose running after benchmarks (restores default Gateway rate limiter)
  --with-rate-limit     Run benchmarks with default single-IP rate limiter enabled (50 req/s, 100 burst)
  --json-out=<path>     Output path for raw JSON results (default: /tmp/backend_bench_results.json)
  -h, --help            Show this help message
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}" >&2
            exit 1
            ;;
    esac
done

OVERRIDE_FILE="$(mktemp /tmp/sc-bench-override.XXXXXX.yml)"

cleanup() {
    local exit_code=$?
    echo ""
    echo "[run-backend-benchmarks] Cleaning up temporary files and Docker state..."
    rm -f "${OVERRIDE_FILE}" /tmp/sc_bench_curl_bridge.c /tmp/sc_bench_curl_bridge.dylib
    if [[ "${KEEP_STACK}" -eq 1 ]]; then
        if [[ "${WITH_RATE_LIMIT}" -eq 0 ]]; then
            echo "[run-backend-benchmarks] Restoring default rate-limited Gateway container..."
            docker compose -f "${COMPOSE_FILE}" up -d --no-deps --force-recreate gateway >/dev/null 2>&1 || true
        fi
        echo "[run-backend-benchmarks] Stack kept running (--keep-stack)."
    else
        echo "[run-backend-benchmarks] Wiping benchmark containers and volumes (docker compose down -v)..."
        docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
        echo "[run-backend-benchmarks] Clean teardown complete."
    fi
    exit "${exit_code}"
}
trap cleanup EXIT

echo "[run-backend-benchmarks] 1/4 Wiping previous Docker Compose state..."
docker compose -f "${COMPOSE_FILE}" down -v

echo "[run-backend-benchmarks] 2/4 Starting fresh stack and seeding demo users..."
"${REPO_ROOT}/scripts/demo-mvp-reset.sh" --keep-client-dbs

if [[ "${WITH_RATE_LIMIT}" -eq 0 ]]; then
    echo "[run-backend-benchmarks] 3/4 Temporarily disabling Gateway single-IP rate limiter for capacity run..."
    cat <<'YAML' > "${OVERRIDE_FILE}"
services:
  gateway:
    environment:
      SECURECLOUD_GATEWAY_RATE_LIMIT_ENABLED: "false"
YAML
    docker compose -f "${COMPOSE_FILE}" -f "${OVERRIDE_FILE}" up -d --no-deps gateway
    sleep 3
else
    echo "[run-backend-benchmarks] 3/4 Keeping default Gateway rate limiter enabled (--with-rate-limit)..."
fi

echo "[run-backend-benchmarks] 4/4 Running all 6 backend benchmark groups..."
python3 "${REPO_ROOT}/scripts/benchmark_backend_compose.py" --json-out "${JSON_OUT}"

echo ""
echo "[run-backend-benchmarks] Benchmark suite completed successfully."
echo "[run-backend-benchmarks] Raw JSON results saved to: ${JSON_OUT}"
