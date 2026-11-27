#!/usr/bin/env bash
set -euo pipefail

# One-command runner for SecureCloud Desktop Client Performance Benchmarks (CLIENT-015-T05).
# Runs all 7 ADR-010 budgets against real Qt 6 QML, real SQLCipher, and real OpenSSL 3.
# Does not require Docker Compose (100% self-contained local execution).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PRESET="dev-release"
FULL_SCALE=1
BUILD_FIRST=0
EXTRA_ARGS=()

for arg in "$@"; do
    case "${arg}" in
        --release)
            PRESET="dev-release"
            FULL_SCALE=1
            ;;
        --debug)
            PRESET="dev-debug"
            FULL_SCALE=0
            ;;
        --full)
            FULL_SCALE=1
            ;;
        --fast)
            FULL_SCALE=0
            ;;
        --build)
            BUILD_FIRST=1
            ;;
        --help|-h)
            cat <<'EOF'
Usage: scripts/run-client-benchmarks.sh [options] [-- <gtest args>]

Options:
  --release          Official dev-release (-O3) full-scale benchmark run (default, ~9.3 s)
  --debug            Fast dev-debug sanity benchmark run (~3.6 s)
  --full             Force SECURECLOUD_RUN_CLIENT_BENCHMARKS=1 (full ADR-010 workload counts)
  --fast             Force fast sanity workload counts
  --build            Configure & build client + benchmark targets before running
  -h, --help         Show this help message

Examples:
  ./scripts/run-client-benchmarks.sh
  ./scripts/run-client-benchmarks.sh --debug
  ./scripts/run-client-benchmarks.sh --gtest_filter="*BenchmarkF*"
EOF
            exit 0
            ;;
        *)
            EXTRA_ARGS+=("${arg}")
            ;;
    esac
done

CLIENT_BIN="${REPO_ROOT}/build/${PRESET}/src/client/securecloud-client"
BENCH_BIN="${REPO_ROOT}/build/${PRESET}/tests/unit/securecloud_client_performance_benchmark_test"

if [[ "${BUILD_FIRST}" -eq 1 || ! -x "${BENCH_BIN}" || ! -x "${CLIENT_BIN}" ]]; then
    echo "[run-client-benchmarks] Building securecloud-client & benchmark harness (${PRESET})..."
    cmake --preset "${PRESET}" >/dev/null
    cmake --build "${REPO_ROOT}/build/${PRESET}" --target securecloud-client securecloud_client_performance_benchmark_test -j8
fi

echo "[run-client-benchmarks] Running 7 Desktop Client Performance Budgets (preset=${PRESET}, full_scale=${FULL_SCALE})..."
cd "${REPO_ROOT}"
if [[ "${FULL_SCALE}" -eq 1 ]]; then
    SECURECLOUD_RUN_CLIENT_BENCHMARKS=1 QT_QPA_PLATFORM=offscreen "${BENCH_BIN}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
else
    QT_QPA_PLATFORM=offscreen "${BENCH_BIN}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
fi

echo ""
echo "[run-client-benchmarks] Client performance benchmark suite PASSED."
