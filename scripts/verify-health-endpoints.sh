#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SecureCloud Automated Health & Readiness Verification Suite (SC-013-T06)
# ==============================================================================
# Performs empirical validation against real containerized microservices in
# Docker Compose:
#  1. Host PostgreSQL 14 invariant check on localhost:5432
#  2. Full Compose stack startup & steady-state readiness
#  3. mTLS liveness & readiness probes across all 5 services
#  4. Real Docker outage test: stop postgres, verify auth/files readiness degrades
#     to NOT_SERVING while liveness remains SERVING, and other services stay healthy
#  5. Real Docker recovery test: restart postgres, verify auth/files recover
#  6. Clean teardown and host PostgreSQL non-regression verification
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

COMPOSE_CMD="docker compose --ansi never -f deploy/compose/docker-compose.yml"
BUILD_DIR="${ROOT_DIR}/build/dev-debug"
PROBE_BIN="${BUILD_DIR}/tests/integration/securecloud_health_probe"

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_BLUE="\033[1;34m"

log_info() {
    echo -e "${COLOR_BLUE}[INFO] $1${COLOR_RESET}"
}

log_pass() {
    echo -e "${COLOR_GREEN}[PASS] $1${COLOR_RESET}"
}

log_fail() {
    echo -e "${COLOR_RED}[FAIL] $1${COLOR_RESET}"
    exit 1
}

cleanup() {
    log_info "Teardown: Stopping Compose stack..."
    $COMPOSE_CMD down >/dev/null 2>&1 || true
}

trap cleanup ERR

check_host_pg() {
    if [ -x /opt/homebrew/bin/pg_isready ]; then
        /opt/homebrew/bin/pg_isready -h localhost -p 5432 -q
    elif command -v pg_isready >/dev/null 2>&1; then
        pg_isready -h localhost -p 5432 -q
    else
        nc -z localhost 5432
    fi
}

log_info "Starting SecureCloud Health & Readiness Empirical Verification Suite..."

# Ensure health probe test runner binary exists
if [ ! -x "${PROBE_BIN}" ]; then
    log_info "Compiling securecloud_health_probe CLI runner..."
    cmake --build "${BUILD_DIR}" --target securecloud_health_probe
fi

CA_CERT="${ROOT_DIR}/deploy/dev-pki/ca/ca.crt"
CLIENT_CERT="${ROOT_DIR}/deploy/dev-pki/services/gateway/gateway.crt"
CLIENT_KEY="${ROOT_DIR}/deploy/dev-pki/services/gateway/gateway.key"

probe_service() {
    local target="$1"
    local server_san="$2"
    local service_name="$3"
    local expected="$4"

    local output
    if output=$("${PROBE_BIN}" \
        --target "${target}" \
        --server-name "${server_san}" \
        --service-name "${service_name}" \
        --ca "${CA_CERT}" \
        --cert "${CLIENT_CERT}" \
        --key "${CLIENT_KEY}" \
        --expected-status "${expected}" \
        --timeout-ms 3000 2>&1); then
        return 0
    else
        echo -e "${COLOR_RED}Probe failed for ${server_san} (${target}) service='${service_name}', expected='${expected}': ${output}${COLOR_RESET}"
        return 1
    fi
}

# ==============================================================================
# Check 1: Host PostgreSQL 14 Baseline Check (localhost:5432)
# ==============================================================================
log_info "Check 1: Verifying host PostgreSQL 14 baseline on localhost:5432..."
if check_host_pg; then
    log_pass "Host PostgreSQL 14 is active and untouched on localhost:5432 prior to Compose startup."
else
    log_fail "Host PostgreSQL 14 is not reachable on localhost:5432!"
fi

# ==============================================================================
# Check 2: Compose Environment Startup & Service Readiness
# ==============================================================================
log_info "Check 2: Starting Docker Compose stack (building if needed)..."
$COMPOSE_CMD up -d --build --remove-orphans >/dev/null

log_info "Waiting for persistence infrastructure to reach healthy state..."
for SERVICE in postgres scylladb clickhouse minio; do
    TRIES=0
    HEALTH=$($COMPOSE_CMD ps "$SERVICE" --format '{{.Health}}')
    while [ "$HEALTH" = "starting" ] && [ $TRIES -lt 30 ]; do
        sleep 2
        TRIES=$((TRIES + 1))
        HEALTH=$($COMPOSE_CMD ps "$SERVICE" --format '{{.Health}}')
    done
    if [ "$HEALTH" = "healthy" ]; then
        log_pass "Persistence service '$SERVICE' is healthy."
    else
        log_fail "Persistence service '$SERVICE' failed healthcheck (status: '$HEALTH')."
    fi
done

log_info "Waiting for microservices to reach running state..."
for SERVICE in gateway auth messaging files audit; do
    TRIES=0
    STATE=$($COMPOSE_CMD ps "$SERVICE" --format '{{.State}}')
    while [ "$STATE" != "running" ] && [ $TRIES -lt 15 ]; do
        sleep 1
        TRIES=$((TRIES + 1))
        STATE=$($COMPOSE_CMD ps "$SERVICE" --format '{{.State}}')
    done
    if [ "$STATE" = "running" ]; then
        log_pass "Microservice '$SERVICE' is running."
    else
        log_fail "Microservice '$SERVICE' is not running (state: '$STATE')."
    fi
done

# Allow a moment for initial gRPC listeners to accept connections
sleep 2

# ==============================================================================
# Check 3: Empirical Steady-State mTLS Health & Readiness Probes
# ==============================================================================
log_info "Check 3: Probing steady-state mTLS health and readiness across all 5 services..."

# Gateway (50051)
if probe_service "127.0.0.1:50051" "gateway" "" "SERVING" && \
   probe_service "127.0.0.1:50051" "gateway" "gateway" "SERVING" && \
   probe_service "127.0.0.1:50051" "gateway" "readiness" "SERVING"; then
    log_pass "Gateway: Liveness SERVING, Readiness SERVING."
else
    log_fail "Gateway steady-state probe failed."
fi

# Auth (50052)
if probe_service "127.0.0.1:50052" "auth" "" "SERVING" && \
   probe_service "127.0.0.1:50052" "auth" "auth" "SERVING" && \
   probe_service "127.0.0.1:50052" "auth" "readiness" "SERVING"; then
    log_pass "Auth: Liveness SERVING, Readiness SERVING."
else
    log_fail "Auth steady-state probe failed."
fi

# Messaging (50053)
if probe_service "127.0.0.1:50053" "messaging" "" "SERVING" && \
   probe_service "127.0.0.1:50053" "messaging" "messaging" "SERVING" && \
   probe_service "127.0.0.1:50053" "messaging" "readiness" "SERVING"; then
    log_pass "Messaging: Liveness SERVING, Readiness SERVING."
else
    log_fail "Messaging steady-state probe failed."
fi

# Files (50054)
if probe_service "127.0.0.1:50054" "files" "" "SERVING" && \
   probe_service "127.0.0.1:50054" "files" "files" "SERVING" && \
   probe_service "127.0.0.1:50054" "files" "readiness" "SERVING"; then
    log_pass "Files: Liveness SERVING, Readiness SERVING."
else
    log_fail "Files steady-state probe failed."
fi

# Audit (50055)
if probe_service "127.0.0.1:50055" "audit" "" "SERVING" && \
   probe_service "127.0.0.1:50055" "audit" "audit" "SERVING" && \
   probe_service "127.0.0.1:50055" "audit" "readiness" "SERVING"; then
    log_pass "Audit: Liveness SERVING, Readiness SERVING."
else
    log_fail "Audit steady-state probe failed."
fi

# ==============================================================================
# Check 4: Real Docker Dependency Outage Test (PostgreSQL Down)
# ==============================================================================
log_info "Check 4: Simulating real Docker dependency outage (stopping postgres container)..."
$COMPOSE_CMD stop postgres >/dev/null

log_info "Verifying degraded readiness and persistent liveness..."

# Auth depends on PostgreSQL: readiness must degrade, liveness must remain SERVING
if probe_service "127.0.0.1:50052" "auth" "" "SERVING" && \
   probe_service "127.0.0.1:50052" "auth" "readiness" "NOT_SERVING"; then
    log_pass "Auth: Liveness remained SERVING while Readiness degraded to NOT_SERVING."
else
    log_fail "Auth failed dependency degradation contract during postgres outage."
fi

# Files depends on PostgreSQL: readiness must degrade, liveness must remain SERVING
if probe_service "127.0.0.1:50054" "files" "" "SERVING" && \
   probe_service "127.0.0.1:50054" "files" "readiness" "NOT_SERVING"; then
    log_pass "Files: Liveness remained SERVING while Readiness degraded to NOT_SERVING."
else
    log_fail "Files failed dependency degradation contract during postgres outage."
fi

# Messaging does NOT depend on PostgreSQL: readiness must stay SERVING
if probe_service "127.0.0.1:50053" "messaging" "readiness" "SERVING"; then
    log_pass "Messaging: Readiness remained SERVING (unaffected by postgres outage)."
else
    log_fail "Messaging readiness improperly degraded during postgres outage."
fi

# Audit does NOT depend on PostgreSQL: readiness must stay SERVING
if probe_service "127.0.0.1:50055" "audit" "readiness" "SERVING"; then
    log_pass "Audit: Readiness remained SERVING (unaffected by postgres outage)."
else
    log_fail "Audit readiness improperly degraded during postgres outage."
fi

# Gateway has local readiness only: readiness must stay SERVING
if probe_service "127.0.0.1:50051" "gateway" "readiness" "SERVING"; then
    log_pass "Gateway: Readiness remained SERVING (local readiness preserved)."
else
    log_fail "Gateway readiness improperly degraded during postgres outage."
fi

# ==============================================================================
# Check 5: Real Docker Dependency Recovery Test (PostgreSQL Restored)
# ==============================================================================
log_info "Check 5: Restoring postgres container and verifying readiness recovery..."
$COMPOSE_CMD start postgres >/dev/null

log_info "Waiting for postgres to regain healthy status..."
TRIES=0
HEALTH=$($COMPOSE_CMD ps postgres --format '{{.Health}}')
while [ "$HEALTH" != "healthy" ] && [ $TRIES -lt 30 ]; do
    sleep 2
    TRIES=$((TRIES + 1))
    HEALTH=$($COMPOSE_CMD ps postgres --format '{{.Health}}')
done

if [ "$HEALTH" = "healthy" ]; then
    log_pass "Postgres container regained healthy status."
else
    log_fail "Postgres failed to become healthy after restart (status: '$HEALTH')."
fi

# Verify Auth readiness recovers to SERVING
TRIES=0
AUTH_RECOVERED=0
while [ $TRIES -lt 10 ]; do
    if probe_service "127.0.0.1:50052" "auth" "readiness" "SERVING" >/dev/null 2>&1; then
        AUTH_RECOVERED=1
        break
    fi
    sleep 1
    TRIES=$((TRIES + 1))
done

if [ "$AUTH_RECOVERED" -eq 1 ]; then
    log_pass "Auth: Readiness successfully recovered to SERVING."
else
    log_fail "Auth readiness failed to recover to SERVING."
fi

# Verify Files readiness recovers to SERVING
TRIES=0
FILES_RECOVERED=0
while [ $TRIES -lt 10 ]; do
    if probe_service "127.0.0.1:50054" "files" "readiness" "SERVING" >/dev/null 2>&1; then
        FILES_RECOVERED=1
        break
    fi
    sleep 1
    TRIES=$((TRIES + 1))
done

if [ "$FILES_RECOVERED" -eq 1 ]; then
    log_pass "Files: Readiness successfully recovered to SERVING."
else
    log_fail "Files readiness failed to recover to SERVING."
fi

# ==============================================================================
# Check 6: Teardown & Host PostgreSQL Invariant Non-Regression
# ==============================================================================
log_info "Check 6: Performing clean teardown and verifying host PostgreSQL non-regression..."
$COMPOSE_CMD down >/dev/null

if check_host_pg; then
    log_pass "Host PostgreSQL 14 remains active on localhost:5432 after Compose teardown."
else
    log_fail "Host PostgreSQL 14 regression detected on localhost:5432 after Compose teardown!"
fi

RUNNING_CONTAINERS=$($COMPOSE_CMD ps -q)
if [ -z "$RUNNING_CONTAINERS" ]; then
    log_pass "Zero leftover SecureCloud Compose containers remain."
else
    log_fail "Leftover containers detected after teardown: $RUNNING_CONTAINERS"
fi

log_pass "ALL 6 HEALTH & READINESS VERIFICATION CHECKS PASSED SUCCESSFULLY!"
