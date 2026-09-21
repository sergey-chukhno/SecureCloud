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

# Configurable Compose host ports (default: 50051-50055)
GATEWAY_HOST_PORT="${GATEWAY_HOST_PORT:-50051}"
AUTH_HOST_PORT="${AUTH_HOST_PORT:-50052}"
MESSAGING_HOST_PORT="${MESSAGING_HOST_PORT:-50053}"
FILES_HOST_PORT="${FILES_HOST_PORT:-50054}"
AUDIT_HOST_PORT="${AUDIT_HOST_PORT:-50055}"

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
    local exit_code=$?
    trap - EXIT INT TERM
    log_info "Teardown: Ensuring Compose stack is stopped..."
    $COMPOSE_CMD down >/dev/null 2>&1 || true
    exit "${exit_code}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

# Gateway (${GATEWAY_HOST_PORT})
if probe_service "127.0.0.1:${GATEWAY_HOST_PORT}" "gateway" "" "SERVING" && \
   probe_service "127.0.0.1:${GATEWAY_HOST_PORT}" "gateway" "gateway" "SERVING" && \
   probe_service "127.0.0.1:${GATEWAY_HOST_PORT}" "gateway" "readiness" "SERVING"; then
    log_pass "Gateway: Liveness SERVING, Readiness SERVING."
else
    log_fail "Gateway steady-state probe failed."
fi

# Auth (${AUTH_HOST_PORT})
if probe_service "127.0.0.1:${AUTH_HOST_PORT}" "auth" "" "SERVING" && \
   probe_service "127.0.0.1:${AUTH_HOST_PORT}" "auth" "auth" "SERVING" && \
   probe_service "127.0.0.1:${AUTH_HOST_PORT}" "auth" "readiness" "SERVING"; then
    log_pass "Auth: Liveness SERVING, Readiness SERVING."
else
    log_fail "Auth steady-state probe failed."
fi

# Messaging (${MESSAGING_HOST_PORT})
if probe_service "127.0.0.1:${MESSAGING_HOST_PORT}" "messaging" "" "SERVING" && \
   probe_service "127.0.0.1:${MESSAGING_HOST_PORT}" "messaging" "messaging" "SERVING" && \
   probe_service "127.0.0.1:${MESSAGING_HOST_PORT}" "messaging" "readiness" "SERVING"; then
    log_pass "Messaging: Liveness SERVING, Readiness SERVING."
else
    log_fail "Messaging steady-state probe failed."
fi

# Files (${FILES_HOST_PORT})
if probe_service "127.0.0.1:${FILES_HOST_PORT}" "files" "" "SERVING" && \
   probe_service "127.0.0.1:${FILES_HOST_PORT}" "files" "files" "SERVING" && \
   probe_service "127.0.0.1:${FILES_HOST_PORT}" "files" "readiness" "SERVING"; then
    log_pass "Files: Liveness SERVING, Readiness SERVING."
else
    log_fail "Files steady-state probe failed."
fi

# Audit (${AUDIT_HOST_PORT})
if probe_service "127.0.0.1:${AUDIT_HOST_PORT}" "audit" "" "SERVING" && \
   probe_service "127.0.0.1:${AUDIT_HOST_PORT}" "audit" "audit" "SERVING" && \
   probe_service "127.0.0.1:${AUDIT_HOST_PORT}" "audit" "readiness" "SERVING"; then
    log_pass "Audit: Liveness SERVING, Readiness SERVING."
else
    log_fail "Audit steady-state probe failed."
fi

# ==============================================================================
# Check 3b: Fail-Closed Security Negative Probes (Live Microservices)
# ==============================================================================
log_info "Check 3b: Validating fail-closed security boundaries against live microservices..."

# 1. Server SAN Mismatch Rejection
if "${PROBE_BIN}" --target "127.0.0.1:${AUTH_HOST_PORT}" --server-name "unauthorized.attacker.org" --service-name "" --ca "${CA_CERT}" --cert "${CLIENT_CERT}" --key "${CLIENT_KEY}" --expected-status "SERVING" --timeout-ms 1500 >/dev/null 2>&1; then
    log_fail "Security vulnerability: Server SAN mismatch connection was accepted by auth service!"
else
    log_pass "Server SAN mismatch rejected fail-closed."
fi

# 2. Untrusted CA Certificate Rejection
FAKE_CA="${ROOT_DIR}/build/fake_ca.crt"
openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out "${FAKE_CA}" -days 1 -nodes -subj "/CN=FakeCA" >/dev/null 2>&1 || true
if [ -f "${FAKE_CA}" ]; then
    if "${PROBE_BIN}" --target "127.0.0.1:${AUTH_HOST_PORT}" --server-name "auth" --service-name "" --ca "${FAKE_CA}" --cert "${CLIENT_CERT}" --key "${CLIENT_KEY}" --expected-status "SERVING" --timeout-ms 1500 >/dev/null 2>&1; then
        rm -f "${FAKE_CA}"
        log_fail "Security vulnerability: Untrusted CA connection was accepted by auth service!"
    else
        log_pass "Untrusted CA rejected fail-closed."
    fi
    rm -f "${FAKE_CA}"
fi

# ==============================================================================
# Check 4: Real Docker Dependency Outage Test (PostgreSQL Down)
# ==============================================================================
log_info "Check 4: Simulating real Docker dependency outage (stopping postgres container)..."
$COMPOSE_CMD stop postgres >/dev/null

if [ "${SECURECLOUD_SIMULATE_POST_OUTAGE_FAILURE:-0}" = "1" ]; then
    log_info "[SIMULATION] Simulating verification check failure immediately after PostgreSQL outage begins..."
    log_fail "Simulated verification failure after postgres outage"
fi

log_info "Verifying degraded readiness and persistent liveness..."

# Auth depends on PostgreSQL: readiness must degrade, liveness must remain SERVING
if probe_service "127.0.0.1:${AUTH_HOST_PORT}" "auth" "" "SERVING" && \
   probe_service "127.0.0.1:${AUTH_HOST_PORT}" "auth" "readiness" "NOT_SERVING"; then
    log_pass "Auth: Liveness remained SERVING while Readiness degraded to NOT_SERVING."
else
    log_fail "Auth failed dependency degradation contract during postgres outage."
fi

# Files depends on PostgreSQL: readiness must degrade, liveness must remain SERVING
if probe_service "127.0.0.1:${FILES_HOST_PORT}" "files" "" "SERVING" && \
   probe_service "127.0.0.1:${FILES_HOST_PORT}" "files" "readiness" "NOT_SERVING"; then
    log_pass "Files: Liveness remained SERVING while Readiness degraded to NOT_SERVING."
else
    log_fail "Files failed dependency degradation contract during postgres outage."
fi

# Messaging does NOT depend on PostgreSQL: readiness must stay SERVING
if probe_service "127.0.0.1:${MESSAGING_HOST_PORT}" "messaging" "readiness" "SERVING"; then
    log_pass "Messaging: Readiness remained SERVING (unaffected by postgres outage)."
else
    log_fail "Messaging readiness improperly degraded during postgres outage."
fi

# Audit does NOT depend on PostgreSQL: readiness must stay SERVING
if probe_service "127.0.0.1:${AUDIT_HOST_PORT}" "audit" "readiness" "SERVING"; then
    log_pass "Audit: Readiness remained SERVING (unaffected by postgres outage)."
else
    log_fail "Audit readiness improperly degraded during postgres outage."
fi

# Gateway has local readiness only: readiness must stay SERVING
if probe_service "127.0.0.1:${GATEWAY_HOST_PORT}" "gateway" "readiness" "SERVING"; then
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
    if probe_service "127.0.0.1:${AUTH_HOST_PORT}" "auth" "readiness" "SERVING" >/dev/null 2>&1; then
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
    if probe_service "127.0.0.1:${FILES_HOST_PORT}" "files" "readiness" "SERVING" >/dev/null 2>&1; then
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
# Check 5b: Real Docker Dependency Outage Test 2 (ClickHouse Outage & Recovery)
# ==============================================================================
log_info "Check 5b: Simulating secondary dependency outage (stopping clickhouse container)..."
$COMPOSE_CMD stop clickhouse >/dev/null

log_info "Verifying Audit readiness degrades to NOT_SERVING while others stay unaffected..."

# Audit depends on ClickHouse: readiness must degrade, liveness must remain SERVING
if probe_service "127.0.0.1:${AUDIT_HOST_PORT}" "audit" "" "SERVING" && \
   probe_service "127.0.0.1:${AUDIT_HOST_PORT}" "audit" "readiness" "NOT_SERVING"; then
    log_pass "Audit: Liveness remained SERVING while Readiness degraded to NOT_SERVING."
else
    log_fail "Audit failed dependency degradation contract during clickhouse outage."
fi

# Auth, Files, Messaging, Gateway must NOT degrade
if probe_service "127.0.0.1:${AUTH_HOST_PORT}" "auth" "readiness" "SERVING" && \
   probe_service "127.0.0.1:${FILES_HOST_PORT}" "files" "readiness" "SERVING" && \
   probe_service "127.0.0.1:${MESSAGING_HOST_PORT}" "messaging" "readiness" "SERVING" && \
   probe_service "127.0.0.1:${GATEWAY_HOST_PORT}" "gateway" "readiness" "SERVING"; then
    log_pass "Auth, Files, Messaging, Gateway: Readiness remained SERVING (unaffected by clickhouse outage)."
else
    log_fail "Collateral readiness degradation detected during clickhouse outage."
fi

log_info "Restoring clickhouse container and verifying Audit readiness recovery..."
$COMPOSE_CMD start clickhouse >/dev/null

TRIES=0
HEALTH=$($COMPOSE_CMD ps clickhouse --format '{{.Health}}')
while [ "$HEALTH" != "healthy" ] && [ $TRIES -lt 30 ]; do
    sleep 2
    TRIES=$((TRIES + 1))
    HEALTH=$($COMPOSE_CMD ps clickhouse --format '{{.Health}}')
done

if [ "$HEALTH" = "healthy" ]; then
    log_pass "Clickhouse container regained healthy status."
else
    log_fail "Clickhouse failed to become healthy after restart (status: '$HEALTH')."
fi

TRIES=0
AUDIT_RECOVERED=0
while [ $TRIES -lt 10 ]; do
    if probe_service "127.0.0.1:${AUDIT_HOST_PORT}" "audit" "readiness" "SERVING" >/dev/null 2>&1; then
        AUDIT_RECOVERED=1
        break
    fi
    sleep 1
    TRIES=$((TRIES + 1))
done

if [ "$AUDIT_RECOVERED" -eq 1 ]; then
    log_pass "Audit: Readiness successfully recovered to SERVING."
else
    log_fail "Audit readiness failed to recover to SERVING."
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

# ==============================================================================
# Check 7: Post-Outage Failure Cleanup Trap Resilience
# ==============================================================================
if [ "${SECURECLOUD_SIMULATE_POST_OUTAGE_FAILURE:-0}" = "0" ]; then
    log_info "Check 7: Validating cleanup trap execution when failure occurs after postgres outage..."
    SUB_EXIT=0
    SECURECLOUD_SIMULATE_POST_OUTAGE_FAILURE=1 "${SCRIPT_DIR}/verify-health-endpoints.sh" >/dev/null 2>&1 || SUB_EXIT=$?
    if [ "$SUB_EXIT" -eq 0 ]; then
        log_fail "Expected verify-health-endpoints.sh to fail under simulated post-outage failure, but it succeeded!"
    fi
    log_pass "Subshell failed with expected exit code (${SUB_EXIT})."

    REMAINING_CONTAINERS=$($COMPOSE_CMD ps -q)
    if [ -n "$REMAINING_CONTAINERS" ]; then
        log_fail "Leftover containers detected after post-outage failure! Cleanup trap failed."
    fi
    log_pass "Teardown verified: Zero leftover Compose containers remain."

    if check_host_pg; then
        log_pass "Host PostgreSQL 14 remains active and untouched on localhost:5432 after failure teardown."
    else
        log_fail "Host PostgreSQL 14 regression detected on localhost:5432 after failure teardown!"
    fi
fi

log_pass "ALL 7 HEALTH & READINESS VERIFICATION CHECKS PASSED SUCCESSFULLY!"
