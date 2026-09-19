#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SecureCloud Automated Service Configuration Verification Suite (SC12-T05)
# ==============================================================================
# Validates typed configuration loading, fail-closed startup hardening,
# container secret masking, Compose runtime wiring, and verifies non-regression
# of the developer machine's host PostgreSQL 14 instance on localhost:5432.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

COMPOSE_CMD="docker compose --ansi never -f deploy/compose/docker-compose.yml"
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

check_host_pg() {
    if [ -x /opt/homebrew/bin/pg_isready ]; then
        /opt/homebrew/bin/pg_isready -h localhost -p 5432 -q
    elif command -v pg_isready >/dev/null 2>&1; then
        pg_isready -h localhost -p 5432 -q
    else
        nc -z localhost 5432
    fi
}

check_sc_pg() {
    if [ -x /opt/homebrew/bin/pg_isready ]; then
        /opt/homebrew/bin/pg_isready -h localhost -p 5433 -q
    elif command -v pg_isready >/dev/null 2>&1; then
        pg_isready -h localhost -p 5433 -q
    else
        nc -z localhost 5433
    fi
}

log_info "Starting SecureCloud Service Configuration & Host Non-Regression Verification Suite..."

# ==============================================================================
# Check 1: Host PostgreSQL Initial State Check (localhost:5432)
# ==============================================================================
log_info "Check 1: Verifying host PostgreSQL 14 initial state on localhost:5432..."
if check_host_pg; then
    log_pass "Host PostgreSQL 14 is active and accepting connections on localhost:5432 prior to Compose startup."
else
    log_fail "Host PostgreSQL 14 is not reachable on localhost:5432!"
fi

# ==============================================================================
# Check 2: Compose File Syntax Validation
# ==============================================================================
log_info "Check 2: Validating Docker Compose syntax..."
if $COMPOSE_CMD config >/dev/null; then
    log_pass "Docker Compose file syntax is valid."
else
    log_fail "Docker Compose file syntax validation failed."
fi

# ==============================================================================
# Check 3: Configuration CTest Unit Test Suite Execution
# ==============================================================================
log_info "Check 3: Running CTest configuration test suite..."
if ctest --preset dev-debug -R "Config|ServiceConfig" --output-on-failure >/dev/null; then
    log_pass "CTest configuration unit tests passed."
else
    log_fail "CTest configuration unit tests failed."
fi

# ==============================================================================
# Check 4: Negative Fail-Closed Test (Malformed / Out-of-Range Port)
# ==============================================================================
log_info "Check 4: Verifying negative fail-closed startup on out-of-range port (99999)..."
set +e
PORT_TEST_OUT=$($COMPOSE_CMD run --rm -e SECURECLOUD_GATEWAY_GRPC_PORT=99999 gateway 2>&1)
PORT_TEST_EXIT=$?
set -e
if [ "$PORT_TEST_EXIT" -ne 0 ] && echo "$PORT_TEST_OUT" | grep -q "FATAL: Configuration validation failed"; then
    log_pass "Gateway exited with code $PORT_TEST_EXIT and logged validation error."
else
    log_fail "Gateway failed to fail-closed on malformed port (Exit: $PORT_TEST_EXIT, Output: '$PORT_TEST_OUT')."
fi

# ==============================================================================
# Check 5: Negative Fail-Closed Test (Missing Required Credential)
# ==============================================================================
log_info "Check 5: Verifying negative fail-closed startup on missing database password..."
set +e
AUTH_TEST_OUT=$($COMPOSE_CMD run --rm -e SECURECLOUD_AUTH_DB_PASSWORD="" auth 2>&1)
AUTH_TEST_EXIT=$?
set -e
if [ "$AUTH_TEST_EXIT" -ne 0 ] && echo "$AUTH_TEST_OUT" | grep -q "SECURECLOUD_AUTH_DB_PASSWORD"; then
    log_pass "Auth service exited with code $AUTH_TEST_EXIT on missing DB password and logged validation error."
else
    log_fail "Auth service failed to fail-closed on missing DB password (Exit: $AUTH_TEST_EXIT, Output: '$AUTH_TEST_OUT')."
fi

# ==============================================================================
# Check 6: Positive Stack Lifecycle & Service Health
# ==============================================================================
log_info "Check 6: Starting full Compose stack and verifying service health..."
$COMPOSE_CMD up -d --remove-orphans >/dev/null

# Check persistence containers reach healthy state
for SERVICE in postgres scylladb clickhouse minio; do
    TRIES=0
    HEALTH=$($COMPOSE_CMD ps "$SERVICE" --format '{{.Health}}')
    while [ "$HEALTH" = "starting" ] && [ $TRIES -lt 25 ]; do
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

# Check application services are running
for SERVICE in gateway auth messaging files audit; do
    TRIES=0
    STATE=$($COMPOSE_CMD ps "$SERVICE" --format '{{.State}}')
    while [ "$STATE" != "running" ] && [ $TRIES -lt 10 ]; do
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

# ==============================================================================
# Check 7: SecureCloud PostgreSQL Host Port Check (localhost:5433)
# ==============================================================================
log_info "Check 7: Verifying SecureCloud PostgreSQL on host port 5433 (NOT 5432)..."
if check_sc_pg; then
    log_pass "SecureCloud PostgreSQL 17 is accessible on localhost:5433."
else
    log_fail "SecureCloud PostgreSQL 17 is not accessible on localhost:5433."
fi

# ==============================================================================
# Check 8: Host PostgreSQL Running State Non-Regression (localhost:5432)
# ==============================================================================
log_info "Check 8: Verifying host PostgreSQL 14 remains active on localhost:5432 while Compose runs..."
if check_host_pg; then
    log_pass "Host PostgreSQL 14 continues accepting connections on localhost:5432."
else
    log_fail "Host PostgreSQL 14 on localhost:5432 regression detected while Compose is running!"
fi

# ==============================================================================
# Check 9: Secret Leak Inspection in Microservice Log Streams
# ==============================================================================
log_info "Check 9: Inspecting microservice logs for secret leakage..."
SECRETS_LEAKED=0
for SECRET in "auth_dev_db_secret" "files_dev_db_secret" "audit_dev_db_secret" "files_dev_minio_secret" "postgres_dev_admin_secret" "minioadmin_dev_secret" "clickhouse_dev_admin_secret"; do
    for SERVICE in gateway auth messaging files audit; do
        if $COMPOSE_CMD logs "$SERVICE" 2>&1 | grep -F -q "$SECRET"; then
            echo -e "${COLOR_RED}[FAIL] Secret string leaked in $SERVICE logs!${COLOR_RESET}"
            SECRETS_LEAKED=1
        fi
    done
done
if [ "$SECRETS_LEAKED" -eq 0 ]; then
    log_pass "Zero secret strings found in microservice container logs."
else
    log_fail "Secret leakage detected in container logs!"
fi

# ==============================================================================
# Check 10: Host PostgreSQL Post-Shutdown Non-Regression
# ==============================================================================
log_info "Check 10: Stopping Compose stack and verifying host PostgreSQL 14 non-regression..."
$COMPOSE_CMD down >/dev/null 2>&1
if check_host_pg; then
    log_pass "Host PostgreSQL 14 remains active on localhost:5432 after Compose stack teardown."
else
    log_fail "Host PostgreSQL 14 regression detected after Compose shutdown!"
fi

log_pass "ALL 10 SERVICE CONFIGURATION VERIFICATION CHECKS PASSED SUCCESSFULLY!"
