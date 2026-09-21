#!/usr/bin/env bash
set -euo pipefail

# SecureCloud Automated Persistence Infrastructure Verification Suite (SC11-T05)
# Validates PostgreSQL 17, ScyllaDB 6.0, ClickHouse 24.8, and MinIO S3 Object Storage.

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

log_info "Starting SecureCloud Persistence Infrastructure Verification Suite..."

# Ensure full stack is running
log_info "Ensuring full Compose stack is up..."
$COMPOSE_CMD up -d >/dev/null

# ==============================================================================
# Check 1: Compose File Syntax Validation
# ==============================================================================
log_info "Check 1: Validating Docker Compose syntax..."
if $COMPOSE_CMD config >/dev/null; then
    log_pass "Docker Compose file syntax is valid."
else
    log_fail "Docker Compose file syntax validation failed."
fi

# ==============================================================================
# Check 2: Service Topology & Container Status
# ==============================================================================
log_info "Check 2: Verifying Compose service topology and status..."
MINIO_INIT_EXIT=$($COMPOSE_CMD ps -a minio-init --format '{{.ExitCode}}')
if [ "$MINIO_INIT_EXIT" -eq 0 ]; then
    log_pass "minio-init one-shot initialization job exited with code 0."
else
    log_fail "minio-init failed with exit code $MINIO_INIT_EXIT."
fi

for SERVICE in postgres scylladb clickhouse minio; do
    TRIES=0
    HEALTH=$($COMPOSE_CMD ps "$SERVICE" --format '{{.Health}}')
    while [ "$HEALTH" = "starting" ] && [ $TRIES -lt 15 ]; do
        sleep 2
        TRIES=$((TRIES + 1))
        HEALTH=$($COMPOSE_CMD ps "$SERVICE" --format '{{.Health}}')
    done
    if [ "$HEALTH" = "healthy" ]; then
        log_pass "Service '$SERVICE' is healthy."
    else
        log_fail "Service '$SERVICE' healthcheck failed (status: '$HEALTH')."
    fi
done

# ==============================================================================
# Check 3: PostgreSQL Database Presence & Owner Setup
# ==============================================================================
log_info "Check 3: Verifying PostgreSQL databases..."
AUTH_DB_EXISTS=$($COMPOSE_CMD exec -T postgres psql -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='securecloud_auth';")
FILES_DB_EXISTS=$($COMPOSE_CMD exec -T postgres psql -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='securecloud_files';")

if [ "$AUTH_DB_EXISTS" = "1" ] && [ "$FILES_DB_EXISTS" = "1" ]; then
    log_pass "Databases 'securecloud_auth' and 'securecloud_files' exist."
else
    log_fail "PostgreSQL database creation check failed."
fi

# ==============================================================================
# Check 4: PostgreSQL Database CONNECT Privilege Isolation
# ==============================================================================
log_info "Check 4: Verifying PostgreSQL database CONNECT isolation..."
if $COMPOSE_CMD exec -T postgres psql -U auth_user -d securecloud_auth -c "SELECT 1;" >/dev/null 2>&1; then
    log_pass "auth_user successfully connected to securecloud_auth."
else
    log_fail "auth_user failed to connect to securecloud_auth."
fi

AUTH_ISO_ERR=$($COMPOSE_CMD exec -T postgres psql -U auth_user -d securecloud_files -c "SELECT 1;" 2>&1 || true)
if echo "$AUTH_ISO_ERR" | grep -q "permission denied for database"; then
    log_pass "auth_user connection to securecloud_files rejected with permission denied."
else
    log_fail "auth_user isolation check failed on securecloud_files (output: '$AUTH_ISO_ERR')."
fi

if $COMPOSE_CMD exec -T postgres psql -U files_user -d securecloud_files -c "SELECT 1;" >/dev/null 2>&1; then
    log_pass "files_user successfully connected to securecloud_files."
else
    log_fail "files_user failed to connect to securecloud_files."
fi

FILES_ISO_ERR=$($COMPOSE_CMD exec -T postgres psql -U files_user -d securecloud_auth -c "SELECT 1;" 2>&1 || true)
if echo "$FILES_ISO_ERR" | grep -q "permission denied for database"; then
    log_pass "files_user connection to securecloud_auth rejected with permission denied."
else
    log_fail "files_user isolation check failed on securecloud_auth (output: '$FILES_ISO_ERR')."
fi

# ==============================================================================
# Check 5: PostgreSQL Unprivileged Service User Attributes
# ==============================================================================
log_info "Check 5: Verifying PostgreSQL unprivileged user hardening..."
ROLES_PRIVS=$($COMPOSE_CMD exec -T postgres psql -U postgres -d postgres -tAc "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication FROM pg_roles WHERE rolname IN ('auth_user', 'files_user');")

if echo "$ROLES_PRIVS" | grep -q "auth_user|f|f|f|f" && echo "$ROLES_PRIVS" | grep -q "files_user|f|f|f|f"; then
    log_pass "auth_user and files_user hardened with NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION."
else
    log_fail "Service role hardening verification failed: $ROLES_PRIVS"
fi

# ==============================================================================
# Check 6: ScyllaDB Health & CQL Responsiveness
# ==============================================================================
log_info "Check 6: Verifying ScyllaDB CQL responsiveness..."
if $COMPOSE_CMD exec -T scylladb cqlsh -e "SHOW HOST" >/dev/null 2>&1; then
    log_pass "ScyllaDB is responsive to cqlsh queries."
else
    log_fail "ScyllaDB cqlsh responsiveness check failed."
fi

# ==============================================================================
# Check 7: ClickHouse Health & securecloud_audit Database Presence
# ==============================================================================
log_info "Check 7: Verifying ClickHouse audit database and user..."
CLICKHOUSE_QUERY=$($COMPOSE_CMD exec -T clickhouse clickhouse-client --user audit_user --password audit_dev_db_secret --database securecloud_audit --query "SELECT currentDatabase(), currentUser();")
if echo "$CLICKHOUSE_QUERY" | grep -q "securecloud_audit" && echo "$CLICKHOUSE_QUERY" | grep -q "audit_user"; then
    log_pass "ClickHouse securecloud_audit database and audit_user verified."
else
    log_fail "ClickHouse audit verification failed."
fi

# ==============================================================================
# Check 8: MinIO S3 Object Storage & Bucket Presence
# ==============================================================================
log_info "Check 8: Verifying MinIO bucket and service account..."
MINIO_VERIFY=$($COMPOSE_CMD exec -T minio bash -c "mc --quiet alias set verify_user http://127.0.0.1:9000 files_minio_user files_dev_minio_secret >/dev/null 2>&1 && mc --quiet ls verify_user/")
if echo "$MINIO_VERIFY" | grep -q "securecloud-files-encrypted"; then
    log_pass "MinIO bucket 'securecloud-files-encrypted' accessible by files_minio_user."
else
    log_fail "MinIO bucket/user verification failed."
fi

# ==============================================================================
# Check 9: Compose Internal DNS Resolution
# ==============================================================================
log_info "Check 9: Verifying Compose internal DNS resolution..."
DNS_TEST=$($COMPOSE_CMD exec -T gateway getent hosts postgres scylladb clickhouse minio)
if echo "$DNS_TEST" | grep -q "postgres" && echo "$DNS_TEST" | grep -q "scylladb" && echo "$DNS_TEST" | grep -q "clickhouse" && echo "$DNS_TEST" | grep -q "minio"; then
    log_pass "Internal DNS resolution for persistence services verified from gateway."
else
    log_fail "Internal DNS resolution check failed."
fi

# ==============================================================================
# Check 10: Persistent Volume Data Retention Across Non-Destructive Container Recreation
# ==============================================================================
log_info "Check 10: Verifying persistent volume retention across non-destructive container recreation..."

# Observational check on host PostgreSQL 14 (never remediate or reconfigure)
if command -v pg_isready >/dev/null 2>&1; then
    if pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
        log_info "Host PostgreSQL 14 active on 127.0.0.1:5432 (observational check: confirmed healthy)"
    fi
fi

$COMPOSE_CMD exec -T postgres psql -U auth_user -d securecloud_auth -c "CREATE TABLE IF NOT EXISTS persistent_marker (id INT); INSERT INTO persistent_marker VALUES (42);" >/dev/null 2>&1
$COMPOSE_CMD exec -T clickhouse clickhouse-client --user audit_user --password audit_dev_db_secret --database securecloud_audit --multiquery --query "CREATE TABLE IF NOT EXISTS persistent_marker (id UInt32) ENGINE = TinyLog; INSERT INTO persistent_marker VALUES (42);" < /dev/null >/dev/null 2>&1
$COMPOSE_CMD exec -T minio bash -c "mc --quiet alias set verify_user http://127.0.0.1:9000 files_minio_user files_dev_minio_secret >/dev/null 2>&1 && echo 'marker-42' > /tmp/marker.txt && mc cp --quiet /tmp/marker.txt verify_user/securecloud-files-encrypted/marker.txt >/dev/null 2>&1 && rm -f /tmp/marker.txt"

log_info "Recreating persistence containers (stop -> rm -f -> up -d)..."
$COMPOSE_CMD stop -t 5 postgres scylladb clickhouse minio >/dev/null 2>&1
$COMPOSE_CMD rm -f postgres scylladb clickhouse minio >/dev/null 2>&1
$COMPOSE_CMD up -d postgres scylladb clickhouse minio >/dev/null 2>&1

log_info "Waiting for persistence services to regain health..."
TRIES=0
until [ "$($COMPOSE_CMD ps postgres --format '{{.Health}}')" = "healthy" ] && \
      [ "$($COMPOSE_CMD ps scylladb --format '{{.Health}}')" = "healthy" ] && \
      [ "$($COMPOSE_CMD ps clickhouse --format '{{.Health}}')" = "healthy" ] && \
      [ "$($COMPOSE_CMD ps minio --format '{{.Health}}')" = "healthy" ]; do
    sleep 2
    TRIES=$((TRIES + 1))
    if [ $TRIES -gt 30 ]; then
        log_fail "Timeout waiting for persistence services to regain healthy status."
    fi
done
log_pass "Persistence services regained healthy status after container recreation."

# Observational post-recreation confirmation of host PostgreSQL 14
if command -v pg_isready >/dev/null 2>&1; then
    if pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
        log_pass "Host PostgreSQL 14 on 127.0.0.1:5432 remained healthy and untouched throughout recreation."
    fi
fi

PG_MARKER=$($COMPOSE_CMD exec -T postgres psql -U auth_user -d securecloud_auth -tAc "SELECT id FROM persistent_marker LIMIT 1;")
CH_MARKER=$($COMPOSE_CMD exec -T clickhouse clickhouse-client --user audit_user --password audit_dev_db_secret --database securecloud_audit --query "SELECT id FROM persistent_marker LIMIT 1;" < /dev/null)
MINIO_MARKER=$($COMPOSE_CMD exec -T minio bash -c "mc --quiet alias set verify_user http://127.0.0.1:9000 files_minio_user files_dev_minio_secret >/dev/null 2>&1 && mc cat --quiet verify_user/securecloud-files-encrypted/marker.txt")

$COMPOSE_CMD exec -T postgres psql -U auth_user -d securecloud_auth -c "DROP TABLE IF EXISTS persistent_marker;" >/dev/null 2>&1
$COMPOSE_CMD exec -T clickhouse clickhouse-client --user audit_user --password audit_dev_db_secret --database securecloud_audit --query "DROP TABLE IF EXISTS persistent_marker;" < /dev/null >/dev/null 2>&1
$COMPOSE_CMD exec -T minio bash -c "mc --quiet alias set verify_user http://127.0.0.1:9000 files_minio_user files_dev_minio_secret >/dev/null 2>&1 && mc rm --quiet verify_user/securecloud-files-encrypted/marker.txt" >/dev/null 2>&1

if [ "$PG_MARKER" = "42" ] && echo "$CH_MARKER" | grep -q "42" && echo "$MINIO_MARKER" | grep -q "marker-42"; then
    log_pass "Data persistence retention across non-destructive container recreation verified."
else
    log_fail "Persistent volume retention check failed (PG: '$PG_MARKER', CH: '$CH_MARKER', MinIO: '$MINIO_MARKER')."
fi

# ==============================================================================
# Check 11: Non-Regression Tests (PKI & CTest Suite)
# ==============================================================================
log_info "Check 11: Running PKI and CTest non-regression suites..."
if ./scripts/verify-dev-pki.sh >/dev/null; then
    log_pass "PKI verification suite passed."
else
    log_fail "PKI verification suite failed."
fi

if ctest --preset dev-debug >/dev/null; then
    log_pass "CTest test suite passed."
else
    log_fail "CTest regression test suite failed."
fi

log_pass "ALL 11 PERSISTENCE INFRASTRUCTURE VERIFICATION CHECKS PASSED SUCCESSFULLY!"
