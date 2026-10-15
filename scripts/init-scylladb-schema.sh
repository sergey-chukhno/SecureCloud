#!/usr/bin/env bash
set -euo pipefail

# SecureCloud ScyllaDB Messaging Schema Initializer (MSG-004-T01)
# Idempotently initializes the securecloud_messaging keyspace and all 11 authoritative tables.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

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

MIGRATIONS_DIR="${ROOT_DIR}/src/messaging/db/migrations"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"

log_info "Initializing ScyllaDB Messaging Schema..."

# Check whether Docker compose container is running or local cqlsh is available
USE_COMPOSE=false
if command -v docker >/dev/null 2>&1 && docker compose -f "${COMPOSE_FILE}" ps scylladb 2>/dev/null | grep -q "scylladb"; then
    USE_COMPOSE=true
    log_info "Detected running ScyllaDB Docker Compose container."
elif command -v cqlsh >/dev/null 2>&1; then
    USE_COMPOSE=false
    log_info "Using local cqlsh utility."
else
    log_info "Neither Docker Compose scylladb container nor host cqlsh detected."
    log_info "If using Docker, ensure 'docker compose -f ${COMPOSE_FILE} up -d scylladb' is running."
fi

run_cql_file() {
    local cql_file="$1"
    local file_name
    file_name="$(basename "$cql_file")"
    log_info "Applying migration: ${file_name}..."

    if [ "$USE_COMPOSE" = true ]; then
        docker compose -f "${COMPOSE_FILE}" exec -T scylladb cqlsh -f - < "${cql_file}"
    else
        cqlsh "${SCYLLA_HOST:-127.0.0.1}" "${SCYLLA_PORT:-9042}" -f "${cql_file}"
    fi
    log_pass "Applied ${file_name} successfully."
}

# Apply migrations sequentially
run_cql_file "${MIGRATIONS_DIR}/V001__create_messaging_keyspace.cql"
run_cql_file "${MIGRATIONS_DIR}/V002__create_messaging_tables.cql"
run_cql_file "${MIGRATIONS_DIR}/V003__create_schema_version_tracking.cql"

log_pass "ScyllaDB Messaging Schema successfully initialized and up to date."
