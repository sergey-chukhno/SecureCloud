#!/usr/bin/env bash
set -euo pipefail

# SecureCloud ScyllaDB Messaging Schema Initializer (MSG-004-T01 / CLIENT-015-T06)
# Idempotently initializes securecloud_messaging keyspace and V001..V006 schema migrations.

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

MIGRATIONS_DIR="${MIGRATIONS_DIR:-${ROOT_DIR}/src/messaging/db/migrations}"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"

log_info "Initializing ScyllaDB Messaging Schema from ${MIGRATIONS_DIR}..."

USE_COMPOSE=false
if [ -z "${SCYLLA_HOST:-}" ] && command -v docker >/dev/null 2>&1 && docker compose -f "${COMPOSE_FILE}" ps scylladb 2>/dev/null | grep -q "scylladb"; then
    USE_COMPOSE=true
    log_info "Detected running ScyllaDB Docker Compose container."
elif command -v cqlsh >/dev/null 2>&1; then
    USE_COMPOSE=false
    log_info "Using cqlsh target ${SCYLLA_HOST:-127.0.0.1}:${SCYLLA_PORT:-9042}."
else
    log_fail "Neither Docker Compose scylladb container nor cqlsh is available."
fi

run_cql_query() {
    local cql="$1"
    if [ "$USE_COMPOSE" = true ]; then
        docker compose -f "${COMPOSE_FILE}" exec -T scylladb cqlsh -e "${cql}"
    else
        cqlsh "${SCYLLA_HOST:-127.0.0.1}" "${SCYLLA_PORT:-9042}" -e "${cql}"
    fi
}

run_cql_file() {
    local cql_file="$1"
    local file_name
    file_name="$(basename "$cql_file")"
    log_info "Applying migration: ${file_name}..."

    if [ "$USE_COMPOSE" = true ]; then
        docker compose -f "${COMPOSE_FILE}" exec -T scylladb cqlsh < "${cql_file}"
    else
        cqlsh "${SCYLLA_HOST:-127.0.0.1}" "${SCYLLA_PORT:-9042}" -f "${cql_file}"
    fi
    log_pass "Applied ${file_name} successfully."
}

run_cql_file "${MIGRATIONS_DIR}/V001__create_messaging_keyspace.cql"
run_cql_file "${MIGRATIONS_DIR}/V002__create_messaging_tables.cql"
run_cql_file "${MIGRATIONS_DIR}/V003__create_schema_version_tracking.cql"

# V004 uses ALTER TABLE ... ADD without IF NOT EXISTS; guard via system_schema.columns.
if run_cql_query "SELECT column_name FROM system_schema.columns WHERE keyspace_name = 'securecloud_messaging' AND table_name = 'pending_deliveries_by_device' AND column_name = 'ciphertext_blob';" | grep -q "ciphertext_blob"; then
    log_info "V004__add_per_device_envelope_columns.cql already applied; skipping."
else
    run_cql_file "${MIGRATIONS_DIR}/V004__add_per_device_envelope_columns.cql"
fi

run_cql_file "${MIGRATIONS_DIR}/V005__add_message_id_secondary_indexes.cql"
run_cql_file "${MIGRATIONS_DIR}/V006__create_messaging_audit_outbox.cql"

log_pass "ScyllaDB Messaging Schema (V001..V006) successfully initialized and up to date."
