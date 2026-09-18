#!/bin/sh
set -e

# Shell bootstrap initialization script for PostgreSQL 17
# Enforces unprivileged service users and strict database CONNECT privilege isolation.

AUTH_DB="${AUTH_DB_NAME:-securecloud_auth}"
AUTH_USER="${AUTH_DB_USER:-auth_user}"
AUTH_PASS="${AUTH_DB_PASSWORD:-auth_dev_db_secret}"

FILES_DB="${FILES_DB_NAME:-securecloud_files}"
FILES_USER="${FILES_DB_USER:-files_user}"
FILES_PASS="${FILES_DB_PASSWORD:-files_dev_db_secret}"

echo "[SecureCloud PostgreSQL Init] Bootstrapping databases and service accounts..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create isolated database for Auth service
    CREATE DATABASE ${AUTH_DB};

    -- Create isolated database for Files service
    CREATE DATABASE ${FILES_DB};

    -- Create unprivileged Auth service account
    CREATE USER ${AUTH_USER} WITH PASSWORD '${AUTH_PASS}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

    -- Create unprivileged Files service account
    CREATE USER ${FILES_USER} WITH PASSWORD '${FILES_PASS}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

    -- Grant full privileges on respective databases
    GRANT ALL PRIVILEGES ON DATABASE ${AUTH_DB} TO ${AUTH_USER};
    GRANT ALL PRIVILEGES ON DATABASE ${FILES_DB} TO ${FILES_USER};

    -- Enforce strict database-level CONNECT isolation
    REVOKE CONNECT ON DATABASE ${FILES_DB} FROM PUBLIC;
    REVOKE CONNECT ON DATABASE ${FILES_DB} FROM ${AUTH_USER};

    REVOKE CONNECT ON DATABASE ${AUTH_DB} FROM PUBLIC;
    REVOKE CONNECT ON DATABASE ${AUTH_DB} FROM ${FILES_USER};
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "${AUTH_DB}" <<-EOSQL
    GRANT ALL ON SCHEMA public TO ${AUTH_USER};
    ALTER SCHEMA public OWNER TO ${AUTH_USER};
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "${FILES_DB}" <<-EOSQL
    GRANT ALL ON SCHEMA public TO ${FILES_USER};
    ALTER SCHEMA public OWNER TO ${FILES_USER};
EOSQL

echo "[SecureCloud PostgreSQL Init] Database initialization and isolation setup complete."
