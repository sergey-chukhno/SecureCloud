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

ADMIN_USER="${POSTGRES_USER:-postgres}"
ADMIN_DB="${POSTGRES_DB:-postgres}"

echo "[SecureCloud PostgreSQL Init] Bootstrapping databases and service accounts..."

# 1. Create databases idempotently
psql -v ON_ERROR_STOP=1 --username "$ADMIN_USER" --dbname "$ADMIN_DB" -tc "SELECT 1 FROM pg_database WHERE datname = '${AUTH_DB}'" | grep -q 1 || \
psql -v ON_ERROR_STOP=1 --username "$ADMIN_USER" --dbname "$ADMIN_DB" -c "CREATE DATABASE ${AUTH_DB};"

psql -v ON_ERROR_STOP=1 --username "$ADMIN_USER" --dbname "$ADMIN_DB" -tc "SELECT 1 FROM pg_database WHERE datname = '${FILES_DB}'" | grep -q 1 || \
psql -v ON_ERROR_STOP=1 --username "$ADMIN_USER" --dbname "$ADMIN_DB" -c "CREATE DATABASE ${FILES_DB};"

# 2. Create or update unprivileged service users and configure database grants idempotently
psql -v ON_ERROR_STOP=1 --username "$ADMIN_USER" --dbname "$ADMIN_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${AUTH_USER}') THEN
            CREATE USER ${AUTH_USER} WITH PASSWORD '${AUTH_PASS}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
        ELSE
            ALTER USER ${AUTH_USER} WITH PASSWORD '${AUTH_PASS}';
        END IF;

        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${FILES_USER}') THEN
            CREATE USER ${FILES_USER} WITH PASSWORD '${FILES_PASS}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
        ELSE
            ALTER USER ${FILES_USER} WITH PASSWORD '${FILES_PASS}';
        END IF;
    END
    \$\$;

    -- Grant full privileges on respective databases
    GRANT ALL PRIVILEGES ON DATABASE ${AUTH_DB} TO ${AUTH_USER};
    GRANT ALL PRIVILEGES ON DATABASE ${FILES_DB} TO ${FILES_USER};

    -- Enforce strict database-level CONNECT isolation
    REVOKE CONNECT ON DATABASE ${FILES_DB} FROM PUBLIC;
    REVOKE CONNECT ON DATABASE ${FILES_DB} FROM ${AUTH_USER};

    REVOKE CONNECT ON DATABASE ${AUTH_DB} FROM PUBLIC;
    REVOKE CONNECT ON DATABASE ${AUTH_DB} FROM ${FILES_USER};
EOSQL

# 3. Configure schema permissions for Auth database
psql -v ON_ERROR_STOP=1 --username "$ADMIN_USER" --dbname "${AUTH_DB}" <<-EOSQL
    GRANT ALL ON SCHEMA public TO ${AUTH_USER};
    ALTER SCHEMA public OWNER TO ${AUTH_USER};
EOSQL

# 4. Configure schema permissions for Files database
psql -v ON_ERROR_STOP=1 --username "$ADMIN_USER" --dbname "${FILES_DB}" <<-EOSQL
    GRANT ALL ON SCHEMA public TO ${FILES_USER};
    ALTER SCHEMA public OWNER TO ${FILES_USER};
EOSQL

echo "[SecureCloud PostgreSQL Init] Database initialization and isolation setup complete."

