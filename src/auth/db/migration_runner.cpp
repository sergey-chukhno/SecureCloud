#include "auth/db/migration_runner.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <openssl/sha.h>
#include <sstream>

namespace securecloud::auth::db {

namespace {

constexpr std::string_view kV001Sql = R"SQL(
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
)SQL";

constexpr std::string_view kV002Sql = R"SQL(
-- 1. users
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    credential_identifier VARCHAR(255) NOT NULL UNIQUE,
    password_verifier VARCHAR(255) NOT NULL,
    password_algorithm VARCHAR(64) NOT NULL,
    password_updated_at TIMESTAMPTZ NOT NULL,
    account_status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1
);

-- 2. devices
CREATE TABLE IF NOT EXISTS devices (
    device_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    device_status VARCHAR(32) NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(255),
    last_authenticated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- 3. device_public_keys
CREATE TABLE IF NOT EXISTS device_public_keys (
    key_id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    key_type VARCHAR(64) NOT NULL,
    public_key BYTEA NOT NULL,
    key_status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_key_id UUID REFERENCES device_public_keys(key_id)
);

-- 4. sessions
CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    session_status VARCHAR(32) NOT NULL,
    authentication_level VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ NOT NULL
);

-- 5. refresh_tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    refresh_token_id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    token_verifier VARCHAR(128) NOT NULL UNIQUE,
    token_status VARCHAR(32) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    replaced_by_token_id UUID REFERENCES refresh_tokens(refresh_token_id)
);

-- 6. mfa_configurations
CREATE TABLE IF NOT EXISTS mfa_configurations (
    mfa_configuration_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    factor_type VARCHAR(32) NOT NULL,
    encrypted_secret BYTEA NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    enabled_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1
);

-- 7. mfa_challenges
CREATE TABLE IF NOT EXISTS mfa_challenges (
    mfa_challenge_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    session_id UUID NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    challenge_purpose VARCHAR(32) NOT NULL,
    challenge_status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);
)SQL";

constexpr std::string_view kV003Sql = R"SQL(
CREATE INDEX IF NOT EXISTS idx_devices_user_status ON devices(user_id, device_status);
CREATE INDEX IF NOT EXISTS idx_device_keys_device_status ON device_public_keys(device_id, key_status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_status ON sessions(user_id, session_status);
CREATE INDEX IF NOT EXISTS idx_sessions_device_status ON sessions(device_id, session_status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_status ON refresh_tokens(session_id, token_status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_device_status ON refresh_tokens(device_id, token_status);
CREATE INDEX IF NOT EXISTS idx_mfa_config_user_status ON mfa_configurations(user_id, status);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_status ON mfa_challenges(user_id, challenge_status);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_session_status ON mfa_challenges(session_id, challenge_status);
)SQL";

class AdvisoryLockGuard {
  public:
    AdvisoryLockGuard(pqxx::connection& conn, int64_t lock_id) : conn_(conn), lock_id_(lock_id) {
        pqxx::nontransaction tx(conn_);
        tx.exec("SELECT pg_advisory_lock(" + std::to_string(lock_id_) + ");");
        locked_ = true;
    }

    ~AdvisoryLockGuard() { unlock(); }

    void unlock() {
        if (locked_) {
            try {
                pqxx::nontransaction tx(conn_);
                tx.exec("SELECT pg_advisory_unlock(" + std::to_string(lock_id_) + ");");
            } catch (...) {
            }
            locked_ = false;
        }
    }

  private:
    pqxx::connection& conn_;
    int64_t lock_id_;
    bool locked_{false};
};

} // namespace

MigrationRunner::MigrationRunner(PostgresConnectionPool& pool) : pool_(pool) {}

std::string MigrationRunner::normalize_sql(std::string_view sql_content) {
    std::string result;
    result.reserve(sql_content.size());
    for (std::size_t i = 0; i < sql_content.size(); ++i) {
        if (sql_content[i] == '\r') {
            if (i + 1 < sql_content.size() && sql_content[i + 1] == '\n') {
                continue;
            }
            result.push_back('\n');
        } else {
            result.push_back(sql_content[i]);
        }
    }

    // Trim leading whitespace
    std::size_t start = 0;
    while (start < result.size() && (result[start] == ' ' || result[start] == '\t' || result[start] == '\n')) {
        ++start;
    }

    // Trim trailing whitespace
    std::size_t end = result.size();
    while (end > start && (result[end - 1] == ' ' || result[end - 1] == '\t' || result[end - 1] == '\n')) {
        --end;
    }

    return result.substr(start, end - start);
}

std::string MigrationRunner::calculate_checksum(std::string_view sql_content) {
    std::string normalized = normalize_sql(sql_content);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(normalized.data()), normalized.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::vector<MigrationScript> MigrationRunner::get_standard_migrations() {
    return {
        {1, "create_schema_migrations", std::string(kV001Sql), calculate_checksum(kV001Sql)},
        {2, "create_auth_tables", std::string(kV002Sql), calculate_checksum(kV002Sql)},
        {3, "create_auth_indexes", std::string(kV003Sql), calculate_checksum(kV003Sql)},
    };
}

MigrationResult MigrationRunner::run_migrations() {
    return run_migrations(get_standard_migrations());
}

MigrationResult MigrationRunner::run_migrations(const std::vector<MigrationScript>& scripts) {
    // Sort scripts by version
    std::vector<MigrationScript> sorted_scripts = scripts;
    std::sort(sorted_scripts.begin(), sorted_scripts.end(),
              [](const MigrationScript& a, const MigrationScript& b) { return a.version < b.version; });

    auto conn_lease = pool_.acquire();
    pqxx::connection& conn = *conn_lease;

    // Acquire PostgreSQL advisory lock to serialize concurrent migration runners
    AdvisoryLockGuard lock(conn, k_auth_migration_advisory_lock);

    // 1. Ensure schema_migrations table exists
    {
        pqxx::nontransaction check_tx(conn);
        const auto exists_res = check_tx.exec(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = "
            "'schema_migrations');");
        bool exists = exists_res[0][0].as<bool>();
        if (!exists) {
            pqxx::work init_tx(conn);
            init_tx.exec(kV001Sql);
            init_tx.commit();
        }
    }

    // 2. Query applied migrations and their recorded checksums
    std::map<int, std::string> applied_checksums;
    int max_applied_version = 0;
    {
        pqxx::nontransaction query_tx(conn);
        const auto rows = query_tx.exec("SELECT version, checksum FROM schema_migrations ORDER BY version ASC;");
        for (const auto& row : rows) {
            int version = row[0].as<int>();
            std::string checksum = row[1].as<std::string>();
            applied_checksums[version] = checksum;
            if (version > max_applied_version) {
                max_applied_version = version;
            }
        }
    }

    // 3. Verify checksums of already applied scripts
    for (const auto& script : sorted_scripts) {
        auto it = applied_checksums.find(script.version);
        if (it != applied_checksums.end()) {
            std::string expected_checksum =
                script.checksum.empty() ? calculate_checksum(script.sql_content) : script.checksum;
            if (it->second != expected_checksum) {
                throw MigrationChecksumMismatchException(script.version, expected_checksum, it->second);
            }
        }
    }

    MigrationResult result;
    result.current_version = max_applied_version;

    // 4. Execute pending migrations in strictly ascending version order
    for (const auto& script : sorted_scripts) {
        if (script.version <= max_applied_version) {
            continue;
        }

        std::string checksum = script.checksum.empty() ? calculate_checksum(script.sql_content) : script.checksum;

        try {
            pqxx::work tx(conn);
            tx.exec(script.sql_content);
            tx.exec("INSERT INTO schema_migrations (version, description, checksum, installed_at) VALUES ($1, $2, $3, "
                    "NOW());",
                    pqxx::params{script.version, script.description, checksum});
            tx.commit();

            ++result.migrations_applied;
            result.current_version = script.version;
            result.applied_scripts.push_back("V" + std::to_string(script.version) + "__" + script.description);
        } catch (const std::exception& ex) {
            throw MigrationExecutionException(script.version, script.description, ex.what());
        }
    }

    return result;
}

int MigrationRunner::get_current_schema_version() {
    auto conn_lease = pool_.acquire();
    pqxx::connection& conn = *conn_lease;

    pqxx::nontransaction tx(conn);
    const auto exists_res =
        tx.exec("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = "
                "'schema_migrations');");
    if (!exists_res[0][0].as<bool>()) {
        return 0;
    }

    const auto version_res = tx.exec("SELECT COALESCE(MAX(version), 0) FROM schema_migrations;");
    return version_res[0][0].as<int>();
}

} // namespace securecloud::auth::db
