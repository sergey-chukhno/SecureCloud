#include "files/db/migration_runner.hpp"

#include "files/db/pqxx_compat.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace securecloud::files::db {

namespace {

constexpr std::string_view k_v001_sql = R"SQL(
CREATE TABLE IF NOT EXISTS files (
    file_id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL,
    owner_device_id UUID NOT NULL,
    conversation_id UUID NULL,
    encrypted_size BIGINT NOT NULL CHECK (encrypted_size >= 0),
    content_type VARCHAR(255) NULL,
    encryption_algorithm VARCHAR(64) NOT NULL DEFAULT 'XChaCha20-Poly1305',
    status VARCHAR(32) NOT NULL DEFAULT 'CREATED'
        CHECK (status IN ('CREATED', 'UPLOADING', 'FINALIZING', 'AVAILABLE', 'EXPIRED', 'DELETED', 'FAILED')),
    retention_until TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_versions (
    version_id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    version_number INT NOT NULL DEFAULT 1 CHECK (version_number > 0),
    encrypted_size BIGINT NOT NULL CHECK (encrypted_size >= 0),
    minio_object_key VARCHAR(512) NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT uq_file_version UNIQUE(file_id, version_number)
);

CREATE TABLE IF NOT EXISTS encrypted_file_metadata (
    file_id UUID PRIMARY KEY REFERENCES files(file_id) ON DELETE CASCADE,
    encrypted_filename BYTEA NOT NULL,
    encrypted_mime_type BYTEA NULL,
    metadata_nonce BYTEA NOT NULL,
    metadata_tag BYTEA NOT NULL,
    client_encryption_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_transfers (
    transfer_id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    transfer_type VARCHAR(16) NOT NULL CHECK (transfer_type IN ('UPLOAD', 'DOWNLOAD')),
    initiator_user_id UUID NOT NULL,
    initiator_device_id UUID NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'CREATED'
        CHECK (status IN ('CREATED', 'TRANSFERRING', 'FINALIZING', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED')),
    total_chunks INT NOT NULL CHECK (total_chunks >= 0),
    accepted_chunks INT NOT NULL DEFAULT 0 CHECK (accepted_chunks >= 0),
    total_bytes BIGINT NOT NULL CHECK (total_bytes >= 0),
    transferred_bytes BIGINT NOT NULL DEFAULT 0 CHECK (transferred_bytes >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS file_chunks (
    chunk_id UUID PRIMARY KEY,
    transfer_id UUID NOT NULL REFERENCES file_transfers(transfer_id) ON DELETE CASCADE,
    chunk_index INT NOT NULL CHECK (chunk_index >= 0),
    byte_offset BIGINT NOT NULL CHECK (byte_offset >= 0),
    chunk_size INT NOT NULL CHECK (chunk_size > 0),
    chunk_hash_sha256 VARCHAR(64) NOT NULL,
    minio_chunk_key VARCHAR(512) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'RECEIVED' CHECK (status IN ('RECEIVED', 'COMMITTED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_transfer_chunk UNIQUE(transfer_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS file_access (
    access_id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    grantee_user_id UUID NOT NULL,
    grantee_device_id UUID NULL,
    permission VARCHAR(32) NOT NULL DEFAULT 'READ' CHECK (permission IN ('READ', 'WRITE', 'ADMIN')),
    granted_by UUID NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ NULL,
    CONSTRAINT uq_file_grantee UNIQUE(file_id, grantee_user_id)
);

CREATE TABLE IF NOT EXISTS files_outbox (
    event_id UUID PRIMARY KEY,
    aggregate_type VARCHAR(32) NOT NULL DEFAULT 'FILE',
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload_json JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED')),
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_user_id, status);
CREATE INDEX IF NOT EXISTS idx_files_conversation ON files(conversation_id) WHERE conversation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_files_retention ON files(retention_until) WHERE status != 'DELETED';
CREATE INDEX IF NOT EXISTS idx_file_transfers_file ON file_transfers(file_id, status);
CREATE INDEX IF NOT EXISTS idx_file_chunks_transfer ON file_chunks(transfer_id, chunk_index);
CREATE INDEX IF NOT EXISTS idx_files_outbox_pending ON files_outbox(created_at) WHERE status = 'PENDING';
)SQL";

constexpr std::string_view k_v002_sql = R"SQL(
ALTER TABLE files_outbox
    ALTER COLUMN aggregate_id DROP NOT NULL;

ALTER TABLE files_outbox
    ADD COLUMN IF NOT EXISTS severity VARCHAR(16) NOT NULL DEFAULT 'INFO';

ALTER TABLE files_outbox
    DROP CONSTRAINT IF EXISTS files_outbox_severity_check;

ALTER TABLE files_outbox
    ADD CONSTRAINT files_outbox_severity_check
    CHECK (severity IN ('INFO', 'WARNING', 'SECURITY', 'CRITICAL'));

ALTER TABLE files_outbox
    DROP CONSTRAINT IF EXISTS files_outbox_status_check;

ALTER TABLE files_outbox
    ADD CONSTRAINT files_outbox_status_check
    CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED', 'QUARANTINED'));

ALTER TABLE files_outbox
    DROP CONSTRAINT IF EXISTS files_outbox_retry_count_check;

ALTER TABLE files_outbox
    ADD CONSTRAINT files_outbox_retry_count_check
    CHECK (retry_count >= 0);

ALTER TABLE files_outbox
    ADD COLUMN IF NOT EXISTS last_error TEXT NULL;

ALTER TABLE files_outbox
    ADD COLUMN IF NOT EXISTS leased_until TIMESTAMPTZ NULL;

DROP INDEX IF EXISTS idx_files_outbox_pending;

CREATE INDEX IF NOT EXISTS idx_files_outbox_pending
    ON files_outbox (created_at ASC, leased_until)
    WHERE status = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_files_outbox_cleanup
    ON files_outbox (processed_at ASC)
    WHERE status = 'PUBLISHED' AND processed_at IS NOT NULL;
)SQL";

std::string trim_string(std::string_view s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) {
        return "";
    }
    auto end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(start, end - start + 1));
}

#if defined(SECURECLOUD_FILES_USE_REAL_PQXX) && __has_include(<pqxx/pqxx>)
template <typename S> std::string extract_secret_value(const S& secret) {
    if constexpr (requires { secret.reveal(); }) {
        return std::string(secret.reveal());
    } else if constexpr (requires { secret.unmask(); }) {
        return std::string(secret.unmask());
    } else if constexpr (requires { secret.value(); }) {
        return std::string(secret.value());
    } else if constexpr (requires { secret.get(); }) {
        return std::string(secret.get());
    } else {
        return {};
    }
}

std::string build_pg_conninfo(const ConnectionPoolConfig& cfg) {
    std::ostringstream oss;
    oss << "host=" << cfg.host << " port=" << cfg.port << " dbname=" << cfg.db_name << " user=" << cfg.db_user;
    const std::string pwd = extract_secret_value(cfg.db_password);
    if (!pwd.empty()) {
        std::string escaped;
        escaped.reserve(pwd.size());
        for (char c : pwd) {
            if (c == '\'' || c == '\\') {
                escaped.push_back('\\');
            }
            escaped.push_back(c);
        }
        oss << " password='" << escaped << "'";
    }
    const auto connect_sec = std::max<int64_t>(1, cfg.connect_timeout.count() / 1000);
    oss << " connect_timeout=" << connect_sec;
    return oss.str();
}
#endif

} // namespace

MigrationRunner::MigrationRunner(std::shared_ptr<FilesDbConnectionPool> pool) : pool_(std::move(pool)) {}

std::string_view MigrationRunner::get_v001_schema_sql() noexcept {
    return k_v001_sql;
}

std::string_view MigrationRunner::get_v002_schema_sql() noexcept {
    return k_v002_sql;
}

std::vector<std::string> MigrationRunner::split_statements(std::string_view sql) {
    std::vector<std::string> statements;
    std::istringstream stream{std::string(sql)};
    std::string line;
    std::string current_stmt;
    bool in_dollar_quote = false;

    while (std::getline(stream, line)) {
        if (!in_dollar_quote) {
            auto comment_pos = line.find("--");
            if (comment_pos != std::string::npos) {
                line = line.substr(0, comment_pos);
            }
        }

        std::string trimmed_line = trim_string(line);
        if (trimmed_line.empty()) {
            continue;
        }

        // Toggle dollar-quoting state on odd occurrences of "$$"
        size_t pos = 0;
        while ((pos = trimmed_line.find("$$", pos)) != std::string::npos) {
            in_dollar_quote = !in_dollar_quote;
            pos += 2;
        }

        if (!current_stmt.empty()) {
            current_stmt += " ";
        }
        current_stmt += trimmed_line;

        if (!in_dollar_quote && trimmed_line.ends_with(';')) {
            std::string final_stmt = trim_string(current_stmt);
            if (!final_stmt.empty() && final_stmt != ";") {
                statements.push_back(std::move(final_stmt));
            }
            current_stmt.clear();
        }
    }

    std::string remaining = trim_string(current_stmt);
    if (!remaining.empty() && remaining != ";") {
        statements.push_back(std::move(remaining));
    }

    return statements;
}

bool MigrationRunner::validate_schema_ddl_syntax(std::string_view sql, std::vector<std::string>& out_missing_elements) {
    out_missing_elements.clear();

    const std::vector<std::string> required_tables = {"files",          "file_versions", "encrypted_file_metadata",
                                                      "file_transfers", "file_chunks",   "file_access",
                                                      "files_outbox"};

    const std::vector<std::string> required_indexes = {"idx_files_owner",          "idx_files_conversation",
                                                       "idx_files_retention",      "idx_file_transfers_file",
                                                       "idx_file_chunks_transfer", "idx_files_outbox_pending"};

    const std::vector<std::string> required_constraints = {"uq_file_version", "uq_transfer_chunk", "uq_file_grantee",
                                                           "ON DELETE CASCADE"};

    for (const auto& table : required_tables) {
        std::string needle = "CREATE TABLE IF NOT EXISTS " + table;
        if (sql.find(needle) == std::string_view::npos) {
            out_missing_elements.push_back("Missing table definition: " + table);
        }
    }

    for (const auto& idx : required_indexes) {
        if (sql.find(idx) == std::string_view::npos) {
            out_missing_elements.push_back("Missing index: " + idx);
        }
    }

    for (const auto& constraint : required_constraints) {
        if (sql.find(constraint) == std::string_view::npos) {
            out_missing_elements.push_back("Missing constraint: " + constraint);
        }
    }

    return out_missing_elements.empty();
}

bool MigrationRunner::validate_v002_schema_ddl_syntax(std::string_view sql,
                                                      std::vector<std::string>& out_missing_elements) {
    out_missing_elements.clear();

    const std::vector<std::string> required_clauses = {
        "ALTER TABLE files_outbox",
        "DROP NOT NULL",
        "severity",
        "QUARANTINED",
        "last_error",
        "leased_until",
        "idx_files_outbox_pending",
        "idx_files_outbox_cleanup",
    };

    for (const auto& clause : required_clauses) {
        if (sql.find(clause) == std::string_view::npos) {
            out_missing_elements.push_back("Missing V002 DDL element: " + clause);
        }
    }

    return out_missing_elements.empty();
}

MigrationResult MigrationRunner::run_migrations() {
    MigrationResult result;

    if (std::find(applied_versions_.begin(), applied_versions_.end(), "V001") == applied_versions_.end()) {
        if (!apply_migration("V001", "create_files_schema", get_v001_schema_sql())) {
            result.success = false;
            result.error_message = "Failed to apply V001 schema migration";
            return result;
        }
        result.applied_versions.push_back("V001");
    }

    if (std::find(applied_versions_.begin(), applied_versions_.end(), "V002") == applied_versions_.end()) {
        if (!apply_migration("V002", "harden_files_outbox_table", get_v002_schema_sql())) {
            result.success = false;
            result.error_message = "Failed to apply V002 schema migration";
            return result;
        }
        result.applied_versions.push_back("V002");
    }

    result.success = true;
    return result;
}

bool MigrationRunner::apply_migration(std::string_view version, std::string_view /*description*/,
                                      std::string_view sql) {
    if (std::find(applied_versions_.begin(), applied_versions_.end(), version) != applied_versions_.end()) {
        return true; // Idempotent no-op
    }

    std::vector<std::string> missing;
    bool valid = true;
    if (version == "V001") {
        valid = validate_schema_ddl_syntax(sql, missing);
    } else if (version == "V002") {
        valid = validate_v002_schema_ddl_syntax(sql, missing);
    }

    if (!valid) {
        std::cerr << "[SecureCloud] [files] ERROR: Invalid schema DDL for version " << version << "\n";
        for (const auto& m : missing) {
            std::cerr << "  - " << m << "\n";
        }
        return false;
    }

#if defined(SECURECLOUD_FILES_USE_REAL_PQXX) && __has_include(<pqxx/pqxx>)
    if (pool_) {
        try {
            auto lease = pool_->acquire();
            pqxx::connection conn(build_pg_conninfo(pool_->config()));
            pqxx::work tx(conn);
            for (const auto& stmt : split_statements(sql)) {
                tx.exec(stmt);
            }
            tx.commit();
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] ERROR applying migration " << version << ": " << ex.what() << "\n";
            return false;
        }
    }
#endif

    applied_versions_.emplace_back(version);
    return true;
}

std::vector<std::string> MigrationRunner::get_applied_versions() const {
    return applied_versions_;
}

} // namespace securecloud::files::db
