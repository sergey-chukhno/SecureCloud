#include "messaging/db/migration_runner.hpp"

#include "messaging/db/embedded_migrations.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <openssl/sha.h>
#include <sstream>

namespace securecloud::messaging::db {

ScyllaMigrationRunner::ScyllaMigrationRunner(ICqlExecutor& executor) : executor_(executor) {}

std::string ScyllaMigrationRunner::normalize_cql(std::string_view cql_content) {
    std::string result;
    result.reserve(cql_content.size());
    for (std::size_t i = 0; i < cql_content.size(); ++i) {
        if (cql_content[i] == '\r') {
            if (i + 1 < cql_content.size() && cql_content[i + 1] == '\n') {
                continue;
            }
            result.push_back('\n');
        } else {
            result.push_back(cql_content[i]);
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

std::string ScyllaMigrationRunner::calculate_checksum(std::string_view cql_content) {
    std::string normalized = normalize_cql(cql_content);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(normalized.data()), normalized.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::vector<std::string> ScyllaMigrationRunner::parse_cql_statements(std::string_view cql_content) {
    std::vector<std::string> statements;
    std::string current;
    current.reserve(cql_content.size());

    enum class State { Normal, InSingleQuote, InLineCommentDash, InLineCommentSlash, InBlockComment };

    State state = State::Normal;
    const std::size_t len = cql_content.size();

    for (std::size_t i = 0; i < len; ++i) {
        char c = cql_content[i];
        char next = (i + 1 < len) ? cql_content[i + 1] : '\0';

        switch (state) {
        case State::Normal:
            if (c == '\'') {
                state = State::InSingleQuote;
                current.push_back(c);
            } else if (c == '-' && next == '-') {
                state = State::InLineCommentDash;
                ++i; // skip second dash
            } else if (c == '/' && next == '/') {
                state = State::InLineCommentSlash;
                ++i; // skip second slash
            } else if (c == '/' && next == '*') {
                state = State::InBlockComment;
                ++i; // skip asterisk
            } else if (c == ';') {
                // Statement complete
                // Trim statement
                std::size_t start = 0;
                while (start < current.size() && (current[start] == ' ' || current[start] == '\t' ||
                                                  current[start] == '\n' || current[start] == '\r')) {
                    ++start;
                }
                std::size_t end = current.size();
                while (end > start && (current[end - 1] == ' ' || current[end - 1] == '\t' ||
                                       current[end - 1] == '\n' || current[end - 1] == '\r')) {
                    --end;
                }
                if (end > start) {
                    statements.push_back(current.substr(start, end - start));
                }
                current.clear();
            } else {
                current.push_back(c);
            }
            break;

        case State::InSingleQuote:
            current.push_back(c);
            if (c == '\'') {
                if (next == '\'') {
                    // Escaped single quote
                    current.push_back(next);
                    ++i;
                } else {
                    state = State::Normal;
                }
            }
            break;

        case State::InLineCommentDash:
        case State::InLineCommentSlash:
            if (c == '\n') {
                state = State::Normal;
                current.push_back('\n');
            }
            break;

        case State::InBlockComment:
            if (c == '*' && next == '/') {
                state = State::Normal;
                ++i; // skip slash
            }
            break;
        }
    }

    // Trailing statement without trailing semicolon
    std::size_t start = 0;
    while (start < current.size() &&
           (current[start] == ' ' || current[start] == '\t' || current[start] == '\n' || current[start] == '\r')) {
        ++start;
    }
    std::size_t end = current.size();
    while (end > start && (current[end - 1] == ' ' || current[end - 1] == '\t' || current[end - 1] == '\n' ||
                           current[end - 1] == '\r')) {
        --end;
    }
    if (end > start) {
        statements.push_back(current.substr(start, end - start));
    }

    return statements;
}

std::vector<MigrationScript> ScyllaMigrationRunner::get_standard_migrations() {
    return {{1, "create_messaging_keyspace", std::string(k_v001_keyspace_cql), calculate_checksum(k_v001_keyspace_cql)},
            {2, "create_messaging_tables", std::string(k_v002_tables_cql), calculate_checksum(k_v002_tables_cql)},
            {3, "create_schema_version_tracking", std::string(k_v003_version_tracking_cql),
             calculate_checksum(k_v003_version_tracking_cql)},
            {4, "add_per_device_envelope_columns", std::string(k_v004_per_device_envelope_cql),
             calculate_checksum(k_v004_per_device_envelope_cql)},
            {5, "add_message_id_secondary_indexes", std::string(k_v005_message_id_indexes_cql),
             calculate_checksum(k_v005_message_id_indexes_cql)}};
}

MigrationResult ScyllaMigrationRunner::run_migrations() {
    return run_migrations(get_standard_migrations());
}

MigrationResult ScyllaMigrationRunner::run_migrations(const std::vector<MigrationScript>& scripts) {
    std::vector<MigrationScript> sorted_scripts = scripts;
    std::sort(sorted_scripts.begin(), sorted_scripts.end(),
              [](const MigrationScript& a, const MigrationScript& b) { return a.version < b.version; });

    // 1. Fetch applied migrations
    std::vector<AppliedMigrationRecord> applied_records;
    try {
        applied_records = executor_.get_applied_migrations();
    } catch (...) {
        // Table may not exist yet on initial run
        applied_records.clear();
    }

    std::map<int, AppliedMigrationRecord> applied_map;
    int max_applied_version = 0;
    for (const auto& rec : applied_records) {
        applied_map[rec.version] = rec;
        if (rec.version > max_applied_version) {
            max_applied_version = rec.version;
        }
    }

    MigrationResult result;
    result.current_version = max_applied_version;

    // 2. Process each migration in sequential order
    for (const auto& script : sorted_scripts) {
        auto it = applied_map.find(script.version);
        if (it != applied_map.end()) {
            // Already applied: verify checksum
            if (it->second.checksum != script.checksum) {
                throw MigrationChecksumMismatchException(script.version, script.checksum, it->second.checksum);
            }
            continue;
        }

        // Apply new migration
        auto statements = parse_cql_statements(script.cql_content);
        for (const auto& stmt : statements) {
            try {
                executor_.execute_cql(stmt);
            } catch (const std::exception& ex) {
                throw MigrationExecutionException(script.version, script.script_name, ex.what());
            } catch (...) {
                throw MigrationExecutionException(script.version, script.script_name,
                                                  "Unknown failure executing statement");
            }
        }

        // Record successful application
        try {
            executor_.record_migration(script.version, script.script_name, script.checksum);
        } catch (const std::exception& ex) {
            throw MigrationExecutionException(script.version, script.script_name,
                                              std::string("Failed to record migration: ") + ex.what());
        }

        ++result.migrations_applied;
        result.applied_scripts.push_back(script.script_name);
        if (script.version > result.current_version) {
            result.current_version = script.version;
        }
    }

    return result;
}

} // namespace securecloud::messaging::db
