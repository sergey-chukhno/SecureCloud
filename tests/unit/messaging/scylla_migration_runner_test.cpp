#include "messaging/db/embedded_migrations.hpp"
#include "messaging/db/migration_runner.hpp"

#include <gtest/gtest.h>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::messaging::db::test {
namespace {

class MockCqlExecutor : public ICqlExecutor {
  public:
    void execute_cql(std::string_view cql) override {
        if (fail_on_execute_) {
            throw std::runtime_error("Simulated CQL syntax/execution error");
        }
        executed_statements_.emplace_back(cql);
    }

    std::vector<AppliedMigrationRecord> get_applied_migrations() override {
        if (fail_on_query_) {
            throw std::runtime_error("Table does not exist");
        }
        std::vector<AppliedMigrationRecord> records;
        for (const auto& [version, record] : applied_migrations_) {
            records.push_back(record);
        }
        return records;
    }

    void record_migration(int version, std::string_view script_name, std::string_view checksum) override {
        if (fail_on_record_) {
            throw std::runtime_error("Simulated record migration failure");
        }
        applied_migrations_[version] =
            AppliedMigrationRecord{version, std::string(script_name), std::string(checksum), "2026-10-15T10:00:00Z"};
    }

    void add_applied_migration(int version, std::string_view script_name, std::string_view checksum) {
        applied_migrations_[version] =
            AppliedMigrationRecord{version, std::string(script_name), std::string(checksum), "2026-10-15T09:00:00Z"};
    }

    std::vector<std::string> executed_statements_;
    std::map<int, AppliedMigrationRecord> applied_migrations_;
    bool fail_on_execute_{false};
    bool fail_on_query_{false};
    bool fail_on_record_{false};
};

TEST(ScyllaMigrationRunnerTest, NormalizeCqlAndChecksumCalculation) {
    std::string_view unix_cql = "CREATE KEYSPACE test;\nCREATE TABLE foo (id text);\n";
    std::string_view windows_cql = "\r\nCREATE KEYSPACE test;\r\nCREATE TABLE foo (id text);\r\n\r\n";
    std::string_view padded_cql = "   \n\tCREATE KEYSPACE test;\nCREATE TABLE foo (id text);\t\n  ";

    std::string hash1 = ScyllaMigrationRunner::calculate_checksum(unix_cql);
    std::string hash2 = ScyllaMigrationRunner::calculate_checksum(windows_cql);
    std::string hash3 = ScyllaMigrationRunner::calculate_checksum(padded_cql);

    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(hash1, hash3);
    EXPECT_EQ(hash1.length(), 64U);

    std::string_view different_cql = "CREATE KEYSPACE test2;";
    std::string hash_diff = ScyllaMigrationRunner::calculate_checksum(different_cql);
    EXPECT_NE(hash1, hash_diff);
}

TEST(ScyllaMigrationRunnerTest, ParseCqlStatementsWithCommentsAndQuotes) {
    std::string_view complex_cql = R"CQL(
-- Line comment with dash
CREATE KEYSPACE IF NOT EXISTS test_keyspace;

// Line comment with slash
/* Multi-line block comment
   spanning multiple lines with ; inside */
CREATE TABLE test_keyspace.sample (
    id text,
    name text,
    -- comment inside table def
    description text,
    default_val text DEFAULT 'semi;colon inside single quote and escaped ''quote''',
    PRIMARY KEY (id)
);

INSERT INTO test_keyspace.sample (id, default_val) VALUES ('1', 'hello; world');
)CQL";

    auto statements = ScyllaMigrationRunner::parse_cql_statements(complex_cql);

    ASSERT_EQ(statements.size(), 3U);
    EXPECT_EQ(statements[0], "CREATE KEYSPACE IF NOT EXISTS test_keyspace");
    EXPECT_NE(statements[1].find("CREATE TABLE test_keyspace.sample"), std::string::npos);
    EXPECT_NE(statements[1].find("'semi;colon inside single quote and escaped ''quote'''"), std::string::npos);
    EXPECT_EQ(statements[2], "INSERT INTO test_keyspace.sample (id, default_val) VALUES ('1', 'hello; world')");
}

TEST(ScyllaMigrationRunnerTest, StandardMigrationsHaveValidChecksumsAndOrdering) {
    auto migrations = ScyllaMigrationRunner::get_standard_migrations();

    ASSERT_EQ(migrations.size(), 5U);
    EXPECT_EQ(migrations[0].version, 1);
    EXPECT_EQ(migrations[0].script_name, "create_messaging_keyspace");
    EXPECT_EQ(migrations[0].checksum, ScyllaMigrationRunner::calculate_checksum(k_v001_keyspace_cql));

    EXPECT_EQ(migrations[1].version, 2);
    EXPECT_EQ(migrations[1].script_name, "create_messaging_tables");
    EXPECT_EQ(migrations[1].checksum, ScyllaMigrationRunner::calculate_checksum(k_v002_tables_cql));

    EXPECT_EQ(migrations[2].version, 3);
    EXPECT_EQ(migrations[2].script_name, "create_schema_version_tracking");
    EXPECT_EQ(migrations[2].checksum, ScyllaMigrationRunner::calculate_checksum(k_v003_version_tracking_cql));

    EXPECT_EQ(migrations[3].version, 4);
    EXPECT_EQ(migrations[3].script_name, "add_per_device_envelope_columns");
    EXPECT_EQ(migrations[3].checksum, ScyllaMigrationRunner::calculate_checksum(k_v004_per_device_envelope_cql));

    EXPECT_EQ(migrations[4].version, 5);
    EXPECT_EQ(migrations[4].script_name, "add_message_id_secondary_indexes");
    EXPECT_EQ(migrations[4].checksum, ScyllaMigrationRunner::calculate_checksum(k_v005_message_id_indexes_cql));
}

TEST(ScyllaMigrationRunnerTest, RunMigrationsAppliesAllScriptsSequentially) {
    MockCqlExecutor executor;
    ScyllaMigrationRunner runner(executor);

    auto result = runner.run_migrations();

    EXPECT_EQ(result.migrations_applied, 5);
    EXPECT_EQ(result.current_version, 5);
    ASSERT_EQ(result.applied_scripts.size(), 5U);
    EXPECT_EQ(result.applied_scripts[0], "create_messaging_keyspace");
    EXPECT_EQ(result.applied_scripts[1], "create_messaging_tables");
    EXPECT_EQ(result.applied_scripts[2], "create_schema_version_tracking");
    EXPECT_EQ(result.applied_scripts[3], "add_per_device_envelope_columns");
    EXPECT_EQ(result.applied_scripts[4], "add_message_id_secondary_indexes");

    // Check that executor tracked all 5 migrations
    EXPECT_EQ(executor.applied_migrations_.size(), 5U);
    EXPECT_FALSE(executor.executed_statements_.empty());
}

TEST(ScyllaMigrationRunnerTest, RunMigrationsIsIdempotent) {
    MockCqlExecutor executor;
    ScyllaMigrationRunner runner(executor);

    // Initial run applies 5
    auto result1 = runner.run_migrations();
    EXPECT_EQ(result1.migrations_applied, 5);

    size_t executed_count = executor.executed_statements_.size();

    // Second run applies 0
    auto result2 = runner.run_migrations();
    EXPECT_EQ(result2.migrations_applied, 0);
    EXPECT_EQ(result2.current_version, 5);
    EXPECT_TRUE(result2.applied_scripts.empty());
    EXPECT_EQ(executor.executed_statements_.size(), executed_count);
}

TEST(ScyllaMigrationRunnerTest, RunMigrationsDetectsChecksumMismatch) {
    MockCqlExecutor executor;
    executor.add_applied_migration(1, "create_messaging_keyspace",
                                   "tampered_bad_checksum_000000000000000000000000000000000000000000000");

    ScyllaMigrationRunner runner(executor);

    EXPECT_THROW({ runner.run_migrations(); }, MigrationChecksumMismatchException);
}

TEST(ScyllaMigrationRunnerTest, RunMigrationsFailsOnExecutionError) {
    MockCqlExecutor executor;
    executor.fail_on_execute_ = true;

    ScyllaMigrationRunner runner(executor);

    EXPECT_THROW({ runner.run_migrations(); }, MigrationExecutionException);
}

TEST(ScyllaMigrationRunnerTest, RunMigrationsFailsOnRecordError) {
    MockCqlExecutor executor;
    executor.fail_on_record_ = true;

    ScyllaMigrationRunner runner(executor);

    EXPECT_THROW({ runner.run_migrations(); }, MigrationExecutionException);
}

} // namespace
} // namespace securecloud::messaging::db::test
