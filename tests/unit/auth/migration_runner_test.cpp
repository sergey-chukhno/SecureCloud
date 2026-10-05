#include "auth/db/migration_runner.hpp"

#include <gtest/gtest.h>
#include <string>

namespace securecloud::auth::db::test {

TEST(MigrationRunnerTest, NormalizationHandlesCrlfAndWhitespace) {
    std::string lf_sql = "CREATE TABLE test (\n    id INT PRIMARY KEY\n);\n";
    std::string crlf_sql = "CREATE TABLE test (\r\n    id INT PRIMARY KEY\r\n);\r\n";

    std::string norm_lf = MigrationRunner::normalize_sql(lf_sql);
    std::string norm_crlf = MigrationRunner::normalize_sql(crlf_sql);

    EXPECT_EQ(norm_lf, norm_crlf);
    EXPECT_EQ(norm_lf.find("\r"), std::string::npos);

    std::string checksum_lf = MigrationRunner::calculate_checksum(lf_sql);
    std::string checksum_crlf = MigrationRunner::calculate_checksum(crlf_sql);

    EXPECT_EQ(checksum_lf, checksum_crlf);
    EXPECT_EQ(checksum_lf.size(), 64); // 64 hex characters for SHA-256
}

TEST(MigrationRunnerTest, StandardMigrationsStructure) {
    auto migrations = MigrationRunner::get_standard_migrations();
    ASSERT_EQ(migrations.size(), 3);

    EXPECT_EQ(migrations[0].version, 1);
    EXPECT_EQ(migrations[0].description, "create_schema_migrations");
    EXPECT_FALSE(migrations[0].sql_content.empty());
    EXPECT_EQ(migrations[0].checksum, MigrationRunner::calculate_checksum(migrations[0].sql_content));

    EXPECT_EQ(migrations[1].version, 2);
    EXPECT_EQ(migrations[1].description, "create_auth_tables");
    EXPECT_FALSE(migrations[1].sql_content.empty());
    EXPECT_EQ(migrations[1].checksum, MigrationRunner::calculate_checksum(migrations[1].sql_content));

    EXPECT_EQ(migrations[2].version, 3);
    EXPECT_EQ(migrations[2].description, "create_auth_indexes");
    EXPECT_FALSE(migrations[2].sql_content.empty());
    EXPECT_EQ(migrations[2].checksum, MigrationRunner::calculate_checksum(migrations[2].sql_content));
}

TEST(MigrationRunnerTest, AdvisoryLockConstantDefined) {
    EXPECT_EQ(k_auth_migration_advisory_lock, 0x5343415554483031LL);
}

TEST(MigrationRunnerTest, ExceptionHierarchy) {
    static_assert(std::is_base_of_v<MigrationException, MigrationChecksumMismatchException>);
    static_assert(std::is_base_of_v<MigrationException, MigrationExecutionException>);
    static_assert(std::is_base_of_v<std::runtime_error, MigrationException>);

    MigrationChecksumMismatchException mismatch_ex(2, "expected_hash", "actual_hash");
    std::string msg = mismatch_ex.what();
    EXPECT_NE(msg.find("Checksum mismatch"), std::string::npos);
    EXPECT_NE(msg.find("expected_hash"), std::string::npos);
    EXPECT_NE(msg.find("actual_hash"), std::string::npos);

    MigrationExecutionException exec_ex(1, "script_name", "syntax error");
    std::string exec_msg = exec_ex.what();
    EXPECT_NE(exec_msg.find("Failed to apply migration"), std::string::npos);
    EXPECT_NE(exec_msg.find("syntax error"), std::string::npos);
}

} // namespace securecloud::auth::db::test
