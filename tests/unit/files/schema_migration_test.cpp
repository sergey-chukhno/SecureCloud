#include "files/db/migration_runner.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

namespace securecloud::files::db {
namespace {

std::filesystem::path find_repo_root() {
    auto curr = std::filesystem::current_path();
    while (!curr.empty() && curr != curr.root_path()) {
        if (std::filesystem::exists(curr / "src" / "files" / "db" / "migrations" / "V001__create_files_schema.sql")) {
            return curr;
        }
        curr = curr.parent_path();
    }
    return "";
}

TEST(SchemaMigrationTest, V001FileExistsAndLoads) {
    auto repo_root = find_repo_root();
    ASSERT_FALSE(repo_root.empty()) << "Could not locate repo root containing V001 migration";

    auto file_path = repo_root / "src" / "files" / "db" / "migrations" / "V001__create_files_schema.sql";
    ASSERT_TRUE(std::filesystem::exists(file_path));

    std::ifstream file(file_path);
    ASSERT_TRUE(file.is_open());
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string sql_from_disk = buffer.str();

    EXPECT_FALSE(sql_from_disk.empty());
    EXPECT_NE(sql_from_disk.find("CREATE TABLE IF NOT EXISTS files"), std::string::npos);
}

TEST(SchemaMigrationTest, SchemaContainsAllSevenRequiredTables) {
    std::string_view sql = MigrationRunner::get_v001_schema_sql();

    const std::vector<std::string> expected_tables = {"files",          "file_versions", "encrypted_file_metadata",
                                                      "file_transfers", "file_chunks",   "file_access",
                                                      "files_outbox"};

    for (const auto& table : expected_tables) {
        std::string needle = "CREATE TABLE IF NOT EXISTS " + table;
        EXPECT_NE(sql.find(needle), std::string_view::npos) << "Schema DDL missing required table: " << table;
    }
}

TEST(SchemaMigrationTest, SchemaEnforcesZeroPlaintextInvariant) {
    std::string_view sql = MigrationRunner::get_v001_schema_sql();

    // Verify encrypted fields exist in encrypted_file_metadata
    EXPECT_NE(sql.find("encrypted_filename BYTEA NOT NULL"), std::string_view::npos);
    EXPECT_NE(sql.find("encrypted_mime_type BYTEA NULL"), std::string_view::npos);
    EXPECT_NE(sql.find("metadata_nonce BYTEA NOT NULL"), std::string_view::npos);
    EXPECT_NE(sql.find("metadata_tag BYTEA NOT NULL"), std::string_view::npos);
    EXPECT_NE(sql.find("client_encryption_metadata JSONB"), std::string_view::npos);

    // Verify plaintext fields do NOT exist
    EXPECT_EQ(sql.find("plaintext_filename"), std::string_view::npos);
    EXPECT_EQ(sql.find("plaintext_content"), std::string_view::npos);
    EXPECT_EQ(sql.find("file_encryption_key"), std::string_view::npos);
    EXPECT_EQ(sql.find("private_key"), std::string_view::npos);
}

TEST(SchemaMigrationTest, SchemaDefinesAllCascadeForeignKeys) {
    std::string_view sql = MigrationRunner::get_v001_schema_sql();

    EXPECT_NE(sql.find("file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE"), std::string_view::npos);
    EXPECT_NE(sql.find("file_id UUID PRIMARY KEY REFERENCES files(file_id) ON DELETE CASCADE"), std::string_view::npos);
    EXPECT_NE(sql.find("transfer_id UUID NOT NULL REFERENCES file_transfers(transfer_id) ON DELETE CASCADE"),
              std::string_view::npos);
}

TEST(SchemaMigrationTest, SchemaEnforcesUniqueConstraintsAndIndexes) {
    std::string_view sql = MigrationRunner::get_v001_schema_sql();

    // Unique constraints
    EXPECT_NE(sql.find("CONSTRAINT uq_file_version UNIQUE(file_id, version_number)"), std::string_view::npos);
    EXPECT_NE(sql.find("CONSTRAINT uq_transfer_chunk UNIQUE(transfer_id, chunk_index)"), std::string_view::npos);
    EXPECT_NE(sql.find("CONSTRAINT uq_file_grantee UNIQUE(file_id, grantee_user_id)"), std::string_view::npos);

    // Indexes
    EXPECT_NE(sql.find("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_user_id, status)"),
              std::string_view::npos);
    EXPECT_NE(sql.find("CREATE INDEX IF NOT EXISTS idx_files_conversation ON files(conversation_id) WHERE "
                       "conversation_id IS NOT NULL"),
              std::string_view::npos);
    EXPECT_NE(
        sql.find("CREATE INDEX IF NOT EXISTS idx_files_retention ON files(retention_until) WHERE status != 'DELETED'"),
        std::string_view::npos);
    EXPECT_NE(sql.find("CREATE INDEX IF NOT EXISTS idx_file_transfers_file ON file_transfers(file_id, status)"),
              std::string_view::npos);
    EXPECT_NE(sql.find("CREATE INDEX IF NOT EXISTS idx_file_chunks_transfer ON file_chunks(transfer_id, chunk_index)"),
              std::string_view::npos);
    EXPECT_NE(
        sql.find(
            "CREATE INDEX IF NOT EXISTS idx_files_outbox_pending ON files_outbox(created_at) WHERE status = 'PENDING'"),
        std::string_view::npos);
}

TEST(SchemaMigrationTest, StatementSplitterParsesCleanly) {
    std::string_view sql = MigrationRunner::get_v001_schema_sql();
    auto statements = MigrationRunner::split_statements(sql);

    // 7 tables + 6 indexes = 13 discrete DDL statements
    EXPECT_EQ(statements.size(), 13);

    for (const auto& stmt : statements) {
        EXPECT_FALSE(stmt.empty());
        EXPECT_TRUE(stmt.starts_with("CREATE TABLE") || stmt.starts_with("CREATE INDEX"))
            << "Unexpected statement format: " << stmt;
        EXPECT_TRUE(stmt.ends_with(';'));
    }
}

TEST(SchemaMigrationTest, MigrationRunnerTracksAppliedVersionsIdempotently) {
    MigrationRunner runner(nullptr);
    EXPECT_TRUE(runner.get_applied_versions().empty());

    // First run applies V001
    auto res1 = runner.run_migrations();
    EXPECT_TRUE(res1.success);
    ASSERT_EQ(res1.applied_versions.size(), 1);
    EXPECT_EQ(res1.applied_versions[0], "V001");

    auto applied = runner.get_applied_versions();
    ASSERT_EQ(applied.size(), 1);
    EXPECT_EQ(applied[0], "V001");

    // Second run is idempotent no-op
    auto res2 = runner.run_migrations();
    EXPECT_TRUE(res2.success);
    EXPECT_TRUE(res2.applied_versions.empty());
    EXPECT_EQ(runner.get_applied_versions().size(), 1);
}

TEST(SchemaMigrationTest, MigrationRunnerRejectsInvalidDDL) {
    MigrationRunner runner(nullptr);
    std::string bad_sql = "CREATE TABLE something_else (id INT PRIMARY KEY);";

    std::vector<std::string> missing;
    bool valid = MigrationRunner::validate_schema_ddl_syntax(bad_sql, missing);
    EXPECT_FALSE(valid);
    EXPECT_FALSE(missing.empty());

    bool applied = runner.apply_migration("V999", "bad migration", bad_sql);
    EXPECT_FALSE(applied);
    EXPECT_TRUE(runner.get_applied_versions().empty());
}

} // namespace
} // namespace securecloud::files::db
