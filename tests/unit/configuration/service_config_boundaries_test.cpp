#include "audit_config.hpp"
#include "auth_config.hpp"
#include "files_config.hpp"
#include "gateway_config.hpp"
#include "messaging_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <gtest/gtest.h>
#include <sstream>

namespace securecloud {

namespace {

// C++20 Concepts to statically verify architectural boundary isolation
template <typename T>
concept HasDbPassword = requires(T t) {
    { t.db_password };
};

template <typename T>
concept HasScyllaHost = requires(T t) {
    { t.scylla_host };
};

template <typename T>
concept HasS3SecretKey = requires(T t) {
    { t.s3_secret_key };
};

template <typename T>
concept HasAuthEndpoint = requires(T t) {
    { t.auth_endpoint };
};

// Compile-time verification of strict service ownership boundaries
static_assert(!HasDbPassword<gateway::GatewayConfig>, "GatewayConfig must not expose database credentials");
static_assert(!HasScyllaHost<gateway::GatewayConfig>, "GatewayConfig must not expose ScyllaDB configuration");
static_assert(!HasS3SecretKey<gateway::GatewayConfig>, "GatewayConfig must not expose S3 credentials");
static_assert(HasAuthEndpoint<gateway::GatewayConfig>, "GatewayConfig must expose downstream auth endpoint");

static_assert(HasDbPassword<auth::AuthConfig>, "AuthConfig must expose PostgreSQL db_password");
static_assert(!HasScyllaHost<auth::AuthConfig>, "AuthConfig must not expose ScyllaDB configuration");
static_assert(!HasS3SecretKey<auth::AuthConfig>, "AuthConfig must not expose S3 credentials");
static_assert(!HasAuthEndpoint<auth::AuthConfig>, "AuthConfig must not expose gateway downstream endpoints");

static_assert(!HasDbPassword<messaging::MessagingConfig>, "MessagingConfig must not expose relational db_password");
static_assert(HasScyllaHost<messaging::MessagingConfig>, "MessagingConfig must expose ScyllaDB configuration");
static_assert(!HasS3SecretKey<messaging::MessagingConfig>, "MessagingConfig must not expose S3 credentials");
static_assert(!HasAuthEndpoint<messaging::MessagingConfig>, "MessagingConfig must not expose gateway endpoints");

static_assert(HasDbPassword<files::FilesConfig>, "FilesConfig must expose PostgreSQL db_password");
static_assert(!HasScyllaHost<files::FilesConfig>, "FilesConfig must not expose ScyllaDB configuration");
static_assert(HasS3SecretKey<files::FilesConfig>, "FilesConfig must expose MinIO S3 credentials");
static_assert(!HasAuthEndpoint<files::FilesConfig>, "FilesConfig must not expose gateway endpoints");

static_assert(HasDbPassword<audit::AuditConfig>, "AuditConfig must expose ClickHouse db_password");
static_assert(!HasScyllaHost<audit::AuditConfig>, "AuditConfig must not expose ScyllaDB configuration");
static_assert(!HasS3SecretKey<audit::AuditConfig>, "AuditConfig must not expose S3 credentials");
static_assert(!HasAuthEndpoint<audit::AuditConfig>, "AuditConfig must not expose gateway endpoints");

constexpr uint16_t k_default_postgres_port = 5432;
constexpr uint16_t k_default_scylla_port = 9042;
constexpr uint16_t k_custom_scylla_port = 9043;
constexpr uint16_t k_default_clickhouse_port = 8123;
constexpr uint16_t k_custom_clickhouse_port = 8124;

} // namespace

TEST(ServiceConfigBoundariesTest, GatewayConfigBoundaryAndIsolation) {
    common::configuration::InMemoryConfigurationSource source;
    // Supply foreign service secrets that must be completely ignored by Gateway
    source.set("SECURECLOUD_AUTH_DB_PASSWORD", "should_be_ignored");
    source.set("SECURECLOUD_FILES_S3_SECRET_KEY", "should_be_ignored");
    source.set("SECURECLOUD_GATEWAY_AUTH_ENDPOINT", "auth.prod.internal:50052");
    source.set("SECURECLOUD_GATEWAY_MESSAGING_ENDPOINT", "messaging.prod.internal:50053");

    common::configuration::ValidationResult errors;
    auto config = gateway::GatewayConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.auth_endpoint, "auth.prod.internal:50052");
    EXPECT_EQ(config.messaging_endpoint, "messaging.prod.internal:50053");
    EXPECT_EQ(config.files_endpoint, "files:50054"); // Default
    EXPECT_EQ(config.audit_endpoint, "audit:50055"); // Default
}

TEST(ServiceConfigBoundariesTest, AuthConfigMandatoryPasswordFailClosed) {
    common::configuration::InMemoryConfigurationSource source;
    // Supply foreign passwords to ensure strict boundary isolation
    source.set("SECURECLOUD_FILES_DB_PASSWORD", "files_pw");
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "audit_pw");

    common::configuration::ValidationResult errors;
    auto config = auth::AuthConfig::load(source, errors);

    EXPECT_FALSE(errors.is_valid());
    const auto& err_list = errors.errors();
    ASSERT_EQ(err_list.size(), 1U);
    EXPECT_EQ(err_list[0].setting_key(), "SECURECLOUD_AUTH_DB_PASSWORD");
}

TEST(ServiceConfigBoundariesTest, AuthConfigValidConfigurationAndSecretMasking) {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUTH_DB_PASSWORD", "auth_super_secret");
    source.set("SECURECLOUD_AUTH_DB_HOST", "auth-postgres-host");

    common::configuration::ValidationResult errors;
    auto config = auth::AuthConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.db_host, "auth-postgres-host");
    EXPECT_EQ(config.db_port, k_default_postgres_port);
    EXPECT_EQ(config.db_name, "securecloud_auth");
    EXPECT_EQ(config.db_user, "auth_user");

    // Secret masking in streams
    std::ostringstream ss;
    ss << config.db_password;
    EXPECT_EQ(ss.str(), "[REDACTED]");

    // Explicit exposure
    EXPECT_EQ(config.db_password.expose_unredacted_secret(), "auth_super_secret");
}

TEST(ServiceConfigBoundariesTest, MessagingConfigDefaultSettings) {
    common::configuration::InMemoryConfigurationSource source;
    common::configuration::ValidationResult errors;
    auto config = messaging::MessagingConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.scylla_host, "scylladb");
    EXPECT_EQ(config.scylla_port, k_default_scylla_port);
    EXPECT_EQ(config.scylla_keyspace, "securecloud_messaging");
}

TEST(ServiceConfigBoundariesTest, MessagingConfigBoundaryAndSettings) {
    common::configuration::InMemoryConfigurationSource source;
    // Supply foreign passwords to ensure strict boundary isolation
    source.set("SECURECLOUD_AUTH_DB_PASSWORD", "should_be_ignored");
    source.set("SECURECLOUD_MESSAGING_SCYLLA_HOST", "scylla-node-01");
    source.set("SECURECLOUD_MESSAGING_SCYLLA_PORT", "9043");
    source.set("SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE", "custom_chat_keyspace");

    common::configuration::ValidationResult errors;
    auto config = messaging::MessagingConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.scylla_host, "scylla-node-01");
    EXPECT_EQ(config.scylla_port, k_custom_scylla_port);
    EXPECT_EQ(config.scylla_keyspace, "custom_chat_keyspace");
}

TEST(ServiceConfigBoundariesTest, FilesConfigMandatoryCredentialsFailClosed) {
    // Both credentials missing
    {
        common::configuration::InMemoryConfigurationSource source;
        common::configuration::ValidationResult errors;
        auto config = files::FilesConfig::load(source, errors);

        EXPECT_FALSE(errors.is_valid());
        EXPECT_EQ(errors.errors().size(), 2U);
    }

    // Only S3 key missing
    {
        common::configuration::InMemoryConfigurationSource source;
        source.set("SECURECLOUD_FILES_DB_PASSWORD", "files_pw");

        common::configuration::ValidationResult errors;
        auto config = files::FilesConfig::load(source, errors);

        EXPECT_FALSE(errors.is_valid());
        ASSERT_EQ(errors.errors().size(), 1U);
        EXPECT_EQ(errors.errors()[0].setting_key(), "SECURECLOUD_FILES_S3_SECRET_KEY");
    }

    // Only DB password missing
    {
        common::configuration::InMemoryConfigurationSource source;
        source.set("SECURECLOUD_FILES_S3_SECRET_KEY", "s3_secret");

        common::configuration::ValidationResult errors;
        auto config = files::FilesConfig::load(source, errors);

        EXPECT_FALSE(errors.is_valid());
        ASSERT_EQ(errors.errors().size(), 1U);
        EXPECT_EQ(errors.errors()[0].setting_key(), "SECURECLOUD_FILES_DB_PASSWORD");
    }
}

TEST(ServiceConfigBoundariesTest, FilesConfigValidAndSecretMasking) {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_FILES_DB_PASSWORD", "files_db_pass");
    source.set("SECURECLOUD_FILES_S3_SECRET_KEY", "files_s3_secret");
    source.set("SECURECLOUD_FILES_S3_BUCKET", "custom-bucket");

    common::configuration::ValidationResult errors;
    auto config = files::FilesConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.db_host, "postgres");
    EXPECT_EQ(config.s3_bucket, "custom-bucket");

    // Both secrets masked in streams
    std::ostringstream ss1;
    ss1 << config.db_password;
    EXPECT_EQ(ss1.str(), "[REDACTED]");

    std::ostringstream ss2;
    ss2 << config.s3_secret_key;
    EXPECT_EQ(ss2.str(), "[REDACTED]");

    // Explicit exposure
    EXPECT_EQ(config.db_password.expose_unredacted_secret(), "files_db_pass");
    EXPECT_EQ(config.s3_secret_key.expose_unredacted_secret(), "files_s3_secret");
}

TEST(ServiceConfigBoundariesTest, AuditConfigMandatoryPasswordFailClosed) {
    common::configuration::InMemoryConfigurationSource source;
    // Foreign password should not satisfy audit requirement
    source.set("SECURECLOUD_AUTH_DB_PASSWORD", "auth_pw");

    common::configuration::ValidationResult errors;
    auto config = audit::AuditConfig::load(source, errors);

    EXPECT_FALSE(errors.is_valid());
    ASSERT_EQ(errors.errors().size(), 1U);
    EXPECT_EQ(errors.errors()[0].setting_key(), "SECURECLOUD_AUDIT_DB_PASSWORD");
}

TEST(ServiceConfigBoundariesTest, AuditConfigDefaultSettings) {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "audit_clickhouse_secret");

    common::configuration::ValidationResult errors;
    auto config = audit::AuditConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.db_port, k_default_clickhouse_port);
}

TEST(ServiceConfigBoundariesTest, AuditConfigValidAndSecretMasking) {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "audit_clickhouse_secret");
    source.set("SECURECLOUD_AUDIT_DB_PORT", "8124");

    common::configuration::ValidationResult errors;
    auto config = audit::AuditConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.db_host, "clickhouse");
    EXPECT_EQ(config.db_port, k_custom_clickhouse_port);
    EXPECT_EQ(config.db_name, "securecloud_audit");
    EXPECT_EQ(config.db_user, "audit_user");

    // Secret masking in stream
    std::ostringstream ss;
    ss << config.db_password;
    EXPECT_EQ(ss.str(), "[REDACTED]");

    // Explicit exposure
    EXPECT_EQ(config.db_password.expose_unredacted_secret(), "audit_clickhouse_secret");
}

} // namespace securecloud
