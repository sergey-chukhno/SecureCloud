#include "audit_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <gtest/gtest.h>
#include <sstream>
#include <string>

namespace securecloud::audit::test {

namespace {

common::configuration::InMemoryConfigurationSource create_valid_base_source() {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "SuperSecretPassword123!");
    return source;
}

} // namespace

TEST(AuditConfigTest, DefaultValuesAreValid) {
    auto source = create_valid_base_source();
    common::configuration::ValidationResult errors;

    auto config = AuditConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_EQ(config.common.grpc_port, 50055);
    EXPECT_EQ(config.common.grpc_host, "0.0.0.0");
    EXPECT_EQ(config.clickhouse.host, "clickhouse");
    EXPECT_EQ(config.clickhouse.port, 8123);
    EXPECT_EQ(config.ingestion.workers, 8);
    EXPECT_EQ(config.query.workers, 4);
    EXPECT_EQ(config.ingestion.batch_size, 500);
    EXPECT_EQ(config.ingestion.batch_flush_interval_ms, 200);
}

TEST(AuditConfigTest, CompleteEnvironmentOverride) {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUDIT_GRPC_PORT", "50099");
    source.set("SECURECLOUD_AUDIT_GRPC_HOST", "127.0.0.1");
    source.set("SECURECLOUD_AUDIT_DB_HOST", "ch-cluster.internal");
    source.set("SECURECLOUD_AUDIT_DB_PORT", "9000");
    source.set("SECURECLOUD_AUDIT_DB_USER", "custom_audit");
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "CustomPass456!");
    source.set("SECURECLOUD_AUDIT_INGESTION_WORKERS", "16");
    source.set("SECURECLOUD_AUDIT_MAX_QUEUED_EVENTS", "50000");
    source.set("SECURECLOUD_AUDIT_BATCH_SIZE", "1000");
    source.set("SECURECLOUD_AUDIT_BATCH_FLUSH_INTERVAL_MS", "500");
    source.set("SECURECLOUD_AUDIT_MAX_EVENT_SIZE_BYTES", "131072");
    source.set("SECURECLOUD_AUDIT_QUERY_WORKERS", "8");
    source.set("SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT", "50");
    source.set("SECURECLOUD_AUDIT_MAX_PAGE_LIMIT", "500");
    source.set("SECURECLOUD_AUDIT_QUERY_TIMEOUT_MS", "15000");
    source.set("SECURECLOUD_AUDIT_RETENTION_DAYS", "180");
    source.set("SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS", "10000");

    common::configuration::ValidationResult errors;
    auto config = AuditConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_EQ(config.common.grpc_port, 50099);
    EXPECT_EQ(config.common.grpc_host, "127.0.0.1");
    EXPECT_EQ(config.clickhouse.host, "ch-cluster.internal");
    EXPECT_EQ(config.clickhouse.port, 9000);
    EXPECT_EQ(config.clickhouse.user, "custom_audit");
    EXPECT_EQ(config.clickhouse.password.expose_unredacted_secret(), "CustomPass456!");
    EXPECT_EQ(config.ingestion.workers, 16);
    EXPECT_EQ(config.ingestion.max_queued_events, 50000);
    EXPECT_EQ(config.ingestion.batch_size, 1000);
    EXPECT_EQ(config.ingestion.batch_flush_interval_ms, 500);
    EXPECT_EQ(config.ingestion.max_event_size_bytes, 131072);
    EXPECT_EQ(config.query.workers, 8);
    EXPECT_EQ(config.query.default_page_limit, 50);
    EXPECT_EQ(config.query.max_page_limit, 500);
    EXPECT_EQ(config.query.query_timeout_ms, 15000);
    EXPECT_EQ(config.retention.retention_days, 180);
    EXPECT_EQ(config.retention.shutdown_grace_period_ms, 10000);
}

TEST(AuditConfigTest, MissingRequiredPasswordFailsClosed) {
    common::configuration::InMemoryConfigurationSource empty_source;
    common::configuration::ValidationResult errors;

    auto config = AuditConfig::load(empty_source, errors);

    EXPECT_FALSE(errors.is_valid());
    EXPECT_TRUE(errors.has_errors());
}

TEST(AuditConfigTest, PortBoundaryValidation) {
    {
        auto source = create_valid_base_source();
        source.set("SECURECLOUD_AUDIT_GRPC_PORT", "0");
        common::configuration::ValidationResult errors;
        AuditConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        auto source = create_valid_base_source();
        source.set("SECURECLOUD_AUDIT_GRPC_PORT", "65536");
        common::configuration::ValidationResult errors;
        AuditConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(AuditConfigTest, ReservedPortProhibition) {
    {
        auto source = create_valid_base_source();
        source.set("SECURECLOUD_AUDIT_DB_PORT", "5432");
        common::configuration::ValidationResult errors;
        AuditConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        auto source = create_valid_base_source();
        source.set("SECURECLOUD_AUDIT_DB_PORT", "5433");
        common::configuration::ValidationResult errors;
        AuditConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(AuditConfigTest, IngestionWorkerBounds) {
    {
        auto source = create_valid_base_source();
        source.set("SECURECLOUD_AUDIT_INGESTION_WORKERS", "0");
        common::configuration::ValidationResult errors;
        AuditConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        auto source = create_valid_base_source();
        source.set("SECURECLOUD_AUDIT_INGESTION_WORKERS", "65");
        common::configuration::ValidationResult errors;
        AuditConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        auto source = create_valid_base_source();
        source.set("SECURECLOUD_AUDIT_INGESTION_WORKERS", "8");
        common::configuration::ValidationResult errors;
        AuditConfig::load(source, errors);
        EXPECT_TRUE(errors.is_valid());
    }
}

TEST(AuditConfigTest, BatchSizeAndQueueBounds) {
    auto source = create_valid_base_source();
    source.set("SECURECLOUD_AUDIT_BATCH_SIZE", "2000");
    source.set("SECURECLOUD_AUDIT_MAX_QUEUED_EVENTS", "1000");
    common::configuration::ValidationResult errors;

    AuditConfig::load(source, errors);

    EXPECT_FALSE(errors.is_valid());
}

TEST(AuditConfigTest, QueryLimitsValidation) {
    auto source = create_valid_base_source();
    source.set("SECURECLOUD_AUDIT_DEFAULT_PAGE_LIMIT", "200");
    source.set("SECURECLOUD_AUDIT_MAX_PAGE_LIMIT", "100");
    common::configuration::ValidationResult errors;

    AuditConfig::load(source, errors);

    EXPECT_FALSE(errors.is_valid());
}

TEST(AuditConfigTest, SecretRedactionVerification) {
    auto source = create_valid_base_source();
    common::configuration::ValidationResult errors;

    auto config = AuditConfig::load(source, errors);
    EXPECT_TRUE(errors.is_valid());

    EXPECT_EQ(config.clickhouse.password.expose_unredacted_secret(), "SuperSecretPassword123!");

    std::ostringstream oss;
    oss << config.clickhouse.password;
    std::string redacted_output = oss.str();

    EXPECT_EQ(redacted_output.find("SuperSecretPassword123!"), std::string::npos);
    EXPECT_NE(redacted_output.find("[REDACTED]"), std::string::npos);
}

} // namespace securecloud::audit::test