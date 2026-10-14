#include "messaging_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <gtest/gtest.h>

namespace securecloud::messaging {
namespace {

TEST(MessagingConfigTest, DefaultConfigurationValues) {
    common::configuration::InMemoryConfigurationSource source;
    common::configuration::ValidationResult errors;
    auto config = MessagingConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_EQ(config.common.service_name, "messaging");
    EXPECT_EQ(config.common.grpc_port, 50053);

    // Scylla defaults
    EXPECT_EQ(config.scylla.host, "scylladb");
    EXPECT_EQ(config.scylla.port, 9042);
    EXPECT_EQ(config.scylla.keyspace, "securecloud_messaging");
    EXPECT_EQ(config.scylla.connect_timeout_ms, 5000);
    EXPECT_EQ(config.scylla.request_timeout_ms, 2000);
    EXPECT_EQ(config.scylla.connection_pool_size, 16);

    // Worker defaults (ADR-009, ADR-010)
    EXPECT_EQ(config.workers.submission_workers, 8);
    EXPECT_EQ(config.workers.delivery_workers, 16);
    EXPECT_EQ(config.workers.sync_workers, 8);
    EXPECT_EQ(config.workers.max_queued_submissions, 1024);
    EXPECT_EQ(config.workers.max_queued_deliveries, 4096);
    EXPECT_EQ(config.workers.max_queued_syncs, 1024);

    // Shutdown grace period
    EXPECT_EQ(config.shutdown_grace_period_ms, 10000);

    // Direct compatibility fields
    EXPECT_EQ(config.scylla_host, "scylladb");
    EXPECT_EQ(config.scylla_port, 9042);
    EXPECT_EQ(config.scylla_keyspace, "securecloud_messaging");
}

TEST(MessagingConfigTest, EnvironmentVariableOverrides) {
    common::configuration::InMemoryConfigurationSource source({
        {"SECURECLOUD_MESSAGING_SCYLLA_HOST", "scylla-cluster.internal"},
        {"SECURECLOUD_MESSAGING_SCYLLA_PORT", "9043"},
        {"SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE", "sc_msg_prod"},
        {"SECURECLOUD_MESSAGING_SCYLLA_CONNECT_TIMEOUT_MS", "3000"},
        {"SECURECLOUD_MESSAGING_SCYLLA_REQUEST_TIMEOUT_MS", "1500"},
        {"SECURECLOUD_MESSAGING_SCYLLA_CONNECTION_POOL_SIZE", "32"},
        {"SECURECLOUD_MESSAGING_SUBMISSION_WORKERS", "12"},
        {"SECURECLOUD_MESSAGING_DELIVERY_WORKERS", "32"},
        {"SECURECLOUD_MESSAGING_SYNC_WORKERS", "16"},
        {"SECURECLOUD_MESSAGING_MAX_QUEUED_SUBMISSIONS", "2048"},
        {"SECURECLOUD_MESSAGING_MAX_QUEUED_DELIVERIES", "8192"},
        {"SECURECLOUD_MESSAGING_MAX_QUEUED_SYNCS", "2048"},
        {"SECURECLOUD_MESSAGING_SHUTDOWN_GRACE_PERIOD_MS", "5000"},
    });

    common::configuration::ValidationResult errors;
    auto config = MessagingConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_EQ(config.scylla.host, "scylla-cluster.internal");
    EXPECT_EQ(config.scylla.port, 9043);
    EXPECT_EQ(config.scylla.keyspace, "sc_msg_prod");
    EXPECT_EQ(config.scylla.connect_timeout_ms, 3000);
    EXPECT_EQ(config.scylla.request_timeout_ms, 1500);
    EXPECT_EQ(config.scylla.connection_pool_size, 32);

    EXPECT_EQ(config.workers.submission_workers, 12);
    EXPECT_EQ(config.workers.delivery_workers, 32);
    EXPECT_EQ(config.workers.sync_workers, 16);
    EXPECT_EQ(config.workers.max_queued_submissions, 2048);
    EXPECT_EQ(config.workers.max_queued_deliveries, 8192);
    EXPECT_EQ(config.workers.max_queued_syncs, 2048);

    EXPECT_EQ(config.shutdown_grace_period_ms, 5000);

    // Verify compatibility sync
    EXPECT_EQ(config.scylla_host, "scylla-cluster.internal");
    EXPECT_EQ(config.scylla_port, 9043);
    EXPECT_EQ(config.scylla_keyspace, "sc_msg_prod");
}

TEST(MessagingConfigTest, InvalidScyllaPortValidation) {
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SCYLLA_PORT", "0"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SCYLLA_PORT", "70000"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(MessagingConfigTest, EmptyScyllaHostOrKeyspaceRejected) {
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SCYLLA_HOST", ""},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE", ""},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(MessagingConfigTest, InvalidWorkerBoundsValidation) {
    // Submission workers out of range [1, 128]
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SUBMISSION_WORKERS", "0"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SUBMISSION_WORKERS", "129"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    // Delivery workers out of range [1, 256]
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_DELIVERY_WORKERS", "0"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_DELIVERY_WORKERS", "300"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    // Sync workers out of range [1, 128]
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SYNC_WORKERS", "0"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SYNC_WORKERS", "200"},
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(MessagingConfigTest, InvalidQueueCapacityValidation) {
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_MAX_QUEUED_SUBMISSIONS", "10"}, // below 16
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_MAX_QUEUED_DELIVERIES", "100000"}, // above 65536
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(MessagingConfigTest, InvalidTimeoutAndGracePeriodValidation) {
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SCYLLA_CONNECT_TIMEOUT_MS", "50"}, // below 100
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_MESSAGING_SHUTDOWN_GRACE_PERIOD_MS", "100"}, // below 500
        });
        common::configuration::ValidationResult errors;
        MessagingConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(MessagingConfigTest, NonNumericInputsRejected) {
    common::configuration::InMemoryConfigurationSource source({
        {"SECURECLOUD_MESSAGING_DELIVERY_WORKERS", "not_a_number"},
    });
    common::configuration::ValidationResult errors;
    MessagingConfig::load(source, errors);
    EXPECT_FALSE(errors.is_valid());
}

TEST(MessagingConfigTest, IsolationFromOtherServicesDatabaseVariables) {
    // Supplying Auth PostgreSQL or Files MinIO variables does not affect or pollute MessagingConfig
    common::configuration::InMemoryConfigurationSource source({
        {"SECURECLOUD_AUTH_DB_HOST", "postgres.malicious"},
        {"SECURECLOUD_AUTH_DB_PORT", "5432"},
        {"SECURECLOUD_AUTH_DB_PASSWORD", "super_secret"},
        {"SECURECLOUD_FILES_S3_KEY", "minioadmin"},
    });
    common::configuration::ValidationResult errors;
    auto config = MessagingConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.scylla.host, "scylladb");
    EXPECT_EQ(config.scylla.port, 9042);
}

} // namespace
} // namespace securecloud::messaging
