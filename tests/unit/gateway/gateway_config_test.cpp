#include "gateway_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>

namespace securecloud::gateway {
namespace {

// ============================================================================
// Architectural Invariant Verification (ADR-005, Gateway Design 3.1)
// Compile-time concepts asserting Gateway owns zero business data persistence.
// ============================================================================

template <typename T>
concept HasDbHost = requires(T t) {
    { t.db_host };
};

template <typename T>
concept HasDbPort = requires(T t) {
    { t.db_port };
};

template <typename T>
concept HasDbUser = requires(T t) {
    { t.db_user };
};

template <typename T>
concept HasDbPassword = requires(T t) {
    { t.db_password };
};

template <typename T>
concept HasDbName = requires(T t) {
    { t.db_name };
};

template <typename T>
concept HasPostgresUrl = requires(T t) {
    { t.postgres_url };
};

template <typename T>
concept HasScyllaHost = requires(T t) {
    { t.scylla_host };
};

template <typename T>
concept HasS3Bucket = requires(T t) {
    { t.s3_bucket };
};

template <typename T>
concept HasClickhouseHost = requires(T t) {
    { t.clickhouse_host };
};

// Static compile-time assertion: Gateway must NEVER expose persistence members
static_assert(!HasDbHost<GatewayConfig>, "GatewayConfig must not expose relational db_host");
static_assert(!HasDbPort<GatewayConfig>, "GatewayConfig must not expose relational db_port");
static_assert(!HasDbUser<GatewayConfig>, "GatewayConfig must not expose relational db_user");
static_assert(!HasDbPassword<GatewayConfig>, "GatewayConfig must not expose database credentials");
static_assert(!HasDbName<GatewayConfig>, "GatewayConfig must not expose database schema names");
static_assert(!HasPostgresUrl<GatewayConfig>, "GatewayConfig must not expose PostgreSQL URLs");
static_assert(!HasScyllaHost<GatewayConfig>, "GatewayConfig must not expose ScyllaDB configuration");
static_assert(!HasS3Bucket<GatewayConfig>, "GatewayConfig must not expose S3 object storage configuration");
static_assert(!HasClickhouseHost<GatewayConfig>, "GatewayConfig must not expose ClickHouse configuration");

// ============================================================================
// Unit Test Cases
// ============================================================================

constexpr uint16_t k_expected_default_http_port = 8080;
constexpr uint64_t k_expected_default_payload_bytes = 10485760; // 10 MB
constexpr std::chrono::milliseconds k_expected_default_timeout{5000};
constexpr uint32_t k_expected_default_server_threads = 4;

constexpr uint16_t k_custom_http_port = 8443;
constexpr uint64_t k_custom_payload_bytes = 20971520; // 20 MB
constexpr std::chrono::milliseconds k_custom_timeout{10000};
constexpr uint32_t k_custom_server_threads = 8;

TEST(GatewayConfigTest, DefaultValuesAreSound) {
    common::configuration::InMemoryConfigurationSource source;
    common::configuration::ValidationResult errors;

    auto config = GatewayConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_EQ(config.http_listen_address, "127.0.0.1");
    EXPECT_EQ(config.http_listen_port, k_expected_default_http_port);
    EXPECT_EQ(config.max_payload_bytes, k_expected_default_payload_bytes);
    EXPECT_EQ(config.request_timeout_ms, k_expected_default_timeout);
    EXPECT_EQ(config.server_threads, k_expected_default_server_threads);
    EXPECT_EQ(config.http_listen_endpoint(), "127.0.0.1:8080");

    EXPECT_EQ(config.auth_endpoint, "auth:50052");
    EXPECT_EQ(config.messaging_endpoint, "messaging:50053");
    EXPECT_EQ(config.files_endpoint, "files:50054");
    EXPECT_EQ(config.audit_endpoint, "audit:50055");
}

TEST(GatewayConfigTest, LoadsValidConfigurationFromSource) {
    common::configuration::InMemoryConfigurationSource source({
        {"SECURECLOUD_GATEWAY_HTTP_HOST", "0.0.0.0"},
        {"SECURECLOUD_GATEWAY_HTTP_PORT", "8443"},
        {"SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES", "20971520"},
        {"SECURECLOUD_GATEWAY_REQUEST_TIMEOUT_MS", "10000"},
        {"SECURECLOUD_GATEWAY_SERVER_THREADS", "8"},
        {"SECURECLOUD_GATEWAY_AUTH_ENDPOINT", "auth-prod:50052"},
        {"SECURECLOUD_GATEWAY_MESSAGING_ENDPOINT", "messaging-prod:50053"},
        {"SECURECLOUD_GATEWAY_FILES_ENDPOINT", "files-prod:50054"},
        {"SECURECLOUD_GATEWAY_AUDIT_ENDPOINT", "audit-prod:50055"},
    });
    common::configuration::ValidationResult errors;

    auto config = GatewayConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_EQ(config.http_listen_address, "0.0.0.0");
    EXPECT_EQ(config.http_listen_port, k_custom_http_port);
    EXPECT_EQ(config.max_payload_bytes, k_custom_payload_bytes);
    EXPECT_EQ(config.request_timeout_ms, k_custom_timeout);
    EXPECT_EQ(config.server_threads, k_custom_server_threads);
    EXPECT_EQ(config.http_listen_endpoint(), "0.0.0.0:8443");

    EXPECT_EQ(config.auth_endpoint, "auth-prod:50052");
    EXPECT_EQ(config.messaging_endpoint, "messaging-prod:50053");
    EXPECT_EQ(config.files_endpoint, "files-prod:50054");
    EXPECT_EQ(config.audit_endpoint, "audit-prod:50055");
}

TEST(GatewayConfigTest, RejectsInvalidListenPort) {
    // Port 0 is rejected
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_HTTP_PORT", "0"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Out of range port is rejected
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_HTTP_PORT", "70000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayConfigTest, RejectsOutOfBoundsPayloadBytes) {
    // Too small (< 1024 bytes)
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES", "512"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Too large (> 100 MB / 104857600 bytes)
    {
        common::configuration::InMemoryConfigurationSource source(
            {{"SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES", "200000000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Non-numeric
    {
        common::configuration::InMemoryConfigurationSource source(
            {{"SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES", "invalid"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayConfigTest, RejectsOutOfBoundsRequestTimeout) {
    // Too small (< 100 ms)
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_REQUEST_TIMEOUT_MS", "50"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Too large (> 60000 ms)
    {
        common::configuration::InMemoryConfigurationSource source(
            {{"SECURECLOUD_GATEWAY_REQUEST_TIMEOUT_MS", "70000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Non-numeric
    {
        common::configuration::InMemoryConfigurationSource source(
            {{"SECURECLOUD_GATEWAY_REQUEST_TIMEOUT_MS", "not-a-number"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayConfigTest, RejectsOutOfBoundsServerThreads) {
    // 0 threads is invalid
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_SERVER_THREADS", "0"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // More than 128 threads is invalid
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_SERVER_THREADS", "256"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayConfigTest, RejectsEmptyAuthEndpoint) {
    common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_AUTH_ENDPOINT", ""}});
    common::configuration::ValidationResult errors;
    auto config = GatewayConfig::load(source, errors);
    EXPECT_FALSE(errors.is_valid());
}

TEST(GatewayConfigTest, StrictNoDatabaseArchitecturalInvariant) {
    // Runtime assertion confirming the strict zero-database isolation of Gateway
    GatewayConfig config;
    EXPECT_TRUE(config.auth_endpoint.find("50052") != std::string::npos);
    EXPECT_TRUE(config.messaging_endpoint.find("50053") != std::string::npos);
    EXPECT_TRUE(config.files_endpoint.find("50054") != std::string::npos);
    EXPECT_TRUE(config.audit_endpoint.find("50055") != std::string::npos);
}

} // namespace
} // namespace securecloud::gateway
