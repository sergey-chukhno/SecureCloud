#include "securecloud/configuration/common_service_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <gtest/gtest.h>

namespace securecloud::common::configuration {

namespace {

constexpr uint16_t k_default_gateway_port = 50051;
constexpr uint16_t k_default_auth_port = 50052;
constexpr uint16_t k_default_messaging_port = 50053;
constexpr uint16_t k_override_auth_port = 55555;
constexpr uint16_t k_global_fallback_port = 44444;

constexpr uint64_t k_expected_timeout_ms = 5000;
constexpr uint64_t k_custom_timeout_ms = 2500;

} // namespace

TEST(CommonServiceConfigTest, LoadsDefaultsSuccessfully) {
    InMemoryConfigurationSource source;
    ValidationResult errors;

    auto config = CommonServiceConfig::load(source, "auth", "Auth Service", k_default_auth_port, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.service_name, "auth");
    EXPECT_EQ(config.service_display_name, "Auth Service");
    EXPECT_EQ(config.grpc_host, "0.0.0.0");
    EXPECT_EQ(config.grpc_port, k_default_auth_port);
    EXPECT_EQ(config.listen_address(), "0.0.0.0:50052");
    EXPECT_EQ(config.tls_credentials.ca_cert_path, "/etc/securecloud/certs/ca.crt");
    EXPECT_EQ(config.tls_credentials.service_cert_path, "/etc/securecloud/certs/service.crt");
    EXPECT_EQ(config.tls_credentials.service_key_path, "/etc/securecloud/certs/service.key");
    EXPECT_EQ(config.shutdown_timeout.count(), k_expected_timeout_ms);
}

TEST(CommonServiceConfigTest, AppliesServiceSpecificOverrideOverGlobalFallback) {
    InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUTH_GRPC_PORT", "55555");
    source.set("SECURECLOUD_GRPC_PORT", "44444");
    source.set("SECURECLOUD_AUTH_GRPC_HOST", "127.0.0.1");
    source.set("SECURECLOUD_GRPC_HOST", "0.0.0.0");

    ValidationResult errors;
    auto config = CommonServiceConfig::load(source, "auth", "Auth Service", k_default_auth_port, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.grpc_port, k_override_auth_port);
    EXPECT_EQ(config.grpc_host, "127.0.0.1");
    EXPECT_EQ(config.listen_address(), "127.0.0.1:55555");
}

TEST(CommonServiceConfigTest, AppliesTransitionalGlobalFallbackWhenServiceOverrideAbsent) {
    InMemoryConfigurationSource source;
    source.set("SECURECLOUD_GRPC_PORT", "44444");
    source.set("SECURECLOUD_GRPC_HOST", "10.0.0.1");

    ValidationResult errors;
    auto config = CommonServiceConfig::load(source, "auth", "Auth Service", k_default_auth_port, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.grpc_port, k_global_fallback_port);
    EXPECT_EQ(config.grpc_host, "10.0.0.1");
    EXPECT_EQ(config.listen_address(), "10.0.0.1:44444");
}

TEST(CommonServiceConfigTest, FailsClosedOnMalformedPort) {
    InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUTH_GRPC_PORT", "99999");

    ValidationResult errors;
    auto config = CommonServiceConfig::load(source, "auth", "Auth Service", k_default_auth_port, errors);

    EXPECT_TRUE(errors.has_errors());
    EXPECT_EQ(errors.errors().size(), 1);
    EXPECT_NE(errors.to_string().find("SECURECLOUD_AUTH_GRPC_PORT"), std::string::npos);
}

TEST(CommonServiceConfigTest, FailsClosedOnEmptyCertificatePath) {
    InMemoryConfigurationSource source;
    source.set("SECURECLOUD_CA_CERT_PATH", "");

    ValidationResult errors;
    auto config = CommonServiceConfig::load(source, "auth", "Auth Service", k_default_auth_port, errors);

    EXPECT_TRUE(errors.has_errors());
    EXPECT_EQ(errors.errors().size(), 1);
    EXPECT_NE(errors.to_string().find("SECURECLOUD_CA_CERT_PATH"), std::string::npos);
}

TEST(CommonServiceConfigTest, AppliesExplicitTlsAndTimeoutOverrides) {
    InMemoryConfigurationSource source;
    source.set("SECURECLOUD_CA_CERT_PATH", "/custom/ca.crt");
    source.set("SECURECLOUD_SERVICE_CERT_PATH", "/custom/svc.crt");
    source.set("SECURECLOUD_SERVICE_KEY_PATH", "/custom/svc.key");
    source.set("SECURECLOUD_SHUTDOWN_TIMEOUT_MS", "2500");

    ValidationResult errors;
    auto config = CommonServiceConfig::load(source, "messaging", "Messaging Service", k_default_messaging_port, errors);

    EXPECT_TRUE(errors.is_valid());
    EXPECT_EQ(config.tls_credentials.ca_cert_path, "/custom/ca.crt");
    EXPECT_EQ(config.tls_credentials.service_cert_path, "/custom/svc.crt");
    EXPECT_EQ(config.tls_credentials.service_key_path, "/custom/svc.key");
    EXPECT_EQ(config.shutdown_timeout.count(), k_custom_timeout_ms);
}

TEST(CommonServiceConfigTest, Maintains100PercentIsolationWithInMemorySource) {
    InMemoryConfigurationSource source1;
    source1.set("SECURECLOUD_GATEWAY_GRPC_PORT", "50051");

    InMemoryConfigurationSource source2;
    source2.set("SECURECLOUD_AUTH_GRPC_PORT", "50052");

    ValidationResult errors1;
    ValidationResult errors2;

    auto config1 = CommonServiceConfig::load(source1, "gateway", "Gateway Service", k_default_gateway_port, errors1);
    auto config2 = CommonServiceConfig::load(source2, "auth", "Auth Service", k_default_auth_port, errors2);

    EXPECT_TRUE(errors1.is_valid());
    EXPECT_TRUE(errors2.is_valid());
    EXPECT_EQ(config1.grpc_port, k_default_gateway_port);
    EXPECT_EQ(config2.grpc_port, k_default_auth_port);
}

} // namespace securecloud::common::configuration
