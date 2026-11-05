#include "application/client_config.hpp"

#include <cstdlib>
#include <gtest/gtest.h>

namespace {

using namespace securecloud::client::application;

#if defined(_WIN32)
void set_env(const char* name, const char* value) {
    _putenv_s(name, value);
}
void unset_env(const char* name) {
    _putenv_s(name, "");
}
#else
void set_env(const char* name, const char* value) {
    setenv(name, value, 1);
}
void unset_env(const char* name) {
    unsetenv(name);
}
#endif

TEST(ClientConfigTest, DefaultConfigurationIsValid) {
    const auto config = ClientConfig::create_default();
    EXPECT_TRUE(config.is_valid());
    EXPECT_TRUE(config.validate().empty());
    EXPECT_EQ(config.gateway_url, "https://127.0.0.1");
    EXPECT_EQ(config.gateway_port, 8443);
    EXPECT_EQ(config.connect_timeout_ms.count(), 5000);
    EXPECT_EQ(config.request_timeout_ms.count(), 15000);
    EXPECT_EQ(config.keychain_service_id, "securecloud.desktop");
    EXPECT_EQ(config.heartbeat_interval_ms.count(), 30000);
    EXPECT_EQ(config.sync_poll_interval_ms.count(), 5000);
    EXPECT_EQ(config.max_retry_attempts, 3);
    EXPECT_TRUE(config.auth_token.empty());
}

TEST(ClientConfigTest, ValidationFailsOnInvalidGatewayUrl) {
    auto config = ClientConfig::create_default();

    config.gateway_url = "";
    EXPECT_FALSE(config.is_valid());
    auto errors = config.validate();
    EXPECT_FALSE(errors.empty());

    config.gateway_url = "ftp://invalid.host";
    EXPECT_FALSE(config.is_valid());
    errors = config.validate();
    EXPECT_FALSE(errors.empty());

    config.gateway_url = "http://localhost";
    EXPECT_TRUE(config.is_valid());

    config.gateway_url = "https://gateway.securecloud.internal";
    EXPECT_TRUE(config.is_valid());
}

TEST(ClientConfigTest, ValidationFailsOnZeroPort) {
    auto config = ClientConfig::create_default();
    config.gateway_port = 0;
    EXPECT_FALSE(config.is_valid());
    const auto errors = config.validate();
    ASSERT_EQ(errors.size(), 1u);
    EXPECT_NE(errors[0].find("gateway_port"), std::string::npos);
}

TEST(ClientConfigTest, ValidationFailsOnInvalidTimeouts) {
    auto config = ClientConfig::create_default();

    config.connect_timeout_ms = std::chrono::milliseconds(0);
    EXPECT_FALSE(config.is_valid());

    config.connect_timeout_ms = std::chrono::milliseconds(10000);
    config.request_timeout_ms = std::chrono::milliseconds(5000); // request < connect
    EXPECT_FALSE(config.is_valid());
    const auto errors = config.validate();
    EXPECT_FALSE(errors.empty());
}

TEST(ClientConfigTest, ValidationFailsOnZeroHeartbeatOrSync) {
    auto config = ClientConfig::create_default();
    config.heartbeat_interval_ms = std::chrono::milliseconds(0);
    EXPECT_FALSE(config.is_valid());

    config = ClientConfig::create_default();
    config.sync_poll_interval_ms = std::chrono::milliseconds(0);
    EXPECT_FALSE(config.is_valid());

    config = ClientConfig::create_default();
    config.max_retry_attempts = 0;
    EXPECT_FALSE(config.is_valid());
}

TEST(ClientConfigTest, ValidationFailsOnEmptyKeychainService) {
    auto config = ClientConfig::create_default();
    config.keychain_service_id = "";
    EXPECT_FALSE(config.is_valid());
}

TEST(ClientConfigTest, EnvironmentOverrides) {
    set_env("SECURECLOUD_GATEWAY_URL", "https://prod.securecloud.com");
    set_env("SECURECLOUD_GATEWAY_PORT", "9443");
    set_env("SECURECLOUD_CONNECT_TIMEOUT_MS", "8000");
    set_env("SECURECLOUD_REQUEST_TIMEOUT_MS", "20000");
    set_env("SECURECLOUD_DATABASE_PATH", "/var/data/securecloud.db");
    set_env("SECURECLOUD_KEYCHAIN_SERVICE_ID", "custom.keychain");
    set_env("SECURECLOUD_HEARTBEAT_INTERVAL_MS", "45000");
    set_env("SECURECLOUD_SYNC_POLL_INTERVAL_MS", "10000");
    set_env("SECURECLOUD_MAX_RETRY_ATTEMPTS", "5");
    set_env("SECURECLOUD_AUTH_TOKEN", "super-secret-jwt-token-123");

    const auto config = ClientConfig::from_environment();
    EXPECT_TRUE(config.is_valid());
    EXPECT_EQ(config.gateway_url, "https://prod.securecloud.com");
    EXPECT_EQ(config.gateway_port, 9443);
    EXPECT_EQ(config.connect_timeout_ms.count(), 8000);
    EXPECT_EQ(config.request_timeout_ms.count(), 20000);
    EXPECT_EQ(config.database_path, "/var/data/securecloud.db");
    EXPECT_EQ(config.keychain_service_id, "custom.keychain");
    EXPECT_EQ(config.heartbeat_interval_ms.count(), 45000);
    EXPECT_EQ(config.sync_poll_interval_ms.count(), 10000);
    EXPECT_EQ(config.max_retry_attempts, 5);
    EXPECT_FALSE(config.auth_token.empty());
    EXPECT_EQ(config.auth_token.expose_unredacted_secret(), "super-secret-jwt-token-123");

    // Clean up environment variables
    unset_env("SECURECLOUD_GATEWAY_URL");
    unset_env("SECURECLOUD_GATEWAY_PORT");
    unset_env("SECURECLOUD_CONNECT_TIMEOUT_MS");
    unset_env("SECURECLOUD_REQUEST_TIMEOUT_MS");
    unset_env("SECURECLOUD_DATABASE_PATH");
    unset_env("SECURECLOUD_KEYCHAIN_SERVICE_ID");
    unset_env("SECURECLOUD_HEARTBEAT_INTERVAL_MS");
    unset_env("SECURECLOUD_SYNC_POLL_INTERVAL_MS");
    unset_env("SECURECLOUD_MAX_RETRY_ATTEMPTS");
    unset_env("SECURECLOUD_AUTH_TOKEN");
}

TEST(ClientConfigTest, ToSafeStringRedactsSecretToken) {
    auto config = ClientConfig::create_default();
    config.auth_token = securecloud::common::configuration::SecretString("sensitive-token-xyz");

    const std::string safe_str = config.to_safe_string();
    EXPECT_NE(safe_str.find("[REDACTED]"), std::string::npos);
    EXPECT_EQ(safe_str.find("sensitive-token-xyz"), std::string::npos);
}

} // namespace
