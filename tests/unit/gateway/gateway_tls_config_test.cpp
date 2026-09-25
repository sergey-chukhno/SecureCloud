#include "gateway_config.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

namespace securecloud::gateway {
namespace {

constexpr uint16_t k_expected_default_https_port = 8443;
constexpr const char* k_expected_default_cert_path = "/etc/securecloud/certs/gateway/gateway.crt";
constexpr const char* k_expected_default_key_path = "/etc/securecloud/certs/gateway/gateway.key";
constexpr const char* k_expected_default_ca_path = "/etc/securecloud/certs/ca/ca.crt";
constexpr const char* k_expected_default_tls_version = "TLSv1.3";

constexpr size_t k_expected_default_max_header_bytes = 16384;  // 16 KB
constexpr size_t k_expected_default_max_body_bytes = 10485760; // 10 MB
constexpr uint32_t k_expected_default_read_timeout_ms = 5000;
constexpr uint32_t k_expected_default_write_timeout_ms = 5000;
constexpr uint32_t k_expected_default_idle_timeout_ms = 30000;
constexpr size_t k_expected_default_max_connections = 1024;

TEST(GatewayTlsConfigTest, DefaultValuesAreSound) {
    common::configuration::InMemoryConfigurationSource source;
    common::configuration::ValidationResult errors;

    auto config = GatewayConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();

    // Verify TLS defaults
    EXPECT_TRUE(config.tls.enabled);
    EXPECT_EQ(config.tls.cert_path, k_expected_default_cert_path);
    EXPECT_EQ(config.tls.key_path, k_expected_default_key_path);
    EXPECT_EQ(config.tls.ca_chain_path, k_expected_default_ca_path);
    EXPECT_EQ(config.tls.https_listen_port, k_expected_default_https_port);
    EXPECT_EQ(config.tls.min_tls_version, k_expected_default_tls_version);
    EXPECT_NE(config.tls.cipher_suites.find("TLS_AES_256_GCM_SHA384"), std::string::npos);
    EXPECT_EQ(config.https_listen_endpoint(), "127.0.0.1:8443");

    // Verify Resource Limit defaults
    EXPECT_EQ(config.limits.max_header_bytes, k_expected_default_max_header_bytes);
    EXPECT_EQ(config.limits.max_body_bytes, k_expected_default_max_body_bytes);
    EXPECT_EQ(config.max_payload_bytes, k_expected_default_max_body_bytes);
    EXPECT_EQ(config.limits.read_timeout_ms, k_expected_default_read_timeout_ms);
    EXPECT_EQ(config.limits.write_timeout_ms, k_expected_default_write_timeout_ms);
    EXPECT_EQ(config.limits.idle_timeout_ms, k_expected_default_idle_timeout_ms);
    EXPECT_EQ(config.limits.max_concurrent_connections, k_expected_default_max_connections);
}

TEST(GatewayTlsConfigTest, LoadsValidConfigurationFromSource) {
    common::configuration::InMemoryConfigurationSource source({
        {"SECURECLOUD_GATEWAY_TLS_ENABLED", "true"},
        {"SECURECLOUD_GATEWAY_TLS_CERT_PATH", "/custom/certs/gw.crt"},
        {"SECURECLOUD_GATEWAY_TLS_KEY_PATH", "/custom/certs/gw.key"},
        {"SECURECLOUD_GATEWAY_TLS_CA_PATH", "/custom/certs/ca.crt"},
        {"SECURECLOUD_GATEWAY_HTTPS_PORT", "9443"},
        {"SECURECLOUD_GATEWAY_MIN_TLS_VERSION", "TLSv1.3"},
        {"SECURECLOUD_GATEWAY_TLS_CIPHER_SUITES", "TLS_AES_256_GCM_SHA384"},
        {"SECURECLOUD_GATEWAY_MAX_HEADER_BYTES", "32768"},
        {"SECURECLOUD_GATEWAY_MAX_BODY_BYTES", "20971520"},
        {"SECURECLOUD_GATEWAY_READ_TIMEOUT_MS", "8000"},
        {"SECURECLOUD_GATEWAY_WRITE_TIMEOUT_MS", "8000"},
        {"SECURECLOUD_GATEWAY_IDLE_TIMEOUT_MS", "45000"},
        {"SECURECLOUD_GATEWAY_MAX_CONNECTIONS", "2048"},
    });
    common::configuration::ValidationResult errors;

    auto config = GatewayConfig::load(source, errors);

    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_TRUE(config.tls.enabled);
    EXPECT_EQ(config.tls.cert_path, "/custom/certs/gw.crt");
    EXPECT_EQ(config.tls.key_path, "/custom/certs/gw.key");
    EXPECT_EQ(config.tls.ca_chain_path, "/custom/certs/ca.crt");
    EXPECT_EQ(config.tls.https_listen_port, 9443);
    EXPECT_EQ(config.tls.min_tls_version, "TLSv1.3");
    EXPECT_EQ(config.tls.cipher_suites, "TLS_AES_256_GCM_SHA384");
    EXPECT_EQ(config.https_listen_endpoint(), "127.0.0.1:9443");

    EXPECT_EQ(config.limits.max_header_bytes, 32768U);
    EXPECT_EQ(config.limits.max_body_bytes, 20971520U);
    EXPECT_EQ(config.max_payload_bytes, 20971520U);
    EXPECT_EQ(config.limits.read_timeout_ms, 8000U);
    EXPECT_EQ(config.limits.write_timeout_ms, 8000U);
    EXPECT_EQ(config.limits.idle_timeout_ms, 45000U);
    EXPECT_EQ(config.limits.max_concurrent_connections, 2048U);
}

TEST(GatewayTlsConfigTest, RejectsInsecureTlsVersionDowngrade) {
    const std::vector<std::string> insecure_versions = {"TLSv1.0", "TLSv1.1", "TLSv1.2", "SSLv3", "TLSv2.0"};

    for (const auto& ver : insecure_versions) {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_MIN_TLS_VERSION", ver}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid()) << "Should reject version: " << ver;
    }
}

TEST(GatewayTlsConfigTest, RejectsEmptyCertificateAndKeyPaths) {
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_TLS_CERT_PATH", ""}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_TLS_KEY_PATH", ""}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayTlsConfigTest, ValidatesFileExistenceWhenRequested) {
    // 1. Non-existent path fails when validate_file_paths = true
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_GATEWAY_TLS_CERT_PATH", "/nonexistent/test/path/cert.crt"},
            {"SECURECLOUD_GATEWAY_TLS_KEY_PATH", "/nonexistent/test/path/key.key"},
        });
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors, true);
        EXPECT_FALSE(errors.is_valid());
    }

    // 2. Existing temporary files pass validation
    {
        auto temp_dir = std::filesystem::temp_directory_path() / "securecloud_tls_test";
        std::filesystem::create_directories(temp_dir);
        auto test_cert = temp_dir / "test.crt";
        auto test_key = temp_dir / "test.key";
        auto test_ca = temp_dir / "ca.crt";

        {
            std::ofstream(test_cert) << "dummy cert";
            std::ofstream(test_key) << "dummy key";
            std::ofstream(test_ca) << "dummy ca";
        }

        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_GATEWAY_TLS_CERT_PATH", test_cert.string()},
            {"SECURECLOUD_GATEWAY_TLS_KEY_PATH", test_key.string()},
            {"SECURECLOUD_GATEWAY_TLS_CA_PATH", test_ca.string()},
        });
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors, true);
        EXPECT_TRUE(errors.is_valid()) << errors.to_string();

        std::filesystem::remove_all(temp_dir);
    }
}

TEST(GatewayTlsConfigTest, RejectsConflictingPorts) {
    // HTTPS port conflicts with HTTP port (8080)
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_GATEWAY_HTTP_PORT", "8080"},
            {"SECURECLOUD_GATEWAY_HTTPS_PORT", "8080"},
        });
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // HTTPS port conflicts with gRPC service port (50051)
    {
        common::configuration::InMemoryConfigurationSource source({
            {"SECURECLOUD_GATEWAY_GRPC_PORT", "50051"},
            {"SECURECLOUD_GATEWAY_HTTPS_PORT", "50051"},
        });
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayTlsConfigTest, RejectsOutOfBoundsHeaderLimits) {
    // Header too small (< 1024 bytes)
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_MAX_HEADER_BYTES", "512"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Header too large (> 65536 bytes)
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_MAX_HEADER_BYTES", "70000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayTlsConfigTest, RejectsOutOfBoundsBodyLimits) {
    // Body too small (< 1024 bytes)
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_MAX_BODY_BYTES", "512"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Body too large (> 100 MB)
    {
        common::configuration::InMemoryConfigurationSource source(
            {{"SECURECLOUD_GATEWAY_MAX_BODY_BYTES", "200000000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayTlsConfigTest, RejectsOutOfBoundsTimeouts) {
    // Read timeout out of bounds
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_READ_TIMEOUT_MS", "50"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_READ_TIMEOUT_MS", "70000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Write timeout out of bounds
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_WRITE_TIMEOUT_MS", "50"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_WRITE_TIMEOUT_MS", "70000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // Idle timeout out of bounds
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_IDLE_TIMEOUT_MS", "50"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_IDLE_TIMEOUT_MS", "400000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayTlsConfigTest, RejectsOutOfBoundsConcurrentConnections) {
    // 0 connections invalid
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_MAX_CONNECTIONS", "0"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }

    // > 65536 connections invalid
    {
        common::configuration::InMemoryConfigurationSource source({{"SECURECLOUD_GATEWAY_MAX_CONNECTIONS", "70000"}});
        common::configuration::ValidationResult errors;
        auto config = GatewayConfig::load(source, errors);
        EXPECT_FALSE(errors.is_valid());
    }
}

TEST(GatewayTlsConfigTest, DisabledTlsAllowsEmptyCertificatePaths) {
    common::configuration::InMemoryConfigurationSource source({
        {"SECURECLOUD_GATEWAY_TLS_ENABLED", "false"},
        {"SECURECLOUD_GATEWAY_TLS_CERT_PATH", ""},
        {"SECURECLOUD_GATEWAY_TLS_KEY_PATH", ""},
    });
    common::configuration::ValidationResult errors;
    auto config = GatewayConfig::load(source, errors);
    EXPECT_TRUE(errors.is_valid()) << errors.to_string();
    EXPECT_FALSE(config.tls.enabled);
}

} // namespace
} // namespace securecloud::gateway
