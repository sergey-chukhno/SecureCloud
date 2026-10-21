#include "audit_server.hpp"
#include "securecloud/configuration/configuration_source.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::test {

namespace {

AuditConfig create_valid_config() {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "ValidSecret123!");
    common::configuration::ValidationResult errors;
    return AuditConfig::load(source, errors);
}

} // namespace

TEST(AuditServerLifecycleTest, InitialStateIsConfigured) {
    AuditConfig config = create_valid_config();
    AuditServer server(std::move(config));

    EXPECT_EQ(server.state(), ServiceState::Configured);
    EXPECT_FALSE(server.is_healthy());
}

TEST(AuditServerLifecycleTest, GracefulStopIdempotency) {
    AuditConfig config = create_valid_config();
    AuditServer server(std::move(config));

    EXPECT_NO_THROW(server.stop());
    EXPECT_NE(server.state(), ServiceState::Running);

    // Repeated stop invocations must be safe and idempotent
    EXPECT_NO_THROW(server.stop());
}

TEST(AuditServerLifecycleTest, FailedStartTransitionsToFailedState) {
    AuditConfig config = create_valid_config();
    // Intentionally assign non-existent TLS certificate paths to trigger deterministic failure during credential
    // loading
    config.common.tls_credentials.ca_cert_path = "non_existent_ca.crt";
    config.common.tls_credentials.service_cert_path = "non_existent_service.crt";
    config.common.tls_credentials.service_key_path = "non_existent_service.key";

    AuditServer server(std::move(config));

    EXPECT_FALSE(server.start());
    EXPECT_EQ(server.state(), ServiceState::Failed);
    EXPECT_FALSE(server.is_healthy());
}

} // namespace securecloud::audit::test
