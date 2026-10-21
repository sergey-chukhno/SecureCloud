#include "audit_server.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

inline void ensure_integration_winsock() noexcept {
    static const bool initialized = []() noexcept {
        WSADATA wsa{};
        return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}
#else
inline void ensure_integration_winsock() noexcept {}
#endif

namespace securecloud::audit::test {

namespace {

constexpr uint16_t k_integration_test_port = 50055;
constexpr auto k_test_timeout = std::chrono::seconds(5);

std::filesystem::path find_pki_root() {
#ifdef SECURECLOUD_DEV_PKI_DIR
    std::filesystem::path defined_path(SECURECLOUD_DEV_PKI_DIR);
    if (std::filesystem::exists(defined_path / "ca" / "ca.crt")) {
        return defined_path;
    }
#endif
    auto curr = std::filesystem::current_path();
    while (!curr.empty() && curr != curr.root_path()) {
        if (std::filesystem::exists(curr / "deploy" / "dev-pki" / "ca" / "ca.crt")) {
            return curr / "deploy" / "dev-pki";
        }
        curr = curr.parent_path();
    }
    return "deploy/dev-pki";
}

AuditConfig create_integration_test_config(const std::filesystem::path& pki_root, uint16_t port,
                                           uint16_t clickhouse_port = 8123) {
    common::configuration::InMemoryConfigurationSource source;
    source.set("SECURECLOUD_AUDIT_GRPC_PORT", std::to_string(port));
    source.set("SECURECLOUD_AUDIT_GRPC_HOST", "127.0.0.1");
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "IntegrationTestPassword123!");
    source.set("SECURECLOUD_AUDIT_DB_PORT", std::to_string(clickhouse_port));
    source.set("SECURECLOUD_CA_CERT_PATH", (pki_root / "ca" / "ca.crt").string());
    source.set("SECURECLOUD_SERVICE_CERT_PATH", (pki_root / "services" / "audit" / "audit.crt").string());
    source.set("SECURECLOUD_SERVICE_KEY_PATH", (pki_root / "services" / "audit" / "audit.key").string());

    common::configuration::ValidationResult errors;
    auto config = AuditConfig::load(source, errors);
    if (!errors.is_valid()) {
        throw std::runtime_error("Failed to load test configuration: " + errors.to_string());
    }
    return config;
}

std::shared_ptr<grpc::Channel> create_mtls_channel(const std::filesystem::path& pki_root, uint16_t port) {
    common::security::SecurityCredentialsConfig gateway_config{
        .ca_cert_path = pki_root / "ca" / "ca.crt",
        .service_cert_path = pki_root / "services" / "gateway" / "gateway.crt",
        .service_key_path = pki_root / "services" / "gateway" / "gateway.key",
    };

    return common::security::MtlsCredentialLoader::create_mtls_channel("127.0.0.1:" + std::to_string(port),
                                                                       gateway_config, "audit");
}

std::shared_ptr<grpc::Channel> create_insecure_channel(uint16_t port) {
    return grpc::CreateChannel("127.0.0.1:" + std::to_string(port), grpc::InsecureChannelCredentials());
}

grpc::Status check_health(const std::shared_ptr<grpc::Channel>& channel, const std::string& service_name,
                          common::v1::HealthCheckResponse& response) {
    auto stub = common::v1::HealthService::NewStub(channel);
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));

    common::v1::HealthCheckRequest request;
    request.set_service(service_name);

    return stub->Check(&context, request, &response);
}

void wait_until_server_running(const AuditServer& server) {
    for (int i = 0; i < 30 && server.state() != ServiceState::Running; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace

class AuditServerIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ensure_integration_winsock();
        pki_root_ = find_pki_root();
        ASSERT_TRUE(std::filesystem::exists(pki_root_ / "ca" / "ca.crt"))
            << "Dev PKI directory not found at " << pki_root_;
    }

    std::filesystem::path pki_root_;
};

TEST_F(AuditServerIntegrationTest, AuditServiceStartsAndBindsMtlsPort) {
    auto config = create_integration_test_config(pki_root_, k_integration_test_port);
    AuditServer server(std::move(config));

    std::atomic<bool> start_ok{false};
    std::thread server_thread([&server, &start_ok]() { start_ok = server.start(); });

    wait_until_server_running(server);

    auto channel = create_mtls_channel(pki_root_, k_integration_test_port);
    common::v1::HealthCheckResponse response;
    auto status = check_health(channel, "audit", response);

    EXPECT_TRUE(status.ok()) << "gRPC health check failed: " << status.error_message()
                             << " (code: " << status.error_code() << ")";
    EXPECT_EQ(response.status(), common::v1::HealthCheckResponse::SERVING);

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
    EXPECT_TRUE(start_ok.load());
}

TEST_F(AuditServerIntegrationTest, AuditServiceRejectsInsecurePlaintextConnection) {
    constexpr uint16_t port = 50056;
    auto config = create_integration_test_config(pki_root_, port);
    AuditServer server(std::move(config));

    std::thread server_thread([&server]() { server.start(); });

    wait_until_server_running(server);

    auto channel = create_insecure_channel(port);
    common::v1::HealthCheckResponse response;
    auto status = check_health(channel, "audit", response);

    EXPECT_FALSE(status.ok());

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(AuditServerIntegrationTest, ClickHouseConnectivityProbeHealthDegradation) {
    constexpr uint16_t port = 50057;
    constexpr uint16_t unreachable_ch_port = 12345;

    auto config = create_integration_test_config(pki_root_, port, unreachable_ch_port);
    AuditServer server(std::move(config));

    std::thread server_thread([&server]() { server.start(); });

    wait_until_server_running(server);

    auto channel = create_mtls_channel(pki_root_, port);
    common::v1::HealthCheckResponse response;
    auto status = check_health(channel, "", response);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.status(), common::v1::HealthCheckResponse::SERVING);

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(AuditServerIntegrationTest, GracefulShutdownDrainsCleanly) {
    constexpr uint16_t port = 50058;
    auto config = create_integration_test_config(pki_root_, port);
    AuditServer server(std::move(config));

    std::thread server_thread([&server]() { server.start(); });

    wait_until_server_running(server);
    EXPECT_TRUE(server.is_healthy());

    auto start_time = std::chrono::steady_clock::now();
    server.stop();

    if (server_thread.joinable()) {
        server_thread.join();
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    EXPECT_FALSE(server.is_healthy());
    EXPECT_EQ(server.state(), ServiceState::Stopped);
    EXPECT_LE(elapsed.count(), k_test_timeout.count() * 1000);
}

} // namespace securecloud::audit::test