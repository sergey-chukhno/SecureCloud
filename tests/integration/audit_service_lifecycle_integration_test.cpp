#include "audit_server.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/clickhouse_client.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <algorithm>
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

constexpr uint16_t k_integration_test_port = 50065;
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
    source.set("SECURECLOUD_AUDIT_DB_HOST", "127.0.0.1");
    source.set("SECURECLOUD_AUDIT_DB_PASSWORD", "IntegrationTestPassword123!");
    source.set("SECURECLOUD_AUDIT_DB_PORT", std::to_string(clickhouse_port));
    source.set("SECURECLOUD_AUDIT_SHUTDOWN_GRACE_PERIOD_MS", "500");
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

bool wait_for_health_status(const std::shared_ptr<grpc::Channel>& channel, const std::string& service_name,
                            common::v1::HealthCheckResponse::ServingStatus expected_status,
                            std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        common::v1::HealthCheckResponse response;
        const auto status = check_health(channel, service_name, response);
        if (status.ok() && response.status() == expected_status) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
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
    std::thread server_thread([&server, &start_ok]() {
        start_ok = server.start();
        if (start_ok.load()) {
            server.wait();
        }
    });

    wait_until_server_running(server);

    auto channel = create_mtls_channel(pki_root_, k_integration_test_port);
    common::v1::HealthCheckResponse response;
    auto status = check_health(channel, "audit", response);

    EXPECT_TRUE(status.ok()) << "gRPC health check failed: " << status.error_message()
                             << " (code: " << status.error_code() << ")";
    EXPECT_EQ(response.status(), common::v1::HealthCheckResponse::SERVING);

    channel.reset();
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

    std::atomic<bool> start_ok{false};
    std::thread server_thread([&server, &start_ok]() {
        start_ok = server.start();
        if (start_ok.load()) {
            server.wait();
        }
    });

    wait_until_server_running(server);

    auto channel = create_insecure_channel(port);
    common::v1::HealthCheckResponse response;
    auto status = check_health(channel, "audit", response);

    EXPECT_FALSE(status.ok());

    channel.reset();
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(AuditServerIntegrationTest, LivePipelineDeduplicatesIdenticalEventsAndRejectsPayloadConflicts) {
    constexpr uint16_t port = 50059;
    auto config = create_integration_test_config(pki_root_, port);
    config.clickhouse.host = "127.0.0.1";
    config.clickhouse.password = common::configuration::SecretString("audit_dev_db_secret");

    auto repository_client = std::make_shared<repository::ClickHouseClient>(config.clickhouse);
    if (!repository_client->ping()) {
        GTEST_SKIP() << "Live ClickHouse server unavailable at 127.0.0.1:8123. Skipping live AuditServer test.";
    }
    auto repository = std::make_shared<repository::ClickHouseAuditEventRepository>(repository_client);

    AuditServer server(std::move(config));
    std::atomic<bool> start_ok{false};
    std::thread server_thread([&server, &start_ok]() {
        start_ok = server.start();
        if (start_ok.load()) {
            server.wait();
        }
    });
    wait_until_server_running(server);
    if (!start_ok.load()) {
        if (server_thread.joinable()) {
            server_thread.join();
        }
        FAIL() << "AuditServer did not start";
        return;
    }

    auto channel = create_mtls_channel(pki_root_, port);
    auto stub = securecloud::audit::v1::AuditIngestionService::NewStub(channel);
    securecloud::audit::v1::SubmitAuditEventRequest request;
    auto* event = request.mutable_event();
    const auto event_id = domain::EventId::generate_v7();
    event->set_event_id(event_id.to_string());
    event->set_occurred_at_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    event->set_event_type("gateway.integration.test");
    event->set_severity(securecloud::audit::v1::SEVERITY_INFO);
    event->set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY);
    event->set_producer_instance("gateway-integration");
    event->set_actor_type(securecloud::audit::v1::ACTOR_TYPE_SERVICE);
    event->set_actor_id("gateway");
    event->set_target_type(securecloud::audit::v1::TARGET_TYPE_SERVICE);
    event->set_target_id("audit");
    event->set_correlation_id(domain::EventId::generate_v7().to_string());

    auto submit = [&stub](const securecloud::audit::v1::SubmitAuditEventRequest& submit_request,
                          securecloud::audit::v1::SubmitAuditEventResponse& response) {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        return stub->SubmitAuditEvent(&context, submit_request, &response);
    };

    securecloud::audit::v1::SubmitAuditEventResponse first_response;
    const auto first_status = submit(request, first_response);
    securecloud::audit::v1::SubmitAuditEventResponse retry_response;
    const auto retry_status = submit(request, retry_response);

    auto conflicting_request = request;
    conflicting_request.mutable_event()->set_actor_id("different-actor");
    securecloud::audit::v1::SubmitAuditEventResponse conflict_response;
    const auto conflict_status = submit(conflicting_request, conflict_response);

    EXPECT_TRUE(first_status.ok()) << first_status.error_message();
    EXPECT_TRUE(retry_status.ok()) << retry_status.error_message();
    EXPECT_EQ(conflict_status.error_code(), grpc::StatusCode::ALREADY_EXISTS);

    common::security::SecurityCredentialsConfig audit_credentials{
        .ca_cert_path = pki_root_ / "ca" / "ca.crt",
        .service_cert_path = pki_root_ / "services" / "audit" / "audit.crt",
        .service_key_path = pki_root_ / "services" / "audit" / "audit.key",
    };
    auto audit_channel = common::security::MtlsCredentialLoader::create_mtls_channel(
        "127.0.0.1:" + std::to_string(port), audit_credentials, "audit");
    auto query_stub = securecloud::audit::v1::AuditQueryService::NewStub(audit_channel);
    securecloud::audit::v1::GetAuditEventByIdRequest get_request;
    get_request.set_event_id(event_id.to_string());
    securecloud::audit::v1::GetAuditEventByIdResponse get_response;
    grpc::ClientContext audit_query_context;
    audit_query_context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    const auto audit_query_status = query_stub->GetAuditEventById(&audit_query_context, get_request, &get_response);
    EXPECT_TRUE(audit_query_status.ok()) << audit_query_status.error_message();
    EXPECT_TRUE(get_response.has_event());

    common::security::SecurityCredentialsConfig files_credentials{
        .ca_cert_path = pki_root_ / "ca" / "ca.crt",
        .service_cert_path = pki_root_ / "services" / "files" / "files.crt",
        .service_key_path = pki_root_ / "services" / "files" / "files.key",
    };
    auto files_channel = common::security::MtlsCredentialLoader::create_mtls_channel(
        "127.0.0.1:" + std::to_string(port), files_credentials, "audit");
    auto files_query_stub = securecloud::audit::v1::AuditQueryService::NewStub(files_channel);
    securecloud::audit::v1::QueryAuditEventsRequest files_query_request;
    files_query_request.add_producer_services(securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    grpc::ClientContext files_query_context;
    files_query_context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    securecloud::audit::v1::QueryAuditEventsResponse files_query_response;
    const auto files_query_status =
        files_query_stub->QueryAuditEvents(&files_query_context, files_query_request, &files_query_response);
    EXPECT_EQ(files_query_status.error_code(), grpc::StatusCode::PERMISSION_DENIED);

    const auto duplicate_counts = repository->find_duplicate_event_counts();
    const auto event_duplicate =
        std::find_if(duplicate_counts.begin(), duplicate_counts.end(),
                     [&event_id](const repository::DuplicateEventCount& count) { return count.event_id == event_id; });
    EXPECT_EQ(event_duplicate, duplicate_counts.end()) << "A retry must create only one ClickHouse row";

    channel.reset();
    audit_channel.reset();
    files_channel.reset();
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(AuditServerIntegrationTest, ClickHouseHealthEvaluatorDegradesReadinessWhenUnavailable) {
    constexpr uint16_t port = 50057;
    constexpr uint16_t unreachable_ch_port = 12345;

    auto config = create_integration_test_config(pki_root_, port, unreachable_ch_port);
    AuditServer server(std::move(config));

    std::atomic<bool> start_ok{false};
    std::thread server_thread([&server, &start_ok]() {
        start_ok = server.start();
        if (start_ok.load()) {
            server.wait();
        }
    });

    wait_until_server_running(server);

    auto channel = create_mtls_channel(pki_root_, port);

    // 1. Liveness probe check succeeds
    common::v1::HealthCheckResponse liveness_response;
    auto liveness_status = check_health(channel, "", liveness_response);
    EXPECT_TRUE(liveness_status.ok());
    EXPECT_EQ(liveness_response.status(), common::v1::HealthCheckResponse::SERVING);

    // 2. Readiness probe degrades to NOT_SERVING due to unreachable ClickHouse port
    EXPECT_TRUE(wait_for_health_status(channel, "readiness", common::v1::HealthCheckResponse::NOT_SERVING,
                                       std::chrono::seconds(6)));

    channel.reset();
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
    EXPECT_TRUE(start_ok.load());
}

TEST_F(AuditServerIntegrationTest, GracefulShutdownDrainsCleanly) {
    constexpr uint16_t port = 50058;
    auto config = create_integration_test_config(pki_root_, port);
    AuditServer server(std::move(config));

    std::atomic<bool> start_ok{false};
    std::thread server_thread([&server, &start_ok]() {
        start_ok = server.start();
        if (start_ok.load()) {
            server.wait();
        }
    });

    wait_until_server_running(server);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!server.is_healthy() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
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
