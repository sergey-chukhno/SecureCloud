#include "gateway_config.hpp"
#include "grpc/channel_manager.hpp"
#include "health/gateway_health_evaluator.hpp"
#include "http/http_server.hpp"
#include "http/router.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace securecloud::gateway {
namespace {

constexpr int k_http_status_ok = 200;
constexpr int k_http_status_not_found = 404;
constexpr int k_http_status_service_unavailable = 503;
constexpr int k_probe_cli_timeout_ms = 3000;
constexpr int k_exit_ok = 0;
constexpr std::chrono::milliseconds k_evaluator_probe_timeout{400};
constexpr std::chrono::milliseconds k_rpc_deadline{2000};
constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::milliseconds k_max_acceptable_shutdown_duration{2000};

#ifdef _WIN32
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

int run_health_probe_cli(const std::vector<std::string>& extra_args) {
#ifdef SECURECLOUD_HEALTH_PROBE_BIN
#ifdef _WIN32
    std::string bin_path = SECURECLOUD_HEALTH_PROBE_BIN;
    for (char& c : bin_path) {
        if (c == '/') {
            c = '\\';
        }
    }

    std::string cmdline = "\"" + bin_path + "\"";
    for (const auto& arg : extra_args) {
        cmdline += " \"";
        cmdline += arg;
        cmdline += "\"";
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE nul_handle = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = nul_handle;
    si.hStdError = nul_handle;

    PROCESS_INFORMATION pi{};
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wide_cmd(wide_len);
    MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(), -1, wide_cmd.data(), wide_len);

    BOOL success = CreateProcessW(nullptr, wide_cmd.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);

    if (!success) {
        if (nul_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(nul_handle);
        }
        return -1;
    }

    DWORD wait_res = WaitForSingleObject(pi.hProcess, 3000);
    if (wait_res == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 1000);
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (nul_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(nul_handle);
    }

    return static_cast<int>(exit_code);
#else
    std::vector<std::string> args_storage;
    args_storage.reserve(extra_args.size() + 1);
    args_storage.emplace_back(SECURECLOUD_HEALTH_PROBE_BIN);
    args_storage.insert(args_storage.end(), extra_args.begin(), extra_args.end());

    std::vector<char*> argv;
    argv.reserve(args_storage.size() + 1);
    for (auto& arg : args_storage) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    std::array<char*, 1> empty_env{nullptr};
    pid_t pid = 0;
    int spawn_ret = posix_spawn(&pid, SECURECLOUD_HEALTH_PROBE_BIN, &actions, nullptr, argv.data(), empty_env.data());
    posix_spawn_file_actions_destroy(&actions);
    if (spawn_ret != 0) {
        return -1;
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
#endif
#else
    (void)extra_args;
    return -1;
#endif
}

void register_health_routes(http::Router& router, common::health::HealthStatusManager& health_manager) {
    router.get("/health/live", [&health_manager](const httplib::Request&, httplib::Response& res) {
        if (health_manager.is_live()) {
            res.status = k_http_status_ok;
            res.set_content(R"({"status":"SERVING"})", "application/json");
        } else {
            res.status = k_http_status_service_unavailable;
            res.set_content(R"({"status":"NOT_SERVING"})", "application/json");
        }
    });

    router.get("/health/ready", [&health_manager](const httplib::Request&, httplib::Response& res) {
        if (health_manager.is_ready() && health_manager.evaluate_readiness()) {
            res.status = k_http_status_ok;
            res.set_content(R"({"status":"SERVING"})", "application/json");
        } else {
            res.status = k_http_status_service_unavailable;
            res.set_content(R"({"status":"NOT_SERVING"})", "application/json");
        }
    });
}

GatewayConfig make_test_gateway_config(const common::security::SecurityCredentialsConfig& creds) {
    GatewayConfig config;
    config.common.service_name = "gateway";
    config.common.service_display_name = "SecureCloud API Gateway";
    config.common.grpc_host = "127.0.0.1";
    config.common.grpc_port = 0;
    config.common.tls_credentials = creds;
    config.http_listen_address = "127.0.0.1";
    config.http_listen_port = 0;
    return config;
}

std::pair<std::unique_ptr<::grpc::Server>, uint16_t>
start_mtls_grpc_server(common::health::HealthServiceImpl& service_impl,
                       const common::security::SecurityCredentialsConfig& creds) {
    auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(creds);
    if (!server_creds) {
        return {nullptr, 0};
    }

    ::grpc::ServerBuilder builder;
    int selected_port = 0;
    builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
    builder.RegisterService(&service_impl);

    auto server = builder.BuildAndStart();
    if (!server || selected_port <= 0) {
        return {nullptr, 0};
    }

    return {std::move(server), static_cast<uint16_t>(selected_port)};
}

void verify_http_status_and_body_status(httplib::Client& client, const std::string& path, int expected_status,
                                        const std::string& expected_status_field) {
    auto res = client.Get(path);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, expected_status);
    EXPECT_TRUE(res->has_header("X-Request-Id"));
    auto json_body = nlohmann::json::parse(res->body);
    EXPECT_EQ(json_body["status"], expected_status_field);
}

void verify_error_envelope(const std::string& body, const std::string& expected_req_id) {
    auto json_body = nlohmann::json::parse(body);
    EXPECT_EQ(json_body["error"]["code"], "NOT_FOUND");
    EXPECT_EQ(json_body["error"]["message"], "Resource not found");
    EXPECT_EQ(json_body["error"]["request_id"], expected_req_id);
}

void verify_404_error_response(httplib::Client& client, const std::string& path) {
    auto res = client.Get(path);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_not_found);
    std::string header_req_id = res->get_header_value("X-Request-Id");
    EXPECT_FALSE(header_req_id.empty());
    verify_error_envelope(res->body, header_req_id);
}

void verify_probe_cli_health(const std::string& target, const std::filesystem::path& ca,
                             const std::filesystem::path& cert, const std::filesystem::path& key) {
    std::vector<std::string> probe_args = {
        "--target", target,       "--server-name", "gateway",
        "--ca",     ca.string(),  "--cert",        cert.string(),
        "--key",    key.string(), "--timeout-ms",  std::to_string(k_probe_cli_timeout_ms),
    };
    int exit_code = run_health_probe_cli(probe_args);
    EXPECT_EQ(exit_code, k_exit_ok) << "Expected probe CLI to succeed with exit code 0, got " << exit_code;
}

void verify_grpc_stub_health(const std::string& target, const common::security::SecurityCredentialsConfig& creds,
                             const std::string& server_name) {
    auto channel = common::security::MtlsCredentialLoader::create_mtls_channel(target, creds, server_name);
    ASSERT_NE(channel, nullptr);

    auto stub = common::v1::HealthService::NewStub(channel);
    ::grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);

    common::v1::HealthCheckRequest req;
    common::v1::HealthCheckResponse resp;
    auto status = stub->Check(&ctx, req, &resp);

    EXPECT_TRUE(status.ok()) << "gRPC Health::Check failed: " << status.error_message();
    EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
}

void verify_shutdown_duration(std::chrono::steady_clock::time_point start_time) {
    auto end_time = std::chrono::steady_clock::now();
    auto shutdown_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    EXPECT_LT(shutdown_duration, k_max_acceptable_shutdown_duration)
        << "Shutdown took " << shutdown_duration.count() << "ms, exceeding max bound of "
        << k_max_acceptable_shutdown_duration.count() << "ms";
}

class GatewayIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_root() {
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

    void SetUp() override {
        ensure_integration_winsock();

        auto pki_root = find_pki_root();
        ca_path_ = pki_root / "ca" / "ca.crt";
        gateway_cert_path_ = pki_root / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root / "services" / "gateway" / "gateway.key";
        auth_cert_path_ = pki_root / "services" / "auth" / "auth.crt";
        auth_key_path_ = pki_root / "services" / "auth" / "auth.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_, gateway_cert_path_, gateway_key_path_, auth_cert_path_, auth_key_path_,
        };

        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Required Dev PKI certificate missing: " << path;
        }

        gateway_creds_ = common::security::SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        auth_creds_ = common::security::SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = auth_cert_path_,
            .service_key_path = auth_key_path_,
        };
    }

    std::filesystem::path ca_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;

    common::security::SecurityCredentialsConfig gateway_creds_;
    common::security::SecurityCredentialsConfig auth_creds_;
};

// Scenario 1: External HTTP /health/live returns 200 OK with {"status": "SERVING"}
TEST_F(GatewayIntegrationTest, ExternalHttpLivenessReturnsServing) {
    auto config = make_test_gateway_config(gateway_creds_);

    common::health::HealthStatusManager health_manager(config.common.service_name);
    health_manager.set_live(true);

    http::Router router;
    register_health_routes(router, health_manager);

    http::HttpServer http_server(config);
    router.register_into(http_server);
    ASSERT_TRUE(http_server.start_async());
    http_server.wait_until_ready();

    httplib::Client client("127.0.0.1", http_server.bound_port());
    verify_http_status_and_body_status(client, "/health/live", k_http_status_ok, "SERVING");

    http_server.stop();
}

// Scenario 2: External HTTP /health/ready returns 200 OK when downstream mock is healthy
TEST_F(GatewayIntegrationTest, ExternalHttpReadinessReturnsServingWhenDownstreamHealthy) {
    common::health::HealthStatusManager auth_health("auth");
    auth_health.set_live(true);
    auth_health.set_ready(true);
    common::health::HealthServiceImpl auth_service("auth", auth_health);

    auto [mock_auth_server, mock_auth_port] = start_mtls_grpc_server(auth_service, auth_creds_);
    ASSERT_NE(mock_auth_server, nullptr);

    auto config = make_test_gateway_config(gateway_creds_);
    config.auth_endpoint = "127.0.0.1:" + std::to_string(mock_auth_port);

    common::health::HealthStatusManager gateway_health(config.common.service_name);
    grpc::GrpcChannelManager channel_manager(config);
    health::GatewayHealthEvaluator health_evaluator(channel_manager, k_evaluator_probe_timeout);
    gateway_health.set_readiness_evaluator([&health_evaluator] { return health_evaluator.evaluate_readiness(); });

    gateway_health.set_live(true);
    gateway_health.set_ready(true);

    http::Router router;
    register_health_routes(router, gateway_health);

    http::HttpServer http_server(config);
    router.register_into(http_server);
    ASSERT_TRUE(http_server.start_async());
    http_server.wait_until_ready();

    httplib::Client client("127.0.0.1", http_server.bound_port());
    verify_http_status_and_body_status(client, "/health/ready", k_http_status_ok, "SERVING");

    http_server.stop();
    channel_manager.reset();
    mock_auth_server->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
}

// Scenario 3: External HTTP /health/ready degrades to 503 when downstream dependency fails
TEST_F(GatewayIntegrationTest, ExternalHttpReadinessDegradesWhenDownstreamUnreachable) {
    constexpr uint16_t k_unreachable_port = 1;

    auto config = make_test_gateway_config(gateway_creds_);
    config.auth_endpoint = "127.0.0.1:" + std::to_string(k_unreachable_port);

    common::health::HealthStatusManager gateway_health(config.common.service_name);
    grpc::GrpcChannelManager channel_manager(config);
    health::GatewayHealthEvaluator health_evaluator(channel_manager, k_evaluator_probe_timeout);
    gateway_health.set_readiness_evaluator([&health_evaluator] { return health_evaluator.evaluate_readiness(); });

    gateway_health.set_live(true);
    gateway_health.set_ready(true);

    http::Router router;
    register_health_routes(router, gateway_health);

    http::HttpServer http_server(config);
    router.register_into(http_server);
    ASSERT_TRUE(http_server.start_async());
    http_server.wait_until_ready();

    httplib::Client client("127.0.0.1", http_server.bound_port());
    verify_http_status_and_body_status(client, "/health/ready", k_http_status_service_unavailable, "NOT_SERVING");
    verify_http_status_and_body_status(client, "/health/live", k_http_status_ok, "SERVING");

    http_server.stop();
    channel_manager.reset();
}

// Scenario 4: Internal gRPC mTLS health check succeeds via probe CLI and client stub
TEST_F(GatewayIntegrationTest, InternalGrpcMtlsHealthCheckSucceeds) {
    auto config = make_test_gateway_config(gateway_creds_);

    common::health::HealthStatusManager health_manager(config.common.service_name);
    common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);
    health_manager.set_live(true);
    health_manager.set_ready(true);

    auto [grpc_server, grpc_port] = start_mtls_grpc_server(health_service, config.common.tls_credentials);
    ASSERT_NE(grpc_server, nullptr);

    std::string grpc_target = "127.0.0.1:" + std::to_string(grpc_port);

    verify_probe_cli_health(grpc_target, ca_path_, gateway_cert_path_, gateway_key_path_);
    verify_grpc_stub_health(grpc_target, config.common.tls_credentials, config.common.service_name);

    grpc_server->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
}

// Scenario 5: Unknown HTTP route returns 404 with standard error JSON
TEST_F(GatewayIntegrationTest, UnknownHttpRouteReturns404WithErrorEnvelope) {
    auto config = make_test_gateway_config(gateway_creds_);

    http::Router router;
    router.get("/v1/items", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content("[]", "application/json");
    });

    http::HttpServer http_server(config);
    router.register_into(http_server);
    ASSERT_TRUE(http_server.start_async());
    http_server.wait_until_ready();

    httplib::Client client("127.0.0.1", http_server.bound_port());
    verify_404_error_response(client, "/v1/nonexistent_route");

    http_server.stop();
}

// Scenario 6: Bounded graceful shutdown terminates both HTTP and gRPC listeners cleanly
TEST_F(GatewayIntegrationTest, GracefulShutdownTerminatesBothListenersCleanly) {
    auto config = make_test_gateway_config(gateway_creds_);

    common::health::HealthStatusManager health_manager(config.common.service_name);
    common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);
    health_manager.set_live(true);

    auto [grpc_server, grpc_port] = start_mtls_grpc_server(health_service, config.common.tls_credentials);
    ASSERT_NE(grpc_server, nullptr);

    http::Router router;
    register_health_routes(router, health_manager);

    http::HttpServer http_server(config);
    router.register_into(http_server);
    ASSERT_TRUE(http_server.start_async());
    http_server.wait_until_ready();

    httplib::Client client("127.0.0.1", http_server.bound_port());
    auto pre_res = client.Get("/health/live");
    ASSERT_TRUE(pre_res);
    EXPECT_EQ(pre_res->status, k_http_status_ok);

    auto start_time = std::chrono::steady_clock::now();

    health_manager.set_shutting_down(true);
    http_server.stop();
    grpc_server->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);

    verify_shutdown_duration(start_time);

    EXPECT_EQ(http_server.state(), http::ServerState::Stopped);
    EXPECT_FALSE(http_server.is_running());
}

} // namespace
} // namespace securecloud::gateway

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
