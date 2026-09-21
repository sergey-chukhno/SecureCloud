#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace securecloud::common {
namespace {

using health::HealthServiceImpl;
using health::HealthStatusManager;
using health::probe_tcp_connectivity;
using security::MtlsCredentialLoader;
using security::SecurityCredentialsConfig;

#ifdef _WIN32
using socket_handle_t = SOCKET;
constexpr socket_handle_t k_invalid_socket = INVALID_SOCKET;

inline void close_socket_handle(socket_handle_t s) noexcept {
    if (s != INVALID_SOCKET) {
        ::closesocket(s);
    }
}

inline void ensure_integration_winsock() noexcept {
    struct WinsockInit {
        WinsockInit() noexcept {
            WSADATA wsa{};
            (void)::WSAStartup(MAKEWORD(2, 2), &wsa);
        }
        ~WinsockInit() noexcept { ::WSACleanup(); }
    };
    static WinsockInit init;
}

using socklen_val_t = int;
#else
using socket_handle_t = int;
constexpr socket_handle_t k_invalid_socket = -1;

inline void close_socket_handle(socket_handle_t s) noexcept {
    if (s >= 0) {
        ::close(s);
    }
}

inline void ensure_integration_winsock() noexcept {}

using socklen_val_t = socklen_t;
#endif

constexpr int k_listen_backlog = 5;
constexpr std::chrono::milliseconds k_test_probe_timeout{250};
constexpr std::chrono::milliseconds k_short_rpc_deadline{500};
constexpr std::chrono::seconds k_rpc_deadline{2};

std::string read_file_content(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

class ScopedTcpListener {
  public:
    ScopedTcpListener() {
        ensure_integration_winsock();
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ == k_invalid_socket) {
            return;
        }

#ifdef _WIN32
        const char opt = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#else
        int opt = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            stop();
            return;
        }

        if (::listen(listen_fd_, k_listen_backlog) != 0) {
            stop();
            return;
        }

        socklen_val_t len = sizeof(addr);
        if (::getsockname(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
            port_ = ntohs(addr.sin_port);
        }
    }

    ~ScopedTcpListener() noexcept { stop(); }

    ScopedTcpListener(const ScopedTcpListener&) = delete;
    ScopedTcpListener& operator=(const ScopedTcpListener&) = delete;
    ScopedTcpListener(ScopedTcpListener&&) = delete;
    ScopedTcpListener& operator=(ScopedTcpListener&&) = delete;

    void stop() noexcept {
        if (listen_fd_ != k_invalid_socket) {
            close_socket_handle(listen_fd_);
            listen_fd_ = k_invalid_socket;
        }
    }

    [[nodiscard]] uint16_t port() const noexcept { return port_; }

    [[nodiscard]] bool is_listening() const noexcept { return listen_fd_ != k_invalid_socket; }

  private:
    socket_handle_t listen_fd_{k_invalid_socket};
    uint16_t port_{0};
};

class HealthIntegrationTest : public ::testing::Test {
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
        health_manager_.set_live(true);
        health_manager_.set_ready(true);

        auto pki_root = find_pki_root();
        ca_path_ = pki_root / "ca" / "ca.crt";
        auth_cert_path_ = pki_root / "services" / "auth" / "auth.crt";
        auth_key_path_ = pki_root / "services" / "auth" / "auth.key";
        gateway_cert_path_ = pki_root / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root / "services" / "gateway" / "gateway.key";
        audit_cert_path_ = pki_root / "services" / "audit" / "audit.crt";
        audit_key_path_ = pki_root / "services" / "audit" / "audit.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_,          auth_cert_path_,  auth_key_path_,  gateway_cert_path_,
            gateway_key_path_, audit_cert_path_, audit_key_path_,
        };

        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Dev PKI file missing: " << path;
        }

        auth_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = auth_cert_path_,
            .service_key_path = auth_key_path_,
        };

        gateway_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        audit_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = audit_cert_path_,
            .service_key_path = audit_key_path_,
        };
    }

    static std::pair<std::unique_ptr<grpc::Server>, std::string>
    start_mtls_server(HealthServiceImpl* service_impl, const SecurityCredentialsConfig& server_config) {
        auto server_creds = MtlsCredentialLoader::create_server_credentials(server_config);
        EXPECT_NE(server_creds, nullptr);

        grpc::ServerBuilder builder;
        int selected_port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
        builder.RegisterService(service_impl);

        auto server = builder.BuildAndStart();
        EXPECT_NE(server, nullptr);
        EXPECT_GT(selected_port, 0);

        std::string server_address = "127.0.0.1:" + std::to_string(selected_port);
        return {std::move(server), server_address};
    }

    HealthStatusManager health_manager_{"auth"};
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;
    std::filesystem::path audit_cert_path_;
    std::filesystem::path audit_key_path_;

    SecurityCredentialsConfig auth_config_;
    SecurityCredentialsConfig gateway_config_;
    SecurityCredentialsConfig audit_config_;
};

TEST_F(HealthIntegrationTest, CheckLivenessEmptyServiceReturnsServing) {
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::HealthCheckRequest request;
    request.set_service("");
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "RPC failed: " << status.error_message();
    EXPECT_EQ(response.status(), v1::HealthCheckResponse::SERVING);

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, CheckLivenessCanonicalServiceReturnsServing) {
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::HealthCheckRequest request;
    request.set_service("auth");
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "RPC failed: " << status.error_message();
    EXPECT_EQ(response.status(), v1::HealthCheckResponse::SERVING);

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, CheckReadinessWithHealthyDependencyReturnsServing) {
    ScopedTcpListener dep_listener;
    ASSERT_TRUE(dep_listener.is_listening());

    const uint16_t dep_port = dep_listener.port();
    health_manager_.set_readiness_evaluator(
        [dep_port] { return probe_tcp_connectivity("127.0.0.1", dep_port, k_test_probe_timeout); });

    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::HealthCheckRequest request;
    request.set_service("readiness");
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "RPC failed: " << status.error_message();
    EXPECT_EQ(response.status(), v1::HealthCheckResponse::SERVING);

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, CheckReadinessDegradesOnDependencyOutageWhileLivenessRemainsServing) {
    auto dep_listener = std::make_unique<ScopedTcpListener>();
    ASSERT_TRUE(dep_listener->is_listening());

    const uint16_t dep_port = dep_listener->port();
    health_manager_.set_readiness_evaluator(
        [dep_port] { return probe_tcp_connectivity("127.0.0.1", dep_port, k_test_probe_timeout); });

    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    // Initial state: dependency healthy -> readiness SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::HealthCheckRequest req;
        req.set_service("readiness");
        v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), v1::HealthCheckResponse::SERVING);
    }

    // Simulate dependency outage: close the listening socket
    dep_listener->stop();

    // Readiness query must degrade to NOT_SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::HealthCheckRequest req;
        req.set_service("readiness");
        v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), v1::HealthCheckResponse::NOT_SERVING);
    }

    // Liveness query must remain SERVING (process itself is alive)
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::HealthCheckRequest req;
        req.set_service("");
        v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), v1::HealthCheckResponse::SERVING);
    }

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, CheckReadinessDegradesImmediatelyOnShutdown) {
    ScopedTcpListener dep_listener;
    ASSERT_TRUE(dep_listener.is_listening());

    const uint16_t dep_port = dep_listener.port();
    health_manager_.set_readiness_evaluator(
        [dep_port] { return probe_tcp_connectivity("127.0.0.1", dep_port, k_test_probe_timeout); });

    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    // Signal graceful shutdown
    health_manager_.set_shutting_down(true);

    // Readiness must immediately be NOT_SERVING even though dependency is listening
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::HealthCheckRequest req;
        req.set_service("readiness");
        v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), v1::HealthCheckResponse::NOT_SERVING);
    }

    // Liveness remains SERVING during graceful drain
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::HealthCheckRequest req;
        req.set_service("auth");
        v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), v1::HealthCheckResponse::SERVING);
    }

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, CheckUnknownServiceReturnsServiceUnknown) {
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::HealthCheckRequest request;
    request.set_service("unknown_subsystem");
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "RPC failed: " << status.error_message();
    EXPECT_EQ(response.status(), v1::HealthCheckResponse::SERVICE_UNKNOWN);

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, SecurityPlaintextClientRejected) {
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_short_rpc_deadline);
    v1::HealthCheckRequest request;
    request.set_service("");
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_code(), grpc::StatusCode::OK);

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, SecurityUntrustedCaRejected) {
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto temp_dir = std::filesystem::temp_directory_path() / "untrusted_health_ca_test";
    std::filesystem::create_directories(temp_dir);
    auto untrusted_ca_path = temp_dir / "untrusted_ca.crt";
    {
        std::ofstream ofs(untrusted_ca_path);
        ofs << "-----BEGIN CERTIFICATE-----\nFAKE_CA\n-----END CERTIFICATE-----\n";
    }

    SecurityCredentialsConfig untrusted_config{
        .ca_cert_path = untrusted_ca_path,
        .service_cert_path = gateway_cert_path_,
        .service_key_path = gateway_key_path_,
    };

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, untrusted_config, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::HealthCheckRequest request;
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_code(), grpc::StatusCode::OK);

    server->Shutdown();
    std::filesystem::remove_all(temp_dir);
}

TEST_F(HealthIntegrationTest, SecurityUnauthenticatedClientRejected) {
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    std::string ca_pem = read_file_content(ca_path_);
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca_pem;
    auto client_creds = grpc::SslCredentials(ssl_opts);

    grpc::ChannelArguments ch_args;
    ch_args.SetSslTargetNameOverride("auth");
    auto channel = grpc::CreateCustomChannel(server_address, client_creds, ch_args);
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::HealthCheckRequest request;
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_code(), grpc::StatusCode::OK);

    server->Shutdown();
}

TEST_F(HealthIntegrationTest, SecurityWrongClientIdentityRejectedPostHandshake) {
    // Server expects only "gateway" callers
    HealthServiceImpl health_service("auth", health_manager_, "gateway");
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    // Client connects using "audit" credentials (valid CA cert, but wrong service identity)
    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, audit_config_, "auth");
    auto stub = v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::HealthCheckRequest request;
    request.set_service("");
    v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

    server->Shutdown();
}

int run_health_probe_cli(const std::vector<std::string>& extra_args) {
#ifdef SECURECLOUD_HEALTH_PROBE_BIN
#ifdef _WIN32
    std::string cmdline = "\"" SECURECLOUD_HEALTH_PROBE_BIN "\"";
    for (const auto& arg : extra_args) {
        cmdline += " \"";
        cmdline += arg;
        cmdline += "\"";
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = INVALID_HANDLE_VALUE;
    si.hStdError = INVALID_HANDLE_VALUE;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE nul_handle = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    if (nul_handle != INVALID_HANDLE_VALUE) {
        si.hStdOutput = nul_handle;
        si.hStdError = nul_handle;
    }

    PROCESS_INFORMATION pi{};
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wide_cmd(wide_len);
    MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(), -1, wide_cmd.data(), wide_len);

    BOOL success = CreateProcessW(nullptr, wide_cmd.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);

    if (nul_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(nul_handle);
    }

    if (!success) {
        return -1;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

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

TEST_F(HealthIntegrationTest, HealthProbeCliTimeoutValidation) {
    constexpr int k_exit_invalid_args = 3;
    constexpr int k_exit_rpc_error = 1;

    const std::vector<std::string> base_args = {
        "--target", "127.0.0.1:50051",          "--server-name", "auth",
        "--ca",     ca_path_.string(),          "--cert",        gateway_cert_path_.string(),
        "--key",    gateway_key_path_.string(),
    };

    const std::vector<std::string> invalid_timeouts = {
        "abc",
        "",
        "0",
        "-1",
        "-500",
        "2147483648",              // INT_MAX + 1
        "99999999999999999999999", // uint64 overflow / ERANGE
        "100ms",
        "3.14",
    };

    for (const auto& invalid_timeout : invalid_timeouts) {
        auto args = base_args;
        args.emplace_back("--timeout-ms");
        args.push_back(invalid_timeout);
        int exit_code = run_health_probe_cli(args);
        EXPECT_EQ(exit_code, k_exit_invalid_args)
            << "Expected exit code 3 for invalid timeout-ms '" << invalid_timeout << "', got " << exit_code;
    }

    // Valid positive timeout should not fail with invalid_args (exit code 3)
    auto valid_args = base_args;
    valid_args.emplace_back("--timeout-ms");
    valid_args.emplace_back("1500");
    int exit_code = run_health_probe_cli(valid_args);
    EXPECT_NE(exit_code, k_exit_invalid_args) << "Valid timeout-ms was unexpectedly rejected as invalid argument";
    EXPECT_EQ(exit_code, k_exit_rpc_error)
        << "Expected RPC failure exit code 1 when probing non-listening endpoint, got " << exit_code;
}

} // namespace
} // namespace securecloud::common
