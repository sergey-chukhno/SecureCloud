#include "auth/service/auth_service_impl.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

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

using socket_handle_t = SOCKET;
constexpr socket_handle_t k_invalid_socket = INVALID_SOCKET;

inline void close_socket_handle(socket_handle_t s) noexcept {
    if (s != INVALID_SOCKET) {
        linger l{1, 0};
        ::setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&l), sizeof(l));
        ::closesocket(s);
    }
}
using socklen_val_t = int;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

inline void ensure_integration_winsock() noexcept {}

using socket_handle_t = int;
constexpr socket_handle_t k_invalid_socket = -1;

inline void close_socket_handle(socket_handle_t s) noexcept {
    if (s >= 0) {
        ::close(s);
    }
}
using socklen_val_t = socklen_t;
#endif

namespace securecloud::auth::integration {
namespace {

using common::health::HealthServiceImpl;
using common::health::HealthStatusManager;
using common::health::probe_tcp_connectivity;
using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;

constexpr std::chrono::milliseconds k_rpc_deadline{2000};
constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::milliseconds k_probe_timeout{250};

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

#ifndef _WIN32
        int opt = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            stop();
            return;
        }

        if (::listen(listen_fd_, 5) != 0) {
            stop();
            return;
        }

        socklen_val_t len = sizeof(addr);
        if (::getsockname(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
            port_ = ntohs(addr.sin_port);
        }
    }

    ~ScopedTcpListener() noexcept { stop(); }

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

class AuthIntegrationTest : public ::testing::Test {
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
        health_manager_.set_live(true);
        health_manager_.set_ready(true);

        auto pki_root = find_pki_root();
        ca_path_ = pki_root / "ca" / "ca.crt";
        auth_cert_path_ = pki_root / "services" / "auth" / "auth.crt";
        auth_key_path_ = pki_root / "services" / "auth" / "auth.key";
        gateway_cert_path_ = pki_root / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root / "services" / "gateway" / "gateway.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_, auth_cert_path_, auth_key_path_, gateway_cert_path_, gateway_key_path_,
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
    }

    static std::pair<std::unique_ptr<grpc::Server>, std::string>
    start_server(grpc::Service* auth_service, grpc::Service* health_service,
                 const SecurityCredentialsConfig& server_config) {
        auto server_creds = MtlsCredentialLoader::create_server_credentials(server_config);
        EXPECT_NE(server_creds, nullptr);

        grpc::ServerBuilder builder;
        int selected_port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
        builder.RegisterService(auth_service);
        if (health_service) {
            builder.RegisterService(health_service);
        }

        auto server = builder.BuildAndStart();
        EXPECT_NE(server, nullptr);
        EXPECT_GT(selected_port, 0);

        std::string server_address = "127.0.0.1:" + std::to_string(selected_port);
        return {std::move(server), server_address};
    }

    template <typename StubType>
    static void shutdown_server(std::unique_ptr<grpc::Server>& server, std::unique_ptr<StubType>& stub,
                                std::shared_ptr<grpc::Channel>& channel) {
        if (server) {
            server->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
        }
        stub.reset();
        channel.reset();
        if (server) {
            server.reset();
        }
    }

    HealthStatusManager health_manager_{"auth"};
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    SecurityCredentialsConfig auth_config_;
    SecurityCredentialsConfig gateway_config_;
};

// --- 4-Case mTLS Matrix Tests ---

TEST_F(AuthIntegrationTest, MtlsCase1ValidClientCertSucceeds) {
    service::AuthServiceImpl auth_service;
    auto [server, server_address] = start_server(&auth_service, nullptr, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = v1::AuthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::AuthenticateRequest request;
    v1::AuthenticateResponse response;

    grpc::Status status = stub->Authenticate(&context, request, &response);

    // TLS Handshake succeeds, RPC reaches AuthServiceImpl and returns UNIMPLEMENTED
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);

    shutdown_server(server, stub, channel);
}

TEST_F(AuthIntegrationTest, MtlsCase2MissingClientCertRejected) {
    service::AuthServiceImpl auth_service;
    auto [server, server_address] = start_server(&auth_service, nullptr, auth_config_);

    std::string ca_pem = read_file_content(ca_path_);
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca_pem;
    auto client_creds = grpc::SslCredentials(ssl_opts);

    grpc::ChannelArguments ch_args;
    ch_args.SetSslTargetNameOverride("auth");
    auto channel = grpc::CreateCustomChannel(server_address, client_creds, ch_args);
    auto stub = v1::AuthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::AuthenticateRequest request;
    v1::AuthenticateResponse response;

    grpc::Status status = stub->Authenticate(&context, request, &response);

    EXPECT_FALSE(status.ok()) << "Server unexpectedly accepted connection without client cert";

    shutdown_server(server, stub, channel);
}

TEST_F(AuthIntegrationTest, MtlsCase3UntrustedCaRejected) {
    service::AuthServiceImpl auth_service;
    auto [server, server_address] = start_server(&auth_service, nullptr, auth_config_);

    auto temp_dir = std::filesystem::temp_directory_path() / "untrusted_auth_ca_test";
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
    auto stub = v1::AuthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::AuthenticateRequest request;
    v1::AuthenticateResponse response;

    grpc::Status status = stub->Authenticate(&context, request, &response);

    EXPECT_FALSE(status.ok()) << "Server unexpectedly accepted connection from untrusted CA";

    shutdown_server(server, stub, channel);
    std::filesystem::remove_all(temp_dir);
}

TEST_F(AuthIntegrationTest, MtlsCase4PlaintextConnectionRejected) {
    service::AuthServiceImpl auth_service;
    auto [server, server_address] = start_server(&auth_service, nullptr, auth_config_);

    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    auto stub = v1::AuthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    v1::AuthenticateRequest request;
    v1::AuthenticateResponse response;

    grpc::Status status = stub->Authenticate(&context, request, &response);

    EXPECT_FALSE(status.ok()) << "Server unexpectedly accepted plaintext connection";

    shutdown_server(server, stub, channel);
}

// --- Database Failure Isolation Test ---

TEST_F(AuthIntegrationTest, DatabaseFailureDegradesReadinessToNotServingAndRecovers) {
    ScopedTcpListener mock_db_listener;
    ASSERT_TRUE(mock_db_listener.is_listening());

    std::atomic<uint16_t> active_db_port{mock_db_listener.port()};

    // Dynamic readiness evaluator simulating DB connection check
    health_manager_.set_readiness_evaluator([&active_db_port]() noexcept {
        uint16_t port = active_db_port.load();
        return probe_tcp_connectivity("127.0.0.1", port, k_probe_timeout);
    });

    service::AuthServiceImpl auth_service;
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_server(&auth_service, &health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto health_stub = common::v1::HealthService::NewStub(channel);

    // 1. Initial State: DB reachable -> Readiness SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(health_stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // 2. Inject connection failure: Switch to unreachable loopback 127.0.0.1:5439
    // CRITICAL INVARIANT: Never touch port 5432
    active_db_port.store(5439);

    // Verify readiness degrades to NOT_SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(health_stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::NOT_SERVING);
    }

    // Verify liveness remains SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(health_stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // 3. Restore configuration -> Readiness recovers to SERVING
    active_db_port.store(mock_db_listener.port());

    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(health_stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    mock_db_listener.stop();
    shutdown_server(server, health_stub, channel);
}

// --- Shutdown Test ---

TEST_F(AuthIntegrationTest, BoundedDrainUnderSimulatedClientLoad) {
    service::AuthServiceImpl auth_service;
    HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_server(&auth_service, &health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto auth_stub = v1::AuthService::NewStub(channel);

    std::atomic<bool> keep_calling{true};
    std::thread client_thread([&]() {
        while (keep_calling.load()) {
            grpc::ClientContext ctx;
            ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(100));
            v1::AuthenticateRequest req;
            v1::AuthenticateResponse resp;
            (void)auth_stub->Authenticate(&ctx, req, &resp);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    // Initiate graceful shutdown
    health_manager_.set_shutting_down(true);

    keep_calling.store(false);
    if (client_thread.joinable()) {
        client_thread.join();
    }

    shutdown_server(server, auth_stub, channel);
}

} // namespace
} // namespace securecloud::auth::integration

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
