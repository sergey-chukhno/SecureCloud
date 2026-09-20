#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace securecloud::common {
namespace {

using health::HealthServiceImpl;
using health::HealthStatusManager;
using health::probe_tcp_connectivity;
using security::MtlsCredentialLoader;
using security::SecurityCredentialsConfig;

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
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) {
            return;
        }

        int opt = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

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

        socklen_t len = sizeof(addr);
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
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
    }

    [[nodiscard]] uint16_t port() const noexcept { return port_; }

    [[nodiscard]] bool is_listening() const noexcept { return listen_fd_ >= 0; }

  private:
    int listen_fd_{-1};
    uint16_t port_{0};
};

class HealthIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_root() {
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

} // namespace
} // namespace securecloud::common
