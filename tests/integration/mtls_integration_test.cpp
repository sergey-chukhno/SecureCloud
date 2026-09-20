#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace securecloud::common::security {
namespace {

using health::HealthServiceImpl;
using health::HealthStatusManager;

std::string read_file_content(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

class MtlsIntegrationTest : public ::testing::Test {
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
    start_mtls_server(health::HealthServiceImpl* service_impl, const SecurityCredentialsConfig& server_config) {
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

    health::HealthStatusManager health_manager_{"auth"};
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

TEST_F(MtlsIntegrationTest, PositiveValidGatewayToAuthMtlsSucceeds) {
    health::HealthServiceImpl health_service("auth", health_manager_, "gateway");
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "auth");
    auto stub = securecloud::common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    securecloud::common::v1::HealthCheckRequest request;
    securecloud::common::v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_TRUE(status.ok()) << "RPC failed: " << status.error_message();
    EXPECT_EQ(response.status(), securecloud::common::v1::HealthCheckResponse::SERVING);

    server->Shutdown();
}

TEST_F(MtlsIntegrationTest, NegativeUntrustedCaFailsClosed) {
    health::HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    // Create temp directory for untrusted fake CA
    auto temp_dir = std::filesystem::temp_directory_path() / "untrusted_ca_test";
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
    auto stub = securecloud::common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));
    securecloud::common::v1::HealthCheckRequest request;
    securecloud::common::v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.error_code(), grpc::StatusCode::OK);

    server->Shutdown();
    std::filesystem::remove_all(temp_dir);
}

TEST_F(MtlsIntegrationTest, NegativeMissingClientCertificateFailsClosed) {
    health::HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    // Create client TLS channel with CA trust ONLY (no client cert/key)
    std::string ca_pem = read_file_content(ca_path_);
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca_pem;
    auto client_creds = grpc::SslCredentials(ssl_opts);

    grpc::ChannelArguments ch_args;
    ch_args.SetSslTargetNameOverride("auth");
    auto channel = grpc::CreateCustomChannel(server_address, client_creds, ch_args);
    auto stub = securecloud::common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));
    securecloud::common::v1::HealthCheckRequest request;
    securecloud::common::v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok()) << "Server unexpectedly accepted missing client certificate";

    server->Shutdown();
}

TEST_F(MtlsIntegrationTest, NegativeServerSanMismatchFailsClosed) {
    health::HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    // Client expects target SAN identity "messaging", but server presents "auth"
    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, gateway_config_, "messaging");
    auto stub = securecloud::common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));
    securecloud::common::v1::HealthCheckRequest request;
    securecloud::common::v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok()) << "RPC unexpectedly succeeded when server SAN mismatched target SAN override";

    server->Shutdown();
}

TEST_F(MtlsIntegrationTest, NegativeWrongClientIdentityRejectedPostHandshake) {
    // Server requires peer SAN identity "gateway"
    health::HealthServiceImpl health_service("auth", health_manager_, "gateway");
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    // Client presents trusted "audit" service certificate
    auto channel = MtlsCredentialLoader::create_mtls_channel(server_address, audit_config_, "auth");
    auto stub = securecloud::common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));
    securecloud::common::v1::HealthCheckRequest request;
    securecloud::common::v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok());
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_EQ(status.error_message(), "Peer service identity mismatch");

    server->Shutdown();
}

TEST_F(MtlsIntegrationTest, NegativePlaintextConnectionAttackRejected) {
    health::HealthServiceImpl health_service("auth", health_manager_);
    auto [server, server_address] = start_mtls_server(&health_service, auth_config_);

    // Client attempts insecure connection
    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    auto stub = securecloud::common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));
    securecloud::common::v1::HealthCheckRequest request;
    securecloud::common::v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    EXPECT_FALSE(status.ok()) << "Plaintext client connection was unexpectedly accepted by mTLS server";

    server->Shutdown();
}

TEST_F(MtlsIntegrationTest, NegativeMismatchedKeyCertStartupFailsClosed) {
    // Mismatched config: auth cert with gateway key
    SecurityCredentialsConfig mismatched_config{
        .ca_cert_path = ca_path_,
        .service_cert_path = auth_cert_path_,
        .service_key_path = gateway_key_path_,
    };

    auto server_creds = MtlsCredentialLoader::create_server_credentials(mismatched_config);
    EXPECT_NE(server_creds, nullptr);

    health::HealthServiceImpl health_service("auth", health_manager_);
    grpc::ServerBuilder builder;
    int selected_port = 0;
    builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
    builder.RegisterService(&health_service);

    auto server = builder.BuildAndStart();
    if (server) {
        // If server started, connection attempt with valid client must fail due to key/cert mismatch at handshake
        auto channel = MtlsCredentialLoader::create_mtls_channel("127.0.0.1:" + std::to_string(selected_port),
                                                                 gateway_config_, "auth");
        auto stub = securecloud::common::v1::HealthService::NewStub(channel);

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));
        securecloud::common::v1::HealthCheckRequest request;
        securecloud::common::v1::HealthCheckResponse response;

        grpc::Status status = stub->Check(&context, request, &response);
        EXPECT_FALSE(status.ok());
        server->Shutdown();
    }
}

} // namespace
} // namespace securecloud::common::security
