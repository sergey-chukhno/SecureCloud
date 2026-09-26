#include "gateway_config.hpp"
#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "grpc/client_call_context.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
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
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
#ifdef DeleteFile
#undef DeleteFile
#endif

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

namespace securecloud::gateway::grpc {
namespace {

constexpr std::chrono::milliseconds k_shutdown_timeout{500};
constexpr std::chrono::milliseconds k_test_call_timeout{3000};

std::string read_file_content(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

class ControllableAuthService final : public securecloud::auth::v1::AuthService::Service {
  public:
    std::atomic<bool> delay_rpc{false};
    std::atomic<int> delay_ms{0};
    std::atomic<bool> server_observed_cancellation{false};
    std::atomic<int> rpc_invocations{0};

    void reset_state() {
        delay_rpc.store(false);
        delay_ms.store(0);
        server_observed_cancellation.store(false);
        rpc_invocations.store(0);
    }

    ::grpc::Status ValidateSession(::grpc::ServerContext* context,
                                   const securecloud::auth::v1::ValidateSessionRequest* request,
                                   securecloud::auth::v1::ValidateSessionResponse* response) override {
        rpc_invocations.fetch_add(1);

        if (delay_rpc.load()) {
            int remaining_ms = delay_ms.load();
            while (remaining_ms > 0) {
                if (context->IsCancelled()) {
                    server_observed_cancellation.store(true);
                    return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Call cancelled by client");
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                remaining_ms -= 20;
            }
            if (context->IsCancelled()) {
                server_observed_cancellation.store(true);
                return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Call cancelled by client");
            }
        }

        response->set_is_valid(true);
        response->set_user_id("verified-user-123");
        response->set_device_id("verified-device-456");
        response->set_authentication_level(securecloud::auth::v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        (void)request;
        return ::grpc::Status::OK;
    }

    ::grpc::Status Authenticate(::grpc::ServerContext* /*context*/,
                                const securecloud::auth::v1::AuthenticateRequest* request,
                                securecloud::auth::v1::AuthenticateResponse* response) override {
        rpc_invocations.fetch_add(1);
        response->set_session_id("live-session-789");
        response->set_access_token("live-jwt-token");
        response->set_refresh_token("live-refresh-token");
        response->set_user_id("verified-user-123");
        (void)request;
        return ::grpc::Status::OK;
    }
};

class GatewayAuthGrpcIntegrationTest : public ::testing::Test {
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
        mock_service_.reset_state();

        pki_root_ = find_pki_root();
        ca_path_ = pki_root_ / "ca" / "ca.crt";
        auth_cert_path_ = pki_root_ / "services" / "auth" / "auth.crt";
        auth_key_path_ = pki_root_ / "services" / "auth" / "auth.key";
        gateway_cert_path_ = pki_root_ / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root_ / "services" / "gateway" / "gateway.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_, auth_cert_path_, auth_key_path_, gateway_cert_path_, gateway_key_path_,
        };

        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Required dev PKI credential missing: " << path;
        }

        auth_server_creds_ = common::security::SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = auth_cert_path_,
            .service_key_path = auth_key_path_,
        };

        gateway_client_creds_ = common::security::SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        start_auth_server();
        setup_gateway_client();
    }

    void TearDown() override {
        client_.reset();
        if (channel_manager_) {
            channel_manager_->reset();
            channel_manager_.reset();
        }
        stop_auth_server();
    }

    void start_auth_server(int fixed_port = 0) {
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(auth_server_creds_);
        ASSERT_NE(server_creds, nullptr);

        ::grpc::ServerBuilder builder;
        int port = 0;
        std::string listen_addr = (fixed_port > 0) ? ("127.0.0.1:" + std::to_string(fixed_port)) : "127.0.0.1:0";
        builder.AddListeningPort(listen_addr, server_creds, &port);
        builder.RegisterService(&mock_service_);

        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        ASSERT_GT(port, 0);

        server_port_ = port;
        server_endpoint_ = "127.0.0.1:" + std::to_string(port);
    }

    void stop_auth_server() {
        if (server_) {
            server_->Shutdown(std::chrono::system_clock::now() + k_shutdown_timeout);
            server_->Wait();
            server_.reset();
        }
    }

    void setup_gateway_client() {
        channel_manager_ = std::make_unique<GrpcChannelManager>(
            gateway_client_creds_, server_endpoint_, "127.0.0.1:50053", "127.0.0.1:50054", "127.0.0.1:50055");
        auto auth_channel = channel_manager_->get_auth_channel();
        ASSERT_NE(auth_channel, nullptr);
        client_ = std::make_unique<AuthServiceClient>(auth_channel);
    }

    std::filesystem::path pki_root_;
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    common::security::SecurityCredentialsConfig auth_server_creds_;
    common::security::SecurityCredentialsConfig gateway_client_creds_;

    ControllableAuthService mock_service_;
    std::unique_ptr<::grpc::Server> server_;
    int server_port_ = 0;
    std::string server_endpoint_;

    std::unique_ptr<GrpcChannelManager> channel_manager_;
    std::unique_ptr<AuthServiceClient> client_;
};

// ============================================================================
// Test Case 1: Live mTLS Handshake & RPC Success
// ============================================================================

TEST_F(GatewayAuthGrpcIntegrationTest, LiveMtlsHandshakeAndRpcSuccess) {
    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("active-session-123");
    req.set_access_token("valid-jwt");

    ClientCallContext ctx(k_test_call_timeout);
    auto result = client_->validate_session(req, ctx);

    ASSERT_TRUE(result.has_value()) << "mTLS RPC failed: " << (result.has_error() ? result.error().message : "");
    EXPECT_TRUE(result.value().is_valid());
    EXPECT_EQ(result.value().user_id(), "verified-user-123");
    EXPECT_EQ(result.value().device_id(), "verified-device-456");
    EXPECT_EQ(result.value().authentication_level(), securecloud::auth::v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    EXPECT_EQ(mock_service_.rpc_invocations.load(), 1);
}

// ============================================================================
// Test Case 2: Strict SAN Mismatch Rejection
// ============================================================================

TEST_F(GatewayAuthGrpcIntegrationTest, StrictSanMismatchFailsClosed) {
    // Connect to Auth server address, but override expected SAN to a mismatched identity
    auto bad_san_channel = common::security::MtlsCredentialLoader::create_mtls_channel(
        server_endpoint_, gateway_client_creds_, "wrong_service");
    AuthServiceClient bad_client(bad_san_channel);

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("session-1");
    req.set_access_token("token-1");

    ClientCallContext ctx(std::chrono::milliseconds(1000));
    auto result = bad_client.validate_session(req, ctx);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::ServiceUnavailable);
}

// ============================================================================
// Test Case 3: Untrusted Client Certificate Rejected
// ============================================================================

TEST_F(GatewayAuthGrpcIntegrationTest, UntrustedClientCertificateRejected) {
    // Client connects with CA trust only (missing/omitting client certificate)
    std::string ca_pem = read_file_content(ca_path_);
    ::grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca_pem;
    auto client_creds = ::grpc::SslCredentials(ssl_opts);

    ::grpc::ChannelArguments ch_args;
    ch_args.SetSslTargetNameOverride("auth");
    auto unauthenticated_channel = ::grpc::CreateCustomChannel(server_endpoint_, client_creds, ch_args);
    AuthServiceClient unauthenticated_client(unauthenticated_channel);

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("session-unauthed");

    ClientCallContext ctx(std::chrono::milliseconds(1000));
    auto result = unauthenticated_client.validate_session(req, ctx);

    // Handshake must fail closed because server strictly requires client certificate
    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::ServiceUnavailable);
}

// ============================================================================
// Test Case 4: Deadline Enforcement
// ============================================================================

TEST_F(GatewayAuthGrpcIntegrationTest, ClientCallContextDeadlineEnforced) {
    // Server simulates 400ms delay
    mock_service_.delay_rpc.store(true);
    mock_service_.delay_ms.store(400);

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("slow-session");

    // Client deadline set to 100ms
    ClientCallContext ctx(std::chrono::milliseconds(100));
    auto start_tp = std::chrono::steady_clock::now();
    auto result = client_->validate_session(req, ctx);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_tp);

    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, DependencyErrorKind::Timeout);
    EXPECT_EQ(result.error().grpc_code, ::grpc::StatusCode::DEADLINE_EXCEEDED);
    EXPECT_LT(elapsed.count(), 350); // Aborted well before the 400ms server sleep finished
}

// ============================================================================
// Test Case 5: Cancellation Propagation
// ============================================================================

TEST_F(GatewayAuthGrpcIntegrationTest, ClientCallContextCancellationPropagated) {
    // Server simulates delay allowing cancellation
    mock_service_.delay_rpc.store(true);
    mock_service_.delay_ms.store(600);

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("cancel-session");

    ClientCallContext ctx(std::chrono::milliseconds(3000));

    auto async_call = std::async(std::launch::async, [&]() { return client_->validate_session(req, ctx); });

    // Allow call to establish on the wire, then trigger client cancellation
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    ctx.cancel();
    EXPECT_TRUE(ctx.is_cancelled());

    auto result = async_call.get();
    ASSERT_TRUE(result.has_error());

    // Give server thread a moment to register cancellation
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(mock_service_.server_observed_cancellation.load());
}

// ============================================================================
// Test Case 6: Server Outage & Reconnection Recovery
// ============================================================================

TEST_F(GatewayAuthGrpcIntegrationTest, ServerOutageAndReconnectionRecovery) {
    // 1. Initial RPC succeeds
    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("session-recovery");
    ClientCallContext ctx1(k_test_call_timeout);
    auto res1 = client_->validate_session(req, ctx1);
    ASSERT_TRUE(res1.has_value());

    // 2. Shut down server
    stop_auth_server();

    // 3. Next RPC fails immediately with ServiceUnavailable
    ClientCallContext ctx2(std::chrono::milliseconds(200));
    auto res2 = client_->validate_session(req, ctx2);
    ASSERT_TRUE(res2.has_error());
    EXPECT_EQ(res2.error().kind, DependencyErrorKind::ServiceUnavailable);

    // 4. Restart server on same endpoint address
    start_auth_server(server_port_);

    // 5. Reconnect channel manager and verify subsequent RPC succeeds
    bool reconnected = channel_manager_->reconnect(GrpcChannelManager::k_service_auth);
    EXPECT_TRUE(reconnected);
    EXPECT_TRUE(
        channel_manager_->wait_for_connected(GrpcChannelManager::k_service_auth, std::chrono::milliseconds(2000)));
    client_ = std::make_unique<AuthServiceClient>(channel_manager_->get_auth_channel());

    ClientCallContext ctx3(k_test_call_timeout);
    auto res3 = client_->validate_session(req, ctx3);
    ASSERT_TRUE(res3.has_value()) << "Reconnected RPC failed: " << (res3.has_error() ? res3.error().message : "");
    EXPECT_TRUE(res3.value().is_valid());
}

} // namespace
} // namespace securecloud::gateway::grpc

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
