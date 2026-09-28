#include "gateway_config.hpp"
#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "http/auth/auth_service_token_validator.hpp"
#include "http/auth/authentication_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/gateway_route_registrar.hpp"
#include "http/https_server.hpp"
#include "http/middleware/logging_middleware.hpp"
#include "http/middleware/request_id_middleware.hpp"
#include "http/middleware/resource_limiter_middleware.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/router.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/security/mtls_config.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

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

namespace securecloud::gateway {
namespace {

constexpr int k_http_status_ok = 200;
constexpr int k_http_status_created = 201;
constexpr int k_http_status_bad_request = 400;
constexpr int k_http_status_unauthorized = 401;
constexpr int k_http_status_forbidden = 403;
constexpr int k_http_status_not_implemented = 501;
constexpr int k_http_status_service_unavailable = 503;

constexpr auto k_shutdown_timeout = std::chrono::milliseconds(500);
constexpr auto k_client_timeout = std::chrono::milliseconds(4000);
constexpr const char* k_loopback_address = "127.0.0.1";

class ControllableAuthService final : public securecloud::auth::v1::AuthService::Service {
  public:
    std::atomic<bool> is_valid{true};
    std::atomic<bool> force_auth_error{false};
    std::atomic<securecloud::auth::v1::AuthenticationLevel> auth_level{
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED};

    std::atomic<int> authenticate_invocations{0};
    std::atomic<int> validate_invocations{0};
    std::atomic<int> refresh_invocations{0};
    std::atomic<int> revoke_invocations{0};
    std::atomic<int> get_user_invocations{0};
    std::atomic<int> register_device_invocations{0};

    std::string last_revoked_session;

    void reset_state() {
        is_valid.store(true);
        force_auth_error.store(false);
        auth_level.store(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        authenticate_invocations.store(0);
        validate_invocations.store(0);
        refresh_invocations.store(0);
        revoke_invocations.store(0);
        get_user_invocations.store(0);
        register_device_invocations.store(0);
        last_revoked_session.clear();
    }

    ::grpc::Status Authenticate(::grpc::ServerContext* /*context*/,
                                const securecloud::auth::v1::AuthenticateRequest* request,
                                securecloud::auth::v1::AuthenticateResponse* response) override {
        authenticate_invocations.fetch_add(1);
        if (force_auth_error.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "Invalid credentials");
        }
        if (request->credential_identifier().empty() || request->password().empty()) {
            return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Missing credential identifier or password");
        }
        response->set_session_id("sess-live-alice-123");
        response->set_access_token("valid-access-token-live");
        response->set_refresh_token("valid-refresh-token-live");
        response->set_authentication_level(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
        response->set_user_id("user-alice-live");
        response->set_expires_at_epoch_ms(2000000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status ValidateSession(::grpc::ServerContext* /*context*/,
                                   const securecloud::auth::v1::ValidateSessionRequest* request,
                                   securecloud::auth::v1::ValidateSessionResponse* response) override {
        validate_invocations.fetch_add(1);
        if (!is_valid.load() || request->access_token() == "invalid-token") {
            response->set_is_valid(false);
            return ::grpc::Status::OK;
        }
        response->set_is_valid(true);
        response->set_user_id("user-alice-live");
        response->set_device_id("dev-live-01");
        response->set_authentication_level(auth_level.load());
        response->set_expires_at_epoch_ms(2000000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status RefreshSession(::grpc::ServerContext* /*context*/,
                                  const securecloud::auth::v1::RefreshSessionRequest* request,
                                  securecloud::auth::v1::RefreshSessionResponse* response) override {
        refresh_invocations.fetch_add(1);
        if (request->refresh_token() != "valid-refresh-token-live") {
            return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "Invalid refresh token");
        }
        response->set_session_id("sess-refreshed-live");
        response->set_access_token("valid-access-token-refreshed");
        response->set_new_refresh_token("valid-refresh-token-refreshed");
        response->set_expires_at_epoch_ms(2100000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status RevokeSession(::grpc::ServerContext* /*context*/,
                                 const securecloud::auth::v1::RevokeSessionRequest* request,
                                 securecloud::auth::v1::RevokeSessionResponse* response) override {
        revoke_invocations.fetch_add(1);
        last_revoked_session = request->session_id();
        response->set_revoked(true);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetUser(::grpc::ServerContext* /*context*/, const securecloud::auth::v1::GetUserRequest* request,
                           securecloud::auth::v1::GetUserResponse* response) override {
        get_user_invocations.fetch_add(1);
        auto* u = response->mutable_user();
        u->set_user_id(request->user_id());
        u->set_credential_identifier("alice@securecloud.org");
        u->set_account_status(securecloud::auth::v1::AccountStatus::ACCOUNT_STATUS_ACTIVE);
        u->set_created_at_epoch_ms(1700000000000LL);
        u->set_updated_at_epoch_ms(1705000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status RegisterDevice(::grpc::ServerContext* /*context*/,
                                  const securecloud::auth::v1::RegisterDeviceRequest* /*request*/,
                                  securecloud::auth::v1::RegisterDeviceResponse* response) override {
        register_device_invocations.fetch_add(1);
        response->set_device_id("dev-enrolled-live-99");
        response->set_status(securecloud::auth::v1::DeviceStatus::DEVICE_STATUS_ACTIVE);
        response->set_registered_at_epoch_ms(1720000000000LL);
        return ::grpc::Status::OK;
    }
};

class GatewayRoutingIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_dir() {
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
        mock_auth_service_.reset_state();

        pki_root_ = find_pki_dir();
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

        start_auth_server();
        setup_gateway();
    }

    void TearDown() override {
        stop_gateway();
        stop_auth_server();
    }

    void start_auth_server() {
        common::security::SecurityCredentialsConfig auth_creds{
            .ca_cert_path = ca_path_,
            .service_cert_path = auth_cert_path_,
            .service_key_path = auth_key_path_,
        };
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(auth_creds);
        ASSERT_NE(server_creds, nullptr);

        ::grpc::ServerBuilder builder;
        int port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &port);
        builder.RegisterService(&mock_auth_service_);

        auth_server_ = builder.BuildAndStart();
        ASSERT_NE(auth_server_, nullptr);
        ASSERT_GT(port, 0);

        auth_port_ = port;
        auth_endpoint_ = "127.0.0.1:" + std::to_string(port);
    }

    void stop_auth_server() {
        if (auth_server_) {
            auth_server_->Shutdown(std::chrono::system_clock::now() + k_shutdown_timeout);
            auth_server_->Wait();
            auth_server_.reset();
        }
    }

    void setup_gateway() {
        common::security::SecurityCredentialsConfig gateway_mTLS_creds{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        channel_manager_ = std::make_unique<grpc::GrpcChannelManager>(
            gateway_mTLS_creds, auth_endpoint_, "127.0.0.1:50053", "127.0.0.1:50054", "127.0.0.1:50055");
        auto auth_channel = channel_manager_->get_auth_channel();
        ASSERT_NE(auth_channel, nullptr);
        auth_client_ = std::make_shared<grpc::AuthServiceClient>(auth_channel);

        http::TokenValidatorOptions validator_opts{
            .rpc_timeout = std::chrono::milliseconds(2000),
            .cache_ttl = std::chrono::seconds(2),
            .max_cache_entries = 100,
        };
        token_validator_ = std::make_shared<http::AuthServiceTokenValidator>(auth_client_, validator_opts);

        security_policy_ = std::make_shared<http::GatewaySecurityPolicy>(http::GatewaySecurityPolicy::create_default());

        GatewayConfig cfg;
        cfg.http_listen_address = k_loopback_address;
        cfg.http_listen_port = 0;
        cfg.server_threads = 4;
        cfg.request_timeout_ms = std::chrono::milliseconds(5000);

        cfg.tls.enabled = true;
        cfg.tls.cert_path = gateway_cert_path_.string();
        cfg.tls.key_path = gateway_key_path_.string();
        cfg.tls.ca_chain_path = ca_path_.string();
        cfg.tls.https_listen_port = 0;
        cfg.tls.min_tls_version = "TLSv1.3";
        cfg.tls.cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

        router_ = std::make_unique<http::Router>();
        router_->use(std::make_shared<http::RequestIdMiddleware>());
        router_->use(std::make_shared<http::LoggingMiddleware>());
        router_->use(std::make_shared<http::ResourceLimiterMiddleware>(cfg));
        router_->use(std::make_shared<http::AuthenticationMiddleware>(security_policy_, token_validator_));

        health_manager_ = std::make_shared<common::health::HealthStatusManager>("gateway-routing-test");
        health_manager_->set_live(true);
        health_manager_->set_ready(true);

        auth_proxy_ = std::make_shared<http::AuthProxyHandler>(auth_client_);
        route_registrar_ = std::make_unique<http::GatewayRouteRegistrar>(auth_proxy_, health_manager_);
        route_registrar_->register_all_routes(*router_);

        https_server_ = std::make_unique<http::HttpsServer>(cfg);
        router_->register_into(*https_server_);

        bool started = https_server_->start(k_loopback_address, 0);
        ASSERT_TRUE(started);
        https_port_ = https_server_->bound_port();
        ASSERT_GT(https_port_, 0);
    }

    void stop_gateway() {
        if (https_server_) {
            https_server_->stop();
            https_server_.reset();
        }
        router_.reset();
        route_registrar_.reset();
        auth_proxy_.reset();
        auth_client_.reset();
        if (channel_manager_) {
            channel_manager_->reset();
            channel_manager_.reset();
        }
    }

    std::unique_ptr<httplib::SSLClient> create_client() {
        auto client = std::make_unique<httplib::SSLClient>(k_loopback_address, https_port_);
        client->set_ca_cert_path(ca_path_.string());
        client->enable_server_certificate_verification(true);
        client->enable_server_hostname_verification(false);
        client->set_connection_timeout(k_client_timeout);
        client->set_read_timeout(k_client_timeout);
        client->set_write_timeout(k_client_timeout);
        return client;
    }

    std::filesystem::path pki_root_;
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    ControllableAuthService mock_auth_service_;
    std::unique_ptr<::grpc::Server> auth_server_;
    int auth_port_{0};
    std::string auth_endpoint_;

    std::unique_ptr<grpc::GrpcChannelManager> channel_manager_;
    std::shared_ptr<grpc::AuthServiceClient> auth_client_;
    std::shared_ptr<http::AuthServiceTokenValidator> token_validator_;
    std::shared_ptr<http::GatewaySecurityPolicy> security_policy_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_;
    std::shared_ptr<http::AuthProxyHandler> auth_proxy_;
    std::unique_ptr<http::GatewayRouteRegistrar> route_registrar_;
    std::unique_ptr<http::Router> router_;
    std::unique_ptr<http::HttpsServer> https_server_;
    uint16_t https_port_{0};
};

// ============================================================================
// Integration Test Cases
// ============================================================================

TEST_F(GatewayRoutingIntegrationTest, LivePublicLoginSuccess) {
    auto client = create_client();

    nlohmann::json login_body = {
        {"identifier", "alice@securecloud.org"},
        {"credential", "CorrectPassword123!"},
        {"device_id", "dev-client-1"},
    };

    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");
    EXPECT_TRUE(res->has_header("X-Request-Id"));

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["session_id"], "sess-live-alice-123");
    EXPECT_EQ(j["access_token"], "valid-access-token-live");
    EXPECT_EQ(j["refresh_token"], "valid-refresh-token-live");
    EXPECT_EQ(j["user_id"], "user-alice-live");
    EXPECT_EQ(mock_auth_service_.authenticate_invocations.load(), 1);
}

TEST_F(GatewayRoutingIntegrationTest, LivePublicRefreshSuccess) {
    auto client = create_client();

    nlohmann::json refresh_body = {
        {"refresh_token", "valid-refresh-token-live"},
        {"device_id", "dev-client-1"},
    };

    auto res = client->Post("/api/v1/auth/refresh", refresh_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["session_id"], "sess-refreshed-live");
    EXPECT_EQ(j["access_token"], "valid-access-token-refreshed");
    EXPECT_EQ(j["refresh_token"], "valid-refresh-token-refreshed");
    EXPECT_EQ(mock_auth_service_.refresh_invocations.load(), 1);
}

TEST_F(GatewayRoutingIntegrationTest, LiveProtectedRevokeSuccess) {
    auto client = create_client();

    httplib::Headers headers = {
        {"Authorization", "Bearer valid-access-token-live"},
        {"X-Session-Id", "sess-live-alice-123"},
    };

    nlohmann::json revoke_body = {
        {"session_id", "sess-live-alice-123"},
        {"reason", "User requested logout"},
    };

    auto res = client->Post("/api/v1/auth/revoke", headers, revoke_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_TRUE(j["revoked"].get<bool>());
    EXPECT_EQ(mock_auth_service_.revoke_invocations.load(), 1);
    EXPECT_EQ(mock_auth_service_.last_revoked_session, "sess-live-alice-123");
}

TEST_F(GatewayRoutingIntegrationTest, LiveProtectedUserMeSuccess) {
    auto client = create_client();

    httplib::Headers headers = {
        {"Authorization", "Bearer valid-access-token-live"},
    };

    auto res = client->Get("/api/v1/users/me", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["user"]["user_id"], "user-alice-live");
    EXPECT_EQ(j["user"]["credential_identifier"], "alice@securecloud.org");
    EXPECT_EQ(mock_auth_service_.get_user_invocations.load(), 1);
}

TEST_F(GatewayRoutingIntegrationTest, LiveProtectedAuthMeAliasSuccess) {
    auto client = create_client();

    httplib::Headers headers = {
        {"Authorization", "Bearer valid-access-token-live"},
    };

    auto res = client->Get("/api/v1/auth/me", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["user"]["user_id"], "user-alice-live");
    EXPECT_EQ(j["user"]["credential_identifier"], "alice@securecloud.org");
}

TEST_F(GatewayRoutingIntegrationTest, LiveSensitiveDeviceRegistrationMfaEnforcement) {
    auto client = create_client();

    nlohmann::json dev_body = {
        {"identity_key", "pub-identity-key-data"},
        {"signed_prekey", "pub-signed-prekey-data"},
        {"signed_prekey_signature", "pub-sig"},
        {"one_time_prekeys", {"opk1", "opk2"}},
    };

    // 1. Primary auth level only (without MFA) -> rejected with 403 Forbidden
    mock_auth_service_.auth_level.store(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    token_validator_->clear_cache();

    httplib::Headers headers = {
        {"Authorization", "Bearer valid-access-token-live"},
    };

    auto res_forbidden = client->Post("/api/v1/auth/device/register", headers, dev_body.dump(), "application/json");
    ASSERT_TRUE(res_forbidden);
    EXPECT_EQ(res_forbidden->status, k_http_status_forbidden);
    auto j_err = nlohmann::json::parse(res_forbidden->body);
    EXPECT_EQ(j_err["error"]["code"], "MFA_REQUIRED");

    // 2. MFA verified auth level -> accepted with 201 Created
    mock_auth_service_.auth_level.store(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    token_validator_->clear_cache();

    auto res_created = client->Post("/api/v1/auth/device/register", headers, dev_body.dump(), "application/json");
    ASSERT_TRUE(res_created);
    EXPECT_EQ(res_created->status, k_http_status_created);

    auto j_ok = nlohmann::json::parse(res_created->body);
    EXPECT_EQ(j_ok["device_id"], "dev-enrolled-live-99");
    EXPECT_EQ(mock_auth_service_.register_device_invocations.load(), 1);
}

TEST_F(GatewayRoutingIntegrationTest, LiveMalformedJsonReturns400) {
    auto client = create_client();

    auto res = client->Post("/api/v1/auth/login", "not valid json {", "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_bad_request);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "BAD_REQUEST");
}

TEST_F(GatewayRoutingIntegrationTest, LiveMissingTokenOnProtectedRouteReturns401) {
    auto client = create_client();

    // No Authorization header
    auto res = client->Get("/api/v1/users/me");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_unauthorized);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "UNAUTHENTICATED");
}

TEST_F(GatewayRoutingIntegrationTest, LiveDownstreamStubReturns501) {
    auto client = create_client();

    httplib::Headers headers = {
        {"Authorization", "Bearer valid-access-token-live"},
    };

    auto res = client->Post("/api/v1/messages/send", headers, "{}", "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_not_implemented);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "NOT_IMPLEMENTED");
}

TEST_F(GatewayRoutingIntegrationTest, LiveHealthLiveAndReady) {
    auto client = create_client();

    auto res_live = client->Get("/health/live");
    ASSERT_TRUE(res_live);
    EXPECT_EQ(res_live->status, k_http_status_ok);
    EXPECT_EQ(res_live->body, R"({"status":"SERVING"})");

    auto res_ready = client->Get("/health/ready");
    ASSERT_TRUE(res_ready);
    EXPECT_EQ(res_ready->status, k_http_status_ok);
    EXPECT_EQ(res_ready->body, R"({"status":"SERVING"})");
}

TEST_F(GatewayRoutingIntegrationTest, LiveUpstreamAuthOutageReturns503) {
    // Intentionally shut down backend auth service
    stop_auth_server();

    auto client = create_client();

    nlohmann::json login_body = {
        {"identifier", "alice@securecloud.org"},
        {"credential", "CorrectPassword123!"},
    };

    auto res = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_service_unavailable);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "SERVICE_UNAVAILABLE");
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
