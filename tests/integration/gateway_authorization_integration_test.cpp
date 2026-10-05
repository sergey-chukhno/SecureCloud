#include "gateway_config.hpp"
#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "http/auth/authentication_middleware.hpp"
#include "http/auth/authorization_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/token_validator_interface.hpp"
#include "http/middleware/logging_middleware.hpp"
#include "http/middleware/request_id_middleware.hpp"
#include "http/middleware/resource_limiter_middleware.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/routing/gateway_route_registrar.hpp"
#include "http/routing/router.hpp"
#include "http/server/https_server.hpp"
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
#include <unordered_map>
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
constexpr int k_http_status_unauthorized = 401;
constexpr int k_http_status_forbidden = 403;

constexpr auto k_shutdown_timeout = std::chrono::milliseconds(500);
constexpr auto k_client_timeout = std::chrono::milliseconds(4000);
constexpr const char* k_loopback_address = "127.0.0.1";

/**
 * @brief Mock backend AuthService verifying downstream dispatch counts.
 */
class ControllableAuthService final : public securecloud::auth::v1::AuthService::Service {
  public:
    std::atomic<int> authenticate_invocations{0};
    std::atomic<int> revoke_invocations{0};
    std::atomic<int> register_device_invocations{0};

    void reset_state() {
        authenticate_invocations.store(0);
        revoke_invocations.store(0);
        register_device_invocations.store(0);
    }

    ::grpc::Status Authenticate(::grpc::ServerContext* /*context*/,
                                const securecloud::auth::v1::AuthenticateRequest* request,
                                securecloud::auth::v1::AuthenticateResponse* response) override {
        authenticate_invocations.fetch_add(1);
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

    ::grpc::Status RevokeSession(::grpc::ServerContext* /*context*/,
                                 const securecloud::auth::v1::RevokeSessionRequest* /*request*/,
                                 securecloud::auth::v1::RevokeSessionResponse* response) override {
        revoke_invocations.fetch_add(1);
        response->set_revoked(true);
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

/**
 * @brief Controllable token validator allowing precise testing of scopes, assurance, and device binding.
 */
class ControllableTokenValidator final : public http::ITokenValidator {
  public:
    struct TokenClaims {
        std::string user_id{"user-alice-live"};
        std::string device_id{"dev-live-01"};
        securecloud::auth::v1::AuthenticationLevel auth_level{
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY};
        std::vector<std::string> scopes;
        int64_t expires_at_epoch_ms{2000000000000LL};
    };

    std::unordered_map<std::string, TokenClaims> tokens;

    http::AuthenticatedResult validate(const std::string& token, const std::string& session_id,
                                       const std::string& /*request_id*/) override {
        auto it = tokens.find(token);
        if (it == tokens.end()) {
            return http::TokenValidationError{http::TokenValidationErrorKind::InvalidSignature, "Invalid token"};
        }
        const auto& c = it->second;
        return http::AuthenticatedContext(c.user_id, c.device_id, session_id.empty() ? "sess-authz-live" : session_id,
                                          c.auth_level, c.scopes, c.expires_at_epoch_ms);
    }
};

class GatewayAuthorizationIntegrationTest : public ::testing::Test {
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

        populate_tokens();
        start_auth_server();
        setup_gateway();
    }

    void TearDown() override {
        stop_gateway();
        stop_auth_server();
    }

    void populate_tokens() {
        token_validator_ = std::make_shared<ControllableTokenValidator>();

        // 1. Exact scope: auth:revoke
        token_validator_->tokens["token-exact-revoke"] = {
            .scopes = {"auth:revoke"},
        };

        // 2. Domain wildcard: auth:*
        token_validator_->tokens["token-wildcard-auth"] = {
            .scopes = {"auth:*"},
        };

        // 3. Global wildcard: *
        token_validator_->tokens["token-global-wildcard"] = {
            .scopes = {"*"},
        };

        // 4. Alternative scope: access
        token_validator_->tokens["token-alt-access"] = {
            .scopes = {"access"},
        };

        // 5. Insufficient scope: messages:read
        token_validator_->tokens["token-insufficient-messages"] = {
            .scopes = {"messages:read"},
        };

        // 6. Sensitive route lacking MFA: PRIMARY level
        token_validator_->tokens["token-device-reg-primary"] = {
            .device_id = "dev-live-01",
            .auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
            .scopes = {"device:manage"},
        };

        // 7. Sensitive route lacking device binding: empty device_id
        token_validator_->tokens["token-device-reg-empty-dev"] = {
            .device_id = "",
            .auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
            .scopes = {"device:manage"},
        };

        // 8. Sensitive route fully satisfied: MFA + device:manage + non-empty device_id
        token_validator_->tokens["token-device-reg-valid"] = {
            .device_id = "dev-live-01",
            .auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
            .scopes = {"device:manage"},
        };
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
        router_->use(std::make_shared<http::AuthorizationMiddleware>(security_policy_));

        health_manager_ = std::make_shared<common::health::HealthStatusManager>("gateway-authz-test");
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

    std::unique_ptr<httplib::SSLClient> create_client() const {
        auto client = std::make_unique<httplib::SSLClient>(k_loopback_address, https_port_);
        client->set_ca_cert_path(ca_path_.string().c_str());
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
    std::shared_ptr<ControllableTokenValidator> token_validator_;
    std::unique_ptr<::grpc::Server> auth_server_;
    int auth_port_{0};
    std::string auth_endpoint_;

    std::unique_ptr<grpc::GrpcChannelManager> channel_manager_;
    std::shared_ptr<grpc::AuthServiceClient> auth_client_;
    std::shared_ptr<http::GatewaySecurityPolicy> security_policy_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_;
    std::shared_ptr<http::AuthProxyHandler> auth_proxy_;
    std::unique_ptr<http::GatewayRouteRegistrar> route_registrar_;
    std::unique_ptr<http::Router> router_;
    std::unique_ptr<http::HttpsServer> https_server_;
    int https_port_{0};
};

// Scenario 1: Exact required scope grants access and dispatches to backend
TEST_F(GatewayAuthorizationIntegrationTest, ExactScopeAllowsAccessAndForwards) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-exact-revoke"}});

    auto res = client->Post("/api/v1/auth/revoke");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(mock_auth_service_.revoke_invocations.load(), 1);
}

// Scenario 2: Domain wildcard scope (auth:*) grants access to sub-actions
TEST_F(GatewayAuthorizationIntegrationTest, DomainWildcardAllowsAccessAndForwards) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-wildcard-auth"}});

    auto res = client->Post("/api/v1/auth/revoke");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(mock_auth_service_.revoke_invocations.load(), 1);
}

// Scenario 3: Global superuser wildcard scope (*) grants access to any route
TEST_F(GatewayAuthorizationIntegrationTest, GlobalWildcardAllowsAccessAndForwards) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-global-wildcard"}});

    auto res = client->Post("/api/v1/auth/revoke");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(mock_auth_service_.revoke_invocations.load(), 1);
}

// Scenario 4: Alternative scope (access) satisfies the route security rule
TEST_F(GatewayAuthorizationIntegrationTest, AlternativeScopeAllowsAccessAndForwards) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-alt-access"}});

    auto res = client->Post("/api/v1/auth/revoke");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(mock_auth_service_.revoke_invocations.load(), 1);
}

// Scenario 5: Insufficient scope rejects with 403 at perimeter with ZERO backend calls
TEST_F(GatewayAuthorizationIntegrationTest, InsufficientScopeRejectsAtPerimeterWithoutForwarding) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-insufficient-messages"}});

    auto res = client->Post("/api/v1/auth/revoke");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_forbidden);

    // Invariant: Backend gRPC microservice receives ZERO calls
    EXPECT_EQ(mock_auth_service_.revoke_invocations.load(), 0);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "INSUFFICIENT_SCOPE");
    EXPECT_EQ(j["type"], "https://securecloud.internal/errors/insufficient-scope");
    ASSERT_TRUE(j.contains("missing_scopes"));
    ASSERT_FALSE(j["missing_scopes"].empty());
    EXPECT_EQ(j["missing_scopes"][0], "auth:revoke");
}

// Scenario 6: Sensitive route lacking MFA assurance rejects with 403 at perimeter
TEST_F(GatewayAuthorizationIntegrationTest, SensitiveRouteLackingMfaRejectsAtPerimeter) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-device-reg-primary"}});

    nlohmann::json device_body = {
        {"device_type", "DEVICE_TYPE_MOBILE"},
        {"operating_system", "iOS 18"},
        {"public_key", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0..."},
    };

    auto res = client->Post("/api/v1/auth/device/register", device_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_forbidden);

    // Invariant: Backend receives ZERO calls
    EXPECT_EQ(mock_auth_service_.register_device_invocations.load(), 0);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "MFA_REQUIRED");
    EXPECT_EQ(j["type"], "https://securecloud.internal/errors/mfa-required");
}

// Scenario 7: Sensitive route lacking device binding rejects with 403 at perimeter
TEST_F(GatewayAuthorizationIntegrationTest, SensitiveRouteLackingDeviceBindingRejectsAtPerimeter) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-device-reg-empty-dev"}});

    nlohmann::json device_body = {
        {"device_type", "DEVICE_TYPE_MOBILE"},
        {"operating_system", "iOS 18"},
        {"public_key", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0..."},
    };

    auto res = client->Post("/api/v1/auth/device/register", device_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_forbidden);

    // Invariant: Backend receives ZERO calls
    EXPECT_EQ(mock_auth_service_.register_device_invocations.load(), 0);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "DEVICE_BINDING_REQUIRED");
    EXPECT_EQ(j["type"], "https://securecloud.internal/errors/device-binding-required");
}

// Scenario 8: Sensitive route with MFA and Device Binding forwards successfully
TEST_F(GatewayAuthorizationIntegrationTest, SensitiveRouteWithMfaAndDeviceBindingForwards) {
    auto client = create_client();
    client->set_default_headers({{"Authorization", "Bearer token-device-reg-valid"}});

    nlohmann::json device_body = {
        {"device_type", "DEVICE_TYPE_MOBILE"},
        {"operating_system", "iOS 18"},
        {"public_key", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0..."},
    };

    auto res = client->Post("/api/v1/auth/device/register", device_body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_created);
    EXPECT_EQ(mock_auth_service_.register_device_invocations.load(), 1);
}

// Scenario 9: Public routes bypass authorization without credentials
TEST_F(GatewayAuthorizationIntegrationTest, PublicRoutesBypassAuthorization) {
    auto client = create_client();

    auto res_health = client->Get("/health/live");
    ASSERT_TRUE(res_health);
    EXPECT_EQ(res_health->status, k_http_status_ok);

    nlohmann::json login_body = {
        {"identifier", "alice@securecloud.org"},
        {"credential", "CorrectPassword123!"},
    };

    auto res_login = client->Post("/api/v1/auth/login", login_body.dump(), "application/json");
    ASSERT_TRUE(res_login);
    EXPECT_EQ(res_login->status, k_http_status_ok);
    EXPECT_EQ(mock_auth_service_.authenticate_invocations.load(), 1);
}

// Scenario 10: Missing token on protected route rejects with 401 without forwarding
TEST_F(GatewayAuthorizationIntegrationTest, MissingTokenOnProtectedRouteRejects401) {
    auto client = create_client();

    auto res = client->Post("/api/v1/auth/revoke");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_unauthorized);

    // Invariant: Backend receives ZERO calls
    EXPECT_EQ(mock_auth_service_.revoke_invocations.load(), 0);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_EQ(j["error"]["code"], "UNAUTHENTICATED");
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
