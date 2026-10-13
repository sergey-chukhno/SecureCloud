#include "auth/auth_config.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/crypto/base32.hpp"
#include "auth/crypto/mfa_secret_protector.hpp"
#include "auth/crypto/token_crypto.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/db/migration_runner.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/token_claims.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/mfa_repository.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/crypto_directory_manager.hpp"
#include "auth/service/device_manager.hpp"
#include "auth/service/mfa_authenticator_interface.hpp"
#include "auth/service/mfa_manager.hpp"
#include "auth/service/prekey_manager.hpp"
#include "auth/service/session_manager.hpp"
#include "auth/service/token_manager.hpp"
#include "gateway_config.hpp"
#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "http/auth/authentication_middleware.hpp"
#include "http/auth/authorization_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/local_token_verifier.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/routing/gateway_route_registrar.hpp"
#include "http/routing/router.hpp"
#include "http/server/http_server.hpp"
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

#include <chrono>
#include <filesystem>
#include <gmock/gmock.h>
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

namespace securecloud::gateway::integration::test {
namespace {

using auth::AuthConfig;
using auth::domain::AccountStatus;
using auth::domain::AuthenticationLevel;
using auth::domain::DeviceEntity;
using auth::domain::DeviceStatus;
using auth::domain::SessionEntity;
using auth::domain::SessionStatus;
using auth::domain::UserEntity;
using auth::domain::Uuid;

constexpr auto k_shutdown_timeout = std::chrono::milliseconds(500);
constexpr auto k_client_timeout = std::chrono::milliseconds(5000);
constexpr const char* k_loopback_address = "127.0.0.1";

AuthConfig make_test_auth_config() {
    AuthConfig config;
    config.db_host = "127.0.0.1";
    config.db_port = 5433; // Strictly container port 5433 (PostgreSQL 17)
    config.db_name = "securecloud_auth";
    config.db_user = "auth_user";
    config.db_password = common::configuration::SecretString("auth_dev_db_secret");
    return config;
}

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

// In-memory audit sink for integration tests
class TestAuditSink final : public auth::service::IAuditEventSink {
  public:
    void emit(const auth::domain::AuditEvent& event, std::string_view /*json_payload*/) override {
        emitted_events.push_back(event);
    }
    std::vector<auth::domain::AuditEvent> emitted_events;
};

// ============================================================================
// 1. Strict Port 5432 Protection Preflight Test
// ============================================================================

TEST(GatewayAuthE2EPreflightTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = make_test_auth_config();
    forbidden_cfg.db_port = 5432;

    auth::db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((auth::db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), auth::db::PortForbiddenException);
}

// ============================================================================
// 2. Zero Private Key Exposure & Asymmetric Cryptographic Audit Test
// ============================================================================

TEST(GatewayAuthE2ECryptoTest, ZeroPrivateKeyExposureAudit) {
    auto token_signer = std::make_shared<auth::crypto::Ed25519TokenSigner>("sc-auth-v1");
    std::string public_pem = token_signer->get_public_key_pem();
    EXPECT_THAT(public_pem, ::testing::HasSubstr("PUBLIC KEY"));
    EXPECT_THAT(public_pem, ::testing::Not(::testing::HasSubstr("PRIVATE KEY")));

    // Gateway LocalTokenVerifier strictly constructed from public key PEM
    auto verifier = http::LocalTokenVerifier::from_public_key_pem(public_pem, "sc-auth-v1");
    ASSERT_NE(verifier, nullptr);

    // 1. Valid token generated by Auth service verifies offline cleanly
    auth::domain::AccessTokenClaims valid_claims;
    const auto now = std::chrono::system_clock::now();
    valid_claims.issuer = "https://auth.securecloud.io";
    valid_claims.audience = "https://gateway.securecloud.io";
    valid_claims.user_id = Uuid::generate_v7();
    valid_claims.device_id = Uuid::generate_v7();
    valid_claims.session_id = Uuid::generate_v7();
    valid_claims.issued_at = now;
    valid_claims.expires_at = now + std::chrono::hours(1);
    valid_claims.jti = Uuid::generate_v7();
    valid_claims.scopes = {"access", "read", "write"};
    valid_claims.token_version = 1;
    valid_claims.authentication_level = auth::domain::AuthenticationLevel::PrimaryOnly;

    std::string signed_token = auth::domain::TokenEnvelopeSerializer::serialize(valid_claims, *token_signer);
    auto auth_result = verifier->validate(signed_token, valid_claims.session_id.to_string());
    ASSERT_TRUE(auth_result.has_value());
    EXPECT_EQ(auth_result.value().user_id(), valid_claims.user_id.to_string());
    EXPECT_EQ(auth_result.value().device_id(), valid_claims.device_id.to_string());

    // 2. Tampered token fails verification immediately
    std::string tampered_token = signed_token;
    auto first_dot = tampered_token.find('.');
    auto second_dot = tampered_token.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);
    tampered_token[first_dot + 2] = (tampered_token[first_dot + 2] == 'a') ? 'b' : 'a';

    auto tampered_result = verifier->validate(tampered_token, valid_claims.session_id.to_string());
    EXPECT_FALSE(tampered_result.has_value());

    // 3. Forged token signed with a different key fails verification
    auth::crypto::Ed25519TokenSigner attacker_signer("sc-attacker-key");
    std::string attacker_token = auth::domain::TokenEnvelopeSerializer::serialize(valid_claims, attacker_signer);
    auto attacker_result = verifier->validate(attacker_token, valid_claims.session_id.to_string());
    EXPECT_FALSE(attacker_result.has_value());
}

// ============================================================================
// 3. Live End-to-End Integration Suite Fixture (HTTP Gateway <-> gRPC AuthService)
// ============================================================================

class GatewayAuthE2EIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ensure_integration_winsock();

        // 1. Database Connection & Port Verification
        db_config_ = make_test_auth_config();
        ASSERT_NE(db_config_.db_port, 5432)
            << "CRITICAL ERROR: Tests must NEVER connect to host PostgreSQL on port 5432!";
        ASSERT_EQ(db_config_.db_port, 5433)
            << "Tests must strictly connect to containerized PostgreSQL 17 on port 5433!";

        auth::db::ConnectionPoolConfig pool_cfg;
        pool_cfg.min_connections = 0;
        pool_cfg.max_connections = 10;
        pool_cfg.acquire_timeout = std::chrono::milliseconds{5000};
        pool_cfg.connect_timeout = std::chrono::seconds{2};

        pool_ = std::make_unique<auth::db::PostgresConnectionPool>(db_config_, pool_cfg);
        if (!pool_->ping()) {
            GTEST_SKIP() << "PostgreSQL 17 container on 127.0.0.1:5433 is not reachable. Skipping live database "
                            "integration tests.";
        }

        // Apply migrations
        auth::db::MigrationRunner runner(*pool_);
        runner.run_migrations();

        // 2. Setup Dev PKI Paths
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

        // 3. Setup Repositories and Crypto Engines
        audit_sink_ = std::make_shared<TestAuditSink>();
        audit_publisher_ = std::make_shared<auth::service::AuditEventPublisher>(audit_sink_);

        user_repo_ = std::make_shared<auth::repository::PostgresUserRepository>(*pool_);
        device_repo_ = std::make_shared<auth::repository::PostgresDeviceRepository>(*pool_);
        session_repo_ = std::make_shared<auth::repository::PostgresSessionRepository>(*pool_);
        refresh_token_repo_ = std::make_shared<auth::repository::PostgresRefreshTokenRepository>(*pool_);
        mfa_repo_ = std::make_shared<auth::repository::PostgresMfaRepository>(*pool_);
        public_key_repo_ = std::make_shared<auth::repository::PostgresDevicePublicKeyRepository>(*pool_);

        hasher_ = std::make_shared<auth::crypto::OpenSslArgon2idHasher>();
        token_signer_ = std::make_shared<auth::crypto::Ed25519TokenSigner>("sc-auth-v1");

        test_kek_ = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        secret_protector_ = std::make_shared<auth::crypto::MfaSecretProtector>(test_kek_);
        totp_engine_ = std::make_shared<auth::crypto::TotpEngine>();
        authenticator_ = std::make_shared<auth::service::TotpAuthenticator>(totp_engine_, secret_protector_);

        // 4. Setup Service Managers
        auto verifier = std::make_shared<auth::service::CredentialVerifier>(user_repo_, hasher_);
        session_mgr_ = std::make_shared<auth::service::SessionManager>(session_repo_, device_repo_,
                                                                       std::chrono::hours(24), audit_publisher_);
        auth::service::TokenManagerConfig tm_cfg;
        tm_cfg.concurrency_grace_window = std::chrono::seconds(0);
        token_mgr_ = std::make_shared<auth::service::TokenManager>(token_signer_, refresh_token_repo_, session_repo_,
                                                                   device_repo_, audit_publisher_, tm_cfg);
        mfa_mgr_ = std::make_shared<auth::service::MfaManager>(mfa_repo_, session_repo_, user_repo_, authenticator_,
                                                               totp_engine_, secret_protector_, audit_publisher_);
        device_mgr_ = std::make_shared<auth::service::DeviceManager>(device_repo_, public_key_repo_, session_mgr_,
                                                                     audit_publisher_);
        crypto_dir_mgr_ =
            std::make_shared<auth::service::CryptoDirectoryManager>(device_repo_, public_key_repo_, audit_publisher_);
        prekey_mgr_ = std::make_shared<auth::service::PrekeyManager>(device_repo_, public_key_repo_, audit_publisher_);

        auth_service_impl_ = std::make_unique<auth::service::AuthServiceImpl>(verifier, session_mgr_, audit_publisher_,
                                                                              token_mgr_, mfa_mgr_, device_mgr_,
                                                                              crypto_dir_mgr_, prekey_mgr_, user_repo_);

        // 5. Start Live mTLS gRPC AuthService
        start_auth_server();

        // 6. Setup Gateway Stack
        setup_gateway();
    }

    void TearDown() override {
        if (http_server_) {
            http_server_->stop();
            http_server_.reset();
        }
        auth_client_.reset();
        if (channel_manager_) {
            channel_manager_->reset();
            channel_manager_.reset();
        }
        stop_auth_server();
    }

    void start_auth_server() {
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(auth_server_creds_);
        ASSERT_NE(server_creds, nullptr);

        ::grpc::ServerBuilder builder;
        int port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &port);
        builder.RegisterService(auth_service_impl_.get());

        grpc_server_ = builder.BuildAndStart();
        ASSERT_NE(grpc_server_, nullptr);
        ASSERT_GT(port, 0);

        auth_grpc_port_ = port;
        auth_grpc_endpoint_ = "127.0.0.1:" + std::to_string(port);
    }

    void stop_auth_server() {
        if (grpc_server_) {
            grpc_server_->Shutdown(std::chrono::system_clock::now() + k_shutdown_timeout);
            grpc_server_->Wait();
            grpc_server_.reset();
        }
    }

    void setup_gateway() {
        // Channel manager connecting to downstream AuthService via mTLS
        channel_manager_ = std::make_unique<grpc::GrpcChannelManager>(
            gateway_client_creds_, auth_grpc_endpoint_, "127.0.0.1:50053", "127.0.0.1:50054", "127.0.0.1:50055");
        auto auth_channel = channel_manager_->get_auth_channel();
        ASSERT_NE(auth_channel, nullptr);
        auth_client_ = std::make_shared<grpc::AuthServiceClient>(auth_channel);

        // Gateway perimeter LocalTokenVerifier using Auth public key
        std::string public_pem = token_signer_->get_public_key_pem();
        token_verifier_ = http::LocalTokenVerifier::from_public_key_pem(public_pem, "sc-auth-v1");

        // Gateway Security Policy with default rules + sensitive admin action rule
        security_policy_ = std::make_shared<http::GatewaySecurityPolicy>(http::GatewaySecurityPolicy::create_default());
        security_policy_->add_rule("POST", "/api/v1/admin/sensitive-action", http::RouteAccess::Sensitive, {},
                                   securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

        // Gateway Middlewares
        auth_middleware_ = std::make_shared<http::AuthenticationMiddleware>(security_policy_, token_verifier_);
        authorization_middleware_ = std::make_shared<http::AuthorizationMiddleware>(security_policy_);

        // Gateway Resilience Components
        bulkhead_manager_ = std::make_shared<http::BulkheadManager>();
        GatewayCircuitBreakerConfig cb_cfg;
        cb_cfg.failure_threshold = 2;
        cb_cfg.recovery_timeout_ms = 30000;
        circuit_breaker_ = std::make_shared<http::CircuitBreaker>("auth", cb_cfg);

        GatewayServiceDeadlinesConfig deadline_cfg;
        deadline_cfg.auth_timeout_ms = 4000;
        deadline_manager_ = std::make_shared<http::DeadlineManager>(deadline_cfg);

        // Gateway Proxy Handler
        auth_proxy_ = std::make_shared<http::AuthProxyHandler>(auth_client_, deadline_manager_, nullptr,
                                                               bulkhead_manager_, circuit_breaker_);

        // Setup Router
        router_ = std::make_unique<http::Router>();
        router_->use(auth_middleware_);
        router_->use(authorization_middleware_);

        // Register routes
        auth_proxy_->register_routes(*router_);

        // Add sensitive test endpoint requiring MFA
        router_->add_authenticated_route(
            "POST", "/api/v1/admin/sensitive-action",
            [](const httplib::Request&, httplib::Response& res, const http::AuthenticatedContext& ctx) {
                nlohmann::json body = {
                    {"status", "ACTION_EXECUTED"},
                    {"user_id", ctx.user_id()},
                    {"mfa_verified", ctx.is_mfa_verified()},
                };
                res.status = 200;
                res.set_content(body.dump(), "application/json");
            });

        // Start HTTP Server on random port
        GatewayConfig gw_cfg;
        gw_cfg.http_listen_address = k_loopback_address;
        gw_cfg.http_listen_port = 0;

        http_server_ = std::make_unique<http::HttpServer>(gw_cfg);
        router_->register_into(*http_server_);
        ASSERT_TRUE(http_server_->start_async());
        http_server_->wait_until_ready();
        http_port_ = http_server_->bound_port();
        ASSERT_GT(http_port_, 0);

        http_client_ = std::make_unique<httplib::Client>(k_loopback_address, http_port_);
        http_client_->set_connection_timeout(k_client_timeout);
        http_client_->set_read_timeout(k_client_timeout);
        http_client_->set_write_timeout(k_client_timeout);
    }

    struct SeededUserAndDevice {
        UserEntity user;
        DeviceEntity device;
        std::string raw_password;
    };

    SeededUserAndDevice seed_user_and_device() {
        std::string email = "e2e_user_" + Uuid::generate_v7().to_string() + "@securecloud.io";
        std::string raw_password = "SuperSecurePassword123!";

        UserEntity user;
        user.user_id = Uuid::generate_v7();
        user.credential_identifier = email;
        user.password_verifier = hasher_->hash_password(common::configuration::SecretString(raw_password));
        user.password_algorithm = "argon2id";
        user.password_updated_at = std::chrono::system_clock::now();
        user.account_status = AccountStatus::Active;
        user.created_at = std::chrono::system_clock::now();
        user.updated_at = user.created_at;
        user.version = 1;
        user_repo_->create_user(user);

        DeviceEntity device;
        device.device_id = Uuid::generate_v7();
        device.user_id = user.user_id;
        device.device_status = DeviceStatus::Active;
        device.registered_at = std::chrono::system_clock::now();
        device.last_authenticated_at = device.registered_at;
        device.created_at = device.registered_at;
        device.updated_at = device.registered_at;
        device_repo_->register_device(device);

        return {std::move(user), std::move(device), std::move(raw_password)};
    }

    AuthConfig db_config_;
    std::unique_ptr<auth::db::PostgresConnectionPool> pool_;
    std::shared_ptr<TestAuditSink> audit_sink_;
    std::shared_ptr<auth::service::AuditEventPublisher> audit_publisher_;

    std::shared_ptr<auth::repository::PostgresUserRepository> user_repo_;
    std::shared_ptr<auth::repository::PostgresDeviceRepository> device_repo_;
    std::shared_ptr<auth::repository::PostgresSessionRepository> session_repo_;
    std::shared_ptr<auth::repository::PostgresRefreshTokenRepository> refresh_token_repo_;
    std::shared_ptr<auth::repository::PostgresMfaRepository> mfa_repo_;
    std::shared_ptr<auth::repository::PostgresDevicePublicKeyRepository> public_key_repo_;

    std::shared_ptr<auth::crypto::OpenSslArgon2idHasher> hasher_;
    std::shared_ptr<auth::crypto::Ed25519TokenSigner> token_signer_;
    std::string test_kek_;
    std::shared_ptr<auth::crypto::MfaSecretProtector> secret_protector_;
    std::shared_ptr<auth::crypto::TotpEngine> totp_engine_;
    std::shared_ptr<auth::service::TotpAuthenticator> authenticator_;

    std::shared_ptr<auth::service::SessionManager> session_mgr_;
    std::shared_ptr<auth::service::TokenManager> token_mgr_;
    std::shared_ptr<auth::service::MfaManager> mfa_mgr_;
    std::shared_ptr<auth::service::DeviceManager> device_mgr_;
    std::shared_ptr<auth::service::CryptoDirectoryManager> crypto_dir_mgr_;
    std::shared_ptr<auth::service::PrekeyManager> prekey_mgr_;

    std::unique_ptr<auth::service::AuthServiceImpl> auth_service_impl_;
    std::unique_ptr<::grpc::Server> grpc_server_;
    int auth_grpc_port_{0};
    std::string auth_grpc_endpoint_;

    std::filesystem::path pki_root_;
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    common::security::SecurityCredentialsConfig auth_server_creds_;
    common::security::SecurityCredentialsConfig gateway_client_creds_;

    std::unique_ptr<grpc::GrpcChannelManager> channel_manager_;
    std::shared_ptr<grpc::AuthServiceClient> auth_client_;
    std::shared_ptr<http::LocalTokenVerifier> token_verifier_;
    std::shared_ptr<http::GatewaySecurityPolicy> security_policy_;
    std::shared_ptr<http::AuthenticationMiddleware> auth_middleware_;
    std::shared_ptr<http::AuthorizationMiddleware> authorization_middleware_;
    std::shared_ptr<http::BulkheadManager> bulkhead_manager_;
    std::shared_ptr<http::CircuitBreaker> circuit_breaker_;
    std::shared_ptr<http::DeadlineManager> deadline_manager_;
    std::shared_ptr<http::AuthProxyHandler> auth_proxy_;
    std::unique_ptr<http::Router> router_;
    std::unique_ptr<http::HttpServer> http_server_;
    int http_port_{0};
    std::unique_ptr<httplib::Client> http_client_;
};

// ============================================================================
// Scenario 1: Full End-to-End Primary Login Flow
// ============================================================================

TEST_F(GatewayAuthE2EIntegrationTest, FullEndToEndPrimaryLoginFlow) {
    auto identity = seed_user_and_device();

    // 1. Client sends POST /api/v1/auth/login
    nlohmann::json login_req = {
        {"identifier", identity.user.credential_identifier},
        {"credential", identity.raw_password},
        {"device_id", identity.device.device_id.to_string()},
    };

    auto res = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);

    auto login_res = nlohmann::json::parse(res->body);
    ASSERT_TRUE(login_res.contains("access_token"));
    ASSERT_TRUE(login_res.contains("refresh_token"));
    ASSERT_TRUE(login_res.contains("session_id"));
    EXPECT_FALSE(login_res.value("mfa_required", false));

    std::string access_token = login_res["access_token"].get<std::string>();
    std::string session_id = login_res["session_id"].get<std::string>();
    EXPECT_FALSE(access_token.empty());

    // 2. Client calls GET /api/v1/users/me with Bearer token
    // Verified offline at Gateway edge by LocalTokenVerifier
    httplib::Headers headers = {
        {"Authorization", "Bearer " + access_token},
        {"X-Request-ID", "req-login-e2e-1"},
    };

    auto me_res = http_client_->Get("/api/v1/users/me", headers);
    ASSERT_TRUE(me_res);
    EXPECT_EQ(me_res->status, 200);

    auto me_json = nlohmann::json::parse(me_res->body);
    ASSERT_TRUE(me_json.contains("user"));
    EXPECT_EQ(me_json["user"]["user_id"], identity.user.user_id.to_string());
    EXPECT_EQ(me_json["user"]["credential_identifier"], identity.user.credential_identifier);
}

// ============================================================================
// Scenario 2: Stepped-Up MFA Challenge Flow
// ============================================================================

TEST_F(GatewayAuthE2EIntegrationTest, SteppedUpMfaChallengeFlow) {
    auto identity = seed_user_and_device();

    // 1. Initial Login -> Primary Token
    nlohmann::json login_req = {
        {"identifier", identity.user.credential_identifier},
        {"credential", identity.raw_password},
        {"device_id", identity.device.device_id.to_string()},
    };
    auto login_res = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(login_res);
    EXPECT_EQ(login_res->status, 200);
    auto login_body = nlohmann::json::parse(login_res->body);
    std::string primary_token = login_body["access_token"].get<std::string>();

    httplib::Headers primary_headers = {
        {"Authorization", "Bearer " + primary_token},
    };

    // 2. Sensitive endpoint rejects primary token with HTTP 403 MFA_REQUIRED
    auto sens_res = http_client_->Post("/api/v1/admin/sensitive-action", primary_headers, "{}", "application/json");
    ASSERT_TRUE(sens_res);
    EXPECT_EQ(sens_res->status, 403);
    auto sens_err = nlohmann::json::parse(sens_res->body);
    EXPECT_EQ(sens_err["error"]["code"], "MFA_REQUIRED");

    // 3. Initiate MFA Enrollment
    auto enroll_res = http_client_->Post("/api/v1/auth/mfa/enroll", primary_headers, "{}", "application/json");
    ASSERT_TRUE(enroll_res);
    EXPECT_EQ(enroll_res->status, 200);
    auto enroll_body = nlohmann::json::parse(enroll_res->body);
    ASSERT_TRUE(enroll_body.contains("secret"));
    std::string base32_secret = enroll_body["secret"].get<std::string>();

    auto raw_secret = auth::crypto::Base32::decode(base32_secret);
    ASSERT_TRUE(raw_secret.has_value());

    // 4. Confirm MFA Enrollment with valid TOTP code
    auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::string confirm_code = totp_engine_->compute_code(*raw_secret, now_sec);

    nlohmann::json confirm_req = {{"code", confirm_code}};
    auto confirm_res =
        http_client_->Post("/api/v1/auth/mfa/confirm", primary_headers, confirm_req.dump(), "application/json");
    ASSERT_TRUE(confirm_res);
    EXPECT_EQ(confirm_res->status, 200);

    // 5. Subsequent Login triggers MFA requirement
    auto mfa_login_res = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(mfa_login_res);
    EXPECT_EQ(mfa_login_res->status, 200);
    auto mfa_login_body = nlohmann::json::parse(mfa_login_res->body);
    EXPECT_TRUE(mfa_login_body.value("mfa_required", false));
    std::string challenge_id = mfa_login_body["mfa_challenge_id"].get<std::string>();
    EXPECT_FALSE(challenge_id.empty());

    // 6. Verify MFA Challenge -> receives upgraded token with MFA_VERIFIED assurance
    now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::string challenge_code = totp_engine_->compute_code(*raw_secret, now_sec);

    nlohmann::json verify_req = {
        {"challenge_id", challenge_id},
        {"code", challenge_code},
    };
    auto verify_res =
        http_client_->Post("/api/v1/auth/mfa/verify", primary_headers, verify_req.dump(), "application/json");
    ASSERT_TRUE(verify_res);
    EXPECT_EQ(verify_res->status, 200);
    auto verify_body = nlohmann::json::parse(verify_res->body);
    ASSERT_TRUE(verify_body.contains("access_token"));
    std::string upgraded_token = verify_body["access_token"].get<std::string>();

    // 7. Sensitive endpoint succeeds with upgraded token!
    httplib::Headers upgraded_headers = {
        {"Authorization", "Bearer " + upgraded_token},
    };
    auto sens_ok_res = http_client_->Post("/api/v1/admin/sensitive-action", upgraded_headers, "{}", "application/json");
    ASSERT_TRUE(sens_ok_res);
    EXPECT_EQ(sens_ok_res->status, 200);
    auto sens_ok_body = nlohmann::json::parse(sens_ok_res->body);
    EXPECT_EQ(sens_ok_body["status"], "ACTION_EXECUTED");
    EXPECT_TRUE(sens_ok_body["mfa_verified"]);
}

// ============================================================================
// Scenario 3: Device Enrollment & Cascading Revocation Flow
// ============================================================================

TEST_F(GatewayAuthE2EIntegrationTest, DeviceEnrollmentAndCascadingRevocationFlow) {
    auto identity = seed_user_and_device();

    // 1. Primary Login
    nlohmann::json login_req = {
        {"identifier", identity.user.credential_identifier},
        {"credential", identity.raw_password},
        {"device_id", identity.device.device_id.to_string()},
    };
    auto login_res = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(login_res);
    EXPECT_EQ(login_res->status, 200);
    std::string primary_token = nlohmann::json::parse(login_res->body)["access_token"].get<std::string>();
    httplib::Headers primary_headers = {{"Authorization", "Bearer " + primary_token}};

    // 2. Register secondary device in DB in PendingAuthorization state
    DeviceEntity sec_device;
    sec_device.device_id = Uuid::generate_v7();
    sec_device.user_id = identity.user.user_id;
    sec_device.device_status = DeviceStatus::PendingAuthorization;
    sec_device.registered_at = std::chrono::system_clock::now();
    sec_device.last_authenticated_at = sec_device.registered_at;
    sec_device.created_at = sec_device.registered_at;
    sec_device.updated_at = sec_device.created_at;
    device_repo_->register_device(sec_device);

    // 3. Initiate Pairing for the secondary device
    nlohmann::json pair_req = {{"device_id", sec_device.device_id.to_string()}};
    auto pair_init_res =
        http_client_->Post("/api/v1/devices/pairing", primary_headers, pair_req.dump(), "application/json");
    ASSERT_TRUE(pair_init_res);
    EXPECT_EQ(pair_init_res->status, 200);
    auto pair_body = nlohmann::json::parse(pair_init_res->body);
    ASSERT_TRUE(pair_body.contains("pairing_code"));
    std::string pairing_code = pair_body["pairing_code"].get<std::string>();
    EXPECT_FALSE(pairing_code.empty());

    // 4. Primary token lacks MFA_VERIFIED assurance -> rejected with HTTP 403 MFA_REQUIRED
    nlohmann::json auth_dev_req = {{"pairing_code", pairing_code}};
    auto auth_denied_res = http_client_->Post("/api/v1/devices/" + sec_device.device_id.to_string() + "/authorize",
                                              primary_headers, auth_dev_req.dump(), "application/json");
    ASSERT_TRUE(auth_denied_res);
    EXPECT_EQ(auth_denied_res->status, 403);
    auto auth_denied_body = nlohmann::json::parse(auth_denied_res->body);
    EXPECT_EQ(auth_denied_body["error"]["code"], "MFA_REQUIRED");

    // 5. User steps up assurance via MFA enrollment & verification
    auto enroll_res = http_client_->Post("/api/v1/auth/mfa/enroll", primary_headers, "{}", "application/json");
    ASSERT_TRUE(enroll_res);
    EXPECT_EQ(enroll_res->status, 200);
    auto enroll_body = nlohmann::json::parse(enroll_res->body);
    auto raw_secret = auth::crypto::Base32::decode(enroll_body["secret"].get<std::string>());
    ASSERT_TRUE(raw_secret.has_value());

    auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::string confirm_code = totp_engine_->compute_code(*raw_secret, now_sec);
    nlohmann::json confirm_req = {{"code", confirm_code}};
    auto confirm_res =
        http_client_->Post("/api/v1/auth/mfa/confirm", primary_headers, confirm_req.dump(), "application/json");
    ASSERT_TRUE(confirm_res);
    EXPECT_EQ(confirm_res->status, 200);

    // Re-login to trigger MFA challenge
    auto mfa_login_res = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(mfa_login_res);
    EXPECT_EQ(mfa_login_res->status, 200);
    auto mfa_login_body = nlohmann::json::parse(mfa_login_res->body);
    EXPECT_TRUE(mfa_login_body.value("mfa_required", false));
    std::string challenge_id = mfa_login_body["mfa_challenge_id"].get<std::string>();

    now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::string challenge_code = totp_engine_->compute_code(*raw_secret, now_sec);
    nlohmann::json verify_req = {{"challenge_id", challenge_id}, {"code", challenge_code}};
    auto verify_res =
        http_client_->Post("/api/v1/auth/mfa/verify", primary_headers, verify_req.dump(), "application/json");
    ASSERT_TRUE(verify_res);
    EXPECT_EQ(verify_res->status, 200);
    std::string mfa_token = nlohmann::json::parse(verify_res->body)["access_token"].get<std::string>();
    httplib::Headers mfa_headers = {{"Authorization", "Bearer " + mfa_token}};

    // 6. Stepped-up user successfully authorizes secondary device via pairing code
    auto auth_dev_res = http_client_->Post("/api/v1/devices/" + sec_device.device_id.to_string() + "/authorize",
                                           mfa_headers, auth_dev_req.dump(), "application/json");
    ASSERT_TRUE(auth_dev_res);
    EXPECT_EQ(auth_dev_res->status, 200);

    // 7. Query Device Directory via GET /api/v1/devices
    auto list_res = http_client_->Get("/api/v1/devices", mfa_headers);
    ASSERT_TRUE(list_res);
    EXPECT_EQ(list_res->status, 200);
    auto list_body = nlohmann::json::parse(list_res->body);
    ASSERT_TRUE(list_body.contains("devices"));
    EXPECT_GE(list_body["devices"].size(), 2);

    // 8. Revoke the secondary device via DELETE /api/v1/devices/:device_id
    auto revoke_res = http_client_->Delete("/api/v1/devices/" + sec_device.device_id.to_string(), mfa_headers);
    ASSERT_TRUE(revoke_res);
    EXPECT_EQ(revoke_res->status, 200);
    auto revoke_body = nlohmann::json::parse(revoke_res->body);
    EXPECT_TRUE(revoke_body.value("revoked", false) || revoke_body.value("success", false));

    // Verify device status is Revoked in DB
    auto updated_device = device_repo_->find_by_id(sec_device.device_id);
    ASSERT_TRUE(updated_device.has_value());
    EXPECT_EQ(updated_device->device_status, DeviceStatus::Revoked);
}

// ============================================================================
// Scenario 4: Token Refresh & Token Reuse Detection
// ============================================================================

TEST_F(GatewayAuthE2EIntegrationTest, TokenRefreshAndTokenReuseDetection) {
    auto identity = seed_user_and_device();

    // 1. Primary Login
    nlohmann::json login_req = {
        {"identifier", identity.user.credential_identifier},
        {"credential", identity.raw_password},
        {"device_id", identity.device.device_id.to_string()},
    };
    auto login_res = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(login_res);
    EXPECT_EQ(login_res->status, 200);
    auto login_body = nlohmann::json::parse(login_res->body);
    std::string original_refresh_token = login_body["refresh_token"].get<std::string>();

    // 2. Successful Token Refresh
    nlohmann::json refresh_req = {
        {"refresh_token", original_refresh_token},
        {"device_id", identity.device.device_id.to_string()},
    };
    auto ref_res = http_client_->Post("/api/v1/auth/refresh", refresh_req.dump(), "application/json");
    ASSERT_TRUE(ref_res);
    EXPECT_EQ(ref_res->status, 200);
    auto ref_body = nlohmann::json::parse(ref_res->body);
    ASSERT_TRUE(ref_body.contains("access_token"));
    ASSERT_TRUE(ref_body.contains("refresh_token"));
    std::string rotated_access_token = ref_body["access_token"].get<std::string>();
    std::string rotated_refresh_token = ref_body["refresh_token"].get<std::string>();
    EXPECT_NE(rotated_refresh_token, original_refresh_token);

    // 3. New access token succeeds
    httplib::Headers new_headers = {{"Authorization", "Bearer " + rotated_access_token}};
    auto me_res = http_client_->Get("/api/v1/users/me", new_headers);
    ASSERT_TRUE(me_res);
    EXPECT_EQ(me_res->status, 200);

    // 4. Token Reuse Attack: Replaying the consumed original_refresh_token
    auto attack_res = http_client_->Post("/api/v1/auth/refresh", refresh_req.dump(), "application/json");
    ASSERT_TRUE(attack_res);
    EXPECT_EQ(attack_res->status, 401);
    auto attack_err = nlohmann::json::parse(attack_res->body);
    EXPECT_EQ(attack_err["error"]["code"], "UNAUTHENTICATED");
}

// ============================================================================
// Scenario 5: Resilience Under Downstream Outage
// ============================================================================

TEST_F(GatewayAuthE2EIntegrationTest, ResilienceUnderDownstreamOutage) {
    auto identity = seed_user_and_device();

    // 1. Stop the downstream AuthService gRPC server to simulate catastrophic outage
    stop_auth_server();

    nlohmann::json login_req = {
        {"identifier", identity.user.credential_identifier},
        {"credential", identity.raw_password},
    };

    // Request 1 -> downstream fails, Gateway returns 503 SERVICE_UNAVAILABLE
    auto res1 = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(res1);
    EXPECT_EQ(res1->status, 503);

    // Request 2 -> downstream fails, trips Circuit Breaker to Open
    auto res2 = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(res2);
    EXPECT_EQ(res2->status, 503);

    // Request 3 -> Circuit Breaker is now Open! Fast-fails at perimeter without dispatching RPC
    auto res3 = http_client_->Post("/api/v1/auth/login", login_req.dump(), "application/json");
    ASSERT_TRUE(res3);
    EXPECT_EQ(res3->status, 503);
    EXPECT_TRUE(res3->has_header("Retry-After"));

    auto body3 = nlohmann::json::parse(res3->body);
    EXPECT_EQ(body3["error"]["code"], "CIRCUIT_BREAKER_OPEN");
    EXPECT_EQ(body3["type"], "https://securecloud.internal/errors/circuit-breaker-open");
}

} // namespace
} // namespace securecloud::gateway::integration::test
