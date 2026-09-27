#include "grpc/auth_client_interface.hpp"
#include "http/auth/auth_service_token_validator.hpp"

#include <chrono>
#include <future>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::gateway::http {
namespace {

using ::testing::_;
using ::testing::Return;

class MockAuthClient : public securecloud::gateway::grpc::IAuthClient {
  public:
    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>, authenticate,
                (const securecloud::auth::v1::AuthenticateRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>, validate_session,
                (const securecloud::auth::v1::ValidateSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RefreshSessionResponse>, refresh_session,
                (const securecloud::auth::v1::RefreshSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RevokeSessionResponse>, revoke_session,
                (const securecloud::auth::v1::RevokeSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetUserResponse>, get_user,
                (const securecloud::auth::v1::GetUserRequest& req, securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RegisterDeviceResponse>, register_device,
                (const securecloud::auth::v1::RegisterDeviceRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetCryptoIdentityResponse>,
                get_crypto_identity,
                (const securecloud::auth::v1::GetCryptoIdentityRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetDeviceCryptoDirectoryResponse>,
                get_device_crypto_directory,
                (const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));
};

securecloud::auth::v1::ValidateSessionResponse
make_valid_response(const std::string& user_id = "user-123", const std::string& device_id = "device-456",
                    securecloud::auth::v1::AuthenticationLevel level =
                        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                    int64_t expires_in_seconds = 3600) {
    securecloud::auth::v1::ValidateSessionResponse resp;
    resp.set_is_valid(true);
    resp.set_user_id(user_id);
    resp.set_device_id(device_id);
    resp.set_authentication_level(level);

    auto now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    resp.set_expires_at_epoch_ms(now_ms + (expires_in_seconds * 1000));
    return resp;
}

TEST(AuthServiceTokenValidatorTest, NullClientThrowsInvalidArgument) {
    EXPECT_THROW(AuthServiceTokenValidator(nullptr), std::invalid_argument);
}

TEST(AuthServiceTokenValidatorTest, EmptyTokenFailsImmediately) {
    auto mock_client = std::make_shared<MockAuthClient>();
    EXPECT_CALL(*mock_client, validate_session(_, _)).Times(0);

    AuthServiceTokenValidator validator(mock_client);
    auto res = validator.validate("");
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().kind, TokenValidationErrorKind::InvalidSignature);
}

TEST(AuthServiceTokenValidatorTest, ValidSessionReturnsAuthenticatedContext) {
    auto mock_client = std::make_shared<MockAuthClient>();
    auto expected_resp = make_valid_response(
        "user-abc", "device-def", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED, 3600);

    EXPECT_CALL(*mock_client, validate_session(_, _))
        .WillOnce([&expected_resp](const securecloud::auth::v1::ValidateSessionRequest& req,
                                   securecloud::gateway::grpc::ClientCallContext& ctx) {
            EXPECT_EQ(req.access_token(), "valid-token-123");
            EXPECT_EQ(req.session_id(), "sess-999");
            EXPECT_EQ(ctx.request_id(), "req-trace-001");
            return expected_resp;
        });

    AuthServiceTokenValidator validator(mock_client);
    auto res = validator.validate("valid-token-123", "sess-999", "req-trace-001");

    ASSERT_TRUE(res.has_value());
    const auto& ctx = res.value();
    EXPECT_EQ(ctx.user_id(), "user-abc");
    EXPECT_EQ(ctx.device_id(), "device-def");
    EXPECT_EQ(ctx.session_id(), "sess-999");
    EXPECT_EQ(ctx.authentication_level(),
              securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    EXPECT_TRUE(ctx.is_mfa_verified());
    EXPECT_TRUE(ctx.has_scope("access"));
    EXPECT_EQ(ctx.expires_at_epoch_ms(), expected_resp.expires_at_epoch_ms());
}

TEST(AuthServiceTokenValidatorTest, InvalidSessionReturnsSessionRevoked) {
    auto mock_client = std::make_shared<MockAuthClient>();
    securecloud::auth::v1::ValidateSessionResponse invalid_resp;
    invalid_resp.set_is_valid(false);

    EXPECT_CALL(*mock_client, validate_session(_, _)).WillOnce(Return(invalid_resp));

    AuthServiceTokenValidator validator(mock_client);
    auto res = validator.validate("revoked-token");

    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().kind, TokenValidationErrorKind::SessionRevoked);
}

TEST(AuthServiceTokenValidatorTest, ExpiredTokenReturnsTokenExpired) {
    auto mock_client = std::make_shared<MockAuthClient>();
    auto expired_resp = make_valid_response(
        "user-xyz", "device-xyz", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, -60);

    EXPECT_CALL(*mock_client, validate_session(_, _)).WillOnce(Return(expired_resp));

    AuthServiceTokenValidator validator(mock_client);
    auto res = validator.validate("expired-token");

    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().kind, TokenValidationErrorKind::TokenExpired);
}

TEST(AuthServiceTokenValidatorTest, CacheHitAvoidsRedundantRpc) {
    auto mock_client = std::make_shared<MockAuthClient>();
    auto resp =
        make_valid_response("user-cached", "device-cached",
                            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED, 3600);

    // gRPC must only be called ONCE
    EXPECT_CALL(*mock_client, validate_session(_, _)).Times(1).WillOnce(Return(resp));

    TokenValidatorOptions options{
        .rpc_timeout = std::chrono::milliseconds(500),
        .cache_ttl = std::chrono::seconds(10),
        .max_cache_entries = 100,
    };
    AuthServiceTokenValidator validator(mock_client, options);

    // Call 1: Misses cache, calls RPC
    auto res1 = validator.validate("cached-token", "sess-1");
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(validator.cache_size(), 1u);

    // Call 2: Hits cache, no second RPC
    auto res2 = validator.validate("cached-token", "sess-1");
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2.value().user_id(), "user-cached");
}

TEST(AuthServiceTokenValidatorTest, CacheExpirationForcesFreshRpc) {
    auto mock_client = std::make_shared<MockAuthClient>();
    auto resp1 = make_valid_response("user-1", "device-1",
                                     securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, 3600);
    auto resp2 = make_valid_response(
        "user-2", "device-2", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED, 3600);

    EXPECT_CALL(*mock_client, validate_session(_, _)).Times(2).WillOnce(Return(resp1)).WillOnce(Return(resp2));

    TokenValidatorOptions options{
        .rpc_timeout = std::chrono::milliseconds(500),
        .cache_ttl = std::chrono::seconds(1),
        .max_cache_entries = 100,
    };
    AuthServiceTokenValidator validator(mock_client, options);

    auto res1 = validator.validate("short-ttl-token");
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1.value().user_id(), "user-1");

    // Manually clearing cache simulates cache expiration
    validator.clear_cache();
    EXPECT_EQ(validator.cache_size(), 0u);

    auto res2 = validator.validate("short-ttl-token");
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2.value().user_id(), "user-2");
}

TEST(AuthServiceTokenValidatorTest, CacheDisabledWhenTtlZero) {
    auto mock_client = std::make_shared<MockAuthClient>();
    auto resp = make_valid_response();

    // Must call RPC every time when TTL is 0
    EXPECT_CALL(*mock_client, validate_session(_, _)).Times(2).WillRepeatedly(Return(resp));

    TokenValidatorOptions options{
        .rpc_timeout = std::chrono::milliseconds(500),
        .cache_ttl = std::chrono::seconds(0), // Caching disabled
        .max_cache_entries = 100,
    };
    AuthServiceTokenValidator validator(mock_client, options);

    auto res1 = validator.validate("no-cache-token");
    auto res2 = validator.validate("no-cache-token");
    ASSERT_TRUE(res1.has_value());
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(validator.cache_size(), 0u);
}

TEST(AuthServiceTokenValidatorTest, UpstreamRpcErrorsMappedDeterministically) {
    auto mock_client = std::make_shared<MockAuthClient>();
    AuthServiceTokenValidator validator(mock_client);

    // Timeout -> ServiceUnavailable
    {
        securecloud::gateway::grpc::DependencyError err{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::Timeout,
            .message = "Deadline exceeded",
            .grpc_code = ::grpc::StatusCode::DEADLINE_EXCEEDED,
        };
        EXPECT_CALL(*mock_client, validate_session(_, _))
            .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>(err)));
        auto res = validator.validate("err-token-1");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().kind, TokenValidationErrorKind::ServiceUnavailable);
    }

    // ServiceUnavailable -> ServiceUnavailable
    {
        securecloud::gateway::grpc::DependencyError err{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable,
            .message = "Unavailable",
            .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
        };
        EXPECT_CALL(*mock_client, validate_session(_, _))
            .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>(err)));
        auto res = validator.validate("err-token-2");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().kind, TokenValidationErrorKind::ServiceUnavailable);
    }

    // Unauthenticated -> InvalidSignature
    {
        securecloud::gateway::grpc::DependencyError err{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::Unauthenticated,
            .message = "Unauthenticated caller",
            .grpc_code = ::grpc::StatusCode::UNAUTHENTICATED,
        };
        EXPECT_CALL(*mock_client, validate_session(_, _))
            .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>(err)));
        auto res = validator.validate("err-token-3");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().kind, TokenValidationErrorKind::InvalidSignature);
    }

    // NotFound -> SessionRevoked
    {
        securecloud::gateway::grpc::DependencyError err{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::NotFound,
            .message = "Session not found",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        };
        EXPECT_CALL(*mock_client, validate_session(_, _))
            .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>(err)));
        auto res = validator.validate("err-token-4");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().kind, TokenValidationErrorKind::SessionRevoked);
    }

    // Internal -> InternalError
    {
        securecloud::gateway::grpc::DependencyError err{
            .kind = securecloud::gateway::grpc::DependencyErrorKind::Internal,
            .message = "Internal fatal error",
            .grpc_code = ::grpc::StatusCode::INTERNAL,
        };
        EXPECT_CALL(*mock_client, validate_session(_, _))
            .WillOnce(Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>(err)));
        auto res = validator.validate("err-token-5");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().kind, TokenValidationErrorKind::InternalError);
    }
}

TEST(AuthServiceTokenValidatorTest, CacheEvictionEnforcesMaxEntries) {
    auto mock_client = std::make_shared<MockAuthClient>();
    EXPECT_CALL(*mock_client, validate_session(_, _)).Times(5).WillRepeatedly([](const auto&, auto&) {
        return make_valid_response("user", "device",
                                   securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, 3600);
    });

    TokenValidatorOptions options{
        .rpc_timeout = std::chrono::milliseconds(500),
        .cache_ttl = std::chrono::seconds(60),
        .max_cache_entries = 3,
    };
    AuthServiceTokenValidator validator(mock_client, options);

    for (int i = 0; i < 5; ++i) {
        validator.validate("token-" + std::to_string(i));
    }

    EXPECT_LE(validator.cache_size(), 3u);
}

TEST(AuthServiceTokenValidatorTest, ConcurrentAccessThreadSafe) {
    auto mock_client = std::make_shared<MockAuthClient>();
    EXPECT_CALL(*mock_client, validate_session(_, _)).WillRepeatedly([](const auto&, auto&) {
        return make_valid_response();
    });

    TokenValidatorOptions options{
        .rpc_timeout = std::chrono::milliseconds(500),
        .cache_ttl = std::chrono::seconds(5),
        .max_cache_entries = 50,
    };
    AuthServiceTokenValidator validator(mock_client, options);

    constexpr int kNumThreads = 8;
    constexpr int kItersPerThread = 50;
    std::vector<std::future<void>> futures;
    futures.reserve(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        futures.push_back(std::async(std::launch::async, [&validator]() -> void {
            for (int i = 0; i < kItersPerThread; ++i) {
                std::string token = "token-" + std::to_string(i % 10);
                auto res = validator.validate(token);
                EXPECT_TRUE(res.has_value());
            }
        }));
    }

    for (auto& f : futures) {
        f.get();
    }

    EXPECT_LE(validator.cache_size(), 50u);
}

} // namespace
} // namespace securecloud::gateway::http
