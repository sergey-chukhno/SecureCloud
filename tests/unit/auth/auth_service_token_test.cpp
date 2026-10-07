#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/session_result.hpp"
#include "auth/domain/token_result.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/session_manager.hpp"
#include "auth/service/token_manager.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

class MockCredentialVerifier : public ICredentialVerifier {
  public:
    MOCK_METHOD(domain::AuthenticationResult, verify,
                (const domain::CredentialIdentifier&, const domain::PasswordCredential&), (override));
};

class MockSessionManager : public ISessionManager {
  public:
    MOCK_METHOD(SessionEstablishmentResult, establish_session, (const domain::UserEntity&, const domain::Uuid&),
                (override));
    MOCK_METHOD(domain::SessionValidationResult, validate_session, (const domain::Uuid&, std::optional<domain::Uuid>),
                (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_user, (const domain::Uuid&), (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_device, (const domain::Uuid&), (override));
    domain::SessionRevocationResult revoke_session(const domain::Uuid& session_id, std::string_view reason) override {
        return revoke_session_str(session_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_session_str, (const domain::Uuid&, const std::string&));
    domain::SessionRevocationResult revoke_all_device_sessions(const domain::Uuid& /*device_id*/,
                                                               std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(0);
    }
    domain::SessionRevocationResult revoke_all_user_sessions(const domain::Uuid& /*user_id*/,
                                                             std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(0);
    }
};

class MockAuditEventPublisher : public IAuditEventPublisher {
  public:
    MOCK_METHOD(void, publish, (const domain::AuditEvent&), (noexcept, override));
};

class MockTokenManager : public ITokenManager {
  public:
    MOCK_METHOD(domain::TokenPair, issue_initial_tokens,
                (const domain::SessionEntity&, const std::vector<std::string>&), (override));
    MOCK_METHOD(domain::TokenRefreshResult, refresh_tokens, (std::string_view, const domain::Uuid&, std::string_view),
                (override));
};

domain::UserEntity create_test_user(const domain::Uuid& user_id) {
    domain::UserEntity user;
    user.user_id = user_id;
    user.credential_identifier = "alice@securecloud.io";
    user.password_verifier = "mock_verifier";
    user.password_algorithm = "argon2id";
    user.password_updated_at = std::chrono::system_clock::now();
    user.account_status = domain::AccountStatus::Active;
    user.created_at = std::chrono::system_clock::now();
    user.updated_at = user.created_at;
    user.version = 1;
    return user;
}

domain::DeviceEntity create_test_device(const domain::Uuid& device_id, const domain::Uuid& user_id) {
    domain::DeviceEntity device;
    device.device_id = device_id;
    device.user_id = user_id;
    device.device_status = domain::DeviceStatus::Active;
    device.registered_at = std::chrono::system_clock::now();
    device.last_authenticated_at = device.registered_at;
    device.created_at = device.registered_at;
    device.updated_at = device.registered_at;
    return device;
}

domain::SessionEntity create_test_session(const domain::Uuid& user_id, const domain::Uuid& device_id) {
    domain::SessionEntity session;
    session.session_id = domain::Uuid::generate_v7();
    session.user_id = user_id;
    session.device_id = device_id;
    session.authentication_level = domain::AuthenticationLevel::PrimaryOnly;
    session.session_status = domain::SessionStatus::Active;
    session.created_at = std::chrono::system_clock::now();
    session.expires_at = session.created_at + std::chrono::hours(24);
    return session;
}

class AuthServiceTokenTest : public ::testing::Test {
  protected:
    void SetUp() override {
        credential_verifier_ = std::make_shared<MockCredentialVerifier>();
        session_manager_ = std::make_shared<MockSessionManager>();
        audit_publisher_ = std::make_shared<MockAuditEventPublisher>();
        token_manager_ = std::make_shared<MockTokenManager>();

        auth_service_ =
            std::make_unique<AuthServiceImpl>(credential_verifier_, session_manager_, audit_publisher_, token_manager_);
    }

    std::shared_ptr<MockCredentialVerifier> credential_verifier_;
    std::shared_ptr<MockSessionManager> session_manager_;
    std::shared_ptr<MockAuditEventPublisher> audit_publisher_;
    std::shared_ptr<MockTokenManager> token_manager_;
    std::unique_ptr<AuthServiceImpl> auth_service_;
};

// ============================================================================
// Authenticate RPC with TokenManager tests
// ============================================================================

TEST_F(AuthServiceTokenTest, Authenticate_WithTokenManager_IssuesAndPopulatesTokens) {
    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto user = create_test_user(user_id);
    auto device = create_test_device(device_id, user_id);
    auto session = create_test_session(user_id, device_id);

    EXPECT_CALL(*credential_verifier_, verify(_, _)).WillOnce(Return(domain::AuthenticationResult::success(user)));
    EXPECT_CALL(*session_manager_, establish_session(_, _))
        .WillOnce(Return(SessionEstablishmentResult::success(session, device)));
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    domain::TokenPair mock_tokens;
    mock_tokens.access_token = "mock.signed.access.token";
    mock_tokens.refresh_token = domain::SecretTokenString("sc_rt_test_secret_123");
    mock_tokens.expires_at = session.created_at + std::chrono::minutes(15);

    EXPECT_CALL(*token_manager_, issue_initial_tokens(_, _)).WillOnce(Return(mock_tokens));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::AuthenticateRequest request;
    request.set_credential_identifier("alice@securecloud.io");
    request.set_password("CorrectHorseBatteryStaple1!");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::AuthenticateResponse response;
    auto status = auth_service_->Authenticate(&context, &request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.session_id(), session.session_id.to_string());
    EXPECT_EQ(response.user_id(), user_id.to_string());
    EXPECT_EQ(response.access_token(), "mock.signed.access.token");
    EXPECT_EQ(response.refresh_token(), "sc_rt_test_secret_123");
    int64_t expected_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(mock_tokens.expires_at.time_since_epoch()).count();
    EXPECT_EQ(response.expires_at_epoch_ms(), expected_ms);
}

TEST_F(AuthServiceTokenTest, Authenticate_WithoutTokenManager_MaintainsBackwardCompatibility) {
    auto unconfigured_service =
        std::make_unique<AuthServiceImpl>(credential_verifier_, session_manager_, audit_publisher_, nullptr);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto user = create_test_user(user_id);
    auto device = create_test_device(device_id, user_id);
    auto session = create_test_session(user_id, device_id);

    EXPECT_CALL(*credential_verifier_, verify(_, _)).WillOnce(Return(domain::AuthenticationResult::success(user)));
    EXPECT_CALL(*session_manager_, establish_session(_, _))
        .WillOnce(Return(SessionEstablishmentResult::success(session, device)));
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::AuthenticateRequest request;
    request.set_credential_identifier("alice@securecloud.io");
    request.set_password("CorrectHorseBatteryStaple1!");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::AuthenticateResponse response;
    auto status = unconfigured_service->Authenticate(&context, &request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(response.access_token().empty());
    EXPECT_TRUE(response.refresh_token().empty());
    int64_t session_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(session.expires_at.time_since_epoch()).count();
    EXPECT_EQ(response.expires_at_epoch_ms(), session_ms);
}

// ============================================================================
// RefreshSession RPC tests
// ============================================================================

TEST_F(AuthServiceTokenTest, RefreshSession_Success_PopulatesRotatedTokens) {
    auto session_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();

    domain::TokenPair rotated_tokens;
    rotated_tokens.access_token = "new.signed.access.token.v2";
    rotated_tokens.refresh_token = domain::SecretTokenString("sc_rt_new_rotated_secret_456");
    rotated_tokens.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(15);

    domain::TokenRefreshResult mock_result = domain::TokenRefreshResult::success(rotated_tokens, session_id);
    EXPECT_CALL(*token_manager_, refresh_tokens("sc_rt_old_token", device_id, _)).WillOnce(Return(mock_result));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_old_token");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.session_id(), session_id.to_string());
    EXPECT_EQ(response.access_token(), "new.signed.access.token.v2");
    EXPECT_EQ(response.new_refresh_token(), "sc_rt_new_rotated_secret_456");
    int64_t expected_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(rotated_tokens.expires_at.time_since_epoch()).count();
    EXPECT_EQ(response.expires_at_epoch_ms(), expected_ms);
}

TEST_F(AuthServiceTokenTest, RefreshSession_NullRequestOrResponse_ReturnsInvalidArgument) {
    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, nullptr, &response);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    ::securecloud::auth::v1::RefreshSessionRequest request;
    status = auth_service_->RefreshSession(&context, &request, nullptr);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceTokenTest, RefreshSession_UnconfiguredTokenManager_ReturnsUnimplemented) {
    auto unconfigured_service =
        std::make_unique<AuthServiceImpl>(credential_verifier_, session_manager_, audit_publisher_, nullptr);

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_token");
    request.set_device_id(domain::Uuid::generate_v7().to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = unconfigured_service->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNIMPLEMENTED);
}

TEST_F(AuthServiceTokenTest, RefreshSession_EmptyRefreshToken_ReturnsInvalidArgument) {
    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("");
    request.set_device_id(domain::Uuid::generate_v7().to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("Refresh token must not be empty"));
}

TEST_F(AuthServiceTokenTest, RefreshSession_InvalidDeviceUuid_ReturnsInvalidArgument) {
    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_token");
    request.set_device_id("not-a-valid-uuid");

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("Invalid device UUID format"));
}

TEST_F(AuthServiceTokenTest, RefreshSession_InvalidToken_ReturnsUnauthenticated) {
    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*token_manager_, refresh_tokens("sc_rt_unknown", device_id, _))
        .WillOnce(Return(domain::TokenRefreshResult::invalid_token("Refresh token does not exist")));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_unknown");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("Refresh token does not exist"));
}

TEST_F(AuthServiceTokenTest, RefreshSession_ExpiredToken_ReturnsUnauthenticated) {
    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*token_manager_, refresh_tokens("sc_rt_expired", device_id, _))
        .WillOnce(Return(domain::TokenRefreshResult::expired_token("Refresh token has expired")));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_expired");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("Refresh token has expired"));
}

TEST_F(AuthServiceTokenTest, RefreshSession_CompromiseDetected_ReturnsUnauthenticatedWithRevocationNotice) {
    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*token_manager_, refresh_tokens("sc_rt_replayed", device_id, _))
        .WillOnce(Return(domain::TokenRefreshResult::compromise_detected("Compromise detected")));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_replayed");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("Refresh token reuse detected; session revoked"));
}

TEST_F(AuthServiceTokenTest, RefreshSession_DeviceMismatch_ReturnsPermissionDenied) {
    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*token_manager_, refresh_tokens("sc_rt_stolen", device_id, _))
        .WillOnce(Return(domain::TokenRefreshResult::device_mismatch("Device ID does not match token binding")));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_stolen");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("Device ID does not match token binding"));
}

TEST_F(AuthServiceTokenTest, RefreshSession_ConcurrencyConflict_ReturnsAborted) {
    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*token_manager_, refresh_tokens("sc_rt_racing", device_id, _))
        .WillOnce(Return(domain::TokenRefreshResult::concurrency_conflict("Concurrent refresh")));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_racing");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::ABORTED);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("Concurrent refresh detected"));
}

TEST_F(AuthServiceTokenTest, RefreshSession_DatabaseError_ReturnsInternal) {
    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*token_manager_, refresh_tokens("sc_rt_token", device_id, _))
        .WillOnce(Return(domain::TokenRefreshResult::database_error("PostgreSQL connection timeout")));

    ::grpc::ServerContext context;
    ::securecloud::auth::v1::RefreshSessionRequest request;
    request.set_refresh_token("sc_rt_token");
    request.set_device_id(device_id.to_string());

    ::securecloud::auth::v1::RefreshSessionResponse response;
    auto status = auth_service_->RefreshSession(&context, &request, &response);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INTERNAL);
    EXPECT_THAT(status.error_message(), ::testing::HasSubstr("PostgreSQL connection timeout"));
}

} // namespace
} // namespace securecloud::auth::service::test
