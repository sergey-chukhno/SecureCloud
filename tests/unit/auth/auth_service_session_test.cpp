#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/session_result.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/session_manager.hpp"
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

domain::SessionEntity
create_test_session(const domain::Uuid& user_id, const domain::Uuid& device_id,
                    domain::AuthenticationLevel level = domain::AuthenticationLevel::PrimaryOnly) {
    domain::SessionEntity session;
    session.session_id = domain::Uuid::generate_v7();
    session.user_id = user_id;
    session.device_id = device_id;
    session.authentication_level = level;
    session.session_status = domain::SessionStatus::Active;
    session.created_at = std::chrono::system_clock::now();
    session.expires_at = session.created_at + std::chrono::hours(24);
    session.last_used_at = session.created_at;
    return session;
}

class AuthServiceSessionTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_verifier_ = std::make_shared<StrictMock<MockCredentialVerifier>>();
        mock_session_mgr_ = std::make_shared<StrictMock<MockSessionManager>>();
        mock_audit_pub_ = std::make_shared<StrictMock<MockAuditEventPublisher>>();

        service_ = std::make_unique<AuthServiceImpl>(mock_verifier_, mock_session_mgr_, mock_audit_pub_);
    }

    std::shared_ptr<StrictMock<MockCredentialVerifier>> mock_verifier_;
    std::shared_ptr<StrictMock<MockSessionManager>> mock_session_mgr_;
    std::shared_ptr<StrictMock<MockAuditEventPublisher>> mock_audit_pub_;
    std::unique_ptr<AuthServiceImpl> service_;
    grpc::ServerContext context_;
};

// Test 1: ValidateSession with null request or response returns INVALID_ARGUMENT
TEST_F(AuthServiceSessionTest, ValidateSession_NullRequestOrResponse_ReturnsInvalidArgument) {
    securecloud::auth::v1::ValidateSessionRequest req;
    securecloud::auth::v1::ValidateSessionResponse resp;

    auto status1 = service_->ValidateSession(&context_, nullptr, &resp);
    EXPECT_EQ(status1.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    auto status2 = service_->ValidateSession(&context_, &req, nullptr);
    EXPECT_EQ(status2.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// Test 2: ValidateSession with unconfigured SessionManager returns UNIMPLEMENTED
TEST_F(AuthServiceSessionTest, ValidateSession_UnconfiguredSessionManager_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service(mock_verifier_, nullptr, mock_audit_pub_);

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id(domain::Uuid::generate_v7().to_string());
    securecloud::auth::v1::ValidateSessionResponse resp;

    auto status = unconfigured_service.ValidateSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

// Test 3: ValidateSession with invalid UUID syntax returns INVALID_ARGUMENT
TEST_F(AuthServiceSessionTest, ValidateSession_InvalidSessionIdUuid_ReturnsInvalidArgument) {
    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("invalid-not-a-uuid");
    securecloud::auth::v1::ValidateSessionResponse resp;

    auto status = service_->ValidateSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// Test 4: ValidateSession with active valid session returns OK and populates response payload
TEST_F(AuthServiceSessionTest, ValidateSession_ActiveValidSession_ReturnsOkAndPopulatesResponsePayload) {
    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::AuthenticationLevel::PrimaryOnly);

    EXPECT_CALL(*mock_session_mgr_, validate_session(session.session_id, _))
        .WillOnce(Return(domain::SessionValidationResult::valid(session)));

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id(session.session_id.to_string());
    securecloud::auth::v1::ValidateSessionResponse resp;

    auto status = service_->ValidateSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OK);
    EXPECT_TRUE(resp.is_valid());
    EXPECT_EQ(resp.user_id(), user_id.to_string());
    EXPECT_EQ(resp.device_id(), device_id.to_string());
    EXPECT_EQ(resp.authentication_level(), securecloud::auth::v1::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_GT(resp.expires_at_epoch_ms(), 0);
}

// Test 5: ValidateSession with expired session returns OK and is_valid false
TEST_F(AuthServiceSessionTest, ValidateSession_ExpiredSession_ReturnsOkAndIsValidFalse) {
    auto session_id = domain::Uuid::generate_v7();

    EXPECT_CALL(*mock_session_mgr_, validate_session(session_id, _))
        .WillOnce(Return(domain::SessionValidationResult::expired("Session expired")));

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id(session_id.to_string());
    securecloud::auth::v1::ValidateSessionResponse resp;

    auto status = service_->ValidateSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OK);
    EXPECT_FALSE(resp.is_valid());
}

// Test 6: ValidateSession with revoked session returns OK and is_valid false
TEST_F(AuthServiceSessionTest, ValidateSession_RevokedSession_ReturnsOkAndIsValidFalse) {
    auto session_id = domain::Uuid::generate_v7();

    EXPECT_CALL(*mock_session_mgr_, validate_session(session_id, _))
        .WillOnce(Return(domain::SessionValidationResult::revoked("Session revoked")));

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id(session_id.to_string());
    securecloud::auth::v1::ValidateSessionResponse resp;

    auto status = service_->ValidateSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OK);
    EXPECT_FALSE(resp.is_valid());
}

// Test 7: ValidateSession with device mismatch returns OK and is_valid false
TEST_F(AuthServiceSessionTest, ValidateSession_DeviceMismatch_ReturnsOkAndIsValidFalse) {
    auto session_id = domain::Uuid::generate_v7();

    EXPECT_CALL(*mock_session_mgr_, validate_session(session_id, _))
        .WillOnce(Return(domain::SessionValidationResult::device_mismatch("Device mismatch")));

    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id(session_id.to_string());
    securecloud::auth::v1::ValidateSessionResponse resp;

    auto status = service_->ValidateSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OK);
    EXPECT_FALSE(resp.is_valid());
}

// Test 8: RevokeSession with null request or response returns INVALID_ARGUMENT
TEST_F(AuthServiceSessionTest, RevokeSession_NullRequestOrResponse_ReturnsInvalidArgument) {
    securecloud::auth::v1::RevokeSessionRequest req;
    securecloud::auth::v1::RevokeSessionResponse resp;

    auto status1 = service_->RevokeSession(&context_, nullptr, &resp);
    EXPECT_EQ(status1.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    auto status2 = service_->RevokeSession(&context_, &req, nullptr);
    EXPECT_EQ(status2.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// Test 9: RevokeSession with unconfigured SessionManager returns UNIMPLEMENTED
TEST_F(AuthServiceSessionTest, RevokeSession_UnconfiguredSessionManager_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service(mock_verifier_, nullptr, mock_audit_pub_);

    securecloud::auth::v1::RevokeSessionRequest req;
    req.set_session_id(domain::Uuid::generate_v7().to_string());
    securecloud::auth::v1::RevokeSessionResponse resp;

    auto status = unconfigured_service.RevokeSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

// Test 10: RevokeSession with invalid UUID syntax returns INVALID_ARGUMENT
TEST_F(AuthServiceSessionTest, RevokeSession_InvalidSessionIdUuid_ReturnsInvalidArgument) {
    securecloud::auth::v1::RevokeSessionRequest req;
    req.set_session_id("invalid-session-uuid");
    securecloud::auth::v1::RevokeSessionResponse resp;

    auto status = service_->RevokeSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// Test 11: RevokeSession with active session succeeds and populates revoked true
TEST_F(AuthServiceSessionTest, RevokeSession_ActiveSession_ReturnsOkAndRevokedTrue) {
    auto session_id = domain::Uuid::generate_v7();

    EXPECT_CALL(*mock_session_mgr_, revoke_session_str(session_id, "User logout"))
        .WillOnce(Return(domain::SessionRevocationResult::success(1)));

    securecloud::auth::v1::RevokeSessionRequest req;
    req.set_session_id(session_id.to_string());
    req.set_reason("User logout");
    securecloud::auth::v1::RevokeSessionResponse resp;

    auto status = service_->RevokeSession(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::OK);
    EXPECT_TRUE(resp.revoked());
}

} // namespace
} // namespace securecloud::auth::service::test
