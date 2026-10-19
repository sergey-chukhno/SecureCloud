#include "auth/domain/auth_result.hpp"
#include "auth/domain/credentials.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
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
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
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
    domain::SessionRevocationResult revoke_session(const domain::Uuid& /*session_id*/,
                                                   std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(1);
    }
    domain::SessionRevocationResult revoke_all_device_sessions(const domain::Uuid& /*device_id*/,
                                                               std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(1);
    }
    domain::SessionRevocationResult revoke_all_user_sessions(const domain::Uuid& /*user_id*/,
                                                             std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(1);
    }
};

class MockAuditEventPublisher : public IAuditEventPublisher {
  public:
    MOCK_METHOD(void, publish, (const domain::AuditEvent&), (noexcept, override));
};

domain::UserEntity create_test_user(domain::AccountStatus status = domain::AccountStatus::Active) {
    domain::UserEntity user;
    user.user_id = domain::Uuid::generate_v7();
    user.credential_identifier = "alice@example.com";
    user.password_verifier = "$argon2id$v=19$m=65536,t=3,p=1$fake_salt$fake_hash";
    user.password_algorithm = "argon2id";
    user.password_updated_at = std::chrono::system_clock::now();
    user.account_status = status;
    user.created_at = std::chrono::system_clock::now();
    user.updated_at = std::chrono::system_clock::now();
    user.version = 1;
    return user;
}

domain::DeviceEntity create_test_device(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                        domain::DeviceStatus status = domain::DeviceStatus::Active) {
    domain::DeviceEntity device;
    device.device_id = device_id;
    device.user_id = user_id;
    device.device_status = status;
    device.registered_at = std::chrono::system_clock::now();
    device.last_authenticated_at = std::chrono::system_clock::now();
    device.created_at = std::chrono::system_clock::now();
    device.updated_at = std::chrono::system_clock::now();
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
    session.last_used_at = session.created_at;
    return session;
}

class AuthServiceAuthenticateTest : public ::testing::Test {
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

// ============================================================================
// 1. Null Request or Response
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_NullRequestOrResponse_ReturnsInvalidArgument) {
    v1::AuthenticateRequest req;
    v1::AuthenticateResponse resp;

    EXPECT_EQ(service_->Authenticate(&context_, nullptr, &resp).error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(service_->Authenticate(&context_, &req, nullptr).error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(service_->Authenticate(&context_, nullptr, nullptr).error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// ============================================================================
// 2. Unconfigured Dependencies
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_UnconfiguredDependencies_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service;
    v1::AuthenticateRequest req;
    v1::AuthenticateResponse resp;

    auto status = unconfigured_service.Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

// ============================================================================
// 3. Invalid Credential Identifier Format
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_InvalidCredentialIdentifier_ReturnsInvalidArgument) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("ab"); // Too short (< 3 characters)
    req.set_password("ValidPassword123!");
    req.set_device_id(domain::Uuid::generate_v7().to_string());
    v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
        EXPECT_EQ(ev.credential_identifier, "ab");
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// ============================================================================
// 4. Invalid Password Format or Length
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_InvalidPassword_ReturnsInvalidArgument) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("valid_user@example.com");
    req.set_password(std::string(1025, 'x')); // Exceeds 1024-byte ceiling
    req.set_device_id(domain::Uuid::generate_v7().to_string());
    v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
        EXPECT_EQ(ev.credential_identifier, "valid_user@example.com");
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// ============================================================================
// 5. Invalid Device UUID Format
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_InvalidDeviceIdUuid_ReturnsInvalidArgument) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("valid_user@example.com");
    req.set_password("ValidPassword123!");
    req.set_device_id("not-a-valid-uuid");
    v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
        EXPECT_EQ(ev.credential_identifier, "valid_user@example.com");
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

// ============================================================================
// 6. Invalid Credentials Outcome
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_InvalidCredentials_ReturnsUnauthenticated) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("valid_user@example.com");
    req.set_password("WrongPassword123!");
    auto dev_id = domain::Uuid::generate_v7();
    req.set_device_id(dev_id.to_string());
    v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_verifier_, verify(_, _))
        .WillOnce(Return(domain::AuthenticationResult::invalid_credentials("Invalid credentials")));

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([dev_id](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
        EXPECT_EQ(ev.credential_identifier, "valid_user@example.com");
        EXPECT_EQ(ev.failure_reason, "Invalid credentials");
        ASSERT_TRUE(ev.device_id.has_value());
        EXPECT_EQ(ev.device_id.value(), dev_id);
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_EQ(status.error_message(), "Invalid credentials");
}

// ============================================================================
// 7. Account Disabled Outcome
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_AccountDisabled_ReturnsPermissionDenied) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("disabled_user@example.com");
    req.set_password("CorrectPassword123!");
    auto dev_id = domain::Uuid::generate_v7();
    req.set_device_id(dev_id.to_string());
    v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_verifier_, verify(_, _))
        .WillOnce(Return(domain::AuthenticationResult::account_disabled("Account is not active")));

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([dev_id](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::AccountDisabledAccessAttempt);
        EXPECT_EQ(ev.credential_identifier, "disabled_user@example.com");
        EXPECT_FALSE(ev.user_id.has_value());
        ASSERT_TRUE(ev.device_id.has_value());
        EXPECT_EQ(ev.device_id.value(), dev_id);
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_EQ(status.error_message(), "Account is disabled");
}

// ============================================================================
// 8. Verifier Internal Error Outcome
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_VerifierInternalError_ReturnsInternal) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("valid_user@example.com");
    req.set_password("CorrectPassword123!");
    req.set_device_id(domain::Uuid::generate_v7().to_string());
    v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_verifier_, verify(_, _))
        .WillOnce(Return(domain::AuthenticationResult::internal_error("Database connection lost")));

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INTERNAL);
}

// ============================================================================
// 9. Session Manager Device Not Found Outcome
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_DeviceNotFound_ReturnsNotFound) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("valid_user@example.com");
    req.set_password("CorrectPassword123!");
    auto dev_id = domain::Uuid::generate_v7();
    req.set_device_id(dev_id.to_string());
    v1::AuthenticateResponse resp;

    auto user = create_test_user();

    EXPECT_CALL(*mock_verifier_, verify(_, _)).WillOnce(Return(domain::AuthenticationResult::success(user)));

    EXPECT_CALL(*mock_session_mgr_, establish_session(_, dev_id))
        .WillOnce(Return(SessionEstablishmentResult::device_not_found("Device does not exist")));

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([user, dev_id](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
        EXPECT_EQ(ev.credential_identifier, "valid_user@example.com");
        ASSERT_TRUE(ev.user_id.has_value());
        EXPECT_EQ(ev.user_id.value(), user.user_id);
        ASSERT_TRUE(ev.device_id.has_value());
        EXPECT_EQ(ev.device_id.value(), dev_id);
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

// ============================================================================
// 10. Session Manager Device Revoked Outcome
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_DeviceRevoked_ReturnsPermissionDenied) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("valid_user@example.com");
    req.set_password("CorrectPassword123!");
    auto dev_id = domain::Uuid::generate_v7();
    req.set_device_id(dev_id.to_string());
    v1::AuthenticateResponse resp;

    auto user = create_test_user();

    EXPECT_CALL(*mock_verifier_, verify(_, _)).WillOnce(Return(domain::AuthenticationResult::success(user)));

    EXPECT_CALL(*mock_session_mgr_, establish_session(_, dev_id))
        .WillOnce(Return(SessionEstablishmentResult::device_revoked("Device revoked")));

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([user, dev_id](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
        EXPECT_EQ(ev.credential_identifier, "valid_user@example.com");
        ASSERT_TRUE(ev.user_id.has_value());
        EXPECT_EQ(ev.user_id.value(), user.user_id);
        ASSERT_TRUE(ev.device_id.has_value());
        EXPECT_EQ(ev.device_id.value(), dev_id);
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

// ============================================================================
// 11. Successful Authentication & Response Population
// ============================================================================

TEST_F(AuthServiceAuthenticateTest, Authenticate_SuccessfulAuthentication_ReturnsOkAndPopulatesResponse) {
    v1::AuthenticateRequest req;
    req.set_credential_identifier("valid_user@example.com");
    req.set_password("CorrectPassword123!");
    auto dev_id = domain::Uuid::generate_v7();
    req.set_device_id(dev_id.to_string());
    v1::AuthenticateResponse resp;

    auto user = create_test_user();
    auto device = create_test_device(user.user_id, dev_id);
    auto session = create_test_session(user.user_id, dev_id);

    EXPECT_CALL(*mock_verifier_, verify(_, _)).WillOnce(Return(domain::AuthenticationResult::success(user)));

    EXPECT_CALL(*mock_session_mgr_, establish_session(_, dev_id))
        .WillOnce(Return(SessionEstablishmentResult::success(session, device)));

    EXPECT_CALL(*mock_audit_pub_, publish(_)).WillOnce([user, dev_id, session](const domain::AuditEvent& ev) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginSucceeded);
        EXPECT_EQ(ev.credential_identifier, "valid_user@example.com");
        ASSERT_TRUE(ev.user_id.has_value());
        EXPECT_EQ(ev.user_id.value(), user.user_id);
        ASSERT_TRUE(ev.device_id.has_value());
        EXPECT_EQ(ev.device_id.value(), dev_id);
        ASSERT_TRUE(ev.session_id.has_value());
        EXPECT_EQ(ev.session_id.value(), session.session_id);
    });

    auto status = service_->Authenticate(&context_, &req, &resp);
    EXPECT_TRUE(status.ok()) << "Error: " << status.error_message();

    // Verify response fields
    EXPECT_EQ(resp.session_id(), session.session_id.to_string());
    EXPECT_EQ(resp.user_id(), user.user_id.to_string());
    EXPECT_EQ(resp.authentication_level(), v1::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_GT(resp.expires_at_epoch_ms(), 0);
    EXPECT_FALSE(resp.mfa_required());
    EXPECT_TRUE(resp.access_token().empty());
    EXPECT_TRUE(resp.refresh_token().empty());
}

} // namespace
} // namespace securecloud::auth::service::test
