#include "auth/domain/auth_result.hpp"
#include "auth/domain/credentials.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/mfa_result.hpp"
#include "auth/domain/token_result.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/credential_verifier.hpp"
#include "auth/service/mfa_manager.hpp"
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
using ::testing::NiceMock;
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
    domain::SessionRevocationResult revoke_session(const domain::Uuid& /*session_id*/,
                                                   std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(1);
    }
    domain::SessionRevocationResult revoke_all_device_sessions(const domain::Uuid& device_id,
                                                               std::string_view reason) override {
        return revoke_all_device_sessions_impl(device_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_all_device_sessions_impl,
                (const domain::Uuid&, const std::string&));
    domain::SessionRevocationResult revoke_all_user_sessions(const domain::Uuid& /*user_id*/,
                                                               std::string_view /*reason*/) override {
        return domain::SessionRevocationResult::success(1);
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
    domain::TokenRefreshResult refresh_tokens(std::string_view refresh_token_raw,
                                              const domain::Uuid& presented_device_id,
                                              std::string_view ip_address) override {
        return refresh_tokens_impl(std::string(refresh_token_raw), presented_device_id, std::string(ip_address));
    }
    MOCK_METHOD(domain::TokenRefreshResult, refresh_tokens_impl,
                (const std::string&, const domain::Uuid&, const std::string&));
};

class MockMfaManager : public IMfaManager {
  public:
    MOCK_METHOD(bool, is_mfa_enabled_for_user, (const domain::Uuid&), (override));

    domain::MfaEnrollmentInitiation initiate_enrollment(
        const domain::Uuid& user_id,
        std::string_view issuer,
        std::string_view account_name) override {
        return initiate_enrollment_impl(user_id, std::string(issuer), std::string(account_name));
    }
    MOCK_METHOD(domain::MfaEnrollmentInitiation, initiate_enrollment_impl,
                (const domain::Uuid&, const std::string&, const std::string&));

    domain::MfaEnrollmentConfirmationResult confirm_enrollment(
        const domain::Uuid& user_id,
        std::string_view code,
        const std::string& client_ip) override {
        return confirm_enrollment_impl(user_id, std::string(code), client_ip);
    }
    MOCK_METHOD(domain::MfaEnrollmentConfirmationResult, confirm_enrollment_impl,
                (const domain::Uuid&, const std::string&, const std::string&));

    bool disable_mfa(
        const domain::Uuid& user_id,
        std::string_view code_or_recovery,
        const std::string& client_ip) override {
        return disable_mfa_impl(user_id, std::string(code_or_recovery), client_ip);
    }
    MOCK_METHOD(bool, disable_mfa_impl,
                (const domain::Uuid&, const std::string&, const std::string&));

    domain::MfaChallengeEntity create_challenge(
        const domain::Uuid& user_id,
        const domain::Uuid& session_id,
        domain::MfaChallengePurpose purpose,
        std::chrono::seconds ttl) override {
        return create_challenge_impl(user_id, session_id, purpose, ttl);
    }
    MOCK_METHOD(domain::MfaChallengeEntity, create_challenge_impl,
                (const domain::Uuid&, const domain::Uuid&, domain::MfaChallengePurpose, std::chrono::seconds));

    domain::MfaChallengeVerificationResult verify_challenge(
        const domain::Uuid& challenge_id,
        std::string_view credential,
        const std::string& client_ip) override {
        return verify_challenge_impl(challenge_id, std::string(credential), client_ip);
    }
    MOCK_METHOD(domain::MfaChallengeVerificationResult, verify_challenge_impl,
                (const domain::Uuid&, const std::string&, const std::string&));
};

domain::UserEntity create_test_user(const domain::Uuid& user_id) {
    domain::UserEntity user;
    user.user_id = user_id;
    user.credential_identifier = "alice@securecloud.io";
    user.password_verifier = "argon2_hash";
    user.password_algorithm = "argon2id";
    user.account_status = domain::AccountStatus::Active;
    user.created_at = std::chrono::system_clock::now();
    user.updated_at = std::chrono::system_clock::now();
    user.version = 1;
    return user;
}

domain::DeviceEntity create_test_device(const domain::Uuid& user_id, const domain::Uuid& device_id) {
    domain::DeviceEntity device;
    device.device_id = device_id;
    device.user_id = user_id;
    device.device_status = domain::DeviceStatus::Active;
    device.registered_at = std::chrono::system_clock::now();
    device.last_authenticated_at = std::chrono::system_clock::now();
    device.created_at = std::chrono::system_clock::now();
    device.updated_at = std::chrono::system_clock::now();
    return device;
}

domain::SessionEntity create_test_session(const domain::Uuid& user_id, const domain::Uuid& device_id,
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

class AuthServiceMfaTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_verifier_ = std::make_shared<StrictMock<MockCredentialVerifier>>();
        mock_session_mgr_ = std::make_shared<StrictMock<MockSessionManager>>();
        mock_audit_pub_ = std::make_shared<NiceMock<MockAuditEventPublisher>>();
        mock_token_mgr_ = std::make_shared<StrictMock<MockTokenManager>>();
        mock_mfa_mgr_ = std::make_shared<StrictMock<MockMfaManager>>();

        user_id_ = domain::Uuid::generate_v7();
        device_id_ = domain::Uuid::generate_v7();
        user_ = create_test_user(user_id_);
        device_ = create_test_device(user_id_, device_id_);
        session_ = create_test_session(user_id_, device_id_);

        service_ = std::make_unique<AuthServiceImpl>(
            mock_verifier_, mock_session_mgr_, mock_audit_pub_, mock_token_mgr_, mock_mfa_mgr_);
    }

    std::shared_ptr<StrictMock<MockCredentialVerifier>> mock_verifier_;
    std::shared_ptr<StrictMock<MockSessionManager>> mock_session_mgr_;
    std::shared_ptr<NiceMock<MockAuditEventPublisher>> mock_audit_pub_;
    std::shared_ptr<StrictMock<MockTokenManager>> mock_token_mgr_;
    std::shared_ptr<StrictMock<MockMfaManager>> mock_mfa_mgr_;
    std::unique_ptr<AuthServiceImpl> service_;

    domain::Uuid user_id_;
    domain::Uuid device_id_;
    domain::UserEntity user_;
    domain::DeviceEntity device_;
    domain::SessionEntity session_;
    grpc::ServerContext context_;
};

// ============================================================================
// 1. Authenticate with MFA Step-Up Tests
// ============================================================================

TEST_F(AuthServiceMfaTest, Authenticate_UserWithoutMfa_ReturnsPrimaryTokensAndMfaNotRequired) {
    securecloud::auth::v1::AuthenticateRequest req;
    req.set_credential_identifier("alice@securecloud.io");
    req.set_password("CorrectPassword123!");
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_verifier_, verify(_, _)).WillOnce(Return(domain::AuthenticationResult::success(user_)));
    EXPECT_CALL(*mock_session_mgr_, establish_session(_, _))
        .WillOnce(Return(SessionEstablishmentResult::success(session_, device_)));
    EXPECT_CALL(*mock_mfa_mgr_, is_mfa_enabled_for_user(user_id_)).WillOnce(Return(false));

    domain::TokenPair tokens;
    tokens.access_token = "ey.mock.primary.token";
    tokens.refresh_token = domain::SecretTokenString("mock_refresh_token_secret");
    tokens.expires_at = session_.expires_at;
    EXPECT_CALL(*mock_token_mgr_, issue_initial_tokens(_, _)).WillOnce(Return(tokens));

    auto status = service_->Authenticate(&context_, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_FALSE(resp.mfa_required());
    EXPECT_TRUE(resp.mfa_challenge_id().empty());
    EXPECT_EQ(resp.access_token(), "ey.mock.primary.token");
    EXPECT_EQ(resp.refresh_token(), "mock_refresh_token_secret");
    EXPECT_EQ(resp.authentication_level(), securecloud::auth::v1::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_EQ(resp.session_id(), session_.session_id.to_string());
    EXPECT_EQ(resp.user_id(), user_id_.to_string());
}

TEST_F(AuthServiceMfaTest, Authenticate_UserWithMfa_ReturnsMfaRequiredAndSuppressesTokens) {
    securecloud::auth::v1::AuthenticateRequest req;
    req.set_credential_identifier("alice@securecloud.io");
    req.set_password("CorrectPassword123!");
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::AuthenticateResponse resp;

    EXPECT_CALL(*mock_verifier_, verify(_, _)).WillOnce(Return(domain::AuthenticationResult::success(user_)));
    EXPECT_CALL(*mock_session_mgr_, establish_session(_, _))
        .WillOnce(Return(SessionEstablishmentResult::success(session_, device_)));
    EXPECT_CALL(*mock_mfa_mgr_, is_mfa_enabled_for_user(user_id_)).WillOnce(Return(true));

    domain::MfaChallengeEntity challenge;
    challenge.mfa_challenge_id = domain::Uuid::generate_v7();
    challenge.user_id = user_id_;
    challenge.session_id = session_.session_id;
    challenge.challenge_purpose = domain::MfaChallengePurpose::Login;
    challenge.challenge_status = domain::MfaChallengeStatus::Pending;
    challenge.created_at = std::chrono::system_clock::now();
    challenge.expires_at = challenge.created_at + std::chrono::minutes(5);

    EXPECT_CALL(*mock_mfa_mgr_, create_challenge_impl(user_id_, session_.session_id, domain::MfaChallengePurpose::Login, _))
        .WillOnce(Return(challenge));
    EXPECT_CALL(*mock_token_mgr_, issue_initial_tokens(_, _)).Times(0);

    auto status = service_->Authenticate(&context_, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(resp.mfa_required());
    EXPECT_EQ(resp.mfa_challenge_id(), challenge.mfa_challenge_id.to_string());
    EXPECT_TRUE(resp.access_token().empty());
    EXPECT_TRUE(resp.refresh_token().empty());
    EXPECT_EQ(resp.authentication_level(), securecloud::auth::v1::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_EQ(resp.session_id(), session_.session_id.to_string());
    EXPECT_EQ(resp.user_id(), user_id_.to_string());
}

// ============================================================================
// 2. VerifyMfaChallenge RPC Tests
// ============================================================================

TEST_F(AuthServiceMfaTest, VerifyMfaChallenge_ValidCode_PromotesAndReturnsMfaVerifiedTokens) {
    auto challenge_id = domain::Uuid::generate_v7();
    securecloud::auth::v1::VerifyMfaChallengeRequest req;
    req.set_challenge_id(challenge_id.to_string());
    req.set_code("123456");
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;

    auto ver_res = domain::MfaChallengeVerificationResult::success(1234567, session_.session_id, user_id_);
    EXPECT_CALL(*mock_mfa_mgr_, verify_challenge_impl(challenge_id, "123456", _)).WillOnce(Return(ver_res));

    auto verified_session = session_;
    verified_session.authentication_level = domain::AuthenticationLevel::MfaVerified;
    EXPECT_CALL(*mock_session_mgr_, validate_session(session_.session_id, _))
        .WillOnce(Return(domain::SessionValidationResult::valid(verified_session)));

    domain::TokenPair tokens;
    tokens.access_token = "ey.mock.mfa_verified.token";
    tokens.refresh_token = domain::SecretTokenString("new_verified_refresh_secret");
    tokens.expires_at = verified_session.expires_at;
    EXPECT_CALL(*mock_token_mgr_, issue_initial_tokens(_, _)).WillOnce(Return(tokens));

    auto status = service_->VerifyMfaChallenge(&context_, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(resp.session_id(), session_.session_id.to_string());
    EXPECT_EQ(resp.access_token(), "ey.mock.mfa_verified.token");
    EXPECT_EQ(resp.refresh_token(), "new_verified_refresh_secret");
    EXPECT_EQ(resp.authentication_level(), securecloud::auth::v1::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    EXPECT_GT(resp.expires_at_epoch_ms(), 0);
}

TEST_F(AuthServiceMfaTest, VerifyMfaChallenge_InvalidCode_ReturnsUnauthenticated) {
    auto challenge_id = domain::Uuid::generate_v7();
    securecloud::auth::v1::VerifyMfaChallengeRequest req;
    req.set_challenge_id(challenge_id.to_string());
    req.set_code("000000");
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;

    auto ver_res = domain::MfaChallengeVerificationResult::failure(
        domain::MfaChallengeVerificationStatus::InvalidCode, "Invalid verification code");
    EXPECT_CALL(*mock_mfa_mgr_, verify_challenge_impl(challenge_id, "000000", _)).WillOnce(Return(ver_res));

    auto status = service_->VerifyMfaChallenge(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_NE(status.error_message().find("Invalid verification code"), std::string::npos);
}

TEST_F(AuthServiceMfaTest, VerifyMfaChallenge_ExpiredChallenge_ReturnsDeadlineExceeded) {
    auto challenge_id = domain::Uuid::generate_v7();
    securecloud::auth::v1::VerifyMfaChallengeRequest req;
    req.set_challenge_id(challenge_id.to_string());
    req.set_code("123456");
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;

    auto ver_res = domain::MfaChallengeVerificationResult::failure(
        domain::MfaChallengeVerificationStatus::ExpiredChallenge, "MFA challenge has expired");
    EXPECT_CALL(*mock_mfa_mgr_, verify_challenge_impl(challenge_id, "123456", _)).WillOnce(Return(ver_res));

    auto status = service_->VerifyMfaChallenge(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::DEADLINE_EXCEEDED);
}

TEST_F(AuthServiceMfaTest, VerifyMfaChallenge_MaxAttemptsExceeded_ReturnsPermissionDenied) {
    auto challenge_id = domain::Uuid::generate_v7();
    securecloud::auth::v1::VerifyMfaChallengeRequest req;
    req.set_challenge_id(challenge_id.to_string());
    req.set_code("123456");
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;

    auto ver_res = domain::MfaChallengeVerificationResult::failure(
        domain::MfaChallengeVerificationStatus::MaxAttemptsExceeded, "Max verification attempts exceeded");
    EXPECT_CALL(*mock_mfa_mgr_, verify_challenge_impl(challenge_id, "123456", _)).WillOnce(Return(ver_res));

    auto status = service_->VerifyMfaChallenge(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuthServiceMfaTest, VerifyMfaChallenge_InvalidUuidFormat_ReturnsInvalidArgument) {
    securecloud::auth::v1::VerifyMfaChallengeRequest req;
    req.set_challenge_id("not-a-valid-uuid");
    req.set_code("123456");
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;

    auto status = service_->VerifyMfaChallenge(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceMfaTest, VerifyMfaChallenge_EmptyCode_ReturnsInvalidArgument) {
    auto challenge_id = domain::Uuid::generate_v7();
    securecloud::auth::v1::VerifyMfaChallengeRequest req;
    req.set_challenge_id(challenge_id.to_string());
    req.set_code("");
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;

    auto status = service_->VerifyMfaChallenge(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServiceMfaTest, VerifyMfaChallenge_NullMfaManager_ReturnsUnavailable) {
    AuthServiceImpl no_mfa_service(mock_verifier_, mock_session_mgr_, mock_audit_pub_, mock_token_mgr_, nullptr);
    auto challenge_id = domain::Uuid::generate_v7();
    securecloud::auth::v1::VerifyMfaChallengeRequest req;
    req.set_challenge_id(challenge_id.to_string());
    req.set_code("123456");
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;

    auto status = no_mfa_service.VerifyMfaChallenge(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
}

// ============================================================================
// 3. Enrollment and Disablement RPC Tests
// ============================================================================

TEST_F(AuthServiceMfaTest, InitiateMfaEnrollment_Success_ReturnsSecretAndUri) {
    securecloud::auth::v1::InitiateMfaEnrollmentRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_issuer("SecureCloud");
    req.set_account_name("alice@securecloud.io");
    securecloud::auth::v1::InitiateMfaEnrollmentResponse resp;

    domain::MfaEnrollmentInitiation init_res;
    init_res.mfa_configuration_id = domain::Uuid::generate_v7();
    init_res.base32_secret = domain::SecretMfaString("JBSWY3DPEHPK3PXP");
    init_res.otpauth_uri = "otpauth://totp/SecureCloud:alice?secret=JBSWY3DPEHPK3PXP";

    EXPECT_CALL(*mock_mfa_mgr_, initiate_enrollment_impl(user_id_, "SecureCloud", "alice@securecloud.io"))
        .WillOnce(Return(init_res));

    auto status = service_->InitiateMfaEnrollment(&context_, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(resp.mfa_configuration_id(), init_res.mfa_configuration_id.to_string());
    EXPECT_EQ(resp.secret(), "JBSWY3DPEHPK3PXP");
    EXPECT_EQ(resp.otpauth_uri(), init_res.otpauth_uri);
}

TEST_F(AuthServiceMfaTest, ConfirmMfaEnrollment_Success_ReturnsRecoveryCodes) {
    securecloud::auth::v1::ConfirmMfaEnrollmentRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_code("123456");
    securecloud::auth::v1::ConfirmMfaEnrollmentResponse resp;

    std::vector<std::string> recovery_codes = {
        "1111-2222", "3333-4444", "5555-6666", "7777-8888",
        "9999-0000", "AAAA-BBBB", "CCCC-DDDD", "EEEE-FFFF"
    };
    auto confirm_res = domain::MfaEnrollmentConfirmationResult::success(recovery_codes);

    EXPECT_CALL(*mock_mfa_mgr_, confirm_enrollment_impl(user_id_, "123456", _)).WillOnce(Return(confirm_res));

    auto status = service_->ConfirmMfaEnrollment(&context_, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(resp.success());
    EXPECT_EQ(resp.recovery_codes_size(), 8);
    EXPECT_EQ(resp.recovery_codes(0), "1111-2222");
}

TEST_F(AuthServiceMfaTest, ConfirmMfaEnrollment_InvalidCode_ReturnsUnauthenticated) {
    securecloud::auth::v1::ConfirmMfaEnrollmentRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_code("000000");
    securecloud::auth::v1::ConfirmMfaEnrollmentResponse resp;

    auto confirm_res = domain::MfaEnrollmentConfirmationResult::failure(
        domain::MfaEnrollmentStatus::InvalidCode, "Invalid verification code");

    EXPECT_CALL(*mock_mfa_mgr_, confirm_enrollment_impl(user_id_, "000000", _)).WillOnce(Return(confirm_res));

    auto status = service_->ConfirmMfaEnrollment(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_FALSE(resp.success());
}

TEST_F(AuthServiceMfaTest, DisableMfa_ValidCode_ReturnsSuccess) {
    service_->set_caller_auth_level_for_testing(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    securecloud::auth::v1::DisableMfaRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_code("123456");
    securecloud::auth::v1::DisableMfaResponse resp;

    EXPECT_CALL(*mock_mfa_mgr_, disable_mfa_impl(user_id_, "123456", _)).WillOnce(Return(true));

    auto status = service_->DisableMfa(&context_, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(resp.success());
}

TEST_F(AuthServiceMfaTest, DisableMfa_InvalidCode_ReturnsUnauthenticated) {
    service_->set_caller_auth_level_for_testing(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    securecloud::auth::v1::DisableMfaRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_code("000000");
    securecloud::auth::v1::DisableMfaResponse resp;

    EXPECT_CALL(*mock_mfa_mgr_, disable_mfa_impl(user_id_, "000000", _)).WillOnce(Return(false));

    auto status = service_->DisableMfa(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_FALSE(resp.success());
}

TEST_F(AuthServiceMfaTest, DisableMfa_NotMfaVerified_ReturnsPermissionDenied) {
    service_->set_caller_auth_level_for_testing(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    securecloud::auth::v1::DisableMfaRequest req;
    req.set_user_id(user_id_.to_string());
    req.set_code("123456");
    securecloud::auth::v1::DisableMfaResponse resp;

    EXPECT_CALL(*mock_mfa_mgr_, disable_mfa_impl(_, _, _)).Times(0);

    auto status = service_->DisableMfa(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_FALSE(resp.success());
}

TEST_F(AuthServiceMfaTest, RevokeDevice_NotMfaVerified_ReturnsPermissionDenied) {
    service_->set_caller_auth_level_for_testing(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    securecloud::auth::v1::RevokeDeviceRequest req;
    req.set_device_id(device_id_.to_string());
    req.set_user_id(user_id_.to_string());
    req.set_reason("Lost phone");
    securecloud::auth::v1::RevokeDeviceResponse resp;

    auto status = service_->RevokeDevice(&context_, &req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_FALSE(resp.revoked());
}

TEST_F(AuthServiceMfaTest, RevokeDevice_MfaVerified_RevokesAndReturnsSuccess) {
    service_->set_caller_auth_level_for_testing(securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    securecloud::auth::v1::RevokeDeviceRequest req;
    req.set_device_id(device_id_.to_string());
    req.set_user_id(user_id_.to_string());
    req.set_reason("Lost phone");
    securecloud::auth::v1::RevokeDeviceResponse resp;

    EXPECT_CALL(*mock_session_mgr_, revoke_all_device_sessions_impl(device_id_, "Lost phone"))
        .WillOnce(Return(domain::SessionRevocationResult::success(2)));

    auto status = service_->RevokeDevice(&context_, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(resp.revoked());
    EXPECT_GT(resp.revoked_at_epoch_ms(), 0);
}

} // namespace
} // namespace securecloud::auth::service::test
