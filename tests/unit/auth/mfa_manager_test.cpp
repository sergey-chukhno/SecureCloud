#include "auth/crypto/mfa_secret_protector.hpp"
#include "auth/crypto/recovery_code_generator.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/mfa_result.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/mfa_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/mfa_authenticator_interface.hpp"
#include "auth/service/mfa_manager.hpp"

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

using crypto::MfaSecretProtector;
using crypto::TotpConfig;
using crypto::TotpEngine;
using domain::AuthenticationLevel;
using domain::MfaChallengeEntity;
using domain::MfaChallengePurpose;
using domain::MfaChallengeStatus;
using domain::MfaChallengeVerificationStatus;
using domain::MfaConfigurationEntity;
using domain::MfaEnrollmentStatus;
using domain::MfaFactorType;
using domain::MfaStatus;
using domain::SessionEntity;
using domain::SessionStatus;
using domain::UserEntity;
using domain::Uuid;
using repository::IMfaRepository;
using repository::ISessionRepository;
using repository::IUserRepository;

// ============================================================================
// Mock Repositories
// ============================================================================

class MockMfaRepository : public IMfaRepository {
  public:
    MOCK_METHOD(void, store_mfa_configuration, (const MfaConfigurationEntity&), (override));
    void store_mfa_configuration(const MfaConfigurationEntity& config, pqxx::transaction_base&) override {
        store_mfa_configuration(config);
    }

    MOCK_METHOD(std::optional<MfaConfigurationEntity>, find_mfa_config_by_user_id, (const Uuid&), (override));
    std::optional<MfaConfigurationEntity> find_mfa_config_by_user_id(const Uuid& user_id,
                                                                     pqxx::transaction_base&) override {
        return find_mfa_config_by_user_id(user_id);
    }

    MOCK_METHOD(void, enable_mfa, (const Uuid&, domain::time_point, uint64_t), (override));
    void enable_mfa(const Uuid& config_id, domain::time_point enabled_at, uint64_t expected_version,
                    pqxx::transaction_base&) override {
        enable_mfa(config_id, enabled_at, expected_version);
    }

    MOCK_METHOD(void, disable_mfa, (const Uuid&, domain::time_point, uint64_t), (override));
    void disable_mfa(const Uuid& config_id, domain::time_point disabled_at, uint64_t expected_version,
                     pqxx::transaction_base&) override {
        disable_mfa(config_id, disabled_at, expected_version);
    }

    MOCK_METHOD(void, create_challenge, (const MfaChallengeEntity&), (override));
    void create_challenge(const MfaChallengeEntity& challenge, pqxx::transaction_base&) override {
        create_challenge(challenge);
    }

    MOCK_METHOD(std::optional<MfaChallengeEntity>, find_challenge_by_id, (const Uuid&), (override));
    std::optional<MfaChallengeEntity> find_challenge_by_id(const Uuid& challenge_id, pqxx::transaction_base&) override {
        return find_challenge_by_id(challenge_id);
    }

    MOCK_METHOD(void, complete_challenge, (const Uuid&, domain::time_point), (override));
    void complete_challenge(const Uuid& challenge_id, domain::time_point completed_at,
                            pqxx::transaction_base&) override {
        complete_challenge(challenge_id, completed_at);
    }

    MOCK_METHOD(void, fail_challenge, (const Uuid&), (override));
    void fail_challenge(const Uuid& challenge_id, pqxx::transaction_base&) override { fail_challenge(challenge_id); }
};

class MockSessionRepository : public ISessionRepository {
  public:
    MOCK_METHOD(void, create_session, (const SessionEntity&), (override));
    void create_session(const SessionEntity& s, pqxx::transaction_base&) override { create_session(s); }

    MOCK_METHOD(std::optional<SessionEntity>, find_by_id, (const Uuid&), (override));
    std::optional<SessionEntity> find_by_id(const Uuid& id, pqxx::transaction_base&) override { return find_by_id(id); }

    MOCK_METHOD(std::vector<SessionEntity>, list_active_by_user_id, (const Uuid&), (override));
    std::vector<SessionEntity> list_active_by_user_id(const Uuid& u, pqxx::transaction_base&) override {
        return list_active_by_user_id(u);
    }

    MOCK_METHOD(std::vector<SessionEntity>, list_active_by_device_id, (const Uuid&), (override));
    std::vector<SessionEntity> list_active_by_device_id(const Uuid& d, pqxx::transaction_base&) override {
        return list_active_by_device_id(d);
    }

    MOCK_METHOD(void, update_authentication_level, (const Uuid&, AuthenticationLevel), (override));
    void update_authentication_level(const Uuid& s, AuthenticationLevel l, pqxx::transaction_base&) override {
        update_authentication_level(s, l);
    }

    MOCK_METHOD(void, revoke_session, (const Uuid&, domain::time_point), (override));
    void revoke_session(const Uuid& s, domain::time_point t, pqxx::transaction_base&) override { revoke_session(s, t); }

    MOCK_METHOD(void, revoke_all_user_sessions, (const Uuid&, domain::time_point), (override));
    void revoke_all_user_sessions(const Uuid& u, domain::time_point t, pqxx::transaction_base&) override {
        revoke_all_user_sessions(u, t);
    }

    MOCK_METHOD(void, revoke_all_device_sessions, (const Uuid&, domain::time_point), (override));
    void revoke_all_device_sessions(const Uuid& d, domain::time_point t, pqxx::transaction_base&) override {
        revoke_all_device_sessions(d, t);
    }

    MOCK_METHOD(bool, touch_session_activity, (const Uuid&, domain::time_point), (override));
    bool touch_session_activity(const Uuid& s, domain::time_point t, pqxx::transaction_base&) override {
        return touch_session_activity(s, t);
    }

    MOCK_METHOD(uint64_t, expire_stale_sessions, (domain::time_point), (override));
    uint64_t expire_stale_sessions(domain::time_point t, pqxx::transaction_base&) override {
        return expire_stale_sessions(t);
    }

    MOCK_METHOD(bool, revoke_session_atomic, (const Uuid&, domain::time_point), (override));
    bool revoke_session_atomic(const Uuid& s, domain::time_point t, pqxx::transaction_base&) override {
        return revoke_session_atomic(s, t);
    }

    MOCK_METHOD(uint64_t, revoke_all_device_sessions_atomic, (const Uuid&, domain::time_point), (override));
    uint64_t revoke_all_device_sessions_atomic(const Uuid& d, domain::time_point t, pqxx::transaction_base&) override {
        return revoke_all_device_sessions_atomic(d, t);
    }

    MOCK_METHOD(uint64_t, revoke_all_user_sessions_atomic, (const Uuid&, domain::time_point), (override));
    uint64_t revoke_all_user_sessions_atomic(const Uuid& u, domain::time_point t, pqxx::transaction_base&) override {
        return revoke_all_user_sessions_atomic(u, t);
    }
};

class MockUserRepository : public IUserRepository {
  public:
    MOCK_METHOD(void, create_user, (const UserEntity&), (override));
    void create_user(const UserEntity& u, pqxx::transaction_base&) override { create_user(u); }

    MOCK_METHOD(std::optional<UserEntity>, find_by_id, (const Uuid&), (override));
    std::optional<UserEntity> find_by_id(const Uuid& id, pqxx::transaction_base&) override { return find_by_id(id); }

    std::optional<UserEntity> find_by_credential_identifier(std::string_view id) override {
        return find_by_credential_identifier_str(std::string(id));
    }
    std::optional<UserEntity> find_by_credential_identifier(std::string_view id, pqxx::transaction_base&) override {
        return find_by_credential_identifier_str(std::string(id));
    }
    MOCK_METHOD(std::optional<UserEntity>, find_by_credential_identifier_str, (const std::string&));

    MOCK_METHOD(void, update_user, (const UserEntity&), (override));
    void update_user(const UserEntity& u, pqxx::transaction_base&) override { update_user(u); }

    MOCK_METHOD(void, set_account_status, (const Uuid&, domain::AccountStatus, uint64_t), (override));
    void set_account_status(const Uuid& id, domain::AccountStatus s, uint64_t v, pqxx::transaction_base&) override {
        set_account_status(id, s, v);
    }
};

class MockAuditEventPublisher : public IAuditEventPublisher {
  public:
    MOCK_METHOD(void, publish, (const domain::AuditEvent&), (noexcept, override));
};

// ============================================================================
// Fixture Setup
// ============================================================================

class MfaManagerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const std::string kek_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        secret_protector_ = std::make_shared<MfaSecretProtector>(kek_hex);
        totp_engine_ = std::make_shared<TotpEngine>();
        authenticator_ = std::make_shared<TotpAuthenticator>(totp_engine_, secret_protector_);

        mfa_repository_ = std::make_shared<MockMfaRepository>();
        session_repository_ = std::make_shared<MockSessionRepository>();
        user_repository_ = std::make_shared<MockUserRepository>();
        audit_publisher_ = std::make_shared<MockAuditEventPublisher>();

        mfa_manager_ = std::make_unique<MfaManager>(mfa_repository_, session_repository_, user_repository_,
                                                    authenticator_, totp_engine_, secret_protector_, audit_publisher_);

        user_id_ = Uuid::generate_v7();
        session_id_ = Uuid::generate_v7();

        user_.user_id = user_id_;
        user_.credential_identifier = "alice@securecloud.io";
        user_.account_status = domain::AccountStatus::Active;
    }

    std::shared_ptr<MfaSecretProtector> secret_protector_;
    std::shared_ptr<TotpEngine> totp_engine_;
    std::shared_ptr<TotpAuthenticator> authenticator_;

    std::shared_ptr<MockMfaRepository> mfa_repository_;
    std::shared_ptr<MockSessionRepository> session_repository_;
    std::shared_ptr<MockUserRepository> user_repository_;
    std::shared_ptr<MockAuditEventPublisher> audit_publisher_;

    std::unique_ptr<MfaManager> mfa_manager_;

    Uuid user_id_;
    Uuid session_id_;
    UserEntity user_;
};

// ============================================================================
// 1. Enrollment Tests
// ============================================================================

TEST_F(MfaManagerTest, InitiateEnrollment_Success_StoresPendingConfigAndReturnsUri) {
    EXPECT_CALL(*user_repository_, find_by_id(user_id_)).WillOnce(Return(user_));
    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillOnce(Return(std::nullopt));

    MfaConfigurationEntity stored_config;
    EXPECT_CALL(*mfa_repository_, store_mfa_configuration(_)).WillOnce(DoAll(SaveArg<0>(&stored_config), Return()));
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    auto result = mfa_manager_->initiate_enrollment(user_id_, "SecureCloud");

    EXPECT_EQ(result.mfa_configuration_id, stored_config.mfa_configuration_id);
    EXPECT_FALSE(result.base32_secret.empty());
    EXPECT_NE(result.otpauth_uri.find("otpauth://totp/SecureCloud:alice%40securecloud.io"), std::string::npos);
    EXPECT_EQ(stored_config.status, MfaStatus::Pending);
    EXPECT_EQ(stored_config.user_id, user_id_);
    EXPECT_EQ(stored_config.factor_type, MfaFactorType::Totp);
}

TEST_F(MfaManagerTest, InitiateEnrollment_AlreadyEnabled_ThrowsException) {
    EXPECT_CALL(*user_repository_, find_by_id(user_id_)).WillOnce(Return(user_));

    MfaConfigurationEntity existing;
    existing.status = MfaStatus::Enabled;
    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillOnce(Return(existing));

    EXPECT_THROW((void)mfa_manager_->initiate_enrollment(user_id_), std::runtime_error);
}

TEST_F(MfaManagerTest, ConfirmEnrollment_Success_ActivatesConfigAndReturnsRecoveryCodes) {
    // Generate valid secret and encrypted payload
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity pending_config;
    pending_config.mfa_configuration_id = Uuid::generate_v7();
    pending_config.user_id = user_id_;
    pending_config.status = MfaStatus::Pending;
    pending_config.encrypted_secret = encrypted;
    pending_config.version = 1;

    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillOnce(Return(pending_config));
    EXPECT_CALL(*mfa_repository_, enable_mfa(pending_config.mfa_configuration_id, _, 1)).Times(1);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string valid_code = totp_engine_->compute_code(secret, now);

    auto confirm_res = mfa_manager_->confirm_enrollment(user_id_, valid_code);

    EXPECT_TRUE(confirm_res.is_success());
    EXPECT_EQ(confirm_res.status, MfaEnrollmentStatus::Success);
    EXPECT_EQ(confirm_res.recovery_codes.size(), 8u);
}

TEST_F(MfaManagerTest, ConfirmEnrollment_InvalidCode_RejectsAndRemainsPending) {
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity pending_config;
    pending_config.mfa_configuration_id = Uuid::generate_v7();
    pending_config.user_id = user_id_;
    pending_config.status = MfaStatus::Pending;
    pending_config.encrypted_secret = encrypted;
    pending_config.version = 1;

    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillOnce(Return(pending_config));
    EXPECT_CALL(*mfa_repository_, enable_mfa(_, _, _)).Times(0);

    auto confirm_res = mfa_manager_->confirm_enrollment(user_id_, "000000");

    EXPECT_FALSE(confirm_res.is_success());
    EXPECT_EQ(confirm_res.status, MfaEnrollmentStatus::InvalidCode);
    EXPECT_TRUE(confirm_res.recovery_codes.empty());
}

// ============================================================================
// 2. Challenge Lifecycle & Promotion Tests
// ============================================================================

TEST_F(MfaManagerTest, CreateChallenge_InsertsPendingChallengeWithTtl) {
    MfaChallengeEntity saved_challenge;
    EXPECT_CALL(*mfa_repository_, create_challenge(_)).WillOnce(DoAll(SaveArg<0>(&saved_challenge), Return()));
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    auto challenge = mfa_manager_->create_challenge(user_id_, session_id_, MfaChallengePurpose::Login);

    EXPECT_EQ(challenge.user_id, user_id_);
    EXPECT_EQ(challenge.session_id, session_id_);
    EXPECT_EQ(challenge.challenge_purpose, MfaChallengePurpose::Login);
    EXPECT_EQ(challenge.challenge_status, MfaChallengeStatus::Pending);
    EXPECT_GT(challenge.expires_at, challenge.created_at);
}

TEST_F(MfaManagerTest, VerifyChallenge_Success_PromotesSessionToMfaVerified) {
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity active_config;
    active_config.user_id = user_id_;
    active_config.status = MfaStatus::Enabled;
    active_config.encrypted_secret = encrypted;

    auto challenge_id = Uuid::generate_v7();
    MfaChallengeEntity challenge;
    challenge.mfa_challenge_id = challenge_id;
    challenge.user_id = user_id_;
    challenge.session_id = session_id_;
    challenge.challenge_status = MfaChallengeStatus::Pending;
    challenge.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5);

    EXPECT_CALL(*mfa_repository_, find_challenge_by_id(challenge_id)).WillOnce(Return(challenge));
    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillOnce(Return(active_config));
    EXPECT_CALL(*mfa_repository_, complete_challenge(challenge_id, _)).Times(1);
    EXPECT_CALL(*session_repository_, update_authentication_level(session_id_, AuthenticationLevel::MfaVerified))
        .Times(1);
    EXPECT_CALL(*session_repository_, touch_session_activity(session_id_, _)).Times(1);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string valid_code = totp_engine_->compute_code(secret, now);

    auto result = mfa_manager_->verify_challenge(challenge_id, valid_code);

    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.status, MfaChallengeVerificationStatus::Success);
    EXPECT_EQ(result.matched_time_step, now / 30);
}

// ============================================================================
// 3. Security Invariants: Anti-Replay & Brute-Force Lockout
// ============================================================================

TEST_F(MfaManagerTest, AntiReplay_RejectsIdenticalCodeWithinSameTimeWindow) {
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity active_config;
    active_config.user_id = user_id_;
    active_config.status = MfaStatus::Enabled;
    active_config.encrypted_secret = encrypted;

    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string code = totp_engine_->compute_code(secret, now);

    // 1st challenge with code -> Succeeds
    auto ch1_id = Uuid::generate_v7();
    MfaChallengeEntity ch1;
    ch1.mfa_challenge_id = ch1_id;
    ch1.user_id = user_id_;
    ch1.session_id = session_id_;
    ch1.challenge_status = MfaChallengeStatus::Pending;
    ch1.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5);

    EXPECT_CALL(*mfa_repository_, find_challenge_by_id(ch1_id)).WillOnce(Return(ch1));
    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillRepeatedly(Return(active_config));
    EXPECT_CALL(*mfa_repository_, complete_challenge(ch1_id, _)).Times(1);

    auto res1 = mfa_manager_->verify_challenge(ch1_id, code);
    EXPECT_TRUE(res1.is_success());

    // 2nd challenge replaying the same code in same time step -> REJECTED
    auto ch2_id = Uuid::generate_v7();
    MfaChallengeEntity ch2;
    ch2.mfa_challenge_id = ch2_id;
    ch2.user_id = user_id_;
    ch2.session_id = session_id_;
    ch2.challenge_status = MfaChallengeStatus::Pending;
    ch2.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5);

    EXPECT_CALL(*mfa_repository_, find_challenge_by_id(ch2_id)).WillOnce(Return(ch2));
    EXPECT_CALL(*mfa_repository_, complete_challenge(ch2_id, _)).Times(0);

    auto res2 = mfa_manager_->verify_challenge(ch2_id, code);
    EXPECT_FALSE(res2.is_success());
    EXPECT_NE(res2.error_message.find("replay detected"), std::string::npos);
}

TEST_F(MfaManagerTest, BruteForceLockout_ThreeFailedAttemptsTransitionsToFailed) {
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity active_config;
    active_config.user_id = user_id_;
    active_config.status = MfaStatus::Enabled;
    active_config.encrypted_secret = encrypted;

    auto ch_id = Uuid::generate_v7();
    MfaChallengeEntity ch;
    ch.mfa_challenge_id = ch_id;
    ch.user_id = user_id_;
    ch.session_id = session_id_;
    ch.challenge_status = MfaChallengeStatus::Pending;
    ch.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5);

    EXPECT_CALL(*mfa_repository_, find_challenge_by_id(ch_id)).WillRepeatedly(Return(ch));
    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillRepeatedly(Return(active_config));

    // Attempt 1: bad code
    auto res1 = mfa_manager_->verify_challenge(ch_id, "111111");
    EXPECT_EQ(res1.status, MfaChallengeVerificationStatus::InvalidCode);

    // Attempt 2: bad code
    auto res2 = mfa_manager_->verify_challenge(ch_id, "222222");
    EXPECT_EQ(res2.status, MfaChallengeVerificationStatus::InvalidCode);

    // Attempt 3: bad code -> Lockout! Fails the challenge in repository
    EXPECT_CALL(*mfa_repository_, fail_challenge(ch_id)).Times(1);
    auto res3 = mfa_manager_->verify_challenge(ch_id, "333333");
    EXPECT_EQ(res3.status, MfaChallengeVerificationStatus::MaxAttemptsExceeded);
}

TEST_F(MfaManagerTest, VerifyChallenge_ExpiredChallenge_MarksFailedAndRejects) {
    auto ch_id = Uuid::generate_v7();
    MfaChallengeEntity ch;
    ch.mfa_challenge_id = ch_id;
    ch.user_id = user_id_;
    ch.session_id = session_id_;
    ch.challenge_status = MfaChallengeStatus::Pending;
    ch.expires_at = std::chrono::system_clock::now() - std::chrono::seconds(10); // Expired 10s ago

    EXPECT_CALL(*mfa_repository_, find_challenge_by_id(ch_id)).WillOnce(Return(ch));
    EXPECT_CALL(*mfa_repository_, fail_challenge(ch_id)).Times(1);

    auto res = mfa_manager_->verify_challenge(ch_id, "123456");
    EXPECT_EQ(res.status, MfaChallengeVerificationStatus::ExpiredChallenge);
}

// ============================================================================
// 4. Recovery Code Fallback & Disablement Tests
// ============================================================================

TEST_F(MfaManagerTest, RecoveryCode_SatisfiesChallengeAndBurnsCode) {
    // 1. Confirm enrollment to populate recovery codes in manager
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity pending_config;
    pending_config.mfa_configuration_id = Uuid::generate_v7();
    pending_config.user_id = user_id_;
    pending_config.status = MfaStatus::Pending;
    pending_config.encrypted_secret = encrypted;
    pending_config.version = 1;

    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillRepeatedly(Return(pending_config));

    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string valid_code = totp_engine_->compute_code(secret, now);

    auto confirm_res = mfa_manager_->confirm_enrollment(user_id_, valid_code);
    ASSERT_TRUE(confirm_res.is_success());
    ASSERT_EQ(confirm_res.recovery_codes.size(), 8u);

    std::string emergency_code = confirm_res.recovery_codes[0];

    // 2. Challenge verified with emergency recovery code
    MfaConfigurationEntity active_config = pending_config;
    active_config.status = MfaStatus::Enabled;
    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillRepeatedly(Return(active_config));

    auto ch_id = Uuid::generate_v7();
    MfaChallengeEntity ch;
    ch.mfa_challenge_id = ch_id;
    ch.user_id = user_id_;
    ch.session_id = session_id_;
    ch.challenge_status = MfaChallengeStatus::Pending;
    ch.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5);

    EXPECT_CALL(*mfa_repository_, find_challenge_by_id(ch_id)).WillRepeatedly(Return(ch));
    EXPECT_CALL(*mfa_repository_, complete_challenge(ch_id, _)).Times(1);
    EXPECT_CALL(*session_repository_, update_authentication_level(session_id_, AuthenticationLevel::MfaVerified))
        .Times(1);

    auto verify_res = mfa_manager_->verify_challenge(ch_id, emergency_code);
    EXPECT_TRUE(verify_res.is_success());

    // 3. Re-using the same recovery code on a new challenge fails
    auto ch2_id = Uuid::generate_v7();
    MfaChallengeEntity ch2 = ch;
    ch2.mfa_challenge_id = ch2_id;
    EXPECT_CALL(*mfa_repository_, find_challenge_by_id(ch2_id)).WillOnce(Return(ch2));

    auto reuse_res = mfa_manager_->verify_challenge(ch2_id, emergency_code);
    EXPECT_FALSE(reuse_res.is_success());
}

TEST_F(MfaManagerTest, DisableMfa_ValidCode_DisablesConfiguration) {
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity active_config;
    active_config.mfa_configuration_id = Uuid::generate_v7();
    active_config.user_id = user_id_;
    active_config.status = MfaStatus::Enabled;
    active_config.encrypted_secret = encrypted;
    active_config.version = 2;

    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillRepeatedly(Return(active_config));
    EXPECT_CALL(*mfa_repository_, disable_mfa(active_config.mfa_configuration_id, _, 2)).Times(1);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string valid_code = totp_engine_->compute_code(secret, now);

    EXPECT_TRUE(mfa_manager_->disable_mfa(user_id_, valid_code));
}

TEST_F(MfaManagerTest, DisableMfa_InvalidCode_Fails) {
    auto secret = TotpEngine::generate_secret_bytes(20);
    auto encrypted = secret_protector_->encrypt(secret, user_id_.to_string());

    MfaConfigurationEntity active_config;
    active_config.mfa_configuration_id = Uuid::generate_v7();
    active_config.user_id = user_id_;
    active_config.status = MfaStatus::Enabled;
    active_config.encrypted_secret = encrypted;
    active_config.version = 2;

    EXPECT_CALL(*mfa_repository_, find_mfa_config_by_user_id(user_id_)).WillRepeatedly(Return(active_config));
    EXPECT_CALL(*mfa_repository_, disable_mfa(_, _, _)).Times(0);

    EXPECT_FALSE(mfa_manager_->disable_mfa(user_id_, "000000"));
}

} // namespace
} // namespace securecloud::auth::service::test
