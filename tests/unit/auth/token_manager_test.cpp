#include "auth/crypto/token_crypto.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/token_claims.hpp"
#include "auth/domain/token_result.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/token_manager.hpp"

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
using ::testing::Throw;

// ============================================================================
// GMock Mock Repositories
// ============================================================================

class MockRefreshTokenRepository : public repository::IRefreshTokenRepository {
  public:
    MOCK_METHOD(void, create_token, (const domain::RefreshTokenEntity& token), (override));
    MOCK_METHOD(void, create_token, (const domain::RefreshTokenEntity& token, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<domain::RefreshTokenEntity>, find_by_id, (const domain::Uuid& refresh_token_id),
                (override));
    MOCK_METHOD(std::optional<domain::RefreshTokenEntity>, find_by_id,
                (const domain::Uuid& refresh_token_id, pqxx::transaction_base& tx), (override));

    // Forward string_view to string for MSVC DLL compatibility
    std::optional<domain::RefreshTokenEntity> find_by_verifier(std::string_view verifier_hash) override {
        return find_by_verifier_impl(std::string(verifier_hash));
    }
    MOCK_METHOD(std::optional<domain::RefreshTokenEntity>, find_by_verifier_impl, (const std::string& verifier_hash));

    std::optional<domain::RefreshTokenEntity> find_by_verifier(std::string_view verifier_hash,
                                                               pqxx::transaction_base& tx) override {
        return find_by_verifier_tx_impl(std::string(verifier_hash), tx);
    }
    MOCK_METHOD(std::optional<domain::RefreshTokenEntity>, find_by_verifier_tx_impl,
                (const std::string& verifier_hash, pqxx::transaction_base& tx));

    MOCK_METHOD(repository::TokenRotationResult, rotate_token_atomic,
                (const domain::Uuid& old_token_id, const domain::RefreshTokenEntity& new_token), (override));
    MOCK_METHOD(repository::TokenRotationResult, rotate_token_atomic,
                (const domain::Uuid& old_token_id, const domain::RefreshTokenEntity& new_token,
                 pqxx::transaction_base& tx),
                (override));

    repository::TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash) override {
        return handle_token_reuse_impl(std::string(verifier_hash));
    }
    MOCK_METHOD(repository::TokenReuseDetectedResult, handle_token_reuse_impl, (const std::string& verifier_hash));

    repository::TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash,
                                                            pqxx::transaction_base& tx) override {
        return handle_token_reuse_tx_impl(std::string(verifier_hash), tx);
    }
    MOCK_METHOD(repository::TokenReuseDetectedResult, handle_token_reuse_tx_impl,
                (const std::string& verifier_hash, pqxx::transaction_base& tx));
};

class MockSessionRepository : public repository::ISessionRepository {
  public:
    MOCK_METHOD(void, create_session, (const domain::SessionEntity& session), (override));
    MOCK_METHOD(void, create_session, (const domain::SessionEntity& session, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<domain::SessionEntity>, find_by_id, (const domain::Uuid& session_id), (override));
    MOCK_METHOD(std::optional<domain::SessionEntity>, find_by_id,
                (const domain::Uuid& session_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_by_user_id, (const domain::Uuid& user_id), (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_by_user_id,
                (const domain::Uuid& user_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_by_device_id, (const domain::Uuid& device_id),
                (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_by_device_id,
                (const domain::Uuid& device_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, update_authentication_level, (const domain::Uuid& session_id, domain::AuthenticationLevel level),
                (override));
    MOCK_METHOD(void, update_authentication_level,
                (const domain::Uuid& session_id, domain::AuthenticationLevel level, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(void, revoke_session, (const domain::Uuid& session_id, domain::time_point revoked_at), (override));
    MOCK_METHOD(void, revoke_session,
                (const domain::Uuid& session_id, domain::time_point revoked_at, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(void, revoke_all_user_sessions, (const domain::Uuid& user_id, domain::time_point revoked_at),
                (override));
    MOCK_METHOD(void, revoke_all_user_sessions,
                (const domain::Uuid& user_id, domain::time_point revoked_at, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, revoke_all_device_sessions, (const domain::Uuid& device_id, domain::time_point revoked_at),
                (override));
    MOCK_METHOD(void, revoke_all_device_sessions,
                (const domain::Uuid& device_id, domain::time_point revoked_at, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(bool, touch_session_activity, (const domain::Uuid& session_id, domain::time_point now), (override));
    MOCK_METHOD(bool, touch_session_activity,
                (const domain::Uuid& session_id, domain::time_point now, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(uint64_t, expire_stale_sessions, (domain::time_point now), (override));
    MOCK_METHOD(uint64_t, expire_stale_sessions, (domain::time_point now, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(bool, revoke_session_atomic, (const domain::Uuid& session_id, domain::time_point revoked_at),
                (override));
    MOCK_METHOD(bool, revoke_session_atomic,
                (const domain::Uuid& session_id, domain::time_point revoked_at, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(uint64_t, revoke_all_device_sessions_atomic,
                (const domain::Uuid& device_id, domain::time_point revoked_at), (override));
    MOCK_METHOD(uint64_t, revoke_all_device_sessions_atomic,
                (const domain::Uuid& device_id, domain::time_point revoked_at, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(uint64_t, revoke_all_user_sessions_atomic, (const domain::Uuid& user_id, domain::time_point revoked_at),
                (override));
    MOCK_METHOD(uint64_t, revoke_all_user_sessions_atomic,
                (const domain::Uuid& user_id, domain::time_point revoked_at, pqxx::transaction_base& tx), (override));
};

class MockDeviceRepository : public repository::IDeviceRepository {
  public:
    MOCK_METHOD(void, register_device, (const domain::DeviceEntity& device), (override));
    MOCK_METHOD(void, register_device, (const domain::DeviceEntity& device, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<domain::DeviceEntity>, find_by_id, (const domain::Uuid& device_id), (override));
    MOCK_METHOD(std::optional<domain::DeviceEntity>, find_by_id,
                (const domain::Uuid& device_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::vector<domain::DeviceEntity>, list_active_by_user_id, (const domain::Uuid& user_id), (override));
    MOCK_METHOD(std::vector<domain::DeviceEntity>, list_active_by_user_id,
                (const domain::Uuid& user_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::vector<domain::DeviceEntity>, list_all_by_user_id,
                (const domain::Uuid& user_id, bool include_revoked), (override));
    MOCK_METHOD(std::vector<domain::DeviceEntity>, list_all_by_user_id,
                (const domain::Uuid& user_id, bool include_revoked, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, authorize_device, (const domain::Uuid& device_id, domain::time_point authorized_at), (override));
    MOCK_METHOD(void, authorize_device,
                (const domain::Uuid& device_id, domain::time_point authorized_at, pqxx::transaction_base& tx),
                (override));

    void revoke_device(const domain::Uuid& /*device_id*/, std::string_view /*reason*/,
                       domain::time_point /*revoked_at*/) override {}
    void revoke_device(const domain::Uuid& /*device_id*/, std::string_view /*reason*/,
                       domain::time_point /*revoked_at*/, pqxx::transaction_base& /*tx*/) override {}

    MOCK_METHOD(void, update_last_authenticated, (const domain::Uuid& device_id, domain::time_point auth_time),
                (override));
    MOCK_METHOD(void, update_last_authenticated,
                (const domain::Uuid& device_id, domain::time_point auth_time, pqxx::transaction_base& tx), (override));
};

class MockAuditEventPublisher : public IAuditEventPublisher {
  public:
    MOCK_METHOD(void, publish, (const domain::AuditEvent& event), (noexcept, override));
};

// ============================================================================
// Test Fixture & Helpers
// ============================================================================

class TokenManagerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        signer_ = std::make_shared<crypto::Ed25519TokenSigner>("test-signer-key");
        verifier_ = crypto::Ed25519TokenVerifier::from_signer(*signer_);
        refresh_token_repo_ = std::make_shared<MockRefreshTokenRepository>();
        session_repo_ = std::make_shared<MockSessionRepository>();
        device_repo_ = std::make_shared<MockDeviceRepository>();
        audit_publisher_ = std::make_shared<MockAuditEventPublisher>();

        TokenManagerConfig config;
        config.access_token_ttl = std::chrono::minutes(15);
        config.refresh_token_ttl = std::chrono::hours(24 * 7);
        config.issuer = "https://auth.securecloud.io";
        config.audience = "https://gateway.securecloud.io";
        config.default_scopes = {"access", "files:read", "files:write"};

        token_manager_ = std::make_unique<TokenManager>(signer_, refresh_token_repo_, session_repo_, device_repo_,
                                                        audit_publisher_, config);

        user_id_ = domain::Uuid::generate_v7();
        device_id_ = domain::Uuid::generate_v7();
        session_id_ = domain::Uuid::generate_v7();
    }

    domain::SessionEntity create_active_session() {
        const auto now = std::chrono::system_clock::now();
        domain::SessionEntity session;
        session.session_id = session_id_;
        session.user_id = user_id_;
        session.device_id = device_id_;
        session.session_status = domain::SessionStatus::Active;
        session.authentication_level = domain::AuthenticationLevel::PrimaryOnly;
        session.created_at = now;
        session.expires_at = now + std::chrono::hours(24);
        session.last_used_at = now;
        return session;
    }

    domain::DeviceEntity create_active_device() {
        const auto now = std::chrono::system_clock::now();
        domain::DeviceEntity device;
        device.device_id = device_id_;
        device.user_id = user_id_;
        device.device_status = domain::DeviceStatus::Active;
        device.registered_at = now;
        device.last_authenticated_at = now;
        device.created_at = now;
        device.updated_at = now;
        return device;
    }

    std::shared_ptr<crypto::Ed25519TokenSigner> signer_;
    std::unique_ptr<crypto::Ed25519TokenVerifier> verifier_;
    std::shared_ptr<MockRefreshTokenRepository> refresh_token_repo_;
    std::shared_ptr<MockSessionRepository> session_repo_;
    std::shared_ptr<MockDeviceRepository> device_repo_;
    std::shared_ptr<MockAuditEventPublisher> audit_publisher_;
    std::unique_ptr<TokenManager> token_manager_;

    domain::Uuid user_id_;
    domain::Uuid device_id_;
    domain::Uuid session_id_;
};

// ============================================================================
// 1. Constructor Validation
// ============================================================================

TEST_F(TokenManagerTest, ConstructorValidation_RejectsNullDependencies) {
    TokenManagerConfig valid_config;

    EXPECT_THROW(
        TokenManager(nullptr, refresh_token_repo_, session_repo_, device_repo_, audit_publisher_, valid_config),
        std::invalid_argument);

    EXPECT_THROW(TokenManager(signer_, nullptr, session_repo_, device_repo_, audit_publisher_, valid_config),
                 std::invalid_argument);

    EXPECT_THROW(TokenManager(signer_, refresh_token_repo_, nullptr, device_repo_, audit_publisher_, valid_config),
                 std::invalid_argument);

    EXPECT_THROW(TokenManager(signer_, refresh_token_repo_, session_repo_, nullptr, audit_publisher_, valid_config),
                 std::invalid_argument);

    TokenManagerConfig zero_access_ttl = valid_config;
    zero_access_ttl.access_token_ttl = std::chrono::seconds(0);
    EXPECT_THROW(
        TokenManager(signer_, refresh_token_repo_, session_repo_, device_repo_, audit_publisher_, zero_access_ttl),
        std::invalid_argument);

    TokenManagerConfig zero_refresh_ttl = valid_config;
    zero_refresh_ttl.refresh_token_ttl = std::chrono::seconds(-10);
    EXPECT_THROW(
        TokenManager(signer_, refresh_token_repo_, session_repo_, device_repo_, audit_publisher_, zero_refresh_ttl),
        std::invalid_argument);
}

// ============================================================================
// 2. Initial Token Issuance Tests
// ============================================================================

TEST_F(TokenManagerTest, IssueInitialTokens_Success_CreatesValidTokenPairAndPersistsHashedVerifier) {
    auto session = create_active_session();

    domain::RefreshTokenEntity saved_token;
    EXPECT_CALL(*refresh_token_repo_, create_token(_)).WillOnce(SaveArg<0>(&saved_token));

    auto token_pair = token_manager_->issue_initial_tokens(session);

    // Verify access token envelope
    ASSERT_FALSE(token_pair.access_token.empty());
    auto validation = domain::TokenEnvelopeParser::parse_and_validate(token_pair.access_token, *verifier_);
    ASSERT_TRUE(validation.is_valid()) << validation.error_message;
    ASSERT_NE(validation.claims, nullptr);

    EXPECT_EQ(validation.claims->user_id, session.user_id);
    EXPECT_EQ(validation.claims->device_id, session.device_id);
    EXPECT_EQ(validation.claims->session_id, session.session_id);
    EXPECT_EQ(validation.claims->authentication_level, session.authentication_level);
    EXPECT_EQ(validation.claims->issuer, "https://auth.securecloud.io");
    EXPECT_EQ(validation.claims->audience, "https://gateway.securecloud.io");
    EXPECT_EQ(validation.claims->scopes, std::vector<std::string>({"access", "files:read", "files:write"}));

    // Verify refresh token secret & persistence
    ASSERT_FALSE(token_pair.refresh_token.empty());
    EXPECT_TRUE(token_pair.refresh_token.raw_secret().starts_with("sc_rt_"));

    // Verify that the entity persisted to repository contains the deterministic SHA-256 verifier, NOT the raw secret
    EXPECT_EQ(saved_token.session_id, session.session_id);
    EXPECT_EQ(saved_token.device_id, session.device_id);
    EXPECT_EQ(saved_token.token_status, domain::TokenStatus::Active);
    EXPECT_EQ(saved_token.token_verifier,
              crypto::TokenHasher::compute_sha256_hex(token_pair.refresh_token.raw_secret()));
    EXPECT_NE(saved_token.token_verifier, token_pair.refresh_token.raw_secret());
}

TEST_F(TokenManagerTest, IssueInitialTokens_CustomScopesApplied) {
    auto session = create_active_session();
    std::vector<std::string> custom_scopes = {"admin:all", "metrics:read"};

    EXPECT_CALL(*refresh_token_repo_, create_token(_)).Times(1);

    auto token_pair = token_manager_->issue_initial_tokens(session, custom_scopes);
    auto validation = domain::TokenEnvelopeParser::parse_and_validate(token_pair.access_token, *verifier_);
    ASSERT_TRUE(validation.is_valid());
    EXPECT_EQ(validation.claims->scopes, custom_scopes);
}

TEST_F(TokenManagerTest, IssueInitialTokens_RejectsNonActiveSession) {
    auto session = create_active_session();
    session.session_status = domain::SessionStatus::Revoked;

    EXPECT_CALL(*refresh_token_repo_, create_token(_)).Times(0);
    EXPECT_THROW(token_manager_->issue_initial_tokens(session), std::invalid_argument);
}

TEST_F(TokenManagerTest, IssueInitialTokens_RejectsExpiredSession) {
    auto session = create_active_session();
    session.expires_at = std::chrono::system_clock::now() - std::chrono::seconds(10);

    EXPECT_CALL(*refresh_token_repo_, create_token(_)).Times(0);
    EXPECT_THROW(token_manager_->issue_initial_tokens(session), std::invalid_argument);
}

// ============================================================================
// 3. Refresh Token Rotation Tests
// ============================================================================

TEST_F(TokenManagerTest, RefreshTokens_Success_RotatesTokenAndTouchesActivity) {
    auto session = create_active_session();
    auto device = create_active_device();

    std::string raw_secret = crypto::SecureRandomTokenGenerator::generate_refresh_token(32);
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_secret);

    domain::RefreshTokenEntity existing_rt;
    existing_rt.refresh_token_id = domain::Uuid::generate_v7();
    existing_rt.session_id = session.session_id;
    existing_rt.device_id = device.device_id;
    existing_rt.token_verifier = verifier_hash;
    existing_rt.token_status = domain::TokenStatus::Active;
    existing_rt.issued_at = std::chrono::system_clock::now() - std::chrono::hours(1);
    existing_rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(existing_rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(session));

    domain::RefreshTokenEntity newly_rotated_token;
    EXPECT_CALL(*refresh_token_repo_, rotate_token_atomic(existing_rt.refresh_token_id, _))
        .WillOnce(DoAll(SaveArg<1>(&newly_rotated_token),
                        Return(repository::TokenRotationResult{existing_rt, newly_rotated_token})));

    EXPECT_CALL(*session_repo_, touch_session_activity(session_id_, _)).WillOnce(Return(true));
    EXPECT_CALL(*device_repo_, update_last_authenticated(device_id_, _)).Times(1);

    EXPECT_CALL(*audit_publisher_,
                publish(::testing::Field(&domain::AuditEvent::event_type, domain::AuditEventType::TokenRefreshed)))
        .Times(1);

    auto result = token_manager_->refresh_tokens(raw_secret, device_id_, "127.0.0.1");

    ASSERT_TRUE(result.is_success()) << result.error_message;
    ASSERT_TRUE(result.tokens.has_value());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::Success);

    // Verify new access token envelope
    auto access_val = domain::TokenEnvelopeParser::parse_and_validate(result.tokens->access_token, *verifier_);
    ASSERT_TRUE(access_val.is_valid());
    EXPECT_EQ(access_val.claims->session_id, session_id_);
    EXPECT_EQ(access_val.claims->user_id, user_id_);
    EXPECT_EQ(access_val.claims->device_id, device_id_);

    // Verify new refresh token secret was rotated and is different from the old one
    ASSERT_FALSE(result.tokens->refresh_token.empty());
    EXPECT_NE(result.tokens->refresh_token.raw_secret(), raw_secret);
    EXPECT_EQ(newly_rotated_token.token_verifier,
              crypto::TokenHasher::compute_sha256_hex(result.tokens->refresh_token.raw_secret()));
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsEmptySecret) {
    auto result = token_manager_->refresh_tokens("", device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::InvalidToken);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsUnknownTokenVerifier) {
    std::string secret = "sc_rt_nonexistentsecret123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(std::nullopt));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::InvalidToken);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsExpiredRefreshToken) {
    std::string secret = "sc_rt_expiredtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity expired_rt;
    expired_rt.refresh_token_id = domain::Uuid::generate_v7();
    expired_rt.session_id = session_id_;
    expired_rt.device_id = device_id_;
    expired_rt.token_verifier = verifier_hash;
    expired_rt.token_status = domain::TokenStatus::Active;
    expired_rt.issued_at = std::chrono::system_clock::now() - std::chrono::hours(48);
    expired_rt.expires_at = std::chrono::system_clock::now() - std::chrono::seconds(10); // expired

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(expired_rt));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::ExpiredToken);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsDeviceMismatchOnRefreshToken) {
    std::string secret = "sc_rt_validtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = domain::Uuid::generate_v7(); // Different device!
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::DeviceMismatch);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsUnknownDevice) {
    std::string secret = "sc_rt_validtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = device_id_;
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(std::nullopt));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::DeviceMismatch);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsInactiveDevice) {
    std::string secret = "sc_rt_validtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = device_id_;
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    auto device = create_active_device();
    device.device_status = domain::DeviceStatus::Revoked;

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::DeviceMismatch);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsDeviceUserMismatch) {
    std::string secret = "sc_rt_validtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = device_id_;
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    auto device = create_active_device();
    device.user_id = domain::Uuid::generate_v7(); // Different user!
    auto session = create_active_session();

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(session));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::DeviceMismatch);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsUnknownSession) {
    std::string secret = "sc_rt_validtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = device_id_;
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    auto device = create_active_device();

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(std::nullopt));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::InvalidToken);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsRevokedSession) {
    std::string secret = "sc_rt_validtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = device_id_;
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    auto device = create_active_device();
    auto session = create_active_session();
    session.session_status = domain::SessionStatus::Revoked;

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(session));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::SessionRevoked);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsExpiredSession) {
    std::string secret = "sc_rt_validtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = device_id_;
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    auto device = create_active_device();
    auto session = create_active_session();
    session.expires_at = std::chrono::system_clock::now() - std::chrono::seconds(10); // expired

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(session));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::SessionRevoked);
}

TEST_F(TokenManagerTest, RefreshTokens_DetectsReuseOfRotatedToken_TriggersRevocationAndAudit) {
    std::string secret = "sc_rt_rotatedtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rotated_rt;
    rotated_rt.refresh_token_id = domain::Uuid::generate_v7();
    rotated_rt.session_id = session_id_;
    rotated_rt.device_id = device_id_;
    rotated_rt.token_verifier = verifier_hash;
    rotated_rt.token_status = domain::TokenStatus::Rotated; // Already rotated!
    rotated_rt.issued_at = std::chrono::system_clock::now() - std::chrono::hours(2);
    rotated_rt.rotated_at = std::chrono::system_clock::now() - std::chrono::hours(1); // Past grace window!
    rotated_rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rotated_rt));
    EXPECT_CALL(*refresh_token_repo_, handle_token_reuse_impl(verifier_hash))
        .WillOnce(Return(repository::TokenReuseDetectedResult{
            .session_id = session_id_,
            .device_id = device_id_,
            .revoked_at = std::chrono::system_clock::now(),
        }));

    EXPECT_CALL(*audit_publisher_,
                publish(::testing::Field(&domain::AuditEvent::event_type, domain::AuditEventType::TokenReuseDetected)))
        .Times(1);

    auto result = token_manager_->refresh_tokens(secret, device_id_, "10.0.0.1");

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::CompromiseDetected);
}

TEST_F(TokenManagerTest, RefreshTokens_RotatedTokenWithinGraceWindow_ReturnsConcurrencyConflictWithoutRevocation) {
    std::string secret = "sc_rt_rotatedtoken_recent";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity rotated_rt;
    rotated_rt.refresh_token_id = domain::Uuid::generate_v7();
    rotated_rt.session_id = session_id_;
    rotated_rt.device_id = device_id_;
    rotated_rt.token_verifier = verifier_hash;
    rotated_rt.token_status = domain::TokenStatus::Rotated;
    rotated_rt.issued_at = std::chrono::system_clock::now() - std::chrono::seconds(10);
    rotated_rt.rotated_at = std::chrono::system_clock::now() - std::chrono::seconds(1); // Within 5-second grace window!
    rotated_rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rotated_rt));

    // Must NOT trigger compromise revocation or publish breach event
    EXPECT_CALL(*refresh_token_repo_, handle_token_reuse_impl(_)).Times(0);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(0);

    auto result = token_manager_->refresh_tokens(secret, device_id_, "10.0.0.1");

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::ConcurrencyConflict);
}

TEST_F(TokenManagerTest, RefreshTokens_RejectsRevokedToken) {
    std::string secret = "sc_rt_revokedtoken123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(secret);

    domain::RefreshTokenEntity revoked_rt;
    revoked_rt.refresh_token_id = domain::Uuid::generate_v7();
    revoked_rt.session_id = session_id_;
    revoked_rt.device_id = device_id_;
    revoked_rt.token_verifier = verifier_hash;
    revoked_rt.token_status = domain::TokenStatus::Revoked;
    revoked_rt.issued_at = std::chrono::system_clock::now();
    revoked_rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(revoked_rt));

    auto result = token_manager_->refresh_tokens(secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::SessionRevoked);
}

TEST_F(TokenManagerTest, RefreshTokens_HandlesConcurrentRaceOptimisticLockException) {
    auto session = create_active_session();
    auto device = create_active_device();

    std::string raw_secret = "sc_rt_concurrentrace123456789";
    std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_secret);

    domain::RefreshTokenEntity rt;
    rt.refresh_token_id = domain::Uuid::generate_v7();
    rt.session_id = session_id_;
    rt.device_id = device_id_;
    rt.token_verifier = verifier_hash;
    rt.token_status = domain::TokenStatus::Active;
    rt.issued_at = std::chrono::system_clock::now();
    rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(session));

    EXPECT_CALL(*refresh_token_repo_, rotate_token_atomic(rt.refresh_token_id, _))
        .WillOnce(Throw(repository::OptimisticLockException("Concurrent rotation race")));

    auto result = token_manager_->refresh_tokens(raw_secret, device_id_);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::ConcurrencyConflict);
}

} // namespace
} // namespace securecloud::auth::service::test
