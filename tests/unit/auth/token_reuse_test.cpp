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
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Field;
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
// Token Compromise & Reuse Detection Test Fixture
// ============================================================================

class TokenReuseTest : public ::testing::Test {
  protected:
    void SetUp() override {
        signer_ = std::make_shared<crypto::Ed25519TokenSigner>("compromise-test-key");
        refresh_token_repo_ = std::make_shared<MockRefreshTokenRepository>();
        session_repo_ = std::make_shared<MockSessionRepository>();
        device_repo_ = std::make_shared<MockDeviceRepository>();
        audit_publisher_ = std::make_shared<MockAuditEventPublisher>();

        config_.access_token_ttl = std::chrono::minutes(15);
        config_.refresh_token_ttl = std::chrono::hours(24 * 7);
        config_.concurrency_grace_window = std::chrono::seconds(5); // 5-second grace window

        token_manager_ = std::make_unique<TokenManager>(signer_, refresh_token_repo_, session_repo_, device_repo_,
                                                        audit_publisher_, config_);

        user_id_ = domain::Uuid::generate_v7();
        device_id_ = domain::Uuid::generate_v7();
        session_id_ = domain::Uuid::generate_v7();
    }

    domain::RefreshTokenEntity create_rotated_token(std::string_view verifier_hash,
                                                    std::chrono::seconds rotated_seconds_ago) {
        const auto now = std::chrono::system_clock::now();
        domain::RefreshTokenEntity token;
        token.refresh_token_id = domain::Uuid::generate_v7();
        token.session_id = session_id_;
        token.device_id = device_id_;
        token.token_verifier = std::string(verifier_hash);
        token.token_status = domain::TokenStatus::Rotated;
        token.issued_at = now - std::chrono::hours(2);
        token.rotated_at = now - rotated_seconds_ago;
        token.expires_at = now + std::chrono::hours(24);
        token.replaced_by_token_id = domain::Uuid::generate_v7();
        return token;
    }

    std::shared_ptr<crypto::Ed25519TokenSigner> signer_;
    std::shared_ptr<MockRefreshTokenRepository> refresh_token_repo_;
    std::shared_ptr<MockSessionRepository> session_repo_;
    std::shared_ptr<MockDeviceRepository> device_repo_;
    std::shared_ptr<MockAuditEventPublisher> audit_publisher_;
    TokenManagerConfig config_;
    std::unique_ptr<TokenManager> token_manager_;

    domain::Uuid user_id_;
    domain::Uuid device_id_;
    domain::Uuid session_id_;
};

// ============================================================================
// 1. Replay Attack & Compromise Protocol Execution
// ============================================================================

TEST_F(TokenReuseTest, ReplayOfRotatedToken_OutsideGraceWindow_TriggersCompromiseRevocation) {
    const std::string raw_secret = "sc_rt_stolen_token_123456789";
    const std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_secret);

    // Rotated 15 seconds ago (strictly outside 5s grace window)
    auto rotated_token = create_rotated_token(verifier_hash, std::chrono::seconds(15));

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rotated_token));

    // Verify handle_token_reuse is invoked on the repository to revoke session and sibling tokens
    EXPECT_CALL(*refresh_token_repo_, handle_token_reuse_impl(verifier_hash))
        .WillOnce(Return(repository::TokenReuseDetectedResult{
            .session_id = session_id_,
            .device_id = device_id_,
            .revoked_at = std::chrono::system_clock::now(),
        }));

    // Verify high-severity security audit event is published
    domain::AuditEvent captured_event;
    EXPECT_CALL(*audit_publisher_,
                publish(Field(&domain::AuditEvent::event_type, domain::AuditEventType::TokenReuseDetected)))
        .WillOnce(SaveArg<0>(&captured_event));

    auto result = token_manager_->refresh_tokens(raw_secret, device_id_, "198.51.100.24");

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::CompromiseDetected);
    EXPECT_EQ(result.tokens, std::nullopt);

    // Verify audit event details
    EXPECT_EQ(captured_event.session_id, session_id_);
    EXPECT_EQ(captured_event.device_id, device_id_);
    EXPECT_EQ(captured_event.client_ip, "198.51.100.24");
    EXPECT_FALSE(captured_event.failure_reason.empty());
}

// ============================================================================
// 2. Zero-Secret-Leakage Guarantee
// ============================================================================

TEST_F(TokenReuseTest, CompromiseAuditEvent_GuaranteesZeroSecretOrVerifierLeakage) {
    const std::string raw_secret = "sc_rt_secret_entropy_never_leak_this";
    const std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_secret);

    auto rotated_token = create_rotated_token(verifier_hash, std::chrono::seconds(30));

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rotated_token));
    EXPECT_CALL(*refresh_token_repo_, handle_token_reuse_impl(verifier_hash))
        .WillOnce(Return(repository::TokenReuseDetectedResult{
            .session_id = session_id_,
            .device_id = device_id_,
            .revoked_at = std::chrono::system_clock::now(),
        }));

    domain::AuditEvent captured_event;
    EXPECT_CALL(*audit_publisher_, publish(_)).WillOnce(SaveArg<0>(&captured_event));

    auto result = token_manager_->refresh_tokens(raw_secret, device_id_, "203.0.113.5");

    std::string serialized_json = captured_event.to_json();

    // Invariant: Raw secret and deterministic verifier hash MUST NEVER appear in audit payload
    EXPECT_EQ(serialized_json.find(raw_secret), std::string::npos);
    EXPECT_EQ(serialized_json.find(verifier_hash), std::string::npos);
    EXPECT_EQ(result.error_message.find(raw_secret), std::string::npos);
    EXPECT_EQ(result.error_message.find(verifier_hash), std::string::npos);

    // Verify valid JSON structure
    auto parsed_json = nlohmann::json::parse(serialized_json);
    EXPECT_EQ(parsed_json["event_type"], "auth.token.reuse_detected");
    EXPECT_EQ(parsed_json["session_id"], session_id_.to_string());
    EXPECT_EQ(parsed_json["device_id"], device_id_.to_string());
    EXPECT_EQ(parsed_json["client_ip"], "203.0.113.5");
}

// ============================================================================
// 3. Concurrency Grace Window: Benign Parallel Requests
// ============================================================================

TEST_F(TokenReuseTest, RotatedToken_WithinGraceWindow_YieldsConcurrencyConflictWithoutRevocation) {
    const std::string raw_secret = "sc_rt_concurrent_thread_token";
    const std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_secret);

    // Rotated only 1 second ago (well within 5-second grace window)
    auto recently_rotated = create_rotated_token(verifier_hash, std::chrono::seconds(1));

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(recently_rotated));

    // Invariant: MUST NOT invoke compromise protocol or revoke session
    EXPECT_CALL(*refresh_token_repo_, handle_token_reuse_impl(_)).Times(0);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(0);

    auto result = token_manager_->refresh_tokens(raw_secret, device_id_, "127.0.0.1");

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::ConcurrencyConflict);
    EXPECT_NE(result.error_message.find("grace window"), std::string::npos);
}

// ============================================================================
// 4. Invalidation of Sibling Tokens Following Breach
// ============================================================================

TEST_F(TokenReuseTest, SiblingTokenRefresh_RejectedAfterSessionRevocation) {
    // Sibling token in the same session family
    const std::string sibling_secret = "sc_rt_sibling_token_123";
    const std::string sibling_verifier = crypto::TokenHasher::compute_sha256_hex(sibling_secret);

    domain::RefreshTokenEntity sibling_rt;
    sibling_rt.refresh_token_id = domain::Uuid::generate_v7();
    sibling_rt.session_id = session_id_;
    sibling_rt.device_id = device_id_;
    sibling_rt.token_verifier = sibling_verifier;
    sibling_rt.token_status = domain::TokenStatus::Active;
    sibling_rt.issued_at = std::chrono::system_clock::now() - std::chrono::minutes(10);
    sibling_rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    domain::DeviceEntity device;
    device.device_id = device_id_;
    device.user_id = user_id_;
    device.device_status = domain::DeviceStatus::Active;

    // Session has been marked Revoked due to prior compromise
    domain::SessionEntity revoked_session;
    revoked_session.session_id = session_id_;
    revoked_session.user_id = user_id_;
    revoked_session.device_id = device_id_;
    revoked_session.session_status = domain::SessionStatus::Revoked; // Revoked!
    revoked_session.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(sibling_verifier)).WillOnce(Return(sibling_rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(revoked_session));

    auto result = token_manager_->refresh_tokens(sibling_secret, device_id_);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::SessionRevoked);
}

// ============================================================================
// 5. Concurrent Rotation Simulation (OptimisticLockException)
// ============================================================================

TEST_F(TokenReuseTest, ParallelRotationRace_CatchesOptimisticLockAndReturnsConcurrencyConflict) {
    const std::string raw_secret = "sc_rt_simultaneous_race";
    const std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_secret);

    domain::RefreshTokenEntity active_rt;
    active_rt.refresh_token_id = domain::Uuid::generate_v7();
    active_rt.session_id = session_id_;
    active_rt.device_id = device_id_;
    active_rt.token_verifier = verifier_hash;
    active_rt.token_status = domain::TokenStatus::Active;
    active_rt.issued_at = std::chrono::system_clock::now();
    active_rt.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    domain::DeviceEntity device;
    device.device_id = device_id_;
    device.user_id = user_id_;
    device.device_status = domain::DeviceStatus::Active;

    domain::SessionEntity session;
    session.session_id = session_id_;
    session.user_id = user_id_;
    session.device_id = device_id_;
    session.session_status = domain::SessionStatus::Active;
    session.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(active_rt));
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo_, find_by_id(session_id_)).WillOnce(Return(session));

    // Simultaneous second request committed first; rotate_token_atomic encounters 0 affected rows
    EXPECT_CALL(*refresh_token_repo_, rotate_token_atomic(active_rt.refresh_token_id, _))
        .WillOnce(Throw(repository::OptimisticLockException("Concurrent token rotation race detected")));

    auto result = token_manager_->refresh_tokens(raw_secret, device_id_);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::ConcurrencyConflict);
}

// ============================================================================
// 6. Fail-Safe Resilience Under Database Exception During Reuse Handling
// ============================================================================

TEST_F(TokenReuseTest, ReuseHandling_RepositoryThrows_FailsSafeAndReturnsCompromiseDetected) {
    const std::string raw_secret = "sc_rt_stolen_token_db_failure";
    const std::string verifier_hash = crypto::TokenHasher::compute_sha256_hex(raw_secret);

    auto rotated_token = create_rotated_token(verifier_hash, std::chrono::seconds(20));

    EXPECT_CALL(*refresh_token_repo_, find_by_verifier_impl(verifier_hash)).WillOnce(Return(rotated_token));

    // Database error during reuse handling
    EXPECT_CALL(*refresh_token_repo_, handle_token_reuse_impl(verifier_hash))
        .WillOnce(Throw(repository::DatabaseExecutionException("DB connection dropped during reuse cleanup")));

    // Audit publisher still called
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(1);

    // Fail-safe invariant: Must not crash or propagate raw unhandled database exception
    auto result = token_manager_->refresh_tokens(raw_secret, device_id_);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::TokenRefreshStatus::CompromiseDetected);
}

} // namespace
} // namespace securecloud::auth::service::test
