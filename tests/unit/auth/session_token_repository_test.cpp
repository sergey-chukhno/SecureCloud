#include "auth/auth_config.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::auth::repository::test {
namespace {

using domain::AuthenticationLevel;
using domain::RefreshTokenEntity;
using domain::SessionEntity;
using domain::SessionStatus;
using domain::TokenStatus;
using domain::Uuid;

// ============================================================================
// 1. In-Memory Session & Refresh Token Repositories for Interface Tests
// ============================================================================

class InMemorySessionRepository : public ISessionRepository {
  public:
    void create_session(const SessionEntity& session) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sessions_.find(session.session_id) != sessions_.end()) {
            throw DuplicateEntityException("Session already exists: " + session.session_id.to_string());
        }
        sessions_[session.session_id] = session;
    }

    void create_session(const SessionEntity& session, pqxx::transaction_base& /*tx*/) override {
        create_session(session);
    }

    [[nodiscard]] std::optional<SessionEntity> find_by_id(const Uuid& session_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SessionEntity> find_by_id(const Uuid& session_id,
                                                          pqxx::transaction_base& /*tx*/) override {
        return find_by_id(session_id);
    }

    [[nodiscard]] std::vector<SessionEntity> list_active_by_user_id(const Uuid& user_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<SessionEntity> result;
        for (const auto& [id, s] : sessions_) {
            if (s.user_id == user_id && s.session_status == SessionStatus::Active) {
                result.push_back(s);
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<SessionEntity> list_active_by_user_id(const Uuid& user_id,
                                                                    pqxx::transaction_base& /*tx*/) override {
        return list_active_by_user_id(user_id);
    }

    [[nodiscard]] std::vector<SessionEntity> list_active_by_device_id(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<SessionEntity> result;
        for (const auto& [id, s] : sessions_) {
            if (s.device_id == device_id && s.session_status == SessionStatus::Active) {
                result.push_back(s);
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<SessionEntity> list_active_by_device_id(const Uuid& device_id,
                                                                      pqxx::transaction_base& /*tx*/) override {
        return list_active_by_device_id(device_id);
    }

    void update_authentication_level(const Uuid& session_id, AuthenticationLevel level) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            throw EntityNotFoundException("Session not found: " + session_id.to_string());
        }
        if (it->second.session_status != SessionStatus::Active) {
            throw InvalidEntityStateException("Cannot update authentication level on non-active session: " +
                                              session_id.to_string());
        }
        it->second.authentication_level = level;
    }

    void update_authentication_level(const Uuid& session_id, AuthenticationLevel level,
                                     pqxx::transaction_base& /*tx*/) override {
        update_authentication_level(session_id, level);
    }

    void revoke_session(const Uuid& session_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            throw EntityNotFoundException("Session not found: " + session_id.to_string());
        }
        it->second.session_status = SessionStatus::Revoked;
        it->second.revoked_at = revoked_at;
    }

    void revoke_session(const Uuid& session_id, domain::time_point revoked_at,
                        pqxx::transaction_base& /*tx*/) override {
        revoke_session(session_id, revoked_at);
    }

    void revoke_all_user_sessions(const Uuid& user_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, s] : sessions_) {
            if (s.user_id == user_id && s.session_status == SessionStatus::Active) {
                s.session_status = SessionStatus::Revoked;
                s.revoked_at = revoked_at;
            }
        }
    }

    void revoke_all_user_sessions(const Uuid& user_id, domain::time_point revoked_at,
                                  pqxx::transaction_base& /*tx*/) override {
        revoke_all_user_sessions(user_id, revoked_at);
    }

    void revoke_all_device_sessions(const domain::Uuid& device_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, s] : sessions_) {
            if (s.device_id == device_id && s.session_status == SessionStatus::Active) {
                s.session_status = SessionStatus::Revoked;
                s.revoked_at = revoked_at;
            }
        }
    }

    void revoke_all_device_sessions(const domain::Uuid& device_id, domain::time_point revoked_at,
                                    pqxx::transaction_base& /*tx*/) override {
        revoke_all_device_sessions(device_id, revoked_at);
    }

    bool touch_session_activity(const domain::Uuid& session_id, domain::time_point now) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end() && it->second.session_status == SessionStatus::Active &&
            it->second.expires_at > now) {
            it->second.last_used_at = now;
            return true;
        }
        return false;
    }

    bool touch_session_activity(const domain::Uuid& session_id, domain::time_point now,
                                pqxx::transaction_base& /*tx*/) override {
        return touch_session_activity(session_id, now);
    }

    uint64_t expire_stale_sessions(domain::time_point now) override {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t count = 0;
        for (auto& [id, s] : sessions_) {
            if (s.session_status == SessionStatus::Active && s.expires_at <= now) {
                s.session_status = SessionStatus::Expired;
                ++count;
            }
        }
        return count;
    }

    uint64_t expire_stale_sessions(domain::time_point now, pqxx::transaction_base& /*tx*/) override {
        return expire_stale_sessions(now);
    }

    bool revoke_session_atomic(const domain::Uuid& session_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end() && it->second.session_status == SessionStatus::Active) {
            it->second.session_status = SessionStatus::Revoked;
            it->second.revoked_at = revoked_at;
            return true;
        }
        return false;
    }

    bool revoke_session_atomic(const domain::Uuid& session_id, domain::time_point revoked_at,
                               pqxx::transaction_base& /*tx*/) override {
        return revoke_session_atomic(session_id, revoked_at);
    }

    uint64_t revoke_all_device_sessions_atomic(const domain::Uuid& device_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t count = 0;
        for (auto& [id, s] : sessions_) {
            if (s.device_id == device_id && s.session_status == SessionStatus::Active) {
                s.session_status = SessionStatus::Revoked;
                s.revoked_at = revoked_at;
                ++count;
            }
        }
        return count;
    }

    uint64_t revoke_all_device_sessions_atomic(const domain::Uuid& device_id, domain::time_point revoked_at,
                                               pqxx::transaction_base& /*tx*/) override {
        return revoke_all_device_sessions_atomic(device_id, revoked_at);
    }

    uint64_t revoke_all_user_sessions_atomic(const domain::Uuid& user_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t count = 0;
        for (auto& [id, s] : sessions_) {
            if (s.user_id == user_id && s.session_status == SessionStatus::Active) {
                s.session_status = SessionStatus::Revoked;
                s.revoked_at = revoked_at;
                ++count;
            }
        }
        return count;
    }

    uint64_t revoke_all_user_sessions_atomic(const domain::Uuid& user_id, domain::time_point revoked_at,
                                             pqxx::transaction_base& /*tx*/) override {
        return revoke_all_user_sessions_atomic(user_id, revoked_at);
    }

  private:
    std::mutex mutex_;
    std::map<Uuid, SessionEntity> sessions_;
};

class InMemoryRefreshTokenRepository : public IRefreshTokenRepository {
  public:
    explicit InMemoryRefreshTokenRepository(InMemorySessionRepository& session_repo) : session_repo_(session_repo) {}

    void create_token(const RefreshTokenEntity& token) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tokens_.find(token.refresh_token_id) != tokens_.end()) {
            throw DuplicateEntityException("Refresh token already exists: " + token.refresh_token_id.to_string());
        }
        tokens_[token.refresh_token_id] = token;
    }

    void create_token(const RefreshTokenEntity& token, pqxx::transaction_base& /*tx*/) override { create_token(token); }

    [[nodiscard]] std::optional<RefreshTokenEntity> find_by_id(const Uuid& refresh_token_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tokens_.find(refresh_token_id);
        if (it != tokens_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<RefreshTokenEntity> find_by_id(const Uuid& refresh_token_id,
                                                               pqxx::transaction_base& /*tx*/) override {
        return find_by_id(refresh_token_id);
    }

    [[nodiscard]] std::optional<RefreshTokenEntity> find_by_verifier(std::string_view verifier_hash) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, t] : tokens_) {
            if (t.token_verifier == verifier_hash) {
                return t;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<RefreshTokenEntity> find_by_verifier(std::string_view verifier_hash,
                                                                     pqxx::transaction_base& /*tx*/) override {
        return find_by_verifier(verifier_hash);
    }

    TokenRotationResult rotate_token_atomic(const Uuid& old_token_id, const RefreshTokenEntity& new_token) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tokens_.find(old_token_id);
        if (it == tokens_.end()) {
            throw EntityNotFoundException("Refresh token not found: " + old_token_id.to_string());
        }

        if (it->second.token_status != TokenStatus::Active) {
            throw InvalidEntityStateException("Cannot rotate non-active refresh token (" +
                                              std::string(domain::to_string(it->second.token_status)) +
                                              "): " + old_token_id.to_string());
        }

        const auto now = std::chrono::system_clock::now();
        if (now > it->second.expires_at) {
            throw InvalidEntityStateException("Cannot rotate expired refresh token: " + old_token_id.to_string());
        }

        // 1. Insert new token
        tokens_[new_token.refresh_token_id] = new_token;

        // 2. Mark old token as rotated
        it->second.token_status = TokenStatus::Rotated;
        it->second.rotated_at = now;
        it->second.replaced_by_token_id = new_token.refresh_token_id;

        return TokenRotationResult{
            .old_token = it->second,
            .new_token = new_token,
        };
    }

    TokenRotationResult rotate_token_atomic(const Uuid& old_token_id, const RefreshTokenEntity& new_token,
                                            pqxx::transaction_base& /*tx*/) override {
        return rotate_token_atomic(old_token_id, new_token);
    }

    TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find_if(tokens_.begin(), tokens_.end(),
                               [&](const auto& pair) { return pair.second.token_verifier == verifier_hash; });

        if (it == tokens_.end()) {
            throw EntityNotFoundException("Token verifier not found for reuse handling");
        }

        if (it->second.token_status != TokenStatus::Rotated) {
            throw InvalidEntityStateException("Token reuse handling triggered on non-rotated token: " +
                                              std::string(domain::to_string(it->second.token_status)));
        }

        const auto now = std::chrono::system_clock::now();
        const Uuid session_id = it->second.session_id;
        const Uuid device_id = it->second.device_id;

        // 1. Revoke the entire compromised session
        session_repo_.revoke_session(session_id, now);

        // 2. Revoke all active sibling tokens in that session family
        for (auto& [id, t] : tokens_) {
            if (t.session_id == session_id && t.token_status == TokenStatus::Active) {
                t.token_status = TokenStatus::Revoked;
                t.revoked_at = now;
            }
        }

        return TokenReuseDetectedResult{
            .session_id = session_id,
            .device_id = device_id,
            .revoked_at = now,
        };
    }

    TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash,
                                                pqxx::transaction_base& /*tx*/) override {
        return handle_token_reuse(verifier_hash);
    }

  private:
    std::mutex mutex_;
    InMemorySessionRepository& session_repo_;
    std::map<Uuid, RefreshTokenEntity> tokens_;
};

// ============================================================================
// 2. Host Port 5432 Isolation Test
// ============================================================================

TEST(SessionTokenRepositoryTest, RejectsForbiddenPort5432) {
    AuthConfig forbidden_cfg;
    forbidden_cfg.db_host = "localhost";
    forbidden_cfg.db_port = 5432;
    forbidden_cfg.db_name = "securecloud";
    forbidden_cfg.db_user = "securecloud_app";
    forbidden_cfg.db_password = common::configuration::SecretString{"test"};

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 3. Session Lifecycle & Authentication Step-Up Tests
// ============================================================================

TEST(SessionTokenRepositoryTest, SessionLifecycleAndStepUp) {
    InMemorySessionRepository session_repo;

    const auto user_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    SessionEntity session{
        .session_id = Uuid::generate_v7(),
        .user_id = user_id,
        .device_id = device_id,
        .session_status = SessionStatus::Active,
        .authentication_level = AuthenticationLevel::PrimaryOnly,
        .created_at = now,
        .expires_at = now + std::chrono::hours(24),
        .revoked_at = std::nullopt,
        .last_used_at = now,
    };

    // 1. Create session
    EXPECT_NO_THROW(session_repo.create_session(session));

    // 2. Find by ID
    auto found = session_repo.find_by_id(session.session_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->session_id, session.session_id);
    EXPECT_EQ(found->authentication_level, AuthenticationLevel::PrimaryOnly);

    // 3. List active sessions by user and device
    auto user_sessions = session_repo.list_active_by_user_id(user_id);
    EXPECT_EQ(user_sessions.size(), 1);

    auto device_sessions = session_repo.list_active_by_device_id(device_id);
    EXPECT_EQ(device_sessions.size(), 1);

    // 4. Step-up authentication to MfaVerified
    EXPECT_NO_THROW(session_repo.update_authentication_level(session.session_id, AuthenticationLevel::MfaVerified));
    found = session_repo.find_by_id(session.session_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->authentication_level, AuthenticationLevel::MfaVerified);

    // 5. Revoke session
    const auto revoked_at = now + std::chrono::hours(1);
    EXPECT_NO_THROW(session_repo.revoke_session(session.session_id, revoked_at));

    found = session_repo.find_by_id(session.session_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->session_status, SessionStatus::Revoked);
    EXPECT_EQ(found->revoked_at, revoked_at);

    // 6. Active listing now empty
    EXPECT_TRUE(session_repo.list_active_by_user_id(user_id).empty());

    // 7. Cannot step up a revoked session
    EXPECT_THROW(session_repo.update_authentication_level(session.session_id, AuthenticationLevel::PrimaryOnly),
                 InvalidEntityStateException);
}

// ============================================================================
// 4. Bulk Revocation Tests
// ============================================================================

TEST(SessionTokenRepositoryTest, BulkRevocationByUserAndDevice) {
    InMemorySessionRepository session_repo;

    const auto user_id = Uuid::generate_v7();
    const auto device1_id = Uuid::generate_v7();
    const auto device2_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    SessionEntity s1{
        .session_id = Uuid::generate_v7(),
        .user_id = user_id,
        .device_id = device1_id,
        .session_status = SessionStatus::Active,
        .authentication_level = AuthenticationLevel::PrimaryOnly,
        .created_at = now,
        .expires_at = now + std::chrono::hours(24),
        .revoked_at = std::nullopt,
        .last_used_at = now,
    };

    SessionEntity s2{
        .session_id = Uuid::generate_v7(),
        .user_id = user_id,
        .device_id = device2_id,
        .session_status = SessionStatus::Active,
        .authentication_level = AuthenticationLevel::PrimaryOnly,
        .created_at = now,
        .expires_at = now + std::chrono::hours(24),
        .revoked_at = std::nullopt,
        .last_used_at = now,
    };

    session_repo.create_session(s1);
    session_repo.create_session(s2);
    EXPECT_EQ(session_repo.list_active_by_user_id(user_id).size(), 2);

    // Revoke all sessions for device 1
    session_repo.revoke_all_device_sessions(device1_id, now);
    EXPECT_EQ(session_repo.list_active_by_device_id(device1_id).size(), 0);
    EXPECT_EQ(session_repo.list_active_by_device_id(device2_id).size(), 1);

    // Revoke all sessions for user
    session_repo.revoke_all_user_sessions(user_id, now);
    EXPECT_EQ(session_repo.list_active_by_user_id(user_id).size(), 0);
}

// ============================================================================
// 5. Refresh Token Atomic Rotation & Single-Use Invariant Tests
// ============================================================================

TEST(SessionTokenRepositoryTest, AtomicTokenRotationAndSingleUse) {
    InMemorySessionRepository session_repo;
    InMemoryRefreshTokenRepository token_repo(session_repo);

    const auto session_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    RefreshTokenEntity token1{
        .refresh_token_id = Uuid::generate_v7(),
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = "verifier_hash_token_1",
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720), // 30 days
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };

    token_repo.create_token(token1);

    RefreshTokenEntity token2{
        .refresh_token_id = Uuid::generate_v7(),
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = "verifier_hash_token_2",
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };

    // 1. Atomic rotation: Token 1 -> Token 2
    auto rotation_result = token_repo.rotate_token_atomic(token1.refresh_token_id, token2);
    EXPECT_EQ(rotation_result.old_token.token_status, TokenStatus::Rotated);
    EXPECT_EQ(rotation_result.old_token.replaced_by_token_id, token2.refresh_token_id);
    EXPECT_TRUE(rotation_result.old_token.rotated_at.has_value());
    EXPECT_EQ(rotation_result.new_token.token_status, TokenStatus::Active);

    // 2. Single-use invariant: Attempting to rotate Token 1 again fails!
    RefreshTokenEntity token3{
        .refresh_token_id = Uuid::generate_v7(),
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = "verifier_hash_token_3",
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };
    EXPECT_THROW(token_repo.rotate_token_atomic(token1.refresh_token_id, token3), InvalidEntityStateException);
}

// ============================================================================
// 6. Compromise Reuse Detection Test
// ============================================================================

TEST(SessionTokenRepositoryTest, CompromiseReuseDetectionQuarantinesSession) {
    InMemorySessionRepository session_repo;
    InMemoryRefreshTokenRepository token_repo(session_repo);

    const auto user_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto session_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    SessionEntity session{
        .session_id = session_id,
        .user_id = user_id,
        .device_id = device_id,
        .session_status = SessionStatus::Active,
        .authentication_level = AuthenticationLevel::PrimaryOnly,
        .created_at = now,
        .expires_at = now + std::chrono::hours(24),
        .revoked_at = std::nullopt,
        .last_used_at = now,
    };
    session_repo.create_session(session);

    RefreshTokenEntity token1{
        .refresh_token_id = Uuid::generate_v7(),
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = "stolen_token_1_hash",
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };
    token_repo.create_token(token1);

    // Legitimate rotation Token 1 -> Token 2
    RefreshTokenEntity token2{
        .refresh_token_id = Uuid::generate_v7(),
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = "legitimate_token_2_hash",
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };
    token_repo.rotate_token_atomic(token1.refresh_token_id, token2);

    // Attacker attempts to replay stolen Token 1 (already Rotated!)
    auto reuse_result = token_repo.handle_token_reuse("stolen_token_1_hash");
    EXPECT_EQ(reuse_result.session_id, session_id);
    EXPECT_EQ(reuse_result.device_id, device_id);

    // Verification 1: Compromised session is immediately revoked!
    auto session_after_reuse = session_repo.find_by_id(session_id);
    ASSERT_TRUE(session_after_reuse.has_value());
    EXPECT_EQ(session_after_reuse->session_status, SessionStatus::Revoked);

    // Verification 2: Active sibling child token (Token 2) is also revoked!
    auto token2_after_reuse = token_repo.find_by_id(token2.refresh_token_id);
    ASSERT_TRUE(token2_after_reuse.has_value());
    EXPECT_EQ(token2_after_reuse->token_status, TokenStatus::Revoked);
}

// ============================================================================
// 7. Multi-Threaded Concurrent Token Rotation Race Test
// ============================================================================

TEST(SessionTokenRepositoryTest, ConcurrentTokenRotationRace) {
    InMemorySessionRepository session_repo;
    InMemoryRefreshTokenRepository token_repo(session_repo);

    const auto session_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    RefreshTokenEntity initial_token{
        .refresh_token_id = Uuid::generate_v7(),
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = "race_initial_token_verifier",
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };
    token_repo.create_token(initial_token);

    constexpr int kNumConcurrentThreads = 8;
    std::atomic<int> success_count{0};
    std::atomic<int> collision_count{0};
    std::vector<std::thread> workers;
    workers.reserve(kNumConcurrentThreads);

    std::atomic<bool> start_race{false};

    for (int i = 0; i < kNumConcurrentThreads; ++i) {
        workers.emplace_back([&, i]() {
            while (!start_race.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }

            RefreshTokenEntity new_token{
                .refresh_token_id = Uuid::generate_v7(),
                .session_id = session_id,
                .device_id = device_id,
                .token_verifier = "candidate_verifier_" + std::to_string(i),
                .token_status = TokenStatus::Active,
                .issued_at = now,
                .expires_at = now + std::chrono::hours(720),
                .revoked_at = std::nullopt,
                .rotated_at = std::nullopt,
                .replaced_by_token_id = std::nullopt,
            };

            try {
                token_repo.rotate_token_atomic(initial_token.refresh_token_id, new_token);
                success_count.fetch_add(1, std::memory_order_relaxed);
            } catch (const RepositoryException&) {
                collision_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    start_race.store(true, std::memory_order_release);

    for (auto& t : workers) {
        t.join();
    }

    // Exactly one thread wins the rotation; all other 7 encounter single-use / OCC conflict!
    EXPECT_EQ(success_count.load(), 1);
    EXPECT_EQ(collision_count.load(), kNumConcurrentThreads - 1);

    auto final_old_token = token_repo.find_by_id(initial_token.refresh_token_id);
    ASSERT_TRUE(final_old_token.has_value());
    EXPECT_EQ(final_old_token->token_status, TokenStatus::Rotated);
}

// ============================================================================
// 8. Postgres Repositories Direct Construction with Pool
// ============================================================================

TEST(SessionTokenRepositoryTest, PostgresRepositoriesInstantiateCleanlyWithPool) {
    AuthConfig auth_cfg;
    auth_cfg.db_host = "127.0.0.1";
    auth_cfg.db_port = 5433; // Allowed test port
    auth_cfg.db_name = "securecloud";
    auth_cfg.db_user = "securecloud_app";
    auth_cfg.db_password = common::configuration::SecretString{"dummy"};

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0; // Avoid eager connection in test runner
    pool_cfg.max_connections = 1;

    db::PostgresConnectionPool pool(auth_cfg, pool_cfg);
    PostgresSessionRepository session_repo(pool);
    PostgresRefreshTokenRepository token_repo(pool);

    // Verify objects are validly instantiated
    EXPECT_NO_THROW({
        auto session_ptr = &session_repo;
        auto token_ptr = &token_repo;
        ASSERT_NE(session_ptr, nullptr);
        ASSERT_NE(token_ptr, nullptr);
    });
}

} // namespace
} // namespace securecloud::auth::repository::test
