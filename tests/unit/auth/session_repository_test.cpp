#include "auth/auth_config.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/session_repository.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace securecloud::auth::repository::test {
namespace {

using domain::AuthenticationLevel;
using domain::SessionEntity;
using domain::SessionStatus;
using domain::Uuid;

// Thread-safe in-memory test double of ISessionRepository
class InMemoryTestSessionRepository : public ISessionRepository {
  public:
    void create_session(const SessionEntity& session) override {
        std::lock_guard<std::mutex> lock(mutex_);
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

    [[nodiscard]] std::vector<SessionEntity> list_active_by_device_id(const domain::Uuid& device_id,
                                                                      pqxx::transaction_base& /*tx*/) override {
        return list_active_by_device_id(device_id);
    }

    void update_authentication_level(const Uuid& session_id, AuthenticationLevel level) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            it->second.authentication_level = level;
        }
    }

    void update_authentication_level(const Uuid& session_id, AuthenticationLevel level,
                                     pqxx::transaction_base& /*tx*/) override {
        update_authentication_level(session_id, level);
    }

    void revoke_session(const Uuid& session_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            it->second.session_status = SessionStatus::Revoked;
            it->second.revoked_at = revoked_at;
        }
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

    void revoke_all_device_sessions(const Uuid& device_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, s] : sessions_) {
            if (s.device_id == device_id && s.session_status == SessionStatus::Active) {
                s.session_status = SessionStatus::Revoked;
                s.revoked_at = revoked_at;
            }
        }
    }

    void revoke_all_device_sessions(const Uuid& device_id, domain::time_point revoked_at,
                                    pqxx::transaction_base& /*tx*/) override {
        revoke_all_device_sessions(device_id, revoked_at);
    }

    bool touch_session_activity(const Uuid& session_id, domain::time_point now) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end() && it->second.session_status == SessionStatus::Active &&
            it->second.expires_at > now) {
            it->second.last_used_at = now;
            return true;
        }
        return false;
    }

    bool touch_session_activity(const Uuid& session_id, domain::time_point now,
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

    bool revoke_session_atomic(const Uuid& session_id, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end() && it->second.session_status == SessionStatus::Active) {
            it->second.session_status = SessionStatus::Revoked;
            it->second.revoked_at = revoked_at;
            return true;
        }
        return false;
    }

    bool revoke_session_atomic(const Uuid& session_id, domain::time_point revoked_at,
                               pqxx::transaction_base& /*tx*/) override {
        return revoke_session_atomic(session_id, revoked_at);
    }

    uint64_t revoke_all_device_sessions_atomic(const Uuid& device_id, domain::time_point revoked_at) override {
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

    uint64_t revoke_all_device_sessions_atomic(const Uuid& device_id, domain::time_point revoked_at,
                                               pqxx::transaction_base& /*tx*/) override {
        return revoke_all_device_sessions_atomic(device_id, revoked_at);
    }

    uint64_t revoke_all_user_sessions_atomic(const Uuid& user_id, domain::time_point revoked_at) override {
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

    uint64_t revoke_all_user_sessions_atomic(const Uuid& user_id, domain::time_point revoked_at,
                                             pqxx::transaction_base& /*tx*/) override {
        return revoke_all_user_sessions_atomic(user_id, revoked_at);
    }

  private:
    std::mutex mutex_;
    std::map<Uuid, SessionEntity> sessions_;
};

SessionEntity create_sample_session(Uuid user_id = Uuid::generate_v7(), Uuid device_id = Uuid::generate_v7(),
                                    SessionStatus status = SessionStatus::Active,
                                    std::chrono::seconds ttl = std::chrono::hours(24)) {
    auto now = std::chrono::system_clock::now();
    SessionEntity session;
    session.session_id = Uuid::generate_v7();
    session.user_id = user_id;
    session.device_id = device_id;
    session.session_status = status;
    session.authentication_level = AuthenticationLevel::PrimaryOnly;
    session.created_at = now;
    session.last_used_at = now;
    session.expires_at = now + ttl;
    session.revoked_at = (status == SessionStatus::Revoked) ? std::optional<domain::time_point>{now} : std::nullopt;
    return session;
}

// Test 1: Strict Port 5432 Protection rejects forbidden host port
TEST(SessionRepositoryTest, StrictPort5432Protection) {
    AuthConfig config;
    config.db_host = "127.0.0.1";
    config.db_port = 5432;
    config.db_name = "securecloud_auth";
    config.db_user = "auth_user";
    config.db_password = common::configuration::SecretString("secret");

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(config, pool_cfg)), db::PortForbiddenException);
}

// Test 2: TouchActivity succeeds and updates last_used_at for active unexpired session
TEST(SessionRepositoryTest, TouchActivity_SucceedsForActiveUnexpiredSession) {
    InMemoryTestSessionRepository repo;
    auto session = create_sample_session();
    repo.create_session(session);

    auto touch_time = session.created_at + std::chrono::minutes(5);
    bool touched = repo.touch_session_activity(session.session_id, touch_time);

    EXPECT_TRUE(touched);
    auto retrieved = repo.find_by_id(session.session_id);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->last_used_at, touch_time);
}

// Test 3: TouchActivity rejects expired session
TEST(SessionRepositoryTest, TouchActivity_RejectsExpiredSession) {
    InMemoryTestSessionRepository repo;
    // Session that already expired 10 minutes ago
    auto session = create_sample_session(Uuid::generate_v7(), Uuid::generate_v7(), SessionStatus::Active,
                                         -std::chrono::minutes(10));
    repo.create_session(session);

    auto now = std::chrono::system_clock::now();
    bool touched = repo.touch_session_activity(session.session_id, now);

    EXPECT_FALSE(touched);
}

// Test 4: TouchActivity rejects revoked session
TEST(SessionRepositoryTest, TouchActivity_RejectsRevokedSession) {
    InMemoryTestSessionRepository repo;
    auto session = create_sample_session(Uuid::generate_v7(), Uuid::generate_v7(), SessionStatus::Revoked);
    repo.create_session(session);

    auto now = std::chrono::system_clock::now();
    bool touched = repo.touch_session_activity(session.session_id, now);

    EXPECT_FALSE(touched);
}

// Test 5: TouchActivity rejects non-existent session
TEST(SessionRepositoryTest, TouchActivity_RejectsNonExistentSession) {
    InMemoryTestSessionRepository repo;
    auto unknown_id = Uuid::generate_v7();
    auto now = std::chrono::system_clock::now();

    bool touched = repo.touch_session_activity(unknown_id, now);
    EXPECT_FALSE(touched);
}

// Test 6: ExpireStaleSessions sweeps only active sessions whose expires_at <= now
TEST(SessionRepositoryTest, ExpireStaleSessions_SweepsOnlyExpiredActiveSessions) {
    InMemoryTestSessionRepository repo;
    auto now = std::chrono::system_clock::now();

    // s1: Active, unexpired (+1 hour)
    auto s1 =
        create_sample_session(Uuid::generate_v7(), Uuid::generate_v7(), SessionStatus::Active, std::chrono::hours(1));
    repo.create_session(s1);

    // s2: Active, expired (-10 min)
    auto s2 = create_sample_session(Uuid::generate_v7(), Uuid::generate_v7(), SessionStatus::Active,
                                    -std::chrono::minutes(10));
    repo.create_session(s2);

    // s3: Active, expired (-5 min)
    auto s3 = create_sample_session(Uuid::generate_v7(), Uuid::generate_v7(), SessionStatus::Active,
                                    -std::chrono::minutes(5));
    repo.create_session(s3);

    // s4: Already Revoked, expired (-10 min)
    auto s4 = create_sample_session(Uuid::generate_v7(), Uuid::generate_v7(), SessionStatus::Revoked,
                                    -std::chrono::minutes(10));
    repo.create_session(s4);

    uint64_t swept = repo.expire_stale_sessions(now);

    EXPECT_EQ(swept, 2);
    EXPECT_EQ(repo.find_by_id(s1.session_id)->session_status, SessionStatus::Active);
    EXPECT_EQ(repo.find_by_id(s2.session_id)->session_status, SessionStatus::Expired);
    EXPECT_EQ(repo.find_by_id(s3.session_id)->session_status, SessionStatus::Expired);
    EXPECT_EQ(repo.find_by_id(s4.session_id)->session_status, SessionStatus::Revoked);
}

// Test 7: RevokeSessionAtomic transitions active session and returns true
TEST(SessionRepositoryTest, RevokeSessionAtomic_TransitionsActiveAndReturnsTrue) {
    InMemoryTestSessionRepository repo;
    auto session = create_sample_session();
    repo.create_session(session);

    auto now = std::chrono::system_clock::now();
    bool revoked = repo.revoke_session_atomic(session.session_id, now);

    EXPECT_TRUE(revoked);
    auto retrieved = repo.find_by_id(session.session_id);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->session_status, SessionStatus::Revoked);
    EXPECT_EQ(retrieved->revoked_at, now);
}

// Test 8: RevokeSessionAtomic is idempotent and returns false on subsequent call
TEST(SessionRepositoryTest, RevokeSessionAtomic_IdempotentOnSubsequentCalls) {
    InMemoryTestSessionRepository repo;
    auto session = create_sample_session();
    repo.create_session(session);

    auto now = std::chrono::system_clock::now();
    EXPECT_TRUE(repo.revoke_session_atomic(session.session_id, now));
    // Second revocation attempt against already-revoked session
    EXPECT_FALSE(repo.revoke_session_atomic(session.session_id, now));
}

// Test 9: RevokeAllDeviceSessionsAtomic revokes only active sessions for the targeted device
TEST(SessionRepositoryTest, RevokeAllDeviceSessionsAtomic_RevokesOnlyMatchingActive) {
    InMemoryTestSessionRepository repo;
    auto user_id = Uuid::generate_v7();
    auto dev_target = Uuid::generate_v7();
    auto dev_other = Uuid::generate_v7();

    auto s1 = create_sample_session(user_id, dev_target);
    auto s2 = create_sample_session(user_id, dev_target);
    auto s3 = create_sample_session(user_id, dev_other);

    repo.create_session(s1);
    repo.create_session(s2);
    repo.create_session(s3);

    auto now = std::chrono::system_clock::now();
    uint64_t count = repo.revoke_all_device_sessions_atomic(dev_target, now);

    EXPECT_EQ(count, 2);
    EXPECT_EQ(repo.find_by_id(s1.session_id)->session_status, SessionStatus::Revoked);
    EXPECT_EQ(repo.find_by_id(s2.session_id)->session_status, SessionStatus::Revoked);
    EXPECT_EQ(repo.find_by_id(s3.session_id)->session_status, SessionStatus::Active);
}

// Test 10: RevokeAllUserSessionsAtomic revokes across multiple devices for that user
TEST(SessionRepositoryTest, RevokeAllUserSessionsAtomic_RevokesAcrossMultipleDevices) {
    InMemoryTestSessionRepository repo;
    auto user_target = Uuid::generate_v7();
    auto user_other = Uuid::generate_v7();
    auto dev1 = Uuid::generate_v7();
    auto dev2 = Uuid::generate_v7();

    auto s1 = create_sample_session(user_target, dev1);
    auto s2 = create_sample_session(user_target, dev2);
    auto s3 = create_sample_session(user_other, dev1);

    repo.create_session(s1);
    repo.create_session(s2);
    repo.create_session(s3);

    auto now = std::chrono::system_clock::now();
    uint64_t count = repo.revoke_all_user_sessions_atomic(user_target, now);

    EXPECT_EQ(count, 2);
    EXPECT_EQ(repo.find_by_id(s1.session_id)->session_status, SessionStatus::Revoked);
    EXPECT_EQ(repo.find_by_id(s2.session_id)->session_status, SessionStatus::Revoked);
    EXPECT_EQ(repo.find_by_id(s3.session_id)->session_status, SessionStatus::Active);

    // Also verify PostgresSessionRepository instantiates cleanly with connection pool on valid port 5433
    AuthConfig valid_config;
    valid_config.db_host = "127.0.0.1";
    valid_config.db_port = 5433;
    valid_config.db_name = "securecloud_auth";
    valid_config.db_user = "auth_user";
    valid_config.db_password = common::configuration::SecretString("auth_secret");

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    db::PostgresConnectionPool pool(valid_config, pool_cfg);
    EXPECT_NO_THROW({ PostgresSessionRepository pg_repo(pool); });
}

} // namespace
} // namespace securecloud::auth::repository::test
