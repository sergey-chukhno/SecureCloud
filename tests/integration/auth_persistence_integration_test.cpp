#include "auth/auth_config.hpp"
#include "auth/db/migration_runner.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/mfa_repository.hpp"
#include "auth/repository/refresh_token_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/repository/user_repository.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace securecloud::auth::integration::test {
namespace {

using domain::AccountStatus;
using domain::AuthenticationLevel;
using domain::DeviceEntity;
using domain::DevicePublicKeyEntity;
using domain::DeviceStatus;
using domain::KeyStatus;
using domain::KeyType;
using domain::MfaChallengeEntity;
using domain::MfaChallengePurpose;
using domain::MfaChallengeStatus;
using domain::MfaConfigurationEntity;
using domain::MfaFactorType;
using domain::MfaStatus;
using domain::RefreshTokenEntity;
using domain::SessionEntity;
using domain::SessionStatus;
using domain::TokenStatus;
using domain::UserEntity;
using domain::Uuid;

using repository::DuplicateEntityException;
using repository::EntityNotFoundException;
using repository::InvalidEntityStateException;
using repository::OptimisticLockException;

AuthConfig make_test_auth_config() {
    AuthConfig config;
    config.db_host = "127.0.0.1";
    config.db_port = 5433; // Strictly port 5433 (PostgreSQL 17 container)
    config.db_name = "securecloud_auth";
    config.db_user = "auth_user";
    config.db_password = common::configuration::SecretString("auth_dev_db_secret");
    return config;
}

class AuthPersistenceIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_ = make_test_auth_config();

        // Security Guard Invariant: NEVER touch host PostgreSQL 14 on port 5432!
        ASSERT_NE(config_.db_port, 5432) << "CRITICAL ERROR: Tests must NEVER connect to host PostgreSQL on port 5432!";
        ASSERT_EQ(config_.db_port, 5433) << "Tests must strictly connect to containerized PostgreSQL 17 on port 5433!";

        db::ConnectionPoolConfig pool_cfg;
        pool_cfg.min_connections = 2;
        pool_cfg.max_connections = 10;
        pool_cfg.acquire_timeout = std::chrono::milliseconds{5000};
        pool_cfg.connect_timeout = std::chrono::seconds{2};

        pool_ = std::make_unique<db::PostgresConnectionPool>(config_, pool_cfg);

        // Ensure database is online and reachable
        ASSERT_TRUE(pool_->ping()) << "PostgreSQL 17 container on 127.0.0.1:5433 is not reachable!";

        // Ensure migrations are applied prior to running repository tests
        db::MigrationRunner runner(*pool_);
        runner.run_migrations();
    }

    AuthConfig config_;
    std::unique_ptr<db::PostgresConnectionPool> pool_;
};

// ============================================================================
// 1. Strict Port 5432 Protection & Pre-Flight Isolation
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, StrictPort5432Protection) {
    AuthConfig forbidden_cfg = config_;
    forbidden_cfg.db_port = 5432;

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 2. MigrationRunner Transactional DDL & Idempotency
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, MigrationRunnerAppliesAllMigrationsAndIsIdempotent) {
    // Re-running run_migrations must detect that all 3 migrations are already applied and return 0
    db::MigrationRunner runner(*pool_);
    auto result = runner.run_migrations();
    EXPECT_EQ(result.migrations_applied, 0) << "MigrationRunner must be idempotent when re-run on current schema";
    EXPECT_EQ(result.current_version, 3);
}

// ============================================================================
// 3. UserRepository Full CRUD, Unique Constraint & OCC
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, UserRepositoryCrudAndOptimisticConcurrency) {
    repository::PostgresUserRepository user_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const std::string cred_id = "test_user_" + user_id.to_string() + "@securecloud.local";
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = cred_id,
        .password_verifier = "$argon2id$v=19$m=65536,t=3,p=4$dummyhash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };

    // 1. Create User
    EXPECT_NO_THROW(user_repo.create_user(user));

    // 2. Find by ID
    auto found_by_id = user_repo.find_by_id(user_id);
    ASSERT_TRUE(found_by_id.has_value());
    EXPECT_EQ(found_by_id->credential_identifier, cred_id);
    EXPECT_EQ(found_by_id->version, 1);

    // 3. Find by Credential Identifier
    auto found_by_cred = user_repo.find_by_credential_identifier(cred_id);
    ASSERT_TRUE(found_by_cred.has_value());
    EXPECT_EQ(found_by_cred->user_id, user_id);

    // 4. Duplicate Credential Check
    UserEntity dup_user = user;
    dup_user.user_id = Uuid::generate_v7();
    EXPECT_THROW(user_repo.create_user(dup_user), DuplicateEntityException);

    // 5. Successful OCC Update (version 1 -> 2)
    UserEntity updated_user = *found_by_id;
    updated_user.credential_identifier = "renamed_" + cred_id;
    EXPECT_NO_THROW(user_repo.update_user(updated_user));

    auto post_update = user_repo.find_by_id(user_id);
    ASSERT_TRUE(post_update.has_value());
    EXPECT_EQ(post_update->credential_identifier, "renamed_" + cred_id);
    EXPECT_EQ(post_update->version, 2);

    // 6. OCC Stale Version Conflict (attempting to update using stale version 1)
    UserEntity stale_user = updated_user;
    stale_user.version = 1;
    EXPECT_THROW(user_repo.update_user(stale_user), OptimisticLockException);

    // 7. Update Non-Existent User
    UserEntity missing_user = user;
    missing_user.user_id = Uuid::generate_v7();
    missing_user.credential_identifier = "missing_" + missing_user.user_id.to_string() + "@securecloud.local";
    EXPECT_THROW(user_repo.update_user(missing_user), EntityNotFoundException);
}

// ============================================================================
// 4. DeviceRepository Registration, Active Filtering & Revocation
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, DeviceRepositoryRegistrationAndRevocation) {
    repository::PostgresUserRepository user_repo(*pool_);
    repository::PostgresDeviceRepository device_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = "device_owner_" + user_id.to_string() + "@securecloud.local",
        .password_verifier = "hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(user);

    const auto dev1_id = Uuid::generate_v7();
    DeviceEntity dev1{
        .device_id = dev1_id,
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };

    // 1. Invariant: Rejects registering device with Revoked status
    DeviceEntity revoked_init = dev1;
    revoked_init.device_id = Uuid::generate_v7();
    revoked_init.device_status = DeviceStatus::Revoked;
    EXPECT_THROW(device_repo.register_device(revoked_init), InvalidEntityStateException);

    // 2. Register Active Device
    EXPECT_NO_THROW(device_repo.register_device(dev1));

    auto found_dev = device_repo.find_by_id(dev1_id);
    ASSERT_TRUE(found_dev.has_value());
    EXPECT_EQ(found_dev->device_status, DeviceStatus::Active);

    // 3. List active devices
    auto active_devs = device_repo.list_active_by_user_id(user_id);
    EXPECT_EQ(active_devs.size(), 1);
    EXPECT_EQ(active_devs[0].device_id, dev1_id);

    // 4. Update last authenticated time
    const auto auth_time = now + std::chrono::minutes(5);
    EXPECT_NO_THROW(device_repo.update_last_authenticated(dev1_id, auth_time));

    // 5. Revoke Device
    const auto revoke_time = now + std::chrono::hours(1);
    EXPECT_NO_THROW(device_repo.revoke_device(dev1_id, "Device stolen", revoke_time));

    auto post_revoke = device_repo.find_by_id(dev1_id);
    ASSERT_TRUE(post_revoke.has_value());
    EXPECT_EQ(post_revoke->device_status, DeviceStatus::Revoked);
    EXPECT_EQ(post_revoke->revocation_reason, "Device stolen");

    // 6. Active listing excludes revoked device
    EXPECT_TRUE(device_repo.list_active_by_user_id(user_id).empty());

    // 7. Invariant: Cannot update authentication time on a revoked device
    EXPECT_THROW(device_repo.update_last_authenticated(dev1_id, auth_time), InvalidEntityStateException);
}

// ============================================================================
// 5. SessionRepository Lifecycle & Monotonic Step-Up
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, SessionRepositoryLifecycleAndStepUp) {
    repository::PostgresUserRepository user_repo(*pool_);
    repository::PostgresDeviceRepository device_repo(*pool_);
    repository::PostgresSessionRepository session_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto session_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = "session_user_" + user_id.to_string() + "@securecloud.local",
        .password_verifier = "hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(user);

    DeviceEntity device{
        .device_id = device_id,
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    device_repo.register_device(device);

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

    // 1. Create Session
    EXPECT_NO_THROW(session_repo.create_session(session));

    auto found = session_repo.find_by_id(session_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->session_status, SessionStatus::Active);
    EXPECT_EQ(found->authentication_level, AuthenticationLevel::PrimaryOnly);

    // 2. Step up to MfaVerified
    EXPECT_NO_THROW(session_repo.update_authentication_level(session_id, AuthenticationLevel::MfaVerified));
    found = session_repo.find_by_id(session_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->authentication_level, AuthenticationLevel::MfaVerified);

    // 3. Revoke Session
    EXPECT_NO_THROW(session_repo.revoke_session(session_id, now + std::chrono::hours(1)));
    found = session_repo.find_by_id(session_id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->session_status, SessionStatus::Revoked);

    // 4. Invariant: Cannot step up revoked session
    EXPECT_THROW(session_repo.update_authentication_level(session_id, AuthenticationLevel::PrimaryOnly),
                 InvalidEntityStateException);
}

// ============================================================================
// 6. SessionRepository Bulk Revocation
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, SessionRepositoryBulkRevocation) {
    repository::PostgresUserRepository user_repo(*pool_);
    repository::PostgresDeviceRepository device_repo(*pool_);
    repository::PostgresSessionRepository session_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const auto dev1_id = Uuid::generate_v7();
    const auto dev2_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = "bulk_user_" + user_id.to_string() + "@securecloud.local",
        .password_verifier = "hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(user);

    DeviceEntity dev1{
        .device_id = dev1_id,
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    device_repo.register_device(dev1);

    DeviceEntity dev2 = dev1;
    dev2.device_id = dev2_id;
    device_repo.register_device(dev2);

    SessionEntity s1{
        .session_id = Uuid::generate_v7(),
        .user_id = user_id,
        .device_id = dev1_id,
        .session_status = SessionStatus::Active,
        .authentication_level = AuthenticationLevel::PrimaryOnly,
        .created_at = now,
        .expires_at = now + std::chrono::hours(24),
        .revoked_at = std::nullopt,
        .last_used_at = now,
    };
    session_repo.create_session(s1);

    SessionEntity s2 = s1;
    s2.session_id = Uuid::generate_v7();
    s2.device_id = dev2_id;
    session_repo.create_session(s2);

    EXPECT_EQ(session_repo.list_active_by_user_id(user_id).size(), 2);

    // Revoke by device
    session_repo.revoke_all_device_sessions(dev1_id, now);
    EXPECT_EQ(session_repo.list_active_by_device_id(dev1_id).size(), 0);
    EXPECT_EQ(session_repo.list_active_by_device_id(dev2_id).size(), 1);

    // Revoke all for user
    session_repo.revoke_all_user_sessions(user_id, now);
    EXPECT_EQ(session_repo.list_active_by_user_id(user_id).size(), 0);
}

// ============================================================================
// 7. RefreshTokenRepository Atomic Rotation
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, RefreshTokenRepositoryAtomicRotation) {
    repository::PostgresUserRepository user_repo(*pool_);
    repository::PostgresDeviceRepository device_repo(*pool_);
    repository::PostgresSessionRepository session_repo(*pool_);
    repository::PostgresRefreshTokenRepository token_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto session_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = "token_user_" + user_id.to_string() + "@securecloud.local",
        .password_verifier = "hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(user);

    DeviceEntity device{
        .device_id = device_id,
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    device_repo.register_device(device);

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

    const auto token1_id = Uuid::generate_v7();
    const std::string verifier1 = "verifier_hash_1_" + token1_id.to_string();

    RefreshTokenEntity token1{
        .refresh_token_id = token1_id,
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = verifier1,
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };
    token_repo.create_token(token1);

    const auto token2_id = Uuid::generate_v7();
    const std::string verifier2 = "verifier_hash_2_" + token2_id.to_string();

    RefreshTokenEntity token2{
        .refresh_token_id = token2_id,
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = verifier2,
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };

    // 1. Atomic Single-Use Rotation: Token 1 -> Token 2
    auto rotation_res = token_repo.rotate_token_atomic(token1_id, token2);
    EXPECT_EQ(rotation_res.old_token.token_status, TokenStatus::Rotated);
    EXPECT_EQ(rotation_res.old_token.replaced_by_token_id, token2_id);
    EXPECT_EQ(rotation_res.new_token.token_status, TokenStatus::Active);

    // Verify in database
    auto db_token1 = token_repo.find_by_id(token1_id);
    ASSERT_TRUE(db_token1.has_value());
    EXPECT_EQ(db_token1->token_status, TokenStatus::Rotated);
    EXPECT_EQ(db_token1->replaced_by_token_id, token2_id);

    auto db_token2 = token_repo.find_by_id(token2_id);
    ASSERT_TRUE(db_token2.has_value());
    EXPECT_EQ(db_token2->token_status, TokenStatus::Active);

    // 2. Single-use Invariant: Rotating Token 1 again fails!
    const auto token3_id = Uuid::generate_v7();
    RefreshTokenEntity token3 = token2;
    token3.refresh_token_id = token3_id;
    token3.token_verifier = "verifier_hash_3_" + token3_id.to_string();

    EXPECT_THROW(token_repo.rotate_token_atomic(token1_id, token3), InvalidEntityStateException);
}

// ============================================================================
// 8. RefreshTokenRepository Compromise Reuse Detection
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, RefreshTokenRepositoryCompromiseReuseDetection) {
    repository::PostgresUserRepository user_repo(*pool_);
    repository::PostgresDeviceRepository device_repo(*pool_);
    repository::PostgresSessionRepository session_repo(*pool_);
    repository::PostgresRefreshTokenRepository token_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto session_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = "reuse_user_" + user_id.to_string() + "@securecloud.local",
        .password_verifier = "hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(user);

    DeviceEntity device{
        .device_id = device_id,
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    device_repo.register_device(device);

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

    const auto token1_id = Uuid::generate_v7();
    const std::string verifier1 = "stolen_verifier_" + token1_id.to_string();

    RefreshTokenEntity token1{
        .refresh_token_id = token1_id,
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = verifier1,
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };
    token_repo.create_token(token1);

    const auto token2_id = Uuid::generate_v7();
    const std::string verifier2 = "child_verifier_" + token2_id.to_string();

    RefreshTokenEntity token2{
        .refresh_token_id = token2_id,
        .session_id = session_id,
        .device_id = device_id,
        .token_verifier = verifier2,
        .token_status = TokenStatus::Active,
        .issued_at = now,
        .expires_at = now + std::chrono::hours(720),
        .revoked_at = std::nullopt,
        .rotated_at = std::nullopt,
        .replaced_by_token_id = std::nullopt,
    };

    // Legitimate rotation Token 1 -> Token 2
    token_repo.rotate_token_atomic(token1_id, token2);

    // Compromise Reuse Attempt: Replay stolen Token 1 (already Rotated!)
    auto reuse_result = token_repo.handle_token_reuse(verifier1);
    EXPECT_EQ(reuse_result.session_id, session_id);
    EXPECT_EQ(reuse_result.device_id, device_id);

    // Verification 1: Compromised session is instantly revoked
    auto db_session = session_repo.find_by_id(session_id);
    ASSERT_TRUE(db_session.has_value());
    EXPECT_EQ(db_session->session_status, SessionStatus::Revoked);

    // Verification 2: Active child Token 2 is also revoked
    auto db_token2 = token_repo.find_by_id(token2_id);
    ASSERT_TRUE(db_token2.has_value());
    EXPECT_EQ(db_token2->token_status, TokenStatus::Revoked);
}

// ============================================================================
// 9. DevicePublicKeyRepository Binary Fidelity & Replacement
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, DevicePublicKeyRepositoryFidelityAndReplacement) {
    repository::PostgresUserRepository user_repo(*pool_);
    repository::PostgresDeviceRepository device_repo(*pool_);
    repository::PostgresDevicePublicKeyRepository key_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = "key_owner_" + user_id.to_string() + "@securecloud.local",
        .password_verifier = "hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(user);

    DeviceEntity device{
        .device_id = device_id,
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    device_repo.register_device(device);

    const std::vector<uint8_t> raw_key_1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};

    const auto key1_id = Uuid::generate_v7();
    DevicePublicKeyEntity key1{
        .key_id = key1_id,
        .device_id = device_id,
        .key_type = KeyType::IdentitySigning,
        .public_key = raw_key_1,
        .key_status = KeyStatus::Active,
        .created_at = now,
        .revoked_at = std::nullopt,
        .replaced_by_key_id = std::nullopt,
    };

    // 1. Store Key
    EXPECT_NO_THROW(key_repo.store_public_key(key1));

    // 2. Binary fidelity verification
    auto found_key = key_repo.find_by_id(key1_id);
    ASSERT_TRUE(found_key.has_value());
    EXPECT_EQ(found_key->public_key, raw_key_1);

    // 3. Replace key
    const auto key2_id = Uuid::generate_v7();
    const std::vector<uint8_t> raw_key_2(16, 0x77);
    DevicePublicKeyEntity key2{
        .key_id = key2_id,
        .device_id = device_id,
        .key_type = KeyType::IdentitySigning,
        .public_key = raw_key_2,
        .key_status = KeyStatus::Active,
        .created_at = now,
        .revoked_at = std::nullopt,
        .replaced_by_key_id = std::nullopt,
    };

    EXPECT_NO_THROW(key_repo.replace_key(key1_id, key2));

    auto old_key_after = key_repo.find_by_id(key1_id);
    ASSERT_TRUE(old_key_after.has_value());
    EXPECT_EQ(old_key_after->key_status, KeyStatus::Replaced);
    EXPECT_EQ(old_key_after->replaced_by_key_id, key2_id);

    auto active_keys = key_repo.list_active_keys_by_device_id(device_id);
    ASSERT_EQ(active_keys.size(), 1);
    EXPECT_EQ(active_keys[0].key_id, key2_id);
    EXPECT_EQ(active_keys[0].public_key, raw_key_2);

    // 4. Revoke all keys
    EXPECT_NO_THROW(key_repo.revoke_all_device_keys(device_id, now));
    EXPECT_TRUE(key_repo.list_active_keys_by_device_id(device_id).empty());
}

// ============================================================================
// 10. MfaRepository Lifecycle & Challenge Expiration
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, MfaRepositoryLifecycleAndChallengeExpiration) {
    repository::PostgresUserRepository user_repo(*pool_);
    repository::PostgresDeviceRepository device_repo(*pool_);
    repository::PostgresSessionRepository session_repo(*pool_);
    repository::PostgresMfaRepository mfa_repo(*pool_);

    const auto user_id = Uuid::generate_v7();
    const auto device_id = Uuid::generate_v7();
    const auto session_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    UserEntity user{
        .user_id = user_id,
        .credential_identifier = "mfa_user_" + user_id.to_string() + "@securecloud.local",
        .password_verifier = "hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(user);

    DeviceEntity device{
        .device_id = device_id,
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };
    device_repo.register_device(device);

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

    const auto config_id = Uuid::generate_v7();
    const std::vector<uint8_t> secret = {0xde, 0xad, 0xbe, 0xef};

    MfaConfigurationEntity config{
        .mfa_configuration_id = config_id,
        .user_id = user_id,
        .factor_type = MfaFactorType::Totp,
        .encrypted_secret = secret,
        .status = MfaStatus::Pending,
        .created_at = now,
        .enabled_at = std::nullopt,
        .disabled_at = std::nullopt,
        .version = 1,
    };

    // 1. Store MFA Configuration
    EXPECT_NO_THROW(mfa_repo.store_mfa_configuration(config));

    auto found_cfg = mfa_repo.find_mfa_config_by_user_id(user_id);
    ASSERT_TRUE(found_cfg.has_value());
    EXPECT_EQ(found_cfg->status, MfaStatus::Pending);
    EXPECT_EQ(found_cfg->version, 1);

    // 2. Enable MFA under OCC (version 1 -> 2)
    EXPECT_NO_THROW(mfa_repo.enable_mfa(config_id, now, 1));
    found_cfg = mfa_repo.find_mfa_config_by_user_id(user_id);
    ASSERT_TRUE(found_cfg.has_value());
    EXPECT_EQ(found_cfg->status, MfaStatus::Enabled);
    EXPECT_EQ(found_cfg->version, 2);

    // 3. Stale version rejection
    EXPECT_THROW(mfa_repo.disable_mfa(config_id, now, 1), OptimisticLockException);

    // 4. Create active challenge
    const auto challenge_id = Uuid::generate_v7();
    MfaChallengeEntity challenge{
        .mfa_challenge_id = challenge_id,
        .user_id = user_id,
        .session_id = session_id,
        .challenge_purpose = MfaChallengePurpose::Login,
        .challenge_status = MfaChallengeStatus::Pending,
        .created_at = now,
        .expires_at = now + std::chrono::minutes(5),
        .completed_at = std::nullopt,
    };
    EXPECT_NO_THROW(mfa_repo.create_challenge(challenge));

    // 5. Complete active challenge
    EXPECT_NO_THROW(mfa_repo.complete_challenge(challenge_id, now));
    auto completed = mfa_repo.find_challenge_by_id(challenge_id);
    ASSERT_TRUE(completed.has_value());
    EXPECT_EQ(completed->challenge_status, MfaChallengeStatus::Completed);

    // 6. Expired challenge rejection
    const auto expired_id = Uuid::generate_v7();
    MfaChallengeEntity expired_challenge{
        .mfa_challenge_id = expired_id,
        .user_id = user_id,
        .session_id = session_id,
        .challenge_purpose = MfaChallengePurpose::StepUp,
        .challenge_status = MfaChallengeStatus::Pending,
        .created_at = now - std::chrono::minutes(10),
        .expires_at = now - std::chrono::minutes(5), // Already expired
        .completed_at = std::nullopt,
    };
    EXPECT_NO_THROW(mfa_repo.create_challenge(expired_challenge));
    EXPECT_THROW(mfa_repo.complete_challenge(expired_id, now), InvalidEntityStateException);
}

// ============================================================================
// 11. Multi-Threaded Connection Pool Contention Harness
// ============================================================================

TEST_F(AuthPersistenceIntegrationTest, ConnectionPoolContentionUnderConcurrentLoad) {
    db::ConnectionPoolConfig small_pool_cfg;
    small_pool_cfg.min_connections = 2;
    small_pool_cfg.max_connections = 5; // Constrained 5-connection pool
    small_pool_cfg.acquire_timeout = std::chrono::milliseconds{10000};
    small_pool_cfg.connect_timeout = std::chrono::seconds{2};

    db::PostgresConnectionPool small_pool(config_, small_pool_cfg);

    constexpr int kNumThreads = 20;
    constexpr int kOpsPerThread = 5;

    std::atomic<int> completed_ops{0};
    std::atomic<bool> failure_detected{false};
    std::string failure_reason;
    std::mutex failure_mutex;

    std::vector<std::thread> workers;
    workers.reserve(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        workers.emplace_back([&, t]() {
            try {
                repository::PostgresUserRepository user_repo(small_pool);
                for (int op = 0; op < kOpsPerThread; ++op) {
                    const auto uid = Uuid::generate_v7();
                    const std::string cred =
                        "contention_" + std::to_string(t) + "_" + std::to_string(op) + "_" + uid.to_string();
                    const auto now = std::chrono::system_clock::now();

                    UserEntity u{
                        .user_id = uid,
                        .credential_identifier = cred,
                        .password_verifier = "hash",
                        .password_algorithm = "argon2id",
                        .password_updated_at = now,
                        .account_status = AccountStatus::Active,
                        .created_at = now,
                        .updated_at = now,
                        .version = 1,
                    };

                    user_repo.create_user(u);
                    auto found = user_repo.find_by_id(uid);
                    if (!found.has_value() || found->credential_identifier != cred) {
                        throw std::runtime_error("Data mismatch under contention for " + cred);
                    }
                    completed_ops.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (const std::exception& ex) {
                failure_detected.store(true, std::memory_order_relaxed);
                std::lock_guard<std::mutex> lock(failure_mutex);
                failure_reason = ex.what();
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    EXPECT_FALSE(failure_detected.load()) << "Failure under pool contention: " << failure_reason;
    EXPECT_EQ(completed_ops.load(), kNumThreads * kOpsPerThread);
}

} // namespace
} // namespace securecloud::auth::integration::test

// Deterministic Process Teardown (eliminates MinGW/Windows loader lock hangs)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
