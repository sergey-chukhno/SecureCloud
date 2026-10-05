#include "auth/auth_config.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/user_repository.hpp"

#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::auth::repository::test {
namespace {

using domain::AccountStatus;
using domain::DeviceEntity;
using domain::DeviceStatus;
using domain::UserEntity;
using domain::Uuid;

// ============================================================================
// 1. Exception Hierarchy Tests
// ============================================================================

TEST(UserDeviceRepositoryTest, ExceptionHierarchyInheritance) {
    static_assert(std::is_base_of_v<RepositoryException, EntityNotFoundException>);
    static_assert(std::is_base_of_v<RepositoryException, DuplicateEntityException>);
    static_assert(std::is_base_of_v<RepositoryException, OptimisticLockException>);
    static_assert(std::is_base_of_v<RepositoryException, InvalidEntityStateException>);
    static_assert(std::is_base_of_v<RepositoryException, DatabaseExecutionException>);
    static_assert(std::is_base_of_v<std::runtime_error, RepositoryException>);

    try {
        throw OptimisticLockException("Concurrent OCC conflict detected");
    } catch (const RepositoryException& ex) {
        EXPECT_STREQ(ex.what(), "Concurrent OCC conflict detected");
    }

    try {
        throw DuplicateEntityException("Duplicate user identifier");
    } catch (const RepositoryException& ex) {
        EXPECT_STREQ(ex.what(), "Duplicate user identifier");
    }

    try {
        throw EntityNotFoundException("User not found");
    } catch (const RepositoryException& ex) {
        EXPECT_STREQ(ex.what(), "User not found");
    }

    try {
        throw InvalidEntityStateException("Device already revoked");
    } catch (const RepositoryException& ex) {
        EXPECT_STREQ(ex.what(), "Device already revoked");
    }
}

// ============================================================================
// 2. Strict Port 5432 Host Isolation Guard
// ============================================================================

TEST(UserDeviceRepositoryTest, RejectsForbiddenPort5432Connection) {
    AuthConfig forbidden_cfg;
    forbidden_cfg.db_host = "127.0.0.1";
    forbidden_cfg.db_port = 5432; // Host PostgreSQL 14 port MUST BE FORBIDDEN
    forbidden_cfg.db_name = "securecloud";
    forbidden_cfg.db_user = "securecloud_app";
    forbidden_cfg.db_password = common::configuration::SecretString{"test"};

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 1;
    pool_cfg.max_connections = 1;

    EXPECT_THROW((db::PostgresConnectionPool(forbidden_cfg, pool_cfg)), db::PortForbiddenException);
}

// ============================================================================
// 3. In-Memory Reference Repository for Interface & Invariant Verification
// ============================================================================

class InMemoryUserRepository : public IUserRepository {
  public:
    void create_user(const UserEntity& user) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, existing] : users_) {
            if (existing.credential_identifier == user.credential_identifier) {
                throw DuplicateEntityException("Credential identifier already registered: " +
                                               user.credential_identifier);
            }
        }
        UserEntity copy = user;
        if (copy.version == 0) {
            copy.version = 1;
        }
        users_[user.user_id] = copy;
    }

    void create_user(const UserEntity& user, pqxx::transaction_base& /*tx*/) override { create_user(user); }

    [[nodiscard]] std::optional<UserEntity> find_by_id(const Uuid& user_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(user_id);
        if (it != users_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<UserEntity> find_by_id(const Uuid& user_id, pqxx::transaction_base& /*tx*/) override {
        return find_by_id(user_id);
    }

    [[nodiscard]] std::optional<UserEntity>
    find_by_credential_identifier(std::string_view credential_identifier) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, user] : users_) {
            if (user.credential_identifier == credential_identifier) {
                return user;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<UserEntity> find_by_credential_identifier(std::string_view credential_identifier,
                                                                          pqxx::transaction_base& /*tx*/) override {
        return find_by_credential_identifier(credential_identifier);
    }

    void update_user(const UserEntity& user) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(user.user_id);
        if (it == users_.end()) {
            throw EntityNotFoundException("User not found: " + user.user_id.to_string());
        }

        if (it->second.version != user.version) {
            throw OptimisticLockException("Concurrent modification detected for user " + user.user_id.to_string());
        }

        for (const auto& [id, existing] : users_) {
            if (id != user.user_id && existing.credential_identifier == user.credential_identifier) {
                throw DuplicateEntityException("Credential identifier already registered: " +
                                               user.credential_identifier);
            }
        }

        it->second = user;
        it->second.version += 1;
    }

    void update_user(const UserEntity& user, pqxx::transaction_base& /*tx*/) override { update_user(user); }

    void set_account_status(const Uuid& user_id, AccountStatus status, uint64_t expected_version) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(user_id);
        if (it == users_.end()) {
            throw EntityNotFoundException("User not found: " + user_id.to_string());
        }

        if (it->second.version != expected_version) {
            throw OptimisticLockException("Concurrent modification detected for user " + user_id.to_string());
        }

        it->second.account_status = status;
        it->second.version += 1;
    }

    void set_account_status(const Uuid& user_id, AccountStatus status, uint64_t expected_version,
                            pqxx::transaction_base& /*tx*/) override {
        set_account_status(user_id, status, expected_version);
    }

  private:
    std::mutex mutex_;
    std::map<Uuid, UserEntity> users_;
};

class InMemoryDeviceRepository : public IDeviceRepository {
  public:
    void register_device(const DeviceEntity& device) override {
        if (device.device_status == DeviceStatus::Revoked) {
            throw InvalidEntityStateException("Cannot register a device with Revoked status: " +
                                              device.device_id.to_string());
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (devices_.find(device.device_id) != devices_.end()) {
            throw DuplicateEntityException("Device already registered: " + device.device_id.to_string());
        }
        devices_[device.device_id] = device;
    }

    void register_device(const DeviceEntity& device, pqxx::transaction_base& /*tx*/) override {
        register_device(device);
    }

    [[nodiscard]] std::optional<DeviceEntity> find_by_id(const Uuid& device_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<DeviceEntity> find_by_id(const Uuid& device_id,
                                                         pqxx::transaction_base& /*tx*/) override {
        return find_by_id(device_id);
    }

    [[nodiscard]] std::vector<DeviceEntity> list_active_by_user_id(const Uuid& user_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceEntity> result;
        for (const auto& [id, dev] : devices_) {
            if (dev.user_id == user_id && dev.device_status == DeviceStatus::Active) {
                result.push_back(dev);
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<DeviceEntity> list_active_by_user_id(const Uuid& user_id,
                                                                   pqxx::transaction_base& /*tx*/) override {
        return list_active_by_user_id(user_id);
    }

    void revoke_device(const Uuid& device_id, std::string_view reason, domain::time_point revoked_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it == devices_.end()) {
            throw EntityNotFoundException("Device not found: " + device_id.to_string());
        }
        it->second.device_status = DeviceStatus::Revoked;
        it->second.revocation_reason = std::string(reason);
        it->second.revoked_at = revoked_at;
    }

    void revoke_device(const Uuid& device_id, std::string_view reason, domain::time_point revoked_at,
                       pqxx::transaction_base& /*tx*/) override {
        revoke_device(device_id, reason, revoked_at);
    }

    void update_last_authenticated(const Uuid& device_id, domain::time_point auth_time) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it == devices_.end()) {
            throw EntityNotFoundException("Device not found: " + device_id.to_string());
        }
        if (it->second.device_status == DeviceStatus::Revoked) {
            throw InvalidEntityStateException("Cannot update authentication on a revoked device: " +
                                              device_id.to_string());
        }
        it->second.last_authenticated_at = auth_time;
    }

    void update_last_authenticated(const Uuid& device_id, domain::time_point auth_time,
                                   pqxx::transaction_base& /*tx*/) override {
        update_last_authenticated(device_id, auth_time);
    }

  private:
    std::mutex mutex_;
    std::map<Uuid, DeviceEntity> devices_;
};

// ============================================================================
// 4. User Repository Functional & OCC Tests
// ============================================================================

TEST(UserDeviceRepositoryTest, UserLifecycleAndOptimisticConcurrency) {
    InMemoryUserRepository user_repo;

    const auto now = std::chrono::system_clock::now();
    UserEntity user{
        .user_id = Uuid::generate_v7(),
        .credential_identifier = "alice@securecloud.local",
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

    // 2. Find By ID
    auto found_by_id = user_repo.find_by_id(user.user_id);
    ASSERT_TRUE(found_by_id.has_value());
    EXPECT_EQ(found_by_id->credential_identifier, "alice@securecloud.local");
    EXPECT_EQ(found_by_id->version, 1);

    // 3. Find By Credential Identifier
    auto found_by_cred = user_repo.find_by_credential_identifier("alice@securecloud.local");
    ASSERT_TRUE(found_by_cred.has_value());
    EXPECT_EQ(found_by_cred->user_id, user.user_id);

    // 4. Duplicate Credential Check
    UserEntity duplicate_user = user;
    duplicate_user.user_id = Uuid::generate_v7();
    EXPECT_THROW(user_repo.create_user(duplicate_user), DuplicateEntityException);

    // 5. Successful OCC Update (version 1 -> version 2)
    UserEntity updated_user = *found_by_id;
    updated_user.credential_identifier = "alice_new@securecloud.local";
    EXPECT_NO_THROW(user_repo.update_user(updated_user));

    auto post_update = user_repo.find_by_id(user.user_id);
    ASSERT_TRUE(post_update.has_value());
    EXPECT_EQ(post_update->credential_identifier, "alice_new@securecloud.local");
    EXPECT_EQ(post_update->version, 2);

    // 6. OCC Stale Version Conflict (attempting to update using version 1 when DB is at 2)
    UserEntity stale_user = updated_user;
    stale_user.version = 1; // Stale version!
    stale_user.credential_identifier = "alice_clobber@securecloud.local";
    EXPECT_THROW(user_repo.update_user(stale_user), OptimisticLockException);

    // 7. Update Non-Existent User
    UserEntity missing_user = user;
    missing_user.user_id = Uuid::generate_v7();
    EXPECT_THROW(user_repo.update_user(missing_user), EntityNotFoundException);

    // 8. Account Status OCC Transition
    EXPECT_NO_THROW(user_repo.set_account_status(user.user_id, AccountStatus::Disabled, 2));

    auto disabled_user = user_repo.find_by_id(user.user_id);
    ASSERT_TRUE(disabled_user.has_value());
    EXPECT_EQ(disabled_user->account_status, AccountStatus::Disabled);
    EXPECT_EQ(disabled_user->version, 3);

    // 9. Stale Status Update Collision
    EXPECT_THROW(user_repo.set_account_status(user.user_id, AccountStatus::Active, 2), OptimisticLockException);
}

// ============================================================================
// 5. Device Repository Lifecycle & Invariants Tests
// ============================================================================

TEST(UserDeviceRepositoryTest, DeviceLifecycleAndRevocationInvariants) {
    InMemoryDeviceRepository device_repo;

    const auto user_id = Uuid::generate_v7();
    const auto now = std::chrono::system_clock::now();

    DeviceEntity device1{
        .device_id = Uuid::generate_v7(),
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };

    DeviceEntity device2{
        .device_id = Uuid::generate_v7(),
        .user_id = user_id,
        .device_status = DeviceStatus::Active,
        .registered_at = now,
        .revoked_at = std::nullopt,
        .revocation_reason = std::nullopt,
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };

    // 1. Invariant: Cannot register device with Revoked status
    DeviceEntity invalid_device = device1;
    invalid_device.device_id = Uuid::generate_v7();
    invalid_device.device_status = DeviceStatus::Revoked;
    EXPECT_THROW(device_repo.register_device(invalid_device), InvalidEntityStateException);

    // 2. Register devices
    EXPECT_NO_THROW(device_repo.register_device(device1));
    EXPECT_NO_THROW(device_repo.register_device(device2));

    // 3. List active devices by user
    auto active_devices = device_repo.list_active_by_user_id(user_id);
    EXPECT_EQ(active_devices.size(), 2);

    // 4. Update last authenticated time
    const auto auth_time = now + std::chrono::minutes(5);
    EXPECT_NO_THROW(device_repo.update_last_authenticated(device1.device_id, auth_time));

    auto dev1_after_auth = device_repo.find_by_id(device1.device_id);
    ASSERT_TRUE(dev1_after_auth.has_value());
    EXPECT_EQ(dev1_after_auth->last_authenticated_at, auth_time);

    // 5. Revoke Device 1
    const auto revoke_time = now + std::chrono::hours(1);
    EXPECT_NO_THROW(device_repo.revoke_device(device1.device_id, "Device compromised", revoke_time));

    auto dev1_after_revoke = device_repo.find_by_id(device1.device_id);
    ASSERT_TRUE(dev1_after_revoke.has_value());
    EXPECT_EQ(dev1_after_revoke->device_status, DeviceStatus::Revoked);
    EXPECT_EQ(dev1_after_revoke->revocation_reason, "Device compromised");
    EXPECT_EQ(dev1_after_revoke->revoked_at, revoke_time);

    // 6. Active listing excludes revoked devices
    active_devices = device_repo.list_active_by_user_id(user_id);
    ASSERT_EQ(active_devices.size(), 1);
    EXPECT_EQ(active_devices[0].device_id, device2.device_id);

    // 7. Invariant: Cannot update authentication on a revoked device
    EXPECT_THROW(device_repo.update_last_authenticated(device1.device_id, auth_time), InvalidEntityStateException);

    // 8. Revoking unknown device throws EntityNotFoundException
    EXPECT_THROW(device_repo.revoke_device(Uuid::generate_v7(), "lost", revoke_time), EntityNotFoundException);
}

// ============================================================================
// 6. Postgres Repositories Invariant & Security Guard Tests
// ============================================================================

TEST(UserDeviceRepositoryTest, PostgresDeviceRepositoryRejectsRevokedRegistrationDirectly) {
    AuthConfig auth_cfg;
    auth_cfg.db_host = "127.0.0.1";
    auth_cfg.db_port = 5433; // Allowed test port
    auth_cfg.db_name = "securecloud";
    auth_cfg.db_user = "securecloud_app";
    auth_cfg.db_password = common::configuration::SecretString{"dummy"};

    db::ConnectionPoolConfig pool_cfg;
    pool_cfg.min_connections = 0;
    pool_cfg.max_connections = 1;

    db::PostgresConnectionPool pool(auth_cfg, pool_cfg);
    PostgresDeviceRepository device_repo(pool);

    const auto now = std::chrono::system_clock::now();
    DeviceEntity revoked_device{
        .device_id = Uuid::generate_v7(),
        .user_id = Uuid::generate_v7(),
        .device_status = DeviceStatus::Revoked,
        .registered_at = now,
        .revoked_at = now,
        .revocation_reason = "revoked on creation",
        .last_authenticated_at = now,
        .created_at = now,
        .updated_at = now,
    };

    // Must be rejected by invariant validation prior to attempting database I/O
    EXPECT_THROW(device_repo.register_device(revoked_device), InvalidEntityStateException);
}

// ============================================================================
// 7. Multi-Threaded Concurrent OCC Race Simulation Test
// ============================================================================

TEST(UserDeviceRepositoryTest, ConcurrentOccCollisionSimulation) {
    InMemoryUserRepository user_repo;

    const auto now = std::chrono::system_clock::now();
    const auto user_id = Uuid::generate_v7();
    UserEntity initial_user{
        .user_id = user_id,
        .credential_identifier = "race_user@securecloud.local",
        .password_verifier = "initial_hash",
        .password_algorithm = "argon2id",
        .password_updated_at = now,
        .account_status = AccountStatus::Active,
        .created_at = now,
        .updated_at = now,
        .version = 1,
    };
    user_repo.create_user(initial_user);

    constexpr int kNumConcurrentThreads = 8;
    std::atomic<int> success_count{0};
    std::atomic<int> occ_conflict_count{0};
    std::vector<std::thread> workers;
    workers.reserve(kNumConcurrentThreads);

    // Barrier / synchronization flag to ensure all threads strike at the exact same instant
    std::atomic<bool> start_race{false};

    for (int i = 0; i < kNumConcurrentThreads; ++i) {
        workers.emplace_back([&, i]() {
            while (!start_race.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }

            UserEntity thread_update = initial_user; // All threads start with stale version 1!
            thread_update.credential_identifier = "race_user_" + std::to_string(i) + "@securecloud.local";

            try {
                user_repo.update_user(thread_update);
                success_count.fetch_add(1, std::memory_order_relaxed);
            } catch (const OptimisticLockException&) {
                occ_conflict_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    start_race.store(true, std::memory_order_release);

    for (auto& t : workers) {
        t.join();
    }

    // Exactly one thread wins the race and commits; all others encounter OCC collision!
    EXPECT_EQ(success_count.load(), 1);
    EXPECT_EQ(occ_conflict_count.load(), kNumConcurrentThreads - 1);

    auto final_user = user_repo.find_by_id(user_id);
    ASSERT_TRUE(final_user.has_value());
    EXPECT_EQ(final_user->version, 2);
}

} // namespace
} // namespace securecloud::auth::repository::test
