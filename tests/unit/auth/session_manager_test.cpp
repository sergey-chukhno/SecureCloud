#include "domain/entities.hpp"
#include "domain/enums.hpp"
#include "domain/timestamp.hpp"
#include "domain/uuid.hpp"
#include "repository/device_repository.hpp"
#include "repository/exceptions.hpp"
#include "repository/session_repository.hpp"
#include "service/session_manager.hpp"

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
using ::testing::Throw;

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

    MOCK_METHOD(void, revoke_device,
                (const domain::Uuid& device_id, std::string_view reason, domain::time_point revoked_at), (override));
    MOCK_METHOD(void, revoke_device,
                (const domain::Uuid& device_id, std::string_view reason, domain::time_point revoked_at,
                 pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(void, update_last_authenticated, (const domain::Uuid& device_id, domain::time_point auth_time),
                (override));
    MOCK_METHOD(void, update_last_authenticated,
                (const domain::Uuid& device_id, domain::time_point auth_time, pqxx::transaction_base& tx), (override));
};

domain::UserEntity create_test_user() {
    domain::UserEntity user;
    user.user_id = domain::Uuid::generate_v7();
    user.credential_identifier = "user@securecloud.io";
    user.password_verifier = "verifier";
    user.account_status = domain::AccountStatus::Active;
    user.created_at = std::chrono::system_clock::now();
    user.updated_at = std::chrono::system_clock::now();
    user.version = 1;
    return user;
}

domain::DeviceEntity create_test_device(const domain::Uuid& user_id,
                                        domain::DeviceStatus status = domain::DeviceStatus::Active) {
    domain::DeviceEntity dev;
    dev.device_id = domain::Uuid::generate_v7();
    dev.user_id = user_id;
    dev.device_status = status;
    dev.registered_at = std::chrono::system_clock::now();
    dev.last_authenticated_at = std::chrono::system_clock::now();
    dev.created_at = std::chrono::system_clock::now();
    dev.updated_at = std::chrono::system_clock::now();
    return dev;
}

// Test 1: Valid active device produces active session with PrimaryOnly assurance level
TEST(SessionManagerTest, EstablishSession_ValidActiveDevice_SucceedsWithPrimaryOnlyLevel) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo, std::chrono::hours(24));

    auto user = create_test_user();
    auto device = create_test_device(user.user_id, domain::DeviceStatus::Active);

    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, create_session(_)).Times(1);
    EXPECT_CALL(*device_repo, update_last_authenticated(device.device_id, _)).Times(1);

    auto result = manager.establish_session(user, device.device_id);

    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::Success);
    ASSERT_TRUE(result.session.has_value());
    EXPECT_EQ(result.session->user_id, user.user_id);
    EXPECT_EQ(result.session->device_id, device.device_id);
    EXPECT_EQ(result.session->session_status, domain::SessionStatus::Active);
    EXPECT_EQ(result.session->authentication_level, domain::AuthenticationLevel::PrimaryOnly);

    // Verify session lifetime ~24 hours
    auto duration =
        std::chrono::duration_cast<std::chrono::hours>(result.session->expires_at - result.session->created_at);
    EXPECT_EQ(duration.count(), 24);

    ASSERT_TRUE(result.device.has_value());
    EXPECT_EQ(result.device->device_id, device.device_id);
}

// Test 2: Non-existent device returns DeviceNotFound
TEST(SessionManagerTest, EstablishSession_NonExistentDevice_ReturnsDeviceNotFound) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user = create_test_user();
    auto missing_device_id = domain::Uuid::generate_v7();

    EXPECT_CALL(*device_repo, find_by_id(missing_device_id)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*session_repo, create_session(_)).Times(0);
    EXPECT_CALL(*device_repo, update_last_authenticated(_, _)).Times(0);

    auto result = manager.establish_session(user, missing_device_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::DeviceNotFound);
    EXPECT_FALSE(result.session.has_value());
}

// Test 3: Device belonging to another user returns DeviceNotFound (hijacking defense)
TEST(SessionManagerTest, EstablishSession_ForeignDevice_ReturnsDeviceNotFound) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user1 = create_test_user();
    auto user2 = create_test_user(); // Different user
    auto device_of_user2 = create_test_device(user2.user_id, domain::DeviceStatus::Active);

    EXPECT_CALL(*device_repo, find_by_id(device_of_user2.device_id)).WillOnce(Return(device_of_user2));
    EXPECT_CALL(*session_repo, create_session(_)).Times(0);
    EXPECT_CALL(*device_repo, update_last_authenticated(_, _)).Times(0);

    // user1 tries to authenticate against user2's device
    auto result = manager.establish_session(user1, device_of_user2.device_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::DeviceNotFound);
    EXPECT_FALSE(result.session.has_value());
}

// Test 4: Revoked device returns DeviceRevoked
TEST(SessionManagerTest, EstablishSession_RevokedDevice_ReturnsDeviceRevoked) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user = create_test_user();
    auto device = create_test_device(user.user_id, domain::DeviceStatus::Revoked);

    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, create_session(_)).Times(0);
    EXPECT_CALL(*device_repo, update_last_authenticated(_, _)).Times(0);

    auto result = manager.establish_session(user, device.device_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::DeviceRevoked);
    EXPECT_FALSE(result.session.has_value());
}

// Test 5: Revoked device with reason returns DeviceRevoked
TEST(SessionManagerTest, EstablishSession_RevokedDeviceWithReason_ReturnsDeviceRevoked) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user = create_test_user();
    auto device = create_test_device(user.user_id, domain::DeviceStatus::Revoked);
    device.revocation_reason = "Device reported lost or stolen";

    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, create_session(_)).Times(0);
    EXPECT_CALL(*device_repo, update_last_authenticated(_, _)).Times(0);

    auto result = manager.establish_session(user, device.device_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::DeviceRevoked);
}

// Test 6: Database failure on session creation returns InternalError
TEST(SessionManagerTest, EstablishSession_SessionRepoCreateThrows_ReturnsInternalError) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user = create_test_user();
    auto device = create_test_device(user.user_id, domain::DeviceStatus::Active);

    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, create_session(_)).WillOnce(Throw(repository::DatabaseExecutionException("Disk full")));

    auto result = manager.establish_session(user, device.device_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::InternalError);
}

// Test 7: Database failure on device lookup returns InternalError
TEST(SessionManagerTest, EstablishSession_DeviceRepoFindThrows_ReturnsInternalError) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user = create_test_user();
    auto device_id = domain::Uuid::generate_v7();

    EXPECT_CALL(*device_repo, find_by_id(device_id))
        .WillOnce(Throw(repository::DatabaseExecutionException("Connection dropped")));

    auto result = manager.establish_session(user, device_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::InternalError);
}

// Test 8: Database failure on updating device timestamp returns InternalError
TEST(SessionManagerTest, EstablishSession_DeviceRepoUpdateThrows_ReturnsInternalError) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user = create_test_user();
    auto device = create_test_device(user.user_id, domain::DeviceStatus::Active);

    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, create_session(_)).Times(1);
    EXPECT_CALL(*device_repo, update_last_authenticated(device.device_id, _))
        .WillOnce(Throw(repository::DatabaseExecutionException("Deadlock")));

    auto result = manager.establish_session(user, device.device_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, SessionEstablishmentStatus::InternalError);
}

// Test 9: Custom TTL applies configured duration
TEST(SessionManagerTest, EstablishSession_CustomTtl_AppliesCustomDuration) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo, std::chrono::hours(2));

    auto user = create_test_user();
    auto device = create_test_device(user.user_id, domain::DeviceStatus::Active);

    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, create_session(_)).Times(1);
    EXPECT_CALL(*device_repo, update_last_authenticated(device.device_id, _)).Times(1);

    auto result = manager.establish_session(user, device.device_id);

    ASSERT_TRUE(result.is_success());
    auto duration =
        std::chrono::duration_cast<std::chrono::hours>(result.session->expires_at - result.session->created_at);
    EXPECT_EQ(duration.count(), 2);
}

// Test 10: Constructor throws on null arguments or non-positive TTL
TEST(SessionManagerTest, Constructor_ValidationRules_Enforced) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();

    EXPECT_THROW(SessionManager(nullptr, device_repo), std::invalid_argument);
    EXPECT_THROW(SessionManager(session_repo, nullptr), std::invalid_argument);
    EXPECT_THROW(SessionManager(session_repo, device_repo, std::chrono::seconds(0)), std::invalid_argument);
    EXPECT_THROW(SessionManager(session_repo, device_repo, std::chrono::seconds(-10)), std::invalid_argument);
}

} // namespace
} // namespace securecloud::auth::service::test
