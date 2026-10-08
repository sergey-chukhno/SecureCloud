#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/session_result.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/service/session_manager.hpp"

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

domain::SessionEntity create_test_session(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                          domain::SessionStatus status = domain::SessionStatus::Active,
                                          std::chrono::seconds ttl = std::chrono::hours(24)) {
    auto now = std::chrono::system_clock::now();
    domain::SessionEntity session;
    session.session_id = domain::Uuid::generate_v7();
    session.user_id = user_id;
    session.device_id = device_id;
    session.authentication_level = domain::AuthenticationLevel::PrimaryOnly;
    session.session_status = status;
    session.created_at = now - std::chrono::minutes(5);
    session.last_used_at = now - std::chrono::minutes(1);
    session.expires_at = now + ttl;
    return session;
}

domain::DeviceEntity create_test_device(const domain::Uuid& user_id,
                                        domain::DeviceStatus status = domain::DeviceStatus::Active) {
    auto now = std::chrono::system_clock::now();
    domain::DeviceEntity dev;
    dev.device_id = domain::Uuid::generate_v7();
    dev.user_id = user_id;
    dev.device_status = status;
    dev.registered_at = now - std::chrono::hours(1);
    dev.last_authenticated_at = now - std::chrono::minutes(5);
    dev.created_at = now - std::chrono::hours(1);
    dev.updated_at = now - std::chrono::minutes(5);
    return dev;
}

// Test 1: Valid active session returns Valid status and touches session activity
TEST(SessionValidationTest, ValidateSession_ValidActiveSession_ReturnsValidAndTouchesActivity) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device = create_test_device(user_id, domain::DeviceStatus::Active);
    auto session = create_test_session(user_id, device.device_id, domain::SessionStatus::Active);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, touch_session_activity(session.session_id, _)).WillOnce(Return(true));

    auto result = manager.validate_session(session.session_id, device.device_id);

    EXPECT_TRUE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::Valid);
    ASSERT_TRUE(result.session.has_value());
    EXPECT_EQ(result.session->session_id, session.session_id);
    EXPECT_EQ(result.session->device_id, device.device_id);
}

// Test 2: Non-existent session returns NotFound
TEST(SessionValidationTest, ValidateSession_NonExistentSession_ReturnsNotFound) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto non_existent_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, find_by_id(non_existent_id)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*session_repo, touch_session_activity(_, _)).Times(0);

    auto result = manager.validate_session(non_existent_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::NotFound);
    EXPECT_FALSE(result.session.has_value());
}

// Test 3: Revoked session returns Revoked and does not touch activity
TEST(SessionValidationTest, ValidateSession_RevokedSession_ReturnsRevoked) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Revoked);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, touch_session_activity(_, _)).Times(0);

    auto result = manager.validate_session(session.session_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::Revoked);
}

// Test 4: Session with status Expired returns Expired
TEST(SessionValidationTest, ValidateSession_StatusExpired_ReturnsExpired) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Expired);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, touch_session_activity(_, _)).Times(0);

    auto result = manager.validate_session(session.session_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::Expired);
}

// Test 5: Session with status Active but expired wall-clock time returns Expired
TEST(SessionValidationTest, ValidateSession_ClockExceededExpiry_ReturnsExpired) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    // Negative TTL means expired in the past
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Active, std::chrono::seconds(-60));

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, touch_session_activity(_, _)).Times(0);

    auto result = manager.validate_session(session.session_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::Expired);
}

// Test 6: Claimed device mismatch returns DeviceMismatch
TEST(SessionValidationTest, ValidateSession_ClaimedDeviceMismatch_ReturnsDeviceMismatch) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto actual_device_id = domain::Uuid::generate_v7();
    auto claimed_device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, actual_device_id, domain::SessionStatus::Active);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, touch_session_activity(_, _)).Times(0);

    auto result = manager.validate_session(session.session_id, claimed_device_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::DeviceMismatch);
}

// Test 7: Bound physical device not found in repository returns DeviceMismatch
TEST(SessionValidationTest, ValidateSession_BoundDeviceMissing_ReturnsDeviceMismatch) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Active);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*device_repo, find_by_id(device_id)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*session_repo, touch_session_activity(_, _)).Times(0);

    auto result = manager.validate_session(session.session_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::DeviceMismatch);
}

// Test 8: Bound physical device is Revoked returns DeviceRevoked
TEST(SessionValidationTest, ValidateSession_BoundDeviceRevoked_ReturnsDeviceRevoked) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device = create_test_device(user_id, domain::DeviceStatus::Revoked);
    auto session = create_test_session(user_id, device.device_id, domain::SessionStatus::Active);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*device_repo, find_by_id(device.device_id)).WillOnce(Return(device));
    EXPECT_CALL(*session_repo, touch_session_activity(_, _)).Times(0);

    auto result = manager.validate_session(session.session_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::DeviceRevoked);
}

// Test 9: Repository database exception fails closed with InternalError
TEST(SessionValidationTest, ValidateSession_DatabaseError_FailsClosedWithInternalError) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto session_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, find_by_id(session_id))
        .WillOnce(Throw(repository::DatabaseExecutionException("Connection terminated unexpectedly")));

    auto result = manager.validate_session(session_id);

    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::InternalError);
}

// Test 10: List active sessions for user and device delegates properly
TEST(SessionValidationTest, ListActiveSessions_UserAndDevice_DelegatesProperly) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Active);

    std::vector<domain::SessionEntity> expected_sessions{session};

    EXPECT_CALL(*session_repo, list_active_by_user_id(user_id)).WillOnce(Return(expected_sessions));
    EXPECT_CALL(*session_repo, list_active_by_device_id(device_id)).WillOnce(Return(expected_sessions));

    auto user_sessions = manager.list_active_sessions_for_user(user_id);
    EXPECT_EQ(user_sessions.size(), 1);
    EXPECT_EQ(user_sessions.front().session_id, session.session_id);

    auto device_sessions = manager.list_active_sessions_for_device(device_id);
    EXPECT_EQ(device_sessions.size(), 1);
    EXPECT_EQ(device_sessions.front().session_id, session.session_id);
}

} // namespace
} // namespace securecloud::auth::service::test
