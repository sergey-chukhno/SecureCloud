#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/session_result.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/exceptions.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/service/session_manager.hpp"

#include <atomic>
#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
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
                                          domain::SessionStatus status = domain::SessionStatus::Active) {
    auto now = std::chrono::system_clock::now();
    domain::SessionEntity session;
    session.session_id = domain::Uuid::generate_v7();
    session.user_id = user_id;
    session.device_id = device_id;
    session.authentication_level = domain::AuthenticationLevel::PrimaryOnly;
    session.session_status = status;
    session.created_at = now - std::chrono::minutes(5);
    session.last_used_at = now - std::chrono::minutes(1);
    session.expires_at = now + std::chrono::hours(24);
    return session;
}

// Test 1: Revoking an active session succeeds and returns count 1
TEST(SessionRevocationTest, RevokeSession_ActiveSession_SucceedsAndReturnsCount1) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Active);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, revoke_session_atomic(session.session_id, _)).WillOnce(Return(true));

    auto result = manager.revoke_session(session.session_id, "User logged out");

    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::Success);
    EXPECT_EQ(result.revoked_count, 1);
}

// Test 2: Revoking a non-existent session returns NotFound
TEST(SessionRevocationTest, RevokeSession_NonExistentSession_ReturnsNotFound) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto non_existent_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, find_by_id(non_existent_id)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*session_repo, revoke_session_atomic(_, _)).Times(0);

    auto result = manager.revoke_session(non_existent_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::NotFound);
    EXPECT_EQ(result.revoked_count, 0);
}

// Test 3: Revoking an already revoked session returns AlreadyRevoked
TEST(SessionRevocationTest, RevokeSession_AlreadyRevokedSession_ReturnsAlreadyRevoked) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Revoked);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, revoke_session_atomic(_, _)).Times(0);

    auto result = manager.revoke_session(session.session_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::AlreadyRevoked);
    EXPECT_EQ(result.revoked_count, 0);
}

// Test 4: Revoking an expired session returns AlreadyRevoked
TEST(SessionRevocationTest, RevokeSession_ExpiredSession_ReturnsAlreadyRevoked) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Expired);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, revoke_session_atomic(_, _)).Times(0);

    auto result = manager.revoke_session(session.session_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::AlreadyRevoked);
    EXPECT_EQ(result.revoked_count, 0);
}

// Test 5: Revoking session where concurrent atomic update returns false returns AlreadyRevoked
TEST(SessionRevocationTest, RevokeSession_ConcurrentAtomicFails_ReturnsAlreadyRevoked) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Active);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, revoke_session_atomic(session.session_id, _)).WillOnce(Return(false));

    auto result = manager.revoke_session(session.session_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::AlreadyRevoked);
}

// Test 6: Database exception during session revocation fails closed with InternalError
TEST(SessionRevocationTest, RevokeSession_DatabaseError_FailsClosedWithInternalError) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto session_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, find_by_id(session_id))
        .WillOnce(Throw(repository::DatabaseExecutionException("PostgreSQL connection down")));

    auto result = manager.revoke_session(session_id);

    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::InternalError);
}

// Test 7: Bulk device session revocation revokes all device sessions and returns count
TEST(SessionRevocationTest, RevokeAllDeviceSessions_ActiveSessions_RevokesAllAndReturnsCount) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, revoke_all_device_sessions_atomic(device_id, _)).WillOnce(Return(3));

    auto result = manager.revoke_all_device_sessions(device_id, "Device stolen");

    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::Success);
    EXPECT_EQ(result.revoked_count, 3);
}

// Test 8: Bulk device session revocation with zero active sessions returns success count 0
TEST(SessionRevocationTest, RevokeAllDeviceSessions_NoActiveSessions_ReturnsSuccessZeroCount) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, revoke_all_device_sessions_atomic(device_id, _)).WillOnce(Return(0));

    auto result = manager.revoke_all_device_sessions(device_id);

    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::Success);
    EXPECT_EQ(result.revoked_count, 0);
}

// Test 9: Bulk user session revocation revokes all user sessions and returns count
TEST(SessionRevocationTest, RevokeAllUserSessions_ActiveSessions_RevokesAllAndReturnsCount) {
    auto session_repo = std::make_shared<MockSessionRepository>();
    auto device_repo = std::make_shared<MockDeviceRepository>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, revoke_all_user_sessions_atomic(user_id, _)).WillOnce(Return(5));

    auto result = manager.revoke_all_user_sessions(user_id, "Global account security lockdown");

    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.status, domain::SessionRevocationStatus::Success);
    EXPECT_EQ(result.revoked_count, 5);
}

// Test 10: Multi-threaded race simulation ensuring concurrent revocation and validation resolve deterministically
TEST(SessionRevocationTest, ConcurrentRevokeAndValidate_DeterministicOutcome) {
    auto session_repo = std::make_shared<testing::NiceMock<MockSessionRepository>>();
    auto device_repo = std::make_shared<testing::NiceMock<MockDeviceRepository>>();
    SessionManager manager(session_repo, device_repo);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Active);

    // Shared thread-safe session state simulation
    std::mutex state_mutex;
    domain::SessionStatus current_status = domain::SessionStatus::Active;

    ON_CALL(*session_repo, find_by_id(session.session_id)).WillByDefault([&](const domain::Uuid&) {
        std::lock_guard<std::mutex> lock(state_mutex);
        auto s = session;
        s.session_status = current_status;
        return std::optional<domain::SessionEntity>(s);
    });

    ON_CALL(*session_repo, revoke_session_atomic(session.session_id, _))
        .WillByDefault([&](const domain::Uuid&, domain::time_point) {
            std::lock_guard<std::mutex> lock(state_mutex);
            if (current_status == domain::SessionStatus::Active) {
                current_status = domain::SessionStatus::Revoked;
                return true;
            }
            return false;
        });

    domain::DeviceEntity dev;
    dev.device_id = device_id;
    dev.user_id = user_id;
    dev.device_status = domain::DeviceStatus::Active;
    ON_CALL(*device_repo, find_by_id(device_id)).WillByDefault(Return(dev));
    ON_CALL(*session_repo, touch_session_activity(session.session_id, _)).WillByDefault(Return(true));

    std::atomic<bool> revoke_done{false};
    domain::SessionRevocationResult revoke_result;
    domain::SessionValidationResult validate_result;

    std::thread revoke_thread([&]() {
        revoke_result = manager.revoke_session(session.session_id, "Concurrent test revocation");
        revoke_done = true;
    });

    std::thread validate_thread([&]() {
        // Repeated validations until revocation completes
        while (!revoke_done.load()) {
            std::this_thread::yield();
        }
        // Final post-revocation validation MUST deterministically fail
        validate_result = manager.validate_session(session.session_id, device_id);
    });

    revoke_thread.join();
    validate_thread.join();

    EXPECT_TRUE(revoke_result.is_success());
    EXPECT_EQ(revoke_result.status, domain::SessionRevocationStatus::Success);

    // Post-revocation validation MUST be rejected as Revoked
    EXPECT_FALSE(validate_result.is_valid());
    EXPECT_EQ(validate_result.status, domain::SessionValidationStatus::Revoked);
}

} // namespace
} // namespace securecloud::auth::service::test
