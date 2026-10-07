#include "auth/domain/audit_event.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/session_result.hpp"
#include "auth/domain/timestamp.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/repository/session_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/session_manager.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::Field;
using ::testing::NiceMock;
using ::testing::Return;

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

class MockAuditSink : public IAuditEventSink {
  public:
    void emit(const domain::AuditEvent& event, std::string_view json_payload) override {
        emit_str(event, std::string(json_payload));
    }
    MOCK_METHOD(void, emit_str, (const domain::AuditEvent& event, const std::string& json_payload));
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

// Test 1: SessionRevoked event serializes with exact hierarchical type and non-null fields
TEST(SessionAuditTest, AuditEvent_SessionRevoked_SerializationFidelity) {
    auto session_id = domain::Uuid::generate_v7();
    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();

    auto ev = domain::AuditEvent::session_revoked(session_id, user_id, device_id, "User logout", "192.168.1.10");

    EXPECT_EQ(domain::to_string(ev.event_type), "auth.session.revoked");
    EXPECT_EQ(ev.event_type, domain::AuditEventType::SessionRevoked);

    auto json = nlohmann::json::parse(ev.to_json());
    EXPECT_EQ(json["event_type"], "auth.session.revoked");
    EXPECT_EQ(json["session_id"], session_id.to_string());
    EXPECT_EQ(json["user_id"], user_id.to_string());
    EXPECT_EQ(json["device_id"], device_id.to_string());
    EXPECT_EQ(json["failure_reason"], "User logout");
    EXPECT_EQ(json["client_ip"], "192.168.1.10");
}

// Test 2: SessionExpiredAttempt event serializes with exact type and session ID
TEST(SessionAuditTest, AuditEvent_SessionExpiredAttempt_SerializationFidelity) {
    auto session_id = domain::Uuid::generate_v7();
    auto ev = domain::AuditEvent::session_expired_attempt(session_id, "10.0.0.5");

    EXPECT_EQ(domain::to_string(ev.event_type), "auth.session.expired_attempt");
    EXPECT_EQ(ev.event_type, domain::AuditEventType::SessionExpiredAttempt);

    auto json = nlohmann::json::parse(ev.to_json());
    EXPECT_EQ(json["event_type"], "auth.session.expired_attempt");
    EXPECT_EQ(json["session_id"], session_id.to_string());
    EXPECT_EQ(json["failure_reason"], "Session expired");
    EXPECT_EQ(json["client_ip"], "10.0.0.5");
    EXPECT_TRUE(json["user_id"].is_null());
}

// Test 3: SessionRevokedAttempt event serializes with exact type and session ID
TEST(SessionAuditTest, AuditEvent_SessionRevokedAttempt_SerializationFidelity) {
    auto session_id = domain::Uuid::generate_v7();
    auto ev = domain::AuditEvent::session_revoked_attempt(session_id, "172.16.0.2");

    EXPECT_EQ(domain::to_string(ev.event_type), "auth.session.revoked_attempt");
    EXPECT_EQ(ev.event_type, domain::AuditEventType::SessionRevokedAttempt);

    auto json = nlohmann::json::parse(ev.to_json());
    EXPECT_EQ(json["event_type"], "auth.session.revoked_attempt");
    EXPECT_EQ(json["session_id"], session_id.to_string());
    EXPECT_EQ(json["failure_reason"], "Session revoked");
    EXPECT_EQ(json["client_ip"], "172.16.0.2");
}

// Test 4: Invariant verification: JSON payloads never leak sensitive credential keywords
TEST(SessionAuditTest, AuditEvent_ZeroSensitiveDataLeakage_Invariant) {
    auto session_id = domain::Uuid::generate_v7();
    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();

    auto ev1 = domain::AuditEvent::session_revoked(session_id, user_id, device_id, "Logout");
    auto ev2 = domain::AuditEvent::session_expired_attempt(session_id);
    auto ev3 = domain::AuditEvent::session_revoked_attempt(session_id);

    std::vector<std::string> payloads = {ev1.to_json(), ev2.to_json(), ev3.to_json()};

    for (const auto& payload : payloads) {
        EXPECT_EQ(payload.find("password"), std::string::npos);
        EXPECT_EQ(payload.find("token_verifier"), std::string::npos);
        EXPECT_EQ(payload.find("secret"), std::string::npos);
        EXPECT_EQ(payload.find("private_key"), std::string::npos);
    }
}

// Test 5: Revoking active session emits SessionRevoked audit telemetry
TEST(SessionAuditTest, SessionManager_RevokeSession_EmitsSessionRevokedAudit) {
    auto session_repo = std::make_shared<NiceMock<MockSessionRepository>>();
    auto device_repo = std::make_shared<NiceMock<MockDeviceRepository>>();
    auto audit_publisher = std::make_shared<MockAuditEventPublisher>();
    SessionManager manager(session_repo, device_repo, std::chrono::hours(24), audit_publisher);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Active);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));
    EXPECT_CALL(*session_repo, revoke_session_atomic(session.session_id, _)).WillOnce(Return(true));

    EXPECT_CALL(*audit_publisher,
                publish(Field(&domain::AuditEvent::event_type, domain::AuditEventType::SessionRevoked)))
        .Times(1);

    auto result = manager.revoke_session(session.session_id, "Security termination");
    EXPECT_TRUE(result.is_success());
}

// Test 6: Validating an expired session emits SessionExpiredAttempt audit telemetry
TEST(SessionAuditTest, SessionManager_ValidateExpiredSession_EmitsExpiredAttemptAudit) {
    auto session_repo = std::make_shared<NiceMock<MockSessionRepository>>();
    auto device_repo = std::make_shared<NiceMock<MockDeviceRepository>>();
    auto audit_publisher = std::make_shared<MockAuditEventPublisher>();
    SessionManager manager(session_repo, device_repo, std::chrono::hours(24), audit_publisher);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Expired);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));

    EXPECT_CALL(*audit_publisher,
                publish(Field(&domain::AuditEvent::event_type, domain::AuditEventType::SessionExpiredAttempt)))
        .Times(1);

    auto result = manager.validate_session(session.session_id);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::Expired);
}

// Test 7: Validating a revoked session emits SessionRevokedAttempt audit telemetry
TEST(SessionAuditTest, SessionManager_ValidateRevokedSession_EmitsRevokedAttemptAudit) {
    auto session_repo = std::make_shared<NiceMock<MockSessionRepository>>();
    auto device_repo = std::make_shared<NiceMock<MockDeviceRepository>>();
    auto audit_publisher = std::make_shared<MockAuditEventPublisher>();
    SessionManager manager(session_repo, device_repo, std::chrono::hours(24), audit_publisher);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Revoked);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillOnce(Return(session));

    EXPECT_CALL(*audit_publisher,
                publish(Field(&domain::AuditEvent::event_type, domain::AuditEventType::SessionRevokedAttempt)))
        .Times(1);

    auto result = manager.validate_session(session.session_id);
    EXPECT_FALSE(result.is_valid());
    EXPECT_EQ(result.status, domain::SessionValidationStatus::Revoked);
}

// Test 8: SessionManager operates smoothly without crash when audit publisher is null
TEST(SessionAuditTest, SessionManager_NullAuditPublisher_OperatesWithoutCrash) {
    auto session_repo = std::make_shared<NiceMock<MockSessionRepository>>();
    auto device_repo = std::make_shared<NiceMock<MockDeviceRepository>>();
    SessionManager manager(session_repo, device_repo, std::chrono::hours(24), nullptr);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session = create_test_session(user_id, device_id, domain::SessionStatus::Revoked);

    EXPECT_CALL(*session_repo, find_by_id(session.session_id)).WillRepeatedly(Return(session));

    EXPECT_NO_THROW({
        auto val_res = manager.validate_session(session.session_id);
        EXPECT_FALSE(val_res.is_valid());
        auto rev_res = manager.revoke_session(session.session_id);
        EXPECT_FALSE(rev_res.is_success());
    });
}

// Test 9: Downstream sink exception is absorbed by AuditEventPublisher without bubbling
TEST(SessionAuditTest, AuditEventPublisher_SinkException_NonBlockingNoexcept) {
    auto mock_sink = std::make_shared<MockAuditSink>();
    EXPECT_CALL(*mock_sink, emit_str(_, _)).WillOnce([](const domain::AuditEvent&, const std::string&) {
        throw std::runtime_error("Disk I/O error writing audit log");
    });

    AuditEventPublisher publisher(mock_sink);

    auto ev = domain::AuditEvent::session_revoked_attempt(domain::Uuid::generate_v7());

    EXPECT_NO_THROW({ publisher.publish(ev); });
}

// Test 10: Bulk device session revocation works properly in SessionManager with publisher
TEST(SessionAuditTest, SessionManager_BulkDeviceRevocation_OperatesCorrectlyWithPublisher) {
    auto session_repo = std::make_shared<NiceMock<MockSessionRepository>>();
    auto device_repo = std::make_shared<NiceMock<MockDeviceRepository>>();
    auto audit_publisher = std::make_shared<MockAuditEventPublisher>();
    SessionManager manager(session_repo, device_repo, std::chrono::hours(24), audit_publisher);

    auto device_id = domain::Uuid::generate_v7();
    EXPECT_CALL(*session_repo, revoke_all_device_sessions_atomic(device_id, _)).WillOnce(Return(2));

    auto result = manager.revoke_all_device_sessions(device_id, "Device decommissioned");
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.revoked_count, 2);
}

} // namespace
} // namespace securecloud::auth::service::test
