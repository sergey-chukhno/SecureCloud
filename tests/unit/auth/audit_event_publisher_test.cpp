#include "domain/audit_event.hpp"
#include "domain/auth_outbox_entity.hpp"
#include "domain/uuid.hpp"
#include "repository/auth_outbox_repository.hpp"
#include "service/audit_event_publisher.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::Throw;

class MockAuditEventSink : public IAuditEventSink {
  public:
    void emit(const domain::AuditEvent& event, std::string_view json_payload) override {
        emit_str(event, std::string(json_payload));
    }

    MOCK_METHOD(void, emit_str, (const domain::AuditEvent& event, const std::string& json_payload));
};

class MockAuthOutboxRepository : public repository::IAuthOutboxRepository {
  public:
    MOCK_METHOD(void, stage_event, (const domain::AuthOutboxEntity& event, pqxx::transaction_base& tx), (override));
    MOCK_METHOD(void, stage_event, (const domain::AuthOutboxEntity& event), (override));
    MOCK_METHOD(std::vector<domain::AuthOutboxEntity>, fetch_and_lease_pending_batch,
                (std::size_t limit, std::chrono::seconds lease_duration), (override));
    MOCK_METHOD(bool, mark_published, (const domain::Uuid& event_id), (override));
    MOCK_METHOD(bool, mark_failed, (const domain::Uuid& event_id, std::string_view error), (override));
    MOCK_METHOD(bool, mark_quarantined, (const domain::Uuid& event_id, std::string_view reason), (override));
    MOCK_METHOD(std::size_t, purge_published_older_than,
                (std::chrono::system_clock::time_point cutoff, std::size_t batch_size), (override));
    MOCK_METHOD(std::size_t, count_pending, (), (override));
};

// Test 1: LoginSucceeded emits structured JSON with user, device, and session IDs
TEST(AuditEventPublisherTest, Publish_LoginSucceeded_EmitsStructuredPayloadWithAllIds) {
    auto mock_sink = std::make_shared<MockAuditEventSink>();
    AuditEventPublisher publisher(mock_sink);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session_id = domain::Uuid::generate_v7();

    auto event =
        domain::AuditEvent::login_succeeded(user_id, "alice@securecloud.io", device_id, session_id, "192.168.1.50");

    std::string captured_json;
    EXPECT_CALL(*mock_sink, emit_str(_, _))
        .WillOnce([&captured_json](const domain::AuditEvent& ev, const std::string& json) {
            EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginSucceeded);
            captured_json = json;
        });

    publisher.publish(event);

    auto parsed = nlohmann::json::parse(captured_json);
    EXPECT_EQ(parsed["event_id"], event.event_id.to_string());
    EXPECT_EQ(parsed["event_type"], "auth.login.succeeded");
    EXPECT_EQ(parsed["user_id"], user_id.to_string());
    EXPECT_EQ(parsed["credential_identifier"], "alice@securecloud.io");
    EXPECT_EQ(parsed["device_id"], device_id.to_string());
    EXPECT_EQ(parsed["session_id"], session_id.to_string());
    EXPECT_EQ(parsed["client_ip"], "192.168.1.50");
    EXPECT_TRUE(parsed["failure_reason"].is_null());
}

// Test 2: LoginFailed emits structured payload without password
TEST(AuditEventPublisherTest, Publish_LoginFailed_EmitsStructuredPayloadWithoutPassword) {
    auto mock_sink = std::make_shared<MockAuditEventSink>();
    AuditEventPublisher publisher(mock_sink);

    auto event = domain::AuditEvent::login_failed("bob@securecloud.io", "Password mismatch", std::nullopt, std::nullopt,
                                                  "10.0.0.1");

    std::string captured_json;
    EXPECT_CALL(*mock_sink, emit_str(_, _))
        .WillOnce([&captured_json](const domain::AuditEvent& ev, const std::string& json) {
            EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
            captured_json = json;
        });

    publisher.publish(event);

    auto parsed = nlohmann::json::parse(captured_json);
    EXPECT_EQ(parsed["event_type"], "auth.login.failed");
    EXPECT_EQ(parsed["credential_identifier"], "bob@securecloud.io");
    EXPECT_EQ(parsed["failure_reason"], "Password mismatch");
    EXPECT_EQ(parsed["client_ip"], "10.0.0.1");
    EXPECT_TRUE(parsed["user_id"].is_null());
    EXPECT_TRUE(parsed["session_id"].is_null());
}

// Test 3: AccountDisabledAccessAttempt emits correct event type
TEST(AuditEventPublisherTest, Publish_AccountDisabledAccessAttempt_EmitsCorrectEventType) {
    auto mock_sink = std::make_shared<MockAuditEventSink>();
    AuditEventPublisher publisher(mock_sink);

    auto user_id = domain::Uuid::generate_v7();
    auto event = domain::AuditEvent::account_disabled_attempt(user_id, "disabled_user@securecloud.io",
                                                              "Account is locked or disabled");

    std::string captured_json;
    EXPECT_CALL(*mock_sink, emit_str(_, _))
        .WillOnce(
            [&captured_json](const domain::AuditEvent& /*ev*/, const std::string& json) { captured_json = json; });

    publisher.publish(event);

    auto parsed = nlohmann::json::parse(captured_json);
    EXPECT_EQ(parsed["event_type"], "auth.account.disabled_attempt");
    EXPECT_EQ(parsed["user_id"], user_id.to_string());
    EXPECT_EQ(parsed["credential_identifier"], "disabled_user@securecloud.io");
    EXPECT_EQ(parsed["failure_reason"], "Account is locked or disabled");
}

// Test 4: Strict zero sensitive data leakage invariant
TEST(AuditEventPublisherTest, Publish_ZeroSensitiveDataLeakage_GuaranteesNoSecretOrPasswordFields) {
    auto mock_sink = std::make_shared<MockAuditEventSink>();
    AuditEventPublisher publisher(mock_sink);

    auto event = domain::AuditEvent::login_failed("charlie@securecloud.io", "Invalid credentials");

    std::string captured_json;
    EXPECT_CALL(*mock_sink, emit_str(_, _))
        .WillOnce(
            [&captured_json](const domain::AuditEvent& /*ev*/, const std::string& json) { captured_json = json; });

    publisher.publish(event);

    auto parsed = nlohmann::json::parse(captured_json);
    EXPECT_FALSE(parsed.contains("password"));
    EXPECT_FALSE(parsed.contains("secret"));
    EXPECT_FALSE(parsed.contains("token"));
    EXPECT_FALSE(parsed.contains("hash"));

    // Raw JSON string check
    EXPECT_EQ(captured_json.find("\"password\""), std::string::npos);
    EXPECT_EQ(captured_json.find("\"secret\""), std::string::npos);
}

// Test 5: JSON serialization produces valid standard RFC 8259 JSON
TEST(AuditEventPublisherTest, Publish_JsonSerialization_ValidJsonProduced) {
    domain::AuditEvent ev;
    ev.event_id = domain::Uuid::generate_v7();
    ev.event_type = domain::AuditEventType::LoginSucceeded;
    ev.timestamp = std::chrono::system_clock::now();
    ev.credential_identifier = "test@example.com";
    ev.client_ip = "127.0.0.1";

    std::string json_str = ev.to_json();
    EXPECT_NO_THROW({
        auto parsed = nlohmann::json::parse(json_str);
        EXPECT_EQ(parsed["event_id"], ev.event_id.to_string());
        EXPECT_EQ(parsed["credential_identifier"], "test@example.com");
    });
}

// Test 6: Missing optional fields serialize as null cleanly
TEST(AuditEventPublisherTest, Publish_MissingOptionalFields_SerializesCleanly) {
    domain::AuditEvent ev;
    ev.event_id = domain::Uuid::generate_v7();
    ev.event_type = domain::AuditEventType::LoginFailed;
    ev.timestamp = std::chrono::system_clock::now();
    ev.credential_identifier = "unknown_user";
    ev.user_id = std::nullopt;
    ev.device_id = std::nullopt;
    ev.session_id = std::nullopt;
    ev.failure_reason = "";

    auto parsed = nlohmann::json::parse(ev.to_json());
    EXPECT_TRUE(parsed["user_id"].is_null());
    EXPECT_TRUE(parsed["device_id"].is_null());
    EXPECT_TRUE(parsed["session_id"].is_null());
    EXPECT_TRUE(parsed["failure_reason"].is_null());
}

// Test 7: Sink exception is caught and fails safe without throwing
TEST(AuditEventPublisherTest, Publish_SinkException_CatchesAndFailsSafeWithoutThrowing) {
    auto mock_sink = std::make_shared<MockAuditEventSink>();
    AuditEventPublisher publisher(mock_sink);

    auto event = domain::AuditEvent::login_failed("attacker", "Bad password");

    EXPECT_CALL(*mock_sink, emit_str(_, _)).WillOnce(Throw(std::runtime_error("Audit collector connection dropped")));

    // Fail-safe guarantee: publish must never throw
    EXPECT_NO_THROW(publisher.publish(event));
}

// Test 8: Default sink constructed if null passed, executes safely
TEST(AuditEventPublisherTest, Publish_DefaultSink_DoesNotCrash) {
    AuditEventPublisher publisher(nullptr);
    ASSERT_NE(publisher.sink(), nullptr);

    auto event = domain::AuditEvent::login_failed("test_user", "Failure test");
    EXPECT_NO_THROW(publisher.publish(event));
}

// Test 9: Factory helpers construct valid models
TEST(AuditEventPublisherTest, AuditEvent_FactoryHelpers_ConstructCorrectModels) {
    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session_id = domain::Uuid::generate_v7();

    auto success_ev = domain::AuditEvent::login_succeeded(user_id, "admin", device_id, session_id, "10.1.2.3");
    EXPECT_FALSE(success_ev.event_id.is_nil());
    EXPECT_EQ(success_ev.event_type, domain::AuditEventType::LoginSucceeded);
    EXPECT_EQ(success_ev.credential_identifier, "admin");
    EXPECT_EQ(success_ev.user_id, user_id);
    EXPECT_EQ(success_ev.device_id, device_id);
    EXPECT_EQ(success_ev.session_id, session_id);
    EXPECT_EQ(success_ev.client_ip, "10.1.2.3");

    auto fail_ev = domain::AuditEvent::login_failed("operator", "Locked");
    EXPECT_EQ(fail_ev.event_type, domain::AuditEventType::LoginFailed);
    EXPECT_EQ(fail_ev.failure_reason, "Locked");

    auto disabled_ev = domain::AuditEvent::account_disabled_attempt(user_id, "disabled", "Disabled");
    EXPECT_EQ(disabled_ev.event_type, domain::AuditEventType::AccountDisabledAccessAttempt);
    EXPECT_EQ(disabled_ev.user_id, user_id);

    // AUDIT-013-T01 new factories
    auto mfa_init_ev = domain::AuditEvent::mfa_enrollment_initiated(user_id, "10.0.0.9");
    EXPECT_FALSE(mfa_init_ev.event_id.is_nil());
    EXPECT_EQ(mfa_init_ev.event_type, domain::AuditEventType::MfaEnrollmentInitiated);
    EXPECT_EQ(mfa_init_ev.user_id, user_id);

    auto mfa_fail_ev = domain::AuditEvent::mfa_challenge_failed(user_id, session_id, "Invalid TOTP", "10.0.0.9");
    EXPECT_EQ(mfa_fail_ev.event_type, domain::AuditEventType::MfaChallengeFailed);
    EXPECT_EQ(mfa_fail_ev.session_id, session_id);
    EXPECT_EQ(mfa_fail_ev.failure_reason, "Invalid TOTP");

    auto dev_enr_ev = domain::AuditEvent::device_enrolled(user_id, device_id, false, "10.0.0.9");
    EXPECT_EQ(dev_enr_ev.event_type, domain::AuditEventType::DeviceEnrolled);
    EXPECT_EQ(dev_enr_ev.device_id, device_id);
    EXPECT_EQ(dev_enr_ev.failure_reason, "PENDING_AUTHORIZATION");

    auto prekey_ev = domain::AuditEvent::prekeys_updated(user_id, device_id, 42, "10.0.0.9");
    EXPECT_EQ(prekey_ev.event_type, domain::AuditEventType::PrekeysUpdated);
    EXPECT_EQ(prekey_ev.failure_reason, "ACTIVE_COUNT=42");
}

// Test 10: Event type string representation matches specification
TEST(AuditEventPublisherTest, AuditEventType_ToString_MatchesExpectedNames) {
    EXPECT_EQ(domain::to_string(domain::AuditEventType::LoginSucceeded), "auth.login.succeeded");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::LoginFailed), "auth.login.failed");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::AccountDisabledAccessAttempt), "auth.account.disabled_attempt");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::SessionRevoked), "auth.session.revoked");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::SessionExpiredAttempt), "auth.session.expired_attempt");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::SessionRevokedAttempt), "auth.session.revoked_attempt");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::TokenRefreshed), "auth.token.refreshed");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::TokenReuseDetected), "auth.token.reuse_detected");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::MfaEnrollmentInitiated), "auth.mfa.enrollment_initiated");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::MfaEnrollmentConfirmed), "auth.mfa.enrollment_confirmed");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::MfaDisabled), "auth.mfa.disabled");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::MfaChallengeCreated), "auth.mfa.challenge_created");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::MfaChallengeSucceeded), "auth.mfa.challenge_succeeded");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::MfaChallengeFailed), "auth.mfa.challenge_failed");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::MfaRecoveryCodeUsed), "auth.mfa.recovery_code_used");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::DeviceEnrolled), "auth.device.enrolled");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::DevicePairingInitiated), "auth.device.pairing_initiated");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::DeviceAuthorized), "auth.device.authorized");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::DeviceRevoked), "auth.device.revoked");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::PrekeysUpdated), "auth.device.prekeys_updated");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::SignedPrekeyRotated), "auth.device.signed_prekey_rotated");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::PrekeyInventoryLow), "auth.device.prekey_inventory_low");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::PrekeyInventoryExhausted),
              "auth.device.prekey_inventory_exhausted");
}

// Test 11: OutboxAuditEventPublisher stages autonomous events with aggregate metadata & producer_instance
TEST(AuditEventPublisherTest, OutboxPublisher_Publish_StagesEntityWithMetadataAndProducerInstance) {
    auto mock_outbox = std::make_shared<MockAuthOutboxRepository>();
    auto mock_fallback = std::make_shared<MockAuditEventSink>();
    OutboxAuditEventPublisher publisher(mock_outbox, "auth-eu-west-2", mock_fallback);

    auto user_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto session_id = domain::Uuid::generate_v7();
    auto event =
        domain::AuditEvent::login_succeeded(user_id, "alice@securecloud.io", device_id, session_id, "10.2.3.4");

    domain::AuthOutboxEntity captured_entity;
    EXPECT_CALL(*mock_outbox, stage_event(_)).WillOnce([&captured_entity](const domain::AuthOutboxEntity& entity) {
        captured_entity = entity;
    });
    EXPECT_CALL(*mock_fallback, emit_str(_, _)).Times(0);

    EXPECT_NO_THROW(publisher.publish(event));

    EXPECT_EQ(captured_entity.event_id, event.event_id);
    EXPECT_EQ(captured_entity.event_type, "auth.login.succeeded");
    EXPECT_EQ(captured_entity.status, domain::OutboxStatus::Pending);
    EXPECT_FALSE(captured_entity.aggregate_type.empty());
    EXPECT_FALSE(captured_entity.aggregate_id.has_value());

    auto payload = nlohmann::json::parse(captured_entity.payload_json);
    EXPECT_EQ(payload["event_id"], event.event_id.to_string());
    EXPECT_EQ(payload["event_type"], "auth.login.succeeded");
    EXPECT_EQ(payload["producer_instance"], "auth-eu-west-2");
    EXPECT_EQ(payload["user_id"], user_id.to_string());
    EXPECT_EQ(payload["device_id"], device_id.to_string());
    EXPECT_EQ(payload["session_id"], session_id.to_string());
}

// Test 12: OutboxAuditEventPublisher stages compromise telemetry with full context and zero secret leakage
TEST(AuditEventPublisherTest, OutboxPublisher_Publish_CompromiseEvent_StagesPayloadWithoutSecrets) {
    auto mock_outbox = std::make_shared<MockAuthOutboxRepository>();
    OutboxAuditEventPublisher publisher(mock_outbox, "auth-1", nullptr);

    auto session_id = domain::Uuid::generate_v7();
    auto device_id = domain::Uuid::generate_v7();
    auto event = domain::AuditEvent::token_reuse_detected(session_id, device_id, "203.0.113.42");

    domain::AuthOutboxEntity captured_entity;
    EXPECT_CALL(*mock_outbox, stage_event(_)).WillOnce([&captured_entity](const domain::AuthOutboxEntity& entity) {
        captured_entity = entity;
    });

    publisher.publish(event);

    EXPECT_EQ(captured_entity.event_type, "auth.token.reuse_detected");
    EXPECT_EQ(captured_entity.status, domain::OutboxStatus::Pending);

    auto payload = nlohmann::json::parse(captured_entity.payload_json);
    EXPECT_EQ(payload["session_id"], session_id.to_string());
    EXPECT_EQ(payload["device_id"], device_id.to_string());
    EXPECT_EQ(payload["client_ip"], "203.0.113.42");
    EXPECT_EQ(payload["producer_instance"], "auth-1");
    EXPECT_FALSE(payload.contains("password"));
    EXPECT_FALSE(payload.contains("token"));
    EXPECT_FALSE(payload.contains("secret"));
}

// Test 13: OutboxAuditEventPublisher catches repository failure and emits to fallback sink without throwing
TEST(AuditEventPublisherTest, OutboxPublisher_Publish_RepoThrows_FallsBackToSinkNoexcept) {
    auto mock_outbox = std::make_shared<MockAuthOutboxRepository>();
    auto mock_fallback = std::make_shared<MockAuditEventSink>();
    OutboxAuditEventPublisher publisher(mock_outbox, "auth-1", mock_fallback);

    auto event = domain::AuditEvent::login_failed("mallory@evil.test", "Invalid password");

    EXPECT_CALL(*mock_outbox, stage_event(_)).WillOnce(Throw(std::runtime_error("PostgreSQL connection timeout")));
    EXPECT_CALL(*mock_fallback, emit_str(_, _)).Times(1);

    EXPECT_NO_THROW(publisher.publish(event));
}

// Test 14: OutboxAuditEventPublisher fails closed when constructed with null repository
TEST(AuditEventPublisherTest, OutboxPublisher_Constructor_NullRepo_ThrowsInvalidArgument) {
    EXPECT_THROW((OutboxAuditEventPublisher(nullptr, "auth-1", nullptr)), std::invalid_argument);
}

} // namespace
} // namespace securecloud::auth::service::test
