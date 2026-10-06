#include "domain/audit_event.hpp"
#include "domain/uuid.hpp"
#include "service/audit_event_publisher.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::Throw;

class MockAuditEventSink : public IAuditEventSink {
  public:
    MOCK_METHOD(void, emit, (const domain::AuditEvent& event, std::string_view json_payload), (override));
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
    EXPECT_CALL(*mock_sink, emit(_, _)).WillOnce([&captured_json](const domain::AuditEvent& ev, std::string_view json) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginSucceeded);
        captured_json = std::string(json);
    });

    publisher.publish(event);

    auto parsed = nlohmann::json::parse(captured_json);
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
    EXPECT_CALL(*mock_sink, emit(_, _)).WillOnce([&captured_json](const domain::AuditEvent& ev, std::string_view json) {
        EXPECT_EQ(ev.event_type, domain::AuditEventType::LoginFailed);
        captured_json = std::string(json);
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
    EXPECT_CALL(*mock_sink, emit(_, _))
        .WillOnce([&captured_json](const domain::AuditEvent& /*ev*/, std::string_view json) {
            captured_json = std::string(json);
        });

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
    EXPECT_CALL(*mock_sink, emit(_, _))
        .WillOnce([&captured_json](const domain::AuditEvent& /*ev*/, std::string_view json) {
            captured_json = std::string(json);
        });

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

    EXPECT_CALL(*mock_sink, emit(_, _)).WillOnce(Throw(std::runtime_error("Audit collector connection dropped")));

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
}

// Test 10: Event type string representation matches specification
TEST(AuditEventPublisherTest, AuditEventType_ToString_MatchesExpectedNames) {
    EXPECT_EQ(domain::to_string(domain::AuditEventType::LoginSucceeded), "auth.login.succeeded");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::LoginFailed), "auth.login.failed");
    EXPECT_EQ(domain::to_string(domain::AuditEventType::AccountDisabledAccessAttempt), "auth.account.disabled_attempt");
}

} // namespace
} // namespace securecloud::auth::service::test
