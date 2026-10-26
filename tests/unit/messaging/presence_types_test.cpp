#include "domain/connection_session.hpp"
#include "domain/presence_types.hpp"

#include <gtest/gtest.h>
#include <string>

namespace securecloud::messaging::domain::test {

class PresenceTypesTest : public ::testing::Test {
  protected:
    const UserId test_user_id = *UserId::from_string("018f4a7c-6e21-789a-bcde-0123456789ab");
    const DeviceId test_device_id{"018f4a7c-6e21-789a-bcde-0123456789cd"};
};

// ============================================================================
// 1. PresenceStatus & Serialization Tests
// ============================================================================

TEST_F(PresenceTypesTest, PresenceStatusToStringRoundtrip) {
    EXPECT_EQ(to_string(PresenceStatus::Unspecified), "UNSPECIFIED");
    EXPECT_EQ(to_string(PresenceStatus::Online), "ONLINE");
    EXPECT_EQ(to_string(PresenceStatus::Away), "AWAY");
    EXPECT_EQ(to_string(PresenceStatus::Busy), "BUSY");
    EXPECT_EQ(to_string(PresenceStatus::Offline), "OFFLINE");

    EXPECT_EQ(parse_presence_status("ONLINE"), PresenceStatus::Online);
    EXPECT_EQ(parse_presence_status("online"), PresenceStatus::Online);
    EXPECT_EQ(parse_presence_status("AWAY"), PresenceStatus::Away);
    EXPECT_EQ(parse_presence_status("BUSY"), PresenceStatus::Busy);
    EXPECT_EQ(parse_presence_status("OFFLINE"), PresenceStatus::Offline);
    EXPECT_EQ(parse_presence_status("UNSPECIFIED"), PresenceStatus::Unspecified);
    EXPECT_EQ(parse_presence_status("UNKNOWN"), PresenceStatus::Unspecified);

    EXPECT_FALSE(parse_presence_status("INVALID_STATUS").has_value());
    EXPECT_FALSE(parse_presence_status("").has_value());
}

TEST_F(PresenceTypesTest, PresenceStatusProtoConversion) {
    EXPECT_EQ(to_proto(PresenceStatus::Unspecified), securecloud::messaging::v1::PRESENCE_STATUS_UNSPECIFIED);
    EXPECT_EQ(to_proto(PresenceStatus::Online), securecloud::messaging::v1::PRESENCE_STATUS_ONLINE);
    EXPECT_EQ(to_proto(PresenceStatus::Away), securecloud::messaging::v1::PRESENCE_STATUS_AWAY);
    EXPECT_EQ(to_proto(PresenceStatus::Busy), securecloud::messaging::v1::PRESENCE_STATUS_BUSY);
    EXPECT_EQ(to_proto(PresenceStatus::Offline), securecloud::messaging::v1::PRESENCE_STATUS_OFFLINE);

    EXPECT_EQ(from_proto(securecloud::messaging::v1::PRESENCE_STATUS_ONLINE), PresenceStatus::Online);
    EXPECT_EQ(from_proto(securecloud::messaging::v1::PRESENCE_STATUS_AWAY), PresenceStatus::Away);
    EXPECT_EQ(from_proto(securecloud::messaging::v1::PRESENCE_STATUS_BUSY), PresenceStatus::Busy);
    EXPECT_EQ(from_proto(securecloud::messaging::v1::PRESENCE_STATUS_OFFLINE), PresenceStatus::Offline);
    EXPECT_EQ(from_proto(securecloud::messaging::v1::PRESENCE_STATUS_UNSPECIFIED), PresenceStatus::Unspecified);
}

// ============================================================================
// 2. Custom Status Sanitization & Bounds Tests
// ============================================================================

TEST_F(PresenceTypesTest, StatusMessageSanitizationTrimsWhitespace) {
    EXPECT_EQ(sanitize_status_message("   Deploying field clinic   \n\t"), "Deploying field clinic");
    EXPECT_EQ(sanitize_status_message(""), "");
    EXPECT_EQ(sanitize_status_message("   "), "");
}

TEST_F(PresenceTypesTest, StatusMessageBoundsEnforcedTo140Chars) {
    const std::string exact_140(140, 'A');
    EXPECT_EQ(sanitize_status_message(exact_140), exact_140);

    const std::string oversized_200(200, 'B');
    const auto sanitized = sanitize_status_message(oversized_200);
    EXPECT_EQ(sanitized.size(), 140);
    EXPECT_EQ(sanitized, std::string(140, 'B'));
}

// ============================================================================
// 3. UserPresence Value Object & Protobuf Roundtrip
// ============================================================================

TEST_F(PresenceTypesTest, UserPresenceDefaultAndOnlineChecks) {
    UserPresence presence;
    EXPECT_EQ(presence.status, PresenceStatus::Unspecified);
    EXPECT_FALSE(presence.is_online());

    presence.status = PresenceStatus::Online;
    EXPECT_TRUE(presence.is_online());

    presence.status = PresenceStatus::Away;
    EXPECT_TRUE(presence.is_online());

    presence.status = PresenceStatus::Busy;
    EXPECT_TRUE(presence.is_online());

    presence.status = PresenceStatus::Offline;
    EXPECT_FALSE(presence.is_online());
}

TEST_F(PresenceTypesTest, UserPresenceProtoRoundtrip) {
    UserPresence original;
    original.user_id = test_user_id;
    original.status = PresenceStatus::Busy;
    const auto now = std::chrono::system_clock::now();
    // Truncate to milliseconds for Protobuf roundtrip comparison
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    original.last_active_at = std::chrono::system_clock::time_point(now_ms);
    original.custom_status_message = "Triage in progress";
    original.active_device_count = 2;

    const auto proto = to_proto(original);
    EXPECT_EQ(proto.user_id(), test_user_id.str());
    EXPECT_EQ(proto.status(), securecloud::messaging::v1::PRESENCE_STATUS_BUSY);
    EXPECT_EQ(proto.last_active_unix_ms(), now_ms.count());
    EXPECT_EQ(proto.custom_status_message(), "Triage in progress");

    const auto restored = from_proto(proto);
    EXPECT_EQ(restored.user_id, original.user_id);
    EXPECT_EQ(restored.status, original.status);
    EXPECT_EQ(restored.last_active_at, original.last_active_at);
    EXPECT_EQ(restored.custom_status_message, original.custom_status_message);
}

// ============================================================================
// 4. UpdatePresenceCommand Validation
// ============================================================================

TEST_F(PresenceTypesTest, UpdatePresenceCommandValidity) {
    UpdatePresenceCommand valid_cmd;
    valid_cmd.user_id = test_user_id;
    valid_cmd.status = PresenceStatus::Away;
    valid_cmd.custom_status_message = "Lunch break";
    EXPECT_TRUE(valid_cmd.is_valid());

    UpdatePresenceCommand invalid_user;
    invalid_user.status = PresenceStatus::Online;
    EXPECT_FALSE(invalid_user.is_valid());

    UpdatePresenceCommand invalid_status;
    invalid_status.user_id = test_user_id;
    invalid_status.status = PresenceStatus::Unspecified;
    EXPECT_FALSE(invalid_status.is_valid());
}

// ============================================================================
// 5. ConnectionState & Transition Validator Tests
// ============================================================================

TEST_F(PresenceTypesTest, ConnectionStateToStringAndParse) {
    EXPECT_EQ(to_string(ConnectionState::Connecting), "CONNECTING");
    EXPECT_EQ(to_string(ConnectionState::Active), "ACTIVE");
    EXPECT_EQ(to_string(ConnectionState::Stale), "STALE");
    EXPECT_EQ(to_string(ConnectionState::Terminated), "TERMINATED");

    EXPECT_EQ(parse_connection_state("CONNECTING"), ConnectionState::Connecting);
    EXPECT_EQ(parse_connection_state("ACTIVE"), ConnectionState::Active);
    EXPECT_EQ(parse_connection_state("STALE"), ConnectionState::Stale);
    EXPECT_EQ(parse_connection_state("TERMINATED"), ConnectionState::Terminated);
    EXPECT_FALSE(parse_connection_state("UNKNOWN_STATE").has_value());
}

TEST_F(PresenceTypesTest, LegalConnectionStateTransitions) {
    // From Connecting
    EXPECT_TRUE(is_valid_connection_transition(ConnectionState::Connecting, ConnectionState::Active));
    EXPECT_TRUE(is_valid_connection_transition(ConnectionState::Connecting, ConnectionState::Terminated));

    // From Active
    EXPECT_TRUE(is_valid_connection_transition(ConnectionState::Active, ConnectionState::Stale));
    EXPECT_TRUE(is_valid_connection_transition(ConnectionState::Active, ConnectionState::Terminated));

    // From Stale
    EXPECT_TRUE(is_valid_connection_transition(ConnectionState::Stale, ConnectionState::Active));
    EXPECT_TRUE(is_valid_connection_transition(ConnectionState::Stale, ConnectionState::Terminated));
}

TEST_F(PresenceTypesTest, IllegalConnectionStateTransitions) {
    // Cannot skip from Connecting to Stale directly
    EXPECT_FALSE(is_valid_connection_transition(ConnectionState::Connecting, ConnectionState::Stale));

    // Cannot regress to Connecting once active or stale
    EXPECT_FALSE(is_valid_connection_transition(ConnectionState::Active, ConnectionState::Connecting));
    EXPECT_FALSE(is_valid_connection_transition(ConnectionState::Stale, ConnectionState::Connecting));

    // Terminated is strictly terminal: cannot transition anywhere
    EXPECT_FALSE(is_valid_connection_transition(ConnectionState::Terminated, ConnectionState::Connecting));
    EXPECT_FALSE(is_valid_connection_transition(ConnectionState::Terminated, ConnectionState::Active));
    EXPECT_FALSE(is_valid_connection_transition(ConnectionState::Terminated, ConnectionState::Stale));
    EXPECT_FALSE(is_valid_connection_transition(ConnectionState::Terminated, ConnectionState::Terminated));
}

// ============================================================================
// 6. DeviceConnection Entity & Value Semantics
// ============================================================================

TEST_F(PresenceTypesTest, DeviceConnectionLifecycleTransitions) {
    DeviceConnection conn;
    conn.connection_id = "018f4a7c-6e21-789a-bcde-0123456789ee";
    conn.device_id = test_device_id;
    conn.user_id = test_user_id;
    conn.client_ip = "192.168.1.100";
    conn.user_agent = "SecureCloud-Mobile/1.0";
    conn.auth_session_id = "auth-session-uuid-123";

    EXPECT_EQ(conn.state, ConnectionState::Connecting);
    EXPECT_FALSE(conn.is_active());

    // Handshake succeeds -> Active
    EXPECT_TRUE(conn.transition_to(ConnectionState::Active));
    EXPECT_EQ(conn.state, ConnectionState::Active);
    EXPECT_TRUE(conn.is_active());

    // Idle window elapses -> Stale
    EXPECT_TRUE(conn.transition_to(ConnectionState::Stale));
    EXPECT_EQ(conn.state, ConnectionState::Stale);
    EXPECT_FALSE(conn.is_active());

    // Heartbeat restores to Active
    EXPECT_TRUE(conn.transition_to(ConnectionState::Active));
    EXPECT_EQ(conn.state, ConnectionState::Active);
    EXPECT_TRUE(conn.is_active());

    // Graceful disconnect -> Terminated
    EXPECT_TRUE(conn.transition_to(ConnectionState::Terminated));
    EXPECT_EQ(conn.state, ConnectionState::Terminated);
    EXPECT_FALSE(conn.is_active());

    // Once terminated, cannot resurrect: must create a new connection entity
    EXPECT_FALSE(conn.transition_to(ConnectionState::Active));
    EXPECT_EQ(conn.state, ConnectionState::Terminated);
}

TEST_F(PresenceTypesTest, DeviceConnectionEqualityAndCopyMoveSemantics) {
    DeviceConnection conn1;
    conn1.connection_id = "conn-1";
    conn1.device_id = test_device_id;
    conn1.user_id = test_user_id;
    conn1.state = ConnectionState::Active;

    DeviceConnection conn2 = conn1; // Copy
    EXPECT_EQ(conn1, conn2);

    DeviceConnection conn3;
    conn3.connection_id = "conn-2";
    conn3.device_id = test_device_id;
    conn3.user_id = test_user_id;
    conn3.state = ConnectionState::Active;
    EXPECT_NE(conn1, conn3);

    DeviceConnection conn4 = std::move(conn2); // Move
    EXPECT_EQ(conn1, conn4);
}

} // namespace securecloud::messaging::domain::test
