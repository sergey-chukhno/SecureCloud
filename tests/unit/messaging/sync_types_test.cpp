#include "messaging/domain/sync_types.hpp"
#include "messaging/service/sync_commands.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <thread>

namespace securecloud::messaging::test {
namespace {

using domain::ConversationId;
using domain::DeviceId;
using domain::DeviceSyncCursor;
using service::clamp_sync_batch_size;
using service::GetSyncCursorCommand;
using service::k_default_sync_batch_size;
using service::k_max_sync_batch_size;
using service::k_min_sync_batch_size;
using service::SyncDeviceMessagesCommand;
using service::SyncMessagesResult;
using service::UpdateSyncCursorCommand;
using service::UpdateSyncCursorResult;

TEST(DeviceSyncCursorTest, CreateInitialConstructsValidCursor) {
    auto dev_id = DeviceId("dev-test-123");
    auto conv_id = ConversationId::generate_v7();
    auto before = std::chrono::system_clock::now();

    auto cursor = DeviceSyncCursor::create_initial(dev_id, conv_id);

    EXPECT_TRUE(cursor.is_valid());
    EXPECT_EQ(cursor.device_id, dev_id);
    EXPECT_EQ(cursor.conversation_id, conv_id);
    EXPECT_EQ(cursor.last_synced_sequence, 0U);
    EXPECT_EQ(cursor.sync_version, 1);
    EXPECT_GE(cursor.last_sync_at, before);
}

TEST(DeviceSyncCursorTest, IsValidRejectsEmptyDeviceIdOrNilConversation) {
    DeviceSyncCursor cursor;
    EXPECT_FALSE(cursor.is_valid());

    cursor.device_id = DeviceId("dev-1");
    EXPECT_FALSE(cursor.is_valid()); // conv_id still nil

    cursor.conversation_id = ConversationId::generate_v7();
    EXPECT_TRUE(cursor.is_valid());

    cursor.device_id = DeviceId("");
    EXPECT_FALSE(cursor.is_valid());
}

TEST(DeviceSyncCursorTest, MonotonicProgressionEnforced) {
    auto dev_id = DeviceId("dev-phone-abc");
    auto conv_id = ConversationId::generate_v7();
    auto cursor = DeviceSyncCursor::create_initial(dev_id, conv_id);

    EXPECT_EQ(cursor.last_synced_sequence, 0U);
    EXPECT_TRUE(cursor.can_advance_to(0U));
    EXPECT_TRUE(cursor.can_advance_to(10U));

    auto t1 = std::chrono::system_clock::now();
    cursor.advance_to(100U, t1);

    EXPECT_EQ(cursor.last_synced_sequence, 100U);
    EXPECT_EQ(cursor.sync_version, 2);
    EXPECT_EQ(cursor.last_sync_at, t1);

    // Progression to same or higher sequence allowed
    EXPECT_TRUE(cursor.can_advance_to(100U));
    EXPECT_TRUE(cursor.can_advance_to(150U));

    // Progression to lower sequence rejected
    EXPECT_FALSE(cursor.can_advance_to(99U));
    EXPECT_FALSE(cursor.can_advance_to(0U));

    EXPECT_THROW(cursor.advance_to(99U), std::invalid_argument);
    EXPECT_EQ(cursor.last_synced_sequence, 100U);
    EXPECT_EQ(cursor.sync_version, 2);
}

TEST(DeviceSyncCursorTest, EqualityAndComparisonOperators) {
    auto dev_a = DeviceId("dev-a");
    auto dev_b = DeviceId("dev-b");
    auto conv_id = ConversationId::generate_v7();

    auto c1 = DeviceSyncCursor::create_initial(dev_a, conv_id);
    auto c2 = DeviceSyncCursor::create_initial(dev_a, conv_id);
    c2.last_sync_at = c1.last_sync_at;

    EXPECT_EQ(c1, c2);

    auto c3 = DeviceSyncCursor::create_initial(dev_b, conv_id);
    EXPECT_NE(c1, c3);
}

TEST(SyncCommandsTest, ClampSyncBatchSizeEnforcesBounds) {
    EXPECT_EQ(clamp_sync_batch_size(0), k_default_sync_batch_size);
    EXPECT_EQ(clamp_sync_batch_size(1), 1U);
    EXPECT_EQ(clamp_sync_batch_size(50), 50U);
    EXPECT_EQ(clamp_sync_batch_size(500), 500U);
    EXPECT_EQ(clamp_sync_batch_size(501), k_max_sync_batch_size);
    EXPECT_EQ(clamp_sync_batch_size(10000), k_max_sync_batch_size);
}

TEST(SyncCommandsTest, SyncCommandsDefaultValues) {
    SyncDeviceMessagesCommand cmd;
    EXPECT_EQ(cmd.since_sequence, 0U);
    EXPECT_EQ(cmd.max_messages, k_default_sync_batch_size);
    EXPECT_FALSE(cmd.conversation_id.has_value());

    UpdateSyncCursorCommand update_cmd{
        .device_id = DeviceId("dev-1"),
        .conversation_id = ConversationId::generate_v7(),
        .new_sequence = 42,
        .sync_version = 1
    };
    EXPECT_EQ(update_cmd.new_sequence, 42U);
    EXPECT_EQ(update_cmd.sync_version, 1);
}

TEST(SyncCommandsTest, UpdateSyncCursorResultFactory) {
    auto dev_id = DeviceId("dev-ok");
    auto conv_id = ConversationId::generate_v7();
    auto cursor = DeviceSyncCursor::create_initial(dev_id, conv_id);

    auto ok_res = UpdateSyncCursorResult::ok(cursor);
    EXPECT_TRUE(ok_res.success);
    EXPECT_EQ(ok_res.cursor.device_id, dev_id);
    EXPECT_TRUE(ok_res.error_message.empty());

    auto fail_res = UpdateSyncCursorResult::failure("Sequence regression forbidden");
    EXPECT_FALSE(fail_res.success);
    EXPECT_EQ(fail_res.error_message, "Sequence regression forbidden");
}

TEST(ProtobufSyncContractTest, SyncCursorSerializationWithConversationScope) {
    securecloud::messaging::v1::SyncCursor proto_cursor;
    proto_cursor.set_device_id("dev-laptop-999");
    proto_cursor.set_last_delivered_sequence(1234);
    proto_cursor.set_last_sync_timestamp_unix_ms(1700000000123LL);
    proto_cursor.set_conversation_id("018e3a2b-4c5d-7e8f-9012-3456789abcde");
    proto_cursor.set_sync_version(5);

    std::string serialized;
    ASSERT_TRUE(proto_cursor.SerializeToString(&serialized));

    securecloud::messaging::v1::SyncCursor parsed_cursor;
    ASSERT_TRUE(parsed_cursor.ParseFromString(serialized));

    EXPECT_EQ(parsed_cursor.device_id(), "dev-laptop-999");
    EXPECT_EQ(parsed_cursor.last_delivered_sequence(), 1234);
    EXPECT_EQ(parsed_cursor.last_sync_timestamp_unix_ms(), 1700000000123LL);
    EXPECT_EQ(parsed_cursor.conversation_id(), "018e3a2b-4c5d-7e8f-9012-3456789abcde");
    EXPECT_EQ(parsed_cursor.sync_version(), 5);
}

TEST(ProtobufSyncContractTest, SyncDeviceMessagesRequestAndResponseSerialization) {
    securecloud::messaging::v1::SyncDeviceMessagesRequest request;
    request.set_device_id("dev-phone-1");
    request.set_since_sequence(50);
    request.set_max_messages(100);
    request.set_conversation_id("018e3a2b-4c5d-7e8f-9012-3456789abcde");

    std::string serialized_req;
    ASSERT_TRUE(request.SerializeToString(&serialized_req));

    securecloud::messaging::v1::SyncDeviceMessagesRequest parsed_req;
    ASSERT_TRUE(parsed_req.ParseFromString(serialized_req));
    EXPECT_EQ(parsed_req.device_id(), "dev-phone-1");
    EXPECT_EQ(parsed_req.since_sequence(), 50);
    EXPECT_EQ(parsed_req.max_messages(), 100U);
    EXPECT_EQ(parsed_req.conversation_id(), "018e3a2b-4c5d-7e8f-9012-3456789abcde");

    securecloud::messaging::v1::SyncDeviceMessagesResponse response;
    response.set_device_id("dev-phone-1");
    response.set_has_more(true);
    response.set_next_sequence(151);
    response.set_latest_sequence(250);

    auto* cursor = response.mutable_cursor();
    cursor->set_device_id("dev-phone-1");
    cursor->set_last_delivered_sequence(150);
    cursor->set_conversation_id("018e3a2b-4c5d-7e8f-9012-3456789abcde");
    cursor->set_sync_version(2);

    std::string serialized_res;
    ASSERT_TRUE(response.SerializeToString(&serialized_res));

    securecloud::messaging::v1::SyncDeviceMessagesResponse parsed_res;
    ASSERT_TRUE(parsed_res.ParseFromString(serialized_res));
    EXPECT_EQ(parsed_res.device_id(), "dev-phone-1");
    EXPECT_TRUE(parsed_res.has_more());
    EXPECT_EQ(parsed_res.next_sequence(), 151);
    EXPECT_EQ(parsed_res.latest_sequence(), 250);
    EXPECT_EQ(parsed_res.cursor().conversation_id(), "018e3a2b-4c5d-7e8f-9012-3456789abcde");
    EXPECT_EQ(parsed_res.cursor().sync_version(), 2);
}

TEST(ProtobufSyncContractTest, GetSyncCursorRequestWithConversationId) {
    securecloud::messaging::v1::GetSyncCursorRequest request;
    request.set_device_id("dev-tablet-42");
    request.set_conversation_id("018e3a2b-4c5d-7e8f-9012-3456789abcde");

    std::string serialized;
    ASSERT_TRUE(request.SerializeToString(&serialized));

    securecloud::messaging::v1::GetSyncCursorRequest parsed;
    ASSERT_TRUE(parsed.ParseFromString(serialized));
    EXPECT_EQ(parsed.device_id(), "dev-tablet-42");
    EXPECT_EQ(parsed.conversation_id(), "018e3a2b-4c5d-7e8f-9012-3456789abcde");
}

} // namespace
} // namespace securecloud::messaging::test
