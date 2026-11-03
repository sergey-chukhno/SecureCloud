#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/delivery_state.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/message.hpp"
#include "domain/message_id.hpp"
#include "domain/user.hpp"
#include "domain/user_id.hpp"

#include <gtest/gtest.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;

TEST(DomainIdTest, UserIdValidAndInvalidConstruction) {
    EXPECT_THROW(UserId(""), std::invalid_argument);

    const UserId uid("alice-001");
    EXPECT_EQ(uid.value(), "alice-001");
    EXPECT_EQ(uid.str(), "alice-001");
    EXPECT_FALSE(uid.empty());

    std::ostringstream oss;
    oss << uid;
    EXPECT_EQ(oss.str(), "alice-001");

    const UserId uid2("alice-001");
    const UserId uid3("bob-002");
    EXPECT_EQ(uid, uid2);
    EXPECT_NE(uid, uid3);
    EXPECT_LT(uid, uid3);

    std::unordered_set<UserId> set;
    set.insert(uid);
    EXPECT_EQ(set.count(uid2), 1u);
}

TEST(DomainIdTest, DeviceIdValidAndInvalidConstruction) {
    EXPECT_THROW(DeviceId(""), std::invalid_argument);

    const DeviceId did("macbook-arm64-1");
    EXPECT_EQ(did.value(), "macbook-arm64-1");
    EXPECT_FALSE(did.empty());

    const DeviceId did2("macbook-arm64-1");
    EXPECT_EQ(did, did2);

    std::unordered_map<DeviceId, int> map;
    map[did] = 42;
    EXPECT_EQ(map[did2], 42);
}

TEST(DomainIdTest, ConversationIdAndMessageIdValidation) {
    EXPECT_THROW(ConversationId(""), std::invalid_argument);
    EXPECT_THROW(MessageId(""), std::invalid_argument);

    const ConversationId cid("conv-xyz");
    const MessageId mid("msg-12345");
    EXPECT_EQ(cid.value(), "conv-xyz");
    EXPECT_EQ(mid.value(), "msg-12345");
}

TEST(DomainDeliveryStateTest, ToStringTransitions) {
    EXPECT_EQ(to_string(DeliveryState::LocalPending), "LocalPending");
    EXPECT_EQ(to_string(DeliveryState::Submitting), "Submitting");
    EXPECT_EQ(to_string(DeliveryState::Accepted), "Accepted");
    EXPECT_EQ(to_string(DeliveryState::Delivering), "Delivering");
    EXPECT_EQ(to_string(DeliveryState::Delivered), "Delivered");
    EXPECT_EQ(to_string(DeliveryState::Read), "Read");
    EXPECT_EQ(to_string(DeliveryState::Failed), "Failed");
}

TEST(DomainCryptoIdentityTest, PropertiesAndStatus) {
    CryptoIdentity id("pubkey-bytes-base64", "fingerprint-hex-1234", KeyVerificationStatus::Unverified, "prekey",
                      "sig");

    EXPECT_EQ(id.identity_key(), "pubkey-bytes-base64");
    EXPECT_EQ(id.fingerprint(), "fingerprint-hex-1234");
    EXPECT_EQ(id.verification_status(), KeyVerificationStatus::Unverified);
    EXPECT_EQ(id.signed_prekey(), "prekey");
    EXPECT_EQ(id.signature(), "sig");

    id.set_verification_status(KeyVerificationStatus::Verified);
    EXPECT_EQ(id.verification_status(), KeyVerificationStatus::Verified);
    EXPECT_EQ(to_string(KeyVerificationStatus::Verified), "Verified");
    EXPECT_EQ(to_string(KeyVerificationStatus::KeyChanged), "KeyChanged");
    EXPECT_EQ(to_string(KeyVerificationStatus::Unverified), "Unverified");
}

TEST(DomainDeviceTest, PropertiesAndStatus) {
    const DeviceId did("device-1");
    const UserId uid("user-1");
    const CryptoIdentity identity("key", "fp");

    Device device(did, uid, "Alice's Laptop", identity, DeviceAuthorizationStatus::Authorized);
    EXPECT_EQ(device.device_id(), did);
    EXPECT_EQ(device.user_id(), uid);
    EXPECT_EQ(device.display_name(), "Alice's Laptop");
    EXPECT_EQ(device.status(), DeviceAuthorizationStatus::Authorized);

    device.set_status(DeviceAuthorizationStatus::Revoked);
    EXPECT_EQ(device.status(), DeviceAuthorizationStatus::Revoked);
    EXPECT_EQ(to_string(DeviceAuthorizationStatus::Authorized), "Authorized");
    EXPECT_EQ(to_string(DeviceAuthorizationStatus::Revoked), "Revoked");
    EXPECT_EQ(to_string(DeviceAuthorizationStatus::Pending), "Pending");
}

TEST(DomainUserTest, DeviceManagement) {
    const UserId uid("user-42");
    User user(uid, "Alice");

    EXPECT_EQ(user.user_id(), uid);
    EXPECT_EQ(user.display_name(), "Alice");
    EXPECT_TRUE(user.devices().empty());

    const DeviceId did1("dev-1");
    const DeviceId did2("dev-2");
    const Device dev1(did1, uid, "Phone", CryptoIdentity{});
    const Device dev2(did2, uid, "Tablet", CryptoIdentity{});

    user.add_device(dev1);
    EXPECT_EQ(user.devices().size(), 1u);

    // Update existing device
    Device dev1_updated(did1, uid, "Phone Pro", CryptoIdentity{});
    user.add_device(dev1_updated);
    EXPECT_EQ(user.devices().size(), 1u);
    EXPECT_EQ(user.devices()[0].display_name(), "Phone Pro");

    user.add_device(dev2);
    EXPECT_EQ(user.devices().size(), 2u);

    user.remove_device(did1);
    EXPECT_EQ(user.devices().size(), 1u);
    EXPECT_EQ(user.devices()[0].device_id(), did2);
}

TEST(DomainContactTest, PropertiesAndBlocking) {
    const UserId uid("charlie-77");
    Contact contact(uid, "Charlie", KeyVerificationStatus::Unverified, "fp-charlie");

    EXPECT_EQ(contact.user_id(), uid);
    EXPECT_EQ(contact.alias(), "Charlie");
    EXPECT_FALSE(contact.is_blocked());

    contact.set_alias("Chuck");
    contact.set_blocked(true);
    contact.set_verification_status(KeyVerificationStatus::Verified);

    EXPECT_EQ(contact.alias(), "Chuck");
    EXPECT_TRUE(contact.is_blocked());
    EXPECT_EQ(contact.verification_status(), KeyVerificationStatus::Verified);
}

TEST(DomainConversationTest, ParticipantManagementAndType) {
    const ConversationId cid("conv-group-1");
    const UserId u1("user-1");
    const UserId u2("user-2");
    const UserId u3("user-3");

    Conversation conv(cid, ConversationType::Group, "Project Chat", {u1, u2});
    EXPECT_EQ(conv.conversation_id(), cid);
    EXPECT_EQ(conv.type(), ConversationType::Group);
    EXPECT_EQ(conv.title(), "Project Chat");
    EXPECT_EQ(conv.participants().size(), 2u);
    EXPECT_EQ(to_string(ConversationType::Direct), "Direct");
    EXPECT_EQ(to_string(ConversationType::Group), "Group");

    // Add unique participant
    conv.add_participant(u3);
    EXPECT_EQ(conv.participants().size(), 3u);

    // Re-adding existing participant should deduplicate
    conv.add_participant(u2);
    EXPECT_EQ(conv.participants().size(), 3u);

    conv.remove_participant(u1);
    EXPECT_EQ(conv.participants().size(), 2u);
}

TEST(DomainMessageTest, PropertiesAndLifecycle) {
    const MessageId mid("msg-101");
    const ConversationId cid("conv-001");
    const UserId uid("alice");
    const DeviceId did("laptop");

    Message msg(mid, cid, uid, did, DeliveryState::LocalPending, std::chrono::system_clock::now(), "env-hash-abc", 1);
    EXPECT_EQ(msg.message_id(), mid);
    EXPECT_EQ(msg.conversation_id(), cid);
    EXPECT_EQ(msg.sender_user_id(), uid);
    EXPECT_EQ(msg.sender_device_id(), did);
    EXPECT_EQ(msg.delivery_state(), DeliveryState::LocalPending);
    EXPECT_EQ(msg.encrypted_envelope_ref(), "env-hash-abc");
    EXPECT_EQ(msg.priority(), 1);

    msg.set_delivery_state(DeliveryState::Delivered);
    EXPECT_EQ(msg.delivery_state(), DeliveryState::Delivered);
}

// Minimal mock implementation exercising application abstract interfaces
class MockGatewayClient final : public IGatewayClient {
  public:
    ClientResult<bool> probe_gateway(std::string_view /*path*/) override { return ClientResult<bool>::ok(true); }
    ClientResult<std::string> send_message(const ConversationId& /*conversation_id*/,
                                           std::string_view /*encrypted_envelope*/) override {
        return ClientResult<std::string>::ok("msg-server-assigned-id");
    }
    ClientResult<std::vector<std::string>> sync_messages(std::string_view /*cursor*/) override {
        return ClientResult<std::vector<std::string>>::ok({"msg-1", "msg-2"});
    }
    ClientResult<bool> validate_token(std::string_view token) override {
        return ClientResult<bool>::ok(!token.empty());
    }
    ClientResult<void> disconnect() override { return ClientResult<void>::ok(); }
};

TEST(ApplicationInterfacesTest, InterfacePolymorphismAndContracts) {
    std::unique_ptr<IGatewayClient> gateway = std::make_unique<MockGatewayClient>();
    const auto probe_res = gateway->probe_gateway("/health");
    ASSERT_TRUE(probe_res.is_ok());
    EXPECT_TRUE(probe_res.value());

    const auto send_res = gateway->send_message(ConversationId("c1"), "envelope-data");
    ASSERT_TRUE(send_res.is_ok());
    EXPECT_EQ(send_res.value(), "msg-server-assigned-id");

    const auto sync_res = gateway->sync_messages("cursor-0");
    ASSERT_TRUE(sync_res.is_ok());
    EXPECT_EQ(sync_res.value().size(), 2u);

    const auto val_res = gateway->validate_token("valid.token");
    ASSERT_TRUE(val_res.is_ok());
    EXPECT_TRUE(val_res.value());

    const auto disc_res = gateway->disconnect();
    EXPECT_TRUE(disc_res.is_ok());
}

} // namespace
