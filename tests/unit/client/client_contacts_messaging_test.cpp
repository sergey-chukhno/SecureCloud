#include "application/client_application.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/emergency_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/delivery_state.hpp"
#include "domain/message.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <gtest/gtest.h>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::infrastructure::adapters;

class ContactsMessagingTest : public ::testing::Test {
  protected:
    void SetUp() override {
        local_store_ = std::make_unique<MemoryLocalStore>();
        secure_storage_ = std::make_unique<MemorySecureStorage>();
        crypto_provider_ = std::make_unique<StubCryptoProvider>();
        gateway_client_ = std::make_unique<DefaultGatewayClient>(ClientConfig::create_default());

        contact_manager_ = std::make_unique<ContactManager>(*local_store_);
        messaging_manager_ = std::make_unique<MessagingManager>(*gateway_client_, *local_store_, *crypto_provider_);
        emergency_manager_ = std::make_unique<EmergencyManager>(*local_store_, *secure_storage_);
    }

    std::unique_ptr<MemoryLocalStore> local_store_;
    std::unique_ptr<MemorySecureStorage> secure_storage_;
    std::unique_ptr<StubCryptoProvider> crypto_provider_;
    std::unique_ptr<DefaultGatewayClient> gateway_client_;

    std::unique_ptr<ContactManager> contact_manager_;
    std::unique_ptr<MessagingManager> messaging_manager_;
    std::unique_ptr<EmergencyManager> emergency_manager_;
};

TEST_F(ContactsMessagingTest, ContactDomainPropertiesAndLifecycle) {
    const UserId alice("alice");
    Contact contact(alice, "Alice Liddell", KeyVerificationStatus::Unverified, "fingerprint-123", false,
                    "34567-89012-34567", "Security Officer", PresenceStatus::Online, 2);

    EXPECT_EQ(contact.user_id(), alice);
    EXPECT_EQ(contact.alias(), "Alice Liddell");
    EXPECT_EQ(contact.verification_status(), KeyVerificationStatus::Unverified);
    EXPECT_EQ(contact.identity_fingerprint(), "fingerprint-123");
    EXPECT_FALSE(contact.is_blocked());
    EXPECT_EQ(contact.safety_number(), "34567-89012-34567");
    EXPECT_EQ(contact.role_note(), "Security Officer");
    EXPECT_EQ(contact.presence_status(), PresenceStatus::Online);
    EXPECT_EQ(contact.authorized_device_count(), 2u);

    EXPECT_EQ(to_string(PresenceStatus::Online), "Online");
    EXPECT_EQ(to_string(PresenceStatus::Away), "Away");
    EXPECT_EQ(to_string(PresenceStatus::Offline), "Offline");
}

TEST_F(ContactsMessagingTest, ContactManagerCRUDAndKeyVerification) {
    const UserId bob("bob");

    // 1. Create contact
    auto create_res = contact_manager_->create_contact(bob, "Bob Builder", "11111-22222", "Architect", 3);
    ASSERT_TRUE(create_res.is_ok());
    EXPECT_EQ(create_res.value().alias(), "Bob Builder");
    EXPECT_EQ(create_res.value().safety_number(), "11111-22222");
    EXPECT_EQ(create_res.value().authorized_device_count(), 3u);

    // 2. Read contact
    auto get_res = contact_manager_->get_contact(bob);
    ASSERT_TRUE(get_res.is_ok());
    EXPECT_EQ(get_res.value().role_note(), "Architect");

    // 3. Update alias & role
    auto update_res = contact_manager_->update_contact_alias(bob, "Robert Builder", "Lead Architect");
    ASSERT_TRUE(update_res.is_ok());
    auto updated = contact_manager_->get_contact(bob).value();
    EXPECT_EQ(updated.alias(), "Robert Builder");
    EXPECT_EQ(updated.role_note(), "Lead Architect");

    // 4. Block contact
    EXPECT_TRUE(contact_manager_->set_contact_blocked(bob, true).is_ok());
    EXPECT_TRUE(contact_manager_->get_contact(bob).value().is_blocked());

    // 5. Unblock contact
    EXPECT_TRUE(contact_manager_->set_contact_blocked(bob, false).is_ok());
    EXPECT_FALSE(contact_manager_->get_contact(bob).value().is_blocked());

    // 6. ADR-008: Mark identity key changed
    EXPECT_TRUE(contact_manager_->mark_contact_key_changed(bob, "99999-88888").is_ok());
    auto key_changed_contact = contact_manager_->get_contact(bob).value();
    EXPECT_EQ(key_changed_contact.verification_status(), KeyVerificationStatus::KeyChanged);
    EXPECT_EQ(key_changed_contact.safety_number(), "99999-88888");

    // 7. Verify identity key
    EXPECT_TRUE(contact_manager_->verify_contact_key(bob, true).is_ok());
    EXPECT_EQ(contact_manager_->get_contact(bob).value().verification_status(), KeyVerificationStatus::Verified);

    // 8. Remove contact
    EXPECT_TRUE(contact_manager_->remove_contact(bob).is_ok());
    EXPECT_TRUE(contact_manager_->get_contact(bob).is_error());
}

TEST_F(ContactsMessagingTest, DirectAndGroupConversations) {
    const UserId alice("alice");
    const UserId bob("bob");
    const UserId charlie("charlie");

    // 1. Direct conversation
    auto direct_res = messaging_manager_->open_direct_conversation(alice, bob, "Direct Chat");
    ASSERT_TRUE(direct_res.is_ok());
    auto direct_conv = direct_res.value();
    EXPECT_EQ(direct_conv.type(), ConversationType::Direct);
    EXPECT_TRUE(direct_conv.has_participant(alice));
    EXPECT_TRUE(direct_conv.has_participant(bob));
    EXPECT_FALSE(direct_conv.has_participant(charlie));

    // Reopening returns existing direct conversation idempotently
    auto direct_res2 = messaging_manager_->open_direct_conversation(alice, bob);
    ASSERT_TRUE(direct_res2.is_ok());
    EXPECT_EQ(direct_res2.value().conversation_id(), direct_conv.conversation_id());

    // 2. Group conversation
    auto group_res = messaging_manager_->create_group_conversation(alice, "Crypto Response Team", {bob, charlie});
    ASSERT_TRUE(group_res.is_ok());
    auto group_conv = group_res.value();
    EXPECT_EQ(group_conv.type(), ConversationType::Group);
    EXPECT_EQ(group_conv.title(), "Crypto Response Team");
    EXPECT_EQ(group_conv.participants().size(), 3u);

    // 3. Add participant to group
    const UserId dave("dave");
    EXPECT_TRUE(messaging_manager_->add_group_participant(group_conv.conversation_id(), dave).is_ok());
    auto updated_group = messaging_manager_->get_conversation(group_conv.conversation_id()).value();
    EXPECT_EQ(updated_group.participants().size(), 4u);
    EXPECT_TRUE(updated_group.has_participant(dave));

    // 4. Remove participant from group
    EXPECT_TRUE(messaging_manager_->remove_group_participant(group_conv.conversation_id(), dave).is_ok());
    updated_group = messaging_manager_->get_conversation(group_conv.conversation_id()).value();
    EXPECT_EQ(updated_group.participants().size(), 3u);
    EXPECT_FALSE(updated_group.has_participant(dave));

    // 5. Unread count and mark read
    updated_group.set_unread_count(5);
    EXPECT_TRUE(local_store_->save_conversation(updated_group).is_ok());
    EXPECT_EQ(messaging_manager_->get_conversation(group_conv.conversation_id()).value().unread_count(), 5u);

    EXPECT_TRUE(messaging_manager_->mark_conversation_read(group_conv.conversation_id()).is_ok());
    EXPECT_EQ(messaging_manager_->get_conversation(group_conv.conversation_id()).value().unread_count(), 0u);
}

TEST_F(ContactsMessagingTest, ADR008SecurityGuardBlocksMessagingOnKeyChangedOrBlocked) {
    const UserId alice("alice");
    const UserId bob("bob");
    const DeviceId alice_dev("alice-device-1");

    // Add Bob to contact directory
    ASSERT_TRUE(contact_manager_->create_contact(bob, "Bob", "12345-67890", "Peer", 1).is_ok());

    auto conv_res = messaging_manager_->open_direct_conversation(alice, bob);
    ASSERT_TRUE(conv_res.is_ok());
    const auto cid = conv_res.value().conversation_id();

    // 1. Sending succeeds when Bob is unverified or verified
    auto send_ok = messaging_manager_->stage_outbound_message(cid, alice, alice_dev, "Hello Bob!");
    EXPECT_TRUE(send_ok.is_ok());

    // 2. Mark Bob's key changed (ADR-008 key rotation detected)
    ASSERT_TRUE(contact_manager_->mark_contact_key_changed(bob, "new-fingerprint").is_ok());

    // Outbound send MUST be blocked
    auto send_blocked = messaging_manager_->stage_outbound_message(cid, alice, alice_dev, "Should be blocked!");
    EXPECT_TRUE(send_blocked.is_error());
    EXPECT_NE(send_blocked.error().user_message().find("identity key changed"), std::string::npos);

    // 3. Verify Bob's key -> messaging unlocked
    ASSERT_TRUE(contact_manager_->verify_contact_key(bob, true).is_ok());
    auto send_unlocked = messaging_manager_->stage_outbound_message(cid, alice, alice_dev, "Unlocked message!");
    EXPECT_TRUE(send_unlocked.is_ok());

    // 4. Block Bob -> messaging blocked
    ASSERT_TRUE(contact_manager_->set_contact_blocked(bob, true).is_ok());
    auto send_blocked2 = messaging_manager_->stage_outbound_message(cid, alice, alice_dev, "Blocked message!");
    EXPECT_TRUE(send_blocked2.is_error());
    EXPECT_NE(send_blocked2.error().user_message().find("blocked"), std::string::npos);
}

TEST_F(ContactsMessagingTest, MessageIdempotentRetryAndEmergencyAcknowledgement) {
    const UserId alice("alice");
    const UserId bob("bob");
    const DeviceId alice_dev("alice-device-1");

    ASSERT_TRUE(contact_manager_->create_contact(bob, "Bob", "12345", "Colleague", 1).is_ok());
    auto conv = messaging_manager_->open_direct_conversation(alice, bob).value();
    const auto cid = conv.conversation_id();

    // Stage an outbound message
    auto msg_res = messaging_manager_->stage_outbound_message(cid, alice, alice_dev, "Important message",
                                                              /*priority=*/2, "Alice Liddell");
    ASSERT_TRUE(msg_res.is_ok());
    auto msg = msg_res.value();
    const std::string original_idempotency_key = msg.idempotency_key();
    EXPECT_FALSE(original_idempotency_key.empty());
    EXPECT_EQ(msg.priority(), 2);
    EXPECT_FALSE(msg.emergency_acknowledged());

    // Simulate delivery failure
    EXPECT_TRUE(
        messaging_manager_->update_message_delivery_state(cid, msg.message_id(), DeliveryState::Failed).is_ok());
    auto failed_msg = local_store_->get_message(cid, msg.message_id()).value();
    EXPECT_EQ(failed_msg.delivery_state(), DeliveryState::Failed);

    // Retry failed message
    auto retried_res = messaging_manager_->retry_failed_message(cid, msg.message_id());
    ASSERT_TRUE(retried_res.is_ok());
    EXPECT_EQ(retried_res.value().delivery_state(), DeliveryState::Accepted);
    // Crucial Invariant: idempotency key is preserved across retries
    EXPECT_EQ(retried_res.value().idempotency_key(), original_idempotency_key);
    EXPECT_EQ(retried_res.value().message_id(), msg.message_id());

    // Emergency alert acknowledgement
    EXPECT_EQ(emergency_manager_->unacknowledged_emergency_count(cid), 1u);
    EXPECT_TRUE(emergency_manager_->acknowledge_emergency_message(cid, msg.message_id(), bob).is_ok());
    EXPECT_EQ(emergency_manager_->unacknowledged_emergency_count(cid), 0u);

    auto acked_msg = local_store_->get_message(cid, msg.message_id()).value();
    EXPECT_TRUE(acked_msg.emergency_acknowledged());
}

TEST(WorkspaceViewModelGroupAndRetryTest, GroupConversationsAndRosterManagement) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    ui::NavigationController navController;
    navController.setAuthenticated(true);
    ui::WorkspaceViewModel workspace(app, navController);

    // 1. Initial seeded state: Frances is direct, SecOps is group
    workspace.selectConversation(QStringLiteral("conv-frances"));
    EXPECT_FALSE(workspace.selectedConversationIsGroup());
    EXPECT_EQ(workspace.selectedConversationParticipantCount(), 2);

    workspace.selectConversation(QStringLiteral("conv-secops"));
    EXPECT_TRUE(workspace.selectedConversationIsGroup());
    EXPECT_EQ(workspace.selectedConversationParticipantCount(), 4);
    EXPECT_GT(workspace.selectedConversationDeviceFanoutCount(), 0);
    EXPECT_FALSE(workspace.selectedConversationParticipants().isEmpty());

    // 2. Add and Remove participant from active group
    EXPECT_TRUE(workspace.addParticipantToActiveGroup(QStringLiteral("corina.mccoy@securecloud.org")));
    EXPECT_EQ(workspace.selectedConversationParticipantCount(), 5);

    EXPECT_TRUE(workspace.removeParticipantFromActiveGroup(QStringLiteral("corina.mccoy@securecloud.org")));
    EXPECT_EQ(workspace.selectedConversationParticipantCount(), 4);

    // 3. Create a new group conversation
    const QString newGid = workspace.createGroupConversation(
        QStringLiteral("Frontend Strike Team"),
        {QStringLiteral("frances.swann@securecloud.org"), QStringLiteral("daniel.hamilton@securecloud.org")});
    EXPECT_FALSE(newGid.isEmpty());
    workspace.selectConversation(newGid);
    EXPECT_TRUE(workspace.selectedConversationIsGroup());
    EXPECT_EQ(workspace.selectedPeerName(), QStringLiteral("Frontend Strike Team"));
    // Creator (operator) + 2 invited members = 3 participants
    EXPECT_EQ(workspace.selectedConversationParticipantCount(), 3);

    // 4. Leave active group
    EXPECT_TRUE(workspace.leaveActiveGroup());
}

TEST(WorkspaceViewModelGroupAndRetryTest, ContactsCRUDAndKeyVerificationWorkflow) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    ui::NavigationController navController;
    navController.setAuthenticated(true);
    ui::WorkspaceViewModel workspace(app, navController);

    // 1. Add contact
    const qsizetype initialContactCount = workspace.contacts().size();
    EXPECT_TRUE(workspace.addContact(QStringLiteral("@eve.auditor"), QStringLiteral("Eve Auditor"),
                                     QStringLiteral("External Red Team"), QStringLiteral("55555-44444")));
    EXPECT_EQ(workspace.contacts().size(), initialContactCount + 1);

    // 2. Update contact profile
    EXPECT_TRUE(workspace.updateContactProfile(QStringLiteral("eve.auditor@securecloud.org"),
                                               QStringLiteral("Eve Vance"), QStringLiteral("Senior Auditor")));

    // 3. Key change simulation and non-bypassable warning flag
    workspace.selectContact(QStringLiteral("frances.swann@securecloud.org"));
    EXPECT_FALSE(workspace.selectedPeerKeyChanged());

    workspace.simulatePeerKeyChange(QStringLiteral("frances.swann@securecloud.org"));
    EXPECT_TRUE(workspace.selectedPeerKeyChanged());
    EXPECT_FALSE(workspace.selectedPeerKeyChangedHandle().isEmpty());

    // Outbound messaging must be blocked
    EXPECT_FALSE(workspace.sendMessage(QStringLiteral("Should fail due to key change")));

    // Verify key clears the warning
    workspace.acceptAndVerifyPeerKey(QStringLiteral("frances.swann@securecloud.org"));
    EXPECT_FALSE(workspace.selectedPeerKeyChanged());
    EXPECT_TRUE(workspace.sendMessage(QStringLiteral("Key verified, hello Frances!")));

    // 4. Remove contact
    EXPECT_TRUE(workspace.removeContact(QStringLiteral("eve.auditor@securecloud.org")));
    EXPECT_EQ(workspace.contacts().size(), initialContactCount);
}

TEST(WorkspaceViewModelGroupAndRetryTest, DeliveryFailureRetryAndEmergencyAcknowledgement) {
    const auto config = ClientConfig::create_default();
    ClientApplication app(config);
    ASSERT_TRUE(app.initialize().is_ok());

    ui::NavigationController navController;
    navController.setAuthenticated(true);
    ui::WorkspaceViewModel workspace(app, navController);

    workspace.selectConversation(QStringLiteral("conv-frances"));

    // 1. Simulate delivery failure
    workspace.setSimulateDeliveryFailure(true);
    EXPECT_TRUE(workspace.deliveryFailureSimulated());

    const qsizetype initialCount = workspace.activeMessages().size();
    EXPECT_TRUE(workspace.sendMessage(QStringLiteral("Testing failure pipeline"), 2));
    EXPECT_EQ(workspace.activeMessages().size(), initialCount + 1);

    const auto lastMsg = workspace.activeMessages().last().toMap();
    EXPECT_EQ(lastMsg.value(QStringLiteral("deliveryState")).toString(), QStringLiteral("Failed"));
    const QString failedMsgId = lastMsg.value(QStringLiteral("messageId")).toString();
    const QString idemKey = lastMsg.value(QStringLiteral("idempotencyKey")).toString();

    // 2. Turn off simulation and retry
    workspace.setSimulateDeliveryFailure(false);
    EXPECT_FALSE(workspace.deliveryFailureSimulated());

    EXPECT_TRUE(workspace.retryFailedMessage(failedMsgId));
    const auto retriedMsg = workspace.activeMessages().last().toMap();
    EXPECT_EQ(retriedMsg.value(QStringLiteral("deliveryState")).toString(), QStringLiteral("Delivered"));
    EXPECT_EQ(retriedMsg.value(QStringLiteral("idempotencyKey")).toString(), idemKey);

    // 3. Emergency message & acknowledgement
    workspace.selectConversation(QStringLiteral("conv-angelina"));
    EXPECT_GT(workspace.unacknowledgedEmergencyCount(), 0);

    const auto angelinaMsgs = workspace.activeMessages();
    QString emergencyMsgId;
    for (const auto& item : angelinaMsgs) {
        const auto map = item.toMap();
        if (map.value(QStringLiteral("priority")).toInt() == 3 &&
            !map.value(QStringLiteral("emergencyAcknowledged")).toBool()) {
            emergencyMsgId = map.value(QStringLiteral("messageId")).toString();
            break;
        }
    }
    ASSERT_FALSE(emergencyMsgId.isEmpty());
    const int countBefore = workspace.unacknowledgedEmergencyCount();
    EXPECT_TRUE(workspace.acknowledgeEmergencyMessage(emergencyMsgId));
    EXPECT_EQ(workspace.unacknowledgedEmergencyCount(), countBefore - 1);
}

} // namespace
