#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QSignalSpy>
#include <QVariantList>
#include <QVariantMap>
#include <gtest/gtest.h>
#include <memory>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;

class WorkspaceViewModelRealtimeTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ClientConfig config = ClientConfig::create_default();
        auto gateway = std::make_unique<DefaultGatewayClient>(config);
        gateway_ptr_ = gateway.get();
        auto local_store = std::make_unique<MemoryLocalStore>();
        auto secure_storage = std::make_unique<MemorySecureStorage>();
        auto crypto = std::make_unique<StubCryptoProvider>();

        auto bootstrap =
            ClientBootstrap::create_with_adapters(std::move(config), std::move(gateway), std::move(local_store),
                                                  std::move(secure_storage), std::move(crypto));
        app_ = std::make_unique<ClientApplication>(std::move(bootstrap));
        ASSERT_TRUE(app_->initialize().is_ok());
        ASSERT_TRUE(app_->start().is_ok());
        app_->bootstrap().messaging_manager().set_local_device_id(DeviceId("operator-dev-1"));
    }

    void TearDown() override {
        if (app_) {
            (void)app_->shutdown();
        }
    }

    DefaultGatewayClient* gateway_ptr_{nullptr};
    std::unique_ptr<ClientApplication> app_;
};

TEST_F(WorkspaceViewModelRealtimeTest, ReadReceiptsPropertySignalsAndPersistsInMessagingManager) {
    NavigationController nav;
    WorkspaceViewModel vm(*app_, nav);

    EXPECT_TRUE(vm.readReceiptsEnabled());
    QSignalSpy spy(&vm, &WorkspaceViewModel::readReceiptsEnabledChanged);

    vm.setReadReceiptsEnabled(false);
    EXPECT_FALSE(vm.readReceiptsEnabled());
    EXPECT_FALSE(app_->bootstrap().messaging_manager().read_receipts_enabled());
    EXPECT_EQ(spy.count(), 1);

    // Setting same value does not re-emit
    vm.setReadReceiptsEnabled(false);
    EXPECT_EQ(spy.count(), 1);

    vm.setReadReceiptsEnabled(true);
    EXPECT_TRUE(vm.readReceiptsEnabled());
    EXPECT_TRUE(app_->bootstrap().messaging_manager().read_receipts_enabled());
    EXPECT_EQ(spy.count(), 2);
}

TEST_F(WorkspaceViewModelRealtimeTest, RealtimeDeliveryAckAndReadEventsUpdateTicksViaQueuedConnection) {
    NavigationController nav;
    WorkspaceViewModel vm(*app_, nav);

    vm.selectConversation(QStringLiteral("conv-frances"));
    ASSERT_TRUE(vm.sendMessage(QStringLiteral("Live tick test")));

    const QVariantList msgs_before = vm.activeMessages();
    ASSERT_FALSE(msgs_before.isEmpty());
    const QString sent_id = msgs_before.back().toMap().value(QStringLiteral("messageId")).toString();
    EXPECT_EQ(msgs_before.back().toMap().value(QStringLiteral("deliveryState")).toString(), QStringLiteral("Accepted"));

    RealtimeEvent ack_ev;
    ack_ev.type = RealtimeEventType::DeliveryAck;
    ack_ev.conversation_id = ConversationId("conv-frances");
    ack_ev.message_id = MessageId(sent_id.toStdString());
    ack_ev.server_sequence_number = 101;
    gateway_ptr_->emit_realtime_event(ack_ev);
    QCoreApplication::processEvents();

    const QVariantList msgs_after_ack = vm.activeMessages();
    EXPECT_EQ(msgs_after_ack.back().toMap().value(QStringLiteral("deliveryState")).toString(),
              QStringLiteral("Delivered"));

    RealtimeEvent read_ev;
    read_ev.type = RealtimeEventType::ReadReceipt;
    read_ev.conversation_id = ConversationId("conv-frances");
    read_ev.message_id = MessageId(sent_id.toStdString());
    read_ev.server_sequence_number = 102;
    gateway_ptr_->emit_realtime_event(read_ev);
    QCoreApplication::processEvents();

    const QVariantList msgs_after_read = vm.activeMessages();
    EXPECT_EQ(msgs_after_read.back().toMap().value(QStringLiteral("deliveryState")).toString(), QStringLiteral("Read"));
}

TEST_F(WorkspaceViewModelRealtimeTest, SyncManagerPollRealtimeUpdatesPullsMessagesAndAdvancesCursor) {
    auto& mm = app_->bootstrap().messaging_manager();
    auto& sm = app_->bootstrap().sync_manager();

    const UserId alice("operator@securecloud.org");
    const UserId bob("bob@securecloud.org");
    const DeviceId bob_dev("bob-dev-1");
    auto conv = mm.open_direct_conversation(alice, bob, "Bob").value();

    RealtimeEvent ev;
    ev.type = RealtimeEventType::InboundDirectMessage;
    ev.conversation_id = conv.conversation_id();
    ev.message_id = MessageId("msg-polled-1");
    ev.actor_user_id = bob;
    ev.actor_device_id = bob_dev;
    ev.server_sequence_number = 55;
    ev.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_user_id = {},
        .recipient_device_id = DeviceId("operator-dev-1"),
        .ciphertext_blob = app_->bootstrap().crypto_provider().encrypt_message(bob_dev, "Polled secret").value(),
        .ephemeral_public_key = {},
        .iv = {},
        .auth_tag = {},
    };
    gateway_ptr_->set_simulated_conversation_messages(conv.conversation_id(), {ev});

    auto poll_res = sm.poll_realtime_updates(DeviceId("operator-dev-1"));
    ASSERT_TRUE(poll_res.is_ok());
    EXPECT_GE(poll_res.value(), 1u);
    EXPECT_EQ(sm.conversation_cursor(conv.conversation_id()), 55u);

    auto msgs = mm.get_conversation_messages(conv.conversation_id(), 50).value();
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].message_id(), MessageId("msg-polled-1"));
    EXPECT_EQ(msgs[0].encrypted_envelope_ref(), "Polled secret");
    EXPECT_EQ(gateway_ptr_->sent_delivery_acks().size(), 1u);
}

} // namespace
} // namespace securecloud::client::tests
