#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QQmlComponent>
#include <QQmlContext>
#include <QQmlEngine>
#include <QVariantList>
#include <QVariantMap>
#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;
using namespace std::chrono_literals;

class ForwardingSecureStorage final : public ISecureStorage {
  public:
    explicit ForwardingSecureStorage(std::shared_ptr<MemorySecureStorage> inner) : inner_(std::move(inner)) {}

    ClientResult<void> store_secret(std::string_view key_id,
                                    const common::configuration::SecretString& secret) override {
        return inner_->store_secret(key_id, secret);
    }
    ClientResult<common::configuration::SecretString> get_secret(std::string_view key_id) override {
        return inner_->get_secret(key_id);
    }
    ClientResult<void> delete_secret(std::string_view key_id) override { return inner_->delete_secret(key_id); }
    ClientResult<bool> has_secret(std::string_view key_id) override { return inner_->has_secret(key_id); }
    ClientResult<std::vector<std::string>> list_secret_keys() override { return inner_->list_secret_keys(); }
    ClientResult<std::size_t> purge_all_secrets() override { return inner_->purge_all_secrets(); }

  private:
    std::shared_ptr<MemorySecureStorage> inner_;
};

struct PersistentWorkstation {
    UserId uid;
    DeviceId did;
    std::filesystem::path db_path;
    std::shared_ptr<MemorySecureStorage> shared_storage;
    std::unique_ptr<ClientApplication> app;
    DefaultGatewayClient* gateway{nullptr};
    std::vector<uint8_t> ik_pub;
    std::vector<uint8_t> spk_pub;
    std::vector<uint8_t> spk_sig;
    std::vector<uint8_t> otk_pub;
    std::string otk_id;

    PersistentWorkstation(std::string user, std::string dev, std::filesystem::path db_file)
        : uid(std::move(user)), did(std::move(dev)), db_path(std::move(db_file)),
          shared_storage(std::make_shared<MemorySecureStorage>()) {
        OpenSslCryptoProvider crypto;
        auto ik = crypto.generate_identity_keypair().value();
        auto spk = crypto.generate_signed_prekey(ik.private_key).value();
        auto otk = crypto.generate_dh_keypair().value();

        ik_pub = ik.public_key;
        spk_pub = spk.public_key;
        spk_sig = spk.signature;
        otk_pub = otk.public_key;
        otk_id = did.value() + "-otpk-01";

        std::unordered_map<std::string, common::configuration::SecretString> otk_privs;
        otk_privs.emplace(otk_id, std::move(otk.private_key));
        DevicePrivateBundle bundle(did, ik.public_key, std::move(ik.private_key), spk.public_key,
                                   std::move(spk.private_key), spk.signature, std::move(otk_privs));
        (void)KeyStorageHelper::save_bundle(*shared_storage, bundle);

        boot();
    }

    void boot() {
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = db_path.string();
        auto gw = std::make_unique<DefaultGatewayClient>(cfg);
        gateway = gw.get();
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto sec = std::make_unique<ForwardingSecureStorage>(shared_storage);
        auto sql = std::make_unique<SqlCipherLocalStore>(*shared_storage, *crypto);

        auto bootstrap = ClientBootstrap::create_with_adapters(std::move(cfg), std::move(gw), std::move(sql),
                                                               std::move(sec), std::move(crypto));
        app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(app->initialize().is_ok());
        EXPECT_TRUE(app->start().is_ok());
        app->bootstrap().initialize_ratchet_session_manager(uid, did);
    }

    void restart() {
        if (app) {
            EXPECT_TRUE(app->shutdown().is_ok());
            app.reset();
            gateway = nullptr;
        }
        boot();
    }

    DeviceCryptoDirectoryEntry directory_entry() const {
        return DeviceCryptoDirectoryEntry{
            .device_id = did,
            .identity_key = ik_pub,
            .signed_prekey = spk_pub,
            .signed_prekey_signature = spk_sig,
            .one_time_prekey = otk_pub,
            .one_time_prekey_id = otk_id,
            .status = DeviceAuthorizationStatus::Authorized,
            .identity_key_fingerprint = "",
        };
    }
};

class RealtimeDeliveryAndReceiptsIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_rt_e2e_" + suffix);
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::filesystem::path temp_dir_;
};

TEST_F(RealtimeDeliveryAndReceiptsIntegrationTest, Scenario1LivePollingToEventDeliveryAndReadTickProgression) {
    PersistentWorkstation alice("alice@securecloud.org", "alice-dev-1", temp_dir_ / "alice.db");
    PersistentWorkstation bob("bob@securecloud.org", "bob-dev-1", temp_dir_ / "bob.db");

    alice.gateway->set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway->set_simulated_user_directory(alice.uid, {alice.directory_entry()});

    auto alice_conv =
        alice.app->bootstrap().messaging_manager().open_direct_conversation(alice.uid, bob.uid, "Bob").value();
    auto bob_conv =
        bob.app->bootstrap().messaging_manager().open_direct_conversation(bob.uid, alice.uid, "Alice").value();

    NavigationController nav;
    WorkspaceViewModel alice_vm(*alice.app, nav);
    alice_vm.selectConversation(QString::fromStdString(alice_conv.conversation_id().value()));

    ASSERT_TRUE(alice_vm.sendMessage(QStringLiteral("Real-time delivery check")));
    const QVariantList initial_msgs = alice_vm.activeMessages();
    ASSERT_EQ(initial_msgs.size(), 1);
    const QString sent_msg_id = initial_msgs[0].toMap().value(QStringLiteral("messageId")).toString();
    EXPECT_EQ(initial_msgs[0].toMap().value(QStringLiteral("deliveryState")).toString(), QStringLiteral("Accepted"));

    // Relay encrypted payload from Alice's Gateway to Bob's SyncManager poll
    ASSERT_EQ(alice.gateway->submitted_fanouts().size(), 1u);
    RealtimeEvent inbound_ev;
    inbound_ev.type = RealtimeEventType::InboundDirectMessage;
    inbound_ev.conversation_id = bob_conv.conversation_id();
    inbound_ev.message_id = MessageId(sent_msg_id.toStdString());
    inbound_ev.actor_user_id = alice.uid;
    inbound_ev.actor_device_id = alice.did;
    inbound_ev.server_sequence_number = 10;
    inbound_ev.direct_payload = alice.gateway->submitted_fanouts()[0].device_payloads[0];
    bob.gateway->set_simulated_conversation_messages(bob_conv.conversation_id(), {inbound_ev});

    ASSERT_TRUE(bob.app->bootstrap().sync_manager().poll_realtime_updates(bob.did).is_ok());
    EXPECT_EQ(bob.app->bootstrap().sync_manager().conversation_cursor(bob_conv.conversation_id()), 10u);
    ASSERT_EQ(bob.gateway->sent_delivery_acks().size(), 1u);
    EXPECT_EQ(bob.gateway->sent_delivery_acks()[0].message_id, MessageId(sent_msg_id.toStdString()));

    // Alice receives DeliveryAck -> ViewModel tick advances Accepted -> Delivered
    RealtimeEvent ack_ev;
    ack_ev.type = RealtimeEventType::DeliveryAck;
    ack_ev.conversation_id = alice_conv.conversation_id();
    ack_ev.message_id = MessageId(sent_msg_id.toStdString());
    ack_ev.server_sequence_number = 10;
    alice.gateway->emit_realtime_event(ack_ev);
    QCoreApplication::processEvents();
    EXPECT_EQ(alice_vm.activeMessages()[0].toMap().value(QStringLiteral("deliveryState")).toString(),
              QStringLiteral("Delivered"));

    // Bob reads conversation -> ReadReceipt emitted -> Alice's ViewModel tick advances Delivered -> Read
    ASSERT_TRUE(bob.app->bootstrap()
                    .messaging_manager()
                    .mark_conversation_read(bob_conv.conversation_id(), bob.uid, bob.did)
                    .is_ok());
    ASSERT_EQ(bob.gateway->sent_read_receipts().size(), 1u);

    RealtimeEvent read_ev;
    read_ev.type = RealtimeEventType::ReadReceipt;
    read_ev.conversation_id = alice_conv.conversation_id();
    read_ev.message_id = MessageId(sent_msg_id.toStdString());
    read_ev.server_sequence_number = 11;
    alice.gateway->emit_realtime_event(read_ev);
    QCoreApplication::processEvents();
    EXPECT_EQ(alice_vm.activeMessages()[0].toMap().value(QStringLiteral("deliveryState")).toString(),
              QStringLiteral("Read"));
}

TEST_F(RealtimeDeliveryAndReceiptsIntegrationTest, Scenario2TransientOutageRetryWithIdempotentDeduplication) {
    PersistentWorkstation alice("alice@securecloud.org", "alice-dev-1", temp_dir_ / "alice.db");
    PersistentWorkstation bob("bob@securecloud.org", "bob-dev-1", temp_dir_ / "bob.db");

    alice.gateway->set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway->set_simulated_user_directory(alice.uid, {alice.directory_entry()});

    auto& alice_mm = alice.app->bootstrap().messaging_manager();
    RetryPolicyConfig cfg;
    cfg.initial_backoff = 20ms;
    cfg.max_backoff = 100ms;
    cfg.jitter_ratio = 0.2;
    cfg.max_attempts = 4;
    alice_mm.set_retry_policy(cfg);

    auto alice_conv = alice_mm.open_direct_conversation(alice.uid, bob.uid, "Bob").value();
    auto bob_conv =
        bob.app->bootstrap().messaging_manager().open_direct_conversation(bob.uid, alice.uid, "Alice").value();

    // Simulate transient submission outage (X3DH prekey directory lookup remains available)
    alice.gateway->set_simulated_submission_failure(true, "Simulated 503");

    auto staged =
        alice_mm.stage_outbound_message(alice_conv.conversation_id(), alice.uid, alice.did, "Idempotent retry payload");
    ASSERT_TRUE(staged.is_ok());
    EXPECT_EQ(staged.value().delivery_state(), DeliveryState::LocalPending);
    EXPECT_EQ(alice_mm.pending_retry_count(), 1u);

    // Recover network and process due retries -> preserves idempotency_key
    alice.gateway->set_simulated_submission_failure(false);
    EXPECT_EQ(alice_mm.process_retry_queue(std::chrono::steady_clock::now() + 1s), 1u);
    EXPECT_EQ(alice_mm.pending_retry_count(), 0u);
    ASSERT_EQ(alice.gateway->submitted_fanouts().size(), 1u);
    EXPECT_EQ(alice.gateway->submitted_fanouts()[0].idempotency_key, staged.value().idempotency_key());

    // Simulate at-least-once duplicate delivery to Bob -> Bob persists exactly once
    RealtimeEvent dup_ev;
    dup_ev.type = RealtimeEventType::InboundDirectMessage;
    dup_ev.conversation_id = bob_conv.conversation_id();
    dup_ev.message_id = staged.value().message_id();
    dup_ev.actor_user_id = alice.uid;
    dup_ev.actor_device_id = alice.did;
    dup_ev.server_sequence_number = 25;
    dup_ev.direct_payload = alice.gateway->submitted_fanouts()[0].device_payloads[0];

    bob.gateway->set_simulated_conversation_messages(bob_conv.conversation_id(), {dup_ev, dup_ev});
    ASSERT_TRUE(bob.app->bootstrap().sync_manager().poll_realtime_updates(bob.did).is_ok());
    EXPECT_EQ(bob.app->bootstrap()
                  .messaging_manager()
                  .get_conversation_messages(bob_conv.conversation_id(), 50)
                  .value()
                  .size(),
              1u);
    EXPECT_EQ(
        bob.app->bootstrap().messaging_manager().get_conversation(bob_conv.conversation_id()).value().unread_count(),
        1u);
}

TEST_F(RealtimeDeliveryAndReceiptsIntegrationTest, Scenario3OutOfOrderReceiptAndSequenceMonotonicity) {
    PersistentWorkstation alice("alice@securecloud.org", "alice-dev-1", temp_dir_ / "alice.db");
    PersistentWorkstation bob("bob@securecloud.org", "bob-dev-1", temp_dir_ / "bob.db");
    alice.gateway->set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway->set_simulated_user_directory(alice.uid, {alice.directory_entry()});

    auto& alice_mm = alice.app->bootstrap().messaging_manager();
    auto conv = alice_mm.open_direct_conversation(alice.uid, bob.uid, "Bob").value();
    auto msg =
        alice_mm.stage_outbound_message(conv.conversation_id(), alice.uid, alice.did, "Monotonicity check").value();

    // ReadReceipt (seq 20) arrives first
    RealtimeEvent read_ev;
    read_ev.type = RealtimeEventType::ReadReceipt;
    read_ev.conversation_id = conv.conversation_id();
    read_ev.message_id = msg.message_id();
    read_ev.server_sequence_number = 20;
    ASSERT_TRUE(alice_mm.process_inbound_realtime_event(read_ev).is_ok());

    // Late DeliveryAck (seq 15) and stale Accepted status poll must NOT regress Read or seq 20
    RealtimeEvent late_ack;
    late_ack.type = RealtimeEventType::DeliveryAck;
    late_ack.conversation_id = conv.conversation_id();
    late_ack.message_id = msg.message_id();
    late_ack.server_sequence_number = 15;
    ASSERT_TRUE(alice_mm.process_inbound_realtime_event(late_ack).is_ok());

    alice.gateway->set_simulated_delivery_status(msg.message_id(), MessageDeliveryStatusInfo{
                                                                       .message_id = msg.message_id(),
                                                                       .delivery_state = DeliveryState::Accepted,
                                                                       .server_sequence_number = 12,
                                                                   });
    ASSERT_TRUE(
        alice_mm.update_message_delivery_state(conv.conversation_id(), msg.message_id(), DeliveryState::Accepted, 12)
            .is_ok());

    auto persisted = alice.app->bootstrap().local_store().get_message(conv.conversation_id(), msg.message_id()).value();
    EXPECT_EQ(persisted.delivery_state(), DeliveryState::Read);
    EXPECT_EQ(persisted.server_sequence_number(), 20u);
}

TEST_F(RealtimeDeliveryAndReceiptsIntegrationTest, Scenario4PrivacyGatedReadReceiptsAndSettingsQmlBinding) {
    PersistentWorkstation alice("alice@securecloud.org", "alice-dev-1", temp_dir_ / "alice.db");
    PersistentWorkstation bob("bob@securecloud.org", "bob-dev-1", temp_dir_ / "bob.db");

    alice.gateway->set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway->set_simulated_user_directory(alice.uid, {alice.directory_entry()});

    auto alice_conv =
        alice.app->bootstrap().messaging_manager().open_direct_conversation(alice.uid, bob.uid, "Bob").value();
    auto bob_conv =
        bob.app->bootstrap().messaging_manager().open_direct_conversation(bob.uid, alice.uid, "Alice").value();

    NavigationController nav;
    WorkspaceViewModel bob_vm(*bob.app, nav);

    // Verify SettingsPlaceholder.qml binds readReceiptsSwitch to WorkspaceViewModel::readReceiptsEnabled
    QQmlEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &bob_vm);
    QQmlComponent settings_comp(&engine, QUrl(QStringLiteral("qrc:/qml/SettingsPlaceholder.qml")));
    ASSERT_TRUE(settings_comp.isReady()) << settings_comp.errorString().toStdString();
    std::unique_ptr<QObject> settings_obj(settings_comp.create());
    ASSERT_NE(settings_obj, nullptr);
    auto* rr_switch = settings_obj->findChild<QObject*>(QStringLiteral("readReceiptsSwitch"));
    ASSERT_NE(rr_switch, nullptr);
    EXPECT_TRUE(rr_switch->property("checked").toBool());

    // Disable read receipts via ViewModel -> QML switch reflects false & policy persists
    bob_vm.setReadReceiptsEnabled(false);
    EXPECT_FALSE(rr_switch->property("checked").toBool());
    EXPECT_FALSE(bob.app->bootstrap().messaging_manager().read_receipts_enabled());

    // Alice sends a real E2EE message; Bob receives via SyncManager poll
    auto sent = alice.app->bootstrap()
                    .messaging_manager()
                    .stage_outbound_message(alice_conv.conversation_id(), alice.uid, alice.did, "Private read check")
                    .value();
    ASSERT_EQ(alice.gateway->submitted_fanouts().size(), 1u);

    RealtimeEvent ev;
    ev.type = RealtimeEventType::InboundDirectMessage;
    ev.conversation_id = bob_conv.conversation_id();
    ev.message_id = sent.message_id();
    ev.actor_user_id = alice.uid;
    ev.actor_device_id = alice.did;
    ev.server_sequence_number = 1;
    ev.direct_payload = alice.gateway->submitted_fanouts()[0].device_payloads[0];
    bob.gateway->set_simulated_conversation_messages(bob_conv.conversation_id(), {ev});

    ASSERT_TRUE(bob.app->bootstrap().sync_manager().poll_realtime_updates(bob.did).is_ok());
    // Transport delivery ACK always fires
    ASSERT_EQ(bob.gateway->sent_delivery_acks().size(), 1u);

    // Reading the conversation clears local unread_count to 0, while suppressing SendReadReceipt
    ASSERT_TRUE(bob.app->bootstrap()
                    .messaging_manager()
                    .mark_conversation_read(bob_conv.conversation_id(), bob.uid, bob.did)
                    .is_ok());
    EXPECT_EQ(
        bob.app->bootstrap().messaging_manager().get_conversation(bob_conv.conversation_id()).value().unread_count(),
        0u);
    EXPECT_TRUE(bob.gateway->sent_read_receipts().empty());
}

TEST_F(RealtimeDeliveryAndReceiptsIntegrationTest, Scenario5RetryExpirationFailedAndSqlCipherRestartDurability) {
    PersistentWorkstation alice("alice@securecloud.org", "alice-dev-1", temp_dir_ / "alice.db");
    PersistentWorkstation bob("bob@securecloud.org", "bob-dev-1", temp_dir_ / "bob.db");
    alice.gateway->set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway->set_simulated_user_directory(alice.uid, {alice.directory_entry()});

    ConversationId cid("conv-expire");
    MessageId mid("msg-expire");
    {
        auto& mm = alice.app->bootstrap().messaging_manager();
        ASSERT_TRUE(mm.set_read_receipts_enabled(false).is_ok());

        RetryPolicyConfig cfg;
        cfg.initial_backoff = 10ms;
        cfg.max_backoff = 50ms;
        cfg.jitter_ratio = 0.0;
        cfg.max_attempts = 2;
        mm.set_retry_policy(cfg);

        auto conv = mm.open_direct_conversation(alice.uid, bob.uid, "Bob").value();
        cid = conv.conversation_id();
        ASSERT_TRUE(mm.stage_outbound_message(cid, alice.uid, alice.did, "Warmup").is_ok());

        alice.gateway->set_simulated_submission_failure(true, "Persistent 503");
        auto staged = mm.stage_outbound_message(cid, alice.uid, alice.did, "Will expire");
        ASSERT_TRUE(staged.is_ok());
        mid = staged.value().message_id();

        mm.process_retry_queue(std::chrono::steady_clock::now() + 1s);
        EXPECT_EQ(mm.pending_retry_count(), 0u);
        EXPECT_EQ(alice.app->bootstrap().local_store().get_message(cid, mid).value().delivery_state(),
                  DeliveryState::Failed);
    }

    // Restart Alice against SqlCipherLocalStore + persistent ISecureStorage -> Failed state & privacy policy persist
    alice.restart();
    EXPECT_FALSE(alice.app->bootstrap().messaging_manager().read_receipts_enabled());
    auto persisted = alice.app->bootstrap().local_store().get_message(cid, mid).value();
    EXPECT_EQ(persisted.delivery_state(), DeliveryState::Failed);

    // Manual retry recovers after network returns
    alice.gateway->set_simulated_user_directory(bob.uid, {bob.directory_entry()});
    alice.gateway->set_simulated_user_directory(alice.uid, {alice.directory_entry()});
    auto retried = alice.app->bootstrap().messaging_manager().retry_failed_message(cid, mid);
    ASSERT_TRUE(retried.is_ok());
    EXPECT_EQ(retried.value().idempotency_key(), persisted.idempotency_key());
}

} // namespace
} // namespace securecloud::client::tests
