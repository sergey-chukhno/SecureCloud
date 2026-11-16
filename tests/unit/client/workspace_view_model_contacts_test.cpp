#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/device_id.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <QSignalSpy>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;

class WorkspaceViewModelContactsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ClientConfig config = ClientConfig::create_default();
        auto gateway = std::make_unique<DefaultGatewayClient>(config);
        gateway_ptr_ = gateway.get();

        auto local_store = std::make_unique<MemoryLocalStore>();
        auto secure_storage = std::make_unique<MemorySecureStorage>();
        auto crypto = std::make_unique<OpenSslCryptoProvider>();

        auto bootstrap = ClientBootstrap::create_with_adapters(config, std::move(gateway), std::move(local_store),
                                                               std::move(secure_storage), std::move(crypto));
        app_ = std::make_unique<ClientApplication>(std::move(bootstrap));
        ASSERT_TRUE(app_->initialize().is_ok());

        // Configure genuine Ed25519 local operator key before WorkspaceViewModel constructs
        auto& real_crypto = app_->bootstrap().crypto_provider();
        auto local_kp = real_crypto.generate_identity_keypair().value();
        local_user_id_ = domain::UserId("operator@securecloud.org");
        local_identity_key_ = std::move(local_kp.public_key);
        app_->bootstrap().contact_manager().set_local_identity(local_user_id_, local_identity_key_);

        nav_ = std::make_unique<NavigationController>();
        nav_->setAuthenticated(true);
        vm_ = std::make_unique<WorkspaceViewModel>(*app_, *nav_);
    }

    void TearDown() override {
        vm_.reset();
        nav_.reset();
        if (app_) {
            (void)app_->shutdown();
            app_.reset();
        }
    }

    DefaultGatewayClient* gateway_ptr_{nullptr};
    std::unique_ptr<ClientApplication> app_;
    std::unique_ptr<NavigationController> nav_;
    std::unique_ptr<WorkspaceViewModel> vm_;

    domain::UserId local_user_id_;
    std::vector<uint8_t> local_identity_key_;
};

TEST_F(WorkspaceViewModelContactsTest, InboundMessageFromBlockedSenderDroppedBeforeDecryption) {
    auto& cm = app_->bootstrap().contact_manager();
    auto& mm = app_->bootstrap().messaging_manager();
    auto& crypto = app_->bootstrap().crypto_provider();

    const domain::UserId bob_id("usr-bob-harass");
    const domain::DeviceId bob_dev("dev-bob-01");
    const domain::DeviceId local_dev("dev-local-01");

    ASSERT_TRUE(cm.create_contact(bob_id, "Bob Blocked", "11111 22222", "Peer", 1).is_ok());
    auto conv_res = mm.open_direct_conversation(local_user_id_, bob_id, "Bob Blocked");
    ASSERT_TRUE(conv_res.is_ok());
    const auto conv_id = conv_res.value().conversation_id();

    // Block Bob
    ASSERT_TRUE(cm.set_contact_blocked(bob_id, true).is_ok());

    // Construct a delivery payload and encrypted envelope
    domain::crypto::PerDeviceDeliveryPayload payload;
    payload.recipient_user_id = local_user_id_;
    payload.recipient_device_id = local_dev;
    payload.ciphertext_blob = "malformed-or-secret-ciphertext-should-not-decrypt";

    // 1. PerDeviceDeliveryPayload overload drops before touching crypto/ratchet decryption
    auto drop_res1 = mm.process_inbound_message(conv_id, bob_id, bob_dev, payload);
    EXPECT_TRUE(drop_res1.is_error());
    EXPECT_NE(drop_res1.error().user_message().find("sender is blocked"), std::string::npos);

    // 2. Wire RatchetSessionManager and verify EncryptedMessageEnvelope overload also drops before decryption
    app_->bootstrap().initialize_ratchet_session_manager(local_user_id_, local_dev);
    domain::crypto::EncryptedMessageEnvelope envelope;
    envelope.ratchet_message.header = domain::crypto::RatchetHeader(std::vector<uint8_t>(32, 0x01), 0, 0);
    envelope.ratchet_message.ciphertext = {0xDE, 0xAD, 0xBE, 0xEF};
    (void)crypto;

    auto drop_res2 = mm.process_inbound_message(conv_id, bob_id, bob_dev, envelope);
    EXPECT_TRUE(drop_res2.is_error());
    EXPECT_NE(drop_res2.error().user_message().find("sender is blocked"), std::string::npos);

    // Zero messages stored and unread count untouched
    auto msgs = mm.get_conversation_messages(conv_id).value();
    EXPECT_TRUE(msgs.empty());
    EXPECT_EQ(mm.get_conversation(conv_id).value().unread_count(), 0u);
}

TEST_F(WorkspaceViewModelContactsTest, AddContactByHandleDiscoversDirectoryUserAndComputesSafetyNumber) {
    auto& crypto = app_->bootstrap().crypto_provider();
    const domain::UserId eve_id("usr-eve-dir");
    auto eve_kp = crypto.generate_identity_keypair().value();
    const std::string eve_fp = crypto.compute_identity_fingerprint(eve_kp.public_key).value();

    gateway_ptr_->set_simulated_directory_users({
        domain::DirectoryUserEntry(eve_id, "@eve.dir", "Eve Directory", eve_kp.public_key, eve_fp, 2),
    });

    QSignalSpy contacts_spy(vm_.get(), &WorkspaceViewModel::contactsChanged);
    ASSERT_TRUE(vm_->addContactByHandle(QStringLiteral("@eve.dir"), QString(), QStringLiteral("External Auditor")));
    EXPECT_GE(contacts_spy.count(), 1);

    const std::string expected_sn =
        app_->bootstrap()
            .safety_number_engine()
            .compute_safety_number(local_user_id_, local_identity_key_, eve_id, eve_kp.public_key)
            .value();

    bool found_in_vm = false;
    for (const QVariant& item : vm_->contacts()) {
        const QVariantMap map = item.toMap();
        if (map.value(QStringLiteral("userId")).toString() == QStringLiteral("usr-eve-dir")) {
            found_in_vm = true;
            EXPECT_EQ(map.value(QStringLiteral("displayName")).toString(), QStringLiteral("Eve Directory"));
            EXPECT_EQ(map.value(QStringLiteral("handle")).toString(), QStringLiteral("@eve.dir"));
            EXPECT_EQ(map.value(QStringLiteral("deviceCount")).toInt(), 2);
            EXPECT_EQ(map.value(QStringLiteral("safetyNumber")).toString().toStdString(), expected_sn);
            EXPECT_EQ(map.value(QStringLiteral("safetyNumber")).toString().size(), 71);
            break;
        }
    }
    EXPECT_TRUE(found_in_vm);
}

TEST_F(WorkspaceViewModelContactsTest, BlockContactAndVerifySafetyNumberUpdateStateAndBlockMessaging) {
    auto& crypto = app_->bootstrap().crypto_provider();
    const domain::UserId sam_id("usr-sam-vm");
    auto sam_kp = crypto.generate_identity_keypair().value();
    const std::string sam_fp = crypto.compute_identity_fingerprint(sam_kp.public_key).value();

    gateway_ptr_->set_simulated_directory_users({
        domain::DirectoryUserEntry(sam_id, "@sam.ops", "Sam Ops", sam_kp.public_key, sam_fp, 1),
    });

    ASSERT_TRUE(vm_->addContactByHandle(QStringLiteral("@sam.ops")));
    vm_->selectContact(QStringLiteral("usr-sam-vm"));

    // Verify 60-digit safety number through UI action -> pins key in ISecureStorage
    ASSERT_TRUE(vm_->verifyContactSafetyNumber(QStringLiteral("usr-sam-vm"), true));
    EXPECT_EQ(app_->bootstrap().safety_number_engine().get_verified_fingerprint(sam_id).value(), sam_fp);
    EXPECT_TRUE(vm_->selectedPeerVerified());

    // Block contact through UI action -> updates UI state, masks presence Offline, suspends sendMessage()
    ASSERT_TRUE(vm_->blockContact(QStringLiteral("usr-sam-vm"), true));
    EXPECT_TRUE(vm_->selectedPeerBlocked());
    EXPECT_EQ(vm_->selectedPeerPresence(), QStringLiteral("Offline"));
    EXPECT_FALSE(vm_->sendMessage(QStringLiteral("Should fail while blocked")));

    // Unblock contact -> restores ability to send
    ASSERT_TRUE(vm_->blockContact(QStringLiteral("usr-sam-vm"), false));
    EXPECT_FALSE(vm_->selectedPeerBlocked());
    EXPECT_TRUE(vm_->sendMessage(QStringLiteral("Allowed after unblock")));
}

TEST_F(WorkspaceViewModelContactsTest, SyncContactsDetectsKeyRotationInUiAndAcknowledgeRestoresMessaging) {
    auto& crypto = app_->bootstrap().crypto_provider();
    const domain::UserId zoe_id("usr-zoe-rotate");
    auto zoe_kp_v1 = crypto.generate_identity_keypair().value();
    const std::string zoe_fp_v1 = crypto.compute_identity_fingerprint(zoe_kp_v1.public_key).value();

    gateway_ptr_->set_simulated_directory_users({
        domain::DirectoryUserEntry(zoe_id, "@zoe.sec", "Zoe Sec", zoe_kp_v1.public_key, zoe_fp_v1, 1),
    });

    ASSERT_TRUE(vm_->addContactByHandle(QStringLiteral("@zoe.sec")));
    vm_->selectContact(QStringLiteral("usr-zoe-rotate"));
    ASSERT_TRUE(vm_->verifyContactSafetyNumber(QStringLiteral("usr-zoe-rotate"), true));
    EXPECT_FALSE(vm_->selectedPeerKeyChanged());
    EXPECT_TRUE(vm_->sendMessage(QStringLiteral("Verified message v1")));

    // Rotate Zoe's directory key & simulate new encrypted keypair
    auto zoe_kp_v2 = crypto.generate_identity_keypair().value();
    const std::string zoe_fp_v2 = crypto.compute_identity_fingerprint(zoe_kp_v2.public_key).value();
    ASSERT_NE(zoe_fp_v1, zoe_fp_v2);

    gateway_ptr_->set_simulated_directory_users({
        domain::DirectoryUserEntry(zoe_id, "@zoe.sec", "Zoe Sec", zoe_kp_v2.public_key, zoe_fp_v2, 2),
    });

    // Trigger syncContacts() from UI -> KeyChangeAlertCallback + UI reconciliation runs
    vm_->syncContacts();
    EXPECT_TRUE(vm_->selectedPeerKeyChanged());
    EXPECT_EQ(vm_->selectedConversationDeviceFanoutCount(), 2);
    EXPECT_FALSE(vm_->selectedPeerVerified());
    EXPECT_FALSE(vm_->sendMessage(QStringLiteral("Suspended until key change acknowledged")));

    // Acknowledge key change in UI -> pins new fingerprint in ISecureStorage & resumes messaging
    ASSERT_TRUE(vm_->acknowledgeKeyChange(QStringLiteral("usr-zoe-rotate")));
    EXPECT_FALSE(vm_->selectedPeerKeyChanged());
    EXPECT_TRUE(vm_->selectedPeerVerified());
    EXPECT_EQ(app_->bootstrap().safety_number_engine().get_verified_fingerprint(zoe_id).value(), zoe_fp_v2);
    EXPECT_TRUE(vm_->sendMessage(QStringLiteral("Resumed after re-verification")));
}

TEST_F(WorkspaceViewModelContactsTest, BlockingPeerMasksPresenceConsistentlyAcrossContactsMessagesAndHeader) {
    auto find_presence_in = [](const QVariantList& list, const QString& peer_uid) -> QString {
        for (const QVariant& v : list) {
            const QVariantMap m = v.toMap();
            if (m.value(QStringLiteral("userId")).toString() == peer_uid ||
                m.value(QStringLiteral("peerUserId")).toString() == peer_uid) {
                return m.value(QStringLiteral("presence")).toString();
            }
        }
        return QString();
    };

    const QString frances_uid = QStringLiteral("frances.swann@securecloud.org");
    vm_->selectContact(frances_uid);

    // Initially Frances is Online in Contacts, Messages (conversations), and Chat Header / Inspector
    EXPECT_EQ(find_presence_in(vm_->contacts(), frances_uid), QStringLiteral("Online"));
    EXPECT_EQ(find_presence_in(vm_->conversations(), frances_uid), QStringLiteral("Online"));
    EXPECT_EQ(vm_->selectedPeerPresence(), QStringLiteral("Online"));

    // Toggle block via Inspector action -> Offline everywhere
    vm_->togglePeerBlocked(frances_uid);
    EXPECT_TRUE(vm_->selectedPeerBlocked());
    EXPECT_EQ(find_presence_in(vm_->contacts(), frances_uid), QStringLiteral("Offline"));
    EXPECT_EQ(find_presence_in(vm_->conversations(), frances_uid), QStringLiteral("Offline"));
    EXPECT_EQ(vm_->selectedPeerPresence(), QStringLiteral("Offline"));
    EXPECT_FALSE(vm_->sendMessage(QStringLiteral("Blocked in Messages")));

    // Toggle unblock -> Online restored everywhere
    vm_->togglePeerBlocked(frances_uid);
    EXPECT_FALSE(vm_->selectedPeerBlocked());
    EXPECT_EQ(find_presence_in(vm_->contacts(), frances_uid), QStringLiteral("Online"));
    EXPECT_EQ(find_presence_in(vm_->conversations(), frances_uid), QStringLiteral("Online"));
    EXPECT_EQ(vm_->selectedPeerPresence(), QStringLiteral("Online"));
}

} // namespace
} // namespace securecloud::client::tests
