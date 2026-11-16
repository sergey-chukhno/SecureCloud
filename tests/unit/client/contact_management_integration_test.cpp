#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/delivery_state.hpp"
#include "domain/device_id.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;
using securecloud::common::configuration::SecretString;

struct ClientWorkstation {
    domain::UserId user_id;
    domain::DeviceId device_id;
    std::vector<uint8_t> identity_public_key;
    std::string identity_fingerprint;
    interfaces::DeviceCryptoDirectoryEntry directory_entry;

    std::unique_ptr<MemorySecureStorage> secure_storage;
    std::unique_ptr<MemoryLocalStore> local_store;
    std::unique_ptr<SafetyNumberEngine> safety_engine;
    std::unique_ptr<RatchetSessionManager> ratchet_manager;
    std::unique_ptr<MessagingManager> messaging_manager;
    std::unique_ptr<ContactManager> contact_manager;
};

interfaces::DeviceCryptoDirectoryEntry make_device_directory_entry(interfaces::ICryptoProvider& crypto,
                                                                   const domain::DeviceId& device_id,
                                                                   MemorySecureStorage* storage_opt,
                                                                   std::vector<uint8_t>* pub_key_out = nullptr) {
    auto id_pair = crypto.generate_identity_keypair().value();
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key).value();
    auto otpk_pair = crypto.generate_dh_keypair().value();
    const std::string otpk_id = std::string(device_id.str()) + "-otpk-01";
    const auto id_pub = id_pair.public_key;
    const std::string fp = crypto.compute_identity_fingerprint(id_pub).value_or("");

    if (storage_opt != nullptr) {
        std::unordered_map<std::string, SecretString> otpk_privates;
        otpk_privates.emplace(otpk_id, std::move(otpk_pair.private_key));
        domain::DevicePrivateBundle priv_bundle(device_id, id_pair.public_key, std::move(id_pair.private_key),
                                                spk_res.public_key, std::move(spk_res.private_key), spk_res.signature,
                                                std::move(otpk_privates));
        KeyStorageHelper::save_bundle(*storage_opt, priv_bundle);
        storage_opt->store_secret("device.local.id", SecretString(std::string(device_id.str())));
    }

    if (pub_key_out != nullptr) {
        *pub_key_out = id_pub;
    }

    return interfaces::DeviceCryptoDirectoryEntry{
        .device_id = device_id,
        .identity_key = id_pub,
        .signed_prekey = spk_res.public_key,
        .signed_prekey_signature = spk_res.signature,
        .one_time_prekey = otpk_pair.public_key,
        .one_time_prekey_id = otpk_id,
        .status = domain::DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = fp,
        .remaining_one_time_prekeys = 1,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };
}

ClientWorkstation create_workstation(OpenSslCryptoProvider& crypto, DefaultGatewayClient& gateway,
                                     const std::string& uid_str, const std::string& did_str) {
    ClientWorkstation ws;
    ws.user_id = domain::UserId(uid_str);
    ws.device_id = domain::DeviceId(did_str);
    ws.secure_storage = std::make_unique<MemorySecureStorage>();
    ws.local_store = std::make_unique<MemoryLocalStore>();

    ws.directory_entry =
        make_device_directory_entry(crypto, ws.device_id, ws.secure_storage.get(), &ws.identity_public_key);
    ws.identity_fingerprint = ws.directory_entry.identity_key_fingerprint;

    ws.safety_engine = std::make_unique<SafetyNumberEngine>(crypto, *ws.secure_storage);
    ws.ratchet_manager =
        std::make_unique<RatchetSessionManager>(gateway, *ws.secure_storage, crypto, ws.user_id, ws.device_id);
    ws.messaging_manager =
        std::make_unique<MessagingManager>(gateway, *ws.local_store, crypto, ws.ratchet_manager.get());
    ws.contact_manager = std::make_unique<ContactManager>(*ws.local_store, gateway, *ws.safety_engine);
    ws.contact_manager->set_ratchet_session_manager(ws.ratchet_manager.get());
    ws.contact_manager->set_local_identity(ws.user_id, ws.identity_public_key);

    return ws;
}

class ContactManagementIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        crypto_ = std::make_unique<OpenSslCryptoProvider>();
        gateway_ = std::make_unique<DefaultGatewayClient>(ClientConfig::create_default());
    }

    std::unique_ptr<OpenSslCryptoProvider> crypto_;
    std::unique_ptr<DefaultGatewayClient> gateway_;
};

TEST_F(ContactManagementIntegrationTest, EndToEndDirectoryDiscoveryOnboardingAndMutualSafetyNumberVerification) {
    auto alice = create_workstation(*crypto_, *gateway_, "usr-alice-int", "dev-alice-01");
    auto bob = create_workstation(*crypto_, *gateway_, "usr-bob-int", "dev-bob-01");

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(alice.user_id, "@alice.ops", "Alice Operations", alice.identity_public_key,
                                   alice.identity_fingerprint, 1),
        domain::DirectoryUserEntry(bob.user_id, "@bob.sec", "Bob Security", bob.identity_public_key,
                                   bob.identity_fingerprint, 2),
    });
    gateway_->set_simulated_user_directory(alice.user_id, {alice.directory_entry});
    gateway_->set_simulated_user_directory(bob.user_id, {bob.directory_entry});

    // 1. Alice searches backend directory and onboards Bob with a client-owned local alias
    auto alice_search = alice.contact_manager->search_contacts("@bob.sec");
    ASSERT_TRUE(alice_search.is_ok());
    ASSERT_EQ(alice_search.value().size(), 1u);

    auto alice_bob = alice.contact_manager->add_contact_from_directory(alice_search.value()[0], "Robert (SecOps)",
                                                                       "Verified partner");
    ASSERT_TRUE(alice_bob.is_ok());
    EXPECT_EQ(alice_bob.value().alias(), "Robert (SecOps)");
    EXPECT_EQ(alice_bob.value().safety_number().size(), 71u);
    EXPECT_FALSE(alice_bob.value().is_verified());

    // 2. Bob searches backend directory and onboards Alice independently
    auto bob_search = bob.contact_manager->search_contacts("alice");
    ASSERT_TRUE(bob_search.is_ok());
    ASSERT_EQ(bob_search.value().size(), 1u);

    auto bob_alice = bob.contact_manager->add_contact_from_directory(bob_search.value()[0]);
    ASSERT_TRUE(bob_alice.is_ok());

    // 3. Commutative out-of-band 60-digit Safety Number matches symmetrically
    EXPECT_EQ(alice_bob.value().safety_number(), bob_alice.value().safety_number());
    EXPECT_EQ(alice.contact_manager->get_or_compute_safety_number(bob.user_id).value(),
              bob.contact_manager->get_or_compute_safety_number(alice.user_id).value());

    // 4. Both users confirm the 60-digit number and pin fingerprints in ISecureStorage
    ASSERT_TRUE(alice.contact_manager->set_contact_verified(bob.user_id, true).is_ok());
    ASSERT_TRUE(bob.contact_manager->set_contact_verified(alice.user_id, true).is_ok());

    EXPECT_TRUE(alice.contact_manager->get_contact(bob.user_id).value().is_verified());
    EXPECT_TRUE(bob.contact_manager->get_contact(alice.user_id).value().is_verified());
    EXPECT_EQ(alice.safety_engine->get_verified_fingerprint(bob.user_id).value(), bob.identity_fingerprint);
    EXPECT_EQ(bob.safety_engine->get_verified_fingerprint(alice.user_id).value(), alice.identity_fingerprint);
}

TEST_F(ContactManagementIntegrationTest, EndToEndIdentityKeyRotationAlertSuspensionAndRecoveryLifecycle) {
    auto alice = create_workstation(*crypto_, *gateway_, "usr-alice-krot", "dev-alice-01");
    auto bob = create_workstation(*crypto_, *gateway_, "usr-bob-krot", "dev-bob-01");

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob.user_id, "@bob.krot", "Bob KeyRot", bob.identity_public_key,
                                   bob.identity_fingerprint, 1),
    });
    gateway_->set_simulated_user_directory(bob.user_id, {bob.directory_entry});

    auto onboard_res =
        alice.contact_manager->add_contact_from_directory(gateway_->lookup_user_identity(bob.user_id).value());
    ASSERT_TRUE(onboard_res.is_ok());
    const std::string sn_v1 = onboard_res.value().safety_number();
    ASSERT_TRUE(alice.contact_manager->set_contact_verified(bob.user_id, true).is_ok());

    auto conv_res = alice.messaging_manager->open_direct_conversation(alice.user_id, bob.user_id, "Bob KeyRot");
    ASSERT_TRUE(conv_res.is_ok());
    const auto conv_id = conv_res.value().conversation_id();

    // Establish initial Double Ratchet encrypted stage + mark a Failed message for later retry check
    auto stage1 = alice.messaging_manager->stage_outbound_message(conv_id, alice.user_id, alice.device_id, "Hello v1");
    ASSERT_TRUE(stage1.is_ok());
    auto stage_fail =
        alice.messaging_manager->stage_outbound_message(conv_id, alice.user_id, alice.device_id, "Retry candidate");
    ASSERT_TRUE(stage_fail.is_ok());
    ASSERT_TRUE(
        alice.messaging_manager
            ->update_message_delivery_state(conv_id, stage_fail.value().message_id(), domain::DeliveryState::Failed)
            .is_ok());

    // Capture alert callbacks on Alice's workstation
    std::vector<std::pair<domain::UserId, std::string>> alerts;
    alice.contact_manager->set_key_change_alert_callback(
        [&alerts](const domain::UserId& uid, const std::string& sn) { alerts.emplace_back(uid, sn); });

    // Bob rotates his identity keypair on backend directory
    std::vector<uint8_t> bob_pub_v2;
    auto bob_storage_v2 = std::make_unique<MemorySecureStorage>();
    auto bob_dir_v2 = make_device_directory_entry(*crypto_, bob.device_id, bob_storage_v2.get(), &bob_pub_v2);
    const std::string bob_fp_v2 = bob_dir_v2.identity_key_fingerprint;

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob.user_id, "@bob.krot", "Bob KeyRot", bob_pub_v2, bob_fp_v2, 1),
    });
    gateway_->set_simulated_user_directory(bob.user_id, {bob_dir_v2});

    // Alice synchronizes contacts -> automated KeyChanged transition + alert dispatch + new 60-digit Safety Number
    auto sync_res = alice.contact_manager->sync_contacts();
    ASSERT_TRUE(sync_res.is_ok());
    EXPECT_EQ(sync_res.value(), 1u);

    auto bob_contact = alice.contact_manager->get_contact(bob.user_id).value();
    EXPECT_TRUE(bob_contact.has_key_changed());
    EXPECT_FALSE(bob_contact.can_send_messages());
    EXPECT_NE(bob_contact.safety_number(), sn_v1);
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].first, bob.user_id);
    EXPECT_EQ(alerts[0].second, bob_contact.safety_number());

    // ADR-008 §18 outbound messaging strictly suspended across stage, direct send, and retry
    EXPECT_TRUE(
        alice.messaging_manager->stage_outbound_message(conv_id, alice.user_id, alice.device_id, "Suspended draft")
            .is_error());
    EXPECT_TRUE(alice.messaging_manager
                    ->send_message(conv_id, alice.user_id, alice.device_id, bob.device_id, "Suspended direct")
                    .is_error());
    EXPECT_TRUE(alice.messaging_manager->retry_failed_message(conv_id, stage_fail.value().message_id()).is_error());

    // Alice acknowledges and re-verifies Bob's rotated key
    ASSERT_TRUE(alice.contact_manager->acknowledge_and_verify_key_change(bob.user_id).is_ok());
    auto recovered = alice.contact_manager->get_contact(bob.user_id).value();
    EXPECT_TRUE(recovered.is_verified());
    EXPECT_TRUE(recovered.can_send_messages());
    EXPECT_EQ(alice.safety_engine->get_verified_fingerprint(bob.user_id).value(), bob_fp_v2);

    // Outbound encrypted messaging resumes cleanly
    EXPECT_TRUE(alice.messaging_manager
                    ->stage_outbound_message(conv_id, alice.user_id, alice.device_id, "Resumed after recovery")
                    .is_ok());
}

TEST_F(ContactManagementIntegrationTest, EndToEndContactBlockingAntiHarassmentAndPresenceShield) {
    auto alice = create_workstation(*crypto_, *gateway_, "usr-alice-blk", "dev-alice-01");
    auto bob = create_workstation(*crypto_, *gateway_, "usr-bob-blk", "dev-bob-01");

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(alice.user_id, "@alice", "Alice", alice.identity_public_key,
                                   alice.identity_fingerprint, 1),
        domain::DirectoryUserEntry(bob.user_id, "@bob", "Bob", bob.identity_public_key, bob.identity_fingerprint, 1),
    });
    gateway_->set_simulated_user_directory(alice.user_id, {alice.directory_entry});
    gateway_->set_simulated_user_directory(bob.user_id, {bob.directory_entry});

    ASSERT_TRUE(
        alice.contact_manager->add_contact_from_directory(gateway_->lookup_user_identity(bob.user_id).value()).is_ok());

    // 1. ADR-008 §24 Mutual-Conversation Privacy Shield masks presence until mutual conversation exists
    EXPECT_EQ(alice.contact_manager->resolve_contact_presence(bob.user_id, domain::PresenceStatus::Online).value(),
              domain::PresenceStatus::Offline);

    // 2. Open direct conversation -> live presence resolves and Bob sends initial E2EE message cleanly
    auto alice_conv = alice.messaging_manager->open_direct_conversation(alice.user_id, bob.user_id, "Bob");
    ASSERT_TRUE(alice_conv.is_ok());
    const auto conv_id = alice_conv.value().conversation_id();

    EXPECT_EQ(alice.contact_manager->resolve_contact_presence(bob.user_id, domain::PresenceStatus::Online).value(),
              domain::PresenceStatus::Online);

    const std::string plain1 = "Legitimate initial message";
    auto env1 = bob.ratchet_manager->encrypt_for_device(alice.user_id, alice.device_id,
                                                        std::vector<uint8_t>(plain1.begin(), plain1.end()));
    ASSERT_TRUE(env1.is_ok());
    auto rx1 = alice.messaging_manager->process_inbound_message(conv_id, bob.user_id, bob.device_id, env1.value());
    ASSERT_TRUE(rx1.is_ok());
    EXPECT_EQ(alice.messaging_manager->get_conversation_messages(conv_id).value().size(), 1u);

    // 3. Alice blocks Bob -> presence masked back to Offline, outbound & inbound packets stopped
    ASSERT_TRUE(alice.contact_manager->set_contact_blocked(bob.user_id, true).is_ok());
    EXPECT_EQ(alice.contact_manager->get_contact(bob.user_id).value().presence_status(),
              domain::PresenceStatus::Offline);
    EXPECT_EQ(alice.contact_manager->resolve_contact_presence(bob.user_id, domain::PresenceStatus::Online).value(),
              domain::PresenceStatus::Offline);

    EXPECT_TRUE(alice.messaging_manager->stage_outbound_message(conv_id, alice.user_id, alice.device_id, "Blocked send")
                    .is_error());

    const std::string plain2 = "Harassing packet from blocked sender";
    auto env2 = bob.ratchet_manager->encrypt_for_device(alice.user_id, alice.device_id,
                                                        std::vector<uint8_t>(plain2.begin(), plain2.end()));
    ASSERT_TRUE(env2.is_ok());
    auto rx2 = alice.messaging_manager->process_inbound_message(conv_id, bob.user_id, bob.device_id, env2.value());
    EXPECT_TRUE(rx2.is_error());
    EXPECT_NE(rx2.error().user_message().find("sender is blocked"), std::string::npos);

    // Confirm unread count and message store did not accept the blocked packet
    EXPECT_EQ(alice.messaging_manager->get_conversation_messages(conv_id).value().size(), 1u);
    EXPECT_EQ(alice.messaging_manager->get_conversation(conv_id).value().unread_count(), 1u);
}

TEST_F(ContactManagementIntegrationTest, EndToEndMultiDeviceDirectoryReconciliationAndRevokedSessionPurge) {
    auto alice = create_workstation(*crypto_, *gateway_, "usr-alice-md", "dev-alice-01");
    const domain::UserId bob_id("usr-bob-md");
    const domain::DeviceId bob_dev1("dev-bob-workstation");
    const domain::DeviceId bob_dev2("dev-bob-tablet");
    const domain::DeviceId bob_dev3("dev-bob-phone");

    MemorySecureStorage bob_storage;
    std::vector<uint8_t> bob_pub1;
    auto entry1 = make_device_directory_entry(*crypto_, bob_dev1, &bob_storage, &bob_pub1);
    auto entry2 = make_device_directory_entry(*crypto_, bob_dev2, &bob_storage);
    auto entry3 = make_device_directory_entry(*crypto_, bob_dev3, &bob_storage);

    gateway_->set_simulated_user_directory(bob_id, {entry1, entry2, entry3});
    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob.md", "Bob MultiDevice", bob_pub1, entry1.identity_key_fingerprint, 3),
    });

    ASSERT_TRUE(
        alice.contact_manager->add_contact_from_directory(gateway_->lookup_user_identity(bob_id).value()).is_ok());

    const std::string ping = "Multi-device fanout check";
    std::vector<uint8_t> ping_bytes(ping.begin(), ping.end());

    // Fan-out encrypts across all 3 authorized Bob devices
    auto fan1 = alice.ratchet_manager->encrypt_fanout_for_participants({bob_id}, ping_bytes);
    ASSERT_TRUE(fan1.is_ok());
    EXPECT_EQ(fan1.value().size(), 3u);
    EXPECT_TRUE(alice.ratchet_manager->has_session(bob_id, bob_dev1));
    EXPECT_TRUE(alice.ratchet_manager->has_session(bob_id, bob_dev2));
    EXPECT_TRUE(alice.ratchet_manager->has_session(bob_id, bob_dev3));

    // Bob revokes tablet device on gateway
    ASSERT_TRUE(gateway_->revoke_device(bob_dev2).is_ok());

    // Alice runs sync_contacts() -> device count updated 3 -> 2 and revoked ratchet session purged
    ASSERT_TRUE(alice.contact_manager->sync_contacts().is_ok());
    EXPECT_EQ(alice.contact_manager->get_contact(bob_id).value().authorized_device_count(), 2u);
    EXPECT_TRUE(alice.ratchet_manager->has_session(bob_id, bob_dev1));
    EXPECT_FALSE(alice.ratchet_manager->has_session(bob_id, bob_dev2));
    EXPECT_TRUE(alice.ratchet_manager->has_session(bob_id, bob_dev3));

    // Subsequent fan-out targets ONLY the 2 authorized devices
    auto fan2 = alice.ratchet_manager->encrypt_fanout_for_participants({bob_id}, ping_bytes);
    ASSERT_TRUE(fan2.is_ok());
    EXPECT_EQ(fan2.value().size(), 2u);
}

TEST_F(ContactManagementIntegrationTest, EndToEndWorkspaceViewModelFullUserJourney) {
    ClientConfig config = ClientConfig::create_default();
    auto local_store = std::make_unique<MemoryLocalStore>();
    auto secure_storage = std::make_unique<MemorySecureStorage>();
    auto vm_crypto = std::make_unique<OpenSslCryptoProvider>();
    auto vm_gateway = std::make_unique<DefaultGatewayClient>(config);
    auto* gw_ptr = vm_gateway.get();

    auto bootstrap = ClientBootstrap::create_with_adapters(config, std::move(vm_gateway), std::move(local_store),
                                                           std::move(secure_storage), std::move(vm_crypto));
    ClientApplication app(std::move(bootstrap));
    ASSERT_TRUE(app.initialize().is_ok());

    auto local_kp = app.bootstrap().crypto_provider().generate_identity_keypair().value();
    app.bootstrap().contact_manager().set_local_identity(domain::UserId("operator@securecloud.org"),
                                                         local_kp.public_key);

    NavigationController nav;
    nav.setAuthenticated(true);
    WorkspaceViewModel vm(app, nav);

    const domain::UserId peer_id("usr-journey-01");
    auto kp1 = app.bootstrap().crypto_provider().generate_identity_keypair().value();
    const std::string fp1 = app.bootstrap().crypto_provider().compute_identity_fingerprint(kp1.public_key).value();
    gw_ptr->set_simulated_directory_users({
        domain::DirectoryUserEntry(peer_id, "@journey.peer", "Journey Peer", kp1.public_key, fp1, 1),
    });

    // 1. Add by handle, select, verify 60-digit safety number, and send message
    ASSERT_TRUE(vm.addContactByHandle(QStringLiteral("@journey.peer")));
    vm.selectContact(QStringLiteral("usr-journey-01"));
    EXPECT_EQ(vm.selectedPeerSafetyNumber().size(), 71);
    ASSERT_TRUE(vm.verifyContactSafetyNumber(QStringLiteral("usr-journey-01"), true));
    EXPECT_TRUE(vm.selectedPeerVerified());
    EXPECT_TRUE(vm.sendMessage(QStringLiteral("Trusted message before rotation")));

    // 2. Peer rotates identity key on server -> syncContacts() triggers KeyChanged banner and blocks send
    auto kp2 = app.bootstrap().crypto_provider().generate_identity_keypair().value();
    const std::string fp2 = app.bootstrap().crypto_provider().compute_identity_fingerprint(kp2.public_key).value();
    gw_ptr->set_simulated_directory_users({
        domain::DirectoryUserEntry(peer_id, "@journey.peer", "Journey Peer", kp2.public_key, fp2, 2),
    });

    vm.syncContacts();
    EXPECT_TRUE(vm.selectedPeerKeyChanged());
    EXPECT_FALSE(vm.sendMessage(QStringLiteral("Blocked by ADR-008")));

    // 3. Acknowledge key change -> pins new fingerprint, restores Verified, resumes sending
    ASSERT_TRUE(vm.acknowledgeKeyChange(QStringLiteral("usr-journey-01")));
    EXPECT_FALSE(vm.selectedPeerKeyChanged());
    EXPECT_TRUE(vm.selectedPeerVerified());
    EXPECT_TRUE(vm.sendMessage(QStringLiteral("Trusted message after recovery")));

    // 4. Block & remove contact cleanly
    ASSERT_TRUE(vm.blockContact(QStringLiteral("usr-journey-01"), true));
    EXPECT_EQ(vm.selectedPeerPresence(), QStringLiteral("Offline"));
    EXPECT_FALSE(vm.sendMessage(QStringLiteral("Blocked send")));
    EXPECT_TRUE(vm.removeContact(QStringLiteral("usr-journey-01")));
}

} // namespace
} // namespace securecloud::client::tests
