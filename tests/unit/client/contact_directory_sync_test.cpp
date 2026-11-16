#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/device_id.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::client::application::managers {
namespace {

using infrastructure::adapters::DefaultGatewayClient;
using infrastructure::adapters::KeyStorageHelper;
using infrastructure::adapters::MemoryLocalStore;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;
using securecloud::common::configuration::SecretString;

struct PeerDeviceFixture {
    domain::UserId user_id;
    domain::DeviceId device_id;
    std::vector<uint8_t> identity_public_key;
    std::string identity_fingerprint;
    interfaces::DeviceCryptoDirectoryEntry directory_entry;
};

PeerDeviceFixture make_peer_device(OpenSslCryptoProvider& crypto, const domain::UserId& uid,
                                   const domain::DeviceId& did, MemorySecureStorage* peer_storage = nullptr) {
    auto id_pair = crypto.generate_identity_keypair().value();
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key).value();
    auto otpk_pair = crypto.generate_dh_keypair().value();
    const std::string otpk_id = std::string(did.str()) + "-otpk-01";

    if (peer_storage != nullptr) {
        std::unordered_map<std::string, SecretString> otpk_privates;
        otpk_privates.emplace(otpk_id, std::move(otpk_pair.private_key));
        domain::DevicePrivateBundle bundle(did, id_pair.public_key, std::move(id_pair.private_key), spk_res.public_key,
                                           std::move(spk_res.private_key), spk_res.signature, std::move(otpk_privates));
        KeyStorageHelper::save_bundle(*peer_storage, bundle);
    }

    const std::string fingerprint = crypto.compute_identity_fingerprint(id_pair.public_key).value_or("");

    interfaces::DeviceCryptoDirectoryEntry dir_entry{
        .device_id = did,
        .identity_key = id_pair.public_key,
        .signed_prekey = spk_res.public_key,
        .signed_prekey_signature = spk_res.signature,
        .one_time_prekey = otpk_pair.public_key,
        .one_time_prekey_id = otpk_id,
        .status = domain::DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = fingerprint,
        .remaining_one_time_prekeys = 1,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };

    return PeerDeviceFixture{
        .user_id = uid,
        .device_id = did,
        .identity_public_key = std::move(id_pair.public_key),
        .identity_fingerprint = fingerprint,
        .directory_entry = std::move(dir_entry),
    };
}

class ContactDirectorySyncTest : public ::testing::Test {
  protected:
    void SetUp() override {
        local_store_ = std::make_unique<MemoryLocalStore>();
        secure_storage_ = std::make_unique<MemorySecureStorage>();
        crypto_ = std::make_unique<OpenSslCryptoProvider>();
        gateway_ = std::make_unique<DefaultGatewayClient>(ClientConfig::create_default());
        safety_engine_ = std::make_unique<SafetyNumberEngine>(*crypto_, *secure_storage_);

        local_user_id_ = domain::UserId("usr-alice-local");
        local_device_id_ = domain::DeviceId("dev-alice-01");
        auto local_fixture = make_peer_device(*crypto_, local_user_id_, local_device_id_, secure_storage_.get());
        local_identity_key_ = local_fixture.identity_public_key;

        ratchet_manager_ = std::make_unique<RatchetSessionManager>(*gateway_, *secure_storage_, *crypto_,
                                                                   local_user_id_, local_device_id_);

        contact_manager_ = std::make_unique<ContactManager>(*local_store_, *gateway_, *safety_engine_);
        contact_manager_->set_ratchet_session_manager(ratchet_manager_.get());
        contact_manager_->set_local_identity(local_user_id_, local_identity_key_);
    }

    std::unique_ptr<MemoryLocalStore> local_store_;
    std::unique_ptr<MemorySecureStorage> secure_storage_;
    std::unique_ptr<OpenSslCryptoProvider> crypto_;
    std::unique_ptr<DefaultGatewayClient> gateway_;
    std::unique_ptr<SafetyNumberEngine> safety_engine_;
    std::unique_ptr<RatchetSessionManager> ratchet_manager_;
    std::unique_ptr<ContactManager> contact_manager_;

    domain::UserId local_user_id_;
    domain::DeviceId local_device_id_;
    std::vector<uint8_t> local_identity_key_;
};

TEST_F(ContactDirectorySyncTest, SearchContactsDelegatesToGatewayAndHandlesErrors) {
    // 1. Unwired manager rejects directory search gracefully
    ContactManager unwired_manager(*local_store_);
    auto unwired_res = unwired_manager.search_contacts("frances");
    EXPECT_TRUE(unwired_res.is_error());
    EXPECT_EQ(unwired_res.error().category(), ClientErrorCategory::Validation);

    // 2. Seed directory users on gateway
    const std::vector<uint8_t> key_f(32, 0x1A);
    const std::vector<uint8_t> key_b(32, 0x2B);
    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(domain::UserId("usr-frances"), "@frances.swann", "Frances Swann", key_f,
                                   "FP_FRANCES", 2),
        domain::DirectoryUserEntry(domain::UserId("usr-bob"), "@bob.jones", "Bob Jones", key_b, "FP_BOB", 1),
    });

    auto search_res = contact_manager_->search_contacts("frances");
    ASSERT_TRUE(search_res.is_ok());
    ASSERT_EQ(search_res.value().size(), 1u);
    EXPECT_EQ(search_res.value()[0].user_id(), domain::UserId("usr-frances"));

    // 3. Gateway network error propagates cleanly
    gateway_->set_simulated_failure(true, "Directory unreachable");
    auto fail_res = contact_manager_->search_contacts("bob");
    EXPECT_TRUE(fail_res.is_error());
    EXPECT_EQ(fail_res.error().category(), ClientErrorCategory::Network);
}

TEST_F(ContactDirectorySyncTest, AddContactFromDirectoryComputesSafetyNumberAndPersists) {
    const domain::UserId bob_id("usr-bob-02");
    auto bob_keypair = crypto_->generate_identity_keypair().value();
    const std::string bob_fp = crypto_->compute_identity_fingerprint(bob_keypair.public_key).value();

    const domain::DirectoryUserEntry bob_entry(bob_id, "@bob.jones", "Bob Jones", bob_keypair.public_key, bob_fp, 3);

    // 1. Onboard using display_name fallback (no custom local alias)
    auto add_res = contact_manager_->add_contact_from_directory(bob_entry, "", "Security Engineer");
    ASSERT_TRUE(add_res.is_ok());
    const auto& added = add_res.value();

    EXPECT_EQ(added.user_id(), bob_id);
    EXPECT_EQ(added.alias(), "Bob Jones");
    EXPECT_EQ(added.role_note(), "Security Engineer");
    EXPECT_EQ(added.identity_fingerprint(), bob_fp);
    EXPECT_EQ(added.authorized_device_count(), 3u);
    EXPECT_EQ(added.verification_status(), domain::KeyVerificationStatus::Unverified);
    EXPECT_EQ(added.presence_status(), domain::PresenceStatus::Offline);

    // Safety number must match SafetyNumberEngine formatted 60-digit output (71 chars = 12 blocks + 11 spaces)
    const auto expected_sn =
        safety_engine_->compute_safety_number(local_user_id_, local_identity_key_, bob_id, bob_keypair.public_key)
            .value();
    EXPECT_EQ(added.safety_number(), expected_sn);
    EXPECT_EQ(added.safety_number().size(), 71u);

    // Confirm persisted in ILocalStore
    auto stored_res = contact_manager_->get_contact(bob_id);
    ASSERT_TRUE(stored_res.is_ok());
    EXPECT_EQ(stored_res.value().safety_number(), expected_sn);

    // 2. Custom local alias overrides display_name and remains strictly local
    const domain::UserId carol_id("usr-carol-03");
    auto carol_keypair = crypto_->generate_identity_keypair().value();
    const domain::DirectoryUserEntry carol_entry(carol_id, "@carol.d", "", carol_keypair.public_key, "FP_CAROL", 1);

    auto carol_res = contact_manager_->add_contact_from_directory(carol_entry, "Carol (HQ)", "Ops");
    ASSERT_TRUE(carol_res.is_ok());
    EXPECT_EQ(carol_res.value().alias(), "Carol (HQ)");
}

TEST_F(ContactDirectorySyncTest, SyncContactsUpdatesDeviceCountAndPurgesRevokedRatchetSessions) {
    const domain::UserId bob_id("usr-bob-sync");
    const domain::DeviceId bob_dev1("dev-bob-workstation");
    const domain::DeviceId bob_dev2("dev-bob-handset");

    auto bob_fix1 = make_peer_device(*crypto_, bob_id, bob_dev1);
    auto bob_fix2 = make_peer_device(*crypto_, bob_id, bob_dev2);

    // Setup initial directory with 2 authorized devices
    gateway_->set_simulated_user_directory(bob_id, {bob_fix1.directory_entry, bob_fix2.directory_entry});

    const domain::DirectoryUserEntry bob_user(bob_id, "@bob", "Bob Sync", bob_fix1.identity_public_key,
                                              bob_fix1.identity_fingerprint, 2);
    ASSERT_TRUE(contact_manager_->add_contact_from_directory(bob_user).is_ok());

    // Establish Double Ratchet sessions for BOTH devices
    const std::string ping_msg = "Hello Bob";
    std::vector<uint8_t> ping_bytes(ping_msg.begin(), ping_msg.end());
    ASSERT_TRUE(ratchet_manager_->encrypt_for_device(bob_id, bob_dev1, ping_bytes).is_ok());
    ASSERT_TRUE(ratchet_manager_->encrypt_for_device(bob_id, bob_dev2, ping_bytes).is_ok());
    EXPECT_TRUE(ratchet_manager_->has_session(bob_id, bob_dev1));
    EXPECT_TRUE(ratchet_manager_->has_session(bob_id, bob_dev2));

    // Peer revokes bob_dev2 remotely
    ASSERT_TRUE(gateway_->revoke_device(bob_dev2).is_ok());

    // Run sync_contacts()
    auto sync_res = contact_manager_->sync_contacts();
    ASSERT_TRUE(sync_res.is_ok());
    EXPECT_EQ(sync_res.value(), 1u);

    // Verify contact device count updated from 2 -> 1
    auto updated_contact = contact_manager_->get_contact(bob_id).value();
    EXPECT_EQ(updated_contact.authorized_device_count(), 1u);

    // Verify revoked device Double Ratchet session was purged while authorized device session stayed active
    EXPECT_TRUE(ratchet_manager_->has_session(bob_id, bob_dev1));
    EXPECT_FALSE(ratchet_manager_->has_session(bob_id, bob_dev2));
}

TEST_F(ContactDirectorySyncTest, MutualConversationPrivacyShieldMasksPresenceUntilSharedConversationExists) {
    const domain::UserId dan_id("usr-dan-shield");
    auto dan_keypair = crypto_->generate_identity_keypair().value();
    const domain::DirectoryUserEntry dan_entry(dan_id, "@dan", "Dan Shield", dan_keypair.public_key, "FP_DAN", 2);

    ASSERT_TRUE(contact_manager_->add_contact_from_directory(dan_entry).is_ok());

    // 1. Without a mutual conversation in ILocalStore, ADR-008 §24 masks Online -> Offline
    auto shielded_res = contact_manager_->resolve_contact_presence(dan_id, domain::PresenceStatus::Online);
    ASSERT_TRUE(shielded_res.is_ok());
    EXPECT_EQ(shielded_res.value(), domain::PresenceStatus::Offline);

    auto stored_before = contact_manager_->get_contact(dan_id).value();
    EXPECT_EQ(stored_before.presence_status(), domain::PresenceStatus::Offline);
    EXPECT_FALSE(stored_before.last_seen_at().has_value());

    // 2. Establish a mutual conversation between local user and Dan
    domain::Conversation shared_conv(domain::ConversationId("conv-dan-local"), domain::ConversationType::Direct,
                                     "Dan Shield", {local_user_id_, dan_id});
    ASSERT_TRUE(local_store_->save_conversation(shared_conv).is_ok());

    // Now Online presence resolves and records last_seen_at
    auto exposed_res = contact_manager_->resolve_contact_presence(dan_id, domain::PresenceStatus::Online);
    ASSERT_TRUE(exposed_res.is_ok());
    EXPECT_EQ(exposed_res.value(), domain::PresenceStatus::Online);

    auto stored_after = contact_manager_->get_contact(dan_id).value();
    EXPECT_EQ(stored_after.presence_status(), domain::PresenceStatus::Online);
    EXPECT_TRUE(stored_after.last_seen_at().has_value());

    // 3. Blocking the contact immediately re-enables the privacy shield
    ASSERT_TRUE(contact_manager_->set_blocked(dan_id, true).is_ok());
    EXPECT_EQ(contact_manager_->get_contact(dan_id).value().presence_status(), domain::PresenceStatus::Offline);

    auto blocked_res = contact_manager_->resolve_contact_presence(dan_id, domain::PresenceStatus::Away);
    ASSERT_TRUE(blocked_res.is_ok());
    EXPECT_EQ(blocked_res.value(), domain::PresenceStatus::Offline);

    // 4. Unblocking with 0 authorized devices keeps presence shielded Offline
    ASSERT_TRUE(contact_manager_->set_blocked(dan_id, false).is_ok());
    auto c = contact_manager_->get_contact(dan_id).value();
    c.set_authorized_device_count(0);
    ASSERT_TRUE(contact_manager_->add_or_update_contact(c).is_ok());

    auto zero_dev_res = contact_manager_->resolve_contact_presence(dan_id, domain::PresenceStatus::Online);
    ASSERT_TRUE(zero_dev_res.is_ok());
    EXPECT_EQ(zero_dev_res.value(), domain::PresenceStatus::Offline);
}

TEST_F(ContactDirectorySyncTest, ClientBootstrapWiresContactManagerDependencies) {
    auto bootstrap = std::make_unique<ClientBootstrap>(ClientConfig::create_default());
    bootstrap->initialize_ratchet_session_manager(local_user_id_, local_device_id_);

    // Calling search_contacts through bootstrap's ContactManager proves gateway_ was wired
    auto search_res = bootstrap->contact_manager().search_contacts("anyone");
    EXPECT_TRUE(search_res.is_ok());
    EXPECT_TRUE(search_res.value().empty());
}

} // namespace
} // namespace securecloud::client::application::managers
