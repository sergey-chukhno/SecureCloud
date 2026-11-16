#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/ratchet_session_state.hpp"
#include "domain/device_id.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/prekey_policy.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::client::application::managers {
namespace {

using infrastructure::adapters::DefaultGatewayClient;
using infrastructure::adapters::KeyStorageHelper;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;
using infrastructure::adapters::StubCryptoProvider;
using securecloud::common::configuration::SecretString;

struct TestEndpoint {
    domain::UserId user_id;
    domain::DeviceId device_id;
    std::unique_ptr<MemorySecureStorage> storage;
    interfaces::DeviceCryptoDirectoryEntry dir_entry;
};

TestEndpoint create_endpoint(interfaces::ICryptoProvider& crypto, const std::string& uid_str,
                             const std::string& did_str, bool with_otpk = true) {
    domain::UserId uid(uid_str);
    domain::DeviceId did(did_str);
    auto storage = std::make_unique<MemorySecureStorage>();

    auto id_pair = crypto.generate_identity_keypair().value();
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key).value();

    std::unordered_map<std::string, SecretString> otpk_privates;
    std::optional<std::vector<uint8_t>> otpk_pub;
    std::string otpk_id;

    if (with_otpk) {
        auto otpk_pair = crypto.generate_dh_keypair().value();
        otpk_pub = otpk_pair.public_key;
        otpk_id = did_str + "-otpk-01";
        otpk_privates.emplace(otpk_id, std::move(otpk_pair.private_key));
    }

    domain::DevicePrivateBundle priv_bundle(did, id_pair.public_key, std::move(id_pair.private_key), spk_res.public_key,
                                            std::move(spk_res.private_key), spk_res.signature,
                                            std::move(otpk_privates));
    KeyStorageHelper::save_bundle(*storage, priv_bundle);

    interfaces::DeviceCryptoDirectoryEntry dir_entry{
        .device_id = did,
        .identity_key = id_pair.public_key,
        .signed_prekey = spk_res.public_key,
        .signed_prekey_signature = spk_res.signature,
        .one_time_prekey = otpk_pub,
        .one_time_prekey_id = otpk_id,
        .status = domain::DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = crypto.compute_identity_fingerprint(id_pair.public_key).value_or(""),
        .remaining_one_time_prekeys = with_otpk ? 1 : 0,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };

    return TestEndpoint{
        .user_id = std::move(uid),
        .device_id = std::move(did),
        .storage = std::move(storage),
        .dir_entry = std::move(dir_entry),
    };
}

TEST(RatchetSessionManagerTest, OutboundSessionEstablishmentAndInitialHandshake) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_endpoint(crypto, "usr-alice", "dev-alice-phone");
    auto bob = create_endpoint(crypto, "usr-bob", "dev-bob-phone");

    gateway.set_simulated_directory({bob.dir_entry});

    RatchetSessionManager alice_mgr(gateway, *alice.storage, crypto, alice.user_id, alice.device_id);
    RatchetSessionManager bob_mgr(gateway, *bob.storage, crypto, bob.user_id, bob.device_id);

    EXPECT_FALSE(alice_mgr.has_session(bob.user_id, bob.device_id));
    EXPECT_FALSE(bob_mgr.has_session(alice.user_id, alice.device_id));

    // Alice sends initial message to Bob
    const std::string text1 = "Hello Bob! First contact.";
    auto env1_res = alice_mgr.encrypt_for_device(
        bob.user_id, bob.device_id,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text1.data()), text1.size()));
    ASSERT_TRUE(env1_res.is_ok());

    const auto& env1 = env1_res.value();
    EXPECT_TRUE(env1.x3dh_header.has_value());
    EXPECT_TRUE(alice_mgr.has_session(bob.user_id, bob.device_id));

    // Bob receives and decrypts initial message
    auto dec1_res = bob_mgr.decrypt_from_device(alice.user_id, alice.device_id, env1);
    ASSERT_TRUE(dec1_res.is_ok());
    EXPECT_EQ(dec1_res.value().expose_unredacted_secret(), text1);
    EXPECT_TRUE(bob_mgr.has_session(alice.user_id, alice.device_id));

    // Verify Bob consumed the one-time prekey
    auto bob_bundle = KeyStorageHelper::load_bundle(*bob.storage, bob.device_id).value();
    EXPECT_TRUE(bob_bundle.one_time_prekey_privates().empty());

    // Alice sends subsequent message in established session
    const std::string text2 = "How is the weather today?";
    auto env2_res = alice_mgr.encrypt_for_device(
        bob.user_id, bob.device_id,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text2.data()), text2.size()));
    ASSERT_TRUE(env2_res.is_ok());

    const auto& env2 = env2_res.value();
    EXPECT_FALSE(env2.x3dh_header.has_value()); // No X3DH header in subsequent sends!

    auto dec2_res = bob_mgr.decrypt_from_device(alice.user_id, alice.device_id, env2);
    ASSERT_TRUE(dec2_res.is_ok());
    EXPECT_EQ(dec2_res.value().expose_unredacted_secret(), text2);

    // Bob replies to Alice
    gateway.set_simulated_directory({alice.dir_entry});
    const std::string reply = "Sunny and clear! All systems operational.";
    auto env_rep =
        bob_mgr
            .encrypt_for_device(alice.user_id, alice.device_id,
                                std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(reply.data()), reply.size()))
            .value();
    EXPECT_FALSE(env_rep.x3dh_header.has_value());

    auto dec_rep = alice_mgr.decrypt_from_device(bob.user_id, bob.device_id, env_rep);
    ASSERT_TRUE(dec_rep.is_ok());
    EXPECT_EQ(dec_rep.value().expose_unredacted_secret(), reply);
}

TEST(RatchetSessionManagerTest, PerDevicePayloadSerializationAndValidation) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_endpoint(crypto, "usr-alice", "dev-alice-phone");
    auto bob = create_endpoint(crypto, "usr-bob", "dev-bob-phone");

    gateway.set_simulated_directory({bob.dir_entry});

    RatchetSessionManager alice_mgr(gateway, *alice.storage, crypto, alice.user_id, alice.device_id);
    RatchetSessionManager bob_mgr(gateway, *bob.storage, crypto, bob.user_id, bob.device_id);

    const std::string secret_text = "Mission Briefing: Top Secret";
    auto payload_res = alice_mgr.encrypt_payload_for_device(
        bob.user_id, bob.device_id,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(secret_text.data()), secret_text.size()));
    ASSERT_TRUE(payload_res.is_ok());

    const auto& payload = payload_res.value();
    EXPECT_EQ(payload.recipient_user_id, bob.user_id);
    EXPECT_EQ(payload.recipient_device_id, bob.device_id);
    EXPECT_EQ(payload.algorithm, "AES-256-GCM");
    EXPECT_EQ(payload.ephemeral_public_key.size(), 32u);
    EXPECT_EQ(payload.iv.size(), 12u);
    EXPECT_EQ(payload.auth_tag.size(), 16u);
    EXPECT_FALSE(payload.ciphertext_blob.empty());

    // Bob decrypts from PerDeviceDeliveryPayload
    auto dec_res = bob_mgr.decrypt_payload_from_device(alice.user_id, alice.device_id, payload);
    ASSERT_TRUE(dec_res.is_ok());
    EXPECT_EQ(dec_res.value().expose_unredacted_secret(), secret_text);
}

TEST(RatchetSessionManagerTest, MultiDeviceFanOut) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_endpoint(crypto, "usr-alice", "dev-alice-phone");
    auto bob1 = create_endpoint(crypto, "usr-bob", "dev-bob-phone");
    auto bob2 = create_endpoint(crypto, "usr-bob", "dev-bob-laptop");
    auto alice_comp = create_endpoint(crypto, "usr-alice", "dev-alice-desktop");

    gateway.set_simulated_user_directory(bob1.user_id, {bob1.dir_entry, bob2.dir_entry});
    gateway.set_simulated_user_directory(alice.user_id, {alice.dir_entry, alice_comp.dir_entry});

    RatchetSessionManager alice_mgr(gateway, *alice.storage, crypto, alice.user_id, alice.device_id);
    RatchetSessionManager bob1_mgr(gateway, *bob1.storage, crypto, bob1.user_id, bob1.device_id);
    RatchetSessionManager bob2_mgr(gateway, *bob2.storage, crypto, bob2.user_id, bob2.device_id);
    RatchetSessionManager alice_comp_mgr(gateway, *alice_comp.storage, crypto, alice_comp.user_id,
                                         alice_comp.device_id);

    const std::string broadcast_text = "Urgent announcement: Protocol update scheduled.";
    std::span<const uint8_t> plain_span(reinterpret_cast<const uint8_t*>(broadcast_text.data()), broadcast_text.size());

    // Fan-out to Bob and Alice's companion device
    auto fanout_res = alice_mgr.encrypt_fanout_for_participants({alice.user_id, bob1.user_id}, plain_span);
    ASSERT_TRUE(fanout_res.is_ok());

    const auto& payloads = fanout_res.value();
    EXPECT_EQ(payloads.size(), 3u); // Bob Phone, Bob Laptop, Alice Desktop (Alice phone omitted self)

    // Decrypt on Bob Phone
    auto dec_b1 = bob1_mgr.decrypt_payload_from_device(alice.user_id, alice.device_id, payloads[1]);
    ASSERT_TRUE(dec_b1.is_ok());
    EXPECT_EQ(dec_b1.value().expose_unredacted_secret(), broadcast_text);

    // Decrypt on Bob Laptop
    auto dec_b2 = bob2_mgr.decrypt_payload_from_device(alice.user_id, alice.device_id, payloads[2]);
    ASSERT_TRUE(dec_b2.is_ok());
    EXPECT_EQ(dec_b2.value().expose_unredacted_secret(), broadcast_text);

    // Decrypt on Alice Companion Desktop
    auto dec_ac = alice_comp_mgr.decrypt_payload_from_device(alice.user_id, alice.device_id, payloads[0]);
    ASSERT_TRUE(dec_ac.is_ok());
    EXPECT_EQ(dec_ac.value().expose_unredacted_secret(), broadcast_text);
}

TEST(RatchetSessionManagerTest, PersistenceAndRestartResumption) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_endpoint(crypto, "usr-alice", "dev-alice-phone");
    auto bob = create_endpoint(crypto, "usr-bob", "dev-bob-phone");

    gateway.set_simulated_directory({bob.dir_entry});

    // Session 1: establish and send 2 messages
    {
        RatchetSessionManager alice_mgr(gateway, *alice.storage, crypto, alice.user_id, alice.device_id);
        RatchetSessionManager bob_mgr(gateway, *bob.storage, crypto, bob.user_id, bob.device_id);

        const std::string m1 = "Message 1 before client restart";
        auto env1 =
            alice_mgr
                .encrypt_for_device(bob.user_id, bob.device_id,
                                    std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m1.data()), m1.size()))
                .value();
        EXPECT_EQ(bob_mgr.decrypt_from_device(alice.user_id, alice.device_id, env1).value().expose_unredacted_secret(),
                  m1);

        const std::string m2 = "Message 2 before client restart";
        auto env2 =
            alice_mgr
                .encrypt_for_device(bob.user_id, bob.device_id,
                                    std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m2.data()), m2.size()))
                .value();
        EXPECT_EQ(bob_mgr.decrypt_from_device(alice.user_id, alice.device_id, env2).value().expose_unredacted_secret(),
                  m2);

        EXPECT_EQ(alice_mgr.active_session_count(), 1u);
        EXPECT_EQ(bob_mgr.active_session_count(), 1u);
    } // Both session managers destroyed!

    // Session 2: simulate application relaunch with same storage
    {
        RatchetSessionManager alice_reborn(gateway, *alice.storage, crypto, alice.user_id, alice.device_id);
        RatchetSessionManager bob_reborn(gateway, *bob.storage, crypto, bob.user_id, bob.device_id);

        EXPECT_TRUE(alice_reborn.load_all_sessions().is_ok());
        EXPECT_TRUE(bob_reborn.load_all_sessions().is_ok());

        EXPECT_EQ(alice_reborn.active_session_count(), 1u);
        EXPECT_EQ(bob_reborn.active_session_count(), 1u);

        // Send Message 3 after relaunch: must NOT need X3DH header and must continue ratcheting!
        const std::string m3 = "Message 3 after application restart!";
        auto env3 =
            alice_reborn
                .encrypt_for_device(bob.user_id, bob.device_id,
                                    std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m3.data()), m3.size()))
                .value();
        EXPECT_FALSE(env3.x3dh_header.has_value());

        auto dec3 = bob_reborn.decrypt_from_device(alice.user_id, alice.device_id, env3);
        ASSERT_TRUE(dec3.is_ok());
        EXPECT_EQ(dec3.value().expose_unredacted_secret(), m3);
    }
}

TEST(RatchetSessionManagerTest, SessionTermination) {
    OpenSslCryptoProvider crypto;
    ClientConfig config;
    DefaultGatewayClient gateway(config);

    auto alice = create_endpoint(crypto, "usr-alice", "dev-alice-phone");
    auto bob = create_endpoint(crypto, "usr-bob", "dev-bob-phone");
    gateway.set_simulated_directory({bob.dir_entry});

    RatchetSessionManager alice_mgr(gateway, *alice.storage, crypto, alice.user_id, alice.device_id);

    const std::string msg = "Ping";
    alice_mgr.encrypt_for_device(bob.user_id, bob.device_id,
                                 std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));
    EXPECT_TRUE(alice_mgr.has_session(bob.user_id, bob.device_id));

    // Terminate session
    EXPECT_TRUE(alice_mgr.terminate_session(bob.user_id, bob.device_id).is_ok());
    EXPECT_FALSE(alice_mgr.has_session(bob.user_id, bob.device_id));
    EXPECT_EQ(alice_mgr.active_session_count(), 0u);
}

} // namespace
} // namespace securecloud::client::application::managers
