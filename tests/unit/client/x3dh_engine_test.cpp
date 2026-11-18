#include "domain/crypto/x3dh_engine.hpp"
#include "domain/crypto/x3dh_models.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/prekey_bundle.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include <gtest/gtest.h>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::domain::crypto;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::application::interfaces;

DevicePrivateBundle create_test_device_bundle(ICryptoProvider& crypto, const std::string& device_id_str,
                                              std::size_t otpk_count = 5) {
    auto id_res = crypto.generate_identity_keypair();
    EXPECT_TRUE(id_res.is_ok());
    auto id_pair = std::move(id_res).value();

    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    EXPECT_TRUE(spk_res.is_ok());
    auto spk = std::move(spk_res).value();

    std::unordered_map<std::string, securecloud::common::configuration::SecretString> otpk_privates;
    if (otpk_count > 0) {
        auto otpk_res = crypto.generate_one_time_prekeys(otpk_count, 1);
        EXPECT_TRUE(otpk_res.is_ok());
        for (auto& pair : otpk_res.value()) {
            otpk_privates.emplace(pair.record.id(), std::move(pair.private_key));
        }
    }

    return DevicePrivateBundle(DeviceId(device_id_str), std::move(id_pair.public_key), std::move(id_pair.private_key),
                               std::move(spk.public_key), std::move(spk.private_key), std::move(spk.signature),
                               std::move(otpk_privates));
}

TEST(X3dhModelsTest, HeaderSerializationAndDeserializationRoundtrip) {
    DeviceId dev("device-alice-123");
    std::vector<uint8_t> id_key(PrekeyPolicy::kEd25519PublicKeySize, 0x11);
    std::vector<uint8_t> eph_key(PrekeyPolicy::kX25519PublicKeySize, 0x22);
    std::vector<uint8_t> dh_key(PrekeyPolicy::kX25519PublicKeySize, 0x33);
    std::string otpk_id = "otpk-42";

    // 1. With OTPK
    X3dhHeader header_with_otpk(dev, id_key, eph_key, dh_key, otpk_id);
    auto bytes = header_with_otpk.serialize();
    EXPECT_FALSE(bytes.empty());

    auto des_res = X3dhHeader::deserialize(bytes);
    ASSERT_TRUE(des_res.is_ok());
    const auto& restored = des_res.value();
    EXPECT_EQ(header_with_otpk, restored);
    EXPECT_EQ(restored.initiator_device_id(), dev);
    EXPECT_EQ(restored.initiator_identity_key(), id_key);
    EXPECT_EQ(restored.initiator_ephemeral_key(), eph_key);
    EXPECT_EQ(restored.initiator_dh_key(), dh_key);
    ASSERT_TRUE(restored.has_one_time_prekey());
    EXPECT_EQ(*restored.one_time_prekey_id(), otpk_id);

    // 2. Without OTPK
    X3dhHeader header_no_otpk(dev, id_key, eph_key, dh_key, std::nullopt);
    auto bytes_no_otpk = header_no_otpk.serialize();
    auto des_no_otpk_res = X3dhHeader::deserialize(bytes_no_otpk);
    ASSERT_TRUE(des_no_otpk_res.is_ok());
    EXPECT_EQ(header_no_otpk, des_no_otpk_res.value());
    EXPECT_FALSE(des_no_otpk_res.value().has_one_time_prekey());

    // 3. Corrupted / truncated buffer rejected
    EXPECT_TRUE(X3dhHeader::deserialize({}).is_error());
    std::vector<uint8_t> bad_magic = bytes;
    bad_magic[0] = 0xFF;
    EXPECT_TRUE(X3dhHeader::deserialize(bad_magic).is_error());

    std::vector<uint8_t> truncated(bytes.begin(), bytes.begin() + 10);
    EXPECT_TRUE(X3dhHeader::deserialize(truncated).is_error());
}

TEST(X3dhEngineTest, FullHandshakeParityWithDirectoryEntry) {
    OpenSslCryptoProvider crypto;

    auto alice_bundle = create_test_device_bundle(crypto, "alice-device-1", 0);
    auto bob_bundle = create_test_device_bundle(crypto, "bob-device-1", 5);

    // Build directory entry for Bob dispensing OTPK #1
    auto bob_otpk_res = crypto.generate_one_time_prekeys(1, 1);
    ASSERT_TRUE(bob_otpk_res.is_ok());
    const auto& bob_otpk_record = bob_otpk_res.value().front().record;

    // Ensure bob_bundle has the private key for OTPK #1
    bob_bundle.add_one_time_prekey("1", bob_otpk_res.value().front().private_key);

    DeviceCryptoDirectoryEntry bob_directory_entry{
        .device_id = bob_bundle.device_id(),
        .identity_key = bob_bundle.identity_public_key(),
        .signed_prekey = bob_bundle.signed_prekey_public_key(),
        .signed_prekey_signature = bob_bundle.signed_prekey_signature(),
        .one_time_prekey = bob_otpk_record.public_key(),
        .one_time_prekey_id = "1",
        .status = DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = "SHA256:FAKE",
        .remaining_one_time_prekeys = 4,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };

    // 1. Alice initiates handshake
    auto init_res = X3dhEngine::initiate_handshake(crypto, alice_bundle, bob_directory_entry);
    ASSERT_TRUE(init_res.is_ok());
    const auto& init_val = init_res.value();

    EXPECT_EQ(init_val.shared_secret.size(), PrekeyPolicy::kSharedSecretSize);
    EXPECT_EQ(init_val.header.initiator_device_id(), alice_bundle.device_id());
    ASSERT_TRUE(init_val.header.has_one_time_prekey());
    EXPECT_EQ(*init_val.header.one_time_prekey_id(), "1");

    // 2. Bob processes handshake
    auto resp_res = X3dhEngine::process_handshake(crypto, bob_bundle, init_val.header);
    ASSERT_TRUE(resp_res.is_ok());
    const auto& resp_val = resp_res.value();

    EXPECT_EQ(resp_val.shared_secret.size(), PrekeyPolicy::kSharedSecretSize);
    ASSERT_TRUE(resp_val.claimed_one_time_prekey_id.has_value());
    EXPECT_EQ(*resp_val.claimed_one_time_prekey_id, "1");

    // 3. Master Shared Secret Parity
    EXPECT_EQ(init_val.shared_secret.expose_unredacted_secret(), resp_val.shared_secret.expose_unredacted_secret());

    // 4. OTPK #1 must now be consumed and removed from Bob's bundle
    EXPECT_FALSE(bob_bundle.has_one_time_prekey("1"));
}

TEST(X3dhEngineTest, HandshakeParityWithPrekeyBundle) {
    OpenSslCryptoProvider crypto;

    auto alice_bundle = create_test_device_bundle(crypto, "alice-device-2", 0);
    auto bob_bundle = create_test_device_bundle(crypto, "bob-device-2", 3);

    std::vector<OneTimePrekeyRecord> bob_otpk_records;
    auto bob_otpk_res = crypto.generate_one_time_prekeys(2, 1);
    ASSERT_TRUE(bob_otpk_res.is_ok());
    for (auto& pair : bob_otpk_res.value()) {
        bob_bundle.add_one_time_prekey(pair.record.id(), pair.private_key);
        bob_otpk_records.push_back(std::move(pair.record));
    }

    PrekeyBundle bob_prekey_bundle(bob_bundle.identity_public_key(), bob_bundle.signed_prekey_public_key(),
                                   bob_bundle.signed_prekey_signature(), std::move(bob_otpk_records));

    // Alice initiates with chosen OTPK "2"
    auto init_res = X3dhEngine::initiate_handshake(crypto, alice_bundle, bob_prekey_bundle, "2");
    ASSERT_TRUE(init_res.is_ok());
    EXPECT_EQ(*init_res.value().header.one_time_prekey_id(), "2");

    // Bob processes
    auto resp_res = X3dhEngine::process_handshake(crypto, bob_bundle, init_res.value().header);
    ASSERT_TRUE(resp_res.is_ok());

    // Secret parity
    EXPECT_EQ(init_res.value().shared_secret.expose_unredacted_secret(),
              resp_res.value().shared_secret.expose_unredacted_secret());
    EXPECT_FALSE(bob_bundle.has_one_time_prekey("2"));
}

TEST(X3dhEngineTest, HandshakeWithoutOneTimePrekeyFallback) {
    OpenSslCryptoProvider crypto;

    auto alice_bundle = create_test_device_bundle(crypto, "alice-device-3", 0);
    auto bob_bundle = create_test_device_bundle(crypto, "bob-device-3", 0);

    DeviceCryptoDirectoryEntry bob_directory_entry{
        .device_id = bob_bundle.device_id(),
        .identity_key = bob_bundle.identity_public_key(),
        .signed_prekey = bob_bundle.signed_prekey_public_key(),
        .signed_prekey_signature = bob_bundle.signed_prekey_signature(),
        .one_time_prekey = std::nullopt,
        .one_time_prekey_id = "",
        .status = DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = "SHA256:FAKE",
        .remaining_one_time_prekeys = 0,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };

    auto init_res = X3dhEngine::initiate_handshake(crypto, alice_bundle, bob_directory_entry);
    ASSERT_TRUE(init_res.is_ok());
    EXPECT_FALSE(init_res.value().header.has_one_time_prekey());

    auto resp_res = X3dhEngine::process_handshake(crypto, bob_bundle, init_res.value().header);
    ASSERT_TRUE(resp_res.is_ok());
    EXPECT_FALSE(resp_res.value().claimed_one_time_prekey_id.has_value());

    // 3-way handshake yields identical secret
    EXPECT_EQ(init_res.value().shared_secret.expose_unredacted_secret(),
              resp_res.value().shared_secret.expose_unredacted_secret());
}

TEST(X3dhEngineTest, TamperedSignedPrekeySignatureRejected) {
    OpenSslCryptoProvider crypto;

    auto alice_bundle = create_test_device_bundle(crypto, "alice-device-4", 0);
    auto bob_bundle = create_test_device_bundle(crypto, "bob-device-4", 0);

    auto corrupted_sig = bob_bundle.signed_prekey_signature();
    corrupted_sig[0] ^= 0xFF;

    DeviceCryptoDirectoryEntry corrupted_entry{
        .device_id = bob_bundle.device_id(),
        .identity_key = bob_bundle.identity_public_key(),
        .signed_prekey = bob_bundle.signed_prekey_public_key(),
        .signed_prekey_signature = std::move(corrupted_sig),
        .one_time_prekey = std::nullopt,
        .one_time_prekey_id = "",
    };

    auto init_res = X3dhEngine::initiate_handshake(crypto, alice_bundle, corrupted_entry);
    EXPECT_TRUE(init_res.is_error());
}

TEST(X3dhEngineTest, ConsumedOtpkReplayRejected) {
    OpenSslCryptoProvider crypto;

    auto alice_bundle = create_test_device_bundle(crypto, "alice-device-5", 0);
    auto bob_bundle = create_test_device_bundle(crypto, "bob-device-5", 1);

    auto bob_otpk_res = crypto.generate_one_time_prekeys(1, 1);
    ASSERT_TRUE(bob_otpk_res.is_ok());
    bob_bundle.add_one_time_prekey("1", bob_otpk_res.value().front().private_key);

    DeviceCryptoDirectoryEntry bob_entry{
        .device_id = bob_bundle.device_id(),
        .identity_key = bob_bundle.identity_public_key(),
        .signed_prekey = bob_bundle.signed_prekey_public_key(),
        .signed_prekey_signature = bob_bundle.signed_prekey_signature(),
        .one_time_prekey = bob_otpk_res.value().front().record.public_key(),
        .one_time_prekey_id = "1",
    };

    auto init_res = X3dhEngine::initiate_handshake(crypto, alice_bundle, bob_entry);
    ASSERT_TRUE(init_res.is_ok());

    // First processing succeeds
    auto resp_res1 = X3dhEngine::process_handshake(crypto, bob_bundle, init_res.value().header);
    ASSERT_TRUE(resp_res1.is_ok());

    // Replay with same header (or same OTPK) fails because OTPK is consumed
    auto resp_res2 = X3dhEngine::process_handshake(crypto, bob_bundle, init_res.value().header);
    EXPECT_TRUE(resp_res2.is_error());
}

TEST(X3dhEngineTest, StubCryptoProviderParity) {
    StubCryptoProvider stub;

    auto alice_bundle = create_test_device_bundle(stub, "alice-stub", 0);
    auto bob_bundle = create_test_device_bundle(stub, "bob-stub", 1);

    auto bob_otpk_res = stub.generate_one_time_prekeys(1, 1);
    ASSERT_TRUE(bob_otpk_res.is_ok());
    bob_bundle.add_one_time_prekey("1", bob_otpk_res.value().front().private_key);

    DeviceCryptoDirectoryEntry bob_entry{
        .device_id = bob_bundle.device_id(),
        .identity_key = bob_bundle.identity_public_key(),
        .signed_prekey = bob_bundle.signed_prekey_public_key(),
        .signed_prekey_signature = bob_bundle.signed_prekey_signature(),
        .one_time_prekey = bob_otpk_res.value().front().record.public_key(),
        .one_time_prekey_id = "1",
    };

    auto init_res = X3dhEngine::initiate_handshake(stub, alice_bundle, bob_entry);
    ASSERT_TRUE(init_res.is_ok());

    auto resp_res = X3dhEngine::process_handshake(stub, bob_bundle, init_res.value().header);
    ASSERT_TRUE(resp_res.is_ok());

    EXPECT_EQ(init_res.value().shared_secret.expose_unredacted_secret(),
              resp_res.value().shared_secret.expose_unredacted_secret());
}

} // namespace
