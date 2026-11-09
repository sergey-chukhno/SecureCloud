#include "domain/device_private_bundle.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <sstream>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;
using securecloud::common::configuration::SecretString;

TEST(DevicePrivateBundleTest, ValidConstructionAndInvariants) {
    const DeviceId did("macbook-arm64-1");
    const std::vector<uint8_t> id_pub(PrekeyPolicy::kEd25519PublicKeySize, 0x11);
    const SecretString id_priv(std::string(PrekeyPolicy::kEd25519PrivateKeySize, '\x12'));
    const std::vector<uint8_t> spk_pub(PrekeyPolicy::kX25519PublicKeySize, 0x21);
    const SecretString spk_priv(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x22'));
    const std::vector<uint8_t> spk_sig(PrekeyPolicy::kEd25519SignatureSize, 0x23);

    std::unordered_map<std::string, SecretString> otpks;
    otpks.emplace("1", SecretString(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x31')));
    otpks.emplace("2", SecretString(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x32')));

    DevicePrivateBundle bundle(did, id_pub, id_priv, spk_pub, spk_priv, spk_sig, otpks);

    EXPECT_EQ(bundle.device_id(), did);
    EXPECT_EQ(bundle.identity_public_key(), id_pub);
    EXPECT_EQ(bundle.identity_private_key(), id_priv);
    EXPECT_EQ(bundle.signed_prekey_public_key(), spk_pub);
    EXPECT_EQ(bundle.signed_prekey_private_key(), spk_priv);
    EXPECT_EQ(bundle.signed_prekey_signature(), spk_sig);
    EXPECT_EQ(bundle.one_time_prekey_count(), 2u);
    EXPECT_TRUE(bundle.has_one_time_prekey("1"));
    EXPECT_TRUE(bundle.has_one_time_prekey("2"));
    EXPECT_FALSE(bundle.has_one_time_prekey("3"));

    // Size violation checks
    const std::vector<uint8_t> bad_size_10(10, 0x00);
    const SecretString bad_priv("short");

    EXPECT_THROW(DevicePrivateBundle(DeviceId(""), id_pub, id_priv, spk_pub, spk_priv, spk_sig), std::invalid_argument);
    EXPECT_THROW(DevicePrivateBundle(did, bad_size_10, id_priv, spk_pub, spk_priv, spk_sig), std::invalid_argument);
    EXPECT_THROW(DevicePrivateBundle(did, id_pub, bad_priv, spk_pub, spk_priv, spk_sig), std::invalid_argument);
    EXPECT_THROW(DevicePrivateBundle(did, id_pub, id_priv, bad_size_10, spk_priv, spk_sig), std::invalid_argument);
    EXPECT_THROW(DevicePrivateBundle(did, id_pub, id_priv, spk_pub, bad_priv, spk_sig), std::invalid_argument);
    EXPECT_THROW(DevicePrivateBundle(did, id_pub, id_priv, spk_pub, spk_priv, bad_size_10), std::invalid_argument);
}

TEST(DevicePrivateBundleTest, OtpkLifecycleAndSignedPrekeyUpdate) {
    const DeviceId did("macbook-arm64-1");
    const std::vector<uint8_t> id_pub(PrekeyPolicy::kEd25519PublicKeySize, 0x11);
    const SecretString id_priv(std::string(PrekeyPolicy::kEd25519PrivateKeySize, '\x12'));
    const std::vector<uint8_t> spk_pub(PrekeyPolicy::kX25519PublicKeySize, 0x21);
    const SecretString spk_priv(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x22'));
    const std::vector<uint8_t> spk_sig(PrekeyPolicy::kEd25519SignatureSize, 0x23);

    std::unordered_map<std::string, SecretString> otpks;
    const SecretString otpk1_priv(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x31'));
    otpks.emplace("1", otpk1_priv);

    DevicePrivateBundle bundle(did, id_pub, id_priv, spk_pub, spk_priv, spk_sig, otpks);
    EXPECT_EQ(bundle.one_time_prekey_count(), 1u);

    // Add OTPK
    const SecretString otpk2_priv(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x32'));
    bundle.add_one_time_prekey("2", otpk2_priv);
    EXPECT_EQ(bundle.one_time_prekey_count(), 2u);
    EXPECT_TRUE(bundle.has_one_time_prekey("2"));

    // Take OTPK (removes from bundle)
    auto taken = bundle.take_one_time_prekey("1");
    ASSERT_TRUE(taken.has_value());
    EXPECT_EQ(taken.value(), otpk1_priv);
    EXPECT_FALSE(bundle.has_one_time_prekey("1"));
    EXPECT_EQ(bundle.one_time_prekey_count(), 1u);

    // Second take returns nullopt
    auto taken_again = bundle.take_one_time_prekey("1");
    EXPECT_FALSE(taken_again.has_value());

    // Update signed prekey
    const std::vector<uint8_t> new_spk_pub(PrekeyPolicy::kX25519PublicKeySize, 0x71);
    const SecretString new_spk_priv(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x72'));
    const std::vector<uint8_t> new_spk_sig(PrekeyPolicy::kEd25519SignatureSize, 0x73);

    bundle.update_signed_prekey(new_spk_pub, new_spk_priv, new_spk_sig);
    EXPECT_EQ(bundle.signed_prekey_public_key(), new_spk_pub);
    EXPECT_EQ(bundle.signed_prekey_private_key(), new_spk_priv);
    EXPECT_EQ(bundle.signed_prekey_signature(), new_spk_sig);

    // Convert to public PrekeyBundle
    auto public_bundle = bundle.to_public_bundle();
    EXPECT_EQ(public_bundle.identity_key(), id_pub);
    EXPECT_EQ(public_bundle.signed_prekey(), new_spk_pub);
    EXPECT_EQ(public_bundle.signed_prekey_signature(), new_spk_sig);
}

TEST(KeyStorageHelperTest, SerializeAndDeserializeRoundTrip) {
    OpenSslCryptoProvider crypto;

    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    auto id_pair = std::move(id_res).value();

    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    ASSERT_TRUE(spk_res.is_ok());
    auto spk_result = std::move(spk_res).value();

    auto otpk_res = crypto.generate_one_time_prekeys(5, 1);
    ASSERT_TRUE(otpk_res.is_ok());
    auto otpk_pairs = std::move(otpk_res).value();

    std::unordered_map<std::string, SecretString> otpk_privs;
    for (auto& p : otpk_pairs) {
        otpk_privs.emplace(p.record.id(), std::move(p.private_key));
    }

    const DeviceId did("macbook-roundtrip-test");
    DevicePrivateBundle bundle(did, id_pair.public_key, id_pair.private_key, spk_result.public_key,
                               spk_result.private_key, spk_result.signature, otpk_privs);

    // Serialize
    auto ser_res = KeyStorageHelper::serialize(bundle);
    ASSERT_TRUE(ser_res.is_ok());
    const auto& serialized_secret = ser_res.value();
    EXPECT_FALSE(serialized_secret.empty());

    // Deserialize
    auto deser_res = KeyStorageHelper::deserialize(serialized_secret);
    ASSERT_TRUE(deser_res.is_ok());
    const auto& restored_bundle = deser_res.value();

    EXPECT_EQ(bundle, restored_bundle);
    EXPECT_EQ(restored_bundle.device_id(), did);
    EXPECT_EQ(restored_bundle.identity_public_key(), id_pair.public_key);
    EXPECT_EQ(restored_bundle.identity_private_key(), id_pair.private_key);
    EXPECT_EQ(restored_bundle.signed_prekey_public_key(), spk_result.public_key);
    EXPECT_EQ(restored_bundle.signed_prekey_private_key(), spk_result.private_key);
    EXPECT_EQ(restored_bundle.signed_prekey_signature(), spk_result.signature);
    EXPECT_EQ(restored_bundle.one_time_prekey_count(), 5u);

    for (std::size_t i = 1; i <= 5; ++i) {
        const std::string id = std::to_string(i);
        EXPECT_TRUE(restored_bundle.has_one_time_prekey(id));
    }
}

TEST(KeyStorageHelperTest, TamperAndCorruptionResistance) {
    OpenSslCryptoProvider crypto;
    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    auto id_pair = std::move(id_res).value();
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    ASSERT_TRUE(spk_res.is_ok());
    auto spk = std::move(spk_res).value();

    const DeviceId did("device-tamper-test");
    DevicePrivateBundle bundle(did, id_pair.public_key, id_pair.private_key, spk.public_key, spk.private_key,
                               spk.signature);

    auto ser_res = KeyStorageHelper::serialize(bundle);
    ASSERT_TRUE(ser_res.is_ok());
    const std::string valid_data = ser_res.value().expose_unredacted_secret();

    // 1. Truncated data
    SecretString truncated_data(valid_data.substr(0, 10));
    EXPECT_TRUE(KeyStorageHelper::deserialize(truncated_data).is_error());

    // 2. Corrupted magic header
    std::string bad_magic = valid_data;
    bad_magic[0] = 'X';
    EXPECT_TRUE(KeyStorageHelper::deserialize(SecretString(bad_magic)).is_error());

    // 3. Corrupted format version
    std::string bad_version = valid_data;
    bad_version[4] = 0x99;
    EXPECT_TRUE(KeyStorageHelper::deserialize(SecretString(bad_version)).is_error());

    // 4. Truncated in middle of OTPK data
    std::string cut_middle = valid_data.substr(0, valid_data.size() - 15);
    EXPECT_TRUE(KeyStorageHelper::deserialize(SecretString(cut_middle)).is_error());
}

TEST(KeyStorageHelperTest, SecureStorageIntegrationAndOperations) {
    MemorySecureStorage storage;
    OpenSslCryptoProvider crypto;

    auto id_res = crypto.generate_identity_keypair();
    ASSERT_TRUE(id_res.is_ok());
    auto id_pair = std::move(id_res).value();
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    ASSERT_TRUE(spk_res.is_ok());
    auto spk = std::move(spk_res).value();

    std::unordered_map<std::string, SecretString> otpks;
    otpks.emplace("1", SecretString(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x01')));
    otpks.emplace("2", SecretString(std::string(PrekeyPolicy::kX25519PrivateKeySize, '\x02')));

    const DeviceId did("macbook-storage-test");
    DevicePrivateBundle bundle(did, id_pair.public_key, id_pair.private_key, spk.public_key, spk.private_key,
                               spk.signature, otpks);

    // Initially has no bundle
    EXPECT_FALSE(KeyStorageHelper::has_bundle(storage, did).value());

    // Save bundle
    auto save_res = KeyStorageHelper::save_bundle(storage, bundle);
    ASSERT_TRUE(save_res.is_ok());
    EXPECT_TRUE(KeyStorageHelper::has_bundle(storage, did).value());

    // Load bundle
    auto load_res = KeyStorageHelper::load_bundle(storage, did);
    ASSERT_TRUE(load_res.is_ok());
    EXPECT_EQ(bundle, load_res.value());

    // Remove one-time prekey "1"
    auto rm_res = KeyStorageHelper::remove_one_time_prekey(storage, did, "1");
    ASSERT_TRUE(rm_res.is_ok());

    auto load_after_rm = KeyStorageHelper::load_bundle(storage, did);
    ASSERT_TRUE(load_after_rm.is_ok());
    EXPECT_FALSE(load_after_rm.value().has_one_time_prekey("1"));
    EXPECT_TRUE(load_after_rm.value().has_one_time_prekey("2"));
    EXPECT_EQ(load_after_rm.value().one_time_prekey_count(), 1u);

    // Wipe device keys
    auto wipe_res = KeyStorageHelper::wipe_device_keys(storage, did);
    ASSERT_TRUE(wipe_res.is_ok());
    EXPECT_FALSE(KeyStorageHelper::has_bundle(storage, did).value());
    EXPECT_TRUE(KeyStorageHelper::load_bundle(storage, did).is_error());
}

TEST(KeyStorageHelperTest, SecretStringRedactionGuarantees) {
    const SecretString secret("super-sensitive-private-key-material");
    std::ostringstream oss;
    oss << secret;

    EXPECT_EQ(oss.str(), "[REDACTED]");
    EXPECT_EQ(oss.str().find("super-sensitive"), std::string::npos);
}

} // namespace
