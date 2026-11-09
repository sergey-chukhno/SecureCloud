#include "application/managers/device_manager.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::infrastructure::adapters;

ClientConfig make_test_config() {
    ClientConfig config;
    config.gateway_url = "https://127.0.0.1";
    config.gateway_port = 8443;
    return config;
}

TEST(DeviceManagerTest, FirstTimeBootRegistersDeviceAndSavesKeys) {
    DefaultGatewayClient gateway(make_test_config());
    MemorySecureStorage storage;
    OpenSslCryptoProvider crypto;

    DeviceManager manager(gateway, storage, crypto);

    // Initial state: no local device
    EXPECT_TRUE(manager.get_local_device().is_error());

    const UserId uid("alice-001");
    auto init_res = manager.initialize_or_load_device(uid, "Alice MacBook Pro");
    ASSERT_TRUE(init_res.is_ok());

    const auto& device = init_res.value();
    EXPECT_FALSE(device.device_id().empty());
    EXPECT_TRUE(device.device_id().value().starts_with("dev-"));
    EXPECT_EQ(device.user_id(), uid);
    EXPECT_EQ(device.display_name(), "Alice MacBook Pro");
    EXPECT_EQ(device.status(), DeviceAuthorizationStatus::Authorized);

    // Cryptographic Identity Verification
    const auto& crypto_id = device.crypto_identity();
    EXPECT_TRUE(CryptoIdentity::is_valid_fingerprint(crypto_id.fingerprint()));
    EXPECT_EQ(crypto_id.verification_status(), KeyVerificationStatus::Verified);
    EXPECT_FALSE(crypto_id.signed_prekey().empty());
    EXPECT_FALSE(crypto_id.signature().empty());

    // Storage Verification: keys persisted securely
    EXPECT_TRUE(KeyStorageHelper::has_bundle(storage, device.device_id()).value());
    auto bundle_res = KeyStorageHelper::load_bundle(storage, device.device_id());
    ASSERT_TRUE(bundle_res.is_ok());
    const auto& bundle = bundle_res.value();

    EXPECT_EQ(bundle.device_id(), device.device_id());
    EXPECT_EQ(bundle.one_time_prekey_count(), PrekeyPolicy::kInitialPrekeyBatchSize);
    EXPECT_EQ(bundle.identity_public_key().size(), PrekeyPolicy::kEd25519PublicKeySize);

    // Verify local device getter
    auto local_res = manager.get_local_device();
    ASSERT_TRUE(local_res.is_ok());
    EXPECT_EQ(local_res.value().device_id(), device.device_id());
}

TEST(DeviceManagerTest, RebootLoadsExistingDeviceWithoutRegeneratingKeys) {
    DefaultGatewayClient gateway(make_test_config());
    MemorySecureStorage storage;
    OpenSslCryptoProvider crypto;

    const UserId uid("bob-002");
    DeviceId original_device_id;
    std::string original_fingerprint;
    std::vector<uint8_t> original_identity_pub;

    // Boot 1: Register initial device
    {
        DeviceManager manager1(gateway, storage, crypto);
        auto res1 = manager1.initialize_or_load_device(uid, "Bob Desktop");
        ASSERT_TRUE(res1.is_ok());
        original_device_id = res1.value().device_id();
        original_fingerprint = res1.value().crypto_identity().fingerprint();
        original_identity_pub = res1.value().crypto_identity().identity_key_bytes();
    }

    // Boot 2: Simulate app restart with new DeviceManager instance over same storage
    {
        DeviceManager manager2(gateway, storage, crypto);
        auto res2 = manager2.initialize_or_load_device(uid, "Bob Desktop");
        ASSERT_TRUE(res2.is_ok());

        EXPECT_EQ(res2.value().device_id(), original_device_id);
        EXPECT_EQ(res2.value().crypto_identity().fingerprint(), original_fingerprint);
        EXPECT_EQ(res2.value().crypto_identity().identity_key_bytes(), original_identity_pub);

        // Bundle is unchanged
        auto bundle_res = KeyStorageHelper::load_bundle(storage, original_device_id);
        ASSERT_TRUE(bundle_res.is_ok());
        EXPECT_EQ(bundle_res.value().one_time_prekey_count(), PrekeyPolicy::kInitialPrekeyBatchSize);
    }
}

TEST(DeviceManagerTest, PrekeyReplenishmentAndRotation) {
    DefaultGatewayClient gateway(make_test_config());
    MemorySecureStorage storage;
    OpenSslCryptoProvider crypto;

    DeviceManager manager(gateway, storage, crypto);
    const UserId uid("charlie-003");
    auto reg_res = manager.register_device(uid, "Charlie Phone");
    ASSERT_TRUE(reg_res.is_ok());
    const auto did = reg_res.value().device_id();

    // 1. Initial inventory check
    auto inv_res = manager.check_prekey_inventory();
    ASSERT_TRUE(inv_res.is_ok());
    EXPECT_FALSE(inv_res.value().is_low_inventory());

    // 2. Replenish 50 OTPKs
    auto repl_res = manager.replenish_prekeys(50);
    ASSERT_TRUE(repl_res.is_ok());
    EXPECT_EQ(repl_res.value(), 50u);

    // Verify storage has 100 + 50 = 150 OTPKs
    auto bundle_res = KeyStorageHelper::load_bundle(storage, did);
    ASSERT_TRUE(bundle_res.is_ok());
    EXPECT_EQ(bundle_res.value().one_time_prekey_count(), 150u);

    // 3. Rotate Signed Prekey
    const auto original_spk = bundle_res.value().signed_prekey_public_key();
    const auto original_sig = bundle_res.value().signed_prekey_signature();

    auto rot_res = manager.rotate_signed_prekey();
    ASSERT_TRUE(rot_res.is_ok());

    auto rotated_bundle = KeyStorageHelper::load_bundle(storage, did).value();
    EXPECT_NE(rotated_bundle.signed_prekey_public_key(), original_spk);
    EXPECT_NE(rotated_bundle.signed_prekey_signature(), original_sig);

    // Verify new signature is mathematically valid
    auto verify_res =
        crypto.verify_signed_prekey(rotated_bundle.identity_public_key(), rotated_bundle.signed_prekey_public_key(),
                                    rotated_bundle.signed_prekey_signature());
    ASSERT_TRUE(verify_res.is_ok());
    EXPECT_TRUE(verify_res.value());

    // Verify get_local_device() has the updated signature
    auto local_dev = manager.get_local_device().value();
    EXPECT_EQ(local_dev.crypto_identity().signed_prekey_bytes(), rotated_bundle.signed_prekey_public_key());
}

TEST(DeviceManagerTest, ReconcileAutomatedTrigger) {
    DefaultGatewayClient gateway(make_test_config());
    MemorySecureStorage storage;
    OpenSslCryptoProvider crypto;

    DeviceManager manager(gateway, storage, crypto);
    const UserId uid("diana-004");
    auto reg_res = manager.register_device(uid, "Diana Laptop");
    ASSERT_TRUE(reg_res.is_ok());
    const auto did = reg_res.value().device_id();

    // 1. Reconcile on healthy inventory -> no action
    auto rec1 = manager.reconcile_prekeys();
    ASSERT_TRUE(rec1.is_ok());
    EXPECT_FALSE(rec1.value());

    // 2. Simulate low inventory (< 20) on Gateway
    PrekeyInventoryStatus low_inv(10, 90, 20);
    gateway.set_simulated_inventory_status(low_inv);

    auto rec2 = manager.reconcile_prekeys();
    ASSERT_TRUE(rec2.is_ok());
    EXPECT_TRUE(rec2.value()); // Action taken: replenished 50 OTPKs

    auto bundle = KeyStorageHelper::load_bundle(storage, did).value();
    EXPECT_EQ(bundle.one_time_prekey_count(), 150u);

    // 3. Simulate signed prekey rotation required
    PrekeyInventoryStatus rot_needed(100, 50, 20, std::chrono::system_clock::now(), std::chrono::hours(24 * 8), true);
    gateway.set_simulated_inventory_status(rot_needed);

    auto rec3 = manager.reconcile_prekeys();
    ASSERT_TRUE(rec3.is_ok());
    EXPECT_TRUE(rec3.value()); // Action taken: rotated signed prekey
}

TEST(DeviceManagerTest, DeviceRevocationAndKeyWipe) {
    DefaultGatewayClient gateway(make_test_config());
    MemorySecureStorage storage;
    OpenSslCryptoProvider crypto;

    DeviceManager manager(gateway, storage, crypto);
    const UserId uid("edward-005");
    auto reg_res = manager.register_device(uid, "Edward Workstation");
    ASSERT_TRUE(reg_res.is_ok());
    const auto did = reg_res.value().device_id();

    EXPECT_TRUE(KeyStorageHelper::has_bundle(storage, did).value());
    EXPECT_TRUE(manager.get_local_device().is_ok());

    // Revoke device
    auto revoke_res = manager.revoke_device(did);
    ASSERT_TRUE(revoke_res.is_ok());

    // Local device is wiped
    EXPECT_FALSE(KeyStorageHelper::has_bundle(storage, did).value());
    EXPECT_TRUE(manager.get_local_device().is_error());
}

} // namespace
