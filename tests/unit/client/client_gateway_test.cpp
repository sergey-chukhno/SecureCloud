#include "application/interfaces/i_gateway_client.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::infrastructure::adapters;

ClientConfig make_test_config() {
    ClientConfig config;
    config.gateway_url = "https://127.0.0.1";
    config.gateway_port = 8443;
    return config;
}

PrekeyBundle make_valid_bundle(ICryptoProvider& crypto) {
    auto id_res = crypto.generate_identity_keypair();
    auto id_pair = std::move(id_res).value();

    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key);
    auto spk_result = std::move(spk_res).value();

    auto otpk_res = crypto.generate_one_time_prekeys(10, 1);
    auto otpk_pairs = std::move(otpk_res).value();

    std::vector<OneTimePrekeyRecord> otpk_records;
    otpk_records.reserve(otpk_pairs.size());
    for (auto& p : otpk_pairs) {
        otpk_records.push_back(std::move(p.record));
    }

    return PrekeyBundle(id_pair.public_key, spk_result.public_key, spk_result.signature, otpk_records);
}

TEST(DefaultGatewayClientTest, DeviceRegistrationSuccessAndValidation) {
    DefaultGatewayClient client(make_test_config());
    OpenSslCryptoProvider crypto;

    const UserId uid("alice-001");
    auto bundle = make_valid_bundle(crypto);

    // 1. Successful registration
    auto reg_res = client.register_device(uid, bundle);
    ASSERT_TRUE(reg_res.is_ok());
    const auto& result = reg_res.value();

    EXPECT_FALSE(result.device_id.empty());
    EXPECT_TRUE(result.device_id.value().starts_with("dev-"));
    EXPECT_EQ(result.status, DeviceAuthorizationStatus::Authorized);
    EXPECT_TRUE(result.pairing_code.empty());

    // 2. Empty user ID validation failure
    const UserId empty_uid;
    EXPECT_TRUE(client.register_device(empty_uid, bundle).is_error());

    // 3. Corrupted bundle validation failure (empty key)
    PrekeyBundle bad_bundle;
    EXPECT_TRUE(client.register_device(uid, bad_bundle).is_error());

    // 4. Simulated pending authorization with pairing code
    client.set_simulated_registration_status(DeviceAuthorizationStatus::Pending, "ABCD-1234");
    auto pending_res = client.register_device(uid, bundle);
    ASSERT_TRUE(pending_res.is_ok());
    EXPECT_EQ(pending_res.value().status, DeviceAuthorizationStatus::Pending);
    EXPECT_EQ(pending_res.value().pairing_code, "ABCD-1234");
}

TEST(DefaultGatewayClientTest, PrekeyReplenishmentAndRotation) {
    DefaultGatewayClient client(make_test_config());
    OpenSslCryptoProvider crypto;

    const DeviceId did("dev-000001");

    auto otpk_res = crypto.generate_one_time_prekeys(50, 101);
    ASSERT_TRUE(otpk_res.is_ok());
    std::vector<OneTimePrekeyRecord> records;
    for (auto& p : otpk_res.value()) {
        records.push_back(std::move(p.record));
    }

    // 1. Prekey replenishment upload
    auto update_res = client.update_crypto_prekeys(did, std::nullopt, std::nullopt, records);
    ASSERT_TRUE(update_res.is_ok());
    EXPECT_EQ(update_res.value().active_one_time_prekey_count, 50);

    // 2. Signed prekey rotation upload
    auto id_res = crypto.generate_identity_keypair();
    auto spk_res = crypto.generate_signed_prekey(id_res.value().private_key);
    auto spk = std::move(spk_res).value();

    auto rot_res = client.update_crypto_prekeys(did, spk.public_key, spk.signature, {});
    ASSERT_TRUE(rot_res.is_ok());
    EXPECT_EQ(rot_res.value().active_one_time_prekey_count, 0);

    // 3. Validation failure: empty device ID
    const DeviceId empty_did;
    EXPECT_TRUE(client.update_crypto_prekeys(empty_did, std::nullopt, std::nullopt, records).is_error());

    // 4. Validation failure: invalid signed prekey size
    std::vector<uint8_t> bad_spk(10, 0x01);
    EXPECT_TRUE(client.update_crypto_prekeys(did, bad_spk, spk.signature, {}).is_error());
}

TEST(DefaultGatewayClientTest, PrekeyInventoryStatusQueries) {
    DefaultGatewayClient client(make_test_config());
    const DeviceId did("dev-000001");

    // 1. Default healthy inventory status
    auto status_res = client.get_prekey_inventory_status(did);
    ASSERT_TRUE(status_res.is_ok());
    const auto& status = status_res.value();

    EXPECT_EQ(status.active_prekey_count(), 100);
    EXPECT_FALSE(status.is_low_inventory());
    EXPECT_FALSE(status.needs_replenishment());
    EXPECT_FALSE(status.needs_rotation());

    // 2. Empty device ID rejected
    const DeviceId empty_did;
    EXPECT_TRUE(client.get_prekey_inventory_status(empty_did).is_error());

    // 3. Simulated low inventory trigger
    PrekeyInventoryStatus low_inventory(15, 85, 20);
    client.set_simulated_inventory_status(low_inventory);

    auto low_res = client.get_prekey_inventory_status(did);
    ASSERT_TRUE(low_res.is_ok());
    EXPECT_TRUE(low_res.value().is_low_inventory());
    EXPECT_TRUE(low_res.value().needs_replenishment());

    // 4. Simulated signed prekey rotation required
    PrekeyInventoryStatus rotate_needed(50, 50, 20, std::chrono::system_clock::now(), std::chrono::hours(24 * 8), true);
    client.set_simulated_inventory_status(rotate_needed);

    auto rot_res = client.get_prekey_inventory_status(did);
    ASSERT_TRUE(rot_res.is_ok());
    EXPECT_TRUE(rot_res.value().needs_rotation());
}

TEST(DefaultGatewayClientTest, DeviceCryptoDirectoryDiscovery) {
    DefaultGatewayClient client(make_test_config());
    const UserId uid("bob-002");

    // Initially empty directory
    auto dir_res = client.get_device_crypto_directory(uid);
    ASSERT_TRUE(dir_res.is_ok());
    EXPECT_TRUE(dir_res.value().empty());

    // Empty user ID rejected
    const UserId empty_uid;
    EXPECT_TRUE(client.get_device_crypto_directory(empty_uid).is_error());

    // Simulated directory entries
    std::vector<DeviceCryptoDirectoryEntry> directory;
    directory.push_back(DeviceCryptoDirectoryEntry{
        .device_id = DeviceId("bob-laptop-1"),
        .identity_key = std::vector<uint8_t>(32, 0xAA),
        .signed_prekey = std::vector<uint8_t>(32, 0xBB),
        .signed_prekey_signature = std::vector<uint8_t>(64, 0xCC),
        .one_time_prekey = std::vector<uint8_t>(32, 0xDD),
        .one_time_prekey_id = "otpk-1",
        .status = DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = "SHA256:01:02:...",
        .remaining_one_time_prekeys = 95,
    });
    client.set_simulated_directory(directory);

    auto populated_res = client.get_device_crypto_directory(uid);
    ASSERT_TRUE(populated_res.is_ok());
    EXPECT_EQ(populated_res.value().size(), 1u);
    EXPECT_EQ(populated_res.value()[0].device_id, DeviceId("bob-laptop-1"));
    EXPECT_EQ(populated_res.value()[0].one_time_prekey_id, "otpk-1");
}

TEST(DefaultGatewayClientTest, NetworkFailureSimulation) {
    DefaultGatewayClient client(make_test_config());
    client.set_simulated_failure(true, "Connection refused: gateway offline");

    EXPECT_TRUE(client.probe_gateway().is_error());
    EXPECT_TRUE(client.send_message(ConversationId("c1"), "envelope").is_error());
    EXPECT_TRUE(client.sync_messages("").is_error());
    EXPECT_TRUE(client.validate_token("token").is_error());

    OpenSslCryptoProvider crypto;
    auto bundle = make_valid_bundle(crypto);
    EXPECT_TRUE(client.register_device(UserId("alice"), bundle).is_error());
    EXPECT_TRUE(client.get_prekey_inventory_status(DeviceId("dev-1")).is_error());
    EXPECT_TRUE(client.update_crypto_prekeys(DeviceId("dev-1"), std::nullopt, std::nullopt, {}).is_error());
    EXPECT_TRUE(client.get_device_crypto_directory(UserId("alice")).is_error());
}

} // namespace
