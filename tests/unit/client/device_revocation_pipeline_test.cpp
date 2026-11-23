#include "application/client_config.hpp"
#include "application/client_error.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/crypto/x3dh_engine.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::tests {

using namespace securecloud::client::application;
using namespace securecloud::client::domain;

class DeviceRevocationPipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ClientConfig config;
        config.gateway_url = "http://127.0.0.1:8080";
        gateway_ = std::make_unique<infrastructure::adapters::DefaultGatewayClient>(config);
        secure_storage_ = std::make_unique<infrastructure::adapters::MemorySecureStorage>();
        crypto_provider_ = std::make_unique<infrastructure::adapters::OpenSslCryptoProvider>();

        device_manager_ = std::make_unique<managers::DeviceManager>(*gateway_, *secure_storage_, *crypto_provider_);

        test_user_ = UserId("usr-alice-test");
        companion_user_ = UserId("usr-bob-test");
    }

    interfaces::DeviceCryptoDirectoryEntry
    create_peer_directory_entry(const DeviceId& did,
                                DeviceAuthorizationStatus status = DeviceAuthorizationStatus::Authorized) {
        auto id_pair = crypto_provider_->generate_identity_keypair().value();
        auto spk_res = crypto_provider_->generate_signed_prekey(id_pair.private_key).value();
        auto otpk_pair = crypto_provider_->generate_dh_keypair().value();

        return interfaces::DeviceCryptoDirectoryEntry{
            .device_id = did,
            .identity_key = id_pair.public_key,
            .signed_prekey = spk_res.public_key,
            .signed_prekey_signature = spk_res.signature,
            .one_time_prekey = otpk_pair.public_key,
            .one_time_prekey_id = did.value() + "-otpk-01",
            .status = status,
            .identity_key_fingerprint = crypto_provider_->compute_identity_fingerprint(id_pair.public_key).value_or(""),
            .remaining_one_time_prekeys = 1,
            .signed_prekey_created_at = std::chrono::system_clock::now(),
        };
    }

    std::unique_ptr<infrastructure::adapters::DefaultGatewayClient> gateway_;
    std::unique_ptr<infrastructure::adapters::MemorySecureStorage> secure_storage_;
    std::unique_ptr<infrastructure::adapters::OpenSslCryptoProvider> crypto_provider_;
    std::unique_ptr<managers::DeviceManager> device_manager_;

    UserId test_user_;
    UserId companion_user_;
};

TEST_F(DeviceRevocationPipelineTest, LocalDeviceSelfWipe) {
    auto reg_res = device_manager_->register_device(test_user_, "Primary Laptop");
    ASSERT_TRUE(reg_res.is_ok());
    auto local_dev = reg_res.value();

    // Verify local device is loaded
    auto get_res1 = device_manager_->get_local_device();
    ASSERT_TRUE(get_res1.is_ok());
    EXPECT_EQ(get_res1.value().device_id(), local_dev.device_id());

    // Wipe/revoke local device
    auto rev_res = device_manager_->revoke_device(local_dev.device_id());
    EXPECT_TRUE(rev_res.is_ok());

    // Verify local device state is cleared
    auto get_res2 = device_manager_->get_local_device();
    EXPECT_TRUE(get_res2.is_error());

    // Verify device identity secret key wiped from secure storage
    std::string identity_key_id = "device." + std::string(local_dev.device_id().str()) + ".identity.private";
    auto key_res = secure_storage_->get_secret(identity_key_id);
    EXPECT_TRUE(key_res.is_error());
}

TEST_F(DeviceRevocationPipelineTest, RemoteRevocationRejectsEmptyDevice) {
    auto rev_res = device_manager_->revoke_device(DeviceId{}, "any_mfa_token");
    EXPECT_TRUE(rev_res.is_error());
    EXPECT_EQ(rev_res.error().code(), ClientErrorCode::ValidationFailed);
}

TEST_F(DeviceRevocationPipelineTest, RemoteRevocationRequiresMfa) {
    gateway_->set_simulated_revocation_mfa_requirement(true);
    auto reg_res = device_manager_->register_device(test_user_, "Primary Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    DeviceId companion_id("dev-companion-tablet");

    // 1. Missing MFA token
    auto rev_res1 = device_manager_->revoke_device(companion_id, "");
    EXPECT_TRUE(rev_res1.is_error());
    EXPECT_EQ(rev_res1.error().code(), ClientErrorCode::AuthenticationRequired);

    // 2. Invalid MFA token
    auto rev_res2 = device_manager_->revoke_device(companion_id, "invalid");
    EXPECT_TRUE(rev_res2.is_error());
    EXPECT_EQ(rev_res2.error().code(), ClientErrorCode::InvalidCredentials);
}

TEST_F(DeviceRevocationPipelineTest, RemoteRevocationSuccessWithMfa) {
    auto reg_res = device_manager_->register_device(test_user_, "Primary Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    DeviceId companion_id("dev-companion-tablet");
    CryptoIdentity dummy_id;
    Device companion_device(companion_id, test_user_, "Companion Tablet", dummy_id,
                            DeviceAuthorizationStatus::Authorized);

    gateway_->set_simulated_user_devices(test_user_, {reg_res.value(), companion_device});

    // Revoke remote device with valid MFA
    auto rev_res = device_manager_->revoke_device(companion_id, "valid_mfa_token_or_fido2_signature");
    EXPECT_TRUE(rev_res.is_ok());

    // Verify simulated gateway marked status as Revoked
    auto list_res = gateway_->list_user_devices(test_user_);
    ASSERT_TRUE(list_res.is_ok());
    bool found_and_revoked = false;
    for (const auto& dev : list_res.value()) {
        if (dev.device_id() == companion_id) {
            EXPECT_EQ(dev.status(), DeviceAuthorizationStatus::Revoked);
            EXPECT_EQ(dev.trust_level(), DeviceTrustLevel::Revoked);
            found_and_revoked = true;
        }
    }
    EXPECT_TRUE(found_and_revoked);
}

TEST_F(DeviceRevocationPipelineTest, RatchetSessionPurgeCleansMemoryAndStorage) {
    auto reg_res = device_manager_->register_device(test_user_, "Primary Laptop");
    ASSERT_TRUE(reg_res.is_ok());

    DeviceId companion_id("dev-companion-02");
    managers::RatchetSessionManager session_mgr(*gateway_, *secure_storage_, *crypto_provider_, test_user_,
                                                reg_res.value().device_id());

    // Set up mock directory entry for companion
    auto entry = create_peer_directory_entry(companion_id);
    gateway_->set_simulated_directory({entry});

    // Encrypt payload to establish active Double Ratchet session
    std::string msg = "Secret initial sync payload";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());
    auto enc_res = session_mgr.encrypt_payload_for_device(test_user_, companion_id, plaintext);
    ASSERT_TRUE(enc_res.is_ok());

    // Verify session exists in memory
    EXPECT_TRUE(session_mgr.has_session(test_user_, companion_id));
    EXPECT_EQ(session_mgr.active_session_count(), 1U);

    // Verify session persisted to storage
    auto storage_key = managers::RatchetSessionManager::make_storage_key(test_user_, companion_id);
    auto store_check = secure_storage_->get_secret(storage_key);
    EXPECT_TRUE(store_check.is_ok());

    // Purge session for companion device
    auto purge_res = session_mgr.purge_device_sessions(companion_id);
    EXPECT_TRUE(purge_res.is_ok());

    // Assert session erased from memory and secure storage
    EXPECT_FALSE(session_mgr.has_session(test_user_, companion_id));
    EXPECT_EQ(session_mgr.active_session_count(), 0U);

    auto store_check2 = secure_storage_->get_secret(storage_key);
    EXPECT_TRUE(store_check2.is_error());
}

TEST_F(DeviceRevocationPipelineTest, FanoutExcludesRevokedDevices) {
    auto reg_res = device_manager_->register_device(test_user_, "Sender Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    managers::RatchetSessionManager session_mgr(*gateway_, *secure_storage_, *crypto_provider_, test_user_,
                                                reg_res.value().device_id());

    // Peer Bob has 2 devices: Phone (Authorized) and Tablet (Revoked)
    DeviceId bob_phone("dev-bob-phone");
    DeviceId bob_tablet("dev-bob-tablet");

    auto phone_entry = create_peer_directory_entry(bob_phone, DeviceAuthorizationStatus::Authorized);
    auto tablet_entry = create_peer_directory_entry(bob_tablet, DeviceAuthorizationStatus::Revoked);

    gateway_->set_simulated_user_directory(companion_user_, {phone_entry, tablet_entry});

    // Encrypt fanout for Bob
    std::string msg = "Hello Bob, secure multi-device message";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());
    auto fanout_res = session_mgr.encrypt_fanout_for_participants({companion_user_}, plaintext);
    ASSERT_TRUE(fanout_res.is_ok());

    // Fan-out must contain ONLY phone, and NOT tablet (ADR-008 §16)
    const auto& payloads = fanout_res.value();
    ASSERT_EQ(payloads.size(), 1U);
    EXPECT_EQ(payloads[0].recipient_device_id, bob_phone);
    EXPECT_NE(payloads[0].recipient_device_id, bob_tablet);
}

TEST_F(DeviceRevocationPipelineTest, DeviceManagerTriggersRatchetPurgeOnRevocation) {
    auto reg_res = device_manager_->register_device(test_user_, "Primary Node");
    ASSERT_TRUE(reg_res.is_ok());

    DeviceId companion_id("dev-comp-99");

    managers::RatchetSessionManager session_mgr(*gateway_, *secure_storage_, *crypto_provider_, test_user_,
                                                reg_res.value().device_id());
    device_manager_->set_ratchet_session_manager(&session_mgr);

    // Setup companion directory entry
    auto comp_entry = create_peer_directory_entry(companion_id, DeviceAuthorizationStatus::Authorized);
    gateway_->set_simulated_directory({comp_entry});

    // Establish active session
    std::string msg = "Device sync test";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());
    auto enc_res = session_mgr.encrypt_payload_for_device(test_user_, companion_id, plaintext);
    ASSERT_TRUE(enc_res.is_ok());
    EXPECT_TRUE(session_mgr.has_session(test_user_, companion_id));

    // Revoke device through DeviceManager with MFA
    auto rev_res = device_manager_->revoke_device(companion_id, "valid_mfa_token");
    EXPECT_TRUE(rev_res.is_ok());

    // Assert session was automatically purged in RatchetSessionManager
    EXPECT_FALSE(session_mgr.has_session(test_user_, companion_id));
    EXPECT_EQ(session_mgr.active_session_count(), 0U);
}

} // namespace securecloud::client::tests
