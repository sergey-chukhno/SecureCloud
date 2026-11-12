#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_hardware_authenticator.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/device_pairing_coordinator.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device.hpp"
#include "domain/device_id.hpp"
#include "domain/device_platform_info.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/device_trust_level.hpp"
#include "domain/pairing_challenge_payload.hpp"
#include "domain/short_authentication_string.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/simulated_hardware_authenticator.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace securecloud::client::application {
namespace {

using infrastructure::adapters::DefaultGatewayClient;
using infrastructure::adapters::KeyStorageHelper;
using infrastructure::adapters::MemoryLocalStore;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;
using infrastructure::adapters::SimulatedHardwareAuthenticator;
using managers::DeviceManager;
using managers::DevicePairingCoordinator;
using managers::MessagingManager;
using managers::RatchetSessionManager;
using managers::SafetyNumberEngine;
using securecloud::common::configuration::SecretString;

struct TestEndpoint {
    domain::UserId user_id;
    domain::DeviceId device_id;
    std::string display_name;
    std::vector<uint8_t> identity_public_key;
    std::unique_ptr<MemorySecureStorage> secure_storage;
    std::unique_ptr<MemoryLocalStore> local_store;
    std::unique_ptr<DeviceManager> device_manager;
    std::unique_ptr<RatchetSessionManager> ratchet_manager;
    std::unique_ptr<MessagingManager> messaging_manager;
    std::unique_ptr<SafetyNumberEngine> safety_number_engine;
    std::unique_ptr<DevicePairingCoordinator> pairing_coordinator;
    interfaces::DeviceCryptoDirectoryEntry dir_entry;
};

TestEndpoint create_endpoint(interfaces::ICryptoProvider& crypto, DefaultGatewayClient& gateway,
                             const std::string& uid_str, const std::string& did_str, const std::string& display_name,
                             domain::DeviceTrustLevel trust_level, domain::DeviceAuthorizationStatus auth_status) {
    domain::UserId uid(uid_str);
    domain::DeviceId did(did_str);
    auto secure_storage = std::make_unique<MemorySecureStorage>();
    auto local_store = std::make_unique<MemoryLocalStore>();

    auto id_pair = crypto.generate_identity_keypair().value();
    auto spk_res = crypto.generate_signed_prekey(id_pair.private_key).value();

    std::unordered_map<std::string, SecretString> otpk_privates;
    auto otpk_pair = crypto.generate_dh_keypair().value();
    std::string otpk_id = did_str + "-otpk-01";
    otpk_privates.emplace(otpk_id, std::move(otpk_pair.private_key));

    const auto id_pub = id_pair.public_key;
    domain::DevicePrivateBundle priv_bundle(did, id_pair.public_key, std::move(id_pair.private_key), spk_res.public_key,
                                            std::move(spk_res.private_key), spk_res.signature,
                                            std::move(otpk_privates));
    KeyStorageHelper::save_bundle(*secure_storage, priv_bundle);
    secure_storage->store_secret("device.local.id", SecretString(did_str));

    interfaces::DeviceCryptoDirectoryEntry dir_entry{
        .device_id = did,
        .identity_key = id_pub,
        .signed_prekey = spk_res.public_key,
        .signed_prekey_signature = spk_res.signature,
        .one_time_prekey = otpk_pair.public_key,
        .one_time_prekey_id = otpk_id,
        .status = auth_status,
        .identity_key_fingerprint = crypto.compute_identity_fingerprint(id_pub).value_or(""),
        .remaining_one_time_prekeys = 1,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };

    auto device_mgr = std::make_unique<DeviceManager>(gateway, *secure_storage, crypto);
    auto ratchet_mgr = std::make_unique<RatchetSessionManager>(gateway, *secure_storage, crypto, uid, did);
    device_mgr->set_ratchet_session_manager(ratchet_mgr.get());

    auto messaging_mgr = std::make_unique<MessagingManager>(gateway, *local_store, crypto, ratchet_mgr.get());
    auto safety_engine = std::make_unique<SafetyNumberEngine>(crypto, *secure_storage);
    auto pairing_coord = std::make_unique<DevicePairingCoordinator>(gateway, *secure_storage, crypto, *device_mgr);

    // Initialize local device state
    auto init_dev_res = device_mgr->initialize_or_load_device(uid, display_name);
    if (init_dev_res.is_ok()) {
        auto dev = init_dev_res.value();
        dev.set_trust_level(trust_level);
        dev.set_status(auth_status);
    }

    return TestEndpoint{
        .user_id = std::move(uid),
        .device_id = std::move(did),
        .display_name = display_name,
        .identity_public_key = id_pub,
        .secure_storage = std::move(secure_storage),
        .local_store = std::move(local_store),
        .device_manager = std::move(device_mgr),
        .ratchet_manager = std::move(ratchet_mgr),
        .messaging_manager = std::move(messaging_mgr),
        .safety_number_engine = std::move(safety_engine),
        .pairing_coordinator = std::move(pairing_coord),
        .dir_entry = std::move(dir_entry),
    };
}

class MultiDeviceTrustIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        crypto_ = std::make_unique<OpenSslCryptoProvider>();
        ClientConfig config;
        config.gateway_url = "https://gateway.securecloud.test";
        config.gateway_port = 8443;
        gateway_ = std::make_unique<DefaultGatewayClient>(config);
        hw_auth_ = std::make_unique<SimulatedHardwareAuthenticator>();
    }

    std::unique_ptr<OpenSslCryptoProvider> crypto_;
    std::unique_ptr<DefaultGatewayClient> gateway_;
    std::unique_ptr<SimulatedHardwareAuthenticator> hw_auth_;
};

// 1. Comprehensive Companion Device Pairing and Mutual SAS Matching
TEST_F(MultiDeviceTrustIntegrationTest, CompanionDevicePairingAndMutualSasMatching) {
    const domain::UserId alice_id("alice-uuid-001");

    // Primary workstation (Alice Desktop)
    auto alice_desktop =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-desktop", "Alice MacBook Pro",
                        domain::DeviceTrustLevel::HardwareAttested, domain::DeviceAuthorizationStatus::Authorized);

    // Simulated Gateway pairing result for companion
    interfaces::PairingInitiationResult pairing_init{
        .pairing_code = "739281",
        .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5),
    };
    gateway_->set_simulated_pairing_result(pairing_init);
    gateway_->set_simulated_user_directory(alice_id, {alice_desktop.dir_entry});

    // Companion device (Alice iPad) initiates pairing
    auto companion_storage = std::make_unique<MemorySecureStorage>();
    auto companion_dev_mgr = std::make_unique<DeviceManager>(*gateway_, *companion_storage, *crypto_);
    DevicePairingCoordinator companion_coord(*gateway_, *companion_storage, *crypto_, *companion_dev_mgr);

    auto session_res = companion_coord.initiate_companion_pairing(alice_id, "Alice iPad Pro");
    ASSERT_TRUE(session_res.is_ok()) << session_res.error().user_message();
    auto session = std::move(session_res).value();

    // Register devices in simulated user devices list
    domain::Device comp_device(session.device_id, session.user_id, session.display_name, domain::CryptoIdentity{},
                               domain::DeviceAuthorizationStatus::Pending);
    domain::Device primary_device(alice_desktop.device_id, alice_id, alice_desktop.display_name,
                                  domain::CryptoIdentity{}, domain::DeviceAuthorizationStatus::Authorized);
    gateway_->set_simulated_user_devices(alice_id, {primary_device, comp_device});

    EXPECT_FALSE(session.qr_uri.empty());
    EXPECT_EQ(session.expected_sas.numeric_code().size(), 6);
    EXPECT_EQ(session.expected_sas.visual_emojis().size(), 4);

    // Primary workstation inspects the QR challenge URI
    auto prompt_res = alice_desktop.pairing_coordinator->inspect_pairing_challenge(session.qr_uri);
    ASSERT_TRUE(prompt_res.is_ok()) << prompt_res.error().user_message();
    const auto& prompt = prompt_res.value();

    // Mutual SAS verification: Primary workstation derives identical SAS
    EXPECT_EQ(prompt.sas.numeric_code(), session.expected_sas.numeric_code());
    EXPECT_EQ(prompt.sas.visual_emojis(), session.expected_sas.visual_emojis());
    EXPECT_EQ(prompt.pairing_code, "739281");
    EXPECT_EQ(prompt.display_name, "Alice iPad Pro");

    // Primary workstation approves pairing with MFA
    auto approve_res = alice_desktop.pairing_coordinator->approve_companion_pairing(prompt, "123456");
    EXPECT_TRUE(approve_res.is_ok()) << approve_res.error().user_message();

    // Companion checks status: Gateway transitions to Authorized
    gateway_->set_simulated_registration_status(domain::DeviceAuthorizationStatus::Authorized);
    auto poll_res = companion_coord.poll_companion_authorization(session);
    ASSERT_TRUE(poll_res.is_ok());
    EXPECT_TRUE(poll_res.value());
    EXPECT_TRUE(session.is_authorized);
}

// 2. Hardware MFA Enforcement on Pairing Approval
TEST_F(MultiDeviceTrustIntegrationTest, HardwareMfaEnforcementOnPairingApproval) {
    const domain::UserId alice_id("alice-uuid-001");
    auto alice_desktop =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-desktop", "Alice MacBook Pro",
                        domain::DeviceTrustLevel::HardwareAttested, domain::DeviceAuthorizationStatus::Authorized);

    interfaces::PairingInitiationResult pairing_init{
        .pairing_code = "998877",
        .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5),
    };
    gateway_->set_simulated_pairing_result(pairing_init);

    auto companion_storage = std::make_unique<MemorySecureStorage>();
    auto companion_dev_mgr = std::make_unique<DeviceManager>(*gateway_, *companion_storage, *crypto_);
    DevicePairingCoordinator companion_coord(*gateway_, *companion_storage, *crypto_, *companion_dev_mgr);

    auto session = companion_coord.initiate_companion_pairing(alice_id, "Alice Rogue Device").value();
    auto prompt = alice_desktop.pairing_coordinator->inspect_pairing_challenge(session.qr_uri).value();

    // Attempt authorization without MFA -> Fails with MFA requirement
    gateway_->set_simulated_authorization_mfa_requirement(true);
    auto empty_mfa_res = alice_desktop.pairing_coordinator->approve_companion_pairing(prompt, "");
    EXPECT_TRUE(empty_mfa_res.is_error());
    EXPECT_EQ(empty_mfa_res.error().category(), ClientErrorCategory::Authentication);

    // Attempt authorization with simulated hardware touch rejection -> Fails
    hw_auth_->set_touch_approved(false);
    auto hw_prompt_res = hw_auth_->prompt_for_hardware_mfa("pair:did-alice-rogue");
    EXPECT_TRUE(hw_prompt_res.is_error());

    // Successful hardware touch approval -> Succeeds
    hw_auth_->set_touch_approved(true);
    auto valid_hw_token = hw_auth_->prompt_for_hardware_mfa("pair:did-alice-rogue");
    ASSERT_TRUE(valid_hw_token.is_ok());
    EXPECT_FALSE(valid_hw_token.value().empty());

    auto approved_res = alice_desktop.pairing_coordinator->approve_companion_pairing(prompt, valid_hw_token.value());
    EXPECT_TRUE(approved_res.is_ok());
}

// 3. Multi-Device Fan-Out Encryption & Decryption
TEST_F(MultiDeviceTrustIntegrationTest, MultiDeviceFanOutDeliveryAndDecryption) {
    const domain::UserId alice_id("alice-uuid-001");
    const domain::UserId bob_id("bob-uuid-002");

    // Alice has two authorized devices: Desktop and Laptop
    auto alice_desktop =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-desktop", "Alice Desktop",
                        domain::DeviceTrustLevel::HardwareAttested, domain::DeviceAuthorizationStatus::Authorized);

    auto alice_laptop =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-laptop", "Alice Laptop",
                        domain::DeviceTrustLevel::VerifiedOutOfBand, domain::DeviceAuthorizationStatus::Authorized);

    // Bob has one device: Phone
    auto bob_phone =
        create_endpoint(*crypto_, *gateway_, bob_id.value(), "did-bob-phone", "Bob iPhone",
                        domain::DeviceTrustLevel::VerifiedOutOfBand, domain::DeviceAuthorizationStatus::Authorized);

    // Gateway directory contains both of Alice's authorized devices
    std::vector<interfaces::DeviceCryptoDirectoryEntry> alice_devices{alice_desktop.dir_entry, alice_laptop.dir_entry};
    gateway_->set_simulated_user_directory(alice_id, alice_devices);

    // Gateway directory for Bob contains Bob's phone
    std::vector<interfaces::DeviceCryptoDirectoryEntry> bob_devices{bob_phone.dir_entry};
    gateway_->set_simulated_user_directory(bob_id, bob_devices);

    // Bob sends a message fan-out to Alice
    const std::string plaintext_msg = "Confidential SecOps Alert: multi-device fanout test.";
    std::vector<uint8_t> plaintext_bytes(plaintext_msg.begin(), plaintext_msg.end());

    auto fanout_res = bob_phone.ratchet_manager->encrypt_fanout_for_participants({alice_id}, plaintext_bytes);
    ASSERT_TRUE(fanout_res.is_ok()) << fanout_res.error().user_message();

    const auto& payloads = fanout_res.value();
    // Must deliver to both Alice-Desktop and Alice-Laptop
    ASSERT_EQ(payloads.size(), 2);

    const domain::crypto::PerDeviceDeliveryPayload* desktop_payload = nullptr;
    const domain::crypto::PerDeviceDeliveryPayload* laptop_payload = nullptr;
    for (const auto& p : payloads) {
        if (p.recipient_device_id.value() == "did-alice-desktop") {
            desktop_payload = &p;
        } else if (p.recipient_device_id.value() == "did-alice-laptop") {
            laptop_payload = &p;
        }
    }
    ASSERT_NE(desktop_payload, nullptr);
    ASSERT_NE(laptop_payload, nullptr);

    // Alice Desktop decrypts its designated payload
    auto desktop_decrypt =
        alice_desktop.ratchet_manager->decrypt_payload_from_device(bob_id, bob_phone.device_id, *desktop_payload);
    ASSERT_TRUE(desktop_decrypt.is_ok()) << desktop_decrypt.error().user_message();
    EXPECT_EQ(desktop_decrypt.value().expose_unredacted_secret(), plaintext_msg);

    // Alice Laptop decrypts its designated payload
    auto laptop_decrypt =
        alice_laptop.ratchet_manager->decrypt_payload_from_device(bob_id, bob_phone.device_id, *laptop_payload);
    ASSERT_TRUE(laptop_decrypt.is_ok()) << laptop_decrypt.error().user_message();
    EXPECT_EQ(laptop_decrypt.value().expose_unredacted_secret(), plaintext_msg);
}

// 4. Remote Device Revocation, Session Purging and Fan-Out Exclusion
TEST_F(MultiDeviceTrustIntegrationTest, RemoteRevocationSessionPurgeAndFanOutExclusion) {
    const domain::UserId alice_id("alice-uuid-001");
    const domain::UserId bob_id("bob-uuid-002");

    auto alice_desktop =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-desktop", "Alice Desktop",
                        domain::DeviceTrustLevel::HardwareAttested, domain::DeviceAuthorizationStatus::Authorized);

    auto alice_laptop =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-laptop", "Alice Laptop",
                        domain::DeviceTrustLevel::VerifiedOutOfBand, domain::DeviceAuthorizationStatus::Authorized);

    auto bob_phone =
        create_endpoint(*crypto_, *gateway_, bob_id.value(), "did-bob-phone", "Bob iPhone",
                        domain::DeviceTrustLevel::VerifiedOutOfBand, domain::DeviceAuthorizationStatus::Authorized);

    // Register devices with Bob and establish sessions
    std::vector<interfaces::DeviceCryptoDirectoryEntry> alice_devices{alice_desktop.dir_entry, alice_laptop.dir_entry};
    gateway_->set_simulated_user_directory(alice_id, alice_devices);
    gateway_->set_simulated_user_directory(bob_id, {bob_phone.dir_entry});

    // Initial message establishes active sessions
    const std::string msg1 = "Message 1 before revocation";
    std::vector<uint8_t> msg1_bytes(msg1.begin(), msg1.end());
    auto fanout1 = bob_phone.ratchet_manager->encrypt_fanout_for_participants({alice_id}, msg1_bytes);
    ASSERT_TRUE(fanout1.is_ok());
    EXPECT_EQ(fanout1.value().size(), 2);
    EXPECT_TRUE(bob_phone.ratchet_manager->has_session(alice_id, alice_laptop.device_id));

    // Alice Desktop decrypts message 1 to initialize ratchet session
    for (const auto& p : fanout1.value()) {
        if (p.recipient_device_id.value() == "did-alice-desktop") {
            auto d = alice_desktop.ratchet_manager->decrypt_payload_from_device(bob_id, bob_phone.device_id, p);
            ASSERT_TRUE(d.is_ok());
            EXPECT_EQ(d.value().expose_unredacted_secret(), msg1);
        }
    }

    // Alice-Desktop revokes compromised Alice-Laptop
    auto revoke_res = alice_desktop.device_manager->revoke_device(alice_laptop.device_id, "123456");
    EXPECT_TRUE(revoke_res.is_ok()) << revoke_res.error().user_message();

    // Bob updates directory: Alice-Laptop is now marked Revoked
    auto revoked_laptop_entry = alice_laptop.dir_entry;
    revoked_laptop_entry.status = domain::DeviceAuthorizationStatus::Revoked;
    gateway_->set_simulated_user_directory(alice_id, {alice_desktop.dir_entry, revoked_laptop_entry});

    // Bob purges session for the revoked laptop
    auto purge_res = bob_phone.ratchet_manager->purge_device_sessions(alice_laptop.device_id);
    EXPECT_TRUE(purge_res.is_ok());
    EXPECT_FALSE(bob_phone.ratchet_manager->has_session(alice_id, alice_laptop.device_id));

    // Bob sends a subsequent message to Alice
    const std::string msg2 = "Confidential Message 2 after revocation";
    std::vector<uint8_t> msg2_bytes(msg2.begin(), msg2.end());
    auto fanout2 = bob_phone.ratchet_manager->encrypt_fanout_for_participants({alice_id}, msg2_bytes);
    ASSERT_TRUE(fanout2.is_ok());

    // Fan-Out Exclusion Invariant: only Alice-Desktop receives a payload; Revoked laptop is excluded!
    const auto& payloads2 = fanout2.value();
    ASSERT_EQ(payloads2.size(), 1);
    EXPECT_EQ(payloads2[0].recipient_device_id.value(), "did-alice-desktop");

    // Alice Desktop successfully decrypts
    auto desktop_decrypt2 =
        alice_desktop.ratchet_manager->decrypt_payload_from_device(bob_id, bob_phone.device_id, payloads2[0]);
    ASSERT_TRUE(desktop_decrypt2.is_ok());
    EXPECT_EQ(desktop_decrypt2.value().expose_unredacted_secret(), msg2);
}

// 5. Active Workstation Self-Revocation Protection
TEST_F(MultiDeviceTrustIntegrationTest, ActiveWorkstationSelfRevocationProtection) {
    const domain::UserId alice_id("alice-uuid-001");
    auto alice_desktop =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-desktop", "Alice Desktop",
                        domain::DeviceTrustLevel::HardwareAttested, domain::DeviceAuthorizationStatus::Authorized);

    // When invoking revoke_device on the local device itself, it triggers a local self-wipe
    auto self_revoke = alice_desktop.device_manager->revoke_device(alice_desktop.device_id, "");
    EXPECT_TRUE(self_revoke.is_ok());

    // After self-wipe, local device keys are cleared from secure storage
    auto bundle_res = KeyStorageHelper::load_bundle(*alice_desktop.secure_storage, alice_desktop.device_id);
    EXPECT_TRUE(bundle_res.is_error());
}

// 6. Identity Key Change Detection and Safety Number Verification Lifecycle
TEST_F(MultiDeviceTrustIntegrationTest, IdentityKeyChangeDetectionAndSafetyNumberLifecycle) {
    const domain::UserId alice_id("alice-uuid-001");
    const domain::UserId bob_id("bob-uuid-002");

    auto alice =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-01", "Alice",
                        domain::DeviceTrustLevel::HardwareAttested, domain::DeviceAuthorizationStatus::Authorized);

    auto bob1 =
        create_endpoint(*crypto_, *gateway_, bob_id.value(), "did-bob-01", "Bob Phone",
                        domain::DeviceTrustLevel::VerifiedOutOfBand, domain::DeviceAuthorizationStatus::Authorized);

    // Initial state: Bob is Unverified
    auto status1 = alice.safety_number_engine->evaluate_key_verification_status(bob_id, bob1.identity_public_key);
    ASSERT_TRUE(status1.is_ok());
    EXPECT_EQ(status1.value(), domain::KeyVerificationStatus::Unverified);

    // Alice and Bob compute mutual 60-digit safety numbers
    auto sn_alice = alice.safety_number_engine->compute_safety_number(alice_id, alice.identity_public_key, bob_id,
                                                                      bob1.identity_public_key);
    ASSERT_TRUE(sn_alice.is_ok());

    auto sn_bob = bob1.safety_number_engine->compute_safety_number(bob_id, bob1.identity_public_key, alice_id,
                                                                   alice.identity_public_key);
    ASSERT_TRUE(sn_bob.is_ok());

    // Safety numbers match symmetrically regardless of order
    EXPECT_EQ(sn_alice.value(), sn_bob.value());
    EXPECT_EQ(sn_alice.value().size(), 71); // 12 blocks of 5 digits separated by spaces
    std::string unspaced = sn_alice.value();
    unspaced.erase(std::remove(unspaced.begin(), unspaced.end(), ' '), unspaced.end());
    EXPECT_EQ(unspaced.size(), 60);

    // Alice marks Bob as verified
    auto verify_res = alice.safety_number_engine->set_verification_state(bob_id, bob1.identity_public_key, true);
    EXPECT_TRUE(verify_res.is_ok());

    auto status2 = alice.safety_number_engine->evaluate_key_verification_status(bob_id, bob1.identity_public_key);
    ASSERT_TRUE(status2.is_ok());
    EXPECT_EQ(status2.value(), domain::KeyVerificationStatus::Verified);

    // Bob re-installs or changes his identity key (simulated MITM or device replacement)
    auto bob_new_id_pair = crypto_->generate_identity_keypair().value();
    const auto& bob_new_pub = bob_new_id_pair.public_key;

    // Alice detects KeyChanged
    auto status3 = alice.safety_number_engine->evaluate_key_verification_status(bob_id, bob_new_pub);
    ASSERT_TRUE(status3.is_ok());
    EXPECT_EQ(status3.value(), domain::KeyVerificationStatus::KeyChanged);

    // Alice re-verifies Bob's new key after out-of-band safety number comparison
    auto re_verify_res = alice.safety_number_engine->set_verification_state(bob_id, bob_new_pub, true);
    EXPECT_TRUE(re_verify_res.is_ok());

    auto status4 = alice.safety_number_engine->evaluate_key_verification_status(bob_id, bob_new_pub);
    ASSERT_TRUE(status4.is_ok());
    EXPECT_EQ(status4.value(), domain::KeyVerificationStatus::Verified);
}

// 7. Hardware Attestation and Signed Prekey Rotation
TEST_F(MultiDeviceTrustIntegrationTest, HardwareAttestationAndSignedPrekeyRotation) {
    const domain::UserId alice_id("alice-uuid-001");
    auto alice =
        create_endpoint(*crypto_, *gateway_, alice_id.value(), "did-alice-01", "Alice Workstation",
                        domain::DeviceTrustLevel::HardwareAttested, domain::DeviceAuthorizationStatus::Authorized);

    // Verify hardware attestation simulation
    auto attest_res = hw_auth_->attest_device_authenticator();
    ASSERT_TRUE(attest_res.is_ok());
    const auto& record = attest_res.value();
    EXPECT_EQ(record.authenticator_type(), domain::AuthenticatorType::Platform);
    EXPECT_FALSE(record.aaguid().empty());
    EXPECT_FALSE(record.attestation_statement_hex().empty());

    // Rotate signed prekey
    auto rotate_res = alice.device_manager->rotate_signed_prekey();
    EXPECT_TRUE(rotate_res.is_ok()) << rotate_res.error().user_message();

    // Verify updated bundle has valid signed prekey signature
    auto bundle = KeyStorageHelper::load_bundle(*alice.secure_storage, alice.device_id).value();
    EXPECT_FALSE(bundle.signed_prekey_public_key().empty());
    EXPECT_FALSE(bundle.signed_prekey_signature().empty());

    auto sig_res = crypto_->verify_signed_prekey(bundle.identity_public_key(), bundle.signed_prekey_public_key(),
                                                 bundle.signed_prekey_signature());
    ASSERT_TRUE(sig_res.is_ok());
    EXPECT_TRUE(sig_res.value());
}

} // namespace
} // namespace securecloud::client::application
