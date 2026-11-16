#include "application/client_config.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/contact.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <cctype>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::application::managers {
namespace {

using infrastructure::adapters::DefaultGatewayClient;
using infrastructure::adapters::MemoryLocalStore;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;

class ContactVerificationPipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        local_store_ = std::make_unique<MemoryLocalStore>();
        secure_storage_ = std::make_unique<MemorySecureStorage>();
        crypto_ = std::make_unique<OpenSslCryptoProvider>();
        gateway_ = std::make_unique<DefaultGatewayClient>(ClientConfig::create_default());
        safety_engine_ = std::make_unique<SafetyNumberEngine>(*crypto_, *secure_storage_);

        alice_id_ = domain::UserId("usr-alice-verify");
        auto alice_kp = crypto_->generate_identity_keypair().value();
        alice_ik_ = std::move(alice_kp.public_key);

        contact_manager_ = std::make_unique<ContactManager>(*local_store_, *gateway_, *safety_engine_);
        contact_manager_->set_local_identity(alice_id_, alice_ik_);
    }

    std::unique_ptr<MemoryLocalStore> local_store_;
    std::unique_ptr<MemorySecureStorage> secure_storage_;
    std::unique_ptr<OpenSslCryptoProvider> crypto_;
    std::unique_ptr<DefaultGatewayClient> gateway_;
    std::unique_ptr<SafetyNumberEngine> safety_engine_;
    std::unique_ptr<ContactManager> contact_manager_;

    domain::UserId alice_id_;
    std::vector<uint8_t> alice_ik_;
};

TEST_F(ContactVerificationPipelineTest, GetOrComputeSafetyNumberDerivesFormatsAndCachesInLocalStore) {
    const domain::UserId bob_id("usr-bob-verify");
    auto bob_kp = crypto_->generate_identity_keypair().value();
    const std::string bob_fp = crypto_->compute_identity_fingerprint(bob_kp.public_key).value();
    const std::string alice_fp = crypto_->compute_identity_fingerprint(alice_ik_).value();

    // Save Bob in Alice's local store initially without a computed safety number
    domain::Contact bob_initial(bob_id, "Bob");
    ASSERT_TRUE(contact_manager_->add_or_update_contact(bob_initial).is_ok());

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob", bob_kp.public_key, bob_fp, 1),
        domain::DirectoryUserEntry(alice_id_, "@alice", "Alice", alice_ik_, alice_fp, 1),
    });

    auto sn_res = contact_manager_->get_or_compute_safety_number(bob_id);
    ASSERT_TRUE(sn_res.is_ok());
    const std::string& alice_view_sn = sn_res.value();

    // Expect 12 blocks of 5 decimal digits separated by 11 single spaces = 71 chars
    ASSERT_EQ(alice_view_sn.size(), 71u);
    for (std::size_t i = 0; i < alice_view_sn.size(); ++i) {
        if ((i + 1) % 6 == 0) {
            EXPECT_EQ(alice_view_sn[i], ' ');
        } else {
            EXPECT_TRUE(std::isdigit(static_cast<unsigned char>(alice_view_sn[i])));
        }
    }

    // Confirm cached inside ILocalStore
    auto cached = contact_manager_->get_contact(bob_id).value();
    EXPECT_EQ(cached.safety_number(), alice_view_sn);

    // Commutative symmetry from Bob's independent workstation
    MemoryLocalStore bob_store;
    MemorySecureStorage bob_sec;
    SafetyNumberEngine bob_safety(*crypto_, bob_sec);
    ContactManager bob_contact_mgr(bob_store, *gateway_, bob_safety);
    bob_contact_mgr.set_local_identity(bob_id, bob_kp.public_key);
    ASSERT_TRUE(bob_contact_mgr.add_or_update_contact(domain::Contact(alice_id_, "Alice")).is_ok());

    auto bob_sn_res = bob_contact_mgr.get_or_compute_safety_number(alice_id_);
    ASSERT_TRUE(bob_sn_res.is_ok());
    EXPECT_EQ(bob_sn_res.value(), alice_view_sn);
}

TEST_F(ContactVerificationPipelineTest, GetOrComputeSafetyNumberFallsBackToDeviceCryptoDirectory) {
    const domain::UserId charlie_id("usr-charlie-dir");
    auto charlie_kp = crypto_->generate_identity_keypair().value();
    const std::string charlie_fp = crypto_->compute_identity_fingerprint(charlie_kp.public_key).value();

    ASSERT_TRUE(contact_manager_->add_or_update_contact(domain::Contact(charlie_id, "Charlie")).is_ok());

    // Leave lookup_user_identity empty; provide per-user device crypto directory only
    interfaces::DeviceCryptoDirectoryEntry dev_entry{
        .device_id = domain::DeviceId("dev-charlie-01"),
        .identity_key = charlie_kp.public_key,
        .signed_prekey = std::vector<uint8_t>(32, 0x22),
        .signed_prekey_signature = std::vector<uint8_t>(64, 0x33),
        .one_time_prekey = std::nullopt,
        .one_time_prekey_id = "",
        .status = domain::DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = charlie_fp,
        .remaining_one_time_prekeys = 0,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };
    gateway_->set_simulated_user_directory(charlie_id, {dev_entry});

    auto sn_res = contact_manager_->get_or_compute_safety_number(charlie_id);
    ASSERT_TRUE(sn_res.is_ok());

    auto direct_sn =
        safety_engine_->compute_safety_number(alice_id_, alice_ik_, charlie_id, charlie_kp.public_key).value();
    EXPECT_EQ(sn_res.value(), direct_sn);
}

TEST_F(ContactVerificationPipelineTest, SetContactVerifiedPinsAndClearsFingerprintInSecureStorage) {
    const domain::UserId bob_id("usr-bob-pin");
    auto bob_kp = crypto_->generate_identity_keypair().value();
    const std::string bob_fp = crypto_->compute_identity_fingerprint(bob_kp.public_key).value();

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob Pin", bob_kp.public_key, bob_fp, 1),
    });

    ASSERT_TRUE(contact_manager_->add_or_update_contact(domain::Contact(bob_id, "Bob Pin")).is_ok());

    // Initially Unverified in both stores
    EXPECT_FALSE(contact_manager_->get_contact(bob_id).value().is_verified());
    EXPECT_FALSE(safety_engine_->get_verified_fingerprint(bob_id).value().has_value());

    // Verify contact (out-of-band numeric comparison confirmed)
    auto verify_res = contact_manager_->set_contact_verified(bob_id, true);
    ASSERT_TRUE(verify_res.is_ok());

    // 1. ILocalStore updated with Verified status & pinned fingerprint
    auto contact_after = contact_manager_->get_contact(bob_id).value();
    EXPECT_TRUE(contact_after.is_verified());
    EXPECT_EQ(contact_after.verification_status(), domain::KeyVerificationStatus::Verified);
    EXPECT_EQ(contact_after.identity_fingerprint(), bob_fp);

    // 2. ISecureStorage holds identity.verified.<bob_id> matching Bob's Ed25519 key
    auto stored_fp = safety_engine_->get_verified_fingerprint(bob_id).value();
    ASSERT_TRUE(stored_fp.has_value());
    EXPECT_EQ(*stored_fp, bob_fp);
    EXPECT_EQ(safety_engine_->evaluate_key_verification_status(bob_id, bob_kp.public_key).value(),
              domain::KeyVerificationStatus::Verified);

    // Clear verification state
    ASSERT_TRUE(contact_manager_->set_contact_verified(bob_id, false).is_ok());
    EXPECT_EQ(contact_manager_->get_contact(bob_id).value().verification_status(),
              domain::KeyVerificationStatus::Unverified);
    EXPECT_FALSE(safety_engine_->get_verified_fingerprint(bob_id).value().has_value());
    EXPECT_EQ(safety_engine_->evaluate_key_verification_status(bob_id, bob_kp.public_key).value(),
              domain::KeyVerificationStatus::Unverified);

    // Legacy alias verify_contact_key() also delegates to cryptographic pinning
    ASSERT_TRUE(contact_manager_->verify_contact_key(bob_id, true).is_ok());
    EXPECT_TRUE(safety_engine_->get_verified_fingerprint(bob_id).value().has_value());
}

TEST_F(ContactVerificationPipelineTest, SetContactVerifiedFailsWhenPeerKeyUnresolvableOnWiredGateway) {
    const domain::UserId dave_id("usr-dave-missing");
    ASSERT_TRUE(contact_manager_->add_or_update_contact(domain::Contact(dave_id, "Dave Missing")).is_ok());

    auto res = contact_manager_->set_contact_verified(dave_id, true);
    EXPECT_TRUE(res.is_error());
    EXPECT_EQ(res.error().category(), ClientErrorCategory::Validation);

    // Must remain Unverified in ILocalStore
    EXPECT_EQ(contact_manager_->get_contact(dave_id).value().verification_status(),
              domain::KeyVerificationStatus::Unverified);
}

} // namespace
} // namespace securecloud::client::application::managers
