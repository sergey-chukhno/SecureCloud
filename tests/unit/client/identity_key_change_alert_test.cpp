#include "application/client_config.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/delivery_state.hpp"
#include "domain/device_id.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::client::application::managers {
namespace {

using infrastructure::adapters::DefaultGatewayClient;
using infrastructure::adapters::MemoryLocalStore;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;

class IdentityKeyChangeAlertTest : public ::testing::Test {
  protected:
    void SetUp() override {
        local_store_ = std::make_unique<MemoryLocalStore>();
        secure_storage_ = std::make_unique<MemorySecureStorage>();
        crypto_ = std::make_unique<OpenSslCryptoProvider>();
        gateway_ = std::make_unique<DefaultGatewayClient>(ClientConfig::create_default());
        safety_engine_ = std::make_unique<SafetyNumberEngine>(*crypto_, *secure_storage_);

        alice_id_ = domain::UserId("usr-alice-alert");
        alice_dev_ = domain::DeviceId("dev-alice-01");
        auto alice_kp = crypto_->generate_identity_keypair().value();
        alice_ik_ = std::move(alice_kp.public_key);

        contact_manager_ = std::make_unique<ContactManager>(*local_store_, *gateway_, *safety_engine_);
        contact_manager_->set_local_identity(alice_id_, alice_ik_);

        messaging_manager_ = std::make_unique<MessagingManager>(*gateway_, *local_store_, *crypto_);
    }

    std::unique_ptr<MemoryLocalStore> local_store_;
    std::unique_ptr<MemorySecureStorage> secure_storage_;
    std::unique_ptr<OpenSslCryptoProvider> crypto_;
    std::unique_ptr<DefaultGatewayClient> gateway_;
    std::unique_ptr<SafetyNumberEngine> safety_engine_;
    std::unique_ptr<ContactManager> contact_manager_;
    std::unique_ptr<MessagingManager> messaging_manager_;

    domain::UserId alice_id_;
    domain::DeviceId alice_dev_;
    std::vector<uint8_t> alice_ik_;
};

TEST_F(IdentityKeyChangeAlertTest, SyncContactsDetectsIdentityKeyRotationUpdatesSafetyNumberAndFiresAlert) {
    const domain::UserId bob_id("usr-bob-rotate");
    auto bob_kp_v1 = crypto_->generate_identity_keypair().value();
    const std::string bob_fp_v1 = crypto_->compute_identity_fingerprint(bob_kp_v1.public_key).value();

    // Seed Bob v1 and verify him out-of-band
    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob Rotate", bob_kp_v1.public_key, bob_fp_v1, 1),
    });
    const auto bob_entry_v1 = gateway_->lookup_user_identity(bob_id).value();
    auto add_res = contact_manager_->add_contact_from_directory(bob_entry_v1);
    ASSERT_TRUE(add_res.is_ok());
    const std::string original_sn = add_res.value().safety_number();
    ASSERT_TRUE(contact_manager_->set_contact_verified(bob_id, true).is_ok());

    // Capture key change alerts
    std::vector<std::pair<domain::UserId, std::string>> alerts;
    contact_manager_->set_key_change_alert_callback(
        [&alerts](const domain::UserId& uid, const std::string& new_sn) { alerts.emplace_back(uid, new_sn); });

    // Bob's key rotates on backend directory (e.g., reinstall or MITM substitution)
    auto bob_kp_v2 = crypto_->generate_identity_keypair().value();
    const std::string bob_fp_v2 = crypto_->compute_identity_fingerprint(bob_kp_v2.public_key).value();
    ASSERT_NE(bob_fp_v1, bob_fp_v2);

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob Rotate", bob_kp_v2.public_key, bob_fp_v2, 1),
    });

    auto sync_res = contact_manager_->sync_contacts();
    ASSERT_TRUE(sync_res.is_ok());
    EXPECT_EQ(sync_res.value(), 1u);

    auto bob_updated = contact_manager_->get_contact(bob_id).value();
    EXPECT_EQ(bob_updated.verification_status(), domain::KeyVerificationStatus::KeyChanged);
    EXPECT_TRUE(bob_updated.has_key_changed());
    EXPECT_FALSE(bob_updated.can_send_messages());
    EXPECT_EQ(bob_updated.identity_fingerprint(), bob_fp_v2);

    const std::string expected_new_sn =
        safety_engine_->compute_safety_number(alice_id_, alice_ik_, bob_id, bob_kp_v2.public_key).value();
    EXPECT_NE(bob_updated.safety_number(), original_sn);
    EXPECT_EQ(bob_updated.safety_number(), expected_new_sn);

    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].first, bob_id);
    EXPECT_EQ(alerts[0].second, expected_new_sn);
}

TEST_F(IdentityKeyChangeAlertTest, EvaluateContactKeyChangeDetectsMismatchDirectly) {
    const domain::UserId bob_id("usr-bob-direct");
    auto bob_kp_v1 = crypto_->generate_identity_keypair().value();
    const std::string bob_fp_v1 = crypto_->compute_identity_fingerprint(bob_kp_v1.public_key).value();

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob Direct", bob_kp_v1.public_key, bob_fp_v1, 1),
    });
    ASSERT_TRUE(contact_manager_->add_contact_from_directory(gateway_->lookup_user_identity(bob_id).value()).is_ok());
    ASSERT_TRUE(contact_manager_->set_contact_verified(bob_id, true).is_ok());

    // Observing the same key returns Verified without triggering KeyChanged
    auto match_res = contact_manager_->evaluate_contact_key_change(bob_id, bob_kp_v1.public_key);
    ASSERT_TRUE(match_res.is_ok());
    EXPECT_EQ(match_res.value(), domain::KeyVerificationStatus::Verified);

    // Observing a substituted key transitions immediately to KeyChanged and updates safety number
    auto rogue_kp = crypto_->generate_identity_keypair().value();
    bool alert_fired = false;
    contact_manager_->set_key_change_alert_callback(
        [&alert_fired](const domain::UserId&, const std::string&) { alert_fired = true; });

    auto mismatch_res = contact_manager_->evaluate_contact_key_change(bob_id, rogue_kp.public_key);
    ASSERT_TRUE(mismatch_res.is_ok());
    EXPECT_EQ(mismatch_res.value(), domain::KeyVerificationStatus::KeyChanged);
    EXPECT_TRUE(alert_fired);

    auto bob_after = contact_manager_->get_contact(bob_id).value();
    EXPECT_TRUE(bob_after.has_key_changed());
    EXPECT_EQ(bob_after.safety_number(),
              safety_engine_->compute_safety_number(alice_id_, alice_ik_, bob_id, rogue_kp.public_key).value());
}

TEST_F(IdentityKeyChangeAlertTest, OutboundMessagingSuspendedAcrossStageSendAndRetryOnKeyChange) {
    const domain::UserId bob_id("usr-bob-guard");
    const domain::DeviceId bob_dev("dev-bob-01");
    auto bob_kp_v1 = crypto_->generate_identity_keypair().value();
    const std::string bob_fp_v1 = crypto_->compute_identity_fingerprint(bob_kp_v1.public_key).value();

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob Guard", bob_kp_v1.public_key, bob_fp_v1, 1),
    });
    ASSERT_TRUE(contact_manager_->add_contact_from_directory(gateway_->lookup_user_identity(bob_id).value()).is_ok());
    ASSERT_TRUE(contact_manager_->set_contact_verified(bob_id, true).is_ok());

    auto conv_res = messaging_manager_->open_direct_conversation(alice_id_, bob_id, "Bob Guard");
    ASSERT_TRUE(conv_res.is_ok());
    const auto conv_id = conv_res.value().conversation_id();

    // Stage a message before key change and mark it Failed (to test retry suspension later)
    auto pre_stage = messaging_manager_->stage_outbound_message(conv_id, alice_id_, alice_dev_, "Initial message");
    ASSERT_TRUE(pre_stage.is_ok());
    const auto failed_msg_id = pre_stage.value().message_id();
    ASSERT_TRUE(messaging_manager_->update_message_delivery_state(conv_id, failed_msg_id, domain::DeliveryState::Failed)
                    .is_ok());

    // Now Bob's key unexpectedly changes
    auto bob_kp_v2 = crypto_->generate_identity_keypair().value();
    ASSERT_EQ(contact_manager_->evaluate_contact_key_change(bob_id, bob_kp_v2.public_key).value(),
              domain::KeyVerificationStatus::KeyChanged);

    // 1. stage_outbound_message is strictly suspended (ADR-008 §18)
    auto stage_res = messaging_manager_->stage_outbound_message(conv_id, alice_id_, alice_dev_, "Blocked draft");
    EXPECT_TRUE(stage_res.is_error());
    EXPECT_NE(stage_res.error().user_message().find("recipient identity key changed"), std::string::npos);

    // 2. send_message is strictly suspended
    auto send_res = messaging_manager_->send_message(conv_id, alice_id_, alice_dev_, bob_dev, "Blocked direct send");
    EXPECT_TRUE(send_res.is_error());
    EXPECT_NE(send_res.error().user_message().find("recipient identity key changed"), std::string::npos);

    // 3. retry_failed_message is also strictly suspended
    auto retry_res = messaging_manager_->retry_failed_message(conv_id, failed_msg_id);
    EXPECT_TRUE(retry_res.is_error());
    EXPECT_NE(retry_res.error().user_message().find("recipient identity key changed"), std::string::npos);
}

TEST_F(IdentityKeyChangeAlertTest, AcknowledgeAndVerifyKeyChangePinsNewKeyAndResumesOutboundMessaging) {
    const domain::UserId bob_id("usr-bob-recover");
    const domain::DeviceId bob_dev("dev-bob-02");
    auto bob_kp_v1 = crypto_->generate_identity_keypair().value();
    const std::string bob_fp_v1 = crypto_->compute_identity_fingerprint(bob_kp_v1.public_key).value();

    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob Recover", bob_kp_v1.public_key, bob_fp_v1, 1),
    });
    ASSERT_TRUE(contact_manager_->add_contact_from_directory(gateway_->lookup_user_identity(bob_id).value()).is_ok());
    ASSERT_TRUE(contact_manager_->set_contact_verified(bob_id, true).is_ok());

    auto conv_res = messaging_manager_->open_direct_conversation(alice_id_, bob_id, "Bob Recover");
    ASSERT_TRUE(conv_res.is_ok());
    const auto conv_id = conv_res.value().conversation_id();

    // Rotate key in directory and sync
    auto bob_kp_v2 = crypto_->generate_identity_keypair().value();
    const std::string bob_fp_v2 = crypto_->compute_identity_fingerprint(bob_kp_v2.public_key).value();
    gateway_->set_simulated_directory_users({
        domain::DirectoryUserEntry(bob_id, "@bob", "Bob Recover", bob_kp_v2.public_key, bob_fp_v2, 1),
    });
    ASSERT_TRUE(contact_manager_->sync_contacts().is_ok());
    ASSERT_TRUE(contact_manager_->get_contact(bob_id).value().has_key_changed());
    EXPECT_TRUE(messaging_manager_->stage_outbound_message(conv_id, alice_id_, alice_dev_, "Blocked").is_error());

    // User acknowledges & re-verifies out-of-band
    ASSERT_TRUE(contact_manager_->acknowledge_and_verify_key_change(bob_id).is_ok());

    // Verify new key pinned in ISecureStorage and contact restored to Verified
    auto contact_after = contact_manager_->get_contact(bob_id).value();
    EXPECT_TRUE(contact_after.is_verified());
    EXPECT_FALSE(contact_after.has_key_changed());
    EXPECT_TRUE(contact_after.can_send_messages());
    EXPECT_EQ(contact_after.identity_fingerprint(), bob_fp_v2);
    EXPECT_EQ(contact_after.safety_number(),
              safety_engine_->compute_safety_number(alice_id_, alice_ik_, bob_id, bob_kp_v2.public_key).value());
    EXPECT_EQ(safety_engine_->get_verified_fingerprint(bob_id).value(), bob_fp_v2);

    // Outbound messaging immediately resumes
    EXPECT_TRUE(messaging_manager_->stage_outbound_message(conv_id, alice_id_, alice_dev_, "Resumed").is_ok());
    EXPECT_TRUE(messaging_manager_->send_message(conv_id, alice_id_, alice_dev_, bob_dev, "Resumed direct").is_ok());
}

} // namespace
} // namespace securecloud::client::application::managers
