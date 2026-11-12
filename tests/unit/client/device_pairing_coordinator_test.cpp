#include "application/client_config.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/device_pairing_coordinator.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <string>

namespace securecloud::client::application::managers::test {

class DevicePairingCoordinatorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ClientConfig config;
        config.gateway_url = "http://127.0.0.1:8080";
        gateway_ = std::make_unique<infrastructure::adapters::DefaultGatewayClient>(config);
        secure_storage_ = std::make_unique<infrastructure::adapters::MemorySecureStorage>();
        crypto_provider_ = std::make_unique<infrastructure::adapters::OpenSslCryptoProvider>();
        device_manager_ = std::make_unique<DeviceManager>(*gateway_, *secure_storage_, *crypto_provider_);

        coordinator_ = std::make_unique<DevicePairingCoordinator>(*gateway_, *secure_storage_, *crypto_provider_,
                                                                  *device_manager_);
    }

    std::unique_ptr<infrastructure::adapters::DefaultGatewayClient> gateway_;
    std::unique_ptr<infrastructure::adapters::MemorySecureStorage> secure_storage_;
    std::unique_ptr<infrastructure::adapters::OpenSslCryptoProvider> crypto_provider_;
    std::unique_ptr<DeviceManager> device_manager_;
    std::unique_ptr<DevicePairingCoordinator> coordinator_;
    domain::UserId test_user_{"usr-alice-test"};
};

TEST_F(DevicePairingCoordinatorTest, CompanionInitiationSuccess) {
    auto res = coordinator_->initiate_companion_pairing(test_user_, "MacBook Air Companion");
    ASSERT_TRUE(res.is_ok());

    auto session = res.value();
    EXPECT_EQ(session.user_id, test_user_);
    EXPECT_FALSE(session.device_id.empty());
    EXPECT_EQ(session.display_name, "MacBook Air Companion");
    EXPECT_FALSE(session.is_authorized);
    EXPECT_FALSE(session.qr_uri.empty());
    EXPECT_NE(session.qr_uri.find("securecloud://pair?"), std::string::npos);
    EXPECT_NE(session.qr_uri.find("code="), std::string::npos);

    // Assert SAS generation
    EXPECT_EQ(session.expected_sas.numeric_code().size(), 6U);
    EXPECT_EQ(session.expected_sas.visual_emojis().size(), 4U);
}

TEST_F(DevicePairingCoordinatorTest, CompanionInitiationRejectsEmptyUser) {
    auto res = coordinator_->initiate_companion_pairing(domain::UserId{}, "Tablet");
    EXPECT_TRUE(res.is_error());
    EXPECT_EQ(res.error().code(), ClientErrorCode::ValidationFailed);

    auto res2 = coordinator_->initiate_companion_pairing(test_user_, "");
    EXPECT_TRUE(res2.is_error());
    EXPECT_EQ(res2.error().code(), ClientErrorCode::ValidationFailed);
}

TEST_F(DevicePairingCoordinatorTest, CompanionPollingTransitionsToAuthorized) {
    auto init_res = coordinator_->initiate_companion_pairing(test_user_, "iPad Pro");
    ASSERT_TRUE(init_res.is_ok());
    auto session = init_res.value();

    // 1. Initial poll when no device in gateway list
    auto poll1 = coordinator_->poll_companion_authorization(session);
    ASSERT_TRUE(poll1.is_ok());
    EXPECT_FALSE(poll1.value());
    EXPECT_FALSE(session.is_authorized);

    // 2. Add device as Authorized in simulated gateway
    domain::CryptoIdentity dummy_id;
    domain::Device comp_device(session.device_id, session.user_id, session.display_name, dummy_id,
                               domain::DeviceAuthorizationStatus::Authorized);
    gateway_->set_simulated_user_devices(test_user_, {comp_device});

    // 3. Second poll should detect authorization
    auto poll2 = coordinator_->poll_companion_authorization(session);
    ASSERT_TRUE(poll2.is_ok());
    EXPECT_TRUE(poll2.value());
    EXPECT_TRUE(session.is_authorized);
}

TEST_F(DevicePairingCoordinatorTest, PrimaryInspectionOfValidChallenge) {
    // 1. Register local primary device on workstation
    auto reg_res = device_manager_->register_device(test_user_, "Primary Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    // 2. Companion creates pairing session
    auto comp_res = coordinator_->initiate_companion_pairing(test_user_, "Laptop Node");
    ASSERT_TRUE(comp_res.is_ok());
    const auto& session = comp_res.value();

    // 3. Primary workstation inspects QR URI
    auto prompt_res = coordinator_->inspect_pairing_challenge(session.qr_uri);
    ASSERT_TRUE(prompt_res.is_ok());

    const auto& prompt = prompt_res.value();
    EXPECT_EQ(prompt.user_id, test_user_);
    EXPECT_EQ(prompt.device_id, session.device_id);
    EXPECT_EQ(prompt.display_name, "Laptop Node");
    EXPECT_FALSE(prompt.is_expired());

    // Assert SAS was computed
    EXPECT_EQ(prompt.sas.numeric_code().size(), 6U);
    EXPECT_EQ(prompt.sas.visual_emojis().size(), 4U);
}

TEST_F(DevicePairingCoordinatorTest, PrimaryInspectionRejectsMismatchedUser) {
    // Register workstation under test_user_ ("usr-alice-test")
    auto reg_res = device_manager_->register_device(test_user_, "Primary Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    // Companion session created for a different user ("usr-mallory")
    domain::UserId mallory("usr-mallory-attacker");
    auto comp_res = coordinator_->initiate_companion_pairing(mallory, "Rogue Device");
    ASSERT_TRUE(comp_res.is_ok());

    // Primary inspects Mallory's QR URI
    auto prompt_res = coordinator_->inspect_pairing_challenge(comp_res.value().qr_uri);
    EXPECT_TRUE(prompt_res.is_error());
    EXPECT_EQ(prompt_res.error().code(), ClientErrorCode::ValidationFailed);
    EXPECT_NE(prompt_res.error().user_message().find("mismatch"), std::string::npos);
}

TEST_F(DevicePairingCoordinatorTest, PrimaryInspectionRejectsExpiredChallenge) {
    // Register workstation
    auto reg_res = device_manager_->register_device(test_user_, "Primary Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    // Craft expired challenge payload
    std::vector<uint8_t> pk(32, 0x55);
    auto past = std::chrono::system_clock::now() - std::chrono::minutes(10);
    domain::PairingChallengePayload expired_payload(test_user_, domain::DeviceId("dev-past-01"), pk, "948201", past,
                                                    "Expired Node");

    auto prompt_res = coordinator_->inspect_pairing_challenge(expired_payload.to_uri());
    EXPECT_TRUE(prompt_res.is_error());
    EXPECT_EQ(prompt_res.error().code(), ClientErrorCode::ValidationFailed);
    EXPECT_NE(prompt_res.error().user_message().find("expired"), std::string::npos);
}

TEST_F(DevicePairingCoordinatorTest, PrimaryApprovalWithMfaSuccess) {
    auto reg_res = device_manager_->register_device(test_user_, "Primary Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    auto comp_res = coordinator_->initiate_companion_pairing(test_user_, "Companion Surface");
    ASSERT_TRUE(comp_res.is_ok());

    auto prompt_res = coordinator_->inspect_pairing_challenge(comp_res.value().qr_uri);
    ASSERT_TRUE(prompt_res.is_ok());

    // Approve with valid MFA token
    auto app_res = coordinator_->approve_companion_pairing(prompt_res.value(), "valid_totp_or_hardware_mfa_token");
    EXPECT_TRUE(app_res.is_ok());
}

TEST_F(DevicePairingCoordinatorTest, PrimaryApprovalRejectsMissingOrInvalidMfa) {
    auto reg_res = device_manager_->register_device(test_user_, "Primary Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    auto comp_res = coordinator_->initiate_companion_pairing(test_user_, "Companion Surface");
    ASSERT_TRUE(comp_res.is_ok());

    auto prompt_res = coordinator_->inspect_pairing_challenge(comp_res.value().qr_uri);
    ASSERT_TRUE(prompt_res.is_ok());

    // 1. Missing MFA token
    auto app_res1 = coordinator_->approve_companion_pairing(prompt_res.value(), "");
    EXPECT_TRUE(app_res1.is_error());
    EXPECT_EQ(app_res1.error().code(), ClientErrorCode::AuthenticationRequired);

    // 2. Invalid MFA token
    auto app_res2 = coordinator_->approve_companion_pairing(prompt_res.value(), "invalid");
    EXPECT_TRUE(app_res2.is_error());
    EXPECT_EQ(app_res2.error().code(), ClientErrorCode::InvalidCredentials);
}

TEST_F(DevicePairingCoordinatorTest, FullRoundTripEndToEndPairing) {
    // 1. Primary workstation registers
    auto reg_res = device_manager_->register_device(test_user_, "SecOps Primary");
    ASSERT_TRUE(reg_res.is_ok());

    // 2. Companion device initiates pairing
    auto comp_res = coordinator_->initiate_companion_pairing(test_user_, "Field Tablet");
    ASSERT_TRUE(comp_res.is_ok());
    auto session = comp_res.value();

    // Register companion as Pending in simulated gateway
    domain::CryptoIdentity dummy_id;
    domain::Device comp_device(session.device_id, session.user_id, session.display_name, dummy_id,
                               domain::DeviceAuthorizationStatus::Pending);
    gateway_->set_simulated_user_devices(test_user_, {reg_res.value(), comp_device});

    // 3. Primary workstation scans QR URI
    auto prompt_res = coordinator_->inspect_pairing_challenge(session.qr_uri);
    ASSERT_TRUE(prompt_res.is_ok());
    const auto& prompt = prompt_res.value();

    // 4. Primary workstation approves with MFA
    auto approve_res = coordinator_->approve_companion_pairing(prompt, "mfa_auth_level_verified");
    ASSERT_TRUE(approve_res.is_ok());

    // 5. Companion polls Gateway and detects authorization
    auto poll_res = coordinator_->poll_companion_authorization(session);
    ASSERT_TRUE(poll_res.is_ok());
    EXPECT_TRUE(poll_res.value());
    EXPECT_TRUE(session.is_authorized);
}

} // namespace securecloud::client::application::managers::test
