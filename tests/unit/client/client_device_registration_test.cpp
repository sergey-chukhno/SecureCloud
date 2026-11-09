#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/managers/device_manager.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <gtest/gtest.h>
#include <QSignalSpy>

namespace {

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::application;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::infrastructure;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;

ClientConfig make_test_config() {
    ClientConfig config;
    config.gateway_url = "https://127.0.0.1";
    config.gateway_port = 8443;
    return config;
}

std::unique_ptr<ClientApplication> create_test_app() {
    auto gateway = std::make_unique<DefaultGatewayClient>(make_test_config());
    auto local_store = std::make_unique<MemoryLocalStore>();
    auto secure_storage = std::make_unique<MemorySecureStorage>();
    auto crypto_provider = std::make_unique<OpenSslCryptoProvider>();

    auto bootstrap = ClientBootstrap::create_with_adapters(
        make_test_config(), std::move(gateway), std::move(local_store),
        std::move(secure_storage), std::move(crypto_provider));

    return std::make_unique<ClientApplication>(std::move(bootstrap));
}

TEST(ClientDeviceRegistrationTest, RegistrationPipelineAndKeyGeneration) {
    auto app = create_test_app();
    ASSERT_TRUE(app->initialize().is_ok());

    auto& device_mgr = app->bootstrap().device_manager();
    const UserId uid("alice-secops-01");

    // Initial state: no local device
    EXPECT_TRUE(device_mgr.get_local_device().is_error());

    // Register device
    auto reg_res = device_mgr.register_device(uid, "MacBook Pro M3 Max");
    ASSERT_TRUE(reg_res.is_ok());

    const auto& device = reg_res.value();
    EXPECT_FALSE(device.device_id().empty());
    EXPECT_EQ(device.user_id(), uid);
    EXPECT_EQ(device.display_name(), "MacBook Pro M3 Max");
    EXPECT_EQ(device.status(), DeviceAuthorizationStatus::Authorized);

    // Cryptographic Identity is valid and complete
    const auto& identity = device.crypto_identity();
    EXPECT_TRUE(CryptoIdentity::is_valid_fingerprint(identity.fingerprint()));
    EXPECT_EQ(identity.verification_status(), KeyVerificationStatus::Verified);
    EXPECT_FALSE(identity.identity_key().empty());
    EXPECT_FALSE(identity.signed_prekey().empty());
    EXPECT_FALSE(identity.signature().empty());

    // Secure Storage has the private bundle
    EXPECT_TRUE(KeyStorageHelper::has_bundle(device_mgr.secure_storage(), device.device_id()).value());
    auto bundle_res = KeyStorageHelper::load_bundle(device_mgr.secure_storage(), device.device_id());
    ASSERT_TRUE(bundle_res.is_ok());
    EXPECT_EQ(bundle_res.value().one_time_prekey_count(), PrekeyPolicy::kInitialPrekeyBatchSize);
}

TEST(ClientDeviceRegistrationTest, RegistrationRejectsInvalidParameters) {
    auto app = create_test_app();
    ASSERT_TRUE(app->initialize().is_ok());

    auto& device_mgr = app->bootstrap().device_manager();

    // Empty UserId default constructor produces empty user ID
    const UserId empty_uid;
    auto reg_empty_user = device_mgr.register_device(empty_uid, "Valid Name");
    EXPECT_TRUE(reg_empty_user.is_error());
}

TEST(ClientDeviceRegistrationTest, PrekeyReplenishmentAndRotationPipeline) {
    auto app = create_test_app();
    ASSERT_TRUE(app->initialize().is_ok());

    auto& device_mgr = app->bootstrap().device_manager();
    const UserId uid("bob-secops-02");

    auto reg_res = device_mgr.register_device(uid, "Linux Workstation");
    ASSERT_TRUE(reg_res.is_ok());

    // Check inventory
    auto inv_res = device_mgr.check_prekey_inventory();
    ASSERT_TRUE(inv_res.is_ok());
    EXPECT_EQ(inv_res.value().active_prekey_count(), 100u);
    EXPECT_FALSE(inv_res.value().is_low_inventory());

    // Replenish batch of 50
    auto rep_res = device_mgr.replenish_prekeys(50);
    ASSERT_TRUE(rep_res.is_ok());
    EXPECT_EQ(rep_res.value(), 50u);

    // Rotate signed prekey
    const std::string old_spk = device_mgr.get_local_device().value().crypto_identity().signed_prekey();
    auto rot_res = device_mgr.rotate_signed_prekey();
    ASSERT_TRUE(rot_res.is_ok());

    const std::string new_spk = device_mgr.get_local_device().value().crypto_identity().signed_prekey();
    EXPECT_NE(old_spk, new_spk);

    // Verify signature of rotated prekey
    const auto dev = device_mgr.get_local_device().value();
    auto verify_res = device_mgr.crypto_provider().verify_signed_prekey(
        dev.crypto_identity().identity_key_bytes(),
        dev.crypto_identity().signed_prekey_bytes(),
        dev.crypto_identity().signature_bytes());
    ASSERT_TRUE(verify_res.is_ok());
    EXPECT_TRUE(verify_res.value());
}

TEST(ClientDeviceRegistrationTest, WorkspaceViewModelSettingsTrustCenterIntegration) {
    auto app = create_test_app();
    ASSERT_TRUE(app->initialize().is_ok());

    // Register local device before launching UI
    auto& device_mgr = app->bootstrap().device_manager();
    const UserId uid("charlie-secops-03");
    auto reg_res = device_mgr.register_device(uid, "SecOps Desktop M3");
    ASSERT_TRUE(reg_res.is_ok());
    const auto real_device = reg_res.value();

    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    // 1. Verify localDeviceIdentity reflects the real device
    const QVariantMap local_id = vm.localDeviceIdentity();
    EXPECT_EQ(local_id.value(QStringLiteral("deviceId")).toString().toStdString(),
              real_device.device_id().value());
    EXPECT_EQ(local_id.value(QStringLiteral("displayName")).toString().toStdString(),
              real_device.display_name());
    EXPECT_EQ(local_id.value(QStringLiteral("identityKeyHex")).toString().toStdString(),
              real_device.crypto_identity().identity_key());
    EXPECT_EQ(local_id.value(QStringLiteral("fingerprint")).toString().toStdString(),
              real_device.crypto_identity().fingerprint());
    EXPECT_TRUE(local_id.value(QStringLiteral("fingerprint")).toString().startsWith(QStringLiteral("SHA256:")));
    EXPECT_TRUE(local_id.value(QStringLiteral("isVerified")).toBool());
    EXPECT_EQ(local_id.value(QStringLiteral("status")).toString(), QStringLiteral("Authorized"));
    EXPECT_EQ(local_id.value(QStringLiteral("prekeyCount")).toInt(), 100);
    EXPECT_EQ(local_id.value(QStringLiteral("prekeyHealthStatus")).toString(), QStringLiteral("Healthy"));

    // 2. Verify devices list reflects real device
    const QVariantList dev_list = vm.devices();
    ASSERT_FALSE(dev_list.isEmpty());
    bool found_real_device = false;
    for (const auto& entry_var : dev_list) {
        const QVariantMap entry = entry_var.toMap();
        if (entry.value(QStringLiteral("deviceId")).toString().toStdString() == real_device.device_id().value()) {
            found_real_device = true;
            EXPECT_TRUE(entry.value(QStringLiteral("isCurrentDevice")).toBool());
            EXPECT_TRUE(entry.value(QStringLiteral("isVerified")).toBool());
            EXPECT_EQ(entry.value(QStringLiteral("status")).toString(), QStringLiteral("Authorized"));
            break;
        }
    }
    EXPECT_TRUE(found_real_device);

    // 3. Test rotateSignedPrekey via ViewModel
    QSignalSpy spy_identity(&vm, &WorkspaceViewModel::localDeviceIdentityChanged);
    QSignalSpy spy_devices(&vm, &WorkspaceViewModel::devicesChanged);

    const QString original_spk = local_id.value(QStringLiteral("signedPrekeyId")).toString();
    vm.rotateSignedPrekey();

    EXPECT_GE(spy_identity.count(), 1);
    EXPECT_GE(spy_devices.count(), 1);

    const QVariantMap updated_id = vm.localDeviceIdentity();
    const QString updated_spk = updated_id.value(QStringLiteral("signedPrekeyId")).toString();
    EXPECT_NE(original_spk, updated_spk);
    EXPECT_TRUE(updated_id.value(QStringLiteral("isVerified")).toBool());
}

} // namespace
