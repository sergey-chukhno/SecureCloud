#include "application/client_application.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_hardware_authenticator.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/simulated_hardware_authenticator.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <QSignalSpy>
#include <gtest/gtest.h>
#include <memory>

namespace securecloud::client::tests {

using namespace securecloud::client::application;
using namespace securecloud::client::ui;

class WorkspaceViewModelDevicesTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ClientConfig config;
        config.gateway_url = "http://127.0.0.1:8080";

        app_ = std::make_unique<ClientApplication>(config);
        ASSERT_TRUE(app_->initialize().is_ok());

        nav_ = std::make_unique<NavigationController>();
        vm_ = std::make_unique<WorkspaceViewModel>(*app_, *nav_);

        test_user_ = domain::UserId("usr-alice-test");
    }

    void TearDown() override {
        vm_.reset();
        nav_.reset();
        if (app_) {
            app_->shutdown();
            app_.reset();
        }
    }

    std::unique_ptr<ClientApplication> app_;
    std::unique_ptr<NavigationController> nav_;
    std::unique_ptr<WorkspaceViewModel> vm_;
    domain::UserId test_user_;
};

TEST_F(WorkspaceViewModelDevicesTest, HardwareAttestationInfoReflectsState) {
    auto info = vm_->hardwareAttestationInfo();
    EXPECT_TRUE(info.value(QStringLiteral("available")).toBool());
    EXPECT_TRUE(info.value(QStringLiteral("isVerified")).toBool());
    EXPECT_FALSE(info.value(QStringLiteral("aaguid")).toString().isEmpty());
    EXPECT_FALSE(info.value(QStringLiteral("authenticatorType")).toString().isEmpty());
}

TEST_F(WorkspaceViewModelDevicesTest, PairNewDeviceGeneratesPairingSessionAndEmitsSignal) {
    QSignalSpy spy(vm_.get(), &WorkspaceViewModel::devicesChanged);

    QString devId = vm_->pairNewDevice("Surface Pro 11");
    EXPECT_FALSE(devId.isEmpty());
    EXPECT_GE(spy.count(), 1);

    auto list = vm_->devices();
    bool found = false;
    for (const auto& itemVar : list) {
        auto map = itemVar.toMap();
        if (map.value(QStringLiteral("deviceId")).toString() == devId) {
            EXPECT_EQ(map.value(QStringLiteral("status")).toString(), QStringLiteral("Pending"));
            EXPECT_EQ(map.value(QStringLiteral("displayName")).toString(), QStringLiteral("Surface Pro 11"));
            EXPECT_NE(map.value(QStringLiteral("lastSeenText")).toString().indexOf("SAS:"), -1);
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(WorkspaceViewModelDevicesTest, ApproveDeviceWithHardwareMfaTransitionsToAuthorized) {
    QString devId = vm_->pairNewDevice("Companion iPad");
    ASSERT_FALSE(devId.isEmpty());

    bool ok = vm_->approveDevice(devId);
    EXPECT_TRUE(ok);

    auto list = vm_->devices();
    bool approved = false;
    for (const auto& itemVar : list) {
        auto map = itemVar.toMap();
        if (map.value(QStringLiteral("deviceId")).toString() == devId) {
            EXPECT_EQ(map.value(QStringLiteral("status")).toString(), QStringLiteral("Authorized"));
            EXPECT_TRUE(map.value(QStringLiteral("isVerified")).toBool());
            approved = true;
            break;
        }
    }
    EXPECT_TRUE(approved);
}

TEST_F(WorkspaceViewModelDevicesTest, RevokeDeviceExecutesRevocationPipeline) {
    QString devId = vm_->pairNewDevice("Decommissioned Laptop");
    ASSERT_FALSE(devId.isEmpty());

    // Revoke companion device
    bool ok = vm_->revokeDevice(devId);
    EXPECT_TRUE(ok);

    auto list = vm_->devices();
    bool revoked = false;
    for (const auto& itemVar : list) {
        auto map = itemVar.toMap();
        if (map.value(QStringLiteral("deviceId")).toString() == devId) {
            EXPECT_EQ(map.value(QStringLiteral("status")).toString(), QStringLiteral("Revoked"));
            EXPECT_FALSE(map.value(QStringLiteral("isVerified")).toBool());
            revoked = true;
            break;
        }
    }
    EXPECT_TRUE(revoked);
}

TEST_F(WorkspaceViewModelDevicesTest, RevokingActiveWorkstationFromItselfIsRejected) {
    QSignalSpy errorSpy(vm_.get(), &WorkspaceViewModel::workspaceError);

    // Find the current workstation device ID
    auto list = vm_->devices();
    QString currentDevId;
    for (const auto& itemVar : list) {
        auto map = itemVar.toMap();
        if (map.value(QStringLiteral("isCurrentDevice")).toBool()) {
            currentDevId = map.value(QStringLiteral("deviceId")).toString();
            break;
        }
    }

    ASSERT_FALSE(currentDevId.isEmpty());
    bool ok = vm_->revokeDevice(currentDevId);
    EXPECT_FALSE(ok);
    EXPECT_GE(errorSpy.count(), 1);
    EXPECT_TRUE(errorSpy.first().first().toString().contains("active workstation"));
}

TEST_F(WorkspaceViewModelDevicesTest, TogglePeerVerifiedUpdatesVerificationState) {
    QSignalSpy spy(vm_.get(), &WorkspaceViewModel::conversationsChanged);

    // Select conv-corina (starts unverified)
    vm_->selectConversation(QStringLiteral("conv-corina"));
    EXPECT_FALSE(vm_->selectedPeerVerified());

    // Toggle to verified
    vm_->togglePeerVerified(QStringLiteral(""));
    EXPECT_GE(spy.count(), 1);
    EXPECT_TRUE(vm_->selectedPeerVerified());

    // Toggle back to unverified
    vm_->togglePeerVerified(QStringLiteral(""));
    EXPECT_FALSE(vm_->selectedPeerVerified());
}

} // namespace securecloud::client::tests
