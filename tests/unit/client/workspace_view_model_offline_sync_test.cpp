#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "domain/realtime_events.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QQmlComponent>
#include <QQmlContext>
#include <QQmlEngine>
#include <QSignalSpy>
#include <QUrl>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::ui::test {
namespace {

using namespace application;
using namespace domain;
using namespace infrastructure::adapters;

class WorkspaceViewModelOfflineSyncTest : public ::testing::Test {
  protected:
    void SetUp() override {
        auto config = ClientConfig::create_default();
        auto gw = std::make_unique<DefaultGatewayClient>(config);
        gateway_ptr_ = gw.get();
        auto store = std::make_unique<MemoryLocalStore>();
        ASSERT_TRUE(store->open("mem").is_ok());
        auto sec = std::make_unique<MemorySecureStorage>();
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        crypto_ptr_ = crypto.get();

        auto bootstrap = ClientBootstrap::create_with_adapters(config, std::move(gw), std::move(store), std::move(sec),
                                                               std::move(crypto));
        app_ = std::make_unique<ClientApplication>(std::move(bootstrap));
        ASSERT_TRUE(app_->initialize().is_ok());

        nav_ = std::make_unique<NavigationController>();
        app_vm_ = std::make_unique<AppViewModel>(*app_, *nav_);
        app_vm_->requestLogin(QStringLiteral("operator@securecloud.org"), QStringLiteral("pass123"));

        vm_ = std::make_unique<WorkspaceViewModel>(*app_, *nav_);
    }

    void TearDown() override {
        vm_.reset();
        app_vm_.reset();
        nav_.reset();
        if (app_) {
            (void)app_->shutdown();
        }
        app_.reset();
    }

    DefaultGatewayClient* gateway_ptr_{nullptr};
    OpenSslCryptoProvider* crypto_ptr_{nullptr};
    std::unique_ptr<ClientApplication> app_;
    std::unique_ptr<NavigationController> nav_;
    std::unique_ptr<AppViewModel> app_vm_;
    std::unique_ptr<WorkspaceViewModel> vm_;
};

TEST_F(WorkspaceViewModelOfflineSyncTest, OfflineDraftingUpdatesOutboxCountAndLocalPendingState) {
    EXPECT_EQ(vm_->connectivityState(), QStringLiteral("Online"));
    EXPECT_FALSE(vm_->isOffline());
    EXPECT_FALSE(vm_->isSyncing());
    EXPECT_EQ(vm_->pendingOutboxCount(), 0);
    EXPECT_EQ(app_vm_->connectionStatus(), QStringLiteral("Connected"));

    QSignalSpy conn_spy(vm_.get(), &WorkspaceViewModel::connectivityStateChanged);
    QSignalSpy outbox_spy(vm_.get(), &WorkspaceViewModel::pendingOutboxCountChanged);
    QSignalSpy app_conn_spy(app_vm_.get(), &AppViewModel::connectionStatusChanged);

    vm_->setSimulatedOfflineMode(true);

    EXPECT_TRUE(vm_->isOffline());
    EXPECT_EQ(vm_->connectivityState(), QStringLiteral("Offline"));
    EXPECT_EQ(app_vm_->connectionStatus(), QStringLiteral("Offline"));
    EXPECT_EQ(app_vm_->connectivityState(), QStringLiteral("Offline"));
    EXPECT_GE(conn_spy.count(), 1);
    EXPECT_GE(app_conn_spy.count(), 1);

    const bool sent = vm_->sendMessage(QStringLiteral("Drafted offline in UI"));
    ASSERT_TRUE(sent);
    EXPECT_EQ(vm_->pendingOutboxCount(), 1);
    EXPECT_GE(outbox_spy.count(), 1);
    EXPECT_TRUE(vm_->syncStatusSummary().contains(QStringLiteral("1 in outbox")));

    const QVariantList msgs = vm_->activeMessages();
    ASSERT_FALSE(msgs.isEmpty());
    const QVariantMap last = msgs.last().toMap();
    EXPECT_EQ(last.value(QStringLiteral("text")).toString(), QStringLiteral("Drafted offline in UI"));
    EXPECT_EQ(last.value(QStringLiteral("deliveryState")).toString(), QStringLiteral("LocalPending"));
}

TEST_F(WorkspaceViewModelOfflineSyncTest, ReconnectTriggersCatchUpSyncDrainsOutboxAndMergesRemoteMessages) {
    const QString active_cid = vm_->selectedConversationId();
    ASSERT_FALSE(active_cid.isEmpty());

    std::vector<QString> observed_states;
    QObject::connect(vm_.get(), &WorkspaceViewModel::connectivityStateChanged, vm_.get(),
                     [&]() { observed_states.push_back(vm_->connectivityState()); });

    // Go offline and draft an outbound message
    vm_->setSimulatedOfflineMode(true);
    ASSERT_TRUE(vm_->sendMessage(QStringLiteral("Queued before reconnect")));
    EXPECT_EQ(vm_->pendingOutboxCount(), 1);

    // Seed a missed inbound message on the Gateway while offline
    const ConversationId cid(active_cid.toStdString());
    const UserId bob("bob-remote");
    const DeviceId bob_dev("bob-dev-9");
    RealtimeEvent inbound;
    inbound.type = RealtimeEventType::InboundDirectMessage;
    inbound.conversation_id = cid;
    inbound.message_id = MessageId("msg-missed-while-offline");
    inbound.actor_user_id = bob;
    inbound.actor_device_id = bob_dev;
    inbound.server_sequence_number = 42ULL;
    inbound.direct_payload = crypto::PerDeviceDeliveryPayload{
        .recipient_user_id = {},
        .recipient_device_id = DeviceId("dev-local-01"),
        .ciphertext_blob = crypto_ptr_->encrypt_message(bob_dev, "Missed remote update").value(),
        .ephemeral_public_key = {},
        .iv = {},
        .auth_tag = {},
    };
    gateway_ptr_->set_simulated_conversation_messages(cid, {inbound});

    // Reconnect -> Syncing -> Online, drains outbox and merges missed message into activeMessages
    vm_->setSimulatedOfflineMode(false);

    EXPECT_FALSE(vm_->isOffline());
    EXPECT_FALSE(vm_->isSyncing());
    EXPECT_EQ(vm_->connectivityState(), QStringLiteral("Online"));
    EXPECT_EQ(app_vm_->connectionStatus(), QStringLiteral("Connected"));
    EXPECT_EQ(vm_->pendingOutboxCount(), 0);
    EXPECT_EQ(vm_->selectedConversationId(), active_cid);

    bool saw_offline = false;
    bool saw_syncing = false;
    bool saw_online = false;
    for (const auto& st : observed_states) {
        if (st == QStringLiteral("Offline")) {
            saw_offline = true;
        } else if (st == QStringLiteral("Syncing")) {
            saw_syncing = true;
        } else if (st == QStringLiteral("Online")) {
            saw_online = true;
        }
    }
    EXPECT_TRUE(saw_offline);
    EXPECT_TRUE(saw_syncing);
    EXPECT_TRUE(saw_online);

    bool found_flushed = false;
    bool found_missed = false;
    for (const QVariant& item : vm_->activeMessages()) {
        const QVariantMap map = item.toMap();
        const QString txt = map.value(QStringLiteral("text")).toString();
        if (txt == QStringLiteral("Queued before reconnect")) {
            found_flushed = true;
            EXPECT_EQ(map.value(QStringLiteral("deliveryState")).toString(), QStringLiteral("Accepted"));
        } else if (txt == QStringLiteral("Missed remote update")) {
            found_missed = true;
        }
    }
    EXPECT_TRUE(found_flushed);
    EXPECT_TRUE(found_missed);
}

TEST_F(WorkspaceViewModelOfflineSyncTest, HeadlessQmlWorkspaceLoadsOfflineBannerWithZeroWarnings) {
    QQmlEngine engine;
    std::vector<QString> warnings;
    QObject::connect(&engine, &QQmlEngine::warnings, [&](const QList<QQmlError>& errs) {
        for (const auto& err : errs) {
            warnings.push_back(err.toString());
        }
    });

    UiTheme theme;
    engine.addImportPath(QStringLiteral("qrc:/qml"));
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), vm_.get());
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), app_vm_.get());
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), nav_.get());

    QQmlComponent comp(&engine, QUrl(QStringLiteral("qrc:/qml/WorkspacePlaceholder.qml")));
    ASSERT_EQ(comp.status(), QQmlComponent::Ready) << comp.errorString().toStdString();

    std::unique_ptr<QObject> root(comp.create());
    ASSERT_NE(root, nullptr) << comp.errorString().toStdString();

    QObject* banner = root->findChild<QObject*>(QStringLiteral("connectivityOfflineBanner"));
    ASSERT_NE(banner, nullptr);
    EXPECT_FALSE(banner->property("visible").toBool());

    vm_->setSimulatedOfflineMode(true);
    QCoreApplication::processEvents();
    EXPECT_TRUE(banner->property("visible").toBool());

    ASSERT_TRUE(vm_->sendMessage(QStringLiteral("Banner check")));
    QCoreApplication::processEvents();
    EXPECT_TRUE(banner->property("visible").toBool());

    vm_->setSimulatedOfflineMode(false);
    QCoreApplication::processEvents();
    EXPECT_FALSE(banner->property("visible").toBool());

    EXPECT_TRUE(warnings.empty()) << (warnings.empty() ? "" : warnings.front().toStdString());
}

} // namespace
} // namespace securecloud::client::ui::test
