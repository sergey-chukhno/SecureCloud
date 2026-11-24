#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/messaging_manager.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/workspace_view_model.hpp"

#include <QSignalSpy>
#include <QVariantList>
#include <QVariantMap>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;

class ForwardingSecureStorage final : public ISecureStorage {
  public:
    explicit ForwardingSecureStorage(std::shared_ptr<MemorySecureStorage> inner) : inner_(std::move(inner)) {}

    ClientResult<void> store_secret(std::string_view key_id,
                                    const common::configuration::SecretString& secret) override {
        return inner_->store_secret(key_id, secret);
    }

    ClientResult<common::configuration::SecretString> get_secret(std::string_view key_id) override {
        return inner_->get_secret(key_id);
    }

    ClientResult<void> delete_secret(std::string_view key_id) override { return inner_->delete_secret(key_id); }

    ClientResult<bool> has_secret(std::string_view key_id) override { return inner_->has_secret(key_id); }

    ClientResult<std::vector<std::string>> list_secret_keys() override { return inner_->list_secret_keys(); }

    ClientResult<std::size_t> purge_all_secrets() override { return inner_->purge_all_secrets(); }

  private:
    std::shared_ptr<MemorySecureStorage> inner_;
};

class WorkspaceViewModelGroupPersistenceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        temp_dir_ = std::filesystem::temp_directory_path() / "sc_vm_group_persistence_test";
        std::filesystem::remove_all(temp_dir_);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "workspace.db").string();
    }

    void TearDown() override { std::filesystem::remove_all(temp_dir_); }

    std::unique_ptr<ClientApplication> create_persistent_app(std::shared_ptr<MemorySecureStorage> shared_storage) {
        ClientConfig config = ClientConfig::create_default();
        config.database_path = db_path_;

        auto gateway = std::make_unique<DefaultGatewayClient>(config);
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto secure_storage = std::make_unique<ForwardingSecureStorage>(shared_storage);
        auto local_store = std::make_unique<SqlCipherLocalStore>(*shared_storage, *crypto);

        auto bootstrap =
            ClientBootstrap::create_with_adapters(std::move(config), std::move(gateway), std::move(local_store),
                                                  std::move(secure_storage), std::move(crypto));
        auto app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(app->initialize().is_ok());
        EXPECT_TRUE(app->start().is_ok());
        return app;
    }

    std::unique_ptr<ClientApplication> create_memory_app() {
        ClientConfig config = ClientConfig::create_default();
        auto gateway = std::make_unique<DefaultGatewayClient>(config);
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto secure_storage = std::make_unique<MemorySecureStorage>();
        auto local_store = std::make_unique<MemoryLocalStore>();

        auto bootstrap =
            ClientBootstrap::create_with_adapters(std::move(config), std::move(gateway), std::move(local_store),
                                                  std::move(secure_storage), std::move(crypto));
        auto app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(app->initialize().is_ok());
        EXPECT_TRUE(app->start().is_ok());
        return app;
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(WorkspaceViewModelGroupPersistenceTest, FreshSqlCipherDatabaseStartsEmptyWithoutMockSeed) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto app = create_persistent_app(shared_storage);
    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    EXPECT_TRUE(vm.conversations().isEmpty());
    EXPECT_TRUE(vm.selectedConversationId().isEmpty());
    EXPECT_TRUE(vm.activeMessages().isEmpty());

    EXPECT_TRUE(app->shutdown().is_ok());
}

TEST_F(WorkspaceViewModelGroupPersistenceTest, GroupConversationAndHistoryPersistAcrossRestart) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    QString created_conv_id;

    {
        auto app = create_persistent_app(shared_storage);
        NavigationController nav;
        WorkspaceViewModel vm(*app, nav);

        created_conv_id = vm.createGroupConversation(QStringLiteral("Incident Ops"),
                                                     {QStringLiteral("bob"), QStringLiteral("carol")});
        ASSERT_FALSE(created_conv_id.isEmpty());
        ASSERT_EQ(vm.conversations().size(), 1);
        EXPECT_EQ(vm.selectedConversationId(), created_conv_id);
        EXPECT_TRUE(vm.selectedConversationIsGroup());
        EXPECT_EQ(vm.selectedGroupKeyEpoch(), 1);
        EXPECT_TRUE(vm.localUserIsGroupAdmin());

        EXPECT_TRUE(vm.sendMessage(QStringLiteral("Initial briefing")));
        EXPECT_TRUE(vm.sendMessage(QStringLiteral("Follow-up check")));
        EXPECT_EQ(vm.activeMessages().size(), 2);

        EXPECT_TRUE(app->shutdown().is_ok());
    }

    {
        auto restarted_app = create_persistent_app(shared_storage);
        NavigationController nav;
        WorkspaceViewModel restarted_vm(*restarted_app, nav);

        ASSERT_EQ(restarted_vm.conversations().size(), 1);
        const QVariantMap conv = restarted_vm.conversations().at(0).toMap();
        EXPECT_EQ(conv.value(QStringLiteral("conversationId")).toString(), created_conv_id);
        EXPECT_EQ(conv.value(QStringLiteral("peerDisplayName")).toString(), QStringLiteral("Incident Ops"));
        EXPECT_TRUE(conv.value(QStringLiteral("isGroup")).toBool());

        EXPECT_EQ(restarted_vm.selectedConversationId(), created_conv_id);
        EXPECT_TRUE(restarted_vm.selectedConversationIsGroup());
        EXPECT_EQ(restarted_vm.selectedGroupKeyEpoch(), 1);
        EXPECT_TRUE(restarted_vm.localUserIsGroupAdmin());

        const QVariantList msgs = restarted_vm.activeMessages();
        ASSERT_EQ(msgs.size(), 2);
        EXPECT_EQ(msgs.at(0).toMap().value(QStringLiteral("text")).toString(), QStringLiteral("Initial briefing"));
        EXPECT_EQ(msgs.at(1).toMap().value(QStringLiteral("text")).toString(), QStringLiteral("Follow-up check"));

        EXPECT_TRUE(restarted_app->shutdown().is_ok());
    }
}

TEST_F(WorkspaceViewModelGroupPersistenceTest, GroupParticipantsExposeRolesAndRemovalIncrementsEpoch) {
    auto app = create_memory_app();
    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    const QString conv_id =
        vm.createGroupConversation(QStringLiteral("SecOps"), {QStringLiteral("bob"), QStringLiteral("carol")});
    ASSERT_FALSE(conv_id.isEmpty());
    EXPECT_EQ(vm.selectedGroupKeyEpoch(), 1);
    EXPECT_TRUE(vm.localUserIsGroupAdmin());

    const QVariantList initial_participants = vm.selectedConversationParticipants();
    ASSERT_EQ(initial_participants.size(), 3);

    bool found_local_admin = false;
    bool found_bob_member = false;
    for (const QVariant& item : initial_participants) {
        const QVariantMap p = item.toMap();
        const QString uid = p.value(QStringLiteral("userId")).toString();
        if (uid == QStringLiteral("operator@securecloud.org")) {
            found_local_admin = true;
            EXPECT_EQ(p.value(QStringLiteral("role")).toString(), QStringLiteral("Admin"));
            EXPECT_FALSE(p.value(QStringLiteral("canRemove")).toBool());
        } else if (uid == QStringLiteral("bob")) {
            found_bob_member = true;
            EXPECT_EQ(p.value(QStringLiteral("role")).toString(), QStringLiteral("Member"));
            EXPECT_TRUE(p.value(QStringLiteral("canRemove")).toBool());
        }
    }
    EXPECT_TRUE(found_local_admin);
    EXPECT_TRUE(found_bob_member);

    EXPECT_TRUE(vm.removeParticipantFromActiveGroup(QStringLiteral("bob")));
    EXPECT_EQ(vm.selectedGroupKeyEpoch(), 2);

    const QVariantList updated_participants = vm.selectedConversationParticipants();
    ASSERT_EQ(updated_participants.size(), 2);
    for (const QVariant& item : updated_participants) {
        EXPECT_NE(item.toMap().value(QStringLiteral("userId")).toString(), QStringLiteral("bob"));
    }

    EXPECT_TRUE(app->shutdown().is_ok());
}

TEST_F(WorkspaceViewModelGroupPersistenceTest, NonAdminGroupMutationEmitsWorkspaceErrorAndFails) {
    auto app = create_memory_app();
    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    auto create_res = app->bootstrap().messaging_manager().create_group_conversation(
        UserId("alice"), "ReadOnly Group", {UserId("alice"), UserId("operator@securecloud.org")});
    ASSERT_TRUE(create_res.is_ok());
    const QString conv_id = QString::fromStdString(create_res.value().conversation_id().value());

    vm.reloadFromLocalStore();
    vm.selectConversation(conv_id);

    EXPECT_FALSE(vm.localUserIsGroupAdmin());
    for (const QVariant& item : vm.selectedConversationParticipants()) {
        EXPECT_FALSE(item.toMap().value(QStringLiteral("canRemove")).toBool());
    }

    QSignalSpy error_spy(&vm, &WorkspaceViewModel::workspaceError);
    EXPECT_FALSE(vm.addParticipantToActiveGroup(QStringLiteral("dave")));
    EXPECT_GE(error_spy.count(), 1);

    EXPECT_FALSE(vm.removeParticipantFromActiveGroup(QStringLiteral("alice")));
    EXPECT_GE(error_spy.count(), 2);

    EXPECT_TRUE(app->shutdown().is_ok());
}

} // namespace
} // namespace securecloud::client::tests
