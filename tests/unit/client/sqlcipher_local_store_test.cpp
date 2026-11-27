#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::client::infrastructure::adapters::test {
namespace {

using namespace std::chrono_literals;

class SqlCipherLocalStoreTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_sqlcipher_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "client_vault.db").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::string read_raw_bytes(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return {};
        }
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(SqlCipherLocalStoreTest, RoundTripPersistenceAcrossReopenPreservesConversationsMessagesAndContacts) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    const domain::ConversationId cid("conv-sqlcipher-001");
    const domain::UserId alice("alice-uid");
    const domain::UserId bob("bob-uid");
    const domain::DeviceId alice_dev("alice-dev-1");
    const auto t0 = std::chrono::system_clock::time_point(1760000000000ms);

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        EXPECT_TRUE(store.is_open());

        domain::Conversation conv(cid, domain::ConversationType::Group, "Top Secret Council", {}, t0, t0 + 20s, 3u,
                                  true);
        conv.add_participant(alice, domain::ParticipantRole::Admin);
        conv.add_participant(bob, domain::ParticipantRole::Member);
        conv.set_sender_key_epoch(5u);
        ASSERT_TRUE(store.save_conversation(conv).is_ok());

        domain::Message m1(domain::MessageId("msg-1"), cid, alice, alice_dev, domain::DeliveryState::Delivered, t0 + 5s,
                           "scg:v1:opaque-ref-1", 0, "Alice", "idem-1");
        m1.set_server_sequence_number(1u);
        m1.set_sender_key_epoch(5u);
        ASSERT_TRUE(store.save_message(m1).is_ok());

        domain::Message m2(domain::MessageId("msg-2"), cid, bob, domain::DeviceId("bob-dev-1"),
                           domain::DeliveryState::LocalPending, t0 + 10s, "scg:v1:opaque-ref-2", 1, "Bob", "idem-2");
        m2.set_server_sequence_number(2u);
        ASSERT_TRUE(store.save_message(m2).is_ok());

        m2.set_delivery_state(domain::DeliveryState::Read);
        ASSERT_TRUE(store.update_message(m2).is_ok());

        domain::Contact contact(bob, "Bob Alias", domain::KeyVerificationStatus::Verified, "fp-bob-123", false,
                                "12345 67890", "Security Note", domain::PresenceStatus::Online, 2u, t0 + 15s);
        ASSERT_TRUE(store.save_contact(contact).is_ok());

        ASSERT_TRUE(store.close().is_ok());
        EXPECT_FALSE(store.is_open());
    }

    // Reopen fresh instance against the same DB file and ISecureStorage
    SqlCipherLocalStore reopened(secure_storage, crypto);
    ASSERT_TRUE(reopened.open(db_path_).is_ok());

    const auto conv_res = reopened.get_conversation(cid);
    ASSERT_TRUE(conv_res.is_ok());
    EXPECT_EQ(conv_res.value().title(), "Top Secret Council");
    EXPECT_EQ(conv_res.value().sender_key_epoch(), 5u);
    EXPECT_TRUE(conv_res.value().is_admin(alice));
    EXPECT_FALSE(conv_res.value().is_admin(bob));

    const auto list_res = reopened.list_conversations();
    ASSERT_TRUE(list_res.is_ok());
    ASSERT_EQ(list_res.value().size(), 1u);

    const auto msgs_limited = reopened.get_messages(cid, 1);
    ASSERT_TRUE(msgs_limited.is_ok());
    ASSERT_EQ(msgs_limited.value().size(), 1u);
    EXPECT_EQ(msgs_limited.value()[0].message_id(), domain::MessageId("msg-1"));

    const auto msgs_all = reopened.get_messages(cid, 0);
    ASSERT_TRUE(msgs_all.is_ok());
    ASSERT_EQ(msgs_all.value().size(), 2u);
    EXPECT_EQ(msgs_all.value()[1].delivery_state(), domain::DeliveryState::Read);
    EXPECT_EQ(msgs_all.value()[1].server_sequence_number(), 2u);

    const auto contact_res = reopened.get_contact(bob);
    ASSERT_TRUE(contact_res.is_ok());
    EXPECT_EQ(contact_res.value().alias(), "Bob Alias");
    EXPECT_EQ(contact_res.value().role_note(), "Security Note");

    ASSERT_TRUE(reopened.delete_conversation(cid).is_ok());
    EXPECT_TRUE(reopened.get_conversation(cid).is_error());
    EXPECT_TRUE(reopened.get_messages(cid, 0).value().empty());

    ASSERT_TRUE(reopened.delete_contact(bob).is_ok());
    EXPECT_TRUE(reopened.list_contacts().value().empty());
}

TEST_F(SqlCipherLocalStoreTest, EncryptedDatabaseContainsZeroPlaintextAndNoSqliteMagicHeaderOnDisk) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());

        const domain::ConversationId cid("conv-secret-001");
        domain::Conversation conv(cid, domain::ConversationType::Group, "Confidential Project Apollo");
        ASSERT_TRUE(store.save_conversation(conv).is_ok());

        domain::Message msg(domain::MessageId("msg-secret-001"), cid, domain::UserId("alice"),
                            domain::DeviceId("dev-1"), domain::DeliveryState::Accepted,
                            std::chrono::system_clock::now(), "scg:v1:classified-envelope-marker");
        ASSERT_TRUE(store.save_message(msg).is_ok());

        domain::Contact contact(domain::UserId("charlie"), "Charlie Alias Secret",
                                domain::KeyVerificationStatus::Unverified, "fp-1", false, "", "Private Contact Note");
        ASSERT_TRUE(store.save_contact(contact).is_ok());
        ASSERT_TRUE(store.close().is_ok());
    }

    const std::string db_bytes = read_raw_bytes(db_path_);
    const std::string wal_bytes = read_raw_bytes(db_path_ + "-wal");
    const std::string combined = db_bytes + wal_bytes;

    ASSERT_FALSE(db_bytes.empty());
    EXPECT_EQ(combined.find("SQLite format 3"), std::string::npos);
    EXPECT_EQ(combined.find("Confidential Project Apollo"), std::string::npos);
    EXPECT_EQ(combined.find("scg:v1:classified-envelope-marker"), std::string::npos);
    EXPECT_EQ(combined.find("Charlie Alias Secret"), std::string::npos);
    EXPECT_EQ(combined.find("Private Contact Note"), std::string::npos);
}

TEST_F(SqlCipherLocalStoreTest, FailsClosedOnWrongKeyMissingKeyOrTamperedDatabase) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        ASSERT_TRUE(store.save_contact(domain::Contact(domain::UserId("u1"), "Alice")).is_ok());
        ASSERT_TRUE(store.close().is_ok());
    }

    // 1. Wrong key in ISecureStorage -> fail closed
    {
        MemorySecureStorage wrong_storage;
        ASSERT_TRUE(wrong_storage
                        .store_secret(SqlCipherLocalStore::kMasterKeyId,
                                      common::configuration::SecretString(std::string(64, 'a')))
                        .is_ok());
        SqlCipherLocalStore store_wrong(wrong_storage, crypto);
        const auto res = store_wrong.open(db_path_);
        EXPECT_TRUE(res.is_error());
        EXPECT_FALSE(store_wrong.is_open());
    }

    // 2. Missing key for existing DB -> fail closed
    {
        MemorySecureStorage empty_storage;
        SqlCipherLocalStore store_missing(empty_storage, crypto);
        const auto res = store_missing.open(db_path_);
        EXPECT_TRUE(res.is_error());
        EXPECT_FALSE(store_missing.is_open());
    }

    // 3. Corrupted DB bytes -> fail closed
    {
        std::fstream fs(db_path_, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(fs.is_open());
        fs.seekp(100);
        char byte = 0;
        fs.seekg(100);
        fs.get(byte);
        byte = static_cast<char>(static_cast<unsigned char>(byte) ^ 0xFFu);
        fs.seekp(100);
        fs.put(byte);
        fs.close();

        SqlCipherLocalStore store_corrupt(secure_storage, crypto);
        const auto res = store_corrupt.open(db_path_);
        EXPECT_TRUE(res.is_error());
        EXPECT_FALSE(store_corrupt.is_open());
    }
}

TEST_F(SqlCipherLocalStoreTest, ClientBootstrapOpensSqlCipherWhenDatabasePathConfigured) {
    application::ClientConfig cfg = application::ClientConfig::create_default();
    cfg.database_path = db_path_;

    application::ClientBootstrap bootstrap(cfg);
    EXPECT_NE(dynamic_cast<SqlCipherLocalStore*>(&bootstrap.local_store()), nullptr);
    EXPECT_NE(dynamic_cast<OpenSslCryptoProvider*>(&bootstrap.crypto_provider()), nullptr);

    ASSERT_TRUE(
        bootstrap.local_store().save_contact(domain::Contact(domain::UserId("boot-user"), "Boot Contact")).is_ok());
    EXPECT_TRUE(std::filesystem::exists(db_path_));
}

} // namespace
} // namespace securecloud::client::infrastructure::adapters::test
