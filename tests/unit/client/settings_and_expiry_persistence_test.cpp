#include "domain/conversation.hpp"
#include "domain/message.hpp"
#include "domain/user_profile.hpp"
#include "domain/user_settings.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#if __has_include(<sqlcipher/sqlite3.h>)
#include <sqlcipher/sqlite3.h>
#else
#include <sqlite3.h>
#endif

namespace securecloud::client::infrastructure::adapters::test {
namespace {

using namespace std::chrono_literals;
using namespace securecloud::client::domain;

class SettingsAndExpiryPersistenceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_t02_persist_" + suffix);
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

    static int64_t current_unix_ms() noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(SettingsAndExpiryPersistenceTest, ConversationAndMessageExpiryJsonRoundTripAndLegacyDefaults) {
    const auto t0 = std::chrono::system_clock::time_point(1764000000000ms);
    Conversation conv(ConversationId("conv-ttl"), ConversationType::Group, "Ops", {}, t0, t0 + 10s, 0u, false);
    conv.set_disappearing_ttl_seconds(-500);
    EXPECT_EQ(conv.disappearing_ttl_seconds(), 0);
    conv.set_disappearing_ttl_seconds(86400);
    EXPECT_EQ(conv.disappearing_ttl_seconds(), 86400);

    const auto parsed_conv = Conversation::from_json(conv.to_json());
    ASSERT_TRUE(parsed_conv.has_value());
    EXPECT_EQ(*parsed_conv, conv);
    EXPECT_EQ(parsed_conv->disappearing_ttl_seconds(), 86400);

    // Legacy conversation JSON without disappearing_ttl_seconds defaults cleanly to 0.
    nlohmann::json legacy_conv_doc = nlohmann::json::parse(conv.to_json());
    legacy_conv_doc.erase("disappearing_ttl_seconds");
    const auto parsed_legacy_conv = Conversation::from_json(legacy_conv_doc.dump());
    ASSERT_TRUE(parsed_legacy_conv.has_value());
    EXPECT_EQ(parsed_legacy_conv->disappearing_ttl_seconds(), 0);

    Message msg(MessageId("msg-exp-1"), ConversationId("conv-ttl-1"), UserId("alice-1"), DeviceId("dev-1"),
                DeliveryState::Delivered, t0, "scg:v1:env", 0, "Alice", "idem-exp-1");
    EXPECT_EQ(msg.expires_at_ms(), 0);
    EXPECT_FALSE(msg.is_expired(1764000000000LL));

    msg.set_expires_at_ms(-10);
    EXPECT_EQ(msg.expires_at_ms(), 0);

    msg.set_expires_at_ms(1764003600000LL);
    EXPECT_FALSE(msg.is_expired(1764003599999LL));
    EXPECT_TRUE(msg.is_expired(1764003600000LL));
    EXPECT_TRUE(msg.is_expired(1764003600001LL));

    const auto parsed_msg = Message::from_json(msg.to_json());
    ASSERT_TRUE(parsed_msg.has_value());
    EXPECT_EQ(*parsed_msg, msg);
    EXPECT_EQ(parsed_msg->expires_at_ms(), 1764003600000LL);

    // Legacy message JSON without expires_at_ms defaults cleanly to 0.
    nlohmann::json legacy_msg_doc = nlohmann::json::parse(msg.to_json());
    legacy_msg_doc.erase("expires_at_ms");
    const auto parsed_legacy_msg = Message::from_json(legacy_msg_doc.dump());
    ASSERT_TRUE(parsed_legacy_msg.has_value());
    EXPECT_EQ(parsed_legacy_msg->expires_at_ms(), 0);
}

TEST_F(SettingsAndExpiryPersistenceTest, SqlCipherPersistsProfileAndSettingsAcrossRestartWithoutPlaintextLeakage) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    const UserId uid("user-persist-001");
    const std::string settings_key = "active";

    UserProfile initial_profile;
    initial_profile.user_id = uid;
    initial_profile.public_handle = "alice.secret_handle";
    initial_profile.display_name = "Alice Secret Field Name";
    initial_profile.bio_status = "classified-bio-marker";
    initial_profile.avatar_file_id = "avatar-blob-99";
    initial_profile.avatar_sha256 = std::string(64U, 'a');
    initial_profile.allow_handle_discovery = false;
    initial_profile.updated_at_ms = 1764000001000LL;

    UserSettings initial_settings;
    initial_settings.theme_mode = 2;
    initial_settings.font_scale = 1.30;
    initial_settings.high_contrast_enabled = true;
    initial_settings.read_receipts_enabled = false;
    initial_settings.default_disappearing_timer = DisappearingTimerPreset::TwentyFourHours;
    initial_settings.mfa_required_on_login = true;
    initial_settings.hardware_key_enforced = true;
    initial_settings.recovery_phrase_verified = true;
    initial_settings.use_live_gateway_transport = true;
    initial_settings.proxy.type = ProxyType::Socks5;
    initial_settings.proxy.host = "proxy.secret.corp.local";
    initial_settings.proxy.port = 1080U;
    initial_settings.proxy.username = "field-user";
    initial_settings.tls.custom_gateway_host = "gw.secret.corp.local";
    initial_settings.tls.custom_gateway_port = 9443U;
    initial_settings.tls.pinned_spki_sha256_hex = std::string(64U, 'b');
    initial_settings.tls.enforce_strict_pinning = true;
    initial_settings.updated_at_ms = 1764000002000LL;

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());

        // Missing entries return std::nullopt cleanly; empty keys or invalid models return validation errors.
        const auto missing_profile = store.get_user_profile(uid);
        ASSERT_TRUE(missing_profile.is_ok());
        EXPECT_FALSE(missing_profile.value().has_value());

        const auto missing_settings = store.get_user_settings(settings_key);
        ASSERT_TRUE(missing_settings.is_ok());
        EXPECT_FALSE(missing_settings.value().has_value());

        EXPECT_TRUE(store.get_user_profile(UserId{}).is_error());
        EXPECT_TRUE(store.get_user_settings("").is_error());
        EXPECT_TRUE(store.save_user_settings("", initial_settings).is_error());

        UserSettings invalid_settings;
        invalid_settings.font_scale = 5.0;
        EXPECT_TRUE(store.save_user_settings(settings_key, invalid_settings).is_error());

        UserProfile invalid_profile;
        invalid_profile.user_id = uid;
        invalid_profile.display_name = "";
        EXPECT_TRUE(store.save_user_profile(invalid_profile).is_error());

        ASSERT_TRUE(store.save_user_profile(initial_profile).is_ok());
        ASSERT_TRUE(store.save_user_settings(settings_key, initial_settings).is_ok());
        ASSERT_TRUE(store.close().is_ok());
    }

    // Reopen and verify exact hydration + upsert update + second close/reopen.
    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());

        const auto loaded_profile = store.get_user_profile(uid);
        ASSERT_TRUE(loaded_profile.is_ok());
        ASSERT_TRUE(loaded_profile.value().has_value());
        EXPECT_EQ(*loaded_profile.value(), initial_profile);

        const auto loaded_settings = store.get_user_settings(settings_key);
        ASSERT_TRUE(loaded_settings.is_ok());
        ASSERT_TRUE(loaded_settings.value().has_value());
        EXPECT_EQ(*loaded_settings.value(), initial_settings);

        UserProfile updated_profile = initial_profile;
        updated_profile.display_name = "Alice Updated Name";
        updated_profile.updated_at_ms = 1764000003000LL;
        ASSERT_TRUE(store.save_user_profile(updated_profile).is_ok());

        UserSettings updated_settings = initial_settings;
        updated_settings.default_disappearing_timer = DisappearingTimerPreset::SevenDays;
        updated_settings.updated_at_ms = 1764000004000LL;
        ASSERT_TRUE(store.save_user_settings(settings_key, updated_settings).is_ok());
        ASSERT_TRUE(store.close().is_ok());
    }

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        const auto reloaded_profile = store.get_user_profile(uid);
        ASSERT_TRUE(reloaded_profile.is_ok());
        ASSERT_TRUE(reloaded_profile.value().has_value());
        EXPECT_EQ(reloaded_profile.value()->display_name, "Alice Updated Name");

        const auto reloaded_settings = store.get_user_settings(settings_key);
        ASSERT_TRUE(reloaded_settings.is_ok());
        ASSERT_TRUE(reloaded_settings.value().has_value());
        EXPECT_EQ(reloaded_settings.value()->default_disappearing_timer, DisappearingTimerPreset::SevenDays);
        ASSERT_TRUE(store.close().is_ok());
    }

    // Verify encrypted disk files contain zero plaintext profile or proxy metadata.
    const std::string raw_db = read_raw_bytes(db_path_) + read_raw_bytes(db_path_ + "-wal");
    EXPECT_FALSE(raw_db.empty());
    EXPECT_EQ(raw_db.find("Alice Secret Field Name"), std::string::npos);
    EXPECT_EQ(raw_db.find("Alice Updated Name"), std::string::npos);
    EXPECT_EQ(raw_db.find("alice.secret_handle"), std::string::npos);
    EXPECT_EQ(raw_db.find("classified-bio-marker"), std::string::npos);
    EXPECT_EQ(raw_db.find("proxy.secret.corp.local"), std::string::npos);
    EXPECT_EQ(raw_db.find("gw.secret.corp.local"), std::string::npos);
}

TEST_F(SettingsAndExpiryPersistenceTest, SqlCipherMigratesLegacyMessagesTableWithoutExpiresAtColumn) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    const std::string master_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const auto store_key_res = secure_storage.store_secret(
        SqlCipherLocalStore::kMasterKeyId, securecloud::common::configuration::SecretString(master_key_hex));
    ASSERT_TRUE(store_key_res.is_ok());

    const ConversationId cid("conv-legacy-001");
    const MessageId legacy_mid("msg-legacy-001");
    const UserId uid("user-legacy-001");
    const DeviceId did("dev-legacy-001");

    // Seed a pre-CLIENT-014 encrypted database whose messages table lacks `expires_at_ms`.
    {
        sqlite3* raw_db = nullptr;
        ASSERT_EQ(sqlite3_open_v2(db_path_.c_str(), &raw_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr),
                  SQLITE_OK);
        ASSERT_NE(raw_db, nullptr);

        const std::string pragma_key = "PRAGMA key = \"x'" + master_key_hex + "'\";";
        ASSERT_EQ(sqlite3_exec(raw_db, pragma_key.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);

        static constexpr const char* kLegacySchema = R"sql(
            CREATE TABLE conversations (
                conversation_id TEXT PRIMARY KEY,
                last_activity_at_ms INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sent_at_ms INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
        )sql";
        ASSERT_EQ(sqlite3_exec(raw_db, kLegacySchema, nullptr, nullptr, nullptr), SQLITE_OK);

        nlohmann::json legacy_msg = nlohmann::json::object();
        legacy_msg["message_id"] = legacy_mid.value();
        legacy_msg["conversation_id"] = cid.value();
        legacy_msg["sender_user_id"] = uid.value();
        legacy_msg["sender_device_id"] = did.value();
        legacy_msg["delivery_state"] = "Delivered";
        legacy_msg["sent_at_ms"] = 1764000000000LL;
        legacy_msg["encrypted_envelope_ref"] = "legacy-cipher-ref-pre-ttl";
        legacy_msg["priority"] = 0;
        const std::string legacy_json = legacy_msg.dump();

        static constexpr const char* kInsertSql =
            "INSERT INTO messages (message_id, conversation_id, sent_at_ms, payload_json) VALUES (?1, ?2, ?3, ?4);";
        sqlite3_stmt* stmt = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(raw_db, kInsertSql, -1, &stmt, nullptr), SQLITE_OK);
        sqlite3_bind_text(stmt, 1, legacy_mid.value().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid.value().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, 1764000000000LL);
        sqlite3_bind_text(stmt, 4, legacy_json.c_str(), static_cast<int>(legacy_json.size()), SQLITE_TRANSIENT);
        ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
        sqlite3_close_v2(raw_db);
    }

    // Reopen with SqlCipherLocalStore -> migrates schema cleanly while preserving pre-existing rows.
    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());

        const auto loaded_legacy = store.get_message(cid, legacy_mid);
        ASSERT_TRUE(loaded_legacy.is_ok());
        EXPECT_EQ(loaded_legacy.value().encrypted_envelope_ref(), "legacy-cipher-ref-pre-ttl");
        EXPECT_EQ(loaded_legacy.value().expires_at_ms(), 0);
        EXPECT_FALSE(loaded_legacy.value().is_expired(current_unix_ms() + 100000000LL));

        Message expiring(MessageId("msg-new-exp-002"), cid, uid, did, DeliveryState::Delivered,
                         std::chrono::system_clock::now(), "new-expiring-ref", 0);
        expiring.set_expires_at_ms(current_unix_ms() + 3600000LL);
        ASSERT_TRUE(store.save_message(expiring).is_ok());

        const auto list_res = store.get_messages(cid, 0U);
        ASSERT_TRUE(list_res.is_ok());
        ASSERT_EQ(list_res.value().size(), 2u);
        ASSERT_TRUE(store.close().is_ok());
    }

    // Inspect migrated schema directly to verify `expires_at_ms` column and partial index `idx_messages_expires_at`.
    {
        sqlite3* raw_db = nullptr;
        ASSERT_EQ(sqlite3_open_v2(db_path_.c_str(), &raw_db, SQLITE_OPEN_READONLY, nullptr), SQLITE_OK);
        const std::string pragma_key = "PRAGMA key = \"x'" + master_key_hex + "'\";";
        ASSERT_EQ(sqlite3_exec(raw_db, pragma_key.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);

        bool found_col = false;
        sqlite3_stmt* col_stmt = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(raw_db, "PRAGMA table_info(messages);", -1, &col_stmt, nullptr), SQLITE_OK);
        while (sqlite3_step(col_stmt) == SQLITE_ROW) {
            const unsigned char* name = sqlite3_column_text(col_stmt, 1);
            if (name != nullptr && std::string(reinterpret_cast<const char*>(name)) == "expires_at_ms") {
                found_col = true;
            }
        }
        sqlite3_finalize(col_stmt);
        EXPECT_TRUE(found_col);

        static constexpr const char* kIdxSql =
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_messages_expires_at';";
        bool found_index = false;
        sqlite3_stmt* idx_stmt = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(raw_db, kIdxSql, -1, &idx_stmt, nullptr), SQLITE_OK);
        if (sqlite3_step(idx_stmt) == SQLITE_ROW) {
            found_index = true;
        }
        sqlite3_finalize(idx_stmt);
        EXPECT_TRUE(found_index);
        sqlite3_close_v2(raw_db);
    }
}

TEST_F(SettingsAndExpiryPersistenceTest, SqlCipherAndMemoryStoreEnforceReadExclusionAndExpirySweep) {
    auto verify_store = [](application::interfaces::ILocalStore& store) {
        const ConversationId cid("conv-expiry-sweep");
        const UserId uid("user-exp");
        const DeviceId did("dev-exp");
        const int64_t now_ms = current_unix_ms();

        Conversation conv(cid, ConversationType::Direct, "Ephemeral Chat");
        conv.set_disappearing_ttl_seconds(3600);
        ASSERT_TRUE(store.save_conversation(conv).is_ok());
        const auto loaded_conv = store.get_conversation(cid);
        ASSERT_TRUE(loaded_conv.is_ok());
        EXPECT_EQ(loaded_conv.value().disappearing_ttl_seconds(), 3600);

        Message already_expired(MessageId("msg-1-past"), cid, uid, did, DeliveryState::Delivered,
                                std::chrono::system_clock::time_point(std::chrono::milliseconds(now_ms - 10000)),
                                "ref-past");
        already_expired.set_expires_at_ms(now_ms - 5000);

        Message non_expiring(MessageId("msg-2-forever"), cid, uid, did, DeliveryState::Delivered,
                             std::chrono::system_clock::time_point(std::chrono::milliseconds(now_ms - 5000)),
                             "ref-forever");
        non_expiring.set_expires_at_ms(0);

        Message future_expiring(MessageId("msg-3-future"), cid, uid, did, DeliveryState::Delivered,
                                std::chrono::system_clock::time_point(std::chrono::milliseconds(now_ms - 1000)),
                                "ref-future");
        future_expiring.set_expires_at_ms(now_ms + 3600000);

        ASSERT_TRUE(store.save_message(already_expired).is_ok());
        ASSERT_TRUE(store.save_message(non_expiring).is_ok());
        ASSERT_TRUE(store.save_message(future_expiring).is_ok());

        // Defense-in-depth read exclusion hides `already_expired` immediately before deletion sweep.
        // Limit=2 must return both non-expired messages rather than wasting a slot on the expired one.
        const auto visible = store.get_messages(cid, 2U);
        ASSERT_TRUE(visible.is_ok());
        ASSERT_EQ(visible.value().size(), 2u);
        EXPECT_EQ(visible.value()[0].message_id(), MessageId("msg-2-forever"));
        EXPECT_EQ(visible.value()[1].message_id(), MessageId("msg-3-future"));

        EXPECT_TRUE(store.get_message(cid, MessageId("msg-1-past")).is_error());
        EXPECT_TRUE(store.get_message(cid, MessageId("msg-3-future")).is_ok());

        // Update future message expiration closer to now and verify update_message persists expires_at_ms.
        future_expiring.set_expires_at_ms(now_ms + 120000);
        ASSERT_TRUE(store.update_message(future_expiring).is_ok());
        const auto reloaded_future = store.get_message(cid, MessageId("msg-3-future"));
        ASSERT_TRUE(reloaded_future.is_ok());
        EXPECT_EQ(reloaded_future.value().expires_at_ms(), now_ms + 120000);

        // First sweep at `now_ms` deletes strictly the past message (count == 1).
        const auto sweep1 = store.delete_expired_messages(now_ms);
        ASSERT_TRUE(sweep1.is_ok());
        EXPECT_EQ(sweep1.value(), 1u);

        // Second sweep past `now_ms + 120000` deletes `future_expiring` while retaining `non_expiring`.
        const auto sweep2 = store.delete_expired_messages(now_ms + 120000);
        ASSERT_TRUE(sweep2.is_ok());
        EXPECT_EQ(sweep2.value(), 1u);

        const auto remaining = store.get_messages(cid, 0U);
        ASSERT_TRUE(remaining.is_ok());
        ASSERT_EQ(remaining.value().size(), 1u);
        EXPECT_EQ(remaining.value()[0].message_id(), MessageId("msg-2-forever"));
    };

    {
        MemoryLocalStore mem_store;
        verify_store(mem_store);

        UserProfile p;
        p.user_id = UserId("mem-u1");
        p.display_name = "Memory User";
        ASSERT_TRUE(mem_store.save_user_profile(p).is_ok());

        UserSettings s;
        s.font_scale = 1.15;
        ASSERT_TRUE(mem_store.save_user_settings("active", s).is_ok());

        EXPECT_EQ(*mem_store.get_user_profile(UserId("mem-u1")).value(), p);
        EXPECT_EQ(*mem_store.get_user_settings("active").value(), s);

        mem_store.clear();
        EXPECT_FALSE(mem_store.get_user_profile(UserId("mem-u1")).value().has_value());
        EXPECT_FALSE(mem_store.get_user_settings("active").value().has_value());
    }

    {
        MemorySecureStorage secure_storage;
        OpenSslCryptoProvider crypto;
        SqlCipherLocalStore sql_store(secure_storage, crypto);
        ASSERT_TRUE(sql_store.open(db_path_).is_ok());
        verify_store(sql_store);
        ASSERT_TRUE(sql_store.close().is_ok());
    }
}

} // namespace
} // namespace securecloud::client::infrastructure::adapters::test
