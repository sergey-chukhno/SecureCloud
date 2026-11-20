#include "domain/offline_sync_models.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <vector>

namespace securecloud::client::infrastructure::adapters::test {
namespace {

using domain::Conversation;
using domain::ConversationId;
using domain::ConversationType;
using domain::DeviceId;
using domain::MessageId;
using domain::OfflineOutboxFanOutPayload;
using domain::OfflineOutboxOperationType;
using domain::OfflineOutboxRecord;
using domain::SyncCursorRecord;
using domain::UserId;
using securecloud::common::configuration::SecretString;

OfflineOutboxRecord make_outbox_record(std::string outbox_id, OfflineOutboxOperationType op_type,
                                       const std::string& conv_id, int32_t priority, int64_t created_at_ms,
                                       std::string idempotency_key, std::string payload_json = "") {
    OfflineOutboxRecord rec;
    rec.outbox_id = std::move(outbox_id);
    rec.operation_type = op_type;
    rec.conversation_id = ConversationId(conv_id);
    rec.message_id = MessageId("msg-" + rec.outbox_id);
    rec.transfer_id = op_type == OfflineOutboxOperationType::FileKeyEnvelopeSubmission ? "tr-" + rec.outbox_id : "";
    rec.idempotency_key = std::move(idempotency_key);
    rec.priority = priority;
    rec.created_at_ms = created_at_ms;
    rec.next_retry_at_ms = created_at_ms + 1000LL;
    rec.expires_at_ms = created_at_ms + 86400000LL;

    if (payload_json.empty()) {
        OfflineOutboxFanOutPayload fanout;
        fanout.conversation_id = rec.conversation_id;
        fanout.idempotency_key = rec.idempotency_key;
        fanout.priority = rec.priority;
        const std::array<char, 6> raw_cipher = {'\xFF', '\x00', '\x80', '\xDE', '\xAD', '\x42'};
        fanout.device_payloads.push_back(domain::crypto::PerDeviceDeliveryPayload{
            .recipient_user_id = UserId("bob"),
            .recipient_device_id = DeviceId("bob-dev-1"),
            .ciphertext_blob = std::string(raw_cipher.data(), raw_cipher.size()),
            .ephemeral_public_key = std::vector<uint8_t>{0x01U, 0x02U, 0xFFU, 0x00U},
            .iv = std::vector<uint8_t>{0x11U, 0x22U, 0x33U, 0x44U},
            .auth_tag = std::vector<uint8_t>{0xAAU, 0xBBU, 0xCCU, 0xDDU},
            .algorithm = "X25519-DoubleRatchet-AES256GCM",
        });
        rec.payload_json = fanout.to_json();
    } else {
        rec.payload_json = std::move(payload_json);
    }
    return rec;
}

class OfflineOutboxPersistenceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_offline_sync_" + suffix);
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

TEST_F(OfflineOutboxPersistenceTest, MemoryLocalStoreOutboxCrudPriorityOrderingAndCascade) {
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("mem").is_ok());

    const ConversationId conv_a("conv-outbox-a");
    const ConversationId conv_b("conv-outbox-b");
    ASSERT_TRUE(store.save_conversation(Conversation(conv_a, ConversationType::Direct, "Conv A")).is_ok());
    ASSERT_TRUE(store.save_conversation(Conversation(conv_b, ConversationType::Direct, "Conv B")).is_ok());

    const auto r_norm_late = make_outbox_record("ob-2", OfflineOutboxOperationType::EncryptedMessageSubmission,
                                                "conv-outbox-a", 0, 2000LL, "idem-2");
    const auto r_norm_early = make_outbox_record("ob-1", OfflineOutboxOperationType::DeliveryAck, "conv-outbox-a", 0,
                                                 1000LL, "idem-1", R"({"ack":true})");
    const auto r_emerg = make_outbox_record("ob-4", OfflineOutboxOperationType::EncryptedMessageSubmission,
                                            "conv-outbox-b", 3, 5000LL, "idem-4");
    const auto r_urgent_tie_b = make_outbox_record("ob-3b", OfflineOutboxOperationType::FileKeyEnvelopeSubmission,
                                                   "conv-outbox-a", 2, 3000LL, "idem-3b");
    const auto r_urgent_tie_a = make_outbox_record("ob-3a", OfflineOutboxOperationType::ReadReceipt, "conv-outbox-b", 2,
                                                   3000LL, "idem-3a", R"({"read":true})");

    ASSERT_TRUE(store.save_outbox_record(r_norm_late).is_ok());
    ASSERT_TRUE(store.save_outbox_record(r_norm_early).is_ok());
    ASSERT_TRUE(store.save_outbox_record(r_emerg).is_ok());
    ASSERT_TRUE(store.save_outbox_record(r_urgent_tie_b).is_ok());
    ASSERT_TRUE(store.save_outbox_record(r_urgent_tie_a).is_ok());

    // Deterministic order: priority DESC, created_at_ms ASC, outbox_id ASC
    const auto ordered = store.list_outbox_records();
    ASSERT_TRUE(ordered.is_ok());
    ASSERT_EQ(ordered.value().size(), 5U);
    EXPECT_EQ(ordered.value()[0].outbox_id, "ob-4");
    EXPECT_EQ(ordered.value()[1].outbox_id, "ob-3a");
    EXPECT_EQ(ordered.value()[2].outbox_id, "ob-3b");
    EXPECT_EQ(ordered.value()[3].outbox_id, "ob-1");
    EXPECT_EQ(ordered.value()[4].outbox_id, "ob-2");

    // Limit enforcement
    const auto top2 = store.list_outbox_records(2U);
    ASSERT_TRUE(top2.is_ok());
    ASSERT_EQ(top2.value().size(), 2U);
    EXPECT_EQ(top2.value()[0].outbox_id, "ob-4");
    EXPECT_EQ(top2.value()[1].outbox_id, "ob-3a");

    // Upsert attempt metadata update
    auto updated = r_norm_early;
    updated.attempt_count = 3U;
    updated.last_error = "Gateway timeout";
    ASSERT_TRUE(store.save_outbox_record(updated).is_ok());
    const auto fetched = store.get_outbox_record("ob-1");
    ASSERT_TRUE(fetched.is_ok());
    EXPECT_EQ(fetched.value().attempt_count, 3U);
    EXPECT_EQ(fetched.value().last_error, "Gateway timeout");

    // Explicit delete and missing lookup
    ASSERT_TRUE(store.delete_outbox_record("ob-3a").is_ok());
    EXPECT_TRUE(store.get_outbox_record("ob-3a").is_error());
    EXPECT_TRUE(store.delete_outbox_record("ob-3a").is_error());

    // Cascade delete conversation removes conv_a entries but keeps conv_b ob-4
    ASSERT_TRUE(store.delete_conversation(conv_a).is_ok());
    const auto after_cascade = store.list_outbox_records();
    ASSERT_TRUE(after_cascade.is_ok());
    ASSERT_EQ(after_cascade.value().size(), 1U);
    EXPECT_EQ(after_cascade.value()[0].outbox_id, "ob-4");

    // Validation and closed-store checks
    OfflineOutboxRecord invalid = updated;
    invalid.payload_json.clear();
    EXPECT_TRUE(store.save_outbox_record(invalid).is_error());
    EXPECT_TRUE(store.get_outbox_record("").is_error());
    EXPECT_TRUE(store.delete_outbox_record("").is_error());

    ASSERT_TRUE(store.close().is_ok());
    EXPECT_TRUE(store.save_outbox_record(r_emerg).is_error());
    EXPECT_TRUE(store.get_outbox_record("ob-4").is_error());
    EXPECT_TRUE(store.list_outbox_records().is_error());
    EXPECT_TRUE(store.delete_outbox_record("ob-4").is_error());
}

TEST_F(OfflineOutboxPersistenceTest, MemoryLocalStoreSyncCursorMonotonicityAndListing) {
    MemoryLocalStore store;
    ASSERT_TRUE(store.open("mem").is_ok());

    const DeviceId dev1("dev-mem-1");
    const DeviceId dev2("dev-mem-2");
    const ConversationId conv1("conv-cur-1");
    const ConversationId conv2("conv-cur-2");
    ASSERT_TRUE(store.save_conversation(Conversation(conv1, ConversationType::Direct, "C1")).is_ok());
    ASSERT_TRUE(store.save_conversation(Conversation(conv2, ConversationType::Group, "C2")).is_ok());

    // Unseen cursor returns sequence 0 default cleanly
    const auto fresh = store.get_sync_cursor(dev1, conv1);
    ASSERT_TRUE(fresh.is_ok());
    EXPECT_EQ(fresh.value().last_delivered_sequence, 0ULL);
    EXPECT_EQ(fresh.value().sync_version, 1);

    // Save initial cursor
    const auto s1 = store.save_sync_cursor(SyncCursorRecord{
        .device_id = dev1,
        .conversation_id = conv1,
        .last_delivered_sequence = 40ULL,
        .last_sync_timestamp_ms = 2000LL,
        .sync_version = 1,
    });
    ASSERT_TRUE(s1.is_ok());
    EXPECT_EQ(s1.value().last_delivered_sequence, 40ULL);

    // Stale cursor (< 40) never regresses sequence or timestamp
    const auto s_stale = store.save_sync_cursor(SyncCursorRecord{
        .device_id = dev1,
        .conversation_id = conv1,
        .last_delivered_sequence = 15ULL,
        .last_sync_timestamp_ms = 9000LL,
        .sync_version = 1,
    });
    ASSERT_TRUE(s_stale.is_ok());
    EXPECT_EQ(s_stale.value().last_delivered_sequence, 40ULL);
    EXPECT_EQ(s_stale.value().last_sync_timestamp_ms, 2000LL);

    // Advancing sequence and saving a second conversation & global cursor
    const auto s2 = store.save_sync_cursor(SyncCursorRecord{
        .device_id = dev1,
        .conversation_id = conv1,
        .last_delivered_sequence = 75ULL,
        .last_sync_timestamp_ms = 5000LL,
        .sync_version = 2,
    });
    ASSERT_TRUE(s2.is_ok());
    EXPECT_EQ(s2.value().last_delivered_sequence, 75ULL);
    EXPECT_EQ(s2.value().sync_version, 2);

    ASSERT_TRUE(store
                    .save_sync_cursor(SyncCursorRecord{
                        .device_id = dev1,
                        .conversation_id = conv2,
                        .last_delivered_sequence = 12ULL,
                        .last_sync_timestamp_ms = 3000LL,
                        .sync_version = 1,
                    })
                    .is_ok());
    ASSERT_TRUE(store
                    .save_sync_cursor(SyncCursorRecord{
                        .device_id = dev2,
                        .conversation_id = conv1,
                        .last_delivered_sequence = 99ULL,
                        .last_sync_timestamp_ms = 4000LL,
                        .sync_version = 1,
                    })
                    .is_ok());

    const auto listed = store.list_sync_cursors(dev1);
    ASSERT_TRUE(listed.is_ok());
    ASSERT_EQ(listed.value().size(), 2U);
    EXPECT_EQ(listed.value()[0].conversation_id, conv1);
    EXPECT_EQ(listed.value()[0].last_delivered_sequence, 75ULL);
    EXPECT_EQ(listed.value()[1].conversation_id, conv2);

    // Deleting conv1 cascades sync_cursors for conv1 without deleting conv2
    ASSERT_TRUE(store.delete_conversation(conv1).is_ok());
    const auto listed_after = store.list_sync_cursors(dev1);
    ASSERT_TRUE(listed_after.is_ok());
    ASSERT_EQ(listed_after.value().size(), 1U);
    EXPECT_EQ(listed_after.value()[0].conversation_id, conv2);

    // Validation & closed-store checks
    EXPECT_TRUE(store.save_sync_cursor(SyncCursorRecord{}).is_error());
    EXPECT_TRUE(store.get_sync_cursor(DeviceId{}, conv2).is_error());
    EXPECT_TRUE(store.list_sync_cursors(DeviceId{}).is_error());
    ASSERT_TRUE(store.close().is_ok());
    EXPECT_TRUE(store.save_sync_cursor(s2.value()).is_error());
    EXPECT_TRUE(store.get_sync_cursor(dev1, conv2).is_error());
    EXPECT_TRUE(store.list_sync_cursors(dev1).is_error());
}

TEST_F(OfflineOutboxPersistenceTest, SqlCipherLocalStoreOutboxAndCursorRestartDurability) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    const DeviceId dev("dev-sql-1");
    const ConversationId conv_a("conv-sql-a");
    const ConversationId conv_b("conv-sql-b");

    OfflineOutboxRecord expected_fanout = make_outbox_record(
        "ob-sql-fanout", OfflineOutboxOperationType::EncryptedMessageSubmission, "conv-sql-a", 3, 1500LL, "idem-sql-1");
    OfflineOutboxRecord expected_ack = make_outbox_record(
        "ob-sql-ack", OfflineOutboxOperationType::DeliveryAck, "conv-sql-b", 1, 1200LL, "idem-sql-ack",
        R"({"message_id":"m1","recipient_device_id":"dev-sql-1","delivered_at_ms":100})");

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        ASSERT_TRUE(store.save_conversation(Conversation(conv_a, ConversationType::Direct, "SQL A")).is_ok());
        ASSERT_TRUE(store.save_conversation(Conversation(conv_b, ConversationType::Group, "SQL B")).is_ok());

        ASSERT_TRUE(store.save_outbox_record(expected_ack).is_ok());
        ASSERT_TRUE(store.save_outbox_record(expected_fanout).is_ok());

        // Persist global device cursor + conversation cursor and test monotonic upsert
        ASSERT_TRUE(store
                        .save_sync_cursor(SyncCursorRecord{
                            .device_id = dev,
                            .conversation_id = ConversationId{},
                            .last_delivered_sequence = 10ULL,
                            .last_sync_timestamp_ms = 1000LL,
                            .sync_version = 1,
                        })
                        .is_ok());
        ASSERT_TRUE(store
                        .save_sync_cursor(SyncCursorRecord{
                            .device_id = dev,
                            .conversation_id = conv_a,
                            .last_delivered_sequence = 50ULL,
                            .last_sync_timestamp_ms = 2500LL,
                            .sync_version = 2,
                        })
                        .is_ok());
        const auto stale_res = store.save_sync_cursor(SyncCursorRecord{
            .device_id = dev,
            .conversation_id = conv_a,
            .last_delivered_sequence = 20ULL,
            .last_sync_timestamp_ms = 9999LL,
            .sync_version = 1,
        });
        ASSERT_TRUE(stale_res.is_ok());
        EXPECT_EQ(stale_res.value().last_delivered_sequence, 50ULL);
        EXPECT_EQ(stale_res.value().last_sync_timestamp_ms, 2500LL);

        ASSERT_TRUE(store.close().is_ok());
    }

    // Reopen fresh instance simulating full client restart
    SqlCipherLocalStore reopened(secure_storage, crypto);
    ASSERT_TRUE(reopened.open(db_path_).is_ok());

    const auto outbox_list = reopened.list_outbox_records();
    ASSERT_TRUE(outbox_list.is_ok());
    ASSERT_EQ(outbox_list.value().size(), 2U);
    EXPECT_EQ(outbox_list.value()[0], expected_fanout);
    EXPECT_EQ(outbox_list.value()[1], expected_ack);

    // Verify nested binary FanOut payload survived SQLCipher JSON storage losslessly
    const auto decoded_fanout = OfflineOutboxFanOutPayload::from_json(outbox_list.value()[0].payload_json);
    ASSERT_TRUE(decoded_fanout.has_value());
    ASSERT_EQ(decoded_fanout->device_payloads.size(), 1U);
    EXPECT_EQ(decoded_fanout->device_payloads[0].ciphertext_blob.size(), 6U);

    // Check cursor durability and unseen cursor fallback
    const auto cur_a = reopened.get_sync_cursor(dev, conv_a);
    ASSERT_TRUE(cur_a.is_ok());
    EXPECT_EQ(cur_a.value().last_delivered_sequence, 50ULL);
    EXPECT_EQ(cur_a.value().last_sync_timestamp_ms, 2500LL);
    EXPECT_EQ(cur_a.value().sync_version, 2);

    const auto cur_unseen = reopened.get_sync_cursor(dev, ConversationId("conv-never-synced"));
    ASSERT_TRUE(cur_unseen.is_ok());
    EXPECT_EQ(cur_unseen.value().last_delivered_sequence, 0ULL);

    const auto cursors = reopened.list_sync_cursors(dev);
    ASSERT_TRUE(cursors.is_ok());
    ASSERT_EQ(cursors.value().size(), 2U);
    EXPECT_TRUE(cursors.value()[0].conversation_id.empty());
    EXPECT_EQ(cursors.value()[1].conversation_id, conv_a);

    // Deleting conv_a removes expected_fanout and cur_a, while keeping expected_ack
    ASSERT_TRUE(reopened.delete_conversation(conv_a).is_ok());
    EXPECT_TRUE(reopened.get_outbox_record("ob-sql-fanout").is_error());
    EXPECT_EQ(reopened.get_sync_cursor(dev, conv_a).value().last_delivered_sequence, 0ULL);
    ASSERT_TRUE(reopened.delete_outbox_record("ob-sql-ack").is_ok());
    EXPECT_TRUE(reopened.list_outbox_records().value().empty());
}

TEST_F(OfflineOutboxPersistenceTest, SqlCipherZeroPlaintextLeakageOnDiskForOutboxAndCursors) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    const std::string secret_outbox_id = "outbox-classified-omega-991";
    const std::string secret_conv_id = "conv-top-secret-boardroom-77";
    const std::string secret_idem_key = "idem-unique-secret-token-88421";
    const std::string secret_device_id = "device-classified-alpha-01";
    const std::string secret_error_note = "SensitiveGatewayEndpointTimeoutDetails";

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());

        OfflineOutboxRecord rec =
            make_outbox_record(secret_outbox_id, OfflineOutboxOperationType::EncryptedMessageSubmission, secret_conv_id,
                               2, 1760000100000LL, secret_idem_key);
        rec.last_error = secret_error_note;
        ASSERT_TRUE(store.save_outbox_record(rec).is_ok());

        ASSERT_TRUE(store
                        .save_sync_cursor(SyncCursorRecord{
                            .device_id = DeviceId(secret_device_id),
                            .conversation_id = ConversationId(secret_conv_id),
                            .last_delivered_sequence = 1337ULL,
                            .last_sync_timestamp_ms = 1760000200000LL,
                            .sync_version = 3,
                        })
                        .is_ok());

        ASSERT_TRUE(store.close().is_ok());
    }

    const std::string combined = read_raw_bytes(db_path_) + read_raw_bytes(db_path_ + "-wal");
    ASSERT_FALSE(combined.empty());
    EXPECT_EQ(combined.find("SQLite format 3"), std::string::npos);
    EXPECT_EQ(combined.find(secret_outbox_id), std::string::npos);
    EXPECT_EQ(combined.find(secret_conv_id), std::string::npos);
    EXPECT_EQ(combined.find(secret_idem_key), std::string::npos);
    EXPECT_EQ(combined.find(secret_device_id), std::string::npos);
    EXPECT_EQ(combined.find(secret_error_note), std::string::npos);
}

TEST_F(OfflineOutboxPersistenceTest, SqlCipherRejectsWrongMasterKeyForOutboxAndCursorTables) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        ASSERT_TRUE(store
                        .save_outbox_record(make_outbox_record("ob-k1", OfflineOutboxOperationType::DeliveryAck,
                                                               "conv-k1", 0, 1000LL, "idem-k1", R"({"ok":1})"))
                        .is_ok());
        ASSERT_TRUE(store.close().is_ok());
    }

    ASSERT_TRUE(
        secure_storage.store_secret(SqlCipherLocalStore::kMasterKeyId, SecretString(std::string(64U, '8'))).is_ok());

    SqlCipherLocalStore tampered(secure_storage, crypto);
    const auto open_res = tampered.open(db_path_);
    ASSERT_TRUE(open_res.is_error());
    EXPECT_EQ(open_res.error().category(), application::ClientErrorCategory::Crypto);
    EXPECT_FALSE(tampered.is_open());
}

} // namespace
} // namespace securecloud::client::infrastructure::adapters::test
