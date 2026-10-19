#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/domain/delivery_types.hpp"
#include "messaging/domain/envelope_types.hpp"
#include "messaging/repository/scylla_delivery_state_repository.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::repository::test {
namespace {

using domain::ConversationId;
using domain::DeliveryState;
using domain::DeviceDeliveryRecord;
using domain::DeviceId;
using domain::E2EAlgorithm;
using domain::E2EProtocolVersion;
using domain::MessageId;
using domain::MessagePriority;
using domain::PerDeviceEnvelope;

TEST(ScyllaDeliveryRepositoryEnvelopeTest, SaveAndFetchWithFullPerDeviceEnvelope) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto dev_id = DeviceId("dev-pixel-9-pro");
    auto msg_id = MessageId::generate_v7();
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();

    DeviceDeliveryRecord rec;
    rec.device_id = dev_id;
    rec.delivery_bucket = "202610";
    rec.accepted_at = now;
    rec.message_id = msg_id;
    rec.conversation_id = conv_id;
    rec.message_sequence = 42;
    rec.message_priority = MessagePriority::Normal;
    rec.delivery_state = DeliveryState::Pending;
    rec.attempt_count = 0;
    rec.next_retry_at = now + std::chrono::seconds(15);

    // Populate envelope fields
    rec.ciphertext_blob = std::string("\xCA\xFE\xBA\xBE\x01\x02", 6);
    rec.ephemeral_public_key = std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF};
    rec.iv = std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    rec.auth_tag = std::vector<uint8_t>{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160};
    rec.algorithm = E2EAlgorithm::AES_256_GCM;
    rec.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    rec.one_time_prekey_id = "otk-key-uuid-999";

    // 1. Save pending deliveries
    repo.save_pending_deliveries({rec});
    auto executed = mock->get_executed_prepared();
    ASSERT_EQ(executed.size(), 1U);
    EXPECT_EQ(executed[0].first.value(), "deliv_repo_insert_pending");

    const auto& params = executed[0].second.values();
    ASSERT_EQ(params.size(), 17U);
    EXPECT_EQ(params[0].as_string(), dev_id.str());
    EXPECT_EQ(params[1].as_string(), "202610");
    EXPECT_EQ(params[3].as_string(), msg_id.to_string());
    EXPECT_EQ(params[4].as_string(), conv_id.to_string());
    EXPECT_EQ(params[5].as_int64(), 42);
    EXPECT_EQ(params[6].as_string(), "NORMAL");
    EXPECT_EQ(params[7].as_string(), "PENDING");
    EXPECT_EQ(params[8].as_int(), 0);

    // Verify envelope params
    std::vector<uint8_t> expected_cipher_vec(rec.ciphertext_blob.begin(), rec.ciphertext_blob.end());
    EXPECT_EQ(params[10].as_blob(), expected_cipher_vec);
    EXPECT_EQ(params[11].as_blob(), rec.ephemeral_public_key);
    EXPECT_EQ(params[12].as_blob(), rec.iv);
    EXPECT_EQ(params[13].as_blob(), rec.auth_tag);
    EXPECT_EQ(params[14].as_string(), "AES-256-GCM");
    EXPECT_EQ(params[15].as_int(), 1);
    EXPECT_EQ(params[16].as_string(), "otk-key-uuid-999");

    // 2. Fetch pending deliveries with all 17 columns
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    int64_t retry_ms = now_ms + 15000;

    db::ScyllaRow row(
        {"device_id", "delivery_bucket", "accepted_at", "message_id", "conversation_id", "message_sequence",
         "message_priority", "delivery_state", "attempt_count", "next_retry_at", "ciphertext_blob",
         "ephemeral_public_key", "iv", "auth_tag", "algorithm", "protocol_version", "one_time_prekey_id"},
        {db::ScyllaValue(dev_id.str()), db::ScyllaValue("202610"), db::ScyllaValue(now_ms),
         db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(conv_id.to_string()),
         db::ScyllaValue(static_cast<int64_t>(42)), db::ScyllaValue("NORMAL"), db::ScyllaValue("PENDING"),
         db::ScyllaValue(0), db::ScyllaValue(retry_ms), db::ScyllaValue(expected_cipher_vec),
         db::ScyllaValue(rec.ephemeral_public_key), db::ScyllaValue(rec.iv), db::ScyllaValue(rec.auth_tag),
         db::ScyllaValue("AES-256-GCM"), db::ScyllaValue(1), db::ScyllaValue("otk-key-uuid-999")});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_fetch_pending"), db::ScyllaQueryResult({row}));

    auto fetched = repo.fetch_pending_for_device(dev_id, "202610", 10);
    ASSERT_EQ(fetched.size(), 1U);
    EXPECT_EQ(fetched[0].device_id, dev_id);
    EXPECT_EQ(fetched[0].delivery_bucket, "202610");
    EXPECT_EQ(fetched[0].message_id, msg_id);
    EXPECT_EQ(fetched[0].conversation_id, conv_id);
    EXPECT_EQ(fetched[0].message_sequence, 42U);
    EXPECT_EQ(fetched[0].message_priority, MessagePriority::Normal);
    EXPECT_EQ(fetched[0].delivery_state, DeliveryState::Pending);

    // Assert exact envelope equality
    EXPECT_EQ(fetched[0].ciphertext_blob, rec.ciphertext_blob);
    EXPECT_EQ(fetched[0].ephemeral_public_key, rec.ephemeral_public_key);
    EXPECT_EQ(fetched[0].iv, rec.iv);
    EXPECT_EQ(fetched[0].auth_tag, rec.auth_tag);
    EXPECT_EQ(fetched[0].algorithm, E2EAlgorithm::AES_256_GCM);
    EXPECT_EQ(fetched[0].protocol_version, E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    ASSERT_TRUE(fetched[0].one_time_prekey_id.has_value());
    EXPECT_EQ(fetched[0].one_time_prekey_id.value(), "otk-key-uuid-999");
}

TEST(ScyllaDeliveryRepositoryEnvelopeTest, SetEnvelopeHelperIntegration) {
    PerDeviceEnvelope env;
    env.recipient_device_id = DeviceId("dev-tablet-456");
    env.ciphertext_blob = std::string("\x00\x11\x22\x33\x44", 5);
    env.ephemeral_public_key = {0xAA, 0xBB};
    env.iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    env.auth_tag = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
    env.algorithm = E2EAlgorithm::AES_256_GCM;
    env.protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet;
    env.one_time_prekey_id = "prekey-88";

    DeviceDeliveryRecord rec;
    rec.device_id = env.recipient_device_id;
    rec.set_envelope(env);

    EXPECT_EQ(rec.ciphertext_blob, env.ciphertext_blob);
    EXPECT_EQ(rec.ephemeral_public_key, env.ephemeral_public_key);
    EXPECT_EQ(rec.iv, env.iv);
    EXPECT_EQ(rec.auth_tag, env.auth_tag);
    EXPECT_EQ(rec.algorithm, E2EAlgorithm::AES_256_GCM);
    EXPECT_EQ(rec.protocol_version, E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet);
    ASSERT_TRUE(rec.one_time_prekey_id.has_value());
    EXPECT_EQ(rec.one_time_prekey_id.value(), "prekey-88");
}

TEST(ScyllaDeliveryRepositoryEnvelopeTest, FetchLegacyRowWithoutEnvelopeColumns) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto dev_id = DeviceId("dev-legacy-1");
    auto msg_id = MessageId::generate_v7();
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Row containing ONLY legacy 10 columns (no envelope columns)
    db::ScyllaRow legacy_row({"device_id", "delivery_bucket", "accepted_at", "message_id", "conversation_id",
                              "message_sequence", "message_priority", "delivery_state", "attempt_count",
                              "next_retry_at"},
                             {db::ScyllaValue(dev_id.str()), db::ScyllaValue("202610"), db::ScyllaValue(now_ms),
                              db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(conv_id.to_string()),
                              db::ScyllaValue(static_cast<int64_t>(10)), db::ScyllaValue("LOW"),
                              db::ScyllaValue("PENDING"), db::ScyllaValue(1), db::ScyllaValue(now_ms + 1000)});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_fetch_pending"), db::ScyllaQueryResult({legacy_row}));

    auto fetched = repo.fetch_pending_for_device(dev_id, "202610", 10);
    ASSERT_EQ(fetched.size(), 1U);
    EXPECT_EQ(fetched[0].device_id, dev_id);
    EXPECT_EQ(fetched[0].message_id, msg_id);

    // Verify envelope fields have default values (backward compatibility)
    EXPECT_TRUE(fetched[0].ciphertext_blob.empty());
    EXPECT_TRUE(fetched[0].ephemeral_public_key.empty());
    EXPECT_TRUE(fetched[0].iv.empty());
    EXPECT_TRUE(fetched[0].auth_tag.empty());
    EXPECT_FALSE(fetched[0].one_time_prekey_id.has_value());
}

TEST(ScyllaDeliveryRepositoryEnvelopeTest, FetchRowWithNullEnvelopeColumns) {
    auto mock = std::make_shared<db::MockScyllaSession>();
    ScyllaDeliveryStateRepository repo(mock);

    auto dev_id = DeviceId("dev-null-env");
    auto msg_id = MessageId::generate_v7();
    auto conv_id = ConversationId::generate_v7();
    auto now = std::chrono::system_clock::now();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Row containing all 17 columns but envelope columns are NULL
    db::ScyllaRow row_with_nulls(
        {"device_id", "delivery_bucket", "accepted_at", "message_id", "conversation_id", "message_sequence",
         "message_priority", "delivery_state", "attempt_count", "next_retry_at", "ciphertext_blob",
         "ephemeral_public_key", "iv", "auth_tag", "algorithm", "protocol_version", "one_time_prekey_id"},
        {db::ScyllaValue(dev_id.str()), db::ScyllaValue("202610"), db::ScyllaValue(now_ms),
         db::ScyllaValue(msg_id.to_string()), db::ScyllaValue(conv_id.to_string()),
         db::ScyllaValue(static_cast<int64_t>(10)), db::ScyllaValue("LOW"), db::ScyllaValue("PENDING"),
         db::ScyllaValue(1), db::ScyllaValue(now_ms + 1000), db::ScyllaValue(), db::ScyllaValue(), db::ScyllaValue(),
         db::ScyllaValue(), db::ScyllaValue(), db::ScyllaValue(), db::ScyllaValue()});

    mock->set_prepared_result(db::PreparedStatementId("deliv_repo_fetch_pending"),
                              db::ScyllaQueryResult({row_with_nulls}));

    auto fetched = repo.fetch_pending_for_device(dev_id, "202610", 10);
    ASSERT_EQ(fetched.size(), 1U);
    EXPECT_TRUE(fetched[0].ciphertext_blob.empty());
    EXPECT_TRUE(fetched[0].ephemeral_public_key.empty());
    EXPECT_TRUE(fetched[0].iv.empty());
    EXPECT_TRUE(fetched[0].auth_tag.empty());
    EXPECT_FALSE(fetched[0].one_time_prekey_id.has_value());
}

} // namespace
} // namespace securecloud::messaging::repository::test
