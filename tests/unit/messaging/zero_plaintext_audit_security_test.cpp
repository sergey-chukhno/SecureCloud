#include "audit/audit_diagnostics.hpp"
#include "audit/canonical_audit_mapper.hpp"
#include "audit/messaging_audit_metrics.hpp"
#include "audit/messaging_outbox_relay.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace securecloud::messaging::audit {
namespace {

class OutboxCaptureRepository final : public repository::IMessagingAuditOutboxRepository {
  public:
    void enqueue_audit_event(const repository::AuditOutboxRecord& record) override {
        std::lock_guard<std::mutex> lock(mutex_);
        records_.push_back(record);
    }

    std::vector<repository::AuditOutboxRecord> fetch_pending_events(const std::string& outbox_bucket, int32_t shard_id,
                                                                    size_t limit,
                                                                    std::chrono::seconds /*lease_duration*/) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<repository::AuditOutboxRecord> out;
        for (const auto& rec : records_) {
            if (rec.outbox_bucket == outbox_bucket && rec.shard_id == shard_id && rec.publish_status == "PENDING") {
                out.push_back(rec);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    void mark_published(const std::string& /*outbox_bucket*/, int32_t /*shard_id*/,
                        const std::chrono::system_clock::time_point& /*created_at*/,
                        const std::string& event_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& rec : records_) {
            if (rec.event_id == event_id) {
                rec.publish_status = "PUBLISHED";
            }
        }
    }

    void record_failure(const std::string& /*outbox_bucket*/, int32_t /*shard_id*/,
                        const std::chrono::system_clock::time_point& /*created_at*/, const std::string& event_id,
                        const std::string& error_message, bool should_quarantine) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& rec : records_) {
            if (rec.event_id == event_id) {
                rec.attempt_count += 1;
                rec.last_error = error_message;
                if (should_quarantine) {
                    rec.publish_status = "QUARANTINED";
                }
            }
        }
    }

    size_t count_pending_backlog(const std::string& outbox_bucket, int32_t shard_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& rec : records_) {
            if (rec.outbox_bucket == outbox_bucket && rec.shard_id == shard_id && rec.publish_status == "PENDING") {
                ++count;
            }
        }
        return count;
    }

    std::vector<repository::AuditOutboxRecord> all_records() {
        std::lock_guard<std::mutex> lock(mutex_);
        return records_;
    }

  private:
    std::mutex mutex_;
    std::vector<repository::AuditOutboxRecord> records_;
};

class CapturingAuditClient final : public IMessagingAuditClient {
  public:
    BatchResult send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& ev : events) {
            dispatched_.push_back(ev);
        }
        return {true, false, "", {}};
    }

    std::vector<securecloud::audit::v1::AuditEventProto> dispatched() {
        std::lock_guard<std::mutex> lock(mutex_);
        return dispatched_;
    }

  private:
    std::mutex mutex_;
    std::vector<securecloud::audit::v1::AuditEventProto> dispatched_;
};

void stage_validated_audit_event(repository::IMessagingAuditOutboxRepository& repo, const std::string& event_id,
                                 const std::string& event_type, const std::string& metadata_json) {
    util::ZeroPlaintextGuard::validate_audit_payload(metadata_json);

    const auto now = std::chrono::system_clock::now();
    repository::AuditOutboxRecord staging_rec;
    staging_rec.outbox_bucket = domain::compute_outbox_bucket_utc(now);
    staging_rec.shard_id = 0;
    staging_rec.created_at = now;
    staging_rec.event_id = event_id;
    staging_rec.event_type = event_type;
    staging_rec.severity = "INFO";
    staging_rec.payload_proto_bin.assign(metadata_json.begin(), metadata_json.end());

    const auto mapped_proto = map_outbox_record_to_canonical_proto(staging_rec);
    ASSERT_TRUE(mapped_proto.has_value());

    std::string serialized_wire;
    ASSERT_TRUE(mapped_proto->SerializeToString(&serialized_wire));

    staging_rec.payload_proto_bin.assign(serialized_wire.begin(), serialized_wire.end());
    repo.enqueue_audit_event(staging_rec);
}

class ZeroPlaintextAuditSecurityTest : public ::testing::Test {
  protected:
    void SetUp() override {
        MessagingAuditMetrics::instance().reset();
        AuditDiagnostics::set_log_sink([this](std::string_view line) {
            std::lock_guard<std::mutex> lock(logs_mutex_);
            captured_logs_.emplace_back(line);
        });
    }

    void TearDown() override {
        AuditDiagnostics::reset_log_sink();
        MessagingAuditMetrics::instance().reset();
    }

    std::vector<std::string> logs() {
        std::lock_guard<std::mutex> lock(logs_mutex_);
        return captured_logs_;
    }

    std::mutex logs_mutex_;
    std::vector<std::string> captured_logs_;
};

TEST_F(ZeroPlaintextAuditSecurityTest, RejectsCiphertextPrekeysPrivateKeysAndTokensBeforeOutboxStaging) {
    OutboxCaptureRepository repo;

    const std::string long_base64_ciphertext(160, 'A');
    const std::vector<std::string> forbidden_payloads = {
        R"({"conversation_id":"conv-1","ciphertext":"deadbeef01020304"})",
        R"({"conversation_id":"conv-1","ciphertext_blob":"aabbccddeeff"})",
        R"({"device_id":"dev-1","ephemeral_public_key":"04aabbccdd"})",
        R"({"device_id":"dev-1","signed_prekey":"0511223344"})",
        R"({"device_id":"dev-1","ratchet_state":"9988776655"})",
        R"({"user_id":"usr-1","private_key":"-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg..."})",
        R"({"user_id":"usr-1","shared_secret":"0123456789abcdef"})",
        R"({"user_id":"usr-1","session_key":"abcdef0123456789"})",
        R"({"user_id":"usr-1","iv":"00112233445566778899aabb"})",
        R"({"user_id":"usr-1","auth_tag":"ffeeddccbbaa99887766554433221100"})",
        R"({"user_id":"usr-1","plaintext":"Hello Alice, meet at 10pm"})",
        R"({"user_id":"usr-1","access_token":"eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c3ItMSJ9.c2lnbmF0dXJl"})",
        R"({"user_id":"usr-1","nested":{"credential":"Bearer secret.jwt.token"}})",
        std::string(R"({"conversation_id":"conv-1","opaque_field":")") + long_base64_ciphertext + R"("})",
        "{\"conversation_id\":\"conv-1\",\"raw_bytes\":\"abc\x01"
        "def\"}",
    };

    for (size_t i = 0; i < forbidden_payloads.size(); ++i) {
        std::string violation;
        EXPECT_FALSE(util::ZeroPlaintextGuard::is_safe_audit_payload(forbidden_payloads[i], &violation))
            << "Payload index " << i << " should have been rejected";
        EXPECT_FALSE(violation.empty());

        EXPECT_THROW(stage_validated_audit_event(repo, domain::generate_audit_event_id(), "message.submitted",
                                                 forbidden_payloads[i]),
                     std::logic_error)
            << "Payload index " << i << " must throw std::logic_error";
    }

    EXPECT_TRUE(repo.all_records().empty());
}

TEST_F(ZeroPlaintextAuditSecurityTest, SerializedOutboxBlobsAndDispatchedProtosContainZeroPlaintextLeakage) {
    auto repo = std::make_shared<OutboxCaptureRepository>();
    auto client = std::make_shared<CapturingAuditClient>();

    constexpr std::string_view kPlaintextCanary = "CONFIDENTIAL_E2EE_MESSAGE_PLAINTEXT_9918273645";
    constexpr std::string_view kCiphertextCanary = "9f8e7d6c5b4a39281716151413121110deadbeefcafebabe";
    constexpr std::string_view kPrivateKeyCanary = "PRIVATE_KEY_MATERIAL_X25519_00112233445566778899";
    constexpr std::string_view kPrekeyCanary = "SIGNED_PREKEY_BUNDLE_AABBCCDDEEFF001122334455";

    struct CanonicalSample {
        std::string event_id;
        std::string event_type;
        std::string metadata_json;
    };

    const std::vector<CanonicalSample> samples = {
        {domain::generate_audit_event_id(), "message.submitted",
         R"({"conversation_id":"conv-100","message_id":"msg-200","recipient_count":2,"payload_size_bytes":128,"algorithm":"X3DH-AES256-GCM"})"},
        {domain::generate_audit_event_id(), "message.delivered",
         R"({"conversation_id":"conv-100","message_id":"msg-200","recipient_device_id":"dev-9"})"},
        {domain::generate_audit_event_id(), "message.read",
         R"({"conversation_id":"conv-100","watermark_sequence":42})"},
        {domain::generate_audit_event_id(), "conversation.created",
         R"({"conversation_id":"conv-100","conversation_type":"GROUP","initial_member_count":3})"},
        {domain::generate_audit_event_id(), "security.authorization.denied",
         R"({"conversation_id":"conv-100","action":"SEND_MESSAGE","denial_reason":"NOT_ACTIVE_MEMBER"})"},
    };

    for (const auto& sample : samples) {
        ASSERT_NO_THROW(stage_validated_audit_event(*repo, sample.event_id, sample.event_type, sample.metadata_json));
    }

    const auto stored_records = repo->all_records();
    ASSERT_EQ(stored_records.size(), samples.size());

    for (const auto& rec : stored_records) {
        const std::string raw_blob(reinterpret_cast<const char*>(rec.payload_proto_bin.data()),
                                   rec.payload_proto_bin.size());
        EXPECT_EQ(raw_blob.find(kPlaintextCanary), std::string::npos);
        EXPECT_EQ(raw_blob.find(kCiphertextCanary), std::string::npos);
        EXPECT_EQ(raw_blob.find(kPrivateKeyCanary), std::string::npos);
        EXPECT_EQ(raw_blob.find(kPrekeyCanary), std::string::npos);
    }

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 1;
    cfg.active_poll_interval = std::chrono::milliseconds(2);
    cfg.idle_poll_interval = std::chrono::milliseconds(5);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 100 && client->dispatched().size() < samples.size(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    relay.stop();

    const auto dispatched = client->dispatched();
    ASSERT_EQ(dispatched.size(), samples.size());

    for (const auto& proto : dispatched) {
        EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
        EXPECT_FALSE(proto.metadata().empty());

        std::string wire_bytes;
        ASSERT_TRUE(proto.SerializeToString(&wire_bytes));
        EXPECT_EQ(wire_bytes.find(kPlaintextCanary), std::string::npos);
        EXPECT_EQ(wire_bytes.find(kCiphertextCanary), std::string::npos);
        EXPECT_EQ(wire_bytes.find(kPrivateKeyCanary), std::string::npos);
        EXPECT_EQ(wire_bytes.find(kPrekeyCanary), std::string::npos);
    }
}

TEST_F(ZeroPlaintextAuditSecurityTest, DiagnosticLogsRedactAllCryptographicAndTokenLeakageVectors) {
    AuditDiagnostics::log_quarantine_event(
        "2026111910", 2, "evt-leak-1", "message.submitted", 5,
        "Upstream error: ciphertext=abcdef0123456789 key=secret_aes_key iv=112233445566 auth_tag=998877665544 "
        "secret=top_secret payload=raw_bytes token=tok_live_98765 password=hunter2 Bearer eyJhbGciOiJIUzI1NiJ9.a.b");

    AuditDiagnostics::log_connection_failure(
        "2026111910", 2, 10, 14, "UNAVAILABLE: handshake failed with token=secret_rpc_token Bearer eyJanotherTokenVal",
        std::chrono::milliseconds(200));

    const auto emitted = logs();
    ASSERT_EQ(emitted.size(), 2U);

    static constexpr std::array<std::string_view, 10> kForbiddenLeakSubstrings = {
        "abcdef0123456789", "secret_aes_key", "112233445566", "998877665544",         "top_secret",
        "raw_bytes",        "tok_live_98765", "hunter2",      "eyJhbGciOiJIUzI1NiJ9", "secret_rpc_token",
    };

    for (const auto& line : emitted) {
        EXPECT_NO_THROW({
            const auto parsed = nlohmann::json::parse(line);
            EXPECT_TRUE(parsed.is_object());
        });

        for (std::string_view secret : kForbiddenLeakSubstrings) {
            EXPECT_EQ(line.find(secret), std::string::npos) << "Leaked secret: " << secret;
        }
        EXPECT_NE(line.find("[REDACTED]"), std::string::npos);
    }
}

} // namespace
} // namespace securecloud::messaging::audit
