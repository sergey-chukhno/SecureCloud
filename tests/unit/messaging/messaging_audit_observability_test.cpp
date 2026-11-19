#include "audit/audit_diagnostics.hpp"
#include "audit/messaging_audit_metrics.hpp"
#include "audit/messaging_outbox_relay.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging::audit {
namespace {

class InMemoryOutboxRepository final : public repository::IMessagingAuditOutboxRepository {
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

    std::string status_of(const std::string& event_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& rec : records_) {
            if (rec.event_id == event_id) {
                return rec.publish_status;
            }
        }
        return "";
    }

  private:
    std::mutex mutex_;
    std::vector<repository::AuditOutboxRecord> records_;
};

class StubAuditClient final : public IMessagingAuditClient {
  public:
    BatchResult next_result{true, false, "", {}};
    std::atomic<size_t> calls{0};

    BatchResult send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& /*events*/) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mutex_);
        return next_result;
    }

    void set_result(BatchResult res) {
        std::lock_guard<std::mutex> lock(mutex_);
        next_result = std::move(res);
    }

  private:
    std::mutex mutex_;
};

std::string current_utc_bucket() {
    const auto now = std::chrono::system_clock::now();
    const auto time_t_val = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &time_t_val);
#else
    gmtime_r(&time_t_val, &tm_buf);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d-%H", &tm_buf);
    return std::string(buf);
}

repository::AuditOutboxRecord make_valid_record(const std::string& event_id, int32_t shard_id,
                                                const std::string& event_type = "message.submitted") {
    securecloud::audit::v1::AuditEventProto proto;
    proto.set_event_id(event_id);
    proto.set_event_type(event_type);
    proto.set_severity(securecloud::audit::v1::SEVERITY_INFO);

    std::string serialized;
    proto.SerializeToString(&serialized);

    repository::AuditOutboxRecord rec;
    rec.outbox_bucket = current_utc_bucket();
    rec.shard_id = shard_id;
    rec.created_at = std::chrono::system_clock::now() - std::chrono::milliseconds(25);
    rec.event_id = event_id;
    rec.event_type = event_type;
    rec.severity = "INFO";
    rec.payload_proto_bin.assign(serialized.begin(), serialized.end());
    return rec;
}

class MessagingAuditObservabilityTest : public ::testing::Test {
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

TEST_F(MessagingAuditObservabilityTest, LockFreeMetricsAndPrometheusExposition) {
    auto& metrics = MessagingAuditMetrics::instance();

    constexpr int kThreads = 4;
    constexpr int kIterations = 250;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&metrics]() {
            for (int i = 0; i < kIterations; ++i) {
                metrics.increment_staged("message.submitted", "INFO");
                metrics.increment_published("message.submitted");
                metrics.increment_retried(AuditRetryReason::Unavailable);
                metrics.increment_quarantined(AuditQuarantineReason::InvalidArgument);
                metrics.record_delivery_latency(0.015);
                metrics.record_batch_size(20);
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }

    metrics.set_shard_backlog(3, 42);

    const uint64_t expected = static_cast<uint64_t>(kThreads * kIterations);
    EXPECT_EQ(metrics.staged_total("message.submitted", "INFO"), expected);
    EXPECT_EQ(metrics.published_total("message.submitted"), expected);
    EXPECT_EQ(metrics.retried_total(AuditRetryReason::Unavailable), expected);
    EXPECT_EQ(metrics.quarantined_total(AuditQuarantineReason::InvalidArgument), expected);
    EXPECT_EQ(metrics.shard_backlog(3), 42);
    EXPECT_EQ(metrics.delivery_latency_count(), expected);
    EXPECT_EQ(metrics.batch_size_count(), expected);
    EXPECT_EQ(metrics.batch_size_sum(), expected * 20);

    const std::string prom = AuditDiagnostics::render_prometheus_metrics();
    EXPECT_NE(prom.find("messaging_audit_events_staged_total{event_type=\"message.submitted\",severity=\"INFO\"} 1000"),
              std::string::npos);
    EXPECT_NE(prom.find("messaging_audit_events_published_total{event_type=\"message.submitted\"} 1000"),
              std::string::npos);
    EXPECT_NE(prom.find("messaging_audit_events_retried_total{reason=\"unavailable\"} 1000"), std::string::npos);
    EXPECT_NE(prom.find("messaging_audit_events_quarantined_total{reason=\"invalid_argument\"} 1000"),
              std::string::npos);
    EXPECT_NE(prom.find("messaging_audit_outbox_backlog_gauge{shard_id=\"3\"} 42"), std::string::npos);
    EXPECT_NE(prom.find("messaging_audit_delivery_latency_seconds_count 1000"), std::string::npos);
    EXPECT_NE(prom.find("messaging_audit_batch_size_count 1000"), std::string::npos);
}

TEST_F(MessagingAuditObservabilityTest, StructuredDiagnosticsSanitizesSensitiveData) {
    AuditDiagnostics::log_quarantine_event("2026-11-19-08", 5, "evt-123", "message.submitted", 5,
                                           "Rejected payload: ciphertext=deadbeef01020304 secret=super_secret_key "
                                           "token=abc123xyz Bearer eyJsecretJwtToken");

    const auto emitted = logs();
    ASSERT_EQ(emitted.size(), 1U);

    const auto parsed = nlohmann::json::parse(emitted[0]);
    EXPECT_EQ(parsed["level"], "ERROR");
    EXPECT_EQ(parsed["security_alert"], true);
    EXPECT_EQ(parsed["event"], "outbox.event_quarantined");
    EXPECT_EQ(parsed["shard_id"], 5);

    const std::string reason = parsed["reason"].get<std::string>();
    EXPECT_EQ(reason.find("deadbeef01020304"), std::string::npos);
    EXPECT_EQ(reason.find("super_secret_key"), std::string::npos);
    EXPECT_EQ(reason.find("abc123xyz"), std::string::npos);
    EXPECT_EQ(reason.find("eyJsecretJwtToken"), std::string::npos);
    EXPECT_NE(reason.find("[REDACTED]"), std::string::npos);
}

TEST_F(MessagingAuditObservabilityTest, RelayRecordsPublishedLatencyBatchAndBacklogMetrics) {
    auto repo = std::make_shared<InMemoryOutboxRepository>();
    auto client = std::make_shared<StubAuditClient>();

    repo->enqueue_audit_event(make_valid_record("evt-1", 0, "message.submitted"));
    repo->enqueue_audit_event(make_valid_record("evt-2", 0, "message.read"));

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 1;
    cfg.active_poll_interval = std::chrono::milliseconds(5);
    cfg.idle_poll_interval = std::chrono::milliseconds(10);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 50 && client->calls.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    relay.stop();

    EXPECT_EQ(repo->status_of("evt-1"), "PUBLISHED");
    EXPECT_EQ(repo->status_of("evt-2"), "PUBLISHED");

    auto& metrics = MessagingAuditMetrics::instance();
    EXPECT_EQ(metrics.published_total("message.submitted"), 1U);
    EXPECT_EQ(metrics.published_total("message.read"), 1U);
    EXPECT_EQ(metrics.batch_size_count(), 1U);
    EXPECT_EQ(metrics.batch_size_sum(), 2U);
    EXPECT_EQ(metrics.delivery_latency_count(), 2U);
    EXPECT_GT(metrics.delivery_latency_sum(), 0.0);
    EXPECT_EQ(metrics.shard_backlog(0), 0);
}

TEST_F(MessagingAuditObservabilityTest, RelayRecordsQuarantineAndRetryMetricsAndLogs) {
    auto repo = std::make_shared<InMemoryOutboxRepository>();
    auto client = std::make_shared<StubAuditClient>();
    client->set_result({false, true, "UNAVAILABLE: upstream timeout", {}});

    // 1 local malformed record (immediate quarantine) + 1 valid record (transient retry -> quarantine at max_retries=1)
    repository::AuditOutboxRecord bad_rec = make_valid_record("evt-corrupt", 0);
    bad_rec.payload_proto_bin = {0xFF, 0xFE, 0xFD, 0x00, 0x01};
    repo->enqueue_audit_event(bad_rec);
    repo->enqueue_audit_event(make_valid_record("evt-transient", 0));

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 1;
    cfg.max_retries = 1;
    cfg.active_poll_interval = std::chrono::milliseconds(5);
    cfg.idle_poll_interval = std::chrono::milliseconds(10);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 50 && client->calls.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    relay.stop();

    EXPECT_EQ(repo->status_of("evt-corrupt"), "QUARANTINED");
    EXPECT_EQ(repo->status_of("evt-transient"), "QUARANTINED");

    auto& metrics = MessagingAuditMetrics::instance();
    EXPECT_EQ(metrics.quarantined_total(AuditQuarantineReason::SerializationFailure), 1U);
    EXPECT_EQ(metrics.quarantined_total(AuditQuarantineReason::MaxRetriesExhausted), 1U);

    bool saw_quarantine_alert = false;
    for (const auto& line : logs()) {
        const auto parsed = nlohmann::json::parse(line);
        if (parsed.value("event", "") == "outbox.event_quarantined") {
            saw_quarantine_alert = true;
            EXPECT_TRUE(parsed.value("security_alert", false));
        }
    }
    EXPECT_TRUE(saw_quarantine_alert);
}

} // namespace
} // namespace securecloud::messaging::audit
