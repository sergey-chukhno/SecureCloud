#include "audit/audit_diagnostics.hpp"
#include "audit/messaging_audit_metrics.hpp"
#include "audit/messaging_outbox_relay.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::audit {
namespace {

class ThreadSafeOutboxRepository final : public repository::IMessagingAuditOutboxRepository {
  public:
    void enqueue_audit_event(const repository::AuditOutboxRecord& record) override {
        std::lock_guard<std::mutex> lock(mutex_);
        records_.push_back(record);
        leased_until_[record.event_id] = std::chrono::steady_clock::time_point::min();
    }

    std::vector<repository::AuditOutboxRecord> fetch_pending_events(const std::string& outbox_bucket, int32_t shard_id,
                                                                    size_t limit,
                                                                    std::chrono::seconds lease_duration) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        std::vector<repository::AuditOutboxRecord> out;

        for (const auto& rec : records_) {
            if (rec.outbox_bucket == outbox_bucket && rec.shard_id == shard_id && rec.publish_status == "PENDING" &&
                leased_until_[rec.event_id] <= now) {
                leased_until_[rec.event_id] = now + lease_duration;
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
                leased_until_[event_id] = std::chrono::steady_clock::time_point::min();
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

    int32_t attempts_of(const std::string& event_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& rec : records_) {
            if (rec.event_id == event_id) {
                return rec.attempt_count;
            }
        }
        return -1;
    }

    size_t count_with_status(const std::string& status) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& rec : records_) {
            if (rec.publish_status == status) {
                ++count;
            }
        }
        return count;
    }

  private:
    std::mutex mutex_;
    std::vector<repository::AuditOutboxRecord> records_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> leased_until_;
};

class RecordingAuditClient final : public IMessagingAuditClient {
  public:
    BatchResult send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) override {
        if (dispatch_delay_.count() > 0) {
            std::this_thread::sleep_for(dispatch_delay_);
        }

        std::lock_guard<std::mutex> lock(mutex_);
        batch_sizes_.push_back(events.size());
        for (const auto& ev : events) {
            dispatched_event_ids_.push_back(ev.event_id());
        }
        return next_result_;
    }

    void set_result(BatchResult result) {
        std::lock_guard<std::mutex> lock(mutex_);
        next_result_ = std::move(result);
    }

    void set_dispatch_delay(std::chrono::milliseconds delay) { dispatch_delay_ = delay; }

    std::vector<std::string> dispatched_ids() {
        std::lock_guard<std::mutex> lock(mutex_);
        return dispatched_event_ids_;
    }

    std::vector<size_t> batch_sizes() {
        std::lock_guard<std::mutex> lock(mutex_);
        return batch_sizes_;
    }

  private:
    std::mutex mutex_;
    BatchResult next_result_{true, false, "", {}};
    std::chrono::milliseconds dispatch_delay_{0};
    std::vector<std::string> dispatched_event_ids_;
    std::vector<size_t> batch_sizes_;
};

std::string make_uuid_v7(uint32_t tag) {
    char buf[40]{};
    std::snprintf(buf, sizeof(buf), "01934400-0000-7000-8000-%012u", tag);
    return std::string(buf);
}

repository::AuditOutboxRecord
make_record(const std::string& event_id, int32_t shard_id,
            std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now(),
            int32_t initial_attempts = 0) {
    securecloud::audit::v1::AuditEventProto proto;
    proto.set_event_id(event_id);
    proto.set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
    proto.set_event_type("message.submitted");
    proto.set_severity(securecloud::audit::v1::SEVERITY_INFO);

    std::string serialized;
    EXPECT_TRUE(proto.SerializeToString(&serialized));

    repository::AuditOutboxRecord rec;
    rec.outbox_bucket = domain::compute_outbox_bucket_utc(created_at);
    rec.shard_id = shard_id;
    rec.created_at = created_at;
    rec.event_id = event_id;
    rec.event_type = "message.submitted";
    rec.severity = "INFO";
    rec.attempt_count = initial_attempts;
    rec.payload_proto_bin.assign(serialized.begin(), serialized.end());
    return rec;
}

class MessagingOutboxRelayTest : public ::testing::Test {
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

TEST_F(MessagingOutboxRelayTest, ShardedPollerServicesAll16ShardsWithoutStarvationOrDuplicates) {
    auto repo = std::make_shared<ThreadSafeOutboxRepository>();
    auto client = std::make_shared<RecordingAuditClient>();

    constexpr int32_t kShards = 16;
    constexpr int kEventsPerShard = 4;
    constexpr size_t kTotalEvents = kShards * kEventsPerShard;

    uint32_t tag = 100;
    for (int32_t shard = 0; shard < kShards; ++shard) {
        for (int i = 0; i < kEventsPerShard; ++i) {
            repo->enqueue_audit_event(make_record(make_uuid_v7(++tag), shard));
        }
    }

    OutboxRelayConfig cfg;
    cfg.worker_threads = 4;
    cfg.total_shards = kShards;
    cfg.active_poll_interval = std::chrono::milliseconds(2);
    cfg.idle_poll_interval = std::chrono::milliseconds(5);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 200 && repo->count_with_status("PUBLISHED") < kTotalEvents; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    relay.stop();

    EXPECT_EQ(repo->count_with_status("PUBLISHED"), kTotalEvents);

    const auto dispatched = client->dispatched_ids();
    EXPECT_EQ(dispatched.size(), kTotalEvents);

    const std::set<std::string> unique_ids(dispatched.begin(), dispatched.end());
    EXPECT_EQ(unique_ids.size(), kTotalEvents);
}

TEST_F(MessagingOutboxRelayTest, DrainsPreviousAndCurrentHourlyBucketsForBoundaryEvents) {
    auto repo = std::make_shared<ThreadSafeOutboxRepository>();
    auto client = std::make_shared<RecordingAuditClient>();

    const auto now = std::chrono::system_clock::now();
    const auto prev_hour = now - std::chrono::hours(1);
    const std::string id_prev = make_uuid_v7(201);
    const std::string id_curr = make_uuid_v7(202);

    repo->enqueue_audit_event(make_record(id_prev, 0, prev_hour));
    repo->enqueue_audit_event(make_record(id_curr, 0, now));

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 1;
    cfg.active_poll_interval = std::chrono::milliseconds(2);
    cfg.idle_poll_interval = std::chrono::milliseconds(5);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 100 && repo->count_with_status("PUBLISHED") < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    relay.stop();

    EXPECT_EQ(repo->status_of(id_prev), "PUBLISHED");
    EXPECT_EQ(repo->status_of(id_curr), "PUBLISHED");
}

TEST_F(MessagingOutboxRelayTest, EnforcesConfiguredMaxBatchSizeOf100Events) {
    auto repo = std::make_shared<ThreadSafeOutboxRepository>();
    auto client = std::make_shared<RecordingAuditClient>();

    constexpr size_t kTotalEvents = 250;
    for (size_t i = 0; i < kTotalEvents; ++i) {
        repo->enqueue_audit_event(make_record(make_uuid_v7(1000 + static_cast<uint32_t>(i)), 0));
    }

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 1;
    cfg.batch_size = 100;
    cfg.active_poll_interval = std::chrono::milliseconds(2);
    cfg.idle_poll_interval = std::chrono::milliseconds(5);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 200 && repo->count_with_status("PUBLISHED") < kTotalEvents; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    relay.stop();

    EXPECT_EQ(repo->count_with_status("PUBLISHED"), kTotalEvents);

    const auto sizes = client->batch_sizes();
    ASSERT_GE(sizes.size(), 3U);
    for (size_t batch_len : sizes) {
        EXPECT_LE(batch_len, 100U);
    }
}

TEST_F(MessagingOutboxRelayTest, ExponentialBackoffAndJitterBoundsAdhereToFormula) {
    auto repo = std::make_shared<ThreadSafeOutboxRepository>();
    auto client = std::make_shared<RecordingAuditClient>();
    client->set_result({false, true, "UNAVAILABLE: downstream connection refused", {}});

    const std::string id_backoff = make_uuid_v7(300);
    repo->enqueue_audit_event(make_record(id_backoff, 0));

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 1;
    cfg.max_retries = 5;
    cfg.base_backoff = std::chrono::milliseconds(5);
    cfg.max_backoff = std::chrono::milliseconds(10000);
    cfg.active_poll_interval = std::chrono::milliseconds(2);
    cfg.idle_poll_interval = std::chrono::milliseconds(5);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 200 && repo->status_of(id_backoff) != "QUARANTINED"; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    relay.stop();

    EXPECT_EQ(repo->status_of(id_backoff), "QUARANTINED");
    EXPECT_EQ(repo->attempts_of(id_backoff), 5);

    std::vector<long long> observed_backoffs;
    for (const auto& line : logs()) {
        const auto parsed = nlohmann::json::parse(line);
        if (parsed.value("event", "") == "outbox.dispatch_failed") {
            observed_backoffs.push_back(parsed.at("backoff_ms").get<long long>());
        }
    }

    ASSERT_EQ(observed_backoffs.size(), 4U);
    for (size_t idx = 0; idx < observed_backoffs.size(); ++idx) {
        const int32_t attempt = static_cast<int32_t>(idx + 1);
        const double nominal_ms = std::min(10000.0, 5.0 * std::pow(2.0, static_cast<double>(attempt)));
        const long long min_expected = static_cast<long long>(nominal_ms * 0.8) - 1;
        const long long max_expected = static_cast<long long>(nominal_ms * 1.2) + 1;

        EXPECT_GE(observed_backoffs[idx], min_expected) << "Attempt " << attempt;
        EXPECT_LE(observed_backoffs[idx], max_expected) << "Attempt " << attempt;
    }
}

TEST_F(MessagingOutboxRelayTest, PartialInvalidArgumentQuarantinesOnlyPoisonPillWithoutBlockingHealthyEvents) {
    auto repo = std::make_shared<ThreadSafeOutboxRepository>();
    auto client = std::make_shared<RecordingAuditClient>();

    const std::string id_healthy_1 = make_uuid_v7(401);
    const std::string id_poison = make_uuid_v7(402);
    const std::string id_healthy_2 = make_uuid_v7(403);

    repo->enqueue_audit_event(make_record(id_healthy_1, 0));
    repo->enqueue_audit_event(make_record(id_poison, 0));
    repo->enqueue_audit_event(make_record(id_healthy_2, 0));

    client->set_result({false, false, "INVALID_ARGUMENT: malformed event schema", {id_poison}});

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 1;
    cfg.active_poll_interval = std::chrono::milliseconds(2);
    cfg.idle_poll_interval = std::chrono::milliseconds(5);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();

    for (int i = 0; i < 100 && repo->status_of(id_poison) != "QUARANTINED"; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    relay.stop();

    // Only the explicitly rejected poison pill is quarantined; healthy events in the partial batch succeed
    EXPECT_EQ(repo->status_of(id_poison), "QUARANTINED");
    EXPECT_EQ(repo->status_of(id_healthy_1), "PUBLISHED");
    EXPECT_EQ(repo->status_of(id_healthy_2), "PUBLISHED");
    EXPECT_EQ(MessagingAuditMetrics::instance().quarantined_total(AuditQuarantineReason::InvalidArgument), 1U);
    EXPECT_EQ(MessagingAuditMetrics::instance().published_total("message.submitted"), 2U);
}

TEST_F(MessagingOutboxRelayTest, StartAndStopAreIdempotentAndDrainInFlightBatchesGracefully) {
    auto repo = std::make_shared<ThreadSafeOutboxRepository>();
    auto client = std::make_shared<RecordingAuditClient>();
    client->set_dispatch_delay(std::chrono::milliseconds(30));

    const std::string id_inflight = make_uuid_v7(501);
    repo->enqueue_audit_event(make_record(id_inflight, 0));

    OutboxRelayConfig cfg;
    cfg.worker_threads = 2;
    cfg.total_shards = 2;
    cfg.active_poll_interval = std::chrono::milliseconds(2);
    cfg.idle_poll_interval = std::chrono::milliseconds(5);

    MessagingOutboxRelay relay(repo, client, cfg);
    relay.start();
    relay.start();

    for (int i = 0; i < 50 && client->dispatched_ids().empty(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    relay.stop();
    relay.stop();

    EXPECT_EQ(repo->status_of(id_inflight), "PUBLISHED");
}

} // namespace
} // namespace securecloud::messaging::audit
