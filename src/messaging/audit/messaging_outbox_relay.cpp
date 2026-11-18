#include "messaging_outbox_relay.hpp"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>

namespace securecloud::messaging::audit {

namespace {

// Formats a given time_point into the required "YYYY-MM-DD-HH" ScyllaDB bucket partition key.
std::string format_hourly_bucket(std::chrono::system_clock::time_point tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &time_t_val);
#else
    gmtime_r(&time_t_val, &tm_buf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d-%H");
    return oss.str();
}

} // anonymous namespace

MessagingOutboxRelay::MessagingOutboxRelay(
    std::shared_ptr<repository::IMessagingAuditOutboxRepository> repository,
    std::shared_ptr<IMessagingAuditClient> audit_client,
    OutboxRelayConfig config)
    : repository_(std::move(repository)),
      audit_client_(std::move(audit_client)),
      config_(std::move(config)) {}

MessagingOutboxRelay::~MessagingOutboxRelay() {
    stop();
}

void MessagingOutboxRelay::start() {
    bool expected = false;
    if (!is_running_.compare_exchange_strong(expected, true)) {
        return; // Already initialized and running
    }

    workers_.reserve(config_.worker_threads);
    for (uint32_t i = 0; i < config_.worker_threads; ++i) {
        workers_.emplace_back(&MessagingOutboxRelay::worker_loop, this, i);
    }
}

void MessagingOutboxRelay::stop() {
    if (is_running_.exchange(false)) {
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();
    }
}

void MessagingOutboxRelay::worker_loop(uint32_t worker_index) {
    // Distribute shards evenly across workers to prevent contention.
    // Example: 4 workers, 16 shards -> Worker 0 handles shards 0, 4, 8, 12.
    std::vector<int32_t> assigned_shards;
    for (uint32_t shard_id = worker_index; shard_id < config_.total_shards; shard_id += config_.worker_threads) {
        assigned_shards.push_back(shard_id);
    }

    size_t current_shard_idx = 0;

    while (is_running_.load(std::memory_order_relaxed)) {
        int32_t shard_id = assigned_shards[current_shard_idx];
        bool processed_any = false;

        // Fetching both current and previous hour to ensure boundary events are completely drained
        const std::string current_bucket = get_current_hourly_bucket();
        const std::string previous_bucket = get_previous_hourly_bucket();

        processed_any |= process_shard(previous_bucket, shard_id);
        processed_any |= process_shard(current_bucket, shard_id);

        current_shard_idx = (current_shard_idx + 1) % assigned_shards.size();

        // Apply dynamic polling backoff based on shard activity
        if (!processed_any) {
            std::this_thread::sleep_for(config_.idle_poll_interval);
        } else {
            std::this_thread::sleep_for(config_.active_poll_interval);
        }
    }
}

bool MessagingOutboxRelay::process_shard(const std::string& bucket, int32_t shard_id) {
    if (!is_running_.load(std::memory_order_relaxed)) {
        return false;
    }

    auto records = repository_->fetch_pending_events(
        bucket, shard_id, config_.batch_size, config_.lease_duration);

    if (records.empty()) {
        return false; // Shard is currently empty
    }

    std::vector<securecloud::audit::v1::AuditEventProto> batch;
    batch.reserve(records.size());

    // 1. Serialization & Local Validation Phase
    for (const auto& record : records) {
        securecloud::audit::v1::AuditEventProto event;
        if (event.ParseFromArray(record.payload_proto_bin.data(), static_cast<int>(record.payload_proto_bin.size()))) {
            batch.push_back(std::move(event));
        } else {
            // Immediate quarantine: Cannot deserialize local persistent payload
            repository_->record_failure(bucket, shard_id, record.created_at, record.event_id,
                                        "Serialization failure: Local Poison Pill", true);
        }
    }

    if (batch.empty()) {
        return true;
    }

    // 2. Network Dispatch Phase
    auto result = audit_client_->send_batch(batch);

    // 3. Acknowledgement & Quarantine Engine
    if (result.success && result.rejected_event_ids.empty()) {
        // Happy Path: Batch fully acknowledged by Audit Ingestion Service
        for (const auto& record : records) {
            repository_->mark_published(bucket, shard_id, record.created_at, record.event_id);
        }
    } else {
        // Resilience Path: Handle partial rejections and transient backoffs
        for (const auto& record : records) {
            bool is_explicitly_rejected = std::find(
                result.rejected_event_ids.begin(),
                result.rejected_event_ids.end(),
                record.event_id) != result.rejected_event_ids.end();

            if (is_explicitly_rejected || (!result.is_transient_error && !result.success)) {
                // Fatal API Rejection (e.g., INVALID_ARGUMENT) -> Strict Quarantine
                repository_->record_failure(bucket, shard_id, record.created_at, record.event_id,
                                            "Permanent rejection: " + result.error_message, true);
            } else if (result.is_transient_error) {
                // Transient Network / Capacity Exhaustion -> Exponential Backoff
                const int32_t current_attempt = record.attempt_count + 1;
                const bool should_quarantine = (current_attempt >= config_.max_retries);

                if (should_quarantine) {
                    repository_->record_failure(bucket, shard_id, record.created_at, record.event_id,
                                                "Quarantined: Max retries exhausted", true);
                } else {
                    auto backoff_ms = calculate_backoff_with_jitter(current_attempt);
                    repository_->record_failure(bucket, shard_id, record.created_at, record.event_id,
                                                "Transient failure: " + result.error_message, false);

                    // Throttle the local worker slightly to prevent slamming the gRPC endpoint
                    std::this_thread::sleep_for(std::chrono::milliseconds(std::min(backoff_ms.count(), 100LL)));
                }
            }
        }
    }

    return true; // We processed items, keep polling active
}

std::string MessagingOutboxRelay::get_current_hourly_bucket() const {
    return format_hourly_bucket(std::chrono::system_clock::now());
}

std::string MessagingOutboxRelay::get_previous_hourly_bucket() const {
    return format_hourly_bucket(std::chrono::system_clock::now() - std::chrono::hours(1));
}

std::chrono::milliseconds MessagingOutboxRelay::calculate_backoff_with_jitter(int32_t attempt_count) const {
    constexpr double base_ms = 100.0;
    constexpr double max_ms = 10000.0;

    // Exponential calculation: min(max_ms, base_ms * 2^attempt)
    double backoff = std::min(max_ms, base_ms * std::pow(2.0, static_cast<double>(attempt_count)));

    // Full Jitter formulation: random value between [0.8 * backoff, 1.2 * backoff]
    thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_real_distribution<double> distribution(0.8, 1.2);

    double jittered_backoff = backoff * distribution(generator);
    return std::chrono::milliseconds(static_cast<long long>(jittered_backoff));
}

} // namespace securecloud::messaging::audit
