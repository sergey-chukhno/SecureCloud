#include "messaging_outbox_relay.hpp"

#include "audit/audit_diagnostics.hpp"
#include "audit/messaging_audit_metrics.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <random>
#include <string_view>

namespace securecloud::messaging::audit {

namespace {

std::string to_upper_ascii(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (char ch : input) {
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
    }
    return out;
}

AuditRetryReason classify_retry_reason(std::string_view error_message) {
    const std::string upper = to_upper_ascii(error_message);
    if (upper.find("DEADLINE_EXCEEDED") != std::string::npos) {
        return AuditRetryReason::DeadlineExceeded;
    }
    if (upper.find("RESOURCE_EXHAUSTED") != std::string::npos) {
        return AuditRetryReason::ResourceExhausted;
    }
    if (upper.find("UNAVAILABLE") != std::string::npos) {
        return AuditRetryReason::Unavailable;
    }
    return AuditRetryReason::InternalError;
}

int32_t infer_grpc_status_code(const IMessagingAuditClient::BatchResult& result) {
    if (result.success) {
        return 0; // OK
    }
    const std::string upper = to_upper_ascii(result.error_message);
    if (upper.find("INVALID_ARGUMENT") != std::string::npos) {
        return 3;
    }
    if (upper.find("DEADLINE_EXCEEDED") != std::string::npos) {
        return 4;
    }
    if (upper.find("RESOURCE_EXHAUSTED") != std::string::npos) {
        return 8;
    }
    if (upper.find("UNAVAILABLE") != std::string::npos) {
        return 14;
    }
    return 13; // INTERNAL
}

void record_acknowledged_event(repository::IMessagingAuditOutboxRepository& repository, MessagingAuditMetrics& metrics,
                               const std::string& bucket, int32_t shard_id, const repository::AuditOutboxRecord& record,
                               std::chrono::system_clock::time_point ack_time) {
    repository.mark_published(bucket, shard_id, record.created_at, record.event_id);
    metrics.increment_published(record.event_type);

    if (record.created_at.time_since_epoch().count() > 0 && ack_time >= record.created_at) {
        const double latency_sec = std::chrono::duration<double>(ack_time - record.created_at).count();
        metrics.record_delivery_latency(latency_sec);
    } else {
        metrics.record_delivery_latency(0.0);
    }
}

} // namespace

MessagingOutboxRelay::MessagingOutboxRelay(std::shared_ptr<repository::IMessagingAuditOutboxRepository> repository,
                                           std::shared_ptr<IMessagingAuditClient> audit_client,
                                           OutboxRelayConfig config)
    : repository_(std::move(repository)), audit_client_(std::move(audit_client)), config_(std::move(config)) {}

MessagingOutboxRelay::~MessagingOutboxRelay() {
    stop();
}

void MessagingOutboxRelay::start() {
    bool expected = false;
    if (!is_running_.compare_exchange_strong(expected, true)) {
        return;
    }

    AuditDiagnostics::log_relay_state_change("started", config_.worker_threads, config_.total_shards);

    workers_.reserve(config_.worker_threads);
    for (uint32_t i = 0; i < config_.worker_threads; ++i) {
        workers_.emplace_back(&MessagingOutboxRelay::worker_loop, this, i);
    }
}

void MessagingOutboxRelay::stop() {
    bool was_running = false;
    {
        std::lock_guard<std::mutex> lock(wake_mutex_);
        was_running = is_running_.exchange(false);
    }
    if (!was_running) {
        return;
    }

    AuditDiagnostics::log_relay_state_change("draining", config_.worker_threads, config_.total_shards);
    wake_cv_.notify_all();

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();

    AuditDiagnostics::log_relay_state_change("stopped", config_.worker_threads, config_.total_shards);
}

void MessagingOutboxRelay::interruptible_wait(std::chrono::milliseconds duration) {
    if (duration.count() <= 0 || !is_running_.load(std::memory_order_relaxed)) {
        return;
    }
    std::unique_lock<std::mutex> lock(wake_mutex_);
    wake_cv_.wait_for(lock, duration, [this]() { return !is_running_.load(std::memory_order_relaxed); });
}

void MessagingOutboxRelay::worker_loop(uint32_t worker_index) {
    std::vector<int32_t> assigned_shards;
    for (uint32_t shard_id = worker_index; shard_id < config_.total_shards; shard_id += config_.worker_threads) {
        assigned_shards.push_back(static_cast<int32_t>(shard_id));
    }

    if (assigned_shards.empty()) {
        return;
    }

    size_t current_shard_idx = 0;
    auto& metrics = MessagingAuditMetrics::instance();

    while (is_running_.load(std::memory_order_relaxed)) {
        const int32_t shard_id = assigned_shards[current_shard_idx];
        bool processed_any = false;

        const std::string current_bucket = get_current_hourly_bucket();
        const std::string previous_bucket = get_previous_hourly_bucket();

        processed_any |= process_shard(previous_bucket, shard_id);
        processed_any |= process_shard(current_bucket, shard_id);

        // Refresh per-shard backlog gauge across active + boundary buckets
        const size_t pending_prev = repository_->count_pending_backlog(previous_bucket, shard_id);
        const size_t pending_curr = repository_->count_pending_backlog(current_bucket, shard_id);
        metrics.set_shard_backlog(shard_id, static_cast<int64_t>(pending_prev + pending_curr));

        current_shard_idx = (current_shard_idx + 1) % assigned_shards.size();

        interruptible_wait(processed_any ? config_.active_poll_interval : config_.idle_poll_interval);
    }
}

bool MessagingOutboxRelay::process_shard(const std::string& bucket, int32_t shard_id) {
    if (!is_running_.load(std::memory_order_relaxed)) {
        return false;
    }

    auto records = repository_->fetch_pending_events(bucket, shard_id, config_.batch_size, config_.lease_duration);
    if (records.empty()) {
        return false;
    }

    auto& metrics = MessagingAuditMetrics::instance();

    std::vector<securecloud::audit::v1::AuditEventProto> batch;
    std::vector<const repository::AuditOutboxRecord*> valid_records;
    batch.reserve(records.size());
    valid_records.reserve(records.size());

    // 1. Serialization & Local Validation Phase
    for (const auto& record : records) {
        securecloud::audit::v1::AuditEventProto event;
        const bool parsed_ok =
            !record.payload_proto_bin.empty() &&
            event.ParseFromArray(record.payload_proto_bin.data(), static_cast<int>(record.payload_proto_bin.size())) &&
            domain::is_valid_audit_uuid_v7(event.event_id()) && !event.event_type().empty() &&
            event.producer_service() == securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING;
        if (parsed_ok) {
            batch.push_back(std::move(event));
            valid_records.push_back(&record);
        } else {
            constexpr std::string_view kReason = "Serialization failure: Local Poison Pill";
            repository_->record_failure(bucket, shard_id, record.created_at, record.event_id, std::string(kReason),
                                        true);
            metrics.increment_quarantined(AuditQuarantineReason::SerializationFailure);
            AuditDiagnostics::log_quarantine_event(bucket, shard_id, record.event_id, record.event_type,
                                                   record.attempt_count + 1, kReason);
        }
    }

    if (batch.empty()) {
        return true;
    }

    // 2. Network Dispatch Phase
    metrics.record_batch_size(batch.size());
    const auto result = audit_client_->send_batch(batch);
    const auto ack_time = std::chrono::system_clock::now();

    // 3. Acknowledgement & Quarantine Engine
    if (result.success && result.rejected_event_ids.empty()) {
        for (const auto* record_ptr : valid_records) {
            record_acknowledged_event(*repository_, metrics, bucket, shard_id, *record_ptr, ack_time);
        }
    } else {
        const AuditRetryReason retry_reason = classify_retry_reason(result.error_message);
        const int32_t grpc_code = infer_grpc_status_code(result);
        const bool has_partial_rejections = !result.rejected_event_ids.empty();
        std::chrono::milliseconds batch_backoff{0};

        for (const auto* record_ptr : valid_records) {
            const auto& record = *record_ptr;
            const bool is_explicitly_rejected =
                std::find(result.rejected_event_ids.begin(), result.rejected_event_ids.end(), record.event_id) !=
                result.rejected_event_ids.end();

            if (is_explicitly_rejected || (!has_partial_rejections && !result.is_transient_error && !result.success)) {
                // Fatal rejection (explicit poison pill or entire batch rejected with non-transient error)
                const std::string reason = "Permanent rejection: " + result.error_message;
                repository_->record_failure(bucket, shard_id, record.created_at, record.event_id, reason, true);
                metrics.increment_quarantined(AuditQuarantineReason::InvalidArgument);
                AuditDiagnostics::log_quarantine_event(bucket, shard_id, record.event_id, record.event_type,
                                                       record.attempt_count + 1, reason);
            } else if (has_partial_rejections && !result.is_transient_error) {
                // BatchSubmitAuditEvents accepted the non-rejected records in the batch
                record_acknowledged_event(*repository_, metrics, bucket, shard_id, record, ack_time);
            } else if (result.is_transient_error) {
                const int32_t current_attempt = record.attempt_count + 1;
                const bool should_quarantine = (current_attempt >= config_.max_retries);

                if (should_quarantine) {
                    constexpr std::string_view kReason = "Quarantined: Max retries exhausted";
                    repository_->record_failure(bucket, shard_id, record.created_at, record.event_id,
                                                std::string(kReason), true);
                    metrics.increment_quarantined(AuditQuarantineReason::MaxRetriesExhausted);
                    AuditDiagnostics::log_quarantine_event(bucket, shard_id, record.event_id, record.event_type,
                                                           current_attempt, kReason);
                } else {
                    const auto backoff_ms = calculate_backoff_with_jitter(current_attempt);
                    batch_backoff = std::max(batch_backoff, backoff_ms);
                    repository_->record_failure(bucket, shard_id, record.created_at, record.event_id,
                                                "Transient failure: " + result.error_message, false);
                    metrics.increment_retried(retry_reason);
                }
            }
        }

        if (result.is_transient_error && batch_backoff.count() > 0) {
            AuditDiagnostics::log_connection_failure(bucket, shard_id, batch.size(), grpc_code, result.error_message,
                                                     batch_backoff);
            interruptible_wait(batch_backoff);
        }
    }

    return true;
}

std::string MessagingOutboxRelay::get_current_hourly_bucket() const {
    return domain::compute_outbox_bucket_utc(std::chrono::system_clock::now());
}

std::string MessagingOutboxRelay::get_previous_hourly_bucket() const {
    return domain::compute_outbox_bucket_utc(std::chrono::system_clock::now() - std::chrono::hours(1));
}

std::chrono::milliseconds MessagingOutboxRelay::calculate_backoff_with_jitter(int32_t attempt_count) const {
    const double base_ms = static_cast<double>(std::max<int64_t>(1, config_.base_backoff.count()));
    const double max_ms = static_cast<double>(std::max<int64_t>(1, config_.max_backoff.count()));

    const double backoff = std::min(max_ms, base_ms * std::pow(2.0, static_cast<double>(attempt_count)));

    thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_real_distribution<double> distribution(0.8, 1.2);

    const double jittered_backoff = backoff * distribution(generator);
    return std::chrono::milliseconds(static_cast<long long>(jittered_backoff));
}

} // namespace securecloud::messaging::audit
