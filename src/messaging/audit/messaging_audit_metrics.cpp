#include "audit/messaging_audit_metrics.hpp"

#include <sstream>

namespace securecloud::messaging::audit {

namespace {

constexpr std::array<std::string_view, 9> kEventTypeLabels = {
    "message.submitted",
    "message.delivered",
    "message.read",
    "conversation.created",
    "conversation.closed",
    "conversation.participant_added",
    "conversation.participant_removed",
    "security.authorization.denied",
    "other",
};

constexpr std::array<std::string_view, 5> kSeverityLabels = {
    "INFO", "WARNING", "SECURITY", "CRITICAL", "UNSPECIFIED",
};

constexpr std::array<std::string_view, 4> kRetryReasonLabels = {
    "unavailable",
    "deadline_exceeded",
    "resource_exhausted",
    "internal_error",
};

constexpr std::array<std::string_view, 4> kQuarantineReasonLabels = {
    "invalid_argument",
    "max_retries_exhausted",
    "serialization_failure",
    "other",
};

} // namespace

MessagingAuditMetrics& MessagingAuditMetrics::instance() {
    static MessagingAuditMetrics s_instance;
    return s_instance;
}

void MessagingAuditMetrics::reset() noexcept {
    for (auto& row : staged_) {
        for (auto& cell : row) {
            cell.store(0, std::memory_order_relaxed);
        }
    }
    for (auto& counter : published_) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : retried_) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : quarantined_) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& gauge : shard_backlog_) {
        gauge.store(0, std::memory_order_relaxed);
    }

    latency_count_.store(0, std::memory_order_relaxed);
    latency_sum_.store(0.0, std::memory_order_relaxed);
    lat_bucket_10ms_.store(0, std::memory_order_relaxed);
    lat_bucket_50ms_.store(0, std::memory_order_relaxed);
    lat_bucket_100ms_.store(0, std::memory_order_relaxed);
    lat_bucket_250ms_.store(0, std::memory_order_relaxed);
    lat_bucket_500ms_.store(0, std::memory_order_relaxed);
    lat_bucket_1s_.store(0, std::memory_order_relaxed);
    lat_bucket_5s_.store(0, std::memory_order_relaxed);

    batch_count_.store(0, std::memory_order_relaxed);
    batch_sum_.store(0, std::memory_order_relaxed);
    batch_bucket_1_.store(0, std::memory_order_relaxed);
    batch_bucket_10_.store(0, std::memory_order_relaxed);
    batch_bucket_25_.store(0, std::memory_order_relaxed);
    batch_bucket_50_.store(0, std::memory_order_relaxed);
    batch_bucket_100_.store(0, std::memory_order_relaxed);
}

size_t MessagingAuditMetrics::event_type_index(std::string_view event_type) noexcept {
    for (size_t i = 0; i < kEventTypeLabels.size() - 1; ++i) {
        if (kEventTypeLabels[i] == event_type) {
            return i;
        }
    }
    return kEventTypeLabels.size() - 1; // "other"
}

size_t MessagingAuditMetrics::severity_index(std::string_view severity) noexcept {
    for (size_t i = 0; i < kSeverityLabels.size() - 1; ++i) {
        if (kSeverityLabels[i] == severity) {
            return i;
        }
    }
    return kSeverityLabels.size() - 1; // "UNSPECIFIED"
}

void MessagingAuditMetrics::increment_staged(std::string_view event_type, std::string_view severity,
                                             uint64_t count) noexcept {
    const size_t et_idx = event_type_index(event_type);
    const size_t sev_idx = severity_index(severity);
    staged_[et_idx][sev_idx].fetch_add(count, std::memory_order_relaxed);
}

uint64_t MessagingAuditMetrics::staged_total(std::string_view event_type, std::string_view severity) const noexcept {
    const size_t et_idx = event_type_index(event_type);
    const size_t sev_idx = severity_index(severity);
    return staged_[et_idx][sev_idx].load(std::memory_order_relaxed);
}

void MessagingAuditMetrics::increment_published(std::string_view event_type, uint64_t count) noexcept {
    const size_t et_idx = event_type_index(event_type);
    published_[et_idx].fetch_add(count, std::memory_order_relaxed);
}

uint64_t MessagingAuditMetrics::published_total(std::string_view event_type) const noexcept {
    const size_t et_idx = event_type_index(event_type);
    return published_[et_idx].load(std::memory_order_relaxed);
}

void MessagingAuditMetrics::increment_retried(AuditRetryReason reason, uint64_t count) noexcept {
    const auto idx = static_cast<size_t>(reason);
    if (idx < retried_.size()) {
        retried_[idx].fetch_add(count, std::memory_order_relaxed);
    }
}

uint64_t MessagingAuditMetrics::retried_total(AuditRetryReason reason) const noexcept {
    const auto idx = static_cast<size_t>(reason);
    if (idx < retried_.size()) {
        return retried_[idx].load(std::memory_order_relaxed);
    }
    return 0;
}

void MessagingAuditMetrics::increment_quarantined(AuditQuarantineReason reason, uint64_t count) noexcept {
    const auto idx = static_cast<size_t>(reason);
    if (idx < quarantined_.size()) {
        quarantined_[idx].fetch_add(count, std::memory_order_relaxed);
    }
}

uint64_t MessagingAuditMetrics::quarantined_total(AuditQuarantineReason reason) const noexcept {
    const auto idx = static_cast<size_t>(reason);
    if (idx < quarantined_.size()) {
        return quarantined_[idx].load(std::memory_order_relaxed);
    }
    return 0;
}

void MessagingAuditMetrics::set_shard_backlog(int32_t shard_id, int64_t pending_count) noexcept {
    if (shard_id >= 0 && static_cast<size_t>(shard_id) < kNumShards) {
        shard_backlog_[static_cast<size_t>(shard_id)].store(pending_count, std::memory_order_relaxed);
    }
}

int64_t MessagingAuditMetrics::shard_backlog(int32_t shard_id) const noexcept {
    if (shard_id >= 0 && static_cast<size_t>(shard_id) < kNumShards) {
        return shard_backlog_[static_cast<size_t>(shard_id)].load(std::memory_order_relaxed);
    }
    return 0;
}

int64_t MessagingAuditMetrics::total_backlog() const noexcept {
    int64_t sum = 0;
    for (const auto& gauge : shard_backlog_) {
        sum += gauge.load(std::memory_order_relaxed);
    }
    return sum;
}

void MessagingAuditMetrics::record_delivery_latency(double seconds) noexcept {
    latency_count_.fetch_add(1, std::memory_order_relaxed);

    double current = latency_sum_.load(std::memory_order_relaxed);
    while (!latency_sum_.compare_exchange_weak(current, current + seconds, std::memory_order_relaxed)) {
    }

    if (seconds <= 0.010) {
        lat_bucket_10ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.050) {
        lat_bucket_50ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.100) {
        lat_bucket_100ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.250) {
        lat_bucket_250ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.500) {
        lat_bucket_500ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 1.000) {
        lat_bucket_1s_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 5.000) {
        lat_bucket_5s_.fetch_add(1, std::memory_order_relaxed);
    }
}

uint64_t MessagingAuditMetrics::delivery_latency_count() const noexcept {
    return latency_count_.load(std::memory_order_relaxed);
}

double MessagingAuditMetrics::delivery_latency_sum() const noexcept {
    return latency_sum_.load(std::memory_order_relaxed);
}

void MessagingAuditMetrics::record_batch_size(size_t batch_size) noexcept {
    batch_count_.fetch_add(1, std::memory_order_relaxed);
    batch_sum_.fetch_add(static_cast<uint64_t>(batch_size), std::memory_order_relaxed);

    if (batch_size <= 1) {
        batch_bucket_1_.fetch_add(1, std::memory_order_relaxed);
    }
    if (batch_size <= 10) {
        batch_bucket_10_.fetch_add(1, std::memory_order_relaxed);
    }
    if (batch_size <= 25) {
        batch_bucket_25_.fetch_add(1, std::memory_order_relaxed);
    }
    if (batch_size <= 50) {
        batch_bucket_50_.fetch_add(1, std::memory_order_relaxed);
    }
    if (batch_size <= 100) {
        batch_bucket_100_.fetch_add(1, std::memory_order_relaxed);
    }
}

uint64_t MessagingAuditMetrics::batch_size_count() const noexcept {
    return batch_count_.load(std::memory_order_relaxed);
}

uint64_t MessagingAuditMetrics::batch_size_sum() const noexcept {
    return batch_sum_.load(std::memory_order_relaxed);
}

std::string MessagingAuditMetrics::to_prometheus_text() const {
    std::ostringstream ss;

    // 1. messaging_audit_events_staged_total
    ss << "# HELP messaging_audit_events_staged_total Monotonic count of audit events staged in ScyllaDB outbox.\n";
    ss << "# TYPE messaging_audit_events_staged_total counter\n";
    for (size_t i = 0; i < kNumEventTypes; ++i) {
        for (size_t j = 0; j < kNumSeverities; ++j) {
            const uint64_t val = staged_[i][j].load(std::memory_order_relaxed);
            if (val > 0 || (i == 0 && j == 0)) {
                ss << "messaging_audit_events_staged_total{event_type=\"" << kEventTypeLabels[i] << "\",severity=\""
                   << kSeverityLabels[j] << "\"} " << val << "\n";
            }
        }
    }

    // 2. messaging_audit_events_published_total
    ss << "# HELP messaging_audit_events_published_total Monotonic count of audit events acknowledged by Audit "
          "Service.\n";
    ss << "# TYPE messaging_audit_events_published_total counter\n";
    for (size_t i = 0; i < kNumEventTypes; ++i) {
        const uint64_t val = published_[i].load(std::memory_order_relaxed);
        if (val > 0 || i == 0) {
            ss << "messaging_audit_events_published_total{event_type=\"" << kEventTypeLabels[i] << "\"} " << val
               << "\n";
        }
    }

    // 3. messaging_audit_events_retried_total
    ss << "# HELP messaging_audit_events_retried_total Monotonic count of transient audit dispatch retries.\n";
    ss << "# TYPE messaging_audit_events_retried_total counter\n";
    for (size_t i = 0; i < retried_.size(); ++i) {
        ss << "messaging_audit_events_retried_total{reason=\"" << kRetryReasonLabels[i] << "\"} "
           << retried_[i].load(std::memory_order_relaxed) << "\n";
    }

    // 4. messaging_audit_events_quarantined_total
    ss << "# HELP messaging_audit_events_quarantined_total Monotonic count of poison-pill audit events quarantined.\n";
    ss << "# TYPE messaging_audit_events_quarantined_total counter\n";
    for (size_t i = 0; i < quarantined_.size(); ++i) {
        ss << "messaging_audit_events_quarantined_total{reason=\"" << kQuarantineReasonLabels[i] << "\"} "
           << quarantined_[i].load(std::memory_order_relaxed) << "\n";
    }

    // 5. messaging_audit_outbox_backlog_gauge
    ss << "# HELP messaging_audit_outbox_backlog_gauge Current number of pending outbox events per shard.\n";
    ss << "# TYPE messaging_audit_outbox_backlog_gauge gauge\n";
    for (size_t shard = 0; shard < kNumShards; ++shard) {
        ss << "messaging_audit_outbox_backlog_gauge{shard_id=\"" << shard << "\"} "
           << shard_backlog_[shard].load(std::memory_order_relaxed) << "\n";
    }

    // 6. messaging_audit_delivery_latency_seconds
    ss << "# HELP messaging_audit_delivery_latency_seconds End-to-end latency from event creation to gRPC ACK.\n";
    ss << "# TYPE messaging_audit_delivery_latency_seconds histogram\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"0.01\"} "
       << lat_bucket_10ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"0.05\"} "
       << lat_bucket_50ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"0.1\"} "
       << lat_bucket_100ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"0.25\"} "
       << lat_bucket_250ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"0.5\"} "
       << lat_bucket_500ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"1.0\"} "
       << lat_bucket_1s_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"5.0\"} "
       << lat_bucket_5s_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_bucket{le=\"+Inf\"} "
       << latency_count_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_sum " << latency_sum_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_delivery_latency_seconds_count " << latency_count_.load(std::memory_order_relaxed) << "\n";

    // 7. messaging_audit_batch_size
    ss << "# HELP messaging_audit_batch_size Distribution of dispatched audit event batch sizes.\n";
    ss << "# TYPE messaging_audit_batch_size histogram\n";
    ss << "messaging_audit_batch_size_bucket{le=\"1\"} " << batch_bucket_1_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_batch_size_bucket{le=\"10\"} " << batch_bucket_10_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_batch_size_bucket{le=\"25\"} " << batch_bucket_25_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_batch_size_bucket{le=\"50\"} " << batch_bucket_50_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_batch_size_bucket{le=\"100\"} " << batch_bucket_100_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_batch_size_bucket{le=\"+Inf\"} " << batch_count_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_batch_size_sum " << batch_sum_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_audit_batch_size_count " << batch_count_.load(std::memory_order_relaxed) << "\n";

    return ss.str();
}

} // namespace securecloud::messaging::audit
