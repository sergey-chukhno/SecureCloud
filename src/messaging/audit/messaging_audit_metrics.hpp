#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::messaging::audit {

enum class AuditRetryReason {
    Unavailable = 0,
    DeadlineExceeded = 1,
    ResourceExhausted = 2,
    InternalError = 3,
    Count = 4
};

enum class AuditQuarantineReason {
    InvalidArgument = 0,
    MaxRetriesExhausted = 1,
    SerializationFailure = 2,
    Other = 3,
    Count = 4
};

/**
 * @brief Lock-free atomic Prometheus telemetry collector for the Messaging Audit Producer (AUDIT-014-T06).
 *
 * Uses pre-allocated atomic arrays for bounded label cardinalities to guarantee
 * zero lock contention and zero heap allocations on hot write paths.
 */
class MessagingAuditMetrics {
  public:
    static constexpr size_t kNumShards = 16;

    static MessagingAuditMetrics& instance();

    /// Resets all counters, gauges, and histograms to zero (for unit test isolation).
    void reset() noexcept;

    // 1. messaging_audit_events_staged_total{event_type, severity} (Counter)
    void increment_staged(std::string_view event_type, std::string_view severity, uint64_t count = 1) noexcept;
    [[nodiscard]] uint64_t staged_total(std::string_view event_type, std::string_view severity) const noexcept;

    // 2. messaging_audit_events_published_total{event_type} (Counter)
    void increment_published(std::string_view event_type, uint64_t count = 1) noexcept;
    [[nodiscard]] uint64_t published_total(std::string_view event_type) const noexcept;

    // 3. messaging_audit_events_retried_total{reason} (Counter)
    void increment_retried(AuditRetryReason reason, uint64_t count = 1) noexcept;
    [[nodiscard]] uint64_t retried_total(AuditRetryReason reason) const noexcept;

    // 4. messaging_audit_events_quarantined_total{reason} (Counter)
    void increment_quarantined(AuditQuarantineReason reason, uint64_t count = 1) noexcept;
    [[nodiscard]] uint64_t quarantined_total(AuditQuarantineReason reason) const noexcept;

    // 5. messaging_audit_outbox_backlog_gauge{shard_id} (Gauge)
    void set_shard_backlog(int32_t shard_id, int64_t pending_count) noexcept;
    [[nodiscard]] int64_t shard_backlog(int32_t shard_id) const noexcept;
    [[nodiscard]] int64_t total_backlog() const noexcept;

    // 6. messaging_audit_delivery_latency_seconds (Histogram: created_at -> gRPC ACK)
    void record_delivery_latency(double seconds) noexcept;
    [[nodiscard]] uint64_t delivery_latency_count() const noexcept;
    [[nodiscard]] double delivery_latency_sum() const noexcept;

    // 7. messaging_audit_batch_size (Histogram: dispatched batch sizes)
    void record_batch_size(size_t batch_size) noexcept;
    [[nodiscard]] uint64_t batch_size_count() const noexcept;
    [[nodiscard]] uint64_t batch_size_sum() const noexcept;

    /// Formats all collected metrics in OpenMetrics / Prometheus text exposition format.
    [[nodiscard]] std::string to_prometheus_text() const;

  private:
    MessagingAuditMetrics() = default;
    ~MessagingAuditMetrics() = default;

    MessagingAuditMetrics(const MessagingAuditMetrics&) = delete;
    MessagingAuditMetrics& operator=(const MessagingAuditMetrics&) = delete;

    static constexpr size_t kNumEventTypes = 9;
    static constexpr size_t kNumSeverities = 5;

    static size_t event_type_index(std::string_view event_type) noexcept;
    static size_t severity_index(std::string_view severity) noexcept;

    std::array<std::array<std::atomic<uint64_t>, kNumSeverities>, kNumEventTypes> staged_{};
    std::array<std::atomic<uint64_t>, kNumEventTypes> published_{};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(AuditRetryReason::Count)> retried_{};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(AuditQuarantineReason::Count)> quarantined_{};
    std::array<std::atomic<int64_t>, kNumShards> shard_backlog_{};

    // Delivery latency histogram (seconds)
    std::atomic<uint64_t> latency_count_{0};
    std::atomic<double> latency_sum_{0.0};
    std::atomic<uint64_t> lat_bucket_10ms_{0};
    std::atomic<uint64_t> lat_bucket_50ms_{0};
    std::atomic<uint64_t> lat_bucket_100ms_{0};
    std::atomic<uint64_t> lat_bucket_250ms_{0};
    std::atomic<uint64_t> lat_bucket_500ms_{0};
    std::atomic<uint64_t> lat_bucket_1s_{0};
    std::atomic<uint64_t> lat_bucket_5s_{0};

    // Batch size histogram (events per batch, max 100 per AUDIT-005)
    std::atomic<uint64_t> batch_count_{0};
    std::atomic<uint64_t> batch_sum_{0};
    std::atomic<uint64_t> batch_bucket_1_{0};
    std::atomic<uint64_t> batch_bucket_10_{0};
    std::atomic<uint64_t> batch_bucket_25_{0};
    std::atomic<uint64_t> batch_bucket_50_{0};
    std::atomic<uint64_t> batch_bucket_100_{0};
};

} // namespace securecloud::messaging::audit
