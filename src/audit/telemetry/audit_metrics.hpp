#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::audit::telemetry {

enum class RpcType : uint8_t { SubmitAuditEvent = 0, BatchSubmitAuditEvents, Count };

enum class RequestStatus : uint8_t { Success = 0, Error, Rejected, Count };

enum class ProducerLabel : uint8_t { Gateway = 0, Auth, Messaging, Files, Audit, Unknown, Count };

enum class SeverityLabel : uint8_t { Info = 0, Warning, Security, Critical, Count };

enum class RejectionReason : uint8_t {
    Unauthenticated = 0,
    ProducerMismatch,
    SensitiveData,
    ClockSkew,
    MalformedUuid,
    OversizedPayload,
    OversizedBatch,
    QueueSaturated,
    Count
};

enum class FlushTrigger : uint8_t { Count = 0, Timer, Shutdown, CountTriggers };

enum class OperationOutcome : uint8_t { Success = 0, Failure, Timeout, Count };

enum class WorkerPoolLabel : uint8_t { Validation = 0, Insertion, Count };

[[nodiscard]] constexpr std::string_view to_string(RpcType rpc) noexcept {
    switch (rpc) {
    case RpcType::SubmitAuditEvent:
        return "SubmitAuditEvent";
    case RpcType::BatchSubmitAuditEvents:
        return "BatchSubmitAuditEvents";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(RequestStatus status) noexcept {
    switch (status) {
    case RequestStatus::Success:
        return "success";
    case RequestStatus::Error:
        return "error";
    case RequestStatus::Rejected:
        return "rejected";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(ProducerLabel producer) noexcept {
    switch (producer) {
    case ProducerLabel::Gateway:
        return "gateway";
    case ProducerLabel::Auth:
        return "auth";
    case ProducerLabel::Messaging:
        return "messaging";
    case ProducerLabel::Files:
        return "files";
    case ProducerLabel::Audit:
        return "audit";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(SeverityLabel severity) noexcept {
    switch (severity) {
    case SeverityLabel::Info:
        return "info";
    case SeverityLabel::Warning:
        return "warning";
    case SeverityLabel::Security:
        return "security";
    case SeverityLabel::Critical:
        return "critical";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(RejectionReason reason) noexcept {
    switch (reason) {
    case RejectionReason::Unauthenticated:
        return "unauthenticated";
    case RejectionReason::ProducerMismatch:
        return "producer_mismatch";
    case RejectionReason::SensitiveData:
        return "sensitive_data";
    case RejectionReason::ClockSkew:
        return "clock_skew";
    case RejectionReason::MalformedUuid:
        return "malformed_uuid";
    case RejectionReason::OversizedPayload:
        return "oversized_payload";
    case RejectionReason::OversizedBatch:
        return "oversized_batch";
    case RejectionReason::QueueSaturated:
        return "queue_saturated";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(FlushTrigger trigger) noexcept {
    switch (trigger) {
    case FlushTrigger::Count:
        return "count";
    case FlushTrigger::Timer:
        return "timer";
    case FlushTrigger::Shutdown:
        return "shutdown";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(OperationOutcome outcome) noexcept {
    switch (outcome) {
    case OperationOutcome::Success:
        return "success";
    case OperationOutcome::Failure:
        return "failure";
    case OperationOutcome::Timeout:
        return "timeout";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(WorkerPoolLabel pool) noexcept {
    switch (pool) {
    case WorkerPoolLabel::Validation:
        return "validation";
    case WorkerPoolLabel::Insertion:
        return "insertion";
    default:
        return "unknown";
    }
}

struct LatencyHistogram {
    static constexpr std::array<double, 11> k_buckets{0.001, 0.005, 0.010, 0.025, 0.050, 0.100,
                                                      0.250, 0.500, 1.0,   2.5,   5.0};
    std::array<std::atomic<uint64_t>, 12> bucket_counts{};
    std::atomic<uint64_t> count{0};
    std::atomic<double> sum{0.0};

    void observe(double value_seconds) noexcept {
        count.fetch_add(1, std::memory_order_relaxed);

        double current_sum = sum.load(std::memory_order_relaxed);
        while (!sum.compare_exchange_weak(current_sum, current_sum + value_seconds, std::memory_order_relaxed)) {
        }

        size_t idx = k_buckets.size();
        for (size_t i = 0; i < k_buckets.size(); ++i) {
            if (value_seconds <= k_buckets[i]) {
                idx = i;
                break;
            }
        }
        bucket_counts[idx].fetch_add(1, std::memory_order_relaxed);
    }

    void reset() noexcept {
        count.store(0, std::memory_order_relaxed);
        sum.store(0.0, std::memory_order_relaxed);
        for (auto& b : bucket_counts) {
            b.store(0, std::memory_order_relaxed);
        }
    }
};

struct BatchSizeHistogram {
    static constexpr std::array<uint64_t, 8> k_buckets{1, 10, 50, 100, 250, 500, 750, 1000};
    std::array<std::atomic<uint64_t>, 9> bucket_counts{};
    std::atomic<uint64_t> count{0};
    std::atomic<uint64_t> sum{0};

    void observe(uint64_t batch_size) noexcept {
        count.fetch_add(1, std::memory_order_relaxed);
        sum.fetch_add(batch_size, std::memory_order_relaxed);

        size_t idx = k_buckets.size();
        for (size_t i = 0; i < k_buckets.size(); ++i) {
            if (batch_size <= k_buckets[i]) {
                idx = i;
                break;
            }
        }
        bucket_counts[idx].fetch_add(1, std::memory_order_relaxed);
    }

    void reset() noexcept {
        count.store(0, std::memory_order_relaxed);
        sum.store(0, std::memory_order_relaxed);
        for (auto& b : bucket_counts) {
            b.store(0, std::memory_order_relaxed);
        }
    }
};

/// High-performance, lock-free operational metrics collector for Audit Service.
class AuditMetrics {
  public:
    AuditMetrics() noexcept = default;
    ~AuditMetrics() = default;

    AuditMetrics(const AuditMetrics&) = delete;
    AuditMetrics& operator=(const AuditMetrics&) = delete;

    [[nodiscard]] static AuditMetrics& instance() noexcept;

    // --- Metric Recording Operations (Lock-Free, Memory Order Relaxed) ---

    void record_ingestion_request(RpcType rpc, RequestStatus status, uint64_t count = 1) noexcept;
    void record_ingested_event(ProducerLabel producer, SeverityLabel severity, uint64_t count = 1) noexcept;
    void record_rejected_event(RejectionReason reason, uint64_t count = 1) noexcept;
    void record_duplicate_event(ProducerLabel producer, uint64_t count = 1) noexcept;
    void record_persisted_events(ProducerLabel producer, uint64_t count) noexcept;
    void record_persisted_batch(OperationOutcome outcome) noexcept;

    void set_queue_depth(int64_t depth) noexcept;
    void set_queue_capacity(int64_t capacity) noexcept;
    void record_queue_saturated_drop(ProducerLabel producer, uint64_t count = 1) noexcept;
    void observe_queue_wait_duration(double seconds) noexcept;

    void record_batch_flush(FlushTrigger trigger) noexcept;
    void observe_batch_size(uint64_t size) noexcept;

    void set_active_workers(WorkerPoolLabel pool, int64_t count) noexcept;
    void set_service_draining(bool draining) noexcept;

    void observe_clickhouse_insert_duration(double seconds) noexcept;
    void record_clickhouse_insert_operation(OperationOutcome outcome) noexcept;
    void record_clickhouse_retry(uint64_t count = 1) noexcept;
    void record_clickhouse_bulkhead_rejection(uint64_t count = 1) noexcept;
    void set_clickhouse_available(bool available) noexcept;

    /// Renders current metrics state in standard OpenMetrics / Prometheus text exposition format.
    [[nodiscard]] std::string to_prometheus_text() const;

    /// Resets all counters, gauges, and histogram buckets to zero (for test isolation).
    void reset() noexcept;

  private:
    // Counters
    std::array<std::array<std::atomic<uint64_t>, static_cast<size_t>(RequestStatus::Count)>,
               static_cast<size_t>(RpcType::Count)>
        ingestion_requests_total_{};

    std::array<std::array<std::atomic<uint64_t>, static_cast<size_t>(SeverityLabel::Count)>,
               static_cast<size_t>(ProducerLabel::Count)>
        ingested_events_total_{};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(RejectionReason::Count)> rejected_events_total_{};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(ProducerLabel::Count)> duplicate_events_total_{};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(ProducerLabel::Count)> persisted_events_total_{};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(OperationOutcome::Count)> persisted_batches_total_{};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(ProducerLabel::Count)> queue_saturated_drops_total_{};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(FlushTrigger::CountTriggers)> batch_flush_total_{};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(OperationOutcome::Count)>
        clickhouse_insert_operations_total_{};

    std::atomic<uint64_t> clickhouse_retries_total_{0};
    std::atomic<uint64_t> clickhouse_bulkhead_rejections_total_{0};

    // Gauges
    std::atomic<int64_t> queue_depth_{0};
    std::atomic<int64_t> queue_capacity_{0};
    std::array<std::atomic<int64_t>, static_cast<size_t>(WorkerPoolLabel::Count)> workers_active_{};
    std::atomic<int64_t> service_draining_{0};
    std::atomic<int64_t> clickhouse_available_{1};

    // Histograms
    LatencyHistogram queue_wait_duration_seconds_{};
    BatchSizeHistogram batch_size_events_{};
    LatencyHistogram clickhouse_insert_duration_seconds_{};
};

} // namespace securecloud::audit::telemetry
