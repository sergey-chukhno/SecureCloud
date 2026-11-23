#include "telemetry/audit_metrics.hpp"

#include <sstream>

namespace securecloud::audit::telemetry {

AuditMetrics& AuditMetrics::instance() noexcept {
    static AuditMetrics metrics;
    return metrics;
}

void AuditMetrics::record_ingestion_request(RpcType rpc, RequestStatus status, uint64_t count) noexcept {
    auto r_idx = static_cast<size_t>(rpc);
    auto s_idx = static_cast<size_t>(status);
    if (r_idx < static_cast<size_t>(RpcType::Count) && s_idx < static_cast<size_t>(RequestStatus::Count)) {
        ingestion_requests_total_[r_idx][s_idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuditMetrics::record_ingested_event(ProducerLabel producer, SeverityLabel severity, uint64_t count) noexcept {
    auto p_idx = static_cast<size_t>(producer);
    auto s_idx = static_cast<size_t>(severity);
    if (p_idx < static_cast<size_t>(ProducerLabel::Count) && s_idx < static_cast<size_t>(SeverityLabel::Count)) {
        ingested_events_total_[p_idx][s_idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuditMetrics::record_rejected_event(RejectionReason reason, uint64_t count) noexcept {
    auto r_idx = static_cast<size_t>(reason);
    if (r_idx < static_cast<size_t>(RejectionReason::Count)) {
        rejected_events_total_[r_idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuditMetrics::record_duplicate_event(ProducerLabel producer, uint64_t count) noexcept {
    auto p_idx = static_cast<size_t>(producer);
    if (p_idx < static_cast<size_t>(ProducerLabel::Count)) {
        duplicate_events_total_[p_idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuditMetrics::record_persisted_events(ProducerLabel producer, uint64_t count) noexcept {
    auto p_idx = static_cast<size_t>(producer);
    if (p_idx < static_cast<size_t>(ProducerLabel::Count)) {
        persisted_events_total_[p_idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuditMetrics::record_persisted_batch(OperationOutcome outcome) noexcept {
    auto o_idx = static_cast<size_t>(outcome);
    if (o_idx < static_cast<size_t>(OperationOutcome::Count)) {
        persisted_batches_total_[o_idx].fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditMetrics::set_queue_depth(int64_t depth) noexcept {
    queue_depth_.store(depth, std::memory_order_relaxed);
}

void AuditMetrics::set_queue_capacity(int64_t capacity) noexcept {
    queue_capacity_.store(capacity, std::memory_order_relaxed);
}

void AuditMetrics::record_queue_saturated_drop(ProducerLabel producer, uint64_t count) noexcept {
    auto p_idx = static_cast<size_t>(producer);
    if (p_idx < static_cast<size_t>(ProducerLabel::Count)) {
        queue_saturated_drops_total_[p_idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuditMetrics::observe_queue_wait_duration(double seconds) noexcept {
    queue_wait_duration_seconds_.observe(seconds);
}

void AuditMetrics::record_batch_flush(FlushTrigger trigger) noexcept {
    auto t_idx = static_cast<size_t>(trigger);
    if (t_idx < static_cast<size_t>(FlushTrigger::CountTriggers)) {
        batch_flush_total_[t_idx].fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditMetrics::observe_batch_size(uint64_t size) noexcept {
    batch_size_events_.observe(size);
}

void AuditMetrics::set_active_workers(WorkerPoolLabel pool, int64_t count) noexcept {
    auto p_idx = static_cast<size_t>(pool);
    if (p_idx < static_cast<size_t>(WorkerPoolLabel::Count)) {
        workers_active_[p_idx].store(count, std::memory_order_relaxed);
    }
}

void AuditMetrics::set_service_draining(bool draining) noexcept {
    service_draining_.store(draining ? 1 : 0, std::memory_order_relaxed);
}

void AuditMetrics::observe_clickhouse_insert_duration(double seconds) noexcept {
    clickhouse_insert_duration_seconds_.observe(seconds);
}

void AuditMetrics::record_clickhouse_insert_operation(OperationOutcome outcome) noexcept {
    auto o_idx = static_cast<size_t>(outcome);
    if (o_idx < static_cast<size_t>(OperationOutcome::Count)) {
        clickhouse_insert_operations_total_[o_idx].fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditMetrics::record_clickhouse_retry(uint64_t count) noexcept {
    clickhouse_retries_total_.fetch_add(count, std::memory_order_relaxed);
}

void AuditMetrics::record_clickhouse_bulkhead_rejection(uint64_t count) noexcept {
    clickhouse_bulkhead_rejections_total_.fetch_add(count, std::memory_order_relaxed);
}

void AuditMetrics::set_clickhouse_available(bool available) noexcept {
    clickhouse_available_.store(available ? 1 : 0, std::memory_order_relaxed);
}

void AuditMetrics::reset() noexcept {
    for (auto& row : ingestion_requests_total_) {
        for (auto& cell : row)
            cell.store(0, std::memory_order_relaxed);
    }
    for (auto& row : ingested_events_total_) {
        for (auto& cell : row)
            cell.store(0, std::memory_order_relaxed);
    }
    for (auto& item : rejected_events_total_)
        item.store(0, std::memory_order_relaxed);
    for (auto& item : duplicate_events_total_)
        item.store(0, std::memory_order_relaxed);
    for (auto& item : persisted_events_total_)
        item.store(0, std::memory_order_relaxed);
    for (auto& item : persisted_batches_total_)
        item.store(0, std::memory_order_relaxed);
    for (auto& item : queue_saturated_drops_total_)
        item.store(0, std::memory_order_relaxed);
    for (auto& item : batch_flush_total_)
        item.store(0, std::memory_order_relaxed);
    for (auto& item : clickhouse_insert_operations_total_)
        item.store(0, std::memory_order_relaxed);

    clickhouse_retries_total_.store(0, std::memory_order_relaxed);
    clickhouse_bulkhead_rejections_total_.store(0, std::memory_order_relaxed);

    queue_depth_.store(0, std::memory_order_relaxed);
    queue_capacity_.store(0, std::memory_order_relaxed);
    for (auto& item : workers_active_)
        item.store(0, std::memory_order_relaxed);
    service_draining_.store(0, std::memory_order_relaxed);
    clickhouse_available_.store(1, std::memory_order_relaxed);

    queue_wait_duration_seconds_.reset();
    batch_size_events_.reset();
    clickhouse_insert_duration_seconds_.reset();
}

std::string AuditMetrics::to_prometheus_text() const {
    std::ostringstream ss;

    // 1. audit_ingestion_requests_total
    ss << "# HELP audit_ingestion_requests_total Total number of incoming gRPC ingestion requests\n";
    ss << "# TYPE audit_ingestion_requests_total counter\n";
    for (size_t r = 0; r < static_cast<size_t>(RpcType::Count); ++r) {
        for (size_t s = 0; s < static_cast<size_t>(RequestStatus::Count); ++s) {
            uint64_t val = ingestion_requests_total_[r][s].load(std::memory_order_relaxed);
            ss << "audit_ingestion_requests_total{rpc=\"" << to_string(static_cast<RpcType>(r)) << "\",status=\""
               << to_string(static_cast<RequestStatus>(s)) << "\"} " << val << "\n";
        }
    }

    // 2. audit_ingested_events_total
    ss << "# HELP audit_ingested_events_total Total number of ingested audit events\n";
    ss << "# TYPE audit_ingested_events_total counter\n";
    for (size_t p = 0; p < static_cast<size_t>(ProducerLabel::Count); ++p) {
        for (size_t s = 0; s < static_cast<size_t>(SeverityLabel::Count); ++s) {
            uint64_t val = ingested_events_total_[p][s].load(std::memory_order_relaxed);
            ss << "audit_ingested_events_total{producer=\"" << to_string(static_cast<ProducerLabel>(p))
               << "\",severity=\"" << to_string(static_cast<SeverityLabel>(s)) << "\"} " << val << "\n";
        }
    }

    // 3. audit_rejected_events_total
    ss << "# HELP audit_rejected_events_total Total number of rejected audit events by reason\n";
    ss << "# TYPE audit_rejected_events_total counter\n";
    for (size_t r = 0; r < static_cast<size_t>(RejectionReason::Count); ++r) {
        uint64_t val = rejected_events_total_[r].load(std::memory_order_relaxed);
        ss << "audit_rejected_events_total{reason=\"" << to_string(static_cast<RejectionReason>(r)) << "\"} " << val
           << "\n";
    }

    // 4. audit_duplicate_events_total
    ss << "# HELP audit_duplicate_events_total Total number of duplicate audit events detected\n";
    ss << "# TYPE audit_duplicate_events_total counter\n";
    for (size_t p = 0; p < static_cast<size_t>(ProducerLabel::Count); ++p) {
        uint64_t val = duplicate_events_total_[p].load(std::memory_order_relaxed);
        ss << "audit_duplicate_events_total{producer=\"" << to_string(static_cast<ProducerLabel>(p)) << "\"} " << val
           << "\n";
    }

    // 5. audit_persisted_events_total
    ss << "# HELP audit_persisted_events_total Total number of events persisted to storage\n";
    ss << "# TYPE audit_persisted_events_total counter\n";
    for (size_t p = 0; p < static_cast<size_t>(ProducerLabel::Count); ++p) {
        uint64_t val = persisted_events_total_[p].load(std::memory_order_relaxed);
        ss << "audit_persisted_events_total{producer=\"" << to_string(static_cast<ProducerLabel>(p)) << "\"} " << val
           << "\n";
    }

    // 6. audit_persisted_batches_total
    ss << "# HELP audit_persisted_batches_total Total number of batch persistence operations\n";
    ss << "# TYPE audit_persisted_batches_total counter\n";
    for (size_t o = 0; o < static_cast<size_t>(OperationOutcome::Count); ++o) {
        uint64_t val = persisted_batches_total_[o].load(std::memory_order_relaxed);
        ss << "audit_persisted_batches_total{outcome=\"" << to_string(static_cast<OperationOutcome>(o)) << "\"} " << val
           << "\n";
    }

    // 7. Gauges: queue depth & capacity
    ss << "# HELP audit_queue_depth Current number of events in ingestion queue\n";
    ss << "# TYPE audit_queue_depth gauge\n";
    ss << "audit_queue_depth " << queue_depth_.load(std::memory_order_relaxed) << "\n";

    ss << "# HELP audit_queue_capacity Hard capacity ceiling of ingestion queue\n";
    ss << "# TYPE audit_queue_capacity gauge\n";
    ss << "audit_queue_capacity " << queue_capacity_.load(std::memory_order_relaxed) << "\n";

    // 8. audit_queue_saturated_drops_total
    ss << "# HELP audit_queue_saturated_drops_total Total events dropped due to queue saturation\n";
    ss << "# TYPE audit_queue_saturated_drops_total counter\n";
    for (size_t p = 0; p < static_cast<size_t>(ProducerLabel::Count); ++p) {
        uint64_t val = queue_saturated_drops_total_[p].load(std::memory_order_relaxed);
        ss << "audit_queue_saturated_drops_total{producer=\"" << to_string(static_cast<ProducerLabel>(p)) << "\"} "
           << val << "\n";
    }

    // 9. Latency Histogram: queue_wait_duration_seconds
    ss << "# HELP audit_queue_wait_duration_seconds Time spend by events in queue before batching\n";
    ss << "# TYPE audit_queue_wait_duration_seconds histogram\n";
    uint64_t cumulative_queue = 0;
    for (size_t i = 0; i < LatencyHistogram::k_buckets.size(); ++i) {
        cumulative_queue += queue_wait_duration_seconds_.bucket_counts[i].load(std::memory_order_relaxed);
        ss << "audit_queue_wait_duration_seconds_bucket{le=\"" << LatencyHistogram::k_buckets[i] << "\"} "
           << cumulative_queue << "\n";
    }
    cumulative_queue +=
        queue_wait_duration_seconds_.bucket_counts[LatencyHistogram::k_buckets.size()].load(std::memory_order_relaxed);
    ss << "audit_queue_wait_duration_seconds_bucket{le=\"+Inf\"} " << cumulative_queue << "\n";
    ss << "audit_queue_wait_duration_seconds_sum " << queue_wait_duration_seconds_.sum.load(std::memory_order_relaxed)
       << "\n";
    ss << "audit_queue_wait_duration_seconds_count "
       << queue_wait_duration_seconds_.count.load(std::memory_order_relaxed) << "\n";

    // 10. audit_batch_flush_total
    ss << "# HELP audit_batch_flush_total Total batch flushes by trigger type\n";
    ss << "# TYPE audit_batch_flush_total counter\n";
    for (size_t t = 0; t < static_cast<size_t>(FlushTrigger::CountTriggers); ++t) {
        uint64_t val = batch_flush_total_[t].load(std::memory_order_relaxed);
        ss << "audit_batch_flush_total{trigger=\"" << to_string(static_cast<FlushTrigger>(t)) << "\"} " << val << "\n";
    }

    // 11. Batch Size Histogram: batch_size_events
    ss << "# HELP audit_batch_size_events Distribution of event counts per batch\n";
    ss << "# TYPE audit_batch_size_events histogram\n";
    uint64_t cumulative_batch = 0;
    for (size_t i = 0; i < BatchSizeHistogram::k_buckets.size(); ++i) {
        cumulative_batch += batch_size_events_.bucket_counts[i].load(std::memory_order_relaxed);
        ss << "audit_batch_size_events_bucket{le=\"" << BatchSizeHistogram::k_buckets[i] << "\"} " << cumulative_batch
           << "\n";
    }
    cumulative_batch +=
        batch_size_events_.bucket_counts[BatchSizeHistogram::k_buckets.size()].load(std::memory_order_relaxed);
    ss << "audit_batch_size_events_bucket{le=\"+Inf\"} " << cumulative_batch << "\n";
    ss << "audit_batch_size_events_sum " << batch_size_events_.sum.load(std::memory_order_relaxed) << "\n";
    ss << "audit_batch_size_events_count " << batch_size_events_.count.load(std::memory_order_relaxed) << "\n";

    // 12. audit_workers_active
    ss << "# HELP audit_workers_active Active threads in worker pools\n";
    ss << "# TYPE audit_workers_active gauge\n";
    for (size_t p = 0; p < static_cast<size_t>(WorkerPoolLabel::Count); ++p) {
        int64_t val = workers_active_[p].load(std::memory_order_relaxed);
        ss << "audit_workers_active{pool=\"" << to_string(static_cast<WorkerPoolLabel>(p)) << "\"} " << val << "\n";
    }

    // 13. audit_service_draining
    ss << "# HELP audit_service_draining Binary indicator whether service is draining\n";
    ss << "# TYPE audit_service_draining gauge\n";
    ss << "audit_service_draining " << service_draining_.load(std::memory_order_relaxed) << "\n";

    // 14. Latency Histogram: clickhouse_insert_duration_seconds
    ss << "# HELP audit_clickhouse_insert_duration_seconds End-to-end latency of ClickHouse inserts\n";
    ss << "# TYPE audit_clickhouse_insert_duration_seconds histogram\n";
    uint64_t cumulative_ch = 0;
    for (size_t i = 0; i < LatencyHistogram::k_buckets.size(); ++i) {
        cumulative_ch += clickhouse_insert_duration_seconds_.bucket_counts[i].load(std::memory_order_relaxed);
        ss << "audit_clickhouse_insert_duration_seconds_bucket{le=\"" << LatencyHistogram::k_buckets[i] << "\"} "
           << cumulative_ch << "\n";
    }
    cumulative_ch += clickhouse_insert_duration_seconds_.bucket_counts[LatencyHistogram::k_buckets.size()].load(
        std::memory_order_relaxed);
    ss << "audit_clickhouse_insert_duration_seconds_bucket{le=\"+Inf\"} " << cumulative_ch << "\n";
    ss << "audit_clickhouse_insert_duration_seconds_sum "
       << clickhouse_insert_duration_seconds_.sum.load(std::memory_order_relaxed) << "\n";
    ss << "audit_clickhouse_insert_duration_seconds_count "
       << clickhouse_insert_duration_seconds_.count.load(std::memory_order_relaxed) << "\n";

    // 15. audit_clickhouse_insert_operations_total
    ss << "# HELP audit_clickhouse_insert_operations_total Bulk operations count by outcome\n";
    ss << "# TYPE audit_clickhouse_insert_operations_total counter\n";
    for (size_t o = 0; o < static_cast<size_t>(OperationOutcome::Count); ++o) {
        uint64_t val = clickhouse_insert_operations_total_[o].load(std::memory_order_relaxed);
        ss << "audit_clickhouse_insert_operations_total{outcome=\"" << to_string(static_cast<OperationOutcome>(o))
           << "\"} " << val << "\n";
    }

    // 16. audit_clickhouse_retries_total
    ss << "# HELP audit_clickhouse_retries_total Total insert retry attempts executed\n";
    ss << "# TYPE audit_clickhouse_retries_total counter\n";
    ss << "audit_clickhouse_retries_total " << clickhouse_retries_total_.load(std::memory_order_relaxed) << "\n";

    // 17. audit_clickhouse_bulkhead_rejections_total
    ss << "# HELP audit_clickhouse_bulkhead_rejections_total Total operations rejected by bulkhead\n";
    ss << "# TYPE audit_clickhouse_bulkhead_rejections_total counter\n";
    ss << "audit_clickhouse_bulkhead_rejections_total "
       << clickhouse_bulkhead_rejections_total_.load(std::memory_order_relaxed) << "\n";

    // 18. audit_clickhouse_available
    ss << "# HELP audit_clickhouse_available Reachability status of ClickHouse cluster\n";
    ss << "# TYPE audit_clickhouse_available gauge\n";
    ss << "audit_clickhouse_available " << clickhouse_available_.load(std::memory_order_relaxed) << "\n";

    return ss.str();
}

} // namespace securecloud::audit::telemetry
