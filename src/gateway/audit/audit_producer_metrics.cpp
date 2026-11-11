#include "audit/audit_producer_metrics.hpp"

#include <cmath>
#include <sstream>

namespace securecloud::gateway::audit {

void AuditProducerMetrics::set_pending_events(bool is_mandatory, uint64_t count) noexcept {
    if (is_mandatory) {
        pending_mandatory_.store(count, std::memory_order_relaxed);
    } else {
        pending_best_effort_.store(count, std::memory_order_relaxed);
    }
}

void AuditProducerMetrics::set_pending_bytes(uint64_t bytes) noexcept {
    pending_bytes_.store(bytes, std::memory_order_relaxed);
}

void AuditProducerMetrics::set_oldest_pending_age_seconds(double seconds) noexcept {
    const uint64_t ms = static_cast<uint64_t>(std::max(0.0, seconds) * 1000.0);
    oldest_pending_age_ms_.store(ms, std::memory_order_relaxed);
}

void AuditProducerMetrics::set_spool_unsynced_events(uint64_t count) noexcept {
    spool_unsynced_events_.store(count, std::memory_order_relaxed);
}

void AuditProducerMetrics::set_circuit_state(uint8_t state) noexcept {
    circuit_state_.store(state, std::memory_order_relaxed);
}

void AuditProducerMetrics::increment_admitted([[maybe_unused]] bool is_mandatory, const std::string& result) noexcept {
    if (result == "durably_queued") {
        admitted_mandatory_queued_.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "accepted_pending_sync") {
        admitted_mandatory_pending_.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "accepted_non_durable") {
        admitted_best_effort_buffer_.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "rejected_spool_full" || result == "rejected_full") {
        admitted_rejected_spool_full_.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "rejected_disabled") {
        admitted_rejected_disabled_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditProducerMetrics::increment_batches(const std::string& outcome) noexcept {
    if (outcome == "success") {
        batches_success_.fetch_add(1, std::memory_order_relaxed);
    } else if (outcome == "retryable") {
        batches_retryable_.fetch_add(1, std::memory_order_relaxed);
    } else if (outcome == "terminal") {
        batches_terminal_.fetch_add(1, std::memory_order_relaxed);
    } else if (outcome == "ambiguous") {
        batches_ambiguous_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditProducerMetrics::increment_events_delivered(uint64_t count) noexcept {
    events_delivered_total_.fetch_add(count, std::memory_order_relaxed);
}

void AuditProducerMetrics::increment_retries(const std::string& reason) noexcept {
    if (reason == "timeout") {
        retries_timeout_.fetch_add(1, std::memory_order_relaxed);
    } else if (reason == "server_error") {
        retries_server_error_.fetch_add(1, std::memory_order_relaxed);
    } else {
        retries_network_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditProducerMetrics::increment_quarantined(const std::string& reason) noexcept {
    if (reason == "corrupted") {
        quarantined_corrupted_.fetch_add(1, std::memory_order_relaxed);
    } else {
        quarantined_validation_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditProducerMetrics::increment_events_lost(bool is_mandatory,
                                                 [[maybe_unused]] const std::string& reason) noexcept {
    if (is_mandatory) {
        lost_mandatory_full_.fetch_add(1, std::memory_order_relaxed);
    } else {
        lost_best_effort_evicted_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditProducerMetrics::increment_torn_records() noexcept {
    spool_torn_records_total_.fetch_add(1, std::memory_order_relaxed);
}

ProducerHealthState AuditProducerMetrics::health_state() const noexcept {
    const uint8_t circuit = circuit_state_.load(std::memory_order_relaxed);
    const uint64_t lost_mandatory = lost_mandatory_full_.load(std::memory_order_relaxed);
    const uint64_t rejected_full = admitted_rejected_spool_full_.load(std::memory_order_relaxed);

    if (circuit == 2 || lost_mandatory > 1000) { // Circuit open or heavy loss
        return ProducerHealthState::Unavailable;
    }
    if (circuit == 1 || rejected_full > 0 || lost_mandatory > 0) {
        return ProducerHealthState::Degraded;
    }
    return ProducerHealthState::Healthy;
}

std::string AuditProducerMetrics::to_openmetrics_text() const {
    std::ostringstream ss;

    ss << "# HELP gateway_audit_pending_events Current count of pending audit events in memory or spool.\n"
       << "# TYPE gateway_audit_pending_events gauge\n"
       << "gateway_audit_pending_events{class=\"mandatory\"} " << pending_mandatory_.load(std::memory_order_relaxed)
       << "\n"
       << "gateway_audit_pending_events{class=\"best_effort\"} " << pending_best_effort_.load(std::memory_order_relaxed)
       << "\n\n";

    ss << "# HELP gateway_audit_pending_bytes Total bytes of pending audit events.\n"
       << "# TYPE gateway_audit_pending_bytes gauge\n"
       << "gateway_audit_pending_bytes " << pending_bytes_.load(std::memory_order_relaxed) << "\n\n";

    const double oldest_sec = static_cast<double>(oldest_pending_age_ms_.load(std::memory_order_relaxed)) / 1000.0;
    ss << "# HELP gateway_audit_oldest_pending_age_seconds Age of oldest unacknowledged event.\n"
       << "# TYPE gateway_audit_oldest_pending_age_seconds gauge\n"
       << "gateway_audit_oldest_pending_age_seconds " << oldest_sec << "\n\n";

    ss << "# HELP gateway_audit_events_admitted_total Total audit events presented for admission.\n"
       << "# TYPE gateway_audit_events_admitted_total counter\n"
       << "gateway_audit_events_admitted_total{class=\"mandatory\",result=\"durably_queued\"} "
       << admitted_mandatory_queued_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_events_admitted_total{class=\"mandatory\",result=\"accepted_pending_sync\"} "
       << admitted_mandatory_pending_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_events_admitted_total{class=\"best_effort\",result=\"accepted_non_durable\"} "
       << admitted_best_effort_buffer_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_events_admitted_total{class=\"mandatory\",result=\"rejected_spool_full\"} "
       << admitted_rejected_spool_full_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_events_admitted_total{class=\"mandatory\",result=\"rejected_disabled\"} "
       << admitted_rejected_disabled_.load(std::memory_order_relaxed) << "\n\n";

    ss << "# HELP gateway_audit_delivery_batches_total Total audit delivery batch attempts.\n"
       << "# TYPE gateway_audit_delivery_batches_total counter\n"
       << "gateway_audit_delivery_batches_total{outcome=\"success\"} "
       << batches_success_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_delivery_batches_total{outcome=\"retryable\"} "
       << batches_retryable_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_delivery_batches_total{outcome=\"terminal\"} "
       << batches_terminal_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_delivery_batches_total{outcome=\"ambiguous\"} "
       << batches_ambiguous_.load(std::memory_order_relaxed) << "\n\n";

    ss << "# HELP gateway_audit_events_delivered_total Total audit events acknowledged by upstream Audit Service.\n"
       << "# TYPE gateway_audit_events_delivered_total counter\n"
       << "gateway_audit_events_delivered_total " << events_delivered_total_.load(std::memory_order_relaxed) << "\n\n";

    ss << "# HELP gateway_audit_delivery_retries_total Total delivery retry attempts.\n"
       << "# TYPE gateway_audit_delivery_retries_total counter\n"
       << "gateway_audit_delivery_retries_total{reason=\"network\"} "
       << retries_network_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_delivery_retries_total{reason=\"timeout\"} "
       << retries_timeout_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_delivery_retries_total{reason=\"server_error\"} "
       << retries_server_error_.load(std::memory_order_relaxed) << "\n\n";

    ss << "# HELP gateway_audit_events_quarantined_total Total unrecoverable records quarantined.\n"
       << "# TYPE gateway_audit_events_quarantined_total counter\n"
       << "gateway_audit_events_quarantined_total{reason=\"validation_failed\"} "
       << quarantined_validation_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_events_quarantined_total{reason=\"corrupted\"} "
       << quarantined_corrupted_.load(std::memory_order_relaxed) << "\n\n";

    ss << "# HELP gateway_audit_events_lost_total Total events permanently dropped.\n"
       << "# TYPE gateway_audit_events_lost_total counter\n"
       << "gateway_audit_events_lost_total{class=\"mandatory\",reason=\"spool_full\"} "
       << lost_mandatory_full_.load(std::memory_order_relaxed) << "\n"
       << "gateway_audit_events_lost_total{class=\"best_effort\",reason=\"buffer_evicted\"} "
       << lost_best_effort_evicted_.load(std::memory_order_relaxed) << "\n\n";

    ss << "# HELP gateway_audit_spool_unsynced_events Events written to spool pending fsync.\n"
       << "# TYPE gateway_audit_spool_unsynced_events gauge\n"
       << "gateway_audit_spool_unsynced_events " << spool_unsynced_events_.load(std::memory_order_relaxed) << "\n\n";

    ss << "# HELP gateway_audit_spool_torn_records_total Partial or damaged records encountered during replay.\n"
       << "# TYPE gateway_audit_spool_torn_records_total counter\n"
       << "gateway_audit_spool_torn_records_total " << spool_torn_records_total_.load(std::memory_order_relaxed)
       << "\n\n";

    ss << "# HELP gateway_audit_circuit_state State of delivery circuit breaker (0=Closed, 1=HalfOpen, 2=Open).\n"
       << "# TYPE gateway_audit_circuit_state gauge\n"
       << "gateway_audit_circuit_state " << static_cast<uint32_t>(circuit_state_.load(std::memory_order_relaxed))
       << "\n# EOF\n";

    return ss.str();
}

} // namespace securecloud::gateway::audit
