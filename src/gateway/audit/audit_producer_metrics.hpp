#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace securecloud::gateway::audit {

/// State of Gateway Audit Producer operational health.
enum class ProducerHealthState : uint8_t {
    Healthy,
    Degraded,
    Unavailable
};

[[nodiscard]] constexpr const char* to_string(ProducerHealthState state) noexcept {
    switch (state) {
    case ProducerHealthState::Healthy:
        return "HEALTHY";
    case ProducerHealthState::Degraded:
        return "DEGRADED";
    case ProducerHealthState::Unavailable:
        return "UNAVAILABLE";
    }
    return "UNAVAILABLE";
}

/**
 * @brief Lock-free metrics collector & OpenMetrics text exporter for Gateway Audit Producer (AUDIT-012-T06).
 *
 * Uses strictly closed label sets (mandatory/best_effort, outcomes, reasons) with zero high-cardinality fields.
 */
class AuditProducerMetrics {
  public:
    AuditProducerMetrics() = default;
    ~AuditProducerMetrics() = default;

    AuditProducerMetrics(const AuditProducerMetrics&) = delete;
    AuditProducerMetrics& operator=(const AuditProducerMetrics&) = delete;

    // --- Gauges ---
    void set_pending_events(bool is_mandatory, uint64_t count) noexcept;
    void set_pending_bytes(uint64_t bytes) noexcept;
    void set_oldest_pending_age_seconds(double seconds) noexcept;
    void set_spool_unsynced_events(uint64_t count) noexcept;
    void set_circuit_state(uint8_t state) noexcept; // 0=Closed, 1=HalfOpen, 2=Open

    // --- Counters ---
    void increment_admitted(bool is_mandatory, const std::string& result) noexcept;
    void increment_batches(const std::string& outcome) noexcept; // success, retryable, terminal, ambiguous
    void increment_events_delivered(uint64_t count = 1) noexcept;
    void increment_retries(const std::string& reason) noexcept;
    void increment_quarantined(const std::string& reason) noexcept;
    void increment_events_lost(bool is_mandatory, const std::string& reason) noexcept;
    void increment_torn_records() noexcept;

    // --- Health Evaluation & Export ---
    [[nodiscard]] ProducerHealthState health_state() const noexcept;
    [[nodiscard]] std::string to_openmetrics_text() const;

  private:
    // Gauges
    std::atomic<uint64_t> pending_mandatory_{0};
    std::atomic<uint64_t> pending_best_effort_{0};
    std::atomic<uint64_t> pending_bytes_{0};
    std::atomic<uint64_t> oldest_pending_age_ms_{0};
    std::atomic<uint64_t> spool_unsynced_events_{0};
    std::atomic<uint8_t> circuit_state_{0};

    // Counters - Admitted
    std::atomic<uint64_t> admitted_mandatory_queued_{0};
    std::atomic<uint64_t> admitted_mandatory_pending_{0};
    std::atomic<uint64_t> admitted_best_effort_buffer_{0};
    std::atomic<uint64_t> admitted_rejected_spool_full_{0};
    std::atomic<uint64_t> admitted_rejected_disabled_{0};

    // Counters - Batches
    std::atomic<uint64_t> batches_success_{0};
    std::atomic<uint64_t> batches_retryable_{0};
    std::atomic<uint64_t> batches_terminal_{0};
    std::atomic<uint64_t> batches_ambiguous_{0};

    // Counters - Events
    std::atomic<uint64_t> events_delivered_total_{0};

    // Counters - Retries
    std::atomic<uint64_t> retries_network_{0};
    std::atomic<uint64_t> retries_timeout_{0};
    std::atomic<uint64_t> retries_server_error_{0};

    // Counters - Quarantined & Lost
    std::atomic<uint64_t> quarantined_validation_{0};
    std::atomic<uint64_t> quarantined_corrupted_{0};
    std::atomic<uint64_t> lost_mandatory_full_{0};
    std::atomic<uint64_t> lost_best_effort_evicted_{0};

    // Counters - Spool
    std::atomic<uint64_t> spool_torn_records_total_{0};
};

} // namespace securecloud::gateway::audit
