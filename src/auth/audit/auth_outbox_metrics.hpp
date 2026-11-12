#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::auth::audit {

enum class StagingCategory : uint8_t {
    Transactional = 0, // Category A: enlisted in business PostgreSQL tx
    Autonomous,        // Category B: standalone outbox tx
    Count
};

enum class BatchOutcome : uint8_t {
    Success = 0, // Full batch accepted by AuditIngestionService
    Retryable,   // Transient RPC/network failure; retained in PENDING
    Rejected,    // Partial or full permanent rejection / quarantine
    Count
};

enum class QuarantineReason : uint8_t {
    MalformedPayload = 0, // Invalid JSON structure in payload_json
    SchemaValidation,     // Violated AUDIT-002 / AuthAuditMapper invariants
    RemoteRejected,       // Permanently rejected by AuditIngestionService
    Count
};

[[nodiscard]] constexpr std::string_view to_string(StagingCategory category) noexcept {
    switch (category) {
    case StagingCategory::Transactional:
        return "transactional";
    case StagingCategory::Autonomous:
        return "autonomous";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(BatchOutcome outcome) noexcept {
    switch (outcome) {
    case BatchOutcome::Success:
        return "success";
    case BatchOutcome::Retryable:
        return "retryable";
    case BatchOutcome::Rejected:
        return "rejected";
    default:
        return "unknown";
    }
}

[[nodiscard]] constexpr std::string_view to_string(QuarantineReason reason) noexcept {
    switch (reason) {
    case QuarantineReason::MalformedPayload:
        return "malformed_payload";
    case QuarantineReason::SchemaValidation:
        return "schema_validation";
    case QuarantineReason::RemoteRejected:
        return "remote_rejected";
    default:
        return "unknown";
    }
}

/// Lock-free, zero-allocation operational metrics collector for the Auth Transactional Outbox (AUDIT-013-T06).
/// Adheres to AUDIT-011 conventions: fixed bounded label cardinality, relaxed atomic increments,
/// and OpenMetrics / Prometheus text exposition format.
class AuthOutboxMetrics {
  public:
    AuthOutboxMetrics() noexcept = default;
    ~AuthOutboxMetrics() = default;

    AuthOutboxMetrics(const AuthOutboxMetrics&) = delete;
    AuthOutboxMetrics& operator=(const AuthOutboxMetrics&) = delete;

    [[nodiscard]] static AuthOutboxMetrics& instance() noexcept;

    // --- Lock-Free Recording API (Zero Heap Allocation, Memory Order Relaxed) ---

    void record_event_staged(StagingCategory category, uint64_t count = 1) noexcept;
    void record_events_delivered(uint64_t count) noexcept;
    void record_delivery_batch(BatchOutcome outcome, uint64_t count = 1) noexcept;
    void record_retry(uint64_t count = 1) noexcept;
    void record_quarantined(QuarantineReason reason, uint64_t count = 1) noexcept;
    void record_purged(uint64_t count) noexcept;

    void set_pending_events(int64_t count) noexcept;
    void increment_pending_events(int64_t delta = 1) noexcept;
    void decrement_pending_events(int64_t delta = 1) noexcept;
    void set_oldest_pending_age_seconds(double age_seconds) noexcept;

    // --- Atomic Snapshot Readers ---

    [[nodiscard]] int64_t pending_events() const noexcept;
    [[nodiscard]] uint64_t events_staged_total(StagingCategory category) const noexcept;
    [[nodiscard]] uint64_t events_delivered_total() const noexcept;
    [[nodiscard]] uint64_t delivery_batches_total(BatchOutcome outcome) const noexcept;
    [[nodiscard]] uint64_t retries_total() const noexcept;
    [[nodiscard]] uint64_t quarantined_total(QuarantineReason reason) const noexcept;
    [[nodiscard]] uint64_t purged_total() const noexcept;
    [[nodiscard]] double oldest_pending_age_seconds() const noexcept;

    /// Renders all metrics in standard Prometheus / OpenMetrics text exposition format.
    [[nodiscard]] std::string to_prometheus_text() const;

    /// Resets all counters and gauges to zero (for deterministic unit test isolation).
    void reset() noexcept;

  private:
    std::atomic<int64_t> pending_events_{0};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(StagingCategory::Count)> events_staged_total_{};
    std::atomic<uint64_t> events_delivered_total_{0};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(BatchOutcome::Count)> delivery_batches_total_{};
    std::atomic<uint64_t> retries_total_{0};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(QuarantineReason::Count)> quarantined_total_{};
    std::atomic<uint64_t> purged_total_{0};
    std::atomic<double> oldest_pending_age_seconds_{0.0};
};

} // namespace securecloud::auth::audit
