#pragma once

#include <atomic>
#include <cstdint>

namespace securecloud::audit::ingestion {

/// Thread-safe operational and security telemetry counters for audit deduplication and persistence.
struct DeduplicationMetrics {
    std::atomic<uint64_t> audit_events_persisted_new_total{0};
    std::atomic<uint64_t> audit_dedup_hits_committed_total{0};
    std::atomic<uint64_t> audit_dedup_hits_inflight_coalesced_total{0};
    std::atomic<uint64_t> audit_dedup_payload_conflicts_total{0};
    std::atomic<uint64_t> audit_dedup_cache_evictions_ttl_total{0};
    std::atomic<uint64_t> audit_dedup_cache_evictions_lru_total{0};
    std::atomic<uint64_t> audit_dedup_inflight_rollbacks_total{0};
    std::atomic<uint64_t> audit_persistence_ambiguous_outcomes_total{0};

    static DeduplicationMetrics& instance() noexcept {
        static DeduplicationMetrics metrics;
        return metrics;
    }

    void reset() noexcept {
        audit_events_persisted_new_total.store(0, std::memory_order_relaxed);
        audit_dedup_hits_committed_total.store(0, std::memory_order_relaxed);
        audit_dedup_hits_inflight_coalesced_total.store(0, std::memory_order_relaxed);
        audit_dedup_payload_conflicts_total.store(0, std::memory_order_relaxed);
        audit_dedup_cache_evictions_ttl_total.store(0, std::memory_order_relaxed);
        audit_dedup_cache_evictions_lru_total.store(0, std::memory_order_relaxed);
        audit_dedup_inflight_rollbacks_total.store(0, std::memory_order_relaxed);
        audit_persistence_ambiguous_outcomes_total.store(0, std::memory_order_relaxed);
    }
};

} // namespace securecloud::audit::ingestion