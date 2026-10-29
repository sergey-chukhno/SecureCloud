#include "ingestion/deduplication_metrics.hpp"
#include "repository/audit_event_repository_interface.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::testing {

TEST(DeduplicationMetricsTest, CounterAtomicIncrementsAndReset) {
    auto& metrics = ingestion::DeduplicationMetrics::instance();
    metrics.reset();

    metrics.audit_events_persisted_new_total.fetch_add(5, std::memory_order_relaxed);
    metrics.audit_dedup_hits_committed_total.fetch_add(2, std::memory_order_relaxed);
    metrics.audit_dedup_payload_conflicts_total.fetch_add(1, std::memory_order_relaxed);

    EXPECT_EQ(metrics.audit_events_persisted_new_total.load(), 5u);
    EXPECT_EQ(metrics.audit_dedup_hits_committed_total.load(), 2u);
    EXPECT_EQ(metrics.audit_dedup_payload_conflicts_total.load(), 1u);

    metrics.reset();
    EXPECT_EQ(metrics.audit_events_persisted_new_total.load(), 0u);
}

} // namespace securecloud::audit::testing