#include "audit/audit_producer_metrics.hpp"

#include <gtest/gtest.h>

namespace securecloud::gateway::audit {

TEST(AuditProducerMetricsTest, GaugeAndCounterUpdatesReflectInOpenMetricsOutput) {
    AuditProducerMetrics metrics;

    metrics.set_pending_events(true, 42);
    metrics.set_pending_bytes(1024);
    metrics.increment_admitted(true, "durably_queued");
    metrics.increment_events_delivered(10);
    metrics.set_circuit_state(0);

    const std::string text = metrics.to_openmetrics_text();

    EXPECT_NE(text.find("gateway_audit_pending_events{class=\"mandatory\"} 42"), std::string::npos);
    EXPECT_NE(text.find("gateway_audit_pending_bytes 1024"), std::string::npos);
    EXPECT_NE(text.find("gateway_audit_events_admitted_total{class=\"mandatory\",result=\"durably_queued\"} 1"),
              std::string::npos);
    EXPECT_NE(text.find("gateway_audit_events_delivered_total 10"), std::string::npos);
    EXPECT_NE(text.find("gateway_audit_circuit_state 0"), std::string::npos);
    EXPECT_EQ(metrics.health_state(), ProducerHealthState::Healthy);
}

TEST(AuditProducerMetricsTest, HealthDegradesWhenSpoolFullOrCircuitOpen) {
    AuditProducerMetrics metrics;

    metrics.increment_admitted(true, "rejected_spool_full");
    EXPECT_EQ(metrics.health_state(), ProducerHealthState::Degraded);

    metrics.set_circuit_state(2); // Open
    EXPECT_EQ(metrics.health_state(), ProducerHealthState::Unavailable);
}

} // namespace securecloud::gateway::audit
