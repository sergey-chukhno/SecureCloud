#include "telemetry/audit_metrics.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::telemetry::testing {

class AuditMetricsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        AuditMetrics::instance().reset();
    }
};

TEST_F(AuditMetricsTest, InitialStateIsZero) {
    auto& metrics = AuditMetrics::instance();
    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_ingestion_requests_total{rpc=\"SubmitAuditEvent\",status=\"success\"} 0"), std::string::npos);
    EXPECT_NE(text.find("audit_queue_depth 0"), std::string::npos);
    EXPECT_NE(text.find("audit_clickhouse_available 1"), std::string::npos);
}

TEST_F(AuditMetricsTest, IncrementsCountersAndGaugesCorrectly) {
    auto& metrics = AuditMetrics::instance();

    metrics.record_ingestion_request(RpcType::SubmitAuditEvent, RequestStatus::Success, 10);
    metrics.record_ingested_event(ProducerLabel::Auth, SeverityLabel::Security, 5);
    metrics.record_rejected_event(RejectionReason::SensitiveData, 2);
    metrics.set_queue_depth(120);

    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_ingestion_requests_total{rpc=\"SubmitAuditEvent\",status=\"success\"} 10"), std::string::npos);
    EXPECT_NE(text.find("audit_ingested_events_total{producer=\"auth\",severity=\"security\"} 5"), std::string::npos);
    EXPECT_NE(text.find("audit_rejected_events_total{reason=\"sensitive_data\"} 2"), std::string::npos);
    EXPECT_NE(text.find("audit_queue_depth 120"), std::string::npos);
}

TEST_F(AuditMetricsTest, ObservesHistogramBucketsCorrectly) {
    auto& metrics = AuditMetrics::instance();

    metrics.observe_batch_size(25);
    metrics.observe_batch_size(500);

    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_batch_size_events_count 2"), std::string::npos);
    EXPECT_NE(text.find("audit_batch_size_events_sum 525"), std::string::npos);
}

TEST_F(AuditMetricsTest, ResetClearsAllCountersAndHistograms) {
    auto& metrics = AuditMetrics::instance();

    metrics.record_clickhouse_retry(3);
    metrics.observe_clickhouse_insert_duration(0.125);
    metrics.reset();

    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_clickhouse_retries_total 0"), std::string::npos);
    EXPECT_NE(text.find("audit_clickhouse_insert_duration_seconds_count 0"), std::string::npos);
}

} // namespace securecloud::audit::telemetry::testing
