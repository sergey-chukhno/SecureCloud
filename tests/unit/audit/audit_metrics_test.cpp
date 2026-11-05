#include "telemetry/audit_diagnostics.hpp"
#include "telemetry/audit_metrics.hpp"

#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <string>

namespace securecloud::audit::telemetry::testing {

class AuditMetricsUnitTest : public ::testing::Test {
  protected:
    void SetUp() override {
        AuditMetrics::instance().reset();
        AuditDiagnostics::instance().reset_rate_limiters();
        AuditDiagnostics::instance().set_service_state(lifecycle::DetailedServiceState::Ready);
    }
};

// Test 1: Counter & Gauge Accuracy
TEST_F(AuditMetricsUnitTest, CounterAndGaugeAccuracy) {
    auto& metrics = AuditMetrics::instance();

    metrics.record_ingestion_request(RpcType::SubmitAuditEvent, RequestStatus::Success, 15);
    metrics.record_ingestion_request(RpcType::BatchSubmitAuditEvents, RequestStatus::Rejected, 3);
    metrics.record_ingested_event(ProducerLabel::Auth, SeverityLabel::Security, 25);
    metrics.record_rejected_event(RejectionReason::ClockSkew, 4);
    metrics.record_duplicate_event(ProducerLabel::Gateway, 2);
    metrics.record_persisted_events(ProducerLabel::Auth, 20);
    metrics.record_persisted_batch(OperationOutcome::Success);

    metrics.set_queue_depth(42);
    metrics.set_queue_capacity(10000);
    metrics.set_active_workers(WorkerPoolLabel::Validation, 8);
    metrics.set_service_draining(true);
    metrics.set_clickhouse_available(false);

    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_ingestion_requests_total{rpc=\"SubmitAuditEvent\",status=\"success\"} 15"),
              std::string::npos);
    EXPECT_NE(text.find("audit_ingestion_requests_total{rpc=\"BatchSubmitAuditEvents\",status=\"rejected\"} 3"),
              std::string::npos);
    EXPECT_NE(text.find("audit_ingested_events_total{producer=\"auth\",severity=\"security\"} 25"), std::string::npos);
    EXPECT_NE(text.find("audit_rejected_events_total{reason=\"clock_skew\"} 4"), std::string::npos);
    EXPECT_NE(text.find("audit_duplicate_events_total{producer=\"gateway\"} 2"), std::string::npos);
    EXPECT_NE(text.find("audit_persisted_events_total{producer=\"auth\"} 20"), std::string::npos);
    EXPECT_NE(text.find("audit_persisted_batches_total{outcome=\"success\"} 1"), std::string::npos);

    EXPECT_NE(text.find("audit_queue_depth 42"), std::string::npos);
    EXPECT_NE(text.find("audit_queue_capacity 10000"), std::string::npos);
    EXPECT_NE(text.find("audit_workers_active{pool=\"validation\"} 8"), std::string::npos);
    EXPECT_NE(text.find("audit_service_draining 1"), std::string::npos);
    EXPECT_NE(text.find("audit_clickhouse_available 0"), std::string::npos);
}

// Test 2: Latency & Batch Size Histogram Bucket Accumulation
TEST_F(AuditMetricsUnitTest, HistogramBucketAccumulation) {
    auto& metrics = AuditMetrics::instance();

    // Latency observations
    metrics.observe_clickhouse_insert_duration(0.002); // falls into le="0.005"
    metrics.observe_clickhouse_insert_duration(0.045); // falls into le="0.050"
    metrics.observe_clickhouse_insert_duration(1.500); // falls into le="2.5"

    // Batch size observations
    metrics.observe_batch_size(5);   // le="10"
    metrics.observe_batch_size(250); // le="250"
    metrics.observe_batch_size(900); // le="1000"

    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_clickhouse_insert_duration_seconds_count 3"), std::string::npos);
    EXPECT_NE(text.find("audit_batch_size_events_count 3"), std::string::npos);
    EXPECT_NE(text.find("audit_batch_size_events_sum 1155"), std::string::npos);
}

// Test 3: OpenMetrics Text Formatting Fidelity
TEST_F(AuditMetricsUnitTest, OpenMetricsTextFormattingFidelity) {
    auto& metrics = AuditMetrics::instance();
    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("# HELP audit_ingestion_requests_total"), std::string::npos);
    EXPECT_NE(text.find("# TYPE audit_ingestion_requests_total counter"), std::string::npos);
    EXPECT_NE(text.find("# HELP audit_queue_depth"), std::string::npos);
    EXPECT_NE(text.find("# TYPE audit_queue_depth gauge"), std::string::npos);
    EXPECT_NE(text.find("# HELP audit_clickhouse_insert_duration_seconds"), std::string::npos);
    EXPECT_NE(text.find("# TYPE audit_clickhouse_insert_duration_seconds histogram"), std::string::npos);
}

// Test 4: Reset Semantics
TEST_F(AuditMetricsUnitTest, ResetSemantics) {
    auto& metrics = AuditMetrics::instance();

    metrics.record_ingestion_request(RpcType::SubmitAuditEvent, RequestStatus::Success, 100);
    metrics.set_queue_depth(500);
    metrics.observe_batch_size(200);

    metrics.reset();

    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_ingestion_requests_total{rpc=\"SubmitAuditEvent\",status=\"success\"} 0"),
              std::string::npos);
    EXPECT_NE(text.find("audit_queue_depth 0"), std::string::npos);
    EXPECT_NE(text.find("audit_batch_size_events_count 0"), std::string::npos);
}

// Test 5: Zero Sensitive Data Reflection
TEST_F(AuditMetricsUnitTest, ZeroSensitiveDataReflection) {
    std::string plain = "Invalid UUID string";
    std::string sensitive_pwd = "Authentication failed for user admin with password SuperSecretPassword123!";
    std::string sensitive_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.SecretToken";

    EXPECT_EQ(AuditDiagnostics::sanitize_detail(plain), "Invalid UUID string");
    EXPECT_EQ(AuditDiagnostics::sanitize_detail(sensitive_pwd), "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuditDiagnostics::sanitize_detail(sensitive_token), "[REDACTED_SENSITIVE_DATA]");

    std::ostringstream buffer;
    std::streambuf* old_cout = std::cout.rdbuf(buffer.rdbuf());

    log_ingestion_rejection("sensitive_data", "auth", "SubmitAuditEvent", std::nullopt, sensitive_pwd);

    std::cout.rdbuf(old_cout);
    std::string log_output = buffer.str();

    EXPECT_EQ(log_output.find("SuperSecretPassword123!"), std::string::npos);
    EXPECT_NE(log_output.find("[REDACTED_SENSITIVE_DATA]"), std::string::npos);
}

} // namespace securecloud::audit::telemetry::testing
