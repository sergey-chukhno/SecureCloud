#include "health/audit_health_evaluator.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/repository_resilience.hpp"
#include "telemetry/audit_metrics.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace securecloud::audit::repository::testing {

using ::testing::_;
using ::testing::Return;

class MockClickHouseClient : public ClickHouseClient {
  public:
    MockClickHouseClient() : ClickHouseClient(ClickHouseConfig{}) {}
    MOCK_METHOD(bool, execute_insert,
                (const std::string& query, const std::string& data, std::chrono::milliseconds timeout), (override));
    MOCK_METHOD(bool, ping, (std::chrono::milliseconds timeout), (override));
};

class AuditPersistenceTelemetryTest : public ::testing::Test {
  protected:
    void SetUp() override { telemetry::AuditMetrics::instance().reset(); }

    static domain::AuditEvent create_test_event(domain::ProducerService producer = domain::ProducerService::Auth) {
        domain::AuditEvent evt;
        evt.event_id = domain::EventId::generate_v7();
        evt.producer_service = producer;
        evt.event_type = "auth.user.login";
        evt.occurred_at = std::chrono::system_clock::now();
        evt.received_at = std::chrono::system_clock::now();
        return evt;
    }
};

TEST_F(AuditPersistenceTelemetryTest, InsertBatchMetricsSuccess) {
    auto mock_client = std::make_shared<MockClickHouseClient>();
    EXPECT_CALL(*mock_client, execute_insert(_, _, _)).WillOnce(Return(true));

    ClickHouseAuditEventRepository repo(mock_client);

    std::vector<domain::AuditEvent> events;
    events.push_back(create_test_event(domain::ProducerService::Auth));
    events.push_back(create_test_event(domain::ProducerService::Auth));
    events.push_back(create_test_event(domain::ProducerService::Gateway));

    EXPECT_TRUE(repo.insert_batch(events));

    std::string text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_clickhouse_insert_operations_total{outcome=\"success\"} 1"), std::string::npos);
    EXPECT_NE(text.find("audit_persisted_batches_total{outcome=\"success\"} 1"), std::string::npos);
    EXPECT_NE(text.find("audit_persisted_events_total{producer=\"auth\"} 2"), std::string::npos);
    EXPECT_NE(text.find("audit_persisted_events_total{producer=\"gateway\"} 1"), std::string::npos);
    EXPECT_NE(text.find("audit_clickhouse_insert_duration_seconds_count 1"), std::string::npos);
}

TEST_F(AuditPersistenceTelemetryTest, InsertBatchMetricsFailure) {
    auto mock_client = std::make_shared<MockClickHouseClient>();
    EXPECT_CALL(*mock_client, execute_insert(_, _, _)).WillOnce(Return(false));

    ClickHouseAuditEventRepository repo(mock_client);

    std::vector<domain::AuditEvent> events;
    events.push_back(create_test_event());

    EXPECT_FALSE(repo.insert_batch(events));

    std::string text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_clickhouse_insert_operations_total{outcome=\"failure\"} 1"), std::string::npos);
    EXPECT_NE(text.find("audit_persisted_batches_total{outcome=\"failure\"} 1"), std::string::npos);
}

TEST_F(AuditPersistenceTelemetryTest, ResilienceRetryMetrics) {
    RepositoryResilience resilience(10);

    uint32_t attempts = 0;
    try {
        resilience.execute(
            [&attempts]() -> bool {
                attempts++;
                if (attempts < 3) {
                    throw ClickHouseTimeoutException("Timeout simulation");
                }
                return true;
            },
            3);
    } catch (...) {
    }

    std::string text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_clickhouse_retries_total 2"), std::string::npos);
}

TEST_F(AuditPersistenceTelemetryTest, HealthEvaluatorClickHouseAvailableGauge) {
    common::health::HealthStatusManager health_mgr("test");

    health::AuditHealthEvaluator evaluator(
        health_mgr, [](std::chrono::milliseconds) { return true; }, [](uint32_t&) { return true; },
        health::AuditHealthEvaluatorConfig{.auto_start = false});

    (void)evaluator.evaluate_once();

    std::string text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_clickhouse_available 1"), std::string::npos);
}

} // namespace securecloud::audit::repository::testing
