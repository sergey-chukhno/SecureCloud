#include "ingestion/batch_aggregator.hpp"
#include "ingestion/bounded_ingestion_queue.hpp"
#include "telemetry/audit_metrics.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

namespace securecloud::audit::ingestion::testing {

class AuditQueueTelemetryTest : public ::testing::Test {
  protected:
    void SetUp() override { telemetry::AuditMetrics::instance().reset(); }

    static IngestionEnvelope make_test_envelope(domain::ProducerService producer = domain::ProducerService::Auth) {
        IngestionEnvelope env;
        env.event.event_id = domain::EventId::generate_v7();
        env.event.producer_service = producer;
        env.event.event_type = "auth.user.login";
        env.event.occurred_at = std::chrono::system_clock::now();
        env.event.received_at = std::chrono::system_clock::now();
        env.enqueued_at = std::chrono::system_clock::now();
        return env;
    }
};

TEST_F(AuditQueueTelemetryTest, QueueDepthAndCapacityGauges) {
    BoundedIngestionQueue queue(10);

    std::string text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_queue_capacity 10"), std::string::npos);
    EXPECT_NE(text.find("audit_queue_depth 0"), std::string::npos);

    EXPECT_TRUE(queue.try_push(make_test_envelope()));
    EXPECT_TRUE(queue.try_push(make_test_envelope()));

    text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_queue_depth 2"), std::string::npos);

    (void)queue.pop(std::chrono::milliseconds(10));

    text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_queue_depth 1"), std::string::npos);
}

TEST_F(AuditQueueTelemetryTest, SaturatedDropCounter) {
    BoundedIngestionQueue queue(1);

    EXPECT_TRUE(queue.try_push(make_test_envelope(domain::ProducerService::Auth)));
    EXPECT_FALSE(queue.try_push(make_test_envelope(domain::ProducerService::Auth)));

    std::string text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_queue_saturated_drops_total{producer=\"auth\"} 1"), std::string::npos);
}

TEST_F(AuditQueueTelemetryTest, BatchFlushTriggersAndSizeMetrics) {
    auto input_queue = std::make_shared<BoundedIngestionQueue>(100);
    auto output_queue = std::make_shared<BoundedBatchQueue>(10);

    BatchAggregator aggregator(5, std::chrono::milliseconds(50), input_queue, output_queue);
    aggregator.start();

    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(input_queue->try_push(make_test_envelope()));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    aggregator.stop();

    std::string text = telemetry::AuditMetrics::instance().to_prometheus_text();
    EXPECT_NE(text.find("audit_batch_flush_total{trigger=\"count\"} 1"), std::string::npos);
    EXPECT_NE(text.find("audit_batch_size_events_count 1"), std::string::npos);
}

} // namespace securecloud::audit::ingestion::testing
