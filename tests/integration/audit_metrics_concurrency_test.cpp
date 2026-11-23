#include "telemetry/audit_metrics.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::audit::telemetry::testing {

class AuditMetricsConcurrencyTest : public ::testing::Test {
  protected:
    void SetUp() override { AuditMetrics::instance().reset(); }
};

// Test 6: High-Concurrency Hot-Path Stress (8 threads x 12,500 ops = 100,000 total operations)
TEST_F(AuditMetricsConcurrencyTest, HighConcurrencyHotPathStress) {
    auto& metrics = AuditMetrics::instance();
    constexpr size_t kNumThreads = 8;
    constexpr size_t kOpsPerThread = 12500; // 100,000 ops in total

    std::vector<std::thread> threads;
    threads.reserve(kNumThreads);

    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&metrics, t]() {
            auto producer = static_cast<ProducerLabel>(t % static_cast<size_t>(ProducerLabel::Count));
            auto severity = static_cast<SeverityLabel>(t % static_cast<size_t>(SeverityLabel::Count));
            auto reason = static_cast<RejectionReason>(t % static_cast<size_t>(RejectionReason::Count));

            for (size_t i = 0; i < kOpsPerThread; ++i) {
                metrics.record_ingestion_request(RpcType::SubmitAuditEvent, RequestStatus::Success);
                metrics.record_ingested_event(producer, severity);
                metrics.record_rejected_event(reason);
                metrics.observe_clickhouse_insert_duration(0.012);
                metrics.observe_batch_size(100);
            }
        });
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time);

    std::cout << "[AUDIT-011-T06 Integration] Completed 100,000 concurrent metric updates in " << elapsed.count()
              << " ms.\n";

    std::string text = metrics.to_prometheus_text();

    EXPECT_NE(text.find("audit_clickhouse_insert_duration_seconds_count 100000"), std::string::npos);
    EXPECT_NE(text.find("audit_batch_size_events_count 100000"), std::string::npos);
}

// Test 7: Bounded Memory & Label Cardinality Invariant (1,000,000 event recordings across all label permutations)
TEST_F(AuditMetricsConcurrencyTest, BoundedMemoryAndLabelCardinalityInvariant) {
    auto& metrics = AuditMetrics::instance();

    std::string initial_text = metrics.to_prometheus_text();
    const size_t initial_size = initial_text.size();

    constexpr size_t kTotalEvents = 1000000;

    for (size_t i = 0; i < kTotalEvents; ++i) {
        auto p = static_cast<ProducerLabel>(i % static_cast<size_t>(ProducerLabel::Count));
        auto s = static_cast<SeverityLabel>(i % static_cast<size_t>(SeverityLabel::Count));
        auto r = static_cast<RejectionReason>(i % static_cast<size_t>(RejectionReason::Count));
        auto rpc = static_cast<RpcType>(i % static_cast<size_t>(RpcType::Count));
        auto st = static_cast<RequestStatus>(i % static_cast<size_t>(RequestStatus::Count));

        metrics.record_ingested_event(p, s);
        metrics.record_rejected_event(r);
        metrics.record_ingestion_request(rpc, st);
    }

    std::string text_after_million = metrics.to_prometheus_text();

    // Verify string buffer layout footprint does not scale dynamically with million iterations
    EXPECT_NEAR(static_cast<double>(text_after_million.size()), static_cast<double>(initial_size), 500.0);
}

} // namespace securecloud::audit::telemetry::testing
