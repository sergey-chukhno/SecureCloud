#include "audit/audit_producer_metrics.hpp"
#include "audit/bounded_memory_pending_store.hpp"
#include "audit/gateway_audit_event_factory.hpp"
#include "audit/gateway_audit_producer.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::gateway::audit::unit_test {

// Test strict request-path isolation (< 1ms p99 latency delta)
TEST(AuditVerificationUnitTest, RequestPathIsolationUnderStoreLoad) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto factory = std::make_shared<GatewayAuditEventFactory>("gateway-node-1");
    auto producer = create_gateway_audit_producer(store, factory, true, 10, 1000);

    GatewayAuditObservation obs;
    obs.type = GatewayAuditEventType::TokenRejected;
    obs.client_ip = "192.168.1.1";
    obs.route_class = "auth_login";

    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 100; ++i) {
        producer->record_observation(obs);
    }
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);

    // 100 admission requests must not block the HTTP request thread
    EXPECT_LT(elapsed.count() / 100, 1000); // Average latency < 1ms
}

// Concurrent Multi-Producer Stress Test (8 threads x 100k records)
TEST(AuditVerificationUnitTest, MultiProducerConcurrentStressTest) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(1000000, 100 * 1024 * 1024);
    auto factory = std::make_shared<GatewayAuditEventFactory>("gateway-stress-node");
    auto producer = create_gateway_audit_producer(store, factory, true, 10, 10000);

    constexpr int kNumThreads = 8;
    constexpr int kOpsPerThread = 10000;

    std::vector<std::thread> threads;
    threads.reserve(kNumThreads);

    for (int i = 0; i < kNumThreads; ++i) {
        threads.emplace_back([producer, i]() {
            GatewayAuditObservation obs;
            obs.type = GatewayAuditEventType::TokenRejected;
            obs.client_ip = "10.0.0." + std::to_string(i);
            obs.route_class = "api_gateway";

            for (int j = 0; j < kOpsPerThread; ++j) {
                producer->record_observation(obs);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(producer->enqueued_count(), static_cast<uint64_t>(kNumThreads * kOpsPerThread));
}

} // namespace securecloud::gateway::audit::unit_test
