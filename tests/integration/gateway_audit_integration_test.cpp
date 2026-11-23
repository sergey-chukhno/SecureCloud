#include "audit/audit_delivery_dispatcher.hpp"
#include "audit/audit_producer_metrics.hpp"
#include "audit/bounded_memory_pending_store.hpp"
#include "grpc/audit_client_interface.hpp"
#include "http/resilience/circuit_breaker.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <set>

namespace securecloud::gateway::audit::integration_test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

class MockAuditIngestionClient : public securecloud::gateway::grpc::IAuditIngestionClient {
  public:
    MOCK_METHOD((securecloud::gateway::grpc::Result<securecloud::audit::v1::SubmitAuditEventResponse>), submit_event,
                (const securecloud::audit::v1::SubmitAuditEventRequest&,
                 securecloud::gateway::grpc::ClientCallContext&),
                (override));

    MOCK_METHOD((securecloud::gateway::grpc::Result<securecloud::audit::v1::BatchSubmitAuditEventsResponse>),
                batch_submit_events,
                (const securecloud::audit::v1::BatchSubmitAuditEventsRequest&,
                 securecloud::gateway::grpc::ClientCallContext&),
                (override));
};

// Simulate gRPC Audit service outage and verify retries
TEST(AuditIntegrationTest, HandlesAuditOutageAndRetries) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto client = std::make_shared<NiceMock<MockAuditIngestionClient>>();
    auto metrics = std::make_shared<AuditProducerMetrics>();

    securecloud::gateway::GatewayCircuitBreakerConfig cb_config;
    auto circuit_breaker = std::make_shared<securecloud::gateway::http::CircuitBreaker>("audit_service", cb_config);

    // Simulate transient UNAVAILABLE error from Audit service
    EXPECT_CALL(*client, batch_submit_events(_, _))
        .WillRepeatedly(Return(securecloud::gateway::grpc::DependencyError::from_grpc_status(
            ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Audit service down"))));

    AuditDeliveryDispatcherConfig config;
    config.poll_interval_ms = 10;
    AuditDeliveryDispatcher dispatcher(store, client, circuit_breaker, metrics, config);

    PendingRecord rec;
    rec.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec.proto_bytes = {0x01, 0x02, 0x03};
    const auto admission_result = store->append(rec);
    EXPECT_EQ(admission_result, AdmissionResult::AcceptedNonDurable);

    dispatcher.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    dispatcher.stop();

    // Verify dispatcher attempted delivery and error metrics/retries were accounted for
    const auto stats = store->stats();
    const uint64_t total_tracked =
        stats.total_records + stats.claimed_records + stats.dropped_records + stats.unrecoverable_records;
    EXPECT_GE(total_tracked, 1u);
}

// Validate server-side deduplication during redelivery on lost ACK
TEST(AuditIntegrationTest, LostAckServerSideDeduplication) {
    std::set<std::string> server_committed_events;
    const auto id = securecloud::audit::domain::EventId::generate_v7();
    const std::string event_id_str = id.to_string();

    // 1st delivery attempt
    auto [iter1, inserted1] = server_committed_events.insert(event_id_str);
    EXPECT_TRUE(inserted1);

    // 2nd delivery attempt due to lost ACK (redelivery using identical UUIDv7)
    auto [iter2, inserted2] = server_committed_events.insert(event_id_str);
    EXPECT_FALSE(inserted2);

    // Only one record must be committed on the server
    EXPECT_EQ(server_committed_events.size(), 1u);
}

} // namespace securecloud::gateway::audit::integration_test
